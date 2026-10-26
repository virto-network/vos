//! The node API over QUIC: an endpoint of its own on its own thread, the
//! client's key checked at the handshake against the node's `gateways`,
//! one request a bidirectional stream.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use quinn::VarInt;
use vos_api::{Event, FrameError, Framing, Kind, Reader, Requests, error_frame, frame};
use vos_net::api::{Runner, Runtime, Spawner};

use super::{Api, Via, is_large};
use crate::timeout;

/// A connection quiet this long closes.
const IDLE: Duration = Duration::from_secs(30);
/// What one stream may have in flight unread: an install's body arrives
/// in windows of it.
const STREAM_WINDOW: u32 = 1 << 20;
/// The code a stream is stopped or reset with.
const STOPPED: VarInt = VarInt::from_u32(0);
/// The code a connection past the node's bound is closed with.
const FULL: VarInt = VarInt::from_u32(1);
/// Handshakes under way at once: past them, a client is refused.
const HANDSHAKES: usize = 64;
/// Handshakes under way at once from one address (an IPv6 address's /64):
/// one host cannot take every handshake's place.
const HANDSHAKES_PER_ADDRESS: usize = 8;
/// How long a handshake may take.
const HANDSHAKE: Duration = Duration::from_secs(10);

/// The API's QUIC endpoint, served until dropped.
pub(crate) struct Served {
    endpoint: quinn::Endpoint,
    _accept: smol::Task<()>,
    /// Dropped last: it stops the endpoint's thread.
    _runner: Runner,
}

impl Served {
    pub(crate) fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        self.endpoint.close(VarInt::from_u32(0), b"");
    }
}

/// What the endpoint serves with.
pub(crate) struct Limits {
    pub(crate) connections: usize,
    pub(crate) in_flight: usize,
    pub(crate) deadline: Duration,
}

/// Bind `listen` for the node whose secret seed is `secret`, taking the
/// clients whose keys `gateways` lists.
pub(crate) fn serve(
    api: Arc<Api>,
    secret: &[u8; 32],
    listen: SocketAddr,
    gateways: Vec<[u8; 32]>,
    limits: Limits,
) -> std::io::Result<Served> {
    let gateways: HashSet<[u8; 32]> = gateways.into_iter().collect();
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(
            u32::try_from(limits.in_flight).unwrap_or(u32::MAX),
        ))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u32(STREAM_WINDOW))
        .max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(IDLE).expect("an idle timeout QUIC can carry"),
        ))
        .keep_alive_interval(None)
        .datagram_receive_buffer_size(None);
    let server = vos_net::api::server_config(
        secret,
        move |key| gateways.contains(key),
        Arc::new(transport),
    );
    let socket = std::net::UdpSocket::bind(listen)?;
    let runner = Runner::start()?;
    let endpoint = quinn::Endpoint::new(
        vos_net::api::endpoint_config(secret),
        Some(server),
        socket,
        Arc::new(Runtime(runner.spawner())),
    )?;
    let spawner = runner.spawner();
    let accept = spawner
        .spawn(accept(api, endpoint.clone(), spawner.clone(), limits))
        .expect("the endpoint's executor runs");
    Ok(Served {
        endpoint,
        _accept: accept,
        _runner: runner,
    })
}

/// A connection's place among the open ones, given back when it ends.
struct Place(Arc<AtomicUsize>);

impl Drop for Place {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A handshake's place among its address's, given back when it ends.
struct Shaking {
    by: Arc<Mutex<HashMap<IpAddr, usize>>>,
    address: IpAddr,
}

impl Shaking {
    /// A place for a handshake from `address`, if it has fewer than its
    /// share under way.
    fn take(by: &Arc<Mutex<HashMap<IpAddr, usize>>>, address: IpAddr) -> Option<Self> {
        let address = match address {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6((u128::from(v6) & !((1u128 << 64) - 1)).into()),
            },
            v4 => v4,
        };
        let mut counts = by.lock().expect("the handshakes");
        let count = counts.entry(address).or_insert(0);
        if *count >= HANDSHAKES_PER_ADDRESS {
            return None;
        }
        *count += 1;
        Some(Self {
            by: Arc::clone(by),
            address,
        })
    }
}

impl Drop for Shaking {
    fn drop(&mut self) {
        let mut counts = self.by.lock().expect("the handshakes");
        if let Some(count) = counts.get_mut(&self.address) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.address);
            }
        }
    }
}

/// A place among `open`, if fewer than `most` hold one.
fn take(open: &Arc<AtomicUsize>, most: usize) -> Option<Place> {
    open.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |held| {
        (held < most).then_some(held + 1)
    })
    .ok()
    .map(|_| Place(Arc::clone(open)))
}

async fn accept(api: Arc<Api>, endpoint: quinn::Endpoint, spawner: Spawner, limits: Limits) {
    let limits = Arc::new(limits);
    let (open, handshaking) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let by_address = Arc::new(Mutex::new(HashMap::new()));
    while let Some(incoming) = endpoint.accept().await {
        // A client proves its address first, so a flood from addresses
        // that are not its sender's holds no handshake.
        if !incoming.remote_address_validated() {
            let _ = incoming.retry();
            continue;
        }
        let Some(own) = Shaking::take(&by_address, incoming.remote_address().ip()) else {
            incoming.refuse();
            continue;
        };
        let Some(shaking) = take(&handshaking, HANDSHAKES) else {
            incoming.refuse();
            continue;
        };
        let (api, limits, streams) = (Arc::clone(&api), Arc::clone(&limits), spawner.clone());
        let open = Arc::clone(&open);
        let Some(task) = spawner.spawn(async move {
            let connection = match timeout(HANDSHAKE, async { incoming.await }).await {
                Some(Ok(connection)) => connection,
                Some(Err(error)) => {
                    tracing::debug!(%error, "an API client's handshake failed");
                    return;
                }
                None => return,
            };
            drop((shaking, own));
            // Past the connections allowed, one is closed once it shook
            // hands: a listed client's, as the handshake checked its key.
            let Some(_place) = take(&open, limits.connections) else {
                connection.close(FULL, b"");
                return;
            };
            while let Ok((send, receive)) = connection.accept_bi().await {
                let api = Arc::clone(&api);
                let deadline = limits.deadline;
                if let Some(task) = streams.spawn(request(api, send, receive, deadline)) {
                    task.detach();
                }
            }
        }) else {
            return;
        };
        task.detach();
    }
}

/// One stream's request and its answer.
async fn request(
    api: Arc<Api>,
    mut send: quinn::SendStream,
    mut receive: quinn::RecvStream,
    deadline: Duration,
) {
    let mut reader = Reader::requests(Framing::Quic, Requests::All);
    let mut started: Option<Instant> = None;
    // The request's place among the large bodies, if it is large: past
    // them, it is answered `Unavailable` before its body is read.
    let mut large = None;
    let event = loop {
        if let Some(event) = reader.event() {
            break event;
        }
        if large.is_none() && is_large(&reader, Framing::Quic) {
            match api.large.try_acquire_arc() {
                Some(place) => large = Some(place),
                None => {
                    let _ = receive.stop(STOPPED);
                    let bytes = error_frame(Framing::Quic, 0, FrameError::Unavailable);
                    if send.write_all(&bytes).await.is_ok() {
                        let _ = send.finish();
                    }
                    return;
                }
            }
        }
        let read = match started {
            Some(started) => {
                let left = (started + deadline).saturating_duration_since(Instant::now());
                match timeout(left, receive.read_chunk(usize::MAX, true)).await {
                    Some(read) => read,
                    // Past its deadline: no answer, the stream reset.
                    None => {
                        let _ = receive.stop(STOPPED);
                        let _ = send.reset(STOPPED);
                        return;
                    }
                }
            }
            None => receive.read_chunk(usize::MAX, true).await,
        };
        match read {
            Ok(Some(chunk)) => {
                started.get_or_insert_with(Instant::now);
                reader.push(&chunk.bytes);
            }
            Ok(None) => match reader.finish() {
                Some(event) => break event,
                // An empty stream: nothing to answer.
                None => return,
            },
            Err(_) => return,
        }
    };
    let _ = receive.stop(STOPPED);
    let bytes = match event {
        Event::Frame(request) => {
            let kind = Kind::from_u16(request.kind).expect("the reader's kinds");
            let runtime = Arc::clone(&api.inner.runtime);
            // On the node's thread, as every request is handled.
            let answer = runtime
                .spawn(async move { api.handle(kind, request.body, Via::Quic).await })
                .await;
            frame(Framing::Quic, request.kind, 0, &answer)
        }
        Event::Error { error, .. } => error_frame(Framing::Quic, 0, error),
    };
    if send.write_all(&bytes).await.is_ok() {
        let _ = send.finish();
    }
    drop(large);
}
