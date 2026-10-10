//! The network over QUIC (quinn on smol), with TLS 1.3 bound to node keys
//! both ways.
//!
//! - **Connections.** Each node dials every peer it sends to and sends
//!   only on its own connection, so a send never waits for the other side
//!   to dial; the accepting side only reads. That is two connections per
//!   pair. A dropped connection is redialed with backoff, and frames wait
//!   in a bounded queue per peer and class meanwhile.
//! - **Restarts.** Stateless resets are keyed by the node's secret, so a
//!   restarted node resets at once the connections its last run held. The
//!   name a node dials with carries its incarnation: a peer dialing in as
//!   a new incarnation also closes this node's connection to the old one,
//!   which redials.
//! - **Streams** are unidirectional. One opens with its class and id, then
//!   carries frames, each a length (u32, big-endian) and its bytes.
//!   Liveness, Consensus and Requests keep a stream per id for the
//!   connection's life; Bulk opens one per frame. Streams are sent by
//!   class priority, Liveness first.
//! - **Flow control.** The connection's receive window is unlimited, so a
//!   few unread streams cannot stall the rest; each stream's window, and
//!   the cap on concurrent bulk streams, bound what is buffered.
//! - **Frames are bounded on receipt,** per class, and read as they
//!   arrive: a length prefix never sizes an allocation by itself.
//! - No keepalives: the node's own liveness messages carry that. An idle
//!   connection closes after [`IDLE`], and the next send redials.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use quinn::VarInt;
use ring::rand::SecureRandom;
use smol::future::FutureExt;
use smol::stream::StreamExt;

use crate::tls::{self, Identity, Table};
use crate::{
    Arrivals, Class, Deliver, Incoming, Limits, Network, NodeKey, NodeNumber, Peer, Refused,
    arrivals,
};

/// An idle connection closes after this long.
pub const IDLE: Duration = Duration::from_secs(30);
/// What a queued frame costs beyond its bytes, so empty frames are
/// bounded too.
const FRAME_COST: usize = 64;
/// What one stream may have in flight unread.
const STREAM_WINDOW: u32 = 1 << 20;
/// What a connection may have in flight unacknowledged, for every stream:
/// well above the bulk streams' share, so they never fill it.
const SEND_WINDOW: u64 = 16 << 20;
/// Bulk frames in flight at once on one connection.
const BULK_STREAMS: usize = 4;
/// The round trip assumed before one is measured: a cluster's, not the
/// internet's, so a lost first packet is sent again soon.
const INITIAL_RTT: Duration = Duration::from_millis(100);
/// A dial gives up after this long and is tried again, so a peer that
/// comes back is reached soon, not at the end of a long retransmission
/// backoff.
const DIAL: Duration = Duration::from_secs(2);
const MIN_BACKOFF: Duration = Duration::from_millis(50);
const MAX_BACKOFF: Duration = Duration::from_secs(1);
/// The bytes before a stream's frames: its class and id.
const HEADER: usize = 9;

/// Codes a connection or stream is closed with.
mod code {
    use quinn::VarInt;

    pub const CLOSED: VarInt = VarInt::from_u32(0);
    /// The peer dialed in as a new incarnation.
    pub const RESTARTED: VarInt = VarInt::from_u32(1);
    /// The peer is no longer configured.
    pub const UNCONFIGURED: VarInt = VarInt::from_u32(2);
    /// A frame over its class's bound.
    pub const TOO_LARGE: VarInt = VarInt::from_u32(3);
    /// A stream with no class.
    pub const MALFORMED: VarInt = VarInt::from_u32(4);
}

/// A node's endpoint.
pub struct Config {
    pub number: NodeNumber,
    /// The node's secret seed: its key, and its stateless-reset key.
    pub secret: [u8; 32],
    pub listen: SocketAddr,
    pub peers: Vec<Peer>,
    pub limits: Limits,
    /// Streams a peer may hold open at once on its connection to this
    /// node: a long-lived stream per busy group and class, and the bulk
    /// streams. More wait for one to finish.
    pub streams: u32,
    /// A long-lived stream quiet for this long is finished, so streams
    /// held open are those of groups busy lately.
    pub quiet: Duration,
}

impl Config {
    pub fn new(number: NodeNumber, secret: [u8; 32], listen: SocketAddr) -> Self {
        Self {
            number,
            secret,
            listen,
            peers: Vec::new(),
            limits: Limits::default(),
            streams: 1 << 13,
            quiet: Duration::from_secs(10),
        }
    }
}

/// The network over QUIC. Dropping it closes every connection.
pub struct Quic {
    inner: Arc<Inner>,
    accept: Option<smol::Task<()>>,
}

struct Inner {
    number: NodeNumber,
    identity: Identity,
    /// The name this run dials with: its incarnation.
    name: String,
    endpoint: quinn::Endpoint,
    transport: Arc<quinn::TransportConfig>,
    table: Table,
    links: Mutex<HashMap<NodeNumber, Link>>,
    deliver: Deliver,
    limits: Limits,
    quiet: Duration,
    closed: AtomicBool,
}

impl Quic {
    /// Bind `config.listen` and start accepting the configured peers.
    pub fn bind(config: Config) -> io::Result<(Self, Arrivals)> {
        let identity = Identity::new(&config.secret);
        let transport = Arc::new(transport(config.streams));
        let table = Table::default();
        let server = identity.server(Arc::clone(&table), Arc::clone(&transport));
        let socket = std::net::UdpSocket::bind(config.listen)?;
        let endpoint = quinn::Endpoint::new(
            identity.endpoint(),
            Some(server),
            socket,
            Arc::new(quinn::SmolRuntime),
        )?;
        let mut incarnation = [0u8; 8];
        ring::rand::SystemRandom::new()
            .fill(&mut incarnation)
            .map_err(|_| io::Error::other("no randomness"))?;
        let (deliver, arrivals) = arrivals();
        let inner = Arc::new(Inner {
            number: config.number,
            identity,
            name: format!("vos-{:016x}", u64::from_be_bytes(incarnation)),
            endpoint,
            transport,
            table,
            links: Mutex::new(HashMap::new()),
            deliver,
            limits: config.limits,
            quiet: config.quiet,
            closed: AtomicBool::new(false),
        });
        inner.set_peers(config.peers);
        let accept = smol::spawn(accept(Arc::clone(&inner)));
        Ok((
            Self {
                inner,
                accept: Some(accept),
            },
            arrivals,
        ))
    }

    /// The address this node listens on.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner
            .endpoint
            .local_addr()
            .expect("a bound endpoint's address")
    }

    /// This node's public key.
    pub fn key(&self) -> NodeKey {
        self.inner.identity.key
    }

    /// Close every connection, wait until the peers have been told, and
    /// stop every task.
    pub async fn shutdown(mut self) {
        let links = self.inner.close();
        self.inner.endpoint.wait_idle().await;
        for link in links {
            link.task.cancel().await;
        }
        if let Some(accept) = self.accept.take() {
            accept.cancel().await;
        }
    }
}

impl Drop for Quic {
    fn drop(&mut self) {
        self.inner.close();
    }
}

impl Inner {
    /// Refuse every later send and close every connection: the links
    /// taken out, whose tasks stop when dropped.
    fn close(&self) -> Vec<Link> {
        self.closed.store(true, Ordering::Release);
        let links = std::mem::take(&mut *self.links.lock().expect("the links"));
        self.endpoint.close(code::CLOSED, b"");
        links.into_values().collect()
    }

    fn set_peers(&self, peers: Vec<Peer>) {
        let peers: Vec<Peer> = peers
            .into_iter()
            .filter(|peer| peer.number != self.number)
            .collect();
        let mut links = self.links.lock().expect("the links");
        *self.table.write().expect("the peer table") =
            peers.iter().map(|peer| (peer.key, peer.number)).collect();
        let mut kept = HashMap::new();
        for peer in peers {
            let link = match links.remove(&peer.number) {
                Some(link) if link.peer == peer && !link.task.is_finished() => link,
                _ => Link::spawn(self, peer.clone()),
            };
            kept.insert(peer.number, link);
        }
        // Dropping a link stops its task, which closes its connection.
        *links = kept;
    }

    /// Peer `from` dialed in with `name`: if that is a new incarnation,
    /// this node's connection to it reached the old one.
    fn dialed_in(&self, from: NodeNumber, name: Option<String>) {
        let links = self.links.lock().expect("the links");
        let Some(link) = links.get(&from) else {
            return;
        };
        let mut seen = link.shared.incarnation.lock().expect("the incarnation");
        let connection = link.shared.connection.lock().expect("the connection");
        if seen.is_some()
            && *seen != name
            && let Some(connection) = connection.as_ref()
        {
            connection.close(code::RESTARTED, b"");
        }
        *seen = name;
    }

    fn configured(&self, key: &NodeKey, from: NodeNumber) -> bool {
        self.table.read().expect("the peer table").get(key) == Some(&from)
    }
}

fn transport(streams: u32) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_uni_streams(VarInt::from_u32(streams))
        .max_concurrent_bidi_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u32(STREAM_WINDOW))
        .send_window(SEND_WINDOW)
        .max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(IDLE).expect("an idle timeout QUIC can carry"),
        ))
        .initial_rtt(INITIAL_RTT)
        .keep_alive_interval(None)
        .datagram_receive_buffer_size(None);
    transport
}

/// Frames waiting for one peer, the bytes they hold per class, and its
/// connection.
struct Shared {
    held: [AtomicUsize; 4],
    /// Notified whenever held bytes are released.
    released: event_listener::Event,
    limits: Limits,
    /// The connection this node holds to the peer, while it does.
    connection: Mutex<Option<quinn::Connection>>,
    /// The name the peer last dialed in with.
    incarnation: Mutex<Option<String>>,
}

impl Shared {
    /// Hold `bytes` for a frame of `class`, unless the class's queue is
    /// full. A queue under its budget takes any frame its class allows, so
    /// it holds less than its budget and one frame.
    fn hold(&self, class: Class, bytes: usize) -> bool {
        let budget = self.limits.queue(class);
        self.held[class as usize]
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                (held < budget).then_some(held + bytes + FRAME_COST)
            })
            .is_ok()
    }

    fn has_room(&self, class: Class) -> bool {
        self.held[class as usize].load(Ordering::Acquire) < self.limits.queue(class)
    }
}

/// A frame on its way, holding its bytes in its peer's queue until it is
/// written or lost.
struct Outgoing {
    class: Class,
    stream: u64,
    frame: Vec<u8>,
    shared: Arc<Shared>,
}

impl Drop for Outgoing {
    fn drop(&mut self) {
        self.shared.held[self.class as usize]
            .fetch_sub(self.frame.len() + FRAME_COST, Ordering::AcqRel);
        self.shared.released.notify(usize::MAX);
    }
}

/// The sending side to one peer: its queue, and the task that dials it and
/// writes.
struct Link {
    peer: Peer,
    frames: smol::channel::Sender<Outgoing>,
    shared: Arc<Shared>,
    task: smol::Task<()>,
}

impl Link {
    fn spawn(inner: &Inner, peer: Peer) -> Self {
        let shared = Arc::new(Shared {
            held: Default::default(),
            released: event_listener::Event::new(),
            limits: inner.limits,
            connection: Mutex::new(None),
            incarnation: Mutex::new(None),
        });
        let (frames, queued) = smol::channel::unbounded();
        let client = inner
            .identity
            .client(peer.key, Arc::clone(&inner.transport));
        let task = smol::spawn(dial(
            inner.endpoint.clone(),
            client,
            peer.address,
            inner.name.clone(),
            queued,
            Arc::clone(&shared),
            inner.quiet,
        ));
        Self {
            peer,
            frames,
            shared,
            task,
        }
    }
}

/// Dial the peer whenever there is something to send, and write to it
/// until the connection closes.
async fn dial(
    endpoint: quinn::Endpoint,
    client: quinn::ClientConfig,
    address: SocketAddr,
    name: String,
    queued: smol::channel::Receiver<Outgoing>,
    shared: Arc<Shared>,
    quiet: Duration,
) {
    let mut next = None;
    let mut backoff = MIN_BACKOFF;
    loop {
        if next.is_none() {
            match queued.recv().await {
                Ok(frame) => next = Some(frame),
                Err(_) => return,
            }
        }
        let connecting = match endpoint.connect_with(client.clone(), address, &name) {
            Ok(connecting) => connecting,
            Err(error) => {
                tracing::warn!(%address, %error, "cannot dial a peer");
                return;
            }
        };
        let timeout = async {
            smol::Timer::after(DIAL).await;
            Err(quinn::ConnectionError::TimedOut)
        };
        let connection = match connecting.or(timeout).await {
            Ok(connection) => connection,
            Err(error) => {
                tracing::debug!(%address, %error, "dial failed");
                smol::Timer::after(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };
        *shared.connection.lock().expect("the connection") = Some(connection.clone());
        write(&connection, &mut next, &queued, quiet).await;
        *shared.connection.lock().expect("the connection") = None;
        if refused(&connection) {
            // The peer took the handshake, then refused this node: dialing
            // again at once would only be refused again.
            tracing::debug!(%address, "a peer refused this node");
            smol::Timer::after(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        } else {
            backoff = MIN_BACKOFF;
        }
    }
}

/// Whether the peer closed `connection` refusing this node: a TLS alert
/// (its key was not taken), or the peer no longer configuring it.
fn refused(connection: &quinn::Connection) -> bool {
    match connection.close_reason() {
        Some(quinn::ConnectionError::ConnectionClosed(close)) => {
            (0x100..0x200).contains(&u64::from(close.error_code))
        }
        Some(quinn::ConnectionError::ApplicationClosed(close)) => {
            close.error_code == code::UNCONFIGURED
        }
        _ => false,
    }
}

/// Write queued frames on `connection` until it closes. A frame taken but
/// not yet handed to a stream stays in `next`, for the next connection.
async fn write(
    connection: &quinn::Connection,
    next: &mut Option<Outgoing>,
    queued: &smol::channel::Receiver<Outgoing>,
    quiet: Duration,
) {
    enum Event {
        Frame(Outgoing),
        Sweep,
        Done,
    }
    let mut streams: HashMap<(Class, u64), Writer> = HashMap::new();
    // Writers finishing their quiet streams. A new stream for the same id
    // opens only once its old one is finished and the peer has it all.
    let mut retiring: HashMap<(Class, u64), smol::Task<()>> = HashMap::new();
    let every = (quiet / 2).max(Duration::from_millis(1));
    let mut sweep = smol::Timer::interval(every);
    let mut swept = Instant::now();
    let bulk = Arc::new(smol::lock::Semaphore::new(BULK_STREAMS));
    let mut sending: Vec<smol::Task<()>> = Vec::new();
    loop {
        // Swept on time even while frames never stop coming.
        if swept.elapsed() >= every {
            retire(&mut streams, &mut retiring, quiet);
            swept = Instant::now();
        }
        let frame = match next.take() {
            Some(frame) => frame,
            None => {
                let frame = async {
                    match queued.recv().await {
                        Ok(frame) => Event::Frame(frame),
                        Err(_) => Event::Done,
                    }
                };
                let closed = async {
                    connection.closed().await;
                    Event::Done
                };
                let swept = async {
                    sweep.next().await;
                    Event::Sweep
                };
                match frame.or(closed).or(swept).await {
                    Event::Frame(frame) => frame,
                    Event::Sweep => continue,
                    Event::Done => return,
                }
            }
        };
        if connection.close_reason().is_some() {
            *next = Some(frame);
            return;
        }
        if frame.class.stream_per_frame() {
            sending.retain(|task| !task.is_finished());
            let connection = connection.clone();
            let bulk = Arc::clone(&bulk);
            sending.push(smol::spawn(async move {
                let _permit = bulk.acquire().await;
                let _ = write_bulk(&connection, frame).await;
            }));
            continue;
        }
        let key = (frame.class, frame.stream);
        let frame = match streams.get_mut(&key) {
            Some(writer) => match writer.frames.try_send(frame) {
                Ok(()) => {
                    writer.last = Instant::now();
                    continue;
                }
                // The stream failed: the frame goes on a new one.
                Err(error) => error.into_inner(),
            },
            None => frame,
        };
        let previous = retiring.remove(&key);
        let writer = Writer::spawn(connection.clone(), frame.class, frame.stream, previous);
        let _ = writer.frames.try_send(frame);
        streams.insert(key, writer);
    }
}

/// Retire the writers of streams quiet for `quiet`: each writes what it
/// still holds, then finishes its stream, so the peer can grant another.
fn retire(
    streams: &mut HashMap<(Class, u64), Writer>,
    retiring: &mut HashMap<(Class, u64), smol::Task<()>>,
    quiet: Duration,
) {
    retiring.retain(|_, task| !task.is_finished());
    let now = Instant::now();
    let quiet: Vec<_> = streams
        .iter()
        .filter(|(_, writer)| now.duration_since(writer.last) >= quiet)
        .map(|(key, _)| *key)
        .collect();
    for key in quiet {
        let writer = streams.remove(&key).expect("a quiet writer");
        // Dropping its sender ends its queue once drained.
        retiring.insert(key, writer.task);
    }
}

/// A long-lived stream's writer, and when it was last handed a frame.
struct Writer {
    frames: smol::channel::Sender<Outgoing>,
    task: smol::Task<()>,
    last: Instant,
}

impl Writer {
    /// A writer for a new stream, opened once `previous`, the last stream
    /// for the same id, is finished and all acknowledged.
    fn spawn(
        connection: quinn::Connection,
        class: Class,
        stream: u64,
        previous: Option<smol::Task<()>>,
    ) -> Self {
        let (frames, queued) = smol::channel::unbounded::<Outgoing>();
        let task = smol::spawn(async move {
            if let Some(previous) = previous {
                previous.await;
            }
            let written = async {
                let mut send = connection.open_uni().await.ok()?;
                send.set_priority(class.priority()).ok()?;
                send.write_all(&header(class, stream)).await.ok()?;
                while let Ok(frame) = queued.recv().await {
                    write_frame(&mut send, &frame.frame).await.ok()?;
                }
                send.finish().ok()?;
                send.stopped().await.ok()?;
                Some(())
            };
            if written.await.is_none() {
                // Release what is queued here: the next frame for this
                // stream opens another.
                queued.close();
                while queued.try_recv().is_ok() {}
            }
        });
        Self {
            frames,
            task,
            last: Instant::now(),
        }
    }
}

fn header(class: Class, stream: u64) -> [u8; HEADER] {
    let mut header = [0u8; HEADER];
    header[0] = class as u8;
    header[1..].copy_from_slice(&stream.to_be_bytes());
    header
}

async fn write_frame(send: &mut quinn::SendStream, frame: &[u8]) -> Result<(), quinn::WriteError> {
    let length = u32::try_from(frame.len()).expect("a frame within its class's bound");
    send.write_all(&length.to_be_bytes()).await?;
    send.write_all(frame).await
}

/// A bulk frame on a stream of its own, held until the peer has it all.
async fn write_bulk(connection: &quinn::Connection, frame: Outgoing) -> Option<()> {
    let mut send = connection.open_uni().await.ok()?;
    send.set_priority(frame.class.priority()).ok()?;
    send.write_all(&header(frame.class, frame.stream))
        .await
        .ok()?;
    write_frame(&mut send, &frame.frame).await.ok()?;
    send.finish().ok()?;
    drop(frame);
    send.stopped().await.ok()?;
    Some(())
}

/// Accept peers' connections, for as long as the endpoint is open.
async fn accept(inner: Arc<Inner>) {
    let mut serving: Vec<smol::Task<()>> = Vec::new();
    while let Some(incoming) = inner.endpoint.accept().await {
        serving.retain(|task| !task.is_finished());
        serving.push(smol::spawn(serve(Arc::clone(&inner), incoming)));
    }
}

/// Read a peer's connection: every stream it opens, each frame delivered
/// with the peer its key is configured for.
async fn serve(inner: Arc<Inner>, incoming: quinn::Incoming) {
    let connection = match incoming.await {
        Ok(connection) => connection,
        Err(error) => {
            tracing::debug!(%error, "a peer's handshake failed");
            return;
        }
    };
    let Some(key) = tls::peer_key(&connection) else {
        return;
    };
    let Some(from) = inner
        .table
        .read()
        .expect("the peer table")
        .get(&key)
        .copied()
    else {
        connection.close(code::UNCONFIGURED, b"");
        return;
    };
    inner.dialed_in(from, tls::server_name(&connection));
    let peer = Arc::new(Reading {
        inner,
        connection: connection.clone(),
        key,
        from,
        bulk: smol::lock::Semaphore::new(BULK_STREAMS),
        turns: Mutex::new(HashMap::new()),
    });
    let mut reading: Vec<smol::Task<()>> = Vec::new();
    while let Ok(stream) = connection.accept_uni().await {
        reading.retain(|task| !task.is_finished());
        reading.push(smol::spawn(read(Arc::clone(&peer), stream)));
    }
}

/// A peer's connection being read.
struct Reading {
    inner: Arc<Inner>,
    connection: quinn::Connection,
    key: NodeKey,
    from: NodeNumber,
    /// Bulk frames read at once.
    bulk: smol::lock::Semaphore,
    turns: Turns,
}

/// A turn per id: a stream's frames are delivered only once the last
/// stream for the same id has delivered all of its own.
type Turns = Mutex<HashMap<(Class, u64), Arc<smol::lock::Mutex<()>>>>;

/// Read one stream's frames, as they arrive.
async fn read(peer: Arc<Reading>, mut stream: quinn::RecvStream) {
    let mut header = [0u8; HEADER];
    if stream.read_exact(&mut header).await.is_err() {
        return;
    }
    let Some(class) = Class::from_u8(header[0]) else {
        let _ = stream.stop(code::MALFORMED);
        return;
    };
    let id = u64::from_be_bytes(header[1..].try_into().expect("eight bytes"));
    if class.stream_per_frame() {
        frames(&peer, stream, class, id).await;
        return;
    }
    let turn = Arc::clone(
        peer.turns
            .lock()
            .expect("the turns")
            .entry((class, id))
            .or_default(),
    );
    let held = turn.lock_arc().await;
    frames(&peer, stream, class, id).await;
    drop(held);
    let mut turns = peer.turns.lock().expect("the turns");
    // No later stream waits for this id: forget it.
    if Arc::strong_count(&turn) == 2 {
        turns.remove(&(class, id));
    }
}

/// Deliver a stream's frames until it ends.
async fn frames(peer: &Reading, mut stream: quinn::RecvStream, class: Class, id: u64) {
    let limit = peer.inner.limits.of(class);
    loop {
        let mut length = [0u8; 4];
        if stream.read_exact(&mut length).await.is_err() {
            return;
        }
        let length = u32::from_be_bytes(length) as usize;
        if length > limit {
            tracing::warn!(from = peer.from, ?class, length, "a frame over its bound");
            let _ = stream.stop(code::TOO_LARGE);
            return;
        }
        let _permit = match class.stream_per_frame() {
            true => Some(peer.bulk.acquire().await),
            false => None,
        };
        let Some(frame) = read_frame(&mut stream, length).await else {
            return;
        };
        if !peer.inner.configured(&peer.key, peer.from) {
            peer.connection.close(code::UNCONFIGURED, b"");
            return;
        }
        let incoming = Incoming {
            from: peer.from,
            stream: id,
            frame,
        };
        if !peer.inner.deliver.deliver(class, incoming).await {
            return;
        }
    }
}

/// A frame of `length` bytes, grown as its bytes arrive.
async fn read_frame(stream: &mut quinn::RecvStream, length: usize) -> Option<Vec<u8>> {
    let mut frame = Vec::with_capacity(length.min(STREAM_WINDOW as usize));
    while frame.len() < length {
        let chunk = stream.read_chunk(length - frame.len(), true).await.ok()??;
        frame.extend_from_slice(&chunk.bytes);
    }
    Some(frame)
}

impl Network for Quic {
    fn send(
        &self,
        to: NodeNumber,
        class: Class,
        stream: u64,
        frame: Vec<u8>,
    ) -> Result<(), Refused> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(Refused::Closed);
        }
        if frame.len() > self.inner.limits.of(class) {
            return Err(Refused::TooLarge);
        }
        let links = self.inner.links.lock().expect("the links");
        let link = links.get(&to).ok_or(Refused::UnknownPeer)?;
        if !link.shared.hold(class, frame.len()) {
            return Err(Refused::Full);
        }
        let outgoing = Outgoing {
            class,
            stream,
            frame,
            shared: Arc::clone(&link.shared),
        };
        link.frames.try_send(outgoing).map_err(|_| Refused::Closed)
    }

    fn ready(&self, to: NodeNumber, class: Class) -> impl Future<Output = ()> + Send {
        let shared = self
            .inner
            .links
            .lock()
            .expect("the links")
            .get(&to)
            .map(|link| Arc::clone(&link.shared));
        async move {
            let Some(shared) = shared else {
                return;
            };
            loop {
                let released = shared.released.listen();
                if shared.has_room(class) {
                    return;
                }
                released.await;
            }
        }
    }

    fn peers(&self) -> Vec<NodeNumber> {
        self.inner
            .links
            .lock()
            .expect("the links")
            .keys()
            .copied()
            .collect()
    }

    fn set_peers(&self, peers: Vec<Peer>) {
        self.inner.set_peers(peers);
    }
}
