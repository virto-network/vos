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
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use quinn::VarInt;
use ring::rand::SecureRandom;
use smol::future::FutureExt;

use crate::tls::{Identity, Table};
use crate::{
    Arrivals, Class, Deliver, Limits, Network, NodeKey, NodeNumber, Peer, Refused, arrivals,
};

pub(crate) mod executor;
mod receive;
mod send;

use executor::{Runner, Runtime, Spawner};
use receive::accept;
use send::{Link, Outgoing};

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
/// Streams a peer may hold open at once, unless configured otherwise.
const STREAMS: u32 = 1 << 13;
/// How long a long-lived stream stays quiet before it is finished, unless
/// configured otherwise.
const QUIET: Duration = Duration::from_secs(10);
/// How long a network dropped waits for its peers to hear the close.
const CLOSING: Duration = Duration::from_millis(100);
/// QUIC's CRYPTO_ERROR codes: 0x100 plus a TLS alert's code.
const CRYPTO_ERRORS: std::ops::Range<u64> = 0x100..0x200;

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
    /// A connection quiet for this long closes: [`IDLE`] by default.
    pub idle: Duration,
}

impl Config {
    pub fn new(number: NodeNumber, secret: [u8; 32], listen: SocketAddr) -> Self {
        Self {
            number,
            secret,
            listen,
            peers: Vec::new(),
            limits: Limits::default(),
            streams: STREAMS,
            quiet: QUIET,
            idle: IDLE,
        }
    }
}

/// The network over QUIC. Dropping it closes every connection, waits
/// briefly for the peers to hear it, and stops every task.
pub struct Quic {
    inner: Arc<Inner>,
    _accept: smol::Task<()>,
    /// Dropped last: it stops the network's thread.
    _runner: Runner,
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
    spawner: Spawner,
}

impl Quic {
    /// Bind `config.listen` and start accepting the configured peers.
    pub fn bind(config: Config) -> io::Result<(Self, Arrivals)> {
        let identity = Identity::new(&config.secret);
        let transport = Arc::new(transport(config.streams, config.idle));
        let table = Table::default();
        let server = identity.server(Arc::clone(&table), Arc::clone(&transport));
        let socket = std::net::UdpSocket::bind(config.listen)?;
        let runner = Runner::start()?;
        let endpoint = quinn::Endpoint::new(
            identity.endpoint(),
            Some(server),
            socket,
            Arc::new(Runtime(runner.spawner())),
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
            spawner: runner.spawner(),
        });
        inner.set_peers(config.peers);
        let accept = runner
            .spawner()
            .spawn(accept(Arc::clone(&inner)))
            .expect("the network's executor runs while it is open");
        Ok((
            Self {
                inner,
                _accept: accept,
                _runner: runner,
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

    /// Replace the peer table, without a restart: a peer changed or gone
    /// loses its connection.
    pub fn set_peers(&self, peers: Vec<Peer>) {
        self.inner.set_peers(peers);
    }
}

impl Drop for Quic {
    fn drop(&mut self) {
        self.inner.close();
        // Let the peers hear the close, briefly, before the thread stops.
        smol::block_on(self.inner.endpoint.wait_idle().or(async {
            smol::Timer::after(CLOSING).await;
        }));
    }
}

impl Inner {
    /// Close every connection.
    fn close(&self) {
        let links = std::mem::take(&mut *self.links.lock().expect("the links"));
        self.endpoint.close(code::CLOSED, b"");
        // Dropping a link stops its task.
        drop(links);
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

    /// The configured peer whose key is `key`.
    fn peer_number(&self, key: &NodeKey) -> Option<NodeNumber> {
        self.table.read().expect("the peer table").get(key).copied()
    }

    fn configured(&self, key: &NodeKey, from: NodeNumber) -> bool {
        self.peer_number(key) == Some(from)
    }
}

fn transport(streams: u32, idle: Duration) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_uni_streams(VarInt::from_u32(streams))
        .max_concurrent_bidi_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u32(STREAM_WINDOW))
        .send_window(SEND_WINDOW)
        .max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(idle).expect("an idle timeout QUIC can carry"),
        ))
        .initial_rtt(INITIAL_RTT)
        .keep_alive_interval(None)
        .datagram_receive_buffer_size(None);
    transport
}

impl Network for Quic {
    fn send(
        &self,
        to: NodeNumber,
        class: Class,
        stream: u64,
        frame: Vec<u8>,
    ) -> Result<(), Refused> {
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
            queued: Instant::now(),
        };
        link.frames.try_send(outgoing).map_err(|_| Refused::Closed)
    }

    fn ready(&self, to: NodeNumber, class: Class) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let shared = self
            .inner
            .links
            .lock()
            .expect("the links")
            .get(&to)
            .map(|link| Arc::clone(&link.shared));
        Box::pin(async move {
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
        })
    }
}
