//! The network over QUIC (quinn on smol), with TLS 1.3 bound to node keys
//! both ways.
//!
//! - **Connections.** Each node dials every peer it sends to and sends
//!   only on its own connection, so a send never waits for the other side
//!   to dial; the accepting side only reads, and the dialed side may open
//!   no stream. That is two connections per pair, and one inbound
//!   connection per key: a newer one replaces the older. A dropped
//!   connection is redialed, with backoff when it was refused or lived
//!   briefly, on the next frame sent; frames sent meanwhile wait in a
//!   bounded queue per peer and class, and those already handed to the
//!   dropped connection are lost with it.
//! - **Handshakes.** A sender proves its address (a retry) before the
//!   node spends a handshake on it. Handshakes under way are bounded per
//!   address, and in total for addresses no configured peer has; one
//!   that fails keeps its place a while, so the places bound handshakes a
//!   second too; each has a deadline.
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
//!   few unread streams cannot stall the rest: what quinn buffers for a
//!   peer's streams not being read is bounded by [`Config::streams`] times
//!   a stream's window (1 MiB).
//! - **Frames are bounded on receipt,** per class, and a frame takes its
//!   bytes from its peer's budget for that class ([`Config::assembling`])
//!   before it is read: past the budget, a stream waits unread, which flow
//!   control pushes back to the sender. Frames waiting for the consumer
//!   are bounded in bytes per class.
//! - No keepalives: the node's own liveness messages carry that. An idle
//!   connection closes after [`IDLE`], and the next send redials.

use std::collections::HashMap;
use std::future::{Future, IntoFuture};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use quinn::VarInt;
use ring::rand::SecureRandom;
use smol::future::FutureExt;

use crate::tls::{ALPN, Identity, Table};
use crate::{
    Arrivals, Class, Deliver, Limits, Network, NodeKey, NodeNumber, Peer, Refused, arrivals,
};

mod admit;
pub(crate) mod executor;
mod receive;
mod send;

use admit::Admission;
use executor::{Runner, Runtime, Spawner};
use receive::accept;
use send::{Link, Outgoing};

/// An idle connection closes after this long.
pub const IDLE: Duration = Duration::from_secs(30);
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
/// A connection that closes sooner than this after it was made is backed
/// off from, as a refused one is.
const SETTLED: Duration = Duration::from_secs(1);
/// The bytes before a stream's frames: its class and id.
const HEADER: usize = 9;
/// Streams a peer may hold open at once, unless configured otherwise.
const STREAMS: u32 = 1 << 13;
/// How long a long-lived stream stays quiet before it is finished, unless
/// configured otherwise.
const QUIET: Duration = Duration::from_secs(10);
/// Frames of one class a peer may have this node assemble at once, in
/// that class's largest frames, unless configured otherwise.
const ASSEMBLING: usize = 4;
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
    /// A stream with no class; or, closing a connection, too many streams
    /// that broke the protocol.
    pub const MALFORMED: VarInt = VarInt::from_u32(4);
    /// A newer connection from the same key took this one's place.
    pub const REPLACED: VarInt = VarInt::from_u32(5);
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
    /// node: a long-lived stream per busy id and class, and the bulk
    /// streams. More wait for one to finish. Times a stream's window, it
    /// bounds what a peer's streams not being read hold.
    pub streams: u32,
    /// A long-lived stream quiet for this long is finished, so streams
    /// held open are those of ids busy lately.
    pub quiet: Duration,
    /// A connection quiet for this long closes: [`IDLE`] by default.
    pub idle: Duration,
    /// The bytes of one class's frames a peer may have this node assemble
    /// at once, in that class's largest frames (1 MiB at least): 4 by
    /// default. A budget under its bound takes one frame more.
    pub assembling: usize,
}

/// How the endpoint takes handshakes, each from an address its sender
/// proved first. An address is an IPv4 address or an IPv6 address's /64.
#[derive(Clone, Copy, Debug)]
struct Handshakes {
    /// Handshakes under way at once from addresses no configured peer
    /// has, in all.
    total: usize,
    /// Handshakes under way at once from one address, for each
    /// configured peer at that address (one at least).
    per_address: usize,
    /// How long a handshake may take.
    deadline: Duration,
    /// How long a handshake that failed keeps its place: so an address's
    /// places bound its handshakes a second, not only those under way.
    failed: Duration,
}

impl Default for Handshakes {
    fn default() -> Self {
        Self {
            total: 64,
            per_address: 8,
            deadline: Duration::from_secs(10),
            failed: Duration::from_secs(1),
        }
    }
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
            assembling: ASSEMBLING,
        }
    }

    /// Refuse what would panic, stall or never take a frame.
    fn check(&self) -> io::Result<()> {
        let refuse = |what: &str| Err(io::Error::new(io::ErrorKind::InvalidInput, what.to_owned()));
        let limits = &self.limits;
        if Class::ALL.into_iter().any(|class| limits.of(class) == 0) {
            return refuse("a class's frame limit is 0");
        }
        if self.streams == 0 || self.assembling == 0 {
            return refuse("no stream, or no frame, a peer may send");
        }
        if quinn::IdleTimeout::try_from(self.idle).is_err() {
            return refuse("an idle timeout QUIC cannot carry");
        }
        Ok(())
    }
}

/// The network over QUIC. Dropping it closes every connection, waits up
/// to 100 ms for the peers to hear it (blocking the thread that drops
/// it), and stops every task.
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
    /// What this node dials with: the dialed side may open no stream.
    dialing: Arc<quinn::TransportConfig>,
    table: Table,
    links: Mutex<HashMap<NodeNumber, Link>>,
    /// Each configured key's connection into this node, and the number it
    /// had then.
    inbound: Mutex<HashMap<NodeKey, (NodeNumber, quinn::Connection)>>,
    admission: Arc<Admission>,
    deliver: Deliver,
    limits: Limits,
    quiet: Duration,
    assembling: usize,
    spawner: Spawner,
}

impl Quic {
    /// Bind `config.listen` and start accepting the configured peers.
    pub fn bind(config: Config) -> io::Result<(Self, Arrivals)> {
        config.check()?;
        let identity = Identity::new(&config.secret);
        let accepting = Arc::new(transport(config.streams, config.idle));
        let dialing = Arc::new(transport(0, config.idle));
        let table = Table::default();
        let server = identity.server(Arc::clone(&table), accepting);
        let socket = std::net::UdpSocket::bind(config.listen)?;
        let runner = Runner::start()?;
        let endpoint = quinn::Endpoint::new(
            identity.endpoint(ALPN),
            Some(server),
            socket,
            Arc::new(Runtime(runner.spawner())),
        )?;
        let mut incarnation = [0u8; 8];
        ring::rand::SystemRandom::new()
            .fill(&mut incarnation)
            .map_err(|_| io::Error::other("no randomness"))?;
        let (deliver, arrivals) = arrivals(&config.limits);
        let inner = Arc::new(Inner {
            number: config.number,
            identity,
            name: format!("vos-{:016x}", u64::from_be_bytes(incarnation)),
            endpoint,
            dialing,
            table,
            links: Mutex::new(HashMap::new()),
            inbound: Mutex::new(HashMap::new()),
            admission: Arc::new(Admission::new(Handshakes::default())),
            deliver,
            limits: config.limits,
            quiet: config.quiet,
            assembling: config.assembling,
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
    /// loses its connections, both ways. Frames it sent that are already
    /// in the arrival queues stay there.
    pub fn set_peers(&self, peers: Vec<Peer>) {
        self.inner.set_peers(peers);
    }
}

impl Drop for Quic {
    fn drop(&mut self) {
        self.inner.close();
        // Let the peers hear the close, briefly, before the thread stops.
        smol::block_on(within(CLOSING, self.inner.endpoint.wait_idle()));
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
        let table: HashMap<NodeKey, NodeNumber> =
            peers.iter().map(|peer| (peer.key, peer.number)).collect();
        self.admission.set_peers(&peers);
        *self.table.write().expect("the peer table") = table.clone();
        // A key gone, or under another number, loses its connection into
        // this node, and what its readers hold.
        self.inbound
            .lock()
            .expect("the inbound connections")
            .retain(|key, (number, connection)| {
                let kept = table.get(key) == Some(number);
                if !kept {
                    connection.close(code::UNCONFIGURED, b"");
                }
                kept
            });
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
        let mut links = self.links.lock().expect("the links");
        let Some(link) = links.get_mut(&from) else {
            return;
        };
        if link.incarnation.is_some()
            && link.incarnation != name
            && let Some(connection) = link.connection.lock().expect("the connection").as_ref()
        {
            connection.close(code::RESTARTED, b"");
        }
        link.incarnation = name;
    }

    /// `connection`, just authenticated as `key`'s: the number the key is
    /// configured for, and the connection takes the place of the key's
    /// earlier one into this node, which closes. The table is read under
    /// the inbound connections' lock, so a removal that comes meanwhile
    /// finds the connection and closes it.
    fn dialed(&self, key: NodeKey, connection: &quinn::Connection) -> Option<NodeNumber> {
        let mut inbound = self.inbound.lock().expect("the inbound connections");
        let from = self.peer_number(&key)?;
        if let Some((_, earlier)) = inbound.insert(key, (from, connection.clone())) {
            earlier.close(code::REPLACED, b"");
        }
        Some(from)
    }

    /// `connection`, `key`'s, ended: forget it, unless a newer one took
    /// its place.
    fn hung_up(&self, key: &NodeKey, connection: &quinn::Connection) {
        let mut inbound = self.inbound.lock().expect("the inbound connections");
        if inbound
            .get(key)
            .is_some_and(|(_, held)| held.stable_id() == connection.stable_id())
        {
            inbound.remove(key);
        }
    }

    /// The configured peer whose key is `key`.
    fn peer_number(&self, key: &NodeKey) -> Option<NodeNumber> {
        self.table.read().expect("the peer table").get(key).copied()
    }

    fn configured(&self, key: &NodeKey, from: NodeNumber) -> bool {
        self.peer_number(key) == Some(from)
    }
}

/// `future`'s output, unless `limit` passes first.
async fn within<T>(limit: Duration, future: impl IntoFuture<Output = T>) -> Option<T> {
    async { Some(future.await) }
        .or(async {
            smol::Timer::after(limit).await;
            None
        })
        .await
}

fn transport(streams: u32, idle: Duration) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_uni_streams(VarInt::from_u32(streams))
        .max_concurrent_bidi_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u32(STREAM_WINDOW))
        .send_window(SEND_WINDOW)
        .max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(idle).expect("an idle timeout checked at bind"),
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
        let held = link
            .queued
            .try_hold(class, frame.len())
            .ok_or(Refused::Full)?;
        let outgoing = Outgoing {
            class,
            stream,
            frame,
            _held: held,
            queued: Instant::now(),
        };
        link.frames.try_send(outgoing).map_err(|_| Refused::Closed)
    }

    fn limits(&self) -> Limits {
        self.inner.limits
    }

    fn ready(&self, to: NodeNumber, class: Class) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let queued = self
            .inner
            .links
            .lock()
            .expect("the links")
            .get(&to)
            .map(|link| Arc::clone(&link.queued));
        Box::pin(async move {
            if let Some(queued) = queued {
                queued.room(class).await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_that_takes_no_frame_is_refused() {
        let config = || Config::new(1, [1; 32], "127.0.0.1:0".parse().unwrap());
        let refused = |config: Config| {
            Quic::bind(config).err().map(|error| error.kind()) == Some(io::ErrorKind::InvalidInput)
        };
        assert!(refused(Config {
            streams: 0,
            ..config()
        }));
        assert!(refused(Config {
            assembling: 0,
            ..config()
        }));
        assert!(refused(Config {
            limits: Limits {
                liveness: 0,
                ..Limits::default()
            },
            ..config()
        }));
        assert!(refused(Config {
            idle: Duration::from_secs(u64::MAX / 2),
            ..config()
        }));
        assert!(Quic::bind(config()).is_ok());
    }
}
