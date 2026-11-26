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
//!   node spends a handshake on it, and handshakes are bounded per address
//!   and in all (`Handshakes`).
//! - **Restarts.** The name a node dials with carries its incarnation: a
//!   peer dialing in as a new incarnation also closes this node's
//!   connection to the old one, which redials.
//! - **Streams** are unidirectional, sent by class priority. One opens
//!   with its class and id, then carries frames, each a length (u32,
//!   big-endian) and its bytes.
//! - **Flow control.** The connection's receive window is unlimited, so a
//!   few unread streams cannot stall the rest: what quinn buffers for a
//!   peer's streams not being read is bounded by [`Config::streams`] times
//!   a stream's window (`STREAM_WINDOW`). A frame takes its bytes from its
//!   peer's budget for its class ([`Config::assembling`]) before it is
//!   read: past it, a stream waits unread, which flow control pushes back
//!   to the sender.
//! - No keepalives: a connection is kept up by what is sent on it. An
//!   idle connection closes after [`IDLE`], and the next send redials.

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

use crate::tls::{Identity, Table};
use crate::{Arrivals, Class, Classes, Deliver, Network, NodeKey, Peer, Refused, arrivals};

mod admit;
mod executor;
mod receive;
mod send;

use admit::Admission;
pub use executor::{Runner, Runtime, Spawner};
use receive::accept;
use send::{Link, Outgoing};

/// An idle connection closes after this long.
pub const IDLE: Duration = Duration::from_secs(30);
/// What one stream may have in flight unread.
const STREAM_WINDOW: u32 = 1 << 20;
/// What a connection may have in flight unacknowledged, for every stream:
/// well above the share of the streams of single frames, so they never
/// fill it.
const SEND_WINDOW: u64 = 16 << 20;
/// Frames of classes of streams per frame in flight at once on one
/// connection, of every such class together.
const FRAME_STREAMS: usize = 4;
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

/// The protocol an endpoint speaks, the caller's: its name, and the
/// domain its keys are derived under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Protocol {
    /// The ALPN protocol name, 1 to 255 bytes: an endpoint takes only a
    /// connection that names it.
    pub alpn: Vec<u8>,
    /// What the endpoint's stateless-reset key and the mark on its
    /// connection ids are derived under, from the node's secret, before a
    /// label of each key's and the ALPN name: so the keys of one secret's
    /// endpoints differ by protocol, and an application's differ from
    /// every other use of the secret it makes.
    pub domain: Vec<u8>,
}

impl Protocol {
    fn check(&self) -> io::Result<()> {
        if self.alpn.is_empty() || self.alpn.len() > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an ALPN name of 1 to 255 bytes",
            ));
        }
        Ok(())
    }
}

/// A node's endpoint.
pub struct Config {
    /// The node's secret seed: its key, and what its stateless-reset and
    /// connection-id keys are derived from.
    pub secret: [u8; 32],
    pub listen: SocketAddr,
    pub protocol: Protocol,
    pub classes: Classes,
    pub peers: Vec<Peer>,
    /// Streams a peer may hold open at once on its connection to this
    /// node: a long-lived stream per busy id and class, and the streams of
    /// single frames. More wait for one to finish. Times a stream's window, it
    /// bounds what a peer's streams not being read hold.
    pub streams: u32,
    /// A long-lived stream quiet for this long is finished, so streams
    /// held open are those of ids busy lately.
    pub quiet: Duration,
    /// A connection quiet for this long closes: [`IDLE`] by default.
    pub idle: Duration,
    /// The bytes of one class's frames a peer may have this node assemble
    /// at once, in that class's largest frames (and `BUDGET_FLOOR` at
    /// least): `ASSEMBLING` by default.
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
    pub fn new(secret: [u8; 32], listen: SocketAddr, protocol: Protocol, classes: Classes) -> Self {
        Self {
            secret,
            listen,
            protocol,
            classes,
            peers: Vec::new(),
            streams: STREAMS,
            quiet: QUIET,
            idle: IDLE,
            assembling: ASSEMBLING,
        }
    }

    /// Refuse what would panic, stall or never take a frame.
    fn check(&self) -> io::Result<()> {
        let refuse = |what: &str| Err(io::Error::new(io::ErrorKind::InvalidInput, what.to_owned()));
        self.protocol.check()?;
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
/// to `CLOSING` for the peers to hear it (blocking the thread that drops
/// it), and stops every task.
pub struct Quic {
    inner: Arc<Inner>,
    _accept: smol::Task<()>,
    /// Dropped last: it stops the network's thread.
    _runner: Runner,
}

struct Inner {
    identity: Identity,
    /// The name this run dials with: its incarnation.
    name: String,
    endpoint: quinn::Endpoint,
    /// What this node dials with: the dialed side may open no stream.
    dialing: Arc<quinn::TransportConfig>,
    table: Table,
    links: Mutex<HashMap<NodeKey, Link>>,
    /// Each configured key's connection into this node.
    inbound: Mutex<HashMap<NodeKey, quinn::Connection>>,
    admission: Arc<Admission>,
    deliver: Deliver,
    classes: Classes,
    alpn: Vec<u8>,
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
        let server = identity.server(Arc::clone(&table), &config.protocol.alpn, accepting);
        let socket = std::net::UdpSocket::bind(config.listen)?;
        let runner = Runner::start()?;
        let endpoint = quinn::Endpoint::new(
            identity.endpoint(&config.protocol),
            Some(server),
            socket,
            Arc::new(Runtime(runner.spawner())),
        )?;
        let mut incarnation = [0u8; 8];
        ring::rand::SystemRandom::new()
            .fill(&mut incarnation)
            .map_err(|_| io::Error::other("no randomness"))?;
        let (deliver, arrivals) = arrivals(&config.classes);
        let inner = Arc::new(Inner {
            identity,
            name: format!("vos-{:016x}", u64::from_be_bytes(incarnation)),
            endpoint,
            dialing,
            table,
            links: Mutex::new(HashMap::new()),
            inbound: Mutex::new(HashMap::new()),
            admission: Arc::new(Admission::new(Handshakes::default())),
            deliver,
            classes: config.classes,
            alpn: config.protocol.alpn,
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

    /// Replace the peer table, without a restart: a peer gone loses its
    /// connections, both ways, and one at a new address the connection
    /// this node dialed. Frames it sent that are already in the arrival
    /// queues stay there. Of peers listed twice under one key, the last
    /// counts; this node's own key is left out.
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
        let own = self.identity.key;
        let peers: HashMap<NodeKey, Peer> = peers
            .into_iter()
            .filter(|peer| peer.key != own)
            .map(|peer| (peer.key, peer))
            .collect();
        let mut links = self.links.lock().expect("the links");
        let table: std::collections::HashSet<NodeKey> = peers.keys().copied().collect();
        let listed: Vec<Peer> = peers.values().cloned().collect();
        self.admission.set_peers(&listed);
        *self.table.write().expect("the peer table") = table.clone();
        // A key gone loses its connection into this node, and what its
        // readers hold.
        self.inbound
            .lock()
            .expect("the inbound connections")
            .retain(|key, connection| {
                let kept = table.contains(key);
                if !kept {
                    connection.close(code::UNCONFIGURED, b"");
                }
                kept
            });
        let mut kept = HashMap::new();
        for (key, peer) in peers {
            let link = match links.remove(&key) {
                Some(link) if link.peer == peer && !link.task.is_finished() => link,
                _ => Link::spawn(self, peer),
            };
            kept.insert(key, link);
        }
        // Dropping a link stops its task, which closes its connection.
        *links = kept;
    }

    /// Peer `from` dialed in with `name`: if that is a new incarnation,
    /// this node's connection to it reached the old one.
    fn dialed_in(&self, from: &NodeKey, name: Option<String>) {
        let mut links = self.links.lock().expect("the links");
        let Some(link) = links.get_mut(from) else {
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

    /// `connection`, just authenticated as `key`'s: whether the key is
    /// configured, and then the connection takes the place of the key's
    /// earlier one into this node, which closes. The table is read under
    /// the inbound connections' lock, so a removal that comes meanwhile
    /// finds the connection and closes it.
    fn dialed(&self, key: NodeKey, connection: &quinn::Connection) -> bool {
        let mut inbound = self.inbound.lock().expect("the inbound connections");
        if !self.configured(&key) {
            return false;
        }
        if let Some(earlier) = inbound.insert(key, connection.clone()) {
            earlier.close(code::REPLACED, b"");
        }
        true
    }

    /// `connection`, `key`'s, ended: forget it, unless a newer one took
    /// its place.
    fn hung_up(&self, key: &NodeKey, connection: &quinn::Connection) {
        let mut inbound = self.inbound.lock().expect("the inbound connections");
        if inbound
            .get(key)
            .is_some_and(|held| held.stable_id() == connection.stable_id())
        {
            inbound.remove(key);
        }
    }

    /// Whether a configured peer has `key`.
    fn configured(&self, key: &NodeKey) -> bool {
        self.table.read().expect("the peer table").contains(key)
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
    fn send(&self, to: NodeKey, class: Class, stream: u64, frame: Vec<u8>) -> Result<(), Refused> {
        if self.inner.classes.get(class).is_none() {
            return Err(Refused::UnknownClass);
        }
        if frame.len() > self.inner.classes.max_frame(class) {
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

    fn classes(&self) -> Classes {
        self.inner.classes.clone()
    }

    fn ready(&self, to: NodeKey, class: Class) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let queued = self
            .inner
            .links
            .lock()
            .expect("the links")
            .get(&to)
            .filter(|_| self.inner.classes.get(class).is_some())
            .map(|link| Arc::clone(&link.queued));
        Box::pin(async move {
            if let Some(queued) = queued {
                queued.room(class).await;
            }
        })
    }
}

/// The accepting side of protocol `alpn` for the node whose secret seed
/// is `secret`, taking a dialing side whose key `allowed` takes, with TLS
/// 1.3 bound to node keys as between peers. No session resumes: every
/// handshake checks the key. Address validation, bounds on handshakes and
/// connections, and migration are the caller's.
pub fn server_config(
    secret: &[u8; 32],
    alpn: &[u8],
    allowed: impl Fn(&NodeKey) -> bool + Send + Sync + 'static,
    transport: Arc<quinn::TransportConfig>,
) -> quinn::ServerConfig {
    Identity::new(secret).server_with(Arc::new(allowed), alpn, transport)
}

/// The dialing side of protocol `alpn` for the node whose secret seed is
/// `secret`, pinned to the accepting side whose key is `server`.
pub fn client_config(
    secret: &[u8; 32],
    alpn: &[u8],
    server: NodeKey,
    transport: Arc<quinn::TransportConfig>,
) -> quinn::ClientConfig {
    Identity::new(secret).client_with(alpn, server, transport)
}

/// The endpoint's configuration of `protocol` for the node whose secret
/// seed is `secret`, as a [`Quic`] endpoint's: QUIC version 1, its
/// stateless resets and connection ids keyed by the secret and the
/// protocol, apart from the secret's endpoints of other protocols.
pub fn endpoint_config(secret: &[u8; 32], protocol: &Protocol) -> quinn::EndpointConfig {
    Identity::new(secret).endpoint(protocol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClassSpec, Streams};

    #[test]
    fn configuration_that_takes_no_frame_is_refused() {
        let classes = Classes::new([ClassSpec {
            priority: 0,
            max_frame: 1,
            arrivals: 1,
            streams: Streams::PerId,
            max_age: None,
        }])
        .unwrap();
        let protocol = Protocol {
            alpn: b"test/1".to_vec(),
            domain: b"test/".to_vec(),
        };
        let config = || {
            Config::new(
                [1; 32],
                "127.0.0.1:0".parse().unwrap(),
                protocol.clone(),
                classes.clone(),
            )
        };
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
            idle: Duration::from_secs(u64::MAX / 2),
            ..config()
        }));
        for alpn in [Vec::new(), vec![b'a'; 256]] {
            assert!(refused(Config {
                protocol: Protocol {
                    alpn,
                    ..protocol.clone()
                },
                ..config()
            }));
        }
        assert!(Quic::bind(config()).is_ok());
    }
}
