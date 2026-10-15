//! The network between VOS nodes. It knows nothing of consensus: a later
//! consensus for public spaces, or another transport, sits on the same
//! interface.
//!
//! - **Authenticated channels between node keys.** A node is its ed25519
//!   key; every arrival carries the authenticated peer it came from.
//! - **Classes of traffic** ([`Class`]), each with its priority, its own
//!   arrival queue and its own bound on a frame's size.
//! - **Streams by group or by message.** Liveness, Consensus and Requests
//!   frames travel on a long-lived stream per id (an agent's group), so
//!   one agent's large frame never delays another's; Bulk opens a stream
//!   per frame. Order holds within one stream on one connection, and only
//!   there: a redial can reorder across the old and new connections. A
//!   frame is delivered at most once.
//! - **Frames are bytes;** their meaning belongs to the layer above.
//!
//! [`quic::Quic`] runs it over QUIC with TLS 1.3 bound to node keys;
//! [`memory::Hub`] connects endpoints in one process, for tests.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

pub mod memory;
pub mod quic;
mod tls;

pub use tls::{pkcs8, public_key, spki};

/// A node of the space: the 8-bit node part of an agent id.
pub type NodeNumber = u8;

/// A node's public key.
pub type NodeKey = [u8; 32];

/// A peer as the configuration knows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub number: NodeNumber,
    pub key: NodeKey,
    pub address: SocketAddr,
}

/// A class of traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Class {
    /// Pair heartbeats, sent ahead of every other class.
    Liveness = 0,
    /// Consensus messages, a stream per group.
    Consensus = 1,
    /// Client requests forwarded, and messages between agents, a stream
    /// per agent so a session's pipelined requests keep their order.
    Requests = 2,
    /// Blobs and snapshot chunks, a stream per frame.
    Bulk = 3,
}

impl Class {
    pub const ALL: [Class; 4] = [
        Class::Liveness,
        Class::Consensus,
        Class::Requests,
        Class::Bulk,
    ];

    fn from_u8(byte: u8) -> Option<Self> {
        Self::ALL.get(usize::from(byte)).copied()
    }

    /// The stream priority: higher is sent first.
    fn priority(self) -> i32 {
        Class::Bulk as i32 - self as i32
    }

    /// Whether a frame opens a stream of its own.
    fn stream_per_frame(self) -> bool {
        self == Class::Bulk
    }
}

/// The most bytes a frame of each class may hold, checked on receipt
/// before anything is allocated. A frame's length travels as a `u32`, so
/// no bound goes above it.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub liveness: usize,
    pub consensus: usize,
    pub requests: usize,
    pub bulk: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Limits {
    pub const DEFAULT: Self = Self {
        liveness: 64 << 10,
        // An append: entries up to the 1 MiB append cap, or one larger
        // entry alone, with their envelope. A work result of 64 KiB or more
        // travels as a blob, so this leaves room to spare.
        consensus: 5 << 20,
        requests: 1 << 20,
        // A 64 MiB program, with its header.
        bulk: (64 << 20) + (64 << 10),
    };
}

impl Limits {
    fn of(&self, class: Class) -> usize {
        let limit = match class {
            Class::Liveness => self.liveness,
            Class::Consensus => self.consensus,
            Class::Requests => self.requests,
            Class::Bulk => self.bulk,
        };
        limit.min(u32::MAX as usize)
    }

    /// The budget of frames of `class` waiting for one peer: four of the
    /// largest frames' worth, or one bulk frame's. A queue under its budget
    /// takes one frame more.
    fn queue(&self, class: Class) -> usize {
        match class {
            Class::Bulk => self.bulk,
            class => 4 * self.of(class),
        }
    }
}

/// A frame that arrived.
#[derive(Debug, PartialEq, Eq)]
pub struct Incoming {
    /// The authenticated peer it came from.
    pub from: NodeNumber,
    pub stream: u64,
    pub frame: Vec<u8>,
}

/// Arrivals, a queue per class: a consumer drains Liveness and Consensus
/// first, so a backlog of bulk never sits ahead of a heartbeat.
pub struct Arrivals {
    pub liveness: smol::channel::Receiver<Incoming>,
    pub consensus: smol::channel::Receiver<Incoming>,
    pub requests: smol::channel::Receiver<Incoming>,
    pub bulk: smol::channel::Receiver<Incoming>,
}

/// The sending half of [`Arrivals`].
#[derive(Clone)]
pub(crate) struct Deliver {
    queues: [smol::channel::Sender<Incoming>; 4],
}

/// How many frames each class's arrival queue holds before a stream's
/// reader waits for the consumer (and the sender, for flow control).
const ARRIVALS: usize = 1024;
/// Bulk frames are large: few wait.
const BULK_ARRIVALS: usize = 16;

pub(crate) fn arrivals() -> (Deliver, Arrivals) {
    let (liveness, liveness_rx) = smol::channel::bounded(ARRIVALS);
    let (consensus, consensus_rx) = smol::channel::bounded(ARRIVALS);
    let (requests, requests_rx) = smol::channel::bounded(ARRIVALS);
    let (bulk, bulk_rx) = smol::channel::bounded(BULK_ARRIVALS);
    (
        Deliver {
            queues: [liveness, consensus, requests, bulk],
        },
        Arrivals {
            liveness: liveness_rx,
            consensus: consensus_rx,
            requests: requests_rx,
            bulk: bulk_rx,
        },
    )
}

impl Deliver {
    /// Hand an arrival over, waiting while its class's queue is full.
    pub(crate) async fn deliver(&self, class: Class, incoming: Incoming) -> bool {
        self.queues[class as usize].send(incoming).await.is_ok()
    }

    pub(crate) fn try_deliver(
        &self,
        class: Class,
        incoming: Incoming,
    ) -> Result<(), smol::channel::TrySendError<Incoming>> {
        self.queues[class as usize].try_send(incoming)
    }

    /// Whether a frame of `class` would be taken now, or dropped because
    /// the consumer is gone: either way, not a wait.
    pub(crate) fn has_room(&self, class: Class) -> bool {
        let queue = &self.queues[class as usize];
        queue.is_closed() || !queue.is_full()
    }
}

/// Why a frame was not queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The peer's queue is full: wait for [`Network::ready`], or drop.
    Full,
    /// No configured peer has that number.
    UnknownPeer,
    /// The frame is larger than its class allows.
    TooLarge,
    /// The link to the peer is down for good: its address cannot be
    /// dialed.
    Closed,
}

/// The network between this node and its peers, as a node sends on it.
pub trait Network: Send + Sync + 'static {
    /// Queue `frame` for `to` on stream `stream` of `class`. Never blocks:
    /// it refuses, and the caller decides (Raft drops; a forward or a bulk
    /// transfer retries).
    fn send(
        &self,
        to: NodeNumber,
        class: Class,
        stream: u64,
        frame: Vec<u8>,
    ) -> Result<(), Refused>;

    /// Resolves once `to` can likely take another frame of `class`.
    fn ready(&self, to: NodeNumber, class: Class) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}
