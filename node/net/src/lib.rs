//! The network between VOS nodes. It knows nothing of consensus; the
//! defaults of [`Limits`] are what a VOS node sends.
//!
//! - **Authenticated channels between node keys.** A node is its ed25519
//!   key; every arrival carries the authenticated peer it came from.
//! - **Classes of traffic** ([`Class`]), each with its priority, its own
//!   arrival queue and its own bound on a frame's size.
//! - **Streams by id or by message.** Liveness, Consensus and Requests
//!   frames travel on a long-lived stream per id (the caller's: a node
//!   folds its groups onto a bounded set of lanes), so one id's large
//!   frame never delays another's; Bulk opens a stream per frame. Order
//!   holds within one id on one connection, and only there: a redial can
//!   reorder across the old and new connections. A frame is delivered at
//!   most once, and may be delivered long after it was sent: only a
//!   Liveness frame is dropped for its age.
//! - **What a peer can make a node hold is bounded in bytes:** the frames
//!   it has the node assemble, per class; the frames waiting for the
//!   consumer, per class for every peer; one inbound connection per key.
//! - **Frames are bytes;** their meaning belongs to the layer above.
//!
//! [`quic::Quic`] runs it over QUIC with TLS 1.3 bound to node keys;
//! [`memory::Hub`] connects endpoints in one process, for tests.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use smol::future::FutureExt;

pub mod api;
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
    /// Consensus messages, a stream per id.
    Consensus = 1,
    /// Client requests forwarded, and messages between agents, a stream
    /// per id, so a session's pipelined requests keep their order.
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

    pub(crate) fn of(&self, class: Class) -> usize {
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
            Class::Bulk => self.of(class),
            class => self.of(class).saturating_mul(4),
        }
    }

    /// `frames` of `class`'s largest frames, with what each costs beyond
    /// its bytes.
    fn frames(&self, class: Class, frames: usize) -> usize {
        self.of(class)
            .saturating_add(FRAME_COST)
            .saturating_mul(frames)
    }
}

/// What a frame costs beyond its bytes, so empty frames are bounded too.
pub(crate) const FRAME_COST: usize = 64;

/// Bytes held per class under a budget each, and a wakeup whenever some
/// are let go.
pub(crate) struct Budgets {
    held: [AtomicUsize; 4],
    budgets: [usize; 4],
    /// Per class, so a frame let go wakes only its own class's waiters.
    released: [event_listener::Event; 4],
}

/// The least a budget holds, so classes of small frames still take many.
const BUDGET_FLOOR: usize = 1 << 20;

impl Budgets {
    /// A budget of `frames` of each class's largest frames.
    pub(crate) fn new(limits: &Limits, frames: usize) -> Arc<Self> {
        Self::with(Class::ALL.map(|class| limits.frames(class, frames).max(BUDGET_FLOOR)))
    }

    /// A budget of `budgets[class]` bytes for each class.
    pub(crate) fn with(budgets: [usize; 4]) -> Arc<Self> {
        Arc::new(Self {
            held: Default::default(),
            budgets,
            released: Default::default(),
        })
    }

    /// Hold a frame of `bytes` while the class is under its budget: one
    /// under it takes one frame more, as a peer's send queue does.
    pub(crate) fn try_hold(self: &Arc<Self>, class: Class, bytes: usize) -> Option<Hold> {
        let cost = bytes.saturating_add(FRAME_COST);
        let budget = self.budgets[class as usize];
        self.held[class as usize]
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                (held < budget).then(|| held.saturating_add(cost))
            })
            .ok()?;
        Some(Hold {
            budgets: Some(Arc::clone(self)),
            class,
            cost,
        })
    }

    /// Hold a frame of `bytes`, waiting until it fits.
    pub(crate) async fn hold(self: &Arc<Self>, class: Class, bytes: usize) -> Hold {
        loop {
            let released = self.released[class as usize].listen();
            if let Some(hold) = self.try_hold(class, bytes) {
                return hold;
            }
            released.await;
        }
    }

    pub(crate) fn has_room(&self, class: Class) -> bool {
        self.held[class as usize].load(Ordering::Acquire) < self.budgets[class as usize]
    }

    /// Resolves once the class is under its budget.
    pub(crate) async fn room(&self, class: Class) {
        loop {
            let released = self.released[class as usize].listen();
            if self.has_room(class) {
                return;
            }
            released.await;
        }
    }
}

/// A frame's bytes held under a budget, let go when dropped.
pub(crate) struct Hold {
    budgets: Option<Arc<Budgets>>,
    class: Class,
    cost: usize,
}

impl Hold {
    /// Nothing held.
    pub(crate) fn none() -> Self {
        Self {
            budgets: None,
            class: Class::Liveness,
            cost: 0,
        }
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        if let Some(budgets) = self.budgets.take() {
            budgets.held[self.class as usize].fetch_sub(self.cost, Ordering::AcqRel);
            budgets.released[self.class as usize].notify(usize::MAX);
        }
    }
}

/// A frame that arrived. It holds its place in its class's arrival
/// budget until it is dropped.
pub struct Incoming {
    /// The authenticated peer it came from.
    pub from: NodeNumber,
    pub stream: u64,
    pub frame: Vec<u8>,
    held: Hold,
}

impl Incoming {
    pub(crate) fn new(from: NodeNumber, stream: u64, frame: Vec<u8>) -> Self {
        Self {
            from,
            stream,
            frame,
            held: Hold::none(),
        }
    }
}

impl std::fmt::Debug for Incoming {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Incoming")
            .field("from", &self.from)
            .field("stream", &self.stream)
            .field("frame", &self.frame)
            .finish()
    }
}

/// Arrivals, a queue per class: a consumer drains Liveness and Consensus
/// first, so a backlog of bulk never sits ahead of a heartbeat. Each
/// queue is bounded in frames and in bytes; a frame counts against the
/// bytes until the consumer drops it.
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
    waiting: Arc<Budgets>,
}

/// How many frames each class's arrival queue holds before a stream's
/// reader waits for the consumer (and the sender, for flow control).
const ARRIVALS: usize = 1024;
/// Bulk frames are large: few wait.
const BULK_ARRIVALS: usize = 16;
/// The bytes each class's arrival queue holds, unless configured
/// otherwise: this many of its largest frames.
pub(crate) const WAITING: usize = 4;

/// Arrival queues bounded in bytes by `waiting` of each class's largest
/// frames under `limits`.
pub(crate) fn arrivals(limits: &Limits, waiting: usize) -> (Deliver, Arrivals) {
    let (liveness, liveness_rx) = smol::channel::bounded(ARRIVALS);
    let (consensus, consensus_rx) = smol::channel::bounded(ARRIVALS);
    let (requests, requests_rx) = smol::channel::bounded(ARRIVALS);
    let (bulk, bulk_rx) = smol::channel::bounded(BULK_ARRIVALS);
    (
        Deliver {
            queues: [liveness, consensus, requests, bulk],
            waiting: Budgets::new(limits, waiting),
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
    pub(crate) async fn deliver(&self, class: Class, mut incoming: Incoming) -> bool {
        let queue = &self.queues[class as usize];
        let bytes = incoming.frame.len();
        let held = self.waiting.hold(class, bytes).or(async {
            // The consumer is gone: nothing it would read is held.
            queue.closed().await;
            Hold::none()
        });
        incoming.held = held.await;
        queue.send(incoming).await.is_ok()
    }

    pub(crate) fn try_deliver(
        &self,
        class: Class,
        mut incoming: Incoming,
    ) -> Result<(), smol::channel::TrySendError<Incoming>> {
        let queue = &self.queues[class as usize];
        if queue.is_closed() {
            return Err(smol::channel::TrySendError::Closed(incoming));
        }
        match self.waiting.try_hold(class, incoming.frame.len()) {
            Some(held) => incoming.held = held,
            None => return Err(smol::channel::TrySendError::Full(incoming)),
        }
        queue.try_send(incoming).map_err(|error| {
            let mut incoming = match error {
                smol::channel::TrySendError::Full(incoming)
                | smol::channel::TrySendError::Closed(incoming) => incoming,
            };
            incoming.held = Hold::none();
            match queue.is_closed() {
                true => smol::channel::TrySendError::Closed(incoming),
                false => smol::channel::TrySendError::Full(incoming),
            }
        })
    }

    /// Whether a frame of `class` would be taken now, or dropped because
    /// the consumer is gone: either way, not a wait.
    pub(crate) fn has_room(&self, class: Class) -> bool {
        let queue = &self.queues[class as usize];
        queue.is_closed() || (!queue.is_full() && self.waiting.has_room(class))
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

    /// The largest frame of each class it sends.
    fn limits(&self) -> Limits {
        Limits::DEFAULT
    }
}
