//! A network of nodes that know each other by their ed25519 keys. It
//! carries frames of bytes; what they mean belongs to the layer above.
//!
//! - **Authenticated channels between node keys.** A peer is its ed25519
//!   key and its address; every arrival carries the authenticated key it
//!   came from, and a node takes frames only from the keys it lists.
//! - **Classes of traffic** the caller defines ([`Classes`]): each with
//!   its priority, its bound on a frame's size, its own bounded arrival
//!   queue, its streams, and an age past which a queued frame is dropped.
//!   A class is its index in the table.
//! - **Streams by id or by frame.** A class of [`Streams::PerId`] sends
//!   on a long-lived stream per id (the caller's), so one id's large frame
//!   never delays another's; one of [`Streams::PerFrame`] opens a stream
//!   per frame. Order holds within one id on one connection, and only
//!   there: a redial can reorder across the old and new connections. A
//!   frame is delivered at most once, and may be delivered long after it
//!   was sent: only a class with an age drops a frame for waiting.
//! - **What a peer can make a node hold is bounded in bytes:** the frames
//!   it has the node assemble, per class; the frames waiting for the
//!   consumer, per class for every peer; one inbound connection per key.
//!
//! [`quic::Quic`] runs it over QUIC with TLS 1.3 bound to node keys;
//! [`memory::Hub`] connects endpoints in one process, for tests.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

mod budget;
mod deliver;
pub mod memory;
pub mod quic;
mod tls;

use budget::{Budgets, FRAME_COST, Hold};
use deliver::{Deliver, arrivals};
pub use tls::{pkcs8, public_key, spki};

/// A node's ed25519 public key.
pub type NodeKey = [u8; 32];

/// A peer: its key, and where it is dialed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub key: NodeKey,
    pub address: SocketAddr,
}

/// A class of traffic: its index in the [`Classes`] table. It travels as
/// the byte that opens each stream.
pub type Class = u8;

/// The most classes a table holds.
pub const MAX_CLASSES: usize = 16;

/// How a class's frames take streams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Streams {
    /// A long-lived stream per id, so a stream's frames keep their order.
    /// A peer's send queue of the class holds four of its largest frames.
    PerId,
    /// A stream per frame. A peer's send queue of the class holds one of
    /// its largest frames, and a connection has four of its frames in
    /// flight at once.
    PerFrame,
}

/// A class of traffic as the caller defines it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassSpec {
    /// A stream of a higher priority is sent first.
    pub priority: i32,
    /// The most bytes a frame may hold, checked on send, and on receipt
    /// before anything is allocated. A frame's length travels as a `u32`,
    /// so a bound above it is taken as `u32::MAX`.
    pub max_frame: usize,
    /// The frames its arrival queue holds before a stream's reader waits
    /// for the consumer (and the sender, for flow control).
    pub arrivals: usize,
    pub streams: Streams,
    /// A frame that has waited in its peer's send queue longer than this
    /// when the connection takes it is dropped: for frames that say
    /// something only while they are fresh. A live connection takes each
    /// frame at once, so the age counts only a wait for a connection (a
    /// dial, a backoff, a redial); a frame the connection holds is not
    /// aged. `None` keeps every frame, however late; a zero age drops
    /// every frame that waited at all.
    pub max_age: Option<Duration>,
}

/// The caller's table of classes: class `n` is its `n`th entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classes(Arc<[ClassSpec]>);

/// The most frames a class's arrival queue may hold, which is allocated
/// when the queue is made.
pub const MAX_ARRIVALS: usize = 1 << 20;

/// Why a table of classes was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidClasses {
    /// No class, or more than [`MAX_CLASSES`].
    Count(usize),
    /// A class whose frames may hold no byte.
    NoFrame(Class),
    /// A class whose arrival queue holds no frame, or more than
    /// [`MAX_ARRIVALS`].
    NoArrival(Class),
}

impl std::fmt::Display for InvalidClasses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Count(count) => write!(f, "{count} classes, not 1 to {MAX_CLASSES}"),
            Self::NoFrame(class) => write!(f, "class {class}'s frame bound is 0"),
            Self::NoArrival(class) => write!(
                f,
                "class {class}'s arrival queue holds no frame, or more than {MAX_ARRIVALS}"
            ),
        }
    }
}

impl std::error::Error for InvalidClasses {}

impl Classes {
    /// A table of `classes`, refused if it would take no frame of some
    /// class.
    pub fn new(classes: impl Into<Vec<ClassSpec>>) -> Result<Self, InvalidClasses> {
        let classes: Vec<ClassSpec> = classes.into();
        if classes.is_empty() || classes.len() > MAX_CLASSES {
            return Err(InvalidClasses::Count(classes.len()));
        }
        for (class, spec) in (0..).zip(&classes) {
            if spec.max_frame == 0 {
                return Err(InvalidClasses::NoFrame(class));
            }
            if spec.arrivals == 0 || spec.arrivals > MAX_ARRIVALS {
                return Err(InvalidClasses::NoArrival(class));
            }
        }
        Ok(Self(classes.into()))
    }

    pub fn get(&self, class: Class) -> Option<&ClassSpec> {
        self.0.get(usize::from(class))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Never: a table holds one class at least.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Each class with its definition.
    pub fn iter(&self) -> impl Iterator<Item = (Class, &ClassSpec)> {
        (0..).zip(self.0.iter())
    }

    /// The bound on a frame of `class`, which the table holds.
    pub(crate) fn max_frame(&self, class: Class) -> usize {
        self.0[usize::from(class)].max_frame.min(u32::MAX as usize)
    }

    /// The budget of frames of `class` queued for one peer: four of its
    /// largest frames' worth, or one for a class of streams per frame.
    pub(crate) fn queue(&self, class: Class) -> usize {
        let frames = match self.0[usize::from(class)].streams {
            Streams::PerFrame => 1,
            Streams::PerId => 4,
        };
        self.max_frame(class).saturating_mul(frames)
    }

    /// `frames` of each class's largest frames, with what each costs
    /// beyond its bytes.
    fn frames(&self, frames: usize) -> Vec<usize> {
        self.iter()
            .map(|(class, _)| {
                self.max_frame(class)
                    .saturating_add(FRAME_COST)
                    .saturating_mul(frames)
            })
            .collect()
    }
}

/// A frame that arrived. It holds its place in its class's arrival
/// budget until it is dropped.
pub struct Incoming {
    /// The authenticated key it came from.
    pub from: NodeKey,
    pub stream: u64,
    pub frame: Vec<u8>,
    held: Option<Hold>,
}

impl Incoming {
    pub(crate) fn new(from: NodeKey, stream: u64, frame: Vec<u8>) -> Self {
        Self {
            from,
            stream,
            frame,
            held: None,
        }
    }
}

impl std::fmt::Debug for Incoming {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Incoming")
            .field("from", &self.from)
            .field("stream", &self.stream)
            .field("frame", &self.frame)
            .finish_non_exhaustive()
    }
}

/// Arrivals, a queue per class, which the consumer drains in an order of
/// its own (so a backlog of one class need never sit ahead of another).
/// Each queue is bounded in frames and in bytes; a frame counts against
/// the bytes until the consumer drops it.
pub struct Arrivals {
    queues: Box<[smol::channel::Receiver<Incoming>]>,
}

impl Arrivals {
    /// The queue of `class`.
    ///
    /// # Panics
    ///
    /// If the table has no class `class`.
    pub fn queue(&self, class: Class) -> &smol::channel::Receiver<Incoming> {
        &self.queues[usize::from(class)]
    }

    /// Every class's queue, by class.
    pub fn queues(&self) -> &[smol::channel::Receiver<Incoming>] {
        &self.queues
    }
}

/// Why a frame was not queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refused {
    /// The peer's queue is full: wait for [`Network::ready`], or drop.
    Full,
    /// No configured peer has that key.
    UnknownPeer,
    /// The table has no such class.
    UnknownClass,
    /// The frame is larger than its class allows.
    TooLarge,
    /// The link to the peer is down for good: its address cannot be
    /// dialed.
    Closed,
}

/// The network between this node and its peers, as a node sends on it.
pub trait Network: Send + Sync + 'static {
    /// Queue `frame` for `to` on stream `stream` of `class`. Never blocks:
    /// it refuses, and the caller decides whether to drop or retry.
    fn send(&self, to: NodeKey, class: Class, stream: u64, frame: Vec<u8>) -> Result<(), Refused>;

    /// Resolves once `to` can likely take another frame of `class`.
    fn ready(&self, to: NodeKey, class: Class) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;

    /// The classes it sends.
    fn classes(&self) -> Classes;
}

/// `key`'s first bytes, in hex, to name a peer in a log.
pub(crate) fn short(key: &NodeKey) -> String {
    key[..4].iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ClassSpec {
        ClassSpec {
            priority: 0,
            max_frame: 1,
            arrivals: 1,
            streams: Streams::PerId,
            max_age: None,
        }
    }

    #[test]
    fn a_table_that_takes_no_frame_of_a_class_is_refused() {
        assert_eq!(Classes::new([]), Err(InvalidClasses::Count(0)));
        assert_eq!(
            Classes::new([spec(); MAX_CLASSES + 1]),
            Err(InvalidClasses::Count(MAX_CLASSES + 1))
        );
        let no_frame = ClassSpec {
            max_frame: 0,
            ..spec()
        };
        assert_eq!(
            Classes::new([spec(), no_frame]),
            Err(InvalidClasses::NoFrame(1))
        );
        let no_arrival = ClassSpec {
            arrivals: 0,
            ..spec()
        };
        assert_eq!(
            Classes::new([no_arrival]),
            Err(InvalidClasses::NoArrival(0))
        );
        let too_many = ClassSpec {
            arrivals: MAX_ARRIVALS + 1,
            ..spec()
        };
        assert_eq!(Classes::new([too_many]), Err(InvalidClasses::NoArrival(0)));
        let classes = Classes::new([spec(); MAX_CLASSES]).unwrap();
        assert_eq!(classes.len(), MAX_CLASSES);
        assert!(classes.get(MAX_CLASSES as Class).is_none());
    }

    #[test]
    fn a_frame_bound_is_at_most_a_u32() {
        let classes = Classes::new([ClassSpec {
            max_frame: usize::MAX,
            ..spec()
        }])
        .unwrap();
        assert_eq!(classes.max_frame(0), u32::MAX as usize);
    }
}
