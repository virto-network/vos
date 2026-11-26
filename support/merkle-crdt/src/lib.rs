//! # merkle-crdt
//!
//! A `no_std` replica for operation-based Merkle-CRDTs, after Sanjuán et
//! al., [*Merkle-CRDTs: Merkle-DAGs meet CRDTs*](https://arxiv.org/abs/2004.00107):
//! one scope's operations as a Merkle-DAG, each node a batch of operations
//! signed by its author, applied to a storage-backed CRDT in causal order.
//!
//! The DAG and the apply (each node once, after its parents) are the
//! paper's. The authors' signed, numbered chains, the equivocations and
//! the bounds are not in it. Its DAG-Syncer and Broadcaster, which fetch
//! and announce nodes, are the caller's. The paper's children are the
//! parents here, and its roots the heads.
//!
//! - **Nodes** ([`Node`]) are content-addressed: a node's [`Cid`] is the
//!   hash of its bytes, and it names its parents by theirs. It carries its
//!   author's key, the author's sequence number and an ed25519 signature
//!   over the scope, the author, the number, the operations and the
//!   parents.
//! - **A replica** ([`Replica`]) applies only the nodes it has not applied,
//!   in causal order, onto the rows it already has; a node whose parents
//!   are missing is held until they arrive. A local operation is applied
//!   in place. Each batch is one atomic [`Store`] commit.
//! - **Storage** is the caller's: it implements [`Store`] over its own
//!   database, and may carry its own writes in the same commit.
//!   [`MemStore`] keeps a scope in memory, for tests.
//! - **Authors' chains**: an author numbers its nodes from 0, each naming
//!   the previous among its parents. Two nodes at one number are an
//!   [`Equivocation`]: both kept, reported, and filtered by the CRDT's reads.
//! - **Fetching** is the caller's, sans I/O: it delivers nodes' bytes to
//!   [`Replica::ingest`] in any batching. A node that arrives before its
//!   parents is held, up to the held bounds ([`MAX_HELD`]); past them it is
//!   dropped and must be delivered again. [`Replica::wanted`] names the
//!   parents missing, [`Replica::have`] and [`Replica::cursor`] where to
//!   go on from: a gap longer than the bounds is fetched oldest first, or
//!   delivered in one batch, which orders any number of nodes itself.
//! - **The CRDT** ([`Apply`]) writes only through [`Rows`], so its state
//!   commits with the nodes it came from.
//!
//! Replicas that applied the same nodes have the same DAG and the same
//! heads. Their rows are the same only if [`Apply`] gives the same rows
//! for every causal order of the same nodes, whichever of two
//! equivocating nodes came second.
//!
//! Every ed25519 key is an author: the library admits any node whose
//! signature checks. A caller whose scope has a set of writers checks a
//! node's author ([`validate`], then [`Header::read`]) before it hands the
//! node to [`Replica::ingest`].
//!
//! ```
//! use merkle_crdt::{Event, Hasher, MemStore, Replica, Rows, Scope};
//! use ed25519_dalek::SigningKey;
//!
//! # struct H; impl Hasher for H { type Output = [u8; 32]; fn hash(d: &[u8]) -> [u8; 32] {
//! #   let mut o = [0u8; 32]; for (i, b) in d.iter().enumerate() { o[i % 32] ^= b.rotate_left(i as u32 % 8); } o
//! # }}
//! // A grow-only set of strings, one row an element.
//! fn add(event: Event<'_, H, String>, rows: &mut dyn Rows) {
//!     rows.write(event.ops.as_bytes(), Some(&[]));
//! }
//!
//! const SCOPE: Scope = Scope([1; 16]);
//! let phone_key = SigningKey::from_bytes(&[1; 32]);
//! let laptop_key = SigningKey::from_bytes(&[2; 32]);
//! let mut phone = Replica::<H, String, _>::open(MemStore::new(), SCOPE).unwrap();
//! let mut laptop = Replica::<H, String, _>::open(MemStore::new(), SCOPE).unwrap();
//!
//! phone.record(&phone_key, "eggs".into(), &mut add).unwrap();
//! laptop.record(&laptop_key, "milk".into(), &mut add).unwrap();
//!
//! // Each pushes its outbox; the other ingests it, in one batch.
//! let to_laptop = phone.outbox().unwrap().into_iter().map(|node| node.bytes);
//! let to_phone = laptop.outbox().unwrap().into_iter().map(|node| node.bytes);
//! laptop.ingest(to_laptop, None, &mut add).unwrap();
//! phone.ingest(to_phone, None, &mut add).unwrap();
//!
//! assert_eq!(phone.store().rows(), laptop.store().rows());
//! assert_eq!(phone.heads(), laptop.heads());
//! ```

#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

// The README's example, compiled and run as a doc test.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct Readme;

mod apply;
mod cid;
mod encode;
mod hasher;
mod node;
mod replica;
mod signed;
mod store;

pub use apply::{Apply, Event, MAX_ROW_KEY, MAX_ROW_VALUE, Rows};
pub use cid::Cid;
pub use encode::{Decode, Encode, MAX_DECODE_ITEMS};
pub use hasher::Hasher;
pub use node::{Header, MAX_PARENTS, Node};
pub use replica::{
    Equivocation, Error, Ingested, MAX_HELD, MAX_HELD_BYTES, MAX_HELD_PER_AUTHOR, Outgoing, Replica,
};
pub use signed::{Author, Refusal, Scope, Validated, validate};
pub use store::{Applied, Changes, Loaded, MemStore, Store};
