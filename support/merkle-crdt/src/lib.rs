//! # Merkle-CRDTs
//!
//! A `no_std` implementation of [Merkle-CRDTs](https://arxiv.org/abs/2004.00107):
//! one scope's operations as a Merkle-DAG, each node a batch of operations
//! signed by its author, applied to a storage-backed CRDT in causal order.
//!
//! - **Nodes** ([`Node`]) are content-addressed: a node's [`Cid`] is the
//!   hash of its bytes, and it names its parents by theirs. Its payload
//!   ([`Signed`]) carries its author's key, the author's sequence number
//!   and an ed25519 signature over the operations and the parents.
//! - **A replica** ([`Replica`]) applies only the nodes it has not applied,
//!   in causal order, onto the rows it already has; a node whose parents
//!   are missing is held until they arrive. A local operation is applied
//!   in place. Each batch is one atomic [`Store`] commit.
//! - **Authors' chains**: an author numbers its nodes from 0, each naming
//!   the previous among its parents. Two nodes at one number are an
//!   [`Equivocation`]: both kept, reported, and filtered by the CRDT's reads.
//! - **Fetching** is batched ([`sync`]): from a peer that walks the DAG,
//!   by wanted CIDs and each author's highest number, or from a cursor over
//!   a server that only numbers what it accepted.
//! - **The CRDT** ([`Apply`]) writes only through [`Rows`], so its state
//!   commits with the nodes it came from; [`rebuild`] replays a whole DAG
//!   for recovery and audits.
//!
//! The DAG gives causal delivery, not convergence: [`Apply`] must give the
//! same rows for every causal order of the same nodes.
//!
//! ```
//! use merkle_crdt::{Event, Hasher, MemStore, Replica, Rows};
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
//! let phone_key = SigningKey::from_bytes(&[1; 32]);
//! let laptop_key = SigningKey::from_bytes(&[2; 32]);
//! let mut phone = Replica::<H, String, _>::open(MemStore::new()).unwrap();
//! let mut laptop = Replica::<H, String, _>::open(MemStore::new()).unwrap();
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

mod apply;
mod cid;
mod encode;
mod hasher;
mod node;
mod rebuild;
mod replica;
mod signed;
mod store;
pub mod sync;

#[cfg(feature = "fjall")]
mod store_fjall;

pub use apply::{Apply, Event, Rows};
pub use cid::Cid;
pub use encode::{Decode, Encode};
pub use hasher::Hasher;
pub use node::{DagNode, Header};
pub use rebuild::{Rebuilt, rebuild};
pub use replica::{Equivocation, Error, Ingested, Outgoing, Replica};
pub use signed::{Author, Node, Refusal, Signed, message, validate};
pub use store::{Applied, Changes, Loaded, MemStore, Store};

#[cfg(feature = "fjall")]
pub use store_fjall::{FjallError, FjallStore};
