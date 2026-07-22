//! # Merkle-CRDTs
//!
//! A generic `no_std` implementation of [Merkle-CRDTs](https://arxiv.org/abs/2004.00107),
//! a transport and persistence layer for Conflict-Free Replicated Data Types (CRDTs) built
//! on Merkle-DAGs.
//!
//! ## Key Ideas
//!
//! - **Merkle-Clock**: A Merkle-DAG used as a logical clock. Each node represents an event,
//!   and new events become root nodes pointing to previous roots. Merging two clocks is
//!   simply the union of their DAG node sets — a Grow-Only Set (G-Set) CRDT.
//!
//! - **Merkle-CRDT**: A Merkle-Clock whose nodes carry CRDT payloads. The DAG structure
//!   provides causal ordering, content-addressing enables efficient sync, and the whole
//!   system works without coordination between replicas.
//!
//! The Merkle-DAG is causal transport and durable storage; it does **not** make an
//! arbitrary payload convergent. `Payload::apply` must itself implement a CRDT whose
//! result is independent of every valid causal replay order. Command logs that overwrite
//! ordinary mutable state are not CRDTs.
//!
//! ## Properties
//!
//! - **Transport-agnostic**: works over any network (DHT, PubSub, sneakernet)
//! - **No coordination**: replicas operate independently, sync when convenient
//! - **Self-verifying**: content-addressed nodes can be fetched from untrusted sources
//! - **Cryptographic deduplication**: identical events have identical CIDs
//! - **Cryptographic causal ordering**: the DAG encodes happened-before relationships
//!
//! ## Quick Example
//!
//! ```rust
//! use merkle_crdt::*;
//!
//! # struct H; impl Hasher for H { type Output = [u8; 32]; fn hash(d: &[u8]) -> [u8; 32] {
//! #   let mut o = [0u8; 32]; for (i, b) in d.iter().enumerate() { o[i % 32] ^= b; } o
//! # }}
//! // Define your CRDT operation
//! #[derive(Clone, Debug)]
//! struct AddItem(String);
//!
//! impl Encode for AddItem {
//!     fn encode_to(&self, buf: &mut Vec<u8>) { self.0.encode_to(buf); }
//! }
//!
//! impl Payload for AddItem {
//!     type State = std::collections::BTreeSet<String>;
//!     fn apply(state: &mut Self::State, op: &Self) { state.insert(op.0.clone()); }
//! }
//!
//! // Create two independent replicas
//! let mut alice: MerkleCrdt<H, AddItem, MemStore<H, AddItem>> = MerkleCrdt::default();
//! let mut bob: MerkleCrdt<H, AddItem, MemStore<H, AddItem>> = MerkleCrdt::default();
//!
//! alice.apply(AddItem("apple".into())).unwrap();
//! bob.apply(AddItem("banana".into())).unwrap();
//!
//! // Sync (in any order, any number of times)
//! let bob_roots: Vec<_> = bob.roots().iter().cloned().collect();
//! for root in bob_roots { alice.sync(&root, bob.store()).unwrap(); }
//! let alice_roots: Vec<_> = alice.roots().iter().cloned().collect();
//! for root in alice_roots { bob.sync(&root, alice.store()).unwrap(); }
//!
//! // Both replicas converge to the same state
//! assert_eq!(alice.state(), bob.state());
//! ```

#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod cid;
mod clock;
mod crdt;
mod encode;
mod hasher;
mod node;
mod store;
pub mod sync;

pub use cid::Cid;
pub use clock::MerkleClock;
pub use crdt::{MerkleCrdt, Payload};
pub use encode::{Decode, Encode};
pub use hasher::Hasher;
pub use node::DagNode;
pub use store::{MemStore, Store};
pub use sync::{AcceptAll, NodeValidator};

#[cfg(feature = "redb")]
mod store_redb;
#[cfg(feature = "redb")]
pub use store_redb::{RedbStore, RedbStoreError};

/// Error type for single-store operations.
#[derive(Debug)]
pub enum Error<E> {
    /// An error from the underlying store.
    Store(E),
    /// A referenced node was not found.
    MissingNode,
    /// Stored bytes do not match the content identifier under which they were found.
    InvalidCid,
    /// Reachable content-addressed nodes contain a causal cycle.
    InvalidDag,
    /// A stored node failed the application-provided author or payload policy.
    InvalidAuthor,
}

impl<E> From<E> for Error<E> {
    fn from(e: E) -> Self {
        Error::Store(e)
    }
}

impl<E: core::fmt::Display> core::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Store(e) => write!(f, "store error: {e}"),
            Error::MissingNode => write!(f, "referenced node not found in store"),
            Error::InvalidCid => write!(f, "stored node CID verification failed"),
            Error::InvalidDag => write!(f, "stored nodes contain a causal cycle"),
            Error::InvalidAuthor => write!(f, "stored node author validation failed"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: std::error::Error + 'static> std::error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Store(e) => Some(e),
            Error::MissingNode | Error::InvalidCid | Error::InvalidDag | Error::InvalidAuthor => {
                None
            }
        }
    }
}
