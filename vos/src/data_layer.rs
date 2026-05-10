//! Pluggable data layer for VOS service continuation bodies.
//!
//! In the CoreVM-on-JAM split, a service's persisted continuation has
//! two parts:
//!
//! - A small **header** (PC, registers, heap, commitment hash, …) that
//!   lives in the service's on-chain storage. See
//!   [`crate::pvm_image::ContinuationHeader`].
//! - A large **body** (the PVM `flat_mem` bytes) that lives in the
//!   data-availability layer, content-addressed by the blake2b hash of
//!   its bytes.
//!
//! [`DataLayer`] abstracts the body store. The default in-process
//! [`MemoryDataLayer`] is a `HashMap<[u8; 32], Vec<u8>>`. A real
//! backend (LevelDB, JAM DA, …) drops in by implementing the trait.
//!
//! The trait is `async` so disk- and network-backed implementations
//! can plug in without restructuring the runtime; the in-memory
//! default returns immediately.
//!
//! Despite the name, this is not (yet) a JAM data-availability lane —
//! VOS runs it locally today. The name is chosen so that on-chain
//! wiring will replace `MemoryDataLayer` with a backend that pushes
//! bodies into the real DA bus, and validators reassemble the
//! continuation from `(storage header, DA body)` exactly as on-chain
//! refine does.

use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::collections::HashMap;

/// Pluggable backend for content-addressed continuation bodies.
///
/// Implementations MUST be monotonic per `(commitment, body)`: a
/// `put` followed by a `get` must return the same bytes the caller
/// wrote. Beyond that the backend is free to dedup, evict cold blobs,
/// shard, replicate, etc. Because the keyspace is content-addressed,
/// two services that capture identical flat_mem will share one body —
/// no extra bookkeeping required.
pub trait DataLayer: Send + Sync {
    /// Fetch the body for `commitment`, or `None` if it isn't stored.
    async fn get(&self, commitment: &[u8; 32]) -> Option<Vec<u8>>;

    /// Store `body` under its commitment. The caller is responsible
    /// for ensuring `commitment == blake2b(body)`; the backend is
    /// allowed to assume this and skip the check.
    async fn put(&mut self, commitment: [u8; 32], body: Vec<u8>);

    /// Drop the body for `commitment`. Idempotent: removing an absent
    /// key is a no-op.
    async fn remove(&mut self, commitment: &[u8; 32]);

    /// Synchronous existence check. Hot-path-friendly: every real
    /// backend can answer cheaply from an in-memory index. If a
    /// backend can't, it should block inside.
    fn contains(&self, commitment: &[u8; 32]) -> bool;
}

// --- In-memory default ---

/// Default [`DataLayer`] implementation: a process-local `HashMap`
/// keyed by commitment.
#[cfg(feature = "std")]
#[derive(Default)]
pub struct MemoryDataLayer {
    bodies: HashMap<[u8; 32], Vec<u8>>,
}

#[cfg(feature = "std")]
impl MemoryDataLayer {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(feature = "std")]
impl DataLayer for MemoryDataLayer {
    async fn get(&self, commitment: &[u8; 32]) -> Option<Vec<u8>> {
        self.bodies.get(commitment).cloned()
    }

    async fn put(&mut self, commitment: [u8; 32], body: Vec<u8>) {
        self.bodies.insert(commitment, body);
    }

    async fn remove(&mut self, commitment: &[u8; 32]) {
        self.bodies.remove(commitment);
    }

    fn contains(&self, commitment: &[u8; 32]) -> bool {
        self.bodies.contains_key(commitment)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn memory_roundtrip() {
        let mut d = MemoryDataLayer::new();
        let k = [7u8; 32];
        assert!(pollster::block_on(d.get(&k)).is_none());
        assert!(!d.contains(&k));
        pollster::block_on(d.put(k, vec![1, 2, 3]));
        assert!(d.contains(&k));
        assert_eq!(pollster::block_on(d.get(&k)), Some(vec![1, 2, 3]));
        pollster::block_on(d.remove(&k));
        assert!(!d.contains(&k));
    }
}
