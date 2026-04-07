//! Pluggable data layer for VOS service continuations.
//!
//! Each service's canonical state is a serialized PVM image (see
//! [`crate::pvm_image`]). The runtime reads it before refine and
//! writes it back after. [`DataLayer`] abstracts that storage so
//! the backend can be in-process RAM, a local file, a LevelDB,
//! or — eventually — a real on-chain DA lane.
//!
//! The trait is `async` so disk- and network-backed implementations
//! can drop in without restructuring the runtime. The default
//! [`MemoryDataLayer`] implementation returns immediately.
//!
//! Zero-copy ownership: `get` returns an owned `Vec<u8>` so the caller
//! can `split_off` its tail into a fresh `Pvm`'s `flat_mem` without a
//! second copy; `put` takes ownership of the captured image.
//!
//! Despite the name, this is not (yet) a JAM data-availability lane —
//! VOS runs it locally today. The name is chosen with the expectation
//! that on-chain wiring will replace `MemoryDataLayer` with a backend
//! that pushes continuation blobs into a real DA bus so validators can
//! replay refine deterministically.

use alloc::vec::Vec;
use vos_abi::service::ServiceId;

#[cfg(feature = "std")]
use std::collections::HashMap;

/// Pluggable backend for service continuation images.
///
/// Implementations MUST be monotonic per `(service_id, image)`: a
/// `put` followed by a `get` must return the same bytes the caller
/// wrote. Beyond that the backend is free to evict, compress, replicate,
/// or shard however it likes.
pub trait DataLayer: Send + Sync {
    /// Fetch the current continuation image for `service`, or `None`
    /// if the service has never been suspended (or was explicitly
    /// removed).
    async fn get(&self, service: ServiceId) -> Option<Vec<u8>>;

    /// Store a new continuation image for `service`, replacing any
    /// prior image.
    async fn put(&mut self, service: ServiceId, image: Vec<u8>);

    /// Drop the continuation image for `service`. The next `get` must
    /// return `None`.
    async fn remove(&mut self, service: ServiceId);

    /// Synchronous `contains` check. Not async because runtimes call
    /// it on hot paths and every real backend can answer cheaply from
    /// an in-memory index. If a backend can't, it should block inside.
    fn contains(&self, service: ServiceId) -> bool;
}

// --- In-memory default ---

/// Default [`DataLayer`] implementation: a process-local `HashMap`.
///
/// Behaves exactly like the previous inline `continuations` map, with
/// the async interface faked (every method returns immediately). Use
/// this for tests, offline `vosx` runs, and as a reference for writing
/// real backends.
#[cfg(feature = "std")]
#[derive(Default)]
pub struct MemoryDataLayer {
    images: HashMap<u32, Vec<u8>>,
}

#[cfg(feature = "std")]
impl MemoryDataLayer {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(feature = "std")]
impl DataLayer for MemoryDataLayer {
    async fn get(&self, service: ServiceId) -> Option<Vec<u8>> {
        self.images.get(&service.0).cloned()
    }

    async fn put(&mut self, service: ServiceId, image: Vec<u8>) {
        self.images.insert(service.0, image);
    }

    async fn remove(&mut self, service: ServiceId) {
        self.images.remove(&service.0);
    }

    fn contains(&self, service: ServiceId) -> bool {
        self.images.contains_key(&service.0)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn memory_roundtrip() {
        let mut d = MemoryDataLayer::new();
        let id = ServiceId(7);
        assert!(pollster::block_on(d.get(id)).is_none());
        assert!(!d.contains(id));
        pollster::block_on(d.put(id, vec![1, 2, 3]));
        assert!(d.contains(id));
        assert_eq!(pollster::block_on(d.get(id)), Some(vec![1, 2, 3]));
        pollster::block_on(d.remove(id));
        assert!(!d.contains(id));
    }
}
