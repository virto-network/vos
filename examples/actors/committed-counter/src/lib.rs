//! Committed-counter — the `anchor_kind 0x02` fixture.
//!
//! The smallest actor with a `#[storage(committed)]` field: every
//! dispatch that touches `entries` moves its SMT root, the halt path
//! folds that root with the state-blob hash into the composite the
//! work-result anchors, and the host verifies the chain against the
//! recorded composite row. The e2e in `vos/tests/elf_integration.rs`
//! drives mutations across dispatches and cold restarts and checks the
//! guest-maintained root against a host-side full recompute.

use vos::prelude::*;
use vos::storage::CommittedMap;

#[actor]
struct CommittedCounter {
    /// Blob-resident control field — proves blob writes and committed
    /// rows anchor together: this travels in the state write, the map
    /// rows and their SMT nodes travel as row effects, one composite
    /// covers both.
    generation: u64,
    #[storage(committed)]
    entries: CommittedMap<u64, u64>,
}

#[messages]
impl CommittedCounter {
    fn new() -> Self {
        CommittedCounter {
            generation: 0,
            entries: Default::default(),
        }
    }

    /// Insert one entry. Replies 1 when the key is new, 0 on replace.
    #[msg]
    async fn put(&mut self, key: u64, value: u64) -> u64 {
        self.generation += 1;
        u64::from(self.entries.insert(&key, &value))
    }

    /// Point read; `u64::MAX` when absent.
    #[msg]
    async fn get(&mut self, key: u64) -> u64 {
        self.entries.get(&key).unwrap_or(u64::MAX)
    }

    /// Remove one entry. Replies 1 when it existed.
    #[msg]
    async fn del(&mut self, key: u64) -> u64 {
        self.generation += 1;
        u64::from(self.entries.remove(&key))
    }

    /// The committed field's own SMT root (not the composite).
    #[msg]
    async fn root(&self) -> Vec<u8> {
        self.entries.root().to_vec()
    }

    /// Entry count + generation, for cheap liveness asserts.
    #[msg]
    async fn stats(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(&self.entries.len().to_le_bytes());
        out.extend_from_slice(&self.generation.to_le_bytes());
        out
    }
}
