//! Big-map — the storage-type pressure fixture.
//!
//! Holds a `#[storage]` map whose stored rows grow far past the 256 KiB
//! guest heap: entries live as per-service KV rows, the state blob
//! carries only the `generation` counter, and each dispatch touches a
//! handful of rows however many entries exist. The e2e in
//! `vos/tests/elf_integration.rs` bulk-loads tens of thousands of
//! entries, then point-reads, range-reads, and removes against them —
//! the walls a blob-resident map hits (heap on decode, the 1 MiB halt
//! cap on re-encode) never come into play.
//!
//! Bulk loads use ascending keys so one dispatch's touched index pages
//! stay adjacent; scattered writes are fine too, just batched smaller —
//! the touched set, not the map, is what must fit in guest memory.

use vos::prelude::*;
use vos::storage::{StorageMap, StorageSet, fill_page};

#[actor]
struct BigMap {
    /// Blob-resident control field — proves the split: this travels in
    /// the state write, the map does not.
    generation: u64,
    #[storage]
    entries: StorageMap<u64, u64>,
    #[storage]
    seen: StorageSet<[u8; 32]>,
}

#[messages]
impl BigMap {
    fn new() -> Self {
        BigMap {
            generation: 0,
            entries: Default::default(),
            seen: Default::default(),
        }
    }

    /// Insert `n` entries `key -> key * 3` starting at `start`.
    /// Replies with the map's total entry count.
    #[msg]
    async fn bulk(&mut self, start: u64, n: u64) -> u64 {
        for key in start..start + n {
            self.entries.insert(&key, &(key * 3));
        }
        self.entries.len()
    }

    /// Point read; `u64::MAX` when absent.
    #[msg]
    async fn get(&mut self, key: u64) -> u64 {
        self.entries.get(&key).unwrap_or(u64::MAX)
    }

    /// Insert one entry. Replies 1 when the key is new, 0 on replace.
    #[msg]
    async fn put(&mut self, key: u64, value: u64) -> u64 {
        u64::from(self.entries.insert(&key, &value))
    }

    /// Remove. Replies 1 when the key was present.
    #[msg]
    async fn remove(&mut self, key: u64) -> u64 {
        u64::from(self.entries.remove(&key))
    }

    #[msg]
    async fn count(&mut self) -> u64 {
        self.entries.len()
    }

    /// Paged ordered range read: sum the values of up to `rows`
    /// entries with key ≥ `start` — the cursor-page pattern list
    /// handlers use to stay under the reply caps.
    #[msg]
    async fn sum_range(&mut self, start: u64, rows: u64) -> u64 {
        let mut it = self.entries.iter_from(&start).map(|(_, v)| v);
        let (page, _more) = fill_page(&mut it, rows as usize, 8 * 1024);
        page.iter().sum()
    }

    /// Dedup marker (storage set). Replies 1 when the id is new.
    #[msg]
    async fn mark(&mut self, id: [u8; 32]) -> u64 {
        u64::from(self.seen.insert(&id))
    }

    /// Bump the blob-resident counter (state write alongside rows).
    #[msg]
    async fn bump(&mut self) -> u64 {
        self.generation += 1;
        self.generation
    }
}
