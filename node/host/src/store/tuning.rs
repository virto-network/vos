//! The store benchmark's tuning and probes: not the node's API.

use fjall::KeyspaceCreateOptions;

use super::{Fjall, Result};

/// Read tuning for the `state` partition. The defaults are the fastest
/// configuration the store benchmark found at 10M rows.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct Tuning {
    /// Block cache, shared by every partition.
    pub cache_bytes: u64,
    /// Skip filters on the last level, where most rows live: reads of
    /// actor state mostly hit, and a filter that says "maybe" costs a
    /// lookup for nothing. Misses then cost a block search.
    pub expect_hits: bool,
    /// Size of the hash index in each data block, relative to its keys; 0
    /// builds none, and a point read binary-searches the block.
    pub hash_ratio: f32,
    /// Keep every level's filter and index blocks in the cache.
    pub pin_all: bool,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            cache_bytes: 1 << 30,
            expect_hits: true,
            hash_ratio: 0.0,
            pin_all: false,
        }
    }
}

impl Tuning {
    pub(super) fn rows(&self) -> KeyspaceCreateOptions {
        use fjall::config::{HashRatioPolicy, PinningPolicy};
        let mut options = KeyspaceCreateOptions::default()
            .expect_point_read_hits(self.expect_hits)
            .data_block_hash_ratio_policy(HashRatioPolicy::all(self.hash_ratio));
        if self.pin_all {
            options = options
                .filter_block_pinning_policy(PinningPolicy::all(true))
                .index_block_pinning_policy(PinningPolicy::all(true));
        }
        options
    }
}

impl Fjall {
    /// Compact the state partitions into one sorted run each, as after a
    /// bulk load.
    #[doc(hidden)]
    pub fn compact(&self) -> Result<()> {
        self.state().major_compact()?;
        self.system().major_compact()?;
        Ok(())
    }

    #[doc(hidden)]
    pub fn disk_space(&self) -> Result<u64> {
        self.database().disk_space()
    }

    /// The bytes of the state partition's active memtable, which a read
    /// of its rows searches first: it only grows until the memtable is
    /// sealed and another takes its place.
    #[doc(hidden)]
    pub fn state_memtable_bytes(&self) -> u64 {
        use fjall::AbstractTree;
        self.state().tree.active_memtable().size()
    }

    /// The state partition's sealed memtables not yet flushed, which reads
    /// search next.
    #[doc(hidden)]
    pub fn state_sealed_memtables(&self) -> usize {
        self.state().sealed_memtable_count()
    }
}
