//! Storage trait. Hides the on-disk shape of the Raft log + meta
//! + snapshot state behind a small handful of read/write methods.
//!
//! Async API. Implementations whose backend is genuinely
//! synchronous (an in-memory `BTreeMap`, a redb txn) are free to
//! return ready futures from inside an `async fn` body — there's
//! no required yield. Implementations on top of async storage
//! drivers (Embassy SPI flash, an async key-value store) can
//! `.await` natively.
//!
//! ## Design notes
//!
//! - **Reads return `Result`** even for fields that an in-memory
//!   impl would never fail to retrieve. This keeps the trait
//!   uniform across backends; implementations free to use
//!   [`core::convert::Infallible`] as their error type.
//! - **Writes batch through [`WriteBatch`]**. Multiple field
//!   updates that must land atomically (append + meta-advance,
//!   truncate + append, snapshot-replace + meta-advance) flow
//!   through one method call. The backend composes them into a
//!   single redb txn, a single flash erase-program cycle, or
//!   whatever its native unit of atomicity is.
//! - **Cached scalars** (`last_index`, `last_term`,
//!   `snap_last_index`, `snap_last_term`) are reads the worker
//!   hits on every loop iteration; an impl is free to cache
//!   these in memory and only consult disk on
//!   [`Storage::load_meta`] / [`Storage::commit_batch`].

use alloc::vec::Vec;
use core::fmt::Debug;

use crate::config::NodeId;
use crate::log_entry::LogEntry;
use crate::meta::Meta;

/// Atomic write — every field that's `Some` lands together; a
/// crash mid-batch leaves either the pre-batch or the post-batch
/// state on disk, never a partial mix.
///
/// Field ordering is *semantic*, not directional: an
/// implementation MUST apply truncate first, then compact, then
/// the appends, then state, then meta — that's the order Raft
/// expects when (e.g.) a follower truncates a divergent tail and
/// grafts the leader's authoritative version.
#[derive(Debug, Clone)]
pub struct WriteBatch<N: NodeId> {
    /// Drop every entry whose `index > truncate_after`. No-op
    /// when `None` or when `truncate_after >= last_index`.
    pub truncate_after: Option<u64>,
    /// Drop every entry whose `index <= compact_to.0` and
    /// remember the snap pointer at `(index, term)`. The
    /// implementation also persists this as
    /// `meta.snap_last_*` if `meta` is `None` — otherwise the
    /// caller's `meta` field is authoritative and must match.
    pub compact_to: Option<(u64, u64)>,
    /// Append at the end. Indices must be contiguous starting
    /// at `last_index + 1` (or the truncated tail's tail index
    /// + 1, when both `truncate_after` and `appends` are set).
    pub appends: Vec<LogEntry>,
    /// Replace the snapshot row with these bytes. `None` =
    /// leave the existing snapshot row in place. Empty `Vec`
    /// = explicitly clear the row.
    pub state: Option<Vec<u8>>,
    /// Replace the durable scalars. `None` = leave them in
    /// place.
    pub meta: Option<Meta<N>>,
}

// Manual impl so the empty-batch shorthand `..Default::default()`
// doesn't force `N: Default` onto every caller. `Option<Meta<N>>`
// is `None` regardless of whether `N` itself is `Default`.
impl<N: NodeId> Default for WriteBatch<N> {
    fn default() -> Self {
        Self {
            truncate_after: None,
            compact_to: None,
            appends: Vec::new(),
            state: None,
            meta: None,
        }
    }
}

/// Storage backend for one Raft replica.
///
/// Implementations own the on-disk representation. The crate
/// ships a [`MemStorage`](crate::storage::MemStorage) for tests;
/// vos provides a redb-backed impl in its own module.
///
/// `last_*` / `snap_last_*` are sync — they're hot-path reads
/// the worker checks on every loop iteration, and an
/// implementation is expected to keep them in memory. The
/// random-access + write methods are `async fn` so an embedded
/// SPI-flash impl can yield while the bus transfers bytes.
pub trait Storage<N: NodeId>: Send + 'static {
    type Error: Debug + Send + Sync + 'static;

    // ── Cached log-tail scalars (sync) ──────────────────────
    /// Index of the highest entry currently in the log. `0` =
    /// no entries (and no snapshot either).
    fn last_index(&self) -> u64;
    /// Term of the entry at `last_index`. `0` when the log is
    /// empty.
    fn last_term(&self) -> u64;
    /// Highest index that's been compacted into the snapshot.
    /// `0` = no snapshot yet.
    fn snap_last_index(&self) -> u64;
    /// Term of the entry at `snap_last_index`. `0` when no
    /// snapshot exists.
    fn snap_last_term(&self) -> u64;

    // ── Random-access reads (async) ─────────────────────────
    /// Term of the entry at `index`, or `None` if out of range.
    /// Index `0` is the implicit pre-log slot — both sides agree
    /// it has term `0`. `index == snap_last_index` returns the
    /// snap term; `index < snap_last_index` returns `None`
    /// (the entry has been compacted away).
    fn term_at(
        &self,
        index: u64,
    ) -> impl core::future::Future<Output = Result<Option<u64>, Self::Error>> + Send;

    /// Read entries `[start..=end]` in index order. Indices that
    /// have been compacted are silently skipped — callers asking
    /// for those should fall back to a snapshot install.
    fn entries(
        &self,
        start: u64,
        end: u64,
    ) -> impl core::future::Future<Output = Result<Vec<LogEntry>, Self::Error>> + Send;

    /// Read the snapshot row. Empty `Vec` when no snapshot has
    /// been installed.
    fn read_state(
        &self,
    ) -> impl core::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send;

    /// Read all durable scalars. Default for a fresh log:
    /// `Meta::default()`.
    fn load_meta(
        &self,
    ) -> impl core::future::Future<Output = Result<Meta<N>, Self::Error>> + Send;

    // ── Atomic write (async) ────────────────────────────────
    /// Apply a [`WriteBatch`] atomically, refresh whatever the
    /// implementation needs for its cached `last_*` / `snap_*`
    /// readers, and return.
    fn commit_batch(
        &mut self,
        batch: WriteBatch<N>,
    ) -> impl core::future::Future<Output = Result<(), Self::Error>> + Send;
}

// ── In-memory test backend ──────────────────────────────────

/// In-memory [`Storage`] for tests + simulators. Doesn't
/// persist anything — drop the `MemStorage` and the cluster's
/// state vanishes — but matches the trait semantics exactly.
pub struct MemStorage<N: NodeId> {
    log: alloc::collections::BTreeMap<u64, LogEntry>,
    state: Vec<u8>,
    meta: Meta<N>,
}

impl<N: NodeId> Default for MemStorage<N> {
    fn default() -> Self {
        Self {
            log: alloc::collections::BTreeMap::new(),
            state: Vec::new(),
            meta: Meta::default(),
        }
    }
}

impl<N: NodeId> MemStorage<N> {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<N: NodeId> Storage<N> for MemStorage<N> {
    type Error = core::convert::Infallible;

    fn last_index(&self) -> u64 {
        self.log
            .keys()
            .next_back()
            .copied()
            .unwrap_or(self.meta.snap_last_index)
    }

    fn last_term(&self) -> u64 {
        self.log
            .values()
            .next_back()
            .map(|e| e.term)
            .unwrap_or(self.meta.snap_last_term)
    }

    fn snap_last_index(&self) -> u64 {
        self.meta.snap_last_index
    }

    fn snap_last_term(&self) -> u64 {
        self.meta.snap_last_term
    }

    async fn term_at(&self, index: u64) -> Result<Option<u64>, Self::Error> {
        if index == 0 {
            return Ok(Some(0));
        }
        if index < self.meta.snap_last_index {
            return Ok(None);
        }
        if index == self.meta.snap_last_index && self.meta.snap_last_index > 0 {
            return Ok(Some(self.meta.snap_last_term));
        }
        Ok(self.log.get(&index).map(|e| e.term))
    }

    async fn entries(&self, start: u64, end: u64) -> Result<Vec<LogEntry>, Self::Error> {
        if start > end {
            return Ok(Vec::new());
        }
        let effective_start = start.max(self.meta.snap_last_index + 1);
        Ok(self
            .log
            .range(effective_start..=end)
            .map(|(_, v)| v.clone())
            .collect())
    }

    async fn read_state(&self) -> Result<Vec<u8>, Self::Error> {
        Ok(self.state.clone())
    }

    async fn load_meta(&self) -> Result<Meta<N>, Self::Error> {
        Ok(self.meta.clone())
    }

    async fn commit_batch(&mut self, batch: WriteBatch<N>) -> Result<(), Self::Error> {
        if let Some(after) = batch.truncate_after {
            self.log.retain(|k, _| *k <= after);
        }
        if let Some((idx, term)) = batch.compact_to {
            self.log.retain(|k, _| *k > idx);
            self.meta.snap_last_index = idx;
            self.meta.snap_last_term = term;
        }
        for entry in batch.appends {
            self.log.insert(entry.index, entry);
        }
        if let Some(state) = batch.state {
            self.state = state;
        }
        if let Some(meta) = batch.meta {
            // Caller's meta wins. (compact_to + meta combinations
            // are valid as long as both agree on snap_last_*; we
            // don't enforce that here — production-quality
            // backends should reject the inconsistency.)
            self.meta = meta;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use crate::testutil::block_on;

    type Mem = MemStorage<u16>;

    fn entry(idx: u64, term: u64) -> LogEntry {
        LogEntry {
            index: idx,
            term,
            payload: vec![idx as u8],
        }
    }

    #[test]
    fn fresh_storage_has_zero_indices() {
        block_on(async {
            let s = Mem::new();
            assert_eq!(s.last_index(), 0);
            assert_eq!(s.last_term(), 0);
            assert_eq!(s.snap_last_index(), 0);
            assert_eq!(s.term_at(0).await.unwrap(), Some(0));
            assert_eq!(s.term_at(1).await.unwrap(), None);
        });
    }

    #[test]
    fn append_and_read_roundtrip() {
        block_on(async {
            let mut s = Mem::new();
            s.commit_batch(WriteBatch {
                appends: vec![entry(1, 1), entry(2, 1), entry(3, 2)],
                ..Default::default()
            })
            .await
            .unwrap();
            assert_eq!(s.last_index(), 3);
            assert_eq!(s.last_term(), 2);
            assert_eq!(s.term_at(2).await.unwrap(), Some(1));
            assert_eq!(s.entries(1, 3).await.unwrap().len(), 3);
        });
    }

    #[test]
    fn truncate_after_drops_tail() {
        block_on(async {
            let mut s = Mem::new();
            s.commit_batch(WriteBatch {
                appends: vec![entry(1, 1), entry(2, 1), entry(3, 2)],
                ..Default::default()
            })
            .await
            .unwrap();
            s.commit_batch(WriteBatch {
                truncate_after: Some(1),
                ..Default::default()
            })
            .await
            .unwrap();
            assert_eq!(s.last_index(), 1);
            assert_eq!(s.entries(1, 5).await.unwrap().len(), 1);
        });
    }

    #[test]
    fn compact_drops_head_and_anchors_term() {
        block_on(async {
            let mut s = Mem::new();
            s.commit_batch(WriteBatch {
                appends: vec![entry(1, 1), entry(2, 1), entry(3, 2)],
                ..Default::default()
            })
            .await
            .unwrap();
            s.commit_batch(WriteBatch {
                compact_to: Some((2, 1)),
                ..Default::default()
            })
            .await
            .unwrap();
            assert_eq!(s.snap_last_index(), 2);
            assert_eq!(s.snap_last_term(), 1);
            assert_eq!(s.term_at(1).await.unwrap(), None,
                "compacted entry returns None");
            assert_eq!(s.term_at(2).await.unwrap(), Some(1),
                "snap boundary returns snap_last_term");
            assert_eq!(s.term_at(3).await.unwrap(), Some(2));
            assert_eq!(s.entries(1, 5).await.unwrap().len(), 1,
                "only entry 3 survives compaction");
        });
    }
}
