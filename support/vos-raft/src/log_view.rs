//! The protocol core's view of its log, held in memory: every live entry's
//! term as compact runs, a bounded cache of the newest entries, and every
//! live configuration entry. Entries the cache no longer holds are loaded
//! from the host's store on demand.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use crate::config::NodeId;
use crate::log_entry::{EntryKind, LogEntry};

/// Bytes an entry costs the cache beyond its payload.
const ENTRY_OVERHEAD: usize = 64;

/// Keep the longest prefix of `entries` within `max_bytes`, and at least
/// one entry.
pub(crate) fn cap_bytes<N: NodeId>(entries: &mut Vec<LogEntry<N>>, max_bytes: usize) {
    let mut bytes = 0;
    let keep = entries
        .iter()
        .position(|entry| {
            bytes += entry_bytes(entry);
            bytes > max_bytes
        })
        .map_or(entries.len(), |at| at.max(1));
    entries.truncate(keep);
}

pub(crate) fn entry_bytes<N: NodeId>(entry: &LogEntry<N>) -> usize {
    ENTRY_OVERHEAD
        + match &entry.kind {
            EntryKind::Data { payload } => payload.len(),
            EntryKind::ConfigChange { joint_old, members } => {
                (members.len() + joint_old.as_ref().map_or(0, Vec::len)) * 8
            }
        }
}

#[derive(Debug, Clone)]
pub(crate) struct LogView<N: NodeId> {
    snap_index: u64,
    snap_term: u64,
    last: u64,
    /// `(first index, term)` runs covering `snap_index + 1..=last`, in order.
    runs: Vec<(u64, u64)>,
    /// A contiguous suffix of the log, ending at `last`.
    cache: VecDeque<LogEntry<N>>,
    cache_bytes: usize,
    cache_limit: usize,
    /// Every live configuration entry, by index.
    configs: BTreeMap<u64, LogEntry<N>>,
    /// The log's running byte count at the end of each live entry, in
    /// order: the entry at `snap_index + 1 + k` ends at `ends[k]`, and the
    /// snapshot at `start`.
    ends: VecDeque<u64>,
    start: u64,
}

impl<N: NodeId> LogView<N> {
    pub(crate) fn new(snap_index: u64, snap_term: u64, cache_limit: usize) -> Self {
        Self {
            snap_index,
            snap_term,
            last: snap_index,
            runs: Vec::new(),
            cache: VecDeque::new(),
            cache_bytes: 0,
            cache_limit,
            configs: BTreeMap::new(),
            ends: VecDeque::new(),
            start: 0,
        }
    }

    pub(crate) fn snap_index(&self) -> u64 {
        self.snap_index
    }

    pub(crate) fn snap_term(&self) -> u64 {
        self.snap_term
    }

    pub(crate) fn last_index(&self) -> u64 {
        self.last
    }

    pub(crate) fn last_term(&self) -> u64 {
        self.runs.last().map_or(self.snap_term, |&(_, term)| term)
    }

    /// The term of the entry at `index`, if the log holds it (the snapshot
    /// boundary included).
    pub(crate) fn term_at(&self, index: u64) -> Option<u64> {
        if index == self.snap_index {
            return Some(self.snap_term);
        }
        if index < self.snap_index || index > self.last {
            return None;
        }
        let at = self.runs.partition_point(|&(first, _)| first <= index);
        Some(self.runs[at - 1].1)
    }

    /// The bytes of the live entries through `index`.
    pub(crate) fn bytes_through(&self, index: u64) -> u64 {
        self.end_at(index) - self.start
    }

    /// The lowest index from which the entries after it, through `to`,
    /// take at most `max_bytes`.
    pub(crate) fn point_keeping(&self, to: u64, max_bytes: u64) -> u64 {
        let to = to.clamp(self.snap_index, self.last);
        let floor = self.end_at(to).saturating_sub(max_bytes);
        if self.start >= floor {
            return self.snap_index;
        }
        self.snap_index + 1 + self.ends.partition_point(|&end| end < floor) as u64
    }

    fn end_at(&self, index: u64) -> u64 {
        let index = index.min(self.last);
        if index <= self.snap_index {
            return self.start;
        }
        self.ends[(index - self.snap_index - 1) as usize]
    }

    /// The first index of the run of `term` that holds `index`.
    pub(crate) fn first_of_term_at(&self, index: u64) -> u64 {
        let at = self.runs.partition_point(|&(first, _)| first <= index);
        if at == 0 {
            return self.snap_index + 1;
        }
        self.runs[at - 1].0
    }

    /// The last index whose entry has a term at most `term`, for a leader
    /// skipping a follower's conflicting term.
    pub(crate) fn last_index_of_term_at_most(&self, term: u64) -> u64 {
        let mut last = self.snap_index;
        for (position, &(first, run_term)) in self.runs.iter().enumerate() {
            if run_term > term {
                break;
            }
            let end = self
                .runs
                .get(position + 1)
                .map_or(self.last, |&(next, _)| next - 1);
            if end >= first {
                last = end;
            }
        }
        last
    }

    /// Append `entries`, which must continue the log at `last + 1`.
    pub(crate) fn append(&mut self, entries: &[LogEntry<N>]) {
        for entry in entries {
            assert_eq!(entry.index, self.last + 1, "appends continue the log");
            match self.runs.last() {
                Some(&(_, term)) if term == entry.term => {}
                _ => self.runs.push((entry.index, entry.term)),
            }
            self.last = entry.index;
            let end = self.ends.back().map_or(self.start, |&end| end);
            self.ends.push_back(end + entry_bytes(entry) as u64);
            if matches!(entry.kind, EntryKind::ConfigChange { .. }) {
                self.configs.insert(entry.index, entry.clone());
            }
            // The cache is a suffix of the log: an append always continues it.
            if self
                .cache
                .back()
                .is_some_and(|back| back.index + 1 != entry.index)
            {
                self.clear_cache();
            }
            self.cache_bytes += entry_bytes(entry);
            self.cache.push_back(entry.clone());
        }
    }

    /// Drop every entry after `index`.
    pub(crate) fn truncate_after(&mut self, index: u64) {
        if index >= self.last {
            return;
        }
        let index = index.max(self.snap_index);
        self.last = index;
        self.ends.truncate((index - self.snap_index) as usize);
        while self.runs.last().is_some_and(|&(first, _)| first > index) {
            self.runs.pop();
        }
        while self.cache.back().is_some_and(|entry| entry.index > index) {
            let entry = self.cache.pop_back().expect("checked above");
            self.cache_bytes -= entry_bytes(&entry);
        }
        self.configs.retain(|&at, _| at <= index);
    }

    /// Forget every entry through `index`, now covered by a snapshot whose
    /// last entry has `term`. A log that does not reach `index`, or holds
    /// another term there, is dropped whole.
    pub(crate) fn compact_to(&mut self, index: u64, term: u64) {
        if index <= self.snap_index {
            return;
        }
        if self.term_at(index) != Some(term) {
            self.runs.clear();
            self.clear_cache();
            self.configs.clear();
            self.ends.clear();
            self.start = 0;
            self.last = index;
        } else {
            let at = self.runs.partition_point(|&(first, _)| first <= index);
            self.runs.drain(..at.saturating_sub(1));
            if let Some(first) = self.runs.first_mut() {
                first.0 = first.0.max(index + 1);
            }
            if self
                .runs
                .first()
                .is_some_and(|&(first, _)| first > self.last)
            {
                self.runs.clear();
            }
            while self.cache.front().is_some_and(|entry| entry.index <= index) {
                let entry = self.cache.pop_front().expect("checked above");
                self.cache_bytes -= entry_bytes(&entry);
            }
            self.configs.retain(|&at, _| at > index);
            let dropped = (index - self.snap_index) as usize;
            self.start = self.ends[dropped - 1];
            self.ends.drain(..dropped);
        }
        self.snap_index = index;
        self.snap_term = term;
    }

    /// Entries `from..=to` from the cache, at most `max_bytes` but at least
    /// one; `None` when the cache does not reach back to `from`.
    pub(crate) fn entries(&self, from: u64, to: u64, max_bytes: usize) -> Option<Vec<LogEntry<N>>> {
        if from > to {
            return Some(Vec::new());
        }
        let first = self.cache.front()?.index;
        if from < first || to > self.last {
            return None;
        }
        let mut out = Vec::new();
        let mut bytes = 0;
        for entry in self
            .cache
            .range((from - first) as usize..=(to - first) as usize)
        {
            let size = entry_bytes(entry);
            if !out.is_empty() && bytes + size > max_bytes {
                break;
            }
            bytes += size;
            out.push(entry.clone());
        }
        Some(out)
    }

    /// The entry at `index`, if the cache or the configuration index holds
    /// it.
    pub(crate) fn entry(&self, index: u64) -> Option<LogEntry<N>> {
        if let Some(entry) = self.configs.get(&index) {
            return Some(entry.clone());
        }
        let first = self.cache.front()?.index;
        (index >= first && index <= self.last).then(|| self.cache[(index - first) as usize].clone())
    }

    /// Live configuration entries, in index order.
    pub(crate) fn configs(&self) -> impl DoubleEndedIterator<Item = &LogEntry<N>> {
        self.configs.values()
    }

    /// The first cached index, if any entry is cached.
    pub(crate) fn cache_first(&self) -> Option<u64> {
        self.cache.front().map(|entry| entry.index)
    }

    /// Entries loaded from the store, kept if they still match the log and
    /// join the cache's front. Returns those that matched, in order.
    pub(crate) fn loaded(&mut self, entries: Vec<LogEntry<N>>) -> Vec<LogEntry<N>> {
        let matching: Vec<LogEntry<N>> = entries
            .into_iter()
            .take_while(|entry| self.term_at(entry.index) == Some(entry.term))
            .collect();
        let joins = match (matching.last(), self.cache.front()) {
            (Some(last), Some(front)) => last.index + 1 == front.index,
            (Some(last), None) => last.index == self.last,
            (None, _) => false,
        };
        if joins {
            for entry in matching.iter().rev() {
                self.cache_bytes += entry_bytes(entry);
                self.cache.push_front(entry.clone());
            }
        }
        matching
    }

    /// Evict the oldest cached entries beyond the byte limit, keeping every
    /// entry above `keep_from`, which may not yet be in the host's store.
    pub(crate) fn evict(&mut self, keep_from: u64) {
        while self.cache_bytes > self.cache_limit
            && self
                .cache
                .front()
                .is_some_and(|entry| entry.index < keep_from)
        {
            let entry = self.cache.pop_front().expect("checked above");
            self.cache_bytes -= entry_bytes(&entry);
        }
    }

    fn clear_cache(&mut self) {
        self.cache.clear();
        self.cache_bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn entry(index: u64, term: u64) -> LogEntry<u16> {
        LogEntry::data(index, term, vec![index as u8])
    }

    fn log(terms: &[u64]) -> LogView<u16> {
        let mut log = LogView::new(0, 0, usize::MAX);
        let entries: Vec<_> = terms
            .iter()
            .enumerate()
            .map(|(at, &term)| entry(at as u64 + 1, term))
            .collect();
        log.append(&entries);
        log
    }

    #[test]
    fn terms_come_from_runs() {
        let log = log(&[1, 1, 2, 2, 2, 5]);
        assert_eq!(log.term_at(0), Some(0));
        assert_eq!(log.term_at(2), Some(1));
        assert_eq!(log.term_at(3), Some(2));
        assert_eq!(log.term_at(6), Some(5));
        assert_eq!(log.term_at(7), None);
        assert_eq!(log.first_of_term_at(5), 3);
        assert_eq!(log.last_index_of_term_at_most(4), 5);
        assert_eq!(log.last_index_of_term_at_most(0), 0);
        assert_eq!(log.last_term(), 5);
    }

    #[test]
    fn truncation_and_compaction_keep_runs_exact() {
        let mut log = log(&[1, 1, 2, 2, 3]);
        log.truncate_after(3);
        assert_eq!(log.last_index(), 3);
        assert_eq!(log.term_at(3), Some(2));
        log.append(&[entry(4, 4)]);
        assert_eq!(log.term_at(4), Some(4));
        log.compact_to(3, 2);
        assert_eq!(log.term_at(2), None);
        assert_eq!(log.term_at(3), Some(2));
        assert_eq!(log.term_at(4), Some(4));
        assert_eq!(log.entries(4, 4, 0).unwrap()[0].index, 4);
        assert!(log.entries(3, 4, usize::MAX).is_none());
        // A snapshot the log does not match replaces it whole.
        log.compact_to(9, 7);
        assert_eq!(log.last_index(), 9);
        assert_eq!(log.last_term(), 7);
        assert_eq!(log.term_at(4), None);
    }

    #[test]
    fn loaded_entries_must_still_match() {
        let mut log = LogView::new(0, 0, 0);
        log.append(&[entry(1, 1), entry(2, 1), entry(3, 2)]);
        log.evict(4);
        assert!(log.entries(1, 3, usize::MAX).is_none());
        // A stale load from before a truncation: entry 3 at term 1.
        let stale = log.loaded(vec![entry(1, 1), entry(2, 1), entry(3, 1)]);
        assert_eq!(stale.len(), 2);
        let fresh = log.loaded(vec![entry(1, 1), entry(2, 1), entry(3, 2)]);
        assert_eq!(fresh.len(), 3);
    }

    #[test]
    fn eviction_keeps_entries_not_yet_stored() {
        let mut log = LogView::new(0, 0, 0);
        log.append(&[entry(1, 1), entry(2, 1), entry(3, 1)]);
        log.evict(2);
        assert!(log.entries(1, 1, usize::MAX).is_none());
        assert_eq!(log.entries(2, 3, usize::MAX).unwrap().len(), 2);
    }

    fn sized(index: u64, term: u64, bytes: usize) -> LogEntry<u16> {
        LogEntry::data(index, term, vec![0u8; bytes - ENTRY_OVERHEAD])
    }

    #[test]
    fn live_bytes_follow_appends_truncations_and_compactions() {
        let mut log = LogView::new(0, 0, usize::MAX);
        log.append(&[
            sized(1, 1, 100),
            sized(2, 1, 200),
            sized(3, 1, 300),
            sized(4, 1, 400),
        ]);
        assert_eq!(log.bytes_through(4), 1000);
        assert_eq!(log.bytes_through(2), 300);
        assert_eq!(log.bytes_through(9), 1000);
        // Entries 3 and 4 take 700 bytes; 2 through 4 take more.
        assert_eq!(log.point_keeping(4, 700), 2);
        assert_eq!(log.point_keeping(4, 699), 3);
        assert_eq!(log.point_keeping(4, 0), 4);
        assert_eq!(log.point_keeping(4, u64::MAX), 0);
        log.truncate_after(2);
        assert_eq!(log.bytes_through(4), 300);
        log.append(&[sized(3, 2, 1000)]);
        assert_eq!(log.bytes_through(3), 1300);
        log.compact_to(1, 1);
        assert_eq!(log.bytes_through(1), 0);
        assert_eq!(log.bytes_through(3), 1200);
        assert_eq!(log.point_keeping(3, 1000), 2);
        assert_eq!(log.point_keeping(3, u64::MAX), 1);
        // A snapshot the log does not match leaves nothing live.
        log.compact_to(5, 3);
        assert_eq!(log.bytes_through(5), 0);
        assert_eq!(log.bytes_through(9), 0);
        assert_eq!(log.point_keeping(9, 0), 5);
        log.append(&[sized(6, 3, 100)]);
        assert_eq!(log.bytes_through(6), 100);
        assert_eq!(log.point_keeping(6, 99), 6);
    }
}
