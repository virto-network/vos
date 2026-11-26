//! One simulated node's store.

use alloc::collections::{BTreeMap, VecDeque};
use core::cmp;

use crate::core::{ActiveConfigRecord, Recovered, SnapshotSwitch, Write};
use crate::log_entry::LogEntry;
use crate::meta::Meta;

/// A queued store operation.
#[derive(Debug, Clone)]
pub(super) enum Op {
    Write(Write<u16>),
    Compact {
        through: u64,
        configuration: Option<ActiveConfigRecord<u16>>,
    },
}

/// One node's store: durable state, and operations not yet synced.
#[derive(Debug, Clone, Default)]
pub(super) struct Store {
    pub(super) meta: Meta<u16>,
    pub(super) log: BTreeMap<u64, LogEntry<u16>>,
    pub(super) active_config: Option<ActiveConfigRecord<u16>>,
    pub(super) log_start_config: Option<ActiveConfigRecord<u16>>,
    pub(super) applied: u64,
    pub(super) unsynced: VecDeque<Op>,
    /// The last log position held before a retirement wiped the rest.
    pub(super) vote_floor: Option<(u64, u64)>,
}

/// What one sync made durable.
#[derive(Debug, Default)]
pub(super) struct Synced {
    pub(super) seq: Option<u64>,
    pub(super) compacted: Option<u64>,
}

impl Store {
    pub(super) fn apply(&mut self, op: &Op, synced: &mut Synced) {
        match op {
            Op::Write(write) => {
                if let Some(after) = write.truncate_after {
                    self.log.retain(|&index, _| index <= after);
                }
                for entry in &write.entries {
                    self.log.insert(entry.index, entry.clone());
                }
                if let Some(hard) = &write.meta {
                    self.meta.current_term = hard.current_term;
                    self.meta.voted_for = hard.voted_for;
                    self.meta.commit_index = hard.commit_index;
                }
                if let Some(record) = &write.active_config {
                    self.active_config = Some(record.clone());
                }
                synced.seq = Some(write.seq);
            }
            Op::Compact {
                through,
                configuration,
            } => {
                let through = *through;
                if through > self.meta.snap_last_index
                    && let Some(term) = self.log.get(&through).map(|entry| entry.term)
                {
                    self.log.retain(|&index, _| index > through);
                    self.meta.snap_last_index = through;
                    self.meta.snap_last_term = term;
                    self.log_start_config = configuration.clone();
                    synced.compacted = Some(through);
                }
            }
        }
    }

    /// Make every queued operation durable.
    pub(super) fn sync(&mut self) -> Synced {
        let mut synced = Synced::default();
        while let Some(op) = self.unsynced.pop_front() {
            self.apply(&op, &mut synced);
        }
        synced
    }

    /// Lose the unsynced operations after a prefix of `keep` of them.
    pub(super) fn crash(&mut self, keep: usize) {
        let mut synced = Synced::default();
        for _ in 0..keep.min(self.unsynced.len()) {
            let op = self.unsynced.pop_front().expect("counted");
            self.apply(&op, &mut synced);
        }
        self.unsynced.clear();
    }

    /// Switch to a snapshot, durably.
    pub(super) fn switch(&mut self, switch: &SnapshotSwitch<u16>) {
        if let Some(after) = switch.truncate_after {
            self.log.retain(|&at, _| at <= after);
        }
        let index = switch.meta.snap_last_index;
        self.log.retain(|&at, _| at > index);
        self.meta = switch.meta.clone();
        self.active_config = Some(switch.active_config.clone());
        self.log_start_config = switch.log_start_config.clone();
        self.applied = self.applied.max(index);
    }

    pub(super) fn recovered(&self) -> Recovered<u16> {
        Recovered {
            meta: self.meta.clone(),
            entries: self
                .log
                .range(self.meta.snap_last_index + 1..)
                .map(|(_, entry)| entry.clone())
                .collect(),
            active_config: self.active_config.clone(),
            log_start_config: self.log_start_config.clone(),
            applied: self.applied,
            vote_floor: self.vote_floor,
        }
    }

    /// Retire: the log, state and configuration go; the term and vote
    /// stay, and so does the last log position held, as the floor of
    /// every vote it gives if it is added again.
    pub(super) fn retire(&mut self, keep_floor: bool) {
        self.sync();
        let last = self.log.last_key_value().map_or(
            (self.meta.snap_last_index, self.meta.snap_last_term),
            |(index, entry)| (*index, entry.term),
        );
        // The later position, by term then index.
        self.vote_floor = keep_floor.then(|| {
            self.vote_floor.map_or(last, |floor| {
                cmp::max_by_key(floor, last, |&(index, term)| (term, index))
            })
        });
        self.log.clear();
        self.meta = Meta {
            current_term: self.meta.current_term,
            voted_for: self.meta.voted_for,
            ..Meta::default()
        };
        self.active_config = None;
        self.log_start_config = None;
        self.applied = 0;
    }

    /// The entry at `index` as written so far, durable or not.
    pub(super) fn written(&self, index: u64) -> Option<LogEntry<u16>> {
        let mut entry = self.log.get(&index).cloned();
        for op in &self.unsynced {
            let Op::Write(write) = op else {
                continue;
            };
            if write.truncate_after.is_some_and(|after| after < index) {
                entry = None;
            }
            if let Some(written) = write.entries.iter().find(|written| written.index == index) {
                entry = Some(written.clone());
            }
        }
        entry
    }
}
