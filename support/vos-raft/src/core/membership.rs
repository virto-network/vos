//! Configurations: the record and its quorum maths, membership changes,
//! a follower's view of them, the configuration a snapshot or a compaction
//! keeps, and recovery.

use alloc::vec::Vec;

use super::{ChangeMembershipError, Core, SnapshotSwitch};
use crate::config::NodeId;
use crate::log_entry::{EntryKind, LogEntry};
use crate::message::{AppendResult, Message};
use crate::meta::Meta;
use crate::role::Role;

/// A configuration, joint while `joint_old` is set, when a quorum needs
/// majorities of both sets: the one a replica operates under, the one in
/// effect at its log's start or at a compaction, the one a snapshot carries.
///
/// `log_index` is the index of the entry that established it (0 for the
/// static members). A replica's own record compares it with the durable
/// `commit_index` before treating exclusion from the view as a committed
/// removal; `None` is unknown provenance, never proof of one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveConfigRecord<N: NodeId> {
    pub log_index: Option<u64>,
    pub current: Vec<N>,
    pub joint_old: Option<Vec<N>>,
}

impl<N: NodeId> ActiveConfigRecord<N> {
    pub(super) fn steady(log_index: u64, members: Vec<N>) -> Self {
        Self {
            log_index: Some(log_index),
            current: members,
            joint_old: None,
        }
    }

    /// The configuration a log entry establishes, if it is a configuration
    /// entry.
    pub(crate) fn from_entry(entry: &LogEntry<N>) -> Option<Self> {
        match &entry.kind {
            EntryKind::ConfigChange { joint_old, members } => Some(Self {
                log_index: Some(entry.index),
                current: members.clone(),
                joint_old: joint_old.clone(),
            }),
            EntryKind::Data { .. } => None,
        }
    }

    fn is_joint(&self) -> bool {
        self.joint_old.is_some()
    }

    /// Where a joint configuration stays pending, for a leader to
    /// finalize: at its own entry.
    fn joint_entry(&self) -> Option<u64> {
        self.log_index.filter(|_| self.is_joint())
    }

    /// The members of `current`, then those of `joint_old` not met before.
    pub(super) fn members(&self) -> impl Iterator<Item = N> + '_ {
        let old = self.joint_old.as_deref().unwrap_or_default();
        let added = old
            .iter()
            .enumerate()
            .filter(|&(at, member)| !self.current.contains(member) && !old[..at].contains(member))
            .map(|(_, member)| member);
        self.current.iter().chain(added).copied()
    }

    pub(super) fn contains(&self, node: N) -> bool {
        self.current.contains(&node)
            || self
                .joint_old
                .as_ref()
                .is_some_and(|old| old.contains(&node))
    }

    pub(super) fn quorum_holds(&self, mut holds: impl FnMut(N) -> bool) -> bool {
        let majority = |set: &[N], holds: &mut dyn FnMut(N) -> bool| {
            set.iter().filter(|&&member| holds(member)).count() > set.len() / 2
        };
        majority(&self.current, &mut holds)
            && self
                .joint_old
                .as_ref()
                .is_none_or(|old| majority(old, &mut holds))
    }

    /// The highest score a quorum reaches, in both sets when joint.
    pub(super) fn majority_floor(&self, mut score: impl FnMut(N) -> u64) -> Option<u64> {
        let floor = |set: &[N], score: &mut dyn FnMut(N) -> u64| {
            let mut scores: Vec<u64> = set.iter().map(|&member| score(member)).collect();
            scores.sort_unstable_by(|a, b| b.cmp(a));
            let quorum = set.len() / 2 + 1;
            (quorum <= scores.len()).then(|| scores[quorum - 1])
        };
        let mut result = floor(&self.current, &mut score)?;
        if let Some(old) = &self.joint_old {
            result = result.min(floor(old, &mut score)?);
        }
        Some(result)
    }
}

impl<N: NodeId> Core<N> {
    pub(super) fn rebuild_leader_tracking(&mut self) {
        let next = self.log.last_index() + 1;
        let now = self.now;
        let me = self.cfg.me;
        let Some(leading) = self.leading.as_mut() else {
            return;
        };
        let active = &self.active;
        for member in active.members().filter(|&member| member != me) {
            leading.next_index.entry(member).or_insert(next);
            leading.match_index.entry(member).or_insert(0);
            leading.answered.entry(member).or_insert(now);
        }
        let tracked = |member: &N| active.contains(*member);
        leading.next_index.retain(|member, _| tracked(member));
        leading.match_index.retain(|member, _| tracked(member));
        leading.in_flight.retain(|member, _| tracked(member));
        leading.snapshotting.retain(|member, _| tracked(member));
        leading.acked_round.retain(|member, _| tracked(member));
        leading.answered.retain(|member, _| tracked(member));
        leading.sent_commit.retain(|member, _| tracked(member));
        leading.acked_commit.retain(|member, _| tracked(member));
        leading.loading.retain(tracked);
        leading.silent.retain(tracked);
    }

    pub(super) fn start_membership_change(
        &mut self,
        members: Vec<N>,
    ) -> Result<u64, ChangeMembershipError> {
        if self.role != Role::Leader || self.transferring() {
            return Err(ChangeMembershipError::NotLeader);
        }
        if self.active.is_joint() {
            return Err(ChangeMembershipError::InProgress);
        }
        // A solo leader ran no check-quorum: its window starts now.
        if self.is_solo() {
            self.check_quorum_due = self.now + self.cfg.election_timeout_ms.1;
            if let Some(leading) = self.leading.as_mut() {
                leading.recent.clear();
            }
        }
        if members.is_empty() {
            return Err(ChangeMembershipError::EmptyConfig);
        }
        let index = self.log.last_index() + 1;
        let old = self.active.current.clone();
        self.write_entries(alloc::vec![LogEntry::config_change(
            index,
            self.term,
            Some(old.clone()),
            members.clone(),
        )]);
        // The joint configuration applies at once, before it commits.
        self.adopt_configuration(ActiveConfigRecord {
            log_index: Some(index),
            current: members,
            joint_old: Some(old),
        });
        self.try_advance_commit();
        self.replicate_all();
        Ok(index)
    }

    /// Advance a committed membership transition: a committed joint entry
    /// appends the final one; a committed final entry becomes effective.
    pub(super) fn auto_finalize_joint_config(&mut self) {
        // Not while handing over: the target must hold the whole log.
        if self.role != Role::Leader || !self.active.is_joint() || self.transferring() {
            return;
        }
        let Some(pending) = self.pending_joint_entry else {
            return;
        };
        if self.commit < pending {
            return;
        }
        // An entry compacted away is the joint configuration in effect, or,
        // pending past it, its final one.
        let (joint_old, members) = match self.log.entry(pending).map(|entry| entry.kind) {
            Some(EntryKind::ConfigChange { joint_old, members }) => (joint_old, members),
            None if pending <= self.log.snap_index() => {
                let joint_old = (Some(pending) == self.active.log_index)
                    .then(|| self.active.joint_old.clone())
                    .flatten();
                (joint_old, self.active.current.clone())
            }
            _ => return,
        };
        if joint_old.is_none() {
            self.adopt_configuration(ActiveConfigRecord::steady(pending, members));
            return;
        }
        let index = self.log.last_index() + 1;
        self.write_entries(alloc::vec![LogEntry::config_change(
            index, self.term, None, members,
        )]);
        // The joint view stays effective until this final entry commits, so a
        // retiring leader that crashes can still recover and replicate it.
        self.pending_joint_entry = Some(index);
        self.replicate_all();
    }

    /// Put `record` in effect: recorded, pending at its entry while joint,
    /// and tracked by a leader.
    fn adopt_configuration(&mut self, record: ActiveConfigRecord<N>) {
        self.pending_joint_entry = record.joint_entry();
        self.active = record;
        self.write_active_config();
        self.rebuild_leader_tracking();
    }

    /// A follower's view of membership after an append: truncated rows drop
    /// their configurations, and the last configuration entry appended takes
    /// effect at once.
    pub(super) fn follow_membership(
        &mut self,
        truncate_after: Option<u64>,
        appends: &[LogEntry<N>],
    ) {
        let invalidated_config = match (truncate_after, self.active.log_index) {
            (Some(after), Some(index)) => after < index,
            _ => false,
        };
        let invalidated_pending = match (truncate_after, self.pending_joint_entry) {
            (Some(after), Some(index)) => after < index,
            _ => false,
        };
        // A truncation that removes the entry the view came from falls back
        // to the latest configuration entry it keeps, else the log start's.
        let adopted = appends
            .iter()
            .rev()
            .find_map(ActiveConfigRecord::from_entry)
            .or_else(|| {
                let after = truncate_after.filter(|_| invalidated_config)?;
                // Unknown at the log's start (a host that kept no record):
                // the static members, the best left.
                Some(
                    self.config_at(after)
                        .unwrap_or_else(|| ActiveConfigRecord::steady(0, self.cfg.members.clone())),
                )
            });
        let Some(record) = adopted else {
            if invalidated_pending {
                self.pending_joint_entry = self.active.joint_entry();
            }
            return;
        };
        self.adopt_configuration(record);
    }

    /// A replica whose commit index crossed a pending final configuration
    /// adopts it.
    pub(super) fn follow_committed_membership(&mut self) {
        if self.active.is_joint()
            && let Some(pending) = self.pending_joint_entry
            && pending <= self.commit
            && let Some(entry) = self.log.entry(pending)
            && let EntryKind::ConfigChange {
                joint_old: None,
                members,
            } = entry.kind
        {
            self.adopt_configuration(ActiveConfigRecord::steady(pending, members));
        }
    }

    /// What switching to a received snapshot at (`index`, `term`) writes
    /// besides the state, all in one atomic batch: a crash then leaves the
    /// old replica or the new one, never a snapshot with a stale membership
    /// record. The host calls [`Self::snapshot_installed`] once it is durable.
    ///
    /// `configuration`, the one the snapshot carries, counts only with the
    /// index of its entry, at or below `index`: one without, or above, is
    /// ignored, and this replica's own configuration there serves.
    pub fn snapshot_switch(
        &self,
        index: u64,
        term: u64,
        configuration: Option<&ActiveConfigRecord<N>>,
    ) -> SnapshotSwitch<N> {
        let keeps_suffix = self.log.term_at(index) == Some(term);
        SnapshotSwitch {
            truncate_after: (!keeps_suffix).then_some(index),
            // The term and vote in memory are at least as new as any write
            // queued before the switch, and persisting them early is safe;
            // older ones could rewind a vote a queued write already made.
            meta: Meta {
                current_term: self.term,
                voted_for: self.vote,
                commit_index: self.commit.max(index),
                snap_last_index: index,
                snap_last_term: term,
            },
            active_config: self.snapshot_record(index, keeps_suffix, configuration),
            log_start_config: self.start_after_snapshot(index, configuration),
        }
    }

    /// The configuration in effect at an installed snapshot's index: the
    /// one it carries, else this replica's at that index, if known.
    fn start_after_snapshot(
        &self,
        index: u64,
        configuration: Option<&ActiveConfigRecord<N>>,
    ) -> Option<ActiveConfigRecord<N>> {
        configuration
            .filter(|configuration| configuration.log_index.is_some_and(|at| at <= index))
            .cloned()
            .or_else(|| self.config_at(index))
    }

    /// The host switched this replica to a received snapshot, durably, with
    /// the rows of [`Self::snapshot_switch`], given the same
    /// `configuration`, which counts on the same terms.
    pub fn snapshot_installed(
        &mut self,
        index: u64,
        term: u64,
        configuration: Option<ActiveConfigRecord<N>>,
    ) {
        if index <= self.log.snap_index() {
            return;
        }
        let keeps_suffix = self.log.term_at(index) == Some(term);
        let carried = self
            .carried(index, keeps_suffix, configuration.as_ref())
            .is_some();
        let record = self.snapshot_record(index, keeps_suffix, configuration.as_ref());
        self.log_start_config = self.start_after_snapshot(index, configuration.as_ref());
        self.log.compact_to(index, term);
        self.durable_index = if keeps_suffix {
            self.durable_index.max(index)
        } else {
            self.written.clear();
            index
        };
        self.forget_written();
        self.verified = self.verified.max(index);
        self.adopt_snapshot_configuration(index, carried, record);
        self.advance_commit(index);
        self.write_meta(true);
        if let Some(leader) = self.seen_leader {
            let matched = self.durable_index.min(self.verified);
            self.respond(
                leader,
                Message::AppendAnswer {
                    term: self.term,
                    round: 0,
                    commit: index,
                    result: AppendResult::Matched { matched },
                },
            );
        }
    }

    /// The configuration a snapshot at `index` carries, when it takes
    /// effect: established at or below the snapshot, with no configuration
    /// entry above it in the log kept.
    fn carried<'a>(
        &self,
        index: u64,
        keeps_suffix: bool,
        configuration: Option<&'a ActiveConfigRecord<N>>,
    ) -> Option<&'a ActiveConfigRecord<N>> {
        let live_above = keeps_suffix && self.log.config_after(index);
        configuration.filter(|configuration| {
            !live_above && configuration.log_index.is_some_and(|at| at <= index)
        })
    }

    /// The membership record after a snapshot at `index`: the configuration
    /// it carries, if that takes effect ([`Self::carried`]), else the
    /// current view, whose provenance survives only if a configuration
    /// entry above the snapshot is kept or it was committed before the
    /// install.
    fn snapshot_record(
        &self,
        index: u64,
        keeps_suffix: bool,
        configuration: Option<&ActiveConfigRecord<N>>,
    ) -> ActiveConfigRecord<N> {
        if let Some(carried) = self.carried(index, keeps_suffix, configuration) {
            return carried.clone();
        }
        let live_above = keeps_suffix && self.log.config_after(index);
        ActiveConfigRecord {
            log_index: if live_above {
                self.active.log_index
            } else {
                self.active.log_index.filter(|&at| at <= self.commit)
            },
            ..self.active.clone()
        }
    }

    /// Adopt `record`, from [`Self::snapshot_record`] before the install:
    /// the configuration the snapshot `carried`, or the current view.
    fn adopt_snapshot_configuration(
        &mut self,
        index: u64,
        carried: bool,
        record: ActiveConfigRecord<N>,
    ) {
        // A joint configuration the snapshot holds stays pending at its
        // entry, compacted or not, so this replica, leading, finalizes it.
        if carried {
            self.adopt_configuration(record);
            return;
        }
        if self.pending_joint_entry.is_some_and(|at| at <= index) {
            self.pending_joint_entry = None;
        }
        self.active = record;
        self.write_active_config();
    }

    /// Where a compaction through `through` stops to keep a tail of at
    /// most `entries` entries and `bytes` bytes for a follower a little
    /// behind.
    pub fn compaction_point(&self, through: u64, entries: u64, bytes: u64) -> u64 {
        through
            .saturating_sub(entries)
            .max(self.log.point_keeping(through, bytes))
    }

    /// The host compacted its log through `through`.
    pub fn compacted(&mut self, through: u64) {
        let Some(term) = self.log.term_at(through) else {
            return;
        };
        if through <= self.log.snap_index() || through > self.compact_bound {
            return;
        }
        self.log_start_config = self.config_at(through);
        self.log.compact_to(through, term);
    }

    /// The configuration in effect at `index`, at or after the log's start,
    /// with the index of the entry that established it: the latest
    /// configuration entry at or below it, else the log start's, if known.
    /// Its index is always set. A host exporting a snapshot at its applied
    /// index ships this.
    pub fn config_at(&self, index: u64) -> Option<ActiveConfigRecord<N>> {
        self.log
            .config_at(index)
            .or(self.log_start_config.as_ref())
            .cloned()
    }

    /// Recover the configuration in effect from the live log's latest
    /// configuration entry, else the persisted record, else the static
    /// members.
    pub(super) fn recover_configuration(&mut self, persisted: Option<ActiveConfigRecord<N>>) {
        let Some(latest) = self.log.configs().next_back() else {
            // The later of the persisted record and the configuration at
            // the log's start: a crash can lose the record's update after
            // a compaction past a newer configuration made it durable.
            let start = self.log_start_config.clone();
            self.active = match persisted {
                Some(record)
                    if start.as_ref().is_none_or(|start| {
                        record.log_index.unwrap_or(0) >= start.log_index.unwrap_or(0)
                    }) =>
                {
                    record
                }
                _ => {
                    start.unwrap_or_else(|| ActiveConfigRecord::steady(0, self.cfg.members.clone()))
                }
            };
            // A joint one stays pending at its entry, for a leader to
            // finalize.
            self.pending_joint_entry = self.active.joint_entry();
            return;
        };
        // A retiring leader that appended, but did not commit, the final
        // configuration excluding itself keeps the joint view, so it can still
        // campaign and replicate that final entry.
        let me = self.cfg.me;
        let retiring = latest.joint_old.is_none()
            && latest.log_index.is_some_and(|index| index > self.commit)
            && !latest.current.contains(&me);
        let prior_joint = || {
            let joint = |record: &&ActiveConfigRecord<N>| {
                record.joint_old.is_some() && record.current == latest.current
            };
            self.log
                .configs()
                .rev()
                .skip(1)
                .find(joint)
                .cloned()
                .or_else(|| {
                    persisted
                        .as_ref()
                        .filter(joint)
                        .map(|record| ActiveConfigRecord {
                            log_index: Some(record.log_index.unwrap_or(0)),
                            ..record.clone()
                        })
                })
        };
        if retiring
            && let Some(prior) = prior_joint()
            && prior
                .joint_old
                .as_ref()
                .is_some_and(|old| old.contains(&me))
        {
            self.pending_joint_entry = latest.log_index;
            self.active = prior;
            return;
        }
        self.active = latest.clone();
        self.pending_joint_entry = self.active.joint_entry();
    }
}
