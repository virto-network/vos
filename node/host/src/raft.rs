//! vos-raft's core over the node's store: what one agent's replica writes,
//! reads back for a peer, compacts and recovers.
//!
//! A data entry's Raft payload is the store's entry payload (its kind, its
//! blobs and its body), or empty for a new leader's no-op. A configuration
//! entry is vos-raft's own. The snapshot pointer in the core's meta is not
//! the host's: the log start moves only by compaction and a snapshot
//! switch, in their own row.

use vos_raft::core::{Load, Recovered, SnapshotSwitch, Write};
use vos_raft::{ActiveConfigRecord, EntryKind as RaftKind, LogEntry as RaftEntry, Meta};
use vos_wire::ids::AgentId;

use std::collections::VecDeque;

use crate::blobs::Blobs;
use crate::storage::Change;
use crate::store::{
    self, EntryKind, Fjall, HardState, LogEntry, Membership, NodeNumber, RaftRows, Store, Switch,
};

/// The store's entry for a Raft entry.
pub fn to_store(entry: &RaftEntry<NodeNumber>) -> LogEntry {
    match &entry.kind {
        RaftKind::Data { payload } if payload.is_empty() => LogEntry {
            term: entry.term,
            kind: EntryKind::NoOp,
            blobs: Vec::new(),
            body: Vec::new(),
        },
        // A payload this node cannot read is kept as the body of a work
        // result, which then fails to apply: it never panics the node. A
        // data payload never becomes a membership change.
        RaftKind::Data { payload } => LogEntry::from_payload(entry.term, payload)
            .filter(|parsed| parsed.kind != EntryKind::Configuration)
            .unwrap_or_else(|| LogEntry::result(entry.term, payload.clone())),
        RaftKind::ConfigChange { joint_old, members } => LogEntry {
            term: entry.term,
            kind: EntryKind::Configuration,
            blobs: Vec::new(),
            body: store::encode_configuration(members, joint_old.as_deref()),
        },
    }
}

/// The Raft entry for the store's entry at `index`.
pub fn to_raft(index: u64, entry: &LogEntry) -> RaftEntry<NodeNumber> {
    match entry.kind {
        EntryKind::NoOp => RaftEntry::data(index, entry.term, Vec::new()),
        EntryKind::Result => RaftEntry::data(index, entry.term, entry.payload()),
        EntryKind::Configuration => match store::decode_configuration(&entry.body) {
            Some((members, joint_old)) => {
                RaftEntry::config_change(index, entry.term, joint_old, members)
            }
            None => RaftEntry::data(index, entry.term, entry.payload()),
        },
    }
}

/// The writer's changes for one of the core's writes, in its order:
/// truncate, append, then the hard state and membership. The meta's
/// snapshot pointer is left out.
pub fn changes(agent: AgentId, write: &Write<NodeNumber>) -> Vec<Change> {
    let mut changes = Vec::with_capacity(write.entries.len() + 3);
    if let Some(after) = write.truncate_after {
        changes.push(Change::Truncate { agent, after });
    }
    for entry in &write.entries {
        changes.push(Change::Append {
            agent,
            index: entry.index,
            entry: to_store(entry),
        });
    }
    if let Some(meta) = &write.meta {
        changes.push(Change::Hard {
            agent,
            hard: HardState {
                term: meta.current_term,
                vote: meta.voted_for,
                commit: meta.commit_index,
            },
            sync: write.sync,
        });
    }
    if let Some(record) = &write.active_config {
        changes.push(Change::Membership {
            agent,
            membership: membership(record),
        });
    }
    changes
}

/// The entries a load asks for, within its bytes.
pub fn load(
    store: &impl Store,
    agent: AgentId,
    load: &Load,
) -> store::Result<Vec<RaftEntry<NodeNumber>>> {
    Ok(store
        .log_range(agent, load.from, load.to, load.max_bytes)?
        .iter()
        .map(|(index, entry)| to_raft(*index, entry))
        .collect())
}

/// The compaction of the log through `through`, if the log still holds it,
/// with `configuration` in effect there, when the core knows it.
pub fn compaction(
    store: &impl Store,
    agent: AgentId,
    through: u64,
    configuration: Option<&ActiveConfigRecord<NodeNumber>>,
) -> store::Result<Option<Change>> {
    Ok(store
        .log_entry(agent, through)?
        .map(|entry| Change::Compact {
            agent,
            through,
            term: entry.term,
            membership: configuration.map(membership),
        }))
}

fn membership(record: &ActiveConfigRecord<NodeNumber>) -> Membership {
    Membership {
        index: record.log_index,
        members: record.current.clone(),
        joint_old: record.joint_old.clone(),
    }
}

fn record(membership: Membership) -> ActiveConfigRecord<NodeNumber> {
    ActiveConfigRecord {
        log_index: membership.index,
        current: membership.members,
        joint_old: membership.joint_old,
    }
}

/// The writer's switch to a snapshot staged under `epoch`, at `index` and
/// `term`, with the rows vos-raft's core computed for it: one synced batch.
pub fn switch_change(
    agent: AgentId,
    epoch: u8,
    index: u64,
    term: u64,
    switch: &SnapshotSwitch<NodeNumber>,
) -> Change {
    Change::Switch {
        agent,
        switch: Switch {
            epoch,
            index,
            term,
            hard: HardState {
                term: switch.meta.current_term,
                vote: switch.meta.voted_for,
                commit: switch.meta.commit_index,
            },
            membership: membership(&switch.active_config),
            log_start_membership: switch.log_start_config.as_ref().map(membership),
            truncate_after: switch.truncate_after,
        },
    }
}

/// What recovery must do to `agent`'s log so that no entry is left
/// without its blob, before its core is recovered: the changes, for the
/// node log writer (after it was told the agent's recovered applied
/// index), and the index the log is cut from, if any.
///
/// An entry naming a blob the store does not hold was never reported
/// durable, so no replica counted it; every agent shares one journal, so
/// its row can survive a crash its blob did not. The log is cut at the
/// first such entry.
///
/// An entry at or below the applied index whose blob is gone (a disk that
/// lost what it said it wrote) is committed, and the state holds its
/// effect: the log is compacted through the applied index instead, with
/// the membership in effect there, so no entry is left without its blob
/// and the log never ends below it.
pub fn recovery_cut(store: &Fjall, blobs: &Blobs, agent: AgentId) -> store::Result<Cut> {
    let rows = store.raft(agent)?;
    let missing = |entry: &LogEntry| -> store::Result<bool> {
        for blob in &entry.blobs {
            if !blobs.contains(&blob.hash)? {
                return Ok(true);
            }
        }
        Ok(false)
    };
    let mut cut = Cut::default();
    let mut applied_lost = false;
    for (index, entry) in &rows.log {
        if !missing(entry)? {
            continue;
        }
        if *index <= rows.applied {
            applied_lost = true;
            continue;
        }
        cut.changes.push(Change::Truncate {
            agent,
            after: index - 1,
        });
        cut.from = Some(*index);
        break;
    }
    if applied_lost
        && let Some((_, at_applied)) = rows.log.iter().find(|(index, _)| *index == rows.applied)
    {
        let membership = rows
            .log
            .iter()
            .rev()
            .filter(|(index, entry)| {
                *index <= rows.applied && entry.kind == EntryKind::Configuration
            })
            .find_map(|(index, entry)| {
                let (members, joint_old) = store::decode_configuration(&entry.body)?;
                Some(Membership {
                    index: Some(*index),
                    members,
                    joint_old,
                })
            })
            .or(rows.log_start_membership.clone());
        cut.changes.insert(
            0,
            Change::Compact {
                agent,
                through: rows.applied,
                term: at_applied.term,
                membership,
            },
        );
    }
    Ok(cut)
}

/// Recovery's changes to one agent's log ([`recovery_cut`]).
#[derive(Default)]
pub struct Cut {
    pub changes: Vec<Change>,
    /// The index the log is cut from, if it is.
    pub from: Option<u64>,
}

/// The entry reports one replica owes its core: its writes in order, each
/// with the blobs its entries name that were missing. A write's entries
/// are reported once its blobs, and every earlier write's, are stored.
#[derive(Default)]
pub struct EntryReports {
    pending: VecDeque<Pending>,
}

struct Pending {
    seq: u64,
    /// The write's entries that still wait, by index, with their blobs.
    waiting: Vec<(u64, Vec<[u8; 32]>)>,
}

impl EntryReports {
    /// `write` is durable. A truncation in it drops the waits of the
    /// entries it removed, from earlier writes too. `stored` answers from a
    /// [`Blobs::touch`] of the write's blobs, so none of them is collected
    /// while the entry comes to rely on it.
    pub fn written(&mut self, write: &Write<NodeNumber>, stored: impl Fn(&[u8; 32]) -> bool) {
        if let Some(after) = write.truncate_after {
            for pending in &mut self.pending {
                pending.waiting.retain(|(index, _)| *index <= after);
            }
        }
        let waiting = write
            .entries
            .iter()
            .filter_map(|entry| {
                let missing: Vec<[u8; 32]> = to_store(entry)
                    .blobs
                    .iter()
                    .map(|blob| blob.hash)
                    .filter(|hash| !stored(hash))
                    .collect();
                (!missing.is_empty()).then_some((entry.index, missing))
            })
            .collect();
        self.pending.push_back(Pending {
            seq: write.seq,
            waiting,
        });
    }

    /// The last write whose entries can now be reported, if any.
    pub fn ready(&mut self, stored: impl Fn(&[u8; 32]) -> bool) -> Option<u64> {
        let mut last = None;
        while let Some(front) = self.pending.front_mut() {
            front
                .waiting
                .retain(|(_, missing)| missing.iter().any(|hash| !stored(hash)));
            if !front.waiting.is_empty() {
                break;
            }
            last = Some(front.seq);
            self.pending.pop_front();
        }
        last
    }

    /// Every blob a waiting write still needs, each once: the host fetches
    /// them together.
    pub fn missing(&self) -> Vec<[u8; 32]> {
        let mut missing: Vec<[u8; 32]> = self
            .pending
            .iter()
            .flat_map(|pending| pending.waiting.iter())
            .flat_map(|(_, missing)| missing.iter().copied())
            .collect();
        missing.sort_unstable();
        missing.dedup();
        missing
    }

    /// A snapshot switch at `index`: the entries at or below it are covered,
    /// and with them every entry above if the log's suffix went.
    pub fn switched(&mut self, index: u64, keeps_suffix: bool) {
        for pending in &mut self.pending {
            pending
                .waiting
                .retain(|(at, _)| keeps_suffix && *at > index);
        }
    }
}

/// What the core recovers from the store's rows.
pub fn recovered(rows: RaftRows) -> Recovered<NodeNumber> {
    Recovered {
        meta: Meta {
            current_term: rows.hard.term,
            voted_for: rows.hard.vote,
            commit_index: rows.hard.commit,
            snap_last_index: rows.log_start.0,
            snap_last_term: rows.log_start.1,
        },
        entries: rows
            .log
            .iter()
            .map(|(index, entry)| to_raft(*index, entry))
            .collect(),
        active_config: rows.membership.map(record),
        log_start_config: rows.log_start_membership.map(record),
        applied: rows.applied,
        vote_floor: rows.vote_floor,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Arc;

    use vos_raft::core::{Action, Answer, Core, SnapshotConfiguration};
    use vos_raft::{Config, Message, Role};
    use vos_wire::result::Write as StateWrite;

    use super::*;
    use crate::NoHooks;
    use crate::storage::StorageThread;
    use crate::store::{Batch as _, BlobRef, Fjall, View};

    const AGENT: AgentId = AgentId(7);
    const NODES: [NodeNumber; 3] = [1, 2, 3];

    #[test]
    fn entries_round_trip_through_the_store() {
        let result = LogEntry {
            term: 4,
            kind: EntryKind::Result,
            blobs: vec![BlobRef {
                hash: [9; 32],
                len: 1 << 20,
            }],
            body: b"result".to_vec(),
        };
        let raft = to_raft(5, &result);
        assert_eq!(to_store(&raft), result);
        let no_op = RaftEntry::data(6, 4, Vec::new());
        assert_eq!(to_store(&no_op).kind, EntryKind::NoOp);
        assert_eq!(to_raft(6, &to_store(&no_op)), no_op);
        let configuration = RaftEntry::config_change(7, 4, Some(vec![1, 2, 3]), vec![1, 2, 4]);
        assert_eq!(to_raft(7, &to_store(&configuration)), configuration);
        let unreadable = RaftEntry::data(8, 4, vec![0xee, 1]);
        assert_eq!(to_store(&unreadable).body, vec![0xee, 1]);
        // A data payload shaped like a configuration stays data.
        let disguised = RaftEntry::data(9, 4, vec![2, 0, 0, 1, 7, 0]);
        let stored = to_store(&disguised);
        assert_eq!(stored.kind, EntryKind::Result);
        assert!(matches!(to_raft(9, &stored).kind, RaftKind::Data { .. }));
    }

    /// A Raft write of `entries` (index, blobs named), after `truncate`.
    fn write(seq: u64, truncate: Option<u64>, entries: &[(u64, &[[u8; 32]])]) -> Write<NodeNumber> {
        Write {
            seq,
            truncate_after: truncate,
            entries: entries
                .iter()
                .map(|(index, blobs)| {
                    let entry = LogEntry {
                        blobs: blobs
                            .iter()
                            .map(|hash| BlobRef {
                                hash: *hash,
                                len: 1,
                            })
                            .collect(),
                        ..LogEntry::result(1, vec![1])
                    };
                    RaftEntry::data(*index, 1, entry.payload())
                })
                .collect(),
            meta: None,
            active_config: None,
            sync: true,
        }
    }

    #[test]
    fn entry_reports_wait_for_blobs_in_write_order() {
        let stored = std::cell::RefCell::new(std::collections::HashSet::new());
        let is_stored = |hash: &[u8; 32]| stored.borrow().contains(hash);
        let mut reports = EntryReports::default();
        reports.written(&write(1, None, &[(1, &[[7; 32]])]), is_stored);
        reports.written(&write(2, None, &[(2, &[])]), is_stored);
        assert_eq!(
            reports.ready(is_stored),
            None,
            "the first write waits for its blob"
        );
        assert_eq!(reports.missing(), vec![[7; 32]]);
        stored.borrow_mut().insert([7; 32]);
        assert_eq!(reports.ready(is_stored), Some(2));
        assert_eq!(reports.ready(is_stored), None);
    }

    #[test]
    fn a_truncation_drops_the_waits_it_removes() {
        let is_stored = |_: &[u8; 32]| false;
        let mut reports = EntryReports::default();
        reports.written(&write(1, None, &[(11, &[[7; 32]])]), is_stored);
        // A new leader replaces 11, with an entry naming no blob.
        reports.written(&write(2, Some(10), &[(11, &[])]), is_stored);
        assert_eq!(reports.ready(is_stored), Some(2));
    }

    #[test]
    fn every_awaited_blob_is_listed_and_a_switch_releases_its_waits() {
        let is_stored = |_: &[u8; 32]| false;
        let mut reports = EntryReports::default();
        reports.written(&write(1, None, &[(1, &[[7; 32]])]), is_stored);
        reports.written(
            &write(2, None, &[(2, &[[8; 32], [7; 32]]), (3, &[[9; 32]])]),
            is_stored,
        );
        assert_eq!(reports.missing(), vec![[7; 32], [8; 32], [9; 32]]);
        // A snapshot through 2, keeping the suffix: only 3 still waits.
        reports.switched(2, true);
        assert_eq!(reports.missing(), vec![[9; 32]]);
        assert_eq!(reports.ready(is_stored), Some(1));
        // A snapshot that dropped the suffix releases everything.
        reports.switched(2, false);
        assert_eq!(reports.ready(is_stored), Some(2));
    }

    #[test]
    fn recovery_cuts_the_log_at_its_first_missing_blob() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path().join("store")).unwrap();
        let blobs = Blobs::open(dir.path().join("blobs"), &store).unwrap();
        let held = Arc::new(vec![1u8; 100]);
        let held_ref = crate::blobs::blob_ref(&held);
        smol::block_on(blobs.put(held_ref, held)).unwrap();
        let naming = |blob: BlobRef| LogEntry {
            blobs: vec![blob],
            ..LogEntry::result(1, Vec::new())
        };
        let lost = BlobRef {
            hash: [9; 32],
            len: 100,
        };
        let mut batch = store.batch();
        batch.append(AGENT, 1, &LogEntry::result(1, vec![1]));
        batch.append(AGENT, 2, &naming(held_ref));
        batch.append(AGENT, 3, &naming(lost));
        batch.append(AGENT, 4, &LogEntry::result(1, vec![4]));
        batch.commit(crate::store::Durability::Synced).unwrap();
        let writer = StorageThread::spawn(store.clone(), Arc::new(NoHooks));
        let cut = recovery_cut(&store, &blobs, AGENT).unwrap();
        assert_eq!(cut.from, Some(3));
        smol::block_on(writer.commit(cut.changes)).unwrap();
        let held_indices: Vec<u64> = store
            .raft(AGENT)
            .unwrap()
            .log
            .iter()
            .map(|(index, _)| *index)
            .collect();
        assert_eq!(held_indices, vec![1, 2]);
        assert!(
            recovery_cut(&store, &blobs, AGENT)
                .unwrap()
                .changes
                .is_empty()
        );
    }

    /// An applied entry whose blob is gone compacts the log through the
    /// applied index, keeping the configuration in effect there.
    #[test]
    fn recovery_compacts_past_an_applied_entry_missing_its_blob() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path().join("store")).unwrap();
        let blobs = Blobs::open(dir.path().join("blobs"), &store).unwrap();
        let lost = LogEntry {
            blobs: vec![BlobRef {
                hash: [9; 32],
                len: 100,
            }],
            ..LogEntry::result(1, Vec::new())
        };
        let configuration = LogEntry {
            term: 1,
            kind: EntryKind::Configuration,
            blobs: Vec::new(),
            body: store::encode_configuration(&[1, 2, 4], None),
        };
        let mut batch = store.batch();
        batch.append(AGENT, 1, &LogEntry::result(1, vec![1]));
        batch.append(AGENT, 2, &configuration);
        batch.append(AGENT, 3, &lost);
        batch.append(AGENT, 4, &LogEntry::result(1, vec![4]));
        batch.apply(AGENT, 0, 3, &[]);
        batch.commit(crate::store::Durability::Synced).unwrap();
        let writer = StorageThread::spawn(store.clone(), Arc::new(NoHooks));
        writer.recovered(AGENT, 3);
        let cut = recovery_cut(&store, &blobs, AGENT).unwrap();
        assert_eq!(cut.from, None);
        smol::block_on(writer.commit(cut.changes)).unwrap();
        let rows = store.raft(AGENT).unwrap();
        assert_eq!(rows.log_start, (3, 1));
        assert_eq!(
            rows.log_start_membership,
            Some(Membership {
                index: Some(2),
                members: vec![1, 2, 4],
                joint_old: None,
            })
        );
        assert_eq!(
            rows.log.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            vec![4]
        );
    }

    /// The key the test's state machine counts applied entries under.
    fn counter() -> Vec<u8> {
        vec![0x01, 0x00]
    }

    /// One replica: its store, writer and core, and what it applied.
    struct Replica {
        dir: std::path::PathBuf,
        store: Option<Fjall>,
        writer: Option<StorageThread>,
        core: Option<Core<NodeNumber>>,
        applied: u64,
    }

    /// A snapshot in flight: from, to, its index and term, the
    /// configuration in effect there, and its rows.
    type Shipped = (
        NodeNumber,
        NodeNumber,
        u64,
        u64,
        Option<SnapshotConfiguration<NodeNumber>>,
        Vec<(Vec<u8>, Vec<u8>)>,
    );

    struct Group {
        compact_hysteresis: u64,
        replicas: BTreeMap<NodeNumber, Replica>,
        network: VecDeque<(NodeNumber, NodeNumber, Message<NodeNumber>)>,
        snapshots: VecDeque<Shipped>,
        installs: u64,
        now: u64,
        seed: u64,
        /// Every entry any replica applied, by index: they must agree.
        applied: BTreeMap<u64, LogEntry>,
        _dir: tempfile::TempDir,
    }

    fn config(me: NodeNumber, compact_hysteresis: u64) -> Config<NodeNumber> {
        let mut cfg = Config::new(me, NODES.to_vec(), [0; 32]);
        cfg.election_timeout_ms = (150, 300);
        cfg.heartbeat_interval_ms = 50;
        cfg.compact_hysteresis = compact_hysteresis;
        cfg.cache_bytes = 256;
        cfg
    }

    impl Group {
        fn new(compact_hysteresis: u64) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let mut group = Self {
                compact_hysteresis,
                replicas: BTreeMap::new(),
                snapshots: VecDeque::new(),
                installs: 0,
                network: VecDeque::new(),
                now: 0,
                seed: 1,
                applied: BTreeMap::new(),
                _dir: dir,
            };
            for node in NODES {
                let dir = group._dir.path().join(format!("node{node}"));
                group.replicas.insert(
                    node,
                    Replica {
                        dir,
                        store: None,
                        writer: None,
                        core: None,
                        applied: 0,
                    },
                );
                group.start(node);
            }
            group
        }

        /// Open `node`'s store and recover its core from it.
        fn start(&mut self, node: NodeNumber) {
            self.seed = self.seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let replica = self.replicas.get_mut(&node).unwrap();
            let store = Fjall::open(&replica.dir).unwrap();
            let rows = store.raft(AGENT).unwrap();
            replica.applied = rows.applied;
            let writer = StorageThread::spawn(store.clone(), Arc::new(NoHooks));
            writer.recovered(AGENT, rows.applied);
            let core = Core::new(
                config(node, self.compact_hysteresis),
                recovered(rows),
                self.now,
                self.seed,
            );
            replica.writer = Some(writer);
            replica.store = Some(store);
            replica.core = Some(core);
            self.process(node);
        }

        /// Stop `node` and drop its store, as a process exit would.
        fn stop(&mut self, node: NodeNumber) {
            let replica = self.replicas.get_mut(&node).unwrap();
            replica.core = None;
            replica.writer = None;
            replica.store = None;
        }

        fn process(&mut self, node: NodeNumber) {
            loop {
                let replica = self.replicas.get_mut(&node).unwrap();
                let Some(core) = replica.core.as_mut() else {
                    return;
                };
                let actions = core.take_actions();
                if actions.is_empty() {
                    return;
                }
                for action in actions {
                    let replica = self.replicas.get_mut(&node).unwrap();
                    let core = replica.core.as_mut().unwrap();
                    let writer = replica.writer.as_ref().unwrap();
                    let store = replica.store.as_ref().unwrap();
                    match action {
                        Action::Write(write) => {
                            smol::block_on(writer.commit(changes(AGENT, &write))).unwrap();
                            core.durable(write.seq);
                            core.entries_durable(write.seq);
                        }
                        Action::Send { to, message } => self.network.push_back((node, to, message)),
                        Action::LoadEntries(request) => {
                            let entries = load(store, AGENT, &request).unwrap();
                            core.loaded(request, entries);
                        }
                        Action::Committed { index } => {
                            for at in replica.applied + 1..=index {
                                let entry = store
                                    .log_entry(AGENT, at)
                                    .unwrap()
                                    .expect("a committed entry");
                                let count = replica.applied + 1;
                                let writes = vec![StateWrite {
                                    key: counter(),
                                    value: Some(count.to_be_bytes().to_vec()),
                                }];
                                smol::block_on(writer.commit(vec![Change::Apply {
                                    agent: AGENT,
                                    epoch: store.snapshot().epoch(AGENT).unwrap(),
                                    index: at,
                                    writes,
                                }]))
                                .unwrap();
                                replica.applied = at;
                                let earlier =
                                    self.applied.entry(at).or_insert_with(|| entry.clone());
                                assert_eq!(
                                    *earlier, entry,
                                    "replicas applied different entries at {at}"
                                );
                            }
                            core.durably_applied(writer.durably_applied(AGENT));
                        }
                        Action::CompactBound {
                            through,
                            configuration,
                        } => {
                            if let Some(change) =
                                compaction(store, AGENT, through, configuration.as_ref()).unwrap()
                            {
                                smol::block_on(writer.commit(vec![change])).unwrap();
                                core.compacted(through);
                            }
                        }
                        Action::SendSnapshot { to, .. } => {
                            // Exported at the leader's own applied index,
                            // with the configuration in effect there.
                            let mut export = store.export(AGENT).unwrap();
                            let configuration = core.config_at(export.applied).map(|record| {
                                SnapshotConfiguration {
                                    members: record.current,
                                    joint_old: record.joint_old,
                                    index: record.log_index.unwrap_or(0),
                                }
                            });
                            let mut rows = Vec::new();
                            while let Some(chunk) = export.next_chunk(1 << 12).unwrap() {
                                rows.extend(chunk);
                            }
                            self.snapshots.push_back((
                                node,
                                to,
                                export.applied,
                                export.term,
                                configuration,
                                rows,
                            ));
                        }
                        Action::Answer(Answer::Propose { .. })
                        | Action::Answer(_)
                        | Action::Changed { .. } => {}
                    }
                }
            }
        }

        /// `to` installs a snapshot from `from`: staged under its next
        /// epoch, switched to in one synced batch, the old epoch dropped.
        fn install(&mut self, shipped: Shipped) {
            let (from, to, index, term, configuration, rows) = shipped;
            let replica = self.replicas.get_mut(&to).unwrap();
            let Some(core) = replica.core.as_mut() else {
                return;
            };
            if core.role() != Role::Follower
                || core.status().leader_hint != Some(from)
                || index <= replica.applied
            {
                return;
            }
            let store = replica.store.as_ref().unwrap();
            let writer = replica.writer.as_ref().unwrap();
            let old = store.snapshot().epoch(AGENT).unwrap();
            let epoch = crate::store::next_epoch(old);
            let drop = |epoch| Change::DropEpoch {
                agent: AGENT,
                epoch,
                limit: usize::MAX,
            };
            smol::block_on(writer.commit(vec![drop(epoch)])).unwrap();
            smol::block_on(writer.commit(vec![Change::Stage {
                agent: AGENT,
                epoch,
                first: true,
                rows,
            }]))
            .unwrap();
            let switch = core.snapshot_switch(index, term, configuration.as_ref());
            smol::block_on(writer.commit(vec![switch_change(AGENT, epoch, index, term, &switch)]))
                .unwrap();
            core.snapshot_installed(index, term, configuration);
            replica.applied = index;
            smol::block_on(writer.commit(vec![drop(old)])).unwrap();
            assert!(store.stale_epochs(AGENT).unwrap().is_empty());
            self.installs += 1;
            self.process(to);
        }

        fn run(&mut self, millis: u64) {
            let until = self.now + millis;
            while self.now < until {
                self.now += 1;
                while let Some(shipped) = self.snapshots.pop_front() {
                    self.install(shipped);
                }
                while let Some((from, to, message)) = self.network.pop_front() {
                    if let Some(core) = self.replicas.get_mut(&to).unwrap().core.as_mut() {
                        core.tick(self.now);
                        core.receive(from, message);
                        self.process(to);
                    }
                }
                for node in NODES {
                    if let Some(core) = self.replicas.get_mut(&node).unwrap().core.as_mut()
                        && core.next_deadline() <= self.now
                    {
                        core.tick(self.now);
                        self.process(node);
                    }
                }
            }
        }

        fn leader(&self) -> Option<NodeNumber> {
            NODES.into_iter().find(|node| {
                self.replicas[node]
                    .core
                    .as_ref()
                    .is_some_and(|core| core.role() == Role::Leader)
            })
        }

        fn propose(&mut self, node: NodeNumber, n: u64) {
            let payload = LogEntry::result(0, n.to_be_bytes().to_vec()).payload();
            self.replicas
                .get_mut(&node)
                .unwrap()
                .core
                .as_mut()
                .unwrap()
                .propose(n, payload);
            self.process(node);
        }
    }

    /// Every replica applied the same entries through the same index, and
    /// its state says so: the index it applied through.
    fn agreed(group: &Group) -> u64 {
        let indices: Vec<u64> = NODES
            .iter()
            .map(|node| group.replicas[node].applied)
            .collect();
        assert!(indices.iter().all(|&at| at == indices[0]), "{indices:?}");
        for node in NODES {
            let store = group.replicas[&node].store.as_ref().unwrap();
            let count = store.snapshot().get(AGENT, &counter()).unwrap().unwrap();
            assert_eq!(u64::from_be_bytes(count.try_into().unwrap()), indices[0]);
        }
        indices[0]
    }

    fn results(group: &Group) -> u64 {
        group
            .applied
            .values()
            .filter(|entry| entry.kind == EntryKind::Result)
            .count() as u64
    }

    /// Every replica recovers its log, hard state and applied index from
    /// its store across restarts, the leader's included. Logs compact as
    /// they go, so a replica down meanwhile catches up by a snapshot.
    #[test]
    fn a_group_over_real_stores_keeps_its_log_across_restarts() {
        let mut group = Group::new(4);
        let mut proposed = 0;
        for round in 0..12u64 {
            group.run(400);
            let leader = group.leader().expect("a leader");
            for _ in 0..10 {
                proposed += 1;
                group.propose(leader, proposed);
            }
            group.run(400);
            // Restart one replica, the leader every third round.
            let node = if round.is_multiple_of(3) {
                leader
            } else {
                NODES[(round % 3) as usize]
            };
            group.stop(node);
            group.run(200);
            group.start(node);
        }
        group.run(1_000);
        let leader = group.leader().expect("a leader");
        group.propose(leader, 0);
        group.run(1_000);
        agreed(&group);
        assert!(group.installs > 0, "no replica needed a snapshot");
        // Entries a replica installed by snapshot it never applied one by
        // one; the group as a whole applied every result.
        assert!(results(&group) > proposed, "{} results", results(&group));
    }

    /// Every replica compacts while all are up, then each restarts from
    /// its compacted log (the log-start row becomes the core's snapshot
    /// pointer), and the group goes on.
    #[test]
    fn replicas_restart_from_compacted_logs() {
        let mut group = Group::new(4);
        group.run(400);
        let leader = group.leader().expect("a leader");
        for n in 1..=30 {
            group.propose(leader, n);
            group.run(5);
        }
        group.run(1_000);
        let before = agreed(&group);
        for node in NODES {
            let start = group.replicas[&node]
                .store
                .as_ref()
                .unwrap()
                .raft(AGENT)
                .unwrap()
                .log_start;
            assert!(start.0 > 0, "node {node} compacted before its restart");
            group.stop(node);
            group.start(node);
            group.run(500);
        }
        let leader = group.leader().expect("a leader after the restarts");
        for n in 31..=40 {
            group.propose(leader, n);
            group.run(5);
        }
        group.run(1_000);
        assert!(agreed(&group) > before);
        assert_eq!(results(&group), 40);
    }

    /// With every replica up, each compacts its log below what it durably
    /// applied, and keeps the rest.
    #[test]
    fn a_group_over_real_stores_compacts_its_logs() {
        let mut group = Group::new(4);
        group.run(400);
        let leader = group.leader().expect("a leader");
        for n in 1..=60 {
            group.propose(leader, n);
            group.run(5);
        }
        group.run(1_000);
        let through = agreed(&group);
        assert!(results(&group) == 60);
        for node in NODES {
            let store = group.replicas[&node].store.as_ref().unwrap();
            let rows = store.raft(AGENT).unwrap();
            assert!(rows.log_start.0 > 0, "node {node} never compacted");
            assert!(rows.log_start.0 <= rows.applied);
            assert_eq!(rows.applied, through);
            assert_eq!(
                rows.log.first().map(|(index, _)| *index),
                Some(rows.log_start.0 + 1),
                "node {node}: the log starts right after its start row"
            );
        }
    }
}
