use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::Arc;

use vos_raft::core::{Action, Answer, Core};
use vos_raft::{Config, Message, Role};
use vos_wire::result::Write as StateWrite;

use super::*;
use crate::NoHooks;
use crate::storage::StorageThread;
use crate::store::{BlobRef, Fjall};

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

#[test]
fn a_large_results_blob_weighs_in_its_payload() {
    let blob = BlobRef {
        hash: [9; 32],
        len: 3 << 20,
    };
    let program = BlobRef {
        hash: [8; 32],
        len: 5 << 20,
    };
    let large = LogEntry {
        term: 1,
        kind: EntryKind::LargeResult,
        blobs: vec![blob, program],
        body: Vec::new(),
    };
    let payload = large.payload();
    assert_eq!(payload_weight(&payload), payload.len() as u64 + (3 << 20));
    // An inline result's programs, and anything else, weigh its bytes.
    let installs = LogEntry {
        blobs: vec![program],
        ..LogEntry::result(1, vec![7; 100])
    };
    let payload = installs.payload();
    assert_eq!(payload_weight(&payload), payload.len() as u64);
    assert_eq!(payload_weight(&[]), 0);
    let truncated = &large.payload()[..20];
    assert_eq!(payload_weight(truncated), 20);
}

/// `reports` told `write` is durable, its entries naming the blobs their
/// appends name.
fn written(
    reports: &mut EntryReports,
    write: &Write<NodeNumber>,
    stored: impl Fn(&[u8; 32]) -> bool,
) {
    reports.written(write, named(&changes(AGENT, write)), stored);
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
    let stored = std::cell::RefCell::new(HashSet::new());
    let is_stored = |hash: &[u8; 32]| stored.borrow().contains(hash);
    let mut reports = EntryReports::default();
    written(&mut reports, &write(1, None, &[(1, &[[7; 32]])]), is_stored);
    written(&mut reports, &write(2, None, &[(2, &[])]), is_stored);
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
    written(
        &mut reports,
        &write(1, None, &[(11, &[[7; 32]])]),
        is_stored,
    );
    // A new leader replaces 11, with an entry naming no blob.
    written(&mut reports, &write(2, Some(10), &[(11, &[])]), is_stored);
    assert_eq!(reports.ready(is_stored), Some(2));
}

#[test]
fn every_awaited_blob_is_listed_and_a_switch_releases_its_waits() {
    let is_stored = |_: &[u8; 32]| false;
    let mut reports = EntryReports::default();
    written(&mut reports, &write(1, None, &[(1, &[[7; 32]])]), is_stored);
    written(
        &mut reports,
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
    batch.commit(crate::store::PersistMode::SyncAll).unwrap();
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

    // Committed through 4: the entry at 3 is kept, its blob to fetch
    // again, and the log is cut at the next entry missing one, past
    // the commit.
    let other = AgentId(8);
    let gone = BlobRef {
        hash: [5; 32],
        len: 100,
    };
    let mut batch = store.batch();
    batch.append(other, 1, &LogEntry::result(1, vec![1]));
    batch.append(other, 2, &naming(held_ref));
    batch.append(other, 3, &naming(lost));
    batch.append(other, 4, &LogEntry::result(1, vec![4]));
    batch.append(other, 5, &naming(gone));
    batch.append(other, 6, &LogEntry::result(1, vec![6]));
    batch.apply(other, 0, 1, &[]);
    batch.hard_state(
        other,
        &HardState {
            term: 1,
            vote: None,
            commit: 4,
        },
    );
    batch.commit(crate::store::PersistMode::SyncAll).unwrap();
    writer.recovered(other, 1);
    let cut = recovery_cut(&store, &blobs, other).unwrap();
    assert_eq!(cut.from, Some(5));
    assert_eq!(cut.refetch, vec![(3, vec![lost.hash])]);
    smol::block_on(writer.commit(cut.changes)).unwrap();
    let rows = store.raft(other).unwrap();
    assert_eq!(
        rows.log.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    assert_eq!(rows.log_start.0, 0, "nothing applied is compacted");
}

/// The committed entries recovery keeps without their blobs wait ahead
/// of every write, and once their blobs come, report as recovered.
#[test]
fn recovered_entries_wait_for_their_blobs_ahead_of_every_write() {
    let stored = std::cell::RefCell::new(HashSet::new());
    let is_stored = |hash: &[u8; 32]| stored.borrow().contains(hash);
    let mut reports = EntryReports::default();
    reports.recovered(vec![(3, vec![[7; 32]])]);
    written(&mut reports, &write(1, None, &[(5, &[])]), is_stored);
    assert_eq!(reports.missing(), vec![[7; 32]]);
    assert_eq!(reports.ready(is_stored), None, "the write waits behind");
    stored.borrow_mut().insert([7; 32]);
    assert_eq!(reports.ready(is_stored), Some(1));
    reports.recovered(vec![(9, vec![[8; 32]])]);
    stored.borrow_mut().insert([8; 32]);
    assert_eq!(reports.ready(is_stored), Some(RECOVERED));
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
    batch.commit(crate::store::PersistMode::SyncAll).unwrap();
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
    Option<ActiveConfigRecord<NodeNumber>>,
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
    let mut cfg = Config::new(me, NODES.to_vec());
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
                            let earlier = self.applied.entry(at).or_insert_with(|| entry.clone());
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
                        let configuration = core.config_at(export.applied);
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
