//! vos-raft's core over the node's store: what one agent's replica writes,
//! reads back for a peer, compacts and recovers.
//!
//! A data entry's Raft payload is the store's entry payload (its kind, its
//! blobs and its body), or empty for a new leader's no-op. A configuration
//! entry is vos-raft's own. The snapshot pointer in the core's meta is not
//! the host's: the log start moves only by compaction and a snapshot
//! switch, in their own row.

use vos_raft::core::{Load, Recovered, Write};
use vos_raft::{ActiveConfigRecord, EntryKind as RaftKind, LogEntry as RaftEntry, Meta};
use vos_wire::ids::AgentId;

use crate::storage::Change;
use crate::store::{self, EntryKind, HardState, LogEntry, Membership, NodeNumber, RaftRows, Store};

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
            membership: Membership {
                index: record.log_index,
                members: record.current.clone(),
                joint_old: record.joint_old.clone(),
            },
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

/// The compaction of the log through `through`, if the log still holds it.
pub fn compaction(
    store: &impl Store,
    agent: AgentId,
    through: u64,
) -> store::Result<Option<Change>> {
    Ok(store
        .log_entry(agent, through)?
        .map(|entry| Change::Compact {
            agent,
            through,
            term: entry.term,
        }))
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
        active_config: rows.membership.map(|membership| ActiveConfigRecord {
            log_index: membership.index,
            current: membership.members,
            joint_old: membership.joint_old,
        }),
        applied: rows.applied,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Arc;

    use vos_raft::core::{Action, Answer, Core};
    use vos_raft::{Config, Message, Role};
    use vos_wire::result::Write as StateWrite;

    use super::*;
    use crate::NoHooks;
    use crate::storage::StorageThread;
    use crate::store::{BlobRef, Fjall, View};

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

    struct Group {
        compact_hysteresis: u64,
        replicas: BTreeMap<NodeNumber, Replica>,
        network: VecDeque<(NodeNumber, NodeNumber, Message<NodeNumber>)>,
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
                        Action::CompactBound { through } => {
                            if let Some(change) = compaction(store, AGENT, through).unwrap() {
                                smol::block_on(writer.commit(vec![change])).unwrap();
                                core.compacted(through);
                            }
                        }
                        Action::SendSnapshot { to, .. } => core.snapshot_failed(to),
                        Action::Answer(Answer::Propose { .. })
                        | Action::Answer(_)
                        | Action::Changed { .. } => {}
                    }
                }
            }
        }

        fn run(&mut self, millis: u64) {
            let until = self.now + millis;
            while self.now < until {
                self.now += 1;
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

    /// Without compaction past a stopped replica (it would need a
    /// snapshot), every replica recovers its log, hard state and applied
    /// index from its store across restarts, the leader's included.
    #[test]
    fn a_group_over_real_stores_keeps_its_log_across_restarts() {
        let mut group = Group::new(u64::MAX);
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
