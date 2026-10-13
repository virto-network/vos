//! A deterministic simulation of replicas, their network and their stores,
//! for testing the protocol core under faults.
//!
//! - [`Network`] carries any payload between nodes, and drops, delays,
//!   duplicates, reorders and partitions as configured. Everything is driven
//!   by one seeded generator, so a failing seed replays exactly.
//! - [`Store`] is one node's durable state with a queue of unsynced writes
//!   and compactions; a crash keeps any prefix of them. A snapshot switch
//!   is durable at once.
//! - [`Cluster`] runs one [`Core`] per node over both, carries snapshots
//!   between them, and checks Raft's safety properties as it goes, and
//!   every answered read index against what was committed when the read
//!   was asked.

use alloc::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};
use alloc::vec::Vec;
use core::cmp::Reverse;

use crate::config::{Config, NodeId};
use crate::core::{
    Action, ActiveConfigRecord, Answer, Core, Recovered, SnapshotConfiguration, SnapshotSwitch,
    Write,
};
use crate::log_entry::{EntryKind, LogEntry};
use crate::message::Message;
use crate::meta::Meta;
use crate::pair::PeerTable;
use crate::role::Role;

/// A small, seeded generator.
#[derive(Debug, Clone)]
pub struct Random(u64);

impl Random {
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// True with probability `per_million` / 1,000,000.
    pub fn chance(&mut self, per_million: u64) -> bool {
        self.next_u64() % 1_000_000 < per_million
    }

    /// Uniform in `low..=high`.
    pub fn between(&mut self, low: u64, high: u64) -> u64 {
        low + self.next_u64() % (high - low + 1)
    }
}

/// What the network does to messages.
#[derive(Debug, Clone, Copy)]
pub struct Faults {
    pub drop_per_million: u64,
    pub duplicate_per_million: u64,
    /// Delivery takes this many milliseconds, uniformly.
    pub delay: (u64, u64),
}

impl Default for Faults {
    fn default() -> Self {
        Self {
            drop_per_million: 0,
            duplicate_per_million: 0,
            delay: (1, 1),
        }
    }
}

/// A simulated network between nodes, for any payload.
pub struct Network<N: Ord + Copy, P> {
    faults: Faults,
    in_flight: BinaryHeap<Reverse<(u64, u64, N, N)>>,
    payloads: BTreeMap<u64, P>,
    next: u64,
    cut: BTreeSet<(N, N)>,
}

impl<N: Ord + Copy, P: Clone> Network<N, P> {
    pub fn new(faults: Faults) -> Self {
        Self {
            faults,
            in_flight: BinaryHeap::new(),
            payloads: BTreeMap::new(),
            next: 0,
            cut: BTreeSet::new(),
        }
    }

    pub fn set_faults(&mut self, faults: Faults) {
        self.faults = faults;
    }

    /// Queue `payload` from `from` to `to` at time `now`.
    pub fn send(&mut self, random: &mut Random, now: u64, from: N, to: N, payload: P) {
        if self.cut.contains(&(from, to)) || random.chance(self.faults.drop_per_million) {
            return;
        }
        let copies = if random.chance(self.faults.duplicate_per_million) {
            2
        } else {
            1
        };
        for _ in 0..copies {
            let at = now + random.between(self.faults.delay.0, self.faults.delay.1);
            self.next += 1;
            self.payloads.insert(self.next, payload.clone());
            self.in_flight.push(Reverse((at, self.next, from, to)));
        }
    }

    /// The next delivery due at or before `now`.
    pub fn deliver(&mut self, now: u64) -> Option<(N, N, P)> {
        let Reverse((at, _, _, _)) = *self.in_flight.peek()?;
        if at > now {
            return None;
        }
        let Reverse((_, id, from, to)) = self.in_flight.pop().expect("peeked");
        let payload = self.payloads.remove(&id).expect("queued with its payload");
        // A partition made after sending still stops the message.
        if self.cut.contains(&(from, to)) {
            return self.deliver(now);
        }
        Some((from, to, payload))
    }

    /// When the next message is due.
    pub fn next_due(&self) -> Option<u64> {
        self.in_flight.peek().map(|Reverse((at, ..))| *at)
    }

    /// Stop messages from `from` to `to`.
    pub fn cut(&mut self, from: N, to: N) {
        self.cut.insert((from, to));
    }

    /// Separate `group` from everyone else, both ways.
    pub fn isolate(&mut self, group: &[N], all: &[N]) {
        for &inside in group {
            for &other in all {
                if !group.contains(&other) {
                    self.cut.insert((inside, other));
                    self.cut.insert((other, inside));
                }
            }
        }
    }

    pub fn heal(&mut self) {
        self.cut.clear();
    }
}

/// What travels between simulated nodes.
#[derive(Debug, Clone)]
pub enum Packet {
    Raft(Message<u16>),
    /// A node's pair heartbeat: the term it leads the group at, if it
    /// does.
    Pair {
        incarnation: u64,
        round: u64,
        leading: Option<u64>,
    },
    /// A whole snapshot, sent at the sender's `term`.
    Snapshot {
        term: u64,
        index: u64,
        index_term: u64,
        configuration: Option<SnapshotConfiguration<u16>>,
    },
}

/// A queued store operation.
#[derive(Debug, Clone)]
enum Op<N: NodeId> {
    Write(Write<N>),
    Compact {
        through: u64,
        configuration: Option<ActiveConfigRecord<N>>,
    },
}

/// One node's store: durable state, and operations not yet synced.
#[derive(Debug, Clone)]
pub struct Store<N: NodeId> {
    meta: Meta<N>,
    log: BTreeMap<u64, LogEntry<N>>,
    active_config: Option<ActiveConfigRecord<N>>,
    log_start_config: Option<ActiveConfigRecord<N>>,
    applied: u64,
    unsynced: VecDeque<Op<N>>,
    /// The last log position held before a retirement wiped the rest.
    vote_floor: Option<(u64, u64)>,
}

impl<N: NodeId> Default for Store<N> {
    fn default() -> Self {
        Self {
            meta: Meta::default(),
            log: BTreeMap::new(),
            active_config: None,
            log_start_config: None,
            applied: 0,
            unsynced: VecDeque::new(),
            vote_floor: None,
        }
    }
}

/// What one sync made durable.
#[derive(Debug, Default)]
struct Synced {
    seq: Option<u64>,
    compacted: Option<u64>,
}

impl<N: NodeId> Store<N> {
    fn apply(&mut self, op: &Op<N>, synced: &mut Synced) {
        match op {
            Op::Write(write) => {
                if let Some(after) = write.truncate_after {
                    self.log.retain(|&index, _| index <= after);
                }
                for entry in &write.entries {
                    self.log.insert(entry.index, entry.clone());
                }
                if let Some(meta) = &write.meta {
                    // Only compaction and a switch move the snapshot pointer.
                    self.meta = Meta {
                        snap_last_index: self.meta.snap_last_index,
                        snap_last_term: self.meta.snap_last_term,
                        ..meta.clone()
                    };
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
    fn sync(&mut self) -> Synced {
        let mut synced = Synced::default();
        while let Some(op) = self.unsynced.pop_front() {
            self.apply(&op, &mut synced);
        }
        synced
    }

    /// Lose the unsynced operations after a prefix of `keep` of them.
    fn crash(&mut self, keep: usize) {
        let mut synced = Synced::default();
        for _ in 0..keep.min(self.unsynced.len()) {
            let op = self.unsynced.pop_front().expect("counted");
            self.apply(&op, &mut synced);
        }
        self.unsynced.clear();
    }

    /// Switch to a snapshot at (`index`, `term`), durably.
    fn switch(&mut self, index: u64, switch: SnapshotSwitch<N>) {
        if let Some(after) = switch.truncate_after {
            self.log.retain(|&at, _| at <= after);
        }
        self.log.retain(|&at, _| at > index);
        self.meta = switch.meta;
        self.active_config = Some(switch.active_config);
        self.log_start_config = switch.log_start_config;
        self.applied = self.applied.max(index);
    }

    fn recovered(&self) -> Recovered<N> {
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
    fn retire(&mut self, keep_floor: bool) {
        self.sync();
        let last = self.log.last_key_value().map_or(
            (self.meta.snap_last_index, self.meta.snap_last_term),
            |(index, entry)| (*index, entry.term),
        );
        self.vote_floor = keep_floor.then(|| {
            let (index, term) = last;
            self.vote_floor.map_or(last, |floor| {
                if (floor.1, floor.0) > (term, index) {
                    floor
                } else {
                    last
                }
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
    fn written(&self, index: u64) -> Option<LogEntry<N>> {
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

/// A violated safety property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// Two leaders in one term.
    TwoLeaders { term: u64 },
    /// Two different entries committed at one index.
    CommitConflict { index: u64 },
    /// A replica committed past the end of its own log.
    CommitBeyondLog { index: u64 },
    /// A read index below what was committed when the read was asked.
    StaleRead { index: u64, committed: u64 },
    /// A replica compacted past its commit index.
    SnapshotPastCommit { snapshot: u64, commit: u64 },
}

/// Replicas of one group over a simulated network and stores.
pub struct Cluster {
    pub random: Random,
    pub now: u64,
    pub network: Network<u16, Packet>,
    nodes: Vec<u16>,
    cores: BTreeMap<u16, Option<Core<u16>>>,
    stores: BTreeMap<u16, Store<u16>>,
    cfg: Config<u16>,
    /// Sync delay in milliseconds.
    pub sync_delay: (u64, u64),
    sync_due: BTreeMap<u16, u64>,
    /// How long after a sync its entries are reported durable, in
    /// milliseconds, as when a node waits for the blobs they name: terms,
    /// votes and truncations are reported at once.
    pub entry_lag: (u64, u64),
    /// Entry reports waiting out their lag: (due, write) per node.
    entry_reports: BTreeMap<u16, Vec<(u64, u64)>>,
    /// Each node's applied index, durable at its next sync.
    applied: BTreeMap<u16, u64>,
    leaders: BTreeMap<u64, u16>,
    /// The committed entry at each index, as the first replica that
    /// committed it held it.
    committed: BTreeMap<u64, (u64, Option<Vec<u8>>)>,
    /// Each replica's highest index whose committed entry was compared: a
    /// commit that jumps compares every entry it passes, not just its tip.
    checked: BTreeMap<u16, u64>,
    pub violations: Vec<Violation>,
    /// Proposal answers: token to index.
    pub proposed: BTreeMap<u64, u64>,
    /// Read-index answers: token to index.
    pub reads: BTreeMap<u64, Result<u64, crate::core::ReadIndexError>>,
    /// For each read asked, the highest index committed anywhere then.
    read_floors: BTreeMap<u64, u64>,
    /// Snapshots installed, across all nodes.
    pub installs: u64,
    /// Compactions made durable, across all nodes.
    pub compactions: u64,
    /// Loads answered, across all nodes.
    pub loads: u64,
    /// Membership changes started, across all nodes.
    pub changes_started: u64,
    /// Raft messages sent, by sender and receiver.
    pub raft_sent: BTreeMap<(u16, u16), u64>,
    /// Retirements, across all nodes.
    pub retirements: u64,
    /// Nodes retired, running no group until a configuration names them
    /// again.
    retired: BTreeSet<u16>,
    /// The hosts' pair heartbeats, when on.
    pair: Option<Pair>,
    next_token: u64,
}

/// Each node's host sending pair heartbeats and vouching with what it
/// hears, as a node does.
struct Pair {
    interval: u64,
    next: u64,
    tables: BTreeMap<u16, PeerTable<u16, (), u64>>,
    incarnations: BTreeMap<u16, u64>,
    rounds: BTreeMap<u16, u64>,
    /// Nodes whose host sends no pair heartbeat until then, their cores
    /// running on.
    silent_until: BTreeMap<u16, u64>,
}

impl Cluster {
    pub fn new(nodes: &[u16], seed: u64, faults: Faults) -> Self {
        Self::with_config(nodes, seed, faults, |_| {})
    }

    /// As [`Self::new`], with the replicas' configuration adjusted by
    /// `adjust`.
    pub fn with_config(
        nodes: &[u16],
        seed: u64,
        faults: Faults,
        adjust: impl FnOnce(&mut Config<u16>),
    ) -> Self {
        let mut cfg = Config::new(nodes[0], nodes.to_vec());
        cfg.election_timeout_ms = (150, 300);
        cfg.heartbeat_interval_ms = 50;
        cfg.resend_timeout_ms = 100;
        cfg.snapshot_timeout_ms = 1_000;
        adjust(&mut cfg);
        let mut cluster = Self {
            random: Random::new(seed),
            now: 0,
            network: Network::new(faults),
            nodes: nodes.to_vec(),
            cores: BTreeMap::new(),
            stores: BTreeMap::new(),
            cfg,
            sync_delay: (1, 3),
            sync_due: BTreeMap::new(),
            entry_lag: (0, 0),
            entry_reports: BTreeMap::new(),
            applied: BTreeMap::new(),
            leaders: BTreeMap::new(),
            committed: BTreeMap::new(),
            checked: BTreeMap::new(),
            violations: Vec::new(),
            proposed: BTreeMap::new(),
            reads: BTreeMap::new(),
            read_floors: BTreeMap::new(),
            installs: 0,
            compactions: 0,
            loads: 0,
            changes_started: 0,
            raft_sent: BTreeMap::new(),
            retirements: 0,
            retired: BTreeSet::new(),
            pair: None,
            next_token: 0,
        };
        for &node in nodes {
            cluster.stores.insert(node, Store::default());
            cluster.start(node);
        }
        cluster
    }

    /// Turn the hosts' pair heartbeats on, every `interval` milliseconds:
    /// each host vouches with them for the group's leader and members
    /// before a deadline and a pre-vote, as with idle heartbeats off.
    pub fn pair_heartbeats(&mut self, interval: u64) {
        self.pair = Some(Pair {
            interval,
            next: self.now,
            tables: BTreeMap::new(),
            incarnations: self.nodes.iter().map(|&node| (node, 1)).collect(),
            rounds: BTreeMap::new(),
            silent_until: BTreeMap::new(),
        });
    }

    /// Every host sends its pair heartbeat again.
    pub fn end_pair_blackouts(&mut self) {
        if let Some(pair) = self.pair.as_mut() {
            pair.silent_until.clear();
        }
    }

    /// `node`'s host sends no pair heartbeat for `millis`, as when its
    /// thread is starved, while its core runs on.
    pub fn pair_blackout(&mut self, node: u16, millis: u64) {
        let until = self.now + millis;
        if let Some(pair) = self.pair.as_mut() {
            pair.silent_until.insert(node, until);
        }
    }

    /// Vouch for `node`'s leader and members from its host's table, empty
    /// if it heard nothing yet.
    fn vouch(&mut self, node: u16) {
        let now = self.now;
        let (Some(pair), Some(Some(core))) = (self.pair.as_ref(), self.cores.get_mut(&node)) else {
            return;
        };
        let table = pair.tables.get(&node);
        core.vouch(
            now,
            |leader, term| table.and_then(|table| table.listed(leader, &(), term)),
            |member| table.and_then(|table| table.heard_at(member)),
        );
    }

    /// Every live node sends its pair heartbeat.
    fn send_pair_heartbeats(&mut self) {
        let now = self.now;
        let Some(pair) = self.pair.as_mut() else {
            return;
        };
        pair.next = now + pair.interval;
        for &from in &self.nodes {
            let Some(Some(core)) = self.cores.get(&from) else {
                continue;
            };
            if pair
                .silent_until
                .get(&from)
                .is_some_and(|&until| until > now)
            {
                continue;
            }
            let leading = (core.role() == Role::Leader).then(|| core.status().current_term);
            let round = pair.rounds.entry(from).or_insert(0);
            *round += 1;
            for &to in self.nodes.iter().filter(|&&to| to != from) {
                let packet = Packet::Pair {
                    incarnation: pair.incarnations[&from],
                    round: *round,
                    leading,
                };
                self.network.send(&mut self.random, now, from, to, packet);
            }
        }
    }

    /// Start `node` again: a new run of its host, and its group.
    fn start(&mut self, node: u16) {
        if let Some(pair) = self.pair.as_mut() {
            *pair.incarnations.entry(node).or_insert(0) += 1;
            pair.rounds.remove(&node);
        }
        self.start_group(node);
    }

    /// Start `node`'s group from its store.
    fn start_group(&mut self, node: u16) {
        let mut cfg = self.cfg.clone();
        cfg.me = node;
        let seed = self.random.next_u64();
        let recovered = self.stores[&node].recovered();
        self.applied.insert(node, recovered.applied);
        let core = Core::new(cfg, recovered, self.now, seed);
        self.cores.insert(node, Some(core));
        self.process(node);
    }

    pub fn nodes(&self) -> &[u16] {
        &self.nodes
    }

    pub fn core(&self, node: u16) -> Option<&Core<u16>> {
        self.cores.get(&node)?.as_ref()
    }

    /// Crash `node`: it loses its unsynced writes after a random prefix and
    /// stays down until [`Self::restart`].
    pub fn crash(&mut self, node: u16) {
        let keep = self.random.next_u64() as usize % 4;
        self.stores.get_mut(&node).expect("a node").crash(keep);
        self.cores.insert(node, None);
        // What it committed but had not synced is gone: once it commits
        // there again, those entries are compared again.
        self.checked.remove(&node);
        self.sync_due.remove(&node);
        self.entry_reports.remove(&node);
        // A host starts again with nothing heard.
        if let Some(pair) = self.pair.as_mut() {
            pair.tables.remove(&node);
        }
    }

    pub fn restart(&mut self, node: u16) {
        if !self.retired.contains(&node) && self.cores.get(&node).is_some_and(Option::is_none) {
            self.start(node);
        }
    }

    /// The node that leads at the highest term, if any.
    pub fn leader(&self) -> Option<u16> {
        self.cores
            .iter()
            .filter_map(|(&node, core)| {
                let core = core.as_ref()?;
                (core.role() == Role::Leader).then(|| (core.status().current_term, node))
            })
            .max()
            .map(|(_, node)| node)
    }

    /// Propose `payload` at `node`: its token.
    pub fn propose(&mut self, node: u16, payload: Vec<u8>) -> u64 {
        self.next_token += 1;
        let token = self.next_token;
        if let Some(Some(core)) = self.cores.get_mut(&node) {
            core.propose(token, payload);
            self.process(node);
        }
        token
    }

    /// Ask `node` for a read index: its token.
    pub fn read_index(&mut self, node: u16) -> u64 {
        self.next_token += 1;
        let token = self.next_token;
        let floor = self.committed_index();
        self.read_floors.insert(token, floor);
        if let Some(Some(core)) = self.cores.get_mut(&node) {
            core.read_index(token, Some(2_000));
            self.process(node);
        }
        token
    }

    /// `node`'s host gives up on its unreported entries.
    pub fn discard_unreported(&mut self, node: u16) {
        if let Some(Some(core)) = self.cores.get_mut(&node) {
            core.discard_unreported();
            self.process(node);
        }
    }

    /// Ask `node` to change the group's membership to `members`: its token.
    pub fn change_membership(&mut self, node: u16, members: Vec<u16>) -> u64 {
        self.next_token += 1;
        let token = self.next_token;
        if let Some(Some(core)) = self.cores.get_mut(&node) {
            core.change_membership(token, members);
            self.process(node);
        }
        token
    }

    /// `node`'s host releases the voters a committed change removed.
    pub fn release_retiring_voters(&mut self, node: u16) {
        if let Some(Some(core)) = self.cores.get_mut(&node) {
            core.release_retiring_voters();
            self.process(node);
        }
    }

    /// `node`'s host retires it, as its directory said a committed final
    /// configuration dropped it: its group stops, and its log and state
    /// go, its term, vote and vote floor kept. `keep_floor` false retires
    /// as a host that kept no floor would.
    pub fn retire(&mut self, node: u16, keep_floor: bool) {
        if self.cores.get(&node).is_none_or(Option::is_none) {
            return;
        }
        self.stores
            .get_mut(&node)
            .expect("a node")
            .retire(keep_floor);
        self.applied.insert(node, 0);
        self.checked.remove(&node);
        self.sync_due.remove(&node);
        self.entry_reports.remove(&node);
        self.cores.insert(node, None);
        self.retired.insert(node);
        self.retirements += 1;
    }

    /// A configuration names retired `node` again: its host starts its
    /// group, empty, from the members the group was created with.
    pub fn readmit(&mut self, node: u16) {
        if self.retired.remove(&node) {
            self.start_group(node);
        }
    }

    pub fn is_retired(&self, node: u16) -> bool {
        self.retired.contains(&node)
    }

    /// Whether `node`'s store holds anything of the group's log or state.
    pub fn holds_replica(&self, node: u16) -> bool {
        let store = &self.stores[&node];
        !store.log.is_empty() || store.applied > 0 || store.meta.snap_last_index > 0
    }

    /// Run for `millis` of simulated time.
    pub fn run(&mut self, millis: u64) {
        let until = self.now + millis;
        while self.now < until {
            self.step(until);
        }
    }

    fn step(&mut self, until: u64) {
        let next = [
            self.network.next_due(),
            self.pair.as_ref().map(|pair| pair.next),
            self.sync_due.values().min().copied(),
            self.entry_reports
                .values()
                .flat_map(|reports| reports.iter().map(|&(due, ..)| due))
                .min(),
            self.cores
                .values()
                .filter_map(|core| core.as_ref().map(Core::next_deadline))
                .min(),
        ]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(until)
        .clamp(self.now, until);
        self.now = next.max(self.now);
        let now = self.now;
        if self.pair.as_ref().is_some_and(|pair| pair.next <= now) {
            self.send_pair_heartbeats();
        }
        while let Some((from, to, packet)) = self.network.deliver(now) {
            match packet {
                Packet::Raft(message) => {
                    let due = self.cores.get(&to).is_some_and(|core| {
                        core.as_ref()
                            .is_some_and(|core| core.next_deadline() <= now)
                    });
                    if due || matches!(message, Message::PreVote { .. }) {
                        self.vouch(to);
                    }
                    if let Some(Some(core)) = self.cores.get_mut(&to) {
                        core.tick(now);
                        core.receive(from, message);
                        self.process(to);
                    }
                }
                Packet::Pair {
                    incarnation,
                    round,
                    leading,
                } => {
                    if self.cores.get(&to).is_some_and(Option::is_some)
                        && let Some(pair) = self.pair.as_mut()
                    {
                        let heard = pair.tables.entry(to).or_default().heard(
                            from,
                            now,
                            incarnation,
                            round,
                            leading.map(|term| ((), term)),
                        );
                        // A peer's new run, or one heard again after a
                        // silence, is probed, as a node does.
                        let gap = self.cfg.election_timeout_ms.1;
                        if heard.is_some_and(|heard| {
                            heard.new_run || heard.before.is_some_and(|before| before + gap <= now)
                        }) && let Some(Some(core)) = self.cores.get_mut(&to)
                        {
                            core.probe(from);
                            self.process(to);
                        }
                    }
                }
                Packet::Snapshot {
                    term,
                    index,
                    index_term,
                    configuration,
                } => self.install(from, to, term, index, index_term, configuration),
            }
        }
        let due: Vec<u16> = self
            .sync_due
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(&node, _)| node)
            .collect();
        for node in due {
            self.sync_due.remove(&node);
            self.sync(node);
        }
        for node in self.nodes.clone() {
            let Some(reports) = self.entry_reports.get_mut(&node) else {
                continue;
            };
            let (ready, waiting): (Vec<_>, Vec<_>) =
                reports.drain(..).partition(|&(due, ..)| due <= now);
            *reports = waiting;
            if let Some(Some(core)) = self.cores.get_mut(&node) {
                for (_, seq) in ready {
                    core.entries_durable(seq);
                }
                self.process(node);
            }
        }
        for node in self.nodes.clone() {
            if self.cores.get(&node).is_some_and(|core| {
                core.as_ref()
                    .is_some_and(|core| core.next_deadline() <= now)
            }) {
                self.vouch(node);
            }
            if let Some(Some(core)) = self.cores.get_mut(&node)
                && core.next_deadline() <= now
            {
                core.tick(now);
                self.process(node);
            }
        }
        if self.now == until {
            self.now += 1;
        }
    }

    /// Make `node`'s queued operations durable and tell its core.
    fn sync(&mut self, node: u16) {
        let applied = self.applied.get(&node).copied().unwrap_or(0);
        let store = self.stores.get_mut(&node).expect("a node");
        let synced = store.sync();
        store.applied = store.applied.max(applied);
        let Some(Some(core)) = self.cores.get_mut(&node) else {
            return;
        };
        if let Some(seq) = synced.seq {
            core.durable(seq);
        }
        if let Some(seq) = synced.seq {
            if self.entry_lag.1 == 0 {
                core.entries_durable(seq);
            } else {
                let due = self.now + self.random.between(self.entry_lag.0, self.entry_lag.1);
                self.entry_reports.entry(node).or_default().push((due, seq));
            }
        }
        core.durably_applied(applied);
        if let Some(through) = synced.compacted {
            self.compactions += 1;
            core.compacted(through);
            let status = core.status();
            if status.snap_last_index > status.commit_index {
                self.violations.push(Violation::SnapshotPastCommit {
                    snapshot: status.snap_last_index,
                    commit: status.commit_index,
                });
            }
        }
        self.process(node);
    }

    /// `to` receives a snapshot from `from`, and switches to it if `from`
    /// leads its current term: after every write before it, durably.
    fn install(
        &mut self,
        from: u16,
        to: u16,
        term: u64,
        index: u64,
        index_term: u64,
        configuration: Option<SnapshotConfiguration<u16>>,
    ) {
        for _ in 0..8 {
            if self.stores[&to].unsynced.is_empty() {
                break;
            }
            self.sync_due.remove(&to);
            self.sync(to);
        }
        let Some(Some(core)) = self.cores.get_mut(&to) else {
            return;
        };
        let status = core.status();
        if core.role() != Role::Follower
            || status.leader_hint != Some(from)
            || status.current_term != term
            || index <= status.snap_last_index
            || !self.stores[&to].unsynced.is_empty()
        {
            return;
        }
        let switch = core.snapshot_switch(index, index_term, configuration.as_ref());
        self.stores
            .get_mut(&to)
            .expect("a node")
            .switch(index, switch);
        let applied = self.applied.entry(to).or_insert(0);
        *applied = (*applied).max(index);
        self.installs += 1;
        core.snapshot_installed(index, index_term, configuration);
        self.process(to);
    }

    /// Carry out `node`'s actions.
    fn process(&mut self, node: u16) {
        loop {
            let actions = match self.cores.get_mut(&node) {
                Some(Some(core)) => core.take_actions(),
                _ => return,
            };
            if actions.is_empty() {
                break;
            }
            for action in actions {
                match action {
                    Action::Write(write) => self.queue(node, Op::Write(write)),
                    Action::Send { to, message } => {
                        let now = self.now;
                        *self.raft_sent.entry((node, to)).or_insert(0) += 1;
                        self.network
                            .send(&mut self.random, now, node, to, Packet::Raft(message));
                    }
                    Action::LoadEntries(load) => {
                        let entries: Vec<LogEntry<u16>> = self.stores[&node]
                            .log
                            .range(load.from..=load.to)
                            .map(|(_, entry)| entry.clone())
                            .collect();
                        self.loads += 1;
                        if let Some(Some(core)) = self.cores.get_mut(&node) {
                            core.loaded(load, entries);
                        }
                    }
                    Action::Committed { index } => {
                        let applied = self.applied.entry(node).or_insert(0);
                        *applied = (*applied).max(index);
                        self.check_commit(node, index);
                    }
                    Action::SendSnapshot {
                        to,
                        index,
                        term,
                        configuration,
                    } => {
                        let sender_term = match self.cores.get(&node) {
                            Some(Some(core)) => core.status().current_term,
                            _ => continue,
                        };
                        let now = self.now;
                        self.network.send(
                            &mut self.random,
                            now,
                            node,
                            to,
                            Packet::Snapshot {
                                term: sender_term,
                                index,
                                index_term: term,
                                configuration,
                            },
                        );
                    }
                    Action::CompactBound {
                        through,
                        configuration,
                    } => self.queue(
                        node,
                        Op::Compact {
                            through,
                            configuration,
                        },
                    ),
                    Action::Answer(Answer::Propose {
                        token,
                        result: Ok(index),
                    }) => {
                        self.proposed.insert(token, index);
                    }
                    Action::Answer(Answer::ReadIndex { token, result }) => {
                        if let Ok(index) = result {
                            let committed = self.read_floors.get(&token).copied().unwrap_or(0);
                            if index < committed {
                                self.violations
                                    .push(Violation::StaleRead { index, committed });
                            }
                        }
                        self.reads.insert(token, result);
                    }
                    Action::Answer(Answer::ChangeMembership { result: Ok(_), .. }) => {
                        self.changes_started += 1;
                    }
                    Action::Answer(_) => {}
                    Action::Changed { term, role, .. } => {
                        if role == Role::Leader {
                            match self.leaders.get(&term) {
                                Some(&other) if other != node => {
                                    self.violations.push(Violation::TwoLeaders { term });
                                }
                                _ => {
                                    self.leaders.insert(term, node);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn queue(&mut self, node: u16, op: Op<u16>) {
        self.stores
            .get_mut(&node)
            .expect("a node")
            .unsynced
            .push_back(op);
        if !self.sync_due.contains_key(&node) {
            let at = self.now + self.random.between(self.sync_delay.0, self.sync_delay.1);
            self.sync_due.insert(node, at);
        }
    }

    /// Record what `node` committed through `index`, and compare it with
    /// what every other replica committed there.
    fn check_commit(&mut self, node: u16, index: u64) {
        let Some(Some(core)) = self.cores.get(&node) else {
            return;
        };
        if index > core.status().last_log_index {
            self.violations.push(Violation::CommitBeyondLog { index });
            return;
        }
        let store = &self.stores[&node];
        let start = self.checked.get(&node).map_or(1, |&at| at + 1);
        if index >= start {
            self.checked.insert(node, index);
        }
        for at in start..=index {
            let Some(entry) = store.written(at) else {
                continue;
            };
            let payload = match entry.kind {
                EntryKind::Data { payload } => Some(payload),
                _ => None,
            };
            match self.committed.get(&at) {
                Some((term, held)) if (*term, held) != (entry.term, &payload) => {
                    self.violations
                        .push(Violation::CommitConflict { index: at });
                }
                Some(_) => {}
                None => {
                    self.committed.insert(at, (entry.term, payload));
                }
            }
        }
    }

    /// The payloads committed so far, in index order.
    pub fn committed_payloads(&self) -> Vec<Vec<u8>> {
        self.committed
            .values()
            .filter_map(|(_, payload)| payload.clone())
            .filter(|payload| !payload.is_empty())
            .collect()
    }

    /// Highest index committed by any replica.
    pub fn committed_index(&self) -> u64 {
        self.committed.keys().next_back().copied().unwrap_or(0)
    }
}
