//! Several replicas, each with the store its host keeps, crashing between
//! a write and its sync: a term is led once, by one log, and no replica
//! applies an entry another applied differently.

use std::collections::BTreeMap;

use vos_raft::core::{Action, Core, Recovered};
use vos_raft::{Config, EntryKind, LogEntry, Message, Meta, Role};

/// A replica and what its host made durable, restartable from it.
struct Stored {
    me: u16,
    members: Vec<u16>,
    pre_vote: bool,
    core: Core<u16>,
    log: BTreeMap<u64, LogEntry<u16>>,
    hard: (u64, Option<u16>),
    commit: u64,
    applied: Vec<(u64, Vec<u8>)>,
}

impl Stored {
    fn new(me: u16, members: &[u16], pre_vote: bool) -> Self {
        let mut stored = Self {
            me,
            members: members.to_vec(),
            pre_vote,
            core: Core::new(
                Config::new(me, members.to_vec()),
                Recovered::default(),
                0,
                0,
            ),
            log: BTreeMap::new(),
            hard: (0, None),
            commit: 0,
            applied: Vec::new(),
        };
        stored.restart();
        stored
    }

    /// A crash and a restart: what was synced is recovered, nothing else.
    fn restart(&mut self) {
        let mut cfg = Config::new(self.me, self.members.clone());
        cfg.pre_vote = self.pre_vote;
        let recovered = Recovered {
            meta: Meta {
                current_term: self.hard.0,
                voted_for: self.hard.1,
                ..Meta::default()
            },
            entries: self.log.values().cloned().collect(),
            ..Recovered::default()
        };
        self.core = Core::new(cfg, recovered, 0, u64::from(self.me));
        self.commit = 0;
        self.applied.clear();
        self.core.take_actions();
    }

    /// Carry out the core's actions, every write synced and reported when
    /// `sync`, else left unsynced (a crash loses it). The messages to
    /// send, by receiver.
    fn run(&mut self, sync: bool) -> Vec<(u16, Message<u16>)> {
        let mut out = Vec::new();
        loop {
            let actions = self.core.take_actions();
            if actions.is_empty() {
                break;
            }
            for action in actions {
                match action {
                    Action::Send { to, message } => out.push((to, message)),
                    Action::Write(write) if sync => {
                        if let Some(after) = write.truncate_after {
                            self.log.retain(|&index, _| index <= after);
                        }
                        for entry in &write.entries {
                            self.log.insert(entry.index, entry.clone());
                        }
                        if let Some(meta) = &write.meta {
                            self.hard = (meta.current_term, meta.voted_for);
                        }
                        self.core.durable(write.seq);
                        self.core.entries_durable(write.seq);
                    }
                    Action::Committed { index } => self.commit = self.commit.max(index),
                    _ => {}
                }
            }
        }
        let from = self.applied.last().map_or(0, |&(index, _)| index) + 1;
        for index in from..=self.commit {
            let Some(entry) = self.log.get(&index) else {
                break;
            };
            if let EntryKind::Data { payload } = &entry.kind {
                self.applied.push((index, payload.clone()));
            }
        }
        out
    }

    fn leads(&self, term: u64) -> bool {
        self.core.role() == Role::Leader && self.core.status().current_term == term
    }
}

fn to(messages: &[(u16, Message<u16>)], node: u16) -> Vec<Message<u16>> {
    messages
        .iter()
        .filter(|(to, _)| *to == node)
        .map(|(_, message)| message.clone())
        .collect()
}

fn group(members: &[u16], pre_vote: bool) -> BTreeMap<u16, Stored> {
    members
        .iter()
        .map(|&node| (node, Stored::new(node, members, pre_vote)))
        .collect()
}

/// Deliver everything the nodes but `skip` send each other, every write
/// synced, until none sends. What was sent, in order.
fn pump(nodes: &mut BTreeMap<u16, Stored>, skip: &[u16]) -> Vec<(u16, u16, Message<u16>)> {
    let mut carried = Vec::new();
    loop {
        let mut round = Vec::new();
        for (&from, node) in nodes.iter_mut() {
            if !skip.contains(&from) {
                round.extend(node.run(true).into_iter().map(|(to, m)| (from, to, m)));
            }
        }
        if round.is_empty() {
            return carried;
        }
        for (from, to, message) in round {
            carried.push((from, to, message.clone()));
            if !skip.contains(&to)
                && let Some(node) = nodes.get_mut(&to)
            {
                node.core.receive(from, message);
            }
        }
    }
}

/// Send `from`'s messages in `sent` to `peer`, and its answers back.
fn exchange(nodes: &mut BTreeMap<u16, Stored>, from: u16, sent: &[(u16, Message<u16>)], peer: u16) {
    for message in to(sent, peer) {
        node(nodes, peer).core.receive(from, message);
    }
    for message in to(&node(nodes, peer).run(true), from) {
        node(nodes, from).core.receive(peer, message);
    }
}

/// Whether two replicas applied the same entry at every index both
/// applied.
/// The replica `id` of `nodes`.
fn node(nodes: &mut BTreeMap<u16, Stored>, id: u16) -> &mut Stored {
    nodes.get_mut(&id).expect("a node")
}

fn agree(a: &[(u64, Vec<u8>)], b: &[(u64, Vec<u8>)]) -> bool {
    let b: BTreeMap<_, _> = b.iter().cloned().collect();
    a.iter()
        .all(|(index, payload)| b.get(index).is_none_or(|held| held == payload))
}

/// Pre-votes off: a candidate whose peers grant it before its term is
/// synced, crashing then, comes back below the term and would campaign
/// at it again.
#[test]
fn a_term_is_led_once_across_a_crash() {
    let (me, a, b) = (1u16, 2u16, 3u16);
    let mut nodes = group(&[me, a, b], false);
    node(&mut nodes, me).core.tick(1_000);
    let votes = node(&mut nodes, me).run(false);
    exchange(&mut nodes, me, &votes, a);
    exchange(&mut nodes, me, &votes, b);
    assert!(
        !nodes[&me].leads(1),
        "it leads before its own term is durable"
    );
    // What it sends now, its no-op and x, reaches A alone, unsynced at ME.
    let mut led = false;
    for propose in [false, true] {
        if propose {
            node(&mut nodes, me).core.propose(1, b"x".to_vec());
        }
        led |= nodes[&me].leads(1);
        let sent = node(&mut nodes, me).run(false);
        exchange(&mut nodes, me, &sent, a);
    }
    // ME crashes: none of its writes was synced. It campaigns again.
    node(&mut nodes, me).restart();
    node(&mut nodes, me).core.tick(1_000);
    let votes = node(&mut nodes, me).run(true);
    exchange(&mut nodes, me, &votes, a);
    exchange(&mut nodes, me, &votes, b);
    let term = nodes[&me].core.status().current_term;
    assert!(!(led && term == 1), "one node led term 1 twice");
    node(&mut nodes, me).core.propose(2, b"y".to_vec());
    pump(&mut nodes, &[]);
    for round in 1..=4u64 {
        for node in nodes.values_mut() {
            node.core.tick(1_000 + 2_000 * round);
        }
        pump(&mut nodes, &[]);
    }
    for node in [a, b] {
        assert!(
            agree(&nodes[&me].applied, &nodes[&node].applied),
            "{me} applied {:?}, {node} applied {:?}",
            nodes[&me].applied,
            nodes[&node].applied
        );
    }
}

/// Pre-votes on: a transfer's target campaigns without a pre-vote. Granted
/// before its term is synced, crashing then, it is handed the same term
/// again by the old leader's frames delivered late.
#[test]
fn a_transfers_target_leads_its_term_once_across_a_crash() {
    let (me, a, b, c, d) = (1u16, 2u16, 3u16, 4u16, 5u16);
    let mut nodes = group(&[me, a, b, c, d], true);
    node(&mut nodes, a).core.tick(1_000);
    let setup = pump(&mut nodes, &[]);
    assert!(nodes[&a].leads(1));
    node(&mut nodes, a).core.transfer_leadership(Some(me));
    let handover = node(&mut nodes, a).run(true);
    let late_append = setup
        .iter()
        .rev()
        .find(|(from, to, message)| {
            (*from, *to) == (a, me) && matches!(message, Message::Append { .. })
        })
        .map(|(_, _, message)| message.clone())
        .expect("A sent ME an append");
    let timeout_now = to(&handover, me)
        .into_iter()
        .find(|message| matches!(message, Message::TimeoutNow { .. }))
        .expect("A sent ME a TimeoutNow");
    // ME campaigns at term 2: its term and vote are written, not synced.
    node(&mut nodes, me).core.receive(a, timeout_now.clone());
    let votes = node(&mut nodes, me).run(false);
    for peer in [b, c, d] {
        exchange(&mut nodes, me, &votes, peer);
    }
    assert!(
        !nodes[&me].leads(2),
        "it leads before its own term is durable"
    );
    // Its no-op and x reach B alone.
    let mut led = false;
    for propose in [false, true] {
        if propose {
            node(&mut nodes, me).core.propose(1, b"x".to_vec());
        }
        for _ in 0..3 {
            led |= nodes[&me].leads(2);
            let sent = node(&mut nodes, me).run(false);
            exchange(&mut nodes, me, &sent, b);
        }
    }
    // ME crashes; the link delivers A's old frames again.
    node(&mut nodes, me).restart();
    node(&mut nodes, me).core.receive(a, late_append);
    node(&mut nodes, me).core.receive(a, timeout_now);
    let votes = node(&mut nodes, me).run(true);
    for peer in [b, c, d] {
        exchange(&mut nodes, me, &votes, peer);
    }
    assert!(!(led && nodes[&me].leads(2)), "one node led term 2 twice");
    node(&mut nodes, me).core.propose(2, b"y".to_vec());
    pump(&mut nodes, &[a]);
    for round in 1..=4u64 {
        node(&mut nodes, me).core.tick(2_000 * round);
        pump(&mut nodes, &[a]);
    }
    for node in [b, c, d] {
        assert!(
            agree(&nodes[&me].applied, &nodes[&node].applied),
            "{me} applied {:?}, {node} applied {:?}",
            nodes[&me].applied,
            nodes[&node].applied
        );
    }
}

/// Pre-votes off: a candidate asks for votes with a log tail it has not
/// synced, crashes, and campaigns at the same term with a shorter log. A
/// grant made to the longer log must not elect the shorter one.
#[test]
fn a_grant_counts_only_for_the_log_it_was_made_to() {
    let (me, l) = (1u16, 2u16);
    let mut nodes = group(&[1, 2, 3, 4, 5], false);
    node(&mut nodes, l).core.tick(1_000);
    pump(&mut nodes, &[]);
    assert!(nodes[&l].leads(1));
    // L proposes e: 3 and 4 hold it durably, ME unsynced, 5 never. L
    // commits it with 3 and 4.
    node(&mut nodes, l).core.propose(1, b"e".to_vec());
    let appends = node(&mut nodes, l).run(true);
    for message in to(&appends, me) {
        node(&mut nodes, me).core.receive(l, message);
    }
    node(&mut nodes, me).run(false);
    for peer in [3u16, 4] {
        exchange(&mut nodes, l, &appends, peer);
    }
    node(&mut nodes, l).run(true);
    assert_eq!(nodes[&l].applied.last(), Some(&(2, b"e".to_vec())));
    // ME's timer fires: unsynced, it asks no one for a vote.
    node(&mut nodes, me).core.tick(1_000);
    let votes = node(&mut nodes, me).run(false);
    assert!(
        to(&votes, 3).is_empty(),
        "it asks for votes before its term and log are durable: {votes:?}"
    );
    // ME crashes, and campaigns again without e: what it asks now, every
    // peer answers, and those that hold e refuse it.
    node(&mut nodes, me).restart();
    assert_eq!(nodes[&me].core.status().last_log_index, 1);
    node(&mut nodes, me).core.tick(1_000);
    let votes = node(&mut nodes, me).run(true);
    for peer in [3u16, 4, 5] {
        exchange(&mut nodes, me, &votes, peer);
    }
    assert_ne!(
        nodes[&me].core.role(),
        Role::Leader,
        "it leads without the committed entry"
    );
}
