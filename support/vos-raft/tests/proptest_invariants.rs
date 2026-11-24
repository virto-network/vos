//! One replica under random messages, from peers no real group would
//! produce, keeps Raft's invariants: its term never goes back, it makes at
//! most one vote per term durable, an entry it holds changes only for a
//! leader of a later term, and its snapshot and commit indexes never go
//! back. Every write is durable as soon as it is made.

use std::collections::BTreeMap;

use proptest::prelude::*;
use vos_raft::core::{Action, Core, Recovered};
use vos_raft::{Config, LogEntry, Message, Role};

const ME: u16 = 0xAAAA;
const PEERS: [u16; 2] = [0xBBBB, 0xCCCC];

#[derive(Debug, Clone)]
enum Op {
    Receive(u16, Message<u16>),
    /// A snapshot at (index, term) from a peer at a term, switched to only
    /// while that peer leads this replica's term.
    Install(u16, u64, (u64, u64)),
}

/// An append from `leader` at `term`, of `count` entries after `prev`.
fn append(leader: u16, term: u64, prev: (u64, u64), commit: u64, count: u8) -> Op {
    let (prev_index, prev_term) = prev;
    let entries = (0..count)
        .map(|n| LogEntry::data(prev_index + 1 + u64::from(n), term, vec![n]))
        .collect();
    let message = Message::Append {
        term,
        leader,
        prev_index,
        prev_term,
        commit,
        round: 1,
        entries,
    };
    Op::Receive(leader, message)
}

fn vote(candidate: u16, term: u64, (last_index, last_term): (u64, u64)) -> Op {
    let message = Message::Vote {
        term,
        candidate,
        last_index,
        last_term,
    };
    Op::Receive(candidate, message)
}

fn op() -> impl Strategy<Value = Op> {
    // Two peers and few terms, so a snapshot often comes from the leader of
    // the current term.
    let peer = || prop::sample::select(PEERS.to_vec());
    let (term, index) = (0u64..12, 0u64..30);
    let position = || (index.clone(), term.clone());
    prop_oneof![
        (peer(), term.clone(), position(), index.clone(), 0u8..3)
            .prop_map(|(from, term, prev, commit, count)| append(from, term, prev, commit, count)),
        (peer(), term.clone(), position()).prop_map(|(from, term, last)| vote(from, term, last)),
        (peer(), term.clone(), position()).prop_map(|(from, term, at)| Op::Install(from, term, at)),
    ]
}

/// A replica and its store: the durable term and vote, and each entry's
/// term.
struct Replica {
    core: Core<u16>,
    hard: (u64, Option<u16>),
    log: BTreeMap<u64, u64>,
    sent: Vec<Message<u16>>,
}

impl Replica {
    fn new() -> Self {
        let cfg = Config::new(ME, vec![ME, PEERS[0], PEERS[1]]);
        let core = Core::new(cfg, Recovered::default(), 0, 7);
        let (hard, log, sent) = ((0, None), BTreeMap::new(), Vec::new());
        Self {
            core,
            hard,
            log,
            sent,
        }
    }

    fn deliver(&mut self, op: Op) {
        match op {
            Op::Receive(from, message) => self.core.receive(from, message),
            Op::Install(from, term, (index, index_term)) => {
                let status = self.core.status();
                if self.core.role() == Role::Follower
                    && status.leader_hint == Some(from)
                    && status.current_term == term
                    && index > status.snap_last_index
                {
                    let switch = self.core.snapshot_switch(index, index_term, None);
                    let after = switch.truncate_after.unwrap_or(u64::MAX);
                    self.log.retain(|&at, _| at <= after && at > index);
                    self.hard = (switch.meta.current_term, switch.meta.voted_for);
                    self.core.snapshot_installed(index, index_term, None);
                }
            }
        }
        // Write and report every write, until the core asks for nothing.
        loop {
            let actions = self.core.take_actions();
            if actions.is_empty() {
                return;
            }
            for action in actions {
                match action {
                    Action::Write(write) => {
                        if let Some(after) = write.truncate_after {
                            self.log.retain(|&at, _| at <= after);
                        }
                        let terms = write.entries.iter().map(|entry| (entry.index, entry.term));
                        self.log.extend(terms);
                        if let Some(meta) = write.meta {
                            self.hard = (meta.current_term, meta.voted_for);
                        }
                        self.core.durable(write.seq);
                        self.core.entries_durable(write.seq);
                    }
                    Action::Send { message, .. } => self.sent.push(message),
                    _ => {}
                }
            }
        }
    }
}

fn invariants_hold(ops: Vec<Op>) -> Result<(), TestCaseError> {
    let mut replica = Replica::new();
    let (mut term, mut commit, mut snapshot) = (0, 0, 0);
    // The durable vote of each term, and each index's entry term, so far.
    let mut votes: BTreeMap<u64, u16> = BTreeMap::new();
    let mut held: BTreeMap<u64, u64> = BTreeMap::new();
    for op in ops {
        replica.deliver(op);
        let status = replica.core.status();
        prop_assert!(status.current_term >= term, "the term went back");
        prop_assert!(status.commit_index >= commit, "the commit went back");
        prop_assert!(status.snap_last_index >= snapshot, "the snapshot went back");
        prop_assert!(status.commit_index >= status.snap_last_index);
        term = status.current_term;
        commit = status.commit_index;
        snapshot = status.snap_last_index;
        if let (at, Some(vote)) = replica.hard {
            let first = *votes.entry(at).or_insert(vote);
            prop_assert_eq!(first, vote, "two votes in term {}", at);
        }
        for (&index, &entry_term) in &replica.log {
            prop_assert!(
                entry_term <= term,
                "entry {index} is from term {entry_term}"
            );
            // Only a leader of a later term than the entry's replaces it.
            let before = held.insert(index, entry_term).unwrap_or(entry_term);
            prop_assert!(
                before == entry_term || term > before,
                "entry {index} replaced"
            );
        }
    }
    Ok(())
}

proptest! {
    #[test]
    fn invariants_hold_under_random_messages(ops in prop::collection::vec(op(), 0..50)) {
        invariants_hold(ops)?;
    }

    /// Of two candidates asking for votes in one term, at most one is
    /// granted.
    #[test]
    fn at_most_one_vote_per_term_under_random_pairings(
        term in 1u64..50,
        first in 0xBBBBu16..=0xBBBE,
        second in 0xBBBFu16..=0xBBC2,
    ) {
        let mut replica = Replica::new();
        for candidate in [first, second] {
            replica.deliver(vote(candidate, term, (0, 0)));
        }
        let granted = replica
            .sent
            .iter()
            .filter(|message| matches!(message, Message::VoteAnswer { granted: true, .. }))
            .count();
        prop_assert!(granted <= 1, "{granted} votes in term {term}");
    }
}

/// An entry at term 0, then a rejected append and an accepted one from a
/// leader of term 11 that replaces it.
#[test]
fn an_entry_replaced_by_a_later_leader_keeps_the_invariants() {
    let leader = PEERS[0];
    let ops = vec![
        append(leader, 0, (0, 0), 0, 1),
        append(leader, 11, (0, 1), 0, 0),
        append(leader, 11, (0, 0), 0, 1),
    ];
    invariants_hold(ops).unwrap();
}
