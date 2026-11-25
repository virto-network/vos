//! Building replicas and reading what they do.

use vos_raft::core::{Action, Core, Load, Recovered, Write};
use vos_raft::{AppendResult, Config, LogEntry, Message, Meta, Role};

pub const LEADER_A: u16 = 2;
pub const LEADER_B: u16 = 3;
pub const ME: u16 = 1;

pub fn config() -> Config<u16> {
    Config::new(ME, vec![ME, LEADER_A, LEADER_B])
}

/// What a replica at `term` recovers: `entries`, committed and applied
/// through `commit`.
pub fn recovered(term: u64, commit: u64, entries: Vec<LogEntry<u16>>) -> Recovered<u16> {
    Recovered {
        meta: Meta {
            current_term: term,
            commit_index: commit,
            ..Meta::default()
        },
        entries,
        applied: commit,
        ..Recovered::default()
    }
}

/// `recovered`, its log starting after a snapshot through `index` at
/// `term`.
pub fn snapshotted(mut recovered: Recovered<u16>, (index, term): (u64, u64)) -> Recovered<u16> {
    recovered.meta.snap_last_index = index;
    recovered.meta.snap_last_term = term;
    recovered
}

/// A follower at `term`, durably holding `terms` (entry i + 1 has
/// `terms[i]`), committed through `commit`.
pub fn follower(term: u64, terms: &[u64], commit: u64) -> Core<u16> {
    let entries = terms
        .iter()
        .enumerate()
        .map(|(at, &term)| LogEntry::data(at as u64 + 1, term, vec![at as u8]))
        .collect();
    let mut core = Core::new(config(), recovered(term, commit, entries), 0, 7);
    core.take_actions();
    core
}

/// An append in round 1 of data entries at (index, term).
pub fn append(
    term: u64,
    leader: u16,
    prev: (u64, u64),
    commit: u64,
    entries: &[(u64, u64)],
) -> Message<u16> {
    let entries = entries
        .iter()
        .map(|&(index, term)| LogEntry::data(index, term, vec![0xee]))
        .collect();
    append_entries(term, leader, prev, commit, entries)
}

/// An append in round 1 of `entries`.
pub fn append_entries(
    term: u64,
    leader: u16,
    (prev_index, prev_term): (u64, u64),
    commit: u64,
    entries: Vec<LogEntry<u16>>,
) -> Message<u16> {
    Message::Append {
        term,
        leader,
        prev_index,
        prev_term,
        commit,
        round: 1,
        entries,
    }
}

/// Report `write` durable, its entries included, as a host without
/// blobs does.
pub fn persist(core: &mut Core<u16>, write: &Write<u16>) {
    core.durable(write.seq);
    core.entries_durable(write.seq);
}

/// The last write the core asks for, taking its actions.
pub fn last_write(core: &mut Core<u16>) -> Write<u16> {
    writes(&core.take_actions()).pop().expect("a write")
}

/// Report the last write in `actions` durable.
pub fn persist_last(core: &mut Core<u16>, actions: &[Action<u16>]) {
    persist(core, writes(actions).last().expect("a write"));
}

/// Report every write the core asks for durable, until it asks none.
pub fn persist_all(core: &mut Core<u16>) {
    loop {
        let actions = core.take_actions();
        if actions.is_empty() {
            return;
        }
        for write in writes(&actions) {
            persist(core, &write);
        }
    }
}

/// Make `core` follow `leader` at `term`, by a heartbeat, every write
/// reported durable.
pub fn follow(core: &mut Core<u16>, leader: u16, term: u64) {
    core.receive(leader, append(term, leader, (0, 0), 0, &[]));
    persist_all(core);
    assert_eq!(core.status().leader_hint, Some(leader));
}

/// Persist every write in `actions`, keeping its entries in `store`, the
/// host's log.
pub fn persist_into(store: &mut Vec<LogEntry<u16>>, core: &mut Core<u16>, actions: &[Action<u16>]) {
    for write in writes(actions) {
        store.extend(write.entries.iter().cloned());
        persist(core, &write);
    }
}

/// Make `core` (pre-vote off) lead: its deadline lapses at `at`, its vote
/// is durable, and A grants it. The actions after, its no-op's write
/// among them.
pub fn lead(core: &mut Core<u16>, at: u64) -> Vec<Action<u16>> {
    core.tick(at);
    let vote = last_write(core);
    persist(core, &vote);
    let term = core.status().current_term;
    core.receive(LEADER_A, vote_answer(term, true));
    assert_eq!(core.role(), Role::Leader);
    core.take_actions()
}

/// A two-member group led by `ME`, at term 1, holding its no-op durably.
pub fn leader_of_two() -> Core<u16> {
    leader_of_two_with(|_| {})
}

/// As [`leader_of_two`], with its configuration adjusted by `adjust`.
pub fn leader_of_two_with(adjust: impl FnOnce(&mut Config<u16>)) -> Core<u16> {
    let mut core = without_pre_votes(Recovered::default(), |cfg| {
        cfg.members = vec![ME, LEADER_A];
        adjust(cfg);
    });
    let actions = lead(&mut core, 1_000);
    persist_last(&mut core, &actions);
    core.take_actions();
    core
}

/// A three-member group led by `ME`, at term 1, with idle heartbeats
/// off, whose followers acknowledged its no-op and the commit.
pub fn idle_leader_of_three() -> Core<u16> {
    leader_of_three_with(|cfg| cfg.idle_heartbeats = false)
}

/// A three-member group led by `ME`, at term 1, its configuration
/// adjusted by `adjust`, whose followers acknowledged its no-op and the
/// commit.
pub fn leader_of_three_with(adjust: impl FnOnce(&mut Config<u16>)) -> Core<u16> {
    let mut core = without_pre_votes(Recovered::default(), adjust);
    let actions = lead(&mut core, 1_000);
    persist_last(&mut core, &actions);
    for peer in [LEADER_A, LEADER_B] {
        core.receive(peer, acked(1, 0));
        core.receive(peer, acked(1, 1));
    }
    core.take_actions();
    core
}

/// A replica with pre-votes off, recovering `recovered`, its
/// configuration adjusted by `adjust`, its first actions taken.
pub fn without_pre_votes(
    recovered: Recovered<u16>,
    adjust: impl FnOnce(&mut Config<u16>),
) -> Core<u16> {
    let mut cfg = config();
    cfg.pre_vote = false;
    adjust(&mut cfg);
    let mut core = Core::new(cfg, recovered, 0, 5);
    core.take_actions();
    core
}

pub fn writes(actions: &[Action<u16>]) -> Vec<Write<u16>> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Write(write) => Some(write.clone()),
            _ => None,
        })
        .collect()
}

/// The highest index any acknowledgement in `actions` claims.
pub fn claimed(actions: &[Action<u16>]) -> Option<u64> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Send {
                message:
                    Message::AppendAnswer {
                        result: AppendResult::Matched { matched },
                        ..
                    },
                ..
            } => Some(*matched),
            _ => None,
        })
        .max()
}

pub fn committed(actions: &[Action<u16>]) -> Option<u64> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Committed { index } => Some(*index),
            _ => None,
        })
        .max()
}

pub fn sent(actions: &[Action<u16>]) -> Vec<Message<u16>> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Send { message, .. } => Some(message.clone()),
            _ => None,
        })
        .collect()
}

/// The appends in `actions`, as (receiver, commit, round).
pub fn appends(actions: &[Action<u16>]) -> Vec<(u16, u64, u64)> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Send {
                to,
                message: Message::Append { commit, round, .. },
            } => Some((*to, *commit, *round)),
            _ => None,
        })
        .collect()
}

/// The appends in `actions` to `peer`, as (previous index, entry
/// indexes).
pub fn entries_to(actions: &[Action<u16>], peer: u16) -> Vec<(u64, Vec<u64>)> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Send {
                to,
                message:
                    Message::Append {
                        prev_index,
                        entries,
                        ..
                    },
            } if *to == peer => Some((
                *prev_index,
                entries.iter().map(|entry| entry.index).collect(),
            )),
            _ => None,
        })
        .collect()
}

/// A's answer, at term 1, that it holds through `matched`.
pub fn matched(matched: u64) -> Message<u16> {
    acked(matched, 0)
}

/// A's answer, at term 1, to an append carrying `commit`.
pub fn acked(matched: u64, commit: u64) -> Message<u16> {
    acked_at(1, 0, matched, commit)
}

/// An answer, at `term` in heartbeat `round`, that the peer holds through
/// `matched`, to an append carrying `commit`.
pub fn acked_at(term: u64, round: u64, matched: u64, commit: u64) -> Message<u16> {
    Message::AppendAnswer {
        term,
        round,
        commit,
        result: AppendResult::Matched { matched },
    }
}

pub fn vote(term: u64, candidate: u16, (last_index, last_term): (u64, u64)) -> Message<u16> {
    Message::Vote {
        term,
        candidate,
        last_index,
        last_term,
    }
}

pub fn pre_vote(
    next_term: u64,
    candidate: u16,
    (last_index, last_term): (u64, u64),
) -> Message<u16> {
    Message::PreVote {
        next_term,
        candidate,
        last_index,
        last_term,
    }
}

pub fn vote_answer(term: u64, granted: bool) -> Message<u16> {
    Message::VoteAnswer { term, granted }
}

/// The loads in `actions`.
pub fn loads(actions: &[Action<u16>]) -> Vec<Load> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::LoadEntries(load) => Some(*load),
            _ => None,
        })
        .collect()
}

pub fn compact_bounds(actions: &[Action<u16>]) -> Vec<u64> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::CompactBound { through, .. } => Some(*through),
            _ => None,
        })
        .collect()
}
