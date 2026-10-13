//! The protocol core, driven directly: what it claims, applies and sends,
//! write by write. Cluster behaviour under faults is in `tests/simulated.rs`.

use vos_raft::core::{
    Action, Answer, ChangeMembershipError, Core, ProposeError, ReadIndexError, Recovered,
    SnapshotConfiguration, Write,
};
use vos_raft::{
    ActiveConfigRecord, AppendResult, Config, EntryKind, LogEntry, Message, Meta, Role,
};

const LEADER_A: u16 = 2;
const LEADER_B: u16 = 3;
const ME: u16 = 1;

fn config() -> Config<u16> {
    let mut cfg = Config::new(ME, vec![ME, LEADER_A, LEADER_B]);
    cfg.election_timeout_ms = (150, 300);
    cfg.heartbeat_interval_ms = 50;
    cfg
}

/// A follower at `term`, durably holding `terms` (entry i + 1 has
/// `terms[i]`), committed through `commit`.
fn follower(term: u64, terms: &[u64], commit: u64) -> Core<u16> {
    let entries = terms
        .iter()
        .enumerate()
        .map(|(at, &term)| LogEntry::data(at as u64 + 1, term, vec![at as u8]))
        .collect();
    let recovered = Recovered {
        meta: Meta {
            current_term: term,
            voted_for: None,
            commit_index: commit,
            snap_last_index: 0,
            snap_last_term: 0,
        },
        entries,
        active_config: None,
        log_start_config: None,
        applied: commit,
        vote_floor: None,
    };
    let mut core = Core::new(config(), recovered, 0, 7);
    core.take_actions();
    core
}

fn append(
    term: u64,
    leader: u16,
    prev: (u64, u64),
    commit: u64,
    entries: &[(u64, u64)],
) -> Message<u16> {
    Message::Append {
        term,
        leader,
        prev_index: prev.0,
        prev_term: prev.1,
        commit,
        round: 1,
        entries: entries
            .iter()
            .map(|&(index, term)| LogEntry::data(index, term, vec![0xee]))
            .collect(),
    }
}

/// Report `write` durable, its entries included, as a host without
/// blobs does.
fn persist(core: &mut Core<u16>, write: &Write<u16>) {
    core.durable(write.seq);
    core.entries_durable(write.seq);
}

fn writes(actions: &[Action<u16>]) -> Vec<Write<u16>> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Write(write) => Some(write.clone()),
            _ => None,
        })
        .collect()
}

/// The highest index any acknowledgement in `actions` claims.
fn claimed(actions: &[Action<u16>]) -> Option<u64> {
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

fn committed(actions: &[Action<u16>]) -> Option<u64> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Committed { index } => Some(*index),
            _ => None,
        })
        .max()
}

fn sent(actions: &[Action<u16>]) -> Vec<Message<u16>> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Send { message, .. } => Some(message.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn a_late_report_of_a_replaced_write_vouches_for_nothing() {
    // Durable through 10; leader A (term 2) sends 11, written but not yet
    // durable.
    let mut core = follower(2, &[1; 10], 10);
    core.receive(LEADER_A, append(2, LEADER_A, (10, 1), 0, &[(11, 2)]));
    let first = core.take_actions();
    let old_write = writes(&first).last().expect("a write").clone();
    assert_eq!(
        claimed(&first),
        Some(10),
        "only the durable prefix is claimed"
    );

    // Leader B (term 3) replaces 11 and adds 12.
    core.receive(
        LEADER_B,
        append(3, LEADER_B, (10, 1), 0, &[(11, 3), (12, 3)]),
    );
    let second = core.take_actions();
    let new_write = writes(&second).last().expect("a write").clone();

    // The old write's report arrives late. It wrote an entry at 11 too, but
    // at term 2: it must not vouch for B's entry there.
    persist(&mut core, &old_write);
    let late = core.take_actions();
    assert!(claimed(&late).is_none_or(|index| index <= 10), "{late:?}");
    assert_eq!(core.status().durable_index, 10);

    // B's own write does.
    persist(&mut core, &new_write);
    let ready = core.take_actions();
    assert_eq!(claimed(&ready), Some(12));
    assert_eq!(core.status().durable_index, 12);
}

/// A two-member group led by `ME`, at term 1, holding its no-op durably.
fn leader_of_two() -> Core<u16> {
    leader_of_two_with(|_| {})
}

/// As [`leader_of_two`], with its configuration adjusted by `adjust`.
fn leader_of_two_with(adjust: impl FnOnce(&mut Config<u16>)) -> Core<u16> {
    let mut cfg = config();
    cfg.members = vec![ME, LEADER_A];
    cfg.pre_vote = false;
    adjust(&mut cfg);
    let mut core = Core::new(cfg, Recovered::default(), 0, 5);
    core.take_actions();
    core.tick(1_000);
    let vote = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &vote);
    core.receive(
        LEADER_A,
        Message::VoteAnswer {
            term: 1,
            granted: true,
        },
    );
    assert_eq!(core.role(), Role::Leader);
    let no_op = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &no_op);
    core.take_actions();
    core
}

#[test]
fn a_leader_sends_each_peer_a_commit_it_has_acknowledged() {
    // A three-member group led by ME; peers A and B.
    let mut cfg = config();
    cfg.pre_vote = false;
    let mut core = Core::new(cfg, Recovered::default(), 0, 5);
    core.take_actions();
    core.tick(1_000);
    let vote = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &vote);
    core.receive(
        LEADER_A,
        Message::VoteAnswer {
            term: 1,
            granted: true,
        },
    );
    assert_eq!(core.role(), Role::Leader);
    for n in 0..4u8 {
        core.propose(u64::from(n), vec![n]);
    }
    let write = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &write);
    let answer = |matched| Message::AppendAnswer {
        term: 1,
        round: 0,
        commit: 0,
        result: AppendResult::Matched { matched },
    };
    // A holds everything, B only through 2: the leader commits 5.
    core.receive(LEADER_A, answer(5));
    core.receive(LEADER_B, answer(2));
    assert_eq!(committed(&core.take_actions()), Some(5));
    // Its next heartbeat tells B no more than B acknowledged.
    core.tick(1_000 + 60);
    let to_b: Vec<u64> = core
        .take_actions()
        .into_iter()
        .filter_map(|action| match action {
            Action::Send {
                to: LEADER_B,
                message: Message::Append { commit, .. },
            } => Some(commit),
            _ => None,
        })
        .collect();
    assert!(!to_b.is_empty());
    assert!(to_b.iter().all(|&commit| commit <= 2), "{to_b:?}");
}

#[test]
fn a_commit_index_never_applies_an_unverified_entry() {
    // The follower holds a stale, uncommitted entry 11 from term 2.
    let mut core = follower(2, &[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2], 10);
    // Leader B of term 3 committed its own entry 11; its heartbeat, with
    // commit 11, overtakes the append that would replace ours.
    core.receive(LEADER_B, append(3, LEADER_B, (10, 1), 11, &[]));
    let actions = core.take_actions();
    assert!(
        committed(&actions).is_none_or(|index| index <= 10),
        "applied the stale entry: {actions:?}"
    );
    // The append arrives: 11 is replaced and verified, and may apply.
    core.receive(LEADER_B, append(3, LEADER_B, (10, 1), 11, &[(11, 3)]));
    let actions = core.take_actions();
    assert_eq!(committed(&actions), Some(11));
}

#[test]
fn a_vote_leaves_only_once_it_is_durable() {
    let mut core = follower(1, &[1, 1], 2);
    core.receive(
        LEADER_B,
        Message::Vote {
            term: 2,
            candidate: LEADER_B,
            last_index: 2,
            last_term: 1,
        },
    );
    let actions = core.take_actions();
    assert!(
        !sent(&actions)
            .iter()
            .any(|message| matches!(message, Message::VoteAnswer { granted: true, .. })),
        "granted before the vote was durable"
    );
    let write = writes(&actions).last().expect("the vote's write").clone();
    assert!(write.sync);
    assert_eq!(
        write.meta.as_ref().map(|meta| meta.voted_for),
        Some(Some(LEADER_B))
    );
    persist(&mut core, &write);
    let actions = core.take_actions();
    assert!(sent(&actions).contains(&Message::VoteAnswer {
        term: 2,
        granted: true
    }));
}

#[test]
fn an_answer_at_a_new_term_waits_for_the_term() {
    let mut core = follower(1, &[1, 1], 2);
    // A heartbeat at term 3: the follower adopts it, and may not answer at
    // term 3 until term 3 is durable.
    core.receive(LEADER_B, append(3, LEADER_B, (2, 1), 2, &[]));
    let actions = core.take_actions();
    assert!(sent(&actions).is_empty(), "{actions:?}");
    let write = writes(&actions).last().expect("the term's write").clone();
    persist(&mut core, &write);
    let actions = core.take_actions();
    assert!(matches!(
        sent(&actions).as_slice(),
        [Message::AppendAnswer { term: 3, .. }]
    ));
    // At the durable term, a heartbeat is answered at once.
    core.receive(LEADER_B, append(3, LEADER_B, (2, 1), 2, &[]));
    let actions = core.take_actions();
    assert_eq!(sent(&actions).len(), 1);
}

#[test]
fn a_candidate_counts_its_own_vote_only_once_durable() {
    let mut cfg = config();
    cfg.members = vec![ME];
    let mut core = Core::new(cfg, Recovered::default(), 0, 3);
    core.take_actions();
    core.tick(1_000);
    let actions = core.take_actions();
    assert_eq!(
        core.role(),
        Role::Candidate,
        "not leader before the vote is durable"
    );
    let write = writes(&actions).last().expect("term and vote").clone();
    persist(&mut core, &write);
    let actions = core.take_actions();
    assert_eq!(core.role(), Role::Leader);
    // Its no-op commits only once durable, too.
    assert!(committed(&actions).is_none());
    let no_op = writes(&actions).last().expect("the no-op").clone();
    persist(&mut core, &no_op);
    assert_eq!(committed(&core.take_actions()), Some(1));
}

#[test]
fn heartbeats_go_to_peers_with_an_append_in_flight() {
    let mut core = leader_of_two();
    // The no-op is in flight to the peer, unanswered; the next heartbeat
    // still goes.
    core.tick(1_000 + 60);
    let actions = core.take_actions();
    assert!(sent(&actions).iter().any(|message| matches!(
        message,
        Message::Append { entries, .. } if entries.is_empty()
    )));
}

fn matched(matched: u64) -> Message<u16> {
    Message::AppendAnswer {
        term: 1,
        round: 0,
        commit: 0,
        result: AppendResult::Matched { matched },
    }
}

/// The appends in `actions` to `peer`, as (prev_index, entry indices).
fn appends_to(actions: &[Action<u16>], peer: u16) -> Vec<(u64, Vec<u64>)> {
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

fn proposals_refused(actions: &[Action<u16>]) -> usize {
    actions
        .iter()
        .filter(|action| {
            matches!(
                action,
                Action::Answer(Answer::Propose {
                    result: Err(ProposeError::NotLeader),
                    ..
                })
            )
        })
        .count()
}

/// The commits in `actions` sent to `peer` in appends with no entries.
fn commits_to(actions: &[Action<u16>], peer: u16) -> Vec<(u64, u64)> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Send {
                to,
                message:
                    Message::Append {
                        commit,
                        round,
                        entries,
                        ..
                    },
            } if *to == peer && entries.is_empty() => Some((*commit, *round)),
            _ => None,
        })
        .collect()
}

#[test]
fn followers_learn_a_commit_at_once_without_a_heartbeat() {
    // A three-member group led by ME; its no-op is in flight to A and B.
    let mut cfg = config();
    cfg.pre_vote = false;
    let mut core = Core::new(cfg, Recovered::default(), 0, 5);
    core.take_actions();
    core.tick(1_000);
    let vote = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &vote);
    core.receive(
        LEADER_A,
        Message::VoteAnswer {
            term: 1,
            granted: true,
        },
    );
    let no_op = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &no_op);
    core.take_actions();
    // A holds the no-op: it commits, and A is told at once, in the round of
    // the leader's first heartbeat, opening none; B, with the no-op still
    // in flight, is not.
    core.receive(LEADER_A, matched(1));
    let actions = core.take_actions();
    assert_eq!(committed(&actions), Some(1));
    assert_eq!(commits_to(&actions, LEADER_A), vec![(1, 1)]);
    assert!(commits_to(&actions, LEADER_B).is_empty());
    // B's answer frees its slot: B learns the commit too, once.
    core.receive(LEADER_B, matched(1));
    assert_eq!(commits_to(&core.take_actions(), LEADER_B), vec![(1, 1)]);
    core.receive(LEADER_B, matched(1));
    assert!(commits_to(&core.take_actions(), LEADER_B).is_empty());
    // A later entry: its append carries the old commit, and the new one
    // follows each acknowledgement, never above what the peer holds.
    core.propose(1, vec![1]);
    let write = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &write);
    core.take_actions();
    core.receive(LEADER_A, matched(2));
    let actions = core.take_actions();
    assert_eq!(committed(&actions), Some(2));
    assert_eq!(commits_to(&actions, LEADER_A), vec![(2, 1)]);
    assert!(commits_to(&actions, LEADER_B).is_empty());
}

#[test]
fn a_proposal_goes_out_at_once_unless_an_append_is_in_flight() {
    let mut core = leader_of_two();
    // The no-op is in flight to A: a proposal waits for its answer.
    core.propose(1, vec![1]);
    let actions = core.take_actions();
    assert!(appends_to(&actions, LEADER_A).is_empty(), "{actions:?}");
    // A acknowledges the no-op: the proposal follows at once, without
    // waiting for a heartbeat.
    core.receive(LEADER_A, matched(1));
    assert_eq!(
        appends_to(&core.take_actions(), LEADER_A),
        vec![(1, vec![2])]
    );
    // With the slot free again, a proposal is sent as it is made.
    core.receive(LEADER_A, matched(2));
    core.take_actions();
    core.propose(2, vec![2]);
    assert_eq!(
        appends_to(&core.take_actions(), LEADER_A),
        vec![(2, vec![3])]
    );
}

#[test]
fn an_append_carries_at_most_its_byte_cap() {
    let mut cfg = config();
    cfg.members = vec![ME, LEADER_A];
    cfg.pre_vote = false;
    cfg.max_append_bytes = 100;
    let mut core = Core::new(cfg, Recovered::default(), 0, 5);
    core.take_actions();
    core.tick(1_000);
    let vote = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &vote);
    core.receive(
        LEADER_A,
        Message::VoteAnswer {
            term: 1,
            granted: true,
        },
    );
    core.take_actions();
    for n in 0..3u8 {
        core.propose(u64::from(n), vec![n; 60]);
    }
    core.take_actions();
    // Each 60-byte entry fills most of the cap: one entry per append.
    for next in 2..=4 {
        core.receive(LEADER_A, matched(next - 1));
        assert_eq!(
            appends_to(&core.take_actions(), LEADER_A),
            vec![(next - 1, vec![next])]
        );
    }
}

#[test]
fn a_rejection_moves_the_probe_past_the_conflicting_term() {
    // The leader holds 1..=3 at term 1 and 4..=6 at term 3; elected at
    // term 4, it appends its no-op at 7.
    let mut cfg = config();
    cfg.members = vec![ME, LEADER_A];
    cfg.pre_vote = false;
    let entries = [1, 1, 1, 3, 3, 3]
        .iter()
        .enumerate()
        .map(|(at, &term)| LogEntry::data(at as u64 + 1, term, vec![at as u8]))
        .collect();
    let recovered = Recovered {
        meta: Meta {
            current_term: 3,
            voted_for: None,
            commit_index: 3,
            snap_last_index: 0,
            snap_last_term: 0,
        },
        entries,
        active_config: None,
        log_start_config: None,
        applied: 3,
        vote_floor: None,
    };
    let mut core = Core::new(cfg, recovered, 0, 5);
    core.take_actions();
    core.tick(1_000);
    let vote = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &vote);
    core.receive(
        LEADER_A,
        Message::VoteAnswer {
            term: 4,
            granted: true,
        },
    );
    assert_eq!(core.role(), Role::Leader);
    let (probe, _) = appends_to(&core.take_actions(), LEADER_A)[0].clone();
    assert!(probe >= 6, "the first probe follows the leader's log");
    // A holds 4..=5 at term 2, which the leader never had: the probe
    // skips the whole term at once, to the end of the leader's term 1.
    core.receive(
        LEADER_A,
        Message::AppendAnswer {
            term: 4,
            round: 0,
            commit: 0,
            result: AppendResult::Rejected {
                rejected: probe,
                last_index: 5,
                conflict_term: 2,
                conflict_first: 4,
            },
        },
    );
    let appends = appends_to(&core.take_actions(), LEADER_A);
    assert_eq!(
        appends.first().map(|(prev, _)| *prev),
        Some(3),
        "{appends:?}"
    );
}

#[test]
fn check_quorum_deposes_a_leader_that_hears_from_no_one() {
    let mut core = leader_of_two();
    // A's pair heartbeat counts as hearing from it.
    core.tick(1_000 + 200);
    core.peer_alive(LEADER_A);
    core.tick(1_000 + 310);
    core.take_actions();
    assert_eq!(core.role(), Role::Leader);
    // A whole election timeout of silence: the leader steps down.
    core.tick(1_000 + 620);
    core.take_actions();
    assert_eq!(core.role(), Role::Follower);
}

#[test]
fn a_transfer_hands_over_once_the_target_holds_everything() {
    let mut core = leader_of_two();
    core.receive(LEADER_A, matched(1));
    core.propose(1, vec![1]);
    let write = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &write);
    core.transfer_leadership(Some(LEADER_A));
    let actions = core.take_actions();
    assert!(
        !sent(&actions).contains(&Message::TimeoutNow { term: 1 }),
        "A lacks entry 2: {actions:?}"
    );
    // While handing over, the leader takes no proposals.
    core.propose(2, vec![2]);
    assert_eq!(proposals_refused(&core.take_actions()), 1);
    core.receive(LEADER_A, matched(2));
    assert!(sent(&core.take_actions()).contains(&Message::TimeoutNow { term: 1 }));
}

#[test]
fn a_stalled_writer_hands_leadership_over() {
    let mut core = leader_of_two();
    core.receive(LEADER_A, matched(1));
    // The leader's own write of entry 2 never completes; A holds it.
    core.propose(1, vec![1]);
    core.take_actions();
    core.receive(LEADER_A, matched(2));
    core.take_actions();
    core.writer_health(true);
    assert!(sent(&core.take_actions()).contains(&Message::TimeoutNow { term: 1 }));
}

#[test]
fn a_stalled_leader_keeps_handing_over_until_a_peer_catches_up() {
    let mut core = leader_of_two();
    core.receive(LEADER_A, matched(1));
    core.propose(1, vec![1]);
    core.take_actions();
    // A lacks entry 2: the handover waits, and outlives its deadline.
    core.writer_health(true);
    assert!(!sent(&core.take_actions()).contains(&Message::TimeoutNow { term: 1 }));
    core.tick(1_000 + 310);
    core.receive(LEADER_A, matched(1));
    core.take_actions();
    // Still stalled, the leader still takes no proposals.
    core.propose(2, vec![2]);
    assert_eq!(proposals_refused(&core.take_actions()), 1);
    core.receive(LEADER_A, matched(2));
    assert!(sent(&core.take_actions()).contains(&Message::TimeoutNow { term: 1 }));
}

/// The loads in `actions`.
fn loads(actions: &[Action<u16>]) -> Vec<vos_raft::core::Load> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::LoadEntries(load) => Some(*load),
            _ => None,
        })
        .collect()
}

#[test]
fn a_follower_behind_the_cache_catches_up_from_the_store() {
    // A leader of two whose cache holds almost nothing: entries it has
    // made durable leave the cache as soon as more arrive.
    let mut cfg = config();
    cfg.members = vec![ME, LEADER_A];
    cfg.pre_vote = false;
    cfg.cache_bytes = 1;
    // A stays silent until the resend; check-quorum would depose the leader.
    cfg.check_quorum = false;
    let mut core = Core::new(cfg, Recovered::default(), 0, 5);
    core.take_actions();
    core.tick(1_000);
    let vote = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &vote);
    core.receive(
        LEADER_A,
        Message::VoteAnswer {
            term: 1,
            granted: true,
        },
    );
    // The store: every entry the leader writes, made durable at once.
    let mut store: Vec<LogEntry<u16>> = Vec::new();
    let mut persist_all = |core: &mut Core<u16>, actions: &[Action<u16>]| {
        for write in writes(actions) {
            store.extend(write.entries.iter().cloned());
            persist(core, &write);
        }
    };
    let actions = core.take_actions();
    persist_all(&mut core, &actions);
    for n in 0..6u8 {
        core.propose(u64::from(n), vec![n]);
        let actions = core.take_actions();
        persist_all(&mut core, &actions);
    }
    // A never answered the no-op; its slot frees after the resend timeout,
    // and what it lacks is no longer cached.
    core.tick(1_000 + 1_100);
    let mut actions = core.take_actions();
    let mut sent_to_a: Vec<u64> = Vec::new();
    for _ in 0..20 {
        for (_, entries) in appends_to(&actions, LEADER_A) {
            if let Some(&last) = entries.last() {
                sent_to_a.extend(entries);
                core.receive(LEADER_A, matched(last));
            }
        }
        let pending = loads(&actions);
        for load in pending {
            let entries = store
                .iter()
                .filter(|entry| (load.from..=load.to).contains(&entry.index))
                .cloned()
                .collect();
            core.loaded(load, entries);
        }
        actions = core.take_actions();
        if actions.is_empty() {
            break;
        }
    }
    assert_eq!(
        sent_to_a,
        (1..=7).collect::<Vec<u64>>(),
        "every entry, once, in order"
    );
}

#[test]
fn a_leader_refuses_pre_votes() {
    // Led for longer than the shortest election timeout: a follower that
    // stopped hearing it over a lossy link must not win its pre-vote.
    let mut cfg = config();
    cfg.pre_vote = false;
    cfg.check_quorum = false;
    let mut core = Core::new(cfg, Recovered::default(), 0, 5);
    core.take_actions();
    core.tick(1_000);
    let vote = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &vote);
    core.receive(
        LEADER_A,
        Message::VoteAnswer {
            term: 1,
            granted: true,
        },
    );
    assert_eq!(core.role(), Role::Leader);
    core.tick(1_000 + 400);
    core.take_actions();
    core.receive(
        LEADER_B,
        Message::PreVote {
            next_term: 2,
            candidate: LEADER_B,
            last_index: 100,
            last_term: 1,
        },
    );
    assert!(
        sent(&core.take_actions()).contains(&Message::PreVoteAnswer {
            term: 1,
            next_term: 2,
            granted: false,
        })
    );
}

#[test]
fn a_stalled_leader_steps_down_and_stays_quiet() {
    let mut core = leader_of_two();
    core.receive(LEADER_A, matched(1));
    core.propose(1, vec![1]);
    core.take_actions();
    // A never catches up: every handover times out, and then the leader
    // steps down.
    core.writer_health(true);
    let mut now = 1_000;
    for _ in 0..6 {
        now += 310;
        core.peer_alive(LEADER_A);
        core.tick(now);
        core.take_actions();
    }
    assert_eq!(core.role(), Role::Follower);
    // While its writer is stalled, it does not campaign.
    for _ in 0..10 {
        now += 400;
        core.tick(now);
        let actions = core.take_actions();
        assert!(
            !sent(&actions)
                .iter()
                .any(|message| matches!(message, Message::Vote { .. } | Message::PreVote { .. })),
            "{actions:?}"
        );
    }
    // Once it recovers, it campaigns again.
    core.writer_health(false);
    let mut campaigned = false;
    for _ in 0..4 {
        now += 400;
        core.tick(now);
        campaigned |= sent(&core.take_actions())
            .iter()
            .any(|message| matches!(message, Message::Vote { .. } | Message::PreVote { .. }));
    }
    assert!(campaigned);
}

#[test]
fn timeout_now_counts_only_from_the_leader() {
    let mut core = follower(1, &[1, 1], 2);
    core.receive(LEADER_A, append(1, LEADER_A, (2, 1), 2, &[]));
    core.take_actions();
    core.receive(LEADER_B, Message::TimeoutNow { term: 1 });
    core.take_actions();
    assert_eq!(core.role(), Role::Follower);
    // Nor while its writer is stalled: it could not persist the vote.
    core.writer_health(true);
    core.receive(LEADER_A, Message::TimeoutNow { term: 1 });
    core.take_actions();
    assert_eq!(core.role(), Role::Follower);
    core.writer_health(false);
    core.receive(LEADER_A, Message::TimeoutNow { term: 1 });
    core.take_actions();
    assert_eq!(core.role(), Role::Candidate);
}

#[test]
fn a_snapshot_switch_records_the_newest_term_and_vote() {
    // A vote at term 2 is queued, not yet durable, when a switch is made:
    // the switch must not write an older term or vote over it.
    let mut core = follower(1, &[1, 1], 2);
    core.receive(
        LEADER_B,
        Message::Vote {
            term: 2,
            candidate: LEADER_B,
            last_index: 2,
            last_term: 1,
        },
    );
    core.take_actions();
    let switch = core.snapshot_switch(10, 2, None);
    assert_eq!(switch.meta.current_term, 2);
    assert_eq!(switch.meta.voted_for, Some(LEADER_B));
    assert_eq!(
        (switch.meta.snap_last_index, switch.meta.commit_index),
        (10, 10)
    );
}

#[test]
fn a_load_that_starts_late_sends_nothing() {
    let mut cfg = config();
    cfg.members = vec![ME, LEADER_A];
    cfg.pre_vote = false;
    cfg.cache_bytes = 1;
    cfg.check_quorum = false;
    let mut core = Core::new(cfg, Recovered::default(), 0, 5);
    core.take_actions();
    core.tick(1_000);
    let vote = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &vote);
    core.receive(
        LEADER_A,
        Message::VoteAnswer {
            term: 1,
            granted: true,
        },
    );
    let mut store: Vec<LogEntry<u16>> = Vec::new();
    for n in 0..4u8 {
        let actions = core.take_actions();
        for write in writes(&actions) {
            store.extend(write.entries.iter().cloned());
            persist(&mut core, &write);
        }
        core.propose(u64::from(n), vec![n]);
    }
    for write in writes(&core.take_actions()) {
        store.extend(write.entries.iter().cloned());
        persist(&mut core, &write);
    }
    core.tick(1_000 + 1_100);
    let load = loads(&core.take_actions())[0];
    // The store compacted the load's first entry away meanwhile.
    let late = store
        .iter()
        .filter(|entry| entry.index > load.from && entry.index <= load.to)
        .cloned()
        .collect();
    core.loaded(load, late);
    let actions = core.take_actions();
    assert!(appends_to(&actions, LEADER_A).is_empty(), "{actions:?}");
    assert!(loads(&actions).is_empty(), "not reissued: {actions:?}");
}

/// A follower whose entry waits for a blob that never comes (its leader
/// died with the only copy) still persists terms and votes, and can drop
/// the entry, so the group elects a leader that can commit.
#[test]
fn an_entry_waiting_for_a_lost_blob_never_stalls_an_election() {
    // Durable through 10. Leader A, at term 2, sends entry 11, naming a
    // blob that never arrives: the write lands, its entries are never
    // reported.
    let mut core = follower(1, &[1; 10], 10);
    core.receive(LEADER_A, append(2, LEADER_A, (10, 1), 10, &[(11, 2)]));
    let write = writes(&core.take_actions()).last().unwrap().clone();
    core.durable(write.seq);
    core.take_actions();
    assert_eq!(core.status().durable_index, 10);
    // A dies. B, without 11, asks for votes at term 3: refused, our log
    // is longer.
    let vote = |term| Message::Vote {
        term,
        candidate: LEADER_B,
        last_index: 10,
        last_term: 1,
    };
    core.receive(LEADER_B, vote(3));
    let actions = core.take_actions();
    let term_write = writes(&actions).last().unwrap().clone();
    core.durable(term_write.seq);
    assert!(
        sent(&core.take_actions())
            .iter()
            .chain(sent(&actions).iter())
            .all(|message| !matches!(message, Message::VoteAnswer { granted: true, .. }))
    );
    // The host gives up on the blob: the unreported entry goes, and B's
    // next request is granted, once our vote is durable.
    core.discard_unreported();
    assert_eq!(core.status().last_log_index, 10);
    core.receive(LEADER_B, vote(4));
    let vote_write = writes(&core.take_actions()).last().unwrap().clone();
    core.durable(vote_write.seq);
    assert!(sent(&core.take_actions()).contains(&Message::VoteAnswer {
        term: 4,
        granted: true
    }));
}

#[test]
fn a_discard_keeps_committed_entries() {
    // A follower whose leader committed entry 11 keeps it: a quorum holds
    // its blob.
    let mut core = follower(1, &[1; 10], 10);
    core.receive(
        LEADER_A,
        append(2, LEADER_A, (10, 1), 11, &[(11, 2), (12, 2)]),
    );
    let write = writes(&core.take_actions()).last().unwrap().clone();
    core.durable(write.seq);
    core.take_actions();
    core.discard_unreported();
    assert_eq!(core.status().last_log_index, 11, "12 goes, 11 is committed");
}

#[test]
fn a_leader_steps_down_before_it_discards() {
    let mut leader = leader_of_two();
    leader.receive(LEADER_A, matched(1));
    leader.propose(1, vec![1]);
    let write = writes(&leader.take_actions()).last().unwrap().clone();
    leader.durable(write.seq);
    leader.take_actions();
    // Entry 2's blob never comes: the leader cannot count it, nor know
    // whether its follower made it committed. It steps down, then drops
    // what it never reported, keeping what it committed.
    leader.discard_unreported();
    assert_eq!(leader.role(), Role::Follower);
    assert_eq!(leader.status().last_log_index, 1);
    assert_eq!(leader.status().commit_index, 1);
}

#[test]
fn a_candidate_that_discards_ignores_grants_for_its_longer_log() {
    // Entry 12 waits for a lost blob: written and durable, never reported.
    let mut cfg = config();
    cfg.pre_vote = false;
    let entries = (1..=11)
        .map(|index| LogEntry::data(index, if index == 11 { 2 } else { 1 }, vec![]))
        .collect();
    let recovered = Recovered {
        meta: Meta {
            current_term: 2,
            voted_for: None,
            commit_index: 10,
            snap_last_index: 0,
            snap_last_term: 0,
        },
        entries,
        active_config: None,
        log_start_config: None,
        applied: 10,
        vote_floor: None,
    };
    let mut core = Core::new(cfg, recovered, 0, 7);
    core.take_actions();
    core.receive(LEADER_A, append(2, LEADER_A, (11, 2), 10, &[(12, 2)]));
    let write = writes(&core.take_actions()).last().unwrap().clone();
    core.durable(write.seq);
    core.take_actions();
    // Its leader goes quiet: it campaigns, advertising (12, 2).
    core.tick(1_000);
    let campaign = writes(&core.take_actions()).last().unwrap().clone();
    core.durable(campaign.seq);
    core.take_actions();
    assert_eq!(core.role(), Role::Candidate);
    // The host gives up on 12's blob. Grants made against (12, 2) then
    // arrive, and must not make it leader.
    core.discard_unreported();
    assert_eq!(core.role(), Role::Follower);
    assert_eq!(core.status().last_log_index, 11);
    let term = core.status().current_term;
    core.receive(
        LEADER_A,
        Message::VoteAnswer {
            term,
            granted: true,
        },
    );
    core.receive(
        LEADER_B,
        Message::VoteAnswer {
            term,
            granted: true,
        },
    );
    core.take_actions();
    assert_ne!(core.role(), Role::Leader);
}

#[test]
fn a_report_from_before_a_discard_vouches_for_nothing_written_after() {
    let mut core = follower(1, &[1; 10], 10);
    // Entry (11, 2) is written, durable but unreported (its blob waits).
    core.receive(LEADER_A, append(2, LEADER_A, (10, 1), 10, &[(11, 2)]));
    let first = writes(&core.take_actions()).last().unwrap().clone();
    core.durable(first.seq);
    core.take_actions();
    // The host gives up, and the leader sends the same entry again.
    core.discard_unreported();
    let cut = writes(&core.take_actions()).last().unwrap().clone();
    core.durable(cut.seq);
    core.take_actions();
    core.receive(LEADER_A, append(2, LEADER_A, (10, 1), 10, &[(11, 2)]));
    let again = writes(&core.take_actions()).last().unwrap().clone();
    // The first write's report arrives late: it wrote an entry with the
    // same index and term, but the discard removed it.
    core.entries_durable(first.seq);
    core.take_actions();
    assert_eq!(core.status().durable_index, 10);
    // The second write's report counts.
    core.durable(again.seq);
    core.entries_durable(again.seq);
    assert_eq!(claimed(&core.take_actions()), Some(11));
}

/// After compaction took every configuration entry, a truncation that
/// removes a newer one falls back to the configuration in effect at the
/// log's start, which the host kept, never to the static members.
#[test]
fn a_truncation_falls_back_to_the_log_start_configuration() {
    let at_start = ActiveConfigRecord {
        log_index: Some(5),
        current: vec![ME, LEADER_A, 4],
        joint_old: None,
    };
    let recovered = Recovered {
        meta: Meta {
            current_term: 1,
            voted_for: None,
            commit_index: 12,
            snap_last_index: 10,
            snap_last_term: 1,
        },
        entries: vec![LogEntry::data(11, 1, vec![]), LogEntry::data(12, 1, vec![])],
        active_config: Some(at_start.clone()),
        log_start_config: Some(at_start),
        applied: 12,
        vote_floor: None,
    };
    let mut core = Core::new(config(), recovered, 0, 7);
    core.take_actions();
    assert_eq!(core.status().members, vec![ME, LEADER_A, 4]);
    // Leader A appends a configuration at 13, uncommitted.
    let change = LogEntry::config_change(
        13,
        2,
        Some(vec![ME, LEADER_A, 4]),
        vec![ME, LEADER_A, LEADER_B],
    );
    core.receive(
        LEADER_A,
        Message::Append {
            term: 2,
            leader: LEADER_A,
            prev_index: 12,
            prev_term: 1,
            commit: 12,
            round: 1,
            entries: vec![change],
        },
    );
    core.take_actions();
    assert_eq!(core.status().joint_old, Some(vec![ME, LEADER_A, 4]));
    // Leader 4 of term 3 replaces 13: the configuration goes with it.
    core.receive(4, append(3, 4, (12, 1), 12, &[(13, 3)]));
    core.take_actions();
    let status = core.status();
    assert_eq!(status.members, vec![ME, LEADER_A, 4]);
    assert_eq!(status.joint_old, None);
}

/// A host that kept no record of the configuration at its log's start
/// sends snapshots without one, rather than a guess.
#[test]
fn an_unknown_log_start_configuration_is_never_sent() {
    let mut cfg = config();
    cfg.members = vec![ME, LEADER_A];
    cfg.pre_vote = false;
    let newest = LogEntry::config_change(12, 1, None, vec![ME, LEADER_A]);
    let recovered = Recovered {
        meta: Meta {
            current_term: 1,
            voted_for: None,
            commit_index: 12,
            snap_last_index: 10,
            snap_last_term: 1,
        },
        entries: vec![LogEntry::data(11, 1, vec![]), newest],
        active_config: Some(ActiveConfigRecord {
            log_index: Some(12),
            current: vec![ME, LEADER_A],
            joint_old: None,
        }),
        log_start_config: None,
        applied: 12,
        vote_floor: None,
    };
    let mut core = Core::new(cfg, recovered, 0, 3);
    core.take_actions();
    assert_eq!(core.config_at(10), None, "unknown at the log's start");
    assert!(core.config_at(12).is_some());
    core.tick(1_000);
    let vote = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &vote);
    core.receive(
        LEADER_A,
        Message::VoteAnswer {
            term: 2,
            granted: true,
        },
    );
    assert_eq!(core.role(), Role::Leader);
    core.take_actions();
    // A holds nothing: it needs the snapshot at 10.
    core.receive(
        LEADER_A,
        Message::AppendAnswer {
            term: 2,
            round: 0,
            commit: 0,
            result: AppendResult::Rejected {
                rejected: 12,
                last_index: 0,
                conflict_term: 0,
                conflict_first: 0,
            },
        },
    );
    let snapshot = core
        .take_actions()
        .into_iter()
        .find_map(|action| match action {
            Action::SendSnapshot { configuration, .. } => Some(configuration),
            _ => None,
        })
        .expect("a snapshot for A");
    assert_eq!(snapshot, None);
}

#[test]
fn a_lone_member_leads_at_its_first_tick() {
    let mut cfg = config();
    cfg.members = vec![ME];
    let mut core = Core::new(cfg, Recovered::default(), 0, 9);
    core.tick(0);
    // Its vote counts once durable.
    let vote = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &vote);
    let actions = core.take_actions();
    assert_eq!(core.role(), Role::Leader, "{actions:?}");
}

fn appends(actions: &[Action<u16>]) -> Vec<(u16, u64)> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Send {
                to,
                message: Message::Append { commit, .. },
            } => Some((*to, *commit)),
            _ => None,
        })
        .collect()
}

/// A's answer to an append carrying `commit`.
fn acked(matched: u64, commit: u64) -> Message<u16> {
    Message::AppendAnswer {
        term: 1,
        round: 0,
        commit,
        result: AppendResult::Matched { matched },
    }
}

#[test]
fn an_idle_leader_sends_nothing_once_its_follower_holds_the_commit() {
    let mut core = leader_of_two_with(|cfg| cfg.idle_heartbeats = false);
    core.receive(LEADER_A, matched(1));
    assert_eq!(appends(&core.take_actions()), vec![(LEADER_A, 1)]);
    core.receive(LEADER_A, acked(1, 1));
    core.take_actions();
    // Within check-quorum's window, nothing goes out, and the next
    // deadline is check-quorum's.
    core.peer_alive(LEADER_A);
    for at in (1_050..1_300).step_by(50) {
        core.tick(at);
        assert!(appends(&core.take_actions()).is_empty(), "at {at}");
    }
    assert_eq!(core.next_deadline(), 1_000 + 300);
    // A proposal goes out at once, and its commit after it.
    core.propose(1, vec![1]);
    let actions = core.take_actions();
    persist(&mut core, &writes(&actions).last().unwrap().clone());
    assert_eq!(appends(&actions), vec![(LEADER_A, 1)]);
    core.receive(LEADER_A, matched(2));
    assert_eq!(appends(&core.take_actions()), vec![(LEADER_A, 2)]);
}

#[test]
fn a_lost_commit_notice_is_sent_again() {
    let mut core = leader_of_two_with(|cfg| cfg.idle_heartbeats = false);
    core.receive(LEADER_A, matched(1));
    // The commit notice is lost: A never acknowledges commit 1, so the
    // idle leader's heartbeats carry it again.
    assert_eq!(appends(&core.take_actions()), vec![(LEADER_A, 1)]);
    core.tick(1_000 + 60);
    assert_eq!(appends(&core.take_actions()), vec![(LEADER_A, 1)]);
    core.receive(LEADER_A, acked(1, 1));
    core.take_actions();
    core.tick(1_000 + 120);
    assert!(appends(&core.take_actions()).is_empty());
}

/// A three-member group led by `ME`, at term 1, with idle heartbeats
/// off, whose followers acknowledged its no-op and the commit.
fn idle_leader_of_three() -> Core<u16> {
    let mut cfg = config();
    cfg.pre_vote = false;
    cfg.idle_heartbeats = false;
    let mut core = Core::new(cfg, Recovered::default(), 0, 5);
    core.take_actions();
    core.tick(1_000);
    let vote = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &vote);
    core.receive(
        LEADER_A,
        Message::VoteAnswer {
            term: 1,
            granted: true,
        },
    );
    let no_op = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &no_op);
    for peer in [LEADER_A, LEADER_B] {
        core.receive(peer, acked(1, 0));
        core.receive(peer, acked(1, 1));
    }
    core.take_actions();
    core
}

fn appends_to_peer(actions: &[Action<u16>], peer: u16) -> usize {
    appends(actions)
        .iter()
        .filter(|(to, _)| *to == peer)
        .count()
}

#[test]
fn an_idle_leader_leaves_a_silent_member_without_heartbeats() {
    let mut core = idle_leader_of_three();
    // A falls behind, and its node has not been heard: no heartbeats to
    // it, while B, heard, keeps the quorum.
    core.propose(1, vec![1]);
    let actions = core.take_actions();
    persist(&mut core, &writes(&actions).last().unwrap().clone());
    core.receive(LEADER_B, acked(2, 1));
    core.receive(LEADER_B, acked(2, 2));
    core.vouch(
        1_000 + 40,
        |_, _| None,
        |node| (node == LEADER_B).then_some(1_000 + 35),
    );
    core.take_actions();
    for at in [1_000 + 60, 1_000 + 120, 1_000 + 180] {
        core.tick(at);
        assert_eq!(
            appends_to_peer(&core.take_actions(), LEADER_A),
            0,
            "at {at}"
        );
    }
    // Heard again, it gets heartbeats as it lacks entries.
    core.vouch(1_000 + 190, |_, _| None, |_| Some(1_000 + 185));
    core.take_actions();
    core.tick(1_000 + 250);
    assert!(appends_to_peer(&core.take_actions(), LEADER_A) > 0);
}

#[test]
fn a_leader_that_hears_no_quorum_goes_on_sending() {
    let mut core = leader_of_two_with(|cfg| cfg.idle_heartbeats = false);
    core.take_actions();
    // Its host hears no one: it may be the one gone deaf, so A, behind,
    // still gets heartbeats.
    core.vouch(1_000 + 40, |_, _| None, |_| None);
    core.take_actions();
    core.tick(1_000 + 60);
    assert!(appends_to_peer(&core.take_actions(), LEADER_A) > 0);
}

#[test]
fn a_probed_follower_hears_its_idle_leader_at_once() {
    let mut core = idle_leader_of_three();
    core.tick(1_000 + 60);
    assert!(appends(&core.take_actions()).is_empty());
    core.probe(LEADER_A);
    assert_eq!(appends(&core.take_actions()), vec![(LEADER_A, 1)]);
    // Until it answers, it gets a heartbeat each round.
    core.tick(1_000 + 120);
    assert_eq!(appends_to_peer(&core.take_actions(), LEADER_A), 1);
    core.receive(LEADER_A, acked(1, 1));
    core.take_actions();
    core.tick(1_000 + 180);
    assert!(appends(&core.take_actions()).is_empty());
}

#[test]
fn a_lost_timeout_now_to_an_idle_target_is_sent_again() {
    let mut core = idle_leader_of_three();
    core.transfer_leadership(Some(LEADER_A));
    assert!(sent(&core.take_actions()).contains(&Message::TimeoutNow { term: 1 }));
    // Lost: the target is heartbeated, and its answer brings it again.
    core.tick(1_000 + 60);
    assert_eq!(appends_to_peer(&core.take_actions(), LEADER_A), 1);
    core.receive(LEADER_A, acked(1, 1));
    assert!(sent(&core.take_actions()).contains(&Message::TimeoutNow { term: 1 }));
}

#[test]
fn an_idle_leader_still_sends_heartbeats_to_a_lagging_follower() {
    let mut core = leader_of_two_with(|cfg| cfg.idle_heartbeats = false);
    // A holds nothing yet: each round still reaches it.
    core.take_actions();
    core.tick(1_000 + 50);
    assert!(appends(&core.take_actions()).contains(&(LEADER_A, 0)));
    core.tick(1_000 + 100);
    assert!(!appends(&core.take_actions()).is_empty());
}

#[test]
fn a_read_still_takes_a_round_of_heartbeats() {
    let mut core = leader_of_two_with(|cfg| cfg.idle_heartbeats = false);
    core.receive(LEADER_A, matched(1));
    core.take_actions();
    core.read_index(9, None);
    assert_eq!(appends(&core.take_actions()), vec![(LEADER_A, 1)]);
}

#[test]
fn a_members_pre_vote_draws_a_heartbeat_from_its_leader() {
    let mut core = leader_of_two_with(|cfg| cfg.idle_heartbeats = false);
    core.receive(LEADER_A, matched(1));
    core.take_actions();
    core.receive(
        LEADER_A,
        Message::PreVote {
            next_term: 2,
            candidate: LEADER_A,
            last_index: 1,
            last_term: 1,
        },
    );
    let actions = core.take_actions();
    assert!(
        sent(&actions)
            .iter()
            .any(|message| matches!(message, Message::PreVoteAnswer { granted: false, .. }))
    );
    assert_eq!(appends(&actions), vec![(LEADER_A, 1)]);
    assert_eq!(core.role(), Role::Leader);
}

#[test]
fn a_vouched_leader_moves_the_deadline_and_holds_stickiness() {
    let mut core = follower(1, &[1], 1);
    core.receive(LEADER_A, append(1, LEADER_A, (1, 1), 1, &[]));
    core.take_actions();
    // Vouched for at 1,000: no pre-vote before 1,150, and another node's
    // is refused.
    core.heard_leader_at(1_000);
    assert!(core.next_deadline() >= 1_150);
    core.tick(1_100);
    assert!(sent(&core.take_actions()).is_empty());
    core.receive(
        LEADER_B,
        Message::PreVote {
            next_term: 2,
            candidate: LEADER_B,
            last_index: 1,
            last_term: 1,
        },
    );
    assert!(
        sent(&core.take_actions())
            .iter()
            .any(|message| matches!(message, Message::PreVoteAnswer { granted: false, .. }))
    );
    // An older vouch changes nothing; with none after, the deadline lapses.
    core.heard_leader_at(900);
    core.tick(1_300);
    assert!(
        sent(&core.take_actions())
            .iter()
            .any(|message| matches!(message, Message::PreVote { .. }))
    );
}

#[test]
fn a_solo_group_with_idle_heartbeats_off_arms_no_timer() {
    let mut cfg = config();
    cfg.members = vec![ME];
    cfg.idle_heartbeats = false;
    let mut core = Core::new(cfg, Recovered::default(), 0, 5);
    core.take_actions();
    core.tick(1_000);
    let actions = core.take_actions();
    persist(&mut core, &writes(&actions).last().unwrap().clone());
    core.take_actions();
    assert_eq!(core.role(), Role::Leader);
    assert_eq!(core.next_deadline(), u64::MAX);
}

const JOINER: u16 = 4;

/// Make `core` (pre-vote off) lead: its deadline lapses at `at`, A grants
/// its vote, and A acknowledges its no-op. The actions after.
fn lead_with_a(core: &mut Core<u16>, at: u64) -> Vec<Action<u16>> {
    core.tick(at);
    let vote = writes(&core.take_actions()).last().unwrap().clone();
    persist(core, &vote);
    let term = core.status().current_term;
    core.receive(
        LEADER_A,
        Message::VoteAnswer {
            term,
            granted: true,
        },
    );
    assert_eq!(core.role(), Role::Leader);
    let no_op = writes(&core.take_actions()).last().unwrap().clone();
    persist(core, &no_op);
    let last = core.status().last_log_index;
    core.receive(
        LEADER_A,
        Message::AppendAnswer {
            term,
            round: 0,
            commit: 0,
            result: AppendResult::Matched { matched: last },
        },
    );
    core.take_actions()
}

/// The final configurations `actions` append.
fn finals(actions: &[Action<u16>]) -> Vec<Vec<u16>> {
    writes(actions)
        .iter()
        .flat_map(|write| write.entries.iter())
        .filter_map(|entry| match &entry.kind {
            EntryKind::ConfigChange {
                joint_old: None,
                members,
            } => Some(members.clone()),
            _ => None,
        })
        .collect()
}

/// B replaced by the joiner.
fn joint() -> (Vec<u16>, Vec<u16>) {
    (vec![ME, LEADER_A, JOINER], vec![ME, LEADER_A, LEADER_B])
}

#[test]
fn a_replica_given_a_joint_snapshot_finalizes_it_when_it_leads() {
    let mut cfg = config();
    cfg.pre_vote = false;
    let mut core = Core::new(cfg, Recovered::default(), 0, 5);
    core.take_actions();
    let (members, old) = joint();
    core.snapshot_installed(
        20,
        1,
        Some(SnapshotConfiguration {
            members: members.clone(),
            joint_old: Some(old),
            index: 15,
        }),
    );
    core.take_actions();
    assert!(core.status().joint_old.is_some());
    let actions = lead_with_a(&mut core, 1_000);
    assert_eq!(finals(&actions), vec![members]);
    assert!(core.status().retirement_final_index.is_some(), "B retires");
}

#[test]
fn recovery_takes_the_later_of_the_record_and_the_logs_start() {
    let (members, old) = joint();
    let recovered = Recovered {
        meta: Meta {
            current_term: 2,
            voted_for: None,
            commit_index: 192,
            snap_last_index: 192,
            snap_last_term: 2,
        },
        entries: Vec::new(),
        // A crash lost the record's update to the final configuration,
        // which a compaction had already made the log's start.
        active_config: Some(ActiveConfigRecord {
            log_index: Some(190),
            current: members.clone(),
            joint_old: Some(old),
        }),
        log_start_config: Some(ActiveConfigRecord {
            log_index: Some(192),
            current: members.clone(),
            joint_old: None,
        }),
        applied: 192,
        vote_floor: None,
    };
    let core = Core::new(config(), recovered, 0, 5);
    let status = core.status();
    assert_eq!(
        (status.members, status.joint_old, status.active_config_index),
        (members, None, Some(192))
    );
}

#[test]
fn a_recovered_joint_configuration_is_finalized_by_its_leader() {
    let (members, old) = joint();
    let recovered = Recovered {
        meta: Meta {
            current_term: 1,
            voted_for: None,
            commit_index: 20,
            snap_last_index: 20,
            snap_last_term: 1,
        },
        entries: Vec::new(),
        active_config: Some(ActiveConfigRecord {
            log_index: Some(15),
            current: members.clone(),
            joint_old: Some(old),
        }),
        log_start_config: None,
        applied: 20,
        vote_floor: None,
    };
    let mut cfg = config();
    cfg.pre_vote = false;
    let mut core = Core::new(cfg, recovered, 0, 5);
    core.take_actions();
    let actions = lead_with_a(&mut core, 1_000);
    assert_eq!(finals(&actions), vec![members]);
}

#[test]
fn a_wiped_replica_votes_only_for_a_log_reaching_what_it_held() {
    // Its log and state were wiped; it last held up to index 40, term 3.
    let recovered = Recovered {
        meta: Meta {
            current_term: 3,
            ..Meta::default()
        },
        vote_floor: Some((40, 3)),
        ..Recovered::default()
    };
    let mut core = Core::new(config(), recovered, 0, 7);
    core.take_actions();
    let refused = |actions: &[Action<u16>]| {
        sent(actions).iter().any(|message| {
            matches!(
                message,
                Message::PreVoteAnswer { granted: false, .. }
                    | Message::VoteAnswer { granted: false, .. }
            )
        })
    };
    // A candidate whose log ends behind it, though ahead of its empty
    // log, is refused both.
    core.receive(
        LEADER_A,
        Message::PreVote {
            next_term: 4,
            candidate: LEADER_A,
            last_index: 30,
            last_term: 3,
        },
    );
    assert!(refused(&core.take_actions()));
    core.receive(
        LEADER_A,
        Message::Vote {
            term: 4,
            candidate: LEADER_A,
            last_index: 30,
            last_term: 3,
        },
    );
    // The refusal leaves once the term it adopted is durable.
    let term = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &term);
    assert!(refused(&core.take_actions()));
    // One whose log reaches it gets the vote.
    core.receive(
        LEADER_B,
        Message::Vote {
            term: 5,
            candidate: LEADER_B,
            last_index: 40,
            last_term: 3,
        },
    );
    let vote = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &vote);
    assert!(sent(&core.take_actions()).contains(&Message::VoteAnswer {
        term: 5,
        granted: true,
    }));
}

#[test]
fn a_leader_whose_appends_go_unanswered_steps_down_though_the_node_is_heard() {
    let mut core = leader_of_two_with(|cfg| {
        cfg.idle_heartbeats = false;
        cfg.resend_timeout_ms = 100;
    });
    core.receive(LEADER_A, acked(1, 1));
    core.take_actions();
    // Idle and caught up, A's node heard is enough for check-quorum.
    core.vouch(1_000 + 250, |_, _| None, |_| Some(1_000 + 240));
    core.tick(1_000 + 310);
    core.take_actions();
    assert_eq!(core.role(), Role::Leader);
    // An entry A never answers for: its node's pair heartbeat counts while
    // A answered lately, then no more, and a window deposes the leader.
    core.propose(1, vec![1]);
    let write = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &write);
    core.take_actions();
    // Patience here is three election timeouts: 900 ms.
    core.vouch(1_000 + 890, |_, _| None, |_| Some(1_000 + 880));
    core.tick(1_000 + 910);
    core.take_actions();
    assert_eq!(core.role(), Role::Leader, "A answered at 1,000");
    core.vouch(1_000 + 1_190, |_, _| None, |_| Some(1_000 + 1_180));
    core.tick(1_000 + 1_210);
    core.take_actions();
    assert_eq!(core.role(), Role::Follower);
}

fn compact_bounds(actions: &[Action<u16>]) -> Vec<u64> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::CompactBound { through, .. } => Some(*through),
            _ => None,
        })
        .collect()
}

/// A log of large entries makes a compaction due on its bytes before its
/// length, and the tail a compaction keeps is bounded in bytes too.
#[test]
fn large_entries_make_a_compaction_due_by_their_bytes() {
    let mut cfg = config();
    cfg.compact_hysteresis = 1_000;
    cfg.compact_bytes = 1_000;
    // Each entry costs 300 bytes as the cache counts it: 64 beyond its
    // payload.
    let entries = (1..=8)
        .map(|index| LogEntry::data(index, 1, vec![0; 236]))
        .collect();
    let recovered = Recovered {
        meta: Meta {
            current_term: 1,
            voted_for: None,
            commit_index: 8,
            snap_last_index: 0,
            snap_last_term: 0,
        },
        entries,
        ..Recovered::default()
    };
    let mut core = Core::new(cfg, recovered, 0, 7);
    core.take_actions();
    core.durably_applied(3);
    assert!(compact_bounds(&core.take_actions()).is_empty(), "900 bytes");
    core.durably_applied(4);
    assert_eq!(compact_bounds(&core.take_actions()), [4]);
    // Entries 3 and 4 take 600 bytes; 2 through 4 more than 700.
    let point = core.compaction_point(4, 10, 700);
    assert_eq!(point, 2);
    core.compacted(point);
    core.durably_applied(5);
    assert!(
        compact_bounds(&core.take_actions()).is_empty(),
        "the tail and entry 5 take 900 bytes"
    );
    core.durably_applied(6);
    assert_eq!(compact_bounds(&core.take_actions()), [6]);
    // The tail's entry count bounds it as well.
    assert_eq!(core.compaction_point(6, 1, 700), 5);
}

/// The read answers in `actions`, as (token, result).
fn reads(actions: &[Action<u16>]) -> Vec<(u64, Result<u64, ReadIndexError>)> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Answer(Answer::ReadIndex { token, result }) => Some((*token, *result)),
            _ => None,
        })
        .collect()
}

/// An answer, in heartbeat `round`, that the peer holds through `matched`.
fn matched_in(round: u64, matched: u64) -> Message<u16> {
    Message::AppendAnswer {
        term: 1,
        round,
        commit: 0,
        result: AppendResult::Matched { matched },
    }
}

/// A read resolves only on answers to a round sent after it was asked: an
/// answer to an earlier round proves leadership only as of then, and a
/// newer leader may have committed since.
#[test]
fn read_index_ignores_answers_to_heartbeats_sent_before_it() {
    let mut core = idle_leader_of_three();
    core.read_index(1, None);
    let [(_, first)] = commits_to(&core.take_actions(), LEADER_A)[..] else {
        panic!("one heartbeat to A");
    };
    core.read_index(2, None);
    let [(_, second)] = commits_to(&core.take_actions(), LEADER_A)[..] else {
        panic!("one heartbeat to A");
    };
    // Both answers to the first round land after the second read was asked.
    for peer in [LEADER_A, LEADER_B] {
        core.receive(peer, matched_in(first, 1));
    }
    assert_eq!(reads(&core.take_actions()), [(1, Ok(1))]);
    core.receive(LEADER_A, matched_in(second, 1));
    assert_eq!(reads(&core.take_actions()), [(2, Ok(1))]);
}

#[test]
fn read_index_returns_backpressure_when_queue_full() {
    let mut core = leader_of_two_with(|cfg| cfg.max_pending_reads = 2);
    let mut actions = Vec::new();
    for token in 1..=3 {
        core.read_index(token, None);
        actions.extend(core.take_actions());
    }
    assert_eq!(reads(&actions), [(3, Err(ReadIndexError::Backpressure))]);
    // A answers the latest round: the queue drains, and takes reads again.
    let round = commits_to(&actions, LEADER_A).last().unwrap().1;
    core.receive(LEADER_A, matched_in(round, 1));
    assert_eq!(reads(&core.take_actions()), [(1, Ok(1)), (2, Ok(1))]);
    core.read_index(4, None);
    assert!(reads(&core.take_actions()).is_empty());
}

/// A leader cut off from its group steps down at check-quorum, and answers
/// every read it holds that it stepped down.
#[test]
fn read_index_returns_leader_stepped_on_partition_step_down() {
    let mut core = leader_of_two();
    core.read_index(1, None);
    core.take_actions();
    core.tick(1_000 + 310);
    let actions = core.take_actions();
    assert_eq!(core.role(), Role::Follower);
    assert_eq!(reads(&actions), [(1, Err(ReadIndexError::LeaderStepped))]);
}

#[test]
fn pre_candidate_reverts_to_follower_after_consecutive_misses() {
    let mut cfg = config();
    cfg.pre_candidate_misses_before_revert = 2;
    let mut core = Core::new(cfg, Recovered::default(), 0, 5);
    // No pre-vote is ever answered.
    let mut roles = Vec::new();
    for _ in 0..3 {
        core.tick(core.next_deadline());
        core.take_actions();
        roles.push(core.role());
    }
    assert_eq!(
        roles,
        [Role::PreCandidate, Role::PreCandidate, Role::Follower]
    );
    assert_eq!(core.status().current_term, 0);
}

/// Any answer at a higher term deposes a leader, which adopts the term
/// durably.
#[test]
fn leader_steps_down_on_higher_term_append_response() {
    let mut core = leader_of_two();
    core.receive(
        LEADER_A,
        Message::AppendAnswer {
            term: 99,
            round: 1,
            commit: 0,
            result: AppendResult::Rejected {
                rejected: 0,
                last_index: 0,
                conflict_term: 0,
                conflict_first: 0,
            },
        },
    );
    let actions = core.take_actions();
    assert_eq!(
        (core.role(), core.status().current_term),
        (Role::Follower, 99)
    );
    let write = writes(&actions).last().expect("the term's write").clone();
    assert!(write.sync);
    assert_eq!(write.meta.map(|meta| meta.current_term), Some(99));
}

#[test]
fn candidate_steps_down_on_higher_term_vote_response() {
    let mut cfg = config();
    cfg.pre_vote = false;
    let mut core = Core::new(cfg, Recovered::default(), 0, 5);
    core.tick(1_000);
    core.take_actions();
    assert_eq!(core.role(), Role::Candidate);
    core.receive(
        LEADER_A,
        Message::VoteAnswer {
            term: 99,
            granted: false,
        },
    );
    core.take_actions();
    assert_eq!(
        (core.role(), core.status().current_term),
        (Role::Follower, 99)
    );
}

/// A membership change starts only at a leader, with members, and while no
/// other change is in progress.
#[test]
fn change_membership_is_refused_off_a_leader_empty_or_in_progress() {
    let change = |core: &mut Core<u16>, token, members| {
        core.change_membership(token, members);
        core.take_actions()
            .into_iter()
            .find_map(|action| match action {
                Action::Answer(Answer::ChangeMembership { result, .. }) => Some(result),
                _ => None,
            })
            .expect("an answer")
    };
    let mut not_leader = follower(1, &[1], 1);
    assert_eq!(
        change(&mut not_leader, 1, vec![ME, LEADER_A]),
        Err(ChangeMembershipError::NotLeader)
    );
    let mut leader = leader_of_two();
    assert_eq!(
        change(&mut leader, 2, Vec::new()),
        Err(ChangeMembershipError::EmptyConfig)
    );
    assert!(change(&mut leader, 3, vec![ME, LEADER_A, LEADER_B]).is_ok());
    assert_eq!(
        change(&mut leader, 4, vec![ME, LEADER_A]),
        Err(ChangeMembershipError::InProgress)
    );
}

/// A replayed append, shorter than one already taken, leaves the log as it
/// is: every entry it carries is already there.
#[test]
fn stale_append_entries_does_not_regress_follower_log() {
    let mut core = follower(5, &[], 0);
    let entries = [(1, 5), (2, 5), (3, 5)];
    core.receive(LEADER_A, append(5, LEADER_A, (0, 0), 0, &entries));
    core.take_actions();
    core.receive(LEADER_A, append(5, LEADER_A, (0, 0), 0, &entries[..2]));
    let actions = core.take_actions();
    assert!(
        writes(&actions)
            .iter()
            .all(|write| write.truncate_after.is_none()),
        "{actions:?}"
    );
    assert_eq!(core.status().last_log_index, 3);
}

fn record(
    log_index: Option<u64>,
    current: Vec<u16>,
    joint_old: Option<Vec<u16>>,
) -> ActiveConfigRecord<u16> {
    ActiveConfigRecord {
        log_index,
        current,
        joint_old,
    }
}

/// A truncation that removes the entry the membership record came from
/// writes the record again: a restart must not adopt a configuration no
/// entry backs.
#[test]
fn truncate_dropping_originating_config_change_invalidates_persisted_view() {
    let grown = vec![ME, LEADER_A, LEADER_B, JOINER];
    let recovered = Recovered {
        meta: Meta {
            current_term: 1,
            ..Meta::default()
        },
        entries: vec![LogEntry::config_change(1, 1, None, grown.clone())],
        active_config: Some(record(Some(1), grown.clone(), None)),
        ..Recovered::default()
    };
    let mut core = Core::new(config(), recovered, 0, 7);
    core.take_actions();
    assert_eq!(core.status().members, grown);
    // A leader of term 5 replaces entry 1 with data.
    core.receive(LEADER_A, append(5, LEADER_A, (0, 0), 0, &[(1, 5)]));
    let records: Vec<_> = writes(&core.take_actions())
        .into_iter()
        .filter_map(|write| write.active_config)
        .collect();
    let members = vec![ME, LEADER_A, LEADER_B];
    assert_eq!(records, [record(Some(0), members.clone(), None)]);
    assert_eq!(core.status().members, members);
}

/// A snapshot switch records the membership in effect at the snapshot: the
/// one it carries; else the replica's, with its entry's index only if that
/// entry committed, since an uncommitted one may yet be replaced.
#[test]
fn a_snapshot_switch_records_the_membership_in_effect() {
    let three = vec![ME, LEADER_A, LEADER_B];
    let mut cfg = config();
    cfg.members = vec![ME];
    // A configuration committed at 5, which the switch compacts away.
    let committed = Recovered {
        meta: Meta {
            current_term: 1,
            voted_for: None,
            commit_index: 6,
            snap_last_index: 4,
            snap_last_term: 1,
        },
        entries: vec![
            LogEntry::config_change(5, 1, None, three.clone()),
            LogEntry::data(6, 1, vec![]),
        ],
        active_config: Some(record(Some(5), three.clone(), None)),
        applied: 6,
        ..Recovered::default()
    };
    let core = Core::new(cfg.clone(), committed, 0, 7);
    let switch = core.snapshot_switch(10, 5, None);
    assert_eq!(switch.active_config, record(Some(5), three.clone(), None));
    assert!(switch.meta.commit_index >= 10);
    // A fresh replica takes the snapshot's own.
    let fresh = Core::new(cfg, Recovered::default(), 0, 7);
    let carried = SnapshotConfiguration {
        members: three.clone(),
        joint_old: None,
        index: 37,
    };
    let switch = fresh.snapshot_switch(100, 6, Some(&carried));
    assert_eq!(switch.active_config, record(Some(37), three, None));
    assert!(switch.meta.commit_index >= 100);
    // A joint configuration appended at 5, committed only through 2.
    let speculative = Recovered {
        meta: Meta {
            current_term: 3,
            commit_index: 2,
            ..Meta::default()
        },
        entries: (1..=4)
            .map(|index| LogEntry::data(index, 3, vec![]))
            .chain([LogEntry::config_change(
                5,
                3,
                Some(vec![LEADER_A]),
                vec![ME, LEADER_A],
            )])
            .collect(),
        active_config: Some(record(Some(5), vec![ME, LEADER_A], Some(vec![LEADER_A]))),
        applied: 2,
        ..Recovered::default()
    };
    let core = Core::new(config(), speculative, 0, 7);
    let switch = core.snapshot_switch(10, 3, None);
    assert_eq!(
        switch.active_config,
        record(None, vec![ME, LEADER_A], Some(vec![LEADER_A]))
    );
    assert_eq!(switch.meta.commit_index, 10);
}
