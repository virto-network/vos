//! A leader: what it sends, commits and reads, how it hands over, and
//! when it, or a candidate, steps down.

use vos_raft::core::{Action, Answer, Core, ProposeError, ReadIndexError, Recovered};
use vos_raft::{AppendResult, LogEntry, Message, Role};

use crate::common::{
    LEADER_A, LEADER_B, ME, append, appends, committed, config, entries_to, follower,
    idle_leader_of_three, lead, leader_of_two, leader_of_two_with, loads, matched, persist,
    persist_into, recovered, sent, writes,
};

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

#[test]
fn a_leader_sends_each_peer_a_commit_it_has_acknowledged() {
    // A three-member group led by ME; peers A and B.
    let mut cfg = config();
    cfg.pre_vote = false;
    let mut core = Core::new(cfg, Recovered::default(), 0, 5);
    core.take_actions();
    lead(&mut core, 1_000);
    for n in 0..4u8 {
        core.propose(u64::from(n), vec![n]);
    }
    let write = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &write);
    // A holds everything, B only through 2: the leader commits 5.
    core.receive(LEADER_A, matched(5));
    core.receive(LEADER_B, matched(2));
    assert_eq!(committed(&core.take_actions()), Some(5));
    // Its next heartbeat tells B no more than B acknowledged.
    core.tick(1_000 + 60);
    let to_b: Vec<u64> = appends(&core.take_actions())
        .into_iter()
        .filter_map(|(to, commit, _)| (to == LEADER_B).then_some(commit))
        .collect();
    assert!(!to_b.is_empty());
    assert!(to_b.iter().all(|&commit| commit <= 2), "{to_b:?}");
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

#[test]
fn followers_learn_a_commit_at_once_without_a_heartbeat() {
    // A three-member group led by ME; its no-op is in flight to A and B.
    let mut cfg = config();
    cfg.pre_vote = false;
    let mut core = Core::new(cfg, Recovered::default(), 0, 5);
    core.take_actions();
    let actions = lead(&mut core, 1_000);
    persist(&mut core, writes(&actions).last().unwrap());
    core.take_actions();
    // A holds the no-op: it commits, and A is told at once, in the round of
    // the leader's first heartbeat, opening none; B, with the no-op still
    // in flight, is not.
    core.receive(LEADER_A, matched(1));
    let actions = core.take_actions();
    assert_eq!(committed(&actions), Some(1));
    assert_eq!(appends(&actions), [(LEADER_A, 1, 1)]);
    // B's answer frees its slot: B learns the commit too, once.
    core.receive(LEADER_B, matched(1));
    assert_eq!(appends(&core.take_actions()), [(LEADER_B, 1, 1)]);
    core.receive(LEADER_B, matched(1));
    assert!(appends(&core.take_actions()).is_empty());
    // A later entry: its append carries the old commit, and the new one
    // follows each acknowledgement, never above what the peer holds.
    core.propose(1, vec![1]);
    let write = writes(&core.take_actions()).last().unwrap().clone();
    persist(&mut core, &write);
    core.take_actions();
    core.receive(LEADER_A, matched(2));
    let actions = core.take_actions();
    assert_eq!(committed(&actions), Some(2));
    assert_eq!(appends(&actions), [(LEADER_A, 2, 1)]);
}

#[test]
fn a_proposal_goes_out_at_once_unless_an_append_is_in_flight() {
    let mut core = leader_of_two();
    // The no-op is in flight to A: a proposal waits for its answer.
    core.propose(1, vec![1]);
    let actions = core.take_actions();
    assert!(entries_to(&actions, LEADER_A).is_empty(), "{actions:?}");
    // A acknowledges the no-op: the proposal follows at once, without
    // waiting for a heartbeat.
    core.receive(LEADER_A, matched(1));
    assert_eq!(entries_to(&core.take_actions(), LEADER_A), [(1, vec![2])]);
    // With the slot free again, a proposal is sent as it is made.
    core.receive(LEADER_A, matched(2));
    core.take_actions();
    core.propose(2, vec![2]);
    assert_eq!(entries_to(&core.take_actions(), LEADER_A), [(2, vec![3])]);
}

#[test]
fn an_append_carries_at_most_its_byte_cap() {
    let mut cfg = config();
    cfg.members = vec![ME, LEADER_A];
    cfg.pre_vote = false;
    cfg.max_append_bytes = 100;
    let mut core = Core::new(cfg, Recovered::default(), 0, 5);
    core.take_actions();
    lead(&mut core, 1_000);
    for n in 0..3u8 {
        core.propose(u64::from(n), vec![n; 60]);
    }
    core.take_actions();
    // Each 60-byte entry fills most of the cap: one entry per append.
    for next in 2..=4 {
        core.receive(LEADER_A, matched(next - 1));
        assert_eq!(
            entries_to(&core.take_actions(), LEADER_A),
            [(next - 1, vec![next])]
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
    let mut core = Core::new(cfg, recovered(3, 3, entries), 0, 5);
    core.take_actions();
    let (probe, _) = entries_to(&lead(&mut core, 1_000), LEADER_A)[0].clone();
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
    let appends = entries_to(&core.take_actions(), LEADER_A);
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
    core.vouch(1_000 + 200, |_, _| None, |_| Some(1_000 + 200));
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
        core.vouch(now, |_, _| None, |_| Some(now));
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
    // The store: every entry the leader writes, made durable at once.
    let mut store = Vec::new();
    let actions = lead(&mut core, 1_000);
    persist_into(&mut store, &mut core, &actions);
    for n in 0..6u8 {
        core.propose(u64::from(n), vec![n]);
        let actions = core.take_actions();
        persist_into(&mut store, &mut core, &actions);
    }
    // A never answered the no-op; its slot frees after the resend timeout,
    // and what it lacks is no longer cached.
    core.tick(1_000 + 1_100);
    let mut actions = core.take_actions();
    let mut sent_to_a: Vec<u64> = Vec::new();
    for _ in 0..20 {
        for (_, entries) in entries_to(&actions, LEADER_A) {
            if let Some(&last) = entries.last() {
                sent_to_a.extend(entries);
                core.receive(LEADER_A, matched(last));
            }
        }
        for load in loads(&actions) {
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
    lead(&mut core, 1_000);
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
fn a_load_that_starts_late_sends_nothing() {
    let mut cfg = config();
    cfg.members = vec![ME, LEADER_A];
    cfg.pre_vote = false;
    cfg.cache_bytes = 1;
    cfg.check_quorum = false;
    let mut core = Core::new(cfg, Recovered::default(), 0, 5);
    core.take_actions();
    let mut store = Vec::new();
    let actions = lead(&mut core, 1_000);
    persist_into(&mut store, &mut core, &actions);
    for n in 0..4u8 {
        core.propose(u64::from(n), vec![n]);
        let actions = core.take_actions();
        persist_into(&mut store, &mut core, &actions);
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
    assert!(entries_to(&actions, LEADER_A).is_empty(), "{actions:?}");
    assert!(loads(&actions).is_empty(), "not reissued: {actions:?}");
}

/// A read resolves only on answers to a round sent after it was asked: an
/// answer to an earlier round proves leadership only as of then, and a
/// newer leader may have committed since.
#[test]
fn read_index_ignores_answers_to_heartbeats_sent_before_it() {
    let mut core = idle_leader_of_three();
    core.read_index(1, None);
    let [(LEADER_A, _, first), (LEADER_B, ..)] = appends(&core.take_actions())[..] else {
        panic!("one heartbeat to each");
    };
    core.read_index(2, None);
    let [(LEADER_A, _, second), (LEADER_B, ..)] = appends(&core.take_actions())[..] else {
        panic!("one heartbeat to each");
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
    let (_, _, round) = *appends(&actions).last().unwrap();
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
