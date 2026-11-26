//! Who a replica takes messages from, and what it refuses whoever sends
//! it: an append that would replace a committed entry, a second leader of
//! one term, a term without a successor, and numbers past its own log.

use vraft::core::{Core, Recovered};
use vraft::{AppendResult, Config, Message, Role};

use crate::common::{
    LEADER_A, LEADER_B, ME, acked_at, append, config, follower, leader_of_two, matched,
    persist_last, pre_vote, recovered, sent, vote, vote_answer, writes,
};

/// A node the host authenticated that is in no configuration this
/// replica knows.
const OUTSIDER: u16 = 9;

/// A follower at term 1 holding three entries of term 1, committed and
/// applied, that heard no leader since it started.
fn committed_follower() -> Core<u16> {
    follower(1, &[1, 1, 1], 3)
}

/// `committed_follower`, following A at term 1.
fn following_a() -> Core<u16> {
    let mut core = committed_follower();
    core.receive(LEADER_A, append(1, LEADER_A, (3, 1), 3, &[]));
    core.take_actions();
    assert_eq!(core.status().leader_hint, Some(LEADER_A));
    core
}

#[test]
fn an_append_never_replaces_a_committed_entry() {
    for from in [LEADER_A, OUTSIDER] {
        let mut core = committed_follower();
        let entries: Vec<(u64, u64)> = (1..=4).map(|index| (index, 2)).collect();
        core.receive(from, append(2, from, (0, 0), 4, &entries));
        let actions = core.take_actions();
        for write in writes(&actions) {
            assert!(
                write.truncate_after.is_none_or(|after| after >= 3),
                "a write cuts the log after {:?}, below the commit index 3",
                write.truncate_after
            );
        }
        let status = core.status();
        assert_eq!(
            (status.current_term, status.leader_hint, status.commit_index),
            (1, None, 3),
            "it took the append of {from}"
        );
        assert_eq!(status.refused, 1);
        assert!(sent(&actions).is_empty(), "it answered {actions:?}");
    }
}

/// A leader of a later term that holds the committed entries is taken.
#[test]
fn an_append_past_the_commit_is_taken() {
    let mut core = committed_follower();
    core.receive(LEADER_A, append(2, LEADER_A, (2, 1), 4, &[(3, 1), (4, 2)]));
    let actions = core.take_actions();
    persist_last(&mut core, &actions);
    let status = core.status();
    assert_eq!((status.current_term, status.last_log_index), (2, 4));
    assert_eq!(status.leader_hint, Some(LEADER_A));
}

#[test]
fn a_term_has_one_leader() {
    // A leader at term 1 keeps leading against another naming itself
    // leader of term 1.
    let mut core = leader_of_two();
    core.receive(OUTSIDER, append(1, OUTSIDER, (0, 0), 0, &[]));
    core.take_actions();
    assert_eq!(core.role(), Role::Leader);
    // A follower of A at term 1 keeps following A.
    let mut core = following_a();
    core.receive(LEADER_B, append(1, LEADER_B, (3, 1), 3, &[(4, 1)]));
    let actions = core.take_actions();
    assert_eq!(core.status().leader_hint, Some(LEADER_A));
    assert_eq!(core.status().last_log_index, 3);
    assert!(writes(&actions).is_empty());
    assert_eq!(core.status().refused, 1);
}

/// A node outside the configuration asks for votes: while the replica
/// hears a leader it is ignored, and the term stays.
#[test]
fn an_outsider_does_not_depose_a_live_leader() {
    let vote = vote(7, OUTSIDER, (100, 6));
    let mut leader = leader_of_two();
    leader.receive(OUTSIDER, vote.clone());
    leader.take_actions();
    assert_eq!(
        (leader.role(), leader.status().current_term),
        (Role::Leader, 1)
    );
    let mut core = following_a();
    core.receive(OUTSIDER, vote);
    let actions = core.take_actions();
    assert_eq!(core.status().current_term, 1);
    assert_eq!(core.status().voted_for, None);
    assert!(sent(&actions).is_empty());
}

/// A replica that lags a membership change may not know a member that
/// campaigns, and its vote may be the one the group needs: with no leader
/// to hear, it answers.
#[test]
fn a_replica_with_no_leader_answers_a_candidate_it_does_not_know() {
    let mut core = committed_follower();
    core.receive(OUTSIDER, vote(2, OUTSIDER, (5, 1)));
    let actions = core.take_actions();
    persist_last(&mut core, &actions);
    assert!(sent(&core.take_actions()).contains(&vote_answer(2, true)));
}

/// A replica added to a group starts from the members the group was
/// created with, which do not name it: until a configuration naming it
/// reaches it, every node a later change added is unknown to it, and it
/// still answers their vote requests while no leader is heard.
#[test]
fn a_replica_not_yet_in_its_configuration_answers_the_members_it_does_not_know() {
    let joiner = 4;
    let mut core = Core::new(
        Config::new(joiner, vec![ME, LEADER_A, LEADER_B]),
        Recovered::default(),
        0,
        3,
    );
    core.take_actions();
    core.receive(OUTSIDER, vote(3, OUTSIDER, (5, 2)));
    let actions = core.take_actions();
    persist_last(&mut core, &actions);
    assert!(sent(&core.take_actions()).contains(&vote_answer(3, true)));
    // It never campaigns: it is no member as it knows them.
    core.tick(10_000);
    assert!(!core.campaigning());
}

/// Answers count from members only, and an outsider's answer at a higher
/// term moves no term: nothing this replica asked an outsider needs it.
#[test]
fn an_outsiders_answers_change_nothing() {
    let answers = [
        vote_answer(5, false),
        Message::PreVoteAnswer {
            term: 5,
            next_term: 6,
            granted: false,
        },
        acked_at(5, 0, 0, 0),
    ];
    for answer in answers {
        let mut core = leader_of_two();
        core.receive(OUTSIDER, answer.clone());
        core.take_actions();
        assert_eq!(
            (core.role(), core.status().current_term),
            (Role::Leader, 1),
            "{answer:?}"
        );
    }
}

/// A term without a successor is refused from anyone: taken, it would
/// end every election after it.
#[test]
fn a_term_without_a_successor_is_refused() {
    let mut core = committed_follower();
    core.receive(LEADER_A, vote_answer(u64::MAX, false));
    core.receive(LEADER_A, append(u64::MAX, LEADER_A, (3, 1), 3, &[]));
    core.receive(LEADER_A, pre_vote(u64::MAX, LEADER_A, (9, 1)));
    let actions = core.take_actions();
    assert!(sent(&actions).is_empty(), "{actions:?}");
    assert_eq!(core.status().current_term, 1);
    assert_eq!(core.status().refused, 3);
    // The election timer fires as usual.
    core.tick(10_000);
    assert!(core.campaigning());
}

/// A replica whose store holds the last term there is (written before
/// the refusal above) never campaigns, and never panics.
#[test]
fn a_replica_at_the_last_term_stays_a_follower() {
    for pre_vote in [true, false] {
        let mut cfg = config();
        cfg.pre_vote = pre_vote;
        let mut core = Core::new(cfg, recovered(u64::MAX, 0, Vec::new()), 0, 3);
        for at in 1..=5 {
            core.tick(at * 1_000);
            core.take_actions();
        }
        assert_eq!(core.role(), Role::Follower);
        assert_eq!(core.status().current_term, u64::MAX);
    }
    // A group of one too.
    let mut cfg = config();
    cfg.members = vec![ME];
    let mut core = Core::new(cfg, recovered(u64::MAX, 0, Vec::new()), 0, 3);
    core.tick(0);
    core.take_actions();
    assert_eq!(core.role(), Role::Follower);
}

/// A member's claim past any index does not panic its leader, and counts
/// for no more than the leader's own log.
#[test]
fn an_acknowledgement_past_the_log_counts_for_the_log() {
    let mut core = leader_of_two();
    core.receive(LEADER_A, matched(u64::MAX));
    core.take_actions();
    assert_eq!(
        core.match_index(LEADER_A),
        Some(core.status().last_log_index)
    );
    let mut core = leader_of_two();
    core.receive(
        LEADER_A,
        Message::AppendAnswer {
            term: 1,
            round: u64::MAX,
            commit: u64::MAX,
            result: AppendResult::Rejected {
                rejected: u64::MAX,
                last_index: u64::MAX,
                conflict_term: 0,
                conflict_first: u64::MAX,
            },
        },
    );
    core.take_actions();
    assert_eq!(core.role(), Role::Leader);
}

/// A follower whose leader fell silent for the election timeout's lower
/// end hears no leader: it answers a candidate it does not know, which a
/// change it lags may have made a member.
#[test]
fn a_follower_whose_leader_fell_silent_answers_a_candidate_it_does_not_know() {
    let mut core = following_a();
    let vote = vote(2, OUTSIDER, (5, 1));
    core.receive(OUTSIDER, vote.clone());
    core.take_actions();
    assert_eq!(core.status().current_term, 1, "a leader is heard");
    let low = config().election_timeout_ms.0;
    core.defer_campaign(low, u64::MAX);
    core.receive(OUTSIDER, vote);
    let actions = core.take_actions();
    persist_last(&mut core, &actions);
    assert!(sent(&core.take_actions()).contains(&vote_answer(2, true)));
}

/// A term far past this replica's is refused: one message cannot take a
/// group to the last term there is.
#[test]
fn a_term_far_past_the_replicas_is_refused() {
    let mut core = following_a();
    core.receive(LEADER_A, append(u64::MAX - 1, LEADER_A, (3, 1), 3, &[]));
    core.receive(LEADER_B, pre_vote(1 << 40, LEADER_B, (9, 1)));
    let actions = core.take_actions();
    assert!(sent(&actions).is_empty(), "{actions:?}");
    assert_eq!(core.status().current_term, 1);
    assert_eq!(core.status().refused, 2);
}

/// A replica one term short of the last campaigns into it, and then, with
/// no term to follow, stays a follower.
#[test]
fn a_replica_that_reaches_the_last_term_stops_campaigning() {
    let mut cfg = config();
    cfg.members = vec![ME];
    let mut core = Core::new(cfg, recovered(u64::MAX - 1, 0, Vec::new()), 0, 3);
    core.tick(0);
    crate::common::persist_all(&mut core);
    assert_eq!(core.role(), Role::Leader);
    assert_eq!(core.status().current_term, u64::MAX);
    // Deposed by nothing it takes, it leads on; a replica of three at the
    // last term, after its timeout, is a follower.
    let mut cfg = config();
    cfg.pre_vote = false;
    let mut core = Core::new(cfg, recovered(u64::MAX - 1, 0, Vec::new()), 0, 3);
    core.tick(1_000);
    crate::common::persist_all(&mut core);
    assert_eq!(core.role(), Role::Candidate);
    core.tick(10_000);
    core.take_actions();
    assert_eq!(core.role(), Role::Follower);
    assert!(!core.campaign_due(20_000));
}
