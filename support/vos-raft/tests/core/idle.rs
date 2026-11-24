//! A group with idle heartbeats off: a leader sends nothing to members
//! caught up, and the hosts' pair heartbeats vouch for it instead.

use vos_raft::core::{Core, Recovered};
use vos_raft::{Message, Role};

use crate::common::{
    LEADER_A, LEADER_B, ME, acked, append, appends, config, entries_to, follower,
    idle_leader_of_three, leader_of_two_with, matched, persist, sent, writes,
};

/// An idle leader sends its follower the commit at once, and again each
/// round until the follower acknowledges it; then nothing until there is
/// something new.
#[test]
fn an_idle_leader_sends_nothing_once_its_follower_holds_the_commit() {
    let mut core = leader_of_two_with(|cfg| cfg.idle_heartbeats = false);
    core.receive(LEADER_A, matched(1));
    assert_eq!(appends(&core.take_actions()), [(LEADER_A, 1, 1)]);
    // The commit notice is lost: A never acknowledges commit 1, so the
    // idle leader's heartbeats carry it again.
    core.tick(1_000 + 60);
    assert_eq!(appends(&core.take_actions()), [(LEADER_A, 1, 2)]);
    core.receive(LEADER_A, acked(1, 1));
    core.take_actions();
    // Within check-quorum's window, nothing goes out, and the next
    // deadline is check-quorum's.
    core.vouch(1_000 + 60, |_, _| None, |_| Some(1_000 + 60));
    for at in (1_110..1_300).step_by(50) {
        core.tick(at);
        assert!(appends(&core.take_actions()).is_empty(), "at {at}");
    }
    assert_eq!(core.next_deadline(), 1_000 + 300);
    // A proposal goes out at once, and its commit after it.
    core.propose(1, vec![1]);
    let actions = core.take_actions();
    persist(&mut core, writes(&actions).last().unwrap());
    assert_eq!(appends(&actions), [(LEADER_A, 1, 3)]);
    core.receive(LEADER_A, matched(2));
    assert_eq!(appends(&core.take_actions()), [(LEADER_A, 2, 3)]);
}

#[test]
fn an_idle_leader_leaves_a_silent_member_without_heartbeats() {
    let mut core = idle_leader_of_three();
    // A falls behind, and its node has not been heard: no heartbeats to
    // it, while B, heard, keeps the quorum.
    core.propose(1, vec![1]);
    let actions = core.take_actions();
    persist(&mut core, writes(&actions).last().unwrap());
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
        assert!(
            entries_to(&core.take_actions(), LEADER_A).is_empty(),
            "at {at}"
        );
    }
    // Heard again, it gets heartbeats as it lacks entries.
    core.vouch(1_000 + 190, |_, _| None, |_| Some(1_000 + 185));
    core.take_actions();
    core.tick(1_000 + 250);
    assert!(!entries_to(&core.take_actions(), LEADER_A).is_empty());
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
    assert!(!entries_to(&core.take_actions(), LEADER_A).is_empty());
}

#[test]
fn a_probed_follower_hears_its_idle_leader_at_once() {
    let mut core = idle_leader_of_three();
    core.tick(1_000 + 60);
    assert!(appends(&core.take_actions()).is_empty());
    core.probe(LEADER_A);
    assert_eq!(appends(&core.take_actions()), [(LEADER_A, 1, 2)]);
    // Until it answers, it gets a heartbeat each round.
    core.tick(1_000 + 120);
    assert_eq!(entries_to(&core.take_actions(), LEADER_A).len(), 1);
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
    assert_eq!(entries_to(&core.take_actions(), LEADER_A).len(), 1);
    core.receive(LEADER_A, acked(1, 1));
    assert!(sent(&core.take_actions()).contains(&Message::TimeoutNow { term: 1 }));
}

#[test]
fn an_idle_leader_still_sends_heartbeats_to_a_lagging_follower() {
    let mut core = leader_of_two_with(|cfg| cfg.idle_heartbeats = false);
    // A holds nothing yet: each round still reaches it.
    core.take_actions();
    core.tick(1_000 + 50);
    assert!(appends(&core.take_actions()).contains(&(LEADER_A, 0, 2)));
    core.tick(1_000 + 100);
    assert!(!appends(&core.take_actions()).is_empty());
}

#[test]
fn a_read_still_takes_a_round_of_heartbeats() {
    let mut core = leader_of_two_with(|cfg| cfg.idle_heartbeats = false);
    core.receive(LEADER_A, matched(1));
    core.take_actions();
    core.read_index(9, None);
    assert_eq!(appends(&core.take_actions()), [(LEADER_A, 1, 2)]);
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
    assert_eq!(appends(&actions), [(LEADER_A, 1, 1)]);
    assert_eq!(core.role(), Role::Leader);
}

#[test]
fn a_vouched_leader_moves_the_deadline_and_holds_stickiness() {
    let mut core = follower(1, &[1], 1);
    core.receive(LEADER_A, append(1, LEADER_A, (1, 1), 1, &[]));
    core.take_actions();
    // Vouched for at 1,000: no pre-vote before 1,150, and another node's
    // is refused.
    core.vouch(1_000, |_, _| Some(1_000), |_| None);
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
    core.vouch(1_100, |_, _| Some(990), |_| None);
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
    persist(&mut core, writes(&actions).last().unwrap());
    core.take_actions();
    assert_eq!(core.role(), Role::Leader);
    assert_eq!(core.next_deadline(), u64::MAX);
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

#[test]
fn a_follower_is_quiescent_while_its_leader_is_vouched_for() {
    let mut core = follower(1, &[1], 1);
    assert!(!core.quiescent(0), "no leader heard yet");
    core.receive(LEADER_A, append(1, LEADER_A, (1, 1), 1, &[]));
    core.take_actions();
    // Heard at 0, its stickiness holds until 150: a host that notices a
    // lapse within 50 may stop ticking it, one that needs 150 may not.
    assert!(core.quiescent(50));
    assert!(!core.quiescent(150));
    core.tick(120);
    core.take_actions();
    assert!(!core.quiescent(50), "120 and 50 reach 150");
    core.vouch(120, |_, _| Some(110), |_| None);
    assert!(core.quiescent(50), "vouched for at 110");
    // Its leader no longer listed, the deadline lapses: a pre-candidate
    // keeps its timers.
    core.tick(1_000);
    assert!(
        sent(&core.take_actions())
            .iter()
            .any(|message| matches!(message, Message::PreVote { .. }))
    );
    assert!(!core.quiescent(0));
}

#[test]
fn an_idle_leader_is_quiescent_once_every_member_is_caught_up_and_heard() {
    let mut core = idle_leader_of_three();
    assert!(!core.quiescent(0), "a heartbeat round is due");
    // The round finds both caught up: check-quorum's is the only deadline.
    core.tick(1_000 + 60);
    core.take_actions();
    assert!(core.quiescent(0));
    // A member's node unheard: the leader keeps its timers.
    core.vouch(
        1_000 + 70,
        |_, _| None,
        |node| (node == LEADER_A).then_some(1_000 + 65),
    );
    assert!(!core.quiescent(0));
    core.vouch(1_000 + 80, |_, _| None, |_| Some(1_000 + 75));
    assert!(core.quiescent(0));
    // An entry on its way keeps it ticking.
    core.propose(1, vec![1]);
    let actions = core.take_actions();
    persist(&mut core, writes(&actions).last().unwrap());
    core.take_actions();
    assert!(!core.quiescent(0));
}

#[test]
fn a_leader_with_a_read_waiting_is_not_quiescent() {
    let mut core = idle_leader_of_three();
    core.tick(1_000 + 60);
    core.take_actions();
    assert!(core.quiescent(0));
    core.read_index(9, None);
    core.take_actions();
    assert!(!core.quiescent(0));
}

#[test]
fn a_leader_resumed_after_a_quiet_wait_counts_only_members_heard_since() {
    let mut core = idle_leader_of_three();
    core.tick(1_000 + 60);
    core.take_actions();
    assert!(core.quiescent(0));
    // Quiet past check-quorum's window, its members' nodes fell silent:
    // what it heard of them before the wait no longer holds it up.
    core.resume(5_000);
    core.vouch(5_000, |_, _| None, |_| None);
    core.tick(5_000);
    core.take_actions();
    assert_eq!(core.role(), Role::Follower);
}

#[test]
fn a_leader_resumed_with_its_members_heard_keeps_leading() {
    let mut core = idle_leader_of_three();
    core.tick(1_000 + 60);
    core.take_actions();
    core.resume(5_000);
    core.vouch(5_000, |_, _| None, |_| Some(4_900));
    core.tick(5_000);
    core.take_actions();
    assert_eq!(core.role(), Role::Leader);
}
