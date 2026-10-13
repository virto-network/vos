//! What a replica claims and applies, and what waits for its writes.

use vos_raft::core::{Action, Core, Recovered};
use vos_raft::{LogEntry, Message, Role};

use crate::common::{
    LEADER_A, LEADER_B, ME, append, claimed, committed, compact_bounds, config, follower,
    leader_of_two, matched, persist, recovered, sent, writes,
};

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

/// No other member could lead: a lone member campaigns at its first tick,
/// and counts its own vote, and its no-op, only once they are durable.
#[test]
fn a_lone_member_campaigns_at_once_and_counts_its_vote_once_durable() {
    let mut cfg = config();
    cfg.members = vec![ME];
    let mut core = Core::new(cfg, Recovered::default(), 0, 3);
    core.take_actions();
    core.tick(0);
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
    assert!(committed(&actions).is_none());
    let no_op = writes(&actions).last().expect("the no-op").clone();
    persist(&mut core, &no_op);
    assert_eq!(committed(&core.take_actions()), Some(1));
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
    let mut core = Core::new(cfg, recovered(2, 10, entries), 0, 7);
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
    for peer in [LEADER_A, LEADER_B] {
        core.receive(
            peer,
            Message::VoteAnswer {
                term,
                granted: true,
            },
        );
    }
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

#[test]
fn a_wiped_replica_votes_only_for_a_log_reaching_what_it_held() {
    // Its log and state were wiped; it last held up to index 40, term 3.
    let recovered = Recovered {
        vote_floor: Some((40, 3)),
        ..recovered(3, 0, Vec::new())
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
    // Committed through 8, applied through none.
    let recovered = Recovered {
        applied: 0,
        ..recovered(1, 8, entries)
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
