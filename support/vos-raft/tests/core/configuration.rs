//! Membership: changes, the configuration a replica follows, recovers and
//! keeps with its log's start, and what a snapshot carries.

use vos_raft::core::{Action, Answer, ChangeMembershipError, Core, Recovered};
use vos_raft::{ActiveConfigRecord, AppendResult, Config, EntryKind, LogEntry, Message};

use crate::common::{
    LEADER_A, LEADER_B, ME, append, committed, compact_bounds, config, entries_to, follower, lead,
    leader_of_three_with, leader_of_two, loads, matched, persist, persist_into, recovered, sent,
    snapshotted, writes,
};

const JOINER: u16 = 4;

/// B replaced by the joiner: (members, old members).
fn joint() -> (Vec<u16>, Vec<u16>) {
    (vec![ME, LEADER_A, JOINER], vec![ME, LEADER_A, LEADER_B])
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

/// Make `core` lead ([`lead`]), and A acknowledge its no-op. The actions
/// after.
fn lead_with_a(core: &mut Core<u16>, at: u64) -> Vec<Action<u16>> {
    let actions = lead(core, at);
    persist(core, writes(&actions).last().unwrap());
    let status = core.status();
    core.receive(
        LEADER_A,
        Message::AppendAnswer {
            term: status.current_term,
            round: 0,
            commit: 0,
            result: AppendResult::Matched {
                matched: status.last_log_index,
            },
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

/// After compaction took every configuration entry, a truncation that
/// removes a newer one falls back to the configuration in effect at the
/// log's start, which the host kept, never to the static members.
#[test]
fn a_truncation_falls_back_to_the_log_start_configuration() {
    let at_start = record(Some(5), vec![ME, LEADER_A, 4], None);
    let entries = vec![LogEntry::data(11, 1, vec![]), LogEntry::data(12, 1, vec![])];
    let recovered = Recovered {
        active_config: Some(at_start.clone()),
        log_start_config: Some(at_start),
        ..snapshotted(recovered(1, 12, entries), (10, 1))
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
        active_config: Some(record(Some(12), vec![ME, LEADER_A], None)),
        ..snapshotted(
            recovered(1, 12, vec![LogEntry::data(11, 1, vec![]), newest]),
            (10, 1),
        )
    };
    let mut core = Core::new(cfg, recovered, 0, 3);
    core.take_actions();
    assert_eq!(core.config_at(10), None, "unknown at the log's start");
    assert!(core.config_at(12).is_some());
    lead(&mut core, 1_000);
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
fn a_replica_given_a_joint_snapshot_finalizes_it_when_it_leads() {
    let mut cfg = config();
    cfg.pre_vote = false;
    let mut core = Core::new(cfg, Recovered::default(), 0, 5);
    core.take_actions();
    let (members, old) = joint();
    core.snapshot_installed(20, 1, Some(record(Some(15), members.clone(), Some(old))));
    core.take_actions();
    assert!(core.status().joint_old.is_some());
    let actions = lead_with_a(&mut core, 1_000);
    assert_eq!(finals(&actions), vec![members]);
}

#[test]
fn recovery_takes_the_later_of_the_record_and_the_logs_start() {
    let (members, old) = joint();
    let recovered = Recovered {
        // A crash lost the record's update to the final configuration,
        // which a compaction had already made the log's start.
        active_config: Some(record(Some(190), members.clone(), Some(old))),
        log_start_config: Some(record(Some(192), members.clone(), None)),
        ..snapshotted(recovered(2, 192, Vec::new()), (192, 2))
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
        active_config: Some(record(Some(15), members.clone(), Some(old))),
        ..snapshotted(recovered(1, 20, Vec::new()), (20, 1))
    };
    let mut cfg = config();
    cfg.pre_vote = false;
    let mut core = Core::new(cfg, recovered, 0, 5);
    core.take_actions();
    let actions = lead_with_a(&mut core, 1_000);
    assert_eq!(finals(&actions), vec![members]);
}

/// Once a change's final entry commits, the next change starts at once,
/// the voter it removed hears nothing more, and compaction reaches the
/// commit.
#[test]
fn the_next_change_starts_once_the_final_entry_commits() {
    let mut core = leader_of_three_with(|cfg| cfg.compact_hysteresis = 1);
    // B is replaced by the joiner: the joint entry at 2.
    let (members, _) = joint();
    core.change_membership(1, members.clone());
    let actions = core.take_actions();
    assert!(actions.contains(&Action::Answer(Answer::ChangeMembership {
        token: 1,
        result: Ok(2),
    })));
    persist(&mut core, writes(&actions).last().unwrap());
    // A acknowledges it: it commits, and the final entry follows at 3.
    core.receive(LEADER_A, matched(2));
    let actions = core.take_actions();
    assert_eq!(finals(&actions), vec![members.clone()]);
    persist(&mut core, writes(&actions).last().unwrap());
    // A acknowledges the final entry: it commits, and B is out. B still has
    // the joint entry's append in flight, so the append carrying the commit
    // skips it.
    core.receive(LEADER_A, matched(3));
    let mut after = core.take_actions();
    assert_eq!(committed(&after), Some(3));
    let status = core.status();
    assert_eq!((status.members, status.joint_old), (members, None));
    // The next change starts at once.
    core.change_membership(2, vec![ME, LEADER_A]);
    let actions = core.take_actions();
    assert!(actions.contains(&Action::Answer(Answer::ChangeMembership {
        token: 2,
        result: Ok(4),
    })));
    after.extend(actions);
    // Compaction may reach the commit.
    core.durably_applied(3);
    assert_eq!(compact_bounds(&core.take_actions()), [3]);
    // B's late answer draws nothing, and no heartbeat goes to it.
    core.receive(LEADER_B, matched(2));
    after.extend(core.take_actions());
    for at in (1_050..=1_250).step_by(50) {
        core.tick(at);
        after.extend(core.take_actions());
    }
    assert!(!entries_to(&after, LEADER_A).is_empty());
    assert!(entries_to(&after, LEADER_B).is_empty(), "{after:?}");
}

/// A load a voter waited on that comes back after the final entry removed
/// it sends that voter nothing.
#[test]
fn a_load_answered_after_a_removal_sends_the_removed_voter_nothing() {
    // A leader of three whose cache holds almost nothing; B never answers.
    let mut cfg = config();
    cfg.pre_vote = false;
    cfg.cache_bytes = 1;
    cfg.resend_timeout_ms = 100;
    cfg.check_quorum = false;
    let mut core = Core::new(cfg, Recovered::default(), 0, 5);
    core.take_actions();
    lead_with_a(&mut core, 1_000);
    let mut store = vec![LogEntry::data(1, 1, Vec::new())];
    // B is replaced by the joiner: the joint entry at 2, the final one at 3.
    let (members, _) = joint();
    core.change_membership(1, members);
    let actions = core.take_actions();
    persist_into(&mut store, &mut core, &actions);
    core.receive(LEADER_A, matched(2));
    let actions = core.take_actions();
    persist_into(&mut store, &mut core, &actions);
    // B's slot frees after the resend timeout, and what it lacks is no
    // longer cached: the leader loads it.
    core.tick(1_000 + 150);
    let load = loads(&core.take_actions())
        .into_iter()
        .find(|load| load.from == 1)
        .expect("a load for B");
    // The final entry commits, then the load comes back.
    core.receive(LEADER_A, matched(3));
    let mut after = core.take_actions();
    assert_eq!(committed(&after), Some(3));
    let entries = store
        .iter()
        .filter(|entry| (load.from..=load.to).contains(&entry.index))
        .cloned()
        .collect();
    core.loaded(load, entries);
    after.extend(core.take_actions());
    let to_b = after.iter().any(|action| {
        matches!(
            action,
            Action::Send { to: LEADER_B, .. } | Action::SendSnapshot { to: LEADER_B, .. }
        )
    });
    assert!(!to_b, "{after:?}");
}

/// A configuration entry takes effect where it is appended: a voter
/// removed that holds the final entry never campaigns, and one holding
/// only the joint entry is refused by a member that holds the final one.
#[test]
fn a_removed_voter_campaigns_only_in_the_configuration_it_holds() {
    // ME is replaced by the joiner: the joint entry at 2, the final one
    // at 3.
    let old = vec![ME, LEADER_A, LEADER_B];
    let members = vec![LEADER_A, LEADER_B, JOINER];
    let joint = LogEntry::config_change(2, 1, Some(old.clone()), members.clone());
    let last = LogEntry::config_change(3, 1, None, members.clone());
    let from_a = |entries: Vec<LogEntry<u16>>| Message::Append {
        term: 1,
        leader: LEADER_A,
        prev_index: 1,
        prev_term: 1,
        commit: 1,
        round: 1,
        entries,
    };
    let campaigns = |actions: &[Action<u16>]| {
        sent(actions)
            .into_iter()
            .filter(|message| matches!(message, Message::PreVote { .. } | Message::Vote { .. }))
            .collect::<Vec<_>>()
    };
    // Holding the final entry, ME is no member: its timer asks for nothing.
    let mut removed = follower(1, &[1], 1);
    removed.receive(LEADER_A, from_a(vec![joint.clone(), last.clone()]));
    removed.take_actions();
    assert_eq!(removed.status().members, members);
    for at in (1_000..=5_000).step_by(500) {
        removed.tick(at);
        assert!(campaigns(&removed.take_actions()).is_empty(), "at {at}");
    }
    // Holding only the joint entry, it asks A for a pre-vote.
    let mut behind = follower(1, &[1], 1);
    behind.receive(LEADER_A, from_a(vec![joint.clone()]));
    behind.take_actions();
    behind.tick(1_000);
    let pre_vote = behind
        .take_actions()
        .into_iter()
        .find_map(|action| match action {
            Action::Send {
                to: LEADER_A,
                message: message @ Message::PreVote { .. },
            } => Some(message),
            _ => None,
        })
        .expect("a pre-vote to A");
    // A replica of A's that held only the joint entry would grant it; A,
    // holding the final entry, refuses it.
    let granted = |entries: Vec<LogEntry<u16>>| {
        let config = Config::new(LEADER_A, old.clone());
        let mut a = Core::new(config, recovered(1, 1, entries), 0, 7);
        a.take_actions();
        a.receive(ME, pre_vote.clone());
        sent(&a.take_actions())
            .into_iter()
            .find_map(|message| match message {
                Message::PreVoteAnswer { granted, .. } => Some(granted),
                _ => None,
            })
    };
    let no_op = LogEntry::data(1, 1, vec![0]);
    assert_eq!(granted(vec![no_op.clone(), joint.clone()]), Some(true));
    assert_eq!(granted(vec![no_op, joint, last]), Some(false));
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

/// A truncation that removes the entry the membership record came from
/// writes the record again: a restart must not adopt a configuration no
/// entry backs.
#[test]
fn truncate_dropping_originating_config_change_invalidates_persisted_view() {
    let grown = vec![ME, LEADER_A, LEADER_B, JOINER];
    let recovered = Recovered {
        active_config: Some(record(Some(1), grown.clone(), None)),
        ..recovered(
            1,
            0,
            vec![LogEntry::config_change(1, 1, None, grown.clone())],
        )
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
    let entries = vec![
        LogEntry::config_change(5, 1, None, three.clone()),
        LogEntry::data(6, 1, vec![]),
    ];
    let committed = Recovered {
        active_config: Some(record(Some(5), three.clone(), None)),
        ..snapshotted(recovered(1, 6, entries), (4, 1))
    };
    let core = Core::new(cfg.clone(), committed, 0, 7);
    let switch = core.snapshot_switch(10, 5, None);
    assert_eq!(switch.active_config, record(Some(5), three.clone(), None));
    assert!(switch.meta.commit_index >= 10);
    // A fresh replica takes the snapshot's own.
    let fresh = Core::new(cfg, Recovered::default(), 0, 7);
    let carried = record(Some(37), three.clone(), None);
    let switch = fresh.snapshot_switch(100, 6, Some(&carried));
    assert_eq!(switch.active_config, record(Some(37), three, None));
    assert!(switch.meta.commit_index >= 100);
    // A joint configuration appended at 5, committed only through 2.
    let entries = (1..=4)
        .map(|index| LogEntry::data(index, 3, vec![]))
        .chain([LogEntry::config_change(
            5,
            3,
            Some(vec![LEADER_A]),
            vec![ME, LEADER_A],
        )])
        .collect();
    let speculative = Recovered {
        active_config: Some(record(Some(5), vec![ME, LEADER_A], Some(vec![LEADER_A]))),
        ..recovered(3, 2, entries)
    };
    let core = Core::new(config(), speculative, 0, 7);
    let switch = core.snapshot_switch(10, 3, None);
    assert_eq!(
        switch.active_config,
        record(None, vec![ME, LEADER_A], Some(vec![LEADER_A]))
    );
    assert_eq!(switch.meta.commit_index, 10);
}
