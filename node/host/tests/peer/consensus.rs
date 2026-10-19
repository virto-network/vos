//! Arrivals through the checks to a real consensus core: a new member
//! heard, and followed.

use super::*;

/// Replica 1 of a group whose members, as it knows them, are 1, 2 and 3.
/// The space also configures node 4, which a change the replica has not
/// seen yet made a member, and not node 5.
fn replica() -> Core<NodeNumber> {
    let mut core = Core::new(Config::new(1, vec![1, 2, 3]), Recovered::default(), 0, 3);
    core.take_actions();
    core
}

/// Deliver `message` from `from` as the node would: over the wire, then
/// through the checks, then to the core.
fn deliver(
    core: &mut Core<NodeNumber>,
    from: NodeNumber,
    message: Message<NodeNumber>,
) -> Result<(), Refusal> {
    let sent = PeerMessage::Raft {
        agent: AGENT,
        message: to_wire(&message),
    };
    let arrived = decode(&sent.encode())?;
    let way = (peer::class(&sent), peer::stream(&sent));
    peer::check(&SPACE, &OURS, from, way, &arrived, unfollowed)?;
    let PeerMessage::Raft { message, .. } = arrived else {
        unreachable!("a Raft message stays one");
    };
    core.receive(from, from_wire(message));
    Ok(())
}

/// Report every write in `actions` durable, as a host without blobs does.
fn persist(core: &mut Core<NodeNumber>, actions: &[Action<NodeNumber>]) {
    let writes: Vec<&Write<NodeNumber>> = actions
        .iter()
        .filter_map(|action| match action {
            Action::Write(write) => Some(write),
            _ => None,
        })
        .collect();
    for write in writes {
        core.durable(write.seq);
        core.entries_durable(write.seq);
    }
}

fn settle(core: &mut Core<NodeNumber>) -> Vec<Action<NodeNumber>> {
    let mut all = Vec::new();
    loop {
        let actions = core.take_actions();
        if actions.is_empty() {
            return all;
        }
        persist(core, &actions);
        all.extend(actions);
    }
}

#[test]
fn a_new_member_is_heard_before_the_replica_knows_it_but_counted_only_as_a_member() {
    let mut core = replica();
    core.tick(1_000);
    settle(&mut core);
    assert_eq!(core.role(), Role::PreCandidate);

    // Pre-votes and votes from node 4 reach the core, which does not count
    // them: node 4 is not a member as it knows them.
    let pre_vote = |granted| Message::PreVoteAnswer {
        term: 0,
        next_term: 1,
        granted,
    };
    assert_eq!(deliver(&mut core, 4, pre_vote(true)), Ok(()));
    settle(&mut core);
    assert_eq!(core.role(), Role::PreCandidate);
    assert_eq!(
        deliver(&mut core, 5, pre_vote(true)),
        Err(Refusal::Stranger)
    );
    assert_eq!(deliver(&mut core, 2, pre_vote(true)), Ok(()));
    settle(&mut core);
    assert_eq!(core.role(), Role::Candidate);
    let vote = Message::VoteAnswer {
        term: 1,
        granted: true,
    };
    assert_eq!(deliver(&mut core, 4, vote.clone()), Ok(()));
    settle(&mut core);
    assert_eq!(core.role(), Role::Candidate);
    assert_eq!(deliver(&mut core, 2, vote), Ok(()));
    settle(&mut core);
    assert_eq!(core.role(), Role::Leader);

    // As leader: node 4's acknowledgement does not commit; a member's does.
    let matched = Message::AppendAnswer {
        term: 1,
        round: 1,
        commit: 0,
        result: AppendResult::Matched { matched: 1 },
    };
    assert_eq!(deliver(&mut core, 4, matched.clone()), Ok(()));
    settle(&mut core);
    assert_eq!(core.status().commit_index, 0);
    assert_eq!(deliver(&mut core, 3, matched), Ok(()));
    settle(&mut core);
    assert_eq!(core.status().commit_index, 1);

    // Once the leader adds node 4, its acknowledgement counts: the joint
    // configuration needs majorities of 1, 2, 3 and of 1, 2, 3, 4.
    core.change_membership(1, vec![1, 2, 3, 4]);
    settle(&mut core);
    let joint = |matched| Message::AppendAnswer {
        term: 1,
        round: 2,
        commit: 1,
        result: AppendResult::Matched { matched },
    };
    assert_eq!(deliver(&mut core, 2, joint(2)), Ok(()));
    settle(&mut core);
    assert_eq!(
        core.status().commit_index,
        1,
        "two of four is no majority of the new members"
    );
    assert_eq!(deliver(&mut core, 4, joint(2)), Ok(()));
    settle(&mut core);
    assert_eq!(core.status().commit_index, 2);
}

#[test]
fn a_replica_follows_a_new_member_that_leads_a_later_term() {
    let mut core = replica();
    let append = |leader| Message::Append {
        term: 5,
        leader,
        prev_index: 0,
        prev_term: 0,
        commit: 0,
        round: 1,
        entries: vec![LogEntry::data(1, 5, Vec::new())],
    };
    // Node 4 names node 2 as the leader: refused before the core sees it.
    assert_eq!(
        deliver(&mut core, 4, append(2)),
        Err(Refusal::NotTheLeaderNamed)
    );
    assert_eq!(core.status().current_term, 0);
    assert_eq!(deliver(&mut core, 4, append(4)), Ok(()));
    let actions = settle(&mut core);
    assert_eq!(core.status().leader_hint, Some(4));
    assert_eq!(core.status().current_term, 5);
    assert!(actions.iter().any(|action| matches!(
        action,
        Action::Send {
            to: 4,
            message: Message::AppendAnswer { .. }
        }
    )));
}
