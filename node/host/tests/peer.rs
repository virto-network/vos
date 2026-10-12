//! What nodes send each other: every message survives the wire whole, and
//! each arrival passes the checks before it reaches a group, here a real
//! consensus core.

/// The allocator the node's binary runs on.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use proptest::prelude::*;
use vos_net::Class;
use vos_node::peer::{self, Drops, Refusal, decode, from_wire, to_wire};
use vos_raft::core::{Action, Core, Recovered, Write};
use vos_raft::{AppendResult, Config, LogEntry, Message, Role};
use vos_wire::Encode;
use vos_wire::ids::{AgentId, InstanceId, MethodId, ProgramHash, Session};
use vos_wire::ingress::{Answer, Call};
use vos_wire::peer::{
    Configuration, CreationRecord, Leading, Manifest, NodeNumber, PeerMessage, Placement, Raft,
    SnapshotAck, SnapshotChunk,
};
use vos_wire::result::Outcome;

const AGENT: AgentId = AgentId(7);

fn node() -> impl Strategy<Value = NodeNumber> {
    any::<u8>()
}

fn entry() -> impl Strategy<Value = LogEntry<NodeNumber>> {
    let data = (
        any::<u64>(),
        any::<u64>(),
        prop::collection::vec(any::<u8>(), 0..64),
    )
        .prop_map(|(index, term, payload)| LogEntry::data(index, term, payload));
    let configuration = (
        any::<u64>(),
        any::<u64>(),
        prop::option::of(prop::collection::vec(node(), 0..5)),
        prop::collection::vec(node(), 0..5),
    )
        .prop_map(|(index, term, joint_old, members)| {
            LogEntry::config_change(index, term, joint_old, members)
        });
    prop_oneof![data, configuration]
}

fn message() -> impl Strategy<Value = Message<NodeNumber>> {
    let append = (
        any::<[u64; 5]>(),
        node(),
        prop::collection::vec(entry(), 0..4),
    )
        .prop_map(
            |([term, prev_index, prev_term, commit, round], leader, entries)| Message::Append {
                term,
                leader,
                prev_index,
                prev_term,
                commit,
                round,
                entries,
            },
        );
    let result = prop_oneof![
        any::<u64>().prop_map(|matched| AppendResult::Matched { matched }),
        any::<[u64; 4]>().prop_map(|[rejected, last_index, conflict_term, conflict_first]| {
            AppendResult::Rejected {
                rejected,
                last_index,
                conflict_term,
                conflict_first,
            }
        }),
    ];
    let answer = (any::<[u64; 3]>(), result).prop_map(|([term, round, commit], result)| {
        Message::AppendAnswer {
            term,
            round,
            commit,
            result,
        }
    });
    let vote =
        (any::<[u64; 3]>(), node()).prop_map(|([term, last_index, last_term], candidate)| {
            Message::Vote {
                term,
                candidate,
                last_index,
                last_term,
            }
        });
    let vote_answer = (any::<u64>(), any::<bool>())
        .prop_map(|(term, granted)| Message::VoteAnswer { term, granted });
    let pre_vote =
        (any::<[u64; 3]>(), node()).prop_map(|([next_term, last_index, last_term], candidate)| {
            Message::PreVote {
                next_term,
                candidate,
                last_index,
                last_term,
            }
        });
    let pre_vote_answer =
        (any::<[u64; 2]>(), any::<bool>()).prop_map(|([term, next_term], granted)| {
            Message::PreVoteAnswer {
                term,
                next_term,
                granted,
            }
        });
    let timeout_now = any::<u64>().prop_map(|term| Message::TimeoutNow { term });
    prop_oneof![
        append,
        answer,
        vote,
        vote_answer,
        pre_vote,
        pre_vote_answer,
        timeout_now
    ]
}

proptest! {
    #[test]
    fn every_raft_message_survives_the_wire(message in message(), agent in any::<u32>()) {
        let frame = PeerMessage::Raft {
            agent: AgentId(agent),
            message: to_wire(&message),
        }
        .encode();
        let PeerMessage::Raft { agent: arrived, message: wire } = decode(&frame).unwrap() else {
            panic!("not a Raft message");
        };
        prop_assert_eq!(arrived, AgentId(agent));
        prop_assert_eq!(from_wire(wire), message);
    }
}

fn chunk(term: u64) -> SnapshotChunk {
    SnapshotChunk {
        agent: AGENT,
        term,
        index: 40,
        snapshot_term: 3,
        sequence: 0,
        manifest: Some(Manifest {
            configuration: Some(Configuration {
                members: vec![1, 2, 3],
                joint_old: Some(vec![1, 2]),
                index: 12,
            }),
            last_result: Some((1_000, [7; 32])),
        }),
        rows: vec![(b"key".to_vec(), b"value".to_vec())],
        last: false,
    }
}

#[test]
fn every_other_message_survives_the_wire() {
    let bytes = b"a blob".to_vec();
    let messages = [
        PeerMessage::SnapshotChunk(chunk(5)),
        PeerMessage::SnapshotAck(SnapshotAck {
            agent: AGENT,
            term: 5,
            index: 40,
            next: 2,
        }),
        PeerMessage::BlobRequest {
            agent: AGENT,
            hashes: vec![[1; 32], [2; 32]],
        },
        PeerMessage::Blob {
            hash: vos_pvm::precompile::blake2b_256(&bytes),
            bytes,
        },
        PeerMessage::Liveness {
            incarnation: 9,
            round: 3,
            leading: vec![Leading {
                agent: AGENT,
                term: 4,
            }],
        },
        forward(),
        PeerMessage::ReadIndex {
            agent: AGENT,
            token: 78,
        },
        PeerMessage::Deliver {
            to: AGENT,
            message: vos_wire::batch::Message {
                from: AgentId(9),
                sequence: 3,
                instance: InstanceId(1),
                method: MethodId(2),
                arguments: vec![4],
            },
            relayed: true,
        },
        PeerMessage::Acknowledge {
            sender: AGENT,
            receiver: AgentId(9),
            sequence: 3,
            relayed: false,
        },
        PeerMessage::DirectoryRequest { agent: AGENT },
        PeerMessage::ReadIndexAnswer {
            agent: AGENT,
            token: 78,
            index: Some(41),
        },
        PeerMessage::Forwarded {
            agent: AGENT,
            token: 77,
            term: 6,
            answer: Answer::Ran {
                outcome: Outcome::Done(vec![1, 2]),
                at: 40,
            },
        },
    ];
    for message in messages {
        assert_eq!(decode(&message.encode()), Ok(message));
    }
}

fn forward() -> PeerMessage {
    PeerMessage::Forward {
        agent: AGENT,
        token: 77,
        term: 6,
        call: Call {
            session: Session {
                key: [1; 32],
                name: [2; 16],
                t0: 3,
            },
            sequence: 4,
            instance: InstanceId(5),
            method: MethodId(6),
            arguments: vec![7],
            signature: [8; 64],
        },
    }
}

#[test]
fn a_forwarded_call_comes_from_a_replica_on_its_agent_s_requests_stream() {
    let forward = forward();
    assert_eq!(peer::class(&forward), Class::Requests);
    assert_eq!(peer::stream(&forward), u64::from(AGENT.0));
    let read_index = PeerMessage::ReadIndex {
        agent: AGENT,
        token: 1,
    };
    assert_eq!(peer::class(&read_index), Class::Requests);
    assert_eq!(peer::stream(&read_index), u64::from(AGENT.0));
    // An acknowledgement travels on its sender's stream: the agent it is
    // for.
    let acknowledge = PeerMessage::Acknowledge {
        sender: AGENT,
        receiver: AgentId(9),
        sequence: 1,
        relayed: false,
    };
    assert_eq!(peer::class(&acknowledge), Class::Requests);
    assert_eq!(peer::stream(&acknowledge), u64::from(AGENT.0));
    assert_eq!(
        peer::check(
            &SPACE,
            2,
            (Class::Consensus, u64::from(AGENT.0)),
            &forward,
            unfollowed
        ),
        Err(Refusal::WrongClass)
    );
    // Its sender must replicate the agent: the leader trusts it to have
    // checked the call's signature. While a placement is uncommitted, the
    // nodes of the configuration before may still lead.
    let placement = |replicas: Vec<NodeNumber>, committed| Placement {
        replicas,
        before: vec![1, 2, 3],
        term: 4,
        index: 9,
        joint: false,
        committed,
    };
    assert_eq!(
        peer::check_replica(Some(&placement(vec![1, 2, 3], true)), 2),
        Ok(())
    );
    assert_eq!(
        peer::check_replica(Some(&placement(vec![1, 3, 4], true)), 2),
        Err(Refusal::NotAReplica)
    );
    assert_eq!(
        peer::check_replica(Some(&placement(vec![1, 3, 4], false)), 2),
        Ok(())
    );
    assert_eq!(peer::check_replica(None, 2), Err(Refusal::NotAReplica));
}

/// Placements are ordered by the announcing leader's term first: a
/// configuration announced by a leader that failed before it committed is
/// outranked by the next leader's, at whatever index.
#[test]
fn placements_are_ordered_by_term_then_index_then_commitment() {
    let placement = |term, index, committed| Placement {
        replicas: vec![1, 2, 3],
        before: Vec::new(),
        term,
        index,
        joint: false,
        committed,
    };
    assert!(placement(5, 80, false).order() > placement(4, 100, false).order());
    assert!(placement(4, 100, false).order() > placement(4, 90, true).order());
    assert!(placement(4, 100, true).order() > placement(4, 100, false).order());
}

/// A placement at creation comes from the agent's creator, or relayed
/// whole by one of its replicas; a later one from a node it names, or one
/// of the configuration it supersedes.
#[test]
fn a_placement_comes_from_its_creator_then_from_its_members() {
    // Created by node 1: its number is the id's top byte.
    let agent = AgentId(1 << 24 | 7);
    let record = CreationRecord {
        agent,
        replicas: vec![1, 2, 3],
        creator: CreationRecord::creator_of(agent),
        time: 0,
        program: ProgramHash([0; 32]),
        accumulate_gas: 0,
    };
    let creator = record.creator;
    let check = |from, placement: Placement| {
        let message = PeerMessage::Directory {
            record: record.clone(),
            placement,
        };
        peer::check(
            &SPACE,
            from,
            (Class::Requests, u64::from(agent.0)),
            &message,
            |_| None,
        )
    };
    let created = Placement::created(&record);
    assert_eq!(check(creator, created.clone()), Ok(()));
    assert_eq!(check(2, created.clone()), Ok(()), "relayed by a replica");
    assert_eq!(
        check(4, created.clone()),
        Err(Refusal::NotTheCreator),
        "neither its creator nor a replica"
    );
    let altered = Placement {
        replicas: vec![1, 2],
        ..created.clone()
    };
    assert_eq!(
        check(2, altered),
        Err(Refusal::NotTheCreator),
        "a term-0 placement other than the creation's"
    );
    // A record claiming a creator other than its id's.
    let claimed = CreationRecord {
        creator: 2,
        ..record.clone()
    };
    let relayed = PeerMessage::Directory {
        placement: Placement::created(&claimed),
        record: claimed,
    };
    assert_eq!(
        peer::check(
            &SPACE,
            3,
            (Class::Requests, u64::from(agent.0)),
            &relayed,
            |_| None,
        ),
        Err(Refusal::NotTheCreator)
    );
    let later = Placement {
        replicas: vec![1, 2, 4],
        before: vec![1, 2, 3, 4],
        term: 3,
        index: 12,
        joint: false,
        committed: false,
    };
    assert_eq!(check(3, later.clone()), Ok(()), "a leader removing itself");
    assert_eq!(check(4, later.clone()), Ok(()));
    let stranger = Placement {
        before: vec![1, 2],
        ..later
    };
    assert_eq!(check(3, stranger), Err(Refusal::NotTheCreator));
}

/// A placement replaces a held one it outranks, except that none takes
/// back a commit: a new leader announcing the committed configuration
/// before it learns that it committed leaves the commit held.
#[test]
fn no_placement_takes_back_a_commit() {
    let placement = |term, index, committed| Placement {
        replicas: vec![1, 2, 3],
        before: vec![1, 2, 4],
        term,
        index,
        joint: false,
        committed,
    };
    let held = placement(4, 100, true);
    assert!(!placement(5, 100, false).supersedes(&held));
    assert!(!placement(5, 90, true).supersedes(&held));
    assert!(!placement(4, 100, true).supersedes(&held));
    assert!(placement(5, 100, true).supersedes(&held));
    assert!(placement(4, 120, false).supersedes(&held));
    assert!(
        placement(5, 80, false).supersedes(&placement(4, 100, false)),
        "a phantom gives way"
    );
}

#[test]
fn a_frame_is_one_whole_message() {
    let frame = PeerMessage::Liveness {
        incarnation: 1,
        round: 2,
        leading: Vec::new(),
    }
    .encode();
    assert_eq!(
        decode(&[&frame[..], &[0]].concat()),
        Err(Refusal::Undecodable)
    );
    assert_eq!(decode(&frame[..frame.len() - 1]), Err(Refusal::Undecodable));
    assert_eq!(decode(&[0xff]), Err(Refusal::Undecodable));
    assert_eq!(decode(&[]), Err(Refusal::Undecodable));
}

const SPACE: [NodeNumber; 4] = [1, 2, 3, 4];

fn raft(message: Raft) -> PeerMessage {
    PeerMessage::Raft {
        agent: AGENT,
        message,
    }
}

fn unfollowed(_: AgentId) -> Option<(NodeNumber, u64)> {
    None
}

/// Check `message` as it arrives on its own class and stream.
fn check(
    space: &[NodeNumber],
    from: NodeNumber,
    message: &PeerMessage,
    followed: impl FnOnce(AgentId) -> Option<(NodeNumber, u64)>,
) -> Result<(), Refusal> {
    let way = (peer::class(message), peer::stream(message));
    peer::check(space, from, way, message, followed)
}

#[test]
fn each_message_comes_on_its_class_and_a_raft_message_on_its_agent_s_stream() {
    let append = raft(Raft::Append {
        term: 2,
        leader: 2,
        prev_index: 0,
        prev_term: 0,
        commit: 0,
        round: 1,
        entries: Vec::new(),
    });
    assert_eq!(peer::class(&append), Class::Consensus);
    assert_eq!(peer::stream(&append), u64::from(AGENT.0));
    // On bulk, a Raft frame would escape its class's bound.
    assert_eq!(
        peer::check(
            &SPACE,
            2,
            (Class::Bulk, u64::from(AGENT.0)),
            &append,
            unfollowed
        ),
        Err(Refusal::WrongClass)
    );
    assert_eq!(
        peer::check(&SPACE, 2, (Class::Consensus, 8), &append, unfollowed),
        Err(Refusal::WrongStream)
    );
    let bytes = b"a blob".to_vec();
    let blob = PeerMessage::Blob {
        hash: vos_pvm::precompile::blake2b_256(&bytes),
        bytes,
    };
    assert_eq!(
        peer::check(&SPACE, 2, (Class::Consensus, 0), &blob, unfollowed),
        Err(Refusal::WrongClass)
    );
    assert_eq!(
        peer::check(&SPACE, 2, (Class::Bulk, 3), &blob, unfollowed),
        Ok(())
    );
}

#[test]
fn only_configured_nodes_are_heard() {
    let liveness = PeerMessage::Liveness {
        incarnation: 1,
        round: 1,
        leading: Vec::new(),
    };
    assert_eq!(check(&SPACE, 4, &liveness, unfollowed), Ok(()));
    assert_eq!(
        check(&SPACE, 5, &liveness, unfollowed),
        Err(Refusal::Stranger)
    );
    let answer = raft(Raft::VoteAnswer {
        term: 3,
        granted: true,
    });
    assert_eq!(
        check(&SPACE, 5, &answer, unfollowed),
        Err(Refusal::Stranger)
    );
    assert_eq!(check(&SPACE, 2, &answer, unfollowed), Ok(()));
}

#[test]
fn an_append_comes_from_its_leader_and_a_vote_request_from_its_candidate() {
    let append = |leader| {
        raft(Raft::Append {
            term: 2,
            leader,
            prev_index: 0,
            prev_term: 0,
            commit: 0,
            round: 1,
            entries: Vec::new(),
        })
    };
    assert_eq!(check(&SPACE, 2, &append(2), unfollowed), Ok(()));
    assert_eq!(
        check(&SPACE, 3, &append(2), unfollowed),
        Err(Refusal::NotTheLeaderNamed)
    );
    let vote = |candidate| {
        raft(Raft::Vote {
            term: 2,
            candidate,
            last_index: 0,
            last_term: 0,
        })
    };
    let pre_vote = |candidate| {
        raft(Raft::PreVote {
            next_term: 2,
            candidate,
            last_index: 0,
            last_term: 0,
        })
    };
    for request in [vote, pre_vote] {
        assert_eq!(check(&SPACE, 3, &request(3), unfollowed), Ok(()));
        assert_eq!(
            check(&SPACE, 2, &request(3), unfollowed),
            Err(Refusal::NotTheCandidateNamed)
        );
    }
}

#[test]
fn a_snapshot_chunk_comes_from_the_leader_followed_in_its_term() {
    let chunk = PeerMessage::SnapshotChunk(chunk(5));
    let follows = |agent: AgentId| {
        assert_eq!(agent, AGENT);
        Some((2, 5))
    };
    assert_eq!(check(&SPACE, 2, &chunk, follows), Ok(()));
    // Another configured node, the leader of another term, or a replica
    // that follows no one.
    assert_eq!(
        check(&SPACE, 3, &chunk, follows),
        Err(Refusal::NotTheLeaderFollowed)
    );
    assert_eq!(
        check(&SPACE, 2, &chunk, |_| Some((2, 6))),
        Err(Refusal::NotTheLeaderFollowed)
    );
    assert_eq!(
        check(&SPACE, 2, &chunk, unfollowed),
        Err(Refusal::NotTheLeaderFollowed)
    );
}

#[test]
fn a_blob_hashes_to_its_name() {
    let bytes = b"a program".to_vec();
    let hash = vos_pvm::precompile::blake2b_256(&bytes);
    let blob = |bytes: Vec<u8>| PeerMessage::Blob { hash, bytes };
    assert_eq!(check(&SPACE, 1, &blob(bytes.clone()), unfollowed), Ok(()));
    let mut forged = bytes;
    forged[0] ^= 1;
    assert_eq!(
        check(&SPACE, 1, &blob(forged), unfollowed),
        Err(Refusal::WrongBlob)
    );
}

#[test]
fn drops_are_counted_by_why() {
    let drops = Drops::default();
    drops.count(Refusal::Stranger);
    drops.count(Refusal::Stranger);
    drops.count(Refusal::WrongBlob);
    assert_eq!(drops.get(Refusal::Stranger), 2);
    assert_eq!(drops.get(Refusal::WrongBlob), 1);
    for refusal in Refusal::ALL {
        if refusal != Refusal::Stranger && refusal != Refusal::WrongBlob {
            assert_eq!(drops.get(refusal), 0);
        }
    }
}

/// Replica 1 of a group whose members, as it knows them, are 1, 2 and 3.
/// The space also configures node 4, which a change the replica has not
/// seen yet made a member, and not node 5.
fn replica() -> Core<NodeNumber> {
    let mut core = Core::new(
        Config::new(1, vec![1, 2, 3], [0; 32]),
        Recovered::default(),
        0,
        3,
    );
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
    peer::check(&SPACE, from, way, &arrived, unfollowed)?;
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
