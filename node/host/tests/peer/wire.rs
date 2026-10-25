//! Every message survives the wire whole, and a frame is one message.

use super::*;

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
                body: vos_wire::batch::Body::Call {
                    instance: InstanceId(1),
                    method: MethodId(2),
                    arguments: vec![4],
                    awaiting: None,
                },
            },
            relayed: true,
        },
        PeerMessage::Acknowledge {
            sender: AGENT,
            receiver: AgentId(9),
            sequence: 3,
            relayed: false,
        },
        PeerMessage::Behind {
            sender: AGENT,
            receiver: AgentId(9),
            relayed: true,
        },
        PeerMessage::DirectoryRequest { agent: AGENT },
        PeerMessage::AnchorRow {
            agent: AGENT,
            token: 79,
            window: 5,
        },
        PeerMessage::AnchorRowAnswer {
            agent: AGENT,
            token: 79,
            root: Some([7; 32]),
        },
        PeerMessage::ReadIndexAnswer {
            agent: AGENT,
            token: 78,
            index: Some(41),
        },
        PeerMessage::Forwarded {
            agent: AGENT,
            token: 77,
            term: 6,
            answer: Response::Ran {
                outcome: Outcome::Done(vec![1, 2]),
                at: 40,
            },
        },
    ];
    for message in messages {
        assert_eq!(decode(&message.encode()), Ok(message));
    }
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
