//! The checks an arrival passes: its class and stream, its sender, and
//! what it carries.

use super::*;

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
    let replicas_of =
        |replicas: Vec<NodeNumber>, committed| placement(&replicas, &[1, 2, 3], (4, 9), committed);
    assert_eq!(
        peer::check_replica(Some(&replicas_of(vec![1, 2, 3], true)), 2),
        Ok(())
    );
    assert_eq!(
        peer::check_replica(Some(&replicas_of(vec![1, 3, 4], true)), 2),
        Err(Refusal::NotAReplica)
    );
    assert_eq!(
        peer::check_replica(Some(&replicas_of(vec![1, 3, 4], false)), 2),
        Ok(())
    );
    assert_eq!(peer::check_replica(None, 2), Err(Refusal::NotAReplica));
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
