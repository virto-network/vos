//! Placements: their order, where they come from, and no commit taken
//! back.

use super::*;

/// Placements are ordered by the announcing leader's term first: a
/// configuration announced by a leader that failed before it committed is
/// outranked by the next leader's, at whatever index.
#[test]
fn placements_are_ordered_by_term_then_index_then_commitment() {
    let announced = |term, index, committed| placement(&[1, 2, 3], &[], (term, index), committed);
    assert!(announced(5, 80, false).order() > announced(4, 100, false).order());
    assert!(announced(4, 100, false).order() > announced(4, 90, true).order());
    assert!(announced(4, 100, true).order() > announced(4, 100, false).order());
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
        space: OURS,
    };
    let creator = record.creator;
    let check = |from, placement: Placement| {
        let message = PeerMessage::Directory {
            record: record.clone(),
            placement,
        };
        peer::check(
            &SPACE,
            &OURS,
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
            &OURS,
            3,
            (Class::Requests, u64::from(agent.0)),
            &relayed,
            |_| None,
        ),
        Err(Refusal::NotTheCreator)
    );
    let later = placement(&[1, 2, 4], &[1, 2, 3, 4], (3, 12), false);
    assert_eq!(check(3, later.clone()), Ok(()), "a leader removing itself");
    assert_eq!(check(4, later.clone()), Ok(()));
    let stranger = Placement {
        before: vec![1, 2],
        ..later
    };
    assert_eq!(check(3, stranger), Err(Refusal::NotTheCreator));
    // A record of another space, or of none, from its very creator.
    for space in [vos_wire::SpaceId([0xb2; 32]), vos_wire::SpaceId::NONE] {
        let other = CreationRecord {
            space,
            ..record.clone()
        };
        let message = PeerMessage::Directory {
            placement: Placement::created(&other),
            record: other,
        };
        assert_eq!(
            peer::check(
                &SPACE,
                &OURS,
                creator,
                (Class::Requests, u64::from(agent.0)),
                &message,
                |_| None,
            ),
            Err(Refusal::OtherSpace)
        );
    }
}

/// A placement replaces a held one it outranks, except that none takes
/// back a commit: a new leader announcing the committed configuration
/// before it learns that it committed leaves the commit held.
#[test]
fn no_placement_takes_back_a_commit() {
    let announced =
        |term, index, committed| placement(&[1, 2, 3], &[1, 2, 4], (term, index), committed);
    let held = announced(4, 100, true);
    assert!(!announced(5, 100, false).supersedes(&held));
    assert!(!announced(5, 90, true).supersedes(&held));
    assert!(!announced(4, 100, true).supersedes(&held));
    assert!(announced(5, 100, true).supersedes(&held));
    assert!(announced(4, 120, false).supersedes(&held));
    assert!(
        announced(5, 80, false).supersedes(&announced(4, 100, false)),
        "a phantom gives way"
    );
}
