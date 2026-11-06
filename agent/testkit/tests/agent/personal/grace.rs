//! The lease and the lapsed agent's grace: past its lease the agent
//! refuses pushes, the inbox, pairing and any commit but one carrying a
//! removal, and still takes removals, `alive`, votes and evidence, and
//! serves reads; only a re-proof moves the lease.

use vos_wire::personal::{
    Candidacy, Effect, Envelope, PersonalError, Policy, RECOVERY, Recipient, Recorded,
};

use super::*;

/// A lapsed agent in its grace refuses pushes, the inbox, a slot and a
/// commit carrying no removal (or an add), and takes the recovery scope's
/// pushes, a removal, its commit, `alive` and the votes; reads are served.
/// A re-proof ends the grace.
#[test]
fn a_lapsed_agent_takes_removals_alive_and_votes_and_refuses_pushes() {
    let policy = Policy {
        lease_ms: 30 * DAY,
        ..Policy::DEFAULT
    };
    let mut home = Home::with(policy);
    home.pair(0, 1);
    home.push(0, envelope(scope(1), 1, 1, 100)).unwrap();
    home.pass(30 * DAY);
    assert!(home.overview().lapsed);
    assert_eq!(
        home.push(0, envelope(scope(1), 1, 2, 100)),
        Err(PersonalError::Lapsed)
    );
    home.push(0, envelope(RECOVERY, 1, 3, 100)).unwrap();
    let soon = home.now + HOUR_MS;
    assert_eq!(
        home.call::<u64>(
            sync(0),
            "put",
            ((Recipient::Devices, [1u8; 16]), (soon, vec![1u8]))
        ),
        Err(PersonalError::Lapsed)
    );
    assert_eq!(
        home.call::<u64>(sync(0), "open_slot", ([9u8; 16], [9u8; 32])),
        Err(PersonalError::Lapsed)
    );
    assert_eq!(
        home.call::<Candidacy>(admin(0), "commit", update(2, 1)),
        Err(PersonalError::Lapsed)
    );
    // A stolen phone is still removed.
    home.call::<Recorded>(sync(1), "alive", ()).unwrap();
    home.call::<Recorded>(admin(0), "remove", 1u32).unwrap();
    home.pass(72 * HOUR_MS);
    let adding = Effect {
        add: Some(device(2)),
        remove: vec![1],
    };
    assert_eq!(
        home.call::<Candidacy>(admin(0), "commit", commit(2, adding, vec![2; 700])),
        Err(PersonalError::Lapsed),
        "no add in the grace"
    );
    let removal = home.commit_removing(0, vec![1]);
    assert_eq!(removal.set, vec![0]);
    // Reads are served.
    let read: Vec<Envelope> = home.query(sync(0), "since", (scope(1), 0u64)).unwrap();
    assert_eq!(read.len(), 1);
    let kit_read: Vec<Envelope> = home.query(KIT, "since", (RECOVERY, 0u64)).unwrap();
    assert_eq!(kit_read.len(), 1);
    // A re-proof ends the grace.
    home.call::<Recorded>(HOMES, "renew", ()).unwrap();
    assert!(!home.overview().lapsed);
    home.push(0, envelope(scope(1), 2, 4, 100)).unwrap();
}

/// B9: the lease counts re-proofs, not uptime: an agent no batch reached
/// for months keeps its lease to the day; a push retried across the
/// outage is stored once.
#[test]
fn the_lease_counts_re_proofs_not_uptime() {
    let mut home = Home::new();
    let bytes = envelope(scope(1), 0, 1, 500);
    let first = home.push(0, bytes.clone()).unwrap();
    home.pass(300 * DAY);
    let retried = home.push(0, bytes).unwrap();
    assert_eq!(retried.position, first.position);
    let until = home.overview().lease_until;
    assert_eq!(until, T0 + 395 * DAY + 1, "from the assignment's batch");
    home.pass(until - home.now);
    assert!(!home.overview().lapsed);
    home.push(0, envelope(scope(1), 0, 2, 500)).unwrap();
    home.pass(1);
    assert!(home.overview().lapsed);
    home.call::<Recorded>(HOMES, "renew", ()).unwrap();
    let renewed = home.overview().lease_until;
    assert_eq!(renewed, home.now - 1 + 395 * DAY);
}
