//! The commit log: who may commit, one candidate an epoch, the confirming
//! set in the candidate's entry, the votes and the verdicts, and the
//! matured removals every commit carries.

use vos_wire::abi::Failure;
use vos_wire::personal::{
    Body, Candidacy, DeviceView, Effect, Entry, Overview, PersonalError, Policy, Recorded,
    Standing, Verdict, Void, Voted,
};

use super::*;

/// The gate: a commit from a sync key, or from an admin key whose device
/// may not commit (in probation, its removal matured, a delayed admin's
/// add inline), is refused, as is one from the kit, a stranger or the
/// home; an active device's admin key commits. A23: a sync key alone
/// commits nothing.
#[test]
fn a_commit_from_a_sync_key_or_a_device_that_may_not_commit_is_refused() {
    let mut home = Home::new();
    for caller in [sync(0), KIT, STRANGER, HOMES] {
        assert_eq!(
            home.call::<Candidacy>(caller, "commit", update(1, 1)),
            Err(if caller == sync(0) {
                PersonalError::SyncKey
            } else {
                PersonalError::NotAdmitted
            }),
            "{caller:?}"
        );
        assert_eq!(
            home.call::<Recorded>(caller, "remove", 0u32),
            Err(if caller == sync(0) {
                PersonalError::SyncKey
            } else {
                PersonalError::NotAdmitted
            }),
            "{caller:?}'s removal"
        );
    }
    // Device 1 paired: in probation it commits nothing, nor removes.
    home.pair(0, 1);
    assert_eq!(
        home.call::<Candidacy>(admin(1), "commit", update(2, 1)),
        Err(PersonalError::Probation)
    );
    assert_eq!(
        home.call::<Recorded>(admin(1), "remove", 0u32),
        Err(PersonalError::Probation)
    );
    assert_eq!(
        home.call::<Candidacy>(sync(1), "commit", update(2, 1)),
        Err(PersonalError::SyncKey)
    );
    // Its probation over, it commits.
    home.pass(72 * HOUR_MS);
    let candidacy: Candidacy = home.call(admin(1), "commit", update(2, 1)).unwrap();
    home.confirm_all(2, &candidacy.set);
    // A delayed admin's add waits as an operation first: never inline.
    home.pair_keys(0, delayed(2));
    home.pass(72 * HOUR_MS);
    let effect = Effect {
        add: Some(device(3)),
        remove: Vec::new(),
    };
    assert_eq!(
        home.call::<Candidacy>(admin(2), "commit", commit(4, effect, vec![4; 600])),
        Err(PersonalError::Delayed)
    );
    // Device 1's removal matured: its admin key commits nothing.
    home.call::<Recorded>(admin(0), "remove", 1u32).unwrap();
    home.pass(72 * HOUR_MS);
    for caller in [admin(1), sync(1)] {
        assert_eq!(
            home.call::<Candidacy>(caller, "commit", update(4, 9)),
            Err(PersonalError::NotAdmitted),
            "its keys admitted no more once the removal matured"
        );
    }
}

/// One candidate an epoch, the confirmed epoch plus one; A10: a commit
/// re-sent answers as it did, and once decided is refused, so a commit is
/// a candidate once; a void frees the epoch for another.
#[test]
fn one_candidate_an_epoch_and_a_commit_is_a_candidate_once() {
    let mut home = Home::new();
    assert_eq!(
        home.call::<Candidacy>(admin(0), "commit", update(2, 1)),
        Err(PersonalError::EpochGap { confirmed: 0 })
    );
    let first: Candidacy = home.call(admin(0), "commit", update(1, 1)).unwrap();
    assert_eq!(first.set, vec![0]);
    assert_eq!(
        home.call::<Candidacy>(admin(0), "commit", update(1, 2)),
        Err(PersonalError::EpochTaken)
    );
    let again: Candidacy = home.call(admin(0), "commit", update(1, 1)).unwrap();
    assert_eq!((again.index, again.set), (first.index, first.set.clone()));
    let voted: Voted = home.call(sync(0), "nack", (1u64, [0u8; 64])).unwrap();
    assert_eq!(voted.verdict, Some(Verdict::Void(Void::Nack)));
    assert_eq!(
        home.call::<Candidacy>(admin(0), "commit", update(1, 1)),
        Err(PersonalError::Decided)
    );
    let other: Candidacy = home.call(admin(0), "commit", update(1, 2)).unwrap();
    home.confirm_all(1, &other.set);
    let overview = home.overview();
    assert_eq!((overview.confirmed, overview.candidate), (1, None));
    assert_eq!(
        home.call::<Candidacy>(admin(0), "commit", update(2, 2)),
        Err(PersonalError::Decided),
        "the confirmed commit is a candidate no more"
    );
}

/// The confirming set is the devices seen by a call within the window, in
/// probation or active; the candidate's log entry holds it; a device
/// outside it votes nothing, and the set's votes with one `h` confirm.
#[test]
fn the_confirming_set_is_the_devices_seen_in_the_window_and_is_logged() {
    let mut home = Home::new();
    home.pair(0, 1);
    home.pair(0, 2);
    home.call::<Recorded>(sync(2), "alive", ()).unwrap();
    home.pass(73 * HOUR_MS);
    // Device 1 calls inside the window; device 2's last call is older.
    home.call::<Recorded>(sync(1), "alive", ()).unwrap();
    home.pass(HOUR_MS);
    let candidacy: Candidacy = home.call(admin(0), "commit", update(3, 7)).unwrap();
    assert_eq!(candidacy.set, vec![0, 1]);
    let entries: Vec<(u64, Entry)> = home.query(sync(0), "log", candidacy.index).unwrap();
    match &entries[0].1.body {
        Body::Candidate { set, epoch, by, .. } => {
            assert_eq!((set.clone(), *epoch, *by), (vec![0, 1], 3, 0));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        home.call::<Voted>(sync(2), "confirm", (3u64, [3u8; 32], [0u8; 64])),
        Err(PersonalError::NotConfirming)
    );
    let voted: Voted = home
        .call(sync(1), "confirm", (3u64, [3u8; 32], [0u8; 64]))
        .unwrap();
    assert_eq!(voted.verdict, None, "the set is not complete");
    assert_eq!(
        home.call::<Voted>(sync(1), "confirm", (3u64, [3u8; 32], [0u8; 64])),
        Err(PersonalError::Voted)
    );
    let voted: Voted = home
        .call(sync(0), "confirm", (3u64, [3u8; 32], [0u8; 64]))
        .unwrap();
    assert_eq!(voted.verdict, Some(Verdict::Confirmed([3; 32])));
    assert_eq!(home.overview().confirmed, 3);
    assert_eq!(
        home.call::<Voted>(sync(0), "confirm", (3u64, [3u8; 32], [0u8; 64])),
        Err(PersonalError::NoCandidate)
    );
}

/// A nack voids a candidate, and so do a second `h` from its set and its
/// window passing without the set complete; each void frees the epoch and
/// drops the device the candidate added, whose keys are admitted no more.
#[test]
fn a_nack_a_second_h_or_the_window_voids_a_candidate() {
    let mut home = Home::new();
    home.pair(0, 1);
    home.pass(72 * HOUR_MS);
    home.call::<Recorded>(sync(1), "alive", ()).unwrap();
    // Two `h` from the set.
    let candidacy: Candidacy = home.call(admin(0), "commit", update(2, 1)).unwrap();
    assert_eq!(candidacy.set, vec![0, 1]);
    home.call::<Voted>(sync(0), "confirm", (2u64, [1u8; 32], [0u8; 64]))
        .unwrap();
    let voted: Voted = home
        .call(sync(1), "confirm", (2u64, [2u8; 32], [0u8; 64]))
        .unwrap();
    assert_eq!(voted.verdict, Some(Verdict::Void(Void::Split)));
    // A window without the set: the add it carried is dropped.
    let effect = Effect {
        add: Some(device(2)),
        remove: Vec::new(),
    };
    let candidacy: Candidacy = home
        .call(admin(0), "commit", commit(2, effect, vec![2; 900]))
        .unwrap();
    home.call::<Voted>(sync(0), "confirm", (2u64, [1u8; 32], [0u8; 64]))
        .unwrap();
    home.call::<Recorded>(sync(2), "alive", ()).unwrap();
    home.pass(72 * HOUR_MS);
    home.call::<Recorded>(sync(1), "alive", ()).unwrap();
    let overview = home.overview();
    assert_eq!((overview.confirmed, overview.candidate), (1, None));
    let entries: Vec<(u64, Entry)> = home.query(sync(0), "log", candidacy.index).unwrap();
    assert!(entries.iter().any(|(_, entry)| entry.body
        == Body::Verdict {
            epoch: 2,
            verdict: Verdict::Void(Void::Timeout)
        }));
    let devices: Vec<DeviceView> = home.query(sync(0), "devices", ()).unwrap();
    assert_eq!(devices[2].standing, Standing::Dropped);
    assert_eq!(
        home.call::<Recorded>(sync(2), "alive", ()),
        Err(PersonalError::NotAdmitted)
    );
    assert!(
        home.node
            .get(&vos_wire::keys::admitted(PERSONAL, &device(2).sync))
            .is_none()
    );
    // A nack from the set.
    home.call::<Candidacy>(admin(0), "commit", update(2, 3))
        .unwrap();
    let voted: Voted = home.call(sync(1), "nack", (2u64, [0u8; 64])).unwrap();
    assert_eq!(voted.verdict, Some(Verdict::Void(Void::Nack)));
    let overview: Overview = home.overview();
    assert_eq!((overview.confirmed, overview.candidate), (1, None));
}

/// A20: two attacker devices with their removals matured are both removed
/// by one commit carrying both, whose set leaves them out and whose votes
/// they cannot cast; a commit must carry every matured removal and only
/// those; and a device whose removal matures while a candidate waits has
/// no voice in it, the others' confirmations deciding it then.
#[test]
fn one_commit_carries_every_matured_removal_and_removed_devices_have_no_voice() {
    let mut home = Home::new();
    for n in 1..=4 {
        home.pair(0, n);
    }
    home.pass(72 * HOUR_MS);
    for n in 1..=4 {
        home.call::<Recorded>(sync(n), "alive", ()).unwrap();
    }
    home.call::<Recorded>(admin(0), "remove", 3u32).unwrap();
    home.call::<Recorded>(admin(1), "remove", 4u32).unwrap();
    assert_eq!(
        home.call::<Recorded>(admin(2), "remove", 4u32),
        Err(PersonalError::Pending)
    );
    let epoch = home.overview().confirmed + 1;
    let removing = |remove: Vec<u32>| commit(epoch, Effect { add: None, remove }, vec![0x33; 650]);
    assert_eq!(
        home.call::<Candidacy>(admin(0), "commit", removing(vec![3])),
        Err(PersonalError::NotMatured(3)),
        "not yet matured"
    );
    home.pass(72 * HOUR_MS);
    // The removals matured: the attackers' liveness is refused.
    for n in [3, 4] {
        assert_eq!(
            home.call::<Recorded>(sync(n), "alive", ()),
            Err(PersonalError::NotAdmitted)
        );
    }
    assert_eq!(
        home.call::<Candidacy>(admin(0), "commit", update(epoch, 5)),
        Err(PersonalError::MissingRemoval(3))
    );
    assert_eq!(
        home.call::<Candidacy>(admin(0), "commit", removing(vec![3])),
        Err(PersonalError::MissingRemoval(4))
    );
    assert_eq!(
        home.call::<Candidacy>(admin(0), "commit", removing(vec![3, 4, 2])),
        Err(PersonalError::NotMatured(2))
    );
    for n in [1, 2] {
        home.call::<Recorded>(sync(n), "alive", ()).unwrap();
    }
    let candidacy: Candidacy = home.call(admin(0), "commit", removing(vec![3, 4])).unwrap();
    assert_eq!(candidacy.set, vec![0, 1, 2]);
    for n in [3, 4] {
        assert_eq!(
            home.call::<Voted>(sync(n), "nack", (epoch, [0u8; 64])),
            Err(PersonalError::NotAdmitted),
            "a matured device's keys are admitted no more"
        );
    }
    home.confirm_all(epoch, &candidacy.set);
    let devices: Vec<DeviceView> = home.query(sync(0), "devices", ()).unwrap();
    for n in [3, 4] {
        assert_eq!(devices[n].standing, Standing::Removed);
        assert_eq!(devices[n].removal.unwrap().committed, Some(epoch));
    }
    // Carried: the next commit owes nothing.
    let next: Candidacy = home.call(admin(0), "commit", update(epoch + 1, 6)).unwrap();
    home.confirm_all(epoch + 1, &next.set);

    // Device 2's removal matures while a candidate waits on it: once the
    // others confirmed, the maturity decides it.
    home.call::<Recorded>(admin(0), "remove", 2u32).unwrap();
    home.pass(70 * HOUR_MS);
    let epoch = epoch + 2;
    let candidacy: Candidacy = home.call(admin(0), "commit", update(epoch, 7)).unwrap();
    assert_eq!(candidacy.set, vec![0, 1, 2]);
    for n in [0, 1] {
        let voted: Voted = home
            .call(sync(n), "confirm", (epoch, [7u8; 32], [0u8; 64]))
            .unwrap();
        assert_eq!(voted.verdict, None);
    }
    home.pass(2 * HOUR_MS);
    assert_eq!(
        home.call::<Voted>(sync(2), "nack", (epoch, [0u8; 64])),
        Err(PersonalError::NotAdmitted)
    );
    // A refused call's writes are none: the next call settles it.
    assert_eq!(home.overview().confirmed, epoch - 1);
    home.call::<Recorded>(sync(1), "alive", ()).unwrap();
    assert_eq!(home.overview().confirmed, epoch);
    assert_eq!(
        home.call::<Candidacy>(admin(0), "commit", update(epoch + 1, 8)),
        Err(PersonalError::MissingRemoval(2))
    );
}

/// The home's calls take the role `homes`: no other caller assigns,
/// configures or renews, and an agent is assigned once. Nothing else is
/// taken before the assignment.
#[test]
fn only_the_home_assigns_and_once() {
    let mut home = Home::installed();
    assert_eq!(
        home.call::<Recorded>(sync(0), "alive", ()),
        Err(PersonalError::Unassigned)
    );
    for caller in [sync(0), STRANGER] {
        assert_eq!(
            home.refused(caller, "assign", (device(0), kit())),
            Failure::Forbidden
        );
        assert_eq!(
            home.refused(caller, "configure", Policy::DEFAULT),
            Failure::Forbidden
        );
        assert_eq!(home.refused(caller, "renew", ()), Failure::Forbidden);
    }
    assert_eq!(
        home.call::<Recorded>(HOMES, "renew", ()),
        Err(PersonalError::Unassigned)
    );
    let mut sharing = kit();
    sharing.entries[0].signing = device(0).admin;
    assert_eq!(
        home.call::<Recorded>(HOMES, "assign", (device(0), sharing)),
        Err(PersonalError::KeyTaken)
    );
    home.call::<Recorded>(HOMES, "assign", (device(0), kit()))
        .unwrap();
    assert_eq!(
        home.call::<Recorded>(HOMES, "assign", (device(1), kit())),
        Err(PersonalError::Assigned)
    );
    let devices: Vec<DeviceView> = home.query(KIT, "devices", ()).unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].standing, Standing::Active, "the claiming device");
}

/// A removal that matured inside a candidate's window decides it as the
/// window's end would have, however late the next call comes: the other
/// devices of its set had confirmed, so it is confirmed, not timed out.
#[test]
fn a_maturity_inside_the_window_decides_before_the_timeout() {
    let mut home = Home::new();
    home.pair(0, 1);
    home.pass(62 * HOUR_MS);
    home.call::<Recorded>(sync(1), "alive", ()).unwrap();
    home.call::<Recorded>(admin(0), "remove", 1u32).unwrap();
    home.pass(62 * HOUR_MS);
    let candidacy: Candidacy = home.call(admin(0), "commit", update(2, 2)).unwrap();
    assert_eq!(candidacy.set, vec![0, 1]);
    home.call::<Voted>(sync(0), "confirm", (2u64, [2u8; 32], [0u8; 64]))
        .unwrap();
    // Device 1's removal matures 10 h into the window; no call comes
    // until well past its end.
    home.pass(80 * HOUR_MS);
    home.call::<Recorded>(sync(0), "alive", ()).unwrap();
    assert_eq!(home.overview().confirmed, 2);
    let entries: Vec<(u64, Entry)> = home.query(sync(0), "log", candidacy.index).unwrap();
    assert!(entries.iter().any(|(_, entry)| entry.body
        == Body::Verdict {
            epoch: 2,
            verdict: Verdict::Confirmed([2; 32])
        }));
}

/// `alive` is logged at most once an hour a device: posted more often it
/// answers the entry logged last, so liveness cannot grow the log.
#[test]
fn alive_grows_the_log_at_most_once_an_hour() {
    let mut home = Home::new();
    let first: Recorded = home.call(sync(0), "alive", ()).unwrap();
    for _ in 0..20 {
        let again: Recorded = home.call(sync(0), "alive", ()).unwrap();
        assert_eq!(again.index, first.index);
    }
    home.pass(HOUR_MS);
    let later: Recorded = home.call(sync(0), "alive", ()).unwrap();
    assert_eq!(later.index, first.index + 1);
}
