//! The device set's operations (`light-node.md` §3.5) through the device
//! group: a contested removal resolved by two devices, a removal made
//! immediate by a second signature, a regroup into a new group, and a
//! restore with its new kit. Each device honours a maturity only once the
//! evidence the log carries supports it, a second signature's or a
//! resolution's posted after the maturity it made among it, so none of
//! these honest flows raises `Unsigned`.

use ed25519_dalek::SigningKey;
use vos_light::group::{Alarm, DeviceGroup, Event, GroupError, Restored, Why};
use vos_wire::Encode;
use vos_wire::personal::{
    DeviceView, NewKit, OpState, Operation, Overview, PersonalError, Recorded, RecoveryView, Woken,
    r2_hash,
};

use crate::home::Home;
use crate::phone::{Phone, kit, kit_entry};
use crate::{NOTES, agree, all, household, policy, settle};

/// A household of `count` phones, each seasoned and seen.
fn seasoned(count: u8) -> (Home, Vec<Phone>) {
    let (mut home, mut phones) = household(count);
    home.pass(policy().seasoning_ms);
    for phone in &mut phones {
        phone.alive(&mut home);
    }
    (home, phones)
}

/// `signer`'s call of `name` with `arguments`, its evidence posted under
/// `poster` with what rides beside it: the call's log index.
fn operate(
    home: &mut Home,
    signer: &SigningKey,
    poster: &SigningKey,
    name: &str,
    arguments: Vec<u8>,
    attached: Option<Vec<u8>>,
) -> u64 {
    let (index, message, signature) = unevidenced(home, signer, name, arguments);
    post(home, poster, index, message, signature, attached);
    index
}

/// `signer`'s call of `name` with `arguments`, no evidence posted yet:
/// its log index, and the message and signature its evidence carries.
fn unevidenced(
    home: &mut Home,
    signer: &SigningKey,
    name: &str,
    arguments: Vec<u8>,
) -> (u64, Vec<u8>, [u8; 64]) {
    let reply = home.call(signer, name, arguments);
    let index = reply.answer::<Recorded>().unwrap().index;
    (index, reply.message, reply.signature)
}

fn post(
    home: &mut Home,
    poster: &SigningKey,
    index: u64,
    message: Vec<u8>,
    signature: [u8; 64],
    attached: Option<Vec<u8>>,
) {
    home.call(
        poster,
        "evidence",
        ((index, message), (signature, attached)).encode(),
    )
    .answer::<Recorded>()
    .unwrap();
}

fn state(home: &Home, reader: &Phone, index: u64) -> OpState {
    home.query::<Operation>(reader.sync_key(), "operation", index.encode())
        .unwrap()
        .state
}

/// No event an alarm that the log asserts what its evidence does not
/// support.
fn signed(events: &[Vec<Event>]) {
    for events in events {
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::Alarm(Alarm::Unsigned { .. }))),
            "{events:?}"
        );
    }
}

/// The removals `phone`'s next commit would carry.
fn owed(home: &Home, phone: &mut Phone) -> Vec<u32> {
    let prepared = phone.group().commit(None, home.now).unwrap();
    phone.group().abandon().unwrap();
    prepared.effect.remove
}

/// What `phone`, its keys admitted no more, makes of the log as `reader`
/// relays it.
fn relayed(home: &Home, reader: &Phone, phone: &mut Phone) -> Vec<Event> {
    let cursor = phone.group().cursor();
    let entries = home.log(reader.sync_key(), cursor).unwrap();
    phone.group().follow(entries).unwrap()
}

/// A thief's device removes an owner's, whose removal of it in return makes
/// one contest; two other seasoned devices resolve it for the owner, the
/// second's resolution maturing the owner's removal and dropping the
/// thief's. The devices hold off until the second resolution's evidence
/// verifies, then the owner's commit carries the removal and the thief is
/// out.
#[test]
fn a_contested_removal_resolved_by_two_devices_is_carried() {
    let (mut home, mut phones) = seasoned(4);
    let (owners, thief) = phones.split_at_mut(3);
    let thief = &mut thief[0];
    let theirs = operate(
        &mut home,
        &thief.admin,
        &thief.sync,
        "remove",
        0u32.encode(),
        None,
    );
    let ours = operate(
        &mut home,
        &owners[0].admin,
        &owners[0].sync,
        "remove",
        3u32.encode(),
        None,
    );
    assert_eq!(state(&home, &owners[0], ours), OpState::Contested);
    home.pass(policy().operation_delay_ms);
    for owner in owners.iter_mut() {
        owner.alive(&mut home);
    }
    assert_eq!(state(&home, &owners[0], theirs), OpState::Contested);

    operate(
        &mut home,
        &owners[1].admin,
        &owners[1].sync,
        "resolve",
        (ours, true).encode(),
        None,
    );
    let (index, message, signature) = unevidenced(
        &mut home,
        &owners[2].admin,
        "resolve",
        (ours, true).encode(),
    );
    assert!(matches!(
        state(&home, &owners[0], ours),
        OpState::Matured { .. }
    ));
    assert!(matches!(
        state(&home, &owners[0], theirs),
        OpState::Cancelled { .. }
    ));
    signed(&settle(&mut home, &mut all(owners)));
    assert!(
        owed(&home, &mut owners[0]).is_empty(),
        "no device honours a resolution before its evidence"
    );
    post(&mut home, &owners[2].sync, index, message, signature, None);
    signed(&settle(&mut home, &mut all(owners)));
    assert_eq!(owed(&home, &mut owners[0]), vec![3]);

    let candidacy = owners[0].update(&mut home).unwrap();
    assert_eq!(candidacy.set, vec![0, 1, 2]);
    let events = settle(&mut home, &mut all(owners));
    signed(&events);
    for events in &events {
        assert!(
            events.contains(&Event::Confirmed { epoch: 4 }),
            "{events:?}"
        );
    }
    agree(&mut all(owners), 4);
    let events = relayed(&home, &owners[0], thief);
    assert!(events.contains(&Event::Removed), "{events:?}");
}

/// A removal made immediate by a second seasoned device's signature: it
/// matures in the cosign's call, before the cosign's evidence is posted;
/// the devices honour it once that evidence verifies, and the next
/// commit carries it.
#[test]
fn a_cosigned_removal_is_carried_once_its_cosign_verifies() {
    let (mut home, mut phones) = seasoned(3);
    let removal = operate(
        &mut home,
        &phones[0].admin,
        &phones[0].sync,
        "remove",
        2u32.encode(),
        None,
    );
    let (index, message, signature) =
        unevidenced(&mut home, &phones[1].admin, "cosign", removal.encode());
    assert!(matches!(
        state(&home, &phones[0], removal),
        OpState::Matured { .. }
    ));
    let (owners, _) = phones.split_at_mut(2);
    signed(&settle(&mut home, &mut all(owners)));
    assert!(owed(&home, &mut owners[0]).is_empty());
    post(&mut home, &owners[1].sync, index, message, signature, None);
    signed(&settle(&mut home, &mut all(owners)));
    assert_eq!(owed(&home, &mut owners[1]), vec![2]);

    let candidacy = owners[1].update(&mut home).unwrap();
    assert_eq!(candidacy.set, vec![0, 1]);
    let events = settle(&mut home, &mut all(owners));
    signed(&events);
    for events in &events {
        assert!(
            events.contains(&Event::Confirmed { epoch: 3 }),
            "{events:?}"
        );
    }
    agree(&mut all(owners), 3);
    let (owners, removed) = phones.split_at_mut(2);
    let events = relayed(&home, &owners[0], &mut removed[0]);
    assert!(events.contains(&Event::Removed), "{events:?}");
}

/// A regroup naming one device, made immediate by the kit's second
/// signature, voids the pending candidate; no commit but the regrouper's
/// new group comes next, which the device kept joins by its Welcome from
/// the key package it handed over. The new group's epochs count on from
/// the agent's, its keys new, and the named device is out.
#[test]
fn a_regroup_starts_a_new_group_with_the_rest() {
    let (mut home, mut phones) = seasoned(3);
    let before = agree(&mut all(&mut phones), 2);
    phones[1].update(&mut home).unwrap();
    let regroup = operate(
        &mut home,
        &phones[0].admin,
        &phones[0].sync,
        "regroup",
        vec![2u32].encode(),
        None,
    );
    operate(
        &mut home,
        &kit(0),
        &kit(0),
        "cosign",
        regroup.encode(),
        None,
    );
    let (kept, named) = phones.split_at_mut(2);
    let events = settle(&mut home, &mut all(kept));
    signed(&events);
    for events in &events {
        assert!(
            events.iter().any(|event| matches!(
                event,
                Event::Voided {
                    epoch: 3,
                    why: Why::Regroup,
                    ..
                }
            )),
            "{events:?}"
        );
    }
    assert!(matches!(
        kept[1].group().commit(None, home.now),
        Err(GroupError::Regroup)
    ));
    assert!(matches!(
        kept[1].group().regroup(Vec::new(), home.now),
        Err(GroupError::NoRegroup)
    ));

    let package = kept[1].group().regroup_package(home.now).unwrap();
    let prepared = kept[0].group().regroup(vec![package], home.now).unwrap();
    assert_eq!(prepared.effect.remove, vec![2]);
    let candidacy = kept[0].send(&mut home, &prepared).unwrap();
    assert_eq!(candidacy.set, vec![0, 1]);
    let events = settle(&mut home, &mut all(kept));
    signed(&events);
    for events in &events {
        assert!(
            events.contains(&Event::Confirmed { epoch: 3 }),
            "{events:?}"
        );
    }
    let after = agree(&mut all(kept), 3);
    assert_ne!(after, before);
    let events = relayed(&home, &kept[0], &mut named[0]);
    assert!(events.contains(&Event::Removed), "{events:?}");

    kept[1].update(&mut home).unwrap();
    let events = settle(&mut home, &mut all(kept));
    for events in &events {
        assert!(
            events.contains(&Event::Confirmed { epoch: 4 }),
            "{events:?}"
        );
    }
    agree(&mut all(kept), 4);
    assert_eq!(
        kept[0].group().archive().keys(3, &NOTES),
        &[after],
        "the archive records the new group's epochs"
    );
}

/// Wake the agent as `key` until nothing is left due.
fn woken(home: &mut Home, key: &SigningKey) {
    loop {
        let woken: Woken = home.call(key, "wake", ().encode()).answer().unwrap();
        if woken.settled {
            return;
        }
    }
}

/// Every device lost: the kit restores, carrying the next kit, its `R2`
/// in the evidence. At maturity the old devices see their removal under
/// the kit's verified evidence; the restore's device starts a new group
/// alone from what it reads of the agent, its first commit carrying every
/// removal, pairs a new phone, and follows the new kit's removal of it,
/// which the old kit can no longer sign.
#[test]
fn a_restore_starts_a_new_group_under_its_new_kit() {
    let (mut home, mut phones) = household(2);
    let mut restored = Phone::new(9);
    let next = kit(1);
    let r2 = [0x77; 32];
    let new_kit = NewKit {
        entries: vec![kit_entry(&next)],
        r2_hash: r2_hash(&r2),
    };
    operate(
        &mut home,
        &kit(0),
        &kit(0),
        "restore",
        (restored.keys.clone(), new_kit).encode(),
        Some(r2.to_vec()),
    );
    home.pass(policy().kit_delay_ms);
    home.call(&kit(0), "wake", ().encode())
        .answer::<Woken>()
        .unwrap();
    woken(&mut home, &restored.sync);
    for phone in &mut phones {
        let events = relayed(&home, &restored, phone);
        signed(std::slice::from_ref(&events));
        assert!(events.contains(&Event::Removed), "{events:?}");
        assert_eq!(
            home.log(phone.sync_key(), 0).map(|_| ()),
            Err(PersonalError::NotAdmitted)
        );
    }

    let overview: Overview = home
        .query(restored.sync_key(), "overview", ().encode())
        .unwrap();
    let devices: Vec<DeviceView> = home
        .query(restored.sync_key(), "devices", ().encode())
        .unwrap();
    let recovery: RecoveryView = home
        .query(restored.sync_key(), "recovery", ().encode())
        .unwrap();
    assert_eq!(recovery.released, Some([0xc4; 32]), "the previous R2");
    let read = Restored {
        next: overview.next,
        chain: overview.chain,
        time: home.now,
        confirmed: overview.confirmed,
        policy: policy(),
        kit: recovery.entries.iter().map(|entry| entry.signing).collect(),
        devices,
    };
    restored.group = Some(
        DeviceGroup::restore(&restored.store, home.agent(), restored.keys.clone(), read).unwrap(),
    );
    let epoch = overview.confirmed + 1;
    let candidacy = restored.update(&mut home).unwrap();
    assert_eq!(candidacy.set, vec![2]);
    let events = settle(&mut home, &mut [&mut restored]);
    assert!(
        events[0].contains(&Event::Confirmed { epoch }),
        "{events:?}"
    );

    let mut paired = Phone::new(10);
    restored.pair(&mut home, &mut paired);
    let events = settle(&mut home, &mut [&mut restored, &mut paired]);
    signed(&events);
    agree(&mut [&mut restored, &mut paired], epoch + 1);

    assert_eq!(
        home.call(&kit(0), "remove", 3u32.encode())
            .answer::<Recorded>(),
        Err(PersonalError::NotAdmitted),
        "the old kit signs nothing"
    );
    operate(&mut home, &next, &next, "remove", 3u32.encode(), None);
    home.pass(policy().kit_delay_ms);
    restored.alive(&mut home);
    signed(&settle(&mut home, &mut [&mut restored]));
    assert_eq!(owed(&home, &mut restored), vec![3]);
    let candidacy = restored.update(&mut home).unwrap();
    assert_eq!(candidacy.set, vec![2]);
    let events = settle(&mut home, &mut [&mut restored]);
    assert!(
        events[0].contains(&Event::Confirmed { epoch: epoch + 2 }),
        "{events:?}"
    );
}
