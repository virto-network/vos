//! The device set's operations (`light-node.md` §3.5) through the device
//! group: a contested removal resolved by two devices, a removal made
//! immediate by a second signature, a regroup into a new group, and a
//! restore with its new kit. Each device honours a maturity only once the
//! evidence the log carries supports it, a second signature's or a
//! resolution's posted after the maturity it made among it, so none of
//! these honest flows raises `Unsigned`; a maturity asserted before its
//! delay does, and a device that cannot follow regroups.

use ed25519_dalek::SigningKey;
use vos_abi::Encode;
use vos_light::group::{Alarm, Course, DeviceGroup, Event, GroupError, Remedy, Restored, Why};
use vos_light::kit::KitKey;
use vos_wire::personal::{
    Attached, Body, DeviceView, Effect, Entry, OpState, Operation, Overview, PersonalError,
    Recorded, RecoveryView, Woken, chain,
};

use crate::garble::{Anything, hostile};
use crate::home::Home;
use crate::phone::{Phone, kit, kit_key};
use crate::{NOTES, agree, all, commit_as, confirm_as, household, policy, settle};

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
/// `poster` with the `R2` that rides beside it: the call's log index.
pub(crate) fn operate(
    home: &mut Home,
    signer: &SigningKey,
    poster: &SigningKey,
    name: &str,
    arguments: Vec<u8>,
    r2: Option<[u8; 32]>,
) -> u64 {
    let (index, message, signature) = unevidenced(home, signer, name, arguments);
    post(home, poster, index, message, signature, r2);
    index
}

/// `signer`'s call of `name` with `arguments`, no evidence posted yet:
/// its log index, and the message and signature its evidence carries.
pub(crate) fn unevidenced(
    home: &mut Home,
    signer: &SigningKey,
    name: &str,
    arguments: Vec<u8>,
) -> (u64, Vec<u8>, [u8; 64]) {
    let reply = home.call(signer, name, arguments);
    let index = reply.answer::<Recorded>().unwrap().index;
    (index, reply.message, reply.signature)
}

pub(crate) fn post(
    home: &mut Home,
    poster: &SigningKey,
    index: u64,
    message: Vec<u8>,
    signature: [u8; 64],
    r2: Option<[u8; 32]>,
) {
    let attached = Attached { welcome: None, r2 };
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
    let prepared = phone.group().commit(None, home.now()).unwrap();
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

/// A regroup keeps its regrouper alone: one naming only some of the other
/// devices is refused; one naming them all, made immediate by the kit's
/// second signature, voids the pending candidate, and no commit but the
/// regrouper's new group of it alone comes next, carrying every other
/// device's removal. The new group's epochs count on from the agent's, its
/// keys new, and every other device is out: it pairs again.
#[test]
fn a_regroup_starts_a_new_group_of_its_regrouper_alone() {
    let (mut home, mut phones) = seasoned(3);
    let before = agree(&mut all(&mut phones), 2);
    phones[1].update(&mut home).unwrap();
    let partial = home.call(&phones[0].admin, "regroup", vec![2u32].encode());
    assert_eq!(
        partial.answer::<Recorded>(),
        Err(PersonalError::Malformed),
        "a regroup names every other live device"
    );
    let regroup = operate(
        &mut home,
        &phones[0].admin,
        &phones[0].sync,
        "regroup",
        vec![1u32, 2].encode(),
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
    let events = settle(&mut home, &mut all(&mut phones[..1]));
    signed(&events);
    assert!(
        events[0].iter().any(|event| matches!(
            event,
            Event::Voided {
                epoch: 3,
                why: Why::Regroup,
                ..
            }
        )),
        "{events:?}"
    );
    assert!(matches!(
        phones[0].group().commit(None, home.now()),
        Err(GroupError::Regroup)
    ));
    assert_eq!(phones[0].group().regrouper(), Some(0));

    let prepared = phones[0].group().regroup(home.now()).unwrap();
    assert_eq!(prepared.effect.remove, vec![1, 2]);
    let candidacy = phones[0].send(&mut home, &prepared).unwrap();
    assert_eq!(candidacy.set, vec![0]);
    let events = phones[0].read(&mut home);
    signed(std::slice::from_ref(&events));
    assert!(
        events.contains(&Event::Confirmed { epoch: 3 }),
        "{events:?}"
    );
    let after = agree(&mut all(&mut phones[..1]), 3);
    assert_ne!(after, before);
    assert_eq!(
        phones[0].group().regrouper(),
        None,
        "the new group confirmed"
    );
    let (regrouper, others) = phones.split_at_mut(1);
    for other in others {
        let events = relayed(&home, &regrouper[0], other);
        assert!(events.contains(&Event::Removed), "{events:?}");
        assert!(matches!(
            other.group().regroup(home.now()),
            Err(GroupError::Out)
        ));
    }
    assert_eq!(
        regrouper[0].group().archive().keys(3, &NOTES),
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

/// Every device lost: the kit restores, carrying the next kit, its `R`
/// drawn and held in the restoring device's store, its `R2` in the
/// evidence. At maturity the old devices see their removal under the
/// kit's verified evidence; the restore's device reads the previous `R2`
/// and the entries it went with, starts a new group alone from what it
/// reads of the agent, its `R` the kit's, its first commit carrying every
/// removal and re-sealing the kit, pairs a new phone, and follows the new
/// kit's removal of it, which the old kit can no longer sign.
#[test]
fn a_restore_starts_a_new_group_under_its_new_kit() {
    let (mut home, mut phones) = household(2);
    let mut restored = Phone::new(9);
    let next = kit_key(1);
    let split =
        vos_light::group::restoring(&restored.store, &[next], &home.agent(), |_| Vec::new())
            .unwrap();
    operate(
        &mut home,
        &kit(0),
        &kit(0),
        "restore",
        (restored.keys.clone(), split.kit.clone()).encode(),
        Some(*split.r2()),
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
            home.query::<Overview>(phone.sync_key(), "overview", Vec::new())
                .map(|_| ()),
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
    assert!(recovery.released.is_some(), "the previous R2");
    assert_eq!(
        recovery.previous.iter().map(KitKey::of).collect::<Vec<_>>(),
        vec![kit_key(0)],
        "the entries it went with"
    );
    let read = Restored {
        next: overview.next,
        chain: overview.chain,
        time: home.now(),
        confirmed: overview.confirmed,
        policy: policy(),
        kit: vec![next],
        r_hash: split.kit.r_hash,
        devices,
    };
    restored.group = Some(
        DeviceGroup::restore(&restored.store, home.agent(), restored.keys.clone(), read).unwrap(),
    );
    assert!(
        !restored.group().holds_recovery(),
        "its R travels from its first commit, which re-seals the kit"
    );
    assert_eq!(
        restored.group().archive().recovery.as_ref().unwrap().r,
        *split.r()
    );
    let epoch = overview.confirmed + 1;
    let prepared = restored.group().commit(None, home.now()).unwrap();
    assert_eq!(prepared.effect.remove, vec![0, 1]);
    assert!(
        prepared.effect.rekey.is_some(),
        "a removal re-seals the kit"
    );
    let candidacy = restored.send(&mut home, &prepared).unwrap();
    assert_eq!(candidacy.set, vec![2]);
    let events = settle(&mut home, &mut [&mut restored]);
    assert!(
        events[0].contains(&Event::Confirmed { epoch }),
        "{events:?}"
    );
    let recovery: RecoveryView = home
        .query(restored.sync_key(), "recovery", ().encode())
        .unwrap();
    assert_eq!(recovery.released, None, "deleted at its first commit");
    assert!(restored.group().holds_recovery());
    assert_ne!(
        restored.group().archive().recovery.as_ref().unwrap().r,
        *split.r(),
        "the commit's R"
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
    operate(&mut home, &kit(1), &kit(1), "remove", 3u32.encode(), None);
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

/// `entries` with `body` appended at batch time `at`, chained.
fn append(entries: &mut Vec<(u64, Entry)>, before: [u8; 32], at: u64, body: Body) -> u64 {
    let (index, last) = entries
        .last()
        .map_or((0, before), |(index, entry)| (index + 1, entry.chain));
    entries.push((
        index,
        Entry {
            at,
            chain: chain(&last, index, at, &body),
            body,
        },
    ));
    index
}

/// Operators assert that a removal matured before its delay passed, or
/// at a maturity time past the entry's own: neither is supported, so the
/// device raises `Unsigned` and owes no removal; and an entry whose batch
/// time goes back stops the reading.
#[test]
fn a_maturity_before_its_delay_is_unsigned() {
    let (mut home, mut phones) = seasoned(3);
    let removal = operate(
        &mut home,
        &phones[0].admin,
        &phones[0].sync,
        "remove",
        2u32.encode(),
        None,
    );
    let matures = home.now() + policy().operation_delay_ms;
    let (cursor, before) = phones[1].group().view();
    let mut entries = home.log(phones[1].sync_key(), cursor).unwrap();
    let early = append(
        &mut entries,
        before,
        home.now(),
        Body::Settled {
            op: removal,
            state: OpState::Matured { at: home.now() },
        },
    );
    append(
        &mut entries,
        before,
        home.now(),
        Body::Matured { device: 2 },
    );
    let events = phones[1].group().follow(entries).unwrap();
    assert!(
        events.contains(&Event::Alarm(Alarm::Unsigned { index: early })),
        "{events:?}"
    );

    let (cursor, before) = phones[0].group().view();
    let mut entries = home.log(phones[0].sync_key(), cursor).unwrap();
    let ahead = append(
        &mut entries,
        before,
        home.now(),
        Body::Settled {
            op: removal,
            state: OpState::Matured { at: matures },
        },
    );
    append(
        &mut entries,
        before,
        home.now(),
        Body::Matured { device: 2 },
    );
    let back = append(
        &mut entries,
        before,
        home.now() - 1,
        Body::Renewed { until: 0 },
    );
    let events = phones[0].group().follow(entries).unwrap();
    assert!(
        events.contains(&Event::Alarm(Alarm::Unsigned { index: ahead })),
        "{events:?}"
    );
    assert!(
        events.contains(&Event::Alarm(Alarm::Log { index: back })),
        "{events:?}"
    );
    for phone in &mut phones[..2] {
        assert!(owed(&home, phone).is_empty());
    }
}

/// A device that cannot follow, with no other device to pair from,
/// regroups: it reads on for the device set's operations while stuck,
/// follows the epoch it could not by the agent's word, and once its
/// regroup of the committer matures starts a new group alone, the first
/// commit after the confirmed epoch, carrying the removal.
#[test]
fn a_device_that_cannot_follow_regroups() {
    let (mut home, mut phones) = seasoned(2);
    home.pass(policy().confirm_window_ms + 1);
    phones[0].alive(&mut home);
    let mut attacker = hostile(
        &phones[0].store,
        Some(Vec::new()),
        Anything {
            path: true,
            encrypt: true,
        },
    );
    let output = attacker.commit_builder().build().unwrap();
    let handshake = output.commit_message.to_bytes().unwrap();
    attacker.apply_pending_commit().unwrap();
    let index = commit_as(&mut home, &phones[0], 2, Effect::default(), handshake, None);
    let h = vos_mls::confirmation(
        vos_light::group::CONFIRM,
        &crate::home::IDENTITY,
        2,
        &attacker.epoch_authenticator().unwrap(),
    );
    confirm_as(&mut home, &phones[0], 2, index, h);
    let events = phones[1].read(&mut home);
    assert!(
        events.contains(&Event::Alarm(Alarm::CannotFollow {
            epoch: 2,
            committer: 0,
            remedy: Remedy::Regroup,
        })),
        "{events:?}"
    );

    operate(
        &mut home,
        &phones[1].admin,
        &phones[1].sync,
        "regroup",
        vec![0u32].encode(),
        None,
    );
    home.pass(policy().operation_delay_ms);
    phones[1].alive(&mut home);
    signed(&[phones[1].read(&mut home)]);
    let prepared = phones[1].group().regroup(home.now()).unwrap();
    assert_eq!(prepared.epoch, 3);
    assert_eq!(prepared.effect.remove, vec![0]);
    let candidacy = phones[1].send(&mut home, &prepared).unwrap();
    assert_eq!(candidacy.set, vec![1]);
    let events = phones[1].read(&mut home);
    assert!(
        events.contains(&Event::Confirmed { epoch: 3 }),
        "{events:?}"
    );
    assert_eq!(phones[1].group().course(), Course::Following);
    phones[1].group().key(NOTES).unwrap();
}

/// A delayed admin's add waits its delay: its inline add is refused
/// (`Delayed`), so it signs an add operation; until it matures its commit
/// carrying the add is refused too; once it matured the delayed admin's
/// own commit carries it, and every device confirms the new phone.
#[test]
fn a_delayed_admins_add_waits_its_delay() {
    let mut home = Home::new(policy());
    let mut first = Phone::new(1);
    first.claim(&mut home);
    let mut delayed = Phone::delayed(2);
    first.pair(&mut home, &mut delayed);
    settle(&mut home, &mut [&mut first, &mut delayed]);
    home.pass(policy().seasoning_ms);
    first.alive(&mut home);
    delayed.alive(&mut home);

    let mut new = Phone::new(3);
    let attempt = |home: &mut Home, delayed: &mut Phone, new: &Phone| {
        let package = DeviceGroup::key_package(&new.store, &new.keys, home.now()).unwrap();
        let (prepared, _) = delayed
            .group()
            .pair(new.keys.clone(), package, home.now())
            .unwrap();
        delayed.send(home, &prepared)
    };
    assert_eq!(
        attempt(&mut home, &mut delayed, &new),
        Err(PersonalError::Delayed)
    );
    let add = operate(
        &mut home,
        &delayed.admin,
        &delayed.sync,
        "add",
        new.keys.encode(),
        None,
    );
    home.pass(policy().operation_delay_ms / 2);
    delayed.alive(&mut home);
    delayed.read(&mut home);
    assert_eq!(
        attempt(&mut home, &mut delayed, &new),
        Err(PersonalError::Delayed),
        "not before its delay"
    );
    home.pass(policy().operation_delay_ms / 2);
    first.alive(&mut home);
    delayed.alive(&mut home);
    signed(&settle(&mut home, &mut [&mut first, &mut delayed]));
    assert!(matches!(state(&home, &first, add), OpState::Matured { .. }));
    delayed.pair(&mut home, &mut new);
    let events = settle(&mut home, &mut [&mut first, &mut delayed, &mut new]);
    signed(&events);
    for events in &events {
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Event::Confirmed { .. })),
            "{events:?}"
        );
    }
    assert_eq!(new.group().id(), Some(2));
    let epoch = first.group().confirmed();
    agree(&mut [&mut first, &mut delayed, &mut new], epoch);
}

/// An admin key replaced (a biometric change): another seasoned device
/// signs the replacement, the new key signs from its maturity, the old one
/// no more, and the device's next commit renews its leaf to the new key,
/// which every device confirms, and the commits after it. A replacement
/// whose evidence never comes is cancelled at its due time: its key signs
/// nothing.
#[test]
fn a_replaced_admin_key_signs_and_renews_its_leaf() {
    let (mut home, mut phones) = seasoned(3);
    let new_admin = |n: u8| SigningKey::from_bytes(&[0x70 | n; 32]);
    let replacement = |key: &SigningKey| vos_wire::personal::NewAdmin {
        key: key.verifying_key().to_bytes(),
        class: vos_wire::personal::AdminClass::Strong,
        attestation: vos_wire::personal::Attestation {
            hardware: true,
            verified_boot: true,
        },
    };
    let fresh = new_admin(3);
    operate(
        &mut home,
        &phones[0].admin,
        &phones[0].sync,
        "replace",
        (2u32, replacement(&fresh)).encode(),
        None,
    );
    home.pass(policy().probation_ms);
    for phone in &mut phones {
        phone.alive(&mut home);
    }
    signed(&settle(&mut home, &mut all(&mut phones)));
    let old = std::mem::replace(&mut phones[2].admin, fresh);
    assert_eq!(
        home.call(&old, "remove", 0u32.encode())
            .answer::<Recorded>(),
        Err(PersonalError::NotAdmitted),
        "the old key signs nothing"
    );
    let epoch = phones[0].group().confirmed() + 1;
    phones[2].update(&mut home).unwrap();
    let events = settle(&mut home, &mut all(&mut phones));
    signed(&events);
    for events in &events {
        assert!(events.contains(&Event::Confirmed { epoch }), "{events:?}");
    }
    for n in [0, 2] {
        phones[n].update(&mut home).unwrap();
        signed(&settle(&mut home, &mut all(&mut phones)));
    }
    agree(&mut all(&mut phones), epoch + 2);

    // A replacement whose evidence never comes is cancelled at its due
    // time, as every device closes it: its key signs nothing.
    let late = new_admin(2);
    let (index, _, _) = unevidenced(
        &mut home,
        &phones[0].admin,
        "replace",
        (1u32, replacement(&late)).encode(),
    );
    home.pass(policy().probation_ms);
    for phone in &mut phones {
        phone.alive(&mut home);
    }
    signed(&settle(&mut home, &mut all(&mut phones)));
    assert!(matches!(
        home.query::<vos_wire::personal::Operation>(
            phones[0].sync_key(),
            "operation",
            index.encode()
        )
        .unwrap()
        .state,
        vos_wire::personal::OpState::Cancelled {
            why: vos_wire::personal::Cancel::Unevidenced,
            ..
        }
    ));
    phones[1].admin = late;
    assert_eq!(phones[1].update(&mut home), Err(PersonalError::NotAdmitted));
}

/// E29: a replacement contested and resolved upheld, by the kit, still
/// waits out the new key's probation. The agent matures it at its own
/// time; a maturity the operators assert before is unsupported, the
/// replacement open on every device until then.
#[test]
fn a_resolved_replacement_waits_out_its_probation() {
    let (mut home, mut phones) = seasoned(2);
    let fresh = SigningKey::from_bytes(&[0x73; 32]);
    let admin = vos_wire::personal::NewAdmin {
        key: fresh.verifying_key().to_bytes(),
        class: vos_wire::personal::AdminClass::Strong,
        attestation: vos_wire::personal::Attestation {
            hardware: true,
            verified_boot: true,
        },
    };
    let replacement = operate(
        &mut home,
        &phones[0].admin,
        &phones[0].sync,
        "replace",
        (1u32, admin).encode(),
        None,
    );
    operate(
        &mut home,
        &phones[1].admin,
        &phones[1].sync,
        "veto",
        replacement.encode(),
        None,
    );

    operate(
        &mut home,
        &kit(0),
        &kit(0),
        "resolve",
        (replacement, true).encode(),
        None,
    );
    assert_eq!(state(&home, &phones[0], replacement), OpState::Contested);

    let (cursor, before) = phones[0].group().view();
    let mut entries = home.log(phones[0].sync_key(), cursor).unwrap();
    let early = append(
        &mut entries,
        before,
        home.now(),
        Body::Settled {
            op: replacement,
            state: OpState::Matured { at: home.now() },
        },
    );
    let events = phones[0].group().follow(entries).unwrap();
    assert!(
        events.contains(&Event::Alarm(Alarm::Unsigned { index: early })),
        "{events:?}"
    );
    assert!(
        phones[1]
            .read(&mut home)
            .iter()
            .all(|event| !matches!(event, Event::Alarm(_))),
    );
    assert!(
        phones[1]
            .group()
            .operations()
            .iter()
            .any(|open| open.index == replacement),
        "open through its probation"
    );

    home.pass(policy().probation_ms);
    phones[1].alive(&mut home);
    let events = phones[1].read(&mut home);
    assert!(
        events.iter().all(|event| !matches!(event, Event::Alarm(_))),
        "{events:?}"
    );
    assert!(matches!(
        state(&home, &phones[1], replacement),
        OpState::Matured { .. }
    ));
    assert!(
        phones[1]
            .group()
            .operations()
            .iter()
            .all(|open| open.index != replacement)
    );
}
