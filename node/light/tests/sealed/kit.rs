//! The recovery kit through the device group and sealed sync against
//! `Personal` (`light-node.md` §3.5): a phrase kit and a security-key kit
//! made and rotated; a restore on a fresh store, reading the personal
//! space back; a restore cancelled by
//! liveness and the kit rotated after it; a contested removal resolved by
//! the kit; the kit alone removing a phone that holds only a sync key; and
//! `R` rotated at a removal, so the removed device opens nothing the
//! recovery scope holds after it (§3.6, D3).

use vos_light::group::{Alarm, Archive, DeviceGroup, Event, Restored};
use vos_light::job::{Commit, owed_commit};
use vos_light::kit::{self, KitKey, KitSecret, Split};
use vos_light::personal::recover;
use vos_wire::personal::{
    Attached, DeviceView, OpState, Operation, Overview, Recorded, RecoveryView, Woken,
};

use super::*;
use crate::phone::Touch;

/// A home claimed by phone 1 with the kit of `keys`, `count - 1` more
/// phones paired, every phone seasoned and seen, the notes actor
/// installed on each and its scope tracked: the claim's split too.
pub(super) fn household_with(count: u8, keys: Vec<KitKey>) -> (Home, Vec<Phone>, Split) {
    let homes = SigningKey::from_bytes(&[0x50; 32]);
    let mut home = Home::new(&homes, policy());
    let mut phones: Vec<Phone> = (1..=count).map(Phone::new).collect();
    let split = phones[0].claim_with(&mut home, &homes, keys);
    for n in 1..count as usize {
        let (paired, rest) = phones.split_at_mut(n);
        paired[0].pair(&mut home, &mut rest[0]);
        settle(&mut home, &mut phones[..=n]);
        phones[n].alive(&mut home);
    }
    home.pass(policy().probation_ms + policy().seasoning_ms);
    for phone in &mut phones {
        phone.alive(&mut home);
        install(&phone.light, NOTES);
        let scope = scope_of(phone, NOTES);
        phone.group().key(scope).unwrap();
    }
    (home, phones, split)
}

/// `signer`'s admin call of `name`, its evidence posted under `poster`
/// with `r2` beside it: its log index.
pub(super) fn operate(
    home: &mut Home,
    signer: &SigningKey,
    poster: &SigningKey,
    name: &str,
    arguments: Vec<u8>,
    r2: Option<[u8; 32]>,
) -> u64 {
    let reply = home.call(signer, name, arguments);
    let index = reply.answer::<Recorded>().unwrap().index;
    let attached = Attached { welcome: None, r2 };
    home.call(
        poster,
        "evidence",
        ((index, reply.message), (reply.signature, attached)).encode(),
    )
    .answer::<Recorded>()
    .unwrap();
    index
}

fn state(home: &Home, reader: [u8; 32], index: u64) -> OpState {
    home.query::<Operation>(reader, "operation", index.encode())
        .unwrap()
        .state
}

/// The `R` `phone` holds.
pub(super) fn r_of(phone: &mut Phone) -> [u8; 32] {
    phone.group().archive().recovery.as_ref().unwrap().r
}

/// Each phone's archive read and pushed, then its recovery envelopes, in
/// turn, twice: what a sync round does.
pub(super) fn sync_keys(home: &mut Home, phones: &mut [Phone]) {
    for _ in 0..2 {
        for phone in phones.iter_mut() {
            with(home, phone, &[], |sync| sync.archive()).unwrap();
            with(home, phone, &[], |sync| sync.recovery()).unwrap();
        }
    }
}

/// The recovery scope's envelopes the kit `key` reads: those after its
/// kit's last re-seal.
pub(super) fn kit_reads(home: &Home, key: &KitSecret) -> Vec<Envelope> {
    home.query(key.key().signing, "since", (RECOVERY, 0u64).encode())
        .unwrap()
}

/// Phone `n`, a fresh install, opens a restore signed by `kit`, carrying
/// the next kit `next`, its `R` held in its store: the phone, the split
/// and the restore's log index.
pub(super) fn open_restore(
    home: &mut Home,
    kit: &KitSecret,
    next: &KitSecret,
    n: u8,
) -> (Phone, Split, u64) {
    let restoring = Phone::new(n);
    let split = vos_light::group::restoring(&restoring.store, &[next.key()], &home.agent(), |_| {
        Vec::new()
    })
    .unwrap();
    let signing = kit.signing();
    let index = operate(
        home,
        &signing,
        &signing,
        "restore",
        (restoring.keys.clone(), split.kit.clone()).encode(),
        Some(*split.r2()),
    );
    (restoring, split, index)
}

/// The restore matured: `kit` wakes the agent, and the restored phone
/// recovers the archive from the recovery scope.
pub(super) fn matured(home: &mut Home, kit: &KitSecret, restored: &Phone) -> Archive {
    home.pass(policy().kit_delay_ms);
    home.call(&kit.signing(), "wake", ().encode())
        .answer::<Woken>()
        .unwrap();
    loop {
        let woken: Woken = home
            .call(&restored.sync, "wake", ().encode())
            .answer()
            .unwrap();
        if woken.settled {
            break;
        }
    }
    let view: RecoveryView = home
        .query(restored.sync_key(), "recovery", ().encode())
        .unwrap();
    let envelopes = stored(home, restored, RECOVERY);
    recover(kit, &view, &home.identity, &envelopes).expect("the kit recovers the archive")
}

/// The restored phone's new group at its home, from what it reads there.
pub(super) fn restart(home: &Home, restored: &mut Phone, split: &Split, next: &KitSecret) {
    let overview: Overview = home
        .query(restored.sync_key(), "overview", ().encode())
        .unwrap();
    let devices: Vec<DeviceView> = home
        .query(restored.sync_key(), "devices", ().encode())
        .unwrap();
    let read = Restored {
        next: overview.next,
        chain: overview.chain,
        time: home.now(),
        confirmed: overview.confirmed,
        policy: policy(),
        kit: vec![next.key()],
        r_hash: split.kit.r_hash,
        devices,
    };
    restored.group = Some(
        DeviceGroup::restore(&restored.store, home.agent(), restored.keys.clone(), read).unwrap(),
    );
}

/// Notes set on each phone, pushed, and the keys pushed to the recovery
/// scope: what a restore reads back.
pub(super) fn written(home: &mut Home, phones: &mut [Phone]) {
    for (n, phone) in phones.iter_mut().enumerate() {
        set(&phone.light, NOTES, n as u64, 10 + n as u64);
        with(home, phone, &[NOTES], |sync| sync.push(NOTES)).unwrap();
    }
    sync_keys(home, phones);
}

/// A phrase kit and a security-key kit: the phrase shown once as 24
/// words, which name it again; the security key's `hmac-secret` the same
/// 32 bytes at every touch, never shown. A claim seals `R1` to both, each
/// opens it and not the other's, and `R1 ⊕ R2` is the device's `R`. A
/// device rotates the kit to a new phrase and a new security key, a
/// second seasoned device's signature making it immediate: the new kit's
/// `R` is the rotating device's from its verified maturity and the other
/// device's from its archive, the recovery scope re-sealed under it for
/// the new kit, and the old kit admitted no more.
#[test]
fn phrase_and_security_key_kits_are_made_and_rotated() {
    let phrase = KitSecret::phrase().unwrap();
    let words = phrase.words().unwrap();
    assert_eq!(words.split(' ').count(), kit::WORDS);
    assert_eq!(KitSecret::from_words(&words).unwrap().key(), phrase.key());
    let short: Vec<&str> = words.split(' ').take(23).collect();
    assert!(KitSecret::from_words(&short.join(" ")).is_none());
    let key = KitSecret::security_key(&mut Touch(7)).unwrap();
    assert_eq!(
        KitSecret::security_key(&mut Touch(7)).unwrap().key(),
        key.key(),
        "the same at every touch"
    );
    assert!(key.words().is_none());
    assert_ne!(key.key().signing, phrase.key().signing);

    let (mut home, mut phones, split) = household_with(2, vec![phrase.key(), key.key()]);
    for (at, kit) in [&phrase, &key].into_iter().enumerate() {
        let r1 = kit.open_r1(&split.kit.entries[at], &home.identity).unwrap();
        assert_eq!(*kit::join(&r1, split.r2()), *split.r());
        assert!(
            kit.open_r1(&split.kit.entries[1 - at], &home.identity)
                .is_none()
        );
    }
    assert_eq!(r_of(&mut phones[0]), *split.r());
    assert_eq!(r_of(&mut phones[1]), *split.r(), "pairing carries R");

    let next_phrase = KitSecret::phrase().unwrap();
    let next_key = KitSecret::security_key(&mut Touch(8)).unwrap();
    let rotation = phones[0]
        .group()
        .rotate(&[next_phrase.key(), next_key.key()])
        .unwrap();
    let (admin, sync) = (phones[0].admin.clone(), phones[0].sync.clone());
    let index = operate(
        &mut home,
        &admin,
        &sync,
        "rotate",
        rotation.kit.encode(),
        Some(*rotation.r2()),
    );
    assert_eq!(
        r_of(&mut phones[0]),
        *split.r(),
        "held aside until it matures"
    );
    let (admin, sync) = (phones[1].admin.clone(), phones[1].sync.clone());
    operate(&mut home, &admin, &sync, "cosign", index.encode(), None);
    assert!(matches!(
        state(&home, phones[0].sync_key(), index),
        OpState::Matured { .. }
    ));
    settle(&mut home, &mut phones);
    assert!(phones[0].group().holds_recovery());
    assert_eq!(r_of(&mut phones[0]), *rotation.r());
    assert!(!phones[1].group().holds_recovery(), "an archive brings it");
    sync_keys(&mut home, &mut phones);
    assert!(phones[1].group().holds_recovery());
    assert_eq!(r_of(&mut phones[1]), *rotation.r());
    assert_eq!(
        phones[1].group().kit(),
        &[next_phrase.key(), next_key.key()]
    );

    let view: RecoveryView = home
        .query(phones[0].sync_key(), "recovery", ().encode())
        .unwrap();
    for (at, kit) in [&next_phrase, &next_key].into_iter().enumerate() {
        let r1 = kit.open_r1(&view.entries[at], &home.identity).unwrap();
        assert_eq!(*kit::join(&r1, rotation.r2()), *rotation.r());
        let recovered = open_recovery(rotation.r(), &home.identity, &kit_reads(&home, kit));
        assert_eq!(
            recovered.unwrap().naming,
            phones[0].group().archive().naming,
            "re-sealed under the new R"
        );
    }
    assert_eq!(
        home.query::<RecoveryView>(phrase.key().signing, "recovery", ().encode()),
        Err(PersonalError::NotAdmitted),
        "the old kit is admitted no more"
    );
}

/// Every device lost: a fresh install enters the phrase's words, opens the
/// restore with a new kit (the rotation every restore is), and once it
/// matured reads the previous `R2`, opens `R1` with the kit, recovers the
/// archive from the recovery scope, starts its group, and reads back the
/// notes the old phones wrote; its first commit re-seals the kit under a
/// new `R`.
#[test]
fn a_restore_here_reads_the_personal_space_back() {
    let phrase = KitSecret::phrase().unwrap();
    let words = phrase.words().unwrap();
    let (mut home, mut phones, _) = household_with(2, vec![phrase.key()]);
    written(&mut home, &mut phones);
    drop(phones);

    let kit = KitSecret::from_words(&words).unwrap();
    let next = KitSecret::phrase().unwrap();
    let (mut restored, split, _) = open_restore(&mut home, &kit, &next, 9);
    let archive = matured(&mut home, &kit, &restored);
    restart(&home, &mut restored, &split, &next);
    restored.group().inherit(&archive).unwrap();
    install(&restored.light, NOTES);
    let caught = with(&mut home, &mut restored, &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert!(caught.passed.is_empty(), "{:?}", caught.passed);
    for n in 0..2 {
        assert_eq!(count(&restored.light, NOTES, n), Some(10 + n));
    }

    let before = r_of(&mut restored);
    assert_eq!(before, *split.r(), "the restore's R");
    let epoch = restored.group().confirmed() + 1;
    let prepared = restored.group().commit(None, home.now()).unwrap();
    assert_eq!(prepared.effect.remove, vec![0, 1]);
    restored.send(&mut home, &prepared).unwrap();
    restored.read(&mut home);
    assert_eq!(restored.group().confirmed(), epoch);
    assert_ne!(r_of(&mut restored), before, "re-sealed at its first commit");
    set(&restored.light, NOTES, 5, 15);
    with(&mut home, &mut restored, &[NOTES], |sync| sync.push(NOTES)).unwrap();
    let kept = with(&mut home, &mut restored, &[], |sync| sync.recovery()).unwrap();
    assert!(kept.pushed > 0);
    let r = r_of(&mut restored);
    let recovered = open_recovery(&r, &home.identity, &kit_reads(&home, &next)).unwrap();
    assert!(
        !recovered
            .keys(epoch, &scope_of(&restored, NOTES))
            .is_empty(),
        "the new kit's copy holds the new epoch's keys"
    );
}

/// A leaked kit's restore: every device shows the kit's operation and
/// answers it with `alive`, which cancels it; then the owner rotates the
/// kit, two devices making it immediate, and the leaked kit signs nothing
/// more.
#[test]
fn liveness_cancels_a_restore_and_the_kit_is_rotated() {
    let leaked = KitSecret::phrase().unwrap();
    let (mut home, mut phones, _) = household_with(2, vec![leaked.key()]);
    let next = KitSecret::phrase().unwrap();
    let (stranger, _, index) = open_restore(&mut home, &leaked, &next, 9);
    let mut events = Vec::new();
    for phone in phones.iter_mut() {
        events.push(phone.read(&mut home));
    }
    assert!(
        events[0].contains(&Event::Alarm(Alarm::Kit { index })),
        "{events:?}"
    );
    assert!(matches!(
        state(&home, phones[0].sync_key(), index),
        OpState::Cancelled {
            why: vos_wire::personal::Cancel::Alive,
            ..
        }
    ));
    home.pass(policy().kit_delay_ms);
    phones[0].alive(&mut home);
    assert_eq!(
        home.query::<Overview>(stranger.sync_key(), "overview", ().encode()),
        Err(PersonalError::NotAdmitted),
        "the restore never matured"
    );

    let fresh = KitSecret::security_key(&mut Touch(3)).unwrap();
    let rotation = phones[1].group().rotate(&[fresh.key()]).unwrap();
    let (admin, sync) = (phones[1].admin.clone(), phones[1].sync.clone());
    let rotate = operate(
        &mut home,
        &admin,
        &sync,
        "rotate",
        rotation.kit.encode(),
        Some(*rotation.r2()),
    );
    let (admin, sync) = (phones[0].admin.clone(), phones[0].sync.clone());
    operate(&mut home, &admin, &sync, "cosign", rotate.encode(), None);
    settle(&mut home, &mut phones);
    sync_keys(&mut home, &mut phones);
    for phone in &mut phones {
        assert!(phone.group().holds_recovery());
        assert_eq!(r_of(phone), *rotation.r());
    }
    assert_eq!(
        home.call(&leaked.signing(), "remove", 0u32.encode())
            .answer::<Recorded>(),
        Err(PersonalError::NotAdmitted)
    );
}

/// A thief who passed the owner's biometric holds a device: the owner's
/// removal of it is vetoed, a contest; the kit resolves it at once, and
/// the owner's commit carries the removal, re-sealing the kit under a new
/// `R`.
#[test]
fn a_contested_removal_is_resolved_by_the_kit() {
    let key = KitSecret::security_key(&mut Touch(4)).unwrap();
    let (mut home, mut phones, split) = household_with(2, vec![key.key()]);
    let (admin, sync) = (phones[0].admin.clone(), phones[0].sync.clone());
    let removal = operate(&mut home, &admin, &sync, "remove", 1u32.encode(), None);
    let (admin, sync) = (phones[1].admin.clone(), phones[1].sync.clone());
    operate(&mut home, &admin, &sync, "veto", removal.encode(), None);
    home.pass(policy().operation_delay_ms);
    phones[0].alive(&mut home);
    assert_eq!(
        state(&home, phones[0].sync_key(), removal),
        OpState::Contested
    );
    let signing = key.signing();
    operate(
        &mut home,
        &signing,
        &signing,
        "resolve",
        (removal, true).encode(),
        None,
    );
    assert!(matches!(
        state(&home, phones[0].sync_key(), removal),
        OpState::Matured { .. }
    ));
    let events = phones[0].read(&mut home);
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::Alarm(Alarm::Unsigned { .. }))),
        "{events:?}"
    );
    let candidacy = phones[0].update(&mut home).unwrap();
    assert_eq!(candidacy.set, vec![0]);
    let events = phones[0].read(&mut home);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::Confirmed { .. })),
        "{events:?}"
    );
    assert_ne!(r_of(&mut phones[0]), *split.r(), "R rotated at the removal");
    let (owner, thief) = phones.split_at_mut(1);
    let cursor = thief[0].group().cursor();
    let entries = home.log(owner[0].sync_key(), cursor).unwrap();
    let events = thief[0].group().follow(entries).unwrap();
    assert!(events.contains(&Event::Removed), "{events:?}");
}

/// The owner lost every device but a phone a thief holds after its first
/// unlock: its sync key, not its admin key. The kit's removal of it can be
/// cancelled only by a veto, which the thief cannot sign; it matures, the
/// phone's `alive` is refused from then, and the kit's restore matures in
/// its turn: two of the kit's delays in all.
#[test]
fn the_kit_alone_removes_a_phone_that_holds_only_a_sync_key() {
    let phrase = KitSecret::phrase().unwrap();
    let (mut home, mut phones, _) = household_with(1, vec![phrase.key()]);
    written(&mut home, &mut phones);
    let started = home.now();
    let signing = phrase.signing();
    let removal = operate(&mut home, &signing, &signing, "remove", 0u32.encode(), None);
    phones[0].read(&mut home);
    home.pass(policy().kit_delay_ms / 2);
    phones[0].alive(&mut home);
    assert_eq!(
        state(&home, phones[0].sync_key(), removal),
        OpState::Pending,
        "alive cancels a restore, not a removal"
    );
    home.pass(policy().kit_delay_ms / 2);
    home.call(&signing, "wake", ().encode())
        .answer::<Woken>()
        .unwrap();
    assert_eq!(
        home.call(&phones[0].sync, "alive", ().encode())
            .answer::<Recorded>(),
        Err(PersonalError::NotAdmitted),
        "the phone has no voice"
    );

    let next = KitSecret::phrase().unwrap();
    let (mut restored, split, _) = open_restore(&mut home, &phrase, &next, 9);
    let archive = matured(&mut home, &phrase, &restored);
    assert!(home.now() - started >= 2 * policy().kit_delay_ms);
    restart(&home, &mut restored, &split, &next);
    restored.group().inherit(&archive).unwrap();
    install(&restored.light, NOTES);
    with(&mut home, &mut restored, &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert_eq!(count(&restored.light, NOTES, 0), Some(10));
}

/// `R` rotates at every removal: the commit carrying it draws a new `R`,
/// `R1` sealed to the kit's key with no kit holder, `R2` to the agent. The
/// committer takes the new `R` at the commit's verdict and re-seals the
/// recovery scope under it; the other device takes it from an archive of
/// the new epoch. The removed device, holding the old `R`, opens nothing
/// pushed there after the removal, even served every envelope; the kit
/// opens it all.
#[test]
fn r_rotates_at_a_removal_and_the_removed_device_opens_nothing_after() {
    let key = KitSecret::security_key(&mut Touch(5)).unwrap();
    let (mut home, mut phones, split) = household_with(3, vec![key.key()]);
    written(&mut home, &mut phones);
    let old = r_of(&mut phones[2]);
    assert_eq!(old, *split.r());
    let (admin, sync) = (phones[0].admin.clone(), phones[0].sync.clone());
    let removal = operate(&mut home, &admin, &sync, "remove", 2u32.encode(), None);
    let (admin, sync) = (phones[1].admin.clone(), phones[1].sync.clone());
    operate(&mut home, &admin, &sync, "cosign", removal.encode(), None);
    settle(&mut home, &mut phones[..2]);
    for phone in &mut phones[..2] {
        assert_eq!(
            owed_commit(phone.group()),
            Some(Commit::Removals),
            "the matured removal is owed a commit"
        );
    }
    let epoch = phones[0].group().confirmed() + 1;
    let prepared = phones[0].group().commit(None, home.now()).unwrap();
    assert_eq!(prepared.effect.remove, vec![2]);
    let rekey = prepared.effect.rekey.clone().expect("the kit re-sealed");
    phones[0].send(&mut home, &prepared).unwrap();
    settle(&mut home, &mut phones[..2]);
    assert_eq!(phones[1].group().confirmed(), epoch);
    let new = r_of(&mut phones[0]);
    assert_ne!(new, old);
    assert_eq!(vos_wire::personal::r_hash(&new), rekey.r_hash);
    let view: RecoveryView = home
        .query(phones[0].sync_key(), "recovery", ().encode())
        .unwrap();
    assert_eq!(view.entries, rekey.entries, "R1 re-sealed to the kit");
    let r1 = key.open_r1(&view.entries[0], &home.identity).unwrap();
    assert_ne!(*r1, [0; 32]);
    assert!(!phones[1].group().holds_recovery());
    assert_eq!(
        with(&mut home, &mut phones[1], &[], |sync| sync.recovery()).unwrap(),
        Default::default(),
        "nothing pushed under the old R once the log names a new one"
    );
    sync_keys(&mut home, &mut phones[..2]);
    assert_eq!(r_of(&mut phones[1]), new, "from the new epoch's archive");

    set(&phones[1].light, NOTES, 7, 77);
    with(&mut home, &mut phones[1], &[NOTES], |sync| sync.push(NOTES)).unwrap();
    phones[1].update(&mut home).unwrap();
    settle(&mut home, &mut phones[..2]);
    sync_keys(&mut home, &mut phones[..2]);

    let after = kit_reads(&home, &key);
    assert!(!after.is_empty());
    assert!(
        open_recovery(&old, &home.identity, &after).is_none(),
        "the removed device's R opens nothing after its removal"
    );
    let served = stored(&home, &phones[0], RECOVERY);
    let opened = open_recovery(&old, &home.identity, &served).unwrap();
    assert!(
        opened.keys(epoch, &scope_of(&phones[0], NOTES)).is_empty(),
        "nor anything of the epochs after it, every envelope served"
    );
    let recovered = open_recovery(&new, &home.identity, &after).unwrap();
    assert!(
        !recovered
            .keys(epoch + 1, &scope_of(&phones[0], NOTES))
            .is_empty()
    );
}

/// The operators log `Void` for the epoch every device confirmed by its
/// own count, the commit carrying a removal: the new `R` is named nowhere
/// and the old one, which the removed device holds, is held by no device
/// that may push under it. Nothing of the new epoch reaches the recovery
/// scope under the old `R`, and the next commit re-seals the kit.
#[test]
fn a_void_verdict_after_a_confirmed_removal_rotates_r_all_the_same() {
    let key = KitSecret::security_key(&mut Touch(7)).unwrap();
    let (mut home, mut phones, split) = household_with(3, vec![key.key()]);
    written(&mut home, &mut phones);
    let old = *split.r();
    let (admin, sync) = (phones[0].admin.clone(), phones[0].sync.clone());
    let removal = operate(&mut home, &admin, &sync, "remove", 2u32.encode(), None);
    let (admin, sync) = (phones[1].admin.clone(), phones[1].sync.clone());
    operate(&mut home, &admin, &sync, "cosign", removal.encode(), None);
    settle(&mut home, &mut phones[..2]);
    let epoch = phones[0].group().confirmed() + 1;
    let prepared = phones[0].group().commit(None, home.now()).unwrap();
    assert_eq!(prepared.effect.remove, vec![2]);
    phones[0].send(&mut home, &prepared).unwrap();
    let mut voided = [false; 2];
    for _ in 0..4 {
        for (phone, voided) in phones[..2].iter_mut().zip(&mut voided) {
            if !*voided {
                *voided = read_voided(&mut home, phone, epoch);
            }
        }
    }
    assert_eq!(voided, [true; 2]);
    for phone in &mut phones[..2] {
        assert_eq!(phone.group().confirmed(), epoch);
        assert!(!phone.group().holds_recovery());
        assert_eq!(
            owed_commit(phone.group()),
            Some(Commit::Reseal),
            "the user is asked for the commit that re-seals the kit"
        );
        assert_eq!(
            with(&mut home, phone, &[], |sync| sync.recovery()).unwrap(),
            Default::default(),
            "nothing pushed under an R the removed device holds"
        );
    }
    let served = stored(&home, &phones[0], RECOVERY);
    let opened = open_recovery(&old, &home.identity, &served).unwrap();
    assert!(opened.keys(epoch, &scope_of(&phones[0], NOTES)).is_empty());
    let next = phones[0].group().commit(None, home.now()).unwrap();
    assert!(
        next.effect.rekey.is_some(),
        "the next commit re-seals the kit"
    );
}

/// A restore whose evidence a device judges invalid (its view of the kit
/// or the policy is not the agent's) is answered with `alive` all the
/// same: liveness needs no judgement, so the restore is cancelled.
#[test]
fn a_restore_a_device_judges_invalid_is_answered_alive() {
    let leaked = KitSecret::phrase().unwrap();
    let (mut home, mut phones, _) = household_with(2, vec![leaked.key()]);
    let next = KitSecret::phrase().unwrap();
    let restoring = Phone::new(9);
    let split = vos_light::group::restoring(&restoring.store, &[next.key()], &home.agent(), |_| {
        Vec::new()
    })
    .unwrap();
    let signing = leaked.signing();
    let reply = home.call(
        &signing,
        "restore",
        (restoring.keys.clone(), split.kit.clone()).encode(),
    );
    let index = reply.answer::<Recorded>().unwrap().index;
    // Its evidence as the agent stores it, its signature not the call's.
    home.call(
        &signing,
        "evidence",
        (
            (index, reply.message),
            (
                [0x5a_u8; 64],
                Attached {
                    welcome: None,
                    r2: Some(*split.r2()),
                },
            ),
        )
            .encode(),
    )
    .answer::<Recorded>()
    .unwrap();
    phones[0].read(&mut home);
    assert!(matches!(
        state(&home, phones[0].sync_key(), index),
        OpState::Cancelled {
            why: vos_wire::personal::Cancel::Alive,
            ..
        }
    ));
}

/// An admin call whose evidence post is lost (a kill between the call and
/// its evidence, its answer never read) is held before it leaves: the next
/// reading finds it in the log and posts its evidence, so the removal
/// matures rather than being cancelled for want of it, and the next
/// commit carries it.
#[test]
fn a_held_calls_evidence_is_posted_again_after_a_kill() {
    let key = KitSecret::security_key(&mut Touch(8)).unwrap();
    let (mut home, mut phones, _) = household_with(3, vec![key.key()]);
    let admin = phones[0].admin.clone();
    let signed = home.sign(&admin, "remove", 2u32.encode());
    phones[0]
        .group()
        .sending(signed.message.clone(), signed.signature, None)
        .unwrap();
    let removal = home.send(signed).answer::<Recorded>().unwrap().index;
    crate::restart(&mut phones[0]);
    phones[0].read(&mut home);
    let entries = home.log(phones[0].sync_key(), removal).unwrap();
    assert!(
        entries.iter().any(|(_, entry)| matches!(
            entry.body,
            vos_wire::personal::Body::Evidence { index, .. } if index == removal
        )),
        "the evidence posted from the held call"
    );
    home.pass(policy().operation_delay_ms);
    phones[0].alive(&mut home);
    assert!(matches!(
        state(&home, phones[0].sync_key(), removal),
        OpState::Matured { .. }
    ));
    settle(&mut home, &mut phones[..2]);
    let prepared = phones[0].group().commit(None, home.now()).unwrap();
    assert_eq!(prepared.effect.remove, vec![2]);
    phones[0].send(&mut home, &prepared).unwrap();
}

/// `phone` reading the log, posting what it asks for, with the verdict on
/// `epoch` shown it as `Void`, its reading stopped there: whether it read
/// that verdict.
fn read_voided(home: &mut Home, phone: &mut Phone, epoch: u64) -> bool {
    let (cursor, before) = phone.group().view();
    let mut entries = home.log(phone.sync_key(), cursor).unwrap();
    let verdict = entries.iter().position(|(_, entry)| {
        matches!(entry.body, vos_wire::personal::Body::Verdict { epoch: of, .. } if of == epoch)
    });
    if let Some(at) = verdict {
        entries.truncate(at + 1);
        let last = at
            .checked_sub(1)
            .map_or(before, |previous| entries[previous].1.chain);
        let (index, entry) = &mut entries[at];
        entry.body = vos_wire::personal::Body::Verdict {
            epoch,
            verdict: vos_wire::personal::Verdict::Void(vos_wire::personal::Void::Nack),
        };
        entry.chain = vos_wire::personal::chain(&last, *index, entry.at, &entry.body);
    }
    for event in phone.group().follow(entries).unwrap() {
        match event {
            Event::Vote {
                epoch,
                vote,
                message,
            } => phone.vote(home, epoch, vote, &message),
            Event::Evidence {
                index,
                message,
                signature,
                attached,
            } => phone.evidence(home, index, message, signature, attached),
            _ => {}
        }
    }
    verdict.is_some()
}

/// A chunk of an archive, as sealed sync frames it.
#[derive(vos_abi::Decode)]
struct Chunk {
    _digest: [u8; 32],
    part: u16,
    parts: u16,
    bytes: Vec<u8>,
}

/// The archives in the archive scope sealed under `key`, each of one
/// chunk.
fn archives_under(home: &Home, reader: &Phone, key: &[u8; 32]) -> Vec<Archive> {
    let scope = reader
        .group
        .as_ref()
        .unwrap()
        .archive()
        .scope(vos_light::personal::ARCHIVE_NAME);
    stored(home, reader, scope)
        .iter()
        .filter_map(|envelope| {
            let (_, body) = sealed::open(&[*key], &home.identity, &envelope.bytes).ok()?;
            let chunk = Chunk::decode_exact(&body)?;
            (chunk.part == 0 && chunk.parts == 1)
                .then(|| Archive::decode_exact(&chunk.bytes))
                .flatten()
        })
        .collect()
}

/// A kit rotation that matures while the commit carrying a removal is
/// pending: the commit's re-sealed kit is the old kit's, so neither the
/// agent nor any device takes it, and the rotation's `R` stands. While the
/// removal was owed no device let that `R` travel, so no archive sealed
/// under an epoch the removed device is in holds it.
#[test]
fn a_rotation_maturing_before_a_removals_commit_reaches_no_removed_device() {
    let key = KitSecret::security_key(&mut Touch(6)).unwrap();
    let (mut home, mut phones, _) = household_with(3, vec![key.key()]);
    let next = KitSecret::security_key(&mut Touch(16)).unwrap();
    let rotation = phones[1].group().rotate(&[next.key()]).unwrap();
    let (admin, sync) = (phones[1].admin.clone(), phones[1].sync.clone());
    let rotate = operate(
        &mut home,
        &admin,
        &sync,
        "rotate",
        rotation.kit.encode(),
        Some(*rotation.r2()),
    );
    let (admin, sync) = (phones[0].admin.clone(), phones[0].sync.clone());
    let removal = operate(&mut home, &admin, &sync, "remove", 2u32.encode(), None);
    let (admin, sync) = (phones[1].admin.clone(), phones[1].sync.clone());
    operate(&mut home, &admin, &sync, "cosign", removal.encode(), None);
    settle(&mut home, &mut phones[..2]);
    let removed_key = phones[2].group().archive_key().unwrap();
    let prepared = phones[0].group().commit(None, home.now()).unwrap();
    let signed = home.sign(&phones[0].admin, "commit", prepared.arguments());
    phones[0]
        .group()
        .signed_commit(signed.message.clone(), signed.signature)
        .unwrap();
    let candidacy = home
        .send(signed)
        .answer::<vos_wire::personal::Candidacy>()
        .unwrap();
    let Event::Evidence {
        index,
        message,
        signature,
        attached,
    } = phones[0].group().called_commit(candidacy.index).unwrap()
    else {
        unreachable!()
    };
    phones[0].evidence(&mut home, index, message, signature, attached);

    home.pass(policy().operation_delay_ms);
    for phone in &mut phones[..2] {
        phone.alive(&mut home);
    }
    assert!(matches!(
        state(&home, phones[0].sync_key(), rotate),
        OpState::Matured { .. }
    ));
    // The rotation's R is the drawer's before the commit is decided, and
    // both push their archives under the epoch the removed device is in.
    let cursor = phones[1].group().cursor();
    let entries = home.log(phones[1].sync_key(), cursor).unwrap();
    phones[1].group().follow(entries).unwrap();
    assert_eq!(r_of(&mut phones[1]), *rotation.r());
    let epoch = phones[1].group().confirmed();
    sync_keys(&mut home, &mut phones[..2]);
    assert_eq!(phones[1].group().confirmed(), epoch);
    settle(&mut home, &mut phones[..2]);
    sync_keys(&mut home, &mut phones[..2]);
    settle(&mut home, &mut phones[..2]);
    sync_keys(&mut home, &mut phones[..2]);
    assert_eq!(phones[0].group().confirmed(), phones[1].group().confirmed());
    for phone in &mut phones[..2] {
        assert!(phone.group().holds_recovery());
        assert_eq!(r_of(phone), *rotation.r(), "the rotation's R stands");
    }
    let view: RecoveryView = home
        .query(phones[0].sync_key(), "recovery", ().encode())
        .unwrap();
    assert_eq!(view.entries, rotation.kit.entries);
    let archives = archives_under(&home, &phones[0], &removed_key);
    assert!(!archives.is_empty());
    for archive in archives {
        assert!(
            archive
                .recovery
                .as_ref()
                .is_none_or(|held| held.r != *rotation.r()),
            "no archive the removed device opens holds the rotation's R"
        );
    }
}

/// A kit rotation the kit signs leaves no device holding its `R`: the
/// devices push nothing to the recovery scope until a device's next
/// commit re-seals the kit under an `R` of its own.
#[test]
fn a_rotation_the_kit_signs_is_re_sealed_by_the_next_commit() {
    let old = KitSecret::phrase().unwrap();
    let (mut home, mut phones, _) = household_with(2, vec![old.key()]);
    let next = KitSecret::phrase().unwrap();
    let split = Split::draw(&[next.key()], &home.identity).unwrap();
    let signing = old.signing();
    operate(
        &mut home,
        &signing,
        &signing,
        "rotate",
        split.kit.encode(),
        Some(*split.r2()),
    );
    home.pass(policy().kit_delay_ms);
    for phone in &mut phones {
        phone.alive(&mut home);
    }
    settle(&mut home, &mut phones);
    for phone in &mut phones {
        assert!(!phone.group().holds_recovery());
        assert_eq!(phone.group().kit(), &[next.key()]);
        assert_eq!(
            with(&mut home, phone, &[], |sync| sync.recovery()).unwrap(),
            Default::default()
        );
    }
    let prepared = phones[0].group().commit(None, home.now()).unwrap();
    assert!(prepared.effect.remove.is_empty());
    let rekey = prepared.effect.rekey.clone().expect("the kit re-sealed");
    phones[0].send(&mut home, &prepared).unwrap();
    settle(&mut home, &mut phones);
    sync_keys(&mut home, &mut phones);
    for phone in &mut phones {
        assert!(phone.group().holds_recovery());
        assert_eq!(vos_wire::personal::r_hash(&r_of(phone)), rekey.r_hash);
    }
    let r = r_of(&mut phones[0]);
    assert!(open_recovery(&r, &home.identity, &kit_reads(&home, &next)).is_some());
}
