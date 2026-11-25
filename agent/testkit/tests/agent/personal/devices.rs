//! The device set (`light-node.md` §3.5) on a test home's policy, a day a
//! minute: standing and seasoning, operations and their delays, vetoes,
//! contests and resolutions, immediate removal, a probation frozen under
//! a removal, the kit's operations, a restore and its `R2`, kit rotation,
//! admin-key replacement, a delayed admin's add, a regroup and a leave.

use vos_wire::personal::{
    AdminClass, Attestation, Body, Cancel, DeviceView, Entry, NewAdmin, OpState, RECOVERY,
    RecoveryView, Standing, Verdict, Void,
};

use super::*;

/// A test home whose devices 0 to `n - 1` are seasoned, each seen now.
fn seasoned(n: u8) -> Home {
    let mut home = Home::with(minutes());
    for k in 1..n {
        home.pair(0, k);
    }
    home.pass(10 * MINUTE);
    for k in 0..n {
        home.call::<Recorded>(sync(k), "alive", ()).unwrap();
    }
    home
}

fn view(home: &Home, reader: Principal, id: DeviceId) -> DeviceView {
    let devices: Vec<DeviceView> = home.query(reader, "devices", ()).unwrap();
    devices.into_iter().find(|view| view.id == id).unwrap()
}

fn standing(home: &Home, reader: Principal, id: DeviceId) -> Standing {
    view(home, reader, id).standing
}

fn state(home: &Home, reader: Principal, index: u64) -> OpState {
    home.operation(reader, index).state
}

fn matured(state: OpState) -> bool {
    matches!(state, OpState::Matured { .. })
}

fn cancelled(state: OpState) -> Option<Cancel> {
    match state {
        OpState::Cancelled { why, .. } => Some(why),
        _ => None,
    }
}

/// A new admin key for a replacement.
fn new_admin(n: u8) -> NewAdmin {
    NewAdmin {
        key: [0xa0 + n; 32],
        class: AdminClass::Strong,
        attestation: Attestation {
            hardware: true,
            verified_boot: false,
        },
    }
}

/// States on the policy's times: a paired device in probation, then
/// active, then seasoned; the claiming device active at once and seasoned
/// after the seasoning. A probation device signs no operation and vetoes
/// nothing.
#[test]
fn a_device_is_in_probation_then_active_then_seasoned() {
    let mut home = Home::with(minutes());
    home.pair(0, 1);
    let (zero, one) = (view(&home, sync(0), 0), view(&home, sync(0), 1));
    assert_eq!((zero.standing, zero.seasoned), (Standing::Active, false));
    assert_eq!((one.standing, one.seasoned), (Standing::Probation, false));
    let removal = home.operate(KIT, "remove", 0u32).unwrap();
    assert_eq!(
        home.operate(admin(1), "veto", removal),
        Err(PersonalError::Probation)
    );
    assert_eq!(
        home.operate(admin(1), "remove", 0u32),
        Err(PersonalError::Probation)
    );
    home.call::<Recorded>(admin(0), "veto", removal).unwrap();
    home.pass(3 * MINUTE);
    let one = view(&home, sync(0), 1);
    assert_eq!((one.standing, one.seasoned), (Standing::Active, false));
    home.pass(4 * MINUTE);
    assert!(view(&home, sync(0), 0).seasoned, "seven minutes active");
    assert!(!view(&home, sync(0), 1).seasoned);
    home.pass(3 * MINUTE);
    assert!(view(&home, sync(0), 1).seasoned);
}

/// Rules 3–5: a removal is pending for the delay and vetoed by any active
/// device, its target included, once; contested it does not mature, and
/// only two seasoned devices other than its target resolve it, the first
/// alone deciding nothing. The kit vetoes nothing, and a sync key signs no
/// veto.
#[test]
fn a_veto_contests_a_removal_and_two_seasoned_devices_resolve_it() {
    let mut home = seasoned(3);
    let removal = home.operate(admin(0), "remove", 2u32).unwrap();
    assert_eq!(
        home.operate(KIT, "veto", removal),
        Err(PersonalError::KitVeto)
    );
    assert_eq!(
        home.operate(sync(2), "veto", removal),
        Err(PersonalError::SyncKey)
    );
    assert_eq!(
        home.operate(admin(2), "resolve", (removal, true)),
        Err(PersonalError::Uncontested)
    );
    home.operate(admin(2), "veto", removal).unwrap();
    assert_eq!(
        home.operate(admin(2), "veto", removal),
        Err(PersonalError::Vetoed)
    );
    assert_eq!(state(&home, sync(0), removal), OpState::Contested);
    home.pass(10 * MINUTE);
    home.call::<Recorded>(sync(1), "alive", ()).unwrap();
    assert_eq!(standing(&home, sync(0), 2), Standing::Active);
    assert_eq!(
        home.operate(admin(2), "resolve", (removal, false)),
        Err(PersonalError::Targeted)
    );
    home.operate(admin(0), "resolve", (removal, true)).unwrap();
    assert_eq!(state(&home, sync(0), removal), OpState::Contested);
    home.operate(admin(1), "resolve", (removal, true)).unwrap();
    assert!(matured(state(&home, sync(0), removal)));
    assert_eq!(standing(&home, sync(0), 2), Standing::Removed);
}

/// Rule 5: the kit resolves a contest at once, either way; uncontested, a
/// device's removal matures at its delay and not before.
#[test]
fn the_kit_resolves_a_contest_at_once() {
    let mut home = seasoned(2);
    let first = home.operate(admin(0), "remove", 1u32).unwrap();
    home.operate(admin(1), "veto", first).unwrap();
    home.operate(KIT, "resolve", (first, false)).unwrap();
    assert_eq!(
        cancelled(state(&home, sync(0), first)),
        Some(Cancel::Resolved)
    );
    let second = home.operate(admin(0), "remove", 1u32).unwrap();
    home.operate(admin(1), "veto", second).unwrap();
    home.operate(KIT, "resolve", (second, true)).unwrap();
    assert!(matured(state(&home, sync(0), second)));
    assert_eq!(standing(&home, sync(0), 1), Standing::Removed);

    let mut home = seasoned(2);
    let removal = home.operate(admin(0), "remove", 1u32).unwrap();
    home.pass(3 * MINUTE - 3);
    assert_eq!(standing(&home, sync(0), 1), Standing::Active);
    home.pass(1);
    assert_eq!(
        standing(&home, sync(0), 1),
        Standing::Removed,
        "a read computes a removal due by its time"
    );
    home.call::<Recorded>(sync(0), "alive", ()).unwrap();
    assert!(matured(state(&home, sync(0), removal)));
}

/// Rule 6: two seasoned devices with strong admins other than the target
/// remove it at once, contested or not; a target, the signer again, an
/// unseasoned device and a delayed admin make it nothing.
#[test]
fn two_seasoned_devices_remove_at_once() {
    let mut home = Home::with(minutes());
    home.pair(0, 1);
    home.pair(0, 2);
    home.pair_keys(0, delayed(3));
    home.pass(10 * MINUTE);
    for n in 0..4 {
        home.call::<Recorded>(sync(n), "alive", ()).unwrap();
    }
    home.pair(0, 4);
    home.pass(3 * MINUTE);
    let removal = home.operate(admin(0), "remove", 2u32).unwrap();
    home.operate(admin(2), "veto", removal).unwrap();
    for (caller, refusal) in [
        (admin(2), PersonalError::Targeted),
        (admin(0), PersonalError::NotSigner),
        (admin(4), PersonalError::Unseasoned),
        (admin(3), PersonalError::Unseasoned),
    ] {
        assert_eq!(
            home.operate(caller, "cosign", removal),
            Err(refusal),
            "{caller:?}"
        );
    }
    assert!(view(&home, sync(0), 3).seasoned, "seasoned, but delayed");
    home.operate(admin(1), "cosign", removal).unwrap();
    assert!(matured(state(&home, sync(0), removal)));
    assert_eq!(standing(&home, sync(0), 2), Standing::Removed);
}

/// A second signature or a resolution decides at its evidence, never at
/// its call: one whose signer withholds the evidence decides nothing, the
/// signer may sign it again, and another device's evidenced signature
/// decides; the withheld one's evidence posted late changes nothing. A device's later resolution replaces its earlier one,
/// evidenced or not.
#[test]
fn a_second_signature_or_a_resolution_decides_at_its_evidence() {
    let posted = |home: &mut Home, n: u8, name: &str, index: u64| {
        let signed = message(device(n).admin, home.method(name), &home.logged(index));
        home.call::<Recorded>(
            sync(n),
            "evidence",
            evidence(index, signed, Attached::default()),
        )
        .unwrap();
    };
    let mut home = seasoned(4);
    let removal = home.operate(admin(0), "remove", 3u32).unwrap();
    let withheld = home.unevidenced(admin(1), "cosign", removal).unwrap();
    assert_eq!(state(&home, sync(0), removal), OpState::Pending);
    home.unevidenced(admin(1), "cosign", removal).unwrap();
    assert_eq!(state(&home, sync(0), removal), OpState::Pending);
    home.operate(admin(2), "cosign", removal).unwrap();
    assert!(matured(state(&home, sync(0), removal)));
    posted(&mut home, 1, "cosign", withheld);
    assert!(matured(state(&home, sync(0), removal)));

    let mut home = seasoned(4);
    let removal = home.operate(admin(0), "remove", 3u32).unwrap();
    home.operate(admin(3), "veto", removal).unwrap();
    let first = home
        .unevidenced(admin(1), "resolve", (removal, true))
        .unwrap();
    home.operate(admin(2), "resolve", (removal, true)).unwrap();
    assert_eq!(state(&home, sync(0), removal), OpState::Contested);
    home.operate(admin(1), "resolve", (removal, false)).unwrap();
    posted(&mut home, 1, "resolve", first);
    assert_eq!(
        state(&home, sync(0), removal),
        OpState::Contested,
        "a resolution replaced counts no more"
    );
    home.operate(admin(1), "resolve", (removal, true)).unwrap();
    assert!(matured(state(&home, sync(0), removal)));
    assert_eq!(standing(&home, sync(0), 3), Standing::Removed);
}

/// An operation the devices hold no evidence of matures for none of them:
/// a removal due without its call's evidence is cancelled `Unevidenced`,
/// its target keeping its voice; a cosign before the evidence is refused,
/// and makes the removal immediate once the evidence came.
#[test]
fn an_operation_due_without_its_evidence_is_cancelled() {
    let mut home = seasoned(3);
    let removal = home.unevidenced(admin(0), "remove", 2u32).unwrap();
    home.pass(3 * MINUTE + 1);
    home.wake(sync(0)).unwrap();
    assert_eq!(
        cancelled(state(&home, sync(0), removal)),
        Some(Cancel::Unevidenced)
    );
    assert_eq!(standing(&home, sync(0), 2), Standing::Active);
    // A cosign before the evidence is refused, and taken once it came.
    let removal = home.unevidenced(admin(0), "remove", 2u32).unwrap();
    assert_eq!(
        home.operate(admin(1), "cosign", removal),
        Err(PersonalError::Unevidenced)
    );
    let signed = message(
        device(0).admin,
        home.method("remove"),
        &home.logged(removal),
    );
    home.call::<Recorded>(
        sync(0),
        "evidence",
        evidence(removal, signed, Attached::default()),
    )
    .unwrap();
    home.operate(admin(1), "cosign", removal).unwrap();
    assert!(matured(state(&home, sync(0), removal)));
    assert_eq!(standing(&home, sync(0), 2), Standing::Removed);
}

/// A resolution naming an operation that has no evidence yet is refused:
/// it would be cancelled at once for want of it, and its rival, the one the
/// resolution dropped, reopened.
#[test]
fn a_resolution_onto_an_unevidenced_operation_is_refused() {
    let mut home = seasoned(2);
    let removal = home.unevidenced(admin(0), "remove", 1u32).unwrap();
    home.operate(admin(1), "veto", removal).unwrap();
    assert_eq!(
        home.operate(KIT, "resolve", (removal, true)),
        Err(PersonalError::Unevidenced)
    );
    let signed = message(
        device(0).admin,
        home.method("remove"),
        &home.logged(removal),
    );
    home.call::<Recorded>(
        sync(0),
        "evidence",
        evidence(removal, signed, Attached::default()),
    )
    .unwrap();
    home.operate(KIT, "resolve", (removal, true)).unwrap();
    assert!(matured(state(&home, sync(0), removal)));
}

/// Rule 5: two removals aimed at each other are one contest, which no
/// device of the two resolves; the resolution names the one that matures,
/// and the other is dropped.
#[test]
fn two_removals_aimed_at_each_other_are_one_contest() {
    let mut home = seasoned(3);
    let owner = home.operate(admin(0), "remove", 1u32).unwrap();
    let thief = home.operate(admin(1), "remove", 0u32).unwrap();
    for index in [owner, thief] {
        assert_eq!(state(&home, sync(2), index), OpState::Contested);
    }
    for caller in [admin(0), admin(1)] {
        assert_eq!(
            home.operate(caller, "resolve", (owner, true)),
            Err(PersonalError::Targeted)
        );
    }
    home.operate(admin(2), "resolve", (owner, true)).unwrap();
    home.pass(10 * MINUTE);
    home.call::<Recorded>(sync(2), "alive", ()).unwrap();
    assert_eq!(state(&home, sync(2), owner), OpState::Contested);
    // The kit names the thief's dropped, so the owner's matures.
    home.operate(KIT, "resolve", (thief, false)).unwrap();
    assert!(matured(state(&home, sync(0), owner)));
    assert_eq!(
        cancelled(state(&home, sync(0), thief)),
        Some(Cancel::Resolved)
    );
    assert_eq!(standing(&home, sync(0), 1), Standing::Removed);
    assert_eq!(standing(&home, sync(0), 0), Standing::Active);
}

/// Rule 8, A14: a removal open against a probation device freezes its
/// probation, which runs on from where it stopped once the removal is
/// dropped: an add cannot ripen into a vote inside its removal's window.
#[test]
fn a_removal_freezes_its_targets_probation() {
    let mut home = seasoned(2);
    home.pair(1, 2);
    home.pass(MINUTE);
    let left = view(&home, sync(0), 2).device.active_from - home.now();
    let removal = home.operate(admin(0), "remove", 2u32).unwrap();
    home.operate(admin(1), "veto", removal).unwrap();
    home.pass(20 * MINUTE);
    home.call::<Recorded>(sync(0), "alive", ()).unwrap();
    assert_eq!(standing(&home, sync(0), 2), Standing::Probation);
    assert_eq!(
        home.operate(admin(2), "veto", removal),
        Err(PersonalError::Probation)
    );
    home.operate(KIT, "resolve", (removal, false)).unwrap();
    let thawed = view(&home, sync(0), 2);
    assert_eq!(thawed.standing, Standing::Probation);
    assert_eq!(
        thawed.device.active_from,
        home.now() - 1 + left,
        "the probation left when the removal opened"
    );
    home.pass(left);
    assert_eq!(standing(&home, sync(0), 2), Standing::Active);
}

/// Rule 7, D3: the kit's operations wait the kit's delay, are cancelled
/// by any active device's veto, and its removal matures unvetoed; a
/// leaked kit alone completes nothing while a device vetoes.
#[test]
fn the_kits_operations_wait_and_a_veto_cancels_them() {
    let mut home = seasoned(2);
    let removal = home.operate(KIT, "remove", 0u32).unwrap();
    home.pass(7 * MINUTE - 3);
    home.operate(admin(0), "veto", removal).unwrap();
    assert_eq!(
        cancelled(state(&home, sync(0), removal)),
        Some(Cancel::Veto)
    );
    let removal = home.operate(KIT, "remove", 1u32).unwrap();
    home.pass(7 * MINUTE - 3);
    assert_eq!(standing(&home, sync(0), 1), Standing::Active);
    home.pass(1);
    home.call::<Recorded>(sync(0), "alive", ()).unwrap();
    assert!(matured(state(&home, sync(0), removal)));
    // Device 1's removal matured: it has no voice.
    assert_eq!(
        home.call::<Recorded>(sync(1), "alive", ()),
        Err(PersonalError::NotAdmitted)
    );
}

/// D1: a restore waits the kit's delay; any device's `alive` cancels it,
/// and a device's veto; once its target's removal matured, that device's
/// `alive` is ignored, and the restore matures: every device removed, its
/// device alone and active, the kit replaced, and the previous `R2`
/// released to its device alone. A restore whose evidence never brought
/// its `R2` matures to nothing.
#[test]
fn a_restore_is_cancelled_by_alive_and_releases_r2_once_matured() {
    let mut home = Home::with(minutes());
    let (next, r2) = new_kit(1);
    let restore = (device(5), next.clone());
    let first = home.operate(KIT, "restore", restore.clone()).unwrap();
    home.call::<Recorded>(sync(0), "alive", ()).unwrap();
    assert_eq!(cancelled(state(&home, KIT, first)), Some(Cancel::Alive));
    let unevidenced = home.operate(KIT, "restore", restore.clone()).unwrap();
    home.pass(7 * MINUTE);
    home.wake(KIT).unwrap();
    assert_eq!(
        cancelled(state(&home, KIT, unevidenced)),
        Some(Cancel::Unevidenced)
    );

    let removal = home.operate(KIT, "remove", 0u32).unwrap();
    home.deposit(KIT, KIT_KEY, removal, "remove", 0u32, r2)
        .expect_err("a removal carries no R2");
    home.pass(7 * MINUTE);
    home.wake(KIT).unwrap();
    assert!(matured(state(&home, KIT, removal)));
    let index = home.operate(KIT, "restore", restore.clone()).unwrap();
    home.deposit(KIT, KIT_KEY, index, "restore", restore.clone(), [0; 32])
        .expect_err("not the R2 named");
    home.deposit(KIT, KIT_KEY, index, "restore", restore.clone(), r2)
        .unwrap();
    assert_eq!(
        home.call::<Recorded>(sync(0), "alive", ()),
        Err(PersonalError::NotAdmitted),
        "the removed device's alive is ignored"
    );
    // The restore's device is admitted at ingress once a call settles the
    // restore: the kit's.
    home.pass(7 * MINUTE);
    home.wake(KIT).unwrap();
    assert!(matured(state(&home, sync(5), index)));
    assert_eq!(
        standing(&home, sync(5), 1),
        Standing::Active,
        "the restore's device, the set's second"
    );
    assert_eq!(standing(&home, sync(5), 0), Standing::Removed);
    let released: RecoveryView = home.query(sync(5), "recovery", ()).unwrap();
    assert_eq!(released.released, Some(kit().r2), "the previous R2");
    assert_eq!(released.entries, next.entries);
    let read: RecoveryView = home.query(kit_key(1, 1), "recovery", ()).unwrap();
    assert_eq!(read.released, None, "for the restore's device alone");
    assert_eq!(
        home.query::<RecoveryView>(KIT, "recovery", ()),
        Err(PersonalError::NotAdmitted),
        "the previous kit is admitted no more"
    );
    // The new group's first commit carries the old device's removal.
    let epoch = home
        .query::<Overview>(sync(5), "overview", ())
        .unwrap()
        .confirmed
        + 1;
    assert_eq!(
        home.call::<Candidacy>(admin(5), "commit", update(epoch, 1)),
        Err(PersonalError::MissingRemoval(0))
    );
    let effect = Effect {
        add: None,
        remove: vec![0],
        rekey: None,
    };
    assert_eq!(
        home.call::<Candidacy>(
            admin(5),
            "commit",
            commit(epoch, effect.clone(), vec![9; 600])
        ),
        Err(PersonalError::Rekey),
        "a removal re-seals the kit"
    );
    let (mut stale, _) = home.rekey(sync(5), 9);
    stale.entries[0].sealing = [0x99; 32];
    let effect = Effect {
        rekey: Some(stale),
        ..effect
    };
    assert_eq!(
        home.call::<Candidacy>(
            admin(5),
            "commit",
            commit(epoch, effect.clone(), vec![9; 600])
        ),
        Err(PersonalError::Rekey),
        "the kit's own entries, each with a new R1"
    );
    let effect = Effect {
        rekey: Some(home.rekey(sync(5), 9).0),
        ..effect
    };
    home.call::<Candidacy>(admin(5), "commit", commit(epoch, effect, vec![9; 600]))
        .unwrap();
}

/// A kit rotation: by one device pending and contestable, by two seasoned
/// devices at once, by the kit vetoable; once matured the previous kit is
/// admitted no more, `R2` is the new one, and the new kit reads the
/// recovery scope from the rotation on, the envelopes re-sealed under its
/// `R`.
#[test]
fn a_kit_rotation_replaces_the_kit_and_its_recovery_scope_starts_over() {
    let mut home = seasoned(2);
    let epoch = home.overview().confirmed;
    home.push(0, envelope(RECOVERY, epoch, 1, 300)).unwrap();
    let (first, r2) = new_kit(1);
    let rotation = home.operate(admin(0), "rotate", first.clone()).unwrap();
    home.deposit(
        sync(0),
        device(0).admin,
        rotation,
        "rotate",
        first.clone(),
        r2,
    )
    .unwrap();
    home.operate(admin(1), "veto", rotation).unwrap();
    home.pass(10 * MINUTE);
    home.call::<Recorded>(sync(0), "alive", ()).unwrap();
    assert_eq!(state(&home, sync(0), rotation), OpState::Contested);
    home.operate(KIT, "resolve", (rotation, true)).unwrap();
    assert!(matured(state(&home, sync(0), rotation)));
    assert_eq!(
        home.query::<RecoveryView>(KIT, "recovery", ()),
        Err(PersonalError::NotAdmitted)
    );
    let recovery: RecoveryView = home.query(kit_key(1, 0), "recovery", ()).unwrap();
    assert_eq!((recovery.from, recovery.entries), (1, first.entries));
    let resealed = envelope(RECOVERY, epoch, 2, 300);
    home.push(0, resealed.clone()).unwrap();
    let read: Vec<vos_wire::personal::Envelope> = home
        .query(kit_key(1, 1), "since", (RECOVERY, 0u64))
        .unwrap();
    assert_eq!(
        read.iter()
            .map(|envelope| envelope.bytes.clone())
            .collect::<Vec<_>>(),
        vec![resealed]
    );

    // Two seasoned devices rotate at once, the R2 posted first.
    let (second, r2) = new_kit(2);
    let rotation = home.operate(admin(1), "rotate", second.clone()).unwrap();
    home.deposit(
        sync(1),
        device(1).admin,
        rotation,
        "rotate",
        second.clone(),
        r2,
    )
    .unwrap();
    home.operate(admin(0), "cosign", rotation).unwrap();
    assert!(matured(state(&home, sync(0), rotation)));
    home.query::<RecoveryView>(kit_key(2, 0), "recovery", ())
        .unwrap();

    // The kit's rotation waits, and a veto cancels it.
    let (third, _) = new_kit(3);
    let rotation = home.operate(kit_key(2, 1), "rotate", third).unwrap();
    assert_eq!(
        home.operation(sync(0), rotation).matures,
        home.now() - 1 + 7 * MINUTE
    );
    home.operate(admin(1), "veto", rotation).unwrap();
    assert_eq!(
        cancelled(state(&home, sync(0), rotation)),
        Some(Cancel::Veto)
    );
}

/// A12: another seasoned device, or the kit, replaces a device's admin
/// key: the old key signs until the replacement matures, its probation,
/// and the new key from then; the device keeps its seasoning. The device
/// itself and an unseasoned device sign no replacement.
#[test]
fn an_admin_key_replacement_keeps_the_seasoning() {
    let mut home = seasoned(2);
    home.pair(0, 2);
    home.pass(3 * MINUTE);
    assert_eq!(
        home.operate(admin(1), "replace", (1u32, new_admin(1))),
        Err(PersonalError::Targeted)
    );
    assert_eq!(
        home.operate(admin(2), "replace", (1u32, new_admin(1))),
        Err(PersonalError::Unseasoned)
    );
    let replacement = home
        .operate(admin(0), "replace", (1u32, new_admin(1)))
        .unwrap();
    home.pass(3 * MINUTE - 3);
    let replaced = Principal::Client(new_admin(1).key);
    assert_eq!(
        home.operate(replaced, "remove", 2u32),
        Err(PersonalError::NotAdmitted),
        "the new key signs nothing in its probation"
    );
    home.pass(1);
    let removal = home.operate(replaced, "remove", 2u32).unwrap();
    assert!(matured(state(&home, sync(0), replacement)));
    assert_eq!(
        home.operate(admin(1), "veto", removal),
        Err(PersonalError::NotAdmitted),
        "the old key is admitted no more"
    );
    let one = view(&home, sync(0), 1);
    assert!(one.seasoned);
    assert_eq!(one.device.keys.admin, new_admin(1).key);
    assert!(
        !one.device.keys.attestation.verified_boot,
        "recorded, shown"
    );
    home.operate(replaced, "cosign", removal)
        .expect_err("its own removal");
    home.operate(admin(0), "cosign", removal).unwrap();
    // The kit's replacement waits the kit's delay.
    let replacement = home.operate(KIT, "replace", (0u32, new_admin(2))).unwrap();
    let operation = home.operation(sync(0), replacement);
    assert_eq!(operation.matures, operation.at + 7 * MINUTE);
}

/// E29: a replacement contested and resolved upheld still waits out the
/// new key's probation: the new key signs nothing before it, and the
/// replacement matures at its own time.
#[test]
fn a_resolved_replacement_keeps_its_probation() {
    let mut home = seasoned(2);
    let replacement = home
        .operate(admin(0), "replace", (1u32, new_admin(1)))
        .unwrap();
    home.operate(admin(1), "veto", replacement).unwrap();
    assert_eq!(state(&home, sync(0), replacement), OpState::Contested);
    home.operate(KIT, "resolve", (replacement, true)).unwrap();
    assert!(
        !matured(state(&home, sync(0), replacement)),
        "upheld, in its probation"
    );
    let replaced = Principal::Client(new_admin(1).key);
    home.pass(MINUTE);
    assert_eq!(
        home.operate(replaced, "remove", 0u32),
        Err(PersonalError::NotAdmitted),
        "the new key signs nothing in its probation"
    );
    home.pass(2 * MINUTE);
    home.wake(sync(0)).unwrap();
    assert!(matured(state(&home, sync(0), replacement)));
    assert_eq!(view(&home, sync(0), 1).device.keys.admin, new_admin(1).key);
}

/// Rule 1, A18: a delayed admin's add is an operation that waits and can
/// be contested, then a commit carries it; it never adds inline.
#[test]
fn a_delayed_admins_add_waits_then_a_commit_carries_it() {
    let mut home = Home::with(minutes());
    home.pair_keys(0, delayed(1));
    home.pass(3 * MINUTE);
    home.call::<Recorded>(sync(0), "alive", ()).unwrap();
    home.call::<Recorded>(sync(1), "alive", ()).unwrap();
    let add = |n| Effect {
        add: Some(device(n)),
        remove: Vec::new(),
        rekey: None,
    };
    assert_eq!(
        home.call::<Candidacy>(admin(1), "commit", commit(2, add(2), vec![2; 600])),
        Err(PersonalError::Delayed)
    );
    let operation = home.operate(admin(1), "add", device(2)).unwrap();
    assert_eq!(
        home.call::<Candidacy>(admin(1), "commit", commit(2, add(2), vec![2; 600])),
        Err(PersonalError::Delayed),
        "not yet matured"
    );
    home.pass(3 * MINUTE);
    let candidacy: Candidacy = home
        .call(admin(1), "commit", commit(2, add(2), vec![2; 600]))
        .unwrap();
    home.confirm_all(2, &candidacy.set);
    assert_eq!(
        state(&home, sync(0), operation),
        OpState::Carried { epoch: 2 }
    );
    assert_eq!(standing(&home, sync(0), 2), Standing::Probation);
    // A contested add does not mature.
    let contested = home.operate(admin(1), "add", device(3)).unwrap();
    home.operate(admin(0), "veto", contested).unwrap();
    home.pass(10 * MINUTE);
    home.call::<Recorded>(sync(0), "alive", ()).unwrap();
    assert_eq!(state(&home, sync(0), contested), OpState::Contested);
}

/// A24: a regroup by a seasoned device names every other live device,
/// waits and is vetoable as a removal is, and is immediate with the kit's
/// second signature: every other device removed, one paired while it was
/// open too, its signer alone kept, and the pending candidate, the old
/// group's, void.
#[test]
fn a_regroup_removes_every_other_device_and_starts_a_new_group() {
    let mut home = seasoned(3);
    home.pair(0, 3);
    home.pass(3 * MINUTE);
    assert_eq!(
        home.operate(admin(3), "regroup", vec![0u32, 1, 2]),
        Err(PersonalError::Unseasoned)
    );
    assert_eq!(
        home.operate(admin(0), "regroup", vec![0u32]),
        Err(PersonalError::Targeted)
    );
    assert_eq!(
        home.operate(KIT, "regroup", vec![2u32]),
        Err(PersonalError::NotSigner)
    );
    assert_eq!(
        home.operate(admin(0), "regroup", vec![2u32]),
        Err(PersonalError::Malformed),
        "it keeps its signer alone"
    );
    let regroup = home.operate(admin(0), "regroup", vec![1u32, 2, 3]).unwrap();
    home.operate(admin(2), "veto", regroup).unwrap();
    assert_eq!(state(&home, sync(0), regroup), OpState::Contested);
    home.pair(0, 4);
    let epoch = home.overview().confirmed + 1;
    let candidacy: Candidacy = home.call(admin(1), "commit", update(epoch, 4)).unwrap();
    home.operate(KIT, "cosign", regroup).unwrap();
    assert!(matured(state(&home, sync(0), regroup)));
    for id in 1..=4 {
        assert_eq!(standing(&home, sync(0), id), Standing::Removed, "{id}");
    }
    assert_ne!(standing(&home, sync(0), 0), Standing::Removed);
    assert_eq!(home.overview().candidate, None);
    let entries: Vec<(u64, Entry)> = home.query(sync(0), "log", candidacy.index).unwrap();
    assert!(entries.iter().any(|(_, entry)| entry.body
        == Body::Verdict {
            epoch,
            verdict: Verdict::Void(Void::Regroup)
        }));
}

/// Rule 9: once a device's removal matures, its vetoes count no more, so
/// a contest resting on them alone is pending again and matures, and its
/// own open operations are cancelled.
#[test]
fn a_removed_devices_vetoes_and_operations_count_no_more() {
    let mut home = seasoned(3);
    let owners = home.operate(admin(0), "remove", 1u32).unwrap();
    home.operate(admin(2), "veto", owners).unwrap();
    let thiefs = home
        .operate(admin(2), "replace", (1u32, new_admin(1)))
        .unwrap();
    home.operate(admin(1), "veto", thiefs).unwrap();
    home.pass(5 * MINUTE);
    let removal = home.operate(admin(0), "remove", 2u32).unwrap();
    home.operate(admin(1), "cosign", removal).unwrap();
    assert_eq!(standing(&home, sync(0), 2), Standing::Removed);
    assert_eq!(state(&home, sync(0), owners), OpState::Contested);
    // The next call settles the silencing, a row a step, in time order.
    home.call::<Recorded>(sync(0), "alive", ()).unwrap();
    assert_eq!(
        cancelled(state(&home, sync(0), thiefs)),
        Some(Cancel::Signer)
    );
    assert!(
        matured(state(&home, sync(0), owners)),
        "its delay passed: due once its contest lifted"
    );
}

/// Rule 9 inside the delay: a contest resting on a removed device's veto
/// alone is pending again once a call settles its silencing, which a read
/// does not, so the kit has no contest to resolve, and the removal matures
/// at its own time.
#[test]
fn a_contest_lifted_inside_the_delay_matures_at_its_own_time() {
    let mut home = seasoned(3);
    let removal = home.operate(admin(0), "remove", 2u32).unwrap();
    let matures = home.operation(sync(0), removal).matures;
    home.operate(admin(1), "veto", removal).unwrap();
    let vetoers = home.operate(admin(0), "remove", 1u32).unwrap();
    home.operate(admin(1), "veto", vetoers).unwrap();
    home.operate(KIT, "resolve", (vetoers, true)).unwrap();
    assert_eq!(standing(&home, sync(0), 1), Standing::Removed);
    assert_eq!(
        state(&home, sync(0), removal),
        OpState::Contested,
        "a read shows what the agent stores"
    );
    assert_eq!(
        home.operate(KIT, "resolve", (removal, true)),
        Err(PersonalError::Uncontested),
        "a call settles the silencing before it runs"
    );
    assert_eq!(
        state(&home, sync(0), removal),
        OpState::Contested,
        "refused, it wrote nothing"
    );
    home.call::<Recorded>(sync(0), "alive", ()).unwrap();
    assert_eq!(state(&home, sync(0), removal), OpState::Pending);
    assert_eq!(
        home.operation(sync(0), removal).matures,
        matures,
        "due at its own time"
    );
    home.pass(matures - home.overview().at - 1);
    assert_eq!(standing(&home, sync(0), 2), Standing::Active);
    home.call::<Recorded>(sync(0), "alive", ()).unwrap();
    assert_eq!(state(&home, sync(0), removal), OpState::Pending);
    home.call::<Recorded>(sync(0), "alive", ()).unwrap();
    assert_eq!(
        state(&home, sync(0), removal),
        OpState::Matured { at: matures }
    );
    assert_eq!(standing(&home, sync(0), 2), Standing::Removed);
}

/// B6: an admin call names its place, the log's head its signer read, and
/// is taken at a place no earlier than the entry after the last admin call
/// logged and no later than the head. One behind that call, naming a chain
/// the log never had or a head ahead of it is refused `StaleHead`, and
/// logs nothing: a call the log took cannot be taken again later, so a
/// route that logs it again on a fork logs what no agent took. Entries
/// that are no admin call move no place on, and what fell due is settled
/// ahead of a call placed before the batch settles it.
#[test]
fn an_admin_call_is_taken_only_at_the_place_it_names() {
    let mut home = seasoned(3);
    let before = home.head(admin(0));
    let removal = home.unevidenced(admin(0), "remove", 2u32).unwrap();
    assert_eq!(removal, before.next, "logged at its place");
    let head = home.head(admin(1));
    let elsewhere = [
        before,
        Place {
            next: head.next,
            chain: [0xab; 32],
        },
        Place {
            next: head.next + 1,
            chain: head.chain,
        },
    ];
    for place in elsewhere {
        let run = home.run_as(admin(1), "veto", place.arguments(&removal.encode()));
        assert_eq!(
            answer::<Recorded>("veto", &run.outcome),
            Err(PersonalError::StaleHead)
        );
        let run = home.run_as(admin(0), "remove", place.arguments(&1u32.encode()));
        assert_eq!(
            answer::<Recorded>("remove", &run.outcome),
            Err(PersonalError::StaleHead)
        );
    }
    assert_eq!(home.head(admin(1)), head, "nothing logged");
    // A lease renewed is no admin call: the veto signed before it is taken.
    let run = home.run_as(HOMES, "renew", Vec::new());
    answer::<Recorded>("renew", &run.outcome).unwrap();
    let run = home.run_as(admin(1), "veto", head.arguments(&removal.encode()));
    let veto = answer::<Recorded>("veto", &run.outcome).unwrap();
    assert!(veto.index > head.next, "{veto:?} after {head:?}");
    assert_eq!(home.logged(veto.index), head.arguments(&removal.encode()));
    // A removal falls due unevidenced: a call placed before the batch
    // settles it is taken after the cancellation.
    let due = home.unevidenced(admin(0), "remove", 1u32).unwrap();
    let place = home.head(admin(2));
    home.pass(3 * MINUTE + 1);
    let run = home.run_as(admin(2), "remove", place.arguments(&0u32.encode()));
    let taken = answer::<Recorded>("remove", &run.outcome).unwrap();
    assert!(taken.index > place.next, "{taken:?} after {place:?}");
    assert_eq!(
        cancelled(state(&home, sync(0), due)),
        Some(Cancel::Unevidenced)
    );
}

/// B6 for commits: a commit names its place as every admin call does and
/// is taken by the same rule. One behind the last admin call, on a chain
/// the log never had or ahead of the head is refused `StaleHead` and logs
/// nothing; one placed before entries that are no admin call is taken. A
/// commit the window's end voided, sent again at its place, is refused:
/// the agent takes it at no later index under the epoch the void left,
/// while a commit placed before that batch settled the void is taken
/// after it.
#[test]
fn a_commit_is_taken_only_at_the_place_it_names() {
    let mut home = seasoned(3);
    let epoch = home.overview().confirmed + 1;
    let before = home.head(admin(0));
    home.unevidenced(admin(0), "remove", 2u32).unwrap();
    let head = home.head(admin(1));
    let elsewhere = [
        before,
        Place {
            next: head.next,
            chain: [0xab; 32],
        },
        Place {
            next: head.next + 1,
            chain: head.chain,
        },
    ];
    let first = update(epoch, 1).encode();
    for place in elsewhere {
        let run = home.run_as(admin(1), "commit", place.arguments(&first));
        assert_eq!(
            answer::<Candidacy>("commit", &run.outcome),
            Err(PersonalError::StaleHead)
        );
    }
    assert_eq!(home.head(admin(1)), head, "nothing logged");
    let run = home.run_as(HOMES, "renew", Vec::new());
    answer::<Recorded>("renew", &run.outcome).unwrap();
    let run = home.run_as(admin(1), "commit", head.arguments(&first));
    let candidacy = answer::<Candidacy>("commit", &run.outcome).unwrap();
    assert!(candidacy.index > head.next, "{candidacy:?} after {head:?}");
    assert_eq!(home.logged(candidacy.index), head.arguments(&first));

    let place = home.head(admin(2));
    home.pass(minutes().confirm_window_ms + 1);
    let run = home.run_as(admin(1), "commit", head.arguments(&first));
    assert_eq!(
        answer::<Candidacy>("commit", &run.outcome),
        Err(PersonalError::StaleHead)
    );
    let second = update(epoch, 2).encode();
    let run = home.run_as(admin(2), "commit", place.arguments(&second));
    let next = answer::<Candidacy>("commit", &run.outcome).unwrap();
    assert!(next.index > place.next, "{next:?} after {place:?}");
    assert_eq!(home.logged(next.index), place.arguments(&second));
    let voided = (candidacy.index..next.index).any(|index| {
        home.query::<Vec<(u64, Entry)>>(sync(0), "log", index)
            .unwrap()
            .iter()
            .any(|(at, entry)| {
                *at == index
                    && entry.body
                        == Body::Verdict {
                            epoch,
                            verdict: Verdict::Void(Void::Timeout),
                        }
            })
    });
    assert!(voided, "the first voided before the second");
}

/// B6: every operation and veto is an admin call whose evidence its
/// signer posts, a device under its sync key and the kit under its own.
#[test]
fn operations_are_signed_end_to_end_and_their_evidence_stored() {
    let mut home = seasoned(2);
    let removal = home.unevidenced(KIT, "remove", 1u32).unwrap();
    let signed = message(KIT_KEY, home.method("remove"), &home.logged(removal));
    assert_eq!(
        home.call::<Recorded>(
            sync(0),
            "evidence",
            evidence(removal, signed.clone(), Attached::default())
        ),
        Err(PersonalError::NotYours)
    );
    home.call::<Recorded>(
        KIT,
        "evidence",
        evidence(removal, signed, Attached::default()),
    )
    .unwrap();
    let veto = home.operate(admin(1), "veto", removal).unwrap();
    let signed = message(device(1).admin, home.method("veto"), &home.logged(veto));
    home.call::<Recorded>(
        sync(1),
        "evidence",
        evidence(veto, signed, Attached::default()),
    )
    .unwrap();
    let entries: Vec<(u64, Entry)> = home.query(sync(0), "log", removal).unwrap();
    assert!(matches!(
        entries[0].1.body,
        Body::Operation {
            by: vos_wire::personal::Signer::Kit(0),
            ..
        }
    ));
    assert!(entries.iter().any(|(_, entry)| matches!(
        entry.body,
        Body::Veto { by: 1, op, .. } if op == removal
    )));
}

/// What one call may cost: half the limit `Personal`'s settling handlers
/// declare, 40M, so the bound holds with room.
const BOUND: u64 = 20_000_000;

/// A full set, eight seasoned devices, each holding as many operations as
/// it may (device 0 one fewer, for the regroup), each operation vetoed by
/// every other device and resolved by one: its operations by signer.
fn full_set() -> (Home, Vec<(u64, u8)>) {
    let mut home = Home::with(minutes());
    for n in 1..8 {
        home.pair(0, n);
    }
    home.pass(10 * MINUTE);
    for n in 0..8 {
        home.call::<Recorded>(sync(n), "alive", ()).unwrap();
    }
    let mut held = Vec::new();
    for n in 0..8u8 {
        for k in u8::from(n == 0)..2 {
            let index = home
                .operate(admin(n), "add", device(16 + 2 * n + k))
                .unwrap();
            held.push((index, n));
        }
    }
    for (index, signer) in &held {
        let (index, signer) = (index, *signer);
        for n in (0..8u8).filter(|n| *n != signer) {
            home.operate(admin(n), "veto", *index).unwrap();
        }
        home.operate(admin((signer + 1) % 8), "resolve", (*index, false))
            .unwrap();
    }
    (home, held)
}

fn within_bound(home: &Home) {
    for (name, gas) in &home.gas {
        assert!(*gas < BOUND, "{name}: {gas} gas");
    }
}

/// The bounds: a regroup naming seven devices, each of which vetoed every
/// operation and holds as many as it may, matures, and their silencing
/// cancels and lifts every one, a row a step; a restore over the same set
/// matures. Each call stays under [`BOUND`].
#[test]
fn the_worst_regroup_and_restore_stay_within_a_calls_gas() {
    let (mut home, held) = full_set();
    let regroup = home
        .operate(admin(0), "regroup", (1..8u32).collect::<Vec<_>>())
        .unwrap();
    home.pass(3 * MINUTE);
    home.wake(sync(0)).unwrap();
    assert!(matured(state(&home, sync(0), regroup)));
    for (index, signer) in held {
        let state = state(&home, sync(0), index);
        if signer == 0 {
            assert!(matured(state), "{index}: {state:?}, its vetoers silenced");
        } else {
            assert_eq!(cancelled(state), Some(Cancel::Signer), "{index}");
        }
    }
    within_bound(&home);

    let (mut home, _) = full_set();
    let (next, r2) = new_kit(1);
    let restore = (device(50), next);
    let index = home.operate(KIT, "restore", restore.clone()).unwrap();
    home.deposit(KIT, KIT_KEY, index, "restore", restore, r2)
        .unwrap();
    home.pass(7 * MINUTE);
    // The restore replaces the kit: its next wakes are the new kit's.
    home.wake(KIT)
        .or_else(|_| home.wake(kit_key(1, 0)))
        .unwrap();
    assert!(matured(state(&home, kit_key(1, 0), index)));
    within_bound(&home);
}

/// Settling: a call settles a few steps due before it runs and refuses
/// with `Settling` while more are due, writing nothing; `wake` settles
/// them a few at a time, and each matures at its own time however late.
#[test]
fn a_call_refuses_while_operations_are_left_due_and_wake_settles_them() {
    let mut home = seasoned(6);
    let removals: Vec<(u64, u32)> = (2..6u32)
        .map(|target| (home.operate(admin(0), "remove", target).unwrap(), target))
        .collect();
    home.pass(10 * MINUTE);
    let refused = home.run(sync(1), "alive", ());
    assert!(matches!(
        answer::<Recorded>("alive", &refused.outcome),
        Err(PersonalError::Settling)
    ));
    assert!(refused.writes.is_empty(), "a refused call writes nothing");
    let woken: Woken = home.call(sync(1), "wake", ()).unwrap();
    assert!(!woken.settled);
    let woken: Woken = home.call(sync(1), "wake", ()).unwrap();
    assert!(woken.settled);
    for (index, target) in removals {
        let operation = home.operation(sync(0), index);
        assert_eq!(
            operation.state,
            OpState::Matured {
                at: operation.matures
            }
        );
        assert_eq!(
            view(&home, sync(0), target).removal.unwrap().at,
            operation.matures
        );
    }
    home.call::<Recorded>(sync(1), "alive", ()).unwrap();
}

/// Rule 5: a regroup naming a device and that device's removal of the
/// regroup's signer are one contest, in either order.
#[test]
fn a_regroup_and_its_targets_removal_of_its_signer_are_one_contest() {
    let mut home = seasoned(3);
    let regroup = home.operate(admin(0), "regroup", vec![1u32, 2]).unwrap();
    let removal = home.operate(admin(1), "remove", 0u32).unwrap();
    for index in [regroup, removal] {
        assert_eq!(state(&home, sync(2), index), OpState::Contested);
    }
    home.operate(KIT, "resolve", (removal, false)).unwrap();
    assert!(matured(state(&home, sync(0), regroup)));
    assert_eq!(standing(&home, sync(0), 1), Standing::Removed);
}

/// The keys an open operation brings are taken: a pairing slot or an add
/// cannot squat them to cancel it at maturity.
#[test]
fn an_open_operations_keys_cannot_be_squatted() {
    let mut home = seasoned(2);
    let replacement = home
        .operate(admin(0), "replace", (1u32, new_admin(1)))
        .unwrap();
    assert_eq!(
        home.call::<u64>(sync(1), "open_slot", (scope(9), new_admin(1).key)),
        Err(PersonalError::KeyTaken)
    );
    let (kit, _) = new_kit(1);
    home.operate(admin(1), "rotate", kit.clone()).unwrap();
    let squat = NewDevice {
        admin: kit.entries[0].signing,
        ..device(4)
    };
    let effect = Effect {
        add: Some(squat),
        remove: Vec::new(),
        rekey: None,
    };
    let epoch = home.overview().confirmed + 1;
    assert_eq!(
        home.call::<Candidacy>(admin(0), "commit", commit(epoch, effect, vec![4; 600])),
        Err(PersonalError::KeyTaken)
    );
    home.pass(3 * MINUTE);
    home.wake(sync(0)).unwrap();
    assert!(matured(state(&home, sync(0), replacement)));
}

/// A device's rotation is a veto of the kit's pending restore or
/// rotation, so a leaked kit cannot hold the kit's place; and the kit's
/// operations count against the policy's daily allowance.
#[test]
fn a_devices_rotation_takes_the_kits_place_and_the_kit_has_an_allowance() {
    let policy = Policy {
        kit_operations_per_day: 2,
        ..minutes()
    };
    let mut home = Home::with(policy);
    let (next, _) = new_kit(1);
    let restore = home
        .operate(KIT, "restore", (device(5), next.clone()))
        .unwrap();
    let (rotated, _) = new_kit(2);
    home.operate(admin(0), "rotate", rotated).unwrap();
    assert_eq!(
        cancelled(state(&home, sync(0), restore)),
        Some(Cancel::Veto)
    );
    home.operate(KIT, "remove", 0u32).unwrap();
    assert_eq!(
        home.operate(KIT, "replace", (0u32, new_admin(3))),
        Err(PersonalError::Quota)
    );
}

/// A device whose add a candidate makes signs nothing before the verdict
/// (`Undecided`), so a void candidate drops it with nothing of its open.
#[test]
fn an_undecided_device_signs_nothing_and_is_dropped_with_its_candidate() {
    let policy = Policy {
        confirm_window_ms: 10 * MINUTE,
        ..minutes()
    };
    let mut home = Home::with(policy);
    home.pair(0, 1);
    let effect = Effect {
        add: Some(device(2)),
        remove: Vec::new(),
        rekey: None,
    };
    let candidacy: Candidacy = home
        .call(admin(0), "commit", commit(2, effect, vec![2; 600]))
        .unwrap();
    home.pass(3 * MINUTE);
    assert_eq!(
        home.operate(admin(2), "add", device(6)),
        Err(PersonalError::Undecided)
    );
    home.call::<Voted>(sync(0), "nack", (2u64, [0u8; 64]))
        .unwrap();
    assert!(candidacy.set.contains(&0));
    assert_eq!(standing(&home, sync(0), 2), Standing::Dropped);
}

/// The previous `R2` stays released until the restore's device has
/// committed a group of its own.
#[test]
fn the_released_r2_is_deleted_at_the_restored_devices_first_commit() {
    let mut home = Home::with(minutes());
    let removal = home.operate(KIT, "remove", 0u32).unwrap();
    home.pass(7 * MINUTE);
    home.wake(KIT).unwrap();
    assert!(matured(state(&home, KIT, removal)));
    let (next, r2) = new_kit(1);
    let restore = (device(5), next);
    let index = home.operate(KIT, "restore", restore.clone()).unwrap();
    home.deposit(KIT, KIT_KEY, index, "restore", restore, r2)
        .unwrap();
    home.pass(7 * MINUTE);
    home.wake(KIT)
        .or_else(|_| home.wake(kit_key(1, 0)))
        .unwrap();
    let released: RecoveryView = home.query(sync(5), "recovery", ()).unwrap();
    assert_eq!(released.released, Some(kit().r2));
    assert_eq!(released.previous, kit().entries, "the entries it went with");
    let (rekey, r2) = home.rekey(sync(5), 9);
    let effect = Effect {
        add: None,
        remove: vec![0],
        rekey: Some(rekey.clone()),
    };
    let arguments = commit(1, effect, vec![9; 600]);
    let candidacy: Candidacy = home.call(admin(5), "commit", arguments.clone()).unwrap();
    let entries: Vec<(u64, Entry)> = home.query(sync(5), "log", candidacy.index).unwrap();
    let Body::Candidate { call, .. } = &entries[0].1.body else {
        panic!("{:?}", entries[0]);
    };
    let signed = message(device(5).admin, home.method("commit"), &call.arguments);
    assert_eq!(
        home.call::<Recorded>(
            sync(5),
            "evidence",
            evidence(candidacy.index, signed.clone(), Attached::default())
        ),
        Err(PersonalError::Welcome),
        "a re-sealed kit's evidence carries its R2"
    );
    home.call::<Recorded>(
        sync(5),
        "evidence",
        evidence(candidacy.index, signed, with_r2(r2)),
    )
    .unwrap();
    let pushed = home.push(5, envelope(RECOVERY, 0, 3, 200)).unwrap();
    home.call::<Voted>(sync(5), "confirm", (1u64, [1u8; 32], [0u8; 64]))
        .unwrap();
    assert_eq!(candidacy.set, vec![1]);
    let released: RecoveryView = home.query(sync(5), "recovery", ()).unwrap();
    assert_eq!(released.released, None);
    assert!(released.previous.is_empty());
    assert_eq!(released.entries, rekey.entries, "the kit re-sealed");
    assert_eq!(
        released.from, pushed.position,
        "the kit reads what follows the re-seal"
    );
}

/// The rows of an open removal, by their keys: the due index's under its
/// maturity, its tag (an operation's, before a silencing's or a kit's
/// retirement at one time) and its index; the signer's under its tag and
/// its device, then the index; its kind's under the kind's byte and its
/// target.
#[test]
fn an_open_removal_is_keyed_by_its_maturity_its_signer_and_its_kind() {
    use vos_abi::keys::{self, Transform};
    use vos_testkit::programs::table_tag;

    let mut home = seasoned(3);
    let removal = home.operate(admin(0), "remove", 2u32).unwrap();
    let matures = home.operation(sync(0), removal).matures;
    let row = |table: &str, transform: Transform, key: &[u8]| {
        let mut row = keys::table_rows(PERSONAL, table_tag(table), transform);
        transform.append(key, &mut row);
        home.node().get(&row)
    };
    let due = [&matures.to_be_bytes()[..], &[0], &removal.to_be_bytes()].concat();
    assert_eq!(row("due", Transform::Ordered, &due), Some(Vec::new()));
    let signed = [&[0, 0, 0, 0, 0][..], &removal.to_be_bytes()].concat();
    assert_eq!(row("signed", Transform::Ordered, &signed), Some(vec![0]));
    let kind = [&[0][..], &2u32.to_be_bytes()].concat();
    assert_eq!(
        row("kinds", Transform::Hashed, &kind),
        Some(removal.encode())
    );
}

/// The whole log `reader` reads, page by page.
fn log_read(home: &Home, reader: Principal) -> Result<Vec<(u64, Entry)>, PersonalError> {
    let mut log: Vec<(u64, Entry)> = Vec::new();
    loop {
        let from = log.last().map_or(0, |(index, _)| index + 1);
        let page: Vec<(u64, Entry)> = home.query(reader, "log", from)?;
        if page.is_empty() {
            return Ok(log);
        }
        log.extend(page);
    }
}

/// A removed device's sync key reads the log through its removal's entry
/// and on within the confirming window after its maturity, where the
/// evidence its removal rests on is, so the device leaves on the log it
/// verifies; past the window nothing, and nothing else at all. A key never
/// admitted reads nothing.
#[test]
fn a_removed_device_reads_the_log_its_removal_rests_on() {
    let mut home = seasoned(3);
    home.operate(admin(0), "remove", 2u32).unwrap();
    home.pass(3 * MINUTE);
    home.call::<Recorded>(sync(0), "alive", ()).unwrap();
    assert_eq!(standing(&home, sync(0), 2), Standing::Removed);
    let removed = log_read(&home, sync(2)).unwrap();
    assert!(
        removed
            .iter()
            .any(|(_, entry)| entry.body == Body::Matured { device: 2 }),
        "its removal's entry"
    );
    assert_eq!(removed, log_read(&home, sync(0)).unwrap());
    // Within the window, the set's entries after its removal too.
    let within = home.operate(admin(0), "remove", 1u32).unwrap();
    let removed = log_read(&home, sync(2)).unwrap();
    assert!(removed.iter().any(|(index, _)| *index == within));
    assert_eq!(
        home.query::<Overview>(sync(2), "overview", ()),
        Err(PersonalError::NotAdmitted)
    );
    assert_eq!(
        home.query::<Vec<(u64, Entry)>>(admin(2), "log", 0u64),
        Err(PersonalError::NotAdmitted),
        "its admin key reads nothing"
    );

    home.pass(4 * MINUTE);
    let later = home.operate(KIT, "remove", 0u32).unwrap();
    assert_eq!(
        log_read(&home, sync(2)).unwrap(),
        removed,
        "nothing past the window"
    );
    assert!(
        log_read(&home, sync(0))
            .unwrap()
            .iter()
            .any(|(index, _)| *index == later)
    );
    assert_eq!(
        home.query::<Vec<(u64, Entry)>>(Principal::Client([0x77; 32]), "log", 0u64),
        Err(PersonalError::NotAdmitted)
    );
}

/// A leave: a device's own removal, signed by its own admin key, on its
/// probation too, matures when its evidence is posted, with no delay;
/// no device vetoes or cosigns it, and from then the device has no voice.
/// The set's last live device may not leave: nothing would commit it.
#[test]
fn a_device_leaves_by_its_own_removal_on_its_probation_too() {
    let mut home = seasoned(1);
    home.pair(0, 1);
    assert_eq!(standing(&home, sync(0), 1), Standing::Probation);
    let leave = home.unevidenced(admin(1), "remove", 1u32).unwrap();
    assert_eq!(state(&home, sync(0), leave), OpState::Pending);
    assert_eq!(
        home.unevidenced(admin(1), "remove", 1u32),
        Err(PersonalError::Pending),
        "one leave open at once"
    );
    assert_eq!(
        home.operate(admin(0), "veto", leave),
        Err(PersonalError::Leaving)
    );
    assert_eq!(
        home.operate(admin(0), "cosign", leave),
        Err(PersonalError::Leaving)
    );
    assert_eq!(
        home.operate(admin(1), "veto", leave),
        Err(PersonalError::Probation),
        "a leave signs nothing else on probation"
    );
    let signed = message(device(1).admin, home.method("remove"), &home.logged(leave));
    home.call::<Recorded>(
        sync(1),
        "evidence",
        evidence(leave, signed, Attached::default()),
    )
    .unwrap();
    assert!(matured(state(&home, sync(0), leave)));
    assert_eq!(standing(&home, sync(0), 1), Standing::Removed);
    let log = log_read(&home, sync(1)).unwrap();
    assert!(
        log.iter()
            .any(|(_, entry)| entry.body == Body::Matured { device: 1 }),
        "the leaver reads its removal through"
    );
    assert_eq!(
        home.operate(admin(1), "remove", 0u32),
        Err(PersonalError::NotAdmitted),
        "its keys admitted no more"
    );
    assert_eq!(
        home.operate(admin(0), "remove", 0u32),
        Err(PersonalError::Alone)
    );
}

/// A leave whose evidence never comes is cancelled `Unevidenced` once the
/// operation delay passes, its signer keeping its voice.
#[test]
fn a_leave_without_its_evidence_is_cancelled() {
    let mut home = seasoned(2);
    let leave = home.unevidenced(admin(1), "remove", 1u32).unwrap();
    home.pass(3 * MINUTE + 1);
    home.wake(sync(0)).unwrap();
    assert_eq!(
        cancelled(state(&home, sync(0), leave)),
        Some(Cancel::Unevidenced)
    );
    assert_eq!(standing(&home, sync(0), 1), Standing::Active);
    home.operate(admin(1), "remove", 1u32).unwrap();
    assert_eq!(standing(&home, sync(0), 1), Standing::Removed);
}

/// A leave while another device's removal of the leaver is open, pending,
/// vetoed by the leaver, or one of a pair aimed at each other: the leave
/// takes no other removal's place and matures; the removal of the leaver
/// ends `Moot` with it, and the leaver's own removal of its rival is
/// cancelled with its silencing, the rival keeping its voice.
#[test]
fn a_leave_ends_the_removals_aimed_at_its_device() {
    for case in ["pending", "vetoed", "rivals"] {
        let mut home = seasoned(3);
        let removal = home.operate(admin(0), "remove", 2u32).unwrap();
        let rival = match case {
            "vetoed" => {
                home.operate(admin(2), "veto", removal).unwrap();
                None
            }
            "rivals" => Some(home.operate(admin(2), "remove", 0u32).unwrap()),
            _ => None,
        };
        let leave = home.operate(admin(2), "remove", 2u32).unwrap();
        assert!(matured(state(&home, sync(0), leave)), "{case}");
        assert_eq!(standing(&home, sync(0), 2), Standing::Removed, "{case}");
        assert_eq!(
            cancelled(state(&home, sync(0), removal)),
            Some(Cancel::Moot),
            "{case}"
        );
        home.wake(sync(0)).unwrap();
        if let Some(rival) = rival {
            assert_eq!(
                cancelled(state(&home, sync(0), rival)),
                Some(Cancel::Signer),
                "{case}"
            );
        }
        assert_eq!(standing(&home, sync(0), 0), Standing::Active, "{case}");
        home.pass(10 * MINUTE);
        assert_eq!(standing(&home, sync(1), 0), Standing::Active, "{case}");
    }
}

/// A leave on a probation frozen under the kit's removal of the device,
/// with a replacement of its admin key open too: both end `Moot` with the
/// leave. Evidence posted past the leave's deadline leaves it cancelled.
/// An active leaver vetoes and cosigns its own leave no more than another.
#[test]
fn a_leave_on_a_frozen_probation_ends_what_acts_on_it() {
    let mut home = seasoned(2);
    home.pair(0, 2);
    let removal = home.operate(KIT, "remove", 2u32).unwrap();
    let replacement = home
        .operate(admin(0), "replace", (2u32, new_admin(2)))
        .unwrap();
    assert_eq!(standing(&home, sync(0), 2), Standing::Probation);
    let leave = home.operate(admin(2), "remove", 2u32).unwrap();
    assert!(matured(state(&home, sync(0), leave)));
    for open in [removal, replacement] {
        assert_eq!(cancelled(state(&home, sync(0), open)), Some(Cancel::Moot));
    }

    let leave = home.unevidenced(admin(1), "remove", 1u32).unwrap();
    for name in ["veto", "cosign"] {
        assert_eq!(
            home.operate(admin(1), name, leave),
            Err(PersonalError::Leaving)
        );
    }
    home.pass(3 * MINUTE);
    let signed = message(device(1).admin, home.method("remove"), &home.logged(leave));
    home.call::<Recorded>(
        sync(1),
        "evidence",
        evidence(leave, signed, Attached::default()),
    )
    .unwrap();
    assert_eq!(
        cancelled(state(&home, sync(0), leave)),
        Some(Cancel::Unevidenced)
    );
    assert_eq!(standing(&home, sync(0), 1), Standing::Active);
}

/// A leave beside an add the pending candidate makes: that device is not
/// another live device, so the set's one confirmed device may not leave
/// (were the candidate void, no device would be left), and a leave opened
/// before, evidenced once the only other live device is that one, is
/// cancelled `Alone`. The device being added signs nothing until the
/// verdict, its own leave included; confirmed, it leaves.
#[test]
fn a_leave_counts_only_the_confirmed_group() {
    let mut home = seasoned(1);
    let epoch = home.overview().confirmed + 1;
    let effect = Effect {
        add: Some(device(1)),
        ..Effect::default()
    };
    let candidacy: Candidacy = home
        .call(
            admin(0),
            "commit",
            commit(epoch, effect, vec![epoch as u8; 700]),
        )
        .unwrap();
    assert_eq!(
        home.operate(admin(0), "remove", 0u32),
        Err(PersonalError::Alone),
        "the device being added is no other live device"
    );
    assert_eq!(
        home.unevidenced(admin(1), "remove", 1u32),
        Err(PersonalError::Undecided),
        "the device being added signs no leave"
    );
    home.confirm_all(epoch, &candidacy.set);
    home.operate(admin(1), "remove", 1u32).unwrap();
    assert_eq!(standing(&home, sync(0), 1), Standing::Removed);

    let mut home = seasoned(2);
    let leave = home.unevidenced(admin(0), "remove", 0u32).unwrap();
    let epoch = home.overview().confirmed + 1;
    let effect = Effect {
        add: Some(device(2)),
        ..Effect::default()
    };
    home.call::<Candidacy>(
        admin(1),
        "commit",
        commit(epoch, effect, vec![epoch as u8; 700]),
    )
    .unwrap();
    home.operate(admin(1), "remove", 1u32).unwrap();
    let signed = message(device(0).admin, home.method("remove"), &home.logged(leave));
    home.call::<Recorded>(
        sync(0),
        "evidence",
        evidence(leave, signed, Attached::default()),
    )
    .unwrap();
    assert_eq!(cancelled(state(&home, sync(0), leave)), Some(Cancel::Alone));
    assert_eq!(standing(&home, sync(0), 0), Standing::Active);
}

/// Two leaves opened side by side, each while the other device was live:
/// the first to mature removes its device, and the last live device's is
/// cancelled `Alone`, so the set keeps a device to commit it.
#[test]
fn of_two_leaves_side_by_side_the_last_is_cancelled() {
    let mut home = seasoned(2);
    let first = home.unevidenced(admin(0), "remove", 0u32).unwrap();
    let second = home.unevidenced(admin(1), "remove", 1u32).unwrap();
    for (index, n) in [(first, 0u8), (second, 1u8)] {
        let signed = message(device(n).admin, home.method("remove"), &home.logged(index));
        let _ = home.call::<Recorded>(
            sync(n),
            "evidence",
            evidence(index, signed, Attached::default()),
        );
    }
    assert!(matured(state(&home, sync(1), first)));
    assert_eq!(
        cancelled(state(&home, sync(1), second)),
        Some(Cancel::Alone)
    );
    assert_eq!(standing(&home, sync(1), 1), Standing::Active);
}
