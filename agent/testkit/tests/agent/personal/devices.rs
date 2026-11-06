//! The device set (`light-node.md` §3.5) on a test home's policy, a day a
//! minute: standing and seasoning, operations and their delays, vetoes,
//! contests and resolutions, immediate removal, a probation frozen under
//! a removal, the kit's operations, a restore and its `R2`, kit rotation,
//! admin-key replacement, a delayed admin's add and a regroup.

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
    let removal = home.operate(admin(0), "remove", 0u32).unwrap();
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
    home.pass(3 * MINUTE - 2);
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
    let left = view(&home, sync(0), 2).device.active_from - home.now;
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
        home.now - 1 + left,
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
    home.pass(7 * MINUTE - 2);
    home.operate(admin(0), "veto", removal).unwrap();
    assert_eq!(
        cancelled(state(&home, sync(0), removal)),
        Some(Cancel::Veto)
    );
    let removal = home.operate(KIT, "remove", 1u32).unwrap();
    home.pass(7 * MINUTE - 2);
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
        home.now - 1 + 7 * MINUTE
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
    home.pass(3 * MINUTE - 2);
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
    assert_eq!(
        home.operation(sync(0), replacement).matures,
        home.now - 1 + 7 * MINUTE
    );
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

/// A24: a regroup by a seasoned device waits and is vetoable as a removal
/// is, and is immediate with the kit's second signature: the devices it
/// names removed, and the pending candidate, the old group's, void.
#[test]
fn a_regroup_removes_the_devices_it_names_and_starts_a_new_group() {
    let mut home = seasoned(3);
    home.pair(0, 3);
    home.pass(3 * MINUTE);
    assert_eq!(
        home.operate(admin(3), "regroup", vec![2u32]),
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
    let regroup = home.operate(admin(0), "regroup", vec![2u32]).unwrap();
    home.operate(admin(2), "veto", regroup).unwrap();
    assert_eq!(state(&home, sync(0), regroup), OpState::Contested);
    let epoch = home.overview().confirmed + 1;
    let candidacy: Candidacy = home.call(admin(1), "commit", update(epoch, 4)).unwrap();
    home.operate(KIT, "cosign", regroup).unwrap();
    assert!(matured(state(&home, sync(0), regroup)));
    assert_eq!(standing(&home, sync(0), 2), Standing::Removed);
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
    let thiefs = home.operate(admin(2), "regroup", vec![1u32]).unwrap();
    home.operate(admin(1), "veto", thiefs).unwrap();
    home.pass(5 * MINUTE);
    let removal = home.operate(admin(0), "remove", 2u32).unwrap();
    home.operate(admin(1), "cosign", removal).unwrap();
    assert_eq!(standing(&home, sync(0), 2), Standing::Removed);
    assert_eq!(
        cancelled(state(&home, sync(0), thiefs)),
        Some(Cancel::Signer)
    );
    assert_eq!(
        state(&home, sync(0), owners),
        OpState::Pending,
        "its delay passed: due now"
    );
    home.call::<Recorded>(sync(0), "alive", ()).unwrap();
    assert!(matured(state(&home, sync(0), owners)));
}

/// B6: every operation and veto is an admin call whose evidence its
/// signer posts, a device under its sync key and the kit under its own.
#[test]
fn operations_are_signed_end_to_end_and_their_evidence_stored() {
    let mut home = seasoned(2);
    let removal = home.operate(KIT, "remove", 1u32).unwrap();
    let signed = message(KIT_KEY, home.method("remove"), &1u32.encode());
    assert_eq!(
        home.call::<Recorded>(sync(0), "evidence", evidence(removal, signed.clone(), None)),
        Err(PersonalError::NotYours)
    );
    home.call::<Recorded>(KIT, "evidence", evidence(removal, signed, None))
        .unwrap();
    let veto = home.operate(admin(1), "veto", removal).unwrap();
    let signed = message(device(1).admin, home.method("veto"), &removal.encode());
    home.call::<Recorded>(sync(1), "evidence", evidence(veto, signed, None))
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

/// What one maturity may cost: a handler matures at most one operation
/// before it runs, and its own work at most one more, both within its
/// limit, `MAX_HANDLER_GAS`, if each costs under this.
const CASCADE: u64 = vos_wire::defaults::MAX_HANDLER_GAS / 2;

/// The bounds: a device that vetoed every open operation and holds as
/// many as it may is removed by a second signature, its operations
/// cancelled and every contest it alone held lifted; a restore over a full
/// set, every operation open and contested, matures in one wake. Each
/// costs under [`CASCADE`].
#[test]
fn the_worst_removal_and_restore_fit_their_handlers_gas() {
    let mut home = Home::with(minutes());
    for n in 1..8 {
        home.pair(0, n);
    }
    home.pass(10 * MINUTE);
    for n in 0..8 {
        home.call::<Recorded>(sync(n), "alive", ()).unwrap();
    }
    let thief = 7u8;
    let mut vetoable = Vec::new();
    for n in 0..7u8 {
        for k in 0..2u8 {
            vetoable.push(
                home.operate(admin(n), "add", device(16 + 2 * n + k))
                    .unwrap(),
            );
        }
    }
    for n in 2..7u32 {
        vetoable.push(home.operate(admin(1), "remove", n).unwrap());
    }
    let removal = home.operate(admin(0), "remove", u32::from(thief)).unwrap();
    for n in 0..7u32 {
        home.operate(admin(thief), "remove", n).unwrap_or_default();
    }
    for index in &vetoable {
        home.operate(admin(thief), "veto", *index).unwrap();
    }
    home.operate(admin(thief), "add", device(40)).unwrap();
    home.operate(admin(thief), "add", device(41)).unwrap();
    home.operate(admin(1), "cosign", removal).unwrap();
    assert_eq!(standing(&home, sync(0), 7), Standing::Removed);
    for index in &vetoable {
        assert_eq!(state(&home, sync(0), *index), OpState::Pending);
    }
    assert!(home.gas["cosign"] < CASCADE, "{:?}", home.gas);

    // A restore over a full set whose every operation waits on a contest.
    let mut home = Home::with(minutes());
    for n in 1..8 {
        home.pair(0, n);
    }
    home.pass(10 * MINUTE);
    for n in 0..8u8 {
        home.call::<Recorded>(sync(n), "alive", ()).unwrap();
    }
    for n in 0..8u8 {
        let next = (n + 1) % 8;
        for k in 0..2u8 {
            let index = home
                .operate(admin(n), "add", device(16 + 2 * n + k))
                .unwrap();
            home.operate(admin(next), "veto", index).unwrap();
        }
        let removal = home
            .operate(admin(n), "remove", u32::from((n + 2) % 8))
            .unwrap();
        home.operate(admin(next), "veto", removal).unwrap();
    }
    let (next, r2) = new_kit(1);
    let restore = (device(50), next);
    let index = home.operate(KIT, "restore", restore.clone()).unwrap();
    home.deposit(KIT, KIT_KEY, index, "restore", restore, r2)
        .unwrap();
    home.pass(7 * MINUTE);
    home.wake(KIT).unwrap();
    assert!(matured(state(&home, kit_key(1, 0), index)));
    assert!(home.gas["wake"] < CASCADE, "{:?}", home.gas);
}

/// Settling: a call matures one operation due before it runs and refuses
/// with `Settling` while more are due, writing nothing; `wake` settles
/// them a few at a time, and each matures at its own time however late.
#[test]
fn a_call_refuses_while_operations_are_left_due_and_wake_settles_them() {
    let mut home = seasoned(4);
    let first = home.operate(admin(0), "remove", 2u32).unwrap();
    let second = home.operate(admin(0), "remove", 3u32).unwrap();
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
    for (index, target) in [(first, 2), (second, 3)] {
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
