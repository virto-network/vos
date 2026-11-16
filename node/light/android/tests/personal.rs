// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The personal space through the facility as `:vos` serves it, against
//! homes in process: each a credential actor and `Homes` in front of a pool
//! of personal agents running `Personal`, every request over the world's
//! gateway as its onions serve it. A claim, a pairing between two
//! facilities, the memberships it leaves, the yearly re-proof, a removal
//! carried by a commit and revoked in each space, a move to another home;
//! the device set's contests, kit rotations and admin replacements; a
//! restore from the kit; and the personal agent's traffic on its own
//! circuits, never beside a proof, never on the clearnet.

mod common;

use std::collections::HashSet;

use common::phone::*;
use common::*;
use vos_facility::personal::{Claim, KitKind, Owed};
use vos_light::tor::Target;

/// The path the brief names: a claim with a security-key kit, a pairing
/// between two facilities offering the club, the enrollment the first owes
/// and the confirmation the second does, the second's yearly re-proof, the
/// first retired (removed, its removal carried by the second's commit, its
/// leaf revoked in the club by the second's owner proof), and the second
/// moving the personal space to another home. Every request goes to an
/// onion; the personal agent's never share a connection with a proof, and
/// the background job's go on circuits of their own.
#[test]
fn a_personal_space_is_claimed_paired_retired_and_moved() {
    let world = world();
    let home = world.home(HOME, 2, 2);
    let elsewhere = world.home(ELSEWHERE, 3, 1);
    let first = phone(&world, 0x11);
    let second = phone(&world, 0x22);

    // The first phone is in the club, then claims its personal space.
    let member = first.enroll();
    world.enroll(AGENT, &member);
    let claimed = first.claim(&world, home, KitKind::SecurityKey, "first phone");
    assert_eq!(claimed.device, 0);
    assert!(
        first.hand.phrases.lock().unwrap().is_empty(),
        "no phrase for a key's kit"
    );
    let cards = first.hand.cards.lock().unwrap().clone();
    assert_eq!(cards.len(), 1, "the key's card shown");
    let onion = vos_light::tor::onion_address(&world.home_of(home).onions[0].key);
    assert!(cards[0].contains(&("Home".into(), hex::encode(world.home_of(home).handle))));
    assert!(cards[0].contains(&("Onion 1".into(), onion)));
    let devices = first.node.personal().unwrap().devices().unwrap();
    assert_eq!(devices.len(), 1);
    assert!(devices[0].me && devices[0].strong && !devices[0].removed);
    assert_eq!(devices[0].label, "first phone");
    // Claimed again: refused, the device holds its space.
    let again = first.node.personal().unwrap().claim(
        &*first.hand,
        Claim {
            home: world.home_of(home),
            kit: KitKind::Phrase,
            label: "first phone".into(),
        },
    );
    assert!(again.is_err());

    // The second phone is paired from the first, offered the club.
    let (opened, joined) = first.pair(&second, "second phone");
    assert_eq!((opened.device, joined.device), (1, 1));
    assert_eq!((opened.memberships, joined.memberships), (1, 1));
    assert_eq!(second.node.personal().unwrap().devices().unwrap().len(), 2);

    // The first owes its enrollment in the club; the second its own
    // confirmation there, once enrolled through its own s4 session.
    let owed = first.node.space().unwrap().memberships().unwrap();
    assert_eq!(owed.len(), 1);
    assert_eq!(
        (owed[0].owed, owed[0].handle, owed[0].agent),
        (Owed::Enroll, HANDLE, AGENT)
    );
    first
        .node
        .personal()
        .unwrap()
        .enroll_device(&*first.hand, owed[0])
        .unwrap();
    assert!(
        first
            .node
            .space()
            .unwrap()
            .memberships()
            .unwrap()
            .is_empty()
    );
    let confirming = second.node.space().unwrap().memberships().unwrap();
    assert_eq!(confirming.len(), 1);
    assert_eq!(confirming[0].owed, Owed::Confirm);
    let refused = second
        .node
        .personal()
        .unwrap()
        .confirm_device(&*second.hand, confirming[0])
        .unwrap_err();
    assert_eq!(refused.code, s4_credential_contract::Code::NotEnrolled);
    let theirs = second.enroll();
    assert!(
        in_club(&world, &theirs),
        "its leaf placed by the first's proof"
    );
    second
        .node
        .personal()
        .unwrap()
        .confirm_device(&*second.hand, confirming[0])
        .unwrap();
    assert!(
        second
            .node
            .space()
            .unwrap()
            .memberships()
            .unwrap()
            .is_empty()
    );

    // The second's yearly re-proof at the home under its own nullifier,
    // once its open claim there is made by the background job.
    second.node.sync_personal().unwrap();
    second
        .node
        .personal()
        .unwrap()
        .renew(&*second.hand)
        .unwrap();
    let state = world.state.lock().unwrap();
    let homes = state.spaces[&home].homes.as_ref().unwrap();
    assert_eq!(homes.renewed, vec![claimed.agent]);
    drop(state);

    // The background job, on its own circuits: the first confirms the
    // second's commit, which the re-proof's leaf update made.
    let before = seen(&world).len();
    for phone in [&first, &second] {
        let synced = phone.node.sync_personal().unwrap();
        assert_eq!((synced.synced, synced.failed), (1, 0));
    }
    let background: Vec<_> = seen(&world)[before..]
        .iter()
        .map(|seen| seen.circuit)
        .collect();
    assert!(!background.is_empty());
    assert!(
        seen(&world)[..before]
            .iter()
            .all(|seen| !background.contains(&seen.circuit))
    );
    let runs = second.node.runs().unwrap();
    assert!(runs.last().unwrap().apart);

    // The first retired: once the second is past its probation it removes
    // it; the removal matures after the policy's delay, and the second's
    // commit carries it. Its leaf in the club is revoked by the second.
    after(policy().probation_ms);
    second.node.sync_personal().unwrap();
    let removal = second
        .node
        .personal()
        .unwrap()
        .remove(&*second.hand, 0)
        .unwrap();
    let notices = first.node.space().unwrap().operations();
    assert!(notices.is_ok());
    after(policy().operation_delay_ms);
    second
        .node
        .personal()
        .unwrap()
        .update(&*second.hand)
        .unwrap();
    let devices = second.node.personal().unwrap().devices().unwrap();
    assert!(
        devices
            .iter()
            .any(|device| device.id == 0 && device.removed),
        "{devices:?}"
    );
    assert!(removal.index > 0);
    assert!(in_club(&world, &member));
    assert_eq!(
        second
            .node
            .personal()
            .unwrap()
            .revoke(&*second.hand, 0)
            .unwrap(),
        1
    );
    assert!(!in_club(&world, &member), "the first's leaf revoked");
    assert!(in_club(&world, &theirs));

    // The second moves the personal space to another home, a phrase its
    // new kit; everything carried, it alone in the new set.
    let moved = second
        .node
        .personal()
        .unwrap()
        .move_home(
            &*second.hand,
            Claim {
                home: world.home_of(elsewhere),
                kit: KitKind::Phrase,
                label: "second phone".into(),
            },
        )
        .unwrap();
    assert_ne!(moved.agent, claimed.agent);
    assert_eq!(second.hand.phrase().split(' ').count(), 24);
    let devices = second.node.personal().unwrap().devices().unwrap();
    assert_eq!(devices.iter().filter(|device| !device.removed).count(), 1);
    assert!(!world.carrying(moved.agent).is_empty());
    assert!(
        world
            .carrying(moved.agent)
            .iter()
            .all(|seen| world::onion_of(&seen.target) == Some(world::address(&world, 3)))
    );

    // Nothing anonymous or personal on the clearnet (E17, E22): every
    // connection an onion's; the personal agents' never carried a proof,
    // and each proof went alone on its connection.
    let personal = personal_agents(&world);
    let credentialed = ApiKind::Credentialed as u16;
    let all = seen(&world);
    assert!(
        all.iter()
            .all(|seen| matches!(seen.target, Target::Onion { .. }))
    );
    for seen in &all {
        let to_personal = seen
            .requests
            .iter()
            .any(|(_, agent)| personal.contains(agent));
        let proofs = seen
            .requests
            .iter()
            .filter(|(kind, _)| *kind == credentialed)
            .count();
        if to_personal {
            assert_eq!(proofs, 0, "a proof beside the personal agent's traffic");
        }
        if proofs > 0 {
            assert_eq!(seen.requests.len(), 1, "a proof shared its connection");
        }
    }
    for (at, one) in all.iter().enumerate() {
        assert!(
            all[..at].iter().all(|other| other.circuit != one.circuit),
            "each connection on its own circuit"
        );
    }
    let keys: HashSet<_> = all.iter().filter_map(|seen| seen.key).collect();
    assert_eq!(
        keys.len(),
        all.iter().filter(|seen| seen.key.is_some()).count()
    );
}

/// The device set's operations with three phones: a removal vetoed by its
/// target and dropped by the other two; a kit rotation made immediate by a
/// second signature; an admin key replaced and taken once the set shows
/// it; a regroup opened. Every admin call signed at the admin key's prompt.
#[test]
fn the_device_sets_operations_are_signed_by_the_admin_key() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let first = phone(&world, 0x31);
    let second = phone(&world, 0x32);
    let third = phone(&world, 0x33);
    first.claim(&world, home, KitKind::Phrase, "first");
    // A pairing cancelled while it waits for its joiner: refused at its
    // next read of the slot, the space free for the next.
    first
        .node
        .personal()
        .unwrap()
        .pair_offer(&*first.hand)
        .unwrap();
    std::thread::scope(|scope| {
        let opener = scope.spawn(|| first.node.personal().unwrap().pair_await(&*first.hand));
        std::thread::sleep(Duration::from_millis(300));
        first.node.space().unwrap().pair_cancel();
        let cancelled = opener.join().unwrap().unwrap_err();
        assert_eq!(cancelled.code, vos_facility::Code::Declined);
    });
    first.pair(&second, "second");
    first.pair(&third, "third");
    // A device just paired, not seasoned (the third, for the second's new
    // admin key), signs no replacement: checked at once, before the test
    // policy's seconds season it.
    let seconds = second
        .node
        .personal()
        .unwrap()
        .admin_offer(&*second.hand)
        .unwrap();
    let unseasoned = third
        .node
        .personal()
        .unwrap()
        .replace_admin_of(&*third.hand, &seconds)
        .unwrap_err();
    // Refused as unseasoned, or still in its probation when it signs.
    assert!(
        ["Unseasoned", "Probation"]
            .iter()
            .any(|refusal| unseasoned.message.contains(refusal)),
        "{unseasoned:?}"
    );
    // A new admin key for the third, offered to the others: the third
    // itself signs no replacement of its own key.
    // The first offer is the one signed below, a newer one made since: any
    // key offered is taken once the set shows it.
    let offer = third
        .node
        .personal()
        .unwrap()
        .admin_offer(&*third.hand)
        .unwrap();
    third
        .node
        .personal()
        .unwrap()
        .admin_offer(&*third.hand)
        .unwrap();
    // An offer signed by no device of the set, or naming another device
    // than the one that signed it, is refused before the user is asked.
    let mut forged = offer.clone();
    forged[4] ^= 1;
    let mut relabelled = offer.clone();
    relabelled[3] = 1;
    let mut upgraded = offer.clone();
    upgraded[36] ^= 2;
    for code in [forged, relabelled, upgraded] {
        let refused = first
            .node
            .personal()
            .unwrap()
            .replace_admin_of(&*first.hand, &code)
            .unwrap_err();
        assert!(refused.message.contains("not signed"), "{refused:?}");
    }
    let own = third
        .node
        .personal()
        .unwrap()
        .replace_admin_of(&*third.hand, &offer)
        .unwrap_err();
    assert!(own.message.contains("Targeted"), "{own:?}");
    after(policy().probation_ms.max(policy().seasoning_ms));
    for phone in [&first, &second, &third] {
        phone.node.sync_personal().unwrap();
    }
    assert_eq!(first.node.personal().unwrap().devices().unwrap().len(), 3);

    // A removal of the third, contested by its veto, dropped by the first
    // and the second: the first alone decides nothing.
    let removal = first
        .node
        .personal()
        .unwrap()
        .remove(&*first.hand, 2)
        .unwrap();
    third
        .node
        .personal()
        .unwrap()
        .veto(&*third.hand, removal.index)
        .unwrap();
    first
        .node
        .personal()
        .unwrap()
        .resolve(&*first.hand, removal.index, false)
        .unwrap();
    second
        .node
        .personal()
        .unwrap()
        .resolve(&*second.hand, removal.index, false)
        .unwrap();
    after(policy().operation_delay_ms);
    first.node.personal().unwrap().update(&*first.hand).unwrap();
    let devices = first.node.personal().unwrap().devices().unwrap();
    assert!(devices.iter().all(|device| !device.removed), "{devices:?}");

    // A kit rotation by the first, made immediate by the second's
    // signature: a new phrase shown.
    let shown = first.hand.phrases.lock().unwrap().len();
    let rotation = first
        .node
        .personal()
        .unwrap()
        .rotate_kit(&*first.hand, KitKind::Phrase)
        .unwrap();
    assert_eq!(first.hand.phrases.lock().unwrap().len(), shown + 1);
    second
        .node
        .personal()
        .unwrap()
        .cosign(&*second.hand, rotation.index)
        .unwrap();

    // The second's admin key replaced (its old one invalidated, say): the
    // new one made at its prompt, the replacement signed by the kit and
    // matured after the kit's delay; the key is the second's once the set
    // shows it, and signs its next commit. No device cosigns it.
    let old = second.hand.signed_by();
    let keys = second.hand.admin_keys();
    second.hand.will_enter(first.hand.phrase());
    let replacement = second
        .node
        .personal()
        .unwrap()
        .replace_admin(&*second.hand, KitKind::Phrase)
        .unwrap();
    assert_eq!(second.hand.admin_keys(), keys + 1);
    assert!(
        first
            .node
            .personal()
            .unwrap()
            .cosign(&*first.hand, replacement.index)
            .is_err()
    );
    after(policy().kit_delay_ms);
    for phone in [&first, &second, &third] {
        phone.node.sync_personal().unwrap();
    }
    let devices = second.node.personal().unwrap().devices().unwrap();
    assert!(devices.iter().any(|device| device.me && device.id == 1));
    second
        .node
        .personal()
        .unwrap()
        .update(&*second.hand)
        .unwrap();
    assert_ne!(second.hand.signed_by(), old, "the new key signs");

    // The third's admin key replaced by another seasoned device's
    // signature, the first's, beside the offer's key check. The new key is
    // the third's once its probation passes, and signs its next commit.
    let old = third.hand.signed_by();
    first
        .node
        .personal()
        .unwrap()
        .replace_admin_of(&*first.hand, &offer)
        .unwrap();
    after(policy().probation_ms);
    for phone in [&first, &second, &third] {
        phone.node.sync_personal().unwrap();
    }
    third.node.personal().unwrap().devices().unwrap();
    third.node.personal().unwrap().update(&*third.hand).unwrap();
    assert_ne!(third.hand.signed_by(), old, "the new key signs");
    assert!(
        first
            .node
            .personal()
            .unwrap()
            .replace_admin_of(&*first.hand, &[0; 5])
            .is_err(),
        "no offer"
    );

    // A regroup removing the third.
    let regroup = first
        .node
        .personal()
        .unwrap()
        .regroup(&*first.hand, vec![2])
        .unwrap();
    assert!(regroup.index > rotation.index);
    assert!(
        first
            .node
            .personal()
            .unwrap()
            .regroup(&*first.hand, vec![0; 17])
            .is_err()
    );
}

/// A restore from the kit: a fresh phone enters the phrase the first was
/// shown, a new kit split for it; after the kit's delay with no `alive`,
/// the restore matures and the phone reads the personal space back, the
/// only device of the set.
#[test]
fn a_personal_space_is_restored_from_its_phrase() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let lost = phone(&world, 0x41);
    let claimed = lost.claim(&world, home, KitKind::Phrase, "lost phone");
    let words = lost.hand.phrase();
    drop(lost);

    let fresh = phone(&world, 0x42);
    fresh.hand.will_enter(words.clone());
    let restore = Claim {
        home: world.home_of(home),
        kit: KitKind::Phrase,
        label: "new phone".into(),
    };
    fresh
        .node
        .personal()
        .unwrap()
        .restore(&*fresh.hand, restore.clone(), KitKind::Phrase)
        .unwrap();
    assert!(
        fresh
            .node
            .personal()
            .unwrap()
            .restored(&*fresh.hand, KitKind::Phrase)
            .is_err(),
        "not matured yet"
    );
    after(policy().kit_delay_ms);
    let restored = fresh
        .node
        .personal()
        .unwrap()
        .restored(&*fresh.hand, KitKind::Phrase)
        .unwrap();
    assert_eq!(restored.agent, claimed.agent);
    let devices = fresh.node.personal().unwrap().devices().unwrap();
    let standing: Vec<_> = devices.iter().filter(|device| !device.removed).collect();
    assert_eq!(standing.len(), 1);
    assert!(standing[0].me);
    // Restored once: a device holding the space restores nothing.
    assert!(
        fresh
            .node
            .personal()
            .unwrap()
            .restore(&*fresh.hand, restore, KitKind::Phrase)
            .is_err()
    );
}

/// The joiner's open claim at its home: not made at the pairing, but by
/// the background job once the delay drawn for it has passed; its time
/// kept across a restart of the facility, neither lost nor drawn again.
/// Until then its re-proof at the home is refused.
#[test]
fn the_joiners_open_claim_waits_for_its_drawn_time() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let first = phone(&world, 0x51);
    let second = phone(&world, 0x52);
    first.claim(&world, home, KitKind::Phrase, "first");
    // Long enough that a loaded host's pairing, its suites proving beside
    // it, ends before the claim falls due.
    second.node.space().unwrap().set_claim_delay(10_000..10_500);
    let members = || world.state.lock().unwrap().spaces[&home].tree.members();
    let before = members();
    let paired_at = wall();
    first.pair(&second, "second");
    let due = second
        .node
        .space()
        .unwrap()
        .claim_due()
        .expect("the claim owed");
    assert!(
        due >= paired_at + 10_000 && due < wall() + 10_500,
        "drawn in range"
    );
    assert_eq!(members(), before, "not made at the pairing");
    assert!(wall() < due, "the pairing outlasted the claim's delay");
    second.node.sync_personal().unwrap();
    assert_eq!(members(), before, "not made before its time");
    let early = second
        .node
        .personal()
        .unwrap()
        .renew(&*second.hand)
        .unwrap_err();
    assert!(early.message.contains("not made yet"), "{early:?}");

    let second = second.restart(&world);
    assert_eq!(second.node.space().unwrap().claim_due(), Some(due), "kept");
    std::thread::sleep(Duration::from_millis(due.saturating_sub(wall()) + 100));
    second.node.sync_personal().unwrap();
    assert_eq!(members(), before + 1, "made once due");
    assert_eq!(second.node.space().unwrap().claim_due(), None);
    second
        .node
        .personal()
        .unwrap()
        .renew(&*second.hand)
        .unwrap();
}

/// Three phones claimed and paired, past their probation and seasoning.
fn three_phones(seed: u8) -> (Arc<World>, Held, Held, Held) {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let first = phone(&world, seed);
    let second = phone(&world, seed + 1);
    let third = phone(&world, seed + 2);
    first.claim(&world, home, KitKind::Phrase, "first");
    first.pair(&second, "second");
    first.pair(&third, "third");
    after(policy().probation_ms.max(policy().seasoning_ms));
    for phone in [&first, &second, &third] {
        phone.node.sync_personal().unwrap();
    }
    (world, first, second, third)
}

/// A fourth phone paired from `from` while the `others`' background jobs
/// run, each a voice of the set its commit needs: it joins the group and
/// reads itself in the set.
fn fourth_pairs(world: &Arc<World>, from: &Held, others: &[&Held], seed: u8) -> Held {
    /// Set when dropped: the pairing ended, or panicked.
    struct Ended<'a>(&'a std::sync::atomic::AtomicBool);
    impl Drop for Ended<'_> {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let fourth = phone(world, seed);
    let paired = std::sync::atomic::AtomicBool::new(false);
    let (opened, joined) = std::thread::scope(|scope| {
        scope.spawn(|| {
            while !paired.load(std::sync::atomic::Ordering::SeqCst) {
                for other in others {
                    let _ = other.node.sync_personal();
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        });
        let _ended = Ended(&paired);
        from.pair(&fourth, "fourth")
    });
    assert_eq!(opened.device, joined.device);
    let devices = fourth.node.personal().unwrap().devices().unwrap();
    assert!(
        devices
            .iter()
            .any(|device| device.me && device.id == joined.device)
    );
    fourth.node.sync_personal().unwrap();
    fourth
}

/// A fourth phone paired after a kit rotation and two admin keys
/// replaced, one by the kit and one by another device's signature, each
/// taken by its next commit without the set read first. The opener has
/// not read the last commit when the joiner says hello: it catches up
/// before it makes its own, which would otherwise take a decided epoch.
#[test]
fn a_fourth_phone_pairs_after_a_rotation_and_replacements() {
    let (world, first, second, third) = three_phones(0x61);
    let rotation = first
        .node
        .personal()
        .unwrap()
        .rotate_kit(&*first.hand, KitKind::Phrase)
        .unwrap();
    second
        .node
        .personal()
        .unwrap()
        .cosign(&*second.hand, rotation.index)
        .unwrap();
    second.hand.will_enter(first.hand.phrase());
    second
        .node
        .personal()
        .unwrap()
        .replace_admin(&*second.hand, KitKind::Phrase)
        .unwrap();
    after(policy().kit_delay_ms);
    for phone in [&first, &second, &third] {
        phone.node.sync_personal().unwrap();
    }
    let old = *second.hand.signed.lock().unwrap();
    second
        .node
        .personal()
        .unwrap()
        .update(&*second.hand)
        .unwrap();
    assert_ne!(Some(second.hand.signed_by()), old, "the new key signs");
    let offer = third
        .node
        .personal()
        .unwrap()
        .admin_offer(&*third.hand)
        .unwrap();
    first
        .node
        .personal()
        .unwrap()
        .replace_admin_of(&*first.hand, &offer)
        .unwrap();
    after(policy().probation_ms);
    for phone in [&first, &second, &third] {
        phone.node.sync_personal().unwrap();
    }
    let old = *third.hand.signed.lock().unwrap();
    third.node.personal().unwrap().update(&*third.hand).unwrap();
    assert_ne!(Some(third.hand.signed_by()), old, "the new key signs");
    second.node.sync_personal().unwrap();
    fourth_pairs(&world, &first, &[&second, &third], 0x64);
}

/// A fourth phone paired after a kit rotation alone, from a device that
/// did not draw the rotation's `R`.
#[test]
fn a_fourth_phone_pairs_after_a_rotation() {
    let (world, first, second, third) = three_phones(0x81);
    let rotation = second
        .node
        .personal()
        .unwrap()
        .rotate_kit(&*second.hand, KitKind::Phrase)
        .unwrap();
    first
        .node
        .personal()
        .unwrap()
        .cosign(&*first.hand, rotation.index)
        .unwrap();
    for phone in [&first, &second, &third] {
        phone.node.sync_personal().unwrap();
    }
    fourth_pairs(&world, &third, &[&first, &second], 0x84);
}

/// A fourth phone paired by a device whose admin key the kit replaced,
/// its pairing commit the first the new key signs.
#[test]
fn a_fourth_phone_pairs_after_an_admin_replacement() {
    let (world, first, second, third) = three_phones(0x91);
    second.hand.will_enter(first.hand.phrase());
    second
        .node
        .personal()
        .unwrap()
        .replace_admin(&*second.hand, KitKind::Phrase)
        .unwrap();
    after(policy().kit_delay_ms);
    for phone in [&first, &third] {
        phone.node.sync_personal().unwrap();
    }
    let old = *second.hand.signed.lock().unwrap();
    fourth_pairs(&world, &second, &[&first, &third], 0x94);
    assert_ne!(Some(second.hand.signed_by()), old, "the new key signs");
}

/// A fourth phone paired after a regroup that left the first alone: its
/// update starts the new group, which the fourth joins.
#[test]
fn a_fourth_phone_pairs_after_a_regroup() {
    let (world, first, second, third) = three_phones(0xa1);
    first
        .node
        .personal()
        .unwrap()
        .regroup(&*first.hand, vec![1, 2])
        .unwrap();
    after(policy().operation_delay_ms);
    first.node.personal().unwrap().update(&*first.hand).unwrap();
    for phone in [&second, &third] {
        let _ = phone.node.sync_personal();
    }
    let fourth = fourth_pairs(&world, &first, &[], 0xa4);
    let devices = fourth.node.personal().unwrap().devices().unwrap();
    let standing: Vec<_> = devices.iter().filter(|device| !device.removed).collect();
    assert_eq!(standing.len(), 2, "{devices:?}");
}

/// A regroup keeping two of three phones, made immediate by the second's
/// signature: the second hands its key package over from its pass, the
/// first's commit starts the new group with it, the second joins by its
/// Welcome and both hold the new epoch's keys; the third, named, is out
/// and holds none of them. A fourth phone then pairs from the first, the
/// second's vote the one its commit needs.
#[test]
fn a_regroup_keeps_two_of_three_and_a_fourth_pairs() {
    let (world, first, second, third) = three_phones(0xb1);
    let before = first.node.space().unwrap().scope_key(b"notes").unwrap();
    let regroup = first
        .node
        .personal()
        .unwrap()
        .regroup(&*first.hand, vec![2])
        .unwrap();
    second
        .node
        .personal()
        .unwrap()
        .cosign(&*second.hand, regroup.index)
        .unwrap();
    // The second's background pass hands its key package over.
    second.node.sync_personal().unwrap();
    first.node.personal().unwrap().update(&*first.hand).unwrap();
    for phone in [&second, &first, &second, &first] {
        phone.node.sync_personal().unwrap();
    }
    let _ = third.node.sync_personal();
    let key = first.node.space().unwrap().scope_key(b"notes").unwrap();
    assert_ne!(key, before, "a new group's keys");
    assert_eq!(
        second.node.space().unwrap().scope_key(b"notes").unwrap(),
        key
    );
    assert_ne!(
        third.node.space().unwrap().scope_key(b"notes").ok(),
        Some(key)
    );
    for phone in [&first, &second] {
        let devices = phone.node.personal().unwrap().devices().unwrap();
        let standing: Vec<_> = devices.iter().filter(|device| !device.removed).collect();
        assert_eq!(
            standing.iter().map(|device| device.id).collect::<Vec<_>>(),
            vec![0, 1],
            "{devices:?}"
        );
    }
    // The agent no longer admits the third's sync key.
    let out = third.node.personal().unwrap().devices().unwrap_err();
    assert!(out.message.contains("NotAdmitted"), "{out:?}");

    let fourth = fourth_pairs(&world, &first, &[&second], 0xb4);
    second.node.sync_personal().unwrap();
    let key = first.node.space().unwrap().scope_key(b"notes").unwrap();
    assert_eq!(
        second.node.space().unwrap().scope_key(b"notes").unwrap(),
        key
    );
    assert_eq!(
        fourth.node.space().unwrap().scope_key(b"notes").unwrap(),
        key
    );
}

/// A regroup whose kept phone never syncs: the regrouper's commit waits a
/// bounded time for its handover, then is refused naming it and holds
/// nothing; the phone the regroup names commits nothing. The way on is the
/// silent phone's removal: once it matures, the same commit starts the new
/// group without it.
#[test]
fn a_regroup_waits_a_bounded_time_for_a_kept_phones_handover() {
    let (_world, first, _second, third) = three_phones(0xc1);
    first
        .node
        .personal()
        .unwrap()
        .regroup(&*first.hand, vec![2])
        .unwrap();
    after(policy().operation_delay_ms);
    let started = std::time::Instant::now();
    let refused = first
        .node
        .personal()
        .unwrap()
        .update(&*first.hand)
        .unwrap_err();
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(10) && waited < Duration::from_secs(30),
        "bounded: {waited:?}"
    );
    assert_eq!(refused.code, s4_credential_contract::Code::Refused);
    assert!(
        refused.message.contains("\"second\" (device 1)"),
        "{refused:?}"
    );
    // The named phone commits nothing and hands nothing over.
    assert!(third.node.personal().unwrap().update(&*third.hand).is_err());
    first
        .node
        .personal()
        .unwrap()
        .remove(&*first.hand, 1)
        .unwrap();
    after(policy().operation_delay_ms);
    first.node.personal().unwrap().update(&*first.hand).unwrap();
    first.node.sync_personal().unwrap();
    let devices = first.node.personal().unwrap().devices().unwrap();
    let standing: Vec<_> = devices.iter().filter(|device| !device.removed).collect();
    assert_eq!(standing.len(), 1, "{devices:?}");
    first.node.space().unwrap().scope_key(b"notes").unwrap();
}

/// The joiner's open claim that the home refuses: each refusal recorded
/// as the job's failure and the next attempt put off, the wait doubled and
/// kept across a restart; made once the home admits it.
#[test]
fn a_refused_open_claim_backs_off() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let first = phone(&world, 0x71);
    let second = phone(&world, 0x72);
    first.claim(&world, home, KitKind::Phrase, "first");
    first.pair(&second, "second");
    second.node.space().unwrap().set_claim_retry(4_000);
    let members = || world.state.lock().unwrap().spaces[&home].tree.members();
    let openings = || world.state.lock().unwrap().openings;
    let before = members();
    world.state.lock().unwrap().closed = true;

    let asked = openings();
    let refused_at = wall();
    let synced = second.node.sync_personal().unwrap();
    assert_eq!(synced.failed, 1, "the refusal is the job's failure");
    assert_eq!(openings(), asked + 1);
    let due = second
        .node
        .space()
        .unwrap()
        .claim_due()
        .expect("still owed");
    assert!(
        due >= refused_at + 2_000 && due <= wall() + 4_000,
        "put off"
    );
    // Not tried again before its time.
    second.node.sync_personal().unwrap();
    assert_eq!(openings(), asked + 1, "no attempt before the wait ends");

    std::thread::sleep(Duration::from_millis(due.saturating_sub(wall()) + 100));
    let refused_at = wall();
    second.node.sync_personal().unwrap();
    assert_eq!(openings(), asked + 2);
    let due = second
        .node
        .space()
        .unwrap()
        .claim_due()
        .expect("still owed");
    assert!(
        due >= refused_at + 4_000 && due <= wall() + 8_000,
        "the wait doubled"
    );
    let second = second.restart(&world);
    assert_eq!(second.node.space().unwrap().claim_due(), Some(due), "kept");
    second.node.space().unwrap().set_claim_retry(4_000);

    world.state.lock().unwrap().closed = false;
    std::thread::sleep(Duration::from_millis(due.saturating_sub(wall()) + 100));
    let synced = second.node.sync_personal().unwrap();
    assert_eq!((synced.synced, synced.failed), (1, 0));
    assert_eq!(members(), before + 1, "made once admitted");
    assert_eq!(second.node.space().unwrap().claim_due(), None);
}

/// A space the first phone enrolls in after its claim: recorded in the
/// credential book, so a pairing offers it and a retirement revokes the
/// first's leaf there.
#[test]
fn a_space_enrolled_after_the_claim_is_offered_and_revoked() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let first = phone(&world, 0xd1);
    let second = phone(&world, 0xd2);
    first.claim(&world, home, KitKind::Phrase, "first");
    let member = first.enroll();
    world.enroll(AGENT, &member);
    let (opened, joined) = first.pair(&second, "second");
    assert_eq!(
        (opened.memberships, joined.memberships),
        (1, 1),
        "the club offered"
    );
    let owed = first.node.space().unwrap().memberships().unwrap();
    first
        .node
        .personal()
        .unwrap()
        .enroll_device(&*first.hand, owed[0])
        .unwrap();
    let theirs = second.enroll();
    assert!(in_club(&world, &theirs));
    let confirming = second.node.space().unwrap().memberships().unwrap();
    second
        .node
        .personal()
        .unwrap()
        .confirm_device(&*second.hand, confirming[0])
        .unwrap();

    after(policy().probation_ms);
    for phone in [&first, &second] {
        phone.node.sync_personal().unwrap();
    }
    second
        .node
        .personal()
        .unwrap()
        .remove(&*second.hand, 0)
        .unwrap();
    after(policy().operation_delay_ms);
    second
        .node
        .personal()
        .unwrap()
        .update(&*second.hand)
        .unwrap();
    assert_eq!(
        second
            .node
            .personal()
            .unwrap()
            .revoke(&*second.hand, 0)
            .unwrap(),
        1
    );
    assert!(!in_club(&world, &member), "the first's leaf revoked");
    assert!(in_club(&world, &theirs));
}

/// A sign-in in the club, once the path is held.
fn signs_in(phone: &Held) {
    let login = vos_facility::SignIn::read(&object(&[
        ("agent", Value::from(AGENT)),
        ("instance", Value::from(POLL)),
        ("method", Value::from("login")),
        ("arguments", Value::Bytes(Vec::new())),
    ]))
    .unwrap();
    let session = phone.node.open_session(gateway());
    for _ in 0..20 {
        match phone.node.sign_in(
            session,
            login.clone(),
            Arc::clone(&phone.hand) as Arc<dyn vos_facility::node::Prompts>,
        ) {
            Err(refusal) if refusal.code == Code::NoPath => {
                phone.node.sync().unwrap();
            }
            signed => {
                signed.unwrap();
                phone.node.close(session);
                return;
            }
        }
    }
    panic!("no path");
}

/// The light store's layout row under `directory`.
fn layout_of(directory: &std::path::Path) -> Option<Vec<u8>> {
    let db = fjall::Database::builder(directory.join(vos_facility::personal::LIGHT))
        .open()
        .unwrap();
    let meta = db
        .keyspace("meta", fjall::KeyspaceCreateOptions::default)
        .unwrap();
    meta.get(b"layout").unwrap().map(|value| value.to_vec())
}

/// A change made to a stopped phone's files.
type Alter = dyn Fn(&std::path::Path);

/// A personal space this build does not read (its state file of another
/// version, or none; its store of another layout) is named in need of
/// repair and left as it is: the facility opens, and its sign-in runs.
#[test]
fn a_personal_space_this_build_does_not_read_is_kept_and_sign_in_runs() {
    let later = |directory: &std::path::Path| {
        let file = directory.join(vos_facility::personal::FILE);
        let mut bytes = std::fs::read(&file).unwrap();
        bytes[8..10].copy_from_slice(&(vos_facility::personal::STATE_VERSION + 1).to_le_bytes());
        std::fs::write(&file, bytes).unwrap();
    };
    let unversioned = |directory: &std::path::Path| {
        std::fs::write(directory.join(vos_facility::personal::FILE), [1, 0, 2]).unwrap();
    };
    let layout = |directory: &std::path::Path| {
        let db = fjall::Database::builder(directory.join(vos_facility::personal::LIGHT))
            .open()
            .unwrap();
        let meta = db
            .keyspace("meta", fjall::KeyspaceCreateOptions::default)
            .unwrap();
        meta.insert(b"layout", 99u32.to_be_bytes()).unwrap();
        db.persist(fjall::PersistMode::SyncAll).unwrap();
    };
    let alterations: [(&str, &Alter); 3] = [
        ("a later version", &later),
        ("no version", &unversioned),
        ("another layout", &layout),
    ];
    for (what, alter) in alterations {
        let world = world();
        let home = world.home(HOME, 2, 1);
        let phone = phone(&world, 0xe1);
        world.enroll(AGENT, &phone.enroll());
        phone.claim(&world, home, KitKind::Phrase, "phone");
        let Held {
            node,
            hand,
            tag,
            _directory,
        } = phone;
        drop(node);
        assert_eq!(
            layout_of(_directory.path()),
            Some(vos_light::store::LAYOUT.to_be_bytes().to_vec()),
            "the light node's layout written"
        );
        alter(_directory.path());
        let file = _directory.path().join(vos_facility::personal::FILE);
        let state = std::fs::read(&file).unwrap();
        let phone = Held {
            node: node_as(&world, _directory.path(), tag),
            hand,
            tag,
            _directory,
        };
        let refused = phone
            .node
            .personal()
            .and_then(|personal| personal.devices())
            .unwrap_err();
        assert_eq!(refused.code, Code::Store, "{what}");
        assert!(
            refused.message.contains("needs repair"),
            "{what}: {refused:?}"
        );
        let again = phone
            .node
            .personal()
            .and_then(|personal| {
                personal.claim(
                    &*phone.hand,
                    Claim {
                        home: world.home_of(home),
                        kit: KitKind::Phrase,
                        label: "phone".into(),
                    },
                )
            })
            .unwrap_err();
        assert_eq!(again.code, Code::Store, "{what}");
        signs_in(&phone);
        let Held {
            node, _directory, ..
        } = phone;
        drop(node);
        assert_eq!(
            std::fs::read(&file).unwrap(),
            state,
            "{what}: the file kept"
        );
        if what == "another layout" {
            assert_eq!(
                layout_of(_directory.path()),
                Some(99u32.to_be_bytes().to_vec()),
                "the store kept"
            );
        }
    }
}

/// A move whose carry was cut short (the connection lost, the process
/// killed before its last push): the background job finishes it, and the
/// move called again shows no new kit; the space is at its new home
/// already.
#[test]
fn an_interrupted_carry_is_finished_by_the_background_job() {
    let push = common::world::Step::call("push");
    let moved = |kill: Option<usize>| {
        let world = world();
        let home = world.home(HOME, 2, 1);
        let elsewhere = world.home(ELSEWHERE, 3, 2);
        let phone = phone(&world, 0xf1);
        phone.claim(&world, home, KitKind::Phrase, "phone");
        phone.node.space().unwrap().set_wait(3_000);
        let moving = Claim {
            home: world.home_of(elsewhere),
            kit: KitKind::Phrase,
            label: "phone".into(),
        };
        world.trace_from_now(phone.tag);
        if let Some(nth) = kill {
            world.kill(phone.tag, push, nth, common::world::Death::Before);
        }
        let cut = phone
            .node
            .personal()
            .unwrap()
            .move_home(&*phone.hand, moving.clone());
        (world, elsewhere, phone, moving, cut)
    };
    // The carry's last push is the move's last.
    let (world, _, phone, _, moved_whole) = moved(None);
    moved_whole.unwrap();
    let pushes = world
        .trace(phone.tag)
        .iter()
        .filter(|step| **step == push)
        .count();
    let (world, elsewhere, phone, moving, cut) = moved(Some(pushes));
    assert!(world.died(phone.tag), "{cut:?}");
    let phone = phone.restart(&world);
    let shown = phone.hand.phrases.lock().unwrap().len();
    let synced = phone.node.sync_personal().unwrap();
    assert_eq!((synced.synced, synced.failed), (1, 0), "{synced:?}");
    let again = phone
        .node
        .personal()
        .unwrap()
        .move_home(&*phone.hand, moving)
        .unwrap_err();
    assert!(again.message.contains("at that home already"), "{again:?}");
    assert_eq!(
        phone.hand.phrases.lock().unwrap().len(),
        shown,
        "no new kit"
    );
    let pool = world.state.lock().unwrap().spaces[&elsewhere]
        .homes
        .as_ref()
        .unwrap()
        .pool
        .len();
    assert_eq!(pool, 1, "one agent given");
}

/// A restore an `alive` cancelled: the kit entered again opens a new
/// restore, which matures, rather than resuming the cancelled one.
#[test]
fn a_restore_cancelled_by_alive_is_opened_anew() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let lost = phone(&world, 0xc7);
    let claimed = lost.claim(&world, home, KitKind::Phrase, "found phone");
    let words = lost.hand.phrase();
    let fresh = phone(&world, 0xc8);
    fresh.hand.will_enter(words);
    let restore = Claim {
        home: world.home_of(home),
        kit: KitKind::Phrase,
        label: "new phone".into(),
    };
    let first = fresh
        .node
        .personal()
        .unwrap()
        .restore(&*fresh.hand, restore.clone(), KitKind::Phrase)
        .unwrap();
    // The phone thought lost answers `alive`.
    lost.node.sync_personal().unwrap();
    drop(lost);
    after(policy().kit_delay_ms);
    assert!(
        fresh
            .node
            .personal()
            .unwrap()
            .restored(&*fresh.hand, KitKind::Phrase)
            .is_err()
    );
    let second = fresh
        .node
        .personal()
        .unwrap()
        .restore(&*fresh.hand, restore, KitKind::Phrase)
        .unwrap();
    assert!(second.index > first.index, "a new restore");
    after(policy().kit_delay_ms);
    let restored = fresh
        .node
        .personal()
        .unwrap()
        .restored(&*fresh.hand, KitKind::Phrase)
        .unwrap();
    assert_eq!(restored.agent, claimed.agent);
}

/// A device a move left behind pairs again at the new home, its old group
/// still held: its hello names what it carries from the group it leaves,
/// its key package and its rejoin are for those same keys, and it joins
/// the moved set beside the device that moved.
#[test]
fn a_device_a_move_left_rejoins_at_the_new_home() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let elsewhere = world.home(ELSEWHERE, 3, 1);
    let first = phone(&world, 0x51);
    let second = phone(&world, 0x52);
    first.claim(&world, home, KitKind::Phrase, "first phone");
    first.pair(&second, "second phone");
    for phone in [&first, &second] {
        phone.node.sync_personal().unwrap();
    }
    let moved = first
        .node
        .personal()
        .unwrap()
        .move_home(
            &*first.hand,
            Claim {
                home: world.home_of(elsewhere),
                kit: KitKind::Phrase,
                label: "first phone".into(),
            },
        )
        .unwrap();
    let alone = first.node.personal().unwrap().devices().unwrap();
    assert_eq!(alone.iter().filter(|device| !device.removed).count(), 1);

    let (opened, joined) = first.pair(&second, "second phone");
    assert_eq!(opened.device, joined.device);
    let devices = second.node.personal().unwrap().devices().unwrap();
    assert_eq!(
        devices.iter().filter(|device| !device.removed).count(),
        2,
        "{devices:?}"
    );
    assert!(devices.iter().any(|device| device.me && !device.removed));
    second.node.sync_personal().unwrap();
    assert!(!world.carrying(moved.agent).is_empty());
}
