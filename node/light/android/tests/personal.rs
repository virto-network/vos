// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The personal space through the facility as `:vos` serves it, against
//! homes in process: each a credential actor and `Homes` in front of a pool
//! of personal agents running `Personal`, every request over the world's
//! gateway as its onions serve it. A claim, a pairing between two
//! facilities, the memberships it leaves, a removal carried by a commit
//! and revoked in each space, a move to another home and a device pairing
//! again there; the device set's contests, kit rotations, admin
//! replacements and a regroup, its other devices pairing again; a restore
//! from the kit; and the personal agent's traffic on its own circuits,
//! never beside a proof, never on the clearnet.

mod common;

use std::collections::HashSet;

use common::phone::*;
use common::*;
use vos_facility::Enroll;
use vos_facility::personal::{Claim, KitKind, Owed, Why};
use vos_light::tor::Target;

/// The path the brief names: a claim with a security-key kit, a pairing
/// between two facilities offering the club, the enrollment the first owes
/// and the confirmation the second does, the
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
    let kept = World::home_of(&world, home);
    assert_eq!(cards[0].handle, kept.home.handle);
    assert_eq!(cards[0].onions, kept.onions);
    let devices = first.node.personal().unwrap().devices().unwrap();
    assert_eq!(devices.len(), 1);
    assert!(devices[0].me && devices[0].strong && !devices[0].removed);
    assert_eq!(devices[0].label, "first phone");
    // Claimed again: refused, the device holds its space.
    let again = first.node.personal().unwrap().claim(
        &*first.hand,
        Claim {
            home: home_of(&world, home),
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
    assert_eq!(refused.why, Why::NotEnrolled, "{refused:?}");
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

    // The background job, on its own circuits.
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

    // The second moves to another home, a phrase its new kit: it leaves
    // the old one and claims there, alone in the new set.
    let moved = second
        .node
        .personal()
        .unwrap()
        .move_home(
            &*second.hand,
            Claim {
                home: home_of(&world, elsewhere),
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
        assert_eq!(cancelled.why, Why::Cancelled, "{cancelled:?}");
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
            .any(|refusal| unseasoned.detail.contains(refusal)),
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
        assert_eq!(refused.why, Why::StaleOffer, "{refused:?}");
    }
    let own = third
        .node
        .personal()
        .unwrap()
        .replace_admin_of(&*third.hand, &offer)
        .unwrap_err();
    assert_eq!(own.why, Why::OwnKey, "{own:?}");
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

    // A regroup of the first alone, removing the others.
    let regroup = first
        .node
        .personal()
        .unwrap()
        .regroup(&*first.hand)
        .unwrap();
    assert!(regroup.index > rotation.index);
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
        home: home_of(&world, home),
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

/// A regroup of the first alone: once it matures, the first's update
/// starts the new group, and the others, removed and admitted by the agent
/// no more, pair again from it, each leaving the space it held and joining
/// with new keys at the same agent; a fourth phone then pairs, the
/// second's vote the one its commit needs, and all three hold the new
/// group's keys, the third's old ones no more. A live device scanning
/// its own space's code is refused.
#[test]
fn after_a_regroup_the_others_pair_again() {
    let (world, first, second, third) = three_phones(0xa1);
    let before = first.node.space().unwrap().scope_key(b"notes").unwrap();
    first
        .node
        .personal()
        .unwrap()
        .regroup(&*first.hand)
        .unwrap();
    after(policy().operation_delay_ms);
    first.node.personal().unwrap().update(&*first.hand).unwrap();
    for phone in [&second, &third] {
        let _ = phone.node.sync_personal();
    }
    let out = third.node.personal().unwrap().devices().unwrap_err();
    assert!(out.detail.contains("NotAdmitted"), "{out:?}");
    let devices = first.node.personal().unwrap().devices().unwrap();
    let standing: Vec<_> = devices.iter().filter(|device| !device.removed).collect();
    assert_eq!(standing.len(), 1, "{devices:?}");

    let old_sync = second.node.space().unwrap().sync_key();
    let (opened, joined) = first.pair(&second, "second");
    assert_eq!(opened.device, joined.device);
    assert_ne!(
        second.node.space().unwrap().sync_key(),
        old_sync,
        "new keys"
    );
    let fourth = fourth_pairs(&world, &first, &[&second], 0xa4);
    let key = first.node.space().unwrap().scope_key(b"notes").unwrap();
    assert_ne!(key, before, "a new group's keys");
    second.node.sync_personal().unwrap();
    for phone in [&second, &fourth] {
        assert_eq!(
            phone.node.space().unwrap().scope_key(b"notes").unwrap(),
            key
        );
    }
    assert_ne!(
        third.node.space().unwrap().scope_key(b"notes").ok(),
        Some(key)
    );
    let devices = fourth.node.personal().unwrap().devices().unwrap();
    let standing: Vec<_> = devices.iter().filter(|device| !device.removed).collect();
    assert_eq!(standing.len(), 3, "{devices:?}");

    // A device the set holds live scanning its own space's code is
    // refused, and keeps the store and keys it has.
    let sync = fourth.node.space().unwrap().sync_key();
    let code = first
        .node
        .personal()
        .unwrap()
        .pair_offer(&*first.hand)
        .unwrap();
    let refused = fourth
        .node
        .personal()
        .unwrap()
        .pair_join(&*fourth.hand, &code.code, "again")
        .unwrap_err();
    assert!(refused.why == Why::InSetAlready, "{refused:?}");
    assert_eq!(fourth.node.space().unwrap().sync_key(), sync);
    assert_eq!(
        fourth.node.space().unwrap().scope_key(b"notes").unwrap(),
        key
    );
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
    let session = phone.node.open_session(gateway());
    common::phone::signs_in(&phone.node, session, || Arc::clone(&phone.hand), 20);
    phone.node.close(session);
}

/// The light store's keyspace the personal space's rows are in.
const GROUP: &str = "group";

/// A change made to a stopped phone's files.
type Alter = dyn Fn(&std::path::Path);

/// An alteration: what it is, the change, and the row it changes (its
/// keyspace, its key, its value after).
type Alteration<'a> = (&'a str, &'a Alter, &'a str, &'a [u8], Vec<u8>);

/// The light store's keyspace `keyspace` under `directory`, its row `key`
/// set to `value`.
fn set_row(directory: &std::path::Path, keyspace: &str, key: &[u8], value: &[u8]) {
    let db = fjall::Database::builder(directory.join(vos_facility::personal::LIGHT))
        .open()
        .unwrap();
    let rows = db
        .keyspace(keyspace, fjall::KeyspaceCreateOptions::default)
        .unwrap();
    rows.insert(key, value).unwrap();
    db.persist(fjall::PersistMode::SyncAll).unwrap();
}

/// The light store's row `key` of `keyspace` under `directory`.
fn row_of(directory: &std::path::Path, keyspace: &str, key: &[u8]) -> Option<Vec<u8>> {
    let db = fjall::Database::builder(directory.join(vos_facility::personal::LIGHT))
        .open()
        .unwrap();
    let rows = db
        .keyspace(keyspace, fjall::KeyspaceCreateOptions::default)
        .unwrap();
    rows.get(key).unwrap().map(|value| value.to_vec())
}

/// A personal space this build does not read (a row of it that does not
/// decode; its store of another layout) is named in need of repair and
/// left as it is: the facility opens, and its sign-in runs.
#[test]
fn a_personal_space_this_build_does_not_read_is_kept_and_sign_in_runs() {
    let corrupt = |directory: &std::path::Path| set_row(directory, GROUP, b"p/home", &[1, 0, 2]);
    let layout =
        |directory: &std::path::Path| set_row(directory, "meta", b"layout", &99u32.to_be_bytes());
    let alterations: [Alteration; 2] = [
        (
            "a row that does not decode",
            &corrupt,
            GROUP,
            b"p/home",
            vec![1, 0, 2],
        ),
        (
            "another layout",
            &layout,
            "meta",
            b"layout",
            99u32.to_be_bytes().to_vec(),
        ),
    ];
    for (what, alter, keyspace, key, altered) in alterations {
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
            row_of(_directory.path(), "meta", b"layout"),
            Some(vos_light::store::LAYOUT.to_be_bytes().to_vec()),
            "the light node's layout written"
        );
        alter(_directory.path());
        let phone = Held {
            node: node_as(&world, _directory.path(), tag, &hand),
            hand,
            tag,
            _directory,
        };
        let refused = phone
            .node
            .personal()
            .and_then(|personal| personal.devices())
            .unwrap_err();
        assert_eq!(refused.why, Why::NeedsRepair, "{what}: {refused:?}");
        let again = phone
            .node
            .personal()
            .and_then(|personal| {
                personal.claim(
                    &*phone.hand,
                    Claim {
                        home: home_of(&world, home),
                        kit: KitKind::Phrase,
                        label: "phone".into(),
                    },
                )
            })
            .unwrap_err();
        assert_eq!(again.why, Why::NeedsRepair, "{what}: {again:?}");
        signs_in(&phone);
        let Held {
            node, _directory, ..
        } = phone;
        drop(node);
        assert_eq!(
            row_of(_directory.path(), keyspace, key),
            Some(altered),
            "{what}: the store kept"
        );
    }
}

/// The facility's database of a layout this build does not read is
/// refused and left as it is: its enrollments are not read (so no sign-in
/// runs on what it holds), and the personal space, apart from it, still
/// answers.
#[test]
fn a_facility_database_this_build_does_not_read_is_refused_and_kept() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let phone = phone(&world, 0xe2);
    world.enroll(AGENT, &phone.enroll());
    phone.claim(&world, home, KitKind::Phrase, "phone");
    let Held {
        node,
        hand,
        tag,
        _directory,
    } = phone;
    drop(node);
    let layout = |directory: &std::path::Path| {
        let db = fjall::Database::builder(directory.join(vos_facility::kept::DIRECTORY))
            .open()
            .unwrap();
        let rows = db
            .keyspace("rows", fjall::KeyspaceCreateOptions::default)
            .unwrap();
        rows.insert(b"layout", 99u32.to_be_bytes()).unwrap();
        db.persist(fjall::PersistMode::SyncAll).unwrap();
        rows.get(b"layout").unwrap().map(|value| value.to_vec())
    };
    assert_eq!(
        layout(_directory.path()),
        Some(99u32.to_be_bytes().to_vec())
    );
    let phone = Held {
        node: node_as(&world, _directory.path(), tag, &hand),
        hand,
        tag,
        _directory,
    };
    let refused = phone.node.enrollments().unwrap_err();
    assert_eq!(refused.code, Code::Store, "{refused:?}");
    let status = phone.node.status().unwrap();
    assert_eq!(status.phase, vos_facility::personal::Phase::NeedsRepair);
    assert!(status.repair.contains("needs repair"), "{status:?}");
    let devices = phone
        .node
        .personal()
        .and_then(|personal| personal.devices())
        .unwrap();
    assert_eq!(devices.len(), 1);
    let Held {
        node, _directory, ..
    } = phone;
    drop(node);
    let db = fjall::Database::builder(_directory.path().join(vos_facility::kept::DIRECTORY))
        .open()
        .unwrap();
    let rows = db
        .keyspace("rows", fjall::KeyspaceCreateOptions::default)
        .unwrap();
    assert_eq!(
        rows.get(b"layout").unwrap().map(|value| value.to_vec()),
        Some(99u32.to_be_bytes().to_vec()),
        "the database kept"
    );
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
        home: home_of(&world, home),
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

/// A move cut short after its leave (the process killed before the claim
/// at the new home): the phone holds no personal space, its old home's
/// space left; the move called again claims there with a new kit, and the
/// space is at its new home.
#[test]
fn a_move_cut_short_after_its_leave_claims_again() {
    let claim = common::world::Step::proven(vos_wire::homes::method::CLAIM);
    let world = world();
    let home = world.home(HOME, 2, 1);
    let elsewhere = world.home(ELSEWHERE, 3, 2);
    let phone = phone(&world, 0xf1);
    phone.claim(&world, home, KitKind::Phrase, "phone");
    phone.node.space().unwrap().set_wait(3_000);
    let moving = Claim {
        home: home_of(&world, elsewhere),
        kit: KitKind::Phrase,
        label: "phone".into(),
    };
    world.trace_from_now(phone.tag);
    world.kill(phone.tag, claim, 1, common::world::Death::Before);
    let cut = phone
        .node
        .personal()
        .unwrap()
        .move_home(&*phone.hand, moving.clone());
    assert!(world.died(phone.tag), "{cut:?}");
    let phone = phone.restart(&world);
    assert!(!phone.node.space().unwrap().grouped(), "the old space left");
    let moved = phone
        .node
        .personal()
        .unwrap()
        .move_home(&*phone.hand, moving.clone())
        .unwrap();
    let again = phone
        .node
        .personal()
        .unwrap()
        .move_home(&*phone.hand, moving)
        .unwrap_err();
    assert_eq!(again.why, Why::AtThatHome, "{again:?}");
    let pool = world.state.lock().unwrap().spaces[&elsewhere]
        .homes
        .as_ref()
        .unwrap()
        .pool
        .len();
    assert_eq!(pool, 1, "one agent given");
    assert!(!world.carrying(moved.agent).is_empty());
}

/// A device a move left behind pairs again at the new home: it leaves the
/// space it held at the old home and joins the moved set with new keys
/// beside the device that moved, nothing carried; each device's book rows
/// are written again there, and each reads the other's.
#[test]
fn a_device_a_move_left_pairs_again_at_the_new_home() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let elsewhere = world.home(ELSEWHERE, 3, 1);
    let first = phone(&world, 0x51);
    let second = phone(&world, 0x52);
    let member = first.enroll();
    world.enroll(AGENT, &member);
    first.claim(&world, home, KitKind::Phrase, "first phone");
    first.pair(&second, "second phone");
    for phone in [&first, &second] {
        phone.node.sync_personal().unwrap();
    }
    assert_eq!(
        second.node.space().unwrap().recorded(0),
        1,
        "the first's book"
    );
    let moved = first
        .node
        .personal()
        .unwrap()
        .move_home(
            &*first.hand,
            Claim {
                home: home_of(&world, elsewhere),
                kit: KitKind::Phrase,
                label: "first phone".into(),
            },
        )
        .unwrap();
    assert_eq!(moved.device, 0);
    let alone = first.node.personal().unwrap().devices().unwrap();
    assert_eq!(alone.iter().filter(|device| !device.removed).count(), 1);

    let old_sync = second.node.space().unwrap().sync_key();
    let (opened, joined) = first.pair(&second, "second phone");
    assert_eq!((opened.device, joined.device), (1, 1));
    assert_eq!((opened.memberships, joined.memberships), (1, 1));
    assert_ne!(
        second.node.space().unwrap().sync_key(),
        old_sync,
        "new keys"
    );
    let devices = second.node.personal().unwrap().devices().unwrap();
    assert_eq!(
        devices.iter().filter(|device| !device.removed).count(),
        2,
        "{devices:?}"
    );
    assert!(devices.iter().any(|device| device.me && !device.removed));
    for phone in [&first, &second, &first, &second] {
        phone.node.sync_personal().unwrap();
    }
    for phone in [&first, &second] {
        let space = phone.node.space().unwrap();
        assert_eq!(space.recorded(0), 1, "the first's book at the new home");
        assert_eq!(space.recorded(1), 1, "the second's book at the new home");
    }
    assert!(!world.carrying(moved.agent).is_empty());
}

/// A gateway's enrollment naming the device's home is refused unless it
/// names the home's own onions (a home in a space the user belongs to);
/// one that does keeps routes of its own: the user's opt-out of it moves
/// none of the home's traffic, which goes to the home's onion alone, never
/// the clearnet, after a reopen too.
#[test]
fn an_enrollment_naming_the_home_takes_none_of_its_routes() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let phone = phone(&world, 0xe1);
    phone.claim(&world, home, KitKind::Phrase, "phone");
    let enroll_at = |handle: [u8; 32], space: [u8; 32], onion: u8, application: &str| {
        let session = phone.node.open_session(vos_facility::Gateway {
            host_key: Some(ssh_host_key()),
            application: application.into(),
            ..gateway()
        });
        let enrolled = phone.node.enroll(
            session,
            Enroll::read(&enrollment_at(handle, space, AGENT, IDENTITY, onion)).unwrap(),
            Arc::clone(&phone.hand) as Arc<dyn vos_facility::node::Prompts>,
        );
        phone.node.close(session);
        enrolled
    };
    let enroll = |onion: u8| enroll_at(HOME, [0x53; 32], onion, "vos.test");
    let refused = enroll(1).unwrap_err();
    assert_eq!(refused.code, Code::NotPinned);
    assert!(refused.message.contains("home"), "{refused:?}");
    enroll(2).unwrap();
    phone.node.opt_out(HOME, true).unwrap();
    // The open claim's key-signed calls to the home stay on its onion.
    let personal = phone.node.space().unwrap();
    assert_eq!(
        personal.home_route(vos_light::route::Purpose::Member),
        Some(vos_light::route::Route::Onion)
    );
    let before = world.state.lock().unwrap().seen.len();
    phone.node.sync_personal().unwrap();
    let seen = world.state.lock().unwrap().seen[before..].to_vec();
    assert!(!seen.is_empty());
    for seen in &seen {
        assert_eq!(
            vos_light::testing::onion_of(&seen.target),
            Some(vos_light::testing::address(&world, 2)),
            "the home's onion alone: {seen:?}"
        );
    }
    assert_eq!(
        personal.home_route(vos_light::route::Purpose::Member),
        Some(vos_light::route::Route::Onion)
    );
    // A server naming the home's routes' own key as its handle reaches
    // another key: its enrollment and its opt-out leave the home's routes.
    let key = vos_light::route::home(&HOME);
    enroll_at(key, [0x54; 32], 1, "vos.other").unwrap();
    phone.node.sync().unwrap();
    phone.node.opt_out(key, true).unwrap();
    assert_eq!(
        personal.home_route(vos_light::route::Purpose::Member),
        Some(vos_light::route::Route::Onion)
    );
    let before = world.state.lock().unwrap().seen.len();
    phone.node.sync_personal().unwrap();
    for seen in &world.state.lock().unwrap().seen[before..] {
        assert_eq!(
            vos_light::testing::onion_of(&seen.target),
            Some(vos_light::testing::address(&world, 2)),
            "the home's onion alone: {seen:?}"
        );
    }
}
