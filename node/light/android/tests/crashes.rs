// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The personal space's flows with the phone's process killed at each of
//! their steps, as Android kills `:vos` without notice: at each call the
//! flow makes and at each query's first, before the world takes it or
//! after the world took it and before its answer leaves. The process stops
//! there ([`Held::kill`]): its files are kept as they are at that moment,
//! and nothing it would write, show or send after counts. The next process
//! is started from those files, its user and its keys the same, and the
//! flow called again (or the background job run): it ends as one never cut
//! short does, with one agent, one kit shown, and keys the device still
//! holds.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::phone::*;
use common::world::{Death, Step};
use common::*;
use vos_facility::personal::{Claim, KitKind, Why};
use vos_wire::personal::Policy;

/// The deaths tried in `trace`: at each call (by its occurrence) and each
/// query's first, before and after.
fn deaths(trace: &[Step]) -> Vec<(Step, usize, Death)> {
    let mut seen: HashMap<Step, usize> = HashMap::new();
    let mut deaths = Vec::new();
    for step in trace {
        let nth = seen.entry(*step).or_default();
        *nth += 1;
        if step.writes() || *nth == 1 {
            deaths.push((*step, *nth, Death::Before));
            if step.writes() {
                deaths.push((*step, *nth, Death::After));
            }
        }
    }
    deaths
}

/// `scenario` at each of `deaths`, a few at a time.
fn each(deaths: &[(Step, usize, Death)], scenario: impl Fn(Step, usize, Death) + Sync) {
    assert!(!deaths.is_empty());
    for batch in deaths.chunks(4) {
        std::thread::scope(|scope| {
            for &(step, nth, death) in batch {
                let scenario = &scenario;
                scope.spawn(move || scenario(step, nth, death));
            }
        });
    }
}

fn claim(world: &World, home: u32) -> Claim {
    Claim {
        home: home_of(world, home),
        kit: KitKind::Phrase,
        label: "phone".into(),
    }
}

/// The agents `home`'s `Homes` has yet to give.
fn pool(world: &World, home: u32) -> usize {
    world.state.lock().unwrap().spaces[&home]
        .homes
        .as_ref()
        .unwrap()
        .pool
        .len()
}

/// Whether `phone` holds the personal space and reads itself in its set.
fn holds(phone: &Held) -> bool {
    phone.node.personal().is_ok_and(|personal| {
        personal
            .devices()
            .is_ok_and(|devices| devices.iter().any(|device| device.me && !device.removed))
    })
}

/// A claim killed anywhere: claimed again, it ends at the agent the first
/// claim was given, its kit shown once, under the one source key and admin
/// key the device made.
#[test]
fn a_claim_killed_at_any_step_ends_at_one_agent_with_one_kit() {
    let trace = {
        let world = world();
        let home = world.home(HOME, 2, 2);
        let phone = phone(&world, 1);
        world.trace_from_now(1);
        phone
            .node
            .personal()
            .unwrap()
            .claim(&*phone.hand, claim(&world, home))
            .unwrap();
        world.trace(1)
    };
    each(&deaths(&trace), |step, nth, death| {
        let at = format!("{step:?} #{nth} {death:?}");
        let world = world();
        let home = world.home(HOME, 2, 2);
        let phone = phone(&world, 1);
        phone.node.space().unwrap().set_wait(3_000);
        let corpse = phone.kill(&world, step, nth, death);
        let cut = phone
            .node
            .personal()
            .unwrap()
            .claim(&*phone.hand, claim(&world, home));
        assert!(world.died(1), "{at}: not reached: {cut:?}");
        let phone = phone.reborn(&world, corpse);
        match phone
            .node
            .personal()
            .unwrap()
            .claim(&*phone.hand, claim(&world, home))
        {
            Ok(_) => {}
            Err(refusal) if refusal.why == Why::AlreadyHeld => {}
            Err(refusal) => panic!("{at}: the claim again: {refusal:?}"),
        }
        let synced = phone.node.sync_personal().unwrap();
        assert_eq!(synced.failed, 0, "{at}");
        let devices = phone.node.personal().unwrap().devices().unwrap();
        assert!(devices.len() == 1 && devices[0].me, "{at}: {devices:?}");
        assert_eq!(pool(&world, home), 1, "{at}: one agent given");
        // One kit; or, killed between the words shown and the claim held
        // (a store write after the user's tap), new words that say the
        // first are void. The mark is kept before the words are shown and
        // the reads behind them start with them, so a kill in those reads
        // can land before the first words are up: then one kit, saying so.
        let phrases = phone.hand.phrases.lock().unwrap().len();
        let voids = phone.hand.voids.lock().unwrap().clone();
        match phrases {
            1 => assert!(
                voids.is_empty() || (voids.len() == 1 && voids[0].contains("stopped")),
                "{at}: {voids:?}"
            ),
            2 => assert!(
                voids.len() == 1 && voids[0].contains("stopped"),
                "{at}: {voids:?}"
            ),
            _ => panic!("{at}: {phrases} kits"),
        }
        assert_eq!(phone.hand.admin_keys(), 1, "{at}: one admin key");
        assert_eq!(
            phone.hand.aliases.lock().unwrap().len(),
            1,
            "{at}: one source"
        );
    });
}

/// A world whose homes' pairing slots live `slot_ttl_ms`.
fn world_with_slots(slot_ttl_ms: u64) -> Arc<World> {
    let world = world();
    world.state.lock().unwrap().policy = Some(Policy {
        slot_ttl_ms,
        ..policy()
    });
    world
}

/// A pairing whose joiner is killed anywhere: started anew, the joiner
/// either finishes the pairing (its acknowledgement put by its next pass)
/// or holds nothing of it, and pairs again.
#[test]
fn a_pairing_with_its_joiner_killed_at_any_step_ends_paired() {
    const SLOT_MS: u64 = 12_000;
    const WAIT_MS: u64 = 8_000;
    let trace = {
        let world = world_with_slots(SLOT_MS);
        let home = world.home(HOME, 2, 1);
        let first = phone(&world, 1);
        let second = phone(&world, 2);
        first.claim(&world, home, KitKind::Phrase, "first");
        world.trace_from_now(2);
        first.pair(&second, "second");
        world.trace(2)
    };
    each(&deaths(&trace), |step, nth, death| {
        let at = format!("{step:?} #{nth} {death:?}");
        let world = world_with_slots(SLOT_MS);
        let home = world.home(HOME, 2, 1);
        let first = phone(&world, 1);
        let second = phone(&world, 2);
        first.claim(&world, home, KitKind::Phrase, "first");
        // Each wait well inside the slot, and long enough that a loaded
        // host's commit is confirmed within it.
        for phone in [&first, &second] {
            phone.node.space().unwrap().set_wait(WAIT_MS);
        }
        let corpse = second.kill(&world, step, nth, death);
        let code = first
            .node
            .personal()
            .unwrap()
            .pair_offer(&*first.hand)
            .unwrap();
        let second = std::thread::scope(|scope| {
            let opener = scope.spawn(|| first.node.personal().unwrap().pair_await(&*first.hand));
            let cut =
                second
                    .node
                    .personal()
                    .unwrap()
                    .pair_join(&*second.hand, &code.code, "second");
            assert!(world.died(2), "{at}: not reached: {cut:?}");
            let second = second.reborn(&world, corpse);
            second.node.space().unwrap().set_wait(WAIT_MS);
            // Its pass puts an acknowledgement its last process kept.
            let _ = second.node.sync_personal();
            // A pairing cut short before its hello is cancelled by the user;
            // one past it ends with its slot.
            std::thread::sleep(Duration::from_millis(500));
            first.node.space().unwrap().pair_cancel();
            let _ = opener.join().unwrap();
            second
        });
        for _ in 0..3 {
            let _ = first.node.sync_personal();
            let _ = second.node.sync_personal();
        }
        if !holds(&second) {
            first.pair(&second, "second");
        }
        assert!(holds(&second), "{at}");
        let standing = first.node.personal().unwrap().devices().unwrap();
        assert_eq!(
            standing.iter().filter(|device| !device.removed).count(),
            2,
            "{at}: {standing:?}"
        );
        assert_eq!(second.hand.admin_keys(), 1, "{at}: one admin key");
        assert_eq!(
            second.hand.aliases.lock().unwrap().len(),
            1,
            "{at}: one source"
        );
        let synced = second.node.sync_personal().unwrap();
        assert_eq!(synced.failed, 0, "{at}");
    });
}

/// The opener killed at its commit adding the joiner, before the agent
/// takes it or after: started anew, its pass posts the commit's evidence
/// (its message held before the call left) and the joiner joins; or the
/// commit never sent is dropped and the opener pairs another phone. (The
/// joiner left holding a group whose add was never sent pairs again only
/// once a group at the same agent can be dropped.)
#[test]
fn a_pairing_whose_opener_dies_at_its_commit_ends_paired() {
    for death in [Death::After, Death::Before] {
        let world = world_with_slots(12_000);
        let home = world.home(HOME, 2, 1);
        let first = phone(&world, 1);
        let second = phone(&world, 2);
        first.claim(&world, home, KitKind::Phrase, "first");
        second.node.space().unwrap().set_wait(15_000);
        let corpse = first.kill(
            &world,
            Step::call(vos_wire::personal::method::COMMIT),
            1,
            death,
        );
        let code = first
            .node
            .personal()
            .unwrap()
            .pair_offer(&*first.hand)
            .unwrap();
        let (first, joined) = std::thread::scope(|scope| {
            let joiner = scope.spawn(|| {
                second
                    .node
                    .personal()
                    .unwrap()
                    .pair_join(&*second.hand, &code.code, "second")
            });
            let cut = first.node.personal().unwrap().pair_await(&*first.hand);
            assert!(world.died(1), "{death:?}: not reached: {cut:?}");
            let first = first.reborn(&world, corpse);
            while !joiner.is_finished() {
                let _ = first.node.sync_personal();
                std::thread::sleep(Duration::from_millis(300));
            }
            (first, joiner.join().unwrap())
        });
        match death {
            Death::After => {
                joined.unwrap_or_else(|refusal| panic!("{death:?}: {refusal:?}"));
            }
            Death::Before => {
                assert!(joined.is_err());
                let third = phone(&world, 3);
                first.pair(&third, "third");
                assert!(holds(&third));
                assert_eq!(first.node.personal().unwrap().devices().unwrap().len(), 2);
                continue;
            }
        }
        assert!(holds(&second), "{death:?}");
        assert_eq!(
            first.node.personal().unwrap().devices().unwrap().len(),
            2,
            "{death:?}"
        );
    }
}

/// The restores' kit delay: long enough that a process started again on a
/// loaded host posts its evidence within it.
const KIT_DELAY_MS: u64 = 8_000;

fn world_with_kit_delay() -> Arc<World> {
    let world = world();
    world.state.lock().unwrap().policy = Some(Policy {
        kit_delay_ms: KIT_DELAY_MS,
        ..policy()
    });
    world
}

/// A restore killed anywhere: entered again with the kit, it is resumed,
/// no new kit shown, its call sent once and its evidence posted; it matures
/// after the kit's delay and the device reads the space back.
#[test]
fn a_restore_killed_at_any_step_matures_once_resumed() {
    let lost = |world: &Arc<World>, home: u32| {
        let lost = phone(world, 1);
        let claimed = lost.claim(world, home, KitKind::Phrase, "lost phone");
        (claimed.agent, lost.hand.phrase())
    };
    let request = |world: &World, home: u32| Claim {
        home: home_of(world, home),
        kit: KitKind::Phrase,
        label: "new phone".into(),
    };
    let trace = {
        let world = world_with_kit_delay();
        let home = world.home(HOME, 2, 1);
        let (_, words) = lost(&world, home);
        let fresh = phone(&world, 2);
        fresh.hand.will_enter(words);
        world.trace_from_now(2);
        fresh
            .node
            .personal()
            .unwrap()
            .restore(&*fresh.hand, request(&world, home), KitKind::Phrase)
            .unwrap();
        world.trace(2)
    };
    each(&deaths(&trace), |step, nth, death| {
        let at = format!("{step:?} #{nth} {death:?}");
        let world = world_with_kit_delay();
        let home = world.home(HOME, 2, 1);
        let (agent, words) = lost(&world, home);
        let fresh = phone(&world, 2);
        fresh.hand.will_enter(words);
        let corpse = fresh.kill(&world, step, nth, death);
        let cut = fresh.node.personal().unwrap().restore(
            &*fresh.hand,
            request(&world, home),
            KitKind::Phrase,
        );
        assert!(world.died(2), "{at}: not reached: {cut:?}");
        let fresh = fresh.reborn(&world, corpse);
        fresh
            .node
            .personal()
            .unwrap()
            .restore(&*fresh.hand, request(&world, home), KitKind::Phrase)
            .unwrap_or_else(|refusal| panic!("{at}: the restore again: {refusal:?}"));
        assert_eq!(fresh.hand.phrases.lock().unwrap().len(), 1, "{at}: one kit");
        after(KIT_DELAY_MS);
        let restored = fresh
            .node
            .personal()
            .unwrap()
            .restored(&*fresh.hand, KitKind::Phrase)
            .unwrap_or_else(|refusal| panic!("{at}: restored: {refusal:?}"));
        assert_eq!(restored.agent, agent, "{at}");
        assert!(holds(&fresh), "{at}");
        assert_eq!(fresh.hand.admin_keys(), 1, "{at}: one admin key");
    });
}

/// A move killed anywhere: moved again, it ends at the one agent the new
/// home gave, its kit shown once and one admin key made for it (a move
/// killed before its leave leaving again, one killed after finishing its
/// claim, never with a new kit).
#[test]
fn a_move_killed_at_any_step_ends_at_one_agent_with_one_kit() {
    let moving = |world: &World, home: u32| Claim {
        home: home_of(world, home),
        kit: KitKind::Phrase,
        label: "phone".into(),
    };
    let trace = {
        let world = world();
        let home = world.home(HOME, 2, 1);
        let elsewhere = world.home(ELSEWHERE, 3, 2);
        let phone = phone(&world, 1);
        phone.claim(&world, home, KitKind::Phrase, "phone");
        world.trace_from_now(1);
        phone
            .node
            .personal()
            .unwrap()
            .move_home(&*phone.hand, moving(&world, elsewhere))
            .unwrap();
        world.trace(1)
    };
    each(&deaths(&trace), |step, nth, death| {
        let at = format!("{step:?} #{nth} {death:?}");
        let world = world();
        let home = world.home(HOME, 2, 1);
        let elsewhere = world.home(ELSEWHERE, 3, 2);
        let phone = phone(&world, 1);
        phone.claim(&world, home, KitKind::Phrase, "phone");
        phone.node.space().unwrap().set_wait(3_000);
        let corpse = phone.kill(&world, step, nth, death);
        let cut = phone
            .node
            .personal()
            .unwrap()
            .move_home(&*phone.hand, moving(&world, elsewhere));
        assert!(world.died(1), "{at}: not reached: {cut:?}");
        let phone = phone.reborn(&world, corpse);
        let _ = phone.node.sync_personal();
        match phone
            .node
            .personal()
            .unwrap()
            .move_home(&*phone.hand, moving(&world, elsewhere))
        {
            Ok(_) => {}
            Err(refusal) if refusal.why == Why::AtThatHome => {}
            Err(refusal) => panic!("{at}: the move again: {refusal:?}"),
        }
        assert_eq!(pool(&world, elsewhere), 1, "{at}: one agent given");
        // The claim's kit and the move's; or, killed between the move's
        // words shown and its claim held, new words that say those are
        // void.
        let phrases = phone.hand.phrases.lock().unwrap().len();
        let voids = phone.hand.voids.lock().unwrap().clone();
        match phrases {
            2 => assert!(voids.is_empty(), "{at}: {voids:?}"),
            3 => assert!(
                voids.len() == 1 && voids[0].contains("stopped"),
                "{at}: {voids:?}"
            ),
            _ => panic!("{at}: {phrases} kits"),
        }
        let synced = phone.node.sync_personal().unwrap();
        assert_eq!(synced.failed, 0, "{at}");
        assert!(holds(&phone), "{at}");
        assert_eq!(
            phone.hand.admin_keys(),
            2,
            "{at}: the claim's admin key and the move's"
        );
    });
}

/// A leave killed anywhere: the next process's background pass finishes
/// a leave the agent took (its evidence posted, its removal read through,
/// in that process or the one before, and the space forgotten); one never
/// taken is left again. The phone then holds no personal space, and the
/// other phone's pass reads the leaver removed and commits its removal.
/// Most deaths are reached, and some leaves are finished by the pass
/// alone.
#[test]
fn a_leave_killed_at_any_step_ends_left() {
    let paired = |world: &Arc<World>| {
        let home = world.home(HOME, 2, 1);
        let staying = phone(world, 1);
        let leaving = phone(world, 2);
        staying.claim(world, home, KitKind::Phrase, "staying");
        staying.pair(&leaving, "leaving");
        leaving.node.personal().unwrap().follow_behind().unwrap();
        (staying, leaving)
    };
    let trace = {
        let world = world();
        let (_staying, leaving) = paired(&world);
        world.trace_from_now(2);
        leaving
            .node
            .personal()
            .unwrap()
            .leave(&*leaving.hand)
            .unwrap();
        world.trace(2)
    };
    let deaths = deaths(&trace);
    let (died, by_pass) = (AtomicUsize::new(0), AtomicUsize::new(0));
    each(&deaths, |step, nth, death| {
        let at = format!("{step:?} #{nth} {death:?}");
        let world = world();
        let (staying, leaving) = paired(&world);
        leaving.node.space().unwrap().set_wait(3_000);
        let corpse = leaving.kill(&world, step, nth, death);
        let cut = leaving.node.personal().unwrap().leave(&*leaving.hand);
        // A follow's later reads are as many as the log's pages then: a
        // step the trace saw may not come again.
        let leaving = if world.died(2) {
            died.fetch_add(1, Ordering::SeqCst);
            leaving.reborn(&world, corpse)
        } else {
            cut.unwrap_or_else(|refusal| panic!("{at}: not reached: {refusal:?}"));
            world.revive(2);
            leaving
        };
        let phase = || leaving.node.personal().unwrap().status().unwrap().phase;
        let _ = leaving.node.sync_personal();
        if phase() == vos_facility::personal::Phase::None {
            by_pass.fetch_add(1, Ordering::SeqCst);
        } else {
            match leaving.node.personal().unwrap().leave(&*leaving.hand) {
                Ok(()) => {}
                Err(refusal) if refusal.why == Why::NoSpace => {}
                Err(refusal) => panic!("{at}: the leave again: {refusal:?}"),
            }
        }
        let status = leaving.node.personal().unwrap().status().unwrap();
        assert_eq!(
            status.phase,
            vos_facility::personal::Phase::None,
            "{at}: the space cleared"
        );
        staying.node.sync_personal().unwrap();
        staying
            .node
            .personal()
            .unwrap()
            .update(&*staying.hand)
            .unwrap_or_else(|refusal| panic!("{at}: the commit: {refusal:?}"));
        let devices = staying.node.personal().unwrap().devices().unwrap();
        assert_eq!(
            devices.iter().filter(|device| !device.removed).count(),
            1,
            "{at}: {devices:?}"
        );
    });
    let died = died.load(Ordering::SeqCst);
    assert!(
        2 * died >= deaths.len(),
        "{died} of {} deaths reached",
        deaths.len()
    );
    assert!(
        by_pass.load(Ordering::SeqCst) > 0,
        "no leave finished by a pass"
    );
}
