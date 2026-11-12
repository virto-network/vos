// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The personal space's flows with the phone's process killed at each of
//! their steps, as Android kills `:vos` without notice: at each call the
//! flow makes and at each query's first, before the world takes it or
//! after the world took it and before its answer leaves. The process is
//! then started anew from its files, its user and its keys the same, and
//! the flow called again (or the background job run): it ends as one never
//! cut short does, with one agent, one kit shown, and keys the device still
//! holds.

mod common;

use std::collections::HashMap;

use common::phone::*;
use common::world::{Death, Step};
use common::*;
use s4_credential_contract::personal::{Claim, KitKind};
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
        home: world.home_of(home),
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
    phone
        .node
        .devices()
        .is_ok_and(|devices| devices.iter().any(|device| device.me && !device.removed))
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
        phone.node.claim(claim(&world, home), &*phone.hand).unwrap();
        world.trace(1)
    };
    each(&deaths(&trace), |step, nth, death| {
        let at = format!("{step:?} #{nth} {death:?}");
        let world = world();
        let home = world.home(HOME, 2, 2);
        let phone = phone(&world, 1);
        phone.node.set_wait(3_000).unwrap();
        world.kill(1, step, nth, death);
        let cut = phone.node.claim(claim(&world, home), &*phone.hand);
        assert!(world.died(1), "{at}: not reached: {cut:?}");
        let phone = phone.restart(&world);
        match phone.node.claim(claim(&world, home), &*phone.hand) {
            Ok(_) => {}
            Err(refusal) if refusal.message.contains("holds a personal space already") => {}
            Err(refusal) => panic!("{at}: the claim again: {refusal:?}"),
        }
        let synced = phone.node.sync_personal().unwrap();
        assert_eq!(synced.failed, 0, "{at}");
        let devices = phone.node.devices().unwrap();
        assert!(devices.len() == 1 && devices[0].me, "{at}: {devices:?}");
        assert_eq!(pool(&world, home), 1, "{at}: one agent given");
        assert_eq!(phone.hand.phrases.lock().unwrap().len(), 1, "{at}: one kit");
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
        for phone in [&first, &second] {
            phone.node.set_wait(4_000).unwrap();
        }
        world.kill(2, step, nth, death);
        let code = first.node.pair_offer(&*first.hand).unwrap();
        let second = std::thread::scope(|scope| {
            let opener = scope.spawn(|| first.node.pair_await(&*first.hand));
            let cut = second.node.pair_join(&code.code, "second", &*second.hand);
            assert!(world.died(2), "{at}: not reached: {cut:?}");
            let second = second.restart(&world);
            second.node.set_wait(4_000).unwrap();
            // Its pass puts an acknowledgement its last process kept.
            let _ = second.node.sync_personal();
            // A pairing cut short before its hello is cancelled by the user;
            // one past it ends with its slot.
            std::thread::sleep(Duration::from_millis(500));
            first.node.pair_cancel().unwrap();
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
        let standing = first.node.devices().unwrap();
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
        second.node.set_wait(15_000).unwrap();
        world.kill(1, Step::call("commit"), 1, death);
        let code = first.node.pair_offer(&*first.hand).unwrap();
        let (first, joined) = std::thread::scope(|scope| {
            let joiner = scope.spawn(|| second.node.pair_join(&code.code, "second", &*second.hand));
            let cut = first.node.pair_await(&*first.hand);
            assert!(world.died(1), "{death:?}: not reached: {cut:?}");
            let first = first.restart(&world);
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
                assert_eq!(first.node.devices().unwrap().len(), 2);
                continue;
            }
        }
        assert!(holds(&second), "{death:?}");
        assert_eq!(first.node.devices().unwrap().len(), 2, "{death:?}");
    }
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
        home: world.home_of(home),
        kit: KitKind::Phrase,
        label: "new phone".into(),
    };
    let trace = {
        let world = world();
        let home = world.home(HOME, 2, 1);
        let (_, words) = lost(&world, home);
        let fresh = phone(&world, 2);
        fresh.hand.will_enter(words);
        world.trace_from_now(2);
        fresh
            .node
            .restore(request(&world, home), KitKind::Phrase, &*fresh.hand)
            .unwrap();
        world.trace(2)
    };
    each(&deaths(&trace), |step, nth, death| {
        let at = format!("{step:?} #{nth} {death:?}");
        let world = world();
        let home = world.home(HOME, 2, 1);
        let (agent, words) = lost(&world, home);
        let fresh = phone(&world, 2);
        fresh.hand.will_enter(words);
        world.kill(2, step, nth, death);
        let cut = fresh
            .node
            .restore(request(&world, home), KitKind::Phrase, &*fresh.hand);
        assert!(world.died(2), "{at}: not reached: {cut:?}");
        let fresh = fresh.restart(&world);
        fresh
            .node
            .restore(request(&world, home), KitKind::Phrase, &*fresh.hand)
            .unwrap_or_else(|refusal| panic!("{at}: the restore again: {refusal:?}"));
        assert_eq!(fresh.hand.phrases.lock().unwrap().len(), 1, "{at}: one kit");
        after(policy().kit_delay_ms);
        let restored = fresh
            .node
            .restored(KitKind::Phrase, &*fresh.hand)
            .unwrap_or_else(|refusal| panic!("{at}: restored: {refusal:?}"));
        assert_eq!(restored.agent, agent, "{at}");
        assert!(holds(&fresh), "{at}");
        assert_eq!(fresh.hand.admin_keys(), 1, "{at}: one admin key");
    });
}

/// A move killed anywhere: moved again, it ends at the one agent the new
/// home gave, its kit shown once, everything carried (a carry cut short
/// finished by the background job or by the move called again, never by a
/// new kit).
#[test]
fn a_move_killed_at_any_step_ends_at_one_agent_with_one_kit() {
    let moving = |world: &World, home: u32| Claim {
        home: world.home_of(home),
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
            .move_home(moving(&world, elsewhere), &*phone.hand)
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
        phone.node.set_wait(3_000).unwrap();
        world.kill(1, step, nth, death);
        let cut = phone
            .node
            .move_home(moving(&world, elsewhere), &*phone.hand);
        assert!(world.died(1), "{at}: not reached: {cut:?}");
        let phone = phone.restart(&world);
        let _ = phone.node.sync_personal();
        match phone
            .node
            .move_home(moving(&world, elsewhere), &*phone.hand)
        {
            Ok(_) => {}
            Err(refusal) if refusal.message.contains("at that home already") => {}
            Err(refusal) => panic!("{at}: the move again: {refusal:?}"),
        }
        assert_eq!(pool(&world, elsewhere), 1, "{at}: one agent given");
        assert_eq!(
            phone.hand.phrases.lock().unwrap().len(),
            2,
            "{at}: the claim's kit and the move's"
        );
        let synced = phone.node.sync_personal().unwrap();
        assert_eq!(synced.failed, 0, "{at}");
        assert!(holds(&phone), "{at}");
        assert_eq!(phone.hand.admin_keys(), 1, "{at}: one admin key");
    });
}
