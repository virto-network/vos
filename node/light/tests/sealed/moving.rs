//! Moving home (`light-node.md` §3.9) between two homes, each `Personal`:
//! a phone claims an agent at the other home, its claim held beside the
//! group it leaves, the kit split anew there; it leaves a sealed notice at
//! the old home, starts its group at the new one and pushes everything,
//! the recovery envelopes last, before which the kit opens nothing there.
//! The phones that missed the move read the notice and keep writing at the
//! old home; each pairs again from the mover, starts from its checkpoint
//! and carries what the new home lacks, whose old author the readers there
//! take as the set's. A move refused leaves the old group standing, and one
//! interrupted, by a lost answer or a restart, resumes where it stopped,
//! each node at the new home once.

use ed25519_dalek::SigningKey;
use vos_light::group::{Checkpoint, DeviceGroup, Pairing};
use vos_light::home::{Claim, Home as HomeSpace};
use vos_light::kit::{KitKey, KitSecret};
use vos_light::moving::{self, Move, MoveError};
use vos_light::personal::Waiting;
use vos_wire::personal::{Kit, NewDevice, Recorded};

use super::kit::{
    household_with, kit_reads, matured, open_restore, operate, r_of, restart as restored_group,
    written,
};
use super::*;
use crate::home::PERSONAL;

/// The other home's agent identity.
const ELSEWHERE: [u8; 32] = [0x2e; 32];

/// A third home's agent identity.
const FARTHER: [u8; 32] = [0x3e; 32];

/// A home as a device reaches it.
fn space_of(home: &Home) -> HomeSpace {
    HomeSpace {
        space: [0x49; 32],
        handle: [0x4b; 32],
        agent: 4,
        identity: home.identity,
        homes: InstanceId(3),
        credentials: InstanceId(9),
    }
}

/// `phone`'s move of its group to the agent of `to` with the kit of
/// `keys`, held in its store.
fn prepare(phone: &Phone, to: &Home, keys: Vec<KitKey>) -> Move {
    let group = phone.group.as_ref().unwrap();
    Move::prepare(
        &phone.light,
        group,
        phone.keys.clone(),
        keys,
        4,
        to.identity,
    )
    .unwrap()
}

/// `Homes`' assignment of the agent of `to` to the move's claim, as
/// `homes`.
fn assign(to: &mut Home, homes: &SigningKey, held: &Move) {
    let call = held.call(&space_of(to), to.now + MIN).unwrap();
    let (device, kit, _) = <(NewDevice, Kit, u32)>::decode_exact(&call.arguments).unwrap();
    to.call(homes, "assign", (device, kit).encode())
        .answer::<Recorded>()
        .unwrap();
}

/// The move assigned: `phone`'s old group left, its new one started from
/// the log of `to`.
fn claimed(phone: &mut Phone, to: &Home, held: Move) {
    let entries = to.log(phone.sync_key(), 0).unwrap();
    let group = phone.group.take();
    phone.group = Some(
        held.claimed(&phone.light, group, PERSONAL, &entries, to.now)
            .unwrap(),
    );
}

/// `joiner`, a phone of the group the move left, paired again at `home`
/// from `opener`, handed `checkpoint`: its old group left on the handover,
/// and its add committed.
fn pair_again(home: &mut Home, opener: &mut Phone, joiner: &mut Phone, checkpoint: Checkpoint) {
    let group = joiner.group.as_ref().unwrap();
    joiner.keys = moving::naming(&joiner.light, group, joiner.keys.clone()).unwrap();
    let package = DeviceGroup::key_package(&joiner.store, &joiner.keys, home.now).unwrap();
    let (prepared, mut pairing) = opener
        .group()
        .pair(joiner.keys.clone(), package, home.now)
        .unwrap();
    pairing.trust(checkpoint);
    let pairing = Pairing::from_bytes(&pairing.to_bytes()).unwrap();
    let group = joiner.group.take();
    let keys = joiner.keys.clone();
    joiner.group = Some(moving::rejoin(&joiner.light, group, keys, pairing).unwrap());
    opener.send(home, &prepared).unwrap();
}

fn checkpoint(home: &mut Home, phone: &mut Phone) -> Checkpoint {
    with(home, phone, &[NOTES], |sync| sync.checkpoint(NOTES)).unwrap()
}

/// The closure's lifetimes are the link's, which `moving::finish` named
/// alone does not take.
#[allow(clippy::redundant_closure)]
fn finish(home: &mut Home, phone: &mut Phone) -> moving::Finished {
    with(home, phone, &[NOTES], |sync| moving::finish(sync)).unwrap()
}

/// Three phones at a home, each holding every note. The first moves: its
/// claim elsewhere waits beside the group it leaves, a second move refused
/// meanwhile; once the claim is answered it leaves the notice at the old
/// home, and once the new agent is assigned its group starts there, its
/// scopes read afresh, the kit opening nothing there until the move pushed
/// everything: every node, then the recovery envelopes under the new `R`.
/// At the old home the others read the notice; the third writes there,
/// and a fourth phone is paired there by the second and writes too, past
/// the moved first's voice. The second pairs again from the mover's
/// checkpoint and carries both notes, which the mover reads, the fourth's
/// author reaching it from the log, in the keys the second's add named;
/// the third pairs again and
/// carries nothing. The third removed at the new home before it pushed
/// anything there, a new phone paired there with no checkpoint reads the
/// whole history from the new home's start, the third's carried nodes
/// among it. The mover moves again, to a third home, and a phone paired
/// there reads the whole history too, as a restore there does once every
/// device is lost.
#[test]
fn a_move_carries_the_personal_space_and_the_others_pair_again() {
    let kit = KitSecret::phrase().unwrap();
    let (mut home, mut phones, _) = household_with(3, vec![kit.key()]);
    written(&mut home, &mut phones);
    for phone in phones.iter_mut() {
        with(&mut home, phone, &[NOTES], |sync| sync.catch_up(NOTES)).unwrap();
    }
    let naming = phones[0].group().archive().naming;
    let homes = SigningKey::from_bytes(&[0x51; 32]);
    let mut elsewhere = Home::at(&homes, policy(), ELSEWHERE);
    let next = KitSecret::phrase().unwrap();

    let held = prepare(&phones[0], &elsewhere, vec![next.key()]);
    let group = phones[0].group.as_ref().unwrap();
    let keys = phones[0].keys.clone();
    assert!(matches!(
        Move::prepare(
            &phones[0].light,
            group,
            keys,
            vec![next.key()],
            4,
            ELSEWHERE
        ),
        Err(MoveError::Held)
    ));
    assert!(
        Claim::pending(&phones[0].store).unwrap().is_none(),
        "a move's claim is the move's"
    );
    let caught = with(&mut home, &mut phones[0], &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert_eq!(
        caught.waiting,
        Some(Waiting::Moving),
        "the old home is read no more once the claim named what it carries"
    );
    assign(&mut elsewhere, &homes, &held);
    let notice = held.notice(&space_of(&elsewhere));
    with(&mut home, &mut phones[0], &[NOTES], |sync| {
        sync.announce(&notice)
    })
    .unwrap();
    claimed(&mut phones[0], &elsewhere, held);
    assert_eq!(phones[0].group().agent().identity, ELSEWHERE);
    assert!(moving::carrying(&phones[0].store).unwrap());
    assert_eq!(phones[0].light.cursor(NOTES).unwrap(), None);
    assert_eq!(
        phones[0].group().archive().naming,
        naming,
        "the scopes keep their ids"
    );
    phones[0].read(&mut elsewhere);
    let early = with(&mut elsewhere, &mut phones[0], &[], |sync| sync.recovery()).unwrap();
    assert_eq!(
        early.pushed, 0,
        "no recovery envelope while the move carries"
    );
    assert!(
        kit_reads(&elsewhere, &next).is_empty(),
        "the kit opens nothing at the new home yet"
    );

    let finished = finish(&mut elsewhere, &mut phones[0]);
    assert!(finished.done);
    assert_eq!(finished.scopes[0].2.pushed, vec![1, 2, 3]);
    assert!(finished.recovery.pushed > 0);
    assert!(!moving::carrying(&phones[0].store).unwrap());
    assert_eq!(phones[0].light.cursor(NOTES).unwrap(), Some(3));
    let scope = scope_of(&phones[0], NOTES);
    assert_eq!(stored(&elsewhere, &phones[0], scope).len(), 3);
    let r = r_of(&mut phones[0]);
    let recovered = open_recovery(&r, &ELSEWHERE, &kit_reads(&elsewhere, &next)).unwrap();
    assert_eq!(recovered.naming, naming, "the kit's copy at the new home");
    let mover = phones[0].group.as_ref().unwrap();
    for phone in &phones[1..] {
        assert!(
            matches!(mover.carriers(&phone.sync_key(), &scope)[..], [(_, None)]),
            "the mover's keys name each old device"
        );
    }

    // The phones that missed the move: the notice, a note written at the
    // old home, and a fourth phone paired there once the first's voice
    // lapsed, writing too.
    let announced = with(&mut home, &mut phones[1], &[NOTES], |sync| sync.announced()).unwrap();
    assert_eq!(announced, Some(notice.clone()));
    set(&phones[2].light, NOTES, 30, 31);
    with(&mut home, &mut phones[2], &[NOTES], |sync| sync.push(NOTES)).unwrap();
    home.pass(policy().confirm_window_ms + 1);
    let mut late = Phone::new(5);
    phones[1].alive(&mut home);
    phones[2].alive(&mut home);
    phones[1].pair(&mut home, &mut late);
    let mut there = [phones.remove(1), phones.remove(1), late];
    settle(&mut home, &mut there);
    let [second, third, mut late] = there;
    assert!(late.group().id().is_some(), "added at the old home");
    install(&late.light, NOTES);
    set(&late.light, NOTES, 50, 51);
    with(&mut home, &mut late, &[NOTES], |sync| sync.push(NOTES)).unwrap();
    phones.push(second);
    phones.push(third);
    with(&mut home, &mut phones[1], &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert_eq!(count(&phones[1].light, NOTES, 30), Some(31));
    assert_eq!(count(&phones[1].light, NOTES, 50), Some(51));

    let checkpoint_at = checkpoint(&mut elsewhere, &mut phones[0]);
    let (mover, rest) = phones.split_at_mut(1);
    pair_again(&mut elsewhere, &mut mover[0], &mut rest[0], checkpoint_at);
    settle(&mut elsewhere, &mut phones[..2]);
    assert_eq!(phones[1].group().id(), Some(1));
    assert_eq!(phones[1].group().agent().identity, ELSEWHERE);
    let finished = finish(&mut elsewhere, &mut phones[1]);
    assert!(finished.done);
    let (_, caught, carried) = &finished.scopes[0];
    assert_eq!(caught.started, Some(checkpoint_at.position));
    assert_eq!(carried.pushed.len(), 2, "the notes the move did not carry");
    assert_eq!(carried.held, 3);

    // The second's carried authors reach the mover from the log, with no
    // archive read.
    let caught = with(&mut elsewhere, &mut phones[0], &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert!(caught.passed.is_empty(), "{:?}", caught.passed);
    assert!(caught.alarms.is_empty(), "{:?}", caught.alarms);
    assert_eq!(count(&phones[0].light, NOTES, 30), Some(31));
    assert_eq!(count(&phones[0].light, NOTES, 50), Some(51));

    let checkpoint_at = checkpoint(&mut elsewhere, &mut phones[0]);
    let (mover, rest) = phones.split_at_mut(1);
    pair_again(&mut elsewhere, &mut mover[0], &mut rest[1], checkpoint_at);
    settle(&mut elsewhere, &mut phones);
    let finished = finish(&mut elsewhere, &mut phones[2]);
    assert!(finished.done);
    assert!(
        finished.scopes[0].2.pushed.is_empty(),
        "nothing left to carry"
    );
    assert_eq!(stored(&elsewhere, &phones[0], scope).len(), 5);

    // The third removed at once by the two others, seasoned there.
    elsewhere.pass(policy().probation_ms + policy().seasoning_ms);
    for phone in phones.iter_mut() {
        phone.alive(&mut elsewhere);
    }
    let removed = phones[2].group().id().unwrap();
    let (admin, sync) = (phones[0].admin.clone(), phones[0].sync.clone());
    let removal = operate(
        &mut elsewhere,
        &admin,
        &sync,
        "remove",
        removed.encode(),
        None,
    );
    let (admin, sync) = (phones[1].admin.clone(), phones[1].sync.clone());
    operate(
        &mut elsewhere,
        &admin,
        &sync,
        "cosign",
        removal.encode(),
        None,
    );
    settle(&mut elsewhere, &mut phones[..2]);
    phones[0].update(&mut elsewhere).unwrap();
    settle(&mut elsewhere, &mut phones[..2]);
    let third = phones.pop().unwrap();
    assert!(matches!(
        phones[0].group().author(&third.sync_key()),
        Some((_, true))
    ));

    let mut fresh = Phone::new(4);
    phones[0].pair(&mut elsewhere, &mut fresh);
    phones.push(fresh);
    settle(&mut elsewhere, &mut phones);
    install(&phones[2].light, NOTES);
    let caught = with(&mut elsewhere, &mut phones[2], &[NOTES], |sync| {
        sync.archive()?;
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert!(caught.passed.is_empty(), "{:?}", caught.passed);
    for n in 0..3 {
        assert_eq!(count(&phones[2].light, NOTES, n), Some(10 + n));
    }
    assert_eq!(count(&phones[2].light, NOTES, 30), Some(31));
    assert_eq!(count(&phones[2].light, NOTES, 50), Some(51));

    // A second move, to a third home: the mover's keys there name what the
    // first move and the second's pairing carried, the fourth's author
    // among it, which no device of the third home's set is.
    let mut farther = Home::at(&homes, policy(), FARTHER);
    let last = KitSecret::phrase().unwrap();
    let held = prepare(&phones[0], &farther, vec![last.key()]);
    assert_eq!(held.agent().1, FARTHER);
    assign(&mut farther, &homes, &held);
    claimed(&mut phones[0], &farther, held);
    let finished = finish(&mut farther, &mut phones[0]);
    assert!(finished.done);
    let mover = phones[0].group.as_ref().unwrap();
    assert!(
        matches!(mover.carriers(&late.sync_key(), &scope)[..], [(_, None)]),
        "the second move names the fourth's author"
    );
    let mut newest = Phone::new(6);
    phones[0].pair(&mut farther, &mut newest);
    let mut there = vec![phones.remove(0), newest];
    settle(&mut farther, &mut there);
    install(&there[1].light, NOTES);
    let caught = with(&mut farther, &mut there[1], &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert!(caught.passed.is_empty(), "{:?}", caught.passed);
    for n in 0..3 {
        assert_eq!(count(&there[1].light, NOTES, n), Some(10 + n));
    }
    assert_eq!(count(&there[1].light, NOTES, 30), Some(31));
    assert_eq!(count(&there[1].light, NOTES, 50), Some(51));

    // Every device lost: a restore at the third home reads the carried
    // history back, the authors from the device set's keys as the agent
    // shows them, no archive naming one.
    drop(there);
    let after = KitSecret::phrase().unwrap();
    let (mut restored, split, _) = open_restore(&mut farther, &last, &after, 7);
    let archive = matured(&mut farther, &last, &restored);
    restored_group(&farther, &mut restored, &split, &after);
    restored.group().inherit(&archive).unwrap();
    install(&restored.light, NOTES);
    let caught = with(&mut farther, &mut restored, &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert!(caught.passed.is_empty(), "{:?}", caught.passed);
    for n in 0..3 {
        assert_eq!(count(&restored.light, NOTES, n), Some(10 + n));
    }
    assert_eq!(count(&restored.light, NOTES, 30), Some(31));
    assert_eq!(count(&restored.light, NOTES, 50), Some(51));
}

/// A move refused at the other home is abandoned, the old group standing;
/// a move to the agent the group has is refused. A move whose answer was
/// lost is sent again as it was after a restart; once assigned, a restart
/// finds it carrying; a carry round whose answers were lost is sent again
/// as it was after a restart, and the new home holds each node once.
#[test]
fn an_interrupted_move_resumes_where_it_stopped() {
    let kit = KitSecret::phrase().unwrap();
    let (mut home, mut phones, _) = household_with(2, vec![kit.key()]);
    written(&mut home, &mut phones);
    with(&mut home, &mut phones[0], &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    let mut mover = phones.remove(0);
    let homes = SigningKey::from_bytes(&[0x51; 32]);
    let mut elsewhere = Home::at(&homes, policy(), ELSEWHERE);

    let refused = prepare(&mover, &elsewhere, vec![kit.key()]);
    refused.abandon(&mover.store).unwrap();
    assert!(!moving::moving(&mover.store).unwrap());
    let standing = DeviceGroup::open(&mover.store).unwrap().unwrap();
    assert_eq!(standing.agent().identity, home.identity);
    drop(standing);
    let group = mover.group.as_ref().unwrap();
    assert!(matches!(
        Move::prepare(
            &mover.light,
            group,
            mover.keys.clone(),
            vec![kit.key()],
            3,
            home.identity
        ),
        Err(MoveError::Here)
    ));

    let held = prepare(&mover, &elsewhere, vec![kit.key()]);
    let sent = held.call(&space_of(&elsewhere), elsewhere.now).unwrap();
    restart(&mut mover);
    let held = Move::pending(&mover.store)
        .unwrap()
        .expect("held until assigned");
    let again = held.call(&space_of(&elsewhere), elsewhere.now).unwrap();
    assert_eq!(again.arguments, sent.arguments, "the same claim");
    assign(&mut elsewhere, &homes, &held);
    claimed(&mut mover, &elsewhere, held);
    assert!(Move::pending(&mover.store).unwrap().is_none());
    restart(&mut mover);
    assert!(moving::carrying(&mover.store).unwrap());
    assert_eq!(mover.group().agent().identity, ELSEWHERE);
    mover.read(&mut elsewhere);

    // The archive pushed first, so the first push the link fails is the
    // carry's round.
    with(&mut elsewhere, &mut mover, &[], |sync| sync.archive()).unwrap();
    let mut link = HomeLink::new(&mut elsewhere, &mover);
    link.fail = Some(Fail::Lost);
    #[allow(clippy::redundant_closure)]
    let lost = over(&mut link, &mut mover, &[NOTES], |sync| moving::finish(sync));
    assert!(matches!(lost, Err(SyncError::Link(Broken))));
    restart(&mut mover);
    assert!(moving::carrying(&mover.store).unwrap());
    let finished = finish(&mut elsewhere, &mut mover);
    assert!(finished.done);
    assert_eq!(
        finished.scopes[0].2.pushed,
        vec![1, 2],
        "answered by id where the agent took them"
    );
    let scope = scope_of(&mover, NOTES);
    assert_eq!(
        stored(&elsewhere, &mover, scope).len(),
        2,
        "the lost round sent again as it was"
    );
    assert!(!moving::moving(&mover.store).unwrap());
}

/// A pairing of another personal space leaves nothing: the device's group
/// stands.
#[test]
fn a_pairing_of_another_personal_space_is_refused() {
    let (mut home, mut phones) = household(1);
    let homes = SigningKey::from_bytes(&[0x51; 32]);
    let mut elsewhere = Home::at(&homes, policy(), ELSEWHERE);
    let mut stranger = Phone::new(7);
    stranger.claim(&mut elsewhere, &homes);
    let package =
        DeviceGroup::key_package(&phones[0].store, &phones[0].keys, elsewhere.now).unwrap();
    let (_, pairing) = stranger
        .group()
        .pair(phones[0].keys.clone(), package, elsewhere.now)
        .unwrap();
    let group = phones[0].group.take();
    let keys = phones[0].keys.clone();
    assert!(matches!(
        moving::rejoin(&phones[0].light, group, keys, pairing),
        Err(MoveError::Elsewhere)
    ));
    phones[0].group = DeviceGroup::open(&phones[0].store).unwrap();
    assert_eq!(phones[0].group().agent().identity, home.identity);
    phones[0].read(&mut home);
}
