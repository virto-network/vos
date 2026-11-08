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
use vos_wire::personal::{Kit, NewDevice, Recorded};

use super::kit::{household_with, kit_reads, r_of, written};
use super::*;
use crate::home::PERSONAL;

/// The other home's agent identity.
const ELSEWHERE: [u8; 32] = [0x2e; 32];

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
        &phone.store,
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
    drop(phone.group.take());
    phone.group = Some(
        held.claimed(&phone.light, PERSONAL, &entries, to.now)
            .unwrap(),
    );
}

/// `joiner`, a phone of the group the move left, paired again at `home`
/// from `opener`, handed `checkpoint`: its old group left on the handover,
/// and its add committed.
fn pair_again(home: &mut Home, opener: &mut Phone, joiner: &mut Phone, checkpoint: Checkpoint) {
    let package = DeviceGroup::key_package(&joiner.store, &joiner.keys, home.now).unwrap();
    let (prepared, mut pairing) = opener
        .group()
        .pair(joiner.keys.clone(), package, home.now)
        .unwrap();
    pairing.trust(checkpoint);
    let pairing = Pairing::from_bytes(&pairing.to_bytes()).unwrap();
    drop(joiner.group.take());
    joiner.group = Some(moving::rejoin(&joiner.light, joiner.keys.clone(), pairing).unwrap());
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
/// meanwhile, and it leaves the notice at the old home. Once the new
/// agent is assigned its group starts there, its scopes read afresh, and
/// the kit opens nothing there until the move pushed everything: every
/// node, then the recovery envelopes under the new `R`. The others read
/// the notice at the old home and the third writes there. The second pairs
/// again from the mover's checkpoint and carries the third's note, which
/// the mover reads though the third is not yet in the set; the third pairs
/// again and carries nothing. A new phone paired there with no checkpoint
/// reads the whole history from the new home's start.
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
    assert!(matches!(
        Move::prepare(
            &phones[0].store,
            group,
            phones[0].keys.clone(),
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
    let notice = held.notice(&space_of(&elsewhere));
    with(&mut home, &mut phones[0], &[NOTES], |sync| {
        sync.announce(&notice)
    })
    .unwrap();

    assign(&mut elsewhere, &homes, &held);
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
    for phone in &phones[1..] {
        assert!(phone.group.as_ref().unwrap().archive().authors.is_empty());
    }

    // The phones that missed the move: the notice, and a note written at
    // the old home.
    let announced = with(&mut home, &mut phones[1], &[NOTES], |sync| sync.announced()).unwrap();
    assert_eq!(announced, Some(notice.clone()));
    set(&phones[2].light, NOTES, 30, 31);
    with(&mut home, &mut phones[2], &[NOTES], |sync| sync.push(NOTES)).unwrap();
    with(&mut home, &mut phones[1], &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert_eq!(count(&phones[1].light, NOTES, 30), Some(31));

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
    assert_eq!(carried.pushed.len(), 1, "the note the move did not carry");
    assert_eq!(carried.held, 3);

    let caught = with(&mut elsewhere, &mut phones[0], &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert!(caught.passed.is_empty(), "{:?}", caught.passed);
    assert!(caught.alarms.is_empty(), "{:?}", caught.alarms);
    assert_eq!(count(&phones[0].light, NOTES, 30), Some(31));

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
    assert_eq!(stored(&elsewhere, &phones[0], scope).len(), 4);

    let mut fresh = Phone::new(4);
    phones[0].pair(&mut elsewhere, &mut fresh);
    phones.push(fresh);
    settle(&mut elsewhere, &mut phones);
    install(&phones[3].light, NOTES);
    let caught = with(&mut elsewhere, &mut phones[3], &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert!(caught.passed.is_empty(), "{:?}", caught.passed);
    for n in 0..3 {
        assert_eq!(count(&phones[3].light, NOTES, n), Some(10 + n));
    }
    assert_eq!(count(&phones[3].light, NOTES, 30), Some(31));
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
            &mover.store,
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
    assert!(matches!(
        moving::rejoin(&phones[0].light, phones[0].keys.clone(), pairing),
        Err(MoveError::Elsewhere)
    ));
    let standing = DeviceGroup::open(&phones[0].store).unwrap().unwrap();
    assert_eq!(standing.agent().identity, home.identity);
    phones[0].read(&mut home);
}
