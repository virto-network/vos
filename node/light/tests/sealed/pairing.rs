//! Pairing (`light-node.md` §3.8) through a pairing slot's inbox at
//! `Personal`, over Noise `XXpsk3`: the QR code's slot, key and code; the
//! offer of the home and the memberships, the joiner's hello with its
//! "home" nullifier and its handles, the handover of the log, the archive
//! and `R`, acknowledged before the commit adding the joiner, which closes
//! the slot; the joiner reading at once;
//! its enrollments and confirmations held for their prompts; a second
//! claim refused on a device that holds the archive; a code that is not
//! the QR's, or an item the operators replaced, failing the handshake; and
//! the retirement of a phone: the new one paired, the old one removed by
//! the other devices and revoked in every space its handles name.

use ed25519_dalek::SigningKey;
use vos_abi::Encode;
use vos_abi::ids::InstanceId;
use vos_abi::result::Outcome;
use vos_light::group::{DeviceGroup, Event};
use vos_light::home::{self, Claim, ClaimError, Home as HomeSpace};
use vos_light::memberships::{self, Enrollment};
use vos_light::pairing::{
    Code, Hello, Joined, Joiner, Membership, Offer, Opened, Opener, PairError, Put,
};
use vos_testkit::programs;
use vos_wire::books::{Agent, DeviceHandle, Enrolled, Location};
use vos_wire::personal::{Attached, DeviceView, InboxItem, PersonalError, Recorded, Status};

use crate::home::{Home, PERSONAL};
use crate::phone::{Phone, kit_key};
use crate::{NOTES, count, household, install, policy, set, settle, with};

/// The credential book's instance on each phone.
const BOOK: InstanceId = InstanceId(3);
/// A space the user is a member of beside the home.
const CLUB: [u8; 32] = [0xc1; 32];

/// The home, as a device reaches it.
fn home_space(home: &Home) -> HomeSpace {
    HomeSpace {
        space: [0x48; 32],
        handle: [0x4a; 32],
        agent: 3,
        identity: home.identity,
        homes: InstanceId(3),
        credentials: InstanceId(9),
    }
}

fn club() -> Membership {
    Membership {
        space: CLUB,
        handle: [0xc2; 32],
        agent: 11,
        identity: [0xc3; 32],
        credentials: InstanceId(9),
    }
}

/// Phone `n`'s secret in the space whose handle is `handle`, from its
/// source's output.
fn secret(n: u8, handle: &[u8; 32]) -> vos_light::DeviceSecret {
    vos_light::derive_secret(&[n; 32], handle)
}

fn handle_of(n: u8, membership: &Membership) -> DeviceHandle {
    let secret = secret(n, &membership.handle);
    DeviceHandle {
        handle: membership.handle,
        member: vos_light::member(&secret).to_bytes(),
        owner: vos_light::owner(&secret).to_bytes(),
    }
}

/// The slot's items as `key` reads them.
fn inbox(home: &Home, key: [u8; 32]) -> Vec<InboxItem> {
    let mut items: Vec<InboxItem> = Vec::new();
    loop {
        let after = items.last().map(|item| (item.expires, item.id));
        let page: Vec<InboxItem> = home.query(key, "inbox", after.encode()).unwrap();
        if page.is_empty() {
            return items;
        }
        items.extend(page);
    }
}

/// Leave `put` in the slot under `key`.
fn leave(home: &mut Home, key: &SigningKey, put: &Put) {
    home.call(key, "put", put.arguments())
        .answer::<u64>()
        .unwrap();
}

/// An opener's slot opened at the home, and the QR code's bytes.
fn open(home: &mut Home, opener: &mut Phone, offer: Offer) -> (Opener, Vec<u8>) {
    open_in(home, opener, offer, policy().inbox_item_bytes)
}

/// [`open`], the handover in items of `item_bytes`.
fn open_in(
    home: &mut Home,
    opener: &mut Phone,
    offer: Offer,
    item_bytes: u32,
) -> (Opener, Vec<u8>) {
    let (mut side, drawn) = Opener::open(home.identity, offer, item_bytes).unwrap();
    let at = home
        .call(&opener.sync, "open_slot", drawn.slot.arguments())
        .answer::<u64>()
        .unwrap();
    let code = side.code(
        &drawn,
        at + policy().slot_ttl_ms,
        7,
        PERSONAL,
        vec![vos_wire::credentials::Onion {
            key: [0x0e; 32],
            ssh_host_key: [0x0f; 32],
        }],
    );
    (side, code.to_bytes().to_vec())
}

/// The opener's next step from the slot's items.
fn opener_reads(home: &Home, phone: &Phone, side: &mut Opener) -> Opened {
    side.read(&inbox(home, phone.sync_key())).unwrap()
}

/// What the joiner of `code` reads next.
fn joiner_reads(home: &Home, code: &Code, side: &mut Joiner) -> Joined {
    side.read(&inbox(home, code.slot_key().verifying_key().to_bytes()))
        .unwrap()
}

/// The joiner's hello: its keys with its "home" nullifier, its key package
/// and its handle in each offered space.
fn hello(home: &Home, joiner: &mut Phone, n: u8, offer: &Offer) -> Hello {
    joiner.keys.nullifier = offer.home.nullifier(&secret(n, &offer.home.handle));
    Hello {
        device: joiner.keys.clone(),
        key_package: DeviceGroup::key_package(&joiner.store, &joiner.keys, home.now()).unwrap(),
        handles: offer
            .memberships
            .iter()
            .map(|membership| (membership.space, handle_of(n, membership)))
            .collect(),
    }
}

/// `opener` pairs `joiner` (phone `n`) through a slot: the slot's code,
/// the commit made once the joiner acknowledged the handover, and the
/// enrollments held.
fn pair(
    home: &mut Home,
    opener: &mut Phone,
    joiner: &mut Phone,
    n: u8,
    offer: Offer,
) -> (Code, Vec<Enrollment>) {
    pair_in(home, opener, joiner, n, offer, policy().inbox_item_bytes)
}

/// [`pair`], the handover in items of `item_bytes`.
fn pair_in(
    home: &mut Home,
    opener: &mut Phone,
    joiner: &mut Phone,
    n: u8,
    offer: Offer,
    item_bytes: u32,
) -> (Code, Vec<Enrollment>) {
    let (mut side, qr) = open_in(home, opener, offer.clone(), item_bytes);
    let code = Code::from_bytes(&qr).expect("the QR code reads");
    let (mut joining, second) = Joiner::scan(&code).unwrap();
    leave(home, &code.slot_key(), &second);

    let Opened::Check { put: third, .. } = opener_reads(home, opener, &mut side) else {
        panic!("the handshake's last message")
    };
    leave(home, &opener.sync, &third);
    let Joined::Check(check) = joiner_reads(home, &code, &mut joining) else {
        panic!("the check")
    };
    assert_eq!(
        Some(check.as_str()),
        side.check(),
        "both sides show one check"
    );
    leave(home, &opener.sync, &side.offer().unwrap());
    let Joined::Offer(offered) = joiner_reads(home, &code, &mut joining) else {
        panic!("the offer")
    };
    assert_eq!(offered, offer);
    let greeting = hello(home, joiner, n, &offered);
    let put = joining.hello(&greeting).unwrap();
    leave(home, &code.slot_key(), &put);

    let Opened::Hello(heard) = opener_reads(home, opener, &mut side) else {
        panic!("the hello")
    };
    assert_eq!(heard, greeting);
    let enrollments = memberships::plan(&offer.memberships, &heard);
    let (prepared, pairing) = opener
        .group()
        .pair(heard.device.clone(), heard.key_package.clone(), home.now())
        .unwrap();
    let puts = side.hand_over(&pairing).unwrap();
    assert_eq!(
        puts.len() > 1,
        item_bytes < 1024,
        "items of {item_bytes} bytes"
    );
    for put in puts {
        leave(home, &opener.sync, &put);
    }
    assert!(matches!(
        opener_reads(home, opener, &mut side),
        Opened::Waiting
    ));

    let Joined::Handover(pairing, ack) = joiner_reads(home, &code, &mut joining) else {
        panic!("the handover")
    };
    joiner.group =
        Some(DeviceGroup::join(&joiner.store, joiner.keys.clone(), *pairing, Vec::new()).unwrap());
    memberships::expect(&joiner.store, &offered.memberships).unwrap();
    leave(home, &code.slot_key(), &ack);
    assert!(matches!(
        opener_reads(home, opener, &mut side),
        Opened::Received
    ));
    opener.send(home, &prepared).unwrap();
    memberships::hold(&opener.store, &enrollments).unwrap();
    (code, enrollments)
}

/// A device's view in the agent's device set.
fn view_of(home: &Home, reader: &Phone, sync: [u8; 32]) -> DeviceView {
    let devices: Vec<DeviceView> = home
        .query(reader.sync_key(), "devices", ().encode())
        .unwrap();
    devices
        .into_iter()
        .find(|view| view.device.keys.sync == sync)
        .expect("in the device set")
}

/// A phone paired through the slot: the handover acknowledged before the
/// commit, which closes the slot; the new phone's add carries its "home"
/// nullifier; it reads the notes at once, and writes; its enrollment and
/// its confirmation are held
/// until made; and neither phone claims a second agent.
#[test]
fn a_phone_is_paired_through_the_slot_and_reads_at_once() {
    let (mut home, mut phones) = household(1);
    let mut joiner = Phone::new(2);
    for key in 1..=3 {
        set(&phones[0].light, NOTES, key, key * 10);
    }
    with(&mut home, &mut phones[0], &[NOTES], |sync| sync.push(NOTES)).unwrap();
    with(&mut home, &mut phones[0], &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();

    let offer = Offer {
        home: home_space(&home),
        memberships: vec![club()],
    };
    let (code, enrollments) = pair(&mut home, &mut phones[0], &mut joiner, 2, offer.clone());
    phones.push(joiner);
    settle(&mut home, &mut phones);
    let joined = phones[1].group().id().expect("its add confirmed");
    let view = view_of(&home, &phones[0], phones[1].sync_key());
    assert_eq!(view.id, joined);
    assert_eq!(
        view.device.keys.nullifier,
        offer.home.nullifier(&secret(2, &offer.home.handle)),
        "its own nullifier, from its own secret"
    );
    assert_eq!(view.device.status, Status::Live);

    // The slot closed with the add: its key admitted no more.
    let stray = Put {
        slot: code.slot,
        id: [0; 16],
        expires: code.expires,
        bytes: vec![1],
    };
    let refused = home
        .call(&code.slot_key(), "put", stray.arguments())
        .answer::<u64>();
    assert_eq!(refused, Err(PersonalError::NotAdmitted));

    // The joiner reads the scope, and writes.
    install(&phones[1].light, NOTES);
    let caught = with(&mut home, &mut phones[1], &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert!(caught.alarms.is_empty(), "{:?}", caught.alarms);
    for key in 1..=3 {
        assert_eq!(count(&phones[1].light, NOTES, key), Some(key * 10));
    }
    set(&phones[1].light, NOTES, 4, 40);
    with(&mut home, &mut phones[1], &[NOTES], |sync| sync.push(NOTES)).unwrap();
    with(&mut home, &mut phones[0], &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert_eq!(count(&phones[0].light, NOTES, 4), Some(40));

    // Its enrollment in the club, held for the opener's prompt, and its
    // confirmation owed there.
    assert_eq!(enrollments.len(), 1);
    assert_eq!(enrollments[0].device, handle_of(2, &club()));
    assert_eq!(
        memberships::enrollments(&phones[0].store).unwrap(),
        enrollments
    );
    let call = enrollments[0].call(home.now() + 60_000).unwrap();
    assert_eq!(
        call.arguments,
        (handle_of(2, &club()).member, handle_of(2, &club()).owner).encode()
    );
    assert_eq!(call.method, vos_wire::credentials::method::ENROLL_DEVICE.0);
    memberships::done(&phones[0].store, &club()).unwrap();
    assert!(
        memberships::enrollments(&phones[0].store)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        memberships::confirmations(&phones[1].store).unwrap(),
        vec![club()]
    );
    memberships::confirmed(&phones[1].store, &club()).unwrap();
    assert!(
        memberships::confirmations(&phones[1].store)
            .unwrap()
            .is_empty()
    );

    // Neither claims a second agent: each holds the personal space's
    // archive.
    for phone in &phones {
        assert!(home::holds_archive(&phone.store).unwrap());
        assert!(matches!(
            Claim::prepare(
                &phone.store,
                phone.keys.clone(),
                vec![kit_key(5)],
                8,
                [0x08; 32],
                Vec::new()
            ),
            Err(ClaimError::Held)
        ));
    }
    assert!(!home::holds_archive(&Phone::new(9).store).unwrap());
}

/// Someone who photographed the QR and answered first: the opener's third
/// message ends the thief's handshake, which the user's new phone cannot
/// read, so it shows no check to match the opener's; and no side shows a
/// check before the third message, written after the second it answers,
/// so a second message is not ground to a check the new phone shows.
#[test]
fn a_qr_thief_answering_first_leaves_the_new_phone_no_check() {
    let (mut home, mut phones) = household(1);
    let offer = Offer {
        home: home_space(&home),
        memberships: Vec::new(),
    };
    let (mut side, qr) = open(&mut home, &mut phones[0], offer);
    let code = Code::from_bytes(&qr).unwrap();
    let (mut thief, stolen) = Joiner::scan(&code).unwrap();
    let (mut phone, _) = Joiner::scan(&code).unwrap();
    assert_eq!(
        (thief.check(), phone.check()),
        (None, None),
        "no check before the third"
    );
    leave(&mut home, &code.slot_key(), &stolen);
    let Opened::Check { check, put } = side.read(&inbox(&home, phones[0].sync_key())).unwrap()
    else {
        panic!("the thief's second message")
    };
    leave(&mut home, &phones[0].sync, &put);
    let slot = inbox(&home, code.slot_key().verifying_key().to_bytes());
    assert_eq!(phone.read(&slot).err(), Some(PairError::Handshake));
    assert_eq!(phone.check(), None, "the new phone shows no check");
    let Joined::Check(theirs) = thief.read(&slot).unwrap() else {
        panic!("the thief's check")
    };
    assert_eq!(theirs, check, "the opener's check is the thief's alone");
    // Declined, nothing more leaves: the thief reads no offer.
    assert!(matches!(thief.read(&slot).unwrap(), Joined::Waiting));
}

/// The handshake fails under a code that is not the QR's: the pre-shared
/// key enters at its last message, so the joiner cannot read it,
/// and the opener never hears a hello. An item the operators replace fails
/// at its reader, whichever side; and no step is taken out of turn.
#[test]
fn another_code_or_a_replaced_item_fails_the_handshake() {
    let (mut home, mut phones) = household(1);
    let offer = Offer {
        home: home_space(&home),
        memberships: Vec::new(),
    };
    let (mut side, qr) = open(&mut home, &mut phones[0], offer.clone());
    let mut code = Code::from_bytes(&qr).unwrap();
    code.code[0] ^= 1;
    let (mut joining, second) = Joiner::scan(&code).unwrap();
    leave(&mut home, &code.slot_key(), &second);
    let Opened::Check { put: third, .. } = side.read(&inbox(&home, phones[0].sync_key())).unwrap()
    else {
        panic!("the last message")
    };
    leave(&mut home, &phones[0].sync, &third);
    assert_eq!(
        joining
            .read(&inbox(&home, code.slot_key().verifying_key().to_bytes()))
            .err(),
        Some(PairError::Handshake),
        "the handshake does not end under another code"
    );
    assert!(matches!(
        side.read(&inbox(&home, phones[0].sync_key())).unwrap(),
        Opened::Waiting
    ));
    home.call(&phones[0].sync, "close_slot", side.slot().encode())
        .answer::<u64>()
        .unwrap();

    let offer_again = offer.clone();
    let (mut side, qr) = open(&mut home, &mut phones[0], offer);
    let code = Code::from_bytes(&qr).unwrap();
    assert!(Code::from_bytes(&qr[1..]).is_none(), "its version first");
    let (mut joining, second) = Joiner::scan(&code).unwrap();
    assert_eq!(
        joining
            .hello(&Hello {
                device: phones[0].keys.clone(),
                key_package: Vec::new(),
                handles: Vec::new(),
            })
            .err(),
        Some(PairError::Order)
    );
    let (mut joining, _) = Joiner::scan(&code).unwrap();
    leave(&mut home, &code.slot_key(), &second);
    let Opened::Check { put: third, .. } = side.read(&inbox(&home, phones[0].sync_key())).unwrap()
    else {
        panic!("the last message")
    };
    leave(&mut home, &phones[0].sync, &third);
    let mut served = inbox(&home, code.slot_key().verifying_key().to_bytes());
    for item in &mut served {
        if let Some(byte) = item.item.bytes.last_mut() {
            *byte ^= 1;
        }
    }
    assert_eq!(joining.read(&served).err(), Some(PairError::Handshake));
    home.call(&phones[0].sync, "close_slot", side.slot().encode())
        .answer::<u64>()
        .unwrap();

    // The joiner's message replaced, at the opener.
    let (mut side, qr) = open(&mut home, &mut phones[0], offer_again);
    let code = Code::from_bytes(&qr).unwrap();
    let (_, second) = Joiner::scan(&code).unwrap();
    leave(&mut home, &code.slot_key(), &second);
    let mut replaced = inbox(&home, phones[0].sync_key());
    replaced[0].item.bytes[40] ^= 1;
    assert_eq!(side.read(&replaced).err(), Some(PairError::Handshake));
}

/// The credential book installed on `light`, the club joined, and each
/// of `devices`' handle there as the registrar's person record holds it.
fn book(light: &vos_light::Light, devices: &[(u32, u8)]) {
    let book = crate::common::package(programs::program_elf("vos-credential-book"), 1);
    let outcome = light.install(BOOK, &book, Vec::new()).unwrap();
    assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
    let enrolled = Enrolled {
        name: "club".into(),
        credentials: Location {
            agent: club().agent,
            instance: club().credentials.0,
        },
        agents: vec![Agent {
            agent: club().agent,
            identity: club().identity,
        }],
    };
    let call = |method: &str, arguments: Vec<u8>| {
        let outcome = light.call(BOOK, crate::method(method), arguments).unwrap();
        assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
    };
    call("join", (CLUB, enrolled).encode());
    for (device, n) in devices {
        call("handle", (CLUB, *device, handle_of(*n, &club())).encode());
    }
}

/// A pairing cut short after the opener paired the joiner (the joiner
/// gone before its acknowledgement): the opener abandons the commit adding
/// it and closes the slot, holding no enrollment; the next pairing, from a
/// new slot, adds another device.
#[test]
fn a_pairing_cut_short_is_abandoned_and_paired_again() {
    let (mut home, mut phones) = household(1);
    let offer = Offer {
        home: home_space(&home),
        memberships: vec![club()],
    };
    let (mut side, qr) = open(&mut home, &mut phones[0], offer.clone());
    let code = Code::from_bytes(&qr).unwrap();
    let (mut joining, second) = Joiner::scan(&code).unwrap();
    leave(&mut home, &code.slot_key(), &second);
    let Opened::Check { put: third, .. } = opener_reads(&home, &phones[0], &mut side) else {
        panic!("the last message")
    };
    leave(&mut home, &phones[0].sync, &third);
    let Joined::Check(_) = joiner_reads(&home, &code, &mut joining) else {
        panic!("the check")
    };
    leave(&mut home, &phones[0].sync, &side.offer().unwrap());
    let Joined::Offer(offered) = joiner_reads(&home, &code, &mut joining) else {
        panic!("the offer")
    };
    let mut gone = Phone::new(2);
    let greeting = hello(&home, &mut gone, 2, &offered);
    leave(
        &mut home,
        &code.slot_key(),
        &joining.hello(&greeting).unwrap(),
    );
    let Opened::Hello(heard) = opener_reads(&home, &phones[0], &mut side) else {
        panic!("the hello")
    };
    let enrollments = memberships::plan(&offer.memberships, &heard);
    assert_eq!(enrollments.len(), 1);
    let (_, pairing) = phones[0]
        .group()
        .pair(heard.device, heard.key_package, home.now())
        .unwrap();
    for put in side.hand_over(&pairing).unwrap() {
        leave(&mut home, &phones[0].sync, &put);
    }
    // No acknowledgement comes.
    assert!(matches!(
        opener_reads(&home, &phones[0], &mut side),
        Opened::Waiting
    ));
    phones[0].group().abandon().unwrap();
    home.call(&phones[0].sync, "close_slot", side.slot().encode())
        .answer::<u64>()
        .unwrap();
    assert!(
        memberships::enrollments(&phones[0].store)
            .unwrap()
            .is_empty()
    );

    let mut joiner = Phone::new(3);
    pair(&mut home, &mut phones[0], &mut joiner, 3, offer);
    phones.push(joiner);
    settle(&mut home, &mut phones);
    assert_eq!(phones[1].group().id(), Some(1));
    assert_eq!(
        memberships::enrollments(&phones[0].store).unwrap()[0].device,
        handle_of(3, &club())
    );
}

/// A phone retired: the new phone paired from the old one, offered the
/// memberships the old one's handles name; then the old one removed by a
/// seasoned device (the new one in its probation, so the removal waits its
/// delay), carried by a commit, and the old phone, relayed the log, told
/// it is out (it offers to wipe itself); its leaves revoked in every space
/// the credential book holds a handle of it in.
#[test]
fn a_phone_is_retired_once_its_successor_is_paired() {
    let (mut home, mut phones) = household(2);
    home.pass(policy().seasoning_ms);
    for phone in &mut phones {
        phone.alive(&mut home);
    }
    book(&phones[0].light, &[(0, 1), (1, 2)]);

    let offered = memberships::handles_of(&phones[0].light, BOOK, 0).unwrap();
    assert_eq!(offered, vec![(club(), handle_of(1, &club()))]);
    let offer = Offer {
        home: home_space(&home),
        memberships: offered
            .into_iter()
            .map(|(membership, _)| membership)
            .collect(),
    };
    // The handover in items of 600 bytes: many, read across pages.
    let mut successor = Phone::new(3);
    pair_in(&mut home, &mut phones[0], &mut successor, 3, offer, 600);
    phones.push(successor);
    settle(&mut home, &mut phones);
    let id = phones[2].group().id().unwrap();
    memberships::record(&phones[0].light, BOOK, CLUB, id, handle_of(3, &club())).unwrap();
    assert_eq!(
        memberships::handles_of(&phones[0].light, BOOK, id).unwrap(),
        vec![(club(), handle_of(3, &club()))]
    );

    // Phone 1, seasoned, removes the old phone, 0.
    let reply = home.call(&phones[1].admin, "remove", 0u32.encode());
    let index = reply.answer::<Recorded>().unwrap().index;
    let attached = Attached {
        welcome: None,
        r2: None,
    };
    phones[1].evidence(&mut home, index, reply.message, reply.signature, attached);
    home.pass(policy().operation_delay_ms);
    phones[1].alive(&mut home);
    let events = phones[1].read(&mut home);
    assert!(
        !events.iter().any(|event| matches!(event, Event::Alarm(_))),
        "{events:?}"
    );
    let prepared = phones[1].group().commit(None, home.now()).unwrap();
    assert_eq!(prepared.effect.remove, vec![0]);
    phones[1].send(&mut home, &prepared).unwrap();
    let (old, rest) = phones.split_first_mut().unwrap();
    settle(&mut home, rest);
    let entries = home.log(rest[0].sync_key(), old.group().cursor()).unwrap();
    let events = old.group().follow(entries).unwrap();
    assert!(events.contains(&Event::Removed), "{events:?}");

    // Its leaves revoked in every space the book names a handle of it in,
    // by a remaining device's owner proof there.
    book(&rest[0].light, &[(0, 1), (1, 2), (id, 3)]);
    let revoked = memberships::handles_of(&rest[0].light, BOOK, 0).unwrap();
    assert_eq!(revoked, vec![(club(), handle_of(1, &club()))]);
    let (membership, handle) = &revoked[0];
    let call = memberships::revoke_call(membership, &handle.member, home.now() + 60_000).unwrap();
    assert_eq!(call.method, vos_wire::credentials::method::REVOKE_DEVICE.0);
    assert_eq!(call.arguments, handle_of(1, &club()).member.encode());
    assert_eq!(
        (call.space, call.agent, call.instance),
        (CLUB, club().agent, club().credentials.0)
    );
}

/// The claim with a phrase and a security key: held in the store across a
/// restart until the agent's log shows its assignment, then the device's
/// group starts with both kit keys and `R` the kit's; the recovery
/// envelopes it pushes open under that `R` with either kit's `R1`.
#[test]
fn a_claim_with_a_phrase_and_a_security_key_starts_the_group() {
    let mut home = Home::new(policy());
    let phone = Phone::new(1);
    let phrase = vos_light::kit::KitSecret::phrase().unwrap();
    let keys = vec![phrase.key(), kit_key(0)];
    let claim = Claim::prepare(
        &phone.store,
        phone.keys.clone(),
        keys.clone(),
        7,
        home.identity,
        Vec::new(),
    )
    .unwrap();
    assert!(matches!(
        Claim::prepare(
            &phone.store,
            phone.keys.clone(),
            keys.clone(),
            7,
            home.identity,
            Vec::new()
        ),
        Err(ClaimError::Held)
    ));
    assert!(matches!(
        Claim::prepare(
            &Phone::new(2).store,
            phone.keys.clone(),
            Vec::new(),
            7,
            home.identity,
            Vec::new()
        ),
        Err(ClaimError::Kit)
    ));
    let call = claim.call(&home_space(&home), home.now() + 60_000).unwrap();
    assert_eq!(call.method, vos_wire::homes::method::CLAIM.0);
    drop(claim);

    // Again after a restart, the same claim.
    let claim = Claim::pending(&phone.store).unwrap().expect("held");
    assert_eq!(claim.agent(), (7, home.identity));
    let call_again = claim.call(&home_space(&home), call.expires_ms).unwrap();
    assert_eq!(call_again.arguments, call.arguments, "the same claim again");
    let (device, kit, agent): (vos_wire::personal::NewDevice, vos_wire::personal::Kit, u32) =
        vos_abi::Decode::decode_exact(&call.arguments).unwrap();
    assert_eq!((device, agent), (phone.keys.clone(), 7));
    let early = home.log(phone.sync_key(), 0).unwrap_or_default();
    assert!(matches!(
        Claim::pending(&phone.store).unwrap().unwrap().claimed(
            &phone.store,
            PERSONAL,
            &early,
            home.now()
        ),
        Err(ClaimError::Unassigned)
    ));
    // The home assigns the agent, as `Homes`' claim does through
    // `Personal`.
    home.claim(&phone.keys, kit.clone());
    let entries = home.log(phone.sync_key(), 0).unwrap();
    let mut phone = phone;
    let group = claim
        .claimed(&phone.store, PERSONAL, &entries, home.now())
        .unwrap();
    assert!(Claim::pending(&phone.store).unwrap().is_none());
    assert!(group.holds_recovery());
    assert_eq!(group.kit(), &keys[..]);
    for (secret, entry) in [
        phrase,
        vos_light::kit::KitSecret::security_key(&mut crate::phone::Touch(0x4b)).unwrap(),
    ]
    .iter()
    .zip(&kit.entries)
    {
        let r1 = secret.open_r1(entry, &home.identity).expect("its R1 opens");
        let r = vos_light::kit::join(&r1, &kit.r2);
        assert_eq!(
            vos_wire::personal::r_hash(&r),
            vos_wire::personal::r_hash(
                group
                    .archive()
                    .recovery
                    .as_ref()
                    .map(|recovery| &recovery.r)
                    .unwrap()
            )
        );
    }
    phone.group = Some(group);
    phone.read(&mut home);
    assert_eq!(phone.group().id(), Some(0));
    assert!(home::holds_archive(&phone.store).unwrap());
}
