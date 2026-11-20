//! The device group (`light-node.md` §3.4) against `Personal` in a home:
//! phones paired and confirming one group, their keys and scope ids the
//! same; and the gate's adversaries, each a `light-node.md` §8 scenario:
//! a committer encrypting garbage to an awake device (A16) and to a
//! sleeping one, a commit that is no admin call (A23), operations and
//! commits without valid evidence (B6), two attackers removed by one
//! commit (A20, A21), every disallowed proposal (A17), and devices shown
//! different confirming sets (B4).

#[path = "../common/mod.rs"]
mod common;
mod garble;
mod home;
mod phone;
mod set;

use ed25519_dalek::{Signer, SigningKey};
use mls_rs::{ExtensionList, ProtocolVersion};
use vos_abi::Encode;
use vos_abi::ids::InstanceId;
use vos_light::group::{Alarm, Course, DeviceGroup, Event, Remedy, Why};
use vos_wire::personal::{
    Attached, Body, Effect, Entry, Overview, PersonalError, Policy, Recorded, Scope, Vote, chain,
    vote_message,
};

use garble::{Anything, hostile, leaf_key};
use home::Home;
use phone::Phone;

const MIN: u64 = 60_000;
/// A scope the phones seal under.
const NOTES: Scope = [0x6e; 16];

/// A test home's policy: minutes, not days.
fn policy() -> Policy {
    Policy {
        operation_delay_ms: 10 * MIN,
        kit_delay_ms: 20 * MIN,
        probation_ms: 5 * MIN,
        seasoning_ms: 10 * MIN,
        confirm_window_ms: 30 * MIN,
        ..Policy::DEFAULT
    }
}

fn homes() -> SigningKey {
    SigningKey::from_bytes(&[0x50; 32])
}

/// Read every phone, in turn, until none posts anything: each phone's
/// events.
fn settle(home: &mut Home, phones: &mut [&mut Phone]) -> Vec<Vec<Event>> {
    let mut events = vec![Vec::new(); phones.len()];
    for _ in 0..4 {
        for (at, phone) in phones.iter_mut().enumerate() {
            events[at].extend(phone.read(home));
        }
    }
    events
}

fn all(phones: &mut [Phone]) -> Vec<&mut Phone> {
    phones.iter_mut().collect()
}

/// A home claimed by phone 1 and `count - 1` more phones paired, each
/// confirmed by every phone and past its probation, each seen.
fn household(count: u8) -> (Home, Vec<Phone>) {
    let homes = homes();
    let mut home = Home::new(&homes, policy());
    let mut phones: Vec<Phone> = (1..=count).map(Phone::new).collect();
    phones[0].claim(&mut home, &homes);
    for n in 1..count as usize {
        let (paired, rest) = phones.split_at_mut(n);
        paired[0].pair(&mut home, &mut rest[0]);
        settle(&mut home, &mut all(&mut phones[..=n]));
        phones[n].alive(&mut home);
        assert_eq!(phones[n].group().id(), Some(n as u32));
    }
    home.pass(policy().probation_ms);
    for phone in &mut phones {
        phone.alive(&mut home);
    }
    (home, phones)
}

fn overview(home: &Home, phone: &Phone) -> Overview {
    home.query(phone.sync_key(), "overview", ().encode())
        .unwrap()
}

/// Every phone at `epoch`, with the same key for [`NOTES`].
fn agree(phones: &mut [&mut Phone], epoch: u64) -> [u8; 32] {
    let key = phones[0].group().key(NOTES).unwrap();
    for phone in phones.iter_mut() {
        assert_eq!(phone.group().confirmed(), epoch);
        assert_eq!(phone.group().key(NOTES).unwrap(), key);
    }
    key
}

/// The phones of a group confirm each commit: a pairing, then an update;
/// their keys, their scope ids (from the naming secret
/// the pairing carried) and their archives agree, the archive holding
/// every confirmed epoch's key of a tracked scope; a phone reopened while a
/// candidate is pending processes it again from the log; and a store that
/// named a scope already cannot join.
#[test]
fn paired_phones_confirm_one_group() {
    let (mut home, mut phones) = household(3);
    let first = agree(&mut all(&mut phones), 2);
    let instance = InstanceId(9);
    let scope = phones[0].light.scope_id(instance).unwrap();
    for phone in &phones {
        assert_eq!(phone.light.scope_id(instance).unwrap(), scope);
    }
    let stranger = Phone::new(40);
    assert_ne!(stranger.light.scope_id(instance).unwrap(), scope);
    let package = DeviceGroup::key_package(&stranger.store, &stranger.keys, home.now()).unwrap();
    let (_, pairing) = phones[0]
        .group()
        .pair(stranger.keys.clone(), package, home.now())
        .unwrap();
    assert!(matches!(
        DeviceGroup::join(&stranger.store, stranger.keys.clone(), pairing, Vec::new()),
        Err(vos_light::group::GroupError::Scoped)
    ));
    phones[0].group().abandon().unwrap();

    phones[1].update(&mut home).unwrap();
    phones[2].read(&mut home);
    phones[2].group = Some(DeviceGroup::open(&phones[2].store).unwrap().unwrap());
    let events = settle(&mut home, &mut all(&mut phones));
    for events in &events {
        assert!(
            events.contains(&Event::Confirmed { epoch: 3 }),
            "{events:?}"
        );
    }
    let second = agree(&mut all(&mut phones), 3);
    assert_ne!(first, second);
    for phone in &mut phones {
        let archive = phone.group().archive().clone();
        assert_eq!(archive.keys(2, &NOTES), &[first]);
        assert_eq!(archive.keys(3, &NOTES), &[second]);
        let key = phone.group().archive_key().unwrap();
        let sealed = archive.seal(&key, &[3; 24], b"agent");
        let opened = vos_light::group::Archive::open(&key, &[3; 24], b"agent", &sealed).unwrap();
        assert_eq!(opened, archive);
        assert!(vos_light::group::Archive::open(&key, &[3; 24], b"other", &sealed).is_none());
    }
    assert_eq!(overview(&home, &phones[0]).confirmed, 3);
}

/// The committer's evidence, signed by its admin key, posted under its
/// sync key: the evidence call `index`'s message and signature, and what
/// rides beside it.
fn evidence(
    home: &mut Home,
    phone: &Phone,
    index: u64,
    message: Vec<u8>,
    signature: [u8; 64],
    attached: Attached,
) {
    let reply = home.call(
        &phone.sync,
        "evidence",
        ((index, message), (signature, attached)).encode(),
    );
    reply.answer::<Recorded>().unwrap();
}

/// `phone`'s commit call of `handshake` for `epoch` declaring `effect`,
/// under its admin key, with its evidence: the candidate's log index.
fn commit_as(
    home: &mut Home,
    phone: &Phone,
    epoch: u64,
    effect: Effect,
    handshake: Vec<u8>,
    welcome: Option<Vec<u8>>,
) -> u64 {
    let attached = Attached { welcome, r2: None };
    commit_attaching(home, phone, epoch, effect, handshake, attached)
}

/// [`commit_as`] with `attached` beside the evidence.
fn commit_attaching(
    home: &mut Home,
    phone: &Phone,
    epoch: u64,
    effect: Effect,
    handshake: Vec<u8>,
    attached: Attached,
) -> u64 {
    let hash = attached
        .welcome
        .as_deref()
        .map(vos_wire::personal::welcome_hash);
    let reply = home.call(
        &phone.admin,
        "commit",
        ((epoch, effect), (handshake, hash)).encode(),
    );
    let index = reply
        .answer::<vos_wire::personal::Candidacy>()
        .unwrap()
        .index;
    evidence(home, phone, index, reply.message, reply.signature, attached);
    index
}

/// The candidate entry at `index`: its chain, which votes bind.
fn candidate_chain(home: &Home, phone: &Phone, index: u64) -> [u8; 32] {
    let entries = home.log(phone.sync_key(), index).unwrap();
    entries[0].1.chain
}

/// A confirmation of `epoch`'s candidate at `index` with `h`, as a hostile
/// committer signs its own with the sync key it holds.
fn confirm_as(home: &mut Home, phone: &Phone, epoch: u64, index: u64, h: [u8; 32]) {
    let chain = candidate_chain(home, phone, index);
    let message = vote_message(&home::IDENTITY, epoch, index, &chain, &Vote::Confirm(h));
    let signature = phone.sync.sign(&message).to_bytes();
    home.call(&phone.sync, "confirm", (epoch, h, signature).encode());
}

/// A16, the gate: a committer who passed the owner's biometric commits an
/// update whose path secrets reach one awake device as garbage. That
/// device cannot process it and nacks; the epoch is void on every device,
/// nothing is sealed to one side alone: each phone's data key is the
/// confirmed epoch's, the same on both sides.
#[test]
fn garbage_to_an_awake_device_is_nacked_and_seals_nothing() {
    let (mut home, mut phones) = household(3);
    let before = agree(&mut all(&mut phones), 2);
    let mut attacker = {
        let spare = {
            let group = hostile(
                &phones[0].store,
                None,
                Anything {
                    path: true,
                    encrypt: true,
                },
            );
            vec![leaf_key(
                &group,
                &vos_light::group::credential(&phones[1].keys),
            )]
        };
        hostile(
            &phones[0].store,
            Some(spare),
            Anything {
                path: true,
                encrypt: true,
            },
        )
    };
    let output = attacker.commit_builder().build().unwrap();
    let handshake = output.commit_message.to_bytes().unwrap();
    attacker.apply_pending_commit().unwrap();
    let index = commit_as(&mut home, &phones[0], 3, Effect::default(), handshake, None);
    let authenticator = attacker.epoch_authenticator().unwrap().to_vec();
    let h = vos_mls::confirmation(
        vos_light::group::CONFIRM,
        &home::IDENTITY,
        3,
        &authenticator,
    );
    confirm_as(&mut home, &phones[0], 3, index, h);

    let (_, honest) = phones.split_at_mut(1);
    let events = settle(&mut home, &mut all(honest));
    assert!(
        events[1].contains(&Event::Alarm(Alarm::Refused {
            epoch: 3,
            committer: 0
        })),
        "{:?}",
        events[1]
    );
    for events in &events {
        assert!(
            events.contains(&Event::Voided {
                epoch: 3,
                committer: 0,
                why: Why::Nack(2),
            }),
            "{events:?}"
        );
    }
    assert_eq!(agree(&mut all(honest), 2), before);
    assert_eq!(overview(&home, &phones[1]).confirmed, 2);
}

/// A16 asleep: the garbage reaches a device outside the confirming set,
/// so the awake devices confirm without it; on its return it cannot follow
/// the confirmed epoch, raises the alarm naming the committer, and re-pairs
/// from the other live device, as a new device holding every key again.
/// With no other live device to pair from, its remedy is a regroup.
#[test]
fn garbage_to_a_sleeping_device_alarms_on_its_return_and_it_re_pairs() {
    let (mut home, mut phones) = household(3);
    agree(&mut all(&mut phones), 2);
    home.pass(policy().confirm_window_ms + 1);
    phones[0].alive(&mut home);
    phones[1].alive(&mut home);
    let spare = {
        let group = hostile(
            &phones[0].store,
            None,
            Anything {
                path: true,
                encrypt: true,
            },
        );
        vec![leaf_key(
            &group,
            &vos_light::group::credential(&phones[1].keys),
        )]
    };
    let mut attacker = hostile(
        &phones[0].store,
        Some(spare),
        Anything {
            path: true,
            encrypt: true,
        },
    );
    let output = attacker.commit_builder().build().unwrap();
    let handshake = output.commit_message.to_bytes().unwrap();
    attacker.apply_pending_commit().unwrap();
    let index = commit_as(&mut home, &phones[0], 3, Effect::default(), handshake, None);
    let h = vos_mls::confirmation(
        vos_light::group::CONFIRM,
        &home::IDENTITY,
        3,
        &attacker.epoch_authenticator().unwrap(),
    );
    confirm_as(&mut home, &phones[0], 3, index, h);
    let events = phones[1].read(&mut home);
    assert!(
        events.contains(&Event::Confirmed { epoch: 3 }),
        "{events:?}"
    );

    let events = phones[2].read(&mut home);
    assert!(
        events.contains(&Event::Alarm(Alarm::CannotFollow {
            epoch: 3,
            committer: 0,
            remedy: Remedy::RePair,
        })),
        "{events:?}"
    );
    assert_eq!(
        phones[2].group().course(),
        Course::Stuck {
            epoch: 3,
            committer: 0
        }
    );
    assert!(phones[2].group().commit(None, home.now()).is_err());

    // The committer goes quiet; the sleeper re-pairs from the other phone
    // as a new device.
    home.pass(policy().confirm_window_ms + 1);
    phones[1].alive(&mut home);
    let mut again = Phone::new(23);
    phones[1].pair(&mut home, &mut again);
    let events = settle(&mut home, &mut [&mut phones[1], &mut again]);
    assert!(
        events[1].contains(&Event::Confirmed { epoch: 4 }),
        "{:?}",
        events[1]
    );
    let key = phones[1].group().key(NOTES).unwrap();
    assert_eq!(again.group().key(NOTES).unwrap(), key);
    let archive = again.group().archive().clone();
    assert!(
        !archive.keys(2, &NOTES).is_empty(),
        "the pairing carried the archive"
    );

    // Two phones, the other one the committer: nothing to pair from.
    let (mut home, mut phones) = household(2);
    home.pass(policy().confirm_window_ms + 1);
    phones[0].alive(&mut home);
    let mut attacker = hostile(
        &phones[0].store,
        Some(Vec::new()),
        Anything {
            path: true,
            encrypt: true,
        },
    );
    let output = attacker.commit_builder().build().unwrap();
    let handshake = output.commit_message.to_bytes().unwrap();
    attacker.apply_pending_commit().unwrap();
    let index = commit_as(&mut home, &phones[0], 2, Effect::default(), handshake, None);
    let h = vos_mls::confirmation(
        vos_light::group::CONFIRM,
        &home::IDENTITY,
        2,
        &attacker.epoch_authenticator().unwrap(),
    );
    confirm_as(&mut home, &phones[0], 2, index, h);
    let events = phones[1].read(&mut home);
    assert!(
        events.contains(&Event::Alarm(Alarm::CannotFollow {
            epoch: 2,
            committer: 0,
            remedy: Remedy::Regroup,
        })),
        "{events:?}"
    );
}

/// A23, the gate: a commit is an admin call; one made under a sync key is
/// refused by the agent and moves nothing, as is one from a device in
/// probation; the device abandons its held commit and commits again.
#[test]
fn a_commit_that_is_not_an_admin_call_is_refused() {
    let (mut home, mut phones) = household(2);
    let prepared = phones[1].group().commit(None, home.now()).unwrap();
    let reply = home.call(&phones[1].sync, "commit", prepared.arguments());
    assert_eq!(
        reply.answer::<vos_wire::personal::Candidacy>(),
        Err(PersonalError::SyncKey)
    );
    phones[1].group().abandon().unwrap();
    assert_eq!(overview(&home, &phones[0]).candidate, None);
    let events = settle(&mut home, &mut all(&mut phones));
    assert!(
        events
            .iter()
            .flatten()
            .all(|event| !matches!(event, Event::Confirmed { .. }))
    );
    agree(&mut all(&mut phones), 1);

    let mut newest = Phone::new(3);
    phones[0].pair(&mut home, &mut newest);
    let [first, second] = phones.get_disjoint_mut([0, 1]).unwrap();
    settle(&mut home, &mut [first, second, &mut newest]);
    newest.alive(&mut home);
    assert_eq!(newest.update(&mut home), Err(PersonalError::Probation));
    assert!(!newest.group().pending());

    phones[1].update(&mut home).unwrap();
    let [first, second] = phones.get_disjoint_mut([0, 1]).unwrap();
    let events = settle(&mut home, &mut [first, second, &mut newest]);
    for events in &events {
        assert!(
            events.contains(&Event::Confirmed { epoch: 3 }),
            "{events:?}"
        );
    }
}

/// B6, the gate: an operation or a commit without valid evidence moves no
/// device. A commit whose evidence never comes is voted on by nobody and
/// voids at the window's end; one whose evidence does not verify is
/// nacked; a removal whose evidence does not verify is no matured
/// operation: the honest committer does not carry it, and a commit that
/// carries it is nacked, the target still in the group.
#[test]
fn without_valid_evidence_no_device_moves() {
    let (mut home, mut phones) = household(3);
    let prepared = phones[0].group().commit(None, home.now()).unwrap();
    let reply = home.call(&phones[0].admin, "commit", prepared.arguments());
    reply.answer::<vos_wire::personal::Candidacy>().unwrap();
    let (_, others) = phones.split_at_mut(1);
    let events = settle(&mut home, &mut all(others));
    assert!(
        events
            .iter()
            .flatten()
            .all(|event| !matches!(event, Event::Confirmed { .. }))
    );
    home.pass(policy().confirm_window_ms);
    others[0].alive(&mut home);
    let events = settle(&mut home, &mut all(others));
    for events in &events {
        assert!(
            events.contains(&Event::Voided {
                epoch: 3,
                committer: 0,
                why: Why::Timeout
            }),
            "{events:?}"
        );
    }
    let events = phones[0].read(&mut home);
    assert!(events.contains(&Event::Voided {
        epoch: 3,
        committer: 0,
        why: Why::Timeout
    }));
    for phone in &mut phones {
        phone.alive(&mut home);
    }

    // Evidence that does not verify: its signature forged.
    let prepared = phones[0].group().commit(None, home.now()).unwrap();
    let reply = home.call(&phones[0].admin, "commit", prepared.arguments());
    let index = reply
        .answer::<vos_wire::personal::Candidacy>()
        .unwrap()
        .index;
    evidence(
        &mut home,
        &phones[0],
        index,
        reply.message,
        [0x5a; 64],
        Attached::default(),
    );
    let (_, others) = phones.split_at_mut(1);
    let events = settle(&mut home, &mut all(others));
    for events in &events {
        assert!(
            events.contains(&Event::Alarm(Alarm::Refused {
                epoch: 3,
                committer: 0
            })),
            "{events:?}"
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Event::Voided { epoch: 3, .. })),
            "{events:?}"
        );
    }
    phones[0].read(&mut home);
    agree(&mut all(&mut phones), 2);

    // A removal of phone 3 whose evidence is forged.
    let reply = home.call(&phones[0].admin, "remove", 2u32.encode());
    let index = reply.answer::<Recorded>().unwrap().index;
    evidence(
        &mut home,
        &phones[0],
        index,
        reply.message,
        [0x5a; 64],
        Attached::default(),
    );
    home.pass(policy().operation_delay_ms);
    phones[0].alive(&mut home);
    phones[1].alive(&mut home);
    settle(&mut home, &mut all(&mut phones[..2]));
    assert_eq!(
        phones[0].update(&mut home),
        Err(PersonalError::MissingRemoval(2)),
        "the honest committer carries no removal it cannot verify"
    );
    let removes = [vos_light::group::credential(&phones[2].keys)];
    let mut attacker = hostile(
        &phones[0].store,
        None,
        Anything {
            path: true,
            encrypt: true,
        },
    );
    let mut builder = attacker.commit_builder();
    let leaf = attacker_leaf(&attacker_roster(&phones[0].store), &removes[0]);
    builder = builder.remove_member(leaf).unwrap();
    let output = builder.build().unwrap();
    drop(attacker);
    let rekey = vos_light::kit::Split::draw(&[phone::kit_key(0)], &home.identity).unwrap();
    let effect = Effect {
        add: None,
        remove: vec![2],
        rekey: Some(rekey.kit.clone()),
    };
    commit_attaching(
        &mut home,
        &phones[0],
        3,
        effect,
        output.commit_message.to_bytes().unwrap(),
        Attached {
            welcome: None,
            r2: Some(*rekey.r2()),
        },
    );
    let events = phones[1].read(&mut home);
    assert!(
        events.contains(&Event::Alarm(Alarm::Refused {
            epoch: 3,
            committer: 0
        })),
        "{events:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::Voided { epoch: 3, .. })),
        "{events:?}"
    );
    assert_eq!(phones[1].group().confirmed(), 2);
}

/// The credentials of the group in `store`, by leaf.
fn attacker_roster(store: &vos_light::Store) -> Vec<(u32, Vec<u8>)> {
    let group = hostile(
        store,
        None,
        Anything {
            path: true,
            encrypt: true,
        },
    );
    group
        .roster()
        .members_iter()
        .map(|member| {
            let basic = member.signing_identity.credential.as_basic().unwrap();
            (member.index, basic.identifier.clone())
        })
        .collect()
}

fn attacker_leaf(roster: &[(u32, Vec<u8>)], credential: &[u8]) -> u32 {
    roster
        .iter()
        .find(|(_, member)| member == credential)
        .map(|(leaf, _)| *leaf)
        .unwrap()
}

/// `phone`'s removal of `target`, an admin call, and its evidence.
fn remove(home: &mut Home, phone: &Phone, target: u32) {
    let reply = home.call(&phone.admin, "remove", target.encode());
    let index = reply.answer::<Recorded>().unwrap().index;
    evidence(
        home,
        phone,
        index,
        reply.message,
        reply.signature,
        Attached::default(),
    );
}

/// A20 and A21, the gate: two attacker devices nack every commit, which
/// stalls key changes and not data, the committer's own commit voided and
/// deleted; once their removals mature they have no voice, and one commit
/// carries both removals, their nacks refused.
#[test]
fn two_attacker_devices_are_removed_by_one_commit() {
    let (mut home, mut phones) = household(4);
    remove(&mut home, &phones[0], 2);
    remove(&mut home, &phones[0], 3);
    phones[0].update(&mut home).unwrap();
    let (owners, attackers) = phones.split_at_mut(2);
    for attacker in attackers.iter_mut() {
        let cursor = attacker.group().cursor();
        let entries = home.log(attacker.sync_key(), cursor).unwrap();
        let (index, candidate) = entries
            .iter()
            .rev()
            .find(|(_, entry)| matches!(entry.body, Body::Candidate { .. }))
            .cloned()
            .unwrap();
        let events = attacker.group().follow(entries).unwrap();
        for event in events {
            if let Event::Vote { epoch, .. } = event {
                let nack =
                    vote_message(&home::IDENTITY, epoch, index, &candidate.chain, &Vote::Nack);
                attacker.vote(&mut home, epoch, Vote::Nack, &nack);
            }
        }
    }
    let events = settle(&mut home, &mut all(owners));
    for events in &events {
        assert!(
            events.iter().any(|event| matches!(
                event,
                Event::Voided {
                    epoch: 4,
                    why: Why::Nack(2 | 3),
                    ..
                }
            )),
            "{events:?}"
        );
    }
    assert!(
        !owners[0].group().pending(),
        "the committer's own commit is deleted"
    );
    agree(&mut all(owners), 3);

    home.pass(policy().operation_delay_ms);
    owners[0].alive(&mut home);
    owners[1].alive(&mut home);
    for attacker in attackers.iter_mut() {
        assert_eq!(
            home.log(attacker.sync_key(), 0).map(|_| ()),
            Err(PersonalError::NotAdmitted),
            "the agent refuses a matured removal's keys"
        );
        let signature = attacker.sync.sign(b"nack").to_bytes();
        let reply = home.call(&attacker.sync, "nack", (3u64, signature).encode());
        assert_eq!(
            reply.answer::<vos_wire::personal::Voted>(),
            Err(PersonalError::NotAdmitted)
        );
    }
    settle(&mut home, &mut all(owners));
    let candidacy = owners[0].update(&mut home).unwrap();
    assert_eq!(candidacy.set, vec![0, 1]);
    let events = settle(&mut home, &mut all(owners));
    for events in &events {
        assert!(
            events.contains(&Event::Confirmed { epoch: 4 }),
            "{events:?}"
        );
    }
    agree(&mut all(owners), 4);
}

/// A17, the gate: every commit the device group does not allow is nacked
/// by every device that processes it, each epoch void: a group-context
/// change, a ReInit, a handshake in the clear, an external commit, an add
/// without a path, a removal the log does not declare, an add of another
/// device than the matured operation's, and an update changing its leaf's
/// keys. PSK and by-reference proposals are not compiled into the build.
#[test]
fn every_disallowed_proposal_is_nacked() {
    let (mut home, mut phones) = household(3);
    let mut stranger = Phone::new(30);
    let package = DeviceGroup::key_package(&stranger.store, &stranger.keys, home.now()).unwrap();
    let other = Phone::new(31);
    let other_package = DeviceGroup::key_package(&other.store, &other.keys, home.now()).unwrap();
    let suite = vos_mls::SUITE;
    let encrypted = Anything {
        path: true,
        encrypt: true,
    };
    let third = vos_light::group::credential(&phones[2].keys);

    let disallowed: Vec<(&str, Effect, Vec<u8>)> = vec![
        ("group context", Effect::default(), {
            let mut group = hostile(&phones[0].store, None, encrypted);
            let output = group
                .commit_builder()
                .set_group_context_ext(ExtensionList::new())
                .unwrap()
                .build()
                .unwrap();
            output.commit_message.to_bytes().unwrap()
        }),
        ("reinit", Effect::default(), {
            let mut group = hostile(&phones[0].store, None, encrypted);
            let output = group
                .commit_builder()
                .reinit(None, ProtocolVersion::MLS_10, suite, ExtensionList::new())
                .unwrap()
                .build()
                .unwrap();
            output.commit_message.to_bytes().unwrap()
        }),
        ("in the clear", Effect::default(), {
            let mut group = hostile(
                &phones[0].store,
                None,
                Anything {
                    path: true,
                    encrypt: false,
                },
            );
            group
                .commit_builder()
                .build()
                .unwrap()
                .commit_message
                .to_bytes()
                .unwrap()
        }),
        ("external", Effect::default(), {
            let group = hostile(&phones[0].store, None, encrypted);
            let info = group.group_info_message_allowing_ext_commit(true).unwrap();
            external_commit(&mut stranger, info)
        }),
        (
            "add without a path",
            Effect {
                add: Some(stranger.keys.clone()),
                ..Effect::default()
            },
            {
                let mut group = hostile(
                    &phones[0].store,
                    None,
                    Anything {
                        path: false,
                        encrypt: true,
                    },
                );
                let message = mls_rs::MlsMessage::from_bytes(&package).unwrap();
                let output = group
                    .commit_builder()
                    .add_member(message)
                    .unwrap()
                    .build()
                    .unwrap();
                output.commit_message.to_bytes().unwrap()
            },
        ),
        ("an undeclared removal", Effect::default(), {
            let roster = attacker_roster(&phones[0].store);
            let mut group = hostile(&phones[0].store, None, encrypted);
            let leaf = attacker_leaf(&roster, &third);
            let output = group
                .commit_builder()
                .remove_member(leaf)
                .unwrap()
                .build()
                .unwrap();
            output.commit_message.to_bytes().unwrap()
        }),
        ("a leaf's keys changed by its update", Effect::default(), {
            use mls_rs::CipherSuiteProvider;
            use mls_rs::CryptoProvider;
            let mut group = hostile(&phones[0].store, None, encrypted);
            let crypto = mls_rs_crypto_rustcrypto::RustCryptoProvider::default();
            let suite = crypto.cipher_suite_provider(vos_mls::SUITE).unwrap();
            let (secret, public) = suite.signature_key_generate().unwrap();
            let mut keys = phones[0].keys.clone();
            keys.admin = [0xad; 32];
            let credential =
                mls_rs::identity::basic::BasicCredential::new(vos_light::group::credential(&keys));
            let identity =
                mls_rs::identity::SigningIdentity::new(credential.into_credential(), public);
            let output = group
                .commit_builder()
                .set_new_signing_identity(secret, identity)
                .build()
                .unwrap();
            output.commit_message.to_bytes().unwrap()
        }),
        (
            "another device's add",
            Effect {
                add: Some(stranger.keys.clone()),
                ..Effect::default()
            },
            {
                let mut group = hostile(&phones[0].store, None, encrypted);
                let message = mls_rs::MlsMessage::from_bytes(&other_package).unwrap();
                let output = group
                    .commit_builder()
                    .add_member(message)
                    .unwrap()
                    .build()
                    .unwrap();
                output.commit_message.to_bytes().unwrap()
            },
        ),
    ];
    for (what, effect, handshake) in disallowed {
        commit_as(&mut home, &phones[0], 3, effect, handshake, None);
        let (_, honest) = phones.split_at_mut(1);
        let events = settle(&mut home, &mut all(honest));
        for events in &events {
            assert!(
                events.contains(&Event::Alarm(Alarm::Refused {
                    epoch: 3,
                    committer: 0
                })),
                "{what}: {events:?}"
            );
            assert!(
                events.iter().any(|event| matches!(
                    event,
                    Event::Voided {
                        epoch: 3,
                        why: Why::Nack(_),
                        ..
                    }
                )),
                "{what}: {events:?}"
            );
        }
        phones[0].read(&mut home);
        agree(&mut all(&mut phones), 2);
    }
}

/// An external commit by a client of `stranger`'s, joining by `info`.
fn external_commit(stranger: &mut Phone, info: mls_rs::MlsMessage) -> Vec<u8> {
    use mls_rs::CipherSuiteProvider;
    use mls_rs::CryptoProvider;
    let crypto = mls_rs_crypto_rustcrypto::RustCryptoProvider::default();
    let suite = crypto.cipher_suite_provider(vos_mls::SUITE).unwrap();
    let (secret, public) = suite.signature_key_generate().unwrap();
    let credential =
        mls_rs::identity::basic::BasicCredential::new(vos_light::group::credential(&stranger.keys));
    let identity = mls_rs::identity::SigningIdentity::new(credential.into_credential(), public);
    let client = mls_rs::Client::builder()
        .identity_provider(vos_mls::Identity::default())
        .crypto_provider(crypto)
        .mls_rules(Anything {
            path: true,
            encrypt: true,
        })
        .signing_identity(identity, secret, vos_mls::SUITE)
        .build();
    let (_, message) = client
        .external_commit_builder()
        .unwrap()
        .build(info)
        .unwrap();
    message.to_bytes().unwrap()
}

/// `entries` of the log as operators who rewrite the candidate's set show
/// them, `edit` applied to every candidate entry and each chain linked
/// again from `before`.
fn forged(
    entries: Vec<(u64, Entry)>,
    mut before: [u8; 32],
    edit: impl Fn(&mut Vec<u32>),
) -> Vec<(u64, Entry)> {
    entries
        .into_iter()
        .map(|(index, mut entry)| {
            if let Body::Candidate { set, .. } = &mut entry.body {
                edit(set);
            }
            entry.chain = chain(&before, index, entry.at, &entry.body);
            before = entry.chain;
            (index, entry)
        })
        .collect()
}

/// `phone` reading the log as the operators show it, posting its votes.
fn read_forged(home: &mut Home, phone: &mut Phone, edit: impl Fn(&mut Vec<u32>)) -> Vec<Event> {
    let (cursor, before) = phone.group().view();
    let entries = forged(home.log(phone.sync_key(), cursor).unwrap(), before, edit);
    let mut seen = Vec::new();
    for event in phone.group().follow(entries).unwrap() {
        match event {
            Event::Vote {
                epoch,
                vote,
                message,
            } => phone.vote(home, epoch, vote, &message),
            other => seen.push(other),
        }
    }
    seen
}

/// B4, the gate: operators show two devices different confirming sets.
/// Each vote binds the log its voter read, so the votes of a device shown
/// the other log do not verify: every device raises the split-log alarm,
/// and none confirms, whatever the agent's verdict. A device the forged log
/// names absent though it called within the window raises that alarm.
#[test]
fn different_confirming_sets_raise_the_split_log_alarm() {
    let (mut home, mut phones) = household(3);
    phones[0].update(&mut home).unwrap();
    let without_third = |set: &mut Vec<u32>| set.retain(|device| *device != 2);
    let shown = read_forged(&mut home, &mut phones[1], without_third);
    assert!(shown.is_empty(), "{shown:?}");
    let events = phones[0].read(&mut home);
    assert!(
        events.contains(&Event::Alarm(Alarm::SplitLog {
            epoch: 3,
            device: 1
        })),
        "{events:?}"
    );
    let events = phones[2].read(&mut home);
    assert!(
        events.contains(&Event::Alarm(Alarm::SplitLog {
            epoch: 3,
            device: 1
        })),
        "{events:?}"
    );
    let shown = read_forged(&mut home, &mut phones[1], without_third);
    assert!(
        shown.contains(&Event::Alarm(Alarm::SplitLog {
            epoch: 3,
            device: 0
        })),
        "{shown:?}"
    );
    // The agent counts votes it does not verify: its verdict is not the
    // devices', which stay at the epoch they confirmed.
    let events = phones[0].read(&mut home);
    assert!(
        events.contains(&Event::Alarm(Alarm::Verdict { epoch: 3 })),
        "{events:?}"
    );
    for phone in &mut phones {
        assert_eq!(phone.group().confirmed(), 2);
    }

    // Named absent.
    let (mut home, mut phones) = household(2);
    phones[0].update(&mut home).unwrap();
    let without_second = |set: &mut Vec<u32>| set.retain(|device| *device != 1);
    let shown = read_forged(&mut home, &mut phones[1], without_second);
    assert!(
        shown
            .iter()
            .any(|event| matches!(event, Event::Alarm(Alarm::NamedAbsent { epoch: 2, .. }))),
        "{shown:?}"
    );
}

/// B6 for maturity: operators append a maturity that no signed removal
/// supports, which would silence a device's votes. The device ignores it
/// with the alarm; and the entry forks its log from the agent's, so its
/// next reading stops where the agent's entries no longer chain.
#[test]
fn a_maturity_no_signed_removal_supports_is_ignored() {
    let (mut home, mut phones) = household(3);
    let (cursor, before) = phones[1].group().view();
    let mut entries = home.log(phones[1].sync_key(), cursor).unwrap();
    let index = cursor + entries.len() as u64;
    let last = entries.last().map_or(before, |(_, entry)| entry.chain);
    let body = Body::Matured { device: 2 };
    entries.push((
        index,
        Entry {
            at: home.now(),
            chain: chain(&last, index, home.now(), &body),
            body,
        },
    ));
    let events = phones[1].group().follow(entries).unwrap();
    assert!(
        events.contains(&Event::Alarm(Alarm::Unsigned { index })),
        "{events:?}"
    );
    phones[0].update(&mut home).unwrap();
    let events = phones[1].read(&mut home);
    assert!(
        events.contains(&Event::Alarm(Alarm::Log { index: index + 1 })),
        "{events:?}"
    );
}
