//! Local actors on the light node, installed from release artifacts: their
//! merge handlers' operations recorded as signed nodes and their merge
//! fields read by queries, kept across a reopen; what the merge entry
//! refuses; and two devices exchanging their nodes and converging, an
//! equivocating author and a removed one filtered at read.

mod common;

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use vos_abi::abi::Failure;
use vos_abi::ids::{InstanceId, MethodId};
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode};
use vos_light::release::{self, Package};
use vos_light::sync::{Call, Hold, Op};
use vos_light::{Config, Error, Light};
use vos_testkit::programs;

use common::device::{Device, cid, node, open};

const NOTES: InstanceId = InstanceId(1);

fn method(package: &Package, name: &str) -> MethodId {
    programs::method(&package.programs[0], name)
}

/// What every read of `device` sees.
fn state(device: &Device) -> State {
    State {
        tags: device.query("tags", Vec::new()),
        items: device.query("items", Vec::new()),
        titles: device.query("titles", Vec::new()),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct State {
    tags: Vec<String>,
    items: Vec<u64>,
    titles: Vec<(u64, String)>,
}

/// A light node opens with an agent program up to the Gray Paper's bound
/// on a service's code, 4,000,000 bytes, its whole blob counted, and
/// refuses one a byte past it.
#[test]
fn the_agent_program_is_held_to_the_service_code_bound() {
    for (len, fits) in [(4_000_000, true), (4_000_001, false)] {
        let dir = tempfile::tempdir().unwrap();
        let opened = Light::open(dir.path(), &programs::sized(len), Config::default());
        match opened {
            Ok(_) => assert!(fits, "{len} bytes"),
            Err(Error::Fault(fault)) => {
                assert!(!fits, "{len} bytes");
                assert_eq!(
                    fault.message(),
                    "the agent is past the service-code bound (W_C)"
                );
            }
            Err(error) => panic!("{len} bytes: {error:?}"),
        }
    }
}

/// The artifacts round-trip as the app embeds them, and install: the notes
/// actor's merge handlers write its fields, its queries read them, and the
/// light node opened again holds it all, its programs pooled from the
/// store, its author the same.
#[test]
fn a_local_actor_installed_from_release_artifacts_is_called() {
    let (agent, notes) = (common::agent(), common::notes());
    // As `vos-phone`'s build script encodes a package: its derivation, its
    // programs, then its release.
    let bytes = (notes.derivation.clone(), notes.programs.clone(), 1u32).encode();
    assert_eq!(bytes, notes.encode());
    let embedded = Package::decode_exact(&bytes).unwrap();
    assert_eq!(embedded, *notes);
    let dir = tempfile::tempdir().unwrap();
    let author = {
        let light = open(dir.path(), agent, Config::default());
        let device = Device::over(light, NOTES, embedded.clone());
        let installed = device.light.install(NOTES, &embedded, Vec::new()).unwrap();
        assert!(matches!(installed, Outcome::Done(_)), "{installed:?}");
        device.done("tag", "home".to_string().encode());
        device.done("tag", "work".to_string().encode());
        device.done("tag", "home".to_string().encode());
        for item in [3u64, 1, 2] {
            device.done("add", item.encode());
        }
        device.done("remove", 1u64.encode());
        device.done("title", (7u64, "seven".to_string()).encode());
        device.done("title", (7u64, "SEVEN".to_string()).encode());
        device.done("title", (8u64, "eight".to_string()).encode());
        device.done("untitle", 8u64.encode());
        device.done("churn", 9u64.encode());
        assert!(device.query::<bool>("has_tag", "work".to_string().encode()));
        assert!(!device.query::<bool>("has", 1u64.encode()));
        assert_eq!(
            device.query::<Option<String>>("title_of", 7u64.encode()),
            Some("SEVEN".into())
        );
        assert_eq!(
            device.query::<Option<String>>("title_of", 8u64.encode()),
            None
        );
        assert_eq!(device.light.outbox(NOTES).unwrap().len(), 12);
        device.light.author()
    };
    let light = open(dir.path(), agent, Config::default());
    assert_eq!(light.author(), author);
    let device = Device::over(light, NOTES, notes.clone());
    let mut items: Vec<u64> = device.query("items", Vec::new());
    items.sort();
    assert_eq!(items, [2, 3, 9]);
    let mut tags: Vec<String> = device.query("tags", Vec::new());
    tags.sort();
    assert_eq!(tags, ["home", "work"]);
    assert_eq!(
        device.query::<Vec<(u64, String)>>("titles", Vec::new()),
        [(7, "SEVEN".to_string())]
    );
    device.done("add", 1u64.encode());
    assert!(device.query::<bool>("has", 1u64.encode()));
    assert_eq!(device.light.have(NOTES).unwrap()[&author], 12);
}

/// Only merge handlers run on the merge entry, and they write merge fields
/// alone: a command is `Unknown`; a merge handler that reads a merge field
/// or writes a table traps; one that fails declines; none of them records
/// a node or writes a row. A package whose programs are not its
/// derivation's, or another transpiler's, installs nothing, and nodes of
/// an instance not installed are refused.
#[test]
fn the_merge_entry_runs_merge_handlers_writing_merge_fields() {
    let (agent, notes) = (common::agent(), common::notes());
    let dir = tempfile::tempdir().unwrap();
    let light = open(dir.path(), agent, Config::default());
    let mut forged = notes.clone();
    forged.programs[0].push(0);
    assert!(matches!(
        light.install(NOTES, &forged, Vec::new()),
        Err(Error::Package)
    ));
    let mut other = notes.clone();
    other.derivation.transpiler += 1;
    assert!(matches!(
        light.install(NOTES, &other, Vec::new()),
        Err(Error::Transpiler(version)) if version == release::TRANSPILER + 1
    ));
    assert!(matches!(
        light.ingest(NOTES, Vec::new(), None),
        Err(Error::NotInstalled)
    ));
    light.install(NOTES, notes, Vec::new()).unwrap();
    let device = Device::over(light, NOTES, notes.clone());
    device.done("add", 5u64.encode());
    let rows = device.light.store().rows().unwrap();
    let failed = |outcome: Outcome, expected: Failure| match outcome {
        Outcome::Failed { code, .. } => assert_eq!(code, expected),
        other => panic!("{other:?}"),
    };
    failed(
        device.call("bump", 1u64.encode()).unwrap(),
        Failure::Unknown,
    );
    failed(
        device.call("peek", 6u64.encode()).unwrap(),
        Failure::Trapped,
    );
    failed(
        device.call("scribble", 1u64.encode()).unwrap(),
        Failure::Trapped,
    );
    failed(
        device.call("refuse", 6u64.encode()).unwrap(),
        Failure::Handler,
    );
    assert_eq!(
        device.light.store().rows().unwrap(),
        rows,
        "a declined call wrote"
    );
    assert_eq!(device.light.outbox(NOTES).unwrap().len(), 1);
    assert_eq!(device.query::<Vec<u64>>("items", Vec::new()), [5]);
}

/// Two devices issue operations, concurrent ones among them, and exchange
/// their nodes, each in one ingest: both read the same, an operation's
/// time and randomness the issuing device's; a node already applied is a
/// duplicate.
#[test]
fn two_devices_exchange_nodes_and_converge() {
    let (agent, notes) = (common::agent(), common::notes());
    let phone = Device::new(agent, NOTES, notes);
    let laptop = Device::new(agent, NOTES, notes);
    assert_ne!(phone.light.author(), laptop.light.author());
    let stamp = String::decode_exact(&phone.done("stamp", 1u64.encode())).unwrap();
    phone.done("tag", "phone".to_string().encode());
    phone.done("add", 1u64.encode());
    phone.done("title", (2u64, "from the phone".to_string()).encode());
    laptop.done("tag", "laptop".to_string().encode());
    laptop.done("add", 1u64.encode());
    laptop.done("remove", 1u64.encode());
    laptop.done("add", 4u64.encode());
    laptop.done("title", (2u64, "from the laptop".to_string()).encode());

    let to_laptop = phone.push();
    let to_phone = laptop.push();
    let ingested = laptop.light.ingest(NOTES, to_laptop.clone(), None).unwrap();
    assert_eq!(ingested.nodes.applied.len(), to_laptop.len());
    phone.light.ingest(NOTES, to_phone, None).unwrap();
    assert_eq!(state(&phone), state(&laptop));
    assert_eq!(
        laptop.query::<Option<String>>("title_of", 1u64.encode()),
        Some(stamp)
    );
    let again = laptop.light.ingest(NOTES, to_laptop, None).unwrap();
    assert_eq!(again.nodes.duplicates, 4);
    assert!(again.nodes.applied.is_empty());

    // Each now writes after the other's, and the later writes win.
    phone.done("remove", 4u64.encode());
    laptop.done("title", (2u64, "settled".to_string()).encode());
    laptop.light.ingest(NOTES, phone.push(), None).unwrap();
    phone.light.ingest(NOTES, laptop.push(), None).unwrap();
    assert_eq!(state(&phone), state(&laptop));
    let state = state(&phone);
    assert!(!state.items.contains(&4));
    assert!(state.titles.contains(&(2, "settled".into())));
}

/// Operations delivered to three devices in different orders, each a few
/// nodes at a time and some before their parents: every device reads the
/// same.
#[test]
fn delivery_order_does_not_change_what_devices_read() {
    let (agent, notes) = (common::agent(), common::notes());
    let writers = [
        Device::new(agent, NOTES, notes),
        Device::new(agent, NOTES, notes),
    ];
    let mut nodes = Vec::new();
    for round in 0..4u64 {
        for (index, writer) in writers.iter().enumerate() {
            let item = (round + index as u64) % 3;
            writer.done("add", item.encode());
            if round % 2 == index as u64 {
                writer.done("remove", ((round + 1) % 3).encode());
            }
            writer.done("title", (round % 2, format!("{index}/{round}")).encode());
            writer.done("set", (round, index as u64).encode());
        }
        // Each learns the other's nodes of this round.
        let pushed: Vec<Vec<Vec<u8>>> = writers.iter().map(Device::push).collect();
        writers[0]
            .light
            .ingest(NOTES, pushed[1].clone(), None)
            .unwrap();
        writers[1]
            .light
            .ingest(NOTES, pushed[0].clone(), None)
            .unwrap();
        nodes.extend(pushed.into_iter().flatten());
    }
    let expected = state(&writers[0]);
    assert_eq!(state(&writers[1]), expected);
    for order in 0..3u64 {
        let reader = Device::new(agent, NOTES, notes);
        let mut shuffled = nodes.clone();
        shuffle(&mut shuffled, order);
        for chunk in shuffled.chunks(3 + order as usize) {
            reader.light.ingest(NOTES, chunk.to_vec(), None).unwrap();
        }
        assert_eq!(reader.light.wanted(NOTES).unwrap().0, 0);
        assert_eq!(state(&reader), expected, "order {order}");
    }
}

fn call(notes: &Package, name: &str, arguments: Vec<u8>, time: u64) -> Op {
    Op::Call(Call {
        release: 1,
        method: method(notes, name),
        arguments,
        time,
        seed: [time as u8; 32],
    })
}

/// An author that signs two nodes at one sequence number is cut off from
/// it on every device that applies both, its earlier writes kept, both
/// forks applied whichever came first; an author the device set removed is
/// cut off past its frontier, and reads fall back to the others' writes;
/// an operation of a kind this build does not know is held.
#[test]
fn equivocating_and_removed_authors_are_filtered_at_read() {
    let (agent, notes) = (common::agent(), common::notes());
    let phone = Device::new(agent, NOTES, notes);
    let laptop = Device::new(agent, NOTES, notes);
    phone.done("title", (1u64, "phone".to_string()).encode());
    let base = phone.push();
    laptop.light.ingest(NOTES, base.clone(), None).unwrap();
    let after = BTreeSet::from([cid(&base[0])]);

    // A third author: a first node, then two at its second number.
    let thief = SigningKey::from_bytes(&[9; 32]);
    let first = node(
        NOTES,
        &thief,
        0,
        vec![call(
            notes,
            "title",
            (2u64, "thief".to_string()).encode(),
            10,
        )],
        after,
    );
    let second = BTreeSet::from([cid(&first)]);
    let one = node(
        NOTES,
        &thief,
        1,
        vec![call(notes, "title", (1u64, "one".to_string()).encode(), 11)],
        second.clone(),
    );
    let other = node(
        NOTES,
        &thief,
        1,
        vec![
            call(notes, "title", (1u64, "other".to_string()).encode(), 12),
            Op::Unknown {
                kind: 9,
                body: vec![1, 2, 3],
            },
        ],
        second,
    );
    let title =
        |device: &Device, key: u64| device.query::<Option<String>>("title_of", key.encode());
    phone
        .light
        .ingest(NOTES, [first.clone(), one.clone()], None)
        .unwrap();
    assert_eq!(title(&phone, 1).as_deref(), Some("one"));
    let other_cid = other.clone();
    let ingested = phone.light.ingest(NOTES, [other.clone()], None).unwrap();
    assert_eq!(ingested.nodes.equivocations.len(), 1);
    laptop
        .light
        .ingest(NOTES, [other, one, first], None)
        .unwrap();
    for device in [&phone, &laptop] {
        assert_eq!(title(device, 1).as_deref(), Some("phone"));
        assert_eq!(title(device, 2).as_deref(), Some("thief"));
    }
    assert_eq!(state(&phone), state(&laptop));
    // Both forks apply, filtered at read, whichever came first: the
    // unknown kind is held, and nothing quarantined.
    let held = phone.light.held(NOTES).unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].why, Hold::Kind);
    assert_eq!(held[0].cid, cid(&other_cid));
    for device in [&phone, &laptop] {
        assert!(device.light.quarantined(NOTES).unwrap().is_empty());
    }

    // The laptop writes after the phone; the device set then removes the
    // laptop past its frontier, before its write.
    laptop.done("title", (1u64, "laptop".to_string()).encode());
    phone.light.ingest(NOTES, laptop.push(), None).unwrap();
    assert_eq!(title(&phone, 1).as_deref(), Some("laptop"));
    phone
        .light
        .cut_off(NOTES, laptop.light.author(), 0)
        .unwrap();
    assert_eq!(title(&phone, 1).as_deref(), Some("phone"));
    // A later, higher cutoff does not lift it.
    phone
        .light
        .cut_off(NOTES, laptop.light.author(), 5)
        .unwrap();
    assert_eq!(title(&phone, 1).as_deref(), Some("phone"));
}

/// A deterministic shuffle by `seed`.
fn shuffle<T>(items: &mut [T], seed: u64) {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    for at in (1..items.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        items.swap(at, (state % (at as u64 + 1)) as usize);
    }
}
