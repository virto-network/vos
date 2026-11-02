//! A local actor installed on the light node from release artifacts,
//! called and queried, its state kept across a reopen; and what the merge
//! entry refuses.

use vos_light::release::{self, Package};
use vos_light::{Config, Error, Light};
use vos_testkit::programs;
use vos_wire::abi::Failure;
use vos_wire::ids::{InstanceId, MethodId, Principal};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};

const COUNTER: InstanceId = InstanceId(1);
const DEVICE: Principal = Principal::Client([0xd1; 32]);

/// The release artifacts, as the release build computes them: the agent
/// program, and the counter's package.
fn artifacts() -> (Vec<u8>, Package) {
    let read = |path: std::path::PathBuf| std::fs::read(path).unwrap();
    let agent = release::agent(&read(programs::agent_elf())).unwrap();
    let counter = release::package(&read(programs::actor_elf("counter"))).unwrap();
    (agent, counter)
}

fn method(package: &Package, name: &str) -> MethodId {
    programs::method(&package.programs[0], name)
}

fn total(outcome: Outcome) -> u64 {
    match outcome {
        Outcome::Done(bytes) => u64::decode(&bytes).unwrap().0,
        other => panic!("not done: {other:?}"),
    }
}

/// The artifacts round-trip as the app embeds them, and install: the
/// counter, called on the merge entry, counts, its queries read what the
/// calls wrote, and the light node opened again holds it all, its programs
/// pooled from the store.
#[test]
fn a_local_actor_installed_from_release_artifacts_is_called() {
    let (agent, counter) = artifacts();
    // As `vos-phone`'s build script encodes a package: its derivation,
    // then its programs.
    let bytes = (counter.derivation.clone(), counter.programs.clone()).encode();
    assert_eq!(bytes, counter.encode());
    let embedded = Package::decode_exact(&bytes).unwrap();
    assert_eq!(embedded, counter);
    let dir = tempfile::tempdir().unwrap();
    let (increment, value) = (method(&counter, "increment"), method(&counter, "value"));
    {
        let light = Light::open(dir.path(), &agent, Config::default()).unwrap();
        let installed = light.install(COUNTER, &embedded, Vec::new()).unwrap();
        assert!(matches!(installed, Outcome::Done(_)), "{installed:?}");
        for (by, expected) in [(5u64, 5), (7, 12)] {
            let outcome = light.call(DEVICE, COUNTER, increment, by.encode()).unwrap();
            assert_eq!(total(outcome), expected);
        }
        let read = light.query(DEVICE, COUNTER, value, Vec::new()).unwrap();
        assert_eq!(total(read), 12);
    }
    let light = Light::open(dir.path(), &agent, Config::default()).unwrap();
    assert_eq!(
        total(light.query(DEVICE, COUNTER, value, Vec::new()).unwrap()),
        12
    );
    assert_eq!(
        total(
            light
                .call(DEVICE, COUNTER, increment, 1u64.encode())
                .unwrap()
        ),
        13
    );
}

/// A handler's failure writes nothing of its own; a call doing more than
/// writing rows (a message, a committed map) fails `Trapped` with nothing
/// written; a query that writes traps; and a package whose programs are
/// not its derivation's installs nothing.
#[test]
fn the_merge_entry_writes_rows_alone() {
    let (agent, counter) = artifacts();
    let dir = tempfile::tempdir().unwrap();
    let light = Light::open(dir.path(), &agent, Config::default()).unwrap();
    let mut forged = counter.clone();
    forged.programs[0].push(0);
    assert!(matches!(
        light.install(COUNTER, &forged, Vec::new()),
        Err(Error::Package)
    ));
    light.install(COUNTER, &counter, Vec::new()).unwrap();
    let call = |name: &str, arguments: Vec<u8>| {
        light
            .call(DEVICE, COUNTER, method(&counter, name), arguments)
            .unwrap()
    };
    assert_eq!(total(call("increment", u64::MAX.encode())), u64::MAX);
    assert!(matches!(
        call("increment", 1u64.encode()),
        Outcome::Failed {
            code: Failure::Handler,
            ..
        }
    ));
    let rows = light.store().rows().unwrap();
    let trapped = |outcome: Outcome| {
        matches!(
            outcome,
            Outcome::Failed {
                code: Failure::Trapped,
                ..
            }
        )
    };
    assert!(trapped(call("forward", (2u32, 1u32, 3u64).encode())));
    assert!(trapped(call(
        "set_entries",
        vec![(1u64, Some(2u64))].encode()
    )));
    let after: Vec<_> = light
        .store()
        .rows()
        .unwrap()
        .into_iter()
        .filter(|(key, _)| !is_mark(key))
        .collect();
    let before: Vec<_> = rows.into_iter().filter(|(key, _)| !is_mark(key)).collect();
    assert_eq!(after, before, "a refused call wrote a row");
    let sneaky = light
        .query(DEVICE, COUNTER, method(&counter, "sneaky"), Vec::new())
        .unwrap();
    assert!(trapped(sneaky));
    assert_eq!(
        total(
            light
                .query(DEVICE, COUNTER, method(&counter, "value"), Vec::new())
                .unwrap()
        ),
        u64::MAX
    );
}

/// The rows every operation moves: the state version and the latest time.
fn is_mark(key: &[u8]) -> bool {
    key == vos_wire::keys::version() || key == vos_wire::keys::batch_time()
}
