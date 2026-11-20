//! A light node killed mid-operation reopens on one prefix of its
//! operations, each whole: the child installs the notes actor and calls a
//! merge handler in a loop, call `n` setting count `n` to `n`, each a node
//! of the actor's scope, and reports each call it committed; the store,
//! reopened after the kill (and in later rounds a tear of the journal's
//! tail, as a power loss could leave it), holds the nodes of the first
//! calls and their counts, no more and no fewer.

mod common;

use std::path::Path;

use vos_abi::ids::{InstanceId, Principal};
use vos_abi::records::unstored;
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode, keys};
use vos_checker::crash::{Round, Rounds, journal};
use vos_light::release::Package;
use vos_light::{Config, Light};
use vos_testkit::programs;

const NOTES: InstanceId = InstanceId(1);
const DEVICE: Principal = Principal::Client([0xd1; 32]);
const ROUNDS: Rounds = Rounds::twelve("VOS_LIGHT_CRASH_WRITER", "", 40);
/// At most this many bytes of the journal are torn.
const TEAR: u64 = 512;
/// The most operations a tear can take: each operation's batch is over 32
/// bytes (its row of the last time and seed alone is 40), so a tear of
/// `TEAR` bytes reaches at most `TEAR / 32` operations.
const TEAR_REACH: u64 = TEAR / 32;

/// The child: install the notes actor if this store has not, then call it
/// in a loop, reporting each call's number once committed.
fn writer(dir: &Path) {
    let (agent, notes) = (common::agent(), common::notes());
    let set = programs::method(&notes.programs[0], "set");
    let light = Light::open(dir, agent, Config::default()).unwrap();
    if version(&light) == 0 {
        light.install(NOTES, notes, Vec::new()).unwrap();
    }
    let mut calls = recorded(&light);
    loop {
        calls += 1;
        let outcome = light.call(NOTES, set, (calls, calls).encode()).unwrap();
        assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
        println!("{calls}");
    }
}

/// The calls the store holds: its author's nodes in the notes' scope.
fn recorded(light: &Light) -> u64 {
    let have = light.have(NOTES).unwrap();
    have.get(&light.author()).map_or(0, |seq| seq + 1)
}

/// The store's state version: its operations applied.
fn version(light: &Light) -> u64 {
    stored::<u64>(light, &keys::version()).unwrap_or(0)
}

fn stored<T: Decode>(light: &Light, key: &[u8]) -> Option<T> {
    let bytes = light.store().snapshot().get(key).unwrap()?;
    Some(T::decode(unstored(&bytes)?).unwrap().0)
}

fn main() {
    let (agent, notes) = (common::agent(), common::notes());
    let mut last = 0;
    ROUNDS.run(writer, journal(TEAR), |round| {
        check(round, agent, notes, &mut last)
    });
    println!(
        "light crash: {} rounds reopened on one prefix each",
        ROUNDS.rounds
    );
}

/// The store reopened on one prefix of the operations, its install's
/// programs with its rows, at least through the calls the child reported,
/// or else through those `last` round reopened on, but for what a tear
/// takes; and the counts the calls set, those alone.
fn check(round: Round, agent: &[u8], notes: &Package, last: &mut u64) {
    let reported = round.reported.unwrap_or(*last);
    let floor = round.floor(reported, TEAR_REACH);
    let light = Light::open(round.dir, agent, Config::default()).unwrap();
    let calls = if version(&light) > 0 {
        recorded(&light)
    } else {
        0
    };
    assert!(
        calls >= floor,
        "round {}: {calls} calls, but {reported} were reported ({})",
        round.number,
        round.how()
    );
    if version(&light) > 0 {
        let held: Vec<[u8; 32]> = light
            .store()
            .programs()
            .unwrap()
            .into_iter()
            .map(|(hash, _)| hash)
            .collect();
        assert!(
            notes
                .derivation
                .programs()
                .all(|program| held.contains(&program.0)),
            "round {}: the install's rows without its programs",
            round.number
        );
        let query = |name: &str, arguments: Vec<u8>| {
            let method = programs::method(&notes.programs[0], name);
            match light.query(DEVICE, NOTES, method, arguments).unwrap() {
                Outcome::Done(bytes) => bytes,
                outcome => panic!("round {}: {outcome:?}", round.number),
            }
        };
        let counted = query("counted", (None::<u64>, u32::MAX).encode());
        let (counted, _) = <(u32, Option<u64>)>::decode(&counted).unwrap().0;
        assert_eq!(
            u64::from(counted),
            calls,
            "round {}: the counts are not the {calls} calls'",
            round.number
        );
        if calls > 0 {
            let count = query("count", calls.encode());
            assert_eq!(
                Option::<u64>::decode(&count).unwrap().0,
                Some(calls),
                "round {}",
                round.number
            );
        }
    }
    *last = calls;
}
