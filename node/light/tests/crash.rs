//! A light node killed mid-operation reopens on one prefix of its
//! operations, each whole: the child installs the counter and calls it in a
//! loop, call `n` adding `n`, and reports each call it committed; the
//! store, reopened after the kill (and in later rounds a tear of the
//! journal's tail, as a power loss could leave it), holds a state version
//! `v` and the counter's value the sum of the first `v - 1` calls, its
//! latest time its last operation's.

use std::path::Path;

use vos_checker::crash::{Round, Rounds, journal};
use vos_light::release::{self, Package};
use vos_light::{Config, Light};
use vos_testkit::programs;
use vos_wire::ids::{InstanceId, Principal};
use vos_wire::records::unstored;
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode, keys};

const COUNTER: InstanceId = InstanceId(1);
const DEVICE: Principal = Principal::Client([0xd1; 32]);
const ROUNDS: Rounds = Rounds::twelve("VOS_LIGHT_CRASH_WRITER", "", 40);
/// At most this many bytes of the journal are torn.
const TEAR: u64 = 512;
/// The most operations a tear can take: each one's batch holds its row of
/// the last time and seed alone more than 32 bytes.
const TEAR_REACH: u64 = TEAR / 32;

fn artifacts() -> (Vec<u8>, Package) {
    let read = |path: std::path::PathBuf| std::fs::read(path).unwrap();
    let agent = release::agent(&read(programs::agent_elf())).unwrap();
    let counter = release::package(&read(programs::actor_elf("counter"))).unwrap();
    (agent, counter)
}

/// The child: install the counter if this store has not, then call it in
/// a loop, reporting each call's number once committed.
fn writer(dir: &Path) {
    let (agent, counter) = artifacts();
    let increment = programs::method(&counter.programs[0], "increment");
    let light = Light::open(dir, &agent, Config::default()).unwrap();
    let applied = version(&light);
    if applied == 0 {
        light.install(COUNTER, &counter, Vec::new()).unwrap();
    }
    let mut calls = applied.saturating_sub(1);
    loop {
        calls += 1;
        let outcome = light
            .call(DEVICE, COUNTER, increment, calls.encode())
            .unwrap();
        assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
        println!("{calls}");
    }
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
    let (agent, counter) = artifacts();
    let value = programs::method(&counter.programs[0], "value");
    let mut last = 0;
    ROUNDS.run(writer, journal(TEAR), |round| {
        check(round, &agent, value, &mut last)
    });
    println!(
        "light crash: {} rounds reopened on one prefix each",
        ROUNDS.rounds
    );
}

/// The store reopened on one prefix of the operations, at least through
/// the calls the child reported, or else through those `last` round
/// reopened on, but for what a tear takes.
fn check(round: Round, agent: &[u8], value: vos_wire::ids::MethodId, last: &mut u64) {
    let reported = round.reported.unwrap_or(*last);
    let floor = round.floor(reported, TEAR_REACH);
    let light = Light::open(round.dir, agent, Config::default()).unwrap();
    let applied = version(&light);
    let calls = applied.saturating_sub(1);
    assert!(
        calls >= floor,
        "round {}: {calls} calls, but {reported} were reported ({})",
        round.number,
        round.how()
    );
    if applied > 0 {
        let outcome = light.query(DEVICE, COUNTER, value, Vec::new()).unwrap();
        let Outcome::Done(bytes) = outcome else {
            panic!("round {}: {outcome:?}", round.number);
        };
        assert_eq!(
            u64::decode(&bytes).unwrap().0,
            calls * (calls + 1) / 2,
            "round {}: the counter is not the sum of the first {calls} calls",
            round.number
        );
        let latest = stored::<u64>(&light, &keys::batch_time());
        let mark = light
            .store()
            .snapshot()
            .last()
            .unwrap()
            .map(|(time, _)| time);
        assert_eq!(latest, mark, "round {}", round.number);
    }
    *last = calls;
}
