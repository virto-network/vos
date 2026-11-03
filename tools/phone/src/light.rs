//! The light node on the phone (`vos-phone light`): the counter, a local
//! actor, installed from the release artifacts this binary embeds (its
//! build script computes them on the host from the agent's and the
//! counter's ELFs: the phone runs no transpiler), then called and queried
//! over a store in a directory, each operation timed; and the store
//! checked after a kill (`--check`).
//!
//! `vos-phone light --store DIR [--calls N]`: opens the light node at DIR,
//! installs the counter if the store is new, makes N calls (default 200),
//! call `n` adding `n`, and reads the value back. One JSON line an
//! operation kind: `open`, `install` (when it ran), `calls` (the count,
//! each call's p50 and p95 in microseconds, and the value), `query`.
//!
//! `vos-phone light --store DIR --check`: the store, after a kill, one
//! prefix of the operations, each whole: its state version `v` and the
//! counter's value the sum of the first `v - 1` calls. One `check` line;
//! exits 1 when the store is not consistent.

use std::path::Path;
use std::time::Instant;

use vos_light::release::Package;
use vos_light::{Config, Light};
use vos_wire::ids::{InstanceId, MethodId, Principal};
use vos_wire::records::unstored;
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode, keys};

/// The default agent's program, linked, and the counter's package, as the
/// build script computed them; empty when it found no ELFs to build them
/// from.
static AGENT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/agent.bin"));
static COUNTER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/counter.bin"));

const INSTANCE: InstanceId = InstanceId(1);
const DEVICE: Principal = Principal::Client([0xd1; 32]);

pub fn light(args: &[String]) {
    let mut store = None;
    let mut calls = 200u64;
    let mut check = false;
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--store" => store = args.next().cloned(),
            "--calls" => calls = args.next().and_then(|n| n.parse().ok()).expect("--calls N"),
            "--check" => check = true,
            other => panic!("unknown flag {other}"),
        }
    }
    let store = store.expect("--store DIR");
    if AGENT.is_empty() || COUNTER.is_empty() {
        eprintln!(
            "built without the release artifacts: `just build-agent build-test-actors`, then build again"
        );
        std::process::exit(2);
    }
    let counter = Package::decode_exact(COUNTER).expect("the embedded package decodes");
    let methods = Methods {
        increment: MethodId(vos_light::method_id("increment")),
        value: MethodId(vos_light::method_id("value")),
    };
    let started = Instant::now();
    let light = Light::open(Path::new(&store), AGENT, Config::default()).expect("opens");
    println!(
        r#"{{"light":"open","ms":{:.3}}}"#,
        started.elapsed().as_secs_f64() * 1e3
    );
    if check {
        let consistent = self::check(&light, &methods);
        std::process::exit(if consistent { 0 } else { 1 });
    }
    let mut done = version(&light).saturating_sub(1);
    if version(&light) == 0 {
        let started = Instant::now();
        let outcome = light
            .install(INSTANCE, &counter, Vec::new())
            .expect("installs");
        assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
        println!(
            r#"{{"light":"install","ms":{:.3}}}"#,
            started.elapsed().as_secs_f64() * 1e3
        );
    }
    let mut times = Vec::with_capacity(calls as usize);
    let mut value = 0;
    for _ in 0..calls {
        done += 1;
        let started = Instant::now();
        let outcome = light
            .call(DEVICE, INSTANCE, methods.increment, done.encode())
            .expect("a call");
        times.push(started.elapsed().as_micros() as u64);
        value = total(outcome);
    }
    times.sort_unstable();
    let at = |q: usize| times.get((times.len() * q / 100).min(times.len().saturating_sub(1)));
    println!(
        r#"{{"light":"calls","calls":{calls},"p50_us":{},"p95_us":{},"value":{value}}}"#,
        at(50).copied().unwrap_or(0),
        at(95).copied().unwrap_or(0),
    );
    let started = Instant::now();
    let read = total(
        light
            .query(DEVICE, INSTANCE, methods.value, Vec::new())
            .expect("a query"),
    );
    assert_eq!(read, value, "the query reads what the calls wrote");
    println!(
        r#"{{"light":"query","us":{},"value":{read}}}"#,
        started.elapsed().as_micros()
    );
}

/// Whether the store is one prefix of the operations, each whole: the
/// counter the sum of the calls its state version counts, and the latest
/// time its rows hold the one its last operation recorded.
fn check(light: &Light, methods: &Methods) -> bool {
    let applied = version(light);
    let calls = applied.saturating_sub(1);
    let value = match applied {
        0 => 0,
        _ => total(
            light
                .query(DEVICE, INSTANCE, methods.value, Vec::new())
                .expect("a query"),
        ),
    };
    let expected = calls * (calls + 1) / 2;
    let latest = light
        .store()
        .snapshot()
        .get(&keys::batch_time())
        .expect("a read")
        .and_then(|bytes| u64::decode(unstored(&bytes)?).ok())
        .map(|(time, _)| time);
    let last = light
        .store()
        .snapshot()
        .last()
        .expect("a read")
        .map(|(time, _)| time);
    let consistent = applied == 0 || (value == expected && latest == last);
    println!(
        r#"{{"light":"check","version":{applied},"calls":{calls},"value":{value},"expected":{expected},"consistent":{consistent}}}"#
    );
    consistent
}

/// The counter's methods the bench calls.
struct Methods {
    increment: MethodId,
    value: MethodId,
}

/// The store's state version: its operations applied.
fn version(light: &Light) -> u64 {
    let bytes = light
        .store()
        .snapshot()
        .get(&keys::version())
        .expect("a read");
    bytes
        .and_then(|bytes| u64::decode(unstored(&bytes)?).ok())
        .map_or(0, |(version, _)| version)
}

fn total(outcome: Outcome) -> u64 {
    match outcome {
        Outcome::Done(bytes) => u64::decode(&bytes).expect("a total").0,
        other => panic!("not done: {other:?}"),
    }
}
