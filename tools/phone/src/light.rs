//! The light node on the phone (`vos-phone light`): the notes actor, a
//! local actor, installed from the release artifacts this binary embeds
//! (its build script computes them on the host from the agent's and the
//! actor's ELFs: the phone runs no transpiler), then called and queried
//! over a store in a directory, each operation timed; and the store
//! checked after a kill (`--check`).
//!
//! `vos-phone light --store DIR [--calls N]`: opens the light node at DIR,
//! installs the notes actor if the store is new, makes N calls (default
//! 200), call `n` a merge operation setting count `n` to `n`, recorded as
//! a signed node of the actor's scope, and reads the counts back. One JSON
//! line an operation kind: `open`, `install` (when it ran), `calls` (the
//! count, each call's p50 and p95 in microseconds, and the counts held),
//! `query`.
//!
//! `vos-phone light --store DIR --check`: the store, after a kill, one
//! prefix of the operations, each whole: as many counts as its author's
//! nodes, the last call's among them. One `check` line; exits 1 when the
//! store is not consistent.

use std::path::Path;
use std::time::Instant;

use vos_abi::ids::{InstanceId, MethodId, Principal};
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode, keys};
use vos_light::release::Package;
use vos_light::{Config, Light};

/// The default agent's program, linked, and the notes actor's package, as
/// the build script computed them; empty when it found no ELFs to build
/// them from.
pub static AGENT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/agent.bin"));
pub static NOTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/notes.bin"));

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
    embedded(&[AGENT, NOTES]);
    let notes = Package::decode_exact(NOTES).expect("the embedded package decodes");
    let methods = Methods {
        set: MethodId(vos_light::method_id("set")),
        count: MethodId(vos_light::method_id("count")),
        counted: MethodId(vos_light::method_id("counted")),
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
    if !installed(&light) {
        let started = Instant::now();
        let outcome = light
            .install(INSTANCE, &notes, Vec::new())
            .expect("installs");
        assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
        println!(
            r#"{{"light":"install","ms":{:.3}}}"#,
            started.elapsed().as_secs_f64() * 1e3
        );
    }
    let mut done = recorded(&light);
    let mut times = Vec::with_capacity(calls as usize);
    for _ in 0..calls {
        done += 1;
        let started = Instant::now();
        let outcome = light
            .call(INSTANCE, methods.set, (done, done).encode())
            .expect("a call");
        times.push(started.elapsed().as_micros() as u64);
        assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
    }
    let started = Instant::now();
    let read = counted(&light, &methods);
    let us = started.elapsed().as_micros();
    assert_eq!(read, done, "the query reads what the calls wrote");
    println!(
        r#"{{"light":"calls","calls":{calls},"p50_us":{},"p95_us":{},"value":{read}}}"#,
        percentile(&mut times, 50),
        percentile(&mut times, 95),
    );
    println!(r#"{{"light":"query","us":{us},"value":{read}}}"#);
}

/// Whether the store is one prefix of the operations, each whole: as many
/// counts as its author's nodes, the last node's count among them.
fn check(light: &Light, methods: &Methods) -> bool {
    let (calls, counted, last) = if installed(light) {
        let calls = recorded(light);
        let last = match calls {
            0 => true,
            _ => query::<Option<u64>>(light, methods.count, calls.encode()) == Some(calls),
        };
        (calls, counted(light, methods), last)
    } else {
        (0, 0, true)
    };
    let consistent = counted == calls && last;
    println!(
        r#"{{"light":"check","calls":{calls},"counted":{counted},"consistent":{consistent}}}"#
    );
    consistent
}

/// The notes actor's methods the bench calls.
struct Methods {
    set: MethodId,
    count: MethodId,
    counted: MethodId,
}

/// Whether the notes actor is installed.
fn installed(light: &Light) -> bool {
    let row = light
        .store()
        .snapshot()
        .get(&keys::installed(INSTANCE))
        .expect("a read");
    row.is_some()
}

/// The calls the store holds: its author's nodes in the actor's scope.
fn recorded(light: &Light) -> u64 {
    let have = light.have(INSTANCE).expect("the scope");
    have.get(&light.author()).map_or(0, |seq| seq + 1)
}

/// The counts the store holds, read a page at a time.
fn counted(light: &Light, methods: &Methods) -> u64 {
    let mut total = 0;
    let mut after = None::<u64>;
    loop {
        let (seen, last): (u32, Option<u64>) =
            query(light, methods.counted, (after, 4096u32).encode());
        total += u64::from(seen);
        match last {
            Some(last) if seen > 0 => after = Some(last),
            _ => return total,
        }
    }
}

fn query<T: Decode>(light: &Light, method: MethodId, arguments: Vec<u8>) -> T {
    match light
        .query(DEVICE, INSTANCE, method, arguments)
        .expect("a query")
    {
        Outcome::Done(bytes) => T::decode(&bytes).expect("a reply").0,
        other => panic!("not done: {other:?}"),
    }
}

/// Exits, naming the recipes to run, when this binary was built without
/// any of the release `artifacts` it embeds.
pub fn embedded(artifacts: &[&[u8]]) {
    if artifacts.iter().any(|bytes| bytes.is_empty()) {
        eprintln!(
            "built without the release artifacts: `just build-programs build-test-actors`, then build again"
        );
        std::process::exit(2);
    }
}

/// The value at percentile `q` of `times`, sorted here; 0 of none.
pub fn percentile<T: Copy + Default + PartialOrd>(times: &mut [T], q: usize) -> T {
    times.sort_by(|a, b| a.partial_cmp(b).expect("a time"));
    times
        .get((times.len() * q / 100).min(times.len().saturating_sub(1)))
        .copied()
        .unwrap_or_default()
}
