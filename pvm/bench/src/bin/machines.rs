//! Machine costs (slice 1, steps 1.4 and 1.6 gates), for the ledger actor
//! on the interpreter and the JIT:
//! - a fresh machine: create the actor as an inner machine and lay out its
//!   memory, then resume it for the first time until its first exit;
//! - a pooled machine: `instantiate` it from the pool, use it (map a
//!   request page, write a request, run to the first exit), and expunge it,
//!   which resets it for the next use.
//!
//! `machines`: medians for both backends.
//! `machines loop <interpreter|jit> <fresh|pooled> <n>`: repeat n times, for
//! profiling.

use std::sync::Arc;
use std::time::{Duration, Instant};

use vos_pvm::PvmBackend;
use vos_pvm::inner::{InnerExit, InnerMachines, InvokeState, PageMode};
use vos_pvm::pool::{MachinePool, PoolProgram};
use vos_pvm_bench::{Spi, guest_program, load_actor, parse_standard_program};

const HALT: u64 = (1 << 32) - (1 << 16);
const YIELD: u64 = 0x2ff;
const SAMPLES: usize = 201;
/// Where the pooled actor's request page goes: the standard argument
/// region, which a layout without arguments leaves unmapped.
const REQUEST: u32 = ((1u64 << 32) - (1 << 16) - (1 << 24)) as u32;

fn request_registers(stack_top: u64, request: u32) -> [u64; 13] {
    let mut registers = [0u64; 13];
    registers[0] = HALT;
    registers[1] = stack_top;
    registers[7] = u64::from(request);
    registers[8] = 32;
    registers
}

fn request() -> [u8; 32] {
    let mut request = [0u8; 32];
    request[0] = b'Y';
    request
}

/// One fresh machine: (create + layout, first resume).
fn fresh(backend: PvmBackend, actor: &Spi) -> (Duration, Duration) {
    let mut inner = InnerMachines::with_backend(backend);
    let started = Instant::now();
    let loaded = load_actor(&mut inner, actor);
    let layout = started.elapsed();

    inner
        .poke(loaded.id, loaded.args_base as u32, &request())
        .expect("poke request");
    let started = Instant::now();
    let outcome = inner
        .invoke(
            loaded.id,
            InvokeState {
                gas: 1_000_000,
                registers: request_registers(loaded.stack_top, loaded.args_base as u32),
            },
        )
        .expect("invoke");
    let first = started.elapsed();
    assert_eq!(outcome.exit, InnerExit::Host(YIELD));
    (layout, first)
}

/// One pooled use: (acquire, use, reset).
fn pooled(inner: &mut InnerMachines, program: &Arc<PoolProgram>) -> (Duration, Duration, Duration) {
    let stack_top = (1u64 << 32) - 2 * (1 << 16) - (1 << 24);
    let started = Instant::now();
    let id = inner.instantiate(program).expect("instantiate");
    let acquire = started.elapsed();

    let started = Instant::now();
    inner
        .pages(id, REQUEST / 4096, 1, PageMode::AllocateReadWrite)
        .expect("request page");
    inner.poke(id, REQUEST, &request()).expect("poke request");
    let outcome = inner
        .invoke(
            id,
            InvokeState {
                gas: 1_000_000,
                registers: request_registers(stack_top, REQUEST),
            },
        )
        .expect("invoke");
    let used = started.elapsed();
    assert_eq!(outcome.exit, InnerExit::Host(YIELD));

    let started = Instant::now();
    inner.expunge(id).expect("expunge");
    (acquire, used, started.elapsed())
}

fn median(mut samples: Vec<Duration>) -> f64 {
    samples.sort();
    samples[samples.len() / 2].as_secs_f64() * 1e6
}

fn main() {
    let blob = guest_program("actor");
    let actor = parse_standard_program(&blob);
    let pool = Arc::new(MachinePool::new());
    let program = pool
        .program(&pool.install(&blob).expect("install"))
        .unwrap();
    let backend_named = |name: &str| match name {
        "interpreter" => PvmBackend::ForceInterpreter,
        "jit" => PvmBackend::ForceRecompiler,
        other => panic!("unknown backend {other}"),
    };

    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("loop") {
        let backend = backend_named(&args[2]);
        let n: usize = args[4].parse().unwrap();
        let mut inner = InnerMachines::with_backend(backend);
        inner.set_pool(Arc::clone(&pool));
        for _ in 0..n {
            match args[3].as_str() {
                "fresh" => drop(std::hint::black_box(fresh(backend, &actor))),
                "pooled" => drop(std::hint::black_box(pooled(&mut inner, &program))),
                other => panic!("unknown mode {other}"),
            }
        }
        return;
    }
    for name in ["interpreter", "jit"] {
        let backend = backend_named(name);
        let (layout, first): (Vec<_>, Vec<_>) =
            (0..SAMPLES).map(|_| fresh(backend, &actor)).unzip();
        println!(
            "{name:>12} fresh:  create + layout {:.1} µs, first resume {:.1} µs",
            median(layout),
            median(first),
        );

        let mut inner = InnerMachines::with_backend(backend);
        inner.set_pool(Arc::clone(&pool));
        let (mut acquire, mut used, mut reset, mut cycle) = (vec![], vec![], vec![], vec![]);
        for _ in 0..SAMPLES {
            let (a, u, r) = pooled(&mut inner, &program);
            acquire.push(a);
            used.push(u);
            reset.push(r);
            cycle.push(a + r);
        }
        println!(
            "{name:>12} pooled: acquire {:.1} µs, use {:.1} µs, reset {:.1} µs; acquire + reset {:.1} µs",
            median(acquire),
            median(used),
            median(reset),
            median(cycle),
        );
    }
}
