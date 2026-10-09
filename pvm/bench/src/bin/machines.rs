//! Machine creation cost (slice 1, step 1.4 gates): create the ledger actor
//! as an inner machine and lay out its memory, then resume it for the first
//! time until its first exit, on the interpreter and the JIT.
//!
//! `machines`: medians for both backends.
//! `machines loop <interpreter|jit> <n>`: repeat n times, for profiling.

use std::time::{Duration, Instant};

use vos_pvm::PvmBackend;
use vos_pvm::inner::{InnerExit, InnerMachines, InvokeState};
use vos_pvm_bench::{Spi, guest_program, load_actor, parse_standard_program};

const HALT: u64 = (1 << 32) - (1 << 16);
const YIELD: u64 = 0x2ff;
const SAMPLES: usize = 201;

/// One fresh machine: (create + layout, first resume).
fn fresh(backend: PvmBackend, actor: &Spi) -> (Duration, Duration) {
    let mut inner = InnerMachines::with_backend(backend);
    let started = Instant::now();
    let loaded = load_actor(&mut inner, actor);
    let layout = started.elapsed();

    let mut request = [0u8; 32];
    request[0] = b'Y';
    inner
        .poke(loaded.id, loaded.args_base as u32, &request)
        .expect("poke request");
    let mut registers = [0u64; 13];
    registers[0] = HALT;
    registers[1] = loaded.stack_top;
    registers[7] = loaded.args_base;
    registers[8] = request.len() as u64;
    let started = Instant::now();
    let outcome = inner
        .invoke(
            loaded.id,
            InvokeState {
                gas: 1_000_000,
                registers,
            },
        )
        .expect("invoke");
    let first = started.elapsed();
    assert_eq!(outcome.exit, InnerExit::Host(YIELD));
    (layout, first)
}

fn median(mut samples: Vec<Duration>) -> f64 {
    samples.sort();
    samples[samples.len() / 2].as_secs_f64() * 1e6
}

fn main() {
    let actor = parse_standard_program(&guest_program("actor"));
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("loop") {
        let backend = match args[2].as_str() {
            "interpreter" => PvmBackend::ForceInterpreter,
            "jit" => PvmBackend::ForceRecompiler,
            other => panic!("unknown backend {other}"),
        };
        let n: usize = args[3].parse().unwrap();
        for _ in 0..n {
            std::hint::black_box(fresh(backend, &actor));
        }
        return;
    }
    for (name, backend) in [
        ("interpreter", PvmBackend::ForceInterpreter),
        ("JIT", PvmBackend::ForceRecompiler),
    ] {
        let (layout, first): (Vec<_>, Vec<_>) =
            (0..SAMPLES).map(|_| fresh(backend, &actor)).unzip();
        println!(
            "{name:>12}: create + layout {:.1} µs, first resume {:.1} µs",
            median(layout),
            median(first),
        );
    }
}
