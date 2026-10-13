//! Host-call exit cost: an inner machine that loops on `ecalli`, invoked
//! again at every exit, on the interpreter and the JIT.
//! Each iteration is one exit to the host and one re-entry, with nothing
//! else to run.
//!
//! `exits`: the median time per exit on both backends.
//! `exits loop <interpreter|jit> <n>`: n exits, for profiling.

use std::time::Instant;

use vos_pvm::PvmBackend;
use vos_pvm::inner::{InnerExit, InnerMachines, InvokeState};
use vos_pvm_program::{CodeBlob, build_compact_code_blob};

const CALL: u64 = 0x2ff;
const ROUNDS: usize = 31;
const EXITS: usize = 10_000;

/// `loop: ecalli 0x2ff; jump loop`.
fn looping() -> Vec<u8> {
    build_compact_code_blob(&CodeBlob {
        jump_table: Vec::new(),
        code: vec![10, 0xff, 0x02, 40, 0xfd],
        bitmask: vec![1, 0, 0, 1, 0],
    })
    .expect("a code blob")
}

/// A machine looping on its call, ready to run.
fn machine(backend: PvmBackend) -> (InnerMachines, u32) {
    let mut inner = InnerMachines::with_backend(backend);
    let id = inner.create(&looping(), 0).expect("a machine");
    (inner, id)
}

/// Run `exits` exits: each invoke runs to the call and returns.
fn run(inner: &mut InnerMachines, id: u32, exits: usize) {
    let mut state = InvokeState {
        gas: u64::MAX / 2,
        registers: [0; 13],
    };
    for _ in 0..exits {
        let outcome = inner.invoke(id, state).expect("invoke");
        assert_eq!(outcome.exit, InnerExit::Host(CALL));
        state = outcome.state;
    }
}

fn per_exit(backend: PvmBackend) -> f64 {
    let (mut inner, id) = machine(backend);
    run(&mut inner, id, EXITS);
    let mut rounds: Vec<f64> = (0..ROUNDS)
        .map(|_| {
            let started = Instant::now();
            run(&mut inner, id, EXITS);
            started.elapsed().as_secs_f64() * 1e9 / EXITS as f64
        })
        .collect();
    rounds.sort_by(f64::total_cmp);
    rounds[ROUNDS / 2]
}

fn backend(name: &str) -> PvmBackend {
    match name {
        "interpreter" => PvmBackend::ForceInterpreter,
        "jit" => PvmBackend::ForceRecompiler,
        other => panic!("no backend {other}"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let [mode, name, count] = args.as_slice()
        && mode == "loop"
    {
        let (mut inner, id) = machine(backend(name));
        run(&mut inner, id, count.parse().expect("a count"));
        return;
    }
    for name in ["interpreter", "jit"] {
        println!(
            "{name:>12}: {:.0} ns per exit and re-entry",
            per_exit(backend(name))
        );
    }
}
