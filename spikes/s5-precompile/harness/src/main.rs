//! The BLAKE2b precompile on the Gray Paper refine path.
//!
//! `check <precompile.elf> <software.elf> <n>...`: run the precompile guest
//! on a VOS refine host (served natively) and on a JAM-like host (unknown id
//! answers WHAT, the guest falls back to software); compare both with S4's
//! all-software guest, and count steps.
//! `prove <elf> <n>`: trace, prove, encode and verify one run (one per
//! process: peak RSS is per process).

use std::time::Instant;

use vos_pvm::ExitReason;
use vos_pvm::refine::{Machine, MachineObservation};
use vos_pvm::refine_host::RefineContext;
use vos_pvm_proof::refine_codec::encode_refine_proof_bundle;
use vos_pvm_proof::{prove_refine, trace_refine_with_output, verify_refine_bundle_replayed};

const GAS: u64 = 1 << 40;
const WHAT: u64 = u64::MAX - 1;

fn peak_rss_mib() -> f64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|l| l.starts_with("VmHWM:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|k| k.parse::<f64>().ok())
        .unwrap_or(0.0)
        / 1024.0
}

/// VOS: the refine host serves the precompile in place.
fn run_vos(spi: &[u8], n: u64) -> Vec<u8> {
    let invocation = RefineContext::load(spi, &n.to_le_bytes(), GAS)
        .unwrap()
        .run();
    assert_eq!(invocation.exit, ExitReason::Halt);
    invocation.output_bounded(32).unwrap()
}

/// JAM-like: every host call is unknown and answers WHAT. Returns the output
/// and the number of instructions executed.
fn run_jam(spi: &[u8], n: u64) -> (Vec<u8>, u64) {
    let mut machine = Machine::load(spi, &n.to_le_bytes(), GAS).unwrap();
    let mut steps = 0u64;
    loop {
        let exit = machine.resume_observed(|event| {
            if let MachineObservation::Instruction(_) = event {
                steps += 1;
            }
        });
        match exit {
            ExitReason::HostCall(_) => machine.registers_mut()[7] = WHAT,
            other => {
                let invocation = machine.finish(other);
                assert_eq!(invocation.exit, ExitReason::Halt);
                return (invocation.output_bounded(32).unwrap(), steps);
            }
        }
    }
}

fn traced_steps(spi: &[u8], n: u64) -> (usize, usize, Vec<u8>) {
    let (trace, output) = trace_refine_with_output(spi, &n.to_le_bytes(), GAS, 32).expect("trace");
    let steps = trace.slices.iter().map(|s| s.side_note.num_steps()).sum();
    let calls = trace
        .slices
        .iter()
        .map(|s| s.side_note.blake2b_calls.len())
        .sum();
    (steps, calls, output.expect("halted with output"))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let link =
        |path: &str| vos_pvm_compiler::link_elf_spi(&std::fs::read(path).unwrap()).expect("link");
    match args[1].as_str() {
        "check" => {
            let precompile = link(&args[2]);
            let software = link(&args[3]);
            for n in args[4..].iter().map(|a| a.parse::<u64>().unwrap()) {
                let expected = run_vos(&software, n);
                let vos = run_vos(&precompile, n);
                let (jam, jam_steps) = run_jam(&precompile, n);
                let (steps, calls, traced) = traced_steps(&precompile, n);
                assert_eq!(vos, expected, "VOS precompile output differs from software");
                assert_eq!(jam, expected, "JAM fallback output differs from software");
                assert_eq!(traced, expected, "traced output differs");
                println!(
                    "{n} hashes: outputs agree; VOS {steps} steps with {calls} precompile calls; \
                     JAM fallback {jam_steps} steps"
                );
            }
        }
        "prove" => {
            let spi = link(&args[2]);
            let n: u64 = args[3].parse().unwrap();
            let arguments = n.to_le_bytes();
            let started = Instant::now();
            let (trace, _) = trace_refine_with_output(&spi, &arguments, GAS, 32).expect("trace");
            let traced = started.elapsed();
            let steps: usize = trace.slices.iter().map(|s| s.side_note.num_steps()).sum();
            let calls: usize = trace
                .slices
                .iter()
                .map(|s| s.side_note.blake2b_calls.len())
                .sum();
            let started = Instant::now();
            let bundle = prove_refine(trace).expect("prove");
            let proved = started.elapsed();
            let bytes = encode_refine_proof_bundle(&bundle).expect("encode");
            let started = Instant::now();
            verify_refine_bundle_replayed(&bundle, &spi, &arguments, GAS).expect("verify");
            let verified = started.elapsed();
            println!(
                "{n} hashes: {steps} steps, {calls} precompile calls; trace {:.2} s, prove {:.2} s, \
                 verify {:.2} s, proof {:.0} KiB, peak RSS {:.0} MiB",
                traced.as_secs_f64(),
                proved.as_secs_f64(),
                verified.as_secs_f64(),
                bytes.len() as f64 / 1024.0,
                peak_rss_mib(),
            );
        }
        "tamper" => {
            // Corrupt the recorded compression input (or its output bytes in
            // the memory ledger); proving or verification must reject it.
            let spi = link(&args[2]);
            let n: u64 = args[3].parse().unwrap();
            let what = args[4].as_str();
            let arguments = n.to_le_bytes();
            let (mut trace, _) =
                trace_refine_with_output(&spi, &arguments, GAS, 32).expect("trace");
            let note = &mut trace.slices[0].side_note;
            match what {
                "call-input" => note.blake2b_calls[0].h[0] ^= 1,
                "memory-output" => note.blake2b_mem_ops[0].out_bytes[0] ^= 1,
                "unacknowledged" => {
                    let index = note.blake2b_calls.len() - 1;
                    note.blake2b_calls.remove(index);
                    note.blake2b_mem_ops.remove(index);
                }
                _ => panic!("tamper call-input|memory-output|unacknowledged"),
            }
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                prove_refine(trace)
                    .map(|bundle| verify_refine_bundle_replayed(&bundle, &spi, &arguments, GAS))
            }));
            match outcome {
                Ok(Ok(Ok(()))) => println!("{what}: ACCEPTED (unsound)"),
                Ok(Ok(Err(error))) => println!("{what}: rejected at verification: {error:?}"),
                Ok(Err(error)) => println!("{what}: rejected at proving: {error:?}"),
                Err(_) => println!("{what}: rejected (prover panicked)"),
            }
        }
        "tamper-stark" => {
            // Corrupt one compression input, prove, then verify each child
            // STARK alone against an honest trace's public data: no replay.
            let spi = link(&args[2]);
            let n: u64 = args[3].parse().unwrap();
            let arguments = n.to_le_bytes();
            let (mut trace, _) =
                trace_refine_with_output(&spi, &arguments, GAS, 32).expect("trace");
            trace.slices[0].side_note.blake2b_calls[0].h[0] ^= 1;
            let bundle = match prove_refine(trace) {
                Ok(bundle) => bundle,
                Err(error) => return println!("call-input: rejected at proving: {error:?}"),
            };
            let (honest, _) = trace_refine_with_output(&spi, &arguments, GAS, 32).expect("trace");
            for (slice, observed) in bundle.slices.iter().zip(honest.slices) {
                let mut side_note = observed.side_note;
                vos_pvm_proof::prepare_side_note_for_verification(&mut side_note);
                match vos_pvm_proof::verify(slice.proof.clone(), &side_note) {
                    Ok(()) => println!("call-input: STARK ACCEPTED without replay"),
                    Err(error) => println!("call-input: STARK rejected without replay: {error}"),
                }
            }
        }
        _ => panic!("usage: s5-precompile check|prove|tamper|tamper-stark ..."),
    }
}
