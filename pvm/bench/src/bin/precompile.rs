//! Proving the BLAKE2b precompile on the Gray Paper refine path.
//!
//! `precompile prove <n>`: trace, prove, encode and verify n hashes. Run one
//! size per process: peak RSS is per process, and proving needs 4–24 GiB.
//! `precompile tamper <n> call-input|memory-output|unacknowledged`: corrupt a
//! recorded call; proving or verification must reject it.
//! `precompile tamper-stark <n>`: corrupt a call input and verify each child
//! STARK alone, without replay.
//! `precompile native`: the native cost of serving one compression, in
//! nanoseconds and time-stamp-counter cycles, and the gas the guest pays
//! for one compression in software on a JAM host. The VOS price is set from
//! these.
//!
//! Cross-host agreement is a test: `tests/precompile_agreement.rs`.

use std::time::Instant;

use vos_pvm_bench::GAS;
use vos_pvm_proof::refine_codec::encode_refine_proof_bundle;
use vos_pvm_proof::{prove_refine, trace_refine_with_output, verify_refine_bundle_replayed};

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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str).unwrap_or_default() {
        "prove" => {
            let spi = vos_pvm_bench::guest_program("hash-precompile");
            let n: u64 = args[2].parse().unwrap();
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
            let spi = vos_pvm_bench::guest_program("hash-precompile");
            let n: u64 = args[2].parse().unwrap();
            let what = args[3].as_str();
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
            let spi = vos_pvm_bench::guest_program("hash-precompile");
            let n: u64 = args[2].parse().unwrap();
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
        "native" => native(),
        _ => panic!("usage: precompile prove <n> | tamper <n> <what> | tamper-stark <n> | native"),
    }
}

/// Native cost of serving one compression, and the guest's software cost.
fn native() {
    use vos_pvm::interpreter::{Memory, PERM_RW};
    use vos_pvm::precompile::{BLAKE2B_COMPRESS, execute};

    const CALLS: u64 = 1_000_000;
    let mut memory = Memory::flat(vec![0x5a; 0x2000]);
    memory.set_page_perms(vec![PERM_RW; 2]);
    let mut registers = [0u64; vos_pvm::PVM_REGISTER_COUNT];
    registers[7] = 0x0;
    registers[8] = 0x1000;
    registers[9] = 128;
    registers[10] = 1;
    for _ in 0..10_000 {
        std::hint::black_box(execute(BLAKE2B_COMPRESS, &registers, &mut memory));
    }
    let started = Instant::now();
    // SAFETY: reading the time-stamp counter has no side effects.
    let tsc_start = unsafe { core::arch::x86_64::_rdtsc() };
    for _ in 0..CALLS {
        std::hint::black_box(execute(BLAKE2B_COMPRESS, &registers, &mut memory));
    }
    // SAFETY: as above.
    let tsc = unsafe { core::arch::x86_64::_rdtsc() } - tsc_start;
    let elapsed = started.elapsed();

    let software = vos_pvm_bench::guest_program("hash-software");
    let gas_for = |n: u64| {
        let invocation =
            vos_pvm::refine_host::RefineContext::load(&software, &n.to_le_bytes(), GAS)
                .expect("load")
                .run();
        invocation.gas_used
    };
    let per_hash = (gas_for(101) - gas_for(1)) / 100;
    println!(
        "served compression: {:.0} ns, {:.0} TSC cycles; software hash in the guest: {per_hash} gas",
        elapsed.as_nanos() as f64 / CALLS as f64,
        tsc as f64 / CALLS as f64,
    );
}
