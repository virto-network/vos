//! Proving the BLAKE2b precompile in a segment proof (`format::SEGMENT`).
//!
//! `precompile prove <n>`: trace, prove, encode and verify n hashes. Run one
//! size per process: peak RSS is per process, and proving needs 4–24 GiB.
//! `precompile tamper <n> call-input|memory-output|unacknowledged`: corrupt a
//! recorded call; proving, or verification against the honest run's
//! program, must reject it.
//! `precompile native`: the native cost of serving one BLAKE2b and one
//! Poseidon2 compression, in nanoseconds and time-stamp-counter cycles, and
//! the gas the guest pays for each in software on a JAM host. The VOS
//! prices are set from these.
//!
//! Cross-host agreement is a test: `tests/precompile_agreement.rs`.

use std::time::Instant;

use vos_pvm_bench::GAS;
use vos_pvm_proof::kernel::trace_program;
use vos_pvm_proof::{prove, verify};

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
    let spi = vos_pvm_bench::guest_program("hash-precompile");
    let trace = |arguments: &[u8]| trace_program(&spi, arguments, GAS).expect("trace");
    match args.get(1).map(String::as_str).unwrap_or_default() {
        "prove" => {
            let n: u64 = args[2].parse().unwrap();
            let arguments = n.to_le_bytes();
            let started = Instant::now();
            let mut side_note = trace(&arguments).side_note;
            let traced = started.elapsed();
            let steps = side_note.num_steps();
            let calls = side_note.blake2b_calls.len();
            let started = Instant::now();
            let proof = prove(&mut side_note).expect("prove");
            let proved = started.elapsed();
            let bytes = postcard::to_allocvec(&proof).expect("encode");
            let started = Instant::now();
            verify(proof, &side_note).expect("verify");
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
            let n: u64 = args[2].parse().unwrap();
            let what = args[3].as_str();
            let arguments = n.to_le_bytes();
            let honest = trace(&arguments).side_note;
            let mut note = trace(&arguments).side_note;
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
                prove(&mut note).map(|proof| verify(proof, &honest))
            }));
            match outcome {
                Ok(Ok(Ok(()))) => println!("{what}: ACCEPTED (unsound)"),
                Ok(Ok(Err(error))) => println!("{what}: rejected at verification: {error:?}"),
                Ok(Err(error)) => println!("{what}: rejected at proving: {error:?}"),
                Err(_) => println!("{what}: rejected (prover panicked)"),
            }
        }
        "native" => {
            native();
            native_poseidon2();
        }
        _ => panic!("usage: precompile prove <n> | tamper <n> <what> | native"),
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

/// Native cost of serving one Poseidon2 compression, and the guest's
/// software cost when the host answers `WHAT`.
fn native_poseidon2() {
    use vos_pvm::interpreter::{Memory, PERM_RW};
    use vos_pvm::precompile::{POSEIDON2, execute};

    const CALLS: u64 = 1_000_000;
    let mut memory = Memory::flat(vec![0x3a; 0x2000]);
    memory.set_page_perms(vec![PERM_RW; 2]);
    let mut registers = [0u64; vos_pvm::PVM_REGISTER_COUNT];
    registers[7] = 0x0;
    registers[8] = 0x1000;
    for _ in 0..10_000 {
        std::hint::black_box(execute(POSEIDON2, &registers, &mut memory));
    }
    let started = Instant::now();
    // SAFETY: reading the time-stamp counter has no side effects.
    let tsc_start = unsafe { core::arch::x86_64::_rdtsc() };
    for _ in 0..CALLS {
        std::hint::black_box(execute(POSEIDON2, &registers, &mut memory));
    }
    // SAFETY: as above.
    let tsc = unsafe { core::arch::x86_64::_rdtsc() } - tsc_start;
    let elapsed = started.elapsed();

    let guest = vos_pvm_bench::guest_program("poseidon2");
    let gas_for = |n: u64| {
        let invocation = vos_pvm::refine_host::RefineContext::load(&guest, &n.to_le_bytes(), GAS)
            .expect("load")
            .without_precompiles()
            .run_with_host(|_, machine| {
                machine.registers_mut()[7] = vos_pvm_bench::WHAT;
                Ok(())
            });
        invocation.gas_used
    };
    let per_hash = (gas_for(101) - gas_for(1)) / 100;
    println!(
        "served Poseidon2 compression: {:.0} ns, {:.0} TSC cycles; in software in the guest, \
         its unserved call answered for free: {per_hash} gas",
        elapsed.as_nanos() as f64 / CALLS as f64,
        tsc as f64 / CALLS as f64,
    );
}
