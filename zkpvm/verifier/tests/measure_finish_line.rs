//! Session 1 (recursion-completion plan) — MEASURE THE FINISH LINE.
//!
//! Pure measurement of the two unmeasured goal-metrics for a *single light
//! segment* (Track A's unit of work, and one inner proof of Track B):
//!   1. VERIFY COST — serialized proof size (bincode, the on-wire format) +
//!      native `verify_standalone` wall-time.
//!   2. LIGHT-LEAF PROVE PEAK RAM — `VmHWM` (peak resident set) of one
//!      `prove_canonical`, swept over segment size via `STEPS`.
//!
//! A straight-line Add64 chain of `STEPS` instructions traps at the end and is
//! proven as ONE canonical 31-component segment, so `STEPS` is a direct knob on
//! single-segment trace size (the `SEG_STEPS` knob, but applied to a
//! one-segment program — `prove_canonical` proves the whole trace as one
//! segment).
//!
//! Feature-agnostic: build WITHOUT `poseidon2-channel` for the production
//! Blake2s/SimdBackend CEILING, WITH it for the Poseidon2-M31 CpuBackend+to_cpu
//! path (Track A's real stack). The harness prints which path it ran.
//!
//! Run (one measurement per process so `VmHWM` is clean):
//!   STEPS=7    cargo test -p zkpvm-verifier --release --test measure_finish_line \
//!                measure -- --exact --nocapture
//!   STEPS=7    cargo test -p zkpvm-verifier --release --features poseidon2-channel \
//!                --test measure_finish_line measure -- --exact --nocapture

use std::time::Instant;

use javm::PVM_REGISTER_COUNT;
use javm::instruction::Opcode;
use javm::interpreter::Interpreter;

use zkpvm::core::tracing::TracingPvm;
use zkpvm::{SideNote, program_commitment_of_proof, prove_canonical};
use zkpvm_verifier::{PcsPolicy, verify_standalone_with_pcs_policy};

/// `(steps - 1)` Add64-immediate instructions (3 bytes each) + a 1-byte Trap,
/// so the executed trace is exactly `steps` rows. Each Add64 adds 2 to a fixed
/// register (wrapping; state stays bounded) — only the step count matters.
fn build_chain(steps: usize) -> (Vec<u8>, Vec<u8>) {
    assert!(steps >= 1);
    let mut code = Vec::with_capacity(3 * steps);
    let mut bitmask = Vec::with_capacity(3 * steps);
    for _ in 0..steps - 1 {
        code.extend_from_slice(&[Opcode::Add64 as u8, 0x10, 2]);
        bitmask.extend_from_slice(&[1, 0, 0]);
    }
    code.push(Opcode::Trap as u8);
    bitmask.push(1);
    (code, bitmask)
}

/// One numeric field (in KiB) from `/proc/self/status`, e.g. `vm_kib("VmHWM:")`
/// = peak resident set ever held by this process.
fn vm_kib(key: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix(key)?.split_whitespace().next()?.parse().ok())
        .unwrap_or(0)
}

#[test]
fn measure() {
    let steps: usize = std::env::var("STEPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(7);
    let path = if cfg!(feature = "poseidon2-channel") {
        "poseidon2-m31/simd"
    } else {
        "blake2s/simd"
    };

    let (code, bitmask) = build_chain(steps);
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 100;
    regs[1] = 1;
    // The memory chip commits one row per 256-byte page, so the initial memory
    // size sets the memory commitment's log_size (4 MiB = 16384 pages = log14)
    // and, for a compute-light program, the whole proof. `MEM_KIB` knobs it so
    // a low-memory program (the realistic Track-A case) can be measured apart
    // from the memory floor. Default 4096 KiB matches the original harness.
    let mem_kib: usize = std::env::var("MEM_KIB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4096);
    let initial_memory = vec![0u8; mem_kib * 1024];
    let gas: u64 = (steps as u64) * 4 + 100_000;

    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        initial_memory.clone(),
        gas,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run(), javm::ExitReason::Trap, "program must Trap");
    let trace = tracing.into_trace();
    let actual_steps = trace.len();

    let mut sn = SideNote::new(trace, code, bitmask).with_memory(initial_memory);

    // SHAPE=natural → `prove_mobile` (only the chips this trace activates, at
    // natural sizes — the Track-A direct-on-chain path, which does NOT recurse
    // and so needs no canonical 31-chip shape). Default → `prove_canonical`
    // (all 31 chips forced, the Track-B / federation-allowlist shape).
    let natural = std::env::var("SHAPE").as_deref() == Ok("natural");
    let shape = if natural { "natural" } else { "canonical" };

    let t0 = Instant::now();
    let proof = if natural {
        zkpvm::prove_mobile(&mut sn).expect("prove_mobile")
    } else {
        prove_canonical(&mut sn, &[]).expect("prove_canonical")
    };
    let prove_ms = t0.elapsed().as_secs_f64() * 1e3;
    let peak_mib = vm_kib("VmHWM:") as f64 / 1024.0;
    let max_log = proof.log_sizes.iter().copied().max().unwrap_or(0);
    let n_components = proof.log_sizes.len();

    let bytes = bincode::serialize(&proof).expect("bincode serialize").len();

    let commitment = program_commitment_of_proof(&proof);
    let mut verify_ms = f64::INFINITY;
    for _ in 0..5 {
        let p = proof.clone();
        let t = Instant::now();
        verify_standalone_with_pcs_policy(p, commitment, &PcsPolicy::MOBILE).expect("verify");
        verify_ms = verify_ms.min(t.elapsed().as_secs_f64() * 1e3);
    }

    println!(
        "MEASURE path={path} shape={shape} steps={actual_steps} mem_kib={mem_kib} \
         max_log={max_log} n_components={n_components} prove_ms={prove_ms:.0} \
         peak_rss_MiB={peak_mib:.0} proof_bytes={bytes} verify_ms_min={verify_ms:.2}"
    );
}
