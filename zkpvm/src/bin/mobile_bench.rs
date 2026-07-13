//! Minimal on-device proving benchmark: trace + prove + verify a tiny
//! ADD-chain fixture under the MOBILE PCS config, reporting wall-clock
//! times and peak RSS.  This is the artifact to cross-compile and push
//! to a phone for the ARM bring-up numbers (reference x86 point:
//! log14 MOBILE ≈ 1.5 s with target-cpu=native).
//!
//!     cargo build --release -p zkpvm --bin mobile_bench \
//!         --target aarch64-unknown-linux-gnu
//!     ./mobile_bench [log2-steps]     # default 14
//!
//! A `[[bin]]` rather than an example so a cross-build pulls only the
//! prover's own dependency tree (examples build against dev-deps).

use javm::PVM_REGISTER_COUNT;
use javm::instruction::Opcode;
use javm::interpreter::Interpreter;

use zkpvm::core::tracing::TracingPvm;
use zkpvm::{PcsPolicy, SideNote, prove_mobile, verify_with_pcs_policy};

/// `n` sequential ADD64 instructions (registers cycled to avoid data
/// hazards) followed by Trap — the same fixture shape as the
/// `bench_prove_log*` entries in `benches/prove.rs`.
fn generate_add_program(n: usize) -> (Vec<u8>, Vec<u8>) {
    let mut code = Vec::with_capacity(n * 3 + 1);
    let mut bitmask = Vec::with_capacity(n * 3 + 1);
    let (mut ra, mut rb, mut rd) = (0u8, 1u8, 2u8);
    for _ in 0..n {
        code.push(Opcode::Add64 as u8);
        code.push(ra | (rb << 4));
        code.push(rd);
        bitmask.extend_from_slice(&[1, 0, 0]);
        ra = (ra + 1) % 13;
        rb = (rb + 1) % 13;
        rd = (rd + 1) % 13;
    }
    code.push(Opcode::Trap as u8);
    bitmask.push(1);
    (code, bitmask)
}

/// A `VmHWM`-style line from /proc/self/status, in MiB (Linux and
/// Android both expose it); None elsewhere.
fn proc_status_mib(key: &str) -> Option<f64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with(key))?;
    let kib: f64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib / 1024.0)
}

fn main() {
    let log_size: u32 = std::env::args()
        .nth(1)
        .map(|a| a.parse().expect("usage: mobile_bench [log2-steps]"))
        .unwrap_or(14);
    let n_steps = 1usize << log_size;
    println!(
        "mobile_bench: arch={} log_size={log_size} ({n_steps} steps), MOBILE config",
        std::env::consts::ARCH
    );

    // Trace.
    let (code, bitmask) = generate_add_program(n_steps);
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    for (i, r) in regs.iter_mut().take(13).enumerate() {
        *r = (i as u64) + 1;
    }
    let gas = (n_steps as u64 + 100) * 100;
    let t = std::time::Instant::now();
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 64 * 1024],
        gas,
        16,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _exit = tracing.run();
    let steps = tracing.into_trace();
    assert!(steps.len() >= n_steps, "trace shorter than fixture");
    let mut side_note = SideNote::new(steps, code, bitmask);
    let trace_time = t.elapsed();

    // Prove (MOBILE PCS config: blowup=4, q=38, pow=20 — 96 bits).
    let t = std::time::Instant::now();
    let proof = prove_mobile(&mut side_note).expect("prove_mobile failed");
    let prove_time = t.elapsed();

    // Verify under the matching policy: a cheap cross-ISA correctness
    // gate — a NEON/codegen bug shows up here as a rejected proof.
    let t = std::time::Instant::now();
    verify_with_pcs_policy(proof, &side_note, &PcsPolicy::MOBILE).expect("verify failed");
    let verify_time = t.elapsed();

    println!("trace  = {trace_time:>10.2?}");
    println!("prove  = {prove_time:>10.2?}");
    println!("verify = {verify_time:>10.2?}");
    match (proc_status_mib("VmHWM"), proc_status_mib("VmRSS")) {
        (Some(hwm), Some(rss)) => println!("peak RSS = {hwm:.1} MiB (current {rss:.1} MiB)"),
        _ => println!("peak RSS = unavailable (no /proc/self/status)"),
    }
}
