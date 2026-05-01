//! Proving benchmarks at various trace sizes, comparable to Nexus prover-benches.
//!
//! Run with: cargo test -p zkpvm-machine --release bench_prove_ -- --nocapture

use javm::instruction::Opcode;
use javm::interpreter::Interpreter;
use javm::PVM_REGISTER_COUNT;

use zkpvm::core::tracing::TracingPvm;
use zkpvm::{prove, prove_profiled, prove_with_config, verify, PcsConfig, FriConfig};

/// Generate a program with `n` sequential ADD64 instructions followed by Trap.
/// Each ADD cycles through registers to avoid data hazards.
fn generate_add_program(n: usize) -> (Vec<u8>, Vec<u8>) {
    let mut code = Vec::with_capacity(n * 3 + 1);
    let mut bitmask = Vec::with_capacity(n * 3 + 1);

    let mut ra: u8 = 0;
    let mut rb: u8 = 1;
    let mut rd: u8 = 2;

    for _ in 0..n {
        // Add64: 3 bytes [opcode, ra|(rb<<4), rd]
        code.push(Opcode::Add64 as u8);
        code.push(ra | (rb << 4));
        code.push(rd);
        bitmask.push(1);
        bitmask.push(0);
        bitmask.push(0);

        // Cycle registers (13 registers in PVM: 0..12)
        ra = (ra + 1) % 13;
        rb = (rb + 1) % 13;
        rd = (rd + 1) % 13;
    }

    // Trap at the end
    code.push(Opcode::Trap as u8);
    bitmask.push(1);

    (code, bitmask)
}

fn bench_at_log_size(log_size: u32) {
    let n_steps = 1usize << log_size;
    let (code, bitmask) = generate_add_program(n_steps);

    let mut regs = [0u64; PVM_REGISTER_COUNT];
    // Seed registers with small values
    for i in 0..13 {
        regs[i] = (i as u64) + 1;
    }

    let gas = (n_steps as u64 + 100) * 100;
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 64 * 1024],
        gas,
        16, // mem_cycles
    );

    let t0 = std::time::Instant::now();
    let mut tracing = TracingPvm::new(pvm);
    let _exit = tracing.run();
    let steps = tracing.into_trace();
    let trace_time = t0.elapsed();

    // n_steps ADDs + 1 Trap
    assert!(
        steps.len() >= n_steps,
        "expected at least {} steps, got {}",
        n_steps,
        steps.len()
    );

    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask);

    let t1 = std::time::Instant::now();
    let proof = prove(&mut side_note).expect("proving failed");
    let prove_time = t1.elapsed();

    let proof_bytes = bincode::serialize(&proof).unwrap();
    let proof_kb = proof_bytes.len() as f64 / 1024.0;

    let t2 = std::time::Instant::now();
    verify(proof, &side_note).expect("verification failed");
    let verify_time = t2.elapsed();

    eprintln!(
        "LogSize={log_size:>2} | steps={n_steps:>6} | trace={trace_time:>10.2?} | prove={prove_time:>10.2?} | verify={verify_time:>10.2?} | total={:>10.2?} | proof={proof_kb:>6.1} KB",
        trace_time + prove_time + verify_time,
    );
}

fn profile_at_log_size(log_size: u32) {
    let n_steps = 1usize << log_size;
    let (code, bitmask) = generate_add_program(n_steps);

    let mut regs = [0u64; PVM_REGISTER_COUNT];
    for i in 0..13 { regs[i] = (i as u64) + 1; }

    let gas = (n_steps as u64 + 100) * 100;
    let pvm = Interpreter::new(
        code.clone(), bitmask.clone(), vec![], regs,
        vec![0u8; 64 * 1024], gas, 16,
    );

    let mut tracing = TracingPvm::new(pvm);
    let _exit = tracing.run();
    let steps = tracing.into_trace();

    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask);

    eprintln!("=== LogSize={log_size} ({n_steps} steps) ===");
    let (proof, _) = prove_profiled(&mut side_note).expect("proving failed");

    let proof_bytes = bincode::serialize(&proof).unwrap();
    eprintln!("Proof size: {} bytes ({:.1} KB)", proof_bytes.len(), proof_bytes.len() as f64 / 1024.0);

    verify(proof, &side_note).expect("verification failed");
}

#[test]
fn profile_log10() { profile_at_log_size(10); }

#[test]
fn profile_log14() { profile_at_log_size(14); }

/// Sweep log_sizes with test-config (8-bit security) to find the scale breaking point.
#[test]
fn scale_sweep() {
    let test_config = PcsConfig { pow_bits: 5, fri_config: FriConfig::new(0, 1, 3) };
    eprintln!("=== Scale sweep (test security, rough memory estimate) ===");
    eprintln!("  main_cols=286, interaction_cols=~90, constraint_blowup=4");
    eprintln!();
    for log_size in [10, 12, 14, 16, 17, 18, 19].iter() {
        let n_steps = 1usize << log_size;
        let (code, bitmask) = generate_add_program(n_steps);
        let mut regs = [0u64; PVM_REGISTER_COUNT];
        for i in 0..13 { regs[i] = (i as u64) + 1; }
        let gas = (n_steps as u64 + 100) * 100;
        let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, vec![0u8; 64 * 1024], gas, 16);
        let mut tracing = TracingPvm::new(pvm);
        let _exit = tracing.run();
        let steps = tracing.into_trace();
        let mut side_note = zkpvm::SideNote::new(steps, code, bitmask);

        let t = std::time::Instant::now();
        match zkpvm::prove_with_config(&mut side_note, test_config) {
            Ok(p) => {
                let elapsed = t.elapsed();
                let kb = bincode::serialize(&p).unwrap().len() as f64 / 1024.0;
                // Rough memory estimate: main + interaction + quotient at blowup*4
                let rows = 1u64 << log_size;
                let fft_rows = rows * 16; // constraint blowup 2^4
                let field_bytes = 4u64;
                let main_mb = rows * 286 * field_bytes / (1024 * 1024);
                let fft_mb = fft_rows * 286 * field_bytes / (1024 * 1024);
                eprintln!("  log_size={log_size:>2} ({n_steps:>7} steps): prove={elapsed:>8.2?}, proof={kb:>5.1} KB, main_trace≈{main_mb}MB, fft_domain≈{fft_mb}MB");
            }
            Err(e) => { eprintln!("  log_size={log_size:>2} ({n_steps:>7} steps): FAIL {e}"); break; }
        }
    }
}

// ── Security parameter benchmarks ──

fn bench_security(log_size: u32, pow_bits: u32, log_blowup: u32, n_queries: usize) {
    let n_steps = 1usize << log_size;
    let (code, bitmask) = generate_add_program(n_steps);
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    for i in 0..13 { regs[i] = (i as u64) + 1; }
    let gas = (n_steps as u64 + 100) * 100;
    let pvm = Interpreter::new(
        code.clone(), bitmask.clone(), vec![], regs,
        vec![0u8; 64 * 1024], gas, 16,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _exit = tracing.run();
    let steps = tracing.into_trace();
    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask);

    let config = PcsConfig { pow_bits, fri_config: FriConfig::new(0, log_blowup, n_queries) };
    let sec_bits = config.security_bits();

    let t = std::time::Instant::now();
    let proof = prove_with_config(&mut side_note, config).expect("proving failed");
    let prove_time = t.elapsed();

    let proof_bytes = bincode::serialize(&proof).unwrap();
    let proof_kb = proof_bytes.len() as f64 / 1024.0;

    let t = std::time::Instant::now();
    verify(proof, &side_note).expect("verification failed");
    let verify_time = t.elapsed();

    eprintln!(
        "  blowup=2^{log_blowup} queries={n_queries:>2} pow={pow_bits:>2} => {sec_bits:>3}-bit | prove={prove_time:>10.2?} | verify={verify_time:>8.2?} | proof={proof_kb:>6.1} KB"
    );
}

#[test]
fn security_sweep_log12() {
    let log = 12;
    eprintln!("=== Security sweep at LogSize={log} (4096 steps) ===");
    // Baseline (test-only)
    bench_security(log, 5, 1, 3);
    // ~50-bit (development)
    bench_security(log, 16, 2, 17);
    // ~80-bit (light production)
    bench_security(log, 20, 3, 20);
    // ~96-bit (standard production)
    bench_security(log, 20, 4, 19);
    // ~128-bit (high security)
    bench_security(log, 26, 4, 26);
}

#[test]
fn bench_prove_log05() {
    bench_at_log_size(5);
}

#[test]
fn bench_prove_log08() {
    bench_at_log_size(8);
}

#[test]
fn bench_prove_log10() {
    bench_at_log_size(10);
}

#[test]
fn bench_prove_log12() {
    bench_at_log_size(12);
}

#[test]
fn bench_prove_log14() {
    bench_at_log_size(14);
}

// `cargo test --workspace` runs every `#[test]` by default; log16 needs
// ≥16 GB of RAM and OOMs on smaller hosts.  Mark `#[ignore]` so the
// default sweep doesn't trip on it; run explicitly with `cargo test
// --test bench_prove bench_prove_log16 -- --ignored --nocapture` on a
// box with the headroom.
#[test]
#[ignore = "needs ≥16 GB RAM; run explicitly with --ignored"]
fn bench_prove_log16() {
    bench_at_log_size(16);
}
