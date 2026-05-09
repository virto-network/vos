//! Multi-segment proving + `verify_chain` end-to-end.
//!
//! Demonstrates the streaming-proof workflow for executions that
//! exceed a single proof's log_size cap (or just for parallel
//! proving across N workers).  The execution is traced once, sliced
//! into N segments, each segment is proven independently, and the
//! resulting proofs are verified together via `verify_chain`.
//!
//! `verify_chain` checks two things:
//!
//! 1. **Per-proof validity** — each segment's proof verifies
//!    against its own SideNote (same as the single-segment
//!    `verify` path).
//!
//! 2. **Boundary continuity** — segment N's `final_state` must
//!    equal segment N+1's `initial_state`, byte-for-byte (pc,
//!    timestamp, registers, memory_commitment).
//!
//! The boundary states are produced by `prove` directly from the
//! per-segment trace's first/last steps and the side note's
//! initial memory, so the prover can't fabricate them: a segment
//! whose ledger-implied final regs don't match the next segment's
//! initial regs will fail (1), and a chain whose segments don't
//! line up in pc/ts/regs/memory will fail (2).
//!
//! Run from the workspace root:
//!     cargo run -p zkpvm --example multi_segment --release

use javm::ExitReason;
use javm::PVM_REGISTER_COUNT;
use javm::instruction::Opcode;
use javm::interpreter::Interpreter;

use zkpvm::core::tracing::TracingPvm;
use zkpvm::{SideNote, prove, verify_chain};

fn main() {
    println!("zkpvm multi_segment example");
    println!();

    // ── Step 1: build a long-ish program ───────────────────────────
    // Six Add64 instructions chained through registers, then Trap.
    // Total: 7 steps.  We'll cut after step 3 so segment 1 has 3
    // steps and segment 2 has 4 steps (Add Add Add Trap).
    //
    // Add64 reg_byte format: ra | (rb << 4); third byte = rd.
    // regs[2] = regs[0] + regs[1]
    // regs[3] = regs[2] + regs[1]
    // regs[4] = regs[3] + regs[1]
    // regs[5] = regs[4] + regs[1]
    // regs[6] = regs[5] + regs[1]
    // regs[7] = regs[6] + regs[1]
    let code = vec![
        Opcode::Add64 as u8,
        0x10,
        2,
        Opcode::Add64 as u8,
        0x12,
        3,
        Opcode::Add64 as u8,
        0x13,
        4,
        Opcode::Add64 as u8,
        0x14,
        5,
        Opcode::Add64 as u8,
        0x15,
        6,
        Opcode::Add64 as u8,
        0x16,
        7,
        Opcode::Trap as u8,
    ];
    let bitmask: Vec<u8> = vec![1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1];

    // ── Step 2: trace the full execution ───────────────────────────
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 100; // initial accumulator value
    regs[1] = 1; // increment
    let initial_memory = vec![0u8; 4 * 1024 * 1024];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        initial_memory.clone(),
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, ExitReason::Trap, "expected Trap exit");
    let all_steps = tracing.into_trace();
    println!("Traced {} steps total", all_steps.len());
    assert_eq!(all_steps.len(), 7);
    println!(
        "  regs[7] after full trace = {} (expected {})",
        all_steps.last().unwrap().regs_after[7],
        100 + 6,
    );

    // ── Step 3: slice into two segments ────────────────────────────
    // Segment 1: steps[0..3] — three Add64s.  Initial state derives
    //   from steps[0].regs_before automatically.
    // Segment 2: steps[3..7] — three more Add64s + Trap.  Its
    //   initial regs must equal segment 1's final regs (the boundary
    //   continuity check verify_chain enforces).
    let cut = 3;
    let (seg1_steps, seg2_steps) = all_steps.split_at(cut);
    println!(
        "Segment 1: steps[0..{cut}] ({} steps); Segment 2: steps[{cut}..{}] ({} steps)",
        seg1_steps.len(),
        all_steps.len(),
        seg2_steps.len(),
    );

    // ── Step 4: per-segment SideNote → prove ───────────────────────
    // Segment 1 starts from the original regs.  Segment 2 starts
    // from the regs at the cut point (= seg1_steps.last().regs_after
    // = seg2_steps[0].regs_before).
    //
    // Initial memory is the same (no memory writes in this program).
    // For programs that DO write memory across the cut, segment 2's
    // initial_memory would need to be initial_memory + segment-1
    // writes applied (which compute_final_memory_commitment in
    // prove.rs computes for the boundary commitment).
    let mut sn1 = SideNote::new(seg1_steps.to_vec(), code.clone(), bitmask.clone())
        .with_memory(initial_memory.clone());
    let mut sn2 = SideNote::new(seg2_steps.to_vec(), code.clone(), bitmask.clone())
        .with_memory(initial_memory.clone());

    let t = std::time::Instant::now();
    let proof1 = prove(&mut sn1).expect("prove segment 1 failed");
    let dt1 = t.elapsed();
    let t = std::time::Instant::now();
    let proof2 = prove(&mut sn2).expect("prove segment 2 failed");
    let dt2 = t.elapsed();
    println!("Proved segment 1 in {dt1:.2?}; segment 2 in {dt2:.2?}");

    // ── Step 5: inspect boundary states ────────────────────────────
    println!();
    println!("Boundary states:");
    println!(
        "  seg1.initial_state: pc={}, ts={}, regs[7]={}",
        proof1.initial_state.pc, proof1.initial_state.timestamp, proof1.initial_state.registers[7]
    );
    println!(
        "  seg1.final_state:   pc={}, ts={}, regs[7]={}",
        proof1.final_state.pc, proof1.final_state.timestamp, proof1.final_state.registers[7]
    );
    println!(
        "  seg2.initial_state: pc={}, ts={}, regs[7]={}",
        proof2.initial_state.pc, proof2.initial_state.timestamp, proof2.initial_state.registers[7]
    );
    println!(
        "  seg2.final_state:   pc={}, ts={}, regs[7]={}",
        proof2.final_state.pc, proof2.final_state.timestamp, proof2.final_state.registers[7]
    );

    // Assert the chain links up at the prover side (verify_chain
    // will check this independently below; the assertion here is
    // just to make the example's intent obvious).
    assert_eq!(
        proof1.final_state, proof2.initial_state,
        "segment boundary mismatch — prove() should not have returned proofs that don't chain"
    );

    // ── Step 6: verify_chain ───────────────────────────────────────
    // Pass [proof1, proof2] + [&sn1, &sn2].  verify_chain runs
    // verify per segment AND checks final_state == next initial_state.
    let t = std::time::Instant::now();
    verify_chain(&[proof1.clone(), proof2.clone()], &[&sn1, &sn2]).expect("verify_chain failed");
    println!("verify_chain ([2 segments]): ok ({:.2?})", t.elapsed());

    // ── Step 7: demonstrate a broken chain is rejected ─────────────
    // Forge segment 2's initial_state.timestamp by 1.  verify_chain
    // checks final_state == next initial_state byte-wise, so any
    // mismatch is rejected before per-segment verification even runs.
    let mut proof2_forged = proof2.clone();
    proof2_forged.initial_state.timestamp += 1;
    let err = verify_chain(&[proof1, proof2_forged], &[&sn1, &sn2])
        .expect_err("forged-chain verify_chain must reject");
    println!("forged-chain rejection: {err:?}");

    println!();
    println!("All checks passed.");
}
