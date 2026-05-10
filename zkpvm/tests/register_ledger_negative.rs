//! Negative-test corpus for the register-memory ledger
//! (RegisterMemoryChip + CpuChip producers — Phase 9 architecture).
//!
//! These tests target a *different* soundness layer than tests/alu_negative.rs.
//! The ALU-negative corpus forges `regs_after[rd]` on a one-step program;
//! the row's own value-level constraint catches the bad result because
//! `result = f(val_b, val_d)` is checked locally.
//!
//! This file forges register values *across* steps — step 1 writes
//! `regs_after[k] = honest`, step 2's `regs_before[k] = forged`.  The
//! value-level constraint at step 2 is kept satisfied by also forging
//! `regs_after` so that the (forged) `result = f(val_b, val_d)` holds.
//! Only the cross-step register ledger should catch the mismatch
//! between step 1's producer tuple `(k, honest, ts1)` and step 2's
//! consumer tuple `(k, forged, ts1)` — they share the same idx and
//! "last-write timestamp" but differ in value, so the logup balance
//! breaks.
//!
//! These tests pin down that the ledger actually fires on cross-step
//! register inconsistencies, not just intra-row value mismatches.

mod common;
use common::*;

use javm::PVM_REGISTER_COUNT;
use javm::instruction::Opcode;
use javm::interpreter::Interpreter;

use zkpvm::core::step::PvmStep;
use zkpvm::core::tracing::TracingPvm;

/// Build a 2-step program:
///   pc=0: Add64 φ[2] = φ[0] + φ[1]      (ra=0, rb=1, rd=2)
///   pc=3: Add64 φ[3] = φ[2] + φ[2]      (ra=2, rb=2, rd=3)
///   pc=6: Trap
fn two_step_add_program() -> (Vec<u8>, Vec<u8>) {
    let code = vec![
        Opcode::Add64 as u8,
        0x10,
        2, // ra=0, rb=1, rd=2
        Opcode::Add64 as u8,
        0x22,
        3, // ra=2, rb=2, rd=3
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 1, 0, 0, 1];
    (code, bitmask)
}

fn trace_two_step(rv0: u64, rv1: u64) -> (Vec<u8>, Vec<u8>, Vec<PvmStep>) {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = rv0;
    regs[1] = rv1;
    let (code, bitmask) = two_step_add_program();
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10_000,
        25,
    );
    let mut tr = TracingPvm::new(pvm);
    let exit = tr.run();
    assert_eq!(exit, javm::ExitReason::Trap);
    let steps = tr.into_trace();
    assert_eq!(steps.len(), 3, "expected Add, Add, Trap");
    assert_eq!(steps[0].opcode, Opcode::Add64);
    assert_eq!(steps[1].opcode, Opcode::Add64);
    (code, bitmask, steps)
}

#[test]
fn two_step_add_positive_smoke() {
    // Sanity: 5 + 7 = 12, then 12 + 12 = 24.
    let (code, bitmask, steps) = trace_two_step(5, 7);
    assert_eq!(steps[0].regs_after[2], 12);
    assert_eq!(steps[1].regs_before[2], 12);
    assert_eq!(steps[1].regs_after[3], 24);
    prove_and_verify(steps, &code, &bitmask);
}

// Forge step 2's view of φ[2] (both as val_b and val_d, since reg_a=
// reg_b=2).  Keep step 2's regs_after[3] consistent with the forge so
// the row-local Add constraint `result = val_b + val_d` is satisfied
// (100 + 100 = 200).  The ledger consumer at step 2 emits
// (idx=2, value=100, ts=ts_of_last_write_to_2=1), but the producer
// at step 1 emitted (idx=2, value=12, ts=1) — different value → no
// matching producer → imbalance → reject.
#[test]
#[should_panic(expected = "failed")]
fn forged_regs_before_breaks_ledger() {
    let (code, bitmask, mut steps) = trace_two_step(5, 7);
    steps[1].regs_before[2] = 100;
    steps[1].regs_after[3] = 200; // 100 + 100, keeps row-local Add happy
    prove_and_verify(steps, &code, &bitmask);
}

// Symmetric variant: forge step 1's regs_after.  The producer tuple
// becomes (2, 999, 1); but step 1's row-local Add constraint
// (result = val_b + val_d = 5 + 7 = 12) catches the mismatch directly,
// so it's the value-level constraint — not the ledger — that fires.
// Pinned here mostly to assert that *some* constraint catches; the
// cleaner ledger-only test is the one above.
#[test]
#[should_panic(expected = "failed")]
fn forged_regs_after_step1_rejected() {
    let (code, bitmask, mut steps) = trace_two_step(5, 7);
    steps[0].regs_after[2] = 999;
    prove_and_verify(steps, &code, &bitmask);
}

// Forge a register that is NOT touched by either Add: φ[5].  Both
// regs_before[5] and regs_after[5] are 0 throughout the honest trace.
// Forging step 2's regs_after[5] = 1 (without any matching producer)
// should cause a ledger imbalance — but only if the AIR considers
// regs_after[5] live for non-write steps.  The ledger only emits a
// result_write for step.reg_write = Some(5), which Add64 to φ[3]
// doesn't trigger.  So this forge is *invisible* to the ledger and
// should NOT be rejected — pinned as a documented gap (the AIR
// authenticates only registers actually accessed at each step; idle
// registers' regs_before/regs_after can drift freely without a
// corresponding consumer to balance against).
#[test]
fn forged_idle_register_silently_accepted() {
    let (code, bitmask, mut steps) = trace_two_step(5, 7);
    // Mutate a register neither Add reads nor writes.
    steps[1].regs_after[5] = 0xDEAD_BEEF;
    // Honest verification path: this should still prove + verify, since
    // φ[5] is not in any consumer/producer tuple at step 2.
    prove_and_verify(steps, &code, &bitmask);
}
