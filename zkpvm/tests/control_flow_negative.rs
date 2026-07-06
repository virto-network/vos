#![cfg(feature = "prover")]

//! Negative-test corpus for CpuChip's control-flow constraints.
//!
//! Each test crafts an honest branch trace, mutates a control-flow
//! witness column (branch_taken, next_pc), and asserts prove+verify
//! fails.  Together they pin down the branch-decision constraints.

mod common;
use common::*;

use javm::PVM_REGISTER_COUNT;
use javm::instruction::Opcode;
use javm::interpreter::Interpreter;

use zkpvm::core::tracing::TracingPvm;

/// Build a BranchEq program: BranchEq φ[0], φ[1] → +5; then Trap at pc=5.
fn branch_eq_program() -> (Vec<u8>, Vec<u8>) {
    let code = vec![Opcode::BranchEq as u8, 0x10, 5, 0, 0, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 0, 0, 1];
    (code, bitmask)
}

fn trace_branch_eq(rv0: u64, rv1: u64) -> (Vec<u8>, Vec<u8>, Vec<zkpvm::core::step::PvmStep>) {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = rv0;
    regs[1] = rv1;
    let (code, bitmask) = branch_eq_program();
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
    let _ = tr.run();
    (code, bitmask, tr.into_trace())
}

/// Build a Branch program where target ≠ fallthrough: branch at pc=0 with
/// offset=6 → target=6; sequential next_pc = 0 + 1 + 4 = 5 → fallthrough=5.
/// Layout:
///   pc=0..4: BranchXX + reg_byte (0x10) + 3-byte offset (= 6)
///   pc=5:    Trap (fallthrough basic-block start)
///   pc=6:    Trap (target basic-block start)
fn branch_program(op: Opcode) -> (Vec<u8>, Vec<u8>) {
    let code = vec![
        op as u8,
        0x10,
        6,
        0,
        0,
        Opcode::Trap as u8,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1, 1];
    (code, bitmask)
}

fn trace_branch(
    op: Opcode,
    rv0: u64,
    rv1: u64,
) -> (Vec<u8>, Vec<u8>, Vec<zkpvm::core::step::PvmStep>) {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = rv0;
    regs[1] = rv1;
    let (code, bitmask) = branch_program(op);
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
    let _ = tr.run();
    (code, bitmask, tr.into_trace())
}

// ── BranchEq ───────────────────────────────────────────────────────────────
//
// NOTE on tracer's branch_taken semantics:
//   `branch_taken = !exit && next_pc != sequential_next_pc`
// So a branch whose target equals the fallthrough (offset = skip_len + 1)
// records branch_taken = false even when the comparison succeeds.  The
// existing tests/control_flow.rs::prove_branch_eq_taken sets up exactly
// this case (offset=5, sequential_pc=5).  These negative tests use the
// same setup; "forged taken" therefore means the prover claims a branch
// was taken when the AIR knows it shouldn't have been.

#[test]
fn branch_eq_positive_smoke() {
    // Equal regs: at offset=5 the target == sequential_next_pc → tracer
    // records branch_taken = false.  Verifier still accepts the proof.
    let (code, bitmask, steps) = trace_branch_eq(42, 42);
    assert!(!steps[0].branch_taken);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn branch_eq_unequal_smoke() {
    let (code, bitmask, steps) = trace_branch_eq(42, 99);
    assert!(!steps[0].branch_taken);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn branch_eq_forged_taken_when_not_equal_rejected() {
    // val_b ≠ val_d (42 ≠ 99) — honest branch_taken = false.  Forge it to
    // true: the AIR's branch-decision constraint pins branch_taken to the
    // equality flag, so the forge should fail.
    let (code, bitmask, mut steps) = trace_branch_eq(42, 99);
    steps[0].branch_taken = true;
    prove_and_verify(steps, &code, &bitmask);
}

// Documented (intentional, not a gap): when a BranchEq's target equals
// sequential_next_pc, branch_taken=0 and branch_taken=1 are
// observationally identical — both produce the same next_pc and the
// rest of the trace is unaffected.  PVM's branch_taken witness reflects
// "PC took the offset path", not "the comparison succeeded"; tightening
// it to `branch_taken = eq_flag` would conflict with the tracer's
// convention without changing what the proof attests to.  Test pins
// the current behaviour.
#[test]
fn branch_eq_target_equals_fallthrough_branch_taken_unconstrained() {
    let (code, bitmask, mut steps) = trace_branch_eq(42, 42);
    steps[0].branch_taken = true;
    prove_and_verify(steps, &code, &bitmask);
}

// ── BranchNe ─────────────────────────────────────────────────────────────
//
// BranchNe constraint (asymmetric):
//     is_br_ne · (1 - branch_taken) · (1 - byte_eq[i]) = 0
// Reads: IF branch_taken=0, THEN val_b == val_d.  Contrapositive: val_b
// ≠ val_d ⇒ branch_taken=1.  Strict direction caught (claim "not taken"
// when values differ).  Loose direction (claim "taken" when values
// equal) intentionally unconstrained — same rationale as BranchEq.

#[test]
fn branch_ne_unequal_smoke() {
    // 42 ≠ 99 → branch taken to pc=6 (target=6, fallthrough=5).
    let (code, bitmask, steps) = trace_branch(Opcode::BranchNe, 42, 99);
    assert!(steps[0].branch_taken);
    assert_eq!(steps[0].next_pc, 6);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn branch_ne_equal_smoke() {
    // 42 == 42 → fall through to pc=5.
    let (code, bitmask, steps) = trace_branch(Opcode::BranchNe, 42, 42);
    assert!(!steps[0].branch_taken);
    assert_eq!(steps[0].next_pc, 5);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn branch_ne_forged_not_taken_when_unequal_rejected() {
    // val_b ≠ val_d → AIR demands branch_taken=1.  Forge to (false, 5).
    let (code, bitmask, mut steps) = trace_branch(Opcode::BranchNe, 42, 99);
    steps[0].branch_taken = false;
    steps[0].next_pc = 5;
    prove_and_verify(steps, &code, &bitmask);
}

// ── BranchLtU ────────────────────────────────────────────────────────────
//
// BranchLtU constraint (strict): branch_taken == cmp_lt_flag.

#[test]
fn branch_lt_u_taken_smoke() {
    // 100 <_u 200 → cmp_lt_flag=1 → branch taken.
    let (code, bitmask, steps) = trace_branch(Opcode::BranchLtU, 100, 200);
    assert!(steps[0].branch_taken);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn branch_lt_u_not_taken_smoke() {
    // 200 ≮_u 100 → cmp_lt_flag=0 → branch not taken.
    let (code, bitmask, steps) = trace_branch(Opcode::BranchLtU, 200, 100);
    assert!(!steps[0].branch_taken);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn branch_lt_u_forged_not_taken_when_lt_rejected() {
    let (code, bitmask, mut steps) = trace_branch(Opcode::BranchLtU, 100, 200);
    steps[0].branch_taken = false;
    steps[0].next_pc = 5;
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn branch_lt_u_forged_taken_when_ge_rejected() {
    let (code, bitmask, mut steps) = trace_branch(Opcode::BranchLtU, 200, 100);
    steps[0].branch_taken = true;
    steps[0].next_pc = 6;
    prove_and_verify(steps, &code, &bitmask);
}

// ── BranchGeU ────────────────────────────────────────────────────────────
//
// BranchGeU constraint (strict): branch_taken == 1 - cmp_lt_flag.

#[test]
fn branch_ge_u_taken_smoke() {
    let (code, bitmask, steps) = trace_branch(Opcode::BranchGeU, 200, 100);
    assert!(steps[0].branch_taken);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn branch_ge_u_not_taken_smoke() {
    let (code, bitmask, steps) = trace_branch(Opcode::BranchGeU, 100, 200);
    assert!(!steps[0].branch_taken);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn branch_ge_u_forged_not_taken_when_ge_rejected() {
    let (code, bitmask, mut steps) = trace_branch(Opcode::BranchGeU, 200, 100);
    steps[0].branch_taken = false;
    steps[0].next_pc = 5;
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn branch_ge_u_forged_taken_when_lt_rejected() {
    let (code, bitmask, mut steps) = trace_branch(Opcode::BranchGeU, 100, 200);
    steps[0].branch_taken = true;
    steps[0].next_pc = 6;
    prove_and_verify(steps, &code, &bitmask);
}

// ── BranchLtS ────────────────────────────────────────────────────────────
//
// BranchLtS constraint (strict): branch_taken == cmp_lt_s_flag.
// -1 represented as 0xFFFF_FFFF_FFFF_FFFF (twos complement).

#[test]
fn branch_lt_s_negative_lt_zero_smoke() {
    let (code, bitmask, steps) = trace_branch(Opcode::BranchLtS, 0xFFFF_FFFF_FFFF_FFFF, 0);
    assert!(steps[0].branch_taken);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn branch_lt_s_zero_ge_negative_smoke() {
    let (code, bitmask, steps) = trace_branch(Opcode::BranchLtS, 0, 0xFFFF_FFFF_FFFF_FFFF);
    assert!(!steps[0].branch_taken);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn branch_lt_s_forged_not_taken_when_lt_rejected() {
    let (code, bitmask, mut steps) = trace_branch(Opcode::BranchLtS, 0xFFFF_FFFF_FFFF_FFFF, 0);
    steps[0].branch_taken = false;
    steps[0].next_pc = 5;
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn branch_lt_s_forged_taken_when_ge_rejected() {
    let (code, bitmask, mut steps) = trace_branch(Opcode::BranchLtS, 0, 0xFFFF_FFFF_FFFF_FFFF);
    steps[0].branch_taken = true;
    steps[0].next_pc = 6;
    prove_and_verify(steps, &code, &bitmask);
}

// ── BranchGeS ────────────────────────────────────────────────────────────
//
// BranchGeS constraint (strict): branch_taken == 1 - cmp_lt_s_flag.

#[test]
fn branch_ge_s_zero_ge_negative_smoke() {
    let (code, bitmask, steps) = trace_branch(Opcode::BranchGeS, 0, 0xFFFF_FFFF_FFFF_FFFF);
    assert!(steps[0].branch_taken);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn branch_ge_s_negative_lt_zero_smoke() {
    let (code, bitmask, steps) = trace_branch(Opcode::BranchGeS, 0xFFFF_FFFF_FFFF_FFFF, 0);
    assert!(!steps[0].branch_taken);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn branch_ge_s_forged_not_taken_when_ge_rejected() {
    let (code, bitmask, mut steps) = trace_branch(Opcode::BranchGeS, 0, 0xFFFF_FFFF_FFFF_FFFF);
    steps[0].branch_taken = false;
    steps[0].next_pc = 5;
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn branch_ge_s_forged_taken_when_lt_rejected() {
    let (code, bitmask, mut steps) = trace_branch(Opcode::BranchGeS, 0xFFFF_FFFF_FFFF_FFFF, 0);
    steps[0].branch_taken = true;
    steps[0].next_pc = 6;
    prove_and_verify(steps, &code, &bitmask);
}
