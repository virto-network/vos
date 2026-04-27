//! Test helpers shared across `tests/*.rs` integration tests.
//!
//! Cargo treats files directly under `tests/` as separate test binaries, but
//! `tests/common/mod.rs` is included via `mod common;` in each binary without
//! triggering a duplicate-binary warning.  Callers do `mod common;` then
//! `use common::*;`.

use javm::instruction::Opcode;
use javm::interpreter::Interpreter;
use javm::PVM_REGISTER_COUNT;

use zkpvm::core::step::PvmStep;
use zkpvm::core::tracing::TracingPvm;
use zkpvm::{prove, verify};

/// Default flat memory size used by every helper here.  4 MB is enough for
/// every existing test program; bump per-call if a future test needs more.
const DEFAULT_FLAT_MEM: usize = 4 * 1024 * 1024;

/// Default gas + max-steps that programs run with.  Generous because tests
/// typically have ≤ 50 steps.
const DEFAULT_GAS: u64 = 10_000;
const DEFAULT_MAX_STEPS: u8 = 25;

/// Encode a TwoReg instruction at `code[0..2]`: opcode byte then a packed
/// register byte where `rd` lands in the low 4 bits and `ra` in the high 4.
/// JAVM's TwoReg category covers all the BitManip ops, MoveReg, and the
/// 2-arg variants that don't take an immediate.
///
/// The returned `(code, bitmask)` ends with `Trap` so the trace terminates
/// cleanly.  Bitmask follows `[1, 0, 1]`: byte 0 starts a basic block (the
/// real op), byte 1 is the inline reg byte (not a basic-block start),
/// byte 2 starts the next basic block (Trap).
pub fn two_reg_program(op: Opcode, rd: u8, ra: u8) -> (Vec<u8>, Vec<u8>) {
    assert!(rd < 13, "rd out of range (PVM has 13 registers)");
    assert!(ra < 13, "ra out of range (PVM has 13 registers)");
    let reg_byte = (ra << 4) | (rd & 0xF);
    let code = vec![op as u8, reg_byte, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 1];
    (code, bitmask)
}

/// Run a program in the tracing interpreter and return the recorded steps.
/// Asserts the program exits with `Trap` (the canonical happy-path
/// terminator for these tests).
pub fn trace_until_trap(
    code: Vec<u8>,
    bitmask: Vec<u8>,
    regs: [u64; PVM_REGISTER_COUNT],
) -> Vec<PvmStep> {
    let pvm = Interpreter::new(
        code,
        bitmask,
        vec![],
        regs,
        vec![0u8; DEFAULT_FLAT_MEM],
        DEFAULT_GAS,
        DEFAULT_MAX_STEPS,
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap, "expected Trap exit");
    tracing.into_trace()
}

/// Build a side note from steps + code + bitmask, then prove and verify.
/// Panics if either side fails — this is the positive-test happy path.
pub fn prove_and_verify(steps: Vec<PvmStep>, code: &[u8], bitmask: &[u8]) {
    let mut side_note = zkpvm::SideNote::new(steps, code.to_vec(), bitmask.to_vec());
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

/// Same as `prove_and_verify` but additionally prints per-component logup
/// claimed sums via `debug_claimed_sums` before proving.  Useful when a
/// constraint addition produces a `ConstraintsNotSatisfied` and you need to
/// distinguish "logup imbalance" (per-component sums non-zero, total
/// non-zero) from "structural pair-shape blow-up" (sums zero, prover still
/// rejects).  See `crates/zkpvm/src/chips/cpu/CONSTRAINTS.md`.
pub fn prove_and_verify_with_debug(steps: Vec<PvmStep>, code: &[u8], bitmask: &[u8]) {
    let mut side_note = zkpvm::SideNote::new(steps, code.to_vec(), bitmask.to_vec());
    eprintln!("--- per-component logup sums ---");
    zkpvm::debug_claimed_sums(&mut side_note);
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

/// Convenience: trace a TwoReg program with `regs[ra] = input`, then run
/// `prove_and_verify`.  Asserts `regs_after[rd] == expected`.
pub fn prove_two_reg(op: Opcode, rd: u8, ra: u8, input: u64, expected: u64) {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[ra as usize] = input;
    let (code, bitmask) = two_reg_program(op, rd, ra);
    let steps = trace_until_trap(code.clone(), bitmask.clone(), regs);
    assert_eq!(steps[0].opcode, op);
    assert_eq!(
        steps[0].regs_after[rd as usize], expected,
        "{op:?} φ[{rd}] = 0x{:x}, expected 0x{expected:x}", steps[0].regs_after[rd as usize]
    );
    prove_and_verify(steps, &code, &bitmask);
}

/// Convenience for negative tests: trace a TwoReg program, mutate
/// `steps[0].regs_after[rd]` to `forged`, then attempt prove + verify.
/// Caller wraps in `#[should_panic(expected = "ConstraintsNotSatisfied")]`.
pub fn forge_two_reg_result(
    op: Opcode,
    rd: u8,
    ra: u8,
    input: u64,
    forged: u64,
) {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[ra as usize] = input;
    let (code, bitmask) = two_reg_program(op, rd, ra);
    let mut steps = trace_until_trap(code.clone(), bitmask.clone(), regs);
    assert_eq!(steps[0].opcode, op);
    steps[0].regs_after[rd as usize] = forged;
    prove_and_verify(steps, &code, &bitmask);
}

/// Phase 13b negative-test helper: trace a TwoReg program, mutate one of
/// `steps[0]`'s instruction-tuple columns (opcode/imm/reg_a/reg_b/reg_d/
/// skip_len), then prove + verify.  The ProgramMemory consumer demands a
/// tuple matching the canonical decoding of `code` at the step's PC, so
/// any mismatch should make verification fail.  Caller wraps in
/// `#[should_panic(expected = "ConstraintsNotSatisfied")]`.
pub fn forge_step_field<F>(op: Opcode, rd: u8, ra: u8, input: u64, mutate: F)
where
    F: FnOnce(&mut PvmStep),
{
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[ra as usize] = input;
    let (code, bitmask) = two_reg_program(op, rd, ra);
    let mut steps = trace_until_trap(code.clone(), bitmask.clone(), regs);
    assert_eq!(steps[0].opcode, op);
    mutate(&mut steps[0]);
    prove_and_verify(steps, &code, &bitmask);
}
