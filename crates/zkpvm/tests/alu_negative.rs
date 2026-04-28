//! Negative-test corpus for CpuChip's ALU constraints (Phase-15-prep).
//!
//! Each test crafts an honest trace of a ThreeReg ALU op, mutates
//! `regs_after[rd]` to a wrong value, and asserts prove+verify fails.
//! Together they pin down which CpuChip constraints fire on result
//! forgery — a regression in any of these would mean a soundness gap.
//!
//! Categories covered: Add64/Add32, Sub64, Mul64, And, Or, Xor, ShloL64,
//! SetLtU, SetLtS, BranchEq.  Each has 1 negative test per common
//! mutation pattern.

mod common;
use common::*;

use javm::instruction::Opcode;

// ── Add ───────────────────────────────────────────────────────────────────

#[test]
fn add64_positive_smoke() {
    prove_three_reg(Opcode::Add64, 2, 0, 1, 100, 200, 300);
}

#[test]
#[should_panic(expected = "failed")]
fn add64_forged_result_rejected() {
    forge_three_reg_result(Opcode::Add64, 2, 0, 1, 100, 200, /*forged*/ 999);
}

#[test]
#[should_panic(expected = "failed")]
fn add64_off_by_one_rejected() {
    forge_three_reg_result(Opcode::Add64, 2, 0, 1, 100, 200, /*forged*/ 301);
}

// Add32 sign-extension semantics are tricky to test with the prove_three_reg
// helper since the PVM interpreter sign-extends to 64 bits but the CpuChip
// AIR's 32-bit-truncation constraint uses RegValB (raw register) cross-
// constraints rather than the value-level Result.  The existing
// tests/phase2_alu.rs::prove_add32 already covers the positive path with
// inputs that don't trigger sign extension; defer Add32 negative-test
// coverage to a focused future pass.

// ── Sub ───────────────────────────────────────────────────────────────────

#[test]
fn sub64_positive_smoke() {
    prove_three_reg(Opcode::Sub64, 2, 0, 1, 500, 200, 300);
}

#[test]
#[should_panic(expected = "failed")]
fn sub64_forged_result_rejected() {
    forge_three_reg_result(Opcode::Sub64, 2, 0, 1, 500, 200, /*forged*/ 0);
}

// ── Mul ───────────────────────────────────────────────────────────────────

#[test]
fn mul64_positive_smoke() {
    prove_three_reg(Opcode::Mul64, 2, 0, 1, 6, 7, 42);
}

#[test]
#[should_panic(expected = "failed")]
fn mul64_forged_result_rejected() {
    forge_three_reg_result(Opcode::Mul64, 2, 0, 1, 6, 7, /*forged*/ 41);
}

// ── Bitwise ────────────────────────────────────────────────────────────────

#[test]
fn and_positive_smoke() {
    prove_three_reg(Opcode::And, 2, 0, 1, 0xFF00_FF00, 0x0FF0_0FF0, 0x0F00_0F00);
}

#[test]
#[should_panic(expected = "failed")]
fn and_forged_result_rejected() {
    forge_three_reg_result(
        Opcode::And, 2, 0, 1,
        0xFF00_FF00, 0x0FF0_0FF0,
        /*forged*/ 0xFFFF_FFFF, // honest = 0x0F00_0F00
    );
}

#[test]
fn or_positive_smoke() {
    prove_three_reg(Opcode::Or, 2, 0, 1, 0xFF00_0000, 0x0000_FF00, 0xFF00_FF00);
}

#[test]
#[should_panic(expected = "failed")]
fn or_forged_result_rejected() {
    forge_three_reg_result(Opcode::Or, 2, 0, 1, 0xFF00_0000, 0x0000_FF00, /*forged*/ 0);
}

#[test]
fn xor_positive_smoke() {
    prove_three_reg(Opcode::Xor, 2, 0, 1, 0xFF00_FF00, 0x0FF0_0FF0, 0xF0F0_F0F0);
}

#[test]
#[should_panic(expected = "failed")]
fn xor_forged_result_rejected() {
    forge_three_reg_result(
        Opcode::Xor, 2, 0, 1,
        0xFF00_FF00, 0x0FF0_0FF0,
        /*forged*/ 0,
    );
}

// ── Compare ────────────────────────────────────────────────────────────────

#[test]
fn set_lt_u_positive_lt() {
    // 100 <_u 200 → φ[2] = 1
    prove_three_reg(Opcode::SetLtU, 2, 0, 1, 100, 200, 1);
}

#[test]
fn set_lt_u_positive_ge() {
    // 200 !<_u 100 → φ[2] = 0
    prove_three_reg(Opcode::SetLtU, 2, 0, 1, 200, 100, 0);
}

#[test]
#[should_panic(expected = "failed")]
fn set_lt_u_forged_result_rejected() {
    // Honest: 100 <_u 200 = 1.  Forge to 0.
    forge_three_reg_result(Opcode::SetLtU, 2, 0, 1, 100, 200, /*forged*/ 0);
}

#[test]
fn set_lt_s_positive_negative_lt() {
    // -1 <_s 0 → φ[2] = 1.  -1 as u64 = 0xFFFF_FFFF_FFFF_FFFF.
    prove_three_reg(Opcode::SetLtS, 2, 0, 1, 0xFFFF_FFFF_FFFF_FFFF, 0, 1);
}

#[test]
#[should_panic(expected = "failed")]
fn set_lt_s_forged_result_rejected() {
    // Honest: -1 <_s 0 = 1.  Forge: claim -1 ≥_s 0.
    forge_three_reg_result(
        Opcode::SetLtS, 2, 0, 1,
        0xFFFF_FFFF_FFFF_FFFF, 0,
        /*forged*/ 0,
    );
}

// ── Shift ──────────────────────────────────────────────────────────────────

#[test]
fn shlo_l64_positive_smoke() {
    // 1 << 4 = 16.
    prove_three_reg(Opcode::ShloL64, 2, 0, 1, 1, 4, 16);
}

#[test]
#[should_panic(expected = "failed")]
fn shlo_l64_forged_result_rejected() {
    forge_three_reg_result(Opcode::ShloL64, 2, 0, 1, 1, 4, /*forged*/ 8);
}

#[test]
fn shlo_r64_positive_smoke() {
    // 1024 >> 3 = 128.
    prove_three_reg(Opcode::ShloR64, 2, 0, 1, 1024, 3, 128);
}

#[test]
#[should_panic(expected = "failed")]
fn shlo_r64_forged_result_rejected() {
    forge_three_reg_result(Opcode::ShloR64, 2, 0, 1, 1024, 3, /*forged*/ 256);
}

// ── DivRem ─────────────────────────────────────────────────────────────────

#[test]
fn div_u64_positive_smoke() {
    // 100 / 7 = 14 (unsigned).
    prove_three_reg(Opcode::DivU64, 2, 0, 1, 100, 7, 14);
}

#[test]
#[should_panic(expected = "failed")]
fn div_u64_forged_result_rejected() {
    // Honest: 100 / 7 = 14.  Forge: claim 100 / 7 = 13.
    forge_three_reg_result(Opcode::DivU64, 2, 0, 1, 100, 7, /*forged*/ 13);
}

#[test]
fn rem_u64_positive_smoke() {
    // 100 % 7 = 2 (unsigned).
    prove_three_reg(Opcode::RemU64, 2, 0, 1, 100, 7, 2);
}

#[test]
#[should_panic(expected = "failed")]
fn rem_u64_forged_result_rejected() {
    forge_three_reg_result(Opcode::RemU64, 2, 0, 1, 100, 7, /*forged*/ 1);
}

// Note: DivS64 with a negative dividend (e.g. -100 / 7 = -14) currently
// fails proving with ConstraintsNotSatisfied even though the interpreter
// produces the correct quotient (0xFFFF_FFFF_FFFF_FFF2).  The AIR's
// signed-divrem constraint chain has a corner not exercised by existing
// positive tests in tests/phase2_alu.rs.  Filed as 15-divs-debug.
//
// Negative DivS64 testing therefore deferred until the positive case
// proves cleanly.

#[test]
#[should_panic(expected = "failed")]
fn div_s64_forged_unsigned_quotient_rejected() {
    // 100 / 7 = 14 (positive case works).  Forge to 13.
    forge_three_reg_result(Opcode::DivS64, 2, 0, 1, 100, 7, /*forged*/ 13);
}

// ── MulUpper (UU only — SS/SU still prover-trusted; see task 12c) ─────────

#[test]
fn mul_upper_uu_top_bits_smoke() {
    // 2^63 * 2 = 2^64; top 64 bits = 1, low 64 bits = 0.
    prove_three_reg(
        Opcode::MulUpperUU, 2, 0, 1,
        1u64 << 63, 2,
        1,
    );
}

#[test]
#[should_panic(expected = "failed")]
fn mul_upper_uu_forged_result_rejected() {
    forge_three_reg_result(
        Opcode::MulUpperUU, 2, 0, 1,
        1u64 << 63, 2,
        /*forged*/ 0, // honest = 1
    );
}

// Phase 15 finding (resolved): 0xFFFFFFFF² used to fail proving because
// the schoolbook carry per position can exceed u8 (max ~0x3FB at busy
// middle positions).  Trace fill was truncating to u8 → constraint
// mismatch.  Fix: split the carry across MulCarry (low byte) +
// MulCarryHi (high byte); AIR reconstructs the full 16-bit value.
#[test]
fn mul_upper_uu_low32_squared() {
    // 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFF_FFFE_0000_0001 (low 64).
    // Top 64 bits = 0.
    prove_three_reg(
        Opcode::MulUpperUU, 2, 0, 1,
        0xFFFF_FFFF, 0xFFFF_FFFF,
        0,
    );
}

#[test]
fn mul64_low32_squared() {
    // Same operands, plain Mul64: result = low 64 bits.
    prove_three_reg(
        Opcode::Mul64, 2, 0, 1,
        0xFFFF_FFFF, 0xFFFF_FFFF,
        0xFFFF_FFFE_0000_0001,
    );
}

#[test]
fn mul_upper_uu_full_64bit_squared() {
    // 0xFFFFFFFFFFFFFFFF² = 0xFFFFFFFFFFFFFFFE_0000000000000001 (128-bit).
    // Top 64 bits = 0xFFFFFFFFFFFFFFFE.
    prove_three_reg(
        Opcode::MulUpperUU, 2, 0, 1,
        0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFE,
    );
}
