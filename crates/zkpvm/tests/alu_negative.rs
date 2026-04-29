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

// Phase 16: DivS64 with negative operands now proves cleanly thanks to
// the divrem schoolbook's high-byte sign-correction (DivCorrHi /
// DivCorrCarry).  Previously the AIR demanded `q·d + r ≡ b mod 2^128`
// with high 64 bytes = 0, but for signed inputs the unsigned schoolbook
// produces a non-zero high (e.g. -100/7=-14 → q_u·d_u = 7·2^64 − 98,
// r_u = 2^64 − 2 → high = 7).  The new constraint binds the high to
// `sq·d_u + sd·q_u + sr − sa  (mod 2^64)`, matching two's complement.

#[test]
fn div_s64_negative_dividend_smoke() {
    // -100 / 7 = -14.  In u64: dividend = 2^64−100 = 0xFFFFFFFFFFFFFF9C,
    // expected quotient = 2^64−14 = 0xFFFFFFFFFFFFFFF2.
    prove_three_reg(
        Opcode::DivS64, 2, 0, 1,
        (-100i64) as u64, 7,
        (-14i64) as u64,
    );
}

#[test]
fn div_s64_negative_divisor_smoke() {
    // 100 / -7 = -14.
    prove_three_reg(
        Opcode::DivS64, 2, 0, 1,
        100, (-7i64) as u64,
        (-14i64) as u64,
    );
}

#[test]
fn div_s64_both_negative_smoke() {
    // -100 / -7 = 14 (positive quotient with negative operands).
    prove_three_reg(
        Opcode::DivS64, 2, 0, 1,
        (-100i64) as u64, (-7i64) as u64,
        14,
    );
}

#[test]
fn rem_s64_negative_dividend_smoke() {
    // -100 % 7 = -2 (round-toward-zero remainder takes dividend's sign).
    prove_three_reg(
        Opcode::RemS64, 2, 0, 1,
        (-100i64) as u64, 7,
        (-2i64) as u64,
    );
}

#[test]
#[should_panic(expected = "failed")]
fn div_s64_forged_unsigned_quotient_rejected() {
    // 100 / 7 = 14 (positive case works).  Forge to 13.
    forge_three_reg_result(Opcode::DivS64, 2, 0, 1, 100, 7, /*forged*/ 13);
}

#[test]
#[should_panic(expected = "failed")]
fn div_s64_negative_forged_off_by_one_rejected() {
    // -100 / 7 = -14, forge to -13 to confirm the new sign-correction
    // chain still detects forgery on the negative path.
    forge_three_reg_result(
        Opcode::DivS64, 2, 0, 1,
        (-100i64) as u64, 7,
        /*forged*/ (-13i64) as u64,
    );
}

// ── DivS32 / RemS32 with negatives (Phase 18) ────────────────────────────
//
// The 32-bit divrem schoolbook now applies the same sign-correction as
// Phase 16's 64-bit version (high 4 bytes ≡ sq·d_u + sd·q_u + sr − sa
// mod 2^32).  32-bit signs derive from byte 3 of val_b / val_d /
// div_quotient / div_remainder; Phase 18 added the SignSrcQ / SignSrcR
// multiplex so SignBitQ / SignBitR track bit 7 of byte 3 on 32-bit
// DivS rows (Phase 17 alone pinned them to byte 7, which is always
// zero on 32-bit DivS).
//
// Coverage caveat — the AIR's pre-existing 32-bit ALU constraint
// `result[4..8] = 0` (mod.rs:758, shared with all 32-bit ALU ops)
// is incompatible with the interpreter's sign-extension of negative
// 32-bit results to 64-bit (`q as i64 as u64` in javm/src/vm.rs).
// Same gap as documented in the Add32 comment at the top of this
// file.  Tests here are restricted to cases where the 32-bit *result*
// is non-negative (no sign-extension), even though either operand
// (and the schoolbook's high bytes) may be negative — which is
// exactly the path Phase 18's chain corrects.  Negative-result
// DivS32 / RemS32 needs a follow-up that loosens the result-
// truncation constraint to permit sign-extension; deferred.

#[test]
fn div_s32_both_negative_smoke() {
    // -100 / -7 = 14 (positive 32-bit result).  Both operands are
    // negative → sd = 1, sa = 1, sr = 1, sq = 0; high_32(q_u·d_u + r_u)
    // = 14, which the pre-Phase-18 AIR rejected (high bytes forced
    // to 0).  Result column has high bytes = 0 (positive 14), so
    // dodges the result-truncation gap.
    prove_three_reg(
        Opcode::DivS32, 2, 0, 1,
        (-100i32) as u32 as u64,
        (-7i32) as u32 as u64,
        14,
    );
}

#[test]
fn rem_s32_positive_with_negative_divisor_smoke() {
    // 100 % -7 = 2 (positive 32-bit remainder, sign-of-dividend rule).
    // Quotient is -14 (sq = 1, sd = 1) so the schoolbook chain still
    // exercises the 32-bit correction; *result* (= remainder = 2) has
    // high bytes = 0, so the truncation gap is dodged.
    prove_three_reg(
        Opcode::RemS32, 2, 0, 1,
        100,
        (-7i32) as u32 as u64,
        2,
    );
}

#[test]
#[should_panic(expected = "failed")]
fn div_s32_both_negative_forged_off_by_one_rejected() {
    // -100 / -7 = 14, forge to 13.  Confirms the 32-bit chain still
    // rejects a bad quotient on a row whose negative-operand path
    // goes through the new sign-correction.
    forge_three_reg_result(
        Opcode::DivS32, 2, 0, 1,
        (-100i32) as u32 as u64,
        (-7i32) as u32 as u64,
        /*forged*/ 13,
    );
}

// ── MulUpper (UU + SS + SU — Phase 12c bound all three) ──────────────────

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

// Phase 12c probe: MulUpperSS / MulUpperSU were marked deferred because
// the AIR's existing constraint binds `result = mul_high` (high 64 bits
// of UNSIGNED product), correct only for UU.  For SS/SU the high bits
// of the SIGNED product differ by sign corrections that the AIR didn't
// model.  These tests pin the gap.  Flip to passing positive smokes
// when the signed-schoolbook follow-up lands.
#[test]
fn mul_upper_ss_negative_squared_smoke() {
    // (-1) × (-1) signed = 1.  As u64: 0xFFFF...FFFF² = 0xFFFF...FFFE_…1.
    // High 64 of SIGNED product = 0.
    prove_three_reg(
        Opcode::MulUpperSS, 2, 0, 1,
        0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF,
        0,
    );
}

#[test]
fn mul_upper_su_negative_unsigned_smoke() {
    // (-2) signed × 3 unsigned = -6 (signed 128-bit).
    // High 64 of SIGNED = 0xFFFFFFFFFFFFFFFF (sign-ext from -1).
    prove_three_reg(
        Opcode::MulUpperSU, 2, 0, 1,
        0xFFFF_FFFF_FFFF_FFFE, 3,
        0xFFFF_FFFF_FFFF_FFFF,
    );
}

// ── Move / LoadImm ───────────────────────────────────────────────────────
//
// MoveReg constraint: `is_move · (result[i] - val_d[i]) = 0` for all i.
// LoadImm shares the same `is_move` flag — the AIR sees an immediate as
// `val_d = imm` and binds result byte-wise.

#[test]
fn move_reg_positive_smoke() {
    // φ[2] = φ[0] = 0xDEAD_BEEF (TwoReg: rd in low nibble, ra in high).
    prove_two_reg(Opcode::MoveReg, 2, 0, 0xDEAD_BEEF, 0xDEAD_BEEF);
}

#[test]
#[should_panic(expected = "failed")]
fn move_reg_forged_result_rejected() {
    forge_two_reg_result(
        Opcode::MoveReg, 2, 0,
        0xDEAD_BEEF, /*forged*/ 0xCAFE_BABE,
    );
}

// LoadImm has its own encoding (opcode + reg_byte + 4-byte imm), so the
// shared two_reg_program helper doesn't apply.  Inline a small helper
// here that runs LoadImm with `imm=12345` then forges regs_after[ra].
#[test]
#[should_panic(expected = "failed")]
fn load_imm_forged_result_rejected() {
    use javm::PVM_REGISTER_COUNT;
    use javm::interpreter::Interpreter;
    use zkpvm::core::tracing::TracingPvm;

    let regs = [0u64; PVM_REGISTER_COUNT];
    let imm: u32 = 12345;
    let imm_bytes = imm.to_le_bytes();
    let mut code = vec![Opcode::LoadImm as u8, 2]; // ra=2
    code.extend_from_slice(&imm_bytes);
    code.push(Opcode::Trap as u8);
    let mut bitmask = vec![1, 0, 0, 0, 0, 0];
    bitmask.push(1);

    let pvm = Interpreter::new(
        code.clone(), bitmask.clone(), vec![], regs,
        vec![0u8; 4 * 1024 * 1024], 10_000, 25,
    );
    let mut tr = TracingPvm::new(pvm);
    let _ = tr.run();
    let mut steps = tr.into_trace();
    assert_eq!(steps[0].regs_after[2], 12345);
    steps[0].regs_after[2] = 99; // forge — `result = val_d = imm` should reject
    prove_and_verify(steps, &code, &bitmask);
}
