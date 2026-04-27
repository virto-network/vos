//! Phase 12b: BitManip TwoReg ops — positive + negative tests for the
//! constraints added in CpuChip.  Helpers live in `tests/common/mod.rs`.

mod common;
use common::*;

use javm::instruction::Opcode;

// ── ReverseBytes ───────────────────────────────────────────────────────────

#[test]
fn prove_reverse_bytes() {
    prove_two_reg(
        Opcode::ReverseBytes,
        2, 3,
        0x0123_4567_89AB_CDEF,
        0xEFCD_AB89_6745_2301,
    );
}

#[test]
#[should_panic(expected = "ConstraintsNotSatisfied")]
fn reverse_bytes_forged_result_rejected() {
    forge_two_reg_result(
        Opcode::ReverseBytes, 2, 3,
        0x0123_4567_89AB_CDEF,
        0xDEAD_BEEF_DEAD_BEEF,
    );
}

// ── ZeroExtend16 ───────────────────────────────────────────────────────────

#[test]
fn prove_zero_extend_16() {
    prove_two_reg(
        Opcode::ZeroExtend16, 2, 3,
        0xFFFF_FFFF_FFFF_BEEF,
        0xBEEF,
    );
}

#[test]
#[should_panic(expected = "ConstraintsNotSatisfied")]
fn zero_extend_16_forged_upper_byte_rejected() {
    forge_two_reg_result(
        Opcode::ZeroExtend16, 2, 3,
        0xFFFF_FFFF_FFFF_BEEF,
        0x0000_0000_0001_BEEF, // byte 2 = 0x01 must be 0
    );
}

#[test]
#[should_panic(expected = "ConstraintsNotSatisfied")]
fn zero_extend_16_forged_low_byte_rejected() {
    forge_two_reg_result(
        Opcode::ZeroExtend16, 2, 3,
        0xFFFF_FFFF_FFFF_BEEF,
        0xCAFE, // low 16 must equal val_d low 16 (0xBEEF)
    );
}

// ── SignExtend8 ────────────────────────────────────────────────────────────

#[test]
fn prove_sign_extend_8_negative() {
    // val_d byte 0 = 0x80 (sign bit set) → result = 0xFFFF_FFFF_FFFF_FF80.
    prove_two_reg(
        Opcode::SignExtend8, 2, 3,
        0xCAFE_BABE_DEAD_BE80,
        0xFFFF_FFFF_FFFF_FF80,
    );
}

#[test]
fn prove_sign_extend_8_positive() {
    // val_d byte 0 = 0x7F (sign bit clear) → result = 0x7F.
    prove_two_reg(
        Opcode::SignExtend8, 2, 3,
        0xFFFF_FFFF_FFFF_FF7F,
        0x7F,
    );
}

#[test]
#[should_panic(expected = "ConstraintsNotSatisfied")]
fn sign_extend_8_forged_upper_byte_rejected() {
    forge_two_reg_result(
        Opcode::SignExtend8, 2, 3,
        0xCAFE_BABE_DEAD_BE80,
        0x0000_0000_0000_FF80, // bytes 2..7 forged to 0
    );
}

#[test]
#[should_panic(expected = "ConstraintsNotSatisfied")]
fn sign_extend_8_forged_sign_bit_rejected() {
    // Pin: SignExtBit follows bit 7 of val_d[0].  Forging the result to
    // look like zero-extension when the source's sign bit is set should be
    // rejected by the nibble-AND lookup (8 in (hi_nib, 8, 8·SignExtBit)).
    forge_two_reg_result(
        Opcode::SignExtend8, 2, 3,
        0x80,                  // sign bit set
        0x80,                  // honest = 0xFFFF_FFFF_FFFF_FF80
    );
}

// ── SignExtend16 ───────────────────────────────────────────────────────────

#[test]
fn prove_sign_extend_16_negative() {
    prove_two_reg(
        Opcode::SignExtend16, 2, 3,
        0xCAFE_BABE_DEAD_8000,
        0xFFFF_FFFF_FFFF_8000,
    );
}

#[test]
fn prove_sign_extend_16_positive() {
    prove_two_reg(
        Opcode::SignExtend16, 2, 3,
        0xFFFF_FFFF_FFFF_7FFF,
        0x7FFF,
    );
}

#[test]
#[should_panic(expected = "ConstraintsNotSatisfied")]
fn sign_extend_16_forged_upper_byte_rejected() {
    forge_two_reg_result(
        Opcode::SignExtend16, 2, 3,
        0x8000,
        0x0000_0000_FFFF_8000, // bytes 4..7 forged to 0
    );
}

#[test]
#[should_panic(expected = "ConstraintsNotSatisfied")]
fn sign_extend_16_forged_byte_1_rejected() {
    forge_two_reg_result(
        Opcode::SignExtend16, 2, 3,
        0x12_34,
        0x9934, // byte 1 = 0x99 ≠ val_d[1] = 0x12 (positive case, no sign)
    );
}
