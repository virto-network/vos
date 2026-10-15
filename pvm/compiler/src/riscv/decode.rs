//! RISC-V instructions decoded: registers, opcodes, fields and immediates.

use crate::TranspileError;

/// RISC-V register to PVM register mapping.
///
/// RISC-V has 16 registers in the `e` (embedded) ABI:
///   x0 (zero), x1 (ra), x2 (sp), x3 (gp), x4 (tp),
///   x5 (t0), x6 (t1), x7 (t2), x8 (s0), x9 (s1),
///   x10 (a0), x11 (a1), x12 (a2), x13 (a3), x14 (a4), x15 (a5)
///
/// PVM has 13 registers (0-12):
///   0=RA, 1=SP, 2=T0, 3=T1, 4=T2, 5=S0, 6=S1,
///   7=A0, 8=A1, 9=A2, 10=A3, 11=A4, 12=A5
///
/// Mapping: x0 → zero (special), x1 → 0, x2 → 1, x5-x15 → 2-12
/// x3 (gp) and x4 (tp) have no direct mapping and must be spilled.
pub(super) fn map_register(rv_reg: u8) -> Result<Option<u8>, TranspileError> {
    match rv_reg {
        0 => Ok(None),                                         // x0 = zero register (always 0)
        1 => Ok(Some(0)),                                      // x1 (ra) → PVM reg 0 (RA)
        2 => Ok(Some(1)),                                      // x2 (sp) → PVM reg 1 (SP)
        3 | 4 => Err(TranspileError::RegisterMapping(rv_reg)), // gp, tp: no mapping
        5 => Ok(Some(2)),                                      // x5 (t0) → PVM reg 2 (T0)
        6 => Ok(Some(3)),                                      // x6 (t1) → PVM reg 3 (T1)
        7 => Ok(Some(4)),                                      // x7 (t2) → PVM reg 4 (T2)
        8 => Ok(Some(5)),                                      // x8 (s0) → PVM reg 5 (S0)
        9 => Ok(Some(6)),                                      // x9 (s1) → PVM reg 6 (S1)
        10 => Ok(Some(7)),                                     // x10 (a0) → PVM reg 7 (A0)
        11 => Ok(Some(8)),                                     // x11 (a1) → PVM reg 8 (A1)
        12 => Ok(Some(9)),                                     // x12 (a2) → PVM reg 9 (A2)
        13 => Ok(Some(10)),                                    // x13 (a3) → PVM reg 10 (A3)
        14 => Ok(Some(11)),                                    // x14 (a4) → PVM reg 11 (A4)
        15 => Ok(Some(12)),                                    // x15 (a5) → PVM reg 12 (A5)
        _ => Err(TranspileError::RegisterMapping(rv_reg)),
    }
}

/// The RISC-V major opcodes the translation reads, an instruction's low
/// seven bits.
pub(crate) mod op {
    pub(crate) const LOAD: u32 = 0x03;
    pub(crate) const CUSTOM_0: u32 = 0x0b;
    pub(crate) const MISC_MEM: u32 = 0x0f;
    pub(crate) const OP_IMM: u32 = 0x13;
    pub(crate) const AUIPC: u32 = 0x17;
    pub(crate) const OP_IMM_32: u32 = 0x1b;
    pub(crate) const STORE: u32 = 0x23;
    pub(crate) const OP: u32 = 0x33;
    pub(crate) const LUI: u32 = 0x37;
    pub(crate) const OP_32: u32 = 0x3b;
    pub(crate) const BRANCH: u32 = 0x63;
    pub(crate) const JALR: u32 = 0x67;
    pub(crate) const JAL: u32 = 0x6f;
    pub(crate) const SYSTEM: u32 = 0x73;
}

pub(crate) fn opcode(inst: u32) -> u32 {
    inst & 0x7f
}

pub(crate) fn rd(inst: u32) -> u8 {
    ((inst >> 7) & 0x1f) as u8
}

pub(crate) fn funct3(inst: u32) -> u32 {
    (inst >> 12) & 0x7
}

pub(crate) fn rs1(inst: u32) -> u8 {
    ((inst >> 15) & 0x1f) as u8
}

pub(crate) fn rs2(inst: u32) -> u8 {
    ((inst >> 20) & 0x1f) as u8
}

pub(crate) fn funct7(inst: u32) -> u32 {
    (inst >> 25) & 0x7f
}

/// A SYSTEM instruction's CSR.
pub(super) fn csr(inst: u32) -> u32 {
    (inst >> 20) & 0xfff
}

/// An I-type instruction's immediate, sign-extended.
pub(crate) fn i_imm(inst: u32) -> i32 {
    (inst as i32) >> 20
}

/// A U-type instruction's immediate, its upper twenty bits in place.
pub(crate) fn u_imm(inst: u32) -> i32 {
    (inst & 0xffff_f000) as i32
}

/// The instructions of a code section, in order.
pub(crate) fn words(code: &[u8]) -> impl Iterator<Item = u32> + '_ {
    code.chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().expect("four bytes")))
}

/// The instruction at `offset` of a code section, if four bytes lie there.
pub(crate) fn word_at(code: &[u8], offset: usize) -> Option<u32> {
    code.get(offset..offset.checked_add(4)?)
        .map(|word| u32::from_le_bytes(word.try_into().expect("four bytes")))
}

/// What an AUIPC at `address` and the JALR or ADDI after it, `next`, name
/// together: the AUIPC's upper immediate plus the next one's lower.
pub(crate) fn auipc_pair_target(address: u64, auipc: u32, next: u32) -> u64 {
    address.wrapping_add_signed(i64::from(u_imm(auipc)) + i64::from(i_imm(next)))
}

pub(crate) fn decode_j_imm(inst: u32) -> i32 {
    let imm20 = (inst >> 31) & 1;
    let imm10_1 = (inst >> 21) & 0x3FF;
    let imm11 = (inst >> 20) & 1;
    let imm19_12 = (inst >> 12) & 0xFF;
    let imm = (imm20 << 20) | (imm19_12 << 12) | (imm11 << 11) | (imm10_1 << 1);
    // Sign extend from bit 20
    if imm20 != 0 {
        (imm | 0xFFE00000) as i32
    } else {
        imm as i32
    }
}

pub(crate) fn decode_b_imm(inst: u32) -> i32 {
    let imm12 = (inst >> 31) & 1;
    let imm10_5 = (inst >> 25) & 0x3F;
    let imm4_1 = (inst >> 8) & 0xF;
    let imm11 = (inst >> 7) & 1;
    let imm = (imm12 << 12) | (imm11 << 11) | (imm10_5 << 5) | (imm4_1 << 1);
    if imm12 != 0 {
        (imm | 0xFFFFE000) as i32
    } else {
        imm as i32
    }
}

pub(super) fn decode_s_imm(inst: u32) -> i32 {
    let imm11_5 = (inst >> 25) & 0x7F;
    let imm4_0 = (inst >> 7) & 0x1F;
    let imm = (imm11_5 << 5) | imm4_0;
    if imm11_5 & 0x40 != 0 {
        (imm | 0xFFFFF000) as i32
    } else {
        imm as i32
    }
}
