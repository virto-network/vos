//! RISC-V instruction encoders: an instruction's word from its fields, as
//! [`decode`](super::decode) reads them back.

use super::decode::op;

/// An R-type instruction: `rd = rs1 ∘ rs2`.
pub(crate) const fn r_type(
    opcode: u32,
    funct3: u32,
    funct7: u32,
    rd: u32,
    rs1: u32,
    rs2: u32,
) -> u32 {
    (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

/// An I-type instruction, its immediate's low twelve bits.
pub(crate) const fn i_type(opcode: u32, funct3: u32, rd: u32, rs1: u32, imm: i32) -> u32 {
    (((imm as u32) & 0xfff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

/// A store: `rs2` to `imm(rs1)`, the width by `funct3`.
#[cfg(test)]
pub(crate) const fn s_type(funct3: u32, rs1: u32, rs2: u32, imm: i32) -> u32 {
    let imm = imm as u32;
    (((imm >> 5) & 0x7f) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | ((imm & 0x1f) << 7)
        | op::STORE
}

/// A branch `offset` bytes away, the comparison by `funct3`.
pub(crate) const fn b_type(funct3: u32, rs1: u32, rs2: u32, offset: i32) -> u32 {
    let o = offset as u32;
    (((o >> 12) & 1) << 31)
        | (((o >> 5) & 0x3f) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | (((o >> 1) & 0xf) << 8)
        | (((o >> 11) & 1) << 7)
        | op::BRANCH
}

/// `jal rd, offset`.
pub(crate) const fn jal(rd: u32, offset: i32) -> u32 {
    let o = offset as u32;
    (((o >> 20) & 1) << 31)
        | (((o >> 1) & 0x3ff) << 21)
        | (((o >> 11) & 1) << 20)
        | (((o >> 12) & 0xff) << 12)
        | (rd << 7)
        | op::JAL
}

/// `lui rd, imm20`.
pub(crate) const fn lui(rd: u32, imm20: u32) -> u32 {
    (imm20 << 12) | (rd << 7) | op::LUI
}

/// `auipc rd, imm20`.
pub(crate) const fn auipc(rd: u32, imm20: u32) -> u32 {
    (imm20 << 12) | (rd << 7) | op::AUIPC
}

/// `addi rd, rs1, imm`.
pub(crate) const fn addi(rd: u32, rs1: u32, imm: i32) -> u32 {
    i_type(op::OP_IMM, 0, rd, rs1, imm)
}

/// `add rd, rs1, rs2`.
pub(crate) const fn add(rd: u32, rs1: u32, rs2: u32) -> u32 {
    r_type(op::OP, 0, 0, rd, rs1, rs2)
}

/// `sub rd, rs1, rs2`.
pub(crate) const fn sub(rd: u32, rs1: u32, rs2: u32) -> u32 {
    r_type(op::OP, 0, 0x20, rd, rs1, rs2)
}

/// `ld rd, imm(rs1)`.
pub(crate) const fn ld(rd: u32, rs1: u32, imm: i32) -> u32 {
    i_type(op::LOAD, 3, rd, rs1, imm)
}

/// `sd rs2, imm(rs1)`.
#[cfg(test)]
pub(crate) const fn sd(rs2: u32, rs1: u32, imm: i32) -> u32 {
    s_type(3, rs1, rs2, imm)
}

/// `jalr rd, 0(rs1)`.
pub(crate) const fn jalr(rd: u32, rs1: u32) -> u32 {
    i_type(op::JALR, 0, rd, rs1, 0)
}
