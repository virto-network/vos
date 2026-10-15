//! RISC-V instruction decoder and PVM instruction translator.
//!
//! Decodes rv64em instructions and translates them to equivalent
//! PVM bytecode sequences.

mod alu;
mod control;
mod decode;
mod memory;

use std::collections::{BTreeSet, HashMap};

use vos_pvm::instruction::Opcode;

use crate::TranspileError;

pub(crate) use decode::{
    auipc_pair_target, decode_b_imm, decode_j_imm, funct3, op, opcode, rd, rs1, rs2, word_at, words,
};

use decode::{csr, decode_s_imm, funct7, i_imm, map_register, u_imm};

/// Determine the minimum byte width for encoding a signed immediate in PVM format.
///
/// Returns `(lx, bytes)` where `lx` is the byte count (0, 1, 2, or 4) and `bytes`
/// are the little-endian encoded value.
fn encode_var_imm(imm: i32) -> (u8, Vec<u8>) {
    if imm == 0 {
        (0, vec![])
    } else if (-128..=127).contains(&imm) {
        (1, vec![imm as i8 as u8])
    } else if (-32768..=32767).contains(&imm) {
        (2, (imm as i16).to_le_bytes().to_vec())
    } else {
        (4, imm.to_le_bytes().to_vec())
    }
}

/// Translation context for converting RISC-V to PVM.
#[derive(Default)]
pub(crate) struct TranslationContext {
    /// Emitted PVM code bytes.
    pub(crate) code: Vec<u8>,
    /// Bitmask: 1 for instruction start, 0 for continuation.
    pub(crate) bitmask: Vec<u8>,
    /// Jump table entries.
    pub(crate) jump_table: Vec<u32>,
    /// Map from RISC-V address to PVM code offset.
    pub(crate) address_map: HashMap<u64, u32>,
    /// Pending branch fixups: (pvm_imm_offset, target_rv_address, fixup_size)
    fixups: Vec<(usize, u64, u8)>,
    /// Map from fixup imm offset → instruction PC (for PC-relative encoding)
    fixup_pcs: HashMap<usize, u32>,
    /// Jump-table fixups: (jump_table_index, RISC-V address its entry
    /// names), a return address or a code address loaded as a value.
    /// Resolved during `apply_fixups` to patch jump table entries.
    return_fixups: Vec<(usize, u64)>,
    /// Pending AUIPC: (rd, computed_address). Used to pair with the next JALR.
    pending_auipc: Option<(u8, u64)>,
    /// Pending LUI: (rd, upper_imm). Used to fuse LUI+ADDI into single load_imm.
    pending_lui: Option<(u8, i64)>,
    /// Last emitted load_imm: (rd, value, code_position_before_emit).
    /// Enables fusion with a subsequent ADD/AND/OR/XOR/load/store into the
    /// immediate form, eliminating the load_imm instruction entirely.
    pub(crate) pending_load_imm: Option<(u8, i64, usize)>,
    /// Last immediate loaded into t0 (x5) — used for ecalli cap slot.
    last_t0_imm: Option<i32>,
    /// Set by the CSR marker 0x801: the next ecall becomes a PVM `ecalli`
    /// whose id was loaded into t0.
    ecalli_marked: bool,
    /// RISC-V code address ranges (lo, hi), sorted and merged — used to
    /// detect function pointers loaded via auipc+addi that need jump table
    /// entries.
    pub(crate) code_ranges: Vec<(u64, u64)>,
    /// Each `ecalli` emitted: the RISC-V address of its `ecall`, and its id.
    pub(crate) host_calls: Vec<(u64, u32)>,
    /// Point a branch whose target was never translated at a trap, rather
    /// than leave it unresolved: a kernel's code, its unreachable targets
    /// pruned.
    pub(crate) trap_unresolved: bool,
}

impl TranslationContext {
    /// Flush any pending buffered instructions (LUI, AUIPC) at section boundaries.
    pub(crate) fn flush_pending(&mut self) -> Result<(), TranspileError> {
        if let Some((auipc_rd, auipc_val)) = self.pending_auipc.take() {
            self.emit_load_imm(auipc_rd, auipc_val as i64)?;
        }
        if let Some((lui_rd, lui_val)) = self.pending_lui.take() {
            self.emit_load_imm(lui_rd, lui_val)?;
        }
        // pending_load_imm is already emitted — just clear the tracking
        self.pending_load_imm = None;
        Ok(())
    }

    /// Begin translating one RISC-V instruction at an address whose PVM
    /// location may be referenced by another control-flow edge.
    ///
    /// Pending LUI/AUIPC state belongs exclusively to the linear predecessor,
    /// and `pending_load_imm` fusion may remove that predecessor. Flush all of
    /// it before recording a branch target so an incoming edge lands on the
    /// consumer with its own register state intact.
    pub(crate) fn begin_instruction(
        &mut self,
        address: u64,
        is_control_flow_target: bool,
    ) -> Result<(), TranspileError> {
        if is_control_flow_target {
            self.flush_pending()?;
        }
        self.address_map.insert(address, self.code.len() as u32);
        Ok(())
    }

    /// Translate the 32-bit RISC-V instruction `inst` at `addr`.
    pub(crate) fn translate_one(&mut self, inst: u32, addr: u64) -> Result<(), TranspileError> {
        let opcode = opcode(inst);
        let rd = rd(inst);
        let funct3 = funct3(inst);
        let rs1 = rs1(inst);
        let rs2 = rs2(inst);
        let funct7 = funct7(inst);

        // Flush pending auipc if this isn't a JALR or OP-IMM (ADDI) that consumes it.
        if opcode != op::JALR
            && opcode != op::OP_IMM
            && let Some((auipc_rd, auipc_val)) = self.pending_auipc.take()
        {
            self.emit_load_imm(auipc_rd, auipc_val as i64)?;
        }

        // Flush pending LUI if this isn't an OP-IMM (ADDI) that consumes it.
        if opcode != op::OP_IMM
            && let Some((lui_rd, lui_val)) = self.pending_lui.take()
        {
            self.emit_load_imm(lui_rd, lui_val)?;
        }

        // Clear pending_load_imm if this isn't an instruction that can consume it.
        // The OP, OP-32, branch, store and load handlers check and potentially fuse.
        if !matches!(
            opcode,
            op::OP | op::OP_32 | op::BRANCH | op::STORE | op::LOAD
        ) {
            self.pending_load_imm = None; // already emitted, just clear tracking
        }

        match opcode {
            op::LUI => {
                // Buffered for potential LUI+ADDI fusion
                let imm = u_imm(inst);
                // Flush any previous pending LUI (consecutive LUIs)
                if let Some((prev_rd, prev_val)) = self.pending_lui.take() {
                    self.emit_load_imm(prev_rd, prev_val)?;
                }
                self.pending_lui = Some((rd, imm as i64));
            }
            op::AUIPC => {
                // PC + upper immediate, recorded for pairing with the next
                // JALR. Nothing is emitted yet: the JALR handler uses it.
                let computed = (addr as i64 + u_imm(inst) as i64) as u64;
                self.pending_auipc = Some((rd, computed));
            }
            op::JAL => {
                let imm = decode_j_imm(inst);
                let target = (addr as i64 + imm as i64) as u64;
                if rd == 0 {
                    // Plain jump (tail call / goto)
                    self.emit_jump(target);
                } else {
                    // Function call: fused load_imm_jump
                    let rv_return_addr = addr + 4;
                    self.emit_call(rd, rv_return_addr, target)?;
                }
            }
            op::JALR => {
                if funct3 != 0 {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: addr as usize,
                        detail: format!("JALR funct3={funct3}"),
                    });
                }
                self.translate_jalr(rd, rs1, i_imm(inst), addr)?;
            }
            op::BRANCH => {
                let imm = decode_b_imm(inst);
                let target = (addr as i64 + imm as i64) as u64;
                self.translate_branch(funct3, rs1, rs2, target, addr)?;
            }
            op::LOAD => self.translate_load(funct3, rd, rs1, i_imm(inst), addr)?,
            op::STORE => self.translate_store(funct3, rs1, rs2, decode_s_imm(inst), addr)?,
            // add_i, xor_i, etc.
            op::OP_IMM => self.translate_op_imm(funct3, funct7, rd, rs1, i_imm(inst))?,
            // add, sub, mul, etc.
            op::OP => self.translate_op(funct3, funct7, rd, rs1, rs2, addr)?,
            // addiw, slliw, etc.
            op::OP_IMM_32 => self.translate_op_imm_32(funct3, funct7, rd, rs1, i_imm(inst))?,
            // addw, subw, etc.
            op::OP_32 => self.translate_op_32(funct3, funct7, rd, rs1, rs2, addr)?,
            op::SYSTEM => match (funct3, csr(inst)) {
                // ECALL: a marked one becomes `ecalli`; an unmarked one traps.
                (0, 0) => {
                    if std::mem::take(&mut self.ecalli_marked) {
                        let id = self.last_t0_imm.unwrap_or(0) as u32;
                        self.emit_ecalli(id);
                        self.host_calls.push((addr, id));
                        self.last_t0_imm = None;
                    } else {
                        self.emit_op(Opcode::Trap);
                    }
                }
                // CSRRW: CSR 0x801 marks the next ecall as `ecalli` and
                // emits no PVM instruction itself.
                (1, 0x801) => self.ecalli_marked = true,
                // EBREAK, unimp, and every other CSR operation trap.
                _ => self.emit_op(Opcode::Trap),
            },
            // FENCE is a no-op.
            op::MISC_MEM => self.emit_op(Opcode::Fallthrough),
            // T-Head extensions
            op::CUSTOM_0 => match (funct7, funct3) {
                (0x20, 1) => {
                    // th.mveqz rd, rs1, rs2: if rs2 == 0 then rd = rs1
                    if rd == 0 { /* nop */
                    } else if rs2 == 0 {
                        // Condition is x0 (always 0) → always execute: rd = rs1
                        if rs1 == 0 {
                            self.emit_load_imm(rd, 0)?;
                        } else if rd == rs1 {
                            // Self-move is a nop
                            self.emit_op(Opcode::Fallthrough);
                        } else {
                            let pvm_rd = self.require_reg(rd)?;
                            let pvm_rs1 = self.require_reg(rs1)?;
                            self.emit_op(Opcode::MoveReg);
                            self.emit_data(pvm_rd | (pvm_rs1 << 4));
                        }
                    } else if rs1 == 0 {
                        // Source is x0 (always 0): if rs2 == 0 then rd = 0
                        let pvm_rd = self.require_reg(rd)?;
                        let pvm_rs2 = self.require_reg(rs2)?;
                        self.emit_op(Opcode::CmovIzImm);
                        self.emit_data(pvm_rd | (pvm_rs2 << 4));
                        self.emit_var_imm(0);
                    } else {
                        let pvm_rd = self.require_reg(rd)?;
                        let pvm_rs1 = self.require_reg(rs1)?;
                        let pvm_rs2 = self.require_reg(rs2)?;
                        self.emit_op(Opcode::CmovIz);
                        self.emit_data(pvm_rs1 | (pvm_rs2 << 4));
                        self.emit_data(pvm_rd);
                    }
                }
                (0x21, 1) => {
                    // th.mvnez rd, rs1, rs2: if rs2 != 0 then rd = rs1
                    if rd == 0 || rs2 == 0 {
                        // rd==0: nop. rs2==x0: condition "x0 != 0" is always false → nop
                        self.emit_op(Opcode::Fallthrough);
                    } else if rs1 == 0 {
                        let pvm_rd = self.require_reg(rd)?;
                        let pvm_rs2 = self.require_reg(rs2)?;
                        self.emit_op(Opcode::CmovNzImm);
                        self.emit_data(pvm_rd | (pvm_rs2 << 4));
                        self.emit_var_imm(0);
                    } else {
                        let pvm_rd = self.require_reg(rd)?;
                        let pvm_rs1 = self.require_reg(rs1)?;
                        let pvm_rs2 = self.require_reg(rs2)?;
                        self.emit_op(Opcode::CmovNz);
                        self.emit_data(pvm_rs1 | (pvm_rs2 << 4));
                        self.emit_data(pvm_rd);
                    }
                }
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: addr as usize,
                        detail: format!("custom-0 funct7={funct7:#x} funct3={funct3}"),
                    });
                }
            },
            _ => {
                return Err(TranspileError::UnsupportedInstruction {
                    offset: addr as usize,
                    detail: format!("unknown opcode {opcode:#x}"),
                });
            }
        }

        Ok(())
    }

    // ===== Helpers =====

    /// The PVM register for a RISC-V register other than x0. x0 has none:
    /// PVM register 0 holds the return address, so every caller handles x0
    /// itself, as a zero source or a discarded result.
    pub(crate) fn require_reg(&self, rv_reg: u8) -> Result<u8, TranspileError> {
        map_register(rv_reg)?.ok_or(TranspileError::RegisterMapping(rv_reg))
    }

    /// Emit an instruction's opcode, which starts it.
    pub(crate) fn emit_op(&mut self, opcode: Opcode) {
        self.code.push(opcode as u8);
        self.bitmask.push(1);
    }

    pub(crate) fn emit_data(&mut self, byte: u8) {
        self.code.push(byte);
        self.bitmask.push(0);
    }

    pub(crate) fn emit_imm32(&mut self, imm: i32) {
        let bytes = imm.to_le_bytes();
        for b in &bytes {
            self.emit_data(*b);
        }
    }

    /// Emit a signed immediate using the minimum byte width.
    /// PVM instruction categories OneRegOneImm and TwoRegOneImm derive
    /// immediate length from the instruction skip distance, so shorter
    /// encodings are automatically decoded correctly via sign extension.
    /// Compute the number of bytes needed for a variable-length immediate.
    fn var_imm_byte_count(imm: i32) -> usize {
        if imm == 0 {
            0
        } else if (-128..=127).contains(&imm) {
            1
        } else if (-32768..=32767).contains(&imm) {
            2
        } else {
            4
        }
    }

    pub(crate) fn emit_var_imm(&mut self, imm: i32) {
        if imm == 0 {
            // Zero bytes — decoder gets lx=0, sign_extend(0, 0) = 0
        } else if (-128..=127).contains(&imm) {
            self.emit_data(imm as i8 as u8);
        } else if (-32768..=32767).contains(&imm) {
            let bytes = (imm as i16).to_le_bytes();
            for b in &bytes {
                self.emit_data(*b);
            }
        } else {
            let bytes = imm.to_le_bytes();
            for b in &bytes {
                self.emit_data(*b);
            }
        }
    }

    pub(crate) fn emit_load_imm(&mut self, rd: u8, imm: i64) -> Result<(), TranspileError> {
        if rd == 0 {
            return Ok(());
        } // Write to zero register is nop
        let pvm_rd = self.require_reg(rd)?;

        if imm >= i32::MIN as i64 && imm <= i32::MAX as i64 {
            self.emit_op(Opcode::LoadImm);
            self.emit_data(pvm_rd);
            self.emit_var_imm(imm as i32);
        } else {
            self.emit_op(Opcode::LoadImm64);
            self.emit_data(pvm_rd);
            let bytes = (imm as u64).to_le_bytes();
            for b in &bytes {
                self.emit_data(*b);
            }
        }
        Ok(())
    }

    /// Reserve a jump-table entry that [`Self::apply_fixups`] points at the
    /// translation of RISC-V address `target`, and return the address a
    /// djump to it takes.
    fn jump_table_slot(&mut self, target: u64) -> u32 {
        let index = self.jump_table.len();
        self.jump_table.push(0);
        self.return_fixups.push((index, target));
        jump_table_address(index)
    }

    /// Load `address` into `rd`, or its jump-table address when it is code
    /// (a function pointer), and keep the load pending for fusion with the
    /// instruction after it.
    pub(crate) fn load_address(&mut self, rd: u8, address: u64) -> Result<(), TranspileError> {
        let value = if self.is_code_addr(address) {
            i64::from(self.jump_table_slot(address))
        } else {
            address as i64
        };
        let at = self.code.len();
        self.emit_load_imm(rd, value)?;
        self.pending_load_imm = Some((rd, value, at));
        Ok(())
    }

    /// Build a mapping from RISC-V code addresses to PVM jump table addresses.
    ///
    /// Only creates jump table entries for the given `targets` — the set of
    /// RISC-V addresses actually referenced as function pointers (e.g. from
    /// Check whether an address falls within any RISC-V code section.
    pub(crate) fn is_code_addr(&self, addr: u64) -> bool {
        crate::linker::in_ranges(&self.code_ranges, addr)
    }

    /// absolute relocations in data sections like vtables). Returns a map of
    /// RISC-V address → jump table address (= (index+1)*2).
    ///
    /// This is needed to fix indirect calls through function pointers stored in
    /// data sections (vtables, callbacks, etc.). The PVM's `jump_ind` instruction
    /// expects jump table addresses, not raw code offsets.
    pub(crate) fn build_function_pointer_map(
        &mut self,
        targets: &BTreeSet<u64>,
    ) -> HashMap<u64, u32> {
        let mut rv_to_jt = HashMap::new();
        for rv_addr in targets {
            if let Some(&pvm_offset) = self.address_map.get(rv_addr) {
                let jt_idx = self.jump_table.len();
                self.jump_table.push(pvm_offset);
                rv_to_jt.insert(*rv_addr, jump_table_address(jt_idx));
            }
        }
        rv_to_jt
    }

    /// The trap the unresolved targets share, emitted on first use.
    fn shared_trap(&mut self, trap: &mut Option<u32>) -> u32 {
        *trap.get_or_insert_with(|| {
            let at = self.code.len() as u32;
            self.emit_op(Opcode::Trap);
            at
        })
    }

    pub(crate) fn apply_fixups(&mut self) {
        let mut trap = None;
        // PC-relative fixups (branches, jumps)
        for (pvm_offset, rv_target, size) in self.fixups.drain(..).collect::<Vec<_>>() {
            let target = match self.address_map.get(&rv_target) {
                Some(&pvm_target) => Some(pvm_target),
                None if self.trap_unresolved => Some(self.shared_trap(&mut trap)),
                None => None,
            };
            if let Some(pvm_target) = target {
                let inst_pc = self
                    .fixup_pcs
                    .get(&pvm_offset)
                    .copied()
                    .unwrap_or(pvm_offset as u32 - 1);
                let relative = (pvm_target as i64 - inst_pc as i64) as i32;
                let bytes = relative.to_le_bytes();
                self.code[pvm_offset..pvm_offset + size as usize]
                    .copy_from_slice(&bytes[..size as usize]);
            } else {
                tracing::warn!(
                    "unresolved fixup: rv_target={:#x}, pvm_offset={}",
                    rv_target,
                    pvm_offset
                );
            }
        }

        // Resolve return address fixups in the jump table. A call whose
        // return address has no translated instruction (a call to a function
        // that never returns, at the end of a section) gets a trap as its
        // return target. Left at 0, the entry would name the refine entry
        // point, which is a valid jump target: returning would restart the
        // program instead of failing.
        for (jt_idx, rv_addr) in self.return_fixups.drain(..).collect::<Vec<_>>() {
            let target = match self.address_map.get(&rv_addr) {
                Some(&pvm_target) => pvm_target,
                None => self.shared_trap(&mut trap),
            };
            self.jump_table[jt_idx] = target;
        }
    }
}

/// The address a djump takes to jump-table entry `index`.
pub(crate) fn jump_table_address(index: usize) -> u32 {
    ((index + 1) * 2) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_mapping() {
        assert_eq!(map_register(0).unwrap(), None); // zero
        assert_eq!(map_register(1).unwrap(), Some(0)); // ra
        assert_eq!(map_register(2).unwrap(), Some(1)); // sp
        assert_eq!(map_register(10).unwrap(), Some(7)); // a0
        assert_eq!(map_register(15).unwrap(), Some(12)); // a5
        assert!(map_register(3).is_err()); // gp: no mapping
    }

    #[test]
    fn test_decode_j_imm() {
        // JAL x0, 0 (forward)
        assert_eq!(decode_j_imm(0x0000006F), 0);
        // JAL x0, 4
        assert_eq!(decode_j_imm(0x0040006F), 4);
    }

    #[test]
    fn test_decode_j_imm_negative() {
        // JAL with negative offset (backward jump)
        // imm[20|10:1|11|19:12] = all 1s → -2
        // Encoding: bit31=1, bits[30:21]=0x3FF, bit20=1, bits[19:12]=0xFF
        let inst = 0xFFFFF06F; // JAL x0, -2 (the standard encoding for JAL x0, -2)
        let imm = decode_j_imm(inst);
        assert!(imm < 0, "negative offset should be negative");
        assert_eq!(imm, -2);
    }

    #[test]
    fn test_decode_j_imm_max_positive() {
        // JAL with maximum positive offset: imm[20]=0, rest=max
        // imm = 0x0FFFFE (1048574)
        let inst = 0x7FFFF06F; // bit31=0, bits[30:21]=0x3FF, bit20=1, bits[19:12]=0xFF
        let imm = decode_j_imm(inst);
        assert!(imm > 0);
    }

    #[test]
    fn test_decode_b_imm_zero() {
        // BEQ x0, x0, 0
        assert_eq!(decode_b_imm(0x00000063), 0);
    }

    #[test]
    fn test_decode_b_imm_positive() {
        // BEQ with offset +8: imm[12|10:5]=0, imm[4:1]=0100, imm[11]=0
        // inst[11:8]=0100 → imm[4:1]=4, shift by 1 → offset=8
        let inst = 0x00000463; // BEQ x0, x0, +8
        let imm = decode_b_imm(inst);
        assert_eq!(imm, 8);
    }

    #[test]
    fn test_decode_b_imm_negative() {
        // BEQ with negative offset
        // All bits set → -2
        let inst = 0xFE000FE3; // BEQ x0, x0, -2
        let imm = decode_b_imm(inst);
        assert_eq!(imm, -2);
    }

    #[test]
    fn test_decode_s_imm_zero() {
        // SD x0, 0(x0): imm=0
        assert_eq!(decode_s_imm(0x00003023), 0);
    }

    #[test]
    fn test_decode_s_imm_positive() {
        // SD x0, 8(x0): imm[11:5]=0, imm[4:0]=01000
        let inst = 0x00003423; // imm4_0 = 8 (at bits[11:7] = 01000)
        let imm = decode_s_imm(inst);
        assert_eq!(imm, 8);
    }

    #[test]
    fn test_decode_s_imm_negative() {
        // SD x0, -8(x0): imm = -8 = 0xFFF8
        // imm[11:5] = 1111111, imm[4:0] = 11000
        let inst = 0xFE003C23; // SD x0, -8(x0)
        let imm = decode_s_imm(inst);
        assert_eq!(imm, -8);
    }

    #[test]
    fn test_register_mapping_all_a_regs() {
        // a0-a5 map to PVM registers 7-12
        for (rv, pvm) in [(10, 7), (11, 8), (12, 9), (13, 10), (14, 11), (15, 12)] {
            assert_eq!(
                map_register(rv).unwrap(),
                Some(pvm),
                "rv{rv} should map to φ[{pvm}]"
            );
        }
    }

    #[test]
    fn test_register_mapping_s_regs() {
        // s0-s1 map to PVM registers 5-6
        assert_eq!(map_register(8).unwrap(), Some(5)); // s0
        assert_eq!(map_register(9).unwrap(), Some(6)); // s1
    }

    #[test]
    fn test_register_mapping_unmapped() {
        // tp(4), t3-t6(28-31) are unmapped → error
        assert!(map_register(4).is_err()); // tp
        assert!(map_register(28).is_err()); // t3
    }

    #[test]
    fn translates_slt_x0_rs2_to_set_gt_s_imm() {
        // Regression for the x0-as-rs1 SLT path. cipher-clerk's
        // apply_batch monomorphization emits SLT rd, x0, rs2
        // (signed-compare-against-zero with x0 on the LEFT) in the
        // balance-overflow check loop. Before the fix this returned
        // `UnsupportedInstruction { funct7=0x0 funct3=2 }`.
        //
        // Encoding: SLT a0, x0, a1
        //   rd  = x10 (a0)
        //   rs1 = x0
        //   rs2 = x11 (a1)
        //   funct3 = 2 (SLT), funct7 = 0
        let mut ctx = TranslationContext::default();
        let result = ctx.translate_op(
            /* funct3 */ 2, /* funct7 */ 0, /* rd */ 10, /* rs1 */ 0,
            /* rs2 */ 11, /* addr */ 0,
        );
        assert!(
            result.is_ok(),
            "SLT rd=x10, rs1=x0, rs2=x11 should translate: {result:?}",
        );
        // PVM emit: set_gt_s_imm (opcode 143) + packed regs (rd=a0→7,
        // rs2=a1→8 → 7 | (8 << 4) = 0x87) + zero-byte imm (omitted
        // by emit_var_imm when imm == 0).
        assert_eq!(
            ctx.code.as_slice(),
            &[143u8, 0x87u8],
            "expected [set_gt_s_imm, packed(a0,a1)], got {:?}",
            ctx.code,
        );
    }

    #[test]
    fn translates_shift_imm_x0_to_load_zero() {
        // Regression for the x0-as-rs1 shift-immediate path. Rust's stable
        // `slice::sort` (driftsort) merge emits `slli a2, x0, 3` (= 0) as a
        // zeroing idiom. Before the fix, the `_ =>` arm fell through to the
        // register path and shifted PVM reg 0 (= RA, NOT zero), corrupting the
        // merge-cursor pointers and mis-sorting `&usize` slices.
        //
        // SLLI a2, x0, 3:  funct3=1, funct7=0, rd=x12(a2), rs1=x0, imm=shamt=3.
        // Must emit `load_imm a2, 0` → [51, 9] (a2 → PVM reg 9; zero imm omitted).
        for (funct3, funct7, what) in [(1u32, 0u32, "SLLI"), (5, 0, "SRLI"), (5, 0x20, "SRAI")] {
            let mut ctx = TranslationContext::default();
            let r = ctx.translate_op_imm(
                funct3, funct7, /* rd */ 12, /* rs1 */ 0, /* imm */ 3,
            );
            assert!(r.is_ok(), "{what} rd=a2, rs1=x0 should translate: {r:?}");
            assert_eq!(
                ctx.code.as_slice(),
                &[51u8, 9u8],
                "{what} a2, x0, 3 must be load_imm a2,0 (NOT a shift of RA); got {:?}",
                ctx.code,
            );
        }
    }

    #[test]
    fn translates_op_imm_32_x0_directly() {
        // Same x0-as-rs1 class for the RV64-W ops (addiw/slliw/srliw/sraiw).
        // ADDIW a2, x0, 7 = sext32(7) → load_imm a2, 7 = [51, 9, 7].
        let mut ctx = TranslationContext::default();
        ctx.translate_op_imm_32(0, 0, 12, 0, 7).unwrap();
        assert_eq!(
            ctx.code.as_slice(),
            &[51u8, 9u8, 7u8],
            "addiw a2,x0,7 = load_imm 7"
        );
        // SLLIW a2, x0, 3 = 0 → load_imm a2, 0 = [51, 9].
        let mut ctx = TranslationContext::default();
        ctx.translate_op_imm_32(1, 0, 12, 0, 3).unwrap();
        assert_eq!(
            ctx.code.as_slice(),
            &[51u8, 9u8],
            "slliw a2,x0,3 = load_imm 0"
        );
    }

    #[test]
    fn does_not_fuse_left_immediate_into_non_commutative_slt() {
        // Regression: `load_imm rd, K; slt(u) rd, rd, rs2` puts the immediate on
        // the LEFT operand. SLT/SLTU are not commutative and set_lt_*_imm only
        // encodes `(reg < imm)`, so fusing emits `(rs2 < K)` instead of the
        // correct `(K < rs2)`. hkdf's `okm.len() > 255*chunk` check compiled to
        // exactly this at -Os (`sltu a0, 8160, len`); the fused form flipped it
        // to `len < 8160`, so every HKDF-expand spuriously returned InvalidLength.
        for (funct3, what) in [(2u32, "SLT"), (3, "SLTU")] {
            let mut ctx = TranslationContext::default();
            // `load_imm a0, 8160`, tracked as pending (as translate_op_imm would).
            let undo = ctx.code.len();
            ctx.emit_load_imm(10, 8160).unwrap();
            let load_imm = ctx.code.clone();
            ctx.pending_load_imm = Some((10, 8160, undo));
            // SLT(U) a0, a0, a4 (rd=rs1=a0=x10, rs2=a4=x14): must stay `8160 < a4`.
            ctx.translate_op(
                funct3, 0, /*rd*/ 10, /*rs1*/ 10, /*rs2*/ 14, /*addr*/ 4,
            )
            .unwrap();
            // The load_imm must survive (NOT be truncated into an operand-swapped
            // set_lt_*_imm) and a register-form compare appended after it.
            assert_eq!(
                &ctx.code[..load_imm.len()],
                load_imm.as_slice(),
                "{what} with a left immediate must not fuse (would flip the comparison)",
            );
            assert!(
                ctx.code.len() > load_imm.len(),
                "{what}: a register-form compare must follow the preserved load_imm",
            );
        }
    }

    #[test]
    fn control_flow_target_keeps_fallthrough_immediate_out_of_shared_consumer() {
        // Fallthrough computes a stack offset in a0, while another arm jumps
        // directly to the shared ADD with its own a0. Fusing the fallthrough
        // load into the targeted ADD would overwrite the incoming arm's value.
        let mut ctx = TranslationContext::default();
        let lui_a0_0x4000 = 0x0000_4537_u32;
        let addi_a0_a0_0x1e0 = (0x1e0_u32 << 20) | (10 << 15) | (10 << 7) | 0x13;
        let add_a0_sp_a0 = (10_u32 << 20) | (2 << 15) | (10 << 7) | 0x33;

        ctx.begin_instruction(0, false).unwrap();
        ctx.translate_one(lui_a0_0x4000, 0).unwrap();
        ctx.begin_instruction(4, false).unwrap();
        ctx.translate_one(addi_a0_a0_0x1e0, 4).unwrap();
        let load_len = ctx.code.len();
        assert_eq!(ctx.code[0], 51, "fallthrough materializes load_imm");

        ctx.begin_instruction(8, true).unwrap();
        let target = ctx.address_map[&8] as usize;
        assert_eq!(
            target, load_len,
            "the target starts after the predecessor load"
        );
        ctx.translate_one(add_a0_sp_a0, 8).unwrap();

        assert_eq!(ctx.code[0], 51, "targeted fusion must not remove load_imm");
        assert_eq!(
            ctx.code[target], 200,
            "shared consumer remains register ADD64"
        );
    }

    #[test]
    fn store_preserves_a_constant_base_for_later_memory_operations() {
        let mut ctx = TranslationContext::default();
        let undo = ctx.code.len();
        ctx.emit_load_imm(10, 0x21ba0).unwrap();
        let address_load = ctx.code.clone();
        ctx.pending_load_imm = Some((10, 0x21ba0, undo));

        ctx.translate_store(
            3,  /* SD */
            10, /* base: a0 */
            11, /* value: a1 */
            0, 0,
        )
        .unwrap();

        assert_eq!(
            &ctx.code[..address_load.len()],
            address_load.as_slice(),
            "a store must not remove a base address that later instructions can reuse",
        );
        assert!(ctx.code.len() > address_load.len());
    }

    #[test]
    fn unmarked_ecall_traps_instead_of_calling_a_capability() {
        let mut ctx = TranslationContext::default();
        ctx.translate_one(0x0000_0073_u32, 0).unwrap();
        assert_eq!(ctx.code, [0], "unmarked ECALL must compile to trap");
    }
}
