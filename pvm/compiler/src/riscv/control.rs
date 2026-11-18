//! Jumps, calls and branches.

use vos_pvm::instruction::Opcode;

use crate::TranspileError;

use super::{TranslationContext, encode_var_imm};

impl TranslationContext {
    /// `jalr rd, imm(rs1)`: jump to `(rs1 + imm) & !1`, the sum's bit 0
    /// cleared as RISC-V clears it, and write the return address to `rd`.
    ///
    /// A target known at translation (an AUIPC or LUI pair, or base x0) is
    /// a code address, cleared in that domain. A register holds a code
    /// pointer as its jump-table address, `2·(index + 1)`: even, with one
    /// entry per code address. A displacement of 0 from it, or of ±1 that
    /// bit 0's clearing takes back (+1 from an even pointer, -1 from one
    /// with bit 0 set), lands on the entry itself, as the source lands on
    /// its code address. A ±1 of the other parity names the source's
    /// misaligned address two bytes on, where the source faults, and traps;
    /// a displacement of 2 or more names a different instruction of the
    /// source but a different entry of the table, and is refused.
    pub(super) fn translate_jalr(
        &mut self,
        rd: u8,
        rs1: u8,
        imm: i32,
        addr: u64,
    ) -> Result<(), TranspileError> {
        let pending = match (self.pending_auipc.take(), self.pending_lui.take()) {
            (Some((auipc_rd, value)), _) if auipc_rd == rs1 => Some(value as i64),
            (auipc, lui) => {
                if let Some((auipc_rd, value)) = auipc {
                    self.emit_load_imm(auipc_rd, value as i64)?;
                }
                match lui {
                    Some((lui_rd, value)) if lui_rd == rs1 => {
                        // The LUI's register keeps its value unless the
                        // jump's return address overwrites it.
                        if lui_rd != rd {
                            self.emit_load_imm(lui_rd, value)?;
                        }
                        Some(value)
                    }
                    Some((lui_rd, value)) => {
                        self.emit_load_imm(lui_rd, value)?;
                        None
                    }
                    None => None,
                }
            }
        };

        // A static target: an AUIPC/LUI pair, or base x0 (the absolute
        // address `imm`, code only if a section was linked there; otherwise
        // the jump traps).
        let base = match pending {
            Some(value) => Some(value),
            None if rs1 == 0 => Some(0),
            None => None,
        };
        if let Some(base) = base {
            let target = (base.wrapping_add(i64::from(imm)) as u64) & !1;
            if rs1 == 0 && !self.is_code_addr(target) {
                self.emit_op(Opcode::Trap);
            } else if rd == 0 {
                self.emit_jump(target);
            } else {
                self.emit_call(rd, addr + 4, target)?;
            }
            return Ok(());
        }

        if !(-1..=1).contains(&imm) {
            return Err(TranspileError::IndirectDisplacement { at: addr, imm });
        }
        let pvm_rs1 = self.require_reg(rs1)?;
        if rd == 0 {
            self.emit_masked_jump_ind(pvm_rs1, imm);
        } else {
            // An indirect call: the target, bit 0 cleared, in `rd`, which the
            // return address overwrites; `load_imm_jump_ind` jumps through
            // the register's value before it writes it.
            let pvm_rd = self.require_reg(rd)?;
            // A ±1 of the wrong parity branches to a trap after the call.
            let wrong_parity = (imm != 0).then(|| self.emit_parity_branch(pvm_rs1, imm));
            let mut source = pvm_rs1;
            if imm != 0 {
                self.emit_op(Opcode::AddImm64);
                self.emit_data(pvm_rd | (source << 4));
                self.emit_var_imm(imm);
                source = pvm_rd;
            }
            self.emit_op(Opcode::AndImm);
            self.emit_data(pvm_rd | (source << 4));
            self.emit_var_imm(-2);

            let jt_addr = self.jump_table_slot(addr + 4) as i32;
            let lx = Self::var_imm_byte_count(jt_addr);
            self.emit_op(Opcode::LoadImmJumpInd);
            self.emit_data(pvm_rd | (pvm_rd << 4)); // ra = rd, rb = rd
            self.emit_data(lx as u8); // lx: byte count for imm_x (return addr)
            self.emit_var_imm(jt_addr); // imm_x: jump table return address
            self.emit_var_imm(0); // imm_y: offset added to rb

            if let Some(branch) = wrong_parity {
                self.patch_branch(branch);
                self.emit_rotate(pvm_rs1, 63);
                self.emit_op(Opcode::Trap);
            }
        }
        Ok(())
    }

    /// `r` rotated right by one, its bit 0 in the sign, then a branch taken
    /// when that bit is the one a displacement `imm` of ±1 does not clear
    /// (set for +1, clear for -1), then `r` restored on the fall-through.
    /// The branch's target is left to [`Self::patch_branch`]; its path
    /// starts with `r` still rotated.
    fn emit_parity_branch(&mut self, r: u8, imm: i32) -> (usize, usize) {
        self.emit_rotate(r, 1);
        let branch_pc = self.code.len();
        self.emit_op(if imm > 0 {
            Opcode::BranchLtSImm
        } else {
            Opcode::BranchGeSImm
        });
        self.emit_data(r); // lx = 0: the immediate 0
        let offset_at = self.code.len();
        self.emit_imm32(0);
        self.emit_rotate(r, 63);
        (branch_pc, offset_at)
    }

    /// Point a branch from [`Self::emit_parity_branch`] at the next
    /// instruction emitted.
    fn patch_branch(&mut self, (branch_pc, offset_at): (usize, usize)) {
        let relative = (self.code.len() - branch_pc) as i32;
        self.code[offset_at..offset_at + 4].copy_from_slice(&relative.to_le_bytes());
    }

    fn emit_rotate(&mut self, r: u8, by: i32) {
        self.emit_op(Opcode::RotR64Imm);
        self.emit_data(r | (r << 4));
        self.emit_var_imm(by);
    }

    /// `jump_ind` to `(r + imm) & !1` with no register to clear bit 0 in:
    /// `r` rotated right by one puts its bit 0 in the sign, a branch on it
    /// picks the displacement that clears the sum's bit 0, and a rotation
    /// by 63 restores `r` on both paths, so the jump leaves every register
    /// as RISC-V leaves it. For a displacement of ±1, the parity bit 0's
    /// clearing does not take back traps instead (see
    /// [`Self::translate_jalr`]).
    fn emit_masked_jump_ind(&mut self, r: u8, imm: i32) {
        // The displacement for an even `r`, and for an odd one; `None`
        // where the source's target is two bytes past the pointer's.
        let (even, odd) = match imm {
            0 => (Some(0), Some(-1)),
            1 => (Some(0), None),
            _ => (None, Some(-1)),
        };
        let jump = |ctx: &mut Self, displacement: Option<i32>| match displacement {
            Some(displacement) => {
                ctx.emit_op(Opcode::JumpInd);
                ctx.emit_data(r);
                ctx.emit_var_imm(displacement);
            }
            None => ctx.emit_op(Opcode::Trap),
        };
        self.emit_rotate(r, 1);
        let branch_pc = self.code.len();
        self.emit_op(Opcode::BranchLtSImm);
        self.emit_data(r); // lx = 0: the immediate 0
        let offset_at = self.code.len();
        self.emit_imm32(0);
        self.emit_rotate(r, 63);
        jump(self, even);
        self.patch_branch((branch_pc, offset_at));
        self.emit_rotate(r, 63);
        jump(self, odd);
    }

    pub(super) fn translate_branch(
        &mut self,
        funct3: u32,
        rs1: u8,
        rs2: u8,
        target: u64,
        addr: u64,
    ) -> Result<(), TranspileError> {
        // A branch writes no register, so a constant just loaded into an
        // operand may be read on either path after it: keep the load and
        // compare registers. Fusing it needs liveness at both successors,
        // which a second pass over translated blocks could provide.
        self.pending_load_imm = None;

        // Both operands x0: the outcome is static. BEQ, BGE and BGEU always
        // branch and become a jump; BNE, BLT and BLTU never do and emit
        // nothing. Neither may read PVM register 0, which holds RA.
        if rs1 == 0 && rs2 == 0 {
            match funct3 {
                0 | 5 | 7 => self.emit_jump(target),
                1 | 4 | 6 => {}
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: addr as usize,
                        detail: format!("branch funct3={funct3}"),
                    });
                }
            }
            return Ok(());
        }

        // When one operand is x0 (zero register), use immediate branch variants
        // since PVM register 0 = RA, not zero.
        if rs2 == 0 {
            let pvm_rs1 = self.require_reg(rs1)?;
            let pvm_opcode = match funct3 {
                0 => Opcode::BranchEqImm,  // BEQ x, x0
                1 => Opcode::BranchNeImm,  // BNE x, x0
                4 => Opcode::BranchLtSImm, // BLT x, x0
                5 => Opcode::BranchGeSImm, // BGE x, x0
                6 => Opcode::BranchLtUImm, // BLTU x, x0
                7 => Opcode::BranchGeUImm, // BGEU x, x0
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("branch funct3={funct3}"),
                    });
                }
            };
            self.emit_branch_imm(pvm_opcode, pvm_rs1, 0, target);
            return Ok(());
        }

        if rs1 == 0 {
            // Compare x0 against rs2: flip the condition
            let pvm_rs2 = self.require_reg(rs2)?;
            match funct3 {
                // BEQ x0, y → y == 0
                0 => self.emit_branch_imm(Opcode::BranchEqImm, pvm_rs2, 0, target),
                // BNE x0, y → y != 0
                1 => self.emit_branch_imm(Opcode::BranchNeImm, pvm_rs2, 0, target),
                // BLT x0, rs2 → rs2 >= 1 (signed)
                4 => self.emit_branch_imm(Opcode::BranchGeSImm, pvm_rs2, 1, target),
                // BGE x0, rs2 → rs2 < 1 (signed)
                5 => self.emit_branch_imm(Opcode::BranchLtSImm, pvm_rs2, 1, target),
                // BLTU x0, rs2 → rs2 != 0
                6 => self.emit_branch_imm(Opcode::BranchNeImm, pvm_rs2, 0, target),
                // BGEU x0, rs2 → rs2 == 0
                7 => self.emit_branch_imm(Opcode::BranchEqImm, pvm_rs2, 0, target),
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("branch funct3={funct3}"),
                    });
                }
            };
            return Ok(());
        }

        let pvm_rs1 = self.require_reg(rs1)?;
        let pvm_rs2 = self.require_reg(rs2)?;

        // Two register + one offset
        let pvm_opcode = match funct3 {
            0 => Opcode::BranchEq,  // BEQ
            1 => Opcode::BranchNe,  // BNE
            4 => Opcode::BranchLtS, // BLT
            5 => Opcode::BranchGeS, // BGE
            6 => Opcode::BranchLtU, // BLTU
            7 => Opcode::BranchGeU, // BGEU
            _ => {
                return Err(TranspileError::UnsupportedInstruction {
                    offset: 0,
                    detail: format!("branch funct3={funct3}"),
                });
            }
        };

        let inst_pc = self.code.len() as u32;
        self.emit_op(pvm_opcode);
        self.emit_data(pvm_rs1 | (pvm_rs2 << 4));
        // Fixup target offset (PC-relative)
        let fixup_pos = self.code.len();
        self.fixups.push((fixup_pos, target, 4));
        self.fixup_pcs.insert(fixup_pos, inst_pc);
        self.emit_imm32(0); // placeholder

        Ok(())
    }

    pub(crate) fn emit_jump(&mut self, target: u64) {
        let inst_pc = self.code.len() as u32;
        self.emit_op(Opcode::Jump);
        let fixup_pos = self.code.len();
        self.fixups.push((fixup_pos, target, 4));
        self.fixup_pcs.insert(fixup_pos, inst_pc);
        self.emit_imm32(0); // placeholder
    }

    /// Emit load_imm_jump: fuse load_imm + jump into a single PVM instruction.
    /// OneRegImmOffset format — sets register and jumps in one step.
    /// Saves one instruction (and one gas block boundary) per function call.
    fn emit_load_imm_jump(&mut self, rd: u8, imm: i64, target: u64) -> Result<(), TranspileError> {
        let pvm_rd = self.require_reg(rd)?;

        let inst_pc = self.code.len() as u32;
        self.emit_op(Opcode::LoadImmJump);

        // OneRegImmOffset encoding: reg_byte (rd + lX), then imm bytes, then offset bytes.
        // Use variable-length encoding for the immediate.
        let imm_len = Self::var_imm_byte_count(imm as i32);
        let reg_byte = pvm_rd | ((imm_len as u8) << 4);
        self.emit_data(reg_byte);
        self.emit_var_imm(imm as i32);

        // Offset (4 bytes, patched by fixup)
        let fixup_pos = self.code.len();
        self.fixups.push((fixup_pos, target, 4));
        self.fixup_pcs.insert(fixup_pos, inst_pc);
        self.emit_imm32(0); // placeholder offset
        Ok(())
    }

    /// Emit a function call: load return address into rd and jump to target.
    /// Uses load_imm_jump to fuse into a single PVM instruction, saving one
    /// instruction per call site.
    pub(crate) fn emit_call(
        &mut self,
        rd: u8,
        rv_ret_addr: u64,
        target: u64,
    ) -> Result<(), TranspileError> {
        if rd == 0 {
            // No return address needed — just jump
            self.emit_jump(target);
            return Ok(());
        }
        let jt_addr = self.jump_table_slot(rv_ret_addr);
        self.emit_load_imm_jump(rd, i64::from(jt_addr), target)
    }

    pub(crate) fn emit_ecalli(&mut self, id: u32) {
        self.emit_op(Opcode::Ecalli);
        self.emit_var_imm(id as i32);
    }

    /// Emit a OneRegImmOffset instruction (used by branch_*_imm opcodes).
    ///
    /// PVM encoding: [opcode][ra | (lx << 4)][imm (lx bytes LE)][offset (4 bytes LE)]
    /// where lx = minimum bytes to represent the signed immediate.
    fn emit_branch_imm(&mut self, opcode: Opcode, ra: u8, imm: i32, target: u64) {
        let inst_pc = self.code.len() as u32;
        self.emit_op(opcode);

        let (lx, imm_bytes) = encode_var_imm(imm);

        // Pack register and immediate length into one byte
        self.emit_data(ra | (lx << 4));

        // Emit immediate bytes
        for b in &imm_bytes {
            self.emit_data(*b);
        }

        // Emit offset placeholder (4 bytes, filled by fixup)
        let fixup_pos = self.code.len();
        self.fixups.push((fixup_pos, target, 4));
        self.fixup_pcs.insert(fixup_pos, inst_pc);
        self.emit_imm32(0);
    }
}
