//! Jumps, calls and branches.

use vos_pvm::instruction::Opcode;

use crate::TranspileError;

use super::{TranslationContext, encode_var_imm};

impl TranslationContext {
    pub(super) fn translate_jalr(
        &mut self,
        rd: u8,
        rs1: u8,
        imm: i32,
        addr: u64,
    ) -> Result<(), TranspileError> {
        // Check for auipc+jalr pair (PC-relative call/jump)
        if let Some((auipc_rd, auipc_val)) = self.pending_auipc.take() {
            if auipc_rd == rs1 {
                // Combined auipc+jalr: target = auipc_val + imm
                let target = (auipc_val as i64 + imm as i64) as u64;
                if rd == 0 {
                    // Tail call: just jump, no return address
                    self.emit_jump(target);
                } else {
                    // Function call: fused load_imm_jump
                    let rv_return_addr = addr + 4;
                    self.emit_call(rd, rv_return_addr, target)?;
                }
                return Ok(());
            } else {
                // auipc targeted a different register — emit it as load_imm
                self.emit_load_imm(auipc_rd, auipc_val as i64)?;
            }
        }

        // Base x0: the absolute address `imm`. A 12-bit address is code only
        // if a section was linked there; otherwise the jump traps.
        if rs1 == 0 {
            let target = i64::from(imm) as u64;
            let is_code = self.is_code_addr(target);
            if !is_code {
                self.emit_op(Opcode::Trap);
            } else if rd == 0 {
                self.emit_jump(target);
            } else {
                self.emit_call(rd, addr + 4, target)?;
            }
            return Ok(());
        }

        // Plain JALR (no preceding auipc, or auipc was for different reg)
        if rd == 0 {
            // Tail call or return: jump_ind without saving return address.
            // Handles ret (rs1=ra, imm=0) and tail calls through any register.
            let pvm_rs1 = self.require_reg(rs1)?;
            self.emit_op(Opcode::JumpInd);
            self.emit_data(pvm_rs1);
            self.emit_var_imm(imm);
        } else {
            // Indirect call (e.g. vtable dispatch): save return address then jump.
            // load_imm_jump_ind: rd = return_addr, jump via rs1+imm.
            let jt_addr = self.jump_table_slot(addr + 4) as i32;

            let pvm_rd = self.require_reg(rd)?;
            let pvm_rs1 = self.require_reg(rs1)?;
            let lx = Self::var_imm_byte_count(jt_addr);

            self.emit_op(Opcode::LoadImmJumpInd);
            self.emit_data(pvm_rd | (pvm_rs1 << 4)); // reg_byte: ra=rd, rb=rs1
            self.emit_data(lx as u8); // lx: byte count for imm_x (return addr)
            self.emit_var_imm(jt_addr); // imm_x: jump table return address
            self.emit_var_imm(imm); // imm_y: offset added to rs1
        }
        Ok(())
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
