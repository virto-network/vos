//! Arithmetic and logic, with and without immediates, and the constants
//! they fuse.

use vos_pvm::instruction::Opcode;

use crate::TranspileError;

use super::TranslationContext;

impl TranslationContext {
    pub(super) fn translate_op_imm(
        &mut self,
        funct3: u32,
        funct7: u32,
        rd: u8,
        rs1: u8,
        imm: i32,
    ) -> Result<(), TranspileError> {
        // Track `li t0, N` (ADDI x5, x0, N) for ecall ID translation
        if funct3 == 0 && rd == 5 && rs1 == 0 {
            self.last_t0_imm = Some(imm);
        }

        // AUIPC+ADDI fusion: the full address, a jump-table address when it
        // is code (a function pointer), so indirect calls via djump work.
        if let Some((auipc_rd, auipc_val)) = self.pending_auipc.take() {
            if funct3 == 0 && rd == auipc_rd && rs1 == auipc_rd && rd != 0 {
                let full_addr = (auipc_val as i64 + imm as i64) as u64;
                return self.load_address(rd, full_addr);
            }
            // Not a matching ADDI — flush the pending AUIPC
            self.emit_load_imm(auipc_rd, auipc_val as i64)?;
        }

        // LUI+ADDI fusion: if there's a pending LUI and this is ADDI rd, rd, imm
        // with the same register, fuse into a single load_imm with the combined value.
        if let Some((lui_rd, lui_val)) = self.pending_lui.take() {
            if funct3 == 0 && rd == lui_rd && rs1 == lui_rd && rd != 0 {
                let combined = lui_val.wrapping_add(imm as i64);
                // Track for potential fusion with subsequent ALU op
                let pos = self.code.len();
                self.emit_load_imm(rd, combined)?;
                self.pending_load_imm = Some((rd, combined, pos));
                return Ok(());
            }
            // Not a matching ADDI — flush the pending LUI
            self.emit_load_imm(lui_rd, lui_val)?;
        }

        if rd == 0 {
            return Ok(());
        } // Write to x0 is a no-op in RISC-V

        // ADDI rd, rs, 0 is the RISC-V `mv rd, rs` pseudo-instruction.
        // Use compact move_reg (2 bytes) instead of add_imm (6 bytes).
        if funct3 == 0 && imm == 0 && rs1 != 0 {
            if rd == rs1 {
                // ADDI rd, rd, 0 is a NOP
                self.emit_op(Opcode::Fallthrough);
                return Ok(());
            }
            let pvm_rd = self.require_reg(rd)?;
            let pvm_rs1 = self.require_reg(rs1)?;
            self.emit_op(Opcode::MoveReg);
            self.emit_data(pvm_rd | (pvm_rs1 << 4));
            return Ok(());
        }

        // When rs1 = x0 (zero register), treat as loading immediate directly
        // because PVM has no zero register — x0 maps to RA which is NOT zero.
        if rs1 == 0 {
            match funct3 {
                0 => return self.emit_load_imm(rd, imm as i64), // li rd, imm
                2 => {
                    // SLTI rd, x0, imm → rd = (0 < imm) ? 1 : 0
                    return self.emit_load_imm(rd, if 0 < imm { 1 } else { 0 });
                }
                3 => {
                    // SLTIU rd, x0, imm → rd = (0 < imm unsigned) ? 1 : 0
                    return self.emit_load_imm(rd, if imm != 0 { 1 } else { 0 });
                }
                4 => return self.emit_load_imm(rd, imm as i64), // XORI rd, x0, imm = imm
                6 => return self.emit_load_imm(rd, imm as i64), // ORI rd, x0, imm = imm
                7 => return self.emit_load_imm(rd, 0),          // ANDI rd, x0, imm = 0
                // SLLI/SRLI/SRAI rd, x0, shamt → 0 (0 shifted any way is 0). MUST
                // emit it: PVM has no zero register (x0 maps to reg 0 = RA), so
                // falling through to the register path would shift RA, not 0.
                _ => return self.emit_load_imm(rd, 0),
            }
        }

        let pvm_rd = self.require_reg(rd)?;
        let pvm_rs1 = self.require_reg(rs1)?;

        let pvm_opcode = match funct3 {
            0 => Opcode::AddImm64, // ADDI
            1 => {
                if funct7 == 0x30 {
                    // Zbb unary: clz/ctz/cpop/sext.b/sext.h
                    let rs2 = (imm & 0x1F) as u8;
                    let opc = match rs2 {
                        0 => Opcode::LeadingZeroBits64,
                        1 => Opcode::TrailingZeroBits64,
                        2 => Opcode::CountSetBits64,
                        4 => Opcode::SignExtend8,
                        5 => Opcode::SignExtend16,
                        _ => {
                            return Err(TranspileError::UnsupportedInstruction {
                                offset: 0,
                                detail: format!("Zbb rs2={rs2}"),
                            });
                        }
                    };
                    self.emit_op(opc);
                    self.emit_data(pvm_rd | (pvm_rs1 << 4));
                    return Ok(());
                }
                // SLLI (funct7=0x00)
                let shamt = imm & 0x3F;
                self.emit_op(Opcode::ShloLImm64);
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_var_imm(shamt);
                return Ok(());
            }
            2 => Opcode::SetLtSImm, // SLTI
            3 => Opcode::SetLtUImm, // SLTIU
            4 => Opcode::XorImm,    // XORI
            5 => {
                if (funct7 == 0x35 || funct7 == 0x34) && (imm & 0x1F) == 0x18 {
                    // Zbb rev8 (RV64: 0x35, RV32: 0x34)
                    self.emit_op(Opcode::ReverseBytes);
                    self.emit_data(pvm_rd | (pvm_rs1 << 4));
                    return Ok(());
                }
                if funct7 == 0x30 || funct7 == 0x31 {
                    // Zbb RORI: funct6=0x18 (bits 31:26).
                    // funct7=0x30 when shamt<32, funct7=0x31 when shamt>=32 (bit 25 set).
                    let shamt = imm & 0x3F;
                    self.emit_op(Opcode::RotR64Imm);
                    self.emit_data(pvm_rd | (pvm_rs1 << 4));
                    self.emit_var_imm(shamt);
                    return Ok(());
                }
                if funct7 == 0x14 {
                    // Zbb orc.b — OR-combine bytes
                    // No PVM equivalent; emit as trap (rare instruction)
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: "Zbb orc.b not yet supported".into(),
                    });
                }
                // SRLI (funct7=0x00) / SRAI (funct7=0x20+)
                let shamt = imm & 0x3F;
                if funct7 & 0x20 != 0 {
                    self.emit_op(Opcode::SharRImm64);
                } else {
                    self.emit_op(Opcode::ShloRImm64);
                }
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_var_imm(shamt);
                return Ok(());
            }
            6 => Opcode::OrImm,  // ORI
            7 => Opcode::AndImm, // ANDI
            _ => unreachable!(),
        };

        self.emit_op(pvm_opcode);
        self.emit_data(pvm_rd | (pvm_rs1 << 4));
        self.emit_var_imm(imm);

        Ok(())
    }

    /// An OP whose source is x0: fold it to a constant, a move or a
    /// one-register form, as RISC-V defines it (division by zero gives all
    /// ones, remainder by zero the dividend).
    fn translate_op_with_zero(
        &mut self,
        funct3: u32,
        funct7: u32,
        rd: u8,
        rs1: u8,
        rs2: u8,
        addr: u64,
    ) -> Result<(), TranspileError> {
        let unhandled = || TranspileError::UnsupportedInstruction {
            offset: addr as usize,
            detail: format!("unhandled x0 op: funct7={funct7:#x} funct3={funct3}"),
        };
        let pvm_rd = self.require_reg(rd)?;
        let mov = |this: &mut Self, from: u8| -> Result<(), TranspileError> {
            let pvm_from = this.require_reg(from)?;
            this.emit_op(Opcode::MoveReg);
            this.emit_data(pvm_rd | (pvm_from << 4));
            Ok(())
        };
        if rs1 == 0 && rs2 == 0 {
            let value = match (funct7, funct3) {
                (1, 4) | (1, 5) => -1, // DIV/DIVU by zero
                (0, _) | (0x20, 0) | (0x20, 5) | (1, _) => 0,
                _ => return Err(unhandled()),
            };
            return self.emit_load_imm(rd, value);
        }
        if rs1 == 0 {
            let pvm_rs2 = self.require_reg(rs2)?;
            match (funct7, funct3) {
                // ADD/XOR/OR rd, x0, rs2 → rs2
                (0, 0) | (0, 4) | (0, 6) => mov(self, rs2)?,
                // SUB rd, x0, rs2 → 0 - rs2
                (0x20, 0) => {
                    self.emit_op(Opcode::NegAddImm64);
                    self.emit_data(pvm_rd | (pvm_rs2 << 4));
                    self.emit_var_imm(0);
                }
                // Shifts of zero, AND with zero, products and remainders of
                // zero are zero.
                (0, 1) | (0, 5) | (0x20, 5) | (0, 7) | (1, 0..=3) | (1, 6) | (1, 7) => {
                    self.emit_load_imm(rd, 0)?;
                }
                // SLT rd, x0, rs2 → rs2 > 0 (signed)
                (0, 2) => {
                    self.emit_op(Opcode::SetGtSImm);
                    self.emit_data(pvm_rd | (pvm_rs2 << 4));
                    self.emit_var_imm(0);
                }
                // SLTU rd, x0, rs2 → rs2 != 0
                (0, 3) => {
                    if pvm_rd != pvm_rs2 {
                        self.emit_load_imm(rd, 0)?;
                    }
                    // if rs2 != 0 then rd = imm
                    self.emit_op(Opcode::CmovNzImm);
                    self.emit_data(pvm_rd | (pvm_rs2 << 4));
                    self.emit_var_imm(1);
                }
                // DIV/DIVU rd, x0, rs2 → all ones when rs2 is zero, else 0:
                // rd = 0 - (rs2 <u 1).
                (1, 4) | (1, 5) => {
                    self.emit_op(Opcode::SetLtUImm);
                    self.emit_data(pvm_rd | (pvm_rs2 << 4));
                    self.emit_var_imm(1);
                    self.emit_op(Opcode::NegAddImm64);
                    self.emit_data(pvm_rd | (pvm_rd << 4));
                    self.emit_var_imm(0);
                }
                _ => return Err(unhandled()),
            }
            return Ok(());
        }
        let pvm_rs1 = self.require_reg(rs1)?;
        match (funct7, funct3) {
            // ADD/SUB/XOR/OR and shifts by zero, remainders by zero → rs1
            (0, 0)
            | (0x20, 0)
            | (0, 4)
            | (0, 6)
            | (0, 1)
            | (0, 5)
            | (0x20, 5)
            | (1, 6)
            | (1, 7) => {
                mov(self, rs1)?;
            }
            // SLT rd, rs1, x0 → rs1 < 0 (signed); SLTU is always 0.
            (0, 2) => {
                self.emit_op(Opcode::SetLtSImm);
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_var_imm(0);
            }
            (0, 3) | (0, 7) | (1, 0..=3) => self.emit_load_imm(rd, 0)?,
            // DIV/DIVU by zero → all ones
            (1, 4) | (1, 5) => self.emit_load_imm(rd, -1)?,
            _ => return Err(unhandled()),
        }
        Ok(())
    }

    pub(super) fn translate_op(
        &mut self,
        funct3: u32,
        funct7: u32,
        rd: u8,
        rs1: u8,
        rs2: u8,
        addr: u64,
    ) -> Result<(), TranspileError> {
        if rd == 0 {
            return Ok(());
        } // Write to x0 is a no-op in RISC-V

        // Fuse load_imm + ALU op: if one operand was just loaded via load_imm
        // and the value fits in i32, emit the immediate form instead; the
        // load goes too when this overwrites it (`drop_dead_load`). An x0
        // operand has no PVM register to fuse with: the zero path takes it.
        if let Some((load_rd, load_val, undo_pos)) = self.pending_load_imm.take()
            && rs1 != 0
            && rs2 != 0
            && load_val >= i32::MIN as i64
            && load_val <= i32::MAX as i64
        {
            let imm = load_val as i32;
            // Check if rs2 is the loaded register (ADD/AND/OR/XOR rd, rs1, load_rd)
            let fuse_base = if rs2 == load_rd && rs1 != load_rd {
                Some(rs1)
            } else if rs1 == load_rd
                && rs2 != load_rd
                // The imm sits on the LEFT operand here, so the fused form must be
                // commutative. SUB, SLT and SLTU are not: `imm - rs2`, `imm < rs2`
                // and `imm <u rs2` have no left-immediate PVM form (add/set_lt_*_imm
                // all put the immediate on the right), so fusing would silently
                // swap the operands. Leave them to the register path.
                && (funct7, funct3) != (0x20, 0) // SUB
                && (funct7, funct3) != (0, 2) // SLT
                && (funct7, funct3) != (0, 3)
            // SLTU
            {
                Some(rs2)
            } else {
                None
            };

            if let Some(base) = fuse_base {
                let pvm_imm_opcode = match (funct7, funct3) {
                    (0, 0) => Some(Opcode::AddImm64),  // ADD
                    (0, 7) => Some(Opcode::AndImm),    // AND
                    (0, 6) => Some(Opcode::OrImm),     // OR
                    (0, 4) => Some(Opcode::XorImm),    // XOR
                    (1, 0) => Some(Opcode::MulImm64),  // MUL
                    (0, 2) => Some(Opcode::SetLtSImm), // SLT
                    (0, 3) => Some(Opcode::SetLtUImm), // SLTU
                    _ => None,
                };

                if let Some(pvm_opcode) = pvm_imm_opcode {
                    // A switch table reads its base twice: add idx, base, idx;
                    // lw off, 0(idx); add target, off, base; jr target.
                    self.drop_dead_load(rd, load_rd, undo_pos, addr);
                    let pvm_rd = self.require_reg(rd)?;
                    let pvm_base = self.require_reg(base)?;
                    self.emit_op(pvm_opcode);
                    self.emit_data(pvm_rd | (pvm_base << 4));
                    self.emit_var_imm(imm);
                    return Ok(());
                }
            }

            // Special case: shifts with loaded shift count → shift immediate forms.
            // SLL/SRL/SRA rd, rs1, load_rd → shlo_l/shlo_r/shar_r_imm rd, rs1, imm
            // The shifted register must not be the constant's own, which
            // the fusion may drop.
            if rs2 == load_rd
                && rs1 != load_rd
                && matches!((funct7, funct3), (0, 1) | (0, 5) | (0x20, 5))
            {
                let pvm_imm_opcode = match (funct7, funct3) {
                    (0, 1) => Opcode::ShloLImm64,    // SLL
                    (0, 5) => Opcode::ShloRImm64,    // SRL
                    (0x20, 5) => Opcode::SharRImm64, // SRA
                    _ => unreachable!(),
                };
                self.drop_dead_load(rd, load_rd, undo_pos, addr);
                let pvm_rd = self.require_reg(rd)?;
                let pvm_rs1 = self.require_reg(rs1)?;
                self.emit_op(pvm_imm_opcode);
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_var_imm(imm);
                return Ok(());
            }

            // Special case: SUB rd, rs1, load_rd → neg_add_imm rd, rs1, -imm
            // SUB is not commutative, but if rs2 is the loaded register:
            // rd = rs1 - imm = rs1 + (-imm)
            if (funct7, funct3) == (0x20, 0) && rs2 == load_rd && rs1 != load_rd {
                let neg_imm = (-(load_val as i32) as i64) as i32;
                // Use add_imm with negated immediate (avoids neg_add_imm)
                self.drop_dead_load(rd, load_rd, undo_pos, addr);
                let pvm_rd = self.require_reg(rd)?;
                let pvm_rs1 = self.require_reg(rs1)?;
                self.emit_op(Opcode::AddImm64);
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_var_imm(neg_imm);
                return Ok(());
            }
        }
        // Couldn't fuse — load_imm is already emitted, just proceed normally

        // An x0 source reads zero, but PVM register 0 holds RA: no operand
        // below may name it.
        if rs1 == 0 || rs2 == 0 {
            return self.translate_op_with_zero(funct3, funct7, rd, rs1, rs2, addr);
        }

        let pvm_rd = self.require_reg(rd)?;
        let pvm_rs1 = self.require_reg(rs1)?;
        let pvm_rs2 = self.require_reg(rs2)?;

        let pvm_opcode = if funct7 == 1 {
            // M extension (multiply/divide)
            match funct3 {
                0 => Opcode::Mul64,      // MUL
                1 => Opcode::MulUpperSS, // MULH (always 64-bit, gives upper bits)
                2 => Opcode::MulUpperSU, // MULHSU
                3 => Opcode::MulUpperUU, // MULHU
                4 => Opcode::DivS64,     // DIV
                5 => Opcode::DivU64,     // DIVU
                6 => Opcode::RemS64,     // REM
                7 => Opcode::RemU64,     // REMU
                _ => unreachable!(),
            }
        } else if funct7 == 0x20 {
            match funct3 {
                0 => Opcode::Sub64,   // SUB
                5 => Opcode::SharR64, // SRA
                7 | 6 | 4 => {
                    // Zbb ANDN/ORN/XNOR: rd = rs1 OP ~rs2
                    if rd == rs1 && rd == rs2 {
                        return self.emit_load_imm(rd, if funct3 == 7 { 0 } else { -1i64 });
                    }
                    let alu = match funct3 {
                        7 => Opcode::And,
                        6 => Opcode::Or,
                        _ => Opcode::Xor,
                    };
                    if rd != rs1 {
                        // use rd as temp for ~rs2
                        self.emit_op(Opcode::XorImm);
                        self.emit_data(pvm_rd | (pvm_rs2 << 4));
                        self.emit_var_imm(-1);
                        self.emit_op(alu);
                        self.emit_data(pvm_rs1 | (pvm_rd << 4));
                        self.emit_data(pvm_rd);
                    } else {
                        // rd==rs1: NOT rs2 in-place, OP, restore
                        self.emit_op(Opcode::XorImm);
                        self.emit_data(pvm_rs2 | (pvm_rs2 << 4));
                        self.emit_var_imm(-1);
                        self.emit_op(alu);
                        self.emit_data(pvm_rd | (pvm_rs2 << 4));
                        self.emit_data(pvm_rd);
                        self.emit_op(Opcode::XorImm);
                        self.emit_data(pvm_rs2 | (pvm_rs2 << 4));
                        self.emit_var_imm(-1);
                    }
                    return Ok(());
                }
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("OP funct7=0x20 funct3={funct3}"),
                    });
                }
            }
        } else if funct7 == 0x05 {
            // Zbb min/max
            match funct3 {
                4 => Opcode::Min,
                5 => Opcode::MinU,
                6 => Opcode::Max,
                7 => Opcode::MaxU,
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("Zbb f7=5 f3={funct3}"),
                    });
                }
            }
        } else if funct7 == 0x30 {
            // Zbb rotations — emit and return early
            let opc = match funct3 {
                1 => Opcode::RotL64,
                5 => Opcode::RotR64,
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("Zbb f7=30 f3={funct3}"),
                    });
                }
            };
            self.emit_op(opc);
            self.emit_data(pvm_rs1 | (pvm_rs2 << 4));
            self.emit_data(pvm_rd);
            return Ok(());
        } else if funct7 == 0 {
            match funct3 {
                0 => Opcode::Add64,   // ADD
                1 => Opcode::ShloL64, // SLL
                2 => Opcode::SetLtS,  // SLT
                3 => Opcode::SetLtU,  // SLTU
                4 => Opcode::Xor,     // XOR
                5 => Opcode::ShloR64, // SRL
                6 => Opcode::Or,      // OR
                7 => Opcode::And,     // AND
                _ => unreachable!(),
            }
        } else {
            return Err(TranspileError::UnsupportedInstruction {
                offset: 0,
                detail: format!("OP funct7={funct7:#x} funct3={funct3}"),
            });
        };

        // ThreeReg encoding: byte1 = rA | (rB << 4), byte2 = rD
        self.emit_op(pvm_opcode);
        self.emit_data(pvm_rs1 | (pvm_rs2 << 4));
        self.emit_data(pvm_rd);

        Ok(())
    }

    pub(super) fn translate_op_imm_32(
        &mut self,
        funct3: u32,
        funct7: u32,
        rd: u8,
        rs1: u8,
        imm: i32,
    ) -> Result<(), TranspileError> {
        if rd == 0 {
            return Ok(());
        }

        // rs1 = x0 (zero): PVM has no zero register (x0 maps to reg 0 = RA), so
        // materialize the result directly instead of operating on RA. Mirrors the
        // rs1==0 handling in `translate_op_imm`.
        if rs1 == 0 {
            match funct3 {
                0 => return self.emit_load_imm(rd, imm as i64), // ADDIW rd, x0, imm = sext32(imm)
                1 if funct7 != 0x30 => return self.emit_load_imm(rd, 0), // SLLIW rd, x0, _ = 0
                5 if funct7 != 0x30 => return self.emit_load_imm(rd, 0), // SRLIW/SRAIW rd, x0, _ = 0
                _ => {} // Zbb unary (clzw/ctzw/cpopw/roriw) on x0 → general path (no Zbb on target)
            }
        }

        let pvm_rd = self.require_reg(rd)?;
        let pvm_rs1 = self.require_reg(rs1)?;

        match funct3 {
            0 => {
                // ADDIW
                self.emit_op(Opcode::AddImm32);
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_var_imm(imm);
            }
            1 => {
                if funct7 == 0x30 {
                    // Zbb: clzw(rs2=0), ctzw(rs2=1), cpopw(rs2=2)
                    let rs2 = (imm & 0x1F) as u8;
                    let opc = match rs2 {
                        0 => Opcode::LeadingZeroBits32,
                        1 => Opcode::TrailingZeroBits32,
                        2 => Opcode::CountSetBits32,
                        _ => {
                            return Err(TranspileError::UnsupportedInstruction {
                                offset: 0,
                                detail: format!("Zbb-W rs2={rs2}"),
                            });
                        }
                    };
                    self.emit_op(opc);
                    self.emit_data(pvm_rd | (pvm_rs1 << 4));
                } else {
                    // SLLIW (funct7=0x00)
                    let shamt = imm & 0x1F;
                    self.emit_op(Opcode::ShloLImm32);
                    self.emit_data(pvm_rd | (pvm_rs1 << 4));
                    self.emit_var_imm(shamt);
                }
            }
            5 => {
                let shamt = imm & 0x1F;
                if funct7 == 0x30 {
                    // Zbb roriw
                    self.emit_op(Opcode::RotR32Imm);
                } else if funct7 & 0x20 != 0 {
                    // SRAIW (funct7=0x20)
                    self.emit_op(Opcode::SharRImm32);
                } else {
                    // SRLIW (funct7=0x00)
                    self.emit_op(Opcode::ShloRImm32);
                }
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_var_imm(shamt);
            }
            _ => {
                return Err(TranspileError::UnsupportedInstruction {
                    offset: 0,
                    detail: format!("OP-IMM-32 funct3={funct3}"),
                });
            }
        }

        Ok(())
    }

    /// An OP-32 whose source is x0, as [`Self::translate_op_with_zero`]:
    /// results are the low 32 bits, sign-extended.
    fn translate_op_32_with_zero(
        &mut self,
        funct3: u32,
        funct7: u32,
        rd: u8,
        rs1: u8,
        rs2: u8,
        addr: u64,
    ) -> Result<(), TranspileError> {
        let unhandled = || TranspileError::UnsupportedInstruction {
            offset: addr as usize,
            detail: format!("unhandled x0 OP-32: funct7={funct7:#x} funct3={funct3}"),
        };
        let pvm_rd = self.require_reg(rd)?;
        // rd = sign-extended low 32 bits of `from`.
        let sext = |this: &mut Self, from: u8| -> Result<(), TranspileError> {
            let pvm_from = this.require_reg(from)?;
            this.emit_op(Opcode::AddImm32);
            this.emit_data(pvm_rd | (pvm_from << 4));
            this.emit_var_imm(0);
            Ok(())
        };
        if rs1 == 0 && rs2 == 0 {
            let value = match (funct7, funct3) {
                (1, 4) | (1, 5) => -1, // DIVW/DIVUW by zero
                (0, 0) | (0x20, 0) | (0, 1) | (0, 5) | (0x20, 5) | (1, 0) | (1, 6) | (1, 7) => 0,
                (0x04, 4) => 0, // PACKW of zeros
                _ => return Err(unhandled()),
            };
            return self.emit_load_imm(rd, value);
        }
        if rs1 == 0 {
            let pvm_rs2 = self.require_reg(rs2)?;
            match (funct7, funct3) {
                (0, 0) => sext(self, rs2)?, // ADDW rd, x0, rs2
                (0x20, 0) => {
                    // SUBW rd, x0, rs2 → negw
                    self.emit_op(Opcode::NegAddImm32);
                    self.emit_data(pvm_rd | (pvm_rs2 << 4));
                    self.emit_var_imm(0);
                }
                (0, 1) | (0, 5) | (0x20, 5) | (1, 0) | (1, 6) | (1, 7) => {
                    self.emit_load_imm(rd, 0)?;
                }
                // DIVW/DIVUW rd, x0, rs2 → all ones when rs2's low word is
                // zero, else 0.
                (1, 4) | (1, 5) => {
                    sext(self, rs2)?;
                    self.emit_op(Opcode::SetLtUImm);
                    self.emit_data(pvm_rd | (pvm_rd << 4));
                    self.emit_var_imm(1);
                    self.emit_op(Opcode::NegAddImm64);
                    self.emit_data(pvm_rd | (pvm_rd << 4));
                    self.emit_var_imm(0);
                }
                _ => return Err(unhandled()),
            }
            return Ok(());
        }
        let pvm_rs1 = self.require_reg(rs1)?;
        match (funct7, funct3) {
            // ADDW/SUBW, shifts by zero and remainders by zero → sext(rs1)
            (0, 0) | (0x20, 0) | (0, 1) | (0, 5) | (0x20, 5) | (1, 6) | (1, 7) => sext(self, rs1)?,
            (1, 0) => self.emit_load_imm(rd, 0)?,
            (1, 4) | (1, 5) => self.emit_load_imm(rd, -1)?,
            (0x04, 4) => {
                // PACKW rd, rs1, x0 = ZEXT.H rd, rs1 (Zbb)
                self.emit_op(Opcode::AndImm);
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_var_imm(0xFFFF);
            }
            _ => return Err(unhandled()),
        }
        Ok(())
    }

    pub(super) fn translate_op_32(
        &mut self,
        funct3: u32,
        funct7: u32,
        rd: u8,
        rs1: u8,
        rs2: u8,
        addr: u64,
    ) -> Result<(), TranspileError> {
        if rd == 0 {
            return Ok(());
        }

        // Fuse load_imm + 32-bit ALU op: ADDW, MULW, SUB as negated ADD. An x0
        // operand goes to the zero path unfused.
        if let Some((load_rd, load_val, undo_pos)) = self.pending_load_imm.take()
            && rs1 != 0
            && rs2 != 0
            && load_val >= i32::MIN as i64
            && load_val <= i32::MAX as i64
        {
            let imm = load_val as i32;
            let fuse_base = if rs2 == load_rd && rs1 != load_rd {
                Some(rs1)
            } else if rs1 == load_rd && rs2 != load_rd && (funct7, funct3) != (0x20, 0) {
                Some(rs2)
            } else {
                None
            };

            if let Some(base) = fuse_base {
                let pvm_imm_opcode = match (funct7, funct3) {
                    (0, 0) => Some(Opcode::AddImm32), // ADDW
                    (1, 0) => Some(Opcode::MulImm32), // MULW
                    _ => None,
                };
                if let Some(pvm_opcode) = pvm_imm_opcode {
                    self.drop_dead_load(rd, load_rd, undo_pos, addr);
                    let pvm_rd = self.require_reg(rd)?;
                    let pvm_base = self.require_reg(base)?;
                    self.emit_op(pvm_opcode);
                    self.emit_data(pvm_rd | (pvm_base << 4));
                    self.emit_var_imm(imm);
                    return Ok(());
                }
            }
            // 32-bit shifts with loaded shift count → shift immediate forms.
            // SLLW/SRLW/SRAW rd, rs1, load_rd → shlo_l/shlo_r/shar_r_imm_32
            // The shifted register must not be the constant's own, which
            // the fusion may drop.
            if rs2 == load_rd
                && rs1 != load_rd
                && matches!((funct7, funct3), (0, 1) | (0, 5) | (0x20, 5))
            {
                let pvm_imm_opcode = match (funct7, funct3) {
                    (0, 1) => Opcode::ShloLImm32,    // SLLW
                    (0, 5) => Opcode::ShloRImm32,    // SRLW
                    (0x20, 5) => Opcode::SharRImm32, // SRAW
                    _ => unreachable!(),
                };
                self.drop_dead_load(rd, load_rd, undo_pos, addr);
                let pvm_rd = self.require_reg(rd)?;
                let pvm_rs1 = self.require_reg(rs1)?;
                self.emit_op(pvm_imm_opcode);
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_var_imm(imm);
                return Ok(());
            }

            // SUB with loaded rs2: SUBW rd, rs1, load_rd → add_imm_32 rd, rs1, -imm
            if (funct7, funct3) == (0x20, 0) && rs2 == load_rd && rs1 != load_rd {
                let neg_imm = (-(load_val as i32) as i64) as i32;
                self.drop_dead_load(rd, load_rd, undo_pos, addr);
                let pvm_rd = self.require_reg(rd)?;
                let pvm_rs1 = self.require_reg(rs1)?;
                self.emit_op(Opcode::AddImm32);
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_var_imm(neg_imm);
                return Ok(());
            }
        }
        // Couldn't fuse

        // An x0 source reads zero, but PVM register 0 holds RA: no operand
        // below may name it.
        if rs1 == 0 || rs2 == 0 {
            return self.translate_op_32_with_zero(funct3, funct7, rd, rs1, rs2, addr);
        }

        let pvm_rd = self.require_reg(rd)?;
        let pvm_rs1 = self.require_reg(rs1)?;
        let pvm_rs2 = self.require_reg(rs2)?;

        let pvm_opcode = if funct7 == 1 {
            match funct3 {
                0 => Opcode::Mul32,  // MULW
                4 => Opcode::DivS32, // DIVW
                5 => Opcode::DivU32, // DIVUW
                6 => Opcode::RemS32, // REMW
                7 => Opcode::RemU32, // REMUW
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("OP-32 M funct3={funct3}"),
                    });
                }
            }
        } else if funct7 == 0x20 {
            match funct3 {
                0 => Opcode::Sub32,   // SUBW
                5 => Opcode::SharR32, // SRAW
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("OP-32 funct7=0x20 funct3={funct3}"),
                    });
                }
            }
        } else if funct7 == 0x30 {
            // Zbb rolw/rorw
            let opc = match funct3 {
                1 => Opcode::RotL32,
                5 => Opcode::RotR32,
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("OP-32 f7=30 f3={funct3}"),
                    });
                }
            };
            self.emit_op(opc);
            self.emit_data(pvm_rs1 | (pvm_rs2 << 4));
            self.emit_data(pvm_rd);
            return Ok(());
        } else if funct7 == 0x04 && funct3 == 4 {
            // Zbb zext.h
            self.emit_op(Opcode::ZeroExtend16);
            self.emit_data(pvm_rd | (pvm_rs1 << 4));
            return Ok(());
        } else if funct7 == 0 {
            match funct3 {
                0 => Opcode::Add32,   // ADDW
                1 => Opcode::ShloL32, // SLLW
                5 => Opcode::ShloR32, // SRLW
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("OP-32 funct3={funct3}"),
                    });
                }
            }
        } else {
            return Err(TranspileError::UnsupportedInstruction {
                offset: 0,
                detail: format!("OP-32 funct7={funct7:#x} funct3={funct3}"),
            });
        };

        // ThreeReg encoding: byte1 = rA | (rB << 4), byte2 = rD
        self.emit_op(pvm_opcode);
        self.emit_data(pvm_rs1 | (pvm_rs2 << 4));
        self.emit_data(pvm_rd);

        Ok(())
    }

    /// Remove the pending `load_imm` an instruction fuses as its immediate,
    /// when the instruction writes the loaded register: only then is the
    /// constant dead. Any other instruction leaves the register holding it
    /// for later reads, which nothing here can rule out. A fused form must
    /// therefore never read the loaded register as an operand: the
    /// immediate is its value, and this may remove it.
    ///
    /// The fused instruction then starts where the load did. No edge can
    /// land between them: `begin_instruction` flushes pending state at every
    /// control-flow target, so a target is never fused into its
    /// predecessor's load.
    pub(super) fn drop_dead_load(&mut self, rd: u8, load_rd: u8, undo_pos: usize, addr: u64) {
        if rd == load_rd {
            self.code.truncate(undo_pos);
            self.bitmask.truncate(undo_pos);
            self.address_map.insert(addr, undo_pos as u32);
        }
    }
}
