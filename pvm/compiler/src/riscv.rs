//! RISC-V instruction decoder and PVM instruction translator.
//!
//! Decodes rv64em instructions and translates them to equivalent
//! PVM bytecode sequences.

use std::collections::{BTreeSet, HashMap};

use vos_pvm::instruction::Opcode;

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
fn map_register(rv_reg: u8) -> Result<Option<u8>, TranspileError> {
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

    fn translate_jalr(
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

    fn translate_branch(
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

    pub(crate) fn translate_load(
        &mut self,
        funct3: u32,
        rd: u8,
        rs1: u8,
        imm: i32,
        addr: u64,
    ) -> Result<(), TranspileError> {
        if rd == 0 {
            return Ok(());
        } // Write to x0 is a no-op

        // Fuse `load_imm rs1, K; load rd, off(rs1)` into a direct
        // absolute-address load — but ONLY when the load overwrites its own base
        // (`rd == rs1`). Then the loaded constant is dead after the load, so the
        // load_imm is truncated away and an instruction is saved.
        //
        // When `rd != rs1` the base register must survive (it may be reused —
        // e.g. a switch-table base, or simply a later access through it), so the
        // load_imm cannot be removed: a direct load would save nothing AND the
        // base-preserved direct-load path mis-resolves, so we must NOT fuse —
        // fall through to the indirect `load_ind rd, rs1, off`, which reads the
        // same address (rs1 still holds K) and is correct.
        if let Some((load_rd, load_val, undo_pos)) = self.pending_load_imm.take()
            && rs1 == load_rd
            && rd == rs1
        {
            let combined = load_val.wrapping_add(imm as i64);
            if combined >= i32::MIN as i64
                && combined <= i32::MAX as i64
                && let Some(opc) = direct_load(funct3)
            {
                // The load overwrites its base, so the load_imm is dead:
                // truncate it and repoint this instruction's address_map
                // entry to the fused load, else a branch targeting this load
                // resolves past the removed load_imm — into the middle of an
                // instruction (cf. translate_op, which does the same).
                self.drop_dead_load(rd, load_rd, undo_pos, addr);
                let pvm_rd = self.require_reg(rd)?;
                self.emit_op(opc);
                self.emit_data(pvm_rd);
                self.emit_var_imm(combined as i32);
                return Ok(());
            }
        }
        // Couldn't fuse — load_imm already emitted, just proceed

        // Base x0: a load from the absolute address `imm`.
        if rs1 == 0 {
            let opcode =
                direct_load(funct3).ok_or_else(|| TranspileError::UnsupportedInstruction {
                    offset: addr as usize,
                    detail: format!("load funct3={funct3}"),
                })?;
            let pvm_rd = self.require_reg(rd)?;
            self.emit_op(opcode);
            self.emit_data(pvm_rd);
            self.emit_var_imm(imm);
            return Ok(());
        }

        let pvm_rd = self.require_reg(rd)?;
        let pvm_rs1 = self.require_reg(rs1)?;

        // Two register + one immediate
        let pvm_opcode = match funct3 {
            0 => Opcode::LoadIndI8,  // LB
            1 => Opcode::LoadIndI16, // LH
            2 => Opcode::LoadIndI32, // LW
            3 => Opcode::LoadIndU64, // LD
            4 => Opcode::LoadIndU8,  // LBU
            5 => Opcode::LoadIndU16, // LHU
            6 => Opcode::LoadIndU32, // LWU
            _ => {
                return Err(TranspileError::UnsupportedInstruction {
                    offset: 0,
                    detail: format!("load funct3={funct3}"),
                });
            }
        };

        self.emit_op(pvm_opcode);
        self.emit_data(pvm_rd | (pvm_rs1 << 4));
        self.emit_var_imm(imm);

        Ok(())
    }

    pub(crate) fn translate_store(
        &mut self,
        funct3: u32,
        rs1: u8,
        rs2: u8,
        imm: i32,
        addr: u64,
    ) -> Result<(), TranspileError> {
        // A store does not overwrite its base register. Removing a preceding
        // `load_imm base, address` is therefore unsound without whole-block
        // liveness: a later load/store may reuse `base`. Keep the already
        // emitted address load and only clear the adjacent-fusion candidate.
        self.pending_load_imm = None;

        // Base x0: a store to the absolute address `imm`.
        if rs1 == 0 {
            let unsupported = || TranspileError::UnsupportedInstruction {
                offset: addr as usize,
                detail: format!("store funct3={funct3}"),
            };
            if rs2 == 0 {
                // store_imm_u* [imm], 0: TwoImm, the address first.
                let opcode = match funct3 {
                    0 => Opcode::StoreImmU8,
                    1 => Opcode::StoreImmU16,
                    2 => Opcode::StoreImmU32,
                    3 => Opcode::StoreImmU64,
                    _ => return Err(unsupported()),
                };
                let (lx, address) = encode_var_imm(imm);
                self.emit_op(opcode);
                self.emit_data(lx);
                for byte in address {
                    self.emit_data(byte);
                }
            } else {
                // store_u* [imm], rs2
                let opcode = match funct3 {
                    0 => Opcode::StoreU8,
                    1 => Opcode::StoreU16,
                    2 => Opcode::StoreU32,
                    3 => Opcode::StoreU64,
                    _ => return Err(unsupported()),
                };
                let pvm_rs2 = self.require_reg(rs2)?;
                self.emit_op(opcode);
                self.emit_data(pvm_rs2);
                self.emit_var_imm(imm);
            }
            return Ok(());
        }

        // x0 (zero register) has no PVM equivalent — PVM reg 0 is RA, not zero.
        // Use store_imm_ind_* to store a literal zero instead.
        if rs2 == 0 {
            let pvm_rs1 = self.require_reg(rs1)?;
            let pvm_opcode = match funct3 {
                0 => Opcode::StoreImmIndU8,
                1 => Opcode::StoreImmIndU16,
                2 => Opcode::StoreImmIndU32,
                3 => Opcode::StoreImmIndU64,
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("store funct3={funct3}"),
                    });
                }
            };
            // Format: OneRegTwoImm — reg_byte encodes ra + imm_x length
            // reg_byte = ra | (lx << 4)
            // imm_y has length 0, which decodes as 0 (the value we want to store)
            let (lx, imm_bytes) = encode_var_imm(imm);
            self.emit_op(pvm_opcode);
            self.emit_data(pvm_rs1 | (lx << 4));
            for b in &imm_bytes {
                self.emit_data(*b);
            }
            return Ok(());
        }

        let pvm_rs2 = self.require_reg(rs2)?; // data register → rD
        let pvm_rs1 = self.require_reg(rs1)?; // base register → rA

        let pvm_opcode = match funct3 {
            0 => Opcode::StoreIndU8,  // SB
            1 => Opcode::StoreIndU16, // SH
            2 => Opcode::StoreIndU32, // SW
            3 => Opcode::StoreIndU64, // SD
            _ => {
                return Err(TranspileError::UnsupportedInstruction {
                    offset: 0,
                    detail: format!("store funct3={funct3}"),
                });
            }
        };

        self.emit_op(pvm_opcode);
        self.emit_data(pvm_rs2 | (pvm_rs1 << 4));
        self.emit_var_imm(imm);

        Ok(())
    }

    fn translate_op_imm(
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

    fn translate_op(
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

    fn translate_op_imm_32(
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

    fn translate_op_32(
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

    // ===== Helpers =====

    /// The PVM register for a RISC-V register other than x0. x0 has none:
    /// PVM register 0 holds the return address, so every caller handles x0
    /// itself, as a zero source or a discarded result.
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
    fn drop_dead_load(&mut self, rd: u8, load_rd: u8, undo_pos: usize, addr: u64) {
        if rd == load_rd {
            self.code.truncate(undo_pos);
            self.bitmask.truncate(undo_pos);
            self.address_map.insert(addr, undo_pos as u32);
        }
    }

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

/// A direct load's opcode for a RISC-V load's `funct3`.
fn direct_load(funct3: u32) -> Option<Opcode> {
    match funct3 {
        0 => Some(Opcode::LoadI8),  // LB
        1 => Some(Opcode::LoadI16), // LH
        2 => Some(Opcode::LoadI32), // LW
        3 => Some(Opcode::LoadU64), // LD
        4 => Some(Opcode::LoadU8),  // LBU
        5 => Some(Opcode::LoadU16), // LHU
        6 => Some(Opcode::LoadU32), // LWU
        _ => None,
    }
}

// ===== RISC-V instruction decoding =====

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
fn csr(inst: u32) -> u32 {
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

fn decode_s_imm(inst: u32) -> i32 {
    let imm11_5 = (inst >> 25) & 0x7F;
    let imm4_0 = (inst >> 7) & 0x1F;
    let imm = (imm11_5 << 5) | imm4_0;
    if imm11_5 & 0x40 != 0 {
        (imm | 0xFFFFF000) as i32
    } else {
        imm as i32
    }
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
