//! Loads and stores.

use vos_pvm::instruction::Opcode;

use crate::TranspileError;

use super::{TranslationContext, encode_var_imm};

impl TranslationContext {
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
