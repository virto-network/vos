//! The row's instruction: its operands, result, flags and registers.

use super::*;

/// A row's operands and result, as its columns hold them.
#[derive(Clone, Copy)]
pub(super) struct Operands {
    pub val_b: u64,
    pub val_d: u64,
    pub result: u64,
    pub val_b_bytes: [u8; WORD_SIZE],
    pub val_d_bytes: [u8; WORD_SIZE],
    pub result_bytes: [u8; WORD_SIZE],
    pub is_witness: bool,
    pub saved_shift_amount: u8,
    pub saved_shift_amount_compl: u8,
    pub saved_shift_quotient_compl: u64,
}

/// The row's instruction, its operands and its result.
pub(super) fn operands(out: &mut Sinks, s: Step) -> Operands {
    let Sinks {
        trace, side_note, ..
    } = out;
    let Step { row, step, flags } = s;
    trace.fill_columns(row, step.timestamp, Column::Timestamp);
    trace.fill_columns_bytes(row, &step.pc.to_le_bytes(), Column::Pc);
    trace.fill_columns_bytes(row, &step.next_pc.to_le_bytes(), Column::NextPc);
    // Commit the exact encoded byte, not the semantic enum: invalid
    // bytes must not alias canonical Trap in the public program
    // commitment.
    let encoded_opcode = side_note
        .code
        .get(step.pc as usize)
        .copied()
        .unwrap_or_default();
    trace.fill_columns(row, encoded_opcode, Column::Opcode);
    trace.fill_columns(row, step.skip_len as u8, Column::SkipLen);
    // 8-byte immediate witness for the ProgramMemory lookup.
    trace.fill_columns_bytes(row, &step.imm.to_le_bytes(), Column::ImmBytes);
    let host_call_precompile_dispatch =
        if matches!(step.opcode, crate::core::opcode::Opcode::Ecalli) {
            crate::core::ecall::proof_precompile_dispatch_id(step.imm)
        } else {
            0
        };
    trace.fill_columns(
        row,
        host_call_precompile_dispatch,
        Column::HostCallPrecompileDispatch,
    );
    // charge ProgramMemoryChip for this step's instruction
    // fetch.  Two consumer emissions per step (paired) → producer
    // multiplicity = 2 · count_at_pc.
    *side_note.program_memory_counts.entry(step.pc).or_insert(0) += 2;
    // PC carry for sequential next_pc = pc + 1 + skip_len
    {
        let pc_bytes = step.pc.to_le_bytes();
        let sum0 = pc_bytes[0] as u16 + 1 + step.skip_len as u16;
        let c0 = (sum0 >> 8) as u8;
        let sum1 = pc_bytes[1] as u16 + c0 as u16;
        let c1 = (sum1 >> 8) as u8;
        let sum2 = pc_bytes[2] as u16 + c1 as u16;
        let c2 = (sum2 >> 8) as u8;
        trace.fill_columns_bytes(row, &[c0, c1, c2], Column::PcCarry);
    }
    trace.fill_columns(row, step.reg_a as u8, Column::RegA);
    trace.fill_columns(row, step.reg_b as u8, Column::RegB);
    trace.fill_columns(row, step.reg_d as u8, Column::RegD);

    // Source operands.  Default convention (used by all but
    // the ImmAlt, SetGt and Cmov-immediate swaps):
    //   ThreeReg     → (regs[ra], regs[rb])
    //   TwoRegOneImm → (regs[rb], imm)
    //   TwoReg       → (0, regs[rb])
    //   OneRegImmOffset → (regs[ra], imm)  [imm-compare branches]
    //   Other immediate-source ops → (0, imm)
    //
    // The ImmAlt shifts and rotates swap the source convention —
    // the immediate is the shifted value, the register is the
    // shift amount.  In AIR terms: val_b ← imm, val_d ← regs[rb].
    let (mut val_b, mut val_d) = match step.opcode.category() {
        vos_pvm::instruction::InstructionCategory::ThreeReg => {
            (step.regs_before[step.reg_a], step.regs_before[step.reg_b])
        }
        vos_pvm::instruction::InstructionCategory::TwoRegOneImm if flags.is_imm_alt => {
            // ImmAlt swap.
            (step.imm, step.regs_before[step.reg_b])
        }
        vos_pvm::instruction::InstructionCategory::TwoRegOneImm if flags.is_set_gt => {
            // SetGt swap: val_b ← imm, val_d ← regs[rb], so the SetLt
            // comparison computes (imm < reg) = (reg > imm) = the GT result.
            (step.imm, step.regs_before[step.reg_b])
        }
        vos_pvm::instruction::InstructionCategory::TwoRegOneImm if flags.is_cmov_imm => {
            // CmovIzImm/CmovNzImm swap: val_b ← imm (the moved value, so
            // the cmov result constraint `result = val_b` binds it),
            // val_d ← regs[rb] (the condition ValDIsZero gates).
            (step.imm, step.regs_before[step.reg_b])
        }
        vos_pvm::instruction::InstructionCategory::TwoRegOneImm => {
            (step.regs_before[step.reg_b], step.imm)
        }
        vos_pvm::instruction::InstructionCategory::TwoReg => (0, step.regs_before[step.reg_b]),
        vos_pvm::instruction::InstructionCategory::OneRegImmOffset => {
            // BranchEqImm/NeImm/LtImm/etc: compare regs[ra] vs imm
            (step.regs_before[step.reg_a], step.imm)
        }
        _ if uses_immediate(step.opcode) => (0, step.imm),
        _ => (step.regs_before[step.reg_a], step.regs_before[step.reg_b]),
    };

    // For left/right shifts and rotates: save shift amount, then
    // replace val_d with 2^shift_amount.
    //
    // RotR64 / RotR32 are also pow2-replacements, but with
    // val_d = 2^((modulus − n_real) mod modulus) (the complement)
    // so the mul-schoolbook's low+high yields the rotated-right
    // value.  modulus = 32 for 32-bit, 64 for 64-bit.
    let mut saved_shift_amount: u8 = 0;
    let mut saved_shift_amount_compl: u8 = 0;
    let mut saved_shift_quotient_compl: u64 = 0;
    let is_pow2_replacement = (flags.is_shift && flags.shift_op <= 2)
        || flags.is_rotate_l64
        || flags.is_rotate_r64
        || flags.is_rotate_l32
        || flags.is_rotate_r32;
    if is_pow2_replacement {
        let modulus = if flags.is_32bit { 32u64 } else { 64 };
        let shift = val_d % modulus; // n_real = reg_val_d mod modulus
        saved_shift_amount = shift as u8;
        let is_rotate_r = flags.is_rotate_r64 || flags.is_rotate_r32;
        if is_rotate_r {
            // val_d = 2^((modulus − n_real) mod modulus).
            let compl = if shift == 0 { 0 } else { modulus - shift };
            saved_shift_amount_compl = compl as u8;
            // RegValD[0] + compl = 32·k, k's bits in ShiftQuotientCompl.
            saved_shift_quotient_compl = ((val_d & 0xff) + compl) / 32;
            val_d = 1u64 << compl;
            side_note.power_of_two_counts[compl as usize] += 1;
        } else {
            val_d = 1u64 << shift;
            side_note.power_of_two_counts[shift as usize] += 1;
        }
    }

    // Truncate for 32-bit ALU ops (including divrem for right shifts)
    if flags.is_32bit && (flags.is_add || flags.is_sub || flags.is_mul || flags.is_div_rem) {
        val_b &= 0xFFFF_FFFF;
        val_d &= 0xFFFF_FFFF;
    }

    trace.fill_columns(row, val_b, Column::ValB);
    trace.fill_columns(row, val_d, Column::ValD);

    // A witness-input call's result is the count it writes to φ7.
    let is_witness = step.served_ecall() == Some(u64::from(ECALL_WITNESS_INPUT));
    let dr = if is_witness { 7 } else { dest_reg(step) };
    let result = step.regs_after[dr];
    trace.fill_columns(row, result, Column::Result);

    let val_b_bytes = val_b.to_le_bytes();
    let val_d_bytes = val_d.to_le_bytes();
    let result_bytes = result.to_le_bytes();
    Operands {
        val_b,
        val_d,
        result,
        val_b_bytes,
        val_d_bytes,
        result_bytes,
        is_witness,
        saved_shift_amount,
        saved_shift_amount_compl,
        saved_shift_quotient_compl,
    }
}

/// The instruction's flags and the selectors that are their products.
pub(super) fn flag_columns(out: &mut Sinks, s: Step) {
    let Sinks { trace, .. } = out;
    let Step { row, flags, .. } = s;
    // ── Flags ──
    trace.fill_columns(row, false, Column::IsPadding);
    trace.fill_columns(row, flags.is_add, Column::IsAdd);
    trace.fill_columns(row, flags.is_sub, Column::IsSub);
    trace.fill_columns(row, flags.is_mul, Column::IsMul);

    // Selector helpers (filled inline next to the flags they're
    // derived from).
    let is_64bit_b = !flags.is_32bit;
    trace.fill_columns(row, flags.is_add && is_64bit_b, Column::IsAdd64bitH);
    trace.fill_columns(row, flags.is_add && flags.is_32bit, Column::IsAdd32bitH);
    trace.fill_columns(
        row,
        flags.is_sub && !flags.is_neg_add,
        Column::IsSubNotNegaddH,
    );
    trace.fill_columns(row, flags.is_sub && flags.is_neg_add, Column::IsSubNegaddH);
    trace.fill_columns(
        row,
        flags.is_sub && !flags.is_neg_add && is_64bit_b,
        Column::IsSub64NotNegaddH,
    );
    trace.fill_columns(
        row,
        flags.is_sub && flags.is_neg_add && is_64bit_b,
        Column::IsSub64NegaddH,
    );
    trace.fill_columns(row, flags.is_sub && flags.is_32bit, Column::IsSub32bitH);
    trace.fill_columns(row, flags.is_mul && flags.is_32bit, Column::IsMul32bitH);
    // The helpers that also read the operands, the comparison or the
    // division are `helpers`'.
    // IsMulUpper is the (mu_uu+mu_su+mu_ss) sum — no column to fill.
    trace.fill_columns(row, flags.is_mul_upper_uu, Column::IsMulUpperUU);
    trace.fill_columns(row, flags.is_mul_upper_su, Column::IsMulUpperSU);
    trace.fill_columns(row, flags.is_mul_upper_ss, Column::IsMulUpperSS);
    trace.fill_columns(row, flags.is_div_s, Column::IsDivS);
    trace.fill_columns(row, flags.is_shar_r, Column::IsSharR);
    // IsBitwise is folded — no column to fill.
    trace.fill_columns(row, flags.is_shift, Column::IsShift);
    // IsCompare is folded — no column to fill.
    trace.fill_columns(row, flags.is_move, Column::IsMove);
    trace.fill_columns(row, flags.is_32bit, Column::Is32Bit);
    trace.fill_columns(row, flags.is_and, Column::IsAnd);
    trace.fill_columns(row, flags.is_or, Column::IsOr);
    trace.fill_columns(row, flags.is_xor, Column::IsXor);
    trace.fill_columns(row, flags.is_and_inv, Column::IsAndInv);
    trace.fill_columns(row, flags.is_or_inv, Column::IsOrInv);
    trace.fill_columns(row, flags.is_xnor, Column::IsXnor);
    trace.fill_columns(row, flags.is_neg_add, Column::IsNegAdd);
    // IsBranch is folded into the 10 br_* sub-flag sum.
    trace.fill_columns(row, flags.is_br_eq, Column::IsBrEq);
    trace.fill_columns(row, flags.is_br_ne, Column::IsBrNe);
    trace.fill_columns(row, flags.is_br_lt_u, Column::IsBrLtU);
    trace.fill_columns(row, flags.is_br_ge_u, Column::IsBrGeU);
    trace.fill_columns(row, flags.is_br_le_u, Column::IsBrLeU);
    trace.fill_columns(row, flags.is_br_gt_u, Column::IsBrGtU);
    trace.fill_columns(row, flags.is_br_lt_s, Column::IsBrLtS);
    trace.fill_columns(row, flags.is_br_ge_s, Column::IsBrGeS);
    trace.fill_columns(row, flags.is_br_le_s, Column::IsBrLeS);
    trace.fill_columns(row, flags.is_br_gt_s, Column::IsBrGtS);
    trace.fill_columns(row, flags.is_jump, Column::IsJump);

    trace.fill_columns(row, flags.is_div_rem, Column::IsDivRem);
    trace.fill_columns(row, flags.div_rem_op, Column::DivRemOp);
    trace.fill_columns(row, flags.is_reverse_bytes, Column::IsReverseBytes);
    trace.fill_columns(row, flags.is_zero_ext_16, Column::IsZeroExt16);
    trace.fill_columns(row, flags.is_sign_ext_8, Column::IsSignExt8);
    trace.fill_columns(row, flags.is_sign_ext_16, Column::IsSignExt16);
    trace.fill_columns(row, flags.is_trap, Column::IsTrap);
}

/// The register-memory descriptors: which operands are registers, and their
/// indices.
pub(super) fn register_accesses(out: &mut Sinks, s: Step, ops: &Operands) -> StepRegAccesses {
    let Sinks { trace, .. } = out;
    let Step { row, step, .. } = s;
    let Operands { is_witness, .. } = *ops;
    // ── Register-memory producer descriptors ──
    let accesses = step_reg_accesses(step);
    // The indices are the instruction's on every row, whether or not
    // the access is made.
    let shape = access_shape(step.opcode);
    trace.fill_columns(row, accesses.val_b_read.is_some(), Column::ValBIsReg);
    trace.fill_columns(row, shape.val_b_from_a, Column::ValBFromA);
    let val_b_reg = if shape.val_b_from_a {
        step.reg_a
    } else {
        step.reg_b
    };
    trace.fill_columns(row, val_b_reg as u8, Column::ValBRegIdx);
    trace.fill_columns(row, accesses.val_d_read.is_some(), Column::ValDIsReg);
    trace.fill_columns(row, step.reg_b as u8, Column::ValDRegIdx);
    trace.fill_columns(row, accesses.result_write.is_some(), Column::ResultIsReg);
    trace.fill_columns(row, shape.result_to_d, Column::ResultToD);
    let result_reg = if is_witness {
        7
    } else if shape.result_to_d {
        step.reg_d
    } else {
        step.reg_a
    };
    trace.fill_columns(row, result_reg as u8, Column::ResultRegIdx);
    accesses
}

/// The registers' values behind ValB and ValD, and the shift amount's quotient.
pub(super) fn register_values(
    out: &mut Sinks,
    s: Step,
    shift: &Shift,
    accesses: &StepRegAccesses,
) -> u8 {
    let Sinks { trace, .. } = out;
    let Step { row, step, flags } = s;
    let Shift {
        shift_amount,
        is_shift_constrained,
    } = *shift;
    // Raw register value behind ValB + IsTruncated flag.
    let reg_val_b_u64 = accesses.val_b_read.map(|(_, v)| v).unwrap_or(0);
    trace.fill_columns(row, reg_val_b_u64, Column::RegValB);
    let is_truncated: u8 =
        if flags.is_32bit && (flags.is_add || flags.is_sub || flags.is_mul || flags.is_div_rem) {
            1
        } else {
            0
        };
    trace.fill_columns(row, is_truncated, Column::IsTruncated);

    // ValD's source, its register or the immediate, and the shift
    // amount's quotient: RegValD[0] = ShiftAmount + 32·k.
    let reg_val_d_u64 = accesses.val_d_read.map_or(step.imm, |(_, v)| v);
    trace.fill_columns(row, reg_val_d_u64, Column::RegValD);
    let shift_q = if is_shift_constrained {
        ((reg_val_d_u64 & 0xff) - u64::from(shift_amount)) / 32
    } else {
        0
    };
    trace.fill_columns_bytes(row, &bits::<3>(shift_q), Column::ShiftQuotient);
    is_truncated
}

/// The row's Range256 values: the result, the next timestamp and a
/// comparison's subtraction.
pub(super) fn range_checks(out: &mut Sinks, s: Step, ops: &Operands, cmp: &Compare) {
    let Sinks { range_bytes, .. } = out;
    let Step { step, flags, .. } = s;
    let Operands { result_bytes, .. } = *ops;
    let Compare { cmp_sub_result, .. } = *cmp;
    for &b in &result_bytes {
        range_bytes.push(b);
    }
    // The next timestamp's limbs, bytes.
    range_bytes.extend_from_slice(&(step.timestamp + 1).to_le_bytes());
    // Range-check cmp_sub_result bytes for carry chain soundness
    if flags.is_compare || flags.is_branch {
        for &b in &cmp_sub_result {
            range_bytes.push(b);
        }
    }
}

/// The instruction's flags packed into bytes.
pub(super) fn flag_bytes(out: &mut Sinks, s: Step) {
    let Sinks {
        trace, side_note, ..
    } = out;
    let Step { row, step, .. } = s;
    // ── Pack the 48 individual flags into 6 bytes ──
    // The packing matches `program_memory::pack_flags` and the
    // canonical 48-flag layout in `classify_opcode_for_program_memory`.
    // Per-row byte-to-bits lookups (`constraints::program::flag_bits`) bind individual
    // flag columns / sum-of-sub-flags expressions to these bytes.
    // ProgramMemoryChip's preprocessed FlagByte0..5 columns hold
    // the canonical packing for each PC; the prog_mem lookup
    // balance pins each FlagByteI on CpuChip to canonical.
    let canonical_flags =
        crate::chips::cpu::classify::classify_opcode_for_program_memory(step.opcode);
    let flag_bytes = crate::chips::program_memory::pack_flags(&canonical_flags);
    trace.fill_columns(row, flag_bytes[0], Column::FlagByte0);
    trace.fill_columns(row, flag_bytes[1], Column::FlagByte1);
    trace.fill_columns(row, flag_bytes[2], Column::FlagByte2);
    trace.fill_columns(row, flag_bytes[3], Column::FlagByte3);
    trace.fill_columns(row, flag_bytes[4], Column::FlagByte4);
    trace.fill_columns(row, flag_bytes[5], Column::FlagByte5);
    trace.fill_columns(row, flag_bytes[6], Column::FlagByte6);
    trace.fill_columns(row, flag_bytes[7], Column::FlagByte7);
    trace.fill_columns(row, flag_bytes[8], Column::FlagByte8);
    trace.fill_columns(row, flag_bytes[9], Column::FlagByte9);
    // 6 byte-to-bits emissions per real row, one per byte 0..5.
    for &fb in &flag_bytes[..6] {
        side_note.byte_to_bits_counts[fb as usize] += 1;
    }
}
