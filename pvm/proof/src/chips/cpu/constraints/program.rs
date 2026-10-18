//! The instruction's binding to program memory, and the flag bytes' bits.
use alloc::{vec, vec::Vec};

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use super::{Lookups, Trace, is_branch, is_compare, is_store};
use crate::chips::cpu::columns::Column;

/// The program-memory consumer: the instruction tuple of each step.
pub(in crate::chips::cpu) fn program_memory<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
    lookups: &Lookups<'_>,
) {
    let prog_mem_lookup = lookups.prog_mem_lookup;
    let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
    let is_real = E::F::one() - is_pad[0].clone();
    // ════════════════════════════════════════════════════════════════════
    // Program-memory consumer (pc + opcode + regs + imm
    //                          + 10 packed flag bytes
    //                          + imm_y + branch_target)
    //
    // Per real CpuChip step, demand the full instruction tuple from
    // ProgramMemoryChip's preprocessed table.  The tuple binds
    // (pc, opcode, skip_len, regs, imm) plus the 80 flags so a prover
    // can't clear or swap flags to skip or change per-op constraints.
    // The flag bits are packed into 10 bytes on both sides; 6
    // byte-to-bits lookups (next block) bind individual flag columns /
    // sum-of-sub-flags expressions to the matching bit slot in bytes
    // 0..5, and CpuChip's own constraints recompose bytes 6..9.
    //
    // Pair-parity (CONSTRAINTS.md rule 1): two paired emissions with
    // identical multiplicity and tuple.  ProgramMemoryChip doubles its
    // multiplicity column.
    {
        let pc = crate::trace::trace_eval!(trace_eval, Column::Pc);
        let opcode = crate::trace::trace_eval!(trace_eval, Column::Opcode);
        let skip_len = crate::trace::trace_eval!(trace_eval, Column::SkipLen);
        let reg_a = crate::trace::trace_eval!(trace_eval, Column::RegA);
        let reg_b = crate::trace::trace_eval!(trace_eval, Column::RegB);
        let reg_d = crate::trace::trace_eval!(trace_eval, Column::RegD);
        let imm = crate::trace::trace_eval!(trace_eval, Column::ImmBytes);
        let fb0 = crate::trace::trace_eval!(trace_eval, Column::FlagByte0);
        let fb1 = crate::trace::trace_eval!(trace_eval, Column::FlagByte1);
        let fb2 = crate::trace::trace_eval!(trace_eval, Column::FlagByte2);
        let fb3 = crate::trace::trace_eval!(trace_eval, Column::FlagByte3);
        let fb4 = crate::trace::trace_eval!(trace_eval, Column::FlagByte4);
        let fb5 = crate::trace::trace_eval!(trace_eval, Column::FlagByte5);
        let imm_y_for_lookup = crate::trace::trace_eval!(trace_eval, Column::ImmYBytes);
        let branch_target_for_lookup = crate::trace::trace_eval!(trace_eval, Column::BranchTarget);
        let host_call_precompile_dispatch =
            crate::trace::trace_eval!(trace_eval, Column::HostCallPrecompileDispatch);

        let mut tuple: Vec<E::F> = pc.to_vec();
        tuple.push(opcode[0].clone());
        tuple.push(skip_len[0].clone());
        tuple.push(reg_a[0].clone());
        tuple.push(reg_b[0].clone());
        tuple.push(reg_d[0].clone());
        tuple.extend_from_slice(&imm);
        tuple.push(fb0[0].clone());
        tuple.push(fb1[0].clone());
        tuple.push(fb2[0].clone());
        tuple.push(fb3[0].clone());
        tuple.push(fb4[0].clone());
        tuple.push(fb5[0].clone());
        for byte in [
            Column::FlagByte6,
            Column::FlagByte7,
            Column::FlagByte8,
            Column::FlagByte9,
        ] {
            tuple.push(trace_eval.column_eval::<1>(byte)[0].clone());
        }
        // Bind ImmYBytes to canonical imm_y (low 4 bytes) for
        // LoadImmJumpInd; 0 for ops without a second immediate.  Tracer
        // writes 0 to imm_y for those, so balanced.
        tuple.extend_from_slice(&imm_y_for_lookup);
        // Bind BranchTarget to its canonical (pc + sign_extend(offset))
        // for static jumps/branches.  For JumpInd/LoadImmJumpInd and
        // non-branch ops, the canonical is 0; the tracer also writes 0
        // to BranchTarget for those (see decode_branch_target's default
        // arm), so the lookup balances without gating.
        tuple.extend_from_slice(&branch_target_for_lookup);
        tuple.push(host_call_precompile_dispatch[0].clone());

        // Paired emissions; ProgramMemoryChip's mult = 2·count_at_pc.
        eval.add_to_relation(RelationEntry::new(
            prog_mem_lookup,
            is_real.clone().into(),
            &tuple,
        ));
        eval.add_to_relation(RelationEntry::new(
            prog_mem_lookup,
            is_real.clone().into(),
            &tuple,
        ));
    }
}

/// The byte-to-bits decomposition of the flag bytes.
pub(in crate::chips::cpu) fn flag_bits<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
    lookups: &Lookups<'_>,
) {
    let byte_to_bits_lookup = lookups.byte_to_bits_lookup;
    let is_add = crate::trace::trace_eval!(trace_eval, Column::IsAdd);
    let is_sub = crate::trace::trace_eval!(trace_eval, Column::IsSub);
    let is_mul = crate::trace::trace_eval!(trace_eval, Column::IsMul);
    let is_shift = crate::trace::trace_eval!(trace_eval, Column::IsShift);
    let is_move = crate::trace::trace_eval!(trace_eval, Column::IsMove);
    let is_neg_add = crate::trace::trace_eval!(trace_eval, Column::IsNegAdd);
    let is_32bit = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
    let is_and_flag = crate::trace::trace_eval!(trace_eval, Column::IsAnd);
    let is_or_flag = crate::trace::trace_eval!(trace_eval, Column::IsOr);
    let is_xor_flag = crate::trace::trace_eval!(trace_eval, Column::IsXor);
    let is_and_inv_flag = crate::trace::trace_eval!(trace_eval, Column::IsAndInv);
    let is_or_inv_flag = crate::trace::trace_eval!(trace_eval, Column::IsOrInv);
    let is_xnor_flag = crate::trace::trace_eval!(trace_eval, Column::IsXnor);
    let is_store_direct_e = crate::trace::trace_eval!(trace_eval, Column::IsStoreDirect);
    let is_store_imm_any_e = crate::trace::trace_eval!(trace_eval, Column::IsStoreImmAny);
    let is_store_ind_e = crate::trace::trace_eval!(trace_eval, Column::IsStoreInd);
    // ════════════════════════════════════════════════════════════════════
    // Byte-to-bits decomposition lookups
    //
    // Per real CpuChip step, emit 6 lookups against ByteToBitsChip's
    // 256-row table.  Each tuple is `(FlagByteI, bit0, bit1, ..., bit7)`
    // where bit_j is either an individual flag column or a sum-of-
    // sub-flags expression for the 4 folded category slots
    // (is_bitwise / is_compare / is_branch / is_store).
    // Composed with the prog_mem balance (which pins each FlagByteI to
    // canonical), this constrains every individual flag column /
    // sum expression to its canonical value at every real step.
    //
    // 6 emissions per row keep `finalize_logup_in_pairs`'s parity
    // even.  Multiplicity 1 on every row, padding included, so a padding
    // row's zero flag bytes pin its flags.
    //
    // Bit layout per byte (matches `pack_flags` in
    // chips/program_memory.rs and the canonical 48-flag layout in
    // `classify_opcode_for_program_memory`).
    {
        let fb0 = crate::trace::trace_eval!(trace_eval, Column::FlagByte0);
        let fb1 = crate::trace::trace_eval!(trace_eval, Column::FlagByte1);
        let fb2 = crate::trace::trace_eval!(trace_eval, Column::FlagByte2);
        let fb3 = crate::trace::trace_eval!(trace_eval, Column::FlagByte3);
        let fb4 = crate::trace::trace_eval!(trace_eval, Column::FlagByte4);
        let fb5 = crate::trace::trace_eval!(trace_eval, Column::FlagByte5);
        // Read the individual-flag bit expressions for each byte.
        let f_is_jump_p55 = crate::trace::trace_eval!(trace_eval, Column::IsJump);
        let f_is_div_rem_p55 = crate::trace::trace_eval!(trace_eval, Column::IsDivRem);
        let f_is_load_p55 = crate::trace::trace_eval!(trace_eval, Column::IsLoad);
        let f_is_exit_p55 = crate::trace::trace_eval!(trace_eval, Column::IsExit);
        let f_is_reverse_bytes_p55 = crate::trace::trace_eval!(trace_eval, Column::IsReverseBytes);
        let f_is_zero_ext_16_p55 = crate::trace::trace_eval!(trace_eval, Column::IsZeroExt16);
        let f_is_sign_ext_8_p55 = crate::trace::trace_eval!(trace_eval, Column::IsSignExt8);
        let f_is_sign_ext_16_p55 = crate::trace::trace_eval!(trace_eval, Column::IsSignExt16);
        let f_is_trap_p55 = crate::trace::trace_eval!(trace_eval, Column::IsTrap);
        let f_is_jump_ind_p55 = crate::trace::trace_eval!(trace_eval, Column::IsJumpInd);
        let f_is_load_imm_jump_ind_p55 =
            crate::trace::trace_eval!(trace_eval, Column::IsLoadImmJumpInd);
        let f_is_mul_upper_uu_p55 = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperUU);
        let f_is_mul_upper_su_p55 = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperSU);
        let f_is_mul_upper_ss_p55 = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperSS);
        let f_is_div_s_p55 = crate::trace::trace_eval!(trace_eval, Column::IsDivS);
        let f_is_load_i8_p55 = crate::trace::trace_eval!(trace_eval, Column::IsLoadI8);
        let f_is_load_i16_p55 = crate::trace::trace_eval!(trace_eval, Column::IsLoadI16);
        let f_is_load_i32_p55 = crate::trace::trace_eval!(trace_eval, Column::IsLoadI32);
        let f_is_mem_size_1_p55 = crate::trace::trace_eval!(trace_eval, Column::IsMemSize1);
        let f_is_mem_size_2_p55 = crate::trace::trace_eval!(trace_eval, Column::IsMemSize2);
        let f_is_mem_size_4_p55 = crate::trace::trace_eval!(trace_eval, Column::IsMemSize4);
        let f_is_mem_size_8_p55 = crate::trace::trace_eval!(trace_eval, Column::IsMemSize8);
        let f_is_load_direct_p55 = crate::trace::trace_eval!(trace_eval, Column::IsLoadDirect);
        let f_is_mem_indirect_p55 = crate::trace::trace_eval!(trace_eval, Column::IsMemIndirect);
        let f_is_store_imm_direct_p55 =
            crate::trace::trace_eval!(trace_eval, Column::IsStoreImmDirect);
        let f_is_rotate_l64_p55 = crate::trace::trace_eval!(trace_eval, Column::IsRotateL64);
        let f_is_count_set_bits_p55 = crate::trace::trace_eval!(trace_eval, Column::IsCountSetBits);
        let f_is_lzb_p55 = crate::trace::trace_eval!(trace_eval, Column::IsLzb);
        let f_is_tzb_p55 = crate::trace::trace_eval!(trace_eval, Column::IsTzb);
        let f_is_rotate_r64_p55 = crate::trace::trace_eval!(trace_eval, Column::IsRotateR64);
        let f_is_rotate_l32_p55 = crate::trace::trace_eval!(trace_eval, Column::IsRotateL32);
        let f_is_rotate_r32_p55 = crate::trace::trace_eval!(trace_eval, Column::IsRotateR32);
        let f_is_imm_alt_p55 = crate::trace::trace_eval!(trace_eval, Column::IsImmAlt);

        // Sum expressions for the 4 folded category slots.
        let bw_sum_e = is_and_flag[0].clone()
            + is_or_flag[0].clone()
            + is_xor_flag[0].clone()
            + is_and_inv_flag[0].clone()
            + is_or_inv_flag[0].clone()
            + is_xnor_flag[0].clone();
        let cmp_sum_e = is_compare(trace_eval);
        let br_sum_e = is_branch(trace_eval);
        let st_sum_e = is_store(trace_eval);

        // byte 0: (FlagByte0, is_add, is_sub, is_mul, is_shar_r, BW_SUM,
        //          is_shift, CMP_SUM, is_move)
        let tuple0: Vec<E::F> = vec![
            fb0[0].clone(),
            is_add[0].clone(),
            is_sub[0].clone(),
            is_mul[0].clone(),
            trace_eval.column_eval::<1>(Column::IsSharR)[0].clone(),
            bw_sum_e.clone(),
            is_shift[0].clone(),
            cmp_sum_e.clone(),
            is_move[0].clone(),
        ];
        // byte 1: (FlagByte1, is_32bit, BR_SUM, is_jump, is_div_rem,
        //          is_load, ST_SUM, is_exit, is_neg_add)
        let tuple1: Vec<E::F> = vec![
            fb1[0].clone(),
            is_32bit[0].clone(),
            br_sum_e.clone(),
            f_is_jump_p55[0].clone(),
            f_is_div_rem_p55[0].clone(),
            f_is_load_p55[0].clone(),
            st_sum_e.clone(),
            f_is_exit_p55[0].clone(),
            is_neg_add[0].clone(),
        ];
        // byte 2: (FlagByte2, is_reverse_bytes, is_zero_ext_16,
        //          is_sign_ext_8, is_sign_ext_16, is_trap, is_jump_ind,
        //          is_load_imm_jump_ind, is_mul_upper_uu)
        let tuple2: Vec<E::F> = vec![
            fb2[0].clone(),
            f_is_reverse_bytes_p55[0].clone(),
            f_is_zero_ext_16_p55[0].clone(),
            f_is_sign_ext_8_p55[0].clone(),
            f_is_sign_ext_16_p55[0].clone(),
            f_is_trap_p55[0].clone(),
            f_is_jump_ind_p55[0].clone(),
            f_is_load_imm_jump_ind_p55[0].clone(),
            f_is_mul_upper_uu_p55[0].clone(),
        ];
        // byte 3: (FlagByte3, is_mul_upper_su, is_mul_upper_ss, is_div_s,
        //          is_load_i8, is_load_i16, is_load_i32,
        //          is_mem_size_1, is_mem_size_2)
        let tuple3: Vec<E::F> = vec![
            fb3[0].clone(),
            f_is_mul_upper_su_p55[0].clone(),
            f_is_mul_upper_ss_p55[0].clone(),
            f_is_div_s_p55[0].clone(),
            f_is_load_i8_p55[0].clone(),
            f_is_load_i16_p55[0].clone(),
            f_is_load_i32_p55[0].clone(),
            f_is_mem_size_1_p55[0].clone(),
            f_is_mem_size_2_p55[0].clone(),
        ];
        // byte 4: (FlagByte4, is_mem_size_4, is_mem_size_8,
        //          is_store_direct, is_load_direct, is_mem_indirect,
        //          is_store_imm_any, is_store_imm_direct, is_store_ind)
        let tuple4: Vec<E::F> = vec![
            fb4[0].clone(),
            f_is_mem_size_4_p55[0].clone(),
            f_is_mem_size_8_p55[0].clone(),
            is_store_direct_e[0].clone(),
            f_is_load_direct_p55[0].clone(),
            f_is_mem_indirect_p55[0].clone(),
            is_store_imm_any_e[0].clone(),
            f_is_store_imm_direct_p55[0].clone(),
            is_store_ind_e[0].clone(),
        ];
        // byte 5: (FlagByte5, is_rotate_l64, is_count_set_bits,
        //          is_lzb, is_tzb, is_rotate_r64, is_rotate_l32,
        //          is_rotate_r32, is_imm_alt)
        let tuple5: Vec<E::F> = vec![
            fb5[0].clone(),
            f_is_rotate_l64_p55[0].clone(),
            f_is_count_set_bits_p55[0].clone(),
            f_is_lzb_p55[0].clone(),
            f_is_tzb_p55[0].clone(),
            f_is_rotate_r64_p55[0].clone(),
            f_is_rotate_l32_p55[0].clone(),
            f_is_rotate_r32_p55[0].clone(),
            f_is_imm_alt_p55[0].clone(),
        ];

        for t in [&tuple0, &tuple1, &tuple2, &tuple3, &tuple4, &tuple5] {
            eval.add_to_relation(RelationEntry::new(byte_to_bits_lookup, E::EF::one(), t));
        }

        // Flag bytes 6..9, recomposed here from their bits, each bit a
        // boolean column or expression: the register accesses (whose
        // result bit discounts a conditional move that does not move and
        // a witness-input call's count), the division's remainder bit
        // (DivRemOp = 2·is_rem + IsDivS), the operand swaps, and the
        // compare, branch and bitwise sub-operations.
        let col = |column: Column| trace_eval.column_eval::<1>(column)[0].clone();
        let result_bit = col(Column::ResultIsReg) + col(Column::IsCmovIz)
            - col(Column::IsCmovIzVdzH)
            + col(Column::IsCmovNz)
            - col(Column::IsCmovNzNotVdzH)
            - col(Column::IsWitnessEcall);
        let rem_bit = (col(Column::DivRemOp) - col(Column::IsDivS))
            * E::F::from(BaseField::from(2u32).inverse());
        let bytes: [(Column, [E::F; 8]); 4] = [
            (
                Column::FlagByte6,
                [
                    col(Column::ValBIsReg),
                    col(Column::ValBFromA),
                    col(Column::ValDIsReg),
                    result_bit,
                    col(Column::ResultToD),
                    rem_bit,
                    col(Column::IsSetGt),
                    col(Column::IsCmovImm),
                ],
            ),
            (
                Column::FlagByte7,
                [
                    Column::IsSetLtU,
                    Column::IsSetLtS,
                    Column::IsCmovIz,
                    Column::IsCmovNz,
                    Column::IsMinS,
                    Column::IsMinU,
                    Column::IsMaxS,
                    Column::IsMaxU,
                ]
                .map(col),
            ),
            (
                Column::FlagByte8,
                [
                    Column::IsBrEq,
                    Column::IsBrNe,
                    Column::IsBrLtU,
                    Column::IsBrGeU,
                    Column::IsBrLeU,
                    Column::IsBrGtU,
                    Column::IsBrLtS,
                    Column::IsBrGeS,
                ]
                .map(col),
            ),
            (
                Column::FlagByte9,
                [
                    Column::IsBrLeS,
                    Column::IsBrGtS,
                    Column::IsAnd,
                    Column::IsOr,
                    Column::IsXor,
                    Column::IsAndInv,
                    Column::IsOrInv,
                    Column::IsXnor,
                ]
                .map(col),
            ),
        ];
        for (byte, bits) in bytes {
            let mut packed = E::F::zero();
            for bit in bits.iter().rev() {
                eval.add_constraint(bit.clone() * (E::F::one() - bit.clone()));
                packed = packed.clone() + packed + bit.clone();
            }
            eval.add_constraint(col(byte) - packed);
        }
    }
}
