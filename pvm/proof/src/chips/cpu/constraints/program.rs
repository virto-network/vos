//! The instruction's binding to program memory, and the flag bytes' bits.
use alloc::{vec, vec::Vec};

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use super::{Lookups, Row, is_branch, is_compare, is_store};
use crate::chips::cpu::columns::Column;

/// The program-memory consumer: the instruction tuple of each step.
pub(in crate::chips::cpu) fn program_memory<E: EvalAtRow>(
    eval: &mut E,
    row: &Row<E::F>,
    lookups: &Lookups<'_>,
) {
    let prog_mem_lookup = lookups.prog_mem_lookup;
    let is_real = E::F::one() - row.is_padding[0].clone();
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
        let mut tuple: Vec<E::F> = row.pc.to_vec();
        tuple.push(row.opcode[0].clone());
        tuple.push(row.skip_len[0].clone());
        tuple.push(row.reg_a[0].clone());
        tuple.push(row.reg_b[0].clone());
        tuple.push(row.reg_d[0].clone());
        tuple.extend_from_slice(&row.imm_bytes);
        tuple.push(row.flag_byte0[0].clone());
        tuple.push(row.flag_byte1[0].clone());
        tuple.push(row.flag_byte2[0].clone());
        tuple.push(row.flag_byte3[0].clone());
        tuple.push(row.flag_byte4[0].clone());
        tuple.push(row.flag_byte5[0].clone());
        for byte in [
            Column::FlagByte6,
            Column::FlagByte7,
            Column::FlagByte8,
            Column::FlagByte9,
        ] {
            tuple.push(row.column(byte)[0].clone());
        }
        // Bind ImmYBytes to canonical imm_y (low 4 bytes) for
        // LoadImmJumpInd; 0 for ops without a second immediate.  Tracer
        // writes 0 to imm_y for those, so balanced.
        tuple.extend_from_slice(&row.imm_y_bytes);
        // Bind BranchTarget to its canonical (pc + sign_extend(offset))
        // for static jumps/branches.  For JumpInd/LoadImmJumpInd and
        // non-branch ops, the canonical is 0; the tracer also writes 0
        // to BranchTarget for those (see decode_branch_target's default
        // arm), so the lookup balances without gating.
        tuple.extend_from_slice(&row.branch_target);
        tuple.push(row.host_call_precompile_dispatch[0].clone());

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
    row: &Row<E::F>,
    lookups: &Lookups<'_>,
) {
    let byte_to_bits_lookup = lookups.byte_to_bits_lookup;
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
        // Read the individual-flag bit expressions for each byte.

        // Sum expressions for the 4 folded category slots.
        let bw_sum_e = row.is_and[0].clone()
            + row.is_or[0].clone()
            + row.is_xor[0].clone()
            + row.is_and_inv[0].clone()
            + row.is_or_inv[0].clone()
            + row.is_xnor[0].clone();
        let cmp_sum_e = is_compare(row);
        let br_sum_e = is_branch(row);
        let st_sum_e = is_store(row);

        // byte 0: (FlagByte0, is_add, is_sub, is_mul, is_shar_r, BW_SUM,
        //          is_shift, CMP_SUM, is_move)
        let tuple0: Vec<E::F> = vec![
            row.flag_byte0[0].clone(),
            row.is_add[0].clone(),
            row.is_sub[0].clone(),
            row.is_mul[0].clone(),
            row.is_shar_r[0].clone(),
            bw_sum_e.clone(),
            row.is_shift[0].clone(),
            cmp_sum_e.clone(),
            row.is_move[0].clone(),
        ];
        // byte 1: (FlagByte1, is_32bit, BR_SUM, is_jump, is_div_rem,
        //          is_load, ST_SUM, is_exit, is_neg_add)
        let tuple1: Vec<E::F> = vec![
            row.flag_byte1[0].clone(),
            row.is32_bit[0].clone(),
            br_sum_e.clone(),
            row.is_jump[0].clone(),
            row.is_div_rem[0].clone(),
            row.is_load[0].clone(),
            st_sum_e.clone(),
            row.is_exit[0].clone(),
            row.is_neg_add[0].clone(),
        ];
        // byte 2: (FlagByte2, is_reverse_bytes, is_zero_ext_16,
        //          is_sign_ext_8, is_sign_ext_16, is_trap, is_jump_ind,
        //          is_load_imm_jump_ind, is_mul_upper_uu)
        let tuple2: Vec<E::F> = vec![
            row.flag_byte2[0].clone(),
            row.is_reverse_bytes[0].clone(),
            row.is_zero_ext16[0].clone(),
            row.is_sign_ext8[0].clone(),
            row.is_sign_ext16[0].clone(),
            row.is_trap[0].clone(),
            row.is_jump_ind[0].clone(),
            row.is_load_imm_jump_ind[0].clone(),
            row.is_mul_upper_uu[0].clone(),
        ];
        // byte 3: (FlagByte3, is_mul_upper_su, is_mul_upper_ss, is_div_s,
        //          is_load_i8, is_load_i16, is_load_i32,
        //          is_mem_size_1, is_mem_size_2)
        let tuple3: Vec<E::F> = vec![
            row.flag_byte3[0].clone(),
            row.is_mul_upper_su[0].clone(),
            row.is_mul_upper_ss[0].clone(),
            row.is_div_s[0].clone(),
            row.is_load_i8[0].clone(),
            row.is_load_i16[0].clone(),
            row.is_load_i32[0].clone(),
            row.is_mem_size1[0].clone(),
            row.is_mem_size2[0].clone(),
        ];
        // byte 4: (FlagByte4, is_mem_size_4, is_mem_size_8,
        //          is_store_direct, is_load_direct, is_mem_indirect,
        //          is_store_imm_any, is_store_imm_direct, is_store_ind)
        let tuple4: Vec<E::F> = vec![
            row.flag_byte4[0].clone(),
            row.is_mem_size4[0].clone(),
            row.is_mem_size8[0].clone(),
            row.is_store_direct[0].clone(),
            row.is_load_direct[0].clone(),
            row.is_mem_indirect[0].clone(),
            row.is_store_imm_any[0].clone(),
            row.is_store_imm_direct[0].clone(),
            row.is_store_ind[0].clone(),
        ];
        // byte 5: (FlagByte5, is_rotate_l64, is_count_set_bits,
        //          is_lzb, is_tzb, is_rotate_r64, is_rotate_l32,
        //          is_rotate_r32, is_imm_alt)
        let tuple5: Vec<E::F> = vec![
            row.flag_byte5[0].clone(),
            row.is_rotate_l64[0].clone(),
            row.is_count_set_bits[0].clone(),
            row.is_lzb[0].clone(),
            row.is_tzb[0].clone(),
            row.is_rotate_r64[0].clone(),
            row.is_rotate_l32[0].clone(),
            row.is_rotate_r32[0].clone(),
            row.is_imm_alt[0].clone(),
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
        let col = |column: Column| row.column(column)[0].clone();
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
