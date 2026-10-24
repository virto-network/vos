//! The instruction's binding to program memory, and the flag bytes' bits.
use alloc::vec::Vec;

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use super::{Lookups, Row, sum, values};
use crate::chips::cpu::columns::Column;
use crate::chips::cpu::tuples::{FLAG_BYTES, PROGRAM_MEMORY};

/// The program-memory consumer: the instruction tuple of each step.
pub(in crate::chips::cpu) fn program_memory<E: EvalAtRow>(
    eval: &mut E,
    row: &Row<E::F>,
    lookups: &Lookups,
) {
    let prog_mem_lookup = &lookups.prog_mem_lookup;
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
        let tuple = values(row, &PROGRAM_MEMORY);

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
    lookups: &Lookups,
) {
    let byte_to_bits_lookup = &lookups.byte_to_bits_lookup;
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
        let tuples = FLAG_BYTES.map(|(byte, bits)| {
            let mut tuple = Vec::with_capacity(9);
            tuple.push(row.column(byte)[0].clone());
            tuple.extend(bits.map(|flags| sum(row, flags)));
            tuple
        });
        for tuple in &tuples {
            eval.add_to_relation(RelationEntry::new(byte_to_bits_lookup, E::EF::one(), tuple));
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
