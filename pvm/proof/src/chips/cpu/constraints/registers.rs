//! Register-memory accesses and their helpers.
use alloc::{vec, vec::Vec};

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use super::{Lookups, Row};
use crate::core::step::WORD_SIZE;

/// The register-memory binding helpers.
pub(in crate::chips::cpu) fn register_helpers<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    let is_real = E::F::one() - row.is_padding[0].clone();
    // ── Register-memory binding helpers ──
    // The IsTruncated/ValBIsReg/ValDIsReg/ResultIsReg/Phi7Bool/
    // IsBlakeEcall boolean properties are enforced unconditionally
    // below.
    {
        // Boolean flags enforced unconditionally — a gated
        // `is_real · bool_h = 0` pattern would be redundant.
        for flag in [
            &row.is_truncated,
            &row.val_b_is_reg,
            &row.val_d_is_reg,
            &row.result_is_reg,
            &row.phi7_bool,
            &row.is_blake_ecall,
            &row.is_witness_ecall,
        ] {
            eval.add_constraint(flag[0].clone() * (E::F::one() - flag[0].clone()));
        }
        // Selector helpers (deg 2 def each).
        eval.add_constraint(row.real32bit_h[0].clone() - is_real.clone() * row.is32_bit[0].clone());
        eval.add_constraint(
            row.val_b_is_reg_h[0].clone() - is_real.clone() * row.val_b_is_reg[0].clone(),
        );
        eval.add_constraint(
            row.val_b_is_reg_not_trunc_h[0].clone()
                - row.val_b_is_reg_h[0].clone() * (E::F::one() - row.is_truncated[0].clone()),
        );
        eval.add_constraint(
            row.val_b_is_reg_trunc_h[0].clone()
                - row.val_b_is_reg_h[0].clone() * row.is_truncated[0].clone(),
        );
        // Every real row's ValD has a source, its register or the
        // immediate, so the ValD gates are the row's realness.
        eval.add_constraint(
            row.val_d_is_imm_h[0].clone()
                - is_real.clone() * (E::F::one() - row.val_d_is_reg[0].clone()),
        );
        eval.add_constraint(
            row.non_shift_gate_h[0].clone()
                - is_real.clone() * (E::F::one() - row.is_shift_constrained[0].clone()),
        );
        eval.add_constraint(
            row.non_shift_gate_not_trunc_h[0].clone()
                - row.non_shift_gate_h[0].clone() * (E::F::one() - row.is_truncated[0].clone()),
        );
        eval.add_constraint(
            row.non_shift_gate_trunc_h[0].clone()
                - row.non_shift_gate_h[0].clone() * row.is_truncated[0].clone(),
        );
        eval.add_constraint(
            row.real_shift_ch[0].clone() - is_real.clone() * row.is_shift_constrained[0].clone(),
        );
        eval.add_constraint(
            row.is_rotate_r_gate_h[0].clone()
                - is_real.clone() * (row.is_rotate_r64[0].clone() + row.is_rotate_r32[0].clone()),
        );
    }
    // Phi7-related helpers.
    {
        eval.add_constraint(
            row.real_not_phi7_bool_h[0].clone()
                - is_real.clone() * (E::F::one() - row.phi7_bool[0].clone()),
        );
        eval.add_constraint(
            row.real_phi7_bool_h[0].clone() - is_real.clone() * row.phi7_bool[0].clone(),
        );
        // Its bytes' sum, at most 2040, is zero exactly when the
        // register is: φ10 non-zero but ≡ 0 mod p, as a base-256
        // combination would see it, is non-zero here.
        let phi7_sum = row
            .phi7
            .iter()
            .fold(E::F::zero(), |sum, byte| sum + byte.clone());
        eval.add_constraint(row.phi7_times_inv_h[0].clone() - phi7_sum * row.phi7_inv[0].clone());
    }
}

/// The register-memory producers, in the interaction trace's order.
pub(in crate::chips::cpu) fn register_accesses<E: EvalAtRow>(
    eval: &mut E,
    row: &Row<E::F>,
    lookups: &Lookups<'_>,
) {
    let reg_lookup = lookups.reg_lookup;
    let is_real = E::F::one() - row.is_padding[0].clone();
    // Register-memory producers: mirror of the interaction trace
    // emissions in the same order (ValB read → ValD read → Result
    // write) so finalize_logup_in_pairs pairs correctly.
    {
        // RegValB carries the full u64 register value; ValB may be
        // truncated (for 32-bit ALU ops).  Producer uses RegValB.
        let mut tuple: Vec<E::F> = vec![row.val_b_reg_idx[0].clone()];
        for b in &row.reg_val_b {
            tuple.push(b.clone());
        }
        for ts in &row.timestamp {
            tuple.push(ts.clone());
        }
        tuple.push(E::F::from(BaseField::from(0u32))); // is_write = 0 (read)
        eval.add_to_relation(RelationEntry::new(
            reg_lookup,
            row.val_b_is_reg[0].clone().into(),
            &tuple,
        ));

        // RegValD (raw reg_b value) drives the ledger, not ValD
        // (which gets rewritten to 2^shift_amount for shift ops).
        let mut tuple: Vec<E::F> = vec![row.val_d_reg_idx[0].clone()];
        for b in &row.reg_val_d {
            tuple.push(b.clone());
        }
        for ts in &row.timestamp {
            tuple.push(ts.clone());
        }
        tuple.push(E::F::from(BaseField::from(0u32))); // is_write = 0 (read)
        eval.add_to_relation(RelationEntry::new(
            reg_lookup,
            row.val_d_is_reg[0].clone().into(),
            &tuple,
        ));

        // RegValA producer for StoreInd source value.  Emitted as a
        // paired duplicate (mirrors the prog_mem pattern) so pair-parity
        // stays even; RegisterMemoryChip pushes the val_a_read entry
        // twice to match.  Tuple uses RegA directly as the index (reg_a
        // is a column on every row, decoded from the opcode by the
        // ProgramMemory binding).
        let mut tuple_a: Vec<E::F> = vec![row.reg_a[0].clone()];
        for b in &row.reg_val_a {
            tuple_a.push(b.clone());
        }
        for ts in &row.timestamp {
            tuple_a.push(ts.clone());
        }
        tuple_a.push(E::F::from(BaseField::from(0u32))); // is_write = 0 (read)
        eval.add_to_relation(RelationEntry::new(
            reg_lookup,
            row.is_store_ind[0].clone().into(),
            &tuple_a,
        ));
        eval.add_to_relation(RelationEntry::new(
            reg_lookup,
            row.is_store_ind[0].clone().into(),
            &tuple_a,
        ));

        // IsTruncated identity binding; its boolean property is
        // `register_helpers`'.
        // is_truncated = is_32bit · (is_add+is_sub+is_mul+is_div_rem).
        // is_real · is_32bit lifted into Real32bitH so the constraint
        // factors as is_real·is_truncated - Real32bitH·trunc_sum.
        let trunc_sum = row.is_add[0].clone()
            + row.is_sub[0].clone()
            + row.is_mul[0].clone()
            + row.is_div_rem[0].clone();
        eval.add_constraint(
            is_real.clone() * row.is_truncated[0].clone() - row.real32bit_h[0].clone() * trunc_sum,
        );

        // ValB byte-wise cross-constraint.
        for i in 0..4 {
            eval.add_constraint(
                row.val_b_is_reg_h[0].clone() * (row.val_b[i].clone() - row.reg_val_b[i].clone()),
            );
        }
        for i in 4..WORD_SIZE {
            eval.add_constraint(
                row.val_b_is_reg_not_trunc_h[0].clone()
                    * (row.val_b[i].clone() - row.reg_val_b[i].clone()),
            );
            eval.add_constraint(row.val_b_is_reg_trunc_h[0].clone() * row.val_b[i].clone());
        }

        // ValD byte-wise cross-constraint.
        // Skip shift rows (handled by the ShiftQuotient identity below).
        for i in 0..4 {
            eval.add_constraint(
                row.non_shift_gate_h[0].clone() * (row.val_d[i].clone() - row.reg_val_d[i].clone()),
            );
        }
        for i in 4..WORD_SIZE {
            eval.add_constraint(
                row.non_shift_gate_not_trunc_h[0].clone()
                    * (row.val_d[i].clone() - row.reg_val_d[i].clone()),
            );
            eval.add_constraint(row.non_shift_gate_trunc_h[0].clone() * row.val_d[i].clone());
        }

        // An immediate operand is the instruction's: RegValD, which the
        // cross-constraints above tie to ValD, is ImmBytes whenever ValD
        // reads no register.
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                row.val_d_is_imm_h[0].clone()
                    * (row.reg_val_d[i].clone() - row.imm_bytes[i].clone()),
            );
        }

        // Shift-amount identity, on the low byte alone (a modulus of 32
        // or 64 divides 256): RegValD[0] = ShiftAmount + 32·k with k's
        // three bits, k even on a 64-bit shift. Every term is below 2^10,
        // so it holds over the integers: ShiftAmount, in [0, 63] by the
        // PowerOfTwo lookup and in [0, 31] on a 32-bit shift by ValD's
        // zero high bytes, is RegValD's residue.
        let thirty_two = E::F::from(BaseField::from(32u32));
        let bits_value = |bits: &[E::F]| -> E::F {
            bits.iter()
                .rev()
                .fold(E::F::zero(), |acc, bit| acc.clone() + acc + bit.clone())
        };
        for bit in row.shift_quotient.iter() {
            eval.add_constraint(bit.clone() * (E::F::one() - bit.clone()));
        }
        eval.add_constraint(
            (E::F::one() - row.is32_bit[0].clone()) * row.shift_quotient[0].clone(),
        );
        eval.add_constraint(
            row.real_shift_ch[0].clone()
                * (row.reg_val_d[0].clone()
                    - row.shift_amount[0].clone()
                    - thirty_two.clone() * bits_value(&row.shift_quotient)),
        );

        // Complementary identity on RotR64 / RotR32 rows:
        //   RegValD[0] + ShiftAmountCompl = 32·k, k's four bits, k even
        // on a 64-bit rotate. Combined with the ShiftAmountCompl ∈
        // [0, 31 or 0, 63] bound (pow2 table size + the
        // val_d-high-bytes-zero constraint for 32-bit), this uniquely
        // determines ShiftAmountCompl = (modulus − n_real) mod modulus.
        for bit in row.shift_quotient_compl.iter() {
            eval.add_constraint(bit.clone() * (E::F::one() - bit.clone()));
        }
        eval.add_constraint(
            (E::F::one() - row.is32_bit[0].clone()) * row.shift_quotient_compl[0].clone(),
        );
        eval.add_constraint(
            row.is_rotate_r_gate_h[0].clone()
                * (row.reg_val_d[0].clone() + row.shift_amount_compl[0].clone()
                    - thirty_two * bits_value(&row.shift_quotient_compl)),
        );
        // Every shift and rotate row binds its amount: the flag gating
        // the identities is the instruction's shift flag.
        eval.add_constraint(row.is_shift_constrained[0].clone() - row.is_shift[0].clone());

        // The registers each access names, as the instruction fixes
        // them: ValB reads RegA or RegB, ValD reads RegB, and Result
        // writes RegA or RegD, or φ7 on a witness-input call (whose
        // RegA, an ECALLI's, is 0).
        eval.add_constraint(
            row.val_b_reg_idx[0].clone()
                - row.reg_b[0].clone()
                - row.val_b_from_a[0].clone() * (row.reg_a[0].clone() - row.reg_b[0].clone()),
        );
        eval.add_constraint(row.val_d_reg_idx[0].clone() - row.reg_b[0].clone());
        eval.add_constraint(
            row.result_reg_idx[0].clone()
                - row.reg_a[0].clone()
                - row.result_to_d[0].clone() * (row.reg_d[0].clone() - row.reg_a[0].clone())
                - E::F::from(BaseField::from(7u32)) * row.is_witness_ecall[0].clone(),
        );

        let mut tuple: Vec<E::F> = vec![row.result_reg_idx[0].clone()];
        for b in &row.result {
            tuple.push(b.clone());
        }
        for ts in &row.timestamp {
            tuple.push(ts.clone());
        }
        tuple.push(E::F::from(BaseField::from(1u32))); // is_write = 1 (result write)
        eval.add_to_relation(RelationEntry::new(
            reg_lookup,
            row.result_is_reg[0].clone().into(),
            &tuple,
        ));

        // The IsReg booleans are `register_helpers`'.
    }
}
