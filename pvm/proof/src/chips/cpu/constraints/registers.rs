//! Register-memory accesses and their helpers.
use alloc::{vec, vec::Vec};

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use super::{Lookups, Trace};
use crate::chips::cpu::columns::Column;
use crate::core::step::WORD_SIZE;

/// The register-memory binding helpers.
pub(in crate::chips::cpu) fn register_helpers<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
    let is_real = E::F::one() - is_pad[0].clone();
    let is_32bit = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
    // ── Register-memory binding helpers ──
    // The IsTruncated/ValBIsReg/ValDIsReg/ResultIsReg/Phi7Bool/
    // IsBlakeEcall boolean properties are enforced unconditionally
    // below.
    let real_32bit_h = crate::trace::trace_eval!(trace_eval, Column::Real32bitH);
    let val_b_is_reg_h = crate::trace::trace_eval!(trace_eval, Column::ValBIsRegH);
    let val_b_is_reg_not_trunc_h =
        crate::trace::trace_eval!(trace_eval, Column::ValBIsRegNotTruncH);
    let val_b_is_reg_trunc_h = crate::trace::trace_eval!(trace_eval, Column::ValBIsRegTruncH);
    let val_d_is_imm_h = crate::trace::trace_eval!(trace_eval, Column::ValDIsImmH);
    let non_shift_gate_h = crate::trace::trace_eval!(trace_eval, Column::NonShiftGateH);
    let non_shift_gate_not_trunc_h =
        crate::trace::trace_eval!(trace_eval, Column::NonShiftGateNotTruncH);
    let non_shift_gate_trunc_h = crate::trace::trace_eval!(trace_eval, Column::NonShiftGateTruncH);
    let real_shift_c_h = crate::trace::trace_eval!(trace_eval, Column::RealShiftCH);
    let is_rotate_r_gate_h = crate::trace::trace_eval!(trace_eval, Column::IsRotateRGateH);
    {
        let is_truncated_top = crate::trace::trace_eval!(trace_eval, Column::IsTruncated);
        let val_b_is_reg_top = crate::trace::trace_eval!(trace_eval, Column::ValBIsReg);
        let val_d_is_reg_top = crate::trace::trace_eval!(trace_eval, Column::ValDIsReg);
        let result_is_reg_top = crate::trace::trace_eval!(trace_eval, Column::ResultIsReg);
        let phi7_bool_top = crate::trace::trace_eval!(trace_eval, Column::Phi7Bool);
        let is_blake_ecall_top = crate::trace::trace_eval!(trace_eval, Column::IsBlakeEcall);
        let is_shift_c_top = crate::trace::trace_eval!(trace_eval, Column::IsShiftConstrained);
        let is_rot_r64_top = crate::trace::trace_eval!(trace_eval, Column::IsRotateR64);
        let is_rot_r32_top = crate::trace::trace_eval!(trace_eval, Column::IsRotateR32);
        let is_witness_top = crate::trace::trace_eval!(trace_eval, Column::IsWitnessEcall);
        // Boolean flags enforced unconditionally — a gated
        // `is_real · bool_h = 0` pattern would be redundant.
        for flag in [
            &is_truncated_top,
            &val_b_is_reg_top,
            &val_d_is_reg_top,
            &result_is_reg_top,
            &phi7_bool_top,
            &is_blake_ecall_top,
            &is_witness_top,
        ] {
            eval.add_constraint(flag[0].clone() * (E::F::one() - flag[0].clone()));
        }
        // Selector helpers (deg 2 def each).
        eval.add_constraint(real_32bit_h[0].clone() - is_real.clone() * is_32bit[0].clone());
        eval.add_constraint(
            val_b_is_reg_h[0].clone() - is_real.clone() * val_b_is_reg_top[0].clone(),
        );
        eval.add_constraint(
            val_b_is_reg_not_trunc_h[0].clone()
                - val_b_is_reg_h[0].clone() * (E::F::one() - is_truncated_top[0].clone()),
        );
        eval.add_constraint(
            val_b_is_reg_trunc_h[0].clone()
                - val_b_is_reg_h[0].clone() * is_truncated_top[0].clone(),
        );
        // Every real row's ValD has a source, its register or the
        // immediate, so the ValD gates are the row's realness.
        eval.add_constraint(
            val_d_is_imm_h[0].clone()
                - is_real.clone() * (E::F::one() - val_d_is_reg_top[0].clone()),
        );
        eval.add_constraint(
            non_shift_gate_h[0].clone()
                - is_real.clone() * (E::F::one() - is_shift_c_top[0].clone()),
        );
        eval.add_constraint(
            non_shift_gate_not_trunc_h[0].clone()
                - non_shift_gate_h[0].clone() * (E::F::one() - is_truncated_top[0].clone()),
        );
        eval.add_constraint(
            non_shift_gate_trunc_h[0].clone()
                - non_shift_gate_h[0].clone() * is_truncated_top[0].clone(),
        );
        eval.add_constraint(
            real_shift_c_h[0].clone() - is_real.clone() * is_shift_c_top[0].clone(),
        );
        eval.add_constraint(
            is_rotate_r_gate_h[0].clone()
                - is_real.clone() * (is_rot_r64_top[0].clone() + is_rot_r32_top[0].clone()),
        );
    }
    // Phi7-related helpers.
    let real_not_phi7_bool_h = crate::trace::trace_eval!(trace_eval, Column::RealNotPhi7BoolH);
    let real_phi7_bool_h = crate::trace::trace_eval!(trace_eval, Column::RealPhi7BoolH);
    let phi7_times_inv_h = crate::trace::trace_eval!(trace_eval, Column::Phi7TimesInvH);
    {
        let phi7_top = crate::trace::trace_eval!(trace_eval, Column::Phi7);
        let phi7_inv_top = crate::trace::trace_eval!(trace_eval, Column::Phi7Inv);
        let phi7_bool_top = crate::trace::trace_eval!(trace_eval, Column::Phi7Bool);
        eval.add_constraint(
            real_not_phi7_bool_h[0].clone()
                - is_real.clone() * (E::F::one() - phi7_bool_top[0].clone()),
        );
        eval.add_constraint(
            real_phi7_bool_h[0].clone() - is_real.clone() * phi7_bool_top[0].clone(),
        );
        // Its bytes' sum, at most 2040, is zero exactly when the
        // register is: φ10 non-zero but ≡ 0 mod p, as a base-256
        // combination would see it, is non-zero here.
        let phi7_sum = phi7_top
            .iter()
            .fold(E::F::zero(), |sum, byte| sum + byte.clone());
        eval.add_constraint(phi7_times_inv_h[0].clone() - phi7_sum * phi7_inv_top[0].clone());
    }
}

/// The register-memory producers, in the interaction trace's order.
pub(in crate::chips::cpu) fn register_accesses<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
    lookups: &Lookups<'_>,
) {
    let reg_lookup = lookups.reg_lookup;
    let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
    let is_real = E::F::one() - is_pad[0].clone();
    let is_add = crate::trace::trace_eval!(trace_eval, Column::IsAdd);
    let is_sub = crate::trace::trace_eval!(trace_eval, Column::IsSub);
    let is_mul = crate::trace::trace_eval!(trace_eval, Column::IsMul);
    let is_shift = crate::trace::trace_eval!(trace_eval, Column::IsShift);
    let val_b = crate::trace::trace_eval!(trace_eval, Column::ValB);
    let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
    let is_div_rem = crate::trace::trace_eval!(trace_eval, Column::IsDivRem);
    let real_32bit_h = crate::trace::trace_eval!(trace_eval, Column::Real32bitH);
    let val_b_is_reg_h = crate::trace::trace_eval!(trace_eval, Column::ValBIsRegH);
    let val_b_is_reg_not_trunc_h =
        crate::trace::trace_eval!(trace_eval, Column::ValBIsRegNotTruncH);
    let val_b_is_reg_trunc_h = crate::trace::trace_eval!(trace_eval, Column::ValBIsRegTruncH);
    let val_d_is_imm_h = crate::trace::trace_eval!(trace_eval, Column::ValDIsImmH);
    let non_shift_gate_h = crate::trace::trace_eval!(trace_eval, Column::NonShiftGateH);
    let non_shift_gate_not_trunc_h =
        crate::trace::trace_eval!(trace_eval, Column::NonShiftGateNotTruncH);
    let non_shift_gate_trunc_h = crate::trace::trace_eval!(trace_eval, Column::NonShiftGateTruncH);
    let real_shift_c_h = crate::trace::trace_eval!(trace_eval, Column::RealShiftCH);
    let is_rotate_r_gate_h = crate::trace::trace_eval!(trace_eval, Column::IsRotateRGateH);
    let timestamp = crate::trace::trace_eval!(trace_eval, Column::Timestamp);
    // Register-memory producers: mirror of the interaction trace
    // emissions in the same order (ValB read → ValD read → Result
    // write) so finalize_logup_in_pairs pairs correctly.
    {
        let val_b_is_reg = crate::trace::trace_eval!(trace_eval, Column::ValBIsReg);
        let val_b_reg_idx = crate::trace::trace_eval!(trace_eval, Column::ValBRegIdx);
        let val_d_is_reg = crate::trace::trace_eval!(trace_eval, Column::ValDIsReg);
        let val_d_reg_idx = crate::trace::trace_eval!(trace_eval, Column::ValDRegIdx);
        let result_is_reg = crate::trace::trace_eval!(trace_eval, Column::ResultIsReg);
        let result_reg_idx = crate::trace::trace_eval!(trace_eval, Column::ResultRegIdx);
        let result_c = crate::trace::trace_eval!(trace_eval, Column::Result);

        // RegValB carries the full u64 register value; ValB may be
        // truncated (for 32-bit ALU ops).  Producer uses RegValB.
        let reg_val_b = crate::trace::trace_eval!(trace_eval, Column::RegValB);
        let mut tuple: Vec<E::F> = vec![val_b_reg_idx[0].clone()];
        for b in &reg_val_b {
            tuple.push(b.clone());
        }
        for ts in &timestamp {
            tuple.push(ts.clone());
        }
        tuple.push(E::F::from(BaseField::from(0u32))); // is_write = 0 (read)
        eval.add_to_relation(RelationEntry::new(
            reg_lookup,
            val_b_is_reg[0].clone().into(),
            &tuple,
        ));

        // RegValD (raw reg_b value) drives the ledger, not ValD
        // (which gets rewritten to 2^shift_amount for shift ops).
        let reg_val_d = crate::trace::trace_eval!(trace_eval, Column::RegValD);
        let mut tuple: Vec<E::F> = vec![val_d_reg_idx[0].clone()];
        for b in &reg_val_d {
            tuple.push(b.clone());
        }
        for ts in &timestamp {
            tuple.push(ts.clone());
        }
        tuple.push(E::F::from(BaseField::from(0u32))); // is_write = 0 (read)
        eval.add_to_relation(RelationEntry::new(
            reg_lookup,
            val_d_is_reg[0].clone().into(),
            &tuple,
        ));

        // RegValA producer for StoreInd source value.  Emitted as a
        // paired duplicate (mirrors the prog_mem pattern) so pair-parity
        // stays even; RegisterMemoryChip pushes the val_a_read entry
        // twice to match.  Tuple uses RegA directly as the index (reg_a
        // is a column on every row, decoded from the opcode by the
        // ProgramMemory binding).
        let reg_val_a = crate::trace::trace_eval!(trace_eval, Column::RegValA);
        let reg_a_col = crate::trace::trace_eval!(trace_eval, Column::RegA);
        let is_store_ind_col = crate::trace::trace_eval!(trace_eval, Column::IsStoreInd);
        let mut tuple_a: Vec<E::F> = vec![reg_a_col[0].clone()];
        for b in &reg_val_a {
            tuple_a.push(b.clone());
        }
        for ts in &timestamp {
            tuple_a.push(ts.clone());
        }
        tuple_a.push(E::F::from(BaseField::from(0u32))); // is_write = 0 (read)
        eval.add_to_relation(RelationEntry::new(
            reg_lookup,
            is_store_ind_col[0].clone().into(),
            &tuple_a,
        ));
        eval.add_to_relation(RelationEntry::new(
            reg_lookup,
            is_store_ind_col[0].clone().into(),
            &tuple_a,
        ));

        // IsTruncated identity binding; its boolean property is
        // `register_helpers`'.
        let is_truncated = crate::trace::trace_eval!(trace_eval, Column::IsTruncated);
        // is_truncated = is_32bit · (is_add+is_sub+is_mul+is_div_rem).
        // is_real · is_32bit lifted into Real32bitH so the constraint
        // factors as is_real·is_truncated - Real32bitH·trunc_sum.
        let trunc_sum =
            is_add[0].clone() + is_sub[0].clone() + is_mul[0].clone() + is_div_rem[0].clone();
        eval.add_constraint(
            is_real.clone() * is_truncated[0].clone() - real_32bit_h[0].clone() * trunc_sum,
        );

        // ValB byte-wise cross-constraint.
        for i in 0..4 {
            eval.add_constraint(
                val_b_is_reg_h[0].clone() * (val_b[i].clone() - reg_val_b[i].clone()),
            );
        }
        for i in 4..WORD_SIZE {
            eval.add_constraint(
                val_b_is_reg_not_trunc_h[0].clone() * (val_b[i].clone() - reg_val_b[i].clone()),
            );
            eval.add_constraint(val_b_is_reg_trunc_h[0].clone() * val_b[i].clone());
        }

        // ValD byte-wise cross-constraint.
        // Skip shift rows (handled by the ShiftQuotient identity below).
        let is_shift_c = crate::trace::trace_eval!(trace_eval, Column::IsShiftConstrained);
        for i in 0..4 {
            eval.add_constraint(
                non_shift_gate_h[0].clone() * (val_d[i].clone() - reg_val_d[i].clone()),
            );
        }
        for i in 4..WORD_SIZE {
            eval.add_constraint(
                non_shift_gate_not_trunc_h[0].clone() * (val_d[i].clone() - reg_val_d[i].clone()),
            );
            eval.add_constraint(non_shift_gate_trunc_h[0].clone() * val_d[i].clone());
        }

        // An immediate operand is the instruction's: RegValD, which the
        // cross-constraints above tie to ValD, is ImmBytes whenever ValD
        // reads no register.
        let imm_bytes = crate::trace::trace_eval!(trace_eval, Column::ImmBytes);
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                val_d_is_imm_h[0].clone() * (reg_val_d[i].clone() - imm_bytes[i].clone()),
            );
        }

        // Shift-amount identity, on the low byte alone (a modulus of 32
        // or 64 divides 256): RegValD[0] = ShiftAmount + 32·k with k's
        // three bits, k even on a 64-bit shift. Every term is below 2^10,
        // so it holds over the integers: ShiftAmount, in [0, 63] by the
        // PowerOfTwo lookup and in [0, 31] on a 32-bit shift by ValD's
        // zero high bytes, is RegValD's residue.
        let shift_q = crate::trace::trace_eval!(trace_eval, Column::ShiftQuotient);
        let is_32b = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
        let shift_amount_e = crate::trace::trace_eval!(trace_eval, Column::ShiftAmount);
        let thirty_two = E::F::from(BaseField::from(32u32));
        let bits_value = |bits: &[E::F]| -> E::F {
            bits.iter()
                .rev()
                .fold(E::F::zero(), |acc, bit| acc.clone() + acc + bit.clone())
        };
        for bit in shift_q.iter() {
            eval.add_constraint(bit.clone() * (E::F::one() - bit.clone()));
        }
        eval.add_constraint((E::F::one() - is_32b[0].clone()) * shift_q[0].clone());
        eval.add_constraint(
            real_shift_c_h[0].clone()
                * (reg_val_d[0].clone()
                    - shift_amount_e[0].clone()
                    - thirty_two.clone() * bits_value(&shift_q)),
        );

        // Complementary identity on RotR64 / RotR32 rows:
        //   RegValD[0] + ShiftAmountCompl = 32·k, k's four bits, k even
        // on a 64-bit rotate. Combined with the ShiftAmountCompl ∈
        // [0, 31 or 0, 63] bound (pow2 table size + the
        // val_d-high-bytes-zero constraint for 32-bit), this uniquely
        // determines ShiftAmountCompl = (modulus − n_real) mod modulus.
        let shift_q_compl = crate::trace::trace_eval!(trace_eval, Column::ShiftQuotientCompl);
        let shift_amount_compl = crate::trace::trace_eval!(trace_eval, Column::ShiftAmountCompl);
        for bit in shift_q_compl.iter() {
            eval.add_constraint(bit.clone() * (E::F::one() - bit.clone()));
        }
        eval.add_constraint((E::F::one() - is_32b[0].clone()) * shift_q_compl[0].clone());
        eval.add_constraint(
            is_rotate_r_gate_h[0].clone()
                * (reg_val_d[0].clone() + shift_amount_compl[0].clone()
                    - thirty_two * bits_value(&shift_q_compl)),
        );
        // Every shift and rotate row binds its amount: the flag gating
        // the identities is the instruction's shift flag.
        eval.add_constraint(is_shift_c[0].clone() - is_shift[0].clone());

        // The registers each access names, as the instruction fixes
        // them: ValB reads RegA or RegB, ValD reads RegB, and Result
        // writes RegA or RegD, or φ7 on a witness-input call (whose
        // RegA, an ECALLI's, is 0).
        let reg_a = crate::trace::trace_eval!(trace_eval, Column::RegA);
        let reg_b = crate::trace::trace_eval!(trace_eval, Column::RegB);
        let reg_d = crate::trace::trace_eval!(trace_eval, Column::RegD);
        let val_b_from_a = crate::trace::trace_eval!(trace_eval, Column::ValBFromA);
        let result_to_d = crate::trace::trace_eval!(trace_eval, Column::ResultToD);
        let is_witness = crate::trace::trace_eval!(trace_eval, Column::IsWitnessEcall);
        eval.add_constraint(
            val_b_reg_idx[0].clone()
                - reg_b[0].clone()
                - val_b_from_a[0].clone() * (reg_a[0].clone() - reg_b[0].clone()),
        );
        eval.add_constraint(val_d_reg_idx[0].clone() - reg_b[0].clone());
        eval.add_constraint(
            result_reg_idx[0].clone()
                - reg_a[0].clone()
                - result_to_d[0].clone() * (reg_d[0].clone() - reg_a[0].clone())
                - E::F::from(BaseField::from(7u32)) * is_witness[0].clone(),
        );

        let mut tuple: Vec<E::F> = vec![result_reg_idx[0].clone()];
        for b in &result_c {
            tuple.push(b.clone());
        }
        for ts in &timestamp {
            tuple.push(ts.clone());
        }
        tuple.push(E::F::from(BaseField::from(1u32))); // is_write = 1 (result write)
        eval.add_to_relation(RelationEntry::new(
            reg_lookup,
            result_is_reg[0].clone().into(),
            &tuple,
        ));

        // The IsReg booleans are `register_helpers`'.
    }
}
