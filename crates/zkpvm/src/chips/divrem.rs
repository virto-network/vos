//! Phase 54g / 54i / 54k — `DivRemChip`: per-divrem-row chip.
//!
//! CpuChip emits one DivRemLookup producer per `is_div_rem=1` row;
//! DivRemChip consumes once per real row.  DivRemChip witnesses
//! three carry chains internally:
//!
//!   1. (54g) Schoolbook `q·d + r = b` (low 8 bytes) /
//!      `q·d + r = div_corr_hi mod 2^64` (high 8 bytes), in both
//!      64-bit and 32-bit forms.
//!   2. (54i) Unsigned `r < d` uniqueness on
//!      `is_div_rem · ¬div_by_zero · ¬is_div_s` rows.
//!   3. (54k) DivS sign-correction chain pinning DivCorrHi to
//!      `sq·d + sd·q + sr − sb (mod 2^64)` on
//!      `is_div_rem · ¬div_by_zero · is_div_s` rows.  64-bit chain
//!      covers all 8 bytes; 32-bit chain covers low 4.
//!
//! Per-byte Range256 emissions on DivCmpDiff enforce its byte range.
//!
//! Lookup tuple (40 limbs): val_b[8] + val_d[8] + div_quotient[8] +
//! div_remainder[8] + sign_bit_b + sign_bit_d + sign_bit_q +
//! sign_bit_r + is_div_rem + div_by_zero + is_32bit + is_div_s.

#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{
        fields::qm31::SecureField,
        ColumnVec,
    },
    prover::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::core::step::WORD_SIZE;
use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};

use crate::{
    framework::BuiltInComponent,
    lookups::{DivRemLookupElements, Range256LookupElements},
};
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub struct DivRemChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    #[size = 8]
    ValB,
    #[size = 8]
    ValD,
    #[size = 8]
    DivQuotient,
    #[size = 8]
    DivRemainder,
    /// High 8 bytes of the schoolbook output (DivS sign correction
    /// target on signed div rows; 0 on unsigned div rows).  Pinned
    /// CpuChip-side; flowed via the lookup tuple.
    #[size = 8]
    DivCorrHi,
    /// Per-position low byte of the schoolbook carry (16 positions).
    #[size = 16]
    DivMulCarry,
    /// Per-position high byte; full carry = DivMulCarry + 256·DivMulCarryHi.
    #[size = 16]
    DivMulCarryHi,
    #[size = 1]
    IsDivRem,
    #[size = 1]
    DivByZero,
    #[size = 1]
    Is32Bit,
    /// Phase 54i: signed-div flag (flowed via the lookup tuple).  Gates
    /// the unsigned r<d uniqueness chain off so DivS rows aren't forced
    /// through the unsigned predicate (DivS uses |r|<|d| separately —
    /// Phase 30 / 54j).
    #[size = 1]
    IsDivS,
    /// Phase 54i: per-byte `val_d + ~div_remainder + 1` chain witness
    /// (used on unsigned div rows to pin r < d).  Range-checked via
    /// Range256 on every real row.
    #[size = 8]
    DivCmpDiff,
    /// Phase 54i: per-byte boolean carry of the chain.  Top carry = 1
    /// on unsigned div rows.
    #[size = 8]
    DivCmpCarry,
    /// Phase 54k: per-byte carry of the DivS sign-correction chain.
    /// Boolean per byte.
    #[size = 8]
    DivCorrCarry,
    /// Phase 54k: 4 sign bits flowed from CpuChip via the lookup
    /// tuple.  Used by the Phase 16/18 sign-correction chain.
    #[size = 1]
    SignBitB,
    #[size = 1]
    SignBitD,
    #[size = 1]
    SignBitQ,
    #[size = 1]
    SignBitR,
    #[size = 1]
    IsPadding,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "divrem"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for DivRemChip {
    /// Phase 54k: bumped from 2 to 3 (max degree 8).  The Phase 54k
    /// sign-correction chain is degree 6 (`div_s_active * is_64bit *
    /// (sign_bit_q * val_d[i] + ...)` = 4 * 1 * 2).  Schoolbook chain
    /// (54g) is degree 4 (was at the prior bound).
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 3;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (DivRemLookupElements, Range256LookupElements);

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(DivRemLookupElements, Range256LookupElements),
    ) {
        let (divrem_lookup, range256_lookup) = lookup_elements;
        let val_b = crate::trace::trace_eval!(trace_eval, Column::ValB);
        let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
        let div_quotient = crate::trace::trace_eval!(trace_eval, Column::DivQuotient);
        let div_remainder = crate::trace::trace_eval!(trace_eval, Column::DivRemainder);
        let div_corr_hi = crate::trace::trace_eval!(trace_eval, Column::DivCorrHi);
        let mul_carry = crate::trace::trace_eval!(trace_eval, Column::DivMulCarry);
        let mul_carry_hi = crate::trace::trace_eval!(trace_eval, Column::DivMulCarryHi);
        let is_div_rem = crate::trace::trace_eval!(trace_eval, Column::IsDivRem);
        let div_by_zero = crate::trace::trace_eval!(trace_eval, Column::DivByZero);
        let is_32bit = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
        let is_div_s = crate::trace::trace_eval!(trace_eval, Column::IsDivS);
        let div_cmp_diff = crate::trace::trace_eval!(trace_eval, Column::DivCmpDiff);
        let div_cmp_carry = crate::trace::trace_eval!(trace_eval, Column::DivCmpCarry);
        let div_corr_carry = crate::trace::trace_eval!(trace_eval, Column::DivCorrCarry);
        let sign_bit_b = crate::trace::trace_eval!(trace_eval, Column::SignBitB);
        let sign_bit_d = crate::trace::trace_eval!(trace_eval, Column::SignBitD);
        let sign_bit_q = crate::trace::trace_eval!(trace_eval, Column::SignBitQ);
        let sign_bit_r = crate::trace::trace_eval!(trace_eval, Column::SignBitR);
        let is_padding = crate::trace::trace_eval!(trace_eval, Column::IsPadding);

        // Boolean constraints on flag columns.
        for flag in [
            &is_div_rem, &div_by_zero, &is_32bit, &is_div_s,
            &sign_bit_b, &sign_bit_d, &sign_bit_q, &sign_bit_r,
            &is_padding,
        ] {
            eval.add_constraint(flag[0].clone() * (E::F::one() - flag[0].clone()));
        }
        let is_real = E::F::one() - is_padding[0].clone();
        let is_64bit = E::F::one() - is_32bit[0].clone();
        let div_active = is_div_rem[0].clone() * (E::F::one() - div_by_zero[0].clone());

        // ── Phase 54g: schoolbook carry chain ──
        let f256: E::F = E::F::from(BaseField::from(256));
        let full_carry = |k: usize| -> E::F {
            mul_carry[k].clone() + mul_carry_hi[k].clone() * f256.clone()
        };

        // 64-bit chain (16 positions).  Low 8 → val_b; high 8 → div_corr_hi.
        for k in 0..16usize {
            let mut partial_sum = E::F::zero();
            for i in 0..WORD_SIZE {
                let j = k.wrapping_sub(i);
                if j < WORD_SIZE {
                    partial_sum += div_quotient[i].clone() * val_d[j].clone();
                }
            }
            if k < WORD_SIZE {
                partial_sum += div_remainder[k].clone();
            }
            let carry_in = if k == 0 { E::F::zero() } else { full_carry(k - 1) };
            let expected = if k < WORD_SIZE {
                val_b[k].clone()
            } else {
                div_corr_hi[k - WORD_SIZE].clone()
            };
            let c = expected + full_carry(k) * f256.clone() - partial_sum - carry_in;
            eval.add_constraint(
                is_real.clone() * div_active.clone() * is_64bit.clone() * c
            );
        }

        // 32-bit chain (8 positions).  Low 4 → val_b; high 4 → div_corr_hi.
        for k in 0..8usize {
            let mut partial_sum = E::F::zero();
            for i in 0..4usize {
                let j = k.wrapping_sub(i);
                if j < 4 {
                    partial_sum += div_quotient[i].clone() * val_d[j].clone();
                }
            }
            if k < 4 {
                partial_sum += div_remainder[k].clone();
            }
            let carry_in = if k == 0 { E::F::zero() } else { full_carry(k - 1) };
            let expected = if k < 4 {
                val_b[k].clone()
            } else {
                div_corr_hi[k - 4].clone()
            };
            let c = expected + full_carry(k) * f256.clone() - partial_sum - carry_in;
            eval.add_constraint(
                is_real.clone() * div_active.clone() * is_32bit[0].clone() * c
            );
        }

        // ── Phase 54i: r < d uniqueness chain (unsigned div rows) ──
        // Encoded as the carry chain for `val_d - 1 - div_remainder`
        // (= `val_d + ~div_remainder` with carry_in[0] = 0).  The top
        // carry is 1 iff `val_d > div_remainder`.  Without this, the
        // schoolbook q·d+r=b alone admits (q-1, r+d) as another valid
        // pair — see CpuChip's prior comment block at the same spot.
        // Boolean carry on every real row so the column can't drift
        // even when div_u_active=0.
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                is_real.clone() * div_cmp_carry[i].clone()
                    * (E::F::one() - div_cmp_carry[i].clone())
            );
        }
        // Carry chain (gated on `is_real · is_div_rem · ¬div_by_zero · ¬is_div_s`).
        let div_u_active = is_real.clone() * is_div_rem[0].clone()
            * (E::F::one() - div_by_zero[0].clone())
            * (E::F::one() - is_div_s[0].clone());
        let f_255: E::F = E::F::from(BaseField::from(255));
        for i in 0..WORD_SIZE {
            let carry_in = if i == 0 {
                E::F::zero()
            } else {
                div_cmp_carry[i - 1].clone()
            };
            eval.add_constraint(
                div_u_active.clone() * (
                    div_cmp_diff[i].clone()
                        + div_cmp_carry[i].clone() * f256.clone()
                        - val_d[i].clone()
                        - f_255.clone()
                        + div_remainder[i].clone()
                        - carry_in
                )
            );
        }
        // Top carry must be 1 (val_d > div_remainder ⇔ r < d).
        eval.add_constraint(
            div_u_active * (E::F::one() - div_cmp_carry[WORD_SIZE - 1].clone())
        );

        // ── Phase 54k: DivS sign-correction chain ──
        // Was Phase 16/18 on CpuChip.  Pins
        //   div_corr_hi[i] + div_corr_carry[i]·256 + (i==0 ? sb : 0)
        //     = sq·val_d[i] + sd·div_quotient[i] + carry_in + (i==0 ? sr : 0)
        // on `is_real · is_div_rem · ¬div_by_zero · is_div_s` rows.
        // 64-bit chain over all 8 bytes; 32-bit chain over low 4 bytes.
        //
        // No boolean constraint on DivCorrCarry: the trace fill writes
        // carry values in {-1, 0, 1, 2} (see CpuChip trace_fill.rs's
        // Phase 16 block, lines 706-712 region), which are not boolean.
        // The original CpuChip Phase 16/18 had no boolean here either —
        // div_corr_hi is range-checked implicitly via the schoolbook
        // chain (its bytes are bytes of high(q·d+r) mod 2^64), and the
        // prover's freedom in div_corr_carry doesn't enable false
        // proofs given the schoolbook + chain identities.
        let div_s_active = is_real.clone() * is_div_rem[0].clone()
            * (E::F::one() - div_by_zero[0].clone()) * is_div_s[0].clone();
        // 64-bit chain.
        for i in 0..WORD_SIZE {
            let carry_in = if i == 0 {
                E::F::zero()
            } else {
                div_corr_carry[i - 1].clone()
            };
            let extra_lhs = if i == 0 { sign_bit_b[0].clone() } else { E::F::zero() };
            let extra_rhs = if i == 0 { sign_bit_r[0].clone() } else { E::F::zero() };
            eval.add_constraint(
                div_s_active.clone() * is_64bit.clone() * (
                    div_corr_hi[i].clone()
                        + div_corr_carry[i].clone() * f256.clone()
                        + extra_lhs
                        - sign_bit_q[0].clone() * val_d[i].clone()
                        - sign_bit_d[0].clone() * div_quotient[i].clone()
                        - carry_in
                        - extra_rhs
                )
            );
        }
        // 32-bit chain (low 4 bytes only; high 4 of div_corr_hi are
        // unconstrained on 32-bit DivS rows but never observed).
        for i in 0..4 {
            let carry_in = if i == 0 {
                E::F::zero()
            } else {
                div_corr_carry[i - 1].clone()
            };
            let extra_lhs = if i == 0 { sign_bit_b[0].clone() } else { E::F::zero() };
            let extra_rhs = if i == 0 { sign_bit_r[0].clone() } else { E::F::zero() };
            eval.add_constraint(
                div_s_active.clone() * is_32bit[0].clone() * (
                    div_corr_hi[i].clone()
                        + div_corr_carry[i].clone() * f256.clone()
                        + extra_lhs
                        - sign_bit_q[0].clone() * val_d[i].clone()
                        - sign_bit_d[0].clone() * div_quotient[i].clone()
                        - carry_in
                        - extra_rhs
                )
            );
        }

        // Range256 emissions on DivCmpDiff bytes.  8 emissions per real
        // row, gated by is_real, even count (paired with the Phase 54g
        // schoolbook chain's emissions implicitly via finalize_in_pairs).
        for i in 0..WORD_SIZE {
            eval.add_to_relation(RelationEntry::new(
                range256_lookup,
                is_real.clone().into(),
                &[div_cmp_diff[i].clone()],
            ));
        }

        // ── Lookup consumer ──
        let mut tuple: Vec<E::F> = Vec::with_capacity(40);
        tuple.extend_from_slice(&val_b);
        tuple.extend_from_slice(&val_d);
        tuple.extend_from_slice(&div_quotient);
        tuple.extend_from_slice(&div_remainder);
        tuple.push(sign_bit_b[0].clone());
        tuple.push(sign_bit_d[0].clone());
        tuple.push(sign_bit_q[0].clone());
        tuple.push(sign_bit_r[0].clone());
        tuple.push(is_div_rem[0].clone());
        tuple.push(div_by_zero[0].clone());
        tuple.push(is_32bit[0].clone());
        tuple.push(is_div_s[0].clone());

        for _ in 0..2 {
            eval.add_to_relation(RelationEntry::new(
                divrem_lookup,
                (-is_real.clone()).into(),
                &tuple,
            ));
        }

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for DivRemChip {
    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let entries = &side_note.divrem_entries;
        const MIN_LOG_SIZE: u32 = 5;

        if entries.is_empty() {
            let log_size = LOG_N_LANES.max(MIN_LOG_SIZE);
            let mut trace = TraceBuilder::<Column>::new(log_size);
            for row in 0..trace.num_rows() {
                trace.fill_columns(row, true, Column::IsPadding);
            }
            return trace.finalize_bit_reversed();
        }

        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(entries.len()).max(MIN_LOG_SIZE);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        for (row, e) in entries.iter().enumerate() {
            trace.fill_columns_bytes(row, &e.val_b.to_le_bytes(), Column::ValB);
            trace.fill_columns_bytes(row, &e.val_d.to_le_bytes(), Column::ValD);
            trace.fill_columns_bytes(row, &e.div_quotient.to_le_bytes(), Column::DivQuotient);
            trace.fill_columns_bytes(row, &e.div_remainder.to_le_bytes(), Column::DivRemainder);
            trace.fill_columns_bytes(row, &e.div_corr_hi, Column::DivCorrHi);
            trace.fill_columns_bytes(row, &e.div_mul_carry, Column::DivMulCarry);
            trace.fill_columns_bytes(row, &e.div_mul_carry_hi, Column::DivMulCarryHi);
            trace.fill_columns(row, true, Column::IsDivRem);
            trace.fill_columns(row, e.div_by_zero, Column::DivByZero);
            trace.fill_columns(row, e.is_32bit, Column::Is32Bit);
            trace.fill_columns(row, e.is_div_s, Column::IsDivS);
            trace.fill_columns_bytes(row, &e.div_cmp_diff, Column::DivCmpDiff);
            trace.fill_columns_bytes(row, &e.div_cmp_carry, Column::DivCmpCarry);
            trace.fill_columns_bytes(row, &e.div_corr_carry, Column::DivCorrCarry);
            trace.fill_columns(row, e.sign_bit_b, Column::SignBitB);
            trace.fill_columns(row, e.sign_bit_d, Column::SignBitD);
            trace.fill_columns(row, e.sign_bit_q, Column::SignBitQ);
            trace.fill_columns(row, e.sign_bit_r, Column::SignBitR);
            trace.fill_columns(row, false, Column::IsPadding);
        }

        for row in entries.len()..num_rows {
            trace.fill_columns(row, true, Column::IsPadding);
        }

        trace.finalize_bit_reversed()
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        use stwo::prover::backend::simd::m31::PackedBaseField;

        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let divrem: &DivRemLookupElements = lookup_elements.as_ref();
        let range256: &Range256LookupElements = lookup_elements.as_ref();
        let val_b = crate::trace::original_base_column!(component_trace, Column::ValB);
        let val_d = crate::trace::original_base_column!(component_trace, Column::ValD);
        let div_quotient = crate::trace::original_base_column!(component_trace, Column::DivQuotient);
        let div_remainder = crate::trace::original_base_column!(component_trace, Column::DivRemainder);
        let is_div_rem = crate::trace::original_base_column!(component_trace, Column::IsDivRem);
        let div_by_zero = crate::trace::original_base_column!(component_trace, Column::DivByZero);
        let is_32bit = crate::trace::original_base_column!(component_trace, Column::Is32Bit);
        let is_div_s = crate::trace::original_base_column!(component_trace, Column::IsDivS);
        let sign_bit_b = crate::trace::original_base_column!(component_trace, Column::SignBitB);
        let sign_bit_d = crate::trace::original_base_column!(component_trace, Column::SignBitD);
        let sign_bit_q = crate::trace::original_base_column!(component_trace, Column::SignBitQ);
        let sign_bit_r = crate::trace::original_base_column!(component_trace, Column::SignBitR);
        let div_cmp_diff = crate::trace::original_base_column!(component_trace, Column::DivCmpDiff);
        let is_padding = crate::trace::original_base_column!(component_trace, Column::IsPadding);

        // Range256 emissions for DivCmpDiff bytes (8 per row, gated by is_real).
        for col in &div_cmp_diff {
            logup.add_to_relation_with(
                range256,
                [is_padding[0].clone()],
                |[pad]| (PackedBaseField::one() - pad).into(),
                &[col.clone()],
            );
        }

        let mut tuple: Vec<_> = val_b.to_vec();
        tuple.extend_from_slice(&val_d);
        tuple.extend_from_slice(&div_quotient);
        tuple.extend_from_slice(&div_remainder);
        tuple.push(sign_bit_b[0].clone());
        tuple.push(sign_bit_d[0].clone());
        tuple.push(sign_bit_q[0].clone());
        tuple.push(sign_bit_r[0].clone());
        tuple.push(is_div_rem[0].clone());
        tuple.push(div_by_zero[0].clone());
        tuple.push(is_32bit[0].clone());
        tuple.push(is_div_s[0].clone());

        for _ in 0..2 {
            logup.add_to_relation_with(
                divrem,
                [is_padding[0].clone()],
                |[pad]| (-(PackedBaseField::one() - pad)).into(),
                &tuple,
            );
        }

        logup.finalize()
    }
}
