//! Phase 54g — `DivRemChip`: per-divrem-row chip.
//!
//! CpuChip emits one DivRemLookup producer per `is_div_rem=1` row;
//! DivRemChip consumes once per real row.  DivRemChip witnesses the
//! 16-position carry chain for the schoolbook `q·d + r = b` (low 8
//! bytes) / `q·d + r = div_corr_hi mod 2^64` (high 8 bytes), in both
//! 64-bit and 32-bit forms.
//!
//! Lookup tuple (43 limbs): val_b[8] + val_d[8] + div_quotient[8] +
//! div_remainder[8] + div_corr_hi[8] + is_div_rem + div_by_zero +
//! is_32bit.

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
    lookups::DivRemLookupElements,
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
    #[size = 1]
    IsPadding,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "divrem"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for DivRemChip {
    /// Schoolbook constraint is degree 4 (`is_real * is_64bit *
    /// (1 - div_by_zero) * (q*d + r - val_b - ...)`).  Eval domain
    /// needs log_size + 2.
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 2;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = DivRemLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &DivRemLookupElements,
    ) {
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
        let is_padding = crate::trace::trace_eval!(trace_eval, Column::IsPadding);

        // Boolean constraints on flag columns.
        for flag in [&is_div_rem, &div_by_zero, &is_32bit, &is_padding] {
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

        // ── Lookup consumer ──
        let mut tuple: Vec<E::F> = Vec::with_capacity(43);
        tuple.extend_from_slice(&val_b);
        tuple.extend_from_slice(&val_d);
        tuple.extend_from_slice(&div_quotient);
        tuple.extend_from_slice(&div_remainder);
        tuple.extend_from_slice(&div_corr_hi);
        tuple.push(is_div_rem[0].clone());
        tuple.push(div_by_zero[0].clone());
        tuple.push(is_32bit[0].clone());

        for _ in 0..2 {
            eval.add_to_relation(RelationEntry::new(
                lookup_elements,
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
        let val_b = crate::trace::original_base_column!(component_trace, Column::ValB);
        let val_d = crate::trace::original_base_column!(component_trace, Column::ValD);
        let div_quotient = crate::trace::original_base_column!(component_trace, Column::DivQuotient);
        let div_remainder = crate::trace::original_base_column!(component_trace, Column::DivRemainder);
        let div_corr_hi = crate::trace::original_base_column!(component_trace, Column::DivCorrHi);
        let is_div_rem = crate::trace::original_base_column!(component_trace, Column::IsDivRem);
        let div_by_zero = crate::trace::original_base_column!(component_trace, Column::DivByZero);
        let is_32bit = crate::trace::original_base_column!(component_trace, Column::Is32Bit);
        let is_padding = crate::trace::original_base_column!(component_trace, Column::IsPadding);

        let mut tuple: Vec<_> = val_b.to_vec();
        tuple.extend_from_slice(&val_d);
        tuple.extend_from_slice(&div_quotient);
        tuple.extend_from_slice(&div_remainder);
        tuple.extend_from_slice(&div_corr_hi);
        tuple.push(is_div_rem[0].clone());
        tuple.push(div_by_zero[0].clone());
        tuple.push(is_32bit[0].clone());

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
