//! Phase 54a — `MulChip`: per-multiplication-row consumer chip.
//!
//! Foundation for the structural Phase 54 chip-extraction.  CpuChip's
//! schoolbook multiplication AIR fires on every `flags.is_mul=1` row
//! (true muls + left shifts + 64/32-bit rotates that route through the
//! schoolbook).  This chip mirrors those rows on its own narrower trace
//! so a future sub-phase can move the schoolbook constraints here and
//! drop the corresponding columns from CpuChip.
//!
//! Phase 54a scope: chip + lookup wiring only.  No AIR constraints
//! beyond consuming the lookup tuple — both sides (CpuChip and MulChip)
//! still hold the full schoolbook AIR; the lookup balance forces the
//! per-row I/O state to agree.  This validates the wiring before any
//! cells are dropped from CpuChip.
//!
//! Phase 54b will move the schoolbook carry-chain constraints from
//! CpuChip to MulChip; Phase 54c will drop `MulHigh / MulCarry /
//! MulCarryHi` etc. from CpuChip.

#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use num_traits::One;
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
use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};

use crate::{
    framework::BuiltInComponent,
    lookups::MultiplicationLookupElements,
};
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub struct MulChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Operand b (8 bytes, low-endian).
    #[size = 8]
    ValB,
    /// Operand d (8 bytes, low-endian).
    #[size = 8]
    ValD,
    /// Low 64 bits of the schoolbook product (8 bytes).
    #[size = 8]
    Result,
    /// High 64 bits of the schoolbook product (8 bytes).
    #[size = 8]
    MulHigh,
    /// 1 iff this row is a low-output mul variant (Mul / ShloL / RotL/R).
    /// `IsMulLo + IsMulUpperUU + IsMulUpperSU + IsMulUpperSS` partitions
    /// the multiplication-row population.
    #[size = 1]
    IsMulLo,
    #[size = 1]
    IsMulUpperUU,
    #[size = 1]
    IsMulUpperSU,
    #[size = 1]
    IsMulUpperSS,
    /// 1 iff the operation operates on the low 32 bits (and zero-extends).
    #[size = 1]
    Is32Bit,
    /// 1 iff this is a padding row (no real multiplication entry).
    #[size = 1]
    IsPadding,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "mul"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for MulChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = MultiplicationLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &MultiplicationLookupElements,
    ) {
        let val_b = crate::trace::trace_eval!(trace_eval, Column::ValB);
        let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
        let result = crate::trace::trace_eval!(trace_eval, Column::Result);
        let mul_high = crate::trace::trace_eval!(trace_eval, Column::MulHigh);
        let is_mul_lo = crate::trace::trace_eval!(trace_eval, Column::IsMulLo);
        let is_mu_uu = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperUU);
        let is_mu_su = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperSU);
        let is_mu_ss = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperSS);
        let is_32bit = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
        let is_padding = crate::trace::trace_eval!(trace_eval, Column::IsPadding);

        // Boolean constraints on flag columns.
        for flag in [&is_mul_lo, &is_mu_uu, &is_mu_su, &is_mu_ss, &is_32bit, &is_padding] {
            eval.add_constraint(flag[0].clone() * (E::F::one() - flag[0].clone()));
        }

        // Partition: on a real (non-padding) row, exactly one variant flag is 1.
        let is_real = E::F::one() - is_padding[0].clone();
        let variant_sum = is_mul_lo[0].clone()
            + is_mu_uu[0].clone()
            + is_mu_su[0].clone()
            + is_mu_ss[0].clone();
        eval.add_constraint(is_real.clone() * (variant_sum.clone() - E::F::one()));
        // On padding rows all variant flags are 0 (lookup multiplicity = 0).
        eval.add_constraint(is_padding[0].clone() * variant_sum);

        // Consume the multiplication lookup.  Tuple = (val_b[8], val_d[8],
        // result[8], mul_high[8], is_mul_lo, is_mu_uu, is_mu_su, is_mu_ss,
        // is_32bit) = 37 limbs.  Multiplicity = -(1 - is_padding).
        let mut tuple: Vec<E::F> = Vec::with_capacity(37);
        tuple.extend_from_slice(&val_b);
        tuple.extend_from_slice(&val_d);
        tuple.extend_from_slice(&result);
        tuple.extend_from_slice(&mul_high);
        tuple.push(is_mul_lo[0].clone());
        tuple.push(is_mu_uu[0].clone());
        tuple.push(is_mu_su[0].clone());
        tuple.push(is_mu_ss[0].clone());
        tuple.push(is_32bit[0].clone());

        // Two paired emissions to keep finalize_logup_in_pairs happy
        // (CpuChip's producer side also emits in pairs).
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
impl BuiltInProverComponent for MulChip {
    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let entries = &side_note.mul_entries;
        // stwo's FFT path needs domain >= MIN_FFT_LOG_SIZE (5), and the
        // eval domain = log_size + LOG_CONSTRAINT_DEGREE_BOUND.  Ensure
        // a minimum log_size of 5 so even an empty mul trace works.
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
            trace.fill_columns_bytes(row, &e.result.to_le_bytes(), Column::Result);
            trace.fill_columns_bytes(row, &e.mul_high.to_le_bytes(), Column::MulHigh);
            trace.fill_columns(row, e.is_mul_lo, Column::IsMulLo);
            trace.fill_columns(row, e.is_mul_upper_uu, Column::IsMulUpperUU);
            trace.fill_columns(row, e.is_mul_upper_su, Column::IsMulUpperSU);
            trace.fill_columns(row, e.is_mul_upper_ss, Column::IsMulUpperSS);
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
        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let mul: &MultiplicationLookupElements = lookup_elements.as_ref();
        let val_b = crate::trace::original_base_column!(component_trace, Column::ValB);
        let val_d = crate::trace::original_base_column!(component_trace, Column::ValD);
        let result = crate::trace::original_base_column!(component_trace, Column::Result);
        let mul_high = crate::trace::original_base_column!(component_trace, Column::MulHigh);
        let is_mul_lo = crate::trace::original_base_column!(component_trace, Column::IsMulLo);
        let is_mu_uu = crate::trace::original_base_column!(component_trace, Column::IsMulUpperUU);
        let is_mu_su = crate::trace::original_base_column!(component_trace, Column::IsMulUpperSU);
        let is_mu_ss = crate::trace::original_base_column!(component_trace, Column::IsMulUpperSS);
        let is_32bit = crate::trace::original_base_column!(component_trace, Column::Is32Bit);
        let is_padding = crate::trace::original_base_column!(component_trace, Column::IsPadding);

        let mut tuple: Vec<_> = val_b.to_vec();
        tuple.extend_from_slice(&val_d);
        tuple.extend_from_slice(&result);
        tuple.extend_from_slice(&mul_high);
        tuple.push(is_mul_lo[0].clone());
        tuple.push(is_mu_uu[0].clone());
        tuple.push(is_mu_su[0].clone());
        tuple.push(is_mu_ss[0].clone());
        tuple.push(is_32bit[0].clone());

        // Consumer side: multiplicity = -(1 - is_padding).  Emit twice
        // to mirror the verifier-side paired emissions.
        for _ in 0..2 {
            logup.add_to_relation_with(
                mul,
                [is_padding[0].clone()],
                |[pad]| {
                    use stwo::prover::backend::simd::m31::PackedBaseField;
                    (-(PackedBaseField::one() - pad)).into()
                },
                &tuple,
            );
        }

        logup.finalize()
    }
}

