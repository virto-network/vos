//! Phase 54f — `CompareChip`: per-compare-or-branch-row chip.
//!
//! CpuChip emits one CompareLookup producer per `is_compare + is_branch`
//! row; CompareChip consumes once per real row.  CompareChip witnesses
//! the byte-wise subtraction carry chain (val_b + ~val_d + 1) and pins
//! cmp_lt_flag = 1 - cmp_carry[7].  Per-byte Range256 lookups on
//! cmp_sub_result emit from here too.
//!
//! Lookup tuple (17 limbs): val_b[8] + val_d[8] + cmp_lt_flag.

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
use crate::core::step::WORD_SIZE;
use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};

use crate::{
    framework::BuiltInComponent,
    lookups::{CompareLookupElements, Range256LookupElements},
};
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub struct CompareChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    #[size = 8]
    ValB,
    #[size = 8]
    ValD,
    /// 1 iff val_b < val_d (unsigned).  Pinned to `1 - cmp_carry[7]`.
    #[size = 1]
    CmpLtFlag,
    /// Per-byte witness: `val_b[i] + 255 - val_d[i] + carry_in mod 256`.
    /// Range-checked via Range256.
    #[size = 8]
    CmpSubResult,
    /// Per-byte carry of the chain (each byte ∈ {0, 1}).
    #[size = 8]
    CmpCarry,
    #[size = 1]
    IsPadding,
    // (B3 audit dropped CmpLtFlagBoolH + CmpCarryBoolH — booleans
    // are now enforced unconditionally as `X·(1-X)=0`.)
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "compare"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for CompareChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (CompareLookupElements, Range256LookupElements);

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(CompareLookupElements, Range256LookupElements),
    ) {
        let (compare_lookup, range256_lookup) = lookup_elements;
        let val_b = crate::trace::trace_eval!(trace_eval, Column::ValB);
        let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
        let cmp_lt_flag = crate::trace::trace_eval!(trace_eval, Column::CmpLtFlag);
        let cmp_sub_result = crate::trace::trace_eval!(trace_eval, Column::CmpSubResult);
        let cmp_carry = crate::trace::trace_eval!(trace_eval, Column::CmpCarry);
        let is_padding = crate::trace::trace_eval!(trace_eval, Column::IsPadding);

        // Boolean constraint on padding.
        eval.add_constraint(is_padding[0].clone() * (E::F::one() - is_padding[0].clone()));
        // B3 audit: cmp_lt_flag + cmp_carry[i] booleans enforced
        // unconditionally — trace fill defaults both to 0 on padding.
        let is_real = E::F::one() - is_padding[0].clone();
        eval.add_constraint(
            cmp_lt_flag[0].clone() * (E::F::one() - cmp_lt_flag[0].clone())
        );
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                cmp_carry[i].clone() * (E::F::one() - cmp_carry[i].clone())
            );
        }

        // ── Subtraction carry chain ──
        //   sub_result[i] + carry[i]·256 = val_b[i] + 255 - val_d[i] + carry_in
        // (carry_in[0] = 1, carry_in[i] = carry[i-1])
        let f256: E::F = E::F::from(BaseField::from(256));
        let f255: E::F = E::F::from(BaseField::from(255));
        for i in 0..WORD_SIZE {
            let carry_in = if i == 0 { E::F::one() } else { cmp_carry[i - 1].clone() };
            eval.add_constraint(
                is_real.clone() * (
                    cmp_sub_result[i].clone() + cmp_carry[i].clone() * f256.clone()
                    - val_b[i].clone() - f255.clone() + val_d[i].clone() - carry_in
                )
            );
        }
        // cmp_lt_flag = 1 - cmp_carry[7]
        eval.add_constraint(
            is_real.clone()
                * (cmp_lt_flag[0].clone() + cmp_carry[WORD_SIZE - 1].clone() - E::F::one())
        );

        // ── Range256 emissions on cmp_sub_result bytes ──
        // 8 emissions per real row, gated on is_real.
        for i in 0..WORD_SIZE {
            eval.add_to_relation(RelationEntry::new(
                range256_lookup,
                is_real.clone().into(),
                &[cmp_sub_result[i].clone()],
            ));
        }

        // ── CompareLookup consumer ──
        // Tuple (17 limbs): val_b[8] + val_d[8] + cmp_lt_flag.
        let mut tuple: Vec<E::F> = Vec::with_capacity(17);
        tuple.extend_from_slice(&val_b);
        tuple.extend_from_slice(&val_d);
        tuple.push(cmp_lt_flag[0].clone());

        for _ in 0..2 {
            eval.add_to_relation(RelationEntry::new(
                compare_lookup,
                (-is_real.clone()).into(),
                &tuple,
            ));
        }

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for CompareChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        let entries = &side_note.compare_entries;
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
            trace.fill_columns(row, e.cmp_lt_flag, Column::CmpLtFlag);
            trace.fill_columns_bytes(row, &e.cmp_sub_result, Column::CmpSubResult);
            trace.fill_columns_bytes(row, &e.cmp_carry, Column::CmpCarry);
            trace.fill_columns(row, false, Column::IsPadding);
            // Phase I-cmp helper fills.  Boolean helpers are 0 in valid
            // traces (cmp_lt_flag, cmp_carry[i] ∈ {0, 1}).
            // (B3 audit dropped CmpLtFlagBoolH + CmpCarryBoolH fills.)
        }

        for row in entries.len()..num_rows {
            trace.fill_columns(row, true, Column::IsPadding);
        }

        trace.finalize_bit_reversed()
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        use stwo::prover::backend::simd::m31::PackedBaseField;

        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let compare: &CompareLookupElements = lookup_elements.as_ref();
        let range256: &Range256LookupElements = lookup_elements.as_ref();
        let val_b = crate::trace::original_base_column!(component_trace, Column::ValB);
        let val_d = crate::trace::original_base_column!(component_trace, Column::ValD);
        let cmp_lt_flag = crate::trace::original_base_column!(component_trace, Column::CmpLtFlag);
        let cmp_sub_result = crate::trace::original_base_column!(component_trace, Column::CmpSubResult);
        let is_padding = crate::trace::original_base_column!(component_trace, Column::IsPadding);

        let _ = side_note;

        // Range256 emissions for cmp_sub_result bytes (8 per row).
        for col in &cmp_sub_result {
            logup.add_to_relation_with(
                range256,
                [is_padding[0].clone()],
                |[pad]| (PackedBaseField::one() - pad).into(),
                &[col.clone()],
            );
        }

        // CompareLookup consumer.
        let mut tuple: Vec<_> = val_b.to_vec();
        tuple.extend_from_slice(&val_d);
        tuple.push(cmp_lt_flag[0].clone());

        for _ in 0..2 {
            logup.add_to_relation_with(
                compare,
                [is_padding[0].clone()],
                |[pad]| (-(PackedBaseField::one() - pad)).into(),
                &tuple,
            );
        }

        logup.finalize()
    }
}
