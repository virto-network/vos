//! Phase 54e — `BitwiseChip`: per-bitwise-row chip.
//!
//! CpuChip emits one BitwiseLookup producer per `is_bitwise=1` row;
//! BitwiseChip consumes once per real row.  BitwiseChip witnesses the
//! AND result + nibble decompositions, runs the per-op result-binding
//! identities, and emits the 16 nibble-AND lookups against
//! BitwiseLookupChip's table — all moved off CpuChip's wide trace.
//!
//! Lookup tuple (30 limbs): val_b[8] + val_d[8] + result[8] +
//! is_and + is_or + is_xor + is_and_inv + is_or_inv + is_xnor.

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
    lookups::{BitwiseAndLookupElements, BitwiseLookupElements},
};
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub struct BitwiseChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    #[size = 8]
    ValB,
    #[size = 8]
    ValD,
    #[size = 8]
    Result,
    /// `and_result[i] = val_b[i] & val_d[i]` — pinned by 16 nibble-AND
    /// lookups against BitwiseLookupChip's 16×16 table.
    #[size = 8]
    AndResult,
    #[size = 8]
    ValBHiNib,
    #[size = 8]
    ValDHiNib,
    #[size = 8]
    AndResultHiNib,
    /// Per-op flag columns; exactly one is 1 on a real row.
    #[size = 1]
    IsAnd,
    #[size = 1]
    IsOr,
    #[size = 1]
    IsXor,
    #[size = 1]
    IsAndInv,
    #[size = 1]
    IsOrInv,
    #[size = 1]
    IsXnor,
    #[size = 1]
    IsPadding,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "bitwise"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for BitwiseChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    /// Phase 54e — depends on both BitwiseLookup (for the row-level
    /// consumer) and BitwiseAndLookup (for the 16 nibble emissions).
    type LookupElements = (BitwiseLookupElements, BitwiseAndLookupElements);

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(BitwiseLookupElements, BitwiseAndLookupElements),
    ) {
        let (bitwise_lookup, bitwise_and_lookup) = lookup_elements;
        let val_b = crate::trace::trace_eval!(trace_eval, Column::ValB);
        let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
        let result = crate::trace::trace_eval!(trace_eval, Column::Result);
        let and_result = crate::trace::trace_eval!(trace_eval, Column::AndResult);
        let val_b_hi_nib = crate::trace::trace_eval!(trace_eval, Column::ValBHiNib);
        let val_d_hi_nib = crate::trace::trace_eval!(trace_eval, Column::ValDHiNib);
        let and_result_hi_nib = crate::trace::trace_eval!(trace_eval, Column::AndResultHiNib);
        let is_and = crate::trace::trace_eval!(trace_eval, Column::IsAnd);
        let is_or = crate::trace::trace_eval!(trace_eval, Column::IsOr);
        let is_xor = crate::trace::trace_eval!(trace_eval, Column::IsXor);
        let is_and_inv = crate::trace::trace_eval!(trace_eval, Column::IsAndInv);
        let is_or_inv = crate::trace::trace_eval!(trace_eval, Column::IsOrInv);
        let is_xnor = crate::trace::trace_eval!(trace_eval, Column::IsXnor);
        let is_padding = crate::trace::trace_eval!(trace_eval, Column::IsPadding);

        // Boolean constraints on flag columns.
        for flag in [&is_and, &is_or, &is_xor, &is_and_inv, &is_or_inv, &is_xnor, &is_padding] {
            eval.add_constraint(flag[0].clone() * (E::F::one() - flag[0].clone()));
        }
        let is_real = E::F::one() - is_padding[0].clone();
        let variant_sum = is_and[0].clone() + is_or[0].clone() + is_xor[0].clone()
            + is_and_inv[0].clone() + is_or_inv[0].clone() + is_xnor[0].clone();
        eval.add_constraint(is_real.clone() * (variant_sum.clone() - E::F::one()));
        eval.add_constraint(is_padding[0].clone() * variant_sum);

        // ── Per-op result-binding identities (mirroring CpuChip's old
        //    Phase 3 block) ──
        let f255 = E::F::from(BaseField::from(255));
        let f2 = E::F::from(BaseField::from(2u32));
        for i in 0..WORD_SIZE {
            let a = &val_b[i];
            let b = &val_d[i];
            let ar = &and_result[i];
            let r = &result[i];
            // op=0 (AND):     r = ar
            eval.add_constraint(is_and[0].clone() * (r.clone() - ar.clone()));
            // op=1 (OR):      r = a + b - ar
            eval.add_constraint(is_or[0].clone() * (r.clone() - a.clone() - b.clone() + ar.clone()));
            // op=2 (XOR):     r = a + b - 2*ar
            eval.add_constraint(is_xor[0].clone() * (r.clone() - a.clone() - b.clone() + f2.clone() * ar.clone()));
            // op=3 (AndInv):  r = a - ar
            eval.add_constraint(is_and_inv[0].clone() * (r.clone() - a.clone() + ar.clone()));
            // op=4 (OrInv):   r = 255 - b + ar
            eval.add_constraint(is_or_inv[0].clone() * (r.clone() - f255.clone() + b.clone() - ar.clone()));
            // op=5 (Xnor):    r = 255 - a - b + 2*ar
            eval.add_constraint(is_xnor[0].clone() * (r.clone() - f255.clone() + a.clone() + b.clone() - f2.clone() * ar.clone()));
        }

        // ── Bitwise AND nibble-level lookups (16 per real row) ──
        let sixteen: E::F = E::F::from(BaseField::from(16));
        for i in 0..WORD_SIZE {
            // High nibble: (val_b_hi[i], val_d_hi[i], and_result_hi[i])
            eval.add_to_relation(RelationEntry::new(
                bitwise_and_lookup,
                is_real.clone().into(),
                &[val_b_hi_nib[i].clone(), val_d_hi_nib[i].clone(), and_result_hi_nib[i].clone()],
            ));
            // Low nibble: lo = byte - hi*16
            let b_lo = val_b[i].clone() - val_b_hi_nib[i].clone() * sixteen.clone();
            let d_lo = val_d[i].clone() - val_d_hi_nib[i].clone() * sixteen.clone();
            let and_lo = and_result[i].clone() - and_result_hi_nib[i].clone() * sixteen.clone();
            eval.add_to_relation(RelationEntry::new(
                bitwise_and_lookup,
                is_real.clone().into(),
                &[b_lo, d_lo, and_lo],
            ));
        }

        // ── BitwiseLookup consumer ──
        // Tuple (30 limbs): val_b[8] + val_d[8] + result[8] + 6 sub-flags.
        let mut tuple: Vec<E::F> = Vec::with_capacity(30);
        tuple.extend_from_slice(&val_b);
        tuple.extend_from_slice(&val_d);
        tuple.extend_from_slice(&result);
        tuple.push(is_and[0].clone());
        tuple.push(is_or[0].clone());
        tuple.push(is_xor[0].clone());
        tuple.push(is_and_inv[0].clone());
        tuple.push(is_or_inv[0].clone());
        tuple.push(is_xnor[0].clone());

        // Two paired emissions to mirror CpuChip's producer side.
        for _ in 0..2 {
            eval.add_to_relation(RelationEntry::new(
                bitwise_lookup,
                (-is_real.clone()).into(),
                &tuple,
            ));
        }

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for BitwiseChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        let entries = &side_note.bitwise_entries;
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
            trace.fill_columns_bytes(row, &e.and_result, Column::AndResult);
            trace.fill_columns_bytes(row, &e.val_b_hi_nib, Column::ValBHiNib);
            trace.fill_columns_bytes(row, &e.val_d_hi_nib, Column::ValDHiNib);
            trace.fill_columns_bytes(row, &e.and_result_hi_nib, Column::AndResultHiNib);
            trace.fill_columns(row, e.is_and, Column::IsAnd);
            trace.fill_columns(row, e.is_or, Column::IsOr);
            trace.fill_columns(row, e.is_xor, Column::IsXor);
            trace.fill_columns(row, e.is_and_inv, Column::IsAndInv);
            trace.fill_columns(row, e.is_or_inv, Column::IsOrInv);
            trace.fill_columns(row, e.is_xnor, Column::IsXnor);
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

        let bitwise: &BitwiseLookupElements = lookup_elements.as_ref();
        let bitwise_and: &BitwiseAndLookupElements = lookup_elements.as_ref();
        let val_b = crate::trace::original_base_column!(component_trace, Column::ValB);
        let val_d = crate::trace::original_base_column!(component_trace, Column::ValD);
        let result = crate::trace::original_base_column!(component_trace, Column::Result);
        let and_result = crate::trace::original_base_column!(component_trace, Column::AndResult);
        let val_b_hi_nib = crate::trace::original_base_column!(component_trace, Column::ValBHiNib);
        let val_d_hi_nib = crate::trace::original_base_column!(component_trace, Column::ValDHiNib);
        let and_result_hi_nib = crate::trace::original_base_column!(component_trace, Column::AndResultHiNib);
        let is_and = crate::trace::original_base_column!(component_trace, Column::IsAnd);
        let is_or = crate::trace::original_base_column!(component_trace, Column::IsOr);
        let is_xor = crate::trace::original_base_column!(component_trace, Column::IsXor);
        let is_and_inv = crate::trace::original_base_column!(component_trace, Column::IsAndInv);
        let is_or_inv = crate::trace::original_base_column!(component_trace, Column::IsOrInv);
        let is_xnor = crate::trace::original_base_column!(component_trace, Column::IsXnor);
        let is_padding = crate::trace::original_base_column!(component_trace, Column::IsPadding);

        // ── Bitwise AND nibble-level lookups ──
        let sixteen = PackedBaseField::broadcast(BaseField::from(16));
        for i in 0..WORD_SIZE {
            let pad_c = is_padding[0].clone();
            // High nibble lookup
            logup.add_to_relation_with(
                bitwise_and,
                [pad_c.clone()],
                |[pad]| (PackedBaseField::one() - pad).into(),
                &[val_b_hi_nib[i].clone(), val_d_hi_nib[i].clone(), and_result_hi_nib[i].clone()],
            );
            // Low nibble lookup
            let val_b_col_i = val_b[i].clone();
            let val_d_col_i = val_d[i].clone();
            let and_result_col_i = and_result[i].clone();
            let val_b_hi_i = val_b_hi_nib[i].clone();
            let val_d_hi_i = val_d_hi_nib[i].clone();
            let and_hi_i = and_result_hi_nib[i].clone();
            logup.add_to_relation_computed(
                bitwise_and,
                [pad_c],
                |[pad]| (PackedBaseField::one() - pad).into(),
                3,
                move |vec_idx| {
                    let b_lo = val_b_col_i.at(vec_idx) - val_b_hi_i.at(vec_idx) * sixteen;
                    let d_lo = val_d_col_i.at(vec_idx) - val_d_hi_i.at(vec_idx) * sixteen;
                    let and_lo = and_result_col_i.at(vec_idx) - and_hi_i.at(vec_idx) * sixteen;
                    vec![b_lo, d_lo, and_lo]
                },
            );
        }

        // ── BitwiseLookup consumer ──
        let mut tuple: Vec<_> = val_b.to_vec();
        tuple.extend_from_slice(&val_d);
        tuple.extend_from_slice(&result);
        tuple.push(is_and[0].clone());
        tuple.push(is_or[0].clone());
        tuple.push(is_xor[0].clone());
        tuple.push(is_and_inv[0].clone());
        tuple.push(is_or_inv[0].clone());
        tuple.push(is_xnor[0].clone());

        for _ in 0..2 {
            logup.add_to_relation_with(
                bitwise,
                [is_padding[0].clone()],
                |[pad]| (-(PackedBaseField::one() - pad)).into(),
                &tuple,
            );
        }

        logup.finalize()
    }
}
