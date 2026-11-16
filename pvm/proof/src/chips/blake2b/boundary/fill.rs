//! The chip's trace generation, the prover's half.

use super::super::compression::{
    add_compression_interaction_core, build_compression_rows, fill_compression_trace,
    fill_schedule_preprocessed,
};
use super::*;
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};
use crate::{
    framework::BuiltInProverComponent,
    lookups::{AllLookupElements, LogupTraceBuilder},
    side_note::SideNote,
};
use stwo::{
    core::{ColumnVec, fields::m31::BaseField, fields::qm31::SecureField},
    prover::{
        backend::simd::SimdBackend,
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};

impl BuiltInProverComponent for Blake2bBoundaryChip {
    const IS_PRODUCER: bool = true;

    fn generate_preprocessed_trace(&self, log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        fill_schedule_preprocessed(&mut trace);
        let num_rows = trace.num_rows();
        for row in 0..num_rows {
            let gate = (row % 96 != 95) && (row != num_rows - 1);
            trace.fill_columns(row, gate, PreprocessedColumn::ContinuityGate);
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_min(
        &self,
        side_note: &mut SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        if side_note.merkle_blake2b_calls.is_empty() {
            // Canonical-shape: forced present-but-empty (all-padding).
            let log_size = stwo::prover::backend::simd::m31::LOG_N_LANES.max(min_log_size);
            return TraceBuilder::<BoundaryColumn>::new(log_size).finalize_bit_reversed();
        }
        // No memory-op binding: these compressions hash page images / node
        // pairs, not guest RAM — `BoundaryColumn` carries no address/pointer/
        // CallTs columns at all (main-chip-only width).
        let rows = build_compression_rows(&side_note.merkle_blake2b_calls, &[]);
        let num_rows = rows.len();
        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(num_rows).max(min_log_size);
        let mut trace = TraceBuilder::<BoundaryColumn>::new(log_size);
        fill_compression_trace(&mut trace, side_note, &rows);
        // Production multiplicity at each compression's row 95: the unique
        // compression's in-circuit consumption count (a hand-built side note
        // without mults defaults to one consumer per call).
        for k in 0..side_note.merkle_blake2b_calls.len() {
            let mult = side_note.merkle_blake2b_mults.get(k).copied().unwrap_or(1);
            trace.fill_columns(k * 96 + 95, BaseField::from(mult), BoundaryColumn::EmitMult);
        }
        trace.finalize_bit_reversed()
    }

    fn generate_interaction_trace(
        &self,
        component_trace: &ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let range256: &Range256LookupElements = lookup_elements.as_ref();
        let bitwise: &BitwiseAndByteLookupElements = lookup_elements.as_ref();
        add_compression_interaction_core::<PreprocessedColumn, BoundaryColumn>(
            &mut logup,
            component_trace,
            range256,
            bitwise,
        );

        // ── Blake2bCompression producer (mirror of add_constraints) ──
        let compression: &Blake2bCompressionLookupElements = lookup_elements.as_ref();
        let emit_mult =
            crate::trace::original_base_column!(component_trace, BoundaryColumn::EmitMult);
        let h_word_cols: [_; 8] = [
            crate::trace::original_base_column!(component_trace, BoundaryColumn::H0),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::H1),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::H2),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::H3),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::H4),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::H5),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::H6),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::H7),
        ];
        let m_word_cols: [_; 16] = [
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M0),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M1),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M2),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M3),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M4),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M5),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M6),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M7),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M8),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M9),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M10),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M11),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M12),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M13),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M14),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M15),
        ];
        let t_cols = crate::trace::original_base_column!(component_trace, BoundaryColumn::T);
        let f_col = crate::trace::original_base_column!(component_trace, BoundaryColumn::F);
        let output_cols =
            crate::trace::original_base_column!(component_trace, BoundaryColumn::Output);

        logup.add_to_relation_computed(
            compression,
            [emit_mult[0].clone()],
            |[m]| m.into(),
            265,
            move |v| {
                let mut t = Vec::with_capacity(265);
                for w in 0..8 {
                    for b in 0..8 {
                        t.push(h_word_cols[w][b].at(v));
                    }
                }
                for w in 0..16 {
                    for b in 0..8 {
                        t.push(m_word_cols[w][b].at(v));
                    }
                }
                for i in 0..8 {
                    t.push(t_cols[i].at(v));
                }
                t.push(f_col[0].at(v));
                for i in 0..64 {
                    t.push(output_cols[i].at(v));
                }
                t
            },
        );

        logup.finalize()
    }
}
