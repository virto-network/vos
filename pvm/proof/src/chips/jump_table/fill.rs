//! The chip's trace generation, the prover's half.

use super::pin::chip_log_size;
use super::*;
use crate::framework::BuiltInProverComponent;
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
use crate::side_note::SideNote;
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};
use stwo::core::fields::m31::BaseField;
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::SimdBackend,
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};

impl BuiltInProverComponent for JumpTableChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, log_size: u32, side_note: &SideNote) -> FinalizedTrace {
        self.preprocessed_trace(log_size, side_note)
    }

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let log_size = chip_log_size(side_note.jump_table.len()).max(min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        for row in 0..num_rows {
            // CpuChip emits 2 paired JumpInd lookups per step (so the
            // per-pair degree stays under 4 — same trick as
            // ProgramMemory).  Producer multiplicity matches.
            let count = side_note.jump_table_counts.get(row).copied().unwrap_or(0);
            trace.fill_columns(row, BaseField::from(2 * count), Column::Multiplicity);
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

        let jt: &JumpTableLookupElements = lookup_elements.as_ref();
        let addr =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Addr);
        let target =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Target);
        let mult = crate::trace::original_base_column!(component_trace, Column::Multiplicity);

        let mut tuple: Vec<_> = addr.to_vec();
        tuple.extend_from_slice(&target);

        logup.add_to_relation_with(jt, [mult[0].clone()], |[m]| (-m).into(), &tuple);

        logup.finalize()
    }
}
