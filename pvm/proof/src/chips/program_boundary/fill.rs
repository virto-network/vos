//! The chip's trace generation, the prover's half.

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
        backend::simd::{SimdBackend, m31::LOG_N_LANES},
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};

impl BuiltInProverComponent for ProgramBoundaryChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let log_size = LOG_N_LANES.max(min_log_size); // one real row
        let mut trace = TraceBuilder::<Column>::new(log_size);

        if !side_note.steps.is_empty() {
            let first_step = &side_note.steps[0];
            let last_step = side_note.steps.last().unwrap();

            // Row 0: the boundary — matches first step's (ts, pc) and last step's (next_ts, next_pc)
            trace.fill_columns_bytes(0, &first_step.pc.to_le_bytes(), Column::InitialPc);
            trace.fill_columns(0, first_step.timestamp, Column::InitialTimestamp);
            trace.fill_columns_bytes(0, &last_step.next_pc.to_le_bytes(), Column::FinalNextPc);
            trace.fill_columns(0, last_step.timestamp + 1, Column::FinalNextTimestamp);
            trace.fill_columns(0, true, Column::IsReal);
        }
        // Remaining rows are padding (all zero, IsReal=0)

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

        let prog_exec: &ProgramExecutionLookupElements = lookup_elements.as_ref();
        let is_real = crate::trace::original_base_column!(component_trace, Column::IsReal);
        let init_ts =
            crate::trace::original_base_column!(component_trace, Column::InitialTimestamp);
        let init_pc = crate::trace::original_base_column!(component_trace, Column::InitialPc);
        let final_next_ts =
            crate::trace::original_base_column!(component_trace, Column::FinalNextTimestamp);
        let final_next_pc =
            crate::trace::original_base_column!(component_trace, Column::FinalNextPc);

        // Produce (initial_timestamp, initial_pc) — seeds step 0
        {
            let mut tuple: Vec<_> = init_ts.to_vec();
            tuple.extend_from_slice(&init_pc);
            logup.add_to_relation_with(prog_exec, [is_real[0].clone()], |[r]| r.into(), &tuple);
        }

        // Consume (final_next_timestamp, final_next_pc) — absorbs last step's output
        {
            let mut tuple: Vec<_> = final_next_ts.to_vec();
            tuple.extend_from_slice(&final_next_pc);
            logup.add_to_relation_with(prog_exec, [is_real[0].clone()], |[r]| (-r).into(), &tuple);
        }

        logup.finalize()
    }
}
