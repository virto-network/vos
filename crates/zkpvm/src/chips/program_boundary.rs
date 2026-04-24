use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField},
        ColumnVec,
    },
    prover::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
};

use crate::{
    framework::BuiltInComponent,
    lookups::{AllLookupElements, LogupTraceBuilder, ProgramExecutionLookupElements},
    side_note::SideNote,
};

/// ProgramBoundaryChip: closes the program execution lookup loop.
///
/// Produces (timestamp=0, pc=0) — the initial execution state.
/// Consumes (timestamp=N, pc=final_next_pc) — the final execution state.
///
/// This ensures that the CpuChip's step chain forms a valid sequence:
/// boundary→step0→step1→...→stepN-1→boundary.
pub struct ProgramBoundaryChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Initial PC (4 limbs) — always 0 for PVM
    #[size = 4]
    InitialPc,
    /// Initial timestamp (8 limbs) — always 0
    #[size = 8]
    InitialTimestamp,
    /// Final next-PC (4 limbs) — the PC after the last instruction
    #[size = 4]
    FinalNextPc,
    /// Final next-timestamp (8 limbs) — num_steps
    #[size = 8]
    FinalNextTimestamp,
    /// 1 for the single real row, 0 for padding
    #[size = 1]
    IsReal,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "progbound"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for ProgramBoundaryChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = ProgramExecutionLookupElements;


    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let log_size = LOG_N_LANES; // minimum size, only 1 real row
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
        component_trace: ComponentTrace,
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
        let init_ts = crate::trace::original_base_column!(component_trace, Column::InitialTimestamp);
        let init_pc = crate::trace::original_base_column!(component_trace, Column::InitialPc);
        let final_next_ts = crate::trace::original_base_column!(component_trace, Column::FinalNextTimestamp);
        let final_next_pc = crate::trace::original_base_column!(component_trace, Column::FinalNextPc);

        // Produce (initial_timestamp, initial_pc) — seeds step 0
        {
            let mut tuple: Vec<_> = init_ts.to_vec();
            tuple.extend_from_slice(&init_pc);
            logup.add_to_relation_with(
                prog_exec,
                [is_real[0].clone()],
                |[r]| r.into(),
                &tuple,
            );
        }

        // Consume (final_next_timestamp, final_next_pc) — absorbs last step's output
        {
            let mut tuple: Vec<_> = final_next_ts.to_vec();
            tuple.extend_from_slice(&final_next_pc);
            logup.add_to_relation_with(
                prog_exec,
                [is_real[0].clone()],
                |[r]| (-r).into(),
                &tuple,
            );
        }

        logup.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &ProgramExecutionLookupElements,
    ) {
        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);
        let init_ts = crate::trace::trace_eval!(trace_eval, Column::InitialTimestamp);
        let init_pc = crate::trace::trace_eval!(trace_eval, Column::InitialPc);
        let final_next_ts = crate::trace::trace_eval!(trace_eval, Column::FinalNextTimestamp);
        let final_next_pc = crate::trace::trace_eval!(trace_eval, Column::FinalNextPc);

        // Produce (initial_timestamp, initial_pc)
        let mut produce_tuple: Vec<E::F> = init_ts.to_vec();
        produce_tuple.extend_from_slice(&init_pc);
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            is_real[0].clone().into(),
            &produce_tuple,
        ));

        // Consume (final_next_timestamp, final_next_pc)
        let mut consume_tuple: Vec<E::F> = final_next_ts.to_vec();
        consume_tuple.extend_from_slice(&final_next_pc);
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-is_real[0].clone()).into(),
            &consume_tuple,
        ));

        eval.finalize_logup_in_pairs();
    }
}
