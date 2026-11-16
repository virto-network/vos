use crate::prelude::*;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;

use crate::{framework::BuiltInComponent, lookups::ProgramExecutionLookupElements};

/// ProgramBoundaryChip: closes the program execution lookup loop.
///
/// Produces (timestamp=0, pc=0) — the initial execution state.
/// Consumes (timestamp=N, pc=final_next_pc) — the final execution state.
///
/// This ensures that the CpuChip's step chain forms a valid sequence:
/// boundary→step0→step1→...→stepN-1→boundary.
#[derive(Clone, Copy)]
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
    }
}

#[cfg(feature = "prover")]
mod fill;
