use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField},
        ColumnVec,
    },
    prover::{
        backend::simd::SimdBackend,
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::EvalAtRow;

use zkpvm_air_column::{AirColumn, PreprocessedAirColumn};
use zkpvm_trace::{builder::FinalizedTrace, component::ComponentTrace, eval::TraceEval};

use crate::{
    lookups::{AllLookupElements, ComponentLookupElements},
    side_note::SideNote,
};

pub trait BuiltInComponent {
    /// Logarithmic bound for the maximum constraint degree.
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 1;

    type PreprocessedColumn: PreprocessedAirColumn;
    type MainColumn: AirColumn;
    type LookupElements: ComponentLookupElements;

    fn generate_preprocessed_trace(
        &self,
        log_size: u32,
        side_note: &SideNote,
    ) -> FinalizedTrace;

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace;

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    );

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    );
}
