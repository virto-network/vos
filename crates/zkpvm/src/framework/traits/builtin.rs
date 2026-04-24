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

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::{builder::FinalizedTrace, component::ComponentTrace, eval::TraceEval};

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

    /// Default: emits no preprocessed columns.  Chips that need a
    /// non-empty preprocessed trace (Blake2bChip, BitwiseLookupChip,
    /// PowerOfTwoChip, RangeMultiplicity256) override this.
    fn generate_preprocessed_trace(
        &self,
        _log_size: u32,
        _side_note: &SideNote,
    ) -> FinalizedTrace {
        FinalizedTrace::empty()
    }

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
