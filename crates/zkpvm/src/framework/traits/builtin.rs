use stwo_constraint_framework::EvalAtRow;

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;

use crate::lookups::ComponentLookupElements;

#[cfg(feature = "prover")]
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
#[cfg(feature = "prover")]
use crate::trace::{builder::FinalizedTrace, component::ComponentTrace};
#[cfg(feature = "prover")]
use crate::{lookups::AllLookupElements, side_note::SideNote};

/// Verifier-side surface of a chip: column types, constraint-degree bound,
/// lookup-element bag, and the constraint emitter.  Compiled both prover-
/// and verifier-side; in a no_std verifier build this is the only chip
/// trait that gets included.
pub trait BuiltInComponent {
    /// Logarithmic bound for the maximum constraint degree.
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 1;

    type PreprocessedColumn: PreprocessedAirColumn;
    type MainColumn: AirColumn;
    type LookupElements: ComponentLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    );
}

/// Prover-side extension of `BuiltInComponent`: trace materialisation.
/// Behind the `prover` feature gate (11b); the verifier never invokes these.
#[cfg(feature = "prover")]
pub trait BuiltInProverComponent: BuiltInComponent {
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
}
