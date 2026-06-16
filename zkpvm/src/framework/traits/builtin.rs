use stwo_constraint_framework::EvalAtRow;

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;

use crate::lookups::ComponentLookupElements;

#[cfg(feature = "prover")]
use crate::trace::{builder::FinalizedTrace, component::ComponentTrace};
#[cfg(feature = "prover")]
use crate::{lookups::AllLookupElements, side_note::SideNote};
#[cfg(feature = "prover")]
use stwo::{
    core::{
        ColumnVec,
        fields::{m31::BaseField, qm31::SecureField},
    },
    prover::{
        backend::simd::SimdBackend,
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};

/// Verifier-side surface of a chip: column types, constraint-degree bound,
/// lookup-element bag, and the constraint emitter.  Compiled both prover-
/// and verifier-side; in a no_std verifier build this is the only chip
/// trait that gets included.
pub trait BuiltInComponent {
    /// Logarithmic bound for the maximum constraint degree.
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 1;

    type PreprocessedColumn: PreprocessedAirColumn;
    type MainColumn: AirColumn;
    // `ComponentLookupElements` is `pub(crate)` (sealed); harmless when
    // `BuiltInComponent` itself stays `pub(crate)`-reachable, but the
    // Phase I.0 harness re-exports `MachineComponent` through which this
    // bound becomes lexically reachable at `pub`.  Suppress the warning;
    // sealing remains effective since callers can't impl it.
    #[allow(private_bounds)]
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
    fn generate_preprocessed_trace(&self, _log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        FinalizedTrace::empty()
    }

    /// Whether this chip writes to `SideNote` during trace generation.
    /// Default `true` for safety.  Pure consumers override to `false` and
    /// implement `generate_main_trace_immut` instead of (or in addition
    /// to) `generate_main_trace` — `prove_impl_with_components` runs
    /// producers sequentially and consumers in parallel.
    const IS_PRODUCER: bool = true;

    /// Producers (default `IS_PRODUCER = true`) override this.  Consumers
    /// can either override this directly or override
    /// `generate_main_trace_immut` and let the default forward.
    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        // Default: forward to immut path.  Producers MUST override.
        self.generate_main_trace_immut(side_note)
    }

    /// Pure consumers (`IS_PRODUCER = false`) override this; the default
    /// `generate_main_trace` forwards here.  Producers leave the default
    /// panic — `prove_impl_with_components` never invokes this on
    /// producer chips.
    fn generate_main_trace_immut(&self, _side_note: &SideNote) -> FinalizedTrace {
        unimplemented!("non-producer chip must override generate_main_trace_immut")
    }

    /// Canonical-shape proving (federation wire-through W0): like
    /// `generate_main_trace`, but pads the main trace to at least
    /// `min_log_size` rows (`TraceBuilder::new(natural.max(min_log_size))`)
    /// so the program commitment is witness-independent.  The default
    /// ignores the floor (natural size); only the canonical *forcing set* —
    /// the variable preprocessed-bearing chips whose `log_size` must be
    /// pinned for ONE stable commitment across a heterogeneous segment
    /// chain — override it.  Padding rows are `is_real = 0` and inert, so a
    /// forced larger trace proves the identical statement; a forcing-set
    /// chip whose `generate_preprocessed_trace` re-derives its own
    /// `log_size` from `side_note` must switch to the passed (forced)
    /// `log_size` param so its preprocessed trace tracks the forced main
    /// height.  Producers override this; consumers override
    /// `generate_main_trace_immut_min`.
    fn generate_main_trace_min(
        &self,
        side_note: &mut SideNote,
        _min_log_size: u32,
    ) -> FinalizedTrace {
        self.generate_main_trace(side_note)
    }

    /// Consumer counterpart of [`generate_main_trace_min`] (see
    /// `generate_main_trace_immut`).
    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        _min_log_size: u32,
    ) -> FinalizedTrace {
        self.generate_main_trace_immut(side_note)
    }

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
