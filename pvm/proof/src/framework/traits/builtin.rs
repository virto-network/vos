use alloc::vec::Vec;

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

/// How a chip's fractions are finalized: in pairs, each pair one
/// interaction column (the default), or each fraction its own column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Logup {
    Pairs,
    Single,
}

impl Logup {
    /// The batch of each of `n` fractions, then of `extra` more joined to the
    /// last batch: what `finalize_logup_batched` takes. The extra fractions
    /// add no column, and their denominators being constant, no degree.
    pub fn batches(self, n: usize, extra: usize) -> Vec<usize> {
        let batch = |i: usize| match self {
            Self::Pairs => i / 2,
            Self::Single => i,
        };
        let last = n.checked_sub(1).map_or(0, batch);
        (0..n)
            .map(batch)
            .chain(core::iter::repeat_n(last, extra))
            .collect()
    }

    /// Finalizes `eval`'s fractions in this batching.
    pub fn finalize<E: EvalAtRow>(self, eval: &mut E) {
        match self {
            Self::Pairs => eval.finalize_logup_in_pairs(),
            Self::Single => eval.finalize_logup(),
        }
    }
}

/// Verifier-side surface of a chip: column types, constraint-degree bound,
/// lookup-element bag, and the constraint emitter.  Compiled both prover-
/// and verifier-side; in a no_std verifier build this is the only chip
/// trait that gets included.
pub trait BuiltInComponent {
    /// The constraints are evaluated on a domain `2^bound` times the
    /// trace's; their quotient by the trace domain's vanishing polynomial,
    /// of degree about `(d − 1)·N` for a constraint of degree `d`, must fit
    /// it. Bound 1 admits degree ≤ 3.
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 1;

    /// How [`add_constraints`](Self::add_constraints)' fractions are
    /// finalized, which the evaluation does after it.
    const LOGUP: Logup = Logup::Pairs;

    type PreprocessedColumn: PreprocessedAirColumn;
    type MainColumn: AirColumn;
    // `ComponentLookupElements` is `pub(crate)` (sealed); harmless when
    // `BuiltInComponent` itself stays `pub(crate)`-reachable, but the
    // chip-isolated prove harness re-exports `MachineComponent` through which
    // this bound becomes lexically reachable at `pub`.  Suppress the warning;
    // sealing remains effective since callers can't impl it.
    #[allow(private_bounds)]
    type LookupElements: ComponentLookupElements;

    /// The chip's constraints and fractions, the fractions left unfinalized
    /// ([`LOGUP`](Self::LOGUP)).
    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    );
}

/// Prover-side extension of `BuiltInComponent`: trace materialisation.
/// Behind the `prover` feature gate; the verifier never invokes these.
#[cfg(feature = "prover")]
pub trait BuiltInProverComponent: BuiltInComponent {
    /// Default: emits no preprocessed columns.  Chips that need a
    /// non-empty preprocessed trace (Blake2bChip, BitwiseLookupChip,
    /// PowerOfTwoChip, RangeMultiplicity256) override this.
    fn generate_preprocessed_trace(&self, _log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        FinalizedTrace::empty()
    }

    /// Whether this chip writes to `SideNote` during trace generation.
    /// Default `true` for safety. Pure consumers override to `false` and
    /// implement `generate_main_trace_immut_min`: `prove_on` runs producers
    /// sequentially and consumers in parallel.
    const IS_PRODUCER: bool = true;

    /// The main trace, padded to at least `min_log_size` rows
    /// (`TraceBuilder::new(natural.max(min_log_size))`); 0 gives its natural
    /// size. Every chip honours it: a fixed table repeats its entries with no
    /// multiplicity, a boundary or the program's code adds rows that make no
    /// claim (the masked segment pads every chip to its masking's floor), so
    /// a kernel's shape pins every log size; among them the canonical *forcing set*
    /// ([`chip_idx::FORCING`](crate::chip_idx::FORCING)), the variable
    /// preprocessed-bearing chips whose `log_size` the program commitment
    /// depends on. Padding rows are `is_real = 0` and inert, so a forced
    /// larger trace proves the identical statement; a forcing-set chip whose
    /// `generate_preprocessed_trace` re-derives its own `log_size` from
    /// `side_note` must switch to the passed (forced) `log_size` param so
    /// its preprocessed trace tracks the forced main height. Producers
    /// override this; the default forwards to the consumers'
    /// `generate_main_trace_immut_min`.
    fn generate_main_trace_min(
        &self,
        side_note: &mut SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        self.generate_main_trace_immut_min(side_note, min_log_size)
    }

    /// The main trace of a pure consumer (`IS_PRODUCER = false`), which reads
    /// `side_note` only; as [`generate_main_trace_min`]. Producers leave the
    /// default panic: `prove_on` never invokes this on them.
    ///
    /// [`generate_main_trace_min`]: Self::generate_main_trace_min
    fn generate_main_trace_immut_min(
        &self,
        _side_note: &SideNote,
        _min_log_size: u32,
    ) -> FinalizedTrace {
        unimplemented!("non-producer chip must override generate_main_trace_immut_min")
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
