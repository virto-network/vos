use alloc::vec::Vec;

use stwo_constraint_framework::EvalAtRow;

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;

use crate::lookups::ComponentLookupElements;

/// How a chip's fractions are finalized: in pairs, each pair one
/// interaction column (the default), each fraction its own column, or of
/// `total` fractions the first `singles` each its own and the rest in
/// pairs (a chip whose first fractions' denominators are of degree 2, its
/// others' of degree 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Logup {
    Pairs,
    Single,
    SingleThenPairs { singles: usize, total: usize },
}

impl Logup {
    /// The batch of each of `n` fractions, then of `extra` more joined to the
    /// last batch: what `finalize_logup_batched` takes. The extra fractions
    /// add no column, and their denominators being constant, no degree. A
    /// chip has at least one fraction (`n > 0`): with none, the extra ones
    /// would make a batch of their own, a column the chip's interaction trace
    /// does not have.
    pub fn batches(self, n: usize, extra: usize) -> Vec<usize> {
        debug_assert!(n > 0, "a chip with no fraction");
        let batch = |i: usize| match self {
            Self::Pairs => i / 2,
            Self::Single => i,
            Self::SingleThenPairs { singles, .. } if i < singles => i,
            Self::SingleThenPairs { singles, .. } => singles + (i - singles) / 2,
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
            Self::SingleThenPairs { total, .. } => {
                eval.finalize_logup_batched(&self.batches(total, 0))
            }
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

    /// The chip's columns at a row, read from `eval`: every main column by
    /// default; a chip whose instance commits fewer reads the others as zero
    /// ([`TraceEval::with_columns`]).
    fn trace_eval<E: EvalAtRow>(
        &self,
        eval: &mut E,
    ) -> TraceEval<Self::PreprocessedColumn, Self::MainColumn, E> {
        TraceEval::new(eval)
    }

    /// The chip's constraints and fractions, the fractions left unfinalized
    /// ([`LOGUP`](Self::LOGUP)).
    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    );
}

#[cfg(feature = "prover")]
mod prover;
#[cfg(feature = "prover")]
pub use prover::BuiltInProverComponent;
