//! The chips' prover trait, `BuiltInProverComponent`: a chip's traces.

use super::*;
use crate::trace::{builder::FinalizedTrace, component::ComponentTrace};
use crate::{lookups::AllLookupElements, side_note::SideNote};
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

/// Prover-side extension of `BuiltInComponent`: trace materialisation.
/// Behind the `prover` feature gate; the verifier never invokes these.
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
    /// a kernel's shape pins every log size; among them those of the
    /// preprocessed-bearing chips whose rows a run varies, which a shape's
    /// class root depends on. Padding rows are `is_real = 0` and inert, so a forced
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
        component_trace: &ComponentTrace,
        side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    );
}
