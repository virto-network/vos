//! Diagnostics for a trace that fails to prove: the first failing
//! constraint, whole or one component at a time.

use crate::lookups::AllLookupElements;
use crate::pcs::FsChannel;
use crate::side_note::SideNote;
use crate::trace::component::ComponentTrace;

/// Debug: pinpoint the failing constraint when prove fails with
/// `ConstraintsNotSatisfied`.  Generates the same main + interaction trace
/// that `prove_with_explicit_components` would, then runs Stwo's
/// `AssertEvaluator` row-by-row and panics with `row #X, constraint #Y`
/// at the first mismatch.
pub fn debug_assert_constraints_explicit(
    side_note: &mut SideNote,
    components: &[&dyn crate::framework::MachineProverComponent],
) {
    let traces: Vec<ComponentTrace> = components
        .iter()
        .map(|c| c.generate_component_trace(side_note))
        .collect();

    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut stwo::core::channel::Blake2sM31Channel::default();
    for c in components {
        c.draw_lookup_elements(&mut lookup_elements, channel.as_ref_channel());
    }

    for (i, (c, trace)) in components.iter().zip(traces.iter()).enumerate() {
        let (interaction_trace, claimed_sum) =
            c.generate_interaction_trace(trace, side_note, &lookup_elements);
        eprintln!("  [{i}] asserting constraints (claimed_sum={claimed_sum:?})…");
        c.debug_assert_constraints(trace, &interaction_trace, &lookup_elements, claimed_sum);
        eprintln!("  [{i}] all constraints OK");
    }
}
