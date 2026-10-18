//! Diagnostics for a trace that fails to prove: per-component claimed sums
//! and the first failing constraint, whole or one component at a time.

use stwo::core::fields::qm31::SecureField;

use crate::lookups::AllLookupElements;
use crate::pcs::FsChannel;
use crate::side_note::SideNote;
use crate::trace::component::ComponentTrace;

/// Debug: print per-component claimed sums (logup) and check if they balance.
///
/// Gated behind the `debug-internals` feature — production builds
/// don't expose this.  Useful when adding a new constraint and the
/// regression sweep fails: per-component sums help distinguish
/// "ConstraintsNotSatisfied" (some chip writes a wrong column value)
/// from "claimed logup sum is not zero" (lookup imbalance — usually
/// a missing emission or wrong multiplicity).
///
/// Returns `true` iff the total logup sum is zero (the trace would pass the
/// verifier's "claimed logup sum is not zero" check). Callers that only want
/// the printout can ignore the result.
pub fn debug_claimed_sums(side_note: &mut SideNote) -> bool {
    use num_traits::Zero;
    let components = crate::BASE_COMPONENTS;
    // Aligned 1:1 with `BASE_COMPONENTS` (lib.rs). The previous list stopped
    // at 14 names AND skipped `RegMemClosing`, so every label from index 6 on
    // was wrong — fixed here so the per-component breakdown is trustworthy.
    let component_names = [
        "CpuChip",
        "Blake2b",
        "Blake2bBoundary",
        "MemoryChip",
        "MemoryPage",
        "MemoryMerkle",
        "MemoryRootBoundary",
        "RegMemory",
        "RegMemBoundary",
        "RegMemClosing",
        "ProgBoundary",
        "ProgMemory",
        "JumpTable",
        "WitnessInput",
        "Range256",
        "BitwiseLookup",
        "PowerOfTwo",
        "Popcount",
        "Bitcount",
        "ByteToBits",
        "Mul",
        "Bitwise",
        "Compare",
        "DivRem",
        "BitwiseAndByte",
    ];

    let traces: Vec<ComponentTrace> = components
        .iter()
        .map(|c| c.generate_component_trace(side_note))
        .collect();

    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut stwo::core::channel::Blake2sChannel::default();
    for c in components {
        c.draw_lookup_elements(&mut lookup_elements, channel.as_ref_channel());
    }

    let mut total = SecureField::zero();
    for (i, (c, trace)) in components.iter().zip(traces).enumerate() {
        let (_, claimed_sum) = c.generate_interaction_trace(trace, side_note, &lookup_elements);
        let name = component_names.get(i).unwrap_or(&"?");
        eprintln!("  {name:>15}: {claimed_sum:?}");
        total += claimed_sum;
    }
    eprintln!("  {:>15}: {total:?}", "total");
    let balances = total.is_zero();
    if balances {
        eprintln!("  Logup sums BALANCE (zero)");
    } else {
        eprintln!("  Logup sums DO NOT BALANCE");
    }
    balances
}

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
    let channel = &mut stwo::core::channel::Blake2sChannel::default();
    for c in components {
        c.draw_lookup_elements(&mut lookup_elements, channel.as_ref_channel());
    }

    for (i, (c, trace)) in components.iter().zip(traces.iter()).enumerate() {
        let (interaction_trace, claimed_sum) =
            c.generate_interaction_trace(trace.clone(), side_note, &lookup_elements);
        eprintln!("  [{i}] asserting constraints (claimed_sum={claimed_sum:?})…");
        c.debug_assert_constraints(trace, &interaction_trace, &lookup_elements, claimed_sum);
        eprintln!("  [{i}] all constraints OK");
    }
}
