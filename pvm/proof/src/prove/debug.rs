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

/// Memory-frugal variant of [`debug_assert_constraints_explicit`] for traces
/// too large to materialise every component trace at once (the explicit
/// version's `traces: Vec<ComponentTrace>` holds them all and OOMs on
/// multi-million-step actor traces).
///
/// Builds + asserts **one component at a time**, dropping each trace before
/// the next, so peak memory is the single largest chip's trace rather than
/// the sum across all chips. Mirrors `prove_impl_with_components`'s
/// producer/consumer split: the `is_producer()` chips run first
/// (sequentially — they mutate `side_note`'s lookup-multiplicity counts),
/// then the consumer chips read the now-complete counts via the immutable
/// trace-gen path. Per-chip `debug_assert_constraints` is self-contained (it
/// checks each chip's own constraints + logup against that chip's own
/// `claimed_sum`), so the cross-chip lookup balance isn't needed here — only
/// the per-chip constraint satisfaction, which is exactly what catches a
/// `ConstraintsNotSatisfied`.
pub fn debug_assert_constraints_streaming(
    side_note: &mut SideNote,
    components: &[&dyn crate::framework::MachineProverComponent],
) {
    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut stwo::core::channel::Blake2sChannel::default();
    for c in components {
        c.draw_lookup_elements(&mut lookup_elements, channel.as_ref_channel());
    }

    // Pass 1 — PRODUCERS (sequential, mutate counts → must complete before
    // any consumer trace is built).
    for (i, c) in components.iter().enumerate() {
        if !c.is_producer() {
            continue;
        }
        let trace = c.generate_component_trace(side_note);
        let (interaction_trace, claimed_sum) =
            c.generate_interaction_trace(trace.clone(), side_note, &lookup_elements);
        eprintln!("  [{i}] producer: asserting (claimed_sum={claimed_sum:?})…");
        c.debug_assert_constraints(&trace, &interaction_trace, &lookup_elements, claimed_sum);
        eprintln!("  [{i}] producer: OK");
    }

    // Pass 2 — CONSUMERS (read complete counts; no mutation).
    for (i, c) in components.iter().enumerate() {
        if c.is_producer() {
            continue;
        }
        let trace = c.generate_component_trace_immut(side_note);
        let (interaction_trace, claimed_sum) =
            c.generate_interaction_trace(trace.clone(), side_note, &lookup_elements);
        eprintln!("  [{i}] consumer: asserting (claimed_sum={claimed_sum:?})…");
        c.debug_assert_constraints(&trace, &interaction_trace, &lookup_elements, claimed_sum);
        eprintln!("  [{i}] consumer: OK");
    }
}

/// Memory-frugal variant of [`debug_claimed_sums`]: accumulate the GLOBAL
/// logup claimed-sum one component at a time (dropping each trace before the
/// next), so a multi-million-step trace whose component traces can't all be
/// materialised at once still gets a balance verdict. Mirrors
/// [`debug_assert_constraints_streaming`]'s producer-then-consumer ordering
/// (producers mutate the lookup-multiplicity counts the consumers read).
///
/// Returns `true` iff the total is zero — i.e. the trace would pass the
/// verifier's "claimed logup sum is not zero" check. Lets us answer "does the
/// FULL trace balance?" (→ a segment imbalance is a boundary artifact) vs.
/// "does it not?" (→ a real per-chip bug in some region) without OOM.
pub fn debug_claimed_sums_streaming(
    side_note: &mut SideNote,
    components: &[&dyn crate::framework::MachineProverComponent],
) -> bool {
    use num_traits::Zero;
    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut stwo::core::channel::Blake2sChannel::default();
    for c in components {
        c.draw_lookup_elements(&mut lookup_elements, channel.as_ref_channel());
    }

    let mut total = SecureField::zero();
    // Pass 1 — PRODUCERS (sequential, mutate counts → must complete before
    // any consumer trace is built).
    for (i, c) in components.iter().enumerate() {
        if !c.is_producer() {
            continue;
        }
        let trace = c.generate_component_trace(side_note);
        let (_it, claimed_sum) = c.generate_interaction_trace(trace, side_note, &lookup_elements);
        eprintln!("  [{i}] producer: claimed_sum={claimed_sum:?}");
        total += claimed_sum;
    }
    // Pass 2 — CONSUMERS (read complete counts; no mutation).
    for (i, c) in components.iter().enumerate() {
        if c.is_producer() {
            continue;
        }
        let trace = c.generate_component_trace_immut(side_note);
        let (_it, claimed_sum) = c.generate_interaction_trace(trace, side_note, &lookup_elements);
        eprintln!("  [{i}] consumer: claimed_sum={claimed_sum:?}");
        total += claimed_sum;
    }
    eprintln!("  total: {total:?}");
    let balances = total.is_zero();
    eprintln!(
        "  full-trace logup {}",
        if balances {
            "BALANCES (zero)"
        } else {
            "DOES NOT BALANCE"
        }
    );
    balances
}
