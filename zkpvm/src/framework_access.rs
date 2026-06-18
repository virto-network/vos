//! Public access to framework types for the standalone verifier.
//!
//! This module re-exports the types and functions needed by `zkpvm-verifier`
//! without requiring the full `SideNote` / trace generation infrastructure.

#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use stwo::core::{air::Component, fields::qm31::SecureField, pcs::TreeVec};
use stwo_constraint_framework::TraceLocationAllocator;

pub use crate::lookups::AllLookupElements;
use crate::recursion_pcs::ProverChannel;

use crate::BASE_COMPONENTS;

/// Phase 60: select the active-chip indices from the proof's
/// `component_mask`.  Bit i set ⇔ chip i was active.
///
/// Back-compat: `mask == 0` (default for older proofs) falls back to
/// "all chips active" — older proofs predate dynamic selection.
fn active_indices_from_mask(mask: u32) -> alloc::vec::Vec<usize> {
    let n = BASE_COMPONENTS.len();
    if mask == 0 {
        (0..n).collect()
    } else {
        (0..n).filter(|&i| mask & (1 << i) != 0).collect()
    }
}

/// Draw all lookup elements from the channel (same order as prover).
pub fn draw_all_lookup_elements(
    lookup_elements: &mut AllLookupElements,
    channel: &mut ProverChannel,
    component_mask: u32,
) {
    let indices = active_indices_from_mask(component_mask);
    for &i in &indices {
        BASE_COMPONENTS[i].draw_lookup_elements(lookup_elements, channel);
    }
}

/// Re-evaluate CpuChip's constraints through a caller-supplied [`EvalAtRow`] —
/// the recursion OODS-embed seam.
///
/// `BuiltInComponentEval` and the per-chip lookup-element tuples are
/// crate-private, so a chip's `add_constraints` can only be driven with an
/// arbitrary evaluator from inside the crate. The P5.2 verifier-AIR uses this to
/// walk CpuChip's own generic `evaluate` at the OODS point and re-derive its
/// composition contribution in-AIR (CpuChip is the heaviest of the 31 canonical
/// components: 187 `add_constraint` + 45 `add_to_relation`). `lookup` must carry
/// the same relation elements the proof was produced under (draw them with
/// [`draw_all_lookup_elements`]).
pub fn drive_cpu_chip_oods<E: stwo_constraint_framework::EvalAtRow>(
    log_size: u32,
    lookup: &AllLookupElements,
    eval: E,
) -> E {
    use crate::chips::CpuChip;
    use crate::framework::BuiltInComponent;
    use crate::framework::eval::BuiltInComponentEval;
    use crate::lookups::ComponentLookupElements;
    use stwo_constraint_framework::FrameworkEval;

    let cpu = CpuChip;
    let ce = BuiltInComponentEval::<CpuChip> {
        component: &cpu,
        log_size,
        lookup_elements: <CpuChip as BuiltInComponent>::LookupElements::get(lookup),
    };
    ce.evaluate(eval)
}

/// Functions for creating verifier-side component structures.
pub mod create_verifier_components {
    use super::*;

    /// Get trace sizes and preprocessed sizes for active components.
    pub fn trace_and_preprocessed_sizes(
        log_sizes: &[u32],
        component_mask: u32,
    ) -> (Vec<TreeVec<Vec<u32>>>, Vec<u32>) {
        let indices = active_indices_from_mask(component_mask);
        let trace_sizes: Vec<TreeVec<Vec<u32>>> = indices
            .iter()
            .zip(log_sizes)
            .map(|(&i, &log_size)| BASE_COMPONENTS[i].trace_sizes(log_size))
            .collect();
        let preprocessed_sizes: Vec<u32> = indices
            .iter()
            .zip(log_sizes)
            .flat_map(|(&i, &log_size)| BASE_COMPONENTS[i].preprocessed_trace_sizes(log_size))
            .collect();
        (trace_sizes, preprocessed_sizes)
    }

    /// Create verifier components (Box<dyn Component>) from proof data.
    pub fn components<'a>(
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        log_sizes: &[u32],
        claimed_sums: &[SecureField],
        component_mask: u32,
    ) -> Vec<Box<dyn Component + 'a>> {
        let indices = active_indices_from_mask(component_mask);
        indices
            .iter()
            .zip(claimed_sums)
            .zip(log_sizes.iter())
            .map(|((&i, claimed_sum), &log_size)| {
                BASE_COMPONENTS[i].to_component(
                    tree_span_provider,
                    lookup_elements,
                    log_size,
                    *claimed_sum,
                )
            })
            .collect()
    }
}
