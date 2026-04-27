//! Public access to framework types for the standalone verifier.
//!
//! This module re-exports the types and functions needed by `zkpvm-verifier`
//! without requiring the full `SideNote` / trace generation infrastructure.

#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use stwo::{
    core::{
        air::Component,
        channel::Blake2sChannel,
        fields::qm31::SecureField,
        pcs::TreeVec,
    },
};
use stwo_constraint_framework::TraceLocationAllocator;

pub use crate::lookups::AllLookupElements;

use crate::BASE_COMPONENTS;

/// Draw all lookup elements from the channel (same order as prover).
pub fn draw_all_lookup_elements(
    lookup_elements: &mut AllLookupElements,
    channel: &mut Blake2sChannel,
) {
    for c in BASE_COMPONENTS {
        c.draw_lookup_elements(lookup_elements, channel);
    }
}

/// Functions for creating verifier-side component structures.
pub mod create_verifier_components {
    use super::*;

    /// Get trace sizes and preprocessed sizes for all components.
    pub fn trace_and_preprocessed_sizes(
        log_sizes: &[u32],
    ) -> (Vec<TreeVec<Vec<u32>>>, Vec<u32>) {
        let components = BASE_COMPONENTS;
        let trace_sizes: Vec<TreeVec<Vec<u32>>> = components
            .iter()
            .zip(log_sizes)
            .map(|(c, &log_size)| c.trace_sizes(log_size))
            .collect();
        let preprocessed_sizes: Vec<u32> = components
            .iter()
            .zip(log_sizes)
            .flat_map(|(c, &log_size)| c.preprocessed_trace_sizes(log_size))
            .collect();
        (trace_sizes, preprocessed_sizes)
    }

    /// Create verifier components (Box<dyn Component>) from proof data.
    pub fn components<'a>(
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        log_sizes: &[u32],
        claimed_sums: &[SecureField],
    ) -> Vec<Box<dyn Component + 'a>> {
        BASE_COMPONENTS
            .iter()
            .zip(claimed_sums)
            .zip(log_sizes.iter())
            .map(|((comp, claimed_sum), &log_size)| {
                comp.to_component(tree_span_provider, lookup_elements, log_size, *claimed_sum)
            })
            .collect()
    }
}
