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

/// Phase 60: BASE_COMPONENTS index of Blake2bChip — the only conditional
/// chip today.  Mirrors `lib.rs::active_components`.
const BLAKE2B_IDX: usize = 1;

/// Phase 60: infer the active-component selection from the proof's
/// `claimed_log_sizes` length.  Used by the standalone verifier where
/// SideNote isn't available.
///
/// - `len == BASE_COMPONENTS.len()`: all chips active (legacy / hash workloads).
/// - `len == BASE_COMPONENTS.len() - 1`: Blake2bChip skipped (Add-only / no-hash workloads).
/// - other: malformed proof.
fn active_indices(num_in_proof: usize) -> Result<alloc::vec::Vec<usize>, &'static str> {
    let n = BASE_COMPONENTS.len();
    if num_in_proof == n {
        Ok((0..n).collect())
    } else if num_in_proof == n - 1 {
        Ok((0..n).filter(|&i| i != BLAKE2B_IDX).collect())
    } else {
        Err("proof component count doesn't match any known active set")
    }
}

/// Draw all lookup elements from the channel (same order as prover).
/// `num_components` is the active count from `proof.claimed_log_sizes.len()`.
pub fn draw_all_lookup_elements(
    lookup_elements: &mut AllLookupElements,
    channel: &mut Blake2sChannel,
    num_components: usize,
) {
    let indices = active_indices(num_components)
        .expect("proof's component count doesn't match any known set; verifier rejects");
    for &i in &indices {
        BASE_COMPONENTS[i].draw_lookup_elements(lookup_elements, channel);
    }
}

/// Functions for creating verifier-side component structures.
pub mod create_verifier_components {
    use super::*;

    /// Get trace sizes and preprocessed sizes for all components.
    /// `log_sizes.len()` determines which chips were active; mirrors Phase 60
    /// dynamic component selection.
    pub fn trace_and_preprocessed_sizes(
        log_sizes: &[u32],
    ) -> (Vec<TreeVec<Vec<u32>>>, Vec<u32>) {
        let indices = active_indices(log_sizes.len())
            .expect("proof's component count doesn't match any known set");
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
    /// Active-chip selection inferred from `log_sizes.len()`.
    pub fn components<'a>(
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        log_sizes: &[u32],
        claimed_sums: &[SecureField],
    ) -> Vec<Box<dyn Component + 'a>> {
        let indices = active_indices(log_sizes.len())
            .expect("proof's component count doesn't match any known set");
        indices
            .iter()
            .zip(claimed_sums)
            .zip(log_sizes.iter())
            .map(|((&i, claimed_sum), &log_size)| {
                BASE_COMPONENTS[i].to_component(tree_span_provider, lookup_elements, log_size, *claimed_sum)
            })
            .collect()
    }
}
