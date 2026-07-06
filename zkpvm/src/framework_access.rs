//! Public access to framework types for the standalone verifier.
//!
//! This module re-exports the types and functions needed by `zkpvm-verifier`
//! without requiring the full `SideNote` / trace generation infrastructure.

#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use stwo::core::{air::Component, fields::qm31::SecureField, pcs::TreeVec};
use stwo_constraint_framework::TraceLocationAllocator;

pub use crate::lookups::{AllLookupElements, boundary_relation_challenges};
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

/// Re-evaluate one canonical chip's constraints through a caller-supplied
/// [`EvalAtRow`] — the recursion OODS-embed seam.
///
/// `BuiltInComponentEval` and the per-chip lookup-element tuples are
/// crate-private, so a chip's `add_constraints` can only be driven with an
/// arbitrary evaluator from inside the crate. The P5.2 verifier-AIR uses this to
/// walk each canonical component's own generic `evaluate` at the OODS point and
/// re-derive its composition contribution in-AIR. `chip_idx` is its index in
/// `BASE_COMPONENTS` (= [`crate::chip_idx`]); `lookup` must carry the same
/// relation elements the proof was produced under (draw them with
/// [`draw_all_lookup_elements`]).
pub fn drive_chip_oods<E: stwo_constraint_framework::EvalAtRow>(
    chip_idx: usize,
    log_size: u32,
    lookup: &AllLookupElements,
    eval: E,
) -> E {
    use crate::chips::*;
    use crate::framework::BuiltInComponent;
    use crate::framework::eval::BuiltInComponentEval;
    use crate::lookups::ComponentLookupElements;
    use stwo_constraint_framework::FrameworkEval;

    fn run<C: BuiltInComponent, E: stwo_constraint_framework::EvalAtRow>(
        chip: &C,
        log_size: u32,
        lookup: &AllLookupElements,
        eval: E,
    ) -> E {
        let ce = BuiltInComponentEval::<C> {
            component: chip,
            log_size,
            lookup_elements: <C as BuiltInComponent>::LookupElements::get(lookup),
        };
        FrameworkEval::evaluate(&ce, eval)
    }

    use crate::chip_idx as cx;
    match chip_idx {
        cx::CPU => run(&CpuChip, log_size, lookup, eval),
        cx::BLAKE2B => run(&Blake2bChip, log_size, lookup, eval),
        cx::BLAKE2B_BOUNDARY => run(&Blake2bBoundaryChip, log_size, lookup, eval),
        cx::MEMORY => run(&MemoryChip, log_size, lookup, eval),
        cx::MEMORY_PAGE => run(&MemoryPageChip, log_size, lookup, eval),
        cx::MEMORY_MERKLE => run(&MemoryMerkleChip, log_size, lookup, eval),
        cx::MEMORY_ROOT_BOUNDARY => run(&MemoryRootBoundaryChip, log_size, lookup, eval),
        cx::REGISTER_MEMORY => run(&RegisterMemoryChip, log_size, lookup, eval),
        cx::REGISTER_MEMORY_BOUNDARY => run(&RegisterMemoryBoundaryChip, log_size, lookup, eval),
        cx::REGISTER_MEMORY_CLOSING => run(&RegisterMemoryClosingChip, log_size, lookup, eval),
        cx::PROGRAM_BOUNDARY => run(&ProgramBoundaryChip, log_size, lookup, eval),
        cx::PROGRAM_MEMORY => run(&ProgramMemoryChip, log_size, lookup, eval),
        cx::JUMP_TABLE => run(&JumpTableChip, log_size, lookup, eval),
        cx::RANGE_MULTIPLICITY_256 => run(&RangeMultiplicity256, log_size, lookup, eval),
        cx::BITWISE_LOOKUP => run(&BitwiseLookupChip, log_size, lookup, eval),
        cx::POWER_OF_TWO => run(&PowerOfTwoChip, log_size, lookup, eval),
        cx::POPCOUNT => run(&PopcountChip, log_size, lookup, eval),
        cx::BITCOUNT => run(&BitcountChip, log_size, lookup, eval),
        cx::BYTE_TO_BITS => run(&ByteToBitsChip, log_size, lookup, eval),
        cx::MUL => run(&MulChip, log_size, lookup, eval),
        cx::BITWISE => run(&BitwiseChip, log_size, lookup, eval),
        cx::COMPARE => run(&CompareChip, log_size, lookup, eval),
        cx::DIVREM => run(&DivRemChip, log_size, lookup, eval),
        cx::RISTRETTO => run(&RistrettoChip, log_size, lookup, eval),
        cx::RISTRETTO_ECALL => run(&RistrettoEcallChip, log_size, lookup, eval),
        cx::RISTRETTO_COMB_TABLE => run(&RistrettoCombTableChip, log_size, lookup, eval),
        cx::RISTRETTO_FIXED_BASE_CONSUMER => {
            run(&RistrettoFixedBaseConsumerChip, log_size, lookup, eval)
        }
        cx::RISTRETTO_COMB_ANCHOR => run(&RistrettoCombAnchorChip, log_size, lookup, eval),
        cx::RISTRETTO_COMB_SCALAR_BOUNDARY => {
            run(&RistrettoCombScalarBoundaryChip, log_size, lookup, eval)
        }
        cx::RISTRETTO_COMB_COMPRESS => run(&RistrettoCombCompressChip, log_size, lookup, eval),
        cx::RISTRETTO_COMB_COMPRESS_OUTPUT => {
            run(&RistrettoCombCompressOutputChip, log_size, lookup, eval)
        }
        _ => panic!("drive_chip_oods: invalid chip_idx {chip_idx}"),
    }
}

/// [`drive_chip_oods`] for CpuChip (`chip_idx::CPU`).
pub fn drive_cpu_chip_oods<E: stwo_constraint_framework::EvalAtRow>(
    log_size: u32,
    lookup: &AllLookupElements,
    eval: E,
) -> E {
    drive_chip_oods(crate::chip_idx::CPU, log_size, lookup, eval)
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
