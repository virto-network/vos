//! Public access to framework types for the standalone verifier.
//!
//! This module re-exports the types and functions needed by `vos-pvm-proof-verifier`
//! without requiring the full `SideNote` / trace generation infrastructure.

#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use stwo::core::{
    air::{Component, Components},
    circle::CirclePoint,
    fields::qm31::SecureField,
    pcs::{PcsConfig, TreeVec},
    proof::StarkProof,
    vcs_lifted::merkle_hasher::MerkleHasherLifted,
};

use crate::security::SecurityShape;
use stwo_constraint_framework::TraceLocationAllocator;

pub use crate::lookups::{AllLookupElements, RelationChallenges, boundary_relation_challenges};
use crate::pcs::FsChannel;

use crate::BASE_COMPONENTS;

/// Validate exact nested proof dimensions against a fully constructed set of
/// verifier components and its three trace-tree column log-size vectors, and
/// return the shape the proof's security counts are taken at. Shared verbatim
/// by the prover-enabled and standalone no_std verifiers.
pub fn preflight_component_dimensions<H: MerkleHasherLifted>(
    config: &PcsConfig,
    stark: &StarkProof<H>,
    components: &[&dyn Component],
    trace_log_sizes: &TreeVec<Vec<u32>>,
) -> Result<(crate::proof::ProofProtocolShape, SecurityShape), alloc::string::String> {
    let layout = air_layout(config, components, trace_log_sizes)?;
    let protocol = crate::proof::preflight_proof_dimensions(
        config,
        stark,
        &layout.log_sizes,
        &layout.samples,
        layout.composition_log_degree_bound,
    )?;
    Ok((protocol, layout.security_shape(components)))
}

/// The four trees' column log sizes and OODS sample counts an AIR commits,
/// and its composition degree.
pub struct AirLayout {
    pub log_sizes: Vec<Vec<u32>>,
    pub samples: Vec<Vec<usize>>,
    pub composition_log_degree_bound: u32,
    pub max_log_degree_bound: u32,
}

/// The layout of `components` under `config`.
pub fn air_layout(
    config: &PcsConfig,
    components: &[&dyn Component],
    trace_log_sizes: &TreeVec<Vec<u32>>,
) -> Result<AirLayout, alloc::string::String> {
    if trace_log_sizes.len() != 3 || trace_log_sizes[0].is_empty() || components.is_empty() {
        return Err("AIR trace layout must contain three non-empty component trees".into());
    }
    let aggregate = Components {
        components: components.to_vec(),
        n_preprocessed_columns: trace_log_sizes[0].len(),
    };
    let composition_log_degree_bound = aggregate.composition_log_degree_bound();
    let (_, max_log_degree_bound) =
        crate::proof::derive_protocol_degree_shape(config, composition_log_degree_bound)?;
    // Mask offsets, hence only these vector lengths, are independent of the
    // sampled OODS point. Use a fixed valid point and never touch proof data.
    let masks = aggregate.mask_points(
        CirclePoint::<SecureField>::get_point(1),
        max_log_degree_bound,
        false,
    );
    let mut samples: Vec<Vec<usize>> = masks
        .iter()
        .map(|columns| columns.iter().map(Vec::len).collect())
        .collect();
    samples.push(vec![1; 8]);
    let mut log_sizes = trace_log_sizes.0.clone();
    log_sizes.push(vec![max_log_degree_bound; 8]);
    Ok(AirLayout {
        log_sizes,
        samples,
        composition_log_degree_bound,
        max_log_degree_bound,
    })
}

impl AirLayout {
    /// The shape [`crate::security`] counts at.
    ///
    /// The logup fractions are bounded from the interaction tree: each QM31
    /// column, four of its base columns, finalizes at most two fractions a
    /// row (`finalize_logup_in_pairs`), so a base column of `2^l` rows holds
    /// at most `2^l / 2`.
    pub fn security_shape(&self, components: &[&dyn Component]) -> SecurityShape {
        let interaction = self.log_sizes.get(2).map(Vec::as_slice).unwrap_or(&[]);
        SecurityShape {
            log_degree_bound: self.max_log_degree_bound,
            log_trace_length: self.log_sizes[..3]
                .iter()
                .flatten()
                .copied()
                .max()
                .unwrap_or(0),
            log_composition_degree_bound: self.composition_log_degree_bound,
            sampled_values: self.samples.iter().flatten().map(|&n| n as u64).sum(),
            max_samples_per_column: self.samples.iter().flatten().copied().max().unwrap_or(0)
                as u64,
            constraints: components
                .iter()
                .map(|component| component.n_constraints() as u64)
                .sum(),
            logup_fractions: interaction
                .iter()
                .map(|&log_size| (1u64 << log_size) / 2)
                .fold(0u64, u64::saturating_add),
            relation_width: crate::lookups::MAX_RELATION_WIDTH as u64,
        }
    }
}

/// Select the active-chip indices from the proof's
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
    channel: &mut impl FsChannel,
    component_mask: u32,
) {
    let indices = active_indices_from_mask(component_mask);
    for &i in &indices {
        BASE_COMPONENTS[i].draw_lookup_elements(lookup_elements, channel.as_ref_channel());
    }
}

/// Re-evaluate one canonical chip's constraints through a caller-supplied
/// `EvalAtRow` — the recursion OODS-embed seam.
///
/// `BuiltInComponentEval` and the per-chip lookup-element tuples are
/// crate-private, so a chip's `add_constraints` can only be driven with an
/// arbitrary evaluator from inside the crate. The verifier-AIR uses this to
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
        cx::WITNESS_INPUT => run(&WitnessInputChip, log_size, lookup, eval),
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
        cx::BITWISE_AND_BYTE => run(&BitwiseAndByteChip, log_size, lookup, eval),
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

    /// Create verifier components (`Box<dyn Component>`) from proof data.
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
