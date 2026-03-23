use serde::{Deserialize, Serialize};
use stwo::{
    core::{
        channel::{Blake2sChannel, Channel},
        fields::qm31::SecureField,
        pcs::PcsConfig,
        poly::circle::CanonicCoset,
        proof::StarkProof,
        vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
    },
    prover::{
        backend::simd::SimdBackend, poly::circle::PolyOps, CommitmentSchemeProver, ComponentProver,
        ProvingError,
    },
};
use stwo_constraint_framework::TraceLocationAllocator;

use zkpvm_trace::{
    component::ComponentTrace,
    eval::{ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX},
};

use super::BASE_COMPONENTS;
use crate::{lookups::AllLookupElements, side_note::SideNote};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub stark_proof: StarkProof<Blake2sMerkleHasher>,
    pub claimed_sums: Vec<SecureField>,
    pub log_sizes: Vec<u32>,
}

pub fn prove(side_note: &mut SideNote) -> Result<Proof, ProvingError> {
    let components = BASE_COMPONENTS;

    let traces: Vec<ComponentTrace> = components
        .iter()
        .map(|c| c.generate_component_trace(side_note))
        .collect();
    let log_sizes: Vec<u32> = traces.iter().map(ComponentTrace::log_size).collect();

    let max_constraint_log_degree_bound = components
        .iter()
        .zip(&log_sizes)
        .map(|(c, &log_size)| c.max_constraint_log_degree_bound(log_size))
        .max()
        .unwrap_or(0);

    let config = PcsConfig::default();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(max_constraint_log_degree_bound + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    let prover_channel = &mut Blake2sChannel::default();

    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);
    log_sizes.iter().for_each(|log_size| {
        prover_channel.mix_u64(*log_size as u64);
    });

    // Preprocessed trace.
    let mut tree_builder = commitment_scheme.tree_builder();
    for component_trace in &traces {
        tree_builder.extend_evals(component_trace.to_circle_evaluation(PREPROCESSED_TRACE_IDX));
    }
    tree_builder.commit(prover_channel);

    // Main trace.
    let mut tree_builder = commitment_scheme.tree_builder();
    for component_trace in &traces {
        tree_builder.extend_evals(component_trace.to_circle_evaluation(ORIGINAL_TRACE_IDX));
    }
    tree_builder.commit(prover_channel);

    let mut lookup_elements = AllLookupElements::default();
    components
        .iter()
        .for_each(|c| c.draw_lookup_elements(&mut lookup_elements, prover_channel));

    // Interaction trace.
    let mut tree_builder = commitment_scheme.tree_builder();
    let claimed_sums: Vec<SecureField> = components
        .iter()
        .zip(traces)
        .map(|(c, component_trace)| {
            let (interaction_trace, claimed_sum) =
                c.generate_interaction_trace(component_trace, side_note, &lookup_elements);
            tree_builder.extend_evals(interaction_trace);
            claimed_sum
        })
        .collect();
    prover_channel.mix_felts(&claimed_sums);
    tree_builder.commit(prover_channel);

    let tree_span_provider = &mut TraceLocationAllocator::default();
    let components: Vec<Box<dyn ComponentProver<SimdBackend>>> = components
        .iter()
        .zip(&log_sizes)
        .zip(&claimed_sums)
        .map(|((c, log_size), claimed_sum)| {
            c.to_component_prover(
                tree_span_provider,
                &lookup_elements,
                *log_size,
                *claimed_sum,
            )
        })
        .collect();
    let components_ref: Vec<&dyn ComponentProver<SimdBackend>> =
        components.iter().map(|c| &**c).collect();

    let proof = stwo::prover::prove::<SimdBackend, Blake2sMerkleChannel>(
        &components_ref,
        prover_channel,
        commitment_scheme,
    )?;

    Ok(Proof {
        stark_proof: proof,
        claimed_sums,
        log_sizes,
    })
}
