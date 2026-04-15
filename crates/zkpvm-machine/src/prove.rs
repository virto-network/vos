use serde::{Deserialize, Serialize};
use stwo::{
    core::{
        channel::{Blake2sChannel, Channel},
        fields::qm31::SecureField,
        fri::FriConfig,
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
    pub num_components: usize,
    pub pcs_config: PcsConfig,
}

/// Timing breakdown of the proving pipeline.
#[derive(Clone, Debug)]
pub struct ProveProfile {
    pub trace_gen: std::time::Duration,
    pub preprocess_commit: std::time::Duration,
    pub main_commit: std::time::Duration,
    pub interaction_gen: std::time::Duration,
    pub interaction_commit: std::time::Duration,
    pub stark_prove: std::time::Duration,
    pub log_sizes: Vec<u32>,
    pub total_main_columns: usize,
    pub total_interaction_columns: usize,
}

impl std::fmt::Display for ProveProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total = self.trace_gen + self.preprocess_commit + self.main_commit
            + self.interaction_gen + self.interaction_commit + self.stark_prove;
        writeln!(f, "  trace_gen:          {:>10.2?}  ({:.0}%)", self.trace_gen, pct(self.trace_gen, total))?;
        writeln!(f, "  preprocess_commit:  {:>10.2?}  ({:.0}%)", self.preprocess_commit, pct(self.preprocess_commit, total))?;
        writeln!(f, "  main_commit:        {:>10.2?}  ({:.0}%)", self.main_commit, pct(self.main_commit, total))?;
        writeln!(f, "  interaction_gen:    {:>10.2?}  ({:.0}%)", self.interaction_gen, pct(self.interaction_gen, total))?;
        writeln!(f, "  interaction_commit: {:>10.2?}  ({:.0}%)", self.interaction_commit, pct(self.interaction_commit, total))?;
        writeln!(f, "  stark_prove (FRI):  {:>10.2?}  ({:.0}%)", self.stark_prove, pct(self.stark_prove, total))?;
        writeln!(f, "  total:              {:>10.2?}", total)?;
        writeln!(f, "  log_sizes: {:?}", self.log_sizes)?;
        writeln!(f, "  main_cols: {}, interaction_cols: {}", self.total_main_columns, self.total_interaction_columns)?;
        Ok(())
    }
}

fn pct(part: std::time::Duration, total: std::time::Duration) -> f64 {
    100.0 * part.as_secs_f64() / total.as_secs_f64()
}

/// 96-bit security: blowup=16, 19 FRI queries, 20-bit PoW.
pub fn production_pcs_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 20,
        fri_config: FriConfig::new(0, 4, 19),
    }
}

pub fn prove(side_note: &mut SideNote) -> Result<Proof, ProvingError> {
    let (proof, _) = prove_impl(side_note, production_pcs_config(), false)?;
    Ok(proof)
}

pub fn prove_with_config(side_note: &mut SideNote, config: PcsConfig) -> Result<Proof, ProvingError> {
    let (proof, _) = prove_impl(side_note, config, false)?;
    Ok(proof)
}

pub fn prove_profiled(side_note: &mut SideNote) -> Result<(Proof, ProveProfile), ProvingError> {
    prove_impl(side_note, production_pcs_config(), true)
}

pub fn prove_profiled_with_config(side_note: &mut SideNote, config: PcsConfig) -> Result<(Proof, ProveProfile), ProvingError> {
    prove_impl(side_note, config, true)
}

fn prove_impl(side_note: &mut SideNote, config: PcsConfig, profile: bool) -> Result<(Proof, ProveProfile), ProvingError> {
    use std::time::Instant;
    let components = BASE_COMPONENTS;

    let t = Instant::now();
    let traces: Vec<ComponentTrace> = components
        .iter()
        .map(|c| c.generate_component_trace(side_note))
        .collect();
    let log_sizes: Vec<u32> = traces.iter().map(ComponentTrace::log_size).collect();
    let trace_gen = t.elapsed();

    let max_constraint_log_degree_bound = components
        .iter()
        .zip(&log_sizes)
        .map(|(c, &log_size)| c.max_constraint_log_degree_bound(log_size))
        .max()
        .unwrap_or(0);

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
    let t = Instant::now();
    let mut tree_builder = commitment_scheme.tree_builder();
    for component_trace in &traces {
        tree_builder.extend_evals(component_trace.to_circle_evaluation(PREPROCESSED_TRACE_IDX));
    }
    tree_builder.commit(prover_channel);
    let preprocess_commit = t.elapsed();

    // Main trace.
    let t = Instant::now();
    let mut tree_builder = commitment_scheme.tree_builder();
    let mut total_main_columns = 0;
    for component_trace in &traces {
        let evals = component_trace.to_circle_evaluation(ORIGINAL_TRACE_IDX);
        total_main_columns += evals.len();
        tree_builder.extend_evals(evals);
    }
    tree_builder.commit(prover_channel);
    let main_commit = t.elapsed();

    let mut lookup_elements = AllLookupElements::default();
    components
        .iter()
        .for_each(|c| c.draw_lookup_elements(&mut lookup_elements, prover_channel));

    // Interaction trace.
    let t = Instant::now();
    let mut tree_builder = commitment_scheme.tree_builder();
    let mut total_interaction_columns = 0;
    let claimed_sums: Vec<SecureField> = components
        .iter()
        .zip(traces)
        .map(|(c, component_trace)| {
            let (interaction_trace, claimed_sum) =
                c.generate_interaction_trace(component_trace, side_note, &lookup_elements);
            total_interaction_columns += interaction_trace.len();
            tree_builder.extend_evals(interaction_trace);
            claimed_sum
        })
        .collect();
    let interaction_gen = t.elapsed();

    let t = Instant::now();
    prover_channel.mix_felts(&claimed_sums);
    tree_builder.commit(prover_channel);
    let interaction_commit = t.elapsed();

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

    let t = Instant::now();
    let proof = stwo::prover::prove::<SimdBackend, Blake2sMerkleChannel>(
        &components_ref,
        prover_channel,
        commitment_scheme,
    )?;
    let stark_prove = t.elapsed();

    let num_components = BASE_COMPONENTS.len();
    let prof = ProveProfile {
        trace_gen, preprocess_commit, main_commit,
        interaction_gen, interaction_commit, stark_prove,
        log_sizes: log_sizes.clone(),
        total_main_columns, total_interaction_columns,
    };

    if profile {
        eprintln!("{prof}");
    }

    Ok((Proof {
        stark_proof: proof,
        claimed_sums,
        num_components,
        log_sizes,
        pcs_config: config,
    }, prof))
}
