use num_traits::Zero;
use stwo::{
    core::{
        air::Component,
        channel::{Blake2sChannel, Channel},
        fields::qm31::SecureField,
        pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec},
        poly::circle::CanonicCoset,
        vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
        verifier::VerificationError,
    },
    prover::{
        backend::simd::SimdBackend, poly::circle::PolyOps, CommitmentSchemeProver,
    },
};
use stwo_constraint_framework::TraceLocationAllocator;

use crate::trace::eval::{INTERACTION_TRACE_IDX, ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX};

use super::Proof;
use crate::{lookups::AllLookupElements, side_note::SideNote};

/// Verify a chain of segment proofs. Each segment's final state must match
/// the next segment's initial state. Each segment is verified independently.
pub fn verify_chain(proofs: &[Proof], side_notes: &[&SideNote]) -> Result<(), VerificationError> {
    if proofs.len() != side_notes.len() {
        return Err(VerificationError::InvalidStructure(
            "proofs and side_notes length mismatch".to_string(),
        ));
    }
    // Check segment continuity
    for window in proofs.windows(2) {
        if window[0].final_state != window[1].initial_state {
            return Err(VerificationError::InvalidStructure(
                format!("segment chain broken: final state at ts={} doesn't match next initial at ts={}",
                    window[0].final_state.timestamp, window[1].initial_state.timestamp),
            ));
        }
    }
    // Verify each segment independently
    for (proof, side_note) in proofs.iter().zip(side_notes) {
        verify(proof.clone(), side_note)?;
    }
    Ok(())
}

/// Default per-component log_size cap used by `verify`.  See
/// `zkpvm_verifier::DEFAULT_MAX_LOG_SIZE` for the rationale; same value
/// kept in sync deliberately so prover-side and verifier-only paths
/// reject at the same threshold.
pub const DEFAULT_MAX_LOG_SIZE: u32 = 24;

pub fn verify(proof: Proof, side_note: &SideNote) -> Result<(), VerificationError> {
    verify_with_options(
        proof,
        side_note,
        DEFAULT_MAX_LOG_SIZE,
        &crate::proof::PcsPolicy::STANDARD,
    )
}

/// Caller-supplied per-component `log_size` cap variant of `verify`.
/// See `verify` for the default and `Phase 43` for the rationale.
pub fn verify_with_max_log_size(
    proof: Proof,
    side_note: &SideNote,
    max_log_size: u32,
) -> Result<(), VerificationError> {
    verify_with_options(proof, side_note, max_log_size, &crate::proof::PcsPolicy::STANDARD)
}

/// Phase 49: enforce a custom `PcsPolicy` (FRI shape + PoW floor)
/// on `proof.pcs_config`.  Most deployers want `PcsPolicy::STANDARD`;
/// override for stricter (more security) or looser (test harness)
/// floors.  See SECURITY.md "Proof shape".
pub fn verify_with_pcs_policy(
    proof: Proof,
    side_note: &SideNote,
    policy: &crate::proof::PcsPolicy,
) -> Result<(), VerificationError> {
    verify_with_options(proof, side_note, DEFAULT_MAX_LOG_SIZE, policy)
}

/// Both knobs at once.
pub fn verify_with_options(
    proof: Proof,
    side_note: &SideNote,
    max_log_size: u32,
    policy: &crate::proof::PcsPolicy,
) -> Result<(), VerificationError> {
    // Phase 60: select active components from side_note (same predicate
    // the prover used).  See `active_components_verifier` doc-comment.
    let components_owned = super::active_components_verifier(side_note);
    let components: &[&dyn crate::framework::MachineComponent] = &components_owned;
    // Phase 42: reject proofs from a different AIR shape early, before
    // any cryptographic work.  `format_version` is bumped whenever the
    // chip list / column counts / lookup-tuple shape changes in a way
    // that would make an older verifier silently accept the wrong thing.
    if proof.format_version != crate::proof::PROOF_FORMAT_VERSION {
        return Err(VerificationError::InvalidStructure(format!(
            "proof format version mismatch: verifier expects {}, proof has {}",
            crate::proof::PROOF_FORMAT_VERSION,
            proof.format_version,
        )));
    }
    // Phase 43: cap log_sizes so a malicious prover can't force a
    // giant Merkle commitment phase.
    if let Some(&offending) = proof.log_sizes.iter().find(|&&ls| ls > max_log_size) {
        return Err(VerificationError::InvalidStructure(format!(
            "proof log_size {offending} exceeds cap {max_log_size}"
        )));
    }
    // Phase 49: enforce the PcsPolicy floor — reject under-spec'd
    // pcs_configs before any cryptographic work.  Default policy is
    // PcsPolicy::STANDARD.
    if let Err(msg) = crate::proof::check_pcs_policy(&proof.pcs_config, policy) {
        return Err(VerificationError::InvalidStructure(msg));
    }
    let Proof {
        stark_proof: proof,
        claimed_sums,
        log_sizes: claimed_log_sizes,
        pcs_config: config,
        ..
    } = proof;

    if claimed_sums.len() != components.len() {
        return Err(VerificationError::InvalidStructure(
            "claimed sums len mismatch".to_string(),
        ));
    }
    if claimed_log_sizes.len() != components.len() {
        return Err(VerificationError::InvalidStructure(
            "log sizes len mismatch".to_string(),
        ));
    }
    let verifier_channel = &mut Blake2sChannel::default();
    claimed_log_sizes.iter().for_each(|log_size| {
        verifier_channel.mix_u64(*log_size as u64);
    });

    // Verify preprocessed trace commitment
    verify_preprocessed_trace(&proof, side_note, verifier_channel, &claimed_log_sizes, &config)?;

    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let sizes: Vec<TreeVec<Vec<u32>>> = components
        .iter()
        .zip(&claimed_log_sizes)
        .map(|(c, &log_size)| c.trace_sizes(log_size))
        .collect();
    let mut log_sizes = TreeVec::concat_cols(sizes.into_iter());
    log_sizes[PREPROCESSED_TRACE_IDX] = components
        .iter()
        .zip(&claimed_log_sizes)
        .flat_map(|(c, &log_size)| c.preprocessed_trace_sizes(log_size))
        .collect();

    for idx in [PREPROCESSED_TRACE_IDX, ORIGINAL_TRACE_IDX] {
        commitment_scheme.commit(proof.commitments[idx], &log_sizes[idx], verifier_channel);
    }

    let mut lookup_elements = AllLookupElements::default();
    components
        .iter()
        .for_each(|c| c.draw_lookup_elements(&mut lookup_elements, verifier_channel));

    // Verify logup sum = 0
    if claimed_sums.iter().sum::<SecureField>() != SecureField::zero() {
        return Err(VerificationError::InvalidStructure(
            "claimed logup sum is not zero".to_string(),
        ));
    }

    let tree_span_provider = &mut TraceLocationAllocator::default();
    let verifier_components: Vec<Box<dyn Component>> = components
        .iter()
        .zip(&claimed_sums)
        .zip(claimed_log_sizes)
        .map(|((comp, claimed_sum), log_size)| {
            comp.to_component(tree_span_provider, &lookup_elements, log_size, *claimed_sum)
        })
        .collect();
    let components_ref: Vec<&dyn Component> = verifier_components.iter().map(|c| &**c).collect();

    verifier_channel.mix_felts(&claimed_sums);
    commitment_scheme.commit(
        proof.commitments[INTERACTION_TRACE_IDX],
        &log_sizes[INTERACTION_TRACE_IDX],
        verifier_channel,
    );

    stwo::core::verifier::verify(&components_ref, verifier_channel, commitment_scheme, proof)
}

fn verify_preprocessed_trace(
    proof: &stwo::core::proof::StarkProof<Blake2sMerkleHasher>,
    side_note: &SideNote,
    verifier_channel: &Blake2sChannel,
    log_sizes: &[u32],
    config: &PcsConfig,
) -> Result<(), VerificationError> {
    // Phase 60: same active-component filter the prover used.  This
    // helper actually re-runs prover-side preprocessing-trace
    // generation to re-commit, so it needs the prover trait, not
    // the verifier-side MachineComponent.
    let components_owned = super::active_components(side_note);
    let components: &[&dyn crate::framework::MachineProverComponent] = &components_owned;
    let max_constraint_log_degree_bound = components
        .iter()
        .zip(log_sizes)
        .map(|(c, &log_size)| c.max_constraint_log_degree_bound(log_size))
        .max()
        .unwrap_or(0);
    let verifier_channel = &mut verifier_channel.clone();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(max_constraint_log_degree_bound + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let commitment_scheme =
        &mut CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(*config, &twiddles);

    let mut tree_builder = commitment_scheme.tree_builder();
    for (c, log_size) in components.iter().zip(log_sizes) {
        tree_builder.extend_evals(c.generate_preprocessed_trace(*log_size, side_note));
    }
    tree_builder.commit(verifier_channel);

    let preprocessed_expected = commitment_scheme.roots()[PREPROCESSED_TRACE_IDX];
    let preprocessed = proof.commitments[PREPROCESSED_TRACE_IDX];
    if preprocessed_expected != preprocessed {
        Err(VerificationError::InvalidStructure(format!(
            "invalid commitment to preprocessed trace: expected {preprocessed_expected}, got {preprocessed}"
        )))
    } else {
        Ok(())
    }
}
