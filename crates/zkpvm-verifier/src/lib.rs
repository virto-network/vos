// zkpvm-verifier: standalone verification for PVM zkVM proofs.
//
// This crate provides a verify function that does NOT require the full
// execution trace (SideNote). It only needs the proof and the expected
// preprocessed trace commitment (which is deterministic per program).
//
// no_std-ready: the verifier path of zkpvm pulls only verifier-side stwo,
// alloc::*, and core::*.  The wasm32-unknown-unknown smoke test (11d) is
// blocked on an upstream javm fix (CODE_WINDOW_SIZE = 1 << 32 overflows on
// 32-bit usize); the host-side `cargo build --no-default-features` still
// validates no_std compatibility.

#![no_std]

extern crate alloc;

use alloc::{boxed::Box, format, string::ToString, vec::Vec};
use num_traits::Zero;
use stwo::{
    core::{
        air::Component,
        channel::{Blake2sChannel, Channel},
        fields::qm31::SecureField,
        pcs::{CommitmentSchemeVerifier, TreeVec},
        vcs::blake2_merkle::Blake2sMerkleChannel,
        verifier::VerificationError,
    },
};
use stwo_constraint_framework::TraceLocationAllocator;

// Re-export the Proof type + the format-version constant the verifier
// was compiled against.  Callers can compare against
// `proof.format_version` themselves for early rejection at the network
// boundary, or just rely on `verify_standalone`'s built-in check.
pub use zkpvm::{Proof, PROOF_FORMAT_VERSION};
// Phase 49: PcsPolicy floor — see SECURITY.md "Proof shape".
pub use zkpvm::proof::{
    check_pcs_policy, PcsPolicy, STANDARD_MIN_FRI_LOG_BLOWUP, STANDARD_MIN_FRI_QUERIES,
    STANDARD_MIN_POW_BITS,
};

use zkpvm::framework_access::{
    create_verifier_components, draw_all_lookup_elements, AllLookupElements,
};

/// Verification hash type (Blake2s Merkle root)
pub use stwo::core::vcs::blake2_hash::Blake2sHash as CommitmentHash;

/// Default per-component log_size cap used by `verify_standalone`.
///
/// At log_size = 24 each chip's main trace has 2^24 ≈ 16M rows; the
/// FRI/Merkle phase commits those plus the preprocessed and
/// interaction traces.  This is well above the largest trace the
/// `prove_vos_actor` benchmark suite produces and well below the
/// log_size where verification CPU/memory cost becomes onerous.
///
/// Callers who need to accept larger proofs (e.g. for batched
/// proving over very long executions) should call
/// `verify_standalone_with_max_log_size` with an explicit bound.
pub const DEFAULT_MAX_LOG_SIZE: u32 = 24;

/// Verify a PVM execution proof.
///
/// # Arguments
/// * `proof` - The STARK proof with claimed sums and log sizes
/// * `preprocessed_commitment` - The expected Merkle root of the preprocessed trace.
///   This is deterministic per program (bytecode + initial memory layout).
///   The caller must compute this once per program and provide it here.
///
/// # Returns
/// `Ok(())` if the proof is valid, `Err(VerificationError)` otherwise.
pub fn verify_standalone(
    proof: Proof,
    preprocessed_commitment: CommitmentHash,
) -> Result<(), VerificationError> {
    verify_standalone_with_options(
        proof,
        preprocessed_commitment,
        DEFAULT_MAX_LOG_SIZE,
        &PcsPolicy::STANDARD,
    )
}

/// Same as `verify_standalone` but with a caller-supplied per-component
/// `log_size` cap.  Use this when you need to accept proofs over larger
/// traces than `DEFAULT_MAX_LOG_SIZE` admits, or — more usefully —
/// tighten the cap for a specific deployment that knows its proof
/// shapes are smaller.
///
/// Reject path: any `log_size > max_log_size` returns
/// `InvalidStructure` before the verifier touches commitments,
/// preventing a malicious prover from forcing the verifier into a
/// giant Merkle commitment phase.
pub fn verify_standalone_with_max_log_size(
    proof: Proof,
    preprocessed_commitment: CommitmentHash,
    max_log_size: u32,
) -> Result<(), VerificationError> {
    verify_standalone_with_options(
        proof,
        preprocessed_commitment,
        max_log_size,
        &PcsPolicy::STANDARD,
    )
}

/// Phase 49: enforce a custom `PcsPolicy` (FRI shape + PoW floor)
/// on `proof.pcs_config`.  Most deployers want `PcsPolicy::STANDARD`;
/// override for stricter (more security) or looser (test harness)
/// floors.  See SECURITY.md "Proof shape".
pub fn verify_standalone_with_pcs_policy(
    proof: Proof,
    preprocessed_commitment: CommitmentHash,
    policy: &PcsPolicy,
) -> Result<(), VerificationError> {
    verify_standalone_with_options(
        proof,
        preprocessed_commitment,
        DEFAULT_MAX_LOG_SIZE,
        policy,
    )
}

/// Both knobs at once.
pub fn verify_standalone_with_options(
    proof: Proof,
    preprocessed_commitment: CommitmentHash,
    max_log_size: u32,
    policy: &PcsPolicy,
) -> Result<(), VerificationError> {
    // Phase 42: reject proofs from a different AIR shape early, before
    // any cryptographic work.  Done first because every subsequent
    // length check assumes the AIR shape this verifier was compiled
    // against.
    if proof.format_version != PROOF_FORMAT_VERSION {
        return Err(VerificationError::InvalidStructure(format!(
            "proof format version mismatch: verifier expects {}, proof has {}",
            PROOF_FORMAT_VERSION, proof.format_version,
        )));
    }
    // Phase 43: cap log_sizes so a malicious prover can't force the
    // verifier into arbitrarily large Merkle commitments.  We check
    // each component's log_size individually against the cap; the
    // dominant cost in verification is roughly O(2^max_log_size · k)
    // per component (k constant), so a single oversized log_size is
    // enough to DoS.
    if let Some(&offending) = proof.log_sizes.iter().find(|&&ls| ls > max_log_size) {
        return Err(VerificationError::InvalidStructure(format!(
            "proof log_size {offending} exceeds cap {max_log_size} \
             (set max_log_size higher or reject this proof)"
        )));
    }
    // Phase 49: enforce the PcsPolicy floor — reject under-spec'd
    // pcs_configs (low pow_bits, low n_queries, low log_blowup_factor)
    // before any cryptographic work.  Default policy is
    // PcsPolicy::STANDARD; deployers needing more / less specify a
    // custom one.
    if let Err(msg) = check_pcs_policy(&proof.pcs_config, policy) {
        return Err(VerificationError::InvalidStructure(msg));
    }
    let Proof {
        stark_proof,
        claimed_sums,
        log_sizes: claimed_log_sizes,
        num_components,
        pcs_config,
        ..
    } = proof;

    if claimed_sums.len() != num_components {
        return Err(VerificationError::InvalidStructure(
            "claimed sums len mismatch".to_string(),
        ));
    }
    if claimed_log_sizes.len() != num_components {
        return Err(VerificationError::InvalidStructure(
            "log sizes len mismatch".to_string(),
        ));
    }

    // Use the proof's own PCS config — `prove()` uses production_pcs_config
    // by default (blowup=16, 19 queries, 20-bit PoW), not PcsConfig::default(),
    // so blindly using default here makes Merkle witness sizes mismatch
    // (Merkle::WitnessTooLong).  The proof carries its config; trust it.
    let config = pcs_config;
    let verifier_channel = &mut Blake2sChannel::default();
    claimed_log_sizes.iter().for_each(|log_size| {
        verifier_channel.mix_u64(*log_size as u64);
    });

    // Check preprocessed trace commitment matches expected
    let actual_preprocessed = stark_proof.commitments[0]; // PREPROCESSED_TRACE_IDX = 0
    if actual_preprocessed != preprocessed_commitment {
        return Err(VerificationError::InvalidStructure(format!(
            "preprocessed commitment mismatch: expected {preprocessed_commitment}, got {actual_preprocessed}"
        )));
    }

    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);

    // Commit preprocessed and original traces
    let (trace_sizes, preprocessed_sizes) =
        create_verifier_components::trace_and_preprocessed_sizes(&claimed_log_sizes);
    let mut log_sizes = TreeVec::concat_cols(trace_sizes.into_iter());
    log_sizes[0] = preprocessed_sizes; // PREPROCESSED_TRACE_IDX

    for idx in [0, 1] {
        // PREPROCESSED_TRACE_IDX, ORIGINAL_TRACE_IDX
        commitment_scheme.commit(
            stark_proof.commitments[idx],
            &log_sizes[idx],
            verifier_channel,
        );
    }

    let mut lookup_elements = AllLookupElements::default();
    draw_all_lookup_elements(&mut lookup_elements, verifier_channel, claimed_log_sizes.len());

    // Verify logup sum = 0
    if claimed_sums.iter().sum::<SecureField>() != SecureField::zero() {
        return Err(VerificationError::InvalidStructure(
            "claimed logup sum is not zero".to_string(),
        ));
    }

    let tree_span_provider = &mut TraceLocationAllocator::default();
    let verifier_components: Vec<Box<dyn Component>> =
        create_verifier_components::components(
            tree_span_provider,
            &lookup_elements,
            &claimed_log_sizes,
            &claimed_sums,
        );
    let components_ref: Vec<&dyn Component> = verifier_components.iter().map(|c| &**c).collect();

    verifier_channel.mix_felts(&claimed_sums);
    commitment_scheme.commit(
        stark_proof.commitments[2], // INTERACTION_TRACE_IDX
        &log_sizes[2],
        verifier_channel,
    );

    stwo::core::verifier::verify(
        &components_ref,
        verifier_channel,
        commitment_scheme,
        stark_proof,
    )
}

