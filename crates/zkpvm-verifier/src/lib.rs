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

use zkpvm::framework_access::{
    create_verifier_components, draw_all_lookup_elements, AllLookupElements,
};

/// Verification hash type (Blake2s Merkle root)
pub use stwo::core::vcs::blake2_hash::Blake2sHash as CommitmentHash;

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
    draw_all_lookup_elements(&mut lookup_elements, verifier_channel);

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

