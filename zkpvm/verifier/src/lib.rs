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
use stwo::core::{
    air::Component,
    channel::{Blake2sChannel, Channel},
    fields::qm31::SecureField,
    pcs::{CommitmentSchemeVerifier, TreeVec},
    vcs_lifted::blake2_merkle::Blake2sMerkleChannel,
    verifier::VerificationError,
};
use stwo_constraint_framework::TraceLocationAllocator;

// Re-export the Proof type + the format-version constant the verifier
// was compiled against.  Callers can compare against
// `proof.format_version` themselves for early rejection at the network
// boundary, or just rely on `verify_standalone`'s built-in check.
pub use zkpvm::{PROOF_FORMAT_VERSION, Proof};
// Phase 49: PcsPolicy floor — see SECURITY.md "Proof shape".
pub use zkpvm::proof::{
    PcsPolicy, STANDARD_MIN_FRI_LOG_BLOWUP, STANDARD_MIN_FRI_QUERIES, STANDARD_MIN_POW_BITS,
    check_pcs_policy,
};

use zkpvm::framework_access::{
    AllLookupElements, create_verifier_components, draw_all_lookup_elements,
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
    verify_standalone_with_options(proof, preprocessed_commitment, DEFAULT_MAX_LOG_SIZE, policy)
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
    // Phase Z0 hardening: `component_mask = 0` was a Phase 60 back-compat
    // sentinel meaning "fall back to count-based inference over the full
    // BASE_COMPONENTS" — it's how older proofs reached the verifier
    // before dynamic chip selection landed. With `format_version` now
    // bumped past those proofs, the only producer of `mask = 0` is the
    // chip-isolated `prove_with_explicit_components` path, whose proofs
    // are documented as "not verifiable via verify_standalone".
    //
    // Reject early. Without this gate, a malicious prover could ship a
    // chip-isolated proof (no FS-transcript mix on the prover side) to
    // verify_standalone, slipping `proof.final_state.registers` past the
    // Z0 binding — the standalone verifier would also skip the mix and
    // tampered registers would verify cleanly.
    if proof.component_mask == 0 {
        return Err(VerificationError::InvalidStructure(
            "component_mask = 0 is invalid at format_version >= 2 \
             (chip-isolated proofs must use verify_with_explicit_components)"
                .to_string(),
        ));
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
        component_mask,
        pcs_config,
        initial_state,
        final_state,
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
    // The active-component reconstruction zips mask-selected chips with
    // the claimed sums/log sizes; require the counts to agree so a
    // mask/num_components mismatch can't silently truncate either side.
    if component_mask.count_ones() as usize != num_components {
        return Err(VerificationError::InvalidStructure(
            "component_mask popcount does not match num_components".to_string(),
        ));
    }
    // Phase A (v7): reject `initial_state.timestamp < 1` per segment (the
    // production consumer verifies single proofs here, not only the chain
    // wrapper).  Step timestamps start at 1, so `initial_ts ≥ 1` excludes the
    // ts=0 per-page boundary writes from being forged as real steps, and (with
    // the CpuChip ts-chain) lands every step ts in [initial_ts, final_ts).
    if initial_state.timestamp < 1 {
        return Err(VerificationError::InvalidStructure(
            "initial_state.timestamp must be >= 1 (Phase A memory-boundary anchoring)".to_string(),
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
        create_verifier_components::trace_and_preprocessed_sizes(
            &claimed_log_sizes,
            component_mask,
        );
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

    // Phase Z0: mix `proof.{initial,final}_state` (registers, pc,
    // timestamp) into the FS transcript. The `component_mask = 0`
    // reject at the top of this function guarantees we only reach here
    // for production proofs that included the boundary + closing chip
    // pair, so the mix is unconditional. The lookup elements drawn next
    // therefore depend on the claimed boundary states. Order MUST match
    // the prover (see `prove.rs`): initial first, then final.
    // `memory_commitment` stays unmixed (computed outside the circuit).
    for r in &initial_state.registers {
        verifier_channel.mix_u64(*r);
    }
    for r in &final_state.registers {
        verifier_channel.mix_u64(*r);
    }
    verifier_channel.mix_u64(initial_state.pc as u64);
    verifier_channel.mix_u64(initial_state.timestamp);
    verifier_channel.mix_u64(final_state.pc as u64);
    verifier_channel.mix_u64(final_state.timestamp);
    // Phase A (v7): entering then exit RAM Merkle root, 4 LE u64 each.
    // Unconditional — the component_mask=0 reject above guarantees a
    // production proof with the Phase-A chips.
    for chunk in initial_state.memory_root.chunks_exact(8) {
        verifier_channel.mix_u64(u64::from_le_bytes(chunk.try_into().unwrap()));
    }
    for chunk in final_state.memory_root.chunks_exact(8) {
        verifier_channel.mix_u64(u64::from_le_bytes(chunk.try_into().unwrap()));
    }

    let mut lookup_elements = AllLookupElements::default();
    draw_all_lookup_elements(&mut lookup_elements, verifier_channel, component_mask);

    // Verify logup sum = 0
    if claimed_sums.iter().sum::<SecureField>() != SecureField::zero() {
        return Err(VerificationError::InvalidStructure(
            "claimed logup sum is not zero".to_string(),
        ));
    }

    // Boundary public-input binding (format v5): each boundary chip's
    // claimed sum must equal the value recomputed from the proof's
    // public boundary states with the just-drawn lookup elements. This
    // BINDS `proof.{initial,final}_state` to the committed boundary
    // COLUMNS; the mix above alone is only tamper-evidence against
    // post-prove edits, not against a from-scratch prover. pc/timestamp
    // columns are pinned to the trace, so those become genuine bound
    // public inputs; the register columns (and the voucher io-hash read
    // from `final_state.registers[9..13]`) are pinned to the trace only
    // by the register-ledger read-consistency, which is vacuous against
    // a from-scratch prover today — see `zkpvm::boundary_binding` and
    // `chips/register_memory_closing.rs`. A mask missing any binding
    // chip cannot bind its boundary states and is rejected outright (all
    // three are unconditionally active in the production prove path).
    let Some(boundary_positions) =
        zkpvm::boundary_binding::boundary_positions_in_mask(component_mask)
    else {
        return Err(VerificationError::InvalidStructure(
            "component_mask lacks a boundary-binding chip \
             (RegisterMemoryBoundary / RegisterMemoryClosing / ProgramBoundary)"
                .to_string(),
        ));
    };
    zkpvm::boundary_binding::check_boundary_claimed_sums(
        &initial_state,
        &final_state,
        &lookup_elements,
        &claimed_sums,
        &boundary_positions,
    )
    .map_err(|msg| VerificationError::InvalidStructure(msg.to_string()))?;

    let tree_span_provider = &mut TraceLocationAllocator::default();
    let verifier_components: Vec<Box<dyn Component>> = create_verifier_components::components(
        tree_span_provider,
        &lookup_elements,
        &claimed_log_sizes,
        &claimed_sums,
        component_mask,
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

/// Verify a CHAIN of segment proofs WITHOUT any side note — the trustless
/// counterpart to `zkpvm::verify_chain` (which needs prover-supplied
/// `SideNote`s and never pins program identity).
///
/// Each segment is verified via [`verify_standalone`] against the SAME
/// `preprocessed_commitment`, so the chain (a) needs no prover-supplied
/// trace data and (b) pins every segment to ONE program identity (a
/// from-scratch prover cannot splice in a segment of a different program).
/// Consecutive segments must chain: `proofs[i].final_state ==
/// proofs[i+1].initial_state`.
///
/// SOUNDNESS SCOPE — the boundary-continuity equality is BOUND for the
/// fields `verify_standalone` binds in-circuit: registers (v6
/// register-ledger read-consistency) and pc/timestamp (CpuChip
/// program-execution chaining + the boundary-binding check). It is
/// TAMPER-EVIDENT ONLY for `SegmentState.memory_commitment`, which is
/// `blake3(flat_mem)` computed OUTSIDE the circuit and unbound — a
/// from-scratch prover can put any matching hash on both sides of a
/// boundary while the actual memory image diverges. So a chain accepted
/// here proves: one program, per-segment validity, and register/pc/
/// timestamp continuity — NOT memory continuity. Binding memory
/// continuity (in-circuit memory commitment / Merkle memory / chain-level
/// handoff) is the remaining work; see
/// `docs/plans/ledger-read-consistency.md`.
///
/// PRECONDITION — every segment must share `preprocessed_commitment`, i.e.
/// have the SAME per-component `log_sizes` (the program commitment is the
/// preprocessed-trace Merkle root, which is size-dependent). Deployments
/// that segment a long trace should pad all segments to one uniform size
/// so a single published commitment pins them all; a chain whose last
/// segment is smaller would currently need its own commitment (a
/// per-segment-commitment variant is future work).
pub fn verify_chain_standalone(
    proofs: &[Proof],
    preprocessed_commitment: CommitmentHash,
    expected_initial_root: [u8; 32],
) -> Result<[u8; 32], VerificationError> {
    verify_chain_standalone_with_options(
        proofs,
        preprocessed_commitment,
        expected_initial_root,
        DEFAULT_MAX_LOG_SIZE,
        &PcsPolicy::STANDARD,
    )
}

/// [`verify_chain_standalone`] with explicit `max_log_size` cap + `PcsPolicy`.
///
/// `expected_initial_root` is the page-Merkle root of the program's starting
/// RAM image — the memory analogue of the program commitment — checked against
/// `proofs[0].initial_state.memory_root`.  On success returns the chain's final
/// root (`proofs.last().final_state.memory_root`) so the caller can pin the
/// post-state.  Callers compute `expected_initial_root` host-side via
/// `zkpvm::page_merkle::image_root` over the input image.
pub fn verify_chain_standalone_with_options(
    proofs: &[Proof],
    preprocessed_commitment: CommitmentHash,
    expected_initial_root: [u8; 32],
    max_log_size: u32,
    policy: &PcsPolicy,
) -> Result<[u8; 32], VerificationError> {
    if proofs.is_empty() {
        return Err(VerificationError::InvalidStructure(
            "verify_chain_standalone: empty proof chain".to_string(),
        ));
    }
    // Phase A: anchor the chain's entering image — proofs[0] must start from the
    // verifier-supplied expected root (the memory analogue of program identity).
    if proofs[0].initial_state.memory_root != expected_initial_root {
        return Err(VerificationError::InvalidStructure(
            "verify_chain_standalone: proofs[0].initial_state.memory_root \
             does not match expected_initial_root"
                .to_string(),
        ));
    }
    // Boundary continuity: each segment's final state must equal the next
    // segment's initial state.  Bound for registers/pc/timestamp (and, Phase A,
    // the memory root) by each segment's in-circuit boundary binding.
    for window in proofs.windows(2) {
        if window[0].final_state != window[1].initial_state {
            return Err(VerificationError::InvalidStructure(format!(
                "segment chain broken: final state at ts={} does not match next initial at ts={}",
                window[0].final_state.timestamp, window[1].initial_state.timestamp,
            )));
        }
    }
    // Each segment verifies standalone against the SAME program commitment:
    // no side note, and program identity is pinned across the whole chain.
    for proof in proofs {
        verify_standalone_with_options(
            proof.clone(),
            preprocessed_commitment,
            max_log_size,
            policy,
        )?;
    }
    Ok(proofs[proofs.len() - 1].final_state.memory_root)
}
