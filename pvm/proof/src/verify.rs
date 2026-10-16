use num_traits::Zero;
use stwo::{
    core::{
        air::Component,
        channel::Channel,
        fields::qm31::SecureField,
        pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec},
        poly::circle::CanonicCoset,
        verifier::VerificationError,
    },
    prover::{CommitmentSchemeProver, poly::circle::PolyOps},
};
use stwo_constraint_framework::TraceLocationAllocator;

use stwo::prover::backend::{BackendForChannel, simd::SimdBackend};

use crate::format::{Encoding, Format};
use crate::pcs::{FsChannel, PcsStack};

use crate::trace::eval::{INTERACTION_TRACE_IDX, ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX};

use super::Proof;
use crate::{lookups::AllLookupElements, side_note::SideNote};

mod recursion;
pub use recursion::{
    ComponentOodsMask, DeepBatch, OodsReconstruction, RecursionData, RecursionTranscript,
    extract_recursion_data, reconstruct_oods_for_recursion, record_canonical_transcript,
};

/// Verify a chain of segment proofs. Each segment's final state must match
/// the next segment's initial state. Each segment is verified independently.
///
/// The continued `SegmentState` fields are bound to the committed boundary
/// columns (boundary-binding check — see `boundary_binding`), so the
/// continuity equality forces real state continuity: pc/timestamp via CpuChip
/// trace pinning, registers via the register-ledger read-consistency binding,
/// and `memory_root` via the in-AIR page-Merkle trie. (`memory_commitment`,
/// a blake3 of the image, is also compared but is unbound/vestigial —
/// `memory_root` carries continuity.) This is a host-side capability (it
/// consumes prover-derived side notes); `vos_pvm_proof_verifier::verify_chain_standalone`
/// is the side-note-free, trust-boundary variant.
pub fn verify_chain(proofs: &[Proof], side_notes: &[&SideNote]) -> Result<(), VerificationError> {
    if proofs.len() != side_notes.len() {
        return Err(VerificationError::InvalidStructure(
            "proofs and side_notes length mismatch".to_string(),
        ));
    }
    // Check segment continuity
    for window in proofs.windows(2) {
        if window[0].final_state != window[1].initial_state {
            return Err(VerificationError::InvalidStructure(format!(
                "segment chain broken: final state at ts={} doesn't match next initial at ts={}",
                window[0].final_state.timestamp, window[1].initial_state.timestamp
            )));
        }
    }
    // Verify each segment independently
    for (proof, side_note) in proofs.iter().zip(side_notes) {
        verify(proof.clone(), side_note)?;
    }
    Ok(())
}

/// Default per-component log_size cap used by `verify`.  See
/// `vos_pvm_proof_verifier::DEFAULT_MAX_LOG_SIZE` for the rationale; same value
/// kept in sync deliberately so prover-side and verifier-only paths
/// reject at the same threshold.
pub const DEFAULT_MAX_LOG_SIZE: u32 = 24;

/// Verify a proof against a `side_note` describing the SAME program +
/// segment the prover ran.
///
/// PRECONDITION: `side_note` must be in the state `prove` left it in —
/// `closing_chip_active` set and the register images backfilled. `prove`
/// applies this via [`crate::prepare_side_note_for_verification`]; a
/// caller that RE-DERIVES a side note (e.g. re-slicing a segment of a
/// traced run to check a chain) MUST call that helper first, or the
/// verifier's Fiat-Shamir transcript diverges from the prover's and an
/// honest proof fails with `OodsNotMatching`. (This is a host-side
/// re-derivation path only; `vos_pvm_proof_verifier::verify_standalone` needs no
/// side note at all.)
pub fn verify(proof: Proof, side_note: &SideNote) -> Result<(), VerificationError> {
    // Default: the conjectured-security floor, which accepts any 96-bit-secure
    // shape (STANDARD and MOBILE both). `None` selects that floor; the strict
    // `verify_with_pcs_policy` path passes an exact `PcsPolicy` instead.
    verify_with_shape(proof, side_note, DEFAULT_MAX_LOG_SIZE, None)
}

/// Caller-supplied per-component `log_size` cap variant of `verify`.
/// See `verify` for the default and the `max_log_size` cap rationale.
/// Shares `verify`'s default FRI-shape floor (the conjectured-security floor).
pub fn verify_with_max_log_size(
    proof: Proof,
    side_note: &SideNote,
    max_log_size: u32,
) -> Result<(), VerificationError> {
    verify_with_shape(proof, side_note, max_log_size, None)
}

/// Enforce a custom `PcsPolicy` (FRI shape + PoW floor)
/// on `proof.pcs_config`.  The default `verify` accepts any shape meeting the
/// conjectured-security floor; reach for this to pin an EXACT shape (stricter
/// deployments) or to accept a looser test-harness shape.  See SECURITY.md
/// "Proof shape".
pub fn verify_with_pcs_policy(
    proof: Proof,
    side_note: &SideNote,
    policy: &crate::proof::PcsPolicy,
) -> Result<(), VerificationError> {
    verify_with_shape(proof, side_note, DEFAULT_MAX_LOG_SIZE, Some(policy))
}

/// Both knobs at once — the explicit-`PcsPolicy` funnel (strict per-field
/// pin). The default `verify` / `verify_with_max_log_size` paths go through
/// `verify_with_shape` with the conjectured-security floor instead.
pub fn verify_with_options(
    proof: Proof,
    side_note: &SideNote,
    max_log_size: u32,
    policy: &crate::proof::PcsPolicy,
) -> Result<(), VerificationError> {
    verify_with_shape(proof, side_note, max_log_size, Some(policy))
}

/// Shared component-setup funnel for the SideNote verify paths. `policy`
/// selects the FRI-shape floor: `None` = the conjectured-security floor (the
/// default `verify` paths — accepts STANDARD and MOBILE), `Some(p)` = an exact
/// `PcsPolicy` pin (the strict `*_with_pcs_policy` paths).
fn verify_with_shape(
    proof: Proof,
    side_note: &SideNote,
    max_log_size: u32,
    policy: Option<&crate::proof::PcsPolicy>,
) -> Result<(), VerificationError> {
    let expected_component_mask = super::active_component_mask(side_note);
    if proof.component_mask != expected_component_mask {
        return Err(VerificationError::InvalidStructure(format!(
            "proof component mask {:#x} differs from SideNote-derived mask {expected_component_mask:#x}",
            proof.component_mask,
        )));
    }
    // Select active components from side_note (same predicate
    // the prover used).  See `active_components_verifier` doc-comment.
    let components_owned = super::active_components_verifier(side_note);
    let components: &[&dyn crate::framework::MachineComponent] = &components_owned;
    let prover_components_owned = super::active_components(side_note);
    let prover_components: &[&dyn crate::framework::MachineProverComponent] =
        &prover_components_owned;
    // Locate the boundary-binding chips in the same active order the
    // claimed sums are indexed by; all three are unconditionally active,
    // so this is always `Some` for the production component selection.
    let boundary_positions = crate::boundary_binding::boundary_positions_in_mask(
        super::active_component_mask(side_note),
    );
    verify_with_options_explicit_components(
        proof,
        side_note,
        max_log_size,
        policy,
        components,
        prover_components,
        boundary_positions,
    )
}

/// Chip-isolated verify path — pair with `prove_with_explicit_components`.
///
/// `components` is the verifier-trait view of the chip set (used for the
/// constraint check).  `prover_components` is the prover-trait view of the
/// SAME set (used to regenerate the preprocessed trace).  In practice they
/// point to the same underlying unit chips and `MachineProverComponent`
/// extends `MachineComponent`, so callers usually have one slice and pass
/// it twice (once via `as &dyn MachineComponent` upcast, once raw).
///
/// `policy` lets the harness use a cheap `PcsConfig` for fast chip-rewrite
/// validation cycles (e.g. `pow_bits = 5`) without tripping the production
/// `PcsPolicy::STANDARD` floor.
///
/// The boundary-binding claimed-sum check is SKIPPED on this path (the
/// caller's arbitrary chip slice has no stable component positions);
/// chip-isolated proofs are not verifiable across a trust boundary
/// anyway — `verify_standalone` rejects their `component_mask = 0`.
pub fn verify_with_explicit_components(
    proof: Proof,
    side_note: &SideNote,
    components: &[&dyn crate::framework::MachineComponent],
    prover_components: &[&dyn crate::framework::MachineProverComponent],
    policy: &crate::proof::PcsPolicy,
) -> Result<(), VerificationError> {
    verify_with_options_explicit_components(
        proof,
        side_note,
        DEFAULT_MAX_LOG_SIZE,
        Some(policy),
        components,
        prover_components,
        None,
    )
}

fn verify_with_options_explicit_components(
    mut proof: Proof,
    side_note: &SideNote,
    max_log_size: u32,
    policy: Option<&crate::proof::PcsPolicy>,
    components: &[&dyn crate::framework::MachineComponent],
    prover_components: &[&dyn crate::framework::MachineProverComponent],
    boundary_positions: Option<crate::boundary_binding::BoundaryChipPositions>,
) -> Result<(), VerificationError> {
    // The format the proof names, admitted and with its Stark proof on the
    // format's channel, and every log size under `max_log_size` (so a
    // malicious prover can't force a giant Merkle commitment phase), before
    // any cryptographic work; then the FRI shape under `policy`.
    let format = crate::proof::preflight_proof_structure(&mut proof, max_log_size)
        .map_err(VerificationError::InvalidStructure)?;
    crate::proof::check_shape_policy(format, &proof.pcs_config, policy)
        .map_err(VerificationError::InvalidStructure)?;
    if proof.pcs_config.fri_config.log_blowup_factor > crate::proof::MAX_RECOMMIT_LOG_BLOWUP {
        return Err(VerificationError::InvalidStructure(format!(
            "proof-side recommitment rejects FRI log blowup above {}",
            crate::proof::MAX_RECOMMIT_LOG_BLOWUP,
        )));
    }
    if proof.claimed_sums.len() != components.len() || proof.log_sizes.len() != components.len() {
        return Err(VerificationError::InvalidStructure(
            "proof component dimensions differ from selected AIR components".to_string(),
        ));
    }
    crate::with_stack!(format.channel, Stack => verify_on::<Stack>(
        proof,
        format,
        side_note,
        components,
        prover_components,
        boundary_positions,
    ), unbuilt => Err(VerificationError::InvalidStructure(format!(
        "format {}'s channel is not built",
        format.number
    ))))
}

fn verify_on<MC: PcsStack>(
    proof: Proof,
    format: &'static Format,
    side_note: &SideNote,
    components: &[&dyn crate::framework::MachineComponent],
    prover_components: &[&dyn crate::framework::MachineProverComponent],
    boundary_positions: Option<crate::boundary_binding::BoundaryChipPositions>,
) -> Result<(), VerificationError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let sizes: Vec<TreeVec<Vec<u32>>> = components
        .iter()
        .zip(&proof.log_sizes)
        .map(|(component, &log_size)| component.trace_sizes(log_size))
        .collect();
    let mut expected_log_sizes = TreeVec::concat_cols(sizes.into_iter());
    expected_log_sizes[PREPROCESSED_TRACE_IDX] = components
        .iter()
        .zip(&proof.log_sizes)
        .flat_map(|(component, &log_size)| component.preprocessed_trace_sizes(log_size))
        .collect();
    let mut dummy_lookup = AllLookupElements::default();
    let mut dummy_channel = MC::C::default();
    components.iter().for_each(|component| {
        component.draw_lookup_elements(&mut dummy_lookup, dummy_channel.as_ref_channel())
    });
    let dummy_allocator = &mut TraceLocationAllocator::default();
    let shape_components: Vec<Box<dyn Component>> = components
        .iter()
        .zip(&proof.claimed_sums)
        .zip(&proof.log_sizes)
        .map(|((component, claimed_sum), &log_size)| {
            component.to_component(dummy_allocator, &dummy_lookup, log_size, *claimed_sum)
        })
        .collect();
    let shape_component_refs: Vec<&dyn Component> = shape_components
        .iter()
        .map(|component| &**component)
        .collect();
    let Proof {
        stark_proof,
        interaction_pow,
        claimed_sums,
        log_sizes: claimed_log_sizes,
        pcs_config: config,
        initial_state,
        final_state,
        ..
    } = proof;
    let proof = MC::from_any(stark_proof).ok_or_else(|| {
        VerificationError::InvalidStructure("Stark proof channel differs".to_string())
    })?;
    let (protocol_shape, security_shape) = crate::framework_access::preflight_component_dimensions(
        &config,
        &proof,
        &shape_component_refs,
        &expected_log_sizes,
    )
    .map_err(VerificationError::InvalidStructure)?;
    if format.encoding == Encoding::Lossless {
        crate::proof::check_format_security(format, &config, &security_shape)
            .map_err(VerificationError::InvalidStructure)?;
    }

    let verifier_channel = &mut MC::C::default();
    crate::proof::mix_statement_header(
        verifier_channel,
        format.number,
        &config,
        &claimed_log_sizes,
    );

    // Verify preprocessed trace commitment
    verify_preprocessed_trace::<MC>(
        &proof,
        side_note,
        verifier_channel,
        &claimed_log_sizes,
        &config,
        prover_components,
    )?;

    let commitment_scheme = &mut CommitmentSchemeVerifier::<MC>::new(config);
    let log_sizes = expected_log_sizes;

    for idx in [PREPROCESSED_TRACE_IDX, ORIGINAL_TRACE_IDX] {
        commitment_scheme.commit(proof.commitments[idx], &log_sizes[idx], verifier_channel);
    }

    // A.1's third and fourth items, as the prover ran them: the boundary
    // states and the interaction PoW, before the relation challenges. Gated
    // on `side_note.closing_chip_active`, as the prover's mix is: the
    // default `verify` path sees the flag via the prover-mutated side_note,
    // and chip-isolated `verify_with_explicit_components` only flips it when
    // the caller's slice includes the boundary + closing chip pair.
    if side_note.closing_chip_active {
        crate::proof::mix_boundary_states(
            verifier_channel,
            format.encoding,
            &initial_state,
            &final_state,
        );
        crate::proof::check_interaction_pow(verifier_channel, format, interaction_pow)
            .map_err(VerificationError::InvalidStructure)?;
    } else if interaction_pow != 0 {
        return Err(VerificationError::InvalidStructure(
            "a proof without the boundary chips carries no interaction PoW".to_string(),
        ));
    }

    let mut lookup_elements = AllLookupElements::default();
    components.iter().for_each(|c| {
        c.draw_lookup_elements(&mut lookup_elements, verifier_channel.as_ref_channel())
    });

    // Verify logup sum = 0
    if claimed_sums.iter().sum::<SecureField>() != SecureField::zero() {
        return Err(VerificationError::InvalidStructure(
            "claimed logup sum is not zero".to_string(),
        ));
    }

    // Boundary public-input binding (format v5): each boundary chip's
    // claimed sum must equal the value recomputed from the proof's
    // public boundary states with the just-drawn lookup elements. This
    // is what BINDS `proof.{initial,final}_state` to the committed
    // boundary columns — the mix above alone is only tamper-evidence
    // against post-prove edits, not against a from-scratch prover. See
    // `boundary_binding` for the soundness argument and
    // `tests/boundary_binding.rs` for the forgery gate. `None`
    // positions = the chip-isolated explicit-components path, which has
    // no stable component order and is not a trust boundary; the
    // production path always supplies `Some`.
    if side_note.closing_chip_active
        && let Some(positions) = &boundary_positions
    {
        crate::boundary_binding::check_boundary_claimed_sums(
            &initial_state,
            &final_state,
            &lookup_elements,
            &claimed_sums,
            positions,
        )
        .map_err(|msg| VerificationError::InvalidStructure(msg.to_string()))?;
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

    let sampled_queries = crate::proof::expected_fiat_shamir_query_count::<MC>(
        verifier_channel,
        &proof,
        &config,
        protocol_shape,
        &log_sizes,
    )
    .map_err(VerificationError::InvalidStructure)?;
    if sampled_queries != protocol_shape.query_count {
        return Err(VerificationError::InvalidStructure(
            "queried-value rows differ from Fiat-Shamir query positions".to_string(),
        ));
    }

    stwo::core::verifier::verify(&components_ref, verifier_channel, commitment_scheme, proof)
}

fn verify_preprocessed_trace<MC: PcsStack>(
    proof: &stwo::core::proof::StarkProof<MC::H>,
    side_note: &SideNote,
    verifier_channel: &MC::C,
    log_sizes: &[u32],
    config: &PcsConfig,
    components: &[&dyn crate::framework::MachineProverComponent],
) -> Result<(), VerificationError>
where
    SimdBackend: BackendForChannel<MC>,
{
    // The caller passes the same prover-trait component set the
    // prover used (either `active_components(side_note)` for the default
    // path, or an explicit slice for the chip-isolated harness).  This
    // helper actually re-runs prover-side preprocessing-trace generation
    // to re-commit, so it needs the prover trait, not the verifier-side
    // MachineComponent.
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
    let commitment_scheme = &mut CommitmentSchemeProver::<SimdBackend, MC>::new(*config, &twiddles);

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
