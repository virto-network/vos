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
/// The side note supplies the program (its preprocessed trace is re-committed
/// and compared) and the component set its steps select; the boundary states
/// come from the proof, which every verifier mixes and binds whatever the
/// side note's `closing_chip_active` says. (`vos_pvm_proof_verifier::
/// verify_standalone` needs no side note at all, only the program's
/// preprocessed commitment.)
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
    let expected_log_sizes = committed_log_sizes(components, &proof.log_sizes);
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
    let config = proof.pcs_config;
    let stark = MC::stark(&proof.stark_proof).ok_or_else(|| {
        VerificationError::InvalidStructure("Stark proof channel differs".to_string())
    })?;
    let (protocol_shape, security_shape) = crate::framework_access::preflight_component_dimensions(
        &config,
        stark,
        &shape_component_refs,
        &expected_log_sizes,
    )
    .map_err(VerificationError::InvalidStructure)?;
    if format.encoding == Encoding::Lossless {
        crate::proof::check_format_security(format, &config, &security_shape)
            .map_err(VerificationError::InvalidStructure)?;
    }

    verify_preprocessed_trace::<MC>(
        stark,
        side_note,
        &proof.log_sizes,
        &config,
        prover_components,
    )?;
    if boundary_positions.is_some() && proof.initial_state.timestamp < 1 {
        return Err(VerificationError::InvalidStructure(
            "initial_state.timestamp must be >= 1 (memory-boundary anchoring)".to_string(),
        ));
    }

    let verifier_channel = &mut MC::C::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<MC>::new(config);
    let TranscriptPrefix {
        lookup_elements,
        verifier_components,
    } = transcript_prefix::<MC>(
        &proof,
        stark,
        format,
        components,
        &expected_log_sizes,
        verifier_channel,
        commitment_scheme,
    )?;

    // Verify logup sum = 0
    if proof.claimed_sums.iter().sum::<SecureField>() != SecureField::zero() {
        return Err(VerificationError::InvalidStructure(
            "claimed logup sum is not zero".to_string(),
        ));
    }

    // Boundary public-input binding (format v5): each boundary chip's
    // claimed sum must equal the value recomputed from the proof's
    // public boundary states with the drawn lookup elements. This
    // is what BINDS `proof.{initial,final}_state` to the committed
    // boundary columns — the mix in the transcript alone is only
    // tamper-evidence against post-prove edits, not against a from-scratch
    // prover. See `boundary_binding` for the soundness argument and
    // `tests/boundary_binding.rs` for the forgery gate. `None`
    // positions = the chip-isolated explicit-components path, which has
    // no stable component order and is not a trust boundary; the
    // production path always supplies `Some`.
    if let Some(positions) = &boundary_positions {
        crate::boundary_binding::check_boundary_claimed_sums(
            &proof.initial_state,
            &proof.final_state,
            &lookup_elements,
            &proof.claimed_sums,
            positions,
        )
        .map_err(|msg| VerificationError::InvalidStructure(msg.to_string()))?;
    }

    let sampled_queries = crate::proof::expected_fiat_shamir_query_count::<MC>(
        verifier_channel,
        stark,
        &config,
        protocol_shape,
        &expected_log_sizes,
    )
    .map_err(VerificationError::InvalidStructure)?;
    if sampled_queries != protocol_shape.query_count {
        return Err(VerificationError::InvalidStructure(
            "queried-value rows differ from Fiat-Shamir query positions".to_string(),
        ));
    }

    let components_ref: Vec<&dyn Component> = verifier_components.iter().map(|c| &**c).collect();
    let stark = MC::from_any(proof.stark_proof).expect("the channel checked above");
    stwo::core::verifier::verify(&components_ref, verifier_channel, commitment_scheme, stark)
}

/// Each tree's column log sizes, as `components` commit them at the proof's
/// `log_sizes`.
fn committed_log_sizes(
    components: &[&dyn crate::framework::MachineComponent],
    log_sizes: &[u32],
) -> TreeVec<Vec<u32>> {
    let sizes: Vec<TreeVec<Vec<u32>>> = components
        .iter()
        .zip(log_sizes)
        .map(|(component, &log_size)| component.trace_sizes(log_size))
        .collect();
    let mut committed = TreeVec::concat_cols(sizes.into_iter());
    committed[PREPROCESSED_TRACE_IDX] = components
        .iter()
        .zip(log_sizes)
        .flat_map(|(component, &log_size)| component.preprocessed_trace_sizes(log_size))
        .collect();
    committed
}

/// What the transcript prefix draws: the relation elements and the
/// components bound to them.
struct TranscriptPrefix<'a> {
    lookup_elements: AllLookupElements,
    verifier_components: Vec<Box<dyn Component + 'a>>,
}

/// The verifier's transcript through the interaction tree's root, as the
/// prover ran it, on `channel` and `commitment_scheme`:
/// - A.1's first five items: the statement header; the preprocessed and main
///   roots; the boundary states and the interaction PoW, which it checks; and
///   the relation elements;
/// - the claimed sums, then the interaction root.
///
/// The verifier and the recursion seams replay this one prefix, and A.1's
/// in-AIR transcript follows it. Every proof mixes its boundary states, as
/// every proof's prover did.
fn transcript_prefix<'a, MC: PcsStack>(
    proof: &Proof,
    stark: &stwo::core::proof::StarkProof<MC::H>,
    format: &Format,
    components: &[&'a dyn crate::framework::MachineComponent],
    log_sizes: &TreeVec<Vec<u32>>,
    channel: &mut MC::C,
    commitment_scheme: &mut CommitmentSchemeVerifier<MC>,
) -> Result<TranscriptPrefix<'a>, VerificationError> {
    crate::proof::mix_statement_header(channel, format.number, &proof.pcs_config, &proof.log_sizes);
    for idx in [PREPROCESSED_TRACE_IDX, ORIGINAL_TRACE_IDX] {
        commitment_scheme.commit(stark.commitments[idx], &log_sizes[idx], channel);
    }

    crate::proof::mix_boundary_states(
        channel,
        format.encoding,
        &proof.initial_state,
        &proof.final_state,
    );
    crate::proof::check_interaction_pow(channel, format, proof.interaction_pow)
        .map_err(VerificationError::InvalidStructure)?;

    let mut lookup_elements = AllLookupElements::default();
    components
        .iter()
        .for_each(|c| c.draw_lookup_elements(&mut lookup_elements, channel.as_ref_channel()));

    let tree_span_provider = &mut TraceLocationAllocator::default();
    let verifier_components = components
        .iter()
        .zip(&proof.claimed_sums)
        .zip(&proof.log_sizes)
        .map(|((c, claimed_sum), &log_size)| {
            c.to_component(tree_span_provider, &lookup_elements, log_size, *claimed_sum)
        })
        .collect();

    channel.mix_felts(&proof.claimed_sums);
    commitment_scheme.commit(
        stark.commitments[INTERACTION_TRACE_IDX],
        &log_sizes[INTERACTION_TRACE_IDX],
        channel,
    );
    Ok(TranscriptPrefix {
        lookup_elements,
        verifier_components,
    })
}

fn verify_preprocessed_trace<MC: PcsStack>(
    proof: &stwo::core::proof::StarkProof<MC::H>,
    side_note: &SideNote,
    log_sizes: &[u32],
    config: &PcsConfig,
    components: &[&dyn crate::framework::MachineProverComponent],
) -> Result<(), VerificationError>
where
    SimdBackend: BackendForChannel<MC>,
{
    if side_note.memory_layout().is_none() {
        return Err(VerificationError::InvalidStructure(
            "a sparse memory image without its program's layout".to_string(),
        ));
    }
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
    // The root does not depend on the channel it is mixed into.
    let verifier_channel = &mut MC::C::default();
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
