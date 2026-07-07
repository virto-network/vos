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

use crate::recursion_pcs::{
    ProverBackend, ProverChannel, ProverMerkleChannel, ProverMerkleHasher, for_commit,
};

use crate::trace::eval::{INTERACTION_TRACE_IDX, ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX};

use super::Proof;
use crate::{lookups::AllLookupElements, side_note::SideNote};

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
/// consumes prover-derived side notes); `zkpvm_verifier::verify_chain_standalone`
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
/// `zkpvm_verifier::DEFAULT_MAX_LOG_SIZE` for the rationale; same value
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
/// re-derivation path only; `zkpvm_verifier::verify_standalone` needs no
/// side note at all.)
pub fn verify(proof: Proof, side_note: &SideNote) -> Result<(), VerificationError> {
    verify_with_options(
        proof,
        side_note,
        DEFAULT_MAX_LOG_SIZE,
        &crate::proof::PcsPolicy::STANDARD,
    )
}

/// Caller-supplied per-component `log_size` cap variant of `verify`.
/// See `verify` for the default and the `max_log_size` cap rationale.
pub fn verify_with_max_log_size(
    proof: Proof,
    side_note: &SideNote,
    max_log_size: u32,
) -> Result<(), VerificationError> {
    verify_with_options(
        proof,
        side_note,
        max_log_size,
        &crate::proof::PcsPolicy::STANDARD,
    )
}

/// Enforce a custom `PcsPolicy` (FRI shape + PoW floor)
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
        policy,
        components,
        prover_components,
        None,
    )
}

fn verify_with_options_explicit_components(
    proof: Proof,
    side_note: &SideNote,
    max_log_size: u32,
    policy: &crate::proof::PcsPolicy,
    components: &[&dyn crate::framework::MachineComponent],
    prover_components: &[&dyn crate::framework::MachineProverComponent],
    boundary_positions: Option<crate::boundary_binding::BoundaryChipPositions>,
) -> Result<(), VerificationError> {
    // Reject proofs from a different AIR shape early, before
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
    // Cap log_sizes so a malicious prover can't force a
    // giant Merkle commitment phase.
    if let Some(&offending) = proof.log_sizes.iter().find(|&&ls| ls > max_log_size) {
        return Err(VerificationError::InvalidStructure(format!(
            "proof log_size {offending} exceeds cap {max_log_size}"
        )));
    }
    // Enforce the PcsPolicy floor — reject under-spec'd
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
        initial_state,
        final_state,
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
    let verifier_channel = &mut ProverChannel::default();
    claimed_log_sizes.iter().for_each(|log_size| {
        verifier_channel.mix_u64(*log_size as u64);
    });

    // Verify preprocessed trace commitment
    verify_preprocessed_trace(
        &proof,
        side_note,
        verifier_channel,
        &claimed_log_sizes,
        &config,
        prover_components,
    )?;

    let commitment_scheme = &mut CommitmentSchemeVerifier::<ProverMerkleChannel>::new(config);
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

    // Mix `proof.{initial,final}_state` (registers, pc,
    // timestamp) into the FS transcript. Mirrors the prover-side mix in
    // `prove.rs` immediately after the main-trace commit, so the lookup
    // elements drawn next depend on the claimed boundary states. Gated
    // on `side_note.closing_chip_active` — the default `verify` path
    // sees the flag via the prover-mutated side_note, and chip-isolated
    // `verify_with_explicit_components` only flips it when the caller's
    // slice includes the boundary + closing chip pair. Order MUST match
    // the prover (initial first, then final). `memory_commitment` stays
    // unmixed (computed outside the circuit).
    if side_note.closing_chip_active {
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
        // Format v7: entering then exit RAM Merkle root, 4 LE u64 each.
        for chunk in initial_state.memory_root.chunks_exact(8) {
            verifier_channel.mix_u64(u64::from_le_bytes(chunk.try_into().unwrap()));
        }
        for chunk in final_state.memory_root.chunks_exact(8) {
            verifier_channel.mix_u64(u64::from_le_bytes(chunk.try_into().unwrap()));
        }
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
    if side_note.closing_chip_active {
        if let Some(positions) = &boundary_positions {
            crate::boundary_binding::check_boundary_claimed_sums(
                &initial_state,
                &final_state,
                &lookup_elements,
                &claimed_sums,
                positions,
            )
            .map_err(|msg| VerificationError::InvalidStructure(msg.to_string()))?;
        }
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
    proof: &stwo::core::proof::StarkProof<ProverMerkleHasher>,
    side_note: &SideNote,
    verifier_channel: &ProverChannel,
    log_sizes: &[u32],
    config: &PcsConfig,
    components: &[&dyn crate::framework::MachineProverComponent],
) -> Result<(), VerificationError> {
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
    let twiddles = ProverBackend::precompute_twiddles(
        CanonicCoset::new(max_constraint_log_degree_bound + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let commitment_scheme =
        &mut CommitmentSchemeProver::<ProverBackend, ProverMerkleChannel>::new(*config, &twiddles);

    let mut tree_builder = commitment_scheme.tree_builder();
    for (c, log_size) in components.iter().zip(log_sizes) {
        tree_builder.extend_evals(for_commit(
            c.generate_preprocessed_trace(*log_size, side_note),
        ));
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

/// One active component's OODS mask, sliced from a real proof's `sampled_values`
/// for the recursion verifier-AIR — the chip's columns in read order, ready
/// to drive the auto-witnessing evaluator. `mask[interaction][column][offset]`;
/// the preprocessed tree (`mask[0]`) is the FULL column set, indexed through
/// `preproc_indices` (stwo's preprocessed remap).
pub struct ComponentOodsMask {
    pub mask: alloc::vec::Vec<alloc::vec::Vec<alloc::vec::Vec<SecureField>>>,
    pub preproc_indices: alloc::vec::Vec<usize>,
}

/// The OODS data reconstructed from a real canonical segment proof by replaying
/// the verifier's Fiat-Shamir transcript (the channel-affecting steps of
/// [`verify_with_options_explicit_components`] + the stwo verifier head) — the
/// inputs the recursion verifier-AIR re-evaluates the inner composition against,
/// plus the proof's own `composition_oods_eval` (the DEEP-ALI ground truth).
pub struct OodsReconstruction {
    /// `(chip_idx, log_size, claimed_sum)` per active component, in
    /// `BASE_COMPONENTS` order.
    pub comps: alloc::vec::Vec<(usize, u32, SecureField)>,
    /// Per-active-component OODS mask, sliced from the proof's `sampled_values`.
    pub component_masks: alloc::vec::Vec<ComponentOodsMask>,
    /// The relation elements drawn from the replayed transcript.
    pub lookup_elements: AllLookupElements,
    pub random_coeff: SecureField,
    pub denom_inverse: SecureField,
    pub oods_x_doubled: SecureField,
    /// The composition-trace OODS mask (the DEEP-ALI recombination inputs).
    pub comp_mask: [SecureField; 8],
    /// The proof's `composition_oods_eval` — what the in-AIR re-eval must match.
    pub composition_value: SecureField,
}

/// Replay a real canonical segment proof's verifier transcript to the OODS point
/// and return everything the verifier-AIR needs to re-evaluate the inner
/// composition in-AIR (the per-component masks sliced from `sampled_values`, the
/// drawn `lookup_elements`/`random_coeff`/`oods_point`-derived scalars, the
/// per-component `claimed_sum`/`log_size`) plus the proof's own composition value.
///
/// This is the read-only reconstruction the recursion harness drives its
/// auto-witnessing evaluator against; it mirrors the channel-affecting steps of
/// [`verify_with_options_explicit_components`] (the preprocessed-root *check*
/// clones the channel, so it is skipped) followed by the stwo verifier head
/// (draw `random_coeff`, commit the composition tree, draw `oods_point`).
///
/// PRECONDITION (same as [`verify`]): `side_note` must be in the prover-left
/// state (`closing_chip_active` set), so the boundary-state mix matches the
/// prover's transcript — else the drawn challenges diverge and the returned OODS
/// data is silently wrong. This is a recursion-harness reconstruction, NOT a
/// trust boundary: it assumes a well-formed proof (its `component_mask` popcount
/// equals `log_sizes`/`claimed_sums` length, and an 8-column composition tree).
pub fn reconstruct_oods_for_recursion(proof: &Proof, side_note: &SideNote) -> OodsReconstruction {
    use stwo::core::air::Components;
    use stwo::core::circle::CirclePoint;
    use stwo::core::constraints::coset_vanishing;
    use stwo::core::fields::FieldExpOps;
    use stwo::core::pcs::utils::try_get_lifting_log_size;
    use stwo::core::verifier::COMPOSITION_LOG_SPLIT;

    let config = proof.pcs_config;
    let sp = &proof.stark_proof;
    let claimed_log_sizes = &proof.log_sizes;
    let claimed_sums = &proof.claimed_sums;

    // The positional zips below (sizes / verifier_components / per-component
    // slices / comps) assume `component_mask` popcount == log_sizes ==
    // claimed_sums; the production verifier enforces this (verify.rs:221-230),
    // so assert it here too rather than silently truncate on a malformed proof.
    let n_active = (proof.component_mask).count_ones() as usize;
    assert_eq!(
        n_active,
        claimed_log_sizes.len(),
        "component_mask popcount must equal log_sizes length"
    );
    assert_eq!(
        n_active,
        claimed_sums.len(),
        "component_mask popcount must equal claimed_sums length"
    );

    // Select components by the PROOF's component_mask, not the side note's
    // natural-active set: a canonical proof forces ALL 31 (padding inactive
    // chips), so `active_components_verifier(side_note)` (which drops e.g.
    // Blake2b/Ristretto for a program that never uses them) would not match the
    // proof's trace layout.
    let active_indices: alloc::vec::Vec<usize> = (0..super::chip_idx::COUNT)
        .filter(|&i| proof.component_mask & (1 << i) != 0)
        .collect();
    let components_owned: alloc::vec::Vec<&dyn crate::framework::MachineComponent> = active_indices
        .iter()
        .map(|&i| super::BASE_COMPONENTS[i] as &dyn crate::framework::MachineComponent)
        .collect();
    let components: &[&dyn crate::framework::MachineComponent] = &components_owned;

    // ── Replay the FS transcript (channel-affecting steps only) ─────────────
    let verifier_channel = &mut ProverChannel::default();
    claimed_log_sizes
        .iter()
        .for_each(|ls| verifier_channel.mix_u64(*ls as u64));

    let commitment_scheme = &mut CommitmentSchemeVerifier::<ProverMerkleChannel>::new(config);
    let sizes: alloc::vec::Vec<TreeVec<alloc::vec::Vec<u32>>> = components
        .iter()
        .zip(claimed_log_sizes)
        .map(|(c, &ls)| c.trace_sizes(ls))
        .collect();
    let mut log_sizes = TreeVec::concat_cols(sizes.into_iter());
    log_sizes[PREPROCESSED_TRACE_IDX] = components
        .iter()
        .zip(claimed_log_sizes)
        .flat_map(|(c, &ls)| c.preprocessed_trace_sizes(ls))
        .collect();

    for idx in [PREPROCESSED_TRACE_IDX, ORIGINAL_TRACE_IDX] {
        commitment_scheme.commit(sp.commitments[idx], &log_sizes[idx], verifier_channel);
    }

    if side_note.closing_chip_active {
        for r in &proof.initial_state.registers {
            verifier_channel.mix_u64(*r);
        }
        for r in &proof.final_state.registers {
            verifier_channel.mix_u64(*r);
        }
        verifier_channel.mix_u64(proof.initial_state.pc as u64);
        verifier_channel.mix_u64(proof.initial_state.timestamp);
        verifier_channel.mix_u64(proof.final_state.pc as u64);
        verifier_channel.mix_u64(proof.final_state.timestamp);
        for chunk in proof.initial_state.memory_root.chunks_exact(8) {
            verifier_channel.mix_u64(u64::from_le_bytes(chunk.try_into().unwrap()));
        }
        for chunk in proof.final_state.memory_root.chunks_exact(8) {
            verifier_channel.mix_u64(u64::from_le_bytes(chunk.try_into().unwrap()));
        }
    }

    let mut lookup_elements = AllLookupElements::default();
    components
        .iter()
        .for_each(|c| c.draw_lookup_elements(&mut lookup_elements, verifier_channel));

    let tree_span_provider = &mut TraceLocationAllocator::default();
    let verifier_components: alloc::vec::Vec<alloc::boxed::Box<dyn Component>> = components
        .iter()
        .zip(claimed_sums)
        .zip(claimed_log_sizes)
        .map(|((c, cs), &ls)| c.to_component(tree_span_provider, &lookup_elements, ls, *cs))
        .collect();

    verifier_channel.mix_felts(claimed_sums);
    commitment_scheme.commit(
        sp.commitments[INTERACTION_TRACE_IDX],
        &log_sizes[INTERACTION_TRACE_IDX],
        verifier_channel,
    );

    // ── stwo verifier head: random_coeff, composition commit, oods_point ────
    let components_ref: alloc::vec::Vec<&dyn Component> =
        verifier_components.iter().map(|c| &**c).collect();
    let n_preprocessed_columns = log_sizes[PREPROCESSED_TRACE_IDX].len();
    let comps_struct = Components {
        components: components_ref,
        n_preprocessed_columns,
    };
    let split = comps_struct.composition_log_degree_bound() - COMPOSITION_LOG_SPLIT;
    let lifting_log_size =
        try_get_lifting_log_size(&config, split + config.fri_config.log_blowup_factor).unwrap();
    let mlbd = lifting_log_size - config.fri_config.log_blowup_factor;

    let random_coeff = verifier_channel.draw_secure_felt();
    let n_comp_cols = sp.sampled_values.last().unwrap().len();
    // COMPOSITION_LOG_SPLIT = 1 ⇒ 2·SECURE_EXTENSION_DEGREE = 8 composition
    // columns; the `comp_mask`/recombination below depend on exactly that shape.
    assert_eq!(n_comp_cols, 8, "expected an 8-column composition tree");
    commitment_scheme.commit(
        *sp.commitments.last().unwrap(),
        &alloc::vec![mlbd; n_comp_cols],
        verifier_channel,
    );
    let oods_point = CirclePoint::<SecureField>::get_random_point(verifier_channel);

    let denom_inverse = coset_vanishing(CanonicCoset::new(mlbd).coset, oods_point).inverse();
    let oods_x_doubled = oods_point.repeated_double(mlbd - 1).x;
    let comp_mask: [SecureField; 8] =
        core::array::from_fn(|i| sp.sampled_values.last().unwrap()[i][0]);

    // The proof's composition_oods_eval = the recombined composition mask
    // (`left + oods_x_doubled · right`). The verifier checked this equals
    // `eval_composition_polynomial_at_point`, so it is the DEEP-ALI ground truth
    // the in-AIR re-eval must reproduce — computed directly here (no second
    // PointEvaluator pass over the components).
    let left =
        SecureField::from_partial_evals([comp_mask[0], comp_mask[1], comp_mask[2], comp_mask[3]]);
    let right =
        SecureField::from_partial_evals([comp_mask[4], comp_mask[5], comp_mask[6], comp_mask[7]]);
    let composition_value = left + oods_x_doubled * right;

    // ── Slice the per-component masks (concat order = BASE_COMPONENTS order) ─
    let preproc_full = sp.sampled_values[PREPROCESSED_TRACE_IDX].clone();
    let mut component_masks = alloc::vec::Vec::new();
    let mut main_off = 0usize;
    let mut int_off = 0usize;
    for ((c, &ls), vc) in components
        .iter()
        .zip(claimed_log_sizes)
        .zip(&verifier_components)
    {
        let ts = c.trace_sizes(ls);
        let n_main = ts[ORIGINAL_TRACE_IDX].len();
        let n_int = ts[INTERACTION_TRACE_IDX].len();
        let main_slice =
            sp.sampled_values[ORIGINAL_TRACE_IDX][main_off..main_off + n_main].to_vec();
        let int_slice = sp.sampled_values[INTERACTION_TRACE_IDX][int_off..int_off + n_int].to_vec();
        main_off += n_main;
        int_off += n_int;
        component_masks.push(ComponentOodsMask {
            mask: alloc::vec![preproc_full.clone(), main_slice, int_slice],
            preproc_indices: vc.preprocessed_column_indices(),
        });
    }

    let comps = active_indices
        .iter()
        .zip(claimed_log_sizes)
        .zip(claimed_sums)
        .map(|((&idx, &ls), &cs)| (idx, ls, cs))
        .collect();

    OodsReconstruction {
        comps,
        component_masks,
        lookup_elements,
        random_coeff,
        denom_inverse,
        oods_x_doubled,
        comp_mask,
        composition_value,
    }
}

/// The verifier-side state the native-recursion data extraction builds by
/// replaying the zkpvm-specific FS-mix prefix of `verify` (the single source of
/// truth for that load-bearing mix order — see [`recursion_verify_prefix`]).
#[cfg(feature = "poseidon2-channel")]
struct RecursionVerifyContext {
    /// The relation elements drawn after the boundary-state mix (the `z`/`alpha`
    /// the boundary-binding + OODS-embed consumers combine over).
    lookup_elements: AllLookupElements,
    /// The stwo verifier components, in active order.
    verifier_components: alloc::vec::Vec<alloc::boxed::Box<dyn Component>>,
}

/// Replay the zkpvm-specific Fiat-Shamir prefix `verify` drives on `channel` and
/// `commitment_scheme`, up to and including the interaction-tree commit: mix the
/// per-component log sizes, commit the preprocessed + main trees, mix the boundary
/// state (gated on `closing_chip_active`), draw the lookup elements, then mix the
/// claimed sums and commit the interaction tree. This is the single definition of
/// that mix order (the order is load-bearing for soundness — a divergence silently
/// corrupts every downstream challenge), shared by [`record_canonical_transcript`]
/// and [`extract_recursion_data`]. After it returns, the caller drives the stwo
/// verifier head (random_coeff / composition commit / OODS) on the same channel.
///
/// Components are selected by the proof's `component_mask` (canonical forces all
/// 31), matching [`reconstruct_oods_for_recursion`]'s trace layout. The
/// preprocessed-root check (`verify_preprocessed_trace`) clones the channel, so it
/// has no transcript effect and is skipped.
#[cfg(feature = "poseidon2-channel")]
fn recursion_verify_prefix(
    proof: &Proof,
    side_note: &SideNote,
    channel: &mut ProverChannel,
    commitment_scheme: &mut CommitmentSchemeVerifier<ProverMerkleChannel>,
) -> RecursionVerifyContext {
    let sp = &proof.stark_proof;
    let claimed_log_sizes = &proof.log_sizes;
    let claimed_sums = &proof.claimed_sums;

    let n_active = (proof.component_mask).count_ones() as usize;
    assert_eq!(
        n_active,
        claimed_log_sizes.len(),
        "component_mask popcount must equal log_sizes length"
    );
    assert_eq!(
        n_active,
        claimed_sums.len(),
        "component_mask popcount must equal claimed_sums length"
    );

    let components_owned: alloc::vec::Vec<&dyn crate::framework::MachineComponent> = (0
        ..super::chip_idx::COUNT)
        .filter(|&i| proof.component_mask & (1 << i) != 0)
        .map(|i| super::BASE_COMPONENTS[i] as &dyn crate::framework::MachineComponent)
        .collect();
    let components: &[&dyn crate::framework::MachineComponent] = &components_owned;

    claimed_log_sizes
        .iter()
        .for_each(|ls| channel.mix_u64(*ls as u64));

    let sizes: alloc::vec::Vec<TreeVec<alloc::vec::Vec<u32>>> = components
        .iter()
        .zip(claimed_log_sizes)
        .map(|(c, &ls)| c.trace_sizes(ls))
        .collect();
    let mut log_sizes = TreeVec::concat_cols(sizes.into_iter());
    log_sizes[PREPROCESSED_TRACE_IDX] = components
        .iter()
        .zip(claimed_log_sizes)
        .flat_map(|(c, &ls)| c.preprocessed_trace_sizes(ls))
        .collect();

    for idx in [PREPROCESSED_TRACE_IDX, ORIGINAL_TRACE_IDX] {
        commitment_scheme.commit(sp.commitments[idx], &log_sizes[idx], channel);
    }

    if side_note.closing_chip_active {
        for r in &proof.initial_state.registers {
            channel.mix_u64(*r);
        }
        for r in &proof.final_state.registers {
            channel.mix_u64(*r);
        }
        channel.mix_u64(proof.initial_state.pc as u64);
        channel.mix_u64(proof.initial_state.timestamp);
        channel.mix_u64(proof.final_state.pc as u64);
        channel.mix_u64(proof.final_state.timestamp);
        for chunk in proof.initial_state.memory_root.chunks_exact(8) {
            channel.mix_u64(u64::from_le_bytes(chunk.try_into().unwrap()));
        }
        for chunk in proof.final_state.memory_root.chunks_exact(8) {
            channel.mix_u64(u64::from_le_bytes(chunk.try_into().unwrap()));
        }
    }

    let mut lookup_elements = AllLookupElements::default();
    components
        .iter()
        .for_each(|c| c.draw_lookup_elements(&mut lookup_elements, channel));

    let tree_span_provider = &mut TraceLocationAllocator::default();
    let verifier_components: alloc::vec::Vec<alloc::boxed::Box<dyn Component>> = components
        .iter()
        .zip(claimed_sums)
        .zip(claimed_log_sizes)
        .map(|((c, cs), &ls)| c.to_component(tree_span_provider, &lookup_elements, ls, *cs))
        .collect();

    channel.mix_felts(claimed_sums);
    commitment_scheme.commit(
        sp.commitments[INTERACTION_TRACE_IDX],
        &log_sizes[INTERACTION_TRACE_IDX],
        channel,
    );

    RecursionVerifyContext {
        lookup_elements,
        verifier_components,
    }
}

/// The full Fiat-Shamir transcript of a real canonical segment proof's
/// verification, recorded as an ordered Poseidon2 permutation sequence — the
/// ground truth the native-recursion verifier-AIR's in-AIR `ChannelChip` replay
/// reproduces row-for-row, and the source of every channel-derived challenge
/// (composition `random_coeff`, OODS point, DEEP `random_coeff`, per-FRI-layer
/// fold alphas, query positions) the downstream consumers latch.
#[cfg(feature = "poseidon2-channel")]
pub struct RecursionTranscript {
    /// Every permutation the verifier transcript performed, in caller order.
    pub records: alloc::vec::Vec<crate::poseidon2::PermRecord>,
    /// The number of permutations performed BEFORE stwo's verifier head — i.e.
    /// through the interaction-tree commit. The composition `random_coeff` is the
    /// first `Squeeze` record at-or-after this index (the head's first draw); the
    /// records before it are the zkpvm prefix (log-size mix, preprocessed+main
    /// commit, boundary-state mix, per-relation lookup-element draws, claimed-sum
    /// mix, interaction commit).
    pub prefix_len: usize,
}

/// Record a real canonical segment proof's full verifier transcript by handing a
/// recording [`Poseidon2M31Channel`](crate::poseidon2::Poseidon2M31Channel)
/// through the SAME Fiat-Shamir sequence [`verify`] drives — the zkpvm prefix
/// ([`recursion_verify_prefix`]) followed by stwo's `verify` head + FRI commit +
/// PoW + query sampling + Merkle decommit. Every absorb/squeeze/pow permutation
/// lands in [`RecursionTranscript::records`] in caller order. This calls the REAL
/// stwo `verify`, so its records are the ground truth [`extract_recursion_data`]'s
/// step-by-step replay is cross-checked against.
///
/// Pairs with [`reconstruct_oods_for_recursion`] (same prefix, returns the OODS
/// masks + scalars). PRECONDITION: `side_note` prover-left. Panics if the proof
/// fails to verify (recursion harness assumes a valid proof).
#[cfg(feature = "poseidon2-channel")]
pub fn record_canonical_transcript(proof: &Proof, side_note: &SideNote) -> RecursionTranscript {
    use alloc::rc::Rc;
    use core::cell::RefCell;

    let recorder = Rc::new(RefCell::new(alloc::vec::Vec::new()));
    let channel = &mut crate::poseidon2::Poseidon2M31Channel::recording(recorder.clone());
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<ProverMerkleChannel>::new(proof.pcs_config);
    let ctx = recursion_verify_prefix(proof, side_note, channel, commitment_scheme);
    let components_ref: alloc::vec::Vec<&dyn Component> =
        ctx.verifier_components.iter().map(|c| &**c).collect();

    // Everything so far is the zkpvm prefix; stwo's `verify` drives the head
    // (random_coeff, composition commit, oods, sampled mix, DEEP coeff), the FRI
    // commit (per-layer roots + fold alphas), PoW, and query sampling next.
    let prefix_len = recorder.borrow().len();
    stwo::core::verifier::verify(
        &components_ref,
        channel,
        commitment_scheme,
        proof.stark_proof.clone(),
    )
    .expect("record_canonical_transcript: proof must verify (recursion harness precondition)");

    let records = recorder.borrow().clone();
    RecursionTranscript {
        records,
        prefix_len,
    }
}

/// Every transcript-derived datum the per-child verifier-AIR's FRI / DEEP-quotient
/// / Merkle-decommit consumers need from a real canonical segment proof, extracted
/// by replaying stwo's `verify` head + `verify_values` step by step via PUBLIC
/// stwo calls (so each challenge / query set is captured as it is drawn, rather
/// than fished out of the raw record stream). The raw per-tree / per-FRI-layer
/// decommit data (roots, `queried_values`, `hash_witness`, `fri_witness`,
/// `last_layer_poly`) is read directly from `proof.stark_proof` using these query
/// positions — it is not duplicated here.
#[cfg(feature = "poseidon2-channel")]
pub struct RecursionData {
    /// The recorded transcript (records + prefix_len), identical to
    /// [`record_canonical_transcript`]'s — cross-checked equal in the gate test.
    pub transcript: RecursionTranscript,
    /// Composition `random_coeff` (the Horner base the OODS embed folds under).
    pub random_coeff: SecureField,
    /// DEEP-quotient `random_coeff` (the `fri_answers` / first-layer-eval coeff).
    pub deep_coeff: SecureField,
    /// The OODS point.
    pub oods_point: stwo::core::circle::CirclePoint<SecureField>,
    /// Per-FRI-layer fold alphas, in fold order (first layer then each inner
    /// layer) — captured by bracketing `FriVerifier::commit`. `len()` ==
    /// `1 + fri_proof.inner_layers.len()`.
    pub fold_alphas: alloc::vec::Vec<SecureField>,
    /// The drawn FRI query positions on the first-layer domain (sorted + deduped;
    /// `len() <= n_queries`). Trace trees 1..4 decommit at these.
    pub query_positions: alloc::vec::Vec<usize>,
    /// The preprocessed tree's remapped query positions (tree 0 decommits here).
    pub preprocessed_query_positions: alloc::vec::Vec<usize>,
    /// The first-layer FRI eval per query position (`fri_answers` — the DEEP
    /// quotients), the input the in-AIR FRI fold chain folds down to the last layer.
    pub first_layer_evals: alloc::vec::Vec<SecureField>,
    /// The relation elements drawn after the boundary-state mix (the `z`/`alpha`
    /// the boundary-binding + OODS-embed consumers combine over) — the same set
    /// [`reconstruct_oods_for_recursion`] returns.
    pub lookup_elements: AllLookupElements,
    /// The FRI first-layer domain log size (= composition tree height).
    pub lifting_log_size: u32,
    /// `lifting_log_size - log_blowup_factor` (the OODS vanishing-domain log size).
    pub max_log_degree_bound: u32,
    /// The Merkle height of each committed trace tree (preprocessed, main,
    /// interaction, composition), in tree order — the number of `hash_children`
    /// levels the streamed per-tree decommit re-hashes. Trees 1.. decommit at
    /// `query_positions`; tree 0 (preprocessed) at `preprocessed_query_positions`.
    pub tree_heights: alloc::vec::Vec<u32>,
    /// Per-tree committed column log sizes, in COMMIT order (the order the columns
    /// appear in `queried_values`). The lifted Merkle leaf hashes the row of all a
    /// tree's columns sorted ASCENDING by log size (stable) — so the streamed
    /// decommit must order its leaf row by these.
    pub tree_column_log_sizes: alloc::vec::Vec<alloc::vec::Vec<u32>>,
    /// The DEEP-quotient (`fri_answers`) decomposition in AIR-friendly form: the
    /// sample batches (grouped by sample point), each carrying per-column the
    /// FLATTENED column index (into `queried_values.flatten()`) + the
    /// complex-conjugate line coefficients `(a, b, c)`. The in-AIR FRI layer-0
    /// input is, per query at domain point `p`,
    /// `Σ_batch (1/line(z, z̄)(p)) · Σ_col (queried[col]·c − (a·p.y + b))` — this
    /// binds the trace-decommit leaves to the OODS samples.
    pub deep_batches: alloc::vec::Vec<DeepBatch>,
}

/// One DEEP-quotient sample batch: a sample point and the columns sampled there,
/// each with its flattened column index + line coefficients. See
/// [`RecursionData::deep_batches`].
#[cfg(feature = "poseidon2-channel")]
pub struct DeepBatch {
    pub point: stwo::core::circle::CirclePoint<SecureField>,
    /// `(flattened column index, a, b, c)` per column in this batch.
    pub cols: alloc::vec::Vec<(usize, SecureField, SecureField, SecureField)>,
    /// Per column (parallel to `cols`): the OODS `sample_value` `v` and the DEEP
    /// random-coeff power `α^i`. These DERIVE `(a, b, c)` via
    /// `complex_conjugate_line_coeffs` (`a=α^i(v̄−v)`, `c=α^i(z̄.y−z.y)`,
    /// `b=α^i(v·c′−a′·z.y)`), so the in-AIR `(a,b,c)` derivation (step 4) reads these
    /// rather than trusting `(a,b,c)` as free host values. `v` is the same OODS mask
    /// the embed routes ⇒ the leaf↔OODS coupling binds through it.
    pub col_samples: alloc::vec::Vec<(SecureField, SecureField)>,
}

/// Extract every transcript-derived datum the per-child verifier-AIR needs from a
/// real canonical segment proof (see [`RecursionData`]). Replays stwo's `verify`
/// head + `verify_values` via PUBLIC stwo calls on a recording channel, capturing
/// the composition/DEEP coeffs, the OODS point, the per-FRI-layer fold alphas (by
/// bracketing `FriVerifier::commit`), the query positions, and the first-layer FRI
/// evals (`fri_answers`); it VALIDATES the extraction end-to-end by running the
/// real per-tree Merkle decommit and `FriVerifier::decommit` (both must succeed).
///
/// The replay reproduces the same transcript [`record_canonical_transcript`]
/// captures from the real stwo `verify` (cross-checked equal in the gate test), so
/// the captured challenges are exactly what the proof was produced under.
///
/// PRECONDITION: `side_note` prover-left. Panics if any validation fails (the
/// recursion harness assumes a well-formed, valid proof).
#[cfg(feature = "poseidon2-channel")]
pub fn extract_recursion_data(proof: &Proof, side_note: &SideNote) -> RecursionData {
    use alloc::rc::Rc;
    use core::cell::RefCell;
    use core::iter::zip;
    use stwo::core::air::Components;
    use stwo::core::circle::CirclePoint;
    use stwo::core::fields::qm31::SECURE_EXTENSION_DEGREE;
    use stwo::core::fri::{CirclePolyDegreeBound, FriVerifier};
    use stwo::core::pcs::quotients::{PointSample, fri_answers};
    use stwo::core::pcs::utils::{prepare_preprocessed_query_positions, try_get_lifting_log_size};
    use stwo::core::verifier::COMPOSITION_LOG_SPLIT;

    let config = proof.pcs_config;
    let sp = proof.stark_proof.clone();

    let recorder = Rc::new(RefCell::new(alloc::vec::Vec::new()));
    let channel = &mut crate::poseidon2::Poseidon2M31Channel::recording(recorder.clone());
    let commitment_scheme = &mut CommitmentSchemeVerifier::<ProverMerkleChannel>::new(config);
    let ctx = recursion_verify_prefix(proof, side_note, channel, commitment_scheme);
    let prefix_len = recorder.borrow().len();

    // ── stwo verifier head (verifier.rs `verify_ex`), replicated via pub calls ─
    let components_ref: alloc::vec::Vec<&dyn Component> =
        ctx.verifier_components.iter().map(|c| &**c).collect();
    let n_preprocessed_columns = commitment_scheme.trees[PREPROCESSED_TRACE_IDX]
        .column_log_sizes
        .len();
    let components_struct = Components {
        components: components_ref.clone(),
        n_preprocessed_columns,
    };
    let split = components_struct.composition_log_degree_bound() - COMPOSITION_LOG_SPLIT;
    let lifting_log_size =
        try_get_lifting_log_size(&config, split + config.fri_config.log_blowup_factor).unwrap();
    let max_log_degree_bound = lifting_log_size - config.fri_config.log_blowup_factor;

    let random_coeff = channel.draw_secure_felt();
    commitment_scheme.commit(
        *sp.commitments.last().unwrap(),
        &alloc::vec![max_log_degree_bound; 2 * SECURE_EXTENSION_DEGREE],
        channel,
    );
    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);
    let mut sample_points = components_struct.mask_points(oods_point, max_log_degree_bound, false);
    sample_points.push(alloc::vec![alloc::vec![oods_point]; 2 * SECURE_EXTENSION_DEGREE]);
    // `lifting_log_size` must equal the committed composition tree height
    // (what `verify_values` uses); assert it so a head/verify_values mismatch
    // surfaces loudly rather than as a wrong-challenge silent failure.
    assert_eq!(
        lifting_log_size,
        commitment_scheme.trees.last().unwrap().height,
        "lifting_log_size must equal the composition tree height"
    );

    // ── verify_values (pcs/verifier.rs), replicated via pub calls ──────────────
    channel.mix_felts(&sp.sampled_values.clone().flatten_cols());
    let deep_coeff = channel.draw_secure_felt();
    let bound = CirclePolyDegreeBound::new(lifting_log_size - config.fri_config.log_blowup_factor);

    // Capture the per-layer fold alphas by bracketing the FRI commit: the squeezes
    // it performs (interleaved with the per-layer root absorbs) ARE the alphas.
    let fri_before = recorder.borrow().len();
    let mut fri_verifier = FriVerifier::<ProverMerkleChannel>::commit(
        channel,
        config.fri_config,
        sp.fri_proof.clone(),
        bound,
    )
    .expect("FRI commit");
    let fold_alphas: alloc::vec::Vec<SecureField> = recorder.borrow()[fri_before..]
        .iter()
        .filter(|r| r.kind == crate::poseidon2::PermKind::Squeeze)
        .map(|r| SecureField::from_m31_array([r.output[0], r.output[1], r.output[2], r.output[3]]))
        .collect();

    assert!(
        channel.verify_pow_nonce(config.pow_bits, sp.proof_of_work),
        "FRI proof-of-work"
    );
    channel.mix_u64(sp.proof_of_work);
    let query_positions = fri_verifier.sample_query_positions(channel);
    let preprocessed_query_positions = prepare_preprocessed_query_positions(
        &query_positions,
        lifting_log_size,
        commitment_scheme.trees[PREPROCESSED_TRACE_IDX].height,
    );

    // Validate the per-tree Merkle decommits (tree 0 uses the remapped positions).
    let query_positions_tree = TreeVec::new(
        commitment_scheme
            .trees
            .iter()
            .enumerate()
            .map(|(i, _)| {
                if i == PREPROCESSED_TRACE_IDX {
                    preprocessed_query_positions.as_slice()
                } else {
                    query_positions.as_slice()
                }
            })
            .collect::<alloc::vec::Vec<_>>(),
    );
    commitment_scheme
        .trees
        .as_ref()
        .zip_eq(sp.decommitments.clone())
        .zip_eq(sp.queried_values.clone())
        .zip_eq(query_positions_tree)
        .map(|(((tree, decommitment), queried_values), qpos)| {
            tree.verify(qpos, queried_values, decommitment)
        })
        .0
        .into_iter()
        .collect::<Result<(), _>>()
        .expect("trace-tree Merkle decommit");

    // The first-layer FRI evals (DEEP quotients), then validate the FRI decommit.
    let column_log_sizes: TreeVec<alloc::vec::Vec<u32>> = TreeVec::new(
        commitment_scheme
            .trees
            .iter()
            .map(|t| t.column_log_sizes.clone())
            .collect::<alloc::vec::Vec<_>>(),
    );
    let samples = sample_points
        .zip_cols(sp.sampled_values.clone())
        .map_cols(|(pts, vals)| {
            zip(pts, vals)
                .map(|(point, value)| PointSample { point, value })
                .collect::<alloc::vec::Vec<_>>()
        });

    // DEEP-quotient decomposition (the AIR's `fri_answers` spec): batches grouped
    // by sample point, each carrying per-column the flattened index + line coeffs.
    // Computed from clones BEFORE `fri_answers` consumes `samples`/`column_log_sizes`.
    let deep_batches = {
        use stwo::core::pcs::quotients::{
            ColumnSampleBatch, build_samples_with_randomness_and_periodicity, column_line_coeffs,
        };
        let cls: alloc::vec::Vec<_> = column_log_sizes
            .0
            .iter()
            .map(|t| t.clone().into_iter())
            .collect();
        let swr = build_samples_with_randomness_and_periodicity(
            &samples,
            cls,
            lifting_log_size,
            deep_coeff,
        );
        let flat: alloc::vec::Vec<_> = swr.iter().flatten().collect();
        let batches = ColumnSampleBatch::new_vec(&flat);
        let lcs = column_line_coeffs(&batches);
        batches
            .iter()
            .zip(lcs)
            .map(|(b, lc)| DeepBatch {
                point: b.point,
                cols: b
                    .cols_vals_randpows
                    .iter()
                    .zip(lc)
                    .map(|(nd, (a, bb, c))| (nd.column_index, a, bb, c))
                    .collect(),
                col_samples: b
                    .cols_vals_randpows
                    .iter()
                    .map(|nd| (nd.sample_value, nd.random_coeff))
                    .collect(),
            })
            .collect::<alloc::vec::Vec<_>>()
    };

    let first_layer_evals = fri_answers(
        column_log_sizes,
        samples,
        deep_coeff,
        &query_positions,
        sp.queried_values.clone(),
        lifting_log_size,
    )
    .expect("fri_answers");
    fri_verifier
        .decommit(first_layer_evals.clone())
        .expect("FRI decommit");

    let records = recorder.borrow().clone();
    RecursionData {
        transcript: RecursionTranscript {
            records,
            prefix_len,
        },
        random_coeff,
        deep_coeff,
        oods_point,
        fold_alphas,
        query_positions,
        preprocessed_query_positions,
        first_layer_evals,
        lookup_elements: ctx.lookup_elements,
        lifting_log_size,
        max_log_degree_bound,
        tree_heights: commitment_scheme.trees.iter().map(|t| t.height).collect(),
        tree_column_log_sizes: commitment_scheme
            .trees
            .iter()
            .map(|t| t.column_log_sizes.clone())
            .collect(),
        deep_batches,
    }
}
