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
/// See `verify` for the default and `Phase 43` for the rationale.
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

/// Phase I.0 chip-isolated verify path — pair with `prove_with_explicit_components`.
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

    // Phase Z0: mix `proof.{initial,final}_state` (registers, pc,
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
        // Phase A (v7): entering then exit RAM Merkle root, 4 LE u64 each.
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
    // Phase 60: caller passes the same prover-trait component set the
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
/// for the P5.2 recursion verifier-AIR — the chip's columns in read order, ready
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
/// and return everything the P5.2 verifier-AIR needs to re-evaluate the inner
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
