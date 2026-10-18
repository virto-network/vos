//! The recursion seams: a real segment proof's verifier transcript replayed
//! and recorded, and the data the in-AIR verifier re-checks (the OODS masks
//! and scalars, the DEEP batches, the FRI fold challenges and query
//! positions) extracted from it. Not trust boundaries: each assumes a
//! well-formed, valid proof and panics otherwise.

use stwo::core::{
    air::Component,
    channel::Channel,
    fields::qm31::SecureField,
    pcs::{CommitmentSchemeVerifier, TreeVec},
    poly::circle::CanonicCoset,
};

use super::Proof;
use crate::lookups::AllLookupElements;
use crate::pcs::PcsStack;
use crate::trace::eval::{INTERACTION_TRACE_IDX, ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX};

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
/// `verify_with_options_explicit_components` + the stwo verifier head) — the
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
/// auto-witnessing evaluator against: the verifier's transcript prefix
/// ([`crate::proof::replay_prefix`]) followed by the stwo verifier head (draw
/// `random_coeff`, commit the composition tree, draw `oods_point`).
///
/// This is a recursion-harness reconstruction, NOT a trust boundary: it
/// assumes a well-formed proof (its `component_mask` popcount equals
/// `log_sizes`/`claimed_sums` length, and an 8-column composition tree).
pub fn reconstruct_oods_for_recursion(proof: &Proof) -> OodsReconstruction {
    let format = crate::proof::proof_format(proof).expect("an admitted proof format");
    crate::with_stack!(format.channel, Stack => reconstruct_oods_on::<Stack>(proof),
        unbuilt => panic!("format {}'s channel is not built", format.number))
}

fn reconstruct_oods_on<MC: PcsStack>(proof: &Proof) -> OodsReconstruction {
    use stwo::core::air::Components;
    use stwo::core::circle::CirclePoint;
    use stwo::core::constraints::coset_vanishing;
    use stwo::core::fields::FieldExpOps;
    use stwo::core::pcs::utils::try_get_lifting_log_size;
    use stwo::core::verifier::COMPOSITION_LOG_SPLIT;

    let config = proof.pcs_config;
    let sp = MC::stark(&proof.stark_proof).expect("the proof's channel");
    let claimed_log_sizes = &proof.log_sizes;
    let claimed_sums = &proof.claimed_sums;
    let verifier_channel = &mut MC::C::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<MC>::new(config);
    let ctx = recursion_verify_prefix::<MC>(proof, verifier_channel, commitment_scheme);
    let components = &ctx.components;
    let log_sizes = &ctx.log_sizes;
    let verifier_components = &ctx.verifier_components;
    let lookup_elements = ctx.lookup_elements.clone();
    let active_indices = &ctx.active_indices;

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
        .zip(verifier_components)
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

/// The verifier-side state the recursion seams build through the transcript
/// prefix ([`super::transcript_prefix`]).
struct RecursionVerifyContext {
    components: alloc::vec::Vec<&'static dyn crate::framework::MachineComponent>,
    active_indices: alloc::vec::Vec<usize>,
    log_sizes: TreeVec<alloc::vec::Vec<u32>>,
    lookup_elements: AllLookupElements,
    verifier_components: alloc::vec::Vec<alloc::boxed::Box<dyn Component>>,
}

/// The verifier's transcript through the interaction tree's root, on a
/// well-formed proof, with the components the proof's mask selects.
fn recursion_verify_prefix<MC: PcsStack>(
    proof: &Proof,
    channel: &mut MC::C,
    commitment_scheme: &mut CommitmentSchemeVerifier<MC>,
) -> RecursionVerifyContext {
    let format = crate::proof::proof_format(proof).expect("an admitted proof format");
    let sp = MC::stark(&proof.stark_proof).expect("the proof's channel");

    // The positional zips assume `component_mask` popcount == log_sizes ==
    // claimed_sums; the production verifier enforces this, so assert it here
    // too rather than silently truncate on a malformed proof.
    let n_active = (proof.component_mask).count_ones() as usize;
    assert_eq!(
        n_active,
        proof.log_sizes.len(),
        "component_mask popcount must equal log_sizes length"
    );
    assert_eq!(
        n_active,
        proof.claimed_sums.len(),
        "component_mask popcount must equal claimed_sums length"
    );

    // Select components by the PROOF's component_mask: a canonical proof
    // forces every chip (padding inactive ones), so a side note's natural
    // active set would not match the proof's trace layout.
    let active_indices: alloc::vec::Vec<usize> = (0..crate::chip_idx::COUNT)
        .filter(|&i| proof.component_mask & (1 << i) != 0)
        .collect();
    let components: alloc::vec::Vec<&'static dyn crate::framework::MachineComponent> =
        active_indices
            .iter()
            .map(|&i| crate::BASE_COMPONENTS[i] as &dyn crate::framework::MachineComponent)
            .collect();
    let log_sizes = super::committed_log_sizes(&components, &proof.log_sizes);
    let prefix = super::transcript_prefix::<MC>(
        proof,
        sp,
        format,
        &components,
        &log_sizes,
        channel,
        commitment_scheme,
    )
    .expect("the transcript prefix (recursion harness precondition)");

    RecursionVerifyContext {
        components,
        active_indices,
        log_sizes,
        lookup_elements: prefix.lookup_elements,
        verifier_components: prefix.verifier_components,
    }
}

/// The full Fiat-Shamir transcript of a real canonical segment proof's
/// verification, recorded as an ordered Poseidon2 permutation sequence — the
/// ground truth the native-recursion verifier-AIR's in-AIR `ChannelChip` replay
/// reproduces row-for-row, and the source of every channel-derived challenge
/// (composition `random_coeff`, OODS point, DEEP `random_coeff`, per-FRI-layer
/// fold alphas, query positions) the downstream consumers latch.
pub struct RecursionTranscript {
    /// Every permutation the verifier transcript performed, in caller order.
    pub records: alloc::vec::Vec<crate::poseidon2::PermRecord>,
    /// The number of permutations performed BEFORE stwo's verifier head — i.e.
    /// through the interaction-tree commit. The composition `random_coeff` is the
    /// first `Squeeze` record at-or-after this index (the head's first draw); the
    /// records before it are the vos-pvm-proof prefix (log-size mix, preprocessed+main
    /// commit, boundary-state mix, per-relation lookup-element draws, claimed-sum
    /// mix, interaction commit).
    pub prefix_len: usize,
}

/// Record a real canonical segment proof's full verifier transcript by handing a
/// recording [`Poseidon2M31Channel`](crate::poseidon2::Poseidon2M31Channel)
/// through the SAME Fiat-Shamir sequence [`verify`](super::verify) drives — the vos-pvm-proof prefix
/// (`recursion_verify_prefix`) followed by stwo's `verify` head + FRI commit +
/// PoW + query sampling + Merkle decommit. Every absorb/squeeze/pow permutation
/// lands in [`RecursionTranscript::records`] in caller order. This calls the REAL
/// stwo `verify`, so its records are the ground truth [`extract_recursion_data`]'s
/// step-by-step replay is cross-checked against.
///
/// Pairs with [`reconstruct_oods_for_recursion`] (same prefix, returns the OODS
/// masks + scalars). Panics if the proof fails to verify (recursion harness assumes a valid proof).
pub fn record_canonical_transcript(proof: &Proof) -> RecursionTranscript {
    use alloc::rc::Rc;
    use core::cell::RefCell;

    let recorder = Rc::new(RefCell::new(alloc::vec::Vec::new()));
    let channel = &mut crate::poseidon2::Poseidon2M31Channel::recording(recorder.clone());
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<crate::poseidon2::P2MerkleChannel>::new(proof.pcs_config);
    let ctx = recursion_verify_prefix(proof, channel, commitment_scheme);
    let components_ref: alloc::vec::Vec<&dyn Component> =
        ctx.verifier_components.iter().map(|c| &**c).collect();

    // Everything so far is the vos-pvm-proof prefix; stwo's `verify` drives the head
    // (random_coeff, composition commit, oods, sampled mix, DEEP coeff), the FRI
    // commit (per-layer roots + fold alphas), PoW, and query sampling next.
    let prefix_len = recorder.borrow().len();
    stwo::core::verifier::verify(
        &components_ref,
        channel,
        commitment_scheme,
        poseidon2_stark(proof).clone(),
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
/// Panics if any validation fails (the recursion harness assumes a
/// well-formed, valid proof).
pub fn extract_recursion_data(proof: &Proof) -> RecursionData {
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
    let sp = poseidon2_stark(proof).clone();

    let recorder = Rc::new(RefCell::new(alloc::vec::Vec::new()));
    let channel = &mut crate::poseidon2::Poseidon2M31Channel::recording(recorder.clone());
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<crate::poseidon2::P2MerkleChannel>::new(config);
    let ctx = recursion_verify_prefix(proof, channel, commitment_scheme);
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
    let mut fri_verifier = FriVerifier::<crate::poseidon2::P2MerkleChannel>::commit(
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

/// The Poseidon2-M31 Stark proof of a proof the recursion seams take.
fn poseidon2_stark(
    proof: &Proof,
) -> &stwo::core::proof::StarkProof<crate::poseidon2::P2MerkleHasher> {
    <crate::poseidon2::P2MerkleChannel as PcsStack>::stark(&proof.stark_proof)
        .expect("the recursion seams take proofs on the Poseidon2-M31 channel")
}

/// What a segment proof's verifier commits and samples, as a function of its
/// shape alone (`component_mask`, `log_sizes`, `config`): the in-AIR
/// verifier's structure, before any proof is read.
pub struct SampleLayout {
    /// The lifting height: the composition tree's, and FRI's first layer's.
    pub lifting_log_size: u32,
    /// `lifting_log_size − log_blowup_factor`.
    pub max_log_degree_bound: u32,
    /// Each tree's columns' log sizes on the evaluation domain, in commit
    /// order: preprocessed, main, interaction, composition.
    pub column_log_sizes: alloc::vec::Vec<alloc::vec::Vec<u32>>,
    /// Each tree's columns' sample points, each the OODS point plus this
    /// offset, in the order the proof's `sampled_values` hold them.
    pub sample_offsets: alloc::vec::Vec<
        alloc::vec::Vec<
            alloc::vec::Vec<stwo::core::circle::CirclePoint<stwo::core::fields::m31::BaseField>>,
        >,
    >,
    /// Each active component's main and interaction columns, and the
    /// preprocessed tree's columns it reads, in its order.
    pub components: alloc::vec::Vec<ComponentLayout>,
}

/// An active component's place in the trees.
pub struct ComponentLayout {
    pub chip: usize,
    pub log_size: u32,
    pub main_columns: core::ops::Range<usize>,
    pub interaction_columns: core::ops::Range<usize>,
    pub preprocessed_indices: alloc::vec::Vec<usize>,
}

/// The [`SampleLayout`] of a segment proof's shape: the components the mask
/// selects at `log_sizes`, their masks at the identity point, which gives
/// each sample point's offset from the OODS point.
pub fn sample_layout(
    component_mask: u32,
    log_sizes: &[u32],
    config: &stwo::core::pcs::PcsConfig,
) -> SampleLayout {
    use stwo::core::air::Components;
    use stwo::core::circle::CirclePoint;
    use stwo::core::fields::m31::BaseField;
    use stwo::core::fields::qm31::SECURE_EXTENSION_DEGREE;
    use stwo::core::pcs::utils::try_get_lifting_log_size;
    use stwo::core::verifier::COMPOSITION_LOG_SPLIT;
    use stwo_constraint_framework::TraceLocationAllocator;

    let active: alloc::vec::Vec<usize> = (0..crate::chip_idx::COUNT)
        .filter(|&i| component_mask & (1 << i) != 0)
        .collect();
    assert_eq!(active.len(), log_sizes.len(), "one log size a component");
    let components: alloc::vec::Vec<&'static dyn crate::framework::MachineComponent> = active
        .iter()
        .map(|&i| crate::BASE_COMPONENTS[i] as &dyn crate::framework::MachineComponent)
        .collect();
    let mut lookup = AllLookupElements::default();
    let mut channel = crate::poseidon2::Poseidon2M31Channel::default();
    for component in &components {
        component.draw_lookup_elements(
            &mut lookup,
            crate::pcs::FsChannel::as_ref_channel(&mut channel),
        );
    }
    let allocator = &mut TraceLocationAllocator::default();
    let verifier_components: alloc::vec::Vec<alloc::boxed::Box<dyn Component>> = components
        .iter()
        .zip(log_sizes)
        .map(|(component, &log_size)| {
            component.to_component(allocator, &lookup, log_size, SecureField::default())
        })
        .collect();
    let committed = super::committed_log_sizes(&components, log_sizes);
    let components_ref: alloc::vec::Vec<&dyn Component> =
        verifier_components.iter().map(|c| &**c).collect();
    let all = Components {
        components: components_ref,
        n_preprocessed_columns: committed[PREPROCESSED_TRACE_IDX].len(),
    };
    let blowup = config.fri_config.log_blowup_factor;
    let split = all.composition_log_degree_bound() - COMPOSITION_LOG_SPLIT;
    let lifting_log_size =
        try_get_lifting_log_size(config, split + blowup).expect("a lifting height");
    let max_log_degree_bound = lifting_log_size - blowup;
    let mut points = all.mask_points(CirclePoint::zero(), max_log_degree_bound, false);
    points.push(alloc::vec![
        alloc::vec![CirclePoint::zero()];
        2 * SECURE_EXTENSION_DEGREE
    ]);
    let base = |coordinate: SecureField| {
        let [x, rest @ ..] = coordinate.to_m31_array();
        assert_eq!(
            rest,
            [BaseField::from(0); 3],
            "a mask offset is a base point"
        );
        x
    };
    let sample_offsets = points
        .0
        .into_iter()
        .map(|tree| {
            tree.into_iter()
                .map(|column| {
                    column
                        .into_iter()
                        .map(|point| CirclePoint {
                            x: base(point.x),
                            y: base(point.y),
                        })
                        .collect()
                })
                .collect()
        })
        .collect();
    let mut column_log_sizes: alloc::vec::Vec<alloc::vec::Vec<u32>> = committed
        .0
        .into_iter()
        .map(|tree| tree.into_iter().map(|log_size| log_size + blowup).collect())
        .collect();
    column_log_sizes.push(alloc::vec![lifting_log_size; 2 * SECURE_EXTENSION_DEGREE]);
    let (mut main, mut interaction) = (0, 0);
    let components = active
        .iter()
        .zip(&components)
        .zip(log_sizes)
        .zip(&verifier_components)
        .map(|(((&chip, component), &log_size), verifier)| {
            let sizes = component.trace_sizes(log_size);
            let n_main = sizes[ORIGINAL_TRACE_IDX].len();
            let n_interaction = sizes[INTERACTION_TRACE_IDX].len();
            let layout = ComponentLayout {
                chip,
                log_size,
                main_columns: main..main + n_main,
                interaction_columns: interaction..interaction + n_interaction,
                preprocessed_indices: verifier.preprocessed_column_indices(),
            };
            main += n_main;
            interaction += n_interaction;
            layout
        })
        .collect();
    SampleLayout {
        lifting_log_size,
        max_log_degree_bound,
        column_log_sizes,
        sample_offsets,
        components,
    }
}
