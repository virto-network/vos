//! Canonical-shape proving: every chip present and padded to a profile, so
//! every segment of a program shares one program commitment; the profiles,
//! the program commitment of a profile, and in-memory chain proving.

use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::{BackendForChannel, simd::SimdBackend};
use stwo::prover::{CommitmentSchemeProver, poly::circle::PolyOps};

use super::{
    ProofTranscriptGeneration, ProvingError, Target, install_thread_pool,
    prepare_side_note_for_verification, prove_impl_with_components_overridden,
};
use crate::format::Format;
use crate::pcs::PcsStack;
use crate::proof::Proof;
use crate::side_note::SideNote;

/// Canonical-shape proving (federation wire-through W0).
///
/// Proves with the FULL `BASE_COMPONENTS` set present (constant
/// `component_mask`, all [`chip_idx::COUNT`](crate::chip_idx::COUNT) bits) and
/// every forcing-set chip's main trace
/// padded up to the per-chip floor in `min_log_sizes` (indexed by
/// [`chip_idx`](crate::chip_idx)), so the preprocessed-trace commitment —
/// the program identity — is identical for every segment of a program
/// regardless of the witness.  That is what lets ONE published program
/// commitment pin a whole *heterogeneous* segment chain via
/// `verify_chain_standalone`: the per-segment active set is constant (full
/// mask) and the preprocessed-bearing chips' `log_size`s are pinned.
///
/// Uses the MOBILE PCS config (the federation policy — verifiers must use
/// `PcsPolicy::MOBILE`).  `min_log_sizes` shorter than the component count
/// is zero-padded; a 0 floor means "natural size" (the fixed-table chips,
/// already uniform, need no floor).  Forced sizes MUST stay `<=
/// DEFAULT_MAX_LOG_SIZE` (24) or the verifier rejects.
pub fn prove_canonical(
    side_note: &mut SideNote,
    min_log_sizes: &[u32],
) -> Result<Proof, ProvingError> {
    prove_canonical_format(side_note, min_log_sizes, &crate::format::LEGACY_SEGMENT)
}

/// [`prove_canonical`] under `format`, at its parameters (format 33's are
/// MOBILE's); [`ProvingError::FormatNotAdmitted`] on a format the registry
/// does not admit.
pub fn prove_canonical_format(
    side_note: &mut SideNote,
    min_log_sizes: &[u32],
    format: &'static Format,
) -> Result<Proof, ProvingError> {
    install_thread_pool();
    prepare_side_note_for_verification(side_note);
    let components = crate::all_components();
    // Full set present ⇒ constant mask = all component bits set.  Built via
    // a widening shift so a COUNT of 32 (all u32 bits) doesn't overflow.
    let component_mask = ((1u64 << crate::chip_idx::COUNT) - 1) as u32;
    let (proof, _) = prove_impl_with_components_overridden(
        side_note,
        Target::of(format)?,
        false,
        components,
        component_mask,
        None,
        min_log_sizes,
        ProofTranscriptGeneration::Current,
    )?;
    Ok(proof)
}

/// Measure the public program commitment for an already-pinned canonical
/// component profile without materializing main/interaction traces or a FRI
/// proof.
///
/// The preprocessed tree is witness-independent by protocol: it contains the
/// authenticated program tables, fixed lookup tables, and their exact
/// per-component heights. Catalog maintenance can therefore re-pin an AIR
/// change without allocating the (potentially multi-gigabyte) canonical main
/// trace. `log_sizes` must be the complete component profile emitted by a
/// canonical measurement; partial profiles are rejected.
pub fn program_commitment_for_profile(
    side_note: &SideNote,
    log_sizes: &[u32],
) -> Option<crate::program_id::ProgramCommitment> {
    program_commitment_for_profile_format(side_note, log_sizes, &crate::format::LEGACY_SEGMENT)
}

/// [`program_commitment_for_profile`] under `format`; `None` on a format the
/// registry does not admit.
pub fn program_commitment_for_profile_format(
    side_note: &SideNote,
    log_sizes: &[u32],
    format: &'static Format,
) -> Option<crate::program_id::ProgramCommitment> {
    install_thread_pool();
    let target = Target::of(format).ok()?;
    crate::with_stack!(format.channel, Stack => {
        program_commitment_on::<Stack>(side_note, log_sizes, target)
    }, unbuilt => None)
}

fn program_commitment_on<MC: PcsStack>(
    side_note: &SideNote,
    log_sizes: &[u32],
    target: Target,
) -> Option<crate::program_id::ProgramCommitment>
where
    SimdBackend: BackendForChannel<MC>,
{
    use crate::pcs::ProofHash;
    let components = crate::all_components();
    if log_sizes.len() != components.len() || log_sizes.contains(&0) {
        return None;
    }

    let config = target.config;
    let max_constraint_log_degree_bound = components
        .iter()
        .zip(log_sizes)
        .map(|(component, &log_size)| component.max_constraint_log_degree_bound(log_size))
        .max()?;
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(max_constraint_log_degree_bound + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let channel = &mut MC::C::default();
    crate::proof::mix_statement_header(channel, target.format.number, &config, log_sizes);
    let mut scheme = CommitmentSchemeProver::<SimdBackend, MC>::new(config, &twiddles);
    let mut tree_builder = scheme.tree_builder();
    for (component, &log_size) in components.iter().zip(log_sizes) {
        tree_builder.extend_evals(component.generate_preprocessed_trace(log_size, side_note));
    }
    tree_builder.commit(channel);
    scheme.roots().first().map(|root| root.into_commitment())
}

/// Prove a segment chain in memory: derive the canonical forcing profile over
/// `bounds` (so every window shares ONE program commitment) and prove each
/// window to that shape. Returns `(profile, per-segment proofs in order)`.
/// `None` if profile derivation or any segment prove fails. `bounds` must be
/// ascending, gapless, and cover the trace (e.g. from `segment::segment_bounds`
/// or `segment::segment_bounds_budgeted`). For streaming / CAS deployment use
/// the `prover-extension` crate instead.
pub fn prove_chain(full: &SideNote, bounds: &[(usize, usize)]) -> Option<(Vec<u32>, Vec<Proof>)> {
    prove_chain_format(full, bounds, &crate::format::LEGACY_SEGMENT)
}

/// [`prove_chain`] under `format`; `None` on a format the registry does not
/// admit.
pub fn prove_chain_format(
    full: &SideNote,
    bounds: &[(usize, usize)],
    format: &'static Format,
) -> Option<(Vec<u32>, Vec<Proof>)> {
    // ONE profile over every window ⇒ one forced shape ⇒ one program
    // commitment for the whole chain (what `verify_chain_standalone` pins).
    let profile = canonical_profile_for_bounds(full, bounds)?;
    let mut proofs = Vec::with_capacity(bounds.len());
    // A second forward cursor is required for the proving pass. Re-slicing
    // each window from the initial image would replay every prior sparse
    // write again and retain/copy progressively larger page snapshots.
    let mut cursor = crate::segment::SegmentCursor::new(full);
    for &(a, b) in bounds {
        let mut sn = cursor.side_note(a, b);
        proofs.push(prove_canonical_format(&mut sn, &profile, format).ok()?);
    }
    Some((profile, proofs))
}

/// Canonical-shape profiling (federation wire-through W0): the NATURAL
/// (unforced) main-trace `log_size` each of the given components would use for
/// `side_note`. The per-segment max of these over a full trace is the
/// `min_log_size` profile `prove_canonical` pads to (so every segment's forced
/// chips share one `log_size`). Mirrors `prove`'s trace-gen prep (`prepare` +
/// `ingest_memory_pages`, so page/merkle-bearing chips report their real size)
/// but stops at `log_size` — no commit, no FRI. `indices` are positions in
/// [`all_components`](crate::all_components) / [`chip_idx`](crate::chip_idx).
pub fn natural_log_sizes_for(side_note: &mut SideNote, indices: &[usize]) -> Vec<u32> {
    prepare_side_note_for_verification(side_note);
    side_note.ingest_memory_pages();
    let comps = crate::all_components();
    indices
        .iter()
        .map(|&i| {
            let c = comps[i];
            let trace = if c.is_producer() {
                c.generate_component_trace(side_note)
            } else {
                c.generate_component_trace_immut(side_note)
            };
            trace.log_size()
        })
        .collect()
}

/// The canonical forcing profile for `seg_steps`-step windows of `full`: the
/// per-chip elementwise MAX of every window's natural main-trace `log_size`
/// (via [`natural_log_sizes_for`]) — the `min_log_sizes` under which
/// [`prove_canonical`] gives all of a chain's windows an identical shape.
/// Chips whose size is already uniform get their own size back (forcing is a
/// no-op); varying chips get the chain-wide max, so the windows collapse onto
/// one canonical shape. The floors are the
/// observed per-window maxima for THIS trace's op pattern, not a proven
/// bound — a deployment's drift guard + allowlist-coverage gate catch a
/// reshaped transition. `None` when the trace is empty, `seg_steps` is zero,
/// or any floor exceeds [`DEFAULT_MAX_LOG_SIZE`](crate::DEFAULT_MAX_LOG_SIZE)
/// (such a profile could only ever produce verifier-rejected proofs).
pub fn canonical_profile_for(full: &SideNote, seg_steps: usize) -> Option<Vec<u32>> {
    if seg_steps == 0 {
        return None;
    }
    canonical_profile_for_bounds(
        full,
        &crate::segment::segment_bounds(full.steps.len(), seg_steps),
    )
}

/// [`canonical_profile_for`] over explicit window bounds — the floors for a
/// content-budgeted cut ([`crate::segment::segment_bounds_budgeted`]), or
/// any other deterministic segmentation. Same guarantees and refusals.
/// `bounds` must be in ascending step order (every segmentation here
/// produces them so): the windows are sliced by one forward
/// [`crate::segment::SegmentCursor`] pass, O(N) in the trace length
/// instead of the per-window prefix replay's O(N²).
pub fn canonical_profile_for_bounds(
    full: &SideNote,
    bounds: &[(usize, usize)],
) -> Option<Vec<u32>> {
    let mut cursor = crate::segment::SegmentCursor::new(full);
    canonical_profile_over(bounds, move |a, b| cursor.side_note(a, b))
}

/// [`canonical_profile_for_bounds`] over a [`crate::CompactTrace`] — the
/// chain-holder form the streaming drivers keep resident. The windows come
/// from one forward [`crate::segment::CompactSegmentCursor`] pass, which
/// yields `SideNote`s field-identical to slicing the expanded full trace,
/// so the derived floors are the same numbers.
pub fn canonical_profile_for_bounds_compact(
    full: &crate::CompactTrace,
    bounds: &[(usize, usize)],
) -> Option<Vec<u32>> {
    let mut cursor = crate::segment::CompactSegmentCursor::new(full);
    canonical_profile_over(bounds, move |a, b| cursor.side_note(a, b))
}

/// The per-chip elementwise-max walk shared by the two holder forms:
/// `window` materializes the `SideNote` for each `[a, b)` in `bounds`
/// (ascending — both callers hand a forward cursor).
fn canonical_profile_over(
    bounds: &[(usize, usize)],
    mut window: impl FnMut(usize, usize) -> SideNote,
) -> Option<Vec<u32>> {
    let mut floors = NaturalFloors::new();
    for &(a, b) in bounds {
        floors.observe(&mut window(a, b));
    }
    floors.finish()
}

/// The canonical-floors accumulator behind [`canonical_profile_for_bounds`]
/// and the streaming derivations: feed every window's `SideNote` in any
/// order via [`Self::observe`], then [`Self::finish`] yields the per-chip
/// elementwise MAX of the observed natural `log_size`s — the canonical
/// forcing profile. `finish` refuses (`None`) when nothing was observed
/// (an empty chain has no floors) or any floor exceeds
/// [`DEFAULT_MAX_LOG_SIZE`](crate::DEFAULT_MAX_LOG_SIZE) (such a profile
/// could only ever produce verifier-rejected proofs) — the same contract
/// [`canonical_profile_for`] documents. Exists so a
/// [`crate::segment::TraceStream`] pass can derive floors without ever
/// holding the chain's trace.
pub struct NaturalFloors {
    indices: Vec<usize>,
    floors: Vec<u32>,
    observed: bool,
}

impl NaturalFloors {
    pub fn new() -> Self {
        let indices: Vec<usize> = (0..crate::chip_idx::COUNT).collect();
        Self {
            floors: vec![0u32; indices.len()],
            indices,
            observed: false,
        }
    }

    /// Fold one window's natural sizes into the floors.
    pub fn observe(&mut self, sn: &mut SideNote) {
        self.observed = true;
        for (floor, natural) in self
            .floors
            .iter_mut()
            .zip(natural_log_sizes_for(sn, &self.indices))
        {
            *floor = (*floor).max(natural);
        }
    }

    pub fn finish(self) -> Option<Vec<u32>> {
        (self.observed
            && self
                .floors
                .iter()
                .all(|&f| f <= crate::DEFAULT_MAX_LOG_SIZE))
        .then_some(self.floors)
    }
}
