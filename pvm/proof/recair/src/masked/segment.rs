//! The masked segment: a run's chips proved masked
//! (`vos_pvm_proof::masked`, variant (c)) by [`super::prove_masked`], and verified
//! by the final verifier's `verify_masked` over the chips laid out from the
//! proof's active-chip mask and log sizes.
//!
//! The transcript is the masked one ([`super`]): the public values after the
//! main tree's root are the boundary states, one M31 a byte; the verifier
//! checks that the claimed sums total zero and that the boundary chips'
//! sums, left unblinded, are those the states fix. Every chip pads to four
//! times its `h` ([`floors`]). No production format proves it: a test or
//! measurement names a masked format of its own.
//!
//! The verifier pins the preprocessed root ([`circuit_root`]): the tables'
//! and the code's content has no other pin. It takes the chips and their
//! sizes from the proof, and the transcript does not mix the chips (as
//! format 35's does not); the device's segment ([`super::device`]) takes
//! both from its program and mixes the chips after the header.

use num_traits::Zero;
use stwo::core::channel::MerkleChannel;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::prover::CommitmentSchemeProver;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::PolyOps;
use vos_pvm_final_verifier::Error;
use vos_pvm_final_verifier::masked::{Claim, MaskedFormat, verify_masked};
use vos_pvm_proof::SegmentState;
use vos_pvm_proof::format::Format;
use vos_pvm_proof::framework_access::AllLookupElements;
use vos_pvm_proof::masked::{
    MaskedSegmentTrace, SegmentComponents, bound_sums, masked_segment_trace, public_values,
};
use vos_pvm_proof::side_note::SideNote;
use vos_pvm_recair_air::masked::MaskedComponents;

use super::{Checks, MaskRng, MaskStats, MaskedProof, MaskedTrace, mask_rows, verifier_format};
use crate::prove::ProveError;
use crate::trace::FirstRowFraction;

/// A masked segment proof: its chips, their log sizes, the boundary states
/// and the masked proof.
#[derive(Clone, Debug)]
pub struct SegmentProof<H: MerkleHasherLifted> {
    /// The chips, as an active-chip mask.
    pub active: u32,
    pub log_sizes: Vec<u32>,
    pub initial_state: SegmentState,
    pub final_state: SegmentState,
    pub proof: MaskedProof<H>,
}

/// Each of the chips `active` names padded to four times its `h` under
/// `format` ([`mask_rows`]), in chip order: the least log sizes its masks
/// fit. `None` for an unmasked format or a mask of no segment chips.
pub fn floors(format: &Format, active: u32) -> Option<Vec<u32>> {
    let any = format.masking?.log_mask_rows + 2;
    let layout = SegmentComponents::layout(active, &vec![any; active.count_ones() as usize])?;
    Some(mask_rows(format, &layout)?.iter().map(|h| h + 2).collect())
}

/// `side_note`'s run over the chips `active` names, proved masked under
/// `format` on `MC`'s trees and channel, each chip at least its floor
/// ([`floors`]), its masks from `rng`.
pub fn prove_segment<MC: MerkleChannel>(
    format: &Format,
    side_note: &mut SideNote,
    active: u32,
    rng: MaskRng,
) -> Result<(SegmentProof<MC::H>, MaskStats), ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    prove_segment_with::<MC>(
        format,
        side_note,
        active,
        rng,
        |_| {},
        |_, _| {},
        Checks::ALL,
    )
}

/// [`prove_segment`], the trace (its main and preprocessed columns) through
/// `tamper` before it is committed, each chip's blinding fraction through
/// `blind` once the relations are drawn, the prover held to `checks` alone:
/// the soundness gates' forced proofs. Only the tests' dev edge has it
/// (`seeded-masks`); no production build does.
#[cfg(feature = "seeded-masks")]
pub fn prove_segment_forced<MC: MerkleChannel>(
    format: &Format,
    side_note: &mut SideNote,
    active: u32,
    rng: MaskRng,
    tamper: impl FnOnce(&mut MaskedSegmentTrace),
    blind: impl Fn(&AllLookupElements, &mut [FirstRowFraction]),
    checks: Checks,
) -> Result<(SegmentProof<MC::H>, MaskStats), ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    prove_segment_with::<MC>(format, side_note, active, rng, tamper, blind, checks)
}

fn prove_segment_with<MC: MerkleChannel>(
    format: &Format,
    side_note: &mut SideNote,
    active: u32,
    rng: MaskRng,
    tamper: impl FnOnce(&mut MaskedSegmentTrace),
    blind: impl Fn(&AllLookupElements, &mut [FirstRowFraction]),
    checks: Checks,
) -> Result<(SegmentProof<MC::H>, MaskStats), ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let floors = floors(format, active).ok_or(ProveError::TraceShape(
        "the format's masking does not fit the chips",
    ))?;
    let mut trace = masked_segment_trace(side_note, active, &floors)
        .map_err(|error| ProveError::Segment(error.to_string()))?;
    let side_note: &SideNote = side_note;
    tamper(&mut trace);
    let public = trace.public();
    let interaction = |relations: &AllLookupElements, blinding: &[FirstRowFraction]| {
        let mut fractions = blinding.to_vec();
        blind(relations, &mut fractions);
        let fractions: Vec<(SecureField, SecureField)> = fractions
            .iter()
            .map(|fraction| (fraction.numerator, fraction.denominator))
            .collect();
        trace.interaction(side_note, relations, &fractions)
    };
    let masked = MaskedTrace {
        active,
        log_sizes: &trace.log_sizes,
        preprocessed: trace.preprocessed(),
        main: &|chip: usize| trace.main(chip),
        public: &public,
        interaction: &interaction,
    };
    let (proof, stats) =
        super::prove_masked_checked::<MC, SegmentComponents>(format, masked, rng, checks)?;
    Ok((
        SegmentProof {
            active,
            log_sizes: trace.log_sizes.clone(),
            initial_state: trace.initial_state,
            final_state: trace.final_state,
            proof,
        },
        stats,
    ))
}

/// The masked format `format` pins for the chips `active` names at
/// `log_sizes`, as its verifier takes it, and the chips laid out.
pub fn segment_format<'a>(
    format: &Format,
    active: u32,
    log_sizes: &'a [u32],
) -> Option<(MaskedFormat<'a>, SegmentComponents)> {
    let layout = SegmentComponents::layout(active, log_sizes)?;
    Some((verifier_format(format, log_sizes, &layout)?, layout))
}

/// The preprocessed root a masked segment of `side_note`'s run over the
/// chips `active` names commits under `format` on `MC`'s trees: each chip's
/// preprocessed columns (the program's code, the jump table, the fixed
/// tables) at its floor ([`floors`]), extended one level, as the prover
/// commits them. What a verifier pins: a function of the program and the
/// shape, never of a proof.
pub fn circuit_root<MC: MerkleChannel>(
    format: &Format,
    side_note: &mut SideNote,
    active: u32,
) -> Result<<MC::H as MerkleHasherLifted>::Hash, ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let floors = floors(format, active).ok_or(ProveError::TraceShape(
        "the format's masking does not fit the chips",
    ))?;
    let trace = masked_segment_trace(side_note, active, &floors)
        .map_err(|error| ProveError::Segment(error.to_string()))?;
    let lifting = super::lifting_log_size(format, &trace.log_sizes)
        .ok_or(ProveError::TraceShape("a component's log size overflows"))?;
    let twiddles =
        SimdBackend::precompute_twiddles(CanonicCoset::new(lifting).circle_domain().half_coset);
    let mut scheme = CommitmentSchemeProver::<SimdBackend, MC>::new(format.pcs_config(), &twiddles);
    let mut builder = scheme.tree_builder();
    builder.extend_polys(super::extend_preprocessed(trace.preprocessed(), &twiddles));
    builder.commit(&mut MC::C::default());
    Ok(scheme.roots()[0])
}

/// Verifies `proof` under `format` against `circuit`, the preprocessed root
/// its program and shape commit ([`circuit_root`]), its chips laid out from
/// its active-chip mask and log sizes: the masked transcript, the claimed
/// sums' total zero and the boundary chips' sums the boundary states'.
/// The root is the only pin of the tables' and the code's content.
pub fn verify_segment<MC: MerkleChannel>(
    format: &Format,
    proof: &SegmentProof<MC::H>,
    circuit: <MC::H as MerkleHasherLifted>::Hash,
) -> Result<(), Error> {
    let (masked, layout) =
        segment_format(format, proof.active, &proof.log_sizes).ok_or(Error::Format)?;
    let public = public_values(&proof.initial_state, &proof.final_state);
    let zero = |_: &AllLookupElements| SecureField::zero();
    let bound = |relations: &AllLookupElements, sums: &[SecureField]| {
        bound_sums(
            proof.active,
            &proof.initial_state,
            &proof.final_state,
            relations,
            sums,
        )
    };
    let claim = Claim {
        log_sizes: &proof.log_sizes,
        circuit: Some(circuit),
        public: &public,
        public_sum: Some(&zero),
        bound_sums: Some(&bound),
        interaction_pow: proof.proof.interaction_pow,
        claimed_sums: &proof.proof.claimed_sums,
    };
    verify_masked::<MC, SegmentComponents>(
        &masked,
        &claim,
        &layout,
        proof.proof.stark_proof.clone(),
    )
}
