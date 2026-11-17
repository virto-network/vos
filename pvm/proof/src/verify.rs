use stwo::core::{
    air::Component,
    pcs::{CommitmentSchemeVerifier, TreeVec},
    verifier::VerificationError,
};
use stwo_constraint_framework::TraceLocationAllocator;

use crate::format::Format;
use crate::pcs::{FsChannel, PcsStack, ProofHash};

use crate::trace::eval::PREPROCESSED_TRACE_IDX;

use super::Proof;
use crate::{lookups::AllLookupElements, side_note::SideNote};

#[cfg(feature = "chip-isolated")]
mod explicit;
mod recursion;
pub use recursion::{
    ComponentOodsMask, OodsReconstruction, RecursionData, RecursionTranscript, SampleLayout,
    extract_recursion_data, reconstruct_oods_for_recursion, record_canonical_transcript,
    replay_stark, sample_layout, sample_layout_of,
};

/// The per-component log size cap `verify` applies, the protocol's.
pub use crate::proof::MAX_PROOF_LOG_SIZE as DEFAULT_MAX_LOG_SIZE;

/// Verify a proof against a `side_note` describing the SAME program +
/// segment the prover ran: [`crate::standalone::verify_standalone`]'s
/// checks, at the preprocessed root committed again from the side note.
///
/// The side note supplies the program (its preprocessed trace is re-committed
/// and compared) and the component set its steps select, which the proof's
/// mask must name; the boundary states come from the proof, which the
/// verifier mixes and binds.
pub fn verify(proof: Proof, side_note: &SideNote) -> Result<(), VerificationError> {
    let expected_component_mask = super::active_component_mask(side_note);
    if proof.component_mask != expected_component_mask {
        return Err(VerificationError::InvalidStructure(format!(
            "proof component mask {:#x} differs from SideNote-derived mask {expected_component_mask:#x}",
            proof.component_mask,
        )));
    }
    crate::standalone::verify_at(proof, |format, proof| {
        // The recommitment's cost grows with the blowup: refused past the
        // cap before any trace is generated.
        if proof.pcs_config.fri_config.log_blowup_factor > crate::proof::MAX_RECOMMIT_LOG_BLOWUP {
            return Err(VerificationError::InvalidStructure(format!(
                "proof-side recommitment rejects FRI log blowup above {}",
                crate::proof::MAX_RECOMMIT_LOG_BLOWUP,
            )));
        }
        if side_note.memory_layout().is_none() {
            return Err(VerificationError::InvalidStructure(
                "a sparse memory image without its program's layout".to_string(),
            ));
        }
        let components = super::active_components(side_note);
        let config = format.verifier_config(&proof.pcs_config);
        crate::with_stack!(format.channel, Stack => Ok(crate::prove::preprocessed_root::<Stack>(
            side_note,
            &components,
            &proof.log_sizes,
            config,
        )
        .into_commitment()), unbuilt => Err(VerificationError::InvalidStructure(format!(
            "format {}'s channel is not built",
            format.number
        ))))
    })
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
/// The boundary binding is SKIPPED on this path (the caller's arbitrary
/// chip slice has no stable component positions); chip-isolated proofs are
/// not verifiable across a trust boundary anyway — `verify_standalone`
/// rejects their `component_mask = 0`. A test seam (`chip-isolated`).
#[cfg(feature = "chip-isolated")]
pub fn verify_with_explicit_components(
    proof: Proof,
    side_note: &SideNote,
    components: &[&dyn crate::framework::MachineComponent],
    prover_components: &[&dyn crate::framework::MachineProverComponent],
) -> Result<(), VerificationError> {
    explicit::verify(proof, side_note, components, prover_components)
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

/// [`crate::proof::replay_prefix`] with `components` drawing the relation
/// elements, then the components bound to them at the proof's log sizes and
/// claimed sums.
fn transcript_prefix<'a, MC: PcsStack>(
    proof: &Proof,
    stark: &stwo::core::proof::StarkProof<MC::H>,
    format: &Format,
    components: &[&'a dyn crate::framework::MachineComponent],
    log_sizes: &TreeVec<Vec<u32>>,
    channel: &mut MC::C,
    commitment_scheme: &mut CommitmentSchemeVerifier<MC>,
) -> Result<TranscriptPrefix<'a>, VerificationError> {
    let lookup_elements = crate::proof::replay_prefix::<MC>(
        proof,
        stark,
        format,
        log_sizes,
        channel,
        commitment_scheme,
        |channel| {
            let mut lookup_elements = AllLookupElements::default();
            for component in components {
                component.draw_lookup_elements(&mut lookup_elements, channel.as_ref_channel());
            }
            lookup_elements
        },
    )?;
    let tree_span_provider = &mut TraceLocationAllocator::default();
    let verifier_components = components
        .iter()
        .zip(&proof.claimed_sums)
        .zip(&proof.log_sizes)
        .map(|((c, claimed_sum), &log_size)| {
            c.to_component(tree_span_provider, &lookup_elements, log_size, *claimed_sum)
        })
        .collect();
    Ok(TranscriptPrefix {
        lookup_elements,
        verifier_components,
    })
}
