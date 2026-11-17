//! The chip-isolated verify path (`chip-isolated`): a proof of a chosen
//! chip slice against its side note, the preprocessed trace committed again
//! from the slice. No boundary binding and no timestamp check: the slice has
//! no stable component positions, and such proofs cross no trust boundary.

use num_traits::Zero;
use stwo::core::{
    air::Component,
    fields::qm31::SecureField,
    pcs::{CommitmentSchemeVerifier, PcsConfig},
    verifier::VerificationError,
};
use stwo_constraint_framework::TraceLocationAllocator;

use stwo::prover::backend::{BackendForChannel, simd::SimdBackend};

use crate::format::Format;
use crate::lookups::AllLookupElements;
use crate::pcs::{FsChannel, PcsStack};
use crate::side_note::SideNote;
use crate::trace::eval::PREPROCESSED_TRACE_IDX;

use super::{DEFAULT_MAX_LOG_SIZE, Proof};

pub(super) fn verify(
    mut proof: Proof,
    side_note: &SideNote,
    components: &[&dyn crate::framework::MachineComponent],
    prover_components: &[&dyn crate::framework::MachineProverComponent],
) -> Result<(), VerificationError> {
    // The format the proof names, admitted and with its Stark proof on the
    // format's channel, and every log size under `DEFAULT_MAX_LOG_SIZE` (so a
    // malicious prover can't force a giant Merkle commitment phase), before
    // any cryptographic work.
    let format = crate::proof::preflight_proof_structure(&mut proof, DEFAULT_MAX_LOG_SIZE)?;
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
) -> Result<(), VerificationError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let expected_log_sizes = super::committed_log_sizes(components, &proof.log_sizes);
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
    // The proof's parameters with its format's DEEP batching, which a proof
    // does not carry.
    let config = format.verifier_config(&proof.pcs_config);
    let stark = MC::stark(&proof.stark_proof).ok_or_else(|| {
        VerificationError::InvalidStructure("Stark proof channel differs".to_string())
    })?;
    let (protocol_shape, security_shape) = crate::framework_access::preflight_component_dimensions(
        &config,
        stark,
        &shape_component_refs,
        &expected_log_sizes,
    )?;
    crate::proof::check_format_security(format, &config, &security_shape)?;

    verify_preprocessed_trace::<MC>(
        stark,
        side_note,
        &proof.log_sizes,
        &config,
        prover_components,
    )?;
    let verifier_channel = &mut MC::C::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<MC>::new(config);
    let super::TranscriptPrefix {
        lookup_elements: _,
        verifier_components,
    } = super::transcript_prefix::<MC>(
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

    let sampled_queries = crate::proof::expected_fiat_shamir_query_count::<MC>(
        verifier_channel,
        stark,
        &config,
        protocol_shape,
        &expected_log_sizes,
    )?;
    if sampled_queries != protocol_shape.query_count {
        return Err(VerificationError::InvalidStructure(
            "queried-value rows differ from Fiat-Shamir query positions".to_string(),
        ));
    }

    let components_ref: Vec<&dyn Component> = verifier_components.iter().map(|c| &**c).collect();
    let stark = MC::from_any(proof.stark_proof).expect("the channel checked above");
    stwo::core::verifier::verify(&components_ref, verifier_channel, commitment_scheme, stark)
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
    // The prover-trait components the prover used, whose preprocessed
    // traces are generated again and committed.
    let preprocessed_expected =
        crate::prove::preprocessed_root::<MC>(side_note, components, log_sizes, *config);
    let preprocessed = proof.commitments[PREPROCESSED_TRACE_IDX];
    if preprocessed_expected != preprocessed {
        Err(VerificationError::InvalidStructure(format!(
            "invalid commitment to preprocessed trace: expected {preprocessed_expected}, got {preprocessed}"
        )))
    } else {
        Ok(())
    }
}
