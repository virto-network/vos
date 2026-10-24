//! The statement's transcript as A.1 orders it: the domain, the format and
//! the PCS configuration, the log sizes, the boundary states and the
//! interaction PoW; and the format's security check on a proof's parameters.

use alloc::{format, string::String, vec::Vec};
use stwo::core::{
    channel::Channel,
    pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec},
    proof::StarkProof,
};

use super::{Proof, SegmentState};
use crate::format::{Format, FormatParams};
use crate::lookups::AllLookupElements;
use crate::pcs::{FsChannel, PcsStack};
use crate::security::{SecurityBits, SecurityShape};
use crate::trace::eval::{INTERACTION_TRACE_IDX, ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX};

// Two fixed little-endian words spelling "VOS/PVM/" and "STARK/FS". The
// format version follows as its own word. This is deliberately mixed before
// log sizes or roots on every proving and verifying path: changing a wire
// version can never merely relabel an old proof under the same transcript.
const PROOF_FS_DOMAIN_WORD_0: u64 = u64::from_le_bytes(*b"VOS/PVM/");
const PROOF_FS_DOMAIN_WORD_1: u64 = u64::from_le_bytes(*b"STARK/FS");

/// Bind the proof protocol domain and exact format generation into a Fiat–
/// Shamir channel. This prefix authenticates the STARK statement transcript.
pub fn mix_proof_fs_domain(channel: &mut impl Channel, format_version: u32, config: &PcsConfig) {
    channel.mix_u64(PROOF_FS_DOMAIN_WORD_0);
    channel.mix_u64(PROOF_FS_DOMAIN_WORD_1);
    channel.mix_u64(u64::from(format_version));
    channel.mix_u64(u64::from(config.pow_bits));
    channel.mix_u64(config.fri_config.n_queries as u64);
    channel.mix_u64(u64::from(config.fri_config.log_blowup_factor));
    channel.mix_u64(u64::from(config.fri_config.log_last_layer_degree_bound));
    channel.mix_u64(u64::from(config.fri_config.fold_step));
    match config.lifting_log_size {
        None => channel.mix_u64(0),
        Some(lifting) => {
            channel.mix_u64(1);
            channel.mix_u64(u64::from(lifting));
        }
    }
}

/// A.1's first item: the domain, the format and the PCS configuration, then
/// each component's log size.
pub fn mix_statement_header(
    channel: &mut impl Channel,
    format_version: u32,
    config: &PcsConfig,
    log_sizes: &[u32],
) {
    mix_proof_fs_domain(channel, format_version, config);
    for &log_size in log_sizes {
        channel.mix_u64(u64::from(log_size));
    }
}

/// A.1's third item: the boundary states, after the main trace's root and
/// before any relation challenge, so the challenges depend on them and the
/// boundary binding's public logup terms are bound: the boundary chips' own
/// bytes ([`crate::boundary_binding::boundary_state_bytes`]), one M31 a byte,
/// as one run of 296.
pub fn mix_boundary_states(
    channel: &mut impl FsChannel,
    initial: &SegmentState,
    final_state: &SegmentState,
) {
    channel.mix_bytes(&crate::boundary_binding::boundary_state_bytes(
        initial,
        final_state,
    ));
}

/// A.1's fourth item, on the verifier's side: the interaction PoW nonce must
/// meet the format's bits on the channel as it stands after the boundary
/// states, and is then mixed.
pub fn check_interaction_pow(
    channel: &mut impl Channel,
    format: &Format,
    nonce: u64,
) -> Result<(), String> {
    let bits = format.interaction_pow_bits();
    if !channel.verify_pow_nonce(bits, nonce) {
        return Err(format!("interaction PoW nonce does not meet {bits} bits"));
    }
    channel.mix_u64(nonce);
    Ok(())
}

/// The verifier's transcript through the interaction tree's root, as the
/// prover ran it, on `channel` and `commitment_scheme`:
/// - A.1's first five items: the statement header; the preprocessed and main
///   roots at `log_sizes`; the boundary states and the interaction PoW, which
///   it checks; and the relation elements, which `draw` draws from the
///   channel as it then stands;
/// - the claimed sums, then the interaction root.
///
/// Every verifier replays this one prefix, and A.1's in-AIR transcript
/// follows it. Every proof mixes its boundary states, as every proof's
/// prover did. It returns the relation elements, for the caller to build
/// its components with.
pub fn replay_prefix<MC: PcsStack>(
    proof: &Proof,
    stark: &StarkProof<MC::H>,
    format: &Format,
    log_sizes: &TreeVec<Vec<u32>>,
    channel: &mut MC::C,
    commitment_scheme: &mut CommitmentSchemeVerifier<MC>,
    draw: impl FnOnce(&mut MC::C) -> AllLookupElements,
) -> Result<AllLookupElements, String> {
    mix_statement_header(channel, format.number, &proof.pcs_config, &proof.log_sizes);
    for idx in [PREPROCESSED_TRACE_IDX, ORIGINAL_TRACE_IDX] {
        commitment_scheme.commit(stark.commitments[idx], &log_sizes[idx], channel);
    }
    mix_boundary_states(channel, &proof.initial_state, &proof.final_state);
    check_interaction_pow(channel, format, proof.interaction_pow)?;
    let lookup_elements = draw(channel);
    channel.mix_felts(&proof.claimed_sums);
    commitment_scheme.commit(
        stark.commitments[INTERACTION_TRACE_IDX],
        &log_sizes[INTERACTION_TRACE_IDX],
        channel,
    );
    Ok(lookup_elements)
}

/// A proof's two counts ([`crate::security`]) at its own parameters and
/// shape, with its format's interaction PoW.
pub fn format_security_bits(
    format: &Format,
    config: &PcsConfig,
    shape: &SecurityShape,
) -> Result<SecurityBits, String> {
    let params = FormatParams::of(
        config,
        format.interaction_pow_bits(),
        format.params.batching,
    );
    crate::security::security_bits(&params, shape)
        .ok_or_else(|| String::from("parameters outside the security analysis"))
}

/// Refuse a proof whose counts, at its own parameters and shape, fall below
/// its format's floors, and one whose parameters are not the format's.
/// Counts first, so a weakened proof is refused for its security whatever
/// else differs.
pub fn check_format_security(
    format: &Format,
    config: &PcsConfig,
    shape: &SecurityShape,
) -> Result<SecurityBits, String> {
    let bits = format_security_bits(format, config, shape)?;
    if bits.conjectured < format.floor.conjectured {
        return Err(format!(
            "proof counts {} conjectured bits, below format {}'s floor of {}",
            bits.conjectured, format.number, format.floor.conjectured
        ));
    }
    if bits.proven < format.floor.proven {
        return Err(format!(
            "proof counts {} proven bits, below format {}'s floor of {}",
            bits.proven, format.number, format.floor.proven
        ));
    }
    if format.verifier_config(config) != format.pcs_config() {
        return Err(format!(
            "proof parameters differ from format {}'s",
            format.number
        ));
    }
    Ok(bits)
}
