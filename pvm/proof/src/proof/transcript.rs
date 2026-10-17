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
use crate::format::{Encoding, Format, FormatParams};
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

#[cfg(feature = "prover")]
const PRE_CONFIG_FS_FORMAT_VERSION: u32 = 18;

/// Bind the proof protocol domain and exact format generation into a Fiat–
/// Shamir channel. This prefix authenticates the STARK statement transcript;
/// Refine's outer bundle transcript additionally authenticates machine
/// identities, native boundary witnesses, and ordered child identities.
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
/// boundary binding's public logup terms are bound.
///
/// - [`Encoding::Lossless`]: the boundary chips' own bytes
///   ([`crate::boundary_binding::boundary_state_bytes`]), one M31 a byte, as
///   one run of 296.
/// - [`Encoding::Legacy`]: format 33's, a u64 at a time: the registers in
///   and out, pc and ts in, pc and ts out, then each memory root as four
///   little-endian u64s.
pub fn mix_boundary_states(
    channel: &mut impl FsChannel,
    encoding: Encoding,
    initial: &SegmentState,
    final_state: &SegmentState,
) {
    match encoding {
        Encoding::Lossless => {
            channel.mix_bytes(&crate::boundary_binding::boundary_state_bytes(
                initial,
                final_state,
            ));
        }
        Encoding::Legacy => {
            for register in initial.registers.iter().chain(&final_state.registers) {
                channel.mix_u64(*register);
            }
            channel.mix_u64(u64::from(initial.pc));
            channel.mix_u64(initial.timestamp);
            channel.mix_u64(u64::from(final_state.pc));
            channel.mix_u64(final_state.timestamp);
            for root in [&initial.memory_root, &final_state.memory_root] {
                for chunk in root.chunks_exact(8) {
                    channel.mix_u64(u64::from_le_bytes(chunk.try_into().unwrap()));
                }
            }
        }
    }
}

/// A.1's fourth item, on the verifier's side: the interaction PoW nonce must
/// meet the format's bits on the channel as it stands after the boundary
/// states, and is then mixed. A format without an interaction PoW takes the
/// nonce 0 and mixes nothing.
pub fn check_interaction_pow(
    channel: &mut impl Channel,
    format: &Format,
    nonce: u64,
) -> Result<(), String> {
    let bits = format.interaction_pow_bits();
    if bits == 0 {
        return if nonce == 0 {
            Ok(())
        } else {
            Err("format carries no interaction PoW, but the proof has a nonce".into())
        };
    }
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
    mix_boundary_states(
        channel,
        format.encoding,
        &proof.initial_state,
        &proof.final_state,
    );
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

/// Adversarial-test seam for constructing a proof under the immediately
/// preceding transcript, which bound the format but omitted `PcsConfig`.
/// The returned proof is deliberately invalid under the current generation.
#[cfg(feature = "prover")]
pub(crate) fn mix_pre_config_proof_fs_domain(channel: &mut impl Channel) {
    channel.mix_u64(PROOF_FS_DOMAIN_WORD_0);
    channel.mix_u64(PROOF_FS_DOMAIN_WORD_1);
    channel.mix_u64(u64::from(PRE_CONFIG_FS_FORMAT_VERSION));
}

/// A proof's two counts ([`crate::security`]) at its own parameters and
/// shape, with its format's interaction PoW.
pub fn format_security_bits(
    format: &Format,
    config: &PcsConfig,
    shape: &SecurityShape,
) -> Result<SecurityBits, String> {
    let params = FormatParams::of(config, format.interaction_pow_bits());
    crate::security::security_bits(&params, shape)
        .ok_or_else(|| String::from("parameters outside the security analysis"))
}

/// Refuse a proof whose counts, at its own parameters and shape, fall below
/// its format's floors; and, under a format with exact parameters, one whose
/// parameters are not the format's. Counts first, so a weakened proof is
/// refused for its security whatever else differs.
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
    if format.exact_params() && *config != format.pcs_config() {
        return Err(format!(
            "proof parameters differ from format {}'s",
            format.number
        ));
    }
    Ok(bits)
}
