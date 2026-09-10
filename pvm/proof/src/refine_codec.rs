//! Canonical, allocation-bounded wire format for [`RefineProofBundle`].
//!
//! Serde remains useful for trusted in-memory interchange, but its generic
//! sequence visitors may reserve a guest-declared nested length before the
//! caller can apply a proof-material budget. This codec reads every length
//! explicitly, validates both a generation-local cardinality and the minimum
//! remaining wire size, charges the resulting allocation, and only then calls
//! `try_reserve_exact`.

use alloc::vec::Vec;
use core::fmt;
use core::mem::size_of;

use stwo::core::fields::m31::{BaseField, P};
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::{FriConfig, FriLayerProof, FriProof};
use stwo::core::pcs::quotients::CommitmentSchemeProof;
use stwo::core::pcs::{PcsConfig, TreeVec};
use stwo::core::poly::line::LinePoly;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::verifier::MerkleDecommitmentLifted;

use crate::proof::{
    MAX_EXTENDED_LOG_SIZE, MAX_FRI_QUERIES, MAX_MERKLE_WITNESS_HASHES, MAX_PROOF_COLUMNS_PER_TREE,
    MAX_PROOF_COMPONENTS, MAX_PROOF_LOG_SIZE, MAX_PROOF_SAMPLES_PER_COLUMN, MIN_PROOF_LOG_SIZE,
    PROOF_COMMITMENT_TREE_COUNT, PROOF_FORMAT_VERSION,
};
use crate::recursion_pcs::{ProverMerkleHash, ProverMerkleHasher};
use crate::{
    Proof, REFINE_BUNDLE_FORMAT_VERSION, RefineHostBoundary, RefineMachineId, RefineProgramId,
    RefineProofBundle, RefineProofSlice, RefineSliceExit, SegmentState,
    refine_bundle_cardinality_is_valid, refine_bundle_commitment,
};

const REFINE_PROOF_BUNDLE_MAGIC: &[u8; 8] = b"VOSRPB01";

/// Version of the explicit production proof-bundle wire representation.
pub const REFINE_PROOF_BUNDLE_CODEC_VERSION: u32 = 1;

/// Generation hard maximum for canonical proof-bundle material.
///
/// A decoder also receives the narrower authenticated runtime contract value;
/// this constant only prevents a caller from widening that value beyond the
/// protocol generation.
pub const MAX_REFINE_PROOF_BUNDLE_WIRE_BYTES: usize =
    vos_agent_sdk::MAX_TRANSITION_PROOF_MATERIAL_BYTES as usize;

// The widest wire-to-memory expansion is an empty nested Vec: its four-byte
// count becomes a three-word Vec header in its parent's allocation (6x on the
// supported 64-bit host and no larger on 32-bit). Two extra units cover enum
// padding and the fixed root object. The limit is derived from the
// authenticated wire ceiling with checked arithmetic at decode time.
const REFINE_PROOF_ALLOCATION_TO_WIRE_RATIO: usize = 8;

/// Generation hard maximum for heap owned by one decoded proof bundle.
pub const MAX_REFINE_PROOF_BUNDLE_ALLOCATION_BYTES: usize =
    MAX_REFINE_PROOF_BUNDLE_WIRE_BYTES * REFINE_PROOF_ALLOCATION_TO_WIRE_RATIO;

const U32_WIRE_BYTES: usize = size_of::<u32>();
const BASE_FIELD_WIRE_BYTES: usize = size_of::<u32>();
const SECURE_FIELD_WIRE_BYTES: usize = 4 * BASE_FIELD_WIRE_BYTES;
const MERKLE_HASH_WIRE_BYTES: usize = 32;
const MIN_FRI_LAYER_WIRE_BYTES: usize = U32_WIRE_BYTES + U32_WIRE_BYTES + 32;
#[cfg(test)]
const SEGMENT_STATE_WIRE_BYTES: usize = 4 + 8 + 13 * 8 + 32 + 32;
const HOST_BOUNDARY_WIRE_BYTES: usize = 1 + 4 + 4 + 32 + 32 + 13 * 8 + 13 * 8;
// Outer machine identity is the shorter variant. The child proof minimum
// includes one component/sum/log, two segment states, four empty trees in
// every TreeVec, and the one-coefficient FRI polynomial required by config.
const MIN_PROOF_SLICE_WIRE_BYTES: usize = 4
    + (1 + 32)
    + 32
    + 32
    + 1
    + (4 + 4 + 4)
    + (4 + 4 + 4 + 4 + 4 + 1)
    + (4 + SECURE_FIELD_WIRE_BYTES)
    + (4 + U32_WIRE_BYTES)
    + 2 * (4 + 8 + 13 * 8 + 32 + 32)
    + (4 + PROOF_COMMITMENT_TREE_COUNT * MERKLE_HASH_WIRE_BYTES)
    + 3 * (4 + PROOF_COMMITMENT_TREE_COUNT * U32_WIRE_BYTES)
    + 8
    + MIN_FRI_LAYER_WIRE_BYTES
    + 4
    + (4 + SECURE_FIELD_WIRE_BYTES);
const COMMITMENT_TEMPORARY_OVERHEAD_BYTES: usize = 64;

/// Fail-closed canonical proof-bundle codec error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefineProofCodecError {
    InvalidCeiling,
    WireLimitExceeded,
    AllocationLimitExceeded,
    AllocationFailed,
    Truncated,
    TrailingBytes,
    InvalidMagic,
    UnsupportedCodecVersion,
    InvalidTag,
    InvalidCardinality,
    NonCanonical,
    InvalidStructure,
    CommitmentMismatch,
}

impl fmt::Display for RefineProofCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCeiling => "invalid authenticated proof-material ceiling",
            Self::WireLimitExceeded => "proof bundle exceeds the authenticated wire ceiling",
            Self::AllocationLimitExceeded => "proof bundle exceeds the derived allocation budget",
            Self::AllocationFailed => "proof bundle allocation failed",
            Self::Truncated => "truncated proof bundle",
            Self::TrailingBytes => "trailing proof-bundle bytes",
            Self::InvalidMagic => "invalid proof-bundle magic",
            Self::UnsupportedCodecVersion => "unsupported proof-bundle codec version",
            Self::InvalidTag => "invalid proof-bundle tag",
            Self::InvalidCardinality => "proof-bundle cardinality is outside protocol bounds",
            Self::NonCanonical => "noncanonical proof-bundle value",
            Self::InvalidStructure => "invalid proof-bundle structure",
            Self::CommitmentMismatch => "proof-bundle transcript commitment mismatch",
        })
    }
}

impl core::error::Error for RefineProofCodecError {}

/// Encode one structurally valid bundle in the unique production wire format.
///
/// Encoding has no caller policy knob: the protocol generation ceiling is
/// authoritative. The bundle must already carry its exact transcript
/// commitment and canonical slice order.
pub fn encode_refine_proof_bundle(
    bundle: &RefineProofBundle,
) -> Result<Vec<u8>, RefineProofCodecError> {
    validate_bundle(bundle)?;
    encode_bundle_fields(bundle)
}

/// Decode one production proof bundle under its authenticated runtime ceiling.
///
/// `max_proof_material_bytes` must be the exact retained runtime-contract
/// value. Zero and values wider than the protocol generation are rejected.
/// Input length is rejected before any parse or allocation. The sole heap
/// budget is derived from this same authenticated value and capped by
/// [`MAX_REFINE_PROOF_BUNDLE_ALLOCATION_BYTES`].
pub fn decode_refine_proof_bundle(
    bytes: &[u8],
    max_proof_material_bytes: u64,
) -> Result<RefineProofBundle, RefineProofCodecError> {
    let maximum_wire = authenticated_wire_ceiling(max_proof_material_bytes)?;
    if bytes.len() > maximum_wire {
        return Err(RefineProofCodecError::WireLimitExceeded);
    }
    let derived_allocation = maximum_wire
        .checked_mul(REFINE_PROOF_ALLOCATION_TO_WIRE_RATIO)
        .ok_or(RefineProofCodecError::InvalidCeiling)?
        .min(MAX_REFINE_PROOF_BUNDLE_ALLOCATION_BYTES);
    let mut decoder = Decoder::new(bytes, derived_allocation)?;
    let bundle = decode_bundle_fields(&mut decoder)?;
    if !decoder.is_finished() {
        return Err(RefineProofCodecError::TrailingBytes);
    }
    // `refine_bundle_commitment` builds one temporary canonical preimage. Our
    // wire contains every field in that preimage plus the much larger child
    // proof payload; only its domain prefix can make the temporary longer.
    // Charge a conservative full-wire copy plus fixed domain headroom before
    // entering that existing helper.
    decoder.charge_temporary(
        bytes
            .len()
            .checked_add(COMMITMENT_TEMPORARY_OVERHEAD_BYTES)
            .ok_or(RefineProofCodecError::AllocationLimitExceeded)?,
    )?;
    validate_bundle(&bundle)?;
    Ok(bundle)
}

fn authenticated_wire_ceiling(maximum: u64) -> Result<usize, RefineProofCodecError> {
    if maximum == 0 || maximum > vos_agent_sdk::MAX_TRANSITION_PROOF_MATERIAL_BYTES {
        return Err(RefineProofCodecError::InvalidCeiling);
    }
    usize::try_from(maximum).map_err(|_| RefineProofCodecError::InvalidCeiling)
}

fn validate_bundle(bundle: &RefineProofBundle) -> Result<(), RefineProofCodecError> {
    if bundle.format_version != REFINE_BUNDLE_FORMAT_VERSION {
        return Err(RefineProofCodecError::InvalidStructure);
    }
    // This is deliberately the existing verifier preflight, after the
    // allocation-safe representation has been fully reconstructed.
    if !refine_bundle_cardinality_is_valid(bundle) {
        return Err(RefineProofCodecError::InvalidStructure);
    }
    if bundle
        .slices
        .iter()
        .enumerate()
        .any(|(index, slice)| slice.order != index as u32)
    {
        return Err(RefineProofCodecError::NonCanonical);
    }
    if bundle.transcript_commitment != refine_bundle_commitment(bundle) {
        return Err(RefineProofCodecError::CommitmentMismatch);
    }
    Ok(())
}

fn encode_bundle_fields(bundle: &RefineProofBundle) -> Result<Vec<u8>, RefineProofCodecError> {
    let mut encoder = Encoder::new();
    encoder.fixed(REFINE_PROOF_BUNDLE_MAGIC)?;
    encoder.u32(REFINE_PROOF_BUNDLE_CODEC_VERSION)?;
    encoder.u32(bundle.format_version)?;
    encoder.fixed(&bundle.outer_program.0)?;
    encoder.fixed(&bundle.arguments_commitment)?;
    encoder.u64(bundle.gas_limit)?;
    encoder.length(bundle.slices.len())?;
    for slice in &bundle.slices {
        encode_slice(&mut encoder, slice)?;
    }
    encoder.length(bundle.host_boundaries.len())?;
    for boundary in &bundle.host_boundaries {
        encode_host_boundary(&mut encoder, boundary)?;
    }
    encode_exit(&mut encoder, bundle.result)?;
    encoder.fixed(&bundle.transcript_commitment)?;
    Ok(encoder.finish())
}

fn decode_bundle_fields(
    decoder: &mut Decoder<'_>,
) -> Result<RefineProofBundle, RefineProofCodecError> {
    if decoder.array::<8>()? != *REFINE_PROOF_BUNDLE_MAGIC {
        return Err(RefineProofCodecError::InvalidMagic);
    }
    if decoder.u32()? != REFINE_PROOF_BUNDLE_CODEC_VERSION {
        return Err(RefineProofCodecError::UnsupportedCodecVersion);
    }
    let format_version = decoder.u32()?;
    if format_version != REFINE_BUNDLE_FORMAT_VERSION {
        return Err(RefineProofCodecError::InvalidStructure);
    }
    let outer_program = RefineProgramId(decoder.array()?);
    let arguments_commitment = decoder.array()?;
    let gas_limit = decoder.u64()?;
    let slices = decoder.vector(
        crate::MAX_REFINE_PROOF_SLICES,
        MIN_PROOF_SLICE_WIRE_BYTES,
        decode_slice,
    )?;
    let host_boundaries = decoder.vector(
        crate::MAX_REFINE_HOST_BOUNDARIES,
        HOST_BOUNDARY_WIRE_BYTES,
        decode_host_boundary,
    )?;
    let result = decode_exit(decoder)?;
    let transcript_commitment = decoder.array()?;
    Ok(RefineProofBundle {
        format_version,
        outer_program,
        arguments_commitment,
        gas_limit,
        slices,
        host_boundaries,
        result,
        transcript_commitment,
    })
}

fn encode_slice(
    encoder: &mut Encoder,
    slice: &RefineProofSlice,
) -> Result<(), RefineProofCodecError> {
    encoder.u32(slice.order)?;
    encode_machine_id(encoder, slice.identity)?;
    encoder.fixed(&slice.entry_state)?;
    encoder.fixed(&slice.observed_exit_state)?;
    encode_exit(encoder, slice.exit)?;
    encode_proof(encoder, &slice.proof)
}

fn decode_slice(decoder: &mut Decoder<'_>) -> Result<RefineProofSlice, RefineProofCodecError> {
    Ok(RefineProofSlice {
        order: decoder.u32()?,
        identity: decode_machine_id(decoder)?,
        entry_state: decoder.array()?,
        observed_exit_state: decoder.array()?,
        exit: decode_exit(decoder)?,
        proof: decode_proof(decoder)?,
    })
}

fn encode_machine_id(
    encoder: &mut Encoder,
    identity: RefineMachineId,
) -> Result<(), RefineProofCodecError> {
    match identity {
        RefineMachineId::Outer { program } => {
            encoder.u8(0)?;
            encoder.fixed(&program.0)
        }
        RefineMachineId::Inner {
            slot,
            generation,
            program,
        } => {
            encoder.u8(1)?;
            encoder.u32(slot)?;
            encoder.u64(generation)?;
            encoder.fixed(&program.0)
        }
    }
}

fn decode_machine_id(decoder: &mut Decoder<'_>) -> Result<RefineMachineId, RefineProofCodecError> {
    match decoder.u8()? {
        0 => Ok(RefineMachineId::Outer {
            program: RefineProgramId(decoder.array()?),
        }),
        1 => Ok(RefineMachineId::Inner {
            slot: decoder.u32()?,
            generation: decoder.u64()?,
            program: RefineProgramId(decoder.array()?),
        }),
        _ => Err(RefineProofCodecError::InvalidTag),
    }
}

fn encode_exit(encoder: &mut Encoder, exit: RefineSliceExit) -> Result<(), RefineProofCodecError> {
    match exit {
        RefineSliceExit::Halt => encoder.u8(0),
        RefineSliceExit::Panic => encoder.u8(1),
        RefineSliceExit::Trap => encoder.u8(2),
        RefineSliceExit::Ecall => encoder.u8(3),
        RefineSliceExit::OutOfGas => encoder.u8(4),
        RefineSliceExit::PageFault(address) => {
            encoder.u8(5)?;
            encoder.u32(address)
        }
        RefineSliceExit::HostCall(call) => {
            encoder.u8(6)?;
            encoder.u64(call)
        }
    }
}

fn decode_exit(decoder: &mut Decoder<'_>) -> Result<RefineSliceExit, RefineProofCodecError> {
    match decoder.u8()? {
        0 => Ok(RefineSliceExit::Halt),
        1 => Ok(RefineSliceExit::Panic),
        2 => Ok(RefineSliceExit::Trap),
        3 => Ok(RefineSliceExit::Ecall),
        4 => Ok(RefineSliceExit::OutOfGas),
        5 => Ok(RefineSliceExit::PageFault(decoder.u32()?)),
        6 => Ok(RefineSliceExit::HostCall(decoder.u64()?)),
        _ => Err(RefineProofCodecError::InvalidTag),
    }
}

fn encode_host_boundary(
    encoder: &mut Encoder,
    boundary: &RefineHostBoundary,
) -> Result<(), RefineProofCodecError> {
    encoder.u8(boundary.call)?;
    encoder.u32(boundary.slices_before)?;
    encoder.u32(boundary.slices_after)?;
    encoder.fixed(&boundary.state_before)?;
    encoder.fixed(&boundary.state_after)?;
    for register in boundary.registers_before {
        encoder.u64(register)?;
    }
    for register in boundary.registers_after {
        encoder.u64(register)?;
    }
    Ok(())
}

fn decode_host_boundary(
    decoder: &mut Decoder<'_>,
) -> Result<RefineHostBoundary, RefineProofCodecError> {
    Ok(RefineHostBoundary {
        call: decoder.u8()?,
        slices_before: decoder.u32()?,
        slices_after: decoder.u32()?,
        state_before: decoder.array()?,
        state_after: decoder.array()?,
        registers_before: decode_registers(decoder)?,
        registers_after: decode_registers(decoder)?,
    })
}

fn encode_proof(encoder: &mut Encoder, proof: &Proof) -> Result<(), RefineProofCodecError> {
    encoder.u32(proof.format_version)?;
    encoder.u32(
        u32::try_from(proof.num_components)
            .map_err(|_| RefineProofCodecError::InvalidCardinality)?,
    )?;
    encoder.u32(proof.component_mask)?;
    encode_pcs_config(encoder, proof.pcs_config)?;
    encoder.length(proof.claimed_sums.len())?;
    for value in &proof.claimed_sums {
        encode_secure_field(encoder, *value)?;
    }
    encoder.length(proof.log_sizes.len())?;
    for &log_size in &proof.log_sizes {
        encoder.u32(log_size)?;
    }
    encode_segment_state(encoder, &proof.initial_state)?;
    encode_segment_state(encoder, &proof.final_state)?;
    encode_stark_proof(encoder, &proof.stark_proof)
}

fn decode_proof(decoder: &mut Decoder<'_>) -> Result<Proof, RefineProofCodecError> {
    let format_version = decoder.u32()?;
    if format_version != PROOF_FORMAT_VERSION {
        return Err(RefineProofCodecError::InvalidStructure);
    }
    let num_components = decoder.u32()? as usize;
    if num_components == 0 || num_components > MAX_PROOF_COMPONENTS {
        return Err(RefineProofCodecError::InvalidCardinality);
    }
    let component_mask = decoder.u32()?;
    let pcs_config = decode_pcs_config(decoder)?;
    let claimed_sums =
        decoder.exact_vector(num_components, SECURE_FIELD_WIRE_BYTES, decode_secure_field)?;
    let log_sizes =
        decoder.exact_vector(num_components, U32_WIRE_BYTES, |decoder| decoder.u32())?;
    validate_log_sizes_and_config(&log_sizes, pcs_config)?;
    let initial_state = decode_segment_state(decoder)?;
    let final_state = decode_segment_state(decoder)?;
    let stark_proof = decode_stark_proof(decoder, pcs_config)?;
    Ok(Proof {
        format_version,
        stark_proof,
        claimed_sums,
        log_sizes,
        num_components,
        component_mask,
        pcs_config,
        initial_state,
        final_state,
    })
}

fn encode_pcs_config(
    encoder: &mut Encoder,
    config: PcsConfig,
) -> Result<(), RefineProofCodecError> {
    encoder.u32(config.pow_bits)?;
    encoder.u32(config.fri_config.log_blowup_factor)?;
    encoder.u32(config.fri_config.log_last_layer_degree_bound)?;
    encoder.u32(
        u32::try_from(config.fri_config.n_queries)
            .map_err(|_| RefineProofCodecError::InvalidCardinality)?,
    )?;
    encoder.u32(config.fri_config.fold_step)?;
    match config.lifting_log_size {
        None => encoder.u8(0),
        Some(value) => {
            encoder.u8(1)?;
            encoder.u32(value)
        }
    }
}

fn decode_pcs_config(decoder: &mut Decoder<'_>) -> Result<PcsConfig, RefineProofCodecError> {
    let pow_bits = decoder.u32()?;
    let log_blowup_factor = decoder.u32()?;
    let log_last_layer_degree_bound = decoder.u32()?;
    let n_queries = decoder.u32()? as usize;
    let fold_step = decoder.u32()?;
    let lifting_log_size = match decoder.u8()? {
        0 => None,
        1 => Some(decoder.u32()?),
        _ => return Err(RefineProofCodecError::InvalidTag),
    };
    if pow_bits > 31
        || !(1..=16).contains(&log_blowup_factor)
        || log_last_layer_degree_bound > 10
        || !(1..=MAX_FRI_QUERIES).contains(&n_queries)
        || fold_step != 1
        || lifting_log_size.is_some_and(|value| value > MAX_EXTENDED_LOG_SIZE)
    {
        return Err(RefineProofCodecError::InvalidStructure);
    }
    Ok(PcsConfig {
        pow_bits,
        fri_config: FriConfig {
            log_blowup_factor,
            log_last_layer_degree_bound,
            n_queries,
            fold_step,
        },
        lifting_log_size,
    })
}

fn validate_log_sizes_and_config(
    log_sizes: &[u32],
    config: PcsConfig,
) -> Result<(), RefineProofCodecError> {
    let maximum_log_size = log_sizes.iter().copied().max().unwrap_or_default();
    if log_sizes
        .iter()
        .any(|&value| !(MIN_PROOF_LOG_SIZE..=MAX_PROOF_LOG_SIZE).contains(&value))
    {
        return Err(RefineProofCodecError::InvalidStructure);
    }
    let maximum_extended = maximum_log_size
        .checked_add(config.fri_config.log_blowup_factor)
        .ok_or(RefineProofCodecError::InvalidStructure)?;
    if maximum_extended > MAX_EXTENDED_LOG_SIZE
        || config
            .lifting_log_size
            .is_some_and(|lifting| lifting < maximum_extended)
    {
        return Err(RefineProofCodecError::InvalidStructure);
    }
    Ok(())
}

fn encode_segment_state(
    encoder: &mut Encoder,
    state: &SegmentState,
) -> Result<(), RefineProofCodecError> {
    encoder.u32(state.pc)?;
    encoder.u64(state.timestamp)?;
    for register in state.registers {
        encoder.u64(register)?;
    }
    encoder.fixed(&state.memory_commitment)?;
    encoder.fixed(&state.memory_root)
}

fn decode_segment_state(decoder: &mut Decoder<'_>) -> Result<SegmentState, RefineProofCodecError> {
    Ok(SegmentState {
        pc: decoder.u32()?,
        timestamp: decoder.u64()?,
        registers: decode_registers(decoder)?,
        memory_commitment: decoder.array()?,
        memory_root: decoder.array()?,
    })
}

fn decode_registers(decoder: &mut Decoder<'_>) -> Result<[u64; 13], RefineProofCodecError> {
    let mut registers = [0u64; 13];
    for register in &mut registers {
        *register = decoder.u64()?;
    }
    Ok(registers)
}

fn encode_stark_proof(
    encoder: &mut Encoder,
    proof: &StarkProof<ProverMerkleHasher>,
) -> Result<(), RefineProofCodecError> {
    // The embedded Stwo config is structurally required to equal the public
    // Proof config. Encoding it once removes a second spelling of the same
    // authenticated value; decode installs the exact value in both fields.
    encoder.length(proof.commitments.len())?;
    for hash in proof.commitments.iter() {
        encode_merkle_hash(encoder, hash)?;
    }
    encoder.length(proof.sampled_values.len())?;
    for tree in proof.sampled_values.iter() {
        encoder.length(tree.len())?;
        for column in tree {
            encoder.length(column.len())?;
            for value in column {
                encode_secure_field(encoder, *value)?;
            }
        }
    }
    encoder.length(proof.decommitments.len())?;
    for decommitment in proof.decommitments.iter() {
        encode_decommitment(encoder, decommitment)?;
    }
    encoder.length(proof.queried_values.len())?;
    for tree in proof.queried_values.iter() {
        encoder.length(tree.len())?;
        for column in tree {
            encoder.length(column.len())?;
            for value in column {
                encode_base_field(encoder, *value)?;
            }
        }
    }
    encoder.u64(proof.proof_of_work)?;
    encode_fri_proof(encoder, &proof.fri_proof)
}

fn decode_stark_proof(
    decoder: &mut Decoder<'_>,
    config: PcsConfig,
) -> Result<StarkProof<ProverMerkleHasher>, RefineProofCodecError> {
    let commitments = TreeVec::new(decoder.exact_vector(
        PROOF_COMMITMENT_TREE_COUNT,
        MERKLE_HASH_WIRE_BYTES,
        decode_merkle_hash,
    )?);
    let sampled_values = TreeVec::new(decoder.exact_vector(
        PROOF_COMMITMENT_TREE_COUNT,
        U32_WIRE_BYTES,
        |decoder| {
            decoder.vector(MAX_PROOF_COLUMNS_PER_TREE, U32_WIRE_BYTES, |decoder| {
                decoder.vector(
                    MAX_PROOF_SAMPLES_PER_COLUMN,
                    SECURE_FIELD_WIRE_BYTES,
                    decode_secure_field,
                )
            })
        },
    )?);
    let decommitments = TreeVec::new(decoder.exact_vector(
        PROOF_COMMITMENT_TREE_COUNT,
        U32_WIRE_BYTES,
        |decoder| decode_decommitment(decoder, MAX_MERKLE_WITNESS_HASHES),
    )?);
    let queried_values = TreeVec::new(decoder.exact_vector(
        PROOF_COMMITMENT_TREE_COUNT,
        U32_WIRE_BYTES,
        |decoder| {
            decoder.vector(MAX_PROOF_COLUMNS_PER_TREE, U32_WIRE_BYTES, |decoder| {
                decoder.vector(
                    config.fri_config.n_queries,
                    BASE_FIELD_WIRE_BYTES,
                    decode_base_field,
                )
            })
        },
    )?);
    let proof_of_work = decoder.u64()?;
    let fri_proof = decode_fri_proof(decoder, config)?;
    Ok(StarkProof(CommitmentSchemeProof {
        config,
        commitments,
        sampled_values,
        decommitments,
        queried_values,
        proof_of_work,
        fri_proof,
    }))
}

fn encode_decommitment(
    encoder: &mut Encoder,
    decommitment: &MerkleDecommitmentLifted<ProverMerkleHasher>,
) -> Result<(), RefineProofCodecError> {
    encoder.length(decommitment.hash_witness.len())?;
    for hash in &decommitment.hash_witness {
        encode_merkle_hash(encoder, hash)?;
    }
    Ok(())
}

fn decode_decommitment(
    decoder: &mut Decoder<'_>,
    maximum_hashes: usize,
) -> Result<MerkleDecommitmentLifted<ProverMerkleHasher>, RefineProofCodecError> {
    Ok(MerkleDecommitmentLifted {
        hash_witness: decoder.vector(maximum_hashes, MERKLE_HASH_WIRE_BYTES, decode_merkle_hash)?,
    })
}

fn encode_fri_proof(
    encoder: &mut Encoder,
    proof: &FriProof<ProverMerkleHasher>,
) -> Result<(), RefineProofCodecError> {
    encode_fri_layer(encoder, &proof.first_layer)?;
    encoder.length(proof.inner_layers.len())?;
    for layer in &proof.inner_layers {
        encode_fri_layer(encoder, layer)?;
    }
    encoder.length(proof.last_layer_poly.iter().count())?;
    for value in proof.last_layer_poly.iter() {
        encode_secure_field(encoder, *value)?;
    }
    Ok(())
}

fn decode_fri_proof(
    decoder: &mut Decoder<'_>,
    config: PcsConfig,
) -> Result<FriProof<ProverMerkleHasher>, RefineProofCodecError> {
    let first_layer = decode_fri_layer(decoder, config.fri_config.n_queries)?;
    let inner_layers = decoder.vector(
        MAX_EXTENDED_LOG_SIZE as usize,
        MIN_FRI_LAYER_WIRE_BYTES,
        |decoder| decode_fri_layer(decoder, config.fri_config.n_queries),
    )?;
    let coefficient_count = 1usize
        .checked_shl(config.fri_config.log_last_layer_degree_bound)
        .ok_or(RefineProofCodecError::InvalidStructure)?;
    let coefficients = decoder.exact_vector(
        coefficient_count,
        SECURE_FIELD_WIRE_BYTES,
        decode_secure_field,
    )?;
    // The exact power-of-two count was authenticated and checked before the
    // allocation, so Stwo's constructor cannot panic here. Its private cached
    // log_size is reconstructed instead of deserialized.
    let last_layer_poly = LinePoly::new(coefficients);
    Ok(FriProof {
        first_layer,
        inner_layers,
        last_layer_poly,
    })
}

fn encode_fri_layer(
    encoder: &mut Encoder,
    layer: &FriLayerProof<ProverMerkleHasher>,
) -> Result<(), RefineProofCodecError> {
    encoder.length(layer.fri_witness.len())?;
    for value in &layer.fri_witness {
        encode_secure_field(encoder, *value)?;
    }
    encode_decommitment(encoder, &layer.decommitment)?;
    encode_merkle_hash(encoder, &layer.commitment)
}

fn decode_fri_layer(
    decoder: &mut Decoder<'_>,
    maximum_queries: usize,
) -> Result<FriLayerProof<ProverMerkleHasher>, RefineProofCodecError> {
    Ok(FriLayerProof {
        fri_witness: decoder.vector(
            maximum_queries,
            SECURE_FIELD_WIRE_BYTES,
            decode_secure_field,
        )?,
        decommitment: decode_decommitment(decoder, MAX_MERKLE_WITNESS_HASHES)?,
        commitment: decode_merkle_hash(decoder)?,
    })
}

fn encode_secure_field(
    encoder: &mut Encoder,
    value: SecureField,
) -> Result<(), RefineProofCodecError> {
    for limb in value.to_m31_array() {
        encode_base_field(encoder, limb)?;
    }
    Ok(())
}

fn decode_secure_field(decoder: &mut Decoder<'_>) -> Result<SecureField, RefineProofCodecError> {
    Ok(SecureField::from_m31_array([
        decode_base_field(decoder)?,
        decode_base_field(decoder)?,
        decode_base_field(decoder)?,
        decode_base_field(decoder)?,
    ]))
}

fn encode_base_field(encoder: &mut Encoder, value: BaseField) -> Result<(), RefineProofCodecError> {
    if value.0 >= P {
        return Err(RefineProofCodecError::NonCanonical);
    }
    encoder.u32(value.0)
}

fn decode_base_field(decoder: &mut Decoder<'_>) -> Result<BaseField, RefineProofCodecError> {
    let value = decoder.u32()?;
    if value >= P {
        return Err(RefineProofCodecError::NonCanonical);
    }
    Ok(BaseField::from_u32_unchecked(value))
}

fn encode_merkle_hash(
    encoder: &mut Encoder,
    hash: &ProverMerkleHash,
) -> Result<(), RefineProofCodecError> {
    encoder.fixed(&crate::recursion_pcs::commitment_bytes(hash))
}

#[cfg(not(feature = "poseidon2-channel"))]
fn decode_merkle_hash(
    decoder: &mut Decoder<'_>,
) -> Result<ProverMerkleHash, RefineProofCodecError> {
    Ok(stwo::core::vcs::blake2_hash::Blake2sHash(decoder.array()?))
}

#[cfg(feature = "poseidon2-channel")]
fn decode_merkle_hash(
    decoder: &mut Decoder<'_>,
) -> Result<ProverMerkleHash, RefineProofCodecError> {
    let mut limbs = [BaseField::from_u32_unchecked(0); 8];
    for limb in &mut limbs {
        *limb = decode_base_field(decoder)?;
    }
    Ok(crate::poseidon2::P2Hash(limbs))
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn fixed(&mut self, value: &[u8]) -> Result<(), RefineProofCodecError> {
        let new_len = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(RefineProofCodecError::WireLimitExceeded)?;
        if new_len > MAX_REFINE_PROOF_BUNDLE_WIRE_BYTES {
            return Err(RefineProofCodecError::WireLimitExceeded);
        }
        self.bytes
            .try_reserve(value.len())
            .map_err(|_| RefineProofCodecError::AllocationFailed)?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), RefineProofCodecError> {
        self.fixed(&[value])
    }

    fn u32(&mut self, value: u32) -> Result<(), RefineProofCodecError> {
        self.fixed(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), RefineProofCodecError> {
        self.fixed(&value.to_le_bytes())
    }

    fn length(&mut self, length: usize) -> Result<(), RefineProofCodecError> {
        self.u32(u32::try_from(length).map_err(|_| RefineProofCodecError::InvalidCardinality)?)
    }
}

struct AllocationBudget {
    remaining: usize,
}

impl AllocationBudget {
    fn charge(&mut self, bytes: usize) -> Result<(), RefineProofCodecError> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or(RefineProofCodecError::AllocationLimitExceeded)?;
        Ok(())
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
    allocation: AllocationBudget,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8], maximum_allocation: usize) -> Result<Self, RefineProofCodecError> {
        let mut allocation = AllocationBudget {
            remaining: maximum_allocation,
        };
        // The returned root owns its two top-level Vec headers. Every nested
        // header is then charged exactly once as part of its parent's reserved
        // element payload; each separately allocated payload is charged by
        // `allocate_vector` immediately before reserve.
        allocation.charge(size_of::<RefineProofBundle>())?;
        Ok(Self {
            bytes,
            position: 0,
            allocation,
        })
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn remaining_wire(&self) -> usize {
        self.bytes.len() - self.position
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RefineProofCodecError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(RefineProofCodecError::Truncated)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(RefineProofCodecError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RefineProofCodecError> {
        self.take(N)?
            .try_into()
            .map_err(|_| RefineProofCodecError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, RefineProofCodecError> {
        Ok(self.array::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32, RefineProofCodecError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, RefineProofCodecError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn vector<T>(
        &mut self,
        maximum_count: usize,
        minimum_element_wire_bytes: usize,
        mut decode: impl FnMut(&mut Self) -> Result<T, RefineProofCodecError>,
    ) -> Result<Vec<T>, RefineProofCodecError> {
        let count = self.vector_count(maximum_count, minimum_element_wire_bytes)?;
        let mut values = self.allocate_vector(count)?;
        for _ in 0..count {
            values.push(decode(self)?);
        }
        Ok(values)
    }

    fn exact_vector<T>(
        &mut self,
        expected_count: usize,
        minimum_element_wire_bytes: usize,
        mut decode: impl FnMut(&mut Self) -> Result<T, RefineProofCodecError>,
    ) -> Result<Vec<T>, RefineProofCodecError> {
        let count = self.u32()? as usize;
        if count != expected_count {
            return Err(RefineProofCodecError::InvalidCardinality);
        }
        self.require_minimum_wire(count, minimum_element_wire_bytes)?;
        let mut values = self.allocate_vector(count)?;
        for _ in 0..count {
            values.push(decode(self)?);
        }
        Ok(values)
    }

    fn vector_count(
        &mut self,
        maximum_count: usize,
        minimum_element_wire_bytes: usize,
    ) -> Result<usize, RefineProofCodecError> {
        let count = self.u32()? as usize;
        if count > maximum_count {
            return Err(RefineProofCodecError::InvalidCardinality);
        }
        self.require_minimum_wire(count, minimum_element_wire_bytes)?;
        Ok(count)
    }

    fn require_minimum_wire(
        &self,
        count: usize,
        minimum_element_wire_bytes: usize,
    ) -> Result<(), RefineProofCodecError> {
        let minimum = count
            .checked_mul(minimum_element_wire_bytes)
            .ok_or(RefineProofCodecError::InvalidCardinality)?;
        if minimum > self.remaining_wire() {
            return Err(RefineProofCodecError::Truncated);
        }
        Ok(())
    }

    fn allocate_vector<T>(&mut self, count: usize) -> Result<Vec<T>, RefineProofCodecError> {
        let allocation = count
            .checked_mul(size_of::<T>())
            .ok_or(RefineProofCodecError::AllocationLimitExceeded)?;
        self.allocation.charge(allocation)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| RefineProofCodecError::AllocationFailed)?;
        Ok(values)
    }

    fn charge_temporary(&mut self, bytes: usize) -> Result<(), RefineProofCodecError> {
        self.allocation.charge(bytes)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    const SLICE_COUNT_OFFSET: usize = 8 + 4 + 4 + 32 + 32 + 8;
    const FIRST_CLAIMED_SUM_COUNT_OFFSET: usize =
        SLICE_COUNT_OFFSET + 4 + 4 + (1 + 32) + 32 + 32 + 1 + 4 + 4 + 4 + (4 + 4 + 4 + 4 + 4 + 1);
    const FIRST_CLAIMED_SUM_LIMB_OFFSET: usize = FIRST_CLAIMED_SUM_COUNT_OFFSET + 4;
    const FIRST_COMMITMENT_OFFSET: usize = FIRST_CLAIMED_SUM_COUNT_OFFSET
        + 4
        + SECURE_FIELD_WIRE_BYTES
        + 4
        + U32_WIRE_BYTES
        + 2 * SEGMENT_STATE_WIRE_BYTES
        + 4;
    const FIRST_SAMPLED_TREE_COLUMN_COUNT_OFFSET: usize = FIRST_CLAIMED_SUM_COUNT_OFFSET
        + 4
        + SECURE_FIELD_WIRE_BYTES
        + 4
        + U32_WIRE_BYTES
        + 2 * SEGMENT_STATE_WIRE_BYTES
        + 4
        + PROOF_COMMITMENT_TREE_COUNT * MERKLE_HASH_WIRE_BYTES
        + 4;

    fn zero_secure() -> SecureField {
        SecureField::from_u32_unchecked(0, 0, 0, 0)
    }

    #[cfg(not(feature = "poseidon2-channel"))]
    fn hash(byte: u8) -> ProverMerkleHash {
        stwo::core::vcs::blake2_hash::Blake2sHash([byte; 32])
    }

    #[cfg(feature = "poseidon2-channel")]
    fn hash(byte: u8) -> ProverMerkleHash {
        crate::poseidon2::P2Hash([BaseField::from_u32_unchecked(byte as u32); 8])
    }

    fn proof() -> Proof {
        let config = PcsConfig {
            pow_bits: 0,
            fri_config: FriConfig {
                log_blowup_factor: 1,
                log_last_layer_degree_bound: 0,
                n_queries: 1,
                fold_step: 1,
            },
            lifting_log_size: None,
        };
        let commitments = TreeVec::new((1..=4).map(hash).collect());
        let sampled_values = TreeVec::new(vec![
            vec![vec![SecureField::from_u32_unchecked(1, 2, 3, 4)]],
            vec![vec![SecureField::from_u32_unchecked(5, 6, 7, 8)]],
            vec![vec![SecureField::from_u32_unchecked(9, 10, 11, 12)]],
            vec![vec![SecureField::from_u32_unchecked(13, 14, 15, 16)]],
        ]);
        let decommitments = TreeVec::new(
            (0..PROOF_COMMITMENT_TREE_COUNT)
                .map(|index| MerkleDecommitmentLifted {
                    hash_witness: vec![hash(30 + index as u8)],
                })
                .collect(),
        );
        let queried_values = TreeVec::new(vec![
            vec![vec![BaseField::from_u32_unchecked(1)]],
            vec![vec![BaseField::from_u32_unchecked(2)]],
            vec![vec![BaseField::from_u32_unchecked(3)]],
            vec![vec![BaseField::from_u32_unchecked(4)]],
        ]);
        let fri_proof = FriProof {
            first_layer: FriLayerProof {
                fri_witness: vec![SecureField::from_u32_unchecked(17, 18, 19, 20)],
                decommitment: MerkleDecommitmentLifted {
                    hash_witness: vec![hash(40)],
                },
                commitment: hash(5),
            },
            inner_layers: vec![FriLayerProof {
                fri_witness: vec![SecureField::from_u32_unchecked(21, 22, 23, 24)],
                decommitment: MerkleDecommitmentLifted {
                    hash_witness: vec![hash(41)],
                },
                commitment: hash(6),
            }],
            last_layer_poly: LinePoly::new(vec![zero_secure()]),
        };
        let state = SegmentState {
            pc: 7,
            timestamp: 11,
            registers: [13; 13],
            memory_commitment: [17; 32],
            memory_root: [19; 32],
        };
        Proof {
            format_version: PROOF_FORMAT_VERSION,
            stark_proof: StarkProof(CommitmentSchemeProof {
                config,
                commitments,
                sampled_values,
                decommitments,
                queried_values,
                proof_of_work: 23,
                fri_proof,
            }),
            claimed_sums: vec![zero_secure()],
            log_sizes: vec![4],
            num_components: 1,
            component_mask: 1,
            pcs_config: config,
            initial_state: state.clone(),
            final_state: state,
        }
    }

    fn bundle() -> RefineProofBundle {
        let outer_program = RefineProgramId([29; 32]);
        let mut bundle = RefineProofBundle {
            format_version: REFINE_BUNDLE_FORMAT_VERSION,
            outer_program,
            arguments_commitment: [31; 32],
            gas_limit: 37,
            slices: vec![RefineProofSlice {
                order: 0,
                identity: RefineMachineId::Outer {
                    program: outer_program,
                },
                entry_state: [41; 32],
                observed_exit_state: [43; 32],
                exit: RefineSliceExit::Halt,
                proof: proof(),
            }],
            host_boundaries: Vec::new(),
            result: RefineSliceExit::Halt,
            transcript_commitment: [0; 32],
        };
        bundle.transcript_commitment = refine_bundle_commitment(&bundle);
        bundle
    }

    fn patch_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn canonical_bundle_roundtrips_under_its_exact_wire_ceiling() {
        let bundle = bundle();
        let encoded = encode_refine_proof_bundle(&bundle).unwrap();
        let decoded = decode_refine_proof_bundle(&encoded, encoded.len() as u64).unwrap();
        assert_eq!(encode_refine_proof_bundle(&decoded).unwrap(), encoded);
        assert_eq!(decoded.transcript_commitment, bundle.transcript_commitment);
        assert_eq!(decoded.slices[0].proof.format_version, PROOF_FORMAT_VERSION);
        assert_eq!(
            decoded.slices[0].proof.stark_proof.config,
            decoded.slices[0].proof.pcs_config
        );
    }

    #[test]
    fn authenticated_wire_ceiling_is_checked_before_parsing() {
        let encoded = encode_refine_proof_bundle(&bundle()).unwrap();
        assert_eq!(
            decode_refine_proof_bundle(&encoded, 0).unwrap_err(),
            RefineProofCodecError::InvalidCeiling
        );
        assert_eq!(
            decode_refine_proof_bundle(
                &encoded,
                vos_agent_sdk::MAX_TRANSITION_PROOF_MATERIAL_BYTES + 1,
            )
            .unwrap_err(),
            RefineProofCodecError::InvalidCeiling
        );
        assert_eq!(
            decode_refine_proof_bundle(&encoded, encoded.len() as u64 - 1).unwrap_err(),
            RefineProofCodecError::WireLimitExceeded
        );
    }

    #[test]
    fn hostile_lengths_fail_before_reserve_at_every_depth() {
        let encoded = encode_refine_proof_bundle(&bundle()).unwrap();

        let mut too_many_slices = encoded.clone();
        patch_u32(&mut too_many_slices, SLICE_COUNT_OFFSET, u32::MAX);
        assert_eq!(
            decode_refine_proof_bundle(&too_many_slices, too_many_slices.len() as u64).unwrap_err(),
            RefineProofCodecError::InvalidCardinality
        );

        let mut wrong_claimed_sums = encoded.clone();
        patch_u32(
            &mut wrong_claimed_sums,
            FIRST_CLAIMED_SUM_COUNT_OFFSET,
            u32::MAX,
        );
        assert_eq!(
            decode_refine_proof_bundle(&wrong_claimed_sums, wrong_claimed_sums.len() as u64)
                .unwrap_err(),
            RefineProofCodecError::InvalidCardinality
        );

        let mut too_many_sampled_columns = encoded;
        patch_u32(
            &mut too_many_sampled_columns,
            FIRST_SAMPLED_TREE_COLUMN_COUNT_OFFSET,
            MAX_PROOF_COLUMNS_PER_TREE as u32 + 1,
        );
        assert_eq!(
            decode_refine_proof_bundle(
                &too_many_sampled_columns,
                too_many_sampled_columns.len() as u64,
            )
            .unwrap_err(),
            RefineProofCodecError::InvalidCardinality
        );
    }

    #[test]
    fn allocation_budget_is_charged_before_reserve() {
        let bytes = [1, 0, 0, 0, 0];
        let mut decoder = Decoder::new(&bytes, size_of::<RefineProofBundle>()).unwrap();
        assert_eq!(
            decoder
                .vector::<u8>(1, 1, |decoder| decoder.u8())
                .unwrap_err(),
            RefineProofCodecError::AllocationLimitExceeded
        );
    }

    #[test]
    fn trailing_and_noncanonical_field_bytes_are_rejected() {
        let encoded = encode_refine_proof_bundle(&bundle()).unwrap();
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_refine_proof_bundle(&trailing, trailing.len() as u64).unwrap_err(),
            RefineProofCodecError::TrailingBytes
        );

        let mut noncanonical = encoded;
        patch_u32(&mut noncanonical, FIRST_CLAIMED_SUM_LIMB_OFFSET, P);
        assert_eq!(
            decode_refine_proof_bundle(&noncanonical, noncanonical.len() as u64).unwrap_err(),
            RefineProofCodecError::NonCanonical
        );
    }

    #[test]
    fn substituted_and_reordered_material_fails_closed() {
        let mut substituted = encode_refine_proof_bundle(&bundle()).unwrap();
        substituted[FIRST_COMMITMENT_OFFSET] ^= 1;
        assert_eq!(
            decode_refine_proof_bundle(&substituted, substituted.len() as u64).unwrap_err(),
            RefineProofCodecError::CommitmentMismatch
        );

        let mut reordered = bundle();
        reordered.slices.push(reordered.slices[0].clone());
        reordered.slices[0].order = 1;
        reordered.slices[1].order = 0;
        reordered.transcript_commitment = refine_bundle_commitment(&reordered);
        let hostile = encode_bundle_fields(&reordered).unwrap();
        assert_eq!(
            decode_refine_proof_bundle(&hostile, hostile.len() as u64).unwrap_err(),
            RefineProofCodecError::NonCanonical
        );
    }
}
