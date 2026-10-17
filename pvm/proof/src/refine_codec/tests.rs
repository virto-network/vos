//! The codec's round trips and its refusals.

use alloc::vec;

use super::*;

const SLICE_COUNT_OFFSET: usize = 8 + 4 + 4 + 32 + 32 + 8;
const FIRST_FORMAT_OFFSET: usize = SLICE_COUNT_OFFSET + 4 + 4 + (1 + 32) + 32 + 32 + 1;
const FIRST_CLAIMED_SUM_COUNT_OFFSET: usize =
    FIRST_FORMAT_OFFSET + 4 + 8 + 4 + 4 + (4 + 4 + 4 + 4 + 4 + 1);
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

fn blake2s_hash(byte: u8) -> stwo::core::vcs::blake2_hash::Blake2sHash {
    stwo::core::vcs::blake2_hash::Blake2sHash([byte; 32])
}

fn poseidon2_hash(byte: u8) -> crate::poseidon2::P2Hash {
    crate::poseidon2::P2Hash([BaseField::from_u32_unchecked(byte as u32); 8])
}

/// A format-33 proof, on the Blake2s channel.
fn proof() -> Proof {
    let (config, stark) = stark_proof(blake2s_hash);
    proof_of(
        crate::format::LEGACY_SEGMENT.number,
        config,
        StarkProofAny::Blake2s(stark),
        0,
    )
}

/// A format-31 proof, on the Poseidon2-M31 channel.
fn poseidon2_proof() -> Proof {
    let (config, stark) = stark_proof(poseidon2_hash);
    proof_of(
        crate::format::SEGMENT.number,
        config,
        StarkProofAny::Poseidon2M31(stark),
        0x0123_4567_89ab_cdef,
    )
}

fn proof_of(
    format_version: u32,
    config: PcsConfig,
    stark_proof: StarkProofAny,
    interaction_pow: u64,
) -> Proof {
    let state = SegmentState {
        pc: 7,
        timestamp: 11,
        registers: [13; 13],
        memory_commitment: [17; 32],
        memory_root: [19; 32],
    };
    Proof {
        format_version,
        stark_proof,
        interaction_pow,
        claimed_sums: vec![zero_secure()],
        log_sizes: vec![4],
        num_components: 1,
        component_mask: 1,
        pcs_config: config,
        initial_state: state.clone(),
        final_state: state,
    }
}

fn stark_proof<H: MerkleHasherLifted>(hash: impl Fn(u8) -> H::Hash) -> (PcsConfig, StarkProof<H>) {
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
    let commitments = TreeVec::new((1..=4).map(&hash).collect());
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
    (
        config,
        StarkProof(CommitmentSchemeProof {
            config,
            commitments,
            sampled_values,
            decommitments,
            queried_values,
            proof_of_work: 23,
            fri_proof,
        }),
    )
}

fn bundle() -> RefineProofBundle {
    bundle_of(proof())
}

fn bundle_of(proof: Proof) -> RefineProofBundle {
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
            proof,
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
    assert_eq!(
        decoded.slices[0].proof.format_version,
        crate::PROOF_FORMAT_VERSION
    );
    assert_eq!(
        decoded.slices[0].proof.stark_proof.config(),
        decoded.slices[0].proof.pcs_config
    );
}

/// A child under the Poseidon2-M31 segment format round-trips, its
/// interaction PoW nonce with it; under a number the registry does not
/// admit, or with its Stark proof on another channel than its format's,
/// it is refused.
#[test]
fn every_admitted_format_roundtrips_and_others_are_refused() {
    let bundle = bundle_of(poseidon2_proof());
    let encoded = encode_refine_proof_bundle(&bundle).unwrap();
    let decoded = decode_refine_proof_bundle(&encoded, encoded.len() as u64).unwrap();
    assert_eq!(encode_refine_proof_bundle(&decoded).unwrap(), encoded);
    let child = &decoded.slices[0].proof;
    assert_eq!(child.format_version, crate::format::SEGMENT.number);
    assert_eq!(child.interaction_pow, 0x0123_4567_89ab_cdef);
    assert!(matches!(child.stark_proof, StarkProofAny::Poseidon2M31(_)));

    for format in crate::format::REGISTRY
        .iter()
        .filter(|format| format.status != crate::format::Status::Admitted)
    {
        let mut reserved = poseidon2_proof();
        reserved.format_version = format.number;
        assert_eq!(
            encode_refine_proof_bundle(&bundle_of(reserved)).unwrap_err(),
            RefineProofCodecError::InvalidStructure,
            "format {}",
            format.number
        );
    }
    let mut crossed = poseidon2_proof();
    crossed.format_version = crate::format::LEGACY_SEGMENT.number;
    assert_eq!(
        encode_refine_proof_bundle(&bundle_of(crossed)).unwrap_err(),
        RefineProofCodecError::InvalidStructure
    );
}

/// The decoder refuses a child whose number the bytes change: to a number
/// the registry does not admit, before reading its proof; to the other
/// admitted format, whose channel would read the proof's hashes as its own,
/// by the transcript commitment, which binds the number; and on the
/// Poseidon2-M31 channel, a Blake2s hash that is no M31 digest.
#[test]
fn the_decoder_refuses_reserved_formats_and_channel_mismatches() {
    let decode = |bytes: &[u8]| decode_refine_proof_bundle(bytes, bytes.len() as u64);
    let encoded = encode_refine_proof_bundle(&bundle_of(poseidon2_proof())).unwrap();
    assert_eq!(
        u32::from_le_bytes(encoded[FIRST_FORMAT_OFFSET..][..4].try_into().unwrap()),
        crate::format::SEGMENT.number
    );
    decode(&encoded).unwrap();
    for number in crate::format::REGISTRY
        .iter()
        .filter(|format| format.status != crate::format::Status::Admitted)
        .map(|format| format.number)
        .chain(crate::format::RETIRED)
        .chain([35])
    {
        let mut reserved = encoded.clone();
        patch_u32(&mut reserved, FIRST_FORMAT_OFFSET, number);
        assert_eq!(
            decode(&reserved).unwrap_err(),
            RefineProofCodecError::InvalidStructure,
            "format {number}"
        );
    }

    let mut crossed = encoded;
    patch_u32(
        &mut crossed,
        FIRST_FORMAT_OFFSET,
        crate::format::LEGACY_SEGMENT.number,
    );
    assert_eq!(
        decode(&crossed).unwrap_err(),
        RefineProofCodecError::CommitmentMismatch
    );

    let (config, stark) = stark_proof(|_| blake2s_hash(0xff));
    let blake2s = proof_of(
        crate::format::LEGACY_SEGMENT.number,
        config,
        StarkProofAny::Blake2s(stark),
        0,
    );
    let mut crossed = encode_refine_proof_bundle(&bundle_of(blake2s)).unwrap();
    patch_u32(
        &mut crossed,
        FIRST_FORMAT_OFFSET,
        crate::format::SEGMENT.number,
    );
    assert_eq!(
        decode(&crossed).unwrap_err(),
        RefineProofCodecError::NonCanonical
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
        decode_refine_proof_bundle(&encoded, (MAX_REFINE_PROOF_BUNDLE_WIRE_BYTES as u64) + 1,)
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
