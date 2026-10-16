//! The format registry at the verifier: every admitted format round-trips
//! and verifies in one build, a proof is refused under another format than
//! its own, the interaction PoW is checked, and a proof below a floor is
//! refused. Format 26 proves on the Poseidon2-M31 channel, its PoW and
//! interaction PoW ground on `SimdBackend`.

use std::sync::OnceLock;

use stwo::core::fields::m31::BaseField;
use stwo::core::proof::StarkProof;
use vos_pvm::PVM_REGISTER_COUNT;
use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;
use vos_pvm_proof::core::tracing::TracingPvm;
use vos_pvm_proof::format::{self, Format};
use vos_pvm_proof::poseidon2::{P2MerkleHasher, Poseidon2M31Channel};
use vos_pvm_proof::security::SecurityBits;
use vos_pvm_proof::{Proof, SideNote, StarkProofAny, program_commitment_of_proof};
use vos_pvm_proof_verifier::{proof_security_bits, verify_standalone};

/// Six chained Add64s and a trap: seven steps over 4 MiB of memory.
fn side_note() -> SideNote {
    let mut code = Vec::new();
    let mut bitmask = Vec::new();
    for register in 2..8 {
        code.extend_from_slice(&[Opcode::Add64 as u8, 0x10 | (register - 1), register]);
        bitmask.extend_from_slice(&[1, 0, 0]);
    }
    code.push(Opcode::Trap as u8);
    bitmask.push(1);
    let mut registers = [0u64; PVM_REGISTER_COUNT];
    registers[0] = 100;
    registers[1] = 1;
    let memory = vec![0u8; 4 * 1024 * 1024];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        registers,
        memory.clone(),
        10_000,
    );
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run(), vos_pvm::ExitReason::Panic);
    let steps = tracing.into_trace();
    assert_eq!(steps.len(), 7);
    SideNote::new(steps, code, bitmask).with_memory(memory)
}

/// One proof under `format` and the side note it was proved over, made once.
fn proved(format: &'static Format) -> &'static (Proof, SideNote) {
    static LEGACY: OnceLock<(Proof, SideNote)> = OnceLock::new();
    static SEGMENT: OnceLock<(Proof, SideNote)> = OnceLock::new();
    let cell = match format.number {
        24 => &LEGACY,
        26 => &SEGMENT,
        number => panic!("format {number} is not proved here"),
    };
    cell.get_or_init(|| {
        let mut side_note = side_note();
        let proof = vos_pvm_proof::prove_format(&mut side_note, format).expect("proves");
        (proof, side_note)
    })
}

fn admitted() -> [&'static Format; 2] {
    [&format::LEGACY_SEGMENT, &format::SEGMENT]
}

fn refused_standalone(proof: Proof, expected: &str) {
    let commitment = proof.preprocessed_commitment().unwrap();
    let error = verify_standalone(proof, commitment).expect_err("refused");
    assert!(error.to_string().contains(expected), "{error}");
}

fn refused_both(proof: Proof, side_note: &SideNote, expected: &str) {
    let error = vos_pvm_proof::verify(proof.clone(), side_note).expect_err("refused");
    assert!(error.to_string().contains(expected), "{error}");
    refused_standalone(proof, expected);
}

fn poseidon2_stark(proof: &mut Proof) -> &mut StarkProof<P2MerkleHasher> {
    match &mut proof.stark_proof {
        StarkProofAny::Poseidon2M31(stark) => stark,
        other => panic!("a Poseidon2-M31 proof, not {:?}", other.channel()),
    }
}

/// Every admitted format proves, round-trips through bincode and postcard,
/// and verifies with and without the side note, in one verifier build; its
/// proof carries its format's channel and parameters.
#[test]
fn every_admitted_format_round_trips() {
    for format in admitted() {
        let (proof, side_note) = proved(format);
        assert_eq!(proof.format_version, format.number);
        assert_eq!(proof.stark_proof.channel(), format.channel);
        assert_eq!(proof.pcs_config, format.pcs_config());
        assert_eq!(
            proof.interaction_pow != 0,
            format.interaction_pow_bits() > 0
        );
        let commitment = program_commitment_of_proof(proof);
        assert_eq!(commitment.channel(), format.channel);

        let bincoded: Proof = bincode::deserialize(&bincode::serialize(proof).unwrap()).unwrap();
        let posted: Proof = postcard::from_bytes(&postcard::to_allocvec(proof).unwrap()).unwrap();
        for decoded in [bincoded, posted] {
            assert_eq!(decoded.interaction_pow, proof.interaction_pow);
            verify_standalone(decoded.clone(), commitment)
                .unwrap_or_else(|error| panic!("format {}: {error}", format.number));
            vos_pvm_proof::verify(decoded, side_note)
                .unwrap_or_else(|error| panic!("format {}: {error}", format.number));
        }
    }
}

/// A proof is refused under every other number: a registered format the
/// registry does not admit, the other admitted format (whose channel its
/// Stark proof is not on), and an unregistered number.
#[test]
fn a_proof_under_one_format_is_refused_under_another() {
    for format in admitted() {
        let (proof, side_note) = proved(format);
        for other in format::REGISTRY
            .iter()
            .filter(|other| other.number != format.number)
        {
            let mut relabelled = proof.clone();
            relabelled.format_version = other.number;
            let expected = if other.status == format::Status::Admitted {
                "Stark proof is on"
            } else {
                "not admitted"
            };
            refused_both(relabelled, side_note, expected);
        }
        for number in [25, 31] {
            let mut relabelled = proof.clone();
            relabelled.format_version = number;
            refused_both(relabelled, side_note, "not registered");
        }
    }
}

/// The interaction PoW is checked: a format-26 proof with a nonce its
/// channel does not accept is refused, and a format-24 proof, which has
/// none, is refused with a nonce.
#[test]
fn the_interaction_pow_is_checked() {
    let (proof, side_note) = proved(&format::SEGMENT);
    let mut wrong = proof.clone();
    // The nonce the verifier checks on the channel as it stands after the
    // boundary states: replay that far and pick one the PoW refuses.
    let channel = transcript_before_interaction_pow(proof);
    wrong.interaction_pow = (proof.interaction_pow + 1..)
        .find(|&nonce| {
            !stwo::core::channel::Channel::verify_pow_nonce(
                &channel,
                format::SEGMENT.interaction_pow_bits(),
                nonce,
            )
        })
        .unwrap();
    assert!(stwo::core::channel::Channel::verify_pow_nonce(
        &channel,
        format::SEGMENT.interaction_pow_bits(),
        proof.interaction_pow
    ));
    refused_both(wrong, side_note, "interaction PoW");

    let (legacy, side_note) = proved(&format::LEGACY_SEGMENT);
    let mut nonced = legacy.clone();
    nonced.interaction_pow = 1;
    refused_both(nonced, side_note, "no interaction PoW");
}

/// The verifier's channel just before the interaction PoW, replayed from the
/// proof as A.1 orders it.
fn transcript_before_interaction_pow(proof: &Proof) -> Poseidon2M31Channel {
    use stwo::core::channel::MerkleChannel;
    let mut channel = Poseidon2M31Channel::default();
    vos_pvm_proof::proof::mix_statement_header(
        &mut channel,
        proof.format_version,
        &proof.pcs_config,
        &proof.log_sizes,
    );
    let mut proof = proof.clone();
    let stark = poseidon2_stark(&mut proof).clone();
    for root in &stark.commitments[..2] {
        vos_pvm_proof::poseidon2::P2MerkleChannel::mix_root(&mut channel, *root);
    }
    vos_pvm_proof::proof::mix_boundary_states(
        &mut channel,
        format::SEGMENT.encoding,
        &proof.initial_state,
        &proof.final_state,
    );
    channel
}

/// A proof below a floor is refused: less PoW than format 26's conjectured
/// floor allows; and, at its floors, parameters other than the format's.
#[test]
fn a_proof_below_a_floor_is_refused() {
    let (proof, side_note) = proved(&format::SEGMENT);
    let with_config = |mutate: fn(&mut stwo::core::pcs::PcsConfig)| {
        let mut changed = proof.clone();
        mutate(&mut changed.pcs_config);
        poseidon2_stark(&mut changed).0.config = changed.pcs_config;
        changed
    };
    refused_both(
        with_config(|config| config.pow_bits = 21),
        side_note,
        "99 conjectured bits, below format 26's floor of 100",
    );
    refused_both(
        with_config(|config| config.pow_bits = 27),
        side_note,
        "differ from format 26",
    );
}

/// The counts of a real proof, at its own shape, clear format 26's floors;
/// format 24's carry its conjectured 96.
#[test]
fn the_bit_counts_are_counted_at_the_proofs_shape() {
    let segment = proof_security_bits(&proved(&format::SEGMENT).0).unwrap();
    let legacy = proof_security_bits(&proved(&format::LEGACY_SEGMENT).0).unwrap();
    assert_eq!(
        (segment, legacy),
        (
            SecurityBits {
                conjectured: 104,
                proven: 64,
            },
            SecurityBits {
                conjectured: 96,
                proven: 57,
            },
        )
    );
    assert!(segment.proven >= format::SEGMENT.floor.proven);
}

/// A full canonical segment proves under format 26 and verifies; a main
/// root with one limb changed is refused, and a non-canonical limb is
/// refused without a panic.
#[test]
fn a_canonical_segment_proves_under_the_poseidon2_format() {
    let mut side_note = side_note();
    let proof = vos_pvm_proof::prove_canonical_format(&mut side_note, &[], &format::SEGMENT)
        .expect("proves");
    assert_eq!(proof.num_components, vos_pvm_proof::chip_idx::COUNT);
    let commitment = program_commitment_of_proof(&proof);
    verify_standalone(proof.clone(), commitment).expect("verifies");

    let mut tampered = proof.clone();
    let root = &mut poseidon2_stark(&mut tampered).0.commitments[1].0[0];
    *root += BaseField::from_u32_unchecked(1);
    assert!(verify_standalone(tampered, commitment).is_err());

    let mut noncanonical = proof;
    poseidon2_stark(&mut noncanonical).0.commitments[1].0[0] =
        BaseField::from_u32_unchecked(u32::MAX);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_standalone(noncanonical, commitment)
    }));
    assert!(outcome.expect("no panic").is_err());
}
