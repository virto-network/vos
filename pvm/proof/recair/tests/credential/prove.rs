//! Proving and verifying: each kind proved under format 44 on the
//! Blake2s-M31 channel and verified by the final verifier against its
//! pinned program; the pins computed from the circuits; the joint circuit
//! proved and verified, and a proof under the retired 42's parameters
//! refused; the prover generic over the channel; the built set's shape the
//! registry's reference.

use num_traits::Zero;
use stwo::core::air::Component;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::quotients::deep_values_of_column;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sMerkleChannel};
use stwo_constraint_framework::Relation;
use vos_pvm_final_verifier::credential::{
    self as verifier, AUTH_PROGRAM, AUTH_ROOT, CredentialProof, MAX_PROOF_BYTES, OWNER_PROGRAM,
    OWNER_ROOT, PINS,
};
use vos_pvm_proof::format::{CREDENTIAL_PROOF, CREDENTIAL_REFERENCE, Format, FormatParams};
use vos_pvm_proof::security::{SecurityShape, proven_count};
use vos_pvm_recair::credential::{self, LOG_SIZES, Statement};
use vos_pvm_recair::masked::MaskRng;
use vos_pvm_recair_air::credential::CredentialKind;
use vos_pvm_recair_air::gate::{GATE_WIDTH, GateRelation};
use vos_pvm_recair_air::masked::{
    BlindRelation, CredentialComponents, MaskedComponent, MaskedComponents, air_log_size,
    committed_log_sizes, composition_log_degree_bound, sample_points,
};

use crate::common::Rng;
use crate::support::{self, auth, joint, owner_statement};

/// `statement`'s proof under format 44.
pub fn prove(statement: &Statement) -> CredentialProof {
    credential::prove(statement, MaskRng::default())
        .expect("the statement proves")
        .0
}

/// Verifies `proof` of `statement` with the final verifier.
pub fn verify(
    statement: &Statement,
    proof: CredentialProof,
) -> Result<(), vos_pvm_final_verifier::Error> {
    let kind = statement.kind().expect("an admitted kind");
    verifier::verify(kind, &statement.words(), proof)
}

/// The final verifier's pinned roots and program ids are the circuits':
/// computed here from the circuit and the registry, a change to either
/// moves them.
#[test]
fn the_pinned_programs_are_the_circuits() {
    let roots = CredentialKind::ALL.map(|kind| {
        credential::preprocessed_root::<Blake2sM31MerkleChannel>(
            &CREDENTIAL_PROOF,
            &credential::circuit(Some(kind)),
        )
        .unwrap()
        .0
    });
    let programs = CredentialKind::ALL.map(credential::program_id);
    eprintln!("roots {roots:?}\nprograms {programs:?}");
    assert_eq!(roots, [AUTH_ROOT, OWNER_ROOT]);
    assert_eq!(programs, [AUTH_PROGRAM, OWNER_PROGRAM]);
    assert_ne!(AUTH_PROGRAM, OWNER_PROGRAM);
    let joint = credential::preprocessed_root::<Blake2sM31MerkleChannel>(
        &CREDENTIAL_PROOF,
        &credential::circuit(None),
    )
    .unwrap()
    .0;
    assert!(!roots.contains(&joint));
    // The retired 42 committed the same columns at the same blowup: one
    // root, another program id, which hashes the format.
    let at_42 = credential::preprocessed_root::<Blake2sM31MerkleChannel>(
        &retired_42(),
        &credential::circuit(Some(CredentialKind::Auth)),
    )
    .unwrap()
    .0;
    assert_eq!(at_42, AUTH_ROOT);
    let params = |format: &Format| {
        let p = format.params;
        [
            p.log_blowup,
            p.n_queries as u32,
            p.pow_bits,
            p.fold_step,
            p.log_last_layer,
            p.interaction_pow_bits,
        ]
    };
    assert_ne!(
        vos_pvm_recair_air::credential::program_id(
            42,
            params(&retired_42()),
            &LOG_SIZES,
            &AUTH_ROOT
        ),
        Some(AUTH_PROGRAM)
    );
}

/// The retired format 42: 43 queries and PoW 20, its number refused by
/// the registry; the tests prove under it to show 44 refuses its proofs.
fn retired_42() -> Format {
    Format {
        number: 42,
        params: FormatParams {
            n_queries: 43,
            pow_bits: 20,
            ..CREDENTIAL_PROOF.params
        },
        ..CREDENTIAL_PROOF
    }
}

/// Auth and owner prove under format 44 and verify against their kinds'
/// programs, from the proof and from its bytes; the bytes within ingress's
/// cap, decoded only whole and canonical.
#[test]
fn each_kind_proves_and_verifies() {
    for statement in [auth(1), owner_statement(2)] {
        let proof = prove(&statement);
        let bytes = verifier::encode(&proof).unwrap();
        eprintln!("{:?}: {} bytes", statement.kind(), bytes.len());
        assert!(bytes.len() <= MAX_PROOF_BYTES);
        let kind = statement.kind().unwrap();
        verifier::verify_bytes(kind, &statement.words(), &bytes).unwrap();
        verify(&statement, proof).unwrap();
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(verifier::decode(&longer).is_err());
        assert!(verifier::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(matches!(
            verifier::decode(&vec![0; MAX_PROOF_BYTES + 1]),
            Err(vos_pvm_final_verifier::Error::Length)
        ));
    }
}

/// Members at two slots of one tree, one statement each: the same shape,
/// both verified.
#[test]
fn the_slot_does_not_move_the_shape() {
    let mut rng = Rng::new(9);
    let enrolled = support::enrolled(&mut rng, &[3, 0xdead_beef], 3);
    let [a, b] = [3, 0xdead_beef].map(|slot| {
        let statement = support::auth_at(&mut rng, &enrolled, slot);
        let proof = prove(&statement);
        let len = verifier::encode(&proof).unwrap().len();
        // The columns a tree commits: the shape. How many values each
        // carries follows the distinct query positions, the coins'.
        let widths: Vec<usize> = proof
            .stark_proof
            .queried_values
            .iter()
            .map(|tree| tree.len())
            .collect();
        verify(&statement, proof).unwrap();
        (len, widths)
    });
    assert_eq!(a.1, b.1);
    eprintln!("bytes at two slots: {} and {}", a.0, b.0);
}

/// Membership and payment together proves and verifies over its own
/// circuit, measured and not admitted; and auth under the retired 42's
/// parameters is refused under 44.
#[test]
fn the_joint_circuit_proves_and_a_retired_42_proof_is_refused() {
    let statement = joint(3);
    let finalized = credential::witness(&statement).unwrap();
    let root = credential::preprocessed_root::<Blake2sM31MerkleChannel>(
        &CREDENTIAL_PROOF,
        &finalized.circuit,
    )
    .unwrap();
    let (proof, stats) = credential::prove_on::<Blake2sM31MerkleChannel>(
        &CREDENTIAL_PROOF,
        &finalized.circuit,
        &finalized.witness,
        MaskRng::default(),
    )
    .unwrap();
    assert_eq!(stats.attempts, 1);
    credential::verify_on::<Blake2sM31MerkleChannel>(
        &CREDENTIAL_PROOF,
        root,
        &statement.words(),
        &proof,
    )
    .unwrap();

    let statement = auth(4);
    let finalized = credential::witness(&statement).unwrap();
    let (proof, _) = credential::prove_on::<Blake2sM31MerkleChannel>(
        &retired_42(),
        &finalized.circuit,
        &finalized.witness,
        MaskRng::default(),
    )
    .unwrap();
    let root = stwo::core::vcs::blake2_hash::Blake2sHash(AUTH_ROOT);
    credential::verify_on::<Blake2sM31MerkleChannel>(
        &retired_42(),
        root,
        &statement.words(),
        &proof,
    )
    .unwrap();
    assert!(
        credential::verify_on::<Blake2sM31MerkleChannel>(
            &CREDENTIAL_PROOF,
            root,
            &statement.words(),
            &proof
        )
        .is_err(),
        "a format-42 proof is not a format-44 proof"
    );
}

/// The prover and the verifier are generic over the channel: auth on the
/// plain Blake2s trees, under format 44's parameters, and a tampered
/// sample refused.
#[test]
fn the_prover_is_generic_over_the_channel() {
    let statement = auth(5);
    let finalized = credential::witness(&statement).unwrap();
    let format = Format {
        number: 0x7e57,
        ..CREDENTIAL_PROOF
    };
    let root =
        credential::preprocessed_root::<Blake2sMerkleChannel>(&format, &finalized.circuit).unwrap();
    let (proof, _) = credential::prove_on::<Blake2sMerkleChannel>(
        &format,
        &finalized.circuit,
        &finalized.witness,
        MaskRng::default(),
    )
    .unwrap();
    credential::verify_on::<Blake2sMerkleChannel>(&format, root, &statement.words(), &proof)
        .unwrap();
    let mut tampered = proof.clone();
    tampered.stark_proof.0.sampled_values[1][0][0] += SecureField::from(BaseField::from(1));
    assert!(
        credential::verify_on::<Blake2sMerkleChannel>(&format, root, &statement.words(), &tampered)
            .is_err()
    );
}

/// The credential set's masked shape, as `format::CREDENTIAL_REFERENCE`
/// counts it, from the built set: its trees' levels, its sample points'
/// DEEP values, its constraints, fractions and relations.
fn credential_shape() -> SecurityShape {
    let relation = GateRelation::dummy();
    let blind = BlindRelation::dummy();
    let set = CredentialComponents::build(&relation, &blind, &LOG_SIZES, &[SecureField::zero(); 2]);
    let trees = committed_log_sizes(&set, &PINS).unwrap();
    let points = sample_points(&set, CirclePoint::<SecureField>::get_point(1), &PINS).unwrap();
    let columns = points.iter().flatten();
    let composition = composition_log_degree_bound(&set).unwrap();
    let components = set.components();
    let masked_level = components
        .iter()
        .flat_map(|&inner| {
            MaskedComponent { inner }
                .trace_log_degree_bounds()
                .0
                .into_iter()
                .flatten()
        })
        .max()
        .unwrap();
    let fractions: u64 = [set.p2.logup_counts(), set.qm31.logup_counts()]
        .iter()
        .flat_map(|counts| counts.values())
        .map(|&n| n as u64)
        .sum();
    let widths = [
        <GateRelation as Relation<BaseField, SecureField>>::get_size(&relation),
        <BlindRelation as Relation<BaseField, SecureField>>::get_size(&blind),
    ];
    assert_eq!(widths, [GATE_WIDTH, 1]);
    SecurityShape {
        log_degree_bound: trees.iter().flatten().copied().max().unwrap(),
        log_trace_length: masked_level,
        log_composition_degree_bound: composition,
        sampled_values: columns
            .clone()
            .map(|column| deep_values_of_column(column.len()) as u64)
            .sum(),
        max_samples_per_column: columns
            .map(|column| deep_values_of_column(column.len()))
            .max()
            .unwrap() as u64,
        constraints: components.iter().map(|c| c.n_constraints() as u64).sum(),
        logup_fractions: fractions,
        relation_width: widths.into_iter().max().unwrap() as u64,
        composition_point_doublings: composition - air_log_size(&set).unwrap(),
    }
}

/// The registry's reference for format 44 is the built set's shape, field
/// for field, and 47 is the least query count clearing 62 bits on it.
#[test]
fn the_credential_reference_shape_is_the_built_sets() {
    let built = credential_shape();
    assert_eq!(built, CREDENTIAL_REFERENCE);
    for format in [CREDENTIAL_PROOF, retired_42()] {
        let count = proven_count(&format.params, &built).unwrap();
        eprintln!("format {}: {count:.3} proven bits", format.number);
        assert!(count >= 62.0);
        let fewer = FormatParams {
            n_queries: format.params.n_queries - 1,
            ..format.params
        };
        assert!(proven_count(&fewer, &built).unwrap() < 62.0);
    }
}
