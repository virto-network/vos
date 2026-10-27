//! The credential AIR's gates (pin I, 7.10).
//!
//! - **Soundness:** a statement its witness does not satisfy, proved all
//!   the same (the honest prover's constraints hold, the wiring does not
//!   balance), is refused by the final verifier: a wrong path, a nullifier
//!   of another secret, an owner digest of another secret; an honest proof
//!   under a changed binding, kind or circuit is refused.
//! - **Forgery:** a forger who proves the path with a value that is not a
//!   bit (its node row a blend of the two orders), or the leaf without its
//!   tag (`C(0, m)`), each with the root it computes stated: its own
//!   circuit is not the pinned one, and its witness under the pinned
//!   circuit breaks one constraint, which the prover refuses and, forced,
//!   the verifier does.

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo::core::verifier::VerificationError;
use stwo::prover::ProvingError;
use vos_pvm_final_verifier::Error;
use vos_pvm_final_verifier::credential::{
    self as verifier, AUTH_ROOT, CREDENTIAL, CredentialProof, OWNER_ROOT,
};
use vos_pvm_proof::format::CREDENTIAL_PROOF;
use vos_pvm_recair::context::Finalized;
use vos_pvm_recair::credential::{self, Forge, Statement, Tags, Words};
use vos_pvm_recair::masked::{Checks, MaskRng, MaskedProof};
use vos_pvm_recair::trace::MainTrace;
use vos_pvm_recair::{Entry, P2Mode, ProveError, WiringError};
use vos_pvm_recair_air::credential::CredentialKind;
use vos_wire::credentials::Tag;

use crate::common::Rng;
use crate::prove::{prove, verify};
use crate::support::{self, auth, nullifier, owner, owner_statement};

type Hasher = stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleHasher;

/// A masked proof as the final verifier takes it.
fn credential_proof(proof: MaskedProof<Hasher>) -> CredentialProof {
    CredentialProof {
        format_version: CREDENTIAL_PROOF.number,
        interaction_pow: proof.interaction_pow,
        claimed_sums: proof.claimed_sums.try_into().unwrap(),
        stark_proof: proof.stark_proof,
    }
}

/// `finalized`'s witness proved over `circuit` (its own or the pinned one)
/// under format 44, held to `checks`, the trace through `tamper`.
fn forced(
    circuit: &vos_pvm_recair::Circuit,
    finalized: &Finalized<SecureField>,
    tamper: impl FnOnce(&mut MainTrace),
    checks: Checks,
) -> Result<CredentialProof, ProveError> {
    credential::prove_forced::<Blake2sM31MerkleChannel>(
        &CREDENTIAL_PROOF,
        circuit,
        &finalized.witness,
        MaskRng::Seeded(3),
        tamper,
        checks,
    )
    .map(|(proof, _)| credential_proof(proof))
}

/// Without the prover's check of the constraints.
const UNCHECKED: Checks = Checks {
    constraints: false,
    ..Checks::ALL
};

/// A statement whose witness does not satisfy it, proved by the honest
/// prover over the pinned circuit (every constraint holds), then refused
/// by the final verifier because the wiring does not balance.
fn assert_unbalanced_refused(statement: &Statement, piece: &str) {
    assert!(
        matches!(credential::witness(statement), Err(ProveError::Witness(p)) if p == piece),
        "{piece}: the honest prover refuses it first"
    );
    let (finalized, mismatches) = credential::forge(statement, &Forge::NONE);
    assert!(
        mismatches.iter().all(|m| m.piece == piece),
        "{mismatches:?}"
    );
    let kind = statement.kind().unwrap();
    assert_eq!(finalized.circuit, credential::circuit(Some(kind)));
    let proof = forced(&finalized.circuit, &finalized, |_| {}, Checks::ALL)
        .expect("every constraint holds");
    assert!(
        matches!(verify(statement, proof), Err(Error::Logup)),
        "{piece}: refused by the logup total"
    );
}

/// A wrong path (a sibling changed), a nullifier of another secret, an
/// owner digest of another secret: each refused.
#[test]
fn a_statement_its_witness_does_not_satisfy_is_refused() {
    let Statement::Auth(public, witness) = auth(31) else {
        unreachable!()
    };
    let mut wrong = witness;
    wrong.siblings[0][0] ^= 1;
    assert_unbalanced_refused(&Statement::Auth(public, wrong), "path");
    let mut wrong = witness;
    wrong.slot ^= 1 << 20;
    assert_unbalanced_refused(&Statement::Auth(public, wrong), "path");

    let mut rng = Rng::new(31);
    let other = support::digest(&mut rng);
    let stolen = vos_pvm_recair::credential::AuthPublic {
        nullifier: nullifier(&other, &public.scope),
        ..public
    };
    assert_unbalanced_refused(&Statement::Auth(stolen, witness), "nullifier");

    let Statement::Owner(public, s) = owner_statement(32) else {
        unreachable!()
    };
    let stolen = vos_pvm_recair::credential::OwnerPublic {
        owner: owner(&other),
        ..public
    };
    assert_unbalanced_refused(&Statement::Owner(stolen, s), "owner");
}

/// An honest proof under another binding, another kind word, another
/// kind's circuit, or another format's pins: refused; and under
/// `verify_with`, which counts no words, one word fewer or one more: an
/// output yielded and not used, or a use not yielded.
#[test]
fn an_honest_proof_of_another_statement_is_refused() {
    let statement = auth(33);
    let proof = prove(&statement);
    verify(&statement, proof.clone()).unwrap();
    let words = statement.words();
    for at in [words.len() - 8, words.len() - 1] {
        let mut changed = words.clone();
        changed[at] = (changed[at] + 1) % vos_wire::credentials::P;
        assert!(
            matches!(
                verifier::verify(CredentialKind::Auth, &changed, proof.clone()),
                Err(Error::Logup | Error::InteractionPow)
            ),
            "the binding's word {at} changed"
        );
    }
    for at in [1, 9, 17] {
        let mut changed = words.clone();
        changed[at] ^= 1;
        assert!(
            verifier::verify(CredentialKind::Auth, &changed, proof.clone()).is_err(),
            "word {at} changed"
        );
    }
    assert!(matches!(
        verifier::verify(CredentialKind::Owner, &words, proof.clone()),
        Err(Error::PublicWords)
    ));
    assert!(matches!(
        verifier::verify_with(&CREDENTIAL, &OWNER_ROOT, &words, proof.clone()),
        Err(Error::Circuit)
    ));
    let mut short = words.clone();
    short.pop();
    let long = [words.as_slice(), &[0]].concat();
    for wrong in [short, long] {
        assert!(
            matches!(
                verifier::verify_with(&CREDENTIAL, &AUTH_ROOT, &wrong, proof.clone()),
                Err(Error::Logup | Error::InteractionPow)
            ),
            "{} words under verify_with",
            wrong.len()
        );
    }
    let mut relabelled = proof.clone();
    relabelled.format_version = 42;
    assert!(matches!(verify(&statement, relabelled), Err(Error::Format)));

    let owner = owner_statement(34);
    let owner_proof = prove(&owner);
    assert!(matches!(
        verifier::verify_with(&CREDENTIAL, &AUTH_ROOT, &owner.words(), owner_proof),
        Err(Error::Circuit)
    ));
}

/// The two wires of `words`.
fn wires(words: &Words) -> [SecureField; 2] {
    [0, 1].map(|w| {
        SecureField::from_m31_array(core::array::from_fn(|j| BaseField::from(words[4 * w + j])))
    })
}

/// The root a forger's path computes for `statement` built as `forge`
/// builds it: what its last node row outputs, which the stated root's
/// mismatches show.
fn forged_root(statement: &Statement, forge: &Forge) -> Words {
    let Statement::Auth(public, _) = statement else {
        unreachable!()
    };
    let claimed = wires(&public.map_root);
    let (_, mismatches) = credential::forge(statement, forge);
    let computed: Vec<SecureField> = claimed
        .iter()
        .map(|wire| {
            mismatches
                .iter()
                .find(|m| m.piece == "path" && m.expected == *wire)
                .expect("the stated root is not the forger's")
                .computed
        })
        .collect();
    let limbs: Vec<u32> = computed
        .iter()
        .flat_map(|wire| wire.to_m31_array().map(|limb| limb.0))
        .collect();
    limbs.try_into().unwrap()
}

/// `statement` (auth) stating the root its forger computes.
fn stating_forged_root(statement: &Statement, forge: &Forge) -> Statement {
    let root = forged_root(statement, forge);
    let Statement::Auth(public, witness) = *statement else {
        unreachable!()
    };
    Statement::Auth(
        vos_pvm_recair::credential::AuthPublic {
            map_root: root,
            ..public
        },
        witness,
    )
}

/// A forger who skips the leaf's tag: the leaf `C(0, m)`, its path's root
/// stated. Its own circuit proves and verifies under its own root, and is
/// refused as another circuit than auth's; its witness under the pinned
/// circuit breaks the leaf row's input constraint: the prover refuses it,
/// and, forced, the verifier.
#[test]
fn a_prover_that_skips_the_leafs_tag_is_refused() {
    let forge = Forge {
        tags: Tags {
            leaf: [0; 8],
            ..Tags::PINNED
        },
        bit: None,
    };
    let statement = stating_forged_root(&auth(35), &forge);
    let (finalized, mismatches) = credential::forge(&statement, &forge);
    assert!(mismatches.is_empty(), "{mismatches:?}");
    let pinned = credential::circuit(Some(CredentialKind::Auth));
    assert_ne!(finalized.circuit, pinned);

    let own = forced(&finalized.circuit, &finalized, |_| {}, Checks::ALL).unwrap();
    let own_root = credential::preprocessed_root::<Blake2sM31MerkleChannel>(
        &CREDENTIAL_PROOF,
        &finalized.circuit,
    )
    .unwrap();
    assert_ne!(own_root, Blake2sHash(AUTH_ROOT));
    verifier::verify_with(&CREDENTIAL, &own_root.0, &statement.words(), own.clone()).unwrap();
    assert!(matches!(verify(&statement, own), Err(Error::Circuit)));

    assert!(matches!(
        forced(&pinned, &finalized, |_| {}, Checks::ALL),
        Err(ProveError::Stwo(ProvingError::ConstraintsNotSatisfied))
    ));
    let proof = forced(&pinned, &finalized, |_| {}, UNCHECKED).unwrap();
    assert!(matches!(
        verify(&statement, proof),
        Err(Error::Stark(VerificationError::OodsNotMatching))
    ));
    // The pinned tag is what the forger dropped.
    assert_eq!(Tags::PINNED.leaf, Tag::Leaf.block());
}

/// A forger who skips the path's bits: level 0's selector 2, not a bit, so
/// the node row's input is a blend of both orders (`2m − c`, `2c − m`), its
/// root stated. The bit's row, its output set to the value so the wiring
/// balances, breaks `b·b = b`: the prover refuses it, and, forced, the
/// verifier; left as computed, the wiring does not balance.
#[test]
fn a_prover_that_skips_the_paths_bits_is_refused() {
    let forge = Forge {
        tags: Tags::PINNED,
        bit: Some((0, 2)),
    };
    let statement = stating_forged_root(&auth(36), &forge);
    let (finalized, mismatches) = credential::forge(&statement, &forge);
    let two = SecureField::from(BaseField::from(2));
    let four = SecureField::from(BaseField::from(4));
    assert_eq!(
        mismatches
            .iter()
            .map(|m| (m.piece, m.expected, m.computed))
            .collect::<Vec<_>>(),
        [("path", two, four)],
        "the bit's row alone"
    );
    let pinned = credential::circuit(Some(CredentialKind::Auth));
    assert_eq!(
        finalized.circuit, pinned,
        "the forger's circuit is the pinned one"
    );
    let row = finalized
        .witness
        .qm31
        .iter()
        .position(|values| *values == [two, two, SecureField::default(), four])
        .expect("the bit's row");
    let balance = |main: &mut MainTrace| {
        for (j, limb) in two.to_m31_array().into_iter().enumerate() {
            main.columns[1][12 + j][row] = limb;
        }
    };
    assert!(matches!(
        forced(&pinned, &finalized, balance, Checks::ALL),
        Err(ProveError::Stwo(ProvingError::ConstraintsNotSatisfied))
    ));
    let proof = forced(&pinned, &finalized, balance, UNCHECKED).unwrap();
    assert!(matches!(
        verify(&statement, proof),
        Err(Error::Stark(VerificationError::OodsNotMatching))
    ));
    let unbalanced = forced(&pinned, &finalized, |_| {}, Checks::ALL).unwrap();
    assert!(matches!(verify(&statement, unbalanced), Err(Error::Logup)));
}

/// A tagged row whose bit is not zero: the owner's row with `b = 1`, its
/// input the node rule's at that bit (`[c + m − prev, prev]`, `prev` the
/// last padding row's output) so its constraints hold, its output the
/// stated owner digest. The bit's use of the zero wire carries 1, which no
/// yield balances: refused by the logup total.
#[test]
fn a_tagged_rows_bit_is_zero() {
    use vos_pvm_poseidon2::{M31, N_STATE, permute};
    use vos_pvm_recair_air::p2::{self, main};

    let Statement::Owner(public, s) = owner_statement(37) else {
        unreachable!()
    };
    let mut prev = [M31::ZERO; N_STATE];
    permute(&mut prev);
    let tag = Tag::Owner.block();
    let input: [M31; N_STATE] = core::array::from_fn(|j| {
        if j < 8 {
            M31::new(tag[j]) + M31::new(s[j]) - prev[j]
        } else {
            prev[j - 8]
        }
    });
    let mut columns = vec![M31::ZERO; main::M];
    let output = p2::permutation_columns(input, &mut columns);
    let forged: Words = core::array::from_fn(|j| output[j].value());
    let statement = Statement::Owner(
        vos_pvm_recair::credential::OwnerPublic {
            owner: forged,
            ..public
        },
        s,
    );
    let (finalized, mismatches) = credential::forge(&statement, &Forge::NONE);
    assert!(
        mismatches.iter().all(|m| m.piece == "owner"),
        "{mismatches:?}"
    );
    let tamper = |trace: &mut MainTrace| {
        let p2 = &mut trace.columns[0];
        for (column, word) in columns.iter().enumerate() {
            p2[column][0] = BaseField::from(word.value());
        }
        p2[main::B][0] = BaseField::from(1);
    };
    let proof = forced(&finalized.circuit, &finalized, tamper, Checks::ALL)
        .expect("every constraint holds at b = 1");
    assert!(matches!(verify(&statement, proof), Err(Error::Logup)));
}

/// A tagged row whose message is no wire: the leaf's row reading a free
/// message instead of the member digest's wire, the member row's yield
/// balanced to the use it lost. Refused by the wiring check, which only a
/// node's free sibling passes.
#[test]
fn a_tagged_rows_free_message_is_refused() {
    let mut circuit = credential::circuit(Some(CredentialKind::Auth));
    circuit
        .check_wiring_without_h8()
        .expect("the pinned circuit's wiring");
    let tagged: Vec<usize> = (0..circuit.p2.len())
        .filter(|&row| circuit.p2[row].mode == Some(P2Mode::Tagged))
        .collect();
    let leaf = tagged[1];
    let removed = circuit.p2[leaf].m[0];
    assert!(
        removed.multiplicity > 0,
        "the leaf's row uses the member wire"
    );
    circuit.p2[leaf].m[0] = Entry::FREE;
    let member = circuit
        .p2
        .iter_mut()
        .find(|row| row.out_address == removed.address)
        .expect("the member row yields it");
    member.out_multiplicity[0] += removed.multiplicity;
    assert_eq!(
        circuit.check_wiring_without_h8(),
        Err(WiringError::FreeMessageAbsorbed { row: leaf })
    );
}
