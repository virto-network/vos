//! The circuits against `vos_wire::credentials`, the tree's and the actor's
//! reference: every `p2` row's input is the reference's words for its
//! compression, every output the reference's digest, and a witness the
//! reference's `Path::proves` refuses, the circuit refuses too.

use stwo::core::fields::qm31::SecureField;
use vos_pvm_recair::ProveError;
use vos_pvm_recair::credential::{self, Statement, Words};
use vos_pvm_recair_air::credential::CredentialKind;
use vos_wire::credentials::{DEPTH, Path, Siblings, Tag, compress, digest, leaf};

use crate::common::Rng;
use crate::support::{self, auth, joint, member, nullifier, owner, owner_statement};

/// Each `p2` row's sixteen input words, in row order.
fn inputs(statement: &Statement) -> Vec<[u32; 16]> {
    credential::witness(statement)
        .expect("the witness satisfies its circuit")
        .witness
        .p2
        .iter()
        .map(|row| {
            let limbs: Vec<u32> = row
                .input
                .iter()
                .flat_map(|wire| wire.to_m31_array().map(|limb| limb.0))
                .collect();
            limbs.try_into().expect("sixteen words")
        })
        .collect()
}

fn concat(left: &Words, right: &Words) -> [u32; 16] {
    core::array::from_fn(|i| if i < 8 { left[i] } else { right[i - 8] })
}

/// The auth circuit's rows are the reference's compressions in order: the
/// member, the leaf, the path's 32 nodes (each child on the side its slot's
/// bit picks), the nullifier's key and the nullifier; its outputs the
/// statement's words. Over members at the leftmost, the rightmost and
/// random slots.
#[test]
fn the_auth_circuit_is_the_references_hashes() {
    let mut rng = Rng::new(7);
    for slot in [0, u32::MAX, 0x8000_0001, rng.next_u64() as u32] {
        let enrolled = support::enrolled(&mut rng, &[slot], 4);
        let statement = support::auth_at(&mut rng, &enrolled, slot);
        let Statement::Auth(public, witness) = statement else {
            unreachable!()
        };
        let s = witness.secret;
        let m = member(&s);
        let rows = inputs(&statement);
        assert_eq!(rows[0], concat(&Tag::Member.block(), &s));
        assert_eq!(rows[1], concat(&Tag::Leaf.block(), &m));
        let mut node = leaf(&m);
        for (level, sibling) in witness.siblings.iter().enumerate() {
            let pair = if slot >> level & 1 == 0 {
                (node, *sibling)
            } else {
                (*sibling, node)
            };
            assert_eq!(rows[2 + level], concat(&pair.0, &pair.1), "level {level}");
            node = compress(&pair.0, &pair.1);
        }
        assert_eq!(node, public.map_root);
        let keyed = compress(&Tag::Nf.block(), &s);
        assert_eq!(rows[2 + DEPTH], concat(&Tag::Nf.block(), &s));
        assert_eq!(rows[3 + DEPTH], concat(&keyed, &public.scope));
        assert_eq!(public.nullifier, nullifier(&s, &public.scope));
        // Padding rows hold the permutation of zero.
        assert!(rows[4 + DEPTH..].iter().all(|row| *row == [0; 16]));

        let path = Path {
            root: digest(&public.map_root),
            slot,
            siblings: Siblings(witness.siblings.map(|sibling| digest(&sibling))),
        };
        assert!(path.proves(&digest(&m)), "the actor's path for slot {slot}");
        assert_eq!(outputs(&statement), statement.words());
    }
}

/// The circuit's outputs, as words.
fn outputs(statement: &Statement) -> Vec<u32> {
    credential::witness(statement)
        .unwrap()
        .witness
        .outputs
        .iter()
        .map(|value: &SecureField| {
            let [word, rest @ ..] = value.to_m31_array();
            assert!(rest.iter().all(|limb| limb.0 == 0));
            word.0
        })
        .collect()
}

/// The owner circuit's one row is `C(T(owner), s)`, its outputs the kind,
/// the owner digest and the binding; the membership-and-payment circuit's
/// rows are auth's and the owner's from the one secret, its outputs without
/// a kind.
#[test]
fn the_owner_and_joint_circuits_are_the_references_hashes() {
    let statement = owner_statement(3);
    let Statement::Owner(public, s) = statement else {
        unreachable!()
    };
    assert_eq!(public.owner, owner(&s));
    assert_eq!(inputs(&statement)[0], concat(&Tag::Owner.block(), &s));
    assert!(inputs(&statement)[1..].iter().all(|row| *row == [0; 16]));
    let words = outputs(&statement);
    assert_eq!(words, statement.words());
    assert_eq!(words.len(), CredentialKind::Owner.public_words());
    assert_eq!(words[0], CredentialKind::Owner as u32);

    let statement = joint(4);
    let Statement::Joint(public, owner_digest, witness) = statement else {
        unreachable!()
    };
    let rows = inputs(&statement);
    assert_eq!(
        rows[4 + DEPTH],
        concat(&Tag::Owner.block(), &witness.secret)
    );
    assert_eq!(owner_digest, owner(&witness.secret));
    let words = outputs(&statement);
    assert_eq!(words.len(), 40);
    assert_eq!(&words[..8], &public.map_root);
    assert_eq!(&words[24..32], &owner_digest);
    let permutations = rows.iter().filter(|row| **row != [0; 16]).count();
    assert_eq!(permutations, 37, "the joint circuit's permutations");
    let auth_rows = inputs(&auth(4))
        .iter()
        .filter(|row| **row != [0; 16])
        .count();
    assert_eq!(auth_rows, 36, "the auth circuit's permutations");
}

/// Whatever the witness, a kind's circuit is one wiring: the program
/// built from no witness.
#[test]
fn the_wiring_does_not_depend_on_the_witness() {
    let auth_circuit = credential::circuit(Some(CredentialKind::Auth));
    for seed in 0..3 {
        assert_eq!(
            credential::witness(&auth(seed)).unwrap().circuit,
            auth_circuit
        );
    }
    let mut rng = Rng::new(11);
    let enrolled = support::enrolled(&mut rng, &[0, u32::MAX], 2);
    for slot in [0, u32::MAX] {
        let statement = support::auth_at(&mut rng, &enrolled, slot);
        assert_eq!(
            credential::witness(&statement).unwrap().circuit,
            auth_circuit
        );
    }
    assert_eq!(
        credential::witness(&owner_statement(1)).unwrap().circuit,
        credential::circuit(Some(CredentialKind::Owner))
    );
    assert_eq!(
        credential::witness(&joint(1)).unwrap().circuit,
        credential::circuit(None)
    );
    assert_ne!(
        auth_circuit,
        credential::circuit(Some(CredentialKind::Owner))
    );
}

/// A witness the reference refuses, the circuit refuses before proving, by
/// the piece that checks it: a sibling changed (the path to another root),
/// another secret's nullifier, another secret's owner digest.
#[test]
fn a_witness_the_reference_refuses_is_refused() {
    let Statement::Auth(public, witness) = auth(5) else {
        unreachable!()
    };
    let mut wrong = witness;
    wrong.siblings[17][3] ^= 1;
    let path = Path {
        root: digest(&public.map_root),
        slot: wrong.slot,
        siblings: Siblings(wrong.siblings.map(|sibling| digest(&sibling))),
    };
    assert!(!path.proves(&digest(&member(&wrong.secret))));
    assert!(matches!(
        credential::witness(&Statement::Auth(public, wrong)),
        Err(ProveError::Witness("path"))
    ));

    let mut rng = Rng::new(5);
    let other = support::digest(&mut rng);
    let mut stolen = public;
    stolen.nullifier = nullifier(&other, &public.scope);
    assert!(matches!(
        credential::witness(&Statement::Auth(stolen, witness)),
        Err(ProveError::Witness("nullifier"))
    ));

    let Statement::Owner(mut public, s) = owner_statement(6) else {
        unreachable!()
    };
    public.owner = owner(&other);
    assert!(matches!(
        credential::witness(&Statement::Owner(public, s)),
        Err(ProveError::Witness("owner"))
    ));
}
