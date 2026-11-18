//! Batch proofs: verified, refused when tampered, and updated from.

use proptest::prelude::*;
use vos_tree::{BatchProof, Decode, Encode, Entry, Error, MAX_KEY};

use crate::common::{
    H, Model, Write, apply, claims, commitments, leaf, pool, scratch, store_of, tampered,
};

/// A pool of keys, a model's contents as indices into it, and the indices of
/// keys to prove, present or absent.
type Case = (Vec<Vec<u8>>, Vec<(usize, u8)>, Vec<usize>);

fn case() -> impl Strategy<Value = Case> {
    (
        pool(),
        prop::collection::vec((any::<usize>(), any::<u8>()), 0..20),
        prop::collection::vec(any::<usize>(), 0..8),
    )
}

fn model_of(pool: &[Vec<u8>], contents: &[(usize, u8)]) -> Model {
    let mut model = Model::new();
    for &(at, value) in contents {
        let key = &pool[at % pool.len()];
        model.insert(key.clone(), leaf(key, 0, &[value]));
    }
    model
}

fn asked(pool: &[Vec<u8>], picks: &[usize]) -> Vec<Vec<u8>> {
    let mut keys: Vec<_> = picks
        .iter()
        .map(|&at| pool[at % pool.len()].clone())
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// A proof of any keys verifies their claims, survives its encoding, and
    /// is refused once tampered with or against a wrong claim.
    #[test]
    fn batch_proofs_verify_and_tampered_ones_fail((pool, contents, picks) in case()) {
        let model = model_of(&pool, &contents);
        let store = store_of(&model);
        let root = scratch(&model);
        let keys = asked(&pool, &picks);
        let claims = claims(&model, &keys);
        let proof = BatchProof::generate(&store, &keys).unwrap();
        prop_assert!(proof.verify(&H, &root, &claims).is_ok());
        let bytes = proof.encode();
        prop_assert_eq!(BatchProof::decode(&bytes).unwrap(), (proof.clone(), bytes.len()));

        for (name, entries) in tampered(&proof.entries) {
            let tampered = BatchProof { entries };
            prop_assert!(tampered.verify(&H, &root, &claims).is_err(), "{} verified", name);
        }
        for at in 0..claims.len() {
            let mut wrong = claims.clone();
            wrong[at].1 = match wrong[at].1 {
                Some(_) => None,
                None => Some([7; 32]),
            };
            prop_assert_eq!(proof.verify(&H, &root, &wrong).err(), Some(Error::Claim));
            if let Some(hash) = &mut wrong[at].1 {
                hash[0] ^= 1;
                prop_assert_eq!(proof.verify(&H, &root, &wrong).err(), Some(Error::Claim));
            }
        }
        let mut other = root;
        other[0] ^= 1;
        prop_assert_eq!(proof.verify(&H, &other, &claims).err(), Some(Error::Root));
    }

    /// Writes to the proven keys from the proof alone give the root the
    /// store's update gives.
    #[test]
    fn updates_from_a_batch_proof_agree_with_the_store(
        (pool, contents, picks) in case(),
        values in prop::collection::vec(prop::option::of(any::<u8>()), 8),
    ) {
        let mut model = model_of(&pool, &contents);
        let mut store = store_of(&model);
        let keys = asked(&pool, &picks);
        let proof = BatchProof::generate(&store, &keys).unwrap();
        let mut witness = proof.verify(&H, &scratch(&model), &claims(&model, &keys)).unwrap();
        let writes: Vec<Write> = keys
            .iter()
            .zip(&values)
            .map(|(key, value)| (key.clone(), value.map(|v| leaf(key, 1, &[v]))))
            .collect();
        let root = vos_tree::update(&H, &mut store, &writes).unwrap();
        apply(&mut model, &writes);
        prop_assert_eq!(root, scratch(&model));
        prop_assert_eq!(proof.update(&H, &commitments(&writes)), Ok(root));
        prop_assert_eq!(witness.update(&H, &commitments(&writes)), Ok(root));
        // The witness goes on from where it is, for the keys still present:
        // a delete may close what a later put of its key would need.
        let again: Vec<Write> = keys
            .iter()
            .filter(|key| model.contains_key(*key))
            .map(|key| (key.clone(), Some(leaf(key, 2, b"again"))))
            .collect();
        let root = vos_tree::update(&H, &mut store, &again).unwrap();
        prop_assert_eq!(witness.update(&H, &commitments(&again)), Ok(root));
    }
}

#[test]
fn a_proof_covers_only_its_keys() {
    let mut model = Model::new();
    for raw in [b"alpha".as_slice(), b"beta", b"gamma", b"delta", b"epsilon"] {
        let key = crate::common::row_key(false, raw);
        model.insert(key.clone(), leaf(&key, 0, raw));
    }
    let store = store_of(&model);
    let root = scratch(&model);
    let alpha = crate::common::row_key(false, b"alpha");
    let gamma = crate::common::row_key(false, b"gamma");
    let proof = BatchProof::generate(&store, std::slice::from_ref(&alpha)).unwrap();
    assert_eq!(
        proof
            .verify(&H, &root, &claims(&model, std::slice::from_ref(&gamma)))
            .err(),
        Some(Error::Uncovered)
    );
    let put = [(gamma.clone(), Some(leaf(&gamma, 1, b"new")))];
    assert_eq!(proof.update(&H, &commitments(&put)), Err(Error::Uncovered));
    let unsorted = [(gamma.clone(), None), (alpha.clone(), None)];
    assert_eq!(proof.update(&H, &commitments(&unsorted)), Err(Error::Order));
    assert_eq!(
        proof.update(&H, &[(Vec::new(), Some([0; 32]))]),
        Err(Error::Key)
    );
    for key in [Vec::new(), vec![1; MAX_KEY + 1]] {
        let claim = [(key, None)];
        assert_eq!(proof.verify(&H, &root, &claim).err(), Some(Error::Key));
    }
}

/// An absent key shorter than the level of a branch its path passes takes
/// 0-bits past its end there, to a leaf it does not prefix: it parted from
/// that branch's keys inside its own bits. (A whole-byte key whose bits all
/// agree with a subtree's common prefix prefixes every key below, the case
/// of the next test.) It is proven absent, and goes in from the proof.
#[test]
fn an_absent_key_ending_above_a_branch_on_its_path() {
    let mut model = Model::new();
    for key in [vec![0x10], vec![0x62, 0, 0, 0x10], vec![0x62, 0, 0, 0x20]] {
        model.insert(key.clone(), leaf(&key, 0, &key));
    }
    let mut store = store_of(&model);
    let key = vec![0x62, 0x01];
    let keys = [key.clone()];
    let proof = BatchProof::generate(&store, &keys).unwrap();
    assert!(
        proof.entries.iter().any(
            |entry| matches!(entry, Entry::Branch(level) if usize::from(*level) >= key.len() * 8)
        ),
        "the path passes a branch past the key's end"
    );
    let mut witness = proof
        .verify(&H, &scratch(&model), &[(key.clone(), None)])
        .unwrap();
    assert_eq!(
        proof
            .verify(&H, &scratch(&model), &[(key.clone(), Some([0; 32]))])
            .err(),
        Some(Error::Claim)
    );
    let put = vec![(key.clone(), Some(leaf(&key, 1, b"new")))];
    let root = vos_tree::update(&H, &mut store, &put).unwrap();
    apply(&mut model, &put);
    assert_eq!(root, scratch(&model));
    assert_eq!(witness.update(&H, &commitments(&put)), Ok(root));
}

/// A claim about a key that prefixes a key of the tree, or that one
/// prefixes, is refused as `Key` rather than proven absent: the tree's keys
/// are prefix-free, so the key could never be put in it, and every key a
/// proof shows absent can be put from it.
#[test]
fn a_key_prefixing_a_tree_key_is_refused() {
    let mut model = Model::new();
    for key in [b"a/abc".to_vec(), b"a/abd".to_vec()] {
        model.insert(key.clone(), leaf(&key, 0, b"v"));
    }
    let mut store = store_of(&model);
    let root = scratch(&model);
    for key in [b"a/ab".to_vec(), b"a/abcd".to_vec()] {
        let proof = BatchProof::generate(&store, std::slice::from_ref(&key)).unwrap();
        assert_eq!(
            proof.verify(&H, &root, &[(key.clone(), None)]).err(),
            Some(Error::Key)
        );
        let put = vec![(key.clone(), Some(leaf(&key, 1, b"v")))];
        assert_eq!(proof.update(&H, &commitments(&put)), Err(Error::Key));
        let before = store.clone();
        assert_eq!(vos_tree::update(&H, &mut store, &put), Err(Error::Key));
        assert_eq!(store, before, "a refused batch writes nothing");
    }
}
