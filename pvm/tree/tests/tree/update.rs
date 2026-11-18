//! Incremental updates over a store, and from proofs.

use proptest::prelude::*;
use vos_tree::{BatchProof, Error, MemStore, RangeProof, empty_root, reachable, stored_root};

use crate::common::{
    H, Model, Ordered, Write, apply, batches, check, claims, commitments, leaf, pool, row_key,
    scratch, store_of, writes,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Random batches of puts and deletes: after each, the root equals the
    /// root of the same leaves built from scratch, the store holds the tree's
    /// rows and no others, every read came before the first write, and the
    /// batch from a proof of its keys, or split over several calls in any
    /// order, gives the same root and rows.
    #[test]
    fn incremental_updates_agree_with_a_build_from_scratch(pool in pool(), batches in batches()) {
        let mut store = Ordered::default();
        let mut model = Model::new();
        for (version, batch) in batches.iter().enumerate() {
            let writes = writes(&pool, batch, version as u8);
            let keys: Vec<Vec<u8>> = writes.iter().map(|(key, _)| key.clone()).collect();
            let before = store.inner.clone();
            let proof = BatchProof::generate(&before, &keys).unwrap();
            let witness = proof.verify(&H, &scratch(&model), &claims(&model, &keys));

            let root = store.update(&writes);
            apply(&mut model, &writes);
            prop_assert_eq!(root, scratch(&model));
            prop_assert_eq!(stored_root(&H, &store.inner).unwrap(), root);
            check(&store.inner, &model);

            prop_assert_eq!(proof.update(&H, &commitments(&writes)), Ok(root));
            prop_assert_eq!(witness.unwrap().update(&H, &commitments(&writes)), Ok(root));

            for size in [1, 3] {
                let mut forward = before.clone();
                let mut backward = before.clone();
                for chunk in writes.chunks(size) {
                    vos_tree::update(&H, &mut forward, chunk).unwrap();
                }
                for chunk in writes.chunks(size).rev() {
                    vos_tree::update(&H, &mut backward, chunk).unwrap();
                }
                prop_assert_eq!(&forward, &store.inner);
                prop_assert_eq!(&backward, &store.inner);
            }
        }
    }
}

#[test]
fn the_empty_tree() {
    let mut store = MemStore::default();
    assert_eq!(stored_root(&H, &store).unwrap(), empty_root(&H));
    assert_eq!(scratch(&Model::new()), empty_root(&H));
    let key = b"a/k\0\0".to_vec();
    let put = vec![(key.clone(), Some(leaf(&key, 1, b"v")))];
    let root = vos_tree::update(&H, &mut store, &put).unwrap();
    let mut model = Model::new();
    apply(&mut model, &put);
    assert_eq!(root, scratch(&model));
    check(&store, &model);

    let delete = vec![(key.clone(), None)];
    assert_eq!(
        vos_tree::update(&H, &mut store, &delete).unwrap(),
        empty_root(&H)
    );
    assert_eq!(store, MemStore::default(), "no row left");
    let absent = vec![(b"a/x\0\0".to_vec(), None)];
    assert_eq!(
        vos_tree::update(&H, &mut store, &absent).unwrap(),
        empty_root(&H)
    );

    let proof = BatchProof::generate(&store, std::slice::from_ref(&key)).unwrap();
    assert!(
        proof
            .verify(&H, &empty_root(&H), &[(key.clone(), None)])
            .is_ok()
    );
    assert_eq!(proof.update(&H, &commitments(&put)), Ok(root));
    let range = RangeProof::generate(&store, b"", None).unwrap();
    let rows: [(Vec<u8>, _); 0] = [];
    assert!(range.verify(&H, &empty_root(&H), b"", None, &rows).is_ok());
    assert_eq!(range.update(&H, &commitments(&put)), Ok(root));
}

/// A batch of 10,000 keys as one call, then changed and half deleted.
#[test]
fn a_batch_of_ten_thousand() {
    let mut model = Model::new();
    let keys: Vec<Vec<u8>> = (0u32..10_000)
        .map(|i| row_key(!i.is_multiple_of(3), &i.to_be_bytes()))
        .collect();
    let put: Vec<_> = {
        let mut put: Vec<_> = keys
            .iter()
            .map(|k| (k.clone(), Some(leaf(k, 1, k))))
            .collect();
        put.sort_by(|a, b| a.0.cmp(&b.0));
        put
    };
    let mut store = MemStore::default();
    let root = vos_tree::update(&H, &mut store, &put).unwrap();
    apply(&mut model, &put);
    assert_eq!(root, scratch(&model));
    check(&store, &model);

    let mut churn: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            (
                k.clone(),
                i.is_multiple_of(2).then(|| leaf(k, 2, b"changed")),
            )
        })
        .collect();
    churn.sort_by(|a, b| a.0.cmp(&b.0));
    let root = vos_tree::update(&H, &mut store, &churn).unwrap();
    apply(&mut model, &churn);
    assert_eq!(root, scratch(&model));
    check(&store, &model);
    assert_eq!(
        store_of(&model),
        store,
        "the same rows as a store built at once"
    );
}

/// The store's update refuses a bad batch, and every walk refuses a store
/// that lacks a row a parent names, with an error and nothing written.
#[test]
fn the_store_path_refuses_rather_than_panics() {
    let mut model = Model::new();
    for raw in [b"b".as_slice(), b"d", b"f", b"h"] {
        let key = row_key(false, raw);
        model.insert(key.clone(), leaf(&key, 0, raw));
    }
    let mut store = store_of(&model);
    let before = store.clone();
    let key = |raw: &[u8]| row_key(false, raw);
    let unsorted: Vec<Write> = vec![(key(b"d"), None), (key(b"b"), None)];
    assert_eq!(
        vos_tree::update(&H, &mut store, &unsorted),
        Err(Error::Order)
    );
    let empty: Vec<Write> = vec![(Vec::new(), None)];
    assert_eq!(vos_tree::update(&H, &mut store, &empty), Err(Error::Key));
    // `a/b` prefixes the row key `a/b\0\0`.
    let prefix = vec![(b"a/b".to_vec(), Some(leaf(b"a/b", 1, b"v")))];
    assert_eq!(vos_tree::update(&H, &mut store, &prefix), Err(Error::Key));
    assert_eq!(store, before, "nothing written");

    let all: Vec<Vec<u8>> = model.keys().cloned().collect();
    let put: Vec<Write> = all
        .iter()
        .map(|k| (k.clone(), Some(leaf(k, 2, b"x"))))
        .collect();
    let mut broken = store.clone();
    let place = broken.nodes.keys().next().unwrap().clone();
    broken.nodes.remove(&place);
    let lacking = broken.clone();
    assert_eq!(vos_tree::update(&H, &mut broken, &put), Err(Error::Missing));
    assert_eq!(broken, lacking, "nothing written");
    assert_eq!(
        BatchProof::generate(&broken, &all).err(),
        Some(Error::Missing)
    );
    assert_eq!(
        RangeProof::generate(&broken, b"", None).err(),
        Some(Error::Missing)
    );
    assert_eq!(reachable(&broken).err(), Some(Error::Missing));

    let mut broken = store.clone();
    broken.leaves.remove(&all[0]);
    assert_eq!(
        BatchProof::generate(&broken, &all).err(),
        Some(Error::Missing)
    );
    assert_eq!(
        RangeProof::generate(&broken, b"", None).err(),
        Some(Error::Missing)
    );
}
