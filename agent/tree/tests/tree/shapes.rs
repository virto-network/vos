//! Tree shapes: depth under each transform, the deepest paths, and the
//! format's known answers.

use vos_tree::{
    BatchProof, Entry, Hash, MemStore, branch_hash, empty_root, keys, leaf_hash, root, salt,
    value_hash,
};

use crate::common::{
    H, Model, apply, check, claims, commitments, leaf, row_key, scratch, store_of,
};

/// The number of branches on `key`'s path, its proof verified.
fn depth(store: &MemStore, model: &Model, key: &[u8]) -> usize {
    let keys = [key.to_vec()];
    let proof = BatchProof::generate(store, &keys).unwrap();
    proof
        .verify(&H, &scratch(model), &claims(model, &keys))
        .unwrap();
    proof
        .entries
        .iter()
        .filter(|entry| matches!(entry, Entry::Branch(_)))
        .count()
}

/// Ordered keys `k, k‖0, k‖00, …` grow the tree a level per key.
#[test]
fn ordered_chains_grow_a_level_per_key() {
    let mut store = MemStore::default();
    let mut model = Model::new();
    for i in 0..200 {
        let raw = [b"k".as_slice(), &vec![0; i]].concat();
        let key = row_key(false, &raw);
        let put = [(key.clone(), Some(leaf(&key, 1, &raw)))];
        let root = vos_tree::update(&H, &mut store, &put).unwrap();
        apply(&mut model, &put);
        assert_eq!(root, scratch(&model));
        assert_eq!(depth(&store, &model, &key), i);
    }
    check(&store, &model);
    for (i, key) in model.keys().enumerate() {
        assert_eq!(depth(&store, &model, key), (i + 1).min(model.len() - 1));
    }
}

/// Keys chosen to make ordered paths deep stay shallow hashed.
#[test]
fn hashed_keys_of_adversarial_shapes_stay_shallow() {
    let mut raws: Vec<Vec<u8>> = Vec::new();
    raws.extend((0..256).map(|i| vec![0; i]));
    raws.extend((1..256).map(|i| vec![0xFF; i]));
    raws.extend((0..256u16).map(|i| [vec![0x55; 64], i.to_be_bytes().to_vec()].concat()));
    let mut deepest = [0; 2];
    for (at, hashed) in [false, true].into_iter().enumerate() {
        let mut model = Model::new();
        for raw in &raws {
            let key = row_key(hashed, raw);
            model.insert(key.clone(), leaf(&key, 0, raw));
        }
        let store = store_of(&model);
        check(&store, &model);
        deepest[at] = model
            .keys()
            .map(|key| depth(&store, &model, key))
            .max()
            .unwrap();
    }
    assert!(deepest[0] >= 255, "ordered: {}", deepest[0]);
    assert!(
        deepest[1] <= 3 * 10,
        "hashed: {} for {} keys",
        deepest[1],
        raws.len()
    );
}

/// A path through every bit of 130-byte keys, the deepest an ordered table
/// of 64-byte keys allows: proven, and updated from its proof.
#[test]
fn a_path_through_every_bit() {
    let base: Vec<u8> = (0..130u8).map(|i| i.wrapping_mul(37) | 1).collect();
    let flip = |key: &[u8], level: usize| {
        let mut key = key.to_vec();
        key[level / 8] ^= 0x80 >> (level % 8);
        key
    };
    let mut model = Model::new();
    model.insert(base.clone(), leaf(&base, 0, b"base"));
    for level in 0..base.len() * 8 {
        let key = flip(&base, level);
        model.insert(key.clone(), leaf(&key, 0, &key));
    }
    let mut store = store_of(&model);
    check(&store, &model);
    assert_eq!(depth(&store, &model, &base), 1040);

    // Its neighbour's leaf opened, so a key beside both can go in.
    let beside = flip(&flip(&base, 1038), 1039);
    let keys = [base.clone(), beside.clone()];
    let proof = BatchProof::generate(&store, &keys).unwrap();
    let mut witness = proof
        .verify(&H, &scratch(&model), &claims(&model, &keys))
        .unwrap();
    let writes = [
        (base.clone(), None),
        (beside.clone(), Some(leaf(&beside, 1, b"beside"))),
    ];
    let mut sorted = writes.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let root = vos_tree::update(&H, &mut store, &sorted).unwrap();
    apply(&mut model, &sorted);
    assert_eq!(root, scratch(&model));
    check(&store, &model);
    assert_eq!(witness.update(&H, &commitments(&sorted)), Ok(root));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The format's hashes, pinned.
#[test]
fn known_answers() {
    let vh = value_hash(&H, &[0x11; 16], b"value");
    let a = keys::ordered(b"a");
    let b = keys::ordered(b"b");
    let (ha, hb): (Hash, Hash) = (leaf_hash(&H, &a, &vh), leaf_hash(&H, &b, &vh));
    let answers = [
        hex(&empty_root(&H)),
        hex(&vh),
        hex(&ha),
        hex(&branch_hash(&H, 6, &ha, &hb)),
        hex(&root(&H, &[(a.as_slice(), vh), (b.as_slice(), vh)])),
        hex(&salt(&H, &[0x22; 32], &a)),
        hex(&keys::hashed(&H, b"a")),
        hex(&keys::private(&H, b"a")),
    ];
    // Computed from the crate's format alone, with another BLAKE2b.
    let pinned = [
        "c8e63f97988369c020d5c7b94ffc7542585e39f607ff889d1e69c390e1690069",
        "333a382279d335b9600363983ca96fdf3b525a9da558d3e24614071e1ac740d8",
        "f0a3b044f203f2fd303188be0d20271e584790ea7f8c87575b1339c68cb54454",
        "206f2e335875bf5fa1ac289cc2e434df0611dca3ca2a7d89f39d80c31aeb0aa5",
        "206f2e335875bf5fa1ac289cc2e434df0611dca3ca2a7d89f39d80c31aeb0aa5",
        "13a54de0963708bba245888512d4dfe3",
        "893cfa8ac124a265b35ec8a85295d187610000",
        "893cfa8ac124a265b35ec8a85295d1877eeac3ec3c178bc397046f60a31f7f8f",
    ];
    assert_eq!(answers, pinned);
}
