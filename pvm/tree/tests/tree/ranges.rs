//! Range proofs: complete ranges, cursors, bounded scans, and updates inside
//! a scanned range.

use proptest::prelude::*;
use vos_tree::keys::{after, prefix_end};
use vos_tree::{Entry, Error, Hash, MemStore, RangeProof, leaf_hash};

use crate::common::{
    H, Model, Write, apply, commitments, leaf, pool, raw_key, row_key, rows, scratch, store_of,
    tampered,
};

/// Verify the range proof of `[from, to)`, check what tampering does to it,
/// and return it.
fn prove(store: &MemStore, model: &Model, from: &[u8], to: Option<&[u8]>) -> RangeProof {
    let root = scratch(model);
    let proof = RangeProof::generate(store, from, to).unwrap();
    let rows = rows(model, from, to);
    if let Err(error) = proof.verify(&H, &root, from, to, &rows) {
        panic!("{error:?}: [{from:?}, {to:?}) over {:?}", model.keys());
    }

    for (name, entries) in tampered(&proof.entries) {
        let tampered = RangeProof { entries };
        assert!(
            tampered.verify(&H, &root, from, to, &rows).is_err(),
            "{name} verified"
        );
    }
    // A leaf in the range closed under its hash leaves the root as it was,
    // and is refused.
    for (at, entry) in proof.entries.iter().enumerate() {
        let Entry::Leaf { key, value_hash } = entry else {
            continue;
        };
        if rows.iter().any(|(row, _)| row == key) {
            let mut entries = proof.entries.clone();
            entries[at] = Entry::Hash(leaf_hash(&H, key, value_hash));
            let dropped = RangeProof { entries };
            assert_eq!(
                dropped.verify(&H, &root, from, to, &rows).err(),
                Some(Error::Uncovered)
            );
        }
    }
    if !rows.is_empty() {
        let fewer = &rows[1..];
        assert_eq!(
            proof.verify(&H, &root, from, to, fewer).err(),
            Some(Error::Claim)
        );
        let mut reversed = rows.clone();
        reversed.reverse();
        if rows.len() > 1 {
            assert_eq!(
                proof.verify(&H, &root, from, to, &reversed).err(),
                Some(Error::Claim)
            );
        }
        let mut changed = rows.clone();
        changed[0].1[0] ^= 1;
        assert_eq!(
            proof.verify(&H, &root, from, to, &changed).err(),
            Some(Error::Claim)
        );
    }
    let mut more = rows.clone();
    more.push((b"zz".to_vec(), [0; 32]));
    assert_eq!(
        proof.verify(&H, &root, from, to, &more).err(),
        Some(Error::Claim)
    );
    proof
}

/// A bound: a pool key, a key between pool keys, or the empty string.
fn bound() -> impl Strategy<Value = (usize, u8)> {
    (any::<usize>(), 0u8..4)
}

fn bound_of(pool: &[Vec<u8>], (at, shape): (usize, u8)) -> Vec<u8> {
    let key = &pool[at % pool.len()];
    match shape {
        0 => key.clone(),
        1 => after(key),
        2 => key[..key.len() - 1].to_vec(),
        _ => Vec::new(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Ranges with cursors on keys, between keys, and at the edges; and
    /// updates inside each, from the proof alone.
    #[test]
    fn range_proofs_verify_and_update(
        pool in pool(),
        contents in prop::collection::vec((any::<usize>(), any::<u8>()), 0..20),
        from in bound(),
        to in prop::option::weighted(0.8, bound()),
        values in prop::collection::vec(prop::option::of(any::<u8>()), 24),
    ) {
        let mut model = Model::new();
        for &(at, value) in &contents {
            let key = &pool[at % pool.len()];
            model.insert(key.clone(), leaf(key, 0, &[value]));
        }
        let mut store = store_of(&model);
        let from = bound_of(&pool, from);
        // A range ending below its start is the empty one at its start.
        let to = to.map(|to| bound_of(&pool, to).max(from.clone()));
        let proof = prove(&store, &model, &from, to.as_deref());

        // Writes to the pool's keys in the range, and to its boundary leaves.
        let low = model.range(..from.clone()).next_back().map(|(key, _)| key.clone());
        let high = to.as_ref().and_then(|to| model.range(to.clone()..).next().map(|(key, _)| key.clone()));
        let inside = |key: &Vec<u8>| *key >= from && to.as_ref().is_none_or(|to| key < to);
        let mut keys: Vec<Vec<u8>> = pool.iter().filter(|key| inside(key)).cloned().collect();
        keys.extend(low.into_iter().chain(high));
        keys.sort();
        keys.dedup();
        let writes: Vec<Write> = keys
            .iter()
            .zip(&values)
            .map(|(key, value)| (key.clone(), value.map(|v| leaf(key, 1, &[v]))))
            .collect();
        let mut witness = proof
            .verify(&H, &scratch(&model), &from, to.as_deref(), &rows(&model, &from, to.as_deref()))
            .unwrap();
        let root = vos_tree::update(&H, &mut store, &writes).unwrap();
        apply(&mut model, &writes);
        prop_assert_eq!(root, scratch(&model));
        prop_assert_eq!(proof.update(&H, &commitments(&writes)), Ok(root));
        prop_assert_eq!(witness.update(&H, &commitments(&writes)), Ok(root));
    }

    /// A bounded scan proves the range from its cursor to just past its last
    /// row, or, short of its limit, to the end of the scanned prefix.
    #[test]
    fn bounded_scans(
        raws in prop::collection::vec((any::<bool>(), raw_key()), 0..24),
        cursor in raw_key(),
        hashed in any::<bool>(),
        limit in 1usize..6,
    ) {
        let mut model = Model::new();
        for (in_map, raw) in &raws {
            let key = row_key(*in_map, raw);
            model.insert(key.clone(), leaf(&key, 0, raw));
        }
        let store = store_of(&model);
        let prefix: &[u8] = if hashed { b"b/" } else { b"a/" };
        let from = row_key(hashed, &cursor);
        let end = prefix_end(prefix);
        let scanned: Vec<_> = rows(&model, &from, end.as_deref()).into_iter().take(limit).collect();
        let to = match scanned.last() {
            Some((last, _)) if scanned.len() == limit => Some(after(last)),
            _ => end,
        };
        prop_assert_eq!(&rows(&model, &from, to.as_deref()), &scanned);
        prove(&store, &model, &from, to.as_deref());
    }
}

/// A tree of four keys, and the ranges a scan of it asks for.
#[test]
fn cursors_edges_and_empty_ranges() {
    let mut model = Model::new();
    for raw in [b"b".as_slice(), b"d", b"f", b"h"] {
        let key = row_key(false, raw);
        model.insert(key.clone(), leaf(&key, 0, raw));
    }
    let store = store_of(&model);
    let key = |raw: &[u8]| row_key(false, raw);
    let ranges: [(Vec<u8>, Option<Vec<u8>>, usize); 11] = [
        (key(b"d"), Some(key(b"g")), 2), // a cursor on a key
        (key(b"c"), Some(key(b"g")), 2), // a cursor between keys
        (key(b"d"), Some(after(&key(b"d"))), 1),
        (key(b"d"), Some(key(b"d")), 0), // empty, at a key
        (key(b"e"), Some(key(b"e")), 0), // empty, between keys
        (key(b"e"), Some(key(b"f")), 0), // empty, the boundaries adjacent
        (Vec::new(), None, 4),           // both edges
        (key(b"a"), Some(key(b"c")), 1), // the left edge
        (key(b"g"), None, 1),            // the right edge
        (key(b"i"), None, 0),            // past every key
        (key(b"f"), Some(key(b"c")), 0), // ending below its start
    ];
    for (from, to, len) in ranges {
        assert_eq!(
            rows(&model, &from, to.as_deref()).len(),
            len,
            "{from:?}..{to:?}"
        );
        prove(&store, &model, &from, to.as_deref());
    }
}

/// A map whose prefix has no successor scans to the tree's right edge.
#[test]
fn a_scan_to_the_right_edge() {
    let mut model = Model::new();
    for raw in [b"x".as_slice(), b"y"] {
        let key = [&[0xFF][..], &row_key(false, raw)].concat();
        model.insert(key.clone(), leaf(&key, 0, raw));
    }
    let key = row_key(true, b"z");
    model.insert(key.clone(), leaf(&key, 0, b"z"));
    let store = store_of(&model);
    assert_eq!(prefix_end(&[0xFF]), None);
    let rows = rows(&model, &[0xFF], None);
    assert_eq!(rows.len(), 2);
    prove(&store, &model, &[0xFF], None);
}

/// A range whose closed subtree hides a key between the boundaries is
/// refused: a proof of another range checked as this one.
#[test]
fn a_range_needs_its_boundaries_open() {
    let mut model = Model::new();
    for raw in [b"b".as_slice(), b"d", b"f", b"h", b"j", b"l"] {
        let key = row_key(false, raw);
        model.insert(key.clone(), leaf(&key, 0, raw));
    }
    let store = store_of(&model);
    let root = scratch(&model);
    let key = |raw: &[u8]| row_key(false, raw);
    let narrow = RangeProof::generate(&store, &key(b"g"), Some(&key(b"i"))).unwrap();
    let wide = rows(&model, &key(b"c"), Some(&key(b"k")));
    assert_eq!(
        narrow
            .verify(&H, &root, &key(b"c"), Some(&key(b"k")), &wide)
            .err(),
        Some(Error::Uncovered)
    );
    let past = rows(&model, &key(b"g"), Some(&key(b"k")));
    assert_eq!(
        narrow
            .verify(&H, &root, &key(b"g"), Some(&key(b"k")), &past)
            .err(),
        Some(Error::Uncovered)
    );
    // It also shows the empty range between its first two leaves.
    let none: [(Vec<u8>, Hash); 0] = [];
    assert!(
        narrow
            .verify(&H, &root, &key(b"g"), Some(&key(b"g")), &none)
            .is_ok()
    );
}
