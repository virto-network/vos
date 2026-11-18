//! A batch proof checked from its encoding: the same judgment as decoding
//! it and verifying the entries, with the same error, both ways.

use proptest::prelude::*;
use vos_tree::{BatchProof, Decode, Encode, Error, Hash, Hasher, MAX_KEY, verify_encoded};

use crate::common::{H, Model, leaf, pool, scratch, store_of, tampered};

/// The judgment of the entries the bytes decode to.
fn decoded(bytes: &[u8], root: &Hash, claims: &[(Vec<u8>, Option<Hash>)]) -> Result<(), Error> {
    let proof = BatchProof::decode_exact(bytes).ok_or(Error::Malformed)?;
    proof.verify(&H, root, claims).map(|_| ())
}

fn agree(bytes: &[u8], root: &Hash, claims: &[(Vec<u8>, Option<Hash>)]) -> Result<(), Error> {
    let streamed = verify_encoded(&H, bytes, root, claims);
    assert_eq!(streamed, decoded(bytes, root, claims), "claims {claims:?}");
    streamed
}

/// Short keys of one or two bytes, so absent keys often part from a
/// subtree at a bit no branch splits on.
fn short_pool() -> impl Strategy<Value = Vec<Vec<u8>>> {
    (1..=2usize).prop_flat_map(|len| {
        prop::collection::btree_set(prop::collection::vec(any::<u8>(), len), 1..24)
            .prop_map(|keys| keys.into_iter().collect())
    })
}

/// A pool of keys of one of the two shapes, a model's contents as indices
/// into it, and claims about indices into it, present or absent, in any
/// order, repeats among them.
type Case = (Vec<Vec<u8>>, Vec<(usize, u8)>, Vec<usize>);

fn case() -> impl Strategy<Value = Case> {
    (
        prop_oneof![pool(), short_pool()],
        prop::collection::vec((any::<usize>(), any::<u8>()), 0..20),
        prop::collection::vec(any::<usize>(), 0..8),
    )
}

/// A tampering of a case's proof, claims or root.
#[derive(Clone, Debug)]
enum Tamper {
    None,
    /// One of the entries' tamperings the proofs' tests make.
    Entries(usize),
    /// A bit of the encoding flipped.
    Bit(usize, u8),
    /// The encoding cut short.
    Truncated(usize),
    /// A byte appended.
    Appended(u8),
    /// A claim's presence flipped, or its commitment changed.
    Claim(usize),
    /// A claim about an empty key, a too long one, or a prefix of a tree key.
    BadKey(usize, u8),
    Root,
    /// A proof of other keys.
    Other(Vec<usize>),
}

fn tamper() -> impl Strategy<Value = Tamper> {
    prop_oneof![
        2 => Just(Tamper::None),
        2 => any::<usize>().prop_map(Tamper::Entries),
        2 => (any::<usize>(), 0..8u8).prop_map(|(at, bit)| Tamper::Bit(at, bit)),
        1 => any::<usize>().prop_map(Tamper::Truncated),
        1 => any::<u8>().prop_map(Tamper::Appended),
        2 => any::<usize>().prop_map(Tamper::Claim),
        1 => (any::<usize>(), 0..3u8).prop_map(|(at, how)| Tamper::BadKey(at, how)),
        1 => Just(Tamper::Root),
        1 => prop::collection::vec(any::<usize>(), 0..4).prop_map(Tamper::Other),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// Over random trees, claims and tamperings, the streamed check and the
    /// decoded one accept and refuse alike, with the same error; untampered,
    /// both accept.
    #[test]
    fn the_streamed_check_is_the_decoded_one((pool, contents, picks) in case(), tamper in tamper()) {
        let mut model = Model::new();
        for &(at, value) in &contents {
            let key = &pool[at % pool.len()];
            model.insert(key.clone(), leaf(key, 0, &[value]));
        }
        let store = store_of(&model);
        let mut root = scratch(&model);
        let keys: Vec<Vec<u8>> = picks.iter().map(|&at| pool[at % pool.len()].clone()).collect();
        let mut claims: Vec<(Vec<u8>, Option<Hash>)> = keys
            .iter()
            .map(|key| (key.clone(), model.get(key).map(|leaf| leaf.value_hash)))
            .collect();
        let proof = BatchProof::generate(&store, &keys).unwrap();
        let mut bytes = proof.encode();
        match tamper {
            Tamper::None => {
                prop_assert_eq!(agree(&bytes, &root, &claims), Ok(()));
                return Ok(());
            }
            Tamper::Entries(pick) => {
                let tampered = tampered(&proof.entries);
                if let Some((_, entries)) = tampered.get(pick % tampered.len().max(1)) {
                    bytes = BatchProof { entries: entries.clone() }.encode();
                }
            }
            Tamper::Bit(at, bit) => {
                let at = at % bytes.len();
                bytes[at] ^= 1 << bit;
            }
            Tamper::Truncated(at) => bytes.truncate(at % bytes.len()),
            Tamper::Appended(byte) => bytes.push(byte),
            Tamper::Claim(at) if !claims.is_empty() => {
                let at = at % claims.len();
                claims[at].1 = match claims[at].1 {
                    Some(mut hash) if at.is_multiple_of(2) => {
                        hash[0] ^= 1;
                        Some(hash)
                    }
                    Some(_) => None,
                    None => Some(leaf(&claims[at].0, 0, &[0]).value_hash),
                };
            }
            Tamper::Claim(_) => {}
            Tamper::BadKey(at, how) => {
                let key = match how {
                    0 => Vec::new(),
                    1 => vec![1; MAX_KEY + 1],
                    _ => pool[at % pool.len()][..1].to_vec(),
                };
                let at = at % (claims.len() + 1);
                claims.insert(at, (key, None));
            }
            Tamper::Root => root[31] ^= 0x80,
            Tamper::Other(picks) => {
                let other: Vec<Vec<u8>> =
                    picks.iter().map(|&at| pool[at % pool.len()].clone()).collect();
                bytes = BatchProof::generate(&store, &other).unwrap().encode();
            }
        }
        agree(&bytes, &root, &claims).ok();
    }
}

/// The tree over 0x80 and 0x81 splits only at bit 7. The absent keys 0x01
/// and 0x40 part from it at bit 0 and bit 1, so both paths end at 0x80's
/// leaf, the left; and 0x01 claimed beside 0x80 ends there too. Claims in
/// key order are not the proof's: both checks accept them.
#[test]
fn absent_keys_parting_where_no_branch_splits() {
    let mut model = Model::new();
    for key in [vec![0x80], vec![0x81]] {
        model.insert(key.clone(), leaf(&key, 0, &key));
    }
    let store = store_of(&model);
    let root = scratch(&model);
    let present = Some(model[&vec![0x80]].value_hash);
    for claims in [
        vec![(vec![0x01], None), (vec![0x40], None)],
        vec![(vec![0x01], None), (vec![0x80], present)],
        vec![
            (vec![0x81], Some(model[&vec![0x81]].value_hash)),
            (vec![0x01], None),
        ],
    ] {
        let keys: Vec<Vec<u8>> = claims.iter().map(|(key, _)| key.clone()).collect();
        let bytes = BatchProof::generate(&store, &keys).unwrap().encode();
        assert_eq!(agree(&bytes, &root, &claims), Ok(()), "{claims:?}");
    }
}

/// A refusal reports the first refused claim, in the claims' order,
/// wherever its path ends; and only once the proof rebuilds the root.
#[test]
fn the_first_refused_claim_is_reported() {
    let mut model = Model::new();
    for key in [vec![0x10], vec![0x80], vec![0x81]] {
        model.insert(key.clone(), leaf(&key, 0, &key));
    }
    let store = store_of(&model);
    let root = scratch(&model);
    let keys = [vec![0x81], vec![0x10], vec![0x20]];
    let bytes = BatchProof::generate(&store, &keys).unwrap().encode();
    let wrong = Some([7; 32]);
    let claims = [(vec![0x81], wrong), (Vec::new(), None), (vec![0x20], None)];
    assert_eq!(agree(&bytes, &root, &claims), Err(Error::Claim));
    let claims = [(Vec::new(), None), (vec![0x81], wrong)];
    assert_eq!(agree(&bytes, &root, &claims), Err(Error::Key));
    let mut other = root;
    other[0] ^= 1;
    assert_eq!(agree(&bytes, &other, &claims), Err(Error::Root));
    assert_eq!(
        agree(&bytes[..bytes.len() - 1], &root, &claims),
        Err(Error::Malformed)
    );
}

/// BLAKE2b's branch hash, one block of words, is the tagged hash.
#[test]
fn the_branch_hash_is_the_tagged_hash() {
    let (left, right) = ([0xA5; 32], core::array::from_fn(|at| at as u8));
    for level in [0, 7, 0x1234, u16::MAX] {
        assert_eq!(
            H.branch(level, &left, &right),
            H.hash(b"vos/tree/branch", &[&level.to_be_bytes(), &left, &right])
        );
    }
}
