//! The root of a set of leaves, built from scratch: the reference every
//! incremental update and proof agrees with.

use crate::Hash;
use crate::hash::{Hasher, branch_hash, empty_root, leaf_hash};
use crate::keys::{bit, first_difference};

/// The root of the tree over `leaves`, keys and their values' commitments,
/// in strictly increasing key order. It panics on keys out of order or not
/// prefix-free: a reference for tests, where the store's path refuses them.
pub fn root<H: Hasher, K: AsRef<[u8]>>(hasher: &H, leaves: &[(K, Hash)]) -> Hash {
    assert!(
        leaves.windows(2).all(|w| w[0].0.as_ref() < w[1].0.as_ref()),
        "leaves in strictly increasing key order"
    );
    if leaves.is_empty() {
        return empty_root(hasher);
    }
    subtree(hasher, leaves)
}

fn subtree<H: Hasher, K: AsRef<[u8]>>(hasher: &H, leaves: &[(K, Hash)]) -> Hash {
    let (first, last) = match leaves {
        [(key, value_hash)] => return leaf_hash(hasher, key.as_ref(), value_hash),
        [first, .., last] => (first.0.as_ref(), last.0.as_ref()),
        [] => unreachable!("a subtree holds a leaf"),
    };
    let level = first_difference(first, last).expect("prefix-free keys");
    let split = leaves.partition_point(|(key, _)| bit(key.as_ref(), level) == 0);
    let left = subtree(hasher, &leaves[..split]);
    let right = subtree(hasher, &leaves[split..]);
    branch_hash(hasher, level, &left, &right)
}
