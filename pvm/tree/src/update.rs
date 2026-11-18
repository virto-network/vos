//! The incremental update of a stored tree.

use alloc::vec::Vec;

use crate::hash::Hasher;
use crate::partial::Partial;
use crate::store::NodeStore;
use crate::{Error, Hash, Leaf, valid_key};

/// Apply `writes`, in strictly increasing key order, to the tree `store`
/// holds: a leaf row to put at a key, or `None` to delete it. Returns the
/// new root.
///
/// Every row on the written keys' paths is rewritten, and the rows of the
/// branches and leaves the writes took off the tree are deleted, so the
/// store holds the tree over its new keys and no other row. Every read comes
/// before the first write. A batch may be split over several calls in key
/// order or in any other: each call leaves the store consistent.
///
/// A batch out of order ([`Error::Order`]), with a key that is empty, too
/// long or not prefix-free with the tree's ([`Error::Key`]), or meeting a
/// row a parent names that the store lacks ([`Error::Missing`]), is refused
/// before anything is written.
pub fn update<S: NodeStore, H: Hasher, K: AsRef<[u8]>>(
    hasher: &H,
    store: &mut S,
    writes: &[(K, Option<Leaf>)],
) -> Result<Hash, S::Error> {
    if !writes.windows(2).all(|w| w[0].0.as_ref() < w[1].0.as_ref()) {
        return Err(Error::Order.into());
    }
    if !writes.iter().all(|(key, _)| valid_key(key.as_ref())) {
        return Err(Error::Key.into());
    }
    let mut tree = Partial::from_top(store.top()?);
    for (key, _) in writes {
        tree.reach(store, key.as_ref())?;
    }
    let commitments: Vec<(&[u8], Option<Hash>)> = writes
        .iter()
        .map(|(key, leaf)| (key.as_ref(), leaf.map(|leaf| leaf.value_hash)))
        .collect();
    let deleted = tree.apply(&commitments)?;
    let mut rehashed = Vec::new();
    let root = tree.rehash(hasher, Some(&mut rehashed));

    for (level, prefix) in &tree.removed {
        store.delete_node(*level, prefix)?;
    }
    for &at in &rehashed {
        let (level, prefix, node) = tree.row(at);
        store.put_node(level, prefix, node)?;
    }
    for (key, leaf) in writes {
        if let Some(leaf) = leaf {
            store.put_leaf(key.as_ref(), *leaf)?;
        }
    }
    for &index in &deleted {
        store.delete_leaf(writes[index].0.as_ref())?;
    }
    store.set_top(tree.top())?;
    Ok(root)
}
