//! Merkle openings over lifted trees (`recursion-air.md` §4.3), and
//! [`expand_decommitment`], the witness builder that turns Stwo's
//! deduplicated decommitment into one path a query.
//!
//! - **A leaf is the whole row,** the tree's columns sorted by log size
//!   (stable), as one sponge; the sort is the circuit's, fixed at build.
//! - **A path** is one node row a level, chained from the leaf, each
//!   ordered by a bit of the position, the last one's output the root's
//!   wires. A sibling is a free value, touching no other gate.
//! - **Paths are not shared across queries:** a repeated position is
//!   verified twice, harmlessly, and the structure does not depend on the
//!   draws.
//!
//! [`expand_decommitment`] is adapted from Stwo, as the workspace pins it,
//! crates/stwo/src/core/vcs_lifted/verifier.rs (`MerkleVerifierLifted::verify`,
//! Apache-2.0), modified to record each node's sibling.

use std::collections::HashMap;

use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;

use crate::context::{Bit, Context, Message, P2Handle, Var};
use crate::gadgets::{leaf_hash, node};
use crate::value::Value;

/// `leaf`'s path to `root`: a node a level, ordered by `bits` (least
/// significant first, the leaf's level first), each over its sibling.
pub fn verify_path<V: Value>(
    context: &mut Context<V>,
    leaf: P2Handle<V>,
    bits: &[Bit],
    siblings: &[[Message<V>; 2]],
    root: [Var; 2],
) {
    assert_eq!(bits.len(), siblings.len(), "a sibling a level");
    assert!(!bits.is_empty(), "a tree of one leaf has no path");
    let mut child = leaf;
    for (level, (&bit, &sibling)) in bits.iter().zip(siblings).enumerate() {
        let out = (level + 1 == bits.len()).then_some(root);
        child = node(context, &child, sibling, bit, out);
    }
}

/// One opening: the leaf of `n_values` values packed four a wire in
/// `wires`, sorted as the tree hashes its row, and its path to `root`.
/// The wires are yielded here when they are guesses.
pub fn verify_opening<V: Value>(
    context: &mut Context<V>,
    wires: &[Var],
    n_values: usize,
    bits: &[Bit],
    siblings: &[[V; 2]],
    root: [Var; 2],
) {
    let leaf = leaf_hash(context, wires, n_values);
    let siblings: Vec<[Message<V>; 2]> = siblings
        .iter()
        .map(|sibling| sibling.map(Message::Free))
        .collect();
    verify_path(context, leaf, bits, &siblings, root);
}

/// Why a decommitment does not expand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpandError {
    WitnessTooShort,
    WitnessTooLong,
}

/// A decommitment expanded: each level's sibling of each node on a queried
/// path, and the root the walk computed.
#[derive(Clone, Debug)]
pub struct Expanded<T> {
    siblings: Vec<HashMap<usize, T>>,
    pub root: T,
}

impl<T: Copy> Expanded<T> {
    /// The path of the leaf at `position`: its sibling at each level, the
    /// leaf's first.
    pub fn path(&self, position: usize) -> Vec<T> {
        self.siblings
            .iter()
            .enumerate()
            .map(|(level, siblings)| siblings[&(position >> level)])
            .collect()
    }
}

/// Replays `MerkleVerifierLifted::verify`'s walk over a tree of `height`
/// levels from its `leaves` (position and hash, sorted by position and
/// deduplicated, as the verifier builds them) and `hash_witness`, which
/// sends each sibling the walk cannot compute once: it records every
/// node's sibling, so each queried position gets its whole path.
pub fn expand_decommitment<H: MerkleHasherLifted>(
    height: u32,
    leaves: &[(usize, H::Hash)],
    hash_witness: &[H::Hash],
) -> Result<Expanded<H::Hash>, ExpandError> {
    assert!(
        leaves.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "leaves sorted and deduplicated"
    );
    let mut witness = hash_witness.iter().copied();
    let mut layer: Vec<(usize, H::Hash)> = leaves.to_vec();
    let mut siblings = Vec::with_capacity(height as usize);
    for _ in 0..height {
        let mut level = HashMap::new();
        let mut next = Vec::with_capacity(layer.len());
        for chunk in layer.chunk_by(|a, b| a.0 ^ 1 == b.0) {
            let (index, hash) = chunk[0];
            let children = match chunk {
                [_] => {
                    let sibling = witness.next().ok_or(ExpandError::WitnessTooShort)?;
                    level.insert(index, sibling);
                    if index & 1 == 0 {
                        (hash, sibling)
                    } else {
                        (sibling, hash)
                    }
                }
                [_, (other, other_hash)] => {
                    level.insert(index, *other_hash);
                    level.insert(*other, hash);
                    (hash, *other_hash)
                }
                _ => unreachable!("a chunk is a node or a pair of siblings"),
            };
            next.push((index >> 1, H::hash_children(children)));
        }
        siblings.push(level);
        layer = next;
    }
    if witness.next().is_some() {
        return Err(ExpandError::WitnessTooLong);
    }
    let [(_, root)] = layer[..] else {
        panic!("the positions lie in one tree of {height} levels");
    };
    Ok(Expanded { siblings, root })
}
