//! Data availability: where a package's segments are read from, by their
//! segment root and index; and its emulation in process.

use std::collections::BTreeMap;
use std::sync::Arc;

use vos_tree::{Blake2b, Hash, Hasher};

/// The tag of [`segment_root`]'s hashes.
const TAG: &[u8] = b"vos/jam/segments";

/// Where exported segments are read from.
pub trait Segments: Send + Sync {
    /// Export `index` of the package whose exports' segment root is `root`.
    fn segment(&self, root: &Hash, index: u32) -> Option<Vec<u8>>;
}

/// A package's exports, by their segment root.
#[derive(Clone, Debug, Default)]
pub struct Da {
    exports: BTreeMap<Hash, Arc<Vec<Vec<u8>>>>,
}

impl Da {
    /// Keep a package's exports: their segment root.
    pub fn put(&mut self, segments: Vec<Vec<u8>>) -> Hash {
        let root = segment_root(&segments);
        self.exports.insert(root, Arc::new(segments));
        root
    }

    /// The exports under `root`.
    pub fn exports(&self, root: &Hash) -> Option<&Arc<Vec<Vec<u8>>>> {
        self.exports.get(root)
    }
}

impl Segments for Da {
    fn segment(&self, root: &Hash, index: u32) -> Option<Vec<u8>> {
        self.exports.get(root)?.get(index as usize).cloned()
    }
}

/// A stand-in for a package's segment root: a binary Merkle tree over the
/// segments' hashes, BLAKE2b-256 under its own tag, its odd node carried up.
/// It names the segments here as the Gray Paper's constant-depth tree
/// names them on JAM, but is not that root.
pub fn segment_root(segments: &[Vec<u8>]) -> Hash {
    let mut level: Vec<Hash> = segments
        .iter()
        .map(|segment| Blake2b.hash(TAG, &[&[0], segment]))
        .collect();
    if level.is_empty() {
        return Blake2b.hash(TAG, &[]);
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [left, right] => Blake2b.hash(TAG, &[&[1], left, right]),
                [odd] => *odd,
                _ => unreachable!("chunks of two"),
            })
            .collect();
    }
    level[0]
}
