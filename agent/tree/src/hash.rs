//! The tree's hashes, under their domain tags.

use crate::{Hash, MAX_KEY, Salt};

/// The tag of a key's hash: the hashed and private transforms.
pub const TAG_KEY: &[u8] = b"vos/tree/key";
/// The tag of a leaf.
pub const TAG_LEAF: &[u8] = b"vos/tree/leaf";
/// The tag of a branch.
pub const TAG_BRANCH: &[u8] = b"vos/tree/branch";
/// The tag of the empty tree's root.
pub const TAG_EMPTY: &[u8] = b"vos/tree/empty";
/// The tag of a salt.
pub const TAG_SALT: &[u8] = b"vos/tree/salt";
/// The tag of a value's commitment.
pub const TAG_VALUE: &[u8] = b"vos/tree/value";

/// BLAKE2b-256, as the host provides it.
pub trait Hasher {
    /// The digest of `tag ‖ parts[0] ‖ parts[1] ‖ …`.
    fn hash(&self, tag: &[u8], parts: &[&[u8]]) -> Hash;
}

/// BLAKE2b-256 in software, or through the compression precompile in a PVM
/// program that has it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Blake2b;

impl Hasher for Blake2b {
    fn hash(&self, tag: &[u8], parts: &[&[u8]]) -> Hash {
        vos_pvm_precompiles::blake2b_hash::<32>(tag, parts)
    }
}

/// The commitment to `value` under `salt`, which a leaf commits: a proof
/// that opens the leaf shows it, and without the salt it hides the value.
pub fn value_hash<H: Hasher>(hasher: &H, salt: &Salt, value: &[u8]) -> Hash {
    hasher.hash(TAG_VALUE, &[salt, value])
}

/// The hash of `key`'s leaf, over its value's commitment.
pub fn leaf_hash<H: Hasher>(hasher: &H, key: &[u8], value_hash: &Hash) -> Hash {
    assert!(key.len() <= MAX_KEY, "a key of at most MAX_KEY bytes");
    let len = (key.len() as u16).to_be_bytes();
    hasher.hash(TAG_LEAF, &[&len, key, value_hash])
}

/// The hash of a branch at `level` over its children's hashes.
pub fn branch_hash<H: Hasher>(hasher: &H, level: u16, left: &Hash, right: &Hash) -> Hash {
    hasher.hash(TAG_BRANCH, &[&level.to_be_bytes(), left, right])
}

/// The empty tree's root.
pub fn empty_root<H: Hasher>(hasher: &H) -> Hash {
    hasher.hash(TAG_EMPTY, &[])
}

/// The salt of `key`'s leaf when a version with `seed` writes it.
pub fn salt<H: Hasher>(hasher: &H, seed: &[u8; 32], key: &[u8]) -> Salt {
    let digest = hasher.hash(TAG_SALT, &[seed, key]);
    let mut salt = [0; 16];
    salt.copy_from_slice(&digest[..16]);
    salt
}
