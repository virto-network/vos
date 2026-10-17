//! The tree's hashes, under their domain tags.

use crate::{Hash, MAX_KEY, Salt};

/// The tag of a key's hash: the hashed and private transforms.
pub(crate) const TAG_KEY: &[u8] = b"vos/tree/key";
/// The tag of a leaf.
pub(crate) const TAG_LEAF: &[u8] = b"vos/tree/leaf";
/// The tag of a branch.
pub(crate) const TAG_BRANCH: &[u8] = b"vos/tree/branch";
/// The tag of the empty tree's root.
pub(crate) const TAG_EMPTY: &[u8] = b"vos/tree/empty";
/// The tag of a salt.
pub(crate) const TAG_SALT: &[u8] = b"vos/tree/salt";
/// The tag of a value's commitment.
pub(crate) const TAG_VALUE: &[u8] = b"vos/tree/value";

/// BLAKE2b-256, as the host provides it.
pub trait Hasher {
    /// The digest of `tag ‖ parts[0] ‖ parts[1] ‖ …`.
    fn hash(&self, tag: &[u8], parts: &[&[u8]]) -> Hash;

    /// A branch's hash at `level` over its children's: [`branch_hash`]. The
    /// most frequent hash, so a hasher may compute it its own way.
    fn branch(&self, level: u16, left: &Hash, right: &Hash) -> Hash {
        self.hash(TAG_BRANCH, &[&level.to_be_bytes(), left, right])
    }
}

/// BLAKE2b-256 in software, or through the compression precompile in a PVM
/// program that has it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Blake2b;

impl Hasher for Blake2b {
    // Inlined where it is called: a key's transform, on every table
    // operation's path, then hashes a tag and parts the caller knows.
    #[inline(always)]
    fn hash(&self, tag: &[u8], parts: &[&[u8]]) -> Hash {
        vos_pvm_precompiles::blake2b_hash::<32>(tag, parts)
    }

    /// One block of words: the tag's 15 bytes, the level's 2, big-endian,
    /// then the children's 32 each from byte 17 on, 81 bytes in all.
    /// Inlined where it is called, so children held in aligned words are
    /// read as words.
    #[inline(always)]
    fn branch(&self, level: u16, left: &Hash, right: &Hash) -> Hash {
        const VOS_TREE: u64 = u64::from_le_bytes(*b"vos/tree");
        const SLASH_BRANCH: u64 = u64::from_le_bytes(*b"/branch\0");
        let word =
            |hash: &Hash, k: usize| u64::from_le_bytes(hash[k * 8..k * 8 + 8].try_into().unwrap());
        let left = [word(left, 0), word(left, 1), word(left, 2), word(left, 3)];
        let right = [
            word(right, 0),
            word(right, 1),
            word(right, 2),
            word(right, 3),
        ];
        let [high, low] = level.to_be_bytes();
        let block: [u64; 16] = [
            VOS_TREE,
            SLASH_BRANCH | u64::from(high) << 56,
            u64::from(low) | left[0] << 8,
            left[0] >> 56 | left[1] << 8,
            left[1] >> 56 | left[2] << 8,
            left[2] >> 56 | left[3] << 8,
            left[3] >> 56 | right[0] << 8,
            right[0] >> 56 | right[1] << 8,
            right[1] >> 56 | right[2] << 8,
            right[2] >> 56 | right[3] << 8,
            right[3] >> 56,
            0,
            0,
            0,
            0,
            0,
        ];
        // An unkeyed 32-byte digest's parameter block: its length, fanout 1
        // and depth 1.
        let mut h = vos_pvm_precompiles::BLAKE2B_IV;
        h[0] ^= 0x0101_0020;
        vos_pvm_precompiles::blake2b_compress_words(&mut h, &block, 81, true);
        let mut digest = [0; 32];
        for (bytes, word) in digest.chunks_exact_mut(8).zip(h) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        digest
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
    hasher.branch(level, left, right)
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
