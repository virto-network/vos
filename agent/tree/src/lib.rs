//! The compressed Merkle tree that commits a map: its format, roots built
//! from scratch or kept up over stored rows, and its proofs.
//!
//! # Keys
//!
//! The tree is over keys `key'`: byte strings of 1 to [`MAX_KEY`] bytes, no
//! one a prefix of another. A key's bits are numbered from 0, most
//! significant first within each byte, so bit order is byte order. A table's
//! row key is `prefix ‖ transform(key)`, with tables' prefixes prefix-free
//! among themselves and the transform one of [`keys`]:
//! - `escape(key)`: each `0x00` becomes `0x00 0xFF`, then `0x00 0x00` ends
//!   the key. Escaped keys are prefix-free and keep the raw keys' order;
//! - `ordered(key) = escape(key)`;
//! - `hashed(key) = H128(key) ‖ escape(key)`, where `H128(key)` is the first
//!   16 bytes of `H("vos/tree/key" ‖ key)`;
//! - `private(key) = H("vos/tree/key" ‖ key)`.
//!
//! # Hashes
//!
//! `H` is BLAKE2b-256, unkeyed, over the concatenation of its arguments.
//! The tags are ASCII, and none is a prefix of another:
//! - a value's commitment: `vh = H("vos/tree/value" ‖ salt ‖ value)`, the
//!   salt 16 bytes;
//! - a leaf: `H("vos/tree/leaf" ‖ len ‖ key' ‖ vh)`, where `len` is the
//!   key's length in bytes as a big-endian `u16`;
//! - a branch: `H("vos/tree/branch" ‖ level ‖ left ‖ right)`, the level a
//!   big-endian `u16` and the children's hashes 32 bytes each;
//! - the empty tree's root: `H("vos/tree/empty")`;
//! - a salt: the first 16 bytes of `H("vos/tree/salt" ‖ seed ‖ key')`, from
//!   a 32-byte seed.
//!
//! A proof opens leaves by their key and `vh` alone, never the salt, so a
//! value it shows beside the one it proves stays hidden however few values
//! it could take.
//!
//! # Shape
//!
//! The tree over a set of keys is unique:
//! - over no key, the empty tree;
//! - over one key, its leaf;
//! - over more, a branch at `level`, the first bit at which the keys do not
//!   all agree. Its left child is the tree over the keys whose bit there is
//!   0, its right child the tree over the others.
//!
//! So every branch has two nonempty children, levels increase strictly down
//! every path and stay within the bits of every key below, and the leaves
//! in order are the keys in byte order. A leaf's hash does not depend on its
//! depth and a branch's commits its own level, so removing a leaf replaces
//! its parent with its sibling, whose hash stays the same.
//!
//! A key's path starts at the root and, at each branch, takes the child that
//! the key's bit at the branch's level selects, a bit past the key's end
//! reading 0. It ends at a leaf: the key's own if the key is present, and
//! otherwise a leaf whose key shares the longest prefix with it. An absent
//! key goes in as a leaf beside the first node of its path deeper than the
//! first bit at which it differs from that leaf, under a new branch at that
//! bit.
//!
//! # Proofs
//!
//! A proof is a pruned tree: its nodes in pre-order (a branch, its left
//! subtree, its right subtree), each an [`Entry`]: a branch by its level, a
//! closed subtree by its hash, an opened leaf by its key and `vh`, or the
//! empty tree as the only entry. No branch has two closed children. Every
//! hash a proof needs appears once, in that order. Proofs are SCALE-coded
//! with the workspace codec, fixed-width little-endian integers: the
//! entries' count as a `u32`, then each entry's index as a byte (0 branch,
//! 1 hash, 2 leaf, 3 empty) and its fields in order: a level as a `u16`, a
//! hash as 32 bytes, a key as a `u32` count and its bytes. (The leaf's hash
//! has its own length encoding, the big-endian `u16` above.)
//! - A [`BatchProof`] opens the paths of a set of keys, each to its end.
//! - A [`RangeProof`] for `[from, to)` opens the paths of the largest key
//!   below `from` and of the first key at or past `to`, each the tree's edge
//!   when there is no such key, and every subtree between them.
//!
//! A verifier rebuilds the root, and checks that levels increase strictly
//! down every path, that each opened leaf lies on the side its key's bit
//! selects at each branch above it, at a level within its key, and that the
//! opened leaves are in strictly increasing order. Then:
//! - for a batch proof, each claimed key's path ends in the proof: at its
//!   own leaf with the claimed `vh`, or, claimed absent, at the empty tree or
//!   at another leaf, which the key neither prefixes nor extends;
//! - for a range proof, the opened leaves and closed subtrees in order are:
//!   any, the last of them an opened leaf below `from`, unless none; the
//!   leaves in the range, which must be the claimed rows; and an opened leaf
//!   at or past `to`, unless nothing follows.
//!
//! [`Witness::update`] applies writes from a proof alone: the puts, then the
//! deletes. A put of an absent key whose path ends in a closed subtree goes
//! in if it differs from an opened leaf below the path's last branch above
//! that branch's level, as every key of a range does.
//!
//! # Rows
//!
//! A [`NodeStore`] holds a tree as rows: one per branch, by its level and
//! the first `level` bits of its keys, holding both children's references
//! and hashes; one per leaf, by its key, holding its salt and `vh`; and the
//! top reference. [`update`] rewrites the rows on the paths of a batch of
//! written keys, reading every row it needs before it writes any.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

mod build;
mod hash;
pub mod keys;
mod partial;
mod proof;
mod range;
mod store;
mod update;

pub use build::root;
pub use hash::{
    Blake2b, Hasher, TAG_BRANCH, TAG_EMPTY, TAG_KEY, TAG_LEAF, TAG_SALT, TAG_VALUE, branch_hash,
    empty_root, leaf_hash, salt, value_hash,
};
pub use proof::{BatchProof, Entry, Witness};
pub use range::RangeProof;
pub use scale::{Decode, Encode};
pub use store::{Child, MemStore, Node, NodeStore, Rows, reachable, stored_root};
pub use update::update;

/// A BLAKE2b-256 digest.
pub type Hash = [u8; 32];

/// A leaf's salt.
pub type Salt = [u8; 16];

/// The longest key, in bytes: every bit index fits a `u16`.
pub const MAX_KEY: usize = 8192;

/// A leaf's row: its salt, which the holder of the value needs to commit to
/// it, and the commitment its leaf hashes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Leaf {
    pub salt: Salt,
    /// `H("vos/tree/value" ‖ salt ‖ value)`.
    pub value_hash: Hash,
}

/// Why a proof, or an update from one, was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The entries are not a pruned tree of the format.
    Malformed,
    /// The proof rebuilds another root.
    Root,
    /// A claim disagrees with the proof.
    Claim,
    /// A key's path leaves what the proof opens.
    Uncovered,
    /// Keys are not in strictly increasing order.
    Order,
    /// A key is empty, longer than [`MAX_KEY`], or a prefix of another.
    Key,
    /// A store lacks a row a parent names.
    Missing,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::Malformed => "not a pruned tree of the format",
            Error::Root => "the proof rebuilds another root",
            Error::Claim => "a claim disagrees with the proof",
            Error::Uncovered => "a key's path leaves what the proof opens",
            Error::Order => "keys out of order",
            Error::Key => "a key empty, too long, or not prefix-free",
            Error::Missing => "a row its parent names is missing",
        })
    }
}

impl core::error::Error for Error {}

/// Whether `key` may be in a tree.
pub(crate) fn valid_key(key: &[u8]) -> bool {
    !key.is_empty() && key.len() <= MAX_KEY
}
