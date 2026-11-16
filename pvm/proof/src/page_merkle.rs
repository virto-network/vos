//! The page Merkle tree for the RAM boundary binding.
//!
//! The zkVM RAM is committed as a complete binary Merkle tree of depth
//! [`DEPTH`], keyed by **page address** (`addr >> PAGE_BITS`): each leaf is the
//! blake2b-256 hash of a [`PAGE_SIZE`]-byte page; absent / never-touched pages
//! hold the all-zero default leaf.  Per segment the prover proves a boundary
//! multiproof — recompute `initial_root` from the entering page images and
//! `final_root` from the exit images, sharing the untouched-subtree witnesses
//! — and binds both roots in-circuit (see
//! `docs/design/memory-merkle-binding.md`).
//!
//! The tree itself — its domain tags, leaf and node — is
//! `vos_pvm_program::image`'s, the one a program's image root is computed
//! over. This module holds the tag chaining states the circuit starts its
//! compressions from; its `host` child, behind the `prover` feature, builds
//! the multiproofs and the compression calls the circuit proves, through the
//! same [`crate::chips::blake2b_compress`] core the in-AIR
//! Blake2bBoundaryChip uses.
//!
//! Hash spec (matches the circuit's tag-block precompute):
//! - `leaf(page)  = blake2b256(LEAF_TAG ‖ page)`   (33 128-byte blocks)
//! - `node(l, r)  = blake2b256(NODE_TAG ‖ l ‖ r)`  (2 128-byte blocks)
//!
//! The tags are distinct full 128-byte first blocks, giving leaf/node domain
//! separation as distinct chaining states; the absent-page default is the
//! all-zero leaf, which cannot collide with `leaf(page)` except with
//! negligible probability.

use alloc::vec::Vec;

use vos_pvm_program::image::{LEAF_TAG, NODE_TAG};
pub use vos_pvm_program::image::{leaf_hash, node_hash};

use crate::chips::blake2b_compress;

/// Bytes per page (the PVM page size).
pub const PAGE_SIZE: usize = 4096;
/// `log2(PAGE_SIZE)`.
pub const PAGE_BITS: u32 = 12;
/// Address space width (RAM addresses are `u32`).
pub const ADDR_BITS: u32 = 32;
/// Tree depth = leaves at page granularity over the full `u32` address space.
pub const DEPTH: u32 = ADDR_BITS - PAGE_BITS;

// Index soundness (see design §1): internal merge-row indices are NOT
// range-checked in the circuit — a wrapped/huge index is unreachable from the
// pinned root `(0, 0)` by child doubling and is orphaned by logup balance.
// That argument is exact only while doubling cannot wrap mod the M31 prime
// `p = 2^31 - 1`, i.e. while every root-reachable index stays `< 2^DEPTH < p`.
const _: () = assert!(
    DEPTH < 31,
    "tree depth must be < log2(p) for index soundness"
);
const _: () = assert!(DEPTH == vos_pvm_program::image::DEPTH);

/// Blake2b IV (raw, pre-parameter-XOR).
const IV: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

/// Parameter block XOR for sequential blake2b with a 32-byte digest
/// (`digest_length = 32`, `key_length = 0`, `fanout = 1`, `depth = 1`).
const PARAM_XOR_256: u64 = 0x0101_0020;

const BLOCK: usize = 128;

/// blake2b-256 initial state (raw IV with the 32-byte-digest parameter XOR).
fn iv_param_256() -> [u64; 8] {
    let mut h = IV;
    h[0] ^= PARAM_XOR_256;
    h
}

/// Load a 128-byte block as 16 little-endian `u64` message words.
fn block_words(block: &[u8]) -> [u64; 16] {
    debug_assert_eq!(block.len(), BLOCK);
    let mut m = [0u64; 16];
    for (i, w) in m.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&block[i * 8..i * 8 + 8]);
        *w = u64::from_le_bytes(b);
    }
    m
}

/// Blake2b chaining state after compressing a tag's full 128-byte first block
/// (`t = 128`, not final): the precomputed prefix every leaf/node hash starts
/// from, so the circuit proves only the payload blocks.
fn h_after_tag(tag: &[u8]) -> [u64; 8] {
    blake2b_compress(
        &iv_param_256(),
        &block_words(&tagged_first_block(tag)),
        128,
        false,
    )
}

/// A tag padded to exactly one 128-byte block.
fn tagged_first_block(tag: &[u8]) -> [u8; BLOCK] {
    let mut b = [0u8; BLOCK];
    b[..tag.len()].copy_from_slice(tag);
    b
}

// Cheap (one compression) and `no_std`-friendly — recomputed rather than
// cached, since the verifier-side `add_constraints` needs them without `std`.
fn h_after_leaf_tag() -> [u64; 8] {
    h_after_tag(LEAF_TAG)
}

fn h_after_node_tag() -> [u64; 8] {
    h_after_tag(NODE_TAG)
}

/// The 8-word blake2b chaining state after compressing the leaf tag's first
/// block — the constant `h_in` of `MemoryPageChip`'s first (block-0) leaf
/// compression.
pub fn h_after_leaf_tag_words() -> [u64; 8] {
    h_after_leaf_tag()
}

/// The 8-word chaining state after the node tag's first block — the constant
/// `h_in` of every `MemoryMerkleChip` node compression.
pub fn h_after_node_tag_words() -> [u64; 8] {
    h_after_node_tag()
}

/// 64-byte little-endian serialization of an 8-word chaining state, matching
/// the `Blake2bCompression` tuple's `h_in` / `h_out` byte layout (word-major,
/// 8 LE bytes per word).
pub fn state_to_bytes(h: &[u64; 8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (i, w) in h.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    out
}

#[cfg(all(test, feature = "prover"))]
mod tests;

#[cfg(feature = "prover")]
mod host;
#[cfg(feature = "prover")]
pub(crate) use host::add_range;
#[cfg(feature = "prover")]
pub use host::{
    Child, MergeNode, MerkleMultiproof, boundary_blake2b_calls, build_multiproof,
    build_multiproof_from_leaves, build_sparse_multiproof, default_hashes, image_root,
    leaf_block_outputs, node_full_output, page_bytes, segment_multiproof,
    sparse_boundary_blake2b_calls, sparse_image_root, sparse_root, touched_pages, trunc32,
};
