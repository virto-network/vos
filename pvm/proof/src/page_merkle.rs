//! Host-side page Merkle tree for the RAM boundary binding.
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
//! over; this module adds the multiproofs and the compression calls the
//! circuit proves, through the same [`crate::chips::blake2b_compress`] core
//! the in-AIR Blake2bBoundaryChip uses.
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

/// The page bytes at `page_idx` in a flat image, zero-padded past the end.
pub fn page_bytes(image: &[u8], page_idx: u32) -> [u8; PAGE_SIZE] {
    let mut page = [0u8; PAGE_SIZE];
    let start = (page_idx as usize) * PAGE_SIZE;
    if start < image.len() {
        let end = (start + PAGE_SIZE).min(image.len());
        page[..end - start].copy_from_slice(&image[start..end]);
    }
    page
}

/// A child slot of a merge row in the boundary multiproof schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Child {
    /// The child hash is computed by a lower merge row (or a leaf row) and is
    /// consumed via the `MerkleNode` relation in-circuit.
    Computed,
    /// The child is an untouched subtree whose hash is supplied as a witness.
    /// The SAME value is used in both the before and after passes (the
    /// frontier-reuse rule); soundness rests on the before-pass root equality.
    Witness([u8; 32]),
}

/// One internal merge node of the boundary multiproof: the chip recomputes
/// `hash_before`/`hash_after` as `node(left, right)` over the two passes,
/// driving one blake2b compression per pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeNode {
    /// Produced level, `0..DEPTH` (children sit at `level + 1`).
    pub level: u32,
    /// Node index at `level`; children are `2*index` and `2*index + 1`.
    pub index: u32,
    pub left: Child,
    pub right: Child,
    /// `[left, right]` child hashes in the before pass (witness children carry
    /// their shared witness value); `node(child_before) == hash_before`.
    pub child_before: [[u8; 32]; 2],
    /// `[left, right]` child hashes in the after pass; `node(child_after) ==
    /// hash_after`.  A witness child's entry equals its `child_before` entry.
    pub child_after: [[u8; 32]; 2],
    pub hash_before: [u8; 32],
    pub hash_after: [u8; 32],
}

/// The boundary multiproof: the leaf set (with before/after hashes), the
/// bottom-up merge schedule, and the two recomputed roots.  `root_before`
/// equals `image_root(entering)` and `root_after` equals `image_root(exiting)`
/// whenever `touched` covers every page that differs between the two images.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleMultiproof {
    /// `(page_idx, before_leaf, after_leaf)`, sorted ascending by page index.
    pub leaves: Vec<(u32, [u8; 32], [u8; 32])>,
    /// Internal merge nodes, emitted bottom-up (level descending, index
    /// ascending within a level).
    pub merges: Vec<MergeNode>,
    pub root_before: [u8; 32],
    pub root_after: [u8; 32],
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

/// First 32 bytes (4 LE words) of a chaining state — the truncated digest a
/// leaf/node compression chain produces.
pub fn trunc32(h: &[u64; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&h[i].to_le_bytes());
    }
    out
}

/// The 32 chained compressions that hash one page into its leaf digest,
/// starting from `h_after_leaf_tag()`.  Appends to `calls`.
fn push_leaf_calls(page: &[u8; PAGE_SIZE], calls: &mut Vec<crate::chips::Blake2bCall>) {
    let mut h = h_after_leaf_tag();
    for block in 0..32usize {
        let m = block_words(&page[block * BLOCK..block * BLOCK + BLOCK]);
        let t = (128 * (block as u128 + 2)) as u128;
        let f = block == 31;
        calls.push(crate::chips::Blake2bCall { h, m, t, f });
        h = blake2b_compress(&h, &m, t, f);
    }
}

/// The 32 running chaining states a page's leaf hash passes through: index `k`
/// is the output of compressing block `k` (so it is block `k+1`'s `h_in`, and
/// `[31]`'s first 32 bytes are the leaf digest).  Each is 64 LE bytes — the
/// `h_out` columns `MemoryPageChip` witnesses per block.
pub fn leaf_block_outputs(page: &[u8; PAGE_SIZE]) -> Vec<[u8; 64]> {
    let mut h = h_after_leaf_tag();
    let mut outs = Vec::with_capacity(32);
    for block in 0..32usize {
        let m = block_words(&page[block * BLOCK..block * BLOCK + BLOCK]);
        let t = (128 * (block as u128 + 2)) as u128;
        let f = block == 31;
        h = blake2b_compress(&h, &m, t, f);
        outs.push(state_to_bytes(&h));
    }
    outs
}

/// Full 64-byte (8-word) output of the node compression of two child digests —
/// the `h_out` columns `MemoryMerkleChip` witnesses (first 32 bytes = the node
/// hash).
pub fn node_full_output(left: &[u8; 32], right: &[u8; 32]) -> [u8; 64] {
    let mut payload = [0u8; BLOCK];
    payload[..32].copy_from_slice(left);
    payload[32..64].copy_from_slice(right);
    state_to_bytes(&blake2b_compress(
        &h_after_node_tag(),
        &block_words(&payload),
        192,
        true,
    ))
}

/// The single compression that hashes two child digests into a node digest.
fn node_call(left: &[u8; 32], right: &[u8; 32]) -> crate::chips::Blake2bCall {
    let mut payload = [0u8; BLOCK];
    payload[..32].copy_from_slice(left);
    payload[32..64].copy_from_slice(right);
    // bytes 64..128 are the zero pad
    crate::chips::Blake2bCall {
        h: h_after_node_tag(),
        m: block_words(&payload),
        t: 192,
        f: true,
    }
}

/// Every blake2b compression the Blake2bBoundaryChip must prove for a
/// segment, DEDUPLICATED, with each unique compression's in-circuit
/// consumption count: for each touched leaf, the 32-block chain over the
/// entering page then the exit page; for each merge node, the before-pass
/// then the after-pass node compression.  Identical compressions are
/// common — two all-zero pages, a read-only page whose passes coincide,
/// same-level default-subtree merges — and each consumer (page / merge
/// chip row) emits −1 into the compression relation, so the boundary chip
/// produces each unique compression ONCE with the count as its logup
/// multiplicity (`EmitMult`): the balance the one-block-per-consumption
/// scheme held, at a fraction of the rows.  Order is first occurrence —
/// deterministic in the multiproof, which prover and re-measurement both
/// derive from the trace.
pub fn boundary_blake2b_calls(
    mp: &MerkleMultiproof,
    entering: &[u8],
    exiting: &[u8],
) -> (Vec<crate::chips::Blake2bCall>, Vec<u32>) {
    boundary_blake2b_calls_with(
        mp,
        |page| page_bytes(entering, page),
        |page| page_bytes(exiting, page),
    )
}

fn boundary_blake2b_calls_with(
    mp: &MerkleMultiproof,
    mut entering_page: impl FnMut(u32) -> [u8; PAGE_SIZE],
    mut exiting_page: impl FnMut(u32) -> [u8; PAGE_SIZE],
) -> (Vec<crate::chips::Blake2bCall>, Vec<u32>) {
    let mut calls = Vec::new();
    for &(p, _, _) in &mp.leaves {
        push_leaf_calls(&entering_page(p), &mut calls); // before pass
        push_leaf_calls(&exiting_page(p), &mut calls); // after pass
    }
    for node in &mp.merges {
        calls.push(node_call(&node.child_before[0], &node.child_before[1]));
        calls.push(node_call(&node.child_after[0], &node.child_after[1]));
    }

    let key = |c: &crate::chips::Blake2bCall| {
        let mut k = [0u8; 8 * 8 + 16 * 8 + 16 + 1];
        for (i, w) in c.h.iter().enumerate() {
            k[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        for (i, w) in c.m.iter().enumerate() {
            k[64 + i * 8..64 + i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        k[192..208].copy_from_slice(&c.t.to_le_bytes());
        k[208] = c.f as u8;
        k
    };
    let mut index: alloc::collections::BTreeMap<[u8; 209], usize> =
        alloc::collections::BTreeMap::new();
    let mut unique = Vec::new();
    let mut mults: Vec<u32> = Vec::new();
    for c in calls {
        match index.entry(key(&c)) {
            alloc::collections::btree_map::Entry::Occupied(e) => mults[*e.get()] += 1,
            alloc::collections::btree_map::Entry::Vacant(e) => {
                e.insert(unique.len());
                unique.push(c);
                mults.push(1);
            }
        }
    }
    (unique, mults)
}

#[cfg(all(test, feature = "prover"))]
mod tests;

#[cfg(feature = "prover")]
mod host;
#[cfg(feature = "prover")]
pub(crate) use host::add_range;
#[cfg(feature = "prover")]
pub use host::{
    build_multiproof, build_multiproof_from_leaves, build_sparse_multiproof, default_hashes,
    image_root, segment_multiproof, sparse_boundary_blake2b_calls, sparse_image_root, sparse_root,
    touched_pages,
};
