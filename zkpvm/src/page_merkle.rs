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
//! This module is the single host-side source of truth for that tree.  It is
//! intentionally independent of any external blake2b crate: it hashes via the
//! same [`blake2b_compress`](crate::chips::blake2b_compress) software core the
//! in-AIR Blake2bBoundaryChip uses, so the host root and the circuit root are
//! identical by construction.
//!
//! Hash spec (matches the circuit's tag-block precompute):
//! - `leaf(page)  = blake2b256(TAG_LEAF ‖ page)`   (33 128-byte blocks)
//! - `node(l, r)  = blake2b256(TAG_NODE ‖ l ‖ r)`  (2 128-byte blocks)
//!
//! `TAG_LEAF` / `TAG_NODE` are distinct full 128-byte first blocks, giving
//! leaf/node domain separation as distinct chaining states; the absent-page
//! default is the all-zero leaf, which cannot collide with `leaf(page)` except
//! with negligible probability.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

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

/// Domain tag prepended as the full first 128-byte block of a leaf hash.
const TAG_LEAF: &[u8] = b"zkpvm/page-merkle/leaf/v1";
/// Domain tag prepended as the full first 128-byte block of a node hash.
const TAG_NODE: &[u8] = b"zkpvm/page-merkle/node/v1";

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

/// Standard blake2b-256 of an arbitrary message, built on the in-circuit
/// software compression core so host and circuit agree bit-for-bit.
fn blake2b256(msg: &[u8]) -> [u8; 32] {
    let mut h = iv_param_256();
    // At least one block, even for an empty message; the final block is
    // zero-padded and `t` counts real (non-padding) bytes processed so far.
    let n_blocks = msg.len().div_ceil(BLOCK).max(1);
    for i in 0..n_blocks {
        let start = i * BLOCK;
        let end = (start + BLOCK).min(msg.len());
        let mut block = [0u8; BLOCK];
        block[..end - start].copy_from_slice(&msg[start..end]);
        let t = end as u128; // bytes processed including this block, padding excluded
        let last = i == n_blocks - 1;
        h = blake2b_compress(&h, &block_words(&block), t, last);
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&h[i].to_le_bytes());
    }
    out
}

/// Build a tag-prefixed message: the tag zero-padded to a full 128-byte block,
/// followed by `payload`.
fn tagged(tag: &[u8], payload: &[u8]) -> Vec<u8> {
    debug_assert!(tag.len() <= BLOCK);
    let mut msg = Vec::with_capacity(BLOCK + payload.len());
    msg.extend_from_slice(tag);
    msg.resize(BLOCK, 0);
    msg.extend_from_slice(payload);
    msg
}

/// Leaf hash of one page.
pub fn leaf_hash(page: &[u8; PAGE_SIZE]) -> [u8; 32] {
    blake2b256(&tagged(TAG_LEAF, page))
}

/// Inner-node hash of two child hashes.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(left);
    payload[32..].copy_from_slice(right);
    blake2b256(&tagged(TAG_NODE, &payload))
}

/// `default_hashes()[ℓ]` = root of an all-zero (absent) subtree at level `ℓ`;
/// `[DEPTH]` is the empty leaf, `[0]` is the empty-tree root.
#[cfg(feature = "prover")]
pub fn default_hashes() -> &'static [[u8; 32]; (DEPTH + 1) as usize] {
    use std::sync::OnceLock;
    static DEFAULTS: OnceLock<[[u8; 32]; (DEPTH + 1) as usize]> = OnceLock::new();
    DEFAULTS.get_or_init(|| {
        let mut d = [[0u8; 32]; (DEPTH + 1) as usize];
        d[DEPTH as usize] = leaf_hash(&[0u8; PAGE_SIZE]);
        for level in (0..DEPTH as usize).rev() {
            d[level] = node_hash(&d[level + 1], &d[level + 1]);
        }
        d
    })
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

/// Map of page index → leaf hash for every page that differs from the default
/// (i.e. has at least one non-zero byte) in a flat image.
#[cfg(feature = "prover")]
fn nondefault_leaves(image: &[u8]) -> BTreeMap<u32, [u8; 32]> {
    let mut leaves = BTreeMap::new();
    let n_pages = image.len().div_ceil(PAGE_SIZE) as u32;
    for p in 0..n_pages {
        let page = page_bytes(image, p);
        if page.iter().any(|&b| b != 0) {
            leaves.insert(p, leaf_hash(&page));
        }
    }
    leaves
}

/// Root of the subtree rooted at `(level, node_idx)` given the non-default
/// leaf hashes of the whole tree.  Short-circuits all-default subtrees, so the
/// cost is `O(non-default pages × DEPTH)`.
#[cfg(feature = "prover")]
fn subtree_root(level: u32, node_idx: u64, leaves: &BTreeMap<u32, [u8; 32]>) -> [u8; 32] {
    if level == DEPTH {
        return *leaves
            .get(&(node_idx as u32))
            .unwrap_or(&default_hashes()[DEPTH as usize]);
    }
    // node_idx < 2^level and span = 2^(DEPTH-level), so the range stays within
    // [0, 2^DEPTH) and (DEPTH < 31) keeps it well inside u32.
    let span = 1u64 << (DEPTH - level);
    let lo = (node_idx * span) as u32;
    let hi = ((node_idx + 1) * span) as u32;
    // Any non-default leaf inside [lo, hi)?
    if leaves.range(lo..hi).next().is_none() {
        return default_hashes()[level as usize];
    }
    let l = subtree_root(level + 1, 2 * node_idx, leaves);
    let r = subtree_root(level + 1, 2 * node_idx + 1, leaves);
    node_hash(&l, &r)
}

/// Root of the page tree given a map of page index → leaf hash for every
/// non-default page (absent pages use the empty-leaf default).
#[cfg(feature = "prover")]
pub fn sparse_root(leaves: &BTreeMap<u32, [u8; 32]>) -> [u8; 32] {
    subtree_root(0, 0, leaves)
}

/// Root of the full page tree for a flat image.
#[cfg(feature = "prover")]
pub fn image_root(image: &[u8]) -> [u8; 32] {
    sparse_root(&nondefault_leaves(image))
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
#[derive(Clone, Debug)]
pub struct MerkleMultiproof {
    /// `(page_idx, before_leaf, after_leaf)`, sorted ascending by page index.
    pub leaves: Vec<(u32, [u8; 32], [u8; 32])>,
    /// Internal merge nodes, emitted bottom-up (level descending, index
    /// ascending within a level).
    pub merges: Vec<MergeNode>,
    pub root_before: [u8; 32],
    pub root_after: [u8; 32],
}

/// Build the boundary multiproof for a segment: `touched` is the set of page
/// indices the segment accessed, `entering`/`exiting` are the flat RAM images
/// at the segment's start/end.  The witness siblings are computed from
/// `entering` (untouched subtrees are identical in `exiting`).
#[cfg(feature = "prover")]
pub fn build_multiproof(
    entering: &[u8],
    exiting: &[u8],
    touched: &BTreeSet<u32>,
) -> MerkleMultiproof {
    build_multiproof_from_leaves(
        &nondefault_leaves(entering),
        &nondefault_leaves(exiting),
        touched,
    )
}

/// Core multiproof builder over non-default leaf maps (page index → leaf
/// hash).  `before`/`after` must agree on every page outside `touched`
/// (the soundness condition the in-circuit ledger enforces); witness siblings
/// are taken from `before`.
#[cfg(feature = "prover")]
pub fn build_multiproof_from_leaves(
    before: &BTreeMap<u32, [u8; 32]>,
    after: &BTreeMap<u32, [u8; 32]>,
    touched: &BTreeSet<u32>,
) -> MerkleMultiproof {
    let empty_leaf = default_hashes()[DEPTH as usize];
    let leaves: Vec<(u32, [u8; 32], [u8; 32])> = touched
        .iter()
        .map(|&p| {
            (
                p,
                *before.get(&p).unwrap_or(&empty_leaf),
                *after.get(&p).unwrap_or(&empty_leaf),
            )
        })
        .collect();

    // Empty touched set: no leaves, no merges; the roots are the full-tree
    // roots (in practice callers always list at least page 0 so this stays a
    // degenerate convenience, never the in-circuit path).
    if leaves.is_empty() {
        return MerkleMultiproof {
            leaves,
            merges: Vec::new(),
            root_before: sparse_root(before),
            root_after: sparse_root(after),
        };
    }

    let entering_leaves = before;
    let mut level_items: Vec<(u64, [u8; 32], [u8; 32])> =
        leaves.iter().map(|&(p, b, a)| (p as u64, b, a)).collect();
    let mut merges = Vec::new();

    for level in (1..=DEPTH).rev() {
        let mut next: Vec<(u64, [u8; 32], [u8; 32])> = Vec::new();
        let mut i = 0;
        while i < level_items.len() {
            let (idx, hb, ha) = level_items[i];
            let parent = idx >> 1;
            let has_sibling =
                idx & 1 == 0 && i + 1 < level_items.len() && level_items[i + 1].0 == idx + 1;
            if has_sibling {
                let (_, hb2, ha2) = level_items[i + 1];
                let pb = node_hash(&hb, &hb2);
                let pa = node_hash(&ha, &ha2);
                merges.push(MergeNode {
                    level: level - 1,
                    index: parent as u32,
                    left: Child::Computed,
                    right: Child::Computed,
                    child_before: [hb, hb2],
                    child_after: [ha, ha2],
                    hash_before: pb,
                    hash_after: pa,
                });
                next.push((parent, pb, pa));
                i += 2;
            } else {
                let sib_idx = idx ^ 1;
                let w = subtree_root(level, sib_idx, entering_leaves);
                let (left, right, child_before, child_after, pb, pa) = if idx & 1 == 0 {
                    (
                        Child::Computed,
                        Child::Witness(w),
                        [hb, w],
                        [ha, w],
                        node_hash(&hb, &w),
                        node_hash(&ha, &w),
                    )
                } else {
                    (
                        Child::Witness(w),
                        Child::Computed,
                        [w, hb],
                        [w, ha],
                        node_hash(&w, &hb),
                        node_hash(&w, &ha),
                    )
                };
                merges.push(MergeNode {
                    level: level - 1,
                    index: parent as u32,
                    left,
                    right,
                    child_before,
                    child_after,
                    hash_before: pb,
                    hash_after: pa,
                });
                next.push((parent, pb, pa));
                i += 1;
            }
        }
        level_items = next;
    }

    debug_assert_eq!(level_items.len(), 1);
    let (root_idx, root_before, root_after) = level_items[0];
    debug_assert_eq!(root_idx, 0);
    MerkleMultiproof {
        leaves,
        merges,
        root_before,
        root_after,
    }
}

/// Insert every page overlapped by the byte range `[ptr, ptr + len)`.
#[cfg(feature = "prover")]
pub(crate) fn add_range(set: &mut BTreeSet<u32>, ptr: u32, len: u32) {
    if len == 0 {
        return;
    }
    let first = ptr >> PAGE_BITS;
    let last = ((ptr as u64 + len as u64 - 1) >> PAGE_BITS).min(u32::MAX as u64) as u32;
    for p in first..=last {
        set.insert(p);
    }
}

/// The set of pages a segment touches: the union of all real RAM byte accesses
/// — step reads/writes plus every precompile mem-op family — mapped to page
/// granularity.  This is the single source of truth the ledger's per-page
/// boundary injection and the boundary multiproof must agree on; it enumerates
/// exactly the address sources that [`crate::chips::memory`]'s ledger builder
/// consumes.
#[cfg(feature = "prover")]
pub fn touched_pages(side_note: &crate::side_note::SideNote) -> BTreeSet<u32> {
    let mut pages = BTreeSet::new();
    for step in &side_note.steps {
        if let Some(ref r) = step.mem_read {
            add_range(&mut pages, r.address, r.size as u32);
        }
        if let Some(ref w) = step.mem_write {
            add_range(&mut pages, w.address, w.size as u32);
        }
    }
    for op in &side_note.blake2b_mem_ops {
        add_range(&mut pages, op.h_ptr, op.h_bytes.len() as u32);
        add_range(&mut pages, op.m_ptr, op.m_bytes.len() as u32);
        // out_bytes overwrite the h range — same pages.
    }
    for op in &side_note.ristretto_mem_ops {
        add_range(&mut pages, op.scalar_ptr, op.scalar_bytes.len() as u32);
        add_range(&mut pages, op.point_ptr, op.point_bytes.len() as u32);
        add_range(&mut pages, op.output_ptr, op.out_bytes.len() as u32);
    }
    for op in &side_note.ristretto_add_mem_ops {
        add_range(&mut pages, op.p_ptr, op.p_bytes.len() as u32);
        add_range(&mut pages, op.q_ptr, op.q_bytes.len() as u32);
        add_range(&mut pages, op.output_ptr, op.out_bytes.len() as u32);
    }
    for op in &side_note.scalar_binop_mem_ops {
        add_range(&mut pages, op.a_ptr, op.a_bytes.len() as u32);
        add_range(&mut pages, op.b_ptr, op.b_bytes.len() as u32);
        add_range(&mut pages, op.output_ptr, op.out_bytes.len() as u32);
    }
    for op in &side_note.scalar_reduce_wide_mem_ops {
        add_range(&mut pages, op.wide_ptr, op.wide_bytes.len() as u32);
        add_range(&mut pages, op.output_ptr, op.out_bytes.len() as u32);
    }
    pages
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
    h_after_tag(TAG_LEAF)
}

fn h_after_node_tag() -> [u64; 8] {
    h_after_tag(TAG_NODE)
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
    let mut calls = Vec::new();
    for &(p, _, _) in &mp.leaves {
        push_leaf_calls(&page_bytes(entering, p), &mut calls); // before pass
        push_leaf_calls(&page_bytes(exiting, p), &mut calls); // after pass
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
    let mut index: alloc::collections::BTreeMap<[u8; 209], usize> = alloc::collections::BTreeMap::new();
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

/// Build the boundary multiproof for a segment from its side note: enumerate
/// the touched pages (always including page 0, so the listed set is never
/// empty and the in-circuit chips stay unconditionally active), take the
/// entering image (`side_note.initial_memory`, already threaded by
/// `segment_side_note`) and the exit image (`replay_writes(.., None)`), and
/// recompute both roots.
#[cfg(feature = "prover")]
pub fn segment_multiproof(side_note: &crate::side_note::SideNote) -> MerkleMultiproof {
    let mut touched = touched_pages(side_note);
    touched.insert(0); // never-empty page set (design §0)
    let exiting = crate::segment::replay_writes(side_note, None);
    build_multiproof(&side_note.initial_memory, &exiting, &touched)
}

#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::*;

    #[test]
    fn blake2b256_known_answer() {
        // Standard BLAKE2b-256 of the empty string.
        let got = blake2b256(b"");
        let want = hex_to_32("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
        assert_eq!(got, want);
    }

    fn hex_to_32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn default_chain_is_consistent() {
        let d = default_hashes();
        assert_eq!(d[DEPTH as usize], leaf_hash(&[0u8; PAGE_SIZE]));
        for level in 0..DEPTH as usize {
            assert_eq!(d[level], node_hash(&d[level + 1], &d[level + 1]));
        }
    }

    #[test]
    fn empty_image_root_is_the_default_root() {
        assert_eq!(image_root(&[]), default_hashes()[0]);
        assert_eq!(image_root(&[0u8; PAGE_SIZE * 3]), default_hashes()[0]);
    }

    #[test]
    fn leaf_and_node_domain_separated() {
        // A node of two empty leaves must not equal a leaf of zeros.
        let d = default_hashes();
        assert_ne!(d[DEPTH as usize], d[DEPTH as usize - 1]);
    }

    /// An image with a few non-default pages: the sparse `image_root` must
    /// equal a direct full recomputation over the occupied pages.
    fn make_image(pages: &[(u32, u8)]) -> Vec<u8> {
        let max_page = pages.iter().map(|&(p, _)| p).max().unwrap_or(0);
        let mut img = vec![0u8; ((max_page + 1) as usize) * PAGE_SIZE];
        for &(p, fill) in pages {
            for b in &mut img[p as usize * PAGE_SIZE..(p as usize + 1) * PAGE_SIZE] {
                *b = fill;
            }
        }
        img
    }

    #[test]
    fn multiproof_roots_match_image_roots() {
        // Entering image: pages 1, 2 (adjacent, share a parent) and 1000 set.
        let entering = make_image(&[(1, 0xAA), (2, 0xBB), (1000, 0xCC)]);
        // Exit image: page 2 changed in place, page 5 newly written
        // (first-touch); pages 1 and 1000 left untouched.
        let mut exiting = entering.clone();
        for b in &mut exiting[2 * PAGE_SIZE..3 * PAGE_SIZE] {
            *b = 0xDD;
        }
        for b in &mut exiting[5 * PAGE_SIZE..6 * PAGE_SIZE] {
            *b = 0xEE;
        }

        // Touched set covers every page that differs: 2 (changed) and 5 (new).
        let touched: BTreeSet<u32> = [2u32, 5].into_iter().collect();
        let mp = build_multiproof(&entering, &exiting, &touched);

        assert_eq!(
            mp.root_before,
            image_root(&entering),
            "before root mismatch"
        );
        assert_eq!(mp.root_after, image_root(&exiting), "after root mismatch");
    }

    /// Synthetic leaf hash for a (page, version) pair — lets the tree logic be
    /// exercised at arbitrary page indices without allocating a flat image.
    fn synth_leaf(page: u32, version: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&page.to_le_bytes());
        h[4] = version;
        h[5] = 0xA5; // keep it clear of the all-zero default leaf
        h
    }

    #[test]
    fn multiproof_extreme_page_indices() {
        // Exercise page 0, the last page, and a deep interior page via sparse
        // leaf maps (no 4 GB flat image).  Each scenario: a few resident pages,
        // one of which is touched and changes value.
        let resident = [3u32, 17, 1 << (DEPTH - 1)];
        for &p in &[0u32, 1, 123_456, (1u32 << DEPTH) - 1] {
            let mut before = BTreeMap::new();
            for &r in &resident {
                before.insert(r, synth_leaf(r, 0));
            }
            before.insert(p, synth_leaf(p, 0));
            let mut after = before.clone();
            after.insert(p, synth_leaf(p, 1)); // touched page changes

            let touched: BTreeSet<u32> = [p].into_iter().collect();
            let mp = build_multiproof_from_leaves(&before, &after, &touched);
            assert_eq!(mp.root_before, sparse_root(&before), "page {p} before");
            assert_eq!(mp.root_after, sparse_root(&after), "page {p} after");
        }
    }

    #[test]
    fn multiproof_many_touched_pages() {
        // A larger touched set (sibling pairs, scattered singletons, first
        // touches) recomputes both roots correctly.
        let mut before = BTreeMap::new();
        for &r in &[0u32, 1, 2, 9, 10, 500, 99_999] {
            before.insert(r, synth_leaf(r, 0));
        }
        let mut after = before.clone();
        // Change some, first-touch others.
        after.insert(1, synth_leaf(1, 1));
        after.insert(9, synth_leaf(9, 1));
        after.insert(42, synth_leaf(42, 1)); // first touch
        after.insert(100_000, synth_leaf(100_000, 1)); // first touch
        let touched: BTreeSet<u32> = [1u32, 9, 42, 100_000].into_iter().collect();

        let mp = build_multiproof_from_leaves(&before, &after, &touched);
        assert_eq!(mp.root_before, sparse_root(&before));
        assert_eq!(mp.root_after, sparse_root(&after));
    }

    #[test]
    fn multiproof_no_change_keeps_roots_equal() {
        let img = make_image(&[(0, 1), (7, 2), (8, 3)]);
        let touched: BTreeSet<u32> = [0u32, 7, 8].into_iter().collect();
        let mp = build_multiproof(&img, &img, &touched);
        assert_eq!(mp.root_before, mp.root_after);
        assert_eq!(mp.root_before, image_root(&img));
    }

    #[test]
    fn multiproof_single_small_pages() {
        // Single touched page, dense-image path (small indices only; extreme
        // indices are covered by `multiproof_extreme_page_indices`).
        for &p in &[0u32, 1, 17] {
            let entering = make_image(&[(p, 0x11)]);
            let mut exiting = entering.clone();
            for b in &mut exiting[p as usize * PAGE_SIZE..(p as usize + 1) * PAGE_SIZE] {
                *b = 0x22;
            }
            let touched: BTreeSet<u32> = [p].into_iter().collect();
            let mp = build_multiproof(&entering, &exiting, &touched);
            assert_eq!(mp.root_before, image_root(&entering), "page {p} before");
            assert_eq!(mp.root_after, image_root(&exiting), "page {p} after");
        }
    }

    /// Trace a small store/load program and confirm the page enumeration
    /// agrees with the ledger's own `analyze_dedup` 4096-byte page count, and
    /// that `segment_multiproof` recomputes the entering/exit image roots.
    #[test]
    fn touched_pages_match_ledger_and_segment_multiproof_round_trips() {
        use crate::core::tracing::TracingPvm;
        use javm::PVM_REGISTER_COUNT;
        use javm::instruction::Opcode;
        use javm::interpreter::Interpreter;

        let mut regs = [0u64; PVM_REGISTER_COUNT];
        regs[0] = 0x42; // value to store
        regs[1] = 0x1000; // base address (page 1)
        let code = vec![
            Opcode::StoreIndU8 as u8,
            0x10,
            0,
            0,
            0,
            0,
            Opcode::LoadIndU8 as u8,
            0x12,
            0,
            0,
            0,
            0,
            Opcode::Trap as u8,
        ];
        let bitmask = vec![1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1];
        let pvm = Interpreter::new(
            code.clone(),
            bitmask.clone(),
            vec![],
            regs,
            vec![0u8; 4 * 1024 * 1024],
            10_000,
            25,
        );
        let mut tr = TracingPvm::new(pvm);
        assert_eq!(tr.run(), javm::ExitReason::Trap);
        let steps = tr.into_trace();
        let sn = crate::side_note::SideNote::new(steps, code, bitmask);

        // The store/load both hit address 0x1000 → page 1.
        let pages = touched_pages(&sn);
        assert!(pages.contains(&1), "expected page 1 (addr 0x1000) touched");

        // Page count must equal the ledger's own distinct 4096-byte page count.
        let report = crate::chips::memory::analyze_dedup(&sn);
        let ledger_4096 = report
            .distinct_pages
            .iter()
            .find(|&&(ps, _)| ps == PAGE_SIZE)
            .map(|&(_, n)| n)
            .expect("analyze_dedup reports a 4096-byte page count");
        assert_eq!(
            pages.len(),
            ledger_4096,
            "touched_pages disagrees with the ledger's distinct 4096-byte page count"
        );

        // segment_multiproof recomputes the entering/exit roots in-the-large.
        let mp = segment_multiproof(&sn);
        let exiting = crate::segment::replay_writes(&sn, None);
        assert_eq!(mp.root_before, image_root(&sn.initial_memory));
        assert_eq!(mp.root_after, image_root(&exiting));
    }

    fn replay(call: &crate::chips::Blake2bCall) -> [u64; 8] {
        blake2b_compress(&call.h, &call.m, call.t, call.f)
    }

    #[test]
    fn leaf_call_chain_reproduces_leaf_hash() {
        // The tag-precompute (start from h_after_leaf_tag, prove 32 page blocks)
        // must equal the full-message blake2b256(TAG_LEAF ‖ page).
        let mut page = [0u8; PAGE_SIZE];
        for (i, b) in page.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let mut calls = Vec::new();
        push_leaf_calls(&page, &mut calls);
        assert_eq!(calls.len(), 32);
        let mut h = calls[0].h;
        for call in &calls {
            // each call's h_in must chain from the previous h_out
            assert_eq!(call.h, h);
            h = replay(call);
        }
        assert_eq!(trunc32(&h), leaf_hash(&page));
    }

    #[test]
    fn node_call_reproduces_node_hash() {
        let l = [0x11u8; 32];
        let r = [0x22u8; 32];
        let call = node_call(&l, &r);
        assert_eq!(trunc32(&replay(&call)), node_hash(&l, &r));
    }

    #[test]
    fn boundary_calls_reproduce_all_multiproof_hashes() {
        let entering = make_image(&[(1, 0xAA), (2, 0xBB), (1000, 0xCC)]);
        let mut exiting = entering.clone();
        for b in &mut exiting[2 * PAGE_SIZE..3 * PAGE_SIZE] {
            *b = 0xDD;
        }
        for b in &mut exiting[5 * PAGE_SIZE..6 * PAGE_SIZE] {
            *b = 0xEE;
        }
        let touched: BTreeSet<u32> = [2u32, 5].into_iter().collect();
        let mp = build_multiproof(&entering, &exiting, &touched);

        // Every merge node's stored child hashes hash to its parent hashes.
        for node in &mp.merges {
            assert_eq!(
                node_hash(&node.child_before[0], &node.child_before[1]),
                node.hash_before
            );
            assert_eq!(
                node_hash(&node.child_after[0], &node.child_after[1]),
                node.hash_after
            );
        }

        // Rebuild the raw one-call-per-consumption list: one block-chain per
        // leaf-pass + one call per node-pass. Replay-consistency holds on it.
        let mut raw = Vec::new();
        for &(p, _, _) in &mp.leaves {
            push_leaf_calls(&page_bytes(&entering, p), &mut raw);
            push_leaf_calls(&page_bytes(&exiting, p), &mut raw);
        }
        for node in &mp.merges {
            raw.push(node_call(&node.child_before[0], &node.child_before[1]));
            raw.push(node_call(&node.child_after[0], &node.child_after[1]));
        }
        assert_eq!(raw.len(), mp.leaves.len() * 2 * 32 + mp.merges.len() * 2);

        // Leaf chains replay to the leaf digests recorded in the multiproof.
        let mut idx = 0;
        for &(_, before_leaf, after_leaf) in &mp.leaves {
            for want in [before_leaf, after_leaf] {
                let mut h = raw[idx].h;
                for _ in 0..32 {
                    assert_eq!(raw[idx].h, h);
                    h = replay(&raw[idx]);
                    idx += 1;
                }
                assert_eq!(trunc32(&h), want);
            }
        }
        // Node calls replay to the node digests.
        for node in &mp.merges {
            assert_eq!(trunc32(&replay(&raw[idx])), node.hash_before);
            idx += 1;
            assert_eq!(trunc32(&replay(&raw[idx])), node.hash_after);
            idx += 1;
        }
        assert_eq!(idx, raw.len());

        // The produced list DEDUPLICATES the raw consumptions: unique calls,
        // multiplicities aggregating every raw occurrence, nothing dropped.
        let (calls, mults) = boundary_blake2b_calls(&mp, &entering, &exiting);
        let key = |c: &crate::chips::Blake2bCall| (c.h, c.m, c.t, c.f);
        assert_eq!(calls.len(), mults.len());
        assert_eq!(mults.iter().map(|&m| m as usize).sum::<usize>(), raw.len());
        let uniq: BTreeSet<_> = calls.iter().map(key).collect();
        assert_eq!(uniq.len(), calls.len(), "deduped list must be unique");
        let mut counts: alloc::collections::BTreeMap<_, u32> = Default::default();
        for c in &raw {
            *counts.entry(key(c)).or_default() += 1;
        }
        assert_eq!(counts.len(), calls.len(), "every distinct raw call survives");
        for (c, &m) in calls.iter().zip(&mults) {
            assert_eq!(counts.get(&key(c)), Some(&m), "multiplicity mismatch");
        }
    }

    /// The dedup soundness story, in fraction space: the boundary chip
    /// produces Σ mult/denom(unique compression) and the page/merge chips
    /// consume Σ 1/denom(consumption) — these must cancel, and a single
    /// off-by-one multiplicity must imbalance them.  `EmitMult`'s value is
    /// deliberately unconstrained in the chip (the RangeMultiplicity256
    /// pattern); this cross-side sum is exactly what pins it in a proof.
    #[test]
    #[cfg(feature = "prover")]
    fn dedup_multiplicities_balance_in_fraction_space() {
        use crate::chips::Blake2bBoundaryChip;
        use crate::harness::MachineComponent;
        use crate::lookups::{AllLookupElements, Blake2bCompressionLookupElements};
        use stwo::core::channel::Blake2sChannel;
        use stwo::core::fields::FieldExpOps;
        use stwo::core::fields::m31::BaseField;
        use stwo::core::fields::qm31::SecureField;
        use stwo_constraint_framework::Relation;

        let entering = make_image(&[(1, 0xAA), (2, 0xBB), (1000, 0xCC)]);
        let mut exiting = entering.clone();
        for b in &mut exiting[2 * PAGE_SIZE..3 * PAGE_SIZE] {
            *b = 0xDD;
        }
        let touched: BTreeSet<u32> = [2u32, 5].into_iter().collect();
        let mp = build_multiproof(&entering, &exiting, &touched);
        let (calls, mults) = boundary_blake2b_calls(&mp, &entering, &exiting);
        let mut raw = Vec::new();
        for &(p, _, _) in &mp.leaves {
            push_leaf_calls(&page_bytes(&entering, p), &mut raw);
            push_leaf_calls(&page_bytes(&exiting, p), &mut raw);
        }
        for node in &mp.merges {
            raw.push(node_call(&node.child_before[0], &node.child_before[1]));
            raw.push(node_call(&node.child_after[0], &node.child_after[1]));
        }
        assert!(calls.len() < raw.len(), "the fixture must actually dedup");

        let mut all = AllLookupElements::default();
        let channel = &mut Blake2sChannel::default();
        Blake2bBoundaryChip.draw_lookup_elements(&mut all, channel);
        let el: &Blake2bCompressionLookupElements = all.as_ref();
        // (h_in[64] ‖ m[128] ‖ t[8] ‖ f[1] ‖ h_out[64]) as byte limbs — the
        // tuple shape both producer and consumers emit.
        let inv_denom = |c: &crate::chips::Blake2bCall| -> SecureField {
            let mut v: Vec<BaseField> = Vec::with_capacity(265);
            for w in c.h {
                v.extend(w.to_le_bytes().map(|b| BaseField::from(b as u32)));
            }
            for w in c.m {
                v.extend(w.to_le_bytes().map(|b| BaseField::from(b as u32)));
            }
            v.extend(c.t.to_le_bytes()[..8].iter().map(|&b| BaseField::from(b as u32)));
            v.push(BaseField::from(c.f as u32));
            v.extend(replay(c).map(|b| BaseField::from(b as u32)));
            <Blake2bCompressionLookupElements as Relation<BaseField, SecureField>>::combine(
                el,
                v.as_slice(),
            )
            .inverse()
        };
        let consumed = raw.iter().map(&inv_denom).fold(SecureField::default(), |a, f| a + f);
        let produced = calls
            .iter()
            .zip(&mults)
            .map(|(c, &m)| inv_denom(c) * BaseField::from(m))
            .fold(SecureField::default(), |a, f| a + f);
        assert_eq!(produced, consumed, "deduped productions must cancel the consumptions");

        let forged = calls
            .iter()
            .zip(&mults)
            .enumerate()
            .map(|(i, (c, &m))| inv_denom(c) * BaseField::from(m + u32::from(i == 0)))
            .fold(SecureField::default(), |a, f| a + f);
        assert_ne!(
            forged, consumed,
            "an off-by-one multiplicity must imbalance the compression relation"
        );
    }

    #[test]
    fn first_touch_page_default_before_leaf() {
        // A page absent from `entering` (default leaf) but written in `exiting`.
        let entering = make_image(&[(100, 0x33)]);
        let mut exiting = entering.clone();
        exiting.resize(201 * PAGE_SIZE, 0);
        for b in &mut exiting[200 * PAGE_SIZE..201 * PAGE_SIZE] {
            *b = 0x44;
        }
        let touched: BTreeSet<u32> = [200u32].into_iter().collect();
        let mp = build_multiproof(&entering, &exiting, &touched);
        // The before-leaf of page 200 is the empty-leaf default.
        let (_, before, _) = mp.leaves.iter().find(|&&(p, _, _)| p == 200).unwrap();
        assert_eq!(*before, default_hashes()[DEPTH as usize]);
        assert_eq!(mp.root_before, image_root(&entering));
        assert_eq!(mp.root_after, image_root(&exiting));
    }
}
