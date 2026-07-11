//! Sparse-Merkle state commitments — the `anchor_kind 0x02` math.
//!
//! A fixed-depth binary SMT over fixed-width keys: depth = 8 × key
//! width, every key is a leaf position, absent keys hash as the
//! [`EMPTY_LEAF`] sentinel. The generalization source is cipher-clerk's
//! `merkle.rs`/`state_root.rs` (depth 128, 16-byte keys), proven
//! end-to-end by the succinct-voucher pipeline; this module widens the
//! same math to any key width and parameterizes the hash domains, so
//! an actor field keyed by `u64` gets a depth-64 tree and cipher-clerk
//! instantiations reproduce cipher-clerk roots byte-for-byte.
//!
//! What lives here is the *math*: hashes, the empty-subtree chain,
//! full-recompute roots over sorted leaf slices, single-key proofs,
//! and the [`BatchProof`] multiproof (one consistent root for N
//! touched keys — the succinct-witness workhorse). The row-backed
//! *incremental* tree that maintains a root across dispatches lives
//! with the storage handles (`vos::storage`), which own the guest
//! overlay; it delegates every hash to this module.
//!
//! ## Conventions (shared with cipher-clerk — do not drift)
//!
//! - `level` counts MSB-first from the root: the bit a node splits on
//!   is `level`, `byte = level / 8`, `bit = 7 - level % 8`. Sorted-by-
//!   key slices split correctly by `partition_point` at every level
//!   (bit-0 keys sort before bit-1 keys in ascending byte order).
//! - `depth` counts from the leaves: [`SmtProof::siblings`]`[0]` is the
//!   leaf-level sibling; `bit_at(key, depth)` reads bit
//!   `8·width − 1 − depth` MSB-first (depth 0 = LSB of the last byte).
//! - The empty chain: `chain[0] = EMPTY_LEAF`,
//!   `chain[d] = node_hash(chain[d−1], chain[d−1])`.
//! - Hashes are `blake2b_256(domain, parts)` with parts concatenated,
//!   no length prefixes (`vos::crypto::blake2b_hash`, which routes
//!   through the blake2b precompile ecall on riscv64).

use alloc::vec::Vec;

use crate::crypto::blake2b_hash;

/// Leaf hash of an absent key. Distinct from any real leaf: content
/// hashes are keyed blake2b outputs, and the all-zero string is not in
/// their image for any domain used here.
pub const EMPTY_LEAF: [u8; 32] = [0u8; 32];

/// Domain tags for the default vos-owned trees (the `anchor_kind 0x02`
/// composite). Application trees that must reproduce pre-existing
/// roots (clerk-ledger ↔ cipher-clerk) instantiate [`SmtParams`] with
/// their own domains instead.
pub const VOS_LEAF_DOMAIN: &[u8] = b"vos/smt/leaf/v1";
pub const VOS_NODE_DOMAIN: &[u8] = b"vos/smt/node/v1";

/// One tree's shape: hash domains + key width in bytes. Depth is
/// always `8 × width` — every key bit is a tree level, so the leaf
/// set alone determines the root (no insertion-order dependence).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmtParams {
    pub leaf_domain: &'static [u8],
    pub node_domain: &'static [u8],
    /// Key width in bytes; tree depth is `8 × width`.
    pub width: usize,
}

impl SmtParams {
    pub const fn vos(width: usize) -> Self {
        Self {
            leaf_domain: VOS_LEAF_DOMAIN,
            node_domain: VOS_NODE_DOMAIN,
            width,
        }
    }

    pub const fn depth(&self) -> usize {
        self.width * 8
    }
}

/// Hash a leaf's content. Callers that key by a *hashed* logical key
/// (forfeiting ordered iteration) must embed the full logical key in
/// `content` so a slot collision rejects instead of aliasing — the
/// cipher-clerk external-id pattern.
pub fn leaf_hash(p: &SmtParams, content: &[u8]) -> [u8; 32] {
    blake2b_hash::<32>(p.leaf_domain, &[content])
}

/// Hash an internal node from its (left, right) child hashes.
pub fn node_hash(p: &SmtParams, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    blake2b_hash::<32>(p.node_domain, &[left, right])
}

/// Empty-subtree hashes for depths `0..=depth()`. Build once per
/// computation and thread through — each entry is one blake2b call.
pub fn empty_chain(p: &SmtParams) -> Vec<[u8; 32]> {
    let mut chain = Vec::with_capacity(p.depth() + 1);
    chain.push(EMPTY_LEAF);
    for d in 1..=p.depth() {
        let below = chain[d - 1];
        chain.push(node_hash(p, &below, &below));
    }
    chain
}

/// Fold a state-blob hash and per-field committed roots into the one
/// composite `anchor_kind 0x02` anchors — the whole agent keyspace
/// with the state blob as the designated first leaf. Field order is
/// the `#[actor]` struct's declaration order (part of the upgrade
/// contract: reordering committed fields moves the anchor).
pub fn composite_fold(
    state_hash: &[u8; 32],
    roots: impl IntoIterator<Item = [u8; 32]>,
) -> [u8; 32] {
    let p = SmtParams::vos(32);
    let mut acc = *state_hash;
    for root in roots {
        acc = node_hash(&p, &acc, &root);
    }
    acc
}

/// Test bit `depth` of `key` counting from the leaves: depth 0 is the
/// LSB of the last byte, depth `8·width − 1` is the MSB of byte 0.
pub fn bit_at(p: &SmtParams, key: &[u8], depth: usize) -> bool {
    debug_assert!(key.len() == p.width && depth < p.depth());
    let bit_from_msb = p.depth() - 1 - depth;
    let byte_idx = bit_from_msb / 8;
    let bit_idx = 7 - (bit_from_msb % 8);
    (key[byte_idx] >> bit_idx) & 1 == 1
}

/// Test the MSB-first bit `level` of `key` (the bit a node at `level`
/// splits on).
pub fn level_bit(key: &[u8], level: usize) -> bool {
    (key[level / 8] >> (7 - (level % 8))) & 1 == 1
}

/// Fold a subtree hash upward through all-empty sibling levels along
/// `key`'s path: `h` is the subtree hash at `from` levels above the
/// leaves; the result is the enclosing subtree hash at `to` levels
/// above the leaves. The compressed-spine primitive: a subtree holding
/// a single leaf (or a single deeper branch) hashes up through nothing
/// but empty siblings.
pub fn spine_hash(
    p: &SmtParams,
    chain: &[[u8; 32]],
    key: &[u8],
    mut h: [u8; 32],
    from: usize,
    to: usize,
) -> [u8; 32] {
    debug_assert!(from <= to && to <= p.depth());
    for depth in from..to {
        let sibling = &chain[depth];
        h = if bit_at(p, key, depth) {
            node_hash(p, sibling, &h)
        } else {
            node_hash(p, &h, sibling)
        };
    }
    h
}

/// SMT root over sorted `(key, leaf_hash)` pairs — the full-recompute
/// reference every incremental representation must agree with.
/// Slice recursion via `partition_point`, zero intermediate
/// allocations; stack frames bounded by the depth (~10 KB at 128).
///
/// `sorted_leaves` MUST be ascending and deduped by key; a violation
/// silently computes a wrong root (mirrors the cipher-clerk contract).
/// `level` is the MSB-first bit this call splits on (0 at the root);
/// `depth_from_leaf` the levels remaining below (start: `p.depth()`).
pub fn sparse_root_sorted<K: AsRef<[u8]>>(
    p: &SmtParams,
    sorted_leaves: &[(K, [u8; 32])],
    level: usize,
    depth_from_leaf: usize,
    chain: &[[u8; 32]],
) -> [u8; 32] {
    if sorted_leaves.is_empty() {
        return chain[depth_from_leaf];
    }
    if depth_from_leaf == 0 {
        return sorted_leaves[0].1;
    }
    let byte_idx = level / 8;
    let bit_idx = 7 - (level % 8);
    let split =
        sorted_leaves.partition_point(|(k, _)| (k.as_ref()[byte_idx] >> bit_idx) & 1 == 0);
    let (left, right) = sorted_leaves.split_at(split);
    let l = sparse_root_sorted(p, left, level + 1, depth_from_leaf - 1, chain);
    let r = sparse_root_sorted(p, right, level + 1, depth_from_leaf - 1, chain);
    node_hash(p, &l, &r)
}

/// Convenience: the root of a whole tree from its sorted leaves.
pub fn root_of_sorted<K: AsRef<[u8]>>(p: &SmtParams, sorted_leaves: &[(K, [u8; 32])]) -> [u8; 32] {
    let chain = empty_chain(p);
    sparse_root_sorted(p, sorted_leaves, 0, p.depth(), &chain)
}

/// A single-key inclusion-or-non-inclusion proof: exactly `depth()`
/// siblings ordered leaf-level-first. `leaf == EMPTY_LEAF` witnesses
/// non-inclusion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtProof {
    pub key: Vec<u8>,
    pub leaf: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
}

impl SmtProof {
    /// Recompute the root from the proof and compare.
    pub fn verify(&self, p: &SmtParams, expected_root: &[u8; 32]) -> bool {
        if self.siblings.len() != p.depth() || self.key.len() != p.width {
            return false;
        }
        let mut hash = self.leaf;
        for (depth, sibling) in self.siblings.iter().enumerate() {
            hash = if bit_at(p, &self.key, depth) {
                node_hash(p, sibling, &hash)
            } else {
                node_hash(p, &hash, sibling)
            };
        }
        &hash == expected_root
    }

    pub fn is_inclusion(&self) -> bool {
        self.leaf != EMPTY_LEAF
    }
}

/// A sparse Merkle **multiproof**: one consistent root for N touched
/// keys. The caller supplies the touched `(key, leaf_hash)` pairs and
/// the proof supplies a *frontier* — cached hashes of every untouched
/// non-empty subtree — so the root recomputes exactly as
/// [`sparse_root_sorted`] would over the full tree.
///
/// The succinct-witness pattern: verify all touched leaves against
/// `root_before` via [`root`](Self::root), then recompute `root_after`
/// from their *updated* hashes reusing the same frontier (untouched
/// branches don't change). Soundness rests on the `root == root_before`
/// equality: a wrong, missing, or extra frontier hash shifts the
/// recomputed root and is rejected.
#[derive(
    rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, Default, PartialEq, Eq,
)]
#[rkyv(crate = rkyv)]
pub struct BatchProof {
    /// Untouched non-empty subtree hashes, sorted by `(level, prefix)`.
    /// `level` = MSB-first bits fixed by the path (0 = whole tree);
    /// `prefix` holds those bits with trailing zeros, `width` bytes.
    /// Empty subtrees are omitted — the verifier falls back to the
    /// empty chain.
    frontier: Vec<FrontierNode>,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
struct FrontierNode {
    level: u16,
    prefix: Vec<u8>,
    hash: [u8; 32],
}

impl BatchProof {
    /// Build a multiproof for `touched_keys` against the full tree
    /// given as sorted `(key, leaf_hash)` leaves. Touched keys absent
    /// from the tree are valid (non-inclusion). Host-side only in
    /// practice — the guest consumes proofs, it doesn't build them.
    pub fn build<K: AsRef<[u8]>>(
        p: &SmtParams,
        sorted_leaves: &[(K, [u8; 32])],
        touched_keys: &[&[u8]],
    ) -> Self {
        let chain = empty_chain(p);
        let mut keys: Vec<&[u8]> = touched_keys.to_vec();
        keys.sort_unstable();
        keys.dedup();
        let mut frontier = Vec::new();
        let prefix = alloc::vec![0u8; p.width];
        build_frontier_rec(p, &keys, sorted_leaves, prefix, 0, &chain, &mut frontier);
        frontier.sort_unstable_by(|a, b| (a.level, &a.prefix).cmp(&(b.level, &b.prefix)));
        Self { frontier }
    }

    /// Recompute the root from `touched` (MUST be sorted ascending and
    /// deduped by key; `leaf_hash == EMPTY_LEAF` for an absent or
    /// removed key) and this proof's frontier.
    pub fn root<K: AsRef<[u8]>>(&self, p: &SmtParams, touched: &[(K, [u8; 32])]) -> [u8; 32] {
        debug_assert!(
            touched.windows(2).all(|w| w[0].0.as_ref() < w[1].0.as_ref()),
            "BatchProof::root requires touched sorted+deduped ascending by key"
        );
        let chain = empty_chain(p);
        let prefix = alloc::vec![0u8; p.width];
        self.root_rec(p, touched, prefix, 0, &chain)
    }

    fn frontier_get(&self, level: usize, prefix: &[u8]) -> Option<[u8; 32]> {
        self.frontier
            .binary_search_by(|n| {
                (n.level as usize, n.prefix.as_slice()).cmp(&(level, prefix))
            })
            .ok()
            .map(|i| self.frontier[i].hash)
    }

    fn root_rec<K: AsRef<[u8]>>(
        &self,
        p: &SmtParams,
        touched: &[(K, [u8; 32])],
        prefix: Vec<u8>,
        level: usize,
        chain: &[[u8; 32]],
    ) -> [u8; 32] {
        let depth_from_leaf = p.depth() - level;
        if touched.is_empty() {
            return self
                .frontier_get(level, &prefix)
                .unwrap_or(chain[depth_from_leaf]);
        }
        if depth_from_leaf == 0 {
            return touched[0].1;
        }
        let byte_idx = level / 8;
        let bit_idx = 7 - (level % 8);
        let split = touched.partition_point(|(k, _)| (k.as_ref()[byte_idx] >> bit_idx) & 1 == 0);
        let (left, right) = touched.split_at(split);
        let mut prefix_r = prefix.clone();
        prefix_r[byte_idx] |= 1 << bit_idx;
        let l = self.root_rec(p, left, prefix, level + 1, chain);
        let r = self.root_rec(p, right, prefix_r, level + 1, chain);
        node_hash(p, &l, &r)
    }
}

/// Walk `touched` and `full` (both sorted) in lockstep: any subtree
/// with no touched key records its real hash if non-empty. Mirrors
/// [`BatchProof::root_rec`]'s split exactly so `(level, prefix)` keys
/// line up — an asymmetric split makes honest proofs fail.
fn build_frontier_rec<K: AsRef<[u8]>>(
    p: &SmtParams,
    touched: &[&[u8]],
    full: &[(K, [u8; 32])],
    prefix: Vec<u8>,
    level: usize,
    chain: &[[u8; 32]],
    out: &mut Vec<FrontierNode>,
) {
    let depth_from_leaf = p.depth() - level;
    if touched.is_empty() {
        if !full.is_empty() {
            out.push(FrontierNode {
                level: level as u16,
                prefix,
                hash: sparse_root_sorted(p, full, level, depth_from_leaf, chain),
            });
        }
        return;
    }
    if depth_from_leaf == 0 {
        return;
    }
    let byte_idx = level / 8;
    let bit_idx = 7 - (level % 8);
    let t_split = touched.partition_point(|k| (k[byte_idx] >> bit_idx) & 1 == 0);
    let (t_left, t_right) = touched.split_at(t_split);
    let f_split = full.partition_point(|(k, _)| (k.as_ref()[byte_idx] >> bit_idx) & 1 == 0);
    let (f_left, f_right) = full.split_at(f_split);
    let mut prefix_r = prefix.clone();
    prefix_r[byte_idx] |= 1 << bit_idx;
    build_frontier_rec(p, t_left, f_left, prefix, level + 1, chain, out);
    build_frontier_rec(p, t_right, f_right, prefix_r, level + 1, chain, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// cipher-clerk's exact domains — the parity instantiation.
    const CC: SmtParams = SmtParams {
        leaf_domain: b"cipher-clerk/smt/leaf/v1",
        node_domain: b"cipher-clerk/smt/node/v1",
        width: 16,
    };

    fn key16(i: u64) -> [u8; 16] {
        let h = blake2b_hash::<32>(b"vos-smt-test-key", &[&i.to_le_bytes()]);
        let mut k = [0u8; 16];
        k.copy_from_slice(&h[..16]);
        k
    }

    fn sorted_leaves(n: u64) -> Vec<([u8; 16], [u8; 32])> {
        let mut v: Vec<_> = (0..n)
            .map(|i| (key16(i), leaf_hash(&CC, &i.to_le_bytes())))
            .collect();
        v.sort_unstable_by_key(|(k, _)| *k);
        v
    }

    /// Byte-parity with cipher-clerk: the same leaves under the same
    /// domains must reproduce the root cipher-clerk's own
    /// `SparseMerkleTree`/`BatchProof` computed (vectors generated by
    /// running cipher-clerk directly). This is what lets clerk-ledger
    /// serve its existing composite roots from this module.
    #[test]
    fn reproduces_cipher_clerk_roots_byte_for_byte() {
        fn parity_key(i: u64) -> [u8; 16] {
            let h = blake2b_hash::<32>(b"vos-smt-parity-key", &[&i.to_le_bytes()]);
            let mut k = [0u8; 16];
            k.copy_from_slice(&h[..16]);
            k
        }
        assert_eq!(
            hex(&leaf_hash(&CC, b"content")),
            "5d8bfb1950db62def17e65a15fcf2d9b5e0e6743842b10337b2257a84167b538",
        );
        let mut leaves: Vec<([u8; 16], [u8; 32])> = (0..10u64)
            .map(|i| (parity_key(i), leaf_hash(&CC, &i.to_le_bytes())))
            .collect();
        leaves.sort_unstable_by_key(|(k, _)| *k);
        let root = root_of_sorted(&CC, &leaves);
        assert_eq!(
            hex(&root),
            "6a765aaaf21c65116c810a400556f2d4829f85be211f3e74d468b50196a2ee1e",
        );
        // The multiproof reconstructs the same root (touched: one
        // present key, one absent) — cipher-clerk's BatchProof printed
        // the identical value for this scenario.
        let touched_keys = [parity_key(3), parity_key(99)];
        let refs: Vec<&[u8]> = touched_keys.iter().map(|k| k.as_slice()).collect();
        let proof = BatchProof::build(&CC, &leaves, &refs);
        let mut t: Vec<([u8; 16], [u8; 32])> = vec![
            (
                parity_key(3),
                leaves
                    .iter()
                    .find(|(k, _)| *k == parity_key(3))
                    .map(|(_, h)| *h)
                    .unwrap(),
            ),
            (parity_key(99), EMPTY_LEAF),
        ];
        t.sort_unstable_by_key(|(k, _)| *k);
        assert_eq!(proof.root(&CC, &t), root);
    }

    fn hex(b: &[u8]) -> alloc::string::String {
        use core::fmt::Write;
        let mut s = alloc::string::String::new();
        for x in b {
            let _ = write!(s, "{x:02x}");
        }
        s
    }

    #[test]
    fn empty_tree_root_is_the_top_of_the_empty_chain() {
        let chain = empty_chain(&CC);
        let leaves: Vec<([u8; 16], [u8; 32])> = Vec::new();
        assert_eq!(root_of_sorted(&CC, &leaves), chain[CC.depth()]);
    }

    #[test]
    fn single_leaf_root_equals_spine_hash() {
        let k = key16(1);
        let h = leaf_hash(&CC, b"content");
        let chain = empty_chain(&CC);
        let root = root_of_sorted(&CC, &[(k, h)]);
        assert_eq!(root, spine_hash(&CC, &chain, &k, h, 0, CC.depth()));
    }

    #[test]
    fn root_is_insertion_order_independent_and_width_generic() {
        for p in [CC, SmtParams::vos(8), SmtParams::vos(2)] {
            let mk = |i: u64| -> Vec<u8> {
                let h = blake2b_hash::<32>(b"k", &[&i.to_le_bytes()]);
                h[..p.width].to_vec()
            };
            let mut leaves: Vec<(Vec<u8>, [u8; 32])> = (0..40u64)
                .map(|i| (mk(i), leaf_hash(&p, &i.to_le_bytes())))
                .collect();
            leaves.sort_unstable();
            leaves.dedup_by(|a, b| a.0 == b.0);
            let root = root_of_sorted(&p, &leaves);
            leaves.reverse();
            leaves.sort_unstable();
            assert_eq!(root_of_sorted(&p, &leaves), root);
        }
    }

    #[test]
    fn smt_proof_verifies_inclusion_and_non_inclusion() {
        let leaves = sorted_leaves(20);
        let root = root_of_sorted(&CC, &leaves);
        let chain = empty_chain(&CC);

        // Inclusion: rebuild each sibling from the reference recursion.
        let target = leaves[7];
        let mut siblings = Vec::new();
        for depth in 0..CC.depth() {
            let level = CC.depth() - 1 - depth;
            // Sibling subtree = leaves matching target's prefix above
            // `level` with the opposite bit at `level`.
            let sib: Vec<([u8; 16], [u8; 32])> = leaves
                .iter()
                .filter(|(k, _)| {
                    (0..level).all(|l| level_bit(k, l) == level_bit(&target.0, l))
                        && level_bit(k, level) != level_bit(&target.0, level)
                })
                .copied()
                .collect();
            siblings.push(sparse_root_sorted(&CC, &sib, level + 1, depth, &chain));
        }
        let proof = SmtProof {
            key: target.0.to_vec(),
            leaf: target.1,
            siblings: siblings.clone(),
        };
        assert!(proof.is_inclusion());
        assert!(proof.verify(&CC, &root));

        // A tampered leaf fails.
        let bad = SmtProof {
            leaf: leaf_hash(&CC, b"forged"),
            ..proof
        };
        assert!(!bad.verify(&CC, &root));
    }

    #[test]
    fn batch_proof_reconstructs_root_and_tracks_updates() {
        let leaves = sorted_leaves(64);
        let root_before = root_of_sorted(&CC, &leaves);

        // Touch three present keys, one absent.
        let absent = key16(1_000);
        let mut touched_keys: Vec<[u8; 16]> =
            vec![leaves[3].0, leaves[40].0, leaves[63].0, absent];
        touched_keys.sort_unstable();
        let key_refs: Vec<&[u8]> = touched_keys.iter().map(|k| k.as_slice()).collect();
        let proof = BatchProof::build(&CC, &leaves, &key_refs);

        let touched_before: Vec<([u8; 16], [u8; 32])> = touched_keys
            .iter()
            .map(|k| {
                let h = leaves
                    .iter()
                    .find(|(lk, _)| lk == k)
                    .map(|(_, h)| *h)
                    .unwrap_or(EMPTY_LEAF);
                (*k, h)
            })
            .collect();
        assert_eq!(proof.root(&CC, &touched_before), root_before);

        // Update two, insert the absent one, remove one — the same
        // frontier must produce exactly the full-recompute root.
        let mut after = touched_before.clone();
        for (k, h) in after.iter_mut() {
            if *k == absent {
                *h = leaf_hash(&CC, b"inserted");
            } else if *k == leaves[3].0 {
                *h = EMPTY_LEAF; // removed
            } else {
                *h = leaf_hash(&CC, b"updated");
            }
        }
        let recomputed = proof.root(&CC, &after);

        let mut full_after: Vec<([u8; 16], [u8; 32])> = leaves
            .iter()
            .filter(|(k, _)| *k != leaves[3].0)
            .map(|(k, h)| {
                let nh = after
                    .iter()
                    .find(|(tk, _)| tk == k)
                    .map(|(_, h)| *h)
                    .unwrap_or(*h);
                (*k, nh)
            })
            .collect();
        full_after.push((absent, leaf_hash(&CC, b"inserted")));
        full_after.sort_unstable_by_key(|(k, _)| *k);
        assert_eq!(recomputed, root_of_sorted(&CC, &full_after));
        assert_ne!(recomputed, root_before);
    }

    #[test]
    fn batch_proof_rejects_a_forged_untouched_branch() {
        let leaves = sorted_leaves(32);
        let root = root_of_sorted(&CC, &leaves);
        let touched = [leaves[0].0];
        let key_refs: Vec<&[u8]> = touched.iter().map(|k| k.as_slice()).collect();
        let mut proof = BatchProof::build(&CC, &leaves, &key_refs);
        // Corrupt one frontier hash: the reconstructed root must shift.
        proof.frontier[0].hash[0] ^= 1;
        let t = [(leaves[0].0, leaves[0].1)];
        assert_ne!(proof.root(&CC, &t), root);
    }
}
