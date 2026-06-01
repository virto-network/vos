//! Composite SMT root computation. Mirrors
//! `cipher_clerk::helpers::MemLedger::root`'s shape:
//! `smt_node_hash(smt_node_hash(accounts_root, transfers_root),
//! journals_root)`. The recursion is allocation-free so it fits in
//! the 64 KB PVM actor heap — see `smt_root_alloc_free` for the
//! algorithmic detail.

use alloc::vec::Vec;
use cipher_clerk::merkle::{SMT_DEPTH, build_empty_chain, smt_leaf_hash, smt_node_hash};
use cipher_clerk::types::{Account as CcAccount, Journal as CcJournal, Transfer as CcTransfer};

// Byte-equivalent to `cipher_clerk::helpers::{account,transfer,
// journal}_leaf_content`, which is feature-gated (`helpers` →
// `signing` → `rand_core/getrandom`) and therefore unavailable to
// the no_std PVM actor. The pure-rkyv path here doesn't need any
// of that. Encoding: 1-byte LEAF_KIND tag (domain separator
// distinguishing account/transfer/journal SMTs even though their
// id spaces could in principle collide) followed by the rkyv
// archive bytes.
//
// The host-side test `smt_root_matches_mem_ledger_for_same_content`
// pins byte equality against `cipher_clerk::helpers::MemLedger`,
// so any upstream change to the leaf shape surfaces there loudly.
const LEAF_ACCOUNT: u8 = 0;
const LEAF_TRANSFER: u8 = 1;
const LEAF_JOURNAL: u8 = 2;

fn account_leaf_content(a: &CcAccount) -> Vec<u8> {
    let archive = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(a)
        .expect("Account rkyv archive must succeed");
    let mut out = Vec::with_capacity(archive.len() + 1);
    out.push(LEAF_ACCOUNT);
    out.extend_from_slice(archive.as_ref());
    out
}

fn transfer_leaf_content(t: &CcTransfer) -> Vec<u8> {
    let archive = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(t)
        .expect("Transfer rkyv archive must succeed");
    let mut out = Vec::with_capacity(archive.len() + 1);
    out.push(LEAF_TRANSFER);
    out.extend_from_slice(archive.as_ref());
    out
}

fn journal_leaf_content(j: &CcJournal) -> Vec<u8> {
    let archive = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(j)
        .expect("Journal rkyv archive must succeed");
    let mut out = Vec::with_capacity(archive.len() + 1);
    out.push(LEAF_JOURNAL);
    out.extend_from_slice(archive.as_ref());
    out
}

/// Composite SMT root over (accounts, transfers, journal). Mirrors
/// `cipher_clerk::helpers::MemLedger::root`'s shape:
/// `smt_node_hash(smt_node_hash(accounts_root, transfers_root),
/// journals_root)`.
///
/// Why not just call `cipher_clerk::merkle::SparseMerkleTree::root`?
/// It walks the SMT by repeatedly splitting the leaves' `BTreeMap`
/// at each bit position, allocating two fresh `BTreeMap`s per
/// level — 128 levels for 128-bit SMTs. Inside the PVM actor's
/// 64 KB heap, the cumulative allocation pressure (plus
/// fragmentation) OOMs even a single-leaf SMT. This local impl
/// builds a sorted `Vec<([u8;16], [u8;32])>` once per sub-tree,
/// then recurses by slice index (`partition_point` for the split
/// per bit) with zero further allocations.
///
/// Byte-equivalent output to MemLedger's algorithm, pinned by the
/// `smt_root_matches_mem_ledger_for_same_content` host unit test.
pub(crate) fn compute_state_root(
    accounts: &[CcAccount],
    transfers: &[CcTransfer],
    journal: Option<&CcJournal>,
) -> [u8; 32] {
    // Empty-subtree cache: 128 + 1 precomputed empty-tree hashes,
    // one per depth-from-leaf. Built once per root() call (it's
    // not heap-allocated — `[[u8; 32]; 129]` is ~4 KB on the
    // stack), shared across all three sub-trees.
    let empty_chain = build_empty_chain();

    // Build sorted (key, leaf_hash) Vec per kind. `accounts` /
    // `transfers` are already sorted by id (LedgerView's
    // binary-search-based put_* invariant), so we can collect
    // in-order. Journal contributes at most one leaf.
    let mut accounts_leaves: Vec<([u8; 16], [u8; 32])> = Vec::with_capacity(accounts.len());
    for a in accounts.iter() {
        accounts_leaves.push((a.id.0, smt_leaf_hash(&account_leaf_content(a))));
    }
    let mut transfers_leaves: Vec<([u8; 16], [u8; 32])> = Vec::with_capacity(transfers.len());
    for t in transfers.iter() {
        transfers_leaves.push((t.id.0, smt_leaf_hash(&transfer_leaf_content(t))));
    }
    let mut journals_leaves: Vec<([u8; 16], [u8; 32])> = Vec::with_capacity(1);
    if let Some(j) = journal {
        journals_leaves.push((j.id.0, smt_leaf_hash(&journal_leaf_content(j))));
    }

    let accounts_root = smt_root_alloc_free(&accounts_leaves, 0, SMT_DEPTH, &empty_chain);
    let transfers_root = smt_root_alloc_free(&transfers_leaves, 0, SMT_DEPTH, &empty_chain);
    let journals_root = smt_root_alloc_free(&journals_leaves, 0, SMT_DEPTH, &empty_chain);

    smt_node_hash(
        &smt_node_hash(&accounts_root, &transfers_root),
        &journals_root,
    )
}

/// Sparse Merkle Tree root over a slice of sorted `(key, leaf_hash)`
/// pairs. Recurses depth-first by bit position, splitting the slice
/// via `partition_point` at each level — zero intermediate
/// allocations.
///
/// `sorted_leaves` MUST be ascending by key. Within any subtree (a
/// fixed bit-prefix), the leaves remain ascending, so
/// `partition_point` correctly splits by the next bit at every
/// level (bit-0 keys appear before bit-1 keys in ascending byte
/// order).
///
/// Stack frames bounded by `SMT_DEPTH = 128`. Each frame holds:
/// two `&[(...)]` slice refs (24 bytes each), three usize args,
/// and the `&empty_cache` ref. ~80 bytes per frame → ~10 KB peak
/// stack, well under the PVM stack budget.
fn smt_root_alloc_free(
    sorted_leaves: &[([u8; 16], [u8; 32])],
    prefix_bit_from_root: usize,
    depth_from_leaf: usize,
    empty_cache: &[[u8; 32]; SMT_DEPTH + 1],
) -> [u8; 32] {
    if sorted_leaves.is_empty() {
        return empty_cache[depth_from_leaf];
    }
    if depth_from_leaf == 0 {
        // Single-leaf subtree at this position. The kernel never
        // creates duplicate-key entries, so multiple leaves at
        // depth 0 would be a state-corruption bug; defensively
        // pick the first.
        return sorted_leaves[0].1;
    }
    let byte_idx = prefix_bit_from_root / 8;
    let bit_idx = 7 - (prefix_bit_from_root % 8);
    let split = sorted_leaves.partition_point(|(k, _)| (k[byte_idx] >> bit_idx) & 1 == 0);
    let (left, right) = sorted_leaves.split_at(split);
    let l = smt_root_alloc_free(
        left,
        prefix_bit_from_root + 1,
        depth_from_leaf - 1,
        empty_cache,
    );
    let r = smt_root_alloc_free(
        right,
        prefix_bit_from_root + 1,
        depth_from_leaf - 1,
        empty_cache,
    );
    smt_node_hash(&l, &r)
}
