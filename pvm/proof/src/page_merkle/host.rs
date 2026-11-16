//! The page tree built on the host: roots, multiproofs and the pages a segment touches, the prover's half.

use super::*;

/// `default_hashes()[ℓ]` = root of an all-zero (absent) subtree at level `ℓ`;
/// `[DEPTH]` is the empty leaf, `[0]` is the empty-tree root.
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

/// Map of page index → leaf hash for every page that differs from the default
/// (i.e. has at least one non-zero byte) in a flat image.
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

fn sparse_image_leaves(image: &crate::SparseMemoryImage) -> BTreeMap<u32, [u8; 32]> {
    image
        .pages()
        .iter()
        .map(|page| (page.page_index, leaf_hash(&page.bytes)))
        .collect()
}

/// Root of the subtree rooted at `(level, node_idx)` given the non-default
/// leaf hashes of the whole tree.  Short-circuits all-default subtrees, so the
/// cost is `O(non-default pages × DEPTH)`.
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
pub fn sparse_root(leaves: &BTreeMap<u32, [u8; 32]>) -> [u8; 32] {
    subtree_root(0, 0, leaves)
}

/// Root of the full page tree for a flat image.
pub fn image_root(image: &[u8]) -> [u8; 32] {
    sparse_root(&nondefault_leaves(image))
}

/// Root of a canonical sparse non-zero-page image.
pub fn sparse_image_root(image: &crate::SparseMemoryImage) -> [u8; 32] {
    sparse_root(&sparse_image_leaves(image))
}

/// Build the boundary multiproof for a segment: `touched` is the set of page
/// indices the segment accessed, `entering`/`exiting` are the flat RAM images
/// at the segment's start/end.  The witness siblings are computed from
/// `entering` (untouched subtrees are identical in `exiting`).
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

/// Sparse-image counterpart to [`build_multiproof`].
pub fn build_sparse_multiproof(
    entering: &crate::SparseMemoryImage,
    exiting: &crate::SparseMemoryImage,
    touched: &BTreeSet<u32>,
) -> MerkleMultiproof {
    build_multiproof_from_leaves(
        &sparse_image_leaves(entering),
        &sparse_image_leaves(exiting),
        touched,
    )
}

/// Core multiproof builder over non-default leaf maps (page index → leaf
/// hash).  `before`/`after` must agree on every page outside `touched`
/// (the soundness condition the in-circuit ledger enforces); witness siblings
/// are taken from `before`.
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
/// — step reads/writes, witness-input writes and BLAKE2b mem-ops — mapped to page
/// granularity.  This is the single source of truth the ledger's per-page
/// boundary injection and the boundary multiproof must agree on; it enumerates
/// exactly the address sources that [`crate::chips::memory`]'s ledger builder
/// consumes.
pub fn touched_pages(side_note: &crate::side_note::SideNote) -> BTreeSet<u32> {
    let mut pages = BTreeSet::new();
    for step in &side_note.steps {
        if let Some(ref r) = step.mem_read {
            add_range(&mut pages, r.address, r.size as u32);
        }
        if let Some(ref w) = step.mem_write {
            add_range(&mut pages, w.address, w.size as u32);
        }
        if let Some(ref w) = step.witness {
            add_range(&mut pages, w.address, w.bytes.len() as u32);
        }
    }
    for op in &side_note.blake2b_mem_ops {
        add_range(&mut pages, op.h_ptr, op.h_bytes.len() as u32);
        add_range(&mut pages, op.m_ptr, op.m_bytes.len() as u32);
        // out_bytes overwrite the h range — same pages.
    }
    for op in &side_note.poseidon2_ops {
        add_range(&mut pages, op.in_ptr, op.input.len() as u32);
        add_range(&mut pages, op.out_ptr, op.output.len() as u32);
    }
    pages
}

/// Sparse-image counterpart to [`boundary_blake2b_calls`].
pub fn sparse_boundary_blake2b_calls(
    mp: &MerkleMultiproof,
    entering: &crate::SparseMemoryImage,
    exiting: &crate::SparseMemoryImage,
) -> (Vec<crate::chips::Blake2bCall>, Vec<u32>) {
    boundary_blake2b_calls_with(mp, |page| entering.page(page), |page| exiting.page(page))
}

/// Build the boundary multiproof for a segment from its side note: enumerate
/// the touched pages (always including page 0, so the listed set is never
/// empty and the in-circuit chips stay unconditionally active), take the
/// entering image (`side_note.initial_memory`, already threaded by
/// `segment_side_note`) and the exit image (`replay_writes(.., None)`), and
/// recompute both roots.
pub fn segment_multiproof(side_note: &crate::side_note::SideNote) -> MerkleMultiproof {
    let mut touched = touched_pages(side_note);
    touched.insert(0); // never-empty page set (design §0)
    match &side_note.sparse_initial_memory {
        Some(entering) => {
            let exiting = crate::segment::replay_sparse_writes(side_note, None);
            build_sparse_multiproof(entering, &exiting, &touched)
        }
        None => {
            let exiting = crate::segment::replay_writes(side_note, None);
            build_multiproof(&side_note.initial_memory, &exiting, &touched)
        }
    }
}
