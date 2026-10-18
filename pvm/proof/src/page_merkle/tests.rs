use super::*;

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
fn page_domains_remain_stable_across_v10_through_v19() {
    assert_eq!(
        leaf_hash(&[0u8; PAGE_SIZE]),
        hex_to_32("fd2c1ac593371c52c7fb0dc8fce568b2edea3cc192ca663a07fed4cd714f8fa3"),
    );
    assert_eq!(
        default_hashes()[0],
        hex_to_32("dbc4371ac97d12de7d3e4e3ead46e41971eae7c94206e9fa4188d30349aceecc"),
    );
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

fn sparse_image_from_dense(image: &[u8]) -> crate::SparseMemoryImage {
    let pages = image
        .chunks(PAGE_SIZE)
        .enumerate()
        .filter_map(|(page_index, chunk)| {
            if chunk.iter().all(|&byte| byte == 0) {
                return None;
            }
            let mut bytes = [0; PAGE_SIZE];
            bytes[..chunk.len()].copy_from_slice(chunk);
            Some(crate::SparseMemoryPage {
                page_index: page_index as u32,
                bytes,
            })
        })
        .collect();
    crate::SparseMemoryImage::new(image.len() as u64, pages).unwrap()
}

#[test]
fn dense_and_sparse_images_have_identical_roots_and_multiproofs() {
    let entering = make_image(&[(1, 0x11), (2, 0x22), (19, 0x33)]);
    let mut exiting = entering.clone();
    exiting[2 * PAGE_SIZE + 7] ^= 0x5a;
    exiting[8 * PAGE_SIZE + 3] = 0x44;
    let sparse_entering = sparse_image_from_dense(&entering);
    let sparse_exiting = sparse_image_from_dense(&exiting);
    let touched: BTreeSet<u32> = [2, 8].into_iter().collect();

    assert_eq!(image_root(&entering), sparse_image_root(&sparse_entering));
    assert_eq!(image_root(&exiting), sparse_image_root(&sparse_exiting));
    let dense = build_multiproof(&entering, &exiting, &touched);
    let sparse = build_sparse_multiproof(&sparse_entering, &sparse_exiting, &touched);
    assert_eq!(dense.leaves, sparse.leaves);
    assert_eq!(dense.merges, sparse.merges);
    assert_eq!(dense.root_before, sparse.root_before);
    assert_eq!(dense.root_after, sparse.root_after);
}

#[test]
fn sparse_image_root_and_multiproof_handle_the_last_guest_page() {
    let span = 1u64 << 32;
    let page_index = (1u32 << DEPTH) - 1;
    let entering = crate::SparseMemoryImage::new(span, Vec::new()).unwrap();
    let mut page = crate::SparseMemoryPage {
        page_index,
        bytes: [0; PAGE_SIZE],
    };
    page.bytes[PAGE_SIZE - 1] = 0x7f;
    let exiting = crate::SparseMemoryImage::new(span, vec![page]).unwrap();
    let touched: BTreeSet<u32> = [page_index].into_iter().collect();
    let proof = build_sparse_multiproof(&entering, &exiting, &touched);

    assert_eq!(proof.root_before, sparse_image_root(&entering));
    assert_eq!(proof.root_after, sparse_image_root(&exiting));
    assert_ne!(proof.root_before, proof.root_after);
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
/// agrees with the pages the ledger's accesses touch, and
/// that `segment_multiproof` recomputes the entering/exit image roots.
#[test]
fn touched_pages_match_ledger_and_segment_multiproof_round_trips() {
    use crate::core::tracing::TracingPvm;
    use vos_pvm::PVM_REGISTER_COUNT;
    use vos_pvm::instruction::Opcode;
    use vos_pvm::interpreter::Interpreter;

    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0x42; // value to store
    regs[1] = 0x1_0000; // first address above the protected low zone (page 16)
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
    );
    let mut tr = TracingPvm::new(pvm);
    assert_eq!(tr.run(), vos_pvm::ExitReason::Panic);
    let steps = tr.into_trace();
    let sn = crate::side_note::SideNote::new(steps, code, bitmask);

    // The store/load both hit address 0x1_0000 → page 16.
    let pages = touched_pages(&sn);
    assert!(
        pages.contains(&16),
        "expected page 16 (addr 0x1_0000) touched"
    );

    // The pages are the ledger's: every page an access touches.
    let ledger_pages: BTreeSet<u32> = crate::chips::memory::access_entries(&sn)
        .iter()
        .map(|e| e.address / PAGE_SIZE as u32)
        .collect();
    assert_eq!(
        pages, ledger_pages,
        "touched_pages disagrees with the ledger's pages"
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
    // must equal the full-message blake2b256(LEAF_TAG ‖ page).
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
    assert_eq!(
        counts.len(),
        calls.len(),
        "every distinct raw call survives"
    );
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
    Blake2bBoundaryChip.draw_lookup_elements(&mut all, channel.into());
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
        v.extend(
            c.t.to_le_bytes()[..8]
                .iter()
                .map(|&b| BaseField::from(b as u32)),
        );
        v.push(BaseField::from(c.f as u32));
        v.extend(replay(c).map(|b| BaseField::from(b as u32)));
        <Blake2bCompressionLookupElements as Relation<BaseField, SecureField>>::combine(
            el,
            v.as_slice(),
        )
        .inverse()
    };
    let consumed = raw
        .iter()
        .map(&inv_denom)
        .fold(SecureField::default(), |a, f| a + f);
    let produced = calls
        .iter()
        .zip(&mults)
        .map(|(c, &m)| inv_denom(c) * BaseField::from(m))
        .fold(SecureField::default(), |a, f| a + f);
    assert_eq!(
        produced, consumed,
        "deduped productions must cancel the consumptions"
    );

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
