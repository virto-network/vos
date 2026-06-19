//! Recursion build P5.3 task #1 — capture the 31-component OODS DAG and cost the
//! two candidate streamed layouts, to PICK the layout before building emission.
//!
//! Task #0 found the full live-set (masks + products) is W ≈ 1700: the acc chain
//! serializes the constraints, so shared mask samples stay live across them — a
//! pure register-window layout would need ~1700 lanes (≈6800 M31/row).
//!
//! The alternative is the CO-LOCATE layout (what recursion_stream_scale modeled):
//! replicate each mask sample onto the rows that consume it (read at offset 0)
//! and keep only PRODUCT values in lanes, read cross-row. Masks are leaves, so
//! replicating them is cheap storage spread over rows; products are short-lived
//! (the Horner collapses each into the next step), so the product-only live-set
//! `W_p` — the real lane count for co-locate — should be far below 1700.
//!
//! This drives the [`GraphBackend`] over all 31 chips and measures, from the real
//! DAG: `W_p` (product-only live-set = co-locate lanes), the mask replication
//! (Σ mask uses), the per-product operand fan-in, and the product→product offset
//! reach. If `W_p` and the reach are small, co-locate is the layout.
//!
//! Run: `cargo test -p zkpvm --test recursion_stream_layout -- --nocapture`

mod recursion_common;

use recursion_common::oods_auto::{GraphBackend, drive_multi};
use std::cell::RefCell;
use std::rc::Rc;
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use zkpvm::chip_idx;
use zkpvm::framework_access::{AllLookupElements, draw_all_lookup_elements, drive_chip_oods};
use zkpvm::recursion_pcs::ProverChannel;

const L: u32 = 4;
const OPS_PER_ROW: usize = 3;

fn full_lookup() -> AllLookupElements {
    let mut lookup = AllLookupElements::default();
    let mut channel = ProverChannel::default();
    draw_all_lookup_elements(&mut lookup, &mut channel, (1u32 << chip_idx::COUNT) - 1);
    lookup
}

fn percentile(sorted: &[u32], p: f64) -> u32 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx]
}

/// Max simultaneously-live count over a set of `[birth, death]` intervals.
fn max_live(intervals: &[(u32, u32)], horizon: u32) -> u32 {
    if intervals.is_empty() {
        return 0;
    }
    let mut delta = vec![0i64; horizon as usize + 2];
    for &(b, d) in intervals {
        delta[b as usize] += 1;
        delta[d as usize + 1] -= 1;
    }
    let mut cur = 0i64;
    let mut max = 0i64;
    for x in delta {
        cur += x;
        if cur > max {
            max = cur;
        }
    }
    max as u32
}

#[test]
fn stream_layout() {
    let lookup = full_lookup();
    let comps: Vec<(usize, u32, SecureField)> = (0..chip_idx::COUNT)
        .map(|idx| {
            (
                idx,
                L,
                SecureField::from_u32_unchecked(7, 11, 13, 17 + idx as u32),
            )
        })
        .collect();

    let ctx = Rc::new(RefCell::new(GraphBackend::new()));
    drive_multi(&ctx, &comps, |idx, ls, e| {
        drive_chip_oods(idx, ls, &lookup, e)
    });
    let g = Rc::try_unwrap(ctx)
        .unwrap_or_else(|_| panic!("a Handle outlived the graph walk"))
        .into_inner();

    let n = g.nodes.len();
    let n_mask = g.n_mask();
    let n_prod = g.n_product();

    // ── Product-rank space: each product gets a row (masks replicate on-row) ──
    // rank[node] = its rank among products (u32::MAX for masks).
    let mut rank = vec![u32::MAX; n];
    let mut next_rank = 0u32;
    for (i, node) in g.nodes.iter().enumerate() {
        if !node.is_mask {
            rank[i] = next_rank;
            next_rank += 1;
        }
    }
    assert_eq!(next_rank as usize, n_prod);

    // Per product: operand fan-in (mask deps replicated on-row; product deps read
    // cross-row from lanes), and the product→product offset reach in rank space.
    let mut mask_fanin: Vec<u32> = Vec::with_capacity(n_prod);
    let mut prod_fanin: Vec<u32> = Vec::with_capacity(n_prod);
    let mut total_mask_uses: u64 = 0;
    let mut prod_offsets: Vec<u32> = Vec::new();
    // Product lifetimes in rank space: live from its own rank to its last consumer.
    let mut last_use = vec![0u32; n_prod];

    for (i, node) in g.nodes.iter().enumerate() {
        if node.is_mask {
            continue;
        }
        let my_rank = rank[i];
        last_use[my_rank as usize] = my_rank; // at least its own row
        let mut mf = 0u32;
        let mut pf = 0u32;
        for &d in &node.deps {
            if g.nodes[d as usize].is_mask {
                mf += 1;
            } else {
                pf += 1;
                let dr = rank[d as usize];
                prod_offsets.push(my_rank - dr);
                if my_rank > last_use[dr as usize] {
                    last_use[dr as usize] = my_rank;
                }
            }
        }
        mask_fanin.push(mf);
        prod_fanin.push(pf);
        total_mask_uses += mf as u64;
    }
    // The final DEEP-ALI equality consumes its product deps at the last row.
    let final_rank = n_prod as u32;
    for &d in &g.final_deps {
        if !g.nodes[d as usize].is_mask {
            let dr = rank[d as usize];
            prod_offsets.push(final_rank - dr);
            last_use[dr as usize] = final_rank;
        }
    }

    // Co-locate lane count W_p = product-only live-set (rank space).
    let prod_intervals: Vec<(u32, u32)> = (0..n_prod).map(|r| (r as u32, last_use[r])).collect();
    let w_p = max_live(&prod_intervals, final_rank);

    prod_offsets.sort_unstable();
    mask_fanin.sort_unstable();
    prod_fanin.sort_unstable();

    let max_offset = prod_offsets.last().copied().unwrap_or(0);
    let mean_fanin = |v: &[u32]| -> f64 {
        if v.is_empty() {
            0.0
        } else {
            v.iter().map(|&x| x as u64).sum::<u64>() as f64 / v.len() as f64
        }
    };

    // Co-locate storage: each product stored once + its mask deps replicated.
    let colocate_qm31 = n_prod as u64 + total_mask_uses;
    let colocate_rows = colocate_qm31.div_ceil(OPS_PER_ROW as u64).max(1);
    let colocate_log = (64 - (colocate_rows.next_power_of_two()).leading_zeros()).saturating_sub(1);
    // Per-row width: OPS_PER_ROW products, each storing 1 + mask_fanin QM31, plus
    // W_p product lanes (read at offset {0,-1}) + a few latched columns.
    let avg_per_prod = 1.0 + mean_fanin(&mask_fanin);
    let per_row_qm31 = OPS_PER_ROW as f64 * avg_per_prod + w_p as f64;

    eprintln!("\n=== P5.3 task #1: 31-component OODS DAG — layout costing ===\n");
    eprintln!("nodes: {n}  ({n_mask} mask samples + {n_prod} witnessed products)");

    eprintln!("\n-- CO-LOCATE layout (replicate masks on-row, products in lanes) --");
    eprintln!("  product-only live-set  W_p = {w_p}  ← the lane count (vs full-window W≈1700)",);
    eprintln!(
        "  mask replication: Σ mask uses = {total_mask_uses}  (avg {:.2}/product, max {})",
        mean_fanin(&mask_fanin),
        mask_fanin.last().copied().unwrap_or(0),
    );
    eprintln!(
        "  product fan-in (lanes read/product): mean {:.2}  p90 {}  p99 {}  max {}",
        mean_fanin(&prod_fanin),
        percentile(&prod_fanin, 0.90),
        percentile(&prod_fanin, 0.99),
        prod_fanin.last().copied().unwrap_or(0),
    );
    eprintln!(
        "  product→product offset reach (rank space): max {max_offset}  mean {:.1}  p50 {}  \
         p90 {}  p99 {}  p99.9 {}",
        mean_fanin(&prod_offsets),
        percentile(&prod_offsets, 0.50),
        percentile(&prod_offsets, 0.90),
        percentile(&prod_offsets, 0.99),
        percentile(&prod_offsets, 0.999),
    );
    eprintln!(
        "  storage ≈ {colocate_qm31} QM31 = {} M31; rows ≈ {colocate_rows} → log {colocate_log} \
         (OPS_PER_ROW={OPS_PER_ROW}); per-row width ≈ {per_row_qm31:.0} QM31 = {:.0} M31.",
        colocate_qm31 * SECURE_EXTENSION_DEGREE as u64,
        per_row_qm31 * SECURE_EXTENSION_DEGREE as f64,
    );

    eprintln!(
        "\nINTERPRETATION: co-locate needs only W_p={w_p} product lanes (read at offset {{0,-1}}) \
         plus on-row replicated masks — vs ~1700 lanes for a pure window. If W_p and the \
         product→product offset reach are small, co-locate is the streamed layout (narrow, \
         matching recursion_stream_scale's ~68 cols/row), and the StreamBackend lays products \
         in walk order with masks inlined onto consumer rows.\n"
    );

    assert!(n_prod > 20_000, "expected ~23294 products, got {n_prod}");
    assert!(w_p > 0, "expected a non-trivial product live-set");
}
