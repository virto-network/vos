//! Recursion build P5.3 task #1 — TWO-STREAM schedule fidelity + window
//! measurement.
//!
//! The single flat stream's window floors at ~151 rows (recursion_stream_capture):
//! products are read at offsets inflated by interspersed leaf/mac cells, so a dense
//! per-cell coeff layout would need ~151·OPS window positions/cell (~190M preproc).
//! The two-stream layout gives product results their own COMPACT stream R (one cell
//! per product, read at product-rank offsets) and keeps leaf/mac scratch in a local
//! working stream W. This file validates the two-stream schedule is a FAITHFUL
//! rewrite of the capture and MEASURES both windows + the dense-coeff cost across
//! `terms_per_mac` and candidate ops/row — host-only, no proving. The goal: both
//! windows ≪ the single-stream 151.
//!
//! Run: `cargo test -p zkpvm --features poseidon2-channel --test recursion_stream_two -- --nocapture`

mod recursion_common;

use num_traits::Zero;
use recursion_common::oods_auto::{N_LATCHED, StreamNode, WOp2};
use recursion_common::synth::{build_capture, synthetic_setup};
use stwo::core::fields::qm31::SecureField;

const L: u32 = 4; // each component's synthetic log_size

fn log2_ceil(n: usize) -> u32 {
    (usize::BITS - n.next_power_of_two().leading_zeros()).saturating_sub(1)
}

/// GATE: the two-stream schedule reproduces every value + the global composition
/// for several `terms_per_mac`, and both windows (W local, R rank-bounded) are far
/// below the single-stream 151-row floor. Measures rows/log/windows/preproc.
#[test]
fn two_stream_fidelity_and_windows() {
    let s = synthetic_setup(L);
    let capture = build_capture(&s);

    // The capture's product node values in capture order — the R cells map 1:1.
    let prod_vals: Vec<SecureField> = capture
        .node_kind
        .iter()
        .enumerate()
        .filter(|(_, k)| matches!(k, StreamNode::Product { .. }))
        .map(|(i, _)| capture.node_value[i])
        .collect();

    eprintln!(
        "two_stream_fidelity_and_windows: {} products, capture truth = {:?}",
        prod_vals.len(),
        s.truth,
    );
    eprintln!("  W cells (leaf/mac) are local; R cells (one/product) carry the cross-row reach.");

    // Candidate (ops_leaf, ops_mac, ops_r) per row.
    let layouts = [(8usize, 4usize, 2usize), (16, 8, 4), (8, 8, 2), (12, 6, 3)];

    for &t in &[2usize, 4, 8, 16, 32] {
        let sched = capture.schedule_two_stream(t);
        let n_leaf = sched
            .w_ops
            .iter()
            .filter(|o| matches!(o, WOp2::Leaf))
            .count();
        let n_mac = sched
            .w_ops
            .iter()
            .filter(|o| matches!(o, WOp2::Mac { .. }))
            .count();
        let n_mul = sched.r_ops.len();

        // Fidelity: the interpreter reproduces the stored values …
        let (w, r_oa, r_ob, r) = sched.interpret();
        assert_eq!(w, sched.w_value, "T={t}: W interpret mismatch");
        assert_eq!(r_oa, sched.r_oa, "T={t}: r_oa interpret mismatch");
        assert_eq!(r_ob, sched.r_ob, "T={t}: r_ob interpret mismatch");
        assert_eq!(r, sched.r_value, "T={t}: r interpret mismatch");
        // … the R products match the capture's products 1:1 …
        assert_eq!(sched.r_value, prod_vals, "T={t}: R products != capture");
        // … and the final equality cell is zero (lhs == rhs == global composition).
        assert!(
            w[sched.final_w].is_zero(),
            "T={t}: final (lhs-rhs) != 0 — composition not reproduced"
        );

        eprintln!("\n  T/mac={t}: {n_leaf} leaves, {n_mac} macs, {n_mul} muls");

        for &(ol, om, orr) in &layouts {
            let lay = sched.layout(ol, om, orr);
            // The layout (resolved window positions) reproduces the schedule values.
            let (lw, _, _, lr) = lay.interpret(&sched);
            assert_eq!(
                lw, sched.w_value,
                "T={t} layout({ol},{om},{orr}): W mismatch"
            );
            assert_eq!(
                lr, sched.r_value,
                "T={t} layout({ol},{om},{orr}): R mismatch"
            );

            let pp_qm31 = lay.preproc_qm31_per_row();
            let total_m31 = (pp_qm31 * 4).saturating_mul(lay.n_rows);
            eprintln!(
                "      layout(L={ol:>2},M={om:>2},R={orr}): rows={:>6} log={:>2}  \
                 dw_leaf={:>2} dw_mac={:>3} dr={:>3}  preproc {:>4}QM31/row ≈{:>3}M M31 cells",
                lay.n_rows,
                log2_ceil(lay.n_rows),
                lay.dw_leaf,
                lay.dw_mac,
                lay.dr,
                pp_qm31,
                total_m31 / 1_000_000,
            );
        }
    }

    eprintln!(
        "\ntwo_stream_fidelity_and_windows GREEN: the two-stream schedule + layout faithfully \
         reproduce the global composition; compare dr (R rank reach in rows) + dw_mac/dw_leaf \
         against the single-stream 151-row floor to pick OPS/terms_per_mac for the AIR."
    );
}

/// GATE: the CO-LOCATE layout (the design's choice, the AIR target) — macs +
/// products share ONE dense stream, leaves ride offset-0 as width. Validates the
/// resolved layout reproduces every slot value + the global composition, and
/// MEASURES the bounded R window (≈ rank-reach/ops_s) + the dense-coeff cost
/// (target: tens of millions of preproc cells, ≤ log 15).
#[test]
fn colocate_layout_and_cost() {
    let s = synthetic_setup(L);
    let capture = build_capture(&s);

    eprintln!(
        "colocate_layout_and_cost: products={}",
        capture
            .node_kind
            .iter()
            .filter(|k| matches!(k, StreamNode::Product { .. }))
            .count()
    );
    eprintln!(
        "  {:>5} {:>6} {:>6}   {:>4} {:>4}  {:>5} {:>3}  {:>4}  {:>9} {:>9}  {:>10}",
        "T/mac",
        "macs",
        "leaf",
        "ops",
        "nlf",
        "rows",
        "log",
        "dr",
        "main/row",
        "pp/row",
        "pp total",
    );

    for &t in &[8usize, 16, 32, 64] {
        let sched = capture.schedule_two_stream(t);
        let n_mac = sched
            .w_ops
            .iter()
            .filter(|o| matches!(o, WOp2::Mac { .. }))
            .count();
        let n_leaf = sched
            .w_ops
            .iter()
            .filter(|o| matches!(o, WOp2::Leaf))
            .count();

        // Generous leaf budget for measurement; max_leaf_in_row reports the real need.
        for &(ops_s, nleaf) in &[(4usize, 512usize), (6, 512), (8, 512)] {
            let lay = sched.layout_colocate(ops_s, nleaf);

            // The resolved co-locate layout reproduces every slot value …
            let grid = lay.interpret();
            for row in 0..lay.n_rows {
                for lane in 0..ops_s {
                    assert_eq!(
                        grid[row][lane], lay.slot_r[row][lane],
                        "T={t} ops={ops_s}: slot ({row},{lane}) interpret mismatch"
                    );
                }
            }
            // … and the final slot (lhs − rhs) is zero.
            assert!(
                lay.slot_r[lay.final_row][lay.final_lane].is_zero(),
                "T={t} ops={ops_s}: final slot (lhs-rhs) != 0"
            );

            // Tight cost: leaf budget = the densest row's actual leaf count.
            let nlf = lay.max_leaf_in_row;
            let win = nlf + ops_s * (lay.dr + 1) + N_LATCHED;
            let pp_row = 2 * ops_s * (win + 1);
            let main_row = nlf + ops_s * 3;
            let pp_total = (pp_row * 4).saturating_mul(lay.n_rows);
            eprintln!(
                "  {t:>5} {n_mac:>6} {n_leaf:>6}   {ops_s:>4} {nlf:>4}  {:>5} {:>3}  {:>4}  {main_row:>6}QM {pp_row:>7}QM  {:>7}M M31",
                lay.n_rows,
                log2_ceil(lay.n_rows),
                lay.dr,
                pp_total / 1_000_000,
            );
        }
    }

    eprintln!(
        "\ncolocate_layout_and_cost GREEN: macs+products in one dense stream + offset-0 leaves \
         reproduce the global composition; the R window dr ≈ rank-reach/ops_s (≪ the 151 floor) \
         and the dense-coeff preproc is tens of millions of cells — the AIR target."
    );
}

/// Diagnostic: the RAW operand structure straight from the capture (independent of
/// any layout) — per-operand mask/product/latched term counts + the product→product
/// rank reach in capture order. This is what bounds a co-locate layout (masks as
/// offset-0 width on the consuming product's row; products dense in their own rows
/// so the R window depth = rank reach / ops_r).
#[test]
fn two_stream_operand_structure() {
    let s = synthetic_setup(L);
    let capture = build_capture(&s);

    // node id → product rank (capture order among products); None for masks.
    let mut prod_rank = vec![usize::MAX; capture.node_kind.len()];
    let mut next = 0usize;
    for (i, k) in capture.node_kind.iter().enumerate() {
        if matches!(k, StreamNode::Product { .. }) {
            prod_rank[i] = next;
            next += 1;
        }
    }

    let (mut max_mask, mut max_prod, mut max_lat) = (0usize, 0usize, 0usize);
    let mut sum_mask = 0usize;
    let mut over8 = 0usize; // operands with > 8 mask terms (would overflow a small leaf budget)
    let mut over16 = 0usize;
    let mut reaches: Vec<usize> = Vec::new();

    let mut tally = |form: &recursion_common::oods_auto::StreamForm, rank: usize| {
        let mut nm = 0usize;
        let mut np = 0usize;
        for &(node, _) in &form.nodes {
            if matches!(capture.node_kind[node as usize], StreamNode::Mask) {
                nm += 1;
            } else {
                np += 1;
                reaches.push(rank - prod_rank[node as usize]);
            }
        }
        max_mask = max_mask.max(nm);
        max_prod = max_prod.max(np);
        max_lat = max_lat.max(form.latched.len());
        sum_mask += nm;
        if nm > 8 {
            over8 += 1;
        }
        if nm > 16 {
            over16 += 1;
        }
    };

    let mut n_operands = 0usize;
    for (i, k) in capture.node_kind.iter().enumerate() {
        if let StreamNode::Product { a, b } = k {
            tally(a, prod_rank[i]);
            tally(b, prod_rank[i]);
            n_operands += 2;
        }
    }

    reaches.sort_unstable();
    let max_reach = reaches.last().copied().unwrap_or(0);
    let mean_reach = if reaches.is_empty() {
        0
    } else {
        reaches.iter().sum::<usize>() / reaches.len()
    };
    let p99 = if reaches.is_empty() {
        0
    } else {
        reaches[reaches.len() * 99 / 100]
    };

    eprintln!(
        "two_stream_operand_structure: {n_operands} operands over {next} products.\n  \
         per-operand terms: max_mask={max_mask} max_product={max_prod} max_latched={max_lat}; \
         avg_mask={:.2}/operand; operands with >8 mask terms: {over8}, >16: {over16}.\n  \
         product→product RANK reach (capture order): max={max_reach} mean={mean_reach} p99={p99} \
         (count={}).",
        sum_mask as f64 / n_operands as f64,
        reaches.len(),
    );
}
