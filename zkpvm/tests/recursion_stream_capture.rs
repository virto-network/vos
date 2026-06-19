//! Recursion build P5.3 task #1 — symbolic-capture fidelity for the streamed
//! emission.
//!
//! The streamed `OodsEval` cannot bind operands eagerly at offset 0 (the existing
//! `VerifyBackend` does, which is why it can't stream); it must capture each
//! product's two operands as SYMBOLIC linear forms (`Σ coeff·node + Σ d·latched +
//! const`) so the read of each node can later be deferred to the consuming
//! product's row at the scheduled offset. `StreamBackend` captures exactly that
//! while computing concrete values (like `MultiRecordBackend`).
//!
//! This validates the capture is FAITHFUL — host-only, no proving:
//!   * every operand form's carried value equals its symbolic re-evaluation over
//!     the captured node/latched values (the in-AIR reconstruction reproduces it);
//!   * every product node = a·b;
//!   * the final DEEP-ALI equality `lhs == rhs` holds and equals the global
//!     composition (the same `PointEvaluationAccumulator` ground truth as
//!     oods_auto_join31).
//!
//! Run: `cargo test -p zkpvm --test recursion_stream_capture -- --nocapture`

mod recursion_common;

use recursion_common::oods_auto::StreamNode;
use recursion_common::synth::{build_capture, synthetic_setup};

const L: u32 = 4; // each component's synthetic log_size

/// GATE: the captured symbolic forms faithfully reconstruct every value, every
/// product is a·b, and the final equality reproduces the global composition.
#[test]
fn stream_capture_fidelity() {
    let s = synthetic_setup(L);
    let capture = build_capture(&s);

    let n_nodes = capture.node_kind.len();
    let mut n_mask = 0usize;
    let mut n_product = 0usize;
    let mut max_node_terms = 0usize;
    let mut max_latched_terms = 0usize;

    for (id, kind) in capture.node_kind.iter().enumerate() {
        match kind {
            StreamNode::Mask => n_mask += 1,
            StreamNode::Product { a, b } => {
                n_product += 1;
                // Each operand form reconstructs its own carried value …
                assert_eq!(
                    a.value,
                    capture.eval_form(a),
                    "product {id}: operand a form value != symbolic eval"
                );
                assert_eq!(
                    b.value,
                    capture.eval_form(b),
                    "product {id}: operand b form value != symbolic eval"
                );
                // … and the product node is exactly a·b.
                assert_eq!(
                    capture.node_value[id],
                    a.value * b.value,
                    "product {id}: node value != a·b"
                );
                max_node_terms = max_node_terms.max(a.nodes.len()).max(b.nodes.len());
                max_latched_terms = max_latched_terms.max(a.latched.len()).max(b.latched.len());
            }
        }
    }

    // The final DEEP-ALI equality holds and equals the global composition.
    let lhs = capture.eval_form(&capture.final_lhs);
    let rhs = capture.eval_form(&capture.final_rhs);
    assert_eq!(lhs, rhs, "final lhs != rhs (DEEP-ALI equality)");
    assert_eq!(
        lhs, s.truth,
        "streamed capture composition != global PointEvaluationAccumulator"
    );

    eprintln!(
        "stream_capture_fidelity GREEN: {n_nodes} nodes ({n_mask} masks + {n_product} products); \
         every operand form reconstructs its value, every product = a·b, and the final equality \
         reproduces the global composition {:?}. Max operand form size: {max_node_terms} node \
         terms + {max_latched_terms} latched terms (the per-product preprocessed-coeff width).",
        s.truth,
    );

    assert!(
        n_product > 20_000,
        "expected ~23294 products, got {n_product}"
    );
    assert_eq!(n_mask + n_product, n_nodes);
}

/// Ops per streamed row (the embed density knob — the bounded offset window is in
/// rows = max cell reach / OPS_PER_ROW).
const OPS_PER_ROW: usize = 8;

/// GATE: the capture compiles to a micro-op SCHEDULE whose host interpreter
/// reproduces every captured product value and the global composition — and
/// MEASURE the streamed layout vs `terms_per_mac` (cells, op mix, rows, window
/// reach). The reach (in rows) is the dense-coeff window depth the AIR mask
/// needs; a higher `terms_per_mac` shortens the Mac chains, packing products
/// denser and cutting the reach (the constraint stays degree 2 regardless of the
/// nonzero count). This is the host reference the streamed AIR must reproduce; no
/// proving yet.
#[test]
fn stream_schedule_fidelity() {
    let s = synthetic_setup(L);
    let capture = build_capture(&s);

    eprintln!(
        "stream_schedule_fidelity GREEN (OPS_PER_ROW={OPS_PER_ROW}): the interpreter reproduces \
         the global composition for every terms_per_mac; reach (rows) is the AIR mask window depth.\n  \
         {:>4}  {:>8}  {:>7} {:>7} {:>7}  {:>6} {:>4}  {:>7} {:>5}",
        "T/mac", "cells", "leaf", "mac", "mul", "rows", "log", "reach_c", "rows",
    );

    for &t in &[2usize, 4, 8, 16, 32, 64, 128, 256] {
        let sched = capture.schedule(t);

        // The interpreter (re-evaluating ops from scratch) matches the stored values.
        let interp = sched.interpret();
        assert_eq!(interp.len(), sched.values.len());
        for (i, (a, b)) in interp.iter().zip(&sched.values).enumerate() {
            assert_eq!(a, b, "T={t} cell {i}: interpreter != stored value");
        }
        assert_eq!(
            interp[sched.lhs_cell], interp[sched.rhs_cell],
            "T={t} scheduled final lhs != rhs"
        );
        assert_eq!(
            interp[sched.lhs_cell], s.truth,
            "T={t} scheduled composition != global PointEvaluationAccumulator"
        );

        let n_cells = sched.ops.len();
        let rows = n_cells.div_ceil(OPS_PER_ROW);
        let log = (usize::BITS - rows.next_power_of_two().leading_zeros()).saturating_sub(1);
        let reach_cells = sched.max_reach();
        let reach_rows = reach_cells.div_ceil(OPS_PER_ROW);
        eprintln!(
            "  {t:>4}  {n_cells:>8}  {:>7} {:>7} {:>7}  {rows:>6} {log:>4}  {reach_cells:>7} {reach_rows:>5}",
            sched.n_leaf, sched.n_mac, sched.n_mul,
        );

        assert!(n_cells > 0 && reach_cells > 0);
    }
}
