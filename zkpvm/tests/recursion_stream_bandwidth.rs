//! Recursion build P5.3 task #0 — measure the cross-row "bandwidth" of the flat
//! 31-component OODS schedule.
//!
//! The streamed OODS-embed layout (recursion-p5.md P5.3) distributes the ~40150
//! schedule nodes (mask samples + witnessed products) down the channel's ~16384
//! perm rows, the Horner accumulator chained cross-row. A streamed row computes a
//! handful of witnessed products, reading each product's operands from nearby
//! rows via fixed mask offsets (the offset spike proved offsets up to ~N/2 read
//! the exact logical row). This is VIABLE only if operands stay within a bounded
//! window `W`: the distinct offset set (≈ `W`) must be small, else the outer OODS
//! mask explodes.
//!
//! This measures `W` directly from the real flat schedule [`drive_multi`]
//! produces over all 31 chips: the max operand distance (how far back a witnessed
//! product reaches) and the live-set width (simultaneously-live nodes), both for
//! the naive order (the chips read every mask up front, `TraceEval::new`) and for
//! a lazy order that defers each mask read to its first use. If the naive
//! bandwidth is large but the lazy live-set is small, the streamed `OodsEval`
//! (task #1) must schedule mask reads lazily.
//!
//! No proving and no real OODS data: the schedule's shape is value-independent,
//! so the [`BandwidthBackend`] walks the chips' `evaluate` symbolically.
//!
//! Run: `cargo test -p zkpvm --test recursion_stream_bandwidth -- --nocapture`

mod recursion_common;

use recursion_common::oods_auto::{BandwidthBackend, drive_multi};
use std::cell::RefCell;
use std::rc::Rc;
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use zkpvm::chip_idx;
use zkpvm::framework_access::{AllLookupElements, draw_all_lookup_elements, drive_chip_oods};
use zkpvm::recursion_pcs::ProverChannel;

/// Synthetic per-component log_size — feeds only the logup `cumsum_shift`
/// (a constant); the schedule shape is independent of it.
const L: u32 = 4;

/// Ops (witnessed product + Horner fold) per streamed row — the embed density
/// the tractability measurement (recursion_stream_scale) picked.
const OPS_PER_ROW: usize = 3;

const CHIP_NAMES: [&str; 31] = [
    "CpuChip",
    "Blake2bChip",
    "Blake2bBoundaryChip",
    "MemoryChip",
    "MemoryPageChip",
    "MemoryMerkleChip",
    "MemoryRootBoundaryChip",
    "RegisterMemoryChip",
    "RegisterMemoryBoundaryChip",
    "RegisterMemoryClosingChip",
    "ProgramBoundaryChip",
    "ProgramMemoryChip",
    "JumpTableChip",
    "RangeMultiplicity256",
    "BitwiseLookupChip",
    "PowerOfTwoChip",
    "PopcountChip",
    "BitcountChip",
    "ByteToBitsChip",
    "MulChip",
    "BitwiseChip",
    "CompareChip",
    "DivRemChip",
    "RistrettoChip",
    "RistrettoEcallChip",
    "RistrettoCombTableChip",
    "RistrettoFixedBaseConsumerChip",
    "RistrettoCombAnchorChip",
    "RistrettoCombScalarBoundaryChip",
    "RistrettoCombCompressChip",
    "RistrettoCombCompressOutputChip",
];

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

/// Drive all 31 chips through one continuous Horner (the join shape) under the
/// dataflow-only backend, and report the operand distances + live-set widths.
#[test]
fn stream_bandwidth() {
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

    let ctx = Rc::new(RefCell::new(BandwidthBackend::new()));
    drive_multi(&ctx, &comps, |idx, ls, e| {
        drive_chip_oods(idx, ls, &lookup, e)
    });
    let b = Rc::try_unwrap(ctx)
        .unwrap_or_else(|_| panic!("a Handle outlived the bandwidth walk"))
        .into_inner();

    // ── Operand-distance distribution (the offset a streamed row must reach) ──
    let mut dists = b.distances.clone();
    dists.sort_unstable();
    let max_dist = dists.last().copied().unwrap_or(0);
    let mean_dist = if dists.is_empty() {
        0.0
    } else {
        dists.iter().map(|&d| d as u64).sum::<u64>() as f64 / dists.len() as f64
    };

    // ── Per-component max distance (which chips reach far) ──
    let mut per_comp_max = [0u32; chip_idx::COUNT];
    for (&d, &c) in b.distances.iter().zip(&b.dist_component) {
        if c < chip_idx::COUNT && d > per_comp_max[c] {
            per_comp_max[c] = d;
        }
    }

    let naive_w = b.live_set_naive();
    let lazy_w = b.live_set_lazy();

    let n_nodes = b.n_nodes();
    let est_rows = n_nodes.div_ceil(OPS_PER_ROW);
    let est_log = (usize::BITS - est_rows.next_power_of_two().leading_zeros()).saturating_sub(1);

    eprintln!("\n=== P5.3 task #0: flat 31-component OODS schedule bandwidth ===\n");
    eprintln!(
        "streamed nodes: {n_nodes}  ({} mask samples + {} witnessed products; \
         {} latched·latched products held off-stream)",
        b.n_mask_nodes, b.n_witness_nodes, b.n_latched_products,
    );
    eprintln!(
        "embed width:    {n_nodes} QM31 = {} M31 values",
        n_nodes * SECURE_EXTENSION_DEGREE,
    );
    eprintln!("\n-- operand distance (furthest streamable operand of each witnessed product) --");
    eprintln!(
        "  max {max_dist}   mean {mean_dist:.1}   p50 {}   p90 {}   p99 {}   p99.9 {}",
        percentile(&dists, 0.50),
        percentile(&dists, 0.90),
        percentile(&dists, 0.99),
        percentile(&dists, 0.999),
    );
    let small = dists.iter().filter(|&&d| d <= 8).count();
    let medium = dists.iter().filter(|&&d| d > 8 && d <= 256).count();
    let large = dists.iter().filter(|&&d| d > 256).count();
    eprintln!(
        "  distance ≤ 8: {small} ({:.1}%)   9..256: {medium} ({:.1}%)   > 256: {large} ({:.1}%)",
        100.0 * small as f64 / dists.len().max(1) as f64,
        100.0 * medium as f64 / dists.len().max(1) as f64,
        100.0 * large as f64 / dists.len().max(1) as f64,
    );

    eprintln!("\n-- per-component max operand distance (top offenders) --");
    let mut ranked: Vec<(usize, u32)> = per_comp_max.iter().copied().enumerate().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1));
    for &(idx, d) in ranked.iter().take(8) {
        eprintln!("  chip {idx:>2} {:<32} max distance {d}", CHIP_NAMES[idx]);
    }

    eprintln!("\n-- live-set width W (window a banded streamed layout must hold) --");
    eprintln!("  naive order (all masks read up front): W = {naive_w}");
    eprintln!("  lazy  order (mask read at first use):  W = {lazy_w}");

    eprintln!(
        "\n-- projected streamed shape (OPS_PER_ROW = {OPS_PER_ROW}) --\n  \
         rows ≈ {est_rows} → log {est_log} (channel is ~log 14); \
         per-row width ≈ ops·(a few QM31) + latched + window W."
    );
    eprintln!(
        "\nINTERPRETATION: the naive max distance ({max_dist}) is the offset a row would \
         reach if masks stay read-up-front; the lazy live-set W ({lazy_w}) is the window the \
         streamed OodsEval must hold if it defers each mask read to first use. The task-#1 \
         scheduler targets W, not the naive distance.\n"
    );

    // The schedule must be non-trivial and the latched aux must stay off-stream.
    assert!(
        n_nodes > 30_000,
        "expected ~40150 streamed nodes, got {n_nodes}"
    );
    assert!(!b.distances.is_empty(), "expected witnessed products");
}
