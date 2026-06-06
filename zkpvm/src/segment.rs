//! Trace segmentation: slice a fully-traced [`SideNote`] into bounded
//! step-range segments that prove independently in bounded memory and chain
//! via [`crate::verify_chain`].
//!
//! A single proof's peak memory scales with the trace's largest chip
//! `log_size`. A multi-million-step actor trace (e.g. a kernel
//! state-transition re-execution) exceeds a 64 GB host even for a *single*
//! chip. Segmentation caps each segment's step count — and hence its
//! `log_size` — so the prover fits on modest hardware, while `verify_chain`
//! re-checks per-segment validity plus boundary continuity (Phase Z0 /
//! Z0-init bind each segment's first/last registers and the memory
//! commitment, so segments cannot be re-stitched dishonestly).
//!
//! This is program-agnostic: any actor whose trace is too large for one
//! proof becomes provable as a chain.

/// Split `[0, total)` into consecutive `[a, b)` ranges of at most
/// `max_steps` steps each (the last may be shorter). Panics if
/// `max_steps == 0`. Returns an empty vec when `total == 0`.
pub fn segment_bounds(total: usize, max_steps: usize) -> alloc::vec::Vec<(usize, usize)> {
    assert!(max_steps > 0, "max_steps must be non-zero");
    let mut bounds = alloc::vec::Vec::new();
    let mut a = 0;
    while a < total {
        let b = (a + max_steps).min(total);
        bounds.push((a, b));
        a = b;
    }
    bounds
}

#[cfg(feature = "prover")]
mod prover {
    use crate::core::step::PvmStep;
    use crate::side_note::SideNote;
    use alloc::vec::Vec;

    /// Slice a fully-traced `SideNote` into the segment covering steps
    /// `[a, b)`. The returned `SideNote` proves independently (in memory
    /// bounded by `b - a`) and chains to the segments on either side.
    ///
    /// Reconstructed per segment:
    /// - `steps` = `full.steps[a..b]` (timestamps retained, so the per-row
    ///   memory-ledger ordering is preserved within the segment);
    /// - `initial_regs` = `full.steps[a].regs_before`;
    /// - `initial_memory` = `full.initial_memory` with every memory write in
    ///   `full.steps[..a]` applied — the memory state *entering* the
    ///   segment, so the boundary memory commitment chains and in-segment
    ///   precompile reads of values written earlier bottom out at the right
    ///   bytes;
    /// - the captured precompile records (blake2b / ristretto scalar-mult /
    ///   point-add / scalar-reduce-wide / scalar-binop), each a parallel
    ///   `call ↔ mem_op` pair, filtered to those whose `mem_op.ts` lies in
    ///   the segment's timestamp window `[steps[a].ts, steps[b].ts)`;
    /// - `jump_table` (program-static, shared by all segments).
    ///
    /// Lookup-multiplicity counts are NOT carried: the chips re-derive them
    /// from the segment's steps during `prove`. `ingest_ristretto_boundary`
    /// re-derives the comb / variable-base routing + comb counts from the
    /// sliced scalar-mult records.
    ///
    /// For chaining N segments efficiently, prefer threading the memory
    /// image yourself (segment k+1's initial memory = segment k's initial
    /// memory + segment k's writes) rather than calling this per segment,
    /// which re-folds `steps[..a]` each time (O(N²) total).
    ///
    /// Panics if `a >= b` or `b > full.steps.len()`.
    pub fn segment_side_note(full: &SideNote, a: usize, b: usize) -> SideNote {
        assert!(
            a < b && b <= full.steps.len(),
            "invalid segment range [{a}, {b}) over {} steps",
            full.steps.len()
        );

        let ts_lo = full.steps[a].timestamp;
        let ts_hi = full.steps.get(b).map(|s| s.timestamp).unwrap_or(u64::MAX);
        let in_window = move |ts: u64| ts >= ts_lo && ts < ts_hi;

        // Memory state entering the segment: initial image + earlier writes.
        let mut mem = full.initial_memory.clone();
        apply_writes(&mut mem, &full.steps[..a]);

        let mut sn = SideNote::new(
            full.steps[a..b].to_vec(),
            full.code.clone(),
            full.bitmask.clone(),
        )
        .with_memory(mem)
        .with_jump_table(full.jump_table.clone())
        .with_initial_regs(full.steps[a].regs_before);

        let (bc, bm) = filter_pair(&full.blake2b_calls, &full.blake2b_mem_ops, |m| {
            in_window(m.ts)
        });
        sn.blake2b_calls = bc;
        sn.blake2b_mem_ops = bm;

        let (rc, rm) = filter_pair(&full.ristretto_calls, &full.ristretto_mem_ops, |m| {
            in_window(m.ts)
        });
        sn.ristretto_calls = rc;
        sn.ristretto_mem_ops = rm;

        let (ac, am) = filter_pair(
            &full.ristretto_add_calls,
            &full.ristretto_add_mem_ops,
            |m| in_window(m.ts),
        );
        sn.ristretto_add_calls = ac;
        sn.ristretto_add_mem_ops = am;

        let (sc, sm) = filter_pair(
            &full.scalar_reduce_wide_calls,
            &full.scalar_reduce_wide_mem_ops,
            |m| in_window(m.ts),
        );
        sn.scalar_reduce_wide_calls = sc;
        sn.scalar_reduce_wide_mem_ops = sm;

        let (bc2, bm2) = filter_pair(&full.scalar_binop_calls, &full.scalar_binop_mem_ops, |m| {
            in_window(m.ts)
        });
        sn.scalar_binop_calls = bc2;
        sn.scalar_binop_mem_ops = bm2;

        // Re-derive comb / variable-base routing + comb counts from the
        // sliced scalar-mult records.
        sn.ingest_ristretto_boundary();
        sn
    }

    /// Apply every `mem_write` in `steps` to `mem` in order.
    pub fn apply_writes(mem: &mut Vec<u8>, steps: &[PvmStep]) {
        for s in steps {
            if let Some(w) = &s.mem_write {
                let addr = w.address as usize;
                let sz = w.size as usize;
                let end = addr + sz;
                if end > mem.len() {
                    mem.resize(end, 0);
                }
                let bytes = w.value.to_le_bytes();
                mem[addr..end].copy_from_slice(&bytes[..sz]);
            }
        }
    }

    /// Keep the i-th `(call, mem_op)` pair iff `pred(mem_op)`. The inputs
    /// are parallel (1:1, same order — the tracer pushes the pair together).
    fn filter_pair<C: Clone, M: Clone>(
        calls: &[C],
        mem_ops: &[M],
        pred: impl Fn(&M) -> bool,
    ) -> (Vec<C>, Vec<M>) {
        debug_assert_eq!(
            calls.len(),
            mem_ops.len(),
            "call/mem_op vectors must be parallel (1:1)"
        );
        let mut out_calls = Vec::new();
        let mut out_mem = Vec::new();
        for (c, m) in calls.iter().zip(mem_ops.iter()) {
            if pred(m) {
                out_calls.push(c.clone());
                out_mem.push(m.clone());
            }
        }
        (out_calls, out_mem)
    }
}

#[cfg(feature = "prover")]
pub use prover::{apply_writes, segment_side_note};
