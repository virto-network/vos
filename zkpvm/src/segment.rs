//! Trace segmentation: slice a fully-traced [`SideNote`] into bounded
//! step-range segments that prove independently in bounded memory and chain
//! via [`crate::verify_chain`].
//!
//! A single proof's peak memory scales with the trace's largest chip
//! `log_size`. A multi-million-step actor trace (e.g. a kernel
//! state-transition re-execution) exceeds a 64 GB host even for a *single*
//! chip. Segmentation caps each segment's step count — and hence its
//! `log_size` — so the prover fits on modest hardware, while `verify_chain`
//! re-checks per-segment validity plus boundary continuity.
//!
//! SOUNDNESS SCOPE. `verify_chain`'s continuity check compares each
//! segment's `final_state` to the next's `initial_state` (registers, pc,
//! timestamp, memory_commitment). Those `SegmentState` fields are proof
//! METADATA: the FS-transcript mix (registers + pc + timestamp; see
//! `prove.rs`) makes a finished proof tamper-evident, but NO constraint
//! binds the metadata to the committed boundary columns, so a malicious
//! from-scratch prover can ship arbitrary self-consistent boundary
//! states (see `chips/register_memory_closing.rs`). `memory_commitment`
//! is weaker still — it is a hash computed outside the circuit and is
//! not even mixed. So this slicer + `verify_chain` is the bounded-memory
//! PROVING capability; it is NOT yet a trustworthy verifier-side chain
//! check. Making it one (real boundary-public-input binding) is the
//! conservation-of-value chain-verification project — see
//! `docs/plans/succinct-merkle-witness.md`.
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
    /// Note: each call reconstructs the entering memory by replaying all
    /// writes with `ts < steps[a].ts` (step stores + precompile outputs), so
    /// proving N segments by calling this per segment is O(N²) in total
    /// replay work. Fine for modest N; a streaming driver could thread the
    /// memory image forward instead.
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

        // Memory state entering the segment: replay EVERY write with
        // `ts < ts_lo` in timestamp order — both regular stores
        // (`step.mem_write`) AND precompile output writes (blake2b /
        // ristretto / scalar-* `*_mem_ops`), which are NOT recorded in
        // `step.mem_write`. Missing the precompile writes leaves stale bytes
        // at their output addresses, so a later segment's read of an
        // earlier-segment precompile result fails the memory-ledger
        // read-consistency check (`is_read · (value − prev) = 0`).
        let mem = replay_writes(full, Some(ts_lo));

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

    /// Replay a `SideNote`'s memory writes over its initial image, in
    /// timestamp order, and return the resulting flat memory. `ts_upper`:
    /// `Some(t)` applies only writes with `ts < t` (the memory state
    /// ENTERING step `t`); `None` applies all writes (the FINAL memory).
    ///
    /// Crucially this includes **precompile output writes** (blake2b's
    /// 64-byte hash at `h_ptr`; ristretto / point-add / scalar-reduce /
    /// scalar-binop's 32-byte result at `output_ptr`), which the per-step
    /// `mem_write` does NOT capture — they live in the `*_mem_ops` records.
    /// Used both for a segment's threaded initial memory (`segment_side_note`)
    /// and its final memory commitment (`prove`'s boundary state); the two
    /// MUST agree or `verify_chain`'s boundary-continuity check rejects.
    pub(crate) fn replay_writes(side_note: &SideNote, ts_upper: Option<u64>) -> Vec<u8> {
        let keep = |ts: u64| ts_upper.is_none_or(|t| ts < t);
        // (ts, addr, 64-byte buffer, len). A fixed buffer avoids a heap
        // allocation per write; 64 = blake2b's output, the widest write.
        let mut writes: Vec<(u64, u32, [u8; 64], u8)> = Vec::new();

        for s in &side_note.steps {
            if let Some(w) = &s.mem_write {
                if keep(s.timestamp) {
                    let sz = w.size as usize;
                    let mut buf = [0u8; 64];
                    buf[..sz].copy_from_slice(&w.value.to_le_bytes()[..sz]);
                    writes.push((s.timestamp, w.address, buf, sz as u8));
                }
            }
        }
        for m in &side_note.blake2b_mem_ops {
            if keep(m.ts) {
                let mut buf = [0u8; 64];
                buf[..64].copy_from_slice(&m.out_bytes);
                writes.push((m.ts, m.h_ptr, buf, 64));
            }
        }
        for m in &side_note.ristretto_mem_ops {
            if keep(m.ts) {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&m.out_bytes);
                writes.push((m.ts, m.output_ptr, buf, 32));
            }
        }
        for m in &side_note.ristretto_add_mem_ops {
            if keep(m.ts) {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&m.out_bytes);
                writes.push((m.ts, m.output_ptr, buf, 32));
            }
        }
        for m in &side_note.scalar_reduce_wide_mem_ops {
            if keep(m.ts) {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&m.out_bytes);
                writes.push((m.ts, m.output_ptr, buf, 32));
            }
        }
        for m in &side_note.scalar_binop_mem_ops {
            if keep(m.ts) {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&m.out_bytes);
                writes.push((m.ts, m.output_ptr, buf, 32));
            }
        }

        // Each timestamp has at most one write (a step is either a regular
        // store or exactly one ECALL precompile), so sorting by ts yields a
        // well-defined replay order with later writes overwriting earlier.
        writes.sort_by_key(|w| w.0);

        let mut mem = side_note.initial_memory.clone();
        for (_ts, addr, buf, len) in &writes {
            let addr = *addr as usize;
            let len = *len as usize;
            let end = addr + len;
            if end > mem.len() {
                mem.resize(end, 0);
            }
            mem[addr..end].copy_from_slice(&buf[..len]);
        }
        mem
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
pub(crate) use prover::replay_writes;
#[cfg(feature = "prover")]
pub use prover::segment_side_note;
