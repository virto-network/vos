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
//! timestamp, memory_commitment). Each segment's verification binds those
//! metadata fields to the committed boundary COLUMNS (boundary-binding
//! check; see `boundary_binding`). Per field:
//!   - pc/timestamp columns are pinned to the trace (CpuChip
//!     program-execution chaining), so the continuity equality forces
//!     real pc/timestamp continuity.
//!   - register columns are pinned to the trace by the register ledger's
//!     read-consistency (v6: a cross-row `#[mask_next_row]` `prev_value`
//!     binding + a `(reg, ts)` sortedness gadget + an `is_write` limb),
//!     which is sound against a from-scratch prover (gate:
//!     `tests/ledger_readconsistency_gate.rs`), so the continuity
//!     equality forces genuine register continuity too (see
//!     `chips/register_memory_closing.rs`).
//!   - `memory_commitment` is a hash computed outside the circuit (not
//!     even FS-mixed), so memory continuity trusts the prover. Closing
//!     it needs an in-circuit memory-image commitment (couples with the
//!     memory-continuity work in `docs/plans/roadmap.md`).
//! Independently, `verify_chain` itself is a HOST-SIDE capability, not a
//! trust-boundary check: it consumes prover-derived `SideNote`s and
//! anchors no per-segment program commitment. Making it a trust boundary
//! (a side-note-free `verify_chain_standalone`) is the
//! chain-verification work in `docs/plans/roadmap.md`.
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
    use crate::chips::blake2b::Blake2bCall;
    use crate::core::step::{CompactStep, MemAccess, NUM_REGS, PvmStep, expand_steps};
    use crate::core::tracing::{
        Blake2bMemOp, RistrettoMemOp, RistrettoPointAddMemOp, RistrettoPointAddRecord,
        RistrettoRecord, ScalarBinopMemOp, ScalarBinopRecord, ScalarMultKind,
        ScalarReduceWideMemOp, ScalarReduceWideRecord, TracingPvm,
    };
    use crate::side_note::{CompactTrace, SideNote};
    use alloc::collections::BTreeSet;
    use alloc::vec::Vec;

    /// The per-step fields the chain-side walkers read — timestamp plus
    /// the two optional memory accesses — implemented by both step forms,
    /// so the budgeted cutter and the write replay are ONE code path each
    /// and the full and compact chain representations cut and thread
    /// identically by construction.
    trait StepView {
        fn ts(&self) -> u64;
        fn read_access(&self) -> Option<&MemAccess>;
        fn write_access(&self) -> Option<&MemAccess>;
    }

    impl StepView for PvmStep {
        fn ts(&self) -> u64 {
            self.timestamp
        }
        fn read_access(&self) -> Option<&MemAccess> {
            self.mem_read.as_ref()
        }
        fn write_access(&self) -> Option<&MemAccess> {
            self.mem_write.as_ref()
        }
    }

    impl StepView for CompactStep {
        fn ts(&self) -> u64 {
            self.timestamp
        }
        fn read_access(&self) -> Option<&MemAccess> {
            self.mem_read.as_ref()
        }
        fn write_access(&self) -> Option<&MemAccess> {
            self.mem_write.as_ref()
        }
    }

    /// Borrowed chain-wide fields common to the two chain holders
    /// ([`SideNote`] and [`CompactTrace`]): the program-static parts and
    /// the five precompile call/mem-op stream pairs. Both cursors, both
    /// budgeted cutters, and the segment assembly take this view, so a
    /// window built from either holder flows through identical code.
    struct ChainParts<'a> {
        code: &'a [u8],
        bitmask: &'a [u8],
        jump_table: &'a [u32],
        blake2b_calls: &'a [crate::chips::blake2b::Blake2bCall],
        blake2b_mem_ops: &'a [crate::core::tracing::Blake2bMemOp],
        ristretto_calls: &'a [crate::core::tracing::RistrettoRecord],
        ristretto_mem_ops: &'a [crate::core::tracing::RistrettoMemOp],
        ristretto_add_calls: &'a [crate::core::tracing::RistrettoPointAddRecord],
        ristretto_add_mem_ops: &'a [crate::core::tracing::RistrettoPointAddMemOp],
        scalar_reduce_wide_calls: &'a [crate::core::tracing::ScalarReduceWideRecord],
        scalar_reduce_wide_mem_ops: &'a [crate::core::tracing::ScalarReduceWideMemOp],
        scalar_binop_calls: &'a [crate::core::tracing::ScalarBinopRecord],
        scalar_binop_mem_ops: &'a [crate::core::tracing::ScalarBinopMemOp],
    }

    impl<'a> From<&'a SideNote> for ChainParts<'a> {
        fn from(full: &'a SideNote) -> Self {
            Self {
                code: &full.code,
                bitmask: &full.bitmask,
                jump_table: &full.jump_table,
                blake2b_calls: &full.blake2b_calls,
                blake2b_mem_ops: &full.blake2b_mem_ops,
                ristretto_calls: &full.ristretto_calls,
                ristretto_mem_ops: &full.ristretto_mem_ops,
                ristretto_add_calls: &full.ristretto_add_calls,
                ristretto_add_mem_ops: &full.ristretto_add_mem_ops,
                scalar_reduce_wide_calls: &full.scalar_reduce_wide_calls,
                scalar_reduce_wide_mem_ops: &full.scalar_reduce_wide_mem_ops,
                scalar_binop_calls: &full.scalar_binop_calls,
                scalar_binop_mem_ops: &full.scalar_binop_mem_ops,
            }
        }
    }

    impl<'a> From<&'a CompactTrace> for ChainParts<'a> {
        fn from(full: &'a CompactTrace) -> Self {
            Self {
                code: &full.code,
                bitmask: &full.bitmask,
                jump_table: &full.jump_table,
                blake2b_calls: &full.blake2b_calls,
                blake2b_mem_ops: &full.blake2b_mem_ops,
                ristretto_calls: &full.ristretto_calls,
                ristretto_mem_ops: &full.ristretto_mem_ops,
                ristretto_add_calls: &full.ristretto_add_calls,
                ristretto_add_mem_ops: &full.ristretto_add_mem_ops,
                scalar_reduce_wide_calls: &full.scalar_reduce_wide_calls,
                scalar_reduce_wide_mem_ops: &full.scalar_reduce_wide_mem_ops,
                scalar_binop_calls: &full.scalar_binop_calls,
                scalar_binop_mem_ops: &full.scalar_binop_mem_ops,
            }
        }
    }

    /// Content-budgeted segmentation: split the trace into maximal windows
    /// holding BOTH budgets — at most `max_steps` steps AND at most
    /// `max_pages` distinct touched memory pages. Distinct pages size the
    /// entering/exiting page-Merkle multiproof and with it
    /// `Blake2bBoundaryChip`'s row count — the widest chip in the AIR — so
    /// step-only windowing leaves every window padded to the chain's worst
    /// window (canonical forcing) no matter how small `max_steps` gets.
    /// Budgeted cuts give memory-dense stretches short windows and
    /// plain-CPU stretches long ones, landing every window's canonical
    /// floors near the budget.
    ///
    /// Deterministic in `(trace, budgets)` — the prover and the catalog
    /// measurement MUST cut identically or the pinned allowlist misses the
    /// live shapes. Page counting mirrors
    /// [`crate::page_merkle::touched_pages`] (same streams, same
    /// `add_range` granularity), so a window's budget holds by the
    /// multiproof's own definition. A single step may exceed `max_pages`
    /// on its own and still forms a one-step window — the budget is a
    /// cost target, not a soundness bound (floors are measured over the
    /// actual windows).
    ///
    /// Panics if either budget is zero.
    pub fn segment_bounds_budgeted(
        full: &SideNote,
        max_steps: usize,
        max_pages: usize,
    ) -> Vec<(usize, usize)> {
        segment_bounds_budgeted_impl(&full.steps, &ChainParts::from(full), max_steps, max_pages)
    }

    /// [`segment_bounds_budgeted`] over a [`CompactTrace`] — the same walk
    /// over the same fields (a compact step carries the identical
    /// timestamp + memory accesses), so the cut is bit-identical to the
    /// full holder's for the same traced run.
    pub fn segment_bounds_budgeted_compact(
        full: &CompactTrace,
        max_steps: usize,
        max_pages: usize,
    ) -> Vec<(usize, usize)> {
        segment_bounds_budgeted_impl(&full.steps, &ChainParts::from(full), max_steps, max_pages)
    }

    fn segment_bounds_budgeted_impl<S: StepView>(
        steps: &[S],
        parts: &ChainParts<'_>,
        max_steps: usize,
        max_pages: usize,
    ) -> Vec<(usize, usize)> {
        /// Advance `cursor` past every op with `ts_of(op) <= ts`, handing
        /// the ones AT `ts` to `push`. Each stream is ts-sorted (the tracer
        /// appends in step order), so one monotone cursor per stream visits
        /// every op exactly once.
        fn take_at<'a, T>(
            ops: &'a [T],
            cursor: &mut usize,
            ts: u64,
            ts_of: impl Fn(&T) -> u64,
            mut push: impl FnMut(&'a T),
        ) {
            while *cursor < ops.len() && ts_of(&ops[*cursor]) <= ts {
                if ts_of(&ops[*cursor]) == ts {
                    push(&ops[*cursor]);
                }
                *cursor += 1;
            }
        }

        let mut cutter = BudgetedCutter::new(max_steps, max_pages);
        let mut bounds = Vec::new();
        let (mut cb, mut cr, mut ca, mut cw, mut cs) = (0, 0, 0, 0, 0);
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        for step in steps {
            let ts = step.ts();
            ranges.clear();
            step_ranges(step, &mut ranges);
            take_at(parts.blake2b_mem_ops, &mut cb, ts, |o| o.ts, |o| {
                blake2b_op_ranges(o, &mut ranges)
            });
            take_at(parts.ristretto_mem_ops, &mut cr, ts, |o| o.ts, |o| {
                ristretto_op_ranges(o, &mut ranges)
            });
            take_at(parts.ristretto_add_mem_ops, &mut ca, ts, |o| o.ts, |o| {
                ristretto_add_op_ranges(o, &mut ranges)
            });
            take_at(parts.scalar_reduce_wide_mem_ops, &mut cw, ts, |o| o.ts, |o| {
                scalar_reduce_wide_op_ranges(o, &mut ranges)
            });
            take_at(parts.scalar_binop_mem_ops, &mut cs, ts, |o| o.ts, |o| {
                scalar_binop_op_ranges(o, &mut ranges)
            });

            let (before, after) = cutter.feed(&ranges);
            bounds.extend(before);
            bounds.extend(after);
        }
        bounds.extend(cutter.finish());
        bounds
    }

    /// The step's own touched ranges: its optional memory read + write.
    fn step_ranges<S: StepView>(s: &S, out: &mut Vec<(u32, u32)>) {
        if let Some(r) = s.read_access() {
            out.push((r.address, r.size as u32));
        }
        if let Some(w) = s.write_access() {
            out.push((w.address, w.size as u32));
        }
    }

    // Per-stream touched ranges of one precompile op — the page-accounting
    // knowledge shared by the offline walker above and the online
    // [`TraceStream`] windower, so the two count identical pages for the
    // same op by construction.
    fn blake2b_op_ranges(o: &Blake2bMemOp, out: &mut Vec<(u32, u32)>) {
        out.push((o.h_ptr, o.h_bytes.len() as u32));
        out.push((o.m_ptr, o.m_bytes.len() as u32));
    }
    fn ristretto_op_ranges(o: &RistrettoMemOp, out: &mut Vec<(u32, u32)>) {
        out.push((o.scalar_ptr, o.scalar_bytes.len() as u32));
        out.push((o.point_ptr, o.point_bytes.len() as u32));
        out.push((o.output_ptr, o.out_bytes.len() as u32));
    }
    fn ristretto_add_op_ranges(o: &RistrettoPointAddMemOp, out: &mut Vec<(u32, u32)>) {
        out.push((o.p_ptr, o.p_bytes.len() as u32));
        out.push((o.q_ptr, o.q_bytes.len() as u32));
        out.push((o.output_ptr, o.out_bytes.len() as u32));
    }
    fn scalar_reduce_wide_op_ranges(o: &ScalarReduceWideMemOp, out: &mut Vec<(u32, u32)>) {
        out.push((o.wide_ptr, o.wide_bytes.len() as u32));
        out.push((o.output_ptr, o.out_bytes.len() as u32));
    }
    fn scalar_binop_op_ranges(o: &ScalarBinopMemOp, out: &mut Vec<(u32, u32)>) {
        out.push((o.a_ptr, o.a_bytes.len() as u32));
        out.push((o.b_ptr, o.b_bytes.len() as u32));
        out.push((o.output_ptr, o.out_bytes.len() as u32));
    }

    /// The incremental budgeted-cut decision — ONE code path behind the
    /// offline [`segment_bounds_budgeted`] walk and the online
    /// [`TraceStream`] windower, so an online cut is bit-identical to the
    /// offline cut of the same trace by construction. Feed each step's
    /// touched ranges in order; the cutter reports the window(s) the step
    /// closed. Page accounting mirrors
    /// [`crate::page_merkle::touched_pages`] (same `add_range`
    /// granularity), exactly as the offline walker always did.
    struct BudgetedCutter {
        max_steps: usize,
        max_pages: usize,
        pages: BTreeSet<u32>,
        /// Start of the currently accumulating window.
        a: usize,
        /// Index the next fed step will occupy.
        next: usize,
    }

    impl BudgetedCutter {
        /// Panics if either budget is zero (the historical
        /// `segment_bounds_budgeted` contract).
        fn new(max_steps: usize, max_pages: usize) -> Self {
            assert!(max_steps > 0, "max_steps must be non-zero");
            assert!(max_pages > 0, "max_pages must be non-zero");
            Self {
                max_steps,
                max_pages,
                pages: BTreeSet::new(),
                a: 0,
                next: 0,
            }
        }

        /// Feed the next step's touched ranges. Returns the bounds of the
        /// window closed BEFORE this step (its page ranges bust the page
        /// budget, so the step opens a fresh window — the window keeps at
        /// least one step, so a lone oversize step still segments) and the
        /// window closed AFTER it (the step budget filled), either or both
        /// `None`.
        fn feed(
            &mut self,
            ranges: &[(u32, u32)],
        ) -> (Option<(usize, usize)>, Option<(usize, usize)>) {
            let i = self.next;
            for &(addr, len) in ranges {
                crate::page_merkle::add_range(&mut self.pages, addr, len);
            }
            let mut before = None;
            if self.pages.len() > self.max_pages && i > self.a {
                before = Some((self.a, i));
                self.a = i;
                self.pages.clear();
                for &(addr, len) in ranges {
                    crate::page_merkle::add_range(&mut self.pages, addr, len);
                }
            }
            self.next = i + 1;
            let mut after = None;
            if self.next - self.a == self.max_steps {
                after = Some((self.a, self.next));
                self.a = self.next;
                self.pages.clear();
            }
            (before, after)
        }

        /// End of trace: the final partial window, if any steps remain
        /// open. Consumes it — a second call returns `None`.
        fn finish(&mut self) -> Option<(usize, usize)> {
            let bounds = (self.next > self.a).then_some((self.a, self.next));
            self.a = self.next;
            self.pages.clear();
            bounds
        }
    }

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
    /// replay work. Fine for a one-off slice; sequential passes over a
    /// chain's windows use [`SegmentCursor`], which threads the memory image
    /// forward and yields identical `SideNote`s in O(N) total.
    ///
    /// Panics if `a >= b` or `b > full.steps.len()`.
    pub fn segment_side_note(full: &SideNote, a: usize, b: usize) -> SideNote {
        assert!(
            a < b && b <= full.steps.len(),
            "invalid segment range [{a}, {b}) over {} steps",
            full.steps.len()
        );
        // Memory state entering the segment: replay EVERY write with
        // `ts < ts_lo` in timestamp order — both regular stores
        // (`step.mem_write`) AND precompile output writes (blake2b /
        // ristretto / scalar-* `*_mem_ops`), which are NOT recorded in
        // `step.mem_write`. Missing the precompile writes leaves stale bytes
        // at their output addresses, so a later segment's read of an
        // earlier-segment precompile result fails the memory-ledger
        // read-consistency check (`is_read · (value − prev) = 0`).
        let mem = replay_writes(full, Some(full.steps[a].timestamp));
        build_segment(full, a, b, mem)
    }

    /// Assemble the segment `SideNote` for `[a, b)` from `full` and the
    /// already-reconstructed entering memory image `mem`. Shared by
    /// [`segment_side_note`] (per-call prefix replay) and [`SegmentCursor`]
    /// (threaded image), so the two produce identical segments by
    /// construction — only the provenance of `mem` differs.
    fn build_segment(full: &SideNote, a: usize, b: usize, mem: Vec<u8>) -> SideNote {
        let ts_hi = full.steps.get(b).map(|s| s.timestamp).unwrap_or(u64::MAX);
        assemble_segment(
            &ChainParts::from(full),
            full.steps[a..b].to_vec(),
            full.steps[a].regs_before,
            mem,
            ts_hi,
        )
    }

    /// Assemble a window's `SideNote` from its already-materialized full
    /// steps, its entering register file, its entering memory image, and
    /// the exclusive timestamp bound of the next window. The single
    /// assembly path behind [`build_segment`] (full holder) and
    /// [`CompactSegmentCursor::side_note`] (compact holder): whatever
    /// produced the inputs, the window flows through identical filtering
    /// and ingestion, so the two chain representations yield equal
    /// segments by construction.
    fn assemble_segment(
        parts: &ChainParts<'_>,
        steps: Vec<PvmStep>,
        initial_regs: [u64; NUM_REGS],
        mem: Vec<u8>,
        ts_hi: u64,
    ) -> SideNote {
        let ts_lo = steps[0].timestamp;
        let in_window = move |ts: u64| ts >= ts_lo && ts < ts_hi;

        let mut sn = SideNote::new(steps, parts.code.to_vec(), parts.bitmask.to_vec())
            .with_memory(mem)
            .with_jump_table(parts.jump_table.to_vec())
            .with_initial_regs(initial_regs);

        let (bc, bm) = filter_pair(parts.blake2b_calls, parts.blake2b_mem_ops, |m| {
            in_window(m.ts)
        });
        sn.blake2b_calls = bc;
        sn.blake2b_mem_ops = bm;

        let (rc, rm) = filter_pair(parts.ristretto_calls, parts.ristretto_mem_ops, |m| {
            in_window(m.ts)
        });
        sn.ristretto_calls = rc;
        sn.ristretto_mem_ops = rm;

        let (ac, am) = filter_pair(
            parts.ristretto_add_calls,
            parts.ristretto_add_mem_ops,
            |m| in_window(m.ts),
        );
        sn.ristretto_add_calls = ac;
        sn.ristretto_add_mem_ops = am;

        let (sc, sm) = filter_pair(
            parts.scalar_reduce_wide_calls,
            parts.scalar_reduce_wide_mem_ops,
            |m| in_window(m.ts),
        );
        sn.scalar_reduce_wide_calls = sc;
        sn.scalar_reduce_wide_mem_ops = sm;

        let (bc2, bm2) = filter_pair(parts.scalar_binop_calls, parts.scalar_binop_mem_ops, |m| {
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
        let mut writes: Vec<PendingWrite> = Vec::new();

        for s in &side_note.steps {
            if keep(s.timestamp) {
                if let Some(w) = write_of_step(s) {
                    writes.push(w);
                }
            }
        }
        for m in &side_note.blake2b_mem_ops {
            if keep(m.ts) {
                writes.push(write_of_bytes(m.ts, m.h_ptr, &m.out_bytes));
            }
        }
        for m in &side_note.ristretto_mem_ops {
            if keep(m.ts) {
                writes.push(write_of_bytes(m.ts, m.output_ptr, &m.out_bytes));
            }
        }
        for m in &side_note.ristretto_add_mem_ops {
            if keep(m.ts) {
                writes.push(write_of_bytes(m.ts, m.output_ptr, &m.out_bytes));
            }
        }
        for m in &side_note.scalar_reduce_wide_mem_ops {
            if keep(m.ts) {
                writes.push(write_of_bytes(m.ts, m.output_ptr, &m.out_bytes));
            }
        }
        for m in &side_note.scalar_binop_mem_ops {
            if keep(m.ts) {
                writes.push(write_of_bytes(m.ts, m.output_ptr, &m.out_bytes));
            }
        }

        let mut mem = side_note.initial_memory.clone();
        apply_writes(&mut mem, writes);
        mem
    }

    /// One memory write pending replay: `(ts, addr, 64-byte buffer, len)`.
    /// A fixed buffer avoids a heap allocation per write; 64 = blake2b's
    /// output, the widest write.
    type PendingWrite = (u64, u32, [u8; 64], u8);

    /// The step's regular store as a pending write, if it made one.
    /// Generic over the step form ([`StepView`]) so the full and compact
    /// replay paths enumerate identical writes.
    fn write_of_step<S: StepView>(s: &S) -> Option<PendingWrite> {
        s.write_access().map(|w| {
            let sz = w.size as usize;
            let mut buf = [0u8; 64];
            buf[..sz].copy_from_slice(&w.value.to_le_bytes()[..sz]);
            (s.ts(), w.address, buf, sz as u8)
        })
    }

    /// A precompile output write (blake2b's 64 bytes at `h_ptr`; the
    /// ristretto / scalar-* 32 bytes at `output_ptr`) as a pending write.
    fn write_of_bytes(ts: u64, addr: u32, out: &[u8]) -> PendingWrite {
        let mut buf = [0u8; 64];
        buf[..out.len()].copy_from_slice(out);
        (ts, addr, buf, out.len() as u8)
    }

    /// Sort pending writes by timestamp and apply them over `mem`, growing
    /// it when a write lands past the current end. Each timestamp has at
    /// most one write (a step is either a regular store or exactly one
    /// ECALL precompile), so sorting by ts yields a well-defined replay
    /// order with later writes overwriting earlier.
    fn apply_writes(mem: &mut Vec<u8>, mut writes: Vec<PendingWrite>) {
        writes.sort_by_key(|w| w.0);
        for (_ts, addr, buf, len) in &writes {
            let addr = *addr as usize;
            let len = *len as usize;
            let end = addr + len;
            if end > mem.len() {
                mem.resize(end, 0);
            }
            mem[addr..end].copy_from_slice(&buf[..len]);
        }
    }

    /// Streaming segment driver: yields [`segment_side_note`]-identical
    /// `SideNote`s for windows visited in ascending step order, threading
    /// the entering memory image FORWARD across windows. Where
    /// `segment_side_note` re-replays the full write prefix per call (O(N²)
    /// total replay over a chain — see its note), the cursor applies each
    /// write exactly once, so a full pass over a chain's windows costs O(N)
    /// replay work in the trace length.
    ///
    /// Equivalence: the segment assembly is [`build_segment`], the same
    /// code `segment_side_note` runs; only the entering image's provenance
    /// differs. The threaded image equals the per-call replay because
    /// advancing to a window start `ts_lo` applies exactly the writes with
    /// `ts` in `[previous ts_lo, ts_lo)`, in timestamp order — the batches
    /// concatenate into the same globally ts-sorted application
    /// `replay_writes` performs (each ts carries at most one write, so
    /// order within a batch is unambiguous). The per-stream walk relies on
    /// each `*_mem_ops` stream being ts-sorted — the tracer appends in step
    /// order, the same invariant [`segment_bounds_budgeted`] leans on.
    ///
    /// Windows may be SKIPPED: requesting only a sparse subset (e.g. the
    /// allowlist-coverage probe set) advances the image across the gap
    /// without building the intervening `SideNote`s, so a sparse pass costs
    /// the same O(N) replay plus only the requested windows' assembly.
    ///
    /// Panics if a window starts before one already yielded (the image
    /// cannot rewind); use a fresh cursor for a second pass.
    pub struct SegmentCursor<'a> {
        full: &'a SideNote,
        /// The carried image: `full.initial_memory` with every write at
        /// `ts < applied_upto` applied.
        mem: Vec<u8>,
        /// Exclusive timestamp bound of the writes already applied.
        applied_upto: u64,
        /// Index of the first step not yet applied to `mem`.
        steps_at: usize,
        /// Per-stream indices of the first precompile output write not yet
        /// applied to `mem`.
        streams: StreamCursors,
    }

    impl<'a> SegmentCursor<'a> {
        /// Start a pass over `full`'s windows from its initial memory.
        pub fn new(full: &'a SideNote) -> Self {
            Self {
                full,
                mem: full.initial_memory.clone(),
                applied_upto: 0,
                steps_at: 0,
                streams: StreamCursors::default(),
            }
        }

        /// The segment `SideNote` for `[a, b)` — byte-identical to
        /// `segment_side_note(full, a, b)`. Panics on an invalid range or a
        /// window starting before one already yielded.
        pub fn side_note(&mut self, a: usize, b: usize) -> SideNote {
            assert!(
                a < b && b <= self.full.steps.len(),
                "invalid segment range [{a}, {b}) over {} steps",
                self.full.steps.len()
            );
            let ts_lo = self.full.steps[a].timestamp;
            assert!(
                ts_lo >= self.applied_upto,
                "windows must be visited in ascending order: window start ts {ts_lo} \
                 precedes the image already advanced to ts {}",
                self.applied_upto
            );
            self.advance_to(ts_lo);
            build_segment(self.full, a, b, self.mem.clone())
        }

        /// Apply every not-yet-applied write with `ts < ts_lo` to the
        /// carried image. Stream enumeration order mirrors
        /// [`replay_writes`] (steps, then the five precompile output
        /// streams); [`apply_writes`] then applies the batch in ts order.
        fn advance_to(&mut self, ts_lo: u64) {
            let full = self.full;
            let mut writes: Vec<PendingWrite> = Vec::new();
            while let Some(s) = full.steps.get(self.steps_at) {
                if s.timestamp >= ts_lo {
                    break;
                }
                if let Some(w) = write_of_step(s) {
                    writes.push(w);
                }
                self.steps_at += 1;
            }
            self.streams
                .drain_below(&ChainParts::from(full), ts_lo, &mut writes);
            apply_writes(&mut self.mem, writes);
            self.applied_upto = ts_lo;
        }
    }

    /// Per-stream indices of the first precompile output write not yet
    /// applied to a cursor's carried image, with the drain that advances
    /// them. Shared by [`SegmentCursor`] and [`CompactSegmentCursor`], so
    /// the two thread identical precompile writes.
    #[derive(Default)]
    struct StreamCursors {
        blake2b: usize,
        ristretto: usize,
        ristretto_add: usize,
        scalar_reduce_wide: usize,
        scalar_binop: usize,
    }

    impl StreamCursors {
        /// Push every not-yet-applied precompile output write with
        /// `ts < ts_lo`. Enumeration order mirrors [`replay_writes`]'s
        /// stream order (blake2b, ristretto, point-add, wide-reduce,
        /// scalar-binop); [`apply_writes`] sorts the batch by ts anyway.
        fn drain_below(
            &mut self,
            parts: &ChainParts<'_>,
            ts_lo: u64,
            out: &mut Vec<PendingWrite>,
        ) {
            drain_stream(
                parts.blake2b_mem_ops,
                &mut self.blake2b,
                ts_lo,
                |m| write_of_bytes(m.ts, m.h_ptr, &m.out_bytes),
                |m| m.ts,
                out,
            );
            drain_stream(
                parts.ristretto_mem_ops,
                &mut self.ristretto,
                ts_lo,
                |m| write_of_bytes(m.ts, m.output_ptr, &m.out_bytes),
                |m| m.ts,
                out,
            );
            drain_stream(
                parts.ristretto_add_mem_ops,
                &mut self.ristretto_add,
                ts_lo,
                |m| write_of_bytes(m.ts, m.output_ptr, &m.out_bytes),
                |m| m.ts,
                out,
            );
            drain_stream(
                parts.scalar_reduce_wide_mem_ops,
                &mut self.scalar_reduce_wide,
                ts_lo,
                |m| write_of_bytes(m.ts, m.output_ptr, &m.out_bytes),
                |m| m.ts,
                out,
            );
            drain_stream(
                parts.scalar_binop_mem_ops,
                &mut self.scalar_binop,
                ts_lo,
                |m| write_of_bytes(m.ts, m.output_ptr, &m.out_bytes),
                |m| m.ts,
                out,
            );
        }
    }

    /// [`SegmentCursor`] over a [`CompactTrace`]: threads BOTH the memory
    /// image and the REGISTER FILE forward across a chain's windows, and
    /// materializes each requested window's full steps
    /// ([`expand_steps`] — window-local, dropped with the window's
    /// `SideNote`), so the chips consume ordinary [`PvmStep`]s while the
    /// chain-wide holder stays compact.
    ///
    /// Equivalence: the yielded `SideNote` equals
    /// `segment_side_note(&full_side_note, a, b)` field for field (unit-
    /// pinned by `compact_cursor_matches_segment_side_note`) — the memory
    /// threading is [`StreamCursors`] + the same step-write enumeration
    /// (both step forms carry identical `mem_write`s), the register file
    /// is exact because a step's whole register delta is its
    /// [`crate::core::step::RegWrite`] (tracer-verified), and the assembly
    /// is [`assemble_segment`], the same path the full holder runs.
    ///
    /// Same visiting contract as [`SegmentCursor`]: ascending window
    /// starts, skipped windows advance the state without building them.
    pub struct CompactSegmentCursor<'a> {
        full: &'a CompactTrace,
        /// The carried image: `full.initial_memory` with every write at
        /// `ts < applied_upto` applied.
        mem: Vec<u8>,
        /// The carried register file: `full.initial_regs` with every step
        /// reg-write at `ts < applied_upto` applied — the file ENTERING
        /// the first unapplied step.
        regs: [u64; NUM_REGS],
        /// Exclusive timestamp bound of the writes already applied.
        applied_upto: u64,
        /// Index of the first step not yet applied to `mem`/`regs`.
        steps_at: usize,
        /// Per-stream indices of the first precompile output write not yet
        /// applied to `mem`.
        streams: StreamCursors,
    }

    impl<'a> CompactSegmentCursor<'a> {
        /// Start a pass over `full`'s windows from its initial memory and
        /// initial register file.
        pub fn new(full: &'a CompactTrace) -> Self {
            Self {
                full,
                mem: full.initial_memory.clone(),
                regs: full.initial_regs,
                applied_upto: 0,
                steps_at: 0,
                streams: StreamCursors::default(),
            }
        }

        /// The segment `SideNote` for `[a, b)` — field-identical to
        /// slicing the expanded full trace. Panics on an invalid range or
        /// a window starting before one already yielded.
        pub fn side_note(&mut self, a: usize, b: usize) -> SideNote {
            assert!(
                a < b && b <= self.full.steps.len(),
                "invalid segment range [{a}, {b}) over {} steps",
                self.full.steps.len()
            );
            let ts_lo = self.full.steps[a].timestamp;
            assert!(
                ts_lo >= self.applied_upto,
                "windows must be visited in ascending order: window start ts {ts_lo} \
                 precedes the image already advanced to ts {}",
                self.applied_upto
            );
            self.advance_to(ts_lo);
            let ts_hi = self
                .full
                .steps
                .get(b)
                .map(|s| s.timestamp)
                .unwrap_or(u64::MAX);
            // The carried file IS the file entering step `a`: timestamps
            // are strictly increasing, so exactly the steps before `a`
            // have ts < ts_lo and their reg writes are already applied.
            let steps = expand_steps(&self.full.steps[a..b], self.regs);
            assemble_segment(
                &ChainParts::from(self.full),
                steps,
                self.regs,
                self.mem.clone(),
                ts_hi,
            )
        }

        /// Apply every not-yet-applied write with `ts < ts_lo`: step
        /// memory writes + register writes in one walk (each step applied
        /// exactly once), then the precompile output streams — the same
        /// enumeration [`SegmentCursor::advance_to`] performs, plus the
        /// register threading the compact form requires.
        fn advance_to(&mut self, ts_lo: u64) {
            let full = self.full;
            let mut writes: Vec<PendingWrite> = Vec::new();
            while let Some(s) = full.steps.get(self.steps_at) {
                if s.timestamp >= ts_lo {
                    break;
                }
                if let Some(w) = write_of_step(s) {
                    writes.push(w);
                }
                if let Some(rw) = s.reg_write {
                    self.regs[rw.index as usize] = rw.value;
                }
                self.steps_at += 1;
            }
            self.streams
                .drain_below(&ChainParts::from(full), ts_lo, &mut writes);
            apply_writes(&mut self.mem, writes);
            self.applied_upto = ts_lo;
        }
    }

    /// Advance `at` past every op with `ts_of(op) < ts_lo`, pushing each
    /// one's pending write. The stream is ts-sorted, so the monotone cursor
    /// visits every op exactly once across a whole pass.
    fn drain_stream<T>(
        ops: &[T],
        at: &mut usize,
        ts_lo: u64,
        to_write: impl Fn(&T) -> PendingWrite,
        ts_of: impl Fn(&T) -> u64,
        out: &mut Vec<PendingWrite>,
    ) {
        while *at < ops.len() && ts_of(&ops[*at]) < ts_lo {
            out.push(to_write(&ops[*at]));
            *at += 1;
        }
    }

    /// One traced step plus the precompile call/mem-op pair its ECALL
    /// recorded — at most one pair, on at most one stream (a step is at
    /// most one ECALL; the invariant the ts-sorted streams rest on). The
    /// unit a [`StepSource`] hands the [`TraceStream`] windower.
    pub struct StepArrival {
        pub(crate) step: CompactStep,
        pub(crate) blake2b: Option<(Blake2bCall, Blake2bMemOp)>,
        pub(crate) ristretto: Option<(RistrettoRecord, RistrettoMemOp)>,
        pub(crate) ristretto_add: Option<(RistrettoPointAddRecord, RistrettoPointAddMemOp)>,
        pub(crate) scalar_reduce_wide: Option<(ScalarReduceWideRecord, ScalarReduceWideMemOp)>,
        pub(crate) scalar_binop: Option<(ScalarBinopRecord, ScalarBinopMemOp)>,
    }

    impl StepArrival {
        /// The step's touched ranges — its own read/write plus its
        /// precompile op's buffers, via the same per-stream helpers the
        /// offline budgeted walk uses, so online page accounting counts
        /// exactly what [`segment_bounds_budgeted`] counts.
        fn ranges(&self, out: &mut Vec<(u32, u32)>) {
            out.clear();
            step_ranges(&self.step, out);
            if let Some((_, o)) = &self.blake2b {
                blake2b_op_ranges(o, out);
            }
            if let Some((_, o)) = &self.ristretto {
                ristretto_op_ranges(o, out);
            }
            if let Some((_, o)) = &self.ristretto_add {
                ristretto_add_op_ranges(o, out);
            }
            if let Some((_, o)) = &self.scalar_reduce_wide {
                scalar_reduce_wide_op_ranges(o, out);
            }
            if let Some((_, o)) = &self.scalar_binop {
                scalar_binop_op_ranges(o, out);
            }
        }

        /// Every attached op must carry the step's own timestamp — the
        /// binding that makes online "ops at this step" equal the offline
        /// walk's ts-filtered `take_at`.
        fn assert_ts_consistent(&self) {
            let ts = self.step.timestamp;
            debug_assert!(self.blake2b.as_ref().is_none_or(|(_, o)| o.ts == ts));
            debug_assert!(self.ristretto.as_ref().is_none_or(|(_, o)| o.ts == ts));
            debug_assert!(self.ristretto_add.as_ref().is_none_or(|(_, o)| o.ts == ts));
            debug_assert!(
                self.scalar_reduce_wide
                    .as_ref()
                    .is_none_or(|(_, o)| o.ts == ts)
            );
            debug_assert!(self.scalar_binop.as_ref().is_none_or(|(_, o)| o.ts == ts));
        }
    }

    /// A producer of traced steps for [`TraceStream`] — the seam that lets
    /// the windower run over a live [`TracingPvm`] ([`TracingSource`]) in
    /// production and over hand-built fixtures in the equivalence tests.
    pub trait StepSource {
        /// The next traced step with its ECALL records, or `None` once the
        /// run terminated.
        fn next_arrival(&mut self) -> Option<StepArrival>;
        /// Register file entering the first produced step; meaningful once
        /// at least one arrival was produced.
        fn initial_regs(&self) -> [u64; NUM_REGS];
    }

    /// The live [`StepSource`]: pumps a [`TracingPvm`] one
    /// [`TracingPvm::step_with_vos_stubs`] iteration per arrival —
    /// identical execution to `run_with_vos_stubs` (the loop over the same
    /// method) — draining the recorded step and its precompile records out
    /// of the tracer as they land, so the tracer holds no trace at all:
    /// the windower's current window is the only step storage anywhere.
    pub struct TracingSource {
        tracer: TracingPvm,
        done: bool,
    }

    impl TracingSource {
        pub fn new(tracer: TracingPvm) -> Self {
            Self {
                tracer,
                done: false,
            }
        }
    }

    /// Take the (at most one) freshly recorded `(call, mem_op)` pair off a
    /// tracer stream. The source drains after every step, so a stream
    /// holds 0 or 1 pairs here.
    fn pop_pair<C, M>(calls: &mut Vec<C>, ops: &mut Vec<M>) -> Option<(C, M)> {
        debug_assert_eq!(calls.len(), ops.len());
        debug_assert!(calls.len() <= 1);
        Some((calls.pop()?, ops.pop()?))
    }

    impl StepSource for TracingSource {
        fn next_arrival(&mut self) -> Option<StepArrival> {
            if self.done {
                return None;
            }
            if self.tracer.step_with_vos_stubs().is_some() {
                self.done = true;
            }
            let step = self
                .tracer
                .take_step()
                .expect("every pumped iteration records exactly one step");
            debug_assert_eq!(self.tracer.num_steps(), 0);
            let t = &mut self.tracer;
            Some(StepArrival {
                step,
                blake2b: pop_pair(&mut t.blake2b_records, &mut t.blake2b_mem_ops).map(
                    |(r, m)| {
                        (
                            Blake2bCall {
                                h: r.h,
                                m: r.m,
                                t: r.t,
                                f: r.f,
                            },
                            m,
                        )
                    },
                ),
                ristretto: pop_pair(&mut t.ristretto_records, &mut t.ristretto_mem_ops),
                ristretto_add: pop_pair(&mut t.ristretto_add_records, &mut t.ristretto_add_mem_ops),
                scalar_reduce_wide: pop_pair(
                    &mut t.scalar_reduce_wide_records,
                    &mut t.scalar_reduce_wide_mem_ops,
                ),
                scalar_binop: pop_pair(&mut t.scalar_binop_records, &mut t.scalar_binop_mem_ops),
            })
        }

        fn initial_regs(&self) -> [u64; NUM_REGS] {
            self.tracer.initial_regs()
        }
    }

    /// One window's accumulating storage: its compact steps plus its
    /// precompile call/mem-op stream slices, exactly the per-window share
    /// of what a [`CompactTrace`] holds chain-wide.
    #[derive(Default)]
    struct WindowBuf {
        steps: Vec<CompactStep>,
        blake2b_calls: Vec<Blake2bCall>,
        blake2b_mem_ops: Vec<Blake2bMemOp>,
        ristretto_calls: Vec<RistrettoRecord>,
        ristretto_mem_ops: Vec<RistrettoMemOp>,
        ristretto_add_calls: Vec<RistrettoPointAddRecord>,
        ristretto_add_mem_ops: Vec<RistrettoPointAddMemOp>,
        scalar_reduce_wide_calls: Vec<ScalarReduceWideRecord>,
        scalar_reduce_wide_mem_ops: Vec<ScalarReduceWideMemOp>,
        scalar_binop_calls: Vec<ScalarBinopRecord>,
        scalar_binop_mem_ops: Vec<ScalarBinopMemOp>,
    }

    impl WindowBuf {
        fn push(&mut self, arr: StepArrival) {
            self.steps.push(arr.step);
            if let Some((c, m)) = arr.blake2b {
                self.blake2b_calls.push(c);
                self.blake2b_mem_ops.push(m);
            }
            if let Some((c, m)) = arr.ristretto {
                self.ristretto_calls.push(c);
                self.ristretto_mem_ops.push(m);
            }
            if let Some((c, m)) = arr.ristretto_add {
                self.ristretto_add_calls.push(c);
                self.ristretto_add_mem_ops.push(m);
            }
            if let Some((c, m)) = arr.scalar_reduce_wide {
                self.scalar_reduce_wide_calls.push(c);
                self.scalar_reduce_wide_mem_ops.push(m);
            }
            if let Some((c, m)) = arr.scalar_binop {
                self.scalar_binop_calls.push(c);
                self.scalar_binop_mem_ops.push(m);
            }
        }

        /// The window's stream slices as a [`ChainParts`] view. Handing
        /// pre-sliced streams through [`assemble_segment`] yields exactly
        /// what filtering the full streams yields: every op here has its
        /// ts inside the window, so the assembly's `in_window` filter
        /// passes each one, in the same (step) order.
        fn parts<'a>(
            &'a self,
            code: &'a [u8],
            bitmask: &'a [u8],
            jump_table: &'a [u32],
        ) -> ChainParts<'a> {
            ChainParts {
                code,
                bitmask,
                jump_table,
                blake2b_calls: &self.blake2b_calls,
                blake2b_mem_ops: &self.blake2b_mem_ops,
                ristretto_calls: &self.ristretto_calls,
                ristretto_mem_ops: &self.ristretto_mem_ops,
                ristretto_add_calls: &self.ristretto_add_calls,
                ristretto_add_mem_ops: &self.ristretto_add_mem_ops,
                scalar_reduce_wide_calls: &self.scalar_reduce_wide_calls,
                scalar_reduce_wide_mem_ops: &self.scalar_reduce_wide_mem_ops,
                scalar_binop_calls: &self.scalar_binop_calls,
                scalar_binop_mem_ops: &self.scalar_binop_mem_ops,
            }
        }

        /// The window's precompile OUTPUT writes as pending writes — the
        /// same per-stream mapping [`StreamCursors::drain_below`] applies
        /// when a cursor advances past these ops.
        fn pending_writes(&self, out: &mut Vec<PendingWrite>) {
            for m in &self.blake2b_mem_ops {
                out.push(write_of_bytes(m.ts, m.h_ptr, &m.out_bytes));
            }
            for m in &self.ristretto_mem_ops {
                out.push(write_of_bytes(m.ts, m.output_ptr, &m.out_bytes));
            }
            for m in &self.ristretto_add_mem_ops {
                out.push(write_of_bytes(m.ts, m.output_ptr, &m.out_bytes));
            }
            for m in &self.scalar_reduce_wide_mem_ops {
                out.push(write_of_bytes(m.ts, m.output_ptr, &m.out_bytes));
            }
            for m in &self.scalar_binop_mem_ops {
                out.push(write_of_bytes(m.ts, m.output_ptr, &m.out_bytes));
            }
        }
    }

    /// A closed window: its step bounds, the exclusive timestamp bound of
    /// the next window (`None` until the successor step's ts is known;
    /// `u64::MAX` for the chain's last window — exactly the offline
    /// `full.steps.get(b).map(ts).unwrap_or(MAX)`), and its buffered
    /// content.
    struct ClosedWindow {
        bounds: (usize, usize),
        ts_hi: Option<u64>,
        buf: WindowBuf,
    }

    /// The streaming chain driver: runs a [`StepSource`] (production: a
    /// live [`TracingPvm`] via [`TracingSource`]) and cuts windows ONLINE
    /// with the same [`BudgetedCutter`] decisions the offline
    /// [`segment_bounds_budgeted`] walk makes, yielding each window's
    /// `SideNote` as the tracer completes it and dropping it before the
    /// next — so a multi-million-step chain is NEVER resident: peak step
    /// storage is one window's compact steps (plus the window-local
    /// expansion during [`Self::side_note`]), instead of the whole
    /// [`CompactTrace`] (~1 GiB at 7.8M steps).
    ///
    /// Equivalence: the cut shares the offline cutter's decision path
    /// (bit-identical bounds); the entering memory image and register
    /// file are threaded forward with the same write enumeration
    /// [`CompactSegmentCursor::advance_to`] performs (batched per window);
    /// and the assembly is [`assemble_segment`] — so every yielded window
    /// is field-identical to the compact cursor's over the same traced
    /// run (unit-pinned by the `trace_stream_*` equivalence tests).
    ///
    /// Contract: call [`Self::next_window`] repeatedly; after each
    /// `Some(bounds)`, optionally call [`Self::side_note`] (or
    /// [`Self::fixed_base_calls`] for the metadata passes) before the next
    /// `next_window` call retires the window — skipped windows advance the
    /// carried state without expansion, the cursor pattern's sparse-probe
    /// economy.
    pub struct TraceStream<S: StepSource> {
        source: S,
        code: Vec<u8>,
        bitmask: Vec<u8>,
        jump_table: Vec<u32>,
        cutter: BudgetedCutter,
        /// The carried image: the initial memory with every retired
        /// window's writes applied — the image ENTERING the current
        /// window, as [`CompactSegmentCursor`] carries it.
        mem: Vec<u8>,
        /// The carried register file entering the current window.
        regs: [u64; NUM_REGS],
        regs_seeded: bool,
        /// The window currently accumulating arrivals.
        acc: WindowBuf,
        /// A step-budget-closed window awaiting its successor's ts.
        pending: Option<ClosedWindow>,
        /// A fully resolved window not yet handed to the caller.
        ready: Option<ClosedWindow>,
        /// The window handed out by the last `next_window`, retired (its
        /// writes applied to the carried state) on the next call.
        current: Option<ClosedWindow>,
        exhausted: bool,
        ranges_scratch: Vec<(u32, u32)>,
        steps_seen: usize,
    }

    impl<S: StepSource> TraceStream<S> {
        /// Windower over `source` with the `(seg_steps, page_budget)` cut;
        /// `page_budget == 0` means the uniform step cut ([`super::
        /// segment_bounds`]), realized as an unbounded page budget — the
        /// budgeted walk degenerates to exactly the uniform bounds.
        /// `initial_memory` is the image the trace starts from (the
        /// pre-run flat_mem); `code`/`bitmask`/`jump_table` the
        /// program-static fields every window shares.
        pub fn new(
            source: S,
            code: Vec<u8>,
            bitmask: Vec<u8>,
            jump_table: Vec<u32>,
            initial_memory: Vec<u8>,
            seg_steps: usize,
            page_budget: usize,
        ) -> Self {
            let max_pages = if page_budget == 0 {
                usize::MAX
            } else {
                page_budget
            };
            Self {
                source,
                code,
                bitmask,
                jump_table,
                cutter: BudgetedCutter::new(seg_steps, max_pages),
                mem: initial_memory,
                regs: [0u64; NUM_REGS],
                regs_seeded: false,
                acc: WindowBuf::default(),
                pending: None,
                ready: None,
                current: None,
                exhausted: false,
                ranges_scratch: Vec::new(),
                steps_seen: 0,
            }
        }

        /// Advance to the next window: retire the previous one (apply its
        /// writes to the carried image + register file) and run the
        /// source until a window completes. Returns its step bounds, or
        /// `None` when the trace is exhausted.
        pub fn next_window(&mut self) -> Option<(usize, usize)> {
            if let Some(w) = self.current.take() {
                self.retire(w);
            }
            loop {
                if let Some(w) = self.ready.take() {
                    let bounds = w.bounds;
                    self.current = Some(w);
                    return Some(bounds);
                }
                if self.exhausted {
                    // Flush: a step-budget-closed window awaiting a
                    // successor that never came (its exclusive ts bound is
                    // MAX), else the final partial window the cutter still
                    // holds open.
                    if let Some(mut p) = self.pending.take() {
                        p.ts_hi = Some(u64::MAX);
                        self.ready = Some(p);
                        continue;
                    }
                    if let Some(bounds) = self.cutter.finish() {
                        debug_assert_eq!(bounds.1 - bounds.0, self.acc.steps.len());
                        self.ready = Some(ClosedWindow {
                            bounds,
                            ts_hi: Some(u64::MAX),
                            buf: core::mem::take(&mut self.acc),
                        });
                        continue;
                    }
                    return None;
                }
                match self.source.next_arrival() {
                    Some(arr) => self.on_arrival(arr),
                    None => self.exhausted = true,
                }
            }
        }

        /// The current window's step bounds (the last `next_window`
        /// return). Panics with no current window.
        pub fn bounds(&self) -> (usize, usize) {
            self.current
                .as_ref()
                .expect("no current window: call next_window first")
                .bounds
        }

        /// Assemble the current window's `SideNote` — field-identical to
        /// [`CompactSegmentCursor::side_note`] over the same traced run
        /// (same entering state threading, same [`assemble_segment`]).
        /// The expansion is window-local and dropped with the returned
        /// `SideNote`. Panics with no current window.
        pub fn side_note(&mut self) -> SideNote {
            let w = self
                .current
                .as_ref()
                .expect("no current window: call next_window first");
            let steps = expand_steps(&w.buf.steps, self.regs);
            assemble_segment(
                &w.buf.parts(&self.code, &self.bitmask, &self.jump_table),
                steps,
                self.regs,
                self.mem.clone(),
                w.ts_hi.expect("a current window's ts bound is resolved"),
            )
        }

        /// The current window's fixed-base scalar-mult (comb) call count —
        /// what `ristretto_comb_calls.len()` would be on its assembled
        /// `SideNote` (`ingest_ristretto_boundary` routes exactly the
        /// `FixedBasepoint`-kind records onto the comb path), without
        /// assembling it. The metadata passes' probe-selection key.
        pub fn fixed_base_calls(&self) -> usize {
            self.current
                .as_ref()
                .expect("no current window: call next_window first")
                .buf
                .ristretto_calls
                .iter()
                .filter(|r| r.kind == ScalarMultKind::FixedBasepoint)
                .count()
        }

        /// Steps consumed so far; the trace's total length once
        /// `next_window` has returned `None`.
        pub fn steps_seen(&self) -> usize {
            self.steps_seen
        }

        fn on_arrival(&mut self, arr: StepArrival) {
            if !self.regs_seeded {
                self.regs = self.source.initial_regs();
                self.regs_seeded = true;
            }
            arr.assert_ts_consistent();
            let ts = arr.step.timestamp;
            // A step-budget-closed window's exclusive ts bound is this
            // step's ts (offline: `full.steps[b].timestamp`).
            if let Some(mut p) = self.pending.take() {
                p.ts_hi = Some(ts);
                debug_assert!(self.ready.is_none());
                self.ready = Some(p);
            }
            let mut ranges = core::mem::take(&mut self.ranges_scratch);
            arr.ranges(&mut ranges);
            let (before, after) = self.cutter.feed(&ranges);
            self.ranges_scratch = ranges;
            if let Some(bounds) = before {
                // Page-budget close: the accumulated steps end BEFORE this
                // step, so its ts is the closed window's exclusive bound.
                // Can't collide with a pending resolution above: a pending
                // window empties the accumulator, and the page close
                // requires an accumulated step.
                debug_assert!(self.ready.is_none());
                debug_assert_eq!(bounds.1 - bounds.0, self.acc.steps.len());
                self.ready = Some(ClosedWindow {
                    bounds,
                    ts_hi: Some(ts),
                    buf: core::mem::take(&mut self.acc),
                });
            }
            self.acc.push(arr);
            self.steps_seen += 1;
            if let Some(bounds) = after {
                debug_assert!(self.pending.is_none());
                debug_assert_eq!(bounds.1 - bounds.0, self.acc.steps.len());
                self.pending = Some(ClosedWindow {
                    bounds,
                    ts_hi: None,
                    buf: core::mem::take(&mut self.acc),
                });
            }
        }

        /// Apply a retired window's writes to the carried state — the
        /// same enumeration [`CompactSegmentCursor::advance_to`] performs
        /// (step stores + register writes in one walk, then the
        /// precompile output streams), batched per window.
        fn retire(&mut self, w: ClosedWindow) {
            let mut writes: Vec<PendingWrite> = Vec::new();
            for s in &w.buf.steps {
                if let Some(pw) = write_of_step(s) {
                    writes.push(pw);
                }
                if let Some(rw) = s.reg_write {
                    self.regs[rw.index as usize] = rw.value;
                }
            }
            w.buf.pending_writes(&mut writes);
            apply_writes(&mut self.mem, writes);
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
pub(crate) use prover::replay_writes;
#[cfg(feature = "prover")]
pub use prover::{
    CompactSegmentCursor, SegmentCursor, StepArrival, StepSource, TraceStream, TracingSource,
    segment_bounds_budgeted, segment_bounds_budgeted_compact, segment_side_note,
};

#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::*;
    use crate::core::step::{MemAccess, NUM_REGS, PvmStep};
    use crate::page_merkle;
    use crate::side_note::SideNote;
    use javm::instruction::Opcode;

    /// A synthetic step at `ts`, optionally writing `size` bytes at `addr`.
    /// The budgeted walker and `touched_pages` read only
    /// timestamp/mem_read/mem_write (+ the precompile streams), so the rest
    /// is inert filler.
    fn step(ts: u64, write: Option<(u32, u8)>) -> PvmStep {
        PvmStep {
            timestamp: ts,
            pc: 0,
            opcode: Opcode::Add64,
            skip_len: 3,
            regs_before: [0; NUM_REGS],
            regs_after: [0; NUM_REGS],
            reg_write: None,
            reg_a: 0,
            reg_b: 0,
            reg_d: 0,
            imm: 0,
            imm_y: 0,
            branch_target: 0,
            branch_taken: false,
            mem_read: None,
            mem_write: write.map(|(address, size)| MemAccess { address, value: 0, size }),
            gas_after: 0,
            gas_charged: 0,
            next_pc: 0,
            exit: false,
        }
    }

    /// 12 steps: 0-3 write page 0, 4-7 spray pages 10..14, 8-11 write page 1.
    fn spray_trace() -> SideNote {
        let mut steps = Vec::new();
        for i in 0..12u64 {
            let addr = match i {
                0..=3 => 0x100,
                4..=7 => ((10 + i as u32 - 4) << page_merkle::PAGE_BITS) + 8,
                _ => (1 << page_merkle::PAGE_BITS) + 0x40,
            };
            steps.push(step(i + 1, Some((addr, 8))));
        }
        SideNote::new(steps, vec![Opcode::Trap as u8], vec![1]).with_memory(vec![0u8; 1 << 16])
    }

    #[test]
    fn budgeted_bounds_partition_and_hold_budgets() {
        let full = spray_trace();
        // Step budget slack (12) isolates the page budget (2): only the
        // page-spray region (steps 4..8, one fresh page each) forces cuts.
        let bounds = segment_bounds_budgeted(&full, 12, 2);
        // Partition: consecutive, gapless, covering [0, total).
        assert_eq!(bounds.first().unwrap().0, 0);
        assert_eq!(bounds.last().unwrap().1, full.steps.len());
        for w in bounds.windows(2) {
            assert_eq!(w[0].1, w[1].0, "windows must be gapless");
        }
        // Budget holds by the multiproof's own page definition.
        for &(a, b) in &bounds {
            let slice = segment_side_note(&full, a, b);
            let pages = page_merkle::touched_pages(&slice);
            assert!(
                pages.len() <= 2 || b - a == 1,
                "page budget violated at [{a},{b}): {} pages",
                pages.len()
            );
        }
        // Content-awareness: the spray region splits what a pure step cut
        // would keep whole.
        assert!(bounds.len() > segment_bounds(full.steps.len(), 12).len());
    }

    #[test]
    fn huge_page_budget_degenerates_to_step_cut() {
        let full = spray_trace();
        assert_eq!(
            segment_bounds_budgeted(&full, 5, usize::MAX >> 1),
            segment_bounds(full.steps.len(), 5),
        );
    }

    /// 12 steps (ts 1..=12) + one record on EVERY precompile stream, laid
    /// out so a 4-step cut ([0,4) [4,8) [8,12)) threads precompile output
    /// writes across both window boundaries:
    ///   - window 0: blake2b at ts 2 (output at 4090 — PAST the 4096-byte
    ///     image, so the entering images of windows 1 and 2 must carry
    ///     `replay_writes`' resize growth) + a Variable scalar mult at ts 3;
    ///   - window 1: a FixedBasepoint scalar mult at ts 5 (exercises the
    ///     comb routing), a point-add at ts 6, a wide reduce at ts 7;
    ///   - window 2: a scalar binop at ts 9 (slice-only — no later window
    ///     observes its write).
    /// Regular stores carry distinct non-zero values, so a missed or
    /// misplaced write/slice can't vanish into an all-zero image. The
    /// register history is CONSISTENT (a non-zero seeded file threaded
    /// through per-step `reg_write`s that rotate across indices, with one
    /// no-write step and one taken branch), so every step has a distinct
    /// file AND the trace converts to compact form — the compact-cursor
    /// equivalence tests reuse this fixture.
    fn threaded_trace() -> SideNote {
        use crate::chips::blake2b::Blake2bCall;
        use crate::core::tracing::{
            Blake2bMemOp, RistrettoMemOp, RistrettoPointAddMemOp, RistrettoPointAddRecord,
            RistrettoRecord, ScalarBinopMemOp, ScalarBinopRecord, ScalarMultKind,
            ScalarReduceWideMemOp, ScalarReduceWideRecord,
        };

        let mut steps = Vec::new();
        let mut regs = [0u64; NUM_REGS];
        regs[1] = 100; // seeded stack pointer — non-zero entering file
        for i in 0..12u64 {
            let ts = i + 1;
            let write = match ts {
                1 => Some((0x50u32, 8u8)),
                4 => Some((0x60, 8)),
                8 => Some((0x70, 8)),
                10 => Some((0x80, 8)),
                11 => Some((0x88, 8)),
                12 => Some((0x90, 8)),
                _ => None, // ts 2,3,5,6,7,9 are the ECALL slots
            };
            let mut s = step(ts, write);
            if let Some(w) = s.mem_write.as_mut() {
                w.value = 0xB000 + ts;
            }
            s.regs_before = regs;
            // ts 6 leaves the file unchanged; every other step writes one
            // register, the index rotating so window boundaries land
            // between writes to different indices.
            if ts != 6 {
                let idx = (ts as usize) % NUM_REGS;
                regs[idx] = 0xC00 + ts;
                s.reg_write = Some(idx);
            }
            s.regs_after = regs;
            if ts == 4 {
                s.branch_taken = true;
                s.branch_target = 0x30;
            }
            steps.push(s);
        }
        let mut sn = SideNote::new(steps, vec![Opcode::Trap as u8], vec![1])
            .with_memory(vec![0u8; 4096])
            .with_jump_table(vec![2, 4]);

        sn.blake2b_calls.push(Blake2bCall { h: [1; 8], m: [2; 16], t: 3, f: true });
        sn.blake2b_mem_ops.push(Blake2bMemOp {
            h_ptr: 4090,
            m_ptr: 0x300,
            ts: 2,
            h_bytes: [5; 64],
            m_bytes: [6; 128],
            out_bytes: core::array::from_fn(|i| 0xA0 ^ i as u8),
        });

        sn.ristretto_calls.push(RistrettoRecord {
            scalar: [7; 32],
            point: [8; 32],
            output: [9; 32],
            kind: ScalarMultKind::Variable,
        });
        sn.ristretto_mem_ops.push(RistrettoMemOp {
            scalar_ptr: 0x100,
            point_ptr: 0x140,
            output_ptr: 0x180,
            ts: 3,
            scalar_bytes: [7; 32],
            point_bytes: [8; 32],
            out_bytes: [9; 32],
            kind: ScalarMultKind::Variable,
        });
        sn.ristretto_calls.push(RistrettoRecord {
            scalar: [0x21; 32],
            point: [0x22; 32],
            output: [0x23; 32],
            kind: ScalarMultKind::FixedBasepoint,
        });
        sn.ristretto_mem_ops.push(RistrettoMemOp {
            scalar_ptr: 0x100,
            point_ptr: 0x140,
            output_ptr: 0x1C0,
            ts: 5,
            scalar_bytes: [0x21; 32],
            point_bytes: [0x22; 32],
            out_bytes: [0x23; 32],
            kind: ScalarMultKind::FixedBasepoint,
        });

        sn.ristretto_add_calls.push(RistrettoPointAddRecord {
            p: [10; 32],
            q: [11; 32],
            output: [12; 32],
        });
        sn.ristretto_add_mem_ops.push(RistrettoPointAddMemOp {
            p_ptr: 0x200,
            q_ptr: 0x220,
            output_ptr: 0x240,
            ts: 6,
            p_bytes: [10; 32],
            q_bytes: [11; 32],
            out_bytes: [12; 32],
        });

        sn.scalar_reduce_wide_calls.push(ScalarReduceWideRecord {
            wide: [13; 64],
            output: [14; 32],
        });
        sn.scalar_reduce_wide_mem_ops.push(ScalarReduceWideMemOp {
            wide_ptr: 0x260,
            output_ptr: 0x2A0,
            ts: 7,
            wide_bytes: [13; 64],
            out_bytes: [14; 32],
        });

        sn.scalar_binop_calls.push(ScalarBinopRecord {
            op_id: 113,
            a: [15; 32],
            b: [16; 32],
            output: [17; 32],
        });
        sn.scalar_binop_mem_ops.push(ScalarBinopMemOp {
            op_id: 113,
            a_ptr: 0x2C0,
            b_ptr: 0x2E0,
            output_ptr: 0x320,
            ts: 9,
            a_bytes: [15; 32],
            b_bytes: [16; 32],
            out_bytes: [17; 32],
        });
        sn
    }

    /// Field-by-field equality of the two slicing paths over every field
    /// `segment_side_note` populates: the sliced steps, the entering image
    /// (raw bytes — both paths apply the identical write set, so even
    /// `replay_writes`' resize growth must agree byte-for-byte, no
    /// root-level indirection needed), the entering registers, the five
    /// filtered call/mem-op stream pairs, the program-static fields, and
    /// everything `ingest_ristretto_boundary` derives (comb calls + counts,
    /// plus the Variable path's range256 bumps).
    fn assert_windows_equal(via_cursor: &SideNote, via_slice: &SideNote) {
        assert_eq!(via_cursor.steps, via_slice.steps);
        assert_eq!(via_cursor.code, via_slice.code);
        assert_eq!(via_cursor.bitmask, via_slice.bitmask);
        assert_eq!(via_cursor.initial_memory, via_slice.initial_memory);
        assert_eq!(via_cursor.initial_regs, via_slice.initial_regs);
        assert_eq!(via_cursor.jump_table, via_slice.jump_table);
        assert_eq!(via_cursor.jump_table_counts, via_slice.jump_table_counts);
        assert_eq!(via_cursor.blake2b_calls, via_slice.blake2b_calls);
        assert_eq!(via_cursor.blake2b_mem_ops, via_slice.blake2b_mem_ops);
        assert_eq!(via_cursor.ristretto_calls, via_slice.ristretto_calls);
        assert_eq!(via_cursor.ristretto_mem_ops, via_slice.ristretto_mem_ops);
        assert_eq!(via_cursor.ristretto_add_calls, via_slice.ristretto_add_calls);
        assert_eq!(via_cursor.ristretto_add_mem_ops, via_slice.ristretto_add_mem_ops);
        assert_eq!(
            via_cursor.scalar_reduce_wide_calls,
            via_slice.scalar_reduce_wide_calls
        );
        assert_eq!(
            via_cursor.scalar_reduce_wide_mem_ops,
            via_slice.scalar_reduce_wide_mem_ops
        );
        assert_eq!(via_cursor.scalar_binop_calls, via_slice.scalar_binop_calls);
        assert_eq!(via_cursor.scalar_binop_mem_ops, via_slice.scalar_binop_mem_ops);
        assert_eq!(via_cursor.ristretto_comb_calls, via_slice.ristretto_comb_calls);
        assert_eq!(via_cursor.ristretto_comb_counts, via_slice.ristretto_comb_counts);
        assert_eq!(via_cursor.range256_counts, via_slice.range256_counts);
    }

    #[test]
    fn cursor_matches_segment_side_note_on_a_full_pass() {
        let full = threaded_trace();
        let bounds = segment_bounds(full.steps.len(), 4);
        assert_eq!(bounds.len(), 3);
        let mut cursor = crate::segment::SegmentCursor::new(&full);
        for &(a, b) in &bounds {
            assert_windows_equal(&cursor.side_note(a, b), &segment_side_note(&full, a, b));
        }

        // Fixture non-vacuity — the properties the equivalence is ABOUT:
        // window 1's entering image carries window 0's blake2b output,
        // including the resize past the original 4096-byte image...
        let w1 = segment_side_note(&full, 4, 8);
        assert_eq!(w1.initial_memory.len(), 4090 + 64);
        let blake_out: [u8; 64] = core::array::from_fn(|i| 0xA0 ^ i as u8);
        assert_eq!(w1.initial_memory[4090..4154], blake_out);
        // ...window 1 routes its FixedBasepoint record onto the comb path...
        assert_eq!(w1.ristretto_comb_calls.len(), 1);
        // ...and window 2's entering image sees every earlier precompile
        // output write (variable mult, comb mult, point add, wide reduce).
        let w2 = segment_side_note(&full, 8, 12);
        assert_eq!(w2.initial_memory[0x180..0x1A0], [9u8; 32]);
        assert_eq!(w2.initial_memory[0x1C0..0x1E0], [0x23u8; 32]);
        assert_eq!(w2.initial_memory[0x240..0x260], [12u8; 32]);
        assert_eq!(w2.initial_memory[0x2A0..0x2C0], [14u8; 32]);
    }

    #[test]
    fn cursor_skips_windows_without_building_them() {
        let full = threaded_trace();
        let bounds = segment_bounds(full.steps.len(), 4);
        // Sparse probe: jump straight to the last window — the gap's writes
        // (windows 0 and 1, both step stores and precompile outputs) must
        // land in the carried image without materializing those windows.
        let (a, b) = bounds[2];
        let mut cursor = crate::segment::SegmentCursor::new(&full);
        assert_windows_equal(&cursor.side_note(a, b), &segment_side_note(&full, a, b));
    }

    #[test]
    #[should_panic(expected = "ascending order")]
    fn cursor_rejects_backward_windows() {
        let full = threaded_trace();
        let mut cursor = crate::segment::SegmentCursor::new(&full);
        cursor.side_note(4, 8);
        cursor.side_note(0, 4);
    }

    /// The compact holder for a full fixture: steps converted one-to-one
    /// (`to_compact` panics if the fixture's register history were not
    /// step-consistent), streams and program-static fields carried over.
    fn compact_of(full: &SideNote) -> crate::side_note::CompactTrace {
        crate::side_note::CompactTrace {
            steps: full.steps.iter().map(|s| s.to_compact()).collect(),
            initial_regs: full.steps[0].regs_before,
            code: full.code.clone(),
            bitmask: full.bitmask.clone(),
            initial_memory: full.initial_memory.clone(),
            jump_table: full.jump_table.clone(),
            blake2b_calls: full.blake2b_calls.clone(),
            blake2b_mem_ops: full.blake2b_mem_ops.clone(),
            ristretto_calls: full.ristretto_calls.clone(),
            ristretto_mem_ops: full.ristretto_mem_ops.clone(),
            ristretto_add_calls: full.ristretto_add_calls.clone(),
            ristretto_add_mem_ops: full.ristretto_add_mem_ops.clone(),
            scalar_reduce_wide_calls: full.scalar_reduce_wide_calls.clone(),
            scalar_reduce_wide_mem_ops: full.scalar_reduce_wide_mem_ops.clone(),
            scalar_binop_calls: full.scalar_binop_calls.clone(),
            scalar_binop_mem_ops: full.scalar_binop_mem_ops.clone(),
        }
    }

    /// The W2.2 soundness bar: every window a [`CompactSegmentCursor`]
    /// yields equals the full-trace slice field for field — including
    /// every `PvmStep` field (snapshots rebuilt from the threaded register
    /// file; `assert_windows_equal`'s steps equality is `PvmStep`'s derived
    /// `PartialEq`), the entering image (with `replay_writes`' resize
    /// growth), the entering registers, and everything
    /// `ingest_ristretto_boundary` derives. The fixture crosses register
    /// writes, a branch, and all five precompile streams over the window
    /// boundaries.
    #[test]
    fn compact_cursor_matches_segment_side_note() {
        let full = threaded_trace();
        let compact = compact_of(&full);
        let bounds = segment_bounds(full.steps.len(), 4);
        assert_eq!(bounds.len(), 3);
        let mut cursor = crate::segment::CompactSegmentCursor::new(&compact);
        let mut windows = Vec::new();
        for &(a, b) in &bounds {
            let via_compact = cursor.side_note(a, b);
            assert_windows_equal(&via_compact, &segment_side_note(&full, a, b));
            windows.push(via_compact);
        }
        // Non-vacuity: the register threading is actually exercised — the
        // windows enter with three DISTINCT non-zero files, and in-window
        // steps carry register writes the expansion must apply.
        assert_ne!(windows[0].initial_regs, windows[1].initial_regs);
        assert_ne!(windows[1].initial_regs, windows[2].initial_regs);
        assert!(windows.iter().all(|w| w.initial_regs[1] != 0));
        assert!(
            windows[1].steps.iter().any(|s| s.reg_write.is_some()),
            "fixture must place register writes inside the windows"
        );
    }

    /// Skipping windows must thread BOTH carried states across the gap:
    /// jumping straight to the last window applies the gap's register
    /// writes and memory writes (step stores + precompile outputs) without
    /// materializing the intervening windows.
    #[test]
    fn compact_cursor_skips_windows_without_building_them() {
        let full = threaded_trace();
        let compact = compact_of(&full);
        let bounds = segment_bounds(full.steps.len(), 4);
        let (a, b) = bounds[2];
        let mut cursor = crate::segment::CompactSegmentCursor::new(&compact);
        assert_windows_equal(&cursor.side_note(a, b), &segment_side_note(&full, a, b));
    }

    #[test]
    #[should_panic(expected = "ascending order")]
    fn compact_cursor_rejects_backward_windows() {
        let full = threaded_trace();
        let compact = compact_of(&full);
        let mut cursor = crate::segment::CompactSegmentCursor::new(&compact);
        cursor.side_note(4, 8);
        cursor.side_note(0, 4);
    }

    /// The budgeted cut must be bit-identical over the two holder forms —
    /// the pinned allowlist assumes producer and measurement cut the same
    /// windows regardless of which representation they walked.
    #[test]
    fn compact_budgeted_bounds_match_full() {
        for full in [spray_trace(), threaded_trace()] {
            let compact = compact_of(&full);
            for (max_steps, max_pages) in [(12, 2), (5, usize::MAX >> 1), (4, 1)] {
                assert_eq!(
                    segment_bounds_budgeted_compact(&compact, max_steps, max_pages),
                    segment_bounds_budgeted(&full, max_steps, max_pages),
                    "cut diverged at budgets ({max_steps}, {max_pages})"
                );
            }
        }
    }

    /// Test-only [`StepSource`]: replays a hand-built full-trace fixture
    /// as arrivals — each step with the precompile pair recorded at its
    /// ts — so the ONLINE windower can be driven over the same synthetic
    /// fixtures the offline paths are pinned on (all five streams,
    /// records crossing window boundaries, resize growth).
    struct ReplaySource {
        arrivals: std::collections::VecDeque<crate::segment::StepArrival>,
        initial_regs: [u64; NUM_REGS],
    }

    impl ReplaySource {
        fn from_side_note(full: &SideNote) -> Self {
            fn pair_at<C: Clone, M: Clone>(
                calls: &[C],
                ops: &[M],
                ts: u64,
                ts_of: impl Fn(&M) -> u64,
            ) -> Option<(C, M)> {
                ops.iter()
                    .position(|m| ts_of(m) == ts)
                    .map(|i| (calls[i].clone(), ops[i].clone()))
            }
            let arrivals = full
                .steps
                .iter()
                .map(|s| {
                    let ts = s.timestamp;
                    crate::segment::StepArrival {
                        step: s.to_compact(),
                        blake2b: pair_at(&full.blake2b_calls, &full.blake2b_mem_ops, ts, |m| {
                            m.ts
                        }),
                        ristretto: pair_at(
                            &full.ristretto_calls,
                            &full.ristretto_mem_ops,
                            ts,
                            |m| m.ts,
                        ),
                        ristretto_add: pair_at(
                            &full.ristretto_add_calls,
                            &full.ristretto_add_mem_ops,
                            ts,
                            |m| m.ts,
                        ),
                        scalar_reduce_wide: pair_at(
                            &full.scalar_reduce_wide_calls,
                            &full.scalar_reduce_wide_mem_ops,
                            ts,
                            |m| m.ts,
                        ),
                        scalar_binop: pair_at(
                            &full.scalar_binop_calls,
                            &full.scalar_binop_mem_ops,
                            ts,
                            |m| m.ts,
                        ),
                    }
                })
                .collect();
            Self {
                arrivals,
                initial_regs: full.steps[0].regs_before,
            }
        }
    }

    impl crate::segment::StepSource for ReplaySource {
        fn next_arrival(&mut self) -> Option<crate::segment::StepArrival> {
            self.arrivals.pop_front()
        }
        fn initial_regs(&self) -> [u64; NUM_REGS] {
            self.initial_regs
        }
    }

    /// A [`TraceStream`] over `full` replayed with the given cut.
    fn stream_of(
        full: &SideNote,
        seg_steps: usize,
        page_budget: usize,
    ) -> crate::segment::TraceStream<ReplaySource> {
        crate::segment::TraceStream::new(
            ReplaySource::from_side_note(full),
            full.code.clone(),
            full.bitmask.clone(),
            full.jump_table.clone(),
            full.initial_memory.clone(),
            seg_steps,
            page_budget,
        )
    }

    /// The W2(a) equivalence bar, synthetic side: over the all-streams
    /// fixture (precompile records crossing both boundaries, resize
    /// growth past the image, comb routing) the ONLINE windower's cut
    /// and windows must equal the offline path — the uniform cut
    /// (`page_budget = 0`) checked window-by-window against
    /// `segment_side_note`, field for field.
    #[test]
    fn trace_stream_matches_offline_windows_on_uniform_cut() {
        let full = threaded_trace();
        let bounds = segment_bounds(full.steps.len(), 4);
        assert_eq!(bounds.len(), 3);
        let mut stream = stream_of(&full, 4, 0);
        let mut streamed_bounds = Vec::new();
        while let Some((a, b)) = stream.next_window() {
            streamed_bounds.push((a, b));
            assert_windows_equal(&stream.side_note(), &segment_side_note(&full, a, b));
        }
        assert_eq!(streamed_bounds, bounds, "online uniform cut diverged");
        assert_eq!(stream.steps_seen(), full.steps.len());
    }

    /// The synthetic budgeted side: online cut bit-identical to
    /// `segment_bounds_budgeted` AND every window field-identical, on
    /// both fixtures across page budgets that trigger page closes,
    /// step closes, and the degenerate huge budget.
    #[test]
    fn trace_stream_budgeted_cut_and_windows_match_offline() {
        for full in [spray_trace(), threaded_trace()] {
            for (max_steps, max_pages) in [(12, 2), (5, usize::MAX >> 1), (4, 1), (1, 3)] {
                let offline = segment_bounds_budgeted(&full, max_steps, max_pages);
                let mut cursor = crate::segment::SegmentCursor::new(&full);
                let mut stream = stream_of(&full, max_steps, max_pages);
                let mut online = Vec::new();
                while let Some((a, b)) = stream.next_window() {
                    online.push((a, b));
                    assert_windows_equal(&stream.side_note(), &cursor.side_note(a, b));
                }
                assert_eq!(
                    online, offline,
                    "cut diverged at budgets ({max_steps}, {max_pages})"
                );
            }
        }
    }

    /// Skipped windows must advance the carried state exactly like the
    /// cursor's skip-advance: assembling only the LAST window after
    /// skipping the rest yields the same window a full offline slice
    /// does — the sparse-probe pattern the measurement passes rely on.
    #[test]
    fn trace_stream_skips_windows_without_building_them() {
        let full = threaded_trace();
        let bounds = segment_bounds(full.steps.len(), 4);
        let (a, b) = bounds[2];
        let mut stream = stream_of(&full, 4, 0);
        while let Some(w) = stream.next_window() {
            if w == (a, b) {
                assert_windows_equal(&stream.side_note(), &segment_side_note(&full, a, b));
                return;
            }
        }
        panic!("stream never reached the probe window");
    }

    /// The comb-count metadata a probe pass keys on must equal what the
    /// assembled window derives — `fixed_base_calls()` is the no-assembly
    /// count of `ristretto_comb_calls` (the fixture routes one
    /// FixedBasepoint and one Variable record through window 1's slice
    /// group, so the count discriminates kinds, not records).
    #[test]
    fn trace_stream_fixed_base_calls_match_assembled_comb_calls() {
        let full = threaded_trace();
        let mut stream = stream_of(&full, 4, 0);
        let mut saw_comb_window = false;
        while stream.next_window().is_some() {
            let counted = stream.fixed_base_calls();
            let assembled = stream.side_note().ristretto_comb_calls.len();
            assert_eq!(counted, assembled);
            saw_comb_window |= counted > 0;
        }
        assert!(saw_comb_window, "fixture must contain a comb window");
    }

    /// The W2(a) equivalence bar, LIVE side: a real multi-window program
    /// (blake2b ECALLs at page-striding pointers, register-moving Add64s)
    /// pumped through [`TracingSource`] must cut and assemble exactly
    /// what the run-to-completion compact holder + cursor produce over an
    /// identical interpreter — pinning the live arrival plumbing (the
    /// step→ECALL-record association) the replay tests can't see.
    #[test]
    fn trace_stream_live_tracer_matches_offline_compact_path() {
        use crate::core::tracing::TracingPvm;
        use javm::instruction::Opcode;
        use javm::interpreter::Interpreter;

        let ecall_id = crate::core::tracing::ECALL_BLAKE2B_COMPRESS as u8;
        // Ecalli 100; (φ7 += φ11); Ecalli; add; Ecalli; Trap — h_ptr
        // strides one page per call so a small page budget cuts between
        // the calls, and each output lands where a later window's
        // entering image must carry it.
        let code = vec![
            Opcode::Ecalli as u8,
            ecall_id,
            Opcode::Add64 as u8,
            0x07 | (11 << 4),
            7,
            Opcode::Ecalli as u8,
            ecall_id,
            Opcode::Add64 as u8,
            0x07 | (11 << 4),
            7,
            Opcode::Ecalli as u8,
            ecall_id,
            Opcode::Trap as u8,
        ];
        let bitmask = vec![1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1];
        let mut regs = [0u64; NUM_REGS];
        regs[7] = 0x1000; // h_ptr — strides by φ[11] per Add64
        regs[8] = 0x100; // m_ptr — fixed
        regs[9] = 0; // t_low
        regs[10] = 1; // f flag
        regs[11] = 0x1000; // page stride
        let flat_mem = vec![0u8; 0x8000];
        let interp = || {
            Interpreter::new(
                code.clone(),
                bitmask.clone(),
                vec![],
                regs,
                flat_mem.clone(),
                10_000,
                25,
            )
        };

        // Offline: run to completion, hold the compact chain form.
        let mut tracing = TracingPvm::new(interp());
        let _ = tracing.run_with_vos_stubs();
        let blake2b_calls = tracing
            .blake2b_calls()
            .iter()
            .map(|c| crate::chips::blake2b::Blake2bCall {
                h: c.h,
                m: c.m,
                t: c.t,
                f: c.f,
            })
            .collect();
        let blake2b_mem_ops = std::mem::take(&mut tracing.blake2b_mem_ops);
        let (steps, initial_regs) = tracing.into_compact();
        assert_eq!(steps.len(), 6, "fixture shape drifted");
        let compact = crate::side_note::CompactTrace {
            steps,
            initial_regs,
            code: code.clone(),
            bitmask: bitmask.clone(),
            initial_memory: flat_mem.clone(),
            jump_table: vec![],
            blake2b_calls,
            blake2b_mem_ops,
            ristretto_calls: vec![],
            ristretto_mem_ops: vec![],
            ristretto_add_calls: vec![],
            ristretto_add_mem_ops: vec![],
            scalar_reduce_wide_calls: vec![],
            scalar_reduce_wide_mem_ops: vec![],
            scalar_binop_calls: vec![],
            scalar_binop_mem_ops: vec![],
        };

        for (seg_steps, page_budget) in [(2usize, 0usize), (6, 2), (4, 2)] {
            let offline = if page_budget == 0 {
                segment_bounds(compact.steps.len(), seg_steps)
            } else {
                segment_bounds_budgeted_compact(&compact, seg_steps, page_budget)
            };
            let mut cursor = crate::segment::CompactSegmentCursor::new(&compact);
            let mut stream = crate::segment::TraceStream::new(
                crate::segment::TracingSource::new(TracingPvm::new(interp())),
                code.clone(),
                bitmask.clone(),
                vec![],
                flat_mem.clone(),
                seg_steps,
                page_budget,
            );
            let mut online = Vec::new();
            let mut windows = Vec::new();
            while let Some((a, b)) = stream.next_window() {
                online.push((a, b));
                let via_stream = stream.side_note();
                assert_windows_equal(&via_stream, &cursor.side_note(a, b));
                windows.push(via_stream);
            }
            assert_eq!(
                online, offline,
                "live cut diverged at budgets ({seg_steps}, {page_budget})"
            );
            // Non-vacuity: a real multi-window chain whose later windows'
            // entering images carry the earlier blake2b outputs.
            assert!(windows.len() >= 2, "fixture must cut into a real chain");
            assert!(
                windows[0].blake2b_calls.len() == 1,
                "window 0 must hold the first blake2b call"
            );
            let out0 = windows[0].blake2b_mem_ops[0].out_bytes;
            assert_eq!(
                windows.last().unwrap().initial_memory[0x1000..0x1040],
                out0,
                "a later window's entering image must carry window 0's blake2b output"
            );
        }
    }
}
