//! Trace segmentation: slice a fully-traced `SideNote` into bounded
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
//! timestamp, memory root). Each segment's verification binds those fields
//! to the committed boundary columns (`boundary_binding`):
//!   - pc/timestamp columns are pinned to the trace by CpuChip's
//!     program-execution chaining;
//!   - register columns are pinned to the trace by the register ledger's
//!     read-consistency (a cross-row `prev_value` binding, a `(reg, ts)`
//!     sortedness gadget and an `is_write` limb; gate:
//!     `tests/ledger_readconsistency_gate.rs`);
//!   - `memory_root` is the page-Merkle root the boundary multiproof binds
//!     in-circuit (`Memory{Page,Merkle,RootBoundary}Chip`).
//! `verify_chain` itself is a host-side capability: it consumes
//! prover-derived `SideNote`s. The side-note-free trust boundary is the
//! verifier crate's `verify_chain_standalone`.
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
    use crate::core::tracing::Blake2bMemOp;
    use crate::side_note::SideNote;
    use alloc::collections::BTreeSet;
    use alloc::vec::Vec;

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
        let mut cb = 0;
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        for step in &full.steps {
            let ts = step.timestamp;
            ranges.clear();
            step_ranges(step, &mut ranges);
            take_at(
                &full.blake2b_mem_ops,
                &mut cb,
                ts,
                |o| o.ts,
                |o| blake2b_op_ranges(o, &mut ranges),
            );

            let (before, after) = cutter.feed(&ranges);
            bounds.extend(before);
            bounds.extend(after);
        }
        bounds.extend(cutter.finish());
        bounds
    }

    /// The step's own touched ranges: its optional memory read + write.
    fn step_ranges(s: &PvmStep, out: &mut Vec<(u32, u32)>) {
        if let Some(r) = &s.mem_read {
            out.push((r.address, r.size as u32));
        }
        if let Some(w) = &s.mem_write {
            out.push((w.address, w.size as u32));
        }
        if let Some(w) = &s.witness {
            out.push((w.address, w.bytes.len() as u32));
        }
    }

    // Per-stream touched ranges of one precompile op.
    fn blake2b_op_ranges(o: &Blake2bMemOp, out: &mut Vec<(u32, u32)>) {
        out.push((o.h_ptr, o.h_bytes.len() as u32));
        out.push((o.m_ptr, o.m_bytes.len() as u32));
    }

    /// The incremental budgeted-cut decision behind
    /// [`segment_bounds_budgeted`]. Feed each step's touched ranges in
    /// order; the cutter reports the window(s) the step closed. Page
    /// accounting mirrors [`crate::page_merkle::touched_pages`] (same
    /// `add_range` granularity).
    struct BudgetedCutter {
        max_steps: usize,
        max_pages: usize,
        pages: BTreeSet<u32>,
        /// Start of the currently accumulating window.
        a: usize,
        /// Index the next fed step will occupy.
        next: usize,
    }

    type ClosedWindows = (Option<(usize, usize)>, Option<(usize, usize)>);

    impl BudgetedCutter {
        /// Panics if either budget is zero.
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
        fn feed(&mut self, ranges: &[(u32, u32)]) -> ClosedWindows {
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
    /// - the captured BLAKE2b precompile records, a parallel
    ///   `call ↔ mem_op` pair, filtered to those whose `mem_op.ts` lies in
    ///   the segment's timestamp window `[steps[a].ts, steps[b].ts)`;
    /// - `jump_table` (program-static, shared by all segments).
    ///
    /// Lookup-multiplicity counts are NOT carried: the chips re-derive them
    /// from the segment's steps during `prove`.
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
        // (`step.mem_write`) AND precompile output writes (blake2b's
        // `blake2b_mem_ops`), which are NOT recorded in
        // `step.mem_write`. Missing the precompile writes leaves stale bytes
        // at their output addresses, so a later segment's read of an
        // earlier-segment precompile result fails the memory-ledger
        // read-consistency check (`is_read · (value − prev) = 0`).
        if full.sparse_initial_memory.is_some() {
            let mem = replay_sparse_writes(full, Some(full.steps[a].timestamp));
            build_sparse_segment(full, a, b, mem)
        } else {
            let mem = replay_writes(full, Some(full.steps[a].timestamp));
            build_segment(full, a, b, mem)
        }
    }

    /// Assemble the segment `SideNote` for `[a, b)` from `full` and the
    /// already-reconstructed entering memory image `mem`. Shared by
    /// [`segment_side_note`] (per-call prefix replay) and [`SegmentCursor`]
    /// (threaded image), so the two produce identical segments by
    /// construction — only the provenance of `mem` differs.
    fn build_segment(full: &SideNote, a: usize, b: usize, mem: Vec<u8>) -> SideNote {
        build_segment_with_memory(full, a, b, SegmentMemory::Dense(mem))
    }

    fn build_sparse_segment(
        full: &SideNote,
        a: usize,
        b: usize,
        mem: crate::SparseMemoryImage,
    ) -> SideNote {
        build_segment_with_memory(full, a, b, SegmentMemory::Sparse(mem))
    }

    fn build_segment_with_memory(
        full: &SideNote,
        a: usize,
        b: usize,
        mem: SegmentMemory,
    ) -> SideNote {
        let ts_lo = full.steps[a].timestamp;
        let ts_hi = full.steps.get(b).map(|s| s.timestamp).unwrap_or(u64::MAX);
        let in_window = move |ts: u64| ts >= ts_lo && ts < ts_hi;

        let sn = SideNote::new(
            full.steps[a..b].to_vec(),
            full.code.to_vec(),
            full.bitmask.to_vec(),
        )
        .with_jump_table(full.jump_table.to_vec())
        .with_initial_regs(full.steps[a].regs_before);
        let sn = match full.memory_layout() {
            Some(layout) => sn.with_memory_layout(layout),
            None => sn,
        };
        let mut sn = match mem {
            SegmentMemory::Dense(memory) => sn.with_memory(memory),
            SegmentMemory::Sparse(memory) => sn.with_sparse_memory(memory),
        };

        let (bc, bm) = filter_pair(&full.blake2b_calls, &full.blake2b_mem_ops, |m| {
            in_window(m.ts)
        });
        sn.blake2b_calls = bc;
        sn.blake2b_mem_ops = bm;

        sn
    }

    /// Replay a `SideNote`'s memory writes over its initial image, in
    /// timestamp order, and return the resulting flat memory. `ts_upper`:
    /// `Some(t)` applies only writes with `ts < t` (the memory state
    /// ENTERING step `t`); `None` applies all writes (the FINAL memory).
    ///
    /// Crucially this includes **precompile output writes** (blake2b's
    /// 64-byte hash at `h_ptr`), which the per-step
    /// `mem_write` does NOT capture — they live in the `*_mem_ops` records.
    /// Used both for a segment's threaded initial memory (`segment_side_note`)
    /// and its final memory commitment (`prove`'s boundary state); the two
    /// MUST agree or `verify_chain`'s boundary-continuity check rejects.
    pub(crate) fn replay_writes(side_note: &SideNote, ts_upper: Option<u64>) -> Vec<u8> {
        let writes = collect_writes(side_note, ts_upper);
        let mut mem = side_note.initial_memory.clone();
        apply_writes(&mut mem, writes);
        mem
    }

    /// Replay writes over a canonical sparse entering image. This is the
    /// Refine proof path's equivalent of [`replay_writes`] and never grows a
    /// dense vector to a high guest address.
    pub(crate) fn replay_sparse_writes(
        side_note: &SideNote,
        ts_upper: Option<u64>,
    ) -> crate::SparseMemoryImage {
        let mut image = side_note
            .sparse_initial_memory
            .clone()
            .expect("sparse replay requires a sparse entering image");
        apply_sparse_writes(&mut image, collect_writes(side_note, ts_upper));
        image
    }

    enum SegmentMemory {
        Dense(Vec<u8>),
        Sparse(crate::SparseMemoryImage),
    }

    fn collect_writes(side_note: &SideNote, ts_upper: Option<u64>) -> Vec<PendingWrite> {
        let keep = |ts: u64| ts_upper.is_none_or(|t| ts < t);
        let mut writes = Vec::new();
        for step in &side_note.steps {
            if keep(step.timestamp) {
                writes_of_step(step, &mut writes);
            }
        }
        for op in &side_note.blake2b_mem_ops {
            if keep(op.ts) {
                writes.push(write_of_bytes(op.ts, op.h_ptr, &op.out_bytes));
            }
        }
        writes
    }

    /// One memory write pending replay: `(ts, addr, 64-byte buffer, len)`.
    /// A fixed buffer avoids a heap allocation per write; 64 = blake2b's
    /// output, the widest write.
    type PendingWrite = (u64, u32, [u8; 64], u8);

    /// The step's regular store, and the bytes a witness-input call
    /// wrote, a buffer's worth a write, as pending writes.
    fn writes_of_step(s: &PvmStep, out: &mut Vec<PendingWrite>) {
        if let Some(w) = &s.mem_write {
            let sz = w.size as usize;
            let mut buf = [0u8; 64];
            buf[..sz].copy_from_slice(&w.value.to_le_bytes()[..sz]);
            out.push((s.timestamp, w.address, buf, sz as u8));
        }
        if let Some(w) = &s.witness {
            for (index, chunk) in w.bytes.chunks(64).enumerate() {
                let address = w.address + 64 * index as u32;
                out.push(write_of_bytes(s.timestamp, address, chunk));
            }
        }
    }

    /// A precompile output write (blake2b's 64 bytes at `h_ptr`) or a
    /// witness input's piece as a pending write.
    fn write_of_bytes(ts: u64, addr: u32, out: &[u8]) -> PendingWrite {
        let mut buf = [0u8; 64];
        buf[..out.len()].copy_from_slice(out);
        (ts, addr, buf, out.len() as u8)
    }

    /// Sort pending writes by timestamp and apply them over `mem`, growing
    /// it when a write lands past the current end. Each timestamp has one
    /// write (a step is either a regular store or exactly one ECALL
    /// precompile), or a witness input's disjoint pieces, so sorting by ts
    /// yields a well-defined replay order with later writes overwriting
    /// earlier.
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

    fn apply_sparse_writes(image: &mut crate::SparseMemoryImage, mut writes: Vec<PendingWrite>) {
        writes.sort_by_key(|write| write.0);
        for (_timestamp, address, bytes, len) in writes {
            assert!(
                image.write(address, &bytes[..len as usize]),
                "proof trace write lies outside its sparse memory span"
            );
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
    /// Equivalence: the segment assembly is `build_segment`, the same
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
        mem: SegmentMemory,
        /// Exclusive timestamp bound of the writes already applied.
        applied_upto: u64,
        /// Index of the first step not yet applied to `mem`.
        steps_at: usize,
        /// Index of the first BLAKE2b output write not yet applied to `mem`.
        blake2b_at: usize,
    }

    impl<'a> SegmentCursor<'a> {
        /// Start a pass over `full`'s windows from its initial memory.
        pub fn new(full: &'a SideNote) -> Self {
            let mem = full.sparse_initial_memory.as_ref().map_or_else(
                || SegmentMemory::Dense(full.initial_memory.clone()),
                |image| SegmentMemory::Sparse(image.clone()),
            );
            Self {
                full,
                mem,
                applied_upto: 0,
                steps_at: 0,
                blake2b_at: 0,
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
            match &self.mem {
                SegmentMemory::Dense(memory) => build_segment(self.full, a, b, memory.clone()),
                SegmentMemory::Sparse(memory) => {
                    build_sparse_segment(self.full, a, b, memory.clone())
                }
            }
        }

        /// Apply every not-yet-applied write with `ts < ts_lo` to the
        /// carried image. Stream enumeration order mirrors
        /// [`replay_writes`] (steps, then the precompile output
        /// stream); [`apply_writes`] then applies the batch in ts order.
        fn advance_to(&mut self, ts_lo: u64) {
            let full = self.full;
            let mut writes: Vec<PendingWrite> = Vec::new();
            while let Some(s) = full.steps.get(self.steps_at) {
                if s.timestamp >= ts_lo {
                    break;
                }
                writes_of_step(s, &mut writes);
                self.steps_at += 1;
            }
            while let Some(m) = full.blake2b_mem_ops.get(self.blake2b_at) {
                if m.ts >= ts_lo {
                    break;
                }
                writes.push(write_of_bytes(m.ts, m.h_ptr, &m.out_bytes));
                self.blake2b_at += 1;
            }
            match &mut self.mem {
                SegmentMemory::Dense(memory) => apply_writes(memory, writes),
                SegmentMemory::Sparse(memory) => apply_sparse_writes(memory, writes),
            }
            self.applied_upto = ts_lo;
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
pub use prover::{SegmentCursor, segment_bounds_budgeted, segment_side_note};
#[cfg(feature = "prover")]
pub(crate) use prover::{replay_sparse_writes, replay_writes};

#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::*;
    use crate::core::step::{MemAccess, NUM_REGS, PvmStep};
    use crate::page_merkle;
    use crate::side_note::SideNote;
    use vos_pvm::instruction::Opcode;

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
            mem_write: write.map(|(address, size)| MemAccess {
                address,
                value: 0,
                size,
            }),
            gas_after: 0,
            gas_charged: 0,
            next_pc: 0,
            host_call_acknowledged: false,
            witness: None,
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

    /// 12 steps (ts 1..=12) + a BLAKE2b compression in each window, laid
    /// out so a 4-step cut ([0,4) [4,8) [8,12)) threads precompile output
    /// writes across both window boundaries:
    ///   - window 0: at ts 2 (output at 4090 — PAST the 4096-byte image, so
    ///     the entering images of windows 1 and 2 must carry
    ///     `replay_writes`' resize growth);
    ///   - window 1: at ts 5, output at 0x180;
    ///   - window 2: at ts 9 (slice-only — no later window observes its
    ///     write).
    /// Regular stores carry distinct non-zero values, so a missed or
    /// misplaced write/slice can't vanish into an all-zero image. The
    /// register history is CONSISTENT (a non-zero seeded file threaded
    /// through per-step `reg_write`s that rotate across indices, with one
    /// no-write step and one taken branch), so every step has a distinct
    /// file.
    fn threaded_trace() -> SideNote {
        use crate::chips::blake2b::Blake2bCall;
        use crate::core::tracing::Blake2bMemOp;

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

        // One compression in each window: ts 2, 5 and 9.
        for (ts, h_ptr, seed) in [(2, 4090, 0xA0u8), (5, 0x180, 0x30), (9, 0x2C0, 0x60)] {
            sn.blake2b_calls.push(Blake2bCall {
                h: [1; 8],
                m: [2; 16],
                t: 3,
                f: true,
            });
            sn.blake2b_mem_ops.push(Blake2bMemOp {
                h_ptr,
                m_ptr: 0x300,
                ts,
                h_bytes: [5; 64],
                m_bytes: [6; 128],
                out_bytes: core::array::from_fn(|i| seed ^ i as u8),
            });
        }
        sn
    }

    /// Field-by-field equality of the two slicing paths over every field
    /// `segment_side_note` populates: the sliced steps, the entering image
    /// (raw bytes — both paths apply the identical write set, so even
    /// `replay_writes`' resize growth must agree byte-for-byte, no
    /// root-level indirection needed), the entering registers, the
    /// filtered call/mem-op streams, the program-static fields and the
    /// range-check counts.
    fn assert_windows_equal(via_cursor: &SideNote, via_slice: &SideNote) {
        assert_eq!(via_cursor.steps, via_slice.steps);
        assert_eq!(via_cursor.code, via_slice.code);
        assert_eq!(via_cursor.bitmask, via_slice.bitmask);
        assert_eq!(via_cursor.initial_memory, via_slice.initial_memory);
        assert_eq!(
            via_cursor.sparse_initial_memory,
            via_slice.sparse_initial_memory
        );
        assert_eq!(via_cursor.initial_regs, via_slice.initial_regs);
        assert_eq!(via_cursor.jump_table, via_slice.jump_table);
        assert_eq!(via_cursor.jump_table_counts, via_slice.jump_table_counts);
        assert_eq!(via_cursor.blake2b_calls, via_slice.blake2b_calls);
        assert_eq!(via_cursor.blake2b_mem_ops, via_slice.blake2b_mem_ops);
        assert_eq!(via_cursor.range256_counts, via_slice.range256_counts);
        assert_eq!(via_cursor.memory_layout(), via_slice.memory_layout());
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
        // ...and window 2's entering image sees window 1's output too,
        // but not its own.
        let w2 = segment_side_note(&full, 8, 12);
        let second_out: [u8; 64] = core::array::from_fn(|i| 0x30 ^ i as u8);
        assert_eq!(w2.initial_memory[0x180..0x1C0], second_out);
        assert_eq!(w2.initial_memory[0x2C0..0x300], [0u8; 64]);
    }

    #[test]
    fn sparse_direct_cursor_and_chain_roots_match_at_high_pages() {
        let mut full = threaded_trace();
        let high_page_index = (u32::MAX as usize / crate::SPARSE_MEMORY_PAGE_SIZE) as u32;
        let mut high_page = crate::SparseMemoryPage {
            page_index: high_page_index,
            bytes: [0; crate::SPARSE_MEMORY_PAGE_SIZE],
        };
        high_page.bytes[crate::SPARSE_MEMORY_PAGE_SIZE - 8] = 0x5a;
        full.initial_memory.clear();
        full.sparse_initial_memory = Some(
            crate::SparseMemoryImage::new(1u64 << 32, vec![high_page])
                .expect("canonical high sparse image"),
        );

        let bounds = segment_bounds(full.steps.len(), 4);
        let mut cursor = SegmentCursor::new(&full);
        let mut previous_root = None;
        for &(start, end) in &bounds {
            let direct = segment_side_note(&full, start, end);
            let via_cursor = cursor.side_note(start, end);
            assert_windows_equal(&direct, &via_cursor);
            assert!(direct.initial_memory.is_empty());
            assert_eq!(
                direct
                    .sparse_initial_memory
                    .as_ref()
                    .expect("sparse segment")
                    .byte(u32::MAX - 7),
                0x5a
            );
            let direct_proof = page_merkle::segment_multiproof(&direct);
            let cursor_proof = page_merkle::segment_multiproof(&via_cursor);
            assert_eq!(direct_proof, cursor_proof);
            if let Some(root) = previous_root {
                assert_eq!(root, direct_proof.root_before);
            }
            previous_root = Some(direct_proof.root_after);
        }
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
}
