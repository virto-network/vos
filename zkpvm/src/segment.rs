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
//!     memory-continuity work in `docs/plans/proving-time.md`).
//! Independently, `verify_chain` itself is a HOST-SIDE capability, not a
//! trust-boundary check: it consumes prover-derived `SideNote`s and
//! anchors no per-segment program commitment. Making it a trust boundary
//! (a side-note-free `verify_chain_standalone`) is the
//! chain-verification work in `docs/plans/succinct-merkle-witness.md`.
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
        assert!(max_steps > 0, "max_steps must be non-zero");
        assert!(max_pages > 0, "max_pages must be non-zero");
        let total = full.steps.len();
        let mut bounds = Vec::new();
        if total == 0 {
            return bounds;
        }

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

        let (mut cb, mut cr, mut ca, mut cw, mut cs) = (0, 0, 0, 0, 0);
        let mut pages: BTreeSet<u32> = BTreeSet::new();
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        let mut a = 0;
        for i in 0..total {
            let step = &full.steps[i];
            let ts = step.timestamp;
            ranges.clear();
            if let Some(r) = &step.mem_read {
                ranges.push((r.address, r.size as u32));
            }
            if let Some(w) = &step.mem_write {
                ranges.push((w.address, w.size as u32));
            }
            take_at(&full.blake2b_mem_ops, &mut cb, ts, |o| o.ts, |o| {
                ranges.push((o.h_ptr, o.h_bytes.len() as u32));
                ranges.push((o.m_ptr, o.m_bytes.len() as u32));
            });
            take_at(&full.ristretto_mem_ops, &mut cr, ts, |o| o.ts, |o| {
                ranges.push((o.scalar_ptr, o.scalar_bytes.len() as u32));
                ranges.push((o.point_ptr, o.point_bytes.len() as u32));
                ranges.push((o.output_ptr, o.out_bytes.len() as u32));
            });
            take_at(&full.ristretto_add_mem_ops, &mut ca, ts, |o| o.ts, |o| {
                ranges.push((o.p_ptr, o.p_bytes.len() as u32));
                ranges.push((o.q_ptr, o.q_bytes.len() as u32));
                ranges.push((o.output_ptr, o.out_bytes.len() as u32));
            });
            take_at(&full.scalar_reduce_wide_mem_ops, &mut cw, ts, |o| o.ts, |o| {
                ranges.push((o.wide_ptr, o.wide_bytes.len() as u32));
                ranges.push((o.output_ptr, o.out_bytes.len() as u32));
            });
            take_at(&full.scalar_binop_mem_ops, &mut cs, ts, |o| o.ts, |o| {
                ranges.push((o.a_ptr, o.a_bytes.len() as u32));
                ranges.push((o.b_ptr, o.b_bytes.len() as u32));
                ranges.push((o.output_ptr, o.out_bytes.len() as u32));
            });

            for &(addr, len) in &ranges {
                crate::page_merkle::add_range(&mut pages, addr, len);
            }
            // Step i busts the page budget: close the window BEFORE it (the
            // window keeps at least one step, so a lone oversize step still
            // segments) and restart the page set from step i's own ranges.
            if pages.len() > max_pages && i > a {
                bounds.push((a, i));
                a = i;
                pages.clear();
                for &(addr, len) in &ranges {
                    crate::page_merkle::add_range(&mut pages, addr, len);
                }
            }
            if i + 1 - a == max_steps || i + 1 == total {
                bounds.push((a, i + 1));
                a = i + 1;
                pages.clear();
            }
        }
        bounds
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
        let ts_lo = full.steps[a].timestamp;
        let ts_hi = full.steps.get(b).map(|s| s.timestamp).unwrap_or(u64::MAX);
        let in_window = move |ts: u64| ts >= ts_lo && ts < ts_hi;

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
    fn write_of_step(s: &PvmStep) -> Option<PendingWrite> {
        s.mem_write.as_ref().map(|w| {
            let sz = w.size as usize;
            let mut buf = [0u8; 64];
            buf[..sz].copy_from_slice(&w.value.to_le_bytes()[..sz]);
            (s.timestamp, w.address, buf, sz as u8)
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
        /// Per-stream index of the first entry not yet applied to `mem`.
        steps_at: usize,
        blake2b_at: usize,
        ristretto_at: usize,
        ristretto_add_at: usize,
        scalar_reduce_wide_at: usize,
        scalar_binop_at: usize,
    }

    impl<'a> SegmentCursor<'a> {
        /// Start a pass over `full`'s windows from its initial memory.
        pub fn new(full: &'a SideNote) -> Self {
            Self {
                full,
                mem: full.initial_memory.clone(),
                applied_upto: 0,
                steps_at: 0,
                blake2b_at: 0,
                ristretto_at: 0,
                ristretto_add_at: 0,
                scalar_reduce_wide_at: 0,
                scalar_binop_at: 0,
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
            drain_stream(
                &full.blake2b_mem_ops,
                &mut self.blake2b_at,
                ts_lo,
                |m| write_of_bytes(m.ts, m.h_ptr, &m.out_bytes),
                |m| m.ts,
                &mut writes,
            );
            drain_stream(
                &full.ristretto_mem_ops,
                &mut self.ristretto_at,
                ts_lo,
                |m| write_of_bytes(m.ts, m.output_ptr, &m.out_bytes),
                |m| m.ts,
                &mut writes,
            );
            drain_stream(
                &full.ristretto_add_mem_ops,
                &mut self.ristretto_add_at,
                ts_lo,
                |m| write_of_bytes(m.ts, m.output_ptr, &m.out_bytes),
                |m| m.ts,
                &mut writes,
            );
            drain_stream(
                &full.scalar_reduce_wide_mem_ops,
                &mut self.scalar_reduce_wide_at,
                ts_lo,
                |m| write_of_bytes(m.ts, m.output_ptr, &m.out_bytes),
                |m| m.ts,
                &mut writes,
            );
            drain_stream(
                &full.scalar_binop_mem_ops,
                &mut self.scalar_binop_at,
                ts_lo,
                |m| write_of_bytes(m.ts, m.output_ptr, &m.out_bytes),
                |m| m.ts,
                &mut writes,
            );
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
pub use prover::{SegmentCursor, segment_bounds_budgeted, segment_side_note};

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
    /// Regular stores carry distinct non-zero values and each step a
    /// distinct register file, so a missed or misplaced write/slice can't
    /// vanish into an all-zero image.
    fn threaded_trace() -> SideNote {
        use crate::chips::blake2b::Blake2bCall;
        use crate::core::tracing::{
            Blake2bMemOp, RistrettoMemOp, RistrettoPointAddMemOp, RistrettoPointAddRecord,
            RistrettoRecord, ScalarBinopMemOp, ScalarBinopRecord, ScalarMultKind,
            ScalarReduceWideMemOp, ScalarReduceWideRecord,
        };

        let mut steps = Vec::new();
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
            s.regs_before[1] = 100 + ts;
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
}
