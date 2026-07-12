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
pub use prover::{segment_bounds_budgeted, segment_side_note};

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
}
