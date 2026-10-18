//! Content-budgeted segment bounds.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::core::step::PvmStep;
use crate::side_note::SideNote;

use crate::core::tracing::Blake2bMemOp;

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
