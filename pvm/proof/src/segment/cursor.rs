//! The streaming segment driver.

use alloc::vec::Vec;

use crate::side_note::SideNote;

use super::window::{
    PendingWrite, SegmentMemory, apply_sparse_writes, apply_writes, build_segment,
    build_sparse_segment, write_of_bytes, writes_of_step,
};

/// Streaming segment driver: yields [`segment_side_note`](super::segment_side_note)-identical
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
/// order, the same invariant [`segment_bounds_budgeted`](super::segment_bounds_budgeted) leans on.
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
            SegmentMemory::Sparse(memory) => build_sparse_segment(self.full, a, b, memory.clone()),
        }
    }

    /// Apply every not-yet-applied write with `ts < ts_lo` to the
    /// carried image. Stream enumeration order mirrors
    /// [`replay_writes`](super::replay_writes) (steps, then the precompile output
    /// stream); [`apply_writes`](super::window::apply_writes) then applies the batch in ts order.
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
