//! A segment's `SideNote`: its steps, records and entering memory image.

use alloc::vec::Vec;

use crate::core::step::PvmStep;
use crate::side_note::SideNote;

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
/// chain's windows use [`SegmentCursor`](super::SegmentCursor), which threads the memory image
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
/// [`segment_side_note`] (per-call prefix replay) and [`SegmentCursor`](super::SegmentCursor)
/// (threaded image), so the two produce identical segments by
/// construction — only the provenance of `mem` differs.
pub(super) fn build_segment(full: &SideNote, a: usize, b: usize, mem: Vec<u8>) -> SideNote {
    build_segment_with_memory(full, a, b, SegmentMemory::Dense(mem))
}

pub(super) fn build_sparse_segment(
    full: &SideNote,
    a: usize,
    b: usize,
    mem: crate::SparseMemoryImage,
) -> SideNote {
    build_segment_with_memory(full, a, b, SegmentMemory::Sparse(mem))
}

fn build_segment_with_memory(full: &SideNote, a: usize, b: usize, mem: SegmentMemory) -> SideNote {
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

pub(super) enum SegmentMemory {
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
    for op in &side_note.poseidon2_ops {
        if keep(op.ts) {
            writes.push(write_of_bytes(op.ts, op.out_ptr, &op.output));
        }
    }
    writes
}

/// One memory write pending replay: `(ts, addr, 64-byte buffer, len)`.
/// A fixed buffer avoids a heap allocation per write; 64 = blake2b's
/// output, the widest write.
pub(super) type PendingWrite = (u64, u32, [u8; 64], u8);

/// The step's regular store, and the bytes a witness-input call
/// wrote, a buffer's worth a write, as pending writes.
pub(super) fn writes_of_step(s: &PvmStep, out: &mut Vec<PendingWrite>) {
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
pub(super) fn write_of_bytes(ts: u64, addr: u32, out: &[u8]) -> PendingWrite {
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
pub(super) fn apply_writes(mem: &mut Vec<u8>, mut writes: Vec<PendingWrite>) {
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

pub(super) fn apply_sparse_writes(
    image: &mut crate::SparseMemoryImage,
    mut writes: Vec<PendingWrite>,
) {
    writes.sort_by_key(|write| write.0);
    for (_timestamp, address, bytes, len) in writes {
        assert!(
            image.write(address, &bytes[..len as usize]),
            "proof trace write lies outside its sparse memory span"
        );
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
