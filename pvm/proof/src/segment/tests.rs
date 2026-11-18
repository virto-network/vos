use super::*;
use crate::core::step::{CompactStep, MemAccess, NUM_REGS, PvmStep, WitnessWrite};
use crate::page_merkle;
use crate::side_note::SideNote;
use vos_pvm::instruction::Opcode;

/// Split `[0, total)` into consecutive `[a, b)` ranges of at most
/// `max_steps` steps each (the last may be shorter). Panics if
/// `max_steps == 0`. Returns an empty vec when `total == 0`.
fn segment_bounds(total: usize, max_steps: usize) -> Vec<(usize, usize)> {
    assert!(max_steps > 0, "max_steps must be non-zero");
    let mut bounds = Vec::new();
    let mut a = 0;
    while a < total {
        let b = (a + max_steps).min(total);
        bounds.push((a, b));
        a = b;
    }
    bounds
}

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
///     write);
/// and a Poseidon2 call in windows 0 and 1, at ts 3 and 7, and a
/// witness-input call writing 70 bytes at ts 6.
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
        // ts 6: a witness-input call, writing 70 bytes (two pieces).
        if ts == 6 {
            s.host_call_acknowledged = true;
            s.witness = Some(Box::new(WitnessWrite {
                address: 0x400,
                bytes: (0..70).map(|i| 0x40 ^ i as u8).collect(),
            }));
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
    // A Poseidon2 call in each of the first two windows: ts 3 and 7.
    for (ts, out_ptr, seed) in [(3, 0x200, 0x11u8), (7, 0x240, 0x22)] {
        sn.poseidon2_ops.push(crate::core::tracing::Poseidon2Op {
            in_ptr: 0x340,
            out_ptr,
            ts,
            input: [7; 64],
            output: core::array::from_fn(|i| seed ^ i as u8),
        });
    }
    sn
}

/// Field-by-field equality of two windows over every field a window
/// carries: the sliced steps, the entering image (raw bytes — both paths
/// apply the identical write set, so even `replay_writes`' resize growth
/// must agree byte-for-byte, no root-level indirection needed), the
/// entering registers, the filtered call/mem-op streams, the
/// program-static fields, and the counts, entries and payloads a proof
/// fills later, all still empty.
fn assert_windows_equal(left: &SideNote, right: &SideNote) {
    assert_eq!(left.steps, right.steps);
    assert_eq!(left.code, right.code);
    assert_eq!(left.bitmask, right.bitmask);
    assert_eq!(left.initial_memory, right.initial_memory);
    assert_eq!(left.sparse_initial_memory, right.sparse_initial_memory);
    assert_eq!(left.initial_regs, right.initial_regs);
    assert_eq!(left.final_regs, right.final_regs);
    assert_eq!(left.jump_table, right.jump_table);
    assert_eq!(left.jump_table_counts, right.jump_table_counts);
    assert_eq!(left.blake2b_calls, right.blake2b_calls);
    assert_eq!(left.blake2b_mem_ops, right.blake2b_mem_ops);
    assert_eq!(left.poseidon2_ops, right.poseidon2_ops);
    assert_eq!(left.merkle_blake2b_calls, right.merkle_blake2b_calls);
    assert_eq!(left.merkle_blake2b_mults, right.merkle_blake2b_mults);
    assert_eq!(left.range256_counts, right.range256_counts);
    assert_eq!(left.bitwise_and_counts, right.bitwise_and_counts);
    assert_eq!(left.bitwise_and_byte_counts, right.bitwise_and_byte_counts);
    assert_eq!(left.power_of_two_counts, right.power_of_two_counts);
    assert_eq!(left.popcount_counts, right.popcount_counts);
    assert_eq!(left.bitcount_counts, right.bitcount_counts);
    assert_eq!(left.byte_to_bits_counts, right.byte_to_bits_counts);
    assert_eq!(left.program_memory_counts, right.program_memory_counts);
    assert_eq!(left.num_initial_mem_entries, right.num_initial_mem_entries);
    assert_eq!(left.closing_chip_active, right.closing_chip_active);
    assert_eq!(left.cpu_rows_local, right.cpu_rows_local);
    assert_eq!(left.memory_layout(), right.memory_layout());
    for window in [left, right] {
        assert!(window.mul_entries.is_empty() && window.bitwise_entries.is_empty());
        assert!(window.compare_entries.is_empty() && window.divrem_entries.is_empty());
        assert!(window.memory_pages.is_none() && window.device.is_none());
    }
}

/// A window as it is built without sharing or partition points: the
/// steps' own `regs_before`, the program's code, bitmask and jump table
/// copied, and every precompile record tested against the window by its
/// timestamp. The oracle the windows are held to.
fn copied_window(full: &SideNote, a: usize, b: usize) -> SideNote {
    let ts_lo = full.steps[a].timestamp;
    let ts_hi = full.steps.get(b).map(|s| s.timestamp).unwrap_or(u64::MAX);
    let in_window = |ts: u64| ts >= ts_lo && ts < ts_hi;
    let sn = SideNote::new(
        full.steps[a..b].to_vec(),
        full.code.to_vec(),
        full.bitmask.to_vec(),
    )
    .with_jump_table(full.jump_table.to_vec())
    .with_initial_regs(full.steps[a].regs_before)
    .with_memory(replay_writes(full, Some(ts_lo)));
    let mut sn = match full.memory_layout() {
        Some(layout) => sn.with_memory_layout(layout),
        None => sn,
    };
    for (call, op) in full.blake2b_calls.iter().zip(&full.blake2b_mem_ops) {
        if in_window(op.ts) {
            sn.blake2b_calls.push(call.clone());
            sn.blake2b_mem_ops.push(op.clone());
        }
    }
    sn.poseidon2_ops = full
        .poseidon2_ops
        .iter()
        .filter(|op| in_window(op.ts))
        .cloned()
        .collect();
    sn
}

/// `full`'s run as the tracer records it: its steps compact, its register
/// file entering them in `initial_regs`.
fn compact(full: &SideNote) -> SideNote<CompactStep> {
    let mut run = SideNote::new(
        full.steps.iter().map(PvmStep::to_compact).collect(),
        full.code.to_vec(),
        full.bitmask.to_vec(),
    )
    .with_jump_table(full.jump_table.to_vec())
    .with_initial_regs(full.steps[0].regs_before)
    .with_memory(full.initial_memory.clone());
    run.blake2b_calls = full.blake2b_calls.clone();
    run.blake2b_mem_ops = full.blake2b_mem_ops.clone();
    run.poseidon2_ops = full.poseidon2_ops.clone();
    run
}

/// Every window of the threaded trace, cut on and just after each of its
/// register writes, its witness-input call, its BLAKE2b and Poseidon2
/// calls and its stores, built four ways — sliced from the full steps,
/// sliced from the compact ones, by a cursor over each — is the copied
/// window; its code, bitmask and jump table are its run's own allocations.
#[test]
fn windows_at_every_cut_are_the_copied_construction() {
    let full = threaded_trace();
    assert_eq!(compact(&full).expand().steps, full.steps);
    let run = compact(&full);
    let n = full.steps.len();
    for a in 0..n {
        for b in a + 1..=n {
            let oracle = copied_window(&full, a, b);
            let from_full = segment_side_note(&full, a, b);
            let from_run = segment_side_note(&run, a, b);
            assert_windows_equal(&from_full, &oracle);
            assert_windows_equal(&from_run, &oracle);
            assert!(alloc::sync::Arc::ptr_eq(&from_full.code, &full.code));
            assert!(alloc::sync::Arc::ptr_eq(&from_full.bitmask, &full.bitmask));
            assert!(alloc::sync::Arc::ptr_eq(
                &from_full.jump_table,
                &full.jump_table
            ));
            assert!(alloc::sync::Arc::ptr_eq(&from_run.code, &run.code));
            // A cursor's pass: `[0, a)`, then `[a, b)`, then `[b, n)`.
            let mut over_full = SegmentCursor::new(&full);
            let mut over_run = SegmentCursor::new(&run);
            for (lo, hi) in [(0, a), (a, b), (b, n)] {
                if lo < hi {
                    let oracle = copied_window(&full, lo, hi);
                    assert_windows_equal(&over_full.side_note(lo, hi), &oracle);
                    assert_windows_equal(&over_run.side_note(lo, hi), &oracle);
                }
            }
        }
    }
    // Non-vacuity: the cuts split each kind of step from its neighbours.
    let witness = full.steps.iter().position(|s| s.witness.is_some());
    assert_eq!(witness, Some(5));
    assert!(full.steps.iter().filter(|s| s.reg_write.is_some()).count() > 6);
    let entering = segment_side_note(&run, 6, 12);
    assert_eq!(
        entering.initial_memory[0x400..0x446],
        full.steps[5].witness.as_ref().unwrap().bytes[..]
    );
    assert_ne!(entering.initial_regs, full.steps[0].regs_before);
}

/// A window's records are sliced by partition points, so a stream out of
/// timestamp order is refused rather than sliced wrongly.
#[test]
#[should_panic(expected = "out of timestamp order")]
fn unsorted_records_are_refused() {
    let mut full = threaded_trace();
    full.poseidon2_ops.swap(0, 1);
    let _ = SegmentCursor::new(&full);
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
    // The Poseidon2 calls' outputs likewise: window 1 enters with window
    // 0's and not its own, window 2 with both; each window holds its own
    // call alone.
    let first_p2: [u8; 32] = core::array::from_fn(|i| 0x11 ^ i as u8);
    let second_p2: [u8; 32] = core::array::from_fn(|i| 0x22 ^ i as u8);
    assert_eq!(w1.initial_memory[0x200..0x220], first_p2);
    assert_eq!(w1.initial_memory[0x240..0x260], [0u8; 32]);
    assert_eq!(w2.initial_memory[0x240..0x260], second_p2);
    assert_eq!(w1.poseidon2_ops.len(), 1);
    assert_eq!(w1.poseidon2_ops[0].ts, 7);
    assert!(w2.poseidon2_ops.is_empty());
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
