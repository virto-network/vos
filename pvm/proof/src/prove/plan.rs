//! A kernel's run planned before any proof: its segments as the cut class's
//! budgets and the classes' page boundaries give them, the gas the run took,
//! and the most segments that gas buys.
//!
//! A window's page-boundary chips (the boundary compressions, the merges and
//! the listed pages' blocks) take rows its pages alone fix: their multiproof,
//! built from the window's side note without a trace. A class whose sizes do
//! not hold them is passed over before any trace is generated, and a window
//! no class holds is cut in half before any proving, so the plan counts what
//! the page boundary does to a run. Its other chips (the memory ledger, the
//! precompiles') are known only from their traces: a window one of them
//! overflows is cut again while proving ([`super::prove_kernel`]), each such
//! cut paid by the gas of the steps that fill the chip.

use alloc::vec::Vec;

use super::SegmentError;
use crate::chip_idx;
use crate::core::step::TraceStep;
use crate::segment::SegmentCursor;
use crate::shape::KernelShape;
use crate::side_note::SideNote;

/// The gas a run pays for each segment past its first: [`max_segments`].
///
/// A segment is a proof, its leaf and about a fold, whatever its steps; a
/// window is closed after 2^15 steps, or as soon as a step would take it
/// past the cut class's 8 pages. A run of steps fills its segments: the
/// in-tree kernels pay from about 100,000 gas a segment (a copy, a word a
/// step) to millions (the precompile loops). A run that loads from pages far
/// apart closes a window every few loads: about 50 gas a segment unrolled,
/// 200 in a loop [measured, x86 dev machine, 2026-11-18]. At 512 gas a
/// segment a run pays at least 64 gas for each page it brings into a
/// window: a page walk is refused, the copy keeps a margin of about ×200.
pub const SEGMENT_GAS: u64 = 512;

/// The most segments a run that took `gas` proves in: one, and one more for
/// each [`SEGMENT_GAS`]. A run past it is refused before any proof
/// ([`SegmentError::Segments`]).
pub const fn max_segments(gas: u64) -> usize {
    let more = gas / SEGMENT_GAS;
    if more >= usize::MAX as u64 {
        usize::MAX
    } else {
        1 + more as usize
    }
}

/// A segment of a planned run: its steps `[a, b)`, and the classes whose
/// step budget and page boundary hold it, bit `c` class `c`. It proves at the
/// first of them whose other chips hold it too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlannedSegment {
    pub steps: (usize, usize),
    pub classes: u8,
}

/// A kernel's run, planned: its segments in order, and the gas it took.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelPlan {
    pub segments: Vec<PlannedSegment>,
    /// The gas the run took: the gas entering its first step, less the gas
    /// left after its last, every block's and every precompile's price.
    pub gas: u64,
}

/// `full`, a kernel's whole run, planned under `shape` as [`super::prove_kernel`]
/// proves it: cut by class `cut`'s budgets, each window held by the classes
/// whose page boundary takes it and cut in half while none does, down to one
/// step. No trace is generated: each window's side note is built and its
/// page multiproof computed, host work in its pages and its memory image.
/// Refused as [`SegmentError::RunLength`] past [`super::MAX_RUN_STEPS`],
/// [`SegmentError::MalformedShape`] on a shape [`KernelShape::check`]
/// refuses or without class `cut`, [`SegmentError::Segments`] as soon as
/// its windows, or its windows and their halves, pass [`max_segments`] of
/// its gas (the windows counted before any multiproof), and
/// [`SegmentError::Shape`] on a step no class's page boundary holds.
pub fn plan_kernel<S: TraceStep>(
    full: &SideNote<S>,
    shape: &KernelShape,
    cut: usize,
) -> Result<KernelPlan, SegmentError> {
    shape.check().map_err(|_| SegmentError::MalformedShape)?;
    let class = shape.classes.get(cut).ok_or(SegmentError::MalformedShape)?;
    if full.steps.len() > super::MAX_RUN_STEPS {
        return Err(SegmentError::RunLength);
    }
    let gas = gas_used(&full.steps);
    let most = max_segments(gas);
    let bounds = crate::segment::segment_bounds_budgeted(
        full,
        1 << class.log_steps,
        usize::from(class.pages),
    );
    if bounds.len() > most {
        return Err(SegmentError::Segments);
    }
    let mut cursor = SegmentCursor::new(full);
    let mut segments = Vec::with_capacity(bounds.len());
    let mut counted = bounds.len();
    for (a, b) in bounds {
        let mut pending = alloc::vec![(a, b)];
        while let Some((a, b)) = pending.pop() {
            match holding(&mut cursor.side_note(a, b), b - a, shape) {
                Ok(classes) => segments.push(PlannedSegment {
                    steps: (a, b),
                    classes,
                }),
                Err(_) if b - a > 1 => {
                    counted += 1;
                    if counted > most {
                        return Err(SegmentError::Segments);
                    }
                    let middle = a + (b - a) / 2;
                    pending.push((middle, b));
                    pending.push((a, middle));
                }
                Err(error) => return Err(error),
            }
        }
    }
    Ok(KernelPlan { segments, gas })
}

/// The gas `steps` took: the gas entering the first, less the gas left
/// after the last.
fn gas_used<S: TraceStep>(steps: &[S]) -> u64 {
    match (steps.first(), steps.last()) {
        (Some(first), Some(last)) => {
            let (after, charged) = first.gas();
            (after + charged).saturating_sub(last.gas().0)
        }
        _ => 0,
    }
}

/// The rows of a compression in the boundary chip.
const COMPRESSION_ROWS: usize = 96;

/// The rows of a listed page in the page chip: its 32 blocks.
const PAGE_ROWS: usize = 32;

/// The page-boundary chips' log sizes `window`'s pages take, a window of
/// a run (its multiproof computed now when it is not yet).
pub(crate) fn page_sizes(window: &mut SideNote) -> [(usize, u32); 3] {
    use crate::trace::utils::ceil_log2_at_least_lanes as lanes;
    if window.memory_pages.is_none() {
        window.ingest_memory_pages();
    }
    let compressions = window.merkle_blake2b_calls.len();
    let (merges, pages) = window
        .memory_pages
        .as_ref()
        .map_or((0, 0), |pages| (pages.multiproof.merges.len(), pages.pages.len()));
    [
        (chip_idx::BLAKE2B_BOUNDARY, lanes(COMPRESSION_ROWS * compressions)),
        (chip_idx::MEMORY_MERKLE, lanes(merges)),
        (chip_idx::MEMORY_PAGE, lanes(PAGE_ROWS * pages)),
    ]
}

/// The classes of `shape` that hold `window`, a window of `steps` steps:
/// bit `c` when class `c` takes that many steps and its page-boundary
/// chips' sizes hold the window's. None: [`SegmentError::Shape`], its chip
/// the one the last class fitting the steps overflows (the CPU when none
/// does).
pub(crate) fn holding(
    window: &mut SideNote,
    steps: usize,
    shape: &KernelShape,
) -> Result<u8, SegmentError> {
    let log_steps = steps.next_power_of_two().trailing_zeros();
    let sizes = page_sizes(window);
    let mut classes = 0u8;
    let mut overflow = chip_idx::CPU;
    for (index, class) in shape.classes.iter().enumerate() {
        if log_steps > u32::from(class.log_steps) {
            continue;
        }
        let over = sizes.iter().find(|&&(chip, size)| {
            let position = (shape.components & ((1 << chip) - 1)).count_ones() as usize;
            class
                .log_sizes
                .get(position)
                .is_none_or(|&pinned| size > u32::from(pinned))
        });
        match over {
            Some(&(chip, _)) => overflow = chip,
            None => classes |= 1 << index,
        }
    }
    if classes == 0 {
        return Err(SegmentError::Shape {
            chip: overflow,
            overflow: true,
        });
    }
    Ok(classes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::step::{MemAccess, NUM_REGS, PvmStep};
    use vos_pvm::instruction::Opcode;

    /// A store of a word at `address`, at `ts`.
    fn store(ts: u64, address: u32) -> PvmStep {
        PvmStep {
            timestamp: ts,
            pc: 0,
            opcode: Opcode::StoreU64,
            skip_len: 0,
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
            mem_write: Some(MemAccess {
                address,
                value: ts,
                size: 8,
            }),
            gas_after: 0,
            gas_charged: 0,
            next_pc: 0,
            host_call_acknowledged: false,
            witness: None,
            exit: false,
        }
    }

    /// The page-boundary chips' sizes the plan computes are their traces',
    /// for pages near and far apart, written once and twice.
    #[test]
    fn the_page_sizes_are_the_traces() {
        for (stride, seeded) in [(1u32, false), (97, true), (4093, false), (4093, true)] {
            let page = |i: u32| i * stride + 16;
            let pages = (0..8u32)
                .filter(|_| seeded)
                .map(|i| crate::SparseMemoryPage {
                    page_index: page(i),
                    bytes: [i as u8 + 1; crate::SPARSE_MEMORY_PAGE_SIZE],
                })
                .collect();
            let image = crate::SparseMemoryImage::new(1 << 32, pages).expect("an image");
            let steps: Vec<PvmStep> = (0..16u32)
                .map(|i| store(u64::from(i) + 1, page(i % 8) << 12))
                .collect();
            let mut window = SideNote::new(steps, vec![Opcode::Trap as u8], vec![1])
                .with_sparse_memory(image)
                .with_memory_layout(crate::memory_layout::MemoryLayout::writable());
            let sizes = page_sizes(&mut window);
            for (chip, size) in sizes {
                let trace = crate::BASE_COMPONENTS[chip].generate_component_trace_min(&mut window, 0);
                assert_eq!(trace.log_size(), size, "chip {chip} at stride {stride}, {seeded}");
            }
        }
    }
}
