//! What a run may make the prover do, bounded before any proof: the
//! segments its gas buys, the classes a window's pages pass over untraced,
//! and the steps a trace and a proof take.

use vos_abi::ids::{MethodId, ProgramHash};
use vos_abi::records::Kernel;
use vos_pvm_compiler::assembler::{Assembler, Reg};
use vos_pvm_proof::chip_idx;
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::kernel::{KernelTraceError, trace_kernel, trace_kernel_within};
use vos_pvm_proof::segment::{SegmentCursor, segment_bounds_budgeted};
use vos_pvm_proof::shape::KernelShape;
use vos_pvm_proof::{
    MAX_RUN_STEPS, SEGMENT_GAS, SegmentError, max_segments, plan_kernel, prove_kernel, prove_shaped,
};

/// `build` at the heap's base, which a program of no read-only data lays
/// out wherever its code is.
fn at_heap(build: impl Fn(u64) -> Vec<u8>) -> Vec<u8> {
    let base = vos_pvm_program::parse_standard_program(&build(0))
        .and_then(|program| Some(program.layout(&[])?.rw.base))
        .expect("a standard program");
    build(base)
}

/// The run's end: an empty output and a return to the halt address.
fn halt(asm: &mut Assembler) {
    for register in [Reg::A0, Reg::A1, Reg::T0, Reg::T2, Reg::S0, Reg::S1] {
        asm.load_imm(register, 0);
    }
    asm.jump_ind(Reg::RA, 0);
}

/// `rounds` blocks of 64 loads, each from a page `stride` pages past the
/// last: a window closed every eight loads, for about six gas each.
fn page_walk(rounds: i32, stride: i32) -> Vec<u8> {
    at_heap(|base| {
        let mut asm = Assembler::new();
        asm.set_heap_pages((64 * stride) as u32 + 1)
            .set_stack_pages(1);
        asm.load_imm_64(Reg::S0, base)
            .load_imm(Reg::T2, 0)
            .fallthrough();
        let start = asm.current_offset();
        for page in 0..64 {
            asm.load_ind_u64(Reg::T0, Reg::S0, page * stride * 4096);
        }
        asm.add_imm_64(Reg::T2, Reg::T2, 1);
        let here = asm.current_offset();
        asm.branch_lt_u_imm(Reg::T2, rounds, start.wrapping_sub(here))
            .fallthrough();
        halt(&mut asm);
        asm.build()
    })
}

/// Two passes over `pages` pages `stride` pages apart, each storing a
/// word of its own into every page: the second pass rewrites pages the
/// first made nonzero, each its own, so no leaf of a window's multiproof
/// is another's or its own before and after. A count to `work` first pays
/// for the run's segments.
fn rewrite(pages: i32, stride: i32, work: i32) -> Vec<u8> {
    at_heap(|base| {
        let mut asm = Assembler::new();
        asm.set_heap_pages((pages * stride) as u32 + 1)
            .set_stack_pages(1);
        asm.load_imm(Reg::T2, 0).fallthrough();
        let start = asm.current_offset();
        asm.add_imm_64(Reg::T2, Reg::T2, 1);
        let here = asm.current_offset();
        asm.branch_lt_u_imm(Reg::T2, work, start.wrapping_sub(here))
            .fallthrough();
        for pass in 0..2 {
            asm.load_imm_64(Reg::S0, base)
                .load_imm(Reg::T2, 1000 * pass)
                .fallthrough();
            let start = asm.current_offset();
            asm.store_ind_u64(Reg::T2, Reg::S0, 0)
                .add_imm_64(Reg::S0, Reg::S0, stride * 4096)
                .add_imm_64(Reg::T2, Reg::T2, 1);
            let here = asm.current_offset();
            asm.branch_lt_u_imm(Reg::T2, 1000 * pass + pages, start.wrapping_sub(here))
                .fallthrough();
        }
        halt(&mut asm);
        asm.build()
    })
}

/// A copy of `pages` pages to the pages after them, a word a step.
fn copy(pages: i32) -> Vec<u8> {
    at_heap(|base| {
        let mut asm = Assembler::new();
        asm.set_heap_pages(2 * pages as u32 + 1).set_stack_pages(1);
        asm.load_imm_64(Reg::S0, base)
            .load_imm_64(Reg::S1, base + pages as u64 * 4096)
            .load_imm(Reg::T2, 0)
            .fallthrough();
        let start = asm.current_offset();
        asm.load_ind_u64(Reg::T0, Reg::S0, 0)
            .store_ind_u64(Reg::T0, Reg::S1, 0)
            .add_imm_64(Reg::S0, Reg::S0, 8)
            .add_imm_64(Reg::S1, Reg::S1, 8)
            .add_imm_64(Reg::T2, Reg::T2, 1);
        let here = asm.current_offset();
        asm.branch_lt_u_imm(Reg::T2, pages * 512, start.wrapping_sub(here));
        halt(&mut asm);
        asm.build()
    })
}

fn record(blob: &[u8]) -> Kernel {
    Kernel {
        method: MethodId(1),
        program: ProgramHash::of(blob),
        image_root: vos_pvm_program::parse_standard_program(blob)
            .and_then(|program| program.image_root())
            .expect("a standard program"),
        shape: vos_pvm_compiler::shape::kernel_shape(blob).expect("a standard program"),
    }
}

fn shape(blob: &[u8]) -> KernelShape {
    KernelShape::try_from(&record(blob).shape).expect("an install's shape")
}

/// The class a run is cut by: the 32k one.
const CUT: usize = 1;

/// A kernel that loads from pages far apart closes a window every eight
/// loads, a segment proof for about 50 gas: its windows pass the segments
/// its gas buys, and the run is refused before any multiproof or proof.
#[test]
fn a_page_walk_is_refused_before_any_proof() {
    let blob = page_walk(16, 1000);
    let shape = shape(&blob);
    let run = trace_kernel(&blob, &[], 1 << 40).expect("halts").side_note;
    let class = &shape.classes[CUT];
    let windows =
        segment_bounds_budgeted(&run, 1 << class.log_steps, usize::from(class.pages)).len();
    let started = std::time::Instant::now();
    let refused = prove_kernel(&run, &shape, CUT, &SEGMENT);
    eprintln!(
        "{} steps, {windows} windows for {} segments' gas, refused in {:?}",
        run.steps.len(),
        max_segments(windows as u64 * 52),
        started.elapsed()
    );
    assert!(matches!(refused, Err(SegmentError::Segments)));
    assert!(matches!(
        plan_kernel(&run, &shape, CUT),
        Err(SegmentError::Segments)
    ));
    assert_eq!(windows, 128);
}

/// A window of eight pages far apart, each nonzero before it and rewritten
/// in it, takes the page boundary past both 8-page classes: the plan holds
/// it to the 24-page class alone, so proving passes over the two others
/// untraced, where a trace generated at each would refuse it.
#[test]
fn far_apart_rewritten_pages_pass_over_both_eight_page_classes() {
    let blob = rewrite(16, 4000, 1000);
    let shape = shape(&blob);
    let run = trace_kernel(&blob, &[], 1 << 40).expect("halts").side_note;
    let plan = plan_kernel(&run, &shape, CUT).expect("the run's gas buys its segments");
    let classes: Vec<u8> = plan
        .segments
        .iter()
        .map(|segment| segment.classes)
        .collect();
    assert_eq!(classes, [0b111, 0b111, 0b100, 0b100]);

    // The same window, traced at the 32k class: its boundary compressions
    // refuse it, after a whole trace's generation.
    let (a, b) = plan.segments[2].steps;
    let mut cursor = SegmentCursor::new(&run);
    let started = std::time::Instant::now();
    let traced = prove_shaped(
        &mut cursor.side_note(a, b),
        &shape.segment(CUT).expect("a class"),
        &SEGMENT,
    );
    let traced_took = started.elapsed();
    assert!(matches!(
        traced,
        Err(SegmentError::Shape {
            chip: chip_idx::BLAKE2B_BOUNDARY,
            overflow: true
        })
    ));
    let started = std::time::Instant::now();
    let replanned = plan_kernel(&run, &shape, CUT).expect("a plan");
    eprintln!(
        "a class refused by its trace: {traced_took:?}; the whole run planned, {} windows: {:?}",
        replanned.segments.len(),
        started.elapsed()
    );
}

/// The in-tree workloads keep a margin over the segments their gas buys:
/// a copy, a word a step, pays about 100,000 gas a segment, 200 times
/// [`SEGMENT_GAS`].
#[test]
fn a_copy_keeps_its_margin() {
    let blob = copy(64);
    let run = trace_kernel(&blob, &[], 1 << 40).expect("halts").side_note;
    let plan = plan_kernel(&run, &shape(&blob), CUT).expect("a plan");
    let per_segment = plan.gas / plan.segments.len() as u64;
    eprintln!(
        "{} steps, {} gas, {} segments: {per_segment} gas a segment",
        run.steps.len(),
        plan.gas,
        plan.segments.len()
    );
    assert!(per_segment >= 100 * SEGMENT_GAS);
}

/// A kernel that only returns: its few gas buy its one segment.
#[test]
fn a_run_of_one_segment_is_always_bought() {
    assert_eq!(max_segments(0), 1);
    let blob = vos_pvm_program::build_standard_program(&vos_pvm_program::StandardProgram {
        ro_data: vec![],
        rw_data: vec![],
        heap_pages: 1,
        stack_size: 4096,
        code: vos_pvm_program::CodeBlob {
            jump_table: vec![],
            code: vec![50, 0],
            bitmask: vec![1, 0],
        },
    })
    .expect("a standard program");
    let run = trace_kernel(&blob, &[], 1_000).expect("halts").side_note;
    let plan = plan_kernel(&run, &shape(&blob), CUT).expect("a plan");
    assert_eq!(plan.segments.len(), 1);
    assert!(plan.gas < SEGMENT_GAS);
}

/// A trace held to fewer steps than its run takes stops there and is
/// refused; held to its steps, it traces whole.
#[test]
fn a_trace_is_held_to_its_steps() {
    let blob = copy(1);
    let steps = trace_kernel(&blob, &[], 1 << 40)
        .expect("halts")
        .side_note
        .steps
        .len();
    assert!(matches!(
        trace_kernel_within(&blob, &[], 1 << 40, steps - 1),
        Err(KernelTraceError::Steps)
    ));
    assert!(trace_kernel_within(&blob, &[], 1 << 40, steps).is_ok());
}

/// A segment ending at the longest run's last step proves and verifies:
/// its ledgers' widest gap, from a `ts = 0` write to the closing read,
/// fits their bits. One step later the run is refused before any trace,
/// where the ordering delta's fill would have panicked.
#[test]
fn a_run_past_the_ledgers_bound_is_refused_before_any_trace() {
    let blob = copy(1);
    let run = trace_kernel(&blob, &[], 1 << 40).expect("halts").side_note;
    let steps = run.steps.len();
    let window = |last: usize| {
        let mut window = SegmentCursor::new(&run).side_note(steps - 4, steps);
        let shift = last as u64 - window.steps.last().expect("a step").timestamp;
        for step in &mut window.steps {
            step.timestamp += shift;
        }
        window
    };
    let mut at = window(MAX_RUN_STEPS);
    let proof = vos_pvm_proof::prove(&mut at).expect("proves at the bound");
    vos_pvm_proof::verify(proof, &at).expect("verifies at the bound");
    let mut past = window(MAX_RUN_STEPS + 1);
    assert!(matches!(
        vos_pvm_proof::prove(&mut past),
        Err(SegmentError::RunLength)
    ));
}
