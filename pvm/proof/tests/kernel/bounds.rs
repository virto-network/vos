//! The steps a run's trace and its proof take, bounded before either.

use vos_pvm_compiler::assembler::{Assembler, Reg};
use vos_pvm_proof::kernel::{KernelTraceError, trace_kernel, trace_kernel_within};
use vos_pvm_proof::segment::SegmentCursor;
use vos_pvm_proof::{MAX_RUN_STEPS, SegmentError};

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
