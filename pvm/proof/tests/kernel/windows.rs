//! A kernel's run cut on, and just after, each kind of step a window's
//! entering state carries across its boundary: a witness-input call (its
//! bytes in memory), a load (its register write), a Poseidon2 call and a
//! BLAKE2b compression (their outputs in memory). Each window of the run as
//! the tracer records it, its steps expanded from the register file
//! entering it, is the window of the run expanded whole; the windows prove,
//! and their chain verifies against the kernel's program.

use crate::common;

use vos_abi::ids::{MethodId, ProgramHash};
use vos_abi::records::Kernel;
use vos_pvm_compiler::assembler::{Assembler, Reg};
use vos_pvm_proof::core::ecall::{ECALL_BLAKE2B_COMPRESS, ECALL_POSEIDON2, ECALL_WITNESS_INPUT};
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::kernel::trace_kernel;
use vos_pvm_proof::program_id::{KernelEntry, KernelProgram};
use vos_pvm_proof::segment::SegmentCursor;
use vos_pvm_proof::{Proof, SegmentError, SideNote, prove_shaped};
use vos_pvm_proof_verifier::verify_kernel_chain;

const ITERATIONS: i32 = 2;

/// Each iteration: eight witness bytes read onto the stack, loaded into
/// T0 and added into T1, the sum stored, a Poseidon2 call over the stack's
/// first 64 bytes and a BLAKE2b compression of the next; then the io-hash
/// set and an empty output.
fn blob() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_heap_pages(1).set_stack_pages(4);
    asm.add_imm_64(Reg::S0, Reg::SP, -0x1000)
        .load_imm(Reg::T1, 0)
        .load_imm(Reg::T2, 0)
        .fallthrough();
    let start = asm.current_offset();
    asm.add_imm_64(Reg::A0, Reg::S0, 576)
        .load_imm(Reg::A1, 8)
        .ecalli(ECALL_WITNESS_INPUT)
        .load_ind_u64(Reg::T0, Reg::S0, 576)
        .add_64(Reg::T1, Reg::T1, Reg::T0)
        .store_ind_u64(Reg::T1, Reg::S0, 512)
        .move_reg(Reg::A0, Reg::S0)
        .move_reg(Reg::A1, Reg::S0)
        .ecalli(ECALL_POSEIDON2)
        .add_imm_64(Reg::A0, Reg::S0, 128)
        .add_imm_64(Reg::A1, Reg::S0, 256)
        .load_imm(Reg::A2, 128)
        .load_imm(Reg::A3, 1)
        .ecalli(ECALL_BLAKE2B_COMPRESS)
        .add_imm_64(Reg::T2, Reg::T2, 1);
    let here = asm.current_offset();
    asm.branch_lt_u_imm(Reg::T2, ITERATIONS, start.wrapping_sub(here));
    for (register, word) in [Reg::A2, Reg::A3, Reg::A4, Reg::A5]
        .into_iter()
        .zip([0x11, 0x22, 0x33, 0x44])
    {
        asm.load_imm(register, word);
    }
    for register in [Reg::A0, Reg::A1, Reg::T0, Reg::T1, Reg::T2, Reg::S0] {
        asm.load_imm(register, 0);
    }
    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

fn witness() -> Vec<u8> {
    (1..=8 * ITERATIONS as u8).collect()
}

fn program(blob: &[u8]) -> KernelProgram {
    let record = Kernel {
        method: MethodId(1),
        program: ProgramHash::of(blob),
        image_root: vos_pvm_program::parse_standard_program(blob)
            .and_then(|program| program.image_root())
            .expect("a standard program"),
        shape: vos_pvm_compiler::shape::kernel_shape(blob).expect("a standard program"),
    };
    common::kernel_program(blob, &record, &SEGMENT)
}

/// `window` proved at the first class of `program` that holds it.
fn proved(program: &KernelProgram, window: impl Fn() -> SideNote) -> Proof {
    for class in 0..program.shape.classes.len() {
        let shape = program.shape.segment(class).expect("a class");
        match prove_shaped(&mut window(), &shape, &SEGMENT) {
            Ok(proof) => return proof,
            Err(SegmentError::Shape { overflow: true, .. }) => continue,
            Err(error) => panic!("the window does not prove: {error:?}"),
        }
    }
    panic!("no class holds the window")
}

/// The windows `cuts` make of `0..steps`.
fn windows(cuts: &[usize], steps: usize) -> Vec<(usize, usize)> {
    let mut points = vec![0];
    points.extend(cuts.iter().copied().filter(|&cut| 0 < cut && cut < steps));
    points.push(steps);
    points.dedup();
    points.windows(2).map(|pair| (pair[0], pair[1])).collect()
}

fn assert_same_window(compact: &SideNote, expanded: &SideNote) {
    assert_eq!(compact.steps, expanded.steps);
    assert_eq!(compact.initial_regs, expanded.initial_regs);
    assert_eq!(
        compact.sparse_initial_memory,
        expanded.sparse_initial_memory
    );
    assert_eq!(compact.blake2b_calls, expanded.blake2b_calls);
    assert_eq!(compact.blake2b_mem_ops, expanded.blake2b_mem_ops);
    assert_eq!(compact.poseidon2_ops, expanded.poseidon2_ops);
    assert_eq!(compact.memory_layout(), expanded.memory_layout());
}

#[test]
fn windows_cut_at_each_kind_of_step_prove_and_chain() {
    let blob = blob();
    let program = program(&blob);
    let entry = KernelEntry::of(&program, &blob).expect("the kernel's entry");
    let run = trace_kernel(&blob, &witness(), 1_000_000)
        .expect("halts")
        .side_note;
    let full = trace_kernel(&blob, &witness(), 1_000_000)
        .expect("halts")
        .side_note
        .expand();
    let steps = full.steps.len();
    assert_eq!(run.steps.len(), steps);
    let at_ts = |ts: u64| {
        full.steps
            .iter()
            .position(|step| step.timestamp == ts)
            .expect("the call's step")
    };
    let read = full
        .steps
        .iter()
        .position(|step| step.witness.is_some())
        .expect("a witness read");
    let load = read + 1;
    assert!(full.steps[load].mem_read.is_some() && full.steps[load].reg_write.is_some());
    let poseidon2 = at_ts(full.poseidon2_ops[0].ts);
    let blake2b = at_ts(full.blake2b_mem_ops[0].ts);
    let kinds = [read, load, poseidon2, blake2b];

    for after in [0, 1] {
        let cuts: Vec<usize> = kinds.iter().map(|&step| step + after).collect();
        let windows = windows(&cuts, steps);
        assert!(windows.len() >= 4, "{windows:?}");
        let mut over_run = SegmentCursor::new(&run);
        let mut over_full = SegmentCursor::new(&full);
        let mut proofs = Vec::new();
        for &(a, b) in &windows {
            let window = over_run.side_note(a, b);
            assert_same_window(&window, &over_full.side_note(a, b));
            assert_eq!(window.initial_regs, full.steps[a].regs_before);
            proofs.push(proved(&program, || {
                SegmentCursor::new(&run).side_note(a, b)
            }));
        }
        let registers = verify_kernel_chain(proofs, &program, &entry).expect("the chain verifies");
        assert_eq!(&registers[9..13], &[0x11, 0x22, 0x33, 0x44]);
    }
}
