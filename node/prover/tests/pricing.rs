//! A statement's proof, priced by the gas its attest paid: a run is planned
//! before anything is proved, and one that takes more segments than its
//! gas buys (`vos_pvm_proof::max_segments`) is refused for good before the
//! kernel's program is computed; a run within it plans as the prover cuts
//! it, at the attest's unchanged charge.

use vos_abi::ids::ProgramHash;
use vos_abi::result::{Attest, KernelReturn};
use vos_node_prover::masked::{MaskedProver, plan};
use vos_node_prover::{Prover, RERUN_GAS, StatementError};
use vos_pvm_compiler::assembler::{Assembler, Reg};
use vos_pvm_proof::kernel::trace_kernel;
use vos_pvm_proof::{SEGMENT_GAS, max_segments};

/// `build` at the heap's base, which a program of no read-only data lays
/// out wherever its code is.
fn at_heap(build: impl Fn(u64) -> Vec<u8>) -> Vec<u8> {
    let base = vos_pvm_program::parse_standard_program(&build(0))
        .and_then(|program| Some(program.layout(&[])?.rw.base))
        .expect("a standard program");
    build(base)
}

/// The run's end: an empty output, the io-hash of a statement of no parts
/// in φ9 to φ12, and a return to the halt address.
fn halt(asm: &mut Assembler) {
    let io_hash = KernelReturn {
        public_args: Vec::new(),
        output: Vec::new(),
        roots: Vec::new(),
    }
    .io_hash();
    for (register, word) in [Reg::A2, Reg::A3, Reg::A4, Reg::A5]
        .into_iter()
        .zip(io_hash.chunks_exact(8))
    {
        asm.load_imm_64(register, u64::from_le_bytes(word.try_into().unwrap()));
    }
    for register in [Reg::A0, Reg::A1, Reg::T0, Reg::T2, Reg::S0, Reg::S1] {
        asm.load_imm(register, 0);
    }
    asm.jump_ind(Reg::RA, 0);
}

/// `rounds` blocks of 64 loads, each from a page `stride` pages past the
/// last: a window closed every eight loads, for a few gas each.
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

/// The record a live run of `blob` on no witness makes.
fn attest(blob: &[u8]) -> Attest {
    Attest {
        program: ProgramHash::of(blob),
        window: None,
        witness_input: Vec::new(),
        output: Vec::new(),
        public_args: Vec::new(),
        roots: Vec::new(),
    }
}

/// A kernel loading from pages far apart takes a segment for a few gas: its
/// plan passes what its gas buys, and the prover refuses its record for good
/// at the plan, before the kernel's program (its classes' roots and leaf
/// circuits) is computed.
#[test]
fn a_page_walk_past_its_gas_is_refused_before_any_proving() {
    let blob = page_walk(16, 1000);
    let run = trace_kernel(&blob, &[], RERUN_GAS)
        .expect("halts")
        .side_note;
    let refused = StatementError::Rerun("the run takes more segments than its gas buys");
    assert_eq!(plan(&blob, &run).err(), Some(refused.clone()));
    let started = std::time::Instant::now();
    assert_eq!(
        MaskedProver::new().prove(&blob, &attest(&blob)).err(),
        Some(refused)
    );
    // Computing the kernel's program alone takes seconds.
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

/// A copy, a word a step, pays far more gas a segment than a segment's
/// price: its plan holds, cut as the prover cuts it, within the segments
/// its gas buys, at the attest's charge as before (its kernel's gas).
#[test]
fn a_copy_is_priced_by_its_gas_as_before() {
    let blob = copy(64);
    let trace = trace_kernel(&blob, &[], RERUN_GAS).expect("halts");
    let plan = plan(&blob, &trace.side_note).expect("the run's gas buys its segments");
    assert!(plan.segments.len() > 1, "{} segments", plan.segments.len());
    assert!(plan.segments.len() <= max_segments(plan.gas));
    assert!(plan.gas / plan.segments.len() as u64 > 100 * SEGMENT_GAS);
}
