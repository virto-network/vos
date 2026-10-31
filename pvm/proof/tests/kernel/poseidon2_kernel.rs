//! A node kernel making the Poseidon2 call (`0x402`) beside BLAKE2b's, as
//! format 41 admits it: its shape holds the Poseidon2 chip and takes the
//! chip's classes (`vos_pvm_compiler::shape::POSEIDON2_CLASSES`), its run
//! proves through segments with the page boundary, each segment's calls its
//! own and the outputs of earlier ones in its entering memory, its chain
//! verifies against its program and states its io-hash, and its segments
//! verify in their leaves within the recursion's padded shape. On a node
//! segment the chip's forgeries are refused: an output not the
//! permutation's, an input word at or above p, a call without its row.

use crate::common;

use vos_pvm_compiler::assembler::{Assembler, Reg};
use vos_pvm_proof::SideNote;
use vos_pvm_proof::chip_idx;
use vos_pvm_proof::core::ecall::{ECALL_BLAKE2B_COMPRESS, ECALL_POSEIDON2, ECALL_WITNESS_INPUT};
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::kernel::trace_kernel;
use vos_pvm_proof::program_id::KernelEntry;
use vos_pvm_proof::{Proof, prove_kernel};
use vos_pvm_proof_verifier::{verify_kernel_chain, verify_kernel_segment};
use vos_wire::ids::{MethodId, ProgramHash};
use vos_wire::records::Kernel;

/// The Poseidon2 calls the kernel chains.
const CALLS: i32 = 1_500;

/// The kernel: 64 witness bytes onto its stack, then [`CALLS`] Poseidon2
/// calls, each over the 64 bytes and writing its 32 over their first half,
/// then a BLAKE2b compression of the 64 bytes as its state and the next 128
/// as its message, its io-hash φ9..12 set and its output empty.
fn blob() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_heap_pages(1).set_stack_pages(1);
    asm.add_imm_64(Reg::S0, Reg::SP, -512)
        .move_reg(Reg::A0, Reg::S0)
        .load_imm(Reg::A1, 64)
        .ecalli(ECALL_WITNESS_INPUT)
        .load_imm(Reg::T2, 0);
    let start = asm.current_offset();
    asm.move_reg(Reg::A0, Reg::S0)
        .move_reg(Reg::A1, Reg::S0)
        .ecalli(ECALL_POSEIDON2)
        .add_imm_64(Reg::T2, Reg::T2, 1);
    let here = asm.current_offset();
    asm.branch_lt_u_imm(Reg::T2, CALLS, start.wrapping_sub(here))
        .move_reg(Reg::A0, Reg::S0)
        .add_imm_64(Reg::A1, Reg::S0, 64)
        .load_imm(Reg::A2, 128)
        .load_imm(Reg::A3, 1)
        .ecalli(ECALL_BLAKE2B_COMPRESS);
    for (register, word) in [Reg::A2, Reg::A3, Reg::A4, Reg::A5]
        .into_iter()
        .zip([0x11, 0x22, 0x33, 0x44])
    {
        asm.load_imm(register, word);
    }
    for register in [Reg::A0, Reg::A1, Reg::T2, Reg::S0] {
        asm.load_imm(register, 0);
    }
    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

/// A witness: sixteen words below p.
fn witness() -> Vec<u8> {
    (0..16u32)
        .flat_map(|i| (0x1234_5678u32.wrapping_mul(i + 1) & 0x7fff_fffe).to_le_bytes())
        .collect()
}

/// The kernel's run.
fn run(blob: &[u8]) -> SideNote {
    trace_kernel(blob, &witness(), 100_000_000)
        .expect("halts")
        .side_note
}

/// The kernel's install record, its shape the derivation's.
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

/// The kernel's shape holds the Poseidon2 chip beside BLAKE2b's, at the
/// chip's classes, and every class's leaf fits the padded shape; its run
/// proves in several segments of class 0, each verified against its
/// program and in its leaf, and the chain states its io-hash.
#[test]
fn a_node_kernels_poseidon2_calls_prove_through_segments() {
    let blob = blob();
    let record = record(&blob);
    let shape = &record.shape;
    let p2 = 1 << chip_idx::POSEIDON2 | 1 << chip_idx::BLAKE2B;
    assert_eq!(shape.chips & p2, p2, "{:#x}", shape.chips);
    let classes: Vec<(u8, u16)> = shape
        .classes
        .iter()
        .map(|class| (class.log_steps, class.pages))
        .collect();
    assert_eq!(classes, vos_pvm_compiler::shape::POSEIDON2_CLASSES);
    for class in &shape.classes {
        let rows = vos_pvm_compiler::leaf::leaf_rows(shape.chips, &class.log_sizes);
        assert!(
            rows.iter()
                .zip(vos_pvm_compiler::leaf::PADDED)
                .all(|(&rows, padded)| rows <= padded),
            "{rows:?}"
        );
        eprintln!(
            "class ({}, {}): leaf {rows:?}",
            class.log_steps, class.pages
        );
    }

    let (program, entry) = vos_pvm_recair::leaf::kernel_program(
        &blob,
        &record,
        vos_pvm_compiler::TRANSPILER_VERSION,
        &SEGMENT,
    )
    .expect("the kernel's program");
    assert_eq!(entry, KernelEntry::of(&program, &blob).unwrap());
    let full = run(&blob);
    assert_eq!(full.poseidon2_ops.len(), CALLS as usize);
    let segments = prove_kernel(&full, &program.shape, 0, &SEGMENT).expect("proves");
    assert!(segments.len() >= 2, "{} segments", segments.len());
    let fold_word = vos_pvm_proof::poseidon2::P2Hash(core::array::from_fn(|i| {
        stwo::core::fields::m31::BaseField::from(9_000 + i as u32)
    }));
    for (position, segment) in segments.iter().enumerate() {
        assert_eq!(
            verify_kernel_segment(segment.proof.clone(), &program).unwrap(),
            segment.class
        );
        assert_ne!(segment.proof.component_mask & 1 << chip_idx::POSEIDON2, 0);
        if position < 2 {
            let leaf = common::prove_leaf(
                &program,
                &entry,
                segment.class,
                &segment.proof,
                position as u32,
                fold_word,
            );
            eprintln!(
                "segment {position}: steps {:?}, class {}, leaf {:?} rows",
                segment.steps, segment.class, leaf.rows
            );
        }
    }
    let proofs: Vec<Proof> = segments.into_iter().map(|segment| segment.proof).collect();
    let registers = verify_kernel_chain(proofs, &program, &entry).expect("the chain verifies");
    assert_eq!(&registers[9..13], &[0x11, 0x22, 0x33, 0x44]);
}

/// A forged run proved over the full chip set is refused, by the prover or
/// by the verifier.
fn refused(mut side_note: SideNote, what: &str) {
    let rejected = match vos_pvm_proof::prove(&mut side_note) {
        Err(_) => true,
        Ok(proof) => vos_pvm_proof::verify(proof, &side_note).is_err(),
    };
    assert!(rejected, "SOUNDNESS GAP: {what} verified on a node segment");
}

/// The kernel's run up to its first call and the two steps after it: a
/// segment holding that call alone.
fn short_run() -> SideNote {
    let full = run(&blob());
    let first = full.poseidon2_ops[0].ts;
    let end = full
        .steps
        .iter()
        .position(|step| step.timestamp > first)
        .expect("steps past the first call")
        + 2;
    let side_note = vos_pvm_proof::segment::SegmentCursor::new(&full).side_note(0, end);
    assert_eq!(side_note.poseidon2_ops.len(), 1);
    side_note
}

/// The honest segment proves; its first call's output byte changed (the
/// ledger's write with it) is refused.
#[test]
fn a_poseidon2_output_not_the_permutations_is_refused_on_a_node_segment() {
    let mut honest = short_run();
    let proof = vos_pvm_proof::prove(&mut honest).expect("proves");
    vos_pvm_proof::verify(proof, &honest).expect("verifies");
    let mut forged = short_run();
    forged.poseidon2_ops[0].output[0] ^= 1;
    refused(forged, "a Poseidon2 output not the permutation's");
}

/// The run with its first call's first input word `word`: the witness
/// input's bytes and the call's, its output the permutation's of the word
/// as the field reads it, so only the word's range is wrong.
fn with_input_word(word: u32) -> SideNote {
    use vos_pvm_poseidon2::{M31, N_STATE, P};
    let mut side_note = short_run();
    let bytes = word.to_le_bytes();
    let step = side_note
        .steps
        .iter_mut()
        .find(|step| step.witness.is_some())
        .expect("the witness input's step");
    step.witness.as_mut().expect("its bytes").bytes[..4].copy_from_slice(&bytes);
    let op = &mut side_note.poseidon2_ops[0];
    op.input[..4].copy_from_slice(&bytes);
    let mut state: [M31; N_STATE] = core::array::from_fn(|j| {
        M31::new(u32::from_le_bytes(op.input[4 * j..4 * j + 4].try_into().unwrap()) % P)
    });
    vos_pvm_poseidon2::permute(&mut state);
    for (bytes, word) in op.output.chunks_exact_mut(4).zip(&state) {
        bytes.copy_from_slice(&word.value().to_le_bytes());
    }
    side_note
}

/// An input word at or above p is refused, p itself included.
#[test]
fn an_input_word_at_or_above_p_is_refused_on_a_node_segment() {
    refused(with_input_word(vos_pvm_poseidon2::P), "an input word p");
    refused(with_input_word((1 << 31) + 5), "an input word 2^31 + 5");
}

/// A call without its row is refused: the calls served and acknowledged by
/// the CPU, the chip's rows (and their memory accesses) gone.
#[test]
fn a_call_without_its_row_is_refused_on_a_node_segment() {
    let mut forged = short_run();
    forged.poseidon2_ops.clear();
    refused(forged, "a Poseidon2 call without its row");
}
