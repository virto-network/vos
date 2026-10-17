#![cfg(feature = "prover")]

//! A kernel's witness input, its run's ends and its io-hash, on the prover's
//! side: the tracer serves the witness input as the agent does and re-runs a
//! kernel from what its attest recorded to the same output and io-hash; the
//! AIR binds each call's count and the bytes it writes to their range; a
//! kernel's proof starts at the image root its install recorded and ends at
//! the halt address exactly when it halts.
//!
//! The kernels are the `kernels` test actor's (`just build-test-actors`),
//! run live on the agent's reference model, which the agent's own tests
//! hold the agent to.

use std::sync::OnceLock;

use vos_pvm::PVM_HALT_ADDR;
use vos_pvm::precompile::WitnessRead;
use vos_pvm_program::{CodeBlob, StandardProgram, build_standard_program};
use vos_pvm_proof::SideNote;
use vos_pvm_proof::core::step::WitnessWrite;
use vos_pvm_proof::kernel::{KernelTrace, KernelTraceError, trace_kernel};
use vos_pvm_proof::segment::SegmentCursor;
use vos_pvm_proof::{prove, verify, verify_chain};
use vos_testkit::Testkit;
use vos_testkit::programs::{derivation, derived, method, package};
use vos_wire::Encode;
use vos_wire::abi::cap::Target;
use vos_wire::ids::{AgentId, InstanceId, Principal, ProgramHash};
use vos_wire::result::Attest;

const PAGE: u64 = 4096;
const RW: u64 = 0x3_0000;
const GAS: u64 = 100_000_000;

/// The witness-input calls of [`reader`], each its destination and
/// capacity, on [`READER_INPUT`]: three bytes, none, four, a short read of
/// the three left, and a read at the end. The agent's tests pin the same
/// (`agent/testkit/tests/agent/tracking.rs`).
const READER_CALLS: [(u64, u64); 5] = [
    (RW + 0x100, 3),
    (RW + 0x200, 0),
    (RW + 0x300, 4),
    (RW + 0x400, 8),
    (RW + 0x500, 5),
];
const READER_INPUT: [u8; 10] = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9];

/// Each call's cursor and count, as the agent's run of the reader stores
/// them: `[3, 0, 4, 3, 0]`.
const READER_READS: [(usize, usize); 5] = [(0, 3), (3, 0), (3, 4), (7, 3), (10, 0)];

/// A standard program that makes `calls`' witness-input calls, storing each
/// count it returns at [`RW`] plus eight bytes a call, and halts with an
/// empty output: the agent's tests' reader, byte for byte.
fn reader(calls: &[(u64, u64)]) -> Vec<u8> {
    let mut code = Vec::new();
    let mut starts = Vec::new();
    let mut emit = |bytes: &[u8]| {
        starts.push(code.len());
        code.extend_from_slice(bytes);
    };
    let load_imm =
        |register: u8, value: u64| [&[51, register][..], &(value as u32).to_le_bytes()].concat();
    for (index, &(destination, capacity)) in calls.iter().enumerate() {
        emit(&load_imm(7, destination));
        emit(&load_imm(8, capacity));
        emit(&[10, 0x01, 0x04]);
        let store = RW as u32 + 8 * index as u32;
        emit(&[&[62, 7][..], &store.to_le_bytes()].concat());
    }
    emit(&load_imm(8, 0));
    emit(&[50, 0]);
    let mut bitmask = vec![0; code.len()];
    for start in starts {
        bitmask[start] = 1;
    }
    build_standard_program(&StandardProgram {
        ro_data: vec![1; PAGE as usize],
        rw_data: vec![],
        heap_pages: 5,
        stack_size: PAGE as u32,
        code: CodeBlob {
            jump_table: vec![],
            code,
            bitmask,
        },
    })
    .unwrap()
}

fn traced_reader(input: &[u8]) -> KernelTrace {
    trace_kernel(&reader(&READER_CALLS), input, GAS).expect("the reader halts")
}

/// Prove one segment and verify it against its side note.
fn proved(mut side_note: SideNote) -> vos_pvm_proof::Proof {
    proved_in(&mut side_note)
}

fn proved_in(side_note: &mut SideNote) -> vos_pvm_proof::Proof {
    let proof = prove(side_note).expect("proving failed");
    verify(proof.clone(), side_note).expect("verification failed");
    proof
}

/// The whole of a trace as one segment.
fn whole(trace: &KernelTrace) -> SideNote {
    let steps = trace.side_note.steps.len();
    SegmentCursor::new(&trace.side_note).side_note(0, steps)
}

/// The tracer serves each witness-input call as the agent does: the next
/// `min(capacity, remaining)` bytes at its destination and their count in
/// φ7, a short read the rest and a read at the end 0, so its cursor before
/// each call is the agent's; and the run proves.
#[test]
fn the_tracer_reads_as_the_agent_does_and_the_run_proves() {
    let trace = traced_reader(&READER_INPUT);
    let reads: Vec<(usize, usize)> = trace
        .reads
        .iter()
        .map(|read| (read.cursor, read.count))
        .collect();
    assert_eq!(reads, READER_READS);
    for (read, &(destination, capacity)) in trace.reads.iter().zip(&READER_CALLS) {
        assert_eq!((read.destination, read.capacity), (destination, capacity));
    }
    // Each call that wrote bytes is its step's witness write, the count
    // its register write.
    let writes: Vec<&WitnessWrite> = trace
        .side_note
        .steps
        .iter()
        .filter_map(|step| step.witness.as_deref())
        .collect();
    assert_eq!(
        writes,
        [
            &WitnessWrite {
                address: (RW + 0x100) as u32,
                bytes: READER_INPUT[..3].to_vec(),
            },
            &WitnessWrite {
                address: (RW + 0x300) as u32,
                bytes: READER_INPUT[3..7].to_vec(),
            },
            &WitnessWrite {
                address: (RW + 0x400) as u32,
                bytes: READER_INPUT[7..].to_vec(),
            },
        ]
    );
    let counts: Vec<u64> = trace
        .side_note
        .steps
        .iter()
        .filter(|step| step.opcode == vos_pvm::instruction::Opcode::Ecalli)
        .map(|step| {
            assert_eq!(step.reg_write, Some(7));
            step.regs_after[7]
        })
        .collect();
    assert_eq!(counts, [3, 0, 4, 3, 0]);
    proved(whole(&trace));
}

/// A call that writes no bytes, of no capacity or at the end of the input,
/// names any destination, even one past 2^32, as the live call does: it
/// returns 0 and the run proves.
#[test]
fn a_call_without_bytes_may_name_any_destination() {
    let calls = [(u64::MAX, 0), (RW + 0x100, 16), (u64::MAX, 4)];
    let trace = trace_kernel(&reader(&calls), &READER_INPUT, GAS).expect("the reader halts");
    let reads: Vec<(u64, usize)> = trace
        .reads
        .iter()
        .map(|read| (read.destination, read.count))
        .collect();
    assert_eq!(reads, [(u64::MAX, 0), (RW + 0x100, 10), (u64::MAX, 0)]);
    proved(whole(&trace));
}

/// A run that reads less than its input, or past it, is not the run the
/// input was recorded from; an input past the cap is refused before any
/// call.
#[test]
fn the_re_run_reads_exactly_its_input() {
    let program = reader(&READER_CALLS);
    // Its calls hold room for 20 bytes.
    let longer = [&READER_INPUT[..], &[0xff; 11]].concat();
    assert_eq!(
        trace_kernel(&program, &longer, GAS).err(),
        Some(KernelTraceError::Unread {
            read: 20,
            input: 21
        })
    );
    let oversize = vec![0u8; vos_pvm::precompile::WITNESS_INPUT_MAX + 1];
    assert_eq!(
        trace_kernel(&program, &oversize, GAS).err(),
        Some(KernelTraceError::Input)
    );
    // A shorter input reads short where the record read whole.
    let shorter = trace_kernel(&program, &READER_INPUT[..5], GAS).expect("halts");
    let reads: Vec<(usize, usize)> = shorter
        .reads
        .iter()
        .map(|read: &WitnessRead| (read.cursor, read.count))
        .collect();
    assert_eq!(reads, [(0, 3), (3, 0), (3, 2), (5, 0), (5, 0)]);
}

/// A proof of the reader whose witness writes are moved off their call's
/// range, or past its count, or whose count passes its capacity, does not
/// verify: the CPU's call tuple names the range, WitnessInputChip writes
/// exactly it, and CompareChip bounds the count.
mod refused {
    use super::*;

    fn forged(edit: impl FnOnce(&mut SideNote)) {
        let mut side_note = whole(&traced_reader(&READER_INPUT));
        edit(&mut side_note);
        proved(side_note);
    }

    fn first_write(side_note: &mut SideNote) -> &mut WitnessWrite {
        side_note
            .steps
            .iter_mut()
            .find_map(|step| step.witness.as_deref_mut())
            .expect("a witness write")
    }

    #[test]
    fn the_honest_run_verifies() {
        forged(|_| {});
    }

    #[test]
    #[should_panic(expected = "failed")]
    fn a_write_moved_past_its_destination() {
        forged(|side_note| first_write(side_note).address += 1);
    }

    #[test]
    #[should_panic(expected = "failed")]
    fn a_write_moved_before_its_destination() {
        forged(|side_note| first_write(side_note).address -= 1);
    }

    #[test]
    #[should_panic(expected = "failed")]
    fn a_byte_past_the_count() {
        forged(|side_note| first_write(side_note).bytes.push(0xee));
    }

    #[test]
    #[should_panic(expected = "failed")]
    fn a_byte_short_of_the_count() {
        forged(|side_note| {
            first_write(side_note).bytes.pop();
        });
    }

    /// A call of capacity 2 claimed to write three bytes: the count, its
    /// bytes and the registers that read it agree, but CompareChip refuses
    /// a count past its capacity.
    #[test]
    #[should_panic(expected = "failed")]
    fn a_count_past_the_capacity() {
        let mut trace = trace_kernel(&reader(&[(RW + 0x100, 2)]), &READER_INPUT[..2], GAS)
            .expect("the reader halts");
        // load φ7, load φ8, the call, the store of its count, load φ8, halt.
        let steps = &mut trace.side_note.steps;
        assert_eq!(steps[2].regs_after[7], 2);
        steps[2].regs_after[7] = 3;
        steps[2].witness.as_deref_mut().unwrap().bytes.push(0xa2);
        for step in &mut steps[3..] {
            step.regs_before[7] = 3;
            step.regs_after[7] = 3;
        }
        steps[3].mem_write.as_mut().unwrap().value = 3;
        proved(whole(&trace));
    }

    /// The same run, honest, proves: the forgery above fails for its count.
    #[test]
    fn a_count_at_its_capacity_proves() {
        let trace = trace_kernel(&reader(&[(RW + 0x100, 2)]), &READER_INPUT[..2], GAS)
            .expect("the reader halts");
        assert_eq!(trace.side_note.steps[2].regs_after[7], 2);
        proved(whole(&trace));
    }
}

/// The `kernels` actor installed on the agent's reference model.
fn kernels() -> Testkit {
    let mut kit = Testkit::new(AgentId(7));
    kit.install_derived(Target::Vos, InstanceId(9), &derived("kernels"), &[])
        .expect("installs");
    kit
}

/// The derivation an install of the `kernels` actor records.
fn install() -> &'static vos_wire::records::Derivation {
    static DERIVATION: OnceLock<vos_wire::records::Derivation> = OnceLock::new();
    DERIVATION.get_or_init(|| derivation(&package("kernels"), &derived("kernels")))
}

/// The kernel blob a derivation names by hash.
fn kernel_blob(program: ProgramHash) -> Vec<u8> {
    derived("kernels")
        .kernels
        .into_iter()
        .map(|(_, kernel)| kernel)
        .find(|kernel| ProgramHash::of(kernel) == program)
        .expect("a derived kernel")
}

/// The attests of one live run of `check`: each kernel's on `values`.
fn live_attests(values: &[u64]) -> Vec<Attest> {
    let mut kit = kernels();
    let check = method(&derived("kernels").actor, "check");
    let step = kit.command(
        Principal::Client([1; 32]),
        InstanceId(9),
        check,
        &values.to_vec().encode(),
    );
    assert!(
        matches!(step.outcome, vos_wire::result::Outcome::Done(_)),
        "{:?}",
        step.outcome
    );
    assert_eq!(step.attests.len(), 3);
    step.attests
}

/// live ≡ traced: each kernel's live run and the prover's re-run of it from
/// its attest end with the same output and io-hash, the re-run reading its
/// recorded input whole, its arguments, in the calls its prologue makes.
#[test]
fn a_kernels_re_run_ends_as_its_live_run() {
    for values in [vec![], vec![1u64, 2, 3, 40], (0..200).collect()] {
        for attest in live_attests(&values) {
            let blob = kernel_blob(attest.program);
            let trace = trace_kernel(&blob, &attest.witness_input, GAS).expect("re-runs");
            assert_eq!(trace.output, attest.output);
            assert_eq!(
                trace.io_hash,
                vos_pvm_precompiles::compute_io_hash(&[], &attest.output, &[])
            );
            let read: usize = trace.reads.iter().map(|read| read.count).sum();
            assert_eq!(read, attest.witness_input.len());
            eprintln!(
                "kernel {:02x?}… on {} values: {} steps, {} bytes in {} calls",
                &attest.program.0[..4],
                values.len(),
                trace.side_note.steps.len(),
                read,
                trace.reads.len(),
            );
            assert_eq!(trace.reads.last().map(|read| read.count), Some(0));
        }
    }
}

/// A kernel's first segment starts at the image root its install recorded,
/// which its initial memory's page tree has: its arguments are not in it.
#[test]
fn a_kernels_proof_starts_at_its_install_s_image_root() {
    let derivation = install();
    for kernel in &derivation.kernels {
        let blob = kernel_blob(kernel.program);
        let empty = trace_kernel(&blob, &[0; 4], GAS);
        let image = match &empty {
            Ok(trace) => &trace.image,
            // A kernel whose method does not decode four zero bytes still
            // laid its memory out: re-trace one that decodes.
            Err(_) => continue,
        };
        assert_eq!(
            vos_pvm_proof::page_merkle::sparse_image_root(image),
            kernel.image_root,
            "{:?}",
            kernel.method
        );
    }
    let attest = &live_attests(&[5, 6, 7])[1];
    let trace = trace_kernel(&kernel_blob(attest.program), &attest.witness_input, GAS).unwrap();
    let image_root = derivation
        .kernels
        .iter()
        .find(|kernel| kernel.program == attest.program)
        .map(|kernel| kernel.image_root)
        .unwrap();
    assert_eq!(
        vos_pvm_proof::page_merkle::sparse_image_root(&trace.image),
        image_root
    );
    let steps = trace.side_note.steps.len();
    let first = proved(SegmentCursor::new(&trace.side_note).side_note(0, steps / 2));
    assert_eq!(first.initial_state.memory_root, image_root);
}

/// A run cut into segments: only the one that ends at the halting step ends
/// at the halt address, a cut just before that step included; and the
/// chain verifies.
#[test]
fn only_a_halting_segment_ends_at_the_halt_address() {
    let attest = &live_attests(&[5, 6, 7])[1];
    let trace = trace_kernel(&kernel_blob(attest.program), &attest.witness_input, GAS).unwrap();
    let steps = trace.side_note.steps.len();
    let last = trace.side_note.steps.last().unwrap();
    assert!(last.exit);
    assert_eq!(last.next_pc, PVM_HALT_ADDR as u32);
    assert!(
        trace.side_note.steps[..steps - 1]
            .iter()
            .all(|step| step.next_pc != PVM_HALT_ADDR as u32),
        "no other step continues at the halt address"
    );
    let mut cursor = SegmentCursor::new(&trace.side_note);
    let bounds = [(0, steps / 2), (steps / 2, steps - 1), (steps - 1, steps)];
    let mut segments: Vec<SideNote> = bounds
        .iter()
        .map(|&(a, b)| cursor.side_note(a, b))
        .collect();
    let proofs: Vec<_> = segments.iter_mut().map(proved_in).collect();
    assert_ne!(proofs[0].final_state.pc, PVM_HALT_ADDR as u32);
    assert_eq!(
        proofs[1].final_state.pc, last.pc,
        "cut just before its halting step, a segment ends at that step"
    );
    assert_ne!(proofs[1].final_state.pc, PVM_HALT_ADDR as u32);
    assert_eq!(proofs[2].final_state.pc, PVM_HALT_ADDR as u32);
    let side_notes: Vec<&SideNote> = segments.iter().collect();
    verify_chain(&proofs, &side_notes).expect("the chain verifies");
}
