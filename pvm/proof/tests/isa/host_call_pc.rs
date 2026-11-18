#![cfg(feature = "prover")]

//! Proof gates for host-call PC disposition. ECALLI stays at its cause PC
//! until a policy-supported handler acknowledges it. These one-row traces
//! make the AIR constraint independent of the program-execution lookup's
//! successor chaining.

use crate::common;
use common::prove_and_verify;

use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;
use vos_pvm::{ExitReason, PVM_REGISTER_COUNT, PVM_ZONE_SIZE};
use vos_pvm_proof::SideNote;
use vos_pvm_proof::core::tracing::{ECALL_BLAKE2B_COMPRESS, TracingPvm};

/// Guest memory: the protected zone plus one page holding the compression's
/// state and message.
const MEMORY_LEN: usize = PVM_ZONE_SIZE as usize + 0x1000;

/// `ecalli id` with the id as its shortest immediate, then a trap.
fn host_program(id: u32) -> (Vec<u8>, Vec<u8>) {
    let length = (4 - id.leading_zeros() as usize / 8).max(1);
    let mut code = vec![Opcode::Ecalli as u8];
    code.extend_from_slice(&id.to_le_bytes()[..length]);
    code.push(Opcode::Trap as u8);
    let mut bitmask = vec![1];
    bitmask.extend(core::iter::repeat_n(0, length));
    bitmask.push(1);
    (code, bitmask)
}

fn tracer(id: u32) -> (Vec<u8>, Vec<u8>, TracingPvm) {
    let (code, bitmask) = host_program(id);
    let mut registers = [0; PVM_REGISTER_COUNT];
    registers[7] = u64::from(PVM_ZONE_SIZE);
    registers[8] = u64::from(PVM_ZONE_SIZE) + 0x40;
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        registers,
        vec![0; MEMORY_LEN],
        10_000,
    );
    (code, bitmask, TracingPvm::new(pvm))
}

fn prove_and_verify_side_note(mut side_note: SideNote) {
    let proof = vos_pvm_proof::prove(&mut side_note).expect("proving failed");
    vos_pvm_proof::verify(proof, &side_note).expect("verification failed");
}

/// One acknowledged precompile row, with its call relation and memory.
fn acknowledged_precompile() -> SideNote {
    let (_, _, mut tracing) = tracer(ECALL_BLAKE2B_COMPRESS);
    assert_eq!(tracing.step_with_precompiles(), None);
    let side_note = tracing.into_side_note().with_memory(vec![0; MEMORY_LEN]);
    assert_eq!(side_note.steps.len(), 1);
    assert!(side_note.steps[0].host_call_acknowledged);
    assert_eq!((side_note.steps[0].pc, side_note.steps[0].next_pc), (0, 3));
    side_note
}

#[test]
fn acknowledged_host_call_segment_proves_at_resume_pc() {
    prove_and_verify_side_note(acknowledged_precompile());
}

#[test]
fn unhandled_host_call_segment_proves_at_cause_pc() {
    let (code, bitmask, mut tracing) = tracer(11);
    assert_eq!(tracing.run_with_precompiles(), ExitReason::HostCall(11));
    let steps = tracing.into_trace();
    assert_eq!(steps.len(), 1);
    assert!(!steps[0].host_call_acknowledged);
    assert_eq!((steps[0].pc, steps[0].next_pc), (0, 0));
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn acknowledged_host_call_rejects_forged_next_pc() {
    let mut side_note = acknowledged_precompile();
    side_note.steps[0].next_pc = 2;
    prove_and_verify_side_note(side_note);
}

#[test]
#[should_panic(expected = "failed")]
fn acknowledged_host_call_rejects_forged_unacknowledged_disposition() {
    let mut side_note = acknowledged_precompile();
    side_note.steps[0].host_call_acknowledged = false;
    prove_and_verify_side_note(side_note);
}

#[test]
#[should_panic(expected = "failed")]
fn unknown_host_call_cannot_forge_acknowledgment() {
    let (code, bitmask, mut tracing) = tracer(11);
    assert_eq!(tracing.run_with_precompiles(), ExitReason::HostCall(11));
    let mut steps = tracing.into_trace();
    steps[0].host_call_acknowledged = true;
    steps[0].next_pc = 2;
    prove_and_verify(steps, &code, &bitmask);
}

/// An unhandled call must expose its cause PC: claiming the sequential
/// successor without an acknowledgment is rejected.
#[test]
#[should_panic(expected = "failed")]
fn unhandled_host_call_rejects_forged_resume_pc() {
    let (code, bitmask, mut tracing) = tracer(11);
    assert_eq!(tracing.run_with_precompiles(), ExitReason::HostCall(11));
    let mut steps = tracing.into_trace();
    steps[0].next_pc = 2;
    prove_and_verify(steps, &code, &bitmask);
}

/// A BLAKE2b call left to the embedder, as an inner machine's is left to
/// its agent, ends its segment at the cause PC and reads no register: the
/// call relation and its register reads come only with acknowledgment.
#[test]
fn unhandled_blake2b_call_segment_proves_at_cause_pc() {
    let (code, bitmask, mut tracing) = tracer(ECALL_BLAKE2B_COMPRESS);
    assert_eq!(tracing.step(), Some(ExitReason::HostCall(0x400)));
    let steps = tracing.into_trace();
    assert_eq!(steps.len(), 1);
    assert!(!steps[0].host_call_acknowledged);
    assert_eq!((steps[0].pc, steps[0].next_pc), (0, 0));
    prove_and_verify(steps, &code, &bitmask);
}

/// A BLAKE2b call the machine cannot serve, its `h` pointer past 32 bits:
/// the machine panics at the call. Its proof says what a call left to the
/// embedder's says, that the segment ends at the cause PC with nothing
/// after it; a host that serves its precompiles in place reads that end as
/// the panic, an embedder that serves them itself as a pending call.
fn failed_blake2b_call() -> (Vec<u8>, Vec<u8>, Vec<vos_pvm_proof::core::step::PvmStep>) {
    let (code, bitmask, mut tracing) = tracer(ECALL_BLAKE2B_COMPRESS);
    tracing.pvm.registers[7] = 1 << 32;
    assert_eq!(tracing.run_with_precompiles(), ExitReason::Panic);
    let steps = tracing.into_trace();
    assert_eq!(steps.len(), 1);
    assert!(!steps[0].host_call_acknowledged);
    assert_eq!((steps[0].pc, steps[0].next_pc), (0, 0));
    (code, bitmask, steps)
}

#[test]
fn a_failed_blake2b_call_ends_its_segment_at_the_cause_pc() {
    let (code, bitmask, steps) = failed_blake2b_call();
    let mut side_note = SideNote::new(steps, code, bitmask);
    let proof = vos_pvm_proof::prove(&mut side_note).expect("proving failed");
    assert_eq!(proof.final_state.pc, 0);
    vos_pvm_proof::verify(proof, &side_note).expect("verification failed");
}

/// The failed call continued at its successor without an acknowledgment.
#[test]
#[should_panic(expected = "failed")]
fn a_failed_blake2b_call_cannot_continue() {
    let (code, bitmask, mut steps) = failed_blake2b_call();
    steps[0].next_pc = 3;
    prove_and_verify(steps, &code, &bitmask);
}

/// The failed call acknowledged: no compression serves it.
#[test]
#[should_panic(expected = "failed")]
fn a_failed_blake2b_call_cannot_be_acknowledged() {
    let (code, bitmask, mut steps) = failed_blake2b_call();
    steps[0].host_call_acknowledged = true;
    steps[0].next_pc = 3;
    prove_and_verify(steps, &code, &bitmask);
}
