#![cfg(feature = "prover")]

//! Proof gates for host-call PC disposition. ECALLI stays at its cause PC
//! until a policy-supported handler acknowledges it. These one-row traces
//! make the AIR constraint independent of the program-execution lookup's
//! successor chaining.

mod common;
use common::prove_and_verify;

use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;
use vos_pvm::{ExitReason, PVM_REGISTER_COUNT, PVM_ZONE_SIZE};
use vos_pvm_proof::SideNote;
use vos_pvm_proof::core::tracing::{ECALL_SCALAR_ADD_MOD_L, TracingPvm};

/// Guest memory: the protected zone plus one page holding the precompile's
/// operands (a, b) and output.
const MEMORY_LEN: usize = PVM_ZONE_SIZE as usize + 0x1000;

fn host_program(id: u8) -> (Vec<u8>, Vec<u8>) {
    (
        vec![Opcode::Ecalli as u8, id, Opcode::Trap as u8],
        vec![1, 0, 1],
    )
}

fn tracer(id: u8) -> (Vec<u8>, Vec<u8>, TracingPvm) {
    let (code, bitmask) = host_program(id);
    let mut registers = [0; PVM_REGISTER_COUNT];
    registers[7] = u64::from(PVM_ZONE_SIZE);
    registers[8] = u64::from(PVM_ZONE_SIZE) + 0x20;
    registers[9] = u64::from(PVM_ZONE_SIZE) + 0x40;
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
    let (_, _, mut tracing) = tracer(ECALL_SCALAR_ADD_MOD_L as u8);
    assert_eq!(tracing.step_with_precompiles(), None);
    let side_note = tracing.into_side_note().with_memory(vec![0; MEMORY_LEN]);
    assert_eq!(side_note.steps.len(), 1);
    assert!(side_note.steps[0].host_call_acknowledged);
    assert_eq!((side_note.steps[0].pc, side_note.steps[0].next_pc), (0, 2));
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
    side_note.steps[0].next_pc = 1;
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
    let code = vec![Opcode::Ecalli as u8, 0x00, 0x04, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];
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
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.step(), Some(ExitReason::HostCall(0x400)));
    let steps = tracing.into_trace();
    assert_eq!(steps.len(), 1);
    assert!(!steps[0].host_call_acknowledged);
    assert_eq!((steps[0].pc, steps[0].next_pc), (0, 0));
    prove_and_verify(steps, &code, &bitmask);
}
