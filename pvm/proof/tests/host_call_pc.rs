#![cfg(feature = "prover")]

//! Proof gates for host-call PC disposition. Standard ECALLI stays at its
//! cause PC until a policy-supported handler acknowledges it; JAR retains its
//! frozen already-advanced PC. These one-row traces make the AIR constraint
//! independent of the program-execution lookup's successor chaining.

mod common;
use common::prove_and_verify;

use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;
use vos_pvm::{ExitReason, IsaMode, PVM_REGISTER_COUNT};
use vos_pvm_proof::core::step::PvmStep;
use vos_pvm_proof::core::tracing::TracingPvm;

fn host_program(id: u8) -> (Vec<u8>, Vec<u8>) {
    (
        vec![Opcode::Ecalli as u8, id, Opcode::Trap as u8],
        vec![1, 0, 1],
    )
}

fn tracer(id: u8, mode: IsaMode) -> (Vec<u8>, Vec<u8>, TracingPvm) {
    let (code, bitmask) = host_program(id);
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        [0; PVM_REGISTER_COUNT],
        vec![0; vos_pvm::PVM_ZONE_SIZE as usize],
        10_000,
        25,
    );
    (code, bitmask, TracingPvm::new_with_isa_mode(pvm, mode))
}

fn prove_and_verify_in_mode(steps: Vec<PvmStep>, code: &[u8], bitmask: &[u8], mode: IsaMode) {
    let mut side_note =
        vos_pvm_proof::SideNote::new(steps, code.to_vec(), bitmask.to_vec()).with_isa_mode(mode);
    let proof = vos_pvm_proof::prove(&mut side_note).expect("proving failed");
    vos_pvm_proof::verify(proof, &side_note).expect("verification failed");
}

fn acknowledged_standard_stub() -> (Vec<u8>, Vec<u8>, Vec<PvmStep>) {
    let (code, bitmask, mut tracing) = tracer(1, IsaMode::Conformance);
    assert_eq!(tracing.step_with_vos_stubs(), None);
    let steps = tracing.into_trace();
    assert_eq!(steps.len(), 1);
    assert!(steps[0].host_call_acknowledged);
    assert_eq!((steps[0].pc, steps[0].next_pc), (0, 2));
    (code, bitmask, steps)
}

#[test]
fn acknowledged_standard_host_call_segment_proves_at_resume_pc() {
    let (code, bitmask, steps) = acknowledged_standard_stub();
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn unhandled_standard_host_call_segment_proves_at_cause_pc() {
    let (code, bitmask, mut tracing) = tracer(11, IsaMode::Conformance);
    assert_eq!(tracing.run_with_vos_stubs(), ExitReason::HostCall(11));
    let steps = tracing.into_trace();
    assert_eq!(steps.len(), 1);
    assert!(!steps[0].host_call_acknowledged);
    assert_eq!((steps[0].pc, steps[0].next_pc), (0, 0));
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn jar_host_call_segment_preserves_frozen_sequential_pc() {
    let (code, bitmask, mut tracing) = tracer(11, IsaMode::Jar);
    assert_eq!(tracing.step(), Some(ExitReason::HostCall(11)));
    let steps = tracing.into_trace();
    assert_eq!(steps.len(), 1);
    assert!(!steps[0].host_call_acknowledged);
    assert_eq!((steps[0].pc, steps[0].next_pc), (0, 2));
    prove_and_verify_in_mode(steps, &code, &bitmask, IsaMode::Jar);
}

#[test]
#[should_panic(expected = "failed")]
fn acknowledged_standard_host_call_rejects_forged_next_pc() {
    let (code, bitmask, mut steps) = acknowledged_standard_stub();
    steps[0].next_pc = 1;
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn acknowledged_standard_host_call_rejects_forged_unacknowledged_disposition() {
    let (code, bitmask, mut steps) = acknowledged_standard_stub();
    steps[0].host_call_acknowledged = false;
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn unknown_standard_host_call_cannot_forge_acknowledgment() {
    let (code, bitmask, mut tracing) = tracer(11, IsaMode::Conformance);
    assert_eq!(tracing.run_with_vos_stubs(), ExitReason::HostCall(11));
    let mut steps = tracing.into_trace();
    steps[0].host_call_acknowledged = true;
    steps[0].next_pc = 2;
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn jar_host_call_rejects_forged_cause_pc() {
    let (code, bitmask, mut tracing) = tracer(11, IsaMode::Jar);
    assert_eq!(tracing.step(), Some(ExitReason::HostCall(11)));
    let mut steps = tracing.into_trace();
    steps[0].next_pc = 0;
    prove_and_verify_in_mode(steps, &code, &bitmask, IsaMode::Jar);
}
