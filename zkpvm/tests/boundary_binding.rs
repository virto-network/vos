//! Boundary public-input binding gate.
//!
//! `proof.{initial,final}_state` (registers, pc, timestamp) must be BOUND
//! to the committed boundary columns — not merely mixed into the
//! Fiat-Shamir transcript. The FS mix alone makes a finished proof
//! tamper-evident but cannot stop a FROM-SCRATCH prover that commits the
//! honest columns while mixing and shipping lying metadata: every
//! challenge such a prover draws is self-consistent with its own (lying)
//! transcript, so nothing in the STARK relates the metadata fields to
//! the committed boundary columns.
//!
//! These tests model that adversary via `prove_with_boundary_override`
//! (honest columns, forged metadata) and assert both `verify` and
//! `verify_standalone` reject every variant. The voucher io-hash
//! (`Proof::public_io_hash`, φ[9..13] of `final_state.registers`) reads
//! this metadata, so external-voucher verification requires these to
//! hold.
//!
//! SCOPE — these cover the metadata→column half of the binding (the
//! override keeps the committed columns HONEST and lies only in the
//! shipped metadata + transcript mix). They do NOT cover a prover that
//! also forges the committed register COLUMNS via the register ledger's
//! free `prev_value` — that column→trace gap is separate and still open
//! (see `chips/register_memory_closing.rs` /
//! `project_register_ledger_readconsistency_gap`); pc/timestamp columns
//! are independently trace-bound by CpuChip and not subject to it.

mod common;

use common::*;
use javm::PVM_REGISTER_COUNT;
use javm::instruction::Opcode;
use zkpvm::core::step::PvmStep;
use zkpvm::{SegmentState, SideNote, program_commitment_of_proof, prove};
use zkpvm_verifier::verify_standalone;

/// Trace a tiny Add64 program whose destination is φ[9] — the first
/// register of the io-hash window `public_io_hash` reads.
fn traced_program() -> (Vec<PvmStep>, Vec<u8>, Vec<u8>) {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[1] = 5;
    regs[2] = 7;
    let (code, bitmask) = three_reg_program(Opcode::Add64, 9, 1, 2);
    let steps = trace_until_trap(code.clone(), bitmask.clone(), regs);
    (steps, code, bitmask)
}

#[test]
fn from_scratch_boundary_forgery_is_rejected() {
    let (steps, code, bitmask) = traced_program();

    // Honest baseline: sanity-check acceptance and harvest the honest
    // boundary metadata + program commitment.
    let mut side_note = SideNote::new(steps.clone(), code.clone(), bitmask.clone());
    let honest = prove(&mut side_note).expect("honest prove failed");
    let commitment = program_commitment_of_proof(&honest);
    zkpvm::verify(honest.clone(), &side_note).expect("honest proof must verify");
    verify_standalone(honest.clone(), commitment).expect("honest proof must verify standalone");
    let honest_initial = honest.initial_state.clone();
    let honest_final = honest.final_state.clone();

    type Forge = fn(&mut SegmentState, &mut SegmentState);
    let variants: &[(&str, Forge)] = &[
        ("final regs φ[9] (io-hash window)", |_, fin| {
            fin.registers[9] ^= 1
        }),
        ("final regs φ[0]", |_, fin| fin.registers[0] = 0xdead_beef),
        ("initial regs φ[1]", |ini, _| ini.registers[1] ^= 0xff),
        ("final pc", |_, fin| fin.pc ^= 4),
        ("final timestamp", |_, fin| fin.timestamp += 1),
        ("initial pc + timestamp", |ini, _| {
            ini.pc ^= 2;
            ini.timestamp += 1;
        }),
    ];

    for (name, forge) in variants {
        let mut forged_initial = honest_initial.clone();
        let mut forged_final = honest_final.clone();
        forge(&mut forged_initial, &mut forged_final);

        let mut sn = SideNote::new(steps.clone(), code.clone(), bitmask.clone());
        let forged = zkpvm::prove_with_boundary_override(&mut sn, forged_initial, forged_final)
            .expect("the from-scratch prover completes its (lying) prove");

        assert!(
            zkpvm::verify(forged.clone(), &sn).is_err(),
            "verify ACCEPTED a from-scratch boundary forgery: {name}"
        );
        assert!(
            verify_standalone(forged, commitment).is_err(),
            "verify_standalone ACCEPTED a from-scratch boundary forgery: {name}"
        );
    }
}

#[test]
fn boundary_override_with_honest_values_verifies() {
    // The forgery seam itself must not break honest proofs: overriding
    // with the TRUE boundary states is indistinguishable from `prove`.
    let (steps, code, bitmask) = traced_program();
    let mut side_note = SideNote::new(steps.clone(), code.clone(), bitmask.clone());
    let honest = prove(&mut side_note).expect("honest prove failed");

    let mut sn = SideNote::new(steps, code, bitmask);
    let overridden = zkpvm::prove_with_boundary_override(
        &mut sn,
        honest.initial_state.clone(),
        honest.final_state.clone(),
    )
    .expect("override prove failed");
    zkpvm::verify(overridden.clone(), &sn).expect("honest-values override must verify");
    verify_standalone(overridden, program_commitment_of_proof(&honest))
        .expect("honest-values override must verify standalone");
}
