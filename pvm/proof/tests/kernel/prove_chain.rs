#![cfg(feature = "prover")]

//! Focused test for the in-memory `vos_pvm_proof::prove_chain` convenience.
//!
//! A small multi-window synthetic trace proves as a canonical-shape chain:
//! `prove_chain` derives ONE forcing profile over the window bounds and proves
//! every window to it, so all segments share one program commitment. The
//! resulting per-segment proofs then verify trustlessly via
//! `verify_chain_standalone` against that single commitment, under `format::SEGMENT`.

use vos_pvm::PVM_REGISTER_COUNT;
use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::{Interpreter, Memory};

use vos_pvm_proof::chips::memory_page::MemoryLayout;
use vos_pvm_proof::core::tracing::TracingPvm;
use vos_pvm_proof::segment::segment_bounds;
use vos_pvm_proof::{SideNote, program_commitment_of_proof, prove_chain};
use vos_pvm_proof_verifier::verify_chain_standalone;

#[test]
fn prove_chain_verifies_as_canonical_chain() {
    // Six chained Add64s + Trap (7 steps) — the chain_standalone fixture.
    let code = vec![
        Opcode::Add64 as u8,
        0x10,
        2,
        Opcode::Add64 as u8,
        0x12,
        3,
        Opcode::Add64 as u8,
        0x13,
        4,
        Opcode::Add64 as u8,
        0x14,
        5,
        Opcode::Add64 as u8,
        0x15,
        6,
        Opcode::Add64 as u8,
        0x16,
        7,
        Opcode::Trap as u8,
    ];
    let bitmask: Vec<u8> = vec![1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1];

    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 100;
    regs[1] = 1;
    let mut memory = Memory::sparse(1u64 << 32);
    memory.init_copy(u32::MAX - 31, b"sparse-chain-high-page");
    let initial_memory = memory.nonzero_page_image().into();
    let pvm = Interpreter::with_memory(code.clone(), bitmask.clone(), vec![], regs, memory, 10_000);
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run(), vos_pvm::ExitReason::Panic);
    let all_steps = tracing.into_trace();
    assert_eq!(all_steps.len(), 7);

    let full = SideNote::new(all_steps, code, bitmask)
        .with_sparse_memory(initial_memory)
        .with_memory_layout(MemoryLayout::writable());
    // Multi-window cut: 4-step windows over 7 steps ⇒ [0,4), [4,7).
    let bounds = segment_bounds(full.steps.len(), 4);
    assert_eq!(bounds, vec![(0, 4), (4, 7)], "expected a 2-window chain");

    let (profile, proofs) = prove_chain(&full, &bounds).expect("prove_chain must succeed");
    assert_eq!(proofs.len(), bounds.len(), "one proof per window");
    assert_eq!(
        profile.len(),
        vos_pvm_proof::chip_idx::COUNT,
        "profile is a per-chip forcing floor"
    );

    // Canonical forcing ⇒ every window shares ONE program commitment.
    let commit = program_commitment_of_proof(&proofs[0]);
    for p in &proofs {
        assert_eq!(
            program_commitment_of_proof(p),
            commit,
            "canonical chain must share one program commitment"
        );
    }

    // prove_chain wired the boundary states, so the chain is continuous.
    for w in proofs.windows(2) {
        assert_eq!(
            w[0].final_state, w[1].initial_state,
            "segments must chain (prove_chain produced the boundary states)"
        );
    }

    // The trustless chain verifier accepts the canonical chain.
    let expected_root = proofs[0].initial_state.memory_root;
    assert_ne!(expected_root, [0; 32], "the high sparse page is root-bound");
    let final_root = verify_chain_standalone(&proofs, commit, expected_root)
        .expect("honest canonical chain must verify standalone");
    assert_eq!(
        final_root,
        proofs.last().unwrap().final_state.memory_root,
        "verify_chain_standalone returns the chain's final root"
    );
}
