#![cfg(feature = "poseidon2-channel")]

//! Recursion build P5.2b (step 3) — match a REAL canonical segment proof's
//! `composition_oods_eval`.
//!
//! Steps 1+2 validated the auto-witnessing evaluator against a SYNTHETIC OODS
//! mask (a strong fuzz of the arithmetisation). This closes the P5.2 gate: drive
//! all 31 components through the evaluator against a REAL `prove_canonical`
//! segment proof's actual OODS data — its `sampled_values`, and the
//! `lookup_elements`/`random_coeff`/`oods_point` reconstructed by replaying the
//! verifier's Fiat-Shamir transcript (`zkpvm::reconstruct_oods_for_recursion`) —
//! and reproduce the proof's own `composition_oods_eval` in-AIR.
//!
//! This binds the evaluator to the real prover/verifier: the per-component mask
//! SLICING matches the proof's `sampled_values` layout, the reconstructed
//! relation elements match what the proof was produced under, and the in-AIR
//! re-eval equals the DEEP-ALI value the verifier checks against the real
//! composition mask.
//!
//! GREEN GATE: the continuous re-eval of all 31 components matches the proof's
//! `composition_oods_eval`, AND equals the recombination of the proof's real
//! composition mask (the DEEP-ALI equality, reproduced in-AIR).
//!
//! `#[ignore]` — `prove_canonical` builds a genuine 31-component segment (~30s
//! release, minutes in debug). Run:
//! `cargo test -p zkpvm --features poseidon2-channel --release \
//!     --test oods_auto_real_segment -- --ignored --nocapture`

mod recursion_common;

use javm::PVM_REGISTER_COUNT;
use javm::instruction::Opcode;
use javm::interpreter::Interpreter;
use recursion_common::oods_auto::{ComponentMask, MultiRecordBackend, drive_multi};
use std::cell::RefCell;
use std::rc::Rc;
use zkpvm::core::tracing::TracingPvm;
use zkpvm::framework_access::drive_chip_oods;
use zkpvm::{SideNote, prove_canonical, reconstruct_oods_for_recursion};

/// Prove a small but genuine program as ONE full 31-component canonical segment,
/// returning the proof + the side note in the prover-left state (the verifier
/// transcript replay needs it). Mirrors `verifier/tests/poseidon2_canonical_segment.rs`.
fn canonical_segment() -> (zkpvm::Proof, SideNote) {
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
    let initial_memory = vec![0u8; 4 * 1024 * 1024];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        initial_memory.clone(),
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run(), javm::ExitReason::Trap);
    let steps = tracing.into_trace();

    let mut sn = SideNote::new(steps, code, bitmask).with_memory(initial_memory);
    let proof = prove_canonical(&mut sn, &[]).expect("prove_canonical under Poseidon2-M31");
    (proof, sn)
}

/// THE GATE (heavy): re-evaluate a real canonical segment's full 31-component
/// OODS composition in-AIR and match the proof's `composition_oods_eval`.
#[test]
#[ignore = "heavy: prove_canonical builds a real 31-component segment (~30s release)"]
fn oods_auto_real_segment_matches() {
    let (proof, sn) = canonical_segment();
    assert_eq!(
        proof.num_components,
        zkpvm::chip_idx::COUNT,
        "canonical proof must carry all 31 components"
    );

    // Replay the verifier transcript to the OODS point: the real lookup_elements,
    // random_coeff, oods-derived scalars, per-component masks (sliced from the
    // proof's sampled_values), and the proof's own composition_oods_eval.
    let r = reconstruct_oods_for_recursion(&proof, &sn);

    // Drive all 31 components through the auto-witnessing evaluator on the REAL
    // masks, accumulating into one continuous Horner.
    let component_masks: Vec<ComponentMask> = r
        .component_masks
        .into_iter()
        .map(|m| ComponentMask {
            mask: m.mask,
            preproc_indices: m.preproc_indices,
        })
        .collect();
    let backend = MultiRecordBackend::new(
        component_masks,
        r.random_coeff,
        r.denom_inverse,
        r.oods_x_doubled,
        r.comp_mask,
    );
    let ctx = Rc::new(RefCell::new(backend));
    let lookup = &r.lookup_elements;
    drive_multi(&ctx, &r.comps, |idx, ls, e| {
        drive_chip_oods(idx, ls, lookup, e)
    });
    let rec = Rc::try_unwrap(ctx)
        .unwrap_or_else(|_| panic!("a Handle outlived the recorder walk"))
        .into_inner();

    let comp = rec.final_lhs.expect("final equality discharged");
    let lhs = rec.final_rhs.expect("final equality discharged");

    // (1) the in-AIR re-eval == the proof's composition_oods_eval.
    assert_eq!(
        comp, r.composition_value,
        "31-component in-AIR OODS re-eval must equal the proof's composition_oods_eval"
    );
    // (2) the DEEP-ALI equality, reproduced in-AIR with the proof's REAL
    // composition mask: comp == left + ox·right.
    assert_eq!(
        comp, lhs,
        "in-AIR composition value must equal the recombined real composition mask (DEEP-ALI)"
    );

    eprintln!(
        "oods_auto_real_segment_matches GREEN: a REAL 31-component canonical segment proof's \
         full OODS composition was re-evaluated in-AIR through the auto-witnessing evaluator \
         (all 31 chips, continuous Horner, real sampled_values + reconstructed transcript) and \
         matches the proof's composition_oods_eval {:?} = the recombined real composition mask. \
         {} QM31 committed columns ({} witnessed).",
        r.composition_value,
        rec.schedule.len(),
        rec.witnessed,
    );
}
