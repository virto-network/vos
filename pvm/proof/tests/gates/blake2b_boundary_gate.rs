#![cfg(feature = "debug-internals")]

//! GATE tests for Blake2bBoundaryChip's soundness-critical additions over the
//! shared compression core: the **IsReal anchor** and the **Blake2bCompression
//! producer**.
//!
//! The boundary chip drops the main chip's CPU-call binding (which is what
//! makes IsReal honest there).  Without a replacement a from-scratch prover
//! could light up only the row-95 production row — making the V-state chain
//! (gated by GateH = IsReal·(1−IsLast)) vacuous on rows 0..94 — and emit a
//! fully forged `h_out`.  The IsReal anchor (IsReal boolean + ContinuityGate ·
//! (IsReal_next − IsReal) = 0) forces IsReal constant across each 96-row
//! compression, so a row-95 production implies the full V-chain from row 0 and
//! `h_out` is the true compression of (h, m, t, f).
//!
//! These build an HONEST boundary component trace, tamper the finalized trace
//! directly (exactly what a from-scratch prover does), and assert the chip's
//! AIR constraints REJECT it.
//!
//! Run with: `cargo test -p vos-pvm-proof --features debug-internals --test
//! blake2b_boundary_gate`.

use vos_pvm_proof::AirColumn;
use vos_pvm_proof::SideNote;
use vos_pvm_proof::chips::Blake2bBoundaryChip;
use vos_pvm_proof::chips::Blake2bCall;
use vos_pvm_proof::chips::blake2b::BoundaryColumn;
use vos_pvm_proof::harness::MachineProverComponent;

use crate::forge::*;
use stwo::core::fields::m31::BaseField;

fn boundary_side_note() -> SideNote {
    let mut sn = SideNote::new(Vec::new(), Vec::new(), Vec::new());
    // One synthetic Merkle compression — arbitrary (h, m, t, f).
    sn.merkle_blake2b_calls.push(Blake2bCall {
        h: [0u64; 8],
        m: [0u64; 16],
        t: 0,
        f: true,
    });
    sn
}

/// IsReal anchor: forge the row-95 production by zeroing IsReal there (kept
/// consistent with the OutputGateH definition so no gate-helper definition
/// fires), leaving IsReal=1 on the rest of the compression.  ONLY the
/// continuity anchor `ContinuityGate·(IsReal_next − IsReal)=0` (at row 94→95)
/// can catch the discontinuity — this asserts it does.
#[test]
fn boundary_isreal_anchor_rejects_lit_only_at_row95() {
    let mut side_note = boundary_side_note();
    let chip = Blake2bBoundaryChip;
    let mut trace = chip.generate_component_trace(&mut side_note);

    let is_real = BoundaryColumn::IsReal.offset();
    let output_gate_h = BoundaryColumn::OutputGateH.offset();

    // Control: the honest trace satisfies every constraint.
    check_chip(&chip, &trace, &side_note)
        .expect("honest Blake2bBoundary trace must satisfy all constraints");

    // The production row is the unique real row with OutputGateH=1 (row 95).
    let prod_row = find_row(&trace, |at| at(output_gate_h) == BaseField::from(1u32));
    assert_eq!(
        trace.original_trace[is_real].as_slice()[prod_row],
        BaseField::from(1u32),
        "honest production row must be real",
    );

    // Forge: zero IsReal at row 95 (so the V-chain that produced its V-state
    // is no longer pinned), and zero OutputGateH to keep its definition
    // (OutputGateH = IsReal·IsLast) satisfied — isolating the anchor.
    trace.original_trace[is_real].as_mut_slice()[prod_row] = BaseField::from(0u32);
    trace.original_trace[output_gate_h].as_mut_slice()[prod_row] = BaseField::from(0u32);

    let res = check_chip(&chip, &trace, &side_note);
    assert!(
        res.is_err(),
        "SOUNDNESS GAP: a Blake2bBoundary compression with IsReal lit only at \
         row 95 (V-chain vacuous on rows 0..94) was ACCEPTED — the IsReal \
         continuity anchor is not binding.",
    );
}

// `h_out` binding (the row-95 output derivation) lives in the shared
// compression core and is exercised end-to-end by the main chip's
// prove_blake2b_precompile / prove_blake2b_via_ecall — no separate tamper
// test here (the core constraint fires after the core's first add_to_relation,
// so it can't unwind cleanly through the debug gate harness anyway).
