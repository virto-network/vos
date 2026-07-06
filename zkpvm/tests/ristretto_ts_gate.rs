#![cfg(feature = "debug-internals")]

//! §7 GATE tests for the ristretto memory-op `ts`-binding (design v4,
//! `docs/plans/ristretto-ts-binding.md`).
//!
//! A from-scratch prover could otherwise set a ristretto memory producer's
//! `ts` to a free value (0 → collides with the §2 per-page ts=0 boundary write
//! → entry forgery; `closing_ts` → exit forgery; or any in-range value to
//! fabricate a memory state), and its `Addr` to alias an unrelated access.
//! The 96-row preprocessed period (RistrettoEcallChip) and the 32-row comb
//! chips now pin every mem-op `ts` to the block's anchored ECALL ts (held via
//! ts-equality from a preprocessed-pinned `InitGate`) and every `Addr` to the
//! register-authenticated operand pointer + a per-byte no-wrap carry offset.
//!
//! These are Pattern-A gates: build an HONEST single-chip `ComponentTrace`,
//! tamper one cell (exactly what a from-scratch prover does — bypassing the
//! honest filler), and assert the chip's AIR constraints REJECT it.  The
//! honest control additionally proves the new constraints + trace generation
//! are self-consistent.  Cross-chip balance (RELATION-A producer/consumer
//! match, ts=0 / closing_ts collision) is exercised by the full-system
//! `voucher_check_smoke` + capstone, not here.
//!
//! Run with: `cargo test -p zkpvm --features debug-internals --test
//! ristretto_ts_gate`.

use zkpvm::AirColumn;
use zkpvm::SideNote;
use zkpvm::chips::{
    RistrettoCombCompressOutputChip, RistrettoCombScalarBoundaryChip, RistrettoEcallChip,
};
use zkpvm::core::tracing::{RistrettoMemOp, ScalarMultKind};
use zkpvm::framework_access::AllLookupElements;
use zkpvm::harness::MachineProverComponent;
use zkpvm::side_note::RistrettoCombCall;
use zkpvm::trace::component::ComponentTrace;

use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::m31::BaseField;

fn assert_chip<C: MachineProverComponent>(
    chip: &C,
    trace: &ComponentTrace,
    side_note: &SideNote,
) -> Result<(), String> {
    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut Blake2sChannel::default();
    chip.draw_lookup_elements(&mut lookup_elements, channel);
    let (interaction_trace, claimed_sum) =
        chip.generate_interaction_trace(trace.clone(), side_note, &lookup_elements);
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        chip.debug_assert_constraints(trace, &interaction_trace, &lookup_elements, claimed_sum);
    }))
    .map_err(|p| {
        p.downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "<non-string panic>".into())
    })
}

/// Find the first row (in stored order) matching a predicate over a
/// column-offset reader.
fn find_row(trace: &ComponentTrace, pred: impl Fn(&dyn Fn(usize) -> BaseField) -> bool) -> usize {
    let n = trace.original_trace[0].as_slice().len();
    (0..n)
        .find(|&r| {
            let at = |off: usize| trace.original_trace[off].as_slice()[r];
            pred(&at)
        })
        .expect("no row matched the search predicate")
}

fn tamper(trace: &mut ComponentTrace, off: usize, row: usize, v: u32) {
    trace.original_trace[off].as_mut_slice()[row] = BaseField::from(v);
}

// ── RistrettoEcallChip — variable-base scalar_mult (all 96 rows real) ──

fn variable_call_sn() -> SideNote {
    let mut sn = SideNote::new(Vec::new(), Vec::new(), Vec::new());
    sn.ristretto_mem_ops.push(RistrettoMemOp {
        scalar_ptr: 0x1000,
        point_ptr: 0x2000,
        output_ptr: 0x3000,
        ts: 42,
        scalar_bytes: [0x11u8; 32],
        point_bytes: [0x22u8; 32],
        out_bytes: [0x33u8; 32],
        kind: ScalarMultKind::Variable,
    });
    sn
}

#[test]
fn ristretto_ecall_honest_variable_call_satisfies_constraints() {
    let sn = variable_call_sn();
    let chip = RistrettoEcallChip;
    let trace = chip.generate_component_trace_immut(&sn);
    assert_chip(&chip, &trace, &sn)
        .expect("honest variable-base RistrettoEcallChip trace must satisfy all constraints");
}

#[test]
fn ristretto_ecall_forged_ts_is_rejected() {
    use zkpvm::chips::ristretto_ecall::Column;
    let sn = variable_call_sn();
    let chip = RistrettoEcallChip;
    let mut trace = chip.generate_component_trace_immut(&sn);
    assert_chip(&chip, &trace, &sn).expect("honest control");

    let is_real = Column::IsReal.offset();
    let init_gate = Column::InitGate.offset();
    let ts = Column::Ts.offset();
    // A real, non-anchor row (InitGate = 0) whose ts must equal the block ts.
    let row = find_row(&trace, |at| {
        at(is_real) == BaseField::from(1u32) && at(init_gate) == BaseField::from(0u32)
    });
    // Forge the low byte of this row's Ts away from the held block ts.
    tamper(&mut trace, ts, row, 99);
    assert!(
        assert_chip(&chip, &trace, &sn).is_err(),
        "SOUNDNESS GAP: a ristretto mem-op whose ts was forged off the \
         block's anchored ECALL ts was ACCEPTED — ts-equality not enforced."
    );
}

#[test]
fn ristretto_ecall_is_write_flip_is_rejected() {
    use zkpvm::chips::ristretto_ecall::Column;
    let sn = variable_call_sn();
    let chip = RistrettoEcallChip;
    let mut trace = chip.generate_component_trace_immut(&sn);
    assert_chip(&chip, &trace, &sn).expect("honest control");

    let is_real = Column::IsReal.offset();
    let is_write = Column::IsWrite.offset();
    // A real read row (a sub-block 0/1 input byte): IsWrite honestly 0.
    let row = find_row(&trace, |at| {
        at(is_real) == BaseField::from(1u32) && at(is_write) == BaseField::from(0u32)
    });
    tamper(&mut trace, is_write, row, 1);
    assert!(
        assert_chip(&chip, &trace, &sn).is_err(),
        "SOUNDNESS GAP: an input read flipped to is_write=1 was ACCEPTED — \
         is_write is not pinned to the sub-block."
    );
}

#[test]
fn ristretto_ecall_forged_addr_is_rejected() {
    use zkpvm::chips::ristretto_ecall::Column;
    let sn = variable_call_sn();
    let chip = RistrettoEcallChip;
    let mut trace = chip.generate_component_trace_immut(&sn);
    assert_chip(&chip, &trace, &sn).expect("honest control");

    let is_real = Column::IsReal.offset();
    let addr = Column::Addr.offset();
    let row = find_row(&trace, |at| at(is_real) == BaseField::from(1u32));
    // Forge the low address byte off `RowPtr + RowOffset` (honest low byte is
    // an offset in 0..31, so 200 is guaranteed wrong).
    tamper(&mut trace, addr, row, 200);
    assert!(
        assert_chip(&chip, &trace, &sn).is_err(),
        "SOUNDNESS GAP: a mem-op address not equal to the authenticated \
         pointer + offset was ACCEPTED — Addr is not bound."
    );
}

#[test]
fn ristretto_ecall_forged_id_is_rejected() {
    use zkpvm::chips::ristretto_ecall::Column;
    let sn = variable_call_sn();
    let chip = RistrettoEcallChip;
    let mut trace = chip.generate_component_trace_immut(&sn);
    assert_chip(&chip, &trace, &sn).expect("honest control");

    let is_real = Column::IsReal.offset();
    let id = Column::Id.offset();
    let row = find_row(&trace, |at| at(is_real) == BaseField::from(1u32));
    // Forge the RELATION-A id away from 110·Is110 + … + 114·Is114.
    tamper(&mut trace, id, row, 111);
    assert!(
        assert_chip(&chip, &trace, &sn).is_err(),
        "SOUNDNESS GAP: a block whose RELATION-A id disagrees with its one-hot \
         id selectors was ACCEPTED — id is not bound."
    );
}

#[test]
fn ristretto_ecall_dodged_init_gate_is_rejected() {
    use zkpvm::chips::ristretto_ecall::Column;
    let sn = variable_call_sn();
    let chip = RistrettoEcallChip;
    let mut trace = chip.generate_component_trace_immut(&sn);
    assert_chip(&chip, &trace, &sn).expect("honest control");

    let init_gate = Column::InitGate.offset();
    let is_real = Column::IsReal.offset();
    // The anchor row (ByteIdx 0): InitGate honestly 1, is_real 1.
    let row = find_row(&trace, |at| at(init_gate) == BaseField::from(1u32));
    // Zero is_real at the anchor (a prover trying to dodge the RELATION-A
    // consume by hiding the block start behind padding).  The InitGate
    // definition (InitGate = is_real · IsByteIdx0_pp) is then violated.
    tamper(&mut trace, is_real, row, 0);
    assert!(
        assert_chip(&chip, &trace, &sn).is_err(),
        "SOUNDNESS GAP: zeroing is_real at the anchor row (dodging the \
         RELATION-A consume) was ACCEPTED — InitGate is not preprocessed-pinned."
    );
}

// ── Comb chips — fixed-base scalar_mult (32-row blocks) ──

fn fixed_base_sn() -> SideNote {
    let mut sn = SideNote::new(Vec::new(), Vec::new(), Vec::new());
    sn.ristretto_comb_calls.push(RistrettoCombCall {
        scalar: [0x07u8; 32],
        out_bytes: [0x09u8; 32],
        output_ptr: 0x3000,
        ts: 50,
    });
    sn.ristretto_mem_ops.push(RistrettoMemOp {
        scalar_ptr: 0x1000,
        point_ptr: 0x2000,
        output_ptr: 0x3000,
        ts: 50,
        scalar_bytes: [0x07u8; 32],
        point_bytes: [0x22u8; 32],
        out_bytes: [0x09u8; 32],
        kind: ScalarMultKind::FixedBasepoint,
    });
    sn
}

#[test]
fn comb_output_honest_satisfies_constraints() {
    let sn = fixed_base_sn();
    let chip = RistrettoCombCompressOutputChip;
    let trace = chip.generate_component_trace_immut(&sn);
    assert_chip(&chip, &trace, &sn)
        .expect("honest RistrettoCombCompressOutputChip trace must satisfy all constraints");
}

#[test]
fn comb_output_forged_ts_is_rejected() {
    use zkpvm::chips::ristretto_comb_compress_output::Column;
    let sn = fixed_base_sn();
    let chip = RistrettoCombCompressOutputChip;
    let mut trace = chip.generate_component_trace_immut(&sn);
    assert_chip(&chip, &trace, &sn).expect("honest control");

    let is_real = Column::IsReal.offset();
    let first = Column::FirstRowGate.offset();
    let ts = Column::Ts.offset();
    // A real, non-first row whose ts must equal the block's anchored ts.
    let row = find_row(&trace, |at| {
        at(is_real) == BaseField::from(1u32) && at(first) == BaseField::from(0u32)
    });
    tamper(&mut trace, ts, row, 99);
    assert!(
        assert_chip(&chip, &trace, &sn).is_err(),
        "SOUNDNESS GAP: a fixed-base output write whose ts was forged off the \
         anchored ECALL ts was ACCEPTED — intra-call ts-equality not enforced."
    );
}

#[test]
fn comb_output_forged_addr_is_rejected() {
    use zkpvm::chips::ristretto_comb_compress_output::Column;
    let sn = fixed_base_sn();
    let chip = RistrettoCombCompressOutputChip;
    let mut trace = chip.generate_component_trace_immut(&sn);
    assert_chip(&chip, &trace, &sn).expect("honest control");

    let is_real = Column::IsReal.offset();
    let addr = Column::Addr.offset();
    let row = find_row(&trace, |at| at(is_real) == BaseField::from(1u32));
    // Honest low address byte is an offset in 0..31, so 200 is guaranteed wrong.
    tamper(&mut trace, addr, row, 200);
    assert!(
        assert_chip(&chip, &trace, &sn).is_err(),
        "SOUNDNESS GAP: a fixed-base output write address not equal to \
         output_ptr + ByteIdx was ACCEPTED — Addr is not bound."
    );
}

#[test]
fn comb_scalar_honest_satisfies_constraints() {
    let sn = fixed_base_sn();
    let chip = RistrettoCombScalarBoundaryChip;
    let trace = chip.generate_component_trace_immut(&sn);
    assert_chip(&chip, &trace, &sn)
        .expect("honest RistrettoCombScalarBoundaryChip trace must satisfy all constraints");
}

#[test]
fn comb_scalar_forged_ts_is_rejected() {
    use zkpvm::chips::ristretto_comb_scalar_boundary::Column;
    let sn = fixed_base_sn();
    let chip = RistrettoCombScalarBoundaryChip;
    let mut trace = chip.generate_component_trace_immut(&sn);
    assert_chip(&chip, &trace, &sn).expect("honest control");

    let is_real = Column::IsReal.offset();
    let first = Column::FirstRowGate.offset();
    let ts = Column::Ts.offset();
    let row = find_row(&trace, |at| {
        at(is_real) == BaseField::from(1u32) && at(first) == BaseField::from(0u32)
    });
    tamper(&mut trace, ts, row, 99);
    assert!(
        assert_chip(&chip, &trace, &sn).is_err(),
        "SOUNDNESS GAP: a fixed-base scalar read whose ts was forged off the \
         anchored ECALL ts was ACCEPTED — intra-call ts-equality not enforced."
    );
}

#[test]
fn comb_scalar_forged_addr_is_rejected() {
    use zkpvm::chips::ristretto_comb_scalar_boundary::Column;
    let sn = fixed_base_sn();
    let chip = RistrettoCombScalarBoundaryChip;
    let mut trace = chip.generate_component_trace_immut(&sn);
    assert_chip(&chip, &trace, &sn).expect("honest control");

    let is_real = Column::IsReal.offset();
    let addr = Column::Addr.offset();
    let row = find_row(&trace, |at| at(is_real) == BaseField::from(1u32));
    // Honest low address byte is an offset in 0..31, so 200 is guaranteed wrong.
    tamper(&mut trace, addr, row, 200);
    assert!(
        assert_chip(&chip, &trace, &sn).is_err(),
        "SOUNDNESS GAP: a fixed-base scalar read address not equal to \
         scalar_ptr + ByteIdx was ACCEPTED — Addr is not bound."
    );
}
