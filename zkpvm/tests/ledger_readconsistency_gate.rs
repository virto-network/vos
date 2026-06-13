#![cfg(feature = "debug-internals")]

//! GATE tests for the register/RAM ledger read-consistency soundness gap.
//!
//! The register (`RegisterMemoryChip`) and RAM (`MemoryChip`) ledgers enforce
//! read-after-write only via `is_read · (value − prev_value) = 0`.  Today
//! `prev_value` is a FREE witness column: no `#[mask_next_row]` ties it to the
//! previous ledger row's value, and there is no `(key, ts)` sortedness check.
//! So a from-scratch prover can fill a read row with a lie `L` and set the
//! same row's `prev_value := L` — read-consistency holds (`L − L = 0`) while
//! the *actual* previous ledger row carries a different value `T`.  That forges
//! any register/memory read, including the closing read that pins
//! `final_state.registers` and hence the voucher io-hash.
//!
//! These tests build an HONEST component trace, then tamper a single read
//! row's `Value` + `PrevValue` cells (bypassing the honest trace filler, which
//! is the only thing that catches the forgery today) and assert the chip's AIR
//! constraints REJECT it.  They are RED until the cross-row `prev_value`
//! binding lands, and GREEN after.  Unlike `register_ledger_negative.rs` /
//! `memory_negative.rs` — which forge the side-note then run the honest filler,
//! so they exercise the *filler*, not the *constraint* — these tamper the
//! finalized trace directly, which is exactly what a from-scratch prover does.
//!
//! Run with: `cargo test -p zkpvm --features debug-internals --test
//! ledger_readconsistency_gate`.

use javm::PVM_REGISTER_COUNT;
use javm::instruction::Opcode;
use javm::interpreter::Interpreter;

use zkpvm::AirColumn;
use zkpvm::SideNote;
use zkpvm::chips::{MemoryChip, RegisterMemoryChip};
use zkpvm::core::step::NUM_REGS;
use zkpvm::core::tracing::TracingPvm;
use zkpvm::framework_access::AllLookupElements;
use zkpvm::harness::MachineProverComponent;
use zkpvm::trace::component::ComponentTrace;

use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::m31::BaseField;

/// Drive a chip's row-by-row `AssertEvaluator` over `trace` (regenerating a
/// self-consistent interaction trace + claimed sum from the — possibly
/// tampered — main trace).  `Ok(())` iff every constraint holds; `Err(msg)`
/// on the first violation.
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

/// Find the single logical row (in finalized / bit-reversed storage order)
/// satisfying `pred`, evaluated over the per-column base-field slices.
fn find_row(trace: &ComponentTrace, pred: impl Fn(&dyn Fn(usize) -> BaseField) -> bool) -> usize {
    let n = trace.original_trace[0].as_slice().len();
    (0..n)
        .find(|&r| {
            let at = |off: usize| trace.original_trace[off].as_slice()[r];
            pred(&at)
        })
        .expect("no row matched the search predicate")
}

// ── Register ledger ─────────────────────────────────────────────────────────

/// Two Add64 steps: `φ2 = φ0 + φ1` (writes φ2=12 at ts=1), then
/// `φ3 = φ2 + φ2` (reads φ2=12 at ts=2).  φ2's ledger is therefore
/// `[(φ2,0,ts0,W_init), (φ2,12,ts1,W), (φ2,12,ts2,R)]` — a clean
/// write-then-read to forge.
fn register_side_note() -> SideNote {
    use zkpvm::core::step::PvmStep;
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 5;
    regs[1] = 7;
    let code = vec![
        Opcode::Add64 as u8,
        0x10,
        2, // ra=0, rb=1, rd=2
        Opcode::Add64 as u8,
        0x22,
        3, // ra=2, rb=2, rd=3
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 1, 0, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10_000,
        25,
    );
    let mut tr = TracingPvm::new(pvm);
    assert_eq!(tr.run(), javm::ExitReason::Trap);
    let steps: Vec<PvmStep> = tr.into_trace();
    assert_eq!(steps[0].regs_after[2], 12);
    assert_eq!(steps[1].regs_before[2], 12);

    let mut sn = SideNote::new(steps, code, bitmask);
    // Mirror `prepare_side_note_for_verification`: engage the closing chip
    // ledger augmentation + seed initial/final register state exactly as the
    // production prove path does.
    sn.closing_chip_active = true;
    let first = &sn.steps[0];
    let last = &sn.steps[sn.steps.len() - 1];
    for i in 0..NUM_REGS {
        sn.initial_regs[i] = first.regs_before[i];
        sn.final_regs[i] = last.regs_after[i];
    }
    sn
}

// GREEN since the register-ledger fix landed (cross-row prev_value binding +
// (reg,ts) sortedness + is_write tuple-binding).  See
// docs/plans/ledger-read-consistency.md.
#[test]
fn register_forged_read_value_is_rejected() {
    use zkpvm::chips::register_memory::Column;

    let side_note = register_side_note();
    let chip = RegisterMemoryChip;
    let mut trace = chip.generate_component_trace_immut(&side_note);

    let regaddr = Column::RegAddr.offset();
    let value = Column::Value.offset();
    let is_write = Column::IsWrite.offset();
    let prev_value = Column::PrevValue.offset();
    let is_padding = Column::IsPadding.offset();

    // Control: the honest trace satisfies every constraint.
    assert_chip(&chip, &trace, &side_note)
        .expect("honest register-ledger trace must satisfy all constraints");

    // Locate φ2's read row (RegAddr=2, IsWrite=0, real, Value low-byte=12).
    let read_row = find_row(&trace, |at| {
        at(regaddr) == BaseField::from(2u32)
            && at(is_write) == BaseField::from(0u32)
            && at(is_padding) == BaseField::from(0u32)
            && at(value) == BaseField::from(12u32)
    });
    // The honest fill pins this read's prev_value to the previous ledger
    // row's value — the φ2 write of 12.
    assert_eq!(
        trace.original_trace[prev_value].as_slice()[read_row],
        BaseField::from(12u32),
        "honest φ2 read row must carry prev_value = 12 (the prior write)"
    );

    // Forge: claim the read returned L=99 and set its own prev_value=99 so
    // read-consistency (`value − prev_value = 0`) still holds.  The *actual*
    // previous ledger row still carries 12.
    let lie = BaseField::from(99u32);
    trace.original_trace[value].as_mut_slice()[read_row] = lie;
    trace.original_trace[prev_value].as_mut_slice()[read_row] = lie;

    let res = assert_chip(&chip, &trace, &side_note);
    assert!(
        res.is_err(),
        "SOUNDNESS GAP: a φ2 read forged to 99 (with prev_value:=99) while the \
         prior ledger row writes 12 was ACCEPTED by RegisterMemoryChip — read \
         consistency is vacuous cross-row (no prev_value binding to the previous \
         row's value)."
    );
}

// ── RAM ledger ──────────────────────────────────────────────────────────────

/// StoreIndU8 `0x42 → [0x1000]` (write at ts=1), then LoadIndU8 `[0x1000]`
/// (read 0x42 at ts=2).  Address 0x1000 is write-first, so the byte ledger is
/// `[(0x1000,0x42,ts1,W), (0x1000,0x42,ts2,R)]`.
fn memory_side_note() -> SideNote {
    use zkpvm::core::step::PvmStep;
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0x42; // value
    regs[1] = 0x1000; // base address
    let code = vec![
        Opcode::StoreIndU8 as u8,
        0x10,
        0,
        0,
        0,
        0, // ra=0 src, rb=1 base, imm=0
        Opcode::LoadIndU8 as u8,
        0x12,
        0,
        0,
        0,
        0, // ra=2 dst, rb=1 base, imm=0
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10_000,
        25,
    );
    let mut tr = TracingPvm::new(pvm);
    assert_eq!(tr.run(), javm::ExitReason::Trap);
    let steps: Vec<PvmStep> = tr.into_trace();
    assert_eq!(steps[1].regs_after[2], 0x42);
    let mut sn = SideNote::new(steps, code, bitmask);
    // Phase A: MemoryChip now injects the per-page `ts=0` boundary writes +
    // closing reads and enforces the group-start/group-end constraints, so the
    // honest trace requires the memory-page payload the prove path builds.
    sn.ingest_memory_pages();
    sn
}

// GREEN since the RAM-ledger fix landed (cross-row prev_value binding +
// (addr,ts) sortedness).  See docs/plans/ledger-read-consistency.md.
#[test]
fn memory_forged_read_value_is_rejected() {
    use zkpvm::chips::memory::Column;

    let side_note = memory_side_note();
    let chip = MemoryChip;
    let mut trace = chip.generate_component_trace_immut(&side_note);

    let addr = Column::Address.offset(); // 4 bytes LE
    let value = Column::Value.offset(); // 1 byte
    let is_write = Column::IsWrite.offset();
    let prev_value = Column::PrevValue.offset();
    let is_padding = Column::IsPadding.offset();

    // Control: honest trace satisfies every constraint.
    assert_chip(&chip, &trace, &side_note)
        .expect("honest RAM-ledger trace must satisfy all constraints");

    // Locate the load row (addr byte1=0x10 ⇒ 0x1000, IsWrite=0, real,
    // Value=0x42).
    let read_row = find_row(&trace, |at| {
        at(addr) == BaseField::from(0u32)
            && at(addr + 1) == BaseField::from(0x10u32)
            && at(is_write) == BaseField::from(0u32)
            && at(is_padding) == BaseField::from(0u32)
            && at(value) == BaseField::from(0x42u32)
    });
    assert_eq!(
        trace.original_trace[prev_value].as_slice()[read_row],
        BaseField::from(0x42u32),
        "honest [0x1000] load row must carry prev_value = 0x42 (the prior store)"
    );

    // Forge: claim the load returned 0x99 with prev_value:=0x99.
    let lie = BaseField::from(0x99u32);
    trace.original_trace[value].as_mut_slice()[read_row] = lie;
    trace.original_trace[prev_value].as_mut_slice()[read_row] = lie;

    let res = assert_chip(&chip, &trace, &side_note);
    assert!(
        res.is_err(),
        "SOUNDNESS GAP: a [0x1000] load forged to 0x99 (with prev_value:=0x99) \
         while the prior ledger row stores 0x42 was ACCEPTED by MemoryChip — \
         read consistency is vacuous cross-row."
    );
}
