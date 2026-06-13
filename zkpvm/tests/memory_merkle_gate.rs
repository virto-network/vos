#![cfg(feature = "debug-internals")]

//! GATE tests for the in-AIR memory-page Merkle binding gadget (design §7).
//!
//! These mirror `ledger_readconsistency_gate.rs` / `blake2b_boundary_gate.rs`:
//! build an HONEST single-chip component trace, tamper the finalized trace (or
//! the listed page set) exactly as a from-scratch prover would, and assert the
//! chip's AIR constraints REJECT it.  Each targets a distinct Phase-A soundness
//! property of the memory-root binding:
//!
//!   - entering-image (`ts=0` boundary write) forgery  → cross-row prev_value
//!     binding (`IsSameAddrNext·(prev_value_next − value) = 0`);
//!   - exit-image (closing read) forgery               → read consistency
//!     (`(1 − is_write)·(value − prev_value) = 0`);
//!   - omitted touched page                            → group-start gate
//!     (`IsGroupStart·timestamp_next = 0`);
//!   - untouched-subtree (witness sibling) forgery     → the shared-value rule
//!     (`IsWitness·(child_before − child_after) = 0`).
//!
//! The boundary-root → public-metadata binding (a forged `memory_root` over
//! honest columns) is covered separately by the override harness in
//! `boundary_binding.rs`; the verifier-side anchors (single-proof `initial_ts`,
//! chain `expected_initial_root`, `component_mask`) live in
//! `voucher_check_smoke.rs` / `chain_standalone.rs`.
//!
//! Run with: `cargo test -p zkpvm --features debug-internals --test
//! memory_merkle_gate`.

use javm::PVM_REGISTER_COUNT;
use javm::instruction::Opcode;
use javm::interpreter::Interpreter;

use zkpvm::AirColumn;
use zkpvm::SideNote;
use zkpvm::chips::{MemoryChip, MemoryMerkleChip};
use zkpvm::core::tracing::TracingPvm;
use zkpvm::framework_access::AllLookupElements;
use zkpvm::harness::MachineProverComponent;
use zkpvm::trace::component::ComponentTrace;

use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::m31::BaseField;

/// Regenerate a self-consistent interaction trace + claimed sum from the
/// (possibly tampered) main trace and run the chip's row-by-row
/// `AssertEvaluator`.  `Ok(())` iff every constraint holds; `Err(msg)` on the
/// first violation.
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

/// First storage row (finalized / bit-reversed order) satisfying `pred`.
fn find_row(trace: &ComponentTrace, pred: impl Fn(&dyn Fn(usize) -> BaseField) -> bool) -> usize {
    let n = trace.original_trace[0].as_slice().len();
    (0..n)
        .find(|&r| {
            let at = |off: usize| trace.original_trace[off].as_slice()[r];
            pred(&at)
        })
        .expect("no row matched the search predicate")
}

/// Trace `StoreIndU8 0x42 → [0x1000]` (page 1) + Trap, then ingest the
/// memory-page Merkle payload exactly as the prove path does.  The resulting
/// SideNote lists pages {0, 1} with a real multiproof (merge rows carrying
/// witness siblings) and a MemoryChip ledger holding the per-page `ts=0`
/// boundary writes + closing reads.
fn paged_side_note() -> SideNote {
    use zkpvm::core::step::PvmStep;
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0x42; // value
    regs[1] = 0x1000; // base address → page 1
    let code = vec![
        Opcode::StoreIndU8 as u8,
        0x10,
        0,
        0,
        0,
        0, // ra=0 src, rb=1 base, imm=0
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1];
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
    let mut sn = SideNote::new(steps, code, bitmask);
    sn.ingest_memory_pages();
    sn
}

// ── Entering-image forgery (entry boundary) ──────────────────────────────────

/// Forge the entering image byte carried by a `ts=0` boundary write.  Its
/// value is bound to the next ledger row's `prev_value` by the cross-row
/// binding `IsSameAddrNext·(prev_value_next − value) = 0`; tampering it while
/// the successor stays honest must REJECT (else a from-scratch prover claims a
/// false entering RAM image, diverging from the bound `initial_root`).
#[test]
fn entering_boundary_write_forgery_rejected() {
    use zkpvm::chips::memory::Column;

    let side_note = paged_side_note();
    let chip = MemoryChip;
    let mut trace = chip.generate_component_trace_immut(&side_note);

    let value = Column::Value.offset();
    let ts = Column::Timestamp.offset();
    let is_write = Column::IsWrite.offset();
    let is_same = Column::IsSameAddrNext.offset();
    let is_pad = Column::IsPadding.offset();

    assert_chip(&chip, &trace, &side_note)
        .expect("honest per-page memory ledger must satisfy all constraints");

    // A `ts=0` boundary write whose successor is the same address (its closing
    // read / first step access) — so the cross-row prev_value binding is live.
    let row = find_row(&trace, |at| {
        at(is_pad) == BaseField::from(0u32)
            && at(is_write) == BaseField::from(1u32)
            && at(is_same) == BaseField::from(1u32)
            && (0..8).all(|k| at(ts + k) == BaseField::from(0u32))
    });

    let honest = trace.original_trace[value].as_slice()[row];
    trace.original_trace[value].as_mut_slice()[row] = honest + BaseField::from(1u32);

    let res = assert_chip(&chip, &trace, &side_note);
    assert!(
        res.is_err(),
        "SOUNDNESS GAP: a forged entering `ts=0` boundary-write byte (while its \
         successor's prev_value stays honest) was ACCEPTED — the entering image \
         is not bound, so the claimed `initial_root` can diverge from the RAM the \
         steps actually read.",
    );
}

// ── Exit-image forgery (closing read) ────────────────────────────────────────

/// Forge a per-page closing-read value (the exit image byte).  The closing read
/// is a read, so read consistency `(1 − is_write)·(value − prev_value) = 0`
/// pins it to the byte's last written value; tampering it must REJECT (else the
/// claimed exit RAM image, hence `final_root`, can lie).
#[test]
fn closing_read_exit_forgery_rejected() {
    use zkpvm::chips::memory::Column;

    let side_note = paged_side_note();
    let chip = MemoryChip;
    let mut trace = chip.generate_component_trace_immut(&side_note);

    let value = Column::Value.offset();
    let is_closing = Column::IsClosing.offset();
    let is_write = Column::IsWrite.offset();
    let is_pad = Column::IsPadding.offset();

    assert_chip(&chip, &trace, &side_note)
        .expect("honest per-page memory ledger must satisfy all constraints");

    let row = find_row(&trace, |at| {
        at(is_pad) == BaseField::from(0u32)
            && at(is_closing) == BaseField::from(1u32)
            && at(is_write) == BaseField::from(0u32)
    });

    let honest = trace.original_trace[value].as_slice()[row];
    trace.original_trace[value].as_mut_slice()[row] = honest + BaseField::from(1u32);

    let res = assert_chip(&chip, &trace, &side_note);
    assert!(
        res.is_err(),
        "SOUNDNESS GAP: a forged closing-read (exit image) byte was ACCEPTED — \
         read consistency on the exit boundary is vacuous, so the claimed \
         `final_root` can diverge from the RAM the steps actually leave.",
    );
}

// ── Omitted touched page ─────────────────────────────────────────────────────

/// Drop the touched non-zero page from the listed set.  Its step store is then
/// no longer prefixed by a `ts=0` boundary write, so its address group starts
/// with a `ts > 0` access — the group-start gate (`IsGroupStart·timestamp_next
/// = 0`) must REJECT (else a prover hides writes by not listing their page).
#[test]
fn omitted_touched_page_rejected() {
    let chip = MemoryChip;

    let side_note = paged_side_note();
    let trace = chip.generate_component_trace_immut(&side_note);
    assert_chip(&chip, &trace, &side_note)
        .expect("honest per-page memory ledger must satisfy all constraints");

    let mut sn = paged_side_note();
    let dropped = sn
        .memory_pages
        .as_mut()
        .map(|p| {
            let before = p.pages.len();
            p.pages.retain(|pg| pg.page_idx != 1);
            before != p.pages.len()
        })
        .unwrap_or(false);
    assert!(dropped, "expected the store to list page 1 as touched");

    let forged = chip.generate_component_trace_immut(&sn);
    let res = assert_chip(&chip, &forged, &sn);
    assert!(
        res.is_err(),
        "SOUNDNESS GAP: a touched page omitted from the listed set was ACCEPTED — \
         page coverage is not enforced, so a prover can carry forged values across \
         a boundary by not listing the page it wrote.",
    );
}

// ── Untouched-subtree (witness sibling) forgery ──────────────────────────────

/// Forge a witness sibling's exit ("after") hash so it differs from its
/// entering ("before") hash.  Witness siblings are untouched subtrees whose
/// root is unchanged across the transition; the shared-value rule
/// `IsWitness·(child_before − child_after) = 0` must REJECT (else a prover
/// forges `final_root` over a subtree it never proved).
#[test]
fn merge_witness_after_tamper_rejected() {
    use zkpvm::chips::memory_merkle::Column;

    let side_note = paged_side_note();
    let chip = MemoryMerkleChip;
    let mut trace = chip.generate_component_trace_immut(&side_note);

    let is_real = Column::IsReal.offset();
    let is_wr = Column::IsWitnessRight.offset();
    let right_after = Column::RightAfter.offset();

    assert_chip(&chip, &trace, &side_note)
        .expect("honest merge schedule must satisfy all constraints");

    // Page 0 sits at index 0 (always the left child), so the combined subtree's
    // siblings are witnesses on the RIGHT.
    let row = find_row(&trace, |at| {
        at(is_real) == BaseField::from(1u32) && at(is_wr) == BaseField::from(1u32)
    });

    let honest = trace.original_trace[right_after].as_slice()[row];
    trace.original_trace[right_after].as_mut_slice()[row] = honest + BaseField::from(1u32);

    let res = assert_chip(&chip, &trace, &side_note);
    assert!(
        res.is_err(),
        "SOUNDNESS GAP: a witness sibling's after-hash forged to differ from its \
         before-hash was ACCEPTED — untouched-subtree reuse is not enforced, so a \
         prover can change `final_root` over a subtree it never proved.",
    );
}
