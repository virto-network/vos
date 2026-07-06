#![cfg(feature = "debug-internals")]

//! GATE test for the CpuChip step-timestamp chaining soundness fix.
//!
//! The program-execution lookup sequences steps by a multiset permutation
//! over `(timestamp, pc) → (next_timestamp, next_pc)` pairs anchored by the
//! ProgramBoundaryChip's `(initial_ts, initial_pc)` / `(final_ts, final_pc)`.
//! Without binding `NextTimestamp = Timestamp + 1`, that permutation also
//! balances disjoint timestamp cycles (e.g. two rows producing/consuming each
//! other at attacker-chosen timestamps), so a forged step can emit a
//! register/memory tuple at a timestamp OUTSIDE `[initial_ts, final_ts)` —
//! notably `ts = 0` or `ts = closing_ts`, which the memory-root boundary
//! binding reserves for its boundary writes / closing reads.
//!
//! This builds an HONEST CpuChip trace, then tampers a single real row's
//! `NextTimestamp` low byte (bypassing the honest filler, exactly what a
//! from-scratch prover does) and asserts the chip's AIR constraints REJECT
//! it.  RED before the `NextTimestamp = Timestamp + 1` carry-chain constraint
//! landed; GREEN after.
//!
//! Run with: `cargo test -p zkpvm --features debug-internals --test
//! cpu_ts_chain_gate`.

use javm::PVM_REGISTER_COUNT;
use javm::instruction::Opcode;
use javm::interpreter::Interpreter;

use zkpvm::AirColumn;
use zkpvm::SideNote;
use zkpvm::chips::CpuChip;
use zkpvm::core::step::NUM_REGS;
use zkpvm::core::tracing::TracingPvm;
use zkpvm::framework_access::AllLookupElements;
use zkpvm::harness::MachineProverComponent;
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

fn find_row(trace: &ComponentTrace, pred: impl Fn(&dyn Fn(usize) -> BaseField) -> bool) -> usize {
    let n = trace.original_trace[0].as_slice().len();
    (0..n)
        .find(|&r| {
            let at = |off: usize| trace.original_trace[off].as_slice()[r];
            pred(&at)
        })
        .expect("no row matched the search predicate")
}

/// Two Add64 steps then Trap: timestamps 1, 2, 3 — a clean chained ts run.
fn side_note() -> SideNote {
    use zkpvm::core::step::PvmStep;
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 5;
    regs[1] = 7;
    let code = vec![
        Opcode::Add64 as u8,
        0x10,
        2,
        Opcode::Add64 as u8,
        0x22,
        3,
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

    let mut sn = SideNote::new(steps, code, bitmask);
    sn.closing_chip_active = true;
    let first = &sn.steps[0];
    let last = &sn.steps[sn.steps.len() - 1];
    for i in 0..NUM_REGS {
        sn.initial_regs[i] = first.regs_before[i];
        sn.final_regs[i] = last.regs_after[i];
    }
    sn
}

#[test]
fn forged_next_timestamp_is_rejected() {
    use zkpvm::chips::cpu::Column;

    let mut sn = side_note();
    let chip = CpuChip;
    let mut trace = chip.generate_component_trace(&mut sn);

    let timestamp = Column::Timestamp.offset();
    let next_ts = Column::NextTimestamp.offset();
    let is_padding = Column::IsPadding.offset();

    // Control: the honest trace satisfies every CpuChip constraint.
    assert_chip(&chip, &trace, &sn).expect("honest CpuChip trace must satisfy all constraints");

    // Locate the first real step (Timestamp low byte = 1, not padding).
    let step0 = find_row(&trace, |at| {
        at(is_padding) == BaseField::from(0u32) && at(timestamp) == BaseField::from(1u32)
    });
    assert_eq!(
        trace.original_trace[next_ts].as_slice()[step0],
        BaseField::from(2u32),
        "honest step-0 NextTimestamp low byte must be 2 (ts + 1)"
    );

    // Forge: pin NextTimestamp back to the step's own timestamp (a "stuck"
    // counter — the building block of a balanced ts cycle).  The carry chain
    // cannot absorb this (it would require carry = 1/256), so the
    // `NextTimestamp = Timestamp + 1` constraint must reject.
    trace.original_trace[next_ts].as_mut_slice()[step0] = BaseField::from(1u32);

    let res = assert_chip(&chip, &trace, &sn);
    assert!(
        res.is_err(),
        "SOUNDNESS GAP: a step whose NextTimestamp was forged to equal its own \
         Timestamp (enabling a balanced ts cycle outside [initial_ts, final_ts)) \
         was ACCEPTED by CpuChip — step timestamps are not chained."
    );
}
