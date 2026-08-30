#![cfg(feature = "debug-internals")]

//! AIR regressions for authenticated precompile dispatch.
//!
//! A continued Standard precompile row must expose the exact CPU selector
//! whose lookup emits the matching handler record. A from-scratch prover must
//! not be able to acknowledge a cryptographic Ecalli, clear or swap its exact
//! selector, and omit the handler-chip row while retaining the sequential
//! continuation.

use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::m31::BaseField;
use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;
use vos_pvm::{ExitReason, IsaMode, PVM_REGISTER_COUNT, PVM_ZONE_SIZE};
use vos_pvm_proof::chips::CpuChip;
use vos_pvm_proof::chips::cpu::Column;
use vos_pvm_proof::core::tracing::{
    ECALL_BLAKE2B_COMPRESS, ECALL_RISTRETTO_POINT_ADD, ECALL_RISTRETTO_SCALAR_MULT,
    ECALL_SCALAR_ADD_MOD_L, ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE, ECALL_SCALAR_MUL_MOD_L,
    TracingPvm,
};
use vos_pvm_proof::framework_access::AllLookupElements;
use vos_pvm_proof::harness::{MachineComponent, MachineProverComponent};
use vos_pvm_proof::trace::component::ComponentTrace;
use vos_pvm_proof::{AirColumn, SideNote};

const ARG0_ADDR: u64 = PVM_ZONE_SIZE as u64 + 0x1000;
const ARG1_ADDR: u64 = ARG0_ADDR + 0x100;
const ARG2_ADDR: u64 = ARG1_ADDR + 0x100;

const PRECOMPILE_SELECTORS: [(u32, Column); 6] = [
    (ECALL_BLAKE2B_COMPRESS, Column::IsBlakeEcall),
    (ECALL_RISTRETTO_SCALAR_MULT, Column::Is110Ecall),
    (ECALL_RISTRETTO_POINT_ADD, Column::Is111Ecall),
    (ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE, Column::Is112Ecall),
    (ECALL_SCALAR_MUL_MOD_L, Column::Is113Ecall),
    (ECALL_SCALAR_ADD_MOD_L, Column::Is114Ecall),
];

fn traced_side_note(id: u32, isa_mode: IsaMode, precompile: bool) -> SideNote {
    let code = vec![Opcode::Ecalli as u8, id as u8, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 1];
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[7] = ARG0_ADDR;
    regs[8] = ARG1_ADDR;
    regs[9] = ARG2_ADDR;
    regs[10] = 1;
    let memory = vec![0u8; PVM_ZONE_SIZE as usize + 0x2000];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        memory.clone(),
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new_with_isa_mode(pvm, isa_mode);
    let exit = if precompile {
        tracing.run_with_precompiles()
    } else {
        tracing.run_with_vos_stubs()
    };
    assert_eq!(
        exit,
        match isa_mode {
            IsaMode::Conformance => ExitReason::Panic,
            IsaMode::Jar => ExitReason::Trap,
        }
    );
    SideNote::new(tracing.into_trace(), code, bitmask)
        .with_isa_mode(isa_mode)
        .with_memory(memory)
}

fn blake_side_note() -> SideNote {
    let code = vec![
        Opcode::Ecalli as u8,
        ECALL_BLAKE2B_COMPRESS as u8,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 1];
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[7] = ARG0_ADDR;
    regs[8] = ARG1_ADDR;
    regs[10] = 1;
    let memory = vec![0u8; PVM_ZONE_SIZE as usize + 0x2000];
    let pvm = Interpreter::new(code, bitmask, vec![], regs, memory.clone(), 10_000, 25);
    let mut tracing = TracingPvm::new_conformance(pvm);
    assert_eq!(tracing.run_with_precompiles(), ExitReason::Panic);
    assert_eq!(tracing.blake2b_records.len(), 1);
    let side_note = tracing.into_side_note().with_memory(memory);
    assert!(side_note.steps[0].host_call_acknowledged);
    assert_eq!((side_note.steps[0].pc, side_note.steps[0].next_pc), (0, 2));
    side_note
}

fn assert_cpu(chip: &CpuChip, trace: &ComponentTrace, side_note: &SideNote) -> Result<(), String> {
    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut Blake2sChannel::default();
    chip.draw_lookup_elements(&mut lookup_elements, channel);
    let (interaction_trace, claimed_sum) =
        chip.generate_interaction_trace(trace.clone(), side_note, &lookup_elements);
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        chip.debug_assert_constraints(trace, &interaction_trace, &lookup_elements, claimed_sum);
    }))
    .map_err(|panic| {
        panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "<non-string panic>".into())
    })
}

#[test]
fn acknowledged_precompile_cannot_clear_or_swap_exact_dispatch_selector() {
    for (selector_index, &(id, selector_column)) in PRECOMPILE_SELECTORS.iter().enumerate() {
        let mut side_note = traced_side_note(id, IsaMode::Conformance, true);
        let chip = CpuChip;
        let trace = chip.generate_component_trace(&mut side_note);
        assert_cpu(&chip, &trace, &side_note)
            .unwrap_or_else(|error| panic!("honest acknowledged Ecalli {id}: {error}"));

        let selector = selector_column.offset();
        let acknowledged = Column::HostCallAcknowledged.offset();
        let dispatch = Column::HostCallPrecompileDispatch.offset();
        let rows = trace.original_trace[0].as_slice().len();
        let row = (0..rows)
            .find(|&row| {
                trace.original_trace[acknowledged].as_slice()[row] == BaseField::from(1u32)
                    && trace.original_trace[dispatch].as_slice()[row] == BaseField::from(id)
            })
            .unwrap_or_else(|| panic!("acknowledged Ecalli {id} CPU row"));
        assert_eq!(
            trace.original_trace[selector].as_slice()[row],
            BaseField::from(1u32)
        );

        // Exact audit forgery: clear the selector so CpuChip omits the
        // handler-call relation while retaining acknowledgment/continuation.
        let mut cleared = trace.clone();
        cleared.original_trace[selector].as_mut_slice()[row] = BaseField::from(0u32);
        assert!(
            assert_cpu(&chip, &cleared, &side_note).is_err(),
            "SOUNDNESS GAP: acknowledged Ecalli {id} accepted without its selector"
        );

        // Swapping to a different one-hot selector must fail the exact-ID
        // equality even though the at-most-one constraint remains satisfied.
        let wrong_selector = PRECOMPILE_SELECTORS
            [(selector_index + 1) % PRECOMPILE_SELECTORS.len()]
        .1
        .offset();
        let mut swapped = trace;
        swapped.original_trace[selector].as_mut_slice()[row] = BaseField::from(0u32);
        swapped.original_trace[wrong_selector].as_mut_slice()[row] = BaseField::from(1u32);
        assert!(
            assert_cpu(&chip, &swapped, &side_note).is_err(),
            "SOUNDNESS GAP: acknowledged Ecalli {id} accepted with a wrong selector"
        );
    }
}

#[test]
fn standard_stub_continues_without_a_precompile_selector() {
    let mut side_note = traced_side_note(1, IsaMode::Conformance, false);
    let chip = CpuChip;
    let trace = chip.generate_component_trace(&mut side_note);
    assert_cpu(&chip, &trace, &side_note)
        .expect("acknowledged lifecycle stub must satisfy CPU AIR");

    let rows = trace.original_trace[0].as_slice().len();
    let row = (0..rows)
        .find(|&row| {
            trace.original_trace[Column::HostCallAcknowledged.offset()].as_slice()[row]
                == BaseField::from(1u32)
        })
        .expect("acknowledged lifecycle-stub row");
    assert_eq!(
        trace.original_trace[Column::HostCallPrecompileDispatch.offset()].as_slice()[row],
        BaseField::from(0u32)
    );
    for &(_, selector) in &PRECOMPILE_SELECTORS {
        assert_eq!(
            trace.original_trace[selector.offset()].as_slice()[row],
            BaseField::from(0u32)
        );
    }
}

#[test]
fn jar_precompile_preserves_frozen_continuation_and_exact_selector() {
    let mut side_note = traced_side_note(ECALL_BLAKE2B_COMPRESS, IsaMode::Jar, true);
    let chip = CpuChip;
    let trace = chip.generate_component_trace(&mut side_note);
    assert_cpu(&chip, &trace, &side_note).expect("frozen Jar precompile must satisfy CPU AIR");

    let rows = trace.original_trace[0].as_slice().len();
    let row = (0..rows)
        .find(|&row| {
            trace.original_trace[Column::HostCallPrecompileDispatch.offset()].as_slice()[row]
                == BaseField::from(ECALL_BLAKE2B_COMPRESS)
        })
        .expect("Jar Blake2b row");
    assert_eq!(
        trace.original_trace[Column::HostCallAcknowledged.offset()].as_slice()[row],
        BaseField::from(0u32)
    );
    assert_eq!(
        trace.original_trace[Column::HostCallContinuesH.offset()].as_slice()[row],
        BaseField::from(1u32)
    );
    assert_eq!(
        trace.original_trace[Column::IsBlakeEcall.offset()].as_slice()[row],
        BaseField::from(1u32)
    );
}

#[test]
fn acknowledged_blake_call_cannot_omit_handler_record() {
    // Control: the complete record proves. This also prevents the negative
    // half from passing merely because the compact test program is invalid.
    let mut honest = blake_side_note();
    let proof = vos_pvm_proof::prove(&mut honest).expect("complete acknowledged precompile prove");
    vos_pvm_proof::verify(proof, &honest).expect("complete acknowledged precompile verify");

    let mut forged = blake_side_note();
    assert_eq!(forged.blake2b_calls.len(), 1);
    assert_eq!(forged.blake2b_mem_ops.len(), 1);
    forged.blake2b_calls.clear();
    forged.blake2b_mem_ops.clear();
    let rejected = match vos_pvm_proof::prove(&mut forged) {
        Err(_) => true,
        Ok(proof) => vos_pvm_proof::verify(proof, &forged).is_err(),
    };
    assert!(
        rejected,
        "SOUNDNESS GAP: acknowledged Ecalli 100 verified without its handler record"
    );
}
