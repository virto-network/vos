#![cfg(feature = "debug-internals")]

//! AIR regressions for authenticated precompile dispatch.
//!
//! A continued precompile row must expose the exact CPU selector
//! whose lookup emits the matching handler record. A from-scratch prover must
//! not be able to acknowledge a cryptographic Ecalli, clear or swap its exact
//! selector, and omit the handler-chip row while retaining the sequential
//! continuation.

use stwo::core::fields::m31::BaseField;
use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;
use vos_pvm::{ExitReason, PVM_REGISTER_COUNT, PVM_ZONE_SIZE};
use vos_pvm_proof::chips::CpuChip;
use vos_pvm_proof::chips::cpu::Column;
use vos_pvm_proof::core::ecall::proof_precompile_dispatch_id;
use vos_pvm_proof::core::tracing::{
    ECALL_BLAKE2B_COMPRESS, ECALL_RISTRETTO_POINT_ADD, ECALL_RISTRETTO_SCALAR_MULT,
    ECALL_SCALAR_ADD_MOD_L, ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE, ECALL_SCALAR_MUL_MOD_L,
    TracingPvm,
};
use vos_pvm_proof::framework_access::AllLookupElements;
use vos_pvm_proof::harness::{MachineComponent, MachineProverComponent};
use vos_pvm_proof::recursion_pcs::ProverChannel;
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

fn traced_side_note(id: u32) -> SideNote {
    // The host-call id as a four-byte little-endian immediate.
    let mut code = vec![Opcode::Ecalli as u8];
    code.extend_from_slice(&id.to_le_bytes());
    code.push(Opcode::Trap as u8);
    let bitmask = vec![1, 0, 0, 0, 0, 1];
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
    );
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run_with_precompiles(), ExitReason::Panic);
    SideNote::new(tracing.into_trace(), code, bitmask).with_memory(memory)
}

fn blake_side_note() -> SideNote {
    let [id_lo, id_hi, ..] = ECALL_BLAKE2B_COMPRESS.to_le_bytes();
    let code = vec![Opcode::Ecalli as u8, id_lo, id_hi, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[7] = ARG0_ADDR;
    regs[8] = ARG1_ADDR;
    regs[10] = 1;
    let memory = vec![0u8; PVM_ZONE_SIZE as usize + 0x2000];
    let pvm = Interpreter::new(code, bitmask, vec![], regs, memory.clone(), 10_000);
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run_with_precompiles(), ExitReason::Panic);
    assert_eq!(tracing.blake2b_records.len(), 1);
    let side_note = tracing.into_side_note().with_memory(memory);
    assert!(side_note.steps[0].host_call_acknowledged);
    assert_eq!((side_note.steps[0].pc, side_note.steps[0].next_pc), (0, 3));
    side_note
}

fn assert_cpu(chip: &CpuChip, trace: &ComponentTrace, side_note: &SideNote) -> Result<(), String> {
    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut ProverChannel::default();
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
        let mut side_note = traced_side_note(id);
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
                    && trace.original_trace[dispatch].as_slice()[row]
                        == BaseField::from(u32::from(proof_precompile_dispatch_id(u64::from(id))))
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
        let mut swapped = trace.clone();
        swapped.original_trace[selector].as_mut_slice()[row] = BaseField::from(0u32);
        swapped.original_trace[wrong_selector].as_mut_slice()[row] = BaseField::from(1u32);
        assert!(
            assert_cpu(&chip, &swapped, &side_note).is_err(),
            "SOUNDNESS GAP: acknowledged Ecalli {id} accepted with a wrong selector"
        );

        // A continued call must select a precompile relation even when the
        // dispatch it claims is zero: no continued call is relation-free.
        let mut relation_free = trace;
        relation_free.original_trace[selector].as_mut_slice()[row] = BaseField::from(0u32);
        relation_free.original_trace[dispatch].as_mut_slice()[row] = BaseField::from(0u32);
        assert!(
            assert_cpu(&chip, &relation_free, &side_note).is_err(),
            "SOUNDNESS GAP: acknowledged Ecalli {id} continued without any precompile relation"
        );
    }
}

/// Only an ECALLI row can be acknowledged. Forge a complete, internally
/// consistent precompile continuation on the terminal trap row: the
/// selector and dispatch agree, yet the CPU AIR must reject it.
#[test]
fn non_ecalli_row_cannot_be_acknowledged() {
    let mut side_note = traced_side_note(ECALL_SCALAR_ADD_MOD_L);
    let chip = CpuChip;
    let trace = chip.generate_component_trace(&mut side_note);
    assert_cpu(&chip, &trace, &side_note).expect("honest trace");

    let opcode = Column::Opcode.offset();
    let rows = trace.original_trace[0].as_slice().len();
    let trap_row = (0..rows)
        .find(|&row| {
            trace.original_trace[Column::IsTrap.offset()].as_slice()[row] == BaseField::from(1u32)
                && trace.original_trace[opcode].as_slice()[row]
                    == BaseField::from(u32::from(Opcode::Trap as u8))
        })
        .expect("terminal trap row");

    let mut forged = trace;
    for (column, value) in [
        (Column::HostCallAcknowledged, 1u32),
        (Column::Is114Ecall, 1),
        (
            Column::HostCallPrecompileDispatch,
            u32::from(proof_precompile_dispatch_id(u64::from(
                ECALL_SCALAR_ADD_MOD_L,
            ))),
        ),
    ] {
        forged.original_trace[column.offset()].as_mut_slice()[trap_row] = BaseField::from(value);
    }
    assert!(
        assert_cpu(&chip, &forged, &side_note).is_err(),
        "SOUNDNESS GAP: a trap row was accepted as an acknowledged precompile call"
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
