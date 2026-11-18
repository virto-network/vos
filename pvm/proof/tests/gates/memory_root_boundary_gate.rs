#![cfg(feature = "debug-internals")]

//! Negative AIR gate for MemoryRootBoundaryChip's row flag.
//!
//! The chip consumes the trie's root `(0, 0, init_root, final_root)` with
//! multiplicity `−IsReal`. `IsReal` is boolean in the chip itself; the
//! verifier's closed-form check of the chip's claimed sum is a second,
//! independent pin on the total it emits.

use crate::forge::*;
use stwo::core::fields::m31::BaseField;
use vos_pvm::instruction::Opcode;
use vos_pvm_proof::AirColumn;
use vos_pvm_proof::SideNote;
use vos_pvm_proof::chips::MemoryRootBoundaryChip;
use vos_pvm_proof::chips::memory_root_boundary::Column as Root;
use vos_pvm_proof::harness::MachineProverComponent;

fn side_note() -> SideNote {
    let code = vec![Opcode::Trap as u8];
    let bitmask = vec![1];
    let pvm = vos_pvm::interpreter::Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        [0u64; vos_pvm::PVM_REGISTER_COUNT],
        vec![0u8; 0x2_0000],
        10_000,
    );
    let mut tracer = vos_pvm_proof::core::tracing::TracingPvm::new(pvm);
    tracer.run();
    let mut sn = SideNote::new(tracer.into_trace(), code, bitmask).with_memory(vec![0u8; 0x2_0000]);
    sn.ingest_memory_pages();
    sn
}

/// The real row's position in the bit-reversed storage order.
fn stored_row_0(log_size: u32) -> usize {
    let rows: Vec<BaseField> = (0..1u32 << log_size).map(BaseField::from).collect();
    let order = vos_pvm_proof::trace::utils::finalize_columns(vec![rows]);
    order[0]
        .as_slice()
        .iter()
        .position(|&at| at == BaseField::from(0u32))
        .expect("row 0")
}

/// G2-4. `IsReal = 2` consumes the root twice.
#[test]
fn is_real_two_is_refused() {
    let mut sn = side_note();
    let mut trace = MemoryRootBoundaryChip.generate_component_trace(&mut sn);
    assert_chip(&MemoryRootBoundaryChip, &trace, &sn);
    if !in_child!("is_real_two_is_refused") {
        return;
    }
    let at = stored_row_0(trace.log_size);
    trace.original_trace[Root::IsReal.offset()].as_mut_slice()[at] = BaseField::from(2u32);
    assert_chip(&MemoryRootBoundaryChip, &trace, &sn);
}
