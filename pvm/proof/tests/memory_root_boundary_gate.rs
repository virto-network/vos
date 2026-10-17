#![cfg(feature = "debug-internals")]

//! Negative AIR gate for MemoryRootBoundaryChip's row flag.
//!
//! The chip consumes the trie's root `(0, 0, init_root, final_root)` with
//! multiplicity `−IsReal`. `IsReal` is boolean in the chip itself; the
//! verifier's closed-form check of the chip's claimed sum is a second,
//! independent pin on the total it emits.

use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::m31::BaseField;
use vos_pvm::instruction::Opcode;
use vos_pvm_proof::AirColumn;
use vos_pvm_proof::SideNote;
use vos_pvm_proof::chips::MemoryRootBoundaryChip;
use vos_pvm_proof::chips::memory_root_boundary::Column as Root;
use vos_pvm_proof::framework_access::AllLookupElements;
use vos_pvm_proof::harness::{MachineComponent, MachineProverComponent};
use vos_pvm_proof::trace::component::ComponentTrace;

fn assert_chip(trace: &ComponentTrace, side_note: &SideNote) {
    let chip = MemoryRootBoundaryChip;
    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut Blake2sChannel::default();
    chip.draw_lookup_elements(&mut lookup_elements, channel.into());
    let (interaction_trace, claimed_sum) =
        chip.generate_interaction_trace(trace.clone(), side_note, &lookup_elements);
    chip.debug_assert_constraints(trace, &interaction_trace, &lookup_elements, claimed_sum);
}

/// `true` in the child, which goes on to the forgery; the parent asserts the
/// child failed.
fn in_child(test_name: &str) -> bool {
    const CHILD: &str = "VOS_MEMORY_ROOT_BOUNDARY_GATE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return true;
    }
    let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg(test_name)
        .env(CHILD, "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run the forged trace in a child process");
    assert!(
        !status.success(),
        "SOUNDNESS GAP: MemoryRootBoundaryChip accepted the forgery of {test_name}"
    );
    false
}

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
    assert_chip(&trace, &sn);
    if !in_child("is_real_two_is_refused") {
        return;
    }
    let at = stored_row_0(trace.log_size);
    trace.original_trace[Root::IsReal.offset()].as_mut_slice()[at] = BaseField::from(2u32);
    assert_chip(&trace, &sn);
}
