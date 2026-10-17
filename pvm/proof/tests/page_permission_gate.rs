#![cfg(feature = "debug-internals")]

//! Negative AIR gates for page permissions: a proof's run is the run on
//! its program's pages, whose permissions it carries. A store to a
//! read-only page, or any access to an unmapped page, faults on the
//! machine; its run continued on a machine with that page writable is
//! refused.

use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::{Interpreter, PERM_NONE, PERM_RO, PERM_RW};
use vos_pvm::{ExitReason, PVM_REGISTER_COUNT, PVM_ZONE_SIZE};
use vos_pvm_proof::SideNote;
use vos_pvm_proof::core::tracing::TracingPvm;

/// A byte in the middle of page 17, above the protected low zone.
const A: u32 = PVM_ZONE_SIZE + 0x1000 + 0x800;
const V: u8 = 0x42;

/// `StoreIndU8 φ0 → [φ1]`, `LoadIndU8 [φ1 + 8] → φ2`, a trap, with φ0 = V
/// and φ1 = A, on a machine whose page at A has `permission`.
fn machine(permission: u8) -> (Interpreter, Vec<u8>, Vec<u8>, Vec<u8>) {
    let code = vec![
        Opcode::StoreIndU8 as u8,
        0x10,
        0,
        0,
        0,
        0,
        Opcode::LoadIndU8 as u8,
        0x12,
        8,
        0,
        0,
        0,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1];
    let mut registers = [0u64; PVM_REGISTER_COUNT];
    registers[0] = u64::from(V);
    registers[1] = u64::from(A);
    let memory = vec![0u8; 4 * 1024 * 1024];
    let mut pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        registers,
        memory.clone(),
        10_000,
    );
    assert!(
        pvm.memory_mut()
            .set_page_range((A / 4096) as usize, 1, permission)
    );
    (pvm, code, bitmask, memory)
}

/// The store faults on a read-only or unmapped page; the run on a machine
/// with the page writable, proven, is refused.
#[test]
fn a_store_to_a_read_only_page_is_refused() {
    for permission in [PERM_RO, PERM_NONE] {
        let (pvm, ..) = machine(permission);
        let mut tracer = TracingPvm::new(pvm);
        assert_eq!(tracer.run(), ExitReason::PageFault(A & !0xfff));
    }
    let (pvm, code, bitmask, memory) = machine(PERM_RW);
    let mut tracer = TracingPvm::new(pvm);
    assert_eq!(tracer.run(), ExitReason::Panic);
    let mut side_note = SideNote::new(tracer.into_trace(), code, bitmask).with_memory(memory);
    let refused = match vos_pvm_proof::prove(&mut side_note) {
        Err(_) => true,
        Ok(proof) => vos_pvm_proof::verify(proof, &side_note).is_err(),
    };
    assert!(refused, "SOUNDNESS GAP: the run on a writable page proved");
}
