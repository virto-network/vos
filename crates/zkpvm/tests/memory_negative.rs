//! Negative-test corpus for CpuChip's memory constraints + MemoryChip
//! ledger consistency (Phase 15-prep).
//!
//! Each test crafts an honest store/load trace, mutates a memory-related
//! witness column (mem_write.value, mem_read.value, mem_read.address),
//! and asserts prove+verify fails.  Together they pin down the
//! load-from-store consistency the AIR enforces via the byte-level
//! memory lookup.

mod common;
use common::*;

use javm::PVM_REGISTER_COUNT;
use javm::instruction::Opcode;
use javm::interpreter::Interpreter;

use zkpvm::core::step::PvmStep;
use zkpvm::core::tracing::TracingPvm;

/// Build a Store-then-Load program: store regs[0]'s low byte at addr=regs[1],
/// then load that byte into regs[2].  Trap follows.
fn store_load_program() -> (Vec<u8>, Vec<u8>) {
    let code = vec![
        Opcode::StoreIndU8 as u8, 0x10, 0, 0, 0, 0,  // ra=0 src, rb=1 base, imm=0
        Opcode::LoadIndU8  as u8, 0x12, 0, 0, 0, 0,  // ra=2 dst, rb=1 base, imm=0
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1];
    (code, bitmask)
}

fn trace_store_load(value: u8, addr: u32) -> (Vec<u8>, Vec<u8>, Vec<PvmStep>) {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = value as u64;
    regs[1] = addr as u64;
    let memory = vec![0u8; 4 * 1024 * 1024];
    let (code, bitmask) = store_load_program();
    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, memory, 10_000, 25);
    let mut tr = TracingPvm::new(pvm);
    let exit = tr.run();
    assert_eq!(exit, javm::ExitReason::Trap);
    let steps = tr.into_trace();
    assert_eq!(steps.len(), 3);
    (code, bitmask, steps)
}

#[test]
fn store_load_positive_smoke() {
    let (code, bitmask, steps) = trace_store_load(0x42, 0x1000);
    assert_eq!(steps[1].regs_after[2], 0x42);
    prove_and_verify(steps, &code, &bitmask);
}

// Phase 15-load-result fix: forging regs_after[dest_reg] on a Load step
// is now caught by the per-byte active-byte binding constraint
// (`is_load · mem_byte_active[i] · (result[i] - mem_value[i]) = 0`).
// Inactive bytes are not yet bound — that's the "tighten signed-load
// extension" follow-up that would need a per-variant IsLoadSigned flag.
#[test]
#[should_panic(expected = "failed")]
fn store_then_load_forged_dest_reg_rejected() {
    let (code, bitmask, mut steps) = trace_store_load(0x42, 0x1000);
    steps[1].regs_after[2] = 0xFF; // honest = 0x42
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn store_forged_value_rejected() {
    // Forge the STORE step's mem_write.value: claim we wrote a different
    // byte than what was actually stored.  The store consumer emits
    // (addr, forged_value, ts, is_write=1).  The matching load demands
    // (addr, real_value_from_register, ts, is_write=0) from the ledger.
    // They no longer balance.
    let (code, bitmask, mut steps) = trace_store_load(0x42, 0x1000);
    if let Some(ref mut w) = steps[0].mem_write {
        w.value = 0xFF; // honest = 0x42
    }
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn load_forged_address_rejected() {
    // Forge the LOAD step's mem_read.address.  The original store at
    // 0x1000 produces a ledger entry at 0x1000; the load's lookup at a
    // different address won't find a match → logup imbalance.
    let (code, bitmask, mut steps) = trace_store_load(0x42, 0x1000);
    if let Some(ref mut r) = steps[1].mem_read {
        r.address = 0x2000; // honest = 0x1000
    }
    prove_and_verify(steps, &code, &bitmask);
}
