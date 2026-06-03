#![cfg(feature = "prover")]

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
    (code, bitmask)
}

fn trace_store_load(value: u8, addr: u32) -> (Vec<u8>, Vec<u8>, Vec<PvmStep>) {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = value as u64;
    regs[1] = addr as u64;
    let memory = vec![0u8; 4 * 1024 * 1024];
    let (code, bitmask) = store_load_program();
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        memory,
        10_000,
        25,
    );
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

#[test]
#[should_panic(expected = "failed")]
fn load_forged_read_value_rejected() {
    // Isolated load-side forge: the load reads addr=0x1000 honestly, but
    // we claim it returned 0xFF instead of the 0x42 we stored.  Update
    // both mem_read.value AND regs_after[2] together so the per-byte
    // result-binding constraint (`is_load * mem_byte_active * (result -
    // mem_value) = 0`) stays satisfied — only the byte-level memory
    // ledger should catch the forgery: the load's lookup tuple is
    // (addr, 0xFF, ts, write=0) but no matching ledger entry exists.
    let (code, bitmask, mut steps) = trace_store_load(0x42, 0x1000);
    if let Some(ref mut r) = steps[1].mem_read {
        r.value = 0xFF; // honest = 0x42
    }
    steps[1].regs_after[2] = 0xFF; // keep result-binding consistent
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn store_forged_address_rejected() {
    // Forge the STORE step's mem_write.address: claim we wrote 0x42 to
    // 0x2000 instead of 0x1000.  The ledger now has (0x2000, 0x42)
    // instead of the (0x1000, 0x42) that the load demands; the load's
    // lookup at the honest 0x1000 finds the 0-init value but the
    // load-result constraint binds it to the (forged) regs_after[2]=
    // 0x42 → mismatch.  Either way, prove+verify must fail.
    let (code, bitmask, mut steps) = trace_store_load(0x42, 0x1000);
    if let Some(ref mut w) = steps[0].mem_write {
        w.address = 0x2000; // honest = 0x1000
    }
    prove_and_verify(steps, &code, &bitmask);
}

// ── U64 round-trip ─────────────────────────────────────────────────────────
//
// 8-byte stores/loads exercise per-byte memory accesses for all 8 bytes
// (vs only one byte for U8).  Catches gaps where the per-byte constraint
// fires on byte 0 but not on bytes 1..8.

fn store_load_u64_program() -> (Vec<u8>, Vec<u8>) {
    let code = vec![
        Opcode::StoreIndU64 as u8,
        0x10,
        0,
        0,
        0,
        0,
        Opcode::LoadIndU64 as u8,
        0x12,
        0,
        0,
        0,
        0,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1];
    (code, bitmask)
}

fn trace_store_load_u64(value: u64, addr: u32) -> (Vec<u8>, Vec<u8>, Vec<PvmStep>) {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = value;
    regs[1] = addr as u64;
    let memory = vec![0u8; 4 * 1024 * 1024];
    let (code, bitmask) = store_load_u64_program();
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        memory,
        10_000,
        25,
    );
    let mut tr = TracingPvm::new(pvm);
    let exit = tr.run();
    assert_eq!(exit, javm::ExitReason::Trap);
    let steps = tr.into_trace();
    assert_eq!(steps.len(), 3);
    (code, bitmask, steps)
}

#[test]
fn store_load_u64_positive_smoke() {
    let (code, bitmask, steps) = trace_store_load_u64(0xDEAD_BEEF_CAFE_BABE, 0x2000);
    assert_eq!(steps[1].regs_after[2], 0xDEAD_BEEF_CAFE_BABE);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn store_load_u64_forged_dest_reg_rejected() {
    // Result-binding constraint should fire on at least one of the 8
    // bytes — flipping any bit of regs_after[2] breaks per-byte equality
    // with the loaded mem_value.
    let (code, bitmask, mut steps) = trace_store_load_u64(0xDEAD_BEEF_CAFE_BABE, 0x2000);
    steps[1].regs_after[2] = 0xDEAD_BEEF_CAFE_BABF; // flip low bit
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn store_u64_forged_value_rejected() {
    // Forge mem_write.value: store claims a different u64.  The 8-byte
    // ledger entries diverge from the honest store, breaking the
    // load's matching consumer.
    let (code, bitmask, mut steps) = trace_store_load_u64(0xDEAD_BEEF_CAFE_BABE, 0x2000);
    if let Some(ref mut w) = steps[0].mem_write {
        w.value = 0x1111_2222_3333_4444; // honest = 0xDEAD_BEEF_CAFE_BABE
    }
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn load_u64_forged_address_rejected() {
    // Forge mem_read.address on the U64 load.  Per-byte address
    // arithmetic + ledger lookup must catch the mismatch on at least
    // one byte position.
    let (code, bitmask, mut steps) = trace_store_load_u64(0xDEAD_BEEF_CAFE_BABE, 0x2000);
    if let Some(ref mut r) = steps[1].mem_read {
        r.address = 0x3000; // honest = 0x2000
    }
    prove_and_verify(steps, &code, &bitmask);
}

// ── is_write discriminator forge tests ────────────────────────────────────
// CpuChip emits the MemoryAccess lookup tuple (addr, value, ts, is_write)
// with `is_write = is_store_col`.  IsStore is itself pinned to the
// canonical opcode via ProgramMemoryChip (Phase 23).  These tests hit the
// remaining "small" gap noted in PLAN: explicit forge-and-reject coverage
// for the is_write lookup field (vs. having soundness inferred from
// IsStore being opcode-pinned + ledger balance).

#[test]
#[should_panic(expected = "failed")]
fn store_drops_mem_write_rejected() {
    // Honest StoreIndU8 emits a MemoryAccess producer with is_write=1.
    // Forging step.mem_write = None makes the MemoryChip ledger skip
    // the entry, leaving the CpuChip producer unmatched → lookup
    // imbalance → ConstraintsNotSatisfied.
    let (code, bitmask, mut steps) = trace_store_load(0x42, 0x1000);
    steps[0].mem_write = None;
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn load_injects_mem_write_rejected() {
    // Forge step.mem_write on a Load row.  CpuChip on this row emits
    // is_write=0 (since IsStore=0 from the canonical Load decoding),
    // but the injected MemoryChip entry has is_write=1 → ledger
    // imbalance.
    let (code, bitmask, mut steps) = trace_store_load(0x42, 0x1000);
    // steps[1] is the LoadIndU8.  Inject a phantom write at the load's
    // address with the loaded value.
    let r = steps[1].mem_read.as_ref().unwrap().clone();
    steps[1].mem_write = Some(zkpvm::core::step::MemAccess {
        address: r.address,
        value: r.value,
        size: r.size,
    });
    prove_and_verify(steps, &code, &bitmask);
}
