//! Trace-assembly helpers for proving an actor's PVM execution.
//!
//! These functions encapsulate the "parse a PVM blob → build an
//! Interpreter → run a trace → assemble a SideNote" pipeline that
//! every prove-side caller of an actor binary needs. The helpers
//! lived as copy-pasted boilerplate in `voucher_check_smoke.rs`,
//! `prove_vos_actor.rs`, and the `clerk-prover` extension until Phase
//! Z0's review surfaced the duplication; consolidating them here
//! keeps the trace-assembly invariants in one place (precompile
//! record forwarding, ristretto boundary ingest, stack-pointer seed).
//!
//! Callers that need to inject runtime witness state (patching
//! flat_mem before tracing) should build the `Interpreter` with
//! [`interpreter_from_blob`], mutate `interp.flat_mem`, then drive
//! `TracingPvm` directly — the witness protocol is callsite-specific
//! and intentionally not part of this module.

use javm::{
    PVM_PAGE_SIZE, PVM_REGISTER_COUNT, compute_mem_cycles,
    interpreter::Interpreter,
    program::{self, CapEntryType},
};

use crate::SideNote;
use crate::core::tracing::TracingPvm;

/// Build a fresh `Interpreter` from a parsed PVM blob's CODE + DATA
/// capabilities. Returns `(interp, flat_mem)` — the second tuple
/// element is a clone of the same `flat_mem` the interpreter was
/// constructed with, so the caller can hand it to
/// `SideNote::with_memory` (which the MemoryChip's initial-image
/// binding requires) without losing the interpreter's view.
///
/// Stack pointer (register 1) is seeded at the top of the largest
/// DATA cap, matching the `vosx run`-time convention.
///
/// `gas` caps execution length. Pass a generous bound for production
/// traces (e.g. `100_000_000` for the voucher-check workload) and
/// expect `ExitReason::OutOfGas` if the actor exceeds it.
///
/// Returns `None` if the blob isn't parseable or lacks a CODE cap.
pub fn interpreter_from_blob(blob: &[u8], gas: u64) -> Option<(Interpreter, Vec<u8>)> {
    let parsed = program::parse_blob(blob)?;

    let mut code_data = None;
    for entry in &parsed.caps {
        if entry.cap_type == CapEntryType::Code {
            code_data = Some(program::cap_data(entry, parsed.data_section).to_vec());
            break;
        }
    }
    let code_blob = program::parse_code_blob(&code_data?)?;

    let mut flat_mem_size: usize = 0;
    for entry in &parsed.caps {
        if entry.cap_type == CapEntryType::Data {
            let end =
                (entry.base_page as usize + entry.page_count as usize) * PVM_PAGE_SIZE as usize;
            flat_mem_size = flat_mem_size.max(end);
        }
    }
    let mut flat_mem = vec![0u8; flat_mem_size];

    for entry in &parsed.caps {
        if entry.cap_type == CapEntryType::Data {
            let addr = entry.base_page as usize * PVM_PAGE_SIZE as usize;
            let data = program::cap_data(entry, parsed.data_section);
            let len = data.len().min(flat_mem.len().saturating_sub(addr));
            if len > 0 {
                flat_mem[addr..addr + len].copy_from_slice(&data[..len]);
            }
        }
    }

    let mut registers = [0u64; PVM_REGISTER_COUNT];
    for entry in &parsed.caps {
        if entry.cap_type == CapEntryType::Data {
            let top = (entry.base_page as u64 + entry.page_count as u64) * PVM_PAGE_SIZE as u64;
            if top > registers[1] {
                registers[1] = top;
            }
        }
    }

    let mem_cycles = compute_mem_cycles(parsed.header.memory_pages);
    let flat_mem_copy = flat_mem.clone();
    let interp = Interpreter::new(
        code_blob.code.to_vec(),
        code_blob.bitmask.to_vec(),
        code_blob.jump_table.to_vec(),
        registers,
        flat_mem,
        gas,
        mem_cycles,
    );
    Some((interp, flat_mem_copy))
}

/// Trace a PVM blob end-to-end and return a `SideNote` ready for
/// `prove`. Runs the interpreter under
/// [`TracingPvm::run_with_vos_stubs`] so every precompile call
/// record (blake2b, ristretto field ops, ristretto add, scalar
/// reduce, scalar binop) is forwarded into the `SideNote` for the
/// matching ECALL chips to consume.
///
/// Returns `None` if the blob isn't parseable. The interpreter's
/// exit reason (Trap, OutOfGas, HostCall, …) is intentionally
/// dropped — callers that need it should drive `TracingPvm`
/// directly via [`interpreter_from_blob`].
pub fn trace_blob(blob: &[u8], gas: u64) -> Option<SideNote> {
    let parsed = program::parse_blob(blob)?;
    let mut code_data = None;
    for entry in &parsed.caps {
        if entry.cap_type == CapEntryType::Code {
            code_data = Some(program::cap_data(entry, parsed.data_section).to_vec());
            break;
        }
    }
    let code_blob = program::parse_code_blob(&code_data?)?;
    let (interp, flat_mem) = interpreter_from_blob(blob, gas)?;

    let mut tracing = TracingPvm::new(interp);
    let _ = tracing.run_with_vos_stubs();

    let blake2b_calls: Vec<_> = tracing.blake2b_calls().to_vec();
    let blake2b_mem_ops = tracing.blake2b_mem_ops.clone();
    let ristretto_calls: Vec<_> = tracing.ristretto_calls().to_vec();
    let ristretto_mem_ops = tracing.ristretto_mem_ops.clone();
    let ristretto_add_records = tracing.ristretto_add_records.clone();
    let ristretto_add_mem_ops = tracing.ristretto_add_mem_ops.clone();
    let scalar_reduce_records = tracing.scalar_reduce_wide_records.clone();
    let scalar_reduce_mem_ops = tracing.scalar_reduce_wide_mem_ops.clone();
    let scalar_binop_records = tracing.scalar_binop_records.clone();
    let scalar_binop_mem_ops = tracing.scalar_binop_mem_ops.clone();
    let steps = tracing.into_trace();

    let mut side_note = SideNote::new(steps, code_blob.code.to_vec(), code_blob.bitmask.to_vec())
        .with_memory(flat_mem)
        .with_jump_table(code_blob.jump_table.to_vec());

    for c in &blake2b_calls {
        side_note
            .blake2b_calls
            .push(crate::chips::blake2b::Blake2bCall {
                h: c.h,
                m: c.m,
                t: c.t,
                f: c.f,
            });
    }
    side_note.blake2b_mem_ops = blake2b_mem_ops;
    side_note.ristretto_calls = ristretto_calls;
    side_note.ristretto_mem_ops = ristretto_mem_ops;
    side_note.ristretto_add_calls = ristretto_add_records;
    side_note.ristretto_add_mem_ops = ristretto_add_mem_ops;
    side_note.scalar_reduce_wide_calls = scalar_reduce_records;
    side_note.scalar_reduce_wide_mem_ops = scalar_reduce_mem_ops;
    side_note.scalar_binop_calls = scalar_binop_records;
    side_note.scalar_binop_mem_ops = scalar_binop_mem_ops;
    side_note.ingest_ristretto_boundary();

    Some(side_note)
}
