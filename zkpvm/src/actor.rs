//! Trace-assembly helpers for proving an actor's PVM execution.
//!
//! These functions encapsulate the "parse a PVM blob → build an
//! Interpreter → run a trace → assemble a SideNote" pipeline that
//! every prove-side caller of an actor binary needs, keeping the
//! trace-assembly invariants in one place (precompile record
//! forwarding, ristretto boundary ingest, stack-pointer seed).
//!
//! Callers that need to inject runtime witness state into a known
//! flat_mem offset (e.g. the host prover patching an actor's
//! `__VOS_WITNESS` buffer with opaque witness bytes) can use
//! [`trace_blob_with_patches`], which applies the patches before tracing
//! and still assembles the `SideNote` here.  Callers whose witness
//! protocol is more bespoke build the `Interpreter` with
//! [`interpreter_from_blob`], mutate `interp.flat_mem`, then drive
//! `TracingPvm` directly.

use javm::{
    PVM_PAGE_SIZE, PVM_REGISTER_COUNT, compute_mem_cycles,
    interpreter::Interpreter,
    program::{self, CapEntryType},
};

use crate::SideNote;
use crate::core::tracing::TracingPvm;
use crate::segment::{TraceStream, TracingSource};
use crate::side_note::CompactTrace;

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
/// traces (e.g. `100_000_000` for a heavy crypto workload) and
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
    trace_blob_with_patches(blob, gas, &[])
}

/// [`trace_blob`] in chain-holder form: the same traced run held as a
/// [`CompactTrace`] — steps without register snapshots, ~2.6× smaller
/// residency than the full `SideNote`, expandable window by window via
/// [`crate::segment::CompactSegmentCursor`]. The single-proof paths
/// assemble through it, and callers that need the whole run in hand
/// (offline cutting, equivalence tests) hold it; the chain drivers
/// themselves stream instead ([`trace_stream`]) and never hold any trace
/// form at all.
pub fn trace_blob_compact(blob: &[u8], gas: u64) -> Option<CompactTrace> {
    trace_blob_compact_with_patches(blob, gas, &[])
}

/// Like [`trace_blob`], but writes each `(offset, bytes)` patch into the
/// initial flat_mem (at `flat_mem[offset..offset + bytes.len()]`) before
/// tracing — both the interpreter's execution image and the `SideNote`'s
/// initial-memory binding see the patched bytes.
///
/// This is the host prover's opaque witness-injection path: `offset` is
/// the actor's `__VOS_WITNESS` ELF symbol address (which equals its
/// flat_mem offset) and `bytes` is the caller-supplied witness, which the
/// prover never interprets.  A patch whose range exceeds flat_mem makes
/// the call return `None`.  With an empty `patches` slice this is
/// identical to [`trace_blob`].
pub fn trace_blob_with_patches(
    blob: &[u8],
    gas: u64,
    patches: &[(usize, &[u8])],
) -> Option<SideNote> {
    // One assembly path: trace compactly, then expand — identical output
    // to assembling from full-step recording, at a transient cost of the
    // compact form alongside the expanded steps.
    Some(trace_blob_compact_with_patches(blob, gas, patches)?.into_side_note())
}

/// [`trace_blob_compact`] with initial-image patches — the compact twin of
/// [`trace_blob_with_patches`] (same patch semantics and `None` cases).
pub fn trace_blob_compact_with_patches(
    blob: &[u8],
    gas: u64,
    patches: &[(usize, &[u8])],
) -> Option<CompactTrace> {
    let setup = trace_setup(blob, gas, patches)?;
    let mut tracing = setup.tracing;
    let _ = tracing.run_with_vos_stubs();

    let blake2b_calls = tracing
        .blake2b_calls()
        .iter()
        .map(|c| crate::chips::blake2b::Blake2bCall {
            h: c.h,
            m: c.m,
            t: c.t,
            f: c.f,
        })
        .collect();
    let blake2b_mem_ops = std::mem::take(&mut tracing.blake2b_mem_ops);
    let ristretto_calls = std::mem::take(&mut tracing.ristretto_records);
    let ristretto_mem_ops = std::mem::take(&mut tracing.ristretto_mem_ops);
    let ristretto_add_calls = std::mem::take(&mut tracing.ristretto_add_records);
    let ristretto_add_mem_ops = std::mem::take(&mut tracing.ristretto_add_mem_ops);
    let scalar_reduce_wide_calls = std::mem::take(&mut tracing.scalar_reduce_wide_records);
    let scalar_reduce_wide_mem_ops = std::mem::take(&mut tracing.scalar_reduce_wide_mem_ops);
    let scalar_binop_calls = std::mem::take(&mut tracing.scalar_binop_records);
    let scalar_binop_mem_ops = std::mem::take(&mut tracing.scalar_binop_mem_ops);
    let (steps, initial_regs) = tracing.into_compact();

    Some(CompactTrace {
        steps,
        initial_regs,
        code: setup.code,
        bitmask: setup.bitmask,
        initial_memory: setup.initial_memory,
        jump_table: setup.jump_table,
        blake2b_calls,
        blake2b_mem_ops,
        ristretto_calls,
        ristretto_mem_ops,
        ristretto_add_calls,
        ristretto_add_mem_ops,
        scalar_reduce_wide_calls,
        scalar_reduce_wide_mem_ops,
        scalar_binop_calls,
        scalar_binop_mem_ops,
    })
}

/// The chain drivers' STREAMING entry point: trace `blob` incrementally,
/// cutting `(seg_steps, page_budget)` windows online (`page_budget == 0` =
/// uniform step cut) and yielding each window's `SideNote` as the run
/// reaches it — the whole trace is NEVER resident (peak step storage is
/// one window), unlike [`trace_blob_compact`] whose `CompactTrace` holds
/// every step until the segment loop ends. Same execution
/// (`run_with_vos_stubs` semantics), same cut, field-identical windows —
/// see [`TraceStream`]. `None` if the blob isn't parseable.
pub fn trace_stream(
    blob: &[u8],
    gas: u64,
    seg_steps: usize,
    page_budget: usize,
) -> Option<TraceStream<TracingSource>> {
    trace_stream_with_patches(blob, gas, &[], seg_steps, page_budget)
}

/// [`trace_stream`] with initial-image patches — the streaming twin of
/// [`trace_blob_compact_with_patches`] (same patch semantics and `None`
/// cases).
pub fn trace_stream_with_patches(
    blob: &[u8],
    gas: u64,
    patches: &[(usize, &[u8])],
    seg_steps: usize,
    page_budget: usize,
) -> Option<TraceStream<TracingSource>> {
    let setup = trace_setup(blob, gas, patches)?;
    Some(TraceStream::new(
        TracingSource::new(setup.tracing),
        setup.code,
        setup.bitmask,
        setup.jump_table,
        setup.initial_memory,
        seg_steps,
        page_budget,
    ))
}

/// A blob parsed + patched up to the brink of tracing: the tracer over the
/// (possibly patched) image, the pre-run image clone, and the
/// program-static fields. One setup path behind the run-to-completion
/// holders and the streaming driver, so the two trace identical runs.
struct TraceSetup {
    tracing: TracingPvm,
    initial_memory: Vec<u8>,
    code: Vec<u8>,
    bitmask: Vec<u8>,
    jump_table: Vec<u32>,
}

fn trace_setup(blob: &[u8], gas: u64, patches: &[(usize, &[u8])]) -> Option<TraceSetup> {
    let parsed = program::parse_blob(blob)?;
    let mut code_data = None;
    for entry in &parsed.caps {
        if entry.cap_type == CapEntryType::Code {
            code_data = Some(program::cap_data(entry, parsed.data_section).to_vec());
            break;
        }
    }
    let code_blob = program::parse_code_blob(&code_data?)?;
    let (mut interp, mut flat_mem) = interpreter_from_blob(blob, gas)?;

    // Inject the witness into the initial image. `interpreter_from_blob`
    // handed back a clone of the interpreter's flat_mem, so patch the
    // clone and sync it back into the interpreter — otherwise the trace
    // would execute over the unpatched original.
    if !patches.is_empty() {
        for (offset, bytes) in patches {
            let end = offset.checked_add(bytes.len())?;
            if end > flat_mem.len() {
                return None;
            }
            flat_mem[*offset..end].copy_from_slice(bytes);
        }
        interp.flat_mem = flat_mem.clone();
    }

    Some(TraceSetup {
        tracing: TracingPvm::new(interp),
        initial_memory: flat_mem,
        code: code_blob.code.to_vec(),
        bitmask: code_blob.bitmask.to_vec(),
        jump_table: code_blob.jump_table.to_vec(),
    })
}
