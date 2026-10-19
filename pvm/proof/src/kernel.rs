//! A kernel's run re-traced for its proof, from what its attest recorded.
//!
//! An attest records its kernel's program and the bytes the kernel read
//! through its witness input (`vos_wire::result::Attest::witness_input`).
//! The prover lays the kernel out as the agent does, with no arguments,
//! serves its witness-input calls from those bytes and its BLAKE2b calls
//! natively, and runs it to its halt. The layout's pages and their
//! permissions go with the trace: they are its proof's, part of its program
//! identity. A kernel's reads are deterministic,
//! so the re-run reads what the live run read, call by call, and ends with
//! the same output and io-hash; one that reads less than the record, or
//! does not halt, is refused.
//!
//! [`trace_program`] runs any standard program on its arguments the same
//! way, for a proof of a run that reads no witness input.

use alloc::vec::Vec;

use vos_pvm::ExitReason;
use vos_pvm::interpreter::{Interpreter, Memory, PERM_NONE, PERM_RO, PERM_RW};
use vos_pvm::precompile::WitnessRead;

use crate::SideNote;
use crate::core::tracing::TracingPvm;
use crate::sparse_memory::SparseMemoryImage;

/// A kernel's run, traced: what a proof of it starts from and proves, and
/// what it ended with.
pub struct KernelTrace {
    /// The trace, its precompile calls and its initial memory: what the
    /// segments are cut from.
    pub side_note: SideNote,
    /// The initial memory, whose page-tree root is the kernel's image root.
    pub image: SparseMemoryImage,
    /// Its output, by the halt convention: φ7's address, φ8's length.
    pub output: Vec<u8>,
    /// Its io-hash, φ9 to φ12 at its halt, eight little-endian bytes each.
    pub io_hash: [u8; 32],
    /// Each witness-input call it made, in order.
    pub reads: Vec<WitnessRead>,
}

/// Why a kernel's run could not be re-traced.
#[derive(Debug, PartialEq, Eq)]
pub enum KernelTraceError {
    /// The blob is not a standard program, or its layout does not fit.
    Program,
    /// The input is past a witness input's cap.
    Input,
    /// The run stopped otherwise than by its halt.
    Exit(ExitReason),
    /// Its output is not readable where φ7 and φ8 name it.
    Output,
    /// It read fewer bytes than the input holds: it is not the run the
    /// input was recorded from.
    Unread { read: usize, input: usize },
}

/// Program `blob` loaded as the agent loads it, on `arguments` with `gas`:
/// its machine at its first step, its initial memory, and its layout's
/// permissions.
fn load(
    blob: &[u8],
    arguments: &[u8],
    gas: u64,
) -> Result<
    (
        Interpreter,
        SparseMemoryImage,
        crate::chips::memory_page::MemoryLayout,
    ),
    KernelTraceError,
> {
    let program = vos_pvm::spi::parse_standard_program(blob).ok_or(KernelTraceError::Program)?;
    let layout = program
        .layout(arguments)
        .ok_or(KernelTraceError::Program)?;
    let mut memory = Memory::sparse(1 << 32);
    let pages = memory.pages();
    let page = u64::from(vos_pvm::PVM_PAGE_SIZE);
    let mapped = memory.set_page_range(0, pages, PERM_NONE)
        && [layout.ro, layout.args, layout.rw, layout.stack]
            .into_iter()
            .filter(|region| region.size > 0)
            .all(|region| {
                let permission = if region.writable { PERM_RW } else { PERM_RO };
                memory.set_page_range(
                    (region.base / page) as usize,
                    (region.size / page) as usize,
                    permission,
                )
            });
    if !mapped {
        return Err(KernelTraceError::Program);
    }
    for (base, data) in [
        (layout.ro.base, layout.ro_data),
        (layout.args.base, layout.args_data),
        (layout.rw.base, layout.rw_data),
    ] {
        if !data.is_empty() {
            memory.init_copy(base as u32, data);
        }
    }
    let image: SparseMemoryImage = memory.nonzero_page_image().into();
    let permissions = crate::chips::memory_page::MemoryLayout::standard(&layout);
    let registers = layout.registers;
    let code = program.code;
    let machine = Interpreter::with_memory(
        code.code,
        code.bitmask,
        code.jump_table,
        registers,
        memory,
        gas,
    );
    Ok((machine, image, permissions))
}

/// Kernel `blob`'s program as a proof sees it before any run: its code,
/// jump table, initial memory and layout, and no step. What its
/// preprocessed roots are computed from.
pub fn kernel_side_note(blob: &[u8]) -> Result<SideNote, KernelTraceError> {
    let (machine, image, permissions) = load(blob, &[], 0)?;
    Ok(TracingPvm::new(machine)
        .into_side_note()
        .with_sparse_memory(image)
        .with_memory_layout(permissions))
}

/// Run kernel `blob` with `gas` on `input`, its witness input, as the
/// agent runs it: the standard layout with no arguments, φ0 the halt
/// address, φ1 the stack's top, φ7 the argument window and φ8 0.
pub fn trace_kernel(blob: &[u8], input: &[u8], gas: u64) -> Result<KernelTrace, KernelTraceError> {
    trace(blob, &[], input, gas)
}

/// Run standard program `blob` with `gas` on `arguments`, mapped read-only
/// in its argument window, with no witness input: φ7 the window and φ8
/// its length.
pub fn trace_program(
    blob: &[u8],
    arguments: &[u8],
    gas: u64,
) -> Result<KernelTrace, KernelTraceError> {
    trace(blob, arguments, &[], gas)
}

fn trace(
    blob: &[u8],
    arguments: &[u8],
    input: &[u8],
    gas: u64,
) -> Result<KernelTrace, KernelTraceError> {
    let (machine, image, permissions) = load(blob, arguments, gas)?;
    let mut tracer = TracingPvm::new(machine)
        .with_witness_input(input.to_vec())
        .ok_or(KernelTraceError::Input)?;
    let exit = tracer.run_with_precompiles();
    if exit != ExitReason::Halt {
        return Err(KernelTraceError::Exit(exit));
    }
    if let Some((read, left)) = tracer.witness_cursor()
        && left > 0
    {
        return Err(KernelTraceError::Unread {
            read,
            input: read + left,
        });
    }
    let registers = tracer.pvm.registers;
    let mut output =
        alloc::vec![0u8; usize::try_from(registers[8]).map_err(|_| KernelTraceError::Output)?];
    let address = u32::try_from(registers[7]).map_err(|_| KernelTraceError::Output)?;
    if !tracer.pvm.memory().read_bytes_checked(address, &mut output) {
        return Err(KernelTraceError::Output);
    }
    let mut io_hash = [0u8; 32];
    for (bytes, word) in io_hash.chunks_exact_mut(8).zip(&registers[9..13]) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    let reads = core::mem::take(&mut tracer.witness_reads);
    let side_note = tracer
        .into_side_note()
        .with_sparse_memory(image.clone())
        .with_memory_layout(permissions);
    Ok(KernelTrace {
        side_note,
        image,
        output,
        io_hash,
        reads,
    })
}
