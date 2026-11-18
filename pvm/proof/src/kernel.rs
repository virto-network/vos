//! A kernel's run re-traced for its proof, from what its attest recorded.
//!
//! An attest records its kernel's program and the bytes the kernel read
//! through its witness input (`vos_abi::result::Attest::witness_input`).
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
use vos_pvm::interpreter::{Interpreter, PERM_NONE};
pub use vos_pvm::interpreter::{Memory, PERM_RO, PERM_RW};
use vos_pvm::precompile::WitnessRead;

use crate::SideNote;
use crate::core::step::CompactStep;
use crate::core::tracing::TracingPvm;
use crate::sparse_memory::SparseMemoryImage;

/// A kernel's run, traced: what a proof of it starts from and proves, and
/// what it ended with.
pub struct KernelTrace {
    /// The trace as the tracer records it ([`TracingPvm::into_run`]), its
    /// precompile calls and its initial memory: what the segments are cut
    /// from, each expanded on its own; [`SideNote::expand`] expands it whole.
    pub side_note: SideNote<CompactStep>,
    /// The initial memory, whose page-tree root is the kernel's image root.
    pub image: SparseMemoryImage,
    /// Its output, by the halt convention: φ7's address, φ8's length.
    pub output: Vec<u8>,
    /// Its io-hash, φ9 to φ12 at its halt, eight little-endian bytes each.
    pub io_hash: [u8; 32],
    /// Each witness-input call it made, in order.
    pub reads: Vec<WitnessRead>,
}

/// Why a kernel's run could not be re-traced: the kind of refusal alone,
/// none of the run's values (its exit's address or step, the bytes it
/// read), which stay with the prover role.
#[derive(Debug, PartialEq, Eq)]
pub enum KernelTraceError {
    /// The blob is not a standard program, or its layout does not fit.
    Program,
    /// The blob is a standard program in other bytes than its one encoding
    /// (`vos_pvm_program::parse_canonical_standard_program`): a kernel's
    /// identity is its blob's hash, so an installed kernel has one blob.
    NotCanonical,
    /// The program's code is longer than a proof's program memory holds,
    /// one row a code byte up to [`crate::proof::MAX_PROOF_LOG_SIZE`]'s
    /// rows: a valid program the prover cannot take, refused before it
    /// runs.
    Code,
    /// A jump-table entry, a static jump's or a branch's target is no basic
    /// block start (`vos_pvm::interpreter::bad_transfer`): the machine
    /// panics at that transfer, and the pin, which knows instruction starts
    /// alone, would let a proof continue there or, for a table entry naming
    /// the halt address, end as a halt.
    Transfer,
    /// The input is past a witness input's cap.
    Input,
    /// The run stopped otherwise than by its halt.
    Exit,
    /// A kernel's nonempty output is not readable where φ7 and φ8 name it:
    /// the kernel contract, stricter than Gray Paper Ψ_M, which reads such
    /// an output as the empty string, as [`trace_program`] does.
    Output,
    /// The host could not allocate the output.
    Allocation,
    /// It read fewer bytes than the input holds: it is not the run the
    /// input was recorded from.
    Unread,
    /// The run took more steps than its trace is held to
    /// ([`trace_kernel_within`]; [`crate::MAX_RUN_STEPS`], the most a proof
    /// orders, for [`trace_kernel`] and [`trace_program`]): stopped there,
    /// before its trace grows past them.
    Steps,
}

/// Program `blob` loaded as the agent loads it, on `arguments` with `gas`:
/// its machine at its first step, its initial memory, and its layout's
/// permissions.
fn load(
    blob: &[u8],
    arguments: &[u8],
    gas: u64,
    forge: impl FnOnce(&mut Memory),
) -> Result<
    (
        Interpreter,
        SparseMemoryImage,
        crate::memory_layout::MemoryLayout,
    ),
    KernelTraceError,
> {
    let program = vos_pvm::spi::parse_standard_program(blob).ok_or(KernelTraceError::Program)?;
    if program.code.code.len() > 1 << crate::proof::MAX_PROOF_LOG_SIZE {
        return Err(KernelTraceError::Code);
    }
    let layout = program.layout(arguments).ok_or(KernelTraceError::Program)?;
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
    forge(&mut memory);
    let image: SparseMemoryImage = memory.nonzero_page_image().into();
    let permissions = crate::memory_layout::MemoryLayout::standard(&layout);
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
/// preprocessed roots are computed from. Refused if `blob` is not its
/// program's one encoding ([`KernelTraceError::NotCanonical`]), or if any
/// of its control transfers lands on no basic block start
/// ([`KernelTraceError::Transfer`]).
pub fn kernel_side_note(blob: &[u8]) -> Result<SideNote, KernelTraceError> {
    let (machine, image, permissions) = load(blob, &[], 0, |_| {})?;
    if vos_pvm_program::parse_canonical_standard_program(blob).is_none() {
        return Err(KernelTraceError::NotCanonical);
    }
    let side_note = TracingPvm::new(machine)
        .into_side_note()
        .with_sparse_memory(image)
        .with_memory_layout(permissions);
    if vos_pvm::interpreter::bad_transfer(
        &side_note.code,
        &side_note.bitmask,
        &side_note.jump_table,
    )
    .is_some()
    {
        return Err(KernelTraceError::Transfer);
    }
    Ok(side_note)
}

/// Run kernel `blob` with `gas` on `input`, its witness input, as the
/// agent runs it: the standard layout with no arguments, φ0 the halt
/// address, φ1 the stack's top, φ7 the argument window and φ8 0. Its halt
/// is held to the kernel contract: a nonempty output is readable
/// ([`KernelTraceError::Output`]); an empty one is empty whatever φ7.
pub fn trace_kernel(blob: &[u8], input: &[u8], gas: u64) -> Result<KernelTrace, KernelTraceError> {
    trace_kernel_within(blob, input, gas, crate::MAX_RUN_STEPS)
}

/// [`trace_kernel`] held to `max_steps` steps: a run that takes more is
/// stopped at them and refused ([`KernelTraceError::Steps`]). The trace's
/// memory is in its steps, about a hundred bytes each beside the calls'
/// records, and the steps a gas are the gas model's (a block's price is
/// its pipeline's cycles, several instructions a cycle): `max_steps` bounds
/// it whatever `gas` is.
pub fn trace_kernel_within(
    blob: &[u8],
    input: &[u8],
    gas: u64,
    max_steps: usize,
) -> Result<KernelTrace, KernelTraceError> {
    trace(blob, &[], Some(input), gas, max_steps, Contract::Kernel, |_| {})
}

/// [`trace_kernel`] with the machine's memory changed by `forge` before
/// the run (its pages' permissions, its bytes), the change in the run's
/// entering image: the device forgery gates' runs, which no loader makes.
/// The tests' dev edge alone (`seeded-masks`).
#[cfg(feature = "seeded-masks")]
pub fn trace_forged_kernel(
    blob: &[u8],
    input: &[u8],
    gas: u64,
    forge: impl FnOnce(&mut Memory),
) -> Result<KernelTrace, KernelTraceError> {
    trace(
        blob,
        &[],
        Some(input),
        gas,
        crate::MAX_RUN_STEPS,
        Contract::Kernel,
        forge,
    )
}

/// Run standard program `blob` with `gas` on `arguments`, mapped read-only
/// in its argument window, with no witness input: φ7 the window and φ8
/// its length. The witness-input call is not served, as the refine host
/// serves it to no machine of its own: a run that makes it stops there and
/// is refused ([`KernelTraceError::Exit`]). Its output is Gray Paper Ψ_M's
/// (`vos_pvm::refine::halt_output`): empty for a zero length whatever φ7,
/// and for a range any byte of which is unreadable.
pub fn trace_program(
    blob: &[u8],
    arguments: &[u8],
    gas: u64,
) -> Result<KernelTrace, KernelTraceError> {
    trace(
        blob,
        arguments,
        None,
        gas,
        crate::MAX_RUN_STEPS,
        Contract::Gray,
        |_| {},
    )
}

/// [`trace_kernel`] run to whatever exit it reaches, a trap included: its
/// side note and how it stopped, what a forged trace of a run that does not
/// halt starts from. The tests' dev edge alone (`seeded-masks`).
#[cfg(feature = "seeded-masks")]
pub fn trace_kernel_to_exit(
    blob: &[u8],
    input: &[u8],
    gas: u64,
) -> Result<(SideNote, ExitReason), KernelTraceError> {
    let (mut tracer, image, permissions) = start(blob, &[], Some(input), gas, |_| {})?;
    let exit = tracer.run_with_precompiles();
    let side_note = tracer
        .into_side_note()
        .with_sparse_memory(image)
        .with_memory_layout(permissions);
    Ok((side_note, exit))
}

/// `blob` loaded on `arguments` with `gas`, `forge` applied, its tracer at
/// its first step, serving the witness-input call from `input` when given.
fn start(
    blob: &[u8],
    arguments: &[u8],
    input: Option<&[u8]>,
    gas: u64,
    forge: impl FnOnce(&mut Memory),
) -> Result<
    (
        TracingPvm,
        SparseMemoryImage,
        crate::memory_layout::MemoryLayout,
    ),
    KernelTraceError,
> {
    let (machine, image, permissions) = load(blob, arguments, gas, forge)?;
    let tracer = TracingPvm::new(machine);
    let tracer = match input {
        Some(input) => tracer
            .with_witness_input(input.to_vec())
            .ok_or(KernelTraceError::Input)?,
        None => tracer,
    };
    Ok((tracer, image, permissions))
}

/// Whose output rule a trace's halt is held to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Contract {
    /// Gray Paper Ψ_M's: an output any byte of which is unreadable is the
    /// empty string.
    Gray,
    /// A kernel's: a nonempty output is readable, or the trace is refused
    /// ([`KernelTraceError::Output`]).
    Kernel,
}

fn trace(
    blob: &[u8],
    arguments: &[u8],
    input: Option<&[u8]>,
    gas: u64,
    max_steps: usize,
    contract: Contract,
    forge: impl FnOnce(&mut Memory),
) -> Result<KernelTrace, KernelTraceError> {
    let (mut tracer, image, permissions) = start(blob, arguments, input, gas, forge)?;
    let exit = tracer
        .run_with_precompiles_within(max_steps)
        .ok_or(KernelTraceError::Steps)?;
    if exit != ExitReason::Halt {
        return Err(KernelTraceError::Exit);
    }
    if let Some((_, left)) = tracer.witness_cursor()
        && left > 0
    {
        return Err(KernelTraceError::Unread);
    }
    let registers = tracer.pvm.registers;
    // Readability is checked before anything is allocated for it: a halt
    // may name any length.
    let output = vos_pvm::refine::halt_output(tracer.pvm.memory(), &registers, usize::MAX)
        .map_err(|_| KernelTraceError::Allocation)?;
    if output.is_empty() && registers[8] != 0 && contract == Contract::Kernel {
        return Err(KernelTraceError::Output);
    }
    let mut io_hash = [0u8; 32];
    for (bytes, word) in io_hash.chunks_exact_mut(8).zip(&registers[9..13]) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    let reads = core::mem::take(&mut tracer.witness_reads);
    let side_note = tracer
        .into_run()
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

#[cfg(test)]
mod tests {
    use vos_pvm_compiler::assembler::{Assembler, Reg};

    use super::{KernelTraceError, kernel_side_note, trace_kernel, trace_program};

    /// `asm`'s program with jump table `table`.
    fn with_table(asm: &Assembler, table: &[u32]) -> Vec<u8> {
        let mut program = vos_pvm_program::parse_standard_program(&asm.build()).unwrap();
        program.code.jump_table = table.to_vec();
        vos_pvm_program::build_standard_program(&program).unwrap()
    }

    /// A jump-table entry naming the halt address, through which a dynamic
    /// jump would end a proved run as a halt where the machine panics, is
    /// refused; one naming a block start is not.
    #[test]
    fn a_jump_table_naming_the_halt_address_is_refused() {
        let mut asm = Assembler::new();
        asm.set_stack_pages(1);
        asm.load_imm(Reg::T0, 2).jump_ind(Reg::T0, 0);
        let halt = vos_pvm::PVM_HALT_ADDR as u32;
        assert_eq!(
            kernel_side_note(&with_table(&asm, &[halt])).err(),
            Some(KernelTraceError::Transfer)
        );
        assert!(kernel_side_note(&with_table(&asm, &[0])).is_ok());
    }

    /// A branch to an instruction inside a block is refused; with a
    /// `fallthrough` ending the block before it, it is not.
    #[test]
    fn a_branch_into_a_block_is_refused() {
        let blob = |ended: bool| {
            let mut asm = Assembler::new();
            asm.set_stack_pages(1);
            asm.load_imm(Reg::T0, 0);
            if ended {
                asm.fallthrough();
            }
            let target = asm.current_offset();
            asm.load_imm(Reg::T1, 0);
            let here = asm.current_offset();
            asm.branch_lt_u_imm(Reg::T0, 1, target.wrapping_sub(here))
                .jump_ind(Reg::RA, 0);
            asm.build()
        };
        assert_eq!(
            kernel_side_note(&blob(false)).err(),
            Some(KernelTraceError::Transfer)
        );
        assert!(kernel_side_note(&blob(true)).is_ok());
    }

    /// A program that halts with φ7 `address` and φ8 `len`.
    fn halting_with(address: u64, len: u64) -> Vec<u8> {
        let mut asm = Assembler::new();
        asm.set_stack_pages(1);
        asm.load_imm_64(Reg::A0, address)
            .load_imm_64(Reg::A1, len)
            .jump_ind(Reg::RA, 0);
        asm.build()
    }

    /// An empty output is empty whatever its pointer, on either tracer.
    #[test]
    fn an_empty_halt_output_is_empty_whatever_its_pointer() {
        for address in [0, 0x1234, u64::from(u32::MAX), u64::MAX] {
            let blob = halting_with(address, 0);
            for arguments in [&[][..], &[1, 2, 3]] {
                let trace = trace_program(&blob, arguments, 1_000).expect("halts");
                assert!(trace.output.is_empty(), "{address:#x}");
            }
            let trace = trace_kernel(&blob, &[], 1_000).expect("halts");
            assert!(trace.output.is_empty(), "{address:#x}");
        }
    }

    /// A nonempty output any byte of which is unreadable: Ψ_M's empty
    /// string on the generic tracer, the kernel contract's refusal on a
    /// kernel's.
    #[test]
    fn an_unreadable_output_is_empty_but_breaks_the_kernel_contract() {
        for (address, len) in [(0, 1), (u64::MAX, 1), (0x1_0000, u64::MAX)] {
            let blob = halting_with(address, len);
            let trace = trace_program(&blob, &[], 1_000).expect("halts");
            assert!(trace.output.is_empty(), "{address:#x}+{len}");
            assert_eq!(
                trace_kernel(&blob, &[], 1_000).err(),
                Some(KernelTraceError::Output),
                "{address:#x}+{len}"
            );
        }
    }

    /// The witness-input call is served to a kernel alone: a standard
    /// program's trace stops at it and is refused, as the refine host
    /// serves it to no machine of its own and the call reaches its
    /// embedder.
    #[test]
    fn a_standard_program_is_served_no_witness_input() {
        let mut asm = Assembler::new();
        asm.set_stack_pages(1);
        asm.load_imm(Reg::A1, 0)
            .ecalli(vos_pvm::precompile::WITNESS_INPUT as u32)
            .load_imm(Reg::A0, 0)
            .load_imm(Reg::A1, 0)
            .jump_ind(Reg::RA, 0);
        let blob = asm.build();
        const GAS: u64 = 1_000_000;
        assert!(trace_kernel(&blob, &[], GAS).is_ok());
        assert_eq!(
            trace_program(&blob, &[], GAS).err(),
            Some(KernelTraceError::Exit)
        );
        let live = vos_pvm::refine_host::RefineContext::load(&blob, &[], GAS)
            .unwrap()
            .try_run()
            .unwrap();
        assert_eq!(
            live.exit,
            vos_pvm::ExitReason::HostCall(vos_pvm::precompile::WITNESS_INPUT)
        );
    }

    /// An installed kernel is its program's one encoding: the same program
    /// with its jump table a byte wider, which the Gray Paper reader takes,
    /// is refused by its own rule.
    #[test]
    fn a_kernel_in_other_bytes_is_refused() {
        let mut asm = Assembler::new();
        asm.set_stack_pages(1);
        asm.load_imm(Reg::T0, 2).jump_ind(Reg::T0, 0);
        let canonical = with_table(&asm, &[0]);
        assert!(kernel_side_note(&canonical).is_ok());
        // The compact code follows the header, the data (none) and its
        // four-byte length: `E(1) ⌢ E_1(1) ⌢ ...`; widen the table to 2.
        let at = vos_pvm_program::StandardHeader::LEN + 4;
        assert_eq!(&canonical[at..at + 2], &[1, 1]);
        let mut wide = canonical[..at].to_vec();
        wide.extend_from_slice(&[1, 2]);
        wide.extend_from_slice(&canonical[at + 2..at + 4]);
        wide.push(0);
        wide.extend_from_slice(&canonical[at + 4..]);
        let length = (wide.len() - at) as u32;
        wide[at - 4..at].copy_from_slice(&length.to_le_bytes());
        assert!(vos_pvm::spi::parse_standard_program(&wide).is_some());
        assert_eq!(
            kernel_side_note(&wide).err(),
            Some(KernelTraceError::NotCanonical)
        );
    }

    /// Code past what a proof's program memory holds is the prover's own
    /// refusal, before any run.
    #[test]
    fn code_past_the_program_memory_is_refused() {
        let len = (1usize << crate::proof::MAX_PROOF_LOG_SIZE) + 1;
        let program = vos_pvm_program::StandardProgram {
            ro_data: Vec::new(),
            rw_data: Vec::new(),
            heap_pages: 0,
            stack_size: 4096,
            code: vos_pvm_program::CodeBlob {
                jump_table: Vec::new(),
                code: vec![0; len],
                bitmask: vec![1; len],
            },
        };
        let blob = vos_pvm_program::build_standard_program(&program).unwrap();
        assert!(vos_pvm::spi::parse_standard_program(&blob).is_some());
        assert_eq!(
            super::trace_program(&blob, &[], 10).err(),
            Some(KernelTraceError::Code)
        );
    }
}
