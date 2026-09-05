//! Kernel-free refine-style execution of GP standard programs (SPI).
//!
//! [`execute`] loads a GP standard-program blob exactly the way
//! `InvocationKernel::new_standard` does — same memory image, page
//! permissions, register file, standard memory latency, and per-page init-gas
//! charge — but runs it on the plain [`Interpreter`] with no capability
//! microkernel and no hostcall dispatch. The whole path is `no_std`, so an
//! embedder (e.g. a wasm32 runtime) can perform pure refine invocations:
//! any `ecalli` surfaces as [`ExitReason::HostCall`] in the returned
//! [`Invocation`] for the embedder to reject or handle itself. Execution
//! always uses the interpreter — never the kernel or the recompiler — on
//! every target, which is the cross-machine determinism guarantee.
//!
//! Semantic-identity notes (pinned by unit tests against the kernel path):
//! - Memory image (GP eq A.42): read-only data at `Z_Z`, read-write data
//!   plus zeroed heap pages after a zone gap, a zeroed stack just below the
//!   argument zone, and the argument bytes in the top input zone. Pages in
//!   the gaps between regions are unmapped.
//! - Page permissions: the read-only and argument regions are mapped
//!   read-only; the read-write+heap and stack regions are read-write. This
//!   is a 1:1 map of [`crate::spi::SpiRegion::writable`], matching the
//!   `init_access` the kernel derives in `spi::to_manifest_blob`.
//! - Registers (GP eq A.43): φ0 = the halt address, φ1 = stack top,
//!   φ7/φ8 = argument base/length; entry is at instruction counter 0 (the
//!   refine / is-authorized entry point).
//! - ISA: [`crate::IsaMode::Conformance`], like the kernel's SPI path —
//!   opcode 3 (`Ecall`, the jar capability surface) panics.
//! - Standard load/store latency is the fixed 25 cycles specified by Gray
//!   Paper v0.8.0, independently of declared page count. Page-tier latency is
//!   confined to the capability/JAR service profile. The init charge still
//!   derives from *declared* mapped pages, never from allocated bytes, so it
//!   is independent of the memory representation.
//! - Gas: [`GAS_PER_PAGE`] is charged per mapped page up front (the
//!   kernel's init charge); a budget below that charge fails with
//!   [`RefineError::OutOfGas`] before executing anything. `gas_used`
//!   includes the init charge, so `budget - gas_used` equals the kernel
//!   VM's remaining gas.
//!
//! 32-bit embedders: the flat image of a real SPI program spans ~4 GiB
//! (GP maps the stack and argument regions just below 2³²), which cannot
//! exist inside a 32-bit heap. [`execute`] therefore selects the
//! interpreter's sparse memory representation on `target_pointer_width =
//! "32"` hosts and the flat one elsewhere; [`execute_with`] lets an
//! embedder force either via [`MemoryModel`]. The representations are
//! semantically indistinguishable — same exits, faulting page bases, gas,
//! registers, and logical memory — pinned by the differential tests below.

use alloc::vec;
use alloc::vec::Vec;

use crate::interpreter::{Interpreter, Memory, PERM_NONE, PERM_RO, PERM_RW};
use crate::spi::{deblob, parse_standard_program};
use crate::{
    ExitReason, GAS_PER_PAGE, Gas, IsaMode, PVM_INIT_INPUT_SIZE, PVM_PAGE_SIZE, PVM_REGISTER_COUNT,
    STANDARD_MEM_CYCLES,
};

/// Why [`execute`] could not run the program at all. Exits of a program
/// that did run (including `OutOfGas` *during* execution) are reported via
/// [`Invocation::exit`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefineError {
    /// The blob does not parse as a GP standard program.
    InvalidBlob,
    /// The memory layout does not fit the address space: the program's
    /// regions overflow the 32-bit guest space (GP eq A.42's total-size
    /// guard), the arguments exceed the `Z_I` input zone, or a flat image
    /// was requested that cannot exist in the host address space.
    LayoutOverflow,
    /// The gas budget is below the per-page memory-init charge.
    OutOfGas,
}

impl core::fmt::Display for RefineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidBlob => f.write_str("blob is not a GP standard program"),
            Self::LayoutOverflow => f.write_str("memory layout exceeds the address space"),
            Self::OutOfGas => f.write_str("gas budget below the memory-init charge"),
        }
    }
}

impl core::error::Error for RefineError {}

/// Which memory representation [`execute_with`] gives the interpreter.
/// Semantically indistinguishable; the choice is purely a host-resource
/// trade-off.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MemoryModel {
    /// Flat on 64-bit hosts (fastest: the ~4 GiB span is lazily-zeroed
    /// virtual memory), sparse on 32-bit hosts (where it cannot exist).
    #[default]
    Auto,
    /// Force the dense flat buffer. Fails with
    /// [`RefineError::LayoutOverflow`] when the span cannot be allocated
    /// on the host (32-bit hosts and real SPI layouts).
    Flat,
    /// Force the sparse page-table representation: allocation is
    /// O(touched pages) plus ~5 MiB of fixed tables for a full span.
    Sparse,
}

/// The result of a completed refine-style invocation.
#[derive(Debug, Clone)]
pub struct Invocation {
    /// How execution stopped. `HostCall`/`Ecall` are returned untouched —
    /// this harness dispatches nothing.
    pub exit: ExitReason,
    /// Total gas consumed: the per-page init charge plus execution gas.
    /// The budget minus this equals the kernel VM's remaining gas for the
    /// same blob/args/budget.
    pub gas_used: Gas,
    /// The register file φ at exit.
    pub registers: [u64; PVM_REGISTER_COUNT],
    /// Instruction counter at the exit boundary. Useful for deterministic
    /// diagnostics without exposing the interpreter itself.
    pub pc: u32,
    mem: Memory,
}

/// A loaded, resumable standard PVM invocation.
///
/// [`execute`] is the convenient one-shot API. Embedders that implement
/// standard host calls use this type to resume after each
/// [`ExitReason::HostCall`].
pub struct Machine {
    initial_gas: Gas,
    interp: Interpreter,
    terminal_exit: Option<ExitReason>,
}

/// Read-only entry and instruction events for one standard machine slice.
pub enum MachineObservation<'a> {
    Enter(&'a Interpreter),
    Instruction(crate::interpreter::InstructionObservation<'a>),
}

impl Machine {
    /// Construct the full Gray Paper Ψ boundary from a canonical compact PVM
    /// blob and an explicit architectural state.
    ///
    /// A failed `deblob(blob, initial_pc)` is represented as an immediate
    /// [`ExitReason::Panic`]. It charges no gas, preserves the gas-funded flag,
    /// all registers, memory bytes and permissions, and normalizes only the
    /// final instruction counter to zero as full Ψ requires.
    pub fn from_pvm_blob(
        pvm_blob: &[u8],
        initial_pc: u64,
        gas: Gas,
        gas_charged: bool,
        registers: [u64; PVM_REGISTER_COUNT],
        memory: Memory,
    ) -> Self {
        let (program, pc, terminal_exit) = match deblob(pvm_blob, initial_pc) {
            Some(program) => (
                program,
                u32::try_from(initial_pc).expect("deblob accepted a 32-bit code index"),
                None,
            ),
            None => (
                // This executable is never entered. It gives the rejected
                // machine an ordinary Interpreter owner for the unchanged
                // register/RAM state without attempting to predecode the
                // attacker-controlled blob.
                crate::program::ParsedCodeBlob {
                    jump_table: Vec::new(),
                    code: vec![0],
                    bitmask: vec![1],
                },
                0,
                Some(ExitReason::Panic),
            ),
        };
        let mut interp = Interpreter::with_memory_and_mode(
            program.code,
            program.bitmask,
            program.jump_table,
            registers,
            memory,
            gas,
            STANDARD_MEM_CYCLES,
            IsaMode::Conformance,
        );
        interp.set_pc(pc);
        interp.restore_boundary_state(gas_charged, None);
        Self {
            initial_gas: gas,
            interp,
            terminal_exit,
        }
    }

    /// Load a standard program using the automatically selected memory
    /// representation.
    pub fn load(spi_blob: &[u8], args: &[u8], gas: Gas) -> Result<Self, RefineError> {
        Self::load_with(spi_blob, args, gas, MemoryModel::Auto)
    }

    /// Load a standard program with an explicit memory representation.
    pub fn load_with(
        spi_blob: &[u8],
        args: &[u8],
        gas: Gas,
        model: MemoryModel,
    ) -> Result<Self, RefineError> {
        let prog = parse_standard_program(spi_blob).ok_or(RefineError::InvalidBlob)?;

        if args.len() as u64 > PVM_INIT_INPUT_SIZE as u64 {
            return Err(RefineError::LayoutOverflow);
        }
        let layout = prog.layout(args).ok_or(RefineError::LayoutOverflow)?;
        let regions = [layout.ro, layout.rw, layout.stack, layout.args];
        let registers = layout.registers;

        let page = PVM_PAGE_SIZE as u64;
        let total_pages: u64 = regions.iter().map(|r| r.size / page).sum();
        let mem_cycles = STANDARD_MEM_CYCLES;
        let init_gas = total_pages * GAS_PER_PAGE;
        if gas < init_gas {
            return Err(RefineError::OutOfGas);
        }

        let max_addr: u64 = regions
            .iter()
            .filter(|r| r.size > 0)
            .map(|r| r.base + r.size)
            .max()
            .unwrap_or(0);
        let use_sparse = match model {
            MemoryModel::Auto => cfg!(target_pointer_width = "32"),
            MemoryModel::Flat => false,
            MemoryModel::Sparse => true,
        };
        if !use_sparse && max_addr > isize::MAX as u64 {
            return Err(RefineError::LayoutOverflow);
        }
        let mut mem = if use_sparse {
            Memory::sparse(max_addr)
        } else {
            Memory::flat(vec![0u8; max_addr as usize])
        };
        let mut page_perms = vec![PERM_NONE; (max_addr / page) as usize];
        for r in regions.iter().filter(|r| r.size > 0) {
            let perm = if r.writable { PERM_RW } else { PERM_RO };
            let first = (r.base / page) as usize;
            page_perms[first..first + (r.size / page) as usize].fill(perm);
        }
        for (base, data) in [
            (layout.ro.base, layout.ro_data),
            (layout.rw.base, layout.rw_data),
            (layout.args.base, layout.args_data),
        ] {
            if !data.is_empty() {
                mem.init_copy(base as u32, data);
            }
        }

        let code = prog.code;
        let mut interp = Interpreter::with_memory_and_mode(
            code.code,
            code.bitmask,
            code.jump_table,
            registers,
            mem,
            gas - init_gas,
            mem_cycles,
            IsaMode::Conformance,
        );
        interp.set_page_perms(page_perms);

        Ok(Self {
            initial_gas: gas,
            interp,
            terminal_exit: None,
        })
    }

    /// Run until the next PVM exit.
    pub fn resume(&mut self) -> ExitReason {
        if let Some(exit) = &self.terminal_exit {
            return exit.clone();
        }
        // Resuming is the host's explicit advancement past a previously
        // surfaced ecalli. The first call is a no-op here.
        self.interp.resume_after_host_call();
        self.interp.run().0
    }

    /// Run until the next PVM exit while observing every instruction.
    ///
    /// This is the proof/diagnostic twin of [`Self::resume`]. It performs
    /// the same pending-host-call acknowledgement before entering the
    /// interpreter and delegates execution to
    /// [`Interpreter::run_observed`], whose callback receives immutable
    /// post-step state. Installing an observer therefore cannot perturb the
    /// standard machine's semantics.
    pub fn resume_observed(
        &mut self,
        mut observer: impl for<'a> FnMut(MachineObservation<'a>),
    ) -> ExitReason {
        self.interp.resume_after_host_call();
        observer(MachineObservation::Enter(&self.interp));
        if let Some(exit) = &self.terminal_exit {
            return exit.clone();
        }
        self.interp
            .run_observed(|instruction| {
                observer(MachineObservation::Instruction(instruction));
            })
            .0
    }

    /// Exact interpreter image owned by this standard machine.
    ///
    /// The returned reference is read-only so trace assemblers can capture
    /// the code, register, and sparse-memory boundary without acquiring a
    /// second execution implementation.
    pub fn interpreter(&self) -> &Interpreter {
        &self.interp
    }

    pub fn gas_remaining(&self) -> Gas {
        self.interp.gas
    }

    /// Whether the block containing the current counter is already funded.
    pub fn gas_charged(&self) -> bool {
        self.interp.gas_charged
    }

    /// Charge host-call gas. Returns `false` without wrapping when the
    /// invocation has insufficient gas.
    pub fn charge(&mut self, gas: Gas) -> bool {
        if self.interp.gas < gas {
            self.interp.gas = 0;
            false
        } else {
            self.interp.gas -= gas;
            true
        }
    }

    /// Return unused gas reserved for an inner invocation.
    pub fn credit(&mut self, gas: Gas) {
        self.interp.gas = self.interp.gas.saturating_add(gas);
    }

    pub fn registers(&self) -> &[u64; PVM_REGISTER_COUNT] {
        &self.interp.registers
    }

    pub fn registers_mut(&mut self) -> &mut [u64; PVM_REGISTER_COUNT] {
        &mut self.interp.registers
    }

    pub fn memory(&self) -> &Memory {
        self.interp.memory()
    }

    pub fn memory_mut(&mut self) -> &mut Memory {
        self.interp.memory_mut()
    }

    /// Consume the machine and retain its final state for inspection.
    pub fn finish(mut self, exit: ExitReason) -> Invocation {
        // Machine-produced Halt/Panic exits have already applied full Ψ's
        // PC-zero normalization. Do not normalize a host-owner-generated
        // failure here: failed/unknown dispatch retains the causing ecalli
        // counter because no successful continuation occurred.
        Invocation {
            exit,
            gas_used: self.initial_gas.saturating_sub(self.interp.gas),
            registers: self.interp.registers,
            pc: self.interp.pc,
            mem: self.interp.take_memory(),
        }
    }
}

impl Invocation {
    /// The output bytes designated by φ7/φ8 at a normal halt, per GP:
    /// `o = μ[φ7 .. φ7+φ8]`.
    ///
    /// Returns `None` unless the exit is [`ExitReason::Halt`] and the whole
    /// range lies on readable pages (GP treats an unreadable output range
    /// at halt as a panic ☇ — that judgement is the embedder's). A
    /// zero-length range is trivially readable.
    pub fn output(&self) -> Option<Vec<u8>> {
        if self.exit != ExitReason::Halt {
            return None;
        }
        let ptr = u32::try_from(self.registers[7]).ok()? as u64;
        let len = u32::try_from(self.registers[8]).ok()? as u64;
        if len == 0 {
            return Some(Vec::new());
        }
        let end = ptr + len;
        if end > self.mem.span() {
            return None;
        }
        let first = (ptr / PVM_PAGE_SIZE as u64) as usize;
        let last = ((end - 1) / PVM_PAGE_SIZE as u64) as usize;
        if self.mem.page_perms()[first..=last].contains(&PERM_NONE) {
            return None;
        }
        let mut out = vec![0u8; len as usize];
        self.mem.read_bytes(ptr as u32, &mut out);
        Some(out)
    }

    /// The guest memory at exit. Address 0 up to the end of the highest
    /// mapped region; read the logical image (unmapped gap pages are zero)
    /// via [`Memory::read_bytes`], which is representation-independent.
    pub fn memory(&self) -> &Memory {
        &self.mem
    }
}

/// Execute a GP standard-program blob as a pure refine-style invocation,
/// selecting the memory representation automatically
/// ([`MemoryModel::Auto`]).
///
/// Parses the canonical bare `spi_blob`, builds the GP memory image and
/// register file for `args`, charges the kernel's per-page init gas, and runs
/// the interpreter from instruction counter 0 (the refine entry) until it
/// exits. Metadata-prefixed predecessor blobs are rejected. No hostcalls are
/// handled: an `ecalli` ends the invocation with [`ExitReason::HostCall`].
pub fn execute(spi_blob: &[u8], args: &[u8], gas: Gas) -> Result<Invocation, RefineError> {
    execute_with(spi_blob, args, gas, MemoryModel::Auto)
}

/// [`execute`] with an explicit [`MemoryModel`].
pub fn execute_with(
    spi_blob: &[u8],
    args: &[u8],
    gas: Gas,
    model: MemoryModel,
) -> Result<Invocation, RefineError> {
    let mut machine = Machine::load_with(spi_blob, args, gas, model)?;
    let exit = machine.resume();
    Ok(machine.finish(exit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PVM_ZONE_SIZE;

    /// Wrap raw code + a memory profile in a bare GP standard-program blob
    /// (no metadata prefix). Mirrors the kernel tests' builder; sizes stay
    /// small so every length nat is a single byte.
    fn build_standard_program(
        ro: &[u8],
        rw: &[u8],
        heap_pages: u16,
        stack_size: u32,
        code: &[u8],
        bitmask: &[u8],
    ) -> Vec<u8> {
        let cb = build_pvm_blob(code, bitmask);

        let mut blob = Vec::new();
        blob.extend_from_slice(&(ro.len() as u32).to_le_bytes()[..3]); // E₃(|o|)
        blob.extend_from_slice(&(rw.len() as u32).to_le_bytes()[..3]); // E₃(|w|)
        blob.extend_from_slice(&heap_pages.to_le_bytes()); // E₂(z)
        blob.extend_from_slice(&stack_size.to_le_bytes()[..3]); // E₃(s)
        blob.extend_from_slice(ro);
        blob.extend_from_slice(rw);
        blob.extend_from_slice(&(cb.len() as u32).to_le_bytes()); // E₄(|c|)
        blob.extend_from_slice(&cb);
        blob
    }

    fn build_pvm_blob(code: &[u8], bitmask: &[u8]) -> Vec<u8> {
        assert!(code.len() < 128, "test code must fit a 1-byte nat");
        assert_eq!(code.len(), bitmask.len());
        // E(|j|=0) ‖ z=1 ‖ E(|c|) ‖ code ‖ packed bitmask.
        let mut blob = vec![0u8, 1u8, code.len() as u8];
        blob.extend_from_slice(code);
        let mut packed = vec![0u8; code.len().div_ceil(8)];
        for (i, &b) in bitmask.iter().enumerate() {
            if b != 0 {
                packed[i / 8] |= 1 << (i % 8);
            }
        }
        blob.extend_from_slice(&packed);
        blob
    }

    /// Tiny assembler: appends one instruction and its bitmask bit.
    fn asm(code: &mut Vec<u8>, bitmask: &mut Vec<u8>, inst: &[u8]) {
        bitmask.push(1);
        bitmask.extend(core::iter::repeat_n(0, inst.len() - 1));
        code.extend_from_slice(inst);
    }

    /// With no read-only data the read-write region starts at 2·Z_Z.
    const RW_BASE: u32 = 2 * PVM_ZONE_SIZE;

    /// A program that copies the first four argument bytes to the start of
    /// the read-write region, designates them as output via φ7/φ8, and
    /// halts: `φ2 ← u32[φ7]; φ3 ← RW_BASE; u32[φ3] ← φ2; φ7 ← RW_BASE;
    /// φ8 ← 4; djump(φ0)`.
    fn round_trip_blob() -> Vec<u8> {
        let (mut code, mut bits) = (Vec::new(), Vec::new());
        let [b0, b1, b2, _] = RW_BASE.to_le_bytes();
        asm(&mut code, &mut bits, &[128, 2 + 16 * 7]); // load_ind_u32 φ2, [φ7+0]
        asm(&mut code, &mut bits, &[51, 3, b0, b1, b2]); // load_imm φ3 = RW_BASE
        asm(&mut code, &mut bits, &[122, 2 + 16 * 3]); // store_ind_u32 [φ3+0], φ2
        asm(&mut code, &mut bits, &[51, 7, b0, b1, b2]); // load_imm φ7 = RW_BASE
        asm(&mut code, &mut bits, &[51, 8, 4]); // load_imm φ8 = 4
        asm(&mut code, &mut bits, &[50, 0]); // jump_ind φ0+0 → halt
        build_standard_program(&[], &[], 1, 4096, &code, &bits)
    }

    /// A program that trips a page fault in the first unmapped page at or
    /// above the standard 64 KiB access boundary.
    fn fault_gap_blob() -> Vec<u8> {
        let (mut code, mut bits) = (Vec::new(), Vec::new());
        asm(&mut code, &mut bits, &[51, 3, 0x00, 0x00, 0x01]); // φ3 = 0x10000
        asm(&mut code, &mut bits, &[130, 4 + 16 * 3]); // load_ind_u64 φ4, [φ3+0]
        asm(&mut code, &mut bits, &[0]); // trap (unreached)
        build_standard_program(&[], &[], 1, 4096, &code, &bits)
    }

    /// A program that writes to the argument region, which GP maps
    /// read-only: `u8[φ7] ← φ2` — a permission fault, not an unmapped one.
    fn ro_write_blob() -> Vec<u8> {
        let (mut code, mut bits) = (Vec::new(), Vec::new());
        asm(&mut code, &mut bits, &[120, 2 + 16 * 7]); // store_ind_u8 [φ7+0], φ2
        asm(&mut code, &mut bits, &[0]); // trap (unreached)
        build_standard_program(&[], &[], 1, 4096, &code, &bits)
    }

    /// A program exercising both GP memory clusters — the stack just below
    /// 2³² and the read-write region near 0 — then outputting the value it
    /// bounced between them: `φ2 ← 0x11223344; u64[φ1-8] ← φ2;
    /// φ3 ← u64[φ1-8]; φ4 ← RW_BASE; u64[φ4] ← φ3; φ5 ← u64[φ4];
    /// φ7 ← φ1-8; φ8 ← 8; djump(φ0)`. Its flat image spans ~4 GiB.
    fn stack_and_rw_blob() -> Vec<u8> {
        let (mut code, mut bits) = (Vec::new(), Vec::new());
        let [b0, b1, b2, _] = RW_BASE.to_le_bytes();
        let neg8 = (-8i8) as u8;
        asm(&mut code, &mut bits, &[51, 2, 0x44, 0x33, 0x22, 0x11]); // load_imm φ2
        asm(&mut code, &mut bits, &[123, 2 + 16, neg8]); // store_ind_u64 [φ1-8], φ2
        asm(&mut code, &mut bits, &[130, 3 + 16, neg8]); // load_ind_u64 φ3, [φ1-8]
        asm(&mut code, &mut bits, &[51, 4, b0, b1, b2]); // load_imm φ4 = RW_BASE
        asm(&mut code, &mut bits, &[123, 3 + 16 * 4]); // store_ind_u64 [φ4+0], φ3
        asm(&mut code, &mut bits, &[130, 5 + 16 * 4]); // load_ind_u64 φ5, [φ4+0]
        asm(&mut code, &mut bits, &[149, 7 + 16, neg8]); // add_imm_64 φ7 = φ1 - 8
        asm(&mut code, &mut bits, &[51, 8, 8]); // load_imm φ8 = 8
        asm(&mut code, &mut bits, &[50, 0]); // jump_ind φ0+0 → halt
        build_standard_program(&[], &[], 1, PVM_ZONE_SIZE, &code, &bits)
    }

    const ARGS: [u8; 6] = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02];
    /// rw (1 heap page) + stack (1 page) + args (1 page) = 3 mapped pages.
    const INIT_GAS: u64 = 3 * GAS_PER_PAGE;

    /// Compare the logical memory image of two invocations over
    /// `[start, end)` via reads (never the representation).
    fn assert_image_range_eq(f: &Invocation, s: &Invocation, start: u64, end: u64) {
        const CHUNK: usize = 4 << 20;
        let n0 = ((end - start) as usize).min(CHUNK);
        let mut bf = vec![0u8; n0];
        let mut bs = vec![0u8; n0];
        let mut addr = start;
        while addr < end {
            let n = ((end - addr) as usize).min(CHUNK);
            f.memory().read_bytes(addr as u32, &mut bf[..n]);
            s.memory().read_bytes(addr as u32, &mut bs[..n]);
            assert_eq!(bf[..n], bs[..n], "logical image diverges at {addr:#x}");
            addr += n as u64;
        }
    }

    /// Differential harness: the same blob/args/budget through the flat
    /// and the sparse memory representation must be indistinguishable —
    /// exit, gas, registers, output, and the logical memory image around
    /// every mapped region (each region plus a page of surrounding gap,
    /// and the span edges).
    fn assert_flat_sparse_parity(
        blob: &[u8],
        args: &[u8],
        gas: Gas,
    ) -> Option<(Invocation, Invocation)> {
        let f = execute_with(blob, args, gas, MemoryModel::Flat);
        let s = execute_with(blob, args, gas, MemoryModel::Sparse);
        match (f, s) {
            (Ok(f), Ok(s)) => {
                assert_eq!(f.exit, s.exit, "exit reasons agree");
                assert_eq!(f.gas_used, s.gas_used, "gas agrees");
                assert_eq!(f.registers, s.registers, "registers agree");
                assert_eq!(f.output(), s.output(), "outputs agree");
                assert_eq!(f.memory().span(), s.memory().span(), "spans agree");
                let span = f.memory().span();
                let page = PVM_PAGE_SIZE as u64;
                let prog = parse_standard_program(blob).expect("parses");
                let layout = prog.layout(args).expect("lays out");
                for r in [layout.ro, layout.rw, layout.stack, layout.args] {
                    if r.size > 0 {
                        let start = r.base.saturating_sub(page);
                        let end = (r.base + r.size + page).min(span);
                        assert_image_range_eq(&f, &s, start, end);
                    }
                }
                assert_image_range_eq(&f, &s, 0, page.min(span));
                if span > page {
                    assert_image_range_eq(&f, &s, span - page, span);
                }
                Some((f, s))
            }
            (Err(fe), Err(se)) => {
                assert_eq!(fe, se, "errors agree");
                None
            }
            (f, s) => panic!("representations disagree on executability: flat {f:?}, sparse {s:?}"),
        }
    }

    #[test]
    fn round_trips_args_through_memory() {
        let inv = execute(&round_trip_blob(), &ARGS, 1_000_000).expect("executes");
        assert_eq!(inv.exit, ExitReason::Halt);
        assert_eq!(
            inv.output().as_deref(),
            Some(&ARGS[..4]),
            "output reflects the args"
        );
        assert!(inv.gas_used > INIT_GAS, "execution consumed gas");
        assert_eq!(
            inv.registers[2],
            u32::from_le_bytes(ARGS[..4].try_into().unwrap()) as u64
        );
        assert_eq!(inv.registers[7], RW_BASE as u64);
        assert_eq!(inv.registers[8], 4);
    }

    #[test]
    fn gas_below_init_charge_is_an_error() {
        assert_eq!(
            execute(&round_trip_blob(), &ARGS, INIT_GAS - 1).unwrap_err(),
            RefineError::OutOfGas
        );
    }

    #[test]
    fn tiny_budget_exits_out_of_gas() {
        let inv = execute(&round_trip_blob(), &ARGS, INIT_GAS + 1).expect("init charge covered");
        assert_eq!(inv.exit, ExitReason::OutOfGas);
        assert_eq!(inv.output(), None);
    }

    #[test]
    fn opcode_zero_surfaces_as_standard_panic() {
        let blob = build_standard_program(&[], &[], 0, 4096, &[0], &[1]);
        let inv = execute(&blob, &[], 1_000_000).expect("executes");
        assert_eq!(inv.exit, ExitReason::Panic);
        assert_eq!(inv.output(), None);
    }

    #[test]
    fn ecall_is_rejected_by_the_standard_program_decoder() {
        // Opcode 3 is the VOS capability-runtime extension and is not in the
        // Gray Paper v0.8.0 opcode set U.
        let blob = build_standard_program(&[], &[], 0, 4096, &[3], &[1]);
        assert!(matches!(
            execute(&blob, &[], 1_000_000),
            Err(RefineError::InvalidBlob)
        ));
    }

    #[test]
    fn ecalli_surfaces_as_hostcall_untouched() {
        // A standard program still needs a terminating instruction after the
        // host-call continuation.
        let blob = build_standard_program(&[], &[], 0, 4096, &[10, 42, 0], &[1, 0, 1]);
        let inv = execute(&blob, &ARGS, 1_000_000).expect("executes");
        assert_eq!(inv.exit, ExitReason::HostCall(42));
        // No dispatch happened: the GP argument registers are untouched.
        let arg_base = (1u64 << 32) - (1 << 16) - PVM_INIT_INPUT_SIZE as u64;
        assert_eq!(inv.registers[7], arg_base);
        assert_eq!(inv.registers[8], ARGS.len() as u64);
        assert_eq!(inv.output(), None, "no output without a halt");
    }

    #[test]
    fn nonzero_host_exit_retains_cause_and_resumes_at_successor() {
        let (mut code, mut bits) = (Vec::new(), Vec::new());
        asm(&mut code, &mut bits, &[51, 2, 9]); // prior posterior state
        asm(&mut code, &mut bits, &[10, 42]); // host at pc 3
        asm(&mut code, &mut bits, &[0]); // resumed standard panic
        let blob = build_standard_program(&[], &[], 0, 4096, &code, &bits);

        let first = execute(&blob, &[], 1_000_000).expect("executes to host boundary");
        assert_eq!(first.exit, ExitReason::HostCall(42));
        assert_eq!(first.pc, 3);
        assert_eq!(first.registers[2], 9);

        let mut machine = Machine::load(&blob, &[], 1_000_000).expect("loads resumable machine");
        assert_eq!(machine.resume(), ExitReason::HostCall(42));
        let after_host = machine.gas_remaining();
        assert_eq!(machine.resume(), ExitReason::Panic);
        assert_eq!(machine.gas_remaining(), after_host);
        let final_state = machine.finish(ExitReason::Panic);
        assert_eq!(final_state.pc, 0);
        assert_eq!(final_state.registers[2], 9);
    }

    #[test]
    fn output_range_must_be_readable() {
        // φ7 points into the unmapped gap between the rw region and the
        // stack; the designated output is not readable.
        let (mut code, mut bits) = (Vec::new(), Vec::new());
        asm(&mut code, &mut bits, &[51, 7, 0, 0, 3]); // load_imm φ7 = 0x30000
        asm(&mut code, &mut bits, &[51, 8, 4]); // load_imm φ8 = 4
        asm(&mut code, &mut bits, &[50, 0]); // jump_ind φ0+0 → halt
        let blob = build_standard_program(&[], &[], 1, 4096, &code, &bits);
        let inv = execute(&blob, &[], 1_000_000).expect("executes");
        assert_eq!(inv.exit, ExitReason::Halt);
        assert_eq!(inv.output(), None, "unreadable output range");
    }

    #[test]
    fn zero_length_output_at_halt_is_empty() {
        // Trivial halt: with empty args φ8 = 0, so the output is empty even
        // though φ7 points at the (unmapped, empty) argument region.
        let blob = build_standard_program(&[], &[], 0, 4096, &[50, 0], &[1, 0]);
        let inv = execute(&blob, &[], 1_000_000).expect("executes");
        assert_eq!(inv.exit, ExitReason::Halt);
        assert_eq!(inv.output(), Some(Vec::new()));
    }

    #[test]
    fn invalid_blob_is_rejected() {
        assert_eq!(
            execute(&[0xFF; 4], &[], 1_000_000).unwrap_err(),
            RefineError::InvalidBlob
        );
    }

    #[test]
    fn full_psi_deblob_failures_panic_without_changing_state() {
        let valid = build_pvm_blob(&[10, 7, 0], &[1, 0, 1]);
        let mut unused_high_bit = valid.clone();
        *unused_high_bit.last_mut().unwrap() |= 0x80;
        let cases = [
            ("truncated", vec![0xff, 0]),
            ("unused bitmask high bit", unused_high_bit),
            ("initial bit unset", build_pvm_blob(&[0], &[0])),
            ("trailing non-terminator", build_pvm_blob(&[2], &[1])),
        ];
        let registers =
            core::array::from_fn(|index| 0x1111_0000_0000_0000u64.wrapping_add(index as u64));
        let bytes: Vec<u8> = (0..2 * PVM_PAGE_SIZE as usize)
            .map(|index| (index as u8).wrapping_mul(17).wrapping_add(3))
            .collect();
        let permissions = vec![PERM_RO, PERM_RW];

        for gas_charged in [false, true] {
            for (name, blob, pc) in cases
                .iter()
                .map(|(name, blob)| (*name, blob.as_slice(), 0u64))
                .chain([
                    ("operand entry", valid.as_slice(), 1),
                    ("end entry", valid.as_slice(), 3),
                    ("wide entry", valid.as_slice(), u64::from(u32::MAX) + 1),
                ])
            {
                let mut memory = Memory::flat(bytes.clone());
                memory.set_page_perms(permissions.clone());
                let mut machine =
                    Machine::from_pvm_blob(blob, pc, 0xfeed_beef, gas_charged, registers, memory);

                assert_eq!(machine.gas_remaining(), 0xfeed_beef, "{name}: gas");
                assert_eq!(machine.gas_charged(), gas_charged, "{name}: funded flag");
                assert_eq!(*machine.registers(), registers, "{name}: registers");
                assert_eq!(
                    machine.memory().page_perms(),
                    permissions,
                    "{name}: permissions"
                );
                let mut actual = vec![0; bytes.len()];
                machine.memory().read_bytes(0, &mut actual);
                assert_eq!(actual, bytes, "{name}: memory before exit");

                let exit = machine.resume();
                assert_eq!(exit, ExitReason::Panic, "{name}: full Ψ exit");
                let invocation = machine.finish(exit);
                assert_eq!(invocation.pc, 0, "{name}: final counter");
                assert_eq!(invocation.gas_used, 0, "{name}: no charge");
                assert_eq!(invocation.registers, registers, "{name}: final registers");
                assert_eq!(invocation.memory().page_perms(), permissions);
                let mut actual = vec![0; bytes.len()];
                invocation.memory().read_bytes(0, &mut actual);
                assert_eq!(actual, bytes, "{name}: final memory");
            }
        }
    }

    #[test]
    fn standard_ecalli_identifier_is_full_sign_extended_register() {
        let cases: &[(&[u8], u64)] = &[
            (&[0xff], u64::MAX),
            (&[0x00, 0x00, 0x00, 0x80], 0xffff_ffff_8000_0000),
            (&[0xff, 0xff, 0xff, 0x7f], 0x7fff_ffff),
        ];
        let registers = core::array::from_fn(|index| 0xa500 + index as u64);
        for (immediate, expected) in cases {
            let mut code = vec![10];
            code.extend_from_slice(immediate);
            code.push(0);
            let mut bitmask = vec![1];
            bitmask.extend(core::iter::repeat_n(0, immediate.len()));
            bitmask.push(1);
            let blob = build_pvm_blob(&code, &bitmask);
            let memory = Memory::flat(vec![0x5a; PVM_PAGE_SIZE as usize]);
            let mut machine = Machine::from_pvm_blob(&blob, 0, 1_000, false, registers, memory);
            assert_eq!(machine.resume(), ExitReason::HostCall(*expected));
            assert_eq!(*machine.registers(), registers);
            let mut actual = vec![0; PVM_PAGE_SIZE as usize];
            machine.memory().read_bytes(0, &mut actual);
            assert_eq!(actual, vec![0x5a; PVM_PAGE_SIZE as usize]);
        }
    }

    #[test]
    fn oversized_args_are_rejected() {
        let args = vec![0u8; PVM_INIT_INPUT_SIZE as usize + 1];
        assert_eq!(
            execute(&round_trip_blob(), &args, 1_000_000).unwrap_err(),
            RefineError::LayoutOverflow
        );
    }

    /// Flat-vs-sparse differential across the whole corpus: halt with
    /// output, mid-run out-of-gas, trap, conformance panic, hostcall,
    /// unreadable output, unmapped-gap fault, read-only fault, and the
    /// two-cluster stack program.
    #[test]
    fn flat_and_sparse_agree_across_corpus() {
        assert_flat_sparse_parity(&round_trip_blob(), &ARGS, 1_000_000);
        assert_flat_sparse_parity(&round_trip_blob(), &ARGS, INIT_GAS + 1);
        assert_flat_sparse_parity(
            &build_standard_program(&[], &[], 0, 4096, &[0], &[1]),
            &[],
            1_000_000,
        );
        assert_flat_sparse_parity(
            &build_standard_program(&[], &[], 0, 4096, &[3], &[1]),
            &[],
            1_000_000,
        );
        assert_flat_sparse_parity(
            &build_standard_program(&[], &[], 0, 4096, &[10, 42], &[1, 0]),
            &ARGS,
            1_000_000,
        );
        {
            let (mut code, mut bits) = (Vec::new(), Vec::new());
            asm(&mut code, &mut bits, &[51, 7, 0, 0, 3]);
            asm(&mut code, &mut bits, &[51, 8, 4]);
            asm(&mut code, &mut bits, &[50, 0]);
            let blob = build_standard_program(&[], &[], 1, 4096, &code, &bits);
            assert_flat_sparse_parity(&blob, &[], 1_000_000);
        }
        assert_flat_sparse_parity(&fault_gap_blob(), &[], 1_000_000);
        assert_flat_sparse_parity(&ro_write_blob(), &ARGS, 1_000_000);
        assert_flat_sparse_parity(&stack_and_rw_blob(), &[], 1_000_000);
    }

    /// The *entire* ~4 GiB logical image — every mapped region and every
    /// unmapped gap — is byte-identical between the representations after
    /// a program that wrote to both address clusters.
    #[test]
    fn full_logical_image_parity_after_two_cluster_writes() {
        let blob = stack_and_rw_blob();
        let f = execute_with(&blob, &ARGS, 1_000_000, MemoryModel::Flat).expect("flat");
        let s = execute_with(&blob, &ARGS, 1_000_000, MemoryModel::Sparse).expect("sparse");
        assert_eq!(f.exit, ExitReason::Halt);
        assert_eq!(f.memory().span(), s.memory().span());
        assert!(
            f.memory().span() > 3 << 30,
            "the flat span is measured in GiB"
        );
        assert_image_range_eq(&f, &s, 0, f.memory().span());
    }

    /// An access to the unmapped gap faults with the same page base under
    /// both representations (GP page faults are page-granular).
    #[test]
    fn page_fault_page_base_agrees() {
        let (f, s) = assert_flat_sparse_parity(&fault_gap_blob(), &[], 1_000_000).unwrap();
        assert_eq!(f.exit, ExitReason::PageFault(0x10000));
        assert_eq!(s.exit, ExitReason::PageFault(0x10000));
    }

    /// A write to the read-only argument region faults with the argument
    /// page base under both representations; a read of the same page (the
    /// round-trip corpus entry) succeeds under both.
    #[test]
    fn read_only_write_faults_identically() {
        let (f, s) = assert_flat_sparse_parity(&ro_write_blob(), &ARGS, 1_000_000).unwrap();
        let arg_base = ((1u64 << 32) - (1 << 16) - PVM_INIT_INPUT_SIZE as u64) as u32;
        assert_eq!(f.exit, ExitReason::PageFault(arg_base));
        assert_eq!(s.exit, ExitReason::PageFault(arg_base));
    }

    /// The sparse representation runs a program whose flat image spans
    /// ~4 GiB — writes at both the stack (just below 2³²) and the rw
    /// region (near 0) — inside a strictly bounded allocation.
    #[test]
    fn sparse_bounds_allocation_for_a_4gib_span() {
        let inv = execute_with(&stack_and_rw_blob(), &[], 1_000_000, MemoryModel::Sparse)
            .expect("executes sparse");
        assert_eq!(inv.exit, ExitReason::Halt);
        assert_eq!(inv.registers[3], 0x11223344, "stack round-trip");
        assert_eq!(inv.registers[5], 0x11223344, "rw round-trip");
        assert_eq!(
            inv.output(),
            Some(0x11223344u64.to_le_bytes().to_vec()),
            "output reads back through the stack region"
        );
        let span = inv.memory().span();
        let allocated = inv.memory().allocated_bytes();
        assert!(span > 3 << 30, "flat-equivalent span is ~4 GiB ({span})");
        assert!(
            allocated < 16 << 20,
            "sparse allocation stays bounded ({allocated} bytes)"
        );
    }

    /// Semantic-identity anchor: the same blob/args/budget through
    /// `InvocationKernel::new_standard` (std, interpreter backend) reaches
    /// the same exit, register file, remaining gas, and memory image.
    /// Together with the flat↔sparse differentials above this anchors the
    /// sparse representation to the kernel too.
    #[cfg(feature = "std")]
    #[test]
    fn matches_kernel_execution() {
        use crate::kernel::{InvocationKernel, KernelResult};
        use crate::vm_pool::VmState;

        let blob = round_trip_blob();
        let budget = 1_000_000u64;

        let inv =
            execute_with(&blob, &ARGS, budget, MemoryModel::Flat).expect("refine harness executes");
        assert_eq!(inv.exit, ExitReason::Halt);

        let mut kernel = InvocationKernel::new_standard(
            &blob,
            &ARGS,
            budget,
            crate::backend::PvmBackend::ForceInterpreter,
        )
        .expect("kernel loads the same blob");
        kernel
            .vm_arena
            .vm_mut(0)
            .transition(VmState::Running)
            .unwrap();
        assert!(matches!(kernel.run(), KernelResult::Halt));

        let vm = kernel.vm_arena.vm(0);
        assert_eq!(&inv.registers, vm.regs(), "register files agree");
        assert_eq!(budget - inv.gas_used, vm.gas(), "gas accounting agrees");
        let (kernel_mem, _, _) = kernel.extract_flat_mem();
        let flat = inv.memory().as_flat().expect("flat was requested");
        assert_eq!(flat, &kernel_mem[..], "memory images agree");
        assert_eq!(inv.output().as_deref(), Some(&ARGS[..4]));
    }
}
