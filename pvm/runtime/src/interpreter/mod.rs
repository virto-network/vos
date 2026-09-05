//! PVM interpreter — software execution of PVM bytecode.
//!
//! Implements the single-step state transition Ψ₁ and the full PVM Ψ.
//! Used as a backend alongside the JIT recompiler.

pub mod memory;

use alloc::{vec, vec::Vec};

use crate::args::{self, Args};
use crate::instruction::Opcode;
use crate::{ExitReason, Gas, PVM_REGISTER_COUNT};
pub use memory::Memory;

/// Pre-decoded instruction for the fast interpreter path.
///
/// Flattened representation: all operands stored directly (no enum discrimination
/// needed at runtime). This avoids the Args pattern-matching overhead.
#[derive(Clone, Copy, Debug)]
pub struct DecodedInst {
    pub opcode: Opcode,
    /// Register A (first register operand, context-dependent).
    pub ra: u8,
    /// Register B (second register operand, context-dependent).
    pub rb: u8,
    /// Register D (destination register, context-dependent).
    pub rd: u8,
    /// First immediate / offset value.
    pub imm1: u64,
    /// Second immediate / offset value.
    pub imm2: u64,
    /// Byte offset of this instruction in the code.
    pub pc: u32,
    /// Byte offset of the next sequential instruction.
    pub next_pc: u32,
    /// Pre-resolved instruction index for the next sequential instruction.
    pub next_idx: u32,
    /// Pre-resolved instruction index for the branch/jump target (u32::MAX = invalid).
    pub target_idx: u32,
    /// Gas cost to charge at gas-block entry (0 for non-gas-block-start instructions).
    /// Gas blocks are {PC=0} ∪ {post-terminator PCs} — branch targets are NOT gas block starts.
    /// u32 suffices: per-block costs are bounded by ~25 instructions × ~100 cycles ≈ 2500.
    pub bb_gas_cost: u32,
}

const _: () = assert!(core::mem::size_of::<DecodedInst>() == 40);

/// PVM instance state (eq A.6).
/// Page access levels for the per-page permission map
/// (see [`Interpreter::set_page_perms`]).
pub const PERM_NONE: u8 = 0;
pub const PERM_RO: u8 = 1;
pub const PERM_RW: u8 = 2;

/// Width of one scalar guest-memory instruction. Keeping this mapping next
/// to the access macros makes the standard preflight impossible to omit when
/// a typed accessor is used by either interpreter loop.
macro_rules! memory_access_width {
    (read_u8) => {
        1usize
    };
    (read_u16_le) => {
        2usize
    };
    (read_u32_le) => {
        4usize
    };
    (read_u64_le) => {
        8usize
    };
    (write_u8) => {
        1usize
    };
    (write_u16_le) => {
        2usize
    };
    (write_u32_le) => {
        4usize
    };
    (write_u64_le) => {
        8usize
    };
}

#[derive(Clone, Debug)]
pub struct Interpreter {
    /// ϱ: Gas counter (remaining gas).
    pub gas: Gas,
    /// φ: 13 general-purpose 64-bit registers.
    pub registers: [u64; PVM_REGISTER_COUNT],
    /// µ: Memory state. Always a whole number of 4 KiB pages with exactly
    /// one permission entry per page. [`Memory::Flat`] (the kernel,
    /// recompiler, and 64-bit default) or [`Memory::Sparse`] (32-bit
    /// embedders); the two are semantically indistinguishable.
    mem: Memory,
    /// ı: Instruction counter (program counter), indexes into code bytes.
    pub pc: u32,
    /// c: Instruction bytecode.
    pub code: Vec<u8>,
    /// k: Opcode bitmask (1 = start of instruction).
    pub bitmask: Vec<u8>,
    /// j: Dynamic jump table (indices into code).
    pub jump_table: Vec<u32>,
    /// Heap base address (h) for the grow-heap host operation.
    pub heap_base: u32,
    /// Current heap top pointer (heap_base + total_allocated).
    pub heap_top: u32,
    /// Maximum heap pages (grow_heap refuses beyond this).
    pub max_heap_pages: u32,
    /// Effective profile-bound load/store cycles. Standard v0.8.0 is always
    /// 25; the capability/JAR profile may use a 25/50/75/100 page tier.
    pub mem_cycles: u8,
    /// Caller-provided capability/JAR tier retained across ISA profile
    /// transitions. Standard execution never consumes this value directly.
    configured_mem_cycles: u8,
    /// A standard `ecalli` that has been surfaced but not acknowledged.
    pending_host_call: Option<crate::PendingHostCall>,
    /// GP basic-block starts: {PC=0} ∪ {post-terminator PCs}. Branch and
    /// djump targets must land on one of these or the instruction panics
    /// (GP eq A.17/A.18). Gas blocks share the same boundaries.
    pub(crate) basic_block_starts: Vec<bool>,
    /// ISA profile: Conformance rejects opcode 3 (Ecall) at execution.
    isa_mode: crate::IsaMode,
    /// Gas model the VM charges under. Private because the pre-decoded
    /// stream caches per-instruction gas labels derived from it — install
    /// via [`Self::set_gas_model`], which re-derives them.
    gas_model: crate::GasModel,
    /// Gas cost for each gas block (indexed by block start PC).
    /// Only entries at gas block starts are meaningful. Gas blocks are
    /// {PC=0} ∪ {post-terminator PCs}, NOT branch targets.
    pub block_gas_costs: Vec<u32>,
    /// Containing gas-block start for every externally enterable PC.
    gas_block_start_by_pc: Vec<u32>,
    /// Whether the block containing the current PC has already been funded.
    /// This is consensus-visible continuation state: host and page-fault
    /// retries must not charge the same block twice, while a fresh arbitrary
    /// mid-block entry must charge the complete containing block.
    pub gas_charged: bool,
    /// JAR v0.8.0: true when the next instruction should be charged block gas.
    /// Set at initialization and after every terminator instruction.
    pub need_gas_charge: bool,
    /// When true, collect instruction trace in `pc_trace`.
    pub tracing_enabled: bool,
    /// Collected instruction trace: (PC, opcode_byte) pairs.
    pub pc_trace: Vec<(u32, u8)>,
    /// Pre-decoded instruction stream (indexed by instruction number).
    pub(crate) decoded_insts: Vec<DecodedInst>,
    /// Mapping from PC byte offset → instruction index. u32::MAX = invalid.
    pub(crate) pc_to_idx: Vec<u32>,
}

/// Read-only observation of one canonical interpreter instruction.
///
/// The `machine_after` reference exposes the exact post-step registers, gas,
/// PC, heap bounds, and memory without allowing an observer to perturb
/// execution. Embedders can use this to construct diagnostics or proof
/// witnesses while the interpreter remains the sole execution semantics.
pub struct InstructionObservation<'a> {
    pub pc_before: u32,
    pub opcode_byte: u8,
    pub registers_before: [u64; crate::PVM_REGISTER_COUNT],
    pub gas_before: crate::Gas,
    pub need_gas_charge_before: bool,
    pub exit: Option<&'a crate::ExitReason>,
    pub machine_after: &'a Interpreter,
}

impl Interpreter {
    /// Create a new PVM from parsed program components, with flat memory
    /// over `flat_mem` (zero-padded to whole pages).
    pub fn new(
        code: Vec<u8>,
        bitmask: Vec<u8>,
        jump_table: Vec<u32>,
        registers: [u64; PVM_REGISTER_COUNT],
        flat_mem: Vec<u8>,
        gas: Gas,
        mem_cycles: u8,
    ) -> Self {
        Self::with_memory(
            code,
            bitmask,
            jump_table,
            registers,
            Memory::flat(flat_mem),
            gas,
            mem_cycles,
        )
    }

    /// Create a new PVM with an explicit memory representation
    /// ([`Memory::flat`] or [`Memory::sparse`]). Memory starts with
    /// RW-everywhere default permissions; the embedder installs the real
    /// per-page map via [`Self::set_page_perms`].
    pub fn with_memory(
        code: Vec<u8>,
        bitmask: Vec<u8>,
        jump_table: Vec<u32>,
        registers: [u64; PVM_REGISTER_COUNT],
        mem: Memory,
        gas: Gas,
        mem_cycles: u8,
    ) -> Self {
        Self::with_memory_and_mode(
            code,
            bitmask,
            jump_table,
            registers,
            mem,
            gas,
            mem_cycles,
            crate::IsaMode::Jar,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_memory_and_mode(
        code: Vec<u8>,
        bitmask: Vec<u8>,
        jump_table: Vec<u32>,
        registers: [u64; PVM_REGISTER_COUNT],
        mem: Memory,
        gas: Gas,
        mem_cycles: u8,
        isa_mode: crate::IsaMode,
    ) -> Self {
        let configured_mem_cycles = mem_cycles;
        let mem_cycles = crate::mem_cycles_for_mode(mem_cycles, isa_mode);
        // Basic blocks and gas blocks share the same boundaries:
        // {0} ∪ post-terminator.
        let basic_block_starts = match isa_mode {
            crate::IsaMode::Jar => compute_runtime_basic_block_starts(&code, &bitmask),
            crate::IsaMode::Conformance => compute_basic_block_starts(&code, &bitmask),
        };
        let block_gas_costs =
            compute_block_gas_costs(&code, &bitmask, &basic_block_starts, mem_cycles, isa_mode);
        let (decoded_insts, pc_to_idx) = predecode_instructions(
            &code,
            &bitmask,
            &basic_block_starts,
            &basic_block_starts,
            &block_gas_costs,
            isa_mode,
        );
        let gas_block_start_by_pc =
            compute_gas_block_start_by_pc(&code, &bitmask, &basic_block_starts, isa_mode);
        Self {
            gas,
            registers,
            mem,
            pc: 0,
            code,
            bitmask,
            jump_table,
            heap_base: 0,
            heap_top: 0,
            max_heap_pages: 0,
            mem_cycles,
            configured_mem_cycles,
            pending_host_call: None,
            basic_block_starts,
            isa_mode,
            gas_model: crate::GasModel::default(),
            block_gas_costs,
            gas_block_start_by_pc,
            gas_charged: false,
            need_gas_charge: true,
            tracing_enabled: false,
            pc_trace: Vec::new(),
            decoded_insts,
            pc_to_idx,
        }
    }

    /// Pre-decode code into an `InterpreterProgram` for storage in a CODE cap.
    /// This performs the expensive one-time work (gas block computation, instruction
    /// pre-decoding) without allocating runtime state (registers, memory, gas).
    pub fn predecode(
        code: &[u8],
        bitmask: &[u8],
        jump_table: &[u32],
        mem_cycles: u8,
        isa_mode: crate::IsaMode,
    ) -> crate::backend::InterpreterProgram {
        let mem_cycles = crate::mem_cycles_for_mode(mem_cycles, isa_mode);
        // Basic blocks and gas blocks share the same boundaries:
        // {0} ∪ post-terminator.
        let basic_block_starts = match isa_mode {
            crate::IsaMode::Jar => compute_runtime_basic_block_starts(code, bitmask),
            crate::IsaMode::Conformance => compute_basic_block_starts(code, bitmask),
        };
        let block_gas_costs =
            compute_block_gas_costs(code, bitmask, &basic_block_starts, mem_cycles, isa_mode);
        let (decoded_insts, pc_to_idx) = predecode_instructions(
            code,
            bitmask,
            &basic_block_starts,
            &basic_block_starts,
            &block_gas_costs,
            isa_mode,
        );
        let gas_block_start_by_pc =
            compute_gas_block_start_by_pc(code, bitmask, &basic_block_starts, isa_mode);
        crate::backend::InterpreterProgram {
            decoded_insts,
            pc_to_idx,
            basic_block_starts,
            block_gas_costs,
            gas_block_start_by_pc,
            code: code.to_vec(),
            bitmask: bitmask.to_vec(),
            jump_table: jump_table.to_vec(),
            mem_cycles,
        }
    }

    /// Set the program counter to a specific offset.
    /// Used by service blobs to select refine (PC=0) or accumulate (PC=5) entry points.
    pub fn set_pc(&mut self, pc: u32) {
        self.pc = pc;
        self.pending_host_call = None;
        self.gas_charged = false;
        self.need_gas_charge = true;
    }

    /// Advance a standard host-call exit to its continuation instruction.
    ///
    /// Returns `true` only when the preceding [`Self::run`] stopped on a
    /// Conformance-profile `ecalli`. JAR/service execution retains its
    /// historical already-advanced program counter and returns `false`.
    pub fn resume_after_host_call(&mut self) -> bool {
        let Some(call) = self.pending_host_call.take() else {
            return false;
        };
        self.pc = call.resume_pc;
        // `ecalli` is not in the standard termination set, so its successor
        // remains in the already-funded block.
        self.gas_charged = true;
        self.need_gas_charge = false;
        true
    }

    /// The unacknowledged standard host call, if any.
    pub fn pending_host_call(&self) -> Option<crate::PendingHostCall> {
        self.pending_host_call
    }

    /// Restore execution-boundary state owned by an embedding scheduler.
    pub(crate) fn restore_boundary_state(
        &mut self,
        gas_charged: bool,
        pending_host_call: Option<crate::PendingHostCall>,
    ) {
        self.gas_charged = gas_charged;
        self.need_gas_charge = !gas_charged;
        self.pending_host_call = pending_host_call;
    }

    /// Internal continuation cursor used by the capability kernel after it
    /// has handled a standard host call.
    pub(crate) fn continuation_pc(&self) -> u32 {
        self.pc
    }

    /// Install the gas model, re-deriving the cached per-instruction gas
    /// labels the fast path charges from (`DecodedInst::bb_gas_cost`).
    ///
    /// Under [`crate::GasModel::PerInstruction`] every decoded instruction
    /// — including the synthetic panic stubs at invalid opcode positions
    /// and the end-of-code sentinel trap — is labelled with a flat cost of
    /// 1, so the fast loop's existing charge-then-execute step reproduces
    /// the Lean oracle (`Jar.JAVM.run`): out-of-gas is checked before the
    /// instruction runs, and the exiting instruction is itself charged.
    /// Under [`crate::GasModel::BlockPipeline`] the labels revert to the
    /// block costs at gas-block starts (0 elsewhere).
    pub fn set_gas_model(&mut self, model: crate::GasModel) {
        self.gas_model = model;
        let standard_sentinel_starts_block = self
            .decoded_insts
            .iter()
            .rev()
            .find(|inst| (inst.pc as usize) < self.code.len())
            .is_none_or(|inst| is_terminator_for_mode(inst.opcode, self.isa_mode));
        for inst in &mut self.decoded_insts {
            inst.bb_gas_cost = match model {
                crate::GasModel::PerInstruction => 1,
                crate::GasModel::BlockPipeline => {
                    let pc = inst.pc as usize;
                    if pc < self.basic_block_starts.len() && self.basic_block_starts[pc] {
                        self.block_gas_costs[pc]
                    } else if pc >= self.code.len() {
                        match self.isa_mode {
                            // Frozen capability-runtime behavior.
                            crate::IsaMode::Jar => 1,
                            // In v0.8 the zero-extended trap is part of an
                            // open final block. It is separately charged only
                            // when a preceding T instruction ended that block.
                            crate::IsaMode::Conformance => {
                                u32::from(standard_sentinel_starts_block) * 2
                            }
                        }
                    } else {
                        0
                    }
                }
            };
        }
    }

    /// The gas model the VM charges under.
    pub fn gas_model(&self) -> crate::GasModel {
        self.gas_model
    }

    /// The instruction-set profile installed in this interpreter.
    ///
    /// Proof adapters use this to preserve authenticated container semantics
    /// when an initialized interpreter crosses the tracing API boundary.
    pub fn isa_mode(&self) -> crate::IsaMode {
        self.isa_mode
    }

    /// Select the instruction-set profile and rebuild all decoded state that
    /// depends on opcode validity, block boundaries, or opcode gas costs.
    ///
    /// Embedders should normally choose the profile at construction. This
    /// transition exists for proof tooling that receives an initialized
    /// interpreter and must bind it to the standard ISA before any step runs.
    pub fn set_isa_mode(&mut self, isa_mode: crate::IsaMode) {
        if self.isa_mode == isa_mode {
            return;
        }
        self.isa_mode = isa_mode;
        self.pending_host_call = None;
        self.gas_charged = false;
        self.need_gas_charge = true;
        self.mem_cycles = crate::mem_cycles_for_mode(self.configured_mem_cycles, isa_mode);
        self.basic_block_starts = match isa_mode {
            crate::IsaMode::Jar => compute_runtime_basic_block_starts(&self.code, &self.bitmask),
            crate::IsaMode::Conformance => compute_basic_block_starts(&self.code, &self.bitmask),
        };
        self.block_gas_costs = compute_block_gas_costs(
            &self.code,
            &self.bitmask,
            &self.basic_block_starts,
            self.mem_cycles,
            isa_mode,
        );
        self.gas_block_start_by_pc = compute_gas_block_start_by_pc(
            &self.code,
            &self.bitmask,
            &self.basic_block_starts,
            isa_mode,
        );
        (self.decoded_insts, self.pc_to_idx) = predecode_instructions(
            &self.code,
            &self.bitmask,
            &self.basic_block_starts,
            &self.basic_block_starts,
            &self.block_gas_costs,
            isa_mode,
        );
        self.set_gas_model(self.gas_model);
    }

    /// Create a simple PVM for testing (code only, trivial bitmask).
    pub fn new_simple(
        code: Vec<u8>,
        registers: [u64; PVM_REGISTER_COUNT],
        flat_mem: Vec<u8>,
        gas: Gas,
    ) -> Self {
        // Build a bitmask where every byte is marked as an instruction start
        // This is a simplified mode; real programs use parse_blob.
        let bitmask = vec![1u8; code.len()];
        Self::new(
            code,
            bitmask,
            vec![],
            registers,
            flat_mem,
            gas,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        )
    }

    /// Install the per-page permission map. `perms` must have exactly one
    /// entry per 4 KiB page of guest memory — the accessors rely on the
    /// page bounds check doubling as the byte-range check.
    pub fn set_page_perms(&mut self, perms: Vec<u8>) {
        self.mem.set_page_perms(perms);
    }

    /// The guest memory.
    pub fn memory(&self) -> &Memory {
        &self.mem
    }

    /// The guest memory, mutably.
    ///
    /// This is intentionally lower-level than the instruction accessors: a
    /// standard Refine embedder needs to implement the `pages`, `peek`, and
    /// `poke` host calls between invocations of an inner machine.
    pub fn memory_mut(&mut self) -> &mut Memory {
        &mut self.mem
    }

    /// Take ownership of the guest memory, leaving an empty flat buffer.
    pub fn take_memory(&mut self) -> Memory {
        core::mem::take(&mut self.mem)
    }

    /// The flat backing buffer. The kernel and recompiler paths construct
    /// the interpreter with flat memory only; panics under [`Memory::Sparse`].
    pub fn flat_mem(&self) -> &[u8] {
        self.mem
            .as_flat()
            .expect("flat_mem() requires the flat memory representation")
    }

    // --- Memory accessors ---
    //
    // Thin dispatch onto the active representation (see `memory` module).
    // For flat memory the hot path is unchanged from the historical
    // flat-buffer accessors: a single page-index shift, one bounds check,
    // one byte load, and one compare on top of the unaligned MOV. Reads
    // need at least PERM_RO on every touched page, writes need PERM_RW;
    // failures report the offending page base (GP page faults are
    // page-granular, matching the Lean oracle and the JIT's SIGSEGV path).

    /// Read a byte; `Err` carries the faulting page base.
    #[inline(always)]
    pub fn read_u8(&self, addr: u32) -> Result<u8, u32> {
        self.mem.read_u8(addr)
    }

    #[inline(always)]
    fn read_u16_le(&self, addr: u32) -> Result<u16, u32> {
        self.mem.read_u16_le(addr)
    }

    #[inline(always)]
    fn read_u32_le(&self, addr: u32) -> Result<u32, u32> {
        self.mem.read_u32_le(addr)
    }

    #[inline(always)]
    fn read_u64_le(&self, addr: u32) -> Result<u64, u32> {
        self.mem.read_u64_le(addr)
    }

    /// Write a byte; `Err` carries the faulting page base.
    #[inline(always)]
    pub fn write_u8(&mut self, addr: u32, val: u8) -> Result<(), u32> {
        self.mem.write_u8(addr, val)
    }

    #[inline(always)]
    fn write_u16_le(&mut self, addr: u32, val: u16) -> Result<(), u32> {
        self.mem.write_u16_le(addr, val)
    }

    #[inline(always)]
    fn write_u32_le(&mut self, addr: u32, val: u32) -> Result<(), u32> {
        self.mem.write_u32_le(addr, val)
    }

    #[inline(always)]
    fn write_u64_le(&mut self, addr: u32, val: u64) -> Result<(), u32> {
        self.mem.write_u64_le(addr, val)
    }

    /// Classify a standard scalar memory access before it can mutate state.
    ///
    /// Gray Paper v0.8 orders the *raw* required indices, reducing each one
    /// modulo 2^32 only when it is inspected. Consequently an access that
    /// starts at the top of the address space checks its high tail first and
    /// only then reaches the wrapped initialization zone. For example, an
    /// eight-byte access at `0xffff_fffc` faults at `0xffff_f000` when that
    /// page is inaccessible, but panics when the high tail is accessible and
    /// the next required byte wraps to address zero.
    ///
    /// The scan is at most eight bytes. Performing it before the existing
    /// typed read/write also makes a failing store atomic across page and
    /// address-space boundaries.
    #[inline(always)]
    fn standard_memory_exception(
        &self,
        addr: u32,
        width: usize,
        write: bool,
    ) -> Option<ExitReason> {
        debug_assert!(matches!(width, 1 | 2 | 4 | 8));
        for offset in 0..width {
            let byte_addr = addr.wrapping_add(offset as u32);
            if byte_addr < crate::PVM_ZONE_SIZE {
                return Some(ExitReason::Panic);
            }
            let accessible = if write {
                self.mem.is_writable(byte_addr, 1)
            } else {
                self.mem.is_readable(byte_addr, 1)
            };
            if !accessible {
                return Some(ExitReason::PageFault(
                    byte_addr & !(crate::PVM_PAGE_SIZE - 1),
                ));
            }
        }
        None
    }

    /// Compute skip(i) — distance to next instruction minus one (eq A.3).
    fn skip(&self, i: usize) -> usize {
        // skip(i) = min(24, first j where (k ++ [1,1,...])_{i+1+j} = 1)
        for j in 0..25 {
            let idx = i + 1 + j;
            let bit = if idx < self.bitmask.len() {
                self.bitmask[idx]
            } else {
                1 // infinite 1s appended
            };
            if bit == 1 {
                return j;
            }
        }
        24
    }

    /// Read from ζ (code with implicit zero extension, eq A.4).
    fn zeta(&self, i: usize) -> u8 {
        if i < self.code.len() { self.code[i] } else { 0 }
    }

    /// Check if a code index is a valid basic block start (public accessor).
    pub fn is_basic_block_start(&self, idx: u64) -> bool {
        let i = idx as usize;
        if i < self.basic_block_starts.len() {
            self.basic_block_starts[i]
        } else {
            false
        }
    }

    fn containing_block_cost(&self, pc: u32) -> Option<u64> {
        let start = *self.gas_block_start_by_pc.get(pc as usize)?;
        if start == u32::MAX {
            return None;
        }
        if start as usize == self.code.len() {
            return Some(match self.isa_mode {
                crate::IsaMode::Jar => 1,
                crate::IsaMode::Conformance => 2,
            });
        }
        self.block_gas_costs
            .get(start as usize)
            .copied()
            .map(u64::from)
    }

    /// Handle an unconditional static jump (eq A.17's `sjump`).
    /// Returns (exit_reason, new_pc) where exit_reason is None for continue.
    fn sjump(&self, target: u64) -> (Option<ExitReason>, u32) {
        if !self.is_basic_block_start(target) {
            (Some(ExitReason::Panic), self.pc)
        } else {
            (None, target as u32)
        }
    }

    /// Handle a conditional static branch (eq A.17's `branch`).
    ///
    /// Standard v0.8 validates both possible successors before selecting one.
    /// The transitional JAR profile keeps its frozen behavior and validates
    /// only a selected explicit target.
    fn branch(&self, target: u64, condition: bool, next_pc: u32) -> (Option<ExitReason>, u32) {
        if self.isa_mode == crate::IsaMode::Conformance
            && (!self.is_basic_block_start(target)
                || !self.is_basic_block_start(u64::from(next_pc)))
        {
            return (Some(ExitReason::Panic), self.pc);
        }
        if !condition {
            (None, next_pc)
        } else {
            self.sjump(target)
        }
    }

    /// Handle dynamic jump (eq A.18).
    fn djump(&self, a: u64) -> (Option<ExitReason>, u32) {
        const ZA: u64 = 2; // Jump alignment factor
        if a == crate::PVM_HALT_ADDR {
            return (Some(ExitReason::Halt), self.pc);
        }
        if a == 0 || a > self.jump_table.len() as u64 * ZA || !a.is_multiple_of(ZA) {
            return (Some(ExitReason::Panic), self.pc);
        }
        let idx = (a / ZA) as usize - 1;
        let target = self.jump_table[idx];
        if !self.is_basic_block_start(target as u64) {
            return (Some(ExitReason::Panic), self.pc);
        }
        (None, target)
    }

    /// Execute a single instruction step Ψ₁ (eq A.6-A.9).
    ///
    /// Gas is charged per gas block: the entire block's cost is deducted
    /// when entering the block. Gas block starts are {PC=0} ∪ {post-terminator PCs};
    /// branch targets are NOT gas block starts (they are validation-only).
    ///
    /// Returns the exit reason if the machine should stop, or None to continue.
    pub fn step(&mut self) -> Option<ExitReason> {
        // Macros for repetitive load/store dispatch arms. Zero runtime overhead —
        // macros expand to the same code as the hand-written variants.
        macro_rules! step_store {
            ($self:expr, $addr:expr, $write_fn:ident, $val:expr, $next_pc:expr) => {{
                let addr = $addr;
                if $self.isa_mode == crate::IsaMode::Conformance
                    && let Some(reason) =
                        $self.standard_memory_exception(addr, memory_access_width!($write_fn), true)
                {
                    return Some(reason);
                }
                match $self.$write_fn(addr, $val) {
                    Ok(()) => $self.pc = $next_pc,
                    Err(page) => return Some(ExitReason::PageFault(page)),
                }
            }};
        }
        macro_rules! step_load {
            ($self:expr, $dst:expr, $addr:expr, $read_fn:ident, |$v:ident| $conv:expr, $next_pc:expr) => {{
                let addr = $addr;
                if $self.isa_mode == crate::IsaMode::Conformance
                    && let Some(reason) =
                        $self.standard_memory_exception(addr, memory_access_width!($read_fn), false)
                {
                    return Some(reason);
                }
                match $self.$read_fn(addr) {
                    Ok($v) => {
                        $self.registers[$dst] = $conv;
                        $self.pc = $next_pc;
                    }
                    Err(page) => return Some(ExitReason::PageFault(page)),
                }
            }};
        }

        let pc = self.pc as usize;

        // Per-instruction metering (GP 0.7.2): 1 gas per instruction,
        // checked BEFORE opcode validation — a VM with 0 gas exits OutOfGas
        // even at an invalid instruction position, and the instruction that
        // exits (halt/trap/panic/fault/hostcall) is itself charged. Mirrors
        // the Lean oracle `Jar.JAVM.run`, which checks gas ahead of
        // `executeStep`.
        if self.gas_model == crate::GasModel::PerInstruction {
            if self.gas == 0 {
                return Some(ExitReason::OutOfGas);
            }
            self.gas -= 1;
        }

        // Fetch and validate opcode (eq A.19)
        let opcode_byte = self.zeta(pc);
        // The predecoded/JIT paths both materialize one synthetic opcode-0
        // instruction exactly at end-of-code. Preserve the same sentinel in
        // the stepping path; positions beyond it remain invalid.
        let is_end_sentinel = pc == self.code.len();
        let bitmask_valid = is_end_sentinel || (pc < self.bitmask.len() && self.bitmask[pc] == 1);

        let opcode = if bitmask_valid {
            opcode_for_mode(opcode_byte, self.isa_mode)
        } else {
            None
        };

        let opcode = match opcode {
            Some(op) => op,
            None => {
                return Some(ExitReason::Panic);
            }
        };

        // Per-gas-block metering (JAR v0.8.0).
        // Gas is charged at gas block entries: initial entry (PC=0) and after
        // terminators. Branch/jump targets are NOT gas block starts per spec
        // (Lean Interpreter.lean:130, GP PR #508).
        let charges_jar_sentinel = is_end_sentinel && self.isa_mode == crate::IsaMode::Jar;
        if self.gas_model == crate::GasModel::BlockPipeline
            && (!self.gas_charged || charges_jar_sentinel)
        {
            let Some(block_cost) = self.containing_block_cost(self.pc) else {
                return Some(ExitReason::Panic);
            };
            if self.gas < block_cost {
                return Some(ExitReason::OutOfGas);
            }
            self.gas -= block_cost;
            self.gas_charged = true;
            self.need_gas_charge = false;
        }

        // Collect trace if enabled
        if self.tracing_enabled {
            self.pc_trace.push((self.pc, opcode_byte));
        }

        // Compute skip length ℓ (eq A.20)
        let skip = self.skip(pc);

        // Default next PC: ı + 1 + skip(ı) (eq A.9)
        let next_pc = (pc + 1 + skip) as u32;

        // Decode arguments
        let category = opcode.category();
        let args = args::decode_args(&self.code, pc, skip, category);

        // Per-instruction trace
        tracing::trace!(pc, ?opcode, gas = self.gas, "pvm-inst");

        // Execute instruction inline
        match opcode {
            // Never produced by from_byte — the step path rejects invalid
            // opcodes above; this arm exists for match exhaustiveness.
            Opcode::Invalid => return Some(ExitReason::Panic),

            // === A.5.1: No arguments ===
            Opcode::Trap => {
                return Some(match self.isa_mode {
                    crate::IsaMode::Jar => ExitReason::Trap,
                    crate::IsaMode::Conformance => ExitReason::Panic,
                });
            }
            Opcode::Fallthrough => {
                if self.isa_mode == crate::IsaMode::Conformance {
                    let (exit, new_pc) = self.sjump(u64::from(next_pc));
                    if let Some(exit) = exit {
                        return Some(exit);
                    }
                    self.pc = new_pc;
                } else {
                    self.pc = next_pc;
                }
            }
            Opcode::Unlikely => {
                self.pc = next_pc;
            }

            // === A.5.1b: Ecall (management ops, no immediate) ===
            // Jar extension — under GP conformance opcode 3 is not a valid
            // instruction and panics when executed.
            Opcode::Ecall => {
                if self.isa_mode == crate::IsaMode::Conformance {
                    return Some(ExitReason::Panic);
                }
                // Advance PC to next instruction before returning
                self.pc = next_pc;
                // Runtime Ecall is a JAR gas-block terminator.  The early
                // return must carry the same unfunded-successor boundary that
                // ordinary terminators install below.
                self.gas_charged = false;
                self.need_gas_charge = true;
                // Exit with special ecall marker. Kernel reads φ[11]=op, φ[12]=subject|object.
                return Some(ExitReason::Ecall);
            }

            // === A.5.2: One immediate ===
            Opcode::Ecalli => {
                if let Args::Imm { imm } = args {
                    let host_id = match self.isa_mode {
                        crate::IsaMode::Conformance => imm,
                        // Preserve the frozen capability/JAR projection.
                        crate::IsaMode::Jar => u64::from(imm as u32),
                    };
                    // Advance PC to next instruction before returning (eq A.9)
                    self.pc = next_pc;
                    if self.isa_mode == crate::IsaMode::Conformance {
                        self.pending_host_call = Some(crate::PendingHostCall {
                            id: host_id,
                            cause_pc: pc as u32,
                            resume_pc: next_pc,
                        });
                        self.pc = pc as u32;
                    }
                    return Some(ExitReason::HostCall(host_id));
                }
            }

            // === A.5.3: One register + extended immediate ===
            Opcode::LoadImm64 => {
                if let Args::RegExtImm { ra, imm } = args {
                    self.registers[ra] = imm;
                    self.pc = next_pc;
                }
            }

            // === A.5.4: Two immediates (store_imm) ===
            Opcode::StoreImmU8 => {
                if let Args::TwoImm { imm_x, imm_y } = args {
                    step_store!(self, imm_x as u32, write_u8, imm_y as u8, next_pc);
                }
            }
            Opcode::StoreImmU16 => {
                if let Args::TwoImm { imm_x, imm_y } = args {
                    step_store!(self, imm_x as u32, write_u16_le, imm_y as u16, next_pc);
                }
            }
            Opcode::StoreImmU32 => {
                if let Args::TwoImm { imm_x, imm_y } = args {
                    step_store!(self, imm_x as u32, write_u32_le, imm_y as u32, next_pc);
                }
            }
            Opcode::StoreImmU64 => {
                if let Args::TwoImm { imm_x, imm_y } = args {
                    step_store!(self, imm_x as u32, write_u64_le, imm_y, next_pc);
                }
            }

            // === A.5.5: One offset (jump) ===
            Opcode::Jump => {
                if let Args::Offset { offset } = args {
                    let (exit, new_pc) = self.sjump(offset);
                    if let Some(e) = exit {
                        return Some(e);
                    }
                    self.pc = new_pc;
                }
            }

            // === A.5.6: One register + one immediate ===
            Opcode::JumpInd => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = self.registers[ra].wrapping_add(imm) % (1u64 << 32);
                    let (exit, new_pc) = self.djump(addr);
                    if let Some(e) = exit {
                        return Some(e);
                    }
                    self.pc = new_pc;
                }
            }
            Opcode::LoadImm => {
                if let Args::RegImm { ra, imm } = args {
                    self.registers[ra] = imm;
                    self.pc = next_pc;
                }
            }
            Opcode::LoadU8 => {
                if let Args::RegImm { ra, imm } = args {
                    step_load!(self, ra, imm as u32, read_u8, |v| v as u64, next_pc);
                }
            }
            Opcode::LoadI8 => {
                if let Args::RegImm { ra, imm } = args {
                    step_load!(
                        self,
                        ra,
                        imm as u32,
                        read_u8,
                        |v| v as i8 as i64 as u64,
                        next_pc
                    );
                }
            }
            Opcode::LoadU16 => {
                if let Args::RegImm { ra, imm } = args {
                    step_load!(self, ra, imm as u32, read_u16_le, |v| v as u64, next_pc);
                }
            }
            Opcode::LoadI16 => {
                if let Args::RegImm { ra, imm } = args {
                    step_load!(
                        self,
                        ra,
                        imm as u32,
                        read_u16_le,
                        |v| v as i16 as i64 as u64,
                        next_pc
                    );
                }
            }
            Opcode::LoadU32 => {
                if let Args::RegImm { ra, imm } = args {
                    step_load!(self, ra, imm as u32, read_u32_le, |v| v as u64, next_pc);
                }
            }
            Opcode::LoadI32 => {
                if let Args::RegImm { ra, imm } = args {
                    step_load!(
                        self,
                        ra,
                        imm as u32,
                        read_u32_le,
                        |v| v as i32 as i64 as u64,
                        next_pc
                    );
                }
            }
            Opcode::LoadU64 => {
                if let Args::RegImm { ra, imm } = args {
                    step_load!(self, ra, imm as u32, read_u64_le, |v| v, next_pc);
                }
            }
            Opcode::StoreU8 => {
                if let Args::RegImm { ra, imm } = args {
                    step_store!(
                        self,
                        imm as u32,
                        write_u8,
                        self.registers[ra] as u8,
                        next_pc
                    );
                }
            }
            Opcode::StoreU16 => {
                if let Args::RegImm { ra, imm } = args {
                    step_store!(
                        self,
                        imm as u32,
                        write_u16_le,
                        self.registers[ra] as u16,
                        next_pc
                    );
                }
            }
            Opcode::StoreU32 => {
                if let Args::RegImm { ra, imm } = args {
                    step_store!(
                        self,
                        imm as u32,
                        write_u32_le,
                        self.registers[ra] as u32,
                        next_pc
                    );
                }
            }
            Opcode::StoreU64 => {
                if let Args::RegImm { ra, imm } = args {
                    step_store!(self, imm as u32, write_u64_le, self.registers[ra], next_pc);
                }
            }

            // === A.5.7: One register + two immediates (store_imm_ind) ===
            Opcode::StoreImmIndU8 => {
                if let Args::RegTwoImm { ra, imm_x, imm_y } = args {
                    step_store!(
                        self,
                        self.registers[ra].wrapping_add(imm_x) as u32,
                        write_u8,
                        imm_y as u8,
                        next_pc
                    );
                }
            }
            Opcode::StoreImmIndU16 => {
                if let Args::RegTwoImm { ra, imm_x, imm_y } = args {
                    step_store!(
                        self,
                        self.registers[ra].wrapping_add(imm_x) as u32,
                        write_u16_le,
                        imm_y as u16,
                        next_pc
                    );
                }
            }
            Opcode::StoreImmIndU32 => {
                if let Args::RegTwoImm { ra, imm_x, imm_y } = args {
                    step_store!(
                        self,
                        self.registers[ra].wrapping_add(imm_x) as u32,
                        write_u32_le,
                        imm_y as u32,
                        next_pc
                    );
                }
            }
            Opcode::StoreImmIndU64 => {
                if let Args::RegTwoImm { ra, imm_x, imm_y } = args {
                    step_store!(
                        self,
                        self.registers[ra].wrapping_add(imm_x) as u32,
                        write_u64_le,
                        imm_y,
                        next_pc
                    );
                }
            }

            // === A.5.8: One register + immediate + offset ===
            Opcode::LoadImmJump => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    self.registers[ra] = imm;
                    let (exit, new_pc) = self.sjump(offset);
                    if let Some(e) = exit {
                        return Some(e);
                    }
                    self.pc = new_pc;
                }
            }
            Opcode::BranchEqImm
            | Opcode::BranchNeImm
            | Opcode::BranchLtUImm
            | Opcode::BranchLeUImm
            | Opcode::BranchGeUImm
            | Opcode::BranchGtUImm
            | Opcode::BranchLtSImm
            | Opcode::BranchLeSImm
            | Opcode::BranchGeSImm
            | Opcode::BranchGtSImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let (a, b) = (self.registers[ra], imm);
                    let cond = match opcode {
                        Opcode::BranchEqImm => a == b,
                        Opcode::BranchNeImm => a != b,
                        Opcode::BranchLtUImm => a < b,
                        Opcode::BranchLeUImm => a <= b,
                        Opcode::BranchGeUImm => a >= b,
                        Opcode::BranchGtUImm => a > b,
                        Opcode::BranchLtSImm => (a as i64) < (b as i64),
                        Opcode::BranchLeSImm => (a as i64) <= (b as i64),
                        Opcode::BranchGeSImm => (a as i64) >= (b as i64),
                        Opcode::BranchGtSImm => (a as i64) > (b as i64),
                        _ => unreachable!(),
                    };
                    let (exit, new_pc) = self.branch(offset, cond, next_pc);
                    if let Some(e) = exit {
                        return Some(e);
                    }
                    self.pc = new_pc;
                }
            }

            // === A.5.9: Two registers ===
            Opcode::MoveReg => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = self.registers[ra];
                    self.pc = next_pc;
                }
            }
            Opcode::CountSetBits64 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = self.registers[ra].count_ones() as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::CountSetBits32 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = (self.registers[ra] as u32).count_ones() as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::LeadingZeroBits64 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = self.registers[ra].leading_zeros() as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::LeadingZeroBits32 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = (self.registers[ra] as u32).leading_zeros() as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::TrailingZeroBits64 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = self.registers[ra].trailing_zeros() as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::TrailingZeroBits32 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = (self.registers[ra] as u32).trailing_zeros() as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::SignExtend8 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = (self.registers[ra] as u8) as i8 as i64 as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::SignExtend16 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = (self.registers[ra] as u16) as i16 as i64 as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::ZeroExtend16 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = self.registers[ra] % (1 << 16);
                    self.pc = next_pc;
                }
            }
            Opcode::ReverseBytes => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = self.registers[ra].swap_bytes();
                    self.pc = next_pc;
                }
            }

            // === A.5.10: Two registers + one immediate ===
            Opcode::StoreIndU8 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    step_store!(
                        self,
                        self.registers[rb].wrapping_add(imm) as u32,
                        write_u8,
                        self.registers[ra] as u8,
                        next_pc
                    );
                }
            }
            Opcode::StoreIndU16 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    step_store!(
                        self,
                        self.registers[rb].wrapping_add(imm) as u32,
                        write_u16_le,
                        self.registers[ra] as u16,
                        next_pc
                    );
                }
            }
            Opcode::StoreIndU32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    step_store!(
                        self,
                        self.registers[rb].wrapping_add(imm) as u32,
                        write_u32_le,
                        self.registers[ra] as u32,
                        next_pc
                    );
                }
            }
            Opcode::StoreIndU64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    step_store!(
                        self,
                        self.registers[rb].wrapping_add(imm) as u32,
                        write_u64_le,
                        self.registers[ra],
                        next_pc
                    );
                }
            }
            Opcode::LoadIndU8 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    step_load!(
                        self,
                        ra,
                        self.registers[rb].wrapping_add(imm) as u32,
                        read_u8,
                        |v| v as u64,
                        next_pc
                    );
                }
            }
            Opcode::LoadIndI8 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    step_load!(
                        self,
                        ra,
                        self.registers[rb].wrapping_add(imm) as u32,
                        read_u8,
                        |v| v as i8 as i64 as u64,
                        next_pc
                    );
                }
            }
            Opcode::LoadIndU16 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    step_load!(
                        self,
                        ra,
                        self.registers[rb].wrapping_add(imm) as u32,
                        read_u16_le,
                        |v| v as u64,
                        next_pc
                    );
                }
            }
            Opcode::LoadIndI16 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    step_load!(
                        self,
                        ra,
                        self.registers[rb].wrapping_add(imm) as u32,
                        read_u16_le,
                        |v| v as i16 as i64 as u64,
                        next_pc
                    );
                }
            }
            Opcode::LoadIndU32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    step_load!(
                        self,
                        ra,
                        self.registers[rb].wrapping_add(imm) as u32,
                        read_u32_le,
                        |v| v as u64,
                        next_pc
                    );
                }
            }
            Opcode::LoadIndI32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    step_load!(
                        self,
                        ra,
                        self.registers[rb].wrapping_add(imm) as u32,
                        read_u32_le,
                        |v| v as i32 as i64 as u64,
                        next_pc
                    );
                }
            }
            Opcode::LoadIndU64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    step_load!(
                        self,
                        ra,
                        self.registers[rb].wrapping_add(imm) as u32,
                        read_u64_le,
                        |v| v,
                        next_pc
                    );
                }
            }
            Opcode::AddImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = args::sign_extend_32(self.registers[rb].wrapping_add(imm));
                    self.pc = next_pc;
                }
            }
            Opcode::AndImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = self.registers[rb] & imm;
                    self.pc = next_pc;
                }
            }
            Opcode::XorImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = self.registers[rb] ^ imm;
                    self.pc = next_pc;
                }
            }
            Opcode::OrImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = self.registers[rb] | imm;
                    self.pc = next_pc;
                }
            }
            Opcode::MulImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = args::sign_extend_32(self.registers[rb].wrapping_mul(imm));
                    self.pc = next_pc;
                }
            }
            Opcode::SetLtUImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = (self.registers[rb] < imm) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::SetLtSImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = ((self.registers[rb] as i64) < (imm as i64)) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::ShloLImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (imm % 32) as u32;
                    self.registers[ra] = args::sign_extend_32(
                        (self.registers[rb] as u32).wrapping_shl(shift) as u64,
                    );
                    self.pc = next_pc;
                }
            }
            Opcode::ShloRImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (imm % 32) as u32;
                    self.registers[ra] = args::sign_extend_32(
                        (self.registers[rb] as u32).wrapping_shr(shift) as u64,
                    );
                    self.pc = next_pc;
                }
            }
            Opcode::SharRImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (imm % 32) as u32;
                    let val = (self.registers[rb] as u32) as i32;
                    self.registers[ra] = val.wrapping_shr(shift) as i64 as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::NegAddImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    // νX + 2^32 - φB, all mod 2^32, then sign-extend
                    let result = imm.wrapping_add((1u64 << 32).wrapping_sub(self.registers[rb]));
                    self.registers[ra] = args::sign_extend_32(result);
                    self.pc = next_pc;
                }
            }
            Opcode::SetGtUImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = (self.registers[rb] > imm) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::SetGtSImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = ((self.registers[rb] as i64) > (imm as i64)) as u64;
                    self.pc = next_pc;
                }
            }
            // Alt shifts: operands swapped (νX as the value being shifted by φB)
            Opcode::ShloLImmAlt32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (self.registers[rb] % 32) as u32;
                    self.registers[ra] =
                        args::sign_extend_32((imm as u32).wrapping_shl(shift) as u64);
                    self.pc = next_pc;
                }
            }
            Opcode::ShloRImmAlt32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (self.registers[rb] % 32) as u32;
                    self.registers[ra] =
                        args::sign_extend_32((imm as u32).wrapping_shr(shift) as u64);
                    self.pc = next_pc;
                }
            }
            Opcode::SharRImmAlt32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (self.registers[rb] % 32) as u32;
                    let val = (imm as u32) as i32;
                    self.registers[ra] = val.wrapping_shr(shift) as i64 as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::CmovIzImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    if self.registers[rb] == 0 {
                        self.registers[ra] = imm;
                    }
                    self.pc = next_pc;
                }
            }
            Opcode::CmovNzImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    if self.registers[rb] != 0 {
                        self.registers[ra] = imm;
                    }
                    self.pc = next_pc;
                }
            }
            Opcode::AddImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = self.registers[rb].wrapping_add(imm);
                    self.pc = next_pc;
                }
            }
            Opcode::MulImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = self.registers[rb].wrapping_mul(imm);
                    self.pc = next_pc;
                }
            }
            Opcode::ShloLImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (imm % 64) as u32;
                    self.registers[ra] = self.registers[rb].wrapping_shl(shift);
                    self.pc = next_pc;
                }
            }
            Opcode::ShloRImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (imm % 64) as u32;
                    self.registers[ra] = self.registers[rb].wrapping_shr(shift);
                    self.pc = next_pc;
                }
            }
            Opcode::SharRImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (imm % 64) as u32;
                    self.registers[ra] = (self.registers[rb] as i64).wrapping_shr(shift) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::NegAddImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = imm.wrapping_sub(self.registers[rb]);
                    self.pc = next_pc;
                }
            }
            Opcode::ShloLImmAlt64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (self.registers[rb] % 64) as u32;
                    self.registers[ra] = imm.wrapping_shl(shift);
                    self.pc = next_pc;
                }
            }
            Opcode::ShloRImmAlt64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (self.registers[rb] % 64) as u32;
                    self.registers[ra] = imm.wrapping_shr(shift);
                    self.pc = next_pc;
                }
            }
            Opcode::SharRImmAlt64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (self.registers[rb] % 64) as u32;
                    self.registers[ra] = (imm as i64).wrapping_shr(shift) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::RotR64Imm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = self.registers[rb].rotate_right((imm % 64) as u32);
                    self.pc = next_pc;
                }
            }
            Opcode::RotR64ImmAlt => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = imm.rotate_right((self.registers[rb] % 64) as u32);
                    self.pc = next_pc;
                }
            }
            Opcode::RotR32Imm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let val = self.registers[rb] as u32;
                    let result = val.rotate_right((imm % 32) as u32);
                    self.registers[ra] = args::sign_extend_32(result as u64);
                    self.pc = next_pc;
                }
            }
            Opcode::RotR32ImmAlt => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let val = imm as u32;
                    let result = val.rotate_right((self.registers[rb] % 32) as u32);
                    self.registers[ra] = args::sign_extend_32(result as u64);
                    self.pc = next_pc;
                }
            }

            // === A.5.11: Two registers + one offset ===
            Opcode::BranchEq
            | Opcode::BranchNe
            | Opcode::BranchLtU
            | Opcode::BranchGeU
            | Opcode::BranchLtS
            | Opcode::BranchGeS => {
                if let Args::TwoRegOffset { ra, rb, offset } = args {
                    let (a, b) = (self.registers[ra], self.registers[rb]);
                    let cond = match opcode {
                        Opcode::BranchEq => a == b,
                        Opcode::BranchNe => a != b,
                        Opcode::BranchLtU => a < b,
                        Opcode::BranchGeU => a >= b,
                        Opcode::BranchLtS => (a as i64) < (b as i64),
                        Opcode::BranchGeS => (a as i64) >= (b as i64),
                        _ => unreachable!(),
                    };
                    let (exit, new_pc) = self.branch(offset, cond, next_pc);
                    if let Some(e) = exit {
                        return Some(e);
                    }
                    self.pc = new_pc;
                }
            }

            // === A.5.12: Two registers + two immediates ===
            Opcode::LoadImmJumpInd => {
                if let Args::TwoRegTwoImm {
                    ra,
                    rb,
                    imm_x,
                    imm_y,
                } = args
                {
                    // GP A.5.12: the jump address uses the PRE-state ω_B; the
                    // register write ω'_A = ν_X happens logically after (when
                    // ra == rb the old value addresses the jump). Matches the
                    // Lean oracle and polkavm.
                    let addr = self.registers[rb].wrapping_add(imm_y) % (1u64 << 32);
                    self.registers[ra] = imm_x;
                    let (exit, new_pc) = self.djump(addr);
                    if let Some(e) = exit {
                        return Some(e);
                    }
                    self.pc = new_pc;
                }
            }

            // === A.5.13: Three registers ===
            Opcode::Add32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] =
                        args::sign_extend_32(self.registers[ra].wrapping_add(self.registers[rb]));
                    self.pc = next_pc;
                }
            }
            Opcode::Sub32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as u32;
                    let b = self.registers[rb] as u32;
                    self.registers[rd] = args::sign_extend_32(a.wrapping_sub(b) as u64);
                    self.pc = next_pc;
                }
            }
            Opcode::Mul32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] =
                        args::sign_extend_32(self.registers[ra].wrapping_mul(self.registers[rb]));
                    self.pc = next_pc;
                }
            }
            Opcode::DivU32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as u32;
                    let b = self.registers[rb] as u32;
                    self.registers[rd] = a
                        .checked_div(b)
                        .map(|q| args::sign_extend_32(q as u64))
                        .unwrap_or(u64::MAX);
                    self.pc = next_pc;
                }
            }
            Opcode::DivS32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as u32 as i32;
                    let b = self.registers[rb] as u32 as i32;
                    self.registers[rd] = if b == 0 {
                        u64::MAX
                    } else if a == i32::MIN && b == -1 {
                        a as i64 as u64 // Z8^-1(Z4(a))
                    } else {
                        (a / b) as i64 as u64
                    };
                    self.pc = next_pc;
                }
            }
            Opcode::RemU32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as u32;
                    let b = self.registers[rb] as u32;
                    self.registers[rd] = if b == 0 {
                        args::sign_extend_32(a as u64)
                    } else {
                        args::sign_extend_32((a % b) as u64)
                    };
                    self.pc = next_pc;
                }
            }
            Opcode::RemS32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as u32 as i32;
                    let b = self.registers[rb] as u32 as i32;
                    self.registers[rd] = if a == i32::MIN && b == -1 {
                        0
                    } else if b == 0 {
                        a as i64 as u64
                    } else {
                        // smod: sign of numerator, mod of absolutes
                        let r = smod_i64(a as i64, b as i64);
                        r as u64
                    };
                    self.pc = next_pc;
                }
            }
            Opcode::ShloL32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let shift = (self.registers[rb] % 32) as u32;
                    self.registers[rd] = args::sign_extend_32(
                        (self.registers[ra] as u32).wrapping_shl(shift) as u64,
                    );
                    self.pc = next_pc;
                }
            }
            Opcode::ShloR32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let shift = (self.registers[rb] % 32) as u32;
                    self.registers[rd] = args::sign_extend_32(
                        (self.registers[ra] as u32).wrapping_shr(shift) as u64,
                    );
                    self.pc = next_pc;
                }
            }
            Opcode::SharR32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let shift = (self.registers[rb] % 32) as u32;
                    let val = self.registers[ra] as u32 as i32;
                    self.registers[rd] = val.wrapping_shr(shift) as i64 as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::Add64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra].wrapping_add(self.registers[rb]);
                    self.pc = next_pc;
                }
            }
            Opcode::Sub64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra].wrapping_sub(self.registers[rb]);
                    self.pc = next_pc;
                }
            }
            Opcode::Mul64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra].wrapping_mul(self.registers[rb]);
                    self.pc = next_pc;
                }
            }
            Opcode::DivU64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra]
                        .checked_div(self.registers[rb])
                        .unwrap_or(u64::MAX);
                    self.pc = next_pc;
                }
            }
            Opcode::DivS64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as i64;
                    let b = self.registers[rb] as i64;
                    self.registers[rd] = if b == 0 {
                        u64::MAX
                    } else if a == i64::MIN && b == -1 {
                        a as u64
                    } else {
                        (a / b) as u64 // Rust truncates toward zero
                    };
                    self.pc = next_pc;
                }
            }
            Opcode::RemU64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = if self.registers[rb] == 0 {
                        self.registers[ra]
                    } else {
                        self.registers[ra] % self.registers[rb]
                    };
                    self.pc = next_pc;
                }
            }
            Opcode::RemS64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as i64;
                    let b = self.registers[rb] as i64;
                    self.registers[rd] = if a == i64::MIN && b == -1 {
                        0
                    } else if b == 0 {
                        a as u64
                    } else {
                        smod_i64(a, b) as u64
                    };
                    self.pc = next_pc;
                }
            }
            Opcode::ShloL64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let shift = (self.registers[rb] % 64) as u32;
                    self.registers[rd] = self.registers[ra].wrapping_shl(shift);
                    self.pc = next_pc;
                }
            }
            Opcode::ShloR64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let shift = (self.registers[rb] % 64) as u32;
                    self.registers[rd] = self.registers[ra].wrapping_shr(shift);
                    self.pc = next_pc;
                }
            }
            Opcode::SharR64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let shift = (self.registers[rb] % 64) as u32;
                    self.registers[rd] = (self.registers[ra] as i64).wrapping_shr(shift) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::And => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra] & self.registers[rb];
                    self.pc = next_pc;
                }
            }
            Opcode::Xor => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra] ^ self.registers[rb];
                    self.pc = next_pc;
                }
            }
            Opcode::Or => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra] | self.registers[rb];
                    self.pc = next_pc;
                }
            }
            Opcode::MulUpperSS => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as i64 as i128;
                    let b = self.registers[rb] as i64 as i128;
                    self.registers[rd] = ((a * b) >> 64) as i64 as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::MulUpperUU => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as u128;
                    let b = self.registers[rb] as u128;
                    self.registers[rd] = ((a * b) >> 64) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::MulUpperSU => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as i64 as i128;
                    let b = self.registers[rb] as u128;
                    // Z8(φA) * φB, signed * unsigned
                    let result = (a * b as i128) >> 64;
                    self.registers[rd] = result as i64 as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::SetLtU => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = (self.registers[ra] < self.registers[rb]) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::SetLtS => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] =
                        ((self.registers[ra] as i64) < (self.registers[rb] as i64)) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::CmovIz => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    if self.registers[rb] == 0 {
                        self.registers[rd] = self.registers[ra];
                    }
                    self.pc = next_pc;
                }
            }
            Opcode::CmovNz => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    if self.registers[rb] != 0 {
                        self.registers[rd] = self.registers[ra];
                    }
                    self.pc = next_pc;
                }
            }
            Opcode::RotL64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] =
                        self.registers[ra].rotate_left((self.registers[rb] % 64) as u32);
                    self.pc = next_pc;
                }
            }
            Opcode::RotL32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let val = self.registers[ra] as u32;
                    let result = val.rotate_left((self.registers[rb] % 32) as u32);
                    self.registers[rd] = args::sign_extend_32(result as u64);
                    self.pc = next_pc;
                }
            }
            Opcode::RotR64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] =
                        self.registers[ra].rotate_right((self.registers[rb] % 64) as u32);
                    self.pc = next_pc;
                }
            }
            Opcode::RotR32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let val = self.registers[ra] as u32;
                    let result = val.rotate_right((self.registers[rb] % 32) as u32);
                    self.registers[rd] = args::sign_extend_32(result as u64);
                    self.pc = next_pc;
                }
            }
            Opcode::AndInv => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra] & !self.registers[rb];
                    self.pc = next_pc;
                }
            }
            Opcode::OrInv => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra] | !self.registers[rb];
                    self.pc = next_pc;
                }
            }
            Opcode::Xnor => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = !(self.registers[ra] ^ self.registers[rb]);
                    self.pc = next_pc;
                }
            }
            Opcode::Max => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as i64;
                    let b = self.registers[rb] as i64;
                    self.registers[rd] = a.max(b) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::MaxU => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra].max(self.registers[rb]);
                    self.pc = next_pc;
                }
            }
            Opcode::Min => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as i64;
                    let b = self.registers[rb] as i64;
                    self.registers[rd] = a.min(b) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::MinU => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra].min(self.registers[rb]);
                    self.pc = next_pc;
                }
            }
        }

        // After execution: if this instruction is a terminator, the next
        // instruction starts a new basic block and needs gas charging.
        if is_terminator_for_mode(opcode, self.isa_mode) {
            self.gas_charged = false;
            self.need_gas_charge = true;
        }

        None
    }

    /// Run the machine until it exits (eq A.1).
    ///
    /// Uses pre-decoded instructions for speed (avoids per-instruction
    /// decode overhead). Gas charges come from the pre-derived
    /// `DecodedInst::bb_gas_cost` labels: block costs at gas-block entries
    /// under [`crate::GasModel::BlockPipeline`], a flat 1 on every
    /// instruction under [`crate::GasModel::PerInstruction`] (see
    /// [`Self::set_gas_model`]).
    /// Returns (exit_reason, gas_used).
    pub fn run(&mut self) -> (ExitReason, Gas) {
        let result = self.run_inner();
        if self.isa_mode == crate::IsaMode::Conformance
            && matches!(result.0, ExitReason::Halt | ExitReason::Panic)
        {
            self.pc = 0;
            self.pending_host_call = None;
        }
        result
    }

    fn run_inner(&mut self) -> (ExitReason, Gas) {
        // Macros for repetitive load/store dispatch arms. Each macro
        // expands to the same code as the hand-written variants, so there is
        // zero runtime overhead.
        macro_rules! do_store {
            ($self:expr, $exit:ident, $addr:expr, $write_fn:ident, $val:expr) => {{
                let addr = $addr;
                if $self.isa_mode == crate::IsaMode::Conformance
                    && let Some(reason) =
                        $self.standard_memory_exception(addr, memory_access_width!($write_fn), true)
                {
                    $exit = Some(reason);
                } else if let Err(page) = $self.$write_fn(addr, $val) {
                    $exit = Some(ExitReason::PageFault(page));
                }
            }};
        }
        macro_rules! do_load {
            ($self:expr, $exit:ident, $dst:expr, $addr:expr, $read_fn:ident, |$v:ident| $conv:expr) => {{
                let addr = $addr;
                if $self.isa_mode == crate::IsaMode::Conformance
                    && let Some(reason) =
                        $self.standard_memory_exception(addr, memory_access_width!($read_fn), false)
                {
                    $exit = Some(reason);
                } else {
                    match $self.$read_fn(addr) {
                        Ok($v) => {
                            $self.registers[$dst] = $conv;
                        }
                        Err(page) => {
                            $exit = Some(ExitReason::PageFault(page));
                        }
                    }
                }
            }};
        }

        let initial_gas = self.gas;

        if self.isa_mode == crate::IsaMode::Conformance
            && let Some(call) = self.pending_host_call
        {
            self.pc = call.cause_pc;
            return (ExitReason::HostCall(call.id), 0);
        }

        // If tracing is enabled, fall back to the slow step-by-step path
        if self.tracing_enabled {
            return self.run_stepping(initial_gas);
        }

        // Resolve starting PC to instruction index
        let mut idx = if (self.pc as usize) < self.pc_to_idx.len() {
            self.pc_to_idx[self.pc as usize]
        } else {
            u32::MAX
        };

        if idx == u32::MAX {
            // Invalid starting PC. Under per-instruction gas the
            // out-of-gas check precedes execution (Lean: `run` checks gas
            // before `executeStep` panics), so an exhausted VM exits
            // OutOfGas even here; otherwise the failed step costs 1.
            if self.gas_model == crate::GasModel::PerInstruction && self.gas == 0 {
                return (ExitReason::OutOfGas, 0);
            }
            if self.isa_mode == crate::IsaMode::Jar {
                self.gas = self.gas.saturating_sub(1);
            }
            return (ExitReason::Panic, initial_gas - self.gas);
        }

        loop {
            // Copy the decoded instruction (avoids borrow conflict with &mut self)
            // SAFETY: idx is maintained within 0..decoded_insts.len() by the decoder
            // and incremented only via validated next_pc / jump targets.
            let inst = *unsafe { self.decoded_insts.get_unchecked(idx as usize) };

            // Gas charge from the pre-derived label: block cost at gas-block
            // entries (JAR v0.8.0), or a flat 1 on every instruction under
            // GasModel::PerInstruction (GP 0.7.2) — see set_gas_model().
            let charge = match self.gas_model {
                crate::GasModel::PerInstruction => u64::from(inst.bb_gas_cost),
                crate::GasModel::BlockPipeline if !self.gas_charged => match self.isa_mode {
                    crate::IsaMode::Conformance => {
                        let Some(cost) = self.containing_block_cost(inst.pc) else {
                            self.pc = inst.pc;
                            return (ExitReason::Panic, initial_gas - self.gas);
                        };
                        cost
                    }
                    crate::IsaMode::Jar => u64::from(inst.bb_gas_cost),
                },
                crate::GasModel::BlockPipeline => 0,
            };
            if charge > 0 {
                if self.gas < charge {
                    self.pc = inst.pc;
                    return (ExitReason::OutOfGas, initial_gas - self.gas);
                }
                self.gas -= charge;
            }
            if self.gas_model == crate::GasModel::BlockPipeline {
                self.gas_charged = true;
                self.need_gas_charge = false;
            }

            // Fast-path execution using flat operands (no Args enum matching).
            let ra = inst.ra as usize;
            let rb = inst.rb as usize;
            let rd = inst.rd as usize;
            let imm1 = inst.imm1;
            let next_pc = inst.next_pc;

            // Most instructions advance sequentially. Branches/jumps set
            // branch_idx to the pre-resolved instruction index.
            let mut branch_idx: u32 = u32::MAX; // sentinel: means sequential
            let mut exit: Option<ExitReason> = None;

            match inst.opcode {
                // === No arguments ===
                Opcode::Trap => {
                    exit = Some(match self.isa_mode {
                        crate::IsaMode::Jar => ExitReason::Trap,
                        crate::IsaMode::Conformance => ExitReason::Panic,
                    });
                }
                Opcode::Fallthrough => {
                    if self.isa_mode == crate::IsaMode::Conformance
                        && !self.is_basic_block_start(u64::from(next_pc))
                    {
                        exit = Some(ExitReason::Panic);
                    }
                }
                Opcode::Unlikely => {}
                Opcode::Invalid => {
                    exit = Some(ExitReason::Panic);
                }
                Opcode::Ecall => {
                    // Jar extension — panics under GP conformance.
                    if self.isa_mode == crate::IsaMode::Conformance {
                        self.pc = inst.pc;
                        return (ExitReason::Panic, initial_gas - self.gas);
                    }
                    self.pc = next_pc;
                    // Runtime Ecall is a JAR gas-block terminator.  This arm
                    // returns before the shared terminator bookkeeping below,
                    // so install the successor boundary explicitly.
                    self.gas_charged = false;
                    self.need_gas_charge = true;
                    return (ExitReason::Ecall, initial_gas - self.gas);
                }

                // === One immediate ===
                Opcode::Ecalli => {
                    let host_id = match self.isa_mode {
                        crate::IsaMode::Conformance => imm1,
                        crate::IsaMode::Jar => u64::from(imm1 as u32),
                    };
                    if self.isa_mode == crate::IsaMode::Conformance {
                        self.pc = inst.pc;
                        self.pending_host_call = Some(crate::PendingHostCall {
                            id: host_id,
                            cause_pc: inst.pc,
                            resume_pc: next_pc,
                        });
                    } else {
                        self.pc = next_pc;
                    }
                    return (ExitReason::HostCall(host_id), initial_gas - self.gas);
                }

                // === One register + extended immediate ===
                Opcode::LoadImm64 => {
                    self.registers[ra] = imm1;
                }

                // === One offset (jump) ===
                Opcode::Jump => {
                    if inst.target_idx != u32::MAX {
                        branch_idx = inst.target_idx;
                    } else {
                        exit = Some(ExitReason::Panic);
                    }
                }

                // === One register + one immediate ===
                Opcode::JumpInd => {
                    let addr = self.registers[ra].wrapping_add(imm1) % (1u64 << 32);
                    let (e, target_pc) = self.djump(addr);
                    if let Some(reason) = e {
                        exit = Some(reason);
                    } else {
                        let t = target_pc as usize;
                        if t < self.pc_to_idx.len() {
                            let tidx = self.pc_to_idx[t];
                            if tidx != u32::MAX {
                                branch_idx = tidx;
                            } else {
                                exit = Some(ExitReason::Panic);
                            }
                        } else {
                            exit = Some(ExitReason::Panic);
                        }
                    }
                }
                Opcode::LoadImm => {
                    self.registers[ra] = imm1;
                }

                // === Two registers ===
                Opcode::MoveReg => {
                    self.registers[rd] = self.registers[ra];
                }
                Opcode::CountSetBits64 => {
                    self.registers[rd] = self.registers[ra].count_ones() as u64;
                }
                Opcode::CountSetBits32 => {
                    self.registers[rd] = (self.registers[ra] as u32).count_ones() as u64;
                }
                Opcode::LeadingZeroBits64 => {
                    self.registers[rd] = self.registers[ra].leading_zeros() as u64;
                }
                Opcode::LeadingZeroBits32 => {
                    self.registers[rd] = (self.registers[ra] as u32).leading_zeros() as u64;
                }
                Opcode::TrailingZeroBits64 => {
                    self.registers[rd] = self.registers[ra].trailing_zeros() as u64;
                }
                Opcode::TrailingZeroBits32 => {
                    self.registers[rd] = (self.registers[ra] as u32).trailing_zeros() as u64;
                }
                Opcode::SignExtend8 => {
                    self.registers[rd] = self.registers[ra] as u8 as i8 as i64 as u64;
                }
                Opcode::SignExtend16 => {
                    self.registers[rd] = self.registers[ra] as u16 as i16 as i64 as u64;
                }
                Opcode::ZeroExtend16 => {
                    self.registers[rd] = self.registers[ra] as u16 as u64;
                }
                Opcode::ReverseBytes => {
                    self.registers[rd] = self.registers[ra].swap_bytes();
                }

                // === Two registers + one immediate ===
                Opcode::AddImm32 => {
                    self.registers[ra] =
                        args::sign_extend_32(self.registers[rb].wrapping_add(imm1));
                }
                Opcode::AddImm64 => {
                    self.registers[ra] = self.registers[rb].wrapping_add(imm1);
                }
                Opcode::MulImm32 => {
                    self.registers[ra] = args::sign_extend_32(
                        (self.registers[rb] as u32).wrapping_mul(imm1 as u32) as u64,
                    );
                }
                Opcode::MulImm64 => {
                    self.registers[ra] = self.registers[rb].wrapping_mul(imm1);
                }
                Opcode::AndImm => {
                    self.registers[ra] = self.registers[rb] & imm1;
                }
                Opcode::XorImm => {
                    self.registers[ra] = self.registers[rb] ^ imm1;
                }
                Opcode::OrImm => {
                    self.registers[ra] = self.registers[rb] | imm1;
                }
                Opcode::SetLtUImm => {
                    self.registers[ra] = if self.registers[rb] < imm1 { 1 } else { 0 };
                }
                Opcode::SetLtSImm => {
                    self.registers[ra] = if (self.registers[rb] as i64) < (imm1 as i64) {
                        1
                    } else {
                        0
                    };
                }
                Opcode::SetGtUImm => {
                    self.registers[ra] = if self.registers[rb] > imm1 { 1 } else { 0 };
                }
                Opcode::SetGtSImm => {
                    self.registers[ra] = if (self.registers[rb] as i64) > (imm1 as i64) {
                        1
                    } else {
                        0
                    };
                }
                Opcode::ShloLImm32 => {
                    self.registers[ra] = args::sign_extend_32(
                        (self.registers[rb] as u32).wrapping_shl((imm1 % 32) as u32) as u64,
                    );
                }
                Opcode::ShloRImm32 => {
                    self.registers[ra] = args::sign_extend_32(
                        (self.registers[rb] as u32).wrapping_shr((imm1 % 32) as u32) as u64,
                    );
                }
                Opcode::SharRImm32 => {
                    self.registers[ra] = (self.registers[rb] as u32 as i32)
                        .wrapping_shr((imm1 % 32) as u32)
                        as i64 as u64;
                }
                Opcode::ShloLImm64 => {
                    self.registers[ra] = self.registers[rb].wrapping_shl((imm1 % 64) as u32);
                }
                Opcode::ShloRImm64 => {
                    self.registers[ra] = self.registers[rb].wrapping_shr((imm1 % 64) as u32);
                }
                Opcode::SharRImm64 => {
                    self.registers[ra] =
                        (self.registers[rb] as i64).wrapping_shr((imm1 % 64) as u32) as u64;
                }
                Opcode::NegAddImm32 => {
                    self.registers[ra] =
                        args::sign_extend_32(imm1.wrapping_sub(self.registers[rb]) as u32 as u64);
                }
                Opcode::NegAddImm64 => {
                    self.registers[ra] = imm1.wrapping_sub(self.registers[rb]);
                }
                Opcode::CmovIzImm => {
                    if self.registers[rb] == 0 {
                        self.registers[ra] = imm1;
                    }
                }
                Opcode::CmovNzImm => {
                    if self.registers[rb] != 0 {
                        self.registers[ra] = imm1;
                    }
                }
                Opcode::RotR64Imm => {
                    self.registers[ra] = self.registers[rb].rotate_right((imm1 % 64) as u32);
                }
                Opcode::RotR32Imm => {
                    self.registers[ra] = args::sign_extend_32(
                        (self.registers[rb] as u32).rotate_right((imm1 % 32) as u32) as u64,
                    );
                }

                // ImmAlt variants: op ra, imm, rb (imm is the "left" operand)
                Opcode::ShloLImmAlt32 => {
                    self.registers[ra] = args::sign_extend_32(
                        (imm1 as u32).wrapping_shl((self.registers[rb] % 32) as u32) as u64,
                    );
                }
                Opcode::ShloRImmAlt32 => {
                    self.registers[ra] = args::sign_extend_32(
                        (imm1 as u32).wrapping_shr((self.registers[rb] % 32) as u32) as u64,
                    );
                }
                Opcode::SharRImmAlt32 => {
                    self.registers[ra] = ((imm1 as u32) as i32)
                        .wrapping_shr((self.registers[rb] % 32) as u32)
                        as i64 as u64;
                }
                Opcode::ShloLImmAlt64 => {
                    self.registers[ra] = imm1.wrapping_shl((self.registers[rb] % 64) as u32);
                }
                Opcode::ShloRImmAlt64 => {
                    self.registers[ra] = imm1.wrapping_shr((self.registers[rb] % 64) as u32);
                }
                Opcode::SharRImmAlt64 => {
                    self.registers[ra] =
                        (imm1 as i64).wrapping_shr((self.registers[rb] % 64) as u32) as u64;
                }
                Opcode::RotR64ImmAlt => {
                    self.registers[ra] = imm1.rotate_right((self.registers[rb] % 64) as u32);
                }
                Opcode::RotR32ImmAlt => {
                    self.registers[ra] = args::sign_extend_32(
                        (imm1 as u32).rotate_right((self.registers[rb] % 32) as u32) as u64,
                    );
                }

                // === Two registers + one offset (branches) ===
                Opcode::BranchEq
                | Opcode::BranchNe
                | Opcode::BranchLtU
                | Opcode::BranchGeU
                | Opcode::BranchLtS
                | Opcode::BranchGeS => {
                    let (a, b) = (self.registers[ra], self.registers[rb]);
                    let cond = match inst.opcode {
                        Opcode::BranchEq => a == b,
                        Opcode::BranchNe => a != b,
                        Opcode::BranchLtU => a < b,
                        Opcode::BranchGeU => a >= b,
                        Opcode::BranchLtS => (a as i64) < (b as i64),
                        Opcode::BranchGeS => (a as i64) >= (b as i64),
                        _ => unreachable!(),
                    };
                    if self.isa_mode == crate::IsaMode::Conformance
                        && (inst.target_idx == u32::MAX
                            || !self.is_basic_block_start(u64::from(next_pc)))
                    {
                        // v0.8 validates both the explicit target and the
                        // sequential successor before selecting either leg.
                        exit = Some(ExitReason::Panic);
                    } else if cond {
                        if inst.target_idx != u32::MAX {
                            branch_idx = inst.target_idx;
                        } else {
                            exit = Some(ExitReason::Panic);
                        }
                    }
                }

                // === Three register ALU ===
                Opcode::Add32 => {
                    self.registers[rd] =
                        args::sign_extend_32(self.registers[ra].wrapping_add(self.registers[rb]));
                }
                Opcode::Sub32 => {
                    self.registers[rd] =
                        args::sign_extend_32(self.registers[ra].wrapping_sub(self.registers[rb]));
                }
                Opcode::Add64 => {
                    self.registers[rd] = self.registers[ra].wrapping_add(self.registers[rb]);
                }
                Opcode::Sub64 => {
                    self.registers[rd] = self.registers[ra].wrapping_sub(self.registers[rb]);
                }
                Opcode::Mul32 => {
                    self.registers[rd] = args::sign_extend_32(
                        (self.registers[ra] as u32).wrapping_mul(self.registers[rb] as u32) as u64,
                    );
                }
                Opcode::Mul64 => {
                    self.registers[rd] = self.registers[ra].wrapping_mul(self.registers[rb]);
                }
                Opcode::And => {
                    self.registers[rd] = self.registers[ra] & self.registers[rb];
                }
                Opcode::Or => {
                    self.registers[rd] = self.registers[ra] | self.registers[rb];
                }
                Opcode::Xor => {
                    self.registers[rd] = self.registers[ra] ^ self.registers[rb];
                }
                Opcode::SetLtU => {
                    self.registers[rd] = if self.registers[ra] < self.registers[rb] {
                        1
                    } else {
                        0
                    };
                }
                Opcode::SetLtS => {
                    self.registers[rd] =
                        if (self.registers[ra] as i64) < (self.registers[rb] as i64) {
                            1
                        } else {
                            0
                        };
                }
                Opcode::CmovIz => {
                    if self.registers[rb] == 0 {
                        self.registers[rd] = self.registers[ra];
                    }
                }
                Opcode::CmovNz => {
                    if self.registers[rb] != 0 {
                        self.registers[rd] = self.registers[ra];
                    }
                }
                Opcode::ShloL32 => {
                    self.registers[rd] = args::sign_extend_32(
                        (self.registers[ra] as u32).wrapping_shl((self.registers[rb] % 32) as u32)
                            as u64,
                    );
                }
                Opcode::ShloR32 => {
                    self.registers[rd] = args::sign_extend_32(
                        (self.registers[ra] as u32).wrapping_shr((self.registers[rb] % 32) as u32)
                            as u64,
                    );
                }
                Opcode::SharR32 => {
                    self.registers[rd] = (self.registers[ra] as u32 as i32)
                        .wrapping_shr((self.registers[rb] % 32) as u32)
                        as i64 as u64;
                }
                Opcode::ShloL64 => {
                    self.registers[rd] =
                        self.registers[ra].wrapping_shl((self.registers[rb] % 64) as u32);
                }
                Opcode::ShloR64 => {
                    self.registers[rd] =
                        self.registers[ra].wrapping_shr((self.registers[rb] % 64) as u32);
                }
                Opcode::SharR64 => {
                    self.registers[rd] = (self.registers[ra] as i64)
                        .wrapping_shr((self.registers[rb] % 64) as u32)
                        as u64;
                }
                Opcode::RotL64 => {
                    self.registers[rd] =
                        self.registers[ra].rotate_left((self.registers[rb] % 64) as u32);
                }
                Opcode::RotR64 => {
                    self.registers[rd] =
                        self.registers[ra].rotate_right((self.registers[rb] % 64) as u32);
                }
                Opcode::RotL32 => {
                    self.registers[rd] = args::sign_extend_32(
                        (self.registers[ra] as u32).rotate_left((self.registers[rb] % 32) as u32)
                            as u64,
                    );
                }
                Opcode::RotR32 => {
                    self.registers[rd] = args::sign_extend_32(
                        (self.registers[ra] as u32).rotate_right((self.registers[rb] % 32) as u32)
                            as u64,
                    );
                }
                Opcode::AndInv => {
                    self.registers[rd] = self.registers[ra] & !self.registers[rb];
                }
                Opcode::OrInv => {
                    self.registers[rd] = self.registers[ra] | !self.registers[rb];
                }
                Opcode::Xnor => {
                    self.registers[rd] = !(self.registers[ra] ^ self.registers[rb]);
                }
                Opcode::Max => {
                    self.registers[rd] =
                        core::cmp::max(self.registers[ra] as i64, self.registers[rb] as i64) as u64;
                }
                Opcode::MaxU => {
                    self.registers[rd] = core::cmp::max(self.registers[ra], self.registers[rb]);
                }
                Opcode::Min => {
                    self.registers[rd] =
                        core::cmp::min(self.registers[ra] as i64, self.registers[rb] as i64) as u64;
                }
                Opcode::MinU => {
                    self.registers[rd] = core::cmp::min(self.registers[ra], self.registers[rb]);
                }

                // === Indirect loads (two reg + imm) ===
                Opcode::LoadIndU8 => do_load!(
                    self,
                    exit,
                    ra,
                    self.registers[rb].wrapping_add(imm1) as u32,
                    read_u8,
                    |v| v as u64
                ),
                Opcode::LoadIndI8 => do_load!(
                    self,
                    exit,
                    ra,
                    self.registers[rb].wrapping_add(imm1) as u32,
                    read_u8,
                    |v| v as i8 as i64 as u64
                ),
                Opcode::LoadIndU16 => do_load!(
                    self,
                    exit,
                    ra,
                    self.registers[rb].wrapping_add(imm1) as u32,
                    read_u16_le,
                    |v| v as u64
                ),
                Opcode::LoadIndI16 => do_load!(
                    self,
                    exit,
                    ra,
                    self.registers[rb].wrapping_add(imm1) as u32,
                    read_u16_le,
                    |v| v as i16 as i64 as u64
                ),
                Opcode::LoadIndU32 => do_load!(
                    self,
                    exit,
                    ra,
                    self.registers[rb].wrapping_add(imm1) as u32,
                    read_u32_le,
                    |v| v as u64
                ),
                Opcode::LoadIndI32 => do_load!(
                    self,
                    exit,
                    ra,
                    self.registers[rb].wrapping_add(imm1) as u32,
                    read_u32_le,
                    |v| v as i32 as i64 as u64
                ),
                Opcode::LoadIndU64 => do_load!(
                    self,
                    exit,
                    ra,
                    self.registers[rb].wrapping_add(imm1) as u32,
                    read_u64_le,
                    |v| v
                ),

                // === Indirect stores (two reg + imm) ===
                Opcode::StoreIndU8 => do_store!(
                    self,
                    exit,
                    self.registers[rb].wrapping_add(imm1) as u32,
                    write_u8,
                    self.registers[ra] as u8
                ),
                Opcode::StoreIndU16 => do_store!(
                    self,
                    exit,
                    self.registers[rb].wrapping_add(imm1) as u32,
                    write_u16_le,
                    self.registers[ra] as u16
                ),
                Opcode::StoreIndU32 => do_store!(
                    self,
                    exit,
                    self.registers[rb].wrapping_add(imm1) as u32,
                    write_u32_le,
                    self.registers[ra] as u32
                ),
                Opcode::StoreIndU64 => do_store!(
                    self,
                    exit,
                    self.registers[rb].wrapping_add(imm1) as u32,
                    write_u64_le,
                    self.registers[ra]
                ),

                // === Div/Rem (three reg, common in crypto) ===
                Opcode::DivU32 => {
                    let b = self.registers[rb] as u32;
                    self.registers[rd] = (self.registers[ra] as u32)
                        .checked_div(b)
                        .map(|q| args::sign_extend_32(q as u64))
                        .unwrap_or(u64::MAX);
                }
                Opcode::DivU64 => {
                    let b = self.registers[rb];
                    self.registers[rd] = self.registers[ra].checked_div(b).unwrap_or(u64::MAX);
                }
                Opcode::DivS32 => {
                    let a = self.registers[ra] as i32;
                    let b = self.registers[rb] as i32;
                    self.registers[rd] = if b == 0 {
                        u64::MAX
                    } else if a == i32::MIN && b == -1 {
                        a as u64
                    } else {
                        args::sign_extend_32((a / b) as i64 as u64)
                    };
                }
                Opcode::DivS64 => {
                    let a = self.registers[ra] as i64;
                    let b = self.registers[rb] as i64;
                    self.registers[rd] = if b == 0 {
                        u64::MAX
                    } else if a == i64::MIN && b == -1 {
                        a as u64
                    } else {
                        (a / b) as u64
                    };
                }
                Opcode::RemU32 => {
                    let b = self.registers[rb] as u32;
                    self.registers[rd] = if b == 0 {
                        args::sign_extend_32(self.registers[ra] as u32 as u64)
                    } else {
                        args::sign_extend_32((self.registers[ra] as u32 % b) as u64)
                    };
                }
                Opcode::RemU64 => {
                    let b = self.registers[rb];
                    self.registers[rd] = if b == 0 {
                        self.registers[ra]
                    } else {
                        self.registers[ra] % b
                    };
                }
                Opcode::RemS32 => {
                    let a = self.registers[ra] as i32;
                    let b = self.registers[rb] as i32;
                    self.registers[rd] = if b == 0 {
                        a as u64
                    } else if a == i32::MIN && b == -1 {
                        0
                    } else {
                        args::sign_extend_32((a % b) as i64 as u64)
                    };
                }
                Opcode::RemS64 => {
                    let a = self.registers[ra] as i64;
                    let b = self.registers[rb] as i64;
                    self.registers[rd] = if b == 0 {
                        a as u64
                    } else if a == i64::MIN && b == -1 {
                        0
                    } else {
                        (a % b) as u64
                    };
                }
                Opcode::MulUpperSS => {
                    self.registers[rd] = ((self.registers[ra] as i64 as i128)
                        .wrapping_mul(self.registers[rb] as i64 as i128)
                        >> 64) as u64;
                }
                Opcode::MulUpperUU => {
                    self.registers[rd] = ((self.registers[ra] as u128)
                        .wrapping_mul(self.registers[rb] as u128)
                        >> 64) as u64;
                }
                Opcode::MulUpperSU => {
                    self.registers[rd] = ((self.registers[ra] as i64 as i128)
                        .wrapping_mul(self.registers[rb] as u128 as i128)
                        >> 64) as u64;
                }

                // === Two immediates (store_imm: addr = imm1, value = imm2) ===
                Opcode::StoreImmU8 => do_store!(self, exit, imm1 as u32, write_u8, inst.imm2 as u8),
                Opcode::StoreImmU16 => {
                    do_store!(self, exit, imm1 as u32, write_u16_le, inst.imm2 as u16)
                }
                Opcode::StoreImmU32 => {
                    do_store!(self, exit, imm1 as u32, write_u32_le, inst.imm2 as u32)
                }
                Opcode::StoreImmU64 => do_store!(self, exit, imm1 as u32, write_u64_le, inst.imm2),

                // === Absolute address loads (addr = imm1) ===
                Opcode::LoadU8 => do_load!(self, exit, ra, imm1 as u32, read_u8, |v| v as u64),
                Opcode::LoadI8 => {
                    do_load!(self, exit, ra, imm1 as u32, read_u8, |v| v as i8 as i64
                        as u64)
                }
                Opcode::LoadU16 => do_load!(self, exit, ra, imm1 as u32, read_u16_le, |v| v as u64),
                Opcode::LoadI16 => do_load!(self, exit, ra, imm1 as u32, read_u16_le, |v| v as i16
                    as i64
                    as u64),
                Opcode::LoadU32 => do_load!(self, exit, ra, imm1 as u32, read_u32_le, |v| v as u64),
                Opcode::LoadI32 => do_load!(self, exit, ra, imm1 as u32, read_u32_le, |v| v as i32
                    as i64
                    as u64),
                Opcode::LoadU64 => do_load!(self, exit, ra, imm1 as u32, read_u64_le, |v| v),

                // === Absolute address stores (addr = imm1, value = reg[ra]) ===
                Opcode::StoreU8 => {
                    do_store!(self, exit, imm1 as u32, write_u8, self.registers[ra] as u8)
                }
                Opcode::StoreU16 => do_store!(
                    self,
                    exit,
                    imm1 as u32,
                    write_u16_le,
                    self.registers[ra] as u16
                ),
                Opcode::StoreU32 => do_store!(
                    self,
                    exit,
                    imm1 as u32,
                    write_u32_le,
                    self.registers[ra] as u32
                ),
                Opcode::StoreU64 => {
                    do_store!(self, exit, imm1 as u32, write_u64_le, self.registers[ra])
                }

                // === Store imm indirect (addr = reg[ra] + imm1, value = imm2) ===
                Opcode::StoreImmIndU8 => do_store!(
                    self,
                    exit,
                    self.registers[ra].wrapping_add(imm1) as u32,
                    write_u8,
                    inst.imm2 as u8
                ),
                Opcode::StoreImmIndU16 => do_store!(
                    self,
                    exit,
                    self.registers[ra].wrapping_add(imm1) as u32,
                    write_u16_le,
                    inst.imm2 as u16
                ),
                Opcode::StoreImmIndU32 => do_store!(
                    self,
                    exit,
                    self.registers[ra].wrapping_add(imm1) as u32,
                    write_u32_le,
                    inst.imm2 as u32
                ),
                Opcode::StoreImmIndU64 => do_store!(
                    self,
                    exit,
                    self.registers[ra].wrapping_add(imm1) as u32,
                    write_u64_le,
                    inst.imm2
                ),

                // === LoadImmJump (reg[ra] = imm1, branch to target) ===
                Opcode::LoadImmJump => {
                    self.registers[ra] = imm1;
                    if inst.target_idx != u32::MAX {
                        branch_idx = inst.target_idx;
                    } else {
                        exit = Some(ExitReason::Panic);
                    }
                }

                // === BranchImm variants (cond on reg[ra] vs imm1, target = target_idx) ===
                Opcode::BranchEqImm
                | Opcode::BranchNeImm
                | Opcode::BranchLtUImm
                | Opcode::BranchLeUImm
                | Opcode::BranchGeUImm
                | Opcode::BranchGtUImm
                | Opcode::BranchLtSImm
                | Opcode::BranchLeSImm
                | Opcode::BranchGeSImm
                | Opcode::BranchGtSImm => {
                    let (a, b) = (self.registers[ra], imm1);
                    let cond = match inst.opcode {
                        Opcode::BranchEqImm => a == b,
                        Opcode::BranchNeImm => a != b,
                        Opcode::BranchLtUImm => a < b,
                        Opcode::BranchLeUImm => a <= b,
                        Opcode::BranchGeUImm => a >= b,
                        Opcode::BranchGtUImm => a > b,
                        Opcode::BranchLtSImm => (a as i64) < (b as i64),
                        Opcode::BranchLeSImm => (a as i64) <= (b as i64),
                        Opcode::BranchGeSImm => (a as i64) >= (b as i64),
                        Opcode::BranchGtSImm => (a as i64) > (b as i64),
                        _ => unreachable!(),
                    };
                    if self.isa_mode == crate::IsaMode::Conformance
                        && (inst.target_idx == u32::MAX
                            || !self.is_basic_block_start(u64::from(next_pc)))
                    {
                        // v0.8 validates both the explicit target and the
                        // sequential successor before selecting either leg.
                        exit = Some(ExitReason::Panic);
                    } else if cond {
                        if inst.target_idx != u32::MAX {
                            branch_idx = inst.target_idx;
                        } else {
                            exit = Some(ExitReason::Panic);
                        }
                    }
                }

                // === Two registers + two immediates ===
                Opcode::LoadImmJumpInd => {
                    // GP A.5.12: address from PRE-state ω_B (matters when
                    // ra == rb); write ω'_A = ν_X after.
                    let addr = self.registers[rb].wrapping_add(inst.imm2) % (1u64 << 32);
                    self.registers[ra] = imm1;
                    let (e, target_pc) = self.djump(addr);
                    if let Some(reason) = e {
                        exit = Some(reason);
                    } else {
                        let t = target_pc as usize;
                        if t < self.pc_to_idx.len() {
                            let tidx = self.pc_to_idx[t];
                            if tidx != u32::MAX {
                                branch_idx = tidx;
                            } else {
                                exit = Some(ExitReason::Panic);
                            }
                        } else {
                            exit = Some(ExitReason::Panic);
                        }
                    }
                }
            }

            if let Some(reason) = exit {
                self.pc = inst.pc;
                return (reason, initial_gas - self.gas);
            }

            if is_terminator_for_mode(inst.opcode, self.isa_mode) {
                self.gas_charged = false;
                self.need_gas_charge = true;
            }

            if branch_idx == u32::MAX {
                // Sequential advance
                idx += 1;
            } else {
                idx = branch_idx;
            }
        }
    }

    /// Run to the next exit while observing every canonical instruction.
    ///
    /// This follows [`Self::step`] exactly and invokes `observer` only after
    /// the step has completed. The observer receives immutable state and
    /// therefore cannot alter execution. The return value has the same shape
    /// as [`Self::run`].
    pub fn run_observed(
        &mut self,
        mut observer: impl FnMut(InstructionObservation<'_>),
    ) -> (ExitReason, Gas) {
        let initial_gas = self.gas;
        loop {
            let pc_before = self.pc;
            let opcode_byte = self.code.get(pc_before as usize).copied().unwrap_or(0);
            let registers_before = self.registers;
            let gas_before = self.gas;
            let need_gas_charge_before = self.need_gas_charge;
            let exit = self.step();
            observer(InstructionObservation {
                pc_before,
                opcode_byte,
                registers_before,
                gas_before,
                need_gas_charge_before,
                exit: exit.as_ref(),
                machine_after: self,
            });
            if let Some(exit) = exit {
                if self.isa_mode == crate::IsaMode::Conformance {
                    match exit {
                        ExitReason::HostCall(_) => debug_assert_eq!(self.pc, pc_before),
                        ExitReason::Halt | ExitReason::Panic => self.pc = 0,
                        _ => {}
                    }
                }
                return (exit, initial_gas.saturating_sub(self.gas));
            }
        }
    }

    /// Slow run path for tracing/stepping mode — uses step() with per-instruction gas.
    fn run_stepping(&mut self, initial_gas: Gas) -> (ExitReason, Gas) {
        loop {
            let pc_before = self.pc;
            match self.step() {
                Some(exit) => {
                    if self.isa_mode == crate::IsaMode::Conformance {
                        match exit {
                            ExitReason::HostCall(_) => debug_assert_eq!(self.pc, pc_before),
                            ExitReason::Halt | ExitReason::Panic => self.pc = 0,
                            _ => {}
                        }
                    }
                    let gas_used = initial_gas - self.gas;
                    return (exit, gas_used);
                }
                None => continue,
            }
        }
    }
}

/// Signed modulo: sign of numerator, mod of absolute values (eq A.33).
fn smod_i64(a: i64, b: i64) -> i64 {
    if b == 0 {
        a
    } else {
        let sign = if a < 0 { -1i64 } else { 1 };
        sign * ((a.unsigned_abs() % b.unsigned_abs()) as i64)
    }
}

/// Compute the set of basic block start indices (ϖ, eq A.5).
/// Compact bitset: 1 bit per code byte, stored as `Vec<u64>`.
/// 64x more cache-friendly than `Vec<bool>` for the compilation hot loop.
pub struct BitSet {
    pub words: Vec<u64>,
}

impl BitSet {
    /// Create a bitset with `n` bits, all cleared.
    pub fn new(n: usize) -> Self {
        Self {
            words: vec![0u64; n.div_ceil(64)],
        }
    }

    /// Set bit at index `i`.
    #[inline(always)]
    pub fn set(&mut self, i: usize) {
        self.words[i / 64] |= 1u64 << (i % 64);
    }

    /// Test bit at index `i`.
    #[inline(always)]
    pub fn get(&self, i: usize) -> bool {
        (self.words[i / 64] >> (i % 64)) & 1 != 0
    }

    /// Build a rank index for O(1) rank queries.
    /// `rank_index[i]` = number of set bits in `words[0..i]` (prefix popcount sum).
    pub fn build_rank_index(&self) -> Vec<u32> {
        let mut idx = Vec::with_capacity(self.words.len());
        let mut sum = 0u32;
        for &w in &self.words {
            idx.push(sum);
            sum += w.count_ones();
        }
        idx
    }

    /// Count set bits before position `pos` using the pre-built rank index.
    /// This is the rank(pos) operation: number of 1-bits at positions 0..pos.
    #[inline(always)]
    pub fn rank(&self, rank_index: &[u32], pos: usize) -> usize {
        let word_idx = pos / 64;
        let bit_idx = pos % 64;
        let prefix = rank_index[word_idx] as usize;
        let mask = if bit_idx == 0 {
            0
        } else {
            (1u64 << bit_idx) - 1
        };
        prefix + (self.words[word_idx] & mask).count_ones() as usize
    }

    /// Collect all set bit positions into a Vec.
    pub fn collect_set_positions(&self) -> Vec<u32> {
        let mut positions = Vec::new();
        for (word_idx, &word) in self.words.iter().enumerate() {
            let mut bits = word;
            while bits != 0 {
                let bit = bits.trailing_zeros() as usize;
                positions.push((word_idx * 64 + bit) as u32);
                bits &= bits - 1;
            }
        }
        positions
    }
}

/// Compute basic block starts as a compact bitset + precomputed skip table.
/// The bitset is 64x smaller than `Vec<bool>`, improving L1 cache utilization
/// during the hot compilation loop (~1.75KB vs ~112KB for ecrecover).
/// Compute the skip (number of argument bytes) for instruction at `pc` by
/// scanning the bitmask for the next instruction start.
///
/// Uses u64 word-at-a-time scanning when possible. The bitmask has value 1
/// at instruction starts and 0 for argument bytes. We find the first 1 after
/// pc+1 by loading 8 bytes at a time and using trailing-zero count.
#[inline(always)]
pub fn skip_for_bitmask(bitmask: &[u8], pc: usize) -> usize {
    let start = pc + 1;
    let bm_len = bitmask.len();

    // Fast path: if we have at least 8 bytes, use a u64 scan.
    // Most instructions are 1-6 bytes, so the first word usually suffices.
    if start + 8 <= bm_len {
        // SAFETY: start + 8 <= bm_len ensures the 8-byte read is within the slice.
        let word = unsafe { core::ptr::read_unaligned(bitmask.as_ptr().add(start) as *const u64) };
        // Each byte is 0 or 1. A byte with value 1 means "instruction start".
        // We want the position of the first non-zero byte.
        if word != 0 {
            // The first non-zero byte position (little-endian: trailing zeros / 8)
            return (word.trailing_zeros() / 8) as usize;
        }
        // All 8 bytes are 0 — continue with scalar scan from start+8
        let mut j = 8;
        while j < 25 {
            let idx = start + j;
            if idx >= bm_len || bitmask[idx] == 1 {
                return j;
            }
            j += 1;
        }
        // No instruction start within 25 bytes: skip caps at 24 (GP F_skip).
        return 24;
    }

    // Scalar fallback for near end of bitmask.
    // No instruction start within 25 bytes → 24 (GP F_skip cap).
    let mut s = 24;
    for j in 0..25 {
        let idx = start + j;
        let bit = if idx < bm_len { bitmask[idx] } else { 1 };
        if bit == 1 {
            s = j;
            break;
        }
    }
    s
}

/// Compute basic block starts AND a precomputed skip table in a single pass.
/// `skip_table[pc]` = number of bytes to skip after the opcode byte (instruction size - 1).
/// Only valid at instruction-start PCs (where `bitmask[pc]` == 1).
///
/// Basic blocks per GP: {PC=0} ∪ {post-terminator PCs}. Branch/djump targets
/// must land on one of these (validated at execution); gas blocks use the
/// same boundaries (GP PR #508, grey PR #154).
pub fn compute_basic_block_starts_with_skips(code: &[u8], bitmask: &[u8]) -> (Vec<bool>, Vec<u8>) {
    let (starts, skip_table) = compute_bb_starts_inner(code, bitmask, crate::IsaMode::Conformance);
    (starts, skip_table)
}

pub fn compute_basic_block_starts(code: &[u8], bitmask: &[u8]) -> Vec<bool> {
    compute_bb_starts_inner(code, bitmask, crate::IsaMode::Conformance).0
}

pub(crate) fn compute_runtime_basic_block_starts(code: &[u8], bitmask: &[u8]) -> Vec<bool> {
    compute_bb_starts_inner(code, bitmask, crate::IsaMode::Jar).0
}

/// Compute gas block starts: {PC=0} ∪ {post-terminator PCs}.
///
/// Gas blocks coincide with GP basic blocks — one shared computation.
pub fn compute_gas_block_starts(code: &[u8], bitmask: &[u8]) -> Vec<bool> {
    compute_basic_block_starts(code, bitmask)
}

/// Map each externally enterable instruction counter to the gas block that
/// contains it. Argument-byte positions remain `u32::MAX`. The synthetic
/// end-of-code opcode-zero position is included at `code.len()`.
pub(crate) fn compute_gas_block_start_by_pc(
    code: &[u8],
    bitmask: &[u8],
    basic_block_starts: &[bool],
    isa_mode: crate::IsaMode,
) -> Vec<u32> {
    let mut result = vec![u32::MAX; code.len() + 1];
    let mut current = None;
    let mut last_terminates = true;
    let mut pc = 0usize;

    while pc < code.len() {
        if pc >= bitmask.len() || bitmask[pc] != 1 {
            pc += 1;
            continue;
        }
        if current.is_none() || basic_block_starts.get(pc).copied().unwrap_or(false) {
            current = Some(pc as u32);
        }
        if let Some(start) = current {
            result[pc] = start;
        }
        let opcode = opcode_for_mode(code[pc], isa_mode);
        last_terminates = opcode.is_some_and(|opcode| is_terminator_for_mode(opcode, isa_mode));
        pc += 1 + skip_for_bitmask(bitmask, pc);
    }

    let sentinel_start = if current.is_none() || last_terminates {
        code.len() as u32
    } else {
        current.unwrap_or(code.len() as u32)
    };
    result[code.len()] = sentinel_start;
    result
}

fn compute_bb_starts_inner(
    code: &[u8],
    bitmask: &[u8],
    isa_mode: crate::IsaMode,
) -> (Vec<bool>, Vec<u8>) {
    let len = code.len();
    if len == 0 {
        return (vec![], vec![]);
    }

    let mut starts = vec![false; len];
    let mut skip_table = vec![0u8; len];

    // Index 0 is always a basic block start if it's a valid instruction
    if !bitmask.is_empty() && bitmask[0] == 1 && opcode_for_mode(code[0], isa_mode).is_some() {
        starts[0] = true;
    }

    // Iterate only over instruction starts (skip non-instruction bytes).
    let mut i = 0;
    while i < len {
        if i >= bitmask.len() || bitmask[i] != 1 {
            i += 1;
            continue;
        }
        let Some(op) = opcode_for_mode(code[i], isa_mode) else {
            i += 1;
            continue;
        };

        let skip = {
            // No instruction start within 25 bytes → 24 (GP F_skip cap).
            let mut s = 24;
            for j in 0..25 {
                let idx = i + 1 + j;
                let bit = if idx < bitmask.len() { bitmask[idx] } else { 1 };
                if bit == 1 {
                    s = j;
                    break;
                }
            }
            s
        };
        skip_table[i] = skip as u8;

        if is_terminator_for_mode(op, isa_mode) {
            // The instruction after a terminator starts a new block
            let next = i + 1 + skip;
            if next < len && next < bitmask.len() && bitmask[next] == 1 {
                starts[next] = true;
            }
        }

        // Branch targets are deliberately NOT marked: GP basic blocks are
        // {0} ∪ post-terminator only, and branch/djump targets must land on
        // one of those or the instruction panics (GP eq A.17/A.18).

        i += 1 + skip; // advance to next instruction start
    }

    (starts, skip_table)
}

#[inline(always)]
fn opcode_for_mode(byte: u8, isa_mode: crate::IsaMode) -> Option<Opcode> {
    Opcode::from_byte_in_mode(byte, isa_mode)
}

#[inline(always)]
fn is_terminator_for_mode(opcode: Opcode, isa_mode: crate::IsaMode) -> bool {
    match isa_mode {
        crate::IsaMode::Jar => opcode.is_runtime_terminator(),
        crate::IsaMode::Conformance => opcode.is_terminator(),
    }
}

/// Compute each basic block's profile-selected pipeline gas cost.
///
/// Uses the same GasSimulator as the recompiler — single code path.
/// Gas is charged per basic block at block entry: max(max_done - 3, 1).
fn compute_block_gas_costs(
    code: &[u8],
    bitmask: &[u8],
    basic_block_starts: &[bool],
    mem_cycles: u8,
    isa_mode: crate::IsaMode,
) -> Vec<u32> {
    use crate::gas_cost::{fast_cost_from_raw, skip_distance};
    use crate::gas_sim::GasSimulator;

    let len = code.len();
    let mut costs = vec![0u32; len];
    let mut sim = GasSimulator::new_for_mode(isa_mode);
    let mut block_start: usize = 0;
    let mut in_block = false;
    let mut last_was_terminator = true;

    let mut pc = 0;
    while pc < len {
        if !basic_block_starts[pc] && !in_block {
            pc += 1;
            continue;
        }

        if basic_block_starts[pc] {
            if in_block {
                // Finalize previous block
                costs[block_start] = sim.flush_and_get_cost();
                sim.reset();
            }
            block_start = pc;
            in_block = true;
        }

        // Extract raw register nibbles. Out-of-bounds bytes (a truncated
        // instruction at end-of-code) read as 0 — matching the zeta
        // zero-extension the decoder and the JIT compile loop use, so the
        // gas model sees the same register operands that execution does.
        // (0xFF here would clamp to register 12 via reg_bit, a spurious
        // dependency that diverges from the recompiler.)
        let raw_opcode = code[pc];
        let opcode_byte = match (isa_mode, raw_opcode) {
            // Keep the retired manifest-only sbrk cost out of the standard
            // opcode table. It always traps after its containing block is
            // charged.
            (crate::IsaMode::Jar, 101) => 254,
            _ => opcode_for_mode(raw_opcode, isa_mode)
                .map(|opcode| opcode as u8)
                .unwrap_or(raw_opcode),
        };
        let raw_ra = if pc + 1 < len { code[pc + 1] & 0x0F } else { 0 };
        let raw_rb = if pc + 1 < len {
            (code[pc + 1] >> 4) & 0x0F
        } else {
            0
        };
        let raw_rd = if pc + 2 < len {
            match isa_mode {
                // A.5.13 clamps the complete encoded rD byte.
                crate::IsaMode::Conformance => code[pc + 2],
                crate::IsaMode::Jar => code[pc + 2] & 0x0f,
            }
        } else {
            0
        };

        let fc = fast_cost_from_raw(
            opcode_byte,
            raw_ra,
            raw_rb,
            raw_rd,
            pc as u32,
            code,
            bitmask,
            mem_cycles,
            isa_mode,
        );
        sim.feed(&fc);
        last_was_terminator = fc.is_terminator;

        // Advance to next instruction
        let skip = skip_distance(bitmask, pc);
        pc += 1 + skip;
    }

    // Finalize last block
    if in_block {
        if isa_mode == crate::IsaMode::Conformance && !last_was_terminator {
            // ζ is zero-extended, so falling off an unterminated program
            // decodes opcode 0 in the same basic block.
            sim.feed(&crate::gas_cost::FastCost {
                cycles: 2,
                decode_slots: 1,
                exec_unit: 0,
                src_mask: 0,
                dst_mask: 0,
                is_terminator: true,
                is_move_reg: false,
            });
        }
        costs[block_start] = sim.flush_and_get_cost();
    }

    costs
}

/// Extract flat operands (ra, rb, rd, imm1, imm2) from a decoded Args enum.
fn flatten_args(args: &Args) -> (u8, u8, u8, u64, u64) {
    match *args {
        Args::None => (0, 0, 0, 0, 0),
        Args::Imm { imm } => (0, 0, 0, imm, 0),
        Args::RegExtImm { ra, imm } => (ra as u8, 0, 0, imm, 0),
        Args::TwoImm { imm_x, imm_y } => (0, 0, 0, imm_x, imm_y),
        Args::Offset { offset } => (0, 0, 0, offset, 0),
        Args::RegImm { ra, imm } => (ra as u8, 0, 0, imm, 0),
        Args::RegTwoImm { ra, imm_x, imm_y } => (ra as u8, 0, 0, imm_x, imm_y),
        Args::RegImmOffset { ra, imm, offset } => (ra as u8, 0, 0, imm, offset),
        Args::TwoReg { rd, ra } => (ra as u8, 0, rd as u8, 0, 0),
        Args::TwoRegImm { ra, rb, imm } => (ra as u8, rb as u8, 0, imm, 0),
        Args::TwoRegOffset { ra, rb, offset } => (ra as u8, rb as u8, 0, offset, 0),
        Args::TwoRegTwoImm {
            ra,
            rb,
            imm_x,
            imm_y,
        } => (ra as u8, rb as u8, 0, imm_x, imm_y),
        Args::ThreeReg { ra, rb, rd } => (ra as u8, rb as u8, rd as u8, 0, 0),
    }
}

/// Pre-decode all instructions into a flat array for fast execution.
///
/// Returns (decoded_insts, pc_to_idx) where:
/// - decoded_insts[i] is the i-th instruction with pre-decoded opcode, args, and gas
/// - pc_to_idx[pc] maps a byte offset to instruction index (u32::MAX = invalid)
fn predecode_instructions(
    code: &[u8],
    bitmask: &[u8],
    basic_block_starts: &[bool],
    gas_block_starts: &[bool],
    block_gas_costs: &[u32],
    isa_mode: crate::IsaMode,
) -> (Vec<DecodedInst>, Vec<u32>) {
    let len = code.len();
    let mut insts = Vec::new();
    let mut pc_to_idx = vec![u32::MAX; len + 1]; // +1 for sentinel

    let skip_at = |i: usize| -> usize {
        for j in 0..25 {
            let idx = i + 1 + j;
            let bit = if idx < bitmask.len() { bitmask[idx] } else { 1 };
            if bit == 1 {
                return j;
            }
        }
        24
    };

    let mut pc = 0;
    while pc < len {
        #[allow(clippy::collapsible_if)] // let-chain requires Rust 2024
        if pc < bitmask.len() && bitmask[pc] == 1 {
            if opcode_for_mode(code[pc], isa_mode).is_none() {
                // Invalid opcode at an instruction start: emit a synthetic
                // panic instruction. Sequential advance in the fast loop must
                // execute (and panic at) this position — silently skipping it
                // would diverge from the step path and the JIT.
                let idx = insts.len() as u32;
                pc_to_idx[pc] = idx;
                let bb_gas_cost = if pc < gas_block_starts.len() && gas_block_starts[pc] {
                    block_gas_costs[pc]
                } else {
                    0
                };
                insts.push(DecodedInst {
                    opcode: Opcode::Invalid,
                    ra: 0,
                    rb: 0,
                    rd: 0,
                    imm1: 0,
                    imm2: 0,
                    pc: pc as u32,
                    next_pc: pc as u32 + 1,
                    next_idx: u32::MAX,
                    target_idx: u32::MAX,
                    bb_gas_cost,
                });
                pc += 1;
                continue;
            }
            if let Some(opcode) = opcode_for_mode(code[pc], isa_mode) {
                let skip = skip_at(pc);
                let next_pc = (pc + 1 + skip) as u32;
                let category = opcode.category();
                let args = args::decode_args(code, pc, skip, category);
                let bb_gas_cost = if pc < gas_block_starts.len() && gas_block_starts[pc] {
                    block_gas_costs[pc]
                } else {
                    0
                };

                // Extract flat operands from decoded args
                let (ra, rb, rd, imm1, imm2) = flatten_args(&args);

                let idx = insts.len() as u32;
                pc_to_idx[pc] = idx;
                insts.push(DecodedInst {
                    opcode,
                    ra,
                    rb,
                    rd,
                    imm1,
                    imm2,
                    pc: pc as u32,
                    next_pc,
                    next_idx: u32::MAX,   // resolved in second pass
                    target_idx: u32::MAX, // resolved in second pass
                    bb_gas_cost,
                });

                // When the skip caps at 24 without reaching an instruction
                // start, sequential flow lands mid-gap — GP panics there
                // (the bitmask bit at the executed position must be set).
                // Emit a panic stub so the fast loop's `idx + 1` advance
                // executes it instead of silently jumping to the next
                // decoded instruction.
                let np = next_pc as usize;
                if np < len && (np >= bitmask.len() || bitmask[np] != 1) {
                    let idx = insts.len() as u32;
                    pc_to_idx[np] = idx;
                    insts.push(DecodedInst {
                        opcode: Opcode::Invalid,
                        ra: 0,
                        rb: 0,
                        rd: 0,
                        imm1: 0,
                        imm2: 0,
                        pc: next_pc,
                        next_pc: next_pc + 1,
                        next_idx: u32::MAX,
                        target_idx: u32::MAX,
                        bb_gas_cost: 0,
                    });
                }

                pc = next_pc as usize;
                continue;
            }
        }
        pc += 1;
    }

    let sentinel_idx = insts.len() as u32;
    // Re-entry at pc == len (e.g. resuming after a host call whose next_pc
    // is the end of code) must land on the sentinel trap.
    pc_to_idx[len] = sentinel_idx;

    // Add a sentinel instruction at the end (trap) so sequential advance past
    // the last instruction doesn't index out of bounds.
    insts.push(DecodedInst {
        opcode: Opcode::Trap,
        ra: 0,
        rb: 0,
        rd: 0,
        imm1: 0,
        imm2: 0,
        pc: len as u32,
        next_pc: len as u32 + 1,
        next_idx: sentinel_idx, // self-loop (will trap anyway)
        target_idx: u32::MAX,
        bb_gas_cost: match isa_mode {
            crate::IsaMode::Jar => 1,
            crate::IsaMode::Conformance => {
                let starts_block = insts
                    .last()
                    .is_none_or(|inst| is_terminator_for_mode(inst.opcode, isa_mode));
                u32::from(starts_block) * 2
            }
        },
    });

    // Second pass: resolve next_idx and target_idx for all instructions.
    #[allow(clippy::needless_range_loop)]
    for i in 0..insts.len() {
        let inst = &insts[i];
        // Resolve next sequential instruction index
        let np = inst.next_pc as usize;
        let next_idx = if np < pc_to_idx.len() {
            let ni = pc_to_idx[np];
            if ni != u32::MAX { ni } else { sentinel_idx }
        } else {
            sentinel_idx
        };

        // Resolve branch/jump target index.
        // For Jump/BranchEq/Ne/LtU/LtS/GeU/GeS: target PC is in imm1.
        // For BranchEqImm/NeImm/.../GtSImm and LoadImmJump: target PC is in imm2.
        let target_idx = {
            let op = inst.opcode;
            let target_from_imm1 = matches!(
                op,
                Opcode::Jump
                    | Opcode::BranchEq
                    | Opcode::BranchNe
                    | Opcode::BranchLtU
                    | Opcode::BranchLtS
                    | Opcode::BranchGeU
                    | Opcode::BranchGeS
            );
            let target_from_imm2 = matches!(
                op,
                Opcode::LoadImmJump
                    | Opcode::BranchEqImm
                    | Opcode::BranchNeImm
                    | Opcode::BranchLtUImm
                    | Opcode::BranchLeUImm
                    | Opcode::BranchGeUImm
                    | Opcode::BranchGtUImm
                    | Opcode::BranchLtSImm
                    | Opcode::BranchLeSImm
                    | Opcode::BranchGeSImm
                    | Opcode::BranchGtSImm
            );
            let target_pc_opt = if target_from_imm1 {
                Some(inst.imm1 as usize)
            } else if target_from_imm2 {
                Some(inst.imm2 as usize)
            } else {
                None
            };
            if let Some(target_pc) = target_pc_opt {
                if target_pc < basic_block_starts.len()
                    && basic_block_starts[target_pc]
                    && target_pc < pc_to_idx.len()
                {
                    pc_to_idx[target_pc]
                } else {
                    u32::MAX
                }
            } else {
                u32::MAX
            }
        };

        // Can't borrow mutably with the immutable reference, so use indexing
        insts[i].next_idx = next_idx;
        insts[i].target_idx = target_idx;
    }

    (insts, pc_to_idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a VM with simple bitmask (every byte is instruction start).
    fn simple_vm(code: Vec<u8>, gas: Gas) -> Interpreter {
        Interpreter::new_simple(code, [0; 13], Vec::new(), gas)
    }

    #[test]
    fn test_trap_instruction() {
        let mut vm = simple_vm(vec![0], 100); // trap = opcode 0
        let (exit, _) = vm.run();
        assert_eq!(exit, ExitReason::Trap);
    }

    #[test]
    fn opcode_zero_exit_is_profile_specific_on_fast_and_stepping_paths() {
        for tracing in [false, true] {
            let mut jar = simple_vm(vec![0], 100);
            jar.tracing_enabled = tracing;
            assert_eq!(jar.run().0, ExitReason::Trap, "JAR tracing={tracing}");

            let mut standard = simple_vm(vec![0], 100);
            standard.set_isa_mode(crate::IsaMode::Conformance);
            standard.tracing_enabled = tracing;
            assert_eq!(
                standard.run().0,
                ExitReason::Panic,
                "v0.8 tracing={tracing}"
            );
        }
    }

    #[test]
    fn invalid_opcode_panics_in_both_profiles() {
        for isa_mode in [crate::IsaMode::Jar, crate::IsaMode::Conformance] {
            let mut vm = simple_vm(vec![u8::MAX], 100);
            vm.set_isa_mode(isa_mode);
            assert_eq!(vm.run().0, ExitReason::Panic, "{isa_mode:?}");
        }
    }

    #[test]
    fn private_ecall_exit_is_profile_specific() {
        let mut jar = simple_vm(vec![Opcode::Ecall as u8], 100);
        assert_eq!(jar.run().0, ExitReason::Ecall);

        let mut standard = simple_vm(vec![Opcode::Ecall as u8], 100);
        standard.set_isa_mode(crate::IsaMode::Conformance);
        assert_eq!(standard.run().0, ExitReason::Panic);
    }

    #[test]
    fn private_ecall_resume_opens_a_fresh_jar_gas_block() {
        // Ecall is a private JAR terminator.  Its successor therefore starts
        // a separately funded block even though execution first returns to
        // the capability kernel at the Ecall boundary.
        let code = vec![
            Opcode::Ecall as u8,
            Opcode::Unlikely as u8,
            Opcode::Trap as u8,
        ];
        let bitmask = vec![1, 1, 1];

        // Exercise both the predecoded fast loop and the step-driven tracing
        // loop: both have an early Ecall return before common terminator
        // bookkeeping.
        for tracing in [false, true] {
            let mut vm = Interpreter::new(
                code.clone(),
                bitmask.clone(),
                vec![],
                [0; 13],
                vec![],
                1_000,
                crate::gas_cost::DEFAULT_MEM_CYCLES,
            );
            vm.tracing_enabled = tracing;
            let first_cost = u64::from(vm.block_gas_costs[0]);
            let successor_cost = u64::from(vm.block_gas_costs[1]);

            assert_eq!(vm.run(), (ExitReason::Ecall, first_cost));
            assert_eq!(vm.pc, 1);
            assert!(!vm.gas_charged, "tracing={tracing}");
            assert!(vm.need_gas_charge, "tracing={tracing}");

            assert_eq!(vm.run(), (ExitReason::Trap, successor_cost));
            assert_eq!(vm.gas, 1_000 - first_cost - successor_cost);
        }
    }

    #[test]
    fn test_fallthrough_instruction() {
        // fallthrough (1) then trap (0)
        let mut vm = simple_vm(vec![1, 0], 100);
        let (exit, gas_used) = vm.run();
        assert_eq!(exit, ExitReason::Trap);
        assert_eq!(gas_used, 2); // 1 for fallthrough + 1 for trap
    }

    #[test]
    fn test_out_of_gas() {
        // Many fallthroughs
        let mut vm = simple_vm(vec![1; 100], 5);
        let (exit, gas_used) = vm.run();
        assert_eq!(exit, ExitReason::OutOfGas);
        assert_eq!(gas_used, 5);
    }

    #[test]
    fn test_empty_program() {
        // PC=0 is already the end of code. The synthetic opcode 0 has the
        // same profile-specific classification on both interpreter paths.
        for tracing in [false, true] {
            let mut jar = simple_vm(vec![], 100);
            jar.tracing_enabled = tracing;
            assert_eq!(jar.run().0, ExitReason::Trap, "JAR tracing={tracing}");

            let mut standard = simple_vm(vec![], 100);
            standard.set_isa_mode(crate::IsaMode::Conformance);
            standard.tracing_enabled = tracing;
            assert_eq!(
                standard.run().0,
                ExitReason::Panic,
                "v0.8 tracing={tracing}"
            );
        }
    }

    #[test]
    fn test_load_imm() {
        // load_imm (51), reg_byte (reg 0), immediate 42 (4 bytes LE)
        // Bitmask: [1, 0, 0, 0, 0, 0, 1] for the load_imm (6 bytes) + trap
        let code = vec![51, 0x00, 42, 0, 0, 0, 0]; // opcode + reg + 4-byte imm + trap
        let bitmask = vec![1, 0, 0, 0, 0, 0, 1];
        let mut vm = Interpreter::new(
            code,
            bitmask,
            vec![],
            [0; 13],
            Vec::new(),
            100,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        );
        vm.step();
        assert_eq!(vm.registers[0], 42);
    }

    #[test]
    fn test_add_imm_64() {
        // add_imm_64 (149), reg_byte (rA=0, rB=1 => 0x10), immediate 10
        let code = vec![149, 0x10, 10, 0, 0, 0, 0]; // trap at end
        let bitmask = vec![1, 0, 0, 0, 0, 0, 1];
        let mut regs = [0u64; 13];
        regs[1] = 32;
        let mut vm = Interpreter::new(
            code,
            bitmask,
            vec![],
            regs,
            Vec::new(),
            100,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        );
        vm.step();
        assert_eq!(vm.registers[0], 42);
    }

    #[test]
    fn test_add64_three_reg() {
        // add_64 (200), reg_byte (rA=0, rB=1 => 0x10), rD=2
        let code = vec![200, 0x10, 2, 0]; // trap at end
        let bitmask = vec![1, 0, 0, 1];
        let mut regs = [0u64; 13];
        regs[0] = 100;
        regs[1] = 200;
        let mut vm = Interpreter::new(
            code,
            bitmask,
            vec![],
            regs,
            Vec::new(),
            100,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        );
        vm.step();
        assert_eq!(vm.registers[2], 300);
    }

    #[test]
    fn test_sub64() {
        let code = vec![201, 0x10, 2, 0];
        let bitmask = vec![1, 0, 0, 1];
        let mut regs = [0u64; 13];
        regs[0] = 300;
        regs[1] = 100;
        let mut vm = Interpreter::new(
            code,
            bitmask,
            vec![],
            regs,
            Vec::new(),
            100,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        );
        vm.step();
        assert_eq!(vm.registers[2], 200);
    }

    #[test]
    fn test_and_xor_or() {
        // AND(210): 0xFF00 & 0x0FF0 = 0x0F00
        let code = vec![210, 0x10, 2, 0];
        let bitmask = vec![1, 0, 0, 1];
        let mut regs = [0u64; 13];
        regs[0] = 0xFF00;
        regs[1] = 0x0FF0;
        let mut vm = Interpreter::new(
            code,
            bitmask,
            vec![],
            regs,
            Vec::new(),
            100,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        );
        vm.step();
        assert_eq!(vm.registers[2], 0x0F00);
    }

    #[test]
    fn test_set_lt_u() {
        let code = vec![216, 0x10, 2, 0];
        let bitmask = vec![1, 0, 0, 1];
        let mut regs = [0u64; 13];
        regs[0] = 5;
        regs[1] = 10;
        let mut vm = Interpreter::new(
            code,
            bitmask,
            vec![],
            regs,
            Vec::new(),
            100,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        );
        vm.step();
        assert_eq!(vm.registers[2], 1);
    }

    #[test]
    fn test_ecalli() {
        // ecalli (10), immediate = 7 (1 byte)
        let code = vec![10, 7];
        let bitmask = vec![1, 0];
        let mut vm = Interpreter::new(
            code,
            bitmask,
            vec![],
            [0; 13],
            Vec::new(),
            100,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        );
        let exit = vm.step();
        assert_eq!(exit, Some(ExitReason::HostCall(7)));
    }

    #[test]
    fn test_move_reg() {
        let code = vec![100, 0x10, 0]; // move_reg rD=0, rA=1, then trap
        let bitmask = vec![1, 0, 1];
        let mut regs = [0u64; 13];
        regs[1] = 42;
        let mut vm = Interpreter::new(
            code,
            bitmask,
            vec![],
            regs,
            Vec::new(),
            100,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        );
        vm.step();
        assert_eq!(vm.registers[0], 42);
    }

    #[test]
    fn test_count_set_bits() {
        let code = vec![102, 0x10, 0]; // count_set_bits_64 rD=0, rA=1
        let bitmask = vec![1, 0, 1];
        let mut regs = [0u64; 13];
        regs[1] = 0xFF; // 8 bits set
        let mut vm = Interpreter::new(
            code,
            bitmask,
            vec![],
            regs,
            Vec::new(),
            100,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        );
        vm.step();
        assert_eq!(vm.registers[0], 8);
    }

    #[test]
    fn test_div_u64_by_zero() {
        let code = vec![203, 0x10, 2, 0];
        let bitmask = vec![1, 0, 0, 1];
        let mut regs = [0u64; 13];
        regs[0] = 100;
        regs[1] = 0; // divide by zero
        let mut vm = Interpreter::new(
            code,
            bitmask,
            vec![],
            regs,
            Vec::new(),
            100,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        );
        vm.step();
        assert_eq!(vm.registers[2], u64::MAX);
    }

    #[test]
    fn test_sign_extend_8() {
        let code = vec![108, 0x10, 0]; // sign_extend_8 rD=0, rA=1
        let bitmask = vec![1, 0, 1];
        let mut regs = [0u64; 13];
        regs[1] = 0x80; // -128 as i8
        let mut vm = Interpreter::new(
            code,
            bitmask,
            vec![],
            regs,
            Vec::new(),
            100,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        );
        vm.step();
        assert_eq!(vm.registers[0] as i64, -128);
    }

    #[test]
    fn test_reverse_bytes() {
        // Capability manifests retain the frozen pre-v0.8 opcode 111.
        let code = vec![111, 0x10, 0]; // reverse_bytes rD=0, rA=1
        let bitmask = vec![1, 0, 1];
        let mut regs = [0u64; 13];
        regs[1] = 0x0123456789ABCDEF;
        let mut vm = Interpreter::new(
            code,
            bitmask,
            vec![],
            regs,
            Vec::new(),
            100,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        );
        vm.step();
        assert_eq!(vm.registers[0], 0xEFCDAB8967452301);
    }

    #[test]
    fn standard_unary_opcodes_use_the_v080_table() {
        let run = |opcode, value| {
            let code = vec![opcode, 0x10, 0];
            let bitmask = vec![1, 0, 1];
            let mut regs = [0u64; 13];
            regs[1] = value;
            let mut vm = Interpreter::with_memory_and_mode(
                code,
                bitmask,
                vec![],
                regs,
                Memory::flat(Vec::new()),
                100,
                crate::gas_cost::DEFAULT_MEM_CYCLES,
                crate::IsaMode::Conformance,
            );
            vm.step();
            vm.registers[0]
        };

        assert_eq!(run(101, 0xff), 8);
        assert_eq!(run(110, 0x0123_4567_89ab_cdef), 0xefcd_ab89_6745_2301);
    }

    // ========================================================================
    // Basic-block strictness tests (GP eq A.17/A.18; supersedes issue #155)
    // ========================================================================
    //
    // Basic blocks (= gas blocks) are {PC=0} ∪ {post-terminator PCs}. Branch
    // and djump targets must land on a block start — a taken branch to a
    // mid-block target panics, and never affects gas block boundaries.

    /// Build a program with a branch target that is NOT post-terminator.
    ///
    /// Layout (bitmask all-1s, so skip=0 for each byte):
    ///   PC 0: Fallthrough (1)   — terminator, so PC 1 is a gas block start
    ///   PC 1: Fallthrough (1)   — terminator, so PC 2 is a gas block start
    ///   PC 2: Fallthrough (1)   — terminator, so PC 3 is a gas block start
    ///   PC 3: MoveReg (100)     — NOT a terminator
    ///   PC 4: Jump (40)         — terminator, offset = 0 bytes (skip=0)
    ///                             target = PC 4 + 0 = PC 4 (self-loop, but
    ///                             compute_bb_starts_inner reads code[i+1..i+5])
    ///
    /// For a cleaner branch target, use explicit bitmask to give Jump a 4-byte
    /// offset field pointing at a non-post-terminator PC.
    fn branch_target_mid_block_program() -> (Vec<u8>, Vec<u8>) {
        // Layout:
        //   PC 0: Fallthrough (1)  — terminator
        //   PC 1: MoveReg (100)    — NOT terminator, bitmask [1,0]
        //   PC 3: MoveReg (100)    — NOT terminator, bitmask [1,0]
        //   PC 5: Jump (40)        — terminator, offset = 4 bytes LE
        //                            bitmask [1,0,0,0,0]
        //                            offset = -2 as i32 → target = 5 + (-2) = 3
        //   PC 10: Trap (0)        — catches fallthrough
        //
        // Gas block starts (spec-correct): PC 0, 1 (post-Fallthrough), 10 (post-Jump)
        // Branch targets (validation):     PC 3 (Jump target)
        // basic_block_starts (old):        PC 0, 1, 3, 10
        // gas_block_starts (new):          PC 0, 1, 10
        let code = vec![
            1, // PC 0: Fallthrough
            100, 0x10, // PC 1: MoveReg rD=0, rA=1 (2 bytes)
            100, 0x10, // PC 3: MoveReg rD=0, rA=1 (2 bytes)
            // PC 5: Jump, offset = -2 as i32 LE = [0xFE, 0xFF, 0xFF, 0xFF]
            40, 0xFE, 0xFF, 0xFF, 0xFF, 0, // PC 10: Trap
        ];
        let bitmask = vec![
            1, // PC 0: Fallthrough
            1, 0, // PC 1-2: MoveReg (skip=1)
            1, 0, // PC 3-4: MoveReg (skip=1)
            1, 0, 0, 0, 0, // PC 5-9: Jump (skip=4)
            1, // PC 10: Trap
        ];
        (code, bitmask)
    }

    #[test]
    fn test_block_starts_exclude_branch_targets() {
        let (code, bitmask) = branch_target_mid_block_program();
        let bb_starts = compute_basic_block_starts(&code, &bitmask);

        // Strict GP set: {0} ∪ post-terminator. The Jump target at PC 3 is
        // mid-block and must NOT be a valid landing site.
        assert!(bb_starts[0], "PC 0 should be a basic block start");
        assert!(
            bb_starts[1],
            "PC 1 should be a basic block start (post-Fallthrough)"
        );
        assert!(
            !bb_starts[3],
            "PC 3 must NOT be a basic block start (mid-block branch target)"
        );
        assert!(
            bb_starts[10],
            "PC 10 should be a basic block start (post-Jump)"
        );
    }

    #[test]
    fn graypaper_markers_and_host_calls_do_not_split_basic_blocks() {
        // unlikely; ecalli(7); load_imm r0, 1; trap
        let code = vec![2, 10, 7, 51, 0, 1, 0];
        let bitmask = vec![1, 1, 0, 1, 0, 0, 1];
        let starts = compute_basic_block_starts(&code, &bitmask);

        assert!(starts[0]);
        assert!(!starts[1], "unlikely is not in Gray Paper set T");
        assert!(!starts[3], "ecalli is not in Gray Paper set T");
        assert!(
            !starts[6],
            "the trap itself ends, rather than starts, a block"
        );
    }

    #[test]
    fn runtime_opcode_three_keeps_its_private_resume_boundary() {
        let code = vec![Opcode::Ecall as u8, Opcode::Trap as u8];
        let bitmask = vec![1, 1];

        let standard = compute_basic_block_starts(&code, &bitmask);
        assert!(!standard[0], "opcode 3 is outside standard opcode set U");

        let runtime = compute_runtime_basic_block_starts(&code, &bitmask);
        assert!(runtime[0]);
        assert!(runtime[1], "runtime ecall requires a resumable boundary");
    }

    #[test]
    fn test_block_gas_costs_only_at_gas_block_starts() {
        let (code, bitmask) = branch_target_mid_block_program();
        let gas_starts = compute_gas_block_starts(&code, &bitmask);
        let costs = compute_block_gas_costs(
            &code,
            &bitmask,
            &gas_starts,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
            crate::IsaMode::Conformance,
        );

        // Gas costs should be nonzero only at gas block starts
        assert!(
            costs[0] > 0,
            "PC 0 (gas block start) should have nonzero cost"
        );
        assert!(
            costs[1] > 0,
            "PC 1 (gas block start) should have nonzero cost"
        );
        assert_eq!(
            costs[3], 0,
            "PC 3 (branch target, NOT gas start) should have zero cost"
        );
        assert!(
            costs[10] > 0,
            "PC 10 (gas block start) should have nonzero cost"
        );
    }

    #[test]
    fn test_step_and_run_same_gas_on_linear_program() {
        // Verify that step() and run() consume the same gas on a simple
        // linear program. This is a generic parity check between the two
        // execution paths (step uses need_gas_charge + block_gas_costs,
        // run uses predecoded bb_gas_cost).
        // Layout:
        //   PC 0: Fallthrough (1)  — terminator
        //   PC 1: MoveReg (100)    — NOT terminator
        //   PC 3: Trap (0)
        let code = vec![1, 100, 0x10, 0];
        let bitmask = vec![1, 1, 0, 1];

        // Run via step()
        let mut vm_step = Interpreter::new(
            code.clone(),
            bitmask.clone(),
            vec![],
            [0; 13],
            Vec::new(),
            1000,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        );
        let initial_gas = vm_step.gas;
        loop {
            if vm_step.step().is_some() {
                break;
            }
        }
        let gas_used_step = initial_gas - vm_step.gas;

        // Run via run()
        let mut vm_run = Interpreter::new(
            code,
            bitmask,
            vec![],
            [0; 13],
            Vec::new(),
            1000,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        );
        let (_, gas_used_run) = vm_run.run();

        assert_eq!(
            gas_used_step, gas_used_run,
            "step() and run() must consume the same gas"
        );
    }

    #[test]
    fn observed_run_is_semantically_identical_and_reports_each_step() {
        // Layout:
        //   PC 0: Fallthrough (1)  — terminator
        //   PC 1: MoveReg (100)    — NOT terminator
        //   PC 3: Trap (0)
        let code = vec![1, 100, 0x10, 0];
        let bitmask = vec![1, 1, 0, 1];
        let mut observed = Interpreter::new(
            code,
            bitmask,
            vec![],
            [0; 13],
            Vec::new(),
            1000,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        );
        observed.registers[1] = 42;
        let mut baseline = observed.clone();

        let expected = baseline.run();
        let mut pcs = Vec::new();
        let mut saw_exit = false;
        let actual = observed.run_observed(|event| {
            pcs.push(event.pc_before);
            assert_eq!(
                event.opcode_byte,
                event.machine_after.code[event.pc_before as usize]
            );
            assert!(event.machine_after.gas <= event.gas_before);
            saw_exit |= event.exit.is_some();
        });

        assert_eq!(actual, expected);
        assert_eq!(observed.pc, baseline.pc);
        assert_eq!(observed.registers, baseline.registers);
        assert_eq!(observed.gas, baseline.gas);
        assert_eq!(observed.flat_mem(), baseline.flat_mem());
        assert_eq!(pcs, vec![0, 1, 3]);
        assert!(saw_exit);
    }

    /// Perf smoke for the flat-memory hot path: a 4-instruction loop with
    /// two 8-byte memory operations per iteration. Ignored by default; run
    /// with `cargo test -p vos_pvm --release -- --ignored perf_smoke --nocapture`
    /// and compare the reported ns/inst before and after touching the
    /// memory accessors (commit f024c184 context: flat throughput matters).
    #[cfg(feature = "std")]
    #[test]
    #[ignore = "perf smoke: run explicitly in release mode"]
    fn perf_smoke_flat_memory_loop() {
        let iters: u64 = 4_000_000;
        // pc 0: add_imm_64  φ2 = φ2 + 1                (3 bytes)
        // pc 3: store_ind_u64 [φ3+0], φ2               (2 bytes)
        // pc 5: load_ind_u64  φ4, [φ3+0]               (2 bytes)
        // pc 7: branch_ne_imm φ2, iters, → pc 0        (7 bytes)
        // pc 14: trap
        let mut code = vec![149, 2 + 16 * 2, 1];
        code.extend_from_slice(&[123, 2 + 16 * 3]);
        code.extend_from_slice(&[130, 4 + 16 * 3]);
        code.push(82);
        code.push(2 + 16 * 4); // ra = 2, lx = 4
        code.extend_from_slice(&(iters as u32).to_le_bytes());
        code.push((-7i8) as u8); // offset → pc 0
        code.push(0);
        let bitmask = vec![1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1];

        let mut vm = Interpreter::new(
            code,
            bitmask,
            vec![],
            [0; 13],
            vec![0u8; 4096],
            u64::MAX / 2,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        );
        let start = std::time::Instant::now();
        let (exit, gas_used) = vm.run();
        let elapsed = start.elapsed();
        assert_eq!(exit, ExitReason::Trap);
        let insts = 4 * iters + 1;
        std::println!(
            "flat perf smoke: {insts} insts in {elapsed:?} ({:.2} ns/inst, gas {gas_used})",
            elapsed.as_nanos() as f64 / insts as f64
        );
    }

    #[test]
    fn test_branch_to_mid_block_target_panics() {
        // GP eq A.17: a taken branch whose target is not a basic-block start
        // panics. PC 3 is a mid-block Jump target in this program.
        let (code, bitmask) = branch_target_mid_block_program();

        let mut vm = Interpreter::new(
            code,
            bitmask,
            vec![],
            [0; 13],
            Vec::new(),
            1000,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        );
        assert!(
            !vm.is_basic_block_start(3),
            "mid-block branch target at PC 3 must not be a valid landing site"
        );
        // Gas cost at PC 3 stays zero (not a block start).
        assert_eq!(vm.block_gas_costs[3], 0);

        // Executing through the Jump at PC 5 (target PC 3) must panic.
        let exit = vm.run();
        assert_eq!(exit.0, ExitReason::Panic, "jump to mid-block must panic");
    }

    // --- GasModel::PerInstruction (GP 0.7.2) ---
    //
    // The oracle is the Lean spec's per-instruction branch
    // (spec/Jar/JAVM/Interpreter.lean, `run`): check gas before executing,
    // charge a flat 1, and charge the exiting instruction too. These tests
    // pin the Rust interpreter to that model on both execution paths.

    /// Build a per-instruction-gas VM over explicit code/bitmask.
    fn pi_vm(code: Vec<u8>, bitmask: Vec<u8>, gas: Gas) -> Interpreter {
        let mut vm = Interpreter::new(
            code,
            bitmask,
            vec![],
            [0; 13],
            Vec::new(),
            gas,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        );
        vm.set_gas_model(crate::GasModel::PerInstruction);
        vm
    }

    #[test]
    fn per_instruction_charges_flat_one_per_instruction() {
        // fallthrough; move_reg φ0←φ1; trap — 3 instructions, 3 gas.
        let code = vec![1, 100, 0x10, 0];
        let bitmask = vec![1, 1, 0, 1];
        let mut vm = pi_vm(code, bitmask, 1000);
        let (exit, gas_used) = vm.run();
        assert_eq!(exit, ExitReason::Trap);
        assert_eq!(gas_used, 3, "3 instructions cost exactly 3 gas");
    }

    #[test]
    fn per_instruction_step_and_run_agree_on_a_loop() {
        // pc 0: load_imm φ2 = 3; pc 3: fallthrough; pc 4: add_imm_64 φ2 += -1;
        // pc 7: branch_ne_imm φ2 ≠ 0 → pc 4 (a post-terminator block start);
        // pc 10: trap. Executes 2 + 3·2 + 1 = 9 instructions.
        let code = vec![51, 2, 3, 1, 149, 0x22, 0xFF, 82, 2, 0xFD, 0];
        let bitmask = vec![1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1];

        let mut vm_run = pi_vm(code.clone(), bitmask.clone(), 1000);
        let (exit, gas_used) = vm_run.run();
        assert_eq!(exit, ExitReason::Trap);
        assert_eq!(gas_used, 9, "9 executed instructions cost 9 gas");
        assert_eq!(vm_run.registers[2], 0);

        let mut vm_step = pi_vm(code, bitmask, 1000);
        let exit_step = loop {
            if let Some(e) = vm_step.step() {
                break e;
            }
        };
        assert_eq!(exit_step, ExitReason::Trap);
        assert_eq!(1000 - vm_step.gas, 9, "step() charges identically");
        assert_eq!(vm_step.registers, vm_run.registers);
    }

    #[test]
    fn per_instruction_out_of_gas_precedes_execution() {
        // Lean: `if gas <= 0 then outOfGas` runs before executeStep, so a
        // budget of 5 executes exactly 5 fallthroughs and the 6th
        // instruction never runs; remaining gas is untouched (0).
        let mut vm = pi_vm(vec![1; 100], vec![1; 100], 5);
        let (exit, gas_used) = vm.run();
        assert_eq!(exit, ExitReason::OutOfGas);
        assert_eq!(gas_used, 5);
        assert_eq!(vm.gas, 0, "OOG leaves the remaining gas untouched");

        // A zero budget is out of gas before anything executes at all.
        let mut vm = pi_vm(vec![0], vec![1], 0);
        let (exit, gas_used) = vm.run();
        assert_eq!(exit, ExitReason::OutOfGas);
        assert_eq!(gas_used, 0, "nothing executed, nothing charged");

        // Same on the stepping path.
        let mut vm = pi_vm(vec![0], vec![1], 0);
        assert_eq!(vm.step(), Some(ExitReason::OutOfGas));
        assert_eq!(vm.gas, 0);
    }

    #[test]
    fn per_instruction_charges_the_exiting_instruction() {
        // The ecalli that exits with HostCall is itself charged (Lean
        // carries gas' = gas - 1 into every exit result).
        let mut vm = pi_vm(vec![10, 7], vec![1, 0], 5);
        let (exit, gas_used) = vm.run();
        assert_eq!(exit, ExitReason::HostCall(7));
        assert_eq!(gas_used, 1);

        // So is a faulting store: store_imm_u8 to unmapped 0x5000.
        // TwoImm encoding: opcode 30, ζ[1]=lx=2, imm_x = 0x5000, imm_y = 0.
        let code = vec![30, 2, 0x00, 0x50];
        let mut vm = pi_vm(code, vec![1, 0, 0, 0], 5);
        let (exit, gas_used) = vm.run();
        assert_eq!(exit, ExitReason::PageFault(0x5000));
        assert_eq!(gas_used, 1, "the faulting instruction is charged");
    }

    #[test]
    fn per_instruction_fall_off_end_is_a_charged_trap() {
        // GP: the bitmask beyond the code is all set and ζ zero-extends, so
        // sequential flow past the last instruction executes opcode 0 (trap)
        // and is charged for it (Lean bitmaskGet/zeta; the fast path's
        // end-of-code sentinel).
        let mut vm = pi_vm(vec![1], vec![1], 10);
        let (exit, gas_used) = vm.run();
        assert_eq!(exit, ExitReason::Trap);
        assert_eq!(gas_used, 2, "fallthrough (1) + implicit trailing trap (1)");
    }

    #[test]
    fn per_instruction_invalid_positions_charge_after_the_gas_check() {
        // An invalid opcode at an instruction start panics but is charged
        // (Lean: executeStep panics after the decrement)…
        let mut vm = pi_vm(vec![77], vec![1], 5);
        let (exit, gas_used) = vm.run();
        assert_eq!(exit, ExitReason::Panic);
        assert_eq!(gas_used, 1);

        // …unless the VM is already out of gas: the gas check precedes
        // opcode validation, so OOG wins over the panic.
        let mut vm = pi_vm(vec![77], vec![1], 0);
        let (exit, gas_used) = vm.run();
        assert_eq!(exit, ExitReason::OutOfGas);
        assert_eq!(gas_used, 0);

        // A mid-instruction starting PC behaves the same way: panic for 1
        // gas when funded, OOG when not.
        let code = vec![51, 0, 42, 0, 0, 0, 0];
        let bitmask = vec![1, 0, 0, 0, 0, 0, 1];
        let mut vm = pi_vm(code.clone(), bitmask.clone(), 5);
        vm.set_pc(2);
        let (exit, gas_used) = vm.run();
        assert_eq!(exit, ExitReason::Panic);
        assert_eq!(gas_used, 1);

        let mut vm = pi_vm(code, bitmask, 0);
        vm.set_pc(2);
        let (exit, gas_used) = vm.run();
        assert_eq!(exit, ExitReason::OutOfGas);
        assert_eq!(gas_used, 0);
    }

    #[test]
    fn set_gas_model_relabels_and_restores_block_costs() {
        // The pre-decoded gas labels are keyed on the model: switching to
        // per-instruction and back must reproduce the block model's charges
        // exactly (the frozen jar1 behaviour).
        let code = vec![51, 2, 3, 1, 149, 0x22, 0xFF, 82, 2, 0xFD, 0];
        let bitmask = vec![1u8, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1];

        let mut pristine = Interpreter::new(
            code.clone(),
            bitmask.clone(),
            vec![],
            [0; 13],
            Vec::new(),
            1000,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        );
        let (block_exit, block_gas) = pristine.run();

        let mut toggled = Interpreter::new(
            code,
            bitmask,
            vec![],
            [0; 13],
            Vec::new(),
            1000,
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        );
        toggled.set_gas_model(crate::GasModel::PerInstruction);
        assert_eq!(toggled.gas_model(), crate::GasModel::PerInstruction);
        toggled.set_gas_model(crate::GasModel::BlockPipeline);
        let (toggle_exit, toggle_gas) = toggled.run();

        assert_eq!(block_exit, toggle_exit);
        assert_eq!(
            block_gas, toggle_gas,
            "restoring the block model restores its exact charges"
        );
        assert_ne!(
            block_gas, 9,
            "the two models are genuinely different cost functions"
        );
    }
}
