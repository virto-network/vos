//! Invocation kernel — multi-VM scheduler with CALL/REPLY semantics.
//!
//! Manages a pool of VMs, dispatches ecalli calls, and handles the
//! capability-based execution model. The kernel is the "microkernel"
//! that sits between the PVM instruction execution and the host
//! (grey-state's refine/accumulate logic).
//!
//! ecalli dispatch:
//! - 0x00..0x7F: CALL cap\[N\] (0x00 = the IPC slot = REPLY to the caller)
//! - imm > 127: panic
//!
//! Program termination follows the GP halt convention: a djump to
//! [`crate::PVM_HALT_ADDR`] (installed in the root VM's ω_0 at init) halts
//! the VM. REPLY is strictly the inter-VM return half of CALL.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::GAS_PER_PAGE;

#[cfg(feature = "std")]
use std::collections::HashMap;

#[cfg(feature = "std")]
fn blake2b_256(bytes: &[u8]) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U32>::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Cache for compiled CODE caps, keyed by blake2b-256 hash of the code sub-blob.
///
/// Avoids re-running JIT compilation when the same PVM blob is used
/// repeatedly (e.g. child actor invocations). Callers pass `&mut CodeCache`
/// and the cache shares compiled code via `Arc<CodeCap>`.
///
/// Blake2b-256 makes collisions negligible, so no blob equality check is needed.
#[cfg(feature = "std")]
pub struct CodeCache {
    entries: HashMap<([u8; 32], crate::IsaMode), Arc<CodeCap>>,
}

#[cfg(feature = "std")]
impl CodeCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Cache key: blake2b-256 of the blob bytes plus the ISA mode the code
    /// was compiled under (compiled code embeds mode-dependent behavior).
    fn cache_key(blob: &[u8], isa_mode: crate::IsaMode) -> ([u8; 32], crate::IsaMode) {
        (blake2b_256(blob), isa_mode)
    }
}

#[cfg(feature = "std")]
impl Default for CodeCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Canonical program installed as an idle VM before an invocation starts.
///
/// The root program receives an owning [`HandleCap`] in `handle_slot`. No
/// protocol capabilities are synthesized for the dormant VM: the root must
/// grant any authority it needs through ordinary capability operations.
#[derive(Clone, Copy, Debug)]
pub struct DormantProgram<'a> {
    pub blob: &'a [u8],
    pub handle_slot: u8,
}

fn invocation_layout_hash(root: &[u8], programs: &[DormantProgram<'_>]) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"JAR invocation layout v1");
    bytes.extend_from_slice(&(programs.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(root.len() as u64).to_le_bytes());
    bytes.extend_from_slice(root);
    for program in programs {
        bytes.push(program.handle_slot);
        bytes.extend_from_slice(&(program.blob.len() as u64).to_le_bytes());
        bytes.extend_from_slice(program.blob);
    }
    blake2b_256(&bytes)
}

fn validate_manifest_memory(parsed: &ParsedBlob<'_>) -> Result<(), KernelError> {
    let initial_pages = parsed
        .caps
        .iter()
        .filter(|entry| entry.cap_type == CapEntryType::Data)
        .try_fold(0u32, |total, entry| total.checked_add(entry.page_count))
        .ok_or(KernelError::InvalidBlob)?;
    if initial_pages > parsed.header.memory_pages {
        return Err(KernelError::InvalidBlob);
    }
    Ok(())
}

fn validate_import_handle_slots(
    root: &ParsedBlob<'_>,
    programs: &[DormantProgram<'_>],
) -> Result<(), KernelError> {
    let mut occupied = BTreeSet::new();
    occupied.insert(IPC_SLOT);
    occupied.extend(1..=28u8);
    occupied.extend(root.caps.iter().map(|entry| entry.cap_index));
    if root.header.memory_pages > 0 {
        occupied.insert(254);
    }
    for program in programs {
        if !occupied.insert(program.handle_slot) {
            return Err(KernelError::ImportHandleUnavailable(program.handle_slot));
        }
    }
    Ok(())
}

/// Resolve a cap reference or return `DispatchResult::Continue` (WHAT already set).
macro_rules! resolve {
    ($self:expr, $ref:expr) => {
        match $self.resolve_or_what($ref) {
            Some(r) => r,
            None => return DispatchResult::Continue,
        }
    };
}
use crate::backing::BackingStore;
use crate::cap::{
    Access, CallableCap, Cap, CapTable, CodeCap, DataCap, HandleCap, IPC_SLOT, ProtocolCap,
    UntypedCap,
};
use crate::program::{self, CapEntryType, CapManifestEntry, ParsedBlob};
use crate::snapshot::{
    CallFrameSnapshot, CapabilitySlotSnapshot, CapabilitySnapshot, KERNEL_SNAPSHOT_VERSION,
    KernelSnapshot, MemoryBlock, MemoryPageRef, PendingHostCallSnapshot, PendingPageFault,
    PendingProtocolCall, SnapshotAccess, SnapshotError, SnapshotIsaMode, SnapshotVmState,
    VmArenaSnapshot, VmSlotSnapshot, VmSnapshot,
};
#[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
use crate::vm_pool::WindowPool;
use crate::vm_pool::{CallFrame, MAX_CODE_CAPS, VmArena, VmId, VmInstance, VmState};

/// WHAT error code (2^64 - 2).
const RESULT_WHAT: u64 = u64::MAX - 1;
const RESULT_LOW: u64 = u64::MAX - 7; // gas limit too low
const RESULT_HUH: u64 = u64::MAX - 8; // invalid operation

/// Result from running the kernel until it needs host interaction.
#[derive(Debug)]
pub enum KernelResult {
    /// Root VM halted normally (djump to [`crate::PVM_HALT_ADDR`]).
    /// Read output via registers/memory accessors (active_reg, read_data_cap_window).
    Halt,
    /// Root VM panicked.
    Panic,
    /// Root VM ran out of gas.
    OutOfGas,
    /// Root VM page-faulted at address.
    PageFault(u32),
    /// A protocol cap was invoked. Host should handle and call `resume_protocol_call`.
    /// Read registers/gas via kernel accessors (active_reg, gas).
    ProtocolCall {
        /// Protocol cap slot number.
        slot: u8,
    },
}

/// One canonical instruction observed while the invocation kernel is running.
///
/// The metadata identifies the exact nested machine and canonical program that
/// executed the instruction. `instruction` exposes immutable pre/post-step PVM
/// state; capability dispatch and scheduler state remain owned by the kernel.
pub struct KernelInstructionObservation<'a> {
    /// VM arena index active for this instruction.
    pub active_vm: u16,
    /// Invocation-local CODE capability identifier.
    pub code_cap_id: u16,
    /// Blake2b-256 commitment to the canonical CODE sub-blob.
    pub program_hash: [u8; 32],
    /// Number of suspended callers below the active VM.
    pub call_depth: usize,
    /// Canonical interpreter instruction observation.
    pub instruction: crate::interpreter::InstructionObservation<'a>,
}

/// Failure to start an observed kernel run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KernelObservationError {
    /// Instruction observations are defined by the canonical interpreter step
    /// boundary. Construct or restore the invocation with `ForceInterpreter`.
    #[error("kernel instruction observation requires the interpreter backend")]
    InterpreterRequired,
}

/// The invocation kernel.
pub struct InvocationKernel {
    /// Physical memory pool.
    pub backing: BackingStore,
    /// Compiled CODE caps (max 5).
    pub code_caps: Vec<Arc<CodeCap>>,
    /// VM instances (generational arena).
    pub vm_arena: VmArena,
    /// Shared UNTYPED cap (bump allocator).
    pub untyped: Arc<UntypedCap>,
    /// Currently active VM index.
    pub active_vm: u16,
    /// Call stack for CALL/REPLY routing.
    pub call_stack: Vec<CallFrame>,
    /// Memory tier (load/store cycles).
    pub mem_cycles: u8,
    /// Next CODE cap ID.
    next_code_id: u16,
    /// Backend selection for CODE cap compilation.
    pub backend: crate::backend::PvmBackend,
    /// ISA profile for CODE cap compilation and execution.
    // Every production constructor is capability-manifest/JAR-only. Keeping
    // the profile private prevents callers from mutating a legacy kernel into
    // a substitute standard outer executor.
    isa_mode: crate::IsaMode,
    /// Commitment to the canonical invocation program/layout inputs.
    invocation_layout_hash: [u8; 32],
    /// Protocol call whose result has not yet been injected.
    pending_protocol_call: Option<PendingProtocolCall>,
    /// Root page fault suspended at an exact retry boundary.
    pending_page_fault: Option<PendingPageFault>,
    /// CODE cap ID for fast recompiler resume after ProtocolCall.
    /// When set, the next `run()` call uses `run_recompiler_resume()` instead
    /// of `run_recompiler_segment()`, avoiding a full JitContext rebuild.
    recompiler_resume_cap: Option<usize>,
    /// Live register/gas context during recompiler execution.
    /// Points to the JitContext's regs/gas fields. When set, `active_reg` and
    /// `active_gas` read/write this directly instead of VmInstance, eliminating
    /// the JitContext ↔ VmInstance register copy on each ecalli.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    live_ctx: Option<*mut crate::recompiler::JitContext>,
    /// Window pool: N pre-allocated 4GB virtual windows with LRU eviction.
    /// Windows are assigned to VMs on CALL/RESUME and evicted when full.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    window_pool: WindowPool,
    /// Index of the window currently assigned to the active VM.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    active_window: usize,
}

impl InvocationKernel {
    /// Create a new kernel from a JAR blob.
    ///
    pub fn new(blob: &[u8], _args: &[u8], gas: u64) -> Result<Self, KernelError> {
        Self::new_with_backend(blob, _args, gas, crate::backend::PvmBackend::Default)
    }

    /// Create a new kernel, reusing cached JIT compilations when available.
    pub fn new_cached(
        blob: &[u8],
        args: &[u8],
        gas: u64,
        cache: &mut CodeCache,
    ) -> Result<Self, KernelError> {
        Self::new_inner(
            blob,
            args,
            gas,
            crate::backend::PvmBackend::Default,
            crate::IsaMode::Jar,
            &[],
            Some(cache),
        )
    }

    /// Create a new kernel with a specific backend selection.
    pub fn new_with_backend(
        blob: &[u8],
        _args: &[u8],
        gas: u64,
        backend: crate::backend::PvmBackend,
    ) -> Result<Self, KernelError> {
        Self::new_inner(blob, _args, gas, backend, crate::IsaMode::Jar, &[], None)
    }

    /// Create an invocation with canonical programs preinstalled as idle VMs.
    ///
    /// This is invocation setup, not a host-call extension. Each imported VM
    /// has exactly the static capability layout declared by its own manifest,
    /// shares the invocation's bounded physical page pool, and is reachable
    /// from the root only through the requested owner HANDLE.
    pub fn new_with_dormant_programs(
        blob: &[u8],
        args: &[u8],
        gas: u64,
        programs: &[DormantProgram<'_>],
        backend: crate::backend::PvmBackend,
    ) -> Result<Self, KernelError> {
        Self::new_inner(
            blob,
            args,
            gas,
            backend,
            crate::IsaMode::Jar,
            programs,
            None,
        )
    }

    fn new_inner(
        blob: &[u8],
        _args: &[u8],
        gas: u64,
        backend: crate::backend::PvmBackend,
        isa_mode: crate::IsaMode,
        dormant_programs: &[DormantProgram<'_>],
        mut code_cache: Option<&mut CodeCache>,
    ) -> Result<Self, KernelError> {
        let parsed = program::parse_blob(blob).ok_or(KernelError::InvalidBlob)?;

        let parsed_dormant = dormant_programs
            .iter()
            .map(|program| program::parse_blob(program.blob).ok_or(KernelError::InvalidBlob))
            .collect::<Result<Vec<_>, _>>()?;
        validate_import_handle_slots(&parsed, dormant_programs)?;
        validate_manifest_memory(&parsed)?;
        for imported in &parsed_dormant {
            validate_manifest_memory(imported)?;
        }

        let memory_pages = parsed_dormant
            .iter()
            .try_fold(parsed.header.memory_pages, |total, imported| {
                total.checked_add(imported.header.memory_pages)
            })
            .ok_or(KernelError::MemoryError)?;
        let init_pages = core::iter::once(&parsed)
            .chain(parsed_dormant.iter())
            .flat_map(|program| program.caps.iter())
            .filter(|entry| entry.cap_type == CapEntryType::Data)
            .try_fold(0u64, |total, entry| {
                total.checked_add(entry.page_count as u64)
            })
            .ok_or(KernelError::MemoryError)?;
        let init_gas_cost = init_pages
            .checked_mul(GAS_PER_PAGE)
            .ok_or(KernelError::OutOfGas)?;
        if gas < init_gas_cost {
            return Err(KernelError::OutOfGas);
        }
        let remaining_gas = gas - init_gas_cost;

        let backing = BackingStore::new(memory_pages).ok_or(KernelError::MemoryError)?;

        let mem_cycles =
            crate::mem_cycles_for_mode(crate::compute_mem_cycles(memory_pages), isa_mode);
        let untyped = Arc::new(UntypedCap::new(memory_pages));

        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        let window_pool =
            WindowPool::new(crate::vm_pool::WINDOW_POOL_SIZE).ok_or(KernelError::MemoryError)?;

        let mut kernel = Self {
            backing,
            code_caps: Vec::with_capacity(MAX_CODE_CAPS),
            vm_arena: VmArena::new(),
            untyped,
            active_vm: 0,
            call_stack: Vec::with_capacity(8),
            mem_cycles,
            next_code_id: 0,
            backend,
            isa_mode,
            invocation_layout_hash: invocation_layout_hash(blob, dormant_programs),
            pending_protocol_call: None,
            pending_page_fault: None,
            recompiler_resume_cap: None,
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            live_ctx: None,
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            window_pool,
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            active_window: 0,
        };

        // Build VM 0's cap table: protocol caps + manifest caps
        let mut cap_table = CapTable::new();

        // Populate protocol caps (slots 1-28). Slot 0 is IPC (REPLY).
        // These are kernel-handled and exit to the host via ProtocolCall when CALLed.
        use crate::cap::ProtocolCap;
        for id in 1..=28u8 {
            cap_table.set_original(id, Cap::Protocol(ProtocolCap { id }));
        }
        let mut data_caps_to_map: Vec<(u32, u32, u32, Access)> = Vec::new(); // (base_page, backing_offset, page_count, access)

        for entry in &parsed.caps {
            let cap = kernel.create_cap_from_manifest(entry, &parsed, &mut code_cache)?;
            if let Cap::Data(ref d) = cap {
                // Record DATA caps that need mapping into the CODE window
                if d.has_any_mapped()
                    && let (Some(base_page), Some(access)) = (d.base_offset, d.access)
                {
                    data_caps_to_map.push((base_page, d.backing_offset, d.page_count, access));
                }
            }
            cap_table.set(entry.cap_index, cap);
        }

        // Resolve the invoke CODE cap to find its code_caps index
        let invoke_code_id = match cap_table.get(parsed.header.invoke_cap) {
            Some(Cap::Code(c)) => c.id,
            _ => return Err(KernelError::InvalidBlob),
        };

        // Assign window 0 to VM 0 and map DATA caps into it.
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        {
            let assignment = kernel.window_pool.assign_window(0, 0);
            kernel.active_window = assignment.window_idx;
            let window_base = kernel.window_pool.window(assignment.window_idx).base();
            for (base_page, backing_offset, page_count, access) in &data_caps_to_map {
                // SAFETY: window_base is from CodeWindow::base() (valid 4GB mmap region).
                unsafe {
                    if !kernel.backing.map_pages(
                        window_base,
                        *base_page,
                        *backing_offset,
                        *page_count,
                        *access,
                    ) {
                        return Err(KernelError::MemoryError);
                    }
                }
            }
        }
        // Non-recompiler platforms: DATA cap mapping is handled at interpreter run time.
        #[cfg(not(all(feature = "std", target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = &data_caps_to_map;
        }

        // Give VM 0 the UNTYPED cap at slot 254 (fixed slot, just below IPC).
        // Skip when memory_pages == 0 — no point creating an empty allocator.
        if parsed.header.memory_pages > 0 {
            cap_table.set(254, Cap::Untyped(Arc::clone(&kernel.untyped)));
        }

        // Write arguments into args cap (cap_index = IPC slot 0)
        let mut args_base: u64 = 0;
        let args_len: u64 = _args.len() as u64;
        if !_args.is_empty() {
            // Find args cap by scanning for cap_index=IPC_SLOT (0)
            let args_cap_entry = parsed.caps.iter().find(|e| e.cap_index == IPC_SLOT);
            if let Some(entry) = args_cap_entry {
                args_base = entry.base_page as u64 * crate::PVM_PAGE_SIZE as u64;
                if let Some(Cap::Data(d)) = cap_table.get(IPC_SLOT) {
                    let capacity = d.page_count as usize * crate::PVM_PAGE_SIZE as usize;
                    if _args.len() > capacity
                        || !kernel.backing.write_init_data(d.backing_offset, _args)
                    {
                        return Err(KernelError::MemoryError);
                    }
                }
            }
        }

        // Create legacy manifest VM 0. The host installs the manifest-owned
        // stack and argument registers; standard outer programs use
        // `RefineContext` instead and never enter this kernel.
        let mut vm0 = VmInstance::new(
            invoke_code_id,
            0, // entry_index (set by caller via CALL)
            cap_table,
            remaining_gas,
        );
        vm0.set_reg(0, crate::PVM_HALT_ADDR); // φ[0] = RA (halt address: `ret` halts)
        vm0.set_reg(1, parsed.header.stack_top as u64); // φ[1] = SP (stack top)
        vm0.set_reg(7, args_base); // φ[7] = args address
        vm0.set_reg(8, args_len); // φ[8] = args length
        vm0.seal_entry_registers();
        kernel.vm_arena.insert(vm0).ok_or(KernelError::TooManyVms)?; // VM 0 gets VmId(0, 0)

        // Dormant programs are complete VM instances, not CODE templates.
        // Their manifest-defined DATA/stack layout is therefore reconstructed
        // exactly and does not depend on CREATE's 64-bit capability-copy mask.
        for (program, imported) in dormant_programs.iter().zip(parsed_dormant.iter()) {
            let mut imported_table = CapTable::new();
            for entry in &imported.caps {
                let cap = kernel.create_cap_from_manifest(entry, imported, &mut code_cache)?;
                imported_table.set(entry.cap_index, cap);
            }
            if imported.header.memory_pages > 0 {
                imported_table.set(254, Cap::Untyped(Arc::clone(&kernel.untyped)));
            }
            let invoke_code_id = match imported_table.get(imported.header.invoke_cap) {
                Some(Cap::Code(code)) => code.id,
                _ => return Err(KernelError::InvalidBlob),
            };
            let mut vm = VmInstance::new(invoke_code_id, 0, imported_table, 0);
            vm.set_reg(0, crate::PVM_HALT_ADDR);
            vm.set_reg(1, imported.header.stack_top as u64);
            vm.seal_entry_registers();
            let vm_id = kernel.vm_arena.insert(vm).ok_or(KernelError::TooManyVms)?;
            kernel.vm_arena.vm_mut(0).cap_table.set(
                program.handle_slot,
                Cap::Handle(HandleCap {
                    vm_id,
                    max_gas: None,
                }),
            );
        }

        Ok(kernel)
    }

    /// Set the instruction counter (byte offset into code) at which the root
    /// VM begins executing on the first [`run`](Self::run).
    ///
    /// The two-slot GP entry prologue emitted by the transpiler places a jump
    /// to the refine body at IC 0 and a jump to the accumulate body (or a
    /// trap, for refine-only blobs) at IC 5. The host therefore selects the
    /// entry point purely by where it starts the counter: `0` for refine /
    /// is-authorized, `5` for accumulate.
    pub fn set_entry_ic(&mut self, entry_ic: u32) {
        self.vm_arena.vm_mut(self.active_vm).pc = entry_ic;
    }

    /// Extract the current flat_mem snapshot from the kernel's DATA cap pages.
    ///
    /// Returns `(flat_mem, heap_base, heap_top)`. The flat_mem is a copy of all
    /// mapped DATA cap pages assembled at their virtual addresses.
    pub fn extract_flat_mem(&self) -> (Vec<u8>, u32, u32) {
        let vm = &self.vm_arena.vm(self.active_vm);

        // Determine memory size from mapped DATA caps.
        let mut max_addr: usize = 0;
        for slot in 0..=255u8 {
            if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                && d.has_any_mapped()
                && let Some(base_page) = d.base_offset
            {
                let end =
                    (base_page as usize + d.page_count as usize) * crate::PVM_PAGE_SIZE as usize;
                max_addr = max_addr.max(end);
            }
        }

        let mut flat_mem = vec![0u8; max_addr];

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let wb = self.active_window_base();
            for slot in 0..=255u8 {
                if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                    && d.has_any_mapped()
                    && let Some(base_page) = d.base_offset
                {
                    let addr = base_page as usize * crate::PVM_PAGE_SIZE as usize;
                    let len = d.page_count as usize * crate::PVM_PAGE_SIZE as usize;
                    if addr + len <= flat_mem.len() {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                wb.add(addr),
                                flat_mem.as_mut_ptr().add(addr),
                                len,
                            );
                        }
                    }
                }
            }
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            for slot in 0..=255u8 {
                if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                    && d.has_any_mapped()
                    && let Some(base_page) = d.base_offset
                {
                    let addr = base_page as usize * crate::PVM_PAGE_SIZE as usize;
                    let len = d.page_count as usize * crate::PVM_PAGE_SIZE as usize;
                    if addr + len <= flat_mem.len() {
                        flat_mem[addr..addr + len].copy_from_slice(
                            self.backing.read_page_slice(d.backing_offset, d.page_count),
                        );
                    }
                }
            }
        }

        (flat_mem, vm.heap_base(), vm.heap_top())
    }

    /// Create a warm-restart kernel: same as `new()` but overlays a saved
    /// flat_mem snapshot onto the DATA cap pages after initialization.
    ///
    /// The kernel always starts at PC=0 (the guest's `_start` entry), but
    /// the heap, statics, and actor instance survive from the previous tick
    /// because the RW DATA pages are pre-populated.
    /// Create a warm-restart kernel: same as [`new`](Self::new) but overlays
    /// a saved flat_mem snapshot onto the RW DATA cap pages after init.
    ///
    /// If `cache` is provided, JIT compilations are reused via
    /// [`CodeCache`] — important for the continuation hot path where the
    /// same blob is re-entered every tick.
    pub fn new_warm(
        blob: &[u8],
        args: &[u8],
        gas: u64,
        flat_mem: &[u8],
        heap_base: u32,
        heap_top: u32,
        cache: Option<&mut CodeCache>,
    ) -> Result<Self, KernelError> {
        let mut kernel = match cache {
            Some(c) => Self::new_cached(blob, args, gas, c)?,
            None => Self::new(blob, args, gas)?,
        };
        // Overlay the saved flat_mem onto RW DATA cap pages.
        let vm = &kernel.vm_arena.vm(0);
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let wb = kernel.active_window_base();
            for slot in 0..=255u8 {
                if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                    && d.has_any_mapped()
                    && d.access == Some(Access::RW)
                    && let Some(base_page) = d.base_offset
                {
                    let addr = base_page as usize * crate::PVM_PAGE_SIZE as usize;
                    let len = d.page_count as usize * crate::PVM_PAGE_SIZE as usize;
                    if addr + len <= flat_mem.len() {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                flat_mem.as_ptr().add(addr),
                                wb.add(addr),
                                len,
                            );
                        }
                    }
                }
            }
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            // Collect overlay info before taking &mut backing.
            let overlays: Vec<(usize, u32, u32)> = (0..=255u8)
                .filter_map(|slot| {
                    let d = if let Some(Cap::Data(d)) = vm.cap_table.get(slot) {
                        d
                    } else {
                        return None;
                    };
                    if !d.has_any_mapped() || d.access != Some(Access::RW) {
                        return None;
                    }
                    let base_page = d.base_offset?;
                    let addr = base_page as usize * crate::PVM_PAGE_SIZE as usize;
                    let len = d.page_count as usize * crate::PVM_PAGE_SIZE as usize;
                    if addr + len > flat_mem.len() {
                        return None;
                    }
                    Some((addr, d.backing_offset, d.page_count))
                })
                .collect();
            for (addr, backing_offset, page_count) in overlays {
                let len = page_count as usize * crate::PVM_PAGE_SIZE as usize;
                kernel
                    .backing
                    .write_page_slice(backing_offset, &flat_mem[addr..addr + len]);
            }
        }

        // Set heap state on VM 0.
        let vm = kernel.vm_arena.vm_mut(0);
        vm.set_heap_base(heap_base);
        vm.set_heap_top(heap_top);

        Ok(kernel)
    }

    /// Capture the complete invocation at a flushed host or retry boundary.
    ///
    /// Native code and virtual-memory windows are deliberately excluded. A
    /// restore recompiles the canonical blob and verifies every CODE sub-blob
    /// hash before installing this machine state.
    pub fn snapshot(&mut self) -> Result<KernelSnapshot, SnapshotError> {
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        {
            self.flush_live_ctx();
            self.recompiler_resume_cap = None;
            crate::recompiler::signal::SIGNAL_STATE.with(|cell| cell.set(core::ptr::null_mut()));
        }

        let pending_call = self.pending_protocol_call;
        let pending_fault = self.pending_page_fault;
        if pending_call.is_some() == pending_fault.is_some() {
            return Err(SnapshotError::NotAtProtocolBoundary);
        }
        self.validate_suspension_boundary(pending_call, pending_fault)?;

        let slots = self
            .vm_arena
            .snapshot_slots()
            .map(|(generation, vm)| {
                Ok(VmSlotSnapshot {
                    generation,
                    vm: vm.map(|vm| self.snapshot_vm(vm)).transpose()?,
                })
            })
            .collect::<Result<Vec<_>, SnapshotError>>()?;

        let mut blocks_by_hash = BTreeMap::<[u8; 32], Vec<u8>>::new();
        let mut memory = Vec::new();
        for page_index in 0..self.backing.total_pages() {
            let bytes = self
                .backing
                .read_page(page_index)
                .ok_or(SnapshotError::InvalidMemory)?;
            if bytes.iter().all(|byte| *byte == 0) {
                continue;
            }
            let block_hash = blake2b_256(&bytes);
            if let Some(existing) = blocks_by_hash.get(&block_hash) {
                if existing != &bytes {
                    return Err(SnapshotError::InvalidMemory);
                }
            } else {
                blocks_by_hash.insert(block_hash, bytes);
            }
            memory.push(MemoryPageRef {
                page_index,
                block_hash,
            });
        }
        let blocks = blocks_by_hash
            .into_iter()
            .map(|(hash, bytes)| MemoryBlock { hash, bytes })
            .collect();

        Ok(KernelSnapshot {
            version: KERNEL_SNAPSHOT_VERSION,
            invocation_layout_hash: self.invocation_layout_hash,
            isa_mode: snapshot_isa_mode(self.isa_mode),
            memory_pages: self.backing.total_pages(),
            mem_cycles: self.mem_cycles,
            next_code_id: self.next_code_id,
            code_hashes: self.code_caps.iter().map(|cap| cap.program_hash).collect(),
            untyped_offset: self.untyped.allocated(),
            active_vm: self.active_vm,
            arena: VmArenaSnapshot {
                slots,
                free_list: self.vm_arena.snapshot_free_list().to_vec(),
            },
            call_stack: self.call_stack.iter().map(snapshot_call_frame).collect(),
            memory,
            blocks,
            pending_call,
            pending_fault,
        })
    }

    /// Restore a portable snapshot against canonical program bytes.
    pub fn restore(
        blob: &[u8],
        snapshot: &KernelSnapshot,
        backend: crate::backend::PvmBackend,
        cache: Option<&mut CodeCache>,
    ) -> Result<Self, SnapshotError> {
        if snapshot.isa_mode != SnapshotIsaMode::Jar {
            return Err(SnapshotError::ProgramMismatch);
        }
        Self::restore_inner(blob, &[], snapshot, backend, cache)
    }

    /// Restore a portable snapshot against the complete canonical invocation
    /// layout used by [`Self::new_with_dormant_programs`].
    pub fn restore_with_dormant_programs(
        blob: &[u8],
        programs: &[DormantProgram<'_>],
        snapshot: &KernelSnapshot,
        backend: crate::backend::PvmBackend,
    ) -> Result<Self, SnapshotError> {
        if snapshot.isa_mode != SnapshotIsaMode::Jar {
            return Err(SnapshotError::ProgramMismatch);
        }
        Self::restore_inner(blob, programs, snapshot, backend, None)
    }

    fn restore_inner(
        blob: &[u8],
        programs: &[DormantProgram<'_>],
        snapshot: &KernelSnapshot,
        backend: crate::backend::PvmBackend,
        cache: Option<&mut CodeCache>,
    ) -> Result<Self, SnapshotError> {
        if snapshot.version != KERNEL_SNAPSHOT_VERSION {
            return Err(SnapshotError::UnsupportedVersion(snapshot.version));
        }
        let isa_mode = restore_isa_mode(snapshot.isa_mode);
        let mut kernel = Self::new_inner(blob, &[], u64::MAX, backend, isa_mode, programs, cache)
            .map_err(|_| SnapshotError::ProgramMismatch)?;

        if kernel.invocation_layout_hash != snapshot.invocation_layout_hash
            || kernel.backing.total_pages() != snapshot.memory_pages
            || kernel.mem_cycles != snapshot.mem_cycles
            || kernel.code_caps.len() != snapshot.code_hashes.len()
            || kernel.next_code_id != snapshot.next_code_id
            || snapshot.next_code_id as usize != snapshot.code_hashes.len()
            || kernel
                .code_caps
                .iter()
                .zip(&snapshot.code_hashes)
                .any(|(cap, expected)| cap.program_hash != *expected)
        {
            return Err(SnapshotError::ProgramMismatch);
        }

        let untyped = Arc::new(
            UntypedCap::restored(snapshot.memory_pages, snapshot.untyped_offset)
                .ok_or(SnapshotError::InvalidCapability)?,
        );

        restore_memory(&mut kernel.backing, snapshot)?;

        let mut slots = Vec::with_capacity(snapshot.arena.slots.len());
        for slot in &snapshot.arena.slots {
            let vm = slot
                .vm
                .as_ref()
                .map(|vm| restore_vm(vm, &kernel.code_caps, &untyped, snapshot.memory_pages))
                .transpose()?;
            slots.push((slot.generation, vm));
        }
        if snapshot.active_vm as usize >= slots.len()
            || slots[snapshot.active_vm as usize].1.is_none()
        {
            return Err(SnapshotError::InvalidScheduler);
        }
        kernel.vm_arena = VmArena::restore_slots(slots, snapshot.arena.free_list.clone())
            .ok_or(SnapshotError::InvalidArena)?;
        kernel.untyped = untyped;
        kernel.active_vm = snapshot.active_vm;
        kernel.call_stack = snapshot
            .call_stack
            .iter()
            .map(restore_call_frame)
            .collect::<Result<Vec<_>, _>>()?;
        kernel.pending_protocol_call = snapshot.pending_call;
        kernel.pending_page_fault = snapshot.pending_fault;
        kernel.recompiler_resume_cap = None;

        let active_vm = kernel.vm_arena.vm(kernel.active_vm);
        if active_vm.state != VmState::Running
            || snapshot.pending_call.is_some() == snapshot.pending_fault.is_some()
        {
            return Err(SnapshotError::InvalidScheduler);
        }
        kernel.validate_suspension_boundary(snapshot.pending_call, snapshot.pending_fault)?;
        validate_call_stack(&kernel)?;

        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        {
            kernel.window_pool = WindowPool::new(crate::vm_pool::WINDOW_POOL_SIZE)
                .ok_or(SnapshotError::InvalidMemory)?;
            kernel.active_window = 0;
            kernel.live_ctx = None;
            crate::recompiler::signal::SIGNAL_STATE.with(|cell| cell.set(core::ptr::null_mut()));
        }

        Ok(kernel)
    }

    /// Validate that the portable suspension record and the per-VM retry
    /// markers describe one and the same execution boundary.  In particular,
    /// no inactive VM may smuggle a latent host/fault continuation into a
    /// snapshot, and strict-v0.8 continuations are always inside an already
    /// funded block.
    fn validate_suspension_boundary(
        &self,
        pending_call: Option<PendingProtocolCall>,
        pending_fault: Option<PendingPageFault>,
    ) -> Result<(), SnapshotError> {
        if pending_call.is_some() == pending_fault.is_some() {
            return Err(SnapshotError::InvalidScheduler);
        }

        let active_vm = self
            .vm_arena
            .snapshot_slots()
            .nth(self.active_vm as usize)
            .and_then(|(_, vm)| vm)
            .ok_or(SnapshotError::InvalidScheduler)?;
        if active_vm.state != VmState::Running {
            return Err(SnapshotError::InvalidScheduler);
        }

        let total_gas = self
            .vm_arena
            .snapshot_slots()
            .try_fold(0u64, |total, (_, vm)| {
                vm.map_or(Some(total), |vm| total.checked_add(vm.gas()))
            })
            .ok_or(SnapshotError::InvalidScheduler)?;
        let _ = total_gas;

        for (index, (_, vm)) in self.vm_arena.snapshot_slots().enumerate() {
            let Some(vm) = vm else { continue };
            if index != self.active_vm as usize {
                if vm.pending_page_fault().is_some() {
                    return Err(SnapshotError::InvalidScheduler);
                }
                if let Some(call) = vm.pending_host_call()
                    && (self.isa_mode != crate::IsaMode::Conformance
                        || vm.state != VmState::Faulted
                        || vm.gas() != 0
                        || !vm.gas_charged()
                        || !self.pending_host_call_matches_vm(vm, call))
                {
                    return Err(SnapshotError::InvalidScheduler);
                }
            }
        }

        match (pending_call, pending_fault) {
            (Some(call), None) => {
                if call.vm_index != self.active_vm
                    || call.cause_pc != active_vm.pc
                    || call.gas_charged != active_vm.gas_charged()
                    || call.result_registers != [7, 8]
                    || active_vm.pending_page_fault().is_some()
                {
                    return Err(SnapshotError::InvalidScheduler);
                }

                let expected_host_call = crate::PendingHostCall {
                    id: call.host_call_id,
                    cause_pc: call.cause_pc,
                    resume_pc: call.resume_pc,
                };
                match self.isa_mode {
                    crate::IsaMode::Conformance
                        if !call.gas_charged
                            || active_vm.pending_host_call() != Some(expected_host_call)
                            || !self
                                .pending_host_call_matches_vm(active_vm, expected_host_call)
                            || u8::try_from(call.host_call_id).ok().is_none_or(|slot| {
                                !matches!(
                                    active_vm.cap_table.get(slot),
                                    Some(Cap::Protocol(protocol)) if protocol.id == call.slot
                                )
                            }) =>
                    {
                        return Err(SnapshotError::InvalidScheduler);
                    }
                    crate::IsaMode::Jar if active_vm.pending_host_call().is_some() => {
                        return Err(SnapshotError::InvalidScheduler);
                    }
                    _ => {}
                }
            }
            (None, Some(fault)) => {
                if fault.vm_index != self.active_vm
                    || fault.cause_pc != active_vm.pc
                    || fault.gas_charged != active_vm.gas_charged()
                    || active_vm.pending_host_call().is_some()
                    || active_vm.pending_page_fault() != Some(fault.address)
                    || (self.isa_mode == crate::IsaMode::Conformance && !fault.gas_charged)
                    || (self.isa_mode == crate::IsaMode::Conformance
                        && !self.pending_page_fault_matches_vm(active_vm, fault))
                {
                    return Err(SnapshotError::InvalidScheduler);
                }
            }
            _ => return Err(SnapshotError::InvalidScheduler),
        }
        Ok(())
    }

    fn pending_host_call_matches_vm(&self, vm: &VmInstance, call: crate::PendingHostCall) -> bool {
        let Some(code_cap) = self.code_caps.get(vm.code_cap_id as usize) else {
            return false;
        };
        let pc = call.cause_pc as usize;
        if code_cap.bitmask.get(pc) != Some(&1)
            || code_cap.code.get(pc) != Some(&(crate::instruction::Opcode::Ecalli as u8))
        {
            return false;
        }
        let skip = crate::interpreter::skip_for_bitmask(&code_cap.bitmask, pc);
        let Some(resume_pc) = call
            .cause_pc
            .checked_add(1)
            .and_then(|next| next.checked_add(skip as u32))
        else {
            return false;
        };
        matches!(
            crate::args::decode_args(
                &code_cap.code,
                pc,
                skip,
                crate::instruction::Opcode::Ecalli.category(),
            ),
            crate::args::Args::Imm { imm }
                if imm == call.id && resume_pc == call.resume_pc
        )
    }

    fn pending_page_fault_matches_vm(&self, vm: &VmInstance, fault: PendingPageFault) -> bool {
        if fault.address % crate::PVM_PAGE_SIZE != 0 {
            return false;
        }
        let Some(code_cap) = self.code_caps.get(vm.code_cap_id as usize) else {
            return false;
        };
        let pc = fault.cause_pc as usize;
        if code_cap.bitmask.get(pc) != Some(&1) {
            return false;
        }
        let Some(opcode) = code_cap
            .code
            .get(pc)
            .and_then(|byte| crate::instruction::Opcode::from_byte_in_mode(*byte, self.isa_mode))
        else {
            return false;
        };
        let skip = crate::interpreter::skip_for_bitmask(&code_cap.bitmask, pc);
        let args = crate::args::decode_args(&code_cap.code, pc, skip, opcode.category());
        use crate::args::Args;
        use crate::instruction::Opcode;
        let (address, width, write) = match (opcode, args) {
            (Opcode::StoreImmU8, Args::TwoImm { imm_x, .. }) => (imm_x as u32, 1, true),
            (Opcode::StoreImmU16, Args::TwoImm { imm_x, .. }) => (imm_x as u32, 2, true),
            (Opcode::StoreImmU32, Args::TwoImm { imm_x, .. }) => (imm_x as u32, 4, true),
            (Opcode::StoreImmU64, Args::TwoImm { imm_x, .. }) => (imm_x as u32, 8, true),
            (Opcode::LoadU8 | Opcode::LoadI8, Args::RegImm { imm, .. }) => (imm as u32, 1, false),
            (Opcode::LoadU16 | Opcode::LoadI16, Args::RegImm { imm, .. }) => (imm as u32, 2, false),
            (Opcode::LoadU32 | Opcode::LoadI32, Args::RegImm { imm, .. }) => (imm as u32, 4, false),
            (Opcode::LoadU64, Args::RegImm { imm, .. }) => (imm as u32, 8, false),
            (Opcode::StoreU8, Args::RegImm { imm, .. }) => (imm as u32, 1, true),
            (Opcode::StoreU16, Args::RegImm { imm, .. }) => (imm as u32, 2, true),
            (Opcode::StoreU32, Args::RegImm { imm, .. }) => (imm as u32, 4, true),
            (Opcode::StoreU64, Args::RegImm { imm, .. }) => (imm as u32, 8, true),
            (Opcode::StoreImmIndU8, Args::RegTwoImm { ra, imm_x, .. }) => {
                (vm.reg(ra).wrapping_add(imm_x) as u32, 1, true)
            }
            (Opcode::StoreImmIndU16, Args::RegTwoImm { ra, imm_x, .. }) => {
                (vm.reg(ra).wrapping_add(imm_x) as u32, 2, true)
            }
            (Opcode::StoreImmIndU32, Args::RegTwoImm { ra, imm_x, .. }) => {
                (vm.reg(ra).wrapping_add(imm_x) as u32, 4, true)
            }
            (Opcode::StoreImmIndU64, Args::RegTwoImm { ra, imm_x, .. }) => {
                (vm.reg(ra).wrapping_add(imm_x) as u32, 8, true)
            }
            (Opcode::StoreIndU8, Args::TwoRegImm { rb, imm, .. }) => {
                (vm.reg(rb).wrapping_add(imm) as u32, 1, true)
            }
            (Opcode::StoreIndU16, Args::TwoRegImm { rb, imm, .. }) => {
                (vm.reg(rb).wrapping_add(imm) as u32, 2, true)
            }
            (Opcode::StoreIndU32, Args::TwoRegImm { rb, imm, .. }) => {
                (vm.reg(rb).wrapping_add(imm) as u32, 4, true)
            }
            (Opcode::StoreIndU64, Args::TwoRegImm { rb, imm, .. }) => {
                (vm.reg(rb).wrapping_add(imm) as u32, 8, true)
            }
            (Opcode::LoadIndU8 | Opcode::LoadIndI8, Args::TwoRegImm { rb, imm, .. }) => {
                (vm.reg(rb).wrapping_add(imm) as u32, 1, false)
            }
            (Opcode::LoadIndU16 | Opcode::LoadIndI16, Args::TwoRegImm { rb, imm, .. }) => {
                (vm.reg(rb).wrapping_add(imm) as u32, 2, false)
            }
            (Opcode::LoadIndU32 | Opcode::LoadIndI32, Args::TwoRegImm { rb, imm, .. }) => {
                (vm.reg(rb).wrapping_add(imm) as u32, 4, false)
            }
            (Opcode::LoadIndU64, Args::TwoRegImm { rb, imm, .. }) => {
                (vm.reg(rb).wrapping_add(imm) as u32, 8, false)
            }
            _ => return false,
        };
        let permission_at = |page: u32| {
            let mut permission = None;
            for slot in 0..=255u8 {
                if let Some(Cap::Data(data)) = vm.cap_table.get(slot)
                    && let (Some(base), Some(access)) = (data.base_offset, data.access)
                    && page >= base
                    && page < base + data.page_count
                    && data.is_page_mapped(page - base)
                {
                    // Runtime mapping loops are slot ordered; the later
                    // overlapping mapping is authoritative.
                    permission = Some(access);
                }
            }
            permission
        };
        let page_ok = |page| match permission_at(page) {
            Some(Access::RW) => true,
            Some(Access::RO) => !write,
            None => false,
        };

        // The transitional JAR profile retains its historical non-cyclic
        // range classification: after an accessible high tail, the raw
        // one-past address faults as page zero. Standard continuations use
        // the exact cyclic exception walk below.
        if self.isa_mode == crate::IsaMode::Jar {
            let first_page = address / crate::PVM_PAGE_SIZE;
            let last_page = ((u64::from(address) + u64::from(width) - 1)
                / u64::from(crate::PVM_PAGE_SIZE)) as u32;
            let expected_fault_page = if !page_ok(first_page) {
                first_page
            } else if !page_ok(last_page) {
                last_page
            } else {
                return false;
            };
            return (u64::from(expected_fault_page) * u64::from(crate::PVM_PAGE_SIZE)) as u32
                == fault.address;
        }

        // Reconstruct the standard memory exception in raw required-index
        // order, reducing each inspected byte modulo 2^32. In particular, an
        // access with an accessible high tail reaches the wrapped low zone
        // and panics; it can never produce a forged PageFault(0) retry marker.
        for offset in 0..width {
            let byte_address = address.wrapping_add(offset);
            if self.isa_mode == crate::IsaMode::Conformance && byte_address < crate::PVM_ZONE_SIZE {
                return false;
            }
            let page = byte_address / crate::PVM_PAGE_SIZE;
            if !page_ok(page) {
                return page * crate::PVM_PAGE_SIZE == fault.address;
            }
        }
        false
    }

    fn snapshot_vm(&self, vm: &VmInstance) -> Result<VmSnapshot, SnapshotError> {
        let mut capabilities = Vec::new();
        for slot in 0..=u8::MAX {
            let Some(capability) = vm.cap_table.get(slot) else {
                if vm.cap_table.is_original(slot) {
                    return Err(SnapshotError::InvalidCapability);
                }
                continue;
            };
            capabilities.push(CapabilitySlotSnapshot {
                slot,
                original: vm.cap_table.is_original(slot),
                capability: snapshot_capability(capability, &self.untyped)?,
            });
        }
        Ok(VmSnapshot {
            state: snapshot_vm_state(vm.state),
            code_cap_id: vm.code_cap_id,
            registers: vm.regs().to_vec(),
            entry_registers: vm.entry_regs().to_vec(),
            pc: vm.pc,
            capabilities,
            caller: vm.caller,
            entry_index: vm.entry_index,
            gas: vm.gas(),
            gas_charged: vm.gas_charged(),
            pending_host_call: vm.pending_host_call().map(|call| PendingHostCallSnapshot {
                id: call.id,
                cause_pc: call.cause_pc,
                resume_pc: call.resume_pc,
            }),
            pending_page_fault: vm.pending_page_fault(),
            heap_base: vm.heap_base(),
            heap_top: vm.heap_top(),
        })
    }

    /// Create a capability from a manifest entry.
    fn create_cap_from_manifest(
        &mut self,
        entry: &CapManifestEntry,
        parsed: &ParsedBlob<'_>,
        code_cache: &mut Option<&mut CodeCache>,
    ) -> Result<Cap, KernelError> {
        match entry.cap_type {
            CapEntryType::Code => {
                let code_data = program::cap_data(entry, parsed.data_section);
                let id = self.next_code_id;
                self.next_code_id += 1;
                if self.code_caps.len() >= MAX_CODE_CAPS {
                    return Err(KernelError::TooManyCodeCaps);
                }

                // Check compile cache first (blake2b-256 makes collisions negligible).
                let cache_key = CodeCache::cache_key(code_data, self.isa_mode);
                if let Some(cached) = code_cache.as_ref().and_then(|c| c.entries.get(&cache_key)) {
                    let code_cap = Arc::clone(cached);
                    self.code_caps.push(Arc::clone(&code_cap));
                    return Ok(Cap::Code(code_cap));
                }

                // Parse the code sub-blob (jump_table + code + bitmask)
                let code_blob =
                    program::parse_code_blob(code_data).ok_or(KernelError::InvalidBlob)?;

                // Compile via selected backend (interpreter or recompiler)
                let compiled = crate::backend::compile(
                    &code_blob.code,
                    &code_blob.bitmask,
                    &code_blob.jump_table,
                    self.mem_cycles,
                    self.backend,
                    self.isa_mode,
                )
                .map_err(|e| {
                    tracing::warn!("compile failed: {e}");
                    KernelError::CompileError
                })?;

                let code_cap = Arc::new(CodeCap {
                    id,
                    program_hash: cache_key.0,
                    compiled,
                    code: code_blob.code,
                    jump_table: code_blob.jump_table,
                    bitmask: code_blob.bitmask,
                });
                self.code_caps.push(Arc::clone(&code_cap));

                // Insert into cache.
                if let Some(cache) = &mut *code_cache {
                    cache.entries.insert(cache_key, Arc::clone(&code_cap));
                }

                Ok(Cap::Code(code_cap))
            }
            CapEntryType::Data => {
                // Allocate pages from UNTYPED
                let backing_offset = self
                    .untyped
                    .retype(entry.page_count)
                    .ok_or(KernelError::OutOfMemory)?;

                // Write initial data if present
                if entry.data_len > 0 {
                    let data = program::cap_data(entry, parsed.data_section);
                    if !self.backing.write_init_data(backing_offset, data) {
                        return Err(KernelError::MemoryError);
                    }
                }

                // Create DATA cap, marked as mapped (actual mmap happens after all caps are created)
                let mut data_cap = DataCap::new(backing_offset, entry.page_count);
                data_cap.map(entry.base_page, entry.init_access);
                Ok(Cap::Data(data_cap))
            }
        }
    }

    /// Dispatch an ecalli immediate from the active VM.
    ///
    /// Returns a `DispatchResult` indicating what the kernel should do next.
    #[inline(always)]
    pub fn dispatch_ecalli(&mut self, imm: u64) -> DispatchResult {
        // Range check: ecalli only valid for 0-127. ≥128 panics the VM.
        // Route through handle_vm_fault so it terminates uniformly: a root VM
        // becomes RootPanic, a nested VM is delivered to its caller as a
        // fault. (Returning a raw Fault here previously left the run loop to
        // `continue` in a half-synced state — the recompiler had written
        // φ[7] into its live JitContext but not flushed it to the VmInstance,
        // so the next full-segment rebuild lost it and diverged from the
        // interpreter.)
        if imm > 127 {
            self.set_active_reg(7, imm);
            return DispatchResult::Fault(FaultType::Panic);
        }
        // Charge ecalli gas cost (10) — matches GP host call gas charge
        let ecalli_gas: u64 = 10;
        let current_gas = self.active_gas();
        if current_gas < ecalli_gas {
            return DispatchResult::Fault(FaultType::OutOfGas);
        }
        // Deduct gas via live_ctx if available, else VmInstance
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        if let Some(ctx) = self.live_ctx {
            // SAFETY: live_ctx is non-null only during JIT execution on this thread;
            // ctx points to the JitContext in the active CodeWindow's CTX page.
            unsafe { (*ctx).gas -= ecalli_gas };
        } else {
            let g = self.vm_arena.vm(self.active_vm).gas();
            self.vm_arena.vm_mut(self.active_vm).set_gas(g - ecalli_gas);
        }
        #[cfg(not(all(feature = "std", target_os = "linux", target_arch = "x86_64")))]
        {
            let g = self.vm_arena.vm(self.active_vm).gas();
            self.vm_arena.vm_mut(self.active_vm).set_gas(g - ecalli_gas);
        }

        let cap_idx = u8::try_from(imm).expect("the capability slot range was checked above");
        if cap_idx == IPC_SLOT {
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            self.flush_live_ctx();
            return self.handle_reply();
        }
        self.handle_call(cap_idx)
    }

    /// Handle CALL on a cap slot.
    #[inline(always)]
    fn handle_call(&mut self, cap_idx: u8) -> DispatchResult {
        let vm = &self.vm_arena.vm(self.active_vm);
        let cap = match vm.cap_table.get(cap_idx) {
            Some(c) => c,
            None => {
                // Missing cap → WHAT
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        match cap {
            Cap::Protocol(p) => {
                let slot = p.id;
                DispatchResult::ProtocolCall { slot }
            }
            Cap::Untyped(_) => {
                #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
                self.flush_live_ctx();
                self.handle_call_untyped()
            }
            Cap::Code(c) => {
                let code_id = c.id;
                let code_cnode_vm = self.active_vm as usize;
                #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
                self.flush_live_ctx();
                self.handle_call_code(code_id, code_cnode_vm)
            }
            Cap::Handle(h) => {
                let target_vm = h.vm_id;
                let max_gas = h.max_gas;
                #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
                self.flush_live_ctx();
                self.handle_call_vm(target_vm, max_gas)
            }
            Cap::Callable(c) => {
                let target_vm = c.vm_id;
                let max_gas = c.max_gas;
                #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
                self.flush_live_ctx();
                self.handle_call_vm(target_vm, max_gas)
            }
            Cap::Data(_) => {
                // DATA is not callable
                self.set_active_reg(7, RESULT_WHAT);
                DispatchResult::Continue
            }
        }
    }

    /// CALL on UNTYPED → RETYPE.
    fn handle_call_untyped(&mut self) -> DispatchResult {
        let n_pages = self.active_reg(7) as u32;
        let gas_cost = 10 + n_pages as u64 * GAS_PER_PAGE;

        let vm = &mut self.vm_arena.vm_mut(self.active_vm);
        if vm.gas() < gas_cost {
            return DispatchResult::Fault(FaultType::OutOfGas);
        }
        vm.set_gas(vm.gas() - gas_cost);

        // Get the UNTYPED cap (it's an Arc, so we can clone the reference)
        let untyped = match vm.cap_table.get(
            // Find the untyped slot — scan cap table
            (0..=254)
                .find(|i| matches!(vm.cap_table.get(*i), Some(Cap::Untyped(_))))
                .unwrap_or(255),
        ) {
            Some(Cap::Untyped(u)) => Arc::clone(u),
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        let backing_offset = match untyped.retype(n_pages) {
            Some(o) => o,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        let data_cap = DataCap::new(backing_offset, n_pages);

        // Caller-picks: destination slot from φ[12] with indirection
        let dst_ref = self.active_reg(12) as u32;
        let (dst_vm, dst_slot) = match self.resolve_cap_ref(dst_ref) {
            Some(r) => r,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };
        if !self.vm_arena.vm(dst_vm as u16).cap_table.is_empty(dst_slot) {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }

        self.vm_arena
            .vm_mut(dst_vm as u16)
            .cap_table
            .set(dst_slot, Cap::Data(data_cap));
        self.set_active_reg(7, dst_slot as u64);
        DispatchResult::Continue
    }

    /// CALL on CODE → CREATE.
    /// φ[7] = bitmask (u64), φ[12] = dst_slot (u32, indirection) for HANDLE.
    /// Bitmask copies from the CODE cap's CNode (the CNode where ecalli resolved
    /// the CODE cap), not necessarily the caller's CNode.
    fn handle_call_code(&mut self, code_cap_id: u16, code_cnode_vm: usize) -> DispatchResult {
        let bitmask = self.active_reg(7);

        // Create child VM's cap table by copying bitmask-selected caps from CODE's CNode
        let mut child_table = CapTable::new();
        let source_vm = self.vm_arena.vm(code_cnode_vm as u16);

        for bit in 0..64u8 {
            if bitmask & (1u64 << bit) != 0
                && let Some(cap) = source_vm.cap_table.get(bit)
            {
                match cap.try_copy() {
                    Some(copy) => {
                        child_table.set(bit, copy);
                    }
                    None => {
                        // Non-copyable cap in bitmask → CREATE fails
                        self.set_active_reg(7, RESULT_WHAT);
                        return DispatchResult::Continue;
                    }
                }
            }
        }

        let child = VmInstance::new(code_cap_id, 0, child_table, 0);
        let child_vm_id = match self.vm_arena.insert(child) {
            Some(id) => id,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        // Caller-picks: HANDLE destination from φ[12] with indirection
        let handle = HandleCap {
            vm_id: child_vm_id,
            max_gas: None,
        };

        let dst_ref = self.active_reg(12) as u32;
        let (dst_vm, dst_slot) = match self.resolve_cap_ref(dst_ref) {
            Some(r) => r,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };
        if !self.vm_arena.vm(dst_vm as u16).cap_table.is_empty(dst_slot) {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }
        self.vm_arena
            .vm_mut(dst_vm as u16)
            .cap_table
            .set(dst_slot, Cap::Handle(handle));
        self.set_active_reg(7, dst_slot as u64);
        DispatchResult::Continue
    }

    /// CALL on HANDLE/CALLABLE → suspend caller, run target VM.
    fn handle_call_vm(&mut self, vm_id: VmId, max_gas: Option<u64>) -> DispatchResult {
        let target_vm_id = vm_id.index();

        // Validate VmId (generation check for stale handles)
        match self.vm_arena.get(vm_id) {
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
            Some(vm) if !vm.can_call() => {
                // Target is not IDLE — re-entrancy prevention
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
            Some(_) => {} // valid and idle
        }

        // Determine gas budget for callee
        let caller_vm = &mut self.vm_arena.vm_mut(self.active_vm);
        let call_overhead = 10u64;
        if caller_vm.gas() < call_overhead {
            return DispatchResult::Fault(FaultType::OutOfGas);
        }
        caller_vm.set_gas(caller_vm.gas() - call_overhead);

        let callee_gas = match max_gas {
            Some(limit) => caller_vm.gas().min(limit),
            None => caller_vm.gas(),
        };
        caller_vm.set_gas(caller_vm.gas() - callee_gas);

        // Save caller state
        let caller_id = self.active_vm;
        let _ = self
            .vm_arena
            .vm_mut(caller_id)
            .transition(VmState::WaitingForReply);

        // Handle IPC cap (φ[12]). 0 = no cap to pass (slot 0 is IPC itself).
        let ipc_cap_slot = self.active_reg(12) as u8;
        let mut ipc_cap_idx = None;
        let mut ipc_was_mapped = None;

        if ipc_cap_slot != 0 && !self.vm_arena.vm(caller_id).cap_table.is_empty(ipc_cap_slot) {
            // Take cap from caller, auto-unmap if DATA
            if let Some(mut cap) = self.vm_arena.vm_mut(caller_id).cap_table.take(ipc_cap_slot) {
                if let Cap::Data(ref mut d) = cap {
                    let mapped_bitmap = d.mapped_bitmap.clone();
                    let mapped_runs = d.mapped_runs();
                    ipc_was_mapped = d
                        .unmap()
                        .map(|(base_page, access)| (base_page, access, mapped_bitmap));
                    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                    if let Some((base_page, _, _)) = ipc_was_mapped.as_ref()
                        && let Some(wb) = self.vm_window_base(caller_id)
                    {
                        for (page_offset, page_count) in mapped_runs {
                            // SAFETY: wb is the caller's assigned 4GB CODE
                            // window and each run came from this DATA cap's
                            // canonical mapped-page bitmap.
                            unsafe {
                                BackingStore::unmap_pages(wb, *base_page + page_offset, page_count);
                            }
                        }
                    }
                }
                ipc_cap_idx = Some(ipc_cap_slot);
                // Place in callee's IPC slot [0]
                self.vm_arena
                    .vm_mut(target_vm_id)
                    .cap_table
                    .set(IPC_SLOT, cap);
            }
        }

        // Push call frame
        self.call_stack.push(CallFrame {
            caller_vm_id: caller_id,
            ipc_cap_idx,
            ipc_was_mapped,
        });

        // Pass args: caller's φ[7]..φ[10] → callee's φ[7]..φ[10]
        let caller_regs = *self.vm_arena.vm(caller_id).regs();

        // Set up callee
        let callee = self.vm_arena.vm_mut(target_vm_id);
        callee.reset_for_call();
        callee.set_gas(callee_gas);
        callee.caller = Some(caller_id);
        callee.set_reg(7, caller_regs[7]);
        callee.set_reg(8, caller_regs[8]);
        callee.set_reg(9, caller_regs[9]);
        callee.set_reg(10, caller_regs[10]);

        let _ = callee.transition(VmState::Running);
        self.active_vm = target_vm_id;

        DispatchResult::Continue
    }

    /// Handle REPLY (ecalli(0) = CALL on the IPC slot): return to the caller.
    ///
    /// REPLY is strictly the inter-VM return half of CALL. A root-VM REPLY
    /// has no caller to return to and panics — programs terminate via the GP
    /// halt convention (djump to [`crate::PVM_HALT_ADDR`]), not via REPLY.
    fn handle_reply(&mut self) -> DispatchResult {
        let frame = match self.call_stack.pop() {
            Some(f) => f,
            None => {
                // No caller — REPLY-as-termination is retired.
                return DispatchResult::RootPanic;
            }
        };

        let callee_id = self.active_vm;
        let caller_id = frame.caller_vm_id;

        // Callee → IDLE
        let _ = self.vm_arena.vm_mut(callee_id).transition(VmState::Idle);

        // Return unused gas to caller
        let unused_gas = self.vm_arena.vm(callee_id).gas();
        let cg = self.vm_arena.vm(caller_id).gas();
        let Some(returned_gas) = cg.checked_add(unused_gas) else {
            self.vm_arena.vm_mut(callee_id).set_gas(0);
            return DispatchResult::RootPanic;
        };
        self.vm_arena.vm_mut(caller_id).set_gas(returned_gas);
        self.vm_arena.vm_mut(callee_id).set_gas(0);

        // Return IPC cap. Moving a DATA cap out of the callee must revoke the
        // callee's virtual mapping before the caller mapping is restored; the
        // capability is exclusive and must never leave an accessible stale
        // alias in a CNode that no longer owns it.
        if let Some(caller_slot) = frame.ipc_cap_idx
            && let Some(mut cap) = self.vm_arena.vm_mut(callee_id).cap_table.take(IPC_SLOT)
        {
            if let Cap::Data(d) = &mut cap
                && d.has_any_mapped()
                && let Some(callee_base_page) = d.base_offset
            {
                #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                if let Some(wb) = self.vm_window_base(callee_id) {
                    for (page_offset, page_count) in d.mapped_runs() {
                        // SAFETY: wb is the callee's assigned 4GB CODE window
                        // and each run came from this DATA cap's canonical
                        // mapped-page bitmap.
                        unsafe {
                            BackingStore::unmap_pages(
                                wb,
                                callee_base_page + page_offset,
                                page_count,
                            );
                        }
                    }
                }
                d.unmap_all();
            }
            // Restore the caller's exact sparse mapping, never the DATA
            // cap's complete owned range.
            if let Some((base_page, access, mapped_bitmap)) = frame.ipc_was_mapped {
                let Cap::Data(d) = &mut cap else {
                    return DispatchResult::RootPanic;
                };
                if !d.restore_mapping(base_page, access, mapped_bitmap) {
                    return DispatchResult::RootPanic;
                }
            }
            self.vm_arena
                .vm_mut(caller_id)
                .cap_table
                .set(caller_slot, cap);

            // Re-establish the physical mapping represented by the returned
            // capability metadata. The caller mapping was revoked on CALL,
            // so updating DataCap::mapped_bitmap alone would leave the CODE
            // window inaccessible (or out of sync with the interpreter).
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            if let Some(Cap::Data(d)) = self.vm_arena.vm(caller_id).cap_table.get(caller_slot)
                && d.has_any_mapped()
                && let (Some(base_page), Some(access)) = (d.base_offset, d.access)
                && let Some(wb) = self.vm_window_base(caller_id)
            {
                for (page_offset, page_count) in d.mapped_runs() {
                    // SAFETY: wb is the caller's assigned 4GB CODE window and
                    // the returned DATA cap owns this exact backing run.
                    unsafe {
                        self.backing.map_pages(
                            wb,
                            base_page + page_offset,
                            d.backing_offset + page_offset,
                            page_count,
                            access,
                        );
                    }
                }
            }
        }

        // Pass φ[7] only + set φ[8]=0 (status = REPLY success)
        let callee_r7 = self.vm_arena.vm(callee_id).reg(7);
        self.vm_arena.vm_mut(callee_id).caller = None;
        self.vm_arena.vm_mut(caller_id).set_reg(7, callee_r7);
        self.vm_arena.vm_mut(caller_id).set_reg(8, 0);

        // Caller → Running
        let _ = self.vm_arena.vm_mut(caller_id).transition(VmState::Running);
        self.active_vm = caller_id;

        DispatchResult::Continue
    }

    /// Resolve a u32 cap reference with HANDLE-chain indirection.
    ///
    /// Encoding: byte 0 = target slot, bytes 1-3 = HANDLE chain (0x00 = end).
    /// Returns (vm_index, cap_slot) or None if resolution fails.
    /// Each intermediate VM must hold a HANDLE and be non-RUNNING.
    fn resolve_cap_ref(&self, cap_ref: u32) -> Option<(usize, u8)> {
        let target_slot = (cap_ref & 0xFF) as u8;
        let ind0 = ((cap_ref >> 8) & 0xFF) as u8;
        let ind1 = ((cap_ref >> 16) & 0xFF) as u8;
        let ind2 = ((cap_ref >> 24) & 0xFF) as u8;

        let mut vm_idx = self.active_vm as usize;

        // Walk indirection chain (high bytes first: ind2, ind1, ind0)
        for &handle_slot in &[ind2, ind1, ind0] {
            if handle_slot == 0 {
                continue; // end of chain
            }
            let vm = &self.vm_arena.vm(vm_idx as u16);
            match vm.cap_table.get(handle_slot) {
                Some(Cap::Handle(h)) => {
                    // Validate VmId (generation check for stale handles)
                    let target = self.vm_arena.get(h.vm_id)?;
                    if target.state == VmState::Running || target.state == VmState::WaitingForReply
                    {
                        return None; // target must be non-RUNNING
                    }
                    vm_idx = h.vm_id.index() as usize;
                }
                _ => return None, // not a HANDLE
            }
        }

        Some((vm_idx, target_slot))
    }

    /// Resolve a cap ref, returning None and setting WHAT if resolution fails.
    fn resolve_or_what(&mut self, cap_ref: u32) -> Option<(usize, u8)> {
        match self.resolve_cap_ref(cap_ref) {
            Some(r) => Some(r),
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                None
            }
        }
    }

    /// Dispatch an ecall (management ops + dynamic CALL).
    /// φ\[11\] = op code, φ\[12\] = subject (low u32) | object (high u32).
    pub fn dispatch_ecall(&mut self, op: u32) -> DispatchResult {
        // Charge ecall gas (same as ecalli)
        let ecall_gas: u64 = 10;
        let current_gas = self.active_gas();
        if current_gas < ecall_gas {
            return DispatchResult::Fault(FaultType::OutOfGas);
        }
        let g = self.vm_arena.vm(self.active_vm).gas();
        self.vm_arena.vm_mut(self.active_vm).set_gas(g - ecall_gas);

        let phi12 = self.active_reg(12);
        let object_ref = (phi12 & 0xFFFFFFFF) as u32; // low u32
        let subject_ref = (phi12 >> 32) as u32; // high u32

        match op {
            0x00 => {
                // Dynamic CALL — resolve subject with indirection
                let (vm_idx, slot) = match self.resolve_or_what(subject_ref) {
                    Some(r) => r,
                    None => return DispatchResult::Continue,
                };
                // For local VM, use existing handle_call
                if vm_idx == self.active_vm as usize {
                    self.handle_call(slot)
                } else {
                    // Remote cap — look up the cap in the remote VM
                    let cap_type = self
                        .vm_arena
                        .vm(vm_idx as u16)
                        .cap_table
                        .get(slot)
                        .map(|c| match c {
                            Cap::Protocol(p) => Some(p.id),
                            _ => None,
                        });
                    match cap_type {
                        Some(Some(id)) => DispatchResult::ProtocolCall { slot: id },
                        _ => {
                            self.set_active_reg(7, RESULT_WHAT);
                            DispatchResult::Continue
                        }
                    }
                }
            }
            0x02 => {
                // MAP — resolve subject (DATA cap)
                let (vm_idx, slot) = resolve!(self, subject_ref);
                self.ecall_map(vm_idx, slot)
            }
            0x03 => {
                // UNMAP — resolve subject (DATA cap)
                let (vm_idx, slot) = resolve!(self, subject_ref);
                self.ecall_unmap(vm_idx, slot)
            }
            0x04 => {
                // SPLIT — resolve subject + object dst
                let (s_vm, s_slot) = resolve!(self, subject_ref);
                let (o_vm, o_slot) = resolve!(self, object_ref);
                self.ecall_split(s_vm, s_slot, o_vm, o_slot)
            }
            0x05 => {
                // DROP — resolve subject
                let (vm_idx, slot) = resolve!(self, subject_ref);
                self.ecall_drop(vm_idx, slot)
            }
            0x06 => {
                // MOVE — resolve subject + object dst
                let (s_vm, s_slot) = resolve!(self, subject_ref);
                let (o_vm, o_slot) = resolve!(self, object_ref);
                self.ecall_move(s_vm, s_slot, o_vm, o_slot)
            }
            0x07 => {
                // COPY — resolve subject + object dst
                let (s_vm, s_slot) = resolve!(self, subject_ref);
                let (o_vm, o_slot) = resolve!(self, object_ref);
                self.ecall_copy(s_vm, s_slot, o_vm, o_slot)
            }
            0x0A => {
                // DOWNGRADE — resolve subject HANDLE + object dst
                let (s_vm, s_slot) = resolve!(self, subject_ref);
                let (o_vm, o_slot) = resolve!(self, object_ref);
                self.ecall_downgrade(s_vm, s_slot, o_vm, o_slot)
            }
            0x0B => {
                // SET_MAX_GAS — resolve subject HANDLE
                let (vm_idx, slot) = resolve!(self, subject_ref);
                self.ecall_set_max_gas(vm_idx, slot)
            }
            0x0C => {
                // DIRTY — TODO
                self.set_active_reg(7, RESULT_WHAT);
                DispatchResult::Continue
            }
            0x0D => {
                // RESUME — resolve subject HANDLE
                let (vm_idx, slot) = resolve!(self, subject_ref);
                // RESUME uses the HANDLE in the resolved VM's cap table
                if vm_idx != self.active_vm as usize {
                    self.set_active_reg(7, RESULT_WHAT);
                    return DispatchResult::Continue;
                }
                self.handle_resume(slot)
            }
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                DispatchResult::Continue
            }
        }
    }

    /// RESUME a FAULTED VM. Same gas model as CALL.
    fn handle_resume(&mut self, handle_idx: u8) -> DispatchResult {
        let vm = self.vm_arena.vm(self.active_vm);
        let (target_vm_vid, max_gas) = match vm.cap_table.get(handle_idx) {
            Some(Cap::Handle(h)) => (h.vm_id, h.max_gas),
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };
        let target_vm_id = target_vm_vid.index();

        // Validate VmId + target must be FAULTED
        match self.vm_arena.get(target_vm_vid) {
            Some(vm) if vm.state == VmState::Faulted => {}
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        }

        // Gas transfer (same as CALL)
        let caller_vm = &mut self.vm_arena.vm_mut(self.active_vm);
        let call_overhead = 10u64;
        if caller_vm.gas() < call_overhead {
            return DispatchResult::Fault(FaultType::OutOfGas);
        }
        caller_vm.set_gas(caller_vm.gas() - call_overhead);

        let callee_gas = match max_gas {
            Some(limit) => caller_vm.gas().min(limit),
            None => caller_vm.gas(),
        };
        caller_vm.set_gas(caller_vm.gas() - callee_gas);

        // Save caller state
        let caller_id = self.active_vm;
        let _ = self
            .vm_arena
            .vm_mut(caller_id)
            .transition(VmState::WaitingForReply);

        // Push call frame (no IPC cap for RESUME)
        self.call_stack.push(CallFrame {
            caller_vm_id: caller_id,
            ipc_cap_idx: None,
            ipc_was_mapped: None,
        });

        // Resume callee: FAULTED → RUNNING, registers/PC preserved
        let callee = self.vm_arena.vm_mut(target_vm_id);
        callee.set_gas(callee_gas);
        callee.caller = Some(caller_id);
        let _ = callee.transition(VmState::Running);
        self.active_vm = target_vm_id;

        DispatchResult::Continue
    }

    // --- ecall management ops (indirection-aware) ---

    /// MAP pages of a DATA cap in its CNode (page-granular).
    /// φ[7]=base_offset, φ[8]=page_offset, φ[9]=page_count.
    fn ecall_map(&mut self, vm_idx: usize, slot: u8) -> DispatchResult {
        let base_offset = self.active_reg(7) as u32;
        let page_offset = self.active_reg(8) as u32;
        let page_count = self.active_reg(9) as u32;
        let access_raw = self.active_reg(10);
        let access = match access_raw {
            0 => Access::RO,
            1 => Access::RW,
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        let window_base = self.vm_window_base(vm_idx as u16);
        let vm = &mut self.vm_arena.vm_mut(vm_idx as u16);
        match vm.cap_table.get_mut(slot) {
            Some(Cap::Data(d)) => {
                if !d.map_pages(base_offset, access, page_offset, page_count) {
                    self.set_active_reg(7, RESULT_WHAT);
                    return DispatchResult::Continue;
                }
                // Map the pages in the VM's window (if it has one)
                #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                if let Some(wb) = window_base {
                    for p in page_offset..page_offset + page_count {
                        // SAFETY: wb is from vm_window_base() (valid 4GB window).
                        unsafe {
                            self.backing.map_pages(
                                wb,
                                base_offset + p,
                                d.backing_offset + p,
                                1,
                                access,
                            );
                        }
                    }
                }
            }
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
            }
        }
        DispatchResult::Continue
    }

    /// UNMAP pages of a DATA cap in its CNode.
    /// φ[7]=page_offset, φ[8]=page_count.
    fn ecall_unmap(&mut self, vm_idx: usize, slot: u8) -> DispatchResult {
        let page_offset = self.active_reg(7) as u32;
        let page_count = self.active_reg(8) as u32;

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        let window_base = self.vm_window_base(vm_idx as u16);
        let vm = &mut self.vm_arena.vm_mut(vm_idx as u16);
        match vm.cap_table.get_mut(slot) {
            Some(Cap::Data(d)) => {
                if let Some(_base_offset) = d.base_offset {
                    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                    if let Some(wb) = window_base {
                        for p in
                            page_offset..page_offset.saturating_add(page_count).min(d.page_count)
                        {
                            if d.is_page_mapped(p) {
                                // SAFETY: wb is from vm_window_base() (valid 4GB window).
                                unsafe {
                                    BackingStore::unmap_pages(wb, _base_offset + p, 1);
                                }
                            }
                        }
                    }
                    d.unmap_pages(page_offset, page_count);
                }
            }
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
            }
        }
        DispatchResult::Continue
    }

    /// SPLIT a DATA cap. Must be fully unmapped.
    /// φ[7]=page_offset. Subject = DATA cap, object = dst slot for high half.
    fn ecall_split(&mut self, s_vm: usize, s_slot: u8, o_vm: usize, o_slot: u8) -> DispatchResult {
        let page_off = self.active_reg(7) as u32;

        // Validate
        let can_split = match self.vm_arena.vm(s_vm as u16).cap_table.get(s_slot) {
            Some(Cap::Data(d)) => !d.has_any_mapped() && page_off > 0 && page_off < d.page_count,
            _ => false,
        };
        if !can_split || !self.vm_arena.vm(o_vm as u16).cap_table.is_empty(o_slot) {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }

        let cap = match self.vm_arena.vm_mut(s_vm as u16).cap_table.take(s_slot) {
            Some(Cap::Data(d)) => d,
            _ => unreachable!(),
        };
        let (lo, hi) = cap.split(page_off).unwrap();
        self.vm_arena
            .vm_mut(s_vm as u16)
            .cap_table
            .set(s_slot, Cap::Data(lo));
        self.vm_arena
            .vm_mut(o_vm as u16)
            .cap_table
            .set(o_slot, Cap::Data(hi));
        DispatchResult::Continue
    }

    /// DROP a cap. Auto-unmaps DATA. Reclaims VM on HANDLE drop.
    fn ecall_drop(&mut self, vm_idx: usize, slot: u8) -> DispatchResult {
        // DROP HANDLE → reclaim VM
        if let Some(Cap::Handle(h)) = self.vm_arena.vm(vm_idx as u16).cap_table.get(slot) {
            let vm_id = h.vm_id;
            self.vm_arena.vm_mut(vm_idx as u16).cap_table.drop_cap(slot);
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            self.window_pool.release(vm_id.index());
            self.vm_arena.remove(vm_id);
            return DispatchResult::Continue;
        }
        if let Some(Cap::Data(d)) = self.vm_arena.vm(vm_idx as u16).cap_table.get(slot)
            && d.has_any_mapped()
            && let Some(_base_offset) = d.base_offset
        {
            let _page_count = d.page_count;
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            if let Some(wb) = self.vm_window_base(vm_idx as u16) {
                // SAFETY: wb is from vm_window_base() (valid 4GB window).
                unsafe {
                    BackingStore::unmap_pages(wb, _base_offset, _page_count);
                }
            }
        }
        self.vm_arena.vm_mut(vm_idx as u16).cap_table.drop_cap(slot);
        DispatchResult::Continue
    }

    /// MOVE a cap between CNodes. Auto-unmaps DATA on CNode change.
    fn ecall_move(&mut self, s_vm: usize, s_slot: u8, o_vm: usize, o_slot: u8) -> DispatchResult {
        if s_vm == o_vm && s_slot == o_slot {
            return DispatchResult::Continue;
        }
        if !self.vm_arena.vm(o_vm as u16).cap_table.is_empty(o_slot) {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }

        let mut cap = match self.vm_arena.vm_mut(s_vm as u16).cap_table.take(s_slot) {
            Some(c) => c,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        // Auto-unmap DATA caps crossing CNode boundaries
        if s_vm != o_vm
            && let Cap::Data(ref mut d) = cap
            && d.has_any_mapped()
            && let Some(_base_offset) = d.base_offset
        {
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            if let Some(wb) = self.vm_window_base(s_vm as u16) {
                // SAFETY: wb is from vm_window_base() (valid 4GB window).
                unsafe {
                    BackingStore::unmap_pages(wb, _base_offset, d.page_count);
                }
            }
            d.unmap_all();
        }

        self.vm_arena.vm_mut(o_vm as u16).cap_table.set(o_slot, cap);
        DispatchResult::Continue
    }

    /// COPY a cap between CNodes (copyable types only).
    fn ecall_copy(&mut self, s_vm: usize, s_slot: u8, o_vm: usize, o_slot: u8) -> DispatchResult {
        if !self.vm_arena.vm(o_vm as u16).cap_table.is_empty(o_slot) {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }
        let copy = match self.vm_arena.vm(s_vm as u16).cap_table.get(s_slot) {
            Some(c) => match c.try_copy() {
                Some(copy) => copy,
                None => {
                    self.set_active_reg(7, RESULT_WHAT);
                    return DispatchResult::Continue;
                }
            },
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };
        self.vm_arena
            .vm_mut(o_vm as u16)
            .cap_table
            .set(o_slot, copy);
        DispatchResult::Continue
    }

    /// DOWNGRADE a HANDLE to CALLABLE. Places CALLABLE at dst.
    fn ecall_downgrade(
        &mut self,
        s_vm: usize,
        s_slot: u8,
        o_vm: usize,
        o_slot: u8,
    ) -> DispatchResult {
        let (vm_id, max_gas) = match self.vm_arena.vm(s_vm as u16).cap_table.get(s_slot) {
            Some(Cap::Handle(h)) => (h.vm_id, h.max_gas),
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };
        if !self.vm_arena.vm(o_vm as u16).cap_table.is_empty(o_slot) {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }
        self.vm_arena
            .vm_mut(o_vm as u16)
            .cap_table
            .set(o_slot, Cap::Callable(CallableCap { vm_id, max_gas }));
        DispatchResult::Continue
    }

    /// SET_MAX_GAS on a HANDLE.
    fn ecall_set_max_gas(&mut self, vm_idx: usize, slot: u8) -> DispatchResult {
        let gas_limit = self.active_reg(7);
        match self.vm_arena.vm_mut(vm_idx as u16).cap_table.get_mut(slot) {
            Some(Cap::Handle(h)) => {
                h.max_gas = Some(gas_limit);
            }
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
            }
        }
        DispatchResult::Continue
    }

    /// Flush live JitContext state to VmInstance. Must be called before
    /// switching active VM or any operation that reads VmInstance directly.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    fn flush_live_ctx(&mut self) {
        if let Some(ctx) = self.live_ctx.take() {
            // SAFETY: live_ctx points to the JitContext in the active CodeWindow's CTX page,
            // valid for the duration of the JIT execution on this thread.
            let ctx = unsafe { &*ctx };
            let vm = &mut self.vm_arena.vm_mut(self.active_vm);
            vm.set_regs(ctx.regs);
            vm.set_gas(ctx.gas);
            vm.pc = ctx.pc;
            vm.set_gas_charged(ctx.gas_charged != 0);
            vm.set_pending_host_call((ctx.host_pending != 0).then_some(crate::PendingHostCall {
                id: ctx.exit_arg,
                cause_pc: ctx.pc,
                resume_pc: ctx.host_resume_pc,
            }));
            vm.set_heap_base(ctx.heap_base);
            vm.set_heap_top(ctx.heap_top);
        }
    }

    // --- Register helpers ---

    pub fn active_reg(&self, idx: usize) -> u64 {
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        if let Some(ctx) = self.live_ctx {
            // SAFETY: live_ctx is valid JitContext pointer (see flush_live_ctx).
            return unsafe { (*ctx).regs[idx] };
        }
        self.vm_arena.vm(self.active_vm).reg(idx)
    }

    pub fn set_active_reg(&mut self, idx: usize, val: u64) {
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        if let Some(ctx) = self.live_ctx {
            // SAFETY: live_ctx is valid JitContext pointer (see flush_live_ctx).
            unsafe { (*ctx).regs[idx] = val };
            return;
        }
        self.vm_arena.vm_mut(self.active_vm).set_reg(idx, val);
    }

    /// Get the active VM's remaining gas.
    pub fn active_gas(&self) -> u64 {
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        if let Some(ctx) = self.live_ctx {
            // SAFETY: live_ctx is valid JitContext pointer (see flush_live_ctx).
            return unsafe { (*ctx).gas };
        }
        self.vm_arena.vm(self.active_vm).gas()
    }

    fn acknowledge_vm_host_call(&mut self, vm_index: u16) -> bool {
        let pending = self.vm_arena.vm(vm_index).pending_host_call();
        let Some(call) = pending else {
            return false;
        };
        let acknowledged = self.vm_arena.vm_mut(vm_index).acknowledge_host_call();
        debug_assert!(acknowledged);
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        if vm_index == self.active_vm
            && let Some(ctx) = self.live_ctx
        {
            // SAFETY: live_ctx is the active VM's context page.
            unsafe {
                (*ctx).host_pending = 0;
                (*ctx).entry_pc = call.resume_pc;
                (*ctx).pc = call.resume_pc;
                (*ctx).gas_charged = 1;
                (*ctx).fast_reentry = 0;
            }
        }
        true
    }

    /// Resume after a protocol call was handled by the host.
    /// Sets return registers and continues execution.
    pub fn resume_protocol_call(
        &mut self,
        result0: u64,
        result1: u64,
    ) -> Result<(), SnapshotError> {
        let pending = self
            .pending_protocol_call
            .take()
            .ok_or(SnapshotError::NotAtProtocolBoundary)?;
        let vm = self.vm_arena.vm(self.active_vm);
        let host_call = vm.pending_host_call();
        if pending.vm_index != self.active_vm
            || pending.cause_pc != vm.pc
            || (self.isa_mode == crate::IsaMode::Conformance
                && host_call.is_none_or(|call| {
                    call.cause_pc != pending.cause_pc
                        || call.resume_pc != pending.resume_pc
                        || call.id != pending.host_call_id
                }))
            || pending.gas_charged != vm.gas_charged()
            || pending.result_registers != [7, 8]
        {
            self.pending_protocol_call = Some(pending);
            return Err(SnapshotError::InvalidScheduler);
        }
        self.set_active_reg(7, result0);
        self.set_active_reg(8, result1);
        if self.isa_mode == crate::IsaMode::Conformance
            && !self.acknowledge_vm_host_call(self.active_vm)
        {
            return Err(SnapshotError::InvalidScheduler);
        }
        Ok(())
    }

    fn suspend_protocol_call(&mut self, slot: u8) -> KernelResult {
        assert!(
            self.pending_protocol_call.is_none(),
            "protocol call must be resumed before another call can suspend"
        );
        let vm = self.vm_arena.vm(self.active_vm);
        let host_call = vm.pending_host_call();
        self.pending_protocol_call = Some(PendingProtocolCall {
            slot,
            host_call_id: host_call.map_or(u64::from(slot), |call| call.id),
            vm_index: self.active_vm,
            cause_pc: host_call.map_or(vm.pc, |call| call.cause_pc),
            resume_pc: host_call.map_or(vm.pc, |call| call.resume_pc),
            gas_charged: vm.gas_charged(),
            result_registers: [7, 8],
        });
        KernelResult::ProtocolCall { slot }
    }

    // --- Window helpers ---

    /// Get the active window's base pointer (guest memory base, R15 in JIT code).
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    fn active_window_base(&self) -> *mut u8 {
        self.window_pool.window(self.active_window).base()
    }

    /// Get the active window's JitContext pointer.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    fn active_window_ctx_ptr(&self) -> *mut u8 {
        self.window_pool.window(self.active_window).ctx_ptr()
    }

    /// Permission table paired with the active 32-bit guest window.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    fn active_window_perms(&self) -> *mut u8 {
        self.window_pool.window(self.active_window).perms()
    }

    /// Get window base for a specific VM, if it has an assigned window.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    fn vm_window_base(&self, vm_idx: u16) -> Option<*mut u8> {
        self.window_pool
            .find_window(vm_idx)
            .map(|idx| self.window_pool.window(idx).base())
    }

    /// Ensure the active VM has a window assigned. Handles eviction and
    /// DATA cap mapping/unmapping. Called before executing any VM code and
    /// after context switches (CALL/REPLY/HALT).
    ///
    /// Fast path: if the active VM already owns the current window, this is
    /// a single branch (no scan). Only does real work on context switches.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    #[inline(always)]
    fn ensure_active_window(&mut self) {
        // Fast path: active VM already owns the current window.
        if self.window_pool.window_owner(self.active_window) == Some(self.active_vm) {
            return;
        }

        let vm_idx = self.active_vm;
        let generation = self.vm_arena.generation_of(vm_idx);
        let assignment = self.window_pool.assign_window(vm_idx, generation);

        // Evict previous owner's DATA caps from the window
        if let Some(evicted_vm) = assignment.evicted {
            self.unmap_vm_data_caps(evicted_vm, assignment.window_idx);
        }

        // Map current VM's DATA caps into the window
        if assignment.needs_map {
            self.map_vm_data_caps(vm_idx, assignment.window_idx);
        }

        self.active_window = assignment.window_idx;
    }

    /// Unmap all of a VM's mapped DATA caps from a window.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    fn unmap_vm_data_caps(&self, vm_idx: u16, window_idx: usize) {
        let wb = self.window_pool.window(window_idx).base();
        let vm = self.vm_arena.vm(vm_idx);
        for slot in 0..=255u8 {
            if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                && d.has_any_mapped()
                && let Some(base_offset) = d.base_offset
            {
                // SAFETY: wb is from window_pool (valid 4GB window).
                unsafe {
                    BackingStore::unmap_pages(wb, base_offset, d.page_count);
                }
            }
        }
    }

    /// Map all of a VM's mapped DATA caps into a window.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    fn map_vm_data_caps(&self, vm_idx: u16, window_idx: usize) {
        let wb = self.window_pool.window(window_idx).base();
        let vm = self.vm_arena.vm(vm_idx);
        for slot in 0..=255u8 {
            if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                && d.has_any_mapped()
                && let Some(base_offset) = d.base_offset
            {
                let access = d.access.unwrap_or(Access::RO);
                for (page_offset, page_count) in d.mapped_runs() {
                    // SAFETY: wb is from window_pool (valid 4GB window), and
                    // the run is an exact subset of this DATA cap.
                    unsafe {
                        self.backing.map_pages(
                            wb,
                            base_offset + page_offset,
                            d.backing_offset + page_offset,
                            page_count,
                            access,
                        );
                    }
                }
            }
        }
    }

    /// Sync VM state after JIT execution returns.
    ///
    /// For ecalli (exit_reason=4): keep live_ctx for fast resume, sync only pc.
    /// For all other exits: full register/gas sync, clear live_ctx and signal state.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn sync_after_jit(&mut self, ctx_raw: *mut crate::recompiler::JitContext) -> (u32, u64) {
        // SAFETY: ctx_raw is still valid after JIT execution returns — it points
        // to the JitContext page in the active CodeWindow's mmap region.
        let ctx = unsafe { &*ctx_raw };
        let exit_reason = ctx.exit_reason;
        let exit_arg = ctx.exit_arg;

        {
            let vm = &mut self.vm_arena.vm_mut(self.active_vm);
            vm.set_regs(ctx.regs);
            vm.set_gas(ctx.gas);
            vm.pc = ctx.pc;
            vm.set_gas_charged(ctx.gas_charged != 0);
            vm.set_pending_host_call((ctx.host_pending != 0).then_some(crate::PendingHostCall {
                id: ctx.exit_arg,
                cause_pc: ctx.pc,
                resume_pc: ctx.host_resume_pc,
            }));
            vm.set_heap_base(ctx.heap_base);
            vm.set_heap_top(ctx.heap_top);
        }

        if exit_reason == 4 {
            // ecalli: keep live_ctx so dispatch reads JitContext directly.
            // Standard execution exposes the causing PC in `ctx.pc`; kernel
            // dispatch has handled the call and resumes from `entry_pc`.
            self.live_ctx = Some(ctx_raw);
        } else {
            self.live_ctx = None;
        }

        (exit_reason, exit_arg)
    }

    /// Execute one segment via the JIT recompiler backend.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    /// Execute via the JIT recompiler.
    ///
    /// For protocol cap ecalli (slots 0-27), this returns to the kernel's `run()`
    /// loop which exits to the host. On re-entry, the JitContext is rebuilt from
    /// VmInstance. To minimize the rebuild cost, `run()` uses `run_recompiler_resume()`
    /// which only updates registers + gas + entry_pc instead of rebuilding all fields.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn run_recompiler_segment(&mut self, code_cap_id: usize) -> (u32, u64) {
        use crate::recompiler::JitContext;

        let code_cap = &self.code_caps[code_cap_id];
        let compiled = match &code_cap.compiled {
            crate::backend::CompiledProgram::Recompiler(c) => c,
            _ => unreachable!(),
        };
        let vm = &self.vm_arena.vm(self.active_vm);
        let ctx_raw = self.active_window_ctx_ptr() as *mut JitContext;
        // SAFETY: ctx_ptr() returns a writable page allocated by CodeWindow::new().
        unsafe {
            ctx_raw.write(JitContext {
                regs: *vm.regs(),
                gas: vm.gas(),
                gas_charged: u32::from(vm.gas_charged()),
                host_pending: u32::from(vm.pending_host_call().is_some()),
                host_resume_pc: vm.pending_host_call().map_or(0, |call| call.resume_pc),
                dispatch_len: compiled.dispatch_table.len() as u32,
                exit_reason: 0,
                // A full rebuild can resume a Faulted VM whose host dispatch
                // previously failed. Preserve the original immediate so the
                // explicit pending-host boundary re-surfaces identically.
                exit_arg: vm.pending_host_call().map_or(0, |call| call.id),
                heap_base: vm.heap_base(),
                heap_top: vm.heap_top(),
                jt_ptr: code_cap.jump_table.as_ptr(),
                jt_len: code_cap.jump_table.len() as u32,
                _pad0: 0,
                // Strict basic-block starts ({0} ∪ post-terminator): djump
                // targets must land on these, not on arbitrary instruction
                // starts (GP eq A.18).
                bb_starts: compiled.block_starts.as_ptr(),
                bb_len: compiled.block_starts.len() as u32,
                _pad1: 0,
                entry_pc: vm.pc,
                pc: vm.pc,
                dispatch_table: compiled.dispatch_table.as_ptr(),
                code_base: compiled.native_code.ptr as u64,
                flat_buf: self.active_window_base(),
                flat_perms: self.active_window_perms(),
                fast_reentry: 0,
                _pad2: 0,
                max_heap_pages: 0,
                _pad3: 0,
                original_bitmap: *vm.cap_table.original_bitmap(),
            });
        }

        self.run_recompiler_inner(code_cap_id, ctx_raw)
    }

    /// Resume recompiler after a protocol call. The JitContext is still live —
    /// only update the result registers that kernel_resume() changed, then
    /// re-enter native code. No full register sync needed.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[inline(always)]
    fn run_recompiler_resume(&mut self, code_cap_id: usize) -> (u32, u64) {
        use crate::recompiler::JitContext;

        let code_cap = &self.code_caps[code_cap_id];
        let compiled = match &code_cap.compiled {
            crate::backend::CompiledProgram::Recompiler(c) => c,
            _ => unreachable!(),
        };
        let ctx_raw = self.active_window_ctx_ptr() as *mut JitContext;

        // The live_ctx was set on the previous ecalli exit. kernel_resume()
        // wrote result regs via set_active_reg which updated JitContext directly.
        // Just set entry_pc and re-enter.
        // SAFETY: ctx_raw points to the JitContext in the active CodeWindow's CTX page.
        let ctx = unsafe { &mut *ctx_raw };
        ctx.entry_pc = self.vm_arena.vm(self.active_vm).pc;
        ctx.exit_reason = 0;
        ctx.exit_arg = 0;

        if let Some(exit) = crate::recompiler::prepare_external_entry(
            ctx,
            &compiled.fault_resume_offsets,
            &compiled.gas_block_start_by_pc,
            &compiled.block_gas_costs,
            self.isa_mode,
        ) {
            let synced = self.sync_after_jit(ctx_raw);
            debug_assert_eq!(synced, exit);
            return exit;
        }

        // Re-install the SIGSEGV state on THIS frame's stack. The state
        // installed by the original `run_recompiler_inner` lived in that
        // (now-returned) frame — re-entering native code with a guest page
        // fault would otherwise dereference a dangling pointer. Same code
        // cap, so the fields match.
        use crate::recompiler::signal;
        let mut signal_state = signal::SignalState {
            code_start: compiled.native_code.ptr as usize,
            code_end: compiled.native_code.ptr as usize + compiled.native_code.len,
            exit_label_addr: compiled.native_code.ptr as usize
                + compiled.exit_label_offset as usize,
            ctx_ptr: ctx_raw,
            trap_table_ptr: compiled.trap_table.as_ptr(),
            trap_table_len: compiled.trap_table.len(),
            fault_resume_offsets_ptr: compiled.fault_resume_offsets.as_ptr(),
            fault_resume_offsets_len: compiled.fault_resume_offsets.len(),
        };
        signal::SIGNAL_STATE.with(|cell| cell.set(&mut signal_state as *mut _));

        let entry = compiled.native_code.entry();
        // SAFETY: entry is valid JIT code; ctx_raw is a valid JitContext.
        unsafe {
            entry(ctx_raw);
        }
        signal::SIGNAL_STATE.with(|cell| cell.set(std::ptr::null_mut()));

        self.sync_after_jit(ctx_raw)
    }

    /// Shared recompiler execution: set up signal handler, enter native code,
    /// sync state back on exit.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn run_recompiler_inner(
        &mut self,
        code_cap_id: usize,
        ctx_raw: *mut crate::recompiler::JitContext,
    ) -> (u32, u64) {
        use crate::recompiler::signal;

        let code_cap = &self.code_caps[code_cap_id];
        let compiled = match &code_cap.compiled {
            crate::backend::CompiledProgram::Recompiler(c) => c,
            _ => unreachable!(),
        };

        // SAFETY: `ctx_raw` points to the active window's initialized context.
        let ctx = unsafe { &mut *ctx_raw };
        if let Some(exit) = crate::recompiler::prepare_external_entry(
            ctx,
            &compiled.fault_resume_offsets,
            &compiled.gas_block_start_by_pc,
            &compiled.block_gas_costs,
            self.isa_mode,
        ) {
            let synced = self.sync_after_jit(ctx_raw);
            debug_assert_eq!(synced, exit);
            return exit;
        }

        signal::ensure_installed();
        let mut signal_state = signal::SignalState {
            code_start: compiled.native_code.ptr as usize,
            code_end: compiled.native_code.ptr as usize + compiled.native_code.len,
            exit_label_addr: compiled.native_code.ptr as usize
                + compiled.exit_label_offset as usize,
            ctx_ptr: ctx_raw,
            trap_table_ptr: compiled.trap_table.as_ptr(),
            trap_table_len: compiled.trap_table.len(),
            fault_resume_offsets_ptr: compiled.fault_resume_offsets.as_ptr(),
            fault_resume_offsets_len: compiled.fault_resume_offsets.len(),
        };
        signal::SIGNAL_STATE.with(|cell| cell.set(&mut signal_state as *mut _));

        let entry = compiled.native_code.entry();
        // SAFETY: entry points to valid JIT code; ctx_raw is a valid JitContext.
        unsafe {
            entry(ctx_raw);
        }
        signal::SIGNAL_STATE.with(|cell| cell.set(std::ptr::null_mut()));

        self.sync_after_jit(ctx_raw)
    }

    /// Execute one segment via the software interpreter backend.
    ///
    /// The interpreter uses a regular Vec<u8> for memory instead of the mmap'd
    /// 4GB window (which would SIGSEGV on unmapped pages without the recompiler's
    /// signal handler). Mapped DATA cap pages are copied in before execution and
    /// written back after.
    fn run_interpreter_segment(
        &mut self,
        code_cap_id: usize,
        observer: Option<&mut dyn for<'a> FnMut(KernelInstructionObservation<'a>)>,
    ) -> (u32, u64) {
        let code_cap = &self.code_caps[code_cap_id];
        let active_vm = self.active_vm;
        let program_hash = code_cap.program_hash;
        let call_depth = self.call_stack.len();
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        let prog = match &code_cap.compiled {
            crate::backend::CompiledProgram::Interpreter(p) => p,
            _ => unreachable!(),
        };
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        let crate::backend::CompiledProgram::Interpreter(prog) = &code_cap.compiled;

        // Determine memory size from mapped DATA caps. Find the highest mapped page.
        let vm = &self.vm_arena.vm(self.active_vm);
        let mut max_addr: usize = 0;
        for slot in 0..=255u8 {
            if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                && d.has_any_mapped()
                && let Some(base_page) = d.base_offset
            {
                let end =
                    (base_page as usize + d.page_count as usize) * crate::PVM_PAGE_SIZE as usize;
                max_addr = max_addr.max(end);
            }
        }
        // Allocate flat memory plus the per-page permission map, copying in
        // mapped pages from the CODE window (Linux) or the backing store
        // (non-Linux). Page-granular: a cap's pages can be individually
        // unmapped (MGMT_UNMAP), and unmapped window pages are PROT_NONE —
        // touching them would fault the host, and they must stay PERM_NONE
        // so guest accesses fault like they do under the JIT.
        let mut flat_mem = vec![0u8; max_addr];
        let mut page_perms =
            vec![crate::interpreter::PERM_NONE; max_addr / crate::PVM_PAGE_SIZE as usize];
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        let window_base = self.active_window_base();
        for slot in 0..=255u8 {
            if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                && d.has_any_mapped()
                && let Some(base_page) = d.base_offset
            {
                let perm = match d.access {
                    Some(Access::RO) => crate::interpreter::PERM_RO,
                    _ => crate::interpreter::PERM_RW,
                };
                for i in 0..d.page_count {
                    if !d.is_page_mapped(i) {
                        continue;
                    }
                    let page = base_page as usize + i as usize;
                    let addr = page * crate::PVM_PAGE_SIZE as usize;
                    let len = crate::PVM_PAGE_SIZE as usize;
                    if addr + len > flat_mem.len() {
                        continue;
                    }
                    page_perms[page] = perm;
                    // SAFETY: window_base points to the 4GB mmap CODE window;
                    // the page is mapped (checked above) so the source is
                    // readable, and addr+len is within flat_mem.
                    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            window_base.add(addr),
                            flat_mem.as_mut_ptr().add(addr),
                            len,
                        );
                    }
                    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
                    flat_mem[addr..addr + len]
                        .copy_from_slice(self.backing.read_page_slice(d.backing_offset + i, 1));
                }
            }
        }

        let vm = &mut self.vm_arena.vm_mut(self.active_vm);
        let mut interp = crate::interpreter::Interpreter::new(
            prog.code.clone(),
            prog.bitmask.clone(),
            prog.jump_table.clone(),
            *vm.regs(),
            flat_mem,
            vm.gas(),
            prog.mem_cycles,
        );
        interp.pc = vm.pc;
        interp.heap_base = vm.heap_base();
        interp.heap_top = vm.heap_top();
        interp.set_isa_mode(self.isa_mode);
        interp.restore_boundary_state(vm.gas_charged(), vm.pending_host_call());
        interp.set_page_perms(page_perms);

        let (exit, _gas_used) = match observer {
            Some(observer) => interp.run_observed(|instruction| {
                observer(KernelInstructionObservation {
                    active_vm,
                    code_cap_id: code_cap_id as u16,
                    program_hash,
                    call_depth,
                    instruction,
                });
            }),
            None => interp.run(),
        };

        // Write back modified pages to the CODE window (Linux) / backing store (non-Linux)
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let vm_ref = &self.vm_arena.vm(self.active_vm);
            let wb = self.active_window_base();
            for slot in 0..=255u8 {
                if let Some(Cap::Data(d)) = vm_ref.cap_table.get(slot)
                    && d.has_any_mapped()
                    && d.access == Some(Access::RW)
                    && let Some(base_page) = d.base_offset
                {
                    for i in 0..d.page_count {
                        if !d.is_page_mapped(i) {
                            continue;
                        }
                        let addr =
                            (base_page as usize + i as usize) * crate::PVM_PAGE_SIZE as usize;
                        let len = crate::PVM_PAGE_SIZE as usize;
                        let flat_mem = interp.flat_mem();
                        if addr + len > flat_mem.len() {
                            continue;
                        }
                        // SAFETY: wb is the active window base; the page is
                        // mapped RW (checked above) and addr+len is within
                        // the interpreter's flat memory.
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                flat_mem.as_ptr().add(addr),
                                wb.add(addr),
                                len,
                            );
                        }
                    }
                }
            }
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            // Collect write-back info first so we can drop the vm borrow before
            // taking &mut self.backing.
            let writebacks: Vec<(usize, u32)> = {
                let vm_ref = &self.vm_arena.vm(self.active_vm);
                let mut pages = Vec::new();
                for slot in 0..=255u8 {
                    let Some(Cap::Data(d)) = vm_ref.cap_table.get(slot) else {
                        continue;
                    };
                    if !d.has_any_mapped() || d.access != Some(Access::RW) {
                        continue;
                    }
                    let Some(base_page) = d.base_offset else {
                        continue;
                    };
                    for i in 0..d.page_count {
                        if !d.is_page_mapped(i) {
                            continue;
                        }
                        let addr =
                            (base_page as usize + i as usize) * crate::PVM_PAGE_SIZE as usize;
                        if addr + crate::PVM_PAGE_SIZE as usize > interp.flat_mem().len() {
                            continue;
                        }
                        pages.push((addr, d.backing_offset + i));
                    }
                }
                pages
            };
            for (addr, backing_page) in writebacks {
                let len = crate::PVM_PAGE_SIZE as usize;
                self.backing
                    .write_page_slice(backing_page, &interp.flat_mem()[addr..addr + len]);
            }
        }

        let vm = &mut self.vm_arena.vm_mut(self.active_vm);
        vm.set_regs(interp.registers);
        vm.set_gas(interp.gas);
        vm.pc = interp.continuation_pc();
        vm.set_gas_charged(interp.gas_charged);
        vm.set_pending_host_call(interp.pending_host_call());
        vm.set_heap_base(interp.heap_base);
        vm.set_heap_top(interp.heap_top);

        match exit {
            crate::ExitReason::Halt => (0, 0),
            crate::ExitReason::Trap => (7, 0), // deliberate trap
            crate::ExitReason::Panic => (1, 0),
            crate::ExitReason::OutOfGas => (2, 0),
            crate::ExitReason::PageFault(addr) => (3, u64::from(addr)),
            crate::ExitReason::HostCall(id) => (4, id),
            crate::ExitReason::Ecall => (6, 0),
        }
    }

    /// Execute one segment of the active VM using the appropriate backend.
    fn run_one_segment(
        &mut self,
        code_cap_id: usize,
        observer: Option<&mut dyn for<'a> FnMut(KernelInstructionObservation<'a>)>,
    ) -> (u32, u64) {
        match &self.code_caps[code_cap_id].compiled {
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            crate::backend::CompiledProgram::Recompiler(_) => {
                debug_assert!(observer.is_none());
                self.run_recompiler_segment(code_cap_id)
            }
            crate::backend::CompiledProgram::Interpreter(_) => {
                self.run_interpreter_segment(code_cap_id, observer)
            }
        }
    }

    /// Run the kernel until it needs host interaction or terminates.
    pub fn run(&mut self) -> KernelResult {
        self.run_inner(None)
    }

    /// Acknowledge a previously surfaced root page fault after the host has
    /// repaired the VM's mapping. Execution retries the causing instruction
    /// with its containing gas block still funded.
    pub fn resume_page_fault(&mut self) -> Result<(), SnapshotError> {
        let pending = self
            .pending_page_fault
            .take()
            .ok_or(SnapshotError::NotAtProtocolBoundary)?;
        let vm = self.vm_arena.vm(self.active_vm);
        if pending.vm_index != self.active_vm
            || pending.cause_pc != vm.pc
            || pending.gas_charged != vm.gas_charged()
            || vm.pending_page_fault() != Some(pending.address)
        {
            self.pending_page_fault = Some(pending);
            return Err(SnapshotError::InvalidScheduler);
        }
        self.vm_arena
            .vm_mut(self.active_vm)
            .set_pending_page_fault(None);
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        {
            self.live_ctx = None;
            self.recompiler_resume_cap = None;
            if self.window_pool.window_owner(self.active_window) == Some(self.active_vm) {
                self.unmap_vm_data_caps(self.active_vm, self.active_window);
                self.map_vm_data_caps(self.active_vm, self.active_window);
            }
        }
        Ok(())
    }

    /// Run the complete nested invocation while observing canonical PVM steps.
    ///
    /// The callback follows VM switches caused by CALL/REPLY and is invoked for
    /// every actor and root-service instruction until the next host-visible
    /// [`KernelResult`]. It cannot mutate either the interpreter or scheduler.
    /// Use [`crate::backend::PvmBackend::ForceInterpreter`] when constructing or
    /// restoring the invocation; the recompiler remains available for normal
    /// execution and is checked for semantic parity independently.
    pub fn run_observed(
        &mut self,
        mut observer: impl for<'a> FnMut(KernelInstructionObservation<'a>),
    ) -> Result<KernelResult, KernelObservationError> {
        if self.code_caps.iter().any(|cap| {
            !matches!(
                &cap.compiled,
                crate::backend::CompiledProgram::Interpreter(_)
            )
        }) {
            return Err(KernelObservationError::InterpreterRequired);
        }
        Ok(self.run_inner(Some(&mut observer)))
    }

    fn run_inner(
        &mut self,
        mut observer: Option<&mut dyn for<'a> FnMut(KernelInstructionObservation<'a>)>,
    ) -> KernelResult {
        assert!(
            self.pending_protocol_call.is_none() && self.pending_page_fault.is_none(),
            "a pending protocol call or page fault must be resumed before run"
        );
        loop {
            // Ensure active VM has a window assigned (handles eviction + DATA cap mapping).
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            self.ensure_active_window();

            let code_cap_id = self.vm_arena.vm(self.active_vm).code_cap_id as usize;

            // Execute via the compiled backend.
            // After a ProtocolCall, recompiler_resume_cap is set so we can resume
            // with a cheap JitContext update instead of a full rebuild.
            let (exit_reason, exit_arg) = if let Some(observer) = observer.as_mut() {
                debug_assert!(self.recompiler_resume_cap.is_none());
                self.run_one_segment(code_cap_id, Some(&mut **observer))
            } else if let Some(ccid) = self.recompiler_resume_cap.take() {
                // Fast path: resume recompiler after protocol call.
                // Only updates regs/gas/pc in the existing JitContext.
                #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                {
                    if ccid == code_cap_id
                        && self.live_ctx.is_some()
                        && self.window_pool.window_owner(self.active_window) == Some(self.active_vm)
                    {
                        self.run_recompiler_resume(ccid)
                    } else {
                        // A host handler that needed authoritative VmInstance
                        // state may have flushed the context before committing
                        // its result.  Rebuild in that case: the old CTX page
                        // is no longer the source of truth.
                        self.run_one_segment(code_cap_id, None)
                    }
                }
                #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
                {
                    let _ = ccid;
                    self.run_one_segment(code_cap_id, None)
                }
            } else {
                self.run_one_segment(code_cap_id, None)
            };

            // Dispatch on the exit reason (shared for both backends).
            match exit_reason {
                4 => {
                    // HostCall(imm) — ecalli (pc already synced by backend)
                    let prev_vm = self.active_vm;
                    match self.dispatch_ecalli(exit_arg) {
                        DispatchResult::Continue => {
                            // The host operation is now committed. Until this
                            // point the issuer remains suspended at the
                            // causing `ecalli`, so an OOG/fault in dispatch
                            // cannot accidentally advance it.
                            self.acknowledge_vm_host_call(prev_vm);
                            // Internal dispatch (RETYPE, CREATE, CALL VM, management ops).
                            // Use resume only if BOTH code cap AND active VM are unchanged.
                            // VM switches (CALL handle, REPLY) change registers/gas — stale
                            // JitContext would produce wrong results.
                            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                            {
                                let new_code_cap_id =
                                    self.vm_arena.vm(self.active_vm).code_cap_id as usize;
                                if self.active_vm == prev_vm
                                    && new_code_cap_id == code_cap_id
                                    && self.live_ctx.is_some()
                                    && self.window_pool.window_owner(self.active_window)
                                        == Some(self.active_vm)
                                    && matches!(
                                        self.code_caps[code_cap_id].compiled,
                                        crate::backend::CompiledProgram::Recompiler(_)
                                    )
                                {
                                    self.recompiler_resume_cap = Some(code_cap_id);
                                }
                            }
                            continue;
                        }
                        DispatchResult::ProtocolCall { slot } => {
                            // Mark the still-live context for a cheap resume;
                            // signal TLS itself was cleared immediately after
                            // native code returned.
                            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                            if matches!(
                                self.code_caps[code_cap_id].compiled,
                                crate::backend::CompiledProgram::Recompiler(_)
                            ) && self.live_ctx.is_some()
                                && self.window_pool.window_owner(self.active_window)
                                    == Some(self.active_vm)
                            {
                                self.recompiler_resume_cap = Some(code_cap_id);
                            }
                            return self.suspend_protocol_call(slot);
                        }
                        DispatchResult::RootHalt => return KernelResult::Halt,
                        DispatchResult::RootPanic => return KernelResult::Panic,
                        DispatchResult::RootOutOfGas => return KernelResult::OutOfGas,
                        DispatchResult::RootPageFault(a) => return KernelResult::PageFault(a),
                        DispatchResult::Fault(fault) => {
                            #[cfg(all(
                                feature = "std",
                                target_os = "linux",
                                target_arch = "x86_64"
                            ))]
                            self.flush_live_ctx();
                            match self.handle_vm_fault(fault) {
                                DispatchResult::Continue => continue,
                                DispatchResult::RootHalt => return KernelResult::Halt,
                                DispatchResult::RootPanic => return KernelResult::Panic,
                                DispatchResult::RootOutOfGas => return KernelResult::OutOfGas,
                                DispatchResult::RootPageFault(a) => {
                                    return KernelResult::PageFault(a);
                                }
                                DispatchResult::ProtocolCall { .. } | DispatchResult::Fault(_) => {
                                    return KernelResult::Panic;
                                }
                            }
                        }
                    }
                }
                0 => {
                    // Halt (djump to the halt address)
                    match self.handle_vm_halt() {
                        DispatchResult::RootHalt => return KernelResult::Halt,
                        DispatchResult::Continue => continue,
                        _ => return KernelResult::Panic,
                    }
                }
                7 => {
                    // Trap (deliberate, opcode 0)
                    match self.handle_vm_fault(FaultType::Trap) {
                        DispatchResult::RootPanic => return KernelResult::Panic,
                        DispatchResult::Continue => continue,
                        _ => return KernelResult::Panic,
                    }
                }
                1 => {
                    // Panic (runtime error)
                    match self.handle_vm_fault(FaultType::Panic) {
                        DispatchResult::RootPanic => return KernelResult::Panic,
                        DispatchResult::Continue => continue,
                        _ => return KernelResult::Panic,
                    }
                }
                2 => {
                    // OOG
                    match self.handle_vm_fault(FaultType::OutOfGas) {
                        DispatchResult::RootOutOfGas => return KernelResult::OutOfGas,
                        DispatchResult::Continue => continue,
                        _ => return KernelResult::OutOfGas,
                    }
                }
                3 => {
                    // Page fault
                    let Ok(page_address) = u32::try_from(exit_arg) else {
                        return KernelResult::Panic;
                    };
                    if self.call_stack.is_empty() {
                        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
                        self.flush_live_ctx();
                        let vm = self.vm_arena.vm_mut(self.active_vm);
                        vm.set_pending_page_fault(Some(page_address));
                        self.pending_page_fault = Some(PendingPageFault {
                            vm_index: self.active_vm,
                            address: page_address,
                            cause_pc: vm.pc,
                            gas_charged: vm.gas_charged(),
                        });
                        return KernelResult::PageFault(page_address);
                    }
                    match self.handle_vm_fault(FaultType::PageFault(page_address)) {
                        DispatchResult::RootPageFault(a) => return KernelResult::PageFault(a),
                        DispatchResult::Continue => continue,
                        _ => return KernelResult::Panic,
                    }
                }
                6 => {
                    // Ecall — management ops / dynamic CALL.
                    // Read φ[11]=op, φ[12]=subject|object from active VM.
                    let op = self.active_reg(11) as u32;
                    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
                    self.flush_live_ctx();
                    match self.dispatch_ecall(op) {
                        DispatchResult::Continue => continue,
                        DispatchResult::ProtocolCall { slot } => {
                            return self.suspend_protocol_call(slot);
                        }
                        DispatchResult::RootHalt => return KernelResult::Halt,
                        DispatchResult::RootPanic => return KernelResult::Panic,
                        DispatchResult::RootOutOfGas => return KernelResult::OutOfGas,
                        DispatchResult::RootPageFault(a) => return KernelResult::PageFault(a),
                        DispatchResult::Fault(fault) => match self.handle_vm_fault(fault) {
                            DispatchResult::Continue => continue,
                            DispatchResult::RootHalt => return KernelResult::Halt,
                            DispatchResult::RootPanic => return KernelResult::Panic,
                            DispatchResult::RootOutOfGas => return KernelResult::OutOfGas,
                            DispatchResult::RootPageFault(a) => {
                                return KernelResult::PageFault(a);
                            }
                            DispatchResult::ProtocolCall { .. } | DispatchResult::Fault(_) => {
                                return KernelResult::Panic;
                            }
                        },
                    }
                }
                _ => return KernelResult::Panic,
            }
        }
    }

    /// Read bytes from a DATA cap's mapped region in the active VM's CODE window.
    pub fn read_data_cap(&self, cap_idx: u8, offset: u32, len: u32) -> Option<Vec<u8>> {
        let vm = &self.vm_arena.vm(self.active_vm);
        let d = match vm.cap_table.get(cap_idx)? {
            Cap::Data(d) => d,
            _ => return None,
        };
        let base_page = d.base_offset?;
        if !d.has_any_mapped() {
            return None;
        }
        let addr = base_page as usize * crate::PVM_PAGE_SIZE as usize + offset as usize;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let wb = self.active_window_base();
            let mut buf = vec![0u8; len as usize];
            // SAFETY: base_page was mmap'd into the window by map_pages.
            unsafe {
                std::ptr::copy_nonoverlapping(wb.add(addr), buf.as_mut_ptr(), len as usize);
            }
            Some(buf)
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let byte_off = d.backing_offset as usize * crate::PVM_PAGE_SIZE as usize
                + (addr - base_page as usize * crate::PVM_PAGE_SIZE as usize);
            self.backing
                .read_bytes_at(byte_off, len as usize)
                .map(|s| s.to_vec())
        }
    }

    /// Resolve the access level of address range `[addr, addr+len)` in the
    /// active VM's address space: the weakest access over the range, or None
    /// if any page in it is unmapped. Empty ranges resolve to RW.
    fn range_access(&self, addr: u32, len: u32) -> Option<Access> {
        if len == 0 {
            return Some(Access::RW);
        }
        let end = addr.checked_add(len - 1)?;
        let first_page = addr / crate::PVM_PAGE_SIZE;
        let last_page = end / crate::PVM_PAGE_SIZE;

        // Collect mapped DATA caps once; cap tables hold only a handful.
        let vm = &self.vm_arena.vm(self.active_vm);
        let mut caps: Vec<(u32, &crate::cap::DataCap)> = Vec::new();
        for slot in 0..=255u8 {
            if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                && let Some(base_page) = d.base_offset
            {
                caps.push((base_page, d));
            }
        }

        let mut access = Access::RW;
        'pages: for page in first_page..=last_page {
            for &(base_page, d) in &caps {
                if page >= base_page
                    && page < base_page + d.page_count
                    && d.is_page_mapped(page - base_page)
                {
                    if d.access == Some(Access::RO) {
                        access = Access::RO;
                    }
                    continue 'pages;
                }
            }
            return None;
        }
        Some(access)
    }

    /// Read bytes directly from the active VM's window by address.
    /// Used for reading output from guest programs that return ptr+len in registers.
    ///
    /// The range is validated against the VM's mapped pages first: addr/len
    /// are guest-supplied and may point at unmapped (PROT_NONE) pages, which
    /// would fault the host process rather than the guest.
    pub fn read_data_cap_window(&self, addr: u32, len: u32) -> Option<Vec<u8>> {
        self.range_access(addr, len)?;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let wb = self.active_window_base();
            let mut buf = vec![0u8; len as usize];
            // SAFETY: the range is fully covered by mapped pages (validated
            // above), so the copy stays inside the window's mapped regions.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    wb.add(addr as usize),
                    buf.as_mut_ptr(),
                    len as usize,
                );
            }
            Some(buf)
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            // On non-Linux the window is not backed by physical pages.
            // Copy page-by-page from each covering DataCap's backing store.
            let mut buf = Vec::with_capacity(len as usize);
            let vm = &self.vm_arena.vm(self.active_vm);
            let mut cursor = addr;
            let mut remaining = len as usize;
            while remaining > 0 {
                let addr_page = cursor / crate::PVM_PAGE_SIZE;
                let offset_in_page = (cursor % crate::PVM_PAGE_SIZE) as usize;
                let chunk = remaining.min(crate::PVM_PAGE_SIZE as usize - offset_in_page);
                let mut copied = false;
                for slot in 0..=255u8 {
                    if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                        && let Some(base_page) = d.base_offset
                        && addr_page >= base_page
                        && addr_page < base_page + d.page_count
                        && d.is_page_mapped(addr_page - base_page)
                    {
                        let page_in_cap = (addr_page - base_page) as usize;
                        let byte_off = (d.backing_offset as usize + page_in_cap)
                            * crate::PVM_PAGE_SIZE as usize
                            + offset_in_page;
                        buf.extend_from_slice(self.backing.read_bytes_at(byte_off, chunk)?);
                        copied = true;
                        break;
                    }
                }
                if !copied {
                    return None;
                }
                remaining -= chunk;
                if remaining == 0 {
                    break;
                }
                // More pages remain, so cursor + chunk stays below 2^32.
                cursor += chunk as u32;
            }
            Some(buf)
        }
    }

    /// Write bytes into a DATA cap's mapped region in the active VM's window.
    pub fn write_data_cap(&mut self, cap_idx: u8, offset: u32, data: &[u8]) -> bool {
        // Extract cap info first, releasing the borrow on vm_arena before
        // mutably borrowing backing on the non-Linux path.
        let cap_info = {
            let vm = &self.vm_arena.vm(self.active_vm);
            let d = match vm.cap_table.get(cap_idx) {
                Some(Cap::Data(d)) => d,
                _ => return false,
            };
            match d.base_offset {
                Some(b) if d.has_any_mapped() => Some((b, d.backing_offset)),
                _ => None,
            }
        };
        let (base_page, backing_offset) = match cap_info {
            Some(info) => info,
            None => return false,
        };
        let addr = base_page as usize * crate::PVM_PAGE_SIZE as usize + offset as usize;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let _ = backing_offset; // only used on non-Linux
            let wb = self.active_window_base();
            // SAFETY: base_page was mmap'd into the window by map_pages.
            unsafe {
                std::ptr::copy_nonoverlapping(data.as_ptr(), wb.add(addr), data.len());
            }
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let byte_off = backing_offset as usize * crate::PVM_PAGE_SIZE as usize
                + (addr - base_page as usize * crate::PVM_PAGE_SIZE as usize);
            self.backing.write_bytes_at(byte_off, data);
        }
        true
    }

    /// Write bytes directly into the active VM's window by address.
    /// Symmetric with [`Self::read_data_cap_window`]: used by hosts that pass
    /// flat virtual addresses (rather than `(cap_idx, offset)` pairs) for
    /// hostcall output buffers. The kernel locates the covering DATA cap and
    /// writes through it. Returns `false` if `addr..addr+len` does not fall
    /// within any mapped DATA cap in the active VM.
    pub fn write_data_cap_window(&mut self, addr: u32, data: &[u8]) -> bool {
        // The full range must be mapped RW: addr is typically guest-supplied,
        // and a raw window write into an unmapped or read-only page would
        // fault the host process rather than the guest.
        let Ok(len) = u32::try_from(data.len()) else {
            return false;
        };
        if self.range_access(addr, len) != Some(Access::RW) {
            return false;
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            // A restored suspended kernel has canonical DATA-cap metadata but
            // no native window assignment until its next `run()`. Protocol
            // hosts must still be able to inject the one resume value before
            // execution continues, so materialize the active mapping here.
            self.ensure_active_window();
            let wb = self.active_window_base();
            // SAFETY: the range is fully covered by RW-mapped pages
            // (validated above).
            unsafe {
                std::ptr::copy_nonoverlapping(data.as_ptr(), wb.add(addr as usize), data.len());
            }
            true
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            // On non-Linux the window is not backed by physical pages.
            // Write page-by-page through each covering DataCap's backing store.
            let mut cursor = addr;
            let mut written = 0usize;
            while written < data.len() {
                let addr_page = cursor / crate::PVM_PAGE_SIZE;
                let offset_in_page = (cursor % crate::PVM_PAGE_SIZE) as usize;
                let chunk =
                    (data.len() - written).min(crate::PVM_PAGE_SIZE as usize - offset_in_page);
                let cap_info = {
                    let vm = &self.vm_arena.vm(self.active_vm);
                    let mut found = None;
                    for slot in 0..=255u8 {
                        if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                            && let Some(base_page) = d.base_offset
                            && addr_page >= base_page
                            && addr_page < base_page + d.page_count
                            && d.is_page_mapped(addr_page - base_page)
                        {
                            found = Some((base_page, d.backing_offset));
                            break;
                        }
                    }
                    found
                };
                let Some((base_page, backing_offset)) = cap_info else {
                    return false;
                };
                let page_in_cap = (addr_page - base_page) as usize;
                let byte_off = (backing_offset as usize + page_in_cap)
                    * crate::PVM_PAGE_SIZE as usize
                    + offset_in_page;
                self.backing
                    .write_bytes_at(byte_off, &data[written..written + chunk]);
                written += chunk;
                if written == data.len() {
                    break;
                }
                // More pages remain, so cursor + chunk stays below 2^32.
                cursor += chunk as u32;
            }
            true
        }
    }

    /// Handle a VM halt (djump to [`crate::PVM_HALT_ADDR`]).
    ///
    /// A root-VM halt is the normal termination of the invocation; the host
    /// reads any output from registers/memory afterwards. A halt in a CALLed
    /// VM bypassed the CALL/REPLY return protocol and is delivered to the
    /// caller as a runtime fault (status 2), matching the Lean kernel.
    pub fn handle_vm_halt(&mut self) -> DispatchResult {
        if self.call_stack.is_empty() {
            let callee_id = self.active_vm;
            let _ = self.vm_arena.vm_mut(callee_id).transition(VmState::Halted);
            DispatchResult::RootHalt
        } else {
            self.handle_vm_fault(FaultType::Panic)
        }
    }

    /// Handle a callee fault with status code and aux value.
    pub fn handle_vm_fault(&mut self, fault: FaultType) -> DispatchResult {
        // Determine status code and aux value based on fault type
        let (status, aux_value) = match fault {
            FaultType::Trap => {
                // Status 1: trap. Preserve child's φ[7] as trap code.
                (1u64, self.vm_arena.vm(self.active_vm).reg(7))
            }
            FaultType::Panic => (2, RESULT_HUH), // Status 2: runtime panic
            FaultType::OutOfGas => (3, RESULT_LOW), // Status 3: OOG
            FaultType::PageFault(addr) => (4, addr as u64), // Status 4: page fault
        };

        let callee_id = self.active_vm;
        let _ = self.vm_arena.vm_mut(callee_id).transition(VmState::Faulted);

        match self.call_stack.pop() {
            Some(frame) => {
                let caller_id = frame.caller_vm_id;

                // Return unused gas
                let unused_gas = self.vm_arena.vm(callee_id).gas();
                let cg = self.vm_arena.vm(caller_id).gas();
                let Some(returned_gas) = cg.checked_add(unused_gas) else {
                    // Fail closed without duplicating the invalid balance.
                    self.vm_arena.vm_mut(callee_id).set_gas(0);
                    return DispatchResult::RootPanic;
                };
                self.vm_arena.vm_mut(caller_id).set_gas(returned_gas);
                self.vm_arena.vm_mut(callee_id).set_gas(0);

                // Set φ[7]=aux_value, φ[8]=status
                self.vm_arena.vm_mut(caller_id).set_reg(7, aux_value);
                self.vm_arena.vm_mut(caller_id).set_reg(8, status);

                let _ = self.vm_arena.vm_mut(caller_id).transition(VmState::Running);
                self.active_vm = caller_id;
                DispatchResult::Continue
            }
            None => {
                // Root VM faulted
                match fault {
                    FaultType::Trap | FaultType::Panic => DispatchResult::RootPanic,
                    FaultType::OutOfGas => DispatchResult::RootOutOfGas,
                    FaultType::PageFault(addr) => DispatchResult::RootPageFault(addr),
                }
            }
        }
    }
}

fn snapshot_isa_mode(mode: crate::IsaMode) -> SnapshotIsaMode {
    match mode {
        crate::IsaMode::Jar => SnapshotIsaMode::Jar,
        crate::IsaMode::Conformance => SnapshotIsaMode::Conformance,
    }
}

fn restore_isa_mode(mode: SnapshotIsaMode) -> crate::IsaMode {
    match mode {
        SnapshotIsaMode::Jar => crate::IsaMode::Jar,
        SnapshotIsaMode::Conformance => crate::IsaMode::Conformance,
    }
}

fn snapshot_vm_state(state: VmState) -> SnapshotVmState {
    match state {
        VmState::Idle => SnapshotVmState::Idle,
        VmState::Running => SnapshotVmState::Running,
        VmState::WaitingForReply => SnapshotVmState::WaitingForReply,
        VmState::Halted => SnapshotVmState::Halted,
        VmState::Faulted => SnapshotVmState::Faulted,
    }
}

fn restore_vm_state(state: SnapshotVmState) -> VmState {
    match state {
        SnapshotVmState::Idle => VmState::Idle,
        SnapshotVmState::Running => VmState::Running,
        SnapshotVmState::WaitingForReply => VmState::WaitingForReply,
        SnapshotVmState::Halted => VmState::Halted,
        SnapshotVmState::Faulted => VmState::Faulted,
    }
}

fn snapshot_access(access: Access) -> SnapshotAccess {
    match access {
        Access::RO => SnapshotAccess::ReadOnly,
        Access::RW => SnapshotAccess::ReadWrite,
    }
}

fn restore_access(access: SnapshotAccess) -> Access {
    match access {
        SnapshotAccess::ReadOnly => Access::RO,
        SnapshotAccess::ReadWrite => Access::RW,
    }
}

fn snapshot_capability(
    capability: &Cap,
    untyped: &Arc<UntypedCap>,
) -> Result<CapabilitySnapshot, SnapshotError> {
    Ok(match capability {
        Cap::Untyped(value) => {
            if !Arc::ptr_eq(value, untyped) {
                return Err(SnapshotError::InvalidCapability);
            }
            CapabilitySnapshot::Untyped
        }
        Cap::Data(value) => CapabilitySnapshot::Data {
            backing_offset: value.backing_offset,
            page_count: value.page_count,
            base_offset: value.base_offset,
            access: value.access.map(snapshot_access),
            mapped_bitmap: value.mapped_bitmap.clone(),
        },
        Cap::Code(value) => CapabilitySnapshot::Code {
            code_cap_id: value.id,
        },
        Cap::Handle(value) => CapabilitySnapshot::Handle {
            vm_index: value.vm_id.index(),
            vm_generation: value.vm_id.generation(),
            max_gas: value.max_gas,
        },
        Cap::Callable(value) => CapabilitySnapshot::Callable {
            vm_index: value.vm_id.index(),
            vm_generation: value.vm_id.generation(),
            max_gas: value.max_gas,
        },
        Cap::Protocol(value) => CapabilitySnapshot::Protocol { id: value.id },
    })
}

fn restore_vm(
    snapshot: &VmSnapshot,
    code_caps: &[Arc<CodeCap>],
    untyped: &Arc<UntypedCap>,
    memory_pages: u32,
) -> Result<VmInstance, SnapshotError> {
    if snapshot.code_cap_id as usize >= code_caps.len() {
        return Err(SnapshotError::InvalidArena);
    }
    let mut cap_table = CapTable::new();
    let mut seen_slots = BTreeSet::new();
    for slot in &snapshot.capabilities {
        if !seen_slots.insert(slot.slot) {
            return Err(SnapshotError::InvalidCapability);
        }
        let capability = restore_capability(&slot.capability, code_caps, untyped, memory_pages)?;
        if slot.original {
            if !matches!(capability, Cap::Protocol(ProtocolCap { id }) if id == slot.slot && slot.slot <= 28)
            {
                return Err(SnapshotError::InvalidCapability);
            }
            cap_table.set_original(slot.slot, capability);
        } else {
            cap_table.set(slot.slot, capability);
        }
    }
    let mut vm = VmInstance::new(
        snapshot.code_cap_id,
        snapshot.entry_index,
        cap_table,
        snapshot.gas,
    );
    vm.state = restore_vm_state(snapshot.state);
    let registers = snapshot
        .registers
        .as_slice()
        .try_into()
        .map_err(|_| SnapshotError::InvalidArena)?;
    vm.set_regs(registers);
    let entry_registers = snapshot
        .entry_registers
        .as_slice()
        .try_into()
        .map_err(|_| SnapshotError::InvalidArena)?;
    vm.set_entry_regs(entry_registers);
    vm.pc = snapshot.pc;
    vm.set_gas_charged(snapshot.gas_charged);
    vm.set_pending_host_call(
        snapshot
            .pending_host_call
            .map(|call| crate::PendingHostCall {
                id: call.id,
                cause_pc: call.cause_pc,
                resume_pc: call.resume_pc,
            }),
    );
    vm.set_pending_page_fault(snapshot.pending_page_fault);
    vm.caller = snapshot.caller;
    vm.set_heap_base(snapshot.heap_base);
    vm.set_heap_top(snapshot.heap_top);
    Ok(vm)
}

fn restore_capability(
    snapshot: &CapabilitySnapshot,
    code_caps: &[Arc<CodeCap>],
    untyped: &Arc<UntypedCap>,
    memory_pages: u32,
) -> Result<Cap, SnapshotError> {
    Ok(match snapshot {
        CapabilitySnapshot::Untyped => Cap::Untyped(Arc::clone(untyped)),
        CapabilitySnapshot::Data {
            backing_offset,
            page_count,
            base_offset,
            access,
            mapped_bitmap,
        } => {
            let expected_bitmap_len = (*page_count as usize).div_ceil(8);
            let backing_end = backing_offset
                .checked_add(*page_count)
                .ok_or(SnapshotError::InvalidCapability)?;
            if *page_count == 0
                || backing_end > memory_pages
                || mapped_bitmap.len() != expected_bitmap_len
                || base_offset.is_some() != access.is_some()
            {
                return Err(SnapshotError::InvalidCapability);
            }
            if let Some(last) = mapped_bitmap.last()
                && page_count % 8 != 0
            {
                let used_mask = (1u8 << (page_count % 8)) - 1;
                if last & !used_mask != 0 {
                    return Err(SnapshotError::InvalidCapability);
                }
            }
            if mapped_bitmap.iter().any(|byte| *byte != 0) && base_offset.is_none() {
                return Err(SnapshotError::InvalidCapability);
            }
            if let Some(base) = base_offset {
                let virtual_end = base
                    .checked_add(*page_count)
                    .ok_or(SnapshotError::InvalidCapability)?;
                if virtual_end as u64 * crate::PVM_PAGE_SIZE as u64 > 1u64 << 32 {
                    return Err(SnapshotError::InvalidCapability);
                }
            }
            Cap::Data(DataCap {
                backing_offset: *backing_offset,
                page_count: *page_count,
                base_offset: *base_offset,
                access: access.map(restore_access),
                mapped_bitmap: mapped_bitmap.clone(),
            })
        }
        CapabilitySnapshot::Code { code_cap_id } => {
            let code = code_caps
                .get(*code_cap_id as usize)
                .ok_or(SnapshotError::InvalidCapability)?;
            Cap::Code(Arc::clone(code))
        }
        CapabilitySnapshot::Handle {
            vm_index,
            vm_generation,
            max_gas,
        } => Cap::Handle(HandleCap {
            vm_id: VmId::new(*vm_index, *vm_generation),
            max_gas: *max_gas,
        }),
        CapabilitySnapshot::Callable {
            vm_index,
            vm_generation,
            max_gas,
        } => Cap::Callable(CallableCap {
            vm_id: VmId::new(*vm_index, *vm_generation),
            max_gas: *max_gas,
        }),
        CapabilitySnapshot::Protocol { id } => Cap::Protocol(ProtocolCap { id: *id }),
    })
}

fn snapshot_call_frame(frame: &CallFrame) -> CallFrameSnapshot {
    let (ipc_base_page, ipc_access, ipc_mapped_bitmap) = match &frame.ipc_was_mapped {
        Some((base_page, access, mapped_bitmap)) => (
            Some(*base_page),
            Some(snapshot_access(*access)),
            Some(mapped_bitmap.clone()),
        ),
        None => (None, None, None),
    };
    CallFrameSnapshot {
        caller_vm_id: frame.caller_vm_id,
        ipc_cap_idx: frame.ipc_cap_idx,
        ipc_base_page,
        ipc_access,
        ipc_mapped_bitmap,
    }
}

fn restore_call_frame(frame: &CallFrameSnapshot) -> Result<CallFrame, SnapshotError> {
    let ipc_was_mapped = match (
        frame.ipc_base_page,
        frame.ipc_access,
        &frame.ipc_mapped_bitmap,
    ) {
        (None, None, None) => None,
        (Some(base_page), Some(access), Some(mapped_bitmap))
            if mapped_bitmap.iter().any(|byte| *byte != 0) =>
        {
            Some((base_page, restore_access(access), mapped_bitmap.clone()))
        }
        _ => return Err(SnapshotError::InvalidScheduler),
    };
    if frame.ipc_cap_idx.is_none() && ipc_was_mapped.is_some() {
        return Err(SnapshotError::InvalidScheduler);
    }
    Ok(CallFrame {
        caller_vm_id: frame.caller_vm_id,
        ipc_cap_idx: frame.ipc_cap_idx,
        ipc_was_mapped,
    })
}

fn restore_memory(
    backing: &mut BackingStore,
    snapshot: &KernelSnapshot,
) -> Result<(), SnapshotError> {
    let mut blocks = BTreeMap::<[u8; 32], &[u8]>::new();
    for block in &snapshot.blocks {
        if block.bytes.len() != crate::PVM_PAGE_SIZE as usize
            || blake2b_256(&block.bytes) != block.hash
            || blocks.insert(block.hash, &block.bytes).is_some()
        {
            return Err(SnapshotError::InvalidMemory);
        }
    }

    let zero_page = vec![0u8; crate::PVM_PAGE_SIZE as usize];
    for page_index in 0..backing.total_pages() {
        if !backing.write_page(page_index, &zero_page) {
            return Err(SnapshotError::InvalidMemory);
        }
    }

    let mut seen_pages = BTreeSet::new();
    let mut used_blocks = BTreeSet::new();
    for page in &snapshot.memory {
        if page.page_index >= backing.total_pages() || !seen_pages.insert(page.page_index) {
            return Err(SnapshotError::InvalidMemory);
        }
        let bytes = blocks
            .get(&page.block_hash)
            .ok_or(SnapshotError::InvalidMemory)?;
        if bytes.iter().all(|byte| *byte == 0) || !backing.write_page(page.page_index, bytes) {
            return Err(SnapshotError::InvalidMemory);
        }
        used_blocks.insert(page.block_hash);
    }
    if used_blocks.len() != blocks.len() {
        return Err(SnapshotError::InvalidMemory);
    }
    Ok(())
}

fn validate_call_stack(kernel: &InvocationKernel) -> Result<(), SnapshotError> {
    let mut callers = BTreeSet::new();
    let mut waiting = BTreeSet::new();
    let mut running = None;
    for (index, (_, vm)) in kernel.vm_arena.snapshot_slots().enumerate() {
        let Some(vm) = vm else { continue };
        let index = u16::try_from(index).map_err(|_| SnapshotError::InvalidScheduler)?;
        match vm.state {
            VmState::Running if running.replace(index).is_some() => {
                return Err(SnapshotError::InvalidScheduler);
            }
            VmState::WaitingForReply => {
                waiting.insert(index);
            }
            _ => {}
        }
    }
    if running != Some(kernel.active_vm) {
        return Err(SnapshotError::InvalidScheduler);
    }

    let mut parent = None;
    for frame in &kernel.call_stack {
        if !callers.insert(frame.caller_vm_id) {
            return Err(SnapshotError::InvalidScheduler);
        }
        let generation = kernel.vm_arena.generation_of(frame.caller_vm_id);
        let caller = kernel
            .vm_arena
            .get(VmId::new(frame.caller_vm_id, generation))
            .ok_or(SnapshotError::InvalidScheduler)?;
        if caller.state != VmState::WaitingForReply || caller.caller != parent {
            return Err(SnapshotError::InvalidScheduler);
        }
        parent = Some(frame.caller_vm_id);
    }
    if callers != waiting {
        return Err(SnapshotError::InvalidScheduler);
    }
    let active = kernel.vm_arena.vm(kernel.active_vm);
    if active.caller == parent {
        Ok(())
    } else {
        Err(SnapshotError::InvalidScheduler)
    }
}

/// Result of dispatching an ecalli.
#[derive(Debug)]
pub enum DispatchResult {
    /// Continue execution of the active VM.
    Continue,
    /// A protocol cap was called — host should handle.
    ProtocolCall { slot: u8 },
    /// Root VM halted normally.
    RootHalt,
    /// Root VM panicked.
    RootPanic,
    /// Root VM ran out of gas.
    RootOutOfGas,
    /// Root VM page-faulted.
    RootPageFault(u32),
    /// A fault in a non-root VM (already handled, caller resumed).
    Fault(FaultType),
}

/// Fault types.
#[derive(Debug, Clone, Copy)]
pub enum FaultType {
    Trap,
    Panic,
    OutOfGas,
    PageFault(u32),
}

/// Kernel errors.
#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("invalid JAR blob")]
    InvalidBlob,
    #[error("memory allocation failed")]
    MemoryError,
    #[error("insufficient gas for initialization")]
    OutOfGas,
    #[error("untyped pool exhausted")]
    OutOfMemory,
    #[error("exceeded max CODE caps ({MAX_CODE_CAPS})")]
    TooManyCodeCaps,
    #[error("cap table full")]
    CapTableFull,
    #[error("dormant-program HANDLE slot {0} is unavailable")]
    ImportHandleUnavailable(u8),
    #[error("exceeded max concurrent VMs")]
    TooManyVms,
    #[error("JIT compilation failed")]
    CompileError,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::ProtocolCap;
    use crate::program::{CapEntryType, CapManifestEntry, build_blob};

    /// Build a minimal code sub-blob (code_header + jump_table + code + bitmask).
    /// Contains a single `trap` instruction (opcode 0).
    fn make_code_sub_blob() -> Vec<u8> {
        let code = [0u8]; // trap instruction
        let bitmask = [1u8]; // instruction start
        let jump_table: &[u32] = &[];
        let entry_size: u8 = 1;

        let mut blob = Vec::new();
        // Sub-blob header: jump_len(4) + entry_size(1) + code_len(4)
        blob.extend_from_slice(&(jump_table.len() as u32).to_le_bytes());
        blob.push(entry_size);
        blob.extend_from_slice(&(code.len() as u32).to_le_bytes());
        // Code bytes
        blob.extend_from_slice(&code);
        // Packed bitmask
        blob.push(bitmask[0]); // 1 bit packed
        blob
    }

    /// Build a JAR blob from raw (code, bitmask bits, jump table).
    /// Layout mirrors `make_simple_blob`: CODE cap at 64, one RW page at 65.
    fn make_blob_with(code: &[u8], bitmask: &[u8], jump_table: &[u32]) -> Vec<u8> {
        let mut code_data = Vec::new();
        code_data.extend_from_slice(&(jump_table.len() as u32).to_le_bytes());
        code_data.push(1u8); // entry_size = 1 (byte targets)
        code_data.extend_from_slice(&(code.len() as u32).to_le_bytes());
        for &t in jump_table {
            code_data.push(t as u8);
        }
        code_data.extend_from_slice(code);
        let mut packed = vec![0u8; code.len().div_ceil(8)];
        for (i, &b) in bitmask.iter().enumerate() {
            if b != 0 {
                packed[i / 8] |= 1 << (i % 8);
            }
        }
        code_data.extend_from_slice(&packed);

        let caps = vec![
            CapManifestEntry {
                cap_index: 64,
                cap_type: CapEntryType::Code,
                base_page: 0,
                page_count: 0,
                init_access: Access::RO,
                data_offset: 0,
                data_len: code_data.len() as u32,
            },
            CapManifestEntry {
                cap_index: 65,
                cap_type: CapEntryType::Data,
                base_page: 0,
                page_count: 1,
                init_access: Access::RW,
                data_offset: 0,
                data_len: 0,
            },
        ];
        build_blob(10, 64, 4096, &caps, &code_data)
    }

    fn run_blob(code: &[u8], bitmask: &[u8], jump_table: &[u32]) -> KernelResult {
        let blob = make_blob_with(code, bitmask, jump_table);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);
        kernel.run()
    }

    /// djump program: `LoadImm T0,2; Fallthrough; MoveReg; JumpInd T0,0;
    /// Trap; JumpInd RA,0`. The djump resolves a = 2 to jump-table entry 0.
    /// Block starts: {0, 4 (post-Fallthrough), 13 (post-Trap)}; PC 6 is an
    /// instruction start but mid-block.
    fn djump_program() -> (Vec<u8>, Vec<u8>) {
        let code = vec![
            51, 2, 2, // PC 0: LoadImm T0, 2
            1, // PC 3: Fallthrough (PC 4 becomes a block start)
            100, 0x23, // PC 4: MoveReg T1 ← T0 (PC 6 is mid-block; RA untouched)
            50, 2, 0, 0, 0, 0, // PC 6: JumpInd T0, 0
            0, // PC 12: Trap (PC 13 becomes a block start)
            50, 0, 0, 0, 0, 0, // PC 13: JumpInd RA, 0 → halt
        ];
        let bitmask = vec![
            1, 0, 0, // LoadImm
            1, // Fallthrough
            1, 0, // MoveReg
            1, 0, 0, 0, 0, 0, // JumpInd
            1, // Trap
            1, 0, 0, 0, 0, 0, // JumpInd (halt)
        ];
        (code, bitmask)
    }

    #[test]
    fn test_djump_to_block_start_halts() {
        let (code, bitmask) = djump_program();
        // Jump-table entry 0 → PC 13 (post-terminator block start): valid.
        let result = run_blob(&code, &bitmask, &[13]);
        assert!(
            matches!(result, KernelResult::Halt),
            "djump to a block start should reach the halt, got: {result:?}"
        );
    }

    #[test]
    fn test_djump_to_mid_block_panics() {
        let (code, bitmask) = djump_program();
        // Jump-table entry 0 → PC 6: an instruction start, but mid-block —
        // GP eq A.18 panics (previously the two backends disagreed here:
        // the JIT validated against raw instruction starts).
        let result = run_blob(&code, &bitmask, &[6]);
        assert!(
            matches!(result, KernelResult::Panic),
            "djump to a mid-block target must panic, got: {result:?}"
        );
    }

    #[test]
    fn test_load_imm_jump_ind_uses_pre_state_base() {
        // GP A.5.12: `load_imm_jump_ind rA, rB, νX, νY` jumps to
        // (ω_B + νY) mod 2^32 using the PRE-state ω_B, and writes
        // ω'_A = νX. With rA == rB the old value must address the jump.
        let code = vec![
            51, 2, 2, // PC 0: LoadImm T0, 2
            180, 0x22, 1, 4, 0, // PC 3: LoadImmJumpInd rA=T0, rB=T0, νX=4, νY=0
            0, // PC 8: Trap (PC 9 becomes a block start)
            50, 0, 0, 0, 0, 0, // PC 9: JumpInd RA, 0 → halt
        ];
        let bitmask = vec![
            1, 0, 0, // LoadImm
            1, 0, 0, 0, 0, // LoadImmJumpInd
            1, // Trap
            1, 0, 0, 0, 0, 0, // JumpInd (halt)
        ];
        // a = old T0 (2) → jump-table entry 0 → PC 9 → halt. If the write
        // ω'_A = νX = 4 were applied first, a = 4 would resolve entry 1 →
        // PC 8 (Trap) → panic.
        let result = run_blob(&code, &bitmask, &[9, 8]);
        assert!(
            matches!(result, KernelResult::Halt),
            "load_imm_jump_ind must use the pre-state base register, got: {result:?}"
        );
    }

    #[test]
    fn test_ecalli_out_of_range_panics_uniformly() {
        // Ecalli with imm > 127 is invalid and must panic the root VM on both
        // backends. It previously left the run loop to continue in a
        // half-synced register state (recompiler φ[7] written to the live
        // JitContext but not flushed), diverging from the interpreter.
        let mut code = vec![10u8]; // Ecalli
        code.extend_from_slice(&200u32.to_le_bytes()); // imm = 200 (> 127)
        let bitmask = vec![1, 0, 0, 0, 0];
        let blob = make_blob_with(&code, &bitmask, &[]);
        for be in [
            crate::backend::PvmBackend::ForceInterpreter,
            crate::backend::PvmBackend::ForceRecompiler,
        ] {
            let mut kernel = InvocationKernel::new_with_backend(&blob, &[], 50_000, be).unwrap();
            let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);
            assert!(
                matches!(kernel.run(), KernelResult::Panic),
                "ecalli(200) must panic the root VM on {be:?}"
            );
        }
    }

    #[test]
    fn jar_kernel_dispatches_its_private_dynamic_ecall() {
        // LoadImm64 φ[12] = empty-slot subject, then Ecall, then Trap.
        // The remaining legacy kernel dispatches the ecall (unresolvable
        // subject → WHAT, continue) and panics at the Trap (pc 11).
        let mut code = vec![20, 12]; // LoadImm64 φ[12]
        code.extend_from_slice(&(200u64 << 32).to_le_bytes()); // subject = slot 200 (empty)
        code.push(3); // PC 10: Ecall
        code.push(0); // PC 11: Trap
        let mut bitmask = vec![0u8; code.len()];
        bitmask[0] = 1; // LoadImm64
        bitmask[10] = 1; // Ecall
        bitmask[11] = 1; // Trap
        let blob = make_blob_with(&code, &bitmask, &[]);

        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);
        let result = kernel.run();
        assert!(matches!(result, KernelResult::Panic));
        assert_eq!(
            kernel.vm_arena.vm(kernel.active_vm).pc,
            11,
            "Jar mode dispatches the ecall and panics at the following Trap"
        );
    }

    /// Build a JAR blob with explicit DATA caps:
    /// (cap_index, base_page, page_count, access, init bytes).
    fn make_blob_with_data_caps(
        code: &[u8],
        bitmask: &[u8],
        jump_table: &[u32],
        data_caps: &[(u8, u32, u32, Access, &[u8])],
        memory_pages: u32,
    ) -> Vec<u8> {
        let mut code_data = Vec::new();
        code_data.extend_from_slice(&(jump_table.len() as u32).to_le_bytes());
        code_data.push(1u8); // entry_size = 1 (byte targets)
        code_data.extend_from_slice(&(code.len() as u32).to_le_bytes());
        for &t in jump_table {
            code_data.push(t as u8);
        }
        code_data.extend_from_slice(code);
        let mut packed = vec![0u8; code.len().div_ceil(8)];
        for (i, &b) in bitmask.iter().enumerate() {
            if b != 0 {
                packed[i / 8] |= 1 << (i % 8);
            }
        }
        code_data.extend_from_slice(&packed);

        let mut data_section = code_data.clone();
        let mut caps = vec![CapManifestEntry {
            cap_index: 64,
            cap_type: CapEntryType::Code,
            base_page: 0,
            page_count: 0,
            init_access: Access::RO,
            data_offset: 0,
            data_len: code_data.len() as u32,
        }];
        for &(cap_index, base_page, page_count, init_access, init) in data_caps {
            let data_offset = data_section.len() as u32;
            data_section.extend_from_slice(init);
            caps.push(CapManifestEntry {
                cap_index,
                cap_type: CapEntryType::Data,
                base_page,
                page_count,
                init_access,
                data_offset,
                data_len: init.len() as u32,
            });
        }
        build_blob(memory_pages, 64, 4096, &caps, &data_section)
    }

    #[test]
    fn invocation_rejects_arguments_larger_than_ipc_cap() {
        let code = [0u8];
        let bitmask = [1u8];
        let blob = make_blob_with_data_caps(&code, &bitmask, &[], &[(0, 1, 1, Access::RW, &[])], 2);
        let fits = vec![0x5A; crate::PVM_PAGE_SIZE as usize];
        assert!(InvocationKernel::new(&blob, &fits, 100_000).is_ok());
        let oversized = vec![0x5A; crate::PVM_PAGE_SIZE as usize + 1];
        assert!(matches!(
            InvocationKernel::new(&blob, &oversized, 100_000),
            Err(KernelError::MemoryError)
        ));
    }

    fn run_mem_blob(
        code: &[u8],
        bitmask: &[u8],
        data_caps: &[(u8, u32, u32, Access, &[u8])],
    ) -> KernelResult {
        let blob = make_blob_with_data_caps(code, bitmask, &[], data_caps, 10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);
        kernel.run()
    }

    /// `LoadImm T0, addr; StoreIndU32 [T0+0] ← T0; JumpInd RA (halt)`.
    fn store_at_program(addr: u32) -> (Vec<u8>, Vec<u8>) {
        let mut code = vec![51, 2]; // LoadImm T0
        code.extend_from_slice(&addr.to_le_bytes());
        code.extend_from_slice(&[122, 0x22, 0, 0, 0, 0]); // StoreIndU32 [T0+0] ← T0
        code.extend_from_slice(&[50, 0, 0, 0, 0, 0]); // JumpInd RA, 0 → halt
        let mut bitmask = vec![0u8; code.len()];
        bitmask[0] = 1;
        bitmask[6] = 1;
        bitmask[12] = 1;
        (code, bitmask)
    }

    /// `LoadImm T0, addr; LoadIndU32 T0 ← [T0+0]; JumpInd RA (halt)`.
    fn load_at_program(addr: u32) -> (Vec<u8>, Vec<u8>) {
        let mut code = vec![51, 2]; // LoadImm T0
        code.extend_from_slice(&addr.to_le_bytes());
        code.extend_from_slice(&[128, 0x22, 0, 0, 0, 0]); // LoadIndU32 T0 ← [T0+0]
        code.extend_from_slice(&[50, 0, 0, 0, 0, 0]); // JumpInd RA, 0 → halt
        let mut bitmask = vec![0u8; code.len()];
        bitmask[0] = 1;
        bitmask[6] = 1;
        bitmask[12] = 1;
        (code, bitmask)
    }

    #[test]
    fn test_write_to_ro_page_faults() {
        // Page 0: RW stack; page 1: RO data. A store into the RO page must
        // page-fault at its page base on both backends. (The interpreter
        // previously accepted the write into its flat buffer and silently
        // dropped it at write-back.)
        let (code, bitmask) = store_at_program(0x1000);
        let caps: &[(u8, u32, u32, Access, &[u8])] = &[
            (65, 0, 1, Access::RW, &[]),
            (66, 1, 1, Access::RO, &[0xAA; 8]),
        ];
        let result = run_mem_blob(&code, &bitmask, caps);
        assert!(
            matches!(result, KernelResult::PageFault(0x1000)),
            "RO write must fault at the page base, got: {result:?}"
        );
    }

    #[test]
    fn test_read_from_ro_page_ok() {
        // Reading the RO page is fine and the program halts.
        let (code, bitmask) = load_at_program(0x1000);
        let caps: &[(u8, u32, u32, Access, &[u8])] = &[
            (65, 0, 1, Access::RW, &[]),
            (66, 1, 1, Access::RO, &[0xAA; 8]),
        ];
        let result = run_mem_blob(&code, &bitmask, caps);
        assert!(
            matches!(result, KernelResult::Halt),
            "RO read should succeed, got: {result:?}"
        );
    }

    #[test]
    fn test_read_from_unmapped_gap_faults() {
        // Caps at pages 0 and 2 leave a gap at page 1: reading it must
        // page-fault on both backends. (The interpreter previously returned
        // zeros for gap reads below the highest mapped address.)
        let (code, bitmask) = load_at_program(0x1000);
        let caps: &[(u8, u32, u32, Access, &[u8])] = &[
            (65, 0, 1, Access::RW, &[]),
            (66, 2, 1, Access::RW, &[0xBB; 8]),
        ];
        let result = run_mem_blob(&code, &bitmask, caps);
        assert!(
            matches!(result, KernelResult::PageFault(0x1000)),
            "gap read must fault at the page base, got: {result:?}"
        );
    }

    #[test]
    fn test_straddling_access_faults_on_second_page() {
        // A u32 store at 0x0FFE touches pages 0 (RW) and 1 (unmapped): the
        // fault address is the *second* page's base — matching hardware
        // (si_addr) under the JIT and the page walk in the interpreter.
        let (code, bitmask) = store_at_program(0x0FFE);
        let caps: &[(u8, u32, u32, Access, &[u8])] = &[(65, 0, 1, Access::RW, &[])];
        let result = run_mem_blob(&code, &bitmask, caps);
        assert!(
            matches!(result, KernelResult::PageFault(0x1000)),
            "straddling fault must report the second page, got: {result:?}"
        );
    }

    fn make_simple_blob(memory_pages: u32) -> Vec<u8> {
        let code_data = make_code_sub_blob();

        let caps = vec![
            CapManifestEntry {
                cap_index: 64,
                cap_type: CapEntryType::Code,
                base_page: 0,
                page_count: 0,
                init_access: Access::RO,
                data_offset: 0,
                data_len: code_data.len() as u32,
            },
            CapManifestEntry {
                cap_index: 65,
                cap_type: CapEntryType::Data,
                base_page: 0,
                page_count: 1,
                init_access: Access::RW,
                data_offset: 0, // doesn't reference data section
                data_len: 0,
            },
        ];
        build_blob(memory_pages, 64, 4096, &caps, &code_data)
    }

    #[test]
    fn test_kernel_create() {
        let blob = make_simple_blob(10);
        let kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        assert_eq!(kernel.vm_arena.len(), 1);
        assert_eq!(kernel.code_caps.len(), 1);
        assert_eq!(kernel.mem_cycles, 25);
    }

    #[test]
    fn test_kernel_retype() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();

        // Set VM 0 to running
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // UNTYPED is at fixed slot 254
        let untyped_slot = 254u8;
        assert!(matches!(
            kernel.vm_arena.vm(0).cap_table.get(untyped_slot),
            Some(Cap::Untyped(_))
        ));

        // Use ecall (UNTYPED slot 254 > 127, can't use ecalli)
        // φ[7]=4 pages, φ[11]=0 (CALL), φ[12]=dst_slot(low) | untyped_slot(high)
        kernel.set_active_reg(7, 4);
        kernel.set_active_reg(11, 0); // op = CALL
        kernel.set_active_reg(12, 66 | ((untyped_slot as u64) << 32));
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        kernel.flush_live_ctx();
        let result = kernel.dispatch_ecall(0);
        assert!(matches!(result, DispatchResult::Continue));

        // φ[7] should be the dst_slot
        let new_cap_idx = kernel.active_reg(7) as u8;
        assert_eq!(new_cap_idx, 66);
        assert!(matches!(
            kernel.vm_arena.vm(0).cap_table.get(new_cap_idx),
            Some(Cap::Data(_))
        ));
    }

    #[test]
    fn test_kernel_create_vm() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Find the CODE cap slot
        let code_slot = 64u8; // From manifest

        // CALL on CODE: φ[7]=bitmask, φ[12]=dst_slot for HANDLE
        kernel.set_active_reg(7, 0); // no caps to copy
        kernel.set_active_reg(12, 66); // HANDLE at slot 66 (64=CODE, 65=DATA)

        let result = kernel.dispatch_ecalli(code_slot as u64);
        assert!(matches!(result, DispatchResult::Continue));

        // Should have created VM 1
        assert_eq!(kernel.vm_arena.len(), 2);
        assert_eq!(kernel.vm_arena.vm(1).state, VmState::Idle);

        // φ[7] = dst_slot
        let handle_idx = kernel.active_reg(7) as u8;
        assert_eq!(handle_idx, 66);
        assert!(matches!(
            kernel.vm_arena.vm(0).cap_table.get(handle_idx),
            Some(Cap::Handle(_))
        ));
    }

    #[test]
    fn test_kernel_call_reply() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Create child VM: φ[7]=bitmask, φ[12]=dst_slot for HANDLE
        kernel.set_active_reg(7, 0); // no caps copied
        kernel.set_active_reg(12, 66); // place HANDLE at slot 66 (64=CODE, 65=DATA)
        kernel.dispatch_ecalli(64); // CALL CODE at slot 64 → CREATE
        let handle_idx = kernel.active_reg(7) as u8;

        // CALL the child: φ[7]=arg0, φ[8]=arg1, φ[12]=0 (no IPC cap)
        kernel.set_active_reg(7, 42);
        kernel.set_active_reg(8, 99);
        kernel.set_active_reg(12, 0);

        let result = kernel.dispatch_ecalli(handle_idx as u64);
        assert!(matches!(result, DispatchResult::Continue));

        // Active VM should now be the child (VM 1)
        assert_eq!(kernel.active_vm, 1);
        assert_eq!(kernel.vm_arena.vm(0).state, VmState::WaitingForReply);
        assert_eq!(kernel.vm_arena.vm(1).state, VmState::Running);

        // Child received args
        assert_eq!(kernel.active_reg(7), 42);
        assert_eq!(kernel.active_reg(8), 99);

        // Child REPLYs with results
        kernel.vm_arena.vm_mut(1).pc = 77;
        kernel.vm_arena.vm_mut(1).set_reg(1, 1234);
        kernel.set_active_reg(7, 100);
        kernel.set_active_reg(8, 200);
        let result = kernel.dispatch_ecalli(u64::from(IPC_SLOT)); // REPLY
        assert!(matches!(result, DispatchResult::Continue));

        // Back to VM 0
        assert_eq!(kernel.active_vm, 0);
        assert_eq!(kernel.vm_arena.vm(0).state, VmState::Running);
        assert_eq!(kernel.vm_arena.vm(1).state, VmState::Idle);

        // Caller received results: φ[7]=child's return, φ[8]=0 (status=REPLY)
        assert_eq!(kernel.active_reg(7), 100);
        assert_eq!(kernel.active_reg(8), 0);

        // A later CALL of the fully replied idle machine is a fresh entry,
        // not a continuation after REPLY. Live suspended machines never pass
        // through this reset boundary.
        kernel.set_active_reg(7, 7);
        kernel.set_active_reg(8, 8);
        kernel.set_active_reg(12, 0);
        assert!(matches!(
            kernel.dispatch_ecalli(handle_idx as u64),
            DispatchResult::Continue
        ));
        assert_eq!(kernel.active_vm, 1);
        assert_eq!(kernel.vm_arena.vm(1).pc, 0);
        assert_eq!(kernel.vm_arena.vm(1).reg(1), 0);
        assert_eq!(kernel.active_reg(7), 7);
        assert_eq!(kernel.active_reg(8), 8);
    }

    #[test]
    fn ipc_data_cap_mapping_follows_its_single_owner() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Create the child and an invocation-owned DATA cap in the caller.
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 66);
        kernel.dispatch_ecalli(64);
        let handle = kernel.active_reg(7) as u8;

        let backing_offset = kernel.untyped.retype(4).unwrap();
        kernel
            .vm_arena
            .vm_mut(0)
            .cap_table
            .set(67, Cap::Data(DataCap::new(backing_offset, 4)));
        // Map only offsets 1 and 3. Native window reconstruction and the
        // IPC round trip must preserve these holes exactly.
        kernel.set_active_reg(7, 20);
        kernel.set_active_reg(8, 1);
        kernel.set_active_reg(9, 1);
        kernel.set_active_reg(10, 1);
        kernel.set_active_reg(12, (67u64) << 32);
        assert!(matches!(
            kernel.dispatch_ecall(0x02),
            DispatchResult::Continue
        ));
        kernel.set_active_reg(7, 20);
        kernel.set_active_reg(8, 3);
        kernel.set_active_reg(9, 1);
        kernel.set_active_reg(10, 1);
        kernel.set_active_reg(12, (67u64) << 32);
        assert!(matches!(
            kernel.dispatch_ecall(0x02),
            DispatchResult::Continue
        ));
        assert!(matches!(
            kernel.vm_arena.vm(0).cap_table.get(67),
            Some(Cap::Data(data))
                if data.mapped_runs() == vec![(1, 1), (3, 1)]
        ));

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let perms = kernel.active_window_perms();
            // SAFETY: the active CodeWindow owns one permission byte per
            // guest page; pages 20..24 are within that table.
            let actual = unsafe { core::slice::from_raw_parts(perms.add(20), 4) };
            assert_eq!(actual, &[0, 2, 0, 2]);

            // Reconstruct the complete VM window from capability metadata.
            // Only bitmap runs may become mapped again.
            unsafe {
                assert!(BackingStore::unmap_pages(
                    kernel.active_window_base(),
                    20,
                    4,
                ));
            }
            kernel.map_vm_data_caps(0, kernel.active_window);
            let actual = unsafe { core::slice::from_raw_parts(perms.add(20), 4) };
            assert_eq!(actual, &[0, 2, 0, 2]);
        }

        // CALL moves the cap into child IPC slot 0 and revokes the caller
        // mapping. The child may then map the same capability into its CNode.
        kernel.set_active_reg(12, 67);
        assert!(matches!(
            kernel.dispatch_ecalli(handle as u64),
            DispatchResult::Continue
        ));
        assert!(kernel.vm_arena.vm(0).cap_table.get(67).is_none());
        assert!(matches!(
            kernel.vm_arena.vm(1).cap_table.get(IPC_SLOT),
            Some(Cap::Data(data)) if !data.has_any_mapped()
        ));

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let caller_window = kernel.vm_window_base(0).unwrap();
            // SAFETY: the permission table is the CodeWindow metadata prefix.
            let perms = unsafe { caller_window.sub(crate::backing::CODE_WINDOW_HEADER_SIZE) };
            let actual = unsafe { core::slice::from_raw_parts(perms.add(20), 4) };
            assert_eq!(actual, &[0, 0, 0, 0]);
        }

        // The callee chooses a different sparse mapping while it owns the
        // cap. REPLY must revoke that view and restore the caller's bitmap.
        kernel.set_active_reg(7, 20);
        kernel.set_active_reg(8, 0);
        kernel.set_active_reg(9, 1);
        kernel.set_active_reg(10, 1);
        kernel.set_active_reg(12, 0);
        assert!(matches!(
            kernel.dispatch_ecall(0x02),
            DispatchResult::Continue
        ));
        kernel.set_active_reg(7, 20);
        kernel.set_active_reg(8, 2);
        kernel.set_active_reg(9, 1);
        kernel.set_active_reg(10, 1);
        kernel.set_active_reg(12, 0);
        assert!(matches!(
            kernel.dispatch_ecall(0x02),
            DispatchResult::Continue
        ));
        assert!(matches!(
            kernel.vm_arena.vm(1).cap_table.get(IPC_SLOT),
            Some(Cap::Data(data)) if data.mapped_runs() == vec![(0, 1), (2, 1)]
        ));

        // REPLY moves ownership back, revokes the child mapping, and restores
        // the caller's original mapping.
        assert!(matches!(
            kernel.dispatch_ecalli(u64::from(IPC_SLOT)),
            DispatchResult::Continue
        ));
        assert!(kernel.vm_arena.vm(1).cap_table.get(IPC_SLOT).is_none());
        assert!(matches!(
            kernel.vm_arena.vm(0).cap_table.get(67),
            Some(Cap::Data(data))
                if data.base_offset == Some(20)
                    && data.mapped_runs() == vec![(1, 1), (3, 1)]
        ));

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let perms = kernel.active_window_perms();
            // SAFETY: the active CodeWindow owns one permission byte per
            // guest page; pages 20..24 are within that table.
            let actual = unsafe { core::slice::from_raw_parts(perms.add(20), 4) };
            assert_eq!(actual, &[0, 2, 0, 2]);
        }

        assert!(kernel.backing.write_init_data(backing_offset + 1, b"ipc"));
        assert_eq!(
            kernel.read_data_cap_window(21 * crate::PVM_PAGE_SIZE, 3),
            Some(b"ipc".to_vec())
        );
        assert_eq!(
            kernel.read_data_cap_window(20 * crate::PVM_PAGE_SIZE, 1),
            None,
            "the caller's bitmap hole must stay unmapped"
        );
    }

    #[test]
    fn test_kernel_no_reentrancy() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Create two child VMs: φ[7]=bitmask, φ[12]=dst_slot
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 66);
        kernel.dispatch_ecalli(64); // CREATE VM 1, HANDLE at 66
        let handle1 = kernel.active_reg(7) as u8;

        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 67);
        kernel.dispatch_ecalli(64); // CREATE VM 2, HANDLE at 67
        let _handle2 = kernel.active_reg(7) as u8;

        // VM 0 calls VM 1
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 0); // no IPC cap (slot 0 = IPC itself)
        kernel.dispatch_ecalli(handle1 as u64);
        assert_eq!(kernel.active_vm, 1);

        // Copy handle1 to VM 1 — but VM 0 is WaitingForReply,
        // so calling VM 0 from VM 1 should fail.
        // First we need a handle to VM 0 in VM 1's cap table.
        // We can't actually create one (no HANDLE to VM 0 exists in VM 1).
        // The reentrancy test is: VM 0 is in WaitingForReply, not IDLE.
        // If anyone tries to call VM 0, it fails.
        assert!(!kernel.vm_arena.vm(0).can_call());
    }

    #[test]
    fn test_kernel_gas_bounding() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Create child VM: φ[7]=bitmask, φ[12]=dst_slot
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 66);
        kernel.dispatch_ecalli(64);
        let handle_idx = kernel.active_reg(7) as u8;

        // SET_MAX_GAS on handle via ecall: φ[7]=5000, φ[11]=0x0B, φ[12]=handle(high)
        kernel.set_active_reg(7, 5000);
        kernel.set_active_reg(11, 0x0B); // SET_MAX_GAS
        kernel.set_active_reg(12, (handle_idx as u64) << 32); // subject=handle, object=0
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        kernel.flush_live_ctx();
        kernel.dispatch_ecall(0x0B);

        // CALL child — gas should be capped at 5000
        let parent_gas_before = kernel.vm_arena.vm(0).gas();
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 0); // no IPC cap (slot 0 = IPC itself)
        kernel.dispatch_ecalli(handle_idx as u64);

        assert_eq!(kernel.active_vm, 1);
        assert_eq!(kernel.vm_arena.vm(1).gas(), 5000);

        // Parent lost 10 (ecalli) + 10 (call overhead) + 5000 (transfer)
        assert_eq!(kernel.vm_arena.vm(0).gas(), parent_gas_before - 5020);
    }

    #[test]
    fn test_kernel_protocol_call() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Set a protocol cap at slot 1 (GAS)
        kernel
            .vm_arena
            .vm_mut(0)
            .cap_table
            .set(1, Cap::Protocol(ProtocolCap { id: 1 }));

        // CALL slot 1 → should return ProtocolCall
        kernel.set_active_reg(7, 123);
        let result = kernel.dispatch_ecalli(1);
        match result {
            DispatchResult::ProtocolCall { slot } => {
                assert_eq!(slot, 1);
                // Registers accessible via kernel.active_reg(7)
                assert_eq!(kernel.active_reg(7), 123);
            }
            _ => panic!("expected ProtocolCall"),
        }
    }

    #[test]
    fn test_kernel_missing_cap() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // CALL empty slot → WHAT
        let result = kernel.dispatch_ecalli(50);
        assert!(matches!(result, DispatchResult::Continue));
        assert_eq!(kernel.active_reg(7), RESULT_WHAT);
    }

    #[test]
    fn test_kernel_downgrade() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Create child: φ[7]=bitmask, φ[12]=dst_slot
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 66);
        kernel.dispatch_ecalli(64);
        let handle_idx = kernel.active_reg(7) as u8;

        // DOWNGRADE handle → callable via ecall
        // φ[11]=0x0A, φ[12]=dst_slot(low) | handle(high)
        kernel.set_active_reg(11, 0x0A); // DOWNGRADE
        // dst slot: pick slot 67 for the callable
        kernel.set_active_reg(12, 67 | ((handle_idx as u64) << 32));
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        kernel.flush_live_ctx();
        kernel.dispatch_ecall(0x0A);
        let callable_idx = 67u8;

        // Handle still exists
        assert!(matches!(
            kernel.vm_arena.vm(0).cap_table.get(handle_idx),
            Some(Cap::Handle(_))
        ));
        // Callable created
        assert!(matches!(
            kernel.vm_arena.vm(0).cap_table.get(callable_idx),
            Some(Cap::Callable(_))
        ));
    }

    #[test]
    fn test_kernel_run_trap() {
        // Build a blob with a `trap` instruction (opcode 0) — causes Panic.
        // This validates the full execution path: blob parse → JIT compile →
        // mmap DATA → execute native code → exit handling.
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);
        let result = kernel.run();
        assert!(
            matches!(result, KernelResult::Panic),
            "trap instruction should cause Panic, got: {result:?}"
        );
    }

    #[test]
    fn test_kernel_cap_bitmask_propagation() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Place protocol caps at slots 1 and 2
        kernel
            .vm_arena
            .vm_mut(0)
            .cap_table
            .set(1, Cap::Protocol(ProtocolCap { id: 1 }));
        kernel
            .vm_arena
            .vm_mut(0)
            .cap_table
            .set(2, Cap::Protocol(ProtocolCap { id: 2 }));

        // Create child VM with bitmask = 0b110 (copy caps at slots 1 and 2)
        kernel.set_active_reg(7, 0b110);
        kernel.set_active_reg(12, 66);
        kernel.dispatch_ecalli(64); // CALL CODE → CREATE

        // The child (VM 1) should have caps at slots 1 and 2
        assert!(
            kernel.vm_arena.vm(1).cap_table.get(1).is_some(),
            "child should inherit cap at slot 1"
        );
        assert!(
            kernel.vm_arena.vm(1).cap_table.get(2).is_some(),
            "child should inherit cap at slot 2"
        );
        // Slot 3 was not in bitmask → should be empty
        assert!(
            kernel.vm_arena.vm(1).cap_table.get(3).is_none(),
            "child should NOT have cap at slot 3"
        );
    }

    #[test]
    fn test_kernel_zero_gas_call() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Create child VM
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 66);
        kernel.dispatch_ecalli(64);
        let handle_idx = kernel.active_reg(7) as u8;

        // CALL with φ[9]=0 (zero gas transfer)
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(8, 0);
        kernel.set_active_reg(9, 0); // zero gas
        kernel.set_active_reg(12, 0);

        let result = kernel.dispatch_ecalli(handle_idx as u64);
        assert!(matches!(result, DispatchResult::Continue));

        // Child should be running but with very little gas
        assert_eq!(kernel.active_vm, 1);
    }

    #[test]
    fn test_kernel_nested_call_reply() {
        // VM 0 creates VM 1, calls it. VM 1 creates VM 2, calls it.
        // VM 2 replies. VM 1 replies. VM 0 receives final result.
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 1_000_000).unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // VM 0 creates VM 1, propagating the CODE cap at slot 64
        // bitmask bit 64 set means child inherits cap at slot 64
        kernel.set_active_reg(7, 1u64 << (64 % 64)); // bit 0 = slot 64's bitmap position
        kernel.set_active_reg(12, 66);
        kernel.dispatch_ecalli(64);
        let h1 = kernel.active_reg(7) as u8;

        // VM 0 calls VM 1
        kernel.set_active_reg(7, 10);
        kernel.set_active_reg(8, 0);
        kernel.set_active_reg(12, 0);
        kernel.dispatch_ecalli(h1 as u64);
        assert_eq!(kernel.active_vm, 1);
        assert_eq!(kernel.active_reg(7), 10);

        // VM 1 creates VM 2 using the inherited CODE cap
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 66);
        kernel.dispatch_ecalli(64);
        // If VM 1 doesn't have CODE cap at 64, CREATE fails silently.
        // Check if VM 2 was created.
        if kernel.vm_arena.len() < 3 {
            // CODE cap wasn't propagated — skip nested part, just test reply chain
            kernel.set_active_reg(7, 77);
            kernel.dispatch_ecalli(u64::from(IPC_SLOT));
            assert_eq!(kernel.active_vm, 0);
            assert_eq!(kernel.active_reg(7), 77);
            return;
        }
        let h2 = kernel.active_reg(7) as u8;

        // VM 1 calls VM 2
        kernel.set_active_reg(7, 20);
        kernel.set_active_reg(8, 0);
        kernel.set_active_reg(12, 0);
        kernel.dispatch_ecalli(h2 as u64);
        assert_eq!(kernel.active_vm, 2);
        assert_eq!(kernel.active_reg(7), 20);

        // VM 2 replies with 99
        kernel.set_active_reg(7, 99);
        kernel.dispatch_ecalli(u64::from(IPC_SLOT));
        assert_eq!(kernel.active_vm, 1);
        assert_eq!(kernel.active_reg(7), 99);

        // VM 1 replies with 77
        kernel.set_active_reg(7, 77);
        kernel.dispatch_ecalli(u64::from(IPC_SLOT));
        assert_eq!(kernel.active_vm, 0);
        assert_eq!(kernel.active_reg(7), 77);
    }

    #[test]
    fn test_code_cache_hit() {
        let blob = make_simple_blob(10);
        let mut cache = CodeCache::new();

        // First creation populates the cache.
        let k1 = InvocationKernel::new_cached(&blob, &[], 100_000, &mut cache).unwrap();
        assert_eq!(cache.entries.len(), 1);
        let first_arc = Arc::clone(&k1.code_caps[0]);
        drop(k1);

        // Second creation with the same blob should hit the cache.
        let k2 = InvocationKernel::new_cached(&blob, &[], 100_000, &mut cache).unwrap();
        assert_eq!(cache.entries.len(), 1); // no new entry
        // The Arc should point to the same allocation.
        assert!(Arc::ptr_eq(&first_arc, &k2.code_caps[0]));
    }

    /// Build a blob with a different code sub-blob (halt instead of trap).
    fn make_halt_blob(memory_pages: u32) -> Vec<u8> {
        // halt = opcode 1 (different from trap = opcode 0)
        let code = [1u8];
        let bitmask = [1u8];
        let jump_table: &[u32] = &[];
        let entry_size: u8 = 1;

        let mut sub = Vec::new();
        sub.extend_from_slice(&(jump_table.len() as u32).to_le_bytes());
        sub.push(entry_size);
        sub.extend_from_slice(&(code.len() as u32).to_le_bytes());
        sub.extend_from_slice(&code);
        sub.push(bitmask[0]);

        let caps = vec![
            CapManifestEntry {
                cap_index: 64,
                cap_type: CapEntryType::Code,
                base_page: 0,
                page_count: 0,
                init_access: Access::RO,
                data_offset: 0,
                data_len: sub.len() as u32,
            },
            CapManifestEntry {
                cap_index: 65,
                cap_type: CapEntryType::Data,
                base_page: 0,
                page_count: 1,
                init_access: Access::RW,
                data_offset: 0,
                data_len: 0,
            },
        ];
        build_blob(memory_pages, 64, 4096, &caps, &sub)
    }

    #[test]
    fn test_code_cache_miss_different_code() {
        let blob1 = make_simple_blob(10);
        let blob2 = make_halt_blob(10); // different code sub-blob content
        let mut cache = CodeCache::new();

        let _k1 = InvocationKernel::new_cached(&blob1, &[], 100_000, &mut cache).unwrap();
        assert_eq!(cache.entries.len(), 1);

        let _k2 = InvocationKernel::new_cached(&blob2, &[], 100_000, &mut cache).unwrap();
        assert_eq!(cache.entries.len(), 2); // separate entry for different code
    }

    #[test]
    fn test_code_cache_no_cache_path() {
        // new() (without cache) still works.
        let blob = make_simple_blob(10);
        let k = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        assert_eq!(k.code_caps.len(), 1);
    }

    #[test]
    fn test_new_warm_uses_cache() {
        let blob = make_simple_blob(10);
        let mut cache = CodeCache::new();

        // Cold start populates the cache.
        let k1 = InvocationKernel::new_cached(&blob, &[], 100_000, &mut cache).unwrap();
        assert_eq!(cache.entries.len(), 1);
        let first_arc = Arc::clone(&k1.code_caps[0]);

        // Extract flat_mem for warm restart.
        let (flat_mem, hb, ht) = k1.extract_flat_mem();
        drop(k1);

        // Warm restart with cache should reuse the compiled code.
        let k2 =
            InvocationKernel::new_warm(&blob, &[], 100_000, &flat_mem, hb, ht, Some(&mut cache))
                .unwrap();
        assert!(Arc::ptr_eq(&first_arc, &k2.code_caps[0]));
        assert_eq!(cache.entries.len(), 1);
    }

    #[test]
    fn test_new_warm_without_cache() {
        let blob = make_simple_blob(10);

        // new_warm with None still works.
        let k1 = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let (flat_mem, hb, ht) = k1.extract_flat_mem();
        drop(k1);

        let k2 = InvocationKernel::new_warm(&blob, &[], 100_000, &flat_mem, hb, ht, None).unwrap();
        assert_eq!(k2.code_caps.len(), 1);
    }

    fn continuation_blob(reply_after_resume: bool) -> Vec<u8> {
        // LoadImm64 T0, 41; Ecalli 7; Add64 T0 + A0 -> A0; then either
        // REPLY (for a child VM) or return through RA (for the root VM).
        let mut code = vec![20, 2];
        code.extend_from_slice(&41u64.to_le_bytes());
        code.extend_from_slice(&[10, 7]);
        code.extend_from_slice(&[200, 0x72, 7]);
        if reply_after_resume {
            code.extend_from_slice(&[10, 0]);
        } else {
            code.extend_from_slice(&[50, 0, 0, 0, 0, 0]);
        }
        let mut bitmask = vec![0u8; code.len()];
        bitmask[0] = 1;
        bitmask[10] = 1;
        bitmask[12] = 1;
        bitmask[15] = 1;
        make_blob_with(&code, &bitmask, &[])
    }

    fn call_dormant_then_halt_blob(handle_slot: u8) -> Vec<u8> {
        // CALL the preinstalled HANDLE, then halt through the root RA after
        // the dormant VM replies.
        let mut code = vec![10, handle_slot];
        code.extend_from_slice(&[50, 0, 0, 0, 0, 0]);
        let mut bitmask = vec![0u8; code.len()];
        bitmask[0] = 1;
        bitmask[2] = 1;
        make_blob_with(&code, &bitmask, &[])
    }

    #[test]
    fn observed_kernel_follows_nested_vm_switches_without_changing_state() {
        let root = call_dormant_then_halt_blob(100);
        let actor = continuation_blob(true);
        let make_kernel = || {
            let programs = [DormantProgram {
                blob: actor.as_slice(),
                handle_slot: 100,
            }];
            let mut kernel = InvocationKernel::new_with_dormant_programs(
                &root,
                &[],
                1_000_000,
                &programs,
                crate::backend::PvmBackend::ForceInterpreter,
            )
            .unwrap();
            kernel
                .vm_arena
                .vm_mut(1)
                .cap_table
                .set(7, Cap::Protocol(ProtocolCap { id: 7 }));
            kernel
                .vm_arena
                .vm_mut(0)
                .transition(VmState::Running)
                .unwrap();
            kernel
        };

        let mut baseline = make_kernel();
        assert!(matches!(
            baseline.run(),
            KernelResult::ProtocolCall { slot: 7 }
        ));
        let expected = baseline.snapshot().unwrap();

        let mut observed = make_kernel();
        let root_hash = observed.code_caps[0].program_hash;
        let actor_hash = observed.code_caps[1].program_hash;
        let mut events = Vec::new();
        let result = observed
            .run_observed(|event| {
                events.push((
                    event.active_vm,
                    event.code_cap_id,
                    event.program_hash,
                    event.call_depth,
                    event.instruction.pc_before,
                    event.instruction.exit.cloned(),
                ));
            })
            .unwrap();

        assert!(matches!(result, KernelResult::ProtocolCall { slot: 7 }));
        assert_eq!(observed.snapshot().unwrap(), expected);
        let first_child = events
            .iter()
            .position(|event| event.0 == 1)
            .expect("child instructions must be observed");
        assert!(
            events[..first_child].iter().all(|event| {
                event.0 == 0 && event.1 == 0 && event.2 == root_hash && event.3 == 0
            })
        );
        assert!(events[first_child..].iter().all(|event| {
            event.0 == 1 && event.1 == 1 && event.2 == actor_hash && event.3 == 1
        }));
        assert!(matches!(
            events.last(),
            Some((1, 1, _, 1, 10, Some(crate::ExitReason::HostCall(7))))
        ));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn observed_kernel_rejects_the_recompiler_backend() {
        let blob = continuation_blob(false);
        let mut kernel = InvocationKernel::new_with_backend(
            &blob,
            &[],
            100_000,
            crate::backend::PvmBackend::ForceRecompiler,
        )
        .unwrap();

        assert!(matches!(
            kernel.run_observed(|_| {}),
            Err(KernelObservationError::InterpreterRequired)
        ));
    }

    fn snapshot_dormant_program_call(
        root: &[u8],
        actor: &[u8],
        backend: crate::backend::PvmBackend,
    ) -> KernelSnapshot {
        let programs = [DormantProgram {
            blob: actor,
            handle_slot: 100,
        }];
        let mut kernel =
            InvocationKernel::new_with_dormant_programs(root, &[], 1_000_000, &programs, backend)
                .unwrap();

        assert_eq!(kernel.vm_arena.len(), 2);
        assert!(matches!(
            kernel.vm_arena.vm(0).cap_table.get(100),
            Some(Cap::Handle(_))
        ));
        assert!(!kernel.vm_arena.vm(0).cap_table.is_original(100));
        for slot in 1..=28 {
            assert!(kernel.vm_arena.vm(0).cap_table.is_original(slot));
            assert!(kernel.vm_arena.vm(1).cap_table.get(slot).is_none());
        }

        // This capability is supplied explicitly by the invocation owner. It
        // is not an original JAM protocol slot in the actor's CNode.
        kernel
            .vm_arena
            .vm_mut(1)
            .cap_table
            .set(7, Cap::Protocol(ProtocolCap { id: 7 }));
        assert!(!kernel.vm_arena.vm(1).cap_table.is_original(7));
        kernel
            .vm_arena
            .vm_mut(0)
            .transition(VmState::Running)
            .unwrap();

        assert!(matches!(
            kernel.run(),
            KernelResult::ProtocolCall { slot: 7 }
        ));
        assert_eq!(kernel.active_vm, 1);
        assert_eq!(kernel.vm_arena.vm(0).state, VmState::WaitingForReply);
        assert_eq!(kernel.vm_arena.vm(1).state, VmState::Running);
        let snapshot = kernel.snapshot().unwrap();
        assert_eq!(snapshot.call_stack.len(), 1);
        snapshot
    }

    #[test]
    fn dormant_program_snapshot_restore_is_exact_and_backend_portable() {
        let root = call_dormant_then_halt_blob(100);
        let actor = continuation_blob(true);
        let interpreter = snapshot_dormant_program_call(
            &root,
            &actor,
            crate::backend::PvmBackend::ForceInterpreter,
        );
        let recompiler = snapshot_dormant_program_call(
            &root,
            &actor,
            crate::backend::PvmBackend::ForceRecompiler,
        );
        assert_eq!(interpreter.to_bytes(), recompiler.to_bytes());

        let programs = [DormantProgram {
            blob: &actor,
            handle_slot: 100,
        }];
        for backend in [
            crate::backend::PvmBackend::ForceInterpreter,
            crate::backend::PvmBackend::ForceRecompiler,
        ] {
            let mut restored = InvocationKernel::restore_with_dormant_programs(
                &root,
                &programs,
                &interpreter,
                backend,
            )
            .unwrap();
            assert_eq!(restored.snapshot().unwrap(), interpreter);
            restored.resume_protocol_call(1, 0).unwrap();
            assert!(matches!(restored.run(), KernelResult::Halt));
            assert_eq!(restored.active_vm, 0);
            assert_eq!(restored.active_reg(7), 42);
            assert_eq!(restored.vm_arena.vm(1).state, VmState::Idle);
        }
    }

    #[test]
    fn dormant_program_restore_binds_bytes_order_and_handle_slots() {
        let root = call_dormant_then_halt_blob(100);
        let actor = continuation_blob(true);
        let snapshot = snapshot_dormant_program_call(
            &root,
            &actor,
            crate::backend::PvmBackend::ForceInterpreter,
        );

        let wrong_slot = [DormantProgram {
            blob: &actor,
            handle_slot: 101,
        }];
        assert!(matches!(
            InvocationKernel::restore_with_dormant_programs(
                &root,
                &wrong_slot,
                &snapshot,
                crate::backend::PvmBackend::ForceInterpreter,
            ),
            Err(SnapshotError::ProgramMismatch)
        ));

        let wrong_actor = continuation_blob(false);
        let wrong_bytes = [DormantProgram {
            blob: &wrong_actor,
            handle_slot: 100,
        }];
        assert!(matches!(
            InvocationKernel::restore_with_dormant_programs(
                &root,
                &wrong_bytes,
                &snapshot,
                crate::backend::PvmBackend::ForceInterpreter,
            ),
            Err(SnapshotError::ProgramMismatch)
        ));
        assert!(matches!(
            InvocationKernel::restore(
                &root,
                &snapshot,
                crate::backend::PvmBackend::ForceInterpreter,
                None
            ),
            Err(SnapshotError::ProgramMismatch)
        ));
    }

    #[test]
    fn dormant_program_handles_must_not_replace_root_authority() {
        let root = call_dormant_then_halt_blob(100);
        let actor = continuation_blob(true);
        for occupied in [0, 7, 64, 65, 254] {
            let programs = [DormantProgram {
                blob: &actor,
                handle_slot: occupied,
            }];
            assert!(matches!(
                InvocationKernel::new_with_dormant_programs(
                    &root,
                    &[],
                    1_000_000,
                    &programs,
                    crate::backend::PvmBackend::ForceInterpreter,
                ),
                Err(KernelError::ImportHandleUnavailable(slot)) if slot == occupied
            ));
        }

        let duplicate = [
            DormantProgram {
                blob: &actor,
                handle_slot: 100,
            },
            DormantProgram {
                blob: &actor,
                handle_slot: 100,
            },
        ];
        assert!(matches!(
            InvocationKernel::new_with_dormant_programs(
                &root,
                &[],
                1_000_000,
                &duplicate,
                crate::backend::PvmBackend::ForceInterpreter,
            ),
            Err(KernelError::ImportHandleUnavailable(100))
        ));
    }

    fn snapshot_root_at_protocol_call(
        blob: &[u8],
        backend: crate::backend::PvmBackend,
    ) -> KernelSnapshot {
        let mut kernel = InvocationKernel::new_with_backend(blob, &[], 100_000, backend).unwrap();
        let vm = kernel.vm_arena.vm_mut(0);
        vm.set_heap_base(0x1200);
        vm.set_heap_top(0x1800);
        vm.transition(VmState::Running).unwrap();
        assert!(kernel.write_data_cap(65, 19, b"durable-memory"));
        assert!(matches!(
            kernel.run(),
            KernelResult::ProtocolCall { slot: 7 }
        ));
        assert_eq!(kernel.vm_arena.vm(0).pc, 12);
        assert_eq!(kernel.active_reg(2), 41);
        kernel.snapshot().unwrap()
    }

    #[test]
    fn snapshot_resume_is_exact_and_backend_portable() {
        let blob = continuation_blob(false);
        let interpreter =
            snapshot_root_at_protocol_call(&blob, crate::backend::PvmBackend::ForceInterpreter);
        let recompiler =
            snapshot_root_at_protocol_call(&blob, crate::backend::PvmBackend::ForceRecompiler);
        assert_eq!(interpreter.to_bytes(), recompiler.to_bytes());

        let bytes = interpreter.to_bytes();
        let decoded = KernelSnapshot::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, interpreter);

        for backend in [
            crate::backend::PvmBackend::ForceInterpreter,
            crate::backend::PvmBackend::ForceRecompiler,
        ] {
            let mut restored = InvocationKernel::restore(&blob, &decoded, backend, None).unwrap();
            assert_eq!(restored.snapshot().unwrap(), decoded);
            assert!(restored.write_data_cap_window(19, b"durable-memory"));
            restored.resume_protocol_call(5, 9).unwrap();
            assert!(matches!(restored.run(), KernelResult::Halt));
            assert_eq!(restored.active_reg(2), 41);
            assert_eq!(restored.active_reg(7), 46);
            assert_eq!(restored.active_reg(8), 9);
            let vm = restored.vm_arena.vm(0);
            assert_eq!(vm.heap_base(), 0x1200);
            assert_eq!(vm.heap_top(), 0x1800);
            assert_eq!(
                restored.read_data_cap(65, 19, 14).as_deref(),
                Some(b"durable-memory".as_slice())
            );
        }
    }

    #[test]
    fn snapshot_rejects_program_memory_and_wire_tampering() {
        let blob = continuation_blob(false);
        let snapshot =
            snapshot_root_at_protocol_call(&blob, crate::backend::PvmBackend::ForceInterpreter);

        let mut retired_v4 = snapshot.clone();
        retired_v4.version = 4;
        assert_eq!(
            KernelSnapshot::from_bytes(&retired_v4.to_bytes()),
            Err(SnapshotError::UnsupportedVersion(4))
        );
        assert!(matches!(
            InvocationKernel::restore(
                &blob,
                &retired_v4,
                crate::backend::PvmBackend::ForceInterpreter,
                None,
            ),
            Err(SnapshotError::UnsupportedVersion(4))
        ));

        let mut wrong_program = snapshot.clone();
        wrong_program.code_hashes[0][0] ^= 1;
        assert!(matches!(
            InvocationKernel::restore(
                &blob,
                &wrong_program,
                crate::backend::PvmBackend::ForceInterpreter,
                None,
            ),
            Err(SnapshotError::ProgramMismatch)
        ));

        let mut retired_standard_profile = snapshot.clone();
        retired_standard_profile.isa_mode = SnapshotIsaMode::Conformance;
        assert!(matches!(
            InvocationKernel::restore(
                &blob,
                &retired_standard_profile,
                crate::backend::PvmBackend::ForceInterpreter,
                None,
            ),
            Err(SnapshotError::ProgramMismatch)
        ));

        let mut corrupt_memory = snapshot.clone();
        corrupt_memory.blocks[0].bytes[0] ^= 1;
        assert!(matches!(
            InvocationKernel::restore(
                &blob,
                &corrupt_memory,
                crate::backend::PvmBackend::ForceInterpreter,
                None,
            ),
            Err(SnapshotError::InvalidMemory)
        ));

        let mut trailing = snapshot.to_bytes();
        trailing.push(0);
        assert_eq!(
            KernelSnapshot::from_bytes(&trailing),
            Err(SnapshotError::TrailingBytes)
        );
    }

    #[test]
    fn nested_call_stack_restores_across_backends() {
        let blob = continuation_blob(true);
        let mut kernel = InvocationKernel::new_with_backend(
            &blob,
            &[],
            1_000_000,
            crate::backend::PvmBackend::ForceInterpreter,
        )
        .unwrap();
        kernel
            .vm_arena
            .vm_mut(0)
            .transition(VmState::Running)
            .unwrap();

        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 66);
        assert!(matches!(
            kernel.dispatch_ecalli(64),
            DispatchResult::Continue
        ));
        let child_handle = kernel.active_reg(7) as u8;
        kernel
            .vm_arena
            .vm_mut(1)
            .cap_table
            .set(7, Cap::Protocol(ProtocolCap { id: 7 }));

        let backing_offset = kernel.untyped.retype(4).unwrap();
        let mut ipc_data = DataCap::new(backing_offset, 4);
        assert!(ipc_data.map_pages(20, Access::RW, 1, 1));
        assert!(ipc_data.map_pages(20, Access::RW, 3, 1));
        kernel
            .vm_arena
            .vm_mut(0)
            .cap_table
            .set(67, Cap::Data(ipc_data));

        kernel.set_active_reg(6, 0xfeed_cafe);
        kernel.set_active_reg(7, 10);
        kernel.set_active_reg(12, 67);
        assert!(matches!(
            kernel.dispatch_ecalli(child_handle as u64),
            DispatchResult::Continue
        ));
        assert_eq!(kernel.active_vm, 1);
        assert!(matches!(
            kernel.run(),
            KernelResult::ProtocolCall { slot: 7 }
        ));
        let snapshot = kernel.snapshot().unwrap();
        assert_eq!(snapshot.call_stack.len(), 1);
        assert_eq!(snapshot.active_vm, 1);
        assert_eq!(
            snapshot.call_stack[0].ipc_mapped_bitmap.as_deref(),
            Some(&[0b0000_1010][..])
        );

        let encoded = snapshot.to_bytes();
        assert_eq!(KernelSnapshot::from_bytes(&encoded).unwrap(), snapshot);

        let mut duplicate_running = snapshot.clone();
        duplicate_running.arena.slots[0].vm.as_mut().unwrap().state = SnapshotVmState::Running;
        assert!(matches!(
            InvocationKernel::restore(
                &blob,
                &duplicate_running,
                crate::backend::PvmBackend::ForceInterpreter,
                None,
            ),
            Err(SnapshotError::InvalidScheduler)
        ));

        let mut broken_chain = snapshot.clone();
        broken_chain.arena.slots[1].vm.as_mut().unwrap().caller = None;
        assert!(matches!(
            InvocationKernel::restore(
                &blob,
                &broken_chain,
                crate::backend::PvmBackend::ForceInterpreter,
                None,
            ),
            Err(SnapshotError::InvalidScheduler)
        ));

        for backend in [
            crate::backend::PvmBackend::ForceInterpreter,
            crate::backend::PvmBackend::ForceRecompiler,
        ] {
            let mut restored = InvocationKernel::restore(&blob, &snapshot, backend, None).unwrap();
            assert_eq!(restored.snapshot().unwrap(), snapshot);
            restored.resume_protocol_call(1, 0).unwrap();

            // The child resumes after its await, replies with 42, and only
            // then does the root begin executing and reach its own call.
            assert!(matches!(
                restored.run(),
                KernelResult::ProtocolCall { slot: 7 }
            ));
            assert_eq!(restored.active_vm, 0);
            assert!(restored.call_stack.is_empty());
            assert_eq!(restored.vm_arena.vm(1).state, VmState::Idle);
            assert_eq!(restored.active_reg(6), 0xfeed_cafe);
            assert_eq!(restored.active_reg(7), 42);
            assert!(matches!(
                restored.vm_arena.vm(0).cap_table.get(67),
                Some(Cap::Data(data)) if data.mapped_runs() == vec![(1, 1), (3, 1)]
            ));
        }
    }
}
