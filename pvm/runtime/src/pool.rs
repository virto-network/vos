//! The node's machine pool: standard programs installed by code hash and
//! prepared once per backend, and idle inner machines laid out from them,
//! ready for `instantiate`.
//!
//! A machine `instantiate` returns is laid out as the standard layout with
//! no arguments, exactly as a loader issuing `machine`, then `pages` and
//! `poke`, would lay it out. When it is expunged it returns to the pool,
//! which resets it to what a fresh build gives:
//! - the pages written since it was built, by the guest or the host, are
//!   restored from the program's image or cleared;
//! - any `pages` changes are undone;
//! - registers, gas, the instruction counter and the continuation state
//!   return to their initial values.
//!
//! Memory revision counters keep counting across resets, so caches keyed by
//! them never mistake a reused machine for its earlier self.
//!
//! [`OuterMachines`] keeps one program's outer machines the same way: a
//! node's agent runs its refine, accumulate and queries on machines laid
//! out once and reset after each run.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use crate::backend::{PreparedExecution, PvmBackend};
use crate::inner::gas;
use crate::interpreter::{Interpreter, Memory, PERM_NONE, PERM_RO, PERM_RW};
use crate::refine::{Invocation, Machine, RefineError};
use crate::spi::{CodeBlob, StandardProgram};
use crate::{Gas, PVM_PAGE_SIZE, PVM_REGISTER_COUNT};

const PAGE: usize = PVM_PAGE_SIZE as usize;

/// Idle machines a pool keeps by default, across programs. Each JIT machine
/// reserves more than 4 GiB of address space, so a process can hold about
/// 30k of them at most.
pub const DEFAULT_IDLE_LIMIT: usize = 4096;

/// Idle machines a pool keeps by default for one program and backend, so
/// one busy program cannot crowd out the others.
pub const DEFAULT_IDLE_PER_PROGRAM: usize = 512;

/// A native machine that has zeroed this many pages in place since its last
/// deep clean has all its pages discarded and its image reinstalled, so
/// idle machines do not keep a past tenant's footprint resident.
const DEEP_CLEAN_PAGES: usize = 256;

/// Lock pool state even after a panic elsewhere: it is only maps and
/// counts, and releasing machines while unwinding must not abort.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A released interpreter machine whose memory grew this much beyond a
/// fresh build's is dropped rather than kept idle.
const IDLE_GROWTH_LIMIT: usize = 4 << 20;

/// BLAKE2b-256 of a standard program blob: the hash JAM names code by.
///
/// It names the whole blob, which `instantiate` lays out, while `machine`
/// takes only the compact code. On JAM, the agent's loader looks the blob
/// up by this hash and extracts the code itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CodeHash(pub [u8; 32]);

impl CodeHash {
    pub fn of(blob: &[u8]) -> Self {
        Self(crate::precompile::blake2b_256(blob))
    }
}

/// Why a program could not be installed or a machine built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolError {
    /// Not a valid standard program, or its layout does not fit.
    InvalidProgram,
    /// The execution backend failed.
    Backend,
}

/// A program's initial memory: page permissions and the pages that are
/// not zero.
struct Image {
    /// (first page, count, permission), in address order.
    regions: Vec<(usize, usize, u8)>,
    pages: BTreeMap<u32, Box<[u8; PAGE]>>,
}

impl Image {
    /// Lay the image into memory whose pages are all inaccessible.
    fn install(&self, memory: &mut Memory) {
        for &(first, count, permission) in &self.regions {
            memory.set_page_range(first, count, permission);
        }
        for (&page, bytes) in &self.pages {
            memory.init_copy(page * PVM_PAGE_SIZE, &bytes[..]);
        }
    }

    /// Return memory laid out by [`Self::install`] to the image: restore or
    /// clear every page written since, and restore the permissions that
    /// changed. Returns the pages zeroed in place, which stay resident, or
    /// `None` when the backend failed to clear pages.
    fn restore(&self, memory: &mut Memory, permissions_changed: bool) -> Option<usize> {
        /// Runs this short are zeroed by writing; longer ones are discarded.
        const WRITE_ZEROS_PAGES: u32 = 16;
        let mut zeroed = 0;
        for range in memory.take_pages_since_reset() {
            let mut page = range.start;
            while page < range.end {
                if let Some(bytes) = self.pages.get(&page) {
                    memory.init_copy(page * PVM_PAGE_SIZE, &bytes[..]);
                    page += 1;
                    continue;
                }
                let next = self
                    .pages
                    .range(page..range.end)
                    .next()
                    .map_or(range.end, |(&next, _)| next);
                let count = next - page;
                if count <= WRITE_ZEROS_PAGES {
                    memory.zero_pages(page as usize, count as usize);
                    zeroed += count as usize;
                } else if !memory.clear_pages(page as usize, count as usize) {
                    return None;
                }
                page = next;
            }
        }
        if permissions_changed {
            self.restore_permissions(memory);
        }
        memory.take_changed_permissions();
        // The restores above are host writes, and no guest has run since
        // the capture: the next period starts clean.
        memory.forget_host_writes();
        Some(zeroed)
    }

    /// Discard every page and reinstall the image's contents, leaving only
    /// the image resident. Permissions are unchanged. False when the backend
    /// failed to discard pages.
    fn deep_clean(&self, memory: &mut Memory) -> bool {
        let pages = memory.pages();
        if !memory.clear_pages(0, pages) {
            return false;
        }
        for (&page, bytes) in &self.pages {
            memory.init_copy(page * PVM_PAGE_SIZE, &bytes[..]);
        }
        memory.forget_host_writes();
        true
    }

    /// Set every page whose permission changed and now differs from the
    /// image back to it, leaving the others untouched.
    fn restore_permissions(&self, memory: &mut Memory) {
        for (first, count, permission) in memory.take_changed_permissions() {
            let end = first + count;
            let mut page = first;
            while page < end {
                let (wanted, until) = self.permission_at(page, end);
                if wanted != permission {
                    memory.set_page_range(page, until - page, wanted);
                }
                page = until;
            }
        }
    }

    /// The image's permission at `page`, and where that stretch ends, up to
    /// `end`.
    fn permission_at(&self, page: usize, end: usize) -> (u8, usize) {
        for &(first, count, permission) in &self.regions {
            if page < first {
                return (PERM_NONE, first.min(end));
            }
            if page < first + count {
                return (permission, (first + count).min(end));
            }
        }
        (PERM_NONE, end)
    }
}

/// A standard program installed in a pool.
pub struct PoolProgram {
    hash: CodeHash,
    code_blob: Arc<[u8]>,
    code: CodeBlob,
    image: Image,
    price: Gas,
    interpreter: OnceLock<Result<PreparedExecution, String>>,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    recompiler: OnceLock<Result<PreparedExecution, String>>,
    /// Host memory a fresh interpreter machine of this program holds.
    fresh_bytes: OnceLock<usize>,
}

impl PoolProgram {
    fn new(blob: &[u8]) -> Result<Self, PoolError> {
        let program = crate::spi::parse_standard_program(blob).ok_or(PoolError::InvalidProgram)?;
        let layout = program.layout(&[]).ok_or(PoolError::InvalidProgram)?;
        let code_blob: Arc<[u8]> = program
            .compact_code()
            .ok_or(PoolError::InvalidProgram)?
            .into();

        let page = PVM_PAGE_SIZE as u64;
        let mut regions = Vec::new();
        for region in [layout.ro, layout.rw, layout.stack] {
            if region.size > 0 {
                let permission = if region.writable { PERM_RW } else { PERM_RO };
                regions.push((
                    (region.base / page) as usize,
                    (region.size / page) as usize,
                    permission,
                ));
            }
        }
        let mut pages = BTreeMap::new();
        for (base, data) in [
            (layout.ro.base, layout.ro_data),
            (layout.rw.base, layout.rw_data),
        ] {
            for (index, chunk) in data.chunks(PAGE).enumerate() {
                if chunk.iter().any(|&byte| byte != 0) {
                    let mut bytes = Box::new([0u8; PAGE]);
                    bytes[..chunk.len()].copy_from_slice(chunk);
                    pages.insert((base / page) as u32 + index as u32, bytes);
                }
            }
        }

        // What the same layout costs a loader in `machine`, `pages` and
        // `poke` calls: read-only data is mapped writable, poked and then
        // made read-only.
        let allocate =
            |pages: u64| gas::PAGES_ALLOC_BASE.saturating_add(pages * gas::PAGES_ALLOC_PER_PAGE);
        let poke = |bytes: usize| {
            gas::POKE_BASE.saturating_add(gas::memory(gas::POKE_PER_KIB, bytes as u64))
        };
        let mut price = gas::MACHINE_BASE
            .saturating_add(gas::memory(gas::MACHINE_PER_KIB, code_blob.len() as u64));
        if layout.ro.size > 0 {
            let pages = layout.ro.size / page;
            price = price
                .saturating_add(allocate(pages))
                .saturating_add(poke(layout.ro_data.len()))
                .saturating_add(
                    gas::PAGES_SET_MODE_BASE.saturating_add(pages * gas::PAGES_SET_MODE_PER_PAGE),
                );
        }
        if layout.rw.size > 0 {
            price = price.saturating_add(allocate(layout.rw.size / page));
            if !layout.rw_data.is_empty() {
                price = price.saturating_add(poke(layout.rw_data.len()));
            }
        }
        if layout.stack.size > 0 {
            price = price.saturating_add(allocate(layout.stack.size / page));
        }

        Ok(Self {
            hash: CodeHash::of(blob),
            code_blob,
            code: program.code,
            image: Image { regions, pages },
            price,
            interpreter: OnceLock::new(),
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            recompiler: OnceLock::new(),
            fresh_bytes: OnceLock::new(),
        })
    }

    pub fn hash(&self) -> CodeHash {
        self.hash
    }

    /// The compact code blob, as `machine` takes it.
    pub fn code_blob(&self) -> &Arc<[u8]> {
        &self.code_blob
    }

    /// The gas `instantiate` charges: what laying out the same machine
    /// costs a loader in host calls.
    pub fn price(&self) -> Gas {
        self.price
    }

    /// Whether a machine of the program may start at instruction counter
    /// `pc`, as `machine` checks its counter.
    pub(crate) fn enters_at(&self, pc: u32) -> bool {
        crate::spi::is_entry(&self.code, u64::from(pc))
    }

    /// Prepared execution on `backend`, built on first use.
    fn prepared(&self, backend: PvmBackend) -> Result<PreparedExecution, PoolError> {
        let slot = match crate::backend::resolve(backend).map_err(|_| PoolError::Backend)? {
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            PvmBackend::ForceRecompiler => &self.recompiler,
            resolved => {
                debug_assert_eq!(resolved, PvmBackend::ForceInterpreter);
                &self.interpreter
            }
        };
        slot.get_or_init(|| {
            PreparedExecution::new_standard(
                &self.code.code,
                &self.code.bitmask,
                &self.code.jump_table,
                backend,
            )
        })
        .clone()
        .map_err(|_| PoolError::Backend)
    }
}

/// What a lent machine needs to return to its pool.
pub(crate) struct PoolTicket {
    pub(crate) program: Arc<PoolProgram>,
    permissions_revision: u64,
    zeroed: usize,
}

impl core::fmt::Debug for PoolTicket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PoolTicket")
            .field("program", &self.program.hash)
            .finish_non_exhaustive()
    }
}

/// An inner machine owned by a pool, lent out by `instantiate`.
pub(crate) struct PooledMachine {
    pub(crate) program: Arc<PoolProgram>,
    pub(crate) execution: PreparedExecution,
    pub(crate) vm: Interpreter,
    /// The permission revision right after the last build or reset.
    permissions_revision: u64,
    /// Pages zeroed in place since the last deep clean.
    zeroed: usize,
}

impl PooledMachine {
    fn build(program: &Arc<PoolProgram>, execution: PreparedExecution) -> Result<Self, PoolError> {
        let sparse = execution.backend() != PvmBackend::ForceRecompiler;
        let mut memory = execution
            .allocate_memory(1u64 << 32, sparse)
            .map_err(|_| PoolError::Backend)?;
        let pages = memory.pages();
        memory.set_page_range(0, pages, PERM_NONE);
        program.image.install(&mut memory);
        memory.take_pages_since_reset();
        memory.take_changed_permissions();
        if sparse {
            program.fresh_bytes.get_or_init(|| memory.allocated_bytes());
        }
        let mut vm = Interpreter::from_predecoded(
            execution.interpreter_program(),
            [0; PVM_REGISTER_COUNT],
            memory,
            0,
        );
        vm.set_pc(0);
        let permissions_revision = vm.memory().permissions_revision();
        Ok(Self {
            program: Arc::clone(program),
            execution,
            vm,
            permissions_revision,
            zeroed: 0,
        })
    }

    /// Lend the machine out as its parts.
    pub(crate) fn into_parts(self) -> (Interpreter, PreparedExecution, PoolTicket) {
        let ticket = PoolTicket {
            program: self.program,
            permissions_revision: self.permissions_revision,
            zeroed: self.zeroed,
        };
        (self.vm, self.execution, ticket)
    }

    /// Reassemble a lent machine.
    pub(crate) fn from_parts(
        vm: Interpreter,
        execution: PreparedExecution,
        ticket: PoolTicket,
    ) -> Self {
        Self {
            program: ticket.program,
            execution,
            vm,
            permissions_revision: ticket.permissions_revision,
            zeroed: ticket.zeroed,
        }
    }

    /// Return the machine to a fresh build's state. False when it cannot
    /// be: its backend failed, so it must be dropped.
    fn reset(&mut self) -> bool {
        if self.vm.memory().tracking_failed() {
            return false;
        }
        let permissions_changed =
            self.vm.memory().permissions_revision() != self.permissions_revision;
        let Some(zeroed) = self
            .program
            .image
            .restore(self.vm.memory_mut(), permissions_changed)
        else {
            return false;
        };
        self.zeroed += zeroed;
        // Interpreter frames are bounded by `keep`; native pages zeroed in
        // place stay resident until discarded.
        if self.zeroed > DEEP_CLEAN_PAGES && !self.vm.memory().is_sparse() {
            if !self.program.image.deep_clean(self.vm.memory_mut()) {
                return false;
            }
            self.zeroed = 0;
        }
        self.vm.reset_state(0);
        self.permissions_revision = self.vm.memory().permissions_revision();
        !self.vm.memory().tracking_failed()
    }

    /// Whether a reset machine is worth keeping idle.
    fn keep(&self) -> bool {
        let memory = self.vm.memory();
        !memory.is_sparse()
            || self.program.fresh_bytes.get().is_none_or(|&fresh| {
                memory.allocated_bytes() <= fresh.saturating_add(IDLE_GROWTH_LIMIT)
            })
    }
}

#[derive(Default)]
struct IdleMachines {
    by_program: HashMap<(CodeHash, PvmBackend), Vec<PooledMachine>>,
    count: usize,
}

/// Installed programs and their idle machines, shared by every refine on a
/// node.
pub struct MachinePool {
    programs: Mutex<HashMap<CodeHash, Arc<PoolProgram>>>,
    idle: Mutex<IdleMachines>,
    idle_limit: usize,
    idle_per_program: usize,
}

impl Default for MachinePool {
    fn default() -> Self {
        Self::with_idle_limits(DEFAULT_IDLE_LIMIT, DEFAULT_IDLE_PER_PROGRAM)
    }
}

impl MachinePool {
    pub fn new() -> Self {
        Self::default()
    }

    /// A pool keeping at most `idle_limit` idle machines, and at most
    /// `idle_per_program` for one program and backend.
    pub fn with_idle_limits(idle_limit: usize, idle_per_program: usize) -> Self {
        Self {
            programs: Mutex::new(HashMap::new()),
            idle: Mutex::new(IdleMachines::default()),
            idle_limit,
            idle_per_program,
        }
    }

    /// Install a standard program, returning its code hash. Installing the
    /// same program again is a no-op. It is parsed before the pool's lock is
    /// taken, so a program loading holds no other run.
    pub fn install(&self, blob: &[u8]) -> Result<CodeHash, PoolError> {
        let hash = CodeHash::of(blob);
        if lock(&self.programs).contains_key(&hash) {
            return Ok(hash);
        }
        let program = Arc::new(PoolProgram::new(blob)?);
        lock(&self.programs).entry(hash).or_insert(program);
        Ok(hash)
    }

    /// Remove an installed program and drop its idle machines. Machines
    /// still lent are dropped when they return.
    pub fn uninstall(&self, hash: &CodeHash) {
        lock(&self.programs).remove(hash);
        let dropped: Vec<PooledMachine> = {
            let mut idle = lock(&self.idle);
            let keys: Vec<_> = idle
                .by_program
                .keys()
                .filter(|(program, _)| program == hash)
                .copied()
                .collect();
            let dropped: Vec<_> = keys
                .iter()
                .filter_map(|key| idle.by_program.remove(key))
                .flatten()
                .collect();
            idle.count -= dropped.len();
            dropped
        };
        drop(dropped);
    }

    /// The installed program with this hash.
    pub fn program(&self, hash: &CodeHash) -> Option<Arc<PoolProgram>> {
        lock(&self.programs).get(hash).cloned()
    }

    /// Idle machines held, across programs.
    pub fn idle(&self) -> usize {
        lock(&self.idle).count
    }

    /// An idle machine of `program` on `backend`, or a fresh build.
    pub(crate) fn acquire(
        &self,
        program: &Arc<PoolProgram>,
        backend: PvmBackend,
    ) -> Result<PooledMachine, PoolError> {
        let execution = program.prepared(backend)?;
        let key = (program.hash, execution.backend());
        let idle = {
            let mut idle = lock(&self.idle);
            let machine = idle.by_program.get_mut(&key).and_then(Vec::pop);
            if machine.is_some() {
                idle.count -= 1;
            }
            machine
        };
        match idle {
            Some(machine) => Ok(machine),
            None => PooledMachine::build(program, execution),
        }
    }

    /// Reset a machine and keep it idle, or drop it when it cannot be reset,
    /// grew too large, its program was uninstalled, or the pool is full.
    pub(crate) fn release(&self, mut machine: PooledMachine) {
        let installed = lock(&self.programs)
            .get(&machine.program.hash)
            .is_some_and(|program| Arc::ptr_eq(program, &machine.program));
        if !installed || !machine.reset() || !machine.keep() {
            return;
        }
        let key = (machine.program.hash, machine.execution.backend());
        let mut idle = lock(&self.idle);
        let for_program = idle.by_program.get(&key).map_or(0, Vec::len);
        if idle.count < self.idle_limit && for_program < self.idle_per_program {
            idle.count += 1;
            idle.by_program.entry(key).or_default().push(machine);
        }
    }
}

/// Idle outer machines an [`OuterMachines`] keeps by default.
pub const DEFAULT_IDLE_OUTER: usize = 64;

/// One program's outer machines: a node's agent runs its refine,
/// accumulate and queries on them.
///
/// Each is built as the pool builds an inner machine, with the program's
/// image and no arguments, and kept between runs. [`Self::load`] lays a
/// run's arguments in and sets its registers, gas and entry, giving what
/// [`Machine::load_prepared_at`] gives with one difference that no guest
/// sees: the memory spans the whole 32-bit address space, as an inner
/// machine's does, and the pages past the layout are inaccessible rather
/// than past the span; both fault alike. [`Self::restore`] resets a
/// finished machine to the image, as [`MachinePool::release`] does.
pub struct OuterMachines {
    program: Arc<PoolProgram>,
    standard: StandardProgram,
    execution: PreparedExecution,
    idle: Mutex<Vec<PooledMachine>>,
    idle_limit: usize,
}

impl OuterMachines {
    pub fn new(blob: &[u8], backend: PvmBackend) -> Result<Self, PoolError> {
        Self::with_idle_limit(blob, backend, DEFAULT_IDLE_OUTER)
    }

    /// Outer machines of `blob` on `backend`, keeping at most `idle_limit`
    /// idle.
    pub fn with_idle_limit(
        blob: &[u8],
        backend: PvmBackend,
        idle_limit: usize,
    ) -> Result<Self, PoolError> {
        let standard = crate::spi::parse_standard_program(blob).ok_or(PoolError::InvalidProgram)?;
        let program = Arc::new(PoolProgram::new(blob)?);
        let execution = program.prepared(backend)?;
        Ok(Self {
            program,
            standard,
            execution,
            idle: Mutex::new(Vec::new()),
            idle_limit,
        })
    }

    /// The resolved backend.
    pub fn backend(&self) -> PvmBackend {
        self.execution.backend()
    }

    /// A machine laid out for `args`, starting at instruction counter
    /// `entry` with `gas`: 0 is refine, 5 accumulate.
    pub fn load(&self, entry: u32, args: &[u8], gas: Gas) -> Result<Machine, RefineError> {
        let layout = self
            .standard
            .layout(args)
            .ok_or(RefineError::LayoutOverflow)?;
        let idle = lock(&self.idle).pop();
        let machine = match idle {
            Some(machine) => machine,
            None => PooledMachine::build(&self.program, self.execution.clone())
                .map_err(|_| RefineError::Backend)?,
        };
        let (mut vm, execution, ticket) = machine.into_parts();
        let memory = vm.memory_mut();
        let args = layout.args;
        if args.size > 0 {
            let permission = if args.writable { PERM_RW } else { PERM_RO };
            let page = PVM_PAGE_SIZE as u64;
            memory.set_page_range(
                (args.base / page) as usize,
                (args.size / page) as usize,
                permission,
            );
            memory.init_copy(args.base as u32, layout.args_data);
        }
        // Dirty pages count from the loaded image, as for a fresh load.
        memory.take_dirty_pages();
        vm.registers = layout.registers;
        vm.gas = gas;
        vm.set_pc(entry);
        Ok(Machine::lent(vm, execution, gas, ticket))
    }

    /// Reset the machine `invocation` finished on and keep it idle, or drop
    /// it when it cannot be reset, grew too large, was not lent here, or
    /// enough are idle.
    pub fn restore(&self, invocation: Invocation) {
        let Some((memory, ticket)) = invocation.into_lent() else {
            return;
        };
        if !Arc::ptr_eq(&ticket.program, &self.program) {
            return;
        }
        let vm = Interpreter::from_predecoded(
            self.execution.interpreter_program(),
            [0; PVM_REGISTER_COUNT],
            memory,
            0,
        );
        let mut machine = PooledMachine::from_parts(vm, self.execution.clone(), ticket);
        if !machine.reset() || !machine.keep() {
            return;
        }
        let mut idle = lock(&self.idle);
        if idle.len() < self.idle_limit {
            idle.push(machine);
        }
    }

    /// Idle machines held.
    pub fn idle(&self) -> usize {
        lock(&self.idle).len()
    }
}

/// Process-wide preparation cache for programs `machine` creates, keyed by
/// the exact code blob and the backend the selection resolves to. A program
/// larger than the admission bound is prepared without caching.
/// The largest program the process-wide preparation cache keeps.
pub(crate) const PREPARED_ADMISSION_BYTES: usize = 2 << 20;

pub(crate) fn prepared_code(
    code_blob: &[u8],
    code: &CodeBlob,
    backend: PvmBackend,
) -> Result<PreparedExecution, String> {
    /// Code bytes kept across programs before the cache starts over.
    const CAPACITY_BYTES: usize = 64 << 20;

    struct Cache {
        by_backend: HashMap<PvmBackend, HashMap<Arc<[u8]>, PreparedExecution>>,
        bytes: usize,
    }
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();

    let backend = crate::backend::resolve(backend)?;
    let prepare =
        || PreparedExecution::new_standard(&code.code, &code.bitmask, &code.jump_table, backend);
    if code_blob.len() > PREPARED_ADMISSION_BYTES {
        return prepare();
    }
    let cache = CACHE.get_or_init(|| {
        Mutex::new(Cache {
            by_backend: HashMap::new(),
            bytes: 0,
        })
    });
    if let Some(execution) = cache
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .by_backend
        .get(&backend)
        .and_then(|programs| programs.get(code_blob))
    {
        return Ok(execution.clone());
    }
    let execution = prepare()?;
    let mut cache = lock(cache);
    if cache.bytes + code_blob.len() > CAPACITY_BYTES {
        cache.by_backend.clear();
        cache.bytes = 0;
    }
    let programs = cache.by_backend.entry(backend).or_default();
    // Another thread may have prepared the same program meanwhile: every
    // caller gets the one entry the cache keeps.
    if let Some(existing) = programs.get(code_blob) {
        return Ok(existing.clone());
    }
    programs.insert(code_blob.into(), execution.clone());
    cache.bytes += code_blob.len();
    Ok(execution)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inner::{InnerError, InnerExit, InnerMachines, InvokeState, PageMode};
    use crate::instruction::Opcode;
    use proptest::prelude::*;

    const ZONE: u32 = 0x1_0000;

    /// A standard program whose code stores φ9 at φ8 (8 bytes) and φ11 at
    /// φ10 (2 bytes), compresses with BLAKE2b (h at φ7, m at φ8), stops at
    /// host call 0x77, stores φ9's low byte at φ12, then traps.
    fn program() -> Vec<u8> {
        let code = vec![
            Opcode::StoreIndU64 as u8,
            9 | (8 << 4),
            Opcode::StoreIndU16 as u8,
            11 | (10 << 4),
            Opcode::Ecalli as u8,
            0x00,
            0x04,
            Opcode::Ecalli as u8,
            0x77,
            Opcode::StoreIndU8 as u8,
            9 | (12 << 4),
            Opcode::Trap as u8,
        ];
        let mut bitmask = vec![0; code.len()];
        for start in [0, 2, 4, 7, 9, 11] {
            bitmask[start] = 1;
        }
        let code = vos_pvm_program::build_compact_code_blob(&CodeBlob {
            code,
            bitmask,
            jump_table: Vec::new(),
        })
        .unwrap();
        let ro: Vec<u8> = (0..300).map(|i| (i * 7) as u8 | 1).collect();
        let rw: Vec<u8> = (0..5000).map(|i| (i * 13) as u8).collect();
        let (heap_pages, stack) = (2u16, 8192u32);
        let mut blob = Vec::new();
        blob.extend_from_slice(&(ro.len() as u32).to_le_bytes()[..3]);
        blob.extend_from_slice(&(rw.len() as u32).to_le_bytes()[..3]);
        blob.extend_from_slice(&heap_pages.to_le_bytes());
        blob.extend_from_slice(&stack.to_le_bytes()[..3]);
        blob.extend_from_slice(&ro);
        blob.extend_from_slice(&rw);
        blob.extend_from_slice(&(code.len() as u32).to_le_bytes());
        blob.extend_from_slice(&code);
        blob
    }

    /// The machine a loader builds with `machine`, then `pages` and `poke`:
    /// the reference a pooled machine must equal.
    fn loaded(blob: &[u8], backend: PvmBackend) -> (InnerMachines, u32) {
        loaded_at(blob, backend, 0)
    }

    /// As [`loaded`], the machine made at instruction counter `pc`.
    fn loaded_at(blob: &[u8], backend: PvmBackend, pc: u32) -> (InnerMachines, u32) {
        let program = crate::spi::parse_standard_program(blob).unwrap();
        let layout = program.layout(&[]).unwrap();
        let mut machines = InnerMachines::with_backend(backend);
        let id = machines
            .create(&program.compact_code().unwrap(), pc)
            .unwrap();
        let page = PVM_PAGE_SIZE as u64;
        let pages = |machines: &mut InnerMachines, region: crate::spi::SpiRegion, mode| {
            machines
                .pages(
                    id,
                    (region.base / page) as u32,
                    (region.size / page) as u32,
                    mode,
                )
                .unwrap();
        };
        if layout.ro.size > 0 {
            pages(&mut machines, layout.ro, PageMode::AllocateReadWrite);
            machines
                .poke(id, layout.ro.base as u32, layout.ro_data)
                .unwrap();
            pages(&mut machines, layout.ro, PageMode::SetReadOnly);
        }
        if layout.rw.size > 0 {
            pages(&mut machines, layout.rw, PageMode::AllocateReadWrite);
            if !layout.rw_data.is_empty() {
                machines
                    .poke(id, layout.rw.base as u32, layout.rw_data)
                    .unwrap();
            }
        }
        if layout.stack.size > 0 {
            pages(&mut machines, layout.stack, PageMode::AllocateReadWrite);
        }
        (machines, id)
    }

    /// Everything a guest or a host can observe of a machine: registers, gas,
    /// counter and continuation state, permissions, and the contents of
    /// every mapped page and every page in `extra`.
    #[derive(Debug, PartialEq, Eq)]
    struct Dump {
        program: Vec<u8>,
        initial_pc: u32,
        registers: [u64; PVM_REGISTER_COUNT],
        gas: Gas,
        pc: u32,
        pending: Option<(u64, u32, u32)>,
        gas_charged: bool,
        need_gas_charge: bool,
        permissions: Vec<(usize, usize, u8)>,
        pages: BTreeMap<u32, Vec<u8>>,
    }

    fn dump(machines: &InnerMachines, id: u32, extra: &[u32]) -> Dump {
        let view = machines
            .views()
            .find(|view| view.identity.slot == id)
            .unwrap();
        let vm = view.machine.unwrap();
        let memory = vm.memory();
        let permissions = memory.permission_runs();
        let mut indices: Vec<u32> = permissions
            .iter()
            .filter(|&&(_, _, permission)| permission != PERM_NONE)
            .flat_map(|&(first, count, _)| first as u32..(first + count) as u32)
            .chain(extra.iter().copied())
            .collect();
        indices.sort_unstable();
        indices.dedup();
        let pages = indices
            .into_iter()
            .map(|index| {
                let mut bytes = vec![0; PAGE];
                memory.read_bytes(index * PVM_PAGE_SIZE, &mut bytes);
                (index, bytes)
            })
            .filter(|(_, bytes)| bytes.iter().any(|&byte| byte != 0))
            .collect();
        Dump {
            program: view.program.to_vec(),
            initial_pc: view.initial_pc,
            registers: vm.registers,
            gas: vm.gas,
            pc: vm.pc,
            pending: vm
                .pending_host_call()
                .map(|call| (call.id, call.cause_pc, call.resume_pc)),
            gas_charged: vm.gas_charged,
            need_gas_charge: vm.need_gas_charge,
            permissions,
            pages,
        }
    }

    /// Addresses the test aims at: inside the layout's regions, across page
    /// boundaries next to mapped and unmapped pages, and outside the layout.
    fn address() -> impl Strategy<Value = u32> {
        let stack_top = ((1u64 << 32) - 2 * u64::from(ZONE) - (1 << 24)) as u32;
        prop_oneof![
            (0u32..300).prop_map(|offset| ZONE + offset),
            (0u32..4 * 4096).prop_map(|offset| 3 * ZONE + offset),
            (0u32..2 * 4096).prop_map(move |offset| stack_top - 2 * 4096 + offset),
            Just(3 * ZONE + 4 * 4096 - 1),
            Just(stack_top - 1),
            Just(ZONE - 1),
            (0u32..64).prop_map(|offset| 0x50_0000 + offset * 4096),
        ]
    }

    #[derive(Clone, Debug)]
    enum Op {
        Poke(u32, u8, u16),
        Pages(u32, u32, u8),
        Invoke(Gas, [u32; 5], u64),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (address(), any::<u8>(), 1u16..6000)
                .prop_map(|(at, byte, len)| Op::Poke(at, byte, len)),
            (address(), 1u32..20, 0u8..5).prop_map(|(at, count, mode)| Op::Pages(
                at / 4096,
                count,
                mode
            )),
            (
                0u64..2000,
                proptest::array::uniform5(address()),
                any::<u64>()
            )
                .prop_map(|(gas, at, value)| Op::Invoke(gas, at, value)),
        ]
    }

    fn apply(
        machines: &mut InnerMachines,
        id: u32,
        op: &Op,
        carried: &mut InvokeState,
    ) -> Vec<u32> {
        match *op {
            Op::Poke(at, byte, len) => {
                let _ = machines.poke(id, at, &vec![byte; len as usize]);
                (at / 4096..=(at.saturating_add(u32::from(len)) - 1) / 4096).collect()
            }
            Op::Pages(first, count, mode) => {
                let _ = machines.pages(
                    id,
                    first,
                    count,
                    PageMode::try_from(u64::from(mode)).unwrap(),
                );
                (first..first.saturating_add(count)).collect()
            }
            Op::Invoke(gas, at, value) => {
                // φ7 h, φ8 store base and m, φ10 second store, φ12 last store.
                let mut registers = carried.registers;
                for (register, &address) in [7, 8, 10, 12, 11].iter().zip(&at) {
                    registers[*register] = u64::from(address);
                }
                registers[9] = value;
                registers[11] = value.rotate_left(17);
                let outcome = machines.invoke(id, InvokeState { gas, registers });
                if let Ok(outcome) = outcome {
                    *carried = outcome.state;
                }
                at.iter()
                    .flat_map(|&address| [address / 4096, address.saturating_add(8) / 4096])
                    .collect()
            }
        }
    }

    /// What [`program`] runs with: h at the read-write data's start, m two
    /// pages on, a 2-byte store across its first page boundary, and the
    /// last store 100 bytes in.
    fn probe_state() -> InvokeState {
        let mut registers = [0; PVM_REGISTER_COUNT];
        registers[7] = u64::from(3 * ZONE);
        registers[8] = u64::from(3 * ZONE + 2 * 4096);
        registers[9] = 0x0123_4567_89ab_cdef;
        registers[10] = u64::from(3 * ZONE + 4095);
        registers[11] = 0xbeef;
        registers[12] = u64::from(3 * ZONE + 100);
        InvokeState {
            gas: 1_000_000,
            registers,
        }
    }

    fn probe(machines: &mut InnerMachines, id: u32) -> (InnerExit, InvokeState) {
        let mut state = probe_state();
        loop {
            let outcome = machines.invoke(id, state).unwrap();
            state = outcome.state;
            if outcome.exit != InnerExit::Host(0x77) {
                return (outcome.exit, state);
            }
        }
    }

    fn backends() -> Vec<PvmBackend> {
        let mut backends = vec![PvmBackend::ForceInterpreter];
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        backends.push(PvmBackend::ForceRecompiler);
        backends
    }

    #[test]
    fn instantiate_lays_out_what_a_loader_builds() {
        let blob = program();
        let pool = Arc::new(MachinePool::new());
        let hash = pool.install(&blob).unwrap();
        assert_eq!(hash, CodeHash::of(&blob));
        assert_eq!(
            pool.install(&blob).unwrap(),
            hash,
            "installing again is a no-op"
        );
        let program = pool.program(&hash).unwrap();
        for backend in backends() {
            let mut pooled = InnerMachines::with_backend(backend);
            pooled.set_pool(Arc::clone(&pool));
            let id = pooled.instantiate(&program, 0).unwrap();
            let (mut reference, reference_id) = loaded(&blob, backend);
            assert_eq!(
                dump(&pooled, id, &[]),
                dump(&reference, reference_id, &[]),
                "{backend:?}"
            );
            assert_eq!(
                probe(&mut pooled, id),
                probe(&mut reference, reference_id),
                "{backend:?}"
            );
            assert_eq!(
                dump(&pooled, id, &[]),
                dump(&reference, reference_id, &[]),
                "{backend:?}"
            );
        }
        // What the loader paid in host calls: machine, then pages, poke and
        // set-read-only for one read-only page, pages and poke for four
        // read-write pages (5,000 data bytes and two heap pages), and pages
        // for two stack pages.
        let code = program.code_blob().len() as u64;
        let expected = gas::MACHINE_BASE
            + gas::memory(gas::MACHINE_PER_KIB, code)
            + gas::PAGES_ALLOC_BASE
            + gas::PAGES_ALLOC_PER_PAGE
            + gas::POKE_BASE
            + gas::memory(gas::POKE_PER_KIB, 300)
            + gas::PAGES_SET_MODE_BASE
            + gas::PAGES_SET_MODE_PER_PAGE
            + gas::PAGES_ALLOC_BASE
            + 4 * gas::PAGES_ALLOC_PER_PAGE
            + gas::POKE_BASE
            + gas::memory(gas::POKE_PER_KIB, 5000)
            + gas::PAGES_ALLOC_BASE
            + 2 * gas::PAGES_ALLOC_PER_PAGE;
        assert_eq!(program.price(), expected);
    }

    /// A machine suspended at a host call, restored from the counter
    /// `expunge` gives and the pages it wrote: a pooled machine
    /// instantiated at that counter, the pages poked back, equals a
    /// loader's machine made there, and resumes right after the call as it
    /// does. Entered mid-block, both are charged the whole block again,
    /// where the machine that never stopped pays nothing more.
    #[test]
    fn instantiate_at_a_counter_resumes_a_suspended_machine() {
        let blob = program();
        let pool = Arc::new(MachinePool::new());
        let program = pool.program(&pool.install(&blob).unwrap()).unwrap();
        // The read-write region's four pages: every page the program writes.
        let first = 3 * ZONE / 4096;
        let written: Vec<u32> = (first..first + 4).collect();
        let state = probe_state();
        let [h, m, last] = [7, 8, 12].map(|register| state.registers[register] as u32);
        let half = state.registers[10] as u32;
        let compression = crate::precompile::price(crate::precompile::BLAKE2B_COMPRESS).unwrap();
        for backend in backends() {
            let mut machines = InnerMachines::with_backend(backend);
            machines.set_pool(Arc::clone(&pool));
            let to_the_call = |machines: &mut InnerMachines| {
                let id = machines.instantiate(&program, 0).unwrap();
                let outcome = machines.invoke(id, probe_state()).unwrap();
                assert_eq!(outcome.exit, InnerExit::Host(0x77), "{backend:?}");
                (id, outcome.state)
            };

            let (stopped, suspended) = to_the_call(&mut machines);
            let pages: Vec<(u32, Vec<u8>)> = written
                .iter()
                .map(|&page| (page, machines.peek(stopped, page * 4096, PAGE).unwrap()))
                .collect();
            let pc = machines.expunge(stopped).unwrap();
            assert_eq!(pc, 9, "{backend:?}: right after the 2-byte call at 7");
            let block = state.gas - suspended.gas - compression;

            let (going, at_call) = to_the_call(&mut machines);
            let continued = machines.invoke(going, at_call.clone()).unwrap();
            assert_eq!(continued.exit, InnerExit::Panic, "{backend:?}");
            assert_eq!(continued.state.gas, at_call.gas, "{backend:?}: funded");
            machines.expunge(going).unwrap();

            // Marks where the stores before the call wrote: a resume that
            // ran them again would overwrite them.
            let restore = |machines: &mut InnerMachines, id: u32| {
                for (page, bytes) in &pages {
                    machines.poke(id, page * 4096, bytes).unwrap();
                }
                for (address, len) in [(h, 64), (m, 8), (half, 2)] {
                    machines.poke(id, address, &vec![0xa5; len]).unwrap();
                }
            };
            let restored = machines.instantiate(&program, pc).unwrap();
            restore(&mut machines, restored);
            let (mut reference, reference_id) = loaded_at(&blob, backend, pc);
            restore(&mut reference, reference_id);
            assert_eq!(
                dump(&machines, restored, &[]),
                dump(&reference, reference_id, &[]),
                "{backend:?}"
            );

            let resumed = machines.invoke(restored, suspended.clone()).unwrap();
            let expected = reference.invoke(reference_id, suspended.clone()).unwrap();
            assert_eq!(resumed, expected, "{backend:?}");
            assert_eq!(
                resumed.exit,
                InnerExit::Panic,
                "{backend:?}: no second call"
            );
            assert_eq!(
                suspended.gas - resumed.state.gas,
                block,
                "{backend:?}: the whole block again"
            );
            assert_eq!(
                machines.peek(restored, last, 1).unwrap(),
                [0xef],
                "{backend:?}: the store after the call landed"
            );
            for (address, len) in [(h, 64), (m, 8), (half, 2)] {
                assert_eq!(
                    machines.peek(restored, address, len).unwrap(),
                    vec![0xa5; len],
                    "{backend:?}: nothing before the call ran again"
                );
            }
            assert_eq!(
                dump(&machines, restored, &[]),
                dump(&reference, reference_id, &[]),
                "{backend:?}"
            );
            assert_eq!(machines.expunge(restored), Ok(0), "{backend:?}");
            assert_eq!(
                machines
                    .instantiate(&program, 0)
                    .map(|id| machines.expunge(id)),
                Ok(Ok(0)),
                "{backend:?}: a machine returned to the pool starts at 0"
            );
        }
    }

    #[test]
    fn instantiate_refuses_a_counter_that_starts_no_instruction() {
        let blob = program();
        let pool = Arc::new(MachinePool::new());
        let program = pool.program(&pool.install(&blob).unwrap()).unwrap();
        let mut machines = InnerMachines::new();
        machines.set_pool(Arc::clone(&pool));
        for pc in [1, 3, 8, 12, u32::MAX] {
            assert_eq!(
                machines.instantiate(&program, pc),
                Err(InnerError::Invalid),
                "{pc}"
            );
        }
        assert!(machines.is_empty());
        let id = machines.instantiate(&program, 11).unwrap();
        assert_eq!(machines.expunge(id), Ok(11));
    }

    #[test]
    fn machines_whose_backend_failed_never_return() {
        let blob = program();
        let pool = Arc::new(MachinePool::new());
        let program = pool.program(&pool.install(&blob).unwrap()).unwrap();
        let mut machines = InnerMachines::new();
        machines.set_pool(Arc::clone(&pool));
        let id = machines.instantiate(&program, 0).unwrap();
        machines.fail_backend_for_test(id);
        machines.expunge(id).unwrap();
        assert_eq!(pool.idle(), 0);
    }

    #[test]
    fn uninstalled_programs_and_full_programs_keep_no_machines() {
        let blob = program();
        let pool = Arc::new(MachinePool::with_idle_limits(8, 1));
        let hash = pool.install(&blob).unwrap();
        let program = pool.program(&hash).unwrap();
        let mut machines = InnerMachines::new();
        machines.set_pool(Arc::clone(&pool));
        let first = machines.instantiate(&program, 0).unwrap();
        let second = machines.instantiate(&program, 0).unwrap();
        machines.expunge(first).unwrap();
        machines.expunge(second).unwrap();
        assert_eq!(pool.idle(), 1, "one idle machine per program");

        let lent = machines.instantiate(&program, 0).unwrap();
        pool.uninstall(&hash);
        assert!(pool.program(&hash).is_none());
        machines.expunge(lent).unwrap();
        assert_eq!(
            pool.idle(),
            0,
            "an uninstalled program's machines are dropped"
        );
    }

    /// A native machine whose resets zeroed many pages in place has all its
    /// pages discarded, and still equals a fresh one.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn scattered_writes_trigger_a_deep_clean() {
        let blob = program();
        let pool = Arc::new(MachinePool::new());
        let program = pool.program(&pool.install(&blob).unwrap()).unwrap();
        let mut machines = InnerMachines::with_backend(PvmBackend::ForceRecompiler);
        machines.set_pool(Arc::clone(&pool));
        let base = 0x50_0000u32 / 4096;
        let zeroed = |pool: &MachinePool| {
            lock(&pool.idle)
                .by_program
                .values()
                .flatten()
                .map(|machine| machine.zeroed)
                .sum::<usize>()
        };
        let mut cleaned = false;
        for _ in 0..4 {
            let id = machines.instantiate(&program, 0).unwrap();
            machines
                .pages(id, base, 400, PageMode::AllocateReadWrite)
                .unwrap();
            for page in (0..400).step_by(2) {
                machines.poke(id, (base + page) * 4096, &[1]).unwrap();
            }
            machines.expunge(id).unwrap();
            cleaned |= zeroed(&pool) == 0;
        }
        assert!(cleaned, "a deep clean ran");
        let id = machines.instantiate(&program, 0).unwrap();
        let (reference, reference_id) = loaded(&blob, PvmBackend::ForceRecompiler);
        let touched: Vec<u32> = (base..base + 400).collect();
        assert_eq!(
            dump(&machines, id, &touched),
            dump(&reference, reference_id, &touched)
        );
    }

    /// A standard program that stores u64 `args[8..16]` at address
    /// `args[0..8]`, then halts with output `args[24..32]` bytes at address
    /// `args[16..24]`.
    fn scribe() -> Vec<u8> {
        let mut code = Vec::new();
        let mut starts = Vec::new();
        let mut asm = |instruction: &[u8]| {
            starts.push(code.len());
            code.extend_from_slice(instruction);
        };
        let load = Opcode::LoadIndU64 as u8;
        asm(&[load, 2 | (7 << 4)]);
        asm(&[load, 3 | (7 << 4), 8]);
        asm(&[load, 4 | (7 << 4), 16]);
        asm(&[load, 5 | (7 << 4), 24]);
        asm(&[Opcode::StoreIndU64 as u8, 3 | (2 << 4)]);
        asm(&[Opcode::MoveReg as u8, 7 | (4 << 4)]);
        asm(&[Opcode::MoveReg as u8, 8 | (5 << 4)]);
        asm(&[Opcode::JumpInd as u8, 0]);
        let mut bitmask = vec![0; code.len()];
        for start in starts {
            bitmask[start] = 1;
        }
        let code = vos_pvm_program::build_compact_code_blob(&CodeBlob {
            code,
            bitmask,
            jump_table: Vec::new(),
        })
        .unwrap();
        let ro: Vec<u8> = (0..300).map(|i| (i * 7) as u8 | 1).collect();
        let rw: Vec<u8> = (0..5000).map(|i| (i * 13) as u8).collect();
        let (heap_pages, stack) = (2u16, 8192u32);
        let mut blob = Vec::new();
        blob.extend_from_slice(&(ro.len() as u32).to_le_bytes()[..3]);
        blob.extend_from_slice(&(rw.len() as u32).to_le_bytes()[..3]);
        blob.extend_from_slice(&heap_pages.to_le_bytes());
        blob.extend_from_slice(&stack.to_le_bytes()[..3]);
        blob.extend_from_slice(&ro);
        blob.extend_from_slice(&rw);
        blob.extend_from_slice(&(code.len() as u32).to_le_bytes());
        blob.extend_from_slice(&code);
        blob
    }

    /// `scribe`'s regions: read-only data, read-write data and heap, the
    /// stack, and the arguments.
    const SCRIBE_RO: u64 = 0x1_0000;
    const SCRIBE_RW: u64 = 0x3_0000;
    const SCRIBE_RW_END: u64 = 0x3_4000;
    const SCRIBE_STACK: u64 = 0xFEFD_E000;
    const SCRIBE_ARGS: u64 = 0xFEFF_0000;

    /// An address in or around one of `scribe`'s regions.
    fn scribe_address() -> impl Strategy<Value = u64> {
        prop_oneof![
            (0..0x4000u64 - 8).prop_map(|offset| SCRIBE_RW + offset),
            (0..0x2000u64 - 8).prop_map(|offset| SCRIBE_STACK + offset),
            (0..0x1000u64).prop_map(|offset| SCRIBE_RO + offset),
            (0..0x3000u64).prop_map(|offset| SCRIBE_ARGS + offset),
            Just(SCRIBE_RW_END - 4),
            Just(0x2_0000),
        ]
    }

    /// One run of `scribe`: its arguments, padded with a pattern to a
    /// length that spans zero to three pages, and its gas.
    fn scribe_run() -> impl Strategy<Value = (Vec<u8>, u64)> {
        (
            scribe_address(),
            any::<u64>(),
            scribe_address(),
            prop_oneof![Just(0u64), Just(8), Just(100), Just(5000)],
            prop_oneof![Just(0usize), Just(16), 32..0x2800usize],
            any::<u8>(),
            prop_oneof![Just(5u64), Just(1_000_000)],
        )
            .prop_map(|(at, value, out, len, size, pattern, gas)| {
                let mut args = Vec::new();
                for word in [at, value, out, len] {
                    args.extend_from_slice(&word.to_le_bytes());
                }
                args.resize(size.max(32), pattern | 1);
                args.truncate(size);
                (args, gas)
            })
    }

    fn finish(mut machine: Machine) -> Invocation {
        let exit = machine.try_resume().unwrap();
        machine.finish(exit)
    }

    /// What a run shows: its exit, gas, registers, counter and output, and
    /// the bytes of every page it may have touched or read.
    fn shown(invocation: &Invocation, args: usize) -> (String, Option<Vec<u8>>, Vec<u8>) {
        let mut bytes = Vec::new();
        let mut page = |at: u64| {
            let mut buffer = vec![0u8; PAGE];
            invocation.memory().read_bytes(at as u32, &mut buffer);
            bytes.extend_from_slice(&buffer);
        };
        for at in (SCRIBE_RO..SCRIBE_RO + 0x1000).step_by(PAGE) {
            page(at);
        }
        for at in (SCRIBE_RW..SCRIBE_RW_END).step_by(PAGE) {
            page(at);
        }
        for at in (SCRIBE_STACK..SCRIBE_STACK + 0x2000).step_by(PAGE) {
            page(at);
        }
        for at in (SCRIBE_ARGS..SCRIBE_ARGS + args.next_multiple_of(PAGE) as u64).step_by(PAGE) {
            page(at);
        }
        let state = format!(
            "{:?} {} {:?} {}",
            invocation.exit, invocation.gas_used, invocation.registers, invocation.pc
        );
        (state, invocation.output_bounded(0x4000), bytes)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Over any sequence of runs, each laying in arguments of a
        /// different length, storing anywhere, faulting or running out of
        /// gas, a kept outer machine runs as a freshly loaded one does, and
        /// leaves nothing behind: its earlier arguments and stores read as
        /// they would on a fresh machine.
        #[test]
        fn kept_outer_machines_equal_fresh_ones(
            runs in proptest::collection::vec(scribe_run(), 1..8),
        ) {
            let blob = scribe();
            for backend in backends() {
                let outer = OuterMachines::new(&blob, backend).unwrap();
                let prepared =
                    crate::refine::PreparedProgram::new_with_backend(&blob, backend).unwrap();
                for (args, gas) in &runs {
                    let kept = finish(outer.load(0, args, *gas).unwrap());
                    let fresh = finish(
                        Machine::load_prepared_at(
                            &prepared,
                            0,
                            args,
                            *gas,
                            crate::refine::MemoryModel::Auto,
                        )
                        .unwrap(),
                    );
                    prop_assert_eq!(
                        shown(&kept, args.len()),
                        shown(&fresh, args.len()),
                        "{:?}",
                        backend
                    );
                    outer.restore(kept);
                    prop_assert_eq!(outer.idle(), 1, "the machine is kept");
                }
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// After any sequence of guest stores (straddling ones included),
        /// precompile output, `poke`, `pages` changes, host-call stops and
        /// running out of gas, a released machine comes back equal to one a
        /// loader builds from scratch, and behaves the same.
        #[test]
        fn released_machines_equal_fresh_ones(ops in proptest::collection::vec(op(), 1..12)) {
            let blob = program();
            let pool = Arc::new(MachinePool::new());
            let program = pool.program(&pool.install(&blob).unwrap()).unwrap();
            for backend in backends() {
                let mut pooled = InnerMachines::with_backend(backend);
                pooled.set_pool(Arc::clone(&pool));
                let id = pooled.instantiate(&program, 0).unwrap();
                let mut carried = InvokeState { gas: 0, registers: [0; PVM_REGISTER_COUNT] };
                let mut touched = Vec::new();
                for op in &ops {
                    touched.extend(apply(&mut pooled, id, op, &mut carried));
                }
                pooled.expunge(id).unwrap();
                prop_assert_eq!(pool.idle(), 1, "the released machine is kept");

                let id = pooled.instantiate(&program, 0).unwrap();
                prop_assert_eq!(pool.idle(), 0, "and lent again");
                let (mut reference, reference_id) = loaded(&blob, backend);
                prop_assert_eq!(
                    dump(&pooled, id, &touched),
                    dump(&reference, reference_id, &touched),
                    "{:?}", backend
                );
                prop_assert_eq!(probe(&mut pooled, id), probe(&mut reference, reference_id));
                prop_assert_eq!(
                    dump(&pooled, id, &touched),
                    dump(&reference, reference_id, &touched),
                    "{:?} after a run", backend
                );
                pooled.expunge(id).unwrap();
                drop(pooled);
                prop_assert_eq!(pool.idle(), 1);
                let _ = pool.acquire(&program, backend).unwrap();
            }
        }
    }
}
