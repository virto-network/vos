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
use std::sync::atomic::{AtomicUsize, Ordering};
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
/// 30k of them at most; and each holds kernel mappings, which
/// [`MappingBudget`] bounds across every pool.
pub const DEFAULT_IDLE_LIMIT: usize = 4096;

/// Idle machines a pool keeps by default for one program and backend, so
/// one busy program cannot crowd out the others.
pub const DEFAULT_IDLE_PER_PROGRAM: usize = 512;

/// Kernel mappings a native machine holds besides one for each run of its
/// guest window's permissions: its permission table, context, guards and
/// host alias, with room to spare.
const NATIVE_FIXED_MAPPINGS: usize = 8;

/// The kernel mappings idle native machines may hold together, process-wide,
/// so machines kept for reuse never crowd out running ones, whose page
/// permissions also take mappings: a quarter of the process's mapping limit
/// (`vm.max_map_count`, read once; Linux's default 65,530 where it cannot
/// be read). A machine past it is dropped rather than kept idle, which
/// changes no result, only how soon a machine is built again.
pub(crate) struct MappingBudget {
    held: AtomicUsize,
    limit: usize,
}

impl MappingBudget {
    const fn new(limit: usize) -> Self {
        Self {
            held: AtomicUsize::new(0),
            limit,
        }
    }

    /// The process's budget.
    fn process() -> &'static Self {
        static BUDGET: OnceLock<MappingBudget> = OnceLock::new();
        BUDGET.get_or_init(|| {
            let limit = std::fs::read_to_string("/proc/sys/vm/max_map_count")
                .ok()
                .and_then(|limit| limit.trim().parse::<usize>().ok())
                .unwrap_or(65_530);
            Self::new(limit / 4)
        })
    }

    /// Claim `mappings`, or `None` past the budget.
    fn claim(&'static self, mappings: usize) -> Option<MappingClaim> {
        self.held
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                (held + mappings <= self.limit).then_some(held + mappings)
            })
            .ok()
            .map(|_| MappingClaim {
                budget: self,
                mappings,
            })
    }
}

/// Mappings an idle machine holds against a [`MappingBudget`], returned
/// when the machine is lent or dropped.
pub(crate) struct MappingClaim {
    budget: &'static MappingBudget,
    mappings: usize,
}

impl Drop for MappingClaim {
    fn drop(&mut self) {
        self.budget.held.fetch_sub(self.mappings, Ordering::Relaxed);
    }
}

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
    /// A service's code past the Gray Paper's service-code bound
    /// ([`crate::spi::MAX_SERVICE_CODE`]): refine and accumulate of it fail
    /// as `BIG`.
    ServiceTooBig,
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
    /// changed. False when the backend failed to clear pages.
    ///
    /// Native memory is a shared mapping, where even a read of a page
    /// never written makes it resident, and no write tracking sees it.
    /// So every page of it the guest could have read and the image leaves
    /// zero (its regions' and those it mapped since) is discarded, and no
    /// page is zeroed in place: an idle native machine holds the image's
    /// pages alone, whatever a past tenant touched. Sparse memory holds a
    /// frame only for a page written, which the restore below zeroes in
    /// place when its run is short.
    fn restore(&self, memory: &mut Memory, permissions_changed: bool) -> bool {
        /// Runs this short are zeroed by writing; longer ones are discarded.
        const WRITE_ZEROS_PAGES: u32 = 16;
        let native = !memory.is_sparse();
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
                if native {
                    // Discarded with the readable pages below.
                } else if count <= WRITE_ZEROS_PAGES {
                    memory.zero_pages(page as usize, count as usize);
                } else if !memory.clear_pages(page as usize, count as usize) {
                    return false;
                }
                page = next;
            }
        }
        let changed = memory.take_changed_permissions();
        if native {
            let mapped = changed
                .iter()
                .filter(|&&(_, _, permission)| permission != PERM_NONE);
            for &(first, count, _) in self.regions.iter().chain(mapped) {
                if !self.clear_unimaged(memory, first, first + count) {
                    return false;
                }
            }
        }
        if permissions_changed {
            self.restore_permissions(memory, changed);
        }
        memory.take_changed_permissions();
        // The restores above are host writes, and no guest has run since
        // the capture: the next period starts clean.
        memory.forget_host_writes();
        true
    }

    /// Discard the pages of `[first, end)` the image holds nothing for.
    /// False when the backend failed to discard them.
    fn clear_unimaged(&self, memory: &mut Memory, first: usize, end: usize) -> bool {
        let mut page = first;
        for (&imaged, _) in self.pages.range(first as u32..end as u32) {
            let imaged = imaged as usize;
            if !memory.clear_pages(page, imaged - page) {
                return false;
            }
            page = imaged + 1;
        }
        memory.clear_pages(page, end - page)
    }

    /// Set every page of `changed`, the runs whose permission changed,
    /// that now differs from the image back to it, leaving the others
    /// untouched.
    fn restore_permissions(&self, memory: &mut Memory, changed: Vec<(usize, usize, u8)>) {
        for (first, count, permission) in changed {
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
    interpreter: OnceLock<PreparedExecution>,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    recompiler: OnceLock<PreparedExecution>,
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
        // A layout's sizes fit the 32-bit address space, so no term is past
        // u64.
        let whole = |gas: Option<Gas>| gas.unwrap_or(Gas::MAX);
        let allocate = |pages: u64| {
            whole(gas::linear(
                gas::PAGES_ALLOC_BASE,
                gas::PAGES_ALLOC_PER_PAGE,
                pages,
            ))
        };
        let poke =
            |bytes: usize| whole(gas::memory(gas::POKE_BASE, gas::POKE_PER_KIB, bytes as u64));
        let mut price = whole(gas::memory(
            gas::MACHINE_BASE,
            gas::MACHINE_PER_KIB,
            code_blob.len() as u64,
        ));
        if layout.ro.size > 0 {
            let pages = layout.ro.size / page;
            price = price
                .saturating_add(allocate(pages))
                .saturating_add(poke(layout.ro_data.len()))
                .saturating_add(whole(gas::linear(
                    gas::PAGES_SET_MODE_BASE,
                    gas::PAGES_SET_MODE_PER_PAGE,
                    pages,
                )));
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

    /// The pages a machine of the program holds mapped as laid out.
    pub(crate) fn mapped_pages(&self) -> usize {
        self.image.regions.iter().map(|&(_, count, _)| count).sum()
    }

    /// Whether a machine of the program may start at instruction counter
    /// `pc`, as `machine` checks its counter.
    pub(crate) fn enters_at(&self, pc: u32) -> bool {
        crate::spi::is_entry(&self.code, u64::from(pc))
    }

    /// Prepared execution on `backend`, built on first use. A failure is
    /// not kept: the host may have lacked a resource it has the next time.
    fn prepared(&self, backend: PvmBackend) -> Result<PreparedExecution, PoolError> {
        let slot = match crate::backend::resolve(backend).map_err(|_| PoolError::Backend)? {
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            PvmBackend::ForceRecompiler => &self.recompiler,
            resolved => {
                debug_assert_eq!(resolved, PvmBackend::ForceInterpreter);
                &self.interpreter
            }
        };
        if let Some(prepared) = slot.get() {
            return Ok(prepared.clone());
        }
        let prepared = PreparedExecution::new_standard(
            &self.code.code,
            &self.code.bitmask,
            &self.code.jump_table,
            backend,
        )
        .map_err(|_| PoolError::Backend)?;
        // Another thread may have prepared it meanwhile: every caller gets
        // the one kept.
        Ok(slot.get_or_init(|| prepared).clone())
    }
}

/// What a lent machine needs to return to its pool.
pub(crate) struct PoolTicket {
    pub(crate) program: Arc<PoolProgram>,
    permissions_revision: u64,
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
    /// Held while the machine is idle.
    idle: Option<MappingClaim>,
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
            idle: None,
        })
    }

    /// Lend the machine out as its parts.
    pub(crate) fn into_parts(self) -> (Interpreter, PreparedExecution, PoolTicket) {
        let ticket = PoolTicket {
            program: self.program,
            permissions_revision: self.permissions_revision,
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
            idle: None,
        }
    }

    /// Return the machine to a fresh build's state. False when it cannot
    /// be: its backend failed, so it must be dropped.
    fn reset(&mut self) -> bool {
        if self.vm.memory().retired() {
            return false;
        }
        let permissions_changed =
            self.vm.memory().permissions_revision() != self.permissions_revision;
        // Interpreter frames are bounded by `keep`; native memory keeps
        // the image's pages alone.
        if !self
            .program
            .image
            .restore(self.vm.memory_mut(), permissions_changed)
        {
            return false;
        }
        self.vm.reset_state(0);
        self.permissions_revision = self.vm.memory().permissions_revision();
        !self.vm.memory().retired()
    }

    /// Whether a reset machine is worth keeping idle, claiming its kernel
    /// mappings from `budget` when it is native: an interpreter machine
    /// that grew too large is not, nor is a native one past the budget.
    fn keep(&mut self, budget: &'static MappingBudget) -> bool {
        let memory = self.vm.memory();
        if memory.is_sparse() {
            return self.program.fresh_bytes.get().is_none_or(|&fresh| {
                memory.allocated_bytes() <= fresh.saturating_add(IDLE_GROWTH_LIMIT)
            });
        }
        let mappings = NATIVE_FIXED_MAPPINGS
            + memory.permission_runs().len()
            + memory.native_activation_splits();
        self.idle = budget.claim(mappings);
        self.idle.is_some()
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
    /// Hashes whose blobs failed to install: no valid program, so asked
    /// for again they are refused without being read, hashed or parsed.
    refused: Mutex<std::collections::HashSet<CodeHash>>,
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
            refused: Mutex::new(std::collections::HashSet::new()),
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
        let program = match PoolProgram::new(blob) {
            Ok(program) => Arc::new(program),
            Err(error) => {
                lock(&self.refused).insert(hash);
                return Err(error);
            }
        };
        lock(&self.programs).entry(hash).or_insert(program);
        Ok(hash)
    }

    /// Whether a blob of this hash failed to install.
    pub fn refused(&self, hash: &CodeHash) -> bool {
        lock(&self.refused).contains(hash)
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
        if !installed || !machine.reset() || !machine.keep(MappingBudget::process()) {
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
/// finished machine to the image, as `MachinePool::release` does.
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

    /// Outer machines of `blob`, a service's code, on `backend`, keeping at
    /// most `idle_limit` idle: refused past the service-code bound
    /// ([`PoolError::ServiceTooBig`]) before it is parsed.
    pub fn with_idle_limit(
        blob: &[u8],
        backend: PvmBackend,
        idle_limit: usize,
    ) -> Result<Self, PoolError> {
        if !crate::spi::service_fits(blob) {
            return Err(PoolError::ServiceTooBig);
        }
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
    /// `entry` with `gas`: 0 is refine, 5 accumulate. An `entry` that is no
    /// instruction start ends the run at once, uncharged
    /// ([`Machine::load_prepared_at`]).
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
        let mut machine = Machine::lent(vm, execution, gas, &layout, ticket);
        machine.enter_at(&self.standard.code, entry);
        Ok(machine)
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
        if !machine.reset() || !machine.keep(MappingBudget::process()) {
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
/// larger than the admission bound, or whose preparation holds more than an
/// eighth of the cache, is prepared without caching, so one large program
/// never empties the cache for every other.
/// The largest program the process-wide preparation cache keeps.
pub(crate) const PREPARED_ADMISSION_BYTES: usize = 2 << 20;

pub(crate) fn prepared_code(
    code_blob: &[u8],
    code: &CodeBlob,
    backend: PvmBackend,
) -> Result<PreparedExecution, String> {
    /// Host bytes the kept preparations hold before the cache starts
    /// over, counted in what each holds (its tables and native code, tens
    /// to hundreds of bytes a blob byte), not by blob. What the cache keeps
    /// changes no result, only how often a program is prepared again.
    const CAPACITY_BYTES: usize = 512 << 20;

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
    let footprint = execution.footprint();
    if footprint > CAPACITY_BYTES / 8 {
        return Ok(execution);
    }
    let mut cache = lock(cache);
    if cache.bytes + footprint > CAPACITY_BYTES {
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
    cache.bytes += footprint;
    Ok(execution)
}

#[cfg(test)]
mod tests;
