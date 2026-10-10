//! Standard Refine inner-machine management.
//!
//! This module implements the portable `machine`, `peek`, `poke`, `pages`,
//! `invoke`, and `expunge` substrate from Gray Paper v0.8.0. It has no
//! capability-kernel dependency and is available in `no_std` builds.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::backend::{PreparedExecution, PvmBackend};
use crate::interpreter::{Interpreter, PERM_NONE, PERM_RO, PERM_RW};
use crate::spi::deblob;
use crate::{ExitReason, Gas, PVM_PAGE_SIZE, PVM_REGISTER_COUNT};

/// Maximum live inner machines in one Refine invocation.
pub const MAX_INNER_MACHINES: usize = 63;

/// Number of pages in the 32-bit PVM address space.
pub const INNER_ADDRESS_PAGES: usize = (1u64 << 32) as usize / PVM_PAGE_SIZE as usize;

/// The first page an inner machine may map.
pub const INNER_FIRST_MAPPABLE_PAGE: u32 = 16;

fn prepare_inner_program(
    program_blob: &[u8],
    program: &vos_pvm_program::CodeBlob,
    backend: PvmBackend,
) -> Result<PreparedExecution, InnerError> {
    #[cfg(feature = "std")]
    let prepared = crate::pool::prepared_code(program_blob, program, backend);
    #[cfg(not(feature = "std"))]
    let prepared = {
        let _ = program_blob;
        PreparedExecution::new_standard(
            &program.code,
            &program.bitmask,
            &program.jump_table,
            backend,
        )
    };
    prepared.map_err(|_| InnerError::Backend)
}

/// Stable host-call identifiers for the standard inner-machine surface.
pub mod host_call {
    pub const MACHINE: u32 = 9;
    pub const PEEK: u32 = 10;
    pub const POKE: u32 = 11;
    pub const PAGES: u32 = 12;
    pub const INVOKE: u32 = 13;
    pub const EXPUNGE: u32 = 14;
    /// VOS extension: an inner machine from the node's pool, laid out as the
    /// installed standard program whose code hash φ7 points at, at
    /// instruction counter 0. On a host without it (JAM), the call answers
    /// `WHAT` and the guest lays the machine out itself with `machine`, then
    /// `pages` and `poke`.
    pub const INSTANTIATE: u32 = 0x480;
    /// VOS extension: read the agent's applied state by key, served when the
    /// node supplies a state reader. φ7/φ8 hold the key, φ9 the output, φ10
    /// the offset into the value and φ11 the output length; φ7 becomes the
    /// value's length, or `NONE`. On JAM the call answers `WHAT` and state
    /// comes from witnesses in the work package.
    pub const STATE_READ: u32 = 0x481;
    /// VOS extension: rows of the agent's applied state under a prefix, in
    /// key order, served when the node supplies a state reader; `WHAT` on
    /// JAM, as `state_read`.
    pub const STATE_SCAN: u32 = 0x482;
}

/// Gray Paper 0.8.0 general and refine host calls the node serves besides
/// the inner-machine calls. `fetch` (2), `write` (5) and `log` (100) were
/// confirmed on PolkaJam 0.1.29 (spike SJ); the rest follow the same
/// numbering, which places `machine` at 9.
pub mod gp_call {
    pub const GAS: u32 = 0;
    pub const FETCH: u32 = 2;
    pub const LOOKUP: u32 = 3;
    pub const READ: u32 = 4;
    pub const WRITE: u32 = 5;
    pub const INFO: u32 = 6;
    pub const HISTORICAL_LOOKUP: u32 = 7;
    pub const EXPORT: u32 = 8;
    pub const LOG: u32 = 100;
}

/// v0.8.0 host-call gas constants.
pub mod gas {
    pub const MACHINE_BASE: u64 = 1_862;
    pub const MACHINE_PER_KIB: u64 = 112;
    pub const PEEK_BASE: u64 = 377;
    pub const PEEK_PER_KIB: u64 = 336;
    pub const POKE_BASE: u64 = 297;
    pub const POKE_PER_KIB: u64 = 224;
    pub const PAGES_FREE_BASE: u64 = 212;
    pub const PAGES_FREE_PER_PAGE: u64 = 118;
    pub const PAGES_ALLOC_BASE: u64 = 275;
    pub const PAGES_ALLOC_PER_PAGE: u64 = 121;
    pub const PAGES_SET_MODE_BASE: u64 = 130;
    pub const PAGES_SET_MODE_PER_PAGE: u64 = 29;
    pub const PAGES_INVALID: u64 = 80;
    pub const INVOKE_BASE: u64 = 968;
    pub const EXPUNGE: u64 = 335;

    /// The standard memory-sized gas function, `ceil(rate * bytes / 1024)`.
    pub const fn memory(rate: u64, bytes: u64) -> u64 {
        let Some(product) = rate.checked_mul(bytes) else {
            return u64::MAX;
        };
        let Some(rounded) = product.checked_add(1023) else {
            return u64::MAX;
        };
        rounded / 1024
    }
}

/// Result-code-shaped failures from an inner-machine operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InnerError {
    /// The 63-machine invocation limit has been reached.
    Full,
    /// The supplied program or page operation is invalid.
    Invalid,
    /// The machine index does not exist.
    Unknown,
    /// The requested inner-memory range is not accessible.
    OutOfBounds,
    /// The selected host backend could not prepare or execute the machine.
    /// This is not a guest result and must not be translated to HUH.
    Backend,
}

/// Page mutation requested through the standard `pages` operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PageMode {
    Free = 0,
    AllocateReadOnly = 1,
    AllocateReadWrite = 2,
    SetReadOnly = 3,
    SetReadWrite = 4,
}

impl TryFrom<u64> for PageMode {
    type Error = InnerError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Free),
            1 => Ok(Self::AllocateReadOnly),
            2 => Ok(Self::AllocateReadWrite),
            3 => Ok(Self::SetReadOnly),
            4 => Ok(Self::SetReadWrite),
            _ => Err(InnerError::Invalid),
        }
    }
}

/// Register and gas state passed through the standard `invoke` operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvokeState {
    pub gas: Gas,
    pub registers: [u64; PVM_REGISTER_COUNT],
}

/// Why an inner invocation returned to its outer machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InnerExit {
    Halt,
    Panic,
    Fault(u32),
    Host(u64),
    OutOfGas,
}

/// Result of invoking one inner machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvokeOutcome {
    pub exit: InnerExit,
    pub state: InvokeState,
}

/// Invocation-unique identity of one inner machine.
///
/// Slots are deliberately reusable after `expunge`; `generation` is not.
/// Proof traces use the pair so two different programs that occupied the
/// same dictionary slot can never be spliced together.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct InnerMachineIdentity {
    pub slot: u32,
    pub generation: u64,
}

/// Immutable dictionary view used by nested proof boundary tracers.
/// `machine` is absent until the lazily-created inner interpreter is first
/// needed; the canonical compact `program` and entry counter remain available
/// in either state.
pub struct InnerMachineView<'a> {
    pub identity: InnerMachineIdentity,
    pub program: &'a [u8],
    pub initial_pc: u32,
    pub machine: Option<&'a Interpreter>,
}

/// Read-only events emitted while an inner machine is invoked.
pub enum InnerMachineObservation<'a> {
    Enter {
        identity: InnerMachineIdentity,
        machine: &'a Interpreter,
    },
    Instruction {
        identity: InnerMachineIdentity,
        instruction: crate::interpreter::InstructionObservation<'a>,
    },
    /// A precompile served in place; execution continues in the same slice.
    Precompile {
        identity: InnerMachineIdentity,
        call: &'a crate::precompile::PrecompileCall,
    },
    Exit {
        identity: InnerMachineIdentity,
        exit: InnerExit,
        machine: &'a Interpreter,
    },
}

struct InnerMachine {
    generation: u64,
    program_blob: Arc<[u8]>,
    execution: PreparedExecution,
    initial_pc: u32,
    vm: Option<Interpreter>,
    /// Set for a machine `instantiate` lent from the pool; it returns there.
    #[cfg(feature = "std")]
    pooled: Option<crate::pool::PoolTicket>,
    /// Set when the execution backend failed on this machine. Its host
    /// state is no longer trusted, so it never returns to the pool.
    backend_failed: bool,
}

impl InnerMachine {
    fn vm(&mut self) -> Result<&mut Interpreter, InnerError> {
        if self.vm.is_none() {
            let mut memory = self
                .execution
                .allocate_memory(
                    1u64 << 32,
                    self.execution.backend() != PvmBackend::ForceRecompiler,
                )
                .map_err(|_| InnerError::Backend)?;
            let pages = memory.pages();
            memory.set_page_range(0, pages, PERM_NONE);
            let mut vm = Interpreter::from_predecoded(
                self.execution.interpreter_program().clone(),
                [0; PVM_REGISTER_COUNT],
                memory,
                0,
            );
            vm.set_pc(self.initial_pc);
            self.vm = Some(vm);
        }
        Ok(self.vm.as_mut().expect("initialized above"))
    }

    fn pc(&self) -> u32 {
        self.vm.as_ref().map_or(self.initial_pc, |vm| vm.pc)
    }

    /// Return a lent machine to its pool; drop any other.
    #[cfg(feature = "std")]
    fn release(self, pool: Option<&crate::pool::MachinePool>) {
        if self.backend_failed {
            return;
        }
        if let (Some(pool), Some(ticket), Some(vm)) = (pool, self.pooled, self.vm) {
            pool.release(crate::pool::PooledMachine::from_parts(
                vm,
                self.execution,
                ticket,
            ));
        }
    }
}

/// Per-Refine dictionary of standard inner machines.
pub struct InnerMachines {
    machines: BTreeMap<u32, InnerMachine>,
    next_generation: u64,
    backend: PvmBackend,
    /// The node's pool, which serves `instantiate`.
    #[cfg(feature = "std")]
    pool: Option<Arc<crate::pool::MachinePool>>,
    /// Whether precompiles are computed in place; otherwise they return to
    /// the outer machine as host calls, as on a JAM node.
    precompiles: bool,
}

impl Default for InnerMachines {
    fn default() -> Self {
        Self::with_backend(PvmBackend::ForceInterpreter)
    }
}

impl InnerMachines {
    pub fn new() -> Self {
        Self::default()
    }

    /// Select execution for this invocation's dictionary. Each machine keeps
    /// independent memory, registers and gas; only preparation is immutable.
    pub fn with_backend(backend: PvmBackend) -> Self {
        Self {
            machines: BTreeMap::new(),
            next_generation: 0,
            backend,
            #[cfg(feature = "std")]
            pool: None,
            precompiles: true,
        }
    }

    /// Serve `instantiate` from `pool`, and return its machines there.
    #[cfg(feature = "std")]
    pub fn set_pool(&mut self, pool: Arc<crate::pool::MachinePool>) {
        self.pool = Some(pool);
    }

    /// Return precompile calls to the outer machine instead of computing
    /// them, as a JAM node does.
    pub fn without_precompiles(&mut self) {
        self.precompiles = false;
    }

    /// The pool serving `instantiate`, if any.
    #[cfg(feature = "std")]
    pub fn pool(&self) -> Option<&Arc<crate::pool::MachinePool>> {
        self.pool.as_ref()
    }

    pub fn len(&self) -> usize {
        self.machines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.machines.is_empty()
    }

    /// Generation assigned to the next successfully created machine.
    ///
    /// Proof-side Refine context commitments bind this counter even when the
    /// live dictionary is empty, so expunge/recreate histories cannot alias.
    pub fn next_generation(&self) -> u64 {
        self.next_generation
    }

    pub fn contains(&self, id: u32) -> bool {
        self.machines.contains_key(&id)
    }

    /// Iterate the dictionary in slot order without initializing dormant
    /// machines or mutating execution state.
    pub fn views(&self) -> impl Iterator<Item = InnerMachineView<'_>> {
        self.machines
            .iter()
            .map(|(&slot, machine)| InnerMachineView {
                identity: InnerMachineIdentity {
                    slot,
                    generation: machine.generation,
                },
                program: &machine.program_blob[..],
                initial_pc: machine.initial_pc,
                machine: machine.vm.as_ref(),
            })
    }

    /// Create a machine from one canonical compact code blob.
    ///
    /// The lowest unused natural-number index is returned.
    pub fn create(&mut self, program_blob: &[u8], initial_pc: u32) -> Result<u32, InnerError> {
        if self.machines.len() >= MAX_INNER_MACHINES {
            return Err(InnerError::Full);
        }
        // Ω_M maps a failed deblob to HUH; unlike full Ψ it does not create
        // a machine which immediately panics.
        let program = deblob(program_blob, u64::from(initial_pc)).ok_or(InnerError::Invalid)?;
        let execution = prepare_inner_program(program_blob, &program, self.backend)?;
        let id = (0..MAX_INNER_MACHINES as u32)
            .find(|id| !self.machines.contains_key(id))
            .expect("a free ID exists below the machine limit");
        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .expect("an invocation cannot create 2^64 inner machines");
        self.machines.insert(
            id,
            InnerMachine {
                generation,
                program_blob: program_blob.into(),
                execution,
                initial_pc,
                vm: None,
                #[cfg(feature = "std")]
                pooled: None,
                backend_failed: false,
            },
        );
        Ok(id)
    }

    /// Lend a machine of an installed `program` from the pool, laid out as
    /// the standard layout with no arguments. The lowest unused index is
    /// returned, as for [`Self::create`].
    #[cfg(feature = "std")]
    pub fn instantiate(
        &mut self,
        program: &Arc<crate::pool::PoolProgram>,
    ) -> Result<u32, InnerError> {
        if self.machines.len() >= MAX_INNER_MACHINES {
            return Err(InnerError::Full);
        }
        let pool = self.pool.as_ref().ok_or(InnerError::Unknown)?;
        let (vm, execution, ticket) = pool
            .acquire(program, self.backend)
            .map_err(|_| InnerError::Backend)?
            .into_parts();
        let id = (0..MAX_INNER_MACHINES as u32)
            .find(|id| !self.machines.contains_key(id))
            .expect("a free ID exists below the machine limit");
        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .expect("an invocation cannot create 2^64 inner machines");
        self.machines.insert(
            id,
            InnerMachine {
                generation,
                program_blob: Arc::clone(program.code_blob()),
                execution,
                initial_pc: 0,
                vm: Some(vm),
                pooled: Some(ticket),
                backend_failed: false,
            },
        );
        Ok(id)
    }

    /// Copy readable bytes out of an inner machine.
    pub fn peek(&mut self, id: u32, source: u32, len: usize) -> Result<Vec<u8>, InnerError> {
        let machine = self.machines.get_mut(&id).ok_or(InnerError::Unknown)?;
        let mut out = vec![0u8; len];
        if !machine.vm()?.memory().read_bytes_checked(source, &mut out) {
            return Err(InnerError::OutOfBounds);
        }
        Ok(out)
    }

    /// Copy bytes into writable inner-machine memory.
    pub fn poke(&mut self, id: u32, destination: u32, data: &[u8]) -> Result<(), InnerError> {
        let machine = self.machines.get_mut(&id).ok_or(InnerError::Unknown)?;
        if !machine
            .vm()?
            .memory_mut()
            .write_bytes_checked(destination, data)
        {
            return Err(InnerError::OutOfBounds);
        }
        Ok(())
    }

    /// Allocate, free, or change access on complete inner-memory pages.
    pub fn pages(
        &mut self,
        id: u32,
        first: u32,
        count: u32,
        mode: PageMode,
    ) -> Result<(), InnerError> {
        let machine = self.machines.get_mut(&id).ok_or(InnerError::Unknown)?;
        let end = first.checked_add(count).ok_or(InnerError::Invalid)?;
        if first < INNER_FIRST_MAPPABLE_PAGE || end as usize >= INNER_ADDRESS_PAGES {
            return Err(InnerError::Invalid);
        }

        let vm = machine.vm()?;
        let memory = vm.memory_mut();
        let first = first as usize;
        let count = count as usize;
        if matches!(mode, PageMode::SetReadOnly | PageMode::SetReadWrite)
            && !memory.pages_mapped(first, count)
        {
            return Err(InnerError::Invalid);
        }

        let permission = match mode {
            PageMode::Free => PERM_NONE,
            PageMode::AllocateReadOnly | PageMode::SetReadOnly => PERM_RO,
            PageMode::AllocateReadWrite | PageMode::SetReadWrite => PERM_RW,
        };
        if matches!(
            mode,
            PageMode::Free | PageMode::AllocateReadOnly | PageMode::AllocateReadWrite
        ) {
            // A native mapping's host zeroing operation can fail even though
            // this guest range is valid. Keep it distinct from guest HUH and
            // never continue execution with uncleared bytes.
            if !memory.clear_pages(first, count) {
                machine.backend_failed = true;
                return Err(InnerError::Backend);
            }
        }
        assert!(memory.set_page_range(first, count, permission));
        Ok(())
    }

    /// Resume a machine with the supplied gas counter and register file.
    pub fn invoke(&mut self, id: u32, state: InvokeState) -> Result<InvokeOutcome, InnerError> {
        self.invoke_with_observer(id, state, None)
    }

    /// Resume a machine while exposing immutable entry, instruction, and
    /// exit observations. This follows [`Self::invoke`] exactly while keeping
    /// the observed path explicitly on the reference interpreter. Ordinary
    /// invocation uses the selected backend without per-instruction callbacks.
    /// A dictionary selected for native execution still retains native memory;
    /// proof/snapshot callers should construct it with `ForceInterpreter`,
    /// which uses sparse inner memory.
    pub fn invoke_observed(
        &mut self,
        id: u32,
        state: InvokeState,
        mut observer: impl for<'a> FnMut(InnerMachineObservation<'a>),
    ) -> Result<InvokeOutcome, InnerError> {
        self.invoke_with_observer(id, state, Some(&mut observer))
    }

    fn invoke_with_observer(
        &mut self,
        id: u32,
        state: InvokeState,
        observer: Option<&mut dyn for<'a> FnMut(InnerMachineObservation<'a>)>,
    ) -> Result<InvokeOutcome, InnerError> {
        let precompiles = self.precompiles;
        let machine = self.machines.get_mut(&id).ok_or(InnerError::Unknown)?;
        let identity = InnerMachineIdentity {
            slot: id,
            generation: machine.generation,
        };
        // Clone immutable preparation, never invocation state. The compiled
        // program remains shared while the mutable architectural state is lent.
        let execution = machine.execution.clone();
        let vm = machine.vm()?;
        vm.gas = state.gas;
        vm.registers = state.registers;
        let mut observer = observer;
        let mut backend_failed = false;
        // Precompiles are served in place and execution continues; every
        // other exit returns to the outer machine.
        let exit = match observer.as_deref_mut() {
            Some(observer) => {
                observer(InnerMachineObservation::Enter {
                    identity,
                    machine: vm,
                });
                loop {
                    let exit = vm
                        .run_observed(|instruction| {
                            observer(InnerMachineObservation::Instruction {
                                identity,
                                instruction,
                            });
                        })
                        .0;
                    match exit {
                        ExitReason::HostCall(call)
                            if precompiles && crate::precompile::is_precompile(call) =>
                        {
                            if !crate::precompile::charge(call, &mut vm.gas) {
                                break ExitReason::OutOfGas;
                            }
                            let registers = vm.registers;
                            let Some(served) =
                                crate::precompile::execute(call, &registers, vm.memory_mut())
                            else {
                                break ExitReason::Panic;
                            };
                            observer(InnerMachineObservation::Precompile {
                                identity,
                                call: &served,
                            });
                            assert!(vm.resume_after_host_call());
                        }
                        other => break other,
                    }
                }
            }
            None => loop {
                let exit = match execution.run(vm) {
                    Ok(exit) => exit,
                    Err(_) => {
                        backend_failed = true;
                        break ExitReason::Panic;
                    }
                };
                match exit {
                    ExitReason::HostCall(call)
                        if precompiles && crate::precompile::is_precompile(call) =>
                    {
                        if !crate::precompile::charge(call, &mut vm.gas) {
                            break ExitReason::OutOfGas;
                        }
                        let registers = vm.registers;
                        if crate::precompile::execute(call, &registers, vm.memory_mut()).is_none() {
                            break ExitReason::Panic;
                        }
                        assert!(vm.resume_after_host_call());
                    }
                    other => break other,
                }
            },
        };
        if backend_failed {
            machine.backend_failed = true;
            return Err(InnerError::Backend);
        }
        let exit = match exit {
            ExitReason::Halt => {
                vm.pc = 0;
                InnerExit::Halt
            }
            ExitReason::Panic => {
                vm.pc = 0;
                InnerExit::Panic
            }
            ExitReason::OutOfGas => InnerExit::OutOfGas,
            ExitReason::PageFault(address) => InnerExit::Fault(address),
            ExitReason::HostCall(id) => {
                // Ω_K returns the host exit but persists the successor PC in
                // the inner machine immediately. Fault/OOG remain on cause.
                assert!(vm.resume_after_host_call());
                InnerExit::Host(id)
            }
        };
        if let Some(observer) = observer {
            observer(InnerMachineObservation::Exit {
                identity,
                exit,
                machine: vm,
            });
        }
        Ok(InvokeOutcome {
            exit,
            state: InvokeState {
                gas: vm.gas,
                registers: vm.registers,
            },
        })
    }

    /// Mark a machine as if its backend had failed.
    #[cfg(test)]
    pub(crate) fn fail_backend_for_test(&mut self, id: u32) {
        self.machines.get_mut(&id).unwrap().backend_failed = true;
    }

    /// Remove a machine and return its current instruction counter. A
    /// machine lent from the pool returns there.
    pub fn expunge(&mut self, id: u32) -> Result<u32, InnerError> {
        let machine = self.machines.remove(&id).ok_or(InnerError::Unknown)?;
        let pc = machine.pc();
        #[cfg(feature = "std")]
        machine.release(self.pool.as_deref());
        Ok(pc)
    }
}

/// Machines still lent from the pool when the invocation ends return there.
#[cfg(feature = "std")]
impl Drop for InnerMachines {
    fn drop(&mut self) {
        let pool = self.pool.take();
        for (_, machine) in core::mem::take(&mut self.machines) {
            machine.release(pool.as_deref());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PVM_HALT_ADDR;

    fn compact_blob(code: &[u8], starts: &[usize]) -> Vec<u8> {
        let mut packed = vec![0u8; code.len().div_ceil(8)];
        for &i in starts {
            packed[i / 8] |= 1 << (i % 8);
        }
        let mut blob = vec![0, 1, code.len() as u8];
        blob.extend_from_slice(code);
        blob.extend_from_slice(&packed);
        blob
    }

    fn host_then_trap() -> Vec<u8> {
        compact_blob(&[10, 42, 0], &[0, 2])
    }

    #[cfg(feature = "std")]
    #[test]
    fn preparation_cache_is_exact_process_wide_and_revalidates_each_entry() {
        let blob = host_then_trap();
        let mut machines = InnerMachines::new();
        let first = machines.create(&blob, 0).unwrap();
        let first = machines.machines[&first].execution.clone();
        let second = machines.create(&blob, 2).unwrap();
        assert!(
            core::ptr::eq(
                first.interpreter_program(),
                machines.machines[&second].execution.interpreter_program()
            ),
            "valid different entry points share only immutable preparation"
        );
        assert_eq!(
            machines.create(&blob, 1),
            Err(InnerError::Invalid),
            "a cache hit must not bypass entry-point validation"
        );
        let different_blob = compact_blob(&[10, 43, 0], &[0, 2]);
        let different = machines.create(&different_blob, 0).unwrap();
        assert!(!core::ptr::eq(
            first.interpreter_program(),
            machines.machines[&different]
                .execution
                .interpreter_program()
        ));
        let worker = std::thread::spawn(move || {
            let mut machines = InnerMachines::new();
            let id = machines.create(&blob, 0).unwrap();
            machines.machines[&id].execution.clone()
        })
        .join()
        .unwrap();
        assert!(
            core::ptr::eq(worker.interpreter_program(), first.interpreter_program()),
            "every worker shares one preparation per program"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn preparation_cache_cap_and_default_bypass_do_not_change_admission() {
        let blob = host_then_trap();
        let mut machines = InnerMachines::new();
        let warm = machines.create(&blob, 0).unwrap();
        let warm = machines.machines[&warm].execution.clone();
        // A canonical program larger than the cache ceiling still creates
        // and executes. Sparse instruction starts keep this fixture modest.
        let code = vec![0; crate::pool::PREPARED_ADMISSION_BYTES];
        let mut bitmask = vec![0; code.len()];
        for start in (0..code.len()).step_by(25) {
            bitmask[start] = 1;
        }
        let oversized = vos_pvm_program::build_compact_code_blob(&vos_pvm_program::CodeBlob {
            code,
            bitmask,
            jump_table: Vec::new(),
        })
        .unwrap();
        assert!(oversized.len() > crate::pool::PREPARED_ADMISSION_BYTES);
        let large = machines.create(&oversized, 0).unwrap();
        assert_eq!(
            machines
                .invoke(
                    large,
                    InvokeState {
                        gas: 1_000_000,
                        registers: [0; PVM_REGISTER_COUNT],
                    }
                )
                .unwrap()
                .exit,
            InnerExit::Panic
        );
        // The default selection is resolved once and shares the resolved
        // backend's entry.
        let mut default = InnerMachines::with_backend(PvmBackend::Default);
        let id = default.create(&blob, 0).unwrap();
        let resolved = crate::backend::resolve(PvmBackend::Default).unwrap();
        let mut explicit = InnerMachines::with_backend(resolved);
        let explicit_id = explicit.create(&blob, 0).unwrap();
        assert!(core::ptr::eq(
            explicit.machines[&explicit_id]
                .execution
                .interpreter_program(),
            default.machines[&id].execution.interpreter_program()
        ));
        let again = machines.create(&blob, 0).unwrap();
        assert!(
            core::ptr::eq(
                machines.machines[&again].execution.interpreter_program(),
                warm.interpreter_program()
            ),
            "bypassed programs must not evict the admitted entry"
        );
    }

    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn preparation_cache_binds_backend_and_never_retains_invocation_state() {
        let blob = compact_blob(&[130, 2 + 16 * 3, 10, 42, 0], &[0, 2, 4]);
        let mut reference = InnerMachines::new();
        let reference_id = reference.create(&blob, 0).unwrap();
        let reference_prepared = reference.machines[&reference_id].execution.clone();
        let mut prior_prepared = None;
        for value in [37u8, 71] {
            let mut machines = InnerMachines::with_backend(PvmBackend::ForceRecompiler);
            let id = machines.create(&blob, 0).unwrap();
            let prepared = machines.machines[&id].execution.clone();
            assert_eq!(prepared.backend(), PvmBackend::ForceRecompiler);
            assert!(!core::ptr::eq(
                reference_prepared.interpreter_program(),
                prepared.interpreter_program()
            ));
            if let Some(prior) = &prior_prepared {
                let prior: &PreparedExecution = prior;
                assert!(core::ptr::eq(
                    prior.interpreter_program(),
                    prepared.interpreter_program()
                ));
            }
            prior_prepared = Some(prepared);
            let address = INNER_FIRST_MAPPABLE_PAGE * PVM_PAGE_SIZE;
            let mut registers = [0; PVM_REGISTER_COUNT];
            registers[3] = u64::from(address);
            let fault = machines
                .invoke(
                    id,
                    InvokeState {
                        gas: 100_000,
                        registers,
                    },
                )
                .unwrap();
            assert_eq!(
                fault.exit,
                InnerExit::Fault(address),
                "fresh memory has no cached mappings"
            );
            machines
                .pages(
                    id,
                    INNER_FIRST_MAPPABLE_PAGE,
                    1,
                    PageMode::AllocateReadWrite,
                )
                .unwrap();
            assert_eq!(
                machines.peek(id, address, 8).unwrap(),
                [0; 8],
                "no prior bytes survive"
            );
            machines.poke(id, address, &[value]).unwrap();
            let host = machines.invoke(id, fault.state).unwrap();
            assert_eq!(host.exit, InnerExit::Host(42));
            assert_eq!(host.state.registers[2], u64::from(value));
            let gas = host.state.gas;
            let terminal = machines.invoke(id, host.state).unwrap();
            assert_eq!(terminal.exit, InnerExit::Panic);
            assert_eq!(
                terminal.state.gas, gas,
                "cached preparation does not change funded host resume"
            );
            assert_eq!(machines.expunge(id), Ok(0));
        }
    }

    #[test]
    fn enforces_sixty_three_machine_limit_and_reuses_lowest_id() {
        let blob = host_then_trap();
        let mut machines = InnerMachines::new();
        for expected in 0..MAX_INNER_MACHINES as u32 {
            assert_eq!(machines.create(&blob, 0), Ok(expected));
        }
        assert_eq!(machines.create(&blob, 0), Err(InnerError::Full));
        assert_eq!(machines.expunge(7), Ok(0));
        assert_eq!(machines.create(&blob, 0), Ok(7));
    }

    #[test]
    fn rejects_malformed_programs_and_invalid_entry_points() {
        let blob = host_then_trap();
        let mut machines = InnerMachines::new();
        assert_eq!(machines.create(&[0xff], 0), Err(InnerError::Invalid));
        assert_eq!(machines.create(&blob, 1), Err(InnerError::Invalid));
        let mut trailing = blob.clone();
        trailing.push(0);
        assert_eq!(machines.create(&trailing, 0), Err(InnerError::Invalid));
    }

    #[test]
    fn pages_poke_and_peek_obey_access_modes_and_zero_allocation() {
        let mut machines = InnerMachines::new();
        let id = machines.create(&host_then_trap(), 0).unwrap();
        let page = INNER_FIRST_MAPPABLE_PAGE;
        let address = page * PVM_PAGE_SIZE + 11;

        assert_eq!(
            machines.poke(id, address, b"hello"),
            Err(InnerError::OutOfBounds)
        );
        machines
            .pages(id, page, 1, PageMode::AllocateReadWrite)
            .unwrap();
        machines.poke(id, address, b"hello").unwrap();
        assert_eq!(machines.peek(id, address, 5).unwrap(), b"hello");
        machines.pages(id, page, 1, PageMode::SetReadOnly).unwrap();
        assert_eq!(
            machines.poke(id, address, b"world"),
            Err(InnerError::OutOfBounds)
        );
        assert_eq!(machines.peek(id, address, 5).unwrap(), b"hello");

        machines
            .pages(id, page, 1, PageMode::AllocateReadWrite)
            .unwrap();
        assert_eq!(machines.peek(id, address, 5).unwrap(), [0; 5]);
        machines.pages(id, page, 1, PageMode::Free).unwrap();
        assert_eq!(machines.peek(id, address, 1), Err(InnerError::OutOfBounds));
        assert_eq!(
            machines.pages(id, 15, 1, PageMode::AllocateReadWrite),
            Err(InnerError::Invalid)
        );
    }

    #[test]
    fn invoke_resumes_after_host_call_then_panics_on_trap() {
        let mut machines = InnerMachines::new();
        let id = machines.create(&host_then_trap(), 0).unwrap();
        let state = InvokeState {
            gas: 100_000,
            registers: [0; PVM_REGISTER_COUNT],
        };
        let first = machines.invoke(id, state).unwrap();
        assert_eq!(first.exit, InnerExit::Host(42));
        assert!(first.state.gas < 100_000);
        assert_eq!(machines.expunge(id), Ok(2));

        let id = machines.create(&host_then_trap(), 0).unwrap();
        let first = machines
            .invoke(
                id,
                InvokeState {
                    gas: 100_000,
                    registers: [0; PVM_REGISTER_COUNT],
                },
            )
            .unwrap();
        let second = machines.invoke(id, first.state).unwrap();
        assert_eq!(second.exit, InnerExit::Panic);
        assert_eq!(machines.expunge(id), Ok(0));
    }

    #[test]
    fn observed_identity_does_not_alias_a_reused_slot() {
        let mut machines = InnerMachines::new();
        let state = InvokeState {
            gas: 100_000,
            registers: [0; PVM_REGISTER_COUNT],
        };
        let first_slot = machines.create(&host_then_trap(), 0).unwrap();
        let mut first_identity = None;
        machines
            .invoke_observed(first_slot, state.clone(), |event| {
                if let InnerMachineObservation::Enter { identity, .. } = event {
                    first_identity = Some(identity);
                }
            })
            .unwrap();
        machines.expunge(first_slot).unwrap();

        let second_slot = machines.create(&host_then_trap(), 0).unwrap();
        let mut second_identity = None;
        machines
            .invoke_observed(second_slot, state, |event| {
                if let InnerMachineObservation::Enter { identity, .. } = event {
                    second_identity = Some(identity);
                }
            })
            .unwrap();

        assert_eq!(first_slot, second_slot);
        assert_eq!(first_identity.unwrap().slot, second_identity.unwrap().slot);
        assert_ne!(first_identity, second_identity);
        assert_eq!(first_identity.unwrap().generation, 0);
        assert_eq!(second_identity.unwrap().generation, 1);
    }

    #[test]
    fn invoke_reports_halt_fault_and_out_of_gas() {
        let mut machines = InnerMachines::new();
        let halt = compact_blob(&[50, 0], &[0]);
        let id = machines.create(&halt, 0).unwrap();
        let mut registers = [0; PVM_REGISTER_COUNT];
        registers[0] = PVM_HALT_ADDR;
        assert_eq!(
            machines
                .invoke(
                    id,
                    InvokeState {
                        gas: 100_000,
                        registers,
                    },
                )
                .unwrap()
                .exit,
            InnerExit::Halt
        );

        let fault = compact_blob(&[130, 2 + 16 * 3, 0], &[0, 2]);
        let id = machines.create(&fault, 0).unwrap();
        let mut registers = [0; PVM_REGISTER_COUNT];
        registers[3] = (INNER_FIRST_MAPPABLE_PAGE * PVM_PAGE_SIZE) as u64;
        assert_eq!(
            machines
                .invoke(
                    id,
                    InvokeState {
                        gas: 100_000,
                        registers,
                    },
                )
                .unwrap()
                .exit,
            InnerExit::Fault(INNER_FIRST_MAPPABLE_PAGE * PVM_PAGE_SIZE)
        );

        let id = machines.create(&host_then_trap(), 0).unwrap();
        assert_eq!(
            machines
                .invoke(
                    id,
                    InvokeState {
                        gas: 0,
                        registers: [0; PVM_REGISTER_COUNT],
                    },
                )
                .unwrap()
                .exit,
            InnerExit::OutOfGas
        );
    }

    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn recompiled_inner_matches_reference_when_reusing_terminal_machines() {
        // A terminal exit resets the inner PC, but does not discard the
        // interpreter's funded gas block. Reusing the same machine must not
        // silently charge it again under a different execution backend.
        let cases = [
            ("host then trap", vec![10, 42, 0], vec![0, 2], 0),
            (
                "host then halt",
                vec![10, 42, 50, 0],
                vec![0, 2],
                crate::PVM_HALT_ADDR,
            ),
            ("trap", vec![0], vec![0], 0),
            ("halt", vec![50, 0], vec![0], crate::PVM_HALT_ADDR),
            ("invalid indirect jump", vec![50, 0], vec![0], 1),
            ("invalid static jump", vec![40, 1], vec![0], 0),
            ("final fallthrough", vec![1], vec![0], 0),
        ];
        for (name, code, starts, return_address) in cases {
            for initial_gas in [0, 1, 100, 1_000] {
                let run = |backend| {
                    let mut machines = InnerMachines::with_backend(backend);
                    let id = machines
                        .create(&compact_blob(&code, &starts), 0)
                        .unwrap_or_else(|error| panic!("{name}, {backend:?}: {error:?}"));
                    let mut registers = [0; PVM_REGISTER_COUNT];
                    registers[0] = return_address;
                    let mut state = InvokeState {
                        gas: initial_gas,
                        registers,
                    };
                    let mut observations = Vec::new();
                    for _ in 0..6 {
                        let outcome = machines.invoke(id, state).unwrap();
                        let vm = machines.machines[&id].vm.as_ref().unwrap();
                        observations.push((outcome.clone(), vm.pc, vm.gas_charged));
                        state = outcome.state;
                    }
                    (observations, machines.expunge(id).unwrap())
                };
                assert_eq!(
                    run(PvmBackend::ForceRecompiler),
                    run(PvmBackend::ForceInterpreter),
                    "{name}, initial gas {initial_gas}"
                );
            }
        }
    }

    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn recompiled_inner_invalid_entry_preserves_existing_funding() {
        for pc in [1, 4, u32::MAX] {
            for funded in [false, true] {
                for gas in [0, 1_000] {
                    let run = |backend| {
                        let mut machines = InnerMachines::with_backend(backend);
                        let id = machines.create(&host_then_trap(), 0).unwrap();
                        let vm = machines.machines.get_mut(&id).unwrap().vm().unwrap();
                        vm.pc = pc;
                        vm.restore_boundary_state(funded, None);
                        let mut state = InvokeState {
                            gas,
                            registers: [0; PVM_REGISTER_COUNT],
                        };
                        let mut observations = Vec::new();
                        for step in 0..3 {
                            let outcome = machines.invoke(id, state).unwrap();
                            let vm = machines.machines[&id].vm.as_ref().unwrap();
                            if step == 0 {
                                assert_eq!(outcome.exit, InnerExit::Panic);
                                assert_eq!(outcome.state.gas, gas);
                                assert_eq!(vm.gas_charged, funded);
                            }
                            observations.push((outcome.clone(), vm.pc, vm.gas_charged));
                            state = outcome.state;
                        }
                        observations
                    };
                    assert_eq!(
                        run(PvmBackend::ForceRecompiler),
                        run(PvmBackend::ForceInterpreter),
                        "invalid pc {pc}, funded {funded}, gas {gas}"
                    );
                }
            }
        }
    }

    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn recompiled_inner_matches_reference_across_fault_repair_host_resume_and_page_reuse() {
        fn run(backend: PvmBackend) -> (Vec<InvokeOutcome>, Vec<u32>, Vec<u8>) {
            let mut machines = InnerMachines::with_backend(backend);
            // Load r2 from r3, host(42), trap. Repair a fault without resetting
            // the funded gas block, then suspend/resume through the host call.
            let blob = compact_blob(&[130, 2 + 16 * 3, 10, 42, 0], &[0, 2, 4]);
            let id = machines.create(&blob, 0).unwrap();
            let page = INNER_FIRST_MAPPABLE_PAGE;
            let address = page * PVM_PAGE_SIZE;
            let mut registers = [0; PVM_REGISTER_COUNT];
            registers[3] = u64::from(address);
            let mut outcomes = Vec::new();
            let mut pcs = Vec::new();
            let fault = machines
                .invoke(
                    id,
                    InvokeState {
                        gas: 100_000,
                        registers,
                    },
                )
                .unwrap();
            assert_eq!(fault.exit, InnerExit::Fault(address));
            outcomes.push(fault.clone());
            pcs.push(machines.views().next().unwrap().machine.unwrap().pc);
            machines
                .pages(id, page, 1, PageMode::AllocateReadWrite)
                .unwrap();
            machines.poke(id, address, &[37]).unwrap();
            machines.pages(id, page, 1, PageMode::SetReadOnly).unwrap();
            assert_eq!(
                machines.poke(id, address, &[99]),
                Err(InnerError::OutOfBounds)
            );
            let resumed = machines.invoke(id, fault.state).unwrap();
            assert_eq!(resumed.exit, InnerExit::Host(42));
            assert_eq!(resumed.state.registers[2], 37);
            outcomes.push(resumed.clone());
            pcs.push(machines.views().next().unwrap().machine.unwrap().pc);
            outcomes.push(machines.invoke(id, resumed.state).unwrap());
            pcs.push(machines.expunge(id).unwrap());

            // A reused slot and a fresh machine must not retain the old bytes.
            let reused = machines.create(&blob, 0).unwrap();
            assert_eq!(reused, id);
            machines
                .pages(reused, page, 1, PageMode::AllocateReadWrite)
                .unwrap();
            let bytes = machines.peek(reused, address, 8).unwrap();
            assert_eq!(bytes, [0; 8]);
            machines.poke(reused, address, &[71]).unwrap();
            machines.pages(reused, page, 1, PageMode::Free).unwrap();
            assert_eq!(
                machines.peek(reused, address, 1),
                Err(InnerError::OutOfBounds)
            );
            machines
                .pages(reused, page, 1, PageMode::AllocateReadWrite)
                .unwrap();
            assert_eq!(machines.peek(reused, address, 8).unwrap(), [0; 8]);
            outcomes.push(
                machines
                    .invoke(reused, InvokeState { gas: 0, registers })
                    .unwrap(),
            );
            pcs.push(machines.expunge(reused).unwrap());
            (outcomes, pcs, bytes)
        }
        assert_eq!(
            run(PvmBackend::ForceRecompiler),
            run(PvmBackend::ForceInterpreter)
        );
    }

    #[test]
    fn pins_host_call_ids_and_gas_schedule() {
        assert_eq!(
            [
                host_call::MACHINE,
                host_call::PEEK,
                host_call::POKE,
                host_call::PAGES,
                host_call::INVOKE,
                host_call::EXPUNGE,
            ],
            [9, 10, 11, 12, 13, 14]
        );
        assert_eq!(
            [
                gp_call::GAS,
                gp_call::FETCH,
                gp_call::LOOKUP,
                gp_call::READ,
                gp_call::WRITE,
                gp_call::INFO,
                gp_call::HISTORICAL_LOOKUP,
                gp_call::EXPORT,
                gp_call::LOG,
            ],
            [0, 2, 3, 4, 5, 6, 7, 8, 100]
        );
        assert_eq!(
            [
                host_call::INSTANTIATE,
                host_call::STATE_READ,
                host_call::STATE_SCAN
            ],
            [0x480, 0x481, 0x482],
            "VOS extensions sit in the node block, past the precompiles"
        );
        assert_eq!(gas::memory(112, 0), 0);
        assert_eq!(gas::memory(112, 1), 1);
        assert_eq!(gas::memory(112, 1024), 112);
        assert_eq!(gas::memory(112, 1025), 113);
    }
}
