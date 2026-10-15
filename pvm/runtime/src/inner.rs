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
    /// installed standard program whose code hash φ7 points at, at the
    /// instruction counter φ8. On a host without it (JAM), the call answers
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
/// confirmed on PolkaJam 0.1.29; the rest follow the same numbering, which
/// places `machine` at 9.
pub mod gp_call {
    pub const GAS: u32 = 0;
    pub const FETCH: u32 = 2;
    pub const LOOKUP: u32 = 3;
    pub const READ: u32 = 4;
    pub const WRITE: u32 = 5;
    pub const INFO: u32 = 6;
    pub const HISTORICAL_LOOKUP: u32 = 7;
    pub const EXPORT: u32 = 8;
    /// Accumulate's: ask for a preimage of the service's.
    pub const SOLICIT: u32 = 24;
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
                self.execution.interpreter_program(),
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
        }
    }

    /// Serve `instantiate` from `pool`, and return its machines there.
    #[cfg(feature = "std")]
    pub fn set_pool(&mut self, pool: Arc<crate::pool::MachinePool>) {
        self.pool = Some(pool);
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
    /// the standard layout with no arguments, at instruction counter
    /// `initial_pc`, which must start an instruction as [`Self::create`]'s
    /// does. Entered mid-block, the machine is charged the whole block, as
    /// one created there is. The lowest unused index is returned, as for
    /// [`Self::create`].
    #[cfg(feature = "std")]
    pub fn instantiate(
        &mut self,
        program: &Arc<crate::pool::PoolProgram>,
        initial_pc: u32,
    ) -> Result<u32, InnerError> {
        if self.machines.len() >= MAX_INNER_MACHINES {
            return Err(InnerError::Full);
        }
        let pool = self.pool.as_ref().ok_or(InnerError::Unknown)?;
        if !program.enters_at(initial_pc) {
            return Err(InnerError::Invalid);
        }
        let (mut vm, execution, ticket) = pool
            .acquire(program, self.backend)
            .map_err(|_| InnerError::Backend)?
            .into_parts();
        vm.set_pc(initial_pc);
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
                initial_pc,
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
        mut observer: Option<&mut dyn for<'a> FnMut(InnerMachineObservation<'a>)>,
    ) -> Result<InvokeOutcome, InnerError> {
        let machine = self.machines.get_mut(&id).ok_or(InnerError::Unknown)?;
        let identity = InnerMachineIdentity {
            slot: id,
            generation: machine.generation,
        };
        // Lay the machine out on first use, then borrow its preparation and
        // its state apart: cloning the preparation would cost two atomic
        // reference counts per exit.
        machine.vm()?;
        let InnerMachine {
            execution,
            vm,
            backend_failed: failed,
            ..
        } = machine;
        let vm = vm.as_mut().expect("laid out above");
        vm.gas = state.gas;
        vm.registers = state.registers;
        // Every exit returns to the outer machine, a precompile call's too:
        // the agent serves an inner machine's precompiles, on every host.
        let exit = match observer.as_deref_mut() {
            Some(observer) => {
                observer(InnerMachineObservation::Enter {
                    identity,
                    machine: vm,
                });
                vm.run_observed(|instruction| {
                    observer(InnerMachineObservation::Instruction {
                        identity,
                        instruction,
                    });
                })
                .0
            }
            None => match execution.run(vm) {
                Ok(exit) => exit,
                Err(_) => {
                    *failed = true;
                    return Err(InnerError::Backend);
                }
            },
        };
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
mod tests;
