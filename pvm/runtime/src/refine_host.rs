//! Standard inner-machine host-call dispatcher for Refine programs.

mod jam;
mod lookup;

pub use jam::{JamItem, JamRefine, JamRun, MAX_EXPORTS, Preimages, SEGMENT, jam_gas};
pub use lookup::{LOOKUP_GAS, serve_lookup};

use alloc::vec::Vec;

use crate::inner::{
    InnerError, InnerExit, InnerMachineIdentity, InnerMachineObservation, InnerMachines,
    InvokeState, MAX_INNER_MACHINES, PageMode, gas, gp_call, host_call,
};
use crate::refine::{Invocation, Machine, MachineObservation, MemoryModel, RefineError};
use crate::{ExitReason, Gas, PVM_REGISTER_COUNT, PvmBackend};

/// Standard host result constants used by the inner-machine calls.
pub mod result {
    pub const OK: u64 = 0;
    pub const NONE: u64 = u64::MAX;
    pub const WHAT: u64 = u64::MAX - 1;
    pub const OOB: u64 = u64::MAX - 2;
    pub const WHO: u64 = u64::MAX - 3;
    pub const FULL: u64 = u64::MAX - 4;
    pub const HUH: u64 = u64::MAX - 8;
}

/// Why a host call stops the outer machine.
enum Stop {
    /// The run ends with this exit; a host call the context does not serve
    /// reaches the embedder.
    Exit(ExitReason),
    /// The execution backend failed: a host error, never a guest outcome.
    Backend,
}

/// A host call stopping the machine on a panic.
const PANIC: Stop = Stop::Exit(ExitReason::Panic);

/// Stable identity of a machine participating in one nested Refine run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RefineMachineIdentity {
    Outer,
    Inner(InnerMachineIdentity),
}

/// Phase of an outer-runtime host-call dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefineHostPhase {
    Before,
    After,
}

/// Read-only nested execution events used by proof and diagnostic tracers.
///
/// `MachineEnter` exposes the exact code and sparse memory image before the
/// first instruction of that slice. `Instruction` is emitted by the sole
/// interpreter execution path. Host boundaries surround all state changes
/// made by calls 9 through 14, including an intervening inner invocation.
pub enum RefineObservation<'a> {
    MachineEnter {
        identity: RefineMachineIdentity,
        machine: &'a crate::interpreter::Interpreter,
    },
    Instruction {
        identity: RefineMachineIdentity,
        instruction: crate::interpreter::InstructionObservation<'a>,
    },
    MachineExit {
        identity: RefineMachineIdentity,
        exit: ExitReason,
        machine: &'a crate::interpreter::Interpreter,
    },
    /// An outer precompile served in place inside the current slice. An
    /// inner machine's precompile call exits to the outer machine instead.
    Precompile {
        identity: RefineMachineIdentity,
        call: &'a crate::precompile::PrecompileCall,
    },
    HostCall {
        phase: RefineHostPhase,
        id: u64,
        outer: &'a Machine,
        inner: &'a InnerMachines,
    },
}

/// What observes an observed run.
type Observer<'o> = &'o mut dyn for<'a> FnMut(RefineObservation<'a>);

/// The agent's applied state, as the node reads it for `state_read`.
pub trait StateReader: Send + Sync {
    fn read(&self, key: &[u8]) -> Option<Vec<u8>>;

    /// Rows whose key starts with `prefix`, in key order, after `after`
    /// when given.
    fn rows<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a [u8]>,
    ) -> alloc::boxed::Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + 'a>;
}

/// Applied state held in memory, by key.
impl StateReader for alloc::collections::BTreeMap<Vec<u8>, Vec<u8>> {
    fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get(key).cloned()
    }

    fn rows<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a [u8]>,
    ) -> alloc::boxed::Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + 'a> {
        alloc::boxed::Box::new(
            self.range(prefix.to_vec()..)
                .take_while(move |(key, _)| key.starts_with(prefix))
                .filter(move |(key, _)| after.is_none_or(|after| key.as_slice() > after))
                .map(|(key, value)| (key.clone(), value.clone())),
        )
    }
}

/// The programs the running agent may load, and where `instantiate` finds
/// one its node's pool lacks.
///
/// The pool is the node's, shared by its agents: a program the agent may
/// not load answers `WHO` though pooled, as a missing one does. A program
/// the source gives is installed in the pool and lent as an installed one
/// is, at the same price, so a run's gas does not depend on what the pool
/// held. A store it cannot read is its own to fault on.
#[cfg(feature = "std")]
pub trait ProgramSource: Send + Sync {
    /// Whether the agent may load the program with this code hash.
    fn owns(&self, hash: &crate::pool::CodeHash) -> bool;
    /// The program with this code hash, if the agent may load it.
    fn program(&self, hash: &crate::pool::CodeHash) -> Option<Vec<u8>>;
}

/// Gas for a host call the Gray Paper prices at its base cost.
const BASE_CALL_GAS: Gas = 10;
/// `state_read`'s price per byte copied, on top of the base price.
pub(crate) const STATE_READ_BYTE_GAS: Gas = 1;

/// Which host serves a refine.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Host {
    /// A VOS node, computing the outer machine's precompiles in place when
    /// `precompiles` is set.
    Node { precompiles: bool },
    /// The JAM-only host ([`RefineContext::try_run_jam`]), at PolkaJam's
    /// prices: it computes no precompile.
    Jam,
}

/// A standard outer PVM plus its per-invocation inner-machine dictionary.
pub struct RefineContext {
    outer: Machine,
    inner: InnerMachines,
    state: Option<alloc::sync::Arc<dyn StateReader>>,
    host: Host,
    /// Where `instantiate` finds a program its pool lacks.
    #[cfg(feature = "std")]
    programs: Option<alloc::sync::Arc<dyn ProgramSource>>,
}

impl RefineContext {
    pub fn load(program: &[u8], args: &[u8], gas: Gas) -> Result<Self, RefineError> {
        Self::load_with(program, args, gas, MemoryModel::Auto)
    }

    pub fn load_with(
        program: &[u8],
        args: &[u8],
        gas: Gas,
        model: MemoryModel,
    ) -> Result<Self, RefineError> {
        Ok(Self::new(Machine::load_with(program, args, gas, model)?))
    }

    /// Explicit execution backend for both the outer runtime and its inner
    /// actors. Use [`Self::try_run`] (or [`Self::try_run_with_host`]) so backend
    /// failures remain host errors, never signed guest outcomes or retries on
    /// another backend.
    pub fn load_with_backend(
        program: &[u8],
        args: &[u8],
        gas: Gas,
        model: MemoryModel,
        backend: PvmBackend,
    ) -> Result<Self, RefineError> {
        Ok(Self::new(Machine::load_with_backend(
            program, args, gas, model, backend,
        )?))
    }

    /// Compute no precompile, as a JAM node does: the outer machine's
    /// reach the embedder. An inner machine's return to the outer machine
    /// as host calls on every host, for its agent to serve.
    pub fn without_precompiles(mut self) -> Self {
        self.host = Host::Node { precompiles: false };
        self
    }

    /// Serve `state_read` from the agent's applied state. Without a reader
    /// the call reaches the embedder, as on JAM. Observed runs refuse a
    /// reader, as they refuse a pool: replaying them has no state until
    /// witnesses exist.
    pub fn with_state(mut self, reader: alloc::sync::Arc<dyn StateReader>) -> Self {
        self.state = Some(reader);
        self
    }

    /// Serve `instantiate` from the node's pool. Inner machines it lends
    /// return to the pool when expunged or when this context is dropped.
    /// Observed runs, which proof tracing uses, do not serve it yet: running
    /// one with a pool is refused, and without a pool `instantiate` reaches
    /// the embedder, as an unknown call reaches a JAM host.
    #[cfg(feature = "std")]
    pub fn with_pool(mut self, pool: alloc::sync::Arc<crate::pool::MachinePool>) -> Self {
        self.inner.set_pool(pool);
        self
    }

    /// Load a program the pool lacks from `source` on `instantiate`, as
    /// [`ProgramSource`] says. Needs a pool ([`Self::with_pool`]).
    #[cfg(feature = "std")]
    pub fn with_programs(mut self, source: alloc::sync::Arc<dyn ProgramSource>) -> Self {
        self.programs = Some(source);
        self
    }

    /// Reuse validated program preparation, never per-invocation machines.
    pub fn load_prepared(
        program: &crate::refine::PreparedProgram,
        args: &[u8],
        gas: Gas,
        model: MemoryModel,
    ) -> Result<Self, RefineError> {
        Ok(Self::new(Machine::load_prepared(
            program, args, gas, model,
        )?))
    }

    /// Serve refine on a loaded machine, such as one
    /// [`crate::pool::OuterMachines`] lent; inner machines run on its
    /// backend.
    pub fn new(outer: Machine) -> Self {
        let inner = InnerMachines::with_backend(outer.backend());
        Self {
            outer,
            inner,
            state: None,
            host: Host::Node { precompiles: true },
            #[cfg(feature = "std")]
            programs: None,
        }
    }

    /// Run the outer program, transparently servicing host calls 9 through
    /// 14. Other host calls are returned to the embedder unchanged.
    pub fn run(self) -> Invocation {
        self.run_with_host(|id, _| Err(ExitReason::HostCall(id)))
    }

    /// Execute the selected backend, preserving backend errors separately from
    /// a completed guest invocation. No execution fault triggers a fallback.
    pub fn try_run(self) -> Result<Invocation, RefineError> {
        self.try_run_with_host(|id, _| Err(ExitReason::HostCall(id)))
    }

    /// Service embedder-owned outer calls without restarting this execution or
    /// discarding its inner-machine dictionary. Built-in calls 9 through 14
    /// remain exclusively owned by Refine. Returning Ok advances past exactly
    /// the pending host call; an error stops at that call's counter.
    ///
    /// The embedder must admit the call, validate memory ranges and charge gas
    /// and its own I/O budgets before doing work. This is not a storage ABI or
    /// an authorization grant. The observed/proof runner does not yet support
    /// external handlers and must not silently substitute for this path.
    pub fn run_with_host(
        self,
        host: impl FnMut(u64, &mut Machine) -> Result<(), ExitReason>,
    ) -> Invocation {
        self.try_run_with_host(host)
            .expect("reference Refine execution; selected backends must use try_run_with_host")
    }

    /// Fallible counterpart of [`Self::run_with_host`] for a selected backend.
    pub fn try_run_with_host(
        mut self,
        mut host: impl FnMut(u64, &mut Machine) -> Result<(), ExitReason>,
    ) -> Result<Invocation, RefineError> {
        loop {
            let exit = self.outer.try_resume()?;
            let ExitReason::HostCall(id) = exit else {
                return Ok(self.outer.finish(exit));
            };
            match self.dispatch(id, None) {
                Ok(()) => {}
                Err(Stop::Exit(ExitReason::HostCall(call))) => {
                    if let Err(exit) = host(call, &mut self.outer) {
                        return Ok(self.outer.finish(exit));
                    }
                }
                Err(Stop::Exit(exit)) => return Ok(self.outer.finish(exit)),
                Err(Stop::Backend) => return Err(RefineError::Backend),
            }
        }
    }

    /// Run the same nested Refine state machine as [`Self::run`] while
    /// reporting immutable machine and host-dispatch boundaries.
    ///
    /// This selects reference interpreter instructions, not new memory or
    /// preparation. A context loaded for the recompiler retains native backing
    /// and prepares its inner programs for that backend. Proof/snapshot callers
    /// must explicitly load `ForceInterpreter` with [`MemoryModel::Sparse`] to
    /// keep value-image inspection proportional to touched pages.
    pub fn run_observed(
        self,
        mut observer: impl for<'a> FnMut(RefineObservation<'a>),
    ) -> Invocation {
        self.run_with_observer(&mut observer)
    }

    fn run_with_observer(mut self, observer: Observer<'_>) -> Invocation {
        // A traced run must execute exactly like a live one, and tracing
        // cannot follow a pooled machine or the node's state yet.
        #[cfg(feature = "std")]
        assert!(
            self.inner.pool().is_none(),
            "observed Refine execution does not serve `instantiate` from a pool"
        );
        assert!(
            self.state.is_none(),
            "observed Refine execution does not serve `state_read`"
        );
        loop {
            let mut exit = self.outer.resume_observed(|event| match event {
                MachineObservation::Enter(machine) => {
                    observer(RefineObservation::MachineEnter {
                        identity: RefineMachineIdentity::Outer,
                        machine,
                    });
                }
                MachineObservation::Instruction(instruction) => {
                    observer(RefineObservation::Instruction {
                        identity: RefineMachineIdentity::Outer,
                        instruction,
                    });
                }
            });
            // Precompiles are served in place; the slice continues.
            while let ExitReason::HostCall(id) = exit {
                if !self.computes_precompiles() || !crate::precompile::is_precompile(id) {
                    break;
                }
                if !self.outer.charge(crate::precompile::price(id).unwrap_or(0)) {
                    exit = ExitReason::OutOfGas;
                    break;
                }
                let registers = *self.outer.registers();
                let Some(call) =
                    crate::precompile::execute(id, &registers, self.outer.memory_mut())
                else {
                    exit = ExitReason::Panic;
                    break;
                };
                observer(RefineObservation::Precompile {
                    identity: RefineMachineIdentity::Outer,
                    call: &call,
                });
                exit = self.outer.continue_observed(|instruction| {
                    observer(RefineObservation::Instruction {
                        identity: RefineMachineIdentity::Outer,
                        instruction,
                    });
                });
            }
            observer(RefineObservation::MachineExit {
                identity: RefineMachineIdentity::Outer,
                exit: exit.clone(),
                machine: self.outer.interpreter(),
            });
            let ExitReason::HostCall(id) = exit else {
                return self.outer.finish(exit);
            };
            observer(RefineObservation::HostCall {
                phase: RefineHostPhase::Before,
                id,
                outer: &self.outer,
                inner: &self.inner,
            });
            let dispatch = self.dispatch(id, Some(&mut *observer));
            observer(RefineObservation::HostCall {
                phase: RefineHostPhase::After,
                id,
                outer: &self.outer,
                inner: &self.inner,
            });
            match dispatch {
                Ok(()) => {}
                Err(Stop::Exit(exit)) => return self.outer.finish(exit),
                Err(Stop::Backend) => {
                    panic!("observed Refine execution requires the reference backend")
                }
            }
        }
    }

    pub fn inner(&self) -> &InnerMachines {
        &self.inner
    }

    /// Whether the outer machine's precompiles are computed in place.
    fn computes_precompiles(&self) -> bool {
        self.host == (Host::Node { precompiles: true })
    }

    /// Serve host call `id`, or stop the machine. An observed run serves
    /// its precompiles before dispatching, and has no pool or state, so
    /// only the arms it reaches see `observer`.
    fn dispatch(&mut self, id: u64, observer: Option<Observer<'_>>) -> Result<(), Stop> {
        match u32::try_from(id) {
            _ if self.computes_precompiles() && crate::precompile::is_precompile(id) => {
                self.precompile(id)
            }
            Ok(host_call::MACHINE) => self.machine(),
            Ok(host_call::PEEK) => self.peek(),
            Ok(host_call::POKE) => self.poke(),
            Ok(host_call::PAGES) => self.pages(),
            Ok(host_call::INVOKE) => self.invoke(observer),
            Ok(host_call::EXPUNGE) => self.expunge(),
            #[cfg(feature = "std")]
            Ok(host_call::INSTANTIATE) if self.inner.pool().is_some() => self.instantiate(),
            Ok(host_call::STATE_READ) if self.state.is_some() => self.state_read(),
            Ok(host_call::STATE_SCAN) if self.state.is_some() => self.state_scan(),
            Ok(gp_call::GAS) => self.gas(),
            // PolkaJam does not serve `log`.
            Ok(gp_call::LOG) if self.host != Host::Jam => self.log(),
            _ => Err(Stop::Exit(ExitReason::HostCall(id))),
        }
    }

    fn charge(&mut self, amount: Gas) -> Result<(), Stop> {
        if self.outer.charge(amount) {
            Ok(())
        } else {
            Err(Stop::Exit(ExitReason::OutOfGas))
        }
    }

    /// Answer the call: φ7 becomes `value`.
    fn answer(&mut self, value: u64) -> Result<(), Stop> {
        self.outer.registers_mut()[7] = value;
        Ok(())
    }

    /// The outer machine's `len` bytes at `address`: a panic when any is
    /// unreadable.
    fn read_outer(&self, address: u64, len: u64) -> Result<Vec<u8>, Stop> {
        self.outer.read_range(address, len).ok_or(PANIC)
    }

    /// Where the outer machine's `len` bytes at `address` lie: a panic when
    /// any is not writable.
    fn outer_range(&self, address: u64, len: u64) -> Result<(u32, usize), Stop> {
        self.outer.writable_range(address, len).ok_or(PANIC)
    }

    fn precompile(&mut self, id: u64) -> Result<(), Stop> {
        self.charge(crate::precompile::price(id).unwrap_or(0))?;
        let registers = *self.outer.registers();
        crate::precompile::execute(id, &registers, self.outer.memory_mut())
            .map(|_| ())
            .ok_or(PANIC)
    }

    /// `gas`: φ7 becomes the gas left after this call's own cost.
    fn gas(&mut self) -> Result<(), Stop> {
        self.charge(match self.host {
            Host::Jam => jam_gas::GAS,
            Host::Node { .. } => BASE_CALL_GAS,
        })?;
        let left = self.outer.gas_remaining();
        self.answer(left)
    }

    /// `log` (JIP-1): φ7 level, φ8/φ9 target, φ10/φ11 message. The node
    /// records it; the guest's registers are unchanged.
    fn log(&mut self) -> Result<(), Stop> {
        self.charge(BASE_CALL_GAS)?;
        #[cfg(feature = "std")]
        {
            let registers = *self.outer.registers();
            let text = |address: u64, len: u64| {
                self.read_outer(address, len.min(4096))
                    .map(|bytes| alloc::string::String::from_utf8_lossy(&bytes).into_owned())
                    .unwrap_or_default()
            };
            tracing::debug!(
                level = registers[7],
                target = %text(registers[8], registers[9]),
                message = %text(registers[10], registers[11]),
                "guest log"
            );
        }
        Ok(())
    }

    /// `state_read`: copy part of the value under the key at φ7/φ8 to φ9,
    /// from offset φ10, at most φ11 bytes; φ7 becomes the value's whole
    /// length, or `NONE` when the key has no value. Costs the base price
    /// and [`STATE_READ_BYTE_GAS`] per byte copied, so a refine's gas also
    /// bounds the node's copying.
    fn state_read(&mut self) -> Result<(), Stop> {
        self.charge(BASE_CALL_GAS)?;
        let registers = *self.outer.registers();
        let key = self.read_outer(registers[7], registers[8])?;
        let reader = self.state.as_ref().expect("dispatched only with a reader");
        let Some(value) = reader.read(&key) else {
            return self.answer(result::NONE);
        };
        let window = crate::refine::window(value.len(), registers[10], registers[11]);
        let (address, len) = self.outer_range(registers[9], window.len() as u64)?;
        self.charge(len as u64 * STATE_READ_BYTE_GAS)?;
        if len > 0
            && !self
                .outer
                .memory_mut()
                .write_bytes_checked(address, &value[window])
        {
            return Err(PANIC);
        }
        self.answer(value.len() as u64)
    }

    /// `state_scan`: rows whose key starts with the prefix at φ7/φ8, after
    /// the key at φ9/φ10 (empty: from the prefix), into φ11, at most φ12
    /// bytes, as whole rows of a four-byte little-endian key length, the
    /// key, a four-byte value length and the value; φ7 becomes the bytes
    /// written, 0 when no rows remain, or `FULL` when the next row alone
    /// exceeds φ12. Costs the base price and [`STATE_READ_BYTE_GAS`] per
    /// byte written.
    fn state_scan(&mut self) -> Result<(), Stop> {
        self.charge(BASE_CALL_GAS)?;
        let registers = *self.outer.registers();
        let prefix = self.read_outer(registers[7], registers[8])?;
        let cursor = self.read_outer(registers[9], registers[10])?;
        let capacity = usize::try_from(registers[12]).unwrap_or(usize::MAX);
        let reader = self.state.as_ref().expect("dispatched only with a reader");
        let after = (!cursor.is_empty()).then_some(cursor.as_slice());
        let mut out = Vec::new();
        let mut full = false;
        for (key, value) in reader.rows(&prefix, after) {
            let row = 8 + key.len() + value.len();
            if out.len() + row > capacity {
                full = out.is_empty();
                break;
            }
            out.extend_from_slice(&(key.len() as u32).to_le_bytes());
            out.extend_from_slice(&key);
            out.extend_from_slice(&(value.len() as u32).to_le_bytes());
            out.extend_from_slice(&value);
        }
        let (address, len) = self.outer_range(registers[11], out.len() as u64)?;
        self.charge(len as u64 * STATE_READ_BYTE_GAS)?;
        if len > 0 && !self.outer.memory_mut().write_bytes_checked(address, &out) {
            return Err(PANIC);
        }
        self.answer(if full { result::FULL } else { len as u64 })
    }

    fn machine(&mut self) -> Result<(), Stop> {
        let registers = *self.outer.registers();
        let (address, len, initial_pc) = (registers[7], registers[8], registers[9]);
        self.charge(gas::MACHINE_BASE.saturating_add(gas::memory(gas::MACHINE_PER_KIB, len)))?;
        // Gray Paper v0.8.0 checks the invocation-wide machine limit before
        // inspecting the caller-supplied program range. At capacity even an
        // unreadable outer pointer therefore returns FULL, rather than
        // panicking while trying to read a program that cannot be installed.
        if self.inner.len() >= MAX_INNER_MACHINES {
            return self.answer(result::FULL);
        }
        let program = self.read_outer(address, len)?;
        let result = match u32::try_from(initial_pc) {
            Ok(pc) => match self.inner.create(&program, pc) {
                Ok(id) => id as u64,
                Err(InnerError::Full) => result::FULL,
                Err(InnerError::Backend) => return Err(Stop::Backend),
                Err(_) => result::HUH,
            },
            Err(_) => result::HUH,
        };
        self.answer(result)
    }

    /// `instantiate`: φ7 points at a 32-byte code hash, and φ8 is the
    /// instruction counter the machine starts at. φ7 becomes the new
    /// machine's index, `WHO` for a program the pool does not hold, `HUH`
    /// for a counter that starts no instruction of it, or `FULL` at the
    /// machine limit. The call costs `machine`'s base, as a failed `machine`
    /// does; an installed program then costs the rest of its price, what
    /// laying it out costs a loader in host calls (never less than the
    /// base), whatever the counter.
    #[cfg(feature = "std")]
    fn instantiate(&mut self) -> Result<(), Stop> {
        self.charge(gas::MACHINE_BASE)?;
        if self.inner.len() >= MAX_INNER_MACHINES {
            return self.answer(result::FULL);
        }
        let registers = *self.outer.registers();
        let (address, initial_pc) = (registers[7], registers[8]);
        let hash = self.read_outer(address, 32)?;
        let hash = crate::pool::CodeHash(hash.try_into().expect("32 bytes read"));
        let owned = self
            .programs
            .as_ref()
            .is_none_or(|source| source.owns(&hash));
        let program = self.inner.pool().filter(|_| owned).and_then(|pool| {
            pool.program(&hash).or_else(|| {
                // Only bytes of the very program asked for, and only a valid
                // one: anything else answers `WHO`, as a missing one does.
                let bytes = self.programs.as_ref()?.program(&hash)?;
                if crate::pool::CodeHash::of(&bytes) != hash {
                    return None;
                }
                pool.install(&bytes).ok()?;
                pool.program(&hash)
            })
        });
        let Some(program) = program else {
            return self.answer(result::WHO);
        };
        self.charge(program.price() - gas::MACHINE_BASE)?;
        let result = match u32::try_from(initial_pc)
            .map_err(|_| InnerError::Invalid)
            .and_then(|pc| self.inner.instantiate(&program, pc))
        {
            Ok(id) => u64::from(id),
            Err(InnerError::Full) => result::FULL,
            Err(InnerError::Backend) => return Err(Stop::Backend),
            Err(_) => result::HUH,
        };
        self.answer(result)
    }

    fn peek(&mut self) -> Result<(), Stop> {
        let registers = *self.outer.registers();
        let (id, outer_address, inner_address, len) =
            (registers[7], registers[8], registers[9], registers[10]);
        self.charge(gas::PEEK_BASE.saturating_add(gas::memory(gas::PEEK_PER_KIB, len)))?;
        let (outer_address, len) = self.outer_range(outer_address, len)?;
        let status = match u32::try_from(id) {
            Ok(id) if self.inner.contains(id) => match (len == 0)
                .then_some(0)
                .or_else(|| u32::try_from(inner_address).ok())
            {
                Some(inner_address) => match self.inner.peek(id, inner_address, len) {
                    Ok(bytes) => {
                        if !self
                            .outer
                            .memory_mut()
                            .write_bytes_checked(outer_address, &bytes)
                        {
                            return Err(PANIC);
                        }
                        result::OK
                    }
                    Err(InnerError::Unknown) => result::WHO,
                    Err(InnerError::OutOfBounds) => result::OOB,
                    Err(InnerError::Backend) => return Err(Stop::Backend),
                    Err(_) => result::HUH,
                },
                None => result::OOB,
            },
            _ => result::WHO,
        };
        self.answer(status)
    }

    fn poke(&mut self) -> Result<(), Stop> {
        let registers = *self.outer.registers();
        let (id, outer_address, inner_address, len) =
            (registers[7], registers[8], registers[9], registers[10]);
        self.charge(gas::POKE_BASE.saturating_add(gas::memory(gas::POKE_PER_KIB, len)))?;
        let bytes = self.read_outer(outer_address, len)?;
        let status = match u32::try_from(id) {
            Ok(id) if self.inner.contains(id) => match bytes
                .is_empty()
                .then_some(0)
                .or_else(|| u32::try_from(inner_address).ok())
            {
                Some(inner_address) => match self.inner.poke(id, inner_address, &bytes) {
                    Ok(()) => result::OK,
                    Err(InnerError::Unknown) => result::WHO,
                    Err(InnerError::OutOfBounds) => result::OOB,
                    Err(InnerError::Backend) => return Err(Stop::Backend),
                    Err(_) => result::HUH,
                },
                None => result::OOB,
            },
            _ => result::WHO,
        };
        self.answer(status)
    }

    fn pages(&mut self) -> Result<(), Stop> {
        let registers = *self.outer.registers();
        let (id, first, count, mode) = (registers[7], registers[8], registers[9], registers[10]);
        self.charge(match mode {
            0 => {
                gas::PAGES_FREE_BASE.saturating_add(count.saturating_mul(gas::PAGES_FREE_PER_PAGE))
            }
            1 | 2 => gas::PAGES_ALLOC_BASE
                .saturating_add(count.saturating_mul(gas::PAGES_ALLOC_PER_PAGE)),
            3 | 4 => gas::PAGES_SET_MODE_BASE
                .saturating_add(count.saturating_mul(gas::PAGES_SET_MODE_PER_PAGE)),
            _ => gas::PAGES_INVALID,
        })?;
        let status = match u32::try_from(id) {
            Ok(id) if self.inner.contains(id) => match (
                u32::try_from(first),
                u32::try_from(count),
                PageMode::try_from(mode),
            ) {
                (Ok(first), Ok(count), Ok(mode)) => {
                    match self.inner.pages(id, first, count, mode) {
                        Ok(()) => result::OK,
                        Err(InnerError::Unknown) => result::WHO,
                        Err(InnerError::Backend) => return Err(Stop::Backend),
                        Err(_) => result::HUH,
                    }
                }
                _ => result::HUH,
            },
            _ => result::WHO,
        };
        self.answer(status)
    }

    fn invoke(&mut self, observer: Option<Observer<'_>>) -> Result<(), Stop> {
        let registers = *self.outer.registers();
        let (id, frame_address) = (registers[7], registers[8]);
        let Ok((frame_address, _)) = self.outer_range(frame_address, 112) else {
            self.charge(gas::INVOKE_BASE)?;
            return Err(PANIC);
        };
        let mut frame = [0u8; 112];
        if !self
            .outer
            .memory()
            .read_bytes_checked(frame_address, &mut frame)
        {
            return Err(PANIC);
        }
        let requested_gas = u64::from_le_bytes(frame[..8].try_into().expect("eight bytes"));
        self.charge(gas::INVOKE_BASE.saturating_add(requested_gas))?;
        let mut inner_registers = [0u64; PVM_REGISTER_COUNT];
        for (i, register) in inner_registers.iter_mut().enumerate() {
            let start = 8 + i * 8;
            *register = u64::from_le_bytes(
                frame[start..start + 8]
                    .try_into()
                    .expect("register frame is complete"),
            );
        }
        let Ok(id) = u32::try_from(id) else {
            return self.answer(result::WHO);
        };
        let state = InvokeState {
            gas: requested_gas,
            registers: inner_registers,
        };
        let outcome = match observer {
            Some(observer) => self.inner.invoke_observed(id, state, |event| match event {
                InnerMachineObservation::Enter { identity, machine } => {
                    observer(RefineObservation::MachineEnter {
                        identity: RefineMachineIdentity::Inner(identity),
                        machine,
                    });
                }
                InnerMachineObservation::Instruction {
                    identity,
                    instruction,
                } => {
                    observer(RefineObservation::Instruction {
                        identity: RefineMachineIdentity::Inner(identity),
                        instruction,
                    });
                }
                InnerMachineObservation::Exit {
                    identity,
                    exit,
                    machine,
                } => {
                    observer(RefineObservation::MachineExit {
                        identity: RefineMachineIdentity::Inner(identity),
                        exit: inner_exit_reason(exit),
                        machine,
                    });
                }
            }),
            None => self.inner.invoke(id, state),
        };
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(InnerError::Unknown) => return self.answer(result::WHO),
            Err(InnerError::Backend) => return Err(Stop::Backend),
            Err(_) => return self.answer(result::HUH),
        };
        self.outer.credit(outcome.state.gas);
        frame[..8].copy_from_slice(&outcome.state.gas.to_le_bytes());
        for (i, register) in outcome.state.registers.iter().enumerate() {
            let start = 8 + i * 8;
            frame[start..start + 8].copy_from_slice(&register.to_le_bytes());
        }
        if !self
            .outer
            .memory_mut()
            .write_bytes_checked(frame_address, &frame)
        {
            return Err(PANIC);
        }
        let (status, detail) = match outcome.exit {
            InnerExit::Halt => (0, None),
            InnerExit::Panic => (1, None),
            InnerExit::Fault(address) => (2, Some(address as u64)),
            InnerExit::Host(id) => (3, Some(id)),
            InnerExit::OutOfGas => (4, None),
        };
        let registers = self.outer.registers_mut();
        registers[7] = status;
        if let Some(detail) = detail {
            registers[8] = detail;
        }
        Ok(())
    }

    fn expunge(&mut self) -> Result<(), Stop> {
        self.charge(gas::EXPUNGE)?;
        let id = self.outer.registers()[7];
        let result = u32::try_from(id)
            .ok()
            .and_then(|id| self.inner.expunge(id).ok())
            .map_or(result::WHO, u64::from);
        self.answer(result)
    }
}

fn inner_exit_reason(exit: InnerExit) -> ExitReason {
    match exit {
        InnerExit::Halt => ExitReason::Halt,
        InnerExit::Panic => ExitReason::Panic,
        InnerExit::Fault(address) => ExitReason::PageFault(address),
        InnerExit::Host(id) => ExitReason::HostCall(id),
        InnerExit::OutOfGas => ExitReason::OutOfGas,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos_pvm_program::{CodeBlob, build_compact_code_blob};

    fn standard_program(args_code: &[u8], starts: &[usize]) -> Vec<u8> {
        standard_program_with_rw(args_code, starts, &[])
    }

    pub(super) fn standard_program_with_rw(
        args_code: &[u8],
        starts: &[usize],
        rw_data: &[u8],
    ) -> Vec<u8> {
        let mut packed = alloc::vec![0u8; args_code.len().div_ceil(8)];
        for &i in starts {
            packed[i / 8] |= 1 << (i % 8);
        }
        let mut code_blob = alloc::vec![0, 1, args_code.len() as u8];
        code_blob.extend_from_slice(args_code);
        code_blob.extend_from_slice(&packed);

        let mut blob = Vec::new();
        blob.extend_from_slice(&[0; 3]);
        blob.extend_from_slice(&(rw_data.len() as u32).to_le_bytes()[..3]);
        blob.extend_from_slice(&0u16.to_le_bytes());
        blob.extend_from_slice(&4096u32.to_le_bytes()[..3]);
        blob.extend_from_slice(rw_data);
        blob.extend_from_slice(&(code_blob.len() as u32).to_le_bytes());
        blob.extend_from_slice(&code_blob);
        blob
    }

    fn inner_program() -> Vec<u8> {
        // host(42), then trap.
        vec![0, 1, 3, 10, 42, 0, 0b0000_0101]
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum ObservedEvent {
        Enter(RefineMachineIdentity, u32),
        Instruction(RefineMachineIdentity, u32),
        Exit(RefineMachineIdentity, ExitReason),
        Host(RefineHostPhase, u64),
    }

    #[test]
    fn observed_nested_run_preserves_semantics_and_machine_identity() {
        const RW_BASE: u32 = 2 * crate::PVM_ZONE_SIZE;
        let mut frame = [0u8; 112];
        frame[..8].copy_from_slice(&100_000u64.to_le_bytes());
        let [b0, b1, b2, _] = RW_BASE.to_le_bytes();
        // machine(args), r8 <- RW_BASE, invoke(machine 0, frame), halt.
        let code = [10, 9, 51, 8, b0, b1, b2, 10, 13, 50, 0];
        let outer = standard_program_with_rw(&code, &[0, 2, 7, 9], &frame);
        let args = inner_program();
        let expected = RefineContext::load_with(&outer, &args, 1_000_000, MemoryModel::Sparse)
            .unwrap()
            .run();
        let prepared = crate::refine::PreparedProgram::new(&outer).unwrap();
        for _ in 0..2 {
            let reused =
                RefineContext::load_prepared(&prepared, &args, 1_000_000, MemoryModel::Sparse)
                    .unwrap()
                    .run();
            assert_eq!(reused.exit, expected.exit);
            assert_eq!(reused.pc, expected.pc);
            assert_eq!(reused.registers, expected.registers);
            assert_eq!(reused.gas_used, expected.gas_used);
            let mut cold_frame = [0; 112];
            let mut reused_frame = [0; 112];
            expected.memory().read_bytes(RW_BASE, &mut cold_frame);
            reused.memory().read_bytes(RW_BASE, &mut reused_frame);
            assert_eq!(reused_frame, cold_frame);
        }

        // Use real nested host dispatch with both machines recompiled. Exact
        // gas includes outer initialization, host charges and the inner refund.
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        {
            let native = crate::refine::PreparedProgram::new_with_backend(
                &outer,
                PvmBackend::ForceRecompiler,
            )
            .unwrap();
            for _ in 0..2 {
                let context =
                    RefineContext::load_prepared(&native, &args, 1_000_000, MemoryModel::Auto)
                        .unwrap();
                assert_eq!(context.outer.backend(), PvmBackend::ForceRecompiler);
                let actual = context.try_run().unwrap();
                assert_eq!(actual.exit, expected.exit);
                assert_eq!(actual.pc, expected.pc);
                assert_eq!(actual.registers, expected.registers);
                assert_eq!(actual.gas_used, expected.gas_used);
                let mut actual_frame = [0; 112];
                let mut expected_frame = [0; 112];
                actual.memory().read_bytes(RW_BASE, &mut actual_frame);
                expected.memory().read_bytes(RW_BASE, &mut expected_frame);
                assert_eq!(actual_frame, expected_frame);
            }
        }

        let mut events = Vec::new();
        let observed = RefineContext::load_with(&outer, &args, 1_000_000, MemoryModel::Sparse)
            .unwrap()
            .run_observed(|event| match event {
                RefineObservation::MachineEnter { identity, machine } => {
                    assert!(
                        machine.memory().allocated_bytes() < 16 << 20,
                        "observation must retain the sparse 4 GiB image"
                    );
                    events.push(ObservedEvent::Enter(identity, machine.pc));
                }
                RefineObservation::Instruction {
                    identity,
                    instruction,
                } => events.push(ObservedEvent::Instruction(identity, instruction.pc_before)),
                RefineObservation::MachineExit { identity, exit, .. } => {
                    events.push(ObservedEvent::Exit(identity, exit));
                }
                RefineObservation::HostCall { phase, id, .. } => {
                    events.push(ObservedEvent::Host(phase, id));
                }
                RefineObservation::Precompile { .. } => {
                    panic!("this program calls no precompile")
                }
            });

        assert_eq!(observed.exit, expected.exit);
        assert_eq!(observed.pc, expected.pc);
        assert_eq!(observed.registers, expected.registers);
        assert_eq!(observed.gas_used, expected.gas_used);
        assert_eq!(
            observed.output_bounded(crate::PVM_PAGE_SIZE as usize),
            expected.output_bounded(crate::PVM_PAGE_SIZE as usize)
        );
        let inner = RefineMachineIdentity::Inner(InnerMachineIdentity {
            slot: 0,
            generation: 0,
        });
        assert!(events.contains(&ObservedEvent::Enter(inner, 0)));
        assert!(events.contains(&ObservedEvent::Instruction(inner, 0)));
        assert!(events.contains(&ObservedEvent::Exit(inner, ExitReason::HostCall(42))));
        assert_eq!(
            events
                .iter()
                .filter_map(|event| match event {
                    ObservedEvent::Enter(RefineMachineIdentity::Outer, pc) => Some(*pc),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            [0, 2, 9],
            "each outer trace slice starts after the prior handled call"
        );
        assert_eq!(
            events
                .iter()
                .filter_map(|event| match event {
                    ObservedEvent::Host(phase, id) => Some((*phase, *id)),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            [
                (RefineHostPhase::Before, 9),
                (RefineHostPhase::After, 9),
                (RefineHostPhase::Before, 13),
                (RefineHostPhase::After, 13),
            ]
        );
    }

    #[test]
    fn outer_machine_create_and_expunge_run_to_halt() {
        // machine(9), expunge(14), jump_ind r0 to the halt address.
        let outer = standard_program(&[10, 9, 10, 14, 50, 0], &[0, 2, 4]);
        let invocation = RefineContext::load(&outer, &inner_program(), 1_000_000)
            .unwrap()
            .run();
        assert_eq!(invocation.exit, ExitReason::Halt);
        assert_eq!(invocation.registers[7], 0, "expunge returned entry PC");
        assert!(invocation.gas_used > 0);
    }

    #[test]
    fn machine_rejects_runtime_only_opcode_three_as_huh() {
        let runtime_only = build_compact_code_blob(&CodeBlob {
            jump_table: Vec::new(),
            code: vec![3],
            bitmask: vec![1],
        })
        .unwrap();
        // machine(9), then jump_ind r0 to the halt address.
        let outer = standard_program(&[10, 9, 50, 0], &[0, 2]);
        let invocation = RefineContext::load(&outer, &runtime_only, 1_000_000)
            .unwrap()
            .run();

        assert_eq!(invocation.exit, ExitReason::Halt);
        assert_eq!(invocation.registers[7], result::HUH);
    }

    /// φ7 ← the rw base (h), φ8 ← rw base + 64 (m), `ecalli id`, halt.
    fn compression_program(id: u16) -> Vec<u8> {
        let [id_lo, id_hi] = id.to_le_bytes();
        let (code, starts) = crate::test_support::code(&[
            &[51, 7, 0x00, 0x00, 0x02], // load_imm φ7, 0x2_0000
            &[51, 8, 0x40, 0x00, 0x02], // load_imm φ8, 0x2_0040
            &[10, id_lo, id_hi],        // ecalli id
            &[50, 0],                   // jump_ind φ0 (the halt address)
        ]);
        standard_program_with_rw(&code, &starts, &[0x5a; 192])
    }

    fn compressed_h() -> [u8; 64] {
        let word = u64::from_le_bytes([0x5a; 8]);
        let h = [word; 8];
        let m = [word; 16];
        let out = crate::precompile::compress(&h, &m, 0, false);
        let mut bytes = [0u8; 64];
        for (i, value) in out.iter().enumerate() {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn precompile_price_is_charged_identically_on_every_path() {
        let program = compression_program(crate::precompile::BLAKE2B_COMPRESS as u16);
        let check = |invocation: &Invocation, path: &str| {
            assert_eq!(invocation.exit, ExitReason::Halt, "{path}");
            let mut h = [0u8; 64];
            invocation.memory().read_bytes(0x2_0000, &mut h);
            assert_eq!(h, compressed_h(), "{path}: served in place");
            invocation.gas_used
        };

        let interpreted = RefineContext::load_with_backend(
            &program,
            &[],
            1_000_000,
            crate::refine::MemoryModel::Auto,
            PvmBackend::ForceInterpreter,
        )
        .unwrap()
        .run();
        let gas = check(&interpreted, "interpreter");
        let observed = RefineContext::load_with_backend(
            &program,
            &[],
            1_000_000,
            crate::refine::MemoryModel::Sparse,
            PvmBackend::ForceInterpreter,
        )
        .unwrap()
        .run_observed(|_| {});
        assert_eq!(check(&observed, "observed"), gas);
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        {
            let native = RefineContext::load_with_backend(
                &program,
                &[],
                1_000_000,
                crate::refine::MemoryModel::Auto,
                PvmBackend::ForceRecompiler,
            )
            .unwrap()
            .try_run()
            .unwrap();
            assert_eq!(check(&native, "recompiler"), gas);
        }

        // The same program naming an id no host serves, resumed for free by
        // the embedder: identical instructions and blocks, minus the price.
        let unpriced = RefineContext::load(&compression_program(0x4ff), &[], 1_000_000)
            .unwrap()
            .run_with_host(|id, _| {
                assert_eq!(id, 0x4ff);
                Ok(())
            });
        assert_eq!(unpriced.exit, ExitReason::Halt);
        assert_eq!(
            gas,
            unpriced.gas_used + crate::precompile::BLAKE2B_COMPRESS_GAS
        );
    }

    #[test]
    fn precompile_output_is_a_dirty_page_on_every_path() {
        let program = compression_program(crate::precompile::BLAKE2B_COMPRESS as u16);
        // The program stores nothing itself: the only write is the
        // compression output at 0x2_0000, written in place by the host.
        let h_page = 0x2_0000 / crate::PVM_PAGE_SIZE;
        let check = |mut invocation: Invocation, path: &str| {
            assert_eq!(invocation.exit, ExitReason::Halt, "{path}");
            assert_eq!(
                invocation.memory_mut().take_dirty_pages(),
                vec![h_page..h_page + 1],
                "{path}: precompile output"
            );
        };
        for (model, observed) in [
            (crate::refine::MemoryModel::Auto, false),
            (crate::refine::MemoryModel::Sparse, true),
        ] {
            let context = RefineContext::load_with_backend(
                &program,
                &[],
                1_000_000,
                model,
                PvmBackend::ForceInterpreter,
            )
            .unwrap();
            let invocation = if observed {
                context.run_observed(|_| {})
            } else {
                context.run()
            };
            check(
                invocation,
                if observed { "observed" } else { "interpreter" },
            );
        }
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        check(
            RefineContext::load_with_backend(
                &program,
                &[],
                1_000_000,
                crate::refine::MemoryModel::Auto,
                PvmBackend::ForceRecompiler,
            )
            .unwrap()
            .try_run()
            .unwrap(),
            "recompiler",
        );
    }

    /// An outer program that calls `instantiate` with the code hash in its
    /// read-write data, then halts.
    #[cfg(feature = "std")]
    fn instantiating_program(hash: [u8; 32]) -> Vec<u8> {
        let [lo, hi] = (crate::inner::host_call::INSTANTIATE as u16).to_le_bytes();
        let (code, starts) = crate::test_support::code(&[
            &[51, 7, 0x00, 0x00, 0x02], // load_imm φ7, 0x2_0000
            &[10, lo, hi],              // ecalli instantiate
            &[50, 0],                   // jump_ind φ0 (the halt address)
        ]);
        standard_program_with_rw(&code, &starts, &hash)
    }

    /// A program the pool lacks, given by the run's source, is installed and
    /// lent at the gas an installed one costs. A source without it, with an
    /// invalid program, or with another program's bytes answers `WHO`, as
    /// does a pooled program the source does not own.
    #[cfg(feature = "std")]
    #[test]
    fn instantiate_loads_what_its_source_gives_at_the_installed_price() {
        use crate::pool::{CodeHash, MachinePool};
        use alloc::sync::Arc;

        struct Source(Vec<(CodeHash, Vec<u8>)>);
        impl ProgramSource for Source {
            fn owns(&self, hash: &CodeHash) -> bool {
                self.0.iter().any(|(given, _)| given == hash)
            }

            fn program(&self, hash: &CodeHash) -> Option<Vec<u8>> {
                self.0
                    .iter()
                    .find(|(given, _)| given == hash)
                    .map(|(_, bytes)| bytes.clone())
            }
        }

        let program = compression_program(crate::precompile::BLAKE2B_COMPRESS as u16);
        let hash = CodeHash::of(&program);
        let another = instantiating_program([0; 32]);
        let run = |pool: &Arc<MachinePool>, source: Option<Source>| {
            let context = RefineContext::load_with_backend(
                &instantiating_program(hash.0),
                &[],
                1_000_000,
                crate::refine::MemoryModel::Auto,
                PvmBackend::ForceInterpreter,
            )
            .unwrap()
            .with_pool(Arc::clone(pool));
            match source {
                Some(source) => context.with_programs(Arc::new(source)),
                None => context,
            }
            .try_run()
            .unwrap()
        };

        let installed = Arc::new(MachinePool::new());
        installed.install(&program).unwrap();
        let reference = run(&installed, None);
        assert_eq!(reference.registers[7], 0, "the installed program is lent");
        let another_agents = run(&installed, Some(Source(Vec::new())));
        assert_eq!(
            another_agents.registers[7],
            result::WHO,
            "a pooled program the source does not own"
        );

        let empty = Arc::new(MachinePool::new());
        let loaded = run(&empty, Some(Source(vec![(hash, program.clone())])));
        assert_eq!(loaded.registers[7], 0, "the source's program is lent");
        assert_eq!(loaded.gas_used, reference.gas_used, "at the same gas");
        assert!(empty.program(&hash).is_some(), "and pooled after");

        for (why, source) in [
            ("nothing", Source(Vec::new())),
            ("an invalid program", Source(vec![(hash, vec![1, 2, 3])])),
            (
                "another program's bytes",
                Source(vec![(hash, another.clone())]),
            ),
        ] {
            let pool = Arc::new(MachinePool::new());
            let refused = run(&pool, Some(source));
            assert_eq!(refused.registers[7], result::WHO, "{why}");
            assert!(pool.program(&hash).is_none(), "{why}: nothing pooled");
        }
    }

    /// An outer program that calls `instantiate` with the code hash in its
    /// read-write data and φ8 the counter `pc` (a `load_imm` immediate,
    /// sign-extended), keeps the answer in φ9, expunges the machine φ7 names
    /// and halts: φ7 is then the counter `expunge` gave, or `WHO`.
    #[cfg(feature = "std")]
    fn instantiating_at_program(hash: [u8; 32], pc: &[u8]) -> Vec<u8> {
        let [lo, hi] = (crate::inner::host_call::INSTANTIATE as u16).to_le_bytes();
        let load_pc = [&[51, 8][..], pc].concat();
        let (code, starts) = crate::test_support::code(&[
            &[51, 7, 0x00, 0x00, 0x02],                    // load_imm φ7, 0x2_0000
            &load_pc,                                      // load_imm φ8, pc
            &[10, lo, hi],                                 // ecalli instantiate
            &[100, 9 | (7 << 4)],                          // move_reg φ9, φ7
            &[10, crate::inner::host_call::EXPUNGE as u8], // ecalli expunge
            &[50, 0],                                      // jump_ind φ0 (the halt address)
        ]);
        standard_program_with_rw(&code, &starts, &hash)
    }

    /// `instantiate` starts the machine at the counter φ8 names, on either
    /// backend, at the price it costs at 0; a counter that starts no
    /// instruction answers `HUH` at the same gas, and lends nothing.
    #[cfg(feature = "std")]
    #[test]
    fn instantiate_starts_at_the_counter_given() {
        use crate::pool::MachinePool;
        // Instructions start at 0, 5, 10 and 13; the code is 15 bytes.
        let installed = compression_program(crate::precompile::BLAKE2B_COMPRESS as u16);
        let pool = alloc::sync::Arc::new(MachinePool::new());
        let hash = pool.install(&installed).unwrap();

        let backends = crate::test_support::backends();
        for &backend in &backends {
            let run = |pc: &[u8]| {
                RefineContext::load_with_backend(
                    &instantiating_at_program(hash.0, pc),
                    &[],
                    1_000_000,
                    crate::refine::MemoryModel::Auto,
                    backend,
                )
                .unwrap()
                .with_pool(alloc::sync::Arc::clone(&pool))
                .try_run()
                .unwrap()
            };
            let started = run(&[10]);
            assert_eq!(started.exit, ExitReason::Halt, "{backend:?}");
            assert_eq!(started.registers[9], 0, "{backend:?}: the first index");
            assert_eq!(started.registers[7], 10, "{backend:?}: at its counter");
            for (pc, why) in [(&[0][..], "the start"), (&[13][..], "the last instruction")] {
                let other = run(pc);
                assert_eq!(other.registers[7], u64::from(pc[0]), "{backend:?}: {why}");
                assert_eq!(other.gas_used, started.gas_used, "{backend:?}: {why}");
            }
            for (pc, why) in [
                (&[1][..], "inside an instruction"),
                (&[15][..], "past the code"),
                (&[0xff][..], "outside the counter's domain"),
            ] {
                let refused = run(pc);
                assert_eq!(refused.registers[9], result::HUH, "{backend:?}: {why}");
                assert_eq!(refused.registers[7], result::WHO, "{backend:?}: {why}");
                assert_eq!(refused.gas_used, started.gas_used, "{backend:?}: {why}");
            }
        }
        assert_eq!(pool.idle(), backends.len(), "one idle machine per backend");
    }

    #[cfg(feature = "std")]
    #[test]
    fn instantiate_lends_pooled_machines_and_takes_them_back() {
        use crate::pool::{CodeHash, MachinePool};
        let installed = compression_program(crate::precompile::BLAKE2B_COMPRESS as u16);
        let pool = alloc::sync::Arc::new(MachinePool::new());
        let hash = pool.install(&installed).unwrap();
        let price = pool.program(&hash).unwrap().price();

        for backend in crate::test_support::backends() {
            let run = |hash: CodeHash| {
                RefineContext::load_with_backend(
                    &instantiating_program(hash.0),
                    &[],
                    1_000_000,
                    crate::refine::MemoryModel::Auto,
                    backend,
                )
                .unwrap()
                .with_pool(alloc::sync::Arc::clone(&pool))
                .try_run()
                .unwrap()
            };
            let lent = run(hash);
            assert_eq!(lent.exit, ExitReason::Halt, "{backend:?}");
            assert_eq!(lent.registers[7], 0, "{backend:?}: the first machine index");
            assert_eq!(
                pool.idle(),
                1,
                "{backend:?}: returned when the context dropped"
            );

            let unknown = run(CodeHash([0xee; 32]));
            assert_eq!(unknown.registers[7], result::WHO, "{backend:?}");
            assert_eq!(
                lent.gas_used - unknown.gas_used,
                price - gas::MACHINE_BASE,
                "{backend:?}: an installed program costs its price"
            );
            assert_eq!(pool.idle(), 1, "{backend:?}: the idle machine was reused");
            // Each backend keeps its own idle machines.
            let _ = pool
                .acquire(&pool.program(&hash).unwrap(), backend)
                .unwrap();
        }

        // Without a pool the call reaches the embedder, as on a JAM host.
        let reached = RefineContext::load(&instantiating_program(hash.0), &[], 1_000_000)
            .unwrap()
            .run();
        assert_eq!(
            reached.exit,
            ExitReason::HostCall(u64::from(crate::inner::host_call::INSTANTIATE))
        );
        let jam = RefineContext::load(&instantiating_program(hash.0), &[], 1_000_000)
            .unwrap()
            .try_run_jam(JamRefine::default())
            .unwrap()
            .invocation;
        assert_eq!(jam.exit, ExitReason::Halt);
        assert_eq!(
            jam.registers[7],
            result::WHAT,
            "the guest's loader takes over"
        );

        // The pool is shared by every refine on a node.
        let shared = alloc::sync::Arc::clone(&pool);
        std::thread::spawn(move || {
            let program = shared.program(&hash).unwrap();
            let mut machines = crate::inner::InnerMachines::new();
            machines.set_pool(alloc::sync::Arc::clone(&shared));
            machines.instantiate(&program, 0).unwrap();
        })
        .join()
        .unwrap();
        assert_eq!(pool.idle(), 1);
    }

    /// Reads the value under "abc" into 0x2_0010 with `state_read`, then
    /// halts with φ7 holding the call's result.
    fn state_reading_program() -> Vec<u8> {
        let [lo, hi] = (crate::inner::host_call::STATE_READ as u16).to_le_bytes();
        let (code, starts) = crate::test_support::code(&[
            &[51, 7, 0x00, 0x00, 0x02], // load_imm φ7, 0x2_0000 (key)
            &[51, 8, 3],                // load_imm φ8, 3
            &[51, 9, 0x10, 0x00, 0x02], // load_imm φ9, 0x2_0010 (output)
            &[51, 10, 1],               // load_imm φ10, 1 (offset)
            &[51, 11, 64],              // load_imm φ11, 64
            &[10, lo, hi],              // ecalli state_read
            &[50, 0],                   // jump_ind φ0 (halt)
        ]);
        let mut rw = b"abc".to_vec();
        rw.resize(0x60, 0);
        standard_program_with_rw(&code, &starts, &rw)
    }

    struct Fixed;
    impl StateReader for Fixed {
        fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
            (key == b"abc").then(|| b"value".to_vec())
        }

        fn rows<'a>(
            &'a self,
            _: &'a [u8],
            _: Option<&'a [u8]>,
        ) -> alloc::boxed::Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + 'a> {
            alloc::boxed::Box::new(core::iter::empty())
        }
    }

    #[test]
    fn state_read_serves_the_nodes_state_and_falls_back_to_what() {
        let program = state_reading_program();
        let served = RefineContext::load(&program, &[], 1_000_000)
            .unwrap()
            .with_state(alloc::sync::Arc::new(Fixed))
            .run();
        assert_eq!(served.exit, ExitReason::Halt);
        assert_eq!(served.registers[7], 5, "the value's whole length");
        let mut out = [0u8; 5];
        served.memory().read_bytes(0x2_0010, &mut out);
        assert_eq!(&out, b"alue\0", "copied from the offset");

        struct Long;
        impl StateReader for Long {
            fn read(&self, _: &[u8]) -> Option<Vec<u8>> {
                Some(vec![7; 1000])
            }

            fn rows<'a>(
                &'a self,
                _: &'a [u8],
                _: Option<&'a [u8]>,
            ) -> alloc::boxed::Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + 'a> {
                alloc::boxed::Box::new(core::iter::empty())
            }
        }
        let long = RefineContext::load(&program, &[], 1_000_000)
            .unwrap()
            .with_state(alloc::sync::Arc::new(Long))
            .run();
        assert_eq!(long.registers[7], 1000);
        assert_eq!(
            long.gas_used - served.gas_used,
            (64 - 4) * STATE_READ_BYTE_GAS,
            "64 bytes copied against 4"
        );

        // Without a reader the call reaches the embedder, and a JAM-only
        // run answers it with `WHAT`.
        let reached = RefineContext::load(&program, &[], 1_000_000).unwrap().run();
        assert_eq!(
            reached.exit,
            ExitReason::HostCall(u64::from(crate::inner::host_call::STATE_READ))
        );
        let jam = RefineContext::load(&program, &[], 1_000_000)
            .unwrap()
            .try_run_jam(JamRefine::default())
            .unwrap()
            .invocation;
        assert_eq!(jam.exit, ExitReason::Halt);
        assert_eq!(jam.registers[7], result::WHAT);
    }

    #[test]
    fn gas_reports_what_is_left() {
        #[rustfmt::skip]
        let code = [
            10, 0,                        // ecalli gas
            50, 0,                        // jump_ind φ0 (halt)
        ];
        let program = standard_program_with_rw(&code, &[0, 2], &[]);
        let invocation = RefineContext::load(&program, &[], 1_000_000).unwrap().run();
        assert_eq!(invocation.exit, ExitReason::Halt);
        let left = invocation.registers[7];
        // The block gas and the call's own 10 are spent before φ7 is set.
        assert!(left < 1_000_000 - 10 && left > 1_000_000 - 1_000, "{left}");
    }

    #[cfg(feature = "std")]
    #[test]
    #[should_panic(expected = "does not serve `instantiate` from a pool")]
    fn observed_runs_refuse_a_pool() {
        let program = compression_program(crate::precompile::BLAKE2B_COMPRESS as u16);
        RefineContext::load(&program, &[], 1_000_000)
            .unwrap()
            .with_pool(alloc::sync::Arc::new(crate::pool::MachinePool::new()))
            .run_observed(|_| {});
    }

    #[test]
    fn unpayable_precompile_stops_out_of_gas_unserved() {
        let program = compression_program(crate::precompile::BLAKE2B_COMPRESS as u16);
        let full = RefineContext::load(&program, &[], 1_000_000).unwrap().run();
        assert_eq!(full.exit, ExitReason::Halt);
        // Funds every block but not the price.
        let budget = full.gas_used - crate::precompile::BLAKE2B_COMPRESS_GAS;
        for observed in [false, true] {
            let context = RefineContext::load_with_backend(
                &program,
                &[],
                budget,
                crate::refine::MemoryModel::Sparse,
                PvmBackend::ForceInterpreter,
            )
            .unwrap();
            let invocation = if observed {
                context.run_observed(|_| {})
            } else {
                context.run()
            };
            assert_eq!(invocation.exit, ExitReason::OutOfGas, "observed={observed}");
            assert_eq!(invocation.pc, 10, "stops on the call's own counter");
            assert_eq!(invocation.gas_used, budget);
            let mut h = [0u8; 64];
            invocation.memory().read_bytes(0x2_0000, &mut h);
            assert_eq!(h, [0x5a; 64], "the call was not served");
        }
    }

    /// Run an inner machine whose program is `ecalli id; trap` with `gas` in
    /// its invocation frame, the host computing the outer machine's
    /// precompiles or not. Returns the outcome code in φ7 and the gas left
    /// in the frame.
    fn invoke_inner_call(id: u16, gas: u64, precompiles: bool) -> (u64, u64) {
        const RW_BASE: u32 = 2 * crate::PVM_ZONE_SIZE;
        let mut frame = [0u8; 112];
        frame[..8].copy_from_slice(&gas.to_le_bytes());
        let [b0, b1, b2, _] = RW_BASE.to_le_bytes();
        // machine(args), r8 <- RW_BASE, invoke(machine 0, frame), halt.
        let code = [10, 9, 51, 8, b0, b1, b2, 10, 13, 50, 0];
        let outer = standard_program_with_rw(&code, &[0, 2, 7, 9], &frame);
        let [id_lo, id_hi] = id.to_le_bytes();
        // ecalli id; trap.
        let inner = vec![0, 1, 4, 10, id_lo, id_hi, 0, 0b0000_1001];
        let mut context =
            RefineContext::load_with(&outer, &inner, 1_000_000, MemoryModel::Sparse).unwrap();
        if !precompiles {
            context = context.without_precompiles();
        }
        let invocation = context.run();
        assert_eq!(invocation.exit, ExitReason::Halt);
        let mut left = [0u8; 8];
        invocation.memory().read_bytes(RW_BASE, &mut left);
        (invocation.registers[7], u64::from_le_bytes(left))
    }

    /// An inner machine's precompile call returns to the outer machine as a
    /// host call, unpriced, whether or not the host computes the outer
    /// machine's: its agent serves it, on every host. Without precompiles,
    /// as on a JAM node, the outer machine's own reach the embedder.
    #[test]
    fn an_inner_machines_precompile_reaches_its_agent() {
        const HOST: u64 = 3;
        let id = crate::precompile::BLAKE2B_COMPRESS as u16;
        let (_, unknown) = invoke_inner_call(0x4ff, 100_000, true);
        for precompiles in [true, false] {
            assert_eq!(
                invoke_inner_call(id, 100_000, precompiles),
                (HOST, unknown),
                "precompiles {precompiles}"
            );
        }

        let [id_lo, id_hi] = id.to_le_bytes();
        let outer = standard_program(&[10, id_lo, id_hi, 50, 0], &[0, 3]);
        let mut seen = Vec::new();
        let invocation = RefineContext::load(&outer, &[], 1_000_000)
            .unwrap()
            .without_precompiles()
            .run_with_host(|call, machine| {
                seen.push(call);
                machine.registers_mut()[7] = result::WHAT;
                Ok(())
            });
        assert_eq!(seen, [u64::from(id)]);
        assert_eq!(invocation.exit, ExitReason::Halt);
    }

    #[test]
    fn unknown_host_call_is_returned_to_the_embedder() {
        let outer = standard_program(&[51, 2, 9, 10, 77, 0], &[0, 3, 5]);
        let invocation = RefineContext::load(&outer, &[], 1_000_000).unwrap().run();
        assert_eq!(invocation.exit, ExitReason::HostCall(77));
        assert_eq!(invocation.pc, 3, "unknown host call stays on its cause");
        assert_eq!(invocation.registers[2], 9);
    }

    #[test]
    fn embedder_calls_resume_without_reexecuting_prior_instructions() {
        // r2 <- 9; external(77); external(77); halt.
        let outer = standard_program(&[51, 2, 9, 10, 77, 10, 77, 50, 0], &[0, 3, 5, 7]);
        let mut calls = 0;
        let invocation = RefineContext::load(&outer, &[], 1_000_000)
            .unwrap()
            .run_with_host(|id, machine| {
                assert_eq!(id, 77);
                calls += 1;
                if !machine.charge(50) {
                    return Err(ExitReason::OutOfGas);
                }
                machine.registers_mut()[2] += 1;
                Ok(())
            });
        assert_eq!(calls, 2);
        assert_eq!(invocation.exit, ExitReason::Halt);
        assert_eq!(invocation.registers[2], 11);
        assert!(invocation.gas_used >= 100);
    }

    #[test]
    fn embedder_refusal_keeps_exact_call_counter_and_stops_execution() {
        let outer = standard_program(&[51, 2, 9, 10, 77, 10, 77, 50, 0], &[0, 3, 5, 7]);
        let mut calls = 0;
        let invocation = RefineContext::load(&outer, &[], 1_000_000)
            .unwrap()
            .run_with_host(|id, _| {
                calls += 1;
                Err(ExitReason::HostCall(id))
            });
        assert_eq!(calls, 1);
        assert_eq!(invocation.exit, ExitReason::HostCall(77));
        assert_eq!(invocation.pc, 3);
        assert_eq!(invocation.registers[2], 9);
    }

    #[test]
    fn embedder_calls_preserve_inner_machines_and_cannot_intercept_builtins() {
        const RW_BASE: u32 = 2 * crate::PVM_ZONE_SIZE;
        let mut frame = [0u8; 112];
        frame[..8].copy_from_slice(&100_000u64.to_le_bytes());
        let [b0, b1, b2, _] = RW_BASE.to_le_bytes();
        let baseline = standard_program_with_rw(
            &[10, 9, 51, 8, b0, b1, b2, 10, 13, 50, 0],
            &[0, 2, 7, 9],
            &frame,
        );
        let expected = RefineContext::load(&baseline, &inner_program(), 1_000_000)
            .unwrap()
            .run();
        let outer = standard_program_with_rw(
            &[10, 9, 10, 77, 51, 8, b0, b1, b2, 10, 13, 10, 77, 50, 0],
            &[0, 2, 4, 9, 11, 13],
            &frame,
        );
        let mut calls = 0;
        let invocation = RefineContext::load(&outer, &inner_program(), 1_000_000)
            .unwrap()
            .run_with_host(|id, _| {
                assert_eq!(id, 77);
                calls += 1;
                Ok(())
            });
        assert_eq!(calls, 2);
        assert_eq!(expected.exit, ExitReason::Halt);
        assert_eq!(invocation.exit, expected.exit);
        let mut expected_frame = [0; 112];
        let mut actual_frame = [0; 112];
        expected.memory().read_bytes(RW_BASE, &mut expected_frame);
        invocation.memory().read_bytes(RW_BASE, &mut actual_frame);
        assert_eq!(actual_frame, expected_frame);
        assert_ne!(
            actual_frame, frame,
            "the retained inner machine must actually execute"
        );
    }

    #[test]
    fn failed_host_dispatch_does_not_advance_the_outer_counter() {
        // Load an unmapped source range, then call machine(9) at pc 8.
        // Dispatch fails before Continue, so the owner must retain that
        // ecalli counter rather than exposing its pc-10 successor.
        let outer = standard_program(&[51, 7, 0, 0, 3, 51, 8, 1, 10, 9, 0], &[0, 5, 8, 10]);
        let invocation = RefineContext::load(&outer, &[], 1_000_000).unwrap().run();
        assert_eq!(invocation.exit, ExitReason::Panic);
        assert_eq!(invocation.pc, 8);
    }

    #[test]
    fn sixty_third_machine_is_admitted_and_sixty_fourth_is_full_before_read() {
        let outer = standard_program(&[0], &[0]);
        let mut context = RefineContext::load(&outer, &[], 10_000_000).unwrap();
        let inner = inner_program();
        for expected in 0..MAX_INNER_MACHINES as u32 {
            assert_eq!(context.inner.create(&inner, 0), Ok(expected));
        }
        assert_eq!(context.inner.len(), 63);
        let registers = context.outer.registers_mut();
        registers[7] = u64::MAX;
        registers[8] = 1;
        registers[9] = 0;

        assert!(context.machine().is_ok());
        assert_eq!(context.outer.registers()[7], result::FULL);
    }

    #[test]
    fn peek_and_poke_report_unknown_machine_before_inner_address_overflow() {
        let outer = standard_program(&[0], &[0]);
        let mut context = RefineContext::load(&outer, &[], 10_000_000).unwrap();
        let outer_address = context.outer.registers()[1] - 1;

        for operation in [RefineContext::peek, RefineContext::poke] {
            let registers = context.outer.registers_mut();
            registers[7] = 0; // no machine zero exists
            registers[8] = outer_address;
            registers[9] = u64::MAX;
            registers[10] = 1;

            assert!(operation(&mut context).is_ok());
            assert_eq!(context.outer.registers()[7], result::WHO);
        }
    }

    #[test]
    fn peek_and_poke_accept_empty_inner_range_above_u32_max() {
        let outer = standard_program(&[0], &[0]);
        let mut context = RefineContext::load(&outer, &[], 10_000_000).unwrap();
        let id = context.inner.create(&inner_program(), 0).unwrap();

        for operation in [RefineContext::peek, RefineContext::poke] {
            let registers = context.outer.registers_mut();
            registers[7] = u64::from(id);
            registers[8] = u64::MAX;
            registers[9] = u64::from(u32::MAX) + 1;
            registers[10] = 0;

            assert!(operation(&mut context).is_ok());
            assert_eq!(context.outer.registers()[7], result::OK);
        }
    }
}
