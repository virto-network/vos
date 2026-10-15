//! Standard inner-machine host-call dispatcher for Refine programs.

mod jam;
mod lookup;
mod machines;
mod state;

pub use jam::{JamItem, JamRefine, JamRun, MAX_EXPORTS, Preimages, SEGMENT, jam_gas};
pub use lookup::{LOOKUP_GAS, serve_lookup};
#[cfg(feature = "std")]
pub use machines::ProgramSource;
pub use state::StateReader;

use alloc::vec::Vec;

use crate::inner::{InnerMachineIdentity, InnerMachines, gp_call, host_call};
use crate::refine::{Invocation, Machine, MachineObservation, MemoryModel, RefineError};
use crate::{ExitReason, Gas, PvmBackend};

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

/// Gas for a host call the Gray Paper prices at its base cost.
const BASE_CALL_GAS: Gas = 10;

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
}

#[cfg(test)]
mod tests;
