//! Standard inner-machine host-call dispatcher for Refine programs.

use alloc::vec::Vec;

use crate::inner::{
    InnerError, InnerExit, InnerMachineIdentity, InnerMachineObservation, InnerMachines,
    InvokeState, MAX_INNER_MACHINES, PageMode, gas, host_call,
};
use crate::refine::{Invocation, Machine, MachineObservation, MemoryModel, RefineError};
use crate::{ExitReason, Gas, PVM_REGISTER_COUNT, PvmBackend};

/// Standard host result constants used by the inner-machine calls.
pub mod result {
    pub const OK: u64 = 0;
    pub const OOB: u64 = u64::MAX - 2;
    pub const WHO: u64 = u64::MAX - 3;
    pub const FULL: u64 = u64::MAX - 4;
    pub const HUH: u64 = u64::MAX - 8;
}

enum Dispatch {
    Continue,
    Exit(ExitReason),
    Backend,
}

/// Aggregate timings only; instruction observation would distort the path
/// being measured. Inner create includes decoding/preparation, and inner invoke
/// includes its frame/refund handling. Neither is a queue or quorum benchmark.
#[cfg(feature = "std")]
#[derive(Default)]
struct ExecutionTimings {
    outer_us: u64,
    inner_create_us: u64,
    inner_invoke_us: u64,
    host_us: u64,
    outer_slices: u64,
}

#[cfg(feature = "std")]
impl Drop for ExecutionTimings {
    fn drop(&mut self) {
        tracing::debug!(
            outer_execution_us = self.outer_us,
            inner_create_us = self.inner_create_us,
            inner_invoke_us = self.inner_invoke_us,
            host_dispatch_us = self.host_us,
            outer_slices = self.outer_slices,
            "Refine execution phases"
        );
    }
}

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
    /// A precompile served in place inside the current slice.
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

/// A standard outer PVM plus its per-invocation inner-machine dictionary.
pub struct RefineContext {
    outer: Machine,
    inner: InnerMachines,
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
        Ok(Self {
            outer: Machine::load_with(program, args, gas, model)?,
            inner: InnerMachines::new(),
        })
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
        let outer = Machine::load_with_backend(program, args, gas, model, backend)?;
        let inner = InnerMachines::with_backend(outer.backend());
        Ok(Self { outer, inner })
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

    /// Reuse validated program preparation, never per-invocation machines.
    pub fn load_prepared(
        program: &crate::refine::PreparedProgram,
        args: &[u8],
        gas: Gas,
        model: MemoryModel,
    ) -> Result<Self, RefineError> {
        let outer = Machine::load_prepared(program, args, gas, model)?;
        let inner = InnerMachines::with_backend(outer.backend());
        Ok(Self { outer, inner })
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
        #[cfg(feature = "std")]
        let mut timings = ExecutionTimings::default();
        loop {
            #[cfg(feature = "std")]
            let started = std::time::Instant::now();
            let exit = self.outer.try_resume();
            #[cfg(feature = "std")]
            {
                timings.outer_us += started.elapsed().as_micros() as u64;
                timings.outer_slices += 1;
            }
            let exit = exit?;
            let ExitReason::HostCall(id) = exit else {
                return Ok(self.outer.finish(exit));
            };
            #[cfg(feature = "std")]
            let started = std::time::Instant::now();
            let dispatch = self.dispatch(id);
            #[cfg(feature = "std")]
            {
                let elapsed = started.elapsed().as_micros() as u64;
                match id {
                    id if id == u64::from(host_call::MACHINE) => timings.inner_create_us += elapsed,
                    id if id == u64::from(host_call::INVOKE) => timings.inner_invoke_us += elapsed,
                    _ => timings.host_us += elapsed,
                }
            }
            match dispatch {
                Dispatch::Continue => {}
                Dispatch::Exit(ExitReason::HostCall(call)) => {
                    #[cfg(feature = "std")]
                    let started = std::time::Instant::now();
                    let result = host(call, &mut self.outer);
                    #[cfg(feature = "std")]
                    {
                        timings.host_us += started.elapsed().as_micros() as u64;
                    }
                    if let Err(exit) = result {
                        return Ok(self.outer.finish(exit));
                    }
                }
                Dispatch::Exit(exit) => return Ok(self.outer.finish(exit)),
                Dispatch::Backend => return Err(RefineError::Backend),
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

    fn run_with_observer(
        mut self,
        observer: &mut dyn for<'a> FnMut(RefineObservation<'a>),
    ) -> Invocation {
        // A traced run must execute exactly like a live one, and tracing
        // cannot follow a pooled machine yet.
        #[cfg(feature = "std")]
        assert!(
            self.inner.pool().is_none(),
            "observed Refine execution does not serve `instantiate` from a pool"
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
                if !crate::precompile::is_precompile(id) {
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
            let dispatch = self.dispatch_observed(id, observer);
            observer(RefineObservation::HostCall {
                phase: RefineHostPhase::After,
                id,
                outer: &self.outer,
                inner: &self.inner,
            });
            match dispatch {
                Dispatch::Continue => {}
                Dispatch::Exit(exit) => return self.outer.finish(exit),
                Dispatch::Backend => {
                    panic!("observed Refine execution requires the reference backend")
                }
            }
        }
    }

    pub fn inner(&self) -> &InnerMachines {
        &self.inner
    }

    fn precompile(&mut self, id: u64) -> Dispatch {
        if let Err(exit) = self.charge(crate::precompile::price(id).unwrap_or(0)) {
            return exit;
        }
        let registers = *self.outer.registers();
        match crate::precompile::execute(id, &registers, self.outer.memory_mut()) {
            Some(_) => Dispatch::Continue,
            None => Dispatch::Exit(ExitReason::Panic),
        }
    }

    fn dispatch(&mut self, id: u64) -> Dispatch {
        match id {
            value if crate::precompile::is_precompile(value) => self.precompile(value),
            value if value == u64::from(host_call::MACHINE) => self.machine(),
            value if value == u64::from(host_call::PEEK) => self.peek(),
            value if value == u64::from(host_call::POKE) => self.poke(),
            value if value == u64::from(host_call::PAGES) => self.pages(),
            value if value == u64::from(host_call::INVOKE) => self.invoke(None),
            value if value == u64::from(host_call::EXPUNGE) => self.expunge(),
            #[cfg(feature = "std")]
            value if value == u64::from(host_call::INSTANTIATE) && self.inner.pool().is_some() => {
                self.instantiate()
            }
            _ => Dispatch::Exit(ExitReason::HostCall(id)),
        }
    }

    fn dispatch_observed(
        &mut self,
        id: u64,
        observer: &mut dyn for<'a> FnMut(RefineObservation<'a>),
    ) -> Dispatch {
        match id {
            value if value == u64::from(host_call::MACHINE) => self.machine(),
            value if value == u64::from(host_call::PEEK) => self.peek(),
            value if value == u64::from(host_call::POKE) => self.poke(),
            value if value == u64::from(host_call::PAGES) => self.pages(),
            value if value == u64::from(host_call::INVOKE) => self.invoke(Some(observer)),
            value if value == u64::from(host_call::EXPUNGE) => self.expunge(),
            _ => Dispatch::Exit(ExitReason::HostCall(id)),
        }
    }

    fn charge(&mut self, amount: Gas) -> Result<(), Dispatch> {
        if self.outer.charge(amount) {
            Ok(())
        } else {
            Err(Dispatch::Exit(ExitReason::OutOfGas))
        }
    }

    fn machine(&mut self) -> Dispatch {
        let registers = *self.outer.registers();
        let (address, len, initial_pc) = (registers[7], registers[8], registers[9]);
        let cost = gas::MACHINE_BASE.saturating_add(gas::memory(gas::MACHINE_PER_KIB, len));
        if let Err(exit) = self.charge(cost) {
            return exit;
        }
        // Gray Paper v0.8.0 checks the invocation-wide machine limit before
        // inspecting the caller-supplied program range. At capacity even an
        // unreadable outer pointer therefore returns FULL, rather than
        // panicking while trying to read a program that cannot be installed.
        if self.inner.len() >= MAX_INNER_MACHINES {
            self.outer.registers_mut()[7] = result::FULL;
            return Dispatch::Continue;
        }
        let Some(program) = self.read_outer(address, len, false) else {
            return Dispatch::Exit(ExitReason::Panic);
        };
        let result = match u32::try_from(initial_pc) {
            Ok(pc) => match self.inner.create(&program, pc) {
                Ok(id) => id as u64,
                Err(InnerError::Full) => result::FULL,
                Err(InnerError::Backend) => return Dispatch::Backend,
                Err(_) => result::HUH,
            },
            Err(_) => result::HUH,
        };
        self.outer.registers_mut()[7] = result;
        Dispatch::Continue
    }

    /// `instantiate`: φ7 points at a 32-byte code hash. φ7 becomes the new
    /// machine's index, `WHO` for a program the pool does not hold, or
    /// `FULL` at the machine limit. The call costs `machine`'s base, as a
    /// failed `machine` does; an installed program then costs the rest of
    /// its price, what laying it out costs a loader in host calls (never
    /// less than the base). The machine starts at instruction counter 0.
    #[cfg(feature = "std")]
    fn instantiate(&mut self) -> Dispatch {
        if let Err(exit) = self.charge(gas::MACHINE_BASE) {
            return exit;
        }
        if self.inner.len() >= MAX_INNER_MACHINES {
            self.outer.registers_mut()[7] = result::FULL;
            return Dispatch::Continue;
        }
        let address = self.outer.registers()[7];
        let Some(hash) = self.read_outer(address, 32, false) else {
            return Dispatch::Exit(ExitReason::Panic);
        };
        let hash = crate::pool::CodeHash(hash.try_into().expect("32 bytes read"));
        let program = self.inner.pool().and_then(|pool| pool.program(&hash));
        let result = match program {
            None => result::WHO,
            Some(program) => {
                if let Err(exit) = self.charge(program.price() - gas::MACHINE_BASE) {
                    return exit;
                }
                match self.inner.instantiate(&program) {
                    Ok(id) => u64::from(id),
                    Err(InnerError::Full) => result::FULL,
                    Err(InnerError::Backend) => return Dispatch::Backend,
                    Err(_) => result::HUH,
                }
            }
        };
        self.outer.registers_mut()[7] = result;
        Dispatch::Continue
    }

    fn peek(&mut self) -> Dispatch {
        let registers = *self.outer.registers();
        let (id, outer_address, inner_address, len) =
            (registers[7], registers[8], registers[9], registers[10]);
        let cost = gas::PEEK_BASE.saturating_add(gas::memory(gas::PEEK_PER_KIB, len));
        if let Err(exit) = self.charge(cost) {
            return exit;
        }
        let Some((outer_address, len)) = self.outer_range(outer_address, len, true) else {
            return Dispatch::Exit(ExitReason::Panic);
        };
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
                            return Dispatch::Exit(ExitReason::Panic);
                        }
                        result::OK
                    }
                    Err(InnerError::Unknown) => result::WHO,
                    Err(InnerError::OutOfBounds) => result::OOB,
                    Err(InnerError::Backend) => return Dispatch::Backend,
                    Err(_) => result::HUH,
                },
                None => result::OOB,
            },
            _ => result::WHO,
        };
        self.outer.registers_mut()[7] = status;
        Dispatch::Continue
    }

    fn poke(&mut self) -> Dispatch {
        let registers = *self.outer.registers();
        let (id, outer_address, inner_address, len) =
            (registers[7], registers[8], registers[9], registers[10]);
        let cost = gas::POKE_BASE.saturating_add(gas::memory(gas::POKE_PER_KIB, len));
        if let Err(exit) = self.charge(cost) {
            return exit;
        }
        let Some(bytes) = self.read_outer(outer_address, len, false) else {
            return Dispatch::Exit(ExitReason::Panic);
        };
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
                    Err(InnerError::Backend) => return Dispatch::Backend,
                    Err(_) => result::HUH,
                },
                None => result::OOB,
            },
            _ => result::WHO,
        };
        self.outer.registers_mut()[7] = status;
        Dispatch::Continue
    }

    fn pages(&mut self) -> Dispatch {
        let registers = *self.outer.registers();
        let (id, first, count, mode) = (registers[7], registers[8], registers[9], registers[10]);
        let cost = match mode {
            0 => {
                gas::PAGES_FREE_BASE.saturating_add(count.saturating_mul(gas::PAGES_FREE_PER_PAGE))
            }
            1 | 2 => gas::PAGES_ALLOC_BASE
                .saturating_add(count.saturating_mul(gas::PAGES_ALLOC_PER_PAGE)),
            3 | 4 => gas::PAGES_SET_MODE_BASE
                .saturating_add(count.saturating_mul(gas::PAGES_SET_MODE_PER_PAGE)),
            _ => gas::PAGES_INVALID,
        };
        if let Err(exit) = self.charge(cost) {
            return exit;
        }
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
                        Err(InnerError::Backend) => return Dispatch::Backend,
                        Err(_) => result::HUH,
                    }
                }
                _ => result::HUH,
            },
            _ => result::WHO,
        };
        self.outer.registers_mut()[7] = status;
        Dispatch::Continue
    }

    fn invoke(
        &mut self,
        observer: Option<&mut dyn for<'a> FnMut(RefineObservation<'a>)>,
    ) -> Dispatch {
        let registers = *self.outer.registers();
        let (id, frame_address) = (registers[7], registers[8]);
        let Some((frame_address, _)) = self.outer_range(frame_address, 112, true) else {
            if let Err(exit) = self.charge(gas::INVOKE_BASE) {
                return exit;
            }
            return Dispatch::Exit(ExitReason::Panic);
        };
        let mut frame = [0u8; 112];
        if !self
            .outer
            .memory()
            .read_bytes_checked(frame_address, &mut frame)
        {
            return Dispatch::Exit(ExitReason::Panic);
        }
        let requested_gas = u64::from_le_bytes(frame[..8].try_into().expect("eight bytes"));
        let total = gas::INVOKE_BASE.saturating_add(requested_gas);
        if let Err(exit) = self.charge(total) {
            return exit;
        }
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
            self.outer.registers_mut()[7] = result::WHO;
            return Dispatch::Continue;
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
                InnerMachineObservation::Precompile { identity, call } => {
                    observer(RefineObservation::Precompile {
                        identity: RefineMachineIdentity::Inner(identity),
                        call,
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
            Err(InnerError::Unknown) => {
                self.outer.registers_mut()[7] = result::WHO;
                return Dispatch::Continue;
            }
            Err(InnerError::Backend) => return Dispatch::Backend,
            Err(_) => {
                self.outer.registers_mut()[7] = result::HUH;
                return Dispatch::Continue;
            }
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
            return Dispatch::Exit(ExitReason::Panic);
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
        Dispatch::Continue
    }

    fn expunge(&mut self) -> Dispatch {
        if let Err(exit) = self.charge(gas::EXPUNGE) {
            return exit;
        }
        let id = self.outer.registers()[7];
        let result = u32::try_from(id)
            .ok()
            .and_then(|id| self.inner.expunge(id).ok())
            .map_or(result::WHO, u64::from);
        self.outer.registers_mut()[7] = result;
        Dispatch::Continue
    }

    fn read_outer(&self, address: u64, len: u64, writable: bool) -> Option<Vec<u8>> {
        let (address, len) = self.outer_range(address, len, writable)?;
        let mut bytes = alloc::vec![0u8; len];
        if self.outer.memory().read_bytes_checked(address, &mut bytes) {
            Some(bytes)
        } else {
            None
        }
    }

    fn outer_range(&self, address: u64, len: u64, writable: bool) -> Option<(u32, usize)> {
        let len = usize::try_from(len).ok()?;
        if len == 0 {
            return Some((0, 0));
        }
        let address = u32::try_from(address).ok()?;
        let accessible = if writable {
            self.outer.memory().is_writable(address, len)
        } else {
            self.outer.memory().is_readable(address, len)
        };
        accessible.then_some((address, len))
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

    fn standard_program_with_rw(args_code: &[u8], starts: &[usize], rw_data: &[u8]) -> Vec<u8> {
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
        let code = [
            51, 7, 0x00, 0x00, 0x02, // load_imm φ7, 0x2_0000
            51, 8, 0x40, 0x00, 0x02, // load_imm φ8, 0x2_0040
            10, id_lo, id_hi, // ecalli id
            50, 0, // jump_ind φ0 (the halt address)
        ];
        standard_program_with_rw(&code, &[0, 5, 10, 13], &[0x5a; 192])
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
        let code = [
            51, 7, 0x00, 0x00, 0x02, // load_imm φ7, 0x2_0000
            10, lo, hi, // ecalli instantiate
            50, 0, // jump_ind φ0 (the halt address)
        ];
        standard_program_with_rw(&code, &[0, 5, 8], &hash)
    }

    #[cfg(feature = "std")]
    #[test]
    fn instantiate_lends_pooled_machines_and_takes_them_back() {
        use crate::pool::{CodeHash, MachinePool};
        let installed = compression_program(crate::precompile::BLAKE2B_COMPRESS as u16);
        let pool = alloc::sync::Arc::new(MachinePool::new());
        let hash = pool.install(&installed).unwrap();
        let price = pool.program(&hash).unwrap().price();

        let mut backends = vec![PvmBackend::ForceInterpreter];
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        backends.push(PvmBackend::ForceRecompiler);
        for backend in backends {
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

        // The pool is shared by every refine on a node.
        let shared = alloc::sync::Arc::clone(&pool);
        std::thread::spawn(move || {
            let program = shared.program(&hash).unwrap();
            let mut machines = crate::inner::InnerMachines::new();
            machines.set_pool(alloc::sync::Arc::clone(&shared));
            machines.instantiate(&program).unwrap();
        })
        .join()
        .unwrap();
        assert_eq!(pool.idle(), 1);
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
    /// its invocation frame. Returns the outcome code in φ7 and the gas left
    /// in the frame.
    fn invoke_inner_call(id: u16, gas: u64) -> (u64, u64) {
        const RW_BASE: u32 = 2 * crate::PVM_ZONE_SIZE;
        let mut frame = [0u8; 112];
        frame[..8].copy_from_slice(&gas.to_le_bytes());
        let [b0, b1, b2, _] = RW_BASE.to_le_bytes();
        // machine(args), r8 <- RW_BASE, invoke(machine 0, frame), halt.
        let code = [10, 9, 51, 8, b0, b1, b2, 10, 13, 50, 0];
        let outer = standard_program_with_rw(&code, &[0, 2, 7, 9], &frame);
        let [id_lo, id_hi] = id.to_le_bytes();
        // ecalli id; trap. The inner machine maps no pages, so a served
        // compression faults on its pointers after paying.
        let inner = vec![0, 1, 4, 10, id_lo, id_hi, 0, 0b0000_1001];
        let invocation = RefineContext::load_with(&outer, &inner, 1_000_000, MemoryModel::Sparse)
            .unwrap()
            .run();
        assert_eq!(invocation.exit, ExitReason::Halt);
        let mut left = [0u8; 8];
        invocation.memory().read_bytes(RW_BASE, &mut left);
        (invocation.registers[7], u64::from_le_bytes(left))
    }

    #[test]
    fn inner_machine_precompile_pays_the_same_price() {
        const PANIC: u64 = 1;
        const HOST: u64 = 3;
        const OUT_OF_GAS: u64 = 4;
        let (outcome, unpriced_left) = invoke_inner_call(0x4ff, 100_000);
        assert_eq!(outcome, HOST, "an unknown id returns to the outer machine");
        let (outcome, priced_left) =
            invoke_inner_call(crate::precompile::BLAKE2B_COMPRESS as u16, 100_000);
        assert_eq!(
            outcome, PANIC,
            "the served call faults on unmapped pointers"
        );
        assert_eq!(
            unpriced_left - priced_left,
            crate::precompile::BLAKE2B_COMPRESS_GAS
        );

        // Funds the block but not the price.
        let blocks = 100_000 - unpriced_left;
        let budget = blocks + crate::precompile::BLAKE2B_COMPRESS_GAS - 1;
        let (outcome, left) = invoke_inner_call(crate::precompile::BLAKE2B_COMPRESS as u16, budget);
        assert_eq!(outcome, OUT_OF_GAS);
        assert_eq!(left, 0);
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

        assert!(matches!(context.machine(), Dispatch::Continue));
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

            assert!(matches!(operation(&mut context), Dispatch::Continue));
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

            assert!(matches!(operation(&mut context), Dispatch::Continue));
            assert_eq!(context.outer.registers()[7], result::OK);
        }
    }
}
