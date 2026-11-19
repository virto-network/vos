//! Standard inner-machine host-call dispatcher for Refine programs.

mod jam;
mod lookup;
mod machines;
mod state;

pub use jam::{FetchKind, JamItem, JamRefine, JamRun, MAX_EXPORTS, Preimages, SEGMENT, jam_gas};
pub use lookup::{LOOKUP_GAS, serve_lookup};
#[cfg(feature = "std")]
pub use machines::ProgramSource;
pub use state::{MAX_STATE_KEY, StateReader, value_window};

use alloc::vec::Vec;

use crate::inner::{InnerMachines, gp_call, host_call};
use crate::refine::{Invocation, Machine, MemoryModel, RefineError};
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

/// The VOS node profile's flat price of `gas` and `log`, smaller than the
/// Gray Paper's (`gas` is 48 on the JAM-only host, [`jam_gas::GAS`]); every
/// figure measured on a VOS node's refine says so.
const BASE_CALL_GAS: Gas = 10;

/// Which host serves a refine.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Host {
    /// A VOS node, computing the outer machine's precompiles in place when
    /// `precompiles` is set.
    Node { precompiles: bool },
    /// The JAM-only host ([`RefineContext::try_run_jam`]), Gray Paper
    /// refine at its tariff: no precompile computed, no VOS extension
    /// served, but for `state_read` and `state_scan` from the context's
    /// state reader when `state` is set, a stand-in for a package's
    /// witness ([`RefineContext::try_run_jam_with_state_stand_in`]).
    Jam { state: bool },
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
    /// actors. Backend failures remain host errors ([`Self::try_run`]),
    /// never signed guest outcomes or retries on another backend.
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
    /// precompile calls reach the embedder.
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
    /// 14. Other host calls are returned to the embedder unchanged. A
    /// backend failure, which a guest may provoke (an executable mapping or
    /// a page permission the host cannot give), is
    /// [`RefineError::Backend`], a host error never a guest outcome: no
    /// failure triggers a fallback or a panic.
    pub fn try_run(self) -> Result<Invocation, RefineError> {
        self.try_run_with_host(|id, _| Err(ExitReason::HostCall(id)))
    }

    /// Service embedder-owned outer calls without restarting this execution or
    /// discarding its inner-machine dictionary. Built-in calls 9 through 14
    /// remain exclusively owned by Refine. Returning Ok advances past exactly
    /// the pending host call; an error stops at that call's counter. Backend
    /// failures are errors, as [`Self::try_run`]'s.
    ///
    /// The embedder must admit the call, validate memory ranges and charge gas
    /// and its own I/O budgets before doing work. This is not a storage ABI or
    /// an authorization grant.
    pub fn try_run_with_host(
        mut self,
        mut host: impl FnMut(u64, &mut Machine) -> Result<(), ExitReason>,
    ) -> Result<Invocation, RefineError> {
        loop {
            let exit = self.outer.try_resume()?;
            let ExitReason::HostCall(id) = exit else {
                return Ok(self.outer.finish(exit));
            };
            match self.dispatch(id) {
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

    pub fn inner(&self) -> &InnerMachines {
        &self.inner
    }

    /// Whether a VOS node serves this refine, with its extensions.
    fn serves_vos(&self) -> bool {
        matches!(self.host, Host::Node { .. })
    }

    /// Whether `state_read` and `state_scan` are served from the state
    /// reader: a VOS node's, or the JAM-only host's state stand-in.
    fn serves_state(&self) -> bool {
        self.state.is_some() && (self.serves_vos() || self.host == Host::Jam { state: true })
    }

    /// Whether the outer machine's precompiles are computed in place.
    fn computes_precompiles(&self) -> bool {
        self.host == (Host::Node { precompiles: true })
    }

    /// Serve host call `id`, or stop the machine.
    fn dispatch(&mut self, id: u64) -> Result<(), Stop> {
        match u32::try_from(id) {
            _ if self.computes_precompiles() && crate::precompile::is_precompile(id) => {
                self.precompile(id)
            }
            Ok(host_call::MACHINE) => self.machine(),
            Ok(host_call::PEEK) => self.peek(),
            Ok(host_call::POKE) => self.poke(),
            Ok(host_call::PAGES) => self.pages(),
            Ok(host_call::INVOKE) => self.invoke(),
            Ok(host_call::EXPUNGE) => self.expunge(),
            // VOS extensions, never on the JAM-only host whatever the
            // context holds, but for its state stand-in's reads.
            #[cfg(feature = "std")]
            Ok(host_call::INSTANTIATE) if self.serves_vos() && self.inner.pool().is_some() => {
                self.instantiate()
            }
            Ok(host_call::STATE_READ) if self.serves_state() => self.state_read(),
            Ok(host_call::STATE_SCAN) if self.serves_state() => self.state_scan(),
            Ok(gp_call::GAS) => self.gas(),
            // `log` is no call of the Gray Paper's.
            Ok(gp_call::LOG) if self.serves_vos() => self.log(),
            _ => Err(Stop::Exit(ExitReason::HostCall(id))),
        }
    }

    fn charge(&mut self, amount: Gas) -> Result<(), Stop> {
        self.charge_whole(Some(amount))
    }

    /// Charge a host call's whole gas, `None` past u64: more than the
    /// machine holds, so out of gas.
    fn charge_whole(&mut self, amount: Option<Gas>) -> Result<(), Stop> {
        match amount {
            Some(amount) if self.outer.charge(amount) => Ok(()),
            _ => {
                // Out of gas spends what is left, whatever the amount.
                self.outer.charge(Gas::MAX);
                Err(Stop::Exit(ExitReason::OutOfGas))
            }
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
            Host::Jam { .. } => jam_gas::GAS,
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
