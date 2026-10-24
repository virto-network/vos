//! The inner-machine calls: `machine`, `instantiate`, `peek`, `poke`,
//! `pages`, `invoke` and `expunge`.

use alloc::vec::Vec;

use crate::PVM_REGISTER_COUNT;
use crate::inner::{InnerError, InnerExit, InvokeState, MAX_INNER_MACHINES, PageMode, gas};

use super::{PANIC, RefineContext, Stop, result};

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

impl RefineContext {
    pub(super) fn machine(&mut self) -> Result<(), Stop> {
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
    pub(super) fn instantiate(&mut self) -> Result<(), Stop> {
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

    pub(super) fn peek(&mut self) -> Result<(), Stop> {
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

    pub(super) fn poke(&mut self) -> Result<(), Stop> {
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

    pub(super) fn pages(&mut self) -> Result<(), Stop> {
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

    pub(super) fn invoke(&mut self) -> Result<(), Stop> {
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
        let outcome = self.inner.invoke(id, state);
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

    pub(super) fn expunge(&mut self) -> Result<(), Stop> {
        self.charge(gas::EXPUNGE)?;
        let id = self.outer.registers()[7];
        let result = u32::try_from(id)
            .ok()
            .and_then(|id| self.inner.expunge(id).ok())
            .map_or(result::WHO, u64::from);
        self.answer(result)
    }
}
