//! Standard inner-machine host-call dispatcher for Refine programs.

use alloc::vec::Vec;

use crate::inner::{
    InnerError, InnerExit, InnerMachines, InvokeState, MAX_INNER_MACHINES, PageMode, gas, host_call,
};
use crate::refine::{Invocation, Machine, MemoryModel, RefineError};
use crate::{ExitReason, Gas, PVM_REGISTER_COUNT};

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

    /// Run the outer program, transparently servicing host calls 9 through
    /// 14. Other host calls are returned to the embedder unchanged.
    pub fn run(mut self) -> Invocation {
        loop {
            let exit = self.outer.resume();
            let ExitReason::HostCall(id) = exit else {
                return self.outer.finish(exit);
            };
            match self.dispatch(id) {
                Dispatch::Continue => {}
                Dispatch::Exit(exit) => return self.outer.finish(exit),
            }
        }
    }

    pub fn inner(&self) -> &InnerMachines {
        &self.inner
    }

    fn dispatch(&mut self, id: u64) -> Dispatch {
        match id {
            value if value == u64::from(host_call::MACHINE) => self.machine(),
            value if value == u64::from(host_call::PEEK) => self.peek(),
            value if value == u64::from(host_call::POKE) => self.poke(),
            value if value == u64::from(host_call::PAGES) => self.pages(),
            value if value == u64::from(host_call::INVOKE) => self.invoke(),
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
                Err(_) => result::HUH,
            },
            Err(_) => result::HUH,
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

    fn invoke(&mut self) -> Dispatch {
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
        let outcome = match self.inner.invoke(
            id,
            InvokeState {
                gas: requested_gas,
                registers: inner_registers,
            },
        ) {
            Ok(outcome) => outcome,
            Err(InnerError::Unknown) => {
                self.outer.registers_mut()[7] = result::WHO;
                return Dispatch::Continue;
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use vos_pvm_program::{CodeBlob, build_compact_code_blob};

    fn standard_program(args_code: &[u8], starts: &[usize]) -> Vec<u8> {
        let mut packed = alloc::vec![0u8; args_code.len().div_ceil(8)];
        for &i in starts {
            packed[i / 8] |= 1 << (i % 8);
        }
        let mut code_blob = alloc::vec![0, 1, args_code.len() as u8];
        code_blob.extend_from_slice(args_code);
        code_blob.extend_from_slice(&packed);

        let mut blob = Vec::new();
        blob.extend_from_slice(&[0; 3]);
        blob.extend_from_slice(&[0; 3]);
        blob.extend_from_slice(&0u16.to_le_bytes());
        blob.extend_from_slice(&4096u32.to_le_bytes()[..3]);
        blob.extend_from_slice(&(code_blob.len() as u32).to_le_bytes());
        blob.extend_from_slice(&code_blob);
        blob
    }

    fn inner_program() -> Vec<u8> {
        // host(42), then trap.
        vec![0, 1, 3, 10, 42, 0, 0b0000_0101]
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

    #[test]
    fn unknown_host_call_is_returned_to_the_embedder() {
        let outer = standard_program(&[51, 2, 9, 10, 77, 0], &[0, 3, 5]);
        let invocation = RefineContext::load(&outer, &[], 1_000_000).unwrap().run();
        assert_eq!(invocation.exit, ExitReason::HostCall(77));
        assert_eq!(invocation.pc, 3, "unknown host call stays on its cause");
        assert_eq!(invocation.registers[2], 9);
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
    fn machine_reports_full_before_reading_an_invalid_outer_pointer() {
        let outer = standard_program(&[0], &[0]);
        let mut context = RefineContext::load(&outer, &[], 10_000_000).unwrap();
        let inner = inner_program();
        for expected in 0..MAX_INNER_MACHINES as u32 {
            assert_eq!(context.inner.create(&inner, 0), Ok(expected));
        }
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
