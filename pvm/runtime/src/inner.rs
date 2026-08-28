//! Standard Refine inner-machine management.
//!
//! This module implements the portable `machine`, `peek`, `poke`, `pages`,
//! `invoke`, and `expunge` substrate from Gray Paper v0.8.0. It has no
//! capability-kernel dependency and is available in `no_std` builds.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::gas_cost::DEFAULT_MEM_CYCLES;
use crate::interpreter::{Interpreter, Memory, PERM_NONE, PERM_RO, PERM_RW};
use crate::program::ParsedCodeBlob;
use crate::spi::{parse_compact_code_blob, validate_code_blob};
use crate::{ExitReason, Gas, IsaMode, PVM_PAGE_SIZE, PVM_REGISTER_COUNT};

/// Maximum live inner machines in one Refine invocation.
pub const MAX_INNER_MACHINES: usize = 63;

/// Number of pages in the 32-bit PVM address space.
pub const INNER_ADDRESS_PAGES: usize = (1u64 << 32) as usize / PVM_PAGE_SIZE as usize;

/// The first page an inner machine may map.
pub const INNER_FIRST_MAPPABLE_PAGE: u32 = 16;

/// Stable host-call identifiers for the standard inner-machine surface.
pub mod host_call {
    pub const MACHINE: u32 = 9;
    pub const PEEK: u32 = 10;
    pub const POKE: u32 = 11;
    pub const PAGES: u32 = 12;
    pub const INVOKE: u32 = 13;
    pub const EXPUNGE: u32 = 14;
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
        rate.saturating_mul(bytes).saturating_add(1023) / 1024
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
    Host(u32),
    OutOfGas,
}

/// Result of invoking one inner machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvokeOutcome {
    pub exit: InnerExit,
    pub state: InvokeState,
}

struct InnerMachine {
    program: Option<ParsedCodeBlob>,
    initial_pc: u32,
    vm: Option<Interpreter>,
}

impl InnerMachine {
    fn vm(&mut self) -> &mut Interpreter {
        if self.vm.is_none() {
            let program = self.program.take().expect("program exists until VM init");
            let mut memory = Memory::sparse(1u64 << 32);
            memory.set_page_perms(vec![PERM_NONE; INNER_ADDRESS_PAGES]);
            let mut vm = Interpreter::with_memory(
                program.code,
                program.bitmask,
                program.jump_table,
                [0; PVM_REGISTER_COUNT],
                memory,
                0,
                DEFAULT_MEM_CYCLES,
            );
            vm.isa_mode = IsaMode::Conformance;
            vm.set_pc(self.initial_pc);
            self.vm = Some(vm);
        }
        self.vm.as_mut().expect("initialized above")
    }

    fn pc(&self) -> u32 {
        self.vm.as_ref().map_or(self.initial_pc, |vm| vm.pc)
    }
}

/// Per-Refine dictionary of standard inner machines.
#[derive(Default)]
pub struct InnerMachines {
    machines: BTreeMap<u32, InnerMachine>,
}

impl InnerMachines {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.machines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.machines.is_empty()
    }

    /// Create a machine from one canonical compact code blob.
    ///
    /// The lowest unused natural-number index is returned.
    pub fn create(&mut self, program_blob: &[u8], initial_pc: u32) -> Result<u32, InnerError> {
        if self.machines.len() >= MAX_INNER_MACHINES {
            return Err(InnerError::Full);
        }
        let program = parse_compact_code_blob(program_blob).ok_or(InnerError::Invalid)?;
        if !validate_code_blob(&program, initial_pc) {
            return Err(InnerError::Invalid);
        }
        let id = (0..MAX_INNER_MACHINES as u32)
            .find(|id| !self.machines.contains_key(id))
            .expect("a free ID exists below the machine limit");
        self.machines.insert(
            id,
            InnerMachine {
                program: Some(program),
                initial_pc,
                vm: None,
            },
        );
        Ok(id)
    }

    /// Copy readable bytes out of an inner machine.
    pub fn peek(&mut self, id: u32, source: u32, len: usize) -> Result<Vec<u8>, InnerError> {
        let machine = self.machines.get_mut(&id).ok_or(InnerError::Unknown)?;
        let mut out = vec![0u8; len];
        if !machine.vm().memory().read_bytes_checked(source, &mut out) {
            return Err(InnerError::OutOfBounds);
        }
        Ok(out)
    }

    /// Copy bytes into writable inner-machine memory.
    pub fn poke(&mut self, id: u32, destination: u32, data: &[u8]) -> Result<(), InnerError> {
        let machine = self.machines.get_mut(&id).ok_or(InnerError::Unknown)?;
        if !machine
            .vm()
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

        let vm = machine.vm();
        let memory = vm.memory_mut();
        let first = first as usize;
        let count = count as usize;
        if matches!(mode, PageMode::SetReadOnly | PageMode::SetReadWrite)
            && memory.page_perms()[first..first + count].contains(&PERM_NONE)
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
            assert!(memory.clear_pages(first, count));
        }
        assert!(memory.set_page_range(first, count, permission));
        Ok(())
    }

    /// Resume a machine with the supplied gas counter and register file.
    pub fn invoke(&mut self, id: u32, state: InvokeState) -> Result<InvokeOutcome, InnerError> {
        let machine = self.machines.get_mut(&id).ok_or(InnerError::Unknown)?;
        let vm = machine.vm();
        vm.gas = state.gas;
        vm.registers = state.registers;
        let (exit, _) = vm.run();
        let exit = match exit {
            ExitReason::Halt => {
                vm.pc = 0;
                InnerExit::Halt
            }
            ExitReason::Trap | ExitReason::Panic | ExitReason::Ecall => {
                vm.pc = 0;
                InnerExit::Panic
            }
            ExitReason::OutOfGas => InnerExit::OutOfGas,
            ExitReason::PageFault(address) => InnerExit::Fault(address),
            ExitReason::HostCall(id) => InnerExit::Host(id),
        };
        Ok(InvokeOutcome {
            exit,
            state: InvokeState {
                gas: vm.gas,
                registers: vm.registers,
            },
        })
    }

    /// Remove a machine and return its current instruction counter.
    pub fn expunge(&mut self, id: u32) -> Result<u32, InnerError> {
        self.machines
            .remove(&id)
            .map(|machine| machine.pc())
            .ok_or(InnerError::Unknown)
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
        assert_eq!(gas::memory(112, 0), 0);
        assert_eq!(gas::memory(112, 1), 1);
        assert_eq!(gas::memory(112, 1024), 112);
        assert_eq!(gas::memory(112, 1025), 113);
    }
}
