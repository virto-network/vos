//! Portable actor-machine loader for guest agent runtimes.
//!
//! This module turns a signed standard-program blob into an inner machine
//! using only host calls 9–14. It is runtime policy-free: directory paging,
//! scheduling, state lanes, and host-call handling remain the agent runtime's
//! responsibility.

use crate::abi::pvm::inner;
use vos_pvm_program::{PAGE_SIZE, Region, StandardProgram, parse_standard_program};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    InvalidProgram,
    MachineLimit,
    InvalidLayout,
    PageOperation,
    MemoryOperation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InnerExit {
    Halt,
    Panic,
    Fault(u32),
    Host(u64),
    OutOfGas,
    InvalidResult(u64),
}

/// One live actor machine owned by the current outer invocation.
pub struct ActorMachine {
    id: u32,
    frame: [u64; 14],
}

impl ActorMachine {
    /// Parse, allocate, and initialize a standard actor program.
    pub fn load(blob: &[u8], args: &[u8]) -> Result<Self, LoadError> {
        let program = parse_standard_program(blob).ok_or(LoadError::InvalidProgram)?;
        let compact = program.compact_code().ok_or(LoadError::InvalidProgram)?;
        let layout = program.layout(args).ok_or(LoadError::InvalidLayout)?;
        let raw_id = inner::machine(&compact, 0);
        if raw_id == inner::RESULT_FULL {
            return Err(LoadError::MachineLimit);
        }
        let id = u32::try_from(raw_id).map_err(|_| LoadError::InvalidProgram)?;
        let mut machine = Self { id, frame: [0; 14] };
        machine.frame[1..].copy_from_slice(&layout.registers);

        if let Err(error) = machine.initialize(&program, args) {
            let _ = inner::expunge(id);
            return Err(error);
        }
        Ok(machine)
    }

    pub const fn id(&self) -> u32 {
        self.id
    }

    pub fn registers(&self) -> &[u64; vos_pvm_program::REGISTER_COUNT] {
        self.frame[1..]
            .try_into()
            .expect("the invocation frame always contains thirteen registers")
    }

    pub fn registers_mut(&mut self) -> &mut [u64; vos_pvm_program::REGISTER_COUNT] {
        (&mut self.frame[1..])
            .try_into()
            .expect("the invocation frame always contains thirteen registers")
    }

    pub const fn gas_remaining(&self) -> u64 {
        self.frame[0]
    }

    /// Resume until the actor halts, faults, exhausts gas, or requests an
    /// actor ABI host operation.
    pub fn resume(&mut self, gas: u64) -> InnerExit {
        self.frame[0] = gas;
        let [status, detail] = inner::invoke(self.id, &mut self.frame);
        match status {
            0 => InnerExit::Halt,
            1 => InnerExit::Panic,
            2 => u32::try_from(detail)
                .map(InnerExit::Fault)
                .unwrap_or(InnerExit::InvalidResult(status)),
            3 => InnerExit::Host(detail),
            4 => InnerExit::OutOfGas,
            other => InnerExit::InvalidResult(other),
        }
    }

    pub fn read(&self, address: u32, output: &mut [u8]) -> Result<(), LoadError> {
        match inner::peek(self.id, address, output) {
            inner::RESULT_OK => Ok(()),
            _ => Err(LoadError::MemoryOperation),
        }
    }

    pub fn write(&mut self, address: u32, input: &[u8]) -> Result<(), LoadError> {
        match inner::poke(self.id, address, input) {
            inner::RESULT_OK => Ok(()),
            _ => Err(LoadError::MemoryOperation),
        }
    }

    fn initialize(&mut self, program: &StandardProgram, args: &[u8]) -> Result<(), LoadError> {
        let layout = program.layout(args).ok_or(LoadError::InvalidLayout)?;
        self.initialize_region(layout.ro, layout.ro_data)?;
        self.initialize_region(layout.rw, layout.rw_data)?;
        self.initialize_region(layout.stack, &[])?;
        self.initialize_region(layout.args, layout.args_data)?;
        Ok(())
    }

    fn initialize_region(&mut self, region: Region, data: &[u8]) -> Result<(), LoadError> {
        if region.size == 0 {
            return Ok(());
        }
        let first = u32::try_from(region.base / u64::from(PAGE_SIZE))
            .map_err(|_| LoadError::InvalidLayout)?;
        let count = u32::try_from(region.size / u64::from(PAGE_SIZE))
            .map_err(|_| LoadError::InvalidLayout)?;
        if inner::pages(self.id, first, count, 2) != inner::RESULT_OK {
            return Err(LoadError::PageOperation);
        }
        if !data.is_empty() {
            let address = u32::try_from(region.base).map_err(|_| LoadError::InvalidLayout)?;
            self.write(address, data)?;
        }
        if !region.writable && inner::pages(self.id, first, count, 3) != inner::RESULT_OK {
            return Err(LoadError::PageOperation);
        }
        Ok(())
    }
}

impl Drop for ActorMachine {
    fn drop(&mut self) {
        let _ = inner::expunge(self.id);
    }
}

/// Compute the page mutations a loader must issue, independent of an
/// executor. Custom runtimes can use this to budget initialization work.
pub fn mapped_pages(program: &StandardProgram, args: &[u8]) -> Option<u32> {
    let layout = program.layout(args)?;
    [layout.ro, layout.rw, layout.stack, layout.args]
        .into_iter()
        .try_fold(0u32, |total, region| {
            let pages = u32::try_from(region.size / u64::from(PAGE_SIZE)).ok()?;
            total.checked_add(pages)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use vos_pvm_program::{CodeBlob, StandardProgram};

    #[test]
    fn page_budget_counts_declared_regions_without_instantiating() {
        let program = StandardProgram {
            ro_data: vec![1],
            rw_data: vec![2],
            heap_pages: 2,
            stack_size: PAGE_SIZE,
            code: CodeBlob {
                jump_table: Vec::new(),
                code: vec![0],
                bitmask: vec![1],
            },
        };
        // ro 1 + rw initialization/heap 3 + stack 1 + args 1.
        assert_eq!(mapped_pages(&program, &[3]), Some(6));
    }
}
