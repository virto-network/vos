//! Portable actor-machine loader for guest agent runtimes.
//!
//! This module turns a signed standard-program blob into an inner machine
//! using only host calls 9–14. It is runtime policy-free: directory paging,
//! scheduling, state lanes, and host-call handling remain the agent runtime's
//! responsibility.

use alloc::vec::Vec;

pub use super::execution::{
    MAX_PORTABLE_MACHINE_MEMORY_BYTES, PortableMachineSnapshot, PortableMemoryRegion,
};
use crate::abi::pvm::inner;
use vos_pvm_program::{PAGE_SIZE, Region, StandardProgram, parse_standard_program};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    InvalidProgram,
    MachineLimit,
    InvalidLayout,
    InvalidSnapshot,
    SnapshotLimit,
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
    writable_regions: Vec<Region>,
    live: bool,
}

impl ActorMachine {
    /// Parse, allocate, and initialize a standard actor program.
    pub fn load(blob: &[u8], args: &[u8]) -> Result<Self, LoadError> {
        Self::load_at(blob, args, 0, None)
    }

    /// Recreate a machine at the exact successor boundary captured by
    /// [`Self::capture`]. The authenticated program and arguments must
    /// reproduce the snapshot's complete mutable region map.
    pub fn restore(
        blob: &[u8],
        args: &[u8],
        snapshot: &PortableMachineSnapshot,
    ) -> Result<Self, LoadError> {
        if !snapshot.is_valid() {
            return Err(LoadError::InvalidSnapshot);
        }
        Self::load_at(blob, args, snapshot.pc, Some(snapshot))
    }

    fn load_at(
        blob: &[u8],
        args: &[u8],
        initial_pc: u32,
        snapshot: Option<&PortableMachineSnapshot>,
    ) -> Result<Self, LoadError> {
        let program = parse_standard_program(blob).ok_or(LoadError::InvalidProgram)?;
        let compact = program.compact_code().ok_or(LoadError::InvalidProgram)?;
        let layout = program.layout(args).ok_or(LoadError::InvalidLayout)?;
        let writable_regions: Vec<_> = [layout.rw, layout.stack]
            .into_iter()
            .filter(|region| region.size != 0)
            .collect();
        if let Some(snapshot) = snapshot {
            Self::validate_snapshot_regions(snapshot, &writable_regions)?;
        }
        let raw_id = inner::machine(&compact, initial_pc);
        if raw_id == inner::RESULT_FULL {
            return Err(LoadError::MachineLimit);
        }
        let id = u32::try_from(raw_id).map_err(|_| LoadError::InvalidProgram)?;
        let mut machine = Self {
            id,
            frame: [0; 14],
            writable_regions,
            live: true,
        };
        machine.frame[1..].copy_from_slice(&layout.registers);

        if let Err(error) = machine.initialize(&program, args) {
            return Err(error);
        }
        if let Some(snapshot) = snapshot {
            for region in &snapshot.memory {
                machine.write(region.base, &region.bytes)?;
            }
            machine.frame[0] = snapshot.gas_remaining;
            machine.frame[1..].copy_from_slice(&snapshot.registers);
        }
        Ok(machine)
    }

    fn validate_snapshot_regions(
        snapshot: &PortableMachineSnapshot,
        expected: &[Region],
    ) -> Result<(), LoadError> {
        if snapshot.memory.len() != expected.len() {
            return Err(LoadError::InvalidSnapshot);
        }
        for (actual, expected) in snapshot.memory.iter().zip(expected) {
            let base = u32::try_from(expected.base).map_err(|_| LoadError::InvalidLayout)?;
            let len = usize::try_from(expected.size).map_err(|_| LoadError::InvalidLayout)?;
            if actual.base != base || actual.bytes.len() != len {
                return Err(LoadError::InvalidSnapshot);
            }
        }
        Ok(())
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

    /// Capture and expunge this live machine. A persisted continuation must
    /// consume no entry in the outer invocation's 63-machine dictionary.
    pub fn capture(mut self) -> Result<PortableMachineSnapshot, LoadError> {
        let memory_bytes = self
            .writable_regions
            .iter()
            .try_fold(0usize, |total, region| {
                let size = usize::try_from(region.size).ok()?;
                total.checked_add(size)
            })
            .filter(|total| *total <= MAX_PORTABLE_MACHINE_MEMORY_BYTES)
            .ok_or(LoadError::SnapshotLimit)?;
        let mut memory = Vec::new();
        memory
            .try_reserve_exact(self.writable_regions.len())
            .map_err(|_| LoadError::SnapshotLimit)?;
        let regions = self.writable_regions.clone();
        let mut captured = 0usize;
        for region in regions {
            let base = u32::try_from(region.base).map_err(|_| LoadError::InvalidLayout)?;
            let len = usize::try_from(region.size).map_err(|_| LoadError::InvalidLayout)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(len)
                .map_err(|_| LoadError::SnapshotLimit)?;
            bytes.resize(len, 0);
            self.read(base, &mut bytes)?;
            captured = captured.checked_add(len).ok_or(LoadError::SnapshotLimit)?;
            memory.push(PortableMemoryRegion { base, bytes });
        }
        debug_assert_eq!(captured, memory_bytes);
        let raw_pc = inner::expunge(self.id);
        let pc = decode_expunge_pc(raw_pc)?;
        self.live = false;
        let snapshot = PortableMachineSnapshot {
            pc,
            gas_remaining: self.frame[0],
            registers: *self.registers(),
            memory,
        };
        if !snapshot.is_valid() {
            return Err(LoadError::InvalidSnapshot);
        }
        Ok(snapshot)
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

/// EXPUNGE returns the successor instruction counter on success and a
/// high-valued standard result sentinel on failure. Never truncate a sentinel
/// into a plausible continuation PC.
fn decode_expunge_pc(raw: u64) -> Result<u32, LoadError> {
    u32::try_from(raw).map_err(|_| LoadError::MemoryOperation)
}

impl Drop for ActorMachine {
    fn drop(&mut self) {
        if self.live {
            let _ = inner::expunge(self.id);
        }
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

    #[test]
    fn snapshot_shape_rejects_unaligned_overlapping_and_oversized_regions() {
        let base = 16 * PAGE_SIZE;
        let snapshot = |memory| PortableMachineSnapshot {
            pc: 0,
            gas_remaining: 1,
            registers: [0; vos_pvm_program::REGISTER_COUNT],
            memory,
        };
        assert_eq!(
            snapshot(vec![PortableMemoryRegion {
                base: base + 1,
                bytes: vec![0; PAGE_SIZE as usize],
            }])
            .is_valid(),
            false
        );
        assert_eq!(
            snapshot(vec![
                PortableMemoryRegion {
                    base,
                    bytes: vec![0; (2 * PAGE_SIZE) as usize],
                },
                PortableMemoryRegion {
                    base: base + PAGE_SIZE,
                    bytes: vec![0; PAGE_SIZE as usize],
                },
            ])
            .is_valid(),
            false
        );
        assert_eq!(
            snapshot(vec![PortableMemoryRegion {
                base,
                bytes: vec![0; MAX_PORTABLE_MACHINE_MEMORY_BYTES + PAGE_SIZE as usize],
            }])
            .is_valid(),
            false
        );
    }

    #[test]
    fn expunge_result_sentinels_never_become_continuation_pcs() {
        assert_eq!(
            decode_expunge_pc(inner::RESULT_WHO),
            Err(LoadError::MemoryOperation)
        );
        assert_eq!(
            decode_expunge_pc(inner::RESULT_HUH),
            Err(LoadError::MemoryOperation)
        );
        assert_eq!(
            decode_expunge_pc(inner::RESULT_FULL),
            Err(LoadError::MemoryOperation)
        );
        assert_eq!(decode_expunge_pc(u64::from(u32::MAX)), Ok(u32::MAX));
    }

    #[cfg(feature = "std")]
    fn physical_program() -> StandardProgram {
        StandardProgram {
            ro_data: vec![0xa5],
            rw_data: vec![0x11; 17],
            heap_pages: 1,
            stack_size: PAGE_SIZE,
            // ECALLI 42 followed by a trap. The first invoke must persist the
            // successor PC (2); recreating at that PC must execute the trap.
            code: CodeBlob {
                jump_table: Vec::new(),
                code: vec![10, 42, 0],
                bitmask: vec![1, 0, 1],
            },
        }
    }

    #[cfg(feature = "std")]
    fn initialize_physical_machine(
        machines: &mut vos_pvm::inner::InnerMachines,
        id: u32,
        program: &StandardProgram,
        args: &[u8],
    ) {
        use vos_pvm::inner::PageMode;

        let layout = program.layout(args).unwrap();
        for (region, data) in [
            (layout.ro, layout.ro_data),
            (layout.rw, layout.rw_data),
            (layout.stack, &[][..]),
            (layout.args, layout.args_data),
        ] {
            if region.size == 0 {
                continue;
            }
            let first = u32::try_from(region.base / u64::from(PAGE_SIZE)).unwrap();
            let count = u32::try_from(region.size / u64::from(PAGE_SIZE)).unwrap();
            machines
                .pages(id, first, count, PageMode::AllocateReadWrite)
                .unwrap();
            if !data.is_empty() {
                machines
                    .poke(id, u32::try_from(region.base).unwrap(), data)
                    .unwrap();
            }
            if !region.writable {
                machines
                    .pages(id, first, count, PageMode::SetReadOnly)
                    .unwrap();
            }
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn physical_machine_snapshot_restores_exact_successor_registers_and_memory() {
        use vos_pvm::inner::{InnerExit as PhysicalExit, InnerMachines, InvokeState};

        let program = physical_program();
        let compact = program.compact_code().unwrap();
        let args = b"portable-continuation";
        let layout = program.layout(args).unwrap();
        let writable_regions: Vec<_> = [layout.rw, layout.stack]
            .into_iter()
            .filter(|region| region.size != 0)
            .collect();
        let mut machines = InnerMachines::new();
        let id = machines.create(&compact, 0).unwrap();
        initialize_physical_machine(&mut machines, id, &program, args);

        let rw_address = u32::try_from(layout.rw.base).unwrap() + 29;
        let stack_address = u32::try_from(layout.stack.base).unwrap() + 7;
        machines.poke(id, rw_address, b"rw-after-yield").unwrap();
        machines
            .poke(id, stack_address, b"stack-after-yield")
            .unwrap();
        let mut registers = layout.registers;
        registers[3] = 0xfeed_beef;
        let first = machines
            .invoke(
                id,
                InvokeState {
                    gas: 100_000,
                    registers,
                },
            )
            .unwrap();
        assert_eq!(first.exit, PhysicalExit::Host(42));

        let memory = writable_regions
            .iter()
            .map(|region| PortableMemoryRegion {
                base: u32::try_from(region.base).unwrap(),
                bytes: machines
                    .peek(
                        id,
                        u32::try_from(region.base).unwrap(),
                        usize::try_from(region.size).unwrap(),
                    )
                    .unwrap(),
            })
            .collect();
        let pc = machines.expunge(id).unwrap();
        let snapshot = PortableMachineSnapshot {
            pc,
            gas_remaining: first.state.gas,
            registers: first.state.registers,
            memory,
        };
        assert_eq!(snapshot.pc, 2);
        assert!(snapshot.is_valid());
        ActorMachine::validate_snapshot_regions(&snapshot, &writable_regions).unwrap();
        assert!(!machines.contains(id));

        let restored = machines.create(&compact, snapshot.pc).unwrap();
        initialize_physical_machine(&mut machines, restored, &program, args);
        for region in &snapshot.memory {
            machines.poke(restored, region.base, &region.bytes).unwrap();
            assert_eq!(
                machines
                    .peek(restored, region.base, region.bytes.len())
                    .unwrap(),
                region.bytes
            );
        }
        assert_eq!(
            machines
                .peek(restored, rw_address, b"rw-after-yield".len())
                .unwrap(),
            b"rw-after-yield"
        );
        assert_eq!(
            machines
                .peek(restored, stack_address, b"stack-after-yield".len())
                .unwrap(),
            b"stack-after-yield"
        );
        let resumed = machines
            .invoke(
                restored,
                InvokeState {
                    gas: snapshot.gas_remaining,
                    registers: snapshot.registers,
                },
            )
            .unwrap();
        assert_eq!(resumed.exit, PhysicalExit::Panic);
        assert_eq!(resumed.state.registers, snapshot.registers);
    }

    #[cfg(feature = "std")]
    #[test]
    fn sixty_fourth_machine_spills_and_fifo_restore_reuses_expunge_slots() {
        use vos_pvm::inner::{InnerError, InnerMachines, MAX_INNER_MACHINES};

        let compact = physical_program().compact_code().unwrap();
        let mut machines = InnerMachines::new();
        for expected in 0..MAX_INNER_MACHINES as u32 {
            assert_eq!(machines.create(&compact, 0), Ok(expected));
        }
        assert_eq!(machines.len(), 63);
        assert_eq!(machines.create(&compact, 0), Err(InnerError::Full));

        // Persisting the FIFO head expunges it; the formerly-64th actor can
        // now run in the released lowest slot while the snapshot is offline.
        assert_eq!(machines.expunge(0), Ok(0));
        assert_eq!(machines.create(&compact, 0), Ok(0));
        assert_eq!(machines.create(&compact, 0), Err(InnerError::Full));

        // Restoring the spilled head is deterministic once the next FIFO
        // machine yields and frees its own slot.
        assert_eq!(machines.expunge(1), Ok(0));
        assert_eq!(machines.create(&compact, 2), Ok(1));
        assert_eq!(machines.len(), 63);
    }
}
