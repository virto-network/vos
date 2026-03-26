//! Actor persistence — PVM snapshot capture and restore.
//!
//! Actors are long-running PVM programs. This module provides the machinery
//! to persist their mutable runtime state (registers, memory, PC, gas, heap
//! pointers) so they can be suspended and resumed across executor restarts.
//!
//! Immutable derived fields (code, bitmask, jump_table, basic_block_starts,
//! decoded_insts) are reconstructed from the original blob on restore.

use javm::program::initialize_program;
use javm::{Gas, Pvm, PVM_REGISTER_COUNT};
use std::collections::HashMap;

/// Captured mutable state of a PVM actor instance.
#[derive(Debug, Clone)]
pub struct PvmSnapshot {
    pub registers: [u64; PVM_REGISTER_COUNT],
    pub flat_mem: Vec<u8>,
    pub pc: u32,
    pub gas: Gas,
    pub heap_base: u32,
    pub heap_top: u32,
    pub need_gas_charge: bool,
    pub suspended: bool,
    pub pending_msg: Option<Vec<u8>>,
}

impl PvmSnapshot {
    /// Capture the mutable state of a live PVM and its actor wrapper.
    pub fn capture(pvm: &Pvm, suspended: bool, pending_msg: Option<&[u8]>) -> Self {
        Self {
            registers: pvm.registers,
            flat_mem: pvm.flat_mem.clone(),
            pc: pvm.pc,
            gas: pvm.gas,
            heap_base: pvm.heap_base,
            heap_top: pvm.heap_top,
            need_gas_charge: pvm.need_gas_charge,
            suspended,
            pending_msg: pending_msg.map(|m| m.to_vec()),
        }
    }

    /// Restore a PVM actor from this snapshot + the original program blob.
    ///
    /// Creates a fresh PVM from the blob (to reconstruct immutable derived
    /// fields), then patches in the mutable state from the snapshot.
    pub fn restore(self, blob: &[u8]) -> Option<Pvm> {
        // Initialize a fresh PVM to get derived fields (code, bitmask, etc.)
        let mut pvm = initialize_program(blob, &[], self.gas)?;

        // Patch mutable fields
        pvm.registers = self.registers;
        pvm.flat_mem = self.flat_mem;
        pvm.pc = self.pc;
        pvm.gas = self.gas;
        pvm.heap_base = self.heap_base;
        pvm.heap_top = self.heap_top;
        pvm.need_gas_charge = self.need_gas_charge;

        Some(pvm)
    }
}

/// Identity for a specific actor instance, used as persistence key.
///
/// Composed of the blob index (which program) and an instance number
/// (which instance of that program).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InstanceId {
    pub blob_idx: u16,
    pub instance: u16,
}

/// Trait for persisting actor snapshots.
pub trait ActorStore {
    type Error: core::fmt::Debug;
    fn save(&mut self, id: InstanceId, snapshot: &PvmSnapshot) -> Result<(), Self::Error>;
    fn load(&self, id: InstanceId) -> Result<Option<PvmSnapshot>, Self::Error>;
    fn remove(&mut self, id: InstanceId) -> Result<(), Self::Error>;
}

/// In-memory actor store backed by a HashMap.
#[derive(Debug, Default)]
pub struct MemActorStore {
    snapshots: HashMap<InstanceId, PvmSnapshot>,
}

impl MemActorStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ActorStore for MemActorStore {
    type Error = core::convert::Infallible;

    fn save(&mut self, id: InstanceId, snapshot: &PvmSnapshot) -> Result<(), Self::Error> {
        self.snapshots.insert(id, snapshot.clone());
        Ok(())
    }

    fn load(&self, id: InstanceId) -> Result<Option<PvmSnapshot>, Self::Error> {
        Ok(self.snapshots.get(&id).cloned())
    }

    fn remove(&mut self, id: InstanceId) -> Result<(), Self::Error> {
        self.snapshots.remove(&id);
        Ok(())
    }
}
