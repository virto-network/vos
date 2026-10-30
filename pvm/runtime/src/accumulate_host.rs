//! The accumulate host: runs a standard program's accumulate entry
//! (instruction counter 5) with the Gray Paper accumulate calls a VOS node
//! serves.
//!
//! The program receives `E(t, s, |inputs|)` as its arguments, in Gray
//! Paper natural encoding, and reads each input with `fetch` (kind 15 for
//! one input, 14 for the encoded sequence). An input is a work item's
//! operand or a deferred transfer, encoded with its kind (see
//! `vos_wire::jam::AccumulateInput`). `read` and `write` reach
//! the agent's own storage. `gas` and `log` are served as in refine. Every
//! other call answers `WHAT`: the node serves no service-management calls.
//!
//! One deliberate difference from a JAM node: `read` of another service's
//! storage answers `NONE`. Agents keep their state to themselves and reach
//! each other by message.

use alloc::vec::Vec;

use crate::inner::gp_call;
use crate::refine::{Invocation, Machine, MemoryModel, PreparedProgram, RefineError};
use crate::refine_host::{FetchKind, result};
use crate::{ExitReason, Gas};

/// The accumulate entry point.
pub const ACCUMULATE_ENTRY: u32 = 5;

/// `read` and `write` name the calling service with this id.
pub const SELF_SERVICE: u64 = u64::MAX;

const BASE_CALL_GAS: Gas = 10;

/// The agent's storage, as accumulate's `read` and `write` see it.
pub trait ServiceStorage {
    fn read(&self, key: &[u8]) -> Option<Vec<u8>>;
    /// Set or (with `None`) delete a value, returning the previous value's
    /// length.
    fn write(&mut self, key: &[u8], value: Option<&[u8]>) -> Option<usize>;
    /// Whether writing `value` at `key` would take the service's storage
    /// past what its balance holds: `write` then answers `FULL` and writes
    /// nothing, as a JAM node does. A VOS node bounds an agent's storage
    /// otherwise, and answers it never.
    fn full(&self, _key: &[u8], _value: Option<&[u8]>) -> bool {
        false
    }
    /// Ask for the preimage of `hash`, `len` bytes long: whether the store
    /// takes the request. A VOS node, which keeps its programs itself,
    /// serves none: the call answers `WHAT`.
    fn solicit(&mut self, _hash: &[u8; 32], _len: u64) -> Option<bool> {
        None
    }
}

/// Accumulate's arguments for `service` at `timeslot` over `inputs`
/// inputs: `E(t, s, |inputs|)`.
pub fn arguments(timeslot: u64, service: u64, inputs: usize) -> Vec<u8> {
    let mut arguments = Vec::new();
    vos_pvm_program::encode_nat(timeslot, &mut arguments);
    vos_pvm_program::encode_nat(service, &mut arguments);
    vos_pvm_program::encode_nat(inputs as u64, &mut arguments);
    arguments
}

/// One accumulate invocation over a batch of inputs.
pub struct AccumulateContext<'a, S: ServiceStorage> {
    machine: Machine,
    service: u64,
    inputs: &'a [Vec<u8>],
    storage: &'a mut S,
}

impl<'a, S: ServiceStorage> AccumulateContext<'a, S> {
    /// Load `program` at its accumulate entry for `service` at `timeslot`.
    pub fn load(
        program: &PreparedProgram,
        timeslot: u64,
        service: u64,
        inputs: &'a [Vec<u8>],
        gas: Gas,
        storage: &'a mut S,
    ) -> Result<Self, RefineError> {
        let machine = Machine::load_prepared_at(
            program,
            ACCUMULATE_ENTRY,
            &arguments(timeslot, service, inputs.len()),
            gas,
            MemoryModel::Auto,
        )?;
        Ok(Self::new(machine, service, inputs, storage))
    }

    /// Serve accumulate on a machine loaded at [`ACCUMULATE_ENTRY`] with
    /// [`arguments`], such as one [`crate::pool::OuterMachines`] lent.
    pub fn new(machine: Machine, service: u64, inputs: &'a [Vec<u8>], storage: &'a mut S) -> Self {
        Self {
            machine,
            service,
            inputs,
            storage,
        }
    }

    /// Run to the end, serving accumulate's host calls.
    pub fn try_run(mut self) -> Result<Invocation, RefineError> {
        loop {
            let exit = self.machine.try_resume()?;
            let ExitReason::HostCall(id) = exit else {
                return Ok(self.machine.finish(exit));
            };
            if !self.machine.charge(BASE_CALL_GAS) {
                return Ok(self.machine.finish(ExitReason::OutOfGas));
            }
            let served = match u32::try_from(id) {
                Ok(gp_call::GAS) => {
                    let left = self.machine.gas_remaining();
                    self.machine.registers_mut()[7] = left;
                    true
                }
                Ok(gp_call::FETCH) => self.fetch(),
                Ok(gp_call::READ) => self.read(),
                Ok(gp_call::WRITE) => self.write(),
                Ok(gp_call::SOLICIT) => self.solicit(),
                Ok(gp_call::LOG) => {
                    self.log();
                    true
                }
                _ => {
                    self.machine.registers_mut()[7] = result::WHAT;
                    true
                }
            };
            if !served {
                return Ok(self.machine.finish(ExitReason::Panic));
            }
        }
    }

    /// Copy `bytes[offset..]`, at most `len` bytes, to guest memory at
    /// `address`, and return the whole length. False when the output is
    /// not writable.
    fn copy_out(&mut self, bytes: &[u8], address: u64, offset: u64, len: u64) -> bool {
        let window = crate::refine::window(bytes.len(), offset, len);
        match self.machine.writable_range(address, window.len() as u64) {
            Some((_, 0)) => true,
            Some((address, _)) => self
                .machine
                .memory_mut()
                .write_bytes_checked(address, &bytes[window]),
            None => false,
        }
    }

    /// `log`: φ7 level, φ8/φ9 target, φ10/φ11 message. Unreadable text is
    /// logged empty: a log never stops the program.
    fn log(&self) {
        #[cfg(feature = "std")]
        {
            let registers = *self.machine.registers();
            let text = |address: u64, len: u64| {
                self.machine
                    .read_range(address, len.min(4096))
                    .map(|bytes| alloc::string::String::from_utf8_lossy(&bytes).into_owned())
                    .unwrap_or_default()
            };
            tracing::debug!(
                level = registers[7],
                target = %text(registers[8], registers[9]),
                message = %text(registers[10], registers[11]),
                "guest log (accumulate)"
            );
        }
    }

    /// `fetch`: φ7 output, φ8 offset, φ9 length, φ10 kind, φ11 index; φ7
    /// becomes the item's whole length, or `NONE`.
    fn fetch(&mut self) -> bool {
        let registers = *self.machine.registers();
        let item = match FetchKind::from_u64(registers[10]) {
            Some(FetchKind::Input) => usize::try_from(registers[11])
                .ok()
                .and_then(|index| self.inputs.get(index))
                .cloned(),
            Some(FetchKind::Inputs) => {
                let mut encoded = Vec::new();
                vos_pvm_program::encode_nat(self.inputs.len() as u64, &mut encoded);
                for input in self.inputs {
                    encoded.extend_from_slice(input);
                }
                Some(encoded)
            }
            _ => None,
        };
        let Some(item) = item else {
            self.machine.registers_mut()[7] = result::NONE;
            return true;
        };
        if !self.copy_out(&item, registers[7], registers[8], registers[9]) {
            return false;
        }
        self.machine.registers_mut()[7] = item.len() as u64;
        true
    }

    /// `read`: φ7 service (this one, by its id or 2^64 − 1), φ8/φ9 key, φ10
    /// output, φ11 offset, φ12 length; φ7 becomes the value's whole length,
    /// or `NONE`.
    fn read(&mut self) -> bool {
        let registers = *self.machine.registers();
        if registers[7] != SELF_SERVICE && registers[7] != self.service {
            self.machine.registers_mut()[7] = result::NONE;
            return true;
        }
        let Some(key) = self.machine.read_range(registers[8], registers[9]) else {
            return false;
        };
        let Some(value) = self.storage.read(&key) else {
            self.machine.registers_mut()[7] = result::NONE;
            return true;
        };
        if !self.copy_out(&value, registers[10], registers[11], registers[12]) {
            return false;
        }
        self.machine.registers_mut()[7] = value.len() as u64;
        true
    }

    /// `solicit`: φ7 the hash, φ8 the length; φ7 becomes `OK`, `HUH` when
    /// the store refuses, or `WHAT` when it serves none.
    fn solicit(&mut self) -> bool {
        let registers = *self.machine.registers();
        let Some(hash) = self.machine.read_range(registers[7], 32) else {
            return false;
        };
        let hash: [u8; 32] = hash.try_into().expect("32 bytes");
        self.machine.registers_mut()[7] = match self.storage.solicit(&hash, registers[8]) {
            Some(true) => result::OK,
            Some(false) => result::HUH,
            None => result::WHAT,
        };
        true
    }

    /// `write`: φ7/φ8 key, φ9/φ10 value (length 0 deletes); φ7 becomes the
    /// previous value's length, or `NONE`; `FULL`, nothing written, when the
    /// storage says it is full.
    fn write(&mut self) -> bool {
        let registers = *self.machine.registers();
        let Some(key) = self.machine.read_range(registers[7], registers[8]) else {
            return false;
        };
        let value = if registers[10] == 0 {
            None
        } else {
            match self.machine.read_range(registers[9], registers[10]) {
                Some(value) => Some(value),
                None => return false,
            }
        };
        if self.storage.full(&key, value.as_deref()) {
            self.machine.registers_mut()[7] = result::FULL;
            return true;
        }
        let previous = self.storage.write(&key, value.as_deref());
        self.machine.registers_mut()[7] = previous.map_or(result::NONE, |len| len as u64);
        true
    }
}

/// Storage held in memory, by key, as a VOS node keeps it: a value
/// written is kept as it is, an empty one too.
impl ServiceStorage for alloc::collections::BTreeMap<Vec<u8>, Vec<u8>> {
    fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get(key).cloned()
    }

    fn write(&mut self, key: &[u8], value: Option<&[u8]>) -> Option<usize> {
        let previous = match value {
            Some(value) => self.insert(key.to_vec(), value.to_vec()),
            None => self.remove(key),
        };
        previous.map(|value| value.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    /// A standard program whose refine entry traps and whose accumulate
    /// entry writes "abc" = "hello", fetches input 0 into 0x2_0010, makes
    /// call `extra`, and halts.
    fn program(extra: u8) -> Vec<u8> {
        #[rustfmt::skip]
        let code: Vec<u8> = vec![
            0, 0, 0, 0, 0,                // IC 0..5: refine traps
            51, 7, 0x00, 0x00, 0x02,      // load_imm φ7, 0x2_0000 (key)
            51, 8, 3,                     // load_imm φ8, 3
            51, 9, 0x03, 0x00, 0x02,      // load_imm φ9, 0x2_0003 (value)
            51, 10, 5,                    // load_imm φ10, 5
            10, 5,                        // ecalli write
            51, 7, 0x10, 0x00, 0x02,      // load_imm φ7, 0x2_0010 (buffer)
            51, 8, 0,                     // load_imm φ8, 0 (offset)
            51, 9, 64,                    // load_imm φ9, 64 (length)
            51, 10, 15,                   // load_imm φ10, 15 (one input)
            51, 11, 0,                    // load_imm φ11, 0 (index)
            10, 2,                        // ecalli fetch
            51, 12, 0,                    // load_imm φ12, 0
            10, extra,                    // ecalli extra
            50, 0,                        // jump_ind φ0 (halt)
        ];
        let starts = [
            0, 1, 2, 3, 4, 5, 10, 13, 18, 21, 23, 28, 31, 34, 37, 40, 42, 45, 47,
        ];
        let mut bitmask = vec![0u8; code.len().div_ceil(8)];
        for start in starts {
            bitmask[start / 8] |= 1 << (start % 8);
        }
        let mut code_blob = vec![0, 1, code.len() as u8];
        code_blob.extend_from_slice(&code);
        code_blob.extend_from_slice(&bitmask);
        let mut rw = b"abchello".to_vec();
        rw.resize(0x60, 0);
        let mut blob = Vec::new();
        blob.extend_from_slice(&[0; 3]);
        blob.extend_from_slice(&(rw.len() as u32).to_le_bytes()[..3]);
        blob.extend_from_slice(&0u16.to_le_bytes());
        blob.extend_from_slice(&4096u32.to_le_bytes()[..3]);
        blob.extend_from_slice(&rw);
        blob.extend_from_slice(&(code_blob.len() as u32).to_le_bytes());
        blob.extend_from_slice(&code_blob);
        blob
    }

    fn run(extra: u8, inputs: &[Vec<u8>], storage: &mut BTreeMap<Vec<u8>, Vec<u8>>) -> Invocation {
        let prepared = PreparedProgram::new(&program(extra)).unwrap();
        AccumulateContext::load(&prepared, 7, 42, inputs, 1_000_000, storage)
            .unwrap()
            .try_run()
            .unwrap()
    }

    #[test]
    fn accumulate_writes_storage_and_fetches_inputs() {
        let mut storage = BTreeMap::new();
        let inputs = vec![b"first input".to_vec(), b"second".to_vec()];
        let invocation = run(gp_call::LOG as u8, &inputs, &mut storage);
        assert_eq!(invocation.exit, ExitReason::Halt);
        assert_eq!(
            storage.get(&b"abc"[..]).map(Vec::as_slice),
            Some(&b"hello"[..])
        );
        let mut fetched = [0u8; 11];
        invocation.memory().read_bytes(0x2_0010, &mut fetched);
        assert_eq!(&fetched, b"first input");
    }

    /// A storage past what its balance holds answers `write` `FULL` and
    /// keeps nothing.
    #[test]
    fn a_full_storage_writes_nothing() {
        struct Full(BTreeMap<Vec<u8>, Vec<u8>>);
        impl ServiceStorage for Full {
            fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
                self.0.read(key)
            }
            fn write(&mut self, key: &[u8], value: Option<&[u8]>) -> Option<usize> {
                self.0.write(key, value)
            }
            fn full(&self, _: &[u8], _: Option<&[u8]>) -> bool {
                true
            }
        }
        let mut storage = Full(BTreeMap::new());
        let prepared = PreparedProgram::new(&program(gp_call::LOG as u8)).unwrap();
        let invocation = AccumulateContext::load(&prepared, 7, 42, &[], 1_000_000, &mut storage)
            .unwrap()
            .try_run()
            .unwrap();
        assert_eq!(invocation.exit, ExitReason::Halt);
        assert!(storage.0.is_empty());
    }

    #[test]
    fn calls_the_node_does_not_serve_answer_what() {
        let mut storage = BTreeMap::new();
        // Gray Paper `transfer` (22 in the 0.8.0 numbering): not served.
        let invocation = run(22, &[], &mut storage);
        assert_eq!(invocation.exit, ExitReason::Halt);
        assert_eq!(invocation.registers[7], result::WHAT);
    }

    #[test]
    fn a_missing_input_reads_as_none() {
        let mut storage = BTreeMap::new();
        let invocation = run(gp_call::GAS as u8, &[], &mut storage);
        assert_eq!(invocation.exit, ExitReason::Halt);
        // `gas` ran last, after `fetch` found no input.
        assert!(invocation.registers[7] < 1_000_000);
        let mut fetched = [0u8; 4];
        invocation.memory().read_bytes(0x2_0010, &mut fetched);
        assert_eq!(fetched, [0; 4]);
    }
}
