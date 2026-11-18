//! The accumulate host: runs a standard program's accumulate entry
//! (instruction counter 5) with the Gray Paper accumulate calls a VOS node
//! serves.
//!
//! The program receives `E(t, s, |inputs|)` as its arguments, in Gray
//! Paper natural encoding, and reads each input with `fetch` (kind 15 for
//! one input, 14 for the encoded sequence). An input is a work item's
//! operand or a deferred transfer, encoded with its kind (see
//! `vos_abi::jam::AccumulateInput`). `read` and `write` reach
//! the agent's own storage. `gas` and `log` are served as in refine.
//! `checkpoint` is the Gray Paper's: a run that ends other than by halting
//! (a panic, a page fault, out of gas) leaves the storage as it was at its
//! last `checkpoint`, or as it was before the run when it made none; φ7
//! becomes the gas left. Every other call answers `WHAT`: the node serves
//! no service-management calls.
//!
//! One deliberate difference from a JAM node: `read` of another service's
//! storage answers `NONE`. Agents keep their state to themselves and reach
//! each other by message.
//!
//! Every call costs the VOS profile's flat base, and a gas for each byte of
//! a key or value it reads from the guest, charged before it is read, and
//! of what it copies out to the guest ([`BYTE_GAS`]).

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::inner::gp_call;
use crate::refine::{Invocation, Machine, MemoryModel, PreparedProgram, RefineError};
use crate::refine_host::{FetchKind, result};
use crate::{ExitReason, Gas};

/// The accumulate entry point.
pub const ACCUMULATE_ENTRY: u32 = 5;

/// `read` and `write` name the calling service with this id.
pub const SELF_SERVICE: u64 = u64::MAX;

/// The VOS accumulate profile's flat price of every call, smaller than the
/// Gray Paper's tariff (`gas` 48, `write` 2,442 and its length terms): a
/// gas figure of this host is the VOS profile's, not a JAM node's.
const BASE_CALL_GAS: Gas = 10;

/// The VOS accumulate profile's price of each byte of a key or value a
/// call reads from the guest, and of each byte it copies out.
pub const BYTE_GAS: Gas = 1;

/// The agent's storage, as accumulate's `read` and `write` see it.
pub trait ServiceStorage {
    /// The value under `key`: its whole length and its bytes from `offset`
    /// on, at most `max` of them (`crate::refine_host::value_window`);
    /// `None` when the key has no value. A read of `max` 0 copies nothing.
    fn read(&self, key: &[u8], offset: usize, max: usize) -> Option<(usize, Vec<u8>)>;
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
    /// The inputs' encoding `fetch` kind 14 serves, built on first use.
    encoded_inputs: Option<Vec<u8>>,
    storage: &'a mut S,
    /// Each key written since the last checkpoint, with the value it held
    /// then: what an exceptional end writes back.
    since_checkpoint: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
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
            encoded_inputs: None,
            storage,
            since_checkpoint: BTreeMap::new(),
        }
    }

    /// Run to the end, serving accumulate's host calls. A run that does not
    /// halt (a backend failure included) leaves the storage at its last
    /// checkpoint.
    pub fn try_run(mut self) -> Result<Invocation, RefineError> {
        let exit = self.serve();
        if !matches!(exit, Ok(ExitReason::Halt)) {
            for (key, value) in core::mem::take(&mut self.since_checkpoint) {
                self.storage.write(&key, value.as_deref());
            }
        }
        Ok(self.machine.finish(exit?))
    }

    /// Serve host calls to the run's last exit.
    fn serve(&mut self) -> Result<ExitReason, RefineError> {
        loop {
            let exit = self.machine.try_resume()?;
            let ExitReason::HostCall(id) = exit else {
                return Ok(exit);
            };
            let served = self
                .charge(BASE_CALL_GAS)
                .and_then(|()| match u32::try_from(id) {
                    Ok(gp_call::GAS) => {
                        let left = self.machine.gas_remaining();
                        self.machine.registers_mut()[7] = left;
                        Ok(())
                    }
                    Ok(gp_call::FETCH) => self.fetch(),
                    Ok(gp_call::READ) => self.read(),
                    Ok(gp_call::WRITE) => self.write(),
                    Ok(gp_call::SOLICIT) => self.solicit(),
                    Ok(gp_call::CHECKPOINT) => {
                        self.since_checkpoint.clear();
                        let left = self.machine.gas_remaining();
                        self.machine.registers_mut()[7] = left;
                        Ok(())
                    }
                    Ok(gp_call::LOG) => {
                        self.log();
                        Ok(())
                    }
                    _ => {
                        self.machine.registers_mut()[7] = result::WHAT;
                        Ok(())
                    }
                });
            if let Err(exit) = served {
                return Ok(exit);
            }
        }
    }

    /// Charge `gas`, or stop out of gas, spending what is left.
    fn charge(&mut self, gas: Gas) -> Result<(), ExitReason> {
        if self.machine.charge(gas) {
            Ok(())
        } else {
            Err(ExitReason::OutOfGas)
        }
    }

    /// Charge for `len` bytes moved, then read them from guest memory at
    /// `address`: a panic when any is unreadable.
    fn read_in(&mut self, address: u64, len: u64) -> Result<Vec<u8>, ExitReason> {
        self.charge(len.saturating_mul(BYTE_GAS))?;
        self.machine
            .read_range(address, len)
            .ok_or(ExitReason::Panic)
    }

    /// Copy `window`, the part a value of `len` bytes from `offset`, at
    /// most `max`, gives, to guest memory at `address`, charged a gas a
    /// byte: a panic when the output is not writable, then out of gas when
    /// the machine cannot pay.
    fn copy_out(
        &mut self,
        window: &[u8],
        len: usize,
        address: u64,
        offset: u64,
        max: u64,
    ) -> Result<(), ExitReason> {
        let size = crate::refine::window(len, offset, max).len();
        let (address, size) = self
            .machine
            .writable_range(address, size as u64)
            .ok_or(ExitReason::Panic)?;
        self.charge(size as u64 * BYTE_GAS)?;
        if size > 0
            && !self
                .machine
                .memory_mut()
                .write_bytes_checked(address, &window[..size])
        {
            return Err(ExitReason::Panic);
        }
        Ok(())
    }

    /// The bytes a copy out may take: at most `max`, and no more than the
    /// gas left pays for, so a host read past them is never made.
    fn affordable(&self, max: u64) -> usize {
        let max = max.min(self.machine.gas_remaining() / BYTE_GAS);
        usize::try_from(max).unwrap_or(usize::MAX)
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
    fn fetch(&mut self) -> Result<(), ExitReason> {
        let registers = *self.machine.registers();
        let inputs = self.inputs;
        let item: Option<Cow<'_, [u8]>> = match FetchKind::from_u64(registers[10]) {
            Some(FetchKind::Input) => usize::try_from(registers[11])
                .ok()
                .and_then(|index| inputs.get(index))
                .map(|input| Cow::Borrowed(input.as_slice())),
            Some(FetchKind::Inputs) => Some(Cow::Owned(core::mem::take(
                self.encoded_inputs.get_or_insert_with(|| {
                    let mut encoded = Vec::new();
                    vos_pvm_program::encode_nat(inputs.len() as u64, &mut encoded);
                    for input in inputs {
                        encoded.extend_from_slice(input);
                    }
                    encoded
                }),
            ))),
            _ => None,
        };
        let Some(item) = item else {
            self.machine.registers_mut()[7] = result::NONE;
            return Ok(());
        };
        let window = crate::refine::window(item.len(), registers[8], registers[9]);
        let copied = self.copy_out(
            &item[window],
            item.len(),
            registers[7],
            registers[8],
            registers[9],
        );
        let len = item.len() as u64;
        if let Cow::Owned(encoded) = item {
            self.encoded_inputs = Some(encoded);
        }
        copied?;
        self.machine.registers_mut()[7] = len;
        Ok(())
    }

    /// `read`: φ7 service (this one, by its id or 2^64 − 1), φ8/φ9 key, φ10
    /// output, φ11 offset, φ12 length; φ7 becomes the value's whole length,
    /// or `NONE`.
    fn read(&mut self) -> Result<(), ExitReason> {
        let registers = *self.machine.registers();
        if registers[7] != SELF_SERVICE && registers[7] != self.service {
            self.machine.registers_mut()[7] = result::NONE;
            return Ok(());
        }
        let key = self.read_in(registers[8], registers[9])?;
        let offset = usize::try_from(registers[11]).unwrap_or(usize::MAX);
        let max = self.affordable(registers[12]);
        let Some((len, window)) = self.storage.read(&key, offset, max) else {
            self.machine.registers_mut()[7] = result::NONE;
            return Ok(());
        };
        self.copy_out(&window, len, registers[10], registers[11], registers[12])?;
        self.machine.registers_mut()[7] = len as u64;
        Ok(())
    }

    /// `solicit`: φ7 the hash, φ8 the length; φ7 becomes `OK`, `HUH` when
    /// the store refuses, or `WHAT` when it serves none.
    fn solicit(&mut self) -> Result<(), ExitReason> {
        let registers = *self.machine.registers();
        let hash = self
            .machine
            .read_range(registers[7], 32)
            .ok_or(ExitReason::Panic)?;
        let hash: [u8; 32] = hash.try_into().expect("32 bytes");
        self.machine.registers_mut()[7] = match self.storage.solicit(&hash, registers[8]) {
            Some(true) => result::OK,
            Some(false) => result::HUH,
            None => result::WHAT,
        };
        Ok(())
    }

    /// `write`: φ7/φ8 key, φ9/φ10 value (length 0 deletes); φ7 becomes the
    /// previous value's length, or `NONE`; `FULL`, nothing written, when the
    /// storage says it is full.
    fn write(&mut self) -> Result<(), ExitReason> {
        let registers = *self.machine.registers();
        let key = self.read_in(registers[7], registers[8])?;
        let value = if registers[10] == 0 {
            None
        } else {
            Some(self.read_in(registers[9], registers[10])?)
        };
        if self.storage.full(&key, value.as_deref()) {
            self.machine.registers_mut()[7] = result::FULL;
            return Ok(());
        }
        if !self.since_checkpoint.contains_key(&key) {
            let held = self.storage.read(&key, 0, usize::MAX).map(|(_, held)| held);
            self.since_checkpoint.insert(key.clone(), held);
        }
        let previous = self.storage.write(&key, value.as_deref());
        self.machine.registers_mut()[7] = previous.map_or(result::NONE, |len| len as u64);
        Ok(())
    }
}

/// Storage held in memory, by key, as a VOS node keeps it: a value
/// written is kept as it is, an empty one too.
impl ServiceStorage for alloc::collections::BTreeMap<Vec<u8>, Vec<u8>> {
    fn read(&self, key: &[u8], offset: usize, max: usize) -> Option<(usize, Vec<u8>)> {
        self.get(key)
            .map(|value| crate::refine_host::value_window(value, offset, max))
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
        standard(&code, &starts, 0)
    }

    /// A standard program of `code`, instructions at `starts`, read-write
    /// data "abchello" padded to 0x60 bytes, then `heap_pages` pages.
    fn standard(code: &[u8], starts: &[usize], heap_pages: u16) -> Vec<u8> {
        let mut bitmask = vec![0u8; code.len().div_ceil(8)];
        for start in starts {
            bitmask[start / 8] |= 1 << (start % 8);
        }
        let mut code_blob = vec![0, 1, code.len() as u8];
        code_blob.extend_from_slice(code);
        code_blob.extend_from_slice(&bitmask);
        let mut rw = b"abchello".to_vec();
        rw.resize(0x60, 0);
        let mut blob = Vec::new();
        blob.extend_from_slice(&[0; 3]);
        blob.extend_from_slice(&(rw.len() as u32).to_le_bytes()[..3]);
        blob.extend_from_slice(&heap_pages.to_le_bytes());
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
            fn read(&self, key: &[u8], offset: usize, max: usize) -> Option<(usize, Vec<u8>)> {
                self.0.read(key, offset, max)
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

    /// `checkpoint` answers the gas left, as `gas` does at the same point.
    #[test]
    fn a_checkpoint_answers_the_gas_left() {
        let checkpoint = run(gp_call::CHECKPOINT as u8, &[], &mut BTreeMap::new());
        let gas = run(gp_call::GAS as u8, &[], &mut BTreeMap::new());
        assert_eq!(checkpoint.exit, ExitReason::Halt);
        assert_eq!(checkpoint.registers[7], gas.registers[7]);
    }

    /// An accumulate that writes "abc" = "hello", makes call `call` (a
    /// checkpoint, or one the host does not serve), writes "ab" = "hello",
    /// then ends by `end`: halts, traps, or writes a value longer than its
    /// gas pays for (out of gas).
    fn checkpointed(call: u32, end: End, storage: &mut BTreeMap<Vec<u8>, Vec<u8>>) -> ExitReason {
        #[rustfmt::skip]
        let mut code: Vec<u8> = vec![
            0, 0, 0, 0, 0,                // IC 0..5: refine traps
            51, 7, 0x00, 0x00, 0x02,      // load_imm φ7, 0x2_0000 ("abc")
            51, 8, 3,                     // load_imm φ8, 3
            51, 9, 0x03, 0x00, 0x02,      // load_imm φ9, 0x2_0003 ("hello")
            51, 10, 5,                    // load_imm φ10, 5
            10, 5,                        // ecalli write
            10, call as u8,               // ecalli call
            51, 7, 0x00, 0x00, 0x02,      // load_imm φ7, 0x2_0000 ("ab")
            51, 8, 2,                     // load_imm φ8, 2
            51, 9, 0x03, 0x00, 0x02,      // load_imm φ9, 0x2_0003 ("hello")
            51, 10, 5,                    // load_imm φ10, 5
            10, 5,                        // ecalli write
        ];
        let mut starts = vec![0, 1, 2, 3, 4, 5, 10, 13, 18, 21, 23, 25, 30, 33, 38, 41];
        #[rustfmt::skip]
        let tail: &[u8] = match end {
            End::Halt => &[50, 0],        // jump_ind φ0 (halt)
            End::Trap => &[0],            // trap
            End::OutOfGas => &[
                51, 7, 0x00, 0x00, 0x02,  // load_imm φ7, 0x2_0000 ("ab")
                51, 10, 0xff,             // load_imm φ10, 2^64 − 1 (value length)
                10, 5,                    // ecalli write
                0,                        // trap (unreached)
            ],
        };
        starts.push(code.len());
        if end == End::OutOfGas {
            starts.extend([5, 8, 10].map(|at| code.len() + at));
        }
        code.extend_from_slice(tail);
        let prepared = PreparedProgram::new(&standard(&code, &starts, 0)).unwrap();
        AccumulateContext::load(&prepared, 7, 42, &[], 1_000_000, storage)
            .unwrap()
            .try_run()
            .unwrap()
            .exit
    }

    #[derive(Clone, Copy, PartialEq)]
    enum End {
        Halt,
        Trap,
        OutOfGas,
    }

    /// A run that ends other than by halting leaves the storage as it was
    /// at its last checkpoint, or before the run when it made none, a key
    /// it held before included; one that halts keeps every write.
    #[test]
    fn an_exceptional_end_reverts_to_the_last_checkpoint() {
        let before = BTreeMap::from([(b"ab".to_vec(), b"old".to_vec())]);
        let hello = || b"hello".to_vec();
        for (end, exit) in [
            (End::Trap, ExitReason::Panic),
            (End::OutOfGas, ExitReason::OutOfGas),
        ] {
            let mut storage = before.clone();
            assert_eq!(checkpointed(gp_call::CHECKPOINT, end, &mut storage), exit);
            let at_checkpoint = BTreeMap::from([
                (b"ab".to_vec(), b"old".to_vec()),
                (b"abc".to_vec(), hello()),
            ]);
            assert_eq!(storage, at_checkpoint, "reverted to the checkpoint");

            let mut storage = before.clone();
            assert_eq!(checkpointed(gp_call::LOG, end, &mut storage), exit);
            assert_eq!(storage, before, "no checkpoint: reverted to the start");
        }
        let mut storage = before.clone();
        assert_eq!(
            checkpointed(gp_call::CHECKPOINT, End::Halt, &mut storage),
            ExitReason::Halt
        );
        let halted = BTreeMap::from([(b"ab".to_vec(), hello()), (b"abc".to_vec(), hello())]);
        assert_eq!(storage, halted, "a halt keeps every write");
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

    /// A storage that records the most bytes each read asked it to copy
    /// (in [`RECORDED`]: the trait reads through a shared borrow).
    #[derive(Default)]
    struct Recording {
        map: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl ServiceStorage for Recording {
        fn read(&self, key: &[u8], offset: usize, max: usize) -> Option<(usize, Vec<u8>)> {
            assert!(key.len() <= 3, "a key the gas paid for");
            RECORDED.with(|cell| cell.borrow_mut().push(max));
            self.map.read(key, offset, max)
        }
        fn write(&mut self, key: &[u8], value: Option<&[u8]>) -> Option<usize> {
            self.map.write(key, value)
        }
    }

    std::thread_local! {
        static RECORDED: core::cell::RefCell<Vec<usize>> = const {
            core::cell::RefCell::new(Vec::new())
        };
    }

    /// `read` of a key of `len` bytes at the read-write data's start,
    /// behind 65,535 heap pages (256 MiB readable at load for no gas), into
    /// 0x2_0010 with φ12 `max`, at 1,000,000 gas: the exit, φ7 and the gas
    /// used.
    fn read_key(len: u32, max: u32, storage: &mut Recording) -> (ExitReason, u64, u64) {
        let [l0, l1, l2, l3] = len.to_le_bytes();
        let [m0, m1, m2, m3] = max.to_le_bytes();
        #[rustfmt::skip]
        let code: Vec<u8> = vec![
            0, 0, 0, 0, 0,                // IC 0..5: refine traps
            51, 7, 0xff,                  // load_imm φ7, -1 (this service)
            51, 8, 0x00, 0x00, 0x02,      // load_imm φ8, 0x2_0000 (key)
            51, 9, l0, l1, l2, l3,        // load_imm φ9, len
            51, 10, 0x10, 0x00, 0x02,     // load_imm φ10, 0x2_0010 (output)
            51, 11, 0,                    // load_imm φ11, 0 (offset)
            51, 12, m0, m1, m2, m3,       // load_imm φ12, max
            10, 4,                        // ecalli read
            50, 0,                        // jump_ind φ0 (halt)
        ];
        let starts = [0, 1, 2, 3, 4, 5, 8, 13, 19, 24, 27, 33, 35];
        let prepared = PreparedProgram::new(&standard(&code, &starts, u16::MAX)).unwrap();
        let invocation = AccumulateContext::load(&prepared, 7, 42, &[], 1_000_000, storage)
            .unwrap()
            .try_run()
            .unwrap();
        (
            invocation.exit,
            invocation.registers[7],
            invocation.gas_used,
        )
    }

    /// A key read from the guest is charged a gas a byte before it is
    /// read, so a 255 MiB key, readable for no gas, is out of gas unread
    /// (unpriced, the host copies all of it for 10 gas). The storage copies no
    /// byte past what the call asks and the gas left pays for: a
    /// zero-length read copies nothing.
    #[test]
    fn accumulate_reads_cost_their_bytes_before_any_is_read() {
        let mut storage = Recording::default();
        storage.map.insert(b"abc".to_vec(), b"hello".to_vec());
        let (exit, _, gas) = read_key(255 << 20, 0, &mut storage);
        assert_eq!((exit, gas), (ExitReason::OutOfGas, 1_000_000));
        assert!(RECORDED.with(|cell| cell.borrow().is_empty()), "never read");

        let (exit, answer, zero) = read_key(3, 0, &mut storage);
        assert_eq!((exit, answer), (ExitReason::Halt, 5));
        let (exit, answer, whole) = read_key(3, u32::MAX, &mut storage);
        assert_eq!((exit, answer), (ExitReason::Halt, 5));
        assert_eq!(whole - zero, 5 * BYTE_GAS, "the bytes copied");
        let asked = RECORDED.with(|cell| cell.borrow().clone());
        assert_eq!(asked[0], 0, "a zero-length read asks for nothing");
        assert!(asked[1] < 1_000_000, "no more than the gas left pays for");
    }
}
