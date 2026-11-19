//! `state_read` and `state_scan`: the agent's applied state, as the node
//! serves it.

use alloc::vec::Vec;

use crate::Gas;

use super::{BASE_CALL_GAS, PANIC, RefineContext, Stop, result};

/// The agent's applied state, as the node reads it for `state_read`.
pub trait StateReader: Send + Sync {
    /// The value under `key`: its whole length and its bytes from `offset`
    /// on, at most `max` of them ([`value_window`]); `None` when the key has
    /// no value. A read of `max` 0 copies nothing.
    fn read(&self, key: &[u8], offset: usize, max: usize) -> Option<(usize, Vec<u8>)>;

    /// The keys of the rows whose key starts with `prefix`, in key order,
    /// after `after` when given, each with its value's length: a scan reads
    /// a value ([`StateReader::read`]) only once it serves its row.
    fn rows<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a [u8]>,
    ) -> alloc::boxed::Box<dyn Iterator<Item = (Vec<u8>, usize)> + 'a>;
}

/// `value`'s whole length and its bytes from `offset` on, at most `max`
/// of them: what a [`StateReader`] (or a service's storage) gives a read.
pub fn value_window(value: &[u8], offset: usize, max: usize) -> (usize, Vec<u8>) {
    let window = crate::refine::window(value.len(), offset as u64, max as u64);
    (value.len(), value[window].to_vec())
}

/// Applied state held in memory, by key.
impl StateReader for alloc::collections::BTreeMap<Vec<u8>, Vec<u8>> {
    fn read(&self, key: &[u8], offset: usize, max: usize) -> Option<(usize, Vec<u8>)> {
        self.get(key).map(|value| value_window(value, offset, max))
    }

    fn rows<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a [u8]>,
    ) -> alloc::boxed::Box<dyn Iterator<Item = (Vec<u8>, usize)> + 'a> {
        alloc::boxed::Box::new(
            self.range(prefix.to_vec()..)
                .take_while(move |(key, _)| key.starts_with(prefix))
                .filter(move |(key, _)| after.is_none_or(|after| key.as_slice() > after))
                .map(|(key, value)| (key.clone(), value.len())),
        )
    }
}

/// `state_read`'s and `state_scan`'s price per byte, on top of the base
/// price: each byte of a key, prefix or cursor read from the guest, and of
/// the output copied to it.
pub(crate) const STATE_READ_BYTE_GAS: Gas = 1;

/// The longest key, prefix or cursor `state_read` and `state_scan` read
/// from the guest; a longer one answers `HUH`, having cost the base price.
/// 4 KiB: past the longest key a VOS agent stores, about 2 KiB (a hashed
/// table's key at its cap, every byte doubled by the escape, behind the
/// table's prefix), whose cursor a scan reads back.
pub const MAX_STATE_KEY: u64 = 4096;

impl RefineContext {
    /// `state_read`: copy part of the value under the key at φ7/φ8 to φ9,
    /// from offset φ10, at most φ11 bytes; φ7 becomes the value's whole
    /// length, `NONE` when the key has no value, or `HUH` for a key past
    /// [`MAX_STATE_KEY`]. Costs the base price and [`STATE_READ_BYTE_GAS`]
    /// per byte of the key, charged before it is read, and per byte copied,
    /// so a refine's gas also bounds the node's copying: the reader copies
    /// no byte past what the gas left pays for.
    pub(super) fn state_read(&mut self) -> Result<(), Stop> {
        self.charge(BASE_CALL_GAS)?;
        let registers = *self.outer.registers();
        if registers[8] > MAX_STATE_KEY {
            return self.answer(result::HUH);
        }
        self.charge(registers[8] * STATE_READ_BYTE_GAS)?;
        let key = self.read_outer(registers[7], registers[8])?;
        let reader = self.state.as_ref().expect("dispatched only with a reader");
        let affordable = self.outer.gas_remaining() / STATE_READ_BYTE_GAS;
        let offset = usize::try_from(registers[10]).unwrap_or(usize::MAX);
        let max = registers[11].min(affordable);
        let max = usize::try_from(max).unwrap_or(usize::MAX);
        let Some((len, bytes)) = reader.read(&key, offset, max) else {
            return self.answer(result::NONE);
        };
        let window = crate::refine::window(len, registers[10], registers[11]).len() as u64;
        let (address, window) = self.outer_range(registers[9], window)?;
        self.charge(window as u64 * STATE_READ_BYTE_GAS)?;
        if window > 0
            && !self
                .outer
                .memory_mut()
                .write_bytes_checked(address, &bytes[..window])
        {
            return Err(PANIC);
        }
        self.answer(len as u64)
    }

    /// `state_scan`: rows whose key starts with the prefix at φ7/φ8, after
    /// the key at φ9/φ10 (empty: from the prefix), into φ11, at most φ12
    /// bytes, as whole rows of a four-byte little-endian key length, the
    /// key, a four-byte value length and the value; φ7 becomes the bytes
    /// written, 0 when no rows remain, `FULL` when the next row alone
    /// exceeds φ12, or `HUH` for a prefix or cursor past
    /// [`MAX_STATE_KEY`]. Costs the base price and [`STATE_READ_BYTE_GAS`]
    /// per byte of the prefix and cursor, charged before they are read,
    /// and per byte written. No row is read past the bytes the gas left
    /// pays for, nor past the first that would reach output the guest
    /// cannot write: such a row stops the call, a panic if the output
    /// range to its end is not writable, else out of gas.
    pub(super) fn state_scan(&mut self) -> Result<(), Stop> {
        self.charge(BASE_CALL_GAS)?;
        let registers = *self.outer.registers();
        if registers[8] > MAX_STATE_KEY || registers[10] > MAX_STATE_KEY {
            return self.answer(result::HUH);
        }
        self.charge((registers[8] + registers[10]) * STATE_READ_BYTE_GAS)?;
        let prefix = self.read_outer(registers[7], registers[8])?;
        let cursor = self.read_outer(registers[9], registers[10])?;
        let capacity = usize::try_from(registers[12]).unwrap_or(usize::MAX);
        let affordable = self.outer.gas_remaining() / STATE_READ_BYTE_GAS;
        let reader = self.state.as_ref().expect("dispatched only with a reader");
        let after = (!cursor.is_empty()).then_some(cursor.as_slice());
        let mut out = Vec::new();
        let mut full = false;
        let mut unpaid = None;
        for (key, value_len) in reader.rows(&prefix, after) {
            let row = 8 + key.len() + value_len;
            if out.len() + row > capacity {
                full = out.is_empty();
                break;
            }
            let len = (out.len() + row) as u64;
            // The output up to here is writable: only this row's part is
            // checked, before the row is gathered.
            let start = registers[11].wrapping_add(out.len() as u64);
            if self.outer.writable_range(start, row as u64).is_none() {
                return Err(PANIC);
            }
            if len > affordable {
                unpaid = Some(len);
                break;
            }
            // The row is served: only now is its value read.
            let Some((_, value)) = reader
                .read(&key, 0, value_len)
                .filter(|(len, value)| *len == value_len && value.len() == value_len)
            else {
                return Err(PANIC);
            };
            out.extend_from_slice(&(key.len() as u32).to_le_bytes());
            out.extend_from_slice(&key);
            out.extend_from_slice(&(value_len as u32).to_le_bytes());
            out.extend_from_slice(&value);
        }
        if let Some(len) = unpaid {
            return self.charge(len.saturating_mul(STATE_READ_BYTE_GAS));
        }
        let (address, len) = self.outer_range(registers[11], out.len() as u64)?;
        self.charge(len as u64 * STATE_READ_BYTE_GAS)?;
        if len > 0 && !self.outer.memory_mut().write_bytes_checked(address, &out) {
            return Err(PANIC);
        }
        self.answer(if full { result::FULL } else { len as u64 })
    }
}
