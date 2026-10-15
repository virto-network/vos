//! `state_read` and `state_scan`: the agent's applied state, as the node
//! serves it.

use alloc::vec::Vec;

use crate::Gas;

use super::{BASE_CALL_GAS, PANIC, RefineContext, Stop, result};

/// The agent's applied state, as the node reads it for `state_read`.
pub trait StateReader: Send + Sync {
    fn read(&self, key: &[u8]) -> Option<Vec<u8>>;

    /// Rows whose key starts with `prefix`, in key order, after `after`
    /// when given.
    fn rows<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a [u8]>,
    ) -> alloc::boxed::Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + 'a>;
}

/// Applied state held in memory, by key.
impl StateReader for alloc::collections::BTreeMap<Vec<u8>, Vec<u8>> {
    fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get(key).cloned()
    }

    fn rows<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a [u8]>,
    ) -> alloc::boxed::Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + 'a> {
        alloc::boxed::Box::new(
            self.range(prefix.to_vec()..)
                .take_while(move |(key, _)| key.starts_with(prefix))
                .filter(move |(key, _)| after.is_none_or(|after| key.as_slice() > after))
                .map(|(key, value)| (key.clone(), value.clone())),
        )
    }
}

/// `state_read`'s price per byte copied, on top of the base price.
pub(crate) const STATE_READ_BYTE_GAS: Gas = 1;

impl RefineContext {
    /// `state_read`: copy part of the value under the key at φ7/φ8 to φ9,
    /// from offset φ10, at most φ11 bytes; φ7 becomes the value's whole
    /// length, or `NONE` when the key has no value. Costs the base price
    /// and [`STATE_READ_BYTE_GAS`] per byte copied, so a refine's gas also
    /// bounds the node's copying.
    pub(super) fn state_read(&mut self) -> Result<(), Stop> {
        self.charge(BASE_CALL_GAS)?;
        let registers = *self.outer.registers();
        let key = self.read_outer(registers[7], registers[8])?;
        let reader = self.state.as_ref().expect("dispatched only with a reader");
        let Some(value) = reader.read(&key) else {
            return self.answer(result::NONE);
        };
        let window = crate::refine::window(value.len(), registers[10], registers[11]);
        let (address, len) = self.outer_range(registers[9], window.len() as u64)?;
        self.charge(len as u64 * STATE_READ_BYTE_GAS)?;
        if len > 0
            && !self
                .outer
                .memory_mut()
                .write_bytes_checked(address, &value[window])
        {
            return Err(PANIC);
        }
        self.answer(value.len() as u64)
    }

    /// `state_scan`: rows whose key starts with the prefix at φ7/φ8, after
    /// the key at φ9/φ10 (empty: from the prefix), into φ11, at most φ12
    /// bytes, as whole rows of a four-byte little-endian key length, the
    /// key, a four-byte value length and the value; φ7 becomes the bytes
    /// written, 0 when no rows remain, or `FULL` when the next row alone
    /// exceeds φ12. Costs the base price and [`STATE_READ_BYTE_GAS`] per
    /// byte written.
    pub(super) fn state_scan(&mut self) -> Result<(), Stop> {
        self.charge(BASE_CALL_GAS)?;
        let registers = *self.outer.registers();
        let prefix = self.read_outer(registers[7], registers[8])?;
        let cursor = self.read_outer(registers[9], registers[10])?;
        let capacity = usize::try_from(registers[12]).unwrap_or(usize::MAX);
        let reader = self.state.as_ref().expect("dispatched only with a reader");
        let after = (!cursor.is_empty()).then_some(cursor.as_slice());
        let mut out = Vec::new();
        let mut full = false;
        for (key, value) in reader.rows(&prefix, after) {
            let row = 8 + key.len() + value.len();
            if out.len() + row > capacity {
                full = out.is_empty();
                break;
            }
            out.extend_from_slice(&(key.len() as u32).to_le_bytes());
            out.extend_from_slice(&key);
            out.extend_from_slice(&(value.len() as u32).to_le_bytes());
            out.extend_from_slice(&value);
        }
        let (address, len) = self.outer_range(registers[11], out.len() as u64)?;
        self.charge(len as u64 * STATE_READ_BYTE_GAS)?;
        if len > 0 && !self.outer.memory_mut().write_bytes_checked(address, &out) {
            return Err(PANIC);
        }
        self.answer(if full { result::FULL } else { len as u64 })
    }
}
