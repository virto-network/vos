//! Small strict codec for consensus-visible VOS wires.

use alloc::string::String;
use alloc::vec::Vec;

/// Maximum one length-prefixed byte/string field accepted by the base codec.
pub const MAX_WIRE_BYTES: usize = 64 * 1024 * 1024;
/// Absolute list-cardinality ceiling. Protocols should normally impose a
/// much smaller schema-specific bound with [`Decoder::list_bounded`].
pub const MAX_WIRE_ITEMS: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    InvalidTag,
    InvalidPlatform,
    InvalidUtf8,
    LimitExceeded,
    TrailingBytes,
    NonCanonical,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid VOS canonical wire: {self:?}")
    }
}

impl core::error::Error for DecodeError {}

/// Canonical little-endian encoder used by higher-level protocol schemas.
pub struct Encoder<'a>(pub &'a mut Vec<u8>);

impl Encoder<'_> {
    pub fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    pub fn bool(&mut self, value: bool) {
        self.u8(value as u8);
    }

    pub fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    pub fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    pub fn fixed(&mut self, value: &[u8; 32]) {
        self.0.extend_from_slice(value);
    }

    pub fn bytes(&mut self, value: &[u8]) {
        self.u32(value.len() as u32);
        self.0.extend_from_slice(value);
    }

    pub fn string(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    pub fn option<T>(&mut self, value: &Option<T>, encode: impl FnOnce(&mut Self, &T)) {
        match value {
            Some(value) => {
                self.bool(true);
                encode(self, value);
            }
            None => self.bool(false),
        }
    }

    pub fn list<T>(&mut self, values: &[T], mut encode: impl FnMut(&mut Self, &T)) {
        self.u32(values.len() as u32);
        for value in values {
            encode(self, value);
        }
    }
}

/// Strict, forward-only decoder. Lists grow only after a complete item has
/// consumed input, preventing tiny malicious frames from triggering large
/// caller-declared allocations.
pub struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub fn exhausted(&self) -> bool {
        self.pos == self.bytes.len()
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    pub fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(DecodeError::LimitExceeded)?;
        let value = self
            .bytes
            .get(self.pos..end)
            .ok_or(DecodeError::Truncated)?;
        self.pos = end;
        Ok(value)
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::NonCanonical),
        }
    }

    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
        ))
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
        ))
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
        ))
    }

    pub fn fixed(&mut self) -> Result<[u8; 32], DecodeError> {
        self.take(32)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)
    }

    pub fn bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        Ok(self.bytes_ref()?.to_vec())
    }

    pub fn bytes_ref(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.u32()? as usize;
        if len > MAX_WIRE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        self.take(len)
    }

    pub fn bytes_bounded(&mut self, maximum: usize) -> Result<Vec<u8>, DecodeError> {
        Ok(self.bytes_ref_bounded(maximum)?.to_vec())
    }

    pub fn bytes_ref_bounded(&mut self, maximum: usize) -> Result<&'a [u8], DecodeError> {
        let len = self.u32()? as usize;
        if len > maximum || len > MAX_WIRE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        self.take(len)
    }

    pub fn string(&mut self) -> Result<String, DecodeError> {
        String::from_utf8(self.bytes()?).map_err(|_| DecodeError::InvalidUtf8)
    }

    pub fn string_bounded(&mut self, maximum: usize) -> Result<String, DecodeError> {
        String::from_utf8(self.bytes_bounded(maximum)?).map_err(|_| DecodeError::InvalidUtf8)
    }

    pub fn option<T>(
        &mut self,
        decode: impl FnOnce(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<Option<T>, DecodeError> {
        if self.bool()? {
            decode(self).map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn list<T>(
        &mut self,
        decode: impl FnMut(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<Vec<T>, DecodeError> {
        self.list_bounded(MAX_WIRE_ITEMS, decode)
    }

    pub fn list_bounded<T>(
        &mut self,
        maximum: usize,
        mut decode: impl FnMut(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<Vec<T>, DecodeError> {
        let len = self.u32()? as usize;
        if len > maximum || len > MAX_WIRE_ITEMS {
            return Err(DecodeError::LimitExceeded);
        }
        let mut values = Vec::new();
        for _ in 0..len {
            let before = self.remaining();
            let value = decode(self)?;
            if self.remaining() >= before {
                return Err(DecodeError::NonCanonical);
            }
            values
                .try_reserve(1)
                .map_err(|_| DecodeError::LimitExceeded)?;
            values.push(value);
        }
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    struct LargeItem([u8; 256]);

    #[test]
    fn claimed_list_length_cannot_preallocate_beyond_input() {
        let bytes = (MAX_WIRE_ITEMS as u32).to_le_bytes();
        let mut decoder = Decoder::new(&bytes);
        let result = decoder.list(|decoder| {
            decoder.u8()?;
            Ok(LargeItem([0; 256]))
        });
        assert!(matches!(result, Err(DecodeError::Truncated)));
    }

    #[test]
    fn schema_bound_is_checked_before_item_allocation() {
        let bytes = 3u32.to_le_bytes();
        let mut decoder = Decoder::new(&bytes);
        let result: Result<Vec<u8>, _> = decoder.list_bounded(2, |decoder| decoder.u8());
        assert_eq!(result, Err(DecodeError::LimitExceeded));
    }

    #[test]
    fn list_items_must_consume_wire_input() {
        let bytes = 1u32.to_le_bytes();
        let mut decoder = Decoder::new(&bytes);
        assert!(matches!(
            decoder.list(|_| Ok(LargeItem([0; 256]))),
            Err(DecodeError::NonCanonical)
        ));
    }

    #[test]
    fn booleans_have_one_canonical_encoding() {
        assert_eq!(Decoder::new(&[0]).bool(), Ok(false));
        assert_eq!(Decoder::new(&[1]).bool(), Ok(true));
        assert_eq!(Decoder::new(&[2]).bool(), Err(DecodeError::NonCanonical));
    }
}
