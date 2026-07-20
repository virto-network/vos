//! Small strict codec for consensus-visible v2 wires.

use alloc::string::String;
use alloc::vec::Vec;

const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_ITEMS: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    InvalidTag,
    InvalidVersion,
    InvalidUtf8,
    LimitExceeded,
    TrailingBytes,
    NonCanonical,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid VOS v2 wire: {self:?}")
    }
}

impl core::error::Error for DecodeError {}

pub trait V2Wire: Sized {
    const MAGIC: [u8; 4];

    fn encode_body(&self, out: &mut Vec<u8>);
    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError>;

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&Self::MAGIC);
        out.extend_from_slice(&super::ABI_VERSION.to_le_bytes());
        self.encode_body(&mut out);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.take(4)? != Self::MAGIC {
            return Err(DecodeError::InvalidTag);
        }
        if decoder.u16()? != super::ABI_VERSION {
            return Err(DecodeError::InvalidVersion);
        }
        let value = Self::decode_body(&mut decoder)?;
        if !decoder.exhausted() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(value)
    }
}

pub(crate) struct Encoder<'a>(pub &'a mut Vec<u8>);

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

pub struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub(crate) fn exhausted(&self) -> bool {
        self.pos == self.bytes.len()
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
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

    pub(crate) fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn bool(&mut self) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::NonCanonical),
        }
    }

    pub(crate) fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
        ))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
        ))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
        ))
    }

    pub(crate) fn fixed(&mut self) -> Result<[u8; 32], DecodeError> {
        self.take(32)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)
    }

    pub(crate) fn bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let len = self.u32()? as usize;
        if len > MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        Ok(self.take(len)?.to_vec())
    }

    pub(crate) fn bytes_ref(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.u32()? as usize;
        if len > MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        self.take(len)
    }

    pub(crate) fn string(&mut self) -> Result<String, DecodeError> {
        String::from_utf8(self.bytes()?).map_err(|_| DecodeError::InvalidUtf8)
    }

    pub(crate) fn option<T>(
        &mut self,
        decode: impl FnOnce(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<Option<T>, DecodeError> {
        if self.bool()? {
            decode(self).map(Some)
        } else {
            Ok(None)
        }
    }

    pub(crate) fn list<T>(
        &mut self,
        mut decode: impl FnMut(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<Vec<T>, DecodeError> {
        let len = self.u32()? as usize;
        if len > MAX_ITEMS {
            return Err(DecodeError::LimitExceeded);
        }
        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            values.push(decode(self)?);
        }
        Ok(values)
    }
}
