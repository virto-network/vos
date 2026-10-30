//! The SCALE pieces the anchor types and a statement encode with:
//! fixed-width little-endian integers, fixed arrays as their bytes, and a
//! compact length before a sequence. A decode is canonical: a compact in its
//! shortest mode, an enum's byte one of its values, nothing longer than the
//! input, so a value has one encoding.

use alloc::vec::Vec;

/// Why bytes do not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ends inside a value.
    Short,
    /// A compact not in its shortest mode, or a value out of its range: an
    /// enum's unknown byte among them.
    Noncanonical,
    /// Bytes left after the value.
    Trailing,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Short => "the input ends inside a value",
            Self::Noncanonical => "a value is not in its canonical encoding",
            Self::Trailing => "bytes are left after the value",
        })
    }
}

/// A length's SCALE compact encoding.
pub fn compact(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=0x3f => out.push((value as u8) << 2),
        0x40..=0x3fff => out.extend_from_slice(&(((value as u16) << 2) | 1).to_le_bytes()),
        0x4000..=0x3fff_ffff => out.extend_from_slice(&(((value as u32) << 2) | 2).to_le_bytes()),
        _ => {
            // 4 to 8 bytes: the value is at least 2^30.
            let width = 8usize.saturating_sub(value.leading_zeros() as usize / 8);
            out.push(((width.saturating_sub(4) as u8) << 2) | 3);
            out.extend(value.to_le_bytes().into_iter().take(width));
        }
    }
}

/// A flag's byte: 0 or 1.
pub fn flag(out: &mut Vec<u8>, value: bool) {
    out.push(u8::from(value));
}

/// An `Option<u64>`: 0, or 1 then the value (8, little-endian).
pub fn option_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        None => out.push(0),
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
}

/// Bytes read in order, each read refusing what the input does not hold.
pub struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    /// A reader at the start of `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// The bytes read so far.
    pub fn used(&self) -> usize {
        self.at
    }

    /// The next `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.at.checked_add(n).ok_or(DecodeError::Short)?;
        let bytes = self.bytes.get(self.at..end).ok_or(DecodeError::Short)?;
        self.at = end;
        Ok(bytes)
    }

    /// The next `N` bytes, as an array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        self.take(N)?
            .first_chunk()
            .copied()
            .ok_or(DecodeError::Short)
    }

    /// A byte.
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        let [byte] = self.array()?;
        Ok(byte)
    }

    /// A little-endian `u32`.
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    /// A little-endian `u64`.
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// A flag: 0 or 1, any other byte refused.
    pub fn flag(&mut self) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::Noncanonical),
        }
    }

    /// An `Option<u64>` ([`option_u64`]), its flag 0 or 1.
    pub fn option_u64(&mut self) -> Result<Option<u64>, DecodeError> {
        Ok(if self.flag()? {
            Some(self.u64()?)
        } else {
            None
        })
    }

    /// A compact, in its shortest mode.
    pub fn compact(&mut self) -> Result<u64, DecodeError> {
        let first = self.u8()?;
        let (value, least) = match first & 3 {
            0 => (u64::from(first >> 2), 0),
            1 => (
                u64::from(u16::from_le_bytes([first, self.u8()?]) >> 2),
                0x40,
            ),
            2 => {
                let rest: [u8; 3] = self.array()?;
                let word = u32::from_le_bytes([first, rest[0], rest[1], rest[2]]);
                (u64::from(word >> 2), 0x4000)
            }
            _ => self.big_integer(first)?,
        };
        if value < least {
            return Err(DecodeError::Noncanonical);
        }
        Ok(value)
    }

    /// A compact's big-integer mode after its first byte: its value, and
    /// the least value the mode takes in that many bytes.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "`width` is `first >> 2` and 4, at most 67, and at most 8 past `get_mut`, so `8·(width − 1)` is 24 to 56"
    )]
    fn big_integer(&mut self, first: u8) -> Result<(u64, u64), DecodeError> {
        let width = usize::from(first >> 2) + 4;
        let mut bytes = [0u8; 8];
        let value = bytes.get_mut(..width).ok_or(DecodeError::Noncanonical)?;
        value.copy_from_slice(self.take(width)?);
        let value = u64::from_le_bytes(bytes);
        // The big-integer mode only past 2^30, and in its fewest bytes.
        let least = (1u64 << (8 * (width - 1))).max(0x4000_0000);
        Ok((value, least))
    }

    /// A count of items at least `item` bytes each, which the input holds.
    pub fn count(&mut self, item: usize) -> Result<usize, DecodeError> {
        let count = self.compact()?;
        let left = self.bytes.len().saturating_sub(self.at) as u64;
        if count.saturating_mul(item as u64) > left {
            return Err(DecodeError::Short);
        }
        Ok(count as usize)
    }

    /// A byte vector: its compact length, then its bytes.
    pub fn bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let len = self.count(1)?;
        Ok(self.take(len)?.to_vec())
    }

    /// Nothing is left.
    pub fn finish(&self) -> Result<(), DecodeError> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(DecodeError::Trailing)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        compact(&mut out, value);
        out
    }

    /// SCALE's own vectors, each mode at its ends; every value decodes back.
    #[test]
    fn compacts_are_scales() {
        let vectors: [(u64, &[u8]); 9] = [
            (0, &[0x00]),
            (1, &[0x04]),
            (63, &[0xfc]),
            (64, &[0x01, 0x01]),
            (16_383, &[0xfd, 0xff]),
            (16_384, &[0x02, 0x00, 0x01, 0x00]),
            (1_073_741_823, &[0xfe, 0xff, 0xff, 0xff]),
            (1_073_741_824, &[0x03, 0x00, 0x00, 0x00, 0x40]),
            (
                u64::MAX,
                &[0x13, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];
        for (value, bytes) in vectors {
            assert_eq!(encoded(value), bytes, "{value}");
            let mut reader = Reader::new(bytes);
            assert_eq!(reader.compact(), Ok(value));
            reader.finish().unwrap();
        }
    }

    /// A value in a longer mode than its own is refused.
    #[test]
    fn a_compact_in_a_longer_mode_is_refused() {
        for bytes in [
            &[0x01, 0x00][..],
            &[0xfd, 0x00],
            &[0x02, 0x00, 0x00, 0x00],
            &[0x03, 0xff, 0xff, 0xff, 0x3f],
            &[0x07, 0xff, 0xff, 0xff, 0xff, 0x00],
            &[0x17, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ] {
            assert_eq!(
                Reader::new(bytes).compact(),
                Err(DecodeError::Noncanonical),
                "{bytes:02x?}"
            );
        }
    }

    /// A flag and an option decode from their encodings; a flag's byte past
    /// 1 is refused.
    #[test]
    fn flags_and_options_are_canonical() {
        for value in [None, Some(0), Some(u64::MAX)] {
            let mut out = Vec::new();
            option_u64(&mut out, value);
            flag(&mut out, value.is_some());
            let mut reader = Reader::new(&out);
            assert_eq!(reader.option_u64(), Ok(value));
            assert_eq!(reader.flag(), Ok(value.is_some()));
            reader.finish().unwrap();
        }
        assert_eq!(Reader::new(&[2]).flag(), Err(DecodeError::Noncanonical));
        assert_eq!(
            Reader::new(&[2, 0]).option_u64(),
            Err(DecodeError::Noncanonical)
        );
    }

    /// A count the input cannot hold is refused before anything is read.
    #[test]
    fn a_count_past_the_input_is_refused() {
        let mut bytes = encoded(5);
        bytes.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(Reader::new(&bytes).bytes(), Err(DecodeError::Short));
        let mut huge = encoded(u64::MAX);
        huge.push(0);
        assert_eq!(Reader::new(&huge).count(32), Err(DecodeError::Short));
    }
}
