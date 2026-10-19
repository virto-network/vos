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
            let width = 8 - value.leading_zeros() as usize / 8;
            out.push((((width - 4) as u8) << 2) | 3);
            out.extend_from_slice(&value.to_le_bytes()[..width]);
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
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    /// A byte.
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    /// A little-endian `u32`.
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    /// A little-endian `u64`.
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.array()?))
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
            _ => {
                let width = usize::from(first >> 2) + 4;
                if width > 8 {
                    return Err(DecodeError::Noncanonical);
                }
                let mut bytes = [0u8; 8];
                bytes[..width].copy_from_slice(self.take(width)?);
                let value = u64::from_le_bytes(bytes);
                // The big-integer mode only past 2^30, and in its fewest bytes.
                let least = (1u64 << (8 * (width - 1))).max(0x4000_0000);
                (value, least)
            }
        };
        if value < least {
            return Err(DecodeError::Noncanonical);
        }
        Ok(value)
    }

    /// A count of items at least `item` bytes each, which the input holds.
    pub fn count(&mut self, item: usize) -> Result<usize, DecodeError> {
        let count = self.compact()?;
        let left = (self.bytes.len() - self.at) as u64;
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
