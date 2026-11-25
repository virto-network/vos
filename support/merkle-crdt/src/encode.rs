use alloc::{string::String, vec::Vec};

/// The most items a vector decodes: a longer one is refused.
pub const MAX_DECODE_ITEMS: usize = 1_000_000;

/// The most items a vector reserves room for before decoding them: a count
/// from the bytes reserves no more, the vector growing as its items decode.
const RESERVE_ITEMS: usize = 1024;

/// Deterministic serialization for CID computation.
///
/// Implementations must produce identical output for identical values, and
/// [`Decode`] must accept only that output: a node is refused unless its
/// bytes re-encode to themselves, so no second encoding of one node gets a
/// second CID.
///
/// Variable-length types should be length-prefixed to ensure unambiguous encoding
/// when composed (e.g. in tuples).
///
/// Encoding has no limit, decoding has: a vector of more than
/// [`MAX_DECODE_ITEMS`] items encodes and does not decode. A replica
/// refuses to record operations whose node does not decode
/// ([`Error::Unencodable`](crate::Error::Unencodable)).
pub trait Encode {
    /// Serialize this value into the buffer.
    fn encode_to(&self, buf: &mut Vec<u8>);

    /// Serialize this value into a new `Vec<u8>`.
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_to(&mut buf);
        buf
    }
}

/// Deserialize from bytes. Inverse of [`Encode`].
pub trait Decode: Sized {
    /// Decode from a byte cursor. Returns the value and advances `pos`.
    fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self>;

    /// Decode from a whole byte slice, refusing bytes left over.
    fn decode(buf: &[u8]) -> Option<Self> {
        let mut pos = 0;
        let value = Self::decode_from(buf, &mut pos)?;
        (pos == buf.len()).then_some(value)
    }
}

impl Encode for () {
    fn encode_to(&self, _buf: &mut Vec<u8>) {}
}

macro_rules! impl_int {
    ($($t:ty),+) => {
        $(impl Encode for $t {
            fn encode_to(&self, buf: &mut Vec<u8>) {
                buf.extend_from_slice(&self.to_le_bytes());
            }
        }

        impl Decode for $t {
            fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self> {
                let b = take(buf, pos, core::mem::size_of::<$t>())?;
                Some(<$t>::from_le_bytes(b.try_into().ok()?))
            }
        })+
    };
}

impl_int!(u8, u32, u64);

impl Encode for [u8] {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.len() as u64).to_le_bytes());
        buf.extend_from_slice(self);
    }
}

impl<const N: usize> Encode for [u8; N] {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self);
    }
}

impl Encode for str {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.as_bytes().encode_to(buf);
    }
}

impl Encode for String {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.as_str().encode_to(buf);
    }
}

impl<T: Encode> Encode for Vec<T> {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.len() as u64).to_le_bytes());
        for item in self {
            item.encode_to(buf);
        }
    }
}

impl<A: Encode, B: Encode> Encode for (A, B) {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.0.encode_to(buf);
        self.1.encode_to(buf);
    }
}

impl<A: Decode, B: Decode> Decode for (A, B) {
    fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self> {
        Some((A::decode_from(buf, pos)?, B::decode_from(buf, pos)?))
    }
}

fn take<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Option<&'a [u8]> {
    let end = pos.checked_add(n)?;
    let s = buf.get(*pos..end)?;
    *pos = end;
    Some(s)
}

fn read_len(buf: &[u8], pos: &mut usize) -> Option<usize> {
    usize::try_from(u64::decode_from(buf, pos)?).ok()
}

fn read_count(buf: &[u8], pos: &mut usize) -> Option<usize> {
    let count = read_len(buf, pos)?;
    (count <= MAX_DECODE_ITEMS).then_some(count)
}

impl Decode for () {
    fn decode_from(_buf: &[u8], _pos: &mut usize) -> Option<Self> {
        Some(())
    }
}

impl<const N: usize> Decode for [u8; N] {
    fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self> {
        let b = take(buf, pos, N)?;
        b.try_into().ok()
    }
}

impl Decode for String {
    fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self> {
        let len = read_len(buf, pos)?;
        let b = take(buf, pos, len)?;
        core::str::from_utf8(b).ok().map(String::from)
    }
}

impl<T: Decode> Decode for Vec<T> {
    fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self> {
        let count = read_count(buf, pos)?;
        let mut v = Vec::with_capacity(count.min(RESERVE_ITEMS));
        for _ in 0..count {
            v.push(T::decode_from(buf, pos)?);
        }
        Some(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_overflow_is_rejected_without_panicking() {
        let mut pos = usize::MAX;
        assert_eq!(take(&[], &mut pos, 1), None);
        assert_eq!(pos, usize::MAX);
    }

    #[test]
    fn adversarial_string_length_is_rejected_without_panicking() {
        assert_eq!(String::decode(&u64::MAX.to_le_bytes()), None);
    }

    #[test]
    fn adversarial_vector_length_is_rejected_before_allocation() {
        assert_eq!(Vec::<u8>::decode(&u64::MAX.to_le_bytes()), None);
        assert_eq!(
            Vec::<()>::decode(&((MAX_DECODE_ITEMS as u64) + 1).to_le_bytes()),
            None
        );
    }
}
