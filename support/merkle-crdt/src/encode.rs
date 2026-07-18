use alloc::{string::String, vec::Vec};

/// Deterministic serialization for CID computation.
///
/// Implementations must produce identical output for identical values.
/// Variable-length types should be length-prefixed to ensure unambiguous encoding
/// when composed (e.g. in tuples).
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

    /// Convenience: decode from a full byte slice.
    fn decode(buf: &[u8]) -> Option<Self> {
        let mut pos = 0;
        let value = Self::decode_from(buf, &mut pos)?;
        (pos == buf.len()).then_some(value)
    }
}

impl Encode for () {
    fn encode_to(&self, _buf: &mut Vec<u8>) {}
}

impl Encode for bool {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.push(*self as u8);
    }
}

macro_rules! impl_encode_int {
    ($($t:ty),+) => {
        $(impl Encode for $t {
            fn encode_to(&self, buf: &mut Vec<u8>) {
                buf.extend_from_slice(&self.to_le_bytes());
            }
        })+
    };
}

impl_encode_int!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

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

impl<T: Encode + Ord> Encode for alloc::collections::BTreeSet<T> {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.len() as u64).to_le_bytes());
        for item in self {
            item.encode_to(buf);
        }
    }
}

impl<K: Encode + Ord, V: Encode> Encode for alloc::collections::BTreeMap<K, V> {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.len() as u64).to_le_bytes());
        for (k, v) in self {
            k.encode_to(buf);
            v.encode_to(buf);
        }
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        match self {
            None => buf.push(0),
            Some(v) => {
                buf.push(1);
                v.encode_to(buf);
            }
        }
    }
}

macro_rules! impl_encode_tuple {
    ($($idx:tt $name:ident),+) => {
        impl<$($name: Encode),+> Encode for ($($name,)+) {
            fn encode_to(&self, buf: &mut Vec<u8>) {
                $(self.$idx.encode_to(buf);)+
            }
        }
    };
}

impl_encode_tuple!(0 A, 1 B);
impl_encode_tuple!(0 A, 1 B, 2 C);
impl_encode_tuple!(0 A, 1 B, 2 C, 3 D);

// ── Decode impls ────────────────────────────────────────────────────

fn take<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Option<&'a [u8]> {
    if *pos + n > buf.len() {
        return None;
    }
    let s = &buf[*pos..*pos + n];
    *pos += n;
    Some(s)
}

fn read_u64(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let b = take(buf, pos, 8)?;
    Some(u64::from_le_bytes(b.try_into().ok()?))
}

impl Decode for () {
    fn decode_from(_buf: &[u8], _pos: &mut usize) -> Option<Self> {
        Some(())
    }
}

impl Decode for bool {
    fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self> {
        Some(*take(buf, pos, 1)?.first()? != 0)
    }
}

macro_rules! impl_decode_int {
    ($($t:ty, $n:expr);+ $(;)?) => {
        $(impl Decode for $t {
            fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self> {
                let b = take(buf, pos, $n)?;
                Some(<$t>::from_le_bytes(b.try_into().ok()?))
            }
        })+
    };
}

impl_decode_int!(
    u8, 1; u16, 2; u32, 4; u64, 8; u128, 16;
    i8, 1; i16, 2; i32, 4; i64, 8; i128, 16;
);

impl<const N: usize> Decode for [u8; N] {
    fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self> {
        let b = take(buf, pos, N)?;
        b.try_into().ok()
    }
}

impl Decode for String {
    fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self> {
        let len = read_u64(buf, pos)? as usize;
        let b = take(buf, pos, len)?;
        core::str::from_utf8(b).ok().map(String::from)
    }
}

impl<T: Decode> Decode for Vec<T> {
    fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self> {
        let count = read_u64(buf, pos)? as usize;
        let mut v = Vec::with_capacity(count);
        for _ in 0..count {
            v.push(T::decode_from(buf, pos)?);
        }
        Some(v)
    }
}

impl<T: Decode + Ord> Decode for alloc::collections::BTreeSet<T> {
    fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self> {
        let count = read_u64(buf, pos)? as usize;
        let mut s = alloc::collections::BTreeSet::new();
        for _ in 0..count {
            if !s.insert(T::decode_from(buf, pos)?) {
                return None;
            }
        }
        Some(s)
    }
}

impl<T: Decode> Decode for Option<T> {
    fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self> {
        match *take(buf, pos, 1)?.first()? {
            0 => Some(None),
            _ => Some(Some(T::decode_from(buf, pos)?)),
        }
    }
}

macro_rules! impl_decode_tuple {
    ($($idx:tt $name:ident),+) => {
        impl<$($name: Decode),+> Decode for ($($name,)+) {
            fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self> {
                Some(($($name::decode_from(buf, pos)?,)+))
            }
        }
    };
}

impl_decode_tuple!(0 A, 1 B);
impl_decode_tuple!(0 A, 1 B, 2 C);
impl_decode_tuple!(0 A, 1 B, 2 C, 3 D);
