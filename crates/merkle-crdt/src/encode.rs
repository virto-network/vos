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
