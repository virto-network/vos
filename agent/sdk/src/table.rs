//! Tables: an instance's rows under a tag derived from the field's name.

use alloc::vec::Vec;
use core::marker::PhantomData;

use vos_wire::abi::{cap, code};
use vos_wire::{Decode, Encode};

use crate::host;

/// An order-preserving key encoding: the encodings of two keys compare as
/// the keys do, so scans run in key order.
pub trait TableKey: Sized {
    fn encode_key(&self, out: &mut Vec<u8>);
    /// Decode from the whole of `bytes`.
    fn decode_key(bytes: &[u8]) -> Option<Self>;
}

macro_rules! unsigned_key {
    ($($ty:ty),*) => {$(
        impl TableKey for $ty {
            fn encode_key(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.to_be_bytes());
            }
            fn decode_key(bytes: &[u8]) -> Option<Self> {
                Some(<$ty>::from_be_bytes(bytes.try_into().ok()?))
            }
        }
    )*};
}

unsigned_key!(u8, u16, u32, u64, u128);

impl<const N: usize> TableKey for [u8; N] {
    fn encode_key(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
    fn decode_key(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok()
    }
}

/// Raw bytes. Only as a whole key or the last part of a tuple: its length
/// is not encoded.
impl TableKey for Vec<u8> {
    fn encode_key(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
    fn decode_key(bytes: &[u8]) -> Option<Self> {
        Some(bytes.to_vec())
    }
}

impl TableKey for alloc::string::String {
    fn encode_key(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }
    fn decode_key(bytes: &[u8]) -> Option<Self> {
        alloc::string::String::from_utf8(bytes.to_vec()).ok()
    }
}

/// A fixed-width part followed by any part.
pub trait FixedKey: TableKey {
    const WIDTH: usize;
}

macro_rules! fixed {
    ($($ty:ty),*) => {$(
        impl FixedKey for $ty {
            const WIDTH: usize = core::mem::size_of::<$ty>();
        }
    )*};
}

fixed!(u8, u16, u32, u64, u128);

impl<const N: usize> FixedKey for [u8; N] {
    const WIDTH: usize = N;
}

impl<A: FixedKey, B: TableKey> TableKey for (A, B) {
    fn encode_key(&self, out: &mut Vec<u8>) {
        self.0.encode_key(out);
        self.1.encode_key(out);
    }
    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (a, b) = bytes.split_at_checked(A::WIDTH)?;
        Some((A::decode_key(a)?, B::decode_key(b)?))
    }
}

/// The tag of a table field: the first four bytes, big-endian, of
/// BLAKE2b-256 over `vos/table/` and the field's name. The `#[actor]`
/// macro computes it at build time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tag(pub u32);

/// A handle on rows of `K` to `V`. It holds no rows: each operation goes
/// to the agent, so memory follows the rows touched.
pub struct Table<K, V> {
    tag: Tag,
    _rows: PhantomData<fn(K) -> V>,
}

/// An unbound handle, until the actor's state binds it to its tag. A
/// field's initial value in `new()`.
impl<K, V> Default for Table<K, V> {
    fn default() -> Self {
        Self {
            tag: Tag(0),
            _rows: PhantomData,
        }
    }
}

impl<K: TableKey, V: Encode + Decode> Table<K, V> {
    pub const fn new(tag: Tag) -> Self {
        Self {
            tag,
            _rows: PhantomData,
        }
    }

    fn prefix(&self) -> Vec<u8> {
        let mut prefix = Vec::with_capacity(5);
        prefix.push(0x01);
        prefix.extend_from_slice(&self.tag.0.to_be_bytes());
        prefix
    }

    fn key(&self, key: &K) -> Vec<u8> {
        let mut bytes = self.prefix();
        key.encode_key(&mut bytes);
        bytes
    }

    /// The row under `key`. A row that does not decode reads as absent.
    pub fn get(&self, key: &K) -> Option<V> {
        let bytes = host::get(&self.key(key))?;
        V::decode(&bytes).ok().map(|(value, _)| value)
    }

    pub fn contains(&self, key: &K) -> bool {
        host::get(&self.key(key)).is_some()
    }

    pub fn insert(&mut self, key: &K, value: &V) {
        host::put(&self.key(key), &value.encode());
    }

    pub fn remove(&mut self, key: &K) {
        host::delete(&self.key(key));
    }

    /// Rows in key order, starting after `after` when given.
    pub fn iter(&self, after: Option<&K>) -> Rows<'_, K, V> {
        let prefix = self.prefix();
        let cursor = after.map(|key| self.key(key)).unwrap_or_default();
        Rows {
            _table: PhantomData,
            prefix,
            cursor,
            buffer: Vec::new(),
            at: 0,
            done: false,
        }
    }
}

/// Rows of a [`Table`], fetched from the agent a buffer at a time.
pub struct Rows<'a, K, V> {
    _table: PhantomData<&'a Table<K, V>>,
    prefix: Vec<u8>,
    cursor: Vec<u8>,
    buffer: Vec<u8>,
    at: usize,
    done: bool,
}

impl<K: TableKey, V: Encode + Decode> Rows<'_, K, V> {
    /// Fetch the next rows into the reused buffer, growing it up to
    /// [`cap::SCAN`], which always holds one row.
    fn refill(&mut self) {
        let mut capacity = self.buffer.capacity().max(4096);
        loop {
            self.buffer.clear();
            self.buffer.resize(capacity, 0);
            let written = host::scan(&self.prefix, &self.cursor, &mut self.buffer);
            if written != code::FULL {
                self.buffer.truncate(written as usize);
                break;
            }
            assert!(capacity < cap::SCAN, "a row larger than a scan");
            capacity = (capacity * 2).min(cap::SCAN);
        }
        self.done = self.buffer.is_empty();
        self.at = 0;
    }

    fn next_row(&mut self) -> Option<(Vec<u8>, Vec<u8>)> {
        let rest = self.buffer.get(self.at..)?;
        let (key, used) = Vec::<u8>::decode(rest).ok()?;
        let (value, more) = Vec::<u8>::decode(&rest[used..]).ok()?;
        self.at += used + more;
        Some((key, value))
    }
}

impl<K: TableKey, V: Encode + Decode> Iterator for Rows<'_, K, V> {
    type Item = (K, V);

    /// The next row. A row that does not decode traps: state the actor
    /// cannot read is a fault, not a row to skip.
    fn next(&mut self) -> Option<(K, V)> {
        if self.at >= self.buffer.len() {
            if self.done {
                return None;
            }
            self.refill();
            if self.done {
                return None;
            }
        }
        let (key, value) = self.next_row()?;
        self.cursor.clone_from(&key);
        let row_key = key
            .get(self.prefix.len()..)
            .expect("a key under the prefix");
        let key = K::decode_key(row_key).expect("an undecodable table key");
        let (value, _) = V::decode(&value).expect("an undecodable table row");
        Some((key, value))
    }
}
