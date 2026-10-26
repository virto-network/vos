//! Tables and committed maps: an instance's rows under a tag derived from
//! the field's name, each keyed under the table's transform.
//!
//! A table chooses its key transform by its third type parameter,
//! [`DefaultTransform`] when it names none: [`Hashed`] iterates in hash
//! order and keeps a committed map's paths short whatever keys clients
//! choose; [`Ordered`] iterates in key order, for keys of at most
//! [`cap::ORDERED_KEY`] bytes encoded.

use alloc::vec::Vec;
use core::marker::PhantomData;

use vos_wire::abi::{Rows, cap, code};
use vos_wire::keys;
use vos_wire::{Decode, Encode};

use crate::host;

/// A key transform a table chooses.
pub trait KeyTransform {
    const TRANSFORM: keys::Transform;
}

/// Rows keyed `H128(key) ‖ escape(key)`: they iterate in hash order, and a
/// committed map's paths stay about log₂ n deep whatever keys clients
/// choose.
pub struct Hashed;

/// Rows keyed by the key itself: they iterate in key order, from any key.
/// Encoded keys are at most [`cap::ORDERED_KEY`] bytes; a longer one fails
/// the step.
pub struct Ordered;

impl KeyTransform for Hashed {
    const TRANSFORM: keys::Transform = keys::Transform::Hashed;
}

impl KeyTransform for Ordered {
    const TRANSFORM: keys::Transform = keys::Transform::Ordered;
}

/// The transform of a table or committed map that names none.
pub type DefaultTransform = Hashed;

/// A key encoding. It preserves order: the encodings of two keys compare
/// as the keys do, so an ordered table scans in key order.
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

/// A handle's binding to its tag: `#[actor]` binds each table and
/// committed map field when it loads the state.
pub trait Bind {
    fn bound(tag: Tag) -> Self;
}

/// Rows of `K` to `V`, reached through the agent a row at a time.
macro_rules! rows_handle {
    ($(#[$meta:meta])* $name:ident, $rows:ident) => {
        $(#[$meta])*
        pub struct $name<K, V, T = DefaultTransform> {
            tag: Tag,
            _rows: PhantomData<fn(K, T) -> V>,
        }

        /// An unbound handle, until the actor's state binds it to its tag.
        /// A field's initial value in `new()`.
        impl<K, V, T: KeyTransform> Default for $name<K, V, T> {
            fn default() -> Self {
                Self::new(Tag(0))
            }
        }

        impl<K, V, T: KeyTransform> Bind for $name<K, V, T> {
            fn bound(tag: Tag) -> Self {
                Self::new(tag)
            }
        }

        impl<K, V, T: KeyTransform> $name<K, V, T> {
            pub const fn new(tag: Tag) -> Self {
                Self {
                    tag,
                    _rows: PhantomData,
                }
            }

            /// The rows the agent reaches for this handle.
            pub const fn rows(&self) -> Rows {
                Rows::$rows {
                    tag: self.tag.0,
                    transform: T::TRANSFORM,
                }
            }
        }

        impl<K: TableKey, V: Encode + Decode, T: KeyTransform> $name<K, V, T> {
            /// The row under `key`. A row that does not decode reads as
            /// absent.
            pub fn get(&self, key: &K) -> Option<V> {
                let bytes = host::get(self.rows(), &encoded(key))?;
                V::decode(&bytes).ok().map(|(value, _)| value)
            }

            pub fn contains(&self, key: &K) -> bool {
                host::get(self.rows(), &encoded(key)).is_some()
            }

            pub fn insert(&mut self, key: &K, value: &V) {
                host::put(self.rows(), &encoded(key), &value.encode());
            }

            pub fn remove(&mut self, key: &K) {
                host::delete(self.rows(), &encoded(key));
            }

            /// The first row in the transform's order, fetched with a
            /// buffer as small as the row allows, where [`Self::iter`]
            /// fetches a buffer's worth of rows. A row that does not decode
            /// traps.
            pub fn first(&self) -> Option<(K, V)> {
                let mut capacity = 64;
                loop {
                    let mut buffer = alloc::vec![0u8; capacity];
                    let written = host::scan(self.rows(), None, &mut buffer);
                    if written == code::FULL {
                        assert!(capacity < cap::SCAN, "a row larger than a scan");
                        capacity = (capacity * 2).min(cap::SCAN);
                        continue;
                    }
                    let rest = buffer.get(..written as usize)?;
                    let (key, used) = Vec::<u8>::decode(rest).ok()?;
                    let (value, _) = Vec::<u8>::decode(&rest[used..]).expect("a row");
                    let key = K::decode_key(&key).expect("an undecodable table key");
                    let (value, _) = V::decode(&value).expect("an undecodable table row");
                    return Some((key, value));
                }
            }

            /// Rows in the transform's order (hash order for [`Hashed`],
            /// key order for [`Ordered`]), starting after `after` when
            /// given.
            pub fn iter(&self, after: Option<&K>) -> Iter<K, V> {
                Iter {
                    _rows: PhantomData,
                    rows: self.rows(),
                    cursor: after.map(encoded),
                    buffer: Vec::new(),
                    at: 0,
                    done: false,
                }
            }
        }
    };
}

rows_handle!(
    /// A handle on rows of `K` to `V`. It holds no rows: each operation goes
    /// to the agent, so memory follows the rows touched.
    Table,
    Table
);

rows_handle!(
    /// A table whose rows also commit to a Merkle root: the node builds the
    /// root after the step commits, and proves rows against it. A handler
    /// reads and writes it as a table, and never sees the root.
    CommittedMap,
    Committed
);

impl<K: TableKey, V, T: KeyTransform> CommittedMap<K, V, T> {
    /// Its row under `key`, as a read at a window's cut names it
    /// ([`crate::context::AtCut::reads`]).
    pub fn read(&self, key: &K) -> Read {
        Read {
            rows: self.rows(),
            key: encoded(key),
        }
    }
}

/// A row a read at a window's cut names: a committed map's, by its raw key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Read {
    pub(crate) rows: Rows,
    pub(crate) key: Vec<u8>,
}

/// A committed map as an attestable `&self` method's view holds it: its
/// rows answered from the rows served at a window's cut, which the kernel's
/// prologue checked against the space's root
/// ([`crate::runtime::verify_served`]). A row the read named is its value
/// there, or absent; any other traps, as a read outside the set the
/// workflow named fails the attest. It neither iterates nor writes.
pub struct ServedMap<K, V, T = DefaultTransform> {
    tag: Tag,
    served: &'static vos_wire::served::Served,
    _rows: PhantomData<fn(K, T) -> V>,
}

impl<K, V, T: KeyTransform> ServedMap<K, V, T> {
    /// The map of tag `tag` over the rows `served`.
    pub fn bound(tag: Tag, served: &'static vos_wire::served::Served) -> Self {
        Self {
            tag,
            served,
            _rows: PhantomData,
        }
    }
}

impl<K: TableKey, V: Decode, T: KeyTransform> ServedMap<K, V, T> {
    /// The served row under `key`: its value at the cut, or `None` when it
    /// was absent there. A row that does not decode reads as absent, as a
    /// committed map's does; a key the read did not name traps.
    pub fn get(&self, key: &K) -> Option<V> {
        let bytes = self.held(key)?;
        V::decode(bytes).ok().map(|(value, _)| value)
    }

    /// Whether the row under `key` was present at the cut; a key the read
    /// did not name traps.
    pub fn contains(&self, key: &K) -> bool {
        self.held(key).is_some()
    }

    fn held(&self, key: &K) -> Option<&'static [u8]> {
        let served = self.served;
        let rows = Rows::Committed {
            tag: self.tag.0,
            transform: T::TRANSFORM,
        };
        let row = keys::row(served.instance, rows, &encoded(key)).expect("a row's key");
        let at = served
            .rows
            .binary_search_by(|(served, _)| served.as_slice().cmp(&row))
            .unwrap_or_else(|_| panic!("a read outside the rows served"));
        served.rows[at]
            .1
            .as_ref()
            .map(|(_, value)| value.as_slice())
    }
}

fn encoded<K: TableKey>(key: &K) -> Vec<u8> {
    let mut bytes = Vec::new();
    key.encode_key(&mut bytes);
    bytes
}

/// Rows of a table or committed map, fetched from the agent a buffer at a
/// time.
pub struct Iter<K, V> {
    _rows: PhantomData<fn() -> (K, V)>,
    rows: Rows,
    /// The key of the last row read, which the next fetch starts after.
    cursor: Option<Vec<u8>>,
    buffer: Vec<u8>,
    at: usize,
    done: bool,
}

impl<K: TableKey, V: Encode + Decode> Iter<K, V> {
    /// Fetch the next rows into the reused buffer, growing it up to
    /// [`cap::SCAN`], which always holds one row.
    fn refill(&mut self) {
        let mut capacity = self.buffer.capacity().max(4096);
        loop {
            self.buffer.clear();
            self.buffer.resize(capacity, 0);
            let written = host::scan(self.rows, self.cursor.as_deref(), &mut self.buffer);
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

impl<K: TableKey, V: Encode + Decode> Iterator for Iter<K, V> {
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
        let decoded = K::decode_key(&key).expect("an undecodable table key");
        self.cursor = Some(key);
        let (value, _) = V::decode(&value).expect("an undecodable table row");
        Some((decoded, value))
    }
}
