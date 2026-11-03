//! Merge fields (`core-model.md` §9.4): CRDTs a `#[msg(merge)]` handler
//! writes on a device and every device that applies its operation writes
//! alike, stored per author, and read filtered by a query.
//!
//! Each holds no rows: each operation goes to the agent, which keeps one
//! entry an element or key and author ([`vos_wire::merge`]) and reads the
//! latest entry among the authors not cut off, an author that equivocated
//! or that the device set removed past its frontier. A merge handler only
//! writes them, and a query only reads them: a merge handler's effects
//! are its operation's alone, whatever the device has applied before.
//!
//! - [`GSet`]: a grow-only set; an element is in it once an admitted
//!   author added it.
//! - [`Set`]: an add/remove set; an element is in it when its latest
//!   admitted add or remove, by the operations' Lamport clocks and then
//!   their authors, is an add. Concurrent ones resolve so on every device.
//! - [`Map`]: last-writer-wins per key and author: a key's value is its
//!   latest admitted write's, by Lamport clock then author; a removal is a
//!   write of no value.
//!
//! Elements and keys are keyed as a table's ([`TableKey`]), under the
//! field's transform ([`Hashed`] by default, or [`crate::table::Ordered`]),
//! which also orders iteration.

use core::marker::PhantomData;

use vos_wire::abi::{Keep, Rows};
use vos_wire::{Decode, Encode};

use crate::host;
use crate::table::{Bind, DefaultTransform, Iter, KeyTransform, TableKey, Tag, encoded};

/// The rows of a merge field of tag `tag`, kept as `keep` says.
const fn rows<T: KeyTransform>(tag: Tag, keep: Keep) -> Rows {
    Rows::Merge {
        tag: tag.0,
        transform: T::TRANSFORM,
        keep,
    }
}

macro_rules! merge_field {
    ($(#[$meta:meta])* $name:ident<$($param:ident),*>) => {
        $(#[$meta])*
        pub struct $name<$($param,)* X = DefaultTransform> {
            tag: Tag,
            _rows: PhantomData<fn($($param,)* X)>,
        }

        /// An unbound handle, until the actor's state binds it to its tag.
        /// A field's initial value in `new()`.
        impl<$($param,)* X: KeyTransform> Default for $name<$($param,)* X> {
            fn default() -> Self {
                Self::bound(Tag(0))
            }
        }

        impl<$($param,)* X: KeyTransform> Bind for $name<$($param,)* X> {
            fn bound(tag: Tag) -> Self {
                Self {
                    tag,
                    _rows: PhantomData,
                }
            }
        }
    };
}

merge_field!(
    /// A grow-only set of `T`: elements are added, never removed.
    GSet<T>
);

merge_field!(
    /// An add/remove set of `T`: an element's latest admitted add or
    /// removal decides.
    Set<T>
);

merge_field!(
    /// A map of `K` to `V`, last-writer-wins per key: a key's latest
    /// admitted write decides.
    Map<K, V>
);

/// The elements of a set, in its transform's order.
pub struct Elements<T>(Iter<T, ()>);

impl<T: TableKey> Iterator for Elements<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        self.0.next().map(|(element, ())| element)
    }
}

impl<T: TableKey, X: KeyTransform> GSet<T, X> {
    fn rows(&self) -> Rows {
        rows::<X>(self.tag, Keep::Earliest)
    }

    /// Add `element`: in a merge handler.
    pub fn insert(&mut self, element: &T) {
        host::put(self.rows(), &encoded(element), &[]);
    }

    /// Whether `element` is in the set: in a query.
    pub fn contains(&self, element: &T) -> bool {
        host::get(self.rows(), &encoded(element)).is_some()
    }

    /// The elements, after `after` when given: in a query.
    pub fn iter(&self, after: Option<&T>) -> Elements<T> {
        Elements(Iter::new(self.rows(), after))
    }
}

impl<T: TableKey, X: KeyTransform> Set<T, X> {
    fn rows(&self) -> Rows {
        rows::<X>(self.tag, Keep::Latest)
    }

    /// Add `element`: in a merge handler.
    pub fn insert(&mut self, element: &T) {
        host::put(self.rows(), &encoded(element), &[]);
    }

    /// Remove `element`: in a merge handler.
    pub fn remove(&mut self, element: &T) {
        host::delete(self.rows(), &encoded(element));
    }

    /// Whether `element` is in the set: in a query.
    pub fn contains(&self, element: &T) -> bool {
        host::get(self.rows(), &encoded(element)).is_some()
    }

    /// The elements, after `after` when given: in a query.
    pub fn iter(&self, after: Option<&T>) -> Elements<T> {
        Elements(Iter::new(self.rows(), after))
    }
}

impl<K: TableKey, V: Encode + Decode, X: KeyTransform> Map<K, V, X> {
    fn rows(&self) -> Rows {
        rows::<X>(self.tag, Keep::Latest)
    }

    /// Write `value` under `key`: in a merge handler.
    pub fn insert(&mut self, key: &K, value: &V) {
        host::put(self.rows(), &encoded(key), &value.encode());
    }

    /// Remove `key`'s value: in a merge handler.
    pub fn remove(&mut self, key: &K) {
        host::delete(self.rows(), &encoded(key));
    }

    /// `key`'s value: in a query. A value that does not decode reads as
    /// absent.
    pub fn get(&self, key: &K) -> Option<V> {
        let bytes = host::get(self.rows(), &encoded(key))?;
        V::decode(&bytes).ok().map(|(value, _)| value)
    }

    /// Whether `key` has a value: in a query.
    pub fn contains(&self, key: &K) -> bool {
        host::get(self.rows(), &encoded(key)).is_some()
    }

    /// The keys with values, and their values, after `after` when given:
    /// in a query.
    pub fn iter(&self, after: Option<&K>) -> Iter<K, V> {
        Iter::new(self.rows(), after)
    }
}
