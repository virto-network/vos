use crate::{Author, Cid, Hasher, Store};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::marker::PhantomData;

/// The rows an [`Apply`] reads and writes: the replica's store under the
/// writes of the batch being applied. A read sees the batch's own earlier
/// writes; the writes reach the store in the batch's one commit, or not at
/// all.
pub trait Rows {
    /// The row `key`.
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>>;
    /// Set the row `key`, or delete it (`None`).
    fn write(&mut self, key: &[u8], value: Option<&[u8]>);
}

/// A node being applied: its identity, its author's position, and its
/// operations. An operation's stable id is the node's (author, seq) and
/// the operation's index in `ops`.
pub struct Event<'a, H: Hasher, O> {
    /// The node's CID.
    pub cid: &'a Cid<H>,
    /// Its author.
    pub author: &'a Author,
    /// Its author's sequence number.
    pub seq: u64,
    /// Its parents.
    pub parents: &'a BTreeSet<Cid<H>>,
    /// Its operations.
    pub ops: &'a O,
}

/// The CRDT a scope's nodes apply to: storage-backed, writing only
/// through [`Rows`].
///
/// Each node is applied exactly once, after all its parents, local nodes
/// included. Concurrent nodes arrive in any order, so the result must not
/// depend on it: that, and keeping nothing outside the rows, is the
/// implementation's contract. Equivocating nodes are applied too; they
/// are filtered when read, by the replica's
/// [`equivocations`](crate::Replica::equivocations).
///
/// An error aborts the whole batch: nothing it applied is committed.
pub trait Apply<H: Hasher, O> {
    /// Why applying failed.
    type Error;
    /// Apply one node.
    fn apply(&mut self, event: Event<'_, H, O>, rows: &mut dyn Rows) -> Result<(), Self::Error>;
}

impl<H: Hasher, O, F: FnMut(Event<'_, H, O>, &mut dyn Rows)> Apply<H, O> for F {
    type Error = core::convert::Infallible;
    fn apply(&mut self, event: Event<'_, H, O>, rows: &mut dyn Rows) -> Result<(), Self::Error> {
        self(event, rows);
        Ok(())
    }
}

/// Rows over a store, or over nothing (a rebuild), under a batch's
/// writes. A read the store fails is kept, and fails the batch.
pub(crate) struct Overlay<'a, H: Hasher, S: Store<H>> {
    pub(crate) store: Option<&'a S>,
    pub(crate) written: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    pub(crate) error: Option<S::Error>,
    pub(crate) hasher: PhantomData<H>,
}

impl<'a, H: Hasher, S: Store<H>> Overlay<'a, H, S> {
    pub(crate) fn new(store: Option<&'a S>) -> Self {
        Self {
            store,
            written: BTreeMap::new(),
            error: None,
            hasher: PhantomData,
        }
    }
}

impl<H: Hasher, S: Store<H>> Rows for Overlay<'_, H, S> {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(value) = self.written.get(key) {
            return value.clone();
        }
        match self.store?.row(key) {
            Ok(value) => value,
            Err(error) => {
                self.error.get_or_insert(error);
                None
            }
        }
    }

    fn write(&mut self, key: &[u8], value: Option<&[u8]>) {
        self.written.insert(key.to_vec(), value.map(<[u8]>::to_vec));
    }
}
