use crate::{Author, Cid, Error, Hasher, Node, Store};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::marker::PhantomData;

/// The longest row key a replica writes: fjall's limit.
pub const MAX_ROW_KEY: usize = 65_535;

/// The longest row value a replica writes: fjall's limit.
pub const MAX_ROW_VALUE: usize = u32::MAX as usize;

/// Whether a store takes a row with this key and value.
pub(crate) fn row_fits(key: &[u8], value: Option<&[u8]>) -> bool {
    !key.is_empty()
        && key.len() <= MAX_ROW_KEY
        && value.is_none_or(|value| value.len() <= MAX_ROW_VALUE)
}

/// The rows an [`Apply`] reads and writes: the replica's store under the
/// writes of the batch being applied. A read sees the batch's own earlier
/// writes; the writes reach the store in the batch's one commit, or not at
/// all.
pub trait Rows {
    /// The row `key`.
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>>;
    /// Set the row `key`, or delete it (`None`). A key is 1 to
    /// [`MAX_ROW_KEY`] bytes, a value at most [`MAX_ROW_VALUE`]: a write
    /// past either fails the batch with [`Error::Row`](crate::Error::Row),
    /// in every store. An [`Apply`] that makes keys from a peer's
    /// operations bounds them itself (a hash, or a refusal it keeps in its
    /// rows), or that peer's node fails every batch that brings it.
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
    /// Whether an applied node of its author already has its sequence
    /// number: it equivocates, and the CRDT's reads filter its author's
    /// chain from `seq` on, in the batch that applies it.
    pub equivocation: bool,
}

/// The CRDT a scope's nodes apply to: storage-backed, writing only
/// through [`Rows`].
///
/// Each node is applied exactly once, after all its parents, local nodes
/// included. Concurrent nodes arrive in any order, so the result must not
/// depend on it: that, and keeping nothing outside the rows, is the
/// implementation's contract. Equivocating nodes are applied too; they
/// are filtered when read, by the replica's
/// [`equivocations`](crate::Replica::equivocations), which the second of
/// two nodes at one number also tells its apply
/// ([`Event::equivocation`]), so the filter's rows commit with it.
///
/// An error aborts the whole batch: nothing it applied is committed, and a
/// feed's page that fails stays unread. An operation the implementation
/// cannot apply yet (a kind it does not know) is therefore kept in its own
/// rows and applied later, never returned as an error.
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

/// Rows over a store under a batch's writes. A read the store fails is
/// kept, and fails the batch; so does a write no store takes.
pub(crate) struct Overlay<'a, H: Hasher, S: Store<H>> {
    store: &'a S,
    written: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    error: Option<S::Error>,
    /// Whether a write was past a store's limits.
    unfit: bool,
    hasher: PhantomData<H>,
}

impl<'a, H: Hasher, S: Store<H>> Overlay<'a, H, S> {
    pub(crate) fn new(store: &'a S) -> Self {
        Self {
            store,
            written: BTreeMap::new(),
            error: None,
            unfit: false,
            hasher: PhantomData,
        }
    }

    /// Apply `node` to `crdt` through these rows. The store's error comes
    /// first, which the CRDT may have seen as a missing row, then a row no
    /// store takes (whose write the CRDT may have read back as missing),
    /// then the CRDT's.
    pub(crate) fn apply<O, A: Apply<H, O>>(
        &mut self,
        crdt: &mut A,
        cid: &Cid<H>,
        node: &Node<H, O>,
        equivocation: bool,
    ) -> Result<(), Error<S::Error, A::Error>> {
        let event = Event {
            cid,
            author: &node.author,
            seq: node.seq,
            parents: &node.parents,
            ops: &node.ops,
            equivocation,
        };
        let result = crdt.apply(event, self);
        if let Some(error) = self.error.take() {
            return Err(Error::Store(error));
        }
        if self.unfit {
            return Err(Error::Row);
        }
        result.map_err(Error::Apply)
    }

    /// The batch's writes.
    pub(crate) fn into_written(self) -> BTreeMap<Vec<u8>, Option<Vec<u8>>> {
        self.written
    }
}

impl<H: Hasher, S: Store<H>> Rows for Overlay<'_, H, S> {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(value) = self.written.get(key) {
            return value.clone();
        }
        match self.store.row(key) {
            Ok(value) => value,
            Err(error) => {
                self.error.get_or_insert(error);
                None
            }
        }
    }

    fn write(&mut self, key: &[u8], value: Option<&[u8]>) {
        if !row_fits(key, value) {
            self.unfit = true;
            return;
        }
        self.written.insert(key.to_vec(), value.map(<[u8]>::to_vec));
    }
}
