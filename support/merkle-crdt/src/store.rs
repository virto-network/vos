use crate::{Author, Cid, Hasher};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::fmt::Debug;

/// Where a replica keeps its scope: the applied nodes, the nodes held until
/// their parents arrive, the index of nodes by author and sequence number,
/// the heads, the cursor, the nodes not yet pushed, and the rows its
/// operations wrote. One replica a store: two replicas over one store each
/// write the store's state from their own memory.
///
/// Every change of one ingest or one local operation reaches the store as
/// one [`Changes`], which [`commit`](Store::commit) writes atomically: a
/// crash leaves the store before the batch or after it.
pub trait Store<H: Hasher> {
    /// The error type for storage operations.
    type Error: Debug;

    /// An applied node's bytes.
    fn node(&self, cid: &Cid<H>) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Whether a node is applied.
    fn contains(&self, cid: &Cid<H>) -> Result<bool, Self::Error>;

    /// A held node's bytes.
    fn held(&self, cid: &Cid<H>) -> Result<Option<Vec<u8>>, Self::Error>;

    /// An applied node `author` signed at `seq`, if there is one (any one,
    /// for an equivocation).
    fn authored(&self, author: &Author, seq: u64) -> Result<Option<Cid<H>>, Self::Error>;

    /// Whether `cid` is an applied node `author` signed at `seq`.
    fn is_authored(&self, author: &Author, seq: u64, cid: &Cid<H>) -> Result<bool, Self::Error>;

    /// A row the applied operations wrote.
    fn row(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

    /// What a replica keeps in memory, read once when it opens.
    fn load(&self) -> Result<Loaded<H>, Self::Error>;

    /// Write `changes`, all of them or none. After an error it is not
    /// known which until the store is opened again: a store may have
    /// written the batch before it failed (fjall's journal does), so a
    /// caller reopens before it retries an operation.
    fn commit(&mut self, changes: Changes<H>) -> Result<(), Self::Error>;
}

/// What a replica reads from its store when it opens.
pub struct Loaded<H: Hasher> {
    /// The applied nodes no applied node names as a parent, each with its
    /// author and sequence number.
    pub heads: BTreeMap<Cid<H>, (Author, u64)>,
    /// Each author's highest sequence number applied, and a node at it.
    pub latest: BTreeMap<Author, (u64, Cid<H>)>,
    /// The (author, sequence number) pairs with more than one applied node.
    pub equivocations: BTreeSet<(Author, u64)>,
    /// The last position ingested from a cursor.
    pub cursor: Option<u64>,
    /// The local nodes not yet pushed, by author and sequence number.
    pub outbox: BTreeMap<(Author, u64), Cid<H>>,
    /// The held nodes: their bytes are read one at a time when the replica
    /// opens.
    pub held: Vec<Cid<H>>,
}

impl<H: Hasher> Default for Loaded<H> {
    fn default() -> Self {
        Self {
            heads: BTreeMap::new(),
            latest: BTreeMap::new(),
            equivocations: BTreeSet::new(),
            cursor: None,
            outbox: BTreeMap::new(),
            held: Vec::new(),
        }
    }
}

/// An applied node as the store keeps it.
pub struct Applied<H: Hasher> {
    /// Its CID.
    pub cid: Cid<H>,
    /// Its author.
    pub author: Author,
    /// Its sequence number.
    pub seq: u64,
    /// Its bytes.
    pub bytes: Vec<u8>,
}

/// One batch of changes: what one ingest or one local operation writes.
pub struct Changes<H: Hasher> {
    /// Nodes applied, in causal order.
    pub applied: Vec<Applied<H>>,
    /// Nodes held until their parents arrive.
    pub held: Vec<(Cid<H>, Vec<u8>)>,
    /// Held nodes released: applied, refused or dropped.
    pub released: BTreeSet<Cid<H>>,
    /// Nodes that became heads, each with its author and sequence number.
    pub heads_added: BTreeMap<Cid<H>, (Author, u64)>,
    /// Heads the batch's nodes name, no longer heads.
    pub heads_removed: BTreeSet<Cid<H>>,
    /// Authors whose highest sequence number moved, with a node at it.
    pub latest: BTreeMap<Author, (u64, Cid<H>)>,
    /// Equivocations found.
    pub equivocations: BTreeSet<(Author, u64)>,
    /// The cursor after the batch, when it moved.
    pub cursor: Option<u64>,
    /// Local nodes to push, by author and sequence number.
    pub outbox: BTreeMap<(Author, u64), Cid<H>>,
    /// Local nodes pushed, by author and sequence number.
    pub pushed: Vec<(Author, u64)>,
    /// Rows written (`Some`) or deleted (`None`).
    pub rows: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl<H: Hasher> Default for Changes<H> {
    fn default() -> Self {
        Self {
            applied: Vec::new(),
            held: Vec::new(),
            released: BTreeSet::new(),
            heads_added: BTreeMap::new(),
            heads_removed: BTreeSet::new(),
            latest: BTreeMap::new(),
            equivocations: BTreeSet::new(),
            cursor: None,
            outbox: BTreeMap::new(),
            pushed: Vec::new(),
            rows: BTreeMap::new(),
        }
    }
}

impl<H: Hasher> Changes<H> {
    /// Whether the batch writes nothing.
    pub fn is_empty(&self) -> bool {
        self.applied.is_empty()
            && self.held.is_empty()
            && self.released.is_empty()
            && self.heads_added.is_empty()
            && self.heads_removed.is_empty()
            && self.latest.is_empty()
            && self.equivocations.is_empty()
            && self.cursor.is_none()
            && self.outbox.is_empty()
            && self.pushed.is_empty()
            && self.rows.is_empty()
    }
}

/// A store in memory: for tests, benchmarks and short-lived replicas.
pub struct MemStore<H: Hasher> {
    nodes: BTreeMap<Cid<H>, Vec<u8>>,
    held: BTreeMap<Cid<H>, Vec<u8>>,
    authored: BTreeMap<(Author, u64), BTreeSet<Cid<H>>>,
    loaded: Loaded<H>,
    rows: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl<H: Hasher> Default for MemStore<H> {
    fn default() -> Self {
        Self {
            nodes: BTreeMap::new(),
            held: BTreeMap::new(),
            authored: BTreeMap::new(),
            loaded: Loaded::default(),
            rows: BTreeMap::new(),
        }
    }
}

impl<H: Hasher> MemStore<H> {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of applied nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether no node is applied.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The rows the applied operations wrote.
    pub fn rows(&self) -> &BTreeMap<Vec<u8>, Vec<u8>> {
        &self.rows
    }

    /// The applied nodes' bytes, by CID.
    pub fn nodes(&self) -> &BTreeMap<Cid<H>, Vec<u8>> {
        &self.nodes
    }
}

impl<H: Hasher> Store<H> for MemStore<H> {
    type Error = core::convert::Infallible;

    fn node(&self, cid: &Cid<H>) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.nodes.get(cid).cloned())
    }

    fn contains(&self, cid: &Cid<H>) -> Result<bool, Self::Error> {
        Ok(self.nodes.contains_key(cid))
    }

    fn held(&self, cid: &Cid<H>) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.held.get(cid).cloned())
    }

    fn authored(&self, author: &Author, seq: u64) -> Result<Option<Cid<H>>, Self::Error> {
        Ok(self
            .authored
            .get(&(*author, seq))
            .and_then(|cids| cids.first().cloned()))
    }

    fn is_authored(&self, author: &Author, seq: u64, cid: &Cid<H>) -> Result<bool, Self::Error> {
        Ok(self
            .authored
            .get(&(*author, seq))
            .is_some_and(|cids| cids.contains(cid)))
    }

    fn row(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.rows.get(key).cloned())
    }

    fn load(&self) -> Result<Loaded<H>, Self::Error> {
        Ok(Loaded {
            heads: self.loaded.heads.clone(),
            latest: self.loaded.latest.clone(),
            equivocations: self.loaded.equivocations.clone(),
            cursor: self.loaded.cursor,
            outbox: self.loaded.outbox.clone(),
            held: self.held.keys().cloned().collect(),
        })
    }

    fn commit(&mut self, changes: Changes<H>) -> Result<(), Self::Error> {
        let loaded = &mut self.loaded;
        for node in changes.applied {
            self.authored
                .entry((node.author, node.seq))
                .or_default()
                .insert(node.cid.clone());
            self.nodes.insert(node.cid, node.bytes);
        }
        for cid in changes.released {
            self.held.remove(&cid);
        }
        self.held.extend(changes.held);
        for cid in changes.heads_removed {
            loaded.heads.remove(&cid);
        }
        loaded.heads.extend(changes.heads_added);
        loaded.latest.extend(changes.latest);
        loaded.equivocations.extend(changes.equivocations);
        if changes.cursor.is_some() {
            loaded.cursor = changes.cursor;
        }
        loaded.outbox.extend(changes.outbox);
        for pushed in changes.pushed {
            loaded.outbox.remove(&pushed);
        }
        for (key, value) in changes.rows {
            match value {
                Some(value) => self.rows.insert(key, value),
                None => self.rows.remove(&key),
            };
        }
        Ok(())
    }
}
