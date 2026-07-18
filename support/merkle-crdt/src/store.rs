use crate::{Cid, DagNode, Hasher};
use alloc::collections::BTreeMap;
use core::fmt::Debug;

/// Abstract storage backend for DAG nodes.
///
/// This corresponds to the *DAG-Syncer* component from the paper (Definition 1):
/// a content-addressed store that maps CIDs to nodes. Implementations can back this
/// with in-memory maps, databases, IPFS, or any content-addressed storage system.
pub trait Store<H: Hasher, P> {
    /// The error type for storage operations.
    type Error: Debug;

    /// Retrieve a node by its content identifier.
    fn get(&self, cid: &Cid<H>) -> Result<Option<DagNode<H, P>>, Self::Error>;

    /// Store a node under the given CID.
    fn put(&mut self, cid: Cid<H>, node: DagNode<H, P>) -> Result<(), Self::Error>;

    /// Store a causally ordered batch. Durable stores should override this
    /// with one transaction. The default may leave an unreachable prefix on
    /// failure; callers must not publish roots or materialized state until the
    /// whole batch succeeds, making retry safe.
    fn put_batch(
        &mut self,
        nodes: alloc::vec::Vec<(Cid<H>, DagNode<H, P>)>,
    ) -> Result<(), Self::Error> {
        for (cid, node) in nodes {
            self.put(cid, node)?;
        }
        Ok(())
    }

    /// Check whether a CID exists without fetching the full node.
    ///
    /// This is an important optimization for DAG inclusion checks during merge
    /// (see paper Section VI-B).
    fn contains(&self, cid: &Cid<H>) -> Result<bool, Self::Error>;
}

/// In-memory store backed by a `BTreeMap`.
///
/// Useful for testing, examples, and lightweight applications.
/// Requires `P: Clone` since nodes are cloned on retrieval.
pub struct MemStore<H: Hasher, P>(BTreeMap<Cid<H>, DagNode<H, P>>);

impl<H: Hasher, P> Default for MemStore<H, P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: Hasher, P> MemStore<H, P> {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Number of nodes in the store.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<H: Hasher, P: Clone> Store<H, P> for MemStore<H, P> {
    type Error = core::convert::Infallible;

    fn get(&self, cid: &Cid<H>) -> Result<Option<DagNode<H, P>>, Self::Error> {
        Ok(self.0.get(cid).cloned())
    }

    fn put(&mut self, cid: Cid<H>, node: DagNode<H, P>) -> Result<(), Self::Error> {
        self.0.insert(cid, node);
        Ok(())
    }

    fn contains(&self, cid: &Cid<H>) -> Result<bool, Self::Error> {
        Ok(self.0.contains_key(cid))
    }
}
