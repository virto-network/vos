//! Anti-entropy synchronization algorithm for Merkle-CRDTs.
//!
//! This module implements the core sync algorithm from the paper (Definition 7):
//! given a remote root CID, walk the remote DAG, collect nodes missing locally,
//! verify their CIDs, and return them in causal order (oldest first) for processing.
//!
//! The algorithm exploits the properties of Merkle-DAGs:
//! - **Content addressing**: if a local CID matches a remote CID, the entire sub-DAG
//!   below it is identical and can be skipped.
//! - **Self-verification**: fetched nodes are verified by recomputing their CID.
//! - **Causal ordering**: post-order traversal gives events in happened-before order.

use crate::{Cid, DagNode, Encode, Hasher, Store};
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

/// Error type for sync operations involving two stores.
#[derive(Debug)]
pub enum SyncError<L, R> {
    /// Error from the local store.
    Local(L),
    /// Error from the remote store.
    Remote(R),
    /// A referenced node was not found in either store.
    MissingNode,
    /// A fetched node's recomputed CID didn't match the expected CID.
    InvalidCid,
}

impl<L: core::fmt::Display, R: core::fmt::Display> core::fmt::Display for SyncError<L, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SyncError::Local(e) => write!(f, "local store error: {e}"),
            SyncError::Remote(e) => write!(f, "remote store error: {e}"),
            SyncError::MissingNode => write!(f, "referenced node not found"),
            SyncError::InvalidCid => write!(f, "fetched node CID verification failed"),
        }
    }
}

#[cfg(feature = "std")]
impl<L: std::error::Error + 'static, R: std::error::Error + 'static> std::error::Error
    for SyncError<L, R>
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SyncError::Local(e) => Some(e),
            SyncError::Remote(e) => Some(e),
            _ => None,
        }
    }
}

/// Fetch nodes from a remote store that are missing in the local store,
/// returned in causal order (oldest/deepest first).
///
/// This is the core of the anti-entropy algorithm (paper Definition 7, steps 1-5).
/// It walks the remote DAG starting from `root`, skipping any sub-DAGs already
/// present locally, and returns the missing nodes topologically sorted so that
/// applying their payloads in order preserves causality.
///
/// Each fetched node is verified by recomputing its CID from the payload and children.
#[allow(clippy::type_complexity)]
pub fn fetch_missing<H, P, L, R>(
    root: &Cid<H>,
    local: &L,
    remote: &R,
) -> Result<Vec<(Cid<H>, DagNode<H, P>)>, SyncError<L::Error, R::Error>>
where
    H: Hasher,
    P: Encode + Clone,
    L: Store<H, P>,
    R: Store<H, P>,
{
    // Step 1: BFS from root, collecting missing nodes
    let mut missing: BTreeMap<Cid<H>, DagNode<H, P>> = BTreeMap::new();
    let mut queue = VecDeque::new();
    let mut visited = BTreeSet::new();

    queue.push_back(root.clone());

    while let Some(cid) = queue.pop_front() {
        if !visited.insert(cid.clone()) {
            continue;
        }
        // If local already has this node, skip it and its entire sub-DAG
        if local.contains(&cid).map_err(SyncError::Local)? {
            continue;
        }

        let node = remote
            .get(&cid)
            .map_err(SyncError::Remote)?
            .ok_or(SyncError::MissingNode)?;

        // Verify the node's CID
        if node.cid() != cid {
            return Err(SyncError::InvalidCid);
        }

        for child in &node.children {
            queue.push_back(child.clone());
        }

        missing.insert(cid, node);
    }

    if missing.is_empty() {
        return Ok(Vec::new());
    }

    // Step 2: Topological sort — oldest (leaves) first, newest (roots) last.
    // We want: if A references B as a child, B comes before A.
    // This is a reverse topological sort using out-degree (Kahn's algorithm).
    Ok(topological_sort(missing))
}

/// Topologically sort DAG nodes so children (older events) come before parents (newer events).
pub(crate) fn topological_sort<H: Hasher, P>(
    mut nodes: BTreeMap<Cid<H>, DagNode<H, P>>,
) -> Vec<(Cid<H>, DagNode<H, P>)> {
    let cid_set: BTreeSet<Cid<H>> = nodes.keys().cloned().collect();

    // out_degree: for each node, count children that are also in the missing set
    let mut out_degree: BTreeMap<Cid<H>, usize> = BTreeMap::new();
    // reverse edges: child → list of parents in the missing set
    let mut parents_of: BTreeMap<Cid<H>, Vec<Cid<H>>> = BTreeMap::new();

    for (cid, node) in &nodes {
        let out = node.children.iter().filter(|c| cid_set.contains(c)).count();
        out_degree.insert(cid.clone(), out);
        for child in &node.children {
            if cid_set.contains(child) {
                parents_of
                    .entry(child.clone())
                    .or_default()
                    .push(cid.clone());
            }
        }
    }

    let mut result = Vec::with_capacity(nodes.len());

    // Start with nodes that have no children in the missing set (oldest / leaves)
    let mut queue: VecDeque<Cid<H>> = out_degree
        .iter()
        .filter(|(_, deg)| **deg == 0)
        .map(|(cid, _)| cid.clone())
        .collect();

    while let Some(cid) = queue.pop_front() {
        // Decrease out-degree of each parent
        if let Some(pars) = parents_of.get(&cid) {
            for parent in pars {
                if let Some(deg) = out_degree.get_mut(parent) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(parent.clone());
                    }
                }
            }
        }
        let node = nodes.remove(&cid).unwrap();
        result.push((cid, node));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemStore, MerkleClock};

    struct TestHasher;
    impl crate::Hasher for TestHasher {
        type Output = [u8; 32];
        fn hash(data: &[u8]) -> [u8; 32] {
            let mut out = [0u8; 32];
            for (i, &b) in data.iter().enumerate() {
                out[i % 32] = out[i % 32].wrapping_add(b);
            }
            for i in 0..32 {
                out[i] = out[i].wrapping_mul(31).wrapping_add(out[(i + 1) % 32]);
            }
            out
        }
    }

    #[test]
    fn fetch_missing_from_diverged_replicas() {
        let mut clock_a = MerkleClock::<TestHasher>::new();
        let mut store_a: MemStore<TestHasher, u64> = MemStore::new();
        let mut clock_b = MerkleClock::<TestHasher>::new();
        let mut store_b: MemStore<TestHasher, u64> = MemStore::new();

        // Both start from the same base
        let base = clock_a.record(0u64, &mut store_a).unwrap();
        store_b
            .put(base.clone(), store_a.get(&base).unwrap().unwrap())
            .unwrap();
        clock_b.add_roots([base]);

        // Diverge
        let _a1 = clock_a.record(1u64, &mut store_a).unwrap();
        let b1 = clock_b.record(2u64, &mut store_b).unwrap();

        // A fetches from B
        let missing = fetch_missing(&b1, &store_a, &store_b).unwrap();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].0, b1);
    }

    #[test]
    fn fetch_missing_empty_when_already_synced() {
        let mut clock = MerkleClock::<TestHasher>::new();
        let mut store: MemStore<TestHasher, u64> = MemStore::new();

        let c1 = clock.record(1u64, &mut store).unwrap();
        let missing = fetch_missing(&c1, &store, &store).unwrap();
        assert!(missing.is_empty());
    }
}
