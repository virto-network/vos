use crate::{Cid, DagNode, Encode, Error, Hasher, Store};
use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;

/// A Merkle-Clock: a logical clock implemented as a Merkle-DAG.
///
/// Each node represents an event. New events are added as root nodes that point to all
/// previous roots, embedding causal history in the DAG structure. The clock's state is
/// fully described by its set of root CIDs.
///
/// Merkle-Clocks are themselves a state-based CRDT (a Grow-Only Set of immutable nodes).
/// Merging two clocks is the union of their node sets, with roots pruned to remove
/// any that are ancestors of others.
///
/// See paper Definitions 4 and 5.
pub struct MerkleClock<H: Hasher> {
    roots: BTreeSet<Cid<H>>,
}

impl<H: Hasher> Default for MerkleClock<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: Hasher> Clone for MerkleClock<H> {
    fn clone(&self) -> Self {
        Self {
            roots: self.roots.clone(),
        }
    }
}

impl<H: Hasher> MerkleClock<H> {
    /// Create an empty Merkle-Clock with no events.
    pub fn new() -> Self {
        Self {
            roots: BTreeSet::new(),
        }
    }

    /// The current root CIDs (heads of the DAG).
    ///
    /// A single root means all events are causally ordered.
    /// Multiple roots indicate concurrent events that haven't been consolidated.
    pub fn roots(&self) -> &BTreeSet<Cid<H>> {
        &self.roots
    }

    /// Record a new event. Creates a DAG node whose children are all current roots,
    /// then makes this new node the sole root.
    ///
    /// This implements the *Implementation Rule* from the paper (Section IV-B):
    /// every new event must reference all previous roots.
    pub fn record<P: Encode, S: Store<H, P>>(
        &mut self,
        payload: P,
        store: &mut S,
    ) -> Result<Cid<H>, Error<S::Error>> {
        // Do not take the current roots before durable recording succeeds. A
        // failed store write must leave the logical clock untouched.
        let children = self.roots.clone();
        let node = DagNode::new(payload, children);
        let cid = node.cid();
        store.put(cid.clone(), node)?;
        self.roots.clear();
        self.roots.insert(cid.clone());
        Ok(cid)
    }

    /// Add root CIDs without pruning. Use [`compact_roots`](Self::compact_roots)
    /// afterwards to remove roots that are ancestors of others.
    pub fn add_roots(&mut self, roots: impl IntoIterator<Item = Cid<H>>) {
        self.roots.extend(roots);
    }

    /// Merge remote roots into this clock, pruning any that are ancestors of others.
    ///
    /// This implements the join operation `M ⊔ N = M ∪ N` from the paper,
    /// followed by root compaction to keep only the "heads".
    pub fn merge<P: Encode + Clone, S: Store<H, P>>(
        &mut self,
        remote_roots: &BTreeSet<Cid<H>>,
        store: &S,
    ) -> Result<(), Error<S::Error>> {
        let mut staged = self.clone();
        staged.roots.extend(remote_roots.iter().cloned());
        staged.compact_roots::<P, S>(store)?;
        *self = staged;
        Ok(())
    }

    /// Remove roots that are ancestors of other roots.
    ///
    /// After merging, some roots may be subsumed by others (i.e., reachable
    /// as descendants from another root). This walks the DAG to prune them.
    pub fn compact_roots<P: Encode + Clone, S: Store<H, P>>(
        &mut self,
        store: &S,
    ) -> Result<(), Error<S::Error>> {
        if self.roots.len() <= 1 {
            return Ok(());
        }

        let candidates = self.roots.clone();
        let mut subsumed = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut stack: Vec<_> = candidates.iter().cloned().collect();
        let target_count = candidates.len();

        while let Some(cid) = stack.pop() {
            if !visited.insert(cid.clone()) {
                continue;
            }
            let node = store.get(&cid)?.ok_or(Error::MissingNode)?;
            if node.cid() != cid {
                return Err(Error::InvalidCid);
            }
            for child in &node.children {
                if candidates.contains(child) && subsumed.insert(child.clone()) {
                    // Early exit: found all but one
                    if subsumed.len() >= target_count - 1 {
                        self.roots = candidates.difference(&subsumed).cloned().collect();
                        return Ok(());
                    }
                }
                if !visited.contains(child) {
                    stack.push(child.clone());
                }
            }
        }

        self.roots = candidates.difference(&subsumed).cloned().collect();
        Ok(())
    }

    /// Walk the DAG from the given root, calling `visitor` for each node in
    /// depth-first post-order (oldest events first = causal order).
    pub fn walk<P, S, F>(
        &self,
        root: &Cid<H>,
        store: &S,
        mut visitor: F,
    ) -> Result<(), Error<S::Error>>
    where
        P: Encode + Clone,
        S: Store<H, P>,
        F: FnMut(&Cid<H>, &DagNode<H, P>),
    {
        let mut visited = BTreeSet::new();
        // None = enter (fetch + push children), Some(node) = exit (visit)
        #[allow(clippy::type_complexity)]
        let mut stack: Vec<(Cid<H>, Option<DagNode<H, P>>)> = vec![(root.clone(), None)];

        while let Some((cid, cached)) = stack.pop() {
            if let Some(node) = cached {
                visitor(&cid, &node);
                continue;
            }
            if !visited.insert(cid.clone()) {
                continue;
            }
            let node = store.get(&cid)?.ok_or(Error::MissingNode)?;
            if node.cid() != cid {
                return Err(Error::InvalidCid);
            }
            // LIFO post-order: push self first, then children in reverse so
            // every child exits before its parent.
            stack.push((cid, Some(node.clone())));
            for child in node.children.iter().rev() {
                if !visited.contains(child) {
                    stack.push((child.clone(), None));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemStore;

    struct TestHasher;
    impl crate::Hasher for TestHasher {
        type Output = [u8; 32];
        fn hash(data: &[u8]) -> [u8; 32] {
            // Simple non-cryptographic hash for testing
            let mut out = [0u8; 32];
            for (i, &b) in data.iter().enumerate() {
                out[i % 32] = out[i % 32].wrapping_add(b);
            }
            // Mix
            for i in 0..32 {
                out[i] = out[i].wrapping_mul(31).wrapping_add(out[(i + 1) % 32]);
            }
            out
        }
    }

    #[test]
    fn record_creates_single_root() {
        let mut clock = MerkleClock::<TestHasher>::new();
        let mut store = MemStore::new();

        let c1 = clock.record(1u64, &mut store).unwrap();
        assert_eq!(clock.roots().len(), 1);
        assert!(clock.roots().contains(&c1));

        let c2 = clock.record(2u64, &mut store).unwrap();
        assert_eq!(clock.roots().len(), 1);
        assert!(clock.roots().contains(&c2));
        assert!(!clock.roots().contains(&c1));

        // c2's children should include c1
        let node = store.get(&c2).unwrap().unwrap();
        assert!(node.children.contains(&c1));
    }

    #[test]
    fn merge_concurrent_clocks() {
        let mut clock_a = MerkleClock::<TestHasher>::new();
        let mut store_a = MemStore::new();
        let mut clock_b = MerkleClock::<TestHasher>::new();
        let mut store_b = MemStore::new();

        let _a1 = clock_a.record(10u64, &mut store_a).unwrap();
        let _b1 = clock_b.record(20u64, &mut store_b).unwrap();

        // After merge, should have 2 roots (concurrent events)
        clock_a.add_roots(clock_b.roots().iter().cloned());
        assert_eq!(clock_a.roots().len(), 2);

        // Recording a new event consolidates into 1 root
        let _a2 = clock_a.record(30u64, &mut store_a).unwrap();
        assert_eq!(clock_a.roots().len(), 1);
    }

    #[test]
    fn walk_visits_children_before_parents() {
        let mut clock = MerkleClock::<TestHasher>::new();
        let mut store = MemStore::new();
        let first = clock.record(1u64, &mut store).unwrap();
        let second = clock.record(2u64, &mut store).unwrap();
        let third = clock.record(3u64, &mut store).unwrap();
        let mut order = Vec::new();
        clock
            .walk(&third, &store, |cid, _| order.push(cid.clone()))
            .unwrap();
        assert_eq!(order, vec![first, second, third]);
    }
}
