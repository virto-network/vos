use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use crate::{Cid, DagNode, Encode, Error, Hasher, MerkleClock, Store};
use crate::sync::{self, SyncError};

/// Trait for CRDT payloads carried by Merkle-CRDT nodes.
///
/// Each node in the Merkle-DAG carries a payload that represents either a CRDT operation
/// (for operation-based CRDTs) or a state delta (for state-based CRDTs). The [`State`](Payload::State)
/// type is the materialized view produced by applying all operations in causal order.
///
/// # Operation-based CRDTs
///
/// For op-based CRDTs, the payload is an operation and `apply` applies it to the state.
/// The Merkle-Clock guarantees causal delivery, so operations are always applied in order.
///
/// # State-based CRDTs
///
/// For state-based CRDTs, set `State = Self` and implement `apply` as the merge/join.
pub trait Payload: Encode + Clone {
    /// The materialized state type.
    type State: Clone + Default;

    /// Apply this payload to the current state.
    fn apply(state: &mut Self::State, op: &Self);
}

/// A Merkle-CRDT replica: a Merkle-Clock with typed CRDT payloads and automatic state tracking.
///
/// This is the main high-level type. It combines a [`MerkleClock`], a [`Store`], and the
/// materialized CRDT state. Operations are recorded as DAG nodes, and syncing with other
/// replicas fetches missing nodes and applies their payloads in causal order.
///
/// See paper Definition 6 and the anti-entropy algorithm (Definition 7).
pub struct MerkleCrdt<H: Hasher, P: Payload, S: Store<H, P>> {
    clock: MerkleClock<H>,
    store: S,
    state: P::State,
}

impl<H: Hasher, P: Payload, S: Store<H, P> + Default> Default for MerkleCrdt<H, P, S> {
    fn default() -> Self {
        Self::new(S::default())
    }
}

impl<H: Hasher, P: Payload, S: Store<H, P>> MerkleCrdt<H, P, S> {
    /// Create a new replica with the given store and empty state.
    pub fn new(store: S) -> Self {
        Self {
            clock: MerkleClock::new(),
            store,
            state: P::State::default(),
        }
    }

    /// Apply a new operation, recording it as a DAG node and updating the local state.
    ///
    /// Returns the CID of the new node. Broadcast this CID to other replicas so they
    /// can sync (the *Broadcaster* component from the paper).
    pub fn apply(&mut self, op: P) -> Result<Cid<H>, Error<S::Error>> {
        P::apply(&mut self.state, &op);
        self.clock.record(op, &mut self.store)
    }

    /// Sync with a remote replica by fetching missing nodes from `remote_root` downward.
    ///
    /// Implements the anti-entropy algorithm (paper Definition 7):
    /// 1. Walk the remote DAG from `remote_root`
    /// 2. Collect nodes not present locally (set D)
    /// 3. If D is empty, no action needed (remote is already included locally)
    /// 4. Otherwise, apply payloads in causal order (oldest first) and merge roots
    pub fn sync<R: Store<H, P>>(
        &mut self,
        remote_root: &Cid<H>,
        remote: &R,
    ) -> Result<(), SyncError<S::Error, R::Error>> {
        let missing = sync::fetch_missing(remote_root, &self.store, remote)?;

        // Def 7 step 4: if D is empty, M_β ⊆ M_α — no action needed
        if missing.is_empty() {
            return Ok(());
        }

        // Def 7 steps 5-6: apply payloads in causal order
        for (cid, node) in missing {
            P::apply(&mut self.state, &node.payload);
            self.store.put(cid, node).map_err(SyncError::Local)?;
        }

        // Def 7 steps 7-8: merge roots (compact prunes subsumed ones)
        self.clock.add_roots([remote_root.clone()]);
        self.clock
            .compact_roots::<P, S>(&self.store)
            .map_err(|e| match e {
                Error::Store(e) => SyncError::Local(e),
                Error::MissingNode => SyncError::MissingNode,
            })?;
        Ok(())
    }

    /// The current materialized CRDT state.
    pub fn state(&self) -> &P::State {
        &self.state
    }

    /// The current root CIDs of the Merkle-Clock.
    pub fn roots(&self) -> &BTreeSet<Cid<H>> {
        self.clock.roots()
    }

    /// Reference to the underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Mutable reference to the underlying store.
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Reference to the underlying Merkle-Clock.
    pub fn clock(&self) -> &MerkleClock<H> {
        &self.clock
    }

    /// Rebuild the CRDT state by walking the entire DAG from all roots.
    ///
    /// Uses a single traversal with shared visited set to avoid double-applying
    /// operations on nodes reachable from multiple roots.
    /// Useful after loading a store from disk or when state may be inconsistent.
    pub fn rebuild_state(&mut self) -> Result<(), Error<S::Error>> {
        self.state = P::State::default();

        // Collect all reachable nodes from all roots (single pass, deduplicated)
        let mut nodes: BTreeMap<Cid<H>, DagNode<H, P>> = BTreeMap::new();
        let mut visited = BTreeSet::new();
        let mut stack: Vec<Cid<H>> = self.clock.roots().iter().cloned().collect();

        while let Some(cid) = stack.pop() {
            if !visited.insert(cid.clone()) {
                continue;
            }
            if let Some(node) = self.store.get(&cid)? {
                for child in &node.children {
                    if !visited.contains(child) {
                        stack.push(child.clone());
                    }
                }
                nodes.insert(cid, node);
            }
        }

        // Apply in causal order (oldest first)
        for (_cid, node) in sync::topological_sort(nodes) {
            P::apply(&mut self.state, &node.payload);
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

    /// A simple counter CRDT — each operation adds a value.
    /// Non-idempotent: applying the same op twice doubles the effect.
    /// This makes it a good test for the double-apply bug.
    #[derive(Clone, Debug)]
    struct CounterOp(i64);

    impl Encode for CounterOp {
        fn encode_to(&self, buf: &mut alloc::vec::Vec<u8>) {
            self.0.encode_to(buf);
        }
    }

    impl Payload for CounterOp {
        type State = i64;
        fn apply(state: &mut i64, op: &Self) {
            *state += op.0;
        }
    }

    type TestCrdt = MerkleCrdt<TestHasher, CounterOp, MemStore<TestHasher, CounterOp>>;

    #[test]
    fn rebuild_state_no_double_apply_with_shared_sub_dag() {
        // Two replicas diverge from a shared base, then we rebuild state
        // from the merged DAG. The shared base must only be counted once.
        let mut alice: TestCrdt = MerkleCrdt::default();
        let mut bob: TestCrdt = MerkleCrdt::default();

        // Shared base: both apply +10
        alice.apply(CounterOp(10)).unwrap();
        let alice_roots: Vec<_> = alice.roots().iter().cloned().collect();
        for root in alice_roots {
            bob.sync(&root, alice.store()).unwrap();
        }
        assert_eq!(*alice.state(), 10);
        assert_eq!(*bob.state(), 10);

        // Diverge: Alice +5, Bob +3
        alice.apply(CounterOp(5)).unwrap();
        bob.apply(CounterOp(3)).unwrap();

        // Sync both ways — now both have 2 roots sharing the base node
        let alice_roots: Vec<_> = alice.roots().iter().cloned().collect();
        for root in alice_roots {
            bob.sync(&root, alice.store()).unwrap();
        }
        let bob_roots: Vec<_> = bob.roots().iter().cloned().collect();
        for root in bob_roots {
            alice.sync(&root, bob.store()).unwrap();
        }

        // Both should be 10 + 5 + 3 = 18
        assert_eq!(*alice.state(), 18);
        assert_eq!(*bob.state(), 18);

        // Rebuild state from scratch — must also be 18, not more
        alice.rebuild_state().unwrap();
        assert_eq!(*alice.state(), 18, "rebuild_state double-applied operations!");
    }

    #[test]
    fn sync_idempotent() {
        let mut alice: TestCrdt = MerkleCrdt::default();
        let mut bob: TestCrdt = MerkleCrdt::default();

        alice.apply(CounterOp(7)).unwrap();
        let roots: Vec<_> = alice.roots().iter().cloned().collect();
        for root in &roots {
            bob.sync(root, alice.store()).unwrap();
        }
        assert_eq!(*bob.state(), 7);

        // Syncing again should be a no-op (Def 7 step 4: D is empty)
        for root in &roots {
            bob.sync(root, alice.store()).unwrap();
        }
        assert_eq!(*bob.state(), 7, "re-sync should be idempotent");
    }

    #[test]
    fn sync_already_included_does_nothing() {
        let mut alice: TestCrdt = MerkleCrdt::default();
        let mut bob: TestCrdt = MerkleCrdt::default();

        // Alice has two events
        alice.apply(CounterOp(1)).unwrap();
        alice.apply(CounterOp(2)).unwrap();

        // Bob syncs everything
        let roots: Vec<_> = alice.roots().iter().cloned().collect();
        for root in &roots {
            bob.sync(root, alice.store()).unwrap();
        }
        assert_eq!(*bob.state(), 3);

        // Bob adds more
        bob.apply(CounterOp(4)).unwrap();
        assert_eq!(*bob.state(), 7);

        // Syncing Alice's old root (which is now an ancestor of Bob's state)
        // should be a no-op — D is empty since Bob already has all of Alice's nodes
        let old_roots = roots;
        for root in &old_roots {
            bob.sync(root, alice.store()).unwrap();
        }
        assert_eq!(*bob.state(), 7, "syncing already-included root should be no-op");
    }
}
