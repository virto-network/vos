use crate::sync::{self, AcceptAll, NodeValidator, SyncError};
use crate::{Cid, DagNode, Encode, Error, Hasher, MerkleClock, Store};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

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
        let mut staged_state = self.state.clone();
        P::apply(&mut staged_state, &op);
        let cid = self.clock.record(op, &mut self.store)?;
        self.state = staged_state;
        Ok(cid)
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
        self.sync_validated(remote_root, remote, &AcceptAll)
    }

    /// Sync with explicit author/payload validation. Nodes are durably staged
    /// first; roots and materialized state activate together only after the
    /// complete ancestry is available and verified.
    pub fn sync_validated<R: Store<H, P>, V: NodeValidator<H, P>>(
        &mut self,
        remote_root: &Cid<H>,
        remote: &R,
        validator: &V,
    ) -> Result<(), SyncError<S::Error, R::Error>> {
        let missing = sync::fetch_missing(remote_root, &self.store, remote)?;
        if missing
            .iter()
            .any(|(cid, node)| !validator.validate(cid, node))
        {
            return Err(SyncError::InvalidAuthor);
        }

        // Store failures may leave an unreachable prefix for a backend using
        // Store::put_batch's default. Logical state is unchanged, and retry
        // safely finishes the ancestry. Transactional stores override the
        // method and commit this batch atomically.
        self.store.put_batch(missing).map_err(SyncError::Local)?;

        let mut staged_clock = self.clock.clone();
        staged_clock.add_roots([remote_root.clone()]);
        staged_clock
            .compact_roots::<P, S>(&self.store)
            .map_err(map_local_error)?;
        if !ancestry_is_valid::<H, P, S, V>(&staged_clock, &self.store, validator)
            .map_err(map_local_error)?
        {
            return Err(SyncError::InvalidAuthor);
        }
        let staged_state =
            materialize::<H, P, S>(&staged_clock, &self.store).map_err(map_local_error)?;

        self.clock = staged_clock;
        self.state = staged_state;
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
        let staged = materialize::<H, P, S>(&self.clock, &self.store)?;
        self.state = staged;
        Ok(())
    }

    /// Recover a replica from durably stored nodes plus its persisted roots.
    /// Activation fails if any ancestry is missing or content-addressed bytes
    /// do not verify.
    pub fn from_roots(
        store: S,
        roots: impl IntoIterator<Item = Cid<H>>,
    ) -> Result<Self, Error<S::Error>> {
        let mut clock = MerkleClock::new();
        clock.add_roots(roots);
        clock.compact_roots::<P, S>(&store)?;
        let state = materialize::<H, P, S>(&clock, &store)?;
        Ok(Self {
            clock,
            store,
            state,
        })
    }
}

fn map_local_error<L, R>(error: Error<L>) -> SyncError<L, R> {
    match error {
        Error::Store(error) => SyncError::Local(error),
        Error::MissingNode => SyncError::MissingNode,
    }
}

fn materialize<H: Hasher, P: Payload, S: Store<H, P>>(
    clock: &MerkleClock<H>,
    store: &S,
) -> Result<P::State, Error<S::Error>> {
    let mut nodes: BTreeMap<Cid<H>, DagNode<H, P>> = BTreeMap::new();
    let mut visited = BTreeSet::new();
    let mut stack: Vec<Cid<H>> = clock.roots().iter().cloned().collect();
    while let Some(cid) = stack.pop() {
        if !visited.insert(cid.clone()) {
            continue;
        }
        let node = store.get(&cid)?.ok_or(Error::MissingNode)?;
        if node.cid() != cid {
            return Err(Error::MissingNode);
        }
        for child in &node.children {
            if !visited.contains(child) {
                stack.push(child.clone());
            }
        }
        nodes.insert(cid, node);
    }
    let mut state = P::State::default();
    for (_, node) in sync::topological_sort(nodes) {
        P::apply(&mut state, &node.payload);
    }
    Ok(state)
}

fn ancestry_is_valid<H: Hasher, P: Payload, S: Store<H, P>, V: NodeValidator<H, P>>(
    clock: &MerkleClock<H>,
    store: &S,
    validator: &V,
) -> Result<bool, Error<S::Error>> {
    let mut visited = BTreeSet::new();
    let mut stack: Vec<Cid<H>> = clock.roots().iter().cloned().collect();
    while let Some(cid) = stack.pop() {
        if !visited.insert(cid.clone()) {
            continue;
        }
        let node = store.get(&cid)?.ok_or(Error::MissingNode)?;
        if node.cid() != cid {
            return Err(Error::MissingNode);
        }
        if !validator.validate(&cid, &node) {
            return Ok(false);
        }
        stack.extend(node.children.iter().cloned());
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemStore, Store};

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

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum InjectedError {
        Write,
    }

    struct FailStore {
        inner: MemStore<TestHasher, CounterOp>,
        writes_before_failure: Option<usize>,
    }

    impl FailStore {
        fn new(writes_before_failure: Option<usize>) -> Self {
            Self {
                inner: MemStore::new(),
                writes_before_failure,
            }
        }
    }

    impl Store<TestHasher, CounterOp> for FailStore {
        type Error = InjectedError;

        fn get(
            &self,
            cid: &Cid<TestHasher>,
        ) -> Result<Option<DagNode<TestHasher, CounterOp>>, Self::Error> {
            Ok(self.inner.get(cid).unwrap())
        }

        fn put(
            &mut self,
            cid: Cid<TestHasher>,
            node: DagNode<TestHasher, CounterOp>,
        ) -> Result<(), Self::Error> {
            if let Some(remaining) = &mut self.writes_before_failure {
                if *remaining == 0 {
                    return Err(InjectedError::Write);
                }
                *remaining -= 1;
            }
            self.inner.put(cid, node).unwrap();
            Ok(())
        }

        fn contains(&self, cid: &Cid<TestHasher>) -> Result<bool, Self::Error> {
            Ok(self.inner.contains(cid).unwrap())
        }
    }

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
        assert_eq!(
            *alice.state(),
            18,
            "rebuild_state double-applied operations!"
        );
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
        assert_eq!(
            *bob.state(),
            7,
            "syncing already-included root should be no-op"
        );
    }

    #[test]
    fn local_store_failure_does_not_mutate_clock_or_state() {
        let store = FailStore::new(Some(0));
        let mut replica: MerkleCrdt<TestHasher, CounterOp, _> = MerkleCrdt::new(store);
        assert!(matches!(
            replica.apply(CounterOp(7)),
            Err(Error::Store(InjectedError::Write))
        ));
        assert_eq!(*replica.state(), 0);
        assert!(replica.roots().is_empty());
    }

    #[test]
    fn partial_sync_is_unpublished_and_safely_retryable() {
        let mut remote: TestCrdt = MerkleCrdt::default();
        remote.apply(CounterOp(1)).unwrap();
        remote.apply(CounterOp(2)).unwrap();
        remote.apply(CounterOp(4)).unwrap();
        let root = remote.roots().iter().next().unwrap().clone();

        let store = FailStore::new(Some(1));
        let mut local: MerkleCrdt<TestHasher, CounterOp, _> = MerkleCrdt::new(store);
        assert!(matches!(
            local.sync(&root, remote.store()),
            Err(SyncError::Local(InjectedError::Write))
        ));
        assert_eq!(*local.state(), 0, "partial nodes must not materialize");
        assert!(local.roots().is_empty(), "partial root must not publish");

        local.store_mut().writes_before_failure = None;
        local.sync(&root, remote.store()).unwrap();
        assert_eq!(*local.state(), 7);
        assert_eq!(local.roots(), remote.roots());
    }

    #[test]
    fn missing_parent_never_activates_root() {
        let missing = Cid::<TestHasher>([9; 32]);
        let node = DagNode::new(CounterOp(2), [missing].into_iter().collect());
        let root = node.cid();
        let mut remote = MemStore::new();
        remote.put(root.clone(), node).unwrap();
        let mut local: TestCrdt = MerkleCrdt::default();
        assert!(matches!(
            local.sync(&root, &remote),
            Err(SyncError::MissingNode)
        ));
        assert_eq!(*local.state(), 0);
        assert!(local.roots().is_empty());
    }

    #[test]
    fn malicious_cid_is_rejected() {
        let node = DagNode::leaf(CounterOp(1));
        let false_cid = Cid::<TestHasher>([0x55; 32]);
        assert_ne!(node.cid(), false_cid);
        let mut remote = MemStore::new();
        remote.put(false_cid.clone(), node).unwrap();
        let mut local: TestCrdt = MerkleCrdt::default();
        assert!(matches!(
            local.sync(&false_cid, &remote),
            Err(SyncError::InvalidCid)
        ));
    }

    #[test]
    fn recovery_requires_complete_ancestry() {
        let mut original: TestCrdt = MerkleCrdt::default();
        original.apply(CounterOp(3)).unwrap();
        original.apply(CounterOp(8)).unwrap();
        let roots = original.roots().iter().cloned().collect::<Vec<_>>();
        let mut copied = MemStore::new();
        for root in &roots {
            original
                .clock()
                .walk(root, original.store(), |cid, node| {
                    copied.put(cid.clone(), node.clone()).unwrap();
                })
                .unwrap();
        }
        let recovered = TestCrdt::from_roots(copied, roots).unwrap();
        assert_eq!(*recovered.state(), 11);
    }

    #[test]
    fn validation_covers_previously_staged_ancestry() {
        struct RejectAll;
        impl NodeValidator<TestHasher, CounterOp> for RejectAll {
            fn validate(
                &self,
                _cid: &Cid<TestHasher>,
                _node: &DagNode<TestHasher, CounterOp>,
            ) -> bool {
                false
            }
        }

        let node = DagNode::leaf(CounterOp(5));
        let root = node.cid();
        let mut local_store = MemStore::new();
        local_store.put(root.clone(), node.clone()).unwrap();
        let mut local: TestCrdt = MerkleCrdt::new(local_store);
        let mut remote = MemStore::new();
        remote.put(root.clone(), node).unwrap();

        assert!(matches!(
            local.sync_validated(&root, &remote, &RejectAll),
            Err(SyncError::InvalidAuthor)
        ));
        assert_eq!(*local.state(), 0);
        assert!(local.roots().is_empty());
    }
}
