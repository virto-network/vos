//! Incremental authenticated state map owned by the generic service guest.
//!
//! Logical keys are hashed into a fixed-depth sparse Merkle tree. The guest
//! reads and rewrites only the touched 256-bit path using ordinary JAM service
//! storage; no host-authored witness or full-state scan is required.

use alloc::vec::Vec;

use super::{Hash, StateKeyV2, V2Wire};
use crate::zk::state::{self, EMPTY_LEAF, SmtParams};

pub const SERVICE_STATE_LEAF_DOMAIN: &[u8] = b"vos/service-state-leaf/v2";
pub const SERVICE_STATE_NODE_DOMAIN: &[u8] = b"vos/service-state-node/v2";
pub const SERVICE_STATE_KEY_DOMAIN: &[u8] = b"vos/service-state-key/v2";

const TREE_DEPTH: usize = 256;
const LEAF_STORAGE_PREFIX: &[u8] = b"\0vos/v2/state-leaf/";
const NODE_STORAGE_PREFIX: &[u8] = b"\0vos/v2/state-node/";

const PARAMS: SmtParams = SmtParams {
    leaf_domain: SERVICE_STATE_LEAF_DOMAIN,
    node_domain: SERVICE_STATE_NODE_DOMAIN,
    width: 32,
};

/// Storage transaction visible to the guest tree. Reads must observe earlier
/// writes in the same transaction. After a write error the transaction is
/// poisoned and must be discarded rather than retried in place.
pub trait StateTreeStore {
    type Error;

    fn read(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;
    fn write(&mut self, key: &[u8], value: Option<&[u8]>) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateTreeError<E> {
    Storage(E),
    CorruptLeaf,
    CorruptNode,
    KeyCollision,
    RootMismatch { expected: Hash, actual: Hash },
}

impl<E: core::fmt::Debug> core::fmt::Display for StateTreeError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid VOS v2 state tree: {self:?}")
    }
}

impl<E: core::fmt::Debug> core::error::Error for StateTreeError<E> {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StateLeafV2 {
    logical_key: StateKeyV2,
    value: Vec<u8>,
}

impl V2Wire for StateLeafV2 {
    const MAGIC: [u8; 4] = *b"VSL2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        use super::wire::Encoder;
        let mut e = Encoder(out);
        e.bytes(&self.logical_key.encode());
        e.bytes(&self.value);
    }

    fn decode_body(d: &mut super::wire::Decoder<'_>) -> Result<Self, super::DecodeError> {
        Ok(Self {
            logical_key: StateKeyV2::decode(&d.bytes()?)?,
            value: d.bytes()?,
        })
    }
}

#[derive(Debug)]
struct AuthenticatedPath {
    position: [u8; 32],
    value: Option<Vec<u8>>,
    /// Siblings ordered leaf-first.
    siblings: Vec<[u8; 32]>,
}

struct Mutation {
    key: Vec<u8>,
    value: Option<Vec<u8>>,
}

pub struct ServiceStateTreeV2<'a, S: StateTreeStore> {
    store: &'a mut S,
    root: Hash,
    empty: Vec<[u8; 32]>,
}

impl<'a, S: StateTreeStore> ServiceStateTreeV2<'a, S> {
    pub fn new(store: &'a mut S, root: Hash) -> Self {
        Self {
            store,
            root,
            empty: state::empty_chain(&PARAMS),
        }
    }

    pub fn empty_root() -> Hash {
        empty_state_root()
    }

    pub const fn root(&self) -> Hash {
        self.root
    }

    pub fn get(&self, key: &StateKeyV2) -> Result<Option<Vec<u8>>, StateTreeError<S::Error>> {
        self.authenticate(key).map(|path| path.value)
    }

    /// Insert, replace, or delete a logical row and return the new root. A
    /// successful call updates the transaction's tree nodes; callers publish
    /// the returned root in the store header only after every row succeeds.
    pub fn apply(
        &mut self,
        key: &StateKeyV2,
        value: Option<&[u8]>,
    ) -> Result<Hash, StateTreeError<S::Error>> {
        let path = self.authenticate(key)?;
        let leaf = value.map(|value| StateLeafV2 {
            logical_key: key.clone(),
            value: value.to_vec(),
        });
        let mut current = leaf.as_ref().map(hash_leaf).unwrap_or(EMPTY_LEAF);
        let mut mutations = Vec::with_capacity(TREE_DEPTH + 1);

        mutations.push(Mutation {
            key: leaf_storage_key(&path.position),
            value: leaf.as_ref().map(V2Wire::encode),
        });
        mutations.push(Mutation {
            key: node_storage_key(TREE_DEPTH, &path.position),
            value: (current != EMPTY_LEAF).then(|| current.to_vec()),
        });

        for depth in 0..TREE_DEPTH {
            let sibling = path.siblings[depth];
            current = if state::bit_at(&PARAMS, &path.position, depth) {
                state::node_hash(&PARAMS, &sibling, &current)
            } else {
                state::node_hash(&PARAMS, &current, &sibling)
            };
            let level = TREE_DEPTH - 1 - depth;
            if level > 0 {
                let prefix = prefix_of(&path.position, level);
                let empty = self.empty[TREE_DEPTH - level];
                mutations.push(Mutation {
                    key: node_storage_key(level, &prefix),
                    value: (current != empty).then(|| current.to_vec()),
                });
            }
        }

        let next_root = Hash(current);
        for mutation in &mutations {
            self.store
                .write(&mutation.key, mutation.value.as_deref())
                .map_err(StateTreeError::Storage)?;
        }
        self.root = next_root;
        Ok(next_root)
    }

    fn authenticate(
        &self,
        requested: &StateKeyV2,
    ) -> Result<AuthenticatedPath, StateTreeError<S::Error>> {
        let position = state_position(requested);
        let leaf_bytes = self
            .store
            .read(&leaf_storage_key(&position))
            .map_err(StateTreeError::Storage)?;
        let (value, mut current) = match leaf_bytes {
            Some(bytes) => {
                let leaf = StateLeafV2::decode(&bytes).map_err(|_| StateTreeError::CorruptLeaf)?;
                if state_position(&leaf.logical_key) != position {
                    return Err(StateTreeError::CorruptLeaf);
                }
                if leaf.logical_key != *requested {
                    return Err(StateTreeError::KeyCollision);
                }
                let hash = hash_leaf(&leaf);
                let stored = self.read_node(TREE_DEPTH, &position)?;
                if stored != Some(hash) {
                    return Err(StateTreeError::CorruptLeaf);
                }
                (Some(leaf.value), hash)
            }
            None => {
                if self.read_node(TREE_DEPTH, &position)?.is_some() {
                    return Err(StateTreeError::CorruptLeaf);
                }
                (None, EMPTY_LEAF)
            }
        };

        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        for depth in 0..TREE_DEPTH {
            let parent_level = TREE_DEPTH - 1 - depth;
            let child_level = parent_level + 1;
            let mut sibling_prefix = prefix_of(&position, child_level);
            toggle_level_bit(&mut sibling_prefix, parent_level);
            let sibling = self
                .read_node(child_level, &sibling_prefix)?
                .unwrap_or(self.empty[depth]);
            siblings.push(sibling);
            current = if state::bit_at(&PARAMS, &position, depth) {
                state::node_hash(&PARAMS, &sibling, &current)
            } else {
                state::node_hash(&PARAMS, &current, &sibling)
            };

            if parent_level > 0 {
                let parent_prefix = prefix_of(&position, parent_level);
                let stored = self.read_node(parent_level, &parent_prefix)?;
                let empty = self.empty[TREE_DEPTH - parent_level];
                let expected = (current != empty).then_some(current);
                if stored != expected {
                    return Err(StateTreeError::CorruptNode);
                }
            }
        }

        let actual = Hash(current);
        if actual != self.root {
            return Err(StateTreeError::RootMismatch {
                expected: self.root,
                actual,
            });
        }
        Ok(AuthenticatedPath {
            position,
            value,
            siblings,
        })
    }

    fn read_node(
        &self,
        level: usize,
        prefix: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, StateTreeError<S::Error>> {
        let bytes = self
            .store
            .read(&node_storage_key(level, prefix))
            .map_err(StateTreeError::Storage)?;
        bytes
            .map(|bytes| bytes.try_into().map_err(|_| StateTreeError::CorruptNode))
            .transpose()
    }
}

pub fn state_position(key: &StateKeyV2) -> [u8; 32] {
    Hash::digest(SERVICE_STATE_KEY_DOMAIN, &[&key.encode()]).0
}

pub fn empty_state_root() -> Hash {
    Hash(
        *state::empty_chain(&PARAMS)
            .last()
            .expect("fixed-depth tree"),
    )
}

fn hash_leaf(leaf: &StateLeafV2) -> [u8; 32] {
    let key = leaf.logical_key.encode();
    let len = (leaf.value.len() as u64).to_le_bytes();
    Hash::digest(SERVICE_STATE_LEAF_DOMAIN, &[&key, &len, &leaf.value]).0
}

fn leaf_storage_key(position: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(LEAF_STORAGE_PREFIX.len() + position.len());
    key.extend_from_slice(LEAF_STORAGE_PREFIX);
    key.extend_from_slice(position);
    key
}

fn node_storage_key(level: usize, prefix: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(NODE_STORAGE_PREFIX.len() + 2 + prefix.len());
    key.extend_from_slice(NODE_STORAGE_PREFIX);
    key.extend_from_slice(&(level as u16).to_be_bytes());
    key.extend_from_slice(prefix);
    key
}

fn prefix_of(position: &[u8; 32], level: usize) -> [u8; 32] {
    debug_assert!(level <= TREE_DEPTH);
    let mut prefix = [0; 32];
    let full_bytes = level / 8;
    prefix[..full_bytes].copy_from_slice(&position[..full_bytes]);
    if level % 8 != 0 {
        let mask = !(0xffu8 >> (level % 8));
        prefix[full_bytes] = position[full_bytes] & mask;
    }
    prefix
}

fn toggle_level_bit(prefix: &mut [u8; 32], level: usize) {
    prefix[level / 8] ^= 1 << (7 - (level % 8));
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::vec;

    use super::*;
    use crate::v2::ActorId;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum StoreError {
        Injected,
    }

    #[derive(Clone, Default)]
    struct MemStore {
        rows: BTreeMap<Vec<u8>, Vec<u8>>,
        writes_before_failure: Option<usize>,
    }

    impl StateTreeStore for MemStore {
        type Error = StoreError;

        fn read(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.rows.get(key).cloned())
        }

        fn write(&mut self, key: &[u8], value: Option<&[u8]>) -> Result<(), Self::Error> {
            if let Some(remaining) = &mut self.writes_before_failure {
                if *remaining == 0 {
                    return Err(StoreError::Injected);
                }
                *remaining -= 1;
            }
            match value {
                Some(value) => {
                    self.rows.insert(key.to_vec(), value.to_vec());
                }
                None => {
                    self.rows.remove(key);
                }
            }
            Ok(())
        }
    }

    fn row(index: u8) -> StateKeyV2 {
        StateKeyV2::ActorRow {
            actor: ActorId([index; 32]),
            key: vec![b's', index],
        }
    }

    fn full_root(values: &BTreeMap<StateKeyV2, Vec<u8>>) -> Hash {
        let mut leaves: Vec<_> = values
            .iter()
            .map(|(key, value)| {
                let leaf = StateLeafV2 {
                    logical_key: key.clone(),
                    value: value.clone(),
                };
                (state_position(key), hash_leaf(&leaf))
            })
            .collect();
        leaves.sort_unstable_by_key(|(key, _)| *key);
        Hash(state::root_of_sorted(&PARAMS, &leaves))
    }

    #[test]
    fn incremental_updates_match_full_recomputation() {
        let mut store = MemStore::default();
        let mut expected = BTreeMap::new();
        let mut root = ServiceStateTreeV2::<MemStore>::empty_root();
        for index in 1..=32 {
            let key = row(index);
            let value = Hash::digest(b"state-tree-test", &[&[index]]).0.to_vec();
            root = {
                let mut tree = ServiceStateTreeV2::new(&mut store, root);
                tree.apply(&key, Some(&value)).unwrap()
            };
            expected.insert(key, value);
            assert_eq!(root, full_root(&expected));
        }

        for index in (1..=32).step_by(2) {
            let key = row(index);
            root = {
                let mut tree = ServiceStateTreeV2::new(&mut store, root);
                tree.apply(&key, None).unwrap()
            };
            expected.remove(&key);
            assert_eq!(root, full_root(&expected));
        }

        for (key, value) in expected {
            let tree = ServiceStateTreeV2::new(&mut store, root);
            assert_eq!(tree.get(&key).unwrap(), Some(value));
        }
    }

    #[test]
    fn corrupt_path_is_rejected_against_the_header_root() {
        let mut store = MemStore::default();
        let key = row(7);
        let root = {
            let mut tree =
                ServiceStateTreeV2::new(&mut store, ServiceStateTreeV2::<MemStore>::empty_root());
            tree.apply(&key, Some(b"value")).unwrap()
        };
        let position = state_position(&key);
        let leaf_node = node_storage_key(TREE_DEPTH, &position);
        store.rows.insert(leaf_node, vec![9; 32]);
        let tree = ServiceStateTreeV2::new(&mut store, root);
        assert_eq!(tree.get(&key), Err(StateTreeError::CorruptLeaf));
    }

    #[test]
    fn failed_staging_transaction_never_changes_committed_rows() {
        let committed = MemStore::default();
        let mut staging = committed.clone();
        staging.writes_before_failure = Some(2);
        let root = ServiceStateTreeV2::<MemStore>::empty_root();
        let result = ServiceStateTreeV2::new(&mut staging, root).apply(&row(1), Some(b"value"));
        assert_eq!(result, Err(StateTreeError::Storage(StoreError::Injected)));
        assert!(committed.rows.is_empty());
        assert_eq!(root, ServiceStateTreeV2::<MemStore>::empty_root());
    }

    #[test]
    fn logical_values_may_be_empty_even_though_jam_zero_length_deletes() {
        let mut store = MemStore::default();
        let key = row(2);
        let root =
            ServiceStateTreeV2::new(&mut store, ServiceStateTreeV2::<MemStore>::empty_root())
                .apply(&key, Some(&[]))
                .unwrap();
        let tree = ServiceStateTreeV2::new(&mut store, root);
        assert_eq!(tree.get(&key).unwrap(), Some(vec![]));
    }
}
