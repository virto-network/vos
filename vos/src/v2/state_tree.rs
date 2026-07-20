//! Incremental authenticated state map owned by the generic service guest.
//!
//! The map is a canonical binary Merkle-Patricia tree over 256-bit logical-key
//! digests. Unlike a fixed-depth sparse tree, an update hashes and reads only
//! actual branch nodes; an empty or small service therefore does not pay 256
//! guest precompile calls per row. Nodes are immutable and content-addressed,
//! while the store header atomically selects the current root.

use alloc::vec::Vec;

use super::wire::{DecodeError, Decoder, Encoder};
use super::{Hash, StateKeyV2, V2Wire};

pub const SERVICE_STATE_LEAF_DOMAIN: &[u8] = b"vos/service-state-leaf/v2";
pub const SERVICE_STATE_NODE_DOMAIN: &[u8] = b"vos/service-state-node/v2";
pub const SERVICE_STATE_KEY_DOMAIN: &[u8] = b"vos/service-state-key/v2";

const TREE_DEPTH: usize = 256;
const NODE_STORAGE_PREFIX: &[u8] = b"\0vos/v2/state-node/";

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
enum StateNodeV2 {
    Leaf {
        position: [u8; 32],
        logical_key: StateKeyV2,
        value: Vec<u8>,
    },
    Branch {
        /// First differing bit, indexed most-significant-bit first.
        bit: u16,
        /// Common bits strictly before `bit`; all remaining bits are zero.
        prefix: [u8; 32],
        left: Hash,
        right: Hash,
    },
}

impl V2Wire for StateNodeV2 {
    const MAGIC: [u8; 4] = *b"VSN2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        match self {
            Self::Leaf {
                position,
                logical_key,
                value,
            } => {
                e.u8(0);
                e.fixed(position);
                e.bytes(&logical_key.encode());
                e.bytes(value);
            }
            Self::Branch {
                bit,
                prefix,
                left,
                right,
            } => {
                e.u8(1);
                e.u16(*bit);
                e.fixed(prefix);
                e.fixed(&left.0);
                e.fixed(&right.0);
            }
        }
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match d.u8()? {
            0 => {
                let position = d.fixed()?;
                let logical_key = StateKeyV2::decode(&d.bytes()?)?;
                let value = d.bytes()?;
                if state_position(&logical_key) != position {
                    return Err(DecodeError::NonCanonical);
                }
                Ok(Self::Leaf {
                    position,
                    logical_key,
                    value,
                })
            }
            1 => {
                let bit = d.u16()?;
                let prefix = d.fixed()?;
                let left = Hash(d.fixed()?);
                let right = Hash(d.fixed()?);
                if usize::from(bit) >= TREE_DEPTH
                    || prefix_of(&prefix, usize::from(bit)) != prefix
                    || left == Hash::ZERO
                    || right == Hash::ZERO
                    || left == right
                {
                    return Err(DecodeError::NonCanonical);
                }
                Ok(Self::Branch {
                    bit,
                    prefix,
                    left,
                    right,
                })
            }
            _ => Err(DecodeError::InvalidTag),
        }
    }
}

pub struct ServiceStateTreeV2<'a, S: StateTreeStore> {
    store: &'a mut S,
    root: Hash,
}

impl<'a, S: StateTreeStore> ServiceStateTreeV2<'a, S> {
    pub fn new(store: &'a mut S, root: Hash) -> Self {
        Self { store, root }
    }

    pub const fn empty_root() -> Hash {
        empty_state_root()
    }

    pub const fn root(&self) -> Hash {
        self.root
    }

    pub(crate) fn store_ref(&self) -> &S {
        self.store
    }

    pub(crate) fn store_mut(&mut self) -> &mut S {
        self.store
    }

    pub fn get(&self, key: &StateKeyV2) -> Result<Option<Vec<u8>>, StateTreeError<S::Error>> {
        let position = state_position(key);
        let mut current = self.root;
        while current != Hash::ZERO {
            match self.read_node(current)? {
                StateNodeV2::Leaf {
                    position: stored_position,
                    logical_key,
                    value,
                } => {
                    if stored_position != position {
                        return Ok(None);
                    }
                    if logical_key != *key {
                        return Err(StateTreeError::KeyCollision);
                    }
                    return Ok(Some(value));
                }
                StateNodeV2::Branch {
                    bit,
                    prefix,
                    left,
                    right,
                } => {
                    let bit = usize::from(bit);
                    if prefix_of(&position, bit) != prefix {
                        return Ok(None);
                    }
                    current = if bit_at(&position, bit) { right } else { left };
                }
            }
        }
        Ok(None)
    }

    /// Insert, replace, or delete one logical row. Newly built Patricia nodes
    /// are content-addressed and immutable; callers publish the returned root
    /// in the store header only after every row in the transaction succeeds.
    pub fn apply(
        &mut self,
        key: &StateKeyV2,
        value: Option<&[u8]>,
    ) -> Result<Hash, StateTreeError<S::Error>> {
        let position = state_position(key);
        let next = self.update(self.root, &position, key, value)?;
        self.root = next;
        Ok(next)
    }

    fn update(
        &mut self,
        current: Hash,
        position: &[u8; 32],
        key: &StateKeyV2,
        value: Option<&[u8]>,
    ) -> Result<Hash, StateTreeError<S::Error>> {
        if current == Hash::ZERO {
            return match value {
                Some(value) => self.store_node(&StateNodeV2::Leaf {
                    position: *position,
                    logical_key: key.clone(),
                    value: value.to_vec(),
                }),
                None => Ok(Hash::ZERO),
            };
        }

        match self.read_node(current)? {
            StateNodeV2::Leaf {
                position: stored_position,
                logical_key,
                value: stored_value,
            } => {
                if stored_position == *position {
                    if logical_key != *key {
                        return Err(StateTreeError::KeyCollision);
                    }
                    return match value {
                        Some(value) if value == stored_value => Ok(current),
                        Some(value) => self.store_node(&StateNodeV2::Leaf {
                            position: *position,
                            logical_key: key.clone(),
                            value: value.to_vec(),
                        }),
                        None => Ok(Hash::ZERO),
                    };
                }
                let Some(value) = value else {
                    return Ok(current);
                };
                let bit = first_differing_bit(&stored_position, position)
                    .expect("distinct positions have a differing bit");
                let inserted = self.store_node(&StateNodeV2::Leaf {
                    position: *position,
                    logical_key: key.clone(),
                    value: value.to_vec(),
                })?;
                self.store_branch(bit, position, current, inserted)
            }
            StateNodeV2::Branch {
                bit,
                prefix,
                left,
                right,
            } => {
                let bit = usize::from(bit);
                if let Some(earlier) = first_difference_before(position, &prefix, bit) {
                    let Some(value) = value else {
                        return Ok(current);
                    };
                    let inserted = self.store_node(&StateNodeV2::Leaf {
                        position: *position,
                        logical_key: key.clone(),
                        value: value.to_vec(),
                    })?;
                    return self.store_branch(earlier, position, current, inserted);
                }

                let right_side = bit_at(position, bit);
                let child = if right_side { right } else { left };
                let next_child = self.update(child, position, key, value)?;
                if next_child == child {
                    return Ok(current);
                }
                if next_child == Hash::ZERO {
                    return Ok(if right_side { left } else { right });
                }
                let node = if right_side {
                    StateNodeV2::Branch {
                        bit: bit as u16,
                        prefix,
                        left,
                        right: next_child,
                    }
                } else {
                    StateNodeV2::Branch {
                        bit: bit as u16,
                        prefix,
                        left: next_child,
                        right,
                    }
                };
                self.store_node(&node)
            }
        }
    }

    fn store_branch(
        &mut self,
        bit: usize,
        inserted_position: &[u8; 32],
        existing: Hash,
        inserted: Hash,
    ) -> Result<Hash, StateTreeError<S::Error>> {
        let (left, right) = if bit_at(inserted_position, bit) {
            (existing, inserted)
        } else {
            (inserted, existing)
        };
        self.store_node(&StateNodeV2::Branch {
            bit: bit as u16,
            prefix: prefix_of(inserted_position, bit),
            left,
            right,
        })
    }

    fn read_node(&self, expected: Hash) -> Result<StateNodeV2, StateTreeError<S::Error>> {
        let bytes = self
            .store
            .read(&node_storage_key(expected))
            .map_err(StateTreeError::Storage)?
            .ok_or(StateTreeError::RootMismatch {
                expected,
                actual: Hash::ZERO,
            })?;
        let node = StateNodeV2::decode(&bytes).map_err(|_| StateTreeError::CorruptNode)?;
        let actual = hash_node(&node);
        if actual != expected {
            return Err(match node {
                StateNodeV2::Leaf { .. } => StateTreeError::CorruptLeaf,
                StateNodeV2::Branch { .. } => StateTreeError::CorruptNode,
            });
        }
        Ok(node)
    }

    fn store_node(&mut self, node: &StateNodeV2) -> Result<Hash, StateTreeError<S::Error>> {
        let hash = hash_node(node);
        let key = node_storage_key(hash);
        let encoded = node.encode();
        if let Some(existing) = self.store.read(&key).map_err(StateTreeError::Storage)? {
            if existing != encoded {
                return Err(StateTreeError::CorruptNode);
            }
            return Ok(hash);
        }
        self.store
            .write(&key, Some(&encoded))
            .map_err(StateTreeError::Storage)?;
        Ok(hash)
    }
}

pub fn state_position(key: &StateKeyV2) -> [u8; 32] {
    Hash::digest(SERVICE_STATE_KEY_DOMAIN, &[&key.encode()]).0
}

pub const fn empty_state_root() -> Hash {
    Hash::ZERO
}

fn hash_node(node: &StateNodeV2) -> Hash {
    match node {
        StateNodeV2::Leaf {
            position,
            logical_key,
            value,
        } => {
            let key = logical_key.encode();
            let len = (value.len() as u64).to_le_bytes();
            Hash::digest(SERVICE_STATE_LEAF_DOMAIN, &[position, &key, &len, value])
        }
        StateNodeV2::Branch {
            bit,
            prefix,
            left,
            right,
        } => Hash::digest(
            SERVICE_STATE_NODE_DOMAIN,
            &[&bit.to_le_bytes(), prefix, &left.0, &right.0],
        ),
    }
}

fn node_storage_key(hash: Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(NODE_STORAGE_PREFIX.len() + hash.0.len());
    key.extend_from_slice(NODE_STORAGE_PREFIX);
    key.extend_from_slice(&hash.0);
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

fn bit_at(position: &[u8; 32], bit: usize) -> bool {
    position[bit / 8] & (1 << (7 - bit % 8)) != 0
}

fn first_differing_bit(left: &[u8; 32], right: &[u8; 32]) -> Option<usize> {
    (0..TREE_DEPTH).find(|bit| bit_at(left, *bit) != bit_at(right, *bit))
}

fn first_difference_before(position: &[u8; 32], prefix: &[u8; 32], before: usize) -> Option<usize> {
    (0..before).find(|bit| bit_at(position, *bit) != bit_at(prefix, *bit))
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

    fn rebuild(values: &BTreeMap<StateKeyV2, Vec<u8>>) -> Hash {
        let mut store = MemStore::default();
        let mut root = empty_state_root();
        for (key, value) in values {
            root = ServiceStateTreeV2::new(&mut store, root)
                .apply(key, Some(value))
                .unwrap();
        }
        root
    }

    #[test]
    fn incremental_updates_match_canonical_recomputation() {
        let mut store = MemStore::default();
        let mut expected = BTreeMap::new();
        let mut root = empty_state_root();
        for index in 1..=32 {
            let key = row(index);
            let value = Hash::digest(b"state-tree-test", &[&[index]]).0.to_vec();
            root = ServiceStateTreeV2::new(&mut store, root)
                .apply(&key, Some(&value))
                .unwrap();
            expected.insert(key, value);
            assert_eq!(root, rebuild(&expected));
        }

        for index in (1..=32).step_by(2) {
            let key = row(index);
            root = ServiceStateTreeV2::new(&mut store, root)
                .apply(&key, None)
                .unwrap();
            expected.remove(&key);
            assert_eq!(root, rebuild(&expected));
        }

        for (key, value) in expected {
            let tree = ServiceStateTreeV2::new(&mut store, root);
            assert_eq!(tree.get(&key).unwrap(), Some(value));
        }
    }

    #[test]
    fn insertion_order_does_not_change_the_root() {
        let entries: Vec<_> = (1..=16)
            .map(|index| (row(index), vec![index, index.wrapping_mul(3)]))
            .collect();
        let mut forward_store = MemStore::default();
        let mut forward = empty_state_root();
        for (key, value) in &entries {
            forward = ServiceStateTreeV2::new(&mut forward_store, forward)
                .apply(key, Some(value))
                .unwrap();
        }
        let mut reverse_store = MemStore::default();
        let mut reverse = empty_state_root();
        for (key, value) in entries.iter().rev() {
            reverse = ServiceStateTreeV2::new(&mut reverse_store, reverse)
                .apply(key, Some(value))
                .unwrap();
        }
        assert_eq!(forward, reverse);
    }

    #[test]
    fn corrupt_content_addressed_node_is_rejected() {
        let mut store = MemStore::default();
        let key = row(7);
        let root = ServiceStateTreeV2::new(&mut store, empty_state_root())
            .apply(&key, Some(b"value"))
            .unwrap();
        store.rows.insert(node_storage_key(root), vec![9; 32]);
        let tree = ServiceStateTreeV2::new(&mut store, root);
        assert!(matches!(
            tree.get(&key),
            Err(StateTreeError::CorruptNode | StateTreeError::CorruptLeaf)
        ));
    }

    #[test]
    fn failed_staging_transaction_never_changes_committed_root() {
        let committed = MemStore::default();
        let mut staging = committed.clone();
        staging.writes_before_failure = Some(0);
        let root = empty_state_root();
        let result = ServiceStateTreeV2::new(&mut staging, root).apply(&row(1), Some(b"value"));
        assert_eq!(result, Err(StateTreeError::Storage(StoreError::Injected)));
        assert!(committed.rows.is_empty());
        assert_eq!(root, empty_state_root());
    }

    #[test]
    fn logical_values_may_be_empty_even_though_jam_zero_length_deletes() {
        let mut store = MemStore::default();
        let key = row(2);
        let root = ServiceStateTreeV2::new(&mut store, empty_state_root())
            .apply(&key, Some(&[]))
            .unwrap();
        let tree = ServiceStateTreeV2::new(&mut store, root);
        assert_eq!(tree.get(&key).unwrap(), Some(vec![]));
    }
}
