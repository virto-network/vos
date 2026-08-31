//! Authenticated invocation ownership indexes.
//!
//! Each ordering scope owns an independent, immutable binary Patricia tree
//! keyed by the big-endian bits of [`InvocationId`].  Nodes and manifests are
//! content addressed.  A manifest is installed only after every node it
//! references can be read back byte-for-byte, so an interrupted update leaves
//! at most unreachable immutable objects.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::fmt;

use super::journal::{
    AgentJournalGenesisId, CanonicalJournalRecord, InvocationIndexId, InvocationIndexManifest,
    InvocationIndexNodeId, InvocationOwnershipKey, InvocationOwnershipLeaf,
    InvocationOwnershipScope, InvocationOwnershipValue, InvocationResultState, JournalStorageClass,
    MAX_INVOCATION_INDEX_MANIFEST_BYTES, MAX_INVOCATION_INDEX_NODE_BYTES,
};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{Hash, InvocationId, NodeId};

/// A Patricia path has at most one branch for each key bit.
pub const MAX_INVOCATION_INDEX_PATH: usize = 256;
/// Maximum canonical bytes read along one authenticated path, including its
/// terminal leaf. Mutations write at most one leaf, one new split, and one
/// replacement branch per path level.
pub const MAX_INVOCATION_INDEX_PATH_BYTES: usize =
    (MAX_INVOCATION_INDEX_PATH + 1) * MAX_INVOCATION_INDEX_NODE_BYTES;
/// Conservative default work budget for the in-memory reference store.
pub const DEFAULT_INVOCATION_INDEX_NODE_LIMIT: usize = 1_000_000;

const NODE_ID_DOMAIN: &[u8] = b"vos/agent/journal/invocation-index-node";

/// Authenticated aggregate for one non-empty Patricia subtree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvocationIndexSummary {
    pub min: InvocationId,
    pub max: InvocationId,
    pub entries: u64,
    pub tombstones: u64,
}

impl InvocationIndexSummary {
    fn from_leaf(leaf: &InvocationOwnershipLeaf) -> Self {
        Self {
            min: leaf.key.invocation,
            max: leaf.key.invocation,
            entries: 1,
            tombstones: u64::from(leaf.owner.result_state.is_tombstone()),
        }
    }

    fn validate(self) -> Result<(), DecodeError> {
        if self.min == InvocationId::ZERO
            || self.max == InvocationId::ZERO
            || self.min > self.max
            || self.entries == 0
            || self.tombstones > self.entries
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

/// A child commitment includes the facts needed to authenticate routing and
/// cardinality without flattening the subtree into its parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvocationIndexChild {
    pub id: InvocationIndexNodeId,
    pub summary: InvocationIndexSummary,
}

impl InvocationIndexChild {
    fn validate(self) -> Result<(), DecodeError> {
        if self.id == InvocationIndexNodeId::ZERO {
            return Err(DecodeError::NonCanonical);
        }
        self.summary.validate()
    }
}

/// One immutable node in a scope-bound invocation ownership Patricia tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvocationIndexNode {
    Leaf(InvocationOwnershipLeaf),
    Branch {
        genesis: AgentJournalGenesisId,
        scope: InvocationOwnershipScope,
        /// First differing bit, indexed most-significant-bit first.
        bit: u16,
        /// Common bits strictly before `bit`; all later bits are zero.
        prefix: [u8; 32],
        left: InvocationIndexChild,
        right: InvocationIndexChild,
    },
}

impl InvocationIndexNode {
    pub fn genesis(&self) -> AgentJournalGenesisId {
        match self {
            Self::Leaf(leaf) => leaf.genesis,
            Self::Branch { genesis, .. } => *genesis,
        }
    }

    pub fn scope(&self) -> InvocationOwnershipScope {
        match self {
            Self::Leaf(leaf) => leaf.key.scope,
            Self::Branch { scope, .. } => *scope,
        }
    }

    pub fn summary(&self) -> Result<InvocationIndexSummary, DecodeError> {
        match self {
            Self::Leaf(leaf) => Ok(InvocationIndexSummary::from_leaf(leaf)),
            Self::Branch { left, right, .. } => Ok(InvocationIndexSummary {
                min: left.summary.min,
                max: right.summary.max,
                entries: left
                    .summary
                    .entries
                    .checked_add(right.summary.entries)
                    .ok_or(DecodeError::LimitExceeded)?,
                tombstones: left
                    .summary
                    .tombstones
                    .checked_add(right.summary.tombstones)
                    .ok_or(DecodeError::LimitExceeded)?,
            }),
        }
    }

    fn validate_inner(&self) -> Result<(), DecodeError> {
        match self {
            Self::Leaf(leaf) => leaf.validate()?,
            Self::Branch {
                genesis,
                scope,
                bit,
                prefix,
                left,
                right,
            } => {
                if *genesis == AgentJournalGenesisId::ZERO || usize::from(*bit) >= 256 {
                    return Err(DecodeError::NonCanonical);
                }
                scope.validate()?;
                left.validate()?;
                right.validate()?;
                let bit = usize::from(*bit);
                if prefix_of(prefix, bit) != *prefix
                    || left.id == right.id
                    || left.summary.max >= right.summary.min
                    || !summary_matches_partition(left.summary, prefix, bit, false)
                    || !summary_matches_partition(right.summary, prefix, bit, true)
                {
                    return Err(DecodeError::NonCanonical);
                }
                self.summary()?.validate()?;
            }
        }
        if self.encode().len() > MAX_INVOCATION_INDEX_NODE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        Ok(())
    }
}

impl ServiceWire for InvocationIndexNode {
    const MAGIC: [u8; 4] = *b"AGIN";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        match self {
            Self::Leaf(leaf) => {
                encoder.u8(0);
                encoder.bytes(&leaf.encode());
            }
            Self::Branch {
                genesis,
                scope,
                bit,
                prefix,
                left,
                right,
            } => {
                encoder.u8(1);
                encoder.fixed(&genesis.0);
                encode_scope(&mut encoder, *scope);
                encoder.u16(*bit);
                encoder.fixed(prefix);
                encode_child(&mut encoder, *left);
                encode_child(&mut encoder, *right);
            }
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if decoder.remaining().saturating_add(36) > MAX_INVOCATION_INDEX_NODE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let node = match decoder.u8()? {
            0 => Self::Leaf(InvocationOwnershipLeaf::decode(&decoder.bytes()?)?),
            1 => Self::Branch {
                genesis: AgentJournalGenesisId(decoder.fixed()?),
                scope: decode_scope(decoder)?,
                bit: decoder.u16()?,
                prefix: decoder.fixed()?,
                left: decode_child(decoder)?,
                right: decode_child(decoder)?,
            },
            _ => return Err(DecodeError::InvalidTag),
        };
        node.validate_inner()?;
        Ok(node)
    }
}

impl super::journal::sealed::Sealed for InvocationIndexNode {}

impl CanonicalJournalRecord for InvocationIndexNode {
    type Id = InvocationIndexNodeId;

    const STORAGE_CLASS: JournalStorageClass = JournalStorageClass::InvocationIndexNode;

    fn validate(&self) -> Result<(), DecodeError> {
        self.validate_inner()
    }

    fn id(&self) -> Self::Id {
        InvocationIndexNodeId(Hash::digest(NODE_ID_DOMAIN, &[&self.encode()]).0)
    }
}

/// Storage boundary used by the index. Implementations must preserve objects
/// immutably. The engine additionally reads every put back and rejects any
/// missing or different bytes.
pub trait InvocationIndexStore {
    type Error;

    /// Maximum nodes an explicit full-tree audit may visit. This is a scrub
    /// work budget, never a lifetime or logical-entry limit for ordinary
    /// open, lookup, update, or publication.
    fn node_limit(&self) -> usize;

    fn load_manifest(&self, id: InvocationIndexId) -> Result<Option<Vec<u8>>, Self::Error>;
    fn load_node(&self, id: InvocationIndexNodeId) -> Result<Option<Vec<u8>>, Self::Error>;
    fn put_manifest(&mut self, id: InvocationIndexId, bytes: &[u8]) -> Result<(), Self::Error>;
    fn put_node(&mut self, id: InvocationIndexNodeId, bytes: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvocationIndexError<E> {
    Storage(E),
    MissingManifest(InvocationIndexId),
    MissingNode(InvocationIndexNodeId),
    CorruptManifest,
    CorruptNode(InvocationIndexNodeId),
    GenesisMismatch,
    ScopeMismatch,
    SummaryMismatch,
    NonCanonicalTree,
    Cycle,
    SharedNode,
    PathLimit,
    NodeLimit,
    ObjectCollision,
    StoreViolation,
    Conflict,
    InvalidTransition,
}

impl<E: fmt::Debug> fmt::Display for InvocationIndexError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid invocation ownership index: {self:?}")
    }
}

impl<E: fmt::Debug> core::error::Error for InvocationIndexError<E> {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvocationIndexMutation {
    Inserted(InvocationIndexId),
    ExactRetry(InvocationIndexId),
    Acknowledged(InvocationIndexId),
}

impl InvocationIndexMutation {
    pub const fn index_id(self) -> InvocationIndexId {
        match self {
            Self::Inserted(id) | Self::ExactRetry(id) | Self::Acknowledged(id) => id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationIndexProof {
    pub manifest: InvocationIndexManifest,
    /// Root-to-terminal canonical nodes. Empty indexes have no nodes.
    pub nodes: Vec<InvocationIndexNode>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvocationIndexProofResult {
    Member(InvocationOwnershipValue),
    NonMember,
}

/// Open, root-authenticated view of one lazily resolved scoped index.
pub struct InvocationIndex<'a, S: InvocationIndexStore> {
    store: &'a mut S,
    manifest: InvocationIndexManifest,
    id: InvocationIndexId,
}

type InvocationIndexPath = Vec<(InvocationIndexNode, bool)>;

impl<'a, S: InvocationIndexStore> InvocationIndex<'a, S> {
    /// Install the canonical empty manifest. This is idempotent and writes no
    /// synthetic root node.
    pub fn create_empty(
        store: &mut S,
        genesis: AgentJournalGenesisId,
        scope: InvocationOwnershipScope,
    ) -> Result<InvocationIndexId, InvocationIndexError<S::Error>> {
        let manifest = InvocationIndexManifest::empty(genesis, scope);
        put_manifest_immutable(store, &manifest)
    }

    /// Authenticate the manifest and root in constant work. Descendants are
    /// authenticated lazily along each lookup, proof, or mutation path.
    pub fn open(
        store: &'a mut S,
        id: InvocationIndexId,
    ) -> Result<Self, InvocationIndexError<S::Error>> {
        let manifest = load_manifest(store, id)?;
        validate_manifest_root(store, id, &manifest)?;
        Ok(Self {
            store,
            manifest,
            id,
        })
    }

    pub const fn id(&self) -> InvocationIndexId {
        self.id
    }

    pub const fn manifest(&self) -> &InvocationIndexManifest {
        &self.manifest
    }

    /// Authenticated membership/nonmembership lookup against the opened root.
    pub fn lookup(
        &self,
        key: InvocationOwnershipKey,
    ) -> Result<Option<InvocationOwnershipValue>, InvocationIndexError<S::Error>> {
        lookup_in_manifest(self.store, &self.manifest, key)
    }

    /// Insert the first owner, accept a byte-exact retry, or apply the sole
    /// legal replacement: Retained to Acknowledged. Tombstones are never
    /// deleted or changed into another disposition.
    pub fn record(
        &mut self,
        key: InvocationOwnershipKey,
        value: InvocationOwnershipValue,
    ) -> Result<InvocationIndexMutation, InvocationIndexError<S::Error>> {
        let leaf = InvocationOwnershipLeaf {
            genesis: self.manifest.genesis,
            key,
            owner: value,
        };
        leaf.validate()
            .map_err(|_| InvocationIndexError::InvalidTransition)?;
        self.require_scope(key.scope)?;
        match self.lookup_leaf(key)? {
            Some(existing) if existing == leaf => Ok(InvocationIndexMutation::ExactRetry(self.id)),
            Some(existing) if acknowledged_successor(&existing, &leaf) => {
                self.replace_leaf(leaf, true)
            }
            Some(_) => Err(InvocationIndexError::Conflict),
            None if value.result_state == InvocationResultState::Acknowledged => {
                Err(InvocationIndexError::InvalidTransition)
            }
            None => self.insert_leaf(leaf),
        }
    }

    /// Produce a compact path proof. Its manifest is included so verifiers can
    /// bind the root to an independently obtained manifest ID.
    pub fn prove(
        &self,
        key: InvocationOwnershipKey,
    ) -> Result<InvocationIndexProof, InvocationIndexError<S::Error>> {
        key.validate()
            .map_err(|_| InvocationIndexError::NonCanonicalTree)?;
        self.require_scope(key.scope)?;
        let mut nodes = Vec::new();
        let Some(mut current) = self.manifest.root else {
            return Ok(InvocationIndexProof {
                manifest: self.manifest,
                nodes,
            });
        };
        let mut branches = 0usize;
        let mut parent_bit = None;
        let mut expected_summary = None;
        let mut visited = BTreeSet::new();
        loop {
            if !visited.insert(current) {
                return Err(InvocationIndexError::Cycle);
            }
            let node = load_node(self.store, current)?;
            validate_context(&node, self.manifest.genesis, self.manifest.scope)?;
            validate_path_summary(&node, expected_summary, nodes.is_empty(), &self.manifest)?;
            nodes
                .try_reserve(1)
                .map_err(|_| InvocationIndexError::NodeLimit)?;
            nodes.push(node);
            match node {
                InvocationIndexNode::Leaf(_) => break,
                InvocationIndexNode::Branch {
                    bit,
                    prefix,
                    left,
                    right,
                    ..
                } => {
                    enforce_increasing_bit(parent_bit, bit)?;
                    branches += 1;
                    if branches > MAX_INVOCATION_INDEX_PATH {
                        return Err(InvocationIndexError::PathLimit);
                    }
                    let bit = usize::from(bit);
                    if prefix_of(&key.invocation.0, bit) != prefix {
                        break;
                    }
                    let child = if bit_at(&key.invocation.0, bit) {
                        right
                    } else {
                        left
                    };
                    current = child.id;
                    expected_summary = Some(child.summary);
                    parent_bit = Some(bit as u16);
                }
            }
        }
        Ok(InvocationIndexProof {
            manifest: self.manifest,
            nodes,
        })
    }

    fn require_scope(
        &self,
        scope: InvocationOwnershipScope,
    ) -> Result<(), InvocationIndexError<S::Error>> {
        if scope == self.manifest.scope {
            Ok(())
        } else {
            Err(InvocationIndexError::ScopeMismatch)
        }
    }

    fn lookup_leaf(
        &self,
        key: InvocationOwnershipKey,
    ) -> Result<Option<InvocationOwnershipLeaf>, InvocationIndexError<S::Error>> {
        lookup_leaf_in_manifest(self.store, &self.manifest, key)
    }

    fn insert_leaf(
        &mut self,
        leaf: InvocationOwnershipLeaf,
    ) -> Result<InvocationIndexMutation, InvocationIndexError<S::Error>> {
        let next_entries = self
            .manifest
            .entries
            .checked_add(1)
            .ok_or(InvocationIndexError::NodeLimit)?;
        let leaf_node = InvocationIndexNode::Leaf(leaf);
        let leaf_ref = put_node_immutable(self.store, &leaf_node)?;
        let root = match self.manifest.root {
            None => leaf_ref.id,
            Some(root) => {
                let (ancestors, terminal_id, terminal) =
                    self.path_to_terminal(root, leaf.key.invocation)?;
                let terminal_ref = child_for(terminal_id, &terminal)?;
                let differing =
                    first_differing_bit(&leaf.key.invocation.0, &terminal_ref.summary.min.0)
                        .ok_or(InvocationIndexError::Conflict)?;
                let mut next =
                    self.store_branch(differing, leaf.key.invocation, terminal_ref, leaf_ref)?;
                next = self.rebuild_ancestors(ancestors, next)?;
                next.id
            }
        };
        let tombstones = self
            .manifest
            .tombstones
            .checked_add(u64::from(leaf.owner.result_state.is_tombstone()))
            .ok_or(InvocationIndexError::NodeLimit)?;
        let next = InvocationIndexManifest {
            root: Some(root),
            entries: next_entries,
            tombstones,
            ..self.manifest
        };
        let id = put_manifest_immutable(self.store, &next)?;
        self.manifest = next;
        self.id = id;
        Ok(InvocationIndexMutation::Inserted(id))
    }

    fn replace_leaf(
        &mut self,
        leaf: InvocationOwnershipLeaf,
        acknowledging: bool,
    ) -> Result<InvocationIndexMutation, InvocationIndexError<S::Error>> {
        let root = self
            .manifest
            .root
            .ok_or(InvocationIndexError::InvalidTransition)?;
        let (ancestors, _, terminal) = self.path_to_terminal(root, leaf.key.invocation)?;
        if !matches!(terminal, InvocationIndexNode::Leaf(found) if found.key == leaf.key) {
            return Err(InvocationIndexError::InvalidTransition);
        }
        let replacement = put_node_immutable(self.store, &InvocationIndexNode::Leaf(leaf))?;
        let root = self.rebuild_ancestors(ancestors, replacement)?.id;
        let tombstones = self
            .manifest
            .tombstones
            .checked_add(u64::from(acknowledging))
            .ok_or(InvocationIndexError::NodeLimit)?;
        let next = InvocationIndexManifest {
            root: Some(root),
            tombstones,
            ..self.manifest
        };
        let id = put_manifest_immutable(self.store, &next)?;
        self.manifest = next;
        self.id = id;
        Ok(InvocationIndexMutation::Acknowledged(id))
    }

    fn path_to_terminal(
        &self,
        root: InvocationIndexNodeId,
        key: InvocationId,
    ) -> Result<
        (
            InvocationIndexPath,
            InvocationIndexNodeId,
            InvocationIndexNode,
        ),
        InvocationIndexError<S::Error>,
    > {
        let mut ancestors = Vec::new();
        let mut current = root;
        let mut parent_bit = None;
        let mut expected_summary = None;
        let mut visited = BTreeSet::new();
        loop {
            if !visited.insert(current) {
                return Err(InvocationIndexError::Cycle);
            }
            let node = load_node(self.store, current)?;
            validate_context(&node, self.manifest.genesis, self.manifest.scope)?;
            validate_path_summary(
                &node,
                expected_summary,
                ancestors.is_empty(),
                &self.manifest,
            )?;
            match node {
                InvocationIndexNode::Leaf(_) => return Ok((ancestors, current, node)),
                InvocationIndexNode::Branch {
                    bit,
                    prefix,
                    left,
                    right,
                    ..
                } => {
                    enforce_increasing_bit(parent_bit, bit)?;
                    if ancestors.len() >= MAX_INVOCATION_INDEX_PATH {
                        return Err(InvocationIndexError::PathLimit);
                    }
                    let bit_usize = usize::from(bit);
                    if prefix_of(&key.0, bit_usize) != prefix {
                        return Ok((ancestors, current, node));
                    }
                    let went_right = bit_at(&key.0, bit_usize);
                    ancestors.push((node, went_right));
                    let child = if went_right { right } else { left };
                    current = child.id;
                    expected_summary = Some(child.summary);
                    parent_bit = Some(bit);
                }
            }
        }
    }

    fn store_branch(
        &mut self,
        bit: usize,
        inserted_key: InvocationId,
        existing: InvocationIndexChild,
        inserted: InvocationIndexChild,
    ) -> Result<InvocationIndexChild, InvocationIndexError<S::Error>> {
        if bit >= 256 {
            return Err(InvocationIndexError::NonCanonicalTree);
        }
        let (left, right) = if bit_at(&inserted_key.0, bit) {
            (existing, inserted)
        } else {
            (inserted, existing)
        };
        put_node_immutable(
            self.store,
            &InvocationIndexNode::Branch {
                genesis: self.manifest.genesis,
                scope: self.manifest.scope,
                bit: bit as u16,
                prefix: prefix_of(&inserted_key.0, bit),
                left,
                right,
            },
        )
    }

    fn rebuild_ancestors(
        &mut self,
        ancestors: Vec<(InvocationIndexNode, bool)>,
        mut replacement: InvocationIndexChild,
    ) -> Result<InvocationIndexChild, InvocationIndexError<S::Error>> {
        for (ancestor, went_right) in ancestors.into_iter().rev() {
            let InvocationIndexNode::Branch {
                genesis,
                scope,
                bit,
                prefix,
                mut left,
                mut right,
            } = ancestor
            else {
                return Err(InvocationIndexError::NonCanonicalTree);
            };
            if went_right {
                right = replacement;
            } else {
                left = replacement;
            }
            replacement = put_node_immutable(
                self.store,
                &InvocationIndexNode::Branch {
                    genesis,
                    scope,
                    bit,
                    prefix,
                    left,
                    right,
                },
            )?;
        }
        Ok(replacement)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OpenedInvocationIndex {
    id: InvocationIndexId,
    manifest: InvocationIndexManifest,
}

/// Ordered, Merge, and replica-local ownership roots opened as one replay
/// provider. A replay publication asks this aggregate for all three IDs, so a
/// scope-specific index can never accidentally authenticate the other lanes.
pub struct InvocationIndexes<'a, S: InvocationIndexStore> {
    store: &'a mut S,
    ordered: OpenedInvocationIndex,
    merge: OpenedInvocationIndex,
    local: OpenedInvocationIndex,
}

impl<'a, S: InvocationIndexStore> InvocationIndexes<'a, S> {
    pub fn open(
        store: &'a mut S,
        ordered: InvocationIndexId,
        merge: InvocationIndexId,
        local: InvocationIndexId,
    ) -> Result<Self, InvocationIndexError<S::Error>> {
        let ordered_manifest = load_manifest(store, ordered)?;
        validate_manifest_root(store, ordered, &ordered_manifest)?;
        let merge_manifest = load_manifest(store, merge)?;
        validate_manifest_root(store, merge, &merge_manifest)?;
        let local_manifest = load_manifest(store, local)?;
        validate_manifest_root(store, local, &local_manifest)?;
        if ordered_manifest.scope != InvocationOwnershipScope::Ordered
            || merge_manifest.scope != InvocationOwnershipScope::Merge
            || !matches!(local_manifest.scope, InvocationOwnershipScope::Local(_))
        {
            return Err(InvocationIndexError::ScopeMismatch);
        }
        if ordered_manifest.genesis != merge_manifest.genesis
            || ordered_manifest.genesis != local_manifest.genesis
        {
            return Err(InvocationIndexError::GenesisMismatch);
        }
        Ok(Self {
            store,
            ordered: OpenedInvocationIndex {
                id: ordered,
                manifest: ordered_manifest,
            },
            merge: OpenedInvocationIndex {
                id: merge,
                manifest: merge_manifest,
            },
            local: OpenedInvocationIndex {
                id: local,
                manifest: local_manifest,
            },
        })
    }

    pub const fn genesis(&self) -> AgentJournalGenesisId {
        self.ordered.manifest.genesis
    }

    pub fn local_node(&self) -> NodeId {
        match self.local.manifest.scope {
            InvocationOwnershipScope::Local(node) => node,
            _ => unreachable!("constructor authenticates the local scope"),
        }
    }

    pub fn index_id(
        &self,
        scope: InvocationOwnershipScope,
    ) -> Result<InvocationIndexId, InvocationIndexError<S::Error>> {
        self.opened(scope).map(|opened| opened.id)
    }

    pub fn manifest(
        &self,
        scope: InvocationOwnershipScope,
    ) -> Result<&InvocationIndexManifest, InvocationIndexError<S::Error>> {
        self.opened(scope).map(|opened| &opened.manifest)
    }

    pub fn lookup(
        &self,
        key: InvocationOwnershipKey,
    ) -> Result<Option<InvocationOwnershipValue>, InvocationIndexError<S::Error>> {
        let opened = self.opened(key.scope)?;
        lookup_in_manifest(self.store, &opened.manifest, key)
    }

    pub fn record(
        &mut self,
        key: InvocationOwnershipKey,
        value: InvocationOwnershipValue,
    ) -> Result<InvocationIndexMutation, InvocationIndexError<S::Error>> {
        let opened = *self.opened(key.scope)?;
        let mut index = InvocationIndex {
            store: &mut *self.store,
            manifest: opened.manifest,
            id: opened.id,
        };
        let mutation = index.record(key, value)?;
        let successor = OpenedInvocationIndex {
            id: index.id,
            manifest: index.manifest,
        };
        match key.scope {
            InvocationOwnershipScope::Ordered => self.ordered = successor,
            InvocationOwnershipScope::Merge => self.merge = successor,
            InvocationOwnershipScope::Local(node) if node == self.local_node() => {
                self.local = successor;
            }
            InvocationOwnershipScope::Local(_) => {
                return Err(InvocationIndexError::ScopeMismatch);
            }
        }
        Ok(mutation)
    }

    fn opened(
        &self,
        scope: InvocationOwnershipScope,
    ) -> Result<&OpenedInvocationIndex, InvocationIndexError<S::Error>> {
        match scope {
            InvocationOwnershipScope::Ordered => Ok(&self.ordered),
            InvocationOwnershipScope::Merge => Ok(&self.merge),
            InvocationOwnershipScope::Local(node) if node == self.local_node() => Ok(&self.local),
            InvocationOwnershipScope::Local(_) => Err(InvocationIndexError::ScopeMismatch),
        }
    }
}

impl<S: InvocationIndexStore> super::replay::InvocationOwnership for InvocationIndex<'_, S> {
    fn lookup(
        &self,
        key: InvocationOwnershipKey,
    ) -> Result<Option<InvocationOwnershipValue>, super::replay::InvocationOwnershipError> {
        InvocationIndex::lookup(self, key).map_err(map_replay_error)
    }

    fn record(
        &mut self,
        key: InvocationOwnershipKey,
        value: InvocationOwnershipValue,
    ) -> Result<(), super::replay::InvocationOwnershipError> {
        InvocationIndex::record(self, key, value)
            .map(|_| ())
            .map_err(map_replay_error)
    }

    fn index_id(
        &self,
        scope: InvocationOwnershipScope,
    ) -> Result<InvocationIndexId, super::replay::InvocationOwnershipError> {
        if scope == self.manifest.scope {
            Ok(self.id)
        } else {
            Err(super::replay::InvocationOwnershipError::Unauthenticated)
        }
    }
}

impl<S: InvocationIndexStore> super::replay::InvocationOwnership for InvocationIndexes<'_, S> {
    fn lookup(
        &self,
        key: InvocationOwnershipKey,
    ) -> Result<Option<InvocationOwnershipValue>, super::replay::InvocationOwnershipError> {
        InvocationIndexes::lookup(self, key).map_err(map_replay_error)
    }

    fn record(
        &mut self,
        key: InvocationOwnershipKey,
        value: InvocationOwnershipValue,
    ) -> Result<(), super::replay::InvocationOwnershipError> {
        InvocationIndexes::record(self, key, value)
            .map(|_| ())
            .map_err(map_replay_error)
    }

    fn index_id(
        &self,
        scope: InvocationOwnershipScope,
    ) -> Result<InvocationIndexId, super::replay::InvocationOwnershipError> {
        InvocationIndexes::index_id(self, scope).map_err(map_replay_error)
    }
}

fn lookup_in_manifest<S: InvocationIndexStore>(
    store: &S,
    manifest: &InvocationIndexManifest,
    key: InvocationOwnershipKey,
) -> Result<Option<InvocationOwnershipValue>, InvocationIndexError<S::Error>> {
    lookup_leaf_in_manifest(store, manifest, key).map(|leaf| leaf.map(|leaf| leaf.owner))
}

fn lookup_leaf_in_manifest<S: InvocationIndexStore>(
    store: &S,
    manifest: &InvocationIndexManifest,
    key: InvocationOwnershipKey,
) -> Result<Option<InvocationOwnershipLeaf>, InvocationIndexError<S::Error>> {
    key.validate()
        .map_err(|_| InvocationIndexError::NonCanonicalTree)?;
    if key.scope != manifest.scope {
        return Err(InvocationIndexError::ScopeMismatch);
    }
    let Some(mut current) = manifest.root else {
        return Ok(None);
    };
    let mut parent_bit = None;
    let mut branches = 0usize;
    let mut expected_summary = None;
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(current) {
            return Err(InvocationIndexError::Cycle);
        }
        let node = load_node(store, current)?;
        validate_context(&node, manifest.genesis, manifest.scope)?;
        validate_path_summary(&node, expected_summary, branches == 0, manifest)?;
        match node {
            InvocationIndexNode::Leaf(leaf) => {
                return Ok((leaf.key == key).then_some(leaf));
            }
            InvocationIndexNode::Branch {
                bit,
                prefix,
                left,
                right,
                ..
            } => {
                enforce_increasing_bit(parent_bit, bit)?;
                branches = branches
                    .checked_add(1)
                    .ok_or(InvocationIndexError::PathLimit)?;
                if branches > MAX_INVOCATION_INDEX_PATH {
                    return Err(InvocationIndexError::PathLimit);
                }
                let bit = usize::from(bit);
                if prefix_of(&key.invocation.0, bit) != prefix {
                    return Ok(None);
                }
                let child = if bit_at(&key.invocation.0, bit) {
                    right
                } else {
                    left
                };
                current = child.id;
                expected_summary = Some(child.summary);
                parent_bit = Some(bit as u16);
            }
        }
    }
}

fn map_replay_error<E>(error: InvocationIndexError<E>) -> super::replay::InvocationOwnershipError {
    match error {
        InvocationIndexError::Conflict | InvocationIndexError::InvalidTransition => {
            super::replay::InvocationOwnershipError::Conflict
        }
        InvocationIndexError::Storage(_)
        | InvocationIndexError::MissingManifest(_)
        | InvocationIndexError::MissingNode(_)
        | InvocationIndexError::NodeLimit
        | InvocationIndexError::StoreViolation => {
            super::replay::InvocationOwnershipError::Unavailable
        }
        InvocationIndexError::CorruptManifest
        | InvocationIndexError::CorruptNode(_)
        | InvocationIndexError::GenesisMismatch
        | InvocationIndexError::ScopeMismatch
        | InvocationIndexError::SummaryMismatch
        | InvocationIndexError::NonCanonicalTree
        | InvocationIndexError::Cycle
        | InvocationIndexError::SharedNode
        | InvocationIndexError::PathLimit
        | InvocationIndexError::ObjectCollision => {
            super::replay::InvocationOwnershipError::Unauthenticated
        }
    }
}

/// Constant-work authentication for ordinary open and publication paths.
///
/// This validates the manifest identity and the one root node, including its
/// embedded genesis/scope and authenticated aggregate counts. Descendants are
/// intentionally resolved only when their key path is accessed.
pub fn validate_manifest_root<S: InvocationIndexStore>(
    store: &S,
    expected: InvocationIndexId,
    manifest: &InvocationIndexManifest,
) -> Result<(), InvocationIndexError<S::Error>> {
    manifest
        .validate()
        .map_err(|_| InvocationIndexError::CorruptManifest)?;
    if manifest.id() != expected {
        return Err(InvocationIndexError::CorruptManifest);
    }
    let Some(root) = manifest.root else {
        return Ok(());
    };
    let node = load_node(store, root)?;
    validate_context(&node, manifest.genesis, manifest.scope)?;
    validate_path_summary(&node, None, true, manifest)
}

/// Explicit full-tree semantic audit for operator scrub and repair tooling.
///
/// Ordinary recovery, head validation, lookup, and publication must use
/// [`validate_manifest_root`] and path validation instead. The store's node
/// limit is an audit work budget; exceeding it does not invalidate a live
/// index or impose a lifetime entry ceiling. Epoch rollover and garbage
/// collection remain a later QC-governed operation.
pub fn audit_manifest<S: InvocationIndexStore>(
    store: &S,
    expected: InvocationIndexId,
    manifest: &InvocationIndexManifest,
) -> Result<(), InvocationIndexError<S::Error>> {
    validate_manifest_root(store, expected, manifest)?;
    let Some(root) = manifest.root else {
        return Ok(());
    };
    let expected_nodes = manifest
        .entries
        .checked_mul(2)
        .and_then(|value| value.checked_sub(1))
        .ok_or(InvocationIndexError::NodeLimit)?;
    let limit = store.node_limit();
    if limit == 0 || expected_nodes > limit as u64 {
        return Err(InvocationIndexError::NodeLimit);
    }
    let mut visited = BTreeSet::new();
    let mut ancestors = Vec::new();
    let summary = resolve_node(
        store,
        root,
        manifest.genesis,
        manifest.scope,
        None,
        None,
        &mut visited,
        &mut ancestors,
        limit,
    )?;
    if summary.entries != manifest.entries || summary.tombstones != manifest.tombstones {
        return Err(InvocationIndexError::SummaryMismatch);
    }
    if visited.len() as u64 != expected_nodes {
        return Err(InvocationIndexError::NonCanonicalTree);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn resolve_node<S: InvocationIndexStore>(
    store: &S,
    id: InvocationIndexNodeId,
    genesis: AgentJournalGenesisId,
    scope: InvocationOwnershipScope,
    expected: Option<InvocationIndexSummary>,
    parent_bit: Option<u16>,
    visited: &mut BTreeSet<InvocationIndexNodeId>,
    ancestors: &mut Vec<InvocationIndexNodeId>,
    limit: usize,
) -> Result<InvocationIndexSummary, InvocationIndexError<S::Error>> {
    if ancestors.contains(&id) {
        return Err(InvocationIndexError::Cycle);
    }
    if !visited.insert(id) {
        return Err(InvocationIndexError::SharedNode);
    }
    if visited.len() > limit {
        return Err(InvocationIndexError::NodeLimit);
    }
    let bytes = load_node_bytes(store, id)?;
    let node =
        InvocationIndexNode::decode(&bytes).map_err(|_| InvocationIndexError::CorruptNode(id))?;
    // Detect an explicit corrupt back-edge before reporting the necessarily
    // accompanying content-ID mismatch. This keeps cycle diagnostics precise.
    if let InvocationIndexNode::Branch { left, right, .. } = node {
        if left.id == id
            || right.id == id
            || ancestors.contains(&left.id)
            || ancestors.contains(&right.id)
        {
            return Err(InvocationIndexError::Cycle);
        }
    }
    if node.id() != id || node.encode() != bytes {
        return Err(InvocationIndexError::CorruptNode(id));
    }
    validate_context(&node, genesis, scope)?;
    let summary = node
        .summary()
        .map_err(|_| InvocationIndexError::NonCanonicalTree)?;
    if expected.is_some_and(|expected| expected != summary) {
        return Err(InvocationIndexError::SummaryMismatch);
    }
    match node {
        InvocationIndexNode::Leaf(_) => Ok(summary),
        InvocationIndexNode::Branch {
            bit, left, right, ..
        } => {
            enforce_increasing_bit(parent_bit, bit)?;
            if ancestors.len() >= MAX_INVOCATION_INDEX_PATH {
                return Err(InvocationIndexError::PathLimit);
            }
            ancestors.push(id);
            let left_summary = resolve_node(
                store,
                left.id,
                genesis,
                scope,
                Some(left.summary),
                Some(bit),
                visited,
                ancestors,
                limit,
            )?;
            let right_summary = resolve_node(
                store,
                right.id,
                genesis,
                scope,
                Some(right.summary),
                Some(bit),
                visited,
                ancestors,
                limit,
            )?;
            ancestors.pop();
            if left_summary != left.summary || right_summary != right.summary {
                return Err(InvocationIndexError::SummaryMismatch);
            }
            Ok(summary)
        }
    }
}

/// Verify a membership or nonmembership proof against an independently known
/// manifest identity.
pub fn verify_invocation_index_proof(
    expected: InvocationIndexId,
    key: InvocationOwnershipKey,
    proof: &InvocationIndexProof,
) -> Result<InvocationIndexProofResult, InvocationIndexError<core::convert::Infallible>> {
    key.validate()
        .map_err(|_| InvocationIndexError::NonCanonicalTree)?;
    proof
        .manifest
        .validate()
        .map_err(|_| InvocationIndexError::CorruptManifest)?;
    if proof.manifest.id() != expected {
        return Err(InvocationIndexError::CorruptManifest);
    }
    if proof.manifest.scope != key.scope {
        return Err(InvocationIndexError::ScopeMismatch);
    }
    let Some(mut expected_node) = proof.manifest.root else {
        return if proof.nodes.is_empty() {
            Ok(InvocationIndexProofResult::NonMember)
        } else {
            Err(InvocationIndexError::NonCanonicalTree)
        };
    };
    let mut expected_summary = None;
    let mut parent_bit = None;
    let mut branches = 0usize;
    for (index, node) in proof.nodes.iter().enumerate() {
        node.validate()
            .map_err(|_| InvocationIndexError::NonCanonicalTree)?;
        if node.id() != expected_node {
            return Err(InvocationIndexError::CorruptNode(expected_node));
        }
        validate_context(node, proof.manifest.genesis, proof.manifest.scope)?;
        let summary = node
            .summary()
            .map_err(|_| InvocationIndexError::NonCanonicalTree)?;
        if index == 0
            && (summary.entries != proof.manifest.entries
                || summary.tombstones != proof.manifest.tombstones)
        {
            return Err(InvocationIndexError::SummaryMismatch);
        }
        if expected_summary.is_some_and(|expected| expected != summary) {
            return Err(InvocationIndexError::SummaryMismatch);
        }
        let last = index + 1 == proof.nodes.len();
        match node {
            InvocationIndexNode::Leaf(leaf) => {
                if !last {
                    return Err(InvocationIndexError::NonCanonicalTree);
                }
                return Ok(if leaf.key == key {
                    InvocationIndexProofResult::Member(leaf.owner)
                } else {
                    InvocationIndexProofResult::NonMember
                });
            }
            InvocationIndexNode::Branch {
                bit,
                prefix,
                left,
                right,
                ..
            } => {
                enforce_increasing_bit(parent_bit, *bit)?;
                branches += 1;
                if branches > MAX_INVOCATION_INDEX_PATH {
                    return Err(InvocationIndexError::PathLimit);
                }
                let branch_bit = *bit;
                let bit = usize::from(branch_bit);
                if prefix_of(&key.invocation.0, bit) != *prefix {
                    return if last {
                        Ok(InvocationIndexProofResult::NonMember)
                    } else {
                        Err(InvocationIndexError::NonCanonicalTree)
                    };
                }
                if last {
                    return Err(InvocationIndexError::NonCanonicalTree);
                }
                let child = if bit_at(&key.invocation.0, bit) {
                    *right
                } else {
                    *left
                };
                expected_node = child.id;
                expected_summary = Some(child.summary);
                parent_bit = Some(branch_bit);
            }
        }
    }
    Err(InvocationIndexError::NonCanonicalTree)
}

fn load_manifest<S: InvocationIndexStore>(
    store: &S,
    id: InvocationIndexId,
) -> Result<InvocationIndexManifest, InvocationIndexError<S::Error>> {
    let bytes = store
        .load_manifest(id)
        .map_err(InvocationIndexError::Storage)?
        .ok_or(InvocationIndexError::MissingManifest(id))?;
    if bytes.len() > MAX_INVOCATION_INDEX_MANIFEST_BYTES {
        return Err(InvocationIndexError::CorruptManifest);
    }
    let manifest = InvocationIndexManifest::decode(&bytes)
        .map_err(|_| InvocationIndexError::CorruptManifest)?;
    if manifest.id() != id || manifest.encode() != bytes {
        return Err(InvocationIndexError::CorruptManifest);
    }
    Ok(manifest)
}

fn load_node_bytes<S: InvocationIndexStore>(
    store: &S,
    id: InvocationIndexNodeId,
) -> Result<Vec<u8>, InvocationIndexError<S::Error>> {
    let bytes = store
        .load_node(id)
        .map_err(InvocationIndexError::Storage)?
        .ok_or(InvocationIndexError::MissingNode(id))?;
    if bytes.len() > MAX_INVOCATION_INDEX_NODE_BYTES {
        return Err(InvocationIndexError::CorruptNode(id));
    }
    Ok(bytes)
}

fn load_node<S: InvocationIndexStore>(
    store: &S,
    id: InvocationIndexNodeId,
) -> Result<InvocationIndexNode, InvocationIndexError<S::Error>> {
    let bytes = load_node_bytes(store, id)?;
    let node =
        InvocationIndexNode::decode(&bytes).map_err(|_| InvocationIndexError::CorruptNode(id))?;
    if node.id() != id || node.encode() != bytes {
        return Err(InvocationIndexError::CorruptNode(id));
    }
    Ok(node)
}

fn put_manifest_immutable<S: InvocationIndexStore>(
    store: &mut S,
    manifest: &InvocationIndexManifest,
) -> Result<InvocationIndexId, InvocationIndexError<S::Error>> {
    manifest
        .validate()
        .map_err(|_| InvocationIndexError::CorruptManifest)?;
    let id = manifest.id();
    let bytes = manifest.encode();
    if let Some(existing) = store
        .load_manifest(id)
        .map_err(InvocationIndexError::Storage)?
    {
        if existing != bytes {
            return Err(InvocationIndexError::ObjectCollision);
        }
        return Ok(id);
    }
    store
        .put_manifest(id, &bytes)
        .map_err(InvocationIndexError::Storage)?;
    match store
        .load_manifest(id)
        .map_err(InvocationIndexError::Storage)?
    {
        Some(installed) if installed == bytes => Ok(id),
        _ => Err(InvocationIndexError::StoreViolation),
    }
}

fn put_node_immutable<S: InvocationIndexStore>(
    store: &mut S,
    node: &InvocationIndexNode,
) -> Result<InvocationIndexChild, InvocationIndexError<S::Error>> {
    node.validate()
        .map_err(|_| InvocationIndexError::NonCanonicalTree)?;
    let id = node.id();
    let bytes = node.encode();
    if let Some(existing) = store.load_node(id).map_err(InvocationIndexError::Storage)? {
        if existing != bytes {
            return Err(InvocationIndexError::ObjectCollision);
        }
    } else {
        store
            .put_node(id, &bytes)
            .map_err(InvocationIndexError::Storage)?;
        match store.load_node(id).map_err(InvocationIndexError::Storage)? {
            Some(installed) if installed == bytes => {}
            _ => return Err(InvocationIndexError::StoreViolation),
        }
    }
    child_for(id, node)
}

fn child_for<E>(
    id: InvocationIndexNodeId,
    node: &InvocationIndexNode,
) -> Result<InvocationIndexChild, InvocationIndexError<E>> {
    Ok(InvocationIndexChild {
        id,
        summary: node
            .summary()
            .map_err(|_| InvocationIndexError::NonCanonicalTree)?,
    })
}

fn validate_context<E>(
    node: &InvocationIndexNode,
    genesis: AgentJournalGenesisId,
    scope: InvocationOwnershipScope,
) -> Result<(), InvocationIndexError<E>> {
    if node.genesis() != genesis {
        return Err(InvocationIndexError::GenesisMismatch);
    }
    if node.scope() != scope {
        return Err(InvocationIndexError::ScopeMismatch);
    }
    Ok(())
}

fn validate_path_summary<E>(
    node: &InvocationIndexNode,
    expected: Option<InvocationIndexSummary>,
    root: bool,
    manifest: &InvocationIndexManifest,
) -> Result<(), InvocationIndexError<E>> {
    let summary = node
        .summary()
        .map_err(|_| InvocationIndexError::NonCanonicalTree)?;
    if expected.is_some_and(|expected| expected != summary)
        || (root
            && (summary.entries != manifest.entries || summary.tombstones != manifest.tombstones))
    {
        return Err(InvocationIndexError::SummaryMismatch);
    }
    Ok(())
}

fn acknowledged_successor(
    existing: &InvocationOwnershipLeaf,
    next: &InvocationOwnershipLeaf,
) -> bool {
    let mut expected = *existing;
    expected.owner.result_state = InvocationResultState::Acknowledged;
    existing.owner.result_state == InvocationResultState::Retained && expected == *next
}

fn enforce_increasing_bit<E>(parent: Option<u16>, bit: u16) -> Result<(), InvocationIndexError<E>> {
    if usize::from(bit) >= 256 || parent.is_some_and(|parent| bit <= parent) {
        Err(InvocationIndexError::NonCanonicalTree)
    } else {
        Ok(())
    }
}

fn encode_scope(encoder: &mut Encoder<'_>, scope: InvocationOwnershipScope) {
    match scope {
        InvocationOwnershipScope::Ordered => encoder.u8(0),
        InvocationOwnershipScope::Merge => encoder.u8(1),
        InvocationOwnershipScope::Local(node) => {
            encoder.u8(2);
            encoder.fixed(&node.0);
        }
    }
}

fn decode_scope(decoder: &mut Decoder<'_>) -> Result<InvocationOwnershipScope, DecodeError> {
    let scope = match decoder.u8()? {
        0 => InvocationOwnershipScope::Ordered,
        1 => InvocationOwnershipScope::Merge,
        2 => InvocationOwnershipScope::Local(NodeId(decoder.fixed()?)),
        _ => return Err(DecodeError::InvalidTag),
    };
    scope.validate()?;
    Ok(scope)
}

fn encode_child(encoder: &mut Encoder<'_>, child: InvocationIndexChild) {
    encoder.fixed(&child.id.0);
    encoder.fixed(&child.summary.min.0);
    encoder.fixed(&child.summary.max.0);
    encoder.u64(child.summary.entries);
    encoder.u64(child.summary.tombstones);
}

fn decode_child(decoder: &mut Decoder<'_>) -> Result<InvocationIndexChild, DecodeError> {
    let child = InvocationIndexChild {
        id: InvocationIndexNodeId(decoder.fixed()?),
        summary: InvocationIndexSummary {
            min: InvocationId(decoder.fixed()?),
            max: InvocationId(decoder.fixed()?),
            entries: decoder.u64()?,
            tombstones: decoder.u64()?,
        },
    };
    child.validate()?;
    Ok(child)
}

fn summary_matches_partition(
    summary: InvocationIndexSummary,
    prefix: &[u8; 32],
    bit: usize,
    right: bool,
) -> bool {
    prefix_of(&summary.min.0, bit) == *prefix
        && prefix_of(&summary.max.0, bit) == *prefix
        && bit_at(&summary.min.0, bit) == right
        && bit_at(&summary.max.0, bit) == right
}

fn prefix_of(position: &[u8; 32], bit: usize) -> [u8; 32] {
    debug_assert!(bit <= 256);
    let mut prefix = [0; 32];
    let full_bytes = bit / 8;
    prefix[..full_bytes].copy_from_slice(&position[..full_bytes]);
    if bit % 8 != 0 {
        let mask = !(0xffu8 >> (bit % 8));
        prefix[full_bytes] = position[full_bytes] & mask;
    }
    prefix
}

fn bit_at(position: &[u8; 32], bit: usize) -> bool {
    position[bit / 8] & (1 << (7 - bit % 8)) != 0
}

fn first_differing_bit(left: &[u8; 32], right: &[u8; 32]) -> Option<usize> {
    (0..256).find(|bit| bit_at(left, *bit) != bit_at(right, *bit))
}

/// Immutable no-filesystem reference store for replay and adapter tests.
#[derive(Clone, Debug)]
pub struct MemoryInvocationIndexStore {
    node_limit: usize,
    manifests: BTreeMap<InvocationIndexId, Vec<u8>>,
    nodes: BTreeMap<InvocationIndexNodeId, Vec<u8>>,
}

impl Default for MemoryInvocationIndexStore {
    fn default() -> Self {
        Self::with_node_limit(DEFAULT_INVOCATION_INDEX_NODE_LIMIT)
    }
}

impl MemoryInvocationIndexStore {
    pub fn with_node_limit(node_limit: usize) -> Self {
        Self {
            node_limit,
            manifests: BTreeMap::new(),
            nodes: BTreeMap::new(),
        }
    }

    pub fn manifest_count(&self) -> usize {
        self.manifests.len()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryInvocationIndexStoreError {
    ImmutableConflict,
    Oversized,
}

impl InvocationIndexStore for MemoryInvocationIndexStore {
    type Error = MemoryInvocationIndexStoreError;

    fn node_limit(&self) -> usize {
        self.node_limit
    }

    fn load_manifest(&self, id: InvocationIndexId) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.manifests.get(&id).cloned())
    }

    fn load_node(&self, id: InvocationIndexNodeId) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.nodes.get(&id).cloned())
    }

    fn put_manifest(&mut self, id: InvocationIndexId, bytes: &[u8]) -> Result<(), Self::Error> {
        if bytes.len() > MAX_INVOCATION_INDEX_MANIFEST_BYTES {
            return Err(MemoryInvocationIndexStoreError::Oversized);
        }
        match self.manifests.get(&id) {
            Some(existing) if existing.as_slice() == bytes => Ok(()),
            Some(_) => Err(MemoryInvocationIndexStoreError::ImmutableConflict),
            None => {
                self.manifests.insert(id, bytes.to_vec());
                Ok(())
            }
        }
    }

    fn put_node(&mut self, id: InvocationIndexNodeId, bytes: &[u8]) -> Result<(), Self::Error> {
        if bytes.len() > MAX_INVOCATION_INDEX_NODE_BYTES {
            return Err(MemoryInvocationIndexStoreError::Oversized);
        }
        match self.nodes.get(&id) {
            Some(existing) if existing.as_slice() == bytes => Ok(()),
            Some(_) => Err(MemoryInvocationIndexStoreError::ImmutableConflict),
            None => {
                self.nodes.insert(id, bytes.to_vec());
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::rc::Rc;
    use alloc::vec;
    use core::cell::Cell;

    use super::*;
    use crate::agent::journal::{
        InvocationDisposition, InvocationOwner, PersistedLane, ReplayInputId,
    };

    fn genesis(seed: u8) -> AgentJournalGenesisId {
        AgentJournalGenesisId([seed; 32])
    }

    fn invocation(bytes: [u8; 32]) -> InvocationId {
        InvocationId(bytes)
    }

    fn key(scope: InvocationOwnershipScope, id: InvocationId) -> InvocationOwnershipKey {
        InvocationOwnershipKey {
            scope,
            invocation: id,
        }
    }

    fn owner(
        scope: InvocationOwnershipScope,
        id: InvocationId,
        result_state: InvocationResultState,
    ) -> InvocationOwnershipValue {
        let terminal = result_state == InvocationResultState::Terminal;
        InvocationOwner {
            scope,
            request_commitment: Hash::digest(b"index-test-request", &[&id.0]),
            first_input: ReplayInputId(Hash::digest(b"index-test-input", &[&id.0]).0),
            lane: match scope {
                InvocationOwnershipScope::Ordered => PersistedLane::Linear,
                InvocationOwnershipScope::Merge => PersistedLane::Merge,
                InvocationOwnershipScope::Local(_) => PersistedLane::Local,
            },
            node: match scope {
                InvocationOwnershipScope::Local(node) => Some(node),
                _ => None,
            },
            disposition: if terminal {
                InvocationDisposition::Rejected
            } else {
                InvocationDisposition::Applied
            },
            result_state,
        }
    }

    fn ids(count: usize) -> Vec<InvocationId> {
        (0..count)
            .map(|index| {
                InvocationId(Hash::digest(b"index-test-key", &[&(index as u64).to_be_bytes()]).0)
            })
            .collect()
    }

    fn maximum_depth_ids() -> Vec<InvocationId> {
        // A leading zero bit ensures the bit-zero neighbour is nonzero after
        // its remaining suffix is cleared.
        let target = invocation([0x55; 32]);
        let mut all = vec![target];
        for bit in 0..256 {
            let mut bytes = target.0;
            let byte = bit / 8;
            bytes[byte] ^= 1 << (7 - bit % 8);
            for suffix_bit in bit + 1..256 {
                bytes[suffix_bit / 8] &= !(1 << (7 - suffix_bit % 8));
            }
            if bytes == [0; 32] {
                bytes[31] = 1;
            }
            all.push(invocation(bytes));
        }
        all
    }

    fn build(
        order: &[InvocationId],
    ) -> (
        MemoryInvocationIndexStore,
        InvocationIndexId,
        InvocationIndexManifest,
    ) {
        let scope = InvocationOwnershipScope::Ordered;
        let mut store = MemoryInvocationIndexStore::default();
        let empty = InvocationIndex::<MemoryInvocationIndexStore>::create_empty(
            &mut store,
            genesis(1),
            scope,
        )
        .unwrap();
        let id = {
            let mut index = InvocationIndex::open(&mut store, empty).unwrap();
            for invocation in order {
                assert!(matches!(
                    index
                        .record(
                            key(scope, *invocation),
                            owner(scope, *invocation, InvocationResultState::Retained),
                        )
                        .unwrap(),
                    InvocationIndexMutation::Inserted(_)
                ));
            }
            index.id()
        };
        let manifest = load_manifest(&store, id).unwrap();
        (store, id, manifest)
    }

    #[test]
    fn node_codec_is_canonical_and_uses_reserved_class() {
        let scope = InvocationOwnershipScope::Ordered;
        let id = invocation([0x42; 32]);
        let node = InvocationIndexNode::Leaf(InvocationOwnershipLeaf {
            genesis: genesis(1),
            key: key(scope, id),
            owner: owner(scope, id, InvocationResultState::Retained),
        });
        assert_eq!(
            InvocationIndexNode::STORAGE_CLASS,
            JournalStorageClass::InvocationIndexNode
        );
        assert_eq!(InvocationIndexNode::decode(&node.encode()).unwrap(), node);
        assert_ne!(node.id(), InvocationIndexNodeId::ZERO);

        let mut trailing = node.encode();
        trailing.push(0);
        assert_eq!(
            InvocationIndexNode::decode(&trailing),
            Err(DecodeError::TrailingBytes)
        );
    }

    #[test]
    fn insertion_order_produces_one_canonical_root() {
        let ascending = ids(64);
        let mut descending = ascending.clone();
        descending.reverse();
        let mut interleaved = Vec::new();
        for offset in 0..32 {
            interleaved.push(ascending[offset]);
            interleaved.push(ascending[63 - offset]);
        }
        let (_, ascending_id, ascending_manifest) = build(&ascending);
        let (_, descending_id, descending_manifest) = build(&descending);
        let (_, interleaved_id, interleaved_manifest) = build(&interleaved);
        assert_eq!(ascending_manifest.root, descending_manifest.root);
        assert_eq!(ascending_manifest.root, interleaved_manifest.root);
        assert_eq!(ascending_id, descending_id);
        assert_eq!(ascending_id, interleaved_id);
    }

    #[test]
    fn first_owner_exact_retry_and_divergence_are_distinct() {
        let scope = InvocationOwnershipScope::Ordered;
        let id = invocation([7; 32]);
        let mut store = MemoryInvocationIndexStore::default();
        let empty = InvocationIndex::<MemoryInvocationIndexStore>::create_empty(
            &mut store,
            genesis(1),
            scope,
        )
        .unwrap();
        let mut index = InvocationIndex::open(&mut store, empty).unwrap();
        let value = owner(scope, id, InvocationResultState::Retained);
        assert!(matches!(
            index.record(key(scope, id), value).unwrap(),
            InvocationIndexMutation::Inserted(_)
        ));
        let installed = index.id();
        assert_eq!(
            index.record(key(scope, id), value).unwrap(),
            InvocationIndexMutation::ExactRetry(installed)
        );
        let mut divergent = value;
        divergent.request_commitment = Hash([0xdd; 32]);
        assert!(matches!(
            index.record(key(scope, id), divergent),
            Err(InvocationIndexError::Conflict)
        ));
        assert_eq!(index.id(), installed);
        assert_eq!(index.lookup(key(scope, id)).unwrap(), Some(value));
    }

    #[test]
    fn acknowledgement_is_the_only_update_and_tombstones_persist() {
        let scope = InvocationOwnershipScope::Ordered;
        let id = invocation([8; 32]);
        let mut store = MemoryInvocationIndexStore::default();
        let empty = InvocationIndex::<MemoryInvocationIndexStore>::create_empty(
            &mut store,
            genesis(1),
            scope,
        )
        .unwrap();
        let final_id = {
            let mut index = InvocationIndex::open(&mut store, empty).unwrap();
            let retained = owner(scope, id, InvocationResultState::Retained);
            index.record(key(scope, id), retained).unwrap();
            let mut acknowledged = retained;
            acknowledged.result_state = InvocationResultState::Acknowledged;
            assert!(matches!(
                index.record(key(scope, id), acknowledged).unwrap(),
                InvocationIndexMutation::Acknowledged(_)
            ));
            let acknowledged_id = index.id();
            assert_eq!(
                index.record(key(scope, id), acknowledged).unwrap(),
                InvocationIndexMutation::ExactRetry(acknowledged_id)
            );
            assert!(matches!(
                index.record(key(scope, id), retained),
                Err(InvocationIndexError::Conflict)
            ));
            assert_eq!(index.lookup(key(scope, id)).unwrap(), Some(acknowledged));
            assert_eq!(index.manifest().entries, 1);
            assert_eq!(index.manifest().tombstones, 1);
            index.id()
        };
        let reopened = InvocationIndex::open(&mut store, final_id).unwrap();
        assert_eq!(reopened.manifest().tombstones, 1);
    }

    #[test]
    fn terminal_owner_can_never_be_acknowledged_or_replaced() {
        let scope = InvocationOwnershipScope::Merge;
        let id = invocation([9; 32]);
        let mut store = MemoryInvocationIndexStore::default();
        let empty = InvocationIndex::<MemoryInvocationIndexStore>::create_empty(
            &mut store,
            genesis(1),
            scope,
        )
        .unwrap();
        let mut index = InvocationIndex::open(&mut store, empty).unwrap();
        let terminal = owner(scope, id, InvocationResultState::Terminal);
        index.record(key(scope, id), terminal).unwrap();
        assert_eq!(index.manifest().tombstones, 1);
        let mut illegal = terminal;
        illegal.result_state = InvocationResultState::Acknowledged;
        illegal.disposition = InvocationDisposition::Applied;
        assert!(matches!(
            index.record(key(scope, id), illegal),
            Err(InvocationIndexError::Conflict)
        ));
        assert_eq!(index.lookup(key(scope, id)).unwrap(), Some(terminal));
    }

    #[test]
    fn roots_cannot_be_transplanted_across_genesis_or_scope() {
        let (mut store, _, original) = build(&[invocation([0x33; 32])]);
        let wrong_genesis = InvocationIndexManifest {
            genesis: genesis(2),
            ..original
        };
        let wrong_genesis_id = put_manifest_immutable(&mut store, &wrong_genesis).unwrap();
        assert!(matches!(
            InvocationIndex::open(&mut store, wrong_genesis_id),
            Err(InvocationIndexError::GenesisMismatch)
        ));

        let wrong_scope = InvocationIndexManifest {
            scope: InvocationOwnershipScope::Merge,
            ..original
        };
        let wrong_scope_id = put_manifest_immutable(&mut store, &wrong_scope).unwrap();
        assert!(matches!(
            InvocationIndex::open(&mut store, wrong_scope_id),
            Err(InvocationIndexError::ScopeMismatch)
        ));
    }

    #[test]
    fn corrupt_missing_child_summary_and_branch_bit_are_rejected() {
        let values = [
            invocation([0x10; 32]),
            invocation([0x40; 32]),
            invocation([0x80; 32]),
        ];
        let (store, id, manifest) = build(&values);
        let root = manifest.root.unwrap();

        let mut corrupt_bytes = store.clone();
        corrupt_bytes.nodes.get_mut(&root).unwrap()[40] ^= 0x80;
        assert!(matches!(
            InvocationIndex::open(&mut corrupt_bytes, id),
            Err(InvocationIndexError::CorruptNode(found)) if found == root
        ));

        let mut missing_root = store.clone();
        missing_root.nodes.remove(&root);
        assert!(matches!(
            InvocationIndex::open(&mut missing_root, id),
            Err(InvocationIndexError::MissingNode(found)) if found == root
        ));

        let root_node = load_node(&store, root).unwrap();
        let InvocationIndexNode::Branch {
            genesis,
            scope,
            bit,
            prefix,
            mut left,
            right,
        } = root_node
        else {
            panic!("three leaves must have a branch root");
        };
        let mut bad_summary_store = store.clone();
        left.summary.entries += 1;
        let bad_summary_node = InvocationIndexNode::Branch {
            genesis,
            scope,
            bit,
            prefix,
            left,
            right,
        };
        let bad_summary_root = put_node_immutable(&mut bad_summary_store, &bad_summary_node)
            .unwrap()
            .id;
        let bad_summary_manifest = InvocationIndexManifest {
            root: Some(bad_summary_root),
            entries: manifest.entries + 1,
            ..manifest
        };
        let bad_summary_id =
            put_manifest_immutable(&mut bad_summary_store, &bad_summary_manifest).unwrap();
        {
            let index = InvocationIndex::open(&mut bad_summary_store, bad_summary_id).unwrap();
            assert!(matches!(
                index.lookup(key(scope, values[0])),
                Err(InvocationIndexError::SummaryMismatch)
            ));
        }
        assert!(matches!(
            audit_manifest(&bad_summary_store, bad_summary_id, &bad_summary_manifest),
            Err(InvocationIndexError::SummaryMismatch)
        ));

        let mut missing_child_store = store.clone();
        let mut missing_left = left;
        missing_left.summary.entries -= 1;
        missing_left.id = InvocationIndexNodeId([0xee; 32]);
        let missing_child_node = InvocationIndexNode::Branch {
            genesis,
            scope,
            bit,
            prefix,
            left: missing_left,
            right,
        };
        let missing_child_root = put_node_immutable(&mut missing_child_store, &missing_child_node)
            .unwrap()
            .id;
        let missing_child_manifest = InvocationIndexManifest {
            root: Some(missing_child_root),
            ..manifest
        };
        let missing_child_id =
            put_manifest_immutable(&mut missing_child_store, &missing_child_manifest).unwrap();
        {
            let index = InvocationIndex::open(&mut missing_child_store, missing_child_id).unwrap();
            assert!(matches!(
                index.lookup(key(scope, values[0])),
                Err(InvocationIndexError::MissingNode(found)) if found == missing_left.id
            ));
        }

        let mut bad_bit_store = store.clone();
        let actual_child_id = match root_node {
            InvocationIndexNode::Branch { left, .. } => left.id,
            _ => unreachable!(),
        };
        let child = load_node(&bad_bit_store, actual_child_id).unwrap();
        let InvocationIndexNode::Branch {
            genesis,
            scope,
            prefix,
            left,
            right,
            ..
        } = child
        else {
            panic!("selected child must be a branch");
        };
        let bad_bit = InvocationIndexNode::Branch {
            genesis,
            scope,
            bit: 0,
            prefix,
            left,
            right,
        };
        bad_bit_store
            .nodes
            .insert(actual_child_id, bad_bit.encode());
        {
            let index = InvocationIndex::open(&mut bad_bit_store, id).unwrap();
            assert!(matches!(
                index.lookup(key(scope, values[0])),
                Err(InvocationIndexError::CorruptNode(found)) if found == actual_child_id
            ));
        }
    }

    #[test]
    fn unrelated_subtree_corruption_is_lazy_until_access_or_audit() {
        let scope = InvocationOwnershipScope::Ordered;
        let left_key = invocation([0x10; 32]);
        let right_key = invocation([0x80; 32]);
        let (mut store, id, manifest) = build(&[left_key, right_key]);
        let root = load_node(&store, manifest.root.unwrap()).unwrap();
        let InvocationIndexNode::Branch { right, .. } = root else {
            panic!("two distinct keys require a branch");
        };
        store.nodes.get_mut(&right.id).unwrap()[40] ^= 0x40;

        {
            let index = InvocationIndex::open(&mut store, id).unwrap();
            assert!(index.lookup(key(scope, left_key)).unwrap().is_some());
            assert!(matches!(
                index.lookup(key(scope, right_key)),
                Err(InvocationIndexError::CorruptNode(found)) if found == right.id
            ));
        }
        assert!(matches!(
            audit_manifest(&store, id, &manifest),
            Err(InvocationIndexError::CorruptNode(found)) if found == right.id
        ));
    }

    #[test]
    fn explicit_corrupt_back_edge_reports_cycle() {
        let scope = InvocationOwnershipScope::Ordered;
        let genesis = genesis(1);
        let mut store = MemoryInvocationIndexStore::default();
        let left_key = invocation([0x10; 32]);
        let middle_key = invocation([0x40; 32]);
        let right_key = invocation([0x80; 32]);
        let middle = InvocationIndexNode::Leaf(InvocationOwnershipLeaf {
            genesis,
            key: key(scope, middle_key),
            owner: owner(scope, middle_key, InvocationResultState::Retained),
        });
        let right = InvocationIndexNode::Leaf(InvocationOwnershipLeaf {
            genesis,
            key: key(scope, right_key),
            owner: owner(scope, right_key, InvocationResultState::Retained),
        });
        let middle_ref = put_node_immutable(&mut store, &middle).unwrap();
        let right_ref = put_node_immutable(&mut store, &right).unwrap();
        let fake_cycle_id = InvocationIndexNodeId([0x55; 32]);
        let cycle_summary = InvocationIndexSummary {
            min: left_key,
            max: middle_key,
            entries: 2,
            tombstones: 0,
        };
        let root_node = InvocationIndexNode::Branch {
            genesis,
            scope,
            bit: 0,
            prefix: [0; 32],
            left: InvocationIndexChild {
                id: fake_cycle_id,
                summary: cycle_summary,
            },
            right: right_ref,
        };
        let root_ref = put_node_immutable(&mut store, &root_node).unwrap();
        let cycle_node = InvocationIndexNode::Branch {
            genesis,
            scope,
            bit: 1,
            prefix: [0; 32],
            left: InvocationIndexChild {
                id: root_ref.id,
                summary: InvocationIndexSummary {
                    min: left_key,
                    max: left_key,
                    entries: 1,
                    tombstones: 0,
                },
            },
            right: middle_ref,
        };
        cycle_node.validate().unwrap();
        store.nodes.insert(fake_cycle_id, cycle_node.encode());
        let manifest = InvocationIndexManifest {
            genesis,
            scope,
            root: Some(root_ref.id),
            entries: 3,
            tombstones: 0,
        };
        let id = put_manifest_immutable(&mut store, &manifest).unwrap();
        InvocationIndex::open(&mut store, id).unwrap();
        assert!(matches!(
            audit_manifest(&store, id, &manifest),
            Err(InvocationIndexError::Cycle)
        ));
    }

    #[test]
    fn membership_and_nonmembership_proofs_verify_and_detect_truncation() {
        let values = [
            invocation([0x10; 32]),
            invocation([0x40; 32]),
            invocation([0x80; 32]),
        ];
        let (mut store, id, _) = build(&values);
        let index = InvocationIndex::open(&mut store, id).unwrap();
        for value in values {
            let proof = index
                .prove(key(InvocationOwnershipScope::Ordered, value))
                .unwrap();
            assert_eq!(
                verify_invocation_index_proof(
                    id,
                    key(InvocationOwnershipScope::Ordered, value),
                    &proof,
                )
                .unwrap(),
                InvocationIndexProofResult::Member(owner(
                    InvocationOwnershipScope::Ordered,
                    value,
                    InvocationResultState::Retained,
                ))
            );
        }
        for absent in [invocation([0x20; 32]), invocation([0xf0; 32])] {
            let proof = index
                .prove(key(InvocationOwnershipScope::Ordered, absent))
                .unwrap();
            assert_eq!(
                verify_invocation_index_proof(
                    id,
                    key(InvocationOwnershipScope::Ordered, absent),
                    &proof,
                )
                .unwrap(),
                InvocationIndexProofResult::NonMember
            );
        }
        let query = key(InvocationOwnershipScope::Ordered, values[0]);
        let mut truncated = index.prove(query).unwrap();
        truncated.nodes.pop();
        assert!(verify_invocation_index_proof(id, query, &truncated).is_err());

        let empty = InvocationIndexManifest::empty(genesis(9), InvocationOwnershipScope::Merge);
        let empty_proof = InvocationIndexProof {
            manifest: empty,
            nodes: Vec::new(),
        };
        assert_eq!(
            verify_invocation_index_proof(
                empty.id(),
                key(InvocationOwnershipScope::Merge, invocation([1; 32])),
                &empty_proof,
            )
            .unwrap(),
            InvocationIndexProofResult::NonMember
        );
    }

    #[test]
    fn last_bit_split_and_full_256_branch_path_are_supported() {
        let left = invocation({
            let mut bytes = [0; 32];
            bytes[31] = 2;
            bytes
        });
        let right = invocation({
            let mut bytes = [0; 32];
            bytes[31] = 3;
            bytes
        });
        let (mut store, id, manifest) = build(&[left, right]);
        let root = load_node(&store, manifest.root.unwrap()).unwrap();
        assert!(matches!(root, InvocationIndexNode::Branch { bit: 255, .. }));
        let index = InvocationIndex::open(&mut store, id).unwrap();
        assert!(
            index
                .lookup(key(InvocationOwnershipScope::Ordered, left))
                .unwrap()
                .is_some()
        );
        assert!(
            index
                .lookup(key(InvocationOwnershipScope::Ordered, right))
                .unwrap()
                .is_some()
        );

        let all = maximum_depth_ids();
        let target = all[0];
        let (mut deep_store, deep_id, _) = build(&all);
        let deep = InvocationIndex::open(&mut deep_store, deep_id).unwrap();
        let proof = deep
            .prove(key(InvocationOwnershipScope::Ordered, target))
            .unwrap();
        assert_eq!(proof.nodes.len(), MAX_INVOCATION_INDEX_PATH + 1);
        assert!(matches!(
            verify_invocation_index_proof(
                deep_id,
                key(InvocationOwnershipScope::Ordered, target),
                &proof,
            ),
            Ok(InvocationIndexProofResult::Member(_))
        ));
    }

    #[test]
    fn open_lookup_and_update_are_bounded_by_one_256_bit_path() {
        let all = maximum_depth_ids();
        let target = all[0];
        let (inner, id, _) = build(&all);
        let counts = Rc::new(OperationCounts::default());
        let mut store = CountingStore {
            inner,
            counts: Rc::clone(&counts),
        };
        let mut index = InvocationIndex::open(&mut store, id).unwrap();
        assert_eq!(counts.manifest_loads.get(), 1);
        assert_eq!(counts.node_loads.get(), 1, "open authenticates only root");

        counts.node_loads.set(0);
        assert!(
            index
                .lookup(key(InvocationOwnershipScope::Ordered, target))
                .unwrap()
                .is_some()
        );
        assert_eq!(counts.node_loads.get(), MAX_INVOCATION_INDEX_PATH + 1);

        counts.node_loads.set(0);
        counts.node_puts.set(0);
        let mut acknowledged = owner(
            InvocationOwnershipScope::Ordered,
            target,
            InvocationResultState::Retained,
        );
        acknowledged.result_state = InvocationResultState::Acknowledged;
        index
            .record(key(InvocationOwnershipScope::Ordered, target), acknowledged)
            .unwrap();
        assert!(counts.node_loads.get() <= 4 * (MAX_INVOCATION_INDEX_PATH + 1));
        assert!(counts.node_puts.get() <= MAX_INVOCATION_INDEX_PATH + 1);
        assert_eq!(index.manifest().entries, all.len() as u64);
    }

    #[derive(Default)]
    struct OperationCounts {
        manifest_loads: Cell<usize>,
        node_loads: Cell<usize>,
        manifest_puts: Cell<usize>,
        node_puts: Cell<usize>,
    }

    struct CountingStore {
        inner: MemoryInvocationIndexStore,
        counts: Rc<OperationCounts>,
    }

    impl InvocationIndexStore for CountingStore {
        type Error = MemoryInvocationIndexStoreError;

        fn node_limit(&self) -> usize {
            self.inner.node_limit()
        }

        fn load_manifest(&self, id: InvocationIndexId) -> Result<Option<Vec<u8>>, Self::Error> {
            self.counts
                .manifest_loads
                .set(self.counts.manifest_loads.get() + 1);
            self.inner.load_manifest(id)
        }

        fn load_node(&self, id: InvocationIndexNodeId) -> Result<Option<Vec<u8>>, Self::Error> {
            self.counts.node_loads.set(self.counts.node_loads.get() + 1);
            self.inner.load_node(id)
        }

        fn put_manifest(&mut self, id: InvocationIndexId, bytes: &[u8]) -> Result<(), Self::Error> {
            self.counts
                .manifest_puts
                .set(self.counts.manifest_puts.get() + 1);
            self.inner.put_manifest(id, bytes)
        }

        fn put_node(&mut self, id: InvocationIndexNodeId, bytes: &[u8]) -> Result<(), Self::Error> {
            self.counts.node_puts.set(self.counts.node_puts.get() + 1);
            self.inner.put_node(id, bytes)
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum InjectedStoreError {
        Injected,
        Inner(MemoryInvocationIndexStoreError),
    }

    struct FailingManifestStore {
        inner: MemoryInvocationIndexStore,
        fail_manifest: bool,
    }

    impl InvocationIndexStore for FailingManifestStore {
        type Error = InjectedStoreError;

        fn node_limit(&self) -> usize {
            self.inner.node_limit()
        }

        fn load_manifest(&self, id: InvocationIndexId) -> Result<Option<Vec<u8>>, Self::Error> {
            self.inner
                .load_manifest(id)
                .map_err(InjectedStoreError::Inner)
        }

        fn load_node(&self, id: InvocationIndexNodeId) -> Result<Option<Vec<u8>>, Self::Error> {
            self.inner.load_node(id).map_err(InjectedStoreError::Inner)
        }

        fn put_manifest(&mut self, id: InvocationIndexId, bytes: &[u8]) -> Result<(), Self::Error> {
            if self.fail_manifest {
                return Err(InjectedStoreError::Injected);
            }
            self.inner
                .put_manifest(id, bytes)
                .map_err(InjectedStoreError::Inner)
        }

        fn put_node(&mut self, id: InvocationIndexNodeId, bytes: &[u8]) -> Result<(), Self::Error> {
            self.inner
                .put_node(id, bytes)
                .map_err(InjectedStoreError::Inner)
        }
    }

    #[test]
    fn nodes_are_installed_before_manifest_and_failure_keeps_current_id() {
        let scope = InvocationOwnershipScope::Ordered;
        let mut store = FailingManifestStore {
            inner: MemoryInvocationIndexStore::default(),
            fail_manifest: false,
        };
        let empty =
            InvocationIndex::<FailingManifestStore>::create_empty(&mut store, genesis(1), scope)
                .unwrap();
        store.fail_manifest = true;
        {
            let mut index = InvocationIndex::open(&mut store, empty).unwrap();
            let id = invocation([0x77; 32]);
            assert!(matches!(
                index.record(
                    key(scope, id),
                    owner(scope, id, InvocationResultState::Retained),
                ),
                Err(InvocationIndexError::Storage(InjectedStoreError::Injected))
            ));
            assert_eq!(index.id(), empty);
        }
        assert_eq!(store.inner.node_count(), 1);
        assert_eq!(store.inner.manifest_count(), 1);
    }

    #[test]
    fn ordinary_paths_ignore_full_audit_budget() {
        let values = [invocation([0x10; 32]), invocation([0x80; 32])];
        let (store, id, manifest) = build(&values);
        let mut limited = MemoryInvocationIndexStore::with_node_limit(2);
        limited.manifests = store.manifests;
        limited.nodes = store.nodes;
        {
            let index = InvocationIndex::open(&mut limited, id).unwrap();
            for value in values {
                assert!(
                    index
                        .lookup(key(InvocationOwnershipScope::Ordered, value))
                        .unwrap()
                        .is_some()
                );
            }
        }
        assert!(matches!(
            audit_manifest(&limited, id, &manifest),
            Err(InvocationIndexError::NodeLimit)
        ));
        assert!(matches!(
            InvocationIndex::open(&mut limited, InvocationIndexId([0xfe; 32])),
            Err(InvocationIndexError::MissingManifest(_))
        ));
    }

    #[test]
    fn large_logical_history_has_no_global_node_limit_refusal() {
        let scope = InvocationOwnershipScope::Ordered;
        let genesis = genesis(7);
        let left_key = invocation([0x10; 32]);
        let mut store = MemoryInvocationIndexStore::with_node_limit(2);
        let left = InvocationIndexNode::Leaf(InvocationOwnershipLeaf {
            genesis,
            key: key(scope, left_key),
            owner: owner(scope, left_key, InvocationResultState::Retained),
        });
        let left = put_node_immutable(&mut store, &left).unwrap();
        // This synthetic sibling summary represents a retained epoch whose
        // physical closure is outside the tiny scrub budget. Ordinary work on
        // the left path must not reinterpret that budget as a lifetime cap.
        let retained_entries = 600_000u64;
        let right = InvocationIndexChild {
            id: InvocationIndexNodeId([0xee; 32]),
            summary: InvocationIndexSummary {
                min: invocation([0x80; 32]),
                max: invocation([0xff; 32]),
                entries: retained_entries,
                tombstones: 0,
            },
        };
        let root = InvocationIndexNode::Branch {
            genesis,
            scope,
            bit: 0,
            prefix: [0; 32],
            left,
            right,
        };
        let root = put_node_immutable(&mut store, &root).unwrap();
        let manifest = InvocationIndexManifest {
            genesis,
            scope,
            root: Some(root.id),
            entries: retained_entries + 1,
            tombstones: 0,
        };
        let id = put_manifest_immutable(&mut store, &manifest).unwrap();
        let (next_id, next_manifest) = {
            let mut index = InvocationIndex::open(&mut store, id).unwrap();
            assert!(index.lookup(key(scope, left_key)).unwrap().is_some());
            let mut acknowledged = owner(scope, left_key, InvocationResultState::Retained);
            acknowledged.result_state = InvocationResultState::Acknowledged;
            index.record(key(scope, left_key), acknowledged).unwrap();
            (index.id(), *index.manifest())
        };
        assert_ne!(next_id, id);
        assert_eq!(next_manifest.entries, retained_entries + 1);
        assert_eq!(next_manifest.tombstones, 1);
        assert!(matches!(
            audit_manifest(&store, next_id, &next_manifest),
            Err(InvocationIndexError::NodeLimit)
        ));
    }

    #[test]
    fn aggregate_routes_three_scopes_and_exposes_atomic_publication_ids() {
        use crate::agent::replay::InvocationOwnership;

        let genesis = genesis(3);
        let local_node = NodeId([0x44; 32]);
        let mut store = MemoryInvocationIndexStore::default();
        let ordered = InvocationIndex::<MemoryInvocationIndexStore>::create_empty(
            &mut store,
            genesis,
            InvocationOwnershipScope::Ordered,
        )
        .unwrap();
        let merge = InvocationIndex::<MemoryInvocationIndexStore>::create_empty(
            &mut store,
            genesis,
            InvocationOwnershipScope::Merge,
        )
        .unwrap();
        let local = InvocationIndex::<MemoryInvocationIndexStore>::create_empty(
            &mut store,
            genesis,
            InvocationOwnershipScope::Local(local_node),
        )
        .unwrap();
        let (next_ordered, next_merge, next_local) = {
            let mut indexes = InvocationIndexes::open(&mut store, ordered, merge, local).unwrap();
            assert_eq!(indexes.genesis(), genesis);
            assert_eq!(indexes.local_node(), local_node);
            let cases = [
                (InvocationOwnershipScope::Ordered, invocation([0x11; 32])),
                (InvocationOwnershipScope::Merge, invocation([0x22; 32])),
                (
                    InvocationOwnershipScope::Local(local_node),
                    invocation([0x33; 32]),
                ),
            ];
            for (scope, invocation) in cases {
                indexes
                    .record(
                        key(scope, invocation),
                        owner(scope, invocation, InvocationResultState::Retained),
                    )
                    .unwrap();
                assert!(indexes.lookup(key(scope, invocation)).unwrap().is_some());
                assert_eq!(indexes.manifest(scope).unwrap().entries, 1);
            }
            assert!(matches!(
                indexes.index_id(InvocationOwnershipScope::Local(NodeId([9; 32]))),
                Err(InvocationIndexError::ScopeMismatch)
            ));
            (
                InvocationOwnership::index_id(&indexes, InvocationOwnershipScope::Ordered).unwrap(),
                InvocationOwnership::index_id(&indexes, InvocationOwnershipScope::Merge).unwrap(),
                InvocationOwnership::index_id(
                    &indexes,
                    InvocationOwnershipScope::Local(local_node),
                )
                .unwrap(),
            )
        };
        assert_ne!(next_ordered, ordered);
        assert_ne!(next_merge, merge);
        assert_ne!(next_local, local);
        let reopened =
            InvocationIndexes::open(&mut store, next_ordered, next_merge, next_local).unwrap();
        assert_eq!(
            reopened
                .manifest(InvocationOwnershipScope::Ordered)
                .unwrap()
                .entries,
            1
        );
    }
}
