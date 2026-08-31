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
    InvocationIndexNodeId, InvocationOutcomeAnchor, InvocationOutcomeId, InvocationOutcomeRecord,
    InvocationOutcomeRef, InvocationOwnershipKey, InvocationOwnershipLeaf,
    InvocationOwnershipScope, InvocationOwnershipValue, InvocationResultState, JournalStorageClass,
    MAX_INVOCATION_INDEX_LIVE_ENTRIES, MAX_INVOCATION_INDEX_LOGICAL_ENTRIES,
    MAX_INVOCATION_INDEX_MANIFEST_BYTES, MAX_INVOCATION_INDEX_NODE_BYTES,
    MAX_INVOCATION_INDEX_RESERVED_OUTCOME_BYTES, MAX_INVOCATION_OUTCOME_BYTES,
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

const fn full_tree_node_count(entries: u64) -> Option<usize> {
    let doubled = match entries.checked_mul(2) {
        Some(value) => value,
        None => return None,
    };
    let nodes = match doubled.checked_sub(1) {
        Some(value) => value,
        None => return None,
    };
    if nodes > usize::MAX as u64 {
        return None;
    }
    Some(nodes as usize)
}

/// Full-tree scrub and garbage-collection budget for one complete logical
/// ownership epoch. A canonical binary Patricia tree has exactly `2n - 1`
/// nodes for `n` leaves.
pub const DEFAULT_INVOCATION_INDEX_NODE_LIMIT: usize =
    match full_tree_node_count(MAX_INVOCATION_INDEX_LOGICAL_ENTRIES) {
        Some(value) => value,
        None => panic!("invocation-index logical limit does not fit the scrub node budget"),
    };

const NODE_ID_DOMAIN: &[u8] = b"vos/agent/journal/invocation-index-node";

/// Authenticated aggregate for one non-empty Patricia subtree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvocationIndexSummary {
    pub min: InvocationId,
    pub max: InvocationId,
    pub entries: u64,
    pub tombstones: u64,
    pub unfinalized: u64,
    pub outcome_records: u64,
    pub reserved_outcome_bytes: u64,
}

impl InvocationIndexSummary {
    fn from_leaf(leaf: &InvocationOwnershipLeaf) -> Self {
        Self {
            min: leaf.key.invocation,
            max: leaf.key.invocation,
            entries: 1,
            tombstones: u64::from(leaf.owner.result_state.is_tombstone()),
            unfinalized: u64::from(leaf.owner.is_unfinalized()),
            outcome_records: leaf.owner.outcome_records(),
            reserved_outcome_bytes: leaf.owner.reserved_outcome_bytes(),
        }
    }

    fn validate(self) -> Result<(), DecodeError> {
        let live = self.entries.checked_sub(self.tombstones);
        if self.min == InvocationId::ZERO
            || self.max == InvocationId::ZERO
            || self.min > self.max
            || self.entries == 0
            || self.tombstones > self.entries
            || self.entries > MAX_INVOCATION_INDEX_LOGICAL_ENTRIES
            || live.is_none_or(|live| live > MAX_INVOCATION_INDEX_LIVE_ENTRIES)
            || live.is_some_and(|live| {
                self.unfinalized > live
                    || self.outcome_records > live
                    || ((self.reserved_outcome_bytes == 0) != (live == 0))
            })
            || self.reserved_outcome_bytes > MAX_INVOCATION_INDEX_RESERVED_OUTCOME_BYTES
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
                unfinalized: left
                    .summary
                    .unfinalized
                    .checked_add(right.summary.unfinalized)
                    .ok_or(DecodeError::LimitExceeded)?,
                outcome_records: left
                    .summary
                    .outcome_records
                    .checked_add(right.summary.outcome_records)
                    .ok_or(DecodeError::LimitExceeded)?,
                reserved_outcome_bytes: left
                    .summary
                    .reserved_outcome_bytes
                    .checked_add(right.summary.reserved_outcome_bytes)
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

/// Separate immutable CAS boundary for exact invocation outcomes. Production
/// stores may implement this on the same descriptor-pinned namespace as the
/// index, but an index implementation can never synthesize result bytes from
/// an ownership leaf alone.
pub trait InvocationOutcomeStore: InvocationIndexStore {
    fn load_outcome(&self, id: InvocationOutcomeId) -> Result<Option<Vec<u8>>, Self::Error>;
    fn put_outcome(&mut self, id: InvocationOutcomeId, bytes: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvocationIndexError<E> {
    Storage(E),
    MissingManifest(InvocationIndexId),
    MissingNode(InvocationIndexNodeId),
    MissingOutcome(InvocationOutcomeId),
    CorruptManifest,
    CorruptNode(InvocationIndexNodeId),
    CorruptOutcome(InvocationOutcomeId),
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
    Capacity,
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
    Transitioned(InvocationIndexId),
    Acknowledged(InvocationIndexId),
}

impl InvocationIndexMutation {
    pub const fn index_id(self) -> InvocationIndexId {
        match self {
            Self::Inserted(id)
            | Self::ExactRetry(id)
            | Self::Transitioned(id)
            | Self::Acknowledged(id) => id,
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

/// Fully authenticated immutable objects reachable from one invocation-index
/// manifest. IDs are returned in canonical ascending order without duplicates
/// so journal garbage collection is independent of tree traversal order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InvocationIndexReachability {
    pub(crate) nodes: Vec<InvocationIndexNodeId>,
    pub(crate) outcomes: Vec<InvocationOutcomeId>,
}

/// Open, root-authenticated view of one lazily resolved scoped index.
pub struct InvocationIndex<'a, S: InvocationOutcomeStore> {
    store: &'a mut S,
    manifest: InvocationIndexManifest,
    id: InvocationIndexId,
}

type InvocationIndexPath = Vec<(InvocationIndexNode, bool)>;

impl<'a, S: InvocationOutcomeStore> InvocationIndex<'a, S> {
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

    /// Persist and read back one exact outcome before any ownership leaf may
    /// reference it. An immutable collision or malformed record fails before
    /// the index root can change.
    pub fn persist_outcome(
        &mut self,
        outcome: &InvocationOutcomeRecord,
    ) -> Result<InvocationOutcomeRef, InvocationIndexError<S::Error>> {
        put_outcome_immutable(self.store, outcome)
    }

    /// Resolve and authenticate the exact retained result for one member.
    pub fn outcome(
        &self,
        key: InvocationOwnershipKey,
    ) -> Result<Option<InvocationOutcomeRecord>, InvocationIndexError<S::Error>> {
        let Some(leaf) = self.lookup_leaf(key)? else {
            return Ok(None);
        };
        leaf.owner
            .outcome()
            .map(|reference| authenticate_outcome(self.store, &leaf, reference))
            .transpose()
    }

    /// Insert a first owner, accept a byte-exact retry, or apply one legal
    /// state-machine transition. Tombstones are never deleted or replaced.
    pub fn record(
        &mut self,
        key: InvocationOwnershipKey,
        value: InvocationOwnershipValue,
    ) -> Result<InvocationIndexMutation, InvocationIndexError<S::Error>> {
        let next = InvocationOwnershipLeaf {
            genesis: self.manifest.genesis,
            key,
            owner: value,
        };
        let existing = self.lookup_leaf(key)?;
        let transition = classify_transition(existing.as_ref(), &next)?;
        let id = self.record_batch(&[(key, value)])?;
        Ok(match transition {
            PlannedTransition::ExactRetry => InvocationIndexMutation::ExactRetry(id),
            PlannedTransition::Insert => InvocationIndexMutation::Inserted(id),
            PlannedTransition::Replace
                if matches!(
                    value.result_state,
                    InvocationResultState::Acknowledged { .. }
                ) =>
            {
                InvocationIndexMutation::Acknowledged(id)
            }
            PlannedTransition::Replace => InvocationIndexMutation::Transitioned(id),
        })
    }

    /// Apply a canonical, strictly key-ordered batch and expose only its final
    /// root. Validation—including exact outcome readback and aggregate quota
    /// checks—finishes before the first node is written. A later store failure
    /// restores this opened view's original manifest/id; immutable orphan
    /// nodes or manifests may remain for garbage collection.
    pub fn record_batch(
        &mut self,
        values: &[(InvocationOwnershipKey, InvocationOwnershipValue)],
    ) -> Result<InvocationIndexId, InvocationIndexError<S::Error>> {
        if values.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(InvocationIndexError::NonCanonicalTree);
        }
        let mut planned = Vec::new();
        let mut counts = ManifestCounts::from_manifest(&self.manifest);
        for (key, value) in values {
            self.require_scope(key.scope)?;
            let leaf = InvocationOwnershipLeaf {
                genesis: self.manifest.genesis,
                key: *key,
                owner: *value,
            };
            leaf.validate()
                .map_err(|_| InvocationIndexError::InvalidTransition)?;
            let existing = self.lookup_leaf(*key)?;
            let transition = classify_transition(existing.as_ref(), &leaf)?;
            authenticate_transition_outcomes(self.store, existing.as_ref(), &leaf, transition)?;
            counts.apply(existing.as_ref(), &leaf, transition)?;
            planned
                .try_reserve(1)
                .map_err(|_| InvocationIndexError::NodeLimit)?;
            planned.push((leaf, transition));
        }
        // Capacity is a property of the atomic final batch, not its required
        // canonical key ordering. In particular, an acknowledgement in the
        // same batch may free the slot needed by a lower-sorting insertion.
        counts.validate()?;

        let original_manifest = self.manifest;
        let original_id = self.id;
        let applied = (|| {
            // Replacements cannot increase live identities or reserved bytes,
            // so applying them first keeps every internally persisted
            // intermediate manifest canonical. Each phase retains canonical
            // key order and the final Patricia root is order-independent.
            for (leaf, transition) in planned.iter().copied() {
                if transition == PlannedTransition::Replace {
                    self.replace_leaf(leaf)?;
                }
            }
            for (leaf, transition) in planned.iter().copied() {
                if transition == PlannedTransition::Insert {
                    self.insert_leaf(leaf)?;
                }
            }
            Ok(())
        })();
        if let Err(error) = applied {
            self.manifest = original_manifest;
            self.id = original_id;
            return Err(error);
        }
        Ok(self.id)
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
                InvocationIndexNode::Leaf(leaf) => {
                    authenticate_leaf_reference(self.store, &leaf)?;
                    break;
                }
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
    ) -> Result<(), InvocationIndexError<S::Error>> {
        let leaf_node = InvocationIndexNode::Leaf(leaf);
        let leaf_ref = put_node_immutable(self.store, &leaf_node)?;
        let root = match self.manifest.root {
            None => leaf_ref,
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
                next
            }
        };
        let next = manifest_from_root(self.manifest, root)?;
        let id = put_manifest_immutable(self.store, &next)?;
        self.manifest = next;
        self.id = id;
        Ok(())
    }

    fn replace_leaf(
        &mut self,
        leaf: InvocationOwnershipLeaf,
    ) -> Result<(), InvocationIndexError<S::Error>> {
        let root = self
            .manifest
            .root
            .ok_or(InvocationIndexError::InvalidTransition)?;
        let (ancestors, _, terminal) = self.path_to_terminal(root, leaf.key.invocation)?;
        if !matches!(terminal, InvocationIndexNode::Leaf(found) if found.key == leaf.key) {
            return Err(InvocationIndexError::InvalidTransition);
        }
        let replacement = put_node_immutable(self.store, &InvocationIndexNode::Leaf(leaf))?;
        let root = self.rebuild_ancestors(ancestors, replacement)?;
        let next = manifest_from_root(self.manifest, root)?;
        let id = put_manifest_immutable(self.store, &next)?;
        self.manifest = next;
        self.id = id;
        Ok(())
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
pub struct InvocationIndexes<'a, S: InvocationOutcomeStore> {
    store: &'a mut S,
    ordered: OpenedInvocationIndex,
    merge: OpenedInvocationIndex,
    local: OpenedInvocationIndex,
}

impl<'a, S: InvocationOutcomeStore> InvocationIndexes<'a, S> {
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

    pub fn unfinalized(
        &self,
        scope: InvocationOwnershipScope,
    ) -> Result<u64, InvocationIndexError<S::Error>> {
        self.opened(scope).map(|opened| opened.manifest.unfinalized)
    }

    /// Persist an exact result into the aggregate's shared immutable outcome
    /// namespace, bound to the root selected by the record's own scope.
    pub fn persist_outcome(
        &mut self,
        outcome: &InvocationOutcomeRecord,
    ) -> Result<InvocationOutcomeRef, InvocationIndexError<S::Error>> {
        let opened = *self.opened(outcome.key.scope)?;
        if outcome.genesis != opened.manifest.genesis {
            return Err(InvocationIndexError::GenesisMismatch);
        }
        put_outcome_immutable(self.store, outcome)
    }

    pub fn lookup(
        &self,
        key: InvocationOwnershipKey,
    ) -> Result<Option<InvocationOwnershipValue>, InvocationIndexError<S::Error>> {
        let opened = self.opened(key.scope)?;
        lookup_in_manifest(self.store, &opened.manifest, key)
    }

    pub fn outcome(
        &self,
        key: InvocationOwnershipKey,
    ) -> Result<Option<InvocationOutcomeRecord>, InvocationIndexError<S::Error>> {
        let opened = self.opened(key.scope)?;
        let Some(leaf) = lookup_leaf_in_manifest(self.store, &opened.manifest, key)? else {
            return Ok(None);
        };
        leaf.owner
            .outcome()
            .map(|reference| authenticate_outcome(self.store, &leaf, reference))
            .transpose()
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

    /// Atomically update exactly one scoped root. The explicit scope keeps an
    /// empty batch unambiguous and prevents a mixed-scope batch from selecting
    /// its publication root by accident.
    pub fn record_batch(
        &mut self,
        scope: InvocationOwnershipScope,
        values: &[(InvocationOwnershipKey, InvocationOwnershipValue)],
    ) -> Result<InvocationIndexId, InvocationIndexError<S::Error>> {
        let opened = *self.opened(scope)?;
        let mut index = InvocationIndex {
            store: &mut *self.store,
            manifest: opened.manifest,
            id: opened.id,
        };
        let id = index.record_batch(values)?;
        let successor = OpenedInvocationIndex {
            id: index.id,
            manifest: index.manifest,
        };
        match scope {
            InvocationOwnershipScope::Ordered => self.ordered = successor,
            InvocationOwnershipScope::Merge => self.merge = successor,
            InvocationOwnershipScope::Local(node) if node == self.local_node() => {
                self.local = successor;
            }
            InvocationOwnershipScope::Local(_) => {
                return Err(InvocationIndexError::ScopeMismatch);
            }
        }
        Ok(id)
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

impl<S: InvocationOutcomeStore> super::replay::InvocationOwnership for InvocationIndex<'_, S> {
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

    fn persist_outcome(
        &mut self,
        outcome: &InvocationOutcomeRecord,
    ) -> Result<InvocationOutcomeRef, super::replay::InvocationOwnershipError> {
        if outcome.key.scope != self.manifest.scope || outcome.genesis != self.manifest.genesis {
            return Err(super::replay::InvocationOwnershipError::Unauthenticated);
        }
        InvocationIndex::persist_outcome(self, outcome).map_err(map_replay_error)
    }

    fn outcome(
        &self,
        key: InvocationOwnershipKey,
    ) -> Result<Option<InvocationOutcomeRecord>, super::replay::InvocationOwnershipError> {
        InvocationIndex::outcome(self, key).map_err(map_replay_error)
    }

    fn record_batch(
        &mut self,
        scope: InvocationOwnershipScope,
        values: &[(InvocationOwnershipKey, InvocationOwnershipValue)],
    ) -> Result<(), super::replay::InvocationOwnershipError> {
        if scope != self.manifest.scope {
            return Err(super::replay::InvocationOwnershipError::Unauthenticated);
        }
        InvocationIndex::record_batch(self, values)
            .map(|_| ())
            .map_err(map_replay_error)
    }

    fn unfinalized(
        &self,
        scope: InvocationOwnershipScope,
    ) -> Result<u64, super::replay::InvocationOwnershipError> {
        if scope == self.manifest.scope {
            Ok(self.manifest.unfinalized)
        } else {
            Err(super::replay::InvocationOwnershipError::Unauthenticated)
        }
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

impl<S: InvocationOutcomeStore> super::replay::InvocationOwnership for InvocationIndexes<'_, S> {
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

    fn persist_outcome(
        &mut self,
        outcome: &InvocationOutcomeRecord,
    ) -> Result<InvocationOutcomeRef, super::replay::InvocationOwnershipError> {
        InvocationIndexes::persist_outcome(self, outcome).map_err(map_replay_error)
    }

    fn outcome(
        &self,
        key: InvocationOwnershipKey,
    ) -> Result<Option<InvocationOutcomeRecord>, super::replay::InvocationOwnershipError> {
        InvocationIndexes::outcome(self, key).map_err(map_replay_error)
    }

    fn record_batch(
        &mut self,
        scope: InvocationOwnershipScope,
        values: &[(InvocationOwnershipKey, InvocationOwnershipValue)],
    ) -> Result<(), super::replay::InvocationOwnershipError> {
        InvocationIndexes::record_batch(self, scope, values)
            .map(|_| ())
            .map_err(map_replay_error)
    }

    fn unfinalized(
        &self,
        scope: InvocationOwnershipScope,
    ) -> Result<u64, super::replay::InvocationOwnershipError> {
        InvocationIndexes::unfinalized(self, scope).map_err(map_replay_error)
    }

    fn index_id(
        &self,
        scope: InvocationOwnershipScope,
    ) -> Result<InvocationIndexId, super::replay::InvocationOwnershipError> {
        InvocationIndexes::index_id(self, scope).map_err(map_replay_error)
    }
}

fn lookup_in_manifest<S: InvocationOutcomeStore>(
    store: &S,
    manifest: &InvocationIndexManifest,
    key: InvocationOwnershipKey,
) -> Result<Option<InvocationOwnershipValue>, InvocationIndexError<S::Error>> {
    lookup_leaf_in_manifest(store, manifest, key).map(|leaf| leaf.map(|leaf| leaf.owner))
}

fn lookup_leaf_in_manifest<S: InvocationOutcomeStore>(
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
                authenticate_leaf_reference(store, &leaf)?;
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
        | InvocationIndexError::MissingOutcome(_)
        | InvocationIndexError::NodeLimit
        | InvocationIndexError::Capacity
        | InvocationIndexError::StoreViolation => {
            super::replay::InvocationOwnershipError::Unavailable
        }
        InvocationIndexError::CorruptManifest
        | InvocationIndexError::CorruptNode(_)
        | InvocationIndexError::CorruptOutcome(_)
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
pub fn validate_manifest_root<S: InvocationOutcomeStore>(
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
    validate_path_summary(&node, None, true, manifest)?;
    if let InvocationIndexNode::Leaf(leaf) = node {
        authenticate_leaf_reference(store, &leaf)?;
    }
    Ok(())
}

/// Explicit full-tree semantic audit for operator scrub and repair tooling.
///
/// Ordinary recovery, head validation, lookup, and publication must use
/// [`validate_manifest_root`] and path validation instead. The store's node
/// limit is an audit work budget; exceeding it does not invalidate a live
/// index. The separate logical-entry ceiling is enforced on new members;
/// checkpoint-governed physical rollover and garbage collection reclaim an
/// acknowledged epoch without weakening permanent ownership semantics.
pub fn audit_manifest<S: InvocationOutcomeStore>(
    store: &S,
    expected: InvocationIndexId,
    manifest: &InvocationIndexManifest,
) -> Result<(), InvocationIndexError<S::Error>> {
    collect_manifest_reachability(store, expected, manifest, store.node_limit()).map(|_| ())
}

/// Collect the complete authenticated object closure of one manifest.
///
/// Unlike ordinary path-oriented validation, this is an explicitly bounded
/// full-tree operation for publication closure checks and journal garbage
/// collection. Both the caller's bound and the store's scrub bound apply.
pub(crate) fn collect_manifest_reachability<S: InvocationOutcomeStore>(
    store: &S,
    expected: InvocationIndexId,
    manifest: &InvocationIndexManifest,
    max_nodes: usize,
) -> Result<InvocationIndexReachability, InvocationIndexError<S::Error>> {
    manifest
        .validate()
        .map_err(|_| InvocationIndexError::CorruptManifest)?;
    if manifest.id() != expected {
        return Err(InvocationIndexError::CorruptManifest);
    }
    let Some(root) = manifest.root else {
        return Ok(InvocationIndexReachability {
            nodes: Vec::new(),
            outcomes: Vec::new(),
        });
    };
    let expected_nodes =
        full_tree_node_count(manifest.entries).ok_or(InvocationIndexError::NodeLimit)?;
    let limit = max_nodes.min(store.node_limit());
    if limit == 0 || expected_nodes > limit {
        return Err(InvocationIndexError::NodeLimit);
    }
    let mut visited = BTreeSet::new();
    let mut outcomes = BTreeSet::new();
    let mut ancestors = Vec::new();
    let summary = resolve_node(
        store,
        root,
        manifest.genesis,
        manifest.scope,
        None,
        None,
        &mut visited,
        &mut outcomes,
        &mut ancestors,
        limit,
        expected_nodes,
    )?;
    if !summary_matches_manifest(summary, manifest) {
        return Err(InvocationIndexError::SummaryMismatch);
    }
    if visited.len() != expected_nodes || outcomes.len() as u64 != manifest.outcome_records {
        return Err(InvocationIndexError::NonCanonicalTree);
    }
    Ok(InvocationIndexReachability {
        nodes: visited.into_iter().collect(),
        outcomes: outcomes.into_iter().collect(),
    })
}

#[allow(clippy::too_many_arguments)]
fn resolve_node<S: InvocationOutcomeStore>(
    store: &S,
    id: InvocationIndexNodeId,
    genesis: AgentJournalGenesisId,
    scope: InvocationOwnershipScope,
    expected: Option<InvocationIndexSummary>,
    parent_bit: Option<u16>,
    visited: &mut BTreeSet<InvocationIndexNodeId>,
    outcomes: &mut BTreeSet<InvocationOutcomeId>,
    ancestors: &mut Vec<InvocationIndexNodeId>,
    limit: usize,
    expected_nodes: usize,
) -> Result<InvocationIndexSummary, InvocationIndexError<S::Error>> {
    if ancestors.contains(&id) {
        return Err(InvocationIndexError::Cycle);
    }
    if !visited.insert(id) {
        return Err(InvocationIndexError::SharedNode);
    }
    if visited.len() > expected_nodes {
        return Err(InvocationIndexError::NonCanonicalTree);
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
        InvocationIndexNode::Leaf(leaf) => {
            authenticate_leaf_reference(store, &leaf)?;
            if let Some(reference) = leaf.owner.outcome() {
                outcomes.insert(reference.outcome);
            }
            Ok(summary)
        }
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
                outcomes,
                ancestors,
                limit,
                expected_nodes,
            )?;
            let right_summary = resolve_node(
                store,
                right.id,
                genesis,
                scope,
                Some(right.summary),
                Some(bit),
                visited,
                outcomes,
                ancestors,
                limit,
                expected_nodes,
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
        if index == 0 && !summary_matches_manifest(summary, &proof.manifest) {
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
        || (root && !summary_matches_manifest(summary, manifest))
    {
        return Err(InvocationIndexError::SummaryMismatch);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PlannedTransition {
    ExactRetry,
    Insert,
    Replace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ManifestCounts {
    entries: u64,
    tombstones: u64,
    unfinalized: u64,
    outcome_records: u64,
    reserved_outcome_bytes: u64,
}

impl ManifestCounts {
    const fn from_manifest(manifest: &InvocationIndexManifest) -> Self {
        Self {
            entries: manifest.entries,
            tombstones: manifest.tombstones,
            unfinalized: manifest.unfinalized,
            outcome_records: manifest.outcome_records,
            reserved_outcome_bytes: manifest.reserved_outcome_bytes,
        }
    }

    fn apply<E>(
        &mut self,
        existing: Option<&InvocationOwnershipLeaf>,
        next: &InvocationOwnershipLeaf,
        transition: PlannedTransition,
    ) -> Result<(), InvocationIndexError<E>> {
        if transition == PlannedTransition::ExactRetry {
            return Ok(());
        }
        let old = existing.map(InvocationIndexSummary::from_leaf);
        let new = InvocationIndexSummary::from_leaf(next);
        if transition == PlannedTransition::Insert {
            self.entries = self
                .entries
                .checked_add(1)
                .ok_or(InvocationIndexError::Capacity)?;
        }
        self.tombstones = replace_count(
            self.tombstones,
            old.map_or(0, |summary| summary.tombstones),
            new.tombstones,
        )?;
        self.unfinalized = replace_count(
            self.unfinalized,
            old.map_or(0, |summary| summary.unfinalized),
            new.unfinalized,
        )?;
        self.outcome_records = replace_count(
            self.outcome_records,
            old.map_or(0, |summary| summary.outcome_records),
            new.outcome_records,
        )?;
        self.reserved_outcome_bytes = replace_count(
            self.reserved_outcome_bytes,
            old.map_or(0, |summary| summary.reserved_outcome_bytes),
            new.reserved_outcome_bytes,
        )?;
        Ok(())
    }

    fn validate<E>(self) -> Result<(), InvocationIndexError<E>> {
        let live = self.entries.checked_sub(self.tombstones);
        if self.entries > MAX_INVOCATION_INDEX_LOGICAL_ENTRIES
            || self.tombstones > self.entries
            || live.is_none_or(|live| live > MAX_INVOCATION_INDEX_LIVE_ENTRIES)
            || live.is_some_and(|live| {
                self.unfinalized > live
                    || self.outcome_records > live
                    || ((self.reserved_outcome_bytes == 0) != (live == 0))
            })
            || self.reserved_outcome_bytes > MAX_INVOCATION_INDEX_RESERVED_OUTCOME_BYTES
        {
            return Err(InvocationIndexError::Capacity);
        }
        Ok(())
    }
}

fn replace_count<E>(current: u64, old: u64, new: u64) -> Result<u64, InvocationIndexError<E>> {
    current
        .checked_sub(old)
        .and_then(|current| current.checked_add(new))
        .ok_or(InvocationIndexError::NonCanonicalTree)
}

fn classify_transition<E>(
    existing: Option<&InvocationOwnershipLeaf>,
    next: &InvocationOwnershipLeaf,
) -> Result<PlannedTransition, InvocationIndexError<E>> {
    next.validate()
        .map_err(|_| InvocationIndexError::InvalidTransition)?;
    let Some(existing) = existing else {
        return match (next.key.scope, next.owner.result_state) {
            (
                InvocationOwnershipScope::Ordered | InvocationOwnershipScope::Local(_),
                InvocationResultState::Retained { .. },
            )
            | (InvocationOwnershipScope::Merge, InvocationResultState::PendingMerge { .. }) => {
                Ok(PlannedTransition::Insert)
            }
            _ => Err(InvocationIndexError::InvalidTransition),
        };
    };
    if existing == next {
        return Ok(PlannedTransition::ExactRetry);
    }
    if existing.genesis != next.genesis
        || existing.key != next.key
        || !same_owner_identity(existing.owner, next.owner)
    {
        return Err(InvocationIndexError::Conflict);
    }
    let legal = match (existing.owner.result_state, next.owner.result_state) {
        (InvocationResultState::PendingMerge { .. }, InvocationResultState::Retained { .. })
            if matches!(next.key.scope, InvocationOwnershipScope::Merge) =>
        {
            true
        }
        (
            InvocationResultState::Retained {
                disposition: old, ..
            },
            InvocationResultState::Acknowledged { disposition: new },
        ) if !matches!(next.key.scope, InvocationOwnershipScope::Merge) => old == new,
        (
            InvocationResultState::Retained {
                disposition: old,
                outcome: old_outcome,
            },
            InvocationResultState::PendingMergeAcknowledgement {
                disposition: new,
                outcome: new_outcome,
                ..
            },
        ) if matches!(next.key.scope, InvocationOwnershipScope::Merge) => {
            old == new && old_outcome == new_outcome
        }
        (
            InvocationResultState::PendingMergeAcknowledgement {
                disposition: old, ..
            },
            InvocationResultState::Acknowledged { disposition: new },
        ) if matches!(next.key.scope, InvocationOwnershipScope::Merge) => old == new,
        _ => false,
    };
    legal
        .then_some(PlannedTransition::Replace)
        .ok_or(InvocationIndexError::InvalidTransition)
}

fn same_owner_identity(left: InvocationOwnershipValue, right: InvocationOwnershipValue) -> bool {
    left.scope == right.scope
        && left.request_commitment == right.request_commitment
        && left.first_input == right.first_input
        && left.lane == right.lane
        && left.node == right.node
}

fn authenticate_transition_outcomes<S: InvocationOutcomeStore>(
    store: &S,
    existing: Option<&InvocationOwnershipLeaf>,
    next: &InvocationOwnershipLeaf,
    transition: PlannedTransition,
) -> Result<(), InvocationIndexError<S::Error>> {
    let existing_outcome = existing
        .and_then(|leaf| leaf.owner.outcome().map(|reference| (leaf, reference)))
        .map(|(leaf, reference)| authenticate_outcome(store, leaf, reference))
        .transpose()?;
    let next_outcome = next
        .owner
        .outcome()
        .map(|reference| authenticate_outcome(store, next, reference))
        .transpose()?;
    if transition == PlannedTransition::ExactRetry {
        return Ok(());
    }
    match (
        existing.map(|leaf| leaf.owner.result_state),
        next.owner.result_state,
    ) {
        (
            Some(InvocationResultState::PendingMerge { source_event }),
            InvocationResultState::Retained { .. },
        ) => match next_outcome.as_ref().map(|outcome| outcome.anchor) {
            Some(InvocationOutcomeAnchor::Merge {
                source_event: anchored,
                ..
            }) if anchored == source_event => {}
            _ => return Err(InvocationIndexError::InvalidTransition),
        },
        (
            Some(InvocationResultState::Retained { .. }),
            InvocationResultState::PendingMergeAcknowledgement {
                acknowledgement_event,
                ..
            },
        ) => {
            let source_event = match existing_outcome.as_ref().map(|outcome| outcome.anchor) {
                Some(InvocationOutcomeAnchor::Merge { source_event, .. }) => source_event,
                _ => return Err(InvocationIndexError::InvalidTransition),
            };
            if acknowledgement_event == source_event {
                return Err(InvocationIndexError::InvalidTransition);
            }
        }
        (
            Some(InvocationResultState::PendingMergeAcknowledgement { .. }),
            InvocationResultState::Acknowledged { .. },
        ) if existing_outcome.is_some() => {}
        (None, InvocationResultState::Retained { .. }) if next_outcome.is_some() => {}
        (None, InvocationResultState::PendingMerge { .. }) => {}
        _ => {}
    }
    Ok(())
}

fn authenticate_leaf_reference<S: InvocationOutcomeStore>(
    store: &S,
    leaf: &InvocationOwnershipLeaf,
) -> Result<(), InvocationIndexError<S::Error>> {
    if let Some(reference) = leaf.owner.outcome() {
        let outcome = authenticate_outcome(store, leaf, reference)?;
        if let InvocationResultState::PendingMergeAcknowledgement {
            acknowledgement_event,
            ..
        } = leaf.owner.result_state
        {
            let InvocationOutcomeAnchor::Merge { source_event, .. } = outcome.anchor else {
                return Err(InvocationIndexError::CorruptOutcome(reference.outcome));
            };
            if acknowledgement_event == source_event {
                return Err(InvocationIndexError::CorruptOutcome(reference.outcome));
            }
        }
    }
    Ok(())
}

fn authenticate_outcome<S: InvocationOutcomeStore>(
    store: &S,
    leaf: &InvocationOwnershipLeaf,
    reference: InvocationOutcomeRef,
) -> Result<InvocationOutcomeRecord, InvocationIndexError<S::Error>> {
    reference
        .validate()
        .map_err(|_| InvocationIndexError::CorruptOutcome(reference.outcome))?;
    let bytes = store
        .load_outcome(reference.outcome)
        .map_err(InvocationIndexError::Storage)?
        .ok_or(InvocationIndexError::MissingOutcome(reference.outcome))?;
    if bytes.len() > MAX_INVOCATION_OUTCOME_BYTES || bytes.len() != reference.encoded_bytes as usize
    {
        return Err(InvocationIndexError::CorruptOutcome(reference.outcome));
    }
    let outcome = InvocationOutcomeRecord::decode(&bytes)
        .map_err(|_| InvocationIndexError::CorruptOutcome(reference.outcome))?;
    if outcome.id() != reference.outcome
        || outcome.encode() != bytes
        || !reference.authenticates(&outcome)
        || outcome.genesis != leaf.genesis
        || outcome.key != leaf.key
        || outcome.request_commitment != leaf.owner.request_commitment
        || outcome.first_input != leaf.owner.first_input
        || outcome.lane != leaf.owner.lane
        || outcome.node != leaf.owner.node
        || Some(outcome.disposition()) != leaf.owner.disposition()
    {
        return Err(InvocationIndexError::CorruptOutcome(reference.outcome));
    }
    Ok(outcome)
}

fn put_outcome_immutable<S: InvocationOutcomeStore>(
    store: &mut S,
    outcome: &InvocationOutcomeRecord,
) -> Result<InvocationOutcomeRef, InvocationIndexError<S::Error>> {
    outcome
        .validate()
        .map_err(|_| InvocationIndexError::CorruptOutcome(outcome.id()))?;
    let reference = InvocationOutcomeRef::for_record(outcome)
        .map_err(|_| InvocationIndexError::CorruptOutcome(outcome.id()))?;
    let bytes = outcome.encode();
    if let Some(existing) = store
        .load_outcome(reference.outcome)
        .map_err(InvocationIndexError::Storage)?
    {
        if existing != bytes {
            return Err(InvocationIndexError::ObjectCollision);
        }
    } else {
        store
            .put_outcome(reference.outcome, &bytes)
            .map_err(InvocationIndexError::Storage)?;
    }
    match store
        .load_outcome(reference.outcome)
        .map_err(InvocationIndexError::Storage)?
    {
        Some(installed) if installed == bytes => {}
        _ => return Err(InvocationIndexError::StoreViolation),
    }
    let decoded = InvocationOutcomeRecord::decode(&bytes)
        .map_err(|_| InvocationIndexError::CorruptOutcome(reference.outcome))?;
    if decoded != *outcome || decoded.id() != reference.outcome {
        return Err(InvocationIndexError::CorruptOutcome(reference.outcome));
    }
    Ok(reference)
}

fn manifest_from_root<E>(
    current: InvocationIndexManifest,
    root: InvocationIndexChild,
) -> Result<InvocationIndexManifest, InvocationIndexError<E>> {
    root.validate()
        .map_err(|_| InvocationIndexError::NonCanonicalTree)?;
    let next = InvocationIndexManifest {
        root: Some(root.id),
        entries: root.summary.entries,
        tombstones: root.summary.tombstones,
        unfinalized: root.summary.unfinalized,
        outcome_records: root.summary.outcome_records,
        reserved_outcome_bytes: root.summary.reserved_outcome_bytes,
        ..current
    };
    next.validate()
        .map_err(|_| InvocationIndexError::Capacity)?;
    Ok(next)
}

fn summary_matches_manifest(
    summary: InvocationIndexSummary,
    manifest: &InvocationIndexManifest,
) -> bool {
    summary.entries == manifest.entries
        && summary.tombstones == manifest.tombstones
        && summary.unfinalized == manifest.unfinalized
        && summary.outcome_records == manifest.outcome_records
        && summary.reserved_outcome_bytes == manifest.reserved_outcome_bytes
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
    encoder.u64(child.summary.unfinalized);
    encoder.u64(child.summary.outcome_records);
    encoder.u64(child.summary.reserved_outcome_bytes);
}

fn decode_child(decoder: &mut Decoder<'_>) -> Result<InvocationIndexChild, DecodeError> {
    let child = InvocationIndexChild {
        id: InvocationIndexNodeId(decoder.fixed()?),
        summary: InvocationIndexSummary {
            min: InvocationId(decoder.fixed()?),
            max: InvocationId(decoder.fixed()?),
            entries: decoder.u64()?,
            tombstones: decoder.u64()?,
            unfinalized: decoder.u64()?,
            outcome_records: decoder.u64()?,
            reserved_outcome_bytes: decoder.u64()?,
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
    outcomes: BTreeMap<InvocationOutcomeId, Vec<u8>>,
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
            outcomes: BTreeMap::new(),
        }
    }

    pub fn manifest_count(&self) -> usize {
        self.manifests.len()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn outcome_count(&self) -> usize {
        self.outcomes.len()
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

impl InvocationOutcomeStore for MemoryInvocationIndexStore {
    fn load_outcome(&self, id: InvocationOutcomeId) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.outcomes.get(&id).cloned())
    }

    fn put_outcome(&mut self, id: InvocationOutcomeId, bytes: &[u8]) -> Result<(), Self::Error> {
        if bytes.len() > MAX_INVOCATION_OUTCOME_BYTES {
            return Err(MemoryInvocationIndexStoreError::Oversized);
        }
        match self.outcomes.get(&id) {
            Some(existing) if existing.as_slice() == bytes => Ok(()),
            Some(_) => Err(MemoryInvocationIndexStoreError::ImmutableConflict),
            None => {
                self.outcomes.insert(id, bytes.to_vec());
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
    use crate::agent::MethodMode;
    use crate::agent::execution::ActorExecutionError;
    use crate::agent::journal::{
        InvocationDisposition, InvocationOutcomeRequestFacts, InvocationOwner, LocalEntryId,
        MergeEventId, MergeSealId, OrderedEntryId, PersistedLane, ReplayInputId,
        VisibleStateCommitment,
    };
    use crate::agent::wire::RuntimeState;
    use crate::service::{ActorId, DeploymentId, ProgramId};

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

    fn request_commitment(id: InvocationId) -> Hash {
        Hash::digest(b"index-test-request", &[&id.0])
    }

    fn first_input(id: InvocationId) -> ReplayInputId {
        ReplayInputId(Hash::digest(b"index-test-input", &[&id.0]).0)
    }

    fn source_event(id: InvocationId) -> MergeEventId {
        MergeEventId(Hash::digest(b"index-test-source", &[&id.0]).0)
    }

    fn test_outcome(
        journal_genesis: AgentJournalGenesisId,
        scope: InvocationOwnershipScope,
        id: InvocationId,
    ) -> InvocationOutcomeRecord {
        let (mode, lane, node, anchor) = match scope {
            InvocationOwnershipScope::Ordered => (
                MethodMode::Linear,
                PersistedLane::Linear,
                None,
                InvocationOutcomeAnchor::Ordered {
                    entry: OrderedEntryId(Hash::digest(b"index-test-ordered", &[&id.0]).0),
                },
            ),
            InvocationOwnershipScope::Merge => (
                MethodMode::Merge,
                PersistedLane::Merge,
                None,
                InvocationOutcomeAnchor::Merge {
                    source_event: source_event(id),
                    finalizing_entry: OrderedEntryId(
                        Hash::digest(b"index-test-finalizing", &[&id.0]).0,
                    ),
                    seal: MergeSealId(Hash::digest(b"index-test-seal", &[&id.0]).0),
                },
            ),
            InvocationOwnershipScope::Local(node) => (
                MethodMode::Local,
                PersistedLane::Local,
                Some(node),
                InvocationOutcomeAnchor::Local {
                    entry: LocalEntryId(Hash::digest(b"index-test-local", &[&id.0]).0),
                },
            ),
        };
        let state = RuntimeState {
            control: vec![1],
            linear: vec![2],
            merge: vec![3],
            local: vec![4],
        };
        let visible = VisibleStateCommitment::from_runtime_state(scope, &state).unwrap();
        let record = InvocationOutcomeRecord {
            genesis: journal_genesis,
            key: key(scope, id),
            request_commitment: request_commitment(id),
            first_input: first_input(id),
            request: InvocationOutcomeRequestFacts {
                actor: ActorId(Hash::digest(b"index-test-actor", &[&id.0]).0),
                incarnation: Hash::digest(b"index-test-incarnation", &[&id.0]),
                deployment: DeploymentId(Hash::digest(b"index-test-deployment", &[&id.0]).0),
                program: ProgramId(Hash::digest(b"index-test-program", &[&id.0]).0),
                mode,
                gas_limit: 100,
            },
            anchor,
            lane,
            node,
            before: visible,
            after: visible,
            result: Err(ActorExecutionError::InvalidInput),
        };
        record.validate().unwrap();
        record
    }

    fn owner_with_state(
        scope: InvocationOwnershipScope,
        id: InvocationId,
        result_state: InvocationResultState,
    ) -> InvocationOwnershipValue {
        InvocationOwner {
            scope,
            request_commitment: request_commitment(id),
            first_input: first_input(id),
            lane: match scope {
                InvocationOwnershipScope::Ordered => PersistedLane::Linear,
                InvocationOwnershipScope::Merge => PersistedLane::Merge,
                InvocationOwnershipScope::Local(_) => PersistedLane::Local,
            },
            node: match scope {
                InvocationOwnershipScope::Local(node) => Some(node),
                _ => None,
            },
            result_state,
        }
    }

    fn retained_for(
        journal_genesis: AgentJournalGenesisId,
        scope: InvocationOwnershipScope,
        id: InvocationId,
    ) -> (InvocationOwnershipValue, InvocationOutcomeRecord) {
        let outcome = test_outcome(journal_genesis, scope, id);
        let reference = InvocationOutcomeRef::for_record(&outcome).unwrap();
        (
            owner_with_state(
                scope,
                id,
                InvocationResultState::Retained {
                    disposition: outcome.disposition(),
                    outcome: reference,
                },
            ),
            outcome,
        )
    }

    fn retained(scope: InvocationOwnershipScope, id: InvocationId) -> InvocationOwnershipValue {
        retained_for(genesis(1), scope, id).0
    }

    fn acknowledged(
        scope: InvocationOwnershipScope,
        id: InvocationId,
        disposition: InvocationDisposition,
    ) -> InvocationOwnershipValue {
        owner_with_state(
            scope,
            id,
            InvocationResultState::Acknowledged { disposition },
        )
    }

    fn pending_merge(id: InvocationId) -> InvocationOwnershipValue {
        owner_with_state(
            InvocationOwnershipScope::Merge,
            id,
            InvocationResultState::PendingMerge {
                source_event: source_event(id),
            },
        )
    }

    fn persist_retained(
        index: &mut InvocationIndex<'_, MemoryInvocationIndexStore>,
        scope: InvocationOwnershipScope,
        id: InvocationId,
    ) -> InvocationOwnershipValue {
        let (owner, outcome) = retained_for(index.manifest.genesis, scope, id);
        assert_eq!(
            index.persist_outcome(&outcome).unwrap(),
            owner.outcome().unwrap()
        );
        owner
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
            for (position, invocation) in order.iter().enumerate() {
                let retained = persist_retained(&mut index, scope, *invocation);
                assert!(matches!(
                    index.record(key(scope, *invocation), retained).unwrap(),
                    InvocationIndexMutation::Inserted(_)
                ));
                // A maximum-depth tree has 257 logical members. Keep its
                // first target live while acknowledging every other owner so
                // the production live-entry quota remains enforced.
                if order.len() > MAX_INVOCATION_INDEX_LIVE_ENTRIES as usize && position != 0 {
                    index
                        .record(
                            key(scope, *invocation),
                            acknowledged(scope, *invocation, retained.disposition().unwrap()),
                        )
                        .unwrap();
                }
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
            owner: retained(scope, id),
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
        let value = persist_retained(&mut index, scope, id);
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
            let retained = persist_retained(&mut index, scope, id);
            index.record(key(scope, id), retained).unwrap();
            let acknowledged = acknowledged(scope, id, retained.disposition().unwrap());
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
                Err(InvocationIndexError::InvalidTransition)
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
    fn local_results_retain_exact_outcomes_then_become_tombstones() {
        let scope = InvocationOwnershipScope::Local(NodeId([0x61; 32]));
        let id = invocation([0x62; 32]);
        let mut store = MemoryInvocationIndexStore::default();
        let empty = InvocationIndex::<MemoryInvocationIndexStore>::create_empty(
            &mut store,
            genesis(1),
            scope,
        )
        .unwrap();
        let mut index = InvocationIndex::open(&mut store, empty).unwrap();
        let retained = persist_retained(&mut index, scope, id);
        let reference = retained.outcome().unwrap();
        index.record(key(scope, id), retained).unwrap();
        assert_eq!(index.manifest().outcome_records, 1);
        assert_eq!(
            index.manifest().reserved_outcome_bytes,
            u64::from(reference.encoded_bytes)
        );
        let acknowledged = acknowledged(scope, id, retained.disposition().unwrap());
        index.record(key(scope, id), acknowledged).unwrap();
        assert_eq!(index.manifest().entries, 1);
        assert_eq!(index.manifest().tombstones, 1);
        assert_eq!(index.manifest().outcome_records, 0);
        assert_eq!(index.manifest().reserved_outcome_bytes, 0);
    }

    #[test]
    fn merge_owner_requires_finalization_before_acknowledgement() {
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
        let pending = pending_merge(id);
        index.record(key(scope, id), pending).unwrap();
        let illegal = acknowledged(scope, id, InvocationDisposition::Rejected);
        assert!(matches!(
            index.record(key(scope, id), illegal),
            Err(InvocationIndexError::InvalidTransition)
        ));
        assert_eq!(index.lookup(key(scope, id)).unwrap(), Some(pending));
        assert_eq!(index.manifest().tombstones, 0);
        assert_eq!(index.manifest().unfinalized, 1);
    }

    #[test]
    fn merge_lifecycle_authenticates_source_outcome_and_acknowledgement() {
        let scope = InvocationOwnershipScope::Merge;
        let id = invocation([0x19; 32]);
        let mut store = MemoryInvocationIndexStore::default();
        let empty = InvocationIndex::<MemoryInvocationIndexStore>::create_empty(
            &mut store,
            genesis(1),
            scope,
        )
        .unwrap();
        let mut index = InvocationIndex::open(&mut store, empty).unwrap();

        let pending = pending_merge(id);
        assert!(matches!(
            index.record(key(scope, id), pending).unwrap(),
            InvocationIndexMutation::Inserted(_)
        ));
        assert_eq!(index.manifest().entries, 1);
        assert_eq!(index.manifest().tombstones, 0);
        assert_eq!(index.manifest().unfinalized, 1);
        assert_eq!(index.manifest().outcome_records, 0);
        assert_eq!(
            index.manifest().reserved_outcome_bytes,
            MAX_INVOCATION_OUTCOME_BYTES as u64
        );

        let mut wrong_source = test_outcome(genesis(1), scope, id);
        let InvocationOutcomeAnchor::Merge { source_event, .. } = &mut wrong_source.anchor else {
            unreachable!()
        };
        *source_event = MergeEventId([0xa1; 32]);
        let wrong_reference = index.persist_outcome(&wrong_source).unwrap();
        let wrong_retained = owner_with_state(
            scope,
            id,
            InvocationResultState::Retained {
                disposition: wrong_source.disposition(),
                outcome: wrong_reference,
            },
        );
        assert!(matches!(
            index.record(key(scope, id), wrong_retained),
            Err(InvocationIndexError::InvalidTransition)
        ));

        let retained = persist_retained(&mut index, scope, id);
        let reference = retained.outcome().unwrap();
        assert!(matches!(
            index.record(key(scope, id), retained).unwrap(),
            InvocationIndexMutation::Transitioned(_)
        ));
        assert_eq!(index.manifest().unfinalized, 0);
        assert_eq!(index.manifest().outcome_records, 1);
        assert_eq!(
            index.manifest().reserved_outcome_bytes,
            u64::from(reference.encoded_bytes)
        );
        assert_eq!(
            index.outcome(key(scope, id)).unwrap(),
            Some(test_outcome(genesis(1), scope, id))
        );

        let acknowledgement_event = MergeEventId([0xa2; 32]);
        let pending_acknowledgement = owner_with_state(
            scope,
            id,
            InvocationResultState::PendingMergeAcknowledgement {
                acknowledgement_event,
                disposition: retained.disposition().unwrap(),
                outcome: reference,
            },
        );
        assert!(matches!(
            index
                .record(key(scope, id), pending_acknowledgement)
                .unwrap(),
            InvocationIndexMutation::Transitioned(_)
        ));
        assert_eq!(index.manifest().unfinalized, 1);
        assert_eq!(index.manifest().outcome_records, 1);

        let acknowledged = acknowledged(scope, id, retained.disposition().unwrap());
        assert!(matches!(
            index.record(key(scope, id), acknowledged).unwrap(),
            InvocationIndexMutation::Acknowledged(_)
        ));
        let acknowledged_id = index.id();
        assert_eq!(
            index.record(key(scope, id), acknowledged).unwrap(),
            InvocationIndexMutation::ExactRetry(acknowledged_id)
        );
        assert_eq!(index.manifest().entries, 1);
        assert_eq!(index.manifest().tombstones, 1);
        assert_eq!(index.manifest().unfinalized, 0);
        assert_eq!(index.manifest().outcome_records, 0);
        assert_eq!(index.manifest().reserved_outcome_bytes, 0);
        assert_eq!(index.outcome(key(scope, id)).unwrap(), None);
    }

    #[test]
    fn merge_acknowledgement_must_follow_retention_and_use_a_distinct_event() {
        let scope = InvocationOwnershipScope::Merge;
        let id = invocation([0x1a; 32]);
        let mut store = MemoryInvocationIndexStore::default();
        let empty = InvocationIndex::<MemoryInvocationIndexStore>::create_empty(
            &mut store,
            genesis(1),
            scope,
        )
        .unwrap();
        let mut index = InvocationIndex::open(&mut store, empty).unwrap();
        let pending = pending_merge(id);
        index.record(key(scope, id), pending).unwrap();
        let retained = persist_retained(&mut index, scope, id);
        let reference = retained.outcome().unwrap();

        let same_source_ack = owner_with_state(
            scope,
            id,
            InvocationResultState::PendingMergeAcknowledgement {
                acknowledgement_event: source_event(id),
                disposition: retained.disposition().unwrap(),
                outcome: reference,
            },
        );
        // A single canonical batch cannot skip Retained: duplicate keys are
        // rejected before either transition can become visible.
        let pending_ack = owner_with_state(
            scope,
            id,
            InvocationResultState::PendingMergeAcknowledgement {
                acknowledgement_event: MergeEventId([0xa3; 32]),
                disposition: retained.disposition().unwrap(),
                outcome: reference,
            },
        );
        assert!(matches!(
            index.record_batch(&[(key(scope, id), retained), (key(scope, id), pending_ack)]),
            Err(InvocationIndexError::NonCanonicalTree)
        ));
        assert_eq!(index.lookup(key(scope, id)).unwrap(), Some(pending));

        index.record(key(scope, id), retained).unwrap();
        assert!(matches!(
            index.record(key(scope, id), same_source_ack),
            Err(InvocationIndexError::InvalidTransition)
        ));
        index.record(key(scope, id), pending_ack).unwrap();
        assert!(matches!(
            index.record(key(scope, id), retained),
            Err(InvocationIndexError::InvalidTransition) | Err(InvocationIndexError::Conflict)
        ));
    }

    #[test]
    fn absent_members_accept_only_the_scope_specific_initial_state() {
        let local_node = NodeId([0x41; 32]);
        for (scope, id, invalid) in [
            (
                InvocationOwnershipScope::Ordered,
                invocation([0x21; 32]),
                owner_with_state(
                    InvocationOwnershipScope::Ordered,
                    invocation([0x21; 32]),
                    InvocationResultState::PendingMerge {
                        source_event: MergeEventId([1; 32]),
                    },
                ),
            ),
            (
                InvocationOwnershipScope::Local(local_node),
                invocation([0x22; 32]),
                acknowledged(
                    InvocationOwnershipScope::Local(local_node),
                    invocation([0x22; 32]),
                    InvocationDisposition::Rejected,
                ),
            ),
        ] {
            let mut store = MemoryInvocationIndexStore::default();
            let empty = InvocationIndex::<MemoryInvocationIndexStore>::create_empty(
                &mut store,
                genesis(1),
                scope,
            )
            .unwrap();
            let mut index = InvocationIndex::open(&mut store, empty).unwrap();
            assert!(matches!(
                index.record(key(scope, id), invalid),
                Err(InvocationIndexError::InvalidTransition)
                    | Err(InvocationIndexError::NonCanonicalTree)
            ));
        }

        let scope = InvocationOwnershipScope::Merge;
        let id = invocation([0x23; 32]);
        let mut store = MemoryInvocationIndexStore::default();
        let empty = InvocationIndex::<MemoryInvocationIndexStore>::create_empty(
            &mut store,
            genesis(1),
            scope,
        )
        .unwrap();
        let mut index = InvocationIndex::open(&mut store, empty).unwrap();
        let retained = persist_retained(&mut index, scope, id);
        assert!(matches!(
            index.record(key(scope, id), retained),
            Err(InvocationIndexError::InvalidTransition)
        ));
    }

    #[test]
    fn retained_leaf_requires_available_exact_outcome_bytes() {
        let scope = InvocationOwnershipScope::Ordered;
        let id = invocation([0x24; 32]);
        let mut store = MemoryInvocationIndexStore::default();
        let empty = InvocationIndex::<MemoryInvocationIndexStore>::create_empty(
            &mut store,
            genesis(1),
            scope,
        )
        .unwrap();
        let mut index = InvocationIndex::open(&mut store, empty).unwrap();
        let (retained, outcome) = retained_for(genesis(1), scope, id);
        let outcome_id = outcome.id();
        assert!(matches!(
            index.record(key(scope, id), retained),
            Err(InvocationIndexError::MissingOutcome(found)) if found == outcome_id
        ));
        assert_eq!(index.id(), empty);
        assert_eq!(index.manifest().entries, 0);
    }

    #[test]
    fn outcome_transplants_and_duplicated_fact_mismatches_are_rejected() {
        let scope = InvocationOwnershipScope::Ordered;
        let id = invocation([0x25; 32]);
        let mut store = MemoryInvocationIndexStore::default();
        let empty = InvocationIndex::<MemoryInvocationIndexStore>::create_empty(
            &mut store,
            genesis(1),
            scope,
        )
        .unwrap();
        let mut index = InvocationIndex::open(&mut store, empty).unwrap();

        let transplanted_outcome = test_outcome(genesis(2), scope, id);
        let transplanted_ref = index.persist_outcome(&transplanted_outcome).unwrap();
        let transplanted_owner = owner_with_state(
            scope,
            id,
            InvocationResultState::Retained {
                disposition: transplanted_outcome.disposition(),
                outcome: transplanted_ref,
            },
        );
        assert!(matches!(
            index.record(key(scope, id), transplanted_owner),
            Err(InvocationIndexError::CorruptOutcome(found)) if found == transplanted_ref.outcome
        ));

        let (mut mismatched_owner, outcome) = retained_for(genesis(1), scope, id);
        let reference = index.persist_outcome(&outcome).unwrap();
        mismatched_owner.request_commitment = Hash([0xb1; 32]);
        assert!(matches!(
            index.record(key(scope, id), mismatched_owner),
            Err(InvocationIndexError::CorruptOutcome(found)) if found == reference.outcome
        ));

        let wrong_disposition = owner_with_state(
            scope,
            id,
            InvocationResultState::Retained {
                disposition: InvocationDisposition::Applied,
                outcome: reference,
            },
        );
        assert!(matches!(
            index.record(key(scope, id), wrong_disposition),
            Err(InvocationIndexError::CorruptOutcome(found)) if found == reference.outcome
        ));
        assert_eq!(index.id(), empty);
    }

    #[test]
    fn outcome_put_detects_collision_and_readback_corruption() {
        let scope = InvocationOwnershipScope::Ordered;
        let id = invocation([0x26; 32]);
        let other_id = invocation([0x27; 32]);
        let mut store = MemoryInvocationIndexStore::default();
        let empty = InvocationIndex::<MemoryInvocationIndexStore>::create_empty(
            &mut store,
            genesis(1),
            scope,
        )
        .unwrap();
        let outcome = test_outcome(genesis(1), scope, id);
        let other = test_outcome(genesis(1), scope, other_id);
        store.outcomes.insert(outcome.id(), other.encode());
        {
            let mut index = InvocationIndex::open(&mut store, empty).unwrap();
            assert_eq!(
                index.persist_outcome(&outcome),
                Err(InvocationIndexError::ObjectCollision)
            );
        }

        let reference = InvocationOutcomeRef::for_record(&outcome).unwrap();
        store
            .outcomes
            .insert(reference.outcome, vec![0; reference.encoded_bytes as usize]);
        let retained = owner_with_state(
            scope,
            id,
            InvocationResultState::Retained {
                disposition: outcome.disposition(),
                outcome: reference,
            },
        );
        let mut index = InvocationIndex::open(&mut store, empty).unwrap();
        assert!(matches!(
            index.record(key(scope, id), retained),
            Err(InvocationIndexError::CorruptOutcome(found)) if found == reference.outcome
        ));
    }

    #[test]
    fn unrelated_outcome_corruption_is_lazy_until_access_or_audit() {
        let scope = InvocationOwnershipScope::Ordered;
        let left_key = invocation([0x10; 32]);
        let right_key = invocation([0x80; 32]);
        let (mut store, id, manifest) = build(&[left_key, right_key]);
        let right_reference = retained(scope, right_key).outcome().unwrap();
        store.outcomes.get_mut(&right_reference.outcome).unwrap()[40] ^= 0x40;

        {
            let index = InvocationIndex::open(&mut store, id).unwrap();
            assert!(index.lookup(key(scope, left_key)).unwrap().is_some());
            assert!(matches!(
                index.lookup(key(scope, right_key)),
                Err(InvocationIndexError::CorruptOutcome(found))
                    if found == right_reference.outcome
            ));
        }
        assert!(matches!(
            audit_manifest(&store, id, &manifest),
            Err(InvocationIndexError::CorruptOutcome(found)) if found == right_reference.outcome
        ));
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
            owner: acknowledged(scope, middle_key, InvocationDisposition::Rejected),
        });
        let right = InvocationIndexNode::Leaf(InvocationOwnershipLeaf {
            genesis,
            key: key(scope, right_key),
            owner: acknowledged(scope, right_key, InvocationDisposition::Rejected),
        });
        let middle_ref = put_node_immutable(&mut store, &middle).unwrap();
        let right_ref = put_node_immutable(&mut store, &right).unwrap();
        let fake_cycle_id = InvocationIndexNodeId([0x55; 32]);
        let cycle_summary = InvocationIndexSummary {
            min: left_key,
            max: middle_key,
            entries: 2,
            tombstones: 2,
            unfinalized: 0,
            outcome_records: 0,
            reserved_outcome_bytes: 0,
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
                    tombstones: 1,
                    unfinalized: 0,
                    outcome_records: 0,
                    reserved_outcome_bytes: 0,
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
            tombstones: 3,
            unfinalized: 0,
            outcome_records: 0,
            reserved_outcome_bytes: 0,
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
                InvocationIndexProofResult::Member(retained(
                    InvocationOwnershipScope::Ordered,
                    value,
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
        let acknowledged = acknowledged(
            InvocationOwnershipScope::Ordered,
            target,
            InvocationDisposition::Rejected,
        );
        index
            .record(key(InvocationOwnershipScope::Ordered, target), acknowledged)
            .unwrap();
        // Two prevalidation walks, the replacement walk, and immutable CAS
        // read-before/readback checks remain a constant number of path reads.
        assert!(counts.node_loads.get() <= 6 * (MAX_INVOCATION_INDEX_PATH + 1));
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

    impl InvocationOutcomeStore for CountingStore {
        fn load_outcome(&self, id: InvocationOutcomeId) -> Result<Option<Vec<u8>>, Self::Error> {
            self.inner.load_outcome(id)
        }

        fn put_outcome(
            &mut self,
            id: InvocationOutcomeId,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            self.inner.put_outcome(id, bytes)
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

    impl InvocationOutcomeStore for FailingManifestStore {
        fn load_outcome(&self, id: InvocationOutcomeId) -> Result<Option<Vec<u8>>, Self::Error> {
            self.inner
                .load_outcome(id)
                .map_err(InjectedStoreError::Inner)
        }

        fn put_outcome(
            &mut self,
            id: InvocationOutcomeId,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            self.inner
                .put_outcome(id, bytes)
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
            let (owner, outcome) = retained_for(genesis(1), scope, id);
            index.persist_outcome(&outcome).unwrap();
            assert!(matches!(
                index.record(key(scope, id), owner),
                Err(InvocationIndexError::Storage(InjectedStoreError::Injected))
            ));
            assert_eq!(index.id(), empty);
        }
        assert_eq!(store.inner.node_count(), 1);
        assert_eq!(store.inner.manifest_count(), 1);
    }

    #[test]
    fn failed_batch_restores_the_opened_manifest_and_id() {
        let scope = InvocationOwnershipScope::Ordered;
        let first = invocation([0x31; 32]);
        let second = invocation([0x32; 32]);
        let mut store = FailingManifestStore {
            inner: MemoryInvocationIndexStore::default(),
            fail_manifest: false,
        };
        let empty =
            InvocationIndex::<FailingManifestStore>::create_empty(&mut store, genesis(1), scope)
                .unwrap();
        let (first_owner, first_outcome) = retained_for(genesis(1), scope, first);
        let (second_owner, second_outcome) = retained_for(genesis(1), scope, second);
        put_outcome_immutable(&mut store, &first_outcome).unwrap();
        put_outcome_immutable(&mut store, &second_outcome).unwrap();
        store.fail_manifest = true;

        {
            let mut index = InvocationIndex::open(&mut store, empty).unwrap();
            let original = *index.manifest();
            assert!(matches!(
                index.record_batch(&[
                    (key(scope, first), first_owner),
                    (key(scope, second), second_owner),
                ]),
                Err(InvocationIndexError::Storage(InjectedStoreError::Injected))
            ));
            assert_eq!(index.id(), empty);
            assert_eq!(*index.manifest(), original);
            assert_eq!(index.lookup(key(scope, first)).unwrap(), None);
            assert_eq!(index.lookup(key(scope, second)).unwrap(), None);
        }
        assert!(
            store.inner.node_count() >= 1,
            "immutable orphans are allowed"
        );
        assert_eq!(store.inner.manifest_count(), 1);
    }

    #[test]
    fn batch_requires_strict_canonical_key_order_and_uniqueness() {
        let scope = InvocationOwnershipScope::Ordered;
        let low = invocation([0x41; 32]);
        let high = invocation([0x42; 32]);
        let mut store = MemoryInvocationIndexStore::default();
        let empty = InvocationIndex::<MemoryInvocationIndexStore>::create_empty(
            &mut store,
            genesis(1),
            scope,
        )
        .unwrap();
        let mut index = InvocationIndex::open(&mut store, empty).unwrap();
        let low_owner = persist_retained(&mut index, scope, low);
        let high_owner = persist_retained(&mut index, scope, high);
        for values in [
            vec![(key(scope, high), high_owner), (key(scope, low), low_owner)],
            vec![(key(scope, low), low_owner), (key(scope, low), low_owner)],
        ] {
            assert!(matches!(
                index.record_batch(&values),
                Err(InvocationIndexError::NonCanonicalTree)
            ));
            assert_eq!(index.id(), empty);
        }
    }

    #[test]
    fn final_net_batch_can_reuse_a_live_slot_regardless_of_key_order() {
        let scope = InvocationOwnershipScope::Ordered;
        let mut members = ids(MAX_INVOCATION_INDEX_LIVE_ENTRIES as usize);
        let (mut store, id, _) = build(&members);
        members.sort();
        let acknowledged_id = *members.last().unwrap();
        let inserted_id = invocation({
            let mut bytes = [0; 32];
            bytes[31] = 1;
            bytes
        });
        assert!(inserted_id < acknowledged_id);
        assert!(!members.contains(&inserted_id));

        let mut index = InvocationIndex::open(&mut store, id).unwrap();
        let inserted_owner = persist_retained(&mut index, scope, inserted_id);
        assert!(matches!(
            index.record(key(scope, inserted_id), inserted_owner),
            Err(InvocationIndexError::Capacity)
        ));
        let acknowledged_owner =
            acknowledged(scope, acknowledged_id, InvocationDisposition::Rejected);
        let next = index
            .record_batch(&[
                (key(scope, inserted_id), inserted_owner),
                (key(scope, acknowledged_id), acknowledged_owner),
            ])
            .unwrap();
        assert_eq!(next, index.id());
        assert_eq!(
            index.manifest().entries,
            MAX_INVOCATION_INDEX_LIVE_ENTRIES + 1
        );
        assert_eq!(index.manifest().tombstones, 1);
        assert_eq!(
            index.manifest().entries - index.manifest().tombstones,
            MAX_INVOCATION_INDEX_LIVE_ENTRIES
        );
        assert_eq!(
            index.lookup(key(scope, inserted_id)).unwrap(),
            Some(inserted_owner)
        );
        assert_eq!(
            index.lookup(key(scope, acknowledged_id)).unwrap(),
            Some(acknowledged_owner)
        );
    }

    #[test]
    fn summaries_enforce_live_and_reserved_outcome_capacity() {
        let valid = InvocationIndexSummary {
            min: invocation([1; 32]),
            max: invocation([2; 32]),
            entries: MAX_INVOCATION_INDEX_LIVE_ENTRIES,
            tombstones: 0,
            unfinalized: MAX_INVOCATION_INDEX_LIVE_ENTRIES,
            outcome_records: 0,
            reserved_outcome_bytes: MAX_INVOCATION_INDEX_RESERVED_OUTCOME_BYTES,
        };
        valid.validate().unwrap();

        assert_eq!(
            InvocationIndexSummary {
                entries: valid.entries + 1,
                reserved_outcome_bytes: valid.reserved_outcome_bytes + 1,
                ..valid
            }
            .validate(),
            Err(DecodeError::NonCanonical)
        );
        assert_eq!(
            InvocationIndexSummary {
                tombstones: valid.entries,
                unfinalized: 0,
                reserved_outcome_bytes: 1,
                ..valid
            }
            .validate(),
            Err(DecodeError::NonCanonical)
        );
        assert_eq!(
            InvocationIndexSummary {
                unfinalized: valid.entries + 1,
                ..valid
            }
            .validate(),
            Err(DecodeError::NonCanonical)
        );
        assert_eq!(
            InvocationIndexSummary {
                outcome_records: valid.entries + 1,
                ..valid
            }
            .validate(),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn reachability_is_empty_or_sorted_and_independent_of_insertion_order() {
        let mut empty_store = MemoryInvocationIndexStore::default();
        let empty_id = InvocationIndex::<MemoryInvocationIndexStore>::create_empty(
            &mut empty_store,
            genesis(1),
            InvocationOwnershipScope::Ordered,
        )
        .unwrap();
        let empty_manifest = load_manifest(&empty_store, empty_id).unwrap();
        assert_eq!(
            collect_manifest_reachability(&empty_store, empty_id, &empty_manifest, 0).unwrap(),
            InvocationIndexReachability {
                nodes: Vec::new(),
                outcomes: Vec::new(),
            }
        );

        let values = [
            invocation([0xf0; 32]),
            invocation([0x10; 32]),
            invocation([0x80; 32]),
        ];
        let (store, id, manifest) = build(&values);
        let reachability = collect_manifest_reachability(&store, id, &manifest, 5).unwrap();
        assert_eq!(reachability.nodes.len(), 5);
        assert_eq!(reachability.outcomes.len(), 3);
        assert!(reachability.nodes.windows(2).all(|ids| ids[0] < ids[1]));
        assert!(reachability.outcomes.windows(2).all(|ids| ids[0] < ids[1]));

        let mut reversed = values;
        reversed.reverse();
        let (other_store, other_id, other_manifest) = build(&reversed);
        assert_eq!(other_id, id);
        assert_eq!(
            collect_manifest_reachability(&other_store, other_id, &other_manifest, 5).unwrap(),
            reachability
        );
    }

    #[test]
    fn reachability_enforces_both_caller_and_store_node_limits() {
        let values = [invocation([0x10; 32]), invocation([0x80; 32])];
        let (store, id, manifest) = build(&values);
        assert!(matches!(
            collect_manifest_reachability(&store, id, &manifest, 2),
            Err(InvocationIndexError::NodeLimit)
        ));
        assert_eq!(
            collect_manifest_reachability(&store, id, &manifest, 3)
                .unwrap()
                .nodes
                .len(),
            3
        );

        let mut limited = MemoryInvocationIndexStore::with_node_limit(2);
        limited.manifests = store.manifests;
        limited.nodes = store.nodes;
        limited.outcomes = store.outcomes;
        assert!(matches!(
            collect_manifest_reachability(&limited, id, &manifest, 3),
            Err(InvocationIndexError::NodeLimit)
        ));
    }

    #[test]
    fn default_reachability_limit_covers_the_complete_logical_epoch() {
        assert_eq!(full_tree_node_count(500_001), Some(1_000_001));
        assert_eq!(
            full_tree_node_count(MAX_INVOCATION_INDEX_LOGICAL_ENTRIES),
            Some(DEFAULT_INVOCATION_INDEX_NODE_LIMIT)
        );

        let store = MemoryInvocationIndexStore::default();
        for (entries, root_byte) in [
            (500_001, 0xa1),
            (MAX_INVOCATION_INDEX_LOGICAL_ENTRIES, 0xa2),
        ] {
            let root = InvocationIndexNodeId([root_byte; 32]);
            let manifest = InvocationIndexManifest {
                genesis: genesis(1),
                scope: InvocationOwnershipScope::Ordered,
                root: Some(root),
                entries,
                tombstones: entries,
                unfinalized: 0,
                outcome_records: 0,
                reserved_outcome_bytes: 0,
            };
            let expected = manifest.id();
            assert!(matches!(
                collect_manifest_reachability(
                    &store,
                    expected,
                    &manifest,
                    DEFAULT_INVOCATION_INDEX_NODE_LIMIT,
                ),
                Err(InvocationIndexError::MissingNode(found)) if found == root
            ));
        }
    }

    #[test]
    fn reachability_authenticates_every_retained_outcome() {
        let values = [invocation([0x10; 32]), invocation([0x80; 32])];
        let (mut store, id, manifest) = build(&values);
        let reference = retained(InvocationOwnershipScope::Ordered, values[1])
            .outcome()
            .unwrap();
        store.outcomes.get_mut(&reference.outcome).unwrap()[40] ^= 0x40;
        assert!(matches!(
            collect_manifest_reachability(&store, id, &manifest, 3),
            Err(InvocationIndexError::CorruptOutcome(found)) if found == reference.outcome
        ));
    }

    #[test]
    fn reachability_excludes_pending_and_tombstoned_outcomes() {
        let scope = InvocationOwnershipScope::Merge;
        let pending_id = invocation([0x10; 32]);
        let pending_ack_id = invocation([0x80; 32]);
        let tombstone_id = invocation([0xf0; 32]);
        let mut store = MemoryInvocationIndexStore::default();
        let empty = InvocationIndex::<MemoryInvocationIndexStore>::create_empty(
            &mut store,
            genesis(1),
            scope,
        )
        .unwrap();
        let pending_ack_reference;
        let tombstoned_reference;
        let final_id = {
            let mut index = InvocationIndex::open(&mut store, empty).unwrap();
            index
                .record(key(scope, pending_id), pending_merge(pending_id))
                .unwrap();

            index
                .record(key(scope, pending_ack_id), pending_merge(pending_ack_id))
                .unwrap();
            let retained = persist_retained(&mut index, scope, pending_ack_id);
            pending_ack_reference = retained.outcome().unwrap();
            index.record(key(scope, pending_ack_id), retained).unwrap();
            index
                .record(
                    key(scope, pending_ack_id),
                    owner_with_state(
                        scope,
                        pending_ack_id,
                        InvocationResultState::PendingMergeAcknowledgement {
                            acknowledgement_event: MergeEventId(
                                Hash::digest(b"index-test-acknowledgement", &[&pending_ack_id.0]).0,
                            ),
                            disposition: retained.disposition().unwrap(),
                            outcome: pending_ack_reference,
                        },
                    ),
                )
                .unwrap();

            index
                .record(key(scope, tombstone_id), pending_merge(tombstone_id))
                .unwrap();
            let retained = persist_retained(&mut index, scope, tombstone_id);
            tombstoned_reference = retained.outcome().unwrap();
            index.record(key(scope, tombstone_id), retained).unwrap();
            index
                .record(
                    key(scope, tombstone_id),
                    owner_with_state(
                        scope,
                        tombstone_id,
                        InvocationResultState::PendingMergeAcknowledgement {
                            acknowledgement_event: MergeEventId(
                                Hash::digest(b"index-test-acknowledgement", &[&tombstone_id.0]).0,
                            ),
                            disposition: retained.disposition().unwrap(),
                            outcome: tombstoned_reference,
                        },
                    ),
                )
                .unwrap();
            index
                .record(
                    key(scope, tombstone_id),
                    acknowledged(scope, tombstone_id, retained.disposition().unwrap()),
                )
                .unwrap();
            index.id()
        };
        let manifest = load_manifest(&store, final_id).unwrap();
        let reachability = collect_manifest_reachability(&store, final_id, &manifest, 5).unwrap();
        assert_eq!(reachability.nodes.len(), 5);
        assert_eq!(reachability.outcomes, vec![pending_ack_reference.outcome]);
        assert!(
            !reachability
                .outcomes
                .contains(&tombstoned_reference.outcome)
        );
        assert_eq!(store.outcome_count(), 2);
    }

    #[test]
    fn ordinary_paths_ignore_full_audit_budget() {
        let values = [invocation([0x10; 32]), invocation([0x80; 32])];
        let (store, id, manifest) = build(&values);
        let mut limited = MemoryInvocationIndexStore::with_node_limit(2);
        limited.manifests = store.manifests;
        limited.nodes = store.nodes;
        limited.outcomes = store.outcomes;
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
    fn logical_cap_allows_retries_and_transitions_but_not_new_members() {
        let scope = InvocationOwnershipScope::Ordered;
        let genesis = genesis(7);
        let left_key = invocation([0x10; 32]);
        let mut store = MemoryInvocationIndexStore::with_node_limit(2);
        let (left_owner, left_outcome) = retained_for(genesis, scope, left_key);
        put_outcome_immutable(&mut store, &left_outcome).unwrap();
        let left = InvocationIndexNode::Leaf(InvocationOwnershipLeaf {
            genesis,
            key: key(scope, left_key),
            owner: left_owner,
        });
        let left = put_node_immutable(&mut store, &left).unwrap();
        // This synthetic sibling summary represents acknowledged history whose
        // physical closure is outside the tiny scrub budget. Ordinary work on
        // the left path can still retry/transition at the logical epoch cap.
        let historical_entries = MAX_INVOCATION_INDEX_LOGICAL_ENTRIES - 1;
        let right = InvocationIndexChild {
            id: InvocationIndexNodeId([0xee; 32]),
            summary: InvocationIndexSummary {
                min: invocation([0x80; 32]),
                max: invocation([0xff; 32]),
                entries: historical_entries,
                tombstones: historical_entries,
                unfinalized: 0,
                outcome_records: 0,
                reserved_outcome_bytes: 0,
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
            entries: MAX_INVOCATION_INDEX_LOGICAL_ENTRIES,
            tombstones: historical_entries,
            unfinalized: 0,
            outcome_records: 1,
            reserved_outcome_bytes: left_owner.reserved_outcome_bytes(),
        };
        let id = put_manifest_immutable(&mut store, &manifest).unwrap();
        let (next_id, next_manifest) = {
            let mut index = InvocationIndex::open(&mut store, id).unwrap();
            assert!(index.lookup(key(scope, left_key)).unwrap().is_some());
            assert_eq!(
                index.record(key(scope, left_key), left_owner).unwrap(),
                InvocationIndexMutation::ExactRetry(id)
            );
            let acknowledged = acknowledged(scope, left_key, InvocationDisposition::Rejected);
            index.record(key(scope, left_key), acknowledged).unwrap();
            let new_key = invocation([0x20; 32]);
            let new_owner = persist_retained(&mut index, scope, new_key);
            assert!(matches!(
                index.record(key(scope, new_key), new_owner),
                Err(InvocationIndexError::Capacity)
            ));
            (index.id(), *index.manifest())
        };
        assert_ne!(next_id, id);
        assert_eq!(next_manifest.entries, MAX_INVOCATION_INDEX_LOGICAL_ENTRIES);
        assert_eq!(
            next_manifest.tombstones,
            MAX_INVOCATION_INDEX_LOGICAL_ENTRIES
        );
        assert_eq!(next_manifest.reserved_outcome_bytes, 0);
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
        let ordered_invocation = invocation([0x11; 32]);
        let merge_invocation = invocation([0x22; 32]);
        let local_invocation = invocation([0x33; 32]);
        let (ordered_owner, ordered_outcome) = retained_for(
            genesis,
            InvocationOwnershipScope::Ordered,
            ordered_invocation,
        );
        let (local_owner, local_outcome) = retained_for(
            genesis,
            InvocationOwnershipScope::Local(local_node),
            local_invocation,
        );
        let (next_ordered, next_merge, next_local) = {
            let mut indexes = InvocationIndexes::open(&mut store, ordered, merge, local).unwrap();
            assert_eq!(indexes.genesis(), genesis);
            assert_eq!(indexes.local_node(), local_node);
            assert_eq!(
                indexes.persist_outcome(&ordered_outcome).unwrap(),
                ordered_owner.outcome().unwrap()
            );
            assert_eq!(
                indexes.persist_outcome(&local_outcome).unwrap(),
                local_owner.outcome().unwrap()
            );
            let cases = [
                (
                    InvocationOwnershipScope::Ordered,
                    ordered_invocation,
                    ordered_owner,
                ),
                (
                    InvocationOwnershipScope::Merge,
                    merge_invocation,
                    pending_merge(merge_invocation),
                ),
                (
                    InvocationOwnershipScope::Local(local_node),
                    local_invocation,
                    local_owner,
                ),
            ];
            for (scope, invocation, owner) in cases {
                indexes.record(key(scope, invocation), owner).unwrap();
                assert!(indexes.lookup(key(scope, invocation)).unwrap().is_some());
                assert_eq!(indexes.manifest(scope).unwrap().entries, 1);
            }
            assert_eq!(
                indexes
                    .outcome(key(InvocationOwnershipScope::Ordered, ordered_invocation,))
                    .unwrap(),
                Some(ordered_outcome)
            );
            assert_eq!(
                indexes
                    .unfinalized(InvocationOwnershipScope::Merge)
                    .unwrap(),
                1
            );
            let merge_before = indexes.index_id(InvocationOwnershipScope::Merge).unwrap();
            assert_eq!(
                indexes
                    .record_batch(InvocationOwnershipScope::Merge, &[])
                    .unwrap(),
                merge_before
            );
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
