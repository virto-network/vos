//! Cumulative authenticated history of acknowledged invocation owners.
//!
//! Each ownership scope has one immutable binary Patricia tree keyed by the
//! big-endian bits of `InvocationId`. A mutation is prepared entirely in an
//! in-memory overlay. Its canonical write plan contains every newly reachable
//! node plus enough facts to re-derive the exact root transition and the exact
//! set of superseded, previously reachable nodes after a crash.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::fmt;

pub(crate) use super::journal::MAX_INVOCATION_HISTORY_NODE_BYTES;
use super::journal::{
    AgentJournalGenesisId, CanonicalJournalRecord, InvocationAcknowledgedFact,
    InvocationHistoryNodeId, InvocationOwnershipScope, JournalStorageClass,
    MAX_INVOCATION_HISTORY_FACT_BYTES,
};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{Hash, InvocationId, NodeId};

/// A Patricia lookup or insertion traverses at most one branch per key bit.
pub(crate) const MAX_INVOCATION_HISTORY_PATH: usize = 256;
/// One inserted fact can create one leaf, one split, and one replacement node
/// for every branch on its authenticated path.
pub(crate) const MAX_INVOCATION_HISTORY_NODES_PER_INSERT: usize = MAX_INVOCATION_HISTORY_PATH + 2;
/// One publication can archive a bounded Merge import or retire every exact
/// proof edge replaced by the largest replay-sealed Merge batch.
pub(crate) const MAX_INVOCATION_HISTORY_INSERTIONS: usize =
    super::journal::MAX_REPLAY_SUFFIX_ENTRIES;
/// Maximum nodes retained by one cumulative publication overlay.
pub(crate) const MAX_INVOCATION_HISTORY_PLAN_NODES: usize =
    MAX_INVOCATION_HISTORY_INSERTIONS * MAX_INVOCATION_HISTORY_NODES_PER_INSERT;
/// Maximum replaced global path nodes named by one publication.
pub(crate) const MAX_INVOCATION_HISTORY_RETIRED_NODES: usize =
    MAX_INVOCATION_HISTORY_INSERTIONS * MAX_INVOCATION_HISTORY_PATH;
/// Maximum canonical bytes read along one authenticated history path.
pub(crate) const MAX_INVOCATION_HISTORY_PATH_BYTES: usize =
    (MAX_INVOCATION_HISTORY_PATH + 1) * MAX_INVOCATION_HISTORY_NODE_BYTES;
/// Maximum aggregate canonical bytes in the reachable overlay nodes.
pub(crate) const MAX_INVOCATION_HISTORY_PLAN_NODE_BYTES: usize =
    MAX_INVOCATION_HISTORY_PLAN_NODES * MAX_INVOCATION_HISTORY_NODE_BYTES;

const SERVICE_WIRE_HEADER_BYTES: usize = 4 + 32;
const SCOPE_MAX_BYTES: usize = 1 + 32;
const OPTIONAL_ID_MAX_BYTES: usize = 1 + 32;
const LIST_LENGTH_BYTES: usize = 4;
const NODE_WRITE_MAX_BYTES: usize = 1 + 32 + 4 + MAX_INVOCATION_HISTORY_NODE_BYTES;
/// Complete bounded crash-recovery wire for one history transition.
pub(crate) const MAX_INVOCATION_HISTORY_WRITE_PLAN_BYTES: usize = SERVICE_WIRE_HEADER_BYTES
    + 32
    + SCOPE_MAX_BYTES
    + 2 * OPTIONAL_ID_MAX_BYTES
    + 3 * LIST_LENGTH_BYTES
    + MAX_INVOCATION_HISTORY_INSERTIONS * (4 + MAX_INVOCATION_HISTORY_FACT_BYTES)
    + MAX_INVOCATION_HISTORY_PLAN_NODES * NODE_WRITE_MAX_BYTES
    + MAX_INVOCATION_HISTORY_RETIRED_NODES * 32;

const NODE_ID_DOMAIN: &[u8] = b"vos/agent/journal/invocation-history-node/v1";

/// Immutable storage resolver used during lookup and preparation. Candidate
/// overlays are supplied by [`InvocationHistoryWritePlan`], never written by
/// this engine.
pub(crate) trait InvocationHistoryStore {
    type Error;

    fn load_history_node(
        &self,
        id: InvocationHistoryNodeId,
    ) -> Result<Option<Vec<u8>>, Self::Error>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InvocationHistoryError<E> {
    Storage(E),
    MissingNode(InvocationHistoryNodeId),
    CorruptNode(InvocationHistoryNodeId),
    GenesisMismatch,
    ScopeMismatch,
    SummaryMismatch,
    NonCanonicalTree,
    Cycle,
    PathLimit,
    NodeLimit,
    PlanLimit,
    ObjectCollision(InvocationHistoryNodeId),
    Conflict,
    InvalidFact,
    InvalidPlan,
}

impl<E: fmt::Debug> fmt::Display for InvocationHistoryError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid invocation acknowledgement history: {self:?}"
        )
    }
}

impl<E: fmt::Debug> core::error::Error for InvocationHistoryError<E> {}

/// Authenticated key range of one non-empty subtree. No cardinality is stored:
/// history is cumulative and has no protocol lifetime ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InvocationHistorySummary {
    min: InvocationId,
    max: InvocationId,
    /// Authenticated tree-wide purpose. Branch construction requires both
    /// children to agree, so inspecting the root proves the history class
    /// without an unbounded full-tree walk.
    transition_proof: bool,
}

impl InvocationHistorySummary {
    fn from_fact(fact: &InvocationAcknowledgedFact) -> Self {
        Self {
            min: fact.key().invocation,
            max: fact.key().invocation,
            transition_proof: fact.is_transition_proof_retirement(),
        }
    }

    fn validate(self) -> Result<(), DecodeError> {
        if self.min == InvocationId::ZERO || self.max == InvocationId::ZERO || self.min > self.max {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InvocationHistoryChild {
    id: InvocationHistoryNodeId,
    summary: InvocationHistorySummary,
}

impl InvocationHistoryChild {
    fn validate(self) -> Result<(), DecodeError> {
        if self.id == InvocationHistoryNodeId::ZERO {
            return Err(DecodeError::NonCanonical);
        }
        self.summary.validate()
    }
}

/// One immutable scope- and genesis-bound acknowledged-history node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InvocationHistoryNode {
    Leaf(InvocationAcknowledgedFact),
    Branch {
        genesis: AgentJournalGenesisId,
        scope: InvocationOwnershipScope,
        /// First differing bit, indexed most-significant-bit first.
        bit: u16,
        /// Common bits strictly before `bit`; all later bits are zero.
        prefix: [u8; 32],
        left: InvocationHistoryChild,
        right: InvocationHistoryChild,
    },
}

impl InvocationHistoryNode {
    pub(crate) fn genesis(&self) -> AgentJournalGenesisId {
        match self {
            Self::Leaf(fact) => fact.genesis(),
            Self::Branch { genesis, .. } => *genesis,
        }
    }

    pub(crate) fn scope(&self) -> InvocationOwnershipScope {
        match self {
            Self::Leaf(fact) => fact.key().scope,
            Self::Branch { scope, .. } => *scope,
        }
    }

    fn summary(&self) -> InvocationHistorySummary {
        match self {
            Self::Leaf(fact) => InvocationHistorySummary::from_fact(fact),
            Self::Branch { left, right, .. } => InvocationHistorySummary {
                min: left.summary.min,
                max: right.summary.max,
                transition_proof: left.summary.transition_proof,
            },
        }
    }

    fn validate_inner(&self) -> Result<(), DecodeError> {
        match self {
            Self::Leaf(fact) => fact.validate()?,
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
                    || left.summary.transition_proof != right.summary.transition_proof
                    || !summary_matches_partition(left.summary, prefix, bit, false)
                    || !summary_matches_partition(right.summary, prefix, bit, true)
                {
                    return Err(DecodeError::NonCanonical);
                }
                self.summary().validate()?;
            }
        }
        if self.encode().len() > MAX_INVOCATION_HISTORY_NODE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        Ok(())
    }
}

impl ServiceWire for InvocationHistoryNode {
    const MAGIC: [u8; 4] = *b"AIH2";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        match self {
            Self::Leaf(fact) => {
                encoder.u8(0);
                encoder.bytes(&fact.encode());
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
        if decoder
            .remaining()
            .saturating_add(SERVICE_WIRE_HEADER_BYTES)
            > MAX_INVOCATION_HISTORY_NODE_BYTES
        {
            return Err(DecodeError::LimitExceeded);
        }
        let node = match decoder.u8()? {
            0 => Self::Leaf(InvocationAcknowledgedFact::decode(&decoder.bytes()?)?),
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

impl super::journal::sealed::Sealed for InvocationHistoryNode {}

impl CanonicalJournalRecord for InvocationHistoryNode {
    type Id = InvocationHistoryNodeId;

    const STORAGE_CLASS: JournalStorageClass = JournalStorageClass::InvocationHistoryNode;

    fn validate(&self) -> Result<(), DecodeError> {
        self.validate_inner()
    }

    fn id(&self) -> Self::Id {
        InvocationHistoryNodeId(Hash::digest(NODE_ID_DOMAIN, &[&self.encode()]).0)
    }
}

/// Canonical immutable node named by a publication plan. Every entry is
/// reachable from the plan's final root; overlay-only intermediate roots are
/// removed before exposure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InvocationHistoryNodeWrite {
    id: InvocationHistoryNodeId,
    bytes: Vec<u8>,
    needs_write: bool,
}

impl InvocationHistoryNodeWrite {
    pub(crate) const fn id(&self) -> InvocationHistoryNodeId {
        self.id
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) const fn needs_write(&self) -> bool {
        self.needs_write
    }

    /// Revalidate the preparation-time classification. A node that needed a
    /// write may since have been staged byte-exactly; a node classified as
    /// reusable must already exist.
    fn validate_availability<S: InvocationHistoryStore>(
        &self,
        store: &S,
    ) -> Result<(), InvocationHistoryError<S::Error>> {
        match store
            .load_history_node(self.id)
            .map_err(InvocationHistoryError::Storage)?
        {
            None if self.needs_write => Ok(()),
            None => Err(InvocationHistoryError::InvalidPlan),
            Some(bytes) if bytes == self.bytes => Ok(()),
            Some(_) => Err(InvocationHistoryError::ObjectCollision(self.id)),
        }
    }
}

/// Canonical bounded crash-recovery description of one history transition.
/// The fields are private so a retirement set can only become authoritative
/// after [`Self::validate`] replays the included facts from `expected_root`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InvocationHistoryWritePlan {
    genesis: AgentJournalGenesisId,
    scope: InvocationOwnershipScope,
    expected_root: Option<InvocationHistoryNodeId>,
    root: Option<InvocationHistoryNodeId>,
    inserted_facts: Vec<InvocationAcknowledgedFact>,
    nodes: Vec<InvocationHistoryNodeWrite>,
    retired_node_ids: Vec<InvocationHistoryNodeId>,
}

impl InvocationHistoryWritePlan {
    pub(crate) const fn genesis(&self) -> AgentJournalGenesisId {
        self.genesis
    }

    pub(crate) const fn scope(&self) -> InvocationOwnershipScope {
        self.scope
    }

    pub(crate) const fn expected_root(&self) -> Option<InvocationHistoryNodeId> {
        self.expected_root
    }

    pub(crate) const fn root(&self) -> Option<InvocationHistoryNodeId> {
        self.root
    }

    pub(crate) fn inserted_facts(&self) -> &[InvocationAcknowledgedFact] {
        &self.inserted_facts
    }

    pub(crate) const fn insertions(&self) -> usize {
        self.inserted_facts.len()
    }

    /// Exact nodes absent when this plan was prepared. Candidate publication
    /// must still use immutable put/readback because a concurrent exact stage
    /// may make one reusable before promotion.
    pub(crate) fn node_writes(&self) -> impl Iterator<Item = &InvocationHistoryNodeWrite> + Clone {
        self.nodes.iter().filter(|write| write.needs_write)
    }

    /// All final-reachable plan-origin nodes. This preserves origin across a
    /// candidate restart even when some bytes already existed globally.
    pub(crate) fn overlay_nodes(&self) -> &[InvocationHistoryNodeWrite] {
        &self.nodes
    }

    pub(crate) fn retired_node_ids(&self) -> &[InvocationHistoryNodeId] {
        &self.retired_node_ids
    }

    pub(crate) fn validate<S: InvocationHistoryStore>(
        &self,
        store: &S,
    ) -> Result<(), InvocationHistoryError<S::Error>> {
        self.validate_structure()
            .map_err(|_| InvocationHistoryError::InvalidPlan)?;
        for write in &self.nodes {
            write.validate_availability(store)?;
        }
        let mut history =
            InvocationHistory::open(store, self.genesis, self.scope, self.expected_root)?;
        for fact in &self.inserted_facts {
            if !history.insert(*fact)?.inserted() {
                return Err(InvocationHistoryError::InvalidPlan);
            }
        }
        let derived = history.write_plan()?;
        if !self.same_transition(&derived) {
            return Err(InvocationHistoryError::InvalidPlan);
        }
        Ok(())
    }

    fn same_transition(&self, other: &Self) -> bool {
        self.genesis == other.genesis
            && self.scope == other.scope
            && self.expected_root == other.expected_root
            && self.root == other.root
            && self.inserted_facts == other.inserted_facts
            && self.nodes.len() == other.nodes.len()
            && self
                .nodes
                .iter()
                .zip(&other.nodes)
                .all(|(left, right)| left.id == right.id && left.bytes == right.bytes)
            && self.retired_node_ids == other.retired_node_ids
    }

    fn validate_structure(&self) -> Result<(), DecodeError> {
        self.scope.validate()?;
        if self.genesis == AgentJournalGenesisId::ZERO
            || self.expected_root == Some(InvocationHistoryNodeId::ZERO)
            || self.root == Some(InvocationHistoryNodeId::ZERO)
        {
            return Err(DecodeError::NonCanonical);
        }
        if self.inserted_facts.len() > MAX_INVOCATION_HISTORY_INSERTIONS
            || self.nodes.len() > MAX_INVOCATION_HISTORY_PLAN_NODES
            || self.retired_node_ids.len() > MAX_INVOCATION_HISTORY_RETIRED_NODES
        {
            return Err(DecodeError::LimitExceeded);
        }
        let unchanged = self.inserted_facts.is_empty();
        if unchanged
            != (self.expected_root == self.root
                && self.nodes.is_empty()
                && self.retired_node_ids.is_empty())
            || (!unchanged && self.root.is_none())
        {
            return Err(DecodeError::NonCanonical);
        }
        let mut previous_fact = None;
        for fact in &self.inserted_facts {
            fact.validate()?;
            if fact.genesis() != self.genesis || fact.key().scope != self.scope {
                return Err(DecodeError::NonCanonical);
            }
            if previous_fact.is_some_and(|previous| previous >= fact.key().invocation) {
                return Err(DecodeError::NonCanonical);
            }
            previous_fact = Some(fact.key().invocation);
        }
        let mut previous_node = None;
        let mut aggregate_bytes = 0usize;
        for write in &self.nodes {
            if write.id == InvocationHistoryNodeId::ZERO
                || write.bytes.len() > MAX_INVOCATION_HISTORY_NODE_BYTES
                || previous_node.is_some_and(|previous| previous >= write.id)
            {
                return Err(DecodeError::NonCanonical);
            }
            aggregate_bytes = aggregate_bytes
                .checked_add(write.bytes.len())
                .ok_or(DecodeError::LimitExceeded)?;
            let node = InvocationHistoryNode::decode(&write.bytes)?;
            if node.id() != write.id || node.genesis() != self.genesis || node.scope() != self.scope
            {
                return Err(DecodeError::NonCanonical);
            }
            previous_node = Some(write.id);
        }
        if aggregate_bytes > MAX_INVOCATION_HISTORY_PLAN_NODE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        if !unchanged
            && self.root.is_none_or(|root| {
                self.nodes
                    .binary_search_by_key(&root, |write| write.id)
                    .is_err()
            })
        {
            return Err(DecodeError::NonCanonical);
        }
        let mut previous_retired = None;
        for id in &self.retired_node_ids {
            if *id == InvocationHistoryNodeId::ZERO
                || previous_retired.is_some_and(|previous| previous >= *id)
                || self
                    .nodes
                    .binary_search_by_key(id, |write| write.id)
                    .is_ok()
            {
                return Err(DecodeError::NonCanonical);
            }
            previous_retired = Some(*id);
        }
        Ok(())
    }
}

impl ServiceWire for InvocationHistoryWritePlan {
    const MAGIC: [u8; 4] = *b"IHWP";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.genesis.0);
        encode_scope(&mut encoder, self.scope);
        encoder.option(&self.expected_root, |encoder, root| encoder.fixed(&root.0));
        encoder.option(&self.root, |encoder, root| encoder.fixed(&root.0));
        encoder.list(&self.inserted_facts, |encoder, fact| {
            encoder.bytes(&fact.encode())
        });
        encoder.list(&self.nodes, |encoder, write| {
            encoder.bool(write.needs_write);
            encoder.fixed(&write.id.0);
            encoder.bytes(&write.bytes);
        });
        encoder.list(&self.retired_node_ids, |encoder, id| encoder.fixed(&id.0));
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if decoder
            .remaining()
            .saturating_add(SERVICE_WIRE_HEADER_BYTES)
            > MAX_INVOCATION_HISTORY_WRITE_PLAN_BYTES
        {
            return Err(DecodeError::LimitExceeded);
        }
        let genesis = AgentJournalGenesisId(decoder.fixed()?);
        let scope = decode_scope(decoder)?;
        let expected_root =
            decoder.option(|decoder| Ok(InvocationHistoryNodeId(decoder.fixed()?)))?;
        let root = decoder.option(|decoder| Ok(InvocationHistoryNodeId(decoder.fixed()?)))?;

        let fact_count = decoder.u32()? as usize;
        if fact_count > MAX_INVOCATION_HISTORY_INSERTIONS {
            return Err(DecodeError::LimitExceeded);
        }
        let mut inserted_facts = Vec::new();
        for _ in 0..fact_count {
            let fact = InvocationAcknowledgedFact::decode(&decoder.bytes()?)?;
            inserted_facts
                .try_reserve(1)
                .map_err(|_| DecodeError::LimitExceeded)?;
            inserted_facts.push(fact);
        }

        let node_count = decoder.u32()? as usize;
        if node_count > MAX_INVOCATION_HISTORY_PLAN_NODES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut nodes = Vec::new();
        for _ in 0..node_count {
            let write = InvocationHistoryNodeWrite {
                needs_write: decoder.bool()?,
                id: InvocationHistoryNodeId(decoder.fixed()?),
                bytes: decoder.bytes()?,
            };
            nodes
                .try_reserve(1)
                .map_err(|_| DecodeError::LimitExceeded)?;
            nodes.push(write);
        }

        let retired_count = decoder.u32()? as usize;
        if retired_count > MAX_INVOCATION_HISTORY_RETIRED_NODES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut retired_node_ids = Vec::new();
        for _ in 0..retired_count {
            let id = InvocationHistoryNodeId(decoder.fixed()?);
            retired_node_ids
                .try_reserve(1)
                .map_err(|_| DecodeError::LimitExceeded)?;
            retired_node_ids.push(id);
        }
        let plan = Self {
            genesis,
            scope,
            expected_root,
            root,
            inserted_facts,
            nodes,
            retired_node_ids,
        };
        plan.validate_structure()?;
        Ok(plan)
    }
}

/// Result of an idempotent insertion attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InvocationHistoryInsert {
    root: Option<InvocationHistoryNodeId>,
    inserted: bool,
}

impl InvocationHistoryInsert {
    pub(crate) const fn root(self) -> Option<InvocationHistoryNodeId> {
        self.root
    }

    pub(crate) const fn inserted(self) -> bool {
        self.inserted
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NodeOrigin {
    Global,
    Overlay,
}

type InvocationHistoryPath = Vec<(
    InvocationHistoryNodeId,
    InvocationHistoryNode,
    bool,
    NodeOrigin,
)>;

/// Lazily authenticated history view with a cumulative, non-persistent
/// publication overlay.
pub(crate) struct InvocationHistory<'a, S: InvocationHistoryStore> {
    store: &'a S,
    genesis: AgentJournalGenesisId,
    scope: InvocationOwnershipScope,
    expected_root: Option<InvocationHistoryNodeId>,
    root: Option<InvocationHistoryNodeId>,
    overlay: BTreeMap<InvocationHistoryNodeId, InvocationHistoryNode>,
    inserted: BTreeMap<InvocationId, InvocationAcknowledgedFact>,
    retired: BTreeSet<InvocationHistoryNodeId>,
}

impl<'a, S: InvocationHistoryStore> InvocationHistory<'a, S> {
    /// Open an authenticated root. Descendants remain lazy and are checked on
    /// the exact paths subsequently read or replaced.
    pub(crate) fn open(
        store: &'a S,
        genesis: AgentJournalGenesisId,
        scope: InvocationOwnershipScope,
        root: Option<InvocationHistoryNodeId>,
    ) -> Result<Self, InvocationHistoryError<S::Error>> {
        scope
            .validate()
            .map_err(|_| InvocationHistoryError::NonCanonicalTree)?;
        if genesis == AgentJournalGenesisId::ZERO || root == Some(InvocationHistoryNodeId::ZERO) {
            return Err(InvocationHistoryError::NonCanonicalTree);
        }
        let history = Self {
            store,
            genesis,
            scope,
            expected_root: root,
            root,
            overlay: BTreeMap::new(),
            inserted: BTreeMap::new(),
            retired: BTreeSet::new(),
        };
        if let Some(root) = root {
            let (node, _) = history.load_node(root)?;
            history.validate_context(&node)?;
        }
        Ok(history)
    }

    /// Reopen a validated cumulative candidate without publishing any node.
    /// Plan nodes remain overlay-origin even if identical candidate bytes have
    /// already been staged globally, so they can never be misclassified as
    /// pre-transition nodes eligible for retirement.
    pub(crate) fn open_with_plan(
        store: &'a S,
        plan: &InvocationHistoryWritePlan,
    ) -> Result<Self, InvocationHistoryError<S::Error>> {
        plan.validate(store)?;
        let mut overlay = BTreeMap::new();
        for write in &plan.nodes {
            let node = InvocationHistoryNode::decode(&write.bytes)
                .map_err(|_| InvocationHistoryError::CorruptNode(write.id))?;
            overlay.insert(write.id, node);
        }
        let inserted = plan
            .inserted_facts
            .iter()
            .map(|fact| (fact.key().invocation, *fact))
            .collect();
        let history = Self {
            store,
            genesis: plan.genesis,
            scope: plan.scope,
            expected_root: plan.expected_root,
            root: plan.root,
            overlay,
            inserted,
            retired: plan.retired_node_ids.iter().copied().collect(),
        };
        if let Some(root) = history.root {
            let (node, _) = history.load_node(root)?;
            history.validate_context(&node)?;
        }
        Ok(history)
    }

    pub(crate) const fn root(&self) -> Option<InvocationHistoryNodeId> {
        self.root
    }

    /// Return the root-authenticated purpose of this cumulative history.
    /// Every descendant path repeats the same purpose in its child summary,
    /// so lookup/insertion also verifies it lazily at each bounded hop.
    pub(crate) fn is_transition_proof_history(
        &self,
    ) -> Result<Option<bool>, InvocationHistoryError<S::Error>> {
        let Some(root) = self.root else {
            return Ok(None);
        };
        let (node, _) = self.load_node(root)?;
        self.validate_context(&node)?;
        Ok(Some(node.summary().transition_proof))
    }

    pub(crate) fn require_history_purpose(
        &self,
        transition_proof: bool,
    ) -> Result<(), InvocationHistoryError<S::Error>> {
        if self
            .is_transition_proof_history()?
            .is_some_and(|actual| actual != transition_proof)
        {
            Err(InvocationHistoryError::InvalidFact)
        } else {
            Ok(())
        }
    }

    /// Audit the complete immutable closure below the opened root.
    ///
    /// This is an operator/test diagnostic, not a production reopen gate:
    /// cumulative history has no protocol cardinality ceiling. Production
    /// lookup and mutation authenticate the root purpose and every summary on
    /// the one bounded Patricia path they traverse. `maximum_nodes` keeps an
    /// explicitly requested diagnostic from becoming an unbounded walk.
    pub(crate) fn validate_complete(
        &self,
        maximum_nodes: usize,
        mut accepts: impl FnMut(InvocationAcknowledgedFact) -> bool,
    ) -> Result<usize, InvocationHistoryError<S::Error>> {
        if maximum_nodes == 0 {
            return Err(InvocationHistoryError::NodeLimit);
        }
        let Some(root) = self.root else {
            return Ok(0);
        };
        let mut stack = Vec::new();
        stack.push((root, None, None));
        let mut visited = BTreeSet::new();
        while let Some((id, parent_bit, expected_summary)) = stack.pop() {
            if !visited.insert(id) {
                return Err(InvocationHistoryError::Cycle);
            }
            if visited.len() > maximum_nodes {
                return Err(InvocationHistoryError::NodeLimit);
            }
            let (node, _) = self.load_node(id)?;
            self.validate_context(&node)?;
            validate_path_summary(&node, expected_summary)?;
            match node {
                InvocationHistoryNode::Leaf(fact) => {
                    if !accepts(fact) {
                        return Err(InvocationHistoryError::InvalidFact);
                    }
                }
                InvocationHistoryNode::Branch {
                    bit, left, right, ..
                } => {
                    enforce_increasing_bit(parent_bit, bit)?;
                    stack.push((right.id, Some(bit), Some(right.summary)));
                    stack.push((left.id, Some(bit), Some(left.summary)));
                }
            }
        }
        Ok(visited.len())
    }

    /// Authenticated membership/nonmembership lookup against the current
    /// global-plus-overlay root.
    pub(crate) fn lookup(
        &self,
        key: super::journal::InvocationOwnershipKey,
    ) -> Result<Option<InvocationAcknowledgedFact>, InvocationHistoryError<S::Error>> {
        key.validate()
            .map_err(|_| InvocationHistoryError::NonCanonicalTree)?;
        if key.scope != self.scope {
            return Err(InvocationHistoryError::ScopeMismatch);
        }
        let Some(mut current) = self.root else {
            return Ok(None);
        };
        let mut expected_summary = None;
        let mut parent_bit = None;
        let mut branches = 0usize;
        let mut visited = BTreeSet::new();
        loop {
            if !visited.insert(current) {
                return Err(InvocationHistoryError::Cycle);
            }
            let (node, _) = self.load_node(current)?;
            self.validate_context(&node)?;
            validate_path_summary(&node, expected_summary)?;
            match node {
                InvocationHistoryNode::Leaf(fact) => {
                    return Ok((fact.key() == key).then_some(fact));
                }
                InvocationHistoryNode::Branch {
                    bit,
                    prefix,
                    left,
                    right,
                    ..
                } => {
                    enforce_increasing_bit(parent_bit, bit)?;
                    branches += 1;
                    if branches > MAX_INVOCATION_HISTORY_PATH {
                        return Err(InvocationHistoryError::PathLimit);
                    }
                    let bit_index = usize::from(bit);
                    if prefix_of(&key.invocation.0, bit_index) != prefix {
                        return Ok(None);
                    }
                    let child = if bit_at(&key.invocation.0, bit_index) {
                        right
                    } else {
                        left
                    };
                    current = child.id;
                    expected_summary = Some(child.summary);
                    parent_bit = Some(bit);
                }
            }
        }
    }

    /// Insert one exact fact. Existing byte-exact facts are idempotent;
    /// reusing an InvocationId for any different permanent fact conflicts.
    pub(crate) fn insert(
        &mut self,
        fact: InvocationAcknowledgedFact,
    ) -> Result<InvocationHistoryInsert, InvocationHistoryError<S::Error>> {
        fact.validate()
            .map_err(|_| InvocationHistoryError::InvalidFact)?;
        if fact.genesis() != self.genesis {
            return Err(InvocationHistoryError::GenesisMismatch);
        }
        if fact.key().scope != self.scope {
            return Err(InvocationHistoryError::ScopeMismatch);
        }

        let Some(root) = self.root else {
            self.require_insert_capacity(1)?;
            let mut pending = BTreeMap::new();
            let leaf = self.plan_node(InvocationHistoryNode::Leaf(fact), &mut pending)?;
            self.commit_insert(fact, pending, BTreeSet::new(), leaf.id);
            return Ok(InvocationHistoryInsert {
                root: self.root,
                inserted: true,
            });
        };

        let (ancestors, terminal_id, terminal) =
            self.path_to_terminal(root, fact.key().invocation)?;
        if let InvocationHistoryNode::Leaf(existing) = terminal {
            if existing.key() == fact.key() {
                if existing == fact {
                    return Ok(InvocationHistoryInsert {
                        root: self.root,
                        inserted: false,
                    });
                }
                return Err(InvocationHistoryError::Conflict);
            }
        }

        self.require_insert_capacity(ancestors.len().saturating_add(2))?;
        let terminal_ref = child_for(terminal_id, &terminal)?;
        let differing = first_differing_bit(&fact.key().invocation.0, &terminal_ref.summary.min.0)
            .ok_or(InvocationHistoryError::Conflict)?;
        let mut pending = BTreeMap::new();
        let inserted = self.plan_node(InvocationHistoryNode::Leaf(fact), &mut pending)?;
        let mut replacement = self.plan_branch(
            differing,
            fact.key().invocation,
            terminal_ref,
            inserted,
            &mut pending,
        )?;
        let mut retired = BTreeSet::new();
        for (id, ancestor, went_right, origin) in ancestors.into_iter().rev() {
            let InvocationHistoryNode::Branch {
                genesis,
                scope,
                bit,
                prefix,
                mut left,
                mut right,
            } = ancestor
            else {
                return Err(InvocationHistoryError::NonCanonicalTree);
            };
            if went_right {
                right = replacement;
            } else {
                left = replacement;
            }
            replacement = self.plan_node(
                InvocationHistoryNode::Branch {
                    genesis,
                    scope,
                    bit,
                    prefix,
                    left,
                    right,
                },
                &mut pending,
            )?;
            if origin == NodeOrigin::Global {
                retired.insert(id);
            }
        }
        if self.retired.len().saturating_add(retired.len()) > MAX_INVOCATION_HISTORY_RETIRED_NODES {
            return Err(InvocationHistoryError::PlanLimit);
        }
        self.commit_insert(fact, pending, retired, replacement.id);
        Ok(InvocationHistoryInsert {
            root: self.root,
            inserted: true,
        })
    }

    /// Freeze the current cumulative overlay. Only nodes reachable from the
    /// final root are retained. The retirement set contains only global nodes
    /// replaced on authenticated paths and excludes every reused global
    /// subtree root.
    pub(crate) fn write_plan(
        &self,
    ) -> Result<InvocationHistoryWritePlan, InvocationHistoryError<S::Error>> {
        let mut reachable_overlay = BTreeSet::new();
        let mut reused_global_roots = BTreeSet::new();
        let mut stack = Vec::new();
        if let Some(root) = self.root {
            stack.push(root);
        }
        while let Some(id) = stack.pop() {
            let Some(node) = self.overlay.get(&id) else {
                reused_global_roots.insert(id);
                continue;
            };
            if !reachable_overlay.insert(id) {
                continue;
            }
            if reachable_overlay.len() > MAX_INVOCATION_HISTORY_PLAN_NODES {
                return Err(InvocationHistoryError::NodeLimit);
            }
            if let InvocationHistoryNode::Branch { left, right, .. } = node {
                stack.push(left.id);
                stack.push(right.id);
            }
        }

        let mut nodes = Vec::new();
        let mut aggregate_bytes = 0usize;
        for id in reachable_overlay {
            let node = self
                .overlay
                .get(&id)
                .ok_or(InvocationHistoryError::InvalidPlan)?;
            let bytes = node.encode();
            aggregate_bytes = aggregate_bytes
                .checked_add(bytes.len())
                .ok_or(InvocationHistoryError::PlanLimit)?;
            if aggregate_bytes > MAX_INVOCATION_HISTORY_PLAN_NODE_BYTES {
                return Err(InvocationHistoryError::PlanLimit);
            }
            let needs_write = match self
                .store
                .load_history_node(id)
                .map_err(InvocationHistoryError::Storage)?
            {
                None => true,
                Some(existing) if existing == bytes => false,
                Some(_) => return Err(InvocationHistoryError::ObjectCollision(id)),
            };
            let write = InvocationHistoryNodeWrite {
                id,
                bytes,
                needs_write,
            };
            nodes.push(write);
        }

        let retired_node_ids = self
            .retired
            .iter()
            .filter(|id| {
                let id = **id;
                !reused_global_roots.contains(&id)
                    && nodes.binary_search_by_key(&id, |write| write.id).is_err()
            })
            .copied()
            .collect();
        let plan = InvocationHistoryWritePlan {
            genesis: self.genesis,
            scope: self.scope,
            expected_root: self.expected_root,
            root: self.root,
            inserted_facts: self.inserted.values().copied().collect(),
            nodes,
            retired_node_ids,
        };
        plan.validate_structure()
            .map_err(|_| InvocationHistoryError::InvalidPlan)?;
        Ok(plan)
    }

    fn commit_insert(
        &mut self,
        fact: InvocationAcknowledgedFact,
        pending: BTreeMap<InvocationHistoryNodeId, InvocationHistoryNode>,
        retired: BTreeSet<InvocationHistoryNodeId>,
        root: InvocationHistoryNodeId,
    ) {
        self.overlay.extend(pending);
        self.retired.extend(retired);
        self.inserted.insert(fact.key().invocation, fact);
        self.root = Some(root);
    }

    fn require_insert_capacity(
        &self,
        additional_nodes: usize,
    ) -> Result<(), InvocationHistoryError<S::Error>> {
        if self.inserted.len() >= MAX_INVOCATION_HISTORY_INSERTIONS {
            return Err(InvocationHistoryError::PlanLimit);
        }
        if self.overlay.len().saturating_add(additional_nodes) > MAX_INVOCATION_HISTORY_PLAN_NODES {
            return Err(InvocationHistoryError::NodeLimit);
        }
        Ok(())
    }

    fn path_to_terminal(
        &self,
        root: InvocationHistoryNodeId,
        key: InvocationId,
    ) -> Result<
        (
            InvocationHistoryPath,
            InvocationHistoryNodeId,
            InvocationHistoryNode,
        ),
        InvocationHistoryError<S::Error>,
    > {
        let mut ancestors = Vec::new();
        let mut current = root;
        let mut parent_bit = None;
        let mut expected_summary = None;
        let mut visited = BTreeSet::new();
        loop {
            if !visited.insert(current) {
                return Err(InvocationHistoryError::Cycle);
            }
            let (node, origin) = self.load_node(current)?;
            self.validate_context(&node)?;
            validate_path_summary(&node, expected_summary)?;
            match node {
                InvocationHistoryNode::Leaf(_) => return Ok((ancestors, current, node)),
                InvocationHistoryNode::Branch {
                    bit,
                    prefix,
                    left,
                    right,
                    ..
                } => {
                    enforce_increasing_bit(parent_bit, bit)?;
                    if ancestors.len() >= MAX_INVOCATION_HISTORY_PATH {
                        return Err(InvocationHistoryError::PathLimit);
                    }
                    let bit_index = usize::from(bit);
                    if prefix_of(&key.0, bit_index) != prefix {
                        return Ok((ancestors, current, node));
                    }
                    let went_right = bit_at(&key.0, bit_index);
                    ancestors.push((current, node, went_right, origin));
                    let child = if went_right { right } else { left };
                    current = child.id;
                    expected_summary = Some(child.summary);
                    parent_bit = Some(bit);
                }
            }
        }
    }

    fn plan_branch(
        &self,
        bit: usize,
        inserted_key: InvocationId,
        existing: InvocationHistoryChild,
        inserted: InvocationHistoryChild,
        pending: &mut BTreeMap<InvocationHistoryNodeId, InvocationHistoryNode>,
    ) -> Result<InvocationHistoryChild, InvocationHistoryError<S::Error>> {
        if bit >= 256 {
            return Err(InvocationHistoryError::NonCanonicalTree);
        }
        let (left, right) = if bit_at(&inserted_key.0, bit) {
            (existing, inserted)
        } else {
            (inserted, existing)
        };
        self.plan_node(
            InvocationHistoryNode::Branch {
                genesis: self.genesis,
                scope: self.scope,
                bit: bit as u16,
                prefix: prefix_of(&inserted_key.0, bit),
                left,
                right,
            },
            pending,
        )
    }

    fn plan_node(
        &self,
        node: InvocationHistoryNode,
        pending: &mut BTreeMap<InvocationHistoryNodeId, InvocationHistoryNode>,
    ) -> Result<InvocationHistoryChild, InvocationHistoryError<S::Error>> {
        node.validate_inner()
            .map_err(|_| InvocationHistoryError::NonCanonicalTree)?;
        self.validate_context(&node)?;
        let id = node.id();
        if self
            .overlay
            .get(&id)
            .or_else(|| pending.get(&id))
            .is_some_and(|existing| existing != &node)
        {
            return Err(InvocationHistoryError::ObjectCollision(id));
        }
        pending.entry(id).or_insert(node);
        child_for(id, &node)
    }

    fn load_node(
        &self,
        id: InvocationHistoryNodeId,
    ) -> Result<(InvocationHistoryNode, NodeOrigin), InvocationHistoryError<S::Error>> {
        if let Some(node) = self.overlay.get(&id) {
            return Ok((*node, NodeOrigin::Overlay));
        }
        let bytes = self
            .store
            .load_history_node(id)
            .map_err(InvocationHistoryError::Storage)?
            .ok_or(InvocationHistoryError::MissingNode(id))?;
        if bytes.len() > MAX_INVOCATION_HISTORY_NODE_BYTES {
            return Err(InvocationHistoryError::CorruptNode(id));
        }
        let node = InvocationHistoryNode::decode(&bytes)
            .map_err(|_| InvocationHistoryError::CorruptNode(id))?;
        if node.id() != id || node.encode() != bytes {
            return Err(InvocationHistoryError::CorruptNode(id));
        }
        Ok((node, NodeOrigin::Global))
    }

    fn validate_context(
        &self,
        node: &InvocationHistoryNode,
    ) -> Result<(), InvocationHistoryError<S::Error>> {
        if node.genesis() != self.genesis {
            return Err(InvocationHistoryError::GenesisMismatch);
        }
        if node.scope() != self.scope {
            return Err(InvocationHistoryError::ScopeMismatch);
        }
        Ok(())
    }
}

fn child_for<E>(
    id: InvocationHistoryNodeId,
    node: &InvocationHistoryNode,
) -> Result<InvocationHistoryChild, InvocationHistoryError<E>> {
    if id == InvocationHistoryNodeId::ZERO {
        return Err(InvocationHistoryError::NonCanonicalTree);
    }
    let child = InvocationHistoryChild {
        id,
        summary: node.summary(),
    };
    child
        .validate()
        .map_err(|_| InvocationHistoryError::NonCanonicalTree)?;
    Ok(child)
}

fn validate_path_summary<E>(
    node: &InvocationHistoryNode,
    expected: Option<InvocationHistorySummary>,
) -> Result<(), InvocationHistoryError<E>> {
    if expected.is_some_and(|summary| summary != node.summary()) {
        return Err(InvocationHistoryError::SummaryMismatch);
    }
    Ok(())
}

fn enforce_increasing_bit<E>(
    parent: Option<u16>,
    child: u16,
) -> Result<(), InvocationHistoryError<E>> {
    if parent.is_some_and(|parent| child <= parent) {
        return Err(InvocationHistoryError::NonCanonicalTree);
    }
    Ok(())
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

fn encode_summary(encoder: &mut Encoder<'_>, summary: InvocationHistorySummary) {
    encoder.bool(summary.transition_proof);
    encoder.fixed(&summary.min.0);
    encoder.fixed(&summary.max.0);
}

fn decode_summary(decoder: &mut Decoder<'_>) -> Result<InvocationHistorySummary, DecodeError> {
    let summary = InvocationHistorySummary {
        transition_proof: decoder.bool()?,
        min: InvocationId(decoder.fixed()?),
        max: InvocationId(decoder.fixed()?),
    };
    summary.validate()?;
    Ok(summary)
}

fn encode_child(encoder: &mut Encoder<'_>, child: InvocationHistoryChild) {
    encoder.fixed(&child.id.0);
    encode_summary(encoder, child.summary);
}

fn decode_child(decoder: &mut Decoder<'_>) -> Result<InvocationHistoryChild, DecodeError> {
    let child = InvocationHistoryChild {
        id: InvocationHistoryNodeId(decoder.fixed()?),
        summary: decode_summary(decoder)?,
    };
    child.validate()?;
    Ok(child)
}

fn summary_matches_partition(
    summary: InvocationHistorySummary,
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
    position[bit / 8] & (0x80 >> (bit % 8)) != 0
}

fn first_differing_bit(left: &[u8; 32], right: &[u8; 32]) -> Option<usize> {
    for (byte_index, (left, right)) in left.iter().zip(right).enumerate() {
        let difference = left ^ right;
        if difference != 0 {
            return Some(byte_index * 8 + difference.leading_zeros() as usize);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::super::journal::{
        InvocationDisposition, InvocationOutcomeId, InvocationOutcomeRef, InvocationOwner,
        InvocationOwnershipKey, InvocationResultState, MergeEventId, PersistedLane, ReplayInputId,
    };
    use super::*;

    #[derive(Default)]
    struct MemoryHistoryStore {
        nodes: BTreeMap<InvocationHistoryNodeId, Vec<u8>>,
    }

    impl InvocationHistoryStore for MemoryHistoryStore {
        type Error = ();

        fn load_history_node(
            &self,
            id: InvocationHistoryNodeId,
        ) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.nodes.get(&id).cloned())
        }
    }

    fn genesis() -> AgentJournalGenesisId {
        AgentJournalGenesisId([0x11; 32])
    }

    fn key(scope: InvocationOwnershipScope, number: u16) -> InvocationOwnershipKey {
        let mut invocation = [0u8; 32];
        invocation[30..].copy_from_slice(&number.to_be_bytes());
        InvocationOwnershipKey {
            scope,
            invocation: InvocationId(invocation),
        }
    }

    fn fact(
        genesis: AgentJournalGenesisId,
        scope: InvocationOwnershipScope,
        number: u16,
        identity: u8,
    ) -> InvocationAcknowledgedFact {
        let key = key(scope, number);
        let (lane, node, result_state) = match scope {
            InvocationOwnershipScope::Ordered => (
                PersistedLane::Linear,
                None,
                InvocationResultState::Retained {
                    disposition: InvocationDisposition::Applied,
                    outcome: InvocationOutcomeRef {
                        outcome: InvocationOutcomeId([identity.wrapping_add(1); 32]),
                        encoded_bytes: 64,
                    },
                },
            ),
            InvocationOwnershipScope::Merge => (
                PersistedLane::Merge,
                None,
                InvocationResultState::PendingMergeAcknowledgement {
                    acknowledgement_event: MergeEventId([identity.wrapping_add(2); 32]),
                    disposition: InvocationDisposition::Rejected,
                    outcome: InvocationOutcomeRef {
                        outcome: InvocationOutcomeId([identity.wrapping_add(3); 32]),
                        encoded_bytes: 65,
                    },
                },
            ),
            InvocationOwnershipScope::Local(node) => (
                PersistedLane::Local,
                Some(node),
                InvocationResultState::Retained {
                    disposition: InvocationDisposition::Forbidden,
                    outcome: InvocationOutcomeRef {
                        outcome: InvocationOutcomeId([identity.wrapping_add(4); 32]),
                        encoded_bytes: 66,
                    },
                },
            ),
        };
        let owner = InvocationOwner {
            scope,
            request_commitment: Hash([identity.wrapping_add(5); 32]),
            first_input: ReplayInputId([identity.wrapping_add(6); 32]),
            lane,
            node,
            result_state,
        };
        InvocationAcknowledgedFact::from_owner(genesis, key, owner).unwrap()
    }

    fn retirement_fact(genesis: AgentJournalGenesisId, number: u16) -> InvocationAcknowledgedFact {
        let mut invocation = [0x71; 32];
        invocation[30..].copy_from_slice(&number.to_be_bytes());
        let mut execution = [0x72; 32];
        execution[30..].copy_from_slice(&number.to_be_bytes());
        InvocationAcknowledgedFact::for_transition_proof_retirement(
            genesis,
            crate::agent_sdk::proof::TransitionProofKey {
                invocation: crate::agent_sdk::InvocationId(invocation),
                execution: crate::agent_sdk::Hash(execution),
            },
        )
        .unwrap()
    }

    fn commit(store: &mut MemoryHistoryStore, plan: &InvocationHistoryWritePlan) {
        for write in plan.node_writes() {
            match store.nodes.get(&write.id()) {
                Some(bytes) => assert_eq!(bytes, write.bytes()),
                None => {
                    store.nodes.insert(write.id(), write.bytes().to_vec());
                }
            }
        }
    }

    #[test]
    fn empty_insert_lookup_exact_retry_conflict_and_reopen() {
        let mut store = MemoryHistoryStore::default();
        let genesis = genesis();
        let scope = InvocationOwnershipScope::Ordered;
        let first = fact(genesis, scope, 1, 10);
        let mut history = InvocationHistory::open(&store, genesis, scope, None).unwrap();
        assert_eq!(history.lookup(first.key()).unwrap(), None);

        let inserted = history.insert(first).unwrap();
        assert!(inserted.inserted());
        assert_eq!(inserted.root(), history.root());
        assert_eq!(history.lookup(first.key()).unwrap(), Some(first));
        assert!(!history.insert(first).unwrap().inserted());
        assert_eq!(
            history.insert(fact(genesis, scope, 1, 11)),
            Err(InvocationHistoryError::Conflict)
        );

        let plan = history.write_plan().unwrap();
        assert_eq!(plan.expected_root(), None);
        assert_eq!(plan.root(), history.root());
        assert_eq!(plan.inserted_facts(), &[first]);
        assert!(plan.retired_node_ids().is_empty());
        assert_eq!(plan.node_writes().count(), plan.overlay_nodes().len());
        plan.validate(&store).unwrap();
        let decoded = InvocationHistoryWritePlan::decode(&plan.encode()).unwrap();
        assert_eq!(decoded, plan);
        decoded.validate(&store).unwrap();

        let root = plan.root();
        commit(&mut store, &plan);
        plan.validate(&store).unwrap();
        assert!(
            plan.overlay_nodes()
                .iter()
                .all(|write| write.validate_availability(&store).is_ok())
        );
        let reopened = InvocationHistory::open(&store, genesis, scope, root).unwrap();
        assert_eq!(reopened.lookup(first.key()).unwrap(), Some(first));
        assert_eq!(reopened.lookup(key(scope, 2)).unwrap(), None,);
    }

    #[test]
    fn complete_audit_rejects_a_cross_purpose_history_root() {
        let mut store = MemoryHistoryStore::default();
        let genesis = genesis();
        let scope = InvocationOwnershipScope::Ordered;

        let ordinary = fact(genesis, scope, 1, 10);
        let mut ordinary_history = InvocationHistory::open(&store, genesis, scope, None).unwrap();
        ordinary_history.insert(ordinary).unwrap();
        let ordinary_plan = ordinary_history.write_plan().unwrap();
        commit(&mut store, &ordinary_plan);
        let ordinary_history =
            InvocationHistory::open(&store, genesis, scope, ordinary_plan.root()).unwrap();
        assert!(matches!(
            ordinary_history.validate_complete(4, |fact| {
                fact.transition_proof_retirement_key().is_some()
            }),
            Err(InvocationHistoryError::InvalidFact)
        ));
        ordinary_history.require_history_purpose(false).unwrap();
        assert_eq!(
            ordinary_history.require_history_purpose(true),
            Err(InvocationHistoryError::InvalidFact)
        );

        let mut retirement_history = InvocationHistory::open(&store, genesis, scope, None).unwrap();
        for byte in [0x31, 0x32] {
            retirement_history
                .insert(
                    InvocationAcknowledgedFact::for_transition_proof_retirement(
                        genesis,
                        crate::agent_sdk::proof::TransitionProofKey {
                            invocation: crate::agent_sdk::InvocationId([byte; 32]),
                            execution: crate::agent_sdk::Hash([byte.wrapping_add(1); 32]),
                        },
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        let retirement_plan = retirement_history.write_plan().unwrap();
        commit(&mut store, &retirement_plan);
        let retirement_history =
            InvocationHistory::open(&store, genesis, scope, retirement_plan.root()).unwrap();
        retirement_history.require_history_purpose(true).unwrap();
        assert_eq!(
            retirement_history.require_history_purpose(false),
            Err(InvocationHistoryError::InvalidFact)
        );
        assert_eq!(
            retirement_history
                .validate_complete(4, |fact| {
                    fact.transition_proof_retirement_key().is_some()
                })
                .unwrap(),
            3
        );
        assert!(matches!(
            retirement_history.validate_complete(2, |_| true),
            Err(InvocationHistoryError::NodeLimit)
        ));

        let logical = crate::agent_sdk::InvocationId([0x41; 32]);
        let first = InvocationAcknowledgedFact::for_transition_proof_retirement(
            genesis,
            crate::agent_sdk::proof::TransitionProofKey {
                invocation: logical,
                execution: crate::agent_sdk::Hash([0x42; 32]),
            },
        )
        .unwrap();
        let conflicting = InvocationAcknowledgedFact::for_transition_proof_retirement(
            genesis,
            crate::agent_sdk::proof::TransitionProofKey {
                invocation: logical,
                execution: crate::agent_sdk::Hash([0x43; 32]),
            },
        )
        .unwrap();
        let mut terminal = InvocationHistory::open(&store, genesis, scope, None).unwrap();
        assert!(terminal.insert(first).unwrap().inserted());
        assert_eq!(
            terminal.insert(conflicting),
            Err(InvocationHistoryError::Conflict)
        );
    }

    #[test]
    fn cumulative_overlay_reopens_and_insertion_order_is_canonical() {
        let store = MemoryHistoryStore::default();
        let genesis = genesis();
        let scope = InvocationOwnershipScope::Ordered;
        let first = fact(genesis, scope, 1, 20);
        let second = fact(genesis, scope, 0x8000, 21);
        let third = fact(genesis, scope, 0x4000, 22);

        let mut history = InvocationHistory::open(&store, genesis, scope, None).unwrap();
        history.insert(second).unwrap();
        history.insert(first).unwrap();
        let first_plan = history.write_plan().unwrap();
        assert_eq!(first_plan.inserted_facts(), &[first, second]);
        first_plan.validate(&store).unwrap();

        let mut continued = InvocationHistory::open_with_plan(&store, &first_plan).unwrap();
        assert_eq!(continued.lookup(first.key()).unwrap(), Some(first));
        assert_eq!(continued.lookup(second.key()).unwrap(), Some(second));
        continued.insert(third).unwrap();
        let final_plan = continued.write_plan().unwrap();
        assert_eq!(final_plan.expected_root(), None);
        assert_eq!(final_plan.inserted_facts(), &[first, third, second]);
        final_plan.validate(&store).unwrap();

        let mut sorted = InvocationHistory::open(&store, genesis, scope, None).unwrap();
        sorted.insert(first).unwrap();
        sorted.insert(third).unwrap();
        sorted.insert(second).unwrap();
        assert_eq!(sorted.root(), continued.root());
        assert_eq!(sorted.write_plan().unwrap(), final_plan);
    }

    #[test]
    fn globally_deduplicated_candidate_remains_overlay_origin() {
        let mut store = MemoryHistoryStore::default();
        let genesis = genesis();
        let scope = InvocationOwnershipScope::Ordered;
        let first = fact(genesis, scope, 1, 25);
        let second = fact(genesis, scope, 2, 26);

        let mut original = InvocationHistory::open(&store, genesis, scope, None).unwrap();
        original.insert(first).unwrap();
        let original_plan = original.write_plan().unwrap();
        commit(&mut store, &original_plan);

        // The same content exists globally as an orphan relative to this
        // empty expected root. It requires no put but must remain overlay
        // provenance when the candidate continues.
        let mut duplicate = InvocationHistory::open(&store, genesis, scope, None).unwrap();
        duplicate.insert(first).unwrap();
        let duplicate_plan = duplicate.write_plan().unwrap();
        assert_eq!(duplicate_plan.node_writes().count(), 0);
        assert_eq!(duplicate_plan.overlay_nodes().len(), 1);
        duplicate_plan.validate(&store).unwrap();

        let mut continued = InvocationHistory::open_with_plan(&store, &duplicate_plan).unwrap();
        continued.insert(second).unwrap();
        let continued_plan = continued.write_plan().unwrap();
        assert!(continued_plan.retired_node_ids().is_empty());
        continued_plan.validate(&store).unwrap();
    }

    #[test]
    fn retired_nodes_are_exact_global_ancestors_and_plan_tampering_fails() {
        let mut store = MemoryHistoryStore::default();
        let genesis = genesis();
        let scope = InvocationOwnershipScope::Ordered;
        let first = fact(genesis, scope, 1, 30);
        let second = fact(genesis, scope, 0x8000, 31);
        let third = fact(genesis, scope, 0x4000, 32);

        let mut initial = InvocationHistory::open(&store, genesis, scope, None).unwrap();
        initial.insert(first).unwrap();
        initial.insert(second).unwrap();
        let initial_plan = initial.write_plan().unwrap();
        let initial_root = initial_plan.root();
        commit(&mut store, &initial_plan);

        let mut successor = InvocationHistory::open(&store, genesis, scope, initial_root).unwrap();
        successor.insert(third).unwrap();
        let plan = successor.write_plan().unwrap();
        assert_eq!(plan.expected_root(), initial_root);
        assert!(!plan.retired_node_ids().is_empty());
        assert!(
            plan.retired_node_ids()
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
        assert!(plan.retired_node_ids().iter().all(|retired| {
            plan.overlay_nodes()
                .binary_search_by_key(retired, |write| write.id())
                .is_err()
        }));
        let first_leaf = InvocationHistoryNode::Leaf(first).id();
        let second_leaf = InvocationHistoryNode::Leaf(second).id();
        assert!(!plan.retired_node_ids().contains(&first_leaf));
        assert!(!plan.retired_node_ids().contains(&second_leaf));
        plan.validate(&store).unwrap();

        let mut omitted_retirement = plan.clone();
        omitted_retirement.retired_node_ids.clear();
        assert_eq!(
            omitted_retirement.validate(&store),
            Err(InvocationHistoryError::InvalidPlan)
        );
        let mut substituted_retirement = plan.clone();
        substituted_retirement.retired_node_ids[0] = first_leaf;
        substituted_retirement.retired_node_ids.sort();
        substituted_retirement.retired_node_ids.dedup();
        assert_eq!(
            substituted_retirement.validate(&store),
            Err(InvocationHistoryError::InvalidPlan)
        );

        commit(&mut store, &plan);
        plan.validate(&store).unwrap();
        let reopened = InvocationHistory::open(&store, genesis, scope, plan.root()).unwrap();
        for expected in [first, second, third] {
            assert_eq!(reopened.lookup(expected.key()).unwrap(), Some(expected));
        }
    }

    #[test]
    fn roots_reject_missing_corrupt_and_cross_context_nodes() {
        let mut store = MemoryHistoryStore::default();
        let genesis = genesis();
        let scope = InvocationOwnershipScope::Ordered;
        let first = fact(genesis, scope, 1, 40);
        let mut history = InvocationHistory::open(&store, genesis, scope, None).unwrap();
        history.insert(first).unwrap();
        let plan = history.write_plan().unwrap();
        let root = plan.root().unwrap();

        assert_eq!(
            InvocationHistory::open(&store, genesis, scope, Some(root)).map(|_| ()),
            Err(InvocationHistoryError::MissingNode(root))
        );
        store.nodes.insert(root, vec![0xff]);
        assert_eq!(
            InvocationHistory::open(&store, genesis, scope, Some(root)).map(|_| ()),
            Err(InvocationHistoryError::CorruptNode(root))
        );
        store.nodes.clear();
        commit(&mut store, &plan);
        assert_eq!(
            InvocationHistory::open(&store, AgentJournalGenesisId([0x12; 32]), scope, Some(root),)
                .map(|_| ()),
            Err(InvocationHistoryError::GenesisMismatch)
        );
        assert_eq!(
            InvocationHistory::open(&store, genesis, InvocationOwnershipScope::Merge, Some(root),)
                .map(|_| ()),
            Err(InvocationHistoryError::ScopeMismatch)
        );

        let mut predecessor_wire = plan.overlay_nodes()[0].bytes().to_vec();
        predecessor_wire[..4].copy_from_slice(b"AIHN");
        assert!(InvocationHistoryNode::decode(&predecessor_wire).is_err());
    }

    #[test]
    fn cumulative_retirement_history_exceeds_one_publication_limit() {
        let mut store = MemoryHistoryStore::default();
        let genesis = genesis();
        let scope = InvocationOwnershipScope::Ordered;

        let mut first = InvocationHistory::open(&store, genesis, scope, None).unwrap();
        for number in 1..=MAX_INVOCATION_HISTORY_INSERTIONS as u16 {
            first.insert(retirement_fact(genesis, number)).unwrap();
        }
        let first_plan = first.write_plan().unwrap();
        assert_eq!(first_plan.insertions(), MAX_INVOCATION_HISTORY_INSERTIONS);
        commit(&mut store, &first_plan);

        let mut second =
            InvocationHistory::open(&store, genesis, scope, first_plan.root()).unwrap();
        second.require_history_purpose(true).unwrap();
        let beyond_one_publication = MAX_INVOCATION_HISTORY_INSERTIONS as u16 + 1;
        let final_fact = retirement_fact(genesis, beyond_one_publication);
        second.insert(final_fact).unwrap();
        let second_plan = second.write_plan().unwrap();
        assert_eq!(second_plan.insertions(), 1);
        commit(&mut store, &second_plan);

        let reopened = InvocationHistory::open(&store, genesis, scope, second_plan.root()).unwrap();
        reopened.require_history_purpose(true).unwrap();
        assert_eq!(
            reopened.lookup(retirement_fact(genesis, 1).key()).unwrap(),
            Some(retirement_fact(genesis, 1))
        );
        assert_eq!(reopened.lookup(final_fact.key()).unwrap(), Some(final_fact));
    }

    #[test]
    fn plans_reject_false_reuse_collisions_and_oversized_counts() {
        let mut store = MemoryHistoryStore::default();
        let genesis = genesis();
        let scope = InvocationOwnershipScope::Ordered;
        let first = fact(genesis, scope, 1, 45);
        let mut history = InvocationHistory::open(&store, genesis, scope, None).unwrap();
        history.insert(first).unwrap();
        let plan = history.write_plan().unwrap();

        let mut false_reuse = plan.clone();
        false_reuse.nodes[0].needs_write = false;
        assert_eq!(
            false_reuse.validate(&store),
            Err(InvocationHistoryError::InvalidPlan)
        );

        store.nodes.insert(plan.nodes[0].id, vec![0xee]);
        assert_eq!(
            plan.validate(&store),
            Err(InvocationHistoryError::ObjectCollision(plan.nodes[0].id))
        );

        let mut excessive = plan;
        excessive.inserted_facts = vec![first; MAX_INVOCATION_HISTORY_INSERTIONS.saturating_add(1)];
        assert_eq!(
            InvocationHistoryWritePlan::decode(&excessive.encode()),
            Err(DecodeError::LimitExceeded)
        );
    }

    #[test]
    fn scopes_and_nodes_are_domain_separated_and_canonical() {
        let genesis = genesis();
        let ordered = fact(genesis, InvocationOwnershipScope::Ordered, 1, 50);
        let merge = fact(genesis, InvocationOwnershipScope::Merge, 1, 50);
        let local = fact(
            genesis,
            InvocationOwnershipScope::Local(NodeId([0x51; 32])),
            1,
            50,
        );
        for fact in [ordered, merge, local] {
            let node = InvocationHistoryNode::Leaf(fact);
            node.validate().unwrap();
            assert_eq!(InvocationHistoryNode::decode(&node.encode()).unwrap(), node);
            assert!(node.encode().len() <= MAX_INVOCATION_HISTORY_NODE_BYTES);
        }
        assert_ne!(
            InvocationHistoryNode::Leaf(ordered).id(),
            InvocationHistoryNode::Leaf(merge).id()
        );
        assert_ne!(
            InvocationHistoryNode::Leaf(ordered).id(),
            InvocationHistoryNode::Leaf(local).id()
        );
    }

    #[test]
    fn one_plan_is_bounded_to_the_publication_archive_limit() {
        let store = MemoryHistoryStore::default();
        let genesis = genesis();
        let scope = InvocationOwnershipScope::Ordered;
        let mut history = InvocationHistory::open(&store, genesis, scope, None).unwrap();
        for number in 1..=MAX_INVOCATION_HISTORY_INSERTIONS as u16 {
            history.insert(fact(genesis, scope, number, 0x60)).unwrap();
        }
        let plan = history.write_plan().unwrap();
        assert_eq!(
            plan.inserted_facts().len(),
            MAX_INVOCATION_HISTORY_INSERTIONS
        );
        assert!(plan.overlay_nodes().len() <= MAX_INVOCATION_HISTORY_PLAN_NODES);
        assert!(plan.encode().len() <= MAX_INVOCATION_HISTORY_WRITE_PLAN_BYTES);
        assert_eq!(
            history.insert(fact(
                genesis,
                scope,
                MAX_INVOCATION_HISTORY_INSERTIONS as u16 + 1,
                0x61,
            )),
            Err(InvocationHistoryError::PlanLimit)
        );
    }
}
