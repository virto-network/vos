//! Journal-owned public transition-proof records and authenticated lookup root.
//!
//! Proof production may use private witnesses, but durable replay authority is
//! restricted to the public tuple below. A journal head names one bounded,
//! canonical index; each index entry names an exact replay input and position,
//! the canonical work and transition bytes, APR4, APM1, and immutable package
//! dependencies. Physical storage must persist and read back that entire
//! closure before publishing a head which names the new index.

use alloc::vec::Vec;

use crate::agent_sdk::proof::{
    MAX_TRANSITION_PROOF_MATERIAL_MANIFEST_BYTES, MAX_TRANSITION_PROOF_RECORD_BYTES,
    TransitionProofKey, TransitionProofMaterialManifest, TransitionProofRecord,
};
use crate::agent_sdk::wire::CanonicalWire as AgentCanonicalWire;
use crate::agent_sdk::{InvocationId, InvocationResultStorage, StateLane};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{BlobRef, Hash, NodeId};

use super::journal::{
    AgentJournalGenesisId, ArtifactClosureId, CanonicalJournalRecord, InvocationHistoryNodeId,
    JournalHeadsId, JournalStorageClass, LocalEntryId, MAX_REPLAY_SUFFIX_ENTRIES, MergeEventId,
    MergeFrontierId, MergeSealId, OrderedBase, OrderedEntryId, ReplayInputId,
    TransitionProofEntryId, TransitionProofIndexId,
};

/// A checkpoint can carry one live proof for every retained invocation while
/// the following suffix adds new or recanonicalized proof records. The hard
/// ceiling keeps both admission and closure traversal independent of storage
/// size; callers must seal/checkpoint before a further batch would exceed it.
pub(crate) const MAX_TRANSITION_PROOF_INDEX_ENTRIES: usize = MAX_REPLAY_SUFFIX_ENTRIES * 2;
/// At most one live proof edge exists for an invocation. The replay suffix is
/// already the protocol-wide bound on concurrently addressable proof work.
pub(crate) const MAX_TRANSITION_PROOF_LIVE_ENTRIES: usize = MAX_REPLAY_SUFFIX_ENTRIES;
/// Complete logical proof material reachable through one authenticated proof
/// index. This is deliberately the same ceiling as one proof: retaining more
/// records must divide the bounded recovery budget rather than multiplying it.
pub(crate) const MAX_TRANSITION_PROOF_INDEX_MATERIAL_BYTES: u64 =
    crate::agent_sdk::MAX_TRANSITION_PROOF_MATERIAL_BYTES;
/// Complete canonical proof tuple, excluding separately content-addressed
/// work, transition, package, manifest, and proof-material bytes.
pub(crate) const MAX_TRANSITION_PROOF_ENTRY_BYTES: usize =
    MAX_TRANSITION_PROOF_RECORD_BYTES + MAX_TRANSITION_PROOF_MATERIAL_MANIFEST_BYTES + 1024;
/// Fixed-width records plus live pointers remain bounded without coupling the
/// index to the (much larger) proof-material closure.
pub(crate) const MAX_TRANSITION_PROOF_INDEX_BYTES: usize = 384 * 1024;
const TRANSITION_PROOF_INDEX_ENTRY_BYTES: usize = 32 + 32 + 32 + 8;
const TRANSITION_PROOF_LIVE_ENTRY_BYTES: usize = 32 + 32;

/// Exact journal position of one proof-bearing invocation transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransitionProofAnchor {
    Ordered {
        entry: OrderedEntryId,
        index: u64,
        merge_frontier: MergeFrontierId,
        merge_seal: Option<MergeSealId>,
    },
    Merge {
        event: MergeEventId,
        causal_height: u64,
        ordered_base: OrderedBase,
    },
    Local {
        entry: LocalEntryId,
        node: NodeId,
        revision: u64,
        ordered_base: OrderedBase,
        merge_frontier: MergeFrontierId,
    },
}

impl TransitionProofAnchor {
    fn validate(self) -> Result<(), DecodeError> {
        match self {
            Self::Ordered {
                entry,
                index,
                merge_frontier,
                merge_seal,
            } => {
                if entry == OrderedEntryId::ZERO
                    || index == 0
                    || merge_frontier == MergeFrontierId::ZERO
                    || merge_seal == Some(MergeSealId::ZERO)
                {
                    return Err(DecodeError::NonCanonical);
                }
            }
            Self::Merge {
                event,
                causal_height,
                ordered_base,
            } => {
                ordered_base.validate()?;
                if event == MergeEventId::ZERO || causal_height == 0 {
                    return Err(DecodeError::NonCanonical);
                }
            }
            Self::Local {
                entry,
                node,
                revision,
                ordered_base,
                merge_frontier,
            } => {
                ordered_base.validate()?;
                if entry == LocalEntryId::ZERO
                    || node == NodeId::ZERO
                    || revision == 0
                    || merge_frontier == MergeFrontierId::ZERO
                {
                    return Err(DecodeError::NonCanonical);
                }
            }
        }
        Ok(())
    }

    fn encode_to(self, encoder: &mut Encoder<'_>) {
        match self {
            Self::Ordered {
                entry,
                index,
                merge_frontier,
                merge_seal,
            } => {
                encoder.u8(0);
                encoder.fixed(entry.as_bytes());
                encoder.u64(index);
                encoder.fixed(merge_frontier.as_bytes());
                encoder.option(&merge_seal, |encoder, seal| encoder.fixed(seal.as_bytes()));
            }
            Self::Merge {
                event,
                causal_height,
                ordered_base,
            } => {
                encoder.u8(1);
                encoder.fixed(event.as_bytes());
                encoder.u64(causal_height);
                encode_ordered_base(encoder, ordered_base);
            }
            Self::Local {
                entry,
                node,
                revision,
                ordered_base,
                merge_frontier,
            } => {
                encoder.u8(2);
                encoder.fixed(entry.as_bytes());
                encoder.fixed(node.as_bytes());
                encoder.u64(revision);
                encode_ordered_base(encoder, ordered_base);
                encoder.fixed(merge_frontier.as_bytes());
            }
        }
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let anchor = match decoder.u8()? {
            0 => Self::Ordered {
                entry: OrderedEntryId(decoder.fixed()?),
                index: decoder.u64()?,
                merge_frontier: MergeFrontierId(decoder.fixed()?),
                merge_seal: decoder.option(|decoder| Ok(MergeSealId(decoder.fixed()?)))?,
            },
            1 => Self::Merge {
                event: MergeEventId(decoder.fixed()?),
                causal_height: decoder.u64()?,
                ordered_base: decode_ordered_base(decoder)?,
            },
            2 => Self::Local {
                entry: LocalEntryId(decoder.fixed()?),
                node: NodeId(decoder.fixed()?),
                revision: decoder.u64()?,
                ordered_base: decode_ordered_base(decoder)?,
                merge_frontier: MergeFrontierId(decoder.fixed()?),
            },
            _ => return Err(DecodeError::InvalidTag),
        };
        anchor.validate()?;
        Ok(anchor)
    }

    fn matches_storage(self, storage: InvocationResultStorage) -> bool {
        matches!(
            (self, storage),
            (
                Self::Ordered { .. },
                InvocationResultStorage::Control | InvocationResultStorage::Lane(StateLane::Linear)
            ) | (
                Self::Merge { .. },
                InvocationResultStorage::Lane(StateLane::Merge)
            ) | (
                Self::Local { .. },
                InvocationResultStorage::Lane(StateLane::Local)
            )
        )
    }
}

/// Complete public tuple required to verify and replay one attested runtime
/// transition without retaining producer-private witness material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct JournalTransitionProof {
    genesis: AgentJournalGenesisId,
    /// Head CAS envelope replaced by the proof-bearing publication. The
    /// exact pre-transition roots are replay-derived from this envelope plus
    /// the authenticated anchor (including pinned Shared/Merge ancestry).
    predecessor: JournalHeadsId,
    input: ReplayInputId,
    anchor: TransitionProofAnchor,
    canonical_work: BlobRef,
    canonical_transition: BlobRef,
    /// Checkpoint/catalog closure from which exact runtime and actor packages
    /// and physical programs must be resolved during verification.
    artifacts: ArtifactClosureId,
    /// Exact current actor package; runtime package is already part of APR4.
    actor_package: BlobRef,
    proof_record: TransitionProofRecord,
    /// Retained canonical bytes make the infallible journal encoder exact;
    /// construction and decoding prove equality with `proof_record`.
    proof_record_wire: Vec<u8>,
    proof_manifest: TransitionProofMaterialManifest,
    proof_manifest_wire: Vec<u8>,
    /// Deterministic verified-publication commitment returned by the proof
    /// host. Publication adapters additionally rederive this before CAS.
    publication: Hash,
}

impl JournalTransitionProof {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        genesis: AgentJournalGenesisId,
        predecessor: JournalHeadsId,
        input: ReplayInputId,
        anchor: TransitionProofAnchor,
        canonical_work: BlobRef,
        canonical_transition: BlobRef,
        artifacts: ArtifactClosureId,
        actor_package: BlobRef,
        proof_record: TransitionProofRecord,
        proof_manifest: TransitionProofMaterialManifest,
        publication: Hash,
    ) -> Result<Self, DecodeError> {
        let proof_record_wire = encode_agent_wire(&proof_record)?;
        let proof_manifest_wire = encode_agent_wire(&proof_manifest)?;
        let value = Self {
            genesis,
            predecessor,
            input,
            anchor,
            canonical_work,
            canonical_transition,
            artifacts,
            actor_package,
            proof_record,
            proof_record_wire,
            proof_manifest,
            proof_manifest_wire,
            publication,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) const fn genesis(&self) -> AgentJournalGenesisId {
        self.genesis
    }

    pub(crate) const fn predecessor(&self) -> JournalHeadsId {
        self.predecessor
    }

    pub(crate) const fn input(&self) -> ReplayInputId {
        self.input
    }

    pub(crate) const fn anchor(&self) -> TransitionProofAnchor {
        self.anchor
    }

    pub(crate) const fn canonical_work(&self) -> &BlobRef {
        &self.canonical_work
    }

    pub(crate) const fn canonical_transition(&self) -> &BlobRef {
        &self.canonical_transition
    }

    pub(crate) const fn artifacts(&self) -> ArtifactClosureId {
        self.artifacts
    }

    pub(crate) const fn actor_package(&self) -> &BlobRef {
        &self.actor_package
    }

    pub(crate) const fn proof_record(&self) -> &TransitionProofRecord {
        &self.proof_record
    }

    pub(crate) fn proof_record_wire(&self) -> &[u8] {
        &self.proof_record_wire
    }

    pub(crate) const fn proof_manifest(&self) -> &TransitionProofMaterialManifest {
        &self.proof_manifest
    }

    pub(crate) fn proof_manifest_wire(&self) -> &[u8] {
        &self.proof_manifest_wire
    }

    pub(crate) const fn publication(&self) -> Hash {
        self.publication
    }

    pub(crate) fn key(&self) -> TransitionProofKey {
        self.proof_record.statement.key()
    }

    pub(crate) fn proof_material_bytes(&self) -> u64 {
        self.proof_manifest.material.len
    }

    fn validate_inner(&self) -> Result<(), DecodeError> {
        self.anchor.validate()?;
        if self.genesis == AgentJournalGenesisId::ZERO
            || self.predecessor == JournalHeadsId::ZERO
            || self.input == ReplayInputId::ZERO
            || !valid_blob_ref(
                &self.canonical_work,
                crate::agent_sdk::wire::MAX_RUNTIME_WORK_WIRE_BYTES as u64,
            )
            || !valid_blob_ref(
                &self.canonical_transition,
                crate::agent_sdk::wire::MAX_RUNTIME_TRANSITION_WIRE_BYTES as u64,
            )
            || self.artifacts == ArtifactClosureId::ZERO
            || !valid_blob_ref(&self.actor_package, super::MAX_CATALOG_ARTIFACT_BYTES)
            || !self.proof_record.validate_shape()
            || !self.proof_manifest.validate()
            || encode_agent_wire(&self.proof_record)? != self.proof_record_wire
            || encode_agent_wire(&self.proof_manifest)? != self.proof_manifest_wire
            || self.publication.as_bytes()
                != self
                    .proof_record
                    .verified_publication_commitment()
                    .map_err(|_| DecodeError::NonCanonical)?
                    .as_bytes()
            || !self
                .anchor
                .matches_storage(self.proof_record.statement.subject.mode.result_storage())
        {
            return Err(DecodeError::NonCanonical);
        }
        if !self.proof_record.proof.matches(&self.proof_manifest_wire) {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

impl ServiceWire for JournalTransitionProof {
    const MAGIC: [u8; 4] = *b"APT2";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(self.genesis.as_bytes());
        encoder.fixed(self.predecessor.as_bytes());
        encoder.fixed(self.input.as_bytes());
        self.anchor.encode_to(&mut encoder);
        encode_blob(&mut encoder, &self.canonical_work);
        encode_blob(&mut encoder, &self.canonical_transition);
        encoder.fixed(self.artifacts.as_bytes());
        encode_blob(&mut encoder, &self.actor_package);
        encoder.bytes(&self.proof_record_wire);
        encoder.bytes(&self.proof_manifest_wire);
        encoder.fixed(self.publication.as_bytes());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_TRANSITION_PROOF_ENTRY_BYTES)?;
        let genesis = AgentJournalGenesisId(decoder.fixed()?);
        let predecessor = JournalHeadsId(decoder.fixed()?);
        let input = ReplayInputId(decoder.fixed()?);
        let anchor = TransitionProofAnchor::decode_from(decoder)?;
        let canonical_work = decode_blob(decoder)?;
        let canonical_transition = decode_blob(decoder)?;
        let artifacts = ArtifactClosureId(decoder.fixed()?);
        let actor_package = decode_blob(decoder)?;
        let (proof_record, proof_record_wire) =
            decode_agent_wire(decoder.bytes_ref()?, MAX_TRANSITION_PROOF_RECORD_BYTES)?;
        let (proof_manifest, proof_manifest_wire) = decode_agent_wire(
            decoder.bytes_ref()?,
            MAX_TRANSITION_PROOF_MATERIAL_MANIFEST_BYTES,
        )?;
        let proof = Self {
            genesis,
            predecessor,
            input,
            anchor,
            canonical_work,
            canonical_transition,
            artifacts,
            actor_package,
            proof_record,
            proof_record_wire,
            proof_manifest,
            proof_manifest_wire,
            publication: Hash(decoder.fixed()?),
        };
        proof.validate_inner()?;
        Ok(proof)
    }
}

impl super::journal::sealed::Sealed for JournalTransitionProof {}

impl CanonicalJournalRecord for JournalTransitionProof {
    type Id = TransitionProofEntryId;

    const STORAGE_CLASS: JournalStorageClass = JournalStorageClass::TransitionProof;

    fn validate(&self) -> Result<(), DecodeError> {
        self.validate_inner()?;
        validate_encoded_bound(self, MAX_TRANSITION_PROOF_ENTRY_BYTES)
    }

    fn id(&self) -> Self::Id {
        TransitionProofEntryId(content_id(b"vos/agent/journal/transition-proof/v2", self))
    }
}

/// One exact key-to-record edge retained for replay until checkpoint
/// compaction. Liveness is represented separately so acknowledgement never
/// makes a proof-bearing suffix transition unreplayable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TransitionProofIndexEntry {
    pub(crate) key: TransitionProofKey,
    pub(crate) record: TransitionProofEntryId,
    /// Authenticated aggregate material length used for bounded admission
    /// before record/manifest/chunk traversal.
    pub(crate) proof_material_bytes: u64,
}

impl TransitionProofIndexEntry {
    pub(crate) fn for_record(
        record: &JournalTransitionProof,
    ) -> Result<Self, TransitionProofIndexError> {
        record
            .validate()
            .map_err(|_| TransitionProofIndexError::Invalid)?;
        let entry = Self {
            key: record.key(),
            record: record.id(),
            proof_material_bytes: record.proof_material_bytes(),
        };
        entry
            .validate()
            .map_err(|_| TransitionProofIndexError::Invalid)?;
        Ok(entry)
    }

    fn validate(self) -> Result<(), DecodeError> {
        if !self.key.validate()
            || self.record == TransitionProofEntryId::ZERO
            || self.proof_material_bytes == 0
            || self.proof_material_bytes > crate::agent_sdk::MAX_TRANSITION_PROOF_MATERIAL_BYTES
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

/// Bounded canonical proof map authenticated by journal heads.
///
/// `records` is append-only between checkpoints. `live` contains at most one
/// exact key per invocation and may be replaced by Resume/recanonicalization
/// or retired by an exact acknowledgement. A checkpoint is the sole boundary
/// which may discard records not referenced by `live`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransitionProofIndexManifest {
    pub(crate) genesis: AgentJournalGenesisId,
    records: Vec<TransitionProofIndexEntry>,
    live: Vec<TransitionProofKey>,
    /// Cumulative exact keys which previously occupied a live edge. The
    /// immutable Patricia nodes live in the same private history namespace as
    /// acknowledged invocations, but this root is disjoint and can only be
    /// advanced with the head CAS that replaces/retires the edge.
    retired_root: Option<InvocationHistoryNodeId>,
}

impl TransitionProofIndexManifest {
    pub(crate) const fn empty(genesis: AgentJournalGenesisId) -> Self {
        Self {
            genesis,
            records: Vec::new(),
            live: Vec::new(),
            retired_root: None,
        }
    }

    pub(crate) fn entries(&self) -> &[TransitionProofIndexEntry] {
        &self.records
    }

    pub(crate) fn live_entries(&self) -> &[TransitionProofKey] {
        &self.live
    }

    pub(crate) const fn retired_root(&self) -> Option<InvocationHistoryNodeId> {
        self.retired_root
    }

    pub(crate) fn with_retired_root(
        &self,
        expected: Option<InvocationHistoryNodeId>,
        next: Option<InvocationHistoryNodeId>,
    ) -> Result<Self, TransitionProofIndexError> {
        self.validate_inner()
            .map_err(|_| TransitionProofIndexError::Invalid)?;
        if self.retired_root != expected
            || next == Some(InvocationHistoryNodeId::ZERO)
            || expected == next
        {
            return Err(TransitionProofIndexError::Conflict);
        }
        let mut manifest = self.clone();
        manifest.retired_root = next;
        manifest
            .validate_inner()
            .map_err(|_| TransitionProofIndexError::Invalid)?;
        Ok(manifest)
    }

    pub(crate) fn get(&self, key: TransitionProofKey) -> Option<TransitionProofIndexEntry> {
        self.records
            .binary_search_by_key(&key, |entry| entry.key)
            .ok()
            .map(|index| self.records[index])
    }

    pub(crate) fn live(&self, invocation: InvocationId) -> Option<TransitionProofKey> {
        self.live
            .binary_search_by_key(&invocation, |key| key.invocation)
            .ok()
            .map(|index| self.live[index])
    }

    /// Publish one record and install it as the invocation's live edge.
    ///
    /// `expected_live` makes Resume and Merge recanonicalization conditional
    /// on the exact edge consumed by replay. A newly observed Invoke supplies
    /// `None`. An already-installed exact entry is idempotent so ambiguous
    /// same-head-CAS completion can be revalidated without fabricating a new
    /// record.
    pub(crate) fn publish(
        &self,
        entry: TransitionProofIndexEntry,
        expected_live: Option<TransitionProofKey>,
    ) -> Result<Self, TransitionProofIndexError> {
        self.validate_inner()
            .map_err(|_| TransitionProofIndexError::Invalid)?;
        entry
            .validate()
            .map_err(|_| TransitionProofIndexError::Invalid)?;
        let current_live = self.live(entry.key.invocation);
        if self.get(entry.key) == Some(entry) && current_live == Some(entry.key) {
            return Ok(self.clone());
        }
        if current_live != expected_live {
            return Err(if current_live.is_some() || expected_live.is_some() {
                TransitionProofIndexError::Conflict
            } else {
                TransitionProofIndexError::Missing
            });
        }
        let mut records = self.records.clone();
        match records.binary_search_by_key(&entry.key, |item| item.key) {
            Ok(index) if records[index] != entry => {
                return Err(TransitionProofIndexError::Conflict);
            }
            Ok(_) => {}
            Err(index) => {
                if records.len() == MAX_TRANSITION_PROOF_INDEX_ENTRIES {
                    return Err(TransitionProofIndexError::Capacity);
                }
                records
                    .try_reserve(1)
                    .map_err(|_| TransitionProofIndexError::Capacity)?;
                records.insert(index, entry);
            }
        }
        let mut live = self.live.clone();
        match live.binary_search_by_key(&entry.key.invocation, |key| key.invocation) {
            Ok(index) => live[index] = entry.key,
            Err(index) => {
                if live.len() == MAX_TRANSITION_PROOF_LIVE_ENTRIES {
                    return Err(TransitionProofIndexError::Capacity);
                }
                live.try_reserve(1)
                    .map_err(|_| TransitionProofIndexError::Capacity)?;
                live.insert(index, entry.key);
            }
        }
        let next = Self {
            genesis: self.genesis,
            records,
            live,
            retired_root: self.retired_root,
        };
        next.validate_inner()
            .map_err(|_| TransitionProofIndexError::Capacity)?;
        Ok(next)
    }

    /// Retire only the exact live edge consumed by a successful
    /// acknowledgement. The corresponding record deliberately remains in the
    /// replay-retained set until checkpoint compaction.
    pub(crate) fn retire(
        &self,
        expected_live: TransitionProofKey,
    ) -> Result<Self, TransitionProofIndexError> {
        self.validate_inner()
            .map_err(|_| TransitionProofIndexError::Invalid)?;
        let index = match self
            .live
            .binary_search_by_key(&expected_live.invocation, |key| key.invocation)
        {
            Ok(index) => index,
            Err(_) if self.get(expected_live).is_some() => return Ok(self.clone()),
            Err(_) => return Err(TransitionProofIndexError::Missing),
        };
        if self.live[index] != expected_live {
            return Err(TransitionProofIndexError::Conflict);
        }
        let mut live = self.live.clone();
        live.remove(index);
        let next = Self {
            genesis: self.genesis,
            records: self.records.clone(),
            live,
            retired_root: self.retired_root,
        };
        next.validate_inner()
            .map_err(|_| TransitionProofIndexError::Invalid)?;
        Ok(next)
    }

    /// Canonical checkpoint successor: retain exactly the public tuples still
    /// needed for delivery/resume and reset replay-only suffix history.
    pub(crate) fn checkpointed(&self) -> Result<Self, TransitionProofIndexError> {
        self.validate_inner()
            .map_err(|_| TransitionProofIndexError::Invalid)?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(self.live.len())
            .map_err(|_| TransitionProofIndexError::Capacity)?;
        for key in &self.live {
            records.push(self.get(*key).ok_or(TransitionProofIndexError::Invalid)?);
        }
        records.sort_unstable_by_key(|entry| entry.key);
        let compact = Self {
            genesis: self.genesis,
            records,
            live: self.live.clone(),
            retired_root: self.retired_root,
        };
        compact
            .validate_inner()
            .map_err(|_| TransitionProofIndexError::Invalid)?;
        Ok(compact)
    }

    fn validate_inner(&self) -> Result<(), DecodeError> {
        if self.genesis == AgentJournalGenesisId::ZERO
            || self.retired_root == Some(InvocationHistoryNodeId::ZERO)
            || self.records.len() > MAX_TRANSITION_PROOF_INDEX_ENTRIES
            || self.live.len() > MAX_TRANSITION_PROOF_LIVE_ENTRIES
        {
            return Err(DecodeError::NonCanonical);
        }
        let mut aggregate = 0u64;
        for entry in &self.records {
            entry.validate()?;
            aggregate = aggregate
                .checked_add(entry.proof_material_bytes)
                .ok_or(DecodeError::LimitExceeded)?;
        }
        if aggregate > MAX_TRANSITION_PROOF_INDEX_MATERIAL_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        if self
            .records
            .windows(2)
            .any(|pair| pair[0].key >= pair[1].key)
            || self
                .live
                .windows(2)
                .any(|pair| pair[0].invocation >= pair[1].invocation)
            || self
                .live
                .iter()
                .any(|key| !key.validate() || self.get(*key).is_none())
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

impl ServiceWire for TransitionProofIndexManifest {
    const MAGIC: [u8; 4] = *b"AJP3";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(self.genesis.as_bytes());
        encoder.list(&self.records, |encoder, entry| {
            encoder.fixed(entry.key.invocation.as_bytes());
            encoder.fixed(entry.key.execution.as_bytes());
            encoder.fixed(entry.record.as_bytes());
            encoder.u64(entry.proof_material_bytes);
        });
        encoder.list(&self.live, |encoder, key| {
            encoder.fixed(key.invocation.as_bytes());
            encoder.fixed(key.execution.as_bytes());
        });
        encoder.option(&self.retired_root, |encoder, root| {
            encoder.fixed(root.as_bytes())
        });
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_TRANSITION_PROOF_INDEX_BYTES)?;
        let genesis = AgentJournalGenesisId(decoder.fixed()?);
        let count = decoder.u32()? as usize;
        if count > MAX_TRANSITION_PROOF_INDEX_ENTRIES {
            return Err(DecodeError::LimitExceeded);
        }
        let entries_bytes = count
            .checked_mul(TRANSITION_PROOF_INDEX_ENTRY_BYTES)
            .ok_or(DecodeError::LimitExceeded)?;
        // Every entry is fixed-width. Prove the complete payload is present
        // before reserving from an attacker-controlled count; the outer wire
        // decoder separately rejects trailing bytes.
        if decoder.remaining() < entries_bytes.saturating_add(4) {
            return Err(DecodeError::NonCanonical);
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(count)
            .map_err(|_| DecodeError::LimitExceeded)?;
        for _ in 0..count {
            records.push(TransitionProofIndexEntry {
                key: TransitionProofKey {
                    invocation: crate::agent_sdk::InvocationId(decoder.fixed()?),
                    execution: crate::agent_sdk::Hash(decoder.fixed()?),
                },
                record: TransitionProofEntryId(decoder.fixed()?),
                proof_material_bytes: decoder.u64()?,
            });
        }
        let live_count = decoder.u32()? as usize;
        if live_count > MAX_TRANSITION_PROOF_LIVE_ENTRIES {
            return Err(DecodeError::LimitExceeded);
        }
        let live_bytes = live_count
            .checked_mul(TRANSITION_PROOF_LIVE_ENTRY_BYTES)
            .ok_or(DecodeError::LimitExceeded)?;
        if decoder.remaining() < live_bytes.saturating_add(1) {
            return Err(DecodeError::NonCanonical);
        }
        let mut live = Vec::new();
        live.try_reserve_exact(live_count)
            .map_err(|_| DecodeError::LimitExceeded)?;
        for _ in 0..live_count {
            live.push(TransitionProofKey {
                invocation: InvocationId(decoder.fixed()?),
                execution: crate::agent_sdk::Hash(decoder.fixed()?),
            });
        }
        let retired_root =
            decoder.option(|decoder| Ok(InvocationHistoryNodeId(decoder.fixed()?)))?;
        let manifest = Self {
            genesis,
            records,
            live,
            retired_root,
        };
        manifest.validate_inner()?;
        Ok(manifest)
    }
}

impl super::journal::sealed::Sealed for TransitionProofIndexManifest {}

impl CanonicalJournalRecord for TransitionProofIndexManifest {
    type Id = TransitionProofIndexId;

    const STORAGE_CLASS: JournalStorageClass = JournalStorageClass::TransitionProofIndex;

    fn validate(&self) -> Result<(), DecodeError> {
        self.validate_inner()?;
        validate_encoded_bound(self, MAX_TRANSITION_PROOF_INDEX_BYTES)
    }

    fn id(&self) -> Self::Id {
        TransitionProofIndexId(content_id(
            b"vos/agent/journal/transition-proof-index/v3",
            self,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransitionProofIndexError {
    Invalid,
    Missing,
    Conflict,
    Capacity,
}

fn valid_blob_ref(reference: &BlobRef, maximum: u64) -> bool {
    reference.hash != Hash::ZERO && reference.len != 0 && reference.len <= maximum
}

fn encode_agent_wire<T: AgentCanonicalWire>(value: &T) -> Result<Vec<u8>, DecodeError> {
    AgentCanonicalWire::encode(value).map_err(|_| DecodeError::NonCanonical)
}

fn decode_agent_wire<T: AgentCanonicalWire>(
    bytes: &[u8],
    maximum: usize,
) -> Result<(T, Vec<u8>), DecodeError> {
    if bytes.len() > maximum {
        return Err(DecodeError::LimitExceeded);
    }
    let value = AgentCanonicalWire::decode(bytes).map_err(|_| DecodeError::NonCanonical)?;
    let canonical = encode_agent_wire(&value)?;
    if canonical != bytes {
        return Err(DecodeError::NonCanonical);
    }
    Ok((value, canonical))
}

fn encode_blob(encoder: &mut Encoder<'_>, reference: &BlobRef) {
    encoder.fixed(reference.hash.as_bytes());
    encoder.u64(reference.len);
}

fn decode_blob(decoder: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    Ok(BlobRef {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    })
}

fn encode_ordered_base(encoder: &mut Encoder<'_>, base: OrderedBase) {
    encoder.u64(base.index);
    encoder.option(&base.head, |encoder, head| encoder.fixed(head.as_bytes()));
}

fn decode_ordered_base(decoder: &mut Decoder<'_>) -> Result<OrderedBase, DecodeError> {
    let base = OrderedBase {
        index: decoder.u64()?,
        head: decoder.option(|decoder| Ok(OrderedEntryId(decoder.fixed()?)))?,
    };
    base.validate()?;
    Ok(base)
}

fn enforce_complete_bound(decoder: &Decoder<'_>, maximum: usize) -> Result<(), DecodeError> {
    if decoder.remaining() > maximum {
        Err(DecodeError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn validate_encoded_bound<T: ServiceWire>(value: &T, maximum: usize) -> Result<(), DecodeError> {
    if value.encode().len() > maximum {
        Err(DecodeError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn content_id<T: ServiceWire>(domain: &[u8], value: &T) -> [u8; 32] {
    Hash::digest(domain, &[&value.encode()]).0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_sdk::proof::{
        ProofLaneRoots, TransitionProofStatement, TransitionProofSubject,
    };
    use crate::agent_sdk::{
        ActorId as CleanActorId, AgentId as CleanAgentId, BlobRef as CleanBlobRef,
        DeploymentId as CleanDeploymentId, Hash as CleanHash, InvocationId as CleanInvocationId,
        MethodMode, ProducerId as CleanProducerId, ProgramId as CleanProgramId,
        SpaceId as CleanSpaceId,
    };
    use alloc::vec;

    fn proof(byte: u8) -> JournalTransitionProof {
        let proof_material = vec![byte; 33];
        let proof_manifest =
            TransitionProofMaterialManifest::for_material(&proof_material).unwrap();
        let proof_manifest_bytes = AgentCanonicalWire::encode(&proof_manifest).unwrap();
        let public_key = [byte.wrapping_add(1); 32];
        let before = ProofLaneRoots {
            control: CleanHash([0x20; 32]),
            linear: Some(CleanHash([0x21; 32])),
            merge: Some(CleanHash([0x22; 32])),
            local: Some(CleanHash([0x23; 32])),
        };
        let after = ProofLaneRoots {
            linear: Some(CleanHash([byte; 32])),
            ..before
        };
        let proof_record = TransitionProofRecord {
            statement: TransitionProofStatement {
                subject: TransitionProofSubject {
                    space: CleanSpaceId([0x30; 32]),
                    agent: CleanAgentId([0x31; 32]),
                    runtime_deployment: CleanDeploymentId([0x32; 32]),
                    runtime_program: CleanProgramId([0x33; 32]),
                    runtime_package: CleanBlobRef::of_bytes(b"runtime-package"),
                    actor: CleanActorId([0x34; 32]),
                    incarnation: CleanHash([0x35; 32]),
                    actor_deployment: CleanDeploymentId([0x36; 32]),
                    actor_program: CleanProgramId([0x37; 32]),
                    invocation: CleanInvocationId([byte; 32]),
                    method: alloc::string::String::from("apply"),
                    mode: MethodMode::Linear,
                },
                before,
                after,
                work: TransitionProofStatement::work_commitment(b"canonical-work"),
                transition: TransitionProofStatement::transition_commitment(
                    b"canonical-transition",
                ),
                refine_trace: CleanHash([0x38; 32]),
                public_io: CleanHash([0x39; 32]),
                proof_system: CleanHash([0x3a; 32]),
            },
            proof: CleanBlobRef::of_bytes(&proof_manifest_bytes),
            producer: CleanProducerId::of_public_key(&public_key),
            producer_public_key: public_key,
            producer_signature: [byte.wrapping_add(2); 64],
        };
        let publication = proof_record.verified_publication_commitment().unwrap();
        JournalTransitionProof::new(
            AgentJournalGenesisId([0x40; 32]),
            JournalHeadsId([0x41; 32]),
            ReplayInputId([0x42; 32]),
            TransitionProofAnchor::Ordered {
                entry: OrderedEntryId([0x43; 32]),
                index: byte as u64,
                merge_frontier: MergeFrontierId([0x44; 32]),
                merge_seal: None,
            },
            BlobRef::of_bytes(b"canonical-work"),
            BlobRef::of_bytes(b"canonical-transition"),
            ArtifactClosureId([0x45; 32]),
            BlobRef::of_bytes(b"actor-package"),
            proof_record,
            proof_manifest,
            Hash(publication.0),
        )
        .unwrap()
    }

    #[test]
    fn proof_tuple_round_trips_and_binds_manifest_position_and_dependencies() {
        let value = proof(1);
        value.validate().unwrap();
        let encoded = value.encode();
        assert!(encoded.len() <= MAX_TRANSITION_PROOF_ENTRY_BYTES);
        assert_eq!(JournalTransitionProof::decode(&encoded).unwrap(), value);
        for magic in [b"AJPT", b"AJP3"] {
            let mut substituted = encoded.clone();
            substituted[..4].copy_from_slice(magic);
            assert!(JournalTransitionProof::decode(&substituted).is_err());
        }

        let id = value.id();
        let mut changed = value.clone();
        changed.predecessor = JournalHeadsId([0x47; 32]);
        assert_ne!(changed.id(), id);
        changed = value.clone();
        changed.input = ReplayInputId([0x48; 32]);
        assert_ne!(changed.id(), id);
        changed = value.clone();
        changed.actor_package = BlobRef::of_bytes(b"other-actor-package");
        assert_ne!(changed.id(), id);
        changed = value.clone();
        changed.proof_manifest =
            TransitionProofMaterialManifest::for_material(b"substituted-proof").unwrap();
        assert_eq!(changed.validate(), Err(DecodeError::NonCanonical));
        changed = value.clone();
        changed.publication = Hash([0x46; 32]);
        assert_eq!(changed.validate(), Err(DecodeError::NonCanonical));

        let mut wrong_position = value;
        wrong_position.anchor = TransitionProofAnchor::Local {
            entry: LocalEntryId([0x49; 32]),
            node: NodeId([0x4a; 32]),
            revision: 1,
            ordered_base: OrderedBase::post_genesis(),
            merge_frontier: MergeFrontierId([0x4b; 32]),
        };
        assert_eq!(wrong_position.validate(), Err(DecodeError::NonCanonical));
    }

    #[test]
    fn proof_index_is_sorted_bounded_idempotent_and_conflict_exact() {
        let first_record = proof(2);
        let second_record = proof(1);
        let first = TransitionProofIndexEntry::for_record(&first_record).unwrap();
        let second = TransitionProofIndexEntry::for_record(&second_record).unwrap();
        let empty = TransitionProofIndexManifest::empty(first_record.genesis);
        empty.validate().unwrap();
        assert_ne!(empty.id(), TransitionProofIndexId::ZERO);

        let one = empty.publish(first, None).unwrap();
        let two = one.publish(second, None).unwrap();
        assert_eq!(two.entries(), &[second, first]);
        assert_eq!(two.get(first.key), Some(first));
        assert_eq!(two.live(first.key.invocation), Some(first.key));
        assert_eq!(two.live(second.key.invocation), Some(second.key));
        assert_eq!(two.publish(second, None).unwrap(), two);

        let mut divergent = second;
        divergent.record = TransitionProofEntryId([0x55; 32]);
        assert_eq!(
            two.publish(divergent, Some(second.key)),
            Err(TransitionProofIndexError::Conflict)
        );
        assert_eq!(
            two.retire(TransitionProofKey {
                invocation: second.key.invocation,
                execution: crate::agent_sdk::Hash([0x55; 32]),
            }),
            Err(TransitionProofIndexError::Conflict)
        );
        let retired = two.retire(second.key).unwrap();
        assert_eq!(retired.entries(), &[second, first]);
        assert_eq!(retired.live(second.key.invocation), None);
        assert_eq!(retired.retire(second.key).unwrap(), retired);
        let one_again = retired.checkpointed().unwrap();
        assert_eq!(one_again, one);
        assert_eq!(
            one_again.retire(second.key),
            Err(TransitionProofIndexError::Missing)
        );
        let encoded = two.encode();
        assert!(encoded.len() <= MAX_TRANSITION_PROOF_INDEX_BYTES);
        assert_eq!(TransitionProofIndexManifest::decode(&encoded).unwrap(), two);

        let mut hostile = empty.encode();
        // ServiceWire header is magic + platform ID; the manifest body starts
        // with genesis followed by this u32 list count.
        let count_offset = 4 + 32 + 32;
        hostile[count_offset..count_offset + 4]
            .copy_from_slice(&((MAX_TRANSITION_PROOF_INDEX_ENTRIES + 1) as u32).to_le_bytes());
        assert_eq!(
            TransitionProofIndexManifest::decode(&hostile),
            Err(DecodeError::LimitExceeded),
        );

        let mut truncated = empty.encode();
        truncated[count_offset..count_offset + 4]
            .copy_from_slice(&(MAX_TRANSITION_PROOF_INDEX_ENTRIES as u32).to_le_bytes());
        assert_eq!(
            TransitionProofIndexManifest::decode(&truncated),
            Err(DecodeError::NonCanonical),
        );

        for magic in [b"AJPX", b"AJP2"] {
            let mut predecessor_wire = encoded.clone();
            predecessor_wire[0..4].copy_from_slice(magic);
            assert!(TransitionProofIndexManifest::decode(&predecessor_wire).is_err());
        }
        let mut cross_purpose = two.encode();
        cross_purpose[..4].copy_from_slice(b"APT2");
        assert!(TransitionProofIndexManifest::decode(&cross_purpose).is_err());
    }

    #[test]
    fn proof_index_caps_logical_material_across_all_records() {
        let first_record = proof(1);
        let second_record = proof(2);
        let mut first = TransitionProofIndexEntry::for_record(&first_record).unwrap();
        let mut second = TransitionProofIndexEntry::for_record(&second_record).unwrap();
        first.proof_material_bytes = MAX_TRANSITION_PROOF_INDEX_MATERIAL_BYTES;
        second.proof_material_bytes = 1;

        let exact = TransitionProofIndexManifest {
            genesis: first_record.genesis,
            records: vec![first],
            live: Vec::new(),
            retired_root: None,
        };
        exact.validate().unwrap();
        assert_eq!(
            TransitionProofIndexManifest::decode(&exact.encode()).unwrap(),
            exact
        );

        let excessive = TransitionProofIndexManifest {
            genesis: first_record.genesis,
            records: vec![first, second],
            live: Vec::new(),
            retired_root: None,
        };
        assert_eq!(excessive.validate(), Err(DecodeError::LimitExceeded));
        assert_eq!(
            TransitionProofIndexManifest::decode(&excessive.encode()),
            Err(DecodeError::LimitExceeded)
        );
    }

    #[test]
    fn proof_index_resume_replaces_only_the_exact_live_edge() {
        let initial_record = proof(3);
        let initial = TransitionProofIndexEntry::for_record(&initial_record).unwrap();
        let mut resumed_record = proof(4);
        resumed_record.proof_record.statement.subject.invocation = initial.key.invocation;
        resumed_record.proof_record.statement.work = CleanHash([0x71; 32]);
        resumed_record.proof_record_wire = encode_agent_wire(&resumed_record.proof_record).unwrap();
        resumed_record.publication = Hash(
            resumed_record
                .proof_record
                .verified_publication_commitment()
                .unwrap()
                .0,
        );
        resumed_record.validate().unwrap();
        let resumed = TransitionProofIndexEntry::for_record(&resumed_record).unwrap();

        let one = TransitionProofIndexManifest::empty(initial_record.genesis)
            .publish(initial, None)
            .unwrap();
        assert_eq!(
            one.publish(
                resumed,
                Some(TransitionProofKey {
                    invocation: initial.key.invocation,
                    execution: CleanHash([0x72; 32]),
                })
            ),
            Err(TransitionProofIndexError::Conflict),
        );
        let two = one.publish(resumed, Some(initial.key)).unwrap();
        assert_eq!(two.entries().len(), 2);
        assert_eq!(two.get(initial.key), Some(initial));
        assert_eq!(two.get(resumed.key), Some(resumed));
        assert_eq!(two.live(initial.key.invocation), Some(resumed.key));
        assert_eq!(two.checkpointed().unwrap().entries(), &[resumed]);
    }
}
