//! Crash-safe Raft routing and application evidence for Shared Agents.
//!
//! This module deliberately stops short of being a Raft storage adapter.  Raw
//! Raft bytes are first decoded as bounded canonical [`AgentRaftCommand`]s,
//! then promoted to [`CommittedAgentRaftEntry`] only through the crate-private
//! read-only durable-log witness.  Applying an ordered command and publishing
//! its exact [`OrderedCommitClaim`] are separate from signing: the evidence
//! ledger first anchors that applied claim, then commits an immutable pledge,
//! and only then invokes a replica signer.
//!
//! `compact_safe` is durable audit state, not a compaction capability.  This
//! file intentionally exposes no Raft snapshot, truncation, or compaction API.

use alloc::vec::Vec;
use core::fmt;

use super::genesis::{
    AgentGenesisAdmissionId, AgentReplicaCommittee, AgentReplicaCommitteeId,
    MAX_AGENT_REPLICA_COMMITTEE_BYTES,
};
use super::journal::{
    AgentJournalGenesisId, CanonicalJournalRecord, JournalHeadsId, MAX_JOURNAL_RECORD_BYTES,
    OrderedBase, OrderedEntry, OrderedEntryId,
};
#[cfg(all(feature = "std", feature = "storage"))]
use super::replay::PublishedSharedOrdered;
use super::shared_commit::{
    MAX_ORDERED_COMMIT_CLAIM_BYTES, MAX_REPLICA_COMMIT_SIGNATURE_BYTES, OrderedCommitClaim,
    ReplicaCommitSignature, ReplicaQuorumCertificate, SharedCommitError,
};
use super::{
    AgentProfile, MAX_AGENT_REPLICAS, MAX_CATALOG_ARTIFACT_BYTES,
    MAX_CATALOG_ARTIFACT_REFERENCED_BYTES, MAX_CATALOG_ARTIFACT_REFERENCES, ReplicaRole,
};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{AgentId, BlobRef, Hash, NodeId, SpaceId};

const SERVICE_WIRE_HEADER_BYTES: usize = 4 + 32;

const ARTIFACT_BATCH_ID_DOMAIN: &[u8] = b"vos/agent/shared/artifact-batch/v1";
const ARTIFACT_CHUNK_COMMITMENT_DOMAIN: &[u8] = b"vos/agent/shared/artifact-batch-chunk/v1";
const AGENT_RAFT_COMMAND_COMMITMENT_DOMAIN: &[u8] = b"vos/agent/shared/raft-command/v1";
const AGENT_RAFT_APPLY_RESERVATION_DOMAIN: &[u8] = b"vos/agent/shared/raft-apply-reservation/v1";

/// Maximum complete generation-scoped route key.
pub const MAX_AGENT_ROUTE_KEY_BYTES: usize = 256;
/// Maximum complete artifact-batch manifest.
pub const MAX_ARTIFACT_BATCH_MANIFEST_BYTES: usize = 16 * 1024;
/// Canonical non-final artifact-chunk width.
pub const ARTIFACT_CHUNK_DATA_BYTES: usize = 64 * 1024;
/// Maximum complete artifact chunk, including its repeated manifest.
pub const MAX_ARTIFACT_CHUNK_WIRE_BYTES: usize = 96 * 1024;
/// Maximum complete Shared Agent Raft command.
pub const MAX_AGENT_RAFT_COMMAND_BYTES: usize = 192 * 1024;
/// Maximum complete apply-audit disposition.
pub const MAX_AGENT_RAFT_AUDIT_DISPOSITION_BYTES: usize = 256;
/// Maximum complete durable apply metadata record.
pub const MAX_AGENT_RAFT_APPLY_META_BYTES: usize = 1024;

/// Phase-1 ceiling on all retained ordered-evidence entries for one route.
///
/// This bounds normal apply work and restart audit while this slice exposes no
/// certified snapshot/retirement operation. Reaching it backpressures ordered
/// apply, including entries which already have a QC, until a later slice adds
/// a crash-safe evidence-retirement protocol.
pub const MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES: usize = 4096;
/// Maximum persisted shares across the bounded per-route evidence window.
pub const MAX_AGENT_RAFT_SHARE_BACKLOG: usize =
    MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES * MAX_AGENT_REPLICAS;

/// Stable physical identity of the one journal store paired with an evidence
/// ledger.
///
/// The filesystem adapter derives this from its pinned external root and
/// stable-lock identity; an in-memory adapter assigns a fresh identity at
/// construction. Copying otherwise matching heads must not reproduce this
/// value. It is deliberately available without the storage feature so the
/// opaque pre-publication reservation has the same shape in every build.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct JournalStoreInstanceId([u8; 32]);

impl JournalStoreInstanceId {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        (bytes != [0; 32]).then_some(Self(bytes))
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Full immutable Shared-Agent generation route.
///
/// Space and Agent alone are insufficient: delayed traffic from a retired
/// generation must not enter a new journal or committee.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentRouteKey {
    space: SpaceId,
    agent: AgentId,
    genesis: AgentJournalGenesisId,
    admission: AgentGenesisAdmissionId,
    committee: AgentReplicaCommitteeId,
}

impl AgentRouteKey {
    pub fn new(
        space: SpaceId,
        agent: AgentId,
        genesis: AgentJournalGenesisId,
        admission: AgentGenesisAdmissionId,
        committee: AgentReplicaCommitteeId,
    ) -> Result<Self, AgentRaftWireError> {
        let route = Self {
            space,
            agent,
            genesis,
            admission,
            committee,
        };
        route.validate()?;
        Ok(route)
    }

    pub fn from_claim(claim: &OrderedCommitClaim) -> Result<Self, AgentRaftWireError> {
        Self::new(
            claim.space(),
            claim.agent(),
            claim.genesis(),
            claim.admission(),
            claim.committee(),
        )
    }

    pub const fn space(self) -> SpaceId {
        self.space
    }

    pub const fn agent(self) -> AgentId {
        self.agent
    }

    pub const fn genesis(self) -> AgentJournalGenesisId {
        self.genesis
    }

    pub const fn admission(self) -> AgentGenesisAdmissionId {
        self.admission
    }

    pub const fn committee(self) -> AgentReplicaCommitteeId {
        self.committee
    }

    pub fn validate(self) -> Result<(), AgentRaftWireError> {
        if self.space == SpaceId::ZERO
            || self.agent == AgentId::ZERO
            || self.genesis == AgentJournalGenesisId::ZERO
            || self.admission == AgentGenesisAdmissionId::ZERO
            || self.committee == AgentReplicaCommitteeId::ZERO
        {
            return Err(AgentRaftWireError::InvalidRoute);
        }
        enforce_wire_bound(&self, MAX_AGENT_ROUTE_KEY_BYTES)
    }
}

impl ServiceWire for AgentRouteKey {
    const MAGIC: [u8; 4] = *b"AGRR";

    fn encode_body(&self, output: &mut Vec<u8>) {
        encode_route(&mut Encoder(output), *self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_AGENT_ROUTE_KEY_BYTES)?;
        decode_route(decoder)
    }
}

/// Stable content identity of one exact artifact manifest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactBatchId([u8; 32]);

impl ArtifactBatchId {
    pub const ZERO: Self = Self([0; 32]);

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ArtifactBatchId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArtifactBatchId(")?;
        for byte in &self.0[..4] {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str("…)")
    }
}

/// Canonical, generation-scoped set of artifacts staged before ordered apply.
///
/// References are strictly ordered by hash, exactly like the journal artifact
/// closure.  Repeating the manifest in every chunk makes every Raft command
/// independently bounded and routable; a receiver never has to interpret a
/// chunk under ambient batch state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactBatchManifest {
    route: AgentRouteKey,
    artifacts: Vec<BlobRef>,
}

impl ArtifactBatchManifest {
    pub fn new(route: AgentRouteKey, artifacts: Vec<BlobRef>) -> Result<Self, AgentRaftWireError> {
        let manifest = Self { route, artifacts };
        manifest.validate()?;
        Ok(manifest)
    }

    pub const fn route(&self) -> AgentRouteKey {
        self.route
    }

    pub fn artifacts(&self) -> &[BlobRef] {
        &self.artifacts
    }

    pub fn id(&self) -> ArtifactBatchId {
        ArtifactBatchId(Hash::digest(ARTIFACT_BATCH_ID_DOMAIN, &[&self.encode()]).0)
    }

    pub fn validate(&self) -> Result<(), AgentRaftWireError> {
        self.route.validate()?;
        let referenced_bytes = self.artifacts.iter().try_fold(0_u64, |total, artifact| {
            total
                .checked_add(artifact.len)
                .ok_or(AgentRaftWireError::LimitExceeded)
        })?;
        if self.artifacts.is_empty()
            || self.artifacts.len() > MAX_CATALOG_ARTIFACT_REFERENCES as usize
            || referenced_bytes > MAX_CATALOG_ARTIFACT_REFERENCED_BYTES
        {
            return Err(AgentRaftWireError::LimitExceeded);
        }
        if self.artifacts.iter().any(|artifact| {
            artifact.hash == Hash::ZERO || artifact.len > MAX_CATALOG_ARTIFACT_BYTES
        }) || self
            .artifacts
            .windows(2)
            .any(|pair| pair[0].hash >= pair[1].hash)
        {
            return Err(AgentRaftWireError::NonCanonical);
        }
        enforce_wire_bound(self, MAX_ARTIFACT_BATCH_MANIFEST_BYTES)
    }
}

impl ServiceWire for ArtifactBatchManifest {
    const MAGIC: [u8; 4] = *b"AGBM";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encode_route(&mut encoder, self.route);
        encoder.list(&self.artifacts, encode_blob_ref);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_ARTIFACT_BATCH_MANIFEST_BYTES)?;
        let route = decode_route(decoder)?;
        let count = decoder.u32()? as usize;
        if count > MAX_CATALOG_ARTIFACT_REFERENCES as usize
            || count > decoder.remaining() / (32 + 8)
        {
            return Err(DecodeError::LimitExceeded);
        }
        let mut artifacts = Vec::new();
        for _ in 0..count {
            artifacts
                .try_reserve(1)
                .map_err(|_| DecodeError::LimitExceeded)?;
            artifacts.push(decode_blob_ref(decoder)?);
        }
        let manifest = Self { route, artifacts };
        manifest.validate().map_err(map_wire_decode_error)?;
        Ok(manifest)
    }
}

/// One uniquely positioned chunk of one artifact in a canonical batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactChunk {
    manifest: ArtifactBatchManifest,
    artifact_index: u32,
    offset: u64,
    bytes: Vec<u8>,
    commitment: Hash,
}

impl ArtifactChunk {
    pub fn new(
        manifest: ArtifactBatchManifest,
        artifact_index: u32,
        offset: u64,
        bytes: Vec<u8>,
    ) -> Result<Self, AgentRaftWireError> {
        let commitment =
            artifact_chunk_commitment(manifest.id(), artifact_index, offset, bytes.as_slice());
        let chunk = Self {
            manifest,
            artifact_index,
            offset,
            bytes,
            commitment,
        };
        chunk.validate()?;
        Ok(chunk)
    }

    pub const fn manifest(&self) -> &ArtifactBatchManifest {
        &self.manifest
    }

    pub fn batch(&self) -> ArtifactBatchId {
        self.manifest.id()
    }

    pub const fn artifact_index(&self) -> u32 {
        self.artifact_index
    }

    pub const fn offset(&self) -> u64 {
        self.offset
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn commitment(&self) -> Hash {
        self.commitment
    }

    pub fn artifact(&self) -> &BlobRef {
        &self.manifest.artifacts[self.artifact_index as usize]
    }

    pub fn validate(&self) -> Result<(), AgentRaftWireError> {
        self.manifest.validate()?;
        let artifact = self
            .manifest
            .artifacts
            .get(self.artifact_index as usize)
            .ok_or(AgentRaftWireError::InvalidArtifactChunk)?;
        let remaining = artifact
            .len
            .checked_sub(self.offset)
            .filter(|_| self.offset < artifact.len)
            .ok_or(AgentRaftWireError::InvalidArtifactChunk)?;
        let expected = remaining.min(ARTIFACT_CHUNK_DATA_BYTES as u64) as usize;
        if self.offset % ARTIFACT_CHUNK_DATA_BYTES as u64 != 0
            || self.bytes.len() != expected
            || self.commitment
                != artifact_chunk_commitment(
                    self.manifest.id(),
                    self.artifact_index,
                    self.offset,
                    self.bytes.as_slice(),
                )
        {
            return Err(AgentRaftWireError::InvalidArtifactChunk);
        }
        enforce_wire_bound(self, MAX_ARTIFACT_CHUNK_WIRE_BYTES)
    }
}

impl ServiceWire for ArtifactChunk {
    const MAGIC: [u8; 4] = *b"AGBC";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.manifest.encode());
        encoder.u32(self.artifact_index);
        encoder.u64(self.offset);
        encoder.bytes(&self.bytes);
        encoder.fixed(&self.commitment.0);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_ARTIFACT_CHUNK_WIRE_BYTES)?;
        let manifest =
            decode_nested::<ArtifactBatchManifest>(decoder, MAX_ARTIFACT_BATCH_MANIFEST_BYTES)?;
        let artifact_index = decoder.u32()?;
        let offset = decoder.u64()?;
        let bytes = bounded_bytes(decoder, ARTIFACT_CHUNK_DATA_BYTES)?;
        let commitment = Hash(decoder.fixed()?);
        let chunk = Self {
            manifest,
            artifact_index,
            offset,
            bytes,
            commitment,
        };
        chunk.validate().map_err(map_wire_decode_error)?;
        Ok(chunk)
    }
}

/// Canonical application payload placed in the ordinary Raft data log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentRaftCommand {
    ArtifactChunk(ArtifactChunk),
    ArtifactAbort {
        route: AgentRouteKey,
        batch: ArtifactBatchId,
    },
    Ordered {
        route: AgentRouteKey,
        artifact_batch: Option<ArtifactBatchId>,
        entry: OrderedEntry,
    },
}

impl AgentRaftCommand {
    pub const fn route(&self) -> AgentRouteKey {
        match self {
            Self::ArtifactChunk(chunk) => chunk.manifest.route,
            Self::ArtifactAbort { route, .. } | Self::Ordered { route, .. } => *route,
        }
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(AGENT_RAFT_COMMAND_COMMITMENT_DOMAIN, &[&self.encode()])
    }

    pub fn validate(&self) -> Result<(), AgentRaftWireError> {
        match self {
            Self::ArtifactChunk(chunk) => chunk.validate()?,
            Self::ArtifactAbort { route, batch } => {
                route.validate()?;
                if *batch == ArtifactBatchId::ZERO {
                    return Err(AgentRaftWireError::InvalidArtifactBatch);
                }
            }
            Self::Ordered {
                route,
                artifact_batch,
                entry,
            } => {
                route.validate()?;
                if *artifact_batch == Some(ArtifactBatchId::ZERO)
                    || entry.genesis != route.genesis
                    || entry.input.runtime.space != route.space
                    || entry.input.runtime.agent != route.agent
                {
                    return Err(AgentRaftWireError::InvalidOrderedCommand);
                }
                entry
                    .validate()
                    .map_err(|_| AgentRaftWireError::InvalidOrderedCommand)?;
            }
        }
        enforce_wire_bound(self, MAX_AGENT_RAFT_COMMAND_BYTES)
    }
}

impl ServiceWire for AgentRaftCommand {
    const MAGIC: [u8; 4] = *b"AGRC";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        match self {
            Self::ArtifactChunk(chunk) => {
                encoder.u8(0);
                encoder.bytes(&chunk.encode());
            }
            Self::ArtifactAbort { route, batch } => {
                encoder.u8(1);
                encode_route(&mut encoder, *route);
                encoder.fixed(batch.as_bytes());
            }
            Self::Ordered {
                route,
                artifact_batch,
                entry,
            } => {
                encoder.u8(2);
                encode_route(&mut encoder, *route);
                encoder.option(artifact_batch, |encoder, batch| {
                    encoder.fixed(batch.as_bytes())
                });
                encoder.bytes(&entry.encode());
            }
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_AGENT_RAFT_COMMAND_BYTES)?;
        let command = match decoder.u8()? {
            0 => Self::ArtifactChunk(decode_nested::<ArtifactChunk>(
                decoder,
                MAX_ARTIFACT_CHUNK_WIRE_BYTES,
            )?),
            1 => Self::ArtifactAbort {
                route: decode_route(decoder)?,
                batch: ArtifactBatchId::from_bytes(decoder.fixed()?),
            },
            2 => Self::Ordered {
                route: decode_route(decoder)?,
                artifact_batch: decoder
                    .option(|decoder| Ok(ArtifactBatchId::from_bytes(decoder.fixed()?)))?,
                entry: decode_nested::<OrderedEntry>(decoder, MAX_JOURNAL_RECORD_BYTES)?,
            },
            _ => return Err(DecodeError::InvalidTag),
        };
        command.validate().map_err(map_wire_decode_error)?;
        Ok(command)
    }
}

/// Deterministic record of what the Shared application did at `applied`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentRaftAuditDisposition {
    ArtifactChunkStored {
        batch: ArtifactBatchId,
        artifact: Hash,
        offset: u64,
        chunk: Hash,
    },
    ArtifactBatchAborted {
        batch: ArtifactBatchId,
    },
    OrderedApplied {
        entry: OrderedEntryId,
        claim: Hash,
        successor: JournalHeadsId,
    },
}

impl AgentRaftAuditDisposition {
    fn validate(self) -> Result<(), AgentRaftWireError> {
        match self {
            Self::ArtifactChunkStored {
                batch,
                artifact,
                chunk,
                ..
            } if batch != ArtifactBatchId::ZERO
                && artifact != Hash::ZERO
                && chunk != Hash::ZERO => {}
            Self::ArtifactBatchAborted { batch } if batch != ArtifactBatchId::ZERO => {}
            Self::OrderedApplied {
                entry,
                claim,
                successor,
            } if entry != OrderedEntryId::ZERO
                && claim != Hash::ZERO
                && successor != JournalHeadsId::ZERO => {}
            _ => return Err(AgentRaftWireError::InvalidApplyMeta),
        }
        enforce_wire_bound(&self, MAX_AGENT_RAFT_AUDIT_DISPOSITION_BYTES)
    }
}

impl ServiceWire for AgentRaftAuditDisposition {
    const MAGIC: [u8; 4] = *b"AGAD";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encode_disposition(&mut encoder, *self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_AGENT_RAFT_AUDIT_DISPOSITION_BYTES)?;
        decode_disposition(decoder)
    }
}

/// Durable dual cursor for Shared-Agent Raft application.
///
/// `applied` advances after deterministic local publication. `compact_safe`
/// advances only after the ledger persists a verified application QC for an
/// anchored claim.  The latter is diagnostic input for a future adapter; it
/// is not itself a snapshot or compaction authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRaftApplyMeta {
    route: AgentRouteKey,
    applied_index: u64,
    applied_term: u64,
    applied_payload: Hash,
    disposition: Option<AgentRaftAuditDisposition>,
    compact_safe_index: u64,
    compact_safe_term: u64,
    compact_safe_qc: Option<Hash>,
}

impl AgentRaftApplyMeta {
    fn post_genesis(route: AgentRouteKey) -> Self {
        Self {
            route,
            applied_index: 0,
            applied_term: 0,
            applied_payload: Hash::ZERO,
            disposition: None,
            compact_safe_index: 0,
            compact_safe_term: 0,
            compact_safe_qc: None,
        }
    }

    pub const fn route(&self) -> AgentRouteKey {
        self.route
    }

    pub const fn applied(&self) -> (u64, u64) {
        (self.applied_index, self.applied_term)
    }

    pub const fn applied_payload(&self) -> Hash {
        self.applied_payload
    }

    pub const fn disposition(&self) -> Option<AgentRaftAuditDisposition> {
        self.disposition
    }

    /// Audit-only cursor. No compaction API consumes this value yet.
    pub const fn compact_safe(&self) -> (u64, u64) {
        (self.compact_safe_index, self.compact_safe_term)
    }

    pub const fn compact_safe_qc(&self) -> Option<Hash> {
        self.compact_safe_qc
    }

    fn advance_applied(
        &self,
        committed: &CommittedAgentRaftEntry,
        disposition: AgentRaftAuditDisposition,
    ) -> Result<Self, AgentRaftLedgerError> {
        disposition.validate().map_err(AgentRaftLedgerError::Wire)?;
        if committed.route() != self.route {
            return Err(AgentRaftLedgerError::WrongRoute);
        }
        if committed.index != self.applied_index.saturating_add(1)
            || (self.applied_index != 0 && committed.term < self.applied_term)
        {
            return Err(AgentRaftLedgerError::ApplyGap);
        }
        let next = Self {
            route: self.route,
            applied_index: committed.index,
            applied_term: committed.term,
            applied_payload: committed.payload_commitment,
            disposition: Some(disposition),
            compact_safe_index: self.compact_safe_index,
            compact_safe_term: self.compact_safe_term,
            compact_safe_qc: self.compact_safe_qc,
        };
        next.validate().map_err(AgentRaftLedgerError::Wire)?;
        Ok(next)
    }

    fn advance_compact_safe(
        &self,
        claim: &OrderedCommitClaim,
        qc: Hash,
    ) -> Result<Self, AgentRaftLedgerError> {
        if qc == Hash::ZERO
            || AgentRouteKey::from_claim(claim).map_err(AgentRaftLedgerError::Wire)? != self.route
            || claim.raft_index() > self.applied_index
        {
            return Err(AgentRaftLedgerError::InvalidClaim);
        }
        if claim.raft_index() < self.compact_safe_index {
            return Ok(self.clone());
        }
        if claim.raft_index() == self.compact_safe_index {
            if claim.raft_term() == self.compact_safe_term && self.compact_safe_qc == Some(qc) {
                return Ok(self.clone());
            }
            return Err(AgentRaftLedgerError::ConflictingCertificate);
        }
        let mut next = self.clone();
        next.compact_safe_index = claim.raft_index();
        next.compact_safe_term = claim.raft_term();
        next.compact_safe_qc = Some(qc);
        next.validate().map_err(AgentRaftLedgerError::Wire)?;
        Ok(next)
    }

    pub fn validate(&self) -> Result<(), AgentRaftWireError> {
        self.route.validate()?;
        let applied_empty = self.applied_index == 0
            && self.applied_term == 0
            && self.applied_payload == Hash::ZERO
            && self.disposition.is_none();
        let applied_present = self.applied_index != 0
            && self.applied_term != 0
            && self.applied_payload != Hash::ZERO
            && self.disposition.is_some();
        let compact_empty = self.compact_safe_index == 0
            && self.compact_safe_term == 0
            && self.compact_safe_qc.is_none();
        let compact_present = self.compact_safe_index != 0
            && self.compact_safe_term != 0
            && self.compact_safe_qc.is_some_and(|qc| qc != Hash::ZERO);
        if (!applied_empty && !applied_present)
            || (!compact_empty && !compact_present)
            || self.compact_safe_index > self.applied_index
            || (self.compact_safe_index == self.applied_index
                && self.compact_safe_index != 0
                && self.compact_safe_term != self.applied_term)
        {
            return Err(AgentRaftWireError::InvalidApplyMeta);
        }
        if let Some(disposition) = self.disposition {
            disposition.validate()?;
        }
        enforce_wire_bound(self, MAX_AGENT_RAFT_APPLY_META_BYTES)
    }
}

impl ServiceWire for AgentRaftApplyMeta {
    const MAGIC: [u8; 4] = *b"AGAM";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encode_route(&mut encoder, self.route);
        encoder.u64(self.applied_index);
        encoder.u64(self.applied_term);
        encoder.fixed(&self.applied_payload.0);
        encoder.option(&self.disposition, |encoder, disposition| {
            encode_disposition(encoder, *disposition)
        });
        encoder.u64(self.compact_safe_index);
        encoder.u64(self.compact_safe_term);
        encoder.option(&self.compact_safe_qc, |encoder, qc| encoder.fixed(&qc.0));
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_AGENT_RAFT_APPLY_META_BYTES)?;
        let meta = Self {
            route: decode_route(decoder)?,
            applied_index: decoder.u64()?,
            applied_term: decoder.u64()?,
            applied_payload: Hash(decoder.fixed()?),
            disposition: decoder.option(decode_disposition)?,
            compact_safe_index: decoder.u64()?,
            compact_safe_term: decoder.u64()?,
            compact_safe_qc: decoder.option(|decoder| Ok(Hash(decoder.fixed()?)))?,
        };
        meta.validate().map_err(map_wire_decode_error)?;
        Ok(meta)
    }
}

/// Opaque proof that a canonical Agent command occupies an exact committed
/// durable Raft-log slot.
///
/// There is no raw constructor and no wire decoder for this type.
#[derive(Clone, Debug)]
pub struct CommittedAgentRaftEntry {
    index: u64,
    term: u64,
    committed_index: u64,
    command: AgentRaftCommand,
    payload_commitment: Hash,
}

impl CommittedAgentRaftEntry {
    pub const fn index(&self) -> u64 {
        self.index
    }

    pub const fn term(&self) -> u64 {
        self.term
    }

    pub const fn committed_index(&self) -> u64 {
        self.committed_index
    }

    pub const fn command(&self) -> &AgentRaftCommand {
        &self.command
    }

    pub const fn route(&self) -> AgentRouteKey {
        self.command.route()
    }

    pub const fn payload_commitment(&self) -> Hash {
        self.payload_commitment
    }

    pub(crate) fn from_durable_log<W: DurableAgentRaftLogWitness>(
        witness: &W,
        index: u64,
    ) -> Result<Self, CommittedAgentRaftEntryError<W::Error>> {
        if index == 0 {
            return Err(CommittedAgentRaftEntryError::Invalid(
                AgentRaftWireError::InvalidCommittedEntry,
            ));
        }
        let (stored_index, term, committed_index, payload) = witness
            .read_committed_payload(index)
            .map_err(CommittedAgentRaftEntryError::Witness)?
            .ok_or(CommittedAgentRaftEntryError::Missing)?;
        if stored_index != index
            || term == 0
            || committed_index < index
            || payload.len() > MAX_AGENT_RAFT_COMMAND_BYTES
        {
            return Err(CommittedAgentRaftEntryError::Invalid(
                AgentRaftWireError::InvalidCommittedEntry,
            ));
        }
        let command = AgentRaftCommand::decode(&payload).map_err(|_| {
            CommittedAgentRaftEntryError::Invalid(AgentRaftWireError::InvalidCommittedEntry)
        })?;
        if command.encode() != payload {
            return Err(CommittedAgentRaftEntryError::Invalid(
                AgentRaftWireError::InvalidCommittedEntry,
            ));
        }
        let payload_commitment = command.commitment();
        Ok(Self {
            index,
            term,
            committed_index,
            command,
            payload_commitment,
        })
    }
}

/// Opaque proof that the evidence ledger durably reserved capacity for this
/// exact next committed application before replay may publish it.
///
/// Only [`AgentRaftEvidenceLedger::reserve_ordered_application`] can mint a
/// production value. An exact retry may mint another equivalent value for the
/// same durable reservation, so safety does not rely on bearer uniqueness:
/// replay is restricted to the bound journal-store instance and an exact
/// idempotent CAS, while the first successful anchor atomically consumes the
/// one durable reservation. The ledger later rejects every duplicate receipt.
#[derive(Debug)]
pub(crate) struct ReservedAgentRaftApplication {
    committed: CommittedAgentRaftEntry,
    local_node: NodeId,
    journal_store: JournalStoreInstanceId,
}

/// Read-only recovery evidence for an exact application already anchored
/// after journal publication. Unlike a reservation, this value cannot
/// authorize replay or another CAS.
#[derive(Clone, Debug)]
pub(crate) struct AnchoredAgentRaftApplication {
    route: AgentRouteKey,
    index: u64,
    term: u64,
    payload: Hash,
    journal_store: JournalStoreInstanceId,
    entry: OrderedEntryId,
    claim: OrderedCommitClaim,
    successor: JournalHeadsId,
}

impl AnchoredAgentRaftApplication {
    pub(crate) const fn route(&self) -> AgentRouteKey {
        self.route
    }

    pub(crate) const fn index(&self) -> u64 {
        self.index
    }

    pub(crate) const fn term(&self) -> u64 {
        self.term
    }

    pub(crate) const fn payload_commitment(&self) -> Hash {
        self.payload
    }

    pub(crate) const fn journal_store(&self) -> JournalStoreInstanceId {
        self.journal_store
    }

    pub(crate) const fn entry(&self) -> OrderedEntryId {
        self.entry
    }

    pub(crate) const fn claim(&self) -> &OrderedCommitClaim {
        &self.claim
    }

    pub(crate) const fn successor(&self) -> JournalHeadsId {
        self.successor
    }
}

impl ReservedAgentRaftApplication {
    #[cfg(test)]
    pub(crate) fn reserved_for_test(
        committed: CommittedAgentRaftEntry,
        local_node: NodeId,
        journal_store: JournalStoreInstanceId,
    ) -> Self {
        Self {
            committed,
            local_node,
            journal_store,
        }
    }

    pub(crate) const fn committed(&self) -> &CommittedAgentRaftEntry {
        &self.committed
    }

    pub(crate) const fn route(&self) -> AgentRouteKey {
        self.committed.route()
    }

    pub(crate) const fn index(&self) -> u64 {
        self.committed.index()
    }

    pub(crate) const fn term(&self) -> u64 {
        self.committed.term()
    }

    pub(crate) const fn payload_commitment(&self) -> Hash {
        self.committed.payload_commitment()
    }

    pub(crate) const fn local_node(&self) -> NodeId {
        self.local_node
    }

    pub(crate) const fn journal_store(&self) -> JournalStoreInstanceId {
        self.journal_store
    }
}

/// Read-only contract implemented later by the production durable Raft log.
///
/// The tuple is `(stored_index, term, durable_commit_index, canonical_payload)`.
/// Implementations must take all four values from one durable read view.  The
/// constructor above independently rejects zeros, a non-committed slot, the
/// wrong index, an over-limit payload, or a non-canonical command.
pub(crate) trait DurableAgentRaftLogWitness {
    type Error;

    fn read_committed_payload(
        &self,
        index: u64,
    ) -> Result<Option<(u64, u64, u64, Vec<u8>)>, Self::Error>;
}

#[derive(Debug)]
pub(crate) enum CommittedAgentRaftEntryError<E> {
    Witness(E),
    Missing,
    Invalid(AgentRaftWireError),
}

/// Structural failure for a canonical Shared-Agent Raft wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentRaftWireError {
    InvalidRoute,
    InvalidArtifactBatch,
    InvalidArtifactChunk,
    InvalidOrderedCommand,
    InvalidApplyMeta,
    InvalidCommittedEntry,
    NonCanonical,
    LimitExceeded,
}

impl fmt::Display for AgentRaftWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Shared Agent Raft wire: {self:?}")
    }
}

impl core::error::Error for AgentRaftWireError {}

/// Durable-ledger, application-ordering, or evidence-validation failure.
#[derive(Debug)]
pub enum AgentRaftLedgerError {
    Wire(AgentRaftWireError),
    SharedCommit(SharedCommitError),
    InvalidCommittee,
    WrongRoute,
    WrongJournalStore,
    LocalReplicaNotVoter,
    UnknownSigner,
    ObserverSigner,
    InvalidSignature,
    OrderedClaimRequired,
    ArtifactBatchReceiptRequired,
    InvalidClaim,
    ClaimNotAnchored,
    ApplyGap,
    AppliedConflict,
    DivergentClaim,
    DivergentReservation,
    ConflictingCertificate,
    BacklogLimit,
    LocalShareRequiresPledge,
    ConfigurationMismatch,
    CorruptLedger,
    FailStopped,
    #[cfg(all(feature = "std", feature = "storage"))]
    Backend(alloc::boxed::Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for AgentRaftLedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::SharedCommit(error) => error.fmt(formatter),
            #[cfg(all(feature = "std", feature = "storage"))]
            Self::Backend(error) => write!(formatter, "Shared Agent evidence backend: {error}"),
            _ => write!(formatter, "Shared Agent Raft evidence failure: {self:?}"),
        }
    }
}

impl core::error::Error for AgentRaftLedgerError {
    #[cfg(all(feature = "std", feature = "storage"))]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::SharedCommit(error) => Some(error),
            Self::Backend(error) => Some(&**error),
            _ => None,
        }
    }
}

impl From<AgentRaftWireError> for AgentRaftLedgerError {
    fn from(error: AgentRaftWireError) -> Self {
        Self::Wire(error)
    }
}

impl From<SharedCommitError> for AgentRaftLedgerError {
    fn from(error: SharedCommitError) -> Self {
        Self::SharedCommit(error)
    }
}

fn artifact_chunk_commitment(
    batch: ArtifactBatchId,
    artifact_index: u32,
    offset: u64,
    bytes: &[u8],
) -> Hash {
    let artifact_index = artifact_index.to_le_bytes();
    let offset = offset.to_le_bytes();
    Hash::digest(
        ARTIFACT_CHUNK_COMMITMENT_DOMAIN,
        &[batch.as_bytes(), &artifact_index, &offset, bytes],
    )
}

fn encode_route(encoder: &mut Encoder<'_>, route: AgentRouteKey) {
    encoder.fixed(&route.space.0);
    encoder.fixed(&route.agent.0);
    encoder.fixed(route.genesis.as_bytes());
    encoder.fixed(route.admission.as_bytes());
    encoder.fixed(route.committee.as_bytes());
}

fn decode_route(decoder: &mut Decoder<'_>) -> Result<AgentRouteKey, DecodeError> {
    AgentRouteKey::new(
        SpaceId(decoder.fixed()?),
        AgentId(decoder.fixed()?),
        AgentJournalGenesisId(decoder.fixed()?),
        AgentGenesisAdmissionId::from_bytes(decoder.fixed()?),
        AgentReplicaCommitteeId::from_bytes(decoder.fixed()?),
    )
    .map_err(map_wire_decode_error)
}

fn encode_blob_ref(encoder: &mut Encoder<'_>, artifact: &BlobRef) {
    encoder.fixed(&artifact.hash.0);
    encoder.u64(artifact.len);
}

fn decode_blob_ref(decoder: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    Ok(BlobRef {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    })
}

fn encode_disposition(encoder: &mut Encoder<'_>, disposition: AgentRaftAuditDisposition) {
    match disposition {
        AgentRaftAuditDisposition::ArtifactChunkStored {
            batch,
            artifact,
            offset,
            chunk,
        } => {
            encoder.u8(0);
            encoder.fixed(batch.as_bytes());
            encoder.fixed(&artifact.0);
            encoder.u64(offset);
            encoder.fixed(&chunk.0);
        }
        AgentRaftAuditDisposition::ArtifactBatchAborted { batch } => {
            encoder.u8(1);
            encoder.fixed(batch.as_bytes());
        }
        AgentRaftAuditDisposition::OrderedApplied {
            entry,
            claim,
            successor,
        } => {
            encoder.u8(2);
            encoder.fixed(entry.as_bytes());
            encoder.fixed(&claim.0);
            encoder.fixed(successor.as_bytes());
        }
    }
}

fn decode_disposition(decoder: &mut Decoder<'_>) -> Result<AgentRaftAuditDisposition, DecodeError> {
    let disposition = match decoder.u8()? {
        0 => AgentRaftAuditDisposition::ArtifactChunkStored {
            batch: ArtifactBatchId::from_bytes(decoder.fixed()?),
            artifact: Hash(decoder.fixed()?),
            offset: decoder.u64()?,
            chunk: Hash(decoder.fixed()?),
        },
        1 => AgentRaftAuditDisposition::ArtifactBatchAborted {
            batch: ArtifactBatchId::from_bytes(decoder.fixed()?),
        },
        2 => AgentRaftAuditDisposition::OrderedApplied {
            entry: OrderedEntryId(decoder.fixed()?),
            claim: Hash(decoder.fixed()?),
            successor: JournalHeadsId(decoder.fixed()?),
        },
        _ => return Err(DecodeError::InvalidTag),
    };
    disposition.validate().map_err(map_wire_decode_error)?;
    Ok(disposition)
}

fn bounded_bytes(decoder: &mut Decoder<'_>, maximum: usize) -> Result<Vec<u8>, DecodeError> {
    let len = decoder.u32()? as usize;
    if len > maximum {
        return Err(DecodeError::LimitExceeded);
    }
    Ok(decoder.take(len)?.to_vec())
}

fn decode_nested<T: ServiceWire>(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<T, DecodeError> {
    let bytes = decoder.bytes_ref()?;
    if bytes.len() > maximum {
        return Err(DecodeError::LimitExceeded);
    }
    T::decode(bytes)
}

fn enforce_complete_bound(decoder: &Decoder<'_>, maximum: usize) -> Result<(), DecodeError> {
    let maximum_body = maximum
        .checked_sub(SERVICE_WIRE_HEADER_BYTES)
        .ok_or(DecodeError::LimitExceeded)?;
    if decoder.remaining() > maximum_body {
        Err(DecodeError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn enforce_wire_bound<T: ServiceWire>(value: &T, maximum: usize) -> Result<(), AgentRaftWireError> {
    if value.encode().len() > maximum {
        Err(AgentRaftWireError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn map_wire_decode_error(error: AgentRaftWireError) -> DecodeError {
    match error {
        AgentRaftWireError::LimitExceeded => DecodeError::LimitExceeded,
        _ => DecodeError::NonCanonical,
    }
}

#[cfg(all(feature = "std", feature = "storage"))]
mod evidence_ledger {
    use alloc::collections::BTreeMap;
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use ed25519_dalek::VerifyingKey;
    use redb::{Database, ReadableTable, TableDefinition};

    use super::*;

    const LEDGER_SCHEMA_VERSION: u32 = 1;
    const MAX_CONFIG_RECORD_BYTES: usize = 72 * 1024;
    const MAX_RESERVATION_RECORD_BYTES: usize = 512;
    const MAX_ANCHOR_RECORD_BYTES: usize = 8 * 1024;
    const MAX_PLEDGE_RECORD_BYTES: usize = 8 * 1024;
    const MAX_SHARE_RECORD_BYTES: usize = 512;
    const MAX_FAIL_STOP_RECORD_BYTES: usize = 512;

    const CONFIG_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_config");
    const APPLY_META_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_apply_meta");
    const RESERVATION_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_apply_reservation");
    const ANCHOR_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_claim_anchors");
    const PLEDGE_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_sign_pledges");
    const SHARE_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_commit_shares");
    const QC_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_quorum_certificates");
    const FAIL_STOP_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_fail_stop");

    const ROUTE_STORAGE_KEY_BYTES: usize = 32 * 5;
    const ENTRY_STORAGE_KEY_BYTES: usize = ROUTE_STORAGE_KEY_BYTES + 8;
    const SHARE_STORAGE_KEY_BYTES: usize = ENTRY_STORAGE_KEY_BYTES + 32;

    /// Signer invoked only after the ledger has durably committed an exact
    /// `(route, Raft index, claim)` pledge.
    pub(crate) trait ReplicaCommitSigner {
        type Error;

        fn node(&self) -> NodeId;
        fn sign_commit_message(&self, message: Hash) -> Result<[u8; 64], Self::Error>;
    }

    #[derive(Debug)]
    pub(crate) enum AgentRaftSignError<E> {
        Ledger(AgentRaftLedgerError),
        Signer(E),
    }

    impl<E: fmt::Display> fmt::Display for AgentRaftSignError<E> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Ledger(error) => error.fmt(formatter),
                Self::Signer(error) => write!(formatter, "replica commit signer failed: {error}"),
            }
        }
    }

    impl<E: core::error::Error + 'static> core::error::Error for AgentRaftSignError<E> {
        fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
            match self {
                Self::Ledger(error) => Some(error),
                Self::Signer(error) => Some(error),
            }
        }
    }

    impl<E> From<AgentRaftLedgerError> for AgentRaftSignError<E> {
        fn from(error: AgentRaftLedgerError) -> Self {
            Self::Ledger(error)
        }
    }

    /// Result of persisting one exact share. A certificate is present once
    /// the independently admitted voter threshold has been verified.
    #[derive(Clone, Debug)]
    pub(crate) struct AgentRaftShareOutcome {
        share: ReplicaCommitSignature,
        certificate: Option<ReplicaQuorumCertificate>,
    }

    impl AgentRaftShareOutcome {
        pub(crate) const fn share(&self) -> &ReplicaCommitSignature {
            &self.share
        }

        pub(crate) const fn certificate(&self) -> Option<&ReplicaQuorumCertificate> {
            self.certificate.as_ref()
        }
    }

    /// Crash-safe sign-once and application-QC ledger for one exact route.
    ///
    /// The database may be shared with other routes. Every key and every value
    /// repeats the complete route, so table selection never supplies ambient
    /// identity. All writes are serialized per handle; redb supplies the
    /// durable cross-handle transaction boundary.
    pub(crate) struct AgentRaftEvidenceLedger {
        database: Arc<Database>,
        route: AgentRouteKey,
        committee: AgentReplicaCommittee,
        local_node: NodeId,
        journal_store: JournalStoreInstanceId,
        writes: std::sync::Mutex<()>,
    }

    impl AgentRaftEvidenceLedger {
        pub(crate) fn open(
            database: Arc<Database>,
            route: AgentRouteKey,
            committee: AgentReplicaCommittee,
            local_node: NodeId,
            journal_store: JournalStoreInstanceId,
        ) -> Result<Self, AgentRaftLedgerError> {
            validate_configuration(route, &committee, local_node)?;
            let expected = ConfigRecord {
                version: LEDGER_SCHEMA_VERSION,
                route,
                committee: committee.clone(),
                local_node,
                journal_store,
            };
            let route_key = route_storage_key(route);
            let transaction = database.begin_write()?;
            {
                let mut table = transaction.open_table(CONFIG_TABLE)?;
                let existing = table
                    .get(route_key.as_slice())?
                    .map(|value| value.value().to_vec());
                match existing {
                    Some(bytes) => {
                        if ConfigRecord::decode(&bytes)
                            .map_err(|_| AgentRaftLedgerError::CorruptLedger)?
                            != expected
                        {
                            return Err(AgentRaftLedgerError::ConfigurationMismatch);
                        }
                    }
                    None => {
                        table.insert(route_key.as_slice(), expected.encode().as_slice())?;
                    }
                }
            }
            {
                let mut table = transaction.open_table(APPLY_META_TABLE)?;
                if table.get(route_key.as_slice())?.is_none() {
                    table.insert(
                        route_key.as_slice(),
                        AgentRaftApplyMeta::post_genesis(route).encode().as_slice(),
                    )?;
                }
            }
            // Opening all tables in the initialization transaction pins their
            // schemas before any later pledge or share can be written.
            {
                let _ = transaction.open_table(ANCHOR_TABLE)?;
            }
            {
                let _ = transaction.open_table(RESERVATION_TABLE)?;
            }
            {
                let _ = transaction.open_table(PLEDGE_TABLE)?;
            }
            {
                let _ = transaction.open_table(SHARE_TABLE)?;
            }
            {
                let _ = transaction.open_table(QC_TABLE)?;
            }
            {
                let _ = transaction.open_table(FAIL_STOP_TABLE)?;
            }
            transaction.commit()?;

            let ledger = Self {
                database,
                route,
                committee,
                local_node,
                journal_store,
                writes: std::sync::Mutex::new(()),
            };
            ledger.audit_recovery()?;
            Ok(ledger)
        }

        pub(crate) const fn route(&self) -> AgentRouteKey {
            self.route
        }

        pub(crate) const fn committee(&self) -> &AgentReplicaCommittee {
            &self.committee
        }

        pub(crate) const fn local_node(&self) -> NodeId {
            self.local_node
        }

        pub(crate) const fn journal_store(&self) -> JournalStoreInstanceId {
            self.journal_store
        }

        pub(crate) fn apply_meta(&self) -> Result<AgentRaftApplyMeta, AgentRaftLedgerError> {
            let key = route_storage_key(self.route);
            let bytes = read_exact(&self.database, APPLY_META_TABLE, key.as_slice())?
                .ok_or(AgentRaftLedgerError::CorruptLedger)?;
            let meta = AgentRaftApplyMeta::decode(&bytes)
                .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            if meta.route != self.route {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }
            Ok(meta)
        }

        pub(crate) fn is_fail_stopped(&self) -> Result<bool, AgentRaftLedgerError> {
            let key = route_storage_key(self.route);
            Ok(read_exact(&self.database, FAIL_STOP_TABLE, key.as_slice())?.is_some())
        }

        /// Durably reserve the one next Ordered slot before replay is allowed
        /// to perform its journal CAS. Exact reopen/retry returns the same
        /// opaque authority; a different slot under the same pending route
        /// permanently fail-stops new work. Because a returned authority may
        /// already have crossed the journal CAS, the exact originally stored
        /// reservation remains drainable into one anchor after fail-stop.
        pub(crate) fn reserve_ordered_application(
            &self,
            committed: &CommittedAgentRaftEntry,
        ) -> Result<ReservedAgentRaftApplication, AgentRaftLedgerError> {
            if committed.route() != self.route {
                return Err(AgentRaftLedgerError::WrongRoute);
            }
            match committed.command() {
                AgentRaftCommand::Ordered {
                    artifact_batch: None,
                    ..
                } => {}
                AgentRaftCommand::Ordered {
                    artifact_batch: Some(_),
                    ..
                } => return Err(AgentRaftLedgerError::ArtifactBatchReceiptRequired),
                _ => return Err(AgentRaftLedgerError::OrderedClaimRequired),
            }
            let _write = self
                .writes
                .lock()
                .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            let route_key = route_storage_key(self.route);
            let expected = ReservationRecord::from_committed(committed, self.journal_store)?;
            let transaction = self.database.begin_write()?;
            let fail_stopped = {
                let table = transaction.open_table(FAIL_STOP_TABLE)?;
                table.get(route_key.as_slice())?.is_some()
            };
            let existing = {
                let table = transaction.open_table(RESERVATION_TABLE)?;
                table
                    .get(route_key.as_slice())?
                    .map(|value| value.value().to_vec())
            }
            .map(|bytes| {
                ReservationRecord::decode(&bytes).map_err(|_| AgentRaftLedgerError::CorruptLedger)
            })
            .transpose()?;
            if fail_stopped && existing.as_ref().is_none_or(|stored| stored != &expected) {
                return Err(AgentRaftLedgerError::FailStopped);
            }
            let current = {
                let table = transaction.open_table(APPLY_META_TABLE)?;
                let bytes = table
                    .get(route_key.as_slice())?
                    .map(|value| value.value().to_vec())
                    .ok_or(AgentRaftLedgerError::CorruptLedger)?;
                AgentRaftApplyMeta::decode(&bytes)
                    .map_err(|_| AgentRaftLedgerError::CorruptLedger)?
            };
            if current.route != self.route {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }

            if committed.index() <= current.applied_index {
                return Err(AgentRaftLedgerError::AppliedConflict);
            }
            if committed.index() != current.applied_index.saturating_add(1)
                || (current.applied_index != 0 && committed.term() < current.applied_term)
            {
                return Err(AgentRaftLedgerError::ApplyGap);
            }

            if let Some(existing) = existing {
                if existing == expected {
                    return Ok(ReservedAgentRaftApplication {
                        committed: committed.clone(),
                        local_node: self.local_node,
                        journal_store: self.journal_store,
                    });
                }
                let fail_stop = FailStopRecord {
                    route: self.route,
                    index: committed.index(),
                    expected: existing.commitment(),
                    observed: expected.commitment(),
                };
                fail_stop.validate()?;
                {
                    let mut table = transaction.open_table(FAIL_STOP_TABLE)?;
                    if table.get(route_key.as_slice())?.is_none() {
                        table.insert(route_key.as_slice(), fail_stop.encode().as_slice())?;
                    }
                }
                transaction.commit()?;
                return Err(AgentRaftLedgerError::DivergentReservation);
            }

            {
                let table = transaction.open_table(ANCHOR_TABLE)?;
                let prefix = route_storage_key(self.route);
                let mut count = 0_usize;
                for row in table.range(prefix.as_slice()..)? {
                    let (key, _) = row?;
                    if !key.value().starts_with(prefix.as_slice()) {
                        break;
                    }
                    if count == MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES {
                        return Err(AgentRaftLedgerError::BacklogLimit);
                    }
                    count += 1;
                }
                if count == MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES {
                    return Err(AgentRaftLedgerError::BacklogLimit);
                }
            }
            {
                let mut table = transaction.open_table(RESERVATION_TABLE)?;
                table.insert(route_key.as_slice(), expected.encode().as_slice())?;
            }
            transaction.commit()?;
            Ok(ReservedAgentRaftApplication {
                committed: committed.clone(),
                local_node: self.local_node,
                journal_store: self.journal_store,
            })
        }

        /// Read the exact post-CAS anchor for an application which already
        /// completed. This recovery value is intentionally not a reservation
        /// and cannot authorize another replay publication.
        pub(crate) fn recover_applied_ordered(
            &self,
            committed: &CommittedAgentRaftEntry,
        ) -> Result<Option<AnchoredAgentRaftApplication>, AgentRaftLedgerError> {
            if committed.route() != self.route {
                return Err(AgentRaftLedgerError::WrongRoute);
            }
            let entry = match committed.command() {
                AgentRaftCommand::Ordered {
                    artifact_batch: None,
                    entry,
                    ..
                } => entry,
                AgentRaftCommand::Ordered {
                    artifact_batch: Some(_),
                    ..
                } => return Err(AgentRaftLedgerError::ArtifactBatchReceiptRequired),
                _ => return Err(AgentRaftLedgerError::OrderedClaimRequired),
            };
            let Some(anchor) = self.anchor(committed.index())? else {
                return Ok(None);
            };
            validate_claim_link(self.route, committed, &anchor.claim)?;
            if anchor.journal_store != self.journal_store
                || anchor.term != committed.term()
                || anchor.payload != committed.payload_commitment()
                || anchor.claim.ordered().head != Some(entry.id())
            {
                return Err(AgentRaftLedgerError::AppliedConflict);
            }
            Ok(Some(AnchoredAgentRaftApplication {
                route: anchor.route,
                index: anchor.index,
                term: anchor.term,
                payload: anchor.payload,
                journal_store: anchor.journal_store,
                entry: entry.id(),
                claim: anchor.claim,
                successor: anchor.successor,
            }))
        }

        // Artifact dispositions remain canonical audit wires, but this first
        // slice intentionally exposes no method that can mint one from a Raft
        // command alone. A later artifact-store adapter must supply an opaque
        // successful-publication receipt before advancing `applied` for a
        // chunk or abort.

        /// Anchor only the exact claim carried by replay's opaque successful
        /// Shared-publication receipt. A raw claim cannot cross this boundary.
        pub(crate) fn anchor_applied_ordered(
            &self,
            published: PublishedSharedOrdered,
        ) -> Result<AgentRaftApplyMeta, AgentRaftLedgerError> {
            let reserved = published.reservation();
            if published.journal_store() != self.journal_store
                || reserved.journal_store() != self.journal_store
                || published.journal_store() != reserved.journal_store()
            {
                return Err(AgentRaftLedgerError::WrongJournalStore);
            }
            let committed = reserved.committed();
            let claim = published.claim();
            validate_claim_link(self.route, committed, claim)?;
            let entry = match committed.command() {
                AgentRaftCommand::Ordered { entry, .. } => entry,
                _ => return Err(AgentRaftLedgerError::InvalidClaim),
            };
            if published.entry() != entry.id()
                || published.raft_index() != committed.index()
                || published.raft_term() != committed.term()
                || published.raft_payload_commitment() != committed.payload_commitment()
            {
                return Err(AgentRaftLedgerError::InvalidClaim);
            }
            self.anchor_validated_ordered(reserved, claim, entry, published.successor())
        }

        #[cfg(test)]
        pub(super) fn anchor_applied_ordered_for_test(
            &self,
            reserved: ReservedAgentRaftApplication,
            claim: &OrderedCommitClaim,
            successor: JournalHeadsId,
        ) -> Result<AgentRaftApplyMeta, AgentRaftLedgerError> {
            let committed = reserved.committed();
            validate_claim_link(self.route, committed, claim)?;
            let entry = match committed.command() {
                AgentRaftCommand::Ordered { entry, .. } => entry,
                _ => return Err(AgentRaftLedgerError::InvalidClaim),
            };
            self.anchor_validated_ordered(&reserved, claim, entry, successor)
        }

        #[cfg(test)]
        pub(super) fn delete_anchor_for_test(
            &self,
            index: u64,
        ) -> Result<(), AgentRaftLedgerError> {
            let transaction = self.database.begin_write()?;
            {
                let mut table = transaction.open_table(ANCHOR_TABLE)?;
                table.remove(entry_storage_key(self.route, index).as_slice())?;
            }
            transaction.commit()?;
            Ok(())
        }

        fn anchor_validated_ordered(
            &self,
            reserved: &ReservedAgentRaftApplication,
            claim: &OrderedCommitClaim,
            entry: &OrderedEntry,
            successor: JournalHeadsId,
        ) -> Result<AgentRaftApplyMeta, AgentRaftLedgerError> {
            let disposition = AgentRaftAuditDisposition::OrderedApplied {
                entry: entry.id(),
                claim: claim.commitment(),
                successor,
            };
            self.record_apply(reserved, disposition, claim)
        }

        fn record_apply(
            &self,
            reserved: &ReservedAgentRaftApplication,
            disposition: AgentRaftAuditDisposition,
            claim: &OrderedCommitClaim,
        ) -> Result<AgentRaftApplyMeta, AgentRaftLedgerError> {
            let committed = reserved.committed();
            if committed.route() != self.route || reserved.local_node() != self.local_node {
                return Err(AgentRaftLedgerError::WrongRoute);
            }
            if reserved.journal_store() != self.journal_store {
                return Err(AgentRaftLedgerError::WrongJournalStore);
            }
            // A durable reservation is irrevocably admitted: its authority
            // may already have crossed the separate journal CAS before a
            // later conflict records fail-stop. Drain only that exact stored
            // reservation so journal and evidence cursors cannot split.
            // Fail-stop still gates every new reserve, pledge, share, and QC.
            let _write = self
                .writes
                .lock()
                .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            let current = self.apply_meta()?;
            if committed.index <= current.applied_index {
                return Err(AgentRaftLedgerError::AppliedConflict);
            }
            let next = current.advance_applied(committed, disposition)?;

            let route_key = route_storage_key(self.route);
            let entry_key = entry_storage_key(self.route, committed.index);
            let expected_reservation =
                ReservationRecord::from_committed(committed, self.journal_store)?;
            let transaction = self.database.begin_write()?;
            {
                let table = transaction.open_table(RESERVATION_TABLE)?;
                let bytes = table
                    .get(route_key.as_slice())?
                    .map(|value| value.value().to_vec())
                    .ok_or(AgentRaftLedgerError::CorruptLedger)?;
                let stored = ReservationRecord::decode(&bytes)
                    .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                if stored != expected_reservation {
                    return Err(AgentRaftLedgerError::DivergentReservation);
                }
            }
            {
                let mut table = transaction.open_table(APPLY_META_TABLE)?;
                let stored = table
                    .get(route_key.as_slice())?
                    .map(|value| value.value().to_vec())
                    .ok_or(AgentRaftLedgerError::CorruptLedger)?;
                let stored = AgentRaftApplyMeta::decode(&stored)
                    .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                if stored != current {
                    return Err(AgentRaftLedgerError::AppliedConflict);
                }
                table.insert(route_key.as_slice(), next.encode().as_slice())?;
            }
            let anchor = AnchorRecord {
                route: self.route,
                index: committed.index,
                term: committed.term,
                payload: committed.payload_commitment,
                journal_store: self.journal_store,
                successor: match disposition {
                    AgentRaftAuditDisposition::OrderedApplied { successor, .. } => successor,
                    _ => return Err(AgentRaftLedgerError::InvalidClaim),
                },
                claim: claim.clone(),
            };
            anchor.validate()?;
            {
                let mut table = transaction.open_table(ANCHOR_TABLE)?;
                if let Some(existing) = table
                    .get(entry_key.as_slice())?
                    .map(|value| value.value().to_vec())
                {
                    let existing = AnchorRecord::decode(&existing)
                        .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                    if existing != anchor {
                        return Err(AgentRaftLedgerError::DivergentClaim);
                    }
                } else {
                    table.insert(entry_key.as_slice(), anchor.encode().as_slice())?;
                }
            }
            {
                let mut table = transaction.open_table(RESERVATION_TABLE)?;
                if table.remove(route_key.as_slice())?.is_none() {
                    return Err(AgentRaftLedgerError::CorruptLedger);
                }
            }
            transaction.commit()?;
            Ok(next)
        }

        /// Sign the exact anchored claim. The signer callback cannot run until
        /// the pledge transaction below has successfully committed.
        pub(crate) fn sign_local<S: ReplicaCommitSigner>(
            &self,
            claim: &OrderedCommitClaim,
            signer: &S,
        ) -> Result<AgentRaftShareOutcome, AgentRaftSignError<S::Error>> {
            if self
                .committee
                .member_by_node(self.local_node)
                .is_none_or(|member| member.replica().role != ReplicaRole::Voter)
            {
                return Err(AgentRaftLedgerError::LocalReplicaNotVoter.into());
            }
            if signer.node() != self.local_node {
                return Err(AgentRaftLedgerError::UnknownSigner.into());
            }
            self.ensure_anchored(claim)?;
            if let Some(share) = self.share(claim.raft_index(), self.local_node)? {
                if self.pledged_claim(claim.raft_index())? != Some(claim.commitment()) {
                    return Err(AgentRaftLedgerError::CorruptLedger.into());
                }
                return Ok(AgentRaftShareOutcome {
                    share,
                    certificate: self.certificate(claim.raft_index())?,
                });
            }

            self.ensure_pledge(claim)?;
            // There is deliberately no fallible storage work between the
            // committed pledge above and this first signer invocation.
            let message =
                ReplicaQuorumCertificate::signing_message(claim.committee(), claim.commitment());
            let bytes = signer
                .sign_commit_message(message)
                .map_err(AgentRaftSignError::Signer)?;
            let share = ReplicaCommitSignature::new(self.local_node, bytes)
                .map_err(AgentRaftLedgerError::SharedCommit)?;
            validate_share(&self.committee, claim, &share)?;
            self.record_share(claim, share).map_err(Into::into)
        }

        /// Validate and durably retain one remote voter share. Shares are not
        /// accepted ahead of local apply; this keeps the total backlog bounded
        /// and prevents a remote claim from creating local certification state
        /// before its exact journal projection exists.
        pub(crate) fn record_remote_share(
            &self,
            claim: &OrderedCommitClaim,
            share: ReplicaCommitSignature,
        ) -> Result<AgentRaftShareOutcome, AgentRaftLedgerError> {
            if share.signer() == self.local_node {
                return Err(AgentRaftLedgerError::LocalShareRequiresPledge);
            }
            self.ensure_anchored(claim)?;
            validate_share(&self.committee, claim, &share)?;
            self.record_share(claim, share)
        }

        pub(crate) fn pledged_claim(
            &self,
            index: u64,
        ) -> Result<Option<Hash>, AgentRaftLedgerError> {
            Ok(self.pledge(index)?.map(|pledge| pledge.claim.commitment()))
        }

        pub(crate) fn certificate(
            &self,
            index: u64,
        ) -> Result<Option<ReplicaQuorumCertificate>, AgentRaftLedgerError> {
            let key = entry_storage_key(self.route, index);
            let Some(bytes) = read_exact(&self.database, QC_TABLE, key.as_slice())? else {
                return Ok(None);
            };
            let certificate = ReplicaQuorumCertificate::decode(&bytes)
                .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            let anchor = self
                .anchor(index)?
                .ok_or(AgentRaftLedgerError::CorruptLedger)?;
            certificate.verify(&self.committee, &anchor.claim)?;
            Ok(Some(certificate))
        }

        fn ensure_operational(&self) -> Result<(), AgentRaftLedgerError> {
            if self.is_fail_stopped()? {
                Err(AgentRaftLedgerError::FailStopped)
            } else {
                Ok(())
            }
        }

        fn ensure_anchored(&self, claim: &OrderedCommitClaim) -> Result<(), AgentRaftLedgerError> {
            self.ensure_operational()?;
            if AgentRouteKey::from_claim(claim).map_err(AgentRaftLedgerError::Wire)? != self.route {
                return Err(AgentRaftLedgerError::WrongRoute);
            }
            let Some(anchor) = self.anchor(claim.raft_index())? else {
                return Err(AgentRaftLedgerError::ClaimNotAnchored);
            };
            if anchor.claim != *claim {
                self.persist_fail_stop(
                    claim.raft_index(),
                    anchor.claim.commitment(),
                    claim.commitment(),
                )?;
                return Err(AgentRaftLedgerError::DivergentClaim);
            }
            Ok(())
        }

        fn ensure_pledge(&self, claim: &OrderedCommitClaim) -> Result<(), AgentRaftLedgerError> {
            self.ensure_operational()?;
            let _write = self
                .writes
                .lock()
                .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            if let Some(existing) = self.pledge(claim.raft_index())? {
                if existing.claim == *claim {
                    return Ok(());
                }
                drop(_write);
                self.persist_fail_stop(
                    claim.raft_index(),
                    existing.claim.commitment(),
                    claim.commitment(),
                )?;
                return Err(AgentRaftLedgerError::DivergentClaim);
            }
            let pledge = PledgeRecord {
                route: self.route,
                index: claim.raft_index(),
                claim: claim.clone(),
            };
            pledge.validate()?;
            let key = entry_storage_key(self.route, claim.raft_index());
            let transaction = self.database.begin_write()?;
            {
                let table = transaction.open_table(FAIL_STOP_TABLE)?;
                if table
                    .get(route_storage_key(self.route).as_slice())?
                    .is_some()
                {
                    return Err(AgentRaftLedgerError::FailStopped);
                }
            }
            {
                let mut table = transaction.open_table(PLEDGE_TABLE)?;
                if let Some(existing) = table
                    .get(key.as_slice())?
                    .map(|value| value.value().to_vec())
                {
                    let existing = PledgeRecord::decode(&existing)
                        .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                    if existing != pledge {
                        return Err(AgentRaftLedgerError::DivergentClaim);
                    }
                } else {
                    table.insert(key.as_slice(), pledge.encode().as_slice())?;
                }
            }
            transaction.commit()?;
            Ok(())
        }

        fn record_share(
            &self,
            claim: &OrderedCommitClaim,
            share: ReplicaCommitSignature,
        ) -> Result<AgentRaftShareOutcome, AgentRaftLedgerError> {
            self.ensure_operational()?;
            self.ensure_anchored(claim)?;
            if share.signer() == self.local_node
                && self.pledged_claim(claim.raft_index())? != Some(claim.commitment())
            {
                return Err(AgentRaftLedgerError::LocalShareRequiresPledge);
            }
            validate_share(&self.committee, claim, &share)?;
            let _write = self
                .writes
                .lock()
                .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            let key = share_storage_key(self.route, claim.raft_index(), share.signer());
            let record = ShareRecord {
                route: self.route,
                index: claim.raft_index(),
                claim: claim.commitment(),
                share: share.clone(),
            };
            record.validate()?;

            let route_key = route_storage_key(self.route);
            let transaction = self.database.begin_write()?;
            {
                let table = transaction.open_table(FAIL_STOP_TABLE)?;
                if table.get(route_key.as_slice())?.is_some() {
                    return Err(AgentRaftLedgerError::FailStopped);
                }
            }
            let mut shares = Vec::new();
            {
                let mut table = transaction.open_table(SHARE_TABLE)?;
                if let Some(existing) = table
                    .get(key.as_slice())?
                    .map(|value| value.value().to_vec())
                {
                    let existing = ShareRecord::decode(&existing)
                        .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                    if existing != record {
                        return Err(AgentRaftLedgerError::AppliedConflict);
                    }
                } else {
                    table.insert(key.as_slice(), record.encode().as_slice())?;
                }
                let prefix = entry_storage_key(self.route, claim.raft_index());
                for row in table.range(prefix.as_slice()..)? {
                    let (row_key, row_value) = row?;
                    if !row_key.value().starts_with(prefix.as_slice()) {
                        break;
                    }
                    let record = ShareRecord::decode(row_value.value())
                        .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                    if record.route != self.route
                        || record.index != claim.raft_index()
                        || record.claim != claim.commitment()
                    {
                        return Err(AgentRaftLedgerError::CorruptLedger);
                    }
                    validate_share(&self.committee, claim, &record.share)?;
                    if shares.len() == MAX_AGENT_REPLICAS {
                        return Err(AgentRaftLedgerError::BacklogLimit);
                    }
                    shares.push(record.share);
                }
            }
            if shares.len() > MAX_AGENT_REPLICAS {
                return Err(AgentRaftLedgerError::BacklogLimit);
            }
            shares.sort_by_key(ReplicaCommitSignature::signer);
            if shares
                .windows(2)
                .any(|pair| pair[0].signer() >= pair[1].signer())
            {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }

            let certificate_key = entry_storage_key(self.route, claim.raft_index());
            let existing_certificate = {
                let table = transaction.open_table(QC_TABLE)?;
                table
                    .get(certificate_key.as_slice())?
                    .map(|value| value.value().to_vec())
            };
            let certificate = if let Some(bytes) = existing_certificate {
                let existing = ReplicaQuorumCertificate::decode(&bytes)
                    .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                if existing.claim() != claim {
                    return Err(AgentRaftLedgerError::ConflictingCertificate);
                }
                existing.verify(&self.committee, claim)?;
                Some(existing)
            } else if shares.len() >= self.committee.quorum_threshold() {
                let certificate = ReplicaQuorumCertificate::new(claim.clone(), shares)?;
                certificate.verify(&self.committee, claim)?;
                {
                    let mut table = transaction.open_table(QC_TABLE)?;
                    table.insert(certificate_key.as_slice(), certificate.encode().as_slice())?;
                }
                Some(certificate)
            } else {
                None
            };
            if let Some(certificate) = &certificate {
                {
                    let mut table = transaction.open_table(APPLY_META_TABLE)?;
                    let bytes = table
                        .get(route_key.as_slice())?
                        .map(|value| value.value().to_vec())
                        .ok_or(AgentRaftLedgerError::CorruptLedger)?;
                    let meta = AgentRaftApplyMeta::decode(&bytes)
                        .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                    let next = meta.advance_compact_safe(claim, certificate.commitment())?;
                    table.insert(route_key.as_slice(), next.encode().as_slice())?;
                }
            }
            transaction.commit()?;
            Ok(AgentRaftShareOutcome { share, certificate })
        }

        fn anchor(&self, index: u64) -> Result<Option<AnchorRecord>, AgentRaftLedgerError> {
            let key = entry_storage_key(self.route, index);
            let Some(bytes) = read_exact(&self.database, ANCHOR_TABLE, key.as_slice())? else {
                return Ok(None);
            };
            let record =
                AnchorRecord::decode(&bytes).map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            if record.route != self.route
                || record.index != index
                || record.journal_store != self.journal_store
            {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }
            Ok(Some(record))
        }

        fn pledge(&self, index: u64) -> Result<Option<PledgeRecord>, AgentRaftLedgerError> {
            let key = entry_storage_key(self.route, index);
            let Some(bytes) = read_exact(&self.database, PLEDGE_TABLE, key.as_slice())? else {
                return Ok(None);
            };
            let record =
                PledgeRecord::decode(&bytes).map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            if record.route != self.route || record.index != index {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }
            Ok(Some(record))
        }

        fn share(
            &self,
            index: u64,
            signer: NodeId,
        ) -> Result<Option<ReplicaCommitSignature>, AgentRaftLedgerError> {
            let key = share_storage_key(self.route, index, signer);
            let Some(bytes) = read_exact(&self.database, SHARE_TABLE, key.as_slice())? else {
                return Ok(None);
            };
            let record =
                ShareRecord::decode(&bytes).map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            if record.route != self.route
                || record.index != index
                || record.share.signer() != signer
            {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }
            Ok(Some(record.share))
        }

        fn persist_fail_stop(
            &self,
            index: u64,
            expected: Hash,
            observed: Hash,
        ) -> Result<(), AgentRaftLedgerError> {
            if index == 0
                || expected == Hash::ZERO
                || observed == Hash::ZERO
                || expected == observed
            {
                return Err(AgentRaftLedgerError::AppliedConflict);
            }
            let _write = self
                .writes
                .lock()
                .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            let record = FailStopRecord {
                route: self.route,
                index,
                expected,
                observed,
            };
            record.validate()?;
            let key = route_storage_key(self.route);
            let transaction = self.database.begin_write()?;
            {
                let mut table = transaction.open_table(FAIL_STOP_TABLE)?;
                if table.get(key.as_slice())?.is_none() {
                    table.insert(key.as_slice(), record.encode().as_slice())?;
                }
            }
            transaction.commit()?;
            Ok(())
        }

        fn audit_recovery(&self) -> Result<(), AgentRaftLedgerError> {
            let route_key = route_storage_key(self.route);
            let config = read_exact(&self.database, CONFIG_TABLE, route_key.as_slice())?
                .ok_or(AgentRaftLedgerError::CorruptLedger)?;
            let config =
                ConfigRecord::decode(&config).map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            if config.route != self.route
                || config.committee != self.committee
                || config.local_node != self.local_node
                || config.journal_store != self.journal_store
            {
                return Err(AgentRaftLedgerError::ConfigurationMismatch);
            }
            let meta = self.apply_meta()?;

            let anchor_rows = rows_for_route_bounded(
                &self.database,
                ANCHOR_TABLE,
                self.route,
                MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES,
            )?;
            let mut anchors = BTreeMap::new();
            for (key, value) in anchor_rows {
                let anchor = AnchorRecord::decode(&value)
                    .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                if key != entry_storage_key(self.route, anchor.index)
                    || anchor.route != self.route
                    || anchor.journal_store != self.journal_store
                    || anchor.index > meta.applied_index
                    || anchors.insert(anchor.index, anchor).is_some()
                {
                    return Err(AgentRaftLedgerError::CorruptLedger);
                }
            }
            if meta.applied_index > MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES as u64
                || anchors.len() != meta.applied_index as usize
                || (1..=meta.applied_index).any(|index| !anchors.contains_key(&index))
            {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }
            if let Some(AgentRaftAuditDisposition::OrderedApplied {
                entry,
                claim,
                successor,
            }) = meta.disposition
            {
                let anchor = anchors
                    .get(&meta.applied_index)
                    .ok_or(AgentRaftLedgerError::CorruptLedger)?;
                if anchor.term != meta.applied_term
                    || anchor.payload != meta.applied_payload
                    || anchor.claim.ordered().head != Some(entry)
                    || anchor.claim.commitment() != claim
                    || anchor.successor != successor
                {
                    return Err(AgentRaftLedgerError::CorruptLedger);
                }
            }

            let reservation_rows =
                rows_for_route_bounded(&self.database, RESERVATION_TABLE, self.route, 1)?;
            if let Some((key, value)) = reservation_rows.into_iter().next() {
                let reservation = ReservationRecord::decode(&value)
                    .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                if key != route_key
                    || reservation.route != self.route
                    || reservation.journal_store != self.journal_store
                    || reservation.index != meta.applied_index.saturating_add(1)
                    || (meta.applied_index != 0 && reservation.term < meta.applied_term)
                    || anchors.contains_key(&reservation.index)
                    || anchors.len() == MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES
                {
                    return Err(AgentRaftLedgerError::CorruptLedger);
                }
            }

            let mut pledges = BTreeMap::new();
            for (key, value) in rows_for_route_bounded(
                &self.database,
                PLEDGE_TABLE,
                self.route,
                MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES,
            )? {
                let pledge = PledgeRecord::decode(&value)
                    .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                if key != entry_storage_key(self.route, pledge.index)
                    || anchors
                        .get(&pledge.index)
                        .is_none_or(|anchor| anchor.claim != pledge.claim)
                    || pledges.insert(pledge.index, pledge).is_some()
                {
                    return Err(AgentRaftLedgerError::CorruptLedger);
                }
            }

            let share_rows = rows_for_route_bounded(
                &self.database,
                SHARE_TABLE,
                self.route,
                MAX_AGENT_RAFT_SHARE_BACKLOG,
            )?;
            for (key, value) in share_rows {
                let share =
                    ShareRecord::decode(&value).map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                let Some(anchor) = anchors.get(&share.index) else {
                    return Err(AgentRaftLedgerError::CorruptLedger);
                };
                if key != share_storage_key(self.route, share.index, share.share.signer())
                    || share.route != self.route
                    || share.claim != anchor.claim.commitment()
                    || (share.share.signer() == self.local_node
                        && pledges
                            .get(&share.index)
                            .is_none_or(|pledge| pledge.claim != anchor.claim))
                {
                    return Err(AgentRaftLedgerError::CorruptLedger);
                }
                validate_share(&self.committee, &anchor.claim, &share.share)?;
            }

            let mut certificates = BTreeMap::new();
            for (key, value) in rows_for_route_bounded(
                &self.database,
                QC_TABLE,
                self.route,
                MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES,
            )? {
                let certificate = ReplicaQuorumCertificate::decode(&value)
                    .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                let index = certificate.claim().raft_index();
                let Some(anchor) = anchors.get(&index) else {
                    return Err(AgentRaftLedgerError::CorruptLedger);
                };
                if key != entry_storage_key(self.route, index)
                    || certificate.claim() != &anchor.claim
                    || certificates.insert(index, certificate.clone()).is_some()
                {
                    return Err(AgentRaftLedgerError::CorruptLedger);
                }
                certificate.verify(&self.committee, &anchor.claim)?;
            }
            match certificates.last_key_value() {
                Some((&index, certificate))
                    if meta.compact_safe_index == index
                        && meta.compact_safe_term == certificate.claim().raft_term()
                        && meta.compact_safe_qc == Some(certificate.commitment()) => {}
                None if meta.compact_safe_index == 0
                    && meta.compact_safe_term == 0
                    && meta.compact_safe_qc.is_none() => {}
                _ => return Err(AgentRaftLedgerError::CorruptLedger),
            }

            if let Some(bytes) = read_exact(&self.database, FAIL_STOP_TABLE, route_key.as_slice())?
            {
                let record = FailStopRecord::decode(&bytes)
                    .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                if record.route != self.route {
                    return Err(AgentRaftLedgerError::CorruptLedger);
                }
            }
            Ok(())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ConfigRecord {
        version: u32,
        route: AgentRouteKey,
        committee: AgentReplicaCommittee,
        local_node: NodeId,
        journal_store: JournalStoreInstanceId,
    }

    impl ConfigRecord {
        fn validate(&self) -> Result<(), AgentRaftLedgerError> {
            if self.version != LEDGER_SCHEMA_VERSION {
                return Err(AgentRaftLedgerError::ConfigurationMismatch);
            }
            validate_configuration(self.route, &self.committee, self.local_node)?;
            if JournalStoreInstanceId::from_bytes(*self.journal_store.as_bytes()).is_none()
                || self.encode().len() > MAX_CONFIG_RECORD_BYTES
            {
                return Err(AgentRaftLedgerError::BacklogLimit);
            }
            Ok(())
        }
    }

    impl ServiceWire for ConfigRecord {
        const MAGIC: [u8; 4] = *b"AGCF";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encoder.u32(self.version);
            encode_route(&mut encoder, self.route);
            encoder.bytes(&self.committee.encode());
            encoder.fixed(&self.local_node.0);
            encoder.fixed(self.journal_store.as_bytes());
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_CONFIG_RECORD_BYTES)?;
            let record = Self {
                version: decoder.u32()?,
                route: decode_route(decoder)?,
                committee: decode_nested::<AgentReplicaCommittee>(
                    decoder,
                    MAX_AGENT_REPLICA_COMMITTEE_BYTES,
                )?,
                local_node: NodeId(decoder.fixed()?),
                journal_store: JournalStoreInstanceId::from_bytes(decoder.fixed()?)
                    .ok_or(DecodeError::NonCanonical)?,
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ReservationRecord {
        route: AgentRouteKey,
        index: u64,
        term: u64,
        payload: Hash,
        journal_store: JournalStoreInstanceId,
    }

    impl ReservationRecord {
        fn from_committed(
            committed: &CommittedAgentRaftEntry,
            journal_store: JournalStoreInstanceId,
        ) -> Result<Self, AgentRaftLedgerError> {
            match committed.command() {
                AgentRaftCommand::Ordered {
                    artifact_batch: None,
                    ..
                } => {}
                AgentRaftCommand::Ordered {
                    artifact_batch: Some(_),
                    ..
                } => return Err(AgentRaftLedgerError::ArtifactBatchReceiptRequired),
                _ => return Err(AgentRaftLedgerError::OrderedClaimRequired),
            }
            let record = Self {
                route: committed.route(),
                index: committed.index(),
                term: committed.term(),
                payload: committed.payload_commitment(),
                journal_store,
            };
            record.validate()?;
            Ok(record)
        }

        fn commitment(&self) -> Hash {
            Hash::digest(AGENT_RAFT_APPLY_RESERVATION_DOMAIN, &[&self.encode()])
        }

        fn validate(&self) -> Result<(), AgentRaftLedgerError> {
            self.route.validate()?;
            if self.index == 0
                || self.term == 0
                || self.payload == Hash::ZERO
                || JournalStoreInstanceId::from_bytes(*self.journal_store.as_bytes()).is_none()
                || self.encode().len() > MAX_RESERVATION_RECORD_BYTES
            {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }
            Ok(())
        }
    }

    impl ServiceWire for ReservationRecord {
        const MAGIC: [u8; 4] = *b"AGRV";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encode_route(&mut encoder, self.route);
            encoder.u64(self.index);
            encoder.u64(self.term);
            encoder.fixed(&self.payload.0);
            encoder.fixed(self.journal_store.as_bytes());
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_RESERVATION_RECORD_BYTES)?;
            let record = Self {
                route: decode_route(decoder)?,
                index: decoder.u64()?,
                term: decoder.u64()?,
                payload: Hash(decoder.fixed()?),
                journal_store: JournalStoreInstanceId::from_bytes(decoder.fixed()?)
                    .ok_or(DecodeError::NonCanonical)?,
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct AnchorRecord {
        route: AgentRouteKey,
        index: u64,
        term: u64,
        payload: Hash,
        journal_store: JournalStoreInstanceId,
        successor: JournalHeadsId,
        claim: OrderedCommitClaim,
    }

    impl AnchorRecord {
        fn validate(&self) -> Result<(), AgentRaftLedgerError> {
            self.claim.validate()?;
            if self.index == 0
                || self.term == 0
                || self.payload == Hash::ZERO
                || JournalStoreInstanceId::from_bytes(*self.journal_store.as_bytes()).is_none()
                || self.successor == JournalHeadsId::ZERO
                || self.index != self.claim.raft_index()
                || self.term != self.claim.raft_term()
                || AgentRouteKey::from_claim(&self.claim)? != self.route
                || self.encode().len() > MAX_ANCHOR_RECORD_BYTES
            {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }
            Ok(())
        }
    }

    impl ServiceWire for AnchorRecord {
        const MAGIC: [u8; 4] = *b"AGCA";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encode_route(&mut encoder, self.route);
            encoder.u64(self.index);
            encoder.u64(self.term);
            encoder.fixed(&self.payload.0);
            encoder.fixed(self.journal_store.as_bytes());
            encoder.fixed(self.successor.as_bytes());
            encoder.bytes(&self.claim.encode());
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_ANCHOR_RECORD_BYTES)?;
            let record = Self {
                route: decode_route(decoder)?,
                index: decoder.u64()?,
                term: decoder.u64()?,
                payload: Hash(decoder.fixed()?),
                journal_store: JournalStoreInstanceId::from_bytes(decoder.fixed()?)
                    .ok_or(DecodeError::NonCanonical)?,
                successor: JournalHeadsId(decoder.fixed()?),
                claim: decode_nested::<OrderedCommitClaim>(
                    decoder,
                    MAX_ORDERED_COMMIT_CLAIM_BYTES,
                )?,
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct PledgeRecord {
        route: AgentRouteKey,
        index: u64,
        claim: OrderedCommitClaim,
    }

    impl PledgeRecord {
        fn validate(&self) -> Result<(), AgentRaftLedgerError> {
            self.claim.validate()?;
            if self.index == 0
                || self.index != self.claim.raft_index()
                || AgentRouteKey::from_claim(&self.claim)? != self.route
                || self.encode().len() > MAX_PLEDGE_RECORD_BYTES
            {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }
            Ok(())
        }
    }

    impl ServiceWire for PledgeRecord {
        const MAGIC: [u8; 4] = *b"AGPL";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encode_route(&mut encoder, self.route);
            encoder.u64(self.index);
            encoder.bytes(&self.claim.encode());
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_PLEDGE_RECORD_BYTES)?;
            let record = Self {
                route: decode_route(decoder)?,
                index: decoder.u64()?,
                claim: decode_nested::<OrderedCommitClaim>(
                    decoder,
                    MAX_ORDERED_COMMIT_CLAIM_BYTES,
                )?,
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ShareRecord {
        route: AgentRouteKey,
        index: u64,
        claim: Hash,
        share: ReplicaCommitSignature,
    }

    impl ShareRecord {
        fn validate(&self) -> Result<(), AgentRaftLedgerError> {
            if self.index == 0
                || self.claim == Hash::ZERO
                || self.share.signer() == NodeId::ZERO
                || self.encode().len() > MAX_SHARE_RECORD_BYTES
            {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }
            self.route.validate()?;
            Ok(())
        }
    }

    impl ServiceWire for ShareRecord {
        const MAGIC: [u8; 4] = *b"AGSH";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encode_route(&mut encoder, self.route);
            encoder.u64(self.index);
            encoder.fixed(&self.claim.0);
            encoder.bytes(&self.share.encode());
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_SHARE_RECORD_BYTES)?;
            let record = Self {
                route: decode_route(decoder)?,
                index: decoder.u64()?,
                claim: Hash(decoder.fixed()?),
                share: decode_nested::<ReplicaCommitSignature>(
                    decoder,
                    MAX_REPLICA_COMMIT_SIGNATURE_BYTES,
                )?,
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct FailStopRecord {
        route: AgentRouteKey,
        index: u64,
        expected: Hash,
        observed: Hash,
    }

    impl FailStopRecord {
        fn validate(&self) -> Result<(), AgentRaftLedgerError> {
            self.route.validate()?;
            if self.index == 0
                || self.expected == Hash::ZERO
                || self.observed == Hash::ZERO
                || self.expected == self.observed
                || self.encode().len() > MAX_FAIL_STOP_RECORD_BYTES
            {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }
            Ok(())
        }
    }

    impl ServiceWire for FailStopRecord {
        const MAGIC: [u8; 4] = *b"AGFS";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encode_route(&mut encoder, self.route);
            encoder.u64(self.index);
            encoder.fixed(&self.expected.0);
            encoder.fixed(&self.observed.0);
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_FAIL_STOP_RECORD_BYTES)?;
            let record = Self {
                route: decode_route(decoder)?,
                index: decoder.u64()?,
                expected: Hash(decoder.fixed()?),
                observed: Hash(decoder.fixed()?),
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    fn validate_configuration(
        route: AgentRouteKey,
        committee: &AgentReplicaCommittee,
        local_node: NodeId,
    ) -> Result<(), AgentRaftLedgerError> {
        route.validate()?;
        committee
            .validate()
            .map_err(|_| AgentRaftLedgerError::InvalidCommittee)?;
        if committee.profile() != AgentProfile::Shared
            || committee.space() != route.space
            || committee.agent() != route.agent
            || committee.id() != route.committee
        {
            return Err(AgentRaftLedgerError::InvalidCommittee);
        }
        committee
            .member_by_node(local_node)
            .ok_or(AgentRaftLedgerError::LocalReplicaNotVoter)?;
        Ok(())
    }

    pub(super) fn validate_claim_link(
        route: AgentRouteKey,
        committed: &CommittedAgentRaftEntry,
        claim: &OrderedCommitClaim,
    ) -> Result<(), AgentRaftLedgerError> {
        claim.validate()?;
        if AgentRouteKey::from_claim(claim)? != route
            || committed.route() != route
            || committed.index != claim.raft_index()
            || committed.term != claim.raft_term()
        {
            return Err(AgentRaftLedgerError::InvalidClaim);
        }
        let entry = match committed.command() {
            AgentRaftCommand::Ordered {
                artifact_batch: None,
                entry,
                ..
            } => entry,
            AgentRaftCommand::Ordered {
                artifact_batch: Some(_),
                ..
            } => return Err(AgentRaftLedgerError::ArtifactBatchReceiptRequired),
            _ => return Err(AgentRaftLedgerError::InvalidClaim),
        };
        let expected = OrderedBase {
            index: entry.index,
            head: Some(entry.id()),
        };
        if claim.ordered() != expected || claim.merge_frontier() != entry.merge_frontier {
            return Err(AgentRaftLedgerError::InvalidClaim);
        }
        // The entry's seal describes this transition, while a claim retains
        // the most recent sealed projection across later ordinary Ordered
        // entries. Comparing `claim.merge_seal()` directly with the entry
        // therefore rejects every ordinary successor after a fence.
        let fence_linked = match entry.merge_seal {
            Some(seal) => {
                claim.merge_fence() == expected
                    && claim
                        .sealed_merge()
                        .is_some_and(|projection| projection.seal() == seal)
            }
            None => claim.merge_fence() != expected,
        };
        if !fence_linked {
            return Err(AgentRaftLedgerError::InvalidClaim);
        }
        Ok(())
    }

    fn validate_share(
        committee: &AgentReplicaCommittee,
        claim: &OrderedCommitClaim,
        share: &ReplicaCommitSignature,
    ) -> Result<(), AgentRaftLedgerError> {
        claim.validate()?;
        if claim.committee() != committee.id() {
            return Err(AgentRaftLedgerError::InvalidCommittee);
        }
        let member = committee
            .member_by_node(share.signer())
            .ok_or(AgentRaftLedgerError::UnknownSigner)?;
        if member.replica().role != ReplicaRole::Voter {
            return Err(AgentRaftLedgerError::ObserverSigner);
        }
        let key = VerifyingKey::from_bytes(member.ed25519_public_key())
            .map_err(|_| AgentRaftLedgerError::InvalidSignature)?;
        let signature = ed25519_dalek::Signature::from_slice(share.signature())
            .map_err(|_| AgentRaftLedgerError::InvalidSignature)?;
        let message =
            ReplicaQuorumCertificate::signing_message(claim.committee(), claim.commitment());
        key.verify_strict(&message.0, &signature)
            .map_err(|_| AgentRaftLedgerError::InvalidSignature)
    }

    fn route_storage_key(route: AgentRouteKey) -> [u8; ROUTE_STORAGE_KEY_BYTES] {
        let mut key = [0_u8; ROUTE_STORAGE_KEY_BYTES];
        key[0..32].copy_from_slice(&route.space.0);
        key[32..64].copy_from_slice(&route.agent.0);
        key[64..96].copy_from_slice(route.genesis.as_bytes());
        key[96..128].copy_from_slice(route.admission.as_bytes());
        key[128..160].copy_from_slice(route.committee.as_bytes());
        key
    }

    fn entry_storage_key(route: AgentRouteKey, index: u64) -> [u8; ENTRY_STORAGE_KEY_BYTES] {
        let mut key = [0_u8; ENTRY_STORAGE_KEY_BYTES];
        key[..ROUTE_STORAGE_KEY_BYTES].copy_from_slice(&route_storage_key(route));
        key[ROUTE_STORAGE_KEY_BYTES..].copy_from_slice(&index.to_be_bytes());
        key
    }

    fn share_storage_key(
        route: AgentRouteKey,
        index: u64,
        signer: NodeId,
    ) -> [u8; SHARE_STORAGE_KEY_BYTES] {
        let mut key = [0_u8; SHARE_STORAGE_KEY_BYTES];
        key[..ENTRY_STORAGE_KEY_BYTES].copy_from_slice(&entry_storage_key(route, index));
        key[ENTRY_STORAGE_KEY_BYTES..].copy_from_slice(&signer.0);
        key
    }

    fn read_exact(
        database: &Database,
        definition: TableDefinition<&[u8], &[u8]>,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, AgentRaftLedgerError> {
        let transaction = database.begin_read()?;
        let table = transaction.open_table(definition)?;
        Ok(table.get(key)?.map(|value| value.value().to_vec()))
    }

    fn rows_for_route_bounded(
        database: &Database,
        definition: TableDefinition<&[u8], &[u8]>,
        route: AgentRouteKey,
        maximum: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, AgentRaftLedgerError> {
        let prefix = route_storage_key(route);
        let transaction = database.begin_read()?;
        let table = transaction.open_table(definition)?;
        let mut rows = Vec::new();
        for row in table.range(prefix.as_slice()..)? {
            let (key, value) = row?;
            if !key.value().starts_with(prefix.as_slice()) {
                break;
            }
            if rows.len() == maximum {
                return Err(AgentRaftLedgerError::BacklogLimit);
            }
            rows.push((key.value().to_vec(), value.value().to_vec()));
        }
        Ok(rows)
    }

    macro_rules! backend_from {
        ($error:ty) => {
            impl From<$error> for AgentRaftLedgerError {
                fn from(error: $error) -> Self {
                    Self::Backend(alloc::boxed::Box::new(error))
                }
            }
        };
    }

    backend_from!(redb::DatabaseError);
    backend_from!(redb::TableError);
    backend_from!(redb::StorageError);
    backend_from!(redb::TransactionError);
    backend_from!(redb::CommitError);
}

#[cfg(all(feature = "std", feature = "storage"))]
#[allow(unused_imports)]
pub(crate) use evidence_ledger::{
    AgentRaftEvidenceLedger, AgentRaftShareOutcome, AgentRaftSignError, ReplicaCommitSigner,
};

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::Cell;

    use ed25519_dalek::{Signer as _, SigningKey};
    use redb::Database;

    use super::*;
    use crate::agent::authority::{
        ActorInvocationClaim, ActorInvocationReceipt, AgentAuthorityBinding,
        ED25519_SIGNATURE_BYTES, ed25519_public_key_wire,
    };
    use crate::agent::execution::{ActorInvocation, ActorInvocationAuth};
    use crate::agent::genesis::{AgentReplicaMember, derive_replica_raft_slot};
    use crate::agent::journal::{
        ArtifactClosureId, InvocationIndexId, LaneStateId, MergeFrontierId, MergeSealId,
        ReplayInput, ReplayOperation, RuntimeBinding,
    };
    use crate::agent::shared_commit::{
        MAX_REPLICA_QUORUM_CERTIFICATE_BYTES, SharedLaneProjection, SharedSealedMergeProjection,
    };
    use crate::agent::{AgentReplica, EXECUTION_SEMANTICS_ID, MethodMode, RUNTIME_ABI_ID};
    use crate::service::{ActorId, DeploymentId, InvocationId, PrincipalId, ProducerId, ProgramId};

    const PEER_ID_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn peer_id(key: &SigningKey) -> Vec<u8> {
        let mut peer = PEER_ID_PREFIX.to_vec();
        peer.extend_from_slice(&key.verifying_key().to_bytes());
        peer
    }

    fn member(key: &SigningKey, role: ReplicaRole) -> AgentReplicaMember {
        let peer = peer_id(key);
        let public_key = key.verifying_key().to_bytes();
        AgentReplicaMember::new(
            AgentReplica {
                node: NodeId::of_authenticated_peer(&peer),
                principal: PrincipalId::of_public_key(&public_key),
                role,
            },
            peer.clone(),
            public_key,
            (role == ReplicaRole::Voter).then(|| derive_replica_raft_slot(&peer)),
        )
        .unwrap()
    }

    fn committee(voters: &[SigningKey], observers: &[SigningKey]) -> AgentReplicaCommittee {
        let mut members = voters
            .iter()
            .map(|key| member(key, ReplicaRole::Voter))
            .chain(
                observers
                    .iter()
                    .map(|key| member(key, ReplicaRole::Observer)),
            )
            .collect::<Vec<_>>();
        members.sort_by_key(|member| member.replica().node);
        AgentReplicaCommittee::new(
            SpaceId([0x11; 32]),
            AgentId([0x22; 32]),
            AgentProfile::Shared,
            members,
        )
        .unwrap()
    }

    fn route(committee: &AgentReplicaCommittee) -> AgentRouteKey {
        AgentRouteKey::new(
            committee.space(),
            committee.agent(),
            AgentJournalGenesisId([0x33; 32]),
            AgentGenesisAdmissionId::from_bytes([0x34; 32]),
            committee.id(),
        )
        .unwrap()
    }

    fn runtime() -> RuntimeBinding {
        RuntimeBinding {
            space: SpaceId([0x11; 32]),
            agent: AgentId([0x22; 32]),
            deployment: DeploymentId([0x23; 32]),
            program: ProgramId([0x24; 32]),
            producer: ProducerId([0x25; 32]),
            package: BlobRef::of_bytes(b"shared runtime package"),
            runtime_abi: RUNTIME_ABI_ID,
            execution_semantics: EXECUTION_SEMANTICS_ID,
        }
    }

    fn ordered_entry(route: AgentRouteKey) -> OrderedEntry {
        OrderedEntry {
            genesis: route.genesis(),
            index: 1,
            parent: None,
            merge_frontier: MergeFrontierId([0x36; 32]),
            merge_seal: Some(MergeSealId([0x3d; 32])),
            input: ReplayInput {
                runtime: runtime(),
                operation: ReplayOperation::SealMerge,
            },
        }
    }

    fn ordinary_ordered_entry(route: AgentRouteKey, parent: OrderedEntryId) -> OrderedEntry {
        let invocation = ActorInvocation {
            invocation: InvocationId([0x61; 32]),
            actor: ActorId([0x62; 32]),
            incarnation: Hash([0x63; 32]),
            deployment: DeploymentId([0x64; 32]),
            program: ProgramId([0x65; 32]),
            mode: MethodMode::Linear,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![0x66],
            availability: Vec::new(),
            gas: 1,
        };
        let public_key = ed25519_public_key_wire([0x67; 32]);
        let authority = ActorInvocationReceipt {
            claim: ActorInvocationClaim {
                authority: AgentAuthorityBinding {
                    agent: route.agent(),
                    actor: ActorId([0x68; 32]),
                    deployment: DeploymentId([0x69; 32]),
                    program: ProgramId([0x6a; 32]),
                    producer: ProducerId::of_public_key(&public_key),
                    public_key,
                },
                space: route.space(),
                agent: route.agent(),
                principal: None,
                credential: None,
                authorization: invocation.authorization_message(),
                auth: invocation.auth.clone(),
                valid_from: 1,
                valid_until: 2,
            },
            signature: vec![0x6b; ED25519_SIGNATURE_BYTES],
        };
        OrderedEntry {
            genesis: route.genesis(),
            index: 2,
            parent: Some(parent),
            merge_frontier: MergeFrontierId([0x6c; 32]),
            merge_seal: None,
            input: ReplayInput {
                runtime: runtime(),
                operation: ReplayOperation::Invoke {
                    invocation,
                    authority,
                    observed_slot: 1,
                },
            },
        }
    }

    fn lane(byte: u8, state: &[u8]) -> SharedLaneProjection {
        SharedLaneProjection::new(LaneStateId([byte; 32]), BlobRef::of_bytes(state)).unwrap()
    }

    fn successor(byte: u8) -> JournalHeadsId {
        JournalHeadsId([byte; 32])
    }

    fn journal_store(byte: u8) -> JournalStoreInstanceId {
        JournalStoreInstanceId::from_bytes([byte; 32]).unwrap()
    }

    fn claim(
        route: AgentRouteKey,
        entry: &OrderedEntry,
        raft_index: u64,
        raft_term: u64,
        linear_state: &[u8],
    ) -> OrderedCommitClaim {
        let ordered = OrderedBase {
            index: entry.index,
            head: Some(entry.id()),
        };
        let merge = lane(0x37, b"observed merge state");
        OrderedCommitClaim::new(
            route.genesis(),
            route.admission(),
            route.committee(),
            raft_index,
            raft_term,
            ordered,
            entry.merge_frontier,
            merge.clone(),
            InvocationIndexId([0x42; 32]),
            runtime(),
            lane(0x38, b"control state"),
            lane(0x39, linear_state),
            InvocationIndexId([0x3a; 32]),
            ArtifactClosureId([0x3b; 32]),
            ordered,
            Some(
                SharedSealedMergeProjection::new(
                    entry.merge_seal.unwrap(),
                    entry.merge_frontier,
                    merge,
                    InvocationIndexId([0x40; 32]),
                )
                .unwrap(),
            ),
            Hash([0x41; 32]),
        )
        .unwrap()
    }

    fn retained_seal_claim(
        route: AgentRouteKey,
        fence: &OrderedEntry,
        entry: &OrderedEntry,
        raft_index: u64,
        raft_term: u64,
    ) -> OrderedCommitClaim {
        let ordered = OrderedBase {
            index: entry.index,
            head: Some(entry.id()),
        };
        let sealed_lane = lane(0x70, b"sealed merge state");
        OrderedCommitClaim::new(
            route.genesis(),
            route.admission(),
            route.committee(),
            raft_index,
            raft_term,
            ordered,
            entry.merge_frontier,
            lane(0x71, b"newer observed merge state"),
            InvocationIndexId([0x72; 32]),
            runtime(),
            lane(0x73, b"control state after ordinary entry"),
            lane(0x74, b"linear state after ordinary entry"),
            InvocationIndexId([0x75; 32]),
            ArtifactClosureId([0x76; 32]),
            OrderedBase {
                index: fence.index,
                head: Some(fence.id()),
            },
            Some(
                SharedSealedMergeProjection::new(
                    fence.merge_seal.unwrap(),
                    fence.merge_frontier,
                    sealed_lane,
                    InvocationIndexId([0x77; 32]),
                )
                .unwrap(),
            ),
            Hash([0x78; 32]),
        )
        .unwrap()
    }

    struct TestWitness {
        row: Option<(u64, u64, u64, Vec<u8>)>,
    }

    impl DurableAgentRaftLogWitness for TestWitness {
        type Error = ();

        fn read_committed_payload(
            &self,
            _index: u64,
        ) -> Result<Option<(u64, u64, u64, Vec<u8>)>, Self::Error> {
            Ok(self.row.clone())
        }
    }

    fn committed(command: AgentRaftCommand, index: u64, term: u64) -> CommittedAgentRaftEntry {
        CommittedAgentRaftEntry::from_durable_log(
            &TestWitness {
                row: Some((index, term, index, command.encode())),
            },
            index,
        )
        .unwrap()
    }

    fn ordered_fixture(
        committee: &AgentReplicaCommittee,
    ) -> (CommittedAgentRaftEntry, OrderedCommitClaim) {
        let route = route(committee);
        let entry = ordered_entry(route);
        let claim = claim(route, &entry, 1, 7, b"linear state");
        let committed = committed(
            AgentRaftCommand::Ordered {
                route,
                artifact_batch: None,
                entry,
            },
            1,
            7,
        );
        (committed, claim)
    }

    #[test]
    fn route_manifest_chunk_and_commands_round_trip_with_hard_bounds() {
        let voters = [key(1)];
        let committee = committee(&voters, &[]);
        let route = route(&committee);
        assert_eq!(AgentRouteKey::decode(&route.encode()).unwrap(), route);

        let bytes = vec![0xa5; ARTIFACT_CHUNK_DATA_BYTES + 17];
        let mut artifacts = vec![BlobRef::of_bytes(&bytes), BlobRef::of_bytes(b"second")];
        artifacts.sort_by_key(|artifact| artifact.hash);
        let target = artifacts
            .iter()
            .position(|artifact| artifact.len == bytes.len() as u64)
            .unwrap() as u32;
        let manifest = ArtifactBatchManifest::new(route, artifacts).unwrap();
        assert_eq!(
            ArtifactBatchManifest::decode(&manifest.encode()).unwrap(),
            manifest
        );
        assert_ne!(manifest.id(), ArtifactBatchId::ZERO);

        let chunk = ArtifactChunk::new(
            manifest.clone(),
            target,
            0,
            bytes[..ARTIFACT_CHUNK_DATA_BYTES].to_vec(),
        )
        .unwrap();
        assert_eq!(ArtifactChunk::decode(&chunk.encode()).unwrap(), chunk);
        let chunk_command = AgentRaftCommand::ArtifactChunk(chunk.clone());
        assert_eq!(
            AgentRaftCommand::decode(&chunk_command.encode()).unwrap(),
            chunk_command
        );
        let abort = AgentRaftCommand::ArtifactAbort {
            route,
            batch: manifest.id(),
        };
        assert_eq!(AgentRaftCommand::decode(&abort.encode()).unwrap(), abort);

        let mut too_many = Vec::new();
        for index in 1..=MAX_CATALOG_ARTIFACT_REFERENCES + 1 {
            let mut hash = [0_u8; 32];
            hash[..4].copy_from_slice(&index.to_be_bytes());
            too_many.push(BlobRef {
                hash: Hash(hash),
                len: 0,
            });
        }
        assert!(matches!(
            ArtifactBatchManifest::new(route, too_many),
            Err(AgentRaftWireError::LimitExceeded)
        ));
        assert!(manifest.encode().len() <= MAX_ARTIFACT_BATCH_MANIFEST_BYTES);
        assert!(chunk.encode().len() <= MAX_ARTIFACT_CHUNK_WIRE_BYTES);
        assert!(chunk_command.encode().len() <= MAX_AGENT_RAFT_COMMAND_BYTES);
    }

    #[test]
    fn chunk_commitment_and_durable_log_promotion_reject_tampering() {
        let voters = [key(1)];
        let committee = committee(&voters, &[]);
        let route = route(&committee);
        let artifact_bytes = b"canonical artifact".to_vec();
        let manifest =
            ArtifactBatchManifest::new(route, vec![BlobRef::of_bytes(&artifact_bytes)]).unwrap();
        let chunk = ArtifactChunk::new(manifest, 0, 0, artifact_bytes).unwrap();
        let mut tampered = chunk.encode();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            ArtifactChunk::decode(&tampered),
            Err(DecodeError::NonCanonical)
        );

        let command = AgentRaftCommand::ArtifactChunk(chunk);
        let encoded = command.encode();
        assert!(matches!(
            CommittedAgentRaftEntry::from_durable_log(
                &TestWitness {
                    row: Some((2, 3, 1, encoded.clone())),
                },
                2,
            ),
            Err(CommittedAgentRaftEntryError::Invalid(
                AgentRaftWireError::InvalidCommittedEntry
            ))
        ));
        assert!(matches!(
            CommittedAgentRaftEntry::from_durable_log(
                &TestWitness {
                    row: Some((3, 3, 3, encoded)),
                },
                2,
            ),
            Err(CommittedAgentRaftEntryError::Invalid(
                AgentRaftWireError::InvalidCommittedEntry
            ))
        ));
    }

    #[test]
    fn ordinary_ordered_successor_accepts_the_prior_retained_merge_seal() {
        let voters = [key(1)];
        let committee = committee(&voters, &[]);
        let route = route(&committee);
        let fence = ordered_entry(route);
        let entry = ordinary_ordered_entry(route, fence.id());
        let claim = retained_seal_claim(route, &fence, &entry, 2, 7);
        assert!(entry.merge_seal.is_none());
        assert_eq!(
            claim.merge_seal(),
            fence.merge_seal,
            "the claim retains the prior fence seal"
        );
        assert_ne!(claim.merge_fence(), claim.ordered());

        let committed = committed(
            AgentRaftCommand::Ordered {
                route,
                artifact_batch: None,
                entry,
            },
            2,
            7,
        );
        evidence_ledger::validate_claim_link(route, &committed, &claim).unwrap();
    }

    struct TempDirectory(std::path::PathBuf);

    impl TempDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(alloc::format!(
                "vos_shared_raft_{label}_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn database(&self) -> std::path::PathBuf {
            self.0.join("evidence.redb")
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TestSignFailure;

    impl fmt::Display for TestSignFailure {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("injected signer failure")
        }
    }

    impl core::error::Error for TestSignFailure {}

    struct CheckingSigner<'a> {
        ledger: &'a AgentRaftEvidenceLedger,
        key: &'a SigningKey,
        expected_index: u64,
        expected_claim: Hash,
        calls: &'a Cell<usize>,
        fail: bool,
    }

    impl ReplicaCommitSigner for CheckingSigner<'_> {
        type Error = TestSignFailure;

        fn node(&self) -> NodeId {
            NodeId::of_authenticated_peer(&peer_id(self.key))
        }

        fn sign_commit_message(&self, message: Hash) -> Result<[u8; 64], Self::Error> {
            // This read opens a new redb transaction from inside the callback;
            // it proves the pledge commit completed before signing began.
            assert_eq!(
                self.ledger.pledged_claim(self.expected_index).unwrap(),
                Some(self.expected_claim)
            );
            self.calls.set(self.calls.get() + 1);
            if self.fail {
                Err(TestSignFailure)
            } else {
                Ok(self.key.sign(&message.0).to_bytes())
            }
        }
    }

    struct PanicSigner {
        node: NodeId,
    }

    impl ReplicaCommitSigner for PanicSigner {
        type Error = TestSignFailure;

        fn node(&self) -> NodeId {
            self.node
        }

        fn sign_commit_message(&self, _message: Hash) -> Result<[u8; 64], Self::Error> {
            panic!("an exact signed retry must not invoke the signer")
        }
    }

    #[test]
    fn pledge_survives_crash_window_and_exact_retry_never_resigns() {
        let directory = TempDirectory::new("pledge_reopen");
        let path = directory.database();
        let voters = [key(1)];
        let committee = committee(&voters, &[]);
        let route = route(&committee);
        let local_node = NodeId::of_authenticated_peer(&peer_id(&voters[0]));
        let (committed, claim) = ordered_fixture(&committee);

        // Crash after the pre-CAS capacity reservation but before publication.
        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = AgentRaftEvidenceLedger::open(
                database,
                route,
                committee.clone(),
                local_node,
                journal_store(0x80),
            )
            .unwrap();
            let reserved = ledger.reserve_ordered_application(&committed).unwrap();
            assert_eq!(
                reserved.payload_commitment(),
                committed.payload_commitment()
            );
            assert_eq!(reserved.journal_store(), journal_store(0x80));
        }

        {
            let database = Arc::new(Database::create(&path).unwrap());
            assert!(matches!(
                AgentRaftEvidenceLedger::open(
                    database,
                    route,
                    committee.clone(),
                    local_node,
                    journal_store(0x81),
                ),
                Err(AgentRaftLedgerError::ConfigurationMismatch)
            ));
        }

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = AgentRaftEvidenceLedger::open(
                database,
                route,
                committee.clone(),
                local_node,
                journal_store(0x80),
            )
            .unwrap();
            let reserved = ledger.reserve_ordered_application(&committed).unwrap();
            let duplicate = ledger.reserve_ordered_application(&committed).unwrap();
            ledger
                .anchor_applied_ordered_for_test(reserved, &claim, successor(0x79))
                .unwrap();
            assert!(matches!(
                ledger.anchor_applied_ordered_for_test(duplicate, &claim, successor(0x79),),
                Err(AgentRaftLedgerError::AppliedConflict)
            ));
            let calls = Cell::new(0);
            let failed = ledger.sign_local(
                &claim,
                &CheckingSigner {
                    ledger: &ledger,
                    key: &voters[0],
                    expected_index: claim.raft_index(),
                    expected_claim: claim.commitment(),
                    calls: &calls,
                    fail: true,
                },
            );
            assert!(matches!(failed, Err(AgentRaftSignError::Signer(_))));
            assert_eq!(calls.get(), 1);
            assert_eq!(
                ledger.pledged_claim(claim.raft_index()).unwrap(),
                Some(claim.commitment())
            );
            assert!(ledger.certificate(claim.raft_index()).unwrap().is_none());
        }

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = AgentRaftEvidenceLedger::open(
                database,
                route,
                committee.clone(),
                local_node,
                journal_store(0x80),
            )
            .unwrap();
            let recovered_application =
                ledger.recover_applied_ordered(&committed).unwrap().unwrap();
            assert_eq!(recovered_application.claim(), &claim);
            assert_eq!(recovered_application.successor(), successor(0x79));
            assert!(matches!(
                ledger.reserve_ordered_application(&committed),
                Err(AgentRaftLedgerError::AppliedConflict)
            ));
            let calls = Cell::new(0);
            let outcome = ledger
                .sign_local(
                    &claim,
                    &CheckingSigner {
                        ledger: &ledger,
                        key: &voters[0],
                        expected_index: claim.raft_index(),
                        expected_claim: claim.commitment(),
                        calls: &calls,
                        fail: false,
                    },
                )
                .unwrap();
            assert_eq!(calls.get(), 1);
            assert!(outcome.certificate().is_some());
            outcome
                .certificate()
                .unwrap()
                .verify(&committee, &claim)
                .unwrap();

            let retried = ledger
                .sign_local(&claim, &PanicSigner { node: local_node })
                .unwrap();
            assert_eq!(retried.share(), outcome.share());
            assert_eq!(
                ledger.apply_meta().unwrap().compact_safe(),
                (claim.raft_index(), claim.raft_term())
            );
        }
    }

    #[test]
    fn reservation_from_another_journal_instance_cannot_anchor() {
        let first_directory = TempDirectory::new("journal_binding_a");
        let second_directory = TempDirectory::new("journal_binding_b");
        let voters = [key(1)];
        let committee = committee(&voters, &[]);
        let route = route(&committee);
        let local_node = NodeId::of_authenticated_peer(&peer_id(&voters[0]));
        let (committed, claim) = ordered_fixture(&committee);
        let first = AgentRaftEvidenceLedger::open(
            Arc::new(Database::create(first_directory.database()).unwrap()),
            route,
            committee.clone(),
            local_node,
            journal_store(0x84),
        )
        .unwrap();
        let second = AgentRaftEvidenceLedger::open(
            Arc::new(Database::create(second_directory.database()).unwrap()),
            route,
            committee,
            local_node,
            journal_store(0x85),
        )
        .unwrap();
        let foreign = first.reserve_ordered_application(&committed).unwrap();
        let local = second.reserve_ordered_application(&committed).unwrap();
        assert!(matches!(
            second.anchor_applied_ordered_for_test(foreign, &claim, successor(0x86)),
            Err(AgentRaftLedgerError::WrongJournalStore)
        ));
        second
            .anchor_applied_ordered_for_test(local, &claim, successor(0x86))
            .unwrap();
    }

    #[test]
    fn ordered_artifact_batch_is_rejected_before_phase_one_reservation() {
        let directory = TempDirectory::new("ordered_artifact_batch");
        let voters = [key(1)];
        let committee = committee(&voters, &[]);
        let route = route(&committee);
        let local_node = NodeId::of_authenticated_peer(&peer_id(&voters[0]));
        let (unbatched, claim) = ordered_fixture(&committee);
        let entry = match unbatched.command() {
            AgentRaftCommand::Ordered { entry, .. } => entry.clone(),
            _ => unreachable!(),
        };
        let batched = committed(
            AgentRaftCommand::Ordered {
                route,
                artifact_batch: Some(ArtifactBatchId::from_bytes([0x88; 32])),
                entry,
            },
            1,
            7,
        );
        let ledger = AgentRaftEvidenceLedger::open(
            Arc::new(Database::create(directory.database()).unwrap()),
            route,
            committee,
            local_node,
            journal_store(0x80),
        )
        .unwrap();
        let before = ledger.apply_meta().unwrap();
        assert!(matches!(
            ledger.reserve_ordered_application(&batched),
            Err(AgentRaftLedgerError::ArtifactBatchReceiptRequired)
        ));
        assert!(matches!(
            ledger.recover_applied_ordered(&batched),
            Err(AgentRaftLedgerError::ArtifactBatchReceiptRequired)
        ));
        assert!(matches!(
            evidence_ledger::validate_claim_link(route, &batched, &claim),
            Err(AgentRaftLedgerError::ArtifactBatchReceiptRequired)
        ));
        assert_eq!(ledger.apply_meta().unwrap(), before);

        // A valid unbatched command can still take the same slot, proving the
        // rejected call wrote neither a reservation nor fail-stop evidence.
        let reserved = ledger.reserve_ordered_application(&unbatched).unwrap();
        ledger
            .anchor_applied_ordered_for_test(reserved, &claim, successor(0x89))
            .unwrap();
    }

    #[test]
    fn divergent_anchored_claim_persists_fail_stop_across_reopen() {
        let directory = TempDirectory::new("equivocation");
        let path = directory.database();
        let voters = [key(1)];
        let committee = committee(&voters, &[]);
        let route = route(&committee);
        let local_node = NodeId::of_authenticated_peer(&peer_id(&voters[0]));
        let (committed, anchored_claim) = ordered_fixture(&committee);
        let entry = match committed.command() {
            AgentRaftCommand::Ordered { entry, .. } => entry,
            _ => unreachable!(),
        };
        let divergent = claim(route, entry, 1, 7, b"divergent linear state");

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = AgentRaftEvidenceLedger::open(
                database,
                route,
                committee.clone(),
                local_node,
                journal_store(0x80),
            )
            .unwrap();
            let reserved = ledger.reserve_ordered_application(&committed).unwrap();
            ledger
                .anchor_applied_ordered_for_test(reserved, &anchored_claim, successor(0x7a))
                .unwrap();
            let calls = Cell::new(0);
            let error = ledger
                .sign_local(
                    &divergent,
                    &CheckingSigner {
                        ledger: &ledger,
                        key: &voters[0],
                        expected_index: divergent.raft_index(),
                        expected_claim: divergent.commitment(),
                        calls: &calls,
                        fail: false,
                    },
                )
                .unwrap_err();
            assert!(matches!(
                error,
                AgentRaftSignError::Ledger(AgentRaftLedgerError::DivergentClaim)
            ));
            assert_eq!(calls.get(), 0);
            assert!(ledger.is_fail_stopped().unwrap());
        }

        let database = Arc::new(Database::create(&path).unwrap());
        let ledger = AgentRaftEvidenceLedger::open(
            database,
            route,
            committee,
            local_node,
            journal_store(0x80),
        )
        .unwrap();
        assert!(ledger.is_fail_stopped().unwrap());
        assert!(matches!(
            ledger.sign_local(&anchored_claim, &PanicSigner { node: local_node }),
            Err(AgentRaftSignError::Ledger(
                AgentRaftLedgerError::FailStopped
            ))
        ));
    }

    #[test]
    fn conflicting_reservation_fail_stops_but_the_admitted_exact_slot_can_drain() {
        let directory = TempDirectory::new("reservation_equivocation");
        let path = directory.database();
        let voters = [key(1)];
        let committee = committee(&voters, &[]);
        let route = route(&committee);
        let local_node = NodeId::of_authenticated_peer(&peer_id(&voters[0]));
        let first_entry = ordered_entry(route);
        let first_claim = claim(route, &first_entry, 1, 7, b"admitted linear state");
        let mut conflicting_entry = first_entry.clone();
        conflicting_entry.merge_frontier = MergeFrontierId([0x7d; 32]);
        let first = committed(
            AgentRaftCommand::Ordered {
                route,
                artifact_batch: None,
                entry: first_entry,
            },
            1,
            7,
        );
        let conflicting = committed(
            AgentRaftCommand::Ordered {
                route,
                artifact_batch: None,
                entry: conflicting_entry,
            },
            1,
            7,
        );

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = AgentRaftEvidenceLedger::open(
                database,
                route,
                committee.clone(),
                local_node,
                journal_store(0x80),
            )
            .unwrap();
            let _lost_after_crash = ledger.reserve_ordered_application(&first).unwrap();
            assert!(matches!(
                ledger.reserve_ordered_application(&conflicting),
                Err(AgentRaftLedgerError::DivergentReservation)
            ));
            assert!(ledger.is_fail_stopped().unwrap());
            // Simulate a crash after the reservation may have crossed the
            // journal CAS but before its in-memory authority reaches anchor.
        }

        let database = Arc::new(Database::create(&path).unwrap());
        let ledger = AgentRaftEvidenceLedger::open(
            database,
            route,
            committee,
            local_node,
            journal_store(0x80),
        )
        .unwrap();
        assert!(ledger.is_fail_stopped().unwrap());
        assert!(matches!(
            ledger.reserve_ordered_application(&conflicting),
            Err(AgentRaftLedgerError::FailStopped)
        ));
        // The exact authority may already have crossed the journal CAS.
        // Reissuing and draining its durable reservation is therefore
        // mandatory even though every new authority and all signing stop.
        let recovered_reservation = ledger.reserve_ordered_application(&first).unwrap();
        ledger
            .anchor_applied_ordered_for_test(recovered_reservation, &first_claim, successor(0x87))
            .unwrap();
        assert!(ledger.is_fail_stopped().unwrap());
        assert!(matches!(
            ledger.sign_local(&first_claim, &PanicSigner { node: local_node }),
            Err(AgentRaftSignError::Ledger(
                AgentRaftLedgerError::FailStopped
            ))
        ));
        let recovered = ledger.recover_applied_ordered(&first).unwrap().unwrap();
        assert_eq!(recovered.claim(), &first_claim);
        assert_eq!(recovered.successor(), successor(0x87));
        assert!(matches!(
            ledger.reserve_ordered_application(&first),
            Err(AgentRaftLedgerError::FailStopped)
        ));
    }

    #[test]
    fn reopen_rejects_a_gap_in_the_permanent_contiguous_anchor_history() {
        let directory = TempDirectory::new("anchor_gap");
        let path = directory.database();
        let voters = [key(1)];
        let committee = committee(&voters, &[]);
        let route = route(&committee);
        let local_node = NodeId::of_authenticated_peer(&peer_id(&voters[0]));
        let fence = ordered_entry(route);
        let first_claim = claim(route, &fence, 1, 7, b"first linear state");
        let first = committed(
            AgentRaftCommand::Ordered {
                route,
                artifact_batch: None,
                entry: fence.clone(),
            },
            1,
            7,
        );
        let ordinary = ordinary_ordered_entry(route, fence.id());
        let second_claim = retained_seal_claim(route, &fence, &ordinary, 2, 7);
        let second = committed(
            AgentRaftCommand::Ordered {
                route,
                artifact_batch: None,
                entry: ordinary,
            },
            2,
            7,
        );

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = AgentRaftEvidenceLedger::open(
                database,
                route,
                committee.clone(),
                local_node,
                journal_store(0x80),
            )
            .unwrap();
            let reserved = ledger.reserve_ordered_application(&first).unwrap();
            ledger
                .anchor_applied_ordered_for_test(reserved, &first_claim, successor(0x82))
                .unwrap();
            let reserved = ledger.reserve_ordered_application(&second).unwrap();
            ledger
                .anchor_applied_ordered_for_test(reserved, &second_claim, successor(0x83))
                .unwrap();
            ledger.delete_anchor_for_test(1).unwrap();
        }

        let database = Arc::new(Database::create(&path).unwrap());
        assert!(matches!(
            AgentRaftEvidenceLedger::open(
                database,
                route,
                committee,
                local_node,
                journal_store(0x80),
            ),
            Err(AgentRaftLedgerError::CorruptLedger)
        ));
    }

    fn share(claim: &OrderedCommitClaim, key: &SigningKey) -> ReplicaCommitSignature {
        let message =
            ReplicaQuorumCertificate::signing_message(claim.committee(), claim.commitment());
        ReplicaCommitSignature::new(
            NodeId::of_authenticated_peer(&peer_id(key)),
            key.sign(&message.0).to_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn remote_voter_shares_form_and_recover_exact_quorum_certificate() {
        let directory = TempDirectory::new("remote_shares");
        let path = directory.database();
        let voters = [key(1), key(2), key(3)];
        let observers = [key(9)];
        let committee = committee(&voters, &observers);
        let route = route(&committee);
        let local_node = NodeId::of_authenticated_peer(&peer_id(&voters[0]));
        let (committed, claim) = ordered_fixture(&committee);

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = AgentRaftEvidenceLedger::open(
                database,
                route,
                committee.clone(),
                local_node,
                journal_store(0x80),
            )
            .unwrap();
            assert!(matches!(
                ledger.record_remote_share(&claim, share(&claim, &voters[1])),
                Err(AgentRaftLedgerError::ClaimNotAnchored)
            ));
            let reserved = ledger.reserve_ordered_application(&committed).unwrap();
            ledger
                .anchor_applied_ordered_for_test(reserved, &claim, successor(0x7b))
                .unwrap();
            let calls = Cell::new(0);
            let local = ledger
                .sign_local(
                    &claim,
                    &CheckingSigner {
                        ledger: &ledger,
                        key: &voters[0],
                        expected_index: claim.raft_index(),
                        expected_claim: claim.commitment(),
                        calls: &calls,
                        fail: false,
                    },
                )
                .unwrap();
            assert!(local.certificate().is_none());

            let observer_error = ledger
                .record_remote_share(&claim, share(&claim, &observers[0]))
                .unwrap_err();
            assert!(matches!(
                observer_error,
                AgentRaftLedgerError::ObserverSigner
            ));
            let quorum = ledger
                .record_remote_share(&claim, share(&claim, &voters[1]))
                .unwrap();
            let certificate = quorum.certificate().unwrap();
            assert_eq!(certificate.signatures().len(), 2);
            certificate.verify(&committee, &claim).unwrap();
            let first_certificate = certificate.clone();
            let late = ledger
                .record_remote_share(&claim, share(&claim, &voters[2]))
                .unwrap();
            assert_eq!(late.certificate(), Some(&first_certificate));
            assert_eq!(
                late.share().signer(),
                member(&voters[2], ReplicaRole::Voter).replica().node
            );
            assert_eq!(
                ledger.apply_meta().unwrap().compact_safe_qc(),
                Some(certificate.commitment())
            );
        }

        let database = Arc::new(Database::create(&path).unwrap());
        let ledger = AgentRaftEvidenceLedger::open(
            database,
            route,
            committee.clone(),
            local_node,
            journal_store(0x80),
        )
        .unwrap();
        let recovered = ledger.certificate(claim.raft_index()).unwrap().unwrap();
        recovered.verify(&committee, &claim).unwrap();
        assert_eq!(recovered.signatures().len(), committee.quorum_threshold());
        assert!(recovered.encode().len() <= MAX_REPLICA_QUORUM_CERTIFICATE_BYTES);
    }

    #[test]
    fn observer_applies_and_verifies_quorum_but_never_pledges_or_signs() {
        let voters = [key(1)];
        let observers = [key(9)];
        let committee = committee(&voters, &observers);
        let route = route(&committee);
        let local_node = NodeId::of_authenticated_peer(&peer_id(&observers[0]));
        let (committed, claim) = ordered_fixture(&committee);
        let directory = TempDirectory::new("observer_apply");
        let database = Arc::new(Database::create(directory.database()).unwrap());
        let ledger = AgentRaftEvidenceLedger::open(
            database,
            route,
            committee.clone(),
            local_node,
            journal_store(0x80),
        )
        .unwrap();
        let reserved = ledger.reserve_ordered_application(&committed).unwrap();
        assert_eq!(reserved.local_node(), local_node);
        ledger
            .anchor_applied_ordered_for_test(reserved, &claim, successor(0x7c))
            .unwrap();

        assert!(matches!(
            ledger.sign_local(&claim, &PanicSigner { node: local_node }),
            Err(AgentRaftSignError::Ledger(
                AgentRaftLedgerError::LocalReplicaNotVoter
            ))
        ));
        assert_eq!(ledger.pledged_claim(claim.raft_index()).unwrap(), None);

        let outcome = ledger
            .record_remote_share(&claim, share(&claim, &voters[0]))
            .unwrap();
        let certificate = outcome.certificate().unwrap();
        certificate.verify(&committee, &claim).unwrap();
        assert_eq!(
            ledger.apply_meta().unwrap().compact_safe_qc(),
            Some(certificate.commitment())
        );
    }
}
