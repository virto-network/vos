//! Durable application-level commit certificates for Shared Agents.
//!
//! Raft transport authentication proves who exchanged replication messages;
//! it does not give an observer or a pruned replay resolver durable evidence
//! that a committed entry was published into the exact Agent journal state.
//! This module defines that evidence. A replica signature is valid only when
//! its operator has first observed the raw Raft commit, atomically published
//! the exact journal projection, and durably recorded a sign-once decision for
//! `(genesis, ordered index)`. Those crash-ordering obligations live in the
//! future Shared host; the canonical claim and verifier live here.
//!
//! A certificate is authenticated-CFT application evidence, not a Byzantine
//! Raft protocol. Its safety relies on deterministic honest application and
//! majority intersection. Decoding checks only canonical shape. Trust is
//! promoted exclusively by [`ReplicaQuorumCertificate::verify`], using an
//! independently admitted, exact [`AgentReplicaCommittee`] and an exact claim
//! expected by the caller.

use alloc::vec::Vec;
use core::fmt;

use super::execution::MAX_RUNTIME_STATE_BYTES;
use super::genesis::{AgentGenesisAdmissionId, AgentReplicaCommittee, AgentReplicaCommitteeId};
use super::journal::{
    AgentJournalGenesisId, ArtifactClosureId, CheckpointId, InvocationIndexId, JournalHeadsId,
    LaneStateId, MergeFrontierId, MergeSealId, OrderedBase, OrderedEntryId, RuntimeBinding,
};
use super::{AgentProfile, MAX_AGENT_REPLICAS, ReplicaRole};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{
    AgentId, BlobRef, DeploymentId, Hash, NodeId, ProducerId, ProgramId, SpaceId,
};

const SERVICE_WIRE_HEADER_BYTES: usize = 4 + 32;

const ORDERED_COMMIT_CLAIM_DOMAIN: &[u8] = b"vos/agent/shared/ordered-commit-claim/v1";
const REPLICA_COMMIT_MESSAGE_DOMAIN: &[u8] = b"vos/agent/shared/replica-commit-signature/v1";
const REPLICA_QUORUM_CERTIFICATE_DOMAIN: &[u8] = b"vos/agent/shared/replica-quorum-certificate/v1";
const VERIFIED_ORDERED_SNAPSHOT_DOMAIN: &[u8] = b"vos/agent/shared/verified-ordered-snapshot/v1";
const AGENT_SNAPSHOT_CLAIM_DOMAIN: &[u8] = b"vos/agent/shared/snapshot-claim/v1";
const AGENT_SNAPSHOT_MESSAGE_DOMAIN: &[u8] = b"vos/agent/shared/snapshot-signature/v1";
const AGENT_SNAPSHOT_CERTIFICATE_DOMAIN: &[u8] = b"vos/agent/shared/snapshot-certificate/v1";
const PORTABLE_SNAPSHOT_CLAIM_DOMAIN: &[u8] = b"vos/agent/shared/portable-snapshot-claim/v1";
const PORTABLE_SNAPSHOT_MESSAGE_DOMAIN: &[u8] = b"vos/agent/shared/portable-snapshot-signature/v1";
const PORTABLE_SNAPSHOT_CERTIFICATE_DOMAIN: &[u8] =
    b"vos/agent/shared/portable-snapshot-certificate/v1";
const COMMON_SNAPSHOT_CLAIM_DOMAIN: &[u8] = b"vos/agent/shared/common-snapshot-claim/v1";
const COMMON_RECOVERY_SNAPSHOT_CLAIM_DOMAIN: &[u8] = b"vos/agent/shared/common-snapshot-claim/v2";
const COMMON_SNAPSHOT_MESSAGE_DOMAIN: &[u8] = b"vos/agent/shared/common-snapshot-signature/v1";
const COMMON_SNAPSHOT_CERTIFICATE_DOMAIN: &[u8] =
    b"vos/agent/shared/common-snapshot-certificate/v1";
const LOCAL_SNAPSHOT_BINDING_DOMAIN: &[u8] = b"vos/agent/shared/local-snapshot-binding/v1";
const LOCAL_SNAPSHOT_MESSAGE_DOMAIN: &[u8] = b"vos/agent/shared/local-snapshot-signature/v1";

/// Maximum complete canonical lane projection.
pub const MAX_SHARED_LANE_PROJECTION_BYTES: usize = 128;
/// Maximum complete canonical last-sealed Merge projection.
pub const MAX_SHARED_SEALED_MERGE_PROJECTION_BYTES: usize = 256;
/// Maximum complete ordered-commit claim.
pub const MAX_ORDERED_COMMIT_CLAIM_BYTES: usize = 4 * 1024;
/// Maximum complete standalone replica signature.
pub const MAX_REPLICA_COMMIT_SIGNATURE_BYTES: usize = 192;
/// Raw Ed25519 signature width used by an admitted replica voter.
pub const REPLICA_COMMIT_ED25519_SIGNATURE_BYTES: usize = 64;
/// Maximum signatures retained by one replica commit certificate.
pub const MAX_REPLICA_COMMIT_SIGNATURES: usize = MAX_AGENT_REPLICAS;
/// Maximum complete replica quorum certificate.
pub const MAX_REPLICA_QUORUM_CERTIFICATE_BYTES: usize = 32 * 1024;
/// Maximum complete Agent-specific checkpoint claim.
pub const MAX_SHARED_AGENT_SNAPSHOT_CLAIM_BYTES: usize =
    MAX_ORDERED_COMMIT_CLAIM_BYTES + super::genesis::MAX_AGENT_REPLICA_COMMITTEE_BYTES + 2 * 1024;
/// Maximum complete Agent-specific checkpoint certificate.
pub const MAX_SHARED_AGENT_SNAPSHOT_CERTIFICATE_BYTES: usize = MAX_SHARED_AGENT_SNAPSHOT_CLAIM_BYTES
    + MAX_REPLICA_COMMIT_SIGNATURES * MAX_REPLICA_COMMIT_SIGNATURE_BYTES
    + 1024;
/// Maximum complete source-instance-independent recovery claim.
pub const MAX_SHARED_AGENT_PORTABLE_SNAPSHOT_CLAIM_BYTES: usize =
    MAX_ORDERED_COMMIT_CLAIM_BYTES + super::genesis::MAX_AGENT_REPLICA_COMMITTEE_BYTES + 2 * 1024;
/// Maximum complete quorum certificate over one portable recovery claim.
pub const MAX_SHARED_AGENT_PORTABLE_SNAPSHOT_CERTIFICATE_BYTES: usize =
    MAX_SHARED_AGENT_PORTABLE_SNAPSHOT_CLAIM_BYTES
        + MAX_REPLICA_COMMIT_SIGNATURES * MAX_REPLICA_COMMIT_SIGNATURE_BYTES
        + 1024;
pub const MAX_SHARED_AGENT_COMMON_SNAPSHOT_CLAIM_BYTES: usize =
    MAX_ORDERED_COMMIT_CLAIM_BYTES + super::genesis::MAX_AGENT_REPLICA_COMMITTEE_BYTES + 160;
pub const MAX_SHARED_AGENT_COMMON_SNAPSHOT_CERTIFICATE_BYTES: usize =
    MAX_SHARED_AGENT_COMMON_SNAPSHOT_CLAIM_BYTES + 3 * MAX_REPLICA_COMMIT_SIGNATURE_BYTES + 128;
pub const MAX_SHARED_AGENT_LOCAL_SNAPSHOT_BINDING_BYTES: usize =
    MAX_SHARED_AGENT_SNAPSHOT_CLAIM_BYTES + MAX_REPLICA_COMMIT_SIGNATURE_BYTES + 128;

/// Exact content-addressed state materialization for one shared lane.
///
/// `manifest` authenticates the journal cursor, runtime, and state reference;
/// `state` lets snapshot installers reject a wrong or truncated preimage before
/// handing any bytes to replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedLaneProjection {
    manifest: LaneStateId,
    state: BlobRef,
}

impl SharedLaneProjection {
    pub fn new(manifest: LaneStateId, state: BlobRef) -> Result<Self, SharedCommitError> {
        let projection = Self { manifest, state };
        projection.validate()?;
        Ok(projection)
    }

    pub const fn manifest(&self) -> LaneStateId {
        self.manifest
    }

    pub const fn state(&self) -> &BlobRef {
        &self.state
    }

    /// Verify one exact opaque state preimage.
    pub fn verify_state(&self, bytes: &[u8]) -> Result<(), SharedCommitError> {
        if bytes.len() > MAX_RUNTIME_STATE_BYTES {
            return Err(SharedCommitError::StateLimitExceeded);
        }
        if !self.state.matches(bytes) {
            return Err(SharedCommitError::StateMismatch);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), SharedCommitError> {
        if self.manifest == LaneStateId::ZERO || !valid_state_ref(&self.state) {
            return Err(SharedCommitError::InvalidProjection);
        }
        enforce_encoded_bound(self, MAX_SHARED_LANE_PROJECTION_BYTES)
    }
}

impl ServiceWire for SharedLaneProjection {
    const MAGIC: [u8; 4] = *b"AGLP";

    fn encode_body(&self, output: &mut Vec<u8>) {
        encode_lane_projection(&mut Encoder(output), self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SHARED_LANE_PROJECTION_BYTES)?;
        decode_lane_projection(decoder)
    }
}

/// Last Merge frontier finalized by the lifecycle fence named by a claim.
///
/// This is deliberately separate from the claim's observed Merge projection.
/// After a fence, physical replicas may have a newer active frontier; neither
/// those active events nor their ownership index are silently folded into the
/// sealed projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedSealedMergeProjection {
    seal: MergeSealId,
    frontier: MergeFrontierId,
    lane: SharedLaneProjection,
    invocations: InvocationIndexId,
}

impl SharedSealedMergeProjection {
    pub fn new(
        seal: MergeSealId,
        frontier: MergeFrontierId,
        lane: SharedLaneProjection,
        invocations: InvocationIndexId,
    ) -> Result<Self, SharedCommitError> {
        let projection = Self {
            seal,
            frontier,
            lane,
            invocations,
        };
        projection.validate()?;
        Ok(projection)
    }

    pub const fn seal(&self) -> MergeSealId {
        self.seal
    }

    pub const fn frontier(&self) -> MergeFrontierId {
        self.frontier
    }

    pub const fn lane(&self) -> &SharedLaneProjection {
        &self.lane
    }

    pub const fn invocations(&self) -> InvocationIndexId {
        self.invocations
    }

    pub fn verify_state(&self, bytes: &[u8]) -> Result<(), SharedCommitError> {
        self.lane.verify_state(bytes)
    }

    pub fn validate(&self) -> Result<(), SharedCommitError> {
        self.lane.validate()?;
        if self.seal == MergeSealId::ZERO
            || self.frontier == MergeFrontierId::ZERO
            || self.invocations == InvocationIndexId::ZERO
        {
            return Err(SharedCommitError::InvalidProjection);
        }
        enforce_encoded_bound(self, MAX_SHARED_SEALED_MERGE_PROJECTION_BYTES)
    }
}

impl ServiceWire for SharedSealedMergeProjection {
    const MAGIC: [u8; 4] = *b"AGMP";

    fn encode_body(&self, output: &mut Vec<u8>) {
        encode_sealed_merge_projection(&mut Encoder(output), self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SHARED_SEALED_MERGE_PROJECTION_BYTES)?;
        decode_sealed_merge_projection(decoder)
    }
}

/// Exact Agent-journal projection published for one committed Raft entry.
///
/// Physical heads IDs, publication revisions, Local state, and active Merge
/// state newer than `merge_frontier` are intentionally absent: those values
/// legitimately differ between replicas. `merge_invocations` is the ownership
/// root at the pinned, pre-transition observed frontier. `sealed_merge`, when
/// present, carries the distinct state and post-finalization ownership root
/// consumed by `merge_fence`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedCommitClaim {
    space: SpaceId,
    agent: AgentId,
    genesis: AgentJournalGenesisId,
    admission: AgentGenesisAdmissionId,
    committee: AgentReplicaCommitteeId,
    raft_index: u64,
    raft_term: u64,
    ordered: OrderedBase,
    merge_frontier: MergeFrontierId,
    merge: SharedLaneProjection,
    merge_invocations: InvocationIndexId,
    runtime: RuntimeBinding,
    control: SharedLaneProjection,
    linear: SharedLaneProjection,
    ordered_invocations: InvocationIndexId,
    artifacts: ArtifactClosureId,
    merge_fence: OrderedBase,
    sealed_merge: Option<SharedSealedMergeProjection>,
    fence_ancestry: Hash,
}

impl OrderedCommitClaim {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        genesis: AgentJournalGenesisId,
        admission: AgentGenesisAdmissionId,
        committee: AgentReplicaCommitteeId,
        raft_index: u64,
        raft_term: u64,
        ordered: OrderedBase,
        merge_frontier: MergeFrontierId,
        merge: SharedLaneProjection,
        merge_invocations: InvocationIndexId,
        runtime: RuntimeBinding,
        control: SharedLaneProjection,
        linear: SharedLaneProjection,
        ordered_invocations: InvocationIndexId,
        artifacts: ArtifactClosureId,
        merge_fence: OrderedBase,
        sealed_merge: Option<SharedSealedMergeProjection>,
        fence_ancestry: Hash,
    ) -> Result<Self, SharedCommitError> {
        let space = runtime.space;
        let agent = runtime.agent;
        let claim = Self {
            space,
            agent,
            genesis,
            admission,
            committee,
            raft_index,
            raft_term,
            ordered,
            merge_frontier,
            merge,
            merge_invocations,
            runtime,
            control,
            linear,
            ordered_invocations,
            artifacts,
            merge_fence,
            sealed_merge,
            fence_ancestry,
        };
        claim.validate()?;
        Ok(claim)
    }

    pub const fn space(&self) -> SpaceId {
        self.space
    }

    pub const fn agent(&self) -> AgentId {
        self.agent
    }

    pub const fn genesis(&self) -> AgentJournalGenesisId {
        self.genesis
    }

    pub const fn admission(&self) -> AgentGenesisAdmissionId {
        self.admission
    }

    pub const fn committee(&self) -> AgentReplicaCommitteeId {
        self.committee
    }

    pub const fn raft_index(&self) -> u64 {
        self.raft_index
    }

    pub const fn raft_term(&self) -> u64 {
        self.raft_term
    }

    /// Rebind this exact logical journal projection to a later authenticated
    /// Raft foundation. Snapshot construction uses this only after the
    /// physical ledger proves every intervening applied row is a leader no-op;
    /// ordinary Ordered commit certificates must keep their original slot.
    pub(crate) fn with_raft_foundation(
        &self,
        raft_index: u64,
        raft_term: u64,
    ) -> Result<Self, SharedCommitError> {
        let mut claim = self.clone();
        claim.raft_index = raft_index;
        claim.raft_term = raft_term;
        claim.validate()?;
        Ok(claim)
    }

    pub const fn ordered(&self) -> OrderedBase {
        self.ordered
    }

    pub const fn merge_frontier(&self) -> MergeFrontierId {
        self.merge_frontier
    }

    pub const fn merge(&self) -> &SharedLaneProjection {
        &self.merge
    }

    /// Ownership/history root at the exact observed pre-transition Merge
    /// frontier. A fence's optional sealed projection carries its distinct
    /// post-finalization root.
    pub const fn merge_invocations(&self) -> InvocationIndexId {
        self.merge_invocations
    }

    pub const fn runtime(&self) -> &RuntimeBinding {
        &self.runtime
    }

    pub const fn control(&self) -> &SharedLaneProjection {
        &self.control
    }

    pub const fn linear(&self) -> &SharedLaneProjection {
        &self.linear
    }

    pub const fn ordered_invocations(&self) -> InvocationIndexId {
        self.ordered_invocations
    }

    pub const fn artifacts(&self) -> ArtifactClosureId {
        self.artifacts
    }

    pub const fn merge_fence(&self) -> OrderedBase {
        self.merge_fence
    }

    pub const fn sealed_merge(&self) -> Option<&SharedSealedMergeProjection> {
        self.sealed_merge.as_ref()
    }

    pub const fn merge_seal(&self) -> Option<MergeSealId> {
        match &self.sealed_merge {
            Some(projection) => Some(projection.seal),
            None => None,
        }
    }

    pub const fn fence_ancestry(&self) -> Hash {
        self.fence_ancestry
    }

    /// Stable content commitment signed by replica voters.
    pub fn commitment(&self) -> Hash {
        Hash::digest(ORDERED_COMMIT_CLAIM_DOMAIN, &[&self.encode()])
    }

    pub fn validate(&self) -> Result<(), SharedCommitError> {
        self.runtime
            .validate()
            .map_err(|_| SharedCommitError::InvalidClaim)?;
        self.ordered
            .validate()
            .map_err(|_| SharedCommitError::InvalidClaim)?;
        self.merge_fence
            .validate()
            .map_err(|_| SharedCommitError::InvalidClaim)?;
        self.merge.validate()?;
        self.control.validate()?;
        self.linear.validate()?;
        if let Some(sealed) = &self.sealed_merge {
            sealed.validate()?;
        }

        let projected_state_bytes = self
            .control
            .state
            .len
            .checked_add(self.linear.state.len)
            .and_then(|bytes| bytes.checked_add(self.merge.state.len))
            .ok_or(SharedCommitError::StateLimitExceeded)?;

        if self.space == SpaceId::ZERO
            || self.agent == AgentId::ZERO
            || self.runtime.space != self.space
            || self.runtime.agent != self.agent
            || self.genesis == AgentJournalGenesisId::ZERO
            || self.admission == AgentGenesisAdmissionId::ZERO
            || self.committee == AgentReplicaCommitteeId::ZERO
            || self.raft_index == 0
            || self.raft_term == 0
            || self.ordered.index == 0
            || self.ordered.head.is_none()
            || self.merge_frontier == MergeFrontierId::ZERO
            || self.merge_invocations == InvocationIndexId::ZERO
            || self.ordered_invocations == InvocationIndexId::ZERO
            || self.artifacts == ArtifactClosureId::ZERO
            || self.fence_ancestry == Hash::ZERO
            || projected_state_bytes > MAX_RUNTIME_STATE_BYTES as u64
            || self.merge_fence.index > self.ordered.index
            || (self.merge_fence.index == self.ordered.index
                && self.merge_fence.head != self.ordered.head)
            || ((self.merge_fence == OrderedBase::post_genesis()) != self.sealed_merge.is_none())
        {
            return Err(SharedCommitError::InvalidClaim);
        }

        // A claim produced by the fence entry itself must pin the exact
        // frontier and state the seal finalized. Later ordered entries retain
        // that sealed projection while their observed Merge frontier may move.
        if self.merge_fence == self.ordered
            && self.sealed_merge.as_ref().is_none_or(|sealed| {
                sealed.frontier != self.merge_frontier || sealed.lane != self.merge
            })
        {
            return Err(SharedCommitError::InvalidClaim);
        }

        enforce_encoded_bound(self, MAX_ORDERED_COMMIT_CLAIM_BYTES)
    }
}

impl ServiceWire for OrderedCommitClaim {
    const MAGIC: [u8; 4] = *b"AGOC";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.space.0);
        encoder.fixed(&self.agent.0);
        encoder.fixed(self.genesis.as_bytes());
        encoder.fixed(self.admission.as_bytes());
        encoder.fixed(self.committee.as_bytes());
        encoder.u64(self.raft_index);
        encoder.u64(self.raft_term);
        encode_ordered_base(&mut encoder, self.ordered);
        encoder.fixed(self.merge_frontier.as_bytes());
        encode_lane_projection(&mut encoder, &self.merge);
        encoder.fixed(self.merge_invocations.as_bytes());
        encode_runtime_binding(&mut encoder, &self.runtime);
        encode_lane_projection(&mut encoder, &self.control);
        encode_lane_projection(&mut encoder, &self.linear);
        encoder.fixed(self.ordered_invocations.as_bytes());
        encoder.fixed(self.artifacts.as_bytes());
        encode_ordered_base(&mut encoder, self.merge_fence);
        encoder.option(&self.sealed_merge, encode_sealed_merge_projection);
        encoder.fixed(&self.fence_ancestry.0);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_ORDERED_COMMIT_CLAIM_BYTES)?;
        let claim = Self {
            space: SpaceId(decoder.fixed()?),
            agent: AgentId(decoder.fixed()?),
            genesis: AgentJournalGenesisId(decoder.fixed()?),
            admission: AgentGenesisAdmissionId::from_bytes(decoder.fixed()?),
            committee: AgentReplicaCommitteeId::from_bytes(decoder.fixed()?),
            raft_index: decoder.u64()?,
            raft_term: decoder.u64()?,
            ordered: decode_ordered_base(decoder)?,
            merge_frontier: MergeFrontierId(decoder.fixed()?),
            merge: decode_lane_projection(decoder)?,
            merge_invocations: InvocationIndexId(decoder.fixed()?),
            runtime: decode_runtime_binding(decoder)?,
            control: decode_lane_projection(decoder)?,
            linear: decode_lane_projection(decoder)?,
            ordered_invocations: InvocationIndexId(decoder.fixed()?),
            artifacts: ArtifactClosureId(decoder.fixed()?),
            merge_fence: decode_ordered_base(decoder)?,
            sealed_merge: decoder.option(decode_sealed_merge_projection)?,
            fence_ancestry: Hash(decoder.fixed()?),
        };
        claim.validate().map_err(map_decode_error)?;
        Ok(claim)
    }
}

/// One canonical Ed25519 signature by an admitted replica node.
///
/// Signatures are ordered by full [`NodeId`]. The admitted committee binds
/// that node to the complete PeerId, raw Ed25519 key, role, principal, and
/// collision-free Raft slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaCommitSignature {
    signer: NodeId,
    signature: [u8; REPLICA_COMMIT_ED25519_SIGNATURE_BYTES],
}

impl ReplicaCommitSignature {
    pub fn new(
        signer: NodeId,
        signature: [u8; REPLICA_COMMIT_ED25519_SIGNATURE_BYTES],
    ) -> Result<Self, SharedCommitError> {
        let signature = Self { signer, signature };
        signature.validate()?;
        Ok(signature)
    }

    pub const fn signer(&self) -> NodeId {
        self.signer
    }

    pub const fn signature(&self) -> &[u8; REPLICA_COMMIT_ED25519_SIGNATURE_BYTES] {
        &self.signature
    }

    pub fn validate(&self) -> Result<(), SharedCommitError> {
        if self.signer == NodeId::ZERO {
            return Err(SharedCommitError::InvalidSigner);
        }
        enforce_encoded_bound(self, MAX_REPLICA_COMMIT_SIGNATURE_BYTES)
    }
}

impl ServiceWire for ReplicaCommitSignature {
    const MAGIC: [u8; 4] = *b"AGRS";

    fn encode_body(&self, output: &mut Vec<u8>) {
        encode_replica_signature(&mut Encoder(output), self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_REPLICA_COMMIT_SIGNATURE_BYTES)?;
        decode_replica_signature(decoder)
    }
}

/// Majority application certificate for one exact ordered publication.
///
/// Construction and decoding validate only bounded canonical shape. Call
/// [`Self::verify`] with the independently admitted exact committee before
/// treating the claim as replay, snapshot, observer, or compaction authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaQuorumCertificate {
    committee: AgentReplicaCommitteeId,
    claim: OrderedCommitClaim,
    signatures: Vec<ReplicaCommitSignature>,
}

impl ReplicaQuorumCertificate {
    pub fn new(
        claim: OrderedCommitClaim,
        signatures: Vec<ReplicaCommitSignature>,
    ) -> Result<Self, SharedCommitError> {
        let certificate = Self {
            committee: claim.committee,
            claim,
            signatures,
        };
        certificate.validate_shape()?;
        Ok(certificate)
    }

    pub const fn committee(&self) -> AgentReplicaCommitteeId {
        self.committee
    }

    pub const fn claim(&self) -> &OrderedCommitClaim {
        &self.claim
    }

    pub fn signatures(&self) -> &[ReplicaCommitSignature] {
        &self.signatures
    }

    /// Canonical hash given to independently held replica signing keys.
    pub fn signing_message(committee: AgentReplicaCommitteeId, claim: Hash) -> Hash {
        Hash::digest(
            REPLICA_COMMIT_MESSAGE_DOMAIN,
            &[committee.as_bytes(), &claim.0],
        )
    }

    pub fn message(&self) -> Hash {
        Self::signing_message(self.committee, self.claim.commitment())
    }

    /// Stable content commitment to the complete claim and signature set.
    pub fn commitment(&self) -> Hash {
        Hash::digest(REPLICA_QUORUM_CERTIFICATE_DOMAIN, &[&self.encode()])
    }

    /// Promote this untrusted wire certificate using an independently
    /// admitted exact committee and an exact claim expected by the caller.
    pub fn verify(
        &self,
        trusted_committee: &AgentReplicaCommittee,
        expected_claim: &OrderedCommitClaim,
    ) -> Result<VerifiedOrderedCommit, SharedCommitError> {
        trusted_committee
            .validate()
            .map_err(|_| SharedCommitError::InvalidCommittee)?;
        self.validate_shape()?;
        expected_claim.validate()?;

        if trusted_committee.profile() != AgentProfile::Shared {
            return Err(SharedCommitError::InvalidCommittee);
        }
        if &self.claim != expected_claim {
            return Err(SharedCommitError::WrongClaim);
        }

        let trusted_id = trusted_committee.id();
        if self.committee != trusted_id
            || self.claim.committee != trusted_id
            || self.claim.space != trusted_committee.space()
            || self.claim.agent != trusted_committee.agent()
        {
            return Err(SharedCommitError::WrongCommittee);
        }
        if self.signatures.len() < trusted_committee.quorum_threshold() {
            return Err(SharedCommitError::InsufficientQuorum);
        }

        let message = self.message();
        for replica_signature in &self.signatures {
            let member = trusted_committee
                .member_by_node(replica_signature.signer)
                .ok_or(SharedCommitError::UnknownSigner)?;
            if member.replica().role != ReplicaRole::Voter {
                return Err(SharedCommitError::ObserverSignature);
            }
            if !verify_ed25519(
                member.ed25519_public_key(),
                &message.0,
                &replica_signature.signature,
            ) {
                return Err(SharedCommitError::InvalidSignature);
            }
        }

        Ok(VerifiedOrderedCommit {
            claim: self.claim.clone(),
            certificate_commitment: self.commitment(),
        })
    }

    fn validate_shape(&self) -> Result<(), SharedCommitError> {
        self.claim.validate()?;
        if self.committee == AgentReplicaCommitteeId::ZERO || self.committee != self.claim.committee
        {
            return Err(SharedCommitError::InvalidCertificate);
        }
        if self.signatures.is_empty() {
            return Err(SharedCommitError::InsufficientQuorum);
        }
        if self.signatures.len() > MAX_REPLICA_COMMIT_SIGNATURES {
            return Err(SharedCommitError::CertificateTooLarge);
        }
        for (index, signature) in self.signatures.iter().enumerate() {
            signature.validate()?;
            if let Some(previous) = index.checked_sub(1).map(|index| &self.signatures[index]) {
                if previous.signer >= signature.signer {
                    return Err(SharedCommitError::NonCanonicalOrder);
                }
            }
        }
        enforce_encoded_bound(self, MAX_REPLICA_QUORUM_CERTIFICATE_BYTES)
    }
}

impl ServiceWire for ReplicaQuorumCertificate {
    const MAGIC: [u8; 4] = *b"AGRQ";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(self.committee.as_bytes());
        encoder.bytes(&self.claim.encode());
        encoder.u32(self.signatures.len() as u32);
        for signature in &self.signatures {
            encode_replica_signature(&mut encoder, signature);
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_REPLICA_QUORUM_CERTIFICATE_BYTES)?;
        let committee = AgentReplicaCommitteeId::from_bytes(decoder.fixed()?);
        let claim = decode_nested::<OrderedCommitClaim>(decoder, MAX_ORDERED_COMMIT_CLAIM_BYTES)?;
        let count = decoder.u32()? as usize;
        if count > MAX_REPLICA_COMMIT_SIGNATURES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut signatures = Vec::new();
        signatures
            .try_reserve_exact(count)
            .map_err(|_| DecodeError::LimitExceeded)?;
        for _ in 0..count {
            signatures.push(decode_replica_signature(decoder)?);
        }
        let certificate = Self {
            committee,
            claim,
            signatures,
        };
        certificate.validate_shape().map_err(map_decode_error)?;
        Ok(certificate)
    }
}

/// Complete identity of one Agent-specific journal/Raft checkpoint.
///
/// The ordinary ordered claim authenticates the portable Shared projection at
/// the selected Raft slot.  A checkpoint additionally commits the exact local
/// journal envelope and its compacted lane/catalog roots, so those values are
/// signed rather than inferred from a snapshot byte stream.  `active_committee`
/// is repeated in full: its ID must equal the route committee carried by
/// `ordered`, and snapshot verification never obtains a committee from the
/// untrusted certificate itself without comparing that complete value to the
/// independently recovered committee-transition state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedAgentSnapshotClaim {
    ordered: OrderedCommitClaim,
    active_committee: AgentReplicaCommittee,
    authority_epoch: u64,
    journal_store: Hash,
    boundary_payload_commitment: Hash,
    ordered_successor: JournalHeadsId,
    checkpoint_predecessor: JournalHeadsId,
    journal_heads: JournalHeadsId,
    checkpoint: CheckpointId,
    local_node: NodeId,
    control: LaneStateId,
    linear: LaneStateId,
    merge: LaneStateId,
    local: LaneStateId,
    ordered_invocations: InvocationIndexId,
    merge_invocations: InvocationIndexId,
    local_invocations: InvocationIndexId,
    artifacts: ArtifactClosureId,
    retired_audit_root: Hash,
    committee_evidence_root: Hash,
    previous_snapshot: Option<Hash>,
}

impl SharedAgentSnapshotClaim {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ordered: OrderedCommitClaim,
        active_committee: AgentReplicaCommittee,
        authority_epoch: u64,
        journal_store: Hash,
        boundary_payload_commitment: Hash,
        ordered_successor: JournalHeadsId,
        checkpoint_predecessor: JournalHeadsId,
        journal_heads: JournalHeadsId,
        checkpoint: CheckpointId,
        local_node: NodeId,
        control: LaneStateId,
        linear: LaneStateId,
        merge: LaneStateId,
        local: LaneStateId,
        ordered_invocations: InvocationIndexId,
        merge_invocations: InvocationIndexId,
        local_invocations: InvocationIndexId,
        artifacts: ArtifactClosureId,
        retired_audit_root: Hash,
        committee_evidence_root: Hash,
        previous_snapshot: Option<Hash>,
    ) -> Result<Self, SharedCommitError> {
        let claim = Self {
            ordered,
            active_committee,
            authority_epoch,
            journal_store,
            boundary_payload_commitment,
            ordered_successor,
            checkpoint_predecessor,
            journal_heads,
            checkpoint,
            local_node,
            control,
            linear,
            merge,
            local,
            ordered_invocations,
            merge_invocations,
            local_invocations,
            artifacts,
            retired_audit_root,
            committee_evidence_root,
            previous_snapshot,
        };
        claim.validate()?;
        Ok(claim)
    }

    pub const fn ordered(&self) -> &OrderedCommitClaim {
        &self.ordered
    }

    pub const fn active_committee(&self) -> &AgentReplicaCommittee {
        &self.active_committee
    }

    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    /// Stable identity of the physical journal store paired with this Raft
    /// generation. This prevents a copied checkpoint from becoming valid in
    /// another otherwise byte-identical store.
    pub const fn journal_store(&self) -> Hash {
        self.journal_store
    }

    pub const fn boundary_payload_commitment(&self) -> Hash {
        self.boundary_payload_commitment
    }

    pub const fn ordered_successor(&self) -> JournalHeadsId {
        self.ordered_successor
    }

    /// Exact current journal head from which the checkpoint publication was
    /// derived. This may be later than `ordered_successor` when authenticated
    /// Merge or Local work followed the selected Ordered boundary.
    pub const fn checkpoint_predecessor(&self) -> JournalHeadsId {
        self.checkpoint_predecessor
    }

    pub const fn journal_heads(&self) -> JournalHeadsId {
        self.journal_heads
    }

    pub const fn checkpoint(&self) -> CheckpointId {
        self.checkpoint
    }

    pub const fn local_node(&self) -> NodeId {
        self.local_node
    }

    pub const fn control(&self) -> LaneStateId {
        self.control
    }

    pub const fn linear(&self) -> LaneStateId {
        self.linear
    }

    pub const fn merge(&self) -> LaneStateId {
        self.merge
    }

    pub const fn local(&self) -> LaneStateId {
        self.local
    }

    pub const fn ordered_invocations(&self) -> InvocationIndexId {
        self.ordered_invocations
    }

    pub const fn merge_invocations(&self) -> InvocationIndexId {
        self.merge_invocations
    }

    pub const fn local_invocations(&self) -> InvocationIndexId {
        self.local_invocations
    }

    pub const fn artifacts(&self) -> ArtifactClosureId {
        self.artifacts
    }

    pub const fn retired_audit_root(&self) -> Hash {
        self.retired_audit_root
    }

    pub const fn committee_evidence_root(&self) -> Hash {
        self.committee_evidence_root
    }

    pub const fn previous_snapshot(&self) -> Option<Hash> {
        self.previous_snapshot
    }

    pub const fn raft_index(&self) -> u64 {
        self.ordered.raft_index
    }

    pub const fn raft_term(&self) -> u64 {
        self.ordered.raft_term
    }

    /// Stable hash signed by the active voter majority.
    pub fn commitment(&self) -> Hash {
        Hash::digest(AGENT_SNAPSHOT_CLAIM_DOMAIN, &[&self.encode()])
    }

    pub fn validate(&self) -> Result<(), SharedCommitError> {
        self.ordered.validate()?;
        self.active_committee
            .validate()
            .map_err(|_| SharedCommitError::InvalidCommittee)?;
        if self.active_committee.profile() != AgentProfile::Shared
            || self.active_committee.space() != self.ordered.space
            || self.active_committee.agent() != self.ordered.agent
            || self.active_committee.id() != self.ordered.committee
            || self
                .active_committee
                .member_by_node(self.local_node)
                .is_none()
            || self.authority_epoch == 0
            || self.journal_store == Hash::ZERO
            || self.boundary_payload_commitment == Hash::ZERO
            || self.ordered_successor == JournalHeadsId::ZERO
            || self.checkpoint_predecessor == JournalHeadsId::ZERO
            || self.journal_heads == JournalHeadsId::ZERO
            || self.checkpoint == CheckpointId::ZERO
            || self.local_node == NodeId::ZERO
            || self.control == LaneStateId::ZERO
            || self.linear == LaneStateId::ZERO
            || self.merge == LaneStateId::ZERO
            || self.local == LaneStateId::ZERO
            || self.ordered_invocations == InvocationIndexId::ZERO
            || self.merge_invocations == InvocationIndexId::ZERO
            || self.local_invocations == InvocationIndexId::ZERO
            || self.artifacts == ArtifactClosureId::ZERO
            || self.retired_audit_root == Hash::ZERO
            || self.committee_evidence_root == Hash::ZERO
            || self.previous_snapshot == Some(Hash::ZERO)
        {
            return Err(SharedCommitError::InvalidSnapshotClaim);
        }
        enforce_encoded_bound(self, MAX_SHARED_AGENT_SNAPSHOT_CLAIM_BYTES)
    }
}

impl ServiceWire for SharedAgentSnapshotClaim {
    const MAGIC: [u8; 4] = *b"AGS3";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.ordered.encode());
        encoder.bytes(&self.active_committee.encode());
        encoder.u64(self.authority_epoch);
        encoder.fixed(&self.journal_store.0);
        encoder.fixed(&self.boundary_payload_commitment.0);
        encoder.fixed(self.ordered_successor.as_bytes());
        encoder.fixed(self.checkpoint_predecessor.as_bytes());
        encoder.fixed(self.journal_heads.as_bytes());
        encoder.fixed(self.checkpoint.as_bytes());
        encoder.fixed(&self.local_node.0);
        encoder.fixed(self.control.as_bytes());
        encoder.fixed(self.linear.as_bytes());
        encoder.fixed(self.merge.as_bytes());
        encoder.fixed(self.local.as_bytes());
        encoder.fixed(self.ordered_invocations.as_bytes());
        encoder.fixed(self.merge_invocations.as_bytes());
        encoder.fixed(self.local_invocations.as_bytes());
        encoder.fixed(self.artifacts.as_bytes());
        encoder.fixed(&self.retired_audit_root.0);
        encoder.fixed(&self.committee_evidence_root.0);
        encoder.option(&self.previous_snapshot, |encoder, previous| {
            encoder.fixed(&previous.0)
        });
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SHARED_AGENT_SNAPSHOT_CLAIM_BYTES)?;
        let claim = Self {
            ordered: decode_nested::<OrderedCommitClaim>(decoder, MAX_ORDERED_COMMIT_CLAIM_BYTES)?,
            active_committee: decode_nested::<AgentReplicaCommittee>(
                decoder,
                super::genesis::MAX_AGENT_REPLICA_COMMITTEE_BYTES,
            )?,
            authority_epoch: decoder.u64()?,
            journal_store: Hash(decoder.fixed()?),
            boundary_payload_commitment: Hash(decoder.fixed()?),
            ordered_successor: JournalHeadsId(decoder.fixed()?),
            checkpoint_predecessor: JournalHeadsId(decoder.fixed()?),
            journal_heads: JournalHeadsId(decoder.fixed()?),
            checkpoint: CheckpointId(decoder.fixed()?),
            local_node: NodeId(decoder.fixed()?),
            control: LaneStateId(decoder.fixed()?),
            linear: LaneStateId(decoder.fixed()?),
            merge: LaneStateId(decoder.fixed()?),
            local: LaneStateId(decoder.fixed()?),
            ordered_invocations: InvocationIndexId(decoder.fixed()?),
            merge_invocations: InvocationIndexId(decoder.fixed()?),
            local_invocations: InvocationIndexId(decoder.fixed()?),
            artifacts: ArtifactClosureId(decoder.fixed()?),
            retired_audit_root: Hash(decoder.fixed()?),
            committee_evidence_root: Hash(decoder.fixed()?),
            previous_snapshot: decoder.option(|decoder| Ok(Hash(decoder.fixed()?)))?,
        };
        claim.validate().map_err(map_decode_error)?;
        Ok(claim)
    }
}

/// Voter-majority authentication for one exact Agent checkpoint claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedAgentSnapshotCertificate {
    claim: SharedAgentSnapshotClaim,
    signatures: Vec<ReplicaCommitSignature>,
}

impl SharedAgentSnapshotCertificate {
    pub fn new(
        claim: SharedAgentSnapshotClaim,
        signatures: Vec<ReplicaCommitSignature>,
    ) -> Result<Self, SharedCommitError> {
        let certificate = Self { claim, signatures };
        certificate.validate_shape()?;
        Ok(certificate)
    }

    pub const fn claim(&self) -> &SharedAgentSnapshotClaim {
        &self.claim
    }

    pub fn signatures(&self) -> &[ReplicaCommitSignature] {
        &self.signatures
    }

    pub(crate) fn signing_message(committee: AgentReplicaCommitteeId, claim: Hash) -> Hash {
        Hash::digest(
            AGENT_SNAPSHOT_MESSAGE_DOMAIN,
            &[committee.as_bytes(), &claim.0],
        )
    }

    pub(crate) fn message(&self) -> Hash {
        Self::signing_message(self.claim.active_committee.id(), self.claim.commitment())
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(AGENT_SNAPSHOT_CERTIFICATE_DOMAIN, &[&self.encode()])
    }

    /// Verify against both the independently recovered active committee and
    /// the exact locally reconstructed checkpoint claim.
    pub fn verify(
        &self,
        trusted_committee: &AgentReplicaCommittee,
        expected_claim: &SharedAgentSnapshotClaim,
    ) -> Result<VerifiedSharedAgentSnapshot, SharedCommitError> {
        trusted_committee
            .validate()
            .map_err(|_| SharedCommitError::InvalidCommittee)?;
        self.validate_shape()?;
        expected_claim.validate()?;
        if &self.claim != expected_claim {
            return Err(SharedCommitError::WrongSnapshotClaim);
        }
        if trusted_committee != self.claim.active_committee()
            || trusted_committee.id() != self.claim.ordered.committee
        {
            return Err(SharedCommitError::WrongCommittee);
        }
        if self.signatures.len() < trusted_committee.quorum_threshold() {
            return Err(SharedCommitError::InsufficientQuorum);
        }
        let message = self.message();
        for signature in &self.signatures {
            let member = trusted_committee
                .member_by_node(signature.signer)
                .ok_or(SharedCommitError::UnknownSigner)?;
            if member.replica().role != ReplicaRole::Voter {
                return Err(SharedCommitError::ObserverSignature);
            }
            if !verify_ed25519(
                member.ed25519_public_key(),
                &message.0,
                &signature.signature,
            ) {
                return Err(SharedCommitError::InvalidSignature);
            }
        }
        Ok(VerifiedSharedAgentSnapshot {
            claim: self.claim.clone(),
            certificate_commitment: self.commitment(),
        })
    }

    fn validate_shape(&self) -> Result<(), SharedCommitError> {
        self.claim.validate()?;
        if self.signatures.is_empty() {
            return Err(SharedCommitError::InsufficientQuorum);
        }
        if self.signatures.len() > MAX_REPLICA_COMMIT_SIGNATURES {
            return Err(SharedCommitError::CertificateTooLarge);
        }
        for (index, signature) in self.signatures.iter().enumerate() {
            signature.validate()?;
            if let Some(previous) = index.checked_sub(1).map(|index| &self.signatures[index])
                && previous.signer >= signature.signer
            {
                return Err(SharedCommitError::NonCanonicalOrder);
            }
        }
        enforce_encoded_bound(self, MAX_SHARED_AGENT_SNAPSHOT_CERTIFICATE_BYTES)
    }
}

impl ServiceWire for SharedAgentSnapshotCertificate {
    const MAGIC: [u8; 4] = *b"AGQ3";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.claim.encode());
        encoder.u32(self.signatures.len() as u32);
        for signature in &self.signatures {
            encode_replica_signature(&mut encoder, signature);
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SHARED_AGENT_SNAPSHOT_CERTIFICATE_BYTES)?;
        let claim = decode_nested::<SharedAgentSnapshotClaim>(
            decoder,
            MAX_SHARED_AGENT_SNAPSHOT_CLAIM_BYTES,
        )?;
        let count = decoder.u32()? as usize;
        if count > MAX_REPLICA_COMMIT_SIGNATURES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut signatures = Vec::new();
        signatures
            .try_reserve_exact(count)
            .map_err(|_| DecodeError::LimitExceeded)?;
        for _ in 0..count {
            signatures.push(decode_replica_signature(decoder)?);
        }
        let certificate = Self { claim, signatures };
        certificate.validate_shape().map_err(map_decode_error)?;
        Ok(certificate)
    }
}

/// Process-local result of exact committee and claim verification.
#[derive(Clone, Debug)]
pub struct VerifiedSharedAgentSnapshot {
    claim: SharedAgentSnapshotClaim,
    certificate_commitment: Hash,
}

impl VerifiedSharedAgentSnapshot {
    pub const fn claim(&self) -> &SharedAgentSnapshotClaim {
        &self.claim
    }

    pub const fn certificate_commitment(&self) -> Hash {
        self.certificate_commitment
    }
}

/// Common checkpoint authority for the fixed-three-voter, Ordered-only path.
/// Voters compare this against independently applied durable state before
/// signing. Local/active Merge work is excluded by the checked host capability,
/// not by pretending that foreign physical heads equal local physical heads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedAgentCommonSnapshotClaim {
    ordered: OrderedCommitClaim,
    active_committee: AgentReplicaCommittee,
    authority_epoch: u64,
    ancestry: SharedAgentCommonSnapshotAncestry,
    // None is the original AGC1 meaning, not permission to drop recovery
    // obligations. AGC2 additionally authenticates the complete bounded
    // per-owner recovery manifest at this exact physical Raft foundation.
    recovery_manifest: Option<Hash>,
}

/// Bounded preimage of the existing Ordered fence-ancestry commitment. Physical
/// checkpoint cadence must not change the semantic ancestry seen by peers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedAgentCommonSnapshotAncestry {
    checkpoint_base: OrderedBase,
    ordered_anchor: Hash,
}

impl SharedAgentCommonSnapshotAncestry {
    pub fn new(
        checkpoint_base: OrderedBase,
        ordered_anchor: Hash,
    ) -> Result<Self, SharedCommitError> {
        if checkpoint_base.validate().is_err() || ordered_anchor == Hash::ZERO {
            return Err(SharedCommitError::InvalidSnapshotClaim);
        }
        Ok(Self {
            checkpoint_base,
            ordered_anchor,
        })
    }
    pub const fn checkpoint_base(&self) -> OrderedBase {
        self.checkpoint_base
    }
    pub const fn ordered_anchor(&self) -> Hash {
        self.ordered_anchor
    }
    pub(crate) fn commitment_for(&self, ordered: &OrderedCommitClaim) -> Hash {
        fn base_bytes(base: OrderedBase) -> [u8; 41] {
            let mut bytes = [0; 41];
            bytes[0] = u8::from(base.head.is_some());
            bytes[1..9].copy_from_slice(&base.index.to_le_bytes());
            if let Some(head) = base.head {
                bytes[9..].copy_from_slice(&head.0);
            }
            bytes
        }
        Hash::digest(
            b"vos/agent/replay/fence-ancestry-evidence",
            &[
                &ordered.genesis().0,
                &base_bytes(self.checkpoint_base),
                &base_bytes(ordered.ordered()),
                &base_bytes(ordered.merge_fence()),
                &self.ordered_anchor.0,
            ],
        )
    }
}

impl SharedAgentCommonSnapshotClaim {
    pub fn new(
        ordered: OrderedCommitClaim,
        active_committee: AgentReplicaCommittee,
        authority_epoch: u64,
        ancestry: SharedAgentCommonSnapshotAncestry,
    ) -> Result<Self, SharedCommitError> {
        let claim = Self {
            ordered,
            active_committee,
            authority_epoch,
            ancestry,
            recovery_manifest: None,
        };
        claim.validate()?;
        Ok(claim)
    }

    pub const fn ordered(&self) -> &OrderedCommitClaim {
        &self.ordered
    }
    pub const fn active_committee(&self) -> &AgentReplicaCommittee {
        &self.active_committee
    }
    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }
    pub const fn ancestry(&self) -> &SharedAgentCommonSnapshotAncestry {
        &self.ancestry
    }
    pub const fn recovery_manifest(&self) -> Option<Hash> {
        self.recovery_manifest
    }
    pub fn with_recovery_manifest(mut self, commitment: Hash) -> Result<Self, SharedCommitError> {
        self.recovery_manifest = Some(commitment);
        self.validate()?;
        Ok(self)
    }
    pub fn commitment(&self) -> Hash {
        let domain = if self.recovery_manifest.is_some() {
            COMMON_RECOVERY_SNAPSHOT_CLAIM_DOMAIN
        } else {
            COMMON_SNAPSHOT_CLAIM_DOMAIN
        };
        Hash::digest(domain, &[&self.encode()])
    }

    pub fn validate(&self) -> Result<(), SharedCommitError> {
        self.ordered.validate()?;
        self.active_committee
            .validate()
            .map_err(|_| SharedCommitError::InvalidCommittee)?;
        if self.authority_epoch == 0
            || self.recovery_manifest == Some(Hash::ZERO)
            || self.active_committee.profile() != AgentProfile::Shared
            || self.active_committee.members().len() != 3
            || self.active_committee.voter_count() != 3
            || self.active_committee.space() != self.ordered.space()
            || self.active_committee.agent() != self.ordered.agent()
            || self.active_committee.id() != self.ordered.committee()
            || self.ancestry.checkpoint_base.validate().is_err()
            || self.ancestry.ordered_anchor == Hash::ZERO
            || self.ancestry.checkpoint_base.index > self.ordered.ordered().index
            || (self.ancestry.checkpoint_base.index == self.ordered.ordered().index
                && self.ancestry.checkpoint_base.head != self.ordered.ordered().head)
            || self.ancestry.commitment_for(&self.ordered) != self.ordered.fence_ancestry()
        {
            return Err(SharedCommitError::InvalidSnapshotClaim);
        }
        enforce_encoded_bound(self, MAX_SHARED_AGENT_COMMON_SNAPSHOT_CLAIM_BYTES)
    }

    /// Common fields only. Physical lane state preimages, indexes and allowed
    /// checkpoint transformations must additionally be verified by replay.
    pub(crate) fn matches_physical_scope(&self, physical: &SharedAgentSnapshotClaim) -> bool {
        self.ordered() == physical.ordered()
            && self.active_committee() == physical.active_committee()
            && self.authority_epoch() == physical.authority_epoch()
            && self.ordered().ordered_invocations() == physical.ordered_invocations()
            && self.ordered().artifacts() == physical.artifacts()
    }
}

impl ServiceWire for SharedAgentCommonSnapshotClaim {
    const MAGIC: [u8; 4] = *b"AGC1";
    fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(if self.recovery_manifest.is_some() {
            b"AGC2"
        } else {
            &Self::MAGIC
        });
        output.extend_from_slice(&crate::service::PLATFORM_ID.0);
        self.encode_body(&mut output);
        output
    }
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let recovery = match decoder.take(4)? {
            b"AGC1" => false,
            b"AGC2" => true,
            _ => return Err(DecodeError::InvalidTag),
        };
        if Hash(decoder.fixed()?) != crate::service::PLATFORM_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let value = Self::decode_body(&mut decoder)?;
        if !decoder.exhausted() || value.recovery_manifest.is_some() != recovery {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
    fn encode_body(&self, output: &mut Vec<u8>) {
        let encoder = &mut Encoder(output);
        encoder.bytes(&self.ordered.encode());
        encoder.bytes(&self.active_committee.encode());
        encoder.u64(self.authority_epoch);
        encode_ordered_base(encoder, self.ancestry.checkpoint_base);
        encoder.fixed(&self.ancestry.ordered_anchor.0);
        if let Some(commitment) = self.recovery_manifest {
            encoder.fixed(&commitment.0);
        }
    }
    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SHARED_AGENT_COMMON_SNAPSHOT_CLAIM_BYTES)?;
        let mut claim = Self::new(
            decode_nested::<OrderedCommitClaim>(decoder, MAX_ORDERED_COMMIT_CLAIM_BYTES)?,
            decode_nested::<AgentReplicaCommittee>(
                decoder,
                super::genesis::MAX_AGENT_REPLICA_COMMITTEE_BYTES,
            )?,
            decoder.u64()?,
            SharedAgentCommonSnapshotAncestry::new(
                decode_ordered_base(decoder)?,
                Hash(decoder.fixed()?),
            )
            .map_err(map_decode_error)?,
        )
        .map_err(map_decode_error)?;
        if !decoder.exhausted() {
            claim = claim
                .with_recovery_manifest(Hash(decoder.fixed()?))
                .map_err(map_decode_error)?;
        }
        Ok(claim)
    }
}

/// Two distinct admitted voters certify one common state, never two different
/// node/store-bound AGS3 claims. This alone is not a physical publication token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedAgentCommonSnapshotCertificate {
    claim: SharedAgentCommonSnapshotClaim,
    signatures: Vec<ReplicaCommitSignature>,
}

impl SharedAgentCommonSnapshotCertificate {
    pub fn new(
        claim: SharedAgentCommonSnapshotClaim,
        signatures: Vec<ReplicaCommitSignature>,
    ) -> Result<Self, SharedCommitError> {
        let certificate = Self { claim, signatures };
        certificate.validate_shape()?;
        Ok(certificate)
    }
    pub const fn claim(&self) -> &SharedAgentCommonSnapshotClaim {
        &self.claim
    }
    pub fn signatures(&self) -> &[ReplicaCommitSignature] {
        &self.signatures
    }
    pub fn commitment(&self) -> Hash {
        Hash::digest(COMMON_SNAPSHOT_CERTIFICATE_DOMAIN, &[&self.encode()])
    }
    pub(crate) fn signing_message(committee: AgentReplicaCommitteeId, claim: Hash) -> Hash {
        Hash::digest(
            COMMON_SNAPSHOT_MESSAGE_DOMAIN,
            &[committee.as_bytes(), &claim.0],
        )
    }
    pub fn verify(
        &self,
        trusted_committee: &AgentReplicaCommittee,
        expected: &SharedAgentCommonSnapshotClaim,
    ) -> Result<VerifiedSharedAgentCommonSnapshot, SharedCommitError> {
        self.validate_shape()?;
        expected.validate()?;
        if expected != &self.claim {
            return Err(SharedCommitError::WrongSnapshotClaim);
        }
        if trusted_committee != self.claim.active_committee() {
            return Err(SharedCommitError::WrongCommittee);
        }
        if self.signatures.len() < trusted_committee.quorum_threshold() {
            return Err(SharedCommitError::InsufficientQuorum);
        }
        let message = Self::signing_message(trusted_committee.id(), self.claim.commitment());
        for signature in &self.signatures {
            verify_snapshot_member_signature(trusted_committee, signature, message)?;
        }
        Ok(VerifiedSharedAgentCommonSnapshot {
            claim: self.claim.clone(),
            certificate_commitment: self.commitment(),
        })
    }
    fn validate_shape(&self) -> Result<(), SharedCommitError> {
        self.claim.validate()?;
        if self.signatures.is_empty() {
            return Err(SharedCommitError::InsufficientQuorum);
        }
        if self.signatures.len() > 3 {
            return Err(SharedCommitError::CertificateTooLarge);
        }
        for (index, signature) in self.signatures.iter().enumerate() {
            signature.validate()?;
            if index != 0 && self.signatures[index - 1].signer >= signature.signer {
                return Err(SharedCommitError::NonCanonicalOrder);
            }
        }
        enforce_encoded_bound(self, MAX_SHARED_AGENT_COMMON_SNAPSHOT_CERTIFICATE_BYTES)
    }
}

fn verify_snapshot_member_signature(
    committee: &AgentReplicaCommittee,
    signature: &ReplicaCommitSignature,
    message: Hash,
) -> Result<(), SharedCommitError> {
    let member = committee
        .member_by_node(signature.signer)
        .ok_or(SharedCommitError::UnknownSigner)?;
    if member.replica().role != ReplicaRole::Voter {
        return Err(SharedCommitError::ObserverSignature);
    }
    if !verify_ed25519(
        member.ed25519_public_key(),
        &message.0,
        &signature.signature,
    ) {
        return Err(SharedCommitError::InvalidSignature);
    }
    Ok(())
}

impl ServiceWire for SharedAgentCommonSnapshotCertificate {
    const MAGIC: [u8; 4] = *b"AGQ4";
    fn encode_body(&self, output: &mut Vec<u8>) {
        let encoder = &mut Encoder(output);
        encoder.bytes(&self.claim.encode());
        encoder.u32(self.signatures.len() as u32);
        for signature in &self.signatures {
            encode_replica_signature(encoder, signature);
        }
    }
    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SHARED_AGENT_COMMON_SNAPSHOT_CERTIFICATE_BYTES)?;
        let claim = decode_nested::<SharedAgentCommonSnapshotClaim>(
            decoder,
            MAX_SHARED_AGENT_COMMON_SNAPSHOT_CLAIM_BYTES,
        )?;
        let count = decoder.u32()? as usize;
        if count > 3 {
            return Err(DecodeError::LimitExceeded);
        }
        let mut signatures = Vec::with_capacity(count);
        for _ in 0..count {
            signatures.push(decode_replica_signature(decoder)?);
        }
        Self::new(claim, signatures).map_err(map_decode_error)
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedSharedAgentCommonSnapshot {
    claim: SharedAgentCommonSnapshotClaim,
    certificate_commitment: Hash,
}
impl VerifiedSharedAgentCommonSnapshot {
    pub const fn claim(&self) -> &SharedAgentCommonSnapshotClaim {
        &self.claim
    }
    pub const fn certificate_commitment(&self) -> Hash {
        self.certificate_commitment
    }
}

/// Separately authenticated physical binding to a quorum-certified common
/// checkpoint. The owner signature binds the entire AGS3 claim and exact QC;
/// it is not a substitute for quorum agreement on the common state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedAgentLocalSnapshotBinding {
    common_certificate: Hash,
    claim: SharedAgentSnapshotClaim,
    signature: ReplicaCommitSignature,
}
impl SharedAgentLocalSnapshotBinding {
    pub fn new(
        common_certificate: Hash,
        claim: SharedAgentSnapshotClaim,
        signature: ReplicaCommitSignature,
    ) -> Result<Self, SharedCommitError> {
        let value = Self {
            common_certificate,
            claim,
            signature,
        };
        value.validate()?;
        Ok(value)
    }
    pub const fn common_certificate(&self) -> Hash {
        self.common_certificate
    }
    pub const fn claim(&self) -> &SharedAgentSnapshotClaim {
        &self.claim
    }
    pub const fn signature(&self) -> &ReplicaCommitSignature {
        &self.signature
    }
    pub fn commitment(&self) -> Hash {
        Hash::digest(LOCAL_SNAPSHOT_BINDING_DOMAIN, &[&self.encode()])
    }
    pub(crate) fn signing_message(
        common_certificate: Hash,
        physical_claim: Hash,
        node: NodeId,
    ) -> Hash {
        Hash::digest(
            LOCAL_SNAPSHOT_MESSAGE_DOMAIN,
            &[&common_certificate.0, &physical_claim.0, &node.0],
        )
    }
    pub fn validate(&self) -> Result<(), SharedCommitError> {
        self.claim.validate()?;
        self.signature.validate()?;
        if self.common_certificate == Hash::ZERO || self.signature.signer != self.claim.local_node()
        {
            return Err(SharedCommitError::WrongSnapshotClaim);
        }
        enforce_encoded_bound(self, MAX_SHARED_AGENT_LOCAL_SNAPSHOT_BINDING_BYTES)
    }
    pub fn verify(
        &self,
        certificate: &SharedAgentCommonSnapshotCertificate,
        expected: &SharedAgentSnapshotClaim,
    ) -> Result<VerifiedSharedAgentSnapshot, SharedCommitError> {
        self.validate()?;
        certificate.verify(expected.active_committee(), certificate.claim())?;
        if &self.claim != expected
            || self.common_certificate != certificate.commitment()
            || !certificate.claim().matches_physical_scope(expected)
        {
            return Err(SharedCommitError::WrongSnapshotClaim);
        }
        verify_snapshot_member_signature(
            expected.active_committee(),
            &self.signature,
            Self::signing_message(
                self.common_certificate,
                self.claim.commitment(),
                self.claim.local_node(),
            ),
        )?;
        Ok(VerifiedSharedAgentSnapshot {
            claim: self.claim.clone(),
            certificate_commitment: self.commitment(),
        })
    }
}
impl ServiceWire for SharedAgentLocalSnapshotBinding {
    const MAGIC: [u8; 4] = *b"AGL1";
    fn encode_body(&self, output: &mut Vec<u8>) {
        let encoder = &mut Encoder(output);
        encoder.fixed(&self.common_certificate.0);
        encoder.bytes(&self.claim.encode());
        encode_replica_signature(encoder, &self.signature);
    }
    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SHARED_AGENT_LOCAL_SNAPSHOT_BINDING_BYTES)?;
        Self::new(
            Hash(decoder.fixed()?),
            decode_nested::<SharedAgentSnapshotClaim>(
                decoder,
                MAX_SHARED_AGENT_SNAPSHOT_CLAIM_BYTES,
            )?,
            decode_replica_signature(decoder)?,
        )
        .map_err(map_decode_error)
    }
}

/// Source-instance-independent identity of one portable Shared recovery point.
///
/// Unlike [`SharedAgentSnapshotClaim`], this claim deliberately contains no
/// `JournalStoreInstanceId`, physical Raft audit root, or source-local
/// publication capability. It instead commits the complete canonical journal
/// closure which an importer must validate against independently supplied
/// genesis/root pins before constructing a new physical generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedAgentPortableSnapshotClaim {
    genesis_intent: Hash,
    root_pins: Hash,
    ordered: OrderedCommitClaim,
    active_committee: AgentReplicaCommittee,
    authority_epoch: u64,
    ordered_successor: JournalHeadsId,
    checkpoint_predecessor: JournalHeadsId,
    journal_heads: JournalHeadsId,
    checkpoint: CheckpointId,
    local_node: NodeId,
    control: LaneStateId,
    linear: LaneStateId,
    merge: LaneStateId,
    local: LaneStateId,
    ordered_invocations: InvocationIndexId,
    merge_invocations: InvocationIndexId,
    local_invocations: InvocationIndexId,
    artifacts: ArtifactClosureId,
    journal_image: Hash,
}

impl SharedAgentPortableSnapshotClaim {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        genesis_intent: Hash,
        root_pins: Hash,
        ordered: OrderedCommitClaim,
        active_committee: AgentReplicaCommittee,
        authority_epoch: u64,
        ordered_successor: JournalHeadsId,
        checkpoint_predecessor: JournalHeadsId,
        journal_heads: JournalHeadsId,
        checkpoint: CheckpointId,
        local_node: NodeId,
        control: LaneStateId,
        linear: LaneStateId,
        merge: LaneStateId,
        local: LaneStateId,
        ordered_invocations: InvocationIndexId,
        merge_invocations: InvocationIndexId,
        local_invocations: InvocationIndexId,
        artifacts: ArtifactClosureId,
        journal_image: Hash,
    ) -> Result<Self, SharedCommitError> {
        let claim = Self {
            genesis_intent,
            root_pins,
            ordered,
            active_committee,
            authority_epoch,
            ordered_successor,
            checkpoint_predecessor,
            journal_heads,
            checkpoint,
            local_node,
            control,
            linear,
            merge,
            local,
            ordered_invocations,
            merge_invocations,
            local_invocations,
            artifacts,
            journal_image,
        };
        claim.validate()?;
        Ok(claim)
    }

    pub const fn genesis_intent(&self) -> Hash {
        self.genesis_intent
    }

    pub const fn root_pins(&self) -> Hash {
        self.root_pins
    }

    pub const fn ordered(&self) -> &OrderedCommitClaim {
        &self.ordered
    }

    pub const fn active_committee(&self) -> &AgentReplicaCommittee {
        &self.active_committee
    }

    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    pub const fn ordered_successor(&self) -> JournalHeadsId {
        self.ordered_successor
    }

    pub const fn checkpoint_predecessor(&self) -> JournalHeadsId {
        self.checkpoint_predecessor
    }

    pub const fn journal_heads(&self) -> JournalHeadsId {
        self.journal_heads
    }

    pub const fn checkpoint(&self) -> CheckpointId {
        self.checkpoint
    }

    pub const fn local_node(&self) -> NodeId {
        self.local_node
    }

    pub const fn control(&self) -> LaneStateId {
        self.control
    }

    pub const fn linear(&self) -> LaneStateId {
        self.linear
    }

    pub const fn merge(&self) -> LaneStateId {
        self.merge
    }

    pub const fn local(&self) -> LaneStateId {
        self.local
    }

    pub const fn ordered_invocations(&self) -> InvocationIndexId {
        self.ordered_invocations
    }

    pub const fn merge_invocations(&self) -> InvocationIndexId {
        self.merge_invocations
    }

    pub const fn local_invocations(&self) -> InvocationIndexId {
        self.local_invocations
    }

    pub const fn artifacts(&self) -> ArtifactClosureId {
        self.artifacts
    }

    pub const fn journal_image(&self) -> Hash {
        self.journal_image
    }

    pub const fn raft_index(&self) -> u64 {
        self.ordered.raft_index
    }

    pub const fn raft_term(&self) -> u64 {
        self.ordered.raft_term
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(PORTABLE_SNAPSHOT_CLAIM_DOMAIN, &[&self.encode()])
    }

    pub fn validate(&self) -> Result<(), SharedCommitError> {
        self.ordered.validate()?;
        self.active_committee
            .validate()
            .map_err(|_| SharedCommitError::InvalidCommittee)?;
        if self.genesis_intent == Hash::ZERO
            || self.root_pins == Hash::ZERO
            || self.active_committee.profile() != AgentProfile::Shared
            || self.active_committee.space() != self.ordered.space
            || self.active_committee.agent() != self.ordered.agent
            || self.active_committee.id() != self.ordered.committee
            || self
                .active_committee
                .member_by_node(self.local_node)
                .is_none()
            || self.authority_epoch == 0
            || self.ordered_successor == JournalHeadsId::ZERO
            || self.checkpoint_predecessor == JournalHeadsId::ZERO
            || self.journal_heads == JournalHeadsId::ZERO
            || self.checkpoint == CheckpointId::ZERO
            || self.local_node == NodeId::ZERO
            || self.control == LaneStateId::ZERO
            || self.linear == LaneStateId::ZERO
            || self.merge == LaneStateId::ZERO
            || self.local == LaneStateId::ZERO
            || self.ordered_invocations == InvocationIndexId::ZERO
            || self.merge_invocations == InvocationIndexId::ZERO
            || self.local_invocations == InvocationIndexId::ZERO
            || self.artifacts == ArtifactClosureId::ZERO
            || self.journal_image == Hash::ZERO
        {
            return Err(SharedCommitError::InvalidSnapshotClaim);
        }
        enforce_encoded_bound(self, MAX_SHARED_AGENT_PORTABLE_SNAPSHOT_CLAIM_BYTES)
    }
}

impl ServiceWire for SharedAgentPortableSnapshotClaim {
    const MAGIC: [u8; 4] = *b"AGP1";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.genesis_intent.0);
        encoder.fixed(&self.root_pins.0);
        encoder.bytes(&self.ordered.encode());
        encoder.bytes(&self.active_committee.encode());
        encoder.u64(self.authority_epoch);
        encoder.fixed(self.ordered_successor.as_bytes());
        encoder.fixed(self.checkpoint_predecessor.as_bytes());
        encoder.fixed(self.journal_heads.as_bytes());
        encoder.fixed(self.checkpoint.as_bytes());
        encoder.fixed(&self.local_node.0);
        encoder.fixed(self.control.as_bytes());
        encoder.fixed(self.linear.as_bytes());
        encoder.fixed(self.merge.as_bytes());
        encoder.fixed(self.local.as_bytes());
        encoder.fixed(self.ordered_invocations.as_bytes());
        encoder.fixed(self.merge_invocations.as_bytes());
        encoder.fixed(self.local_invocations.as_bytes());
        encoder.fixed(self.artifacts.as_bytes());
        encoder.fixed(&self.journal_image.0);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SHARED_AGENT_PORTABLE_SNAPSHOT_CLAIM_BYTES)?;
        let claim = Self {
            genesis_intent: Hash(decoder.fixed()?),
            root_pins: Hash(decoder.fixed()?),
            ordered: decode_nested::<OrderedCommitClaim>(decoder, MAX_ORDERED_COMMIT_CLAIM_BYTES)?,
            active_committee: decode_nested::<AgentReplicaCommittee>(
                decoder,
                super::genesis::MAX_AGENT_REPLICA_COMMITTEE_BYTES,
            )?,
            authority_epoch: decoder.u64()?,
            ordered_successor: JournalHeadsId(decoder.fixed()?),
            checkpoint_predecessor: JournalHeadsId(decoder.fixed()?),
            journal_heads: JournalHeadsId(decoder.fixed()?),
            checkpoint: CheckpointId(decoder.fixed()?),
            local_node: NodeId(decoder.fixed()?),
            control: LaneStateId(decoder.fixed()?),
            linear: LaneStateId(decoder.fixed()?),
            merge: LaneStateId(decoder.fixed()?),
            local: LaneStateId(decoder.fixed()?),
            ordered_invocations: InvocationIndexId(decoder.fixed()?),
            merge_invocations: InvocationIndexId(decoder.fixed()?),
            local_invocations: InvocationIndexId(decoder.fixed()?),
            artifacts: ArtifactClosureId(decoder.fixed()?),
            journal_image: Hash(decoder.fixed()?),
        };
        claim.validate().map_err(map_decode_error)?;
        Ok(claim)
    }
}

/// Voter-majority authority for one exact portable Shared recovery image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedAgentPortableSnapshotCertificate {
    claim: SharedAgentPortableSnapshotClaim,
    signatures: Vec<ReplicaCommitSignature>,
}

impl SharedAgentPortableSnapshotCertificate {
    pub fn new(
        claim: SharedAgentPortableSnapshotClaim,
        signatures: Vec<ReplicaCommitSignature>,
    ) -> Result<Self, SharedCommitError> {
        let certificate = Self { claim, signatures };
        certificate.validate_shape()?;
        Ok(certificate)
    }

    pub const fn claim(&self) -> &SharedAgentPortableSnapshotClaim {
        &self.claim
    }

    pub fn signatures(&self) -> &[ReplicaCommitSignature] {
        &self.signatures
    }

    pub(crate) fn signing_message(committee: AgentReplicaCommitteeId, claim: Hash) -> Hash {
        Hash::digest(
            PORTABLE_SNAPSHOT_MESSAGE_DOMAIN,
            &[committee.as_bytes(), &claim.0],
        )
    }

    fn message(&self) -> Hash {
        Self::signing_message(self.claim.active_committee.id(), self.claim.commitment())
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(PORTABLE_SNAPSHOT_CERTIFICATE_DOMAIN, &[&self.encode()])
    }

    pub fn verify(
        &self,
        trusted_committee: &AgentReplicaCommittee,
        expected_claim: &SharedAgentPortableSnapshotClaim,
    ) -> Result<VerifiedSharedAgentPortableSnapshot, SharedCommitError> {
        trusted_committee
            .validate()
            .map_err(|_| SharedCommitError::InvalidCommittee)?;
        self.validate_shape()?;
        expected_claim.validate()?;
        if &self.claim != expected_claim {
            return Err(SharedCommitError::WrongSnapshotClaim);
        }
        if trusted_committee != self.claim.active_committee()
            || trusted_committee.id() != self.claim.ordered.committee
        {
            return Err(SharedCommitError::WrongCommittee);
        }
        if self.signatures.len() < trusted_committee.quorum_threshold() {
            return Err(SharedCommitError::InsufficientQuorum);
        }
        let message = self.message();
        for signature in &self.signatures {
            let member = trusted_committee
                .member_by_node(signature.signer)
                .ok_or(SharedCommitError::UnknownSigner)?;
            if member.replica().role != ReplicaRole::Voter {
                return Err(SharedCommitError::ObserverSignature);
            }
            if !verify_ed25519(
                member.ed25519_public_key(),
                &message.0,
                &signature.signature,
            ) {
                return Err(SharedCommitError::InvalidSignature);
            }
        }
        Ok(VerifiedSharedAgentPortableSnapshot {
            claim: self.claim.clone(),
            certificate_commitment: self.commitment(),
        })
    }

    fn validate_shape(&self) -> Result<(), SharedCommitError> {
        self.claim.validate()?;
        if self.signatures.is_empty() {
            return Err(SharedCommitError::InsufficientQuorum);
        }
        if self.signatures.len() > MAX_REPLICA_COMMIT_SIGNATURES {
            return Err(SharedCommitError::CertificateTooLarge);
        }
        for (index, signature) in self.signatures.iter().enumerate() {
            signature.validate()?;
            if let Some(previous) = index.checked_sub(1).map(|index| &self.signatures[index])
                && previous.signer >= signature.signer
            {
                return Err(SharedCommitError::NonCanonicalOrder);
            }
        }
        enforce_encoded_bound(self, MAX_SHARED_AGENT_PORTABLE_SNAPSHOT_CERTIFICATE_BYTES)
    }
}

impl ServiceWire for SharedAgentPortableSnapshotCertificate {
    const MAGIC: [u8; 4] = *b"AGX1";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.claim.encode());
        encoder.u32(self.signatures.len() as u32);
        for signature in &self.signatures {
            encode_replica_signature(&mut encoder, signature);
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(
            decoder,
            MAX_SHARED_AGENT_PORTABLE_SNAPSHOT_CERTIFICATE_BYTES,
        )?;
        let claim = decode_nested::<SharedAgentPortableSnapshotClaim>(
            decoder,
            MAX_SHARED_AGENT_PORTABLE_SNAPSHOT_CLAIM_BYTES,
        )?;
        let count = decoder.u32()? as usize;
        if count > MAX_REPLICA_COMMIT_SIGNATURES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut signatures = Vec::new();
        signatures
            .try_reserve_exact(count)
            .map_err(|_| DecodeError::LimitExceeded)?;
        for _ in 0..count {
            signatures.push(decode_replica_signature(decoder)?);
        }
        let certificate = Self { claim, signatures };
        certificate.validate_shape().map_err(map_decode_error)?;
        Ok(certificate)
    }
}

/// Process-local result of exact portable claim/quorum verification.
#[derive(Clone, Debug)]
pub struct VerifiedSharedAgentPortableSnapshot {
    claim: SharedAgentPortableSnapshotClaim,
    certificate_commitment: Hash,
}

impl VerifiedSharedAgentPortableSnapshot {
    pub const fn claim(&self) -> &SharedAgentPortableSnapshotClaim {
        &self.claim
    }

    pub const fn certificate_commitment(&self) -> Hash {
        self.certificate_commitment
    }
}

/// Opaque proof that one ordered claim passed exact-committee QC validation.
///
/// It has no public constructor. In particular, canonical wire decoding never
/// produces this trust token.
#[derive(Clone, Debug)]
pub struct VerifiedOrderedCommit {
    claim: OrderedCommitClaim,
    certificate_commitment: Hash,
}

impl VerifiedOrderedCommit {
    pub const fn claim(&self) -> &OrderedCommitClaim {
        &self.claim
    }

    pub const fn certificate_commitment(&self) -> Hash {
        self.certificate_commitment
    }

    /// Authenticate Control and Linear bytes at this exact committed head.
    pub fn verify_snapshot(
        &self,
        control: &[u8],
        linear: &[u8],
    ) -> Result<VerifiedOrderedSnapshot, SharedCommitError> {
        self.verify_snapshot_at(self, control, linear)
    }

    /// Authenticate this exact base relative to another verification of the
    /// same claim.
    ///
    /// Increasing Agent/Raft indexes do not prove ordered-entry ancestry. A
    /// future checkpoint certificate may add that proof, but this first slice
    /// deliberately rejects every distinct `canonical_head` claim.
    pub fn verify_snapshot_at(
        &self,
        canonical_head: &VerifiedOrderedCommit,
        control: &[u8],
        linear: &[u8],
    ) -> Result<VerifiedOrderedSnapshot, SharedCommitError> {
        if self.claim.space != canonical_head.claim.space
            || self.claim.agent != canonical_head.claim.agent
            || self.claim.genesis != canonical_head.claim.genesis
            || self.claim.admission != canonical_head.claim.admission
            || self.claim.committee != canonical_head.claim.committee
        {
            return Err(SharedCommitError::SnapshotHistoryMismatch);
        }

        if self.claim != canonical_head.claim {
            return Err(SharedCommitError::SnapshotOrderMismatch);
        }

        self.claim.control.verify_state(control)?;
        self.claim.linear.verify_state(linear)?;
        if control
            .len()
            .checked_add(linear.len())
            .is_none_or(|bytes| bytes > MAX_RUNTIME_STATE_BYTES)
        {
            return Err(SharedCommitError::StateLimitExceeded);
        }

        let evidence_commitment = Hash::digest(
            VERIFIED_ORDERED_SNAPSHOT_DOMAIN,
            &[
                &self.certificate_commitment.0,
                &canonical_head.certificate_commitment.0,
            ],
        );
        Ok(VerifiedOrderedSnapshot {
            genesis: self.claim.genesis,
            canonical_head: canonical_head.claim.ordered,
            base: self.claim.ordered,
            runtime: self.claim.runtime.clone(),
            control: control.to_vec(),
            linear: linear.to_vec(),
            control_commitment: self.claim.control.state.clone(),
            linear_commitment: self.claim.linear.state.clone(),
            evidence_commitment,
        })
    }
}

/// Opaque, QC-derived ordered snapshot suitable for a Shared replay adapter.
///
/// This deliberately mirrors the data required by `ResolvedOrderedSnapshot`
/// without exposing a raw constructor. A future replay adapter can consume
/// these getters after the replay module adds its narrow conversion seam.
#[derive(Clone, Debug)]
pub struct VerifiedOrderedSnapshot {
    genesis: AgentJournalGenesisId,
    canonical_head: OrderedBase,
    base: OrderedBase,
    runtime: RuntimeBinding,
    control: Vec<u8>,
    linear: Vec<u8>,
    control_commitment: BlobRef,
    linear_commitment: BlobRef,
    evidence_commitment: Hash,
}

impl VerifiedOrderedSnapshot {
    pub const fn genesis(&self) -> AgentJournalGenesisId {
        self.genesis
    }

    pub const fn canonical_head(&self) -> OrderedBase {
        self.canonical_head
    }

    pub const fn base(&self) -> OrderedBase {
        self.base
    }

    pub const fn runtime(&self) -> &RuntimeBinding {
        &self.runtime
    }

    pub fn control(&self) -> &[u8] {
        &self.control
    }

    pub fn linear(&self) -> &[u8] {
        &self.linear
    }

    pub const fn control_commitment(&self) -> &BlobRef {
        &self.control_commitment
    }

    pub const fn linear_commitment(&self) -> &BlobRef {
        &self.linear_commitment
    }

    pub const fn evidence_commitment(&self) -> Hash {
        self.evidence_commitment
    }
}

/// Structural, trust, or snapshot-materialization failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SharedCommitError {
    InvalidProjection,
    InvalidClaim,
    InvalidSnapshotClaim,
    InvalidCertificate,
    InvalidCommittee,
    InvalidSigner,
    NonCanonicalOrder,
    CertificateTooLarge,
    WrongCommittee,
    WrongClaim,
    WrongSnapshotClaim,
    InsufficientQuorum,
    UnknownSigner,
    ObserverSignature,
    InvalidSignature,
    StateMismatch,
    StateLimitExceeded,
    SnapshotHistoryMismatch,
    SnapshotOrderMismatch,
}

impl fmt::Display for SharedCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Shared Agent commit evidence: {self:?}")
    }
}

impl core::error::Error for SharedCommitError {}

fn encode_lane_projection(encoder: &mut Encoder<'_>, projection: &SharedLaneProjection) {
    encoder.fixed(projection.manifest.as_bytes());
    encode_blob_ref(encoder, &projection.state);
}

fn decode_lane_projection(decoder: &mut Decoder<'_>) -> Result<SharedLaneProjection, DecodeError> {
    let projection = SharedLaneProjection {
        manifest: LaneStateId(decoder.fixed()?),
        state: decode_blob_ref(decoder)?,
    };
    projection.validate().map_err(map_decode_error)?;
    Ok(projection)
}

fn encode_sealed_merge_projection(
    encoder: &mut Encoder<'_>,
    projection: &SharedSealedMergeProjection,
) {
    encoder.fixed(projection.seal.as_bytes());
    encoder.fixed(projection.frontier.as_bytes());
    encode_lane_projection(encoder, &projection.lane);
    encoder.fixed(projection.invocations.as_bytes());
}

fn decode_sealed_merge_projection(
    decoder: &mut Decoder<'_>,
) -> Result<SharedSealedMergeProjection, DecodeError> {
    let projection = SharedSealedMergeProjection {
        seal: MergeSealId(decoder.fixed()?),
        frontier: MergeFrontierId(decoder.fixed()?),
        lane: decode_lane_projection(decoder)?,
        invocations: InvocationIndexId(decoder.fixed()?),
    };
    projection.validate().map_err(map_decode_error)?;
    Ok(projection)
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

fn encode_runtime_binding(encoder: &mut Encoder<'_>, runtime: &RuntimeBinding) {
    encoder.fixed(&runtime.space.0);
    encoder.fixed(&runtime.agent.0);
    encoder.fixed(&runtime.deployment.0);
    encoder.fixed(&runtime.program.0);
    encoder.fixed(&runtime.producer.0);
    encode_blob_ref(encoder, &runtime.package);
    encoder.fixed(&runtime.runtime_abi.0);
    encoder.fixed(&runtime.execution_semantics.0);
}

fn decode_runtime_binding(decoder: &mut Decoder<'_>) -> Result<RuntimeBinding, DecodeError> {
    let runtime = RuntimeBinding {
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        program: ProgramId(decoder.fixed()?),
        producer: ProducerId(decoder.fixed()?),
        package: decode_blob_ref(decoder)?,
        runtime_abi: Hash(decoder.fixed()?),
        execution_semantics: Hash(decoder.fixed()?),
    };
    runtime.validate()?;
    Ok(runtime)
}

fn encode_blob_ref(encoder: &mut Encoder<'_>, reference: &BlobRef) {
    encoder.fixed(&reference.hash.0);
    encoder.u64(reference.len);
}

fn decode_blob_ref(decoder: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    Ok(BlobRef {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    })
}

fn encode_replica_signature(encoder: &mut Encoder<'_>, signature: &ReplicaCommitSignature) {
    encoder.fixed(&signature.signer.0);
    encoder.0.extend_from_slice(&signature.signature);
}

fn decode_replica_signature(
    decoder: &mut Decoder<'_>,
) -> Result<ReplicaCommitSignature, DecodeError> {
    let signature = ReplicaCommitSignature {
        signer: NodeId(decoder.fixed()?),
        signature: decoder
            .take(REPLICA_COMMIT_ED25519_SIGNATURE_BYTES)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
    };
    signature.validate().map_err(map_decode_error)?;
    Ok(signature)
}

fn valid_state_ref(reference: &BlobRef) -> bool {
    reference.hash != Hash::ZERO && reference.len <= MAX_RUNTIME_STATE_BYTES as u64
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

fn enforce_encoded_bound<T: ServiceWire>(
    value: &T,
    maximum: usize,
) -> Result<(), SharedCommitError> {
    if value.encode().len() > maximum {
        Err(SharedCommitError::CertificateTooLarge)
    } else {
        Ok(())
    }
}

fn map_decode_error(error: SharedCommitError) -> DecodeError {
    match error {
        SharedCommitError::CertificateTooLarge | SharedCommitError::StateLimitExceeded => {
            DecodeError::LimitExceeded
        }
        _ => DecodeError::NonCanonical,
    }
}

#[cfg(any(feature = "std", feature = "agent-runtime"))]
fn verify_ed25519(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; REPLICA_COMMIT_ED25519_SIGNATURE_BYTES],
) -> bool {
    let Ok(public_key) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
        return false;
    };
    public_key.verify_strict(message, &signature).is_ok()
}

// Wire types remain available to ordinary no-std consumers. Only the host and
// standard Agent runtime carry Ed25519 verification; other builds fail closed.
#[cfg(not(any(feature = "std", feature = "agent-runtime")))]
fn verify_ed25519(
    _public_key: &[u8; 32],
    _message: &[u8],
    _signature: &[u8; REPLICA_COMMIT_ED25519_SIGNATURE_BYTES],
) -> bool {
    false
}

#[cfg(test)]
pub(crate) fn common_snapshot_claim_for_test() -> SharedAgentCommonSnapshotClaim {
    tests::common_snapshot_claim_fixture()
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::String;

    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;
    use crate::agent::genesis::{AgentReplicaMember, derive_replica_raft_slot};
    use crate::agent::{AgentReplica, EXECUTION_SEMANTICS_ID, RUNTIME_ABI_ID};
    use crate::service::PrincipalId;

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

    fn lane(byte: u8, state: &[u8]) -> SharedLaneProjection {
        SharedLaneProjection::new(LaneStateId([byte; 32]), BlobRef::of_bytes(state)).unwrap()
    }

    fn claim(committee: AgentReplicaCommitteeId) -> OrderedCommitClaim {
        OrderedCommitClaim::new(
            AgentJournalGenesisId([0x33; 32]),
            AgentGenesisAdmissionId::from_bytes([0x34; 32]),
            committee,
            19,
            3,
            OrderedBase {
                index: 7,
                head: Some(OrderedEntryId([0x35; 32])),
            },
            MergeFrontierId([0x36; 32]),
            lane(0x37, b"observed merge state"),
            InvocationIndexId([0x42; 32]),
            runtime(),
            lane(0x38, b"control state"),
            lane(0x39, b"linear state"),
            InvocationIndexId([0x3a; 32]),
            ArtifactClosureId([0x3b; 32]),
            OrderedBase {
                index: 4,
                head: Some(OrderedEntryId([0x3c; 32])),
            },
            Some(
                SharedSealedMergeProjection::new(
                    MergeSealId([0x3d; 32]),
                    MergeFrontierId([0x3e; 32]),
                    lane(0x3f, b"last sealed merge state"),
                    InvocationIndexId([0x40; 32]),
                )
                .unwrap(),
            ),
            Hash([0x41; 32]),
        )
        .unwrap()
    }

    fn signatures(
        claim: &OrderedCommitClaim,
        signers: &[&SigningKey],
    ) -> Vec<ReplicaCommitSignature> {
        let message =
            ReplicaQuorumCertificate::signing_message(claim.committee(), claim.commitment());
        let mut signatures = signers
            .iter()
            .map(|key| {
                ReplicaCommitSignature::new(
                    NodeId::of_authenticated_peer(&peer_id(key)),
                    key.sign(&message.0).to_bytes(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(ReplicaCommitSignature::signer);
        signatures
    }

    fn certificate(claim: OrderedCommitClaim, signers: &[&SigningKey]) -> ReplicaQuorumCertificate {
        let signatures = signatures(&claim, signers);
        ReplicaQuorumCertificate::new(claim, signatures).unwrap()
    }

    pub(super) fn common_snapshot_claim_fixture() -> SharedAgentCommonSnapshotClaim {
        let committee = committee(&[key(1), key(2), key(3)], &[]);
        let mut ordered = claim(committee.id());
        let ancestry =
            SharedAgentCommonSnapshotAncestry::new(OrderedBase::post_genesis(), Hash([0x49; 32]))
                .unwrap();
        ordered.fence_ancestry = ancestry.commitment_for(&ordered);
        SharedAgentCommonSnapshotClaim::new(ordered, committee, 1, ancestry).unwrap()
    }

    fn common_certificate(
        claim: SharedAgentCommonSnapshotClaim,
        signers: &[&SigningKey],
    ) -> SharedAgentCommonSnapshotCertificate {
        let message = SharedAgentCommonSnapshotCertificate::signing_message(
            claim.active_committee().id(),
            claim.commitment(),
        );
        let mut signatures = signers
            .iter()
            .map(|key| {
                ReplicaCommitSignature::new(
                    NodeId::of_authenticated_peer(&peer_id(key)),
                    key.sign(&message.0).to_bytes(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(ReplicaCommitSignature::signer);
        SharedAgentCommonSnapshotCertificate::new(claim, signatures).unwrap()
    }

    fn physical_common_claim(
        common: &SharedAgentCommonSnapshotClaim,
        key: &SigningKey,
        store: u8,
    ) -> SharedAgentSnapshotClaim {
        SharedAgentSnapshotClaim::new(
            common.ordered().clone(),
            common.active_committee().clone(),
            common.authority_epoch(),
            Hash([store; 32]),
            Hash([0x51; 32]),
            JournalHeadsId([0x52; 32]),
            JournalHeadsId([0x53; 32]),
            JournalHeadsId([store; 32]),
            CheckpointId([store; 32]),
            NodeId::of_authenticated_peer(&peer_id(key)),
            LaneStateId([0x54; 32]),
            LaneStateId([0x55; 32]),
            LaneStateId([0x56; 32]),
            LaneStateId([store; 32]),
            common.ordered().ordered_invocations(),
            common.ordered().merge_invocations(),
            InvocationIndexId([store; 32]),
            common.ordered().artifacts(),
            Hash([0x57; 32]),
            Hash([0x58; 32]),
            None,
        )
        .unwrap()
    }

    fn local_binding(
        certificate: &SharedAgentCommonSnapshotCertificate,
        claim: SharedAgentSnapshotClaim,
        key: &SigningKey,
    ) -> SharedAgentLocalSnapshotBinding {
        let message = SharedAgentLocalSnapshotBinding::signing_message(
            certificate.commitment(),
            claim.commitment(),
            claim.local_node(),
        );
        let signature =
            ReplicaCommitSignature::new(claim.local_node(), key.sign(&message.0).to_bytes())
                .unwrap();
        SharedAgentLocalSnapshotBinding::new(certificate.commitment(), claim, signature).unwrap()
    }

    #[test]
    fn common_snapshot_recovery_manifest_is_versioned_and_signed() {
        let legacy = common_snapshot_claim_fixture();
        let legacy_bytes = legacy.encode();
        assert_eq!(&legacy_bytes[..4], b"AGC1");
        assert_eq!(legacy.recovery_manifest(), None);
        assert_eq!(
            legacy.commitment(),
            Hash::digest(COMMON_SNAPSHOT_CLAIM_DOMAIN, &[&legacy_bytes])
        );
        let recovery = legacy
            .clone()
            .with_recovery_manifest(Hash([0x81; 32]))
            .unwrap();
        let recovery_bytes = recovery.encode();
        assert_eq!(&recovery_bytes[..4], b"AGC2");
        assert_eq!(&recovery_bytes[4..legacy_bytes.len()], &legacy_bytes[4..]);
        assert_eq!(recovery_bytes.len(), legacy_bytes.len() + 32);
        assert_eq!(
            SharedAgentCommonSnapshotClaim::decode(&legacy_bytes).unwrap(),
            legacy
        );
        assert_eq!(
            SharedAgentCommonSnapshotClaim::decode(&recovery_bytes).unwrap(),
            recovery
        );
        let certificate = common_certificate(recovery.clone(), &[&key(1), &key(2)]);
        certificate
            .verify(recovery.active_committee(), &recovery)
            .unwrap();
        assert!(
            certificate
                .verify(legacy.active_committee(), &legacy)
                .is_err()
        );
        let substituted = recovery
            .clone()
            .with_recovery_manifest(Hash([0x82; 32]))
            .unwrap();
        assert!(
            certificate
                .verify(substituted.active_committee(), &substituted)
                .is_err()
        );
        let binding = local_binding(
            &certificate,
            physical_common_claim(&recovery, &key(1), 0x61),
            &key(1),
        );
        binding.verify(&certificate, binding.claim()).unwrap();
        let changed_certificate = common_certificate(substituted, &[&key(1), &key(2)]);
        assert!(
            binding
                .verify(&changed_certificate, binding.claim())
                .is_err()
        );
        assert!(legacy.clone().with_recovery_manifest(Hash::ZERO).is_err());
        let mut wrong_version = recovery_bytes.clone();
        wrong_version[..4].copy_from_slice(b"AGC1");
        assert!(SharedAgentCommonSnapshotClaim::decode(&wrong_version).is_err());
        let mut missing = legacy_bytes;
        missing[..4].copy_from_slice(b"AGC2");
        assert!(SharedAgentCommonSnapshotClaim::decode(&missing).is_err());
        let mut trailing = recovery_bytes;
        trailing.push(0);
        assert!(SharedAgentCommonSnapshotClaim::decode(&trailing).is_err());
    }

    #[test]
    fn common_snapshot_quorum_allows_distinct_authenticated_physical_bindings() {
        let common = common_snapshot_claim_fixture();
        let certificate = common_certificate(common.clone(), &[&key(1), &key(2)]);
        certificate
            .verify(common.active_committee(), &common)
            .unwrap();
        let first = local_binding(
            &certificate,
            physical_common_claim(&common, &key(1), 0x61),
            &key(1),
        );
        let second = local_binding(
            &certificate,
            physical_common_claim(&common, &key(3), 0x62),
            &key(3),
        );
        assert_ne!(first.claim(), second.claim());
        for binding in [&first, &second] {
            let verified = binding.verify(&certificate, binding.claim()).unwrap();
            assert_eq!(verified.certificate_commitment(), binding.commitment());
            assert_eq!(
                SharedAgentLocalSnapshotBinding::decode(&binding.encode()).unwrap(),
                *binding
            );
        }
        assert_eq!(
            SharedAgentCommonSnapshotCertificate::decode(&certificate.encode()).unwrap(),
            certificate
        );
        assert_eq!(
            SharedAgentCommonSnapshotClaim::decode(&common.encode()).unwrap(),
            common
        );
        assert!(first.verify(&certificate, second.claim()).is_err());
        // Existing authority decoders do not accept the new domains.
        assert!(SharedAgentSnapshotCertificate::decode(&certificate.encode()).is_err());
        assert!(SharedAgentPortableSnapshotCertificate::decode(&certificate.encode()).is_err());
    }

    #[test]
    fn common_snapshot_rejects_mixed_claims_duplicate_nonvoter_and_under_quorum() {
        let common = common_snapshot_claim_fixture();
        let certificate = common_certificate(common.clone(), &[&key(1), &key(2)]);
        let singleton = common_certificate(common.clone(), &[&key(1)]);
        assert!(matches!(
            singleton.verify(common.active_committee(), &common),
            Err(SharedCommitError::InsufficientQuorum)
        ));
        let duplicated = vec![
            certificate.signatures()[0].clone(),
            certificate.signatures()[0].clone(),
        ];
        assert!(SharedAgentCommonSnapshotCertificate::new(common.clone(), duplicated).is_err());
        let outsider = common_certificate(common.clone(), &[&key(1), &key(9)]);
        assert!(outsider.verify(common.active_committee(), &common).is_err());
        let mut other = common.clone();
        other.authority_epoch += 1;
        assert!(
            certificate
                .verify(common.active_committee(), &other)
                .is_err()
        );
        let changed = SharedAgentCommonSnapshotCertificate::new(
            other.clone(),
            certificate.signatures().to_vec(),
        )
        .unwrap();
        assert!(changed.verify(common.active_committee(), &other).is_err());
        let mut changed_generation = common.clone();
        changed_generation.ordered.genesis = AgentJournalGenesisId([0x71; 32]);
        assert!(
            certificate
                .verify(common.active_committee(), &changed_generation)
                .is_err()
        );
        let mut changed_ancestry = common.clone();
        changed_ancestry.ancestry.ordered_anchor = Hash([0x74; 32]);
        assert!(changed_ancestry.validate().is_err());
        assert!(SharedAgentCommonSnapshotClaim::decode(&changed_ancestry.encode()).is_err());
        let not_fixed_three = committee(&[key(1), key(2)], &[key(3)]);
        assert!(
            SharedAgentCommonSnapshotClaim::new(
                claim(not_fixed_three.id()),
                not_fixed_three,
                1,
                common.ancestry().clone()
            )
            .is_err()
        );
    }

    #[test]
    fn common_snapshot_local_binding_rejects_metadata_and_certificate_substitution() {
        let common = common_snapshot_claim_fixture();
        let certificate = common_certificate(common.clone(), &[&key(1), &key(2)]);
        let binding = local_binding(
            &certificate,
            physical_common_claim(&common, &key(1), 0x61),
            &key(1),
        );
        let mut modified = binding.clone();
        modified.claim.journal_store = Hash([0x72; 32]);
        assert!(modified.verify(&certificate, modified.claim()).is_err());
        let other_qc = common_certificate(common.clone(), &[&key(2), &key(3)]);
        assert!(binding.verify(&other_qc, binding.claim()).is_err());
        modified = binding.clone();
        modified.claim.ordered_invocations = InvocationIndexId([0x73; 32]);
        let signed_wrong_index = local_binding(&certificate, modified.claim, &key(1));
        assert!(
            signed_wrong_index
                .verify(&certificate, signed_wrong_index.claim())
                .is_err()
        );
        let mut trailing = binding.encode();
        trailing.push(0);
        assert!(SharedAgentLocalSnapshotBinding::decode(&trailing).is_err());
    }

    #[test]
    fn voter_majority_promotes_commit_and_checks_snapshot_bytes() {
        let voters = [key(1), key(2), key(3)];
        let observers = [key(9)];
        let committee = committee(&voters, &observers);
        let claim = claim(committee.id());
        let certificate = certificate(claim.clone(), &[&voters[0], &voters[2]]);

        assert_eq!(claim.merge_invocations(), InvocationIndexId([0x42; 32]));
        assert_ne!(
            claim.merge_invocations(),
            claim.sealed_merge().unwrap().invocations()
        );

        let verified = certificate.verify(&committee, &claim).unwrap();
        let snapshot = verified
            .verify_snapshot(b"control state", b"linear state")
            .unwrap();
        assert_eq!(snapshot.genesis(), claim.genesis());
        assert_eq!(snapshot.base(), claim.ordered());
        assert_eq!(snapshot.canonical_head(), claim.ordered());
        assert_eq!(snapshot.runtime(), claim.runtime());
        assert_eq!(snapshot.control(), b"control state");
        assert_eq!(snapshot.linear(), b"linear state");
        assert_ne!(snapshot.evidence_commitment(), Hash::ZERO);
        assert!(matches!(
            verified.verify_snapshot(b"wrong", b"linear state"),
            Err(SharedCommitError::StateMismatch)
        ));
    }

    #[test]
    fn increasing_qcs_without_ordered_ancestry_cannot_mint_relative_snapshot() {
        let voters = [key(1), key(2), key(3)];
        let committee = committee(&voters, &[]);
        let base_claim = claim(committee.id());
        let base_certificate = certificate(base_claim.clone(), &[&voters[0], &voters[1]]);
        let base = base_certificate.verify(&committee, &base_claim).unwrap();

        let mut later_claim = base_claim.clone();
        later_claim.raft_index += 1;
        later_claim.ordered = OrderedBase {
            index: later_claim.ordered.index + 1,
            head: Some(OrderedEntryId([0x77; 32])),
        };
        later_claim.validate().unwrap();
        let later_certificate = certificate(later_claim.clone(), &[&voters[0], &voters[2]]);
        let later = later_certificate.verify(&committee, &later_claim).unwrap();

        assert!(matches!(
            base.verify_snapshot_at(&later, b"control state", b"linear state"),
            Err(SharedCommitError::SnapshotOrderMismatch)
        ));
    }

    #[test]
    fn claim_certificate_and_expected_claim_tampering_fail() {
        let voters = [key(1), key(2), key(3)];
        let committee = committee(&voters, &[]);
        let claim = claim(committee.id());
        let certificate = certificate(claim.clone(), &[&voters[0], &voters[1]]);

        let other_committee = AgentReplicaCommittee::new(
            SpaceId([0x12; 32]),
            committee.agent(),
            AgentProfile::Shared,
            committee.members().to_vec(),
        )
        .unwrap();
        assert!(matches!(
            certificate.verify(&other_committee, &claim),
            Err(SharedCommitError::WrongCommittee)
        ));

        let mut wrong_expected = claim.clone();
        wrong_expected.raft_term += 1;
        assert!(matches!(
            certificate.verify(&committee, &wrong_expected),
            Err(SharedCommitError::WrongClaim)
        ));

        let mut changed_claim = certificate.clone();
        changed_claim.claim.merge_invocations = InvocationIndexId([0x78; 32]);
        let changed_expected = changed_claim.claim.clone();
        assert!(matches!(
            changed_claim.verify(&committee, &changed_expected),
            Err(SharedCommitError::InvalidSignature)
        ));

        let mut changed_signature = certificate;
        changed_signature.signatures[0].signature[0] ^= 1;
        assert!(matches!(
            changed_signature.verify(&committee, &claim),
            Err(SharedCommitError::InvalidSignature)
        ));
    }

    #[test]
    fn quorum_is_voter_only_and_duplicate_signers_are_noncanonical() {
        let voters = [key(1), key(2), key(3)];
        let observers = [key(9)];
        let committee = committee(&voters, &observers);
        let claim = claim(committee.id());

        let minority = certificate(claim.clone(), &[&voters[0]]);
        assert!(matches!(
            minority.verify(&committee, &claim),
            Err(SharedCommitError::InsufficientQuorum)
        ));

        let observer = certificate(claim.clone(), &[&voters[0], &observers[0]]);
        assert!(matches!(
            observer.verify(&committee, &claim),
            Err(SharedCommitError::ObserverSignature)
        ));

        let mut duplicate = certificate(claim, &[&voters[0], &voters[1]]);
        duplicate.signatures[1] = duplicate.signatures[0].clone();
        assert_eq!(
            ReplicaQuorumCertificate::decode(&duplicate.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn all_canonical_wires_round_trip_and_enforce_bounds() {
        let voters = [key(1), key(2), key(3)];
        let committee = committee(&voters, &[]);
        let claim = claim(committee.id());
        let certificate = certificate(claim.clone(), &[&voters[0], &voters[1]]);
        let signature = certificate.signatures()[0].clone();

        assert_eq!(
            SharedLaneProjection::decode(&claim.control().encode()).unwrap(),
            *claim.control()
        );
        let sealed = claim.sealed_merge().unwrap();
        assert_eq!(
            SharedSealedMergeProjection::decode(&sealed.encode()).unwrap(),
            *sealed
        );
        assert_eq!(OrderedCommitClaim::decode(&claim.encode()).unwrap(), claim);

        let mut missing_merge_invocations = claim.clone();
        missing_merge_invocations.merge_invocations = InvocationIndexId::ZERO;
        assert_eq!(
            missing_merge_invocations.validate(),
            Err(SharedCommitError::InvalidClaim)
        );
        assert_eq!(
            OrderedCommitClaim::decode(&missing_merge_invocations.encode()),
            Err(DecodeError::NonCanonical)
        );
        assert_eq!(
            ReplicaCommitSignature::decode(&signature.encode()).unwrap(),
            signature
        );
        assert_eq!(
            ReplicaQuorumCertificate::decode(&certificate.encode()).unwrap(),
            certificate
        );

        let mut oversized = claim.encode();
        oversized.resize(MAX_ORDERED_COMMIT_CLAIM_BYTES + 1, 0);
        assert_eq!(
            OrderedCommitClaim::decode(&oversized),
            Err(DecodeError::LimitExceeded)
        );
    }

    #[test]
    fn commitments_are_protocol_constants() {
        let voters = [key(1), key(2), key(3)];
        let committee = committee(&voters, &[]);
        let claim = claim(committee.id());
        let certificate = certificate(claim.clone(), &[&voters[0], &voters[1]]);

        assert_eq!(
            hex(claim.commitment()),
            "8b3d2a46999ed5e842ba3c0137398f43e89437aed0996bbdc747ef53f1ffcc37"
        );
        assert_eq!(
            hex(certificate.message()),
            "e36d4baf70049f9bf4967b5e97b529ed88b8725a58a6f9181a76dbe6b7751be1"
        );
        assert_eq!(
            hex(certificate.commitment()),
            "98e10adc9f04b784683b7c7d835a0c96df28f5f43009ed804b0189add8b883b3"
        );
    }

    fn hex(hash: Hash) -> String {
        hash.0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    }
}
