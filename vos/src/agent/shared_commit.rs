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
    AgentJournalGenesisId, ArtifactClosureId, InvocationIndexId, LaneStateId, MergeFrontierId,
    MergeSealId, OrderedBase, OrderedEntryId, RuntimeBinding,
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
    InvalidCertificate,
    InvalidCommittee,
    InvalidSigner,
    NonCanonicalOrder,
    CertificateTooLarge,
    WrongCommittee,
    WrongClaim,
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
            "cba7e98da505f747a71d416afaea846e359cd5eb2bd0f913f8704dabec4ec03b"
        );
        assert_eq!(
            hex(certificate.message()),
            "f3a0351b7b660e2ba591bd8dac0825f8a49ba4befa830cc9724b87df7c9e8e9f"
        );
        assert_eq!(
            hex(certificate.commitment()),
            "d28f780eb13ff66557c49dce48c4bf3557c1442f54ab5f8ee77972f3ceba73a7"
        );
    }

    fn hex(hash: Hash) -> String {
        hash.0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    }
}
