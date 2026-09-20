//! Canonical ordinary-Agent genesis admission records.
//!
//! First-system bootstrap and ordinary Agent creation have different trust
//! roots. [`AgentGenesisAdmissionRecord`] makes that distinction durable:
//! [`AgentGenesisAdmissionRecord::RootBootstrap`] wraps the existing
//! independently pinned root admission exactly, while
//! [`AgentGenesisAdmissionRecord::SystemAuthorized`] names a decision which
//! must later be verified against the already trusted live system Agent.
//!
//! Everything in this module is public data. Decoding a record, constructing
//! an internally consistent provision, or verifying its embedded QC shape
//! never promotes it to a replay/bootstrap capability.

use alloc::{boxed::Box, vec, vec::Vec};
use core::fmt;

use super::committee::{
    AuthorityClaimCommitment, AuthorityClaimDomain, AuthorityCommittee, AuthorityCommitteeError,
    AuthorityQuorumCertificate, GenesisIntentId, MAX_AUTHORITY_QC_WIRE_BYTES,
    MAX_SYSTEM_GENESIS_ADMISSION_BYTES, SystemAgentGenesisAdmissionRecord,
};
use super::execution::RuntimeBlob;
use super::journal::{
    AgentJournalGenesisId, CanonicalJournalRecord, MAX_ARTIFACT_CLOSURE_BYTES,
    MAX_REPLAY_INPUT_BYTES, ReplayInput, ReplayInputId, ReplayOperation,
    system_genesis_artifact_closure_commitment,
};
use super::{
    AgentConfig, AgentProfile, AgentReplica, LifecycleRequest, MAX_AGENT_REPLICAS, ReplicaRole,
};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{AgentId, BlobRef, Hash, NodeId, PrincipalId, SpaceId};

const SERVICE_WIRE_HEADER_BYTES: usize = 4 + 32;
const GENESIS_CATALOG_REFERENCES: usize = 1;
const ED25519_PEER_ID_BYTES: usize = 38;
const ED25519_PEER_ID_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];

const LOCATOR_WIRE_BYTES: usize = SERVICE_WIRE_HEADER_BYTES + 2 * 32;
const EXPECTATIONS_BODY_BYTES: usize = 4 * 32 + 8;
const BLOB_REFERENCE_BYTES: usize = 32 + 8;

/// Maximum complete certified transport roster.
pub const MAX_AGENT_REPLICA_COMMITTEE_BYTES: usize = 64 * 1024;
/// Maximum complete ordinary genesis claim.
pub const MAX_AGENT_GENESIS_CLAIM_BYTES: usize = 4 * 1024;
/// Maximum complete ordinary genesis evidence.
pub const MAX_AGENT_GENESIS_EVIDENCE_BYTES: usize = 40 * 1024;
/// Maximum complete finalized-decision record.
pub const MAX_AGENT_GENESIS_DECISION_BYTES: usize = 1024;
/// Maximum complete tagged admission record.
pub const MAX_AGENT_GENESIS_ADMISSION_BYTES: usize = 2 * 1024;
/// Maximum complete ordinary proposal.
pub const MAX_AGENT_GENESIS_PROPOSAL_BYTES: usize = SERVICE_WIRE_HEADER_BYTES
    + 4
    + LOCATOR_WIRE_BYTES
    + 4
    + MAX_REPLAY_INPUT_BYTES
    + EXPECTATIONS_BODY_BYTES
    + 4
    + BLOB_REFERENCE_BYTES;
/// Maximum complete ordinary provision. Catalog preimages remain external.
pub const MAX_AGENT_GENESIS_PROVISION_BYTES: usize = SERVICE_WIRE_HEADER_BYTES
    + 4
    + MAX_AGENT_GENESIS_PROPOSAL_BYTES
    + 4
    + MAX_AGENT_REPLICA_COMMITTEE_BYTES
    + 4
    + MAX_AGENT_GENESIS_EVIDENCE_BYTES
    + 4
    + MAX_AGENT_GENESIS_DECISION_BYTES;

// AJI4 header, seven fixed 32-byte runtime identities plus package hash/len,
// operation tag and nested AWRK length. AWRK holds its header, Manage/Direct
// tags, three identities, four empty state lengths, Create tag, descriptor,
// Some(receipt) tag, receipt and observed slot. The descriptor and receipt
// ceilings include their own headers; counting those here is conservative.
const MAX_CLEAN_CREATE_REPLAY_BYTES: usize = SERVICE_WIRE_HEADER_BYTES
    + 7 * 32
    + BLOB_REFERENCE_BYTES
    + 1
    + 4
    + SERVICE_WIRE_HEADER_BYTES
    + 1
    + 1
    + 3 * 32
    + 4 * 4
    + 1
    + crate::agent_sdk::wire::MAX_AGENT_DESCRIPTOR_WIRE_BYTES
    + 1
    + crate::agent_sdk::wire::MAX_AUTHORITY_RECEIPT_WIRE_BYTES
    + 8;

/// Conservative complete provision bound for clean Create only. Unlike the
/// generic replay ceiling, this excludes invocation availability and populated
/// runtime state. This is a wire bound, not an Authority archive reservation:
/// retained call/approval bytes, archive overhead and terminal state are extra.
pub const MAX_CLEAN_CREATE_GENESIS_PROVISION_BYTES: usize =
    MAX_AGENT_GENESIS_PROVISION_BYTES - MAX_REPLAY_INPUT_BYTES + MAX_CLEAN_CREATE_REPLAY_BYTES;

const PROPOSAL_ID_DOMAIN: &[u8] = b"vos/agent/genesis-proposal/v1";
const REPLICA_COMMITTEE_ID_DOMAIN: &[u8] = b"vos/agent/replica-committee/v1";
const GENESIS_EVIDENCE_ID_DOMAIN: &[u8] = b"vos/agent/genesis-evidence/v1";
const GENESIS_DECISION_ID_DOMAIN: &[u8] = b"vos/agent/system-authority/agent-genesis-decision/v1";
const GENESIS_ADMISSION_ID_DOMAIN: &[u8] = b"vos/agent/genesis-admission/v2";
const GENESIS_PUBLICATION_INVOCATION_DOMAIN: &[u8] =
    b"vos/agent/system-authority/genesis-publication/v1";

macro_rules! genesis_id_type {
    ($name:ident, $label:literal) => {
        #[repr(transparent)]
        #[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const ZERO: Self = Self([0; 32]);

            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub const fn as_hash(self) -> Hash {
                Hash(self.0)
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(value: [u8; 32]) -> Self {
                Self(value)
            }
        }

        impl From<$name> for [u8; 32] {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($label, "("))?;
                for byte in &self.0[..4] {
                    write!(formatter, "{byte:02x}")?;
                }
                formatter.write_str("…)")
            }
        }
    };
}

genesis_id_type!(AgentGenesisProposalId, "AgentGenesisProposalId");
genesis_id_type!(AgentReplicaCommitteeId, "AgentReplicaCommitteeId");
genesis_id_type!(AgentGenesisEvidenceId, "AgentGenesisEvidenceId");
genesis_id_type!(AgentGenesisDecisionId, "AgentGenesisDecisionId");
genesis_id_type!(AgentGenesisAdmissionId, "AgentGenesisAdmissionId");

/// Stable provider archive key for an ordinary Agent genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentGenesisLocator {
    pub space: SpaceId,
    pub agent: AgentId,
}

impl AgentGenesisLocator {
    pub fn validate(self) -> Result<(), AgentGenesisError> {
        if self.space == SpaceId::ZERO || self.agent == AgentId::ZERO {
            Err(AgentGenesisError::InvalidLocator)
        } else {
            Ok(())
        }
    }
}

impl ServiceWire for AgentGenesisLocator {
    const MAGIC: [u8; 4] = *b"AGNL";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.space.0);
        encoder.fixed(&self.agent.0);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let locator = Self {
            space: SpaceId(decoder.fixed()?),
            agent: AgentId(decoder.fixed()?),
        };
        locator.validate().map_err(map_decode_error)?;
        Ok(locator)
    }
}

/// Replay-derived, genesis-ID-free output commitments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentGenesisExpectations {
    runtime_binding: Hash,
    inner_create_request: Hash,
    post_create_state: Hash,
    artifact_closure: Hash,
    sequence: u64,
}

impl AgentGenesisExpectations {
    pub fn new(
        runtime_binding: Hash,
        inner_create_request: Hash,
        post_create_state: Hash,
        artifact_closure: Hash,
        sequence: u64,
    ) -> Result<Self, AgentGenesisError> {
        let expectations = Self {
            runtime_binding,
            inner_create_request,
            post_create_state,
            artifact_closure,
            sequence,
        };
        expectations.validate()?;
        Ok(expectations)
    }

    pub const fn runtime_binding(self) -> Hash {
        self.runtime_binding
    }

    pub const fn inner_create_request(self) -> Hash {
        self.inner_create_request
    }

    pub const fn post_create_state(self) -> Hash {
        self.post_create_state
    }

    pub const fn artifact_closure(self) -> Hash {
        self.artifact_closure
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    pub fn genesis_intent(self) -> Result<GenesisIntentId, AgentGenesisError> {
        GenesisIntentId::from_commitments(self.runtime_binding, self.inner_create_request)
            .map_err(AgentGenesisError::Authority)
    }

    fn validate(self) -> Result<(), AgentGenesisError> {
        if self.runtime_binding == Hash::ZERO
            || self.inner_create_request == Hash::ZERO
            || self.post_create_state == Hash::ZERO
            || self.artifact_closure == Hash::ZERO
            || self.sequence == 0
        {
            Err(AgentGenesisError::InvalidExpectations)
        } else {
            Ok(())
        }
    }
}

/// Exact replay-prepared proposal submitted to the durable system authority.
/// The selected physical replica is deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentGenesisProposal {
    locator: AgentGenesisLocator,
    // ReplayInput contains a large tagged operation. Keep it off the stack
    // while nested provision decoders and signature validators are active.
    // This is an in-memory layout choice only; the canonical wire is unchanged.
    create: Box<ReplayInput>,
    expectations: AgentGenesisExpectations,
    catalog: Vec<BlobRef>,
}

impl AgentGenesisProposal {
    pub fn new(
        locator: AgentGenesisLocator,
        create: ReplayInput,
        expectations: AgentGenesisExpectations,
        catalog: Vec<BlobRef>,
    ) -> Result<Self, AgentGenesisError> {
        let proposal = Self {
            locator,
            create: Box::new(create),
            expectations,
            catalog,
        };
        proposal.validate()?;
        Ok(proposal)
    }

    pub const fn locator(&self) -> AgentGenesisLocator {
        self.locator
    }

    pub const fn create(&self) -> &ReplayInput {
        &self.create
    }

    pub const fn expectations(&self) -> AgentGenesisExpectations {
        self.expectations
    }

    pub fn catalog(&self) -> &[BlobRef] {
        &self.catalog
    }

    pub fn config(&self) -> Result<&AgentConfig, AgentGenesisError> {
        create_config(&self.create).ok_or(AgentGenesisError::InvalidProposal)
    }

    /// Clean-generation descriptor retained by an exact SDK Create proposal.
    pub fn clean_descriptor(
        &self,
    ) -> Result<&crate::agent_sdk::AgentDescriptor, AgentGenesisError> {
        create_clean_descriptor(&self.create).ok_or(AgentGenesisError::InvalidProposal)
    }

    pub fn id(&self) -> AgentGenesisProposalId {
        AgentGenesisProposalId(Hash::digest(PROPOSAL_ID_DOMAIN, &[&self.encode()]).0)
    }

    pub fn validate(&self) -> Result<(), AgentGenesisError> {
        self.locator.validate()?;
        self.expectations.validate()?;
        self.create
            .validate()
            .map_err(|_| AgentGenesisError::InvalidProposal)?;
        let identity = create_identity(&self.create).ok_or(AgentGenesisError::InvalidProposal)?;
        if identity.space != self.locator.space
            || identity.agent != self.locator.agent
            || self.create.runtime.space != self.locator.space
            || self.create.runtime.agent != self.locator.agent
            || self.expectations.runtime_binding != self.create.runtime.commitment()
            || self.expectations.inner_create_request != identity.request
            || self.expectations.sequence != identity.sequence
            || self.catalog.as_slice() != [self.create.runtime.package.clone()]
            || system_genesis_artifact_closure_commitment(&self.catalog)
                .map_err(|_| AgentGenesisError::InvalidCatalog)?
                != self.expectations.artifact_closure
        {
            return Err(AgentGenesisError::InvalidProposal);
        }
        enforce_encoded_bound(self, MAX_AGENT_GENESIS_PROPOSAL_BYTES)
    }
}

impl ServiceWire for AgentGenesisProposal {
    const MAGIC: [u8; 4] = *b"AGNP";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.locator.encode());
        encoder.bytes(&self.create.encode());
        encode_expectations(&mut encoder, self.expectations);
        encoder.list(&self.catalog, encode_blob_ref);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_AGENT_GENESIS_PROPOSAL_BYTES)?;
        let locator = decode_nested::<AgentGenesisLocator>(decoder, LOCATOR_WIRE_BYTES)?;
        let create = decode_nested::<ReplayInput>(decoder, MAX_REPLAY_INPUT_BYTES)?;
        let expectations = decode_expectations(decoder)?;
        if decoder.u32()? as usize != GENESIS_CATALOG_REFERENCES {
            return Err(DecodeError::NonCanonical);
        }
        let catalog = vec![decode_blob_ref(decoder)?];
        let proposal = Self {
            locator,
            create: Box::new(create),
            expectations,
            catalog,
        };
        proposal.validate().map_err(map_decode_error)?;
        Ok(proposal)
    }
}

/// One authority-certified mapping from logical replica identity to complete
/// authenticated transport and signing identity.
/// The logical principal is the enrolled owner, not necessarily the transport
/// key's principal. Construction checks transport consistency only; the
/// descriptor and authority-certified committee bind that owner to this node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentReplicaMember {
    replica: AgentReplica,
    peer_id: Vec<u8>,
    ed25519_public_key: [u8; 32],
    raft_slot: Option<u16>,
}

impl AgentReplicaMember {
    pub fn new(
        replica: AgentReplica,
        peer_id: Vec<u8>,
        ed25519_public_key: [u8; 32],
        raft_slot: Option<u16>,
    ) -> Result<Self, AgentGenesisError> {
        let member = Self {
            replica,
            peer_id,
            ed25519_public_key,
            raft_slot,
        };
        member.validate_identity()?;
        Ok(member)
    }

    pub const fn replica(&self) -> AgentReplica {
        self.replica
    }

    pub fn peer_id(&self) -> &[u8] {
        &self.peer_id
    }

    pub const fn ed25519_public_key(&self) -> &[u8; 32] {
        &self.ed25519_public_key
    }

    pub const fn raft_slot(&self) -> Option<u16> {
        self.raft_slot
    }

    fn validate_identity(&self) -> Result<(), AgentGenesisError> {
        if self.replica.node == NodeId::ZERO
            || self.replica.principal == PrincipalId::ZERO
            || self.ed25519_public_key == [0; 32]
            || canonical_ed25519_peer_key(&self.peer_id) != Some(self.ed25519_public_key)
            || NodeId::of_authenticated_peer(&self.peer_id) != self.replica.node
        {
            return Err(AgentGenesisError::InvalidReplicaCommittee);
        }
        Ok(())
    }
}

/// Immutable initial data-plane membership certified by the system authority.
/// This is not an [`super::committee::AuthorityCommittee`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentReplicaCommittee {
    space: SpaceId,
    agent: AgentId,
    profile: AgentProfile,
    members: Vec<AgentReplicaMember>,
}

impl AgentReplicaCommittee {
    pub fn new(
        space: SpaceId,
        agent: AgentId,
        profile: AgentProfile,
        members: Vec<AgentReplicaMember>,
    ) -> Result<Self, AgentGenesisError> {
        let committee = Self {
            space,
            agent,
            profile,
            members,
        };
        committee.validate()?;
        Ok(committee)
    }

    pub const fn space(&self) -> SpaceId {
        self.space
    }

    pub const fn agent(&self) -> AgentId {
        self.agent
    }

    pub const fn profile(&self) -> AgentProfile {
        self.profile
    }

    pub fn members(&self) -> &[AgentReplicaMember] {
        &self.members
    }

    pub fn voter_count(&self) -> usize {
        self.members
            .iter()
            .filter(|member| member.replica.role == ReplicaRole::Voter)
            .count()
    }

    pub fn quorum_threshold(&self) -> usize {
        self.voter_count() / 2 + 1
    }

    pub fn member_by_node(&self, node: NodeId) -> Option<&AgentReplicaMember> {
        self.members
            .binary_search_by_key(&node, |member| member.replica.node)
            .ok()
            .map(|index| &self.members[index])
    }

    pub fn member_by_peer_id(&self, peer_id: &[u8]) -> Option<&AgentReplicaMember> {
        self.members.iter().find(|member| member.peer_id == peer_id)
    }

    pub fn member_by_raft_slot(&self, raft_slot: u16) -> Option<&AgentReplicaMember> {
        self.members
            .iter()
            .find(|member| member.raft_slot == Some(raft_slot))
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(REPLICA_COMMITTEE_ID_DOMAIN, &[&self.encode()])
    }

    pub fn id(&self) -> AgentReplicaCommitteeId {
        AgentReplicaCommitteeId(self.commitment().0)
    }

    pub fn validate_for(&self, config: &AgentConfig) -> Result<(), AgentGenesisError> {
        self.validate()?;
        config
            .validate()
            .map_err(|_| AgentGenesisError::InvalidReplicaCommittee)?;
        if self.space != config.identity.space
            || self.agent != config.identity.agent
            || self.profile != config.identity.profile
            || self.members.len() != config.replicas.len()
            || self
                .members
                .iter()
                .zip(&config.replicas)
                .any(|(member, replica)| member.replica != *replica)
        {
            return Err(AgentGenesisError::InvalidReplicaCommittee);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AgentGenesisError> {
        if self.space == SpaceId::ZERO
            || self.agent == AgentId::ZERO
            || self.members.is_empty()
            || self.members.len() > MAX_AGENT_REPLICAS
        {
            return Err(AgentGenesisError::InvalidReplicaCommittee);
        }
        for (index, member) in self.members.iter().enumerate() {
            member.validate_identity()?;
            let expected_slot = match (self.profile, member.replica.role) {
                (AgentProfile::Shared, ReplicaRole::Voter) => {
                    Some(derive_replica_raft_slot(&member.peer_id))
                }
                (AgentProfile::Local, _) | (_, ReplicaRole::Observer) => None,
                (AgentProfile::Private, ReplicaRole::Voter) => {
                    return Err(AgentGenesisError::InvalidReplicaCommittee);
                }
            };
            if member.raft_slot != expected_slot {
                return Err(AgentGenesisError::InvalidReplicaCommittee);
            }
            if let Some(previous) = index.checked_sub(1).map(|index| &self.members[index]) {
                if previous.replica.node >= member.replica.node {
                    return Err(AgentGenesisError::InvalidReplicaCommittee);
                }
            }
            if self.members[..index].iter().any(|existing| {
                existing.peer_id == member.peer_id
                    || existing.ed25519_public_key == member.ed25519_public_key
                    || (member.raft_slot.is_some() && existing.raft_slot == member.raft_slot)
            }) {
                return Err(AgentGenesisError::InvalidReplicaCommittee);
            }
        }
        match self.profile {
            AgentProfile::Local if self.members.len() != 1 => {
                return Err(AgentGenesisError::InvalidReplicaCommittee);
            }
            AgentProfile::Shared
                if !self
                    .members
                    .iter()
                    .any(|member| member.replica.role == ReplicaRole::Voter) =>
            {
                return Err(AgentGenesisError::InvalidReplicaCommittee);
            }
            AgentProfile::Private
                if self
                    .members
                    .iter()
                    .any(|member| member.replica.role != ReplicaRole::Observer) =>
            {
                return Err(AgentGenesisError::InvalidReplicaCommittee);
            }
            _ => {}
        }
        enforce_encoded_bound(self, MAX_AGENT_REPLICA_COMMITTEE_BYTES)
    }
}

impl ServiceWire for AgentReplicaCommittee {
    const MAGIC: [u8; 4] = *b"AGRM";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.space.0);
        encoder.fixed(&self.agent.0);
        encoder.u8(self.profile as u8);
        encoder.u32(self.members.len() as u32);
        for member in &self.members {
            encode_replica(&mut encoder, member.replica);
            encoder.bytes(&member.peer_id);
            encoder.fixed(&member.ed25519_public_key);
            encoder.option(&member.raft_slot, |encoder, slot| encoder.u16(*slot));
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_AGENT_REPLICA_COMMITTEE_BYTES)?;
        let space = SpaceId(decoder.fixed()?);
        let agent = AgentId(decoder.fixed()?);
        let profile = decode_profile(decoder.u8()?)?;
        let count = decoder.u32()? as usize;
        if count > MAX_AGENT_REPLICAS {
            return Err(DecodeError::LimitExceeded);
        }
        let mut members = Vec::new();
        members
            .try_reserve_exact(count)
            .map_err(|_| DecodeError::LimitExceeded)?;
        for _ in 0..count {
            let member = AgentReplicaMember {
                replica: decode_replica(decoder)?,
                peer_id: {
                    let peer = decoder.bytes()?;
                    if peer.len() != ED25519_PEER_ID_BYTES {
                        return Err(DecodeError::NonCanonical);
                    }
                    peer
                },
                ed25519_public_key: decoder.fixed()?,
                raft_slot: decoder.option(Decoder::u16)?,
            };
            member.validate_identity().map_err(map_decode_error)?;
            members.push(member);
        }
        let committee = Self {
            space,
            agent,
            profile,
            members,
        };
        committee.validate().map_err(map_decode_error)?;
        Ok(committee)
    }
}

/// Exact ordinary-Agent genesis payload certified by the live system
/// authority committee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentGenesisClaim {
    space: SpaceId,
    system_agent: AgentId,
    system_genesis: AgentJournalGenesisId,
    system_admission: AgentGenesisAdmissionId,
    agent: AgentId,
    profile: AgentProfile,
    authority_binding: Hash,
    proposal: AgentGenesisProposalId,
    create_input: ReplayInputId,
    genesis_intent: GenesisIntentId,
    runtime_binding: Hash,
    post_create_state: Hash,
    artifact_closure: Hash,
    replicas: AgentReplicaCommitteeId,
    sequence: u64,
}

impl AgentGenesisClaim {
    pub fn new(
        system_agent: AgentId,
        system_genesis: AgentJournalGenesisId,
        system_admission: AgentGenesisAdmissionId,
        proposal: &AgentGenesisProposal,
        replicas: &AgentReplicaCommittee,
    ) -> Result<Self, AgentGenesisError> {
        proposal.validate()?;
        let identity =
            create_identity(proposal.create()).ok_or(AgentGenesisError::InvalidProposal)?;
        validate_committee_for_create(replicas, proposal.create())?;
        let claim = Self {
            space: proposal.locator.space,
            system_agent,
            system_genesis,
            system_admission,
            agent: proposal.locator.agent,
            profile: identity.profile,
            authority_binding: identity.authority_binding,
            proposal: proposal.id(),
            create_input: proposal.create.id(),
            genesis_intent: proposal.expectations.genesis_intent()?,
            runtime_binding: proposal.expectations.runtime_binding,
            post_create_state: proposal.expectations.post_create_state,
            artifact_closure: proposal.expectations.artifact_closure,
            replicas: replicas.id(),
            sequence: proposal.expectations.sequence,
        };
        claim.validate_against(proposal, replicas)?;
        Ok(claim)
    }

    pub const fn space(&self) -> SpaceId {
        self.space
    }

    pub const fn system_agent(&self) -> AgentId {
        self.system_agent
    }

    pub const fn system_genesis(&self) -> AgentJournalGenesisId {
        self.system_genesis
    }

    pub const fn system_admission(&self) -> AgentGenesisAdmissionId {
        self.system_admission
    }

    pub const fn agent(&self) -> AgentId {
        self.agent
    }

    pub const fn profile(&self) -> AgentProfile {
        self.profile
    }

    pub const fn authority_binding(&self) -> Hash {
        self.authority_binding
    }

    pub const fn proposal(&self) -> AgentGenesisProposalId {
        self.proposal
    }

    pub const fn create_input(&self) -> ReplayInputId {
        self.create_input
    }

    pub const fn genesis_intent(&self) -> GenesisIntentId {
        self.genesis_intent
    }

    pub const fn runtime_binding(&self) -> Hash {
        self.runtime_binding
    }

    pub const fn post_create_state(&self) -> Hash {
        self.post_create_state
    }

    pub const fn artifact_closure(&self) -> Hash {
        self.artifact_closure
    }

    pub const fn replicas(&self) -> AgentReplicaCommitteeId {
        self.replicas
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn authority_claim(&self) -> AuthorityClaimCommitment {
        AuthorityClaimCommitment::of_bytes(
            AuthorityClaimDomain::AgentGenesis,
            self.sequence,
            &self.encode(),
        )
    }

    pub fn validate_against(
        &self,
        proposal: &AgentGenesisProposal,
        replicas: &AgentReplicaCommittee,
    ) -> Result<(), AgentGenesisError> {
        self.validate()?;
        proposal.validate()?;
        let identity =
            create_identity(proposal.create()).ok_or(AgentGenesisError::InvalidProposal)?;
        validate_committee_for_create(replicas, proposal.create())?;
        if self.space != proposal.locator.space
            || identity
                .system_agent
                .is_some_and(|system_agent| self.system_agent != system_agent)
            || self.agent != proposal.locator.agent
            || self.profile != identity.profile
            || self.authority_binding != identity.authority_binding
            || self.proposal != proposal.id()
            || self.create_input != proposal.create.id()
            || self.genesis_intent != proposal.expectations.genesis_intent()?
            || self.runtime_binding != proposal.expectations.runtime_binding
            || self.post_create_state != proposal.expectations.post_create_state
            || self.artifact_closure != proposal.expectations.artifact_closure
            || self.replicas != replicas.id()
            || self.sequence != proposal.expectations.sequence
        {
            return Err(AgentGenesisError::InvalidClaim);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AgentGenesisError> {
        if self.space == SpaceId::ZERO
            || self.system_agent == AgentId::ZERO
            || self.system_genesis == AgentJournalGenesisId::ZERO
            || self.system_admission == AgentGenesisAdmissionId::ZERO
            || self.agent == AgentId::ZERO
            || self.agent == self.system_agent
            || self.authority_binding == Hash::ZERO
            || self.proposal == AgentGenesisProposalId::ZERO
            || self.create_input == ReplayInputId::ZERO
            || self.genesis_intent == GenesisIntentId::ZERO
            || self.runtime_binding == Hash::ZERO
            || self.post_create_state == Hash::ZERO
            || self.artifact_closure == Hash::ZERO
            || self.replicas == AgentReplicaCommitteeId::ZERO
            || self.sequence == 0
        {
            return Err(AgentGenesisError::InvalidClaim);
        }
        enforce_encoded_bound(self, MAX_AGENT_GENESIS_CLAIM_BYTES)
    }
}

impl ServiceWire for AgentGenesisClaim {
    const MAGIC: [u8; 4] = *b"AGNC";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.space.0);
        encoder.fixed(&self.system_agent.0);
        encoder.fixed(self.system_genesis.as_bytes());
        encoder.fixed(self.system_admission.as_bytes());
        encoder.fixed(&self.agent.0);
        encoder.u8(self.profile as u8);
        encoder.fixed(&self.authority_binding.0);
        encoder.fixed(self.proposal.as_bytes());
        encoder.fixed(self.create_input.as_bytes());
        encoder.fixed(self.genesis_intent.as_bytes());
        encoder.fixed(&self.runtime_binding.0);
        encoder.fixed(&self.post_create_state.0);
        encoder.fixed(&self.artifact_closure.0);
        encoder.fixed(self.replicas.as_bytes());
        encoder.u64(self.sequence);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_AGENT_GENESIS_CLAIM_BYTES)?;
        let claim = Self {
            space: SpaceId(decoder.fixed()?),
            system_agent: AgentId(decoder.fixed()?),
            system_genesis: AgentJournalGenesisId(decoder.fixed()?),
            system_admission: AgentGenesisAdmissionId(decoder.fixed()?),
            agent: AgentId(decoder.fixed()?),
            profile: decode_profile(decoder.u8()?)?,
            authority_binding: Hash(decoder.fixed()?),
            proposal: AgentGenesisProposalId(decoder.fixed()?),
            create_input: ReplayInputId(decoder.fixed()?),
            genesis_intent: GenesisIntentId::from_bytes(decoder.fixed()?),
            runtime_binding: Hash(decoder.fixed()?),
            post_create_state: Hash(decoder.fixed()?),
            artifact_closure: Hash(decoder.fixed()?),
            replicas: AgentReplicaCommitteeId(decoder.fixed()?),
            sequence: decoder.u64()?,
        };
        claim.validate().map_err(map_decode_error)?;
        Ok(claim)
    }
}

/// Canonical QC evidence. Shape validation is not trust promotion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentGenesisEvidence {
    claim: AgentGenesisClaim,
    certificate: AuthorityQuorumCertificate,
}

impl AgentGenesisEvidence {
    pub fn new(
        claim: AgentGenesisClaim,
        certificate: AuthorityQuorumCertificate,
    ) -> Result<Self, AgentGenesisError> {
        let evidence = Self { claim, certificate };
        evidence.validate()?;
        Ok(evidence)
    }

    pub const fn claim(&self) -> &AgentGenesisClaim {
        &self.claim
    }

    pub const fn certificate(&self) -> &AuthorityQuorumCertificate {
        &self.certificate
    }

    pub fn id(&self) -> AgentGenesisEvidenceId {
        AgentGenesisEvidenceId(Hash::digest(GENESIS_EVIDENCE_ID_DOMAIN, &[&self.encode()]).0)
    }

    /// Verify this exact claim against an independently trusted system
    /// committee. The target Agent's replica roster is not that committee.
    ///
    /// Success proves certificate authorization only, not durable publication
    /// or finality. It cannot replace [`AgentGenesisFinalityVerifier`].
    pub fn verify_certificate(
        &self,
        trusted_committee: &AuthorityCommittee,
    ) -> Result<(), AgentGenesisError> {
        self.validate()?;
        if trusted_committee.space() != self.claim.space() {
            return Err(AgentGenesisError::InvalidEvidence);
        }
        self.certificate
            .verify(trusted_committee, self.claim.authority_claim())
            .map_err(AgentGenesisError::Authority)
    }

    /// Certificate authorization with a trusted caller's strict Ed25519
    /// backend, for no-std policy actors. This still does not prove finality.
    pub fn verify_certificate_with(
        &self,
        trusted_committee: &AuthorityCommittee,
        verify_signature: impl FnMut(&[u8; 32], &[u8], &[u8; 64]) -> bool,
    ) -> Result<(), AgentGenesisError> {
        self.validate()?;
        if trusted_committee.space() != self.claim.space() {
            return Err(AgentGenesisError::InvalidEvidence);
        }
        self.certificate
            .verify_with(
                trusted_committee,
                self.claim.authority_claim(),
                verify_signature,
            )
            .map_err(AgentGenesisError::Authority)
    }

    pub fn validate(&self) -> Result<(), AgentGenesisError> {
        self.claim.validate()?;
        if self.certificate.claim() != self.claim.authority_claim()
            || self.certificate.authority_binding() != self.claim.authority_binding
        {
            return Err(AgentGenesisError::InvalidEvidence);
        }
        enforce_encoded_bound(self, MAX_AGENT_GENESIS_EVIDENCE_BYTES)
    }
}

impl ServiceWire for AgentGenesisEvidence {
    const MAGIC: [u8; 4] = *b"AGNE";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.claim.encode());
        encoder.bytes(&self.certificate.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_AGENT_GENESIS_EVIDENCE_BYTES)?;
        let evidence = Self {
            claim: decode_nested::<AgentGenesisClaim>(decoder, MAX_AGENT_GENESIS_CLAIM_BYTES)?,
            certificate: decode_nested::<AuthorityQuorumCertificate>(
                decoder,
                MAX_AUTHORITY_QC_WIRE_BYTES,
            )?,
        };
        evidence.validate().map_err(map_decode_error)?;
        Ok(evidence)
    }
}

/// Content named by the live system Agent's immutable finalized decision log.
/// This record is not proof that the decision was actually finalized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentGenesisDecision {
    system_genesis: AgentJournalGenesisId,
    system_admission: AgentGenesisAdmissionId,
    proposal: AgentGenesisProposalId,
    replicas: AgentReplicaCommitteeId,
    evidence: AgentGenesisEvidenceId,
    claim: AuthorityClaimCommitment,
}

impl AgentGenesisDecision {
    pub fn new(
        proposal: &AgentGenesisProposal,
        replicas: &AgentReplicaCommittee,
        evidence: &AgentGenesisEvidence,
    ) -> Result<Self, AgentGenesisError> {
        evidence.claim.validate_against(proposal, replicas)?;
        let decision = Self {
            system_genesis: evidence.claim.system_genesis,
            system_admission: evidence.claim.system_admission,
            proposal: proposal.id(),
            replicas: replicas.id(),
            evidence: evidence.id(),
            claim: evidence.claim.authority_claim(),
        };
        decision.validate_against(proposal, replicas, evidence)?;
        Ok(decision)
    }

    pub const fn system_genesis(&self) -> AgentJournalGenesisId {
        self.system_genesis
    }

    pub const fn system_admission(&self) -> AgentGenesisAdmissionId {
        self.system_admission
    }

    pub const fn proposal(&self) -> AgentGenesisProposalId {
        self.proposal
    }

    pub const fn replicas(&self) -> AgentReplicaCommitteeId {
        self.replicas
    }

    pub const fn evidence(&self) -> AgentGenesisEvidenceId {
        self.evidence
    }

    pub const fn claim(&self) -> AuthorityClaimCommitment {
        self.claim
    }

    pub fn id(&self) -> AgentGenesisDecisionId {
        AgentGenesisDecisionId(Hash::digest(GENESIS_DECISION_ID_DOMAIN, &[&self.encode()]).0)
    }

    pub fn validate_against(
        &self,
        proposal: &AgentGenesisProposal,
        replicas: &AgentReplicaCommittee,
        evidence: &AgentGenesisEvidence,
    ) -> Result<(), AgentGenesisError> {
        self.validate()?;
        evidence.claim.validate_against(proposal, replicas)?;
        if self.system_genesis != evidence.claim.system_genesis
            || self.system_admission != evidence.claim.system_admission
            || self.proposal != proposal.id()
            || self.replicas != replicas.id()
            || self.evidence != evidence.id()
            || self.claim != evidence.claim.authority_claim()
        {
            return Err(AgentGenesisError::InvalidDecision);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AgentGenesisError> {
        if self.system_genesis == AgentJournalGenesisId::ZERO
            || self.system_admission == AgentGenesisAdmissionId::ZERO
            || self.proposal == AgentGenesisProposalId::ZERO
            || self.replicas == AgentReplicaCommitteeId::ZERO
            || self.evidence == AgentGenesisEvidenceId::ZERO
            || self.claim.domain() != AuthorityClaimDomain::AgentGenesis
        {
            return Err(AgentGenesisError::InvalidDecision);
        }
        enforce_encoded_bound(self, MAX_AGENT_GENESIS_DECISION_BYTES)
    }
}

impl ServiceWire for AgentGenesisDecision {
    const MAGIC: [u8; 4] = *b"AGND";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(self.system_genesis.as_bytes());
        encoder.fixed(self.system_admission.as_bytes());
        encoder.fixed(self.proposal.as_bytes());
        encoder.fixed(self.replicas.as_bytes());
        encoder.fixed(self.evidence.as_bytes());
        encode_authority_claim(&mut encoder, self.claim);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_AGENT_GENESIS_DECISION_BYTES)?;
        let decision = Self {
            system_genesis: AgentJournalGenesisId(decoder.fixed()?),
            system_admission: AgentGenesisAdmissionId(decoder.fixed()?),
            proposal: AgentGenesisProposalId(decoder.fixed()?),
            replicas: AgentReplicaCommitteeId(decoder.fixed()?),
            evidence: AgentGenesisEvidenceId(decoder.fixed()?),
            claim: decode_authority_claim(decoder)?,
        };
        decision.validate().map_err(map_decode_error)?;
        Ok(decision)
    }
}

/// Small tagged record embedded by reference in every journal generation.
/// Its construction proves only internal linkage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentGenesisAdmissionRecord {
    RootBootstrap(SystemAgentGenesisAdmissionRecord),
    SystemAuthorized {
        decision: AgentGenesisDecisionId,
        evidence: AgentGenesisEvidenceId,
        replicas: AgentReplicaCommitteeId,
        claim: AuthorityClaimCommitment,
    },
}

impl AgentGenesisAdmissionRecord {
    pub fn root_bootstrap(
        admission: SystemAgentGenesisAdmissionRecord,
    ) -> Result<Self, AgentGenesisError> {
        let record = Self::RootBootstrap(admission);
        record.validate()?;
        Ok(record)
    }

    pub fn system_authorized(
        decision: &AgentGenesisDecision,
        evidence: &AgentGenesisEvidence,
        replicas: &AgentReplicaCommittee,
    ) -> Result<Self, AgentGenesisError> {
        if decision.evidence != evidence.id()
            || decision.replicas != replicas.id()
            || decision.claim != evidence.claim.authority_claim()
        {
            return Err(AgentGenesisError::InvalidAdmission);
        }
        let record = Self::SystemAuthorized {
            decision: decision.id(),
            evidence: evidence.id(),
            replicas: replicas.id(),
            claim: evidence.claim.authority_claim(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn id(&self) -> AgentGenesisAdmissionId {
        AgentGenesisAdmissionId(Hash::digest(GENESIS_ADMISSION_ID_DOMAIN, &[&self.encode()]).0)
    }

    pub fn validate(&self) -> Result<(), AgentGenesisError> {
        match self {
            Self::RootBootstrap(admission) => {
                admission.validate().map_err(AgentGenesisError::Authority)?;
                if admission.claim().domain() != AuthorityClaimDomain::SystemAgentGenesis {
                    return Err(AgentGenesisError::InvalidAdmission);
                }
            }
            Self::SystemAuthorized {
                decision,
                evidence,
                replicas,
                claim,
            } => {
                if *decision == AgentGenesisDecisionId::ZERO
                    || *evidence == AgentGenesisEvidenceId::ZERO
                    || *replicas == AgentReplicaCommitteeId::ZERO
                    || claim.domain() != AuthorityClaimDomain::AgentGenesis
                {
                    return Err(AgentGenesisError::InvalidAdmission);
                }
            }
        }
        enforce_encoded_bound(self, MAX_AGENT_GENESIS_ADMISSION_BYTES)
    }
}

impl ServiceWire for AgentGenesisAdmissionRecord {
    const MAGIC: [u8; 4] = *b"AGNA";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        match self {
            Self::RootBootstrap(admission) => {
                encoder.u8(0);
                encoder.bytes(&admission.encode());
            }
            Self::SystemAuthorized {
                decision,
                evidence,
                replicas,
                claim,
            } => {
                encoder.u8(1);
                encoder.fixed(decision.as_bytes());
                encoder.fixed(evidence.as_bytes());
                encoder.fixed(replicas.as_bytes());
                encode_authority_claim(&mut encoder, *claim);
            }
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_AGENT_GENESIS_ADMISSION_BYTES)?;
        let record = match decoder.u8()? {
            0 => Self::RootBootstrap(decode_nested::<SystemAgentGenesisAdmissionRecord>(
                decoder,
                MAX_SYSTEM_GENESIS_ADMISSION_BYTES,
            )?),
            1 => Self::SystemAuthorized {
                decision: AgentGenesisDecisionId(decoder.fixed()?),
                evidence: AgentGenesisEvidenceId(decoder.fixed()?),
                replicas: AgentReplicaCommitteeId(decoder.fixed()?),
                claim: decode_authority_claim(decoder)?,
            },
            _ => return Err(DecodeError::InvalidTag),
        };
        record.validate().map_err(map_decode_error)?;
        Ok(record)
    }
}

/// Complete bounded archive response for an ordinary Agent genesis. A live
/// system-Agent verifier must still prove `decision` finalized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentGenesisProvision {
    // Keep the enclosing decoder/validator frame small while each bounded
    // component is decoded and checked. These boxes are not wire fields.
    proposal: Box<AgentGenesisProposal>,
    replicas: Box<AgentReplicaCommittee>,
    evidence: Box<AgentGenesisEvidence>,
    decision: Box<AgentGenesisDecision>,
}

impl AgentGenesisProvision {
    pub fn new(
        proposal: AgentGenesisProposal,
        replicas: AgentReplicaCommittee,
        evidence: AgentGenesisEvidence,
        decision: AgentGenesisDecision,
    ) -> Result<Self, AgentGenesisError> {
        let provision = Self {
            proposal: Box::new(proposal),
            replicas: Box::new(replicas),
            evidence: Box::new(evidence),
            decision: Box::new(decision),
        };
        provision.validate()?;
        Ok(provision)
    }

    pub const fn proposal(&self) -> &AgentGenesisProposal {
        &self.proposal
    }

    pub const fn replicas(&self) -> &AgentReplicaCommittee {
        &self.replicas
    }

    pub const fn evidence(&self) -> &AgentGenesisEvidence {
        &self.evidence
    }

    pub const fn decision(&self) -> &AgentGenesisDecision {
        &self.decision
    }

    /// Exact Linear invocation identity for publishing this provision against
    /// one retained management authorization. This derives an identity only;
    /// it performs no signature verification and grants no publication right.
    pub fn publication_invocation(
        &self,
        authorization_invocation: crate::agent_sdk::InvocationId,
    ) -> Result<crate::agent_sdk::InvocationId, AgentGenesisError> {
        self.validate()?;
        if authorization_invocation == crate::agent_sdk::InvocationId::ZERO {
            return Err(AgentGenesisError::InvalidProvision);
        }
        Ok(crate::agent_sdk::InvocationId(
            Hash::digest(
                GENESIS_PUBLICATION_INVOCATION_DOMAIN,
                &[
                    crate::agent_sdk::RUNTIME_ABI_ID.as_bytes(),
                    authorization_invocation.as_bytes(),
                    &self.encode(),
                ],
            )
            .0,
        ))
    }

    /// Validate a fresh clean Shared Create publication against the exact
    /// pending call and approval selected from trusted Authority state.
    ///
    /// The caller must independently select the committee and pending record;
    /// accepting these from the publication request would not establish policy
    /// authorization. Success neither retains the decision nor proves finality.
    /// An already published exact retry must use its durable publication record,
    /// rather than rerunning this fresh-admission check after receipt expiry.
    pub fn verify_pending_create_at<V>(
        &self,
        call: &crate::agent_sdk::authority::AuthorityCredentialCall,
        approval: &crate::agent_sdk::authority::ManagementApproval,
        trusted_committee: &AuthorityCommittee,
        publication_slot: u64,
        verifier: &V,
    ) -> Result<(), AgentGenesisError>
    where
        V: crate::agent_sdk::authority::AuthorityCredentialVerifier
            + crate::agent_sdk::authority::AuthorityVerifier,
    {
        use crate::agent_sdk::authority::{AuthorityVerifier, receipt_matches_approval};

        self.validate()?;
        let ReplayOperation::CleanManage {
            request,
            authority,
            observed_slot,
        } = &self.proposal.create().operation
        else {
            return Err(AgentGenesisError::InvalidProposal);
        };
        let crate::agent_sdk::ManagementRequest::Create(descriptor) = request else {
            return Err(AgentGenesisError::InvalidProposal);
        };
        if descriptor.identity.profile != crate::agent_sdk::AgentProfile::Shared
            || publication_slot < *observed_slot
            || self.evidence.claim().system_agent().0 != call.authority.system_agent.0
            || descriptor.authority != call.authority.binding
            || request.authorization_plan().as_ref() != Some(&approval.plan)
            || approval.validate_shape().is_err()
            || !approval.matches_call(call)
            || !receipt_matches_approval(authority, approval)
            || !call.authority.binding.accepts(authority)
        {
            return Err(AgentGenesisError::InvalidProvision);
        }
        call.verify_with(verifier)
            .map_err(|_| AgentGenesisError::InvalidEvidence)?;
        authority
            .verify_at(*observed_slot, verifier)
            .map_err(|_| AgentGenesisError::InvalidEvidence)?;
        if !authority.selector.is_live_at(publication_slot) {
            return Err(AgentGenesisError::InvalidEvidence);
        }
        self.evidence
            .verify_certificate_with(trusted_committee, |public, message, signature| {
                AuthorityVerifier::verify(verifier, public, message, signature)
            })
    }

    pub fn admission_record(&self) -> Result<AgentGenesisAdmissionRecord, AgentGenesisError> {
        AgentGenesisAdmissionRecord::system_authorized(
            &self.decision,
            &self.evidence,
            &self.replicas,
        )
    }

    pub fn validate(&self) -> Result<(), AgentGenesisError> {
        self.proposal.validate()?;
        validate_committee_for_create(&self.replicas, self.proposal.create())?;
        self.evidence.validate()?;
        self.evidence
            .claim
            .validate_against(&self.proposal, &self.replicas)?;
        self.decision
            .validate_against(&self.proposal, &self.replicas, &self.evidence)?;
        self.admission_record()?;
        enforce_encoded_bound(self, MAX_AGENT_GENESIS_PROVISION_BYTES)
    }
}

impl ServiceWire for AgentGenesisProvision {
    const MAGIC: [u8; 4] = *b"AGNV";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.proposal.encode());
        encoder.bytes(&self.replicas.encode());
        encoder.bytes(&self.evidence.encode());
        encoder.bytes(&self.decision.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_AGENT_GENESIS_PROVISION_BYTES)?;
        let provision = Self {
            proposal: Box::new(decode_nested::<AgentGenesisProposal>(
                decoder,
                MAX_AGENT_GENESIS_PROPOSAL_BYTES,
            )?),
            replicas: Box::new(decode_nested::<AgentReplicaCommittee>(
                decoder,
                MAX_AGENT_REPLICA_COMMITTEE_BYTES,
            )?),
            evidence: Box::new(decode_nested::<AgentGenesisEvidence>(
                decoder,
                MAX_AGENT_GENESIS_EVIDENCE_BYTES,
            )?),
            decision: Box::new(decode_nested::<AgentGenesisDecision>(
                decoder,
                MAX_AGENT_GENESIS_DECISION_BYTES,
            )?),
        };
        provision.validate().map_err(map_decode_error)?;
        Ok(provision)
    }
}

/// Maximum one-provision archive image, including its exact runtime preimage.
/// Archives store records per locator; this is not a whole-registry bound.
pub const MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES: usize = SERVICE_WIRE_HEADER_BYTES
    + 4 + MAX_AGENT_GENESIS_PROVISION_BYTES
    + 4 + BLOB_REFERENCE_BYTES + 4 + MAX_ARTIFACT_CLOSURE_BYTES;

/// Canonical persistence unit for an ordinary genesis provider. Structural
/// validation and archive recovery confer no finality: every host admission
/// must still cross the independent [`AgentGenesisFinalityVerifier`] boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentGenesisArchiveRecord {
    provision: AgentGenesisProvision,
    catalog: Vec<RuntimeBlob>,
}

impl AgentGenesisArchiveRecord {
    pub fn new(
        provision: AgentGenesisProvision,
        catalog: Vec<RuntimeBlob>,
    ) -> Result<Self, AgentGenesisError> {
        provision.validate()?;
        validate_agent_genesis_catalog(provision.proposal(), &catalog)?;
        Ok(Self { provision, catalog })
    }

    pub const fn provision(&self) -> &AgentGenesisProvision { &self.provision }
    pub fn catalog(&self) -> &[RuntimeBlob] { &self.catalog }
}

impl ServiceWire for AgentGenesisArchiveRecord {
    const MAGIC: [u8; 4] = *b"OGAR";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.provision.encode());
        encoder.list(&self.catalog, |encoder, blob| {
            encode_blob_ref(encoder, &blob.reference);
            encoder.bytes(&blob.bytes);
        });
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES)?;
        let provision = decode_nested::<AgentGenesisProvision>(decoder, MAX_AGENT_GENESIS_PROVISION_BYTES)?;
        if decoder.u32()? as usize != GENESIS_CATALOG_REFERENCES {
            return Err(DecodeError::NonCanonical);
        }
        let reference = decode_blob_ref(decoder)?;
        let bytes = decoder.bytes_ref()?;
        if bytes.len() > MAX_ARTIFACT_CLOSURE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        if reference != provision.proposal().catalog()[0] || !reference.matches(bytes) {
            return Err(DecodeError::NonCanonical);
        }
        // All checks precede copying the potentially large runtime preimage.
        Ok(Self { provision, catalog: vec![RuntimeBlob { reference, bytes: bytes.to_vec() }] })
    }
}

/// Bounded provider failures. Provider availability is not an authority
/// decision and remains separate from live-system verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentGenesisProviderError {
    Unavailable,
    NotConfigured,
    Refused,
    Conflict,
    Corrupt,
}

impl fmt::Display for AgentGenesisProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Agent genesis provider: {self:?}")
    }
}

impl core::error::Error for AgentGenesisProviderError {}

/// Durable archive/issuance boundary. This trait is intentionally not a
/// trusted verifier and cannot promote its own response.
/// [`AgentGenesisArchiveRecord`] is the canonical per-locator persistence
/// unit; implementations must publish it durably before returning a newly
/// issued provision and must refuse conflicting records for that locator.
pub trait AgentGenesisProvider: Send + Sync {
    fn create(
        &self,
        proposal: &AgentGenesisProposal,
        catalog: &[RuntimeBlob],
    ) -> Result<AgentGenesisProvision, AgentGenesisProviderError>;

    fn reproduce(
        &self,
        locator: AgentGenesisLocator,
    ) -> Result<AgentGenesisProvision, AgentGenesisProviderError>;

    fn load_catalog(
        &self,
        locator: AgentGenesisLocator,
        reference: &BlobRef,
    ) -> Result<Option<Vec<u8>>, AgentGenesisProviderError>;
}

/// State-dependent trust boundary which proves that an ordinary-Agent
/// decision is a permanent fact of the already trusted live system Agent.
///
/// [`AgentGenesisProvider`] deliberately cannot implement this proof merely
/// by returning a self-consistent provision. A host must configure an
/// independent verifier backed by authenticated system-Agent replay (or an
/// equally strong pinned proof source), and must invoke it again when a
/// generation is reopened.
pub trait AgentGenesisFinalityVerifier: Send + Sync {
    fn verify_finalized(
        &self,
        provision: &AgentGenesisProvision,
    ) -> Result<(), AgentGenesisFinalityError>;
}

/// Bounded failures from the host-configured live system-Agent verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentGenesisFinalityError {
    Unavailable,
    NotFinalized,
    WrongSystemAgent,
    Conflict,
    Corrupt,
}

impl fmt::Display for AgentGenesisFinalityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Agent genesis finality verifier: {self:?}")
    }
}

impl core::error::Error for AgentGenesisFinalityError {}

/// Opaque proof that one exact canonical provision crossed the configured
/// state-dependent finality boundary. It is intentionally not wire encodable
/// and has no raw constructor.
#[derive(Debug)]
pub(crate) struct VerifiedAgentGenesisProvision {
    provision: AgentGenesisProvision,
}

impl VerifiedAgentGenesisProvision {
    pub(crate) fn verify<V: AgentGenesisFinalityVerifier + ?Sized>(
        provision: AgentGenesisProvision,
        verifier: &V,
    ) -> Result<Self, AgentGenesisProvisionVerificationError> {
        provision
            .validate()
            .map_err(AgentGenesisProvisionVerificationError::InvalidProvision)?;
        verifier
            .verify_finalized(&provision)
            .map_err(AgentGenesisProvisionVerificationError::Finality)?;
        // Revalidate after the external trust call. Implementations receive
        // only a shared reference, but this also keeps the promotion boundary
        // explicit if interior-backed provision fields are ever introduced.
        provision
            .validate()
            .map_err(AgentGenesisProvisionVerificationError::InvalidProvision)?;
        Ok(Self { provision })
    }

    pub(crate) const fn provision(&self) -> &AgentGenesisProvision {
        &self.provision
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AgentGenesisProvisionVerificationError {
    InvalidProvision(AgentGenesisError),
    Finality(AgentGenesisFinalityError),
}

/// Validate exact catalog preimages supplied to or loaded from a provider.
pub fn validate_agent_genesis_catalog(
    proposal: &AgentGenesisProposal,
    catalog: &[RuntimeBlob],
) -> Result<(), AgentGenesisError> {
    proposal.validate()?;
    if catalog.len() != GENESIS_CATALOG_REFERENCES || catalog.len() != proposal.catalog.len() {
        return Err(AgentGenesisError::InvalidCatalog);
    }
    for (blob, expected) in catalog.iter().zip(&proposal.catalog) {
        if &blob.reference != expected
            || blob.bytes.len() > MAX_ARTIFACT_CLOSURE_BYTES
            || !blob.reference.matches(&blob.bytes)
        {
            return Err(AgentGenesisError::InvalidCatalog);
        }
    }
    Ok(())
}

/// Structural validation failures. No variant represents trusted promotion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentGenesisError {
    InvalidLocator,
    InvalidExpectations,
    InvalidProposal,
    InvalidReplicaCommittee,
    InvalidClaim,
    InvalidEvidence,
    InvalidDecision,
    InvalidAdmission,
    InvalidProvision,
    InvalidCatalog,
    LimitExceeded,
    Authority(AuthorityCommitteeError),
}

impl fmt::Display for AgentGenesisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Agent genesis structure: {self:?}")
    }
}

impl core::error::Error for AgentGenesisError {}

/// Deterministic nonzero Raft slot derived from a complete canonical PeerId.
/// Network routing should delegate to this byte-level helper.
pub fn derive_replica_raft_slot(peer_id: &[u8]) -> u16 {
    let bytes = crate::crypto::blake2b_hash::<2>(b"", &[peer_id]);
    match u16::from_le_bytes(bytes) {
        0 => u16::MAX,
        slot => slot,
    }
}

fn canonical_ed25519_peer_key(peer_id: &[u8]) -> Option<[u8; 32]> {
    if peer_id.len() != ED25519_PEER_ID_BYTES
        || peer_id.get(..ED25519_PEER_ID_PREFIX.len()) != Some(ED25519_PEER_ID_PREFIX.as_slice())
    {
        return None;
    }
    peer_id[ED25519_PEER_ID_PREFIX.len()..].try_into().ok()
}

fn create_config(create: &ReplayInput) -> Option<&AgentConfig> {
    let ReplayOperation::Management {
        request: LifecycleRequest::Authorized { request, .. },
    } = &create.operation
    else {
        return None;
    };
    let LifecycleRequest::Create(config) = request.as_ref() else {
        return None;
    };
    Some(config)
}

fn create_clean_descriptor(create: &ReplayInput) -> Option<&crate::agent_sdk::AgentDescriptor> {
    let ReplayOperation::CleanManage {
        request: crate::agent_sdk::ManagementRequest::Create(descriptor),
        ..
    } = &create.operation
    else {
        return None;
    };
    Some(descriptor)
}

#[derive(Clone, Copy)]
struct GenesisCreateIdentity {
    space: SpaceId,
    agent: AgentId,
    profile: AgentProfile,
    authority_binding: Hash,
    system_agent: Option<AgentId>,
    request: Hash,
    sequence: u64,
}

fn create_identity(create: &ReplayInput) -> Option<GenesisCreateIdentity> {
    match &create.operation {
        ReplayOperation::Management {
            request: LifecycleRequest::Authorized { admission, request },
        } => {
            let LifecycleRequest::Create(config) = request.as_ref() else {
                return None;
            };
            Some(GenesisCreateIdentity {
                space: config.identity.space,
                agent: config.identity.agent,
                profile: config.identity.profile,
                authority_binding: config.authority.commitment(),
                system_agent: Some(config.authority.agent),
                request: request.commitment(),
                sequence: admission.receipt.claim.sequence,
            })
        }
        ReplayOperation::CleanManage {
            request: crate::agent_sdk::ManagementRequest::Create(descriptor),
            authority,
            ..
        } => Some(GenesisCreateIdentity {
            space: SpaceId(descriptor.identity.space.0),
            agent: AgentId(descriptor.identity.agent.0),
            profile: match descriptor.identity.profile {
                crate::agent_sdk::AgentProfile::Local => AgentProfile::Local,
                crate::agent_sdk::AgentProfile::Shared => AgentProfile::Shared,
                crate::agent_sdk::AgentProfile::Private => AgentProfile::Private,
            },
            authority_binding: Hash(descriptor.authority.commitment().0),
            system_agent: None,
            request: Hash(
                crate::agent_sdk::ManagementRequest::Create(descriptor.clone())
                    .commitment()
                    .0,
            ),
            sequence: authority.selector.decision_sequence,
        }),
        _ => None,
    }
}

fn validate_committee_for_create(
    committee: &AgentReplicaCommittee,
    create: &ReplayInput,
) -> Result<(), AgentGenesisError> {
    if let Some(config) = create_config(create) {
        return committee.validate_for(config);
    }
    let descriptor = create_clean_descriptor(create).ok_or(AgentGenesisError::InvalidProposal)?;
    committee.validate()?;
    let identity = create_identity(create).ok_or(AgentGenesisError::InvalidProposal)?;
    if committee.space != identity.space
        || committee.agent != identity.agent
        || committee.profile != identity.profile
        || committee.members.len() != descriptor.replicas.len()
        || committee
            .members
            .iter()
            .zip(&descriptor.replicas)
            .any(|(member, replica)| {
                member.replica.node.0 != replica.node.0
                    || member.replica.principal.0 != replica.principal.0
                    || !matches!(
                        (member.replica.role, replica.role),
                        (ReplicaRole::Voter, crate::agent_sdk::ReplicaRole::Voter)
                            | (
                                ReplicaRole::Observer,
                                crate::agent_sdk::ReplicaRole::Observer
                            )
                    )
            })
    {
        return Err(AgentGenesisError::InvalidReplicaCommittee);
    }
    Ok(())
}

fn encode_expectations(encoder: &mut Encoder<'_>, expectations: AgentGenesisExpectations) {
    encoder.fixed(&expectations.runtime_binding.0);
    encoder.fixed(&expectations.inner_create_request.0);
    encoder.fixed(&expectations.post_create_state.0);
    encoder.fixed(&expectations.artifact_closure.0);
    encoder.u64(expectations.sequence);
}

fn decode_expectations(decoder: &mut Decoder<'_>) -> Result<AgentGenesisExpectations, DecodeError> {
    AgentGenesisExpectations::new(
        Hash(decoder.fixed()?),
        Hash(decoder.fixed()?),
        Hash(decoder.fixed()?),
        Hash(decoder.fixed()?),
        decoder.u64()?,
    )
    .map_err(map_decode_error)
}

fn encode_replica(encoder: &mut Encoder<'_>, replica: AgentReplica) {
    encoder.fixed(&replica.node.0);
    encoder.fixed(&replica.principal.0);
    encoder.u8(replica.role as u8);
}

fn decode_replica(decoder: &mut Decoder<'_>) -> Result<AgentReplica, DecodeError> {
    Ok(AgentReplica {
        node: NodeId(decoder.fixed()?),
        principal: PrincipalId(decoder.fixed()?),
        role: match decoder.u8()? {
            0 => ReplicaRole::Voter,
            1 => ReplicaRole::Observer,
            _ => return Err(DecodeError::InvalidTag),
        },
    })
}

fn decode_profile(tag: u8) -> Result<AgentProfile, DecodeError> {
    match tag {
        0 => Ok(AgentProfile::Local),
        1 => Ok(AgentProfile::Shared),
        2 => Ok(AgentProfile::Private),
        _ => Err(DecodeError::InvalidTag),
    }
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

fn encode_authority_claim(encoder: &mut Encoder<'_>, claim: AuthorityClaimCommitment) {
    encoder.u8(claim.domain() as u8);
    encoder.u64(claim.sequence());
    encoder.fixed(&claim.payload_commitment().0);
}

fn decode_authority_claim(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityClaimCommitment, DecodeError> {
    let domain = match decoder.u8()? {
        0 => AuthorityClaimDomain::Lifecycle,
        1 => AuthorityClaimDomain::Invocation,
        2 => AuthorityClaimDomain::SystemAgentGenesis,
        3 => AuthorityClaimDomain::CommitteeRotation,
        4 => AuthorityClaimDomain::Catalog,
        5 => AuthorityClaimDomain::NodeControl,
        6 => AuthorityClaimDomain::AgentGenesis,
        _ => return Err(DecodeError::InvalidTag),
    };
    AuthorityClaimCommitment::from_payload_commitment(
        domain,
        decoder.u64()?,
        Hash(decoder.fixed()?),
    )
    .map_err(|_| DecodeError::NonCanonical)
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

// Do not retain the nested replay decoder's scratch frame while validating
// the enclosing (heap-backed) proposal and its certificate.
#[inline(never)]
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
) -> Result<(), AgentGenesisError> {
    if value.encode().len() > maximum {
        Err(AgentGenesisError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn map_decode_error(error: AgentGenesisError) -> DecodeError {
    match error {
        AgentGenesisError::LimitExceeded => DecodeError::LimitExceeded,
        AgentGenesisError::Authority(
            AuthorityCommitteeError::CommitteeTooLarge
            | AuthorityCommitteeError::CertificateTooLarge
            | AuthorityCommitteeError::RootAnchorTooLarge
            | AuthorityCommitteeError::GenesisEvidenceTooLarge
            | AuthorityCommitteeError::GenesisAdmissionTooLarge,
        ) => DecodeError::LimitExceeded,
        _ => DecodeError::NonCanonical,
    }
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, vec};

    use super::*;
    use crate::agent::authority::{
        AgentAuthorityBinding, AgentAuthorityClaim, AgentAuthorityReceipt,
        CAPABILITY_AGENT_CREATE_SHARED, ED25519_SIGNATURE_BYTES, ed25519_public_key_wire,
    };
    use crate::agent::committee::{
        AuthorityCommittee, AuthorityCommitteeMember, AuthorityMemberRole, AuthoritySignature,
    };
    use crate::agent::contract::RuntimePackageContract;
    use crate::agent::journal::RuntimeBinding;
    use crate::agent::{AgentIdentity, LaneSet, LifecycleAuthorityAdmission, RuntimeCapabilities};
    use crate::service::{
        ActorId, CapabilityId, CredentialId, DeploymentId, PLATFORM_ID, ProducerId, ProgramId,
    };

    const RUNTIME_BYTES: &[u8] = b"ordinary-shared-agent-runtime";

    #[derive(Clone)]
    struct Fixture {
        proposal: AgentGenesisProposal,
        replicas: AgentReplicaCommittee,
        authority: AuthorityCommittee,
        evidence: AgentGenesisEvidence,
        decision: AgentGenesisDecision,
        provision: AgentGenesisProvision,
    }

    fn peer_id(key: [u8; 32]) -> Vec<u8> {
        let mut peer_id = Vec::from(ED25519_PEER_ID_PREFIX);
        peer_id.extend_from_slice(&key);
        peer_id
    }

    fn transport_member(key_byte: u8, role: ReplicaRole) -> AgentReplicaMember {
        let key = [key_byte; 32];
        let peer_id = peer_id(key);
        let node = NodeId::of_authenticated_peer(&peer_id);
        let principal = PrincipalId::of_public_key(&key);
        let raft_slot = (role == ReplicaRole::Voter).then(|| derive_replica_raft_slot(&peer_id));
        AgentReplicaMember::new(
            AgentReplica {
                node,
                principal,
                role,
            },
            peer_id,
            key,
            raft_slot,
        )
        .unwrap()
    }

    fn authority_binding() -> AgentAuthorityBinding {
        let public_key = ed25519_public_key_wire([0x41; 32]);
        AgentAuthorityBinding {
            agent: AgentId([0xa1; 32]),
            actor: ActorId([0xa2; 32]),
            deployment: DeploymentId([0xa3; 32]),
            program: ProgramId([0xa4; 32]),
            producer: ProducerId::of_public_key(&public_key),
            public_key,
        }
    }

    fn fixture() -> Fixture {
        let space = SpaceId([0x11; 32]);
        let owner = PrincipalId([0x12; 32]);
        let nonce = Hash([0x13; 32]);
        let agent = AgentId::derive(space, owner, nonce.as_bytes());

        let mut replica_members = vec![
            transport_member(0x31, ReplicaRole::Voter),
            transport_member(0x32, ReplicaRole::Voter),
            transport_member(0x33, ReplicaRole::Observer),
        ];
        replica_members.sort_by_key(|member| member.replica().node);
        let config = AgentConfig {
            identity: AgentIdentity {
                space,
                agent,
                owner,
                profile: AgentProfile::Shared,
                runtime_deployment: DeploymentId([0x21; 32]),
                runtime_program: ProgramId([0x22; 32]),
                runtime_producer: ProducerId([0x23; 32]),
                transition_producer: ProducerId([0x24; 32]),
            },
            creation_nonce: nonce,
            authority: authority_binding(),
            system_authority_genesis: None,
            runtime_package: BlobRef::of_bytes(RUNTIME_BYTES),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities {
                lanes: LaneSet::ALL,
                scheduling: false,
                proofs: false,
                max_actors: 64,
            },
            replicas: replica_members
                .iter()
                .map(AgentReplicaMember::replica)
                .collect(),
        };
        config.validate().unwrap();

        let runtime = RuntimeBinding {
            space,
            agent,
            deployment: config.identity.runtime_deployment,
            program: config.identity.runtime_program,
            producer: config.identity.runtime_producer,
            package: config.runtime_package.clone(),
            runtime_abi: super::super::RUNTIME_ABI_ID,
            execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
        };
        let inner = LifecycleRequest::Create(config.clone());
        let authority_claim = AgentAuthorityClaim {
            authority: config.authority.clone(),
            space,
            agent,
            principal: owner,
            credential: CredentialId([0x24; 32]),
            capability: CapabilityId::named(CAPABILITY_AGENT_CREATE_SHARED),
            operation: inner.commitment(),
            sequence: 7,
            valid_from: 10,
            valid_until: 30,
        };
        let create = ReplayInput {
            runtime,
            operation: ReplayOperation::Management {
                request: LifecycleRequest::Authorized {
                    admission: LifecycleAuthorityAdmission {
                        receipt: AgentAuthorityReceipt {
                            claim: authority_claim,
                            signature: vec![0x25; ED25519_SIGNATURE_BYTES],
                        },
                        observed_slot: 20,
                    },
                    request: Box::new(inner.clone()),
                },
            },
        };
        create.validate().unwrap();

        let catalog = vec![config.runtime_package.clone()];
        let expectations = AgentGenesisExpectations::new(
            create.runtime.commitment(),
            inner.commitment(),
            Hash([0x26; 32]),
            system_genesis_artifact_closure_commitment(&catalog).unwrap(),
            7,
        )
        .unwrap();
        let proposal = AgentGenesisProposal::new(
            AgentGenesisLocator { space, agent },
            create,
            expectations,
            catalog,
        )
        .unwrap();
        let replicas =
            AgentReplicaCommittee::new(space, agent, AgentProfile::Shared, replica_members)
                .unwrap();

        let authority_member = AuthorityCommitteeMember::new(
            NodeId([0x51; 32]),
            [0x52; 32],
            AuthorityMemberRole::Voter,
        )
        .unwrap();
        let signer = authority_member.signer();
        let authority = AuthorityCommittee::new(
            space,
            config.authority.commitment(),
            1,
            None,
            vec![authority_member],
        )
        .unwrap();
        let claim = AgentGenesisClaim::new(
            config.authority.agent,
            AgentJournalGenesisId::new([0x92; 32]),
            AgentGenesisAdmissionId::from_bytes([0x93; 32]),
            &proposal,
            &replicas,
        )
        .unwrap();
        let certificate = AuthorityQuorumCertificate::new(
            &authority,
            claim.authority_claim(),
            vec![AuthoritySignature::new(signer, [0x53; 64]).unwrap()],
        )
        .unwrap();
        let evidence = AgentGenesisEvidence::new(claim, certificate).unwrap();
        let decision = AgentGenesisDecision::new(&proposal, &replicas, &evidence).unwrap();
        let provision = AgentGenesisProvision::new(
            proposal.clone(),
            replicas.clone(),
            evidence.clone(),
            decision.clone(),
        )
        .unwrap();
        Fixture {
            proposal,
            replicas,
            authority,
            evidence,
            decision,
            provision,
        }
    }

    #[test]
    fn genesis_certificate_requires_independent_committee_and_exact_space_claim() {
        use ed25519_dalek::{Signer as _, SigningKey};

        let fixture = fixture();
        let key = SigningKey::from_bytes(&[0x71; 32]);
        let member = AuthorityCommitteeMember::new(
            NodeId([0x72; 32]),
            key.verifying_key().to_bytes(),
            AuthorityMemberRole::Voter,
        )
        .unwrap();
        let committee_for = |space| {
            AuthorityCommittee::new(
                space,
                fixture.evidence.claim().authority_binding(),
                1,
                None,
                vec![member.clone()],
            )
            .unwrap()
        };
        let sign = |committee: &AuthorityCommittee| {
            let claim = fixture.evidence.claim().clone();
            let message = AuthorityQuorumCertificate::signing_message(
                committee.authority_binding(),
                committee.epoch(),
                committee.commitment(),
                claim.authority_claim(),
            );
            let certificate = AuthorityQuorumCertificate::new(
                committee,
                claim.authority_claim(),
                vec![
                    AuthoritySignature::new(member.signer(), key.sign(&message.0).to_bytes())
                        .unwrap(),
                ],
            )
            .unwrap();
            AgentGenesisEvidence::new(claim, certificate).unwrap()
        };
        let trusted = committee_for(fixture.proposal.locator().space);
        let evidence = sign(&trusted);
        assert_eq!(evidence.verify_certificate(&trusted), Ok(()));
        let mut verified_signatures = 0;
        assert_eq!(
            evidence.verify_certificate_with(&trusted, |public, message, signature| {
                verified_signatures += 1;
                ed25519_dalek::VerifyingKey::from_bytes(public)
                    .unwrap()
                    .verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
                    .is_ok()
            }),
            Ok(())
        );
        assert_eq!(verified_signatures, 1);
        assert_eq!(
            evidence.verify_certificate_with(&trusted, |_, _, _| false),
            Err(AgentGenesisError::Authority(
                AuthorityCommitteeError::InvalidSignature
            ))
        );
        assert!(evidence.verify_certificate(&fixture.authority).is_err());
        assert!(
            evidence
                .verify_certificate_with(&fixture.authority, |_, _, _| {
                    panic!("wrong committee must fail before signature dispatch")
                })
                .is_err()
        );
        let mut substituted = evidence.clone();
        substituted.claim.post_create_state = Hash([0x73; 32]);
        assert!(substituted.verify_certificate(&trusted).is_err());

        // Even valid signatures must not authorize a claim in another space.
        let other_space = committee_for(SpaceId([0x74; 32]));
        let cross_space = sign(&other_space);
        cross_space
            .certificate()
            .verify(&other_space, cross_space.claim().authority_claim())
            .unwrap();
        assert_eq!(
            cross_space.verify_certificate(&other_space),
            Err(AgentGenesisError::InvalidEvidence)
        );
        assert_eq!(
            cross_space.verify_certificate_with(&other_space, |_, _, _| {
                panic!("wrong space must fail before signature dispatch")
            }),
            Err(AgentGenesisError::InvalidEvidence)
        );
    }

    fn maximum_replica_members() -> Vec<AgentReplicaMember> {
        let mut members = (0..MAX_AGENT_REPLICAS)
            .map(|ordinal| {
                let mut key = [0x31; 32];
                key[..2].copy_from_slice(&(ordinal as u16).to_le_bytes());
                let peer = peer_id(key);
                let voter = ordinal == 0;
                AgentReplicaMember::new(
                    AgentReplica {
                        node: NodeId::of_authenticated_peer(&peer),
                        principal: PrincipalId::of_public_key(&key),
                        role: if voter {
                            ReplicaRole::Voter
                        } else {
                            ReplicaRole::Observer
                        },
                    },
                    peer.clone(),
                    key,
                    voter.then(|| derive_replica_raft_slot(&peer)),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        members.sort_by_key(|member| member.replica().node);
        members
    }

    #[test]
    fn maximum_genesis_roster_requires_blob_transport_not_inline_invocation() {
        let baseline = fixture();
        let roster = AgentReplicaCommittee::new(
            baseline.proposal.locator().space,
            baseline.proposal.locator().agent,
            AgentProfile::Shared,
            maximum_replica_members(),
        )
        .unwrap();
        let encoded = roster.encode();
        assert_eq!(AgentReplicaCommittee::decode(&encoded).unwrap(), roster);
        assert!(encoded.len() <= MAX_AGENT_REPLICA_COMMITTEE_BYTES);
        assert!(encoded.len() > crate::agent_sdk::MAX_INVOCATION_MESSAGE_BYTES);
        println!(
            "maximum genesis roster={} invocation limit={}",
            encoded.len(),
            crate::agent_sdk::MAX_INVOCATION_MESSAGE_BYTES
        );
    }

    #[test]
    fn pending_clean_create_requires_exact_signed_authorization_before_publication() {
        check_pending_clean_create(false);
    }

    #[test]
    fn maximum_signed_genesis_provision_fits_caller_availability() {
        check_pending_clean_create(true);
    }

    fn check_pending_clean_create(maximum_roster: bool) {
        use crate::agent_sdk as sdk;
        use core::num::NonZeroU64;
        use ed25519_dalek::{Signer as _, SigningKey};
        use sdk::authority::*;

        struct Strict;
        impl AuthorityVerifier for Strict {
            fn verify(&self, key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
                ed25519_dalek::VerifyingKey::from_bytes(key).is_ok_and(|key| {
                    key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
                        .is_ok()
                })
            }
        }
        impl AuthorityCredentialVerifier for Strict {
            fn verify(&self, key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
                AuthorityVerifier::verify(self, key, message, signature)
            }
        }
        let mut baseline = fixture();
        if maximum_roster {
            baseline.replicas = AgentReplicaCommittee::new(
                baseline.proposal.locator().space,
                baseline.proposal.locator().agent,
                AgentProfile::Shared,
                maximum_replica_members(),
            ).unwrap();
        }
        let key = SigningKey::from_bytes(&[0x81; 32]);
        let public = key.verifying_key().to_bytes();
        let owner = sdk::PrincipalId::of_public_key(&public);
        let space = sdk::SpaceId(baseline.proposal.locator().space.0);
        let nonce = sdk::Hash([0x82; 32]);
        let agent = sdk::AgentId::derive(space, owner, nonce.as_bytes());
        let binding = sdk::authority::AgentAuthorityBinding {
            policy: sdk::Hash([0x83; 32]),
            issuer: AuthorityIssuer {
                principal: owner,
                actor: sdk::ActorId([0x84; 32]),
                deployment: sdk::DeploymentId([0x85; 32]),
                program: sdk::ProgramId([0x86; 32]),
                producer: sdk::ProducerId::of_public_key(&public),
            },
            public_key: public,
            initial_epoch: 1,
        };
        let descriptor = sdk::AgentDescriptor {
            identity: sdk::AgentIdentity {
                space,
                agent,
                owner,
                profile: sdk::AgentProfile::Shared,
                runtime_deployment: sdk::DeploymentId([0x87; 32]),
                runtime_program: sdk::ProgramId([0x88; 32]),
                runtime_producer: sdk::ProducerId([0x89; 32]),
                transition_producer: sdk::ProducerId([0x90; 32]),
            },
            creation_nonce: nonce,
            authority: binding,
            private_recovery: None,
            runtime_package: sdk::BlobRef::of_bytes(RUNTIME_BYTES),
            runtime_contract: sdk::contract::RuntimePackageContract::canonical(),
            capabilities: sdk::RuntimeCapabilities::standard(),
            replicas: baseline
                .replicas
                .members()
                .iter()
                .map(|member| {
                    let replica = member.replica();
                    sdk::AgentReplica {
                        node: sdk::NodeId(replica.node.0),
                        principal: sdk::PrincipalId(replica.principal.0),
                        role: match replica.role {
                            ReplicaRole::Voter => sdk::ReplicaRole::Voter,
                            ReplicaRole::Observer => sdk::ReplicaRole::Observer,
                        },
                    }
                })
                .collect(),
        };
        descriptor.validate().unwrap();
        let request = sdk::ManagementRequest::Create(Box::new(descriptor.clone()));
        let mut call = AuthorityCredentialCall {
            invocation: sdk::InvocationId::ZERO,
            authority: AuthorityActorTarget {
                space,
                system_agent: sdk::AgentId([0xa1; 32]),
                system_runtime_deployment: sdk::DeploymentId([0xa2; 32]),
                binding,
            },
            managed: ManagedAgentTarget {
                space,
                agent,
                owner,
                profile: sdk::AgentProfile::Shared,
                runtime_deployment: descriptor.identity.runtime_deployment,
                transition_producer: descriptor.identity.transition_producer,
            },
            principal: owner,
            credential: sdk::CredentialId::of_public_key(&public),
            request_sequence: NonZeroU64::new(1).unwrap(),
            credential_public_key: public,
            authenticated_node: None,
            requested_valid_from: 10,
            requested_expires_at: 30,
            plan: request.authorization_plan().unwrap(),
            signature: [1; 64],
        };
        call.invocation = call.expected_invocation();
        call.signature = key.sign(&call.signing_bytes()).to_bytes();
        let approval = ManagementApproval::from_call(
            &call,
            NonZeroU64::new(73).unwrap(),
            AuthorityEvidence {
                package: None,
                proof: None,
                commitment: sdk::Hash([0xa3; 32]),
            },
            AuthorityLaneRoots {
                control: Some(sdk::Hash([0xa4; 32])),
                linear: None,
                merge: None,
                local: None,
            },
            1,
            10,
            30,
        )
        .unwrap();
        let mut receipt = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: binding.policy,
                issuer: binding.issuer,
                space,
                agent,
                operation: approval.plan.authority_operation(),
                runtime_deployment: descriptor.identity.runtime_deployment,
                actor: None,
                actor_deployment: None,
                evidence: approval.evidence.clone(),
                lane_roots: approval.lane_roots,
                epoch: 1,
                decision_sequence: 7,
                acknowledged_through: 6,
                valid_from: 10,
                expires_at: 30,
                request: approval.plan_commitment,
            },
            public_key: public,
            signature: [1; 64],
        };
        receipt.signature = key.sign(&receipt.signing_bytes()).to_bytes();
        let mut runtime = baseline.proposal.create().runtime.clone();
        runtime.agent = AgentId(agent.0);
        runtime.deployment = DeploymentId(descriptor.identity.runtime_deployment.0);
        runtime.program = ProgramId(descriptor.identity.runtime_program.0);
        runtime.producer = ProducerId(descriptor.identity.runtime_producer.0);
        runtime.package = BlobRef::of_bytes(RUNTIME_BYTES);
        let create = ReplayInput {
            runtime,
            operation: ReplayOperation::CleanManage {
                request: request.clone(),
                authority: receipt,
                observed_slot: 20,
            },
        };
        let catalog = vec![create.runtime.package.clone()];
        let expectations = AgentGenesisExpectations::new(
            create.runtime.commitment(),
            Hash(request.commitment().0),
            Hash([0xa5; 32]),
            system_genesis_artifact_closure_commitment(&catalog).unwrap(),
            7,
        )
        .unwrap();
        let proposal = AgentGenesisProposal::new(
            AgentGenesisLocator {
                space: SpaceId(space.0),
                agent: AgentId(agent.0),
            },
            create,
            expectations,
            catalog,
        )
        .unwrap();
        let replicas = AgentReplicaCommittee::new(
            SpaceId(space.0),
            AgentId(agent.0),
            AgentProfile::Shared,
            baseline.replicas.members().to_vec(),
        )
        .unwrap();
        let member =
            AuthorityCommitteeMember::new(NodeId([0xa6; 32]), public, AuthorityMemberRole::Voter)
                .unwrap();
        let signer = member.signer();
        let committee = AuthorityCommittee::new(
            SpaceId(space.0),
            Hash(binding.commitment().0),
            1,
            None,
            vec![member],
        )
        .unwrap();
        let claim = AgentGenesisClaim::new(
            AgentId(call.authority.system_agent.0),
            AgentJournalGenesisId::new([0xa7; 32]),
            AgentGenesisAdmissionId::from_bytes([0xa8; 32]),
            &proposal,
            &replicas,
        )
        .unwrap();
        let message = AuthorityQuorumCertificate::signing_message(
            committee.authority_binding(),
            committee.epoch(),
            committee.commitment(),
            claim.authority_claim(),
        );
        let qc = AuthorityQuorumCertificate::new(
            &committee,
            claim.authority_claim(),
            vec![AuthoritySignature::new(signer, key.sign(&message.0).to_bytes()).unwrap()],
        )
        .unwrap();
        let evidence = AgentGenesisEvidence::new(claim, qc).unwrap();
        let decision = AgentGenesisDecision::new(&proposal, &replicas, &evidence).unwrap();
        let provision = AgentGenesisProvision::new(proposal, replicas, evidence, decision).unwrap();
        if maximum_roster {
            let encoded = provision.encode();
            println!("full signed provision={} proposal={} roster={} evidence={} decision={} caller_availability={}",
                encoded.len(), provision.proposal().encode().len(),
                provision.replicas().encode().len(), provision.evidence().encode().len(),
                provision.decision().encode().len(), sdk::MAX_RUNTIME_CALLER_AVAILABILITY_BYTES);
            assert_eq!(provision.replicas().members().len(), MAX_AGENT_REPLICAS);
            assert!(encoded.len() <= MAX_CLEAN_CREATE_GENESIS_PROVISION_BYTES);
            assert!(MAX_CLEAN_CREATE_GENESIS_PROVISION_BYTES <= sdk::MAX_RUNTIME_CALLER_AVAILABILITY_BYTES);
            assert!(encoded.len() <= sdk::MAX_RUNTIME_CALLER_AVAILABILITY_BYTES);
            let reference = crate::service::BlobRef::of_bytes(&encoded);
            let invocation = crate::agent::execution::ActorInvocation {
                invocation: crate::service::InvocationId([1; 32]),
                actor: crate::service::ActorId([2; 32]),
                incarnation: crate::service::Hash([3; 32]),
                deployment: crate::service::DeploymentId([4; 32]),
                program: crate::service::ProgramId([5; 32]),
                mode: crate::agent::MethodMode::Linear,
                auth: crate::agent::execution::ActorInvocationAuth::anonymous(),
                message: alloc::vec![1],
                availability: alloc::vec![crate::agent::execution::RuntimeBlob {
                    reference: reference.clone(), bytes: encoded,
                }],
                gas: 1,
            };
            assert!(invocation.validate().is_ok());
            assert_eq!(invocation.available_preimage(&reference).unwrap().unwrap(), provision.encode());
        }
        let publication = provision.publication_invocation(call.invocation).unwrap();
        assert_ne!(publication, sdk::InvocationId::ZERO);
        assert_ne!(publication, call.invocation);
        assert_ne!(publication, approval.acknowledgement_invocation);
        let reopened = AgentGenesisProvision::decode(&provision.encode()).unwrap();
        assert_eq!(
            reopened.publication_invocation(call.invocation),
            Ok(publication)
        );
        assert_ne!(
            provision
                .publication_invocation(sdk::InvocationId([0xb1; 32]))
                .unwrap(),
            publication
        );
        assert_ne!(
            baseline
                .provision
                .publication_invocation(call.invocation)
                .unwrap(),
            publication
        );
        assert!(
            provision
                .publication_invocation(sdk::InvocationId::ZERO)
                .is_err()
        );
        assert_eq!(
            provision.verify_pending_create_at(&call, &approval, &committee, 20, &Strict),
            Ok(())
        );
        for slot in [19, 31] {
            assert!(
                provision
                    .verify_pending_create_at(&call, &approval, &committee, slot, &Strict)
                    .is_err()
            );
        }
        let mut forged = call.clone();
        forged.signature[0] ^= 1;
        assert!(
            provision
                .verify_pending_create_at(&forged, &approval, &committee, 20, &Strict)
                .is_err()
        );
        let mut changed = approval.clone();
        changed.plan_commitment = sdk::Hash([0xaf; 32]);
        assert!(
            provision
                .verify_pending_create_at(&call, &changed, &committee, 20, &Strict)
                .is_err()
        );
        assert!(
            provision
                .verify_pending_create_at(&call, &approval, &baseline.authority, 20, &Strict)
                .is_err()
        );
    }

    #[test]
    fn ordinary_archive_binds_provision_and_exact_catalog_without_granting_finality() {
        let provision = fixture().provision;
        let runtime = RuntimeBlob { reference: BlobRef::of_bytes(RUNTIME_BYTES), bytes: RUNTIME_BYTES.to_vec() };
        let record = AgentGenesisArchiveRecord::new(provision.clone(), vec![runtime.clone()]).unwrap();
        let encoded = record.encode();
        assert!(encoded.len() <= MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES);
        let reopened = AgentGenesisArchiveRecord::decode(&encoded).unwrap();
        assert_eq!(reopened, record);
        assert_eq!(reopened.encode(), encoded);
        assert_eq!(reopened.catalog(), &[runtime.clone()]);
        assert!(AgentGenesisArchiveRecord::new(provision.clone(), vec![]).is_err());
        assert!(AgentGenesisArchiveRecord::new(provision.clone(), vec![runtime.clone(), runtime]).is_err());
        let other_bytes = b"substituted runtime".to_vec();
        let other = RuntimeBlob { reference: BlobRef::of_bytes(&other_bytes), bytes: other_bytes };
        assert!(AgentGenesisArchiveRecord::new(provision, vec![other]).is_err());
        let count_offset = SERVICE_WIRE_HEADER_BYTES + 4 + record.provision().encode().len();
        for offset in [0, SERVICE_WIRE_HEADER_BYTES + 4, count_offset, count_offset + 4, encoded.len() - 1] {
            let mut corrupt = encoded.clone();
            corrupt[offset] ^= 1;
            assert!(AgentGenesisArchiveRecord::decode(&corrupt).is_err(), "offset {offset}");
        }
        assert!(AgentGenesisArchiveRecord::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut oversized_length = encoded.clone();
        let length_offset = count_offset + 4 + BLOB_REFERENCE_BYTES;
        oversized_length[length_offset..length_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(AgentGenesisArchiveRecord::decode(&oversized_length).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(AgentGenesisArchiveRecord::decode(&trailing).is_err());
        struct NotFinalized;
        impl AgentGenesisFinalityVerifier for NotFinalized {
            fn verify_finalized(&self, _: &AgentGenesisProvision) -> Result<(), AgentGenesisFinalityError> {
                Err(AgentGenesisFinalityError::NotFinalized)
            }
        }
        assert!(matches!(
            VerifiedAgentGenesisProvision::verify(reopened.provision().clone(), &NotFinalized),
            Err(AgentGenesisProvisionVerificationError::Finality(AgentGenesisFinalityError::NotFinalized))
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn archive_provider_reloads_ambiguous_writes_and_refuses_conflicts() {
        use super::super::genesis_archive::{AgentGenesisArchiveStore, ArchivedAgentGenesisProvider};
        use std::sync::{Arc, Mutex};
        #[derive(Clone, Default)]
        struct Store(Arc<Mutex<(Option<Vec<u8>>, bool, usize)>>);
        impl AgentGenesisArchiveStore for Store {
            type Error = ();
            fn load(&self, _: AgentGenesisLocator) -> Result<Option<Vec<u8>>, ()> {
                Ok(self.0.lock().unwrap().0.clone())
            }
            fn insert_if_absent(&self, _: AgentGenesisLocator, record: &[u8]) -> Result<(), ()> {
                let mut state = self.0.lock().unwrap();
                state.2 += 1;
                state.0.get_or_insert_with(|| record.to_vec());
                if core::mem::take(&mut state.1) { Err(()) } else { Ok(()) }
            }
        }
        let fixture = fixture();
        let locator = fixture.proposal.locator();
        let catalog = vec![RuntimeBlob { reference: BlobRef::of_bytes(RUNTIME_BYTES), bytes: RUNTIME_BYTES.to_vec() }];
        let record = AgentGenesisArchiveRecord::new(fixture.provision.clone(), catalog.clone()).unwrap();
        let store = Store::default();
        let archive = ArchivedAgentGenesisProvider::new(locator.space, store.clone()).unwrap();
        assert_eq!(archive.create(&fixture.proposal, &catalog), Err(AgentGenesisProviderError::NotConfigured));
        store.0.lock().unwrap().1 = true;
        assert_eq!(archive.publish(&record), Err(AgentGenesisProviderError::Unavailable));
        drop(archive);
        let archive = ArchivedAgentGenesisProvider::new(locator.space, store.clone()).unwrap();
        archive.publish(&record).unwrap();
        assert_eq!(store.0.lock().unwrap().2, 2, "exact retry must reestablish the durability barrier");
        assert_eq!(store.0.lock().unwrap().0.as_deref(), Some(record.encode().as_slice()));
        assert_eq!(archive.create(&fixture.proposal, &catalog).unwrap(), fixture.provision);
        assert_eq!(archive.reproduce(locator).unwrap(), fixture.provision);
        assert_eq!(archive.load_catalog(locator, &catalog[0].reference).unwrap(), Some(RUNTIME_BYTES.to_vec()));
        assert_eq!(archive.load_catalog(locator, &BlobRef::of_bytes(b"unknown")).unwrap(), None);

        // Structurally consistent alternate evidence for the same locator is
        // still a conflict. Neither fixture is trusted finality evidence.
        let mut claim = fixture.evidence.claim().clone();
        claim.system_genesis = AgentJournalGenesisId::new([0x94; 32]);
        let certificate = AuthorityQuorumCertificate::new(
            &fixture.authority, claim.authority_claim(), fixture.evidence.certificate().signatures().to_vec(),
        ).unwrap();
        let evidence = AgentGenesisEvidence::new(claim, certificate).unwrap();
        let decision = AgentGenesisDecision::new(&fixture.proposal, &fixture.replicas, &evidence).unwrap();
        let other = AgentGenesisProvision::new(fixture.proposal, fixture.replicas, evidence, decision).unwrap();
        let other = AgentGenesisArchiveRecord::new(other, catalog).unwrap();
        assert_eq!(archive.publish(&other), Err(AgentGenesisProviderError::Conflict));
        assert_eq!(archive.reproduce(locator).unwrap(), fixture.provision);
        assert_eq!(store.0.lock().unwrap().2, 2, "conflicting records must not attempt insertion");
        assert_eq!(archive.reproduce(AgentGenesisLocator { space: SpaceId([0xa1; 32]), ..locator }), Err(AgentGenesisProviderError::Refused));
        assert_eq!(archive.reproduce(AgentGenesisLocator { agent: AgentId([0xa2; 32]), ..locator }), Err(AgentGenesisProviderError::Corrupt));
        store.0.lock().unwrap().0.as_mut().unwrap().push(0);
        assert_eq!(archive.reproduce(locator), Err(AgentGenesisProviderError::Corrupt));
    }

    #[test]
    fn self_consistent_provision_never_bypasses_independent_finality() {
        use core::sync::atomic::{AtomicUsize, Ordering};

        struct ControlledFinality {
            calls: AtomicUsize,
            failure: Option<AgentGenesisFinalityError>,
        }
        impl AgentGenesisFinalityVerifier for ControlledFinality {
            fn verify_finalized(
                &self,
                provision: &AgentGenesisProvision,
            ) -> Result<(), AgentGenesisFinalityError> {
                provision.validate().unwrap();
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.failure.map_or(Ok(()), Err)
            }
        }

        let provision = fixture().provision;
        provision.validate().unwrap();
        for failure in [
            AgentGenesisFinalityError::Unavailable,
            AgentGenesisFinalityError::NotFinalized,
            AgentGenesisFinalityError::WrongSystemAgent,
            AgentGenesisFinalityError::Conflict,
            AgentGenesisFinalityError::Corrupt,
        ] {
            let verifier = ControlledFinality {
                calls: AtomicUsize::new(0),
                failure: Some(failure),
            };
            for attempt in 1..=2 {
                assert!(matches!(
                    VerifiedAgentGenesisProvision::verify(provision.clone(), &verifier),
                    Err(AgentGenesisProvisionVerificationError::Finality(error)) if error == failure
                ));
                assert_eq!(verifier.calls.load(Ordering::SeqCst), attempt);
            }
            // Invalid provider contents must not even reach external trust.
            let mut substituted = provision.clone();
            substituted.decision.system_genesis = AgentJournalGenesisId::new([0xf1; 32]);
            assert!(matches!(
                VerifiedAgentGenesisProvision::verify(substituted, &verifier),
                Err(AgentGenesisProvisionVerificationError::InvalidProvision(_))
            ));
            assert_eq!(verifier.calls.load(Ordering::SeqCst), 2);
        }
        // A prior successful promotion is not permission to skip the next
        // verification when reopening. This fake verifier tests sequencing,
        // not authenticity of the fixture's synthetic certificate.
        let mut verifier = ControlledFinality {
            calls: AtomicUsize::new(0),
            failure: None,
        };
        let verified = VerifiedAgentGenesisProvision::verify(provision.clone(), &verifier).unwrap();
        assert_eq!(verified.provision(), &provision);
        verifier.failure = Some(AgentGenesisFinalityError::Unavailable);
        assert!(matches!(
            VerifiedAgentGenesisProvision::verify(provision, &verifier),
            Err(AgentGenesisProvisionVerificationError::Finality(
                AgentGenesisFinalityError::Unavailable
            ))
        ));
        assert_eq!(verifier.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn ordinary_provision_roundtrips_and_links_every_component() {
        let fixture = fixture();
        assert_eq!(
            AgentGenesisProposal::decode(&fixture.proposal.encode()).unwrap(),
            fixture.proposal
        );
        assert_eq!(
            AgentReplicaCommittee::decode(&fixture.replicas.encode()).unwrap(),
            fixture.replicas
        );
        assert_eq!(
            AgentGenesisEvidence::decode(&fixture.evidence.encode()).unwrap(),
            fixture.evidence
        );
        assert_eq!(
            AgentGenesisDecision::decode(&fixture.decision.encode()).unwrap(),
            fixture.decision
        );
        assert_eq!(
            AgentGenesisProvision::decode(&fixture.provision.encode()).unwrap(),
            fixture.provision
        );

        let admission = fixture.provision.admission_record().unwrap();
        assert_eq!(
            AgentGenesisAdmissionRecord::decode(&admission.encode()).unwrap(),
            admission
        );
        assert_ne!(admission.id(), AgentGenesisAdmissionId::ZERO);
        assert!(fixture.proposal.encode().len() <= MAX_AGENT_GENESIS_PROPOSAL_BYTES);
        assert!(fixture.replicas.encode().len() <= MAX_AGENT_REPLICA_COMMITTEE_BYTES);
        assert!(fixture.evidence.encode().len() <= MAX_AGENT_GENESIS_EVIDENCE_BYTES);
        assert!(fixture.decision.encode().len() <= MAX_AGENT_GENESIS_DECISION_BYTES);
        assert!(admission.encode().len() <= MAX_AGENT_GENESIS_ADMISSION_BYTES);
        assert!(fixture.provision.encode().len() <= MAX_AGENT_GENESIS_PROVISION_BYTES);

        assert_eq!(fixture.replicas.voter_count(), 2);
        assert_eq!(fixture.replicas.quorum_threshold(), 2);
        let first = &fixture.replicas.members()[0];
        assert_eq!(
            fixture.replicas.member_by_node(first.replica().node),
            Some(first)
        );
        assert_eq!(
            fixture.replicas.member_by_peer_id(first.peer_id()),
            Some(first)
        );
        if let Some(slot) = first.raft_slot() {
            assert_eq!(fixture.replicas.member_by_raft_slot(slot), Some(first));
        }
        assert_eq!(
            fixture.replicas.id().as_hash(),
            fixture.replicas.commitment()
        );

        let runtime = RuntimeBlob {
            reference: BlobRef::of_bytes(RUNTIME_BYTES),
            bytes: RUNTIME_BYTES.to_vec(),
        };
        assert_eq!(
            validate_agent_genesis_catalog(&fixture.proposal, &[runtime.clone()]),
            Ok(())
        );
        assert_eq!(
            validate_agent_genesis_catalog(&fixture.proposal, &[]),
            Err(AgentGenesisError::InvalidCatalog)
        );
        assert_eq!(
            validate_agent_genesis_catalog(&fixture.proposal, &[runtime.clone(), runtime.clone()]),
            Err(AgentGenesisError::InvalidCatalog)
        );
        // An internally valid package is still not the package committed by
        // this proposal. Provider-supplied hashes cannot redefine that binding.
        let replacement_bytes = b"different ordinary genesis runtime".to_vec();
        let replacement = RuntimeBlob {
            reference: BlobRef::of_bytes(&replacement_bytes),
            bytes: replacement_bytes,
        };
        assert!(replacement.reference.matches(&replacement.bytes));
        assert_ne!(replacement.reference, runtime.reference);
        assert_eq!(
            validate_agent_genesis_catalog(&fixture.proposal, &[replacement]),
            Err(AgentGenesisError::InvalidCatalog)
        );
        let mut corrupt = runtime;
        corrupt.bytes.push(0);
        assert_eq!(
            validate_agent_genesis_catalog(&fixture.proposal, &[corrupt]),
            Err(AgentGenesisError::InvalidCatalog)
        );
    }

    #[test]
    fn root_bootstrap_wraps_the_existing_admission_exactly() {
        let mut old_wire = Vec::new();
        old_wire.extend_from_slice(b"AGGA");
        old_wire.extend_from_slice(&PLATFORM_ID.0);
        let mut encoder = Encoder(&mut old_wire);
        encoder.fixed(&[0x61; 32]);
        encoder.u64(4);
        encoder.fixed(&[0x62; 32]);
        encoder.fixed(&[0x63; 32]);
        encoder.u8(AuthorityClaimDomain::SystemAgentGenesis as u8);
        encoder.u64(9);
        encoder.fixed(&[0x64; 32]);
        let old = SystemAgentGenesisAdmissionRecord::decode(&old_wire).unwrap();

        let generic = AgentGenesisAdmissionRecord::root_bootstrap(old).unwrap();
        let decoded = AgentGenesisAdmissionRecord::decode(&generic.encode()).unwrap();
        assert_eq!(decoded, generic);
        let AgentGenesisAdmissionRecord::RootBootstrap(nested) = decoded else {
            panic!("root tag changed while decoding");
        };
        assert_eq!(nested, old);
        assert_eq!(nested.encode(), old_wire);
        assert_ne!(generic.id().as_hash(), old.id().as_hash());
    }

    #[test]
    fn admission_tags_and_claim_domains_are_fail_closed() {
        let fixture = fixture();
        let admission = fixture.provision.admission_record().unwrap();
        let mut unknown_tag = admission.encode();
        unknown_tag[SERVICE_WIRE_HEADER_BYTES] = 2;
        assert_eq!(
            AgentGenesisAdmissionRecord::decode(&unknown_tag),
            Err(DecodeError::InvalidTag)
        );

        let mut wrong_domain = admission.encode();
        let claim_domain_offset = SERVICE_WIRE_HEADER_BYTES + 1 + 3 * 32;
        wrong_domain[claim_domain_offset] = AuthorityClaimDomain::SystemAgentGenesis as u8;
        assert_eq!(
            AgentGenesisAdmissionRecord::decode(&wrong_domain),
            Err(DecodeError::NonCanonical)
        );

        let claim = fixture.evidence.claim().authority_claim();
        let cross_domain = AuthorityClaimCommitment::from_payload_commitment(
            AuthorityClaimDomain::SystemAgentGenesis,
            claim.sequence(),
            claim.payload_commitment(),
        )
        .unwrap();
        assert_ne!(claim.claim_hash(), cross_domain.claim_hash());
    }

    #[test]
    fn replica_owner_is_distinct_from_transport_but_bound_by_certified_roster() {
        let fixture = fixture();
        let original = fixture.replicas.members()[0].clone();
        let mut logical = original.replica();
        logical.principal = PrincipalId([0x82; 32]);
        assert_ne!(logical.principal, PrincipalId::of_public_key(original.ed25519_public_key()));
        let owner_member = AgentReplicaMember::new(
            logical, original.peer_id().to_vec(), *original.ed25519_public_key(), original.raft_slot(),
        ).unwrap();
        let mut members = fixture.replicas.members().to_vec();
        members[0] = owner_member;
        let changed = AgentReplicaCommittee::new(
            fixture.replicas.space(), fixture.replicas.agent(), fixture.replicas.profile(), members,
        ).unwrap();
        assert_ne!(changed.id(), fixture.replicas.id());
        assert_eq!(AgentReplicaCommittee::decode(&changed.encode()).unwrap(), changed);
        assert!(fixture.evidence.claim().validate_against(&fixture.proposal, &changed).is_err());
        // A self-consistent transport mapping cannot replace the owner in an
        // existing authority-certified provision or its exact descriptor.
        assert!(AgentGenesisProvision::new(
            fixture.proposal.clone(), changed, fixture.evidence.clone(), fixture.decision.clone(),
        ).is_err());
    }

    #[test]
    fn replica_roster_rejects_identity_order_slot_and_size_tampering() {
        let fixture = fixture();
        let first = fixture.replicas.members()[0].clone();

        let mut wrong_key = first.clone();
        wrong_key.ed25519_public_key[0] ^= 1;
        assert_eq!(
            wrong_key.validate_identity(),
            Err(AgentGenesisError::InvalidReplicaCommittee)
        );

        let mut wrong_node = first.clone();
        wrong_node.replica.node = NodeId([0x81; 32]);
        assert_eq!(
            wrong_node.validate_identity(),
            Err(AgentGenesisError::InvalidReplicaCommittee)
        );

        let mut wrong_principal = first.clone();
        wrong_principal.replica.principal = PrincipalId::ZERO;
        assert_eq!(
            wrong_principal.validate_identity(),
            Err(AgentGenesisError::InvalidReplicaCommittee)
        );

        let zero_key_peer = peer_id([0; 32]);
        let zero_key = AgentReplicaMember {
            replica: AgentReplica {
                node: NodeId::of_authenticated_peer(&zero_key_peer),
                principal: PrincipalId::of_public_key(&[0; 32]),
                role: ReplicaRole::Voter,
            },
            peer_id: zero_key_peer,
            ed25519_public_key: [0; 32],
            raft_slot: None,
        };
        assert_eq!(
            zero_key.validate_identity(),
            Err(AgentGenesisError::InvalidReplicaCommittee)
        );

        let mut wrong_slot = fixture.replicas.clone();
        let voter = wrong_slot
            .members
            .iter_mut()
            .find(|member| member.replica.role == ReplicaRole::Voter)
            .unwrap();
        voter.raft_slot = Some(voter.raft_slot.unwrap().wrapping_add(1));
        assert_eq!(
            wrong_slot.validate(),
            Err(AgentGenesisError::InvalidReplicaCommittee)
        );

        let mut unsorted = fixture.replicas.clone();
        unsorted.members.swap(0, 1);
        assert_eq!(
            unsorted.validate(),
            Err(AgentGenesisError::InvalidReplicaCommittee)
        );

        assert_eq!(
            AgentReplicaCommittee::new(
                fixture.replicas.space(),
                fixture.replicas.agent(),
                AgentProfile::Shared,
                vec![first.clone(), first],
            ),
            Err(AgentGenesisError::InvalidReplicaCommittee)
        );

        let mut excessive_count = fixture.replicas.encode();
        let count_offset = SERVICE_WIRE_HEADER_BYTES + 32 + 32 + 1;
        excessive_count[count_offset..count_offset + 4]
            .copy_from_slice(&((MAX_AGENT_REPLICAS + 1) as u32).to_le_bytes());
        assert_eq!(
            AgentReplicaCommittee::decode(&excessive_count),
            Err(DecodeError::LimitExceeded)
        );

        let mut oversized = fixture.replicas.encode();
        oversized.resize(MAX_AGENT_REPLICA_COMMITTEE_BYTES + 1, 0);
        assert_eq!(
            AgentReplicaCommittee::decode(&oversized),
            Err(DecodeError::LimitExceeded)
        );
    }

    #[test]
    fn provision_rejects_cross_component_and_certificate_tampering() {
        let fixture = fixture();
        let mut wrong_system_agent = fixture.evidence.claim().clone();
        wrong_system_agent.system_agent = AgentId([0x73; 32]);
        assert_eq!(
            wrong_system_agent.validate_against(&fixture.proposal, &fixture.replicas),
            Err(AgentGenesisError::InvalidClaim)
        );

        let mut wrong_link = fixture.provision.clone();
        wrong_link.evidence.claim.proposal = AgentGenesisProposalId::from_bytes([0x71; 32]);
        assert_eq!(
            wrong_link.validate(),
            Err(AgentGenesisError::InvalidEvidence)
        );
        assert_eq!(
            AgentGenesisProvision::decode(&wrong_link.encode()),
            Err(DecodeError::NonCanonical)
        );

        let signer = fixture.authority.members()[0].signer();
        let wrong_claim = AuthorityClaimCommitment::of_bytes(
            AuthorityClaimDomain::Lifecycle,
            fixture.evidence.claim().sequence(),
            &fixture.evidence.claim().encode(),
        );
        let wrong_certificate = AuthorityQuorumCertificate::new(
            &fixture.authority,
            wrong_claim,
            vec![AuthoritySignature::new(signer, [0x72; 64]).unwrap()],
        )
        .unwrap();
        assert_eq!(
            AgentGenesisEvidence::new(fixture.evidence.claim().clone(), wrong_certificate),
            Err(AgentGenesisError::InvalidEvidence)
        );

        let mut oversized = fixture.provision.admission_record().unwrap().encode();
        oversized.resize(MAX_AGENT_GENESIS_ADMISSION_BYTES + 1, 0);
        assert_eq!(
            AgentGenesisAdmissionRecord::decode(&oversized),
            Err(DecodeError::LimitExceeded)
        );
    }

    #[test]
    fn local_roster_has_one_exact_peer_and_no_raft_slot() {
        let space = SpaceId([0x81; 32]);
        let member = transport_member(0x83, ReplicaRole::Voter);
        let member = AgentReplicaMember::new(
            member.replica(),
            member.peer_id().to_vec(),
            *member.ed25519_public_key(),
            None,
        )
        .unwrap();
        let committee = AgentReplicaCommittee::new(
            space,
            AgentId([0x84; 32]),
            AgentProfile::Local,
            vec![member.clone()],
        )
        .unwrap();
        assert_eq!(committee.voter_count(), 1);
        assert_eq!(committee.quorum_threshold(), 1);
        assert_eq!(committee.member_by_peer_id(member.peer_id()), Some(&member));
        assert_eq!(committee.member_by_raft_slot(u16::MAX), None);

        let with_slot = AgentReplicaMember::new(
            member.replica(),
            member.peer_id().to_vec(),
            *member.ed25519_public_key(),
            Some(derive_replica_raft_slot(member.peer_id())),
        )
        .unwrap();
        assert_eq!(
            AgentReplicaCommittee::new(
                space,
                AgentId([0x84; 32]),
                AgentProfile::Local,
                vec![with_slot],
            ),
            Err(AgentGenesisError::InvalidReplicaCommittee)
        );
    }

    #[test]
    fn replica_slot_matches_the_network_byte_algorithm() {
        let peer_id = peer_id([0x91; 32]);
        let bytes = crate::crypto::blake2b_hash::<2>(b"", &[&peer_id]);
        let expected = match u16::from_le_bytes(bytes) {
            0 => u16::MAX,
            slot => slot,
        };
        assert_eq!(derive_replica_raft_slot(&peer_id), expected);
        assert_ne!(expected, 0);
    }
}
