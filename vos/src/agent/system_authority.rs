//! Root-seeded live-system authority state for ordinary Agent genesis.
//!
//! This module defines only canonical data and deterministic transitions.
//! Decoding a state, proof, committee, or provider record never promotes it
//! to authority. The replay layer must first authenticate the root system
//! Agent's Standard Control state from its root-admitted journal before it may
//! turn a successful membership lookup into an opaque ordinary-genesis seal.

use alloc::{vec, vec::Vec};
use core::fmt;

use super::committee::{
    AuthorityClaimCommitment, AuthorityClaimDomain, AuthorityCommittee, AuthorityCommitteeError,
    AuthorityQuorumCertificate, MAX_AUTHORITY_COMMITTEE_WIRE_BYTES, MAX_AUTHORITY_QC_WIRE_BYTES,
    RootAnchorConfigCommitment, RootAnchorId, RootAnchorRecord,
};
use super::genesis::{
    AgentGenesisAdmissionId, AgentGenesisClaim, AgentGenesisDecision, AgentGenesisDecisionId,
    AgentGenesisError, AgentGenesisEvidence, AgentGenesisEvidenceId, AgentGenesisProposalId,
    AgentGenesisProvision, AgentReplicaCommitteeId, MAX_AGENT_GENESIS_DECISION_BYTES,
    MAX_AGENT_GENESIS_EVIDENCE_BYTES,
};
use super::journal::{AgentJournalGenesisId, MAX_REPLAY_INPUT_BYTES};
use super::{AgentConfig, AgentProfile};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{AgentId, Hash, SpaceId};

const SERVICE_WIRE_HEADER_BYTES: usize = 4 + 32;
const DECISION_TREE_DEPTH: u16 = 256;
const MAX_DECISION_PROOF_SIBLINGS: usize = DECISION_TREE_DEPTH as usize;
const ROTATION_TREE_DEPTH: u16 = 64;
const MAX_ROTATION_PROOF_SIBLINGS: usize = ROTATION_TREE_DEPTH as usize;

pub const MAX_SYSTEM_AUTHORITY_DECISIONS: u32 = 65_536;
pub const MAX_SYSTEM_AUTHORITY_ROTATIONS: u32 = 4_096;
pub(crate) const MAX_SYSTEM_AUTHORITY_DECISION_TREE_NODES: usize =
    MAX_SYSTEM_AUTHORITY_DECISIONS as usize * (DECISION_TREE_DEPTH as usize + 1);
pub(crate) const MAX_SYSTEM_AUTHORITY_ROTATION_TREE_NODES: usize =
    MAX_SYSTEM_AUTHORITY_ROTATIONS as usize * (ROTATION_TREE_DEPTH as usize + 1);

/// Maximum complete root-seeding descriptor.
pub const MAX_SYSTEM_AUTHORITY_GENESIS_BYTES: usize =
    SERVICE_WIRE_HEADER_BYTES + 32 + 8 + 32 + 8 + 4 + 4 + 4 + MAX_AUTHORITY_COMMITTEE_WIRE_BYTES;
/// Maximum complete replay-authenticated authority state in Standard Control.
pub const MAX_SYSTEM_AUTHORITY_STATE_BYTES: usize = 380 + MAX_AUTHORITY_COMMITTEE_WIRE_BYTES;
/// Maximum complete finalized-decision fact.
pub const MAX_SYSTEM_AUTHORITY_DECISION_FACT_BYTES: usize = 470;
/// Maximum one permanent decision-history node.
pub const MAX_SYSTEM_AUTHORITY_DECISION_NODE_BYTES: usize =
    SERVICE_WIRE_HEADER_BYTES + 1 + 4 + MAX_SYSTEM_AUTHORITY_DECISION_FACT_BYTES;
/// Maximum complete compressed membership/nonmembership proof.
pub const MAX_SYSTEM_AUTHORITY_DECISION_PROOF_BYTES: usize = SERVICE_WIRE_HEADER_BYTES
    + 32
    + 1
    + 4
    + MAX_SYSTEM_AUTHORITY_DECISION_FACT_BYTES
    + 4
    + MAX_DECISION_PROOF_SIBLINGS * (2 + 32);
/// Maximum complete decision command. Full proposals and replica rosters stay
/// in the provider archive and are exact-compared only by ordinary sealing.
pub const MAX_SYSTEM_AUTHORITY_FINALIZE_BYTES: usize = SERVICE_WIRE_HEADER_BYTES
    + 4
    + MAX_AGENT_GENESIS_DECISION_BYTES
    + 4
    + MAX_AGENT_GENESIS_EVIDENCE_BYTES
    + 4
    + MAX_SYSTEM_AUTHORITY_DECISION_PROOF_BYTES;
/// Maximum complete compressed committee-rotation membership proof.
pub const MAX_SYSTEM_AUTHORITY_ROTATION_PROOF_BYTES: usize =
    SERVICE_WIRE_HEADER_BYTES + 8 + 1 + 4 + MAX_ROTATION_PROOF_SIBLINGS * (2 + 32);
/// Maximum scoped joint rotation certificate (claim plus old/new QCs).
pub const MAX_SYSTEM_AUTHORITY_ROTATION_CERTIFICATE_BYTES: usize = SERVICE_WIRE_HEADER_BYTES
    + 4
    + MAX_SYSTEM_AUTHORITY_ROTATION_CLAIM_BYTES
    + 2 * (4 + MAX_AUTHORITY_QC_WIRE_BYTES);
/// Maximum generation-scoped committee-rotation claim.
pub const MAX_SYSTEM_AUTHORITY_ROTATION_CLAIM_BYTES: usize = 300;
/// Maximum complete proof-carrying committee-rotation command.
pub const MAX_SYSTEM_AUTHORITY_ROTATION_BYTES: usize = SERVICE_WIRE_HEADER_BYTES
    + 4
    + MAX_AUTHORITY_COMMITTEE_WIRE_BYTES
    + 4
    + MAX_SYSTEM_AUTHORITY_ROTATION_CERTIFICATE_BYTES
    + 4
    + MAX_SYSTEM_AUTHORITY_ROTATION_PROOF_BYTES;
/// Maximum permanent rotation record and one encoded history node.
pub const MAX_SYSTEM_AUTHORITY_ROTATION_RECORD_BYTES: usize =
    SERVICE_WIRE_HEADER_BYTES + 32 + 32 + 4 + MAX_SYSTEM_AUTHORITY_ROTATION_CERTIFICATE_BYTES;
pub const MAX_SYSTEM_AUTHORITY_ROTATION_NODE_BYTES: usize =
    SERVICE_WIRE_HEADER_BYTES + 1 + 4 + MAX_SYSTEM_AUTHORITY_ROTATION_RECORD_BYTES;
/// Maximum one content-addressed committee record.
pub const MAX_SYSTEM_AUTHORITY_COMMITTEE_RECORD_BYTES: usize =
    SERVICE_WIRE_HEADER_BYTES + 4 + MAX_AUTHORITY_COMMITTEE_WIRE_BYTES;

// A rotation is itself the Management payload. Keep explicit headroom for
// its lifecycle tag and RuntimeBinding instead of silently increasing AGJI.
const _: () = assert!(MAX_SYSTEM_AUTHORITY_ROTATION_BYTES + 4096 <= MAX_REPLAY_INPUT_BYTES);

const ROTATION_ID_DOMAIN: &[u8] = b"vos/agent/system-authority/rotation/v1";
const AUTHORITY_SCOPE_DOMAIN: &[u8] = b"vos/agent/system-authority/journal-scope/v1";
const ROTATION_LEAF_ID_DOMAIN: &[u8] = b"vos/agent/system-authority/rotation-leaf/v1";
const ROTATION_BRANCH_ID_DOMAIN: &[u8] = b"vos/agent/system-authority/rotation-branch/v1";
const ROTATION_EMPTY_ID_DOMAIN: &[u8] = b"vos/agent/system-authority/rotation-empty/v1";
const DECISION_LEAF_ID_DOMAIN: &[u8] = b"vos/agent/system-authority/decision-leaf/v1";
const DECISION_BRANCH_ID_DOMAIN: &[u8] = b"vos/agent/system-authority/decision-branch/v1";
const DECISION_EMPTY_ID_DOMAIN: &[u8] = b"vos/agent/system-authority/decision-empty/v1";
const FINALIZE_OPERATION_DOMAIN: &[u8] = b"vos/agent/system-authority/finalize/v1";
const ROTATION_OPERATION_DOMAIN: &[u8] = b"vos/agent/system-authority/rotation-operation/v1";

macro_rules! authority_id_type {
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

authority_id_type!(SystemAuthorityCommitteeId, "SystemAuthorityCommitteeId");
authority_id_type!(
    SystemAuthorityScopeCommitment,
    "SystemAuthorityScopeCommitment"
);
authority_id_type!(SystemAuthorityRotationId, "SystemAuthorityRotationId");
authority_id_type!(
    SystemAuthorityDecisionNodeId,
    "SystemAuthorityDecisionNodeId"
);
authority_id_type!(
    SystemAuthorityRotationNodeId,
    "SystemAuthorityRotationNodeId"
);

impl SystemAuthorityCommitteeId {
    pub fn of(committee: &AuthorityCommittee) -> Self {
        // Authority QCs and rotation transitions already use this exact
        // canonical committee commitment. The typed wrapper prevents it from
        // being confused with an arbitrary Hash without adding a second ID.
        Self(committee.commitment().0)
    }
}

impl SystemAuthorityScopeCommitment {
    /// Commit to the exact clean generation selected by root-reverified
    /// replay. This commitment is public signing data, never a capability.
    pub fn for_journal(
        root_anchor: RootAnchorId,
        system_genesis: AgentJournalGenesisId,
        agent_admission: AgentGenesisAdmissionId,
    ) -> Result<Self, SystemAuthorityError> {
        if root_anchor == RootAnchorId::ZERO
            || system_genesis == AgentJournalGenesisId::ZERO
            || agent_admission == AgentGenesisAdmissionId::ZERO
        {
            return Err(SystemAuthorityError::InvalidScope);
        }
        Ok(Self(
            Hash::digest(
                AUTHORITY_SCOPE_DOMAIN,
                &[
                    root_anchor.as_bytes(),
                    &system_genesis.0,
                    agent_admission.as_bytes(),
                ],
            )
            .0,
        ))
    }
}

/// Root-pinned seed committed by the root system Agent's exact Create.
///
/// The containing [`super::AgentConfig`] supplies the space, system Agent,
/// and authority binding. Root sealing must exact-compare all fields here to
/// independently configured root pins; this type performs shape checks only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemAuthorityGenesis {
    root_anchor: RootAnchorId,
    root_anchor_config_version: u64,
    root_anchor_config: RootAnchorConfigCommitment,
    initial_committee: AuthorityCommittee,
    initial_sequence: u64,
    decision_limit: u32,
    rotation_limit: u32,
}

impl SystemAuthorityGenesis {
    pub fn new(
        root_anchor: RootAnchorId,
        root_anchor_config_version: u64,
        root_anchor_config: RootAnchorConfigCommitment,
        initial_committee: AuthorityCommittee,
        initial_sequence: u64,
        decision_limit: u32,
        rotation_limit: u32,
    ) -> Result<Self, SystemAuthorityError> {
        let genesis = Self {
            root_anchor,
            root_anchor_config_version,
            root_anchor_config,
            initial_committee,
            initial_sequence,
            decision_limit,
            rotation_limit,
        };
        genesis.validate()?;
        Ok(genesis)
    }

    pub const fn root_anchor(&self) -> RootAnchorId {
        self.root_anchor
    }

    pub const fn root_anchor_config_version(&self) -> u64 {
        self.root_anchor_config_version
    }

    pub const fn root_anchor_config(&self) -> RootAnchorConfigCommitment {
        self.root_anchor_config
    }

    pub const fn initial_committee(&self) -> &AuthorityCommittee {
        &self.initial_committee
    }

    pub const fn initial_sequence(&self) -> u64 {
        self.initial_sequence
    }

    pub const fn decision_limit(&self) -> u32 {
        self.decision_limit
    }

    pub const fn rotation_limit(&self) -> u32 {
        self.rotation_limit
    }

    pub fn validate(&self) -> Result<(), SystemAuthorityError> {
        self.initial_committee
            .validate()
            .map_err(SystemAuthorityError::Authority)?;
        if self.root_anchor == RootAnchorId::ZERO
            || self.root_anchor_config_version == 0
            || self.root_anchor_config == RootAnchorConfigCommitment::ZERO
            || self.initial_sequence == 0
            || self.decision_limit == 0
            || self.decision_limit > MAX_SYSTEM_AUTHORITY_DECISIONS
            || self.rotation_limit == 0
            || self.rotation_limit > MAX_SYSTEM_AUTHORITY_ROTATIONS
            || self.initial_committee.epoch() != 1
            || self.initial_committee.previous_committee().is_some()
        {
            return Err(SystemAuthorityError::InvalidGenesis);
        }
        enforce_encoded_bound(self, MAX_SYSTEM_AUTHORITY_GENESIS_BYTES)
    }

    /// Exact clean-break root-seeding check used by root sealing. The journal
    /// owner and the Agent named by the authority binding must be identical.
    pub(crate) fn validate_root_config(
        &self,
        configured_root: &RootAnchorRecord,
        config: &AgentConfig,
        create_receipt_sequence: u64,
    ) -> Result<(), SystemAuthorityError> {
        self.validate()?;
        configured_root
            .validate()
            .map_err(SystemAuthorityError::Authority)?;
        if config.identity.agent != config.authority.agent
            || config.identity.agent != configured_root.system_agent()
            || config.identity.space != configured_root.space()
            || config.authority.commitment() != configured_root.authority_binding()
            || self.root_anchor != configured_root.id()
            || self.root_anchor_config_version != configured_root.config_version()
            || self.root_anchor_config != configured_root.config_commitment()
            || self.initial_committee != *configured_root.initial_committee()
            || self.initial_sequence != create_receipt_sequence
        {
            Err(SystemAuthorityError::WrongSystemAgent)
        } else {
            Ok(())
        }
    }
}

impl ServiceWire for SystemAuthorityGenesis {
    const MAGIC: [u8; 4] = *b"SAG1";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(self.root_anchor.as_bytes());
        encoder.u64(self.root_anchor_config_version);
        encoder.fixed(self.root_anchor_config.as_bytes());
        encoder.bytes(&self.initial_committee.encode());
        encoder.u64(self.initial_sequence);
        encoder.u32(self.decision_limit);
        encoder.u32(self.rotation_limit);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SYSTEM_AUTHORITY_GENESIS_BYTES)?;
        let genesis = Self {
            root_anchor: RootAnchorId::from_bytes(decoder.fixed()?),
            root_anchor_config_version: decoder.u64()?,
            root_anchor_config: RootAnchorConfigCommitment::from_bytes(decoder.fixed()?),
            initial_committee: decode_nested(decoder, MAX_AUTHORITY_COMMITTEE_WIRE_BYTES)?,
            initial_sequence: decoder.u64()?,
            decision_limit: decoder.u32()?,
            rotation_limit: decoder.u32()?,
        };
        genesis.validate().map_err(map_decode_error)?;
        Ok(genesis)
    }
}

/// Opaque final root-journal scope selected by root-reverified replay, never
/// by provider bytes or public callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SystemAuthorityJournalScope {
    system_genesis: AgentJournalGenesisId,
    agent_admission: AgentGenesisAdmissionId,
}

impl SystemAuthorityJournalScope {
    pub(crate) fn new(
        system_genesis: AgentJournalGenesisId,
        agent_admission: AgentGenesisAdmissionId,
    ) -> Result<Self, SystemAuthorityError> {
        let scope = Self {
            system_genesis,
            agent_admission,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        system_genesis: AgentJournalGenesisId,
        agent_admission: AgentGenesisAdmissionId,
    ) -> Result<Self, SystemAuthorityError> {
        Self::new(system_genesis, agent_admission)
    }

    pub(crate) const fn system_genesis(self) -> AgentJournalGenesisId {
        self.system_genesis
    }

    pub(crate) const fn agent_admission(self) -> AgentGenesisAdmissionId {
        self.agent_admission
    }

    fn validate(self) -> Result<(), SystemAuthorityError> {
        if self.system_genesis == AgentJournalGenesisId::ZERO
            || self.agent_admission == AgentGenesisAdmissionId::ZERO
        {
            Err(SystemAuthorityError::InvalidScope)
        } else {
            Ok(())
        }
    }

    pub(crate) fn commitment(
        self,
        root_anchor: RootAnchorId,
    ) -> Result<SystemAuthorityScopeCommitment, SystemAuthorityError> {
        Self::validate(self)?;
        SystemAuthorityScopeCommitment::for_journal(
            root_anchor,
            self.system_genesis,
            self.agent_admission,
        )
    }
}

/// Permanent fact admitted by the live root system Agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemAuthorityDecisionFact {
    system_genesis: AgentJournalGenesisId,
    system_admission: AgentGenesisAdmissionId,
    space: crate::service::SpaceId,
    system_agent: AgentId,
    authority_binding: Hash,
    target_agent: AgentId,
    profile: AgentProfile,
    proposal: AgentGenesisProposalId,
    create_input: super::journal::ReplayInputId,
    decision: AgentGenesisDecisionId,
    evidence: AgentGenesisEvidenceId,
    replicas: AgentReplicaCommitteeId,
    claim: AuthorityClaimCommitment,
    committee: SystemAuthorityCommitteeId,
    committee_epoch: u64,
}

impl SystemAuthorityDecisionFact {
    fn from_records(
        decision: &AgentGenesisDecision,
        evidence: &AgentGenesisEvidence,
    ) -> Result<Self, SystemAuthorityError> {
        validate_decision_evidence_link(decision, evidence)?;
        let claim = evidence.claim();
        let fact = Self {
            system_genesis: claim.system_genesis(),
            system_admission: claim.system_admission(),
            space: claim.space(),
            system_agent: claim.system_agent(),
            authority_binding: claim.authority_binding(),
            target_agent: claim.agent(),
            profile: claim.profile(),
            proposal: claim.proposal(),
            create_input: claim.create_input(),
            decision: decision.id(),
            evidence: evidence.id(),
            replicas: claim.replicas(),
            claim: claim.authority_claim(),
            committee: SystemAuthorityCommitteeId::from_bytes(evidence.certificate().committee().0),
            committee_epoch: evidence.certificate().epoch(),
        };
        fact.validate()?;
        Ok(fact)
    }

    pub const fn system_genesis(&self) -> AgentJournalGenesisId {
        self.system_genesis
    }

    pub const fn system_admission(&self) -> AgentGenesisAdmissionId {
        self.system_admission
    }

    pub const fn space(&self) -> crate::service::SpaceId {
        self.space
    }

    pub const fn system_agent(&self) -> AgentId {
        self.system_agent
    }

    pub const fn authority_binding(&self) -> Hash {
        self.authority_binding
    }

    pub const fn target_agent(&self) -> AgentId {
        self.target_agent
    }

    pub const fn profile(&self) -> AgentProfile {
        self.profile
    }

    pub const fn proposal(&self) -> AgentGenesisProposalId {
        self.proposal
    }

    pub const fn create_input(&self) -> super::journal::ReplayInputId {
        self.create_input
    }

    pub const fn decision(&self) -> AgentGenesisDecisionId {
        self.decision
    }

    pub const fn evidence(&self) -> AgentGenesisEvidenceId {
        self.evidence
    }

    pub const fn replicas(&self) -> AgentReplicaCommitteeId {
        self.replicas
    }

    pub const fn claim(&self) -> AuthorityClaimCommitment {
        self.claim
    }

    pub const fn committee(&self) -> SystemAuthorityCommitteeId {
        self.committee
    }

    pub const fn committee_epoch(&self) -> u64 {
        self.committee_epoch
    }

    pub fn id(&self) -> SystemAuthorityDecisionNodeId {
        SystemAuthorityDecisionNodeId(Hash::digest(DECISION_LEAF_ID_DOMAIN, &[&self.encode()]).0)
    }

    pub fn validate(&self) -> Result<(), SystemAuthorityError> {
        if self.system_genesis == AgentJournalGenesisId::ZERO
            || self.system_admission == AgentGenesisAdmissionId::ZERO
            || self.space == crate::service::SpaceId::ZERO
            || self.system_agent == AgentId::ZERO
            || self.target_agent == AgentId::ZERO
            || self.target_agent == self.system_agent
            || self.authority_binding == Hash::ZERO
            || self.proposal == AgentGenesisProposalId::ZERO
            || self.create_input == super::journal::ReplayInputId::ZERO
            || self.decision == AgentGenesisDecisionId::ZERO
            || self.evidence == AgentGenesisEvidenceId::ZERO
            || self.replicas == AgentReplicaCommitteeId::ZERO
            || self.claim.domain() != AuthorityClaimDomain::AgentGenesis
            || self.committee == SystemAuthorityCommitteeId::ZERO
            || self.committee_epoch == 0
        {
            return Err(SystemAuthorityError::InvalidDecisionFact);
        }
        enforce_encoded_bound(self, MAX_SYSTEM_AUTHORITY_DECISION_FACT_BYTES)
    }
}

impl ServiceWire for SystemAuthorityDecisionFact {
    const MAGIC: [u8; 4] = *b"SADF";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.system_genesis.0);
        encoder.fixed(self.system_admission.as_bytes());
        encoder.fixed(&self.space.0);
        encoder.fixed(&self.system_agent.0);
        encoder.fixed(&self.authority_binding.0);
        encoder.fixed(&self.target_agent.0);
        encoder.u8(self.profile as u8);
        encoder.fixed(self.proposal.as_bytes());
        encoder.fixed(&self.create_input.0);
        encoder.fixed(self.decision.as_bytes());
        encoder.fixed(self.evidence.as_bytes());
        encoder.fixed(self.replicas.as_bytes());
        encode_authority_claim(&mut encoder, self.claim);
        encoder.fixed(self.committee.as_bytes());
        encoder.u64(self.committee_epoch);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SYSTEM_AUTHORITY_DECISION_FACT_BYTES)?;
        let fact = Self {
            system_genesis: AgentJournalGenesisId(decoder.fixed()?),
            system_admission: AgentGenesisAdmissionId::from_bytes(decoder.fixed()?),
            space: crate::service::SpaceId(decoder.fixed()?),
            system_agent: AgentId(decoder.fixed()?),
            authority_binding: Hash(decoder.fixed()?),
            target_agent: AgentId(decoder.fixed()?),
            profile: decode_profile(decoder.u8()?)?,
            proposal: AgentGenesisProposalId::from_bytes(decoder.fixed()?),
            create_input: super::journal::ReplayInputId(decoder.fixed()?),
            decision: AgentGenesisDecisionId::from_bytes(decoder.fixed()?),
            evidence: AgentGenesisEvidenceId::from_bytes(decoder.fixed()?),
            replicas: AgentReplicaCommitteeId::from_bytes(decoder.fixed()?),
            claim: decode_authority_claim(decoder)?,
            committee: SystemAuthorityCommitteeId::from_bytes(decoder.fixed()?),
            committee_epoch: decoder.u64()?,
        };
        fact.validate().map_err(map_decode_error)?;
        Ok(fact)
    }
}

/// One non-default sibling in a compressed 256-bit sparse Merkle path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemAuthorityDecisionSibling {
    depth: u16,
    node: SystemAuthorityDecisionNodeId,
}

impl SystemAuthorityDecisionSibling {
    pub fn new(
        depth: u16,
        node: SystemAuthorityDecisionNodeId,
    ) -> Result<Self, SystemAuthorityError> {
        let empty = decision_empty_ladder();
        if depth >= DECISION_TREE_DEPTH
            || node == SystemAuthorityDecisionNodeId::ZERO
            || node == empty[usize::from(depth + 1)]
        {
            return Err(SystemAuthorityError::InvalidDecisionProof);
        }
        Ok(Self { depth, node })
    }

    pub const fn depth(self) -> u16 {
        self.depth
    }

    pub const fn node(self) -> SystemAuthorityDecisionNodeId {
        self.node
    }
}

/// Bounded membership or nonmembership proof for one target AgentId.
/// Omitted siblings are the canonical empty subtree for that depth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemAuthorityDecisionProof {
    target_agent: AgentId,
    occupied: Option<SystemAuthorityDecisionFact>,
    siblings: Vec<SystemAuthorityDecisionSibling>,
}

impl SystemAuthorityDecisionProof {
    pub fn vacant(
        target_agent: AgentId,
        siblings: Vec<SystemAuthorityDecisionSibling>,
    ) -> Result<Self, SystemAuthorityError> {
        Self::new(target_agent, None, siblings)
    }

    pub fn occupied(
        fact: SystemAuthorityDecisionFact,
        siblings: Vec<SystemAuthorityDecisionSibling>,
    ) -> Result<Self, SystemAuthorityError> {
        let target_agent = fact.target_agent;
        Self::new(target_agent, Some(fact), siblings)
    }

    fn new(
        target_agent: AgentId,
        occupied: Option<SystemAuthorityDecisionFact>,
        siblings: Vec<SystemAuthorityDecisionSibling>,
    ) -> Result<Self, SystemAuthorityError> {
        let proof = Self {
            target_agent,
            occupied,
            siblings,
        };
        proof.validate()?;
        Ok(proof)
    }

    pub const fn target_agent(&self) -> AgentId {
        self.target_agent
    }

    pub const fn occupied_fact(&self) -> Option<&SystemAuthorityDecisionFact> {
        self.occupied.as_ref()
    }

    pub fn siblings(&self) -> &[SystemAuthorityDecisionSibling] {
        &self.siblings
    }

    pub fn root(&self) -> Result<SystemAuthorityDecisionNodeId, SystemAuthorityError> {
        self.validate()?;
        let leaf = self.occupied.as_ref().map_or_else(
            || empty_decision_node(DECISION_TREE_DEPTH),
            |fact| fact.id(),
        );
        Ok(root_from_path(self.target_agent, leaf, &self.siblings))
    }

    pub fn verifies(
        &self,
        expected_root: SystemAuthorityDecisionNodeId,
    ) -> Result<(), SystemAuthorityError> {
        if expected_root == SystemAuthorityDecisionNodeId::ZERO || self.root()? != expected_root {
            Err(SystemAuthorityError::InvalidDecisionProof)
        } else {
            Ok(())
        }
    }

    fn validate(&self) -> Result<(), SystemAuthorityError> {
        let empty = decision_empty_ladder();
        if self.target_agent == AgentId::ZERO
            || self.siblings.len() > MAX_DECISION_PROOF_SIBLINGS
            || self.occupied.as_ref().is_some_and(|fact| {
                fact.target_agent != self.target_agent || fact.validate().is_err()
            })
        {
            return Err(SystemAuthorityError::InvalidDecisionProof);
        }
        let mut previous = None;
        for sibling in &self.siblings {
            if sibling.depth >= DECISION_TREE_DEPTH
                || sibling.node == SystemAuthorityDecisionNodeId::ZERO
                || sibling.node == empty[usize::from(sibling.depth + 1)]
                || previous.is_some_and(|depth| depth >= sibling.depth)
            {
                return Err(SystemAuthorityError::InvalidDecisionProof);
            }
            previous = Some(sibling.depth);
        }
        enforce_encoded_bound(self, MAX_SYSTEM_AUTHORITY_DECISION_PROOF_BYTES)
    }
}

impl ServiceWire for SystemAuthorityDecisionProof {
    const MAGIC: [u8; 4] = *b"SADP";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.target_agent.0);
        encoder.option(&self.occupied, |encoder, fact| {
            encoder.bytes(&fact.encode())
        });
        encoder.u32(self.siblings.len() as u32);
        for sibling in &self.siblings {
            encoder.u16(sibling.depth);
            encoder.fixed(sibling.node.as_bytes());
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SYSTEM_AUTHORITY_DECISION_PROOF_BYTES)?;
        let target_agent = AgentId(decoder.fixed()?);
        let occupied = decoder.option(|decoder| {
            decode_nested::<SystemAuthorityDecisionFact>(
                decoder,
                MAX_SYSTEM_AUTHORITY_DECISION_FACT_BYTES,
            )
        })?;
        let count = decoder.u32()? as usize;
        if count > MAX_DECISION_PROOF_SIBLINGS {
            return Err(DecodeError::LimitExceeded);
        }
        let mut siblings = Vec::new();
        siblings
            .try_reserve_exact(count)
            .map_err(|_| DecodeError::LimitExceeded)?;
        for _ in 0..count {
            siblings.push(SystemAuthorityDecisionSibling {
                depth: decoder.u16()?,
                node: SystemAuthorityDecisionNodeId::from_bytes(decoder.fixed()?),
            });
        }
        let proof = Self {
            target_agent,
            occupied,
            siblings,
        };
        proof.validate().map_err(map_decode_error)?;
        Ok(proof)
    }
}

/// Immutable node write derived from one verified insertion path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SystemAuthorityDecisionNode {
    Leaf(SystemAuthorityDecisionFact),
    Branch {
        depth: u16,
        left: SystemAuthorityDecisionNodeId,
        right: SystemAuthorityDecisionNodeId,
    },
}

impl SystemAuthorityDecisionNode {
    pub fn id(&self) -> SystemAuthorityDecisionNodeId {
        match self {
            Self::Leaf(fact) => fact.id(),
            Self::Branch { depth, left, right } => decision_branch_id(*depth, *left, *right),
        }
    }

    pub fn validate(&self) -> Result<(), SystemAuthorityError> {
        match self {
            Self::Leaf(fact) => fact.validate(),
            Self::Branch { depth, left, right }
                if *depth < DECISION_TREE_DEPTH
                    && *left != SystemAuthorityDecisionNodeId::ZERO
                    && *right != SystemAuthorityDecisionNodeId::ZERO
                    && *left != *right =>
            {
                Ok(())
            }
            Self::Branch { .. } => Err(SystemAuthorityError::InvalidDecisionNode),
        }
    }
}

impl ServiceWire for SystemAuthorityDecisionNode {
    const MAGIC: [u8; 4] = *b"SADN";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        match self {
            Self::Leaf(fact) => {
                encoder.u8(0);
                encoder.bytes(&fact.encode());
            }
            Self::Branch { depth, left, right } => {
                encoder.u8(1);
                encoder.u16(*depth);
                encoder.fixed(left.as_bytes());
                encoder.fixed(right.as_bytes());
            }
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SYSTEM_AUTHORITY_DECISION_NODE_BYTES)?;
        let node = match decoder.u8()? {
            0 => Self::Leaf(decode_nested(
                decoder,
                MAX_SYSTEM_AUTHORITY_DECISION_FACT_BYTES,
            )?),
            1 => Self::Branch {
                depth: decoder.u16()?,
                left: SystemAuthorityDecisionNodeId::from_bytes(decoder.fixed()?),
                right: SystemAuthorityDecisionNodeId::from_bytes(decoder.fixed()?),
            },
            _ => return Err(DecodeError::InvalidTag),
        };
        node.validate().map_err(map_decode_error)?;
        Ok(node)
    }
}

/// Deterministic permanent-node write plan for one decision insertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SystemAuthorityDecisionWritePlan {
    previous_root: SystemAuthorityDecisionNodeId,
    root: SystemAuthorityDecisionNodeId,
    inserted: bool,
    nodes: Vec<SystemAuthorityDecisionNode>,
    retired_node_ids: Vec<SystemAuthorityDecisionNodeId>,
}

impl SystemAuthorityDecisionWritePlan {
    pub(crate) const fn previous_root(&self) -> SystemAuthorityDecisionNodeId {
        self.previous_root
    }

    pub(crate) const fn root(&self) -> SystemAuthorityDecisionNodeId {
        self.root
    }

    pub(crate) const fn inserted(&self) -> bool {
        self.inserted
    }

    pub(crate) fn nodes(&self) -> &[SystemAuthorityDecisionNode] {
        &self.nodes
    }

    /// Reachability hints only. A store may retire these IDs only after the
    /// successor head CAS and checkpoint/reachability closure make them dead.
    pub(crate) fn retired_node_ids(&self) -> &[SystemAuthorityDecisionNodeId] {
        &self.retired_node_ids
    }
}

/// Proof-carrying bounded command finalized in the system Agent's ordered
/// control history. Provider proposal/catalog/replica bytes are deliberately
/// absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemAuthorityFinalize {
    decision: AgentGenesisDecision,
    evidence: AgentGenesisEvidence,
    proof: SystemAuthorityDecisionProof,
}

impl SystemAuthorityFinalize {
    pub fn new(
        decision: AgentGenesisDecision,
        evidence: AgentGenesisEvidence,
        proof: SystemAuthorityDecisionProof,
    ) -> Result<Self, SystemAuthorityError> {
        let finalize = Self {
            decision,
            evidence,
            proof,
        };
        finalize.validate()?;
        Ok(finalize)
    }

    pub const fn decision(&self) -> &AgentGenesisDecision {
        &self.decision
    }

    pub const fn evidence(&self) -> &AgentGenesisEvidence {
        &self.evidence
    }

    pub const fn proof(&self) -> &SystemAuthorityDecisionProof {
        &self.proof
    }

    pub fn fact(&self) -> Result<SystemAuthorityDecisionFact, SystemAuthorityError> {
        SystemAuthorityDecisionFact::from_records(&self.decision, &self.evidence)
    }

    pub fn operation_commitment(&self) -> Hash {
        Hash::digest(
            FINALIZE_OPERATION_DOMAIN,
            &[&self.decision.encode(), &self.evidence.encode()],
        )
    }

    pub fn validate(&self) -> Result<(), SystemAuthorityError> {
        let fact = self.fact()?;
        self.proof.validate()?;
        if self.proof.target_agent != fact.target_agent {
            return Err(SystemAuthorityError::InvalidFinalize);
        }
        enforce_encoded_bound(self, MAX_SYSTEM_AUTHORITY_FINALIZE_BYTES)
    }
}

impl ServiceWire for SystemAuthorityFinalize {
    const MAGIC: [u8; 4] = *b"SAFN";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.decision.encode());
        encoder.bytes(&self.evidence.encode());
        encoder.bytes(&self.proof.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SYSTEM_AUTHORITY_FINALIZE_BYTES)?;
        let finalize = Self {
            decision: decode_nested(decoder, MAX_AGENT_GENESIS_DECISION_BYTES)?,
            evidence: decode_nested(decoder, MAX_AGENT_GENESIS_EVIDENCE_BYTES)?,
            proof: decode_nested(decoder, MAX_SYSTEM_AUTHORITY_DECISION_PROOF_BYTES)?,
        };
        finalize.validate().map_err(map_decode_error)?;
        Ok(finalize)
    }
}

/// Content-addressed committee record retained for audit and old decision
/// facts after rotation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemAuthorityCommitteeRecord {
    committee: AuthorityCommittee,
}

impl SystemAuthorityCommitteeRecord {
    pub fn new(committee: AuthorityCommittee) -> Result<Self, SystemAuthorityError> {
        committee
            .validate()
            .map_err(SystemAuthorityError::Authority)?;
        let record = Self { committee };
        enforce_encoded_bound(&record, MAX_SYSTEM_AUTHORITY_COMMITTEE_RECORD_BYTES)?;
        Ok(record)
    }

    pub const fn committee(&self) -> &AuthorityCommittee {
        &self.committee
    }

    pub fn id(&self) -> SystemAuthorityCommitteeId {
        SystemAuthorityCommitteeId::of(&self.committee)
    }
}

impl ServiceWire for SystemAuthorityCommitteeRecord {
    const MAGIC: [u8; 4] = *b"SACM";

    fn encode_body(&self, output: &mut Vec<u8>) {
        Encoder(output).bytes(&self.committee.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SYSTEM_AUTHORITY_COMMITTEE_RECORD_BYTES)?;
        Self::new(decode_nested(decoder, MAX_AUTHORITY_COMMITTEE_WIRE_BYTES)?)
            .map_err(map_decode_error)
    }
}

/// Exact generation-scoped transition jointly signed by the retiring and
/// incoming committees. In contrast to the generic committee transition, the
/// signed payload names the materialized root journal generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemAuthorityRotationClaim {
    root_anchor: RootAnchorId,
    root_anchor_config_version: u64,
    root_anchor_config: RootAnchorConfigCommitment,
    authority_scope: SystemAuthorityScopeCommitment,
    space: SpaceId,
    authority_binding: Hash,
    old_epoch: u64,
    old_committee: SystemAuthorityCommitteeId,
    new_epoch: u64,
    new_committee: SystemAuthorityCommitteeId,
    rotation_sequence: u64,
    first_sequence: u64,
}

impl SystemAuthorityRotationClaim {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        root_anchor: RootAnchorId,
        root_anchor_config_version: u64,
        root_anchor_config: RootAnchorConfigCommitment,
        authority_scope: SystemAuthorityScopeCommitment,
        old: &AuthorityCommittee,
        new: &AuthorityCommittee,
        rotation_sequence: u64,
        first_sequence: u64,
    ) -> Result<Self, SystemAuthorityError> {
        old.validate().map_err(SystemAuthorityError::Authority)?;
        new.validate().map_err(SystemAuthorityError::Authority)?;
        let claim = Self {
            root_anchor,
            root_anchor_config_version,
            root_anchor_config,
            authority_scope,
            space: old.space(),
            authority_binding: old.authority_binding(),
            old_epoch: old.epoch(),
            old_committee: SystemAuthorityCommitteeId::of(old),
            new_epoch: new.epoch(),
            new_committee: SystemAuthorityCommitteeId::of(new),
            rotation_sequence,
            first_sequence,
        };
        claim.validate_against_committees(old, new)?;
        Ok(claim)
    }

    pub const fn root_anchor(&self) -> RootAnchorId {
        self.root_anchor
    }

    pub const fn root_anchor_config_version(&self) -> u64 {
        self.root_anchor_config_version
    }

    pub const fn root_anchor_config(&self) -> RootAnchorConfigCommitment {
        self.root_anchor_config
    }

    pub const fn authority_scope(&self) -> SystemAuthorityScopeCommitment {
        self.authority_scope
    }

    pub const fn space(&self) -> SpaceId {
        self.space
    }

    pub const fn authority_binding(&self) -> Hash {
        self.authority_binding
    }

    pub const fn old_epoch(&self) -> u64 {
        self.old_epoch
    }

    pub const fn old_committee(&self) -> SystemAuthorityCommitteeId {
        self.old_committee
    }

    pub const fn new_epoch(&self) -> u64 {
        self.new_epoch
    }

    pub const fn new_committee(&self) -> SystemAuthorityCommitteeId {
        self.new_committee
    }

    pub const fn rotation_sequence(&self) -> u64 {
        self.rotation_sequence
    }

    pub const fn first_sequence(&self) -> u64 {
        self.first_sequence
    }

    pub fn authority_claim(&self) -> AuthorityClaimCommitment {
        AuthorityClaimCommitment::of_bytes(
            AuthorityClaimDomain::CommitteeRotation,
            self.rotation_sequence,
            &self.encode(),
        )
    }

    fn validate_shape(&self) -> Result<(), SystemAuthorityError> {
        if self.root_anchor == RootAnchorId::ZERO
            || self.root_anchor_config_version == 0
            || self.root_anchor_config == RootAnchorConfigCommitment::ZERO
            || self.authority_scope == SystemAuthorityScopeCommitment::ZERO
            || self.space == SpaceId::ZERO
            || self.authority_binding == Hash::ZERO
            || self.old_epoch == 0
            || self.old_epoch.checked_add(1) != Some(self.new_epoch)
            || self.old_committee == SystemAuthorityCommitteeId::ZERO
            || self.new_committee == SystemAuthorityCommitteeId::ZERO
            || self.old_committee == self.new_committee
            || self.rotation_sequence == 0
            || self.first_sequence <= self.rotation_sequence
        {
            return Err(SystemAuthorityError::InvalidRotationProof);
        }
        enforce_encoded_bound(self, MAX_SYSTEM_AUTHORITY_ROTATION_CLAIM_BYTES)
    }

    fn validate_against_committees(
        &self,
        old: &AuthorityCommittee,
        new: &AuthorityCommittee,
    ) -> Result<(), SystemAuthorityError> {
        self.validate_shape()?;
        old.validate().map_err(SystemAuthorityError::Authority)?;
        new.validate().map_err(SystemAuthorityError::Authority)?;
        if self.space != old.space()
            || self.space != new.space()
            || self.authority_binding != old.authority_binding()
            || self.authority_binding != new.authority_binding()
            || self.old_epoch != old.epoch()
            || self.new_epoch != new.epoch()
            || self.old_committee != SystemAuthorityCommitteeId::of(old)
            || self.new_committee != SystemAuthorityCommitteeId::of(new)
            || new.previous_committee() != Some(old.commitment())
        {
            Err(SystemAuthorityError::StaleCommittee)
        } else {
            Ok(())
        }
    }
}

impl ServiceWire for SystemAuthorityRotationClaim {
    const MAGIC: [u8; 4] = *b"SARC";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(self.root_anchor.as_bytes());
        encoder.u64(self.root_anchor_config_version);
        encoder.fixed(self.root_anchor_config.as_bytes());
        encoder.fixed(self.authority_scope.as_bytes());
        encoder.fixed(&self.space.0);
        encoder.fixed(&self.authority_binding.0);
        encoder.u64(self.old_epoch);
        encoder.fixed(self.old_committee.as_bytes());
        encoder.u64(self.new_epoch);
        encoder.fixed(self.new_committee.as_bytes());
        encoder.u64(self.rotation_sequence);
        encoder.u64(self.first_sequence);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SYSTEM_AUTHORITY_ROTATION_CLAIM_BYTES)?;
        let claim = Self {
            root_anchor: RootAnchorId::from_bytes(decoder.fixed()?),
            root_anchor_config_version: decoder.u64()?,
            root_anchor_config: RootAnchorConfigCommitment::from_bytes(decoder.fixed()?),
            authority_scope: SystemAuthorityScopeCommitment::from_bytes(decoder.fixed()?),
            space: SpaceId(decoder.fixed()?),
            authority_binding: Hash(decoder.fixed()?),
            old_epoch: decoder.u64()?,
            old_committee: SystemAuthorityCommitteeId::from_bytes(decoder.fixed()?),
            new_epoch: decoder.u64()?,
            new_committee: SystemAuthorityCommitteeId::from_bytes(decoder.fixed()?),
            rotation_sequence: decoder.u64()?,
            first_sequence: decoder.u64()?,
        };
        claim.validate_shape().map_err(map_decode_error)?;
        Ok(claim)
    }
}

/// Joint old-majority/new-majority proof over one exact scoped transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemAuthorityRotationCertificate {
    transition: SystemAuthorityRotationClaim,
    old_certificate: AuthorityQuorumCertificate,
    new_certificate: AuthorityQuorumCertificate,
}

impl SystemAuthorityRotationCertificate {
    pub fn new(
        transition: SystemAuthorityRotationClaim,
        old_certificate: AuthorityQuorumCertificate,
        new_certificate: AuthorityQuorumCertificate,
    ) -> Result<Self, SystemAuthorityError> {
        let certificate = Self {
            transition,
            old_certificate,
            new_certificate,
        };
        certificate.validate_shape()?;
        Ok(certificate)
    }

    pub const fn transition(&self) -> &SystemAuthorityRotationClaim {
        &self.transition
    }

    pub const fn old_certificate(&self) -> &AuthorityQuorumCertificate {
        &self.old_certificate
    }

    pub const fn new_certificate(&self) -> &AuthorityQuorumCertificate {
        &self.new_certificate
    }

    fn verify(
        &self,
        old: &AuthorityCommittee,
        new: &AuthorityCommittee,
    ) -> Result<(), SystemAuthorityError> {
        self.validate_shape()?;
        self.transition.validate_against_committees(old, new)?;
        let claim = self.transition.authority_claim();
        self.old_certificate
            .verify(old, claim)
            .map_err(SystemAuthorityError::Authority)?;
        self.new_certificate
            .verify(new, claim)
            .map_err(SystemAuthorityError::Authority)
    }

    fn validate_shape(&self) -> Result<(), SystemAuthorityError> {
        self.transition.validate_shape()?;
        let claim = self.transition.authority_claim();
        if self.old_certificate.claim() != claim
            || self.new_certificate.claim() != claim
            || self.old_certificate.authority_binding() != self.transition.authority_binding
            || self.new_certificate.authority_binding() != self.transition.authority_binding
            || self.old_certificate.epoch() != self.transition.old_epoch
            || self.new_certificate.epoch() != self.transition.new_epoch
            || self.old_certificate.committee().0 != *self.transition.old_committee.as_bytes()
            || self.new_certificate.committee().0 != *self.transition.new_committee.as_bytes()
        {
            return Err(SystemAuthorityError::InvalidRotationProof);
        }
        enforce_encoded_bound(self, MAX_SYSTEM_AUTHORITY_ROTATION_CERTIFICATE_BYTES)
    }
}

impl ServiceWire for SystemAuthorityRotationCertificate {
    const MAGIC: [u8; 4] = *b"SARQ";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.transition.encode());
        encoder.bytes(&self.old_certificate.encode());
        encoder.bytes(&self.new_certificate.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SYSTEM_AUTHORITY_ROTATION_CERTIFICATE_BYTES)?;
        let certificate = Self {
            transition: decode_nested(decoder, MAX_SYSTEM_AUTHORITY_ROTATION_CLAIM_BYTES)?,
            old_certificate: decode_nested(decoder, MAX_AUTHORITY_QC_WIRE_BYTES)?,
            new_certificate: decode_nested(decoder, MAX_AUTHORITY_QC_WIRE_BYTES)?,
        };
        certificate.validate_shape().map_err(map_decode_error)?;
        Ok(certificate)
    }
}

/// Permanent record of one jointly certified committee transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemAuthorityRotationRecord {
    old_committee: SystemAuthorityCommitteeId,
    new_committee: SystemAuthorityCommitteeId,
    certificate: SystemAuthorityRotationCertificate,
}

impl SystemAuthorityRotationRecord {
    fn from_command_shape(
        rotation: &SystemAuthorityRotation,
    ) -> Result<Self, SystemAuthorityError> {
        rotation.validate()?;
        let transition = rotation.certificate.transition();
        Ok(Self {
            old_committee: transition.old_committee(),
            new_committee: transition.new_committee(),
            certificate: rotation.certificate.clone(),
        })
    }

    fn new(
        old: &AuthorityCommittee,
        new: &AuthorityCommittee,
        certificate: SystemAuthorityRotationCertificate,
    ) -> Result<Self, SystemAuthorityError> {
        certificate.verify(old, new)?;
        Ok(Self {
            old_committee: SystemAuthorityCommitteeId::of(old),
            new_committee: SystemAuthorityCommitteeId::of(new),
            certificate,
        })
    }

    pub const fn old_committee(&self) -> SystemAuthorityCommitteeId {
        self.old_committee
    }

    pub const fn new_committee(&self) -> SystemAuthorityCommitteeId {
        self.new_committee
    }

    pub const fn certificate(&self) -> &SystemAuthorityRotationCertificate {
        &self.certificate
    }

    pub fn id(&self) -> SystemAuthorityRotationId {
        SystemAuthorityRotationId(Hash::digest(ROTATION_ID_DOMAIN, &[&self.encode()]).0)
    }

    pub fn leaf_id(&self) -> SystemAuthorityRotationNodeId {
        SystemAuthorityRotationNodeId(Hash::digest(ROTATION_LEAF_ID_DOMAIN, &[&self.encode()]).0)
    }

    pub const fn new_epoch(&self) -> u64 {
        self.certificate.transition().new_epoch()
    }

    /// Reverify one permanent historical leaf against the exact committee
    /// records loaded by reopen/GC audit. Callers use the State-level
    /// `verify_historical_rotation` closure so generation scope cannot be
    /// omitted.
    fn verify_with_committees(
        &self,
        old: &AuthorityCommittee,
        new: &AuthorityCommittee,
    ) -> Result<(), SystemAuthorityError> {
        self.validate()?;
        if self.old_committee != SystemAuthorityCommitteeId::of(old)
            || self.new_committee != SystemAuthorityCommitteeId::of(new)
        {
            return Err(SystemAuthorityError::StaleCommittee);
        }
        self.certificate.verify(old, new)
    }

    fn validate(&self) -> Result<(), SystemAuthorityError> {
        self.certificate.validate_shape()?;
        if self.old_committee == SystemAuthorityCommitteeId::ZERO
            || self.new_committee == SystemAuthorityCommitteeId::ZERO
            || self.old_committee == self.new_committee
            || self.old_committee != self.certificate.transition().old_committee()
            || self.new_committee != self.certificate.transition().new_committee()
        {
            return Err(SystemAuthorityError::InvalidRotationNode);
        }
        enforce_encoded_bound(self, MAX_SYSTEM_AUTHORITY_ROTATION_RECORD_BYTES)
    }
}

impl ServiceWire for SystemAuthorityRotationRecord {
    const MAGIC: [u8; 4] = *b"SART";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(self.old_committee.as_bytes());
        encoder.fixed(self.new_committee.as_bytes());
        encoder.bytes(&self.certificate.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SYSTEM_AUTHORITY_ROTATION_RECORD_BYTES)?;
        let record = Self {
            old_committee: SystemAuthorityCommitteeId::from_bytes(decoder.fixed()?),
            new_committee: SystemAuthorityCommitteeId::from_bytes(decoder.fixed()?),
            certificate: decode_nested(decoder, MAX_SYSTEM_AUTHORITY_ROTATION_CERTIFICATE_BYTES)?,
        };
        record.validate().map_err(map_decode_error)?;
        Ok(record)
    }
}

/// One non-default sibling in the epoch-keyed permanent rotation tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemAuthorityRotationSibling {
    depth: u16,
    node: SystemAuthorityRotationNodeId,
}

impl SystemAuthorityRotationSibling {
    pub fn new(
        depth: u16,
        node: SystemAuthorityRotationNodeId,
    ) -> Result<Self, SystemAuthorityError> {
        if depth >= ROTATION_TREE_DEPTH
            || node == SystemAuthorityRotationNodeId::ZERO
            || node == empty_rotation_node(depth + 1)
        {
            return Err(SystemAuthorityError::InvalidRotationProof);
        }
        Ok(Self { depth, node })
    }

    pub const fn depth(self) -> u16 {
        self.depth
    }

    pub const fn node(self) -> SystemAuthorityRotationNodeId {
        self.node
    }
}

/// Permanent membership/nonmembership proof keyed by incoming committee
/// epoch. Omitted siblings are canonical empty subtrees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemAuthorityRotationProof {
    new_epoch: u64,
    occupied: bool,
    siblings: Vec<SystemAuthorityRotationSibling>,
}

impl SystemAuthorityRotationProof {
    pub fn vacant(
        new_epoch: u64,
        siblings: Vec<SystemAuthorityRotationSibling>,
    ) -> Result<Self, SystemAuthorityError> {
        Self::new(new_epoch, false, siblings)
    }

    pub fn occupied(
        new_epoch: u64,
        siblings: Vec<SystemAuthorityRotationSibling>,
    ) -> Result<Self, SystemAuthorityError> {
        Self::new(new_epoch, true, siblings)
    }

    fn new(
        new_epoch: u64,
        occupied: bool,
        siblings: Vec<SystemAuthorityRotationSibling>,
    ) -> Result<Self, SystemAuthorityError> {
        let proof = Self {
            new_epoch,
            occupied,
            siblings,
        };
        proof.validate()?;
        Ok(proof)
    }

    pub const fn new_epoch(&self) -> u64 {
        self.new_epoch
    }

    pub const fn is_occupied(&self) -> bool {
        self.occupied
    }

    pub fn siblings(&self) -> &[SystemAuthorityRotationSibling] {
        &self.siblings
    }

    pub fn root_for(
        &self,
        candidate: &SystemAuthorityRotationRecord,
    ) -> Result<SystemAuthorityRotationNodeId, SystemAuthorityError> {
        self.validate()?;
        if candidate.new_epoch() != self.new_epoch {
            return Err(SystemAuthorityError::InvalidRotationProof);
        }
        let leaf = if self.occupied {
            candidate.leaf_id()
        } else {
            empty_rotation_node(ROTATION_TREE_DEPTH)
        };
        Ok(rotation_root_from_path(
            self.new_epoch,
            leaf,
            &self.siblings,
        ))
    }

    pub fn verifies(
        &self,
        expected_root: SystemAuthorityRotationNodeId,
        candidate: &SystemAuthorityRotationRecord,
    ) -> Result<(), SystemAuthorityError> {
        if expected_root == SystemAuthorityRotationNodeId::ZERO
            || self.root_for(candidate)? != expected_root
        {
            Err(SystemAuthorityError::InvalidRotationProof)
        } else {
            Ok(())
        }
    }

    fn validate(&self) -> Result<(), SystemAuthorityError> {
        if self.new_epoch <= 1 || self.siblings.len() > MAX_ROTATION_PROOF_SIBLINGS {
            return Err(SystemAuthorityError::InvalidRotationProof);
        }
        let empty = rotation_empty_ladder();
        let mut previous = None;
        for sibling in &self.siblings {
            if sibling.depth >= ROTATION_TREE_DEPTH
                || sibling.node == SystemAuthorityRotationNodeId::ZERO
                || sibling.node == empty[usize::from(sibling.depth + 1)]
                || previous.is_some_and(|depth| depth >= sibling.depth)
            {
                return Err(SystemAuthorityError::InvalidRotationProof);
            }
            previous = Some(sibling.depth);
        }
        enforce_encoded_bound(self, MAX_SYSTEM_AUTHORITY_ROTATION_PROOF_BYTES)
    }
}

impl ServiceWire for SystemAuthorityRotationProof {
    const MAGIC: [u8; 4] = *b"SARP";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.u64(self.new_epoch);
        encoder.bool(self.occupied);
        encoder.u32(self.siblings.len() as u32);
        for sibling in &self.siblings {
            encoder.u16(sibling.depth);
            encoder.fixed(sibling.node.as_bytes());
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SYSTEM_AUTHORITY_ROTATION_PROOF_BYTES)?;
        let new_epoch = decoder.u64()?;
        let occupied = decoder.bool()?;
        let count = decoder.u32()? as usize;
        if count > MAX_ROTATION_PROOF_SIBLINGS {
            return Err(DecodeError::LimitExceeded);
        }
        let mut siblings = Vec::new();
        siblings
            .try_reserve_exact(count)
            .map_err(|_| DecodeError::LimitExceeded)?;
        for _ in 0..count {
            siblings.push(SystemAuthorityRotationSibling {
                depth: decoder.u16()?,
                node: SystemAuthorityRotationNodeId::from_bytes(decoder.fixed()?),
            });
        }
        let proof = Self {
            new_epoch,
            occupied,
            siblings,
        };
        proof.validate().map_err(map_decode_error)?;
        Ok(proof)
    }
}

/// Complete proof-carrying rotation command. The proof is outside the joint
/// QC payload, but is authenticated against the current permanent root before
/// the transition can be accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemAuthorityRotation {
    new_committee: AuthorityCommittee,
    certificate: SystemAuthorityRotationCertificate,
    proof: SystemAuthorityRotationProof,
}

impl SystemAuthorityRotation {
    pub fn new(
        new_committee: AuthorityCommittee,
        certificate: SystemAuthorityRotationCertificate,
        proof: SystemAuthorityRotationProof,
    ) -> Result<Self, SystemAuthorityError> {
        let rotation = Self {
            new_committee,
            certificate,
            proof,
        };
        rotation.validate()?;
        Ok(rotation)
    }

    pub const fn new_committee(&self) -> &AuthorityCommittee {
        &self.new_committee
    }

    pub const fn certificate(&self) -> &SystemAuthorityRotationCertificate {
        &self.certificate
    }

    pub const fn proof(&self) -> &SystemAuthorityRotationProof {
        &self.proof
    }

    /// Logical operation identity excludes the replaceable sparse proof. A
    /// retry after later insertions carries a refreshed occupied path while
    /// retaining this exact jointly signed transition and committee.
    pub fn operation_commitment(&self) -> Hash {
        Hash::digest(
            ROTATION_OPERATION_DOMAIN,
            &[&self.new_committee.encode(), &self.certificate.encode()],
        )
    }

    pub fn validate(&self) -> Result<(), SystemAuthorityError> {
        self.new_committee
            .validate()
            .map_err(SystemAuthorityError::Authority)?;
        self.certificate.validate_shape()?;
        self.proof.validate()?;
        let transition = self.certificate.transition();
        if self.proof.new_epoch != self.new_committee.epoch()
            || transition.new_epoch() != self.new_committee.epoch()
            || transition.new_committee() != SystemAuthorityCommitteeId::of(&self.new_committee)
            || transition.space() != self.new_committee.space()
            || transition.authority_binding() != self.new_committee.authority_binding()
            || self.new_committee.previous_committee().map(|id| id.0)
                != Some(*transition.old_committee().as_bytes())
        {
            return Err(SystemAuthorityError::InvalidRotationProof);
        }
        enforce_encoded_bound(self, MAX_SYSTEM_AUTHORITY_ROTATION_BYTES)
    }
}

impl ServiceWire for SystemAuthorityRotation {
    const MAGIC: [u8; 4] = *b"SARO";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.new_committee.encode());
        encoder.bytes(&self.certificate.encode());
        encoder.bytes(&self.proof.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SYSTEM_AUTHORITY_ROTATION_BYTES)?;
        let rotation = Self {
            new_committee: decode_nested(decoder, MAX_AUTHORITY_COMMITTEE_WIRE_BYTES)?,
            certificate: decode_nested(decoder, MAX_SYSTEM_AUTHORITY_ROTATION_CERTIFICATE_BYTES)?,
            proof: decode_nested(decoder, MAX_SYSTEM_AUTHORITY_ROTATION_PROOF_BYTES)?,
        };
        rotation.validate().map_err(map_decode_error)?;
        Ok(rotation)
    }
}

/// Immutable rotation-history node written before publishing the successor
/// Control state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SystemAuthorityRotationNode {
    Leaf(SystemAuthorityRotationRecord),
    Branch {
        depth: u16,
        left: SystemAuthorityRotationNodeId,
        right: SystemAuthorityRotationNodeId,
    },
}

impl SystemAuthorityRotationNode {
    pub fn id(&self) -> SystemAuthorityRotationNodeId {
        match self {
            Self::Leaf(record) => record.leaf_id(),
            Self::Branch { depth, left, right } => rotation_branch_id(*depth, *left, *right),
        }
    }

    pub fn validate(&self) -> Result<(), SystemAuthorityError> {
        match self {
            Self::Leaf(record) => record.validate(),
            Self::Branch { depth, left, right }
                if *depth < ROTATION_TREE_DEPTH
                    && *left != SystemAuthorityRotationNodeId::ZERO
                    && *right != SystemAuthorityRotationNodeId::ZERO
                    && *left != *right =>
            {
                Ok(())
            }
            _ => Err(SystemAuthorityError::InvalidRotationNode),
        }
    }
}

impl ServiceWire for SystemAuthorityRotationNode {
    const MAGIC: [u8; 4] = *b"SARN";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        match self {
            Self::Leaf(record) => {
                encoder.u8(0);
                encoder.bytes(&record.encode());
            }
            Self::Branch { depth, left, right } => {
                encoder.u8(1);
                encoder.u16(*depth);
                encoder.fixed(left.as_bytes());
                encoder.fixed(right.as_bytes());
            }
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SYSTEM_AUTHORITY_ROTATION_NODE_BYTES)?;
        let node = match decoder.u8()? {
            0 => Self::Leaf(decode_nested(
                decoder,
                MAX_SYSTEM_AUTHORITY_ROTATION_RECORD_BYTES,
            )?),
            1 => Self::Branch {
                depth: decoder.u16()?,
                left: SystemAuthorityRotationNodeId::from_bytes(decoder.fixed()?),
                right: SystemAuthorityRotationNodeId::from_bytes(decoder.fixed()?),
            },
            _ => return Err(DecodeError::InvalidTag),
        };
        node.validate().map_err(map_decode_error)?;
        Ok(node)
    }
}

/// Store-side closure for one permanent accepted rotation. Committee records
/// are explicit roots for GC/audit even after they are no longer current.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SystemAuthorityRotationWritePlan {
    previous_root: SystemAuthorityRotationNodeId,
    root: SystemAuthorityRotationNodeId,
    inserted: bool,
    nodes: Vec<SystemAuthorityRotationNode>,
    retired_node_ids: Vec<SystemAuthorityRotationNodeId>,
    committee_records: Vec<SystemAuthorityCommitteeRecord>,
}

impl SystemAuthorityRotationWritePlan {
    pub(crate) const fn previous_root(&self) -> SystemAuthorityRotationNodeId {
        self.previous_root
    }

    pub(crate) const fn root(&self) -> SystemAuthorityRotationNodeId {
        self.root
    }

    pub(crate) const fn inserted(&self) -> bool {
        self.inserted
    }

    pub(crate) fn nodes(&self) -> &[SystemAuthorityRotationNode] {
        &self.nodes
    }

    /// Reachability hints only. A store may retire these IDs only after the
    /// successor head CAS and checkpoint/reachability closure make them dead.
    pub(crate) fn retired_node_ids(&self) -> &[SystemAuthorityRotationNodeId] {
        &self.retired_node_ids
    }

    pub(crate) fn committee_records(&self) -> &[SystemAuthorityCommitteeRecord] {
        &self.committee_records
    }
}

/// Versioned authority state embedded in Standard Control.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemAuthorityState {
    version: u16,
    root_anchor: RootAnchorId,
    root_anchor_config_version: u64,
    root_anchor_config: RootAnchorConfigCommitment,
    space: SpaceId,
    system_agent: AgentId,
    authority_binding: Hash,
    decision_limit: u32,
    rotation_limit: u32,
    journal_scope: Option<SystemAuthorityJournalScope>,
    current_committee: AuthorityCommittee,
    /// High-water in the committee-certified claim namespace only. Standard
    /// lifecycle receipts are replay-protected per target Agent and are not
    /// globally observable from this Control state.
    committee_sequence_high_water: u64,
    rotation_first_sequence: Option<u64>,
    decisions_root: SystemAuthorityDecisionNodeId,
    decision_count: u64,
    rotations_root: SystemAuthorityRotationNodeId,
    rotation_count: u64,
}

impl SystemAuthorityState {
    pub const VERSION: u16 = 1;

    pub fn from_genesis(
        system_agent: AgentId,
        genesis: &SystemAuthorityGenesis,
    ) -> Result<Self, SystemAuthorityError> {
        genesis.validate()?;
        if system_agent == AgentId::ZERO {
            return Err(SystemAuthorityError::InvalidScope);
        }
        let state = Self {
            version: Self::VERSION,
            root_anchor: genesis.root_anchor,
            root_anchor_config_version: genesis.root_anchor_config_version,
            root_anchor_config: genesis.root_anchor_config,
            space: genesis.initial_committee.space(),
            system_agent,
            authority_binding: genesis.initial_committee.authority_binding(),
            decision_limit: genesis.decision_limit,
            rotation_limit: genesis.rotation_limit,
            journal_scope: None,
            current_committee: genesis.initial_committee.clone(),
            committee_sequence_high_water: genesis.initial_sequence,
            rotation_first_sequence: None,
            decisions_root: empty_decision_root(),
            decision_count: 0,
            rotations_root: empty_rotation_root(),
            rotation_count: 0,
        };
        state.validate()?;
        Ok(state)
    }

    pub const fn system_agent(&self) -> AgentId {
        self.system_agent
    }

    pub const fn space(&self) -> SpaceId {
        self.space
    }

    pub const fn authority_binding(&self) -> Hash {
        self.authority_binding
    }

    pub const fn decision_limit(&self) -> u32 {
        self.decision_limit
    }

    pub const fn rotation_limit(&self) -> u32 {
        self.rotation_limit
    }

    pub(crate) const fn root_anchor(&self) -> RootAnchorId {
        self.root_anchor
    }

    pub(crate) const fn root_anchor_config_version(&self) -> u64 {
        self.root_anchor_config_version
    }

    pub(crate) const fn root_anchor_config(&self) -> RootAnchorConfigCommitment {
        self.root_anchor_config
    }

    pub(crate) const fn journal_scope(&self) -> Option<SystemAuthorityJournalScope> {
        self.journal_scope
    }

    pub const fn current_committee(&self) -> &AuthorityCommittee {
        &self.current_committee
    }

    pub fn current_committee_id(&self) -> SystemAuthorityCommitteeId {
        SystemAuthorityCommitteeId::of(&self.current_committee)
    }

    pub const fn committee_sequence_high_water(&self) -> u64 {
        self.committee_sequence_high_water
    }

    pub const fn rotation_first_sequence(&self) -> Option<u64> {
        self.rotation_first_sequence
    }

    pub const fn decisions_root(&self) -> SystemAuthorityDecisionNodeId {
        self.decisions_root
    }

    pub const fn decision_count(&self) -> u64 {
        self.decision_count
    }

    pub const fn rotations_root(&self) -> SystemAuthorityRotationNodeId {
        self.rotations_root
    }

    pub const fn rotation_count(&self) -> u64 {
        self.rotation_count
    }

    /// Re-anchor decoded Control state to the exact cycle-free Create seed on
    /// every Standard restore/checkpoint import. History may advance the
    /// committee and H, but it cannot replace immutable root identity.
    pub(crate) fn validate_against_genesis(
        &self,
        system_agent: AgentId,
        genesis: &SystemAuthorityGenesis,
    ) -> Result<(), SystemAuthorityError> {
        self.validate()?;
        genesis.validate()?;
        if self.system_agent != system_agent
            || self.root_anchor != genesis.root_anchor
            || self.root_anchor_config_version != genesis.root_anchor_config_version
            || self.root_anchor_config != genesis.root_anchor_config
            || self.space != genesis.initial_committee.space()
            || self.authority_binding != genesis.initial_committee.authority_binding()
            || self.decision_limit != genesis.decision_limit
            || self.rotation_limit != genesis.rotation_limit
            || self.committee_sequence_high_water < genesis.initial_sequence
            || (self.rotation_count == 0 && self.current_committee != genesis.initial_committee)
        {
            Err(SystemAuthorityError::InvalidState)
        } else {
            Ok(())
        }
    }

    /// Validate the state-dependent portion of an ordinary-genesis signing
    /// request before a durable QC ledger reserves a signer/sequence pledge.
    /// The replay-minted scope is intentionally required: a public claim and
    /// decoded Control state alone are not a signing capability.
    pub(crate) fn validate_agent_genesis_claim_for_signing(
        &self,
        trusted_scope: SystemAuthorityJournalScope,
        claim: &AgentGenesisClaim,
        proof: &SystemAuthorityDecisionProof,
    ) -> Result<(), SystemAuthorityError> {
        self.validate()?;
        trusted_scope.validate()?;
        claim.validate().map_err(SystemAuthorityError::Genesis)?;
        if claim.system_genesis() != trusted_scope.system_genesis()
            || claim.system_admission() != trusted_scope.agent_admission()
            || claim.space() != self.space
            || claim.system_agent() != self.system_agent
            || claim.authority_binding() != self.authority_binding
            || self
                .journal_scope
                .is_some_and(|existing| existing != trusted_scope)
        {
            return Err(SystemAuthorityError::WrongSystemAgent);
        }
        proof.verifies(self.decisions_root)?;
        if proof.target_agent() != claim.agent() {
            return Err(SystemAuthorityError::InvalidDecisionProof);
        }
        self.validate_fresh_committee_sequence(claim.sequence())?;
        if self.decision_count >= u64::from(self.decision_limit) && proof.occupied_fact().is_none()
        {
            Err(SystemAuthorityError::Capacity)
        } else {
            Ok(())
        }
    }

    /// Validate one exact generation-scoped current->incoming transition
    /// before either committee signs it. Both QC legs must reserve this same
    /// claim; the unsigned tree proof is deliberately not part of this seam.
    pub(crate) fn validate_rotation_claim_for_signing(
        &self,
        trusted_scope: SystemAuthorityJournalScope,
        claim: &SystemAuthorityRotationClaim,
        new_committee: &AuthorityCommittee,
    ) -> Result<(), SystemAuthorityError> {
        self.validate()?;
        trusted_scope.validate()?;
        self.validate_rotation_scope(trusted_scope, claim)?;
        claim.validate_against_committees(&self.current_committee, new_committee)?;
        self.validate_fresh_committee_sequence(claim.rotation_sequence())?;
        if self.rotation_count >= u64::from(self.rotation_limit) {
            Err(SystemAuthorityError::Capacity)
        } else {
            Ok(())
        }
    }

    /// Reverify a permanent historical rotation during scrub/reopen without
    /// allowing callers to forget either the root-generation scope leg or the
    /// old/new committee/QC legs.
    pub(crate) fn verify_historical_rotation(
        &self,
        trusted_scope: SystemAuthorityJournalScope,
        record: &SystemAuthorityRotationRecord,
        old_committee: &AuthorityCommittee,
        new_committee: &AuthorityCommittee,
    ) -> Result<(), SystemAuthorityError> {
        self.validate()?;
        trusted_scope.validate()?;
        self.validate_rotation_scope(trusted_scope, record.certificate().transition())?;
        record.verify_with_committees(old_committee, new_committee)
    }

    /// Reverify one historical ordinary admission as a single scope+fact+
    /// committee closure. This is data validation for post-CAS receipt
    /// construction; success alone is never a sealing capability.
    pub(crate) fn verify_historical_provision(
        &self,
        trusted_scope: SystemAuthorityJournalScope,
        provision: &AgentGenesisProvision,
        fact: &SystemAuthorityDecisionFact,
        committee: &AuthorityCommittee,
    ) -> Result<(), SystemAuthorityError> {
        self.validate()?;
        trusted_scope.validate()?;
        self.validate_fact_scope(trusted_scope, fact)?;
        verify_provision_fact_with_committee(provision, fact, committee)
    }

    pub(crate) fn apply_finalize(
        &self,
        trusted_scope: SystemAuthorityJournalScope,
        finalize: &SystemAuthorityFinalize,
    ) -> Result<SystemAuthorityFinalizeTransition, SystemAuthorityError> {
        self.validate()?;
        trusted_scope.validate()?;
        finalize.validate()?;
        let fact = finalize.fact()?;
        self.validate_fact_scope(trusted_scope, &fact)?;

        finalize.proof.verifies(self.decisions_root)?;
        if finalize.proof.occupied.as_ref() == Some(&fact) {
            return Ok(SystemAuthorityFinalizeTransition {
                state: self.clone(),
                outcome: SystemAuthorityFinalizeOutcome::ExactRetry(fact.decision),
                admitted_fact: Some(fact),
                history: unchanged_history(self.decisions_root),
            });
        }

        if let Some(existing) = finalize.proof.occupied.as_ref() {
            // A first fresh conflict consumes the authenticated committee
            // sequence so an equivocation at that number cannot later win.
            // The occupied path authenticates only `existing`, so every
            // divergent candidate must still carry a valid current QC before
            // it can produce any runtime outcome.
            self.verify_current_certificate(&fact, finalize.evidence())?;
            self.validate_fresh_committee_sequence(fact.claim.sequence())?;
            let mut next = self.clone();
            next.bind_scope(trusted_scope)?;
            next.committee_sequence_high_water = fact.claim.sequence();
            next.rotation_first_sequence = None;
            next.validate()?;
            return Ok(SystemAuthorityFinalizeTransition {
                state: next,
                outcome: SystemAuthorityFinalizeOutcome::TargetConflict(existing.decision),
                admitted_fact: None,
                history: unchanged_history(self.decisions_root),
            });
        }

        self.verify_current_certificate(&fact, finalize.evidence())?;
        self.validate_fresh_committee_sequence(fact.claim.sequence())?;
        if self.decision_count >= u64::from(self.decision_limit) {
            return Err(SystemAuthorityError::Capacity);
        }

        let mut next = self.clone();
        next.bind_scope(trusted_scope)?;
        next.committee_sequence_high_water = fact.claim.sequence();
        next.rotation_first_sequence = None;

        let history = insert_decision(self.decisions_root, &finalize.proof, fact.clone())?;
        next.decisions_root = history.root;
        next.decision_count = next
            .decision_count
            .checked_add(1)
            .ok_or(SystemAuthorityError::Capacity)?;
        let outcome = SystemAuthorityFinalizeOutcome::Admitted(fact.decision);
        next.validate()?;
        Ok(SystemAuthorityFinalizeTransition {
            state: next,
            outcome,
            admitted_fact: Some(fact),
            history,
        })
    }

    pub(crate) fn apply_rotation(
        &self,
        trusted_scope: SystemAuthorityJournalScope,
        rotation: &SystemAuthorityRotation,
    ) -> Result<SystemAuthorityRotationTransition, SystemAuthorityError> {
        self.validate()?;
        trusted_scope.validate()?;
        rotation.validate()?;
        self.validate_rotation_scope(trusted_scope, rotation.certificate.transition())?;
        let candidate = SystemAuthorityRotationRecord::from_command_shape(rotation)?;
        rotation.proof.verifies(self.rotations_root, &candidate)?;

        // Permanent membership is sufficient for an exact retry even after
        // later rotations. Do not compare
        // the old certificate to the now-current committee on this path.
        if rotation.proof.occupied {
            return Ok(SystemAuthorityRotationTransition {
                state: self.clone(),
                exact_retry: true,
                record: candidate,
                history: unchanged_rotation_history(self.rotations_root),
            });
        }
        let record = SystemAuthorityRotationRecord::new(
            &self.current_committee,
            &rotation.new_committee,
            rotation.certificate.clone(),
        )?;
        if record != candidate {
            return Err(SystemAuthorityError::InvalidRotationProof);
        }
        self.validate_rotation_claim_for_signing(
            trusted_scope,
            record.certificate().transition(),
            &rotation.new_committee,
        )?;
        let sequence = record.certificate.transition().rotation_sequence();
        let first = record.certificate.transition().first_sequence();
        let history = insert_rotation(
            self.rotations_root,
            &rotation.proof,
            record.clone(),
            &self.current_committee,
            &rotation.new_committee,
        )?;
        let mut next = self.clone();
        next.current_committee = rotation.new_committee.clone();
        next.bind_scope(trusted_scope)?;
        next.committee_sequence_high_water = sequence;
        next.rotation_first_sequence = Some(first);
        next.rotations_root = history.root;
        next.rotation_count = next
            .rotation_count
            .checked_add(1)
            .ok_or(SystemAuthorityError::Capacity)?;
        next.validate()?;
        Ok(SystemAuthorityRotationTransition {
            state: next,
            exact_retry: false,
            record,
            history,
        })
    }

    pub fn validate(&self) -> Result<(), SystemAuthorityError> {
        self.current_committee
            .validate()
            .map_err(SystemAuthorityError::Authority)?;
        if self.version != Self::VERSION
            || self.root_anchor == RootAnchorId::ZERO
            || self.root_anchor_config_version == 0
            || self.root_anchor_config == RootAnchorConfigCommitment::ZERO
            || self.space == SpaceId::ZERO
            || self.system_agent == AgentId::ZERO
            || self.authority_binding == Hash::ZERO
            || self.decision_limit == 0
            || self.decision_limit > MAX_SYSTEM_AUTHORITY_DECISIONS
            || self.rotation_limit == 0
            || self.rotation_limit > MAX_SYSTEM_AUTHORITY_ROTATIONS
            || self.decision_count > u64::from(self.decision_limit)
            || self.rotation_count > u64::from(self.rotation_limit)
            || self.committee_sequence_high_water == 0
            || self.decisions_root == SystemAuthorityDecisionNodeId::ZERO
            || self.rotations_root == SystemAuthorityRotationNodeId::ZERO
            || self
                .rotation_first_sequence
                .is_some_and(|first| first <= self.committee_sequence_high_water)
            || (self.decision_count == 0) != (self.decisions_root == empty_decision_root())
            || (self.rotation_count == 0) != (self.rotations_root == empty_rotation_root())
            || self.current_committee.space() != self.space
            || self.current_committee.authority_binding() != self.authority_binding
            || self.rotation_count.checked_add(1) != Some(self.current_committee.epoch())
            || (self.rotation_first_sequence.is_some() && self.rotation_count == 0)
            || (self.journal_scope.is_some()
                != (self.decision_count != 0 || self.rotation_count != 0))
        {
            return Err(SystemAuthorityError::InvalidState);
        }
        if let Some(scope) = self.journal_scope {
            scope.validate()?;
        }
        enforce_encoded_bound(self, MAX_SYSTEM_AUTHORITY_STATE_BYTES)
    }

    fn validate_fact_scope(
        &self,
        trusted_scope: SystemAuthorityJournalScope,
        fact: &SystemAuthorityDecisionFact,
    ) -> Result<(), SystemAuthorityError> {
        if fact.system_genesis != trusted_scope.system_genesis
            || fact.system_admission != trusted_scope.agent_admission
            || fact.space != self.space
            || fact.system_agent != self.system_agent
            || fact.authority_binding != self.authority_binding
            || self
                .journal_scope
                .is_some_and(|existing| existing != trusted_scope)
        {
            Err(SystemAuthorityError::WrongSystemAgent)
        } else {
            Ok(())
        }
    }

    fn verify_current_certificate(
        &self,
        fact: &SystemAuthorityDecisionFact,
        evidence: &AgentGenesisEvidence,
    ) -> Result<(), SystemAuthorityError> {
        if fact.committee != self.current_committee_id()
            || fact.committee_epoch != self.current_committee.epoch()
        {
            return Err(SystemAuthorityError::StaleCommittee);
        }
        evidence
            .certificate()
            .verify(&self.current_committee, fact.claim)
            .map_err(SystemAuthorityError::Authority)
    }

    fn validate_rotation_scope(
        &self,
        trusted_scope: SystemAuthorityJournalScope,
        claim: &SystemAuthorityRotationClaim,
    ) -> Result<(), SystemAuthorityError> {
        let expected_scope = trusted_scope.commitment(self.root_anchor)?;
        if claim.root_anchor != self.root_anchor
            || claim.root_anchor_config_version != self.root_anchor_config_version
            || claim.root_anchor_config != self.root_anchor_config
            || claim.authority_scope != expected_scope
            || claim.space != self.space
            || claim.authority_binding != self.authority_binding
            || self
                .journal_scope
                .is_some_and(|existing| existing != trusted_scope)
        {
            Err(SystemAuthorityError::WrongSystemAgent)
        } else {
            Ok(())
        }
    }

    fn validate_fresh_committee_sequence(&self, sequence: u64) -> Result<(), SystemAuthorityError> {
        match self.rotation_first_sequence {
            Some(first) if sequence == first => Ok(()),
            Some(_) => Err(SystemAuthorityError::RotationFirstSequencePending),
            None if sequence > self.committee_sequence_high_water => Ok(()),
            None => Err(SystemAuthorityError::SequenceConflict),
        }
    }

    fn bind_scope(
        &mut self,
        scope: SystemAuthorityJournalScope,
    ) -> Result<(), SystemAuthorityError> {
        match self.journal_scope {
            Some(existing) if existing != scope => Err(SystemAuthorityError::WrongSystemAgent),
            Some(_) => Ok(()),
            None => {
                self.journal_scope = Some(scope);
                Ok(())
            }
        }
    }
}

impl ServiceWire for SystemAuthorityState {
    const MAGIC: [u8; 4] = *b"SAST";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.u16(self.version);
        encoder.fixed(self.root_anchor.as_bytes());
        encoder.u64(self.root_anchor_config_version);
        encoder.fixed(self.root_anchor_config.as_bytes());
        encoder.fixed(&self.space.0);
        encoder.fixed(&self.system_agent.0);
        encoder.fixed(&self.authority_binding.0);
        encoder.u32(self.decision_limit);
        encoder.u32(self.rotation_limit);
        encoder.option(&self.journal_scope, |encoder, scope| {
            encoder.fixed(&scope.system_genesis.0);
            encoder.fixed(scope.agent_admission.as_bytes());
        });
        encoder.bytes(&self.current_committee.encode());
        encoder.u64(self.committee_sequence_high_water);
        encoder.option(&self.rotation_first_sequence, |encoder, sequence| {
            encoder.u64(*sequence)
        });
        encoder.fixed(self.decisions_root.as_bytes());
        encoder.u64(self.decision_count);
        encoder.fixed(self.rotations_root.as_bytes());
        encoder.u64(self.rotation_count);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SYSTEM_AUTHORITY_STATE_BYTES)?;
        let version = decoder.u16()?;
        let root_anchor = RootAnchorId::from_bytes(decoder.fixed()?);
        let root_anchor_config_version = decoder.u64()?;
        let root_anchor_config = RootAnchorConfigCommitment::from_bytes(decoder.fixed()?);
        let space = SpaceId(decoder.fixed()?);
        let system_agent = AgentId(decoder.fixed()?);
        let authority_binding = Hash(decoder.fixed()?);
        let decision_limit = decoder.u32()?;
        let rotation_limit = decoder.u32()?;
        let journal_scope = decoder.option(|decoder| {
            SystemAuthorityJournalScope::new(
                AgentJournalGenesisId(decoder.fixed()?),
                AgentGenesisAdmissionId::from_bytes(decoder.fixed()?),
            )
            .map_err(map_decode_error)
        })?;
        let current_committee = decode_nested(decoder, MAX_AUTHORITY_COMMITTEE_WIRE_BYTES)?;
        let committee_sequence_high_water = decoder.u64()?;
        let rotation_first_sequence = decoder.option(Decoder::u64)?;
        let decisions_root = SystemAuthorityDecisionNodeId::from_bytes(decoder.fixed()?);
        let decision_count = decoder.u64()?;
        let rotations_root = SystemAuthorityRotationNodeId::from_bytes(decoder.fixed()?);
        let rotation_count = decoder.u64()?;
        let state = Self {
            version,
            root_anchor,
            root_anchor_config_version,
            root_anchor_config,
            space,
            system_agent,
            authority_binding,
            decision_limit,
            rotation_limit,
            journal_scope,
            current_committee,
            committee_sequence_high_water,
            rotation_first_sequence,
            decisions_root,
            decision_count,
            rotations_root,
            rotation_count,
        };
        state.validate().map_err(map_decode_error)?;
        Ok(state)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemAuthorityFinalizeOutcome {
    Admitted(AgentGenesisDecisionId),
    ExactRetry(AgentGenesisDecisionId),
    TargetConflict(AgentGenesisDecisionId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemAuthorityFinalizeTransition {
    state: SystemAuthorityState,
    outcome: SystemAuthorityFinalizeOutcome,
    admitted_fact: Option<SystemAuthorityDecisionFact>,
    history: SystemAuthorityDecisionWritePlan,
}

impl SystemAuthorityFinalizeTransition {
    pub const fn state(&self) -> &SystemAuthorityState {
        &self.state
    }

    pub const fn outcome(&self) -> SystemAuthorityFinalizeOutcome {
        self.outcome
    }

    /// Data selected by the deterministic transition. This is not an ordinary
    /// genesis admission capability: sealing additionally requires a separate
    /// opaque receipt binding the root JournalStore instance, post-CAS
    /// successor Heads/root, and permanent membership lookup.
    pub(crate) const fn admitted_fact(&self) -> Option<&SystemAuthorityDecisionFact> {
        self.admitted_fact.as_ref()
    }

    pub(crate) const fn history(&self) -> &SystemAuthorityDecisionWritePlan {
        &self.history
    }

    pub fn into_state(self) -> SystemAuthorityState {
        self.state
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemAuthorityRotationTransition {
    state: SystemAuthorityState,
    exact_retry: bool,
    record: SystemAuthorityRotationRecord,
    history: SystemAuthorityRotationWritePlan,
}

impl SystemAuthorityRotationTransition {
    pub const fn state(&self) -> &SystemAuthorityState {
        &self.state
    }

    pub const fn exact_retry(&self) -> bool {
        self.exact_retry
    }

    pub const fn record(&self) -> &SystemAuthorityRotationRecord {
        &self.record
    }

    pub(crate) const fn history(&self) -> &SystemAuthorityRotationWritePlan {
        &self.history
    }

    pub fn into_state(self) -> SystemAuthorityState {
        self.state
    }
}

/// Exact-compare a provider provision with an already authenticated permanent
/// fact. Success is still data validation, not an admission capability.
pub fn verify_provision_fact(
    provision: &AgentGenesisProvision,
    fact: &SystemAuthorityDecisionFact,
) -> Result<(), SystemAuthorityError> {
    provision
        .validate()
        .map_err(SystemAuthorityError::Genesis)?;
    let derived =
        SystemAuthorityDecisionFact::from_records(provision.decision(), provision.evidence())?;
    if &derived != fact
        || provision.proposal().id() != fact.proposal
        || provision.replicas().id() != fact.replicas
    {
        Err(SystemAuthorityError::InvalidProvision)
    } else {
        Ok(())
    }
}

/// Historical admission reproof used only after replay has authenticated the
/// permanent fact and loaded its content-addressed committee record. Unlike
/// [`verify_provision_fact`], this also rechecks the original QC.
fn verify_provision_fact_with_committee(
    provision: &AgentGenesisProvision,
    fact: &SystemAuthorityDecisionFact,
    committee: &AuthorityCommittee,
) -> Result<(), SystemAuthorityError> {
    verify_provision_fact(provision, fact)?;
    committee
        .validate()
        .map_err(SystemAuthorityError::Authority)?;
    if fact.committee() != SystemAuthorityCommitteeId::of(committee)
        || fact.committee_epoch() != committee.epoch()
    {
        return Err(SystemAuthorityError::StaleCommittee);
    }
    provision
        .evidence()
        .certificate()
        .verify(committee, fact.claim())
        .map_err(SystemAuthorityError::Authority)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemAuthorityError {
    InvalidGenesis,
    InvalidScope,
    InvalidState,
    InvalidDecisionFact,
    InvalidDecisionNode,
    InvalidDecisionProof,
    InvalidRotationNode,
    InvalidRotationProof,
    InvalidFinalize,
    InvalidProvision,
    WrongSystemAgent,
    StaleCommittee,
    SequenceConflict,
    RotationFirstSequencePending,
    Capacity,
    LimitExceeded,
    Authority(AuthorityCommitteeError),
    Genesis(AgentGenesisError),
}

impl fmt::Display for SystemAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "system authority: {self:?}")
    }
}

impl core::error::Error for SystemAuthorityError {}

/// Typed object reference used by bounded proof construction and full-tree
/// reopen/GC audits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SystemAuthorityTreeNodeId {
    Decision(SystemAuthorityDecisionNodeId),
    Rotation(SystemAuthorityRotationNodeId),
}

/// Store-independent failure vocabulary. `Missing` and `Corrupt` identify the
/// exact sealed dependency; `Limit` is deterministic protocol/backpressure,
/// and `Load` preserves the caller's storage error without interpreting it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SystemAuthorityTreeError<E> {
    Load(E),
    Visit(E),
    Missing(SystemAuthorityTreeNodeId),
    Corrupt(SystemAuthorityTreeNodeId),
    Limit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SystemAuthorityRotationLookup {
    proof: SystemAuthorityRotationProof,
    occupied_record: Option<SystemAuthorityRotationRecord>,
}

impl SystemAuthorityRotationLookup {
    pub(crate) const fn proof(&self) -> &SystemAuthorityRotationProof {
        &self.proof
    }

    pub(crate) const fn occupied_record(&self) -> Option<&SystemAuthorityRotationRecord> {
        self.occupied_record.as_ref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SystemAuthorityAuditProgress {
    More,
    Complete { node_count: u64, leaf_count: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DecisionAuditFrame {
    id: SystemAuthorityDecisionNodeId,
    depth: u16,
    prefix: [u8; 32],
}

/// Opaque deterministic DFS cursor. It is process-local scheduling state, not
/// a serialized authority record; after restart a caller begins again from the
/// replay-authenticated root. The pending stack never exceeds tree depth+1.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SystemAuthorityDecisionAuditCursor {
    root: SystemAuthorityDecisionNodeId,
    expected_count: u64,
    maximum_nodes: u64,
    pending: Vec<DecisionAuditFrame>,
    node_count: u64,
    leaf_count: u64,
    complete: bool,
}

impl SystemAuthorityDecisionAuditCursor {
    pub(crate) const fn node_count(&self) -> u64 {
        self.node_count
    }

    pub(crate) const fn leaf_count(&self) -> u64 {
        self.leaf_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RotationAuditFrame {
    id: SystemAuthorityRotationNodeId,
    depth: u16,
    prefix: u64,
}

/// Opaque bounded rotation-audit cursor. Ascending DFS order permits exact
/// epoch and committee-chain validation without retaining all records.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SystemAuthorityRotationAuditCursor {
    root: SystemAuthorityRotationNodeId,
    expected_count: u64,
    maximum_nodes: u64,
    expected_current_committee: SystemAuthorityCommitteeId,
    previous_committee: SystemAuthorityCommitteeId,
    next_epoch: u64,
    pending: Vec<RotationAuditFrame>,
    node_count: u64,
    leaf_count: u64,
    complete: bool,
}

impl SystemAuthorityRotationAuditCursor {
    pub(crate) const fn node_count(&self) -> u64 {
        self.node_count
    }

    pub(crate) const fn leaf_count(&self) -> u64 {
        self.leaf_count
    }
}

/// Build the canonical compressed path for one decision target from sealed
/// nodes. The loader returns canonical wire bytes so this module remains the
/// sole owner of node bounds, IDs, depths, and path rules.
pub(crate) fn prove_decision<E>(
    root: SystemAuthorityDecisionNodeId,
    target: AgentId,
    mut load_node: impl FnMut(SystemAuthorityDecisionNodeId) -> Result<Option<Vec<u8>>, E>,
) -> Result<SystemAuthorityDecisionProof, SystemAuthorityTreeError<E>> {
    let root_ref = SystemAuthorityTreeNodeId::Decision(root);
    if root == SystemAuthorityDecisionNodeId::ZERO || target == AgentId::ZERO {
        return Err(SystemAuthorityTreeError::Corrupt(root_ref));
    }
    let empty = decision_empty_ladder();
    let mut current = root;
    let mut siblings = Vec::new();
    siblings
        .try_reserve_exact(MAX_DECISION_PROOF_SIBLINGS)
        .map_err(|_| SystemAuthorityTreeError::Limit)?;
    for depth in 0..=DECISION_TREE_DEPTH {
        if current == empty[usize::from(depth)] {
            let proof = SystemAuthorityDecisionProof::vacant(target, siblings)
                .map_err(|_| SystemAuthorityTreeError::Corrupt(root_ref))?;
            proof
                .verifies(root)
                .map_err(|_| SystemAuthorityTreeError::Corrupt(root_ref))?;
            return Ok(proof);
        }
        let node = load_decision_node(current, &mut load_node)?;
        match node {
            SystemAuthorityDecisionNode::Branch {
                depth: stored_depth,
                left,
                right,
            } if depth < DECISION_TREE_DEPTH && stored_depth == depth => {
                let (next, sibling) = if bit_at(&target.0, depth) {
                    (right, left)
                } else {
                    (left, right)
                };
                if sibling != empty[usize::from(depth + 1)] {
                    siblings.push(
                        SystemAuthorityDecisionSibling::new(depth, sibling)
                            .map_err(|_| SystemAuthorityTreeError::Corrupt(root_ref))?,
                    );
                }
                current = next;
            }
            SystemAuthorityDecisionNode::Leaf(fact)
                if depth == DECISION_TREE_DEPTH && fact.target_agent() == target =>
            {
                let proof = SystemAuthorityDecisionProof::occupied(fact, siblings)
                    .map_err(|_| SystemAuthorityTreeError::Corrupt(root_ref))?;
                proof
                    .verifies(root)
                    .map_err(|_| SystemAuthorityTreeError::Corrupt(root_ref))?;
                return Ok(proof);
            }
            _ => {
                return Err(SystemAuthorityTreeError::Corrupt(
                    SystemAuthorityTreeNodeId::Decision(current),
                ));
            }
        }
    }
    Err(SystemAuthorityTreeError::Limit)
}

/// Build the canonical compressed path for one incoming epoch. Rotation
/// proofs intentionally carry only an occupied bit, so the authenticated
/// record is returned alongside the proof for callers constructing retries.
pub(crate) fn prove_rotation<E>(
    root: SystemAuthorityRotationNodeId,
    new_epoch: u64,
    mut load_node: impl FnMut(SystemAuthorityRotationNodeId) -> Result<Option<Vec<u8>>, E>,
) -> Result<SystemAuthorityRotationLookup, SystemAuthorityTreeError<E>> {
    let root_ref = SystemAuthorityTreeNodeId::Rotation(root);
    if root == SystemAuthorityRotationNodeId::ZERO || new_epoch <= 1 {
        return Err(SystemAuthorityTreeError::Corrupt(root_ref));
    }
    let empty = rotation_empty_ladder();
    let mut current = root;
    let mut siblings = Vec::new();
    siblings
        .try_reserve_exact(MAX_ROTATION_PROOF_SIBLINGS)
        .map_err(|_| SystemAuthorityTreeError::Limit)?;
    for depth in 0..=ROTATION_TREE_DEPTH {
        if current == empty[usize::from(depth)] {
            let proof = SystemAuthorityRotationProof::vacant(new_epoch, siblings)
                .map_err(|_| SystemAuthorityTreeError::Corrupt(root_ref))?;
            let reconstructed = rotation_root_from_path(
                new_epoch,
                empty[usize::from(ROTATION_TREE_DEPTH)],
                proof.siblings(),
            );
            if reconstructed != root {
                return Err(SystemAuthorityTreeError::Corrupt(root_ref));
            }
            return Ok(SystemAuthorityRotationLookup {
                proof,
                occupied_record: None,
            });
        }
        let node = load_rotation_node(current, &mut load_node)?;
        match node {
            SystemAuthorityRotationNode::Branch {
                depth: stored_depth,
                left,
                right,
            } if depth < ROTATION_TREE_DEPTH && stored_depth == depth => {
                let (next, sibling) = if rotation_bit_at(new_epoch, depth) {
                    (right, left)
                } else {
                    (left, right)
                };
                if sibling != empty[usize::from(depth + 1)] {
                    siblings.push(
                        SystemAuthorityRotationSibling::new(depth, sibling)
                            .map_err(|_| SystemAuthorityTreeError::Corrupt(root_ref))?,
                    );
                }
                current = next;
            }
            SystemAuthorityRotationNode::Leaf(record)
                if depth == ROTATION_TREE_DEPTH && record.new_epoch() == new_epoch =>
            {
                let proof = SystemAuthorityRotationProof::occupied(new_epoch, siblings)
                    .map_err(|_| SystemAuthorityTreeError::Corrupt(root_ref))?;
                proof
                    .verifies(root, &record)
                    .map_err(|_| SystemAuthorityTreeError::Corrupt(root_ref))?;
                return Ok(SystemAuthorityRotationLookup {
                    proof,
                    occupied_record: Some(record),
                });
            }
            _ => {
                return Err(SystemAuthorityTreeError::Corrupt(
                    SystemAuthorityTreeNodeId::Rotation(current),
                ));
            }
        }
    }
    Err(SystemAuthorityTreeError::Limit)
}

/// Begin a scrub/GC audit from replay-authenticated Control state. Ordinary
/// reopen authenticates State/current committee and loads only demanded proof
/// paths; a complete tree scrub is deliberately resumable and need not block
/// open. The cursor itself never carries authority.
pub(crate) fn begin_decision_tree_audit(
    root: SystemAuthorityDecisionNodeId,
    expected_count: u64,
) -> Result<SystemAuthorityDecisionAuditCursor, SystemAuthorityError> {
    if root == SystemAuthorityDecisionNodeId::ZERO
        || expected_count > u64::from(MAX_SYSTEM_AUTHORITY_DECISIONS)
        || (expected_count == 0) != (root == empty_decision_root())
    {
        return Err(SystemAuthorityError::InvalidState);
    }
    let maximum_nodes = expected_count
        .checked_mul(u64::from(DECISION_TREE_DEPTH) + 1)
        .ok_or(SystemAuthorityError::Capacity)?;
    let mut pending = Vec::new();
    pending
        .try_reserve_exact(usize::from(DECISION_TREE_DEPTH) + 1)
        .map_err(|_| SystemAuthorityError::Capacity)?;
    pending.push(DecisionAuditFrame {
        id: root,
        depth: 0,
        prefix: [0; 32],
    });
    Ok(SystemAuthorityDecisionAuditCursor {
        root,
        expected_count,
        maximum_nodes,
        pending,
        node_count: 0,
        leaf_count: 0,
        complete: false,
    })
}

/// Strictly load and visit at most `max_nodes` non-empty decision nodes. The
/// cursor advances only after loader and visitor success, so retry sees the
/// same node. Visitor side effects should therefore be idempotent and can
/// never mint authority. Completion exact-checks the authenticated leaf count.
pub(crate) fn audit_decision_tree_batch<E>(
    cursor: &mut SystemAuthorityDecisionAuditCursor,
    max_nodes: usize,
    mut load_node: impl FnMut(SystemAuthorityDecisionNodeId) -> Result<Option<Vec<u8>>, E>,
    mut visit: impl FnMut(SystemAuthorityDecisionNodeId, &SystemAuthorityDecisionNode) -> Result<(), E>,
) -> Result<SystemAuthorityAuditProgress, SystemAuthorityTreeError<E>> {
    let root_ref = SystemAuthorityTreeNodeId::Decision(cursor.root);
    if max_nodes == 0 {
        return Err(SystemAuthorityTreeError::Limit);
    }
    if cursor.complete {
        return Ok(SystemAuthorityAuditProgress::Complete {
            node_count: cursor.node_count,
            leaf_count: cursor.leaf_count,
        });
    }
    let empty = decision_empty_ladder();
    let mut processed = 0_usize;
    while processed < max_nodes {
        let Some(frame) = cursor.pending.last().copied() else {
            if cursor.leaf_count != cursor.expected_count {
                return Err(SystemAuthorityTreeError::Corrupt(root_ref));
            }
            cursor.complete = true;
            return Ok(SystemAuthorityAuditProgress::Complete {
                node_count: cursor.node_count,
                leaf_count: cursor.leaf_count,
            });
        };
        if frame.depth > DECISION_TREE_DEPTH {
            return Err(SystemAuthorityTreeError::Corrupt(root_ref));
        }
        if frame.id == empty[usize::from(frame.depth)] {
            cursor.pending.pop();
            continue;
        }
        if cursor.node_count >= cursor.maximum_nodes
            || cursor.node_count >= MAX_SYSTEM_AUTHORITY_DECISION_TREE_NODES as u64
        {
            return Err(SystemAuthorityTreeError::Limit);
        }
        let node = load_decision_node(frame.id, &mut load_node)?;
        let next_leaf_count = match &node {
            SystemAuthorityDecisionNode::Branch {
                depth: stored_depth,
                ..
            } if frame.depth < DECISION_TREE_DEPTH && *stored_depth == frame.depth => None,
            SystemAuthorityDecisionNode::Leaf(fact)
                if frame.depth == DECISION_TREE_DEPTH && fact.target_agent().0 == frame.prefix =>
            {
                let next = cursor
                    .leaf_count
                    .checked_add(1)
                    .ok_or(SystemAuthorityTreeError::Limit)?;
                if next > cursor.expected_count {
                    return Err(SystemAuthorityTreeError::Corrupt(root_ref));
                }
                Some(next)
            }
            _ => {
                return Err(SystemAuthorityTreeError::Corrupt(
                    SystemAuthorityTreeNodeId::Decision(frame.id),
                ));
            }
        };
        visit(frame.id, &node).map_err(SystemAuthorityTreeError::Visit)?;
        // Commit the cursor only after load, strict validation, and visitor
        // success. Loader/visitor retry therefore observes this exact node.
        cursor.pending.pop();
        match node {
            SystemAuthorityDecisionNode::Branch { left, right, .. } => {
                let mut right_prefix = frame.prefix;
                set_decision_prefix_bit(&mut right_prefix, frame.depth);
                // LIFO right-then-left yields canonical ascending key order.
                cursor.pending.push(DecisionAuditFrame {
                    id: right,
                    depth: frame.depth + 1,
                    prefix: right_prefix,
                });
                cursor.pending.push(DecisionAuditFrame {
                    id: left,
                    depth: frame.depth + 1,
                    prefix: frame.prefix,
                });
            }
            SystemAuthorityDecisionNode::Leaf(_) => {
                if let Some(leaf_count) = next_leaf_count {
                    cursor.leaf_count = leaf_count;
                }
            }
        }
        cursor.node_count = cursor
            .node_count
            .checked_add(1)
            .ok_or(SystemAuthorityTreeError::Limit)?;
        processed += 1;
    }
    Ok(SystemAuthorityAuditProgress::More)
}

pub(crate) fn begin_rotation_tree_audit(
    root: SystemAuthorityRotationNodeId,
    expected_count: u64,
    initial_committee: SystemAuthorityCommitteeId,
    current_committee: SystemAuthorityCommitteeId,
) -> Result<SystemAuthorityRotationAuditCursor, SystemAuthorityError> {
    if root == SystemAuthorityRotationNodeId::ZERO
        || initial_committee == SystemAuthorityCommitteeId::ZERO
        || current_committee == SystemAuthorityCommitteeId::ZERO
        || expected_count > u64::from(MAX_SYSTEM_AUTHORITY_ROTATIONS)
        || (expected_count == 0) != (root == empty_rotation_root())
        || (expected_count == 0 && initial_committee != current_committee)
    {
        return Err(SystemAuthorityError::InvalidState);
    }
    let maximum_nodes = expected_count
        .checked_mul(u64::from(ROTATION_TREE_DEPTH) + 1)
        .ok_or(SystemAuthorityError::Capacity)?;
    let mut pending = Vec::new();
    pending
        .try_reserve_exact(usize::from(ROTATION_TREE_DEPTH) + 1)
        .map_err(|_| SystemAuthorityError::Capacity)?;
    pending.push(RotationAuditFrame {
        id: root,
        depth: 0,
        prefix: 0,
    });
    Ok(SystemAuthorityRotationAuditCursor {
        root,
        expected_count,
        maximum_nodes,
        expected_current_committee: current_committee,
        previous_committee: initial_committee,
        next_epoch: 2,
        pending,
        node_count: 0,
        leaf_count: 0,
        complete: false,
    })
}

/// Strictly load and visit a bounded canonical ascending-epoch batch. The
/// cursor retains only one pending sibling per depth and the rolling committee
/// chain. Cryptographic scrub visitors load committee records and invoke
/// `SystemAuthorityState::verify_historical_rotation`, which closes both the
/// generation-scope and joint-QC verification legs in one call.
pub(crate) fn audit_rotation_tree_batch<E>(
    cursor: &mut SystemAuthorityRotationAuditCursor,
    max_nodes: usize,
    mut load_node: impl FnMut(SystemAuthorityRotationNodeId) -> Result<Option<Vec<u8>>, E>,
    mut visit: impl FnMut(SystemAuthorityRotationNodeId, &SystemAuthorityRotationNode) -> Result<(), E>,
) -> Result<SystemAuthorityAuditProgress, SystemAuthorityTreeError<E>> {
    let root_ref = SystemAuthorityTreeNodeId::Rotation(cursor.root);
    if max_nodes == 0 {
        return Err(SystemAuthorityTreeError::Limit);
    }
    if cursor.complete {
        return Ok(SystemAuthorityAuditProgress::Complete {
            node_count: cursor.node_count,
            leaf_count: cursor.leaf_count,
        });
    }
    let empty = rotation_empty_ladder();
    let mut processed = 0_usize;
    while processed < max_nodes {
        let Some(frame) = cursor.pending.last().copied() else {
            if cursor.leaf_count != cursor.expected_count
                || cursor.previous_committee != cursor.expected_current_committee
                || cursor.next_epoch != cursor.expected_count.saturating_add(2)
            {
                return Err(SystemAuthorityTreeError::Corrupt(root_ref));
            }
            cursor.complete = true;
            return Ok(SystemAuthorityAuditProgress::Complete {
                node_count: cursor.node_count,
                leaf_count: cursor.leaf_count,
            });
        };
        if frame.depth > ROTATION_TREE_DEPTH {
            return Err(SystemAuthorityTreeError::Corrupt(root_ref));
        }
        if frame.id == empty[usize::from(frame.depth)] {
            cursor.pending.pop();
            continue;
        }
        if cursor.node_count >= cursor.maximum_nodes
            || cursor.node_count >= MAX_SYSTEM_AUTHORITY_ROTATION_TREE_NODES as u64
        {
            return Err(SystemAuthorityTreeError::Limit);
        }
        let node = load_rotation_node(frame.id, &mut load_node)?;
        let next_leaf_state = match &node {
            SystemAuthorityRotationNode::Branch {
                depth: stored_depth,
                ..
            } if frame.depth < ROTATION_TREE_DEPTH && *stored_depth == frame.depth => None,
            SystemAuthorityRotationNode::Leaf(record)
                if frame.depth == ROTATION_TREE_DEPTH
                    && record.new_epoch() == frame.prefix
                    && record.new_epoch() == cursor.next_epoch
                    && record.old_committee() == cursor.previous_committee =>
            {
                let leaf_count = cursor
                    .leaf_count
                    .checked_add(1)
                    .ok_or(SystemAuthorityTreeError::Limit)?;
                if leaf_count > cursor.expected_count {
                    return Err(SystemAuthorityTreeError::Corrupt(root_ref));
                }
                let next_epoch = cursor
                    .next_epoch
                    .checked_add(1)
                    .ok_or(SystemAuthorityTreeError::Limit)?;
                Some((leaf_count, record.new_committee(), next_epoch))
            }
            _ => {
                return Err(SystemAuthorityTreeError::Corrupt(
                    SystemAuthorityTreeNodeId::Rotation(frame.id),
                ));
            }
        };
        visit(frame.id, &node).map_err(SystemAuthorityTreeError::Visit)?;
        cursor.pending.pop();
        match node {
            SystemAuthorityRotationNode::Branch { left, right, .. } => {
                let right_prefix = frame.prefix | (1_u64 << (63 - u32::from(frame.depth)));
                cursor.pending.push(RotationAuditFrame {
                    id: right,
                    depth: frame.depth + 1,
                    prefix: right_prefix,
                });
                cursor.pending.push(RotationAuditFrame {
                    id: left,
                    depth: frame.depth + 1,
                    prefix: frame.prefix,
                });
            }
            SystemAuthorityRotationNode::Leaf(_) => {
                if let Some((leaf_count, previous_committee, next_epoch)) = next_leaf_state {
                    cursor.leaf_count = leaf_count;
                    cursor.previous_committee = previous_committee;
                    cursor.next_epoch = next_epoch;
                }
            }
        }
        cursor.node_count = cursor
            .node_count
            .checked_add(1)
            .ok_or(SystemAuthorityTreeError::Limit)?;
        processed += 1;
    }
    Ok(SystemAuthorityAuditProgress::More)
}

fn load_decision_node<E>(
    id: SystemAuthorityDecisionNodeId,
    load_node: &mut impl FnMut(SystemAuthorityDecisionNodeId) -> Result<Option<Vec<u8>>, E>,
) -> Result<SystemAuthorityDecisionNode, SystemAuthorityTreeError<E>> {
    let reference = SystemAuthorityTreeNodeId::Decision(id);
    let bytes = load_node(id)
        .map_err(SystemAuthorityTreeError::Load)?
        .ok_or(SystemAuthorityTreeError::Missing(reference))?;
    if bytes.len() > MAX_SYSTEM_AUTHORITY_DECISION_NODE_BYTES {
        return Err(SystemAuthorityTreeError::Limit);
    }
    let node = SystemAuthorityDecisionNode::decode(&bytes).map_err(|error| match error {
        DecodeError::LimitExceeded => SystemAuthorityTreeError::Limit,
        _ => SystemAuthorityTreeError::Corrupt(reference),
    })?;
    if node.id() != id {
        Err(SystemAuthorityTreeError::Corrupt(reference))
    } else {
        Ok(node)
    }
}

fn load_rotation_node<E>(
    id: SystemAuthorityRotationNodeId,
    load_node: &mut impl FnMut(SystemAuthorityRotationNodeId) -> Result<Option<Vec<u8>>, E>,
) -> Result<SystemAuthorityRotationNode, SystemAuthorityTreeError<E>> {
    let reference = SystemAuthorityTreeNodeId::Rotation(id);
    let bytes = load_node(id)
        .map_err(SystemAuthorityTreeError::Load)?
        .ok_or(SystemAuthorityTreeError::Missing(reference))?;
    if bytes.len() > MAX_SYSTEM_AUTHORITY_ROTATION_NODE_BYTES {
        return Err(SystemAuthorityTreeError::Limit);
    }
    let node = SystemAuthorityRotationNode::decode(&bytes).map_err(|error| match error {
        DecodeError::LimitExceeded => SystemAuthorityTreeError::Limit,
        _ => SystemAuthorityTreeError::Corrupt(reference),
    })?;
    if node.id() != id {
        Err(SystemAuthorityTreeError::Corrupt(reference))
    } else {
        Ok(node)
    }
}

fn set_decision_prefix_bit(prefix: &mut [u8; 32], depth: u16) {
    let depth = usize::from(depth);
    prefix[depth / 8] |= 0x80 >> (depth % 8);
}

fn insert_decision(
    current_root: SystemAuthorityDecisionNodeId,
    proof: &SystemAuthorityDecisionProof,
    fact: SystemAuthorityDecisionFact,
) -> Result<SystemAuthorityDecisionWritePlan, SystemAuthorityError> {
    proof.verifies(current_root)?;
    if proof.occupied.is_some() || proof.target_agent != fact.target_agent {
        return Err(SystemAuthorityError::InvalidDecisionProof);
    }
    let mut nodes = Vec::new();
    nodes
        .try_reserve_exact(usize::from(DECISION_TREE_DEPTH) + 1)
        .map_err(|_| SystemAuthorityError::Capacity)?;
    let empty = decision_empty_ladder();
    let mut child = fact.id();
    let mut old_child = empty[usize::from(DECISION_TREE_DEPTH)];
    let mut retired_node_ids = Vec::new();
    nodes.push(SystemAuthorityDecisionNode::Leaf(fact));
    let mut sibling_index = proof.siblings.len();
    for depth in (0..DECISION_TREE_DEPTH).rev() {
        let sibling = if sibling_index != 0 && proof.siblings[sibling_index - 1].depth == depth {
            sibling_index -= 1;
            proof.siblings[sibling_index].node
        } else {
            empty[usize::from(depth + 1)]
        };
        let (left, right) = if bit_at(&proof.target_agent.0, depth) {
            (sibling, child)
        } else {
            (child, sibling)
        };
        let branch = SystemAuthorityDecisionNode::Branch { depth, left, right };
        child = branch.id();
        nodes.push(branch);

        let (old_left, old_right) = if bit_at(&proof.target_agent.0, depth) {
            (sibling, old_child)
        } else {
            (old_child, sibling)
        };
        old_child = decision_branch_id(depth, old_left, old_right);
        if old_child != empty[usize::from(depth)] {
            retired_node_ids.push(old_child);
        }
    }
    debug_assert_eq!(sibling_index, 0);
    let root = child;
    nodes.sort_by_key(SystemAuthorityDecisionNode::id);
    retired_node_ids.sort();
    retired_node_ids.dedup();
    retired_node_ids.retain(|id| {
        nodes
            .binary_search_by_key(id, SystemAuthorityDecisionNode::id)
            .is_err()
    });
    Ok(SystemAuthorityDecisionWritePlan {
        previous_root: current_root,
        root,
        inserted: true,
        nodes,
        retired_node_ids,
    })
}

fn unchanged_history(root: SystemAuthorityDecisionNodeId) -> SystemAuthorityDecisionWritePlan {
    SystemAuthorityDecisionWritePlan {
        previous_root: root,
        root,
        inserted: false,
        nodes: Vec::new(),
        retired_node_ids: Vec::new(),
    }
}

fn root_from_path(
    key: AgentId,
    mut child: SystemAuthorityDecisionNodeId,
    siblings: &[SystemAuthorityDecisionSibling],
) -> SystemAuthorityDecisionNodeId {
    let empty = decision_empty_ladder();
    let mut sibling_index = siblings.len();
    for depth in (0..DECISION_TREE_DEPTH).rev() {
        let sibling = if sibling_index != 0 && siblings[sibling_index - 1].depth == depth {
            sibling_index -= 1;
            siblings[sibling_index].node
        } else {
            empty[usize::from(depth + 1)]
        };
        child = if bit_at(&key.0, depth) {
            decision_branch_id(depth, sibling, child)
        } else {
            decision_branch_id(depth, child, sibling)
        };
    }
    child
}

fn bit_at(bytes: &[u8; 32], depth: u16) -> bool {
    let depth = usize::from(depth);
    bytes[depth / 8] & (0x80 >> (depth % 8)) != 0
}

pub fn empty_decision_root() -> SystemAuthorityDecisionNodeId {
    decision_empty_ladder()[0]
}

fn empty_decision_node(depth: u16) -> SystemAuthorityDecisionNodeId {
    decision_empty_ladder()[usize::from(depth)]
}

fn decision_empty_ladder() -> Vec<SystemAuthorityDecisionNodeId> {
    let mut ladder =
        vec![SystemAuthorityDecisionNodeId::ZERO; usize::from(DECISION_TREE_DEPTH) + 1];
    ladder[usize::from(DECISION_TREE_DEPTH)] = SystemAuthorityDecisionNodeId(
        Hash::digest(
            DECISION_EMPTY_ID_DOMAIN,
            &[&DECISION_TREE_DEPTH.to_le_bytes()],
        )
        .0,
    );
    for branch_depth in (0..DECISION_TREE_DEPTH).rev() {
        let child = ladder[usize::from(branch_depth + 1)];
        ladder[usize::from(branch_depth)] = decision_branch_id(branch_depth, child, child);
    }
    ladder
}

fn decision_branch_id(
    depth: u16,
    left: SystemAuthorityDecisionNodeId,
    right: SystemAuthorityDecisionNodeId,
) -> SystemAuthorityDecisionNodeId {
    SystemAuthorityDecisionNodeId(
        Hash::digest(
            DECISION_BRANCH_ID_DOMAIN,
            &[&depth.to_le_bytes(), left.as_bytes(), right.as_bytes()],
        )
        .0,
    )
}

fn insert_rotation(
    current_root: SystemAuthorityRotationNodeId,
    proof: &SystemAuthorityRotationProof,
    record: SystemAuthorityRotationRecord,
    old_committee: &AuthorityCommittee,
    new_committee: &AuthorityCommittee,
) -> Result<SystemAuthorityRotationWritePlan, SystemAuthorityError> {
    proof.verifies(current_root, &record)?;
    if proof.occupied || proof.new_epoch != record.new_epoch() {
        return Err(SystemAuthorityError::InvalidRotationProof);
    }
    let empty = rotation_empty_ladder();
    let mut nodes = Vec::new();
    nodes
        .try_reserve_exact(usize::from(ROTATION_TREE_DEPTH) + 1)
        .map_err(|_| SystemAuthorityError::Capacity)?;
    let mut child = record.leaf_id();
    let mut old_child = empty[usize::from(ROTATION_TREE_DEPTH)];
    let mut retired_node_ids = Vec::new();
    nodes.push(SystemAuthorityRotationNode::Leaf(record));
    let mut sibling_index = proof.siblings.len();
    for depth in (0..ROTATION_TREE_DEPTH).rev() {
        let sibling = if sibling_index != 0 && proof.siblings[sibling_index - 1].depth == depth {
            sibling_index -= 1;
            proof.siblings[sibling_index].node
        } else {
            empty[usize::from(depth + 1)]
        };
        let (left, right) = if rotation_bit_at(proof.new_epoch, depth) {
            (sibling, child)
        } else {
            (child, sibling)
        };
        let branch = SystemAuthorityRotationNode::Branch { depth, left, right };
        child = branch.id();
        nodes.push(branch);

        let (old_left, old_right) = if rotation_bit_at(proof.new_epoch, depth) {
            (sibling, old_child)
        } else {
            (old_child, sibling)
        };
        old_child = rotation_branch_id(depth, old_left, old_right);
        if old_child != empty[usize::from(depth)] {
            retired_node_ids.push(old_child);
        }
    }
    debug_assert_eq!(sibling_index, 0);
    let root = child;
    nodes.sort_by_key(SystemAuthorityRotationNode::id);
    retired_node_ids.sort();
    retired_node_ids.dedup();
    retired_node_ids.retain(|id| {
        nodes
            .binary_search_by_key(id, SystemAuthorityRotationNode::id)
            .is_err()
    });
    let mut committee_records = vec![
        SystemAuthorityCommitteeRecord::new(old_committee.clone())?,
        SystemAuthorityCommitteeRecord::new(new_committee.clone())?,
    ];
    committee_records.sort_by_key(SystemAuthorityCommitteeRecord::id);
    committee_records.dedup_by_key(|record| record.id());
    Ok(SystemAuthorityRotationWritePlan {
        previous_root: current_root,
        root,
        inserted: true,
        nodes,
        retired_node_ids,
        committee_records,
    })
}

fn unchanged_rotation_history(
    root: SystemAuthorityRotationNodeId,
) -> SystemAuthorityRotationWritePlan {
    SystemAuthorityRotationWritePlan {
        previous_root: root,
        root,
        inserted: false,
        nodes: Vec::new(),
        retired_node_ids: Vec::new(),
        committee_records: Vec::new(),
    }
}

fn rotation_root_from_path(
    key: u64,
    mut child: SystemAuthorityRotationNodeId,
    siblings: &[SystemAuthorityRotationSibling],
) -> SystemAuthorityRotationNodeId {
    let empty = rotation_empty_ladder();
    let mut sibling_index = siblings.len();
    for depth in (0..ROTATION_TREE_DEPTH).rev() {
        let sibling = if sibling_index != 0 && siblings[sibling_index - 1].depth == depth {
            sibling_index -= 1;
            siblings[sibling_index].node
        } else {
            empty[usize::from(depth + 1)]
        };
        child = if rotation_bit_at(key, depth) {
            rotation_branch_id(depth, sibling, child)
        } else {
            rotation_branch_id(depth, child, sibling)
        };
    }
    child
}

fn rotation_bit_at(key: u64, depth: u16) -> bool {
    key & (1_u64 << (63 - u32::from(depth))) != 0
}

pub fn empty_rotation_root() -> SystemAuthorityRotationNodeId {
    rotation_empty_ladder()[0]
}

fn empty_rotation_node(depth: u16) -> SystemAuthorityRotationNodeId {
    rotation_empty_ladder()[usize::from(depth)]
}

fn rotation_empty_ladder() -> Vec<SystemAuthorityRotationNodeId> {
    let mut ladder =
        vec![SystemAuthorityRotationNodeId::ZERO; usize::from(ROTATION_TREE_DEPTH) + 1];
    ladder[usize::from(ROTATION_TREE_DEPTH)] = SystemAuthorityRotationNodeId(
        Hash::digest(
            ROTATION_EMPTY_ID_DOMAIN,
            &[&ROTATION_TREE_DEPTH.to_le_bytes()],
        )
        .0,
    );
    for depth in (0..ROTATION_TREE_DEPTH).rev() {
        let child = ladder[usize::from(depth + 1)];
        ladder[usize::from(depth)] = rotation_branch_id(depth, child, child);
    }
    ladder
}

fn rotation_branch_id(
    depth: u16,
    left: SystemAuthorityRotationNodeId,
    right: SystemAuthorityRotationNodeId,
) -> SystemAuthorityRotationNodeId {
    SystemAuthorityRotationNodeId(
        Hash::digest(
            ROTATION_BRANCH_ID_DOMAIN,
            &[&depth.to_le_bytes(), left.as_bytes(), right.as_bytes()],
        )
        .0,
    )
}

fn validate_decision_evidence_link(
    decision: &AgentGenesisDecision,
    evidence: &AgentGenesisEvidence,
) -> Result<(), SystemAuthorityError> {
    decision.validate().map_err(SystemAuthorityError::Genesis)?;
    evidence.validate().map_err(SystemAuthorityError::Genesis)?;
    let claim = evidence.claim();
    if decision.system_genesis() != claim.system_genesis()
        || decision.system_admission() != claim.system_admission()
        || decision.proposal() != claim.proposal()
        || decision.replicas() != claim.replicas()
        || decision.evidence() != evidence.id()
        || decision.claim() != claim.authority_claim()
    {
        Err(SystemAuthorityError::InvalidFinalize)
    } else {
        Ok(())
    }
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

fn decode_profile(tag: u8) -> Result<AgentProfile, DecodeError> {
    match tag {
        0 => Ok(AgentProfile::Local),
        1 => Ok(AgentProfile::Shared),
        2 => Ok(AgentProfile::Private),
        _ => Err(DecodeError::InvalidTag),
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

fn enforce_complete_bound(decoder: &Decoder<'_>, maximum: usize) -> Result<(), DecodeError> {
    let body = maximum
        .checked_sub(SERVICE_WIRE_HEADER_BYTES)
        .ok_or(DecodeError::LimitExceeded)?;
    if decoder.remaining() > body {
        Err(DecodeError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn enforce_encoded_bound<T: ServiceWire>(
    value: &T,
    maximum: usize,
) -> Result<(), SystemAuthorityError> {
    if value.encode().len() > maximum {
        Err(SystemAuthorityError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn map_decode_error(error: SystemAuthorityError) -> DecodeError {
    match error {
        SystemAuthorityError::LimitExceeded | SystemAuthorityError::Capacity => {
            DecodeError::LimitExceeded
        }
        _ => DecodeError::NonCanonical,
    }
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, collections::BTreeMap, vec};

    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;
    use crate::agent::authority::{
        AgentAuthorityBinding, AgentAuthorityClaim, AgentAuthorityReceipt,
        CAPABILITY_AGENT_CREATE_PRIVATE, CAPABILITY_AGENT_CREATE_SHARED, ED25519_SIGNATURE_BYTES,
        ed25519_public_key_wire,
    };
    use crate::agent::committee::{
        AuthorityCommitteeMember, AuthorityMemberRole, AuthoritySignature, AuthoritySignerId,
    };
    use crate::agent::contract::RuntimePackageContract;
    use crate::agent::genesis::{
        AgentGenesisClaim, AgentGenesisExpectations, AgentGenesisLocator, AgentGenesisProposal,
        AgentReplicaCommittee, AgentReplicaMember, derive_replica_raft_slot,
    };
    use crate::agent::journal::{
        ReplayInput, ReplayOperation, RuntimeBinding, system_genesis_artifact_closure_commitment,
    };
    use crate::agent::{
        AgentIdentity, AgentReplica, LaneSet, LifecycleAuthorityAdmission, LifecycleRequest,
        ReplicaRole, RuntimeCapabilities, StateLane,
    };
    use crate::service::{
        ActorId, BlobRef, CapabilityId, CredentialId, DeploymentId, NodeId, PrincipalId,
        ProducerId, ProgramId,
    };

    const SPACE: SpaceId = SpaceId([0x11; 32]);
    const SYSTEM_AGENT: AgentId = AgentId([0xa1; 32]);
    const ROOT_ANCHOR: RootAnchorId = RootAnchorId::from_bytes([0x71; 32]);
    const ROOT_CONFIG: RootAnchorConfigCommitment =
        RootAnchorConfigCommitment::from_bytes([0x72; 32]);
    const RUNTIME_BYTES: &[u8] = b"ordinary-agent-runtime";
    const PEER_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];

    #[derive(Clone)]
    struct OrdinaryFixture {
        proposal: AgentGenesisProposal,
        replicas: AgentReplicaCommittee,
        evidence: AgentGenesisEvidence,
        decision: AgentGenesisDecision,
        provision: AgentGenesisProvision,
    }

    fn authority_binding() -> AgentAuthorityBinding {
        let public_key = ed25519_public_key_wire([0x41; 32]);
        AgentAuthorityBinding {
            agent: SYSTEM_AGENT,
            actor: ActorId([0xa2; 32]),
            deployment: DeploymentId([0xa3; 32]),
            program: ProgramId([0xa4; 32]),
            producer: ProducerId::of_public_key(&public_key),
            public_key,
        }
    }

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn authority_committee(
        epoch: u64,
        previous: Option<Hash>,
        keys: &[SigningKey],
    ) -> AuthorityCommittee {
        let mut members = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                AuthorityCommitteeMember::new(
                    NodeId([(0x80 + index as u8).wrapping_add(key.to_bytes()[0]); 32]),
                    key.verifying_key().to_bytes(),
                    AuthorityMemberRole::Voter,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        members.sort_by_key(AuthorityCommitteeMember::signer);
        AuthorityCommittee::new(
            SPACE,
            authority_binding().commitment(),
            epoch,
            previous,
            members,
        )
        .unwrap()
    }

    fn certificate(
        committee: &AuthorityCommittee,
        claim: AuthorityClaimCommitment,
        keys: &[SigningKey],
    ) -> AuthorityQuorumCertificate {
        let message = AuthorityQuorumCertificate::signing_message(
            committee.authority_binding(),
            committee.epoch(),
            committee.commitment(),
            claim,
        );
        let mut signatures = keys
            .iter()
            .map(|key| {
                AuthoritySignature::new(
                    AuthoritySignerId::of_raw_ed25519(&key.verifying_key().to_bytes()),
                    key.sign(&message.0).to_bytes(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(AuthoritySignature::signer);
        AuthorityQuorumCertificate::new(committee, claim, signatures).unwrap()
    }

    fn system_genesis(committee: &AuthorityCommittee) -> SystemAuthorityGenesis {
        SystemAuthorityGenesis::new(ROOT_ANCHOR, 1, ROOT_CONFIG, committee.clone(), 1, 64, 16)
            .unwrap()
    }

    fn journal_scope() -> SystemAuthorityJournalScope {
        SystemAuthorityJournalScope::new(
            AgentJournalGenesisId::new([0x92; 32]),
            AgentGenesisAdmissionId::from_bytes([0x93; 32]),
        )
        .unwrap()
    }

    fn transport_member(byte: u8, role: ReplicaRole) -> AgentReplicaMember {
        let raw = [byte; 32];
        let mut peer_id = Vec::from(PEER_PREFIX);
        peer_id.extend_from_slice(&raw);
        let node = NodeId::of_authenticated_peer(&peer_id);
        let principal = PrincipalId::of_public_key(&raw);
        let raft_slot = (role == ReplicaRole::Voter).then(|| derive_replica_raft_slot(&peer_id));
        AgentReplicaMember::new(
            AgentReplica {
                node,
                principal,
                role,
            },
            peer_id,
            raw,
            raft_slot,
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn ordinary_fixture(
        profile: AgentProfile,
        sequence: u64,
        post_byte: u8,
        nonce_byte: u8,
        committee: &AuthorityCommittee,
        committee_keys: &[SigningKey],
        scope: SystemAuthorityJournalScope,
    ) -> OrdinaryFixture {
        let mut replica_members = match profile {
            AgentProfile::Shared => vec![
                transport_member(0x31, ReplicaRole::Voter),
                transport_member(0x32, ReplicaRole::Voter),
                transport_member(0x33, ReplicaRole::Observer),
            ],
            AgentProfile::Private => vec![transport_member(0x34, ReplicaRole::Observer)],
            AgentProfile::Local => unreachable!(),
        };
        replica_members.sort_by_key(|member| member.replica().node);
        let owner = if profile == AgentProfile::Private {
            replica_members[0].replica().principal
        } else {
            PrincipalId([0x12; 32])
        };
        let nonce = Hash([nonce_byte; 32]);
        let agent = AgentId::derive(SPACE, owner, nonce.as_bytes());
        let lanes = match profile {
            AgentProfile::Shared => LaneSet::ALL,
            AgentProfile::Private => {
                LaneSet::of(StateLane::Merge).union(LaneSet::of(StateLane::Local))
            }
            AgentProfile::Local => unreachable!(),
        };
        let config = AgentConfig {
            identity: AgentIdentity {
                space: SPACE,
                agent,
                owner,
                profile,
                runtime_deployment: DeploymentId([0x21; 32]),
                runtime_program: ProgramId([0x22; 32]),
                runtime_producer: ProducerId([0x23; 32]),
            },
            creation_nonce: nonce,
            authority: authority_binding(),
            runtime_package: BlobRef::of_bytes(RUNTIME_BYTES),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities {
                lanes,
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
            space: SPACE,
            agent,
            deployment: config.identity.runtime_deployment,
            program: config.identity.runtime_program,
            producer: config.identity.runtime_producer,
            package: config.runtime_package.clone(),
            runtime_abi: super::super::RUNTIME_ABI_ID,
            execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
        };
        let inner = LifecycleRequest::Create(config.clone());
        let capability = match profile {
            AgentProfile::Shared => CAPABILITY_AGENT_CREATE_SHARED,
            AgentProfile::Private => CAPABILITY_AGENT_CREATE_PRIVATE,
            AgentProfile::Local => unreachable!(),
        };
        let create = ReplayInput {
            runtime,
            operation: ReplayOperation::Management {
                request: LifecycleRequest::Authorized {
                    admission: LifecycleAuthorityAdmission {
                        receipt: AgentAuthorityReceipt {
                            claim: AgentAuthorityClaim {
                                authority: config.authority.clone(),
                                space: SPACE,
                                agent,
                                principal: owner,
                                credential: CredentialId([0x24; 32]),
                                capability: CapabilityId::named(capability),
                                operation: inner.commitment(),
                                sequence,
                                valid_from: 10,
                                valid_until: 40,
                            },
                            signature: vec![0x25; ED25519_SIGNATURE_BYTES],
                        },
                        observed_slot: 20,
                    },
                    request: Box::new(inner.clone()),
                },
            },
        };
        let catalog = vec![config.runtime_package.clone()];
        let expectations = AgentGenesisExpectations::new(
            create.runtime.commitment(),
            inner.commitment(),
            Hash([post_byte; 32]),
            system_genesis_artifact_closure_commitment(&catalog).unwrap(),
            sequence,
        )
        .unwrap();
        let proposal = AgentGenesisProposal::new(
            AgentGenesisLocator {
                space: SPACE,
                agent,
            },
            create,
            expectations,
            catalog,
        )
        .unwrap();
        let replicas = AgentReplicaCommittee::new(SPACE, agent, profile, replica_members).unwrap();
        let claim = AgentGenesisClaim::new(
            SYSTEM_AGENT,
            scope.system_genesis(),
            scope.agent_admission(),
            &proposal,
            &replicas,
        )
        .unwrap();
        let qc = certificate(committee, claim.authority_claim(), committee_keys);
        let evidence = AgentGenesisEvidence::new(claim, qc).unwrap();
        let decision = AgentGenesisDecision::new(&proposal, &replicas, &evidence).unwrap();
        let provision = AgentGenesisProvision::new(
            proposal.clone(),
            replicas.clone(),
            evidence.clone(),
            decision.clone(),
        )
        .unwrap();
        OrdinaryFixture {
            proposal,
            replicas,
            evidence,
            decision,
            provision,
        }
    }

    fn rotation(
        state: &SystemAuthorityState,
        signed_scope: SystemAuthorityJournalScope,
        old: &AuthorityCommittee,
        old_keys: &[SigningKey],
        new: &AuthorityCommittee,
        new_keys: &[SigningKey],
        rotation_sequence: u64,
        first_sequence: u64,
        proof: SystemAuthorityRotationProof,
    ) -> SystemAuthorityRotation {
        let transition = SystemAuthorityRotationClaim::new(
            state.root_anchor,
            state.root_anchor_config_version,
            state.root_anchor_config,
            signed_scope.commitment(state.root_anchor).unwrap(),
            old,
            new,
            rotation_sequence,
            first_sequence,
        )
        .unwrap();
        let authority_claim = transition.authority_claim();
        let joint = SystemAuthorityRotationCertificate::new(
            transition,
            certificate(old, authority_claim, old_keys),
            certificate(new, authority_claim, new_keys),
        )
        .unwrap();
        SystemAuthorityRotation::new(new.clone(), joint, proof).unwrap()
    }

    fn rotation_subtree(
        depth: u16,
        records: &[&SystemAuthorityRotationRecord],
    ) -> SystemAuthorityRotationNodeId {
        let empty = rotation_empty_ladder();
        if records.is_empty() {
            return empty[usize::from(depth)];
        }
        if depth == ROTATION_TREE_DEPTH {
            assert_eq!(records.len(), 1);
            return records[0].leaf_id();
        }
        let (left, right): (Vec<_>, Vec<_>) = records
            .iter()
            .copied()
            .partition(|record| !rotation_bit_at(record.new_epoch(), depth));
        rotation_branch_id(
            depth,
            rotation_subtree(depth + 1, &left),
            rotation_subtree(depth + 1, &right),
        )
    }

    fn rotation_proof(
        target_epoch: u64,
        occupied: bool,
        records: &[&SystemAuthorityRotationRecord],
    ) -> SystemAuthorityRotationProof {
        let empty = rotation_empty_ladder();
        let mut path_records = records.to_vec();
        let mut siblings = Vec::new();
        for depth in 0..ROTATION_TREE_DEPTH {
            let target_bit = rotation_bit_at(target_epoch, depth);
            let (same, opposite): (Vec<_>, Vec<_>) = path_records
                .iter()
                .copied()
                .partition(|record| rotation_bit_at(record.new_epoch(), depth) == target_bit);
            let sibling = rotation_subtree(depth + 1, &opposite);
            if sibling != empty[usize::from(depth + 1)] {
                siblings.push(SystemAuthorityRotationSibling::new(depth, sibling).unwrap());
            }
            path_records = same;
        }
        assert_eq!(
            occupied,
            path_records.iter().any(|r| r.new_epoch() == target_epoch)
        );
        if occupied {
            SystemAuthorityRotationProof::occupied(target_epoch, siblings).unwrap()
        } else {
            SystemAuthorityRotationProof::vacant(target_epoch, siblings).unwrap()
        }
    }

    fn install_decision_nodes(
        nodes: &mut BTreeMap<SystemAuthorityDecisionNodeId, Vec<u8>>,
        plan: &SystemAuthorityDecisionWritePlan,
    ) {
        for node in plan.nodes() {
            nodes.insert(node.id(), node.encode());
        }
        for retired in plan.retired_node_ids() {
            nodes.remove(retired);
        }
    }

    fn install_rotation_nodes(
        nodes: &mut BTreeMap<SystemAuthorityRotationNodeId, Vec<u8>>,
        plan: &SystemAuthorityRotationWritePlan,
    ) {
        for node in plan.nodes() {
            nodes.insert(node.id(), node.encode());
        }
        for retired in plan.retired_node_ids() {
            nodes.remove(retired);
        }
    }

    fn decision_tree_with_leaf_at(
        key: AgentId,
        leaf: SystemAuthorityDecisionNode,
    ) -> (
        SystemAuthorityDecisionNodeId,
        BTreeMap<SystemAuthorityDecisionNodeId, Vec<u8>>,
    ) {
        let empty = decision_empty_ladder();
        let mut nodes = BTreeMap::new();
        let mut child = leaf.id();
        nodes.insert(child, leaf.encode());
        for depth in (0..DECISION_TREE_DEPTH).rev() {
            let sibling = empty[usize::from(depth + 1)];
            let (left, right) = if bit_at(&key.0, depth) {
                (sibling, child)
            } else {
                (child, sibling)
            };
            let branch = SystemAuthorityDecisionNode::Branch { depth, left, right };
            child = branch.id();
            nodes.insert(child, branch.encode());
        }
        (child, nodes)
    }

    fn rotation_tree_with_leaf_at(
        epoch: u64,
        leaf: SystemAuthorityRotationNode,
    ) -> (
        SystemAuthorityRotationNodeId,
        BTreeMap<SystemAuthorityRotationNodeId, Vec<u8>>,
    ) {
        let empty = rotation_empty_ladder();
        let mut nodes = BTreeMap::new();
        let mut child = leaf.id();
        nodes.insert(child, leaf.encode());
        for depth in (0..ROTATION_TREE_DEPTH).rev() {
            let sibling = empty[usize::from(depth + 1)];
            let (left, right) = if rotation_bit_at(epoch, depth) {
                (sibling, child)
            } else {
                (child, sibling)
            };
            let branch = SystemAuthorityRotationNode::Branch { depth, left, right };
            child = branch.id();
            nodes.insert(child, branch.encode());
        }
        (child, nodes)
    }

    #[test]
    fn decision_finality_rejects_provider_self_trust_and_closes_replay_conflicts() {
        let keys = vec![key(1)];
        let committee = authority_committee(1, None, &keys);
        let genesis = system_genesis(&committee);
        let state = SystemAuthorityState::from_genesis(SYSTEM_AGENT, &genesis).unwrap();
        let scope = journal_scope();
        let fixture = ordinary_fixture(
            AgentProfile::Shared,
            7,
            0x26,
            0x13,
            &committee,
            &keys,
            scope,
        );
        let fact = SystemAuthorityDecisionFact::from_records(&fixture.decision, &fixture.evidence)
            .unwrap();
        assert_eq!(fact.committee(), SystemAuthorityCommitteeId::of(&committee));
        assert_eq!(fact.committee().as_bytes(), &committee.commitment().0);
        let foreign_domain = SystemAuthorityCommitteeId::from_bytes(
            Hash::digest(
                b"not-the-authority-committee-domain",
                &[&committee.encode()],
            )
            .0,
        );
        assert_ne!(foreign_domain, fact.committee());

        let finalize = SystemAuthorityFinalize::new(
            fixture.decision.clone(),
            fixture.evidence.clone(),
            SystemAuthorityDecisionProof::vacant(fact.target_agent(), vec![]).unwrap(),
        )
        .unwrap();
        let admitted = state.apply_finalize(scope, &finalize).unwrap();
        assert_eq!(
            admitted.outcome(),
            SystemAuthorityFinalizeOutcome::Admitted(fixture.decision.id())
        );
        assert_eq!(admitted.admitted_fact(), Some(&fact));
        assert!(admitted.history().inserted());
        assert_eq!(admitted.state().decision_count(), 1);
        verify_provision_fact(&fixture.provision, &fact).unwrap();

        let reopened = SystemAuthorityState::decode(&admitted.state().encode()).unwrap();
        assert_eq!(reopened, *admitted.state());
        reopened
            .validate_against_genesis(SYSTEM_AGENT, &genesis)
            .unwrap();

        let retry = SystemAuthorityFinalize::new(
            fixture.decision.clone(),
            fixture.evidence.clone(),
            SystemAuthorityDecisionProof::occupied(fact.clone(), vec![]).unwrap(),
        )
        .unwrap();
        let retried = reopened.apply_finalize(scope, &retry).unwrap();
        assert_eq!(
            retried.outcome(),
            SystemAuthorityFinalizeOutcome::ExactRetry(fixture.decision.id())
        );
        assert_eq!(retried.admitted_fact(), Some(&fact));
        assert!(!retried.history().inserted());

        let divergent = ordinary_fixture(
            AgentProfile::Shared,
            8,
            0x27,
            0x13,
            &committee,
            &keys,
            scope,
        );
        assert_eq!(
            divergent.proposal.locator().agent,
            fixture.proposal.locator().agent
        );
        assert_ne!(divergent.decision.id(), fixture.decision.id());
        let conflict = SystemAuthorityFinalize::new(
            divergent.decision.clone(),
            divergent.evidence.clone(),
            SystemAuthorityDecisionProof::occupied(fact.clone(), vec![]).unwrap(),
        )
        .unwrap();
        let conflicted = reopened.apply_finalize(scope, &conflict).unwrap();
        assert_eq!(
            conflicted.outcome(),
            SystemAuthorityFinalizeOutcome::TargetConflict(fixture.decision.id())
        );
        assert_eq!(conflicted.admitted_fact(), None);
        assert_eq!(conflicted.state().committee_sequence_high_water(), 8);
        assert_eq!(
            conflicted.state().decisions_root(),
            reopened.decisions_root()
        );
        assert_eq!(
            conflicted.state().apply_finalize(scope, &conflict),
            Err(SystemAuthorityError::SequenceConflict)
        );

        // A decoded provider-selected committee with its own valid QC never
        // replaces the replay-authenticated current committee.
        let provider_keys = vec![key(9)];
        let provider_committee = authority_committee(1, None, &provider_keys);
        let provider = ordinary_fixture(
            AgentProfile::Shared,
            9,
            0x28,
            0x14,
            &provider_committee,
            &provider_keys,
            scope,
        );
        let provider_fact =
            SystemAuthorityDecisionFact::from_records(&provider.decision, &provider.evidence)
                .unwrap();
        let provider_finalize = SystemAuthorityFinalize::new(
            provider.decision,
            provider.evidence,
            SystemAuthorityDecisionProof::vacant(provider_fact.target_agent(), vec![]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            state.apply_finalize(scope, &provider_finalize),
            Err(SystemAuthorityError::StaleCommittee)
        );

        let wrong_owner_state =
            SystemAuthorityState::from_genesis(AgentId([0xab; 32]), &genesis).unwrap();
        assert_eq!(
            wrong_owner_state.apply_finalize(scope, &finalize),
            Err(SystemAuthorityError::WrongSystemAgent)
        );
    }

    #[test]
    fn shared_and_private_provisions_exact_link_to_permanent_facts() {
        let keys = vec![key(1)];
        let committee = authority_committee(1, None, &keys);
        let scope = journal_scope();
        let shared = ordinary_fixture(
            AgentProfile::Shared,
            7,
            0x31,
            0x41,
            &committee,
            &keys,
            scope,
        );
        let private = ordinary_fixture(
            AgentProfile::Private,
            8,
            0x32,
            0x42,
            &committee,
            &keys,
            scope,
        );
        for fixture in [&shared, &private] {
            let fact =
                SystemAuthorityDecisionFact::from_records(&fixture.decision, &fixture.evidence)
                    .unwrap();
            assert_eq!(
                fact.profile(),
                fixture.proposal.config().unwrap().identity.profile
            );
            assert_eq!(fact.proposal(), fixture.proposal.id());
            assert_eq!(fact.replicas(), fixture.replicas.id());
            verify_provision_fact(&fixture.provision, &fact).unwrap();
        }
        let shared_fact =
            SystemAuthorityDecisionFact::from_records(&shared.decision, &shared.evidence).unwrap();
        assert_eq!(
            verify_provision_fact(&private.provision, &shared_fact),
            Err(SystemAuthorityError::InvalidProvision)
        );
    }

    #[test]
    fn rotation_qcs_are_generation_scoped_and_wire_bounded() {
        let old_keys = vec![key(1)];
        let new_keys = vec![key(2)];
        let old = authority_committee(1, None, &old_keys);
        let new = authority_committee(2, Some(old.commitment()), &new_keys);
        let state =
            SystemAuthorityState::from_genesis(SYSTEM_AGENT, &system_genesis(&old)).unwrap();
        let trusted = journal_scope();
        let wrong_genesis = SystemAuthorityJournalScope::new(
            AgentJournalGenesisId::new([0x94; 32]),
            trusted.agent_admission(),
        )
        .unwrap();
        let wrong_admission = SystemAuthorityJournalScope::new(
            trusted.system_genesis(),
            AgentGenesisAdmissionId::from_bytes([0x95; 32]),
        )
        .unwrap();
        for signed_scope in [wrong_genesis, wrong_admission] {
            let command = rotation(
                &state,
                signed_scope,
                &old,
                &old_keys,
                &new,
                &new_keys,
                10,
                12,
                SystemAuthorityRotationProof::vacant(2, vec![]).unwrap(),
            );
            assert_eq!(
                state.apply_rotation(trusted, &command),
                Err(SystemAuthorityError::WrongSystemAgent)
            );
            let foreign_record =
                SystemAuthorityRotationRecord::from_command_shape(&command).unwrap();
            foreign_record.verify_with_committees(&old, &new).unwrap();
            assert_eq!(
                state.verify_historical_rotation(trusted, &foreign_record, &old, &new,),
                Err(SystemAuthorityError::WrongSystemAgent)
            );
        }

        let command = rotation(
            &state,
            trusted,
            &old,
            &old_keys,
            &new,
            &new_keys,
            10,
            12,
            SystemAuthorityRotationProof::vacant(2, vec![]).unwrap(),
        );
        assert_eq!(
            SystemAuthorityRotationClaim::decode(&command.certificate().transition().encode())
                .unwrap(),
            *command.certificate().transition()
        );
        assert_eq!(
            SystemAuthorityRotationCertificate::decode(&command.certificate().encode()).unwrap(),
            *command.certificate()
        );
        assert_eq!(
            SystemAuthorityRotation::decode(&command.encode()).unwrap(),
            command
        );
        assert_eq!(
            command.certificate().transition().encode().len(),
            MAX_SYSTEM_AUTHORITY_ROTATION_CLAIM_BYTES
        );
        assert!(command.encode().len() <= MAX_SYSTEM_AUTHORITY_ROTATION_BYTES);
        assert!(MAX_SYSTEM_AUTHORITY_ROTATION_BYTES + 4096 <= MAX_REPLAY_INPUT_BYTES);
        let same_payload_wrong_domain = Hash::digest(
            FINALIZE_OPERATION_DOMAIN,
            &[
                &command.new_committee().encode(),
                &command.certificate().encode(),
            ],
        );
        assert_ne!(command.operation_commitment(), same_payload_wrong_domain);
    }

    #[test]
    fn rotations_survive_restart_and_exact_retry_after_later_rotations() {
        let key_sets = [vec![key(1)], vec![key(2)], vec![key(3)], vec![key(4)]];
        let c1 = authority_committee(1, None, &key_sets[0]);
        let c2 = authority_committee(2, Some(c1.commitment()), &key_sets[1]);
        let c3 = authority_committee(3, Some(c2.commitment()), &key_sets[2]);
        let c4 = authority_committee(4, Some(c3.commitment()), &key_sets[3]);
        let genesis = system_genesis(&c1);
        let scope = journal_scope();
        let state = SystemAuthorityState::from_genesis(SYSTEM_AGENT, &genesis).unwrap();

        let r1 = rotation(
            &state,
            scope,
            &c1,
            &key_sets[0],
            &c2,
            &key_sets[1],
            10,
            12,
            SystemAuthorityRotationProof::vacant(2, vec![]).unwrap(),
        );
        let t1 = state.apply_rotation(scope, &r1).unwrap();
        let record1 = t1.record().clone();
        assert_eq!(t1.state().rotation_first_sequence(), Some(12));
        assert_eq!(t1.state().rotation_count(), 1);
        assert!(t1.history().inserted());

        let retry1 = SystemAuthorityRotation::new(
            c2.clone(),
            r1.certificate().clone(),
            rotation_proof(2, true, &[&record1]),
        )
        .unwrap();
        assert_eq!(retry1.operation_commitment(), r1.operation_commitment());
        let retried = t1.state().apply_rotation(scope, &retry1).unwrap();
        assert!(retried.exact_retry());
        assert!(!retried.history().inserted());

        // Any first valid incoming-current-committee command may consume F.
        // A joint next rotation at exactly F is therefore live (important
        // when the decision namespace is at capacity), and installs its own
        // incoming-committee first marker.
        let pending_rotation = rotation(
            t1.state(),
            scope,
            &c2,
            &key_sets[1],
            &c3,
            &key_sets[2],
            12,
            14,
            rotation_proof(3, false, &[&record1]),
        );
        t1.state()
            .validate_rotation_claim_for_signing(
                scope,
                pending_rotation.certificate().transition(),
                &c3,
            )
            .unwrap();
        let chained_at_first = t1.state().apply_rotation(scope, &pending_rotation).unwrap();
        assert_eq!(chained_at_first.state().current_committee(), &c3);
        assert_eq!(chained_at_first.state().rotation_first_sequence(), Some(14));
        assert_eq!(chained_at_first.state().committee_sequence_high_water(), 12);

        let wrong_pending_sequence = rotation(
            t1.state(),
            scope,
            &c2,
            &key_sets[1],
            &c3,
            &key_sets[2],
            13,
            15,
            rotation_proof(3, false, &[&record1]),
        );
        assert_eq!(
            t1.state().validate_rotation_claim_for_signing(
                scope,
                wrong_pending_sequence.certificate().transition(),
                &c3,
            ),
            Err(SystemAuthorityError::RotationFirstSequencePending)
        );
        assert_eq!(
            t1.state().apply_rotation(scope, &wrong_pending_sequence),
            Err(SystemAuthorityError::RotationFirstSequencePending)
        );

        let first = ordinary_fixture(
            AgentProfile::Shared,
            12,
            0x51,
            0x61,
            &c2,
            &key_sets[1],
            scope,
        );
        let first_fact =
            SystemAuthorityDecisionFact::from_records(&first.decision, &first.evidence).unwrap();
        let first_finalize = SystemAuthorityFinalize::new(
            first.decision,
            first.evidence,
            SystemAuthorityDecisionProof::vacant(first_fact.target_agent(), vec![]).unwrap(),
        )
        .unwrap();
        let after_first = t1
            .state()
            .apply_finalize(scope, &first_finalize)
            .unwrap()
            .into_state();
        assert_eq!(after_first.rotation_first_sequence(), None);

        let r2 = rotation(
            &after_first,
            scope,
            &c2,
            &key_sets[1],
            &c3,
            &key_sets[2],
            20,
            22,
            rotation_proof(3, false, &[&record1]),
        );
        let t2 = after_first.apply_rotation(scope, &r2).unwrap();
        let record2 = t2.record().clone();
        assert!(!t2.history().retired_node_ids().is_empty());
        assert!(
            t2.history()
                .retired_node_ids()
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );

        // Clear F=22 with a fresh, valid current-committee conflict. Its QC is
        // verified and H is consumed, but it never becomes an admitted fact.
        let conflict = ordinary_fixture(
            AgentProfile::Shared,
            22,
            0x52,
            0x61,
            &c3,
            &key_sets[2],
            scope,
        );
        let conflict_finalize = SystemAuthorityFinalize::new(
            conflict.decision,
            conflict.evidence,
            SystemAuthorityDecisionProof::occupied(first_fact.clone(), vec![]).unwrap(),
        )
        .unwrap();
        let after_conflict = t2
            .state()
            .apply_finalize(scope, &conflict_finalize)
            .unwrap();
        assert_eq!(after_conflict.admitted_fact(), None);
        assert_eq!(after_conflict.state().rotation_first_sequence(), None);

        let r3 = rotation(
            after_conflict.state(),
            scope,
            &c3,
            &key_sets[2],
            &c4,
            &key_sets[3],
            30,
            32,
            rotation_proof(4, false, &[&record1, &record2]),
        );
        let t3 = after_conflict.state().apply_rotation(scope, &r3).unwrap();
        let record3 = t3.record().clone();
        assert_eq!(t3.state().rotation_count(), 3);
        assert_eq!(t3.state().current_committee(), &c4);
        assert_eq!(t3.state().rotation_first_sequence(), Some(32));

        let refreshed_retry = SystemAuthorityRotation::new(
            c2,
            r1.certificate().clone(),
            rotation_proof(2, true, &[&record1, &record2, &record3]),
        )
        .unwrap();
        assert_eq!(
            refreshed_retry.operation_commitment(),
            r1.operation_commitment()
        );
        let late_retry = t3.state().apply_rotation(scope, &refreshed_retry).unwrap();
        assert!(late_retry.exact_retry());
        assert_eq!(late_retry.state(), t3.state());

        let reopened = SystemAuthorityState::decode(&t3.state().encode()).unwrap();
        assert_eq!(reopened, *t3.state());
        reopened
            .validate_against_genesis(SYSTEM_AGENT, &genesis)
            .unwrap();
        assert_eq!(
            reopened.current_committee().epoch(),
            reopened.rotation_count() + 1
        );

        let mut bad_epoch_count = reopened.clone();
        bad_epoch_count.rotation_count -= 1;
        assert_eq!(
            bad_epoch_count.validate(),
            Err(SystemAuthorityError::InvalidState)
        );
        let mut impossible_prebind =
            SystemAuthorityState::from_genesis(SYSTEM_AGENT, &genesis).unwrap();
        impossible_prebind.journal_scope = Some(scope);
        assert_eq!(
            impossible_prebind.validate(),
            Err(SystemAuthorityError::InvalidState)
        );
    }

    #[test]
    fn signed_capacity_limits_reject_fresh_inserts_but_preserve_exact_retries() {
        let keys = vec![key(1)];
        let committee = authority_committee(1, None, &keys);
        let scope = journal_scope();
        assert_eq!(
            SystemAuthorityGenesis::new(ROOT_ANCHOR, 1, ROOT_CONFIG, committee.clone(), 1, 0, 1,),
            Err(SystemAuthorityError::InvalidGenesis)
        );
        let decision_genesis =
            SystemAuthorityGenesis::new(ROOT_ANCHOR, 1, ROOT_CONFIG, committee.clone(), 1, 1, 1)
                .unwrap();
        let decision_state =
            SystemAuthorityState::from_genesis(SYSTEM_AGENT, &decision_genesis).unwrap();
        let first = ordinary_fixture(
            AgentProfile::Shared,
            7,
            0x81,
            0x82,
            &committee,
            &keys,
            scope,
        );
        let first_fact =
            SystemAuthorityDecisionFact::from_records(&first.decision, &first.evidence).unwrap();
        let first_finalize = SystemAuthorityFinalize::new(
            first.decision.clone(),
            first.evidence.clone(),
            SystemAuthorityDecisionProof::vacant(first_fact.target_agent(), vec![]).unwrap(),
        )
        .unwrap();
        let first_transition = decision_state
            .apply_finalize(scope, &first_finalize)
            .unwrap();
        let mut decision_nodes = BTreeMap::new();
        install_decision_nodes(&mut decision_nodes, first_transition.history());
        let retry_proof = prove_decision(
            first_transition.state().decisions_root(),
            first_fact.target_agent(),
            |id| Ok::<_, ()>(decision_nodes.get(&id).cloned()),
        )
        .unwrap();
        let retry = SystemAuthorityFinalize::new(
            first.decision.clone(),
            first.evidence.clone(),
            retry_proof,
        )
        .unwrap();
        assert_eq!(
            first_transition
                .state()
                .apply_finalize(scope, &retry)
                .unwrap()
                .outcome(),
            SystemAuthorityFinalizeOutcome::ExactRetry(first.decision.id())
        );
        first_transition
            .state()
            .verify_historical_provision(scope, &first.provision, &first_fact, &committee)
            .unwrap();
        let foreign_scope = SystemAuthorityJournalScope::new(
            AgentJournalGenesisId::new([0xa1; 32]),
            scope.agent_admission(),
        )
        .unwrap();
        assert_eq!(
            first_transition.state().verify_historical_provision(
                foreign_scope,
                &first.provision,
                &first_fact,
                &committee,
            ),
            Err(SystemAuthorityError::WrongSystemAgent)
        );

        let second = ordinary_fixture(
            AgentProfile::Shared,
            8,
            0x83,
            0x84,
            &committee,
            &keys,
            scope,
        );
        let second_fact =
            SystemAuthorityDecisionFact::from_records(&second.decision, &second.evidence).unwrap();
        let second_proof = prove_decision(
            first_transition.state().decisions_root(),
            second_fact.target_agent(),
            |id| Ok::<_, ()>(decision_nodes.get(&id).cloned()),
        )
        .unwrap();
        assert_eq!(
            first_transition
                .state()
                .validate_agent_genesis_claim_for_signing(
                    scope,
                    second.evidence.claim(),
                    &second_proof,
                ),
            Err(SystemAuthorityError::Capacity)
        );
        let second_finalize =
            SystemAuthorityFinalize::new(second.decision, second.evidence, second_proof).unwrap();
        assert_eq!(
            first_transition
                .state()
                .apply_finalize(scope, &second_finalize),
            Err(SystemAuthorityError::Capacity)
        );
        let conflict = ordinary_fixture(
            AgentProfile::Shared,
            8,
            0x87,
            0x82,
            &committee,
            &keys,
            scope,
        );
        assert_eq!(conflict.proposal.locator().agent, first_fact.target_agent());
        let conflict_proof = prove_decision(
            first_transition.state().decisions_root(),
            first_fact.target_agent(),
            |id| Ok::<_, ()>(decision_nodes.get(&id).cloned()),
        )
        .unwrap();
        first_transition
            .state()
            .validate_agent_genesis_claim_for_signing(
                scope,
                conflict.evidence.claim(),
                &conflict_proof,
            )
            .unwrap();
        let conflict_finalize =
            SystemAuthorityFinalize::new(conflict.decision, conflict.evidence, conflict_proof)
                .unwrap();
        assert!(matches!(
            first_transition
                .state()
                .apply_finalize(scope, &conflict_finalize)
                .unwrap()
                .outcome(),
            SystemAuthorityFinalizeOutcome::TargetConflict(_)
        ));
        let different_limits =
            SystemAuthorityGenesis::new(ROOT_ANCHOR, 1, ROOT_CONFIG, committee.clone(), 1, 2, 1)
                .unwrap();
        assert_eq!(
            first_transition
                .state()
                .validate_against_genesis(SYSTEM_AGENT, &different_limits),
            Err(SystemAuthorityError::InvalidState)
        );

        let rotation_genesis =
            SystemAuthorityGenesis::new(ROOT_ANCHOR, 1, ROOT_CONFIG, committee.clone(), 1, 2, 1)
                .unwrap();
        let rotation_state =
            SystemAuthorityState::from_genesis(SYSTEM_AGENT, &rotation_genesis).unwrap();
        let second_keys = vec![key(2)];
        let second_committee = authority_committee(2, Some(committee.commitment()), &second_keys);
        let first_rotation = rotation(
            &rotation_state,
            scope,
            &committee,
            &keys,
            &second_committee,
            &second_keys,
            10,
            12,
            SystemAuthorityRotationProof::vacant(2, vec![]).unwrap(),
        );
        let first_rotation_transition = rotation_state
            .apply_rotation(scope, &first_rotation)
            .unwrap();
        let mut rotation_nodes = BTreeMap::new();
        install_rotation_nodes(&mut rotation_nodes, first_rotation_transition.history());
        let rotation_retry_path = prove_rotation(
            first_rotation_transition.state().rotations_root(),
            2,
            |id| Ok::<_, ()>(rotation_nodes.get(&id).cloned()),
        )
        .unwrap();
        let rotation_retry = SystemAuthorityRotation::new(
            second_committee.clone(),
            first_rotation.certificate().clone(),
            rotation_retry_path.proof().clone(),
        )
        .unwrap();
        assert!(
            first_rotation_transition
                .state()
                .apply_rotation(scope, &rotation_retry)
                .unwrap()
                .exact_retry()
        );

        let clear = ordinary_fixture(
            AgentProfile::Shared,
            12,
            0x85,
            0x86,
            &second_committee,
            &second_keys,
            scope,
        );
        let clear_fact =
            SystemAuthorityDecisionFact::from_records(&clear.decision, &clear.evidence).unwrap();
        let clear_finalize = SystemAuthorityFinalize::new(
            clear.decision,
            clear.evidence,
            SystemAuthorityDecisionProof::vacant(clear_fact.target_agent(), vec![]).unwrap(),
        )
        .unwrap();
        let after_clear = first_rotation_transition
            .state()
            .apply_finalize(scope, &clear_finalize)
            .unwrap()
            .into_state();
        let third_keys = vec![key(3)];
        let third_committee =
            authority_committee(3, Some(second_committee.commitment()), &third_keys);
        let fresh_path = prove_rotation(after_clear.rotations_root(), 3, |id| {
            Ok::<_, ()>(rotation_nodes.get(&id).cloned())
        })
        .unwrap();
        let fresh_rotation = rotation(
            &after_clear,
            scope,
            &second_committee,
            &second_keys,
            &third_committee,
            &third_keys,
            20,
            22,
            fresh_path.proof().clone(),
        );
        assert_eq!(
            after_clear.validate_rotation_claim_for_signing(
                scope,
                fresh_rotation.certificate().transition(),
                &third_committee,
            ),
            Err(SystemAuthorityError::Capacity)
        );
        assert_eq!(
            after_clear.apply_rotation(scope, &fresh_rotation),
            Err(SystemAuthorityError::Capacity)
        );
    }

    #[test]
    fn primitive_owned_proof_builders_and_tree_audits_fail_closed() {
        let keys = vec![key(1)];
        let committee = authority_committee(1, None, &keys);
        let genesis = system_genesis(&committee);
        let scope = journal_scope();
        let state = SystemAuthorityState::from_genesis(SYSTEM_AGENT, &genesis).unwrap();
        let target = AgentId([0x71; 32]);

        let mut empty_loads = 0;
        let empty_proof = prove_decision::<()>(empty_decision_root(), target, |_| {
            empty_loads += 1;
            Ok(None)
        })
        .unwrap();
        assert_eq!(empty_loads, 0);
        assert!(empty_proof.occupied_fact().is_none());
        empty_proof.verifies(empty_decision_root()).unwrap();

        let fixture = ordinary_fixture(
            AgentProfile::Shared,
            7,
            0x72,
            0x73,
            &committee,
            &keys,
            scope,
        );
        let fact = SystemAuthorityDecisionFact::from_records(&fixture.decision, &fixture.evidence)
            .unwrap();
        let finalize = SystemAuthorityFinalize::new(
            fixture.decision,
            fixture.evidence,
            SystemAuthorityDecisionProof::vacant(fact.target_agent(), vec![]).unwrap(),
        )
        .unwrap();
        state
            .validate_agent_genesis_claim_for_signing(
                scope,
                finalize.evidence().claim(),
                finalize.proof(),
            )
            .unwrap();
        let transition = state.apply_finalize(scope, &finalize).unwrap();
        let mut decision_nodes = BTreeMap::new();
        install_decision_nodes(&mut decision_nodes, transition.history());

        let occupied = prove_decision(
            transition.state().decisions_root(),
            fact.target_agent(),
            |id| Ok::<_, ()>(decision_nodes.get(&id).cloned()),
        )
        .unwrap();
        assert_eq!(occupied.occupied_fact(), Some(&fact));
        occupied
            .verifies(transition.state().decisions_root())
            .unwrap();
        let vacant_target = AgentId([0x74; 32]);
        let vacant = prove_decision(transition.state().decisions_root(), vacant_target, |id| {
            Ok::<_, ()>(decision_nodes.get(&id).cloned())
        })
        .unwrap();
        assert!(vacant.occupied_fact().is_none());
        vacant
            .verifies(transition.state().decisions_root())
            .unwrap();

        let mut decision_cursor = begin_decision_tree_audit(
            transition.state().decisions_root(),
            transition.state().decision_count(),
        )
        .unwrap();
        assert_eq!(
            audit_decision_tree_batch(
                &mut decision_cursor,
                0,
                |id| Ok::<_, ()>(decision_nodes.get(&id).cloned()),
                |_, _| Ok(()),
            ),
            Err(SystemAuthorityTreeError::Limit)
        );
        let mut visited_decision_ids = Vec::new();
        let mut visited_facts = Vec::new();
        let first_batch = audit_decision_tree_batch(
            &mut decision_cursor,
            1,
            |id| Ok::<_, ()>(decision_nodes.get(&id).cloned()),
            |id, node| {
                visited_decision_ids.push(id);
                if let SystemAuthorityDecisionNode::Leaf(visited) = node {
                    visited_facts.push(visited.clone());
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(first_batch, SystemAuthorityAuditProgress::More);
        assert_eq!(decision_cursor.node_count(), 1);
        loop {
            let progress = audit_decision_tree_batch(
                &mut decision_cursor,
                17,
                |id| Ok::<_, ()>(decision_nodes.get(&id).cloned()),
                |id, node| {
                    visited_decision_ids.push(id);
                    if let SystemAuthorityDecisionNode::Leaf(visited) = node {
                        visited_facts.push(visited.clone());
                    }
                    Ok(())
                },
            )
            .unwrap();
            if let SystemAuthorityAuditProgress::Complete {
                node_count,
                leaf_count,
            } = progress
            {
                assert_eq!(node_count, u64::from(DECISION_TREE_DEPTH) + 1);
                assert_eq!(leaf_count, 1);
                break;
            }
        }
        assert_eq!(decision_cursor.leaf_count(), 1);
        assert_eq!(visited_facts, vec![fact.clone()]);
        assert_eq!(
            visited_decision_ids.len(),
            usize::from(DECISION_TREE_DEPTH) + 1
        );

        let mut visitor_failure = begin_decision_tree_audit(
            transition.state().decisions_root(),
            transition.state().decision_count(),
        )
        .unwrap();
        assert_eq!(
            audit_decision_tree_batch(
                &mut visitor_failure,
                1,
                |id| Ok::<_, u8>(decision_nodes.get(&id).cloned()),
                |_, _| Err(7_u8),
            ),
            Err(SystemAuthorityTreeError::Visit(7))
        );
        let mut retried_after_visit = Vec::new();
        assert_eq!(
            audit_decision_tree_batch(
                &mut visitor_failure,
                1,
                |id| Ok::<_, u8>(decision_nodes.get(&id).cloned()),
                |id, _| {
                    retried_after_visit.push(id);
                    Ok(())
                },
            )
            .unwrap(),
            SystemAuthorityAuditProgress::More
        );
        assert_eq!(
            retried_after_visit,
            vec![transition.state().decisions_root()]
        );
        assert_eq!(visitor_failure.node_count(), 1);
        let mut missing_audit = begin_decision_tree_audit(
            transition.state().decisions_root(),
            transition.state().decision_count(),
        )
        .unwrap();
        assert_eq!(
            audit_decision_tree_batch(&mut missing_audit, 1, |_| Ok::<_, ()>(None), |_, _| Ok(()),),
            Err(SystemAuthorityTreeError::Missing(
                SystemAuthorityTreeNodeId::Decision(transition.state().decisions_root())
            ))
        );
        let mut retried_after_load = Vec::new();
        assert_eq!(
            audit_decision_tree_batch(
                &mut missing_audit,
                1,
                |id| Ok::<_, ()>(decision_nodes.get(&id).cloned()),
                |id, _| {
                    retried_after_load.push(id);
                    Ok(())
                },
            )
            .unwrap(),
            SystemAuthorityAuditProgress::More
        );
        assert_eq!(
            retried_after_load,
            vec![transition.state().decisions_root()]
        );
        let mut wrong_count =
            begin_decision_tree_audit(transition.state().decisions_root(), 2).unwrap();
        assert_eq!(
            audit_decision_tree_batch(
                &mut wrong_count,
                MAX_SYSTEM_AUTHORITY_DECISION_TREE_NODES,
                |id| Ok::<_, ()>(decision_nodes.get(&id).cloned()),
                |_, _| Ok(()),
            ),
            Err(SystemAuthorityTreeError::Corrupt(
                SystemAuthorityTreeNodeId::Decision(transition.state().decisions_root())
            ))
        );

        let decision_root = transition.state().decisions_root();
        assert_eq!(
            prove_decision(decision_root, fact.target_agent(), |_| Ok::<_, ()>(None)),
            Err(SystemAuthorityTreeError::Missing(
                SystemAuthorityTreeNodeId::Decision(decision_root)
            ))
        );
        let leaf_bytes = SystemAuthorityDecisionNode::Leaf(fact.clone()).encode();
        assert_eq!(
            prove_decision(decision_root, fact.target_agent(), |_| {
                Ok::<_, ()>(Some(leaf_bytes.clone()))
            }),
            Err(SystemAuthorityTreeError::Corrupt(
                SystemAuthorityTreeNodeId::Decision(decision_root)
            ))
        );
        let wrong_depth = SystemAuthorityDecisionNode::Branch {
            depth: 1,
            left: empty_decision_node(2),
            right: fact.id(),
        };
        let wrong_depth_id = wrong_depth.id();
        assert_eq!(
            prove_decision(wrong_depth_id, fact.target_agent(), |id| {
                Ok::<_, ()>((id == wrong_depth_id).then(|| wrong_depth.encode()))
            }),
            Err(SystemAuthorityTreeError::Corrupt(
                SystemAuthorityTreeNodeId::Decision(wrong_depth_id)
            ))
        );
        let mut wrong_depth_cursor = begin_decision_tree_audit(wrong_depth_id, 1).unwrap();
        assert!(matches!(
            audit_decision_tree_batch(
                &mut wrong_depth_cursor,
                1,
                |id| Ok::<_, ()>((id == wrong_depth_id).then(|| wrong_depth.encode())),
                |_, _| Ok(()),
            ),
            Err(SystemAuthorityTreeError::Corrupt(
                SystemAuthorityTreeNodeId::Decision(_)
            ))
        ));
        let (wrong_key_root, wrong_key_nodes) = decision_tree_with_leaf_at(
            vacant_target,
            SystemAuthorityDecisionNode::Leaf(fact.clone()),
        );
        assert!(matches!(
            prove_decision(wrong_key_root, vacant_target, |id| {
                Ok::<_, ()>(wrong_key_nodes.get(&id).cloned())
            }),
            Err(SystemAuthorityTreeError::Corrupt(
                SystemAuthorityTreeNodeId::Decision(_)
            ))
        ));
        let duplicate_child = SystemAuthorityDecisionNode::Branch {
            depth: 0,
            left: fact.id(),
            right: fact.id(),
        };
        let duplicate_child_id = duplicate_child.id();
        assert_eq!(
            prove_decision(duplicate_child_id, fact.target_agent(), |id| {
                Ok::<_, ()>((id == duplicate_child_id).then(|| duplicate_child.encode()))
            }),
            Err(SystemAuthorityTreeError::Corrupt(
                SystemAuthorityTreeNodeId::Decision(duplicate_child_id)
            ))
        );

        let new_keys = vec![key(2)];
        let new_committee = authority_committee(2, Some(committee.commitment()), &new_keys);
        let rotation_command = rotation(
            &state,
            scope,
            &committee,
            &keys,
            &new_committee,
            &new_keys,
            10,
            12,
            SystemAuthorityRotationProof::vacant(2, vec![]).unwrap(),
        );
        state
            .validate_rotation_claim_for_signing(
                scope,
                rotation_command.certificate().transition(),
                &new_committee,
            )
            .unwrap();
        let rotation_transition = state.apply_rotation(scope, &rotation_command).unwrap();
        let record = rotation_transition.record().clone();
        let mut rotation_nodes = BTreeMap::new();
        install_rotation_nodes(&mut rotation_nodes, rotation_transition.history());

        let mut empty_rotation_loads = 0;
        let empty_rotation = prove_rotation::<()>(empty_rotation_root(), 2, |_| {
            empty_rotation_loads += 1;
            Ok(None)
        })
        .unwrap();
        assert_eq!(empty_rotation_loads, 0);
        assert!(empty_rotation.occupied_record().is_none());

        let occupied_rotation =
            prove_rotation(rotation_transition.state().rotations_root(), 2, |id| {
                Ok::<_, ()>(rotation_nodes.get(&id).cloned())
            })
            .unwrap();
        assert_eq!(occupied_rotation.occupied_record(), Some(&record));
        occupied_rotation
            .proof()
            .verifies(rotation_transition.state().rotations_root(), &record)
            .unwrap();
        let vacant_rotation =
            prove_rotation(rotation_transition.state().rotations_root(), 3, |id| {
                Ok::<_, ()>(rotation_nodes.get(&id).cloned())
            })
            .unwrap();
        assert!(vacant_rotation.occupied_record().is_none());

        let mut rotation_cursor = begin_rotation_tree_audit(
            rotation_transition.state().rotations_root(),
            1,
            SystemAuthorityCommitteeId::of(&committee),
            SystemAuthorityCommitteeId::of(&new_committee),
        )
        .unwrap();
        let mut visited_rotation_ids = Vec::new();
        let mut visited_records = Vec::new();
        assert_eq!(
            audit_rotation_tree_batch(
                &mut rotation_cursor,
                0,
                |id| Ok::<_, ()>(rotation_nodes.get(&id).cloned()),
                |_, _| Ok(()),
            ),
            Err(SystemAuthorityTreeError::Limit)
        );
        loop {
            let progress = audit_rotation_tree_batch(
                &mut rotation_cursor,
                7,
                |id| Ok::<_, ()>(rotation_nodes.get(&id).cloned()),
                |id, node| {
                    visited_rotation_ids.push(id);
                    if let SystemAuthorityRotationNode::Leaf(visited) = node {
                        visited_records.push(visited.clone());
                    }
                    Ok(())
                },
            )
            .unwrap();
            if let SystemAuthorityAuditProgress::Complete {
                node_count,
                leaf_count,
            } = progress
            {
                assert_eq!(node_count, u64::from(ROTATION_TREE_DEPTH) + 1);
                assert_eq!(leaf_count, 1);
                break;
            }
        }
        assert_eq!(rotation_cursor.leaf_count(), 1);
        assert_eq!(visited_records, vec![record.clone()]);
        assert_eq!(
            visited_rotation_ids.len(),
            usize::from(ROTATION_TREE_DEPTH) + 1
        );
        record
            .verify_with_committees(&committee, &new_committee)
            .unwrap();

        let foreign_keys = vec![key(3)];
        let foreign_committee = authority_committee(1, None, &foreign_keys);
        let mut broken_chain = begin_rotation_tree_audit(
            rotation_transition.state().rotations_root(),
            1,
            SystemAuthorityCommitteeId::of(&foreign_committee),
            SystemAuthorityCommitteeId::of(&new_committee),
        )
        .unwrap();
        assert!(matches!(
            audit_rotation_tree_batch(
                &mut broken_chain,
                MAX_SYSTEM_AUTHORITY_ROTATION_TREE_NODES,
                |id| Ok::<_, ()>(rotation_nodes.get(&id).cloned()),
                |_, _| Ok(()),
            ),
            Err(SystemAuthorityTreeError::Corrupt(
                SystemAuthorityTreeNodeId::Rotation(_)
            ))
        ));

        let rotation_root = rotation_transition.state().rotations_root();
        assert_eq!(
            prove_rotation(rotation_root, 2, |_| Ok::<_, ()>(None)),
            Err(SystemAuthorityTreeError::Missing(
                SystemAuthorityTreeNodeId::Rotation(rotation_root)
            ))
        );
        let rotation_leaf_bytes = SystemAuthorityRotationNode::Leaf(record.clone()).encode();
        assert_eq!(
            prove_rotation(rotation_root, 2, |_| {
                Ok::<_, ()>(Some(rotation_leaf_bytes.clone()))
            }),
            Err(SystemAuthorityTreeError::Corrupt(
                SystemAuthorityTreeNodeId::Rotation(rotation_root)
            ))
        );
        let wrong_rotation_depth = SystemAuthorityRotationNode::Branch {
            depth: 1,
            left: empty_rotation_node(2),
            right: record.leaf_id(),
        };
        let wrong_rotation_depth_id = wrong_rotation_depth.id();
        assert_eq!(
            prove_rotation(wrong_rotation_depth_id, 2, |id| {
                Ok::<_, ()>((id == wrong_rotation_depth_id).then(|| wrong_rotation_depth.encode()))
            }),
            Err(SystemAuthorityTreeError::Corrupt(
                SystemAuthorityTreeNodeId::Rotation(wrong_rotation_depth_id)
            ))
        );
        let (wrong_epoch_root, wrong_epoch_nodes) =
            rotation_tree_with_leaf_at(3, SystemAuthorityRotationNode::Leaf(record.clone()));
        assert!(matches!(
            prove_rotation(wrong_epoch_root, 3, |id| {
                Ok::<_, ()>(wrong_epoch_nodes.get(&id).cloned())
            }),
            Err(SystemAuthorityTreeError::Corrupt(
                SystemAuthorityTreeNodeId::Rotation(_)
            ))
        ));
        let duplicate_rotation_child = SystemAuthorityRotationNode::Branch {
            depth: 0,
            left: record.leaf_id(),
            right: record.leaf_id(),
        };
        let duplicate_rotation_child_id = duplicate_rotation_child.id();
        assert_eq!(
            prove_rotation(duplicate_rotation_child_id, 2, |id| {
                Ok::<_, ()>(
                    (id == duplicate_rotation_child_id).then(|| duplicate_rotation_child.encode()),
                )
            }),
            Err(SystemAuthorityTreeError::Corrupt(
                SystemAuthorityTreeNodeId::Rotation(duplicate_rotation_child_id)
            ))
        );

        // A resumed scrub walks a multi-rotation tree in ascending epoch and
        // can reverify each record against independently loaded committees.
        let first_after_rotation = ordinary_fixture(
            AgentProfile::Shared,
            12,
            0x75,
            0x76,
            &new_committee,
            &new_keys,
            scope,
        );
        let first_fact = SystemAuthorityDecisionFact::from_records(
            &first_after_rotation.decision,
            &first_after_rotation.evidence,
        )
        .unwrap();
        let clear_first = SystemAuthorityFinalize::new(
            first_after_rotation.decision,
            first_after_rotation.evidence,
            SystemAuthorityDecisionProof::vacant(first_fact.target_agent(), vec![]).unwrap(),
        )
        .unwrap();
        let after_first = rotation_transition
            .state()
            .apply_finalize(scope, &clear_first)
            .unwrap()
            .into_state();
        let third_keys = vec![key(4)];
        let third_committee = authority_committee(3, Some(new_committee.commitment()), &third_keys);
        let second_path = prove_rotation(after_first.rotations_root(), 3, |id| {
            Ok::<_, ()>(rotation_nodes.get(&id).cloned())
        })
        .unwrap();
        let second_rotation = rotation(
            &after_first,
            scope,
            &new_committee,
            &new_keys,
            &third_committee,
            &third_keys,
            20,
            22,
            second_path.proof().clone(),
        );
        let second_transition = after_first.apply_rotation(scope, &second_rotation).unwrap();
        let second_record = second_transition.record().clone();
        install_rotation_nodes(&mut rotation_nodes, second_transition.history());
        let mut full_cursor = begin_rotation_tree_audit(
            second_transition.state().rotations_root(),
            2,
            SystemAuthorityCommitteeId::of(&committee),
            SystemAuthorityCommitteeId::of(&third_committee),
        )
        .unwrap();
        let mut full_records = Vec::new();
        loop {
            let progress = audit_rotation_tree_batch(
                &mut full_cursor,
                5,
                |id| Ok::<_, SystemAuthorityError>(rotation_nodes.get(&id).cloned()),
                |_, node| {
                    if let SystemAuthorityRotationNode::Leaf(visited) = node {
                        match visited.new_epoch() {
                            2 => second_transition.state().verify_historical_rotation(
                                scope,
                                visited,
                                &committee,
                                &new_committee,
                            )?,
                            3 => second_transition.state().verify_historical_rotation(
                                scope,
                                visited,
                                &new_committee,
                                &third_committee,
                            )?,
                            _ => return Err(SystemAuthorityError::InvalidRotationNode),
                        }
                        full_records.push(visited.clone());
                    }
                    Ok(())
                },
            )
            .unwrap();
            if matches!(progress, SystemAuthorityAuditProgress::Complete { .. }) {
                break;
            }
        }
        assert_eq!(full_records, vec![record, second_record]);
    }

    #[test]
    fn exact_wire_bounds_and_max_depth_proofs_are_canonical() {
        let keys = vec![key(1)];
        let committee = authority_committee(1, None, &keys);
        let genesis = system_genesis(&committee);
        let state = SystemAuthorityState::from_genesis(SYSTEM_AGENT, &genesis).unwrap();
        assert_eq!(
            MAX_SYSTEM_AUTHORITY_STATE_BYTES,
            380 + MAX_AUTHORITY_COMMITTEE_WIRE_BYTES
        );
        assert_eq!(
            MAX_SYSTEM_AUTHORITY_GENESIS_BYTES,
            128 + MAX_AUTHORITY_COMMITTEE_WIRE_BYTES
        );
        assert_eq!(
            MAX_SYSTEM_AUTHORITY_COMMITTEE_RECORD_BYTES,
            40 + MAX_AUTHORITY_COMMITTEE_WIRE_BYTES
        );
        assert_eq!(
            SystemAuthorityGenesis::decode(&genesis.encode()).unwrap(),
            genesis
        );
        assert!(genesis.encode().len() <= MAX_SYSTEM_AUTHORITY_GENESIS_BYTES);
        assert!(state.encode().len() <= MAX_SYSTEM_AUTHORITY_STATE_BYTES);
        assert_eq!(state.decision_limit(), 64);
        assert_eq!(state.rotation_limit(), 16);
        let committee_record = SystemAuthorityCommitteeRecord::new(committee.clone()).unwrap();
        assert!(committee_record.encode().len() <= MAX_SYSTEM_AUTHORITY_COMMITTEE_RECORD_BYTES);
        assert_eq!(
            SystemAuthorityCommitteeRecord::decode(&committee_record.encode()).unwrap(),
            committee_record
        );

        let scope = journal_scope();
        let fixture = ordinary_fixture(
            AgentProfile::Shared,
            7,
            0x66,
            0x67,
            &committee,
            &keys,
            scope,
        );
        let fact = SystemAuthorityDecisionFact::from_records(&fixture.decision, &fixture.evidence)
            .unwrap();
        assert_eq!(
            fact.encode().len(),
            MAX_SYSTEM_AUTHORITY_DECISION_FACT_BYTES
        );
        let leaf = SystemAuthorityDecisionNode::Leaf(fact);
        assert_eq!(
            leaf.encode().len(),
            MAX_SYSTEM_AUTHORITY_DECISION_NODE_BYTES
        );
        assert_eq!(
            SystemAuthorityDecisionNode::decode(&leaf.encode()).unwrap(),
            leaf
        );

        let decision_siblings = (0..DECISION_TREE_DEPTH)
            .map(|depth| {
                let id = SystemAuthorityDecisionNodeId::from_bytes(
                    Hash::digest(b"decision-proof-work", &[&depth.to_le_bytes()]).0,
                );
                SystemAuthorityDecisionSibling::new(depth, id).unwrap()
            })
            .collect();
        let decision_proof =
            SystemAuthorityDecisionProof::vacant(AgentId([0xee; 32]), decision_siblings).unwrap();
        assert_eq!(
            SystemAuthorityDecisionProof::decode(&decision_proof.encode()).unwrap(),
            decision_proof
        );

        let rotation_siblings = (0..ROTATION_TREE_DEPTH)
            .map(|depth| {
                let id = SystemAuthorityRotationNodeId::from_bytes(
                    Hash::digest(b"rotation-proof-work", &[&depth.to_le_bytes()]).0,
                );
                SystemAuthorityRotationSibling::new(depth, id).unwrap()
            })
            .collect();
        let rotation_proof = SystemAuthorityRotationProof::vacant(2, rotation_siblings).unwrap();
        assert_eq!(
            rotation_proof.encode().len(),
            MAX_SYSTEM_AUTHORITY_ROTATION_PROOF_BYTES
        );
        assert_eq!(
            SystemAuthorityRotationProof::decode(&rotation_proof.encode()).unwrap(),
            rotation_proof
        );
    }
}
