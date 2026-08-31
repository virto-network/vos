//! Crash-safe authority pledge, share, and quorum-certificate ledger.
//!
//! Authority QCs are not safe to issue from provider bytes or a decoded
//! [`SystemAuthorityState`] alone. Replay first re-authenticates the root
//! system Agent's Control state and its exact journal generation, then mints
//! an opaque [`ReplayedSystemAuthorityView`]. The storage adapter durably
//! reserves one claim for that view before it can commit a local sign-once
//! pledge. Only after the pledge transaction commits is an external authority
//! signer invoked.
//!
//! Pledges are keyed by `(authority scope, local signer, committee-global H)`
//! rather than by claim domain or committee epoch. An AgentGenesis claim and
//! a committee rotation at the same sequence therefore cannot both be signed.
//! Rotation shares and QCs are still separated into retiring and incoming
//! committee legs, and both frozen threshold QCs are required for the joint
//! certificate. This module never performs a journal CAS and exposes no public
//! authority capability.

use alloc::vec::Vec;
use core::fmt;

use super::committee::{
    AuthorityClaimCommitment, AuthorityClaimDomain, AuthorityCommittee, AuthorityCommitteeError,
    MAX_AUTHORITY_COMMITTEE_WIRE_BYTES,
};
use super::genesis::{
    AgentGenesisAdmissionId, AgentGenesisClaim, AgentGenesisProposal, AgentReplicaCommittee,
    MAX_AGENT_GENESIS_CLAIM_BYTES, MAX_AGENT_GENESIS_PROPOSAL_BYTES,
    MAX_AGENT_REPLICA_COMMITTEE_BYTES,
};
use super::journal::{AgentJournalGenesisId, JournalHeadsId, LaneStateId};
use super::shared_raft::JournalStoreInstanceId;
use super::system_authority::{
    MAX_SYSTEM_AUTHORITY_DECISION_PROOF_BYTES, MAX_SYSTEM_AUTHORITY_ROTATION_CLAIM_BYTES,
    SystemAuthorityDecisionProof, SystemAuthorityJournalScope, SystemAuthorityRotationClaim,
    SystemAuthorityScopeCommitment, SystemAuthorityState,
};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{AgentId, Hash, SpaceId};

const SERVICE_WIRE_HEADER_BYTES: usize = 4 + 32;
const AUTHORITY_LEDGER_ROUTE_ID_DOMAIN: &[u8] = b"vos/agent/system-authority-ledger/route/v1";
const AUTHORITY_LEDGER_VIEW_DOMAIN: &[u8] = b"vos/agent/system-authority-ledger/view/v1";
const AUTHORITY_LEDGER_STATE_DOMAIN: &[u8] = b"vos/agent/system-authority-ledger/state/v1";

/// Maximum complete generation-bound authority-ledger route.
pub(crate) const MAX_SYSTEM_AUTHORITY_LEDGER_ROUTE_BYTES: usize = 512;
/// Maximum one reserved authority claim, including two complete committees
/// for a generation-scoped rotation.
pub(crate) const MAX_SYSTEM_AUTHORITY_LEDGER_CLAIM_BYTES: usize = SERVICE_WIRE_HEADER_BYTES
    + 1
    + 2 * (4 + MAX_AUTHORITY_COMMITTEE_WIRE_BYTES)
    + 4
    + MAX_SYSTEM_AUTHORITY_ROTATION_CLAIM_BYTES
    + 4
    + MAX_AGENT_GENESIS_CLAIM_BYTES
    + 4
    + MAX_AGENT_GENESIS_PROPOSAL_BYTES
    + 4
    + MAX_AGENT_REPLICA_COMMITTEE_BYTES
    + 4
    + MAX_SYSTEM_AUTHORITY_DECISION_PROOF_BYTES;

/// Canonical route of the one live system-authority journal generation.
///
/// The scope commitment is recomputed from the explicit root anchor, journal
/// genesis, and outer Agent admission. Repeating all deployment pins keeps a
/// database row independently auditable instead of allowing its table key to
/// supply ambient identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SystemAuthorityLedgerRoute {
    root_anchor: super::committee::RootAnchorId,
    root_anchor_config_version: u64,
    root_anchor_config: super::committee::RootAnchorConfigCommitment,
    space: SpaceId,
    system_agent: AgentId,
    authority_binding: Hash,
    system_genesis: AgentJournalGenesisId,
    agent_admission: AgentGenesisAdmissionId,
    authority_scope: SystemAuthorityScopeCommitment,
}

impl SystemAuthorityLedgerRoute {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        root_anchor: super::committee::RootAnchorId,
        root_anchor_config_version: u64,
        root_anchor_config: super::committee::RootAnchorConfigCommitment,
        space: SpaceId,
        system_agent: AgentId,
        authority_binding: Hash,
        system_genesis: AgentJournalGenesisId,
        agent_admission: AgentGenesisAdmissionId,
    ) -> Result<Self, SystemAuthorityLedgerWireError> {
        let authority_scope = SystemAuthorityScopeCommitment::for_journal(
            root_anchor,
            system_genesis,
            agent_admission,
        )
        .map_err(|_| SystemAuthorityLedgerWireError::InvalidRoute)?;
        let route = Self {
            root_anchor,
            root_anchor_config_version,
            root_anchor_config,
            space,
            system_agent,
            authority_binding,
            system_genesis,
            agent_admission,
            authority_scope,
        };
        route.validate()?;
        Ok(route)
    }

    pub(crate) const fn root_anchor(self) -> super::committee::RootAnchorId {
        self.root_anchor
    }

    pub(crate) const fn root_anchor_config_version(self) -> u64 {
        self.root_anchor_config_version
    }

    pub(crate) const fn root_anchor_config(self) -> super::committee::RootAnchorConfigCommitment {
        self.root_anchor_config
    }

    pub(crate) const fn space(self) -> SpaceId {
        self.space
    }

    pub(crate) const fn system_agent(self) -> AgentId {
        self.system_agent
    }

    pub(crate) const fn authority_binding(self) -> Hash {
        self.authority_binding
    }

    pub(crate) const fn system_genesis(self) -> AgentJournalGenesisId {
        self.system_genesis
    }

    pub(crate) const fn agent_admission(self) -> AgentGenesisAdmissionId {
        self.agent_admission
    }

    pub(crate) const fn authority_scope(self) -> SystemAuthorityScopeCommitment {
        self.authority_scope
    }

    pub(crate) fn id(self) -> Hash {
        Hash::digest(AUTHORITY_LEDGER_ROUTE_ID_DOMAIN, &[&self.encode()])
    }

    pub(crate) fn validate(self) -> Result<(), SystemAuthorityLedgerWireError> {
        if self.root_anchor == super::committee::RootAnchorId::ZERO
            || self.root_anchor_config_version == 0
            || self.root_anchor_config == super::committee::RootAnchorConfigCommitment::ZERO
            || self.space == SpaceId::ZERO
            || self.system_agent == AgentId::ZERO
            || self.authority_binding == Hash::ZERO
            || self.system_genesis == AgentJournalGenesisId::ZERO
            || self.agent_admission == AgentGenesisAdmissionId::ZERO
            || self.authority_scope == SystemAuthorityScopeCommitment::ZERO
            || SystemAuthorityScopeCommitment::for_journal(
                self.root_anchor,
                self.system_genesis,
                self.agent_admission,
            )
            .map_err(|_| SystemAuthorityLedgerWireError::InvalidRoute)?
                != self.authority_scope
        {
            return Err(SystemAuthorityLedgerWireError::InvalidRoute);
        }
        enforce_wire_bound(&self, MAX_SYSTEM_AUTHORITY_LEDGER_ROUTE_BYTES)
    }
}

impl ServiceWire for SystemAuthorityLedgerRoute {
    const MAGIC: [u8; 4] = *b"AULR";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(self.root_anchor.as_bytes());
        encoder.u64(self.root_anchor_config_version);
        encoder.fixed(self.root_anchor_config.as_bytes());
        encoder.fixed(&self.space.0);
        encoder.fixed(&self.system_agent.0);
        encoder.fixed(&self.authority_binding.0);
        encoder.fixed(self.system_genesis.as_bytes());
        encoder.fixed(self.agent_admission.as_bytes());
        encoder.fixed(self.authority_scope.as_bytes());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SYSTEM_AUTHORITY_LEDGER_ROUTE_BYTES)?;
        let route = Self {
            root_anchor: super::committee::RootAnchorId::from_bytes(decoder.fixed()?),
            root_anchor_config_version: decoder.u64()?,
            root_anchor_config: super::committee::RootAnchorConfigCommitment::from_bytes(
                decoder.fixed()?,
            ),
            space: SpaceId(decoder.fixed()?),
            system_agent: AgentId(decoder.fixed()?),
            authority_binding: Hash(decoder.fixed()?),
            system_genesis: AgentJournalGenesisId::new(decoder.fixed()?),
            agent_admission: AgentGenesisAdmissionId::from_bytes(decoder.fixed()?),
            authority_scope: SystemAuthorityScopeCommitment::from_bytes(decoder.fixed()?),
        };
        route.validate().map_err(map_wire_decode_error)?;
        Ok(route)
    }
}

/// The committee leg to which one share belongs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub(crate) enum SystemAuthorityCommitteeLeg {
    Current = 0,
    Retiring = 1,
    Incoming = 2,
}

/// Exact authority claim and independently replay-selected committee policy.
///
/// This is public signing data inside the crate, not a reservation. Storage
/// methods additionally require the opaque token returned after a replay view
/// has been transactionally reserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SystemAuthorityLedgerClaim {
    AgentGenesis {
        committee: AuthorityCommittee,
        proposal: AgentGenesisProposal,
        replicas: AgentReplicaCommittee,
        claim: AgentGenesisClaim,
        proof: SystemAuthorityDecisionProof,
    },
    CommitteeRotation {
        retiring: AuthorityCommittee,
        incoming: AuthorityCommittee,
        transition: SystemAuthorityRotationClaim,
    },
}

impl SystemAuthorityLedgerClaim {
    // A shape-valid proposal is not yet a replay-prepared Create candidate:
    // its claimed post-Create state and artifact closure still need exact
    // provider/archive materialization. Production therefore has no raw
    // AgentGenesis request constructor or reservation entrypoint. The future
    // replay-owned prepared-candidate type will be the only issuance seam;
    // decoding this variant remains necessary solely for durable recovery.
    #[cfg(test)]
    fn agent_genesis(
        route: SystemAuthorityLedgerRoute,
        committee: AuthorityCommittee,
        proposal: AgentGenesisProposal,
        replicas: AgentReplicaCommittee,
        proof: SystemAuthorityDecisionProof,
    ) -> Result<Self, SystemAuthorityLedgerWireError> {
        route.validate()?;
        let claim = AgentGenesisClaim::new(
            route.system_agent(),
            route.system_genesis(),
            route.agent_admission(),
            &proposal,
            &replicas,
        )
        .map_err(|_| SystemAuthorityLedgerWireError::InvalidClaim)?;
        let request = Self::AgentGenesis {
            committee,
            proposal,
            replicas,
            claim,
            proof,
        };
        request.validate()?;
        Ok(request)
    }

    fn committee_rotation(
        retiring: AuthorityCommittee,
        incoming: AuthorityCommittee,
        transition: SystemAuthorityRotationClaim,
    ) -> Result<Self, SystemAuthorityLedgerWireError> {
        let request = Self::CommitteeRotation {
            retiring,
            incoming,
            transition,
        };
        request.validate()?;
        Ok(request)
    }

    pub(crate) fn claim(&self) -> AuthorityClaimCommitment {
        match self {
            Self::AgentGenesis { claim, .. } => claim.authority_claim(),
            Self::CommitteeRotation { transition, .. } => transition.authority_claim(),
        }
    }

    pub(crate) fn sequence(&self) -> u64 {
        self.claim().sequence()
    }

    pub(crate) fn committee(
        &self,
        leg: SystemAuthorityCommitteeLeg,
    ) -> Option<&AuthorityCommittee> {
        match (self, leg) {
            (Self::AgentGenesis { committee, .. }, SystemAuthorityCommitteeLeg::Current) => {
                Some(committee)
            }
            (Self::CommitteeRotation { retiring, .. }, SystemAuthorityCommitteeLeg::Retiring) => {
                Some(retiring)
            }
            (Self::CommitteeRotation { incoming, .. }, SystemAuthorityCommitteeLeg::Incoming) => {
                Some(incoming)
            }
            _ => None,
        }
    }

    pub(crate) fn legs(&self) -> &'static [SystemAuthorityCommitteeLeg] {
        match self {
            Self::AgentGenesis { .. } => &[SystemAuthorityCommitteeLeg::Current],
            Self::CommitteeRotation { .. } => &[
                SystemAuthorityCommitteeLeg::Retiring,
                SystemAuthorityCommitteeLeg::Incoming,
            ],
        }
    }

    pub(crate) fn transition(&self) -> Option<&SystemAuthorityRotationClaim> {
        match self {
            Self::AgentGenesis { .. } => None,
            Self::CommitteeRotation { transition, .. } => Some(transition),
        }
    }

    pub(crate) fn agent_genesis_preimages(
        &self,
    ) -> Option<(
        &AgentGenesisProposal,
        &AgentReplicaCommittee,
        &AgentGenesisClaim,
        &SystemAuthorityDecisionProof,
    )> {
        match self {
            Self::AgentGenesis {
                proposal,
                replicas,
                claim,
                proof,
                ..
            } => Some((proposal, replicas, claim, proof)),
            Self::CommitteeRotation { .. } => None,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), SystemAuthorityLedgerWireError> {
        match self {
            Self::AgentGenesis {
                committee,
                proposal,
                replicas,
                claim,
                proof,
            } => {
                committee
                    .validate()
                    .map_err(SystemAuthorityLedgerWireError::Authority)?;
                proposal
                    .validate()
                    .map_err(|_| SystemAuthorityLedgerWireError::InvalidClaim)?;
                claim
                    .validate_against(proposal, replicas)
                    .map_err(|_| SystemAuthorityLedgerWireError::InvalidClaim)?;
                let derived = AgentGenesisClaim::new(
                    claim.system_agent(),
                    claim.system_genesis(),
                    claim.system_admission(),
                    proposal,
                    replicas,
                )
                .map_err(|_| SystemAuthorityLedgerWireError::InvalidClaim)?;
                if &derived != claim {
                    return Err(SystemAuthorityLedgerWireError::InvalidClaim);
                }
                if proof.target_agent() != claim.agent() {
                    return Err(SystemAuthorityLedgerWireError::InvalidClaim);
                }
            }
            Self::CommitteeRotation {
                retiring,
                incoming,
                transition,
            } => {
                retiring
                    .validate()
                    .map_err(SystemAuthorityLedgerWireError::Authority)?;
                incoming
                    .validate()
                    .map_err(SystemAuthorityLedgerWireError::Authority)?;
                if transition.authority_claim().domain() != AuthorityClaimDomain::CommitteeRotation
                    || transition.space() != retiring.space()
                    || transition.space() != incoming.space()
                    || transition.authority_binding() != retiring.authority_binding()
                    || transition.authority_binding() != incoming.authority_binding()
                    || transition.old_epoch() != retiring.epoch()
                    || transition.new_epoch() != incoming.epoch()
                    || transition.old_committee().as_bytes() != &retiring.commitment().0
                    || transition.new_committee().as_bytes() != &incoming.commitment().0
                    || incoming.previous_committee() != Some(retiring.commitment())
                {
                    return Err(SystemAuthorityLedgerWireError::InvalidClaim);
                }
            }
        }
        enforce_wire_bound(self, MAX_SYSTEM_AUTHORITY_LEDGER_CLAIM_BYTES)
    }
}

impl ServiceWire for SystemAuthorityLedgerClaim {
    const MAGIC: [u8; 4] = *b"AULQ";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        match self {
            Self::AgentGenesis {
                committee,
                proposal,
                replicas,
                claim,
                proof,
            } => {
                encoder.u8(0);
                encoder.bytes(&committee.encode());
                encoder.bytes(&proposal.encode());
                encoder.bytes(&replicas.encode());
                encoder.bytes(&claim.encode());
                encoder.bytes(&proof.encode());
            }
            Self::CommitteeRotation {
                retiring,
                incoming,
                transition,
            } => {
                encoder.u8(1);
                encoder.bytes(&retiring.encode());
                encoder.bytes(&incoming.encode());
                encoder.bytes(&transition.encode());
            }
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SYSTEM_AUTHORITY_LEDGER_CLAIM_BYTES)?;
        let request = match decoder.u8()? {
            0 => Self::AgentGenesis {
                committee: decode_nested(decoder, MAX_AUTHORITY_COMMITTEE_WIRE_BYTES)?,
                proposal: decode_nested(decoder, MAX_AGENT_GENESIS_PROPOSAL_BYTES)?,
                replicas: decode_nested(decoder, MAX_AGENT_REPLICA_COMMITTEE_BYTES)?,
                claim: decode_nested(decoder, MAX_AGENT_GENESIS_CLAIM_BYTES)?,
                proof: decode_nested(decoder, MAX_SYSTEM_AUTHORITY_DECISION_PROOF_BYTES)?,
            },
            1 => Self::CommitteeRotation {
                retiring: decode_nested(decoder, MAX_AUTHORITY_COMMITTEE_WIRE_BYTES)?,
                incoming: decode_nested(decoder, MAX_AUTHORITY_COMMITTEE_WIRE_BYTES)?,
                transition: decode_nested(decoder, MAX_SYSTEM_AUTHORITY_ROTATION_CLAIM_BYTES)?,
            },
            _ => return Err(DecodeError::InvalidTag),
        };
        request.validate().map_err(map_wire_decode_error)?;
        Ok(request)
    }
}

/// Replay-authenticated view of the root system Agent's exact Control state.
///
/// Fields and construction stay crate-private. In particular, decoding a
/// [`SystemAuthorityState`] does not produce this value: construction also
/// requires replay's opaque, materialized journal scope.
#[derive(Clone, Debug)]
pub(crate) struct ReplayedSystemAuthorityView {
    route: SystemAuthorityLedgerRoute,
    journal_store: JournalStoreInstanceId,
    heads: JournalHeadsId,
    control_state: LaneStateId,
    trusted_scope: SystemAuthorityJournalScope,
    state: SystemAuthorityState,
    authority_state: Hash,
    commitment: Hash,
}

impl ReplayedSystemAuthorityView {
    /// Bind replay-authenticated authority state to its exact physical store,
    /// predecessor Heads, and Control state.
    ///
    /// The journal scope is deliberately opaque and cannot be reconstructed
    /// from its raw genesis/admission IDs. Consequently decoded authority
    /// state and caller-chosen IDs alone cannot mint this signing view.
    pub(crate) fn from_authenticated_replay(
        trusted_scope: SystemAuthorityJournalScope,
        state: &SystemAuthorityState,
        journal_store: JournalStoreInstanceId,
        heads: JournalHeadsId,
        control_state: LaneStateId,
    ) -> Result<Self, SystemAuthorityLedgerWireError> {
        state
            .validate()
            .map_err(|_| SystemAuthorityLedgerWireError::InvalidStateView)?;
        if JournalStoreInstanceId::from_bytes(*journal_store.as_bytes()).is_none()
            || heads == JournalHeadsId::ZERO
            || control_state == LaneStateId::ZERO
        {
            return Err(SystemAuthorityLedgerWireError::InvalidStateView);
        }
        let route = SystemAuthorityLedgerRoute::new(
            state.root_anchor(),
            state.root_anchor_config_version(),
            state.root_anchor_config(),
            state.space(),
            state.system_agent(),
            state.authority_binding(),
            trusted_scope.system_genesis(),
            trusted_scope.agent_admission(),
        )?;
        if trusted_scope
            .commitment(state.root_anchor())
            .map_err(|_| SystemAuthorityLedgerWireError::InvalidStateView)?
            != route.authority_scope
            || state
                .journal_binding()
                .is_some_and(|binding| binding != trusted_scope.binding())
        {
            return Err(SystemAuthorityLedgerWireError::InvalidStateView);
        }
        let mut view = Self {
            route,
            journal_store,
            heads,
            control_state,
            trusted_scope,
            state: state.clone(),
            authority_state: Hash::ZERO,
            commitment: Hash::ZERO,
        };
        view.authority_state = view.compute_authority_state_commitment();
        view.commitment = view.compute_commitment();
        view.validate()?;
        Ok(view)
    }

    #[cfg(test)]
    fn for_test_from_authenticated_replay(
        trusted_scope: SystemAuthorityJournalScope,
        state: &SystemAuthorityState,
        journal_store: JournalStoreInstanceId,
        heads: JournalHeadsId,
        control_state: LaneStateId,
    ) -> Result<Self, SystemAuthorityLedgerWireError> {
        Self::from_authenticated_replay(trusted_scope, state, journal_store, heads, control_state)
    }

    pub(crate) const fn route(&self) -> SystemAuthorityLedgerRoute {
        self.route
    }

    pub(crate) const fn control_state(&self) -> LaneStateId {
        self.control_state
    }

    pub(crate) const fn journal_store(&self) -> JournalStoreInstanceId {
        self.journal_store
    }

    pub(crate) const fn heads(&self) -> JournalHeadsId {
        self.heads
    }

    pub(crate) const fn committee(&self) -> &AuthorityCommittee {
        self.state.current_committee()
    }

    pub(crate) const fn committee_sequence_high_water(&self) -> u64 {
        self.state.committee_sequence_high_water()
    }

    pub(crate) const fn rotation_first_sequence(&self) -> Option<u64> {
        self.state.rotation_first_sequence()
    }

    pub(crate) const fn commitment(&self) -> Hash {
        self.commitment
    }

    pub(crate) const fn authority_state_commitment(&self) -> Hash {
        self.authority_state
    }

    fn validate_claim(
        &self,
        request: &SystemAuthorityLedgerClaim,
    ) -> Result<(), SystemAuthorityLedgerWireError> {
        self.validate()?;
        request.validate()?;
        if request
            .legs()
            .first()
            .and_then(|leg| request.committee(*leg))
            != Some(self.state.current_committee())
        {
            return Err(SystemAuthorityLedgerWireError::StaleCommittee);
        }
        match request {
            SystemAuthorityLedgerClaim::AgentGenesis { claim, proof, .. } => {
                self.state
                    .validate_agent_genesis_claim_for_signing(self.trusted_scope, claim, proof)
                    .map_err(|_| SystemAuthorityLedgerWireError::InvalidClaim)?;
            }
            SystemAuthorityLedgerClaim::CommitteeRotation {
                incoming,
                transition,
                ..
            } => {
                self.state
                    .validate_rotation_claim_for_signing(self.trusted_scope, transition, incoming)
                    .map_err(|_| SystemAuthorityLedgerWireError::InvalidClaim)?;
            }
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), SystemAuthorityLedgerWireError> {
        self.route.validate()?;
        self.state
            .validate()
            .map_err(|_| SystemAuthorityLedgerWireError::InvalidStateView)?;
        self.state
            .current_committee()
            .validate()
            .map_err(SystemAuthorityLedgerWireError::Authority)?;
        if self.control_state == LaneStateId::ZERO
            || JournalStoreInstanceId::from_bytes(*self.journal_store.as_bytes()).is_none()
            || self.heads == JournalHeadsId::ZERO
            || self.state.current_committee().space() != self.route.space
            || self.state.current_committee().authority_binding() != self.route.authority_binding
            || self.trusted_scope.system_genesis() != self.route.system_genesis
            || self.trusted_scope.agent_admission() != self.route.agent_admission
            || self
                .state
                .journal_binding()
                .is_some_and(|binding| binding != self.trusted_scope.binding())
            || self.authority_state == Hash::ZERO
            || self.compute_authority_state_commitment() != self.authority_state
            || self.commitment == Hash::ZERO
            || self.compute_commitment() != self.commitment
        {
            return Err(SystemAuthorityLedgerWireError::InvalidStateView);
        }
        Ok(())
    }

    fn compute_commitment(&self) -> Hash {
        Hash::digest(
            AUTHORITY_LEDGER_VIEW_DOMAIN,
            &[
                &self.route.id().0,
                self.journal_store.as_bytes(),
                self.heads.as_bytes(),
                self.control_state.as_bytes(),
                &self.authority_state.0,
            ],
        )
    }

    fn compute_authority_state_commitment(&self) -> Hash {
        Hash::digest(AUTHORITY_LEDGER_STATE_DOMAIN, &[&self.state.encode()])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SystemAuthorityLedgerWireError {
    InvalidRoute,
    InvalidClaim,
    InvalidStateView,
    StaleCommittee,
    SequenceConflict,
    LimitExceeded,
    Authority(AuthorityCommitteeError),
}

impl fmt::Display for SystemAuthorityLedgerWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "system authority ledger wire: {self:?}")
    }
}

impl core::error::Error for SystemAuthorityLedgerWireError {}

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

fn enforce_wire_bound<T: ServiceWire>(
    value: &T,
    maximum: usize,
) -> Result<(), SystemAuthorityLedgerWireError> {
    if value.encode().len() > maximum {
        Err(SystemAuthorityLedgerWireError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn map_wire_decode_error(error: SystemAuthorityLedgerWireError) -> DecodeError {
    match error {
        SystemAuthorityLedgerWireError::LimitExceeded => DecodeError::LimitExceeded,
        _ => DecodeError::NonCanonical,
    }
}

#[cfg(all(feature = "std", feature = "storage"))]
mod durable {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use ed25519_dalek::VerifyingKey;
    use redb::{Database, ReadableTable, TableDefinition};

    use super::*;
    use crate::agent::committee::{
        AuthorityMemberRole, AuthorityQuorumCertificate, AuthoritySignature, AuthoritySignerId,
        MAX_AUTHORITY_QC_WIRE_BYTES,
    };
    use crate::agent::system_authority::{
        MAX_SYSTEM_AUTHORITY_ROTATIONS, SystemAuthorityRotationCertificate,
    };
    use crate::service::NodeId;

    const LEDGER_SCHEMA_VERSION: u32 = 1;
    // Config rows are permanent: a key that was ever local must never later be
    // admitted through the remote-share path and bypass its durable pledge.
    // One initial committee plus every protocol-bounded rotation can introduce
    // at most this many distinct local signing keys for a route.
    const MAX_LOCAL_SIGNERS_PER_SCOPE: usize = MAX_SYSTEM_AUTHORITY_ROTATIONS as usize + 1;
    const MAX_SHARE_ROWS_PER_CLAIM: usize = 2 * 256;
    const MAX_QC_ROWS_PER_CLAIM: usize = 2;
    const MAX_CONFIG_RECORD_BYTES: usize = 1024;
    const MAX_META_RECORD_BYTES: usize = 1024;
    const MAX_RESERVATION_RECORD_BYTES: usize =
        MAX_SYSTEM_AUTHORITY_LEDGER_ROUTE_BYTES + MAX_SYSTEM_AUTHORITY_LEDGER_CLAIM_BYTES + 512;
    const MAX_PLEDGE_RECORD_BYTES: usize = 1024;
    const MAX_SHARE_RECORD_BYTES: usize = 1024;
    const MAX_QC_RECORD_BYTES: usize =
        MAX_SYSTEM_AUTHORITY_LEDGER_ROUTE_BYTES + MAX_AUTHORITY_QC_WIRE_BYTES + 512;
    const MAX_FAIL_STOP_RECORD_BYTES: usize = 1024;

    const CONFIG_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("system_authority_ledger_config_v1");
    const META_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("system_authority_ledger_meta_v1");
    const RESERVATION_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("system_authority_ledger_reservation_v1");
    const PLEDGE_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("system_authority_ledger_pledge_v1");
    const SHARE_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("system_authority_ledger_share_v1");
    const QC_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("system_authority_ledger_qc_v1");
    const FAIL_STOP_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("system_authority_ledger_fail_stop_v1");

    const ROUTE_KEY_BYTES: usize = 32;
    const CONFIG_KEY_BYTES: usize = ROUTE_KEY_BYTES + 32;
    const PLEDGE_KEY_BYTES: usize = ROUTE_KEY_BYTES + 32 + 8;
    const CLAIM_PREFIX_BYTES: usize = ROUTE_KEY_BYTES + 8;
    const LEG_KEY_BYTES: usize = CLAIM_PREFIX_BYTES + 1;
    const SHARE_KEY_BYTES: usize = LEG_KEY_BYTES + 32;

    /// External authority signer invoked only after the exact global-sequence
    /// pledge is durable. A crash or callback error can cause the identical
    /// message to be submitted again before its share is retained, so signer
    /// implementations must be deterministic/idempotent for an exact message;
    /// the ledger promises sign-once claim binding, not exactly-once callback
    /// delivery.
    pub(crate) trait SystemAuthoritySigner {
        type Error;

        fn signer(&self) -> AuthoritySignerId;
        fn sign_authority_message(&self, message: Hash) -> Result<[u8; 64], Self::Error>;
    }

    #[derive(Debug)]
    pub(crate) enum SystemAuthoritySignError<E> {
        Ledger(SystemAuthorityLedgerError),
        Signer(E),
    }

    impl<E: fmt::Display> fmt::Display for SystemAuthoritySignError<E> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Ledger(error) => error.fmt(formatter),
                Self::Signer(error) => write!(formatter, "system authority signer failed: {error}"),
            }
        }
    }

    impl<E: core::error::Error + 'static> core::error::Error for SystemAuthoritySignError<E> {
        fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
            match self {
                Self::Ledger(error) => Some(error),
                Self::Signer(error) => Some(error),
            }
        }
    }

    impl<E> From<SystemAuthorityLedgerError> for SystemAuthoritySignError<E> {
        fn from(error: SystemAuthorityLedgerError) -> Self {
            Self::Ledger(error)
        }
    }

    /// Opaque durable reservation. Raw claim bytes cannot construct this.
    #[derive(Clone, Debug)]
    pub(crate) struct ReservedSystemAuthorityClaim {
        record: ReservationRecord,
    }

    impl ReservedSystemAuthorityClaim {
        pub(crate) const fn route(&self) -> SystemAuthorityLedgerRoute {
            self.record.route
        }

        pub(crate) const fn request(&self) -> &SystemAuthorityLedgerClaim {
            &self.record.request
        }

        pub(crate) const fn control_state(&self) -> LaneStateId {
            self.record.control_state
        }

        pub(crate) const fn state_view_commitment(&self) -> Hash {
            self.record.state_view
        }
    }

    /// Rotation-only input to the production reservation seam. The private
    /// field prevents a decoded AgentGenesis request from being promoted into
    /// signing authority. Ordinary genesis will gain a separate constructor
    /// only when replay can supply its opaque, fully materialized Create
    /// candidate.
    #[derive(Clone, Debug)]
    pub(crate) struct SystemAuthorityRotationReservationRequest {
        request: SystemAuthorityLedgerClaim,
    }

    impl SystemAuthorityRotationReservationRequest {
        pub(crate) fn new(
            retiring: AuthorityCommittee,
            incoming: AuthorityCommittee,
            transition: SystemAuthorityRotationClaim,
        ) -> Result<Self, SystemAuthorityLedgerWireError> {
            Ok(Self {
                request: SystemAuthorityLedgerClaim::committee_rotation(
                    retiring, incoming, transition,
                )?,
            })
        }

        pub(crate) fn claim(&self) -> AuthorityClaimCommitment {
            self.request.claim()
        }
    }

    /// Read-only crash-recovery evidence. It deliberately is not convertible
    /// to [`ReservedSystemAuthorityClaim`]: replay must first reconcile the
    /// current authenticated store view through `reserve_or_reconcile`.
    #[derive(Clone, Debug)]
    pub(crate) struct PendingSystemAuthorityRecovery {
        record: ReservationRecord,
    }

    impl PendingSystemAuthorityRecovery {
        pub(crate) const fn route(&self) -> SystemAuthorityLedgerRoute {
            self.record.route
        }

        pub(crate) const fn journal_store(&self) -> JournalStoreInstanceId {
            self.record.journal_store
        }

        pub(crate) const fn predecessor_heads(&self) -> JournalHeadsId {
            self.record.predecessor_heads
        }

        pub(crate) const fn control_state(&self) -> LaneStateId {
            self.record.control_state
        }

        /// Commitment to the complete predecessor tuple, including its exact
        /// store, Heads, Control state, and authenticated authority state.
        pub(crate) const fn state_view_commitment(&self) -> Hash {
            self.record.state_view
        }

        /// Commitment to authority state alone. Replay uses this to
        /// distinguish an unrelated-Heads rebase from an already-published
        /// authority transition without promoting this evidence to a
        /// reservation.
        pub(crate) const fn authority_state_commitment(&self) -> Hash {
            self.record.authority_state
        }

        pub(crate) fn claim(&self) -> AuthorityClaimCommitment {
            self.record.request.claim()
        }

        pub(crate) const fn request(&self) -> &SystemAuthorityLedgerClaim {
            &self.record.request
        }

        pub(crate) fn rotation_request(&self) -> Option<SystemAuthorityRotationReservationRequest> {
            matches!(
                &self.record.request,
                SystemAuthorityLedgerClaim::CommitteeRotation { .. }
            )
            .then(|| SystemAuthorityRotationReservationRequest {
                request: self.record.request.clone(),
            })
        }
    }

    /// How an authenticated reservation attempt related to the durable row.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum SystemAuthorityReservationDisposition {
        New,
        Exact,
        Rebased,
    }

    #[derive(Clone, Debug)]
    pub(crate) struct SystemAuthorityReservationOutcome {
        disposition: SystemAuthorityReservationDisposition,
        reserved: ReservedSystemAuthorityClaim,
    }

    impl SystemAuthorityReservationOutcome {
        pub(crate) const fn disposition(&self) -> SystemAuthorityReservationDisposition {
            self.disposition
        }

        pub(crate) const fn reserved(&self) -> &ReservedSystemAuthorityClaim {
            &self.reserved
        }

        pub(crate) fn into_reserved(self) -> ReservedSystemAuthorityClaim {
            self.reserved
        }
    }

    /// Result of retaining one exact verified share. Once a certificate is
    /// present it is the first threshold certificate and never changes.
    #[derive(Clone, Debug)]
    pub(crate) struct SystemAuthorityShareOutcome {
        share: AuthoritySignature,
        certificate: Option<AuthorityQuorumCertificate>,
    }

    impl SystemAuthorityShareOutcome {
        pub(crate) const fn share(&self) -> &AuthoritySignature {
            &self.share
        }

        pub(crate) const fn certificate(&self) -> Option<&AuthorityQuorumCertificate> {
            self.certificate.as_ref()
        }
    }

    /// Module-private model of replay's future post-CAS receipt. Production
    /// code cannot construct or submit this value: integration must define a
    /// replay/store-owned opaque receipt after sealed-dependency readback and
    /// the exact predecessor-to-successor Heads CAS, then wire that receipt to
    /// the private retirement core without exposing successor facts as a
    /// capability.
    #[derive(Debug)]
    struct PublishedSystemAuthorityClaim {
        reservation: ReservationRecord,
        journal_store: JournalStoreInstanceId,
        successor_heads: JournalHeadsId,
        successor_control: LaneStateId,
        successor_view: Hash,
        successor_authority_state: Hash,
        resulting_high_water: u64,
        resulting_first_sequence: Option<u64>,
        resulting_committee: Hash,
    }

    impl PublishedSystemAuthorityClaim {
        #[cfg(test)]
        fn for_test_after_exact_cas(
            pending: PendingSystemAuthorityRecovery,
            exact_executed_claim: AuthorityClaimCommitment,
            successor: &ReplayedSystemAuthorityView,
        ) -> Result<Self, SystemAuthorityLedgerError> {
            let reservation = pending.record;
            let request = &reservation.request;
            if request.claim() != exact_executed_claim
                || successor.route() != reservation.route
                || successor.journal_store() != reservation.journal_store
                || successor.heads() == reservation.predecessor_heads
                || successor.control_state() == reservation.control_state
                || successor.committee_sequence_high_water() != request.sequence()
            {
                return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
            }
            match request {
                SystemAuthorityLedgerClaim::AgentGenesis { committee, .. } => {
                    if successor.committee() != committee
                        || successor.rotation_first_sequence().is_some()
                    {
                        return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
                    }
                }
                SystemAuthorityLedgerClaim::CommitteeRotation {
                    incoming,
                    transition,
                    ..
                } => {
                    if successor.committee() != incoming
                        || successor.rotation_first_sequence() != Some(transition.first_sequence())
                    {
                        return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
                    }
                }
            }
            Ok(Self {
                journal_store: successor.journal_store(),
                successor_heads: successor.heads(),
                reservation,
                successor_control: successor.control_state(),
                successor_view: successor.commitment(),
                successor_authority_state: successor.authority_state_commitment(),
                resulting_high_water: successor.committee_sequence_high_water(),
                resulting_first_sequence: successor.rotation_first_sequence(),
                resulting_committee: successor.committee().commitment(),
            })
        }
    }

    /// Crash-safe authority signing ledger for one generation route and one
    /// local signer. Multiple handles/signers may share the database; every
    /// mutation rechecks configuration, fail-stop, and reservation in the
    /// same redb write transaction.
    pub(crate) struct SystemAuthorityEvidenceLedger {
        database: Arc<Database>,
        route: SystemAuthorityLedgerRoute,
        journal_store: JournalStoreInstanceId,
        local_node: NodeId,
        local_signer: AuthoritySignerId,
        writes: std::sync::Mutex<()>,
    }

    impl SystemAuthorityEvidenceLedger {
        pub(crate) fn open(
            database: Arc<Database>,
            route: SystemAuthorityLedgerRoute,
            journal_store: JournalStoreInstanceId,
            local_node: NodeId,
            local_signer: AuthoritySignerId,
        ) -> Result<Self, SystemAuthorityLedgerError> {
            route.validate()?;
            if local_node == NodeId::ZERO
                || local_signer == AuthoritySignerId::ZERO
                || JournalStoreInstanceId::from_bytes(*journal_store.as_bytes()).is_none()
            {
                return Err(SystemAuthorityLedgerError::InvalidLocalSigner);
            }
            let expected = ConfigRecord {
                version: LEDGER_SCHEMA_VERSION,
                route,
                journal_store,
                local_node,
                local_signer: *local_signer.as_bytes(),
            };
            expected.validate()?;
            let ledger = Self {
                database: database.clone(),
                route,
                journal_store,
                local_node,
                local_signer,
                writes: std::sync::Mutex::new(()),
            };
            let route_key = route_storage_key(route);
            let key = config_storage_key(route, local_signer.as_bytes());
            // redb serializes writers. Holding this transaction while auditing
            // the last committed snapshot prevents a concurrent writer from
            // changing any route row between preflight and Config insertion.
            // Any pre-existing corruption drops this transaction, so opening
            // a new local signer is a zero-write failure.
            let transaction = database.begin_write()?;
            ledger.audit_recovery_preflight()?;
            let existing = {
                let table = transaction.open_table(CONFIG_TABLE)?;
                table
                    .get(key.as_slice())?
                    .map(|value| value.value().to_vec())
            };
            match existing {
                Some(bytes) => {
                    let existing = ConfigRecord::decode(&bytes)
                        .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                    if existing != expected {
                        return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
                    }
                }
                None => {
                    // A signature admitted while this key was classified as
                    // remote cannot become a local share merely by installing
                    // Config. The writer transaction makes this check atomic
                    // with Config insertion.
                    ledger.recheck_local_signer_installation(&transaction)?;
                    let mut table = transaction.open_table(CONFIG_TABLE)?;
                    let mut count = 0_usize;
                    for row in table.range(route_key.as_slice()..)? {
                        let (row_key, row_value) = row?;
                        if !row_key.value().starts_with(route_key.as_slice()) {
                            break;
                        }
                        let config = ConfigRecord::decode(row_value.value())
                            .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                        if config.route != route
                            || config.journal_store != journal_store
                            || config.local_node != local_node
                        {
                            return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
                        }
                        count += 1;
                        if count >= MAX_LOCAL_SIGNERS_PER_SCOPE {
                            return Err(SystemAuthorityLedgerError::BacklogLimit);
                        }
                    }
                    table.insert(key.as_slice(), expected.encode().as_slice())?;
                }
            }
            // Pin every table schema atomically before the first reservation.
            {
                let _ = transaction.open_table(META_TABLE)?;
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
            Ok(ledger)
        }

        pub(crate) const fn route(&self) -> SystemAuthorityLedgerRoute {
            self.route
        }

        pub(crate) const fn local_signer(&self) -> AuthoritySignerId {
            self.local_signer
        }

        pub(crate) const fn local_node(&self) -> NodeId {
            self.local_node
        }

        pub(crate) const fn journal_store(&self) -> JournalStoreInstanceId {
            self.journal_store
        }

        pub(crate) fn is_fail_stopped(&self) -> Result<bool, SystemAuthorityLedgerError> {
            Ok(read_exact(
                &self.database,
                FAIL_STOP_TABLE,
                route_storage_key(self.route).as_slice(),
            )?
            .is_some())
        }

        /// Reserve a new rotation or reconcile an existing one against the
        /// current replay-authenticated view in one redb transaction. The
        /// production input is rotation-only; decoded AgentGenesis recovery
        /// data cannot cross this signing boundary.
        pub(crate) fn reserve_or_reconcile(
            &self,
            view: &ReplayedSystemAuthorityView,
            request: SystemAuthorityRotationReservationRequest,
        ) -> Result<SystemAuthorityReservationOutcome, SystemAuthorityLedgerError> {
            self.reserve_or_reconcile_claim(view, request.request)
        }

        fn reserve_or_reconcile_claim(
            &self,
            view: &ReplayedSystemAuthorityView,
            request: SystemAuthorityLedgerClaim,
        ) -> Result<SystemAuthorityReservationOutcome, SystemAuthorityLedgerError> {
            if view.route() != self.route || view.journal_store() != self.journal_store {
                return Err(SystemAuthorityLedgerError::WrongRoute);
            }
            // Authenticate and structurally validate the view and request, but
            // deliberately defer claim freshness validation. If an active row
            // names a different authority-state commitment, replay must first
            // determine whether the reserved operation was already published;
            // a stale-sequence error must not hide that recovery state.
            view.validate()?;
            request.validate()?;

            let _write = self.lock_writes()?;
            let route_key = route_storage_key(self.route);
            let transaction = self.database.begin_write()?;
            self.recheck_config(&transaction)?;
            let fail_stopped = transaction
                .open_table(FAIL_STOP_TABLE)?
                .get(route_key.as_slice())?
                .is_some();
            let active = transaction
                .open_table(RESERVATION_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
                .map(|bytes| {
                    ReservationRecord::decode(&bytes)
                        .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)
                })
                .transpose()?;
            let meta = transaction
                .open_table(META_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
                .map(|bytes| {
                    MetaRecord::decode(&bytes)
                        .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)
                })
                .transpose()?;

            if let Some(active) = active {
                active.validate()?;
                let meta = meta.ok_or(SystemAuthorityLedgerError::CorruptLedger)?;
                meta.validate()?;
                if active.route != self.route
                    || active.journal_store != self.journal_store
                    || meta.route != self.route
                    || meta.journal_store != self.journal_store
                    || meta.authority_state != active.authority_state
                    || meta.retired_high_water != active.prior_high_water
                {
                    return Err(SystemAuthorityLedgerError::CorruptLedger);
                }
                if view.authority_state_commitment() != active.authority_state {
                    return Err(SystemAuthorityLedgerError::PublicationRecoveryRequired);
                }
                // Once the authority snapshot is proven identical, validate
                // the proposed claim against that authenticated state before
                // treating it as a competing reservation. Malformed, stale,
                // or foreign decoded input must never be able to persist a
                // fail-stop row.
                view.validate_claim(&request)?;
                self.validate_local_voter(&request)?;
                if active.request != request {
                    if fail_stopped {
                        return Err(SystemAuthorityLedgerError::FailStopped);
                    }
                    let failure = FailStopRecord::for_conflict(
                        self.route,
                        request.sequence(),
                        active.request.claim().claim_hash(),
                        request.claim().claim_hash(),
                    )?;
                    {
                        transaction
                            .open_table(FAIL_STOP_TABLE)?
                            .insert(route_key.as_slice(), failure.encode().as_slice())?;
                    }
                    transaction.commit()?;
                    return Err(SystemAuthorityLedgerError::DivergentReservation);
                }

                if view.committee_sequence_high_water() != active.prior_high_water
                    || view.rotation_first_sequence() != active.prior_first_sequence
                {
                    return Err(SystemAuthorityLedgerError::CorruptLedger);
                }
                let next = ReservationRecord::for_view(self.route, view, request)?;
                if next == active {
                    return Ok(SystemAuthorityReservationOutcome {
                        disposition: SystemAuthorityReservationDisposition::Exact,
                        reserved: ReservedSystemAuthorityClaim { record: active },
                    });
                }
                // Equal request and authority-state commitment means only the
                // authenticated predecessor tuple may differ. Replacing the
                // row invalidates every older sign-capable token while
                // retaining global-H pledges, shares, and frozen QCs.
                transaction
                    .open_table(RESERVATION_TABLE)?
                    .insert(route_key.as_slice(), next.encode().as_slice())?;
                transaction.commit()?;
                return Ok(SystemAuthorityReservationOutcome {
                    disposition: SystemAuthorityReservationDisposition::Rebased,
                    reserved: ReservedSystemAuthorityClaim { record: next },
                });
            }

            if fail_stopped {
                return Err(SystemAuthorityLedgerError::FailStopped);
            }
            view.validate_claim(&request)?;
            self.validate_local_voter(&request)?;
            let expected = ReservationRecord::for_view(self.route, view, request)?;
            let expected_meta = MetaRecord {
                route: self.route,
                journal_store: self.journal_store,
                retired_high_water: expected.prior_high_water,
                authority_state: expected.authority_state,
                last_claim: None,
                last_publication: None,
            };
            expected_meta.validate()?;
            {
                let mut table = transaction.open_table(META_TABLE)?;
                match meta {
                    Some(meta) => {
                        meta.validate()?;
                        if meta.route != self.route
                            || meta.retired_high_water != expected.prior_high_water
                            || meta.journal_store != self.journal_store
                            || meta.authority_state != expected.authority_state
                        {
                            return Err(SystemAuthorityLedgerError::StaleStateView);
                        }
                    }
                    None => {
                        table.insert(route_key.as_slice(), expected_meta.encode().as_slice())?;
                    }
                }
            }
            transaction
                .open_table(RESERVATION_TABLE)?
                .insert(route_key.as_slice(), expected.encode().as_slice())?;
            transaction.commit()?;
            Ok(SystemAuthorityReservationOutcome {
                disposition: SystemAuthorityReservationDisposition::New,
                reserved: ReservedSystemAuthorityClaim { record: expected },
            })
        }

        /// Return the durable active row only as non-sign-capable recovery
        /// evidence. The caller must feed its rotation request and a current
        /// replay-authenticated view through `reserve_or_reconcile` before any
        /// signer or remote-share method will accept it.
        pub(crate) fn recover_pending_claim(
            &self,
        ) -> Result<Option<PendingSystemAuthorityRecovery>, SystemAuthorityLedgerError> {
            let route_key = route_storage_key(self.route);
            let transaction = self.database.begin_read()?;
            let Some(bytes) = transaction
                .open_table(RESERVATION_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
            else {
                return Ok(None);
            };
            let record = ReservationRecord::decode(&bytes)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            let meta = transaction
                .open_table(META_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::CorruptLedger)?;
            let meta =
                MetaRecord::decode(&meta).map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            if record.route != self.route
                || record.journal_store != self.journal_store
                || meta.route != self.route
                || meta.journal_store != self.journal_store
                || meta.retired_high_water != record.prior_high_water
                || meta.authority_state != record.authority_state
            {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            record.validate()?;
            meta.validate()?;
            Ok(Some(PendingSystemAuthorityRecovery { record }))
        }

        /// Run a root-journal checkpoint/GC operation only while reservation
        /// insertion is excluded by redb's global writer. A TargetConflict may
        /// leave no permanent decision-tree leaf, so its exact publication
        /// suffix must remain available until retirement clears the row.
        ///
        /// The journal operation normally targets its own store. It executes
        /// inside this closure while the evidence database writer remains
        /// held; every ledger handle's reservation path must acquire that same
        /// redb writer and therefore cannot race the no-reservation check.
        pub(crate) fn with_no_pending_reservation_for_gc<T>(
            &self,
            operation: impl FnOnce() -> T,
        ) -> Result<T, SystemAuthorityLedgerError> {
            let _write = self.lock_writes()?;
            let transaction = self.database.begin_write()?;
            self.recheck_config(&transaction)?;
            if transaction
                .open_table(RESERVATION_TABLE)?
                .get(route_storage_key(self.route).as_slice())?
                .is_some()
            {
                return Err(SystemAuthorityLedgerError::GcBlockedByPendingReservation);
            }
            let result = operation();
            // Keep the redb writer alive until the external checkpoint/GC
            // operation has completely returned.
            drop(transaction);
            Ok(result)
        }

        #[cfg(test)]
        fn has_pending_reservation(&self) -> Result<bool, SystemAuthorityLedgerError> {
            Ok(self.recover_pending_claim()?.is_some())
        }

        /// Exact retry returns an already retained local share without
        /// invoking the signer again. Otherwise the sign-once pledge commits
        /// first, followed by the callback and verified share transaction.
        pub(crate) fn sign_reserved_leg<S: SystemAuthoritySigner>(
            &self,
            reserved: &ReservedSystemAuthorityClaim,
            leg: SystemAuthorityCommitteeLeg,
            signer: &S,
        ) -> Result<SystemAuthorityShareOutcome, SystemAuthoritySignError<S::Error>> {
            if signer.signer() != self.local_signer {
                return Err(SystemAuthorityLedgerError::WrongSigner.into());
            }
            let committee = reserved
                .record
                .request
                .committee(leg)
                .ok_or(SystemAuthorityLedgerError::WrongCommitteeLeg)?;
            let member = committee
                .member(self.local_signer)
                .ok_or(SystemAuthorityLedgerError::LocalSignerNotVoter)?;
            if member.role() != AuthorityMemberRole::Voter {
                return Err(SystemAuthorityLedgerError::ObserverSigner.into());
            }
            if member.node() != self.local_node {
                return Err(SystemAuthorityLedgerError::LocalSignerNodeMismatch.into());
            }
            self.ensure_reserved(reserved)?;
            if let Some(existing) = self.share_for(reserved, leg, self.local_signer.as_bytes())? {
                return Ok(SystemAuthorityShareOutcome {
                    share: existing,
                    certificate: self.certificate_for(reserved, leg)?,
                });
            }
            self.ensure_pledge(reserved)?;
            // A concurrent exact handle may have completed the same pledge
            // while this handle waited for redb's writer lock.
            if let Some(existing) = self.share_for(reserved, leg, self.local_signer.as_bytes())? {
                return Ok(SystemAuthorityShareOutcome {
                    share: existing,
                    certificate: self.certificate_for(reserved, leg)?,
                });
            }
            let claim = reserved.record.request.claim();
            let message = AuthorityQuorumCertificate::signing_message(
                committee.authority_binding(),
                committee.epoch(),
                committee.commitment(),
                claim,
            );
            let bytes = signer
                .sign_authority_message(message)
                .map_err(SystemAuthoritySignError::Signer)?;
            let share = AuthoritySignature::new(self.local_signer, bytes)
                .map_err(SystemAuthorityLedgerError::Authority)?;
            validate_share(committee, claim, &share)?;
            self.record_share(reserved, leg, share, true)
                .map_err(Into::into)
        }

        /// Retain a remote voter share only for the exact active reservation.
        /// Any signer configured as local for this database must cross its own
        /// durable pledge boundary instead.
        pub(crate) fn record_remote_share(
            &self,
            reserved: &ReservedSystemAuthorityClaim,
            leg: SystemAuthorityCommitteeLeg,
            share: AuthoritySignature,
        ) -> Result<SystemAuthorityShareOutcome, SystemAuthorityLedgerError> {
            self.ensure_reserved(reserved)?;
            let committee = reserved
                .record
                .request
                .committee(leg)
                .ok_or(SystemAuthorityLedgerError::WrongCommitteeLeg)?;
            validate_share(committee, reserved.record.request.claim(), &share)?;
            self.record_share(reserved, leg, share, false)
        }

        pub(crate) fn certificate(
            &self,
            reserved: &ReservedSystemAuthorityClaim,
            leg: SystemAuthorityCommitteeLeg,
        ) -> Result<Option<AuthorityQuorumCertificate>, SystemAuthorityLedgerError> {
            self.ensure_reserved_read_only(reserved)?;
            self.certificate_for(reserved, leg)
        }

        /// Inspect a frozen QC during crash recovery without upgrading the
        /// pending row into signing authority.
        pub(crate) fn pending_certificate(
            &self,
            pending: &PendingSystemAuthorityRecovery,
            leg: SystemAuthorityCommitteeLeg,
        ) -> Result<Option<AuthorityQuorumCertificate>, SystemAuthorityLedgerError> {
            self.ensure_pending_read_only(pending)?;
            self.certificate_for_record(&pending.record, leg)
        }

        pub(crate) fn joint_rotation_certificate(
            &self,
            reserved: &ReservedSystemAuthorityClaim,
        ) -> Result<Option<SystemAuthorityRotationCertificate>, SystemAuthorityLedgerError>
        {
            self.ensure_reserved_read_only(reserved)?;
            let Some(transition) = reserved.record.request.transition().cloned() else {
                return Err(SystemAuthorityLedgerError::WrongCommitteeLeg);
            };
            let Some(old_certificate) =
                self.certificate_for(reserved, SystemAuthorityCommitteeLeg::Retiring)?
            else {
                return Ok(None);
            };
            let Some(new_certificate) =
                self.certificate_for(reserved, SystemAuthorityCommitteeLeg::Incoming)?
            else {
                return Ok(None);
            };
            SystemAuthorityRotationCertificate::new(transition, old_certificate, new_certificate)
                .map(Some)
                .map_err(|_| SystemAuthorityLedgerError::InvalidCertificate)
        }

        pub(crate) fn pending_joint_rotation_certificate(
            &self,
            pending: &PendingSystemAuthorityRecovery,
        ) -> Result<Option<SystemAuthorityRotationCertificate>, SystemAuthorityLedgerError>
        {
            self.ensure_pending_read_only(pending)?;
            let Some(transition) = pending.record.request.transition().cloned() else {
                return Err(SystemAuthorityLedgerError::WrongCommitteeLeg);
            };
            let Some(old_certificate) = self
                .certificate_for_record(&pending.record, SystemAuthorityCommitteeLeg::Retiring)?
            else {
                return Ok(None);
            };
            let Some(new_certificate) = self
                .certificate_for_record(&pending.record, SystemAuthorityCommitteeLeg::Incoming)?
            else {
                return Ok(None);
            };
            SystemAuthorityRotationCertificate::new(transition, old_certificate, new_certificate)
                .map(Some)
                .map_err(|_| SystemAuthorityLedgerError::InvalidCertificate)
        }

        /// Advance the durable retired high-water and clear the active claim
        /// only from replay's exact post-CAS receipt. Pledges, shares, and QCs
        /// are removed in the same transaction; the monotone meta record and
        /// last claim commitment permanently prevent sequence reuse.
        fn retire_published_claim(
            &self,
            published: PublishedSystemAuthorityClaim,
        ) -> Result<(), SystemAuthorityLedgerError> {
            self.retire_validated(published)
        }

        fn ensure_operational(&self) -> Result<(), SystemAuthorityLedgerError> {
            if self.is_fail_stopped()? {
                Err(SystemAuthorityLedgerError::FailStopped)
            } else {
                Ok(())
            }
        }

        fn ensure_reserved(
            &self,
            reserved: &ReservedSystemAuthorityClaim,
        ) -> Result<(), SystemAuthorityLedgerError> {
            self.ensure_operational()?;
            if reserved.record.route != self.route
                || reserved.record.journal_store != self.journal_store
            {
                return Err(SystemAuthorityLedgerError::WrongRoute);
            }
            reserved.record.validate()?;
            let bytes = read_exact(
                &self.database,
                RESERVATION_TABLE,
                route_storage_key(self.route).as_slice(),
            )?
            .ok_or(SystemAuthorityLedgerError::ClaimNotReserved)?;
            let existing = ReservationRecord::decode(&bytes)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            if existing != reserved.record {
                return Err(SystemAuthorityLedgerError::ClaimNotReserved);
            }
            Ok(())
        }

        fn ensure_reserved_read_only(
            &self,
            reserved: &ReservedSystemAuthorityClaim,
        ) -> Result<(), SystemAuthorityLedgerError> {
            if reserved.record.route != self.route
                || reserved.record.journal_store != self.journal_store
            {
                return Err(SystemAuthorityLedgerError::WrongRoute);
            }
            reserved.record.validate()?;
            let transaction = self.database.begin_read()?;
            let table = transaction.open_table(RESERVATION_TABLE)?;
            let bytes = table
                .get(route_storage_key(self.route).as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::ClaimNotReserved)?;
            let existing = ReservationRecord::decode(&bytes)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            if existing != reserved.record {
                return Err(SystemAuthorityLedgerError::ClaimNotReserved);
            }
            Ok(())
        }

        fn ensure_pending_read_only(
            &self,
            pending: &PendingSystemAuthorityRecovery,
        ) -> Result<(), SystemAuthorityLedgerError> {
            if pending.record.route != self.route
                || pending.record.journal_store != self.journal_store
            {
                return Err(SystemAuthorityLedgerError::WrongRoute);
            }
            pending.record.validate()?;
            let transaction = self.database.begin_read()?;
            let bytes = transaction
                .open_table(RESERVATION_TABLE)?
                .get(route_storage_key(self.route).as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::ClaimNotReserved)?;
            let active = ReservationRecord::decode(&bytes)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            if active != pending.record {
                return Err(SystemAuthorityLedgerError::ClaimNotReserved);
            }
            Ok(())
        }

        fn ensure_pledge(
            &self,
            reserved: &ReservedSystemAuthorityClaim,
        ) -> Result<(), SystemAuthorityLedgerError> {
            self.ensure_reserved(reserved)?;
            let _write = self.lock_writes()?;
            let sequence = reserved.record.request.sequence();
            let expected = PledgeRecord {
                route: self.route,
                local_signer: *self.local_signer.as_bytes(),
                sequence,
                claim: reserved.record.request.claim(),
            };
            expected.validate()?;
            let key = pledge_storage_key(self.route, self.local_signer.as_bytes(), sequence);
            let transaction = self.database.begin_write()?;
            self.recheck_all(&transaction, reserved)?;
            let divergent = {
                let mut table = transaction.open_table(PLEDGE_TABLE)?;
                let existing = table
                    .get(key.as_slice())?
                    .map(|value| value.value().to_vec());
                if let Some(bytes) = existing {
                    let existing = PledgeRecord::decode(&bytes)
                        .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                    if existing != expected {
                        Some((existing.claim.claim_hash(), expected.claim.claim_hash()))
                    } else {
                        None
                    }
                } else {
                    table.insert(key.as_slice(), expected.encode().as_slice())?;
                    None
                }
            };
            if let Some((existing, expected)) = divergent {
                let fail_stop =
                    FailStopRecord::for_conflict(self.route, sequence, existing, expected)?;
                let mut failures = transaction.open_table(FAIL_STOP_TABLE)?;
                let route_key = route_storage_key(self.route);
                let already_failed = failures.get(route_key.as_slice())?.is_some();
                if !already_failed {
                    failures.insert(route_key.as_slice(), fail_stop.encode().as_slice())?;
                }
                drop(failures);
                transaction.commit()?;
                return Err(SystemAuthorityLedgerError::DivergentPledge);
            }
            transaction.commit()?;
            Ok(())
        }

        fn record_share(
            &self,
            reserved: &ReservedSystemAuthorityClaim,
            leg: SystemAuthorityCommitteeLeg,
            share: AuthoritySignature,
            locally_pledged: bool,
        ) -> Result<SystemAuthorityShareOutcome, SystemAuthorityLedgerError> {
            self.ensure_reserved(reserved)?;
            let committee = reserved
                .record
                .request
                .committee(leg)
                .ok_or(SystemAuthorityLedgerError::WrongCommitteeLeg)?;
            let claim = reserved.record.request.claim();
            validate_share(committee, claim, &share)?;
            if locally_pledged {
                if share.signer() != self.local_signer
                    || self.pledged_claim(claim.sequence(), share.signer().as_bytes())?
                        != Some(claim)
                {
                    return Err(SystemAuthorityLedgerError::LocalShareRequiresPledge);
                }
            }
            let _write = self.lock_writes()?;
            let stored = StoredShare::from_share(self.route, claim.sequence(), leg, claim, &share)?;
            let key =
                share_storage_key(self.route, claim.sequence(), leg, share.signer().as_bytes());
            let transaction = self.database.begin_write()?;
            self.recheck_all(&transaction, reserved)?;
            if locally_pledged {
                let pledge_key =
                    pledge_storage_key(self.route, share.signer().as_bytes(), claim.sequence());
                let pledge = transaction
                    .open_table(PLEDGE_TABLE)?
                    .get(pledge_key.as_slice())?
                    .map(|value| value.value().to_vec())
                    .ok_or(SystemAuthorityLedgerError::LocalShareRequiresPledge)?;
                let pledge = PledgeRecord::decode(&pledge)
                    .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                if pledge.claim != claim {
                    return Err(SystemAuthorityLedgerError::LocalShareRequiresPledge);
                }
            } else {
                let config_key = config_storage_key(self.route, share.signer().as_bytes());
                if transaction
                    .open_table(CONFIG_TABLE)?
                    .get(config_key.as_slice())?
                    .is_some()
                {
                    return Err(SystemAuthorityLedgerError::LocalShareRequiresPledge);
                }
            }

            let mut shares = Vec::new();
            {
                let mut table = transaction.open_table(SHARE_TABLE)?;
                if let Some(bytes) = table
                    .get(key.as_slice())?
                    .map(|value| value.value().to_vec())
                {
                    let existing = StoredShare::decode(&bytes)
                        .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                    if existing != stored {
                        return Err(SystemAuthorityLedgerError::ConflictingShare);
                    }
                } else {
                    table.insert(key.as_slice(), stored.encode().as_slice())?;
                }
                let prefix = leg_storage_key(self.route, claim.sequence(), leg);
                for row in table.range(prefix.as_slice()..)? {
                    let (row_key, row_value) = row?;
                    if !row_key.value().starts_with(prefix.as_slice()) {
                        break;
                    }
                    if shares.len() == 256 {
                        return Err(SystemAuthorityLedgerError::BacklogLimit);
                    }
                    let row = StoredShare::decode(row_value.value())
                        .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                    if row_key.value()
                        != share_storage_key(self.route, claim.sequence(), leg, &row.signer)
                            .as_slice()
                        || row.route != self.route
                        || row.sequence != claim.sequence()
                        || row.leg != leg
                        || row.claim != claim
                    {
                        return Err(SystemAuthorityLedgerError::CorruptLedger);
                    }
                    shares.push(row.to_share(committee, claim)?);
                }
            }
            shares.sort_by_key(|share| *share.signer().as_bytes());
            if shares
                .windows(2)
                .any(|pair| pair[0].signer().as_bytes() >= pair[1].signer().as_bytes())
            {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }

            let qc_key = leg_storage_key(self.route, claim.sequence(), leg);
            let existing_qc = transaction
                .open_table(QC_TABLE)?
                .get(qc_key.as_slice())?
                .map(|value| value.value().to_vec());
            let certificate = if let Some(bytes) = existing_qc {
                let row = CertificateRecord::decode(&bytes)
                    .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                row.validate_for(self.route, claim.sequence(), leg, committee, claim)?;
                Some(row.certificate)
            } else if shares.len() >= committee.quorum_threshold() {
                let certificate = AuthorityQuorumCertificate::new(committee, claim, shares)
                    .map_err(SystemAuthorityLedgerError::Authority)?;
                certificate
                    .verify(committee, claim)
                    .map_err(SystemAuthorityLedgerError::Authority)?;
                let row = CertificateRecord {
                    route: self.route,
                    sequence: claim.sequence(),
                    leg,
                    claim,
                    certificate: certificate.clone(),
                };
                row.validate()?;
                transaction
                    .open_table(QC_TABLE)?
                    .insert(qc_key.as_slice(), row.encode().as_slice())?;
                Some(certificate)
            } else {
                None
            };
            transaction.commit()?;
            Ok(SystemAuthorityShareOutcome { share, certificate })
        }

        fn share_for(
            &self,
            reserved: &ReservedSystemAuthorityClaim,
            leg: SystemAuthorityCommitteeLeg,
            signer: &[u8; 32],
        ) -> Result<Option<AuthoritySignature>, SystemAuthorityLedgerError> {
            let claim = reserved.record.request.claim();
            let Some(committee) = reserved.record.request.committee(leg) else {
                return Err(SystemAuthorityLedgerError::WrongCommitteeLeg);
            };
            let key = share_storage_key(self.route, claim.sequence(), leg, signer);
            let Some(bytes) = read_exact(&self.database, SHARE_TABLE, key.as_slice())? else {
                return Ok(None);
            };
            let row = StoredShare::decode(&bytes)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            if row.route != self.route
                || row.sequence != claim.sequence()
                || row.leg != leg
                || row.claim != claim
                || &row.signer != signer
            {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            row.to_share(committee, claim).map(Some)
        }

        fn certificate_for(
            &self,
            reserved: &ReservedSystemAuthorityClaim,
            leg: SystemAuthorityCommitteeLeg,
        ) -> Result<Option<AuthorityQuorumCertificate>, SystemAuthorityLedgerError> {
            self.certificate_for_record(&reserved.record, leg)
        }

        fn certificate_for_record(
            &self,
            record: &ReservationRecord,
            leg: SystemAuthorityCommitteeLeg,
        ) -> Result<Option<AuthorityQuorumCertificate>, SystemAuthorityLedgerError> {
            let claim = record.request.claim();
            let Some(committee) = record.request.committee(leg) else {
                return Err(SystemAuthorityLedgerError::WrongCommitteeLeg);
            };
            let key = leg_storage_key(self.route, claim.sequence(), leg);
            let Some(bytes) = read_exact(&self.database, QC_TABLE, key.as_slice())? else {
                return Ok(None);
            };
            let row = CertificateRecord::decode(&bytes)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            row.validate_for(self.route, claim.sequence(), leg, committee, claim)?;
            Ok(Some(row.certificate))
        }

        fn pledged_claim(
            &self,
            sequence: u64,
            signer: &[u8; 32],
        ) -> Result<Option<AuthorityClaimCommitment>, SystemAuthorityLedgerError> {
            let key = pledge_storage_key(self.route, signer, sequence);
            let Some(bytes) = read_exact(&self.database, PLEDGE_TABLE, key.as_slice())? else {
                return Ok(None);
            };
            let pledge = PledgeRecord::decode(&bytes)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            if pledge.route != self.route
                || pledge.local_signer != *signer
                || pledge.sequence != sequence
            {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            Ok(Some(pledge.claim))
        }

        fn retire_validated(
            &self,
            published: PublishedSystemAuthorityClaim,
        ) -> Result<(), SystemAuthorityLedgerError> {
            let reserved = &published.reservation;
            if reserved.route != self.route
                || published.journal_store != self.journal_store
                || reserved.journal_store != self.journal_store
                || published.successor_heads == JournalHeadsId::ZERO
                || published.successor_heads == reserved.predecessor_heads
                || published.successor_control == LaneStateId::ZERO
                || published.successor_control == reserved.control_state
                || published.successor_view == Hash::ZERO
                || published.successor_authority_state == Hash::ZERO
                || published.resulting_high_water != reserved.request.sequence()
            {
                return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
            }
            let request = &reserved.request;
            match request {
                SystemAuthorityLedgerClaim::AgentGenesis { committee, .. } => {
                    if published.resulting_first_sequence.is_some()
                        || published.resulting_committee != committee.commitment()
                    {
                        return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
                    }
                }
                SystemAuthorityLedgerClaim::CommitteeRotation {
                    incoming,
                    transition,
                    ..
                } => {
                    if published.resulting_first_sequence != Some(transition.first_sequence())
                        || published.resulting_committee != incoming.commitment()
                    {
                        return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
                    }
                }
            }

            let _write = self.lock_writes()?;
            let route_key = route_storage_key(self.route);
            let sequence = request.sequence();
            let claim = request.claim();
            let transaction = self.database.begin_write()?;
            self.recheck_config(&transaction)?;
            let current_meta = transaction
                .open_table(META_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::CorruptLedger)?;
            let current_meta = MetaRecord::decode(&current_meta)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;

            let active = transaction
                .open_table(RESERVATION_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec());
            if active.is_none()
                && current_meta.retired_high_water == sequence
                && current_meta.journal_store == self.journal_store
                && current_meta.authority_state == published.successor_authority_state
                && current_meta.last_claim == Some(claim.claim_hash())
                && current_meta.last_publication
                    == Some(LastPublication {
                        predecessor_heads: reserved.predecessor_heads,
                        successor_heads: published.successor_heads,
                        successor_control: published.successor_control,
                        successor_view: published.successor_view,
                    })
            {
                return Ok(());
            }
            let active = active.ok_or(SystemAuthorityLedgerError::ClaimNotReserved)?;
            let active = ReservationRecord::decode(&active)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            if active != *reserved
                || current_meta.route != self.route
                || current_meta.retired_high_water != active.prior_high_water
                || current_meta.journal_store != self.journal_store
                || current_meta.authority_state != active.authority_state
            {
                return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
            }

            // A published operation must have crossed every threshold. Read
            // and verify the frozen QCs inside this same retirement snapshot.
            for leg in request.legs() {
                let committee = request
                    .committee(*leg)
                    .ok_or(SystemAuthorityLedgerError::WrongCommitteeLeg)?;
                let key = leg_storage_key(self.route, sequence, *leg);
                let bytes = transaction
                    .open_table(QC_TABLE)?
                    .get(key.as_slice())?
                    .map(|value| value.value().to_vec())
                    .ok_or(SystemAuthorityLedgerError::CertificateNotReady)?;
                let row = CertificateRecord::decode(&bytes)
                    .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                row.validate_for(self.route, sequence, *leg, committee, claim)?;
            }

            let next_meta = MetaRecord {
                route: self.route,
                journal_store: self.journal_store,
                retired_high_water: sequence,
                authority_state: published.successor_authority_state,
                last_claim: Some(claim.claim_hash()),
                last_publication: Some(LastPublication {
                    predecessor_heads: active.predecessor_heads,
                    successor_heads: published.successor_heads,
                    successor_control: published.successor_control,
                    successor_view: published.successor_view,
                }),
            };
            next_meta.validate()?;
            {
                transaction
                    .open_table(META_TABLE)?
                    .insert(route_key.as_slice(), next_meta.encode().as_slice())?;
            }
            {
                transaction
                    .open_table(RESERVATION_TABLE)?
                    .remove(route_key.as_slice())?;
            }

            // The HWM is now the permanent anti-reuse record. Remove bounded
            // active evidence atomically so every later reservation starts
            // with no stale claim rows.
            let pledge_keys = {
                let table = transaction.open_table(PLEDGE_TABLE)?;
                let mut keys = Vec::new();
                for row in table.range(route_key.as_slice()..)? {
                    let (key, _) = row?;
                    if !key.value().starts_with(route_key.as_slice()) {
                        break;
                    }
                    if key.value().len() != PLEDGE_KEY_BYTES {
                        return Err(SystemAuthorityLedgerError::CorruptLedger);
                    }
                    if key.value()[PLEDGE_KEY_BYTES - 8..] == sequence.to_be_bytes() {
                        keys.push(key.value().to_vec());
                    }
                }
                keys
            };
            {
                let mut table = transaction.open_table(PLEDGE_TABLE)?;
                for key in pledge_keys {
                    table.remove(key.as_slice())?;
                }
            }
            let claim_prefix = claim_storage_prefix(self.route, sequence);
            for definition in [SHARE_TABLE, QC_TABLE] {
                let keys = {
                    let table = transaction.open_table(definition)?;
                    let mut keys = Vec::new();
                    for row in table.range(claim_prefix.as_slice()..)? {
                        let (key, _) = row?;
                        if !key.value().starts_with(claim_prefix.as_slice()) {
                            break;
                        }
                        keys.push(key.value().to_vec());
                    }
                    keys
                };
                let mut table = transaction.open_table(definition)?;
                for key in keys {
                    table.remove(key.as_slice())?;
                }
            }
            transaction.commit()?;
            Ok(())
        }

        /// Reclassifying a signer from remote to local is safe only when each
        /// retained share from that signer already crossed the exact global-H
        /// pledge boundary. `open` calls this while holding the same redb
        /// writer transaction that installs Config, so neither reservation nor
        /// share admission can race the classification change.
        fn recheck_local_signer_installation(
            &self,
            transaction: &redb::WriteTransaction,
        ) -> Result<(), SystemAuthorityLedgerError> {
            let route_key = route_storage_key(self.route);
            let candidate = *self.local_signer.as_bytes();
            let mut retained = Vec::new();
            {
                let table = transaction.open_table(SHARE_TABLE)?;
                let mut rows = 0_usize;
                for row in table.range(route_key.as_slice()..)? {
                    let (key, value) = row?;
                    if !key.value().starts_with(route_key.as_slice()) {
                        break;
                    }
                    if rows == MAX_SHARE_ROWS_PER_CLAIM {
                        return Err(SystemAuthorityLedgerError::BacklogLimit);
                    }
                    rows += 1;
                    let share = StoredShare::decode(value.value())
                        .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                    if key.value()
                        != share_storage_key(self.route, share.sequence, share.leg, &share.signer)
                            .as_slice()
                        || share.route != self.route
                    {
                        return Err(SystemAuthorityLedgerError::CorruptLedger);
                    }
                    if share.signer == candidate {
                        retained.push((share.sequence, share.claim));
                    }
                }
            }
            for (sequence, claim) in retained {
                let key = pledge_storage_key(self.route, &candidate, sequence);
                let pledge = transaction
                    .open_table(PLEDGE_TABLE)?
                    .get(key.as_slice())?
                    .map(|value| value.value().to_vec())
                    .ok_or(SystemAuthorityLedgerError::LocalShareRequiresPledge)?;
                let pledge = PledgeRecord::decode(&pledge)
                    .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                if pledge
                    != (PledgeRecord {
                        route: self.route,
                        local_signer: candidate,
                        sequence,
                        claim,
                    })
                {
                    return Err(SystemAuthorityLedgerError::LocalShareRequiresPledge);
                }
            }
            Ok(())
        }

        fn recheck_config(
            &self,
            transaction: &redb::WriteTransaction,
        ) -> Result<(), SystemAuthorityLedgerError> {
            let key = config_storage_key(self.route, self.local_signer.as_bytes());
            let bytes = transaction
                .open_table(CONFIG_TABLE)?
                .get(key.as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::ConfigurationMismatch)?;
            let config = ConfigRecord::decode(&bytes)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            if config.version != LEDGER_SCHEMA_VERSION
                || config.route != self.route
                || config.journal_store != self.journal_store
                || config.local_node != self.local_node
                || config.local_signer != *self.local_signer.as_bytes()
            {
                return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
            }
            Ok(())
        }

        fn validate_local_voter(
            &self,
            request: &SystemAuthorityLedgerClaim,
        ) -> Result<(), SystemAuthorityLedgerError> {
            if request.legs().iter().any(|leg| {
                request.committee(*leg).is_some_and(|committee| {
                    committee.member(self.local_signer).is_some_and(|member| {
                        member.node() == self.local_node
                            && member.role() == AuthorityMemberRole::Voter
                    })
                })
            }) {
                Ok(())
            } else {
                Err(SystemAuthorityLedgerError::LocalSignerNotVoter)
            }
        }

        fn recheck_all(
            &self,
            transaction: &redb::WriteTransaction,
            reserved: &ReservedSystemAuthorityClaim,
        ) -> Result<(), SystemAuthorityLedgerError> {
            self.recheck_config(transaction)?;
            let route_key = route_storage_key(self.route);
            if transaction
                .open_table(FAIL_STOP_TABLE)?
                .get(route_key.as_slice())?
                .is_some()
            {
                return Err(SystemAuthorityLedgerError::FailStopped);
            }
            let bytes = transaction
                .open_table(RESERVATION_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::ClaimNotReserved)?;
            let active = ReservationRecord::decode(&bytes)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            if active != reserved.record {
                return Err(SystemAuthorityLedgerError::ClaimNotReserved);
            }
            Ok(())
        }

        fn lock_writes(&self) -> Result<std::sync::MutexGuard<'_, ()>, SystemAuthorityLedgerError> {
            self.writes
                .lock()
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)
        }

        fn audit_recovery_preflight(&self) -> Result<(), SystemAuthorityLedgerError> {
            self.audit_recovery_inner(false, true)
        }

        fn audit_recovery_inner(
            &self,
            require_local_config: bool,
            allow_missing_tables: bool,
        ) -> Result<(), SystemAuthorityLedgerError> {
            let route_key = route_storage_key(self.route);
            let config_rows = rows_for_prefix_bounded_maybe_missing(
                &self.database,
                CONFIG_TABLE,
                route_key.as_slice(),
                MAX_LOCAL_SIGNERS_PER_SCOPE,
                allow_missing_tables,
            )?;
            let mut configured = alloc::collections::BTreeSet::new();
            for (key, bytes) in config_rows {
                let config = ConfigRecord::decode(&bytes)
                    .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                if key != config_storage_key(config.route, &config.local_signer)
                    || config.route != self.route
                    || !configured.insert(config.local_signer)
                {
                    return Err(SystemAuthorityLedgerError::CorruptLedger);
                }
                if config.journal_store != self.journal_store
                    || config.local_node != self.local_node
                {
                    return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
                }
                config.validate()?;
            }
            if require_local_config && !configured.contains(self.local_signer.as_bytes()) {
                return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
            }

            let meta = read_exact_maybe_missing(
                &self.database,
                META_TABLE,
                route_key.as_slice(),
                allow_missing_tables,
            )?
            .map(|bytes| {
                MetaRecord::decode(&bytes).map_err(|_| SystemAuthorityLedgerError::CorruptLedger)
            })
            .transpose()?;
            if let Some(meta) = &meta {
                if meta.route != self.route || meta.journal_store != self.journal_store {
                    return Err(SystemAuthorityLedgerError::CorruptLedger);
                }
                meta.validate()?;
            }
            let reservation = read_exact_maybe_missing(
                &self.database,
                RESERVATION_TABLE,
                route_key.as_slice(),
                allow_missing_tables,
            )?
            .map(|bytes| {
                ReservationRecord::decode(&bytes)
                    .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)
            })
            .transpose()?;
            if let Some(reservation) = &reservation {
                reservation.validate()?;
                let meta = meta
                    .as_ref()
                    .ok_or(SystemAuthorityLedgerError::CorruptLedger)?;
                if reservation.route != self.route
                    || reservation.journal_store != self.journal_store
                    || meta.journal_store != self.journal_store
                    || reservation.prior_high_water != meta.retired_high_water
                    || reservation.authority_state != meta.authority_state
                {
                    return Err(SystemAuthorityLedgerError::CorruptLedger);
                }
            }

            let pledge_rows = rows_for_prefix_bounded_maybe_missing(
                &self.database,
                PLEDGE_TABLE,
                route_key.as_slice(),
                MAX_LOCAL_SIGNERS_PER_SCOPE,
                allow_missing_tables,
            )?;
            let share_rows = rows_for_prefix_bounded_maybe_missing(
                &self.database,
                SHARE_TABLE,
                route_key.as_slice(),
                MAX_SHARE_ROWS_PER_CLAIM,
                allow_missing_tables,
            )?;
            let qc_rows = rows_for_prefix_bounded_maybe_missing(
                &self.database,
                QC_TABLE,
                route_key.as_slice(),
                MAX_QC_ROWS_PER_CLAIM,
                allow_missing_tables,
            )?;
            let has_reservation = reservation.is_some();
            let has_evidence_rows =
                !pledge_rows.is_empty() || !share_rows.is_empty() || !qc_rows.is_empty();
            if !has_reservation && has_evidence_rows {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            if let Some(reservation) = reservation {
                let request = &reservation.request;
                let claim = request.claim();
                let mut pledges = alloc::collections::BTreeMap::new();
                for (key, bytes) in pledge_rows {
                    let pledge = PledgeRecord::decode(&bytes)
                        .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                    if key != pledge_storage_key(self.route, &pledge.local_signer, pledge.sequence)
                        || pledge.route != self.route
                        || pledge.sequence != claim.sequence()
                        || pledge.claim != claim
                        || !configured.contains(&pledge.local_signer)
                        || pledges
                            .insert(pledge.local_signer, pledge.clone())
                            .is_some()
                    {
                        return Err(SystemAuthorityLedgerError::CorruptLedger);
                    }
                    let voter_in_a_leg = request.legs().iter().any(|leg| {
                        request.committee(*leg).is_some_and(|committee| {
                            committee.members().iter().any(|member| {
                                member.signer().as_bytes() == &pledge.local_signer
                                    && member.node() == self.local_node
                                    && member.role() == AuthorityMemberRole::Voter
                            })
                        })
                    });
                    if !voter_in_a_leg {
                        return Err(SystemAuthorityLedgerError::CorruptLedger);
                    }
                }

                let mut shares = alloc::collections::BTreeMap::new();
                for (key, bytes) in share_rows {
                    let row = StoredShare::decode(&bytes)
                        .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                    let committee = request
                        .committee(row.leg)
                        .ok_or(SystemAuthorityLedgerError::CorruptLedger)?;
                    if key != share_storage_key(self.route, row.sequence, row.leg, &row.signer)
                        || row.route != self.route
                        || row.sequence != claim.sequence()
                        || row.claim != claim
                        || shares.insert((row.leg, row.signer), row.clone()).is_some()
                    {
                        return Err(SystemAuthorityLedgerError::CorruptLedger);
                    }
                    row.to_share(committee, claim)?;
                    if configured.contains(&row.signer)
                        && pledges
                            .get(&row.signer)
                            .is_none_or(|pledge| pledge.claim != claim)
                    {
                        return Err(SystemAuthorityLedgerError::CorruptLedger);
                    }
                }

                let mut certificates = alloc::collections::BTreeSet::new();
                for (key, bytes) in qc_rows {
                    let row = CertificateRecord::decode(&bytes)
                        .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                    let committee = request
                        .committee(row.leg)
                        .ok_or(SystemAuthorityLedgerError::CorruptLedger)?;
                    if key != leg_storage_key(self.route, row.sequence, row.leg)
                        || !certificates.insert(row.leg)
                    {
                        return Err(SystemAuthorityLedgerError::CorruptLedger);
                    }
                    row.validate_for(self.route, claim.sequence(), row.leg, committee, claim)?;
                    for signature in row.certificate.signatures() {
                        let stored = shares
                            .get(&(row.leg, *signature.signer().as_bytes()))
                            .ok_or(SystemAuthorityLedgerError::CorruptLedger)?;
                        if stored.signature != *signature.signature() {
                            return Err(SystemAuthorityLedgerError::CorruptLedger);
                        }
                    }
                }
            }
            let failure = read_exact_maybe_missing(
                &self.database,
                FAIL_STOP_TABLE,
                route_key.as_slice(),
                allow_missing_tables,
            )?;
            if configured.is_empty()
                && (meta.is_some() || has_reservation || has_evidence_rows || failure.is_some())
            {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            if let Some(bytes) = failure {
                let record = FailStopRecord::decode(&bytes)
                    .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                if record.route != self.route {
                    return Err(SystemAuthorityLedgerError::CorruptLedger);
                }
                record.validate()?;
            }
            Ok(())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ConfigRecord {
        version: u32,
        route: SystemAuthorityLedgerRoute,
        journal_store: JournalStoreInstanceId,
        local_node: NodeId,
        local_signer: [u8; 32],
    }

    impl ConfigRecord {
        fn validate(&self) -> Result<(), SystemAuthorityLedgerError> {
            self.route.validate()?;
            if self.version != LEDGER_SCHEMA_VERSION
                || self.local_node == NodeId::ZERO
                || self.local_signer == [0; 32]
                || JournalStoreInstanceId::from_bytes(*self.journal_store.as_bytes()).is_none()
                || self.encode().len() > MAX_CONFIG_RECORD_BYTES
            {
                return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
            }
            Ok(())
        }
    }

    impl ServiceWire for ConfigRecord {
        const MAGIC: [u8; 4] = *b"AULC";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encoder.u32(self.version);
            encoder.bytes(&self.route.encode());
            encoder.fixed(self.journal_store.as_bytes());
            encoder.fixed(&self.local_node.0);
            encoder.fixed(&self.local_signer);
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_CONFIG_RECORD_BYTES)?;
            let record = Self {
                version: decoder.u32()?,
                route: decode_nested(decoder, MAX_SYSTEM_AUTHORITY_LEDGER_ROUTE_BYTES)?,
                journal_store: JournalStoreInstanceId::from_bytes(decoder.fixed()?)
                    .ok_or(DecodeError::NonCanonical)?,
                local_node: NodeId(decoder.fixed()?),
                local_signer: decoder.fixed()?,
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct LastPublication {
        predecessor_heads: JournalHeadsId,
        successor_heads: JournalHeadsId,
        successor_control: LaneStateId,
        successor_view: Hash,
    }

    impl LastPublication {
        fn validate(&self) -> Result<(), SystemAuthorityLedgerError> {
            if self.predecessor_heads == JournalHeadsId::ZERO
                || self.successor_heads == JournalHeadsId::ZERO
                || self.predecessor_heads == self.successor_heads
                || self.successor_control == LaneStateId::ZERO
                || self.successor_view == Hash::ZERO
            {
                Err(SystemAuthorityLedgerError::CorruptLedger)
            } else {
                Ok(())
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct MetaRecord {
        route: SystemAuthorityLedgerRoute,
        journal_store: JournalStoreInstanceId,
        retired_high_water: u64,
        authority_state: Hash,
        last_claim: Option<Hash>,
        last_publication: Option<LastPublication>,
    }

    impl MetaRecord {
        fn validate(&self) -> Result<(), SystemAuthorityLedgerError> {
            self.route.validate()?;
            if self.retired_high_water == 0
                || JournalStoreInstanceId::from_bytes(*self.journal_store.as_bytes()).is_none()
                || self.authority_state == Hash::ZERO
                || self.last_claim == Some(Hash::ZERO)
                || self.last_claim.is_some() != self.last_publication.is_some()
                || self.encode().len() > MAX_META_RECORD_BYTES
            {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            if let Some(publication) = &self.last_publication {
                publication.validate()?;
            }
            Ok(())
        }
    }

    impl ServiceWire for MetaRecord {
        const MAGIC: [u8; 4] = *b"AULM";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encoder.bytes(&self.route.encode());
            encoder.fixed(self.journal_store.as_bytes());
            encoder.u64(self.retired_high_water);
            encoder.fixed(&self.authority_state.0);
            encoder.option(&self.last_claim, |encoder, claim| encoder.fixed(&claim.0));
            encoder.option(&self.last_publication, |encoder, publication| {
                encoder.fixed(publication.predecessor_heads.as_bytes());
                encoder.fixed(publication.successor_heads.as_bytes());
                encoder.fixed(publication.successor_control.as_bytes());
                encoder.fixed(&publication.successor_view.0);
            });
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_META_RECORD_BYTES)?;
            let record = Self {
                route: decode_nested(decoder, MAX_SYSTEM_AUTHORITY_LEDGER_ROUTE_BYTES)?,
                journal_store: JournalStoreInstanceId::from_bytes(decoder.fixed()?)
                    .ok_or(DecodeError::NonCanonical)?,
                retired_high_water: decoder.u64()?,
                authority_state: Hash(decoder.fixed()?),
                last_claim: decoder.option(|decoder| Ok(Hash(decoder.fixed()?)))?,
                last_publication: decoder.option(|decoder| {
                    Ok(LastPublication {
                        predecessor_heads: JournalHeadsId::new(decoder.fixed()?),
                        successor_heads: JournalHeadsId::new(decoder.fixed()?),
                        successor_control: LaneStateId::new(decoder.fixed()?),
                        successor_view: Hash(decoder.fixed()?),
                    })
                })?,
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ReservationRecord {
        route: SystemAuthorityLedgerRoute,
        journal_store: JournalStoreInstanceId,
        predecessor_heads: JournalHeadsId,
        state_view: Hash,
        authority_state: Hash,
        control_state: LaneStateId,
        prior_high_water: u64,
        prior_first_sequence: Option<u64>,
        request: SystemAuthorityLedgerClaim,
    }

    impl ReservationRecord {
        fn for_view(
            route: SystemAuthorityLedgerRoute,
            view: &ReplayedSystemAuthorityView,
            request: SystemAuthorityLedgerClaim,
        ) -> Result<Self, SystemAuthorityLedgerError> {
            let record = Self {
                route,
                journal_store: view.journal_store(),
                predecessor_heads: view.heads(),
                state_view: view.commitment(),
                authority_state: view.authority_state_commitment(),
                control_state: view.control_state(),
                prior_high_water: view.committee_sequence_high_water(),
                prior_first_sequence: view.rotation_first_sequence(),
                request,
            };
            record.validate()?;
            Ok(record)
        }

        fn validate(&self) -> Result<(), SystemAuthorityLedgerError> {
            self.route.validate()?;
            self.request.validate()?;
            let sequence = self.request.sequence();
            if self.state_view == Hash::ZERO
                || self.authority_state == Hash::ZERO
                || JournalStoreInstanceId::from_bytes(*self.journal_store.as_bytes()).is_none()
                || self.predecessor_heads == JournalHeadsId::ZERO
                || self.control_state == LaneStateId::ZERO
                || self.prior_high_water == 0
                || self
                    .prior_first_sequence
                    .is_some_and(|first| first <= self.prior_high_water)
                || self.encode().len() > MAX_RESERVATION_RECORD_BYTES
            {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            match &self.request {
                SystemAuthorityLedgerClaim::AgentGenesis {
                    committee, claim, ..
                } => {
                    let valid_sequence = match self.prior_first_sequence {
                        Some(first) => sequence == first,
                        None => sequence > self.prior_high_water,
                    };
                    if !valid_sequence
                        || committee.space() != self.route.space
                        || committee.authority_binding() != self.route.authority_binding
                        || claim.system_agent() != self.route.system_agent
                        || claim.system_genesis() != self.route.system_genesis
                        || claim.system_admission() != self.route.agent_admission
                        || claim.space() != self.route.space
                        || claim.authority_binding() != self.route.authority_binding
                    {
                        return Err(SystemAuthorityLedgerError::CorruptLedger);
                    }
                }
                SystemAuthorityLedgerClaim::CommitteeRotation {
                    retiring,
                    incoming,
                    transition,
                } => {
                    let valid_sequence = match self.prior_first_sequence {
                        Some(first) => sequence == first,
                        None => sequence > self.prior_high_water,
                    };
                    if !valid_sequence
                        || retiring.space() != self.route.space
                        || incoming.space() != self.route.space
                        || retiring.authority_binding() != self.route.authority_binding
                        || incoming.authority_binding() != self.route.authority_binding
                        || transition.root_anchor() != self.route.root_anchor
                        || transition.root_anchor_config_version()
                            != self.route.root_anchor_config_version
                        || transition.root_anchor_config() != self.route.root_anchor_config
                        || transition.authority_scope() != self.route.authority_scope
                    {
                        return Err(SystemAuthorityLedgerError::CorruptLedger);
                    }
                }
            }
            Ok(())
        }
    }

    impl ServiceWire for ReservationRecord {
        const MAGIC: [u8; 4] = *b"AULV";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encoder.bytes(&self.route.encode());
            encoder.fixed(self.journal_store.as_bytes());
            encoder.fixed(self.predecessor_heads.as_bytes());
            encoder.fixed(&self.state_view.0);
            encoder.fixed(&self.authority_state.0);
            encoder.fixed(self.control_state.as_bytes());
            encoder.u64(self.prior_high_water);
            encoder.option(&self.prior_first_sequence, |encoder, sequence| {
                encoder.u64(*sequence)
            });
            encoder.bytes(&self.request.encode());
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_RESERVATION_RECORD_BYTES)?;
            let record = Self {
                route: decode_nested(decoder, MAX_SYSTEM_AUTHORITY_LEDGER_ROUTE_BYTES)?,
                journal_store: JournalStoreInstanceId::from_bytes(decoder.fixed()?)
                    .ok_or(DecodeError::NonCanonical)?,
                predecessor_heads: JournalHeadsId::new(decoder.fixed()?),
                state_view: Hash(decoder.fixed()?),
                authority_state: Hash(decoder.fixed()?),
                control_state: LaneStateId::new(decoder.fixed()?),
                prior_high_water: decoder.u64()?,
                prior_first_sequence: decoder.option(Decoder::u64)?,
                request: decode_nested(decoder, MAX_SYSTEM_AUTHORITY_LEDGER_CLAIM_BYTES)?,
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct PledgeRecord {
        route: SystemAuthorityLedgerRoute,
        local_signer: [u8; 32],
        sequence: u64,
        claim: AuthorityClaimCommitment,
    }

    impl PledgeRecord {
        fn validate(&self) -> Result<(), SystemAuthorityLedgerError> {
            self.route.validate()?;
            if self.local_signer == [0; 32]
                || self.sequence == 0
                || self.sequence != self.claim.sequence()
                || self.claim.payload_commitment() == Hash::ZERO
                || self.encode().len() > MAX_PLEDGE_RECORD_BYTES
            {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            Ok(())
        }
    }

    impl ServiceWire for PledgeRecord {
        const MAGIC: [u8; 4] = *b"AULP";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encoder.bytes(&self.route.encode());
            encoder.fixed(&self.local_signer);
            encoder.u64(self.sequence);
            encode_authority_claim(&mut encoder, self.claim);
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_PLEDGE_RECORD_BYTES)?;
            let record = Self {
                route: decode_nested(decoder, MAX_SYSTEM_AUTHORITY_LEDGER_ROUTE_BYTES)?,
                local_signer: decoder.fixed()?,
                sequence: decoder.u64()?,
                claim: decode_authority_claim(decoder)?,
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct StoredShare {
        route: SystemAuthorityLedgerRoute,
        sequence: u64,
        leg: SystemAuthorityCommitteeLeg,
        claim: AuthorityClaimCommitment,
        signer: [u8; 32],
        signature: [u8; 64],
    }

    impl StoredShare {
        fn from_share(
            route: SystemAuthorityLedgerRoute,
            sequence: u64,
            leg: SystemAuthorityCommitteeLeg,
            claim: AuthorityClaimCommitment,
            share: &AuthoritySignature,
        ) -> Result<Self, SystemAuthorityLedgerError> {
            let row = Self {
                route,
                sequence,
                leg,
                claim,
                signer: *share.signer().as_bytes(),
                signature: *share.signature(),
            };
            row.validate()?;
            Ok(row)
        }

        fn to_share(
            &self,
            committee: &AuthorityCommittee,
            claim: AuthorityClaimCommitment,
        ) -> Result<AuthoritySignature, SystemAuthorityLedgerError> {
            let member = committee
                .members()
                .iter()
                .find(|member| member.signer().as_bytes() == &self.signer)
                .ok_or(SystemAuthorityLedgerError::UnknownSigner)?;
            let share = AuthoritySignature::new(member.signer(), self.signature)
                .map_err(SystemAuthorityLedgerError::Authority)?;
            validate_share(committee, claim, &share)?;
            Ok(share)
        }

        fn validate(&self) -> Result<(), SystemAuthorityLedgerError> {
            self.route.validate()?;
            if self.sequence == 0
                || self.sequence != self.claim.sequence()
                || self.signer == [0; 32]
                || self.encode().len() > MAX_SHARE_RECORD_BYTES
            {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            Ok(())
        }
    }

    impl ServiceWire for StoredShare {
        const MAGIC: [u8; 4] = *b"AULS";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encoder.bytes(&self.route.encode());
            encoder.u64(self.sequence);
            encoder.u8(self.leg as u8);
            encode_authority_claim(&mut encoder, self.claim);
            encoder.fixed(&self.signer);
            encoder.0.extend_from_slice(&self.signature);
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_SHARE_RECORD_BYTES)?;
            let record = Self {
                route: decode_nested(decoder, MAX_SYSTEM_AUTHORITY_LEDGER_ROUTE_BYTES)?,
                sequence: decoder.u64()?,
                leg: decode_leg(decoder.u8()?)?,
                claim: decode_authority_claim(decoder)?,
                signer: decoder.fixed()?,
                signature: decoder
                    .take(64)?
                    .try_into()
                    .map_err(|_| DecodeError::Truncated)?,
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct CertificateRecord {
        route: SystemAuthorityLedgerRoute,
        sequence: u64,
        leg: SystemAuthorityCommitteeLeg,
        claim: AuthorityClaimCommitment,
        certificate: AuthorityQuorumCertificate,
    }

    impl CertificateRecord {
        fn validate(&self) -> Result<(), SystemAuthorityLedgerError> {
            self.route.validate()?;
            if self.sequence == 0
                || self.sequence != self.claim.sequence()
                || self.certificate.claim() != self.claim
                || self.encode().len() > MAX_QC_RECORD_BYTES
            {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            Ok(())
        }

        fn validate_for(
            &self,
            route: SystemAuthorityLedgerRoute,
            sequence: u64,
            leg: SystemAuthorityCommitteeLeg,
            committee: &AuthorityCommittee,
            claim: AuthorityClaimCommitment,
        ) -> Result<(), SystemAuthorityLedgerError> {
            self.validate()?;
            if self.route != route
                || self.sequence != sequence
                || self.leg != leg
                || self.claim != claim
            {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            self.certificate
                .verify(committee, claim)
                .map_err(SystemAuthorityLedgerError::Authority)
        }
    }

    impl ServiceWire for CertificateRecord {
        const MAGIC: [u8; 4] = *b"AUQC";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encoder.bytes(&self.route.encode());
            encoder.u64(self.sequence);
            encoder.u8(self.leg as u8);
            encode_authority_claim(&mut encoder, self.claim);
            encoder.bytes(&self.certificate.encode());
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_QC_RECORD_BYTES)?;
            let record = Self {
                route: decode_nested(decoder, MAX_SYSTEM_AUTHORITY_LEDGER_ROUTE_BYTES)?,
                sequence: decoder.u64()?,
                leg: decode_leg(decoder.u8()?)?,
                claim: decode_authority_claim(decoder)?,
                certificate: decode_nested(decoder, MAX_AUTHORITY_QC_WIRE_BYTES)?,
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct FailStopRecord {
        route: SystemAuthorityLedgerRoute,
        sequence: u64,
        expected: Hash,
        observed: Hash,
    }

    impl FailStopRecord {
        fn for_conflict(
            route: SystemAuthorityLedgerRoute,
            sequence: u64,
            expected: Hash,
            observed: Hash,
        ) -> Result<Self, SystemAuthorityLedgerError> {
            let record = Self {
                route,
                sequence,
                expected,
                observed,
            };
            record.validate()?;
            Ok(record)
        }

        fn validate(&self) -> Result<(), SystemAuthorityLedgerError> {
            self.route.validate()?;
            if self.sequence == 0
                || self.expected == Hash::ZERO
                || self.observed == Hash::ZERO
                || self.expected == self.observed
                || self.encode().len() > MAX_FAIL_STOP_RECORD_BYTES
            {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            Ok(())
        }
    }

    impl ServiceWire for FailStopRecord {
        const MAGIC: [u8; 4] = *b"AULF";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encoder.bytes(&self.route.encode());
            encoder.u64(self.sequence);
            encoder.fixed(&self.expected.0);
            encoder.fixed(&self.observed.0);
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_FAIL_STOP_RECORD_BYTES)?;
            let record = Self {
                route: decode_nested(decoder, MAX_SYSTEM_AUTHORITY_LEDGER_ROUTE_BYTES)?,
                sequence: decoder.u64()?,
                expected: Hash(decoder.fixed()?),
                observed: Hash(decoder.fixed()?),
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    #[derive(Debug)]
    pub(crate) enum SystemAuthorityLedgerError {
        Backend(Box<dyn core::error::Error + Send + Sync>),
        Wire(SystemAuthorityLedgerWireError),
        Authority(AuthorityCommitteeError),
        ConfigurationMismatch,
        InvalidLocalSigner,
        WrongRoute,
        StaleStateView,
        ClaimNotReserved,
        DivergentReservation,
        PublicationRecoveryRequired,
        DivergentPledge,
        FailStopped,
        WrongSigner,
        LocalSignerNotVoter,
        LocalSignerNodeMismatch,
        LocalShareRequiresPledge,
        ObserverSigner,
        UnknownSigner,
        InvalidSignature,
        WrongCommitteeLeg,
        ConflictingShare,
        InvalidCertificate,
        CertificateNotReady,
        InvalidPublicationReceipt,
        GcBlockedByPendingReservation,
        BacklogLimit,
        CorruptLedger,
    }

    impl fmt::Display for SystemAuthorityLedgerError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Backend(error) => write!(formatter, "authority ledger backend: {error}"),
                Self::Wire(error) => error.fmt(formatter),
                Self::Authority(error) => error.fmt(formatter),
                other => write!(formatter, "system authority ledger: {other:?}"),
            }
        }
    }

    impl core::error::Error for SystemAuthorityLedgerError {
        fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
            match self {
                Self::Backend(error) => Some(error.as_ref()),
                Self::Wire(error) => Some(error),
                Self::Authority(error) => Some(error),
                _ => None,
            }
        }
    }

    impl From<SystemAuthorityLedgerWireError> for SystemAuthorityLedgerError {
        fn from(error: SystemAuthorityLedgerWireError) -> Self {
            Self::Wire(error)
        }
    }

    impl From<AuthorityCommitteeError> for SystemAuthorityLedgerError {
        fn from(error: AuthorityCommitteeError) -> Self {
            Self::Authority(error)
        }
    }

    fn validate_share(
        committee: &AuthorityCommittee,
        claim: AuthorityClaimCommitment,
        share: &AuthoritySignature,
    ) -> Result<(), SystemAuthorityLedgerError> {
        committee
            .validate()
            .map_err(SystemAuthorityLedgerError::Authority)?;
        let member = committee
            .member(share.signer())
            .ok_or(SystemAuthorityLedgerError::UnknownSigner)?;
        if member.role() != AuthorityMemberRole::Voter {
            return Err(SystemAuthorityLedgerError::ObserverSigner);
        }
        let key = VerifyingKey::from_bytes(member.public_key())
            .map_err(|_| SystemAuthorityLedgerError::InvalidSignature)?;
        let signature = ed25519_dalek::Signature::from_slice(share.signature())
            .map_err(|_| SystemAuthorityLedgerError::InvalidSignature)?;
        let message = AuthorityQuorumCertificate::signing_message(
            committee.authority_binding(),
            committee.epoch(),
            committee.commitment(),
            claim,
        );
        key.verify_strict(&message.0, &signature)
            .map_err(|_| SystemAuthorityLedgerError::InvalidSignature)
    }

    fn route_storage_key(route: SystemAuthorityLedgerRoute) -> [u8; ROUTE_KEY_BYTES] {
        route.id().0
    }

    fn config_storage_key(
        route: SystemAuthorityLedgerRoute,
        signer: &[u8; 32],
    ) -> [u8; CONFIG_KEY_BYTES] {
        let mut key = [0_u8; CONFIG_KEY_BYTES];
        key[..ROUTE_KEY_BYTES].copy_from_slice(&route_storage_key(route));
        key[ROUTE_KEY_BYTES..].copy_from_slice(signer);
        key
    }

    fn pledge_storage_key(
        route: SystemAuthorityLedgerRoute,
        signer: &[u8; 32],
        sequence: u64,
    ) -> [u8; PLEDGE_KEY_BYTES] {
        let mut key = [0_u8; PLEDGE_KEY_BYTES];
        key[..ROUTE_KEY_BYTES].copy_from_slice(&route_storage_key(route));
        key[ROUTE_KEY_BYTES..ROUTE_KEY_BYTES + 32].copy_from_slice(signer);
        key[ROUTE_KEY_BYTES + 32..].copy_from_slice(&sequence.to_be_bytes());
        key
    }

    fn claim_storage_prefix(
        route: SystemAuthorityLedgerRoute,
        sequence: u64,
    ) -> [u8; CLAIM_PREFIX_BYTES] {
        let mut key = [0_u8; CLAIM_PREFIX_BYTES];
        key[..ROUTE_KEY_BYTES].copy_from_slice(&route_storage_key(route));
        key[ROUTE_KEY_BYTES..].copy_from_slice(&sequence.to_be_bytes());
        key
    }

    fn leg_storage_key(
        route: SystemAuthorityLedgerRoute,
        sequence: u64,
        leg: SystemAuthorityCommitteeLeg,
    ) -> [u8; LEG_KEY_BYTES] {
        let mut key = [0_u8; LEG_KEY_BYTES];
        key[..CLAIM_PREFIX_BYTES].copy_from_slice(&claim_storage_prefix(route, sequence));
        key[CLAIM_PREFIX_BYTES] = leg as u8;
        key
    }

    fn share_storage_key(
        route: SystemAuthorityLedgerRoute,
        sequence: u64,
        leg: SystemAuthorityCommitteeLeg,
        signer: &[u8; 32],
    ) -> [u8; SHARE_KEY_BYTES] {
        let mut key = [0_u8; SHARE_KEY_BYTES];
        key[..LEG_KEY_BYTES].copy_from_slice(&leg_storage_key(route, sequence, leg));
        key[LEG_KEY_BYTES..].copy_from_slice(signer);
        key
    }

    fn read_exact(
        database: &Database,
        definition: TableDefinition<&[u8], &[u8]>,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, SystemAuthorityLedgerError> {
        read_exact_maybe_missing(database, definition, key, false)
    }

    fn read_exact_maybe_missing(
        database: &Database,
        definition: TableDefinition<&[u8], &[u8]>,
        key: &[u8],
        allow_missing_table: bool,
    ) -> Result<Option<Vec<u8>>, SystemAuthorityLedgerError> {
        let transaction = database.begin_read()?;
        let table = match transaction.open_table(definition) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) if allow_missing_table => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Ok(table.get(key)?.map(|value| value.value().to_vec()))
    }

    fn rows_for_prefix_bounded(
        database: &Database,
        definition: TableDefinition<&[u8], &[u8]>,
        prefix: &[u8],
        maximum: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, SystemAuthorityLedgerError> {
        rows_for_prefix_bounded_maybe_missing(database, definition, prefix, maximum, false)
    }

    fn rows_for_prefix_bounded_maybe_missing(
        database: &Database,
        definition: TableDefinition<&[u8], &[u8]>,
        prefix: &[u8],
        maximum: usize,
        allow_missing_table: bool,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, SystemAuthorityLedgerError> {
        let transaction = database.begin_read()?;
        let table = match transaction.open_table(definition) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) if allow_missing_table => {
                return Ok(Vec::new());
            }
            Err(error) => return Err(error.into()),
        };
        let mut rows = Vec::new();
        for row in table.range(prefix..)? {
            let (key, value) = row?;
            if !key.value().starts_with(prefix) {
                break;
            }
            if rows.len() == maximum {
                return Err(SystemAuthorityLedgerError::BacklogLimit);
            }
            rows.push((key.value().to_vec(), value.value().to_vec()));
        }
        Ok(rows)
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

    fn decode_leg(value: u8) -> Result<SystemAuthorityCommitteeLeg, DecodeError> {
        match value {
            0 => Ok(SystemAuthorityCommitteeLeg::Current),
            1 => Ok(SystemAuthorityCommitteeLeg::Retiring),
            2 => Ok(SystemAuthorityCommitteeLeg::Incoming),
            _ => Err(DecodeError::InvalidTag),
        }
    }

    #[cfg(test)]
    mod tests {
        use alloc::sync::Arc;
        use alloc::vec;
        use alloc::vec::Vec;
        use core::cell::Cell;

        use super::*;
        use crate::agent::committee::{
            AuthorityCommitteeMember, AuthorityMemberRole, RootAnchorConfigCommitment, RootAnchorId,
        };
        use crate::agent::system_authority::{
            SystemAuthorityGenesis, SystemAuthorityRotation, SystemAuthorityRotationProof,
        };
        use crate::service::NodeId;
        use ed25519_dalek::{Signer as _, SigningKey};

        const SPACE: SpaceId = SpaceId([0x11; 32]);
        const SYSTEM_AGENT: AgentId = AgentId([0x12; 32]);
        const BINDING: Hash = Hash([0x13; 32]);
        const ROOT: RootAnchorId = RootAnchorId::from_bytes([0x14; 32]);
        const ROOT_CONFIG: RootAnchorConfigCommitment =
            RootAnchorConfigCommitment::from_bytes([0x15; 32]);
        const GENESIS: AgentJournalGenesisId = AgentJournalGenesisId::new([0x16; 32]);
        const ADMISSION: AgentGenesisAdmissionId = AgentGenesisAdmissionId::from_bytes([0x17; 32]);
        const HEADS_1: JournalHeadsId = JournalHeadsId::new([0x18; 32]);
        const HEADS_2: JournalHeadsId = JournalHeadsId::new([0x19; 32]);
        const HEADS_REBASE: JournalHeadsId = JournalHeadsId::new([0x1c; 32]);
        const CONTROL_1: LaneStateId = LaneStateId::new([0x1a; 32]);
        const CONTROL_2: LaneStateId = LaneStateId::new([0x1b; 32]);
        const CONTROL_REBASE: LaneStateId = LaneStateId::new([0x1d; 32]);
        const FOREIGN_GENESIS: AgentJournalGenesisId = AgentJournalGenesisId::new([0x1e; 32]);

        struct TempDirectory(std::path::PathBuf);

        impl TempDirectory {
            fn new(label: &str) -> Self {
                let path = std::env::temp_dir().join(alloc::format!(
                    "vos_authority_ledger_{label}_{}_{}",
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
                self.0.join("authority.redb")
            }
        }

        impl Drop for TempDirectory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn key(byte: u8) -> SigningKey {
            SigningKey::from_bytes(&[byte; 32])
        }

        fn committee(
            epoch: u64,
            previous: Option<Hash>,
            keys: &[(SigningKey, AuthorityMemberRole)],
        ) -> AuthorityCommittee {
            let mut members = keys
                .iter()
                .enumerate()
                .map(|(index, (key, role))| {
                    AuthorityCommitteeMember::new(
                        NodeId([(0x40 + index as u8).wrapping_add(key.to_bytes()[0]); 32]),
                        key.verifying_key().to_bytes(),
                        *role,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            members.sort_by_key(AuthorityCommitteeMember::signer);
            AuthorityCommittee::new(SPACE, BINDING, epoch, previous, members).unwrap()
        }

        fn signed_share(
            key: &SigningKey,
            committee: &AuthorityCommittee,
            claim: AuthorityClaimCommitment,
        ) -> AuthoritySignature {
            let message = AuthorityQuorumCertificate::signing_message(
                committee.authority_binding(),
                committee.epoch(),
                committee.commitment(),
                claim,
            );
            AuthoritySignature::new(
                AuthoritySignerId::of_raw_ed25519(&key.verifying_key().to_bytes()),
                key.sign(&message.0).to_bytes(),
            )
            .unwrap()
        }

        struct Fixture {
            state: SystemAuthorityState,
            scope: SystemAuthorityJournalScope,
            route: SystemAuthorityLedgerRoute,
            store: JournalStoreInstanceId,
            view: ReplayedSystemAuthorityView,
            old: AuthorityCommittee,
            incoming: AuthorityCommittee,
            request: SystemAuthorityLedgerClaim,
            keys: Vec<SigningKey>,
        }

        impl Fixture {
            fn new() -> Self {
                let keys = vec![key(0x21), key(0x22), key(0x23), key(0x24)];
                let roles = keys
                    .iter()
                    .cloned()
                    .enumerate()
                    .map(|(index, key)| {
                        (
                            key,
                            if index == 3 {
                                AuthorityMemberRole::Observer
                            } else {
                                AuthorityMemberRole::Voter
                            },
                        )
                    })
                    .collect::<Vec<_>>();
                let old = committee(1, None, &roles);
                let incoming = committee(2, Some(old.commitment()), &roles);
                let genesis =
                    SystemAuthorityGenesis::new(ROOT, 1, ROOT_CONFIG, old.clone(), 1, 8, 8)
                        .unwrap();
                let state = SystemAuthorityState::from_genesis(SYSTEM_AGENT, &genesis).unwrap();
                let scope = SystemAuthorityJournalScope::for_test(GENESIS, ADMISSION).unwrap();
                let route = SystemAuthorityLedgerRoute::new(
                    ROOT,
                    1,
                    ROOT_CONFIG,
                    SPACE,
                    SYSTEM_AGENT,
                    BINDING,
                    GENESIS,
                    ADMISSION,
                )
                .unwrap();
                let store = JournalStoreInstanceId::from_bytes([0x31; 32]).unwrap();
                let view = ReplayedSystemAuthorityView::from_authenticated_replay(
                    scope, &state, store, HEADS_1, CONTROL_1,
                )
                .unwrap();
                let transition = SystemAuthorityRotationClaim::new(
                    ROOT,
                    1,
                    ROOT_CONFIG,
                    route.authority_scope(),
                    &old,
                    &incoming,
                    2,
                    3,
                )
                .unwrap();
                let request = SystemAuthorityLedgerClaim::committee_rotation(
                    old.clone(),
                    incoming.clone(),
                    transition,
                )
                .unwrap();
                Self {
                    state,
                    scope,
                    route,
                    store,
                    view,
                    old,
                    incoming,
                    request,
                    keys,
                }
            }

            fn with_local_key_rotation() -> (Self, SigningKey) {
                let mut fixture = Self::new();
                let incoming_local = key(0x25);
                let mut members = Vec::new();
                members.push(
                    AuthorityCommitteeMember::new(
                        fixture.local_node(),
                        incoming_local.verifying_key().to_bytes(),
                        AuthorityMemberRole::Voter,
                    )
                    .unwrap(),
                );
                for (index, key) in fixture.keys.iter().enumerate().skip(1) {
                    let signer = AuthoritySignerId::of_raw_ed25519(&key.verifying_key().to_bytes());
                    let member = fixture.old.member(signer).unwrap();
                    members.push(
                        AuthorityCommitteeMember::new(
                            member.node(),
                            key.verifying_key().to_bytes(),
                            if index == 3 {
                                AuthorityMemberRole::Observer
                            } else {
                                AuthorityMemberRole::Voter
                            },
                        )
                        .unwrap(),
                    );
                }
                members.sort_by_key(AuthorityCommitteeMember::signer);
                let incoming = AuthorityCommittee::new(
                    SPACE,
                    BINDING,
                    2,
                    Some(fixture.old.commitment()),
                    members,
                )
                .unwrap();
                let transition = SystemAuthorityRotationClaim::new(
                    ROOT,
                    1,
                    ROOT_CONFIG,
                    fixture.route.authority_scope(),
                    &fixture.old,
                    &incoming,
                    2,
                    3,
                )
                .unwrap();
                fixture.request = SystemAuthorityLedgerClaim::committee_rotation(
                    fixture.old.clone(),
                    incoming.clone(),
                    transition,
                )
                .unwrap();
                fixture.incoming = incoming;
                (fixture, incoming_local)
            }

            fn local_signer(&self) -> AuthoritySignerId {
                AuthoritySignerId::of_raw_ed25519(&self.keys[0].verifying_key().to_bytes())
            }

            fn local_node(&self) -> NodeId {
                self.old.member(self.local_signer()).unwrap().node()
            }

            fn rotation_request(&self) -> SystemAuthorityRotationReservationRequest {
                let SystemAuthorityLedgerClaim::CommitteeRotation {
                    retiring,
                    incoming,
                    transition,
                } = &self.request
                else {
                    unreachable!()
                };
                SystemAuthorityRotationReservationRequest::new(
                    retiring.clone(),
                    incoming.clone(),
                    transition.clone(),
                )
                .unwrap()
            }

            fn successor_view(
                &self,
                certificate: SystemAuthorityRotationCertificate,
            ) -> ReplayedSystemAuthorityView {
                let command = SystemAuthorityRotation::new(
                    self.incoming.clone(),
                    certificate,
                    SystemAuthorityRotationProof::vacant(2, vec![]).unwrap(),
                )
                .unwrap();
                let next = self
                    .state
                    .apply_rotation(self.scope, &command)
                    .unwrap()
                    .into_state();
                assert_eq!(next.journal_binding(), Some(self.scope.binding()));
                let foreign_scope = SystemAuthorityJournalScope::for_test(
                    AgentJournalGenesisId::new([0xb7; 32]),
                    self.scope.agent_admission(),
                )
                .unwrap();
                assert!(matches!(
                    ReplayedSystemAuthorityView::for_test_from_authenticated_replay(
                        foreign_scope,
                        &next,
                        self.store,
                        HEADS_2,
                        CONTROL_2,
                    ),
                    Err(SystemAuthorityLedgerWireError::InvalidStateView)
                ));
                ReplayedSystemAuthorityView::for_test_from_authenticated_replay(
                    self.scope, &next, self.store, HEADS_2, CONTROL_2,
                )
                .unwrap()
            }
        }

        struct PledgeCheckingSigner {
            key: SigningKey,
            calls: Cell<usize>,
            database: Arc<Database>,
            pledge_key: [u8; PLEDGE_KEY_BYTES],
        }

        impl SystemAuthoritySigner for PledgeCheckingSigner {
            type Error = core::convert::Infallible;

            fn signer(&self) -> AuthoritySignerId {
                AuthoritySignerId::of_raw_ed25519(&self.key.verifying_key().to_bytes())
            }

            fn sign_authority_message(&self, message: Hash) -> Result<[u8; 64], Self::Error> {
                assert!(
                    read_exact(&self.database, PLEDGE_TABLE, self.pledge_key.as_slice())
                        .unwrap()
                        .is_some(),
                    "signer callback ran before durable pledge"
                );
                self.calls.set(self.calls.get() + 1);
                Ok(self.key.sign(&message.0).to_bytes())
            }
        }

        fn open_ledger(
            database: Arc<Database>,
            fixture: &Fixture,
        ) -> SystemAuthorityEvidenceLedger {
            SystemAuthorityEvidenceLedger::open(
                database,
                fixture.route,
                fixture.store,
                fixture.local_node(),
                fixture.local_signer(),
            )
            .unwrap()
        }

        fn certify_both_legs(
            ledger: &SystemAuthorityEvidenceLedger,
            database: Arc<Database>,
            fixture: &Fixture,
            reserved: &ReservedSystemAuthorityClaim,
        ) -> (PledgeCheckingSigner, SystemAuthorityRotationCertificate) {
            let signer = PledgeCheckingSigner {
                key: fixture.keys[0].clone(),
                calls: Cell::new(0),
                database,
                pledge_key: pledge_storage_key(
                    fixture.route,
                    fixture.local_signer().as_bytes(),
                    fixture.request.sequence(),
                ),
            };
            assert!(
                ledger
                    .sign_reserved_leg(reserved, SystemAuthorityCommitteeLeg::Retiring, &signer)
                    .unwrap()
                    .certificate()
                    .is_none()
            );
            let old_remote = signed_share(&fixture.keys[1], &fixture.old, fixture.request.claim());
            assert!(
                ledger
                    .record_remote_share(
                        reserved,
                        SystemAuthorityCommitteeLeg::Retiring,
                        old_remote,
                    )
                    .unwrap()
                    .certificate()
                    .is_some()
            );
            assert!(
                ledger
                    .sign_reserved_leg(reserved, SystemAuthorityCommitteeLeg::Incoming, &signer)
                    .unwrap()
                    .certificate()
                    .is_none()
            );
            let incoming_remote =
                signed_share(&fixture.keys[1], &fixture.incoming, fixture.request.claim());
            assert!(
                ledger
                    .record_remote_share(
                        reserved,
                        SystemAuthorityCommitteeLeg::Incoming,
                        incoming_remote,
                    )
                    .unwrap()
                    .certificate()
                    .is_some()
            );
            let joint = ledger
                .joint_rotation_certificate(reserved)
                .unwrap()
                .unwrap();
            (signer, joint)
        }

        #[test]
        fn authenticated_view_constructor_keeps_scope_capability_and_exact_ids() {
            let fixture = Fixture::new();

            // Pin the production constructor's capability-bearing signature:
            // raw genesis/admission IDs are not accepted in place of the
            // replay-minted scope.
            let constructor: fn(
                SystemAuthorityJournalScope,
                &SystemAuthorityState,
                JournalStoreInstanceId,
                JournalHeadsId,
                LaneStateId,
            ) -> Result<
                ReplayedSystemAuthorityView,
                SystemAuthorityLedgerWireError,
            > = ReplayedSystemAuthorityView::from_authenticated_replay;

            assert!(matches!(
                constructor(
                    fixture.scope,
                    &fixture.state,
                    fixture.store,
                    JournalHeadsId::ZERO,
                    CONTROL_1,
                ),
                Err(SystemAuthorityLedgerWireError::InvalidStateView)
            ));
            assert!(matches!(
                constructor(
                    fixture.scope,
                    &fixture.state,
                    fixture.store,
                    HEADS_1,
                    LaneStateId::ZERO,
                ),
                Err(SystemAuthorityLedgerWireError::InvalidStateView)
            ));

            let directory = TempDirectory::new("view_scope_store");
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let ledger = open_ledger(database.clone(), &fixture);
            let foreign_scope = SystemAuthorityJournalScope::for_test(
                FOREIGN_GENESIS,
                fixture.scope.agent_admission(),
            )
            .unwrap();
            let foreign_scope_view = constructor(
                foreign_scope,
                &fixture.state,
                fixture.store,
                HEADS_1,
                CONTROL_1,
            )
            .unwrap();
            assert_ne!(foreign_scope_view.route(), fixture.route);
            assert!(matches!(
                ledger.reserve_or_reconcile(&foreign_scope_view, fixture.rotation_request()),
                Err(SystemAuthorityLedgerError::WrongRoute)
            ));

            let foreign_store = JournalStoreInstanceId::from_bytes([0x32; 32]).unwrap();
            let foreign_store_view = constructor(
                fixture.scope,
                &fixture.state,
                foreign_store,
                HEADS_1,
                CONTROL_1,
            )
            .unwrap();
            assert_eq!(foreign_store_view.route(), fixture.route);
            assert!(matches!(
                ledger.reserve_or_reconcile(&foreign_store_view, fixture.rotation_request()),
                Err(SystemAuthorityLedgerError::WrongRoute)
            ));

            // Once authority state has been journal-bound by an executed
            // transition, even another replay-minted scope cannot be used to
            // re-anchor it. `successor_view` asserts that rejection before
            // returning the correctly scoped successor.
            let reserved = ledger
                .reserve_or_reconcile(&fixture.view, fixture.rotation_request())
                .unwrap()
                .into_reserved();
            let (_, joint) = certify_both_legs(&ledger, database, &fixture, &reserved);
            let _ = fixture.successor_view(joint);
        }

        #[test]
        fn pending_recovery_exposes_exact_non_signing_predecessor_evidence() {
            let fixture = Fixture::new();
            let directory = TempDirectory::new("pending_evidence");
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let ledger = open_ledger(database, &fixture);
            ledger
                .reserve_or_reconcile(&fixture.view, fixture.rotation_request())
                .unwrap();

            let pending = ledger.recover_pending_claim().unwrap().unwrap();
            assert_eq!(pending.route(), fixture.view.route());
            assert_eq!(pending.journal_store(), fixture.view.journal_store());
            assert_eq!(pending.predecessor_heads(), fixture.view.heads());
            assert_eq!(pending.control_state(), fixture.view.control_state());
            assert_eq!(pending.state_view_commitment(), fixture.view.commitment());
            assert_eq!(
                pending.authority_state_commitment(),
                fixture.view.authority_state_commitment()
            );
            assert_eq!(pending.claim(), fixture.request.claim());
            assert_eq!(pending.request(), &fixture.request);

            let foreign_heads = ReplayedSystemAuthorityView::from_authenticated_replay(
                fixture.scope,
                &fixture.state,
                fixture.store,
                HEADS_REBASE,
                CONTROL_1,
            )
            .unwrap();
            assert_ne!(pending.predecessor_heads(), foreign_heads.heads());
            assert_ne!(pending.state_view_commitment(), foreign_heads.commitment());
            assert_eq!(
                pending.authority_state_commitment(),
                foreign_heads.authority_state_commitment()
            );

            let foreign_control = ReplayedSystemAuthorityView::from_authenticated_replay(
                fixture.scope,
                &fixture.state,
                fixture.store,
                HEADS_1,
                CONTROL_REBASE,
            )
            .unwrap();
            assert_ne!(pending.control_state(), foreign_control.control_state());
            assert_ne!(
                pending.state_view_commitment(),
                foreign_control.commitment()
            );
            assert_eq!(
                pending.authority_state_commitment(),
                foreign_control.authority_state_commitment()
            );

            let foreign_store = ReplayedSystemAuthorityView::from_authenticated_replay(
                fixture.scope,
                &fixture.state,
                JournalStoreInstanceId::from_bytes([0x33; 32]).unwrap(),
                HEADS_1,
                CONTROL_1,
            )
            .unwrap();
            assert_ne!(pending.journal_store(), foreign_store.journal_store());
            assert_ne!(pending.state_view_commitment(), foreign_store.commitment());
            assert_eq!(
                pending.authority_state_commitment(),
                foreign_store.authority_state_commitment()
            );

            let alternate_keys = vec![
                (fixture.keys[0].clone(), AuthorityMemberRole::Voter),
                (fixture.keys[1].clone(), AuthorityMemberRole::Voter),
                (key(0x2f), AuthorityMemberRole::Voter),
            ];
            let alternate = committee(2, Some(fixture.old.commitment()), &alternate_keys);
            let transition = SystemAuthorityRotationClaim::new(
                ROOT,
                1,
                ROOT_CONFIG,
                fixture.route.authority_scope(),
                &fixture.old,
                &alternate,
                2,
                3,
            )
            .unwrap();
            let alternate = SystemAuthorityRotationReservationRequest::new(
                fixture.old.clone(),
                alternate,
                transition,
            )
            .unwrap();
            assert_ne!(pending.claim(), alternate.claim());

            // Recovery inspection remains usable without reconciliation and
            // therefore without manufacturing a sign-capable reservation.
            assert!(
                ledger
                    .pending_certificate(&pending, SystemAuthorityCommitteeLeg::Retiring)
                    .unwrap()
                    .is_none()
            );
        }

        #[test]
        fn pledge_precedes_callback_exact_retry_and_first_qc_is_frozen() {
            let fixture = Fixture::new();
            let directory = TempDirectory::new("freeze");
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let ledger = open_ledger(database.clone(), &fixture);
            assert!(!ledger.has_pending_reservation().unwrap());
            let swept = Cell::new(false);
            ledger
                .with_no_pending_reservation_for_gc(|| swept.set(true))
                .unwrap();
            assert!(swept.get());
            let outcome = ledger
                .reserve_or_reconcile(&fixture.view, fixture.rotation_request())
                .unwrap();
            assert_eq!(
                outcome.disposition(),
                SystemAuthorityReservationDisposition::New
            );
            let reserved = outcome.into_reserved();
            assert!(ledger.has_pending_reservation().unwrap());
            let swept = Cell::new(false);
            assert!(matches!(
                ledger.with_no_pending_reservation_for_gc(|| swept.set(true)),
                Err(SystemAuthorityLedgerError::GcBlockedByPendingReservation)
            ));
            assert!(!swept.get());
            let (signer, joint) = certify_both_legs(&ledger, database.clone(), &fixture, &reserved);
            assert_eq!(signer.calls.get(), 2, "one callback per committee leg");

            let frozen = joint.old_certificate().clone();
            assert_eq!(frozen.signatures().len(), fixture.old.quorum_threshold());
            let late = signed_share(&fixture.keys[2], &fixture.old, fixture.request.claim());
            let late_outcome = ledger
                .record_remote_share(&reserved, SystemAuthorityCommitteeLeg::Retiring, late)
                .unwrap();
            assert_eq!(late_outcome.certificate(), Some(&frozen));
            assert_eq!(
                ledger
                    .sign_reserved_leg(&reserved, SystemAuthorityCommitteeLeg::Retiring, &signer)
                    .unwrap()
                    .certificate(),
                Some(&frozen)
            );
            assert_eq!(signer.calls.get(), 2, "exact retry reused retained share");

            let unrelated_control =
                ReplayedSystemAuthorityView::for_test_from_authenticated_replay(
                    fixture.scope,
                    &fixture.state,
                    fixture.store,
                    HEADS_REBASE,
                    CONTROL_REBASE,
                )
                .unwrap();
            let outcome = ledger
                .reserve_or_reconcile(&unrelated_control, fixture.rotation_request())
                .unwrap();
            assert_eq!(
                outcome.disposition(),
                SystemAuthorityReservationDisposition::Rebased
            );
            let rebased = outcome.into_reserved();
            assert!(matches!(
                ledger.certificate(&reserved, SystemAuthorityCommitteeLeg::Retiring),
                Err(SystemAuthorityLedgerError::ClaimNotReserved)
            ));
            let reserved = rebased;
            assert_eq!(reserved.record.predecessor_heads, HEADS_REBASE);
            assert_eq!(
                ledger
                    .certificate(&reserved, SystemAuthorityCommitteeLeg::Retiring)
                    .unwrap(),
                Some(frozen.clone()),
                "rebase retains the frozen QC"
            );

            let reopened = open_ledger(database, &fixture);
            let pending = reopened.recover_pending_claim().unwrap().unwrap();
            assert_eq!(pending.request(), &fixture.request);
            assert_eq!(pending.route(), fixture.route);
            assert_eq!(
                reopened
                    .pending_certificate(&pending, SystemAuthorityCommitteeLeg::Retiring)
                    .unwrap(),
                Some(frozen)
            );
            assert!(
                reopened
                    .pending_joint_rotation_certificate(&pending)
                    .unwrap()
                    .is_some()
            );
            let exact = reopened
                .reserve_or_reconcile(&unrelated_control, pending.rotation_request().unwrap())
                .unwrap();
            assert_eq!(
                exact.disposition(),
                SystemAuthorityReservationDisposition::Exact
            );
        }

        #[test]
        fn gc_guard_serializes_reservation_insertion() {
            let fixture = Fixture::new();
            let directory = TempDirectory::new("gc_guard");
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let guard_ledger = open_ledger(database.clone(), &fixture);
            let reserving_ledger = open_ledger(database, &fixture);

            std::thread::scope(|scope| {
                let (started_tx, started_rx) = std::sync::mpsc::channel();
                let (done_tx, done_rx) = std::sync::mpsc::channel();
                let worker = guard_ledger
                    .with_no_pending_reservation_for_gc(|| {
                        let worker = scope.spawn(move || {
                            started_tx.send(()).unwrap();
                            let disposition = reserving_ledger
                                .reserve_or_reconcile(&fixture.view, fixture.rotation_request())
                                .unwrap()
                                .disposition();
                            done_tx.send(disposition).unwrap();
                        });
                        started_rx.recv().unwrap();
                        assert!(
                            done_rx
                                .recv_timeout(std::time::Duration::from_millis(100))
                                .is_err(),
                            "reservation committed while the GC writer guard was held"
                        );
                        worker
                    })
                    .unwrap();
                assert_eq!(
                    done_rx
                        .recv_timeout(std::time::Duration::from_secs(2))
                        .unwrap(),
                    SystemAuthorityReservationDisposition::New
                );
                worker.join().unwrap();
            });
        }

        #[test]
        fn retained_remote_share_blocks_zero_write_local_config_installation() {
            let (fixture, incoming_local) = Fixture::with_local_key_rotation();
            let directory = TempDirectory::new("remote_then_config");
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let ledger = open_ledger(database.clone(), &fixture);
            let reserved = ledger
                .reserve_or_reconcile(&fixture.view, fixture.rotation_request())
                .unwrap()
                .into_reserved();
            let candidate =
                AuthoritySignerId::of_raw_ed25519(&incoming_local.verifying_key().to_bytes());
            let share = signed_share(&incoming_local, &fixture.incoming, fixture.request.claim());
            ledger
                .record_remote_share(
                    &reserved,
                    SystemAuthorityCommitteeLeg::Incoming,
                    share.clone(),
                )
                .unwrap();
            let config_key = config_storage_key(fixture.route, candidate.as_bytes());
            assert!(
                read_exact(&database, CONFIG_TABLE, config_key.as_slice())
                    .unwrap()
                    .is_none()
            );

            assert!(matches!(
                SystemAuthorityEvidenceLedger::open(
                    database.clone(),
                    fixture.route,
                    fixture.store,
                    fixture.local_node(),
                    candidate,
                ),
                Err(SystemAuthorityLedgerError::LocalShareRequiresPledge)
            ));
            assert!(
                read_exact(&database, CONFIG_TABLE, config_key.as_slice())
                    .unwrap()
                    .is_none(),
                "failed signer reclassification installed Config"
            );
            assert!(
                ledger
                    .record_remote_share(&reserved, SystemAuthorityCommitteeLeg::Incoming, share,)
                    .is_ok(),
                "failed Config installation changed retained remote evidence"
            );
        }

        #[test]
        fn local_config_commits_before_remote_share_classification() {
            let (fixture, incoming_local) = Fixture::with_local_key_rotation();
            let directory = TempDirectory::new("config_then_remote");
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let ledger = open_ledger(database.clone(), &fixture);
            let reserved = ledger
                .reserve_or_reconcile(&fixture.view, fixture.rotation_request())
                .unwrap()
                .into_reserved();
            let candidate =
                AuthoritySignerId::of_raw_ed25519(&incoming_local.verifying_key().to_bytes());
            let candidate_ledger = SystemAuthorityEvidenceLedger::open(
                database.clone(),
                fixture.route,
                fixture.store,
                fixture.local_node(),
                candidate,
            )
            .unwrap();
            let share = signed_share(&incoming_local, &fixture.incoming, fixture.request.claim());
            assert!(matches!(
                ledger
                    .record_remote_share(&reserved, SystemAuthorityCommitteeLeg::Incoming, share,),
                Err(SystemAuthorityLedgerError::LocalShareRequiresPledge)
            ));
            assert!(
                read_exact(
                    &database,
                    SHARE_TABLE,
                    share_storage_key(
                        fixture.route,
                        fixture.request.sequence(),
                        SystemAuthorityCommitteeLeg::Incoming,
                        candidate.as_bytes(),
                    )
                    .as_slice(),
                )
                .unwrap()
                .is_none()
            );

            let signer = PledgeCheckingSigner {
                key: incoming_local,
                calls: Cell::new(0),
                database,
                pledge_key: pledge_storage_key(
                    fixture.route,
                    candidate.as_bytes(),
                    fixture.request.sequence(),
                ),
            };
            candidate_ledger
                .sign_reserved_leg(&reserved, SystemAuthorityCommitteeLeg::Incoming, &signer)
                .unwrap();
            assert_eq!(signer.calls.get(), 1);
        }

        #[test]
        fn fail_stop_reopen_drains_existing_qc_and_exact_post_cas_retirement() {
            let fixture = Fixture::new();
            let directory = TempDirectory::new("fail_stop");
            let path = directory.database();
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = open_ledger(database.clone(), &fixture);
            let reserved = ledger
                .reserve_or_reconcile(&fixture.view, fixture.rotation_request())
                .unwrap()
                .into_reserved();
            let (signer, joint) = certify_both_legs(&ledger, database.clone(), &fixture, &reserved);

            let alternate_keys = vec![
                (fixture.keys[0].clone(), AuthorityMemberRole::Voter),
                (fixture.keys[1].clone(), AuthorityMemberRole::Voter),
                (key(0x2f), AuthorityMemberRole::Voter),
            ];
            let alternate = committee(2, Some(fixture.old.commitment()), &alternate_keys);
            let transition = SystemAuthorityRotationClaim::new(
                ROOT,
                1,
                ROOT_CONFIG,
                fixture.route.authority_scope(),
                &fixture.old,
                &alternate,
                2,
                3,
            )
            .unwrap();
            let divergent = SystemAuthorityRotationReservationRequest::new(
                fixture.old.clone(),
                alternate,
                transition,
            )
            .unwrap();
            assert!(matches!(
                ledger.reserve_or_reconcile(&fixture.view, divergent),
                Err(SystemAuthorityLedgerError::DivergentReservation)
            ));
            assert!(ledger.is_fail_stopped().unwrap());
            drop(signer);
            drop(ledger);
            drop(database);

            let database = Arc::new(Database::open(&path).unwrap());
            let reopened = open_ledger(database.clone(), &fixture);
            let pending = reopened.recover_pending_claim().unwrap().unwrap();
            assert!(reopened.has_pending_reservation().unwrap());
            assert!(
                reopened
                    .pending_joint_rotation_certificate(&pending)
                    .unwrap()
                    .is_some()
            );
            let exact = reopened
                .reserve_or_reconcile(&fixture.view, pending.rotation_request().unwrap())
                .unwrap();
            assert_eq!(
                exact.disposition(),
                SystemAuthorityReservationDisposition::Exact
            );
            let recovered = exact.into_reserved();
            let remote = signed_share(&fixture.keys[2], &fixture.old, fixture.request.claim());
            assert!(matches!(
                reopened.record_remote_share(
                    &recovered,
                    SystemAuthorityCommitteeLeg::Retiring,
                    remote
                ),
                Err(SystemAuthorityLedgerError::FailStopped)
            ));

            let successor = fixture.successor_view(joint);
            assert!(matches!(
                reopened.reserve_or_reconcile(&successor, fixture.rotation_request()),
                Err(SystemAuthorityLedgerError::PublicationRecoveryRequired)
            ));
            assert!(reopened.is_fail_stopped().unwrap());
            let receipt = PublishedSystemAuthorityClaim::for_test_after_exact_cas(
                pending,
                fixture.request.claim(),
                &successor,
            )
            .unwrap();
            reopened.retire_published_claim(receipt).unwrap();
            assert!(reopened.recover_pending_claim().unwrap().is_none());
            assert!(!reopened.has_pending_reservation().unwrap());
            let swept = Cell::new(false);
            reopened
                .with_no_pending_reservation_for_gc(|| swept.set(true))
                .unwrap();
            assert!(swept.get());
            assert!(reopened.is_fail_stopped().unwrap());
            assert!(matches!(
                reopened.reserve_or_reconcile(&fixture.view, fixture.rotation_request()),
                Err(SystemAuthorityLedgerError::FailStopped)
                    | Err(SystemAuthorityLedgerError::StaleStateView)
            ));
        }

        #[test]
        fn tampered_local_pledge_fails_reopen_audit() {
            let fixture = Fixture::new();
            let directory = TempDirectory::new("tamper");
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let ledger = open_ledger(database.clone(), &fixture);
            let reserved = ledger
                .reserve_or_reconcile(&fixture.view, fixture.rotation_request())
                .unwrap()
                .into_reserved();
            let signer = PledgeCheckingSigner {
                key: fixture.keys[0].clone(),
                calls: Cell::new(0),
                database: database.clone(),
                pledge_key: pledge_storage_key(
                    fixture.route,
                    fixture.local_signer().as_bytes(),
                    fixture.request.sequence(),
                ),
            };
            ledger
                .sign_reserved_leg(&reserved, SystemAuthorityCommitteeLeg::Retiring, &signer)
                .unwrap();
            let transaction = database.begin_write().unwrap();
            transaction
                .open_table(PLEDGE_TABLE)
                .unwrap()
                .remove(signer.pledge_key.as_slice())
                .unwrap();
            transaction.commit().unwrap();
            assert!(matches!(
                SystemAuthorityEvidenceLedger::open(
                    database,
                    fixture.route,
                    fixture.store,
                    fixture.local_node(),
                    fixture.local_signer()
                ),
                Err(SystemAuthorityLedgerError::CorruptLedger)
            ));
        }

        #[test]
        fn wrong_store_observer_invalid_signature_and_cross_generation_fail_closed() {
            let fixture = Fixture::new();
            let directory = TempDirectory::new("reject");
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let ledger = open_ledger(database.clone(), &fixture);
            let reserved = ledger
                .reserve_or_reconcile(&fixture.view, fixture.rotation_request())
                .unwrap()
                .into_reserved();

            let observer = signed_share(&fixture.keys[3], &fixture.old, fixture.request.claim());
            assert!(matches!(
                ledger.record_remote_share(
                    &reserved,
                    SystemAuthorityCommitteeLeg::Retiring,
                    observer
                ),
                Err(SystemAuthorityLedgerError::ObserverSigner)
            ));
            let invalid = AuthoritySignature::new(
                AuthoritySignerId::of_raw_ed25519(&fixture.keys[1].verifying_key().to_bytes()),
                [0xff; 64],
            )
            .unwrap();
            assert!(matches!(
                ledger.record_remote_share(
                    &reserved,
                    SystemAuthorityCommitteeLeg::Retiring,
                    invalid
                ),
                Err(SystemAuthorityLedgerError::InvalidSignature)
            ));

            let foreign_store = JournalStoreInstanceId::from_bytes([0x32; 32]).unwrap();
            assert!(matches!(
                SystemAuthorityEvidenceLedger::open(
                    database.clone(),
                    fixture.route,
                    foreign_store,
                    fixture.local_node(),
                    fixture.local_signer()
                ),
                Err(SystemAuthorityLedgerError::ConfigurationMismatch)
            ));
            let foreign_signer =
                AuthoritySignerId::of_raw_ed25519(&fixture.keys[1].verifying_key().to_bytes());
            let foreign_node = fixture.old.member(foreign_signer).unwrap().node();
            let node_mismatched = SystemAuthorityEvidenceLedger::open(
                database.clone(),
                fixture.route,
                fixture.store,
                fixture.local_node(),
                foreign_signer,
            )
            .unwrap();
            assert!(matches!(
                node_mismatched.reserve_or_reconcile(&fixture.view, fixture.rotation_request(),),
                Err(SystemAuthorityLedgerError::LocalSignerNotVoter)
            ));
            assert!(matches!(
                SystemAuthorityEvidenceLedger::open(
                    database,
                    fixture.route,
                    fixture.store,
                    foreign_node,
                    foreign_signer,
                ),
                Err(SystemAuthorityLedgerError::ConfigurationMismatch)
            ));

            let foreign_scope = SystemAuthorityScopeCommitment::for_journal(
                ROOT,
                AgentJournalGenesisId::new([0x91; 32]),
                ADMISSION,
            )
            .unwrap();
            let transition = SystemAuthorityRotationClaim::new(
                ROOT,
                1,
                ROOT_CONFIG,
                foreign_scope,
                &fixture.old,
                &fixture.incoming,
                2,
                3,
            )
            .unwrap();
            let foreign = SystemAuthorityLedgerClaim::committee_rotation(
                fixture.old.clone(),
                fixture.incoming.clone(),
                transition,
            )
            .unwrap();
            assert!(matches!(
                fixture.view.validate_claim(&foreign),
                Err(SystemAuthorityLedgerWireError::InvalidClaim)
            ));
            assert!(matches!(
                ledger.reserve_or_reconcile(
                    &fixture.view,
                    SystemAuthorityRotationReservationRequest { request: foreign },
                ),
                Err(SystemAuthorityLedgerError::Wire(
                    SystemAuthorityLedgerWireError::InvalidClaim
                ))
            ));
            assert!(
                !ledger.is_fail_stopped().unwrap(),
                "an unauthenticated competing request must not persist fail-stop"
            );
        }

        #[test]
        fn idle_meta_store_mismatch_rejects_without_installing_config() {
            let fixture = Fixture::new();
            let directory = TempDirectory::new("idle_meta_store");
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let ledger = open_ledger(database.clone(), &fixture);
            drop(ledger);

            let foreign_store = JournalStoreInstanceId::from_bytes([0xa1; 32]).unwrap();
            let meta = MetaRecord {
                route: fixture.route,
                journal_store: foreign_store,
                retired_high_water: fixture.view.committee_sequence_high_water(),
                authority_state: fixture.view.authority_state_commitment(),
                last_claim: None,
                last_publication: None,
            };
            meta.validate().unwrap();
            let route_key = route_storage_key(fixture.route);
            let local_config = config_storage_key(fixture.route, fixture.local_signer().as_bytes());
            let transaction = database.begin_write().unwrap();
            transaction
                .open_table(CONFIG_TABLE)
                .unwrap()
                .remove(local_config.as_slice())
                .unwrap();
            transaction
                .open_table(META_TABLE)
                .unwrap()
                .insert(route_key.as_slice(), meta.encode().as_slice())
                .unwrap();
            transaction.commit().unwrap();

            assert!(matches!(
                SystemAuthorityEvidenceLedger::open(
                    database.clone(),
                    fixture.route,
                    fixture.store,
                    fixture.local_node(),
                    fixture.local_signer(),
                ),
                Err(SystemAuthorityLedgerError::CorruptLedger)
            ));
            assert!(
                read_exact(&database, CONFIG_TABLE, local_config.as_slice())
                    .unwrap()
                    .is_none(),
                "failed open must not install a replacement Config row"
            );
        }

        #[test]
        fn corrupt_existing_row_rejects_new_signer_without_installing_config() {
            let fixture = Fixture::new();
            let directory = TempDirectory::new("zero_write_open");
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let ledger = open_ledger(database.clone(), &fixture);
            drop(ledger);

            let route_key = route_storage_key(fixture.route);
            let transaction = database.begin_write().unwrap();
            transaction
                .open_table(META_TABLE)
                .unwrap()
                .insert(route_key.as_slice(), b"not-a-canonical-meta".as_slice())
                .unwrap();
            transaction.commit().unwrap();

            let new_signer =
                AuthoritySignerId::of_raw_ed25519(&fixture.keys[1].verifying_key().to_bytes());
            let new_config = config_storage_key(fixture.route, new_signer.as_bytes());
            assert!(matches!(
                SystemAuthorityEvidenceLedger::open(
                    database.clone(),
                    fixture.route,
                    fixture.store,
                    fixture.local_node(),
                    new_signer,
                ),
                Err(SystemAuthorityLedgerError::CorruptLedger)
            ));
            assert!(
                read_exact(&database, CONFIG_TABLE, new_config.as_slice())
                    .unwrap()
                    .is_none(),
                "preflight failure must roll back the new Config row"
            );
        }

        #[test]
        fn route_claim_and_global_h_keys_are_canonical_and_bounded() {
            let fixture = Fixture::new();
            assert_eq!(
                SystemAuthorityLedgerRoute::decode(&fixture.route.encode()).unwrap(),
                fixture.route
            );
            assert_eq!(
                SystemAuthorityLedgerClaim::decode(&fixture.request.encode()).unwrap(),
                fixture.request
            );
            assert!(fixture.route.encode().len() <= MAX_SYSTEM_AUTHORITY_LEDGER_ROUTE_BYTES);
            assert!(fixture.request.encode().len() <= MAX_SYSTEM_AUTHORITY_LEDGER_CLAIM_BYTES);

            let mut oversized = fixture.request.encode();
            oversized.resize(MAX_SYSTEM_AUTHORITY_LEDGER_CLAIM_BYTES + 1, 0);
            assert_eq!(
                SystemAuthorityLedgerClaim::decode(&oversized),
                Err(DecodeError::LimitExceeded)
            );

            let signer = fixture.local_signer();
            let rotation_key = pledge_storage_key(fixture.route, signer.as_bytes(), 2);
            let genesis_claim = AuthorityClaimCommitment::of_bytes(
                AuthorityClaimDomain::AgentGenesis,
                2,
                b"different-domain-same-H",
            );
            assert_eq!(
                rotation_key,
                pledge_storage_key(fixture.route, signer.as_bytes(), genesis_claim.sequence()),
                "pledge namespace deliberately excludes claim domain and committee leg"
            );
            assert_eq!(
                MAX_LOCAL_SIGNERS_PER_SCOPE,
                MAX_SYSTEM_AUTHORITY_ROTATIONS as usize + 1
            );
        }
    }

    macro_rules! backend_from {
        ($error:ty) => {
            impl From<$error> for SystemAuthorityLedgerError {
                fn from(error: $error) -> Self {
                    Self::Backend(Box::new(error))
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
pub(crate) use durable::{
    PendingSystemAuthorityRecovery, ReservedSystemAuthorityClaim, SystemAuthorityEvidenceLedger,
    SystemAuthorityLedgerError, SystemAuthorityReservationDisposition,
    SystemAuthorityReservationOutcome, SystemAuthorityRotationReservationRequest,
    SystemAuthorityShareOutcome, SystemAuthoritySignError, SystemAuthoritySigner,
};
