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

use super::catalog_finality::{
    FinalizedCatalogMutationFact, MAX_FINALIZED_CATALOG_MUTATION_FACT_BYTES,
};
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
#[cfg(all(feature = "std", feature = "storage"))]
use super::journal::{
    CanonicalJournalRecord, MAX_JOURNAL_RECORD_BYTES, OrderedEntry, OrderedEntryId, ReplayOperation,
};
use super::shared_raft::JournalStoreInstanceId;
use super::system_authority::{
    MAX_SYSTEM_AUTHORITY_CATALOG_PROOF_BYTES, MAX_SYSTEM_AUTHORITY_DECISION_PROOF_BYTES,
    MAX_SYSTEM_AUTHORITY_ROTATION_CLAIM_BYTES, SystemAuthorityCatalogProof,
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
const MAX_AGENT_GENESIS_LEDGER_CLAIM_BODY_BYTES: usize = 1
    + 5 * 4
    + MAX_AUTHORITY_COMMITTEE_WIRE_BYTES
    + MAX_AGENT_GENESIS_PROPOSAL_BYTES
    + MAX_AGENT_REPLICA_COMMITTEE_BYTES
    + MAX_AGENT_GENESIS_CLAIM_BYTES
    + MAX_SYSTEM_AUTHORITY_DECISION_PROOF_BYTES;
const MAX_ROTATION_LEDGER_CLAIM_BODY_BYTES: usize =
    1 + 3 * 4 + 2 * MAX_AUTHORITY_COMMITTEE_WIRE_BYTES + MAX_SYSTEM_AUTHORITY_ROTATION_CLAIM_BYTES;
const MAX_CATALOG_LEDGER_CLAIM_BODY_BYTES: usize = 1
    + 3 * 4
    + MAX_AUTHORITY_COMMITTEE_WIRE_BYTES
    + MAX_FINALIZED_CATALOG_MUTATION_FACT_BYTES
    + MAX_SYSTEM_AUTHORITY_CATALOG_PROOF_BYTES;

const fn maximum(left: usize, right: usize) -> usize {
    if left > right { left } else { right }
}

/// Maximum one tagged reserved authority claim. The bound is the largest
/// variant rather than the sum of mutually exclusive variant envelopes.
pub(crate) const MAX_SYSTEM_AUTHORITY_LEDGER_CLAIM_BYTES: usize = SERVICE_WIRE_HEADER_BYTES
    + maximum(
        MAX_AGENT_GENESIS_LEDGER_CLAIM_BODY_BYTES,
        maximum(
            MAX_ROTATION_LEDGER_CLAIM_BODY_BYTES,
            MAX_CATALOG_LEDGER_CLAIM_BODY_BYTES,
        ),
    );
const MAX_CATALOG_LEDGER_CLAIM_BYTES: usize =
    SERVICE_WIRE_HEADER_BYTES + MAX_CATALOG_LEDGER_CLAIM_BODY_BYTES;

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
    fn new(
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

    /// Derive the durable route only from an opaque replayed-root scope and
    /// the exact authenticated system-authority state carried by that root.
    /// A decoded state without replay provenance cannot call this safely.
    pub(crate) fn from_authenticated_replay(
        trusted_scope: SystemAuthorityJournalScope,
        state: &SystemAuthorityState,
    ) -> Result<Self, SystemAuthorityLedgerWireError> {
        state
            .validate()
            .map_err(|_| SystemAuthorityLedgerWireError::InvalidStateView)?;
        let route = Self::new(
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
    Catalog {
        committee: AuthorityCommittee,
        fact: FinalizedCatalogMutationFact,
        proof: SystemAuthorityCatalogProof,
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

    fn catalog(
        committee: AuthorityCommittee,
        fact: FinalizedCatalogMutationFact,
        proof: SystemAuthorityCatalogProof,
    ) -> Result<Self, SystemAuthorityLedgerWireError> {
        let request = Self::Catalog {
            committee,
            fact,
            proof,
        };
        request.validate()?;
        Ok(request)
    }

    pub(crate) fn claim(&self) -> AuthorityClaimCommitment {
        match self {
            Self::AgentGenesis { claim, .. } => claim.authority_claim(),
            Self::CommitteeRotation { transition, .. } => transition.authority_claim(),
            Self::Catalog { fact, .. } => fact.authority_claim(),
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
            (Self::Catalog { committee, .. }, SystemAuthorityCommitteeLeg::Current) => {
                Some(committee)
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
            Self::Catalog { .. } => &[SystemAuthorityCommitteeLeg::Current],
        }
    }

    pub(crate) fn transition(&self) -> Option<&SystemAuthorityRotationClaim> {
        match self {
            Self::AgentGenesis { .. } => None,
            Self::CommitteeRotation { transition, .. } => Some(transition),
            Self::Catalog { .. } => None,
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
            Self::CommitteeRotation { .. } | Self::Catalog { .. } => None,
        }
    }

    pub(crate) fn catalog_preimages(
        &self,
    ) -> Option<(&FinalizedCatalogMutationFact, &SystemAuthorityCatalogProof)> {
        match self {
            Self::Catalog { fact, proof, .. } => Some((fact, proof)),
            Self::AgentGenesis { .. } | Self::CommitteeRotation { .. } => None,
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
            Self::Catalog {
                committee,
                fact,
                proof,
            } => {
                committee
                    .validate()
                    .map_err(SystemAuthorityLedgerWireError::Authority)?;
                fact.validate()
                    .map_err(|_| SystemAuthorityLedgerWireError::InvalidClaim)?;
                proof
                    .root()
                    .map_err(|_| SystemAuthorityLedgerWireError::InvalidClaim)?;
                let binding = fact.intent().binding();
                if fact.authority_claim().domain() != AuthorityClaimDomain::Catalog
                    || committee.space() != binding.space()
                    || committee.authority_binding() != binding.authority_binding()
                    || proof.operation_id() != fact.intent().operation_id()
                    || proof.occupied_record_id().is_some()
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
            Self::Catalog {
                committee,
                fact,
                proof,
            } => {
                encoder.u8(2);
                encoder.bytes(&committee.encode());
                encoder.bytes(&fact.encode());
                encoder.bytes(&proof.encode());
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
            2 => Self::Catalog {
                committee: decode_nested(decoder, MAX_AUTHORITY_COMMITTEE_WIRE_BYTES)?,
                fact: decode_nested(decoder, MAX_FINALIZED_CATALOG_MUTATION_FACT_BYTES)?,
                proof: decode_nested(decoder, MAX_SYSTEM_AUTHORITY_CATALOG_PROOF_BYTES)?,
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
        let route = SystemAuthorityLedgerRoute::from_authenticated_replay(trusted_scope, state)?;
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

    pub(crate) const fn authority_state(&self) -> &SystemAuthorityState {
        &self.state
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
            SystemAuthorityLedgerClaim::Catalog { fact, proof, .. } => {
                self.state
                    .validate_catalog_claim_for_signing(self.trusted_scope, fact, proof)
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
    use redb::{Database, ReadableTable, TableDefinition, TableHandle};

    use super::*;
    use crate::agent::committee::{
        AuthorityMemberRole, AuthorityQuorumCertificate, AuthoritySignature, AuthoritySignerId,
        MAX_AUTHORITY_QC_WIRE_BYTES,
    };
    use crate::agent::journal_store::{AgentJournalStore, JournalPublication};
    use crate::agent::replay::{
        PublishedSystemAuthorityCatalog, PublishedSystemAuthorityRotation,
        RecoveredSystemAuthorityCatalog, RecoveredSystemAuthorityRotation, ReplayExecutionResult,
        ReplayMaterialization, ReplaySealedGenesis, RetiredSystemAuthorityCatalogRecovery,
        RetiredSystemAuthorityRotationRecovery, SystemAuthorityCatalogPublicationFacts,
        SystemAuthorityRotationPublicationFacts,
    };
    use crate::agent::system_authority::{
        MAX_SYSTEM_AUTHORITY_CATALOG_FINALIZE_BYTES, MAX_SYSTEM_AUTHORITY_ROTATION_BYTES,
        MAX_SYSTEM_AUTHORITY_ROTATIONS, SystemAuthorityCatalogFinalizeOutcome,
        SystemAuthorityCatalogNodeId, SystemAuthorityCatalogRecord, SystemAuthorityCatalogRecordId,
        SystemAuthorityCommitteeId, SystemAuthorityRotationCertificate, SystemAuthorityRotationId,
        SystemAuthorityRotationNodeId,
    };
    use crate::agent::{LifecycleReply, LifecycleRequest};
    use crate::service::NodeId;

    // Clean-break schema: v6 makes publication intent a bounded tagged union
    // covering committee rotation and catalog finality. The Config sentinel,
    // versioned route table, and empty legacy route tables make every older
    // writer reject this route before it can install a signer or mutate
    // evidence rows.
    const LEDGER_SCHEMA_VERSION: u32 = 6;
    const JOURNAL_EXPOSURE_RECORD_VERSION: u32 = 1;
    // Config rows are permanent: a key that was ever local must never later be
    // admitted through the remote-share path and bypass its durable pledge.
    // One initial committee plus every protocol-bounded rotation can introduce
    // at most this many distinct local signing keys for a route.
    const MAX_LOCAL_SIGNERS_PER_SCOPE: usize = MAX_SYSTEM_AUTHORITY_ROTATIONS as usize + 1;
    const MAX_SHARE_ROWS_PER_CLAIM: usize = 2 * 256;
    const MAX_QC_ROWS_PER_CLAIM: usize = 2;
    const MAX_CONFIG_RECORD_BYTES: usize = 1024;
    const MAX_ROUTE_CONFIG_RECORD_BYTES: usize = 1024;
    const MAX_JOURNAL_EXPOSURE_RECORD_BYTES: usize = 1024;
    const MAX_META_RECORD_BYTES: usize = 1024;
    // Only the two publication-bearing system-authority commands can inhabit
    // this OrderedEntry. Eight KiB covers its ReplayInput/runtime/call and
    // ordered-entry framing; another four KiB covers the intent's route,
    // predecessor/successor commitments, variant tag, and wire framing. This
    // is deliberately smaller than the generic journal record envelope and
    // prevents a decoded intent from allocating against an unrelated maximum.
    const MAX_PUBLICATION_ORDERED_ENTRY_BYTES: usize = maximum(
        MAX_SYSTEM_AUTHORITY_ROTATION_BYTES,
        MAX_SYSTEM_AUTHORITY_CATALOG_FINALIZE_BYTES,
    ) + 8 * 1024;
    const MAX_PUBLICATION_INTENT_RECORD_BYTES: usize =
        MAX_PUBLICATION_ORDERED_ENTRY_BYTES + 4 * 1024;
    const _: () = assert!(MAX_PUBLICATION_INTENT_RECORD_BYTES <= MAX_JOURNAL_RECORD_BYTES);
    // Exact catalog-variant envelope: record header, nested route, five
    // predecessor/view identifiers, sequence marker, and the tagged claim.
    const MAX_CATALOG_RESERVATION_RECORD_BYTES: usize = SERVICE_WIRE_HEADER_BYTES
        + 4
        + MAX_SYSTEM_AUTHORITY_LEDGER_ROUTE_BYTES
        + 5 * 32
        + 8
        + 1
        + 8
        + 4
        + MAX_CATALOG_LEDGER_CLAIM_BYTES;
    const _: () = assert!(MAX_CATALOG_RESERVATION_RECORD_BYTES <= MAX_JOURNAL_RECORD_BYTES);
    const MAX_RESERVATION_RECORD_BYTES: usize =
        MAX_SYSTEM_AUTHORITY_LEDGER_ROUTE_BYTES + MAX_SYSTEM_AUTHORITY_LEDGER_CLAIM_BYTES + 512;
    const MAX_PLEDGE_RECORD_BYTES: usize = 1024;
    const MAX_SHARE_RECORD_BYTES: usize = 1024;
    const MAX_QC_RECORD_BYTES: usize =
        MAX_SYSTEM_AUTHORITY_LEDGER_ROUTE_BYTES + MAX_AUTHORITY_QC_WIRE_BYTES + 512;
    const MAX_FAIL_STOP_RECORD_BYTES: usize = 1024;

    const CONFIG_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("system_authority_ledger_config_v1");
    const ROUTE_CONFIG_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("system_authority_ledger_route_config_v6");
    const LEGACY_ROUTE_CONFIG_TABLE_V5: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("system_authority_ledger_route_config_v5");
    const LEGACY_ROUTE_CONFIG_TABLE_V4: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("system_authority_ledger_route_config_v4");
    const LEGACY_ROUTE_CONFIG_TABLE_V3: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("system_authority_ledger_route_config_v3");
    const JOURNAL_EXPOSURE_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("system_authority_ledger_journal_exposure_v1");
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
    const PUBLICATION_INTENT_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("system_authority_ledger_publication_intent_v3");
    const LEGACY_PUBLICATION_INTENT_TABLE_V2: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("system_authority_ledger_publication_intent_v2");

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

        pub(crate) const fn journal_store(&self) -> JournalStoreInstanceId {
            self.record.journal_store
        }

        pub(crate) const fn predecessor_heads(&self) -> JournalHeadsId {
            self.record.predecessor_heads
        }

        pub(crate) const fn authority_state_commitment(&self) -> Hash {
            self.record.authority_state
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

    /// Catalog-only input to the signing ledger. Recovery may reconstruct it
    /// from an already durable reservation, but a fresh production request
    /// has no raw constructor: the catalog actor integration must first mint
    /// an opaque authenticated semantic-admission token.
    #[derive(Clone, Debug)]
    pub(crate) struct SystemAuthorityCatalogReservationRequest {
        request: SystemAuthorityLedgerClaim,
    }

    impl SystemAuthorityCatalogReservationRequest {
        /// Test-only raw constructor. Production must not turn a decoded fact
        /// into signing authority: the catalog actor integration will expose
        /// a separate constructor which consumes its opaque, authenticated
        /// semantic-admission token.
        #[cfg(test)]
        pub(crate) fn new(
            committee: AuthorityCommittee,
            fact: FinalizedCatalogMutationFact,
            proof: SystemAuthorityCatalogProof,
        ) -> Result<Self, SystemAuthorityLedgerWireError> {
            Ok(Self {
                request: SystemAuthorityLedgerClaim::catalog(committee, fact, proof)?,
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
        publication_intent: Option<PublicationIntentRecord>,
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

        pub(crate) fn catalog_request(&self) -> Option<SystemAuthorityCatalogReservationRequest> {
            matches!(
                &self.record.request,
                SystemAuthorityLedgerClaim::Catalog { .. }
            )
            .then(|| SystemAuthorityCatalogReservationRequest {
                request: self.record.request.clone(),
            })
        }

        pub(crate) const fn expected_successor_heads(&self) -> Option<JournalHeadsId> {
            match &self.publication_intent {
                Some(intent) => Some(intent.successor_heads),
                None => None,
            }
        }

        pub(crate) const fn expected_ordered_entry_id(&self) -> Option<OrderedEntryId> {
            match &self.publication_intent {
                Some(intent) => Some(intent.ordered_entry),
                None => None,
            }
        }

        pub(crate) const fn expected_ordered_entry(&self) -> Option<&OrderedEntry> {
            match &self.publication_intent {
                Some(intent) => Some(&intent.ordered_entry_payload),
                None => None,
            }
        }

        pub(crate) fn matches_publication_facts(
            &self,
            facts: &SystemAuthorityRotationPublicationFacts,
        ) -> bool {
            self.publication_intent.as_ref()
                == PublicationIntentRecord::for_rotation_facts(&self.record, facts)
                    .ok()
                    .as_ref()
        }

        pub(crate) fn matches_catalog_publication_facts(
            &self,
            facts: &SystemAuthorityCatalogPublicationFacts,
        ) -> bool {
            self.publication_intent.as_ref()
                == PublicationIntentRecord::for_catalog_facts(&self.record, facts)
                    .ok()
                    .as_ref()
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

    /// One-shot unlock minted only after the exact post-CAS reservation has
    /// been durably retired. Its private field prevents ordinary crate code
    /// from using replay's result-release seam as a retirement bypass.
    pub(crate) struct RetiredSystemAuthorityRotation {
        _private: (),
    }

    /// One-shot unlock minted only after an exact catalog publication has
    /// durably retired its reservation, intent, pledge, shares, and frozen QC.
    pub(crate) struct RetiredSystemAuthorityCatalog {
        _private: (),
    }

    impl SystemAuthorityShareOutcome {
        pub(crate) const fn share(&self) -> &AuthoritySignature {
            &self.share
        }

        pub(crate) const fn certificate(&self) -> Option<&AuthorityQuorumCertificate> {
            self.certificate.as_ref()
        }
    }

    /// Ledger-private retirement model built only from replay's opaque,
    /// store-borrowing post-CAS receipt.
    #[derive(Debug)]
    struct PublishedSystemAuthorityClaim {
        reservation: ReservationRecord,
        publication_intent: Option<PublicationIntentRecord>,
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
        fn for_rotation_receipt(
            reserved: &ReservedSystemAuthorityClaim,
            facts: &SystemAuthorityRotationPublicationFacts,
            frozen_certificate: &SystemAuthorityRotationCertificate,
        ) -> Result<Self, SystemAuthorityLedgerError> {
            Self::for_rotation_record(&reserved.record, facts, frozen_certificate)
        }

        fn for_recovered_rotation(
            pending: &PendingSystemAuthorityRecovery,
            facts: &SystemAuthorityRotationPublicationFacts,
            frozen_certificate: &SystemAuthorityRotationCertificate,
        ) -> Result<Self, SystemAuthorityLedgerError> {
            if !pending.matches_publication_facts(facts) {
                return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
            }
            Self::for_rotation_record(&pending.record, facts, frozen_certificate)
        }

        fn for_rotation_record(
            reservation: &ReservationRecord,
            facts: &SystemAuthorityRotationPublicationFacts,
            frozen_certificate: &SystemAuthorityRotationCertificate,
        ) -> Result<Self, SystemAuthorityLedgerError> {
            let SystemAuthorityLedgerClaim::CommitteeRotation {
                retiring,
                incoming,
                transition,
            } = &reservation.request
            else {
                return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
            };
            let record = facts.record();
            let command = facts.command();
            if facts.journal_store() != reservation.journal_store
                || facts.predecessor_heads() != reservation.predecessor_heads
                || facts.predecessor_control() != reservation.control_state
                || facts.predecessor_view() != reservation.state_view
                || facts.predecessor_authority_state() != reservation.authority_state
                || facts.successor_heads() == JournalHeadsId::ZERO
                || facts.successor_heads() == facts.predecessor_heads()
                || facts.successor_control() == LaneStateId::ZERO
                || facts.successor_control() == facts.predecessor_control()
                || facts.successor_view() == Hash::ZERO
                || facts.successor_view() == facts.predecessor_view()
                || facts.successor_authority_state() == Hash::ZERO
                || facts.successor_authority_state() == facts.predecessor_authority_state()
                || facts.claim() != reservation.request.claim()
                || command.operation_commitment() != facts.operation()
                || command.new_committee() != incoming
                || command.certificate() != frozen_certificate
                || record.certificate() != frozen_certificate
                || record.certificate().transition() != transition
                || record.old_committee().as_bytes() != &retiring.commitment().0
                || record.new_committee().as_bytes() != &incoming.commitment().0
                || facts.root() == SystemAuthorityRotationNodeId::ZERO
                || facts.result()
                    != &(LifecycleReply::SystemAuthorityRotated {
                        rotation: record.id(),
                        epoch: record.new_epoch(),
                        exact_retry: false,
                    })
            {
                return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
            }
            Ok(Self {
                reservation: reservation.clone(),
                publication_intent: Some(PublicationIntentRecord::for_rotation_facts(
                    reservation,
                    facts,
                )?),
                journal_store: facts.journal_store(),
                successor_heads: facts.successor_heads(),
                successor_control: facts.successor_control(),
                successor_view: facts.successor_view(),
                successor_authority_state: facts.successor_authority_state(),
                resulting_high_water: transition.rotation_sequence(),
                resulting_first_sequence: Some(transition.first_sequence()),
                resulting_committee: incoming.commitment(),
            })
        }

        fn for_catalog_receipt(
            reserved: &ReservedSystemAuthorityClaim,
            facts: &SystemAuthorityCatalogPublicationFacts,
            frozen_certificate: &AuthorityQuorumCertificate,
        ) -> Result<Self, SystemAuthorityLedgerError> {
            Self::for_catalog_record(&reserved.record, facts, frozen_certificate)
        }

        fn for_recovered_catalog(
            pending: &PendingSystemAuthorityRecovery,
            facts: &SystemAuthorityCatalogPublicationFacts,
            frozen_certificate: &AuthorityQuorumCertificate,
        ) -> Result<Self, SystemAuthorityLedgerError> {
            if !pending.matches_catalog_publication_facts(facts) {
                return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
            }
            Self::for_catalog_record(&pending.record, facts, frozen_certificate)
        }

        fn for_catalog_record(
            reservation: &ReservationRecord,
            facts: &SystemAuthorityCatalogPublicationFacts,
            frozen_certificate: &AuthorityQuorumCertificate,
        ) -> Result<Self, SystemAuthorityLedgerError> {
            let SystemAuthorityLedgerClaim::Catalog {
                committee,
                fact,
                proof,
            } = &reservation.request
            else {
                return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
            };
            let record = facts.record();
            let command = facts.command();
            let receipt = record.receipt();
            let finalized = SystemAuthorityCatalogFinalizeOutcome::Finalized {
                operation: record.operation_id(),
                result: fact.result().commitment(),
                catalog_head: fact.resulting_catalog_head(),
                authority_generation: fact.resulting_authority_generation(),
                sequence: fact.sequence(),
            };
            if facts.journal_store() != reservation.journal_store
                || facts.predecessor_heads() != reservation.predecessor_heads
                || facts.predecessor_control() != reservation.control_state
                || facts.predecessor_view() != reservation.state_view
                || facts.predecessor_authority_state() != reservation.authority_state
                || facts.successor_heads() == JournalHeadsId::ZERO
                || facts.successor_heads() == facts.predecessor_heads()
                || facts.successor_control() == LaneStateId::ZERO
                || facts.successor_control() == facts.predecessor_control()
                || facts.successor_view() == Hash::ZERO
                || facts.successor_view() == facts.predecessor_view()
                || facts.successor_authority_state() == Hash::ZERO
                || facts.successor_authority_state() == facts.predecessor_authority_state()
                || facts.claim() != reservation.request.claim()
                || command.operation_commitment() != facts.operation()
                || command.proof() != proof
                || command.receipt() != receipt
                || receipt.fact() != fact
                || receipt.certificate() != frozen_certificate
                || receipt.certificate().committee().0 != committee.commitment().0
                || facts.root() == SystemAuthorityCatalogNodeId::ZERO
                || facts.result() != &LifecycleReply::CatalogFinalized(finalized)
            {
                return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
            }
            Ok(Self {
                reservation: reservation.clone(),
                publication_intent: Some(PublicationIntentRecord::for_catalog_facts(
                    reservation,
                    facts,
                )?),
                journal_store: facts.journal_store(),
                successor_heads: facts.successor_heads(),
                successor_control: facts.successor_control(),
                successor_view: facts.successor_view(),
                successor_authority_state: facts.successor_authority_state(),
                resulting_high_water: fact.sequence(),
                resulting_first_sequence: None,
                resulting_committee: committee.commitment(),
            })
        }

        #[cfg(test)]
        fn for_test_after_exact_cas(
            pending: PendingSystemAuthorityRecovery,
            exact_executed_claim: AuthorityClaimCommitment,
            successor: &ReplayedSystemAuthorityView,
        ) -> Result<Self, SystemAuthorityLedgerError> {
            let PendingSystemAuthorityRecovery {
                record: reservation,
                publication_intent,
            } = pending;
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
                SystemAuthorityLedgerClaim::Catalog { committee, .. } => {
                    if successor.committee() != committee
                        || successor.rotation_first_sequence().is_some()
                    {
                        return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
                    }
                }
            }
            Ok(Self {
                journal_store: successor.journal_store(),
                successor_heads: successor.heads(),
                reservation,
                publication_intent,
                successor_control: successor.control_state(),
                successor_view: successor.commitment(),
                successor_authority_state: successor.authority_state_commitment(),
                resulting_high_water: successor.committee_sequence_high_water(),
                resulting_first_sequence: successor.rotation_first_sequence(),
                resulting_committee: successor.committee().commitment(),
            })
        }
    }

    /// Signer-independent owner of one durable authority-ledger route. Every
    /// production signer child must be derived from the same `Arc`, so route
    /// recovery, publication, retirement, and signing mutations share this
    /// process lock in addition to redb's cross-handle writer serialization.
    pub(crate) struct SystemAuthorityLedgerRouteOwner {
        database: Arc<Database>,
        route: SystemAuthorityLedgerRoute,
        journal_store: JournalStoreInstanceId,
        local_node: NodeId,
        writes: std::sync::Mutex<()>,
    }

    impl SystemAuthorityLedgerRouteOwner {
        /// Open the exact descriptor-pinned file ledger represented by an
        /// opaque capability. The capability fixes both the database and its
        /// filesystem-derived initialization policy before this constructor
        /// sees either value.
        #[cfg(target_os = "linux")]
        pub(crate) fn open_file(
            owner_open: crate::agent::journal_store::FileSystemAuthorityLedgerOwnerOpen,
            sealed: &ReplaySealedGenesis,
        ) -> Result<
            crate::agent::journal_store::OpenedFileSystemAuthorityLedgerOwner,
            SystemAuthorityLedgerError,
        > {
            let route = sealed
                .system_authority_ledger_route()
                .map_err(|_| SystemAuthorityLedgerError::ConfigurationMismatch)?;
            owner_open.open_owner(route)
        }

        /// Initialize or exactly reopen a database whose freshness is proven
        /// by the journal slot's unpublished `.next` inode. Production must
        /// never call this for a canonical sidecar.
        #[cfg(test)]
        pub(crate) fn open_staged(
            database: Arc<Database>,
            route: SystemAuthorityLedgerRoute,
            journal_store: JournalStoreInstanceId,
            local_node: NodeId,
        ) -> Result<Arc<Self>, SystemAuthorityLedgerError> {
            Self::open_with_policy(database, route, journal_store, local_node, true)
        }

        /// Strictly reopen an already-canonical sidecar. Missing route rows,
        /// an empty/truncated database, or any mismatch fail without a commit;
        /// canonical existence never carries initialization authority.
        #[cfg(test)]
        pub(crate) fn open_existing(
            database: Arc<Database>,
            route: SystemAuthorityLedgerRoute,
            journal_store: JournalStoreInstanceId,
            local_node: NodeId,
        ) -> Result<Arc<Self>, SystemAuthorityLedgerError> {
            Self::open_with_policy(database, route, journal_store, local_node, false)
        }

        /// Database-level implementation for the descriptor-backed file
        /// capability. Its permit has a private constructor in
        /// `journal_store`, so production callers cannot select a policy for
        /// an arbitrary database.
        #[cfg(target_os = "linux")]
        pub(crate) fn open_file_database(
            _permit: crate::agent::journal_store::FileSystemAuthorityLedgerOwnerOpenPermit,
            database: Arc<Database>,
            route: SystemAuthorityLedgerRoute,
            journal_store: JournalStoreInstanceId,
            local_node: NodeId,
            allow_staged_initialization: bool,
        ) -> Result<Arc<Self>, SystemAuthorityLedgerError> {
            Self::open_with_policy(
                database,
                route,
                journal_store,
                local_node,
                allow_staged_initialization,
            )
        }

        #[cfg(test)]
        pub(crate) fn open(
            database: Arc<Database>,
            route: SystemAuthorityLedgerRoute,
            journal_store: JournalStoreInstanceId,
            local_node: NodeId,
        ) -> Result<Arc<Self>, SystemAuthorityLedgerError> {
            let owner = Self::open_staged(database, route, journal_store, local_node)?;
            if !owner.journal_exposure_is_committed()? {
                match owner.with_unexposed_journal_initialization(route.system_genesis(), || {
                    Ok::<(), core::convert::Infallible>(())
                })? {
                    Ok(()) => {}
                    Err(never) => match never {},
                }
            }
            Ok(owner)
        }

        fn open_with_policy(
            database: Arc<Database>,
            route: SystemAuthorityLedgerRoute,
            journal_store: JournalStoreInstanceId,
            local_node: NodeId,
            allow_staged_initialization: bool,
        ) -> Result<Arc<Self>, SystemAuthorityLedgerError> {
            route.validate()?;
            if local_node == NodeId::ZERO
                || JournalStoreInstanceId::from_bytes(*journal_store.as_bytes()).is_none()
            {
                return Err(SystemAuthorityLedgerError::InvalidLocalSigner);
            }
            let expected = RouteConfigRecord {
                version: LEDGER_SCHEMA_VERSION,
                route,
                journal_store,
                local_node,
            };
            expected.validate()?;
            let owner = Arc::new(Self {
                database: database.clone(),
                route,
                journal_store,
                local_node,
                writes: std::sync::Mutex::new(()),
            });
            let route_key = route_storage_key(route);
            let sentinel_key = route_owner_sentinel_key(route);
            let _write = owner.lock_writes()?;
            let transaction = database.begin_write()?;
            owner.ensure_exact_table_schema(&transaction)?;
            let existing = {
                let table = transaction.open_table(ROUTE_CONFIG_TABLE)?;
                table
                    .get(route_key.as_slice())?
                    .map(|value| value.value().to_vec())
            };
            match existing {
                Some(bytes) => {
                    let existing = RouteConfigRecord::decode(&bytes)
                        .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                    if existing != expected {
                        return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
                    }
                    let sentinel = transaction
                        .open_table(CONFIG_TABLE)?
                        .get(sentinel_key.as_slice())?
                        .map(|value| value.value().to_vec())
                        .ok_or(SystemAuthorityLedgerError::ConfigurationMismatch)?;
                    let sentinel = RouteConfigRecord::decode(&sentinel)
                        .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                    if sentinel != expected {
                        return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
                    }
                    if owner.table_has_route_residue(&transaction, LEGACY_ROUTE_CONFIG_TABLE_V5)?
                        || owner
                            .table_has_route_residue(&transaction, LEGACY_ROUTE_CONFIG_TABLE_V4)?
                        || owner
                            .table_has_route_residue(&transaction, LEGACY_ROUTE_CONFIG_TABLE_V3)?
                        || owner.table_has_route_residue(
                            &transaction,
                            LEGACY_PUBLICATION_INTENT_TABLE_V2,
                        )?
                    {
                        return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
                    }
                    owner.ensure_dedicated_route_database(&transaction)?;
                    // Holding this writer makes the committed snapshot stable
                    // while the independent read audit runs. Exact reopen is
                    // deliberately zero-write: drop instead of committing.
                    owner.audit_recovery_preflight()?;
                    drop(transaction);
                    drop(_write);
                    return Ok(owner);
                }
                None => {
                    if !allow_staged_initialization {
                        return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
                    }
                    if owner.database_has_any_residue(&transaction)? {
                        return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
                    }
                    transaction
                        .open_table(ROUTE_CONFIG_TABLE)?
                        .insert(route_key.as_slice(), expected.encode().as_slice())?;
                    // v2 scans CONFIG_TABLE and attempts to decode every
                    // route-prefixed row as its signer Config. This distinct
                    // route-owner wire record is therefore an intentional,
                    // permanent rollback fence for older writers.
                    transaction
                        .open_table(CONFIG_TABLE)?
                        .insert(sentinel_key.as_slice(), expected.encode().as_slice())?;
                }
            }
            // Pin every table schema atomically with first route ownership.
            {
                let _ = transaction.open_table(CONFIG_TABLE)?;
            }
            {
                let _ = transaction.open_table(JOURNAL_EXPOSURE_TABLE)?;
            }
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
            {
                let _ = transaction.open_table(PUBLICATION_INTENT_TABLE)?;
            }
            transaction.commit()?;
            drop(_write);
            Ok(owner)
        }

        pub(crate) const fn route(&self) -> SystemAuthorityLedgerRoute {
            self.route
        }

        pub(crate) const fn local_node(&self) -> NodeId {
            self.local_node
        }

        pub(crate) const fn journal_store(&self) -> JournalStoreInstanceId {
            self.journal_store
        }

        pub(crate) fn owns_database(&self, database: &Arc<Database>) -> bool {
            Arc::ptr_eq(&self.database, database)
        }

        pub(crate) fn open_signer(
            self: &Arc<Self>,
            local_signer: AuthoritySignerId,
        ) -> Result<SystemAuthorityEvidenceLedger, SystemAuthorityLedgerError> {
            if local_signer == AuthoritySignerId::ZERO {
                return Err(SystemAuthorityLedgerError::InvalidLocalSigner);
            }
            let expected = ConfigRecord {
                version: LEDGER_SCHEMA_VERSION,
                route: self.route,
                journal_store: self.journal_store,
                local_node: self.local_node,
                local_signer: *local_signer.as_bytes(),
            };
            expected.validate()?;
            let ledger = SystemAuthorityEvidenceLedger {
                owner: Arc::clone(self),
                local_signer,
            };
            let route_key = route_storage_key(self.route);
            let key = config_storage_key(self.route, local_signer.as_bytes());
            let _write = self.lock_writes()?;
            let transaction = self.database.begin_write()?;
            self.recheck_route_config(&transaction)?;
            self.audit_recovery_preflight()?;
            let existing = transaction
                .open_table(CONFIG_TABLE)?
                .get(key.as_slice())?
                .map(|value| value.value().to_vec());
            if let Some(bytes) = existing {
                let existing = ConfigRecord::decode(&bytes)
                    .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                if existing != expected {
                    return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
                }
                drop(transaction);
                return Ok(ledger);
            }

            // A signature admitted while this key was classified as remote
            // cannot become a local share merely by installing Config.
            ledger.recheck_local_signer_installation(&transaction)?;
            let mut count = 0_usize;
            {
                let table = transaction.open_table(CONFIG_TABLE)?;
                for row in table.range(route_key.as_slice()..)? {
                    let (row_key, row_value) = row?;
                    if !row_key.value().starts_with(route_key.as_slice()) {
                        break;
                    }
                    if row_key.value() == route_owner_sentinel_key(self.route) {
                        let sentinel = RouteConfigRecord::decode(row_value.value())
                            .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                        if sentinel
                            != (RouteConfigRecord {
                                version: LEDGER_SCHEMA_VERSION,
                                route: self.route,
                                journal_store: self.journal_store,
                                local_node: self.local_node,
                            })
                        {
                            return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
                        }
                        continue;
                    }
                    let config = ConfigRecord::decode(row_value.value())
                        .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                    if row_key.value()
                        != config_storage_key(config.route, &config.local_signer).as_slice()
                        || config.route != self.route
                        || config.journal_store != self.journal_store
                        || config.local_node != self.local_node
                    {
                        return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
                    }
                    count += 1;
                    if count >= MAX_LOCAL_SIGNERS_PER_SCOPE {
                        return Err(SystemAuthorityLedgerError::BacklogLimit);
                    }
                }
            }
            transaction
                .open_table(CONFIG_TABLE)?
                .insert(key.as_slice(), expected.encode().as_slice())?;
            transaction.commit()?;
            Ok(ledger)
        }

        fn ensure_exact_table_schema(
            &self,
            transaction: &redb::WriteTransaction,
        ) -> Result<(), SystemAuthorityLedgerError> {
            let definitions = [
                ROUTE_CONFIG_TABLE,
                LEGACY_ROUTE_CONFIG_TABLE_V5,
                LEGACY_ROUTE_CONFIG_TABLE_V4,
                LEGACY_ROUTE_CONFIG_TABLE_V3,
                JOURNAL_EXPOSURE_TABLE,
                CONFIG_TABLE,
                META_TABLE,
                RESERVATION_TABLE,
                PLEDGE_TABLE,
                SHARE_TABLE,
                QC_TABLE,
                FAIL_STOP_TABLE,
                PUBLICATION_INTENT_TABLE,
                LEGACY_PUBLICATION_INTENT_TABLE_V2,
            ];
            // Open the complete clean-break schema in this uncommitted writer.
            // On strict reopen the independent read audit below still proves
            // every table was already durable; these opens cannot normalize a
            // missing table because the transaction is dropped on failure.
            for definition in definitions {
                drop(transaction.open_table(definition)?);
            }
            let expected = definitions
                .into_iter()
                .map(|definition| definition.name().to_owned())
                .collect::<alloc::collections::BTreeSet<_>>();
            let mut observed = alloc::collections::BTreeSet::new();
            for table in transaction.list_tables()? {
                if !observed.insert(table.name().to_owned()) || observed.len() > expected.len() {
                    return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
                }
            }
            if observed != expected || transaction.list_multimap_tables()?.next().is_some() {
                return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
            }
            Ok(())
        }

        /// A staged per-Agent sidecar may be initialized only when the whole
        /// ledger is empty, not merely when the requested route prefix is
        /// absent. This prevents publishing a foreign/transplanted database
        /// alongside a newly installed target route.
        fn database_has_any_residue(
            &self,
            transaction: &redb::WriteTransaction,
        ) -> Result<bool, SystemAuthorityLedgerError> {
            for definition in [
                ROUTE_CONFIG_TABLE,
                LEGACY_ROUTE_CONFIG_TABLE_V5,
                LEGACY_ROUTE_CONFIG_TABLE_V4,
                LEGACY_ROUTE_CONFIG_TABLE_V3,
                JOURNAL_EXPOSURE_TABLE,
                CONFIG_TABLE,
                META_TABLE,
                RESERVATION_TABLE,
                PLEDGE_TABLE,
                SHARE_TABLE,
                QC_TABLE,
                FAIL_STOP_TABLE,
                PUBLICATION_INTENT_TABLE,
                LEGACY_PUBLICATION_INTENT_TABLE_V2,
            ] {
                if transaction.open_table(definition)?.first()?.is_some() {
                    return Ok(true);
                }
            }
            Ok(false)
        }

        fn ensure_dedicated_route_database(
            &self,
            transaction: &redb::WriteTransaction,
        ) -> Result<(), SystemAuthorityLedgerError> {
            let route_key = route_storage_key(self.route);
            for definition in [
                ROUTE_CONFIG_TABLE,
                LEGACY_ROUTE_CONFIG_TABLE_V5,
                LEGACY_ROUTE_CONFIG_TABLE_V4,
                LEGACY_ROUTE_CONFIG_TABLE_V3,
                JOURNAL_EXPOSURE_TABLE,
                CONFIG_TABLE,
                META_TABLE,
                RESERVATION_TABLE,
                PLEDGE_TABLE,
                SHARE_TABLE,
                QC_TABLE,
                FAIL_STOP_TABLE,
                PUBLICATION_INTENT_TABLE,
                LEGACY_PUBLICATION_INTENT_TABLE_V2,
            ] {
                let table = transaction.open_table(definition)?;
                for row in [table.first()?, table.last()?].into_iter().flatten() {
                    if !row.0.value().starts_with(route_key.as_slice()) {
                        return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
                    }
                }
            }
            Ok(())
        }

        fn table_has_route_residue(
            &self,
            transaction: &redb::WriteTransaction,
            definition: TableDefinition<&[u8], &[u8]>,
        ) -> Result<bool, SystemAuthorityLedgerError> {
            let route_key = route_storage_key(self.route);
            let table = transaction.open_table(definition)?;
            let mut rows = table.range(route_key.as_slice()..)?;
            let Some(row) = rows.next() else {
                return Ok(false);
            };
            Ok(row?.0.value().starts_with(route_key.as_slice()))
        }

        fn journal_exposure_in_write(
            &self,
            transaction: &redb::WriteTransaction,
        ) -> Result<Option<JournalExposureRecord>, SystemAuthorityLedgerError> {
            let bytes = transaction
                .open_table(JOURNAL_EXPOSURE_TABLE)?
                .get(route_storage_key(self.route).as_slice())?
                .map(|value| value.value().to_vec());
            let Some(bytes) = bytes else {
                return Ok(None);
            };
            let marker = JournalExposureRecord::decode(&bytes)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            if marker != JournalExposureRecord::for_owner(self) {
                return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
            }
            Ok(Some(marker))
        }

        fn journal_exposure_in_read(
            &self,
            transaction: &redb::ReadTransaction,
        ) -> Result<Option<JournalExposureRecord>, SystemAuthorityLedgerError> {
            let bytes = transaction
                .open_table(JOURNAL_EXPOSURE_TABLE)?
                .get(route_storage_key(self.route).as_slice())?
                .map(|value| value.value().to_vec());
            let Some(bytes) = bytes else {
                return Ok(None);
            };
            let marker = JournalExposureRecord::decode(&bytes)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            if marker != JournalExposureRecord::for_owner(self) {
                return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
            }
            Ok(Some(marker))
        }

        fn recheck_route_config_allow_unexposed(
            &self,
            transaction: &redb::WriteTransaction,
        ) -> Result<(), SystemAuthorityLedgerError> {
            let route_key = route_storage_key(self.route);
            let expected = RouteConfigRecord {
                version: LEDGER_SCHEMA_VERSION,
                route: self.route,
                journal_store: self.journal_store,
                local_node: self.local_node,
            };
            let route = transaction
                .open_table(ROUTE_CONFIG_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::ConfigurationMismatch)?;
            let route = RouteConfigRecord::decode(&route)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            let sentinel = transaction
                .open_table(CONFIG_TABLE)?
                .get(route_owner_sentinel_key(self.route).as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::ConfigurationMismatch)?;
            let sentinel = RouteConfigRecord::decode(&sentinel)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            if route != expected
                || sentinel != expected
                || self.table_has_route_residue(transaction, LEGACY_ROUTE_CONFIG_TABLE_V5)?
                || self.table_has_route_residue(transaction, LEGACY_ROUTE_CONFIG_TABLE_V4)?
                || self.table_has_route_residue(transaction, LEGACY_ROUTE_CONFIG_TABLE_V3)?
                || self.table_has_route_residue(transaction, LEGACY_PUBLICATION_INTENT_TABLE_V2)?
            {
                return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
            }
            Ok(())
        }

        fn recheck_route_config(
            &self,
            transaction: &redb::WriteTransaction,
        ) -> Result<(), SystemAuthorityLedgerError> {
            self.recheck_route_config_allow_unexposed(transaction)?;
            if self.journal_exposure_in_write(transaction)?.is_none() {
                return Err(SystemAuthorityLedgerError::JournalExposureRequired);
            }
            Ok(())
        }

        pub(crate) fn journal_exposure_is_committed(
            &self,
        ) -> Result<bool, SystemAuthorityLedgerError> {
            let _write = self.lock_writes()?;
            let transaction = self.database.begin_write()?;
            self.recheck_route_config_allow_unexposed(&transaction)?;
            self.audit_recovery_preflight()?;
            let committed = self.journal_exposure_in_write(&transaction)?.is_some();
            if !committed {
                // Host uses this as the pre-open discriminator. An unmarked
                // route is eligible for filesystem initialization only while
                // its evidence state is still pristine; reject residue before
                // the journal driver gets an opportunity to repair anything.
                self.ensure_unexposed_initialization_pristine(&transaction)?;
            }
            drop(transaction);
            Ok(committed)
        }

        /// Run the one transition which may expose an initialized journal for
        /// a previously unexposed route. The redb writer spans the complete
        /// external operation. An operation error drops the transaction and
        /// therefore cannot install the permanent exposure row.
        pub(crate) fn with_unexposed_journal_initialization<T, E>(
            &self,
            system_genesis: AgentJournalGenesisId,
            operation: impl FnOnce() -> Result<T, E>,
        ) -> Result<Result<T, E>, SystemAuthorityLedgerError> {
            if system_genesis == AgentJournalGenesisId::ZERO
                || system_genesis != self.route.system_genesis()
            {
                return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
            }
            let _write = self.lock_writes()?;
            let transaction = self.database.begin_write()?;
            self.recheck_route_config_allow_unexposed(&transaction)?;
            self.audit_recovery_preflight()?;
            if self.journal_exposure_in_write(&transaction)?.is_some() {
                return Err(SystemAuthorityLedgerError::JournalExposureAlreadyCommitted);
            }
            self.ensure_unexposed_initialization_pristine(&transaction)?;

            let result = operation();
            let value = match result {
                Ok(value) => value,
                Err(error) => {
                    drop(transaction);
                    return Ok(Err(error));
                }
            };

            // The writer excludes every supported ledger mutation while the
            // filesystem driver runs. Recheck the complete ledger snapshot
            // before making the irreversible marker durable nonetheless.
            self.recheck_route_config_allow_unexposed(&transaction)?;
            self.audit_recovery_preflight()?;
            if self.journal_exposure_in_write(&transaction)?.is_some() {
                return Err(SystemAuthorityLedgerError::JournalExposureAlreadyCommitted);
            }
            self.ensure_unexposed_initialization_pristine(&transaction)?;
            let marker = JournalExposureRecord::for_owner(self);
            marker.validate()?;
            transaction.open_table(JOURNAL_EXPOSURE_TABLE)?.insert(
                route_storage_key(self.route).as_slice(),
                marker.encode().as_slice(),
            )?;
            transaction.commit()?;
            Ok(Ok(value))
        }

        fn ensure_unexposed_initialization_pristine(
            &self,
            transaction: &redb::WriteTransaction,
        ) -> Result<(), SystemAuthorityLedgerError> {
            let route_key = route_storage_key(self.route);
            for definition in [
                META_TABLE,
                RESERVATION_TABLE,
                PLEDGE_TABLE,
                SHARE_TABLE,
                QC_TABLE,
                FAIL_STOP_TABLE,
                PUBLICATION_INTENT_TABLE,
            ] {
                if self.table_has_route_residue(transaction, definition)? {
                    return Err(SystemAuthorityLedgerError::CorruptLedger);
                }
            }
            let sentinel_key = route_owner_sentinel_key(self.route);
            let mut signer_rows = 0_usize;
            let table = transaction.open_table(CONFIG_TABLE)?;
            for row in table.range(route_key.as_slice()..)? {
                let (key, _) = row?;
                if !key.value().starts_with(route_key.as_slice()) {
                    break;
                }
                if key.value() != sentinel_key.as_slice() || signer_rows != 0 {
                    return Err(SystemAuthorityLedgerError::CorruptLedger);
                }
                signer_rows += 1;
            }
            if signer_rows != 1 {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            Ok(())
        }

        pub(crate) fn is_fail_stopped(&self) -> Result<bool, SystemAuthorityLedgerError> {
            let transaction = self.database.begin_read()?;
            self.recheck_route_config_read(&transaction)?;
            let Some(bytes) = transaction
                .open_table(FAIL_STOP_TABLE)?
                .get(route_storage_key(self.route).as_slice())?
                .map(|value| value.value().to_vec())
            else {
                return Ok(false);
            };
            let fail_stop = FailStopRecord::decode(&bytes)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            if fail_stop.route != self.route {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            Ok(true)
        }

        fn recheck_route_config_read_allow_unexposed(
            &self,
            transaction: &redb::ReadTransaction,
        ) -> Result<(), SystemAuthorityLedgerError> {
            let route_key = route_storage_key(self.route);
            let expected = RouteConfigRecord {
                version: LEDGER_SCHEMA_VERSION,
                route: self.route,
                journal_store: self.journal_store,
                local_node: self.local_node,
            };
            let route = transaction
                .open_table(ROUTE_CONFIG_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::ConfigurationMismatch)?;
            let sentinel = transaction
                .open_table(CONFIG_TABLE)?
                .get(route_owner_sentinel_key(self.route).as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::ConfigurationMismatch)?;
            if RouteConfigRecord::decode(&route)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?
                != expected
                || RouteConfigRecord::decode(&sentinel)
                    .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?
                    != expected
            {
                return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
            }
            {
                let legacy = transaction.open_table(LEGACY_ROUTE_CONFIG_TABLE_V5)?;
                let mut rows = legacy.range(route_key.as_slice()..)?;
                if let Some(row) = rows.next()
                    && row?.0.value().starts_with(route_key.as_slice())
                {
                    return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
                }
            }
            {
                let legacy = transaction.open_table(LEGACY_ROUTE_CONFIG_TABLE_V4)?;
                let mut rows = legacy.range(route_key.as_slice()..)?;
                if let Some(row) = rows.next()
                    && row?.0.value().starts_with(route_key.as_slice())
                {
                    return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
                }
            }
            {
                let legacy = transaction.open_table(LEGACY_ROUTE_CONFIG_TABLE_V3)?;
                let mut rows = legacy.range(route_key.as_slice()..)?;
                if let Some(row) = rows.next()
                    && row?.0.value().starts_with(route_key.as_slice())
                {
                    return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
                }
            }
            {
                let legacy = transaction.open_table(LEGACY_PUBLICATION_INTENT_TABLE_V2)?;
                let mut rows = legacy.range(route_key.as_slice()..)?;
                if let Some(row) = rows.next()
                    && row?.0.value().starts_with(route_key.as_slice())
                {
                    return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
                }
            }
            Ok(())
        }

        fn recheck_route_config_read(
            &self,
            transaction: &redb::ReadTransaction,
        ) -> Result<(), SystemAuthorityLedgerError> {
            self.recheck_route_config_read_allow_unexposed(transaction)?;
            if self.journal_exposure_in_read(transaction)?.is_none() {
                return Err(SystemAuthorityLedgerError::JournalExposureRequired);
            }
            Ok(())
        }
    }

    /// Crash-safe authority signing child for one permanent local key. The
    /// route owner remains usable for recovery after every signer child has
    /// been dropped or rotated out.
    pub(crate) struct SystemAuthorityEvidenceLedger {
        owner: Arc<SystemAuthorityLedgerRouteOwner>,
        local_signer: AuthoritySignerId,
    }

    impl core::ops::Deref for SystemAuthorityEvidenceLedger {
        type Target = SystemAuthorityLedgerRouteOwner;

        fn deref(&self) -> &Self::Target {
            &self.owner
        }
    }

    impl SystemAuthorityEvidenceLedger {
        /// Compatibility constructor for existing replay/tests. Production
        /// code which needs multiple signer children must open one shared
        /// owner and call `open_signer`; redb still serializes writers across
        /// independently opened compatibility owners.
        #[cfg(test)]
        pub(crate) fn open(
            database: Arc<Database>,
            route: SystemAuthorityLedgerRoute,
            journal_store: JournalStoreInstanceId,
            local_node: NodeId,
            local_signer: AuthoritySignerId,
        ) -> Result<Self, SystemAuthorityLedgerError> {
            let owner =
                SystemAuthorityLedgerRouteOwner::open(database, route, journal_store, local_node)?;
            owner.open_signer(local_signer)
        }

        pub(crate) const fn local_signer(&self) -> AuthoritySignerId {
            self.local_signer
        }

        pub(crate) const fn owner(&self) -> &Arc<SystemAuthorityLedgerRouteOwner> {
            &self.owner
        }

        pub(crate) fn is_fail_stopped(&self) -> Result<bool, SystemAuthorityLedgerError> {
            self.owner.is_fail_stopped()
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

        /// Reserve a fresh catalog finalization or reconcile its exact
        /// durable claim against the current replay-authenticated root view.
        /// Catalog, genesis, and rotation claims all share the same active row
        /// and sequence-keyed pledge namespace. Fresh production callers
        /// cannot construct the request until the semantic-admission gate is
        /// installed; recovery can only reconstruct an already durable claim.
        pub(crate) fn reserve_catalog_or_reconcile(
            &self,
            view: &ReplayedSystemAuthorityView,
            request: SystemAuthorityCatalogReservationRequest,
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
            let publication_intent = transaction
                .open_table(PUBLICATION_INTENT_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
                .map(|bytes| {
                    PublicationIntentRecord::decode(&bytes)
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
                if let Some(intent) = &publication_intent {
                    intent.validate_for_reservation(&active)?;
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

                if publication_intent.is_some() {
                    // The exact admitted request remains drainable, but no
                    // bearer reissue or predecessor rebase may escape cold
                    // reconciliation once publication intent is durable.
                    return Err(SystemAuthorityLedgerError::PublicationRecoveryRequired);
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

            if publication_intent.is_some() {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
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
    }

    impl SystemAuthorityLedgerRouteOwner {
        /// Fence an exposed replay materialization against the authority
        /// high-water which survived outside the replaceable journal root.
        ///
        /// A clean ledger has no `Meta` row until the first reservation and
        /// therefore has no newer authority state to constrain. Once any
        /// reservation has installed `Meta`, every successful retirement
        /// advances it atomically with clearing the active evidence. An idle
        /// owner may expose a driver only when replay reconstructs that exact
        /// retired high-water and authority-state commitment. This rejects an
        /// otherwise internally valid snapshot containing older authority
        /// state before the Host can expose it.
        pub(crate) fn validate_replayed_view(
            &self,
            view: &ReplayedSystemAuthorityView,
        ) -> Result<(), SystemAuthorityLedgerError> {
            view.validate()?;
            if view.route() != self.route || view.journal_store() != self.journal_store {
                return Err(SystemAuthorityLedgerError::WrongRoute);
            }

            let _write = self.lock_writes()?;
            let route_key = route_storage_key(self.route);
            let transaction = self.database.begin_read()?;
            self.recheck_route_config_read(&transaction)?;
            if transaction
                .open_table(RESERVATION_TABLE)?
                .get(route_key.as_slice())?
                .is_some()
            {
                return Err(SystemAuthorityLedgerError::PublicationRecoveryRequired);
            }
            if transaction
                .open_table(PUBLICATION_INTENT_TABLE)?
                .get(route_key.as_slice())?
                .is_some()
            {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            let Some(bytes) = transaction
                .open_table(META_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
            else {
                // No reservation has ever been admitted for this route, so
                // the durable ledger has no later authority state than the
                // root-admitted replay view.
                return Ok(());
            };
            let meta = MetaRecord::decode(&bytes)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            meta.validate()?;
            if meta.route != self.route || meta.journal_store != self.journal_store {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            if meta.retired_high_water != view.committee_sequence_high_water()
                || meta.authority_state != view.authority_state_commitment()
            {
                return Err(SystemAuthorityLedgerError::StaleStateView);
            }
            Ok(())
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
            self.recheck_route_config_read_allow_unexposed(&transaction)?;
            let Some(bytes) = transaction
                .open_table(RESERVATION_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
            else {
                if transaction
                    .open_table(PUBLICATION_INTENT_TABLE)?
                    .get(route_key.as_slice())?
                    .is_some()
                {
                    return Err(SystemAuthorityLedgerError::CorruptLedger);
                }
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
            let publication_intent = transaction
                .open_table(PUBLICATION_INTENT_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
                .map(|bytes| {
                    PublicationIntentRecord::decode(&bytes)
                        .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)
                })
                .transpose()?;
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
            if let Some(intent) = &publication_intent {
                intent.validate_for_reservation(&record)?;
            }
            Ok(Some(PendingSystemAuthorityRecovery {
                record,
                publication_intent,
            }))
        }

        /// Recheck one previously loaded non-signing recovery token against
        /// the exact current Reservation and publication-intent rows.
        pub(crate) fn recheck_pending_recovery(
            &self,
            pending: &PendingSystemAuthorityRecovery,
        ) -> Result<(), SystemAuthorityLedgerError> {
            self.ensure_pending_read_only(pending)
        }

        /// Keep the exact active reservation stable across an external
        /// journal CAS. The otherwise read-only redb writer excludes every
        /// reservation rebase/replacement from all ledger handles until the
        /// operation returns. Equivalent cloned reservation bearers remain
        /// safe because both this preflight and retirement exact-compare the
        /// one durable active row.
        pub(crate) fn with_active_publication_reservation<T, E>(
            &self,
            reserved: &ReservedSystemAuthorityClaim,
            expected_certificate: &SystemAuthorityRotationCertificate,
            facts: &SystemAuthorityRotationPublicationFacts,
            operation: impl FnOnce() -> Result<T, E>,
        ) -> Result<Result<T, E>, SystemAuthorityLedgerError> {
            let _write = self.lock_writes()?;

            // First commit the immutable exact candidate. A crash from this
            // point either leaves the predecessor plus intent or the one
            // precommitted successor; cold recovery can distinguish them.
            let transaction = self.database.begin_write()?;
            let route_key = route_storage_key(self.route);
            let frozen = self.validate_active_rotation_snapshot(&transaction, &reserved.record)?;
            if &frozen != expected_certificate {
                return Err(SystemAuthorityLedgerError::InvalidCertificate);
            }
            let intent = PublicationIntentRecord::for_rotation_facts(&reserved.record, facts)?;
            {
                let mut table = transaction.open_table(PUBLICATION_INTENT_TABLE)?;
                let existing = table
                    .get(route_key.as_slice())?
                    .map(|value| value.value().to_vec());
                match existing {
                    Some(bytes) => {
                        let existing = PublicationIntentRecord::decode(&bytes)
                            .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                        if existing != intent {
                            return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
                        }
                    }
                    None => {
                        table.insert(route_key.as_slice(), intent.encode().as_slice())?;
                    }
                }
            }
            transaction.commit()?;

            // Reacquire and recheck the globally serialized writer after the
            // intent commit. Another handle may have run in between, but no
            // journal write occurs unless every row remains exact now.
            let transaction = self.database.begin_write()?;
            let frozen = self.validate_active_rotation_snapshot(&transaction, &reserved.record)?;
            if &frozen != expected_certificate {
                return Err(SystemAuthorityLedgerError::InvalidCertificate);
            }
            let persisted = transaction
                .open_table(PUBLICATION_INTENT_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::PublicationRecoveryRequired)?;
            let persisted = PublicationIntentRecord::decode(&persisted)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            if persisted != intent {
                return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
            }
            let result = operation();
            // This second writer is intentionally never committed: it fences
            // the exact reservation, QCs, Meta, FailStop, and intent across
            // dependency staging, Heads CAS, and post-CAS readback.
            drop(transaction);
            Ok(result)
        }

        /// Catalog counterpart to `with_active_publication_reservation`.
        /// Commit the exact replay-derived catalog intent before journal
        /// dependencies or Heads can become durable, then keep the active row
        /// and its frozen current-committee QC stable across the caller's
        /// complete publication and readback operation.
        pub(crate) fn with_active_catalog_publication_reservation<T, E>(
            &self,
            reserved: &ReservedSystemAuthorityClaim,
            expected_certificate: &AuthorityQuorumCertificate,
            facts: &SystemAuthorityCatalogPublicationFacts,
            operation: impl FnOnce() -> Result<T, E>,
        ) -> Result<Result<T, E>, SystemAuthorityLedgerError> {
            let _write = self.lock_writes()?;

            let transaction = self.database.begin_write()?;
            let route_key = route_storage_key(self.route);
            let frozen = self.validate_active_catalog_snapshot(&transaction, &reserved.record)?;
            if &frozen != expected_certificate {
                return Err(SystemAuthorityLedgerError::InvalidCertificate);
            }
            let intent = PublicationIntentRecord::for_catalog_facts(&reserved.record, facts)?;
            {
                let mut table = transaction.open_table(PUBLICATION_INTENT_TABLE)?;
                let existing = table
                    .get(route_key.as_slice())?
                    .map(|value| value.value().to_vec());
                match existing {
                    Some(bytes) => {
                        let existing = PublicationIntentRecord::decode(&bytes)
                            .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                        if existing != intent {
                            return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
                        }
                    }
                    None => {
                        table.insert(route_key.as_slice(), intent.encode().as_slice())?;
                    }
                }
            }
            transaction.commit()?;

            let transaction = self.database.begin_write()?;
            let frozen = self.validate_active_catalog_snapshot(&transaction, &reserved.record)?;
            if &frozen != expected_certificate {
                return Err(SystemAuthorityLedgerError::InvalidCertificate);
            }
            let persisted = transaction
                .open_table(PUBLICATION_INTENT_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::PublicationRecoveryRequired)?;
            let persisted = PublicationIntentRecord::decode(&persisted)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            if persisted != intent {
                return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
            }
            let result = operation();
            drop(transaction);
            Ok(result)
        }

        /// Keep the exact cold-recovery row, intent, and frozen QCs stable
        /// across deterministic replay, dependency staging, Heads CAS,
        /// post-CAS readback, and atomic ledger retirement. The recovered
        /// receipt retains the mutable store borrow until this transaction
        /// commits, so no caller-observable CAS-to-retirement gap exists.
        pub(crate) fn with_pending_rotation_recovery_and_retirement<'store, S, E>(
            &self,
            pending: &PendingSystemAuthorityRecovery,
            operation: impl FnOnce(
                &SystemAuthorityRotationCertificate,
            )
                -> Result<RecoveredSystemAuthorityRotation<'store, S>, E>,
        ) -> Result<Result<RetiredSystemAuthorityRotationRecovery, E>, SystemAuthorityLedgerError>
        where
            S: AgentJournalStore + 'store,
        {
            let _write = self.lock_writes()?;
            let transaction = self.database.begin_write()?;
            let frozen = self.validate_active_rotation_snapshot(&transaction, &pending.record)?;
            let expected = pending
                .publication_intent
                .as_ref()
                .ok_or(SystemAuthorityLedgerError::PublicationRecoveryRequired)?;
            let persisted = transaction
                .open_table(PUBLICATION_INTENT_TABLE)?
                .get(route_storage_key(self.route).as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::PublicationRecoveryRequired)?;
            let persisted = PublicationIntentRecord::decode(&persisted)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            if &persisted != expected {
                return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
            }
            let recovered = match operation(&frozen) {
                Ok(recovered) => recovered,
                Err(error) => return Ok(Err(error)),
            };
            let published = PublishedSystemAuthorityClaim::for_recovered_rotation(
                recovered.pending(),
                recovered.facts(),
                &frozen,
            )?;
            self.retire_validated_in_transaction(&transaction, &published)?;
            transaction.commit()?;
            Ok(Ok(recovered.into_retired(RetiredSystemAuthorityRotation {
                _private: (),
            })))
        }

        /// Catalog cold recovery keeps the exact immutable intent, active
        /// reservation, and frozen current-committee QC under one ledger
        /// writer until replay has either persisted/reverified the complete
        /// history closure and the matching claim is atomically retired.
        pub(crate) fn with_pending_catalog_recovery_and_retirement<'store, S, E>(
            &self,
            pending: &PendingSystemAuthorityRecovery,
            operation: impl FnOnce(
                &AuthorityQuorumCertificate,
            ) -> Result<RecoveredSystemAuthorityCatalog<'store, S>, E>,
        ) -> Result<Result<RetiredSystemAuthorityCatalogRecovery, E>, SystemAuthorityLedgerError>
        where
            S: AgentJournalStore + 'store,
        {
            let _write = self.lock_writes()?;
            let transaction = self.database.begin_write()?;
            let frozen = self.validate_active_catalog_snapshot(&transaction, &pending.record)?;
            let expected = pending
                .publication_intent
                .as_ref()
                .ok_or(SystemAuthorityLedgerError::PublicationRecoveryRequired)?;
            let persisted = transaction
                .open_table(PUBLICATION_INTENT_TABLE)?
                .get(route_storage_key(self.route).as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::PublicationRecoveryRequired)?;
            let persisted = PublicationIntentRecord::decode(&persisted)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            if &persisted != expected {
                return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
            }
            let recovered = match operation(&frozen) {
                Ok(recovered) => recovered,
                Err(error) => return Ok(Err(error)),
            };
            let published = PublishedSystemAuthorityClaim::for_recovered_catalog(
                recovered.pending(),
                recovered.facts(),
                &frozen,
            )?;
            self.retire_validated_in_transaction(&transaction, &published)?;
            transaction.commit()?;
            Ok(Ok(recovered.into_retired(RetiredSystemAuthorityCatalog {
                _private: (),
            })))
        }

        fn validate_active_rotation_snapshot(
            &self,
            transaction: &redb::WriteTransaction,
            expected: &ReservationRecord,
        ) -> Result<SystemAuthorityRotationCertificate, SystemAuthorityLedgerError> {
            self.recheck_route_config(transaction)?;
            let route_key = route_storage_key(self.route);
            let active = transaction
                .open_table(RESERVATION_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::ClaimNotReserved)?;
            let active = ReservationRecord::decode(&active)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            if &active != expected
                || active.route != self.route
                || active.journal_store != self.journal_store
            {
                return Err(SystemAuthorityLedgerError::ClaimNotReserved);
            }
            active.validate()?;
            let meta = transaction
                .open_table(META_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::CorruptLedger)?;
            let meta =
                MetaRecord::decode(&meta).map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            meta.validate()?;
            if meta.route != self.route
                || meta.journal_store != self.journal_store
                || meta.retired_high_water != active.prior_high_water
                || meta.authority_state != active.authority_state
            {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            if let Some(bytes) = transaction
                .open_table(FAIL_STOP_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
            {
                let fail_stop = FailStopRecord::decode(&bytes)
                    .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                fail_stop.validate()?;
                if fail_stop.route != self.route {
                    return Err(SystemAuthorityLedgerError::CorruptLedger);
                }
                // A canonical later fail-stop prevents new work but does not
                // revoke an already-frozen exact publication intent.
            }
            let SystemAuthorityLedgerClaim::CommitteeRotation {
                retiring,
                incoming,
                transition,
            } = &active.request
            else {
                return Err(SystemAuthorityLedgerError::WrongCommitteeLeg);
            };
            let claim = active.request.claim();
            let mut certificates = Vec::with_capacity(2);
            for (leg, committee) in [
                (SystemAuthorityCommitteeLeg::Retiring, retiring),
                (SystemAuthorityCommitteeLeg::Incoming, incoming),
            ] {
                let bytes = transaction
                    .open_table(QC_TABLE)?
                    .get(leg_storage_key(self.route, claim.sequence(), leg).as_slice())?
                    .map(|value| value.value().to_vec())
                    .ok_or(SystemAuthorityLedgerError::CertificateNotReady)?;
                let row = CertificateRecord::decode(&bytes)
                    .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                row.validate_for(self.route, claim.sequence(), leg, committee, claim)?;
                certificates.push(row.certificate);
            }
            SystemAuthorityRotationCertificate::new(
                transition.clone(),
                certificates.remove(0),
                certificates.remove(0),
            )
            .map_err(|_| SystemAuthorityLedgerError::InvalidCertificate)
        }

        fn validate_active_catalog_snapshot(
            &self,
            transaction: &redb::WriteTransaction,
            expected: &ReservationRecord,
        ) -> Result<AuthorityQuorumCertificate, SystemAuthorityLedgerError> {
            self.recheck_route_config(transaction)?;
            let route_key = route_storage_key(self.route);
            let active = transaction
                .open_table(RESERVATION_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::ClaimNotReserved)?;
            let active = ReservationRecord::decode(&active)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            if &active != expected
                || active.route != self.route
                || active.journal_store != self.journal_store
            {
                return Err(SystemAuthorityLedgerError::ClaimNotReserved);
            }
            active.validate()?;
            let meta = transaction
                .open_table(META_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::CorruptLedger)?;
            let meta =
                MetaRecord::decode(&meta).map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            meta.validate()?;
            if meta.route != self.route
                || meta.journal_store != self.journal_store
                || meta.retired_high_water != active.prior_high_water
                || meta.authority_state != active.authority_state
            {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            if let Some(bytes) = transaction
                .open_table(FAIL_STOP_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
            {
                let fail_stop = FailStopRecord::decode(&bytes)
                    .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                fail_stop.validate()?;
                if fail_stop.route != self.route {
                    return Err(SystemAuthorityLedgerError::CorruptLedger);
                }
                // As with rotation, a later fail-stop prevents new work but
                // cannot revoke an already frozen exact publication intent.
            }
            let SystemAuthorityLedgerClaim::Catalog { committee, .. } = &active.request else {
                return Err(SystemAuthorityLedgerError::WrongCommitteeLeg);
            };
            let claim = active.request.claim();
            let bytes = transaction
                .open_table(QC_TABLE)?
                .get(
                    leg_storage_key(
                        self.route,
                        claim.sequence(),
                        SystemAuthorityCommitteeLeg::Current,
                    )
                    .as_slice(),
                )?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::CertificateNotReady)?;
            let row = CertificateRecord::decode(&bytes)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            row.validate_for(
                self.route,
                claim.sequence(),
                SystemAuthorityCommitteeLeg::Current,
                committee,
                claim,
            )?;
            Ok(row.certificate)
        }

        /// Run only deterministic journal-open recovery while the exact route
        /// configuration and ledger snapshot are stable. Unlike the ordinary
        /// mutation gate this permits an absent exposure marker, but only for
        /// a pristine evidence state. Once exposed it permits a reservation so
        /// cold authority reconciliation can run after the store is opened.
        pub(crate) fn with_startup_root_recovery<T>(
            &self,
            operation: impl FnOnce(bool) -> T,
        ) -> Result<T, SystemAuthorityLedgerError> {
            let _write = self.lock_writes()?;
            let transaction = self.database.begin_write()?;
            self.recheck_route_config_allow_unexposed(&transaction)?;
            // Existing route ownership pins every table. Holding the writer
            // makes this independent read audit stable while deterministic
            // filesystem stage/layout recovery runs, including when an exact
            // authority reservation is pending.
            self.audit_recovery_preflight()?;
            let journal_exposure_committed =
                self.journal_exposure_in_write(&transaction)?.is_some();
            if !journal_exposure_committed {
                // This path is marker-agnostic, not evidence-agnostic. Before
                // first exposure only the permanent route sentinels may exist;
                // marked routes may legitimately carry pending recovery rows.
                self.ensure_unexposed_initialization_pristine(&transaction)?;
            }
            let result = operation(journal_exposure_committed);
            drop(transaction);
            Ok(result)
        }

        /// Run a complete root mutation only while reservation insertion is
        /// excluded by redb's global writer. A TargetConflict may leave no
        /// permanent decision-tree leaf, so its exact publication suffix must
        /// remain available until retirement clears the row.
        ///
        /// The journal operation executes inside this closure while the
        /// evidence database writer remains held; every signer child must
        /// acquire that same redb writer and cannot race the no-pending check.
        pub(crate) fn with_no_pending_root_mutation<T>(
            &self,
            operation: impl FnOnce() -> T,
        ) -> Result<T, SystemAuthorityLedgerError> {
            let _write = self.lock_writes()?;
            let transaction = self.database.begin_write()?;
            self.recheck_route_config(&transaction)?;
            if transaction
                .open_table(RESERVATION_TABLE)?
                .get(route_storage_key(self.route).as_slice())?
                .is_some()
                || transaction
                    .open_table(PUBLICATION_INTENT_TABLE)?
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

        /// Test-only durable-corruption hook used to prove that cold replay
        /// loads every dependency named by the immutable payload and leaves
        /// the pending evidence untouched on failure.
        #[cfg(test)]
        pub(crate) fn replace_pending_ordered_entry_for_test(
            &self,
            entry: OrderedEntry,
        ) -> Result<(), SystemAuthorityLedgerError> {
            entry
                .validate()
                .map_err(|_| SystemAuthorityLedgerError::InvalidPublicationReceipt)?;
            let _write = self.lock_writes()?;
            let transaction = self.database.begin_write()?;
            self.recheck_route_config(&transaction)?;
            let route_key = route_storage_key(self.route);
            let bytes = transaction
                .open_table(PUBLICATION_INTENT_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::PublicationRecoveryRequired)?;
            let mut intent = PublicationIntentRecord::decode(&bytes)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            intent.ordered_entry = entry.id();
            intent.ordered_entry_payload = entry;
            intent.validate()?;
            transaction
                .open_table(PUBLICATION_INTENT_TABLE)?
                .insert(route_key.as_slice(), intent.encode().as_slice())?;
            transaction.commit()?;
            Ok(())
        }
    }

    impl SystemAuthorityEvidenceLedger {
        pub(crate) fn recover_pending_claim(
            &self,
        ) -> Result<Option<PendingSystemAuthorityRecovery>, SystemAuthorityLedgerError> {
            self.owner.recover_pending_claim()
        }

        pub(crate) fn recheck_pending_recovery(
            &self,
            pending: &PendingSystemAuthorityRecovery,
        ) -> Result<(), SystemAuthorityLedgerError> {
            self.owner.recheck_pending_recovery(pending)
        }

        pub(crate) fn with_active_publication_reservation<T, E>(
            &self,
            reserved: &ReservedSystemAuthorityClaim,
            expected_certificate: &SystemAuthorityRotationCertificate,
            facts: &SystemAuthorityRotationPublicationFacts,
            operation: impl FnOnce() -> Result<T, E>,
        ) -> Result<Result<T, E>, SystemAuthorityLedgerError> {
            self.owner.with_active_publication_reservation(
                reserved,
                expected_certificate,
                facts,
                operation,
            )
        }

        pub(crate) fn with_no_pending_root_mutation<T>(
            &self,
            operation: impl FnOnce() -> T,
        ) -> Result<T, SystemAuthorityLedgerError> {
            self.owner.with_no_pending_root_mutation(operation)
        }

        pub(crate) fn with_no_pending_reservation_for_gc<T>(
            &self,
            operation: impl FnOnce() -> T,
        ) -> Result<T, SystemAuthorityLedgerError> {
            self.owner.with_no_pending_root_mutation(operation)
        }

        #[cfg(test)]
        fn has_pending_reservation(&self) -> Result<bool, SystemAuthorityLedgerError> {
            self.owner.has_pending_reservation()
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
    }

    impl SystemAuthorityLedgerRouteOwner {
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

        /// Retire the exact fresh rotation while its opaque receipt still
        /// retains the mutable physical journal-store borrow. Replay outputs
        /// become available only after the durable reservation row and frozen
        /// QCs have been atomically retired.
        pub(crate) fn retire_published_rotation<S: AgentJournalStore>(
            &self,
            published: PublishedSystemAuthorityRotation<'_, S>,
        ) -> Result<
            (
                JournalPublication,
                ReplayMaterialization,
                Vec<ReplayExecutionResult>,
            ),
            SystemAuthorityLedgerError,
        > {
            let frozen = self
                .joint_rotation_certificate(published.reserved())?
                .ok_or(SystemAuthorityLedgerError::CertificateNotReady)?;
            let claim = PublishedSystemAuthorityClaim::for_rotation_receipt(
                published.reserved(),
                published.facts(),
                &frozen,
            )?;
            self.retire_published_claim(claim)?;
            Ok(published.into_results(RetiredSystemAuthorityRotation { _private: () }))
        }

        /// Retire an exact fresh catalog finalization only after replay's
        /// opaque receipt proves that the complete catalog history closure and
        /// successor journal head are durable. Results remain borrow-locked
        /// until the reservation, intent, and current-committee QC are removed
        /// atomically with the monotone authority high-water update.
        pub(crate) fn retire_published_catalog<S: AgentJournalStore>(
            &self,
            published: PublishedSystemAuthorityCatalog<'_, S>,
        ) -> Result<
            (
                JournalPublication,
                ReplayMaterialization,
                Vec<ReplayExecutionResult>,
            ),
            SystemAuthorityLedgerError,
        > {
            let frozen = self
                .certificate(published.reserved(), SystemAuthorityCommitteeLeg::Current)?
                .ok_or(SystemAuthorityLedgerError::CertificateNotReady)?;
            let claim = PublishedSystemAuthorityClaim::for_catalog_receipt(
                published.reserved(),
                published.facts(),
                &frozen,
            )?;
            self.retire_published_claim(claim)?;
            Ok(published.into_results(RetiredSystemAuthorityCatalog { _private: () }))
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

        fn ensure_reserved(
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
            self.recheck_route_config_read(&transaction)?;
            if let Some(bytes) = transaction
                .open_table(FAIL_STOP_TABLE)?
                .get(route_storage_key(self.route).as_slice())?
                .map(|value| value.value().to_vec())
            {
                let fail_stop = FailStopRecord::decode(&bytes)
                    .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                if fail_stop.route != self.route {
                    return Err(SystemAuthorityLedgerError::CorruptLedger);
                }
                return Err(SystemAuthorityLedgerError::FailStopped);
            }
            let bytes = transaction
                .open_table(RESERVATION_TABLE)?
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
            self.recheck_route_config_read(&transaction)?;
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
            self.recheck_route_config_read(&transaction)?;
            let bytes = transaction
                .open_table(RESERVATION_TABLE)?
                .get(route_storage_key(self.route).as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::ClaimNotReserved)?;
            let active = ReservationRecord::decode(&bytes)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            let publication_intent = transaction
                .open_table(PUBLICATION_INTENT_TABLE)?
                .get(route_storage_key(self.route).as_slice())?
                .map(|value| value.value().to_vec())
                .map(|bytes| {
                    PublicationIntentRecord::decode(&bytes)
                        .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)
                })
                .transpose()?;
            if active != pending.record || publication_intent != pending.publication_intent {
                return Err(SystemAuthorityLedgerError::ClaimNotReserved);
            }
            Ok(())
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
            let transaction = self.database.begin_read()?;
            self.recheck_route_config_read(&transaction)?;
            let Some(bytes) = transaction
                .open_table(QC_TABLE)?
                .get(key.as_slice())?
                .map(|value| value.value().to_vec())
            else {
                return Ok(None);
            };
            let row = CertificateRecord::decode(&bytes)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            row.validate_for(self.route, claim.sequence(), leg, committee, claim)?;
            Ok(Some(row.certificate))
        }
    }

    impl SystemAuthorityEvidenceLedger {
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
            let transaction = self.database.begin_read()?;
            self.owner.recheck_route_config_read(&transaction)?;
            let Some(bytes) = transaction
                .open_table(SHARE_TABLE)?
                .get(key.as_slice())?
                .map(|value| value.value().to_vec())
            else {
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
            self.owner.certificate_for_record(record, leg)
        }

        fn pledged_claim(
            &self,
            sequence: u64,
            signer: &[u8; 32],
        ) -> Result<Option<AuthorityClaimCommitment>, SystemAuthorityLedgerError> {
            let key = pledge_storage_key(self.route, signer, sequence);
            let transaction = self.database.begin_read()?;
            self.owner.recheck_route_config_read(&transaction)?;
            let Some(bytes) = transaction
                .open_table(PLEDGE_TABLE)?
                .get(key.as_slice())?
                .map(|value| value.value().to_vec())
            else {
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
    }

    impl SystemAuthorityLedgerRouteOwner {
        fn retire_validated(
            &self,
            published: PublishedSystemAuthorityClaim,
        ) -> Result<(), SystemAuthorityLedgerError> {
            let _write = self.lock_writes()?;
            let transaction = self.database.begin_write()?;
            self.retire_validated_in_transaction(&transaction, &published)?;
            transaction.commit()?;
            Ok(())
        }

        fn retire_validated_in_transaction(
            &self,
            transaction: &redb::WriteTransaction,
            published: &PublishedSystemAuthorityClaim,
        ) -> Result<(), SystemAuthorityLedgerError> {
            let reserved = &published.reservation;
            let intent_commitment = match &published.publication_intent {
                Some(intent) => intent.facts,
                #[cfg(test)]
                None => Hash::digest(
                    b"vos/agent/system-authority-test-publication-intent/v1",
                    &[
                        reserved.predecessor_heads.as_bytes(),
                        published.successor_heads.as_bytes(),
                        &reserved.request.claim().claim_hash().0,
                    ],
                ),
                #[cfg(not(test))]
                None => return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt),
            };
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
                SystemAuthorityLedgerClaim::Catalog { committee, .. } => {
                    if published.resulting_first_sequence.is_some()
                        || published.resulting_committee != committee.commitment()
                    {
                        return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
                    }
                }
            }

            let route_key = route_storage_key(self.route);
            let sequence = request.sequence();
            let claim = request.claim();
            self.recheck_route_config(&transaction)?;
            let current_meta = transaction
                .open_table(META_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(SystemAuthorityLedgerError::CorruptLedger)?;
            let current_meta = MetaRecord::decode(&current_meta)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            current_meta.validate()?;
            let current_intent = transaction
                .open_table(PUBLICATION_INTENT_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec())
                .map(|bytes| {
                    PublicationIntentRecord::decode(&bytes)
                        .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)
                })
                .transpose()?;

            let active = transaction
                .open_table(RESERVATION_TABLE)?
                .get(route_key.as_slice())?
                .map(|value| value.value().to_vec());
            if active.is_none()
                && current_intent.is_none()
                && current_meta.route == self.route
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
                        intent: intent_commitment,
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
            match (&published.publication_intent, &current_intent) {
                (Some(expected), Some(current)) if expected == current => {}
                #[cfg(test)]
                (None, None) => {}
                _ => return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt),
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
                    intent: intent_commitment,
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
            {
                transaction
                    .open_table(PUBLICATION_INTENT_TABLE)?
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
            Ok(())
        }
    }

    impl SystemAuthorityEvidenceLedger {
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
            self.owner.recheck_route_config(transaction)?;
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
            if transaction
                .open_table(PUBLICATION_INTENT_TABLE)?
                .get(route_key.as_slice())?
                .is_some()
            {
                return Err(SystemAuthorityLedgerError::PublicationRecoveryRequired);
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
    }

    impl SystemAuthorityLedgerRouteOwner {
        fn lock_writes(&self) -> Result<std::sync::MutexGuard<'_, ()>, SystemAuthorityLedgerError> {
            self.writes
                .lock()
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)
        }

        fn audit_recovery_preflight(&self) -> Result<(), SystemAuthorityLedgerError> {
            self.audit_recovery_inner(false)
        }

        fn audit_recovery_inner(
            &self,
            allow_missing_tables: bool,
        ) -> Result<(), SystemAuthorityLedgerError> {
            let route_key = route_storage_key(self.route);
            let expected_route = RouteConfigRecord {
                version: LEDGER_SCHEMA_VERSION,
                route: self.route,
                journal_store: self.journal_store,
                local_node: self.local_node,
            };
            let route_rows = rows_for_prefix_bounded_maybe_missing(
                &self.database,
                ROUTE_CONFIG_TABLE,
                route_key.as_slice(),
                1,
                allow_missing_tables,
            )?;
            let [(route_row_key, route_config)] = route_rows.as_slice() else {
                return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
            };
            if route_row_key.as_slice() != route_key.as_slice() {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            let route_config = RouteConfigRecord::decode(route_config)
                .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
            if route_config != expected_route {
                return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
            }
            if !rows_for_prefix_bounded_maybe_missing(
                &self.database,
                LEGACY_ROUTE_CONFIG_TABLE_V5,
                route_key.as_slice(),
                1,
                allow_missing_tables,
            )?
            .is_empty()
                || !rows_for_prefix_bounded_maybe_missing(
                    &self.database,
                    LEGACY_ROUTE_CONFIG_TABLE_V4,
                    route_key.as_slice(),
                    1,
                    allow_missing_tables,
                )?
                .is_empty()
                || !rows_for_prefix_bounded_maybe_missing(
                    &self.database,
                    LEGACY_ROUTE_CONFIG_TABLE_V3,
                    route_key.as_slice(),
                    1,
                    allow_missing_tables,
                )?
                .is_empty()
                || !rows_for_prefix_bounded_maybe_missing(
                    &self.database,
                    LEGACY_PUBLICATION_INTENT_TABLE_V2,
                    route_key.as_slice(),
                    1,
                    allow_missing_tables,
                )?
                .is_empty()
            {
                return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
            }
            let exposure_rows = rows_for_prefix_bounded_maybe_missing(
                &self.database,
                JOURNAL_EXPOSURE_TABLE,
                route_key.as_slice(),
                1,
                allow_missing_tables,
            )?;
            match exposure_rows.as_slice() {
                [] => {}
                [(key, bytes)] if key.as_slice() == route_key.as_slice() => {
                    let marker = JournalExposureRecord::decode(bytes)
                        .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                    if marker != JournalExposureRecord::for_owner(self) {
                        return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
                    }
                }
                _ => return Err(SystemAuthorityLedgerError::CorruptLedger),
            }
            let config_rows = rows_for_prefix_bounded_maybe_missing(
                &self.database,
                CONFIG_TABLE,
                route_key.as_slice(),
                MAX_LOCAL_SIGNERS_PER_SCOPE + 1,
                allow_missing_tables,
            )?;
            let mut configured = alloc::collections::BTreeSet::new();
            let mut saw_owner_sentinel = false;
            for (key, bytes) in config_rows {
                if key == route_owner_sentinel_key(self.route) {
                    if saw_owner_sentinel {
                        return Err(SystemAuthorityLedgerError::CorruptLedger);
                    }
                    let sentinel = RouteConfigRecord::decode(&bytes)
                        .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                    if sentinel != expected_route {
                        return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
                    }
                    saw_owner_sentinel = true;
                    continue;
                }
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
            if !saw_owner_sentinel {
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
            let publication_intent = read_exact_maybe_missing(
                &self.database,
                PUBLICATION_INTENT_TABLE,
                route_key.as_slice(),
                allow_missing_tables,
            )?
            .map(|bytes| {
                PublicationIntentRecord::decode(&bytes)
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
            if publication_intent.is_some() && reservation.is_none() {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            if let (Some(intent), Some(reservation)) = (&publication_intent, &reservation) {
                intent.validate_for_reservation(reservation)?;
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

                let mut certificates = alloc::collections::BTreeMap::new();
                for (key, bytes) in qc_rows {
                    let row = CertificateRecord::decode(&bytes)
                        .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                    let committee = request
                        .committee(row.leg)
                        .ok_or(SystemAuthorityLedgerError::CorruptLedger)?;
                    if key != leg_storage_key(self.route, row.sequence, row.leg)
                        || certificates
                            .insert(row.leg, row.certificate.clone())
                            .is_some()
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
                if publication_intent.is_some() {
                    let intent = publication_intent
                        .as_ref()
                        .ok_or(SystemAuthorityLedgerError::CorruptLedger)?;
                    match request {
                        SystemAuthorityLedgerClaim::CommitteeRotation {
                            incoming,
                            transition,
                            ..
                        } => {
                            let old = certificates
                                .get(&SystemAuthorityCommitteeLeg::Retiring)
                                .cloned()
                                .ok_or(SystemAuthorityLedgerError::CertificateNotReady)?;
                            let new = certificates
                                .get(&SystemAuthorityCommitteeLeg::Incoming)
                                .cloned()
                                .ok_or(SystemAuthorityLedgerError::CertificateNotReady)?;
                            let frozen = SystemAuthorityRotationCertificate::new(
                                transition.clone(),
                                old,
                                new,
                            )
                            .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                            let ReplayOperation::Management {
                                request: LifecycleRequest::RotateSystemAuthority(command),
                            } = &intent.ordered_entry_payload.input.operation
                            else {
                                return Err(SystemAuthorityLedgerError::CorruptLedger);
                            };
                            if command.certificate() != &frozen
                                || command.certificate().transition() != transition
                                || command.new_committee() != incoming
                            {
                                return Err(SystemAuthorityLedgerError::CorruptLedger);
                            }
                        }
                        SystemAuthorityLedgerClaim::Catalog {
                            committee,
                            fact,
                            proof,
                        } => {
                            let frozen = certificates
                                .get(&SystemAuthorityCommitteeLeg::Current)
                                .ok_or(SystemAuthorityLedgerError::CertificateNotReady)?;
                            let ReplayOperation::Management {
                                request: LifecycleRequest::FinalizeCatalog(command),
                            } = &intent.ordered_entry_payload.input.operation
                            else {
                                return Err(SystemAuthorityLedgerError::CorruptLedger);
                            };
                            if command.receipt().certificate() != frozen
                                || command.receipt().fact() != fact
                                || command.proof() != proof
                                || frozen.committee().0 != committee.commitment().0
                            {
                                return Err(SystemAuthorityLedgerError::CorruptLedger);
                            }
                        }
                        SystemAuthorityLedgerClaim::AgentGenesis { .. } => {
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
                && (meta.is_some()
                    || has_reservation
                    || has_evidence_rows
                    || publication_intent.is_some()
                    || failure.is_some())
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

    /// Permanent proof that the exact root journal reached its externally
    /// visible initialized state. Absence is meaningful only during startup;
    /// once committed this row is never removed by any supported operation.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct JournalExposureRecord {
        version: u32,
        route: SystemAuthorityLedgerRoute,
        journal_store: JournalStoreInstanceId,
        local_node: NodeId,
        system_genesis: AgentJournalGenesisId,
    }

    impl JournalExposureRecord {
        fn for_owner(owner: &SystemAuthorityLedgerRouteOwner) -> Self {
            Self {
                version: JOURNAL_EXPOSURE_RECORD_VERSION,
                route: owner.route,
                journal_store: owner.journal_store,
                local_node: owner.local_node,
                system_genesis: owner.route.system_genesis(),
            }
        }

        fn validate(&self) -> Result<(), SystemAuthorityLedgerError> {
            self.route.validate()?;
            if self.version != JOURNAL_EXPOSURE_RECORD_VERSION
                || JournalStoreInstanceId::from_bytes(*self.journal_store.as_bytes()).is_none()
                || self.local_node == NodeId::ZERO
                || self.system_genesis == AgentJournalGenesisId::ZERO
                || self.system_genesis != self.route.system_genesis()
                || self.encode().len() > MAX_JOURNAL_EXPOSURE_RECORD_BYTES
            {
                return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
            }
            Ok(())
        }
    }

    impl ServiceWire for JournalExposureRecord {
        const MAGIC: [u8; 4] = *b"AULJ";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encoder.u32(self.version);
            encoder.bytes(&self.route.encode());
            encoder.fixed(self.journal_store.as_bytes());
            encoder.fixed(&self.local_node.0);
            encoder.fixed(self.system_genesis.as_bytes());
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_JOURNAL_EXPOSURE_RECORD_BYTES)?;
            let record = Self {
                version: decoder.u32()?,
                route: decode_nested(decoder, MAX_SYSTEM_AUTHORITY_LEDGER_ROUTE_BYTES)?,
                journal_store: JournalStoreInstanceId::from_bytes(decoder.fixed()?)
                    .ok_or(DecodeError::NonCanonical)?,
                local_node: NodeId(decoder.fixed()?),
                system_genesis: AgentJournalGenesisId::new(decoder.fixed()?),
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    /// Permanent signer-independent route ownership. The identical bytes are
    /// stored in the v5 route table and under the reserved all-zero signer key
    /// in legacy Config as a mutual rollback fence.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RouteConfigRecord {
        version: u32,
        route: SystemAuthorityLedgerRoute,
        journal_store: JournalStoreInstanceId,
        local_node: NodeId,
    }

    impl RouteConfigRecord {
        fn validate(&self) -> Result<(), SystemAuthorityLedgerError> {
            self.route.validate()?;
            if self.version != LEDGER_SCHEMA_VERSION
                || self.local_node == NodeId::ZERO
                || JournalStoreInstanceId::from_bytes(*self.journal_store.as_bytes()).is_none()
                || self.encode().len() > MAX_ROUTE_CONFIG_RECORD_BYTES
            {
                return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
            }
            Ok(())
        }
    }

    impl ServiceWire for RouteConfigRecord {
        const MAGIC: [u8; 4] = *b"AULO";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encoder.u32(self.version);
            encoder.bytes(&self.route.encode());
            encoder.fixed(self.journal_store.as_bytes());
            encoder.fixed(&self.local_node.0);
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_ROUTE_CONFIG_RECORD_BYTES)?;
            let record = Self {
                version: decoder.u32()?,
                route: decode_nested(decoder, MAX_SYSTEM_AUTHORITY_LEDGER_ROUTE_BYTES)?,
                journal_store: JournalStoreInstanceId::from_bytes(decoder.fixed()?)
                    .ok_or(DecodeError::NonCanonical)?,
                local_node: NodeId(decoder.fixed()?),
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
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

    /// Transition-specific identity retained inside one bounded publication
    /// intent. The complete command already lives in the canonical ordered
    /// entry, so this tag stores only the independently checked permanent
    /// history identifiers needed for exact recovery.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum PublicationIntentKind {
        Rotation {
            rotation: SystemAuthorityRotationId,
            leaf: SystemAuthorityRotationNodeId,
            root: SystemAuthorityRotationNodeId,
            old_committee: SystemAuthorityCommitteeId,
            new_committee: SystemAuthorityCommitteeId,
        },
        Catalog {
            record: SystemAuthorityCatalogRecordId,
            leaf: SystemAuthorityCatalogNodeId,
            root: SystemAuthorityCatalogNodeId,
        },
    }

    /// Immutable exact publication candidate committed after the required
    /// frozen QC(s) and before any journal dependency or Heads CAS. Its facts
    /// commitment is produced only by replay's private native-transition
    /// object.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct PublicationIntentRecord {
        version: u32,
        route: SystemAuthorityLedgerRoute,
        journal_store: JournalStoreInstanceId,
        predecessor_heads: JournalHeadsId,
        predecessor_control: LaneStateId,
        predecessor_view: Hash,
        predecessor_authority_state: Hash,
        successor_heads: JournalHeadsId,
        ordered_entry: OrderedEntryId,
        ordered_entry_payload: OrderedEntry,
        successor_control: LaneStateId,
        successor_view: Hash,
        successor_authority_state: Hash,
        claim: Hash,
        operation: Hash,
        kind: PublicationIntentKind,
        storage_plan: Hash,
        facts: Hash,
    }

    impl PublicationIntentRecord {
        fn for_rotation_facts(
            reservation: &ReservationRecord,
            facts: &SystemAuthorityRotationPublicationFacts,
        ) -> Result<Self, SystemAuthorityLedgerError> {
            let SystemAuthorityLedgerClaim::CommitteeRotation {
                retiring,
                incoming,
                transition,
            } = &reservation.request
            else {
                return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
            };
            let record = facts.record();
            let ordered_entry = facts.ordered_entry();
            let ReplayOperation::Management {
                request: LifecycleRequest::RotateSystemAuthority(command),
            } = &ordered_entry.input.operation
            else {
                return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
            };
            if facts.journal_store() != reservation.journal_store
                || facts.predecessor_heads() != reservation.predecessor_heads
                || facts.predecessor_control() != reservation.control_state
                || facts.predecessor_view() != reservation.state_view
                || facts.predecessor_authority_state() != reservation.authority_state
                || facts.claim() != reservation.request.claim()
                || facts.successor_heads() == JournalHeadsId::ZERO
                || facts.successor_heads() == facts.predecessor_heads()
                || ordered_entry.validate().is_err()
                || facts.ordered_entry_id() == OrderedEntryId::ZERO
                || command != facts.command()
                || command.operation_commitment() != facts.operation()
                || facts.successor_control() == LaneStateId::ZERO
                || facts.successor_view() == Hash::ZERO
                || facts.successor_authority_state() == Hash::ZERO
                || facts.operation() == Hash::ZERO
                || facts.storage_plan() == Hash::ZERO
                || record.old_committee().as_bytes() != &retiring.commitment().0
                || record.new_committee().as_bytes() != &incoming.commitment().0
                || record.certificate().transition() != transition
                || facts.result()
                    != &(LifecycleReply::SystemAuthorityRotated {
                        rotation: record.id(),
                        epoch: record.new_epoch(),
                        exact_retry: false,
                    })
            {
                return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
            }
            let intent = Self {
                version: LEDGER_SCHEMA_VERSION,
                route: reservation.route,
                journal_store: facts.journal_store(),
                predecessor_heads: facts.predecessor_heads(),
                predecessor_control: facts.predecessor_control(),
                predecessor_view: facts.predecessor_view(),
                predecessor_authority_state: facts.predecessor_authority_state(),
                successor_heads: facts.successor_heads(),
                ordered_entry: facts.ordered_entry_id(),
                ordered_entry_payload: ordered_entry.clone(),
                successor_control: facts.successor_control(),
                successor_view: facts.successor_view(),
                successor_authority_state: facts.successor_authority_state(),
                claim: facts.claim().claim_hash(),
                operation: facts.operation(),
                kind: PublicationIntentKind::Rotation {
                    rotation: record.id(),
                    leaf: record.leaf_id(),
                    root: facts.root(),
                    old_committee: record.old_committee(),
                    new_committee: record.new_committee(),
                },
                storage_plan: facts.storage_plan(),
                facts: facts.commitment(),
            };
            intent.validate()?;
            intent.validate_for_reservation(reservation)?;
            Ok(intent)
        }

        fn for_catalog_facts(
            reservation: &ReservationRecord,
            facts: &SystemAuthorityCatalogPublicationFacts,
        ) -> Result<Self, SystemAuthorityLedgerError> {
            let SystemAuthorityLedgerClaim::Catalog {
                committee,
                fact,
                proof,
            } = &reservation.request
            else {
                return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
            };
            let record = facts.record();
            let ordered_entry = facts.ordered_entry();
            let ReplayOperation::Management {
                request: LifecycleRequest::FinalizeCatalog(command),
            } = &ordered_entry.input.operation
            else {
                return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
            };
            let receipt = record.receipt();
            let finalized = SystemAuthorityCatalogFinalizeOutcome::Finalized {
                operation: record.operation_id(),
                result: fact.result().commitment(),
                catalog_head: fact.resulting_catalog_head(),
                authority_generation: fact.resulting_authority_generation(),
                sequence: fact.sequence(),
            };
            if facts.journal_store() != reservation.journal_store
                || facts.predecessor_heads() != reservation.predecessor_heads
                || facts.predecessor_control() != reservation.control_state
                || facts.predecessor_view() != reservation.state_view
                || facts.predecessor_authority_state() != reservation.authority_state
                || facts.claim() != reservation.request.claim()
                || facts.successor_heads() == JournalHeadsId::ZERO
                || facts.successor_heads() == facts.predecessor_heads()
                || ordered_entry.validate().is_err()
                || facts.ordered_entry_id() == OrderedEntryId::ZERO
                || command != facts.command()
                || command.operation_commitment() != facts.operation()
                || command.receipt() != receipt
                || command.proof() != proof
                || receipt.fact() != fact
                || receipt.certificate().claim() != fact.authority_claim()
                || receipt.certificate().committee().0 != committee.commitment().0
                || facts.successor_control() == LaneStateId::ZERO
                || facts.successor_view() == Hash::ZERO
                || facts.successor_authority_state() == Hash::ZERO
                || facts.operation() == Hash::ZERO
                || facts.root() == SystemAuthorityCatalogNodeId::ZERO
                || facts.storage_plan() == Hash::ZERO
                || facts.result() != &LifecycleReply::CatalogFinalized(finalized)
            {
                return Err(SystemAuthorityLedgerError::InvalidPublicationReceipt);
            }
            let intent = Self {
                version: LEDGER_SCHEMA_VERSION,
                route: reservation.route,
                journal_store: facts.journal_store(),
                predecessor_heads: facts.predecessor_heads(),
                predecessor_control: facts.predecessor_control(),
                predecessor_view: facts.predecessor_view(),
                predecessor_authority_state: facts.predecessor_authority_state(),
                successor_heads: facts.successor_heads(),
                ordered_entry: facts.ordered_entry_id(),
                ordered_entry_payload: ordered_entry.clone(),
                successor_control: facts.successor_control(),
                successor_view: facts.successor_view(),
                successor_authority_state: facts.successor_authority_state(),
                claim: facts.claim().claim_hash(),
                operation: facts.operation(),
                kind: PublicationIntentKind::Catalog {
                    record: record.id(),
                    leaf: record.leaf_id(),
                    root: facts.root(),
                },
                storage_plan: facts.storage_plan(),
                facts: facts.commitment(),
            };
            intent.validate()?;
            intent.validate_for_reservation(reservation)?;
            Ok(intent)
        }

        fn validate(&self) -> Result<(), SystemAuthorityLedgerError> {
            self.route.validate()?;
            if self.version != LEDGER_SCHEMA_VERSION
                || JournalStoreInstanceId::from_bytes(*self.journal_store.as_bytes()).is_none()
                || self.predecessor_heads == JournalHeadsId::ZERO
                || self.successor_heads == JournalHeadsId::ZERO
                || self.predecessor_heads == self.successor_heads
                || self.predecessor_control == LaneStateId::ZERO
                || self.successor_control == LaneStateId::ZERO
                || self.predecessor_view == Hash::ZERO
                || self.successor_view == Hash::ZERO
                || self.predecessor_authority_state == Hash::ZERO
                || self.successor_authority_state == Hash::ZERO
                || self.ordered_entry == OrderedEntryId::ZERO
                || self.ordered_entry_payload.validate().is_err()
                || self.ordered_entry_payload.id() != self.ordered_entry
                || self.claim == Hash::ZERO
                || self.operation == Hash::ZERO
                || self.storage_plan == Hash::ZERO
                || self.facts == Hash::ZERO
                || self.encode().len() > MAX_PUBLICATION_INTENT_RECORD_BYTES
            {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            if self.ordered_entry_payload.genesis != self.route.system_genesis()
                || self.ordered_entry_payload.input.runtime.space != self.route.space()
                || self.ordered_entry_payload.input.runtime.agent != self.route.system_agent()
            {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            match (&self.kind, &self.ordered_entry_payload.input.operation) {
                (
                    PublicationIntentKind::Rotation {
                        rotation,
                        leaf,
                        root,
                        old_committee,
                        new_committee,
                    },
                    ReplayOperation::Management {
                        request: LifecycleRequest::RotateSystemAuthority(command),
                    },
                ) => {
                    let transition = command.certificate().transition();
                    if *rotation == SystemAuthorityRotationId::ZERO
                        || *leaf == SystemAuthorityRotationNodeId::ZERO
                        || *root == SystemAuthorityRotationNodeId::ZERO
                        || *old_committee == SystemAuthorityCommitteeId::ZERO
                        || *new_committee == SystemAuthorityCommitteeId::ZERO
                        || old_committee == new_committee
                        || command.operation_commitment() != self.operation
                        || transition.authority_claim().claim_hash() != self.claim
                        || transition.old_committee() != *old_committee
                        || transition.new_committee() != *new_committee
                        || command.new_committee().commitment().0 != *new_committee.as_bytes()
                        || transition.root_anchor() != self.route.root_anchor()
                        || transition.root_anchor_config_version()
                            != self.route.root_anchor_config_version()
                        || transition.root_anchor_config() != self.route.root_anchor_config()
                        || transition.authority_scope() != self.route.authority_scope()
                        || transition.space() != self.route.space()
                        || transition.authority_binding() != self.route.authority_binding()
                    {
                        return Err(SystemAuthorityLedgerError::CorruptLedger);
                    }
                }
                (
                    PublicationIntentKind::Catalog { record, leaf, root },
                    ReplayOperation::Management {
                        request: LifecycleRequest::FinalizeCatalog(command),
                    },
                ) => {
                    let fact = command.receipt().fact();
                    let binding = fact.intent().binding();
                    if *record == SystemAuthorityCatalogRecordId::ZERO
                        || *leaf == SystemAuthorityCatalogNodeId::ZERO
                        || *root == SystemAuthorityCatalogNodeId::ZERO
                        || command.operation_commitment() != self.operation
                        || fact.authority_claim().claim_hash() != self.claim
                        || command.proof().occupied_record_id().is_some()
                        || command.proof().operation_id() != fact.intent().operation_id()
                        || binding.space() != self.route.space()
                        || binding.authority_binding() != self.route.authority_binding()
                    {
                        return Err(SystemAuthorityLedgerError::CorruptLedger);
                    }
                }
                _ => return Err(SystemAuthorityLedgerError::CorruptLedger),
            }
            Ok(())
        }

        fn validate_for_reservation(
            &self,
            reservation: &ReservationRecord,
        ) -> Result<(), SystemAuthorityLedgerError> {
            self.validate()?;
            if self.route != reservation.route
                || self.journal_store != reservation.journal_store
                || self.predecessor_heads != reservation.predecessor_heads
                || self.predecessor_control != reservation.control_state
                || self.predecessor_view != reservation.state_view
                || self.predecessor_authority_state != reservation.authority_state
                || self.claim != reservation.request.claim().claim_hash()
            {
                return Err(SystemAuthorityLedgerError::CorruptLedger);
            }
            match (
                &self.kind,
                &reservation.request,
                &self.ordered_entry_payload.input.operation,
            ) {
                (
                    PublicationIntentKind::Rotation {
                        old_committee,
                        new_committee,
                        ..
                    },
                    SystemAuthorityLedgerClaim::CommitteeRotation {
                        retiring,
                        incoming,
                        transition,
                    },
                    ReplayOperation::Management {
                        request: LifecycleRequest::RotateSystemAuthority(command),
                    },
                ) if old_committee.as_bytes() == &retiring.commitment().0
                    && new_committee.as_bytes() == &incoming.commitment().0
                    && command.new_committee() == incoming
                    && command.certificate().transition() == transition => {}
                (
                    PublicationIntentKind::Catalog { record, leaf, .. },
                    SystemAuthorityLedgerClaim::Catalog {
                        committee,
                        fact,
                        proof,
                    },
                    ReplayOperation::Management {
                        request: LifecycleRequest::FinalizeCatalog(command),
                    },
                ) => {
                    let candidate = SystemAuthorityCatalogRecord::new(
                        command.receipt().clone(),
                        fact.intent().binding(),
                        committee,
                    )
                    .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)?;
                    if command.receipt().fact() != fact
                        || command.proof() != proof
                        || candidate.id() != *record
                        || candidate.leaf_id() != *leaf
                    {
                        return Err(SystemAuthorityLedgerError::CorruptLedger);
                    }
                }
                _ => return Err(SystemAuthorityLedgerError::CorruptLedger),
            }
            Ok(())
        }
    }

    impl ServiceWire for PublicationIntentRecord {
        const MAGIC: [u8; 4] = *b"AULI";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encoder.u32(self.version);
            encoder.bytes(&self.route.encode());
            encoder.fixed(self.journal_store.as_bytes());
            encoder.fixed(self.predecessor_heads.as_bytes());
            encoder.fixed(self.predecessor_control.as_bytes());
            encoder.fixed(&self.predecessor_view.0);
            encoder.fixed(&self.predecessor_authority_state.0);
            encoder.fixed(self.successor_heads.as_bytes());
            encoder.fixed(self.ordered_entry.as_bytes());
            encoder.bytes(&self.ordered_entry_payload.encode());
            encoder.fixed(self.successor_control.as_bytes());
            encoder.fixed(&self.successor_view.0);
            encoder.fixed(&self.successor_authority_state.0);
            encoder.fixed(&self.claim.0);
            encoder.fixed(&self.operation.0);
            match &self.kind {
                PublicationIntentKind::Rotation {
                    rotation,
                    leaf,
                    root,
                    old_committee,
                    new_committee,
                } => {
                    encoder.u8(0);
                    encoder.fixed(rotation.as_bytes());
                    encoder.fixed(leaf.as_bytes());
                    encoder.fixed(root.as_bytes());
                    encoder.fixed(old_committee.as_bytes());
                    encoder.fixed(new_committee.as_bytes());
                }
                PublicationIntentKind::Catalog { record, leaf, root } => {
                    encoder.u8(1);
                    encoder.fixed(record.as_bytes());
                    encoder.fixed(leaf.as_bytes());
                    encoder.fixed(root.as_bytes());
                }
            }
            encoder.fixed(&self.storage_plan.0);
            encoder.fixed(&self.facts.0);
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_PUBLICATION_INTENT_RECORD_BYTES)?;
            let record = Self {
                version: decoder.u32()?,
                route: decode_nested(decoder, MAX_SYSTEM_AUTHORITY_LEDGER_ROUTE_BYTES)?,
                journal_store: JournalStoreInstanceId::from_bytes(decoder.fixed()?)
                    .ok_or(DecodeError::NonCanonical)?,
                predecessor_heads: JournalHeadsId::new(decoder.fixed()?),
                predecessor_control: LaneStateId::new(decoder.fixed()?),
                predecessor_view: Hash(decoder.fixed()?),
                predecessor_authority_state: Hash(decoder.fixed()?),
                successor_heads: JournalHeadsId::new(decoder.fixed()?),
                ordered_entry: OrderedEntryId::new(decoder.fixed()?),
                ordered_entry_payload: decode_nested(decoder, MAX_PUBLICATION_ORDERED_ENTRY_BYTES)?,
                successor_control: LaneStateId::new(decoder.fixed()?),
                successor_view: Hash(decoder.fixed()?),
                successor_authority_state: Hash(decoder.fixed()?),
                claim: Hash(decoder.fixed()?),
                operation: Hash(decoder.fixed()?),
                kind: match decoder.u8()? {
                    0 => PublicationIntentKind::Rotation {
                        rotation: SystemAuthorityRotationId::from_bytes(decoder.fixed()?),
                        leaf: SystemAuthorityRotationNodeId::from_bytes(decoder.fixed()?),
                        root: SystemAuthorityRotationNodeId::from_bytes(decoder.fixed()?),
                        old_committee: SystemAuthorityCommitteeId::from_bytes(decoder.fixed()?),
                        new_committee: SystemAuthorityCommitteeId::from_bytes(decoder.fixed()?),
                    },
                    1 => PublicationIntentKind::Catalog {
                        record: SystemAuthorityCatalogRecordId::from_bytes(decoder.fixed()?),
                        leaf: SystemAuthorityCatalogNodeId::from_bytes(decoder.fixed()?),
                        root: SystemAuthorityCatalogNodeId::from_bytes(decoder.fixed()?),
                    },
                    _ => return Err(DecodeError::InvalidTag),
                },
                storage_plan: Hash(decoder.fixed()?),
                facts: Hash(decoder.fixed()?),
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
        intent: Hash,
    }

    impl LastPublication {
        fn validate(&self) -> Result<(), SystemAuthorityLedgerError> {
            if self.predecessor_heads == JournalHeadsId::ZERO
                || self.successor_heads == JournalHeadsId::ZERO
                || self.predecessor_heads == self.successor_heads
                || self.successor_control == LaneStateId::ZERO
                || self.successor_view == Hash::ZERO
                || self.intent == Hash::ZERO
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
                encoder.fixed(&publication.intent.0);
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
                        intent: Hash(decoder.fixed()?),
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
                SystemAuthorityLedgerClaim::Catalog {
                    committee,
                    fact,
                    proof,
                } => {
                    let valid_sequence = match self.prior_first_sequence {
                        Some(first) => sequence == first,
                        None => sequence > self.prior_high_water,
                    };
                    let binding = fact.intent().binding();
                    if !valid_sequence
                        || committee.space() != self.route.space
                        || committee.authority_binding() != self.route.authority_binding
                        || binding.space() != self.route.space
                        || binding.authority_binding() != self.route.authority_binding
                        || proof.operation_id() != fact.intent().operation_id()
                        || proof.occupied_record_id().is_some()
                        || self.encode().len() > MAX_CATALOG_RESERVATION_RECORD_BYTES
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
        JournalExposureRequired,
        JournalExposureAlreadyCommitted,
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

    fn route_owner_sentinel_key(route: SystemAuthorityLedgerRoute) -> [u8; CONFIG_KEY_BYTES] {
        config_storage_key(route, &[0; 32])
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
        use crate::agent::catalog_finality::{
            CatalogMutation, CatalogMutationDisposition, CatalogMutationIntent,
            CatalogMutationKind, CatalogMutationResult, FinalizedCatalogMutationReceipt,
            MAX_CATALOG_TRANSITION_DATA_BYTES,
        };
        use crate::agent::committee::{
            AuthorityCommitteeMember, AuthorityMemberRole, MAX_AUTHORITY_COMMITTEE_MEMBERS,
            RootAnchorConfigCommitment, RootAnchorId,
        };
        use crate::agent::journal::{MergeFrontierId, MergeSealId, ReplayInput, RuntimeBinding};
        use crate::agent::system_authority::{
            SystemAuthorityCatalogFinalize, SystemAuthorityCatalogRecord,
            SystemAuthorityCatalogRecordId, SystemAuthorityCatalogSibling, SystemAuthorityGenesis,
            SystemAuthorityRotation, SystemAuthorityRotationProof,
        };
        use crate::service::{
            BlobRef, CapabilityId, CredentialId, DeploymentId, NodeId, OperationId, PrincipalId,
            ProducerId, ProgramId,
        };
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
                let genesis = SystemAuthorityGenesis::new(
                    ROOT,
                    1,
                    ROOT_CONFIG,
                    old.clone(),
                    1,
                    Hash([0x75; 32]),
                    Hash([0x76; 32]),
                    8,
                    8,
                    8,
                )
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

            fn catalog_request(
                &self,
                operation_byte: u8,
                mutation_byte: u8,
            ) -> SystemAuthorityCatalogReservationRequest {
                let operation = OperationId([operation_byte; 32]);
                let intent = CatalogMutationIntent::new(
                    self.state.catalog_binding_record().unwrap(),
                    self.state.authority_generation(),
                    self.state.catalog_head(),
                    PrincipalId([0x81; 32]),
                    CredentialId([0x82; 32]),
                    CapabilityId([0x83; 32]),
                    operation,
                    CatalogMutation::new(CatalogMutationKind::UpdateMetadata, vec![mutation_byte])
                        .unwrap(),
                )
                .unwrap();
                let fact = FinalizedCatalogMutationFact::new(
                    intent,
                    self.state.authority_generation(),
                    self.state.catalog_head(),
                    CatalogMutationResult::new(CatalogMutationDisposition::Rejected, Vec::new())
                        .unwrap(),
                    2,
                )
                .unwrap();
                SystemAuthorityCatalogReservationRequest::new(
                    self.old.clone(),
                    fact,
                    SystemAuthorityCatalogProof::vacant(operation, vec![]).unwrap(),
                )
                .unwrap()
            }

            fn certified_catalog_command(
                &self,
                request: &SystemAuthorityCatalogReservationRequest,
            ) -> (
                SystemAuthorityCatalogFinalize,
                SystemAuthorityCatalogRecord,
                AuthorityQuorumCertificate,
            ) {
                let (fact, proof) = request.request.catalog_preimages().unwrap();
                let claim = fact.authority_claim();
                let mut signatures = vec![
                    signed_share(&self.keys[0], &self.old, claim),
                    signed_share(&self.keys[1], &self.old, claim),
                ];
                signatures.sort_by_key(AuthoritySignature::signer);
                let certificate =
                    AuthorityQuorumCertificate::new(&self.old, claim, signatures).unwrap();
                certificate.verify(&self.old, claim).unwrap();
                let receipt = FinalizedCatalogMutationReceipt::new(
                    fact.clone(),
                    certificate.clone(),
                    self.state.catalog_binding_record().unwrap(),
                    &self.old,
                )
                .unwrap();
                let record = SystemAuthorityCatalogRecord::new(
                    receipt.clone(),
                    self.state.catalog_binding_record().unwrap(),
                    &self.old,
                )
                .unwrap();
                let command = SystemAuthorityCatalogFinalize::new(receipt, proof.clone()).unwrap();
                (command, record, certificate)
            }

            fn catalog_successor_view(
                &self,
                command: &SystemAuthorityCatalogFinalize,
            ) -> (ReplayedSystemAuthorityView, SystemAuthorityCatalogNodeId) {
                let transition = self
                    .state
                    .apply_catalog_finalize(self.scope, command)
                    .unwrap();
                let root = transition.history().root();
                let next = transition.into_state();
                assert_eq!(next.journal_binding(), Some(self.scope.binding()));
                assert_eq!(next.rotation_first_sequence(), None);
                (
                    ReplayedSystemAuthorityView::for_test_from_authenticated_replay(
                        self.scope, &next, self.store, HEADS_2, CONTROL_2,
                    )
                    .unwrap(),
                    root,
                )
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
            SystemAuthorityLedgerRouteOwner::open(
                database,
                fixture.route,
                fixture.store,
                fixture.local_node(),
            )
            .unwrap()
            .open_signer(fixture.local_signer())
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

        fn catalog_ordered_entry(command: SystemAuthorityCatalogFinalize) -> OrderedEntry {
            OrderedEntry {
                genesis: GENESIS,
                index: 1,
                parent: None,
                merge_frontier: MergeFrontierId::new([0x91; 32]),
                merge_seal: Some(MergeSealId::new([0x92; 32])),
                input: ReplayInput {
                    runtime: RuntimeBinding {
                        space: SPACE,
                        agent: SYSTEM_AGENT,
                        deployment: DeploymentId([0x93; 32]),
                        program: ProgramId([0x94; 32]),
                        producer: ProducerId([0x95; 32]),
                        package: BlobRef::of_bytes(b"catalog-ledger-test-runtime"),
                        runtime_abi: crate::agent::RUNTIME_ABI_ID,
                        execution_semantics: crate::agent::EXECUTION_SEMANTICS_ID,
                    },
                    operation: ReplayOperation::Management {
                        request: LifecycleRequest::FinalizeCatalog(command),
                    },
                },
            }
        }

        fn catalog_publication_intent_for_test(
            reservation: &ReservationRecord,
            successor: &ReplayedSystemAuthorityView,
            command: SystemAuthorityCatalogFinalize,
            record: &SystemAuthorityCatalogRecord,
            root: SystemAuthorityCatalogNodeId,
        ) -> PublicationIntentRecord {
            let entry = catalog_ordered_entry(command.clone());
            let intent = PublicationIntentRecord {
                version: LEDGER_SCHEMA_VERSION,
                route: reservation.route,
                journal_store: reservation.journal_store,
                predecessor_heads: reservation.predecessor_heads,
                predecessor_control: reservation.control_state,
                predecessor_view: reservation.state_view,
                predecessor_authority_state: reservation.authority_state,
                successor_heads: successor.heads(),
                ordered_entry: entry.id(),
                ordered_entry_payload: entry,
                successor_control: successor.control_state(),
                successor_view: successor.commitment(),
                successor_authority_state: successor.authority_state_commitment(),
                claim: reservation.request.claim().claim_hash(),
                operation: command.operation_commitment(),
                kind: PublicationIntentKind::Catalog {
                    record: record.id(),
                    leaf: record.leaf_id(),
                    root,
                },
                storage_plan: Hash([0x96; 32]),
                facts: Hash([0x97; 32]),
            };
            intent.validate().unwrap();
            intent.validate_for_reservation(reservation).unwrap();
            intent
        }

        #[test]
        fn catalog_claim_round_trips_and_uses_only_the_current_committee_leg() {
            let fixture = Fixture::new();
            let request = fixture.catalog_request(0x84, 0x85);
            let claim = request.claim();
            let (fact, proof) = request.request.catalog_preimages().unwrap();
            assert_eq!(claim.domain(), AuthorityClaimDomain::Catalog);
            assert_eq!(claim.sequence(), 2);
            assert_eq!(fact.authority_claim(), claim);
            assert_eq!(proof.operation_id(), OperationId([0x84; 32]));
            assert_eq!(
                request.request.legs(),
                &[SystemAuthorityCommitteeLeg::Current]
            );
            assert_eq!(
                request
                    .request
                    .committee(SystemAuthorityCommitteeLeg::Current),
                Some(&fixture.old)
            );
            assert!(
                request
                    .request
                    .committee(SystemAuthorityCommitteeLeg::Retiring)
                    .is_none()
            );
            assert_eq!(
                SystemAuthorityLedgerClaim::decode(&request.request.encode()),
                Ok(request.request.clone())
            );
            assert!(request.request.encode().len() <= MAX_SYSTEM_AUTHORITY_LEDGER_CLAIM_BYTES);

            let occupied = SystemAuthorityCatalogProof::occupied(
                OperationId([0x84; 32]),
                SystemAuthorityCatalogRecordId::from_bytes([0x86; 32]),
                vec![],
            )
            .unwrap();
            assert!(matches!(
                SystemAuthorityCatalogReservationRequest::new(
                    fixture.old.clone(),
                    fact.clone(),
                    occupied,
                ),
                Err(SystemAuthorityLedgerWireError::InvalidClaim)
            ));
        }

        #[test]
        fn catalog_reservation_signs_once_and_conflicts_globally_at_the_same_sequence() {
            let fixture = Fixture::new();
            let directory = TempDirectory::new("catalog_reservation");
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let ledger = open_ledger(database.clone(), &fixture);
            let request = fixture.catalog_request(0x87, 0x88);
            let claim = request.claim();
            let outcome = ledger
                .reserve_catalog_or_reconcile(&fixture.view, request)
                .unwrap();
            assert_eq!(
                outcome.disposition(),
                SystemAuthorityReservationDisposition::New
            );
            let reserved = outcome.into_reserved();
            let pending = ledger.recover_pending_claim().unwrap().unwrap();
            assert_eq!(pending.claim(), claim);
            assert_eq!(pending.catalog_request().unwrap().claim(), claim);

            let signer = PledgeCheckingSigner {
                key: fixture.keys[0].clone(),
                calls: Cell::new(0),
                database,
                pledge_key: pledge_storage_key(
                    fixture.route,
                    fixture.local_signer().as_bytes(),
                    claim.sequence(),
                ),
            };
            assert!(
                ledger
                    .sign_reserved_leg(&reserved, SystemAuthorityCommitteeLeg::Current, &signer,)
                    .unwrap()
                    .certificate()
                    .is_none()
            );
            assert_eq!(signer.calls.get(), 1);
            assert!(matches!(
                ledger
                    .sign_reserved_leg(&reserved, SystemAuthorityCommitteeLeg::Retiring, &signer,),
                Err(SystemAuthoritySignError::Ledger(
                    SystemAuthorityLedgerError::WrongCommitteeLeg
                ))
            ));
            let remote = signed_share(&fixture.keys[1], &fixture.old, claim);
            let certificate = ledger
                .record_remote_share(&reserved, SystemAuthorityCommitteeLeg::Current, remote)
                .unwrap()
                .certificate()
                .cloned()
                .unwrap();
            certificate.verify(&fixture.old, claim).unwrap();

            assert!(matches!(
                ledger.reserve_or_reconcile(&fixture.view, fixture.rotation_request()),
                Err(SystemAuthorityLedgerError::DivergentReservation)
            ));
            assert!(ledger.is_fail_stopped().unwrap());
        }

        #[test]
        fn catalog_intent_survives_reopen_and_retires_without_resigning() {
            let fixture = Fixture::new();
            let directory = TempDirectory::new("catalog_intent_recovery");
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let ledger = open_ledger(database.clone(), &fixture);
            let request = fixture.catalog_request(0x89, 0x8a);
            let claim = request.claim();
            let (command, record, expected_certificate) =
                fixture.certified_catalog_command(&request);
            let reserved = ledger
                .reserve_catalog_or_reconcile(&fixture.view, request.clone())
                .unwrap()
                .into_reserved();
            let signer = PledgeCheckingSigner {
                key: fixture.keys[0].clone(),
                calls: Cell::new(0),
                database: database.clone(),
                pledge_key: pledge_storage_key(
                    fixture.route,
                    fixture.local_signer().as_bytes(),
                    claim.sequence(),
                ),
            };
            assert!(
                ledger
                    .sign_reserved_leg(&reserved, SystemAuthorityCommitteeLeg::Current, &signer,)
                    .unwrap()
                    .certificate()
                    .is_none()
            );
            let remote = signed_share(&fixture.keys[1], &fixture.old, claim);
            let frozen = ledger
                .record_remote_share(&reserved, SystemAuthorityCommitteeLeg::Current, remote)
                .unwrap()
                .certificate()
                .cloned()
                .unwrap();
            assert_eq!(frozen, expected_certificate);
            assert_eq!(signer.calls.get(), 1);
            assert_eq!(
                ledger
                    .reserve_catalog_or_reconcile(&fixture.view, request.clone())
                    .unwrap()
                    .disposition(),
                SystemAuthorityReservationDisposition::Exact
            );
            ledger
                .sign_reserved_leg(&reserved, SystemAuthorityCommitteeLeg::Current, &signer)
                .unwrap();
            assert_eq!(
                signer.calls.get(),
                1,
                "exact retry reused the durable share"
            );

            let (successor, root) = fixture.catalog_successor_view(&command);
            let intent = catalog_publication_intent_for_test(
                &reserved.record,
                &successor,
                command,
                &record,
                root,
            );
            assert_eq!(
                PublicationIntentRecord::decode(&intent.encode()).unwrap(),
                intent
            );
            assert!(intent.encode().len() <= MAX_PUBLICATION_INTENT_RECORD_BYTES);
            let mut wrong_record = intent.clone();
            let PublicationIntentKind::Catalog { record, .. } = &mut wrong_record.kind else {
                unreachable!()
            };
            *record = SystemAuthorityCatalogRecordId::from_bytes([0x9a; 32]);
            wrong_record.validate().unwrap();
            assert!(matches!(
                wrong_record.validate_for_reservation(&reserved.record),
                Err(SystemAuthorityLedgerError::CorruptLedger)
            ));

            let transaction = database.begin_write().unwrap();
            transaction
                .open_table(PUBLICATION_INTENT_TABLE)
                .unwrap()
                .insert(
                    route_storage_key(fixture.route).as_slice(),
                    intent.encode().as_slice(),
                )
                .unwrap();
            transaction.commit().unwrap();
            drop(ledger);

            let reopened = open_ledger(database.clone(), &fixture);
            let pending = reopened.recover_pending_claim().unwrap().unwrap();
            assert_eq!(pending.claim(), claim);
            assert!(pending.catalog_request().is_some());
            assert_eq!(pending.expected_successor_heads(), Some(successor.heads()));
            assert_eq!(
                pending.expected_ordered_entry(),
                Some(&intent.ordered_entry_payload)
            );
            assert_eq!(
                reopened
                    .pending_certificate(&pending, SystemAuthorityCommitteeLeg::Current)
                    .unwrap(),
                Some(expected_certificate)
            );
            assert!(matches!(
                reopened.reserve_catalog_or_reconcile(&fixture.view, request),
                Err(SystemAuthorityLedgerError::PublicationRecoveryRequired)
            ));

            let published =
                PublishedSystemAuthorityClaim::for_test_after_exact_cas(pending, claim, &successor)
                    .unwrap();
            reopened.retire_published_claim(published).unwrap();
            assert!(reopened.recover_pending_claim().unwrap().is_none());
            reopened.validate_replayed_view(&successor).unwrap();
            let meta = MetaRecord::decode(
                &read_exact(
                    &database,
                    META_TABLE,
                    route_storage_key(fixture.route).as_slice(),
                )
                .unwrap()
                .unwrap(),
            )
            .unwrap();
            assert_eq!(meta.retired_high_water, claim.sequence());
            assert_eq!(meta.authority_state, successor.authority_state_commitment());
        }

        #[test]
        fn catalog_v6_record_sizes_are_bounded_without_duplicate_receipt() {
            let fixture = Fixture::new();
            let mut keys = Vec::with_capacity(MAX_AUTHORITY_COMMITTEE_MEMBERS);
            let mut members = Vec::with_capacity(MAX_AUTHORITY_COMMITTEE_MEMBERS);
            for index in 0..MAX_AUTHORITY_COMMITTEE_MEMBERS {
                let ordinal = u16::try_from(index + 1).unwrap().to_le_bytes();
                let key_seed = Hash::digest(b"catalog-ledger-max-key", &[&ordinal]).0;
                let key = SigningKey::from_bytes(&key_seed);
                let node = NodeId(Hash::digest(b"catalog-ledger-max-node", &[&ordinal]).0);
                members.push(
                    AuthorityCommitteeMember::new(
                        node,
                        key.verifying_key().to_bytes(),
                        AuthorityMemberRole::Voter,
                    )
                    .unwrap(),
                );
                keys.push(key);
            }
            members.sort_by_key(AuthorityCommitteeMember::signer);
            let committee = AuthorityCommittee::new(SPACE, BINDING, 1, None, members).unwrap();

            let operation = OperationId([0xa4; 32]);
            let mutation = CatalogMutation::new(
                CatalogMutationKind::UpdateMetadata,
                vec![0xa5; MAX_CATALOG_TRANSITION_DATA_BYTES],
            )
            .unwrap();
            let intent = CatalogMutationIntent::new(
                fixture.state.catalog_binding_record().unwrap(),
                fixture.state.authority_generation(),
                fixture.state.catalog_head(),
                PrincipalId([0xa6; 32]),
                CredentialId([0xa7; 32]),
                CapabilityId([0xa8; 32]),
                operation,
                mutation,
            )
            .unwrap();
            let fact = FinalizedCatalogMutationFact::new(
                intent,
                fixture.state.authority_generation(),
                fixture.state.catalog_head(),
                CatalogMutationResult::new(CatalogMutationDisposition::Rejected, Vec::new())
                    .unwrap(),
                2,
            )
            .unwrap();
            let siblings = (0_u16..256)
                .map(|depth| {
                    let depth_bytes = depth.to_le_bytes();
                    let node = SystemAuthorityCatalogNodeId::from_bytes(
                        Hash::digest(
                            b"catalog-ledger-max-proof-node",
                            &[&operation.0, &depth_bytes],
                        )
                        .0,
                    );
                    SystemAuthorityCatalogSibling::new(depth, node).unwrap()
                })
                .collect::<Vec<_>>();
            let proof = SystemAuthorityCatalogProof::vacant(operation, siblings).unwrap();
            let request = SystemAuthorityCatalogReservationRequest::new(
                committee.clone(),
                fact.clone(),
                proof.clone(),
            )
            .unwrap()
            .request;
            let reservation = ReservationRecord {
                route: fixture.route,
                journal_store: fixture.store,
                predecessor_heads: fixture.view.heads(),
                state_view: fixture.view.commitment(),
                authority_state: fixture.view.authority_state_commitment(),
                control_state: fixture.view.control_state(),
                prior_high_water: fixture.view.committee_sequence_high_water(),
                prior_first_sequence: fixture.view.rotation_first_sequence(),
                request,
            };
            reservation.validate().unwrap();

            let mut signatures = keys
                .iter()
                .map(|key| signed_share(key, &committee, fact.authority_claim()))
                .collect::<Vec<_>>();
            signatures.sort_by_key(AuthoritySignature::signer);
            let certificate =
                AuthorityQuorumCertificate::new(&committee, fact.authority_claim(), signatures)
                    .unwrap();
            let receipt = FinalizedCatalogMutationReceipt::new(
                fact,
                certificate,
                fixture.state.catalog_binding_record().unwrap(),
                &committee,
            )
            .unwrap();
            let record = SystemAuthorityCatalogRecord::new(
                receipt.clone(),
                fixture.state.catalog_binding_record().unwrap(),
                &committee,
            )
            .unwrap();
            let command = SystemAuthorityCatalogFinalize::new(receipt, proof.clone()).unwrap();
            let entry = catalog_ordered_entry(command.clone());
            let publication = PublicationIntentRecord {
                version: LEDGER_SCHEMA_VERSION,
                route: fixture.route,
                journal_store: fixture.store,
                predecessor_heads: fixture.view.heads(),
                predecessor_control: fixture.view.control_state(),
                predecessor_view: fixture.view.commitment(),
                predecessor_authority_state: fixture.view.authority_state_commitment(),
                successor_heads: HEADS_2,
                ordered_entry: entry.id(),
                ordered_entry_payload: entry,
                successor_control: CONTROL_2,
                successor_view: Hash([0xa9; 32]),
                successor_authority_state: Hash([0xaa; 32]),
                claim: reservation.request.claim().claim_hash(),
                operation: command.operation_commitment(),
                kind: PublicationIntentKind::Catalog {
                    record: record.id(),
                    leaf: record.leaf_id(),
                    root: proof.root().unwrap(),
                },
                storage_plan: Hash([0xab; 32]),
                facts: Hash([0xac; 32]),
            };
            publication.validate().unwrap();
            publication.validate_for_reservation(&reservation).unwrap();

            let reservation_bytes = reservation.encode().len();
            let publication_bytes = publication.encode().len();
            assert!(reservation_bytes <= MAX_CATALOG_RESERVATION_RECORD_BYTES);
            assert!(publication_bytes <= MAX_PUBLICATION_INTENT_RECORD_BYTES);
            assert!(publication.ordered_entry_payload.encode().len() <= MAX_JOURNAL_RECORD_BYTES);
            assert_eq!(
                ReservationRecord::decode(&reservation.encode()).unwrap(),
                reservation
            );
            assert_eq!(
                PublicationIntentRecord::decode(&publication.encode()).unwrap(),
                publication
            );
            eprintln!(
                "catalog v6 sizes: reservation={reservation_bytes}/{MAX_CATALOG_RESERVATION_RECORD_BYTES}, publication={publication_bytes}/{MAX_PUBLICATION_INTENT_RECORD_BYTES}, ordered_entry={}/{}",
                publication.ordered_entry_payload.encode().len(),
                MAX_PUBLICATION_ORDERED_ENTRY_BYTES,
            );
        }

        #[test]
        fn route_owner_opens_and_gates_without_any_signer() {
            let fixture = Fixture::new();
            let directory = TempDirectory::new("route_owner_no_signer");
            let database = Arc::new(Database::create(directory.database()).unwrap());

            let owner = SystemAuthorityLedgerRouteOwner::open(
                database.clone(),
                fixture.route,
                fixture.store,
                fixture.local_node(),
            )
            .unwrap();
            assert_eq!(owner.route(), fixture.route);
            assert_eq!(owner.journal_store(), fixture.store);
            assert_eq!(owner.local_node(), fixture.local_node());
            assert!(!owner.is_fail_stopped().unwrap());
            assert!(owner.recover_pending_claim().unwrap().is_none());
            assert_eq!(owner.with_no_pending_root_mutation(|| 7_u8).unwrap(), 7);

            let route_key = route_storage_key(fixture.route);
            let sentinel_key = route_owner_sentinel_key(fixture.route);
            let route_bytes = read_exact(&database, ROUTE_CONFIG_TABLE, route_key.as_slice())
                .unwrap()
                .unwrap();
            let sentinel_bytes = read_exact(&database, CONFIG_TABLE, sentinel_key.as_slice())
                .unwrap()
                .unwrap();
            assert_eq!(route_bytes, sentinel_bytes);
            assert_eq!(
                RouteConfigRecord::decode(&route_bytes).unwrap(),
                RouteConfigRecord {
                    version: LEDGER_SCHEMA_VERSION,
                    route: fixture.route,
                    journal_store: fixture.store,
                    local_node: fixture.local_node(),
                }
            );
            assert!(
                ConfigRecord::decode(&sentinel_bytes).is_err(),
                "a legacy writer must reject the permanent v5 owner sentinel"
            );

            // Exact owner reopen audits the already-pinned route without
            // installing a signer or changing either permanent row.
            let reopened = SystemAuthorityLedgerRouteOwner::open(
                database.clone(),
                fixture.route,
                fixture.store,
                fixture.local_node(),
            )
            .unwrap();
            assert!(reopened.recover_pending_claim().unwrap().is_none());
            assert_eq!(
                read_exact(&database, ROUTE_CONFIG_TABLE, route_key.as_slice())
                    .unwrap()
                    .unwrap(),
                route_bytes
            );
            assert_eq!(
                read_exact(&database, CONFIG_TABLE, sentinel_key.as_slice())
                    .unwrap()
                    .unwrap(),
                sentinel_bytes
            );
        }

        #[test]
        fn journal_exposure_marker_is_permanent_error_sensitive_and_gates_mutation() {
            let fixture = Fixture::new();
            let directory = TempDirectory::new("journal_exposure_lifecycle");
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let owner = SystemAuthorityLedgerRouteOwner::open_staged(
                database.clone(),
                fixture.route,
                fixture.store,
                fixture.local_node(),
            )
            .unwrap();

            assert!(!owner.journal_exposure_is_committed().unwrap());
            assert!(owner.recover_pending_claim().unwrap().is_none());
            let entered = Cell::new(false);
            assert!(matches!(
                owner.with_no_pending_root_mutation(|| entered.set(true)),
                Err(SystemAuthorityLedgerError::JournalExposureRequired)
            ));
            assert!(!entered.get());
            assert!(matches!(
                owner.open_signer(fixture.local_signer()),
                Err(SystemAuthorityLedgerError::JournalExposureRequired)
            ));

            let wrong_genesis_entered = Cell::new(false);
            assert!(matches!(
                owner.with_unexposed_journal_initialization(FOREIGN_GENESIS, || {
                    wrong_genesis_entered.set(true);
                    Ok::<_, u8>(())
                }),
                Err(SystemAuthorityLedgerError::ConfigurationMismatch)
            ));
            assert!(!wrong_genesis_entered.get());
            assert!(!owner.journal_exposure_is_committed().unwrap());

            assert_eq!(
                owner
                    .with_unexposed_journal_initialization(GENESIS, || Err::<(), _>(7_u8))
                    .unwrap(),
                Err(7)
            );
            assert!(!owner.journal_exposure_is_committed().unwrap());
            assert_eq!(
                owner
                    .with_unexposed_journal_initialization(GENESIS, || Ok::<_, u8>(11_u8))
                    .unwrap(),
                Ok(11)
            );
            assert!(owner.journal_exposure_is_committed().unwrap());

            let marker = read_exact(
                &database,
                JOURNAL_EXPOSURE_TABLE,
                route_storage_key(fixture.route).as_slice(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                JournalExposureRecord::decode(&marker).unwrap(),
                JournalExposureRecord::for_owner(&owner)
            );
            assert!(matches!(
                owner.with_unexposed_journal_initialization(GENESIS, || Ok::<_, u8>(())),
                Err(SystemAuthorityLedgerError::JournalExposureAlreadyCommitted)
            ));

            let reopened = SystemAuthorityLedgerRouteOwner::open_existing(
                database,
                fixture.route,
                fixture.store,
                fixture.local_node(),
            )
            .unwrap();
            assert!(reopened.journal_exposure_is_committed().unwrap());
            assert_eq!(
                reopened.with_no_pending_root_mutation(|| 13_u8).unwrap(),
                13
            );
        }

        #[test]
        fn unexposed_evidence_residue_rejects_preopen_and_startup_without_running_operations() {
            let fixture = Fixture::new();
            let directory = TempDirectory::new("unexposed_evidence_preopen");
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let owner = SystemAuthorityLedgerRouteOwner::open_staged(
                database.clone(),
                fixture.route,
                fixture.store,
                fixture.local_node(),
            )
            .unwrap();
            let route_key = route_storage_key(fixture.route);
            let meta = MetaRecord {
                route: fixture.route,
                journal_store: fixture.store,
                retired_high_water: fixture.view.committee_sequence_high_water(),
                authority_state: fixture.view.authority_state_commitment(),
                last_claim: None,
                last_publication: None,
            };
            meta.validate().unwrap();
            let meta_bytes = meta.encode();
            let transaction = database.begin_write().unwrap();
            transaction
                .open_table(META_TABLE)
                .unwrap()
                .insert(route_key.as_slice(), meta_bytes.as_slice())
                .unwrap();
            transaction.commit().unwrap();

            assert!(matches!(
                owner.journal_exposure_is_committed(),
                Err(SystemAuthorityLedgerError::CorruptLedger)
            ));

            let startup_entered = Cell::new(false);
            assert!(matches!(
                owner.with_startup_root_recovery(|_| startup_entered.set(true)),
                Err(SystemAuthorityLedgerError::CorruptLedger)
            ));
            assert!(!startup_entered.get());

            let initialization_entered = Cell::new(false);
            assert!(matches!(
                owner.with_unexposed_journal_initialization(GENESIS, || {
                    initialization_entered.set(true);
                    Ok::<_, u8>(())
                }),
                Err(SystemAuthorityLedgerError::CorruptLedger)
            ));
            assert!(!initialization_entered.get());
            assert_eq!(
                read_exact(&database, META_TABLE, route_key.as_slice())
                    .unwrap()
                    .unwrap(),
                meta_bytes
            );
            assert!(
                read_exact(&database, JOURNAL_EXPOSURE_TABLE, route_key.as_slice())
                    .unwrap()
                    .is_none()
            );
        }

        #[test]
        fn malformed_or_mismatched_journal_exposure_residue_rejects_without_writes() {
            let fixture = Fixture::new();
            let foreign_store = JournalStoreInstanceId::from_bytes([0xa2; 32]).unwrap();
            let foreign_node = NodeId([0xa3; 32]);
            let foreign_route = SystemAuthorityLedgerRoute::new(
                ROOT,
                1,
                ROOT_CONFIG,
                SPACE,
                SYSTEM_AGENT,
                BINDING,
                FOREIGN_GENESIS,
                ADMISSION,
            )
            .unwrap();

            let expected = JournalExposureRecord {
                version: JOURNAL_EXPOSURE_RECORD_VERSION,
                route: fixture.route,
                journal_store: fixture.store,
                local_node: fixture.local_node(),
                system_genesis: GENESIS,
            };
            let mut foreign_route_record = expected.clone();
            foreign_route_record.route = foreign_route;
            foreign_route_record.system_genesis = FOREIGN_GENESIS;
            let mut foreign_store_record = expected.clone();
            foreign_store_record.journal_store = foreign_store;
            let mut foreign_node_record = expected.clone();
            foreign_node_record.local_node = foreign_node;
            let mut mismatched_genesis_record = expected.clone();
            mismatched_genesis_record.system_genesis = FOREIGN_GENESIS;

            for (label, key, bytes, configuration_mismatch) in [
                (
                    "marker_foreign_route",
                    route_storage_key(fixture.route).to_vec(),
                    foreign_route_record.encode(),
                    true,
                ),
                (
                    "marker_foreign_store",
                    route_storage_key(fixture.route).to_vec(),
                    foreign_store_record.encode(),
                    true,
                ),
                (
                    "marker_foreign_node",
                    route_storage_key(fixture.route).to_vec(),
                    foreign_node_record.encode(),
                    true,
                ),
                (
                    "marker_mismatched_genesis",
                    route_storage_key(fixture.route).to_vec(),
                    mismatched_genesis_record.encode(),
                    false,
                ),
                (
                    "marker_malformed",
                    route_storage_key(fixture.route).to_vec(),
                    b"not-a-journal-exposure-record".to_vec(),
                    false,
                ),
                (
                    "marker_unknown_key",
                    {
                        let mut key = route_storage_key(fixture.route).to_vec();
                        key.push(0xff);
                        key
                    },
                    expected.encode(),
                    false,
                ),
            ] {
                let directory = TempDirectory::new(label);
                let database = Arc::new(Database::create(directory.database()).unwrap());
                let owner = SystemAuthorityLedgerRouteOwner::open_staged(
                    database.clone(),
                    fixture.route,
                    fixture.store,
                    fixture.local_node(),
                )
                .unwrap();
                let transaction = database.begin_write().unwrap();
                transaction
                    .open_table(JOURNAL_EXPOSURE_TABLE)
                    .unwrap()
                    .insert(key.as_slice(), bytes.as_slice())
                    .unwrap();
                transaction.commit().unwrap();

                let before = read_exact(&database, JOURNAL_EXPOSURE_TABLE, key.as_slice())
                    .unwrap()
                    .unwrap();
                let result = owner.journal_exposure_is_committed();
                if configuration_mismatch {
                    assert!(matches!(
                        result,
                        Err(SystemAuthorityLedgerError::ConfigurationMismatch)
                    ));
                } else {
                    assert!(matches!(
                        result,
                        Err(SystemAuthorityLedgerError::CorruptLedger)
                    ));
                }
                assert_eq!(
                    read_exact(&database, JOURNAL_EXPOSURE_TABLE, key.as_slice())
                        .unwrap()
                        .unwrap(),
                    before
                );
                assert!(
                    SystemAuthorityLedgerRouteOwner::open_existing(
                        database.clone(),
                        fixture.route,
                        fixture.store,
                        fixture.local_node(),
                    )
                    .is_err()
                );
                assert_eq!(
                    read_exact(&database, JOURNAL_EXPOSURE_TABLE, key.as_slice())
                        .unwrap()
                        .unwrap(),
                    before
                );
            }
        }

        #[test]
        fn signer_children_share_one_owner_lock_and_route_state() {
            let fixture = Fixture::new();
            let directory = TempDirectory::new("shared_owner");
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let owner = SystemAuthorityLedgerRouteOwner::open(
                database,
                fixture.route,
                fixture.store,
                fixture.local_node(),
            )
            .unwrap();
            let first = owner.open_signer(fixture.local_signer()).unwrap();
            let second_signer =
                AuthoritySignerId::of_raw_ed25519(&fixture.keys[1].verifying_key().to_bytes());
            let second = owner.open_signer(second_signer).unwrap();
            assert!(Arc::ptr_eq(first.owner(), second.owner()));
            assert!(Arc::ptr_eq(first.owner(), &owner));

            first
                .reserve_or_reconcile(&fixture.view, fixture.rotation_request())
                .unwrap();
            let pending = second.recover_pending_claim().unwrap().unwrap();
            assert_eq!(pending.claim(), fixture.request.claim());
            assert!(matches!(
                owner.with_no_pending_root_mutation(|| ()),
                Err(SystemAuthorityLedgerError::GcBlockedByPendingReservation)
            ));
        }

        #[test]
        fn owner_mismatch_and_legacy_residue_fail_without_writes() {
            let fixture = Fixture::new();
            let directory = TempDirectory::new("owner_mismatch");
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let owner = SystemAuthorityLedgerRouteOwner::open(
                database.clone(),
                fixture.route,
                fixture.store,
                fixture.local_node(),
            )
            .unwrap();
            drop(owner);
            let route_key = route_storage_key(fixture.route);
            let sentinel_key = route_owner_sentinel_key(fixture.route);
            let route_before = read_exact(&database, ROUTE_CONFIG_TABLE, route_key.as_slice())
                .unwrap()
                .unwrap();
            let sentinel_before = read_exact(&database, CONFIG_TABLE, sentinel_key.as_slice())
                .unwrap()
                .unwrap();

            let foreign_store = JournalStoreInstanceId::from_bytes([0xa2; 32]).unwrap();
            assert!(matches!(
                SystemAuthorityLedgerRouteOwner::open(
                    database.clone(),
                    fixture.route,
                    foreign_store,
                    fixture.local_node(),
                ),
                Err(SystemAuthorityLedgerError::ConfigurationMismatch)
            ));
            assert!(matches!(
                SystemAuthorityLedgerRouteOwner::open(
                    database.clone(),
                    fixture.route,
                    fixture.store,
                    NodeId([0xa3; 32]),
                ),
                Err(SystemAuthorityLedgerError::ConfigurationMismatch)
            ));
            assert_eq!(
                read_exact(&database, ROUTE_CONFIG_TABLE, route_key.as_slice())
                    .unwrap()
                    .unwrap(),
                route_before
            );
            assert_eq!(
                read_exact(&database, CONFIG_TABLE, sentinel_key.as_slice())
                    .unwrap()
                    .unwrap(),
                sentinel_before
            );

            // A route containing a v2 signer Config cannot be upgraded in
            // place. Failed v5 open neither installs RouteConfig nor replaces
            // the pre-existing signer row with the owner sentinel.
            let legacy_directory = TempDirectory::new("legacy_residue");
            let legacy_database = Arc::new(Database::create(legacy_directory.database()).unwrap());
            let signer_key = config_storage_key(fixture.route, fixture.local_signer().as_bytes());
            let legacy = ConfigRecord {
                version: 2,
                route: fixture.route,
                journal_store: fixture.store,
                local_node: fixture.local_node(),
                local_signer: *fixture.local_signer().as_bytes(),
            }
            .encode();
            let transaction = legacy_database.begin_write().unwrap();
            transaction
                .open_table(CONFIG_TABLE)
                .unwrap()
                .insert(signer_key.as_slice(), legacy.as_slice())
                .unwrap();
            transaction.commit().unwrap();
            assert!(matches!(
                SystemAuthorityLedgerRouteOwner::open(
                    legacy_database.clone(),
                    fixture.route,
                    fixture.store,
                    fixture.local_node(),
                ),
                Err(SystemAuthorityLedgerError::ConfigurationMismatch)
            ));
            assert_eq!(
                read_exact(&legacy_database, CONFIG_TABLE, signer_key.as_slice())
                    .unwrap()
                    .unwrap(),
                legacy
            );
            assert!(
                read_exact_maybe_missing(
                    &legacy_database,
                    ROUTE_CONFIG_TABLE,
                    route_key.as_slice(),
                    true,
                )
                .unwrap()
                .is_none()
            );
            assert!(
                read_exact(&legacy_database, CONFIG_TABLE, sentinel_key.as_slice())
                    .unwrap()
                    .is_none()
            );

            // The immediately preceding v4 route owner is retained as an
            // expected-empty rollback fence. Its exact bytes survive a failed
            // v5 open, while neither the v5 route row nor Config sentinel is
            // installed.
            let v4_directory = TempDirectory::new("v4_route_residue");
            let v4_database = Arc::new(Database::create(v4_directory.database()).unwrap());
            let v4 = RouteConfigRecord {
                version: 4,
                route: fixture.route,
                journal_store: fixture.store,
                local_node: fixture.local_node(),
            }
            .encode();
            let transaction = v4_database.begin_write().unwrap();
            transaction
                .open_table(LEGACY_ROUTE_CONFIG_TABLE_V4)
                .unwrap()
                .insert(route_key.as_slice(), v4.as_slice())
                .unwrap();
            transaction.commit().unwrap();
            assert!(matches!(
                SystemAuthorityLedgerRouteOwner::open(
                    v4_database.clone(),
                    fixture.route,
                    fixture.store,
                    fixture.local_node(),
                ),
                Err(SystemAuthorityLedgerError::ConfigurationMismatch)
            ));
            assert_eq!(
                read_exact(
                    &v4_database,
                    LEGACY_ROUTE_CONFIG_TABLE_V4,
                    route_key.as_slice(),
                )
                .unwrap()
                .unwrap(),
                v4
            );
            assert!(
                read_exact_maybe_missing(
                    &v4_database,
                    ROUTE_CONFIG_TABLE,
                    route_key.as_slice(),
                    true,
                )
                .unwrap()
                .is_none()
            );
            assert!(
                read_exact_maybe_missing(
                    &v4_database,
                    CONFIG_TABLE,
                    sentinel_key.as_slice(),
                    true,
                )
                .unwrap()
                .is_none()
            );

            // A v3 route-owner marker remains an equally permanent rollback
            // fence. Its exact bytes survive a failed v5 open as well.
            let v3_directory = TempDirectory::new("v3_route_residue");
            let v3_database = Arc::new(Database::create(v3_directory.database()).unwrap());
            let v3 = RouteConfigRecord {
                version: 3,
                route: fixture.route,
                journal_store: fixture.store,
                local_node: fixture.local_node(),
            }
            .encode();
            let transaction = v3_database.begin_write().unwrap();
            transaction
                .open_table(LEGACY_ROUTE_CONFIG_TABLE_V3)
                .unwrap()
                .insert(route_key.as_slice(), v3.as_slice())
                .unwrap();
            transaction.commit().unwrap();
            assert!(matches!(
                SystemAuthorityLedgerRouteOwner::open(
                    v3_database.clone(),
                    fixture.route,
                    fixture.store,
                    fixture.local_node(),
                ),
                Err(SystemAuthorityLedgerError::ConfigurationMismatch)
            ));
            assert_eq!(
                read_exact(
                    &v3_database,
                    LEGACY_ROUTE_CONFIG_TABLE_V3,
                    route_key.as_slice(),
                )
                .unwrap()
                .unwrap(),
                v3
            );
            assert!(
                read_exact_maybe_missing(
                    &v3_database,
                    ROUTE_CONFIG_TABLE,
                    route_key.as_slice(),
                    true,
                )
                .unwrap()
                .is_none()
            );
            assert!(
                read_exact_maybe_missing(
                    &v3_database,
                    CONFIG_TABLE,
                    sentinel_key.as_slice(),
                    true,
                )
                .unwrap()
                .is_none()
            );
        }

        #[test]
        fn incomplete_owner_rows_and_missing_pinned_table_fail_closed() {
            let fixture = Fixture::new();
            let route_key = route_storage_key(fixture.route);
            let sentinel_key = route_owner_sentinel_key(fixture.route);
            let expected = RouteConfigRecord {
                version: LEDGER_SCHEMA_VERSION,
                route: fixture.route,
                journal_store: fixture.store,
                local_node: fixture.local_node(),
            };

            let partial_directory = TempDirectory::new("partial_owner");
            let partial = Arc::new(Database::create(partial_directory.database()).unwrap());
            let transaction = partial.begin_write().unwrap();
            transaction
                .open_table(ROUTE_CONFIG_TABLE)
                .unwrap()
                .insert(route_key.as_slice(), expected.encode().as_slice())
                .unwrap();
            transaction.commit().unwrap();
            assert!(matches!(
                SystemAuthorityLedgerRouteOwner::open(
                    partial.clone(),
                    fixture.route,
                    fixture.store,
                    fixture.local_node(),
                ),
                Err(SystemAuthorityLedgerError::ConfigurationMismatch)
            ));
            assert!(
                read_exact_maybe_missing(&partial, CONFIG_TABLE, sentinel_key.as_slice(), true)
                    .unwrap()
                    .is_none(),
                "failed open must not complete a partial owner installation"
            );

            let missing_directory = TempDirectory::new("missing_pinned_table");
            let missing = Arc::new(Database::create(missing_directory.database()).unwrap());
            let owner = SystemAuthorityLedgerRouteOwner::open(
                missing.clone(),
                fixture.route,
                fixture.store,
                fixture.local_node(),
            )
            .unwrap();
            drop(owner);
            let transaction = missing.begin_write().unwrap();
            assert!(transaction.delete_table(PLEDGE_TABLE).unwrap());
            transaction.commit().unwrap();
            assert!(
                SystemAuthorityLedgerRouteOwner::open(
                    missing.clone(),
                    fixture.route,
                    fixture.store,
                    fixture.local_node(),
                )
                .is_err()
            );
            let read = missing.begin_read().unwrap();
            assert!(read.open_table(PLEDGE_TABLE).is_err());
        }

        #[test]
        fn owner_row_tamper_blocks_child_reads_and_writes_without_state_change() {
            let fixture = Fixture::new();
            let directory = TempDirectory::new("owner_row_tamper");
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let owner = SystemAuthorityLedgerRouteOwner::open(
                database.clone(),
                fixture.route,
                fixture.store,
                fixture.local_node(),
            )
            .unwrap();
            let child = owner.open_signer(fixture.local_signer()).unwrap();
            let route_key = route_storage_key(fixture.route);
            let transaction = database.begin_write().unwrap();
            transaction
                .open_table(CONFIG_TABLE)
                .unwrap()
                .remove(route_owner_sentinel_key(fixture.route).as_slice())
                .unwrap();
            transaction.commit().unwrap();

            assert!(matches!(
                child.reserve_or_reconcile(&fixture.view, fixture.rotation_request()),
                Err(SystemAuthorityLedgerError::ConfigurationMismatch)
            ));
            assert!(matches!(
                owner.recover_pending_claim(),
                Err(SystemAuthorityLedgerError::ConfigurationMismatch)
            ));
            assert!(
                read_exact(&database, RESERVATION_TABLE, route_key.as_slice())
                    .unwrap()
                    .is_none(),
                "failed child mutation must not create a reservation"
            );
            assert!(
                read_exact(&database, META_TABLE, route_key.as_slice())
                    .unwrap()
                    .is_none(),
                "failed child mutation must not initialize Meta"
            );
        }

        #[test]
        fn owner_recovers_and_retires_after_signer_child_is_dropped() {
            let fixture = Fixture::new();
            let directory = TempDirectory::new("owner_retirement");
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let owner = SystemAuthorityLedgerRouteOwner::open(
                database.clone(),
                fixture.route,
                fixture.store,
                fixture.local_node(),
            )
            .unwrap();
            let ledger = owner.open_signer(fixture.local_signer()).unwrap();
            let reserved = ledger
                .reserve_or_reconcile(&fixture.view, fixture.rotation_request())
                .unwrap()
                .into_reserved();
            let (signer, joint) = certify_both_legs(&ledger, database, &fixture, &reserved);
            let pending = owner.recover_pending_claim().unwrap().unwrap();
            let successor = fixture.successor_view(joint);
            drop(signer);
            drop(ledger);

            assert!(
                owner
                    .pending_joint_rotation_certificate(&pending)
                    .unwrap()
                    .is_some()
            );
            let receipt = PublishedSystemAuthorityClaim::for_test_after_exact_cas(
                pending,
                fixture.request.claim(),
                &successor,
            )
            .unwrap();
            owner.retire_published_claim(receipt).unwrap();
            assert!(owner.recover_pending_claim().unwrap().is_none());
            assert_eq!(owner.with_no_pending_root_mutation(|| 9_u8).unwrap(), 9);
        }

        #[test]
        fn replayed_view_must_match_surviving_retired_high_water_before_exposure() {
            let fixture = Fixture::new();
            let directory = TempDirectory::new("replayed_view_retired_fence");
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let owner = SystemAuthorityLedgerRouteOwner::open(
                database.clone(),
                fixture.route,
                fixture.store,
                fixture.local_node(),
            )
            .unwrap();
            assert!(owner.validate_replayed_view(&fixture.view).is_ok());

            let ledger = owner.open_signer(fixture.local_signer()).unwrap();
            let reserved = ledger
                .reserve_or_reconcile(&fixture.view, fixture.rotation_request())
                .unwrap()
                .into_reserved();
            assert!(matches!(
                owner.validate_replayed_view(&fixture.view),
                Err(SystemAuthorityLedgerError::PublicationRecoveryRequired)
            ));
            let (signer, joint) = certify_both_legs(&ledger, database.clone(), &fixture, &reserved);
            let pending = owner.recover_pending_claim().unwrap().unwrap();
            let successor = fixture.successor_view(joint);
            drop(signer);
            drop(ledger);
            let receipt = PublishedSystemAuthorityClaim::for_test_after_exact_cas(
                pending,
                fixture.request.claim(),
                &successor,
            )
            .unwrap();
            owner.retire_published_claim(receipt).unwrap();
            assert!(owner.validate_replayed_view(&successor).is_ok());

            let route_key = route_storage_key(fixture.route);
            let meta_before = read_exact(&database, META_TABLE, route_key.as_slice())
                .unwrap()
                .unwrap();
            assert!(matches!(
                owner.validate_replayed_view(&fixture.view),
                Err(SystemAuthorityLedgerError::StaleStateView)
            ));
            assert_eq!(
                read_exact(&database, META_TABLE, route_key.as_slice())
                    .unwrap()
                    .unwrap(),
                meta_before,
                "a stale replay rejection must not rewrite the surviving high-water",
            );
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
    PendingSystemAuthorityRecovery, ReservedSystemAuthorityClaim, RetiredSystemAuthorityCatalog,
    RetiredSystemAuthorityRotation, SystemAuthorityCatalogReservationRequest,
    SystemAuthorityEvidenceLedger, SystemAuthorityLedgerError, SystemAuthorityLedgerRouteOwner,
    SystemAuthorityReservationDisposition, SystemAuthorityReservationOutcome,
    SystemAuthorityRotationReservationRequest, SystemAuthorityShareOutcome,
    SystemAuthoritySignError, SystemAuthoritySigner,
};
