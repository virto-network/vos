//! Bounded, public recovery custody for a fixed three-voter Shared generation.
//!
//! Registration is not invocation authorization. It records which physical
//! owner must retain an exact read, including its original clock and artifacts.
//! Only validated physical replay may attach a result or positive ACK. A slot
//! survives ACK until its owner signs the next exact sequence after durably
//! clearing its local pending record. No timeout or remote owner can release it.
//! Decoding a manifest establishes shape, not checkpoint or execution authority.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use super::genesis::{
    AgentReplicaCommittee, AgentReplicaCommitteeId, MAX_AGENT_REPLICA_COMMITTEE_BYTES,
};
use super::journal::{
    CanonicalJournalRecord, OrderedEntry, ReplayInput, ReplayInputId, ReplayOperation,
};
use super::shared_commit::{OrderedCommitClaim, ReplicaCommitSignature};
use super::shared_raft::AgentGenerationRouteKey;
use super::{AgentProfile, ReplicaRole};
use crate::agent_sdk as sdk;
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{Hash, NodeId};
use sdk::authority::{AuthorityProjectionQuery, AuthorityProjectionSelector};
use sdk::wire::CanonicalWire;
use sdk::{
    InvocationAuthorization, InvocationWork, RuntimeExecutionContext, RuntimeOutcome, RuntimeState,
    RuntimeTransition, RuntimeWork,
};

pub const MAX_SHARED_RECOVERY_SLOTS: usize = 3;
pub const MAX_SHARED_RECOVERY_REQUEST_BYTES: usize =
    sdk::MAX_RUNTIME_AVAILABILITY_BYTES + 2 * sdk::MAX_INVOCATION_MESSAGE_BYTES + 16 * 1024;
pub const MAX_SHARED_RECOVERY_REGISTRATION_BYTES: usize = MAX_SHARED_RECOVERY_REQUEST_BYTES + 256;
pub const MAX_SHARED_RECOVERY_OUTCOME_BYTES: usize = sdk::MAX_INVOCATION_REPLY_BYTES + 2048;
pub const MAX_SHARED_RECOVERY_OBSERVATION_BYTES: usize = sdk::MAX_RUNTIME_AVAILABILITY_BYTES
    + sdk::MAX_INVOCATION_MESSAGE_BYTES
    + MAX_SHARED_RECOVERY_OUTCOME_BYTES
    + super::shared_commit::MAX_ORDERED_COMMIT_CLAIM_BYTES
    + 32 * 1024;
pub const MAX_SHARED_RECOVERY_SLOT_BYTES: usize =
    MAX_SHARED_RECOVERY_REGISTRATION_BYTES + 2 * MAX_SHARED_RECOVERY_OBSERVATION_BYTES + 256;
pub const MAX_SHARED_RECOVERY_MANIFEST_BYTES: usize = MAX_SHARED_RECOVERY_SLOTS
    * MAX_SHARED_RECOVERY_SLOT_BYTES
    + MAX_AGENT_REPLICA_COMMITTEE_BYTES
    + 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SharedRecoveryError {
    InvalidEnvelope,
    ScopeMismatch,
    InvalidSignature,
    Conflict,
    Sequence,
    NotAcknowledged,
    InvalidObservation,
    LimitExceeded,
}

impl fmt::Display for SharedRecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Shared recovery evidence: {self:?}")
    }
}
impl core::error::Error for SharedRecoveryError {}

/// Unsigned custody message. A signer must additionally prove its own durable
/// pending-record clear before signing a replacement; this type cannot do so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedRecoveryRegistrationRequest {
    generation: AgentGenerationRouteKey,
    committee: AgentReplicaCommitteeId,
    owner: NodeId,
    sequence: u64,
    previous: Option<Hash>,
    query: AuthorityProjectionQuery,
    envelope: RuntimeWork,
}

impl SharedRecoveryRegistrationRequest {
    pub fn new(
        generation: AgentGenerationRouteKey,
        committee: AgentReplicaCommitteeId,
        owner: NodeId,
        sequence: u64,
        previous: Option<Hash>,
        query: AuthorityProjectionQuery,
        work: InvocationWork,
        authorization: InvocationAuthorization,
    ) -> Result<Self, SharedRecoveryError> {
        let InvocationAuthorization::PublicPreflight(preflight) = &authorization else {
            return Err(SharedRecoveryError::InvalidEnvelope);
        };
        let envelope = RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: RuntimeState::default(),
            observed_slot: preflight.observed_slot,
            invocation: Box::new(work),
            authorization: Box::new(authorization),
        };
        let value = Self {
            generation,
            committee,
            owner,
            sequence,
            previous,
            query,
            envelope,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn generation(&self) -> AgentGenerationRouteKey {
        self.generation
    }
    pub const fn committee(&self) -> AgentReplicaCommitteeId {
        self.committee
    }
    pub const fn owner(&self) -> NodeId {
        self.owner
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn previous(&self) -> Option<Hash> {
        self.previous
    }
    pub const fn query(&self) -> &AuthorityProjectionQuery {
        &self.query
    }
    pub const fn envelope(&self) -> &RuntimeWork {
        &self.envelope
    }
    pub fn work(&self) -> &InvocationWork {
        match &self.envelope {
            RuntimeWork::Invoke { invocation, .. } => invocation,
            _ => unreachable!("private validated envelope"),
        }
    }
    pub fn authorization(&self) -> &InvocationAuthorization {
        match &self.envelope {
            RuntimeWork::Invoke { authorization, .. } => authorization,
            _ => unreachable!("private validated envelope"),
        }
    }
    pub fn signing_message(&self) -> Hash {
        Hash::digest(
            b"vos/agent/shared/recovery-registration-signature/v1",
            &[&self.encode()],
        )
    }
    pub fn validate(&self) -> Result<(), SharedRecoveryError> {
        let RuntimeWork::Invoke {
            context,
            state,
            invocation,
            authorization,
            observed_slot,
        } = &self.envelope
        else {
            return Err(SharedRecoveryError::InvalidEnvelope);
        };
        let InvocationAuthorization::PublicPreflight(preflight) = authorization.as_ref() else {
            return Err(SharedRecoveryError::InvalidEnvelope);
        };
        if self.generation.validate().is_err()
            || self.committee.as_bytes() == &[0; 32]
            || self.owner == NodeId::ZERO
            || self.sequence == 0
            || (self.sequence == 1) != self.previous.is_none()
            || self.previous == Some(Hash::ZERO)
            || *context != RuntimeExecutionContext::Direct
            || !state.is_empty()
            || *observed_slot != preflight.observed_slot
            || invocation.space.0 != self.generation.space().0
            || invocation.agent.0 != self.generation.agent().0
            || self.query.recovery.is_none()
            || !projection_query_matches_work(&self.query, invocation, authorization)
            || self.query.recovery.is_some_and(|scope| {
                scope.generation.0 != self.generation.replication_id()
                    || scope.committee.0 != *self.committee.as_bytes()
            })
        {
            return Err(SharedRecoveryError::InvalidEnvelope);
        }
        self.envelope
            .encode()
            .map_err(|_| SharedRecoveryError::InvalidEnvelope)?;
        bound(self, MAX_SHARED_RECOVERY_REQUEST_BYTES)
    }
}

impl ServiceWire for SharedRecoveryRegistrationRequest {
    const MAGIC: [u8; 4] = *b"RRG1";
    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut e = Encoder(output);
        e.bytes(&self.generation.encode());
        e.fixed(self.committee.as_bytes());
        e.fixed(&self.owner.0);
        e.u64(self.sequence);
        e.option(&self.previous, |e, value| e.fixed(&value.0));
        e.bytes(&self.query.encode().expect("private canonical query"));
        e.bytes(&self.envelope.encode().expect("private canonical envelope"));
    }
    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_bound(d, MAX_SHARED_RECOVERY_REQUEST_BYTES)?;
        let value = Self {
            generation: nested(d, super::shared_raft::MAX_AGENT_GENERATION_ROUTE_KEY_BYTES)?,
            committee: AgentReplicaCommitteeId::from_bytes(d.fixed()?),
            owner: NodeId(d.fixed()?),
            sequence: d.u64()?,
            previous: d.option(|d| d.fixed().map(Hash))?,
            query: sdk_nested(d, sdk::wire::MAX_AUTHORITY_PROJECTION_QUERY_WIRE_BYTES)?,
            envelope: sdk_nested(d, MAX_SHARED_RECOVERY_REQUEST_BYTES)?,
        };
        value.validate().map_err(decode_error)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedRecoveryRegistration {
    request: SharedRecoveryRegistrationRequest,
    signature: ReplicaCommitSignature,
}

impl SharedRecoveryRegistration {
    pub fn new(
        request: SharedRecoveryRegistrationRequest,
        signature: ReplicaCommitSignature,
    ) -> Result<Self, SharedRecoveryError> {
        let value = Self { request, signature };
        value.validate()?;
        Ok(value)
    }
    pub const fn request(&self) -> &SharedRecoveryRegistrationRequest {
        &self.request
    }
    pub const fn generation(&self) -> AgentGenerationRouteKey {
        self.request.generation()
    }
    pub const fn committee(&self) -> AgentReplicaCommitteeId {
        self.request.committee()
    }
    pub const fn owner(&self) -> NodeId {
        self.request.owner()
    }
    pub const fn sequence(&self) -> u64 {
        self.request.sequence()
    }
    pub const fn previous(&self) -> Option<Hash> {
        self.request.previous()
    }
    pub const fn query(&self) -> &AuthorityProjectionQuery {
        self.request.query()
    }
    pub fn work(&self) -> &InvocationWork {
        self.request.work()
    }
    pub fn authorization(&self) -> &InvocationAuthorization {
        self.request.authorization()
    }
    pub const fn signature(&self) -> &ReplicaCommitSignature {
        &self.signature
    }
    pub fn signing_message(&self) -> Hash {
        self.request.signing_message()
    }
    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/shared/recovery-registration/v1",
            &[&self.encode()],
        )
    }
    pub fn validate(&self) -> Result<(), SharedRecoveryError> {
        self.request.validate()?;
        if self.signature.validate().is_err() || self.signature.signer() != self.owner() {
            return Err(SharedRecoveryError::InvalidSignature);
        }
        bound(self, MAX_SHARED_RECOVERY_REGISTRATION_BYTES)
    }
    /// Verify custody only. The existing signed-query admission path still
    /// owns credential/enrollment, fresh time, and invocation authorization.
    pub fn verify(
        &self,
        generation: AgentGenerationRouteKey,
        committee: &AgentReplicaCommittee,
    ) -> Result<(), SharedRecoveryError> {
        self.validate()?;
        validate_scope(generation, committee)?;
        if self.generation() != generation || self.committee() != committee.id() {
            return Err(SharedRecoveryError::ScopeMismatch);
        }
        let member = committee
            .member_by_node(self.owner())
            .ok_or(SharedRecoveryError::ScopeMismatch)?;
        if member.replica().role != ReplicaRole::Voter
            || !verify_signature(
                member.ed25519_public_key(),
                &self.signing_message().0,
                self.signature.signature(),
            )
        {
            return Err(SharedRecoveryError::InvalidSignature);
        }
        Ok(())
    }
}

impl ServiceWire for SharedRecoveryRegistration {
    const MAGIC: [u8; 4] = *b"RRS1";
    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut e = Encoder(output);
        e.bytes(&self.request.encode());
        e.bytes(&self.signature.encode());
    }
    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_bound(d, MAX_SHARED_RECOVERY_REGISTRATION_BYTES)?;
        Self::new(
            nested(d, MAX_SHARED_RECOVERY_REQUEST_BYTES)?,
            nested(d, super::shared_commit::MAX_REPLICA_COMMIT_SIGNATURE_BYTES)?,
        )
        .map_err(decode_error)
    }
}

/// Canonical public evidence, never by itself permission to update a manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedRecoveryObservation {
    generation: AgentGenerationRouteKey,
    raft_index: u64,
    raft_term: u64,
    claim: OrderedCommitClaim,
    input: ReplayInput,
    outcome: RuntimeOutcome,
}

impl SharedRecoveryObservation {
    pub const fn generation(&self) -> AgentGenerationRouteKey {
        self.generation
    }
    pub const fn raft_index(&self) -> u64 {
        self.raft_index
    }
    pub const fn raft_term(&self) -> u64 {
        self.raft_term
    }
    pub const fn claim(&self) -> &OrderedCommitClaim {
        &self.claim
    }
    pub fn claim_commitment(&self) -> Hash {
        self.claim.commitment()
    }
    pub const fn input(&self) -> &ReplayInput {
        &self.input
    }
    pub fn input_id(&self) -> ReplayInputId {
        self.input.id()
    }
    pub const fn outcome(&self) -> &RuntimeOutcome {
        &self.outcome
    }
    pub fn is_acknowledgement(&self) -> bool {
        matches!(self.outcome, RuntimeOutcome::Acknowledged(Ok(_)))
    }
    pub fn validate_binding(
        &self,
        index: u64,
        term: u64,
        claim: Hash,
        input: &ReplayInput,
    ) -> Result<(), SharedRecoveryError> {
        self.validate()?;
        if (
            self.raft_index,
            self.raft_term,
            self.claim.commitment(),
            &self.input,
        ) != (index, term, claim, input)
        {
            return Err(SharedRecoveryError::InvalidObservation);
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<(), SharedRecoveryError> {
        if self.generation.validate().is_err()
            || self.raft_index == 0
            || self.raft_term == 0
            || self.claim.validate().is_err()
            || self.claim.raft_index() != self.raft_index
            || self.claim.raft_term() != self.raft_term
            || self.claim.space() != self.generation.space()
            || self.claim.agent() != self.generation.agent()
            || self.claim.genesis() != self.generation.genesis()
            || self.claim.admission() != self.generation.admission()
            || self.claim.runtime() != &self.input.runtime
            || self.input.validate().is_err()
            || self.input.runtime.space != self.generation.space()
            || self.input.runtime.agent != self.generation.agent()
        {
            return Err(SharedRecoveryError::InvalidObservation);
        }
        match (&self.input.operation, &self.outcome) {
            (
                ReplayOperation::CleanInvoke {
                    context: RuntimeExecutionContext::Direct,
                    work,
                    authorization,
                    observed_slot,
                },
                RuntimeOutcome::Completed(result),
            ) => {
                let InvocationAuthorization::PublicPreflight(preflight) = authorization else {
                    return Err(SharedRecoveryError::InvalidObservation);
                };
                if work.mode != sdk::MethodMode::Query
                    || !authorization.matches_work(work)
                    || *observed_slot != preflight.observed_slot
                    || result.as_ref().is_ok_and(|reply| {
                        reply.invocation != work.invocation
                            || reply.actor != work.actor
                            || reply.incarnation != work.incarnation
                            || reply.deployment != work.deployment
                            || reply.mode != work.mode
                            || reply.gas_remaining > work.gas
                    })
                {
                    return Err(SharedRecoveryError::InvalidObservation);
                }
            }
            (
                ReplayOperation::CleanAcknowledge {
                    context: RuntimeExecutionContext::Direct,
                    expected_live: None,
                    work,
                    authorization,
                },
                RuntimeOutcome::Acknowledged(Ok(ack)),
            ) => {
                if work.mode != sdk::MethodMode::Query
                    || !matches!(authorization, InvocationAuthorization::PublicPreflight(_))
                    || ack.invocation != work.invocation
                    || ack.actor != work.actor
                    || ack.incarnation != work.incarnation
                    || ack.deployment != work.deployment
                    || ack.mode != work.mode
                    || ack.work != work.commitment()
                    || ack.authorization != authorization.commitment()
                {
                    return Err(SharedRecoveryError::InvalidObservation);
                }
            }
            _ => return Err(SharedRecoveryError::InvalidObservation),
        }
        let bytes = outcome_bytes(&self.outcome)?;
        // SDK decoding also enforces public reply-lane and outcome shape.
        let decoded = RuntimeTransition::decode(&bytes)
            .map_err(|_| SharedRecoveryError::InvalidObservation)?;
        if !decoded.state.is_empty() || decoded.outcome != self.outcome {
            return Err(SharedRecoveryError::InvalidObservation);
        }
        bound(self, MAX_SHARED_RECOVERY_OBSERVATION_BYTES)
    }
    fn matches(&self, request: &SharedRecoveryRegistrationRequest) -> bool {
        if self.generation != request.generation() {
            return false;
        }
        match &self.input.operation {
            ReplayOperation::CleanInvoke {
                work,
                authorization,
                ..
            } => work == request.work() && authorization == request.authorization(),
            ReplayOperation::CleanAcknowledge {
                work,
                authorization,
                ..
            } => {
                work == &sdk::InvocationRetirement::from_work(request.work())
                    && authorization == request.authorization()
            }
            _ => false,
        }
    }
}

impl ServiceWire for SharedRecoveryObservation {
    const MAGIC: [u8; 4] = *b"RRO1";
    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut e = Encoder(output);
        e.bytes(&self.generation.encode());
        e.u64(self.raft_index);
        e.u64(self.raft_term);
        e.bytes(&self.claim.encode());
        e.bytes(&self.input.encode());
        e.bytes(&outcome_bytes(&self.outcome).expect("private bounded outcome"));
    }
    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_bound(d, MAX_SHARED_RECOVERY_OBSERVATION_BYTES)?;
        let generation = nested(d, super::shared_raft::MAX_AGENT_GENERATION_ROUTE_KEY_BYTES)?;
        let raft_index = d.u64()?;
        let raft_term = d.u64()?;
        let claim = nested(d, super::shared_commit::MAX_ORDERED_COMMIT_CLAIM_BYTES)?;
        let input = nested(d, super::journal::MAX_REPLAY_INPUT_BYTES)?;
        let transition: RuntimeTransition = sdk_nested(d, MAX_SHARED_RECOVERY_OUTCOME_BYTES)?;
        if !transition.state.is_empty() {
            return Err(DecodeError::NonCanonical);
        }
        let value = Self {
            generation,
            raft_index,
            raft_term,
            claim,
            input,
            outcome: transition.outcome,
        };
        value.validate().map_err(decode_error)?;
        Ok(value)
    }
}

/// Only the physical apply/replay boundary may mint this capability. Network
/// bytes and a decoded observation cannot call `SharedRecoveryManifest::observe`.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedSharedRecoveryObservation(SharedRecoveryObservation);

impl VerifiedSharedRecoveryObservation {
    pub(crate) fn observation(&self) -> &SharedRecoveryObservation {
        &self.0
    }
    /// The V2 audit has checked the exact physical slot/input/claim. This may
    /// fold a provisional manifest during ledger open, before VM replay. The
    /// driver must independently compare every unpruned outcome with fresh
    /// replay before serving or certifying that manifest. Certified baseline
    /// records instead require their exact common-QC manifest commitment.
    /// Merely decoding a record is never sufficient to call this constructor.
    pub(crate) fn from_audited_record(
        observation: SharedRecoveryObservation,
    ) -> Result<Self, SharedRecoveryError> {
        observation.validate()?;
        Ok(Self(observation))
    }
    pub(crate) fn from_published(
        published: &super::replay::PublishedSharedOrdered,
        entry: &OrderedEntry,
        outcome: RuntimeOutcome,
    ) -> Result<Self, SharedRecoveryError> {
        if published.entry() != entry.id()
            || published.claim().ordered().head != Some(entry.id())
            || published.claim().ordered().index != entry.index
            || published.claim().genesis() != entry.genesis
        {
            return Err(SharedRecoveryError::InvalidObservation);
        }
        Self::from_validated_replay(
            published.raft_index(),
            published.raft_term(),
            published.claim(),
            &entry.input,
            &outcome,
        )
    }
    /// Caller has independently validated the exact physical Ordered slot and
    /// obtained `outcome` from its replay executor, not a peer or decoded capsule.
    pub(crate) fn from_validated_replay(
        index: u64,
        term: u64,
        claim: &OrderedCommitClaim,
        input: &ReplayInput,
        outcome: &RuntimeOutcome,
    ) -> Result<Self, SharedRecoveryError> {
        if claim.validate().is_err()
            || claim.raft_index() != index
            || claim.raft_term() != term
            || claim.runtime() != &input.runtime
        {
            return Err(SharedRecoveryError::InvalidObservation);
        }
        let generation = AgentGenerationRouteKey::new(
            claim.space(),
            claim.agent(),
            claim.genesis(),
            claim.admission(),
        )
        .map_err(|_| SharedRecoveryError::ScopeMismatch)?;
        let value = SharedRecoveryObservation {
            generation,
            raft_index: index,
            raft_term: term,
            claim: claim.clone(),
            input: input.clone(),
            outcome: outcome.clone(),
        };
        value.validate()?;
        Ok(Self(value))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedRecoverySlot {
    registration: SharedRecoveryRegistration,
    raft_index: u64,
    raft_term: u64,
    invoke: Option<SharedRecoveryObservation>,
    acknowledgement: Option<SharedRecoveryObservation>,
}

impl SharedRecoverySlot {
    pub const fn registration(&self) -> &SharedRecoveryRegistration {
        &self.registration
    }
    pub const fn owner(&self) -> NodeId {
        self.registration.owner()
    }
    pub const fn sequence(&self) -> u64 {
        self.registration.sequence()
    }
    pub const fn raft_index(&self) -> u64 {
        self.raft_index
    }
    pub const fn raft_term(&self) -> u64 {
        self.raft_term
    }
    pub const fn invoke(&self) -> Option<&SharedRecoveryObservation> {
        self.invoke.as_ref()
    }
    pub const fn acknowledgement(&self) -> Option<&SharedRecoveryObservation> {
        self.acknowledgement.as_ref()
    }
    pub fn is_acknowledged(&self) -> bool {
        self.acknowledgement.is_some()
    }
    pub fn completed(&self) -> bool {
        self.is_acknowledged()
    }
    pub fn commitment(&self) -> Hash {
        Hash::digest(b"vos/agent/shared/recovery-slot/v1", &[&self.encode()])
    }
    fn validate(&self) -> Result<(), SharedRecoveryError> {
        self.registration.validate()?;
        if self.raft_index == 0 || self.raft_term == 0 {
            return Err(SharedRecoveryError::InvalidEnvelope);
        }
        for evidence in [&self.invoke, &self.acknowledgement].into_iter().flatten() {
            evidence.validate()?;
            if !evidence.matches(self.registration.request())
                || evidence.claim.committee() != self.registration.committee()
            {
                return Err(SharedRecoveryError::InvalidObservation);
            }
        }
        if self
            .invoke
            .as_ref()
            .is_some_and(SharedRecoveryObservation::is_acknowledgement)
            || self.acknowledgement.as_ref().is_some_and(|ack| {
                !ack.is_acknowledgement()
                    || self.invoke.as_ref().is_none_or(|invoke| {
                        invoke.raft_index >= ack.raft_index || invoke.raft_term > ack.raft_term
                    })
            })
        {
            return Err(SharedRecoveryError::InvalidObservation);
        }
        bound(self, MAX_SHARED_RECOVERY_SLOT_BYTES)
    }
}

impl ServiceWire for SharedRecoverySlot {
    const MAGIC: [u8; 4] = *b"RSL1";
    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut e = Encoder(output);
        e.bytes(&self.registration.encode());
        e.u64(self.raft_index);
        e.u64(self.raft_term);
        e.option(&self.invoke, |e, value| e.bytes(&value.encode()));
        e.option(&self.acknowledgement, |e, value| e.bytes(&value.encode()));
    }
    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_bound(d, MAX_SHARED_RECOVERY_SLOT_BYTES)?;
        let value = Self {
            registration: nested(d, MAX_SHARED_RECOVERY_REGISTRATION_BYTES)?,
            raft_index: d.u64()?,
            raft_term: d.u64()?,
            invoke: d.option(|d| nested(d, MAX_SHARED_RECOVERY_OBSERVATION_BYTES))?,
            acknowledgement: d.option(|d| nested(d, MAX_SHARED_RECOVERY_OBSERVATION_BYTES))?,
        };
        value.validate().map_err(decode_error)?;
        Ok(value)
    }
}

/// At most one monotonically numbered slot for each independently admitted
/// voter. Completed slots are retained watermarks, never silently discarded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedRecoveryManifest {
    generation: AgentGenerationRouteKey,
    committee: AgentReplicaCommittee,
    slots: Vec<SharedRecoverySlot>,
}

impl SharedRecoveryManifest {
    pub fn new(
        generation: AgentGenerationRouteKey,
        committee: AgentReplicaCommittee,
    ) -> Result<Self, SharedRecoveryError> {
        validate_scope(generation, &committee)?;
        Ok(Self {
            generation,
            committee,
            slots: Vec::new(),
        })
    }
    pub const fn generation(&self) -> AgentGenerationRouteKey {
        self.generation
    }
    pub const fn committee(&self) -> &AgentReplicaCommittee {
        &self.committee
    }
    pub fn slots(&self) -> &[SharedRecoverySlot] {
        &self.slots
    }
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
    pub fn slot(&self, owner: NodeId) -> Option<&SharedRecoverySlot> {
        self.slots
            .binary_search_by_key(&owner, SharedRecoverySlot::owner)
            .ok()
            .map(|index| &self.slots[index])
    }
    pub fn commitment(&self) -> Hash {
        Hash::digest(b"vos/agent/shared/recovery-manifest/v1", &[&self.encode()])
    }
    pub fn validate(&self) -> Result<(), SharedRecoveryError> {
        validate_scope(self.generation, &self.committee)?;
        if self.slots.len() > MAX_SHARED_RECOVERY_SLOTS
            || self
                .slots
                .windows(2)
                .any(|pair| pair[0].owner() >= pair[1].owner())
        {
            return Err(SharedRecoveryError::InvalidEnvelope);
        }
        for (index, slot) in self.slots.iter().enumerate() {
            slot.validate()?;
            slot.registration.verify(self.generation, &self.committee)?;
            for other in &self.slots[..index] {
                if !slot.is_acknowledged()
                    && !other.is_acknowledged()
                    && !same_request(slot.registration.request(), other.registration.request())
                {
                    return Err(SharedRecoveryError::Conflict);
                }
                if same_invocation(slot.registration.request(), other.registration.request()) {
                    if !same_request(slot.registration.request(), other.registration.request())
                        || slot.invoke != other.invoke
                        || slot.acknowledgement != other.acknowledgement
                    {
                        return Err(SharedRecoveryError::Conflict);
                    }
                }
            }
        }
        bound(self, MAX_SHARED_RECOVERY_MANIFEST_BYTES)
    }
    pub fn validate_at(&self, raft_index: u64) -> Result<(), SharedRecoveryError> {
        self.validate()?;
        if self.slots.iter().any(|slot| {
            slot.raft_index > raft_index
                || [&slot.invoke, &slot.acknowledgement]
                    .into_iter()
                    .flatten()
                    .any(|evidence| evidence.raft_index > raft_index)
        }) {
            return Err(SharedRecoveryError::InvalidObservation);
        }
        Ok(())
    }
    pub fn validate_at_raft_index(&self, raft_index: u64) -> Result<(), SharedRecoveryError> {
        self.validate_at(raft_index)
    }
    fn last_position(&self) -> (u64, u64) {
        self.slots
            .iter()
            .flat_map(|slot| {
                core::iter::once((slot.raft_index, slot.raft_term)).chain(
                    [&slot.invoke, &slot.acknowledgement]
                        .into_iter()
                        .flatten()
                        .map(|evidence| (evidence.raft_index, evidence.raft_term)),
                )
            })
            .max()
            .unwrap_or((0, 0))
    }
    /// Pure succession check, not evidence that the owner cleared its PAP2.
    pub fn validate_registration(
        &self,
        request: &SharedRecoveryRegistrationRequest,
    ) -> Result<(), SharedRecoveryError> {
        request.validate()?;
        if request.generation() != self.generation
            || request.committee() != self.committee.id()
            || self.committee.member_by_node(request.owner()).is_none()
        {
            return Err(SharedRecoveryError::ScopeMismatch);
        }
        for slot in &self.slots {
            if same_invocation(slot.registration.request(), request)
                && !same_request(slot.registration.request(), request)
            {
                return Err(SharedRecoveryError::Conflict);
            }
        }
        match self.slot(request.owner()) {
            None if request.sequence() == 1 && request.previous().is_none() => Ok(()),
            Some(slot) if slot.registration.request() == request => Ok(()),
            Some(slot) => {
                if !slot.is_acknowledged() {
                    return Err(SharedRecoveryError::NotAcknowledged);
                }
                if slot.sequence().checked_add(1) != Some(request.sequence())
                    || request.previous() != Some(slot.commitment())
                {
                    return Err(SharedRecoveryError::Sequence);
                }
                Ok(())
            }
            None => Err(SharedRecoveryError::Sequence),
        }?;
        // One exact unfinished projection shares one Invoke/ACK capacity
        // reservation across its physical owners. A second distinct pending
        // request must not consume that headroom. A late holder of an already
        // completed request inherits terminal evidence and needs no pair.
        let inherits_terminal = self.slots.iter().any(|slot| {
            slot.is_acknowledged() && same_request(slot.registration.request(), request)
        });
        if !inherits_terminal
            && self.slots.iter().any(|slot| {
                !slot.is_acknowledged() && !same_request(slot.registration.request(), request)
            })
        {
            return Err(SharedRecoveryError::Conflict);
        }
        Ok(())
    }
    pub fn apply_registration(
        &mut self,
        registration: &SharedRecoveryRegistration,
        raft_index: u64,
        raft_term: u64,
    ) -> Result<bool, SharedRecoveryError> {
        registration.verify(self.generation, &self.committee)?;
        self.validate_registration(registration.request())?;
        if raft_index == 0 || raft_term == 0 {
            return Err(SharedRecoveryError::InvalidEnvelope);
        }
        if let Some(existing) = self.slot(registration.owner())
            && existing.registration == *registration
        {
            return Ok(false);
        }
        let previous = self.last_position();
        if raft_index <= previous.0 || raft_term < previous.1 {
            return Err(SharedRecoveryError::InvalidObservation);
        }
        let retained = self
            .slots
            .iter()
            .find(|slot| same_request(slot.registration.request(), registration.request()));
        let slot = SharedRecoverySlot {
            registration: registration.clone(),
            raft_index,
            raft_term,
            invoke: retained.and_then(|slot| slot.invoke.clone()),
            acknowledgement: retained.and_then(|slot| slot.acknowledgement.clone()),
        };
        let mut candidate = self.clone();
        match candidate
            .slots
            .binary_search_by_key(&registration.owner(), SharedRecoverySlot::owner)
        {
            Ok(index) => candidate.slots[index] = slot,
            Err(index) => candidate.slots.insert(index, slot),
        }
        candidate.validate_at(raft_index)?;
        *self = candidate;
        Ok(true)
    }
    pub(crate) fn observe(
        &mut self,
        verified: &VerifiedSharedRecoveryObservation,
    ) -> Result<bool, SharedRecoveryError> {
        let observation = verified.observation();
        observation.validate()?;
        if observation.generation != self.generation {
            return Err(SharedRecoveryError::ScopeMismatch);
        }
        let mut candidate = self.clone();
        let mut changed = false;
        for slot in &mut candidate.slots {
            if !observation.matches(slot.registration.request()) {
                continue;
            }
            if observation.claim().committee() != slot.registration.committee() {
                return Err(SharedRecoveryError::ScopeMismatch);
            }
            let target = if observation.is_acknowledgement() {
                &mut slot.acknowledgement
            } else {
                &mut slot.invoke
            };
            match target {
                Some(previous)
                    if previous != observation
                        && (observation.raft_index <= previous.raft_index
                            || observation.raft_term < previous.raft_term) =>
                {
                    return Err(SharedRecoveryError::Conflict);
                }
                // Custody retains the first terminal Invoke and first
                // positive ACK. Later committed retries have their own
                // physical evidence, but cannot replace this capsule even
                // when execution legitimately returns a different outcome.
                Some(_) => {}
                None => {
                    *target = Some(observation.clone());
                    changed = true;
                }
            }
        }
        candidate.validate()?;
        if changed {
            let previous = self.last_position();
            if observation.raft_index <= previous.0 || observation.raft_term < previous.1 {
                return Err(SharedRecoveryError::InvalidObservation);
            }
            *self = candidate;
        }
        Ok(changed)
    }
}

impl ServiceWire for SharedRecoveryManifest {
    const MAGIC: [u8; 4] = *b"RMF1";
    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut e = Encoder(output);
        e.bytes(&self.generation.encode());
        e.bytes(&self.committee.encode());
        e.u8(self.slots.len() as u8);
        for slot in &self.slots {
            e.bytes(&slot.encode());
        }
    }
    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_bound(d, MAX_SHARED_RECOVERY_MANIFEST_BYTES)?;
        let generation = nested(d, super::shared_raft::MAX_AGENT_GENERATION_ROUTE_KEY_BYTES)?;
        let committee = nested(d, MAX_AGENT_REPLICA_COMMITTEE_BYTES)?;
        let count = d.u8()? as usize;
        if count > MAX_SHARED_RECOVERY_SLOTS {
            return Err(DecodeError::LimitExceeded);
        }
        let mut slots = Vec::with_capacity(count);
        for _ in 0..count {
            slots.push(nested(d, MAX_SHARED_RECOVERY_SLOT_BYTES)?);
        }
        let value = Self {
            generation,
            committee,
            slots,
        };
        value.validate().map_err(decode_error)?;
        Ok(value)
    }
}

fn same_invocation(
    left: &SharedRecoveryRegistrationRequest,
    right: &SharedRecoveryRegistrationRequest,
) -> bool {
    left.work().invocation == right.work().invocation
}
fn same_request(
    left: &SharedRecoveryRegistrationRequest,
    right: &SharedRecoveryRegistrationRequest,
) -> bool {
    left.query == right.query
        && left.work() == right.work()
        && left.authorization() == right.authorization()
}
fn validate_scope(
    generation: AgentGenerationRouteKey,
    committee: &AgentReplicaCommittee,
) -> Result<(), SharedRecoveryError> {
    if generation.validate().is_err()
        || committee.validate().is_err()
        || committee.profile() != AgentProfile::Shared
        || committee.members().len() != MAX_SHARED_RECOVERY_SLOTS
        || committee.voter_count() != MAX_SHARED_RECOVERY_SLOTS
        || committee.space() != generation.space()
        || committee.agent() != generation.agent()
    {
        return Err(SharedRecoveryError::ScopeMismatch);
    }
    Ok(())
}
pub(crate) fn projection_query_matches_work(
    query: &AuthorityProjectionQuery,
    work: &InvocationWork,
    authorization: &InvocationAuthorization,
) -> bool {
    let InvocationAuthorization::PublicPreflight(preflight) = authorization else {
        return false;
    };
    let target = query.authority;
    let Ok(bytes) = query.encode() else {
        return false;
    };
    let method = match query.selector {
        AuthorityProjectionSelector::Inventory { .. } => "inventory_projection_page",
        AuthorityProjectionSelector::Credential => "credential_projection",
        AuthorityProjectionSelector::Agents { .. } => "agent_projection_page",
        AuthorityProjectionSelector::AgentReplicas { .. } => "agent_replica_projection_page",
        AuthorityProjectionSelector::Actors { .. } => "actor_projection_page",
    };
    use crate::actors::codec::Encode as _;
    let mut message = alloc::vec![crate::actors::value::TAG_DYNAMIC];
    message.extend(
        crate::actors::value::Msg::new(method)
            .with("query", crate::actors::value::Value::Bytes(bytes))
            .encode(),
    );
    let invocation = sdk::Hash::digest(
        b"vos/system-authority/projection-invocation/v2",
        &[query.commitment().as_bytes()],
    );
    query.validate_shape().is_ok()
        && work.validate()
        && authorization.matches_work(work)
        && query
            .recovery
            .is_none_or(|scope| scope.accepted_slot == preflight.observed_slot)
        && work.space == target.space
        && work.agent == target.system_agent
        && work.runtime_deployment == target.system_runtime_deployment
        && work.actor == target.binding.issuer.actor
        && work.deployment == target.binding.issuer.deployment
        && work.program == target.binding.issuer.program
        && work.mode == sdk::MethodMode::Query
        && work.invocation.0 == invocation.0
        && work.origin.principal.is_none()
        && work.origin.transport_node == query.attesting_node()
        && work.origin.credential.is_none()
        && work.origin.actor.is_none()
        && work.origin.capability.is_none()
        && work.roles == sdk::InvocationRoleClaims::none()
        && work.message == message
        && !work.recovery_only
}
fn outcome_bytes(outcome: &RuntimeOutcome) -> Result<Vec<u8>, SharedRecoveryError> {
    let bytes = RuntimeTransition {
        state: RuntimeState::default(),
        outcome: outcome.clone(),
    }
    .encode()
    .map_err(|_| SharedRecoveryError::InvalidObservation)?;
    if bytes.len() > MAX_SHARED_RECOVERY_OUTCOME_BYTES {
        return Err(SharedRecoveryError::LimitExceeded);
    }
    Ok(bytes)
}
fn bound<T: ServiceWire>(value: &T, maximum: usize) -> Result<(), SharedRecoveryError> {
    if value.encode().len() > maximum {
        Err(SharedRecoveryError::LimitExceeded)
    } else {
        Ok(())
    }
}
fn decode_bound(d: &Decoder<'_>, maximum: usize) -> Result<(), DecodeError> {
    if d.remaining().saturating_add(36) > maximum {
        Err(DecodeError::LimitExceeded)
    } else {
        Ok(())
    }
}
fn nested<T: ServiceWire>(d: &mut Decoder<'_>, maximum: usize) -> Result<T, DecodeError> {
    let bytes = d.bytes_ref()?;
    if bytes.len() > maximum {
        return Err(DecodeError::LimitExceeded);
    }
    let value = T::decode(bytes)?;
    if value.encode() != bytes {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}
fn sdk_nested<T: CanonicalWire>(d: &mut Decoder<'_>, maximum: usize) -> Result<T, DecodeError> {
    let bytes = d.bytes_ref()?;
    if bytes.len() > maximum {
        return Err(DecodeError::LimitExceeded);
    }
    let value = T::decode(bytes).map_err(|_| DecodeError::NonCanonical)?;
    if value.encode().map_err(|_| DecodeError::NonCanonical)? != bytes {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}
fn decode_error(error: SharedRecoveryError) -> DecodeError {
    if error == SharedRecoveryError::LimitExceeded {
        DecodeError::LimitExceeded
    } else {
        DecodeError::NonCanonical
    }
}
#[cfg(any(feature = "std", feature = "agent-runtime"))]
fn verify_signature(key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(key) else {
        return false;
    };
    key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
        .is_ok()
}
#[cfg(not(any(feature = "std", feature = "agent-runtime")))]
fn verify_signature(_: &[u8; 32], _: &[u8], _: &[u8; 64]) -> bool {
    false
}

#[cfg(test)]
pub(crate) fn recovery_registration_for_test(
    owner_key: u8,
    nonce: u8,
) -> SharedRecoveryRegistration {
    tests::registration(owner_key, nonce)
}

#[cfg(test)]
pub(crate) fn completed_recovery_manifest_for_test() -> SharedRecoveryManifest {
    tests::completed_manifest()
}

#[cfg(test)]
pub(crate) fn recovery_observation_for_test(
    registration: &SharedRecoveryRegistration,
    index: u64,
    acknowledgement: bool,
) -> VerifiedSharedRecoveryObservation {
    tests::observation(registration, index, acknowledgement)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use sdk::authority::{
        AgentAuthorityBinding, AuthorityActorTarget, AuthorityIngressAuthentication,
        AuthorityIssuer, AuthorityProjectionRecoveryDelegation,
    };

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }
    fn node(byte: u8) -> NodeId {
        let mut peer = alloc::vec![0, 0x24, 8, 1, 0x12, 0x20];
        peer.extend_from_slice(&key(byte).verifying_key().to_bytes());
        NodeId::of_authenticated_peer(&peer)
    }
    fn manifest() -> SharedRecoveryManifest {
        let common = super::super::shared_commit::common_snapshot_claim_for_test();
        let claim = common.ordered();
        SharedRecoveryManifest::new(
            AgentGenerationRouteKey::new(
                claim.space(),
                claim.agent(),
                claim.genesis(),
                claim.admission(),
            )
            .unwrap(),
            common.active_committee().clone(),
        )
        .unwrap()
    }
    fn query_work(
        nonce: u8,
    ) -> (
        AuthorityProjectionQuery,
        InvocationWork,
        InvocationAuthorization,
    ) {
        let manifest = manifest();
        let runtime = super::super::shared_commit::common_snapshot_claim_for_test()
            .ordered()
            .runtime()
            .clone();
        let public_key = key(7).verifying_key().to_bytes();
        let mut query = AuthorityProjectionQuery {
            authority: AuthorityActorTarget {
                space: sdk::SpaceId(runtime.space.0),
                system_agent: sdk::AgentId(runtime.agent.0),
                system_runtime_deployment: sdk::DeploymentId(runtime.deployment.0),
                binding: AgentAuthorityBinding {
                    policy: sdk::Hash([0x51; 32]),
                    issuer: AuthorityIssuer {
                        principal: sdk::PrincipalId([0x52; 32]),
                        actor: sdk::ActorId([0x53; 32]),
                        deployment: sdk::DeploymentId([0x54; 32]),
                        program: sdk::ProgramId([0x55; 32]),
                        producer: sdk::ProducerId::of_public_key(&public_key),
                    },
                    public_key,
                    initial_epoch: 1,
                },
            },
            credential: sdk::CredentialId::of_public_key(&public_key),
            nonce: sdk::Hash([nonce; 32]),
            selector: AuthorityProjectionSelector::Credential,
            authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
                credential_public_key: public_key,
                signature: [1; 64],
            },
            recovery: Some(AuthorityProjectionRecoveryDelegation {
                generation: sdk::Hash(manifest.generation().replication_id()),
                committee: sdk::Hash(*manifest.committee().id().as_bytes()),
                accepted_slot: 10,
                expires_at: 20,
            }),
        };
        let signature = key(7).sign(&query.signing_bytes()).to_bytes();
        let AuthorityIngressAuthentication::ApiCredentialSignature {
            signature: stored, ..
        } = &mut query.authentication
        else {
            unreachable!()
        };
        *stored = signature;
        use crate::actors::codec::Encode as _;
        let mut message = alloc::vec![crate::actors::value::TAG_DYNAMIC];
        message.extend(
            crate::actors::value::Msg::new("credential_projection")
                .with(
                    "query",
                    crate::actors::value::Value::Bytes(query.encode().unwrap()),
                )
                .encode(),
        );
        let invocation = sdk::Hash::digest(
            b"vos/system-authority/projection-invocation/v2",
            &[query.commitment().as_bytes()],
        );
        let work = InvocationWork {
            space: query.authority.space,
            agent: query.authority.system_agent,
            runtime_deployment: query.authority.system_runtime_deployment,
            invocation: sdk::InvocationId(invocation.0),
            actor: query.authority.binding.issuer.actor,
            incarnation: sdk::Hash([0x56; 32]),
            deployment: query.authority.binding.issuer.deployment,
            program: query.authority.binding.issuer.program,
            mode: sdk::MethodMode::Query,
            origin: sdk::InvocationOrigin {
                principal: None,
                transport_node: None,
                credential: None,
                actor: None,
                capability: None,
            },
            roles: sdk::InvocationRoleClaims::none(),
            message,
            installation_data: None,
            availability: Vec::new(),
            gas: 100,
            recovery_only: false,
        };
        let auth =
            InvocationAuthorization::PublicPreflight(sdk::PublicPreflight::for_work(&work, 10));
        (query, work, auth)
    }
    fn sign(
        request: SharedRecoveryRegistrationRequest,
        owner_key: u8,
    ) -> SharedRecoveryRegistration {
        let signature = key(owner_key).sign(&request.signing_message().0).to_bytes();
        SharedRecoveryRegistration::new(
            request,
            ReplicaCommitSignature::new(node(owner_key), signature).unwrap(),
        )
        .unwrap()
    }
    pub(super) fn registration(owner_key: u8, nonce: u8) -> SharedRecoveryRegistration {
        let scope = manifest();
        let (query, work, auth) = query_work(nonce);
        sign(
            SharedRecoveryRegistrationRequest::new(
                scope.generation(),
                scope.committee().id(),
                node(owner_key),
                1,
                None,
                query,
                work,
                auth,
            )
            .unwrap(),
            owner_key,
        )
    }
    fn replacement(
        manifest: &SharedRecoveryManifest,
        owner_key: u8,
        nonce: u8,
    ) -> SharedRecoveryRegistration {
        let previous = manifest.slot(node(owner_key)).unwrap();
        let (query, work, auth) = query_work(nonce);
        sign(
            SharedRecoveryRegistrationRequest::new(
                manifest.generation(),
                manifest.committee().id(),
                node(owner_key),
                previous.sequence() + 1,
                Some(previous.commitment()),
                query,
                work,
                auth,
            )
            .unwrap(),
            owner_key,
        )
    }
    pub(super) fn observation(
        registration: &SharedRecoveryRegistration,
        index: u64,
        ack: bool,
    ) -> VerifiedSharedRecoveryObservation {
        let common = super::super::shared_commit::common_snapshot_claim_for_test();
        let claim = common.ordered().with_raft_foundation(index, 3).unwrap();
        let work = registration.work();
        let auth = registration.authorization();
        let (operation, outcome) = if ack {
            (
                ReplayOperation::CleanAcknowledge {
                    context: RuntimeExecutionContext::Direct,
                    expected_live: None,
                    work: sdk::InvocationRetirement::from_work(work),
                    authorization: auth.clone(),
                },
                RuntimeOutcome::Acknowledged(Ok(sdk::InvocationAcknowledgement {
                    invocation: work.invocation,
                    actor: work.actor,
                    incarnation: work.incarnation,
                    deployment: work.deployment,
                    mode: work.mode,
                    work: work.commitment(),
                    authorization: auth.commitment(),
                })),
            )
        } else {
            (
                ReplayOperation::CleanInvoke {
                    context: RuntimeExecutionContext::Direct,
                    work: work.clone(),
                    authorization: auth.clone(),
                    observed_slot: 10,
                },
                RuntimeOutcome::Completed(Ok(sdk::InvocationReply {
                    invocation: work.invocation,
                    actor: work.actor,
                    incarnation: work.incarnation,
                    deployment: work.deployment,
                    mode: work.mode,
                    lane: None,
                    status: sdk::InvocationStatus::Done,
                    reply: b"exact public response".to_vec(),
                    gas_remaining: 99,
                    observation: sdk::InvocationObservation::default(),
                })),
            )
        };
        let input = ReplayInput {
            runtime: claim.runtime().clone(),
            operation,
        };
        VerifiedSharedRecoveryObservation::from_validated_replay(index, 3, &claim, &input, &outcome)
            .unwrap()
    }

    pub(super) fn completed_manifest() -> SharedRecoveryManifest {
        let registration = registration(1, 9);
        let mut state = manifest();
        state.apply_registration(&registration, 1, 3).unwrap();
        state
            .observe(&observation(&registration, 2, false))
            .unwrap();
        state.observe(&observation(&registration, 3, true)).unwrap();
        state
    }

    #[test]
    fn custody_roundtrip_signature_and_exact_idempotence() {
        let registration = registration(1, 9);
        let mut manifest = manifest();
        registration
            .verify(manifest.generation(), manifest.committee())
            .unwrap();
        assert_eq!(
            SharedRecoveryRegistration::decode(&registration.encode()).unwrap(),
            registration
        );
        assert!(manifest.apply_registration(&registration, 1, 3).unwrap());
        let original = manifest.clone();
        assert!(!manifest.apply_registration(&registration, 2, 3).unwrap());
        assert_eq!(manifest, original);
        assert_eq!(
            SharedRecoveryManifest::decode(&manifest.encode()).unwrap(),
            manifest
        );
        assert!(manifest.validate_at_raft_index(0).is_err());
        manifest.validate_at_raft_index(1).unwrap();
    }

    #[test]
    fn exact_owner_sequence_replacement_requires_ack_and_previous_commitment() {
        let first = registration(1, 9);
        let mut state = manifest();
        state.apply_registration(&first, 1, 3).unwrap();
        let denied = replacement(&state, 1, 10);
        let before = state.clone();
        assert_eq!(
            state.apply_registration(&denied, 2, 3),
            Err(SharedRecoveryError::NotAcknowledged)
        );
        assert_eq!(state, before);
        state.observe(&observation(&first, 10, false)).unwrap();
        let before_ack = state.slot(node(1)).unwrap().commitment();
        state.observe(&observation(&first, 11, true)).unwrap();
        assert_ne!(before_ack, state.slot(node(1)).unwrap().commitment());
        let next = replacement(&state, 1, 10);
        let mut stale = next.request().clone();
        stale.previous = Some(before_ack);
        assert_eq!(
            state.apply_registration(&sign(stale, 1), 12, 3),
            Err(SharedRecoveryError::Sequence)
        );
        assert!(state.apply_registration(&next, 12, 3).unwrap());
        assert_eq!(state.slot(node(1)).unwrap().sequence(), 2);
        assert!(!state.slot(node(1)).unwrap().completed());
        assert!(state.apply_registration(&first, 13, 3).is_err());
    }

    #[test]
    fn every_owner_gets_same_exact_evidence_and_late_holder_inherits_it() {
        let mut state = manifest();
        let first = registration(1, 9);
        let second = registration(2, 9);
        state.apply_registration(&first, 1, 3).unwrap();
        state.apply_registration(&second, 2, 3).unwrap();
        let invoke = observation(&first, 10, false);
        assert!(state.observe(&invoke).unwrap());
        assert!(!state.observe(&invoke).unwrap());
        let ack = observation(&first, 11, true);
        state.observe(&ack).unwrap();
        assert!(state.slots().iter().all(SharedRecoverySlot::completed));
        state
            .apply_registration(&registration(3, 9), 12, 3)
            .unwrap();
        assert_eq!(state.slots().len(), 3);
        assert!(
            state
                .slots()
                .iter()
                .all(|slot| slot.invoke() == Some(invoke.observation())
                    && slot.acknowledgement() == Some(ack.observation()))
        );
        assert_eq!(
            SharedRecoveryManifest::decode(&state.encode()).unwrap(),
            state
        );
        assert!(state.validate_at(11).is_err());
        state.validate_at(12).unwrap();
    }

    #[test]
    fn only_one_distinct_unfinished_projection_consumes_lifecycle_headroom() {
        let first = registration(1, 9);
        let different = registration(2, 10);
        let mut state = manifest();
        state.apply_registration(&first, 1, 3).unwrap();
        for index in [2, 1023] {
            let before = state.clone();
            assert_eq!(
                state.validate_registration(different.request()),
                Err(SharedRecoveryError::Conflict)
            );
            assert_eq!(
                state.apply_registration(&different, index, 3),
                Err(SharedRecoveryError::Conflict)
            );
            assert_eq!(state, before);
        }
        state.apply_registration(&registration(2, 9), 2, 3).unwrap();
        state.observe(&observation(&first, 3, false)).unwrap();
        assert!(
            state
                .apply_registration(&registration(3, 10), 4, 3)
                .is_err()
        );
        state.observe(&observation(&first, 4, true)).unwrap();
        let next = replacement(&state, 2, 10);
        state.apply_registration(&next, 5, 3).unwrap();
        // The archived result is still recoverable and can gain another
        // physical owner while a different unfinished projection is active.
        state.apply_registration(&registration(3, 9), 6, 3).unwrap();
        assert!(state.slot(node(3)).unwrap().completed());
        assert!(!state.slot(node(2)).unwrap().completed());
        let unchanged = state.clone();
        assert!(!state.apply_registration(&first, 7, 3).unwrap());
        assert_eq!(state, unchanged);

        let mut malformed = state;
        let slot = malformed
            .slots
            .iter_mut()
            .find(|slot| slot.owner() == node(3))
            .unwrap();
        slot.invoke = None;
        slot.acknowledgement = None;
        assert_eq!(malformed.validate(), Err(SharedRecoveryError::Conflict));
        assert!(SharedRecoveryManifest::decode(&malformed.encode()).is_err());
    }

    #[test]
    fn same_invocation_changed_gas_authorization_or_foreign_owner_cannot_register() {
        let first = registration(1, 9);
        let mut state = manifest();
        state.apply_registration(&first, 1, 3).unwrap();
        let (query, mut work, _) = query_work(9);
        work.gas += 1;
        let authorization =
            InvocationAuthorization::PublicPreflight(sdk::PublicPreflight::for_work(&work, 10));
        let conflict = sign(
            SharedRecoveryRegistrationRequest::new(
                state.generation(),
                state.committee().id(),
                node(2),
                1,
                None,
                query,
                work,
                authorization,
            )
            .unwrap(),
            2,
        );
        let before = state.clone();
        assert_eq!(
            state.apply_registration(&conflict, 2, 3),
            Err(SharedRecoveryError::Conflict)
        );
        assert_eq!(state, before);
        assert!(
            state
                .apply_registration(&registration(4, 10), 2, 3)
                .is_err()
        );
        assert_eq!(state, before);
    }

    #[test]
    fn changed_signed_fields_and_scope_are_not_accepted() {
        let state = manifest();
        let first = registration(1, 9);
        let mut tampered = first.clone();
        tampered.request.sequence = 2;
        tampered.request.previous = Some(Hash([7; 32]));
        assert_eq!(
            tampered.verify(state.generation(), state.committee()),
            Err(SharedRecoveryError::InvalidSignature)
        );
        let other_generation = AgentGenerationRouteKey::new(
            state.generation().space(),
            state.generation().agent(),
            super::super::journal::AgentJournalGenesisId([8; 32]),
            state.generation().admission(),
        )
        .unwrap();
        assert_eq!(
            first.verify(other_generation, state.committee()),
            Err(SharedRecoveryError::ScopeMismatch)
        );
        let mut bytes = first.encode();
        bytes.push(0);
        assert!(SharedRecoveryRegistration::decode(&bytes).is_err());
    }

    #[test]
    fn legacy_query_without_delegation_cannot_become_recovery_custody() {
        let mut request = registration(1, 9).request().clone();
        request.query.recovery = None;
        // Preserve a canonically shaped, correctly signed legacy read and
        // rebuild its exact work identity: rejection must be the missing
        // delegation, not an incidental stale signature or message mismatch.
        let signature = key(7).sign(&request.query.signing_bytes()).to_bytes();
        let AuthorityIngressAuthentication::ApiCredentialSignature {
            signature: stored, ..
        } = &mut request.query.authentication
        else {
            unreachable!()
        };
        *stored = signature;
        use crate::actors::codec::Encode as _;
        let mut message = alloc::vec![crate::actors::value::TAG_DYNAMIC];
        message.extend(
            crate::actors::value::Msg::new("credential_projection")
                .with(
                    "query",
                    crate::actors::value::Value::Bytes(request.query.encode().unwrap()),
                )
                .encode(),
        );
        let RuntimeWork::Invoke {
            invocation,
            authorization,
            ..
        } = &mut request.envelope
        else {
            unreachable!()
        };
        invocation.message = message;
        invocation.invocation = sdk::InvocationId(
            sdk::Hash::digest(
                b"vos/system-authority/projection-invocation/v2",
                &[request.query.commitment().as_bytes()],
            )
            .0,
        );
        **authorization = InvocationAuthorization::PublicPreflight(sdk::PublicPreflight::for_work(
            invocation, 10,
        ));
        assert!(projection_query_matches_work(
            &request.query,
            request.work(),
            request.authorization()
        ));
        assert_eq!(
            request.validate(),
            Err(SharedRecoveryError::InvalidEnvelope)
        );
        assert!(SharedRecoveryRegistrationRequest::decode(&request.encode()).is_err());
    }

    #[test]
    fn custody_expiry_never_releases_unseen_or_committed_slot() {
        let first = registration(1, 9);
        let mut state = manifest();
        state.apply_registration(&first, 1, 3).unwrap();
        assert!(!first.query().recovery.unwrap().admits_at(u64::MAX));
        assert_eq!(
            state.apply_registration(&replacement(&state, 1, 10), 2, 3),
            Err(SharedRecoveryError::NotAcknowledged)
        );
        state.observe(&observation(&first, 10, false)).unwrap();
        state.observe(&observation(&first, 11, true)).unwrap();
        assert!(state.slot(node(1)).unwrap().completed());
    }

    #[test]
    fn ack_without_invoke_and_conflicting_outcome_leave_manifest_unchanged() {
        let first = registration(1, 9);
        let mut state = manifest();
        state.apply_registration(&first, 1, 3).unwrap();
        let before = state.clone();
        assert!(state.observe(&observation(&first, 11, true)).is_err());
        assert_eq!(state, before);
        state.observe(&observation(&first, 10, false)).unwrap();
        let before = state.clone();
        let mut changed = observation(&first, 10, false);
        let RuntimeOutcome::Completed(Ok(reply)) = &mut changed.0.outcome else {
            unreachable!()
        };
        reply.reply.push(1);
        assert_eq!(state.observe(&changed), Err(SharedRecoveryError::Conflict));
        assert_eq!(state, before);
    }

    #[test]
    fn repeated_positions_keep_first_invoke_and_positive_ack_capsule() {
        let first = registration(1, 9);
        let mut state = manifest();
        state.apply_registration(&first, 1, 3).unwrap();
        state.observe(&observation(&first, 2, false)).unwrap();
        state.observe(&observation(&first, 3, true)).unwrap();
        state.apply_registration(&registration(2, 9), 4, 3).unwrap();
        let canonical = state.clone();
        for (index, ack) in [(5, false), (6, true), (7, false), (8, true)] {
            let mut repeated = observation(&first, index, ack);
            if index == 7 {
                repeated.0.outcome = RuntimeOutcome::Completed(Err(sdk::InvocationError::NotFound));
            }
            assert!(!state.observe(&repeated).unwrap());
            assert_eq!(state, canonical);
        }
        assert_eq!(
            SharedRecoveryManifest::decode(&state.encode()).unwrap(),
            canonical
        );
        let mut foreign = observation(&first, 9, false);
        let old = foreign.0.claim();
        foreign.0.claim = OrderedCommitClaim::new(
            old.genesis(),
            old.admission(),
            AgentReplicaCommitteeId::from_bytes([0xff; 32]),
            old.raft_index(),
            old.raft_term(),
            old.ordered(),
            old.merge_frontier(),
            old.merge().clone(),
            old.merge_invocations(),
            old.runtime().clone(),
            old.control().clone(),
            old.linear().clone(),
            old.ordered_invocations(),
            old.artifacts(),
            old.merge_fence(),
            old.sealed_merge().cloned(),
            old.fence_ancestry(),
        )
        .unwrap();
        assert_eq!(
            state.observe(&foreign),
            Err(SharedRecoveryError::ScopeMismatch)
        );
        assert_eq!(state, canonical);
    }

    #[test]
    fn observation_binding_and_public_outcome_validation_fail_closed() {
        let first = registration(1, 9);
        let observation = observation(&first, 10, false);
        let value = observation.observation();
        assert_eq!(
            SharedRecoveryObservation::decode(&value.encode()).unwrap(),
            *value
        );
        value
            .validate_binding(10, 3, value.claim_commitment(), value.input())
            .unwrap();
        assert!(
            value
                .validate_binding(11, 3, value.claim_commitment(), value.input())
                .is_err()
        );
        assert!(
            value
                .validate_binding(10, 4, value.claim_commitment(), value.input())
                .is_err()
        );
        assert!(
            value
                .validate_binding(10, 3, Hash([0xff; 32]), value.input())
                .is_err()
        );
        let mut invalid = value.clone();
        let RuntimeOutcome::Completed(Ok(reply)) = &mut invalid.outcome else {
            unreachable!()
        };
        reply.gas_remaining = first.work().gas + 1;
        assert_eq!(
            invalid.validate(),
            Err(SharedRecoveryError::InvalidObservation)
        );
        let mut invalid = value.clone();
        let RuntimeOutcome::Completed(Ok(reply)) = &mut invalid.outcome else {
            unreachable!()
        };
        reply.lane = Some(sdk::StateLane::Linear);
        assert!(invalid.validate().is_err());
        let mut invalid = value.clone();
        invalid.outcome = RuntimeOutcome::Acknowledged(Err(sdk::InvocationError::NotFound));
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn canonical_slot_count_order_and_complete_byte_limits_are_enforced() {
        let mut state = manifest();
        state.apply_registration(&registration(1, 9), 1, 3).unwrap();
        state.apply_registration(&registration(2, 9), 2, 3).unwrap();
        let mut reversed = state.clone();
        reversed.slots.reverse();
        assert!(SharedRecoveryManifest::decode(&reversed.encode()).is_err());
        let mut excessive = state.clone();
        excessive.slots.extend(state.slots.clone());
        assert_eq!(
            SharedRecoveryManifest::decode(&excessive.encode()),
            Err(DecodeError::LimitExceeded)
        );
        let mut bytes = state.encode();
        bytes.resize(MAX_SHARED_RECOVERY_MANIFEST_BYTES + 1, 0);
        assert_eq!(
            SharedRecoveryManifest::decode(&bytes),
            Err(DecodeError::LimitExceeded)
        );
        assert!(state.encode().len() <= MAX_SHARED_RECOVERY_MANIFEST_BYTES);
    }
}
