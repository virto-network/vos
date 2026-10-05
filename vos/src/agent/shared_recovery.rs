//! Bounded authenticated retention for unfinished System management.
//!
//! Only the exact owner-signed management scope and its physical Invoke/ACK
//! evidence are retained. Registration grants no execution authorization;
//! release still requires the original owner's durable terminal and exact
//! positive evidence. Internal observations never enter this manifest.
//! Decoding establishes shape, not checkpoint or execution authority.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use super::genesis::{
    AgentReplicaCommittee, AgentReplicaCommitteeId, MAX_AGENT_REPLICA_COMMITTEE_BYTES,
};
use super::journal::{
    CanonicalJournalRecord, OrderedBase, OrderedEntry, ReplayInput, ReplayInputId, ReplayOperation,
};
use super::shared_commit::{OrderedCommitClaim, ReplicaCommitSignature};
use super::shared_raft::AgentGenerationRouteKey;
use super::{AgentProfile, ReplicaRole};
use crate::agent_sdk as sdk;
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{Hash, NodeId};
use sdk::wire::CanonicalWire;
use sdk::{
    InvocationAuthorization, InvocationWork, RuntimeExecutionContext, RuntimeOutcome, RuntimeState,
    RuntimeTransition, RuntimeWork,
};

#[cfg(feature = "std")]
pub(crate) mod management;
#[cfg(feature = "std")]
pub(crate) use management::{
    MAX_SHARED_MANAGEMENT_RECOVERY_REGISTRATION_BYTES,
    MAX_SHARED_MANAGEMENT_RECOVERY_RELEASE_BYTES, SharedManagementRecoveryRegistration,
    SharedManagementRecoveryRelease, SharedManagementRecoverySlot,
};

/// Fixed founding-voter and independent management-holder bound.
pub const MAX_SHARED_RECOVERY_SLOTS: usize = 3;
pub const MAX_SHARED_RECOVERY_REQUEST_BYTES: usize =
    sdk::MAX_RUNTIME_AVAILABILITY_BYTES + 2 * sdk::MAX_INVOCATION_MESSAGE_BYTES + 16 * 1024;
pub const MAX_SHARED_RECOVERY_OUTCOME_BYTES: usize = sdk::MAX_INVOCATION_REPLY_BYTES + 2048;
pub const MAX_SHARED_RECOVERY_OBSERVATION_BYTES: usize = sdk::MAX_RUNTIME_AVAILABILITY_BYTES
    + sdk::MAX_INVOCATION_MESSAGE_BYTES
    + MAX_SHARED_RECOVERY_OUTCOME_BYTES
    + super::shared_commit::MAX_ORDERED_COMMIT_CLAIM_BYTES
    + 32 * 1024;
#[cfg(not(feature = "std"))]
pub const MAX_SHARED_RECOVERY_MANIFEST_BYTES: usize = MAX_AGENT_REPLICA_COMMITTEE_BYTES + 1024;
#[cfg(feature = "std")]
pub const MAX_SHARED_RECOVERY_MANIFEST_BYTES: usize = MAX_AGENT_REPLICA_COMMITTEE_BYTES
    + 1024
    + MAX_SHARED_RECOVERY_SLOTS * management::MAX_SHARED_MANAGEMENT_RECOVERY_SLOT_BYTES;

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
        self.input.retained_recovery_id()
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
                // Public Query and retained management Linear evidence use the
                // same exact signed preflight binding. Recording evidence
                // grants no authorization to execute or recover a mutation.
                if !matches!(work.mode, sdk::MethodMode::Query | sdk::MethodMode::Linear)
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
                if !matches!(work.mode, sdk::MethodMode::Query | sdk::MethodMode::Linear)
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
}

impl ServiceWire for SharedRecoveryObservation {
    const MAGIC: [u8; 4] = *b"RRO1";
    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut e = Encoder(output);
        e.bytes(&self.generation.encode());
        e.u64(self.raft_index);
        e.u64(self.raft_term);
        e.bytes(&self.claim.encode());
        e.bytes(&self.input.encode_retained_recovery());
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
    #[cfg(test)]
    pub(crate) fn from_audited_record(
        observation: SharedRecoveryObservation,
    ) -> Result<Self, SharedRecoveryError> {
        observation.validate()?;
        Ok(Self(observation))
    }
    /// Same provisional physical-audit capability, with the exact slot/input
    /// binding checked in this constructor. No validation survives mutation
    /// or a later storage observation; the driver replay requirement above
    /// remains unchanged.
    pub(super) fn from_bound_audited_record(
        observation: SharedRecoveryObservation,
        index: u64,
        term: u64,
        claim: Hash,
        input: &ReplayInput,
    ) -> Result<Self, SharedRecoveryError> {
        observation.validate_binding(index, term, claim, input)?;
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

/// At most one monotonically numbered management scope per admitted voter.
/// Released scopes retain their signed watermarks; observations have no slots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedRecoveryManifest {
    generation: AgentGenerationRouteKey,
    committee: AgentReplicaCommittee,
    #[cfg(feature = "std")]
    management: Vec<SharedManagementRecoverySlot>,
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
            #[cfg(feature = "std")]
            management: Vec::new(),
        })
    }
    pub const fn generation(&self) -> AgentGenerationRouteKey {
        self.generation
    }
    pub const fn committee(&self) -> &AgentReplicaCommittee {
        &self.committee
    }
    pub fn is_empty(&self) -> bool {
        #[cfg(feature = "std")]
        {
            self.management.is_empty()
        }
        #[cfg(not(feature = "std"))]
        {
            true
        }
    }
    #[cfg(feature = "std")]
    pub(crate) fn management_slots(&self) -> &[SharedManagementRecoverySlot] {
        &self.management
    }
    #[cfg(feature = "std")]
    pub(crate) fn management_slot(&self, owner: NodeId) -> Option<&SharedManagementRecoverySlot> {
        self.management
            .binary_search_by_key(&owner, SharedManagementRecoverySlot::owner)
            .ok()
            .map(|index| &self.management[index])
    }
    #[cfg(feature = "std")]
    pub(crate) fn management_origin_for_root(
        &self,
        owner: NodeId,
        root: &management::SharedManagementRecoveryMember,
    ) -> Result<NodeId, SharedRecoveryError> {
        self.validate()?;
        root.validate_scope(self.generation)?;
        management::management_origin_for_root(&self.management, owner, root)
    }
    #[cfg(feature = "std")]
    pub(crate) fn has_pending_management(&self) -> bool {
        self.management.iter().any(|slot| !slot.is_released())
    }
    #[cfg(feature = "std")]
    pub(crate) fn apply_management_registration(
        &mut self,
        registration: &SharedManagementRecoveryRegistration,
        index: u64,
        term: u64,
    ) -> Result<bool, SharedRecoveryError> {
        self.validate_management_registration_request(registration.request())?;
        let mut candidate = self.clone();
        let changed = management::apply_management_registration_after_request_validation(
            &mut candidate.management,
            self.generation,
            &self.committee,
            registration,
            index,
            term,
        )?;
        if changed {
            let previous = self.last_position();
            if index <= previous.0 || term < previous.1 {
                return Err(SharedRecoveryError::InvalidObservation);
            }
            // The same-call helper fully validated these candidate slots,
            // including signatures and all inherited evidence, against this
            // unchanged generation/committee. Keep the remaining manifest
            // scope, whole encoded bound and positions before publication.
            validate_scope(candidate.generation, &candidate.committee)?;
            bound(&candidate, MAX_SHARED_RECOVERY_MANIFEST_BYTES)?;
            candidate.validate_positions_after_validation(index)?;
            *self = candidate;
        }
        Ok(changed)
    }
    #[cfg(feature = "std")]
    pub(crate) fn apply_management_release(
        &mut self,
        release: &SharedManagementRecoveryRelease,
        index: u64,
        term: u64,
    ) -> Result<bool, SharedRecoveryError> {
        let mut candidate = self.clone();
        let changed = management::apply_management_release(
            &mut candidate.management,
            self.generation,
            &self.committee,
            release,
            index,
            term,
        )?;
        if changed {
            let previous = self.last_position();
            if index <= previous.0 || term < previous.1 {
                return Err(SharedRecoveryError::InvalidObservation);
            }
            candidate.validate_at(index)?;
            *self = candidate;
        }
        Ok(changed)
    }

    pub(crate) fn observations(&self) -> Vec<&SharedRecoveryObservation> {
        #[cfg(feature = "std")]
        {
            self.management
                .iter()
                .flat_map(SharedManagementRecoverySlot::observations)
                .collect()
        }
        #[cfg(not(feature = "std"))]
        {
            Vec::new()
        }
    }
    pub(crate) fn retains_input(&self, input: &ReplayInput) -> bool {
        #[cfg(feature = "std")]
        {
            self.management.iter().any(|slot| slot.matches_input(input))
        }
        #[cfg(not(feature = "std"))]
        {
            let _ = input;
            false
        }
    }
    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/shared/management-recovery-manifest/v4",
            &[&self.encode()],
        )
    }
    pub fn validate(&self) -> Result<(), SharedRecoveryError> {
        validate_scope(self.generation, &self.committee)?;
        #[cfg(feature = "std")]
        management::validate_management_slots(&self.management, self.generation, &self.committee)?;
        bound(self, MAX_SHARED_RECOVERY_MANIFEST_BYTES)
    }
    pub fn validate_at(&self, raft_index: u64) -> Result<(), SharedRecoveryError> {
        self.validate()?;
        self.validate_positions_after_validation(raft_index)
    }
    /// Only the position check after complete immutable manifest validation.
    pub(super) fn validate_positions_after_validation(
        &self,
        raft_index: u64,
    ) -> Result<(), SharedRecoveryError> {
        #[cfg(feature = "std")]
        for slot in &self.management {
            if slot.last_position().0 > raft_index {
                return Err(SharedRecoveryError::InvalidObservation);
            }
        }
        #[cfg(not(feature = "std"))]
        let _ = raft_index;
        Ok(())
    }
    pub fn validate_at_raft_index(&self, raft_index: u64) -> Result<(), SharedRecoveryError> {
        self.validate_at(raft_index)
    }
    fn last_position(&self) -> (u64, u64) {
        #[cfg(feature = "std")]
        {
            management::management_last_position(&self.management)
        }
        #[cfg(not(feature = "std"))]
        {
            (0, 0)
        }
    }
    #[cfg(feature = "std")]
    pub(crate) fn validate_management_registration_request(
        &self,
        request: &management::SharedManagementRecoveryRegistrationRequest,
    ) -> Result<(), SharedRecoveryError> {
        management::validate_management_registration_request(
            &self.management,
            self.generation,
            &self.committee,
            request,
        )
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
        #[cfg(feature = "std")]
        let changed =
            management::observe_management_candidate(&mut candidate.management, verified)?;
        #[cfg(not(feature = "std"))]
        let changed = false;
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
    const MAGIC: [u8; 4] = *b"RMF4";
    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut e = Encoder(output);
        e.bytes(&self.generation.encode());
        e.bytes(&self.committee.encode());
        #[cfg(feature = "std")]
        {
            e.u8(self.management.len() as u8);
            for slot in &self.management {
                e.bytes(&slot.encode());
            }
        }
        #[cfg(not(feature = "std"))]
        e.u8(0);
    }
    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_bound(d, MAX_SHARED_RECOVERY_MANIFEST_BYTES)?;
        let generation = nested(d, super::shared_raft::MAX_AGENT_GENERATION_ROUTE_KEY_BYTES)?;
        let committee = nested(d, MAX_AGENT_REPLICA_COMMITTEE_BYTES)?;
        let count = d.u8()? as usize;
        if count > MAX_SHARED_RECOVERY_SLOTS {
            return Err(DecodeError::LimitExceeded);
        }
        #[cfg(feature = "std")]
        let management = {
            let mut slots = Vec::with_capacity(count);
            for _ in 0..count {
                slots.push(nested(
                    d,
                    management::MAX_SHARED_MANAGEMENT_RECOVERY_SLOT_BYTES,
                )?);
            }
            slots
        };
        #[cfg(not(feature = "std"))]
        if count != 0 {
            return Err(DecodeError::InvalidTag);
        }
        let value = Self {
            generation,
            committee,
            #[cfg(feature = "std")]
            management,
        };
        value.validate().map_err(decode_error)?;
        Ok(value)
    }
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

/// Canonical serialization, never validation or execution authority. These
/// ServiceWire encoders already serialize without admission checks; their
/// private retained envelopes still undergo the complete checked SDK encode
/// in every constructor/validation path and strict SDK decode on input.
/// Avoid hiding another caller-sized preimage validation inside each enclosing
/// bound, commitment, signature message, and canonical re-encoding. This uses
/// the existing journal encoder's exact frame/body mechanism, not cached bytes.
fn encode_retained_envelope(work: &RuntimeWork) -> Result<Vec<u8>, sdk::wire::WireError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&RuntimeWork::MAGIC);
    bytes.extend_from_slice(sdk::RUNTIME_ABI_ID.as_bytes());
    work.encode_body(&mut vos_protocol::wire::Encoder(&mut bytes));
    if bytes.len() > RuntimeWork::MAX_ENCODED_BYTES {
        return Err(sdk::wire::WireError::LimitExceeded);
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

#[cfg(all(test, feature = "std"))]
pub(crate) fn management_manifest_for_test() -> SharedRecoveryManifest {
    let common = super::shared_commit::common_snapshot_claim_for_test();
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
#[cfg(all(test, feature = "std"))]
pub(crate) fn management_node_for_test(owner: u8) -> NodeId {
    let key = ed25519_dalek::SigningKey::from_bytes(&[owner; 32]);
    let mut peer = alloc::vec![0, 0x24, 8, 1, 0x12, 0x20];
    peer.extend_from_slice(&key.verifying_key().to_bytes());
    NodeId::of_authenticated_peer(&peer)
}
/// Structural physical-evidence fixture, not custody or execution authority.
/// Its work carries a real signed Linear administration call. Multiple test
/// holders of the same nonce share the original node's exact immutable work.
#[cfg(all(test, feature = "std"))]
#[derive(Clone, Debug)]
pub(crate) struct ManagementRecoveryFixture {
    generation: AgentGenerationRouteKey,
    committee: AgentReplicaCommitteeId,
    owner: NodeId,
    envelope: RuntimeWork,
}
#[cfg(all(test, feature = "std"))]
impl ManagementRecoveryFixture {
    pub(crate) const fn generation(&self) -> AgentGenerationRouteKey {
        self.generation
    }
    pub(crate) const fn committee(&self) -> AgentReplicaCommitteeId {
        self.committee
    }
    pub(crate) const fn owner(&self) -> NodeId {
        self.owner
    }
    pub(crate) const fn envelope(&self) -> &RuntimeWork {
        &self.envelope
    }
    pub(crate) fn work(&self) -> &InvocationWork {
        let RuntimeWork::Invoke { invocation, .. } = &self.envelope else {
            unreachable!()
        };
        invocation
    }
    pub(crate) fn authorization(&self) -> &InvocationAuthorization {
        let RuntimeWork::Invoke { authorization, .. } = &self.envelope else {
            unreachable!()
        };
        authorization
    }
}
#[cfg(all(test, feature = "std"))]
pub(crate) fn management_recovery_fixture_for_test(
    owner: u8,
    nonce: u8,
) -> ManagementRecoveryFixture {
    management_recovery_fixture_at_slot_for_test(owner, nonce, 10)
}
#[cfg(all(test, feature = "std"))]
pub(crate) fn management_recovery_fixture_at_slot_for_test(
    owner: u8,
    nonce: u8,
    observed_slot: u64,
) -> ManagementRecoveryFixture {
    use crate::actors::codec::Encode as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use sdk::authority::{
        AgentAuthorityBinding, AuthorityActorTarget, AuthorityAdminCall, AuthorityAdminOperation,
        AuthorityIssuer,
    };
    let manifest = management_manifest_for_test();
    let runtime = super::shared_commit::common_snapshot_claim_for_test()
        .ordered()
        .runtime()
        .clone();
    let key = SigningKey::from_bytes(&[7; 32]);
    let public_key = key.verifying_key().to_bytes();
    let authority = AuthorityActorTarget {
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
    };
    let mut call = AuthorityAdminCall {
        invocation: sdk::InvocationId::ZERO,
        authority,
        administrator: sdk::PrincipalId([0x52; 32]),
        credential: sdk::CredentialId::of_public_key(&public_key),
        request_sequence: core::num::NonZeroU64::new(u64::from(nonce) + 1).unwrap(),
        credential_public_key: public_key,
        authenticated_node: sdk::NodeId(management_node_for_test(1).0),
        observed_slot,
        expected_generation: core::num::NonZeroU64::new(1).unwrap(),
        operation: AuthorityAdminOperation::SetSpaceRole {
            principal: sdk::PrincipalId([0x52; 32]),
            role: sdk::RoleId([nonce.wrapping_add(1).max(1); 32]),
            granted: true,
        },
        signature: [1; 64],
    };
    call.invocation = call.expected_invocation();
    call.signature = key.sign(&call.signing_bytes()).to_bytes();
    call.validate_shape().unwrap();
    let mut message = alloc::vec![crate::actors::value::TAG_DYNAMIC];
    message.extend(
        crate::actors::value::Msg::new("administer")
            .with(
                "call",
                crate::actors::value::Value::Bytes(call.encode().unwrap()),
            )
            .encode(),
    );
    let work = InvocationWork {
        space: authority.space,
        agent: authority.system_agent,
        runtime_deployment: authority.system_runtime_deployment,
        invocation: call.invocation,
        actor: authority.binding.issuer.actor,
        incarnation: sdk::Hash([0x56; 32]),
        deployment: authority.binding.issuer.deployment,
        program: authority.binding.issuer.program,
        mode: sdk::MethodMode::Linear,
        origin: sdk::InvocationOrigin {
            principal: Some(call.administrator),
            transport_node: Some(call.authenticated_node),
            credential: Some(call.credential),
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
    work.validate().then_some(()).unwrap();
    let authorization = InvocationAuthorization::PublicPreflight(sdk::PublicPreflight::for_work(
        &work,
        observed_slot,
    ));
    let envelope = RuntimeWork::Invoke {
        context: RuntimeExecutionContext::Direct,
        state: RuntimeState::default(),
        invocation: Box::new(work),
        authorization: Box::new(authorization),
        observed_slot,
    };
    envelope.encode().unwrap();
    ManagementRecoveryFixture {
        generation: manifest.generation(),
        committee: manifest.committee().id(),
        owner: management_node_for_test(owner),
        envelope,
    }
}
#[cfg(all(test, feature = "std"))]
pub(crate) fn management_observation_for_test(
    fixture: &ManagementRecoveryFixture,
    index: u64,
    acknowledge: bool,
) -> VerifiedSharedRecoveryObservation {
    let common = super::shared_commit::common_snapshot_claim_for_test();
    let claim = common.ordered().with_raft_foundation(index, 3).unwrap();
    let work = fixture.work();
    let authorization = fixture.authorization();
    let InvocationAuthorization::PublicPreflight(preflight) = authorization else {
        unreachable!()
    };
    let (operation, outcome) = if acknowledge {
        (
            ReplayOperation::CleanAcknowledge {
                context: RuntimeExecutionContext::Direct,
                expected_live: None,
                work: sdk::InvocationRetirement::from_work(work),
                authorization: authorization.clone(),
            },
            RuntimeOutcome::Acknowledged(Ok(sdk::InvocationAcknowledgement {
                invocation: work.invocation,
                actor: work.actor,
                incarnation: work.incarnation,
                deployment: work.deployment,
                mode: work.mode,
                work: work.commitment(),
                authorization: authorization.commitment(),
            })),
        )
    } else {
        (
            ReplayOperation::CleanInvoke {
                context: RuntimeExecutionContext::Direct,
                work: work.clone(),
                authorization: authorization.clone(),
                observed_slot: preflight.observed_slot,
            },
            RuntimeOutcome::Completed(Ok(sdk::InvocationReply {
                invocation: work.invocation,
                actor: work.actor,
                incarnation: work.incarnation,
                deployment: work.deployment,
                mode: work.mode,
                lane: work.mode.write_lane(),
                status: sdk::InvocationStatus::Done,
                reply: b"management terminal".to_vec(),
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
#[cfg(all(test, feature = "std"))]
pub(crate) fn completed_management_manifest_for_test() -> SharedRecoveryManifest {
    let mut manifest = management_manifest_for_test();
    manifest
        .management
        .push(management::completed_management_slot_for_test());
    manifest.validate().unwrap();
    manifest
}
#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    #[test]
    fn management_only_manifest_is_strict_rmf4_without_read_slots_or_expiry() {
        let manifest = management_manifest_for_test();
        assert!(manifest.is_empty());
        let encoded = manifest.encode();
        assert_eq!(&encoded[..4], b"RMF4");
        assert_eq!(SharedRecoveryManifest::decode(&encoded).unwrap(), manifest);
        for tag in [*b"RMF1", *b"RMF2", *b"RMF3"] {
            let mut old = encoded.clone();
            old[..4].copy_from_slice(&tag);
            assert!(SharedRecoveryManifest::decode(&old).is_err());
        }
        for end in 0..encoded.len() {
            assert!(SharedRecoveryManifest::decode(&encoded[..end]).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(SharedRecoveryManifest::decode(&trailing).is_err());
    }
    #[test]
    fn complete_management_evidence_round_trips_without_internal_read_records() {
        let manifest = completed_management_manifest_for_test();
        assert!(!manifest.is_empty());
        assert_eq!(manifest.management_slots().len(), 1);
        assert_eq!(manifest.observations().len(), 2);
        assert_eq!(
            SharedRecoveryManifest::decode(&manifest.encode()).unwrap(),
            manifest
        );
        manifest.validate_at(3).unwrap();
        assert!(manifest.validate_at(2).is_err());
    }
    #[test]
    fn replay_observations_bind_exact_preflight_for_public_query_and_management() {
        for mode in [sdk::MethodMode::Query, sdk::MethodMode::Linear] {
            let mut fixture = management_recovery_fixture_for_test(1, 7);
            let RuntimeWork::Invoke {
                invocation,
                authorization,
                ..
            } = &mut fixture.envelope
            else {
                unreachable!()
            };
            invocation.mode = mode;
            **authorization = InvocationAuthorization::PublicPreflight(
                sdk::PublicPreflight::for_work(invocation, 10),
            );
            fixture.envelope.encode().unwrap();
            for acknowledge in [false, true] {
                let verified = management_observation_for_test(&fixture, 2, acknowledge);
                let observation = verified.observation();
                assert_eq!(
                    SharedRecoveryObservation::decode(&observation.encode()).unwrap(),
                    *observation
                );
                let mut wrong = observation.clone();
                if let ReplayOperation::CleanInvoke { observed_slot, .. } =
                    &mut wrong.input.operation
                {
                    *observed_slot += 1;
                    assert!(wrong.validate().is_err());
                }
            }
        }
    }
}
