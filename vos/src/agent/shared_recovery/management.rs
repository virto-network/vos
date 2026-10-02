//! Retention only for an origin's exact, unfinished System management scope.
//!
//! These records neither authorize a mutation nor delegate its execution. The
//! existing credential calls, receipts, runtime and lifecycle still own those
//! decisions. Registration precedes the independent intent write; release is
//! owner-signed only after that lifecycle's durable terminal/intent clear. A
//! positive runtime ACK is an additional release prerequisite, never a substitute
//! for that owner-side check. There is deliberately no timeout or expiry release.

use super::*;
use crate::agent::clean_management_intent::ManagementJournalAnchor;

pub(crate) const MAX_SHARED_MANAGEMENT_RECOVERY_MEMBERS: usize = 8;
pub(crate) const MAX_SHARED_MANAGEMENT_RECOVERY_SLOTS: usize = 3;
pub(crate) const MAX_SHARED_MANAGEMENT_RECOVERY_SCOPE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_SHARED_MANAGEMENT_RECOVERY_SLOT_BYTES: usize =
    MAX_SHARED_MANAGEMENT_RECOVERY_SCOPE_BYTES;
const MAX_MEMBER_BYTES: usize = MAX_SHARED_RECOVERY_REQUEST_BYTES + 512;
// The member count is not permission to grow the existing Raft allocation.
// A complete signed registration must fit one existing physical command.
pub(crate) const MAX_SHARED_MANAGEMENT_RECOVERY_REGISTRATION_BYTES: usize =
    super::super::journal::MAX_JOURNAL_RECORD_BYTES;
const MAX_REGISTRATION_REQUEST_BYTES: usize =
    MAX_SHARED_MANAGEMENT_RECOVERY_REGISTRATION_BYTES - 256;
pub(crate) const MAX_SHARED_MANAGEMENT_RECOVERY_RELEASE_BYTES: usize = 1024;

/// One immutable dependency. Its parent names an earlier member of the same
/// owner's scope, not merely another request with the same actor or Agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SharedManagementRecoveryMember {
    parent: Option<Hash>,
    anchor: ManagementJournalAnchor,
    envelope: RuntimeWork,
}

impl SharedManagementRecoveryMember {
    pub(crate) fn new(
        parent: Option<Hash>,
        anchor: ManagementJournalAnchor,
        envelope: RuntimeWork,
    ) -> Result<Self, SharedRecoveryError> {
        let value = Self {
            parent,
            anchor,
            envelope,
        };
        value.validate()?;
        Ok(value)
    }
    pub(crate) const fn parent(&self) -> Option<Hash> {
        self.parent
    }
    pub(crate) const fn anchor(&self) -> &ManagementJournalAnchor {
        &self.anchor
    }
    pub(crate) const fn envelope(&self) -> &RuntimeWork {
        &self.envelope
    }
    pub(crate) fn work(&self) -> &InvocationWork {
        match &self.envelope {
            RuntimeWork::Invoke { invocation, .. } => invocation,
            _ => unreachable!("private validated management envelope"),
        }
    }
    pub(crate) fn authorization(&self) -> &InvocationAuthorization {
        match &self.envelope {
            RuntimeWork::Invoke { authorization, .. } => authorization,
            _ => unreachable!("private validated management envelope"),
        }
    }
    pub(crate) fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/shared/management-recovery-member/v1",
            &[&self.encode()],
        )
    }
    fn validate(&self) -> Result<(), SharedRecoveryError> {
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
        if self.parent == Some(Hash::ZERO)
            || ManagementJournalAnchor::decode(&self.anchor.encode()).as_ref() != Ok(&self.anchor)
            || *context != RuntimeExecutionContext::Direct
            || !state.is_empty()
            || invocation.recovery_only
            || invocation.mode != sdk::MethodMode::Linear
            || **authorization
                != InvocationAuthorization::PublicPreflight(sdk::PublicPreflight::for_work(
                    invocation,
                    *observed_slot,
                ))
        {
            return Err(SharedRecoveryError::InvalidEnvelope);
        }
        // The checked SDK envelope encode validates this same immutable
        // invocation, including every availability preimage. Keep that full
        // check without hashing the work a second time above.
        self.envelope
            .encode()
            .map_err(|_| SharedRecoveryError::InvalidEnvelope)?;
        bound(self, MAX_MEMBER_BYTES)
    }
    pub(super) fn validate_scope(
        &self,
        generation: AgentGenerationRouteKey,
    ) -> Result<(), SharedRecoveryError> {
        self.validate()?;
        if self.anchor.genesis != generation.genesis()
            || self.anchor.admission != generation.admission()
            || self.work().space.0 != generation.space().0
            || self.work().agent.0 != generation.agent().0
        {
            return Err(SharedRecoveryError::ScopeMismatch);
        }
        Ok(())
    }
    pub(crate) fn matches_input(&self, input: &ReplayInput) -> bool {
        if self.anchor.runtime != input.runtime.commitment() {
            return false;
        }
        match (&self.envelope, &input.operation) {
            (
                RuntimeWork::Invoke {
                    context,
                    invocation,
                    authorization,
                    observed_slot,
                    ..
                },
                ReplayOperation::CleanInvoke {
                    context: actual_context,
                    work,
                    authorization: actual_authorization,
                    observed_slot: actual_slot,
                },
            ) => {
                context == actual_context
                    && invocation.as_ref() == work
                    && authorization.as_ref() == actual_authorization
                    && observed_slot == actual_slot
            }
            (
                RuntimeWork::Invoke {
                    context,
                    invocation,
                    authorization,
                    ..
                },
                ReplayOperation::CleanAcknowledge {
                    context: actual_context,
                    expected_live: None,
                    work,
                    authorization: actual_authorization,
                },
            ) => {
                context == actual_context
                    && sdk::InvocationRetirement::from_work(invocation) == *work
                    && authorization.as_ref() == actual_authorization
            }
            _ => false,
        }
    }
    fn matches(&self, observation: &SharedRecoveryObservation) -> bool {
        if !self.matches_input(observation.input())
            || observation.claim().ordered().index <= self.anchor.ordered.index
        {
            return false;
        }
        true
    }
}
impl ServiceWire for SharedManagementRecoveryMember {
    const MAGIC: [u8; 4] = *b"MRM1";
    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut e = Encoder(output);
        e.option(&self.parent, |e, value| e.fixed(&value.0));
        e.bytes(&self.anchor.encode());
        e.bytes(
            &encode_retained_envelope(&self.envelope).expect("private bounded management envelope"),
        );
    }
    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_bound(d, MAX_MEMBER_BYTES)?;
        Self::new(
            d.option(|d| d.fixed().map(Hash))?,
            nested(d, 256)?,
            sdk_nested(d, MAX_SHARED_RECOVERY_REQUEST_BYTES)?,
        )
        .map_err(decode_error)
    }
}

/// Complete immutable member set. Extensions append exactly one dependency;
/// the previous slot commitment binds its evidence as well as its requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SharedManagementRecoveryRegistrationRequest {
    generation: AgentGenerationRouteKey,
    committee: AgentReplicaCommitteeId,
    owner: NodeId,
    // The first acquiring node, not the current custody holder. Exact shadow
    // holders and extensions preserve this signed family provenance.
    origin_owner: NodeId,
    sequence: u64,
    previous: Option<Hash>,
    members: Vec<SharedManagementRecoveryMember>,
}
impl SharedManagementRecoveryRegistrationRequest {
    pub(crate) fn new(
        generation: AgentGenerationRouteKey,
        committee: AgentReplicaCommitteeId,
        owner: NodeId,
        origin_owner: NodeId,
        sequence: u64,
        previous: Option<Hash>,
        members: Vec<SharedManagementRecoveryMember>,
    ) -> Result<Self, SharedRecoveryError> {
        let value = Self {
            generation,
            committee,
            owner,
            origin_owner,
            sequence,
            previous,
            members,
        };
        value.validate()?;
        Ok(value)
    }
    pub(crate) const fn generation(&self) -> AgentGenerationRouteKey {
        self.generation
    }
    pub(crate) const fn committee(&self) -> AgentReplicaCommitteeId {
        self.committee
    }
    pub(crate) const fn owner(&self) -> NodeId {
        self.owner
    }
    pub(crate) const fn origin_owner(&self) -> NodeId {
        self.origin_owner
    }
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub(crate) const fn previous(&self) -> Option<Hash> {
        self.previous
    }
    pub(crate) fn members(&self) -> &[SharedManagementRecoveryMember] {
        &self.members
    }
    pub(crate) fn signing_message(&self) -> Hash {
        Hash::digest(
            b"vos/agent/shared/management-recovery-registration-signature/v1",
            &[&self.encode()],
        )
    }
    pub(crate) fn validate(&self) -> Result<(), SharedRecoveryError> {
        if self.members.len() > MAX_SHARED_MANAGEMENT_RECOVERY_MEMBERS {
            return Err(SharedRecoveryError::LimitExceeded);
        }
        if self.generation.validate().is_err()
            || self.committee.as_bytes() == &[0; 32]
            || self.owner == NodeId::ZERO
            || self.origin_owner == NodeId::ZERO
            || self.sequence == 0
            || (self.sequence == 1) != self.previous.is_none()
            || self.previous == Some(Hash::ZERO)
            || self.members.is_empty()
        {
            return Err(SharedRecoveryError::InvalidEnvelope);
        }
        for (index, member) in self.members.iter().enumerate() {
            member.validate_scope(self.generation)?;
            if (index == 0) != member.parent().is_none()
                || member.parent().is_some_and(|parent| {
                    !self.members[..index]
                        .iter()
                        .any(|prior| prior.commitment() == parent)
                })
                || self.members[..index]
                    .iter()
                    .any(|prior| prior.work().invocation == member.work().invocation)
            {
                return Err(SharedRecoveryError::Conflict);
            }
        }
        bound(self, MAX_REGISTRATION_REQUEST_BYTES)
    }
}
impl ServiceWire for SharedManagementRecoveryRegistrationRequest {
    const MAGIC: [u8; 4] = *b"MRQ2";
    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut e = Encoder(output);
        e.bytes(&self.generation.encode());
        e.fixed(self.committee.as_bytes());
        e.fixed(&self.owner.0);
        e.fixed(&self.origin_owner.0);
        e.u64(self.sequence);
        e.option(&self.previous, |e, value| e.fixed(&value.0));
        e.list(&self.members, |e, value| e.bytes(&value.encode()));
    }
    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_bound(d, MAX_REGISTRATION_REQUEST_BYTES)?;
        let value = Self {
            generation: nested(
                d,
                super::super::shared_raft::MAX_AGENT_GENERATION_ROUTE_KEY_BYTES,
            )?,
            committee: AgentReplicaCommitteeId::from_bytes(d.fixed()?),
            owner: NodeId(d.fixed()?),
            origin_owner: NodeId(d.fixed()?),
            sequence: d.u64()?,
            previous: d.option(|d| d.fixed().map(Hash))?,
            members: {
                let count = d.u32()? as usize;
                if count > MAX_SHARED_MANAGEMENT_RECOVERY_MEMBERS {
                    return Err(DecodeError::LimitExceeded);
                }
                let mut members = Vec::with_capacity(count);
                for _ in 0..count {
                    members.push(nested(d, MAX_MEMBER_BYTES)?);
                }
                members
            },
        };
        value.validate().map_err(decode_error)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SharedManagementRecoveryRegistration {
    request: SharedManagementRecoveryRegistrationRequest,
    signature: ReplicaCommitSignature,
}
impl SharedManagementRecoveryRegistration {
    pub(crate) fn new(
        request: SharedManagementRecoveryRegistrationRequest,
        signature: ReplicaCommitSignature,
    ) -> Result<Self, SharedRecoveryError> {
        let value = Self { request, signature };
        value.validate()?;
        Ok(value)
    }
    pub(crate) const fn request(&self) -> &SharedManagementRecoveryRegistrationRequest {
        &self.request
    }
    pub(crate) const fn owner(&self) -> NodeId {
        self.request.owner()
    }
    pub(crate) const fn origin_owner(&self) -> NodeId {
        self.request.origin_owner()
    }
    pub(crate) const fn sequence(&self) -> u64 {
        self.request.sequence()
    }
    pub(crate) const fn signature(&self) -> &ReplicaCommitSignature {
        &self.signature
    }
    pub(crate) fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/shared/management-recovery-registration/v1",
            &[&self.encode()],
        )
    }
    pub(crate) fn validate(&self) -> Result<(), SharedRecoveryError> {
        self.request.validate()?;
        validate_owner_signature_shape(self.owner(), &self.signature)?;
        bound(self, MAX_SHARED_MANAGEMENT_RECOVERY_REGISTRATION_BYTES)
    }
    pub(crate) fn verify(
        &self,
        generation: AgentGenerationRouteKey,
        committee: &AgentReplicaCommittee,
    ) -> Result<(), SharedRecoveryError> {
        self.validate()?;
        self.verify_after_validation(generation, committee)
    }

    // Only for this call's exact immutable registration immediately after
    // complete validation. This still checks both owners, voter membership,
    // committee/generation binding and the actual signature.
    fn verify_after_validation(
        &self,
        generation: AgentGenerationRouteKey,
        committee: &AgentReplicaCommittee,
    ) -> Result<(), SharedRecoveryError> {
        validate_request_owner(
            generation,
            committee,
            self.request.generation(),
            self.request.committee(),
            self.origin_owner(),
        )?;
        verify_owner(
            generation,
            committee,
            self.request.generation(),
            self.request.committee(),
            self.owner(),
            self.request.signing_message(),
            &self.signature,
        )
    }
}
impl ServiceWire for SharedManagementRecoveryRegistration {
    const MAGIC: [u8; 4] = *b"MRG1";
    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut e = Encoder(output);
        e.bytes(&self.request.encode());
        e.bytes(&self.signature.encode());
    }
    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_bound(d, MAX_SHARED_MANAGEMENT_RECOVERY_REGISTRATION_BYTES)?;
        Self::new(
            nested(d, MAX_REGISTRATION_REQUEST_BYTES)?,
            nested(
                d,
                super::super::shared_commit::MAX_REPLICA_COMMIT_SIGNATURE_BYTES,
            )?,
        )
        .map_err(decode_error)
    }
}

/// Owner pledge that the exact fully ACKed scope has a durable lifecycle
/// terminal. Construction checks evidence, not the owner's independent WAL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SharedManagementRecoveryReleaseRequest {
    generation: AgentGenerationRouteKey,
    committee: AgentReplicaCommitteeId,
    owner: NodeId,
    sequence: u64,
    scope: Hash,
}
impl SharedManagementRecoveryReleaseRequest {
    pub(crate) fn for_slot(
        slot: &SharedManagementRecoverySlot,
    ) -> Result<Self, SharedRecoveryError> {
        slot.validate()?;
        if slot.is_released() || !slot.all_acknowledged() {
            return Err(SharedRecoveryError::NotAcknowledged);
        }
        Ok(Self {
            generation: slot.registration.request.generation(),
            committee: slot.registration.request.committee(),
            owner: slot.owner(),
            sequence: slot.sequence(),
            scope: slot.commitment(),
        })
    }
    pub(crate) const fn generation(&self) -> AgentGenerationRouteKey {
        self.generation
    }
    pub(crate) const fn committee(&self) -> AgentReplicaCommitteeId {
        self.committee
    }
    pub(crate) const fn owner(&self) -> NodeId {
        self.owner
    }
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub(crate) const fn scope(&self) -> Hash {
        self.scope
    }
    pub(crate) fn signing_message(&self) -> Hash {
        Hash::digest(
            b"vos/agent/shared/management-recovery-release-signature/v1",
            &[&self.encode()],
        )
    }
    fn validate(&self) -> Result<(), SharedRecoveryError> {
        if self.generation.validate().is_err()
            || self.committee.as_bytes() == &[0; 32]
            || self.owner == NodeId::ZERO
            || self.sequence == 0
            || self.scope == Hash::ZERO
        {
            return Err(SharedRecoveryError::InvalidEnvelope);
        }
        Ok(())
    }
}
impl ServiceWire for SharedManagementRecoveryReleaseRequest {
    const MAGIC: [u8; 4] = *b"MLQ1";
    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut e = Encoder(output);
        e.bytes(&self.generation.encode());
        e.fixed(self.committee.as_bytes());
        e.fixed(&self.owner.0);
        e.u64(self.sequence);
        e.fixed(&self.scope.0);
    }
    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_bound(d, MAX_SHARED_MANAGEMENT_RECOVERY_RELEASE_BYTES)?;
        let value = Self {
            generation: nested(
                d,
                super::super::shared_raft::MAX_AGENT_GENERATION_ROUTE_KEY_BYTES,
            )?,
            committee: AgentReplicaCommitteeId::from_bytes(d.fixed()?),
            owner: NodeId(d.fixed()?),
            sequence: d.u64()?,
            scope: Hash(d.fixed()?),
        };
        value.validate().map_err(decode_error)?;
        Ok(value)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SharedManagementRecoveryRelease {
    request: SharedManagementRecoveryReleaseRequest,
    signature: ReplicaCommitSignature,
}
impl SharedManagementRecoveryRelease {
    pub(crate) fn new(
        request: SharedManagementRecoveryReleaseRequest,
        signature: ReplicaCommitSignature,
    ) -> Result<Self, SharedRecoveryError> {
        let value = Self { request, signature };
        value.validate()?;
        Ok(value)
    }
    pub(crate) const fn request(&self) -> &SharedManagementRecoveryReleaseRequest {
        &self.request
    }
    pub(crate) const fn owner(&self) -> NodeId {
        self.request.owner()
    }
    pub(crate) const fn signature(&self) -> &ReplicaCommitSignature {
        &self.signature
    }
    pub(crate) fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/shared/management-recovery-release/v1",
            &[&self.encode()],
        )
    }
    pub(crate) fn validate(&self) -> Result<(), SharedRecoveryError> {
        self.request.validate()?;
        validate_owner_signature_shape(self.owner(), &self.signature)?;
        bound(self, MAX_SHARED_MANAGEMENT_RECOVERY_RELEASE_BYTES)
    }
    pub(crate) fn verify(
        &self,
        generation: AgentGenerationRouteKey,
        committee: &AgentReplicaCommittee,
    ) -> Result<(), SharedRecoveryError> {
        self.validate()?;
        verify_owner(
            generation,
            committee,
            self.request.generation(),
            self.request.committee(),
            self.owner(),
            self.request.signing_message(),
            &self.signature,
        )
    }
}
impl ServiceWire for SharedManagementRecoveryRelease {
    const MAGIC: [u8; 4] = *b"MLR1";
    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut e = Encoder(output);
        e.bytes(&self.request.encode());
        e.bytes(&self.signature.encode());
    }
    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_bound(d, MAX_SHARED_MANAGEMENT_RECOVERY_RELEASE_BYTES)?;
        Self::new(
            nested(d, MAX_SHARED_MANAGEMENT_RECOVERY_RELEASE_BYTES)?,
            nested(
                d,
                super::super::shared_commit::MAX_REPLICA_COMMIT_SIGNATURE_BYTES,
            )?,
        )
        .map_err(decode_error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SharedManagementRecoveryMemberEvidence {
    invoke: Option<SharedRecoveryObservation>,
    acknowledgement: Option<SharedRecoveryObservation>,
}
impl SharedManagementRecoveryMemberEvidence {
    pub(crate) const fn invoke(&self) -> Option<&SharedRecoveryObservation> {
        self.invoke.as_ref()
    }
    pub(crate) const fn acknowledgement(&self) -> Option<&SharedRecoveryObservation> {
        self.acknowledgement.as_ref()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct ReleasePosition {
    release: SharedManagementRecoveryRelease,
    raft_index: u64,
    raft_term: u64,
}

/// One active lifecycle per owner, with a retained signed terminal watermark.
/// Its evidence survives intermediate local member drains without releasing the parent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SharedManagementRecoverySlot {
    registration: SharedManagementRecoveryRegistration,
    raft_index: u64,
    raft_term: u64,
    members_evidence: Vec<SharedManagementRecoveryMemberEvidence>,
    release: Option<ReleasePosition>,
}
impl SharedManagementRecoverySlot {
    pub(crate) const fn registration(&self) -> &SharedManagementRecoveryRegistration {
        &self.registration
    }
    pub(crate) const fn owner(&self) -> NodeId {
        self.registration.owner()
    }
    pub(crate) const fn origin_owner(&self) -> NodeId {
        self.registration.origin_owner()
    }
    pub(crate) const fn sequence(&self) -> u64 {
        self.registration.sequence()
    }
    pub(crate) fn members(&self) -> &[SharedManagementRecoveryMember] {
        self.registration.request.members()
    }
    pub(crate) const fn raft_index(&self) -> u64 {
        self.raft_index
    }
    pub(crate) const fn raft_term(&self) -> u64 {
        self.raft_term
    }
    pub(crate) fn release_raft_index(&self) -> Option<u64> {
        self.release.as_ref().map(|position| position.raft_index)
    }
    pub(crate) fn release_raft_term(&self) -> Option<u64> {
        self.release.as_ref().map(|position| position.raft_term)
    }
    pub(crate) fn matches_input(&self, input: &ReplayInput) -> bool {
        self.registration
            .request
            .members()
            .iter()
            .any(|member| member.matches_input(input))
    }
    pub(crate) fn observations(&self) -> impl Iterator<Item = &SharedRecoveryObservation> {
        self.members_evidence.iter().flat_map(|evidence| {
            [evidence.invoke.as_ref(), evidence.acknowledgement.as_ref()]
                .into_iter()
                .flatten()
        })
    }
    pub(crate) fn members_evidence(&self) -> &[SharedManagementRecoveryMemberEvidence] {
        &self.members_evidence
    }
    pub(crate) fn release(&self) -> Option<&SharedManagementRecoveryRelease> {
        self.release.as_ref().map(|position| &position.release)
    }
    pub(crate) const fn is_released(&self) -> bool {
        self.release.is_some()
    }
    pub(crate) fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/shared/management-recovery-slot/v1",
            &[&self.encode()],
        )
    }
    pub(crate) fn all_acknowledged(&self) -> bool {
        self.members_evidence
            .iter()
            .all(|evidence| evidence.acknowledgement.is_some())
    }
    pub(crate) fn last_position(&self) -> (u64, u64) {
        core::iter::once((self.raft_index, self.raft_term))
            .chain(self.members_evidence.iter().flat_map(|evidence| {
                [&evidence.invoke, &evidence.acknowledgement]
                    .into_iter()
                    .flatten()
                    .map(|observation| (observation.raft_index(), observation.raft_term()))
            }))
            .chain(
                self.release
                    .iter()
                    .map(|position| (position.raft_index, position.raft_term)),
            )
            .max()
            .unwrap_or((0, 0))
    }
    fn commitment_without_release(&self) -> Hash {
        let mut prior = self.clone();
        prior.release = None;
        prior.commitment()
    }
    pub(crate) fn validate(&self) -> Result<(), SharedRecoveryError> {
        self.registration.validate()?;
        if self.raft_index == 0
            || self.raft_term == 0
            || self.members_evidence.len() != self.registration.request.members().len()
        {
            return Err(SharedRecoveryError::InvalidEnvelope);
        }
        for (member, evidence) in self
            .registration
            .request
            .members()
            .iter()
            .zip(&self.members_evidence)
        {
            for observation in [&evidence.invoke, &evidence.acknowledgement]
                .into_iter()
                .flatten()
            {
                observation.validate()?;
                if observation.generation() != self.registration.request.generation()
                    || observation.claim().committee() != self.registration.request.committee()
                    || !member.matches(observation)
                {
                    return Err(SharedRecoveryError::InvalidObservation);
                }
            }
            if evidence
                .invoke
                .as_ref()
                .is_some_and(SharedRecoveryObservation::is_acknowledgement)
                || evidence.acknowledgement.as_ref().is_some_and(|ack| {
                    !ack.is_acknowledgement()
                        || evidence.invoke.as_ref().is_none_or(|invoke| {
                            invoke.raft_index() >= ack.raft_index()
                                || invoke.raft_term() > ack.raft_term()
                        })
                })
            {
                return Err(SharedRecoveryError::InvalidObservation);
            }
        }
        if let Some(position) = &self.release {
            position.release.validate()?;
            let request = position.release.request();
            if !self.all_acknowledged()
                || request.generation() != self.registration.request.generation()
                || request.committee() != self.registration.request.committee()
                || request.owner() != self.owner()
                || request.sequence() != self.sequence()
                || request.scope() != self.commitment_without_release()
                || position.raft_index == 0
                || position.raft_term == 0
                || self
                    .members_evidence
                    .iter()
                    .flat_map(|evidence| {
                        [&evidence.invoke, &evidence.acknowledgement]
                            .into_iter()
                            .flatten()
                    })
                    .any(|evidence| {
                        evidence.raft_index() >= position.raft_index
                            || evidence.raft_term() > position.raft_term
                    })
                || position.raft_index <= self.raft_index
                || position.raft_term < self.raft_term
            {
                return Err(SharedRecoveryError::InvalidObservation);
            }
        }
        bound(self, MAX_SHARED_MANAGEMENT_RECOVERY_SCOPE_BYTES)
    }
    pub(crate) fn validate_at(&self, raft_index: u64) -> Result<(), SharedRecoveryError> {
        self.validate()?;
        if self.last_position().0 > raft_index {
            return Err(SharedRecoveryError::InvalidObservation);
        }
        Ok(())
    }
}
impl ServiceWire for SharedManagementRecoverySlot {
    const MAGIC: [u8; 4] = *b"MRS1";
    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut e = Encoder(output);
        e.bytes(&self.registration.encode());
        e.u64(self.raft_index);
        e.u64(self.raft_term);
        e.list(&self.members_evidence, |e, evidence| {
            e.option(&evidence.invoke, |e, value| e.bytes(&value.encode()));
            e.option(&evidence.acknowledgement, |e, value| {
                e.bytes(&value.encode())
            });
        });
        e.option(&self.release, |e, position| {
            e.bytes(&position.release.encode());
            e.u64(position.raft_index);
            e.u64(position.raft_term);
        });
    }
    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_bound(d, MAX_SHARED_MANAGEMENT_RECOVERY_SCOPE_BYTES)?;
        let value = Self {
            registration: nested(d, MAX_SHARED_MANAGEMENT_RECOVERY_REGISTRATION_BYTES)?,
            raft_index: d.u64()?,
            raft_term: d.u64()?,
            members_evidence: {
                let count = d.u32()? as usize;
                if count > MAX_SHARED_MANAGEMENT_RECOVERY_MEMBERS {
                    return Err(DecodeError::LimitExceeded);
                }
                let mut members = Vec::with_capacity(count);
                for _ in 0..count {
                    members.push(SharedManagementRecoveryMemberEvidence {
                        invoke: d.option(|d| nested(d, MAX_SHARED_RECOVERY_OBSERVATION_BYTES))?,
                        acknowledgement: d
                            .option(|d| nested(d, MAX_SHARED_RECOVERY_OBSERVATION_BYTES))?,
                    });
                }
                members
            },
            release: d.option(|d| {
                Ok(ReleasePosition {
                    release: nested(d, MAX_SHARED_MANAGEMENT_RECOVERY_RELEASE_BYTES)?,
                    raft_index: d.u64()?,
                    raft_term: d.u64()?,
                })
            })?,
        };
        value.validate().map_err(decode_error)?;
        Ok(value)
    }
}

pub(crate) fn validate_management_slots(
    slots: &[SharedManagementRecoverySlot],
    generation: AgentGenerationRouteKey,
    committee: &AgentReplicaCommittee,
) -> Result<(), SharedRecoveryError> {
    validate_scope(generation, committee)?;
    if slots.len() > MAX_SHARED_MANAGEMENT_RECOVERY_SLOTS
        || slots
            .windows(2)
            .any(|pair| pair[0].owner() >= pair[1].owner())
    {
        return Err(SharedRecoveryError::InvalidEnvelope);
    }
    for (index, slot) in slots.iter().enumerate() {
        slot.validate()?;
        slot.registration
            .verify_after_validation(generation, committee)?;
        if let Some(release) = slot.release() {
            release.verify(generation, committee)?;
        }
        for other in &slots[..index] {
            for (member, evidence) in slot
                .registration
                .request
                .members()
                .iter()
                .zip(&slot.members_evidence)
            {
                for (prior, prior_evidence) in other
                    .registration
                    .request
                    .members()
                    .iter()
                    .zip(&other.members_evidence)
                {
                    if member.work().invocation == prior.work().invocation
                        && (member.anchor != prior.anchor
                            || member.envelope != prior.envelope
                            || (member.parent().is_none()
                                && prior.parent().is_none()
                                && slot.origin_owner() != other.origin_owner())
                            || evidence != prior_evidence)
                    {
                        return Err(SharedRecoveryError::Conflict);
                    }
                }
            }
        }
    }
    Ok(())
}
pub(crate) fn management_last_position(slots: &[SharedManagementRecoverySlot]) -> (u64, u64) {
    slots
        .iter()
        .map(SharedManagementRecoverySlot::last_position)
        .max()
        .unwrap_or((0, 0))
}

/// Resolve the first acquiring node from an exact retained root. Released
/// holders remain witnesses until their slot is replaced; another live holder
/// carries the same signed provenance even if the original slot is gone.
/// Absence is only a new acquisition, never evidence about pruned history.
pub(crate) fn management_origin_for_root(
    slots: &[SharedManagementRecoverySlot],
    owner: NodeId,
    root: &SharedManagementRecoveryMember,
) -> Result<NodeId, SharedRecoveryError> {
    root.validate()?;
    if owner == NodeId::ZERO || root.parent().is_some() {
        return Err(SharedRecoveryError::InvalidEnvelope);
    }
    let mut origin = None;
    for slot in slots {
        for prior in slot.members() {
            if prior.work().invocation != root.work().invocation {
                continue;
            }
            // A root cannot be reconstructed from a different anchored request
            // or from another family's dependency with the same invocation ID.
            if prior != root || origin.is_some_and(|value| value != slot.origin_owner()) {
                return Err(SharedRecoveryError::Conflict);
            }
            origin = Some(slot.origin_owner());
        }
    }
    Ok(origin.unwrap_or(owner))
}

/// Pure pre-sign succession and capacity check. It cannot mint a signature,
/// mutate a manifest or establish native lifecycle authorization.
pub(crate) fn validate_management_registration_request(
    slots: &[SharedManagementRecoverySlot],
    generation: AgentGenerationRouteKey,
    committee: &AgentReplicaCommittee,
    request: &SharedManagementRecoveryRegistrationRequest,
) -> Result<(), SharedRecoveryError> {
    validate_management_slots(slots, generation, committee)?;
    request.validate()?;
    validate_request_owner(
        generation,
        committee,
        request.generation(),
        request.committee(),
        request.owner(),
    )?;
    validate_request_owner(
        generation,
        committee,
        request.generation(),
        request.committee(),
        request.origin_owner(),
    )?;
    if slots
        .iter()
        .any(|slot| slot.registration.request() == request)
    {
        return Ok(());
    }
    let evidence = prospective_management_evidence(slots, request)?;
    // Fixed signature envelope and scalar/list tags, plus independently bounded
    // retained observations. No fake signature is constructed for this check.
    let mut bytes = request.encode().len()
        + 36
        + 8
        + super::super::shared_commit::MAX_REPLICA_COMMIT_SIGNATURE_BYTES
        + 36
        + 4
        + 16
        + 4
        + 1;
    for evidence in &evidence {
        bytes = bytes
            .checked_add(2)
            .ok_or(SharedRecoveryError::LimitExceeded)?;
        for observation in [&evidence.invoke, &evidence.acknowledgement]
            .into_iter()
            .flatten()
        {
            bytes = bytes
                .checked_add(4 + observation.encode().len())
                .ok_or(SharedRecoveryError::LimitExceeded)?;
        }
    }
    if bytes > MAX_SHARED_MANAGEMENT_RECOVERY_SCOPE_BYTES {
        return Err(SharedRecoveryError::LimitExceeded);
    }
    Ok(())
}

fn prospective_management_evidence(
    slots: &[SharedManagementRecoverySlot],
    request: &SharedManagementRecoveryRegistrationRequest,
) -> Result<Vec<SharedManagementRecoveryMemberEvidence>, SharedRecoveryError> {
    if request.origin_owner()
        != management_origin_for_root(slots, request.owner(), &request.members()[0])?
    {
        return Err(SharedRecoveryError::Conflict);
    }
    let existing =
        slots.binary_search_by_key(&request.owner(), SharedManagementRecoverySlot::owner);
    let mut evidence = match existing {
        Ok(index) => {
            let previous = &slots[index];
            if previous.sequence().checked_add(1) != Some(request.sequence())
                || request.previous() != Some(previous.commitment())
            {
                return Err(SharedRecoveryError::Sequence);
            }
            if previous.is_released() {
                if request.members().len() != 1 {
                    return Err(SharedRecoveryError::Conflict);
                }
                alloc::vec![SharedManagementRecoveryMemberEvidence {
                    invoke: None,
                    acknowledgement: None
                }]
            } else {
                let old_members = previous.registration.request.members();
                if request.members().len() != old_members.len() + 1
                    || !request.members().starts_with(old_members)
                {
                    return Err(SharedRecoveryError::Conflict);
                }
                let mut evidence = previous.members_evidence.clone();
                evidence.push(SharedManagementRecoveryMemberEvidence {
                    invoke: None,
                    acknowledgement: None,
                });
                evidence
            }
        }
        Err(_) => {
            if request.sequence() != 1
                || request.previous().is_some()
                || request.members().len() != 1
            {
                return Err(SharedRecoveryError::Sequence);
            }
            if slots.len() >= MAX_SHARED_MANAGEMENT_RECOVERY_SLOTS {
                return Err(SharedRecoveryError::LimitExceeded);
            }
            alloc::vec![SharedManagementRecoveryMemberEvidence {
                invoke: None,
                acknowledgement: None
            }]
        }
    };
    // Exact holders inherit only evidence already retained by this replicated
    // manifest. A same-ID substitution is rejected even after another owner
    // released its lifecycle; registration never fabricates a terminal.
    for (member, target) in request.members().iter().zip(&mut evidence) {
        for prior_slot in slots.iter() {
            for (prior, retained) in prior_slot
                .members()
                .iter()
                .zip(prior_slot.members_evidence())
            {
                if member.work().invocation != prior.work().invocation {
                    continue;
                }
                if member.anchor != prior.anchor || member.envelope != prior.envelope {
                    return Err(SharedRecoveryError::Conflict);
                }
                if (target.invoke.is_some() || target.acknowledgement.is_some())
                    && target != retained
                {
                    return Err(SharedRecoveryError::Conflict);
                }
                *target = retained.clone();
            }
        }
    }
    Ok(evidence)
}

pub(crate) fn apply_management_registration(
    slots: &mut Vec<SharedManagementRecoverySlot>,
    generation: AgentGenerationRouteKey,
    committee: &AgentReplicaCommittee,
    registration: &SharedManagementRecoveryRegistration,
    raft_index: u64,
    raft_term: u64,
) -> Result<bool, SharedRecoveryError> {
    validate_management_registration_request(slots, generation, committee, registration.request())?;
    registration.verify(generation, committee)?;
    let existing =
        slots.binary_search_by_key(&registration.owner(), SharedManagementRecoverySlot::owner);
    if existing.is_ok_and(|index| slots[index].registration == *registration) {
        return Ok(false);
    }
    validate_later_position(management_last_position(slots), raft_index, raft_term)?;
    let evidence = prospective_management_evidence(slots, registration.request())?;
    let slot = SharedManagementRecoverySlot {
        registration: registration.clone(),
        raft_index,
        raft_term,
        members_evidence: evidence,
        release: None,
    };
    slot.validate_at(raft_index)?;
    let mut candidate = slots.clone();
    match existing {
        Ok(index) => candidate[index] = slot,
        Err(index) => candidate.insert(index, slot),
    }
    validate_management_slots(&candidate, generation, committee)?;
    *slots = candidate;
    Ok(true)
}

pub(crate) fn validate_management_release_request(
    slots: &[SharedManagementRecoverySlot],
    generation: AgentGenerationRouteKey,
    committee: &AgentReplicaCommittee,
    request: &SharedManagementRecoveryReleaseRequest,
) -> Result<(), SharedRecoveryError> {
    validate_management_slots(slots, generation, committee)?;
    validate_management_release_request_after_slots_validation(
        slots, generation, committee, request,
    )
}

// Only for this same call's immutable slots after full validation, including
// their registration/release signatures. This is the remaining exact request
// check, not custody provenance, signing authority, or permission to skip a
// fresh physical-prefix preflight. The checked wrapper above remains mandatory
// for callers without that dominating validation.
pub(in crate::agent) fn validate_management_release_request_after_slots_validation(
    slots: &[SharedManagementRecoverySlot],
    generation: AgentGenerationRouteKey,
    committee: &AgentReplicaCommittee,
    request: &SharedManagementRecoveryReleaseRequest,
) -> Result<(), SharedRecoveryError> {
    request.validate()?;
    validate_request_owner(
        generation,
        committee,
        request.generation(),
        request.committee(),
        request.owner(),
    )?;
    let slot = slots
        .iter()
        .find(|slot| slot.owner() == request.owner())
        .ok_or(SharedRecoveryError::ScopeMismatch)?;
    if slot
        .release()
        .is_some_and(|release| release.request() == request)
    {
        return Ok(());
    }
    if slot.is_released() || !slot.all_acknowledged() {
        return Err(SharedRecoveryError::NotAcknowledged);
    }
    if request.sequence() != slot.sequence() || request.scope() != slot.commitment() {
        return Err(SharedRecoveryError::Conflict);
    }
    Ok(())
}

pub(crate) fn apply_management_release(
    slots: &mut Vec<SharedManagementRecoverySlot>,
    generation: AgentGenerationRouteKey,
    committee: &AgentReplicaCommittee,
    release: &SharedManagementRecoveryRelease,
    raft_index: u64,
    raft_term: u64,
) -> Result<bool, SharedRecoveryError> {
    validate_management_release_request(slots, generation, committee, release.request())?;
    release.verify(generation, committee)?;
    let index = slots
        .binary_search_by_key(&release.owner(), SharedManagementRecoverySlot::owner)
        .map_err(|_| SharedRecoveryError::ScopeMismatch)?;
    let slot = &slots[index];
    if slot.release() == Some(release) {
        return Ok(false);
    }
    if slot.is_released() || !slot.all_acknowledged() {
        return Err(SharedRecoveryError::NotAcknowledged);
    }
    if release.request.sequence() != slot.sequence() || release.request.scope() != slot.commitment()
    {
        return Err(SharedRecoveryError::Conflict);
    }
    validate_later_position(management_last_position(slots), raft_index, raft_term)?;
    let mut candidate = slots.clone();
    candidate[index].release = Some(ReleasePosition {
        release: release.clone(),
        raft_index,
        raft_term,
    });
    validate_management_slots(&candidate, generation, committee)?;
    *slots = candidate;
    Ok(true)
}

/// Only a physical apply/replay capability may extend retained evidence. Later
/// exact retries are ordinary rows and never overwrite the first observation.
/// Direct test callers retain the checked, atomic wrapper used by the original
/// fold. Production uses only its disposable whole-manifest candidate below.
#[cfg(test)]
pub(crate) fn observe_management(
    slots: &mut Vec<SharedManagementRecoverySlot>,
    verified: &VerifiedSharedRecoveryObservation,
) -> Result<bool, SharedRecoveryError> {
    let observation = verified.observation();
    observation.validate()?;
    let mut candidate = slots.clone();
    let changed = observe_management_candidate(&mut candidate, verified)?;
    for slot in &candidate {
        slot.validate()?;
    }
    if changed {
        validate_later_position(
            management_last_position(slots),
            observation.raft_index(),
            observation.raft_term(),
        )?;
        *slots = candidate;
    }
    Ok(changed)
}

/// Fold only into a disposable candidate owned by SharedRecoveryManifest::observe.
/// That caller validates the immutable incoming observation, validates the
/// complete resulting manifest (including signatures, bounds and contradictions),
/// then checks its global position before publication. Preserve the independent
/// local index/term rule too: a global lexicographic maximum need not carry the
/// same term as the management-only maximum in an invalid candidate.
/// Never use this helper to mutate a published slot collection directly.
pub(super) fn observe_management_candidate(
    slots: &mut [SharedManagementRecoverySlot],
    verified: &VerifiedSharedRecoveryObservation,
) -> Result<bool, SharedRecoveryError> {
    let observation = verified.observation();
    let previous = management_last_position(slots);
    let mut changed = false;
    for slot in slots {
        if slot.registration.request.generation() != observation.generation() {
            continue;
        }
        for (member, evidence) in slot
            .registration
            .request
            .members()
            .iter()
            .zip(&mut slot.members_evidence)
        {
            if !member.matches(observation) {
                continue;
            }
            if observation.claim().committee() != slot.registration.request.committee() {
                return Err(SharedRecoveryError::ScopeMismatch);
            }
            let target = if observation.is_acknowledgement() {
                &mut evidence.acknowledgement
            } else {
                &mut evidence.invoke
            };
            match target {
                Some(prior)
                    if prior != observation
                        && (observation.raft_index() <= prior.raft_index()
                            || observation.raft_term() < prior.raft_term()) =>
                {
                    return Err(SharedRecoveryError::Conflict);
                }
                Some(_) => (),
                None if slot.release.is_some() => return Err(SharedRecoveryError::Conflict),
                None => {
                    *target = Some(observation.clone());
                    changed = true;
                }
            }
        }
    }
    if changed {
        validate_later_position(previous, observation.raft_index(), observation.raft_term())?;
    }
    Ok(changed)
}
fn validate_later_position(
    previous: (u64, u64),
    index: u64,
    term: u64,
) -> Result<(), SharedRecoveryError> {
    if index == 0 || term == 0 || index <= previous.0 || term < previous.1 {
        Err(SharedRecoveryError::InvalidObservation)
    } else {
        Ok(())
    }
}
fn validate_owner_signature_shape(
    owner: NodeId,
    signature: &ReplicaCommitSignature,
) -> Result<(), SharedRecoveryError> {
    if signature.validate().is_err() || signature.signer() != owner {
        Err(SharedRecoveryError::InvalidSignature)
    } else {
        Ok(())
    }
}
fn verify_owner(
    generation: AgentGenerationRouteKey,
    committee: &AgentReplicaCommittee,
    actual_generation: AgentGenerationRouteKey,
    actual_committee: AgentReplicaCommitteeId,
    owner: NodeId,
    message: Hash,
    signature: &ReplicaCommitSignature,
) -> Result<(), SharedRecoveryError> {
    validate_request_owner(
        generation,
        committee,
        actual_generation,
        actual_committee,
        owner,
    )?;
    let member = committee
        .member_by_node(owner)
        .ok_or(SharedRecoveryError::ScopeMismatch)?;
    if !verify_signature(
        member.ed25519_public_key(),
        &message.0,
        signature.signature(),
    ) {
        return Err(SharedRecoveryError::InvalidSignature);
    }
    Ok(())
}
fn validate_request_owner(
    generation: AgentGenerationRouteKey,
    committee: &AgentReplicaCommittee,
    actual_generation: AgentGenerationRouteKey,
    actual_committee: AgentReplicaCommitteeId,
    owner: NodeId,
) -> Result<(), SharedRecoveryError> {
    validate_scope(generation, committee)?;
    if actual_generation != generation || actual_committee != committee.id() {
        return Err(SharedRecoveryError::ScopeMismatch);
    }
    let member = committee
        .member_by_node(owner)
        .ok_or(SharedRecoveryError::ScopeMismatch)?;
    if member.replica().role != ReplicaRole::Voter {
        return Err(SharedRecoveryError::InvalidSignature);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn completed_management_slot_for_test() -> SharedManagementRecoverySlot {
    tests::completed_slot()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn scope() -> SharedRecoveryManifest {
        management_manifest_for_test()
    }
    fn node(owner: u8) -> NodeId {
        management_node_for_test(owner)
    }
    fn key(owner: u8) -> SigningKey {
        SigningKey::from_bytes(&[owner; 32])
    }
    fn member(nonce: u8, parent: Option<Hash>) -> SharedManagementRecoveryMember {
        let template = management_recovery_fixture_for_test(1, nonce);
        let work = template.work().clone();
        let authorization =
            InvocationAuthorization::PublicPreflight(sdk::PublicPreflight::for_work(&work, 10));
        let scope = scope();
        let runtime = super::super::super::shared_commit::common_snapshot_claim_for_test()
            .ordered()
            .runtime()
            .clone();
        SharedManagementRecoveryMember::new(
            parent,
            ManagementJournalAnchor {
                genesis: scope.generation().genesis(),
                admission: scope.generation().admission(),
                runtime: runtime.commitment(),
                ordered: OrderedBase::post_genesis(),
            },
            RuntimeWork::Invoke {
                context: RuntimeExecutionContext::Direct,
                state: RuntimeState::default(),
                invocation: Box::new(work),
                authorization: Box::new(authorization),
                observed_slot: 10,
            },
        )
        .unwrap()
    }
    fn sign_registration(
        owner: u8,
        sequence: u64,
        previous: Option<Hash>,
        members: Vec<SharedManagementRecoveryMember>,
    ) -> SharedManagementRecoveryRegistration {
        sign_registration_from(owner, node(owner), sequence, previous, members)
    }
    fn sign_registration_from(
        owner: u8,
        origin_owner: NodeId,
        sequence: u64,
        previous: Option<Hash>,
        members: Vec<SharedManagementRecoveryMember>,
    ) -> SharedManagementRecoveryRegistration {
        let scope = scope();
        let request = SharedManagementRecoveryRegistrationRequest::new(
            scope.generation(),
            scope.committee().id(),
            node(owner),
            origin_owner,
            sequence,
            previous,
            members,
        )
        .unwrap();
        let signature = ReplicaCommitSignature::new(
            node(owner),
            key(owner).sign(&request.signing_message().0).to_bytes(),
        )
        .unwrap();
        SharedManagementRecoveryRegistration::new(request, signature).unwrap()
    }
    fn sign_release(
        slot: &SharedManagementRecoverySlot,
        owner: u8,
    ) -> SharedManagementRecoveryRelease {
        let request = SharedManagementRecoveryReleaseRequest::for_slot(slot).unwrap();
        let signature = ReplicaCommitSignature::new(
            node(owner),
            key(owner).sign(&request.signing_message().0).to_bytes(),
        )
        .unwrap();
        SharedManagementRecoveryRelease::new(request, signature).unwrap()
    }
    fn observe(
        member: &SharedManagementRecoveryMember,
        index: u64,
        acknowledge: bool,
    ) -> VerifiedSharedRecoveryObservation {
        let common = super::super::super::shared_commit::common_snapshot_claim_for_test();
        let claim = common.ordered().with_raft_foundation(index, 3).unwrap();
        let work = member.work();
        let authorization = member.authorization();
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
                    observed_slot: 10,
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
    fn register(
        slots: &mut Vec<SharedManagementRecoverySlot>,
        registration: &SharedManagementRecoveryRegistration,
        index: u64,
    ) -> Result<bool, SharedRecoveryError> {
        let scope = scope();
        apply_management_registration(
            slots,
            scope.generation(),
            scope.committee(),
            registration,
            index,
            3,
        )
    }
    fn release(
        slots: &mut Vec<SharedManagementRecoverySlot>,
        release: &SharedManagementRecoveryRelease,
        index: u64,
    ) -> Result<bool, SharedRecoveryError> {
        let scope = scope();
        apply_management_release(
            slots,
            scope.generation(),
            scope.committee(),
            release,
            index,
            3,
        )
    }
    pub(super) fn completed_slot() -> SharedManagementRecoverySlot {
        let member = member(10, None);
        let registration = sign_registration(1, 1, None, alloc::vec![member.clone()]);
        let mut slots = Vec::new();
        register(&mut slots, &registration, 1).unwrap();
        observe_management(&mut slots, &observe(&member, 2, false)).unwrap();
        observe_management(&mut slots, &observe(&member, 3, true)).unwrap();
        slots.remove(0)
    }

    #[test]
    fn management_pre_sign_succession_checks_need_no_fabricated_signature() {
        let slot = completed_slot();
        let scope = scope();
        let slots = alloc::vec![slot.clone()];
        let release = SharedManagementRecoveryReleaseRequest::for_slot(&slot).unwrap();
        validate_management_release_request(
            &slots,
            scope.generation(),
            scope.committee(),
            &release,
        )
        .unwrap();
        validate_management_slots(&slots, scope.generation(), scope.committee()).unwrap();
        validate_management_release_request_after_slots_validation(
            &slots,
            scope.generation(),
            scope.committee(),
            &release,
        )
        .unwrap();
        let child = member(11, Some(slot.members()[0].commitment()));
        let extension = SharedManagementRecoveryRegistrationRequest::new(
            scope.generation(),
            scope.committee().id(),
            slot.owner(),
            slot.origin_owner(),
            slot.sequence() + 1,
            Some(slot.commitment()),
            alloc::vec![slot.members()[0].clone(), child],
        )
        .unwrap();
        validate_management_registration_request(
            &slots,
            scope.generation(),
            scope.committee(),
            &extension,
        )
        .unwrap();
        let mut wrong_previous = extension.clone();
        wrong_previous.previous = Some(Hash([0x9e; 32]));
        assert_eq!(
            validate_management_registration_request(
                &slots,
                scope.generation(),
                scope.committee(),
                &wrong_previous
            ),
            Err(SharedRecoveryError::Sequence)
        );
        let mut wrong_scope = release;
        wrong_scope.scope = Hash([0x9e; 32]);
        assert_eq!(
            validate_management_release_request(
                &slots,
                scope.generation(),
                scope.committee(),
                &wrong_scope
            ),
            Err(SharedRecoveryError::Conflict)
        );
        assert_eq!(
            validate_management_release_request_after_slots_validation(
                &slots,
                scope.generation(),
                scope.committee(),
                &wrong_scope,
            ),
            Err(SharedRecoveryError::Conflict)
        );
        assert_eq!(slots, alloc::vec![slot]);
    }

    #[test]
    fn management_manifest_roundtrip_binds_full_scope_and_terminal_in_rmf4() {
        let scope = scope();
        let mut manifest =
            SharedRecoveryManifest::new(scope.generation(), scope.committee().clone()).unwrap();
        assert!(manifest.is_empty());
        assert_eq!(&manifest.encode()[..4], b"RMF4");
        let before = manifest.commitment();
        let member = member(10, None);
        let registration = sign_registration(1, 1, None, alloc::vec![member.clone()]);
        assert!(
            manifest
                .apply_management_registration(&registration, 1, 3)
                .unwrap()
        );
        assert!(manifest.has_pending_management());
        assert!(manifest.observe(&observe(&member, 2, false)).unwrap());
        assert!(manifest.observe(&observe(&member, 3, true)).unwrap());
        let terminal = sign_release(manifest.management_slot(node(1)).unwrap(), 1);
        assert!(manifest.apply_management_release(&terminal, 4, 3).unwrap());
        assert!(!manifest.has_pending_management());
        assert!(!manifest.is_empty(), "terminal watermark is retained");
        let bytes = manifest.encode();
        assert_eq!(&bytes[..4], b"RMF4");
        assert_ne!(manifest.commitment(), before);
        let reopened = SharedRecoveryManifest::decode(&bytes).unwrap();
        assert_eq!(reopened, manifest);
        assert_eq!(
            reopened.management_slot(node(1)).unwrap().release(),
            Some(&terminal)
        );
        reopened.validate_at(4).unwrap();
        assert!(reopened.validate_at(3).is_err());
        for legacy in [*b"RMF1", *b"RMF2", *b"RMF3"] {
            let mut retagged = bytes.clone();
            retagged[..4].copy_from_slice(&legacy);
            assert!(SharedRecoveryManifest::decode(&retagged).is_err());
        }
    }

    #[test]
    fn management_members_refuse_queries_and_observations_without_retention() {
        let scope = scope();
        let anchor = member(10, None).anchor().clone();
        let fixture = management_recovery_fixture_for_test(1, 10);
        let mut query = fixture.work().clone();
        query.mode = sdk::MethodMode::Query;
        let authorization =
            InvocationAuthorization::PublicPreflight(sdk::PublicPreflight::for_work(&query, 10));
        let envelope = RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: RuntimeState::default(),
            invocation: Box::new(query.clone()),
            authorization: Box::new(authorization.clone()),
            observed_slot: 10,
        };
        envelope.encode().unwrap();
        assert_eq!(
            SharedManagementRecoveryMember::new(None, anchor.clone(), envelope),
            Err(SharedRecoveryError::InvalidEnvelope),
        );
        #[cfg(feature = "experimental-state-blocks")]
        {
            let observe = RuntimeWork::Observe {
                context: RuntimeExecutionContext::Direct,
                state: RuntimeState::default(),
                invocation: Box::new(query),
                authorization: Box::new(authorization),
                observed_slot: 10,
            };
            observe.encode().unwrap();
            assert_eq!(
                SharedManagementRecoveryMember::new(None, anchor, observe),
                Err(SharedRecoveryError::InvalidEnvelope),
            );
        }
        assert!(scope.is_empty());
    }

    #[test]
    fn management_registration_preserves_exact_authorization_and_actual_voter_signature() {
        let registration = sign_registration(1, 1, None, alloc::vec![member(10, None)]);
        let scope = scope();
        registration
            .verify(scope.generation(), scope.committee())
            .unwrap();
        registration.validate().unwrap();
        registration
            .verify_after_validation(scope.generation(), scope.committee())
            .unwrap();
        let mut tampered = registration.clone();
        let RuntimeWork::Invoke {
            invocation,
            authorization,
            ..
        } = &mut tampered.request.members[0].envelope
        else {
            unreachable!()
        };
        invocation.gas -= 1;
        **authorization = InvocationAuthorization::PublicPreflight(sdk::PublicPreflight::for_work(
            invocation, 10,
        ));
        assert_eq!(
            tampered.verify(scope.generation(), scope.committee()),
            Err(SharedRecoveryError::InvalidSignature)
        );
        tampered.validate().unwrap();
        assert_eq!(
            tampered.verify_after_validation(scope.generation(), scope.committee()),
            Err(SharedRecoveryError::InvalidSignature)
        );
        let outside = sign_registration(4, 1, None, alloc::vec![member(10, None)]);
        assert_eq!(
            outside.verify(scope.generation(), scope.committee()),
            Err(SharedRecoveryError::ScopeMismatch)
        );
        outside.validate().unwrap();
        assert_eq!(
            outside.verify_after_validation(scope.generation(), scope.committee()),
            Err(SharedRecoveryError::ScopeMismatch)
        );
        let mut wrong_clock = registration.request.members[0].clone();
        let RuntimeWork::Invoke { observed_slot, .. } = &mut wrong_clock.envelope else {
            unreachable!()
        };
        *observed_slot = 11;
        assert_eq!(
            wrong_clock.validate(),
            Err(SharedRecoveryError::InvalidEnvelope)
        );
    }

    #[test]
    fn management_dependency_and_complete_command_bounds_fail_closed() {
        let root = member(10, None);
        let child = member(11, Some(root.commitment()));
        sign_registration(1, 1, None, alloc::vec![root.clone(), child])
            .validate()
            .unwrap();
        let scope = scope();
        assert!(
            SharedManagementRecoveryRegistrationRequest::new(
                scope.generation(),
                scope.committee().id(),
                node(1),
                node(1),
                1,
                None,
                alloc::vec![root.clone(), member(11, Some(Hash([0x88; 32])))]
            )
            .is_err()
        );
        assert!(
            SharedManagementRecoveryRegistrationRequest::new(
                scope.generation(),
                scope.committee().id(),
                node(1),
                node(1),
                1,
                None,
                alloc::vec![root.clone(), member(10, Some(root.commitment()))]
            )
            .is_err()
        );
        let mut chain = alloc::vec![root];
        for nonce in 11..=18 {
            chain.push(member(nonce, Some(chain.last().unwrap().commitment())));
        }
        let mut oversized = sign_registration(1, 1, None, chain[..8].to_vec())
            .request()
            .clone();
        oversized.members = chain.clone();
        assert_eq!(
            SharedManagementRecoveryRegistrationRequest::decode(&oversized.encode()),
            Err(DecodeError::LimitExceeded)
        );
        assert_eq!(
            SharedManagementRecoveryRegistrationRequest::new(
                scope.generation(),
                scope.committee().id(),
                node(1),
                node(1),
                1,
                None,
                chain
            ),
            Err(SharedRecoveryError::LimitExceeded)
        );
        assert!(
            MAX_SHARED_MANAGEMENT_RECOVERY_REGISTRATION_BYTES
                + super::super::super::shared_raft::MAX_AGENT_ROUTE_KEY_BYTES
                + 128
                <= super::super::super::shared_raft::MAX_AGENT_RAFT_COMMAND_BYTES
        );
    }

    #[test]
    fn management_first_invoke_and_positive_ack_are_immutable_on_exact_retries() {
        let member = member(10, None);
        let registration = sign_registration(1, 1, None, alloc::vec![member.clone()]);
        let mut slots = Vec::new();
        assert!(register(&mut slots, &registration, 1).unwrap());
        assert!(!register(&mut slots, &registration, 1).unwrap());
        assert_eq!(
            SharedManagementRecoveryReleaseRequest::for_slot(&slots[0]),
            Err(SharedRecoveryError::NotAcknowledged)
        );
        assert!(observe_management(&mut slots, &observe(&member, 2, false)).unwrap());
        assert!(observe_management(&mut slots, &observe(&member, 3, true)).unwrap());
        let first = slots.clone();
        assert!(!observe_management(&mut slots, &observe(&member, 4, false)).unwrap());
        assert!(!observe_management(&mut slots, &observe(&member, 5, true)).unwrap());
        assert_eq!(slots, first);
        assert!(!slots[0].is_released(), "ACKs are not lifecycle finality");
        assert_eq!(slots[0].observations().count(), 2);
        assert!(slots[0].matches_input(observe(&member, 8, false).observation().input()));
        assert_eq!(slots[0].last_position(), (3, 3));
    }

    #[test]
    fn management_scope_extensions_retain_parent_evidence_until_signed_lifecycle_release() {
        let parent = member(10, None);
        let registration = sign_registration(1, 1, None, alloc::vec![parent.clone()]);
        let mut slots = Vec::new();
        register(&mut slots, &registration, 1).unwrap();
        observe_management(&mut slots, &observe(&parent, 2, false)).unwrap();
        observe_management(&mut slots, &observe(&parent, 3, true)).unwrap();
        let parent_evidence = slots[0].members_evidence()[0].clone();
        let child = member(11, Some(parent.commitment()));
        let extension = sign_registration(
            1,
            2,
            Some(slots[0].commitment()),
            alloc::vec![parent, child.clone()],
        );
        register(&mut slots, &extension, 4).unwrap();
        assert_eq!(slots[0].members_evidence()[0], parent_evidence);
        assert_eq!(
            SharedManagementRecoveryReleaseRequest::for_slot(&slots[0]),
            Err(SharedRecoveryError::NotAcknowledged)
        );
        observe_management(&mut slots, &observe(&child, 5, false)).unwrap();
        observe_management(&mut slots, &observe(&child, 6, true)).unwrap();
        let terminal = sign_release(&slots[0], 1);
        assert!(release(&mut slots, &terminal, 7).unwrap());
        assert!(!release(&mut slots, &terminal, 7).unwrap());
        assert!(slots[0].is_released());
        assert_eq!(slots[0].release(), Some(&terminal));
        assert_eq!(slots[0].release_raft_index(), Some(7));
        assert_eq!(slots[0].observations().count(), 4);
        assert_eq!(slots[0].last_position(), (7, 3));
        let watermark = slots[0].commitment();
        let next = sign_registration(1, 3, Some(watermark), alloc::vec![member(12, None)]);
        register(&mut slots, &next, 8).unwrap();
        assert!(!slots[0].is_released());
        assert!(slots[0].members_evidence()[0].invoke().is_none());
        assert_eq!(slots[0].sequence(), 3);
    }

    #[test]
    fn management_exact_second_holder_inherits_only_existing_physical_evidence() {
        let member = member(10, None);
        let first = sign_registration(1, 1, None, alloc::vec![member.clone()]);
        let mut slots = Vec::new();
        register(&mut slots, &first, 1).unwrap();
        observe_management(&mut slots, &observe(&member, 2, false)).unwrap();
        observe_management(&mut slots, &observe(&member, 3, true)).unwrap();
        let second = sign_registration_from(2, node(1), 1, None, alloc::vec![member.clone()]);
        register(&mut slots, &second, 4).unwrap();
        assert_eq!(slots[0].members_evidence(), slots[1].members_evidence());
        let mut substitution = member;
        substitution.anchor.ordered =
            super::super::super::shared_commit::common_snapshot_claim_for_test()
                .ordered()
                .ordered();
        let substitution = sign_registration(3, 1, None, alloc::vec![substitution]);
        let before = slots.clone();
        assert_eq!(
            register(&mut slots, &substitution, 5),
            Err(SharedRecoveryError::Conflict)
        );
        assert_eq!(slots, before);
    }

    #[test]
    fn management_origin_is_derived_at_first_acquisition_and_shadow_holders_cannot_replace_it() {
        let root = member(10, None);
        let mut slots = Vec::new();
        let invented = sign_registration_from(1, node(2), 1, None, alloc::vec![root.clone()]);
        assert_eq!(
            register(&mut slots, &invented, 1),
            Err(SharedRecoveryError::Conflict)
        );
        assert!(slots.is_empty());
        let first = sign_registration(1, 1, None, alloc::vec![root.clone()]);
        register(&mut slots, &first, 1).unwrap();
        let before = slots.clone();
        let shadow = sign_registration(2, 1, None, alloc::vec![root.clone()]);
        assert_eq!(
            register(&mut slots, &shadow, 2),
            Err(SharedRecoveryError::Conflict)
        );
        assert_eq!(slots, before);
        let inherited = management_origin_for_root(&slots, node(2), &root).unwrap();
        assert_eq!(inherited, node(1));
        let shadow = sign_registration_from(2, inherited, 1, None, alloc::vec![root.clone()]);
        register(&mut slots, &shadow, 2).unwrap();
        assert_eq!(slots.len(), 2);
        assert!(slots.iter().all(|slot| slot.origin_owner() == node(1)));

        // The provenance is signed, not an unsigned sidecar. A signer can sign
        // a different claim, but the transition still refuses to invent it.
        let mut tampered = shadow.clone();
        tampered.request.origin_owner = node(2);
        let scope = scope();
        assert_eq!(
            tampered.verify(scope.generation(), scope.committee()),
            Err(SharedRecoveryError::InvalidSignature)
        );
        let replacement = sign_registration_from(
            1,
            node(2),
            2,
            Some(
                slots
                    .iter()
                    .find(|slot| slot.owner() == node(1))
                    .unwrap()
                    .commitment(),
            ),
            alloc::vec![member(12, None)],
        );
        assert!(
            register(&mut slots, &replacement, 3).is_err(),
            "unfinished roots cannot disappear through replacement"
        );
    }

    #[test]
    fn management_origin_survives_extensions_released_reuse_and_original_holder_replacement() {
        let root = member(10, None);
        let mut slots = Vec::new();
        register(
            &mut slots,
            &sign_registration(1, 1, None, alloc::vec![root.clone()]),
            1,
        )
        .unwrap();
        register(
            &mut slots,
            &sign_registration_from(2, node(1), 1, None, alloc::vec![root.clone()]),
            2,
        )
        .unwrap();
        observe_management(&mut slots, &observe(&root, 3, false)).unwrap();
        observe_management(&mut slots, &observe(&root, 4, true)).unwrap();
        let original = slots
            .iter()
            .find(|slot| slot.owner() == node(1))
            .unwrap()
            .clone();
        release(&mut slots, &sign_release(&original, 1), 5).unwrap();
        let released = slots
            .iter()
            .find(|slot| slot.owner() == node(1))
            .unwrap()
            .clone();
        // Released slots are still provenance witnesses until replaced.
        assert_eq!(
            management_origin_for_root(&slots, node(3), &root).unwrap(),
            node(1)
        );
        register(
            &mut slots,
            &sign_registration(
                1,
                2,
                Some(released.commitment()),
                alloc::vec![member(12, None)],
            ),
            6,
        )
        .unwrap();
        assert!(
            slots
                .iter()
                .find(|slot| slot.owner() == node(1))
                .unwrap()
                .members()[0]
                != root
        );

        // The surviving exact shadow retains the original node after that
        // node's entire slot is replaced by an unrelated, fresh lifecycle.
        assert_eq!(
            management_origin_for_root(&slots, node(3), &root).unwrap(),
            node(1)
        );
        register(
            &mut slots,
            &sign_registration_from(3, node(1), 1, None, alloc::vec![root.clone()]),
            7,
        )
        .unwrap();
        let shadow = slots
            .iter()
            .find(|slot| slot.owner() == node(2))
            .unwrap()
            .clone();
        let child = member(11, Some(root.commitment()));
        let before = slots.clone();
        let substituted = sign_registration(
            2,
            2,
            Some(shadow.commitment()),
            alloc::vec![root.clone(), child.clone()],
        );
        assert_eq!(
            register(&mut slots, &substituted, 8),
            Err(SharedRecoveryError::Conflict)
        );
        assert_eq!(slots, before);
        let extension = sign_registration_from(
            2,
            node(1),
            2,
            Some(shadow.commitment()),
            alloc::vec![root.clone(), child.clone()],
        );
        register(&mut slots, &extension, 8).unwrap();
        observe_management(&mut slots, &observe(&child, 9, false)).unwrap();
        observe_management(&mut slots, &observe(&child, 10, true)).unwrap();
        let extended = slots
            .iter()
            .find(|slot| slot.owner() == node(2))
            .unwrap()
            .clone();
        release(&mut slots, &sign_release(&extended, 2), 11).unwrap();
        let released = slots
            .iter()
            .find(|slot| slot.owner() == node(2))
            .unwrap()
            .clone();
        // Reacquiring the same released root still is not a new origin.
        let wrong_reuse =
            sign_registration(2, 3, Some(released.commitment()), alloc::vec![root.clone()]);
        assert_eq!(
            register(&mut slots, &wrong_reuse, 12),
            Err(SharedRecoveryError::Conflict)
        );
        let reused = sign_registration_from(
            2,
            node(1),
            3,
            Some(released.commitment()),
            alloc::vec![root.clone()],
        );
        register(&mut slots, &reused, 12).unwrap();
        let reused = slots
            .iter()
            .find(|slot| slot.owner() == node(2))
            .unwrap()
            .clone();
        release(&mut slots, &sign_release(&reused, 2), 13).unwrap();
        let released = slots
            .iter()
            .find(|slot| slot.owner() == node(2))
            .unwrap()
            .clone();
        register(
            &mut slots,
            &sign_registration(
                2,
                4,
                Some(released.commitment()),
                alloc::vec![member(13, None)],
            ),
            14,
        )
        .unwrap();
        assert_eq!(
            management_origin_for_root(&slots, node(1), &root).unwrap(),
            node(1)
        );
        assert_eq!(
            slots
                .iter()
                .find(|slot| slot.owner() == node(3))
                .unwrap()
                .origin_owner(),
            node(1)
        );
    }

    #[test]
    fn management_origin_is_bound_by_nested_wire_export_and_replayed_registration() {
        let scope = scope();
        let root = member(10, None);
        let first = sign_registration(1, 1, None, alloc::vec![root.clone()]);
        let shadow = sign_registration_from(2, node(1), 1, None, alloc::vec![root]);
        let mut live =
            SharedRecoveryManifest::new(scope.generation(), scope.committee().clone()).unwrap();
        let mut replayed = live.clone();
        for (offset, registration) in [&first, &shadow].into_iter().enumerate() {
            live.apply_management_registration(registration, offset as u64 + 1, 3)
                .unwrap();
            let wire = registration.encode();
            let decoded = SharedManagementRecoveryRegistration::decode(&wire).unwrap();
            assert_eq!(decoded.origin_owner(), node(1));
            replayed
                .apply_management_registration(&decoded, offset as u64 + 1, 3)
                .unwrap();
            assert_eq!(&registration.request().encode()[..4], b"MRQ2");
            let mut old = registration.request().encode();
            old[..4].copy_from_slice(b"MRQ1");
            assert!(SharedManagementRecoveryRegistrationRequest::decode(&old).is_err());
            let mut old_wrapper = wire;
            // The outer unchanged MRG1 must enforce its nested MRQ2 tag too.
            let nested_request = 4 + crate::service::PLATFORM_ID.0.len() + 4;
            old_wrapper[nested_request..nested_request + 4].copy_from_slice(b"MRQ1");
            assert!(SharedManagementRecoveryRegistration::decode(&old_wrapper).is_err());
        }
        assert_eq!(replayed, live);
        let exported = live.encode();
        let reopened = SharedRecoveryManifest::decode(&exported).unwrap();
        assert_eq!(reopened, live);
        assert_eq!(
            reopened
                .management_origin_for_root(node(3), &first.request().members()[0])
                .unwrap(),
            node(1)
        );
        let mut substituted = reopened.clone();
        let slot = substituted
            .management
            .iter_mut()
            .find(|slot| slot.owner() == node(2))
            .unwrap();
        slot.registration = sign_registration(2, 1, None, slot.members().to_vec());
        assert!(
            SharedRecoveryManifest::decode(&substituted.encode()).is_err(),
            "even a genuine current-holder signature cannot change family provenance"
        );
    }

    #[test]
    fn management_stale_replacement_or_release_refusal_never_changes_retention() {
        let parent = member(10, None);
        let mut slots = Vec::new();
        let initial = sign_registration(1, 1, None, alloc::vec![parent.clone()]);
        register(&mut slots, &initial, 1).unwrap();
        observe_management(&mut slots, &observe(&parent, 2, false)).unwrap();
        observe_management(&mut slots, &observe(&parent, 3, true)).unwrap();
        let terminal = sign_release(&slots[0], 1);
        let child = member(11, Some(parent.commitment()));
        let extension = sign_registration(
            1,
            2,
            Some(slots[0].commitment()),
            alloc::vec![parent, child],
        );
        register(&mut slots, &extension, 4).unwrap();
        let before = slots.clone();
        assert!(release(&mut slots, &terminal, 5).is_err());
        let stale = sign_registration(
            1,
            2,
            Some(initial.commitment()),
            alloc::vec![member(12, None)],
        );
        assert_eq!(
            register(&mut slots, &stale, 5),
            Err(SharedRecoveryError::Sequence)
        );
        assert_eq!(slots, before);
        assert!(slots[0].validate_at(3).is_err());
    }

    #[test]
    fn management_terminal_wire_retains_release_and_refuses_truncated_or_trailing_bytes() {
        let member = member(10, None);
        let registration = sign_registration(1, 1, None, alloc::vec![member.clone()]);
        let mut slots = Vec::new();
        register(&mut slots, &registration, 1).unwrap();
        observe_management(&mut slots, &observe(&member, 2, false)).unwrap();
        observe_management(&mut slots, &observe(&member, 3, true)).unwrap();
        let terminal = sign_release(&slots[0], 1);
        release(&mut slots, &terminal, 4).unwrap();
        assert_eq!(
            SharedManagementRecoveryRegistration::decode(&registration.encode()).unwrap(),
            registration
        );
        assert_eq!(
            SharedManagementRecoveryRelease::decode(&terminal.encode()).unwrap(),
            terminal
        );
        let bytes = slots[0].encode();
        assert_eq!(
            SharedManagementRecoverySlot::decode(&bytes).unwrap(),
            slots[0]
        );
        for end in [0, 4, 36, bytes.len() - 1] {
            assert!(SharedManagementRecoverySlot::decode(&bytes[..end]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            SharedManagementRecoverySlot::decode(&trailing),
            Err(DecodeError::TrailingBytes)
        );
        assert_eq!(management_last_position(&slots), (4, 3));
    }

    #[test]
    fn retained_management_serialization_is_byte_exact_but_never_admits_forged_preimages() {
        for length in [1, 64 * 1024, sdk::MAX_RUNTIME_AVAILABILITY_BYTES] {
            let mut retained = member(46, None);
            let RuntimeWork::Invoke {
                invocation,
                authorization,
                observed_slot,
                ..
            } = &mut retained.envelope
            else {
                unreachable!()
            };
            let bytes = alloc::vec![0x5a; length];
            invocation.availability = alloc::vec![sdk::RuntimeBlob {
                reference: sdk::BlobRef::of_bytes(&bytes),
                bytes,
            }];
            **authorization = InvocationAuthorization::PublicPreflight(
                sdk::PublicPreflight::for_work(invocation, *observed_slot),
            );
            retained.validate().unwrap();
            let checked = retained.envelope.encode().unwrap();
            assert_eq!(
                encode_retained_envelope(&retained.envelope).unwrap(),
                checked
            );
            let mut expected = Vec::new();
            expected.extend_from_slice(&SharedManagementRecoveryMember::MAGIC);
            expected.extend_from_slice(&crate::service::PLATFORM_ID.0);
            let mut e = Encoder(&mut expected);
            e.option(&retained.parent, |e, value| e.fixed(&value.0));
            e.bytes(&retained.anchor.encode());
            e.bytes(&checked);
            assert_eq!(retained.encode(), expected);
            assert!(expected.len() <= MAX_MEMBER_BYTES);
            assert_eq!(
                SharedManagementRecoveryMember::decode(&expected).unwrap(),
                retained
            );

            let mut forged = retained.clone();
            let RuntimeWork::Invoke { invocation, .. } = &mut forged.envelope else {
                unreachable!()
            };
            invocation.availability[0].bytes[0] ^= 1;
            assert!(forged.envelope.encode().is_err());
            assert!(encode_retained_envelope(&forged.envelope).is_ok());
            assert_eq!(forged.validate(), Err(SharedRecoveryError::InvalidEnvelope));
            assert!(SharedManagementRecoveryMember::decode(&forged.encode()).is_err());
            let mut forged_manifest = candidate_manifest(&retained);
            forged_manifest.management[0].registration.request.members[0] = forged.clone();
            assert_eq!(
                forged_manifest.validate(),
                Err(SharedRecoveryError::InvalidEnvelope)
            );
            assert!(SharedRecoveryManifest::decode(&forged_manifest.encode()).is_err());
            let forged_registration = forged_manifest.management[0].registration();
            assert_eq!(
                forged_registration
                    .verify(forged_manifest.generation(), forged_manifest.committee(),),
                Err(SharedRecoveryError::InvalidEnvelope)
            );
            assert_eq!(
                SharedManagementRecoveryMember::new(forged.parent, forged.anchor, forged.envelope,),
                Err(SharedRecoveryError::InvalidEnvelope)
            );
        }
    }

    #[test]
    fn management_unmatched_clock_or_nonpositive_ack_is_never_custody_evidence() {
        let member = member(10, None);
        let registration = sign_registration(1, 1, None, alloc::vec![member.clone()]);
        let mut slots = Vec::new();
        register(&mut slots, &registration, 1).unwrap();
        let mut wrong_clock = observe(&member, 2, false).observation().clone();
        let ReplayOperation::CleanInvoke {
            work,
            authorization,
            observed_slot,
            ..
        } = &mut wrong_clock.input.operation
        else {
            unreachable!()
        };
        *observed_slot = 11;
        *authorization =
            InvocationAuthorization::PublicPreflight(sdk::PublicPreflight::for_work(work, 11));
        let wrong_clock =
            VerifiedSharedRecoveryObservation::from_audited_record(wrong_clock).unwrap();
        assert!(!observe_management(&mut slots, &wrong_clock).unwrap());
        assert!(slots[0].members_evidence()[0].invoke().is_none());
        observe_management(&mut slots, &observe(&member, 2, false)).unwrap();
        let mut wrong_ack = observe(&member, 3, true).observation().clone();
        let RuntimeOutcome::Acknowledged(Ok(ack)) = &mut wrong_ack.outcome else {
            unreachable!()
        };
        ack.authorization = sdk::Hash([0x91; 32]);
        assert!(VerifiedSharedRecoveryObservation::from_audited_record(wrong_ack).is_err());
        let mut negative_ack = observe(&member, 3, true).observation().clone();
        negative_ack.outcome = RuntimeOutcome::Acknowledged(Err(sdk::InvocationError::NotFound));
        assert!(VerifiedSharedRecoveryObservation::from_audited_record(negative_ack).is_err());
        assert!(slots[0].members_evidence()[0].acknowledgement().is_none());
        let scope = scope();
        let mut request =
            SharedManagementRecoveryReleaseRequest::for_slot(&completed_slot()).unwrap();
        request.scope = slots[0].commitment();
        validate_management_slots(&slots, scope.generation(), scope.committee()).unwrap();
        assert_eq!(
            validate_management_release_request_after_slots_validation(
                &slots,
                scope.generation(),
                scope.committee(),
                &request,
            ),
            Err(SharedRecoveryError::NotAcknowledged)
        );
        assert_eq!(
            validate_management_release_request(
                &slots,
                scope.generation(),
                scope.committee(),
                &request,
            ),
            Err(SharedRecoveryError::NotAcknowledged)
        );
    }

    fn candidate_manifest(member: &SharedManagementRecoveryMember) -> SharedRecoveryManifest {
        let template = scope();
        let mut manifest =
            SharedRecoveryManifest::new(template.generation(), template.committee().clone())
                .unwrap();
        let registration = sign_registration(1, 1, None, alloc::vec![member.clone()]);
        manifest
            .apply_management_registration(&registration, 1, 3)
            .unwrap();
        manifest
    }

    #[test]
    fn management_candidate_fold_matches_checked_wrapper_and_keeps_first_capsules() {
        let member = member(40, None);
        let mut manifest = candidate_manifest(&member);
        let mut checked = manifest.management.clone();
        for (index, acknowledgement) in [(2, false), (3, true), (4, false), (5, true)] {
            let observation = observe(&member, index, acknowledgement);
            let expected = observe_management(&mut checked, &observation);
            assert_eq!(manifest.observe(&observation), expected);
            assert_eq!(manifest.management, checked);
            manifest.validate_at(index).unwrap();
        }
        let first = manifest.management[0].members_evidence.clone();
        let terminal = sign_release(&manifest.management[0], 1);
        manifest.apply_management_release(&terminal, 6, 3).unwrap();
        checked = manifest.management.clone();
        for (index, acknowledgement) in [(7, false), (8, true)] {
            let observation = observe(&member, index, acknowledgement);
            assert_eq!(manifest.observe(&observation), Ok(false));
            assert_eq!(observe_management(&mut checked, &observation), Ok(false));
            assert_eq!(manifest.management, checked);
            assert_eq!(manifest.management[0].members_evidence, first);
        }
        assert!(manifest.management[0].is_released());
        manifest.validate_at(6).unwrap();
    }

    #[test]
    fn management_candidate_fold_still_checks_final_contradictions_signatures_and_bounds() {
        let member = member(41, None);
        let mut manifest = candidate_manifest(&member);
        manifest.observe(&observe(&member, 2, false)).unwrap();
        let shadow = sign_registration_from(2, node(1), 1, None, alloc::vec![member.clone()]);
        manifest
            .apply_management_registration(&shadow, 3, 3)
            .unwrap();
        let valid = manifest.clone();
        let mut conflicting = observe(&member, 2, false).observation().clone();
        let RuntimeOutcome::Completed(Ok(reply)) = &mut conflicting.outcome else {
            unreachable!()
        };
        reply.reply.push(0xa5);
        conflicting.validate().unwrap();
        manifest.management[1].members_evidence[0].invoke = Some(conflicting);
        let before = manifest.encode();
        assert_eq!(
            manifest.observe(&observe(&member, 4, true)),
            Err(SharedRecoveryError::Conflict),
        );
        assert_eq!(manifest.encode(), before);

        let mut unsigned = valid.clone();
        let signing_message = unsigned.management[0]
            .registration
            .request
            .signing_message();
        unsigned.management[0].registration.signature =
            ReplicaCommitSignature::new(node(1), key(2).sign(&signing_message.0).to_bytes())
                .unwrap();
        let before = unsigned.encode();
        assert_eq!(
            unsigned.observe(&observe(&member, 4, true)),
            Err(SharedRecoveryError::InvalidSignature),
        );
        assert_eq!(unsigned.encode(), before);

        let mut oversized = valid;
        let RuntimeWork::Invoke { invocation, .. } =
            &mut oversized.management[0].registration.request.members[0].envelope
        else {
            unreachable!()
        };
        invocation
            .message
            .resize(sdk::MAX_INVOCATION_MESSAGE_BYTES + 1, 0);
        let before = oversized.clone();
        assert_eq!(
            oversized.observe(&observe(&member, 4, true)),
            Err(SharedRecoveryError::InvalidEnvelope),
        );
        assert_eq!(oversized, before);
    }

    #[test]
    fn management_candidate_fold_refuses_early_ack_and_position_without_publication() {
        let member = member(42, None);
        let mut manifest = candidate_manifest(&member);
        let before = manifest.clone();
        assert_eq!(
            manifest.observe(&observe(&member, 2, true)),
            Err(SharedRecoveryError::InvalidObservation),
        );
        assert_eq!(manifest, before);
        assert_eq!(
            manifest.observe(&observe(&member, 1, false)),
            Err(SharedRecoveryError::InvalidObservation),
        );
        assert_eq!(manifest, before);

        manifest.observe(&observe(&member, 2, false)).unwrap();
        let before = manifest.clone();
        let mut lower_term = observe(&member, 3, true).observation().clone();
        lower_term.raft_term = 2;
        lower_term.claim = lower_term.claim.with_raft_foundation(3, 2).unwrap();
        let lower_term =
            VerifiedSharedRecoveryObservation::from_audited_record(lower_term).unwrap();
        assert_eq!(
            manifest.observe(&lower_term),
            Err(SharedRecoveryError::InvalidObservation),
        );
        assert_eq!(manifest, before);
        let mut changed_first = observe(&member, 2, false).observation().clone();
        let RuntimeOutcome::Completed(Ok(reply)) = &mut changed_first.outcome else {
            unreachable!()
        };
        reply.reply.push(0x5a);
        let changed_first =
            VerifiedSharedRecoveryObservation::from_audited_record(changed_first).unwrap();
        assert_eq!(
            manifest.observe(&changed_first),
            Err(SharedRecoveryError::Conflict),
        );
        assert_eq!(manifest, before);
    }

    #[test]
    fn management_candidate_validate_at_keeps_root_invoke_ack_release_and_signature_bounds() {
        let member = member(43, None);
        let mut manifest = candidate_manifest(&member);
        let assert_decoded_bounds = |manifest: &SharedRecoveryManifest, last: u64| {
            let decoded = SharedRecoveryManifest::decode(&manifest.encode()).unwrap();
            for at in 0..=last {
                assert_eq!(
                    decoded.validate_positions_after_validation(at),
                    manifest.validate_at(at)
                );
            }
        };
        assert_decoded_bounds(&manifest, 1);
        assert_eq!(
            manifest.validate_at(0),
            Err(SharedRecoveryError::InvalidObservation)
        );
        manifest.validate_at(1).unwrap();
        manifest.observe(&observe(&member, 2, false)).unwrap();
        assert_decoded_bounds(&manifest, 2);
        assert_eq!(
            manifest.validate_at(1),
            Err(SharedRecoveryError::InvalidObservation)
        );
        manifest.validate_at(2).unwrap();
        manifest.observe(&observe(&member, 3, true)).unwrap();
        assert_decoded_bounds(&manifest, 3);
        assert_eq!(
            manifest.validate_at(2),
            Err(SharedRecoveryError::InvalidObservation)
        );
        manifest.validate_at(3).unwrap();
        let terminal = sign_release(&manifest.management[0], 1);
        manifest.apply_management_release(&terminal, 4, 3).unwrap();
        assert_decoded_bounds(&manifest, 4);
        assert_eq!(
            manifest.validate_at(3),
            Err(SharedRecoveryError::InvalidObservation)
        );
        manifest.validate_at(4).unwrap();
        let signing_message = manifest.management[0]
            .release
            .as_ref()
            .unwrap()
            .release
            .request
            .signing_message();
        manifest.management[0]
            .release
            .as_mut()
            .unwrap()
            .release
            .signature =
            ReplicaCommitSignature::new(node(1), key(2).sign(&signing_message.0).to_bytes())
                .unwrap();
        assert_eq!(
            manifest.validate_at(u64::MAX),
            Err(SharedRecoveryError::InvalidSignature)
        );
        assert!(SharedRecoveryManifest::decode(&manifest.encode()).is_err());
    }
}
