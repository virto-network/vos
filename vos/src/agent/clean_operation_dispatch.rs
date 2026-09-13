//! Native physical execution boundary for retained Authority operation work.
//! The caller must persist the complete envelope and its journal anchor before
//! execution, and retain admission until coordinator/issuer recovery retires it.

use super::*;
#[path = "clean_operation_completion.rs"]
mod completion;
#[path = "clean_operation_denial.rs"]
mod denial;
#[path = "clean_operation_retirement.rs"]
mod retirement;
use crate::agent::authority_operation_coordinator::{
    AuthorityOperationActorDispatch, AuthorityOperationActorDispatcher,
    AuthorityOperationActorMethod, AuthorityOperationActorResult,
};
use crate::agent::clean_management_intent::ManagementJournalAnchor;
use crate::agent::sdk::authority_operation::{
    AuthorityOperationApproval, AuthorityOperationCall, AuthorityOperationIssuanceAck,
    MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES, MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES,
};
pub(crate) use completion::RetainedNativeOperationCompletion;
pub use completion::{
    MAX_NATIVE_OPERATION_COMPLETION_BYTES, NativeAuthorityOperationCompletionSigner,
    native_operation_completion_invocations,
};
pub use retirement::{
    MAX_NATIVE_OPERATION_RETIREMENT_BYTES, NativeAuthorityOperationRetirementSigner,
    NativeAuthorityOperationRetirementStore, native_operation_retirement_completion,
};

const MAX_DISPATCH_REQUEST_BYTES: usize =
    if MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES > MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES {
        MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES
    } else {
        MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES
    };
const MAX_DISPATCH_ANCHOR_BYTES: usize = 1024;

pub const MAX_NATIVE_AUTHORITY_OPERATION_DISPATCH_BYTES: usize =
    RetainedAuthorityOperationDispatch::MAX_ENCODED_BYTES;

/// Check immutable file-key and Authority binding, not native journal finality.
pub fn native_operation_record_matches(
    authority: AuthorityActorTarget,
    invocation: InvocationId,
    bytes: &[u8],
) -> bool {
    RetainedAuthorityOperationDispatch::decode(bytes).is_ok_and(|record| {
        record.request.target == authority
            && record.request.context.invocation == invocation
            && record.encode().ok().as_deref() == Some(bytes)
    })
}

/// Immutable per-invocation native dispatch records under one writer lease.
/// Successful retention means the exact bytes survive restart. Repeated exact
/// retention is allowed; replacing different bytes or discarding predecessors
/// is not. Readers must enforce the record byte ceiling before allocating.
pub trait NativeAuthorityOperationJournalStore {
    type Error;

    fn load(&mut self, invocation: InvocationId) -> Result<Option<Vec<u8>>, Self::Error>;
    fn retain(&mut self, invocation: InvocationId, record: &[u8]) -> Result<(), Self::Error>;
}

/// Exact admission loaded while the journal and certificate leases are held.
/// Signed terminal records may exclude retired pairs; every remaining native
/// anchor is independently authenticated before exposing the recovered route.
pub struct NativeAuthorityOperationStartupAdmission<'a> {
    pub(super) authority: AuthorityActorTarget,
    pub(super) pending: Vec<(ManagementJournalAnchor, RuntimeWork)>,
    pub(super) retirements: Vec<[RuntimeWork; 2]>,
    pub(super) has_history: bool,
    _lease: core::marker::PhantomData<&'a mut ()>,
}

impl<'a> NativeAuthorityOperationStartupAdmission<'a> {
    /// Supply the complete bounded discovery set, including initial stages.
    /// Missing or duplicate records are errors, never empty recovery state.
    pub fn load<J: NativeAuthorityOperationJournalStore>(
        journal: &'a mut J,
        authority: AuthorityActorTarget,
        invocations: &[InvocationId],
    ) -> Result<Self, SharedAgentHostError> {
        Self::load_with_completions(journal, authority, invocations, &[])
    }

    pub(super) fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.retirements.is_empty()
    }

    /// Signed continuations classify exact pairs as retiring, never released.
    /// The caller must retain the completion store's lease alongside the journal.
    pub fn load_with_completions<J: NativeAuthorityOperationJournalStore>(
        journal: &'a mut J,
        authority: AuthorityActorTarget,
        invocations: &[InvocationId],
        certificates: &[Vec<u8>],
    ) -> Result<Self, SharedAgentHostError> {
        Self::load_with_retirements(journal, authority, invocations, certificates, &[])
    }

    /// Terminal certificates remove only their exact verified pairs from
    /// admission. All three backing stores must remain exclusively leased.
    pub fn load_with_retirements<J: NativeAuthorityOperationJournalStore>(
        journal: &'a mut J,
        authority: AuthorityActorTarget,
        invocations: &[InvocationId],
        certificates: &[Vec<u8>],
        terminal_certificates: &[Vec<u8>],
    ) -> Result<Self, SharedAgentHostError> {
        let maximum = 2 * crate::agent::authority_operation_coordinator::MAX_AUTHORITY_OPERATION_COORDINATOR_RECORDS;
        if !authority.is_valid()
            || invocations.len() > maximum
            || certificates.len() > maximum / 2
            || terminal_certificates.len() > maximum / 2
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let mut records = std::collections::BTreeMap::new();
        for &invocation in invocations {
            if invocation == InvocationId::ZERO || records.contains_key(&invocation) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            let bytes = journal
                .load(invocation)
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .ok_or(SharedAgentHostError::Unavailable)?;
            if !native_operation_record_matches(authority, invocation, &bytes) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            let record = RetainedAuthorityOperationDispatch::decode(&bytes)
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            records.insert(invocation, record);
        }
        for record in records.values() {
            if record.request.method == AuthorityOperationActorMethod::AcknowledgeIssuance {
                let ack = AuthorityOperationIssuanceAck::decode(&record.request.request)
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                let predecessor = records
                    .get(&ack.authorization_invocation)
                    .ok_or(SharedAgentHostError::ScopeMismatch)?;
                if predecessor.request.method != AuthorityOperationActorMethod::AuthorizeOperation {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                let call = AuthorityOperationCall::decode(&predecessor.request.request)
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                if ack.operation_call != call.commitment()
                    || ack.issued_at < predecessor.request.context.observed_slot
                {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
            }
        }
        let mut retired = std::collections::BTreeSet::new();
        for certificate in terminal_certificates {
            let completion =
                native_operation_retirement_completion(&authority.binding.public_key, certificate)
                    .ok_or(SharedAgentHostError::ScopeMismatch)?;
            if !certificates.contains(&completion) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            let [authorization, acknowledgement] = completion::completion_invocations(&completion)?;
            if !retired.insert(authorization) || !retired.insert(acknowledgement) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            retirement::restore_retirement(
                authority,
                records
                    .get(&authorization)
                    .ok_or(SharedAgentHostError::ScopeMismatch)?,
                records
                    .get(&acknowledgement)
                    .ok_or(SharedAgentHostError::ScopeMismatch)?,
                certificate,
            )?;
        }
        let mut retiring = std::collections::BTreeSet::new();
        let mut retirements = Vec::new();
        for certificate in certificates {
            let [authorization, acknowledgement] = completion::completion_invocations(certificate)?;
            if !retiring.insert(authorization) || !retiring.insert(acknowledgement) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            let authorization = records
                .get(&authorization)
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            let acknowledgement = records
                .get(&acknowledgement)
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            completion::restore_completion(authority, authorization, acknowledgement, certificate)?;
            if !retired.contains(&authorization.request.context.invocation) {
                retirements.push([
                    authorization.envelope.clone(),
                    acknowledgement.envelope.clone(),
                ]);
            }
        }
        Ok(Self {
            authority,
            has_history: !records.is_empty(),
            pending: records
                .into_values()
                .filter(|record| !retiring.contains(&record.request.context.invocation))
                .map(|record| (record.anchor, record.envelope))
                .collect(),
            retirements,
            _lease: core::marker::PhantomData,
        })
    }
}

/// Trusted coordinator adapter: all successful replies come from physical
/// execution/replay, never from cached unsigned approval bytes. Authorization
/// is captured durably by the coordinator's pre-pledge retention hook.
pub(crate) struct NativeAuthorityOperationDispatcher<'a, P, R, I, J>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
    J: NativeAuthorityOperationJournalStore,
{
    owner: &'a mut CleanSystemAgentBootstrapOwner<P, R, I>,
    journal: &'a mut J,
}

impl<'a, P, R, I, J> NativeAuthorityOperationDispatcher<'a, P, R, I, J>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
    J: NativeAuthorityOperationJournalStore,
{
    pub(crate) fn new(
        owner: &'a mut CleanSystemAgentBootstrapOwner<P, R, I>,
        journal: &'a mut J,
    ) -> Self {
        Self { owner, journal }
    }

    fn retained(
        &mut self,
        invocation: InvocationId,
    ) -> Result<Option<RetainedAuthorityOperationDispatch>, SharedAgentHostError> {
        self.journal
            .load(invocation)
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .map(|bytes| {
                let record = RetainedAuthorityOperationDispatch::decode(&bytes)
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                if record.request.context.invocation != invocation
                    || record.request.target != self.owner.authority_target()
                    || record.encode().ok().as_deref() != Some(bytes.as_slice())
                {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                Ok(record)
            })
            .transpose()
    }
}

impl<P, R, I, J> AuthorityOperationActorDispatcher
    for NativeAuthorityOperationDispatcher<'_, P, R, I, J>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
    J: NativeAuthorityOperationJournalStore,
{
    type Error = SharedAgentHostError;

    fn retain_authorization(
        &mut self,
        request: &AuthorityOperationActorDispatch,
    ) -> Result<(), Self::Error> {
        if request.method != AuthorityOperationActorMethod::AuthorizeOperation
            || request.target != self.owner.authority_target()
            || !request.has_valid_request()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if let Some(retained) = self.retained(request.context.invocation)? {
            return if retained.request == *request {
                Ok(())
            } else {
                Err(SharedAgentHostError::ScopeMismatch)
            };
        }
        let journal = &mut self.journal;
        let captured = self
            .owner
            .capture_authority_operation_dispatch(request, |record| {
                journal
                    .retain(
                        request.context.invocation,
                        &record
                            .encode()
                            .map_err(|_| SharedAgentHostError::ScopeMismatch)?,
                    )
                    .map_err(|_| SharedAgentHostError::Unavailable)
            })?;
        if self.retained(request.context.invocation)?.as_ref() != Some(&captured) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Ok(())
    }

    fn dispatch(
        &mut self,
        request: &AuthorityOperationActorDispatch,
    ) -> Result<AuthorityOperationActorResult, Self::Error> {
        use crate::Decode as _;
        if request.target != self.owner.authority_target() || !request.has_valid_request() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let mut retained = self.retained(request.context.invocation)?;
        if retained
            .as_ref()
            .is_some_and(|record| record.request != *request)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        match request.method {
            AuthorityOperationActorMethod::AuthorizeOperation => {
                // Absence is not permission to reconstruct work from a later
                // route/clock after the coordinator has pledged its context.
                if retained.is_none() {
                    return Err(SharedAgentHostError::Unavailable);
                }
            }
            AuthorityOperationActorMethod::AcknowledgeIssuance => {
                let ack = AuthorityOperationIssuanceAck::decode(&request.request)
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                let predecessor = self
                    .retained(ack.authorization_invocation)?
                    .ok_or(SharedAgentHostError::Unavailable)?;
                if predecessor.request.method != AuthorityOperationActorMethod::AuthorizeOperation {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                // Re-observe the exact retained native approval, including on
                // an AOI1 retry. A signed AOI1 cannot supply its own policy.
                let approval_reply = self.owner.execute_authority_operation_dispatch(
                    predecessor.request(),
                    predecessor.envelope(),
                    predecessor.anchor(),
                )?;
                let Some(crate::value::Value::Bytes(bytes)) =
                    crate::value::Value::try_decode(&approval_reply.reply)
                else {
                    return Err(SharedAgentHostError::ScopeMismatch);
                };
                let approval = AuthorityOperationApproval::decode(&bytes)
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                let call = AuthorityOperationCall::decode(&predecessor.request.request)
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                if !ack.matches_pending(&call, &approval) {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                if retained.is_none() {
                    let journal = &mut self.journal;
                    let captured = self.owner.extend_authority_operation_dispatch(
                        &predecessor,
                        &approval,
                        request,
                        |record| {
                            let bytes = record
                                .encode()
                                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                            journal
                                .retain(request.context.invocation, &bytes)
                                .map_err(|_| SharedAgentHostError::Unavailable)
                        },
                    )?;
                    retained = self.retained(request.context.invocation)?;
                    if retained.as_ref() != Some(&captured) {
                        return Err(SharedAgentHostError::Unavailable);
                    }
                }
            }
        }
        let retained = retained.ok_or(SharedAgentHostError::Unavailable)?;
        self.owner.execute_authority_operation_dispatch(
            request,
            retained.envelope(),
            retained.anchor(),
        )
    }
}

/// Immutable native input retained before operation policy or AOI1 execution.
/// A valid record is not its own trust anchor: reopening/execution must still
/// authenticate its pinned Authority and journal admission through the owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RetainedAuthorityOperationDispatch {
    request: AuthorityOperationActorDispatch,
    envelope: RuntimeWork,
    anchor: ManagementJournalAnchor,
}

/// Ephemeral proof produced only by replaying both successful native phases.
/// It must be signed and durably retained before either result is acknowledged.
#[derive(Clone)]
pub(crate) struct VerifiedNativeOperationCompletion {
    target: AuthorityActorTarget,
    authorization: RetainedAuthorityOperationDispatch,
    acknowledgement: RetainedAuthorityOperationDispatch,
}

impl RetainedAuthorityOperationDispatch {
    fn new(
        request: AuthorityOperationActorDispatch,
        envelope: RuntimeWork,
        anchor: ManagementJournalAnchor,
    ) -> Result<Self, SharedAgentHostError> {
        let record = Self {
            request,
            envelope,
            anchor,
        };
        record
            .validate_wire()
            .then_some(record)
            .ok_or(SharedAgentHostError::ScopeMismatch)
    }

    pub(crate) fn request(&self) -> &AuthorityOperationActorDispatch {
        &self.request
    }

    pub(crate) fn envelope(&self) -> &RuntimeWork {
        &self.envelope
    }

    pub(crate) fn anchor(&self) -> &ManagementJournalAnchor {
        &self.anchor
    }
}

impl CanonicalWire for RetainedAuthorityOperationDispatch {
    const MAGIC: [u8; 4] = *b"NOD1";
    const MAX_ENCODED_BYTES: usize =
        64 + MAX_DISPATCH_REQUEST_BYTES + MAX_RUNTIME_WORK_WIRE_BYTES + MAX_DISPATCH_ANCHOR_BYTES;

    fn validate_wire(&self) -> bool {
        matches_operation_envelope(&self.request, &self.envelope)
            && self.envelope.validate_wire()
            && self.request.request.len() <= MAX_DISPATCH_REQUEST_BYTES
            && ManagementJournalAnchor::decode(&self.anchor.encode())
                .is_ok_and(|anchor| anchor == self.anchor)
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.u8(self.request.method as u8);
        encoder.bytes(&self.request.request);
        encoder.bytes(
            &self
                .envelope
                .encode()
                .expect("validated native operation work"),
        );
        encoder.bytes(&self.anchor.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let method = match decoder.u8()? {
            0 => AuthorityOperationActorMethod::AuthorizeOperation,
            1 => AuthorityOperationActorMethod::AcknowledgeIssuance,
            _ => return Err(DecodeError::InvalidTag),
        };
        let bytes = decoder.bytes_bounded(MAX_DISPATCH_REQUEST_BYTES)?;
        let target = match method {
            AuthorityOperationActorMethod::AuthorizeOperation => {
                AuthorityOperationCall::decode(&bytes)
                    .map_err(|_| DecodeError::NonCanonical)?
                    .authority
            }
            AuthorityOperationActorMethod::AcknowledgeIssuance => {
                AuthorityOperationIssuanceAck::decode(&bytes)
                    .map_err(|_| DecodeError::NonCanonical)?
                    .authority
            }
        };
        let envelope = RuntimeWork::decode(&decoder.bytes_bounded(MAX_RUNTIME_WORK_WIRE_BYTES)?)
            .map_err(|_| DecodeError::NonCanonical)?;
        let anchor =
            ManagementJournalAnchor::decode(&decoder.bytes_bounded(MAX_DISPATCH_ANCHOR_BYTES)?)
                .map_err(|_| DecodeError::NonCanonical)?;
        let RuntimeWork::Invoke {
            invocation,
            observed_slot,
            ..
        } = &envelope
        else {
            return Err(DecodeError::NonCanonical);
        };
        let request = AuthorityOperationActorDispatch {
            target,
            method,
            context: crate::agent_sdk::InvocationContext {
                invocation: invocation.invocation,
                actor: invocation.actor,
                mode: invocation.mode,
                origin: invocation.origin,
                roles: invocation.roles,
                observed_slot: *observed_slot,
            },
            request: bytes,
        };
        Self::new(request, envelope, anchor).map_err(|_| DecodeError::NonCanonical)
    }
}

fn operation_message(request: &AuthorityOperationActorDispatch) -> Vec<u8> {
    dynamic_message(
        request.method.name(),
        match request.method {
            AuthorityOperationActorMethod::AuthorizeOperation => "call",
            AuthorityOperationActorMethod::AcknowledgeIssuance => "ack",
        },
        crate::actors::value::Value::Bytes(request.request.clone()),
    )
}

/// Match the whole retained native input to its signed operation domain.
/// This is not a journal-admission proof; the physical host checks the anchor.
pub(crate) fn matches_operation_envelope(
    request: &AuthorityOperationActorDispatch,
    envelope: &RuntimeWork,
) -> bool {
    let RuntimeWork::Invoke {
        context,
        state,
        invocation: work,
        authorization,
        observed_slot,
    } = envelope
    else {
        return false;
    };
    request.has_valid_request()
        && *context == RuntimeExecutionContext::Direct
        && state.is_empty()
        && work.validate()
        && work.space == request.target.space
        && work.agent == request.target.system_agent
        && work.runtime_deployment == request.target.system_runtime_deployment
        && work.actor == request.target.binding.issuer.actor
        && work.deployment == request.target.binding.issuer.deployment
        && work.program == request.target.binding.issuer.program
        && work.invocation == request.context.invocation
        && work.actor == request.context.actor
        && work.mode == request.context.mode
        && work.origin == request.context.origin
        && work.roles == request.context.roles
        && *observed_slot == request.context.observed_slot
        && !work.recovery_only
        && work.message == operation_message(request)
        && **authorization
            == InvocationAuthorization::PublicPreflight(
                super::super::sdk::PublicPreflight::for_work(work, *observed_slot),
            )
}

impl<P, R, I> CleanSystemAgentBootstrapOwner<P, R, I>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    pub(crate) fn verify_native_operation_completion(
        &mut self,
        authorization: &RetainedAuthorityOperationDispatch,
        acknowledgement: &RetainedAuthorityOperationDispatch,
        issued: &crate::agent::authority_operation_issuer::IssuedAuthorityOperation,
    ) -> Result<VerifiedNativeOperationCompletion, SharedAgentHostError> {
        use crate::Decode as _;
        if authorization.request.method != AuthorityOperationActorMethod::AuthorizeOperation
            || acknowledgement.request.method != AuthorityOperationActorMethod::AcknowledgeIssuance
            || authorization.request.target != self.authority_target()
            || acknowledgement.request.target != self.authority_target()
            || issued.receipt != issued.issuance_ack.receipt
            || acknowledgement.request.request
                != issued
                    .issuance_ack
                    .encode()
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let call = AuthorityOperationCall::decode(&authorization.request.request)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let result = self.execute_authority_operation_dispatch(
            authorization.request(),
            authorization.envelope(),
            authorization.anchor(),
        )?;
        let Some(crate::value::Value::Bytes(bytes)) =
            crate::value::Value::try_decode(&result.reply)
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        let approval = AuthorityOperationApproval::decode(&bytes)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if !issued.issuance_ack.matches_pending(&call, &approval) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let result = self.execute_authority_operation_dispatch(
            acknowledgement.request(),
            acknowledgement.envelope(),
            acknowledgement.anchor(),
        )?;
        if crate::value::Value::try_decode(&result.reply) != Some(crate::value::Value::Bool(true)) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Ok(VerifiedNativeOperationCompletion {
            target: self.authority_target(),
            authorization: authorization.clone(),
            acknowledgement: acknowledgement.clone(),
        })
    }

    /// Acknowledge both results but keep the reservation held. This phase must
    /// not be wired into ingress until terminal evidence can be durably saved
    /// and recovered. It deliberately never calls complete/release retirement.
    pub(crate) fn acknowledge_native_operation_completion(
        &mut self,
        retained: &RetainedNativeOperationCompletion,
    ) -> Result<bool, SharedAgentHostError> {
        self.acknowledge_native_operation_completion_observing(retained, || Ok(()))
    }

    /// Observe each independently verified positive acknowledgement. An
    /// observer failure stops before the next result and preserves reservation.
    /// The observer must not re-enter the owner or release admission.
    pub(crate) fn acknowledge_native_operation_completion_observing<F>(
        &mut self,
        retained: &RetainedNativeOperationCompletion,
        mut observed: F,
    ) -> Result<bool, SharedAgentHostError>
    where
        F: FnMut() -> Result<(), SharedAgentHostError>,
    {
        let completion = &retained.completion;
        if completion.target != self.authority_target() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let pair = [
            completion.authorization.envelope(),
            completion.acknowledgement.envelope(),
        ];
        let agent = crate::service::AgentId(self.pins.agent.0);
        self._network_host.ensure_reattached(agent)?;
        let mut material = self.supervisor_invocation_material(
            self.pins.agent,
            completion.target.binding.issuer.actor,
        )?;
        material.root_provenance = false;
        let identity = crate::agent::supervisor_adapters::physical_material_identity(&material)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        for envelope in pair {
            let RuntimeWork::Invoke {
                invocation,
                authorization,
                observed_slot,
                ..
            } = envelope
            else {
                return Err(SharedAgentHostError::ScopeMismatch);
            };
            if !crate::agent::supervisor_adapters::physical_material_authorizes_reserved_work(
                &material,
                identity,
                RuntimeExecutionContext::Direct,
                invocation,
                authorization,
                *observed_slot,
            ) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        }
        self._network_host
            .handoff_management_pending_to_retirement(agent, &[pair])?;
        let mut changed = false;
        for envelope in pair {
            let RuntimeWork::Invoke {
                invocation,
                authorization,
                ..
            } = envelope
            else {
                unreachable!()
            };
            if self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .retained_positive_clean_acknowledgement(agent, invocation, authorization)?
            {
                continue;
            }
            let outcome = self
                ._network_host
                .supervisor_acknowledge_management_retirement(
                    identity,
                    (**invocation).clone(),
                    (**authorization).clone(),
                )?;
            let crate::agent::sdk::RuntimeOutcome::Acknowledged(Ok(ack)) = outcome else {
                return Err(SharedAgentHostError::Unavailable);
            };
            if ack.invocation != invocation.invocation
                || ack.actor != invocation.actor
                || ack.incarnation != invocation.incarnation
                || ack.deployment != invocation.deployment
                || ack.mode != invocation.mode
                || ack.work != invocation.commitment()
                || ack.authorization != authorization.commitment()
                || !self
                    .host
                    .lock()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                    .retained_positive_clean_acknowledgement(agent, invocation, authorization)?
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            changed = true;
            observed()?;
        }
        Ok(changed)
    }

    /// Reserve and durably retain the first exact operation invocation before
    /// it is given to the coordinator. The callback runs under admission and
    /// must sync the record without re-entering this owner. A callback error
    /// retains the reservation; retry/reopen must resolve the saved evidence.
    /// Once a record exists, use it directly: do not call fresh preparation
    /// after the observed clock or installed material has advanced.
    pub(crate) fn capture_authority_operation_dispatch<F>(
        &mut self,
        request: &AuthorityOperationActorDispatch,
        persist: F,
    ) -> Result<RetainedAuthorityOperationDispatch, SharedAgentHostError>
    where
        F: FnOnce(&RetainedAuthorityOperationDispatch) -> Result<(), SharedAgentHostError>,
    {
        if request.method != AuthorityOperationActorMethod::AuthorizeOperation {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let proposed = self.prepare_authority_operation_dispatch(request)?;
        self._network_host.capture_management_pending(
            crate::service::AgentId(self.pins.agent.0),
            &proposed,
            |(anchor, envelope)| {
                let retained = RetainedAuthorityOperationDispatch::new(
                    request.clone(),
                    envelope.clone(),
                    anchor.clone(),
                )?;
                persist(&retained)?;
                Ok(retained)
            },
        )
    }

    /// Extend only the exact retained authorization with its signed issuance
    /// acknowledgement. The journal admission layer independently requires the
    /// predecessor to be present; a matching signature cannot invent admission.
    pub(crate) fn extend_authority_operation_dispatch<F>(
        &mut self,
        predecessor: &RetainedAuthorityOperationDispatch,
        approval: &AuthorityOperationApproval,
        request: &AuthorityOperationActorDispatch,
        persist: F,
    ) -> Result<RetainedAuthorityOperationDispatch, SharedAgentHostError>
    where
        F: FnOnce(&RetainedAuthorityOperationDispatch) -> Result<(), SharedAgentHostError>,
    {
        if !predecessor.validate_wire()
            || predecessor.request.method != AuthorityOperationActorMethod::AuthorizeOperation
            || predecessor.request.target != self.authority_target()
            || request.method != AuthorityOperationActorMethod::AcknowledgeIssuance
            || !request.has_valid_request()
            || request.context.observed_slot < predecessor.request.context.observed_slot
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let call = AuthorityOperationCall::decode(&predecessor.request.request)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let acknowledgement = AuthorityOperationIssuanceAck::decode(&request.request)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if !acknowledgement.matches_pending(&call, approval) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let proposed = self.prepare_authority_operation_dispatch(request)?;
        self._network_host.extend_management_pending(
            crate::service::AgentId(self.pins.agent.0),
            &(predecessor.anchor.clone(), predecessor.envelope.clone()),
            &proposed,
            |(anchor, envelope)| {
                let retained = RetainedAuthorityOperationDispatch::new(
                    request.clone(),
                    envelope.clone(),
                    anchor.clone(),
                )?;
                persist(&retained)?;
                Ok(retained)
            },
        )
    }

    /// Prepare fresh installed material. Authorization uses the current clock;
    /// AOI1 uses its already-signed issuance clock, never a later host clock.
    /// Recovery must use the saved whole envelope instead of this method.
    pub(crate) fn prepare_authority_operation_dispatch(
        &self,
        request: &AuthorityOperationActorDispatch,
    ) -> Result<RuntimeWork, SharedAgentHostError> {
        if self.record.pending_projection.is_some()
            || request.target != self.authority_target()
            || !request.has_valid_request()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let mut material = self
            .supervisor_invocation_material(self.pins.agent, request.target.binding.issuer.actor)?;
        material.root_provenance = false;
        if material.actor.entry.deployment != request.target.binding.issuer.deployment
            || material.actor.entry.program != request.target.binding.issuer.program
            || material.producer != request.target.binding.issuer.producer
            || request.context.observed_slot > material.observed_slot
            || (request.method == AuthorityOperationActorMethod::AuthorizeOperation
                && material.observed_slot != request.context.observed_slot)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let identity = super::super::supervisor_adapters::physical_material_identity(&material)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let mut availability = vec![
            material.program.clone(),
            material.schema.clone(),
            material.policies.clone(),
        ];
        availability.extend(material.installation_data.clone());
        availability.sort_unstable_by(|left, right| left.reference.cmp(&right.reference));
        let work = super::super::sdk::InvocationWork {
            space: request.target.space,
            agent: request.target.system_agent,
            runtime_deployment: request.target.system_runtime_deployment,
            invocation: request.context.invocation,
            actor: request.context.actor,
            incarnation: material.actor.incarnation,
            deployment: request.target.binding.issuer.deployment,
            program: request.target.binding.issuer.program,
            mode: request.context.mode,
            origin: request.context.origin,
            roles: request.context.roles,
            message: operation_message(request),
            installation_data: material.actor.entry.installation_data.clone(),
            availability,
            gas: self.invocation_gas,
            recovery_only: false,
        };
        let authorization = InvocationAuthorization::PublicPreflight(
            super::super::sdk::PublicPreflight::for_work(&work, request.context.observed_slot),
        );
        if !super::super::supervisor_adapters::physical_material_authorizes_reserved_work(
            &material,
            identity,
            RuntimeExecutionContext::Direct,
            &work,
            &authorization,
            request.context.observed_slot,
        ) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let envelope = RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: RuntimeState::default(),
            invocation: Box::new(work),
            authorization: Box::new(authorization),
            observed_slot: request.context.observed_slot,
        };
        matches_operation_envelope(request, &envelope)
            .then_some(envelope)
            .ok_or(SharedAgentHostError::ScopeMismatch)
    }

    /// Execute only the exact previously persisted envelope. The shared host
    /// independently authenticates the pre-dispatch anchor against its journal
    /// and waits for durable Linear completion. This does not retire the result.
    pub(crate) fn execute_authority_operation_dispatch(
        &self,
        request: &AuthorityOperationActorDispatch,
        envelope: &RuntimeWork,
        anchor: &super::super::clean_management_intent::ManagementJournalAnchor,
    ) -> Result<AuthorityOperationActorResult, SharedAgentHostError> {
        if self.record.pending_projection.is_some()
            || request.target != self.authority_target()
            || !matches_operation_envelope(request, envelope)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let RuntimeWork::Invoke {
            invocation: work,
            authorization,
            observed_slot,
            ..
        } = envelope
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        let mut material = self.supervisor_invocation_material(self.pins.agent, work.actor)?;
        material.root_provenance = false;
        if material.producer != request.target.binding.issuer.producer {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let identity = super::super::supervisor_adapters::physical_material_identity(&material)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if !super::super::supervisor_adapters::physical_material_authorizes_reserved_work(
            &material,
            identity,
            RuntimeExecutionContext::Direct,
            work,
            authorization,
            *observed_slot,
        ) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let outcome = self.supervisor_invoke_persisted_management(
            identity,
            (**work).clone(),
            (**authorization).clone(),
            anchor,
        )?;
        let super::super::sdk::RuntimeOutcome::Completed(Ok(reply)) = outcome else {
            return Err(SharedAgentHostError::Unavailable);
        };
        if reply.invocation != work.invocation
            || reply.actor != work.actor
            || reply.incarnation != work.incarnation
            || reply.deployment != work.deployment
            || reply.mode != work.mode
            || reply.status != super::super::sdk::InvocationStatus::Done
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Ok(AuthorityOperationActorResult {
            target: request.target,
            method: request.method,
            context: request.context,
            request: request.request.clone(),
            authenticated: true,
            durable: true,
            reply: reply.reply,
        })
    }
}
