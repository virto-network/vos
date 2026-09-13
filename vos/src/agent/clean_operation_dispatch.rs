//! Native physical execution boundary for retained Authority operation work.
//! The caller must persist the complete envelope and its journal anchor before
//! execution, and retain admission until coordinator/issuer recovery retires it.

use super::*;
use crate::agent::authority_operation_coordinator::{
    AuthorityOperationActorDispatch, AuthorityOperationActorMethod, AuthorityOperationActorResult,
};
use crate::agent::clean_management_intent::ManagementJournalAnchor;
use crate::agent::sdk::authority_operation::{
    AuthorityOperationApproval, AuthorityOperationCall, AuthorityOperationIssuanceAck,
    MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES, MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES,
};

const MAX_DISPATCH_REQUEST_BYTES: usize =
    if MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES > MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES {
        MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES
    } else {
        MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES
    };
const MAX_DISPATCH_ANCHOR_BYTES: usize = 1024;

/// Immutable native input retained before operation policy or AOI1 execution.
/// A valid record is not its own trust anchor: reopening/execution must still
/// authenticate its pinned Authority and journal admission through the owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RetainedAuthorityOperationDispatch {
    request: AuthorityOperationActorDispatch,
    envelope: RuntimeWork,
    anchor: ManagementJournalAnchor,
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
