//! Retained native Authority administration. This is not an ingress API:
//! callers must authenticate the local node and persist before dispatch.
//! Admission and the terminal reply remain retained until explicit retirement.

use super::*;
#[path = "clean_admin_terminal.rs"]
pub(crate) mod terminal;
use crate::agent::clean_management_intent::ManagementJournalAnchor;
use crate::agent::sdk::authority::{AuthorityAdminCall, AuthorityAdminResult};
use crate::agent::sdk::{InvocationContext, InvocationOrigin, InvocationWork, PublicPreflight};

/// Immutable records under an exclusive writer lease. Implementations must
/// bound reads before allocation and reject replacement with different bytes.
pub trait NativeAuthorityAdminJournalStore {
    type Error;
    fn load(&mut self, invocation: InvocationId) -> Result<Option<Vec<u8>>, Self::Error>;
    fn retain(&mut self, invocation: InvocationId, bytes: &[u8]) -> Result<(), Self::Error>;
}

pub const MAX_NATIVE_AUTHORITY_ADMIN_DISPATCH_BYTES: usize =
    RetainedAuthorityAdminDispatch::MAX_ENCODED_BYTES;

/// File-key and signed envelope validation, not physical journal finality.
pub fn native_admin_record_matches(
    authority: AuthorityActorTarget,
    invocation: InvocationId,
    bytes: &[u8],
) -> bool {
    RetainedAuthorityAdminDispatch::decode(bytes).is_ok_and(|record| {
        record.call.authority == authority && record.call.invocation == invocation
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RetainedAuthorityAdminDispatch {
    pub(super) call: AuthorityAdminCall,
    pub(super) envelope: RuntimeWork,
    pub(super) anchor: ManagementJournalAnchor,
    pub(super) preparation: NativeAuthorityAdminPreparation,
}

fn message(call: &AuthorityAdminCall) -> Vec<u8> {
    dynamic_message(
        "administer",
        "call",
        crate::actors::value::Value::Bytes(call.encode().expect("validated admin call")),
    )
}

/// Used only after independently replaying the exact anchored Invoke and
/// positive ACK. Admin success has no subsequent issuance/application phase;
/// it may remain reserved while its terminal certificate is being persisted.
pub(crate) fn matches_successful_admin_reply(
    anchor: &ManagementJournalAnchor,
    envelope: &RuntimeWork,
    reply: &[u8],
) -> bool {
    use crate::Decode as _;
    let Some(crate::actors::value::Value::Bytes(bytes)) =
        crate::actors::value::Value::try_decode(reply)
    else {
        return false;
    };
    let Ok(result) = AuthorityAdminResult::decode(&bytes) else {
        return false;
    };
    result.verify_with(&RawCredentialVerifier).is_ok()
        && admin_envelope_matches(&result.call, envelope, anchor)
}

fn admin_envelope_matches(
    call: &AuthorityAdminCall,
    envelope: &RuntimeWork,
    anchor: &ManagementJournalAnchor,
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
    call.verify_with(&RawCredentialVerifier).is_ok()
        && envelope.validate_wire()
        && ManagementJournalAnchor::decode(&anchor.encode()).is_ok_and(|a| a == *anchor)
        && *context == RuntimeExecutionContext::Direct
        && state.is_empty()
        && work.space == call.authority.space
        && work.agent == call.authority.system_agent
        && work.runtime_deployment == call.authority.system_runtime_deployment
        && work.deployment == call.authority.binding.issuer.deployment
        && work.program == call.authority.binding.issuer.program
        && !work.recovery_only
        && call.matches_invocation_context(&InvocationContext {
            invocation: work.invocation,
            actor: work.actor,
            mode: work.mode,
            origin: work.origin,
            roles: work.roles,
            observed_slot: *observed_slot,
        })
        && work.message == message(call)
        && **authorization
            == InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(
                work,
                *observed_slot,
            ))
}

impl CanonicalWire for RetainedAuthorityAdminDispatch {
    const MAGIC: [u8; 4] = *b"NAD2";
    const MAX_ENCODED_BYTES: usize = 64
        + crate::agent_sdk::wire::MAX_AUTHORITY_ADMIN_CALL_WIRE_BYTES
        + MAX_RUNTIME_WORK_WIRE_BYTES
        + 1024
        + NativeAuthorityAdminPreparation::MAX_ENCODED_BYTES;

    fn validate_wire(&self) -> bool {
        admin_envelope_matches(&self.call, &self.envelope, &self.anchor)
            && self.preparation.matches_call(&self.call)
            && matches!(&self.envelope, RuntimeWork::Invoke { invocation, .. }
                if invocation.incarnation == self.preparation.incarnation())
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.bytes(&self.call.encode().expect("validated admin call"));
        encoder.bytes(&self.envelope.encode().expect("validated admin work"));
        encoder.bytes(&self.anchor.encode());
        encoder.bytes(
            &self
                .preparation
                .encode()
                .expect("validated admin preparation"),
        );
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let call = AuthorityAdminCall::decode(
            &decoder.bytes_bounded(crate::agent_sdk::wire::MAX_AUTHORITY_ADMIN_CALL_WIRE_BYTES)?,
        )
        .map_err(|_| DecodeError::NonCanonical)?;
        let envelope = RuntimeWork::decode(&decoder.bytes_bounded(MAX_RUNTIME_WORK_WIRE_BYTES)?)
            .map_err(|_| DecodeError::NonCanonical)?;
        let anchor = ManagementJournalAnchor::decode(&decoder.bytes_bounded(1024)?)
            .map_err(|_| DecodeError::NonCanonical)?;
        let value = Self {
            call,
            envelope,
            anchor,
            preparation: NativeAuthorityAdminPreparation::decode(
                &decoder.bytes_bounded(NativeAuthorityAdminPreparation::MAX_ENCODED_BYTES)?,
            )
            .map_err(|_| DecodeError::NonCanonical)?,
        };
        value
            .validate_wire()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

impl<P, R, I> CleanSystemAgentBootstrapOwner<P, R, I>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    /// Retry uses the whole retained envelope, never newly selected material
    /// or a newly sampled clock. A failed publication leaves admission held.
    pub(crate) fn retain_authority_admin<J: NativeAuthorityAdminJournalStore>(
        &mut self,
        call: &AuthorityAdminCall,
        preparation: &NativeAuthorityAdminPreparation,
        journal: &mut J,
    ) -> Result<RetainedAuthorityAdminDispatch, SharedAgentHostError> {
        if !preparation.matches_call(call)
            || call.authority != self.authority_target()
            || call.authenticated_node != self.pins.node
            || self.record.pending_projection.is_some()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if let Some(bytes) = journal
            .load(call.invocation)
            .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            let retained = RetainedAuthorityAdminDispatch::decode(&bytes)
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            if retained.call != *call || retained.preparation != *preparation {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            self._network_host.ensure_management_pending_member(
                crate::service::AgentId(self.pins.agent.0),
                &retained.anchor,
                &retained.envelope,
            )?;
            // Confirm durable retention even after an ambiguous prior write.
            journal
                .retain(call.invocation, &bytes)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            return Ok(retained);
        }
        if let Some((anchor, envelope)) = self._network_host.retained_management_pending(
            crate::service::AgentId(self.pins.agent.0),
            call.invocation,
        )? {
            let retained = RetainedAuthorityAdminDispatch {
                call: call.clone(),
                envelope,
                anchor,
                preparation: preparation.clone(),
            };
            let bytes = retained
                .encode()
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            journal
                .retain(call.invocation, &bytes)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            return Ok(retained);
        }
        let mut material = self
            .supervisor_invocation_material(self.pins.agent, call.authority.binding.issuer.actor)?;
        material.root_provenance = false;
        if material.observed_slot < call.observed_slot
            || material.actor.incarnation != preparation.incarnation()
            || material.actor.entry.deployment != call.authority.binding.issuer.deployment
            || material.actor.entry.program != call.authority.binding.issuer.program
            || material.producer != call.authority.binding.issuer.producer
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let identity = crate::agent::supervisor_adapters::physical_material_identity(&material)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let mut availability = vec![
            material.program.clone(),
            material.schema.clone(),
            material.policies.clone(),
        ];
        availability.extend(material.installation_data.clone());
        availability.sort_unstable_by(|a, b| a.reference.cmp(&b.reference));
        let work = InvocationWork {
            space: call.authority.space,
            agent: call.authority.system_agent,
            runtime_deployment: call.authority.system_runtime_deployment,
            invocation: call.invocation,
            actor: call.authority.binding.issuer.actor,
            incarnation: material.actor.incarnation,
            deployment: call.authority.binding.issuer.deployment,
            program: call.authority.binding.issuer.program,
            mode: MethodMode::Linear,
            origin: InvocationOrigin {
                principal: Some(call.administrator),
                credential: Some(call.credential),
                transport_node: Some(call.authenticated_node),
                actor: None,
                capability: None,
            },
            roles: InvocationRoleClaims::none(),
            message: message(call),
            installation_data: material.actor.entry.installation_data.clone(),
            availability,
            gas: self.invocation_gas,
            recovery_only: false,
        };
        let authorization = InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(
            &work,
            call.observed_slot,
        ));
        if !crate::agent::supervisor_adapters::physical_material_authorizes_reserved_work(
            &material,
            identity,
            RuntimeExecutionContext::Direct,
            &work,
            &authorization,
            call.observed_slot,
        ) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let proposed = RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: RuntimeState::default(),
            invocation: Box::new(work),
            authorization: Box::new(authorization),
            observed_slot: call.observed_slot,
        };
        self._network_host
            .capture_management_pending_with_checkpoint(
                crate::service::AgentId(self.pins.agent.0),
                &proposed,
                &self.pins.replicas,
                self.snapshot_signer.as_ref(),
                |(anchor, envelope)| {
                    let retained = RetainedAuthorityAdminDispatch {
                        call: call.clone(),
                        envelope: envelope.clone(),
                        anchor: anchor.clone(),
                        preparation: preparation.clone(),
                    };
                    let bytes = retained
                        .encode()
                        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                    journal
                        .retain(call.invocation, &bytes)
                        .map_err(|_| SharedAgentHostError::Unavailable)?;
                    Ok(retained)
                },
            )
    }

    /// None means a durable actor denial, not a transport failure. Neither
    /// outcome acknowledges the reply or releases the reserved native work.
    pub(crate) fn execute_authority_admin(
        &self,
        retained: &RetainedAuthorityAdminDispatch,
    ) -> Result<Option<AuthorityAdminResult>, SharedAgentHostError> {
        if !retained.validate_wire()
            || retained.call.authority != self.authority_target()
            || retained.call.authenticated_node != self.pins.node
            || self.record.pending_projection.is_some()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let RuntimeWork::Invoke {
            invocation: work,
            authorization,
            observed_slot,
            ..
        } = &retained.envelope
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        let mut material = self.supervisor_invocation_material(self.pins.agent, work.actor)?;
        material.root_provenance = false;
        let identity = crate::agent::supervisor_adapters::physical_material_identity(&material)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if material.producer != retained.call.authority.binding.issuer.producer
            || !crate::agent::supervisor_adapters::physical_material_authorizes_reserved_work(
                &material,
                identity,
                RuntimeExecutionContext::Direct,
                work,
                authorization,
                *observed_slot,
            )
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let outcome = self.supervisor_invoke_persisted_management(
            identity,
            (**work).clone(),
            (**authorization).clone(),
            &retained.anchor,
        )?;
        let crate::agent_sdk::RuntimeOutcome::Completed(Ok(reply)) = outcome else {
            return Err(SharedAgentHostError::Unavailable);
        };
        if reply.invocation != work.invocation
            || reply.actor != work.actor
            || reply.incarnation != work.incarnation
            || reply.deployment != work.deployment
            || reply.mode != work.mode
            || reply.status != crate::agent_sdk::InvocationStatus::Done
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        use crate::Decode as _;
        let Some(crate::actors::value::Value::Bytes(bytes)) =
            crate::actors::value::Value::try_decode(&reply.reply)
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        if bytes.is_empty() {
            return Ok(None);
        }
        let result = AuthorityAdminResult::decode(&bytes)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if result.call != retained.call || result.verify_with(&RawCredentialVerifier).is_err() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Ok(Some(result))
    }
}
