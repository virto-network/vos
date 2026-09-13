//! Native physical execution boundary for retained Authority operation work.
//! The caller must persist the complete envelope and its journal anchor before
//! execution, and retain admission until coordinator/issuer recovery retires it.

use super::*;
use crate::agent::authority_operation_coordinator::{
    AuthorityOperationActorDispatch, AuthorityOperationActorMethod, AuthorityOperationActorResult,
};

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
    /// Prepare only fresh work. Recovery must use the saved whole envelope,
    /// never current installation data or a regenerated authorization clock.
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
            || material.observed_slot != request.context.observed_slot
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
            super::super::sdk::PublicPreflight::for_work(&work, material.observed_slot),
        );
        if !super::super::supervisor_adapters::physical_material_authorizes_work(
            &material,
            identity,
            RuntimeExecutionContext::Direct,
            &work,
            &authorization,
        ) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let envelope = RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: RuntimeState::default(),
            invocation: Box::new(work),
            authorization: Box::new(authorization),
            observed_slot: material.observed_slot,
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
