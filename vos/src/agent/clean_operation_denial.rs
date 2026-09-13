//! Native operation denial proof, not a terminal retirement certificate.
use super::*;
use crate::agent::authority_operation_issuer::{
    AuthorityOperationIssuerStore, DurableAuthorityOperationIssuer,
};
use crate::agent::sdk::{InvocationStatus, RuntimeOutcome};

pub(crate) struct VerifiedNativeOperationDenial<'a> {
    proof: VerifiedManagementDenial,
    target: AuthorityActorTarget,
    // Prevent issuance or replacement of the parsed issuer while this unissued
    // denial is being acknowledged. The caller must also retain its store lease.
    _issuer: core::marker::PhantomData<&'a mut ()>,
}

impl<P, R, I> CleanSystemAgentBootstrapOwner<P, R, I>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    /// Inspect only already-durable native policy execution. No fresh dispatch,
    /// signing, or release is permitted by this verification boundary.
    pub(crate) fn verify_native_operation_denial<'a, B: AuthorityOperationIssuerStore>(
        &mut self,
        record: &RetainedAuthorityOperationDispatch,
        issuer: &'a mut DurableAuthorityOperationIssuer<B>,
    ) -> Result<Option<VerifiedNativeOperationDenial<'a>>, SharedAgentHostError> {
        let target = self.authority_target();
        if record.request.target != target
            || record.request.method != AuthorityOperationActorMethod::AuthorizeOperation
            || !record.validate_wire()
            || issuer.authority() != target
            || issuer.is_poisoned()
            || issuer
                .recover_retained(record.request.context.invocation)
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let call = AuthorityOperationCall::decode(&record.request.request)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let RuntimeWork::Invoke {
            invocation,
            authorization,
            observed_slot,
            ..
        } = &record.envelope
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        let agent = crate::service::AgentId(self.pins.agent.0);
        self._network_host.ensure_reattached(agent)?;
        self._network_host.ensure_management_pending_member(
            agent,
            &record.anchor,
            &record.envelope,
        )?;
        let mut material =
            self.supervisor_invocation_material(self.pins.agent, target.binding.issuer.actor)?;
        material.root_provenance = false;
        let identity = crate::agent::supervisor_adapters::physical_material_identity(&material)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
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
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let Some(input) = host.management_denial_invocation_after_anchor(
            agent,
            &record.anchor,
            &record.envelope,
        )?
        else {
            return Ok(None);
        };
        let RuntimeOutcome::Completed(Ok(reply)) =
            host.replay_durable_management_denial(agent, &record.anchor, &record.envelope)?
        else {
            return Ok(None);
        };
        if reply.invocation != invocation.invocation
            || reply.actor != invocation.actor
            || reply.incarnation != invocation.incarnation
            || reply.deployment != invocation.deployment
            || reply.mode != invocation.mode
            || reply.status != InvocationStatus::Done
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if reply.reply != crate::Encode::encode(&crate::value::Value::Bytes(Vec::new())) {
            return Ok(None);
        }
        Ok(Some(VerifiedNativeOperationDenial {
            proof: VerifiedManagementDenial {
                call: call.commitment(),
                anchor: record.anchor.clone(),
                work: record.envelope.clone(),
                input,
            },
            target,
            _issuer: core::marker::PhantomData,
        }))
    }

    /// Positively acknowledge only the exact verified unissued denial. Keep its
    /// reservation until separate durable terminal evidence authorizes release.
    pub(crate) fn acknowledge_native_operation_denial(
        &mut self,
        denial: &VerifiedNativeOperationDenial<'_>,
    ) -> Result<bool, SharedAgentHostError> {
        if denial.target != self.authority_target() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let (anchor, envelope) = denial.proof.envelope();
        let RuntimeWork::Invoke {
            invocation,
            authorization,
            ..
        } = envelope
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        let agent = crate::service::AgentId(self.pins.agent.0);
        self._network_host.ensure_reattached(agent)?;
        self._network_host
            .ensure_management_pending_member(agent, anchor, envelope)?;
        if self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .retained_positive_clean_acknowledgement(agent, invocation, authorization)?
        {
            return Ok(false);
        }
        let mut material = self
            .supervisor_invocation_material(self.pins.agent, denial.target.binding.issuer.actor)?;
        material.root_provenance = false;
        let identity = crate::agent::supervisor_adapters::physical_material_identity(&material)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let RuntimeOutcome::Acknowledged(Ok(ack)) = self
            ._network_host
            .supervisor_acknowledge_management_denial(identity, &denial.proof)?
        else {
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
        Ok(true)
    }
}
