//! Online-owner Install transport hooks. Temporary bytes are not authority,
//! application evidence, or canonical Raft artifact publication.

use super::*;
use crate::agent::package_admission::AdmittedActorPackage;
use crate::network::agent_protocol::{
    AgentGenerationRoute, ForwardedSharedInstallOwner, ForwardedSharedInstallRequest,
};

impl SharedAgentHost {
    fn forwarded_install_target(
        &mut self,
        agent: AgentId,
        request: &crate::agent_sdk::ManagementRequest,
        receipt: &crate::agent_sdk::authority::AuthorityReceipt,
    ) -> Result<crate::agent_sdk::authority::ManagedAgentTarget, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if !hosted.driver.uses_external_state()
            || matches!(
                hosted.intent.authority,
                SharedGenesisAuthority::SystemBootstrap { .. }
            )
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let descriptor = hosted.driver.clean_descriptor().map_err(map_driver_error)?;
        let committee = hosted.driver.active_committee().map_err(map_driver_error)?;
        if descriptor.identity.profile != crate::agent_sdk::AgentProfile::Shared
            || committee.members().len() != 3
            || committee.voter_count() != 3
            || !matches!(request, crate::agent_sdk::ManagementRequest::Install(_))
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        // Verify the exact signed receipt and target, without resampling its
        // lifetime or claiming the temporary upload is already applicable.
        super::super::driver::verify_clean_management_receipt(
            &descriptor,
            request,
            receipt,
            receipt.selector.valid_from,
            false,
        )
        .map_err(|_| SharedAgentHostError::InvalidProvision)?;
        Ok(crate::agent_sdk::authority::ManagedAgentTarget {
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            owner: descriptor.identity.owner,
            profile: descriptor.identity.profile,
            runtime_deployment: descriptor.identity.runtime_deployment,
            transition_producer: descriptor.identity.transition_producer,
        })
    }

    fn validate_forwarded_install_scope(
        &mut self,
        owner: ForwardedSharedInstallOwner,
        sender: crate::agent_sdk::NodeId,
        agent: AgentId,
        request: &crate::agent_sdk::ManagementRequest,
        receipt: &crate::agent_sdk::authority::AuthorityReceipt,
        require_approval: bool,
    ) -> Result<(), SharedAgentHostError> {
        let managed = self.forwarded_install_target(agent, request, receipt)?;
        if owner.system.space.0 != self.scope().space.0
            || owner.system.agent.0 == agent.0
            || sender == crate::agent_sdk::NodeId::ZERO
            || self
                .root_pins
                .as_ref()
                .is_some_and(|pins| pins.record().system_agent().0 != owner.system.agent.0)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let system = self
            .agents
            .get(&AgentId(owner.system.agent.0))
            .ok_or(SharedAgentHostError::Unavailable)?;
        if !matches!(
            system.intent.authority,
            SharedGenesisAuthority::SystemBootstrap { .. }
        ) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        system
            .driver
            .validate_forwarded_install_owner(
                sender,
                owner,
                request,
                receipt,
                managed,
                require_approval,
            )
            .map_err(map_driver_error)?;
        self.lease.validate_live().map_err(map_outer_lease_error)
    }

    /// Called inside the existing managed proposal+host critical section,
    /// after drain and immediately before ordinary management preparation.
    pub(crate) fn validate_forwarded_shared_install_owner(
        &mut self,
        system: AgentGenerationRoute,
        sender: crate::agent_sdk::NodeId,
        registration: crate::agent_sdk::Hash,
        member: crate::agent_sdk::Hash,
        request: &crate::agent_sdk::ManagementRequest,
        authority: &crate::agent_sdk::authority::AuthorityReceipt,
    ) -> Result<(), SharedAgentHostError> {
        self.validate_forwarded_install_scope(
            ForwardedSharedInstallOwner {
                system,
                registration,
                member,
            },
            sender,
            AgentId(authority.selector.agent.0),
            request,
            authority,
            true,
        )
    }

    pub(crate) fn transfer_forwarded_shared_install_package(
        &mut self,
        agent: AgentId,
        sender: crate::agent_sdk::NodeId,
        request: &ForwardedSharedInstallRequest,
    ) -> Result<u64, SharedAgentHostError> {
        self.validate_forwarded_install_scope(
            request.owner,
            sender,
            agent,
            &request.request,
            &request.authority,
            false,
        )?;
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .transfer_forwarded_install_package(sender, request)
            .map_err(map_driver_error)
    }

    pub(crate) fn load_forwarded_shared_install_package(
        &mut self,
        agent: AgentId,
        sender: crate::agent_sdk::NodeId,
        request: &ForwardedSharedInstallRequest,
    ) -> Result<AdmittedActorPackage, SharedAgentHostError> {
        self.validate_forwarded_install_scope(
            request.owner,
            sender,
            agent,
            &request.request,
            &request.authority,
            false,
        )?;
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .load_forwarded_install(sender, request)
            .map_err(map_driver_error)
    }

    pub(crate) fn retire_forwarded_shared_install_package(
        &mut self,
        agent: AgentId,
        sender: crate::agent_sdk::NodeId,
        request: &ForwardedSharedInstallRequest,
    ) -> Result<(), SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .retire_forwarded_install(sender, request)
            .map_err(map_driver_error)
    }

    pub(crate) fn retained_forwarded_shared_install(
        &mut self,
        agent: AgentId,
        request: &crate::agent_sdk::ManagementRequest,
        authority: &crate::agent_sdk::authority::AuthorityReceipt,
    ) -> Result<
        Option<(
            super::super::journal::ReplayInputId,
            crate::agent_sdk::RuntimeOutcome,
            u64,
        )>,
        SharedAgentHostError,
    > {
        self.forwarded_install_target(agent, request, authority)?;
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .retained_forwarded_install(request, authority)
            .map_err(map_driver_error)
    }
}
