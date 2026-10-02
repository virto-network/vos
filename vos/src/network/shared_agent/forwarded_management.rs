//! Explicit online-original-owner Install transfer and submission. Peer
//! progress is never a result; the origin uses only its exact local replay.

use super::*;
use crate::agent::driver::SdkManagementArtifacts;
use crate::agent::package_admission::AdmittedActorPackage;
use crate::network::agent_protocol::{
    ForwardedSharedInstallOperation, ForwardedSharedInstallOwner, ForwardedSharedInstallRequest,
};

impl SharedRouteHandler {
    fn forwarded_install_fingerprint(
        &self,
        host: &SharedAgentHost,
    ) -> Result<(shared_raft::AgentRouteKey, AttachmentFingerprint), SharedAgentHostError> {
        let status = host
            .supervisor_attachment_status(self.agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        let fingerprint = AttachmentFingerprint::from_attachment_status(&status)?;
        if status.transport != SharedAgentTransportState::Attached
            || fingerprint.protocol_route != self.route
            || fingerprint.members.len() != 3
            || fingerprint.voters.len() != 3
            || fingerprint.next_committee.is_some()
            || fingerprint.joint_old.is_some()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Ok((status.route, fingerprint))
    }

    pub(super) fn handle_forwarded_shared_install(
        &self,
        sender: NodeId,
        request: &ForwardedSharedInstallRequest,
    ) -> Result<u64, SharedAgentHostError> {
        if !request.is_valid(self.route) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        // Do not keep this preparation lock across ordinary management submit:
        // that existing path freshly validates owner proof under both guards.
        let package = {
            let proposal = self
                .proposal
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            if proposal.is_reserved() {
                return Err(SharedAgentHostError::Conflict);
            }
            let worker = self
                .worker
                .as_ref()
                .ok_or(SharedAgentHostError::TransportNotAttached)?;
            if !self.has_local_proposer(worker) {
                return Err(SharedAgentHostError::Unavailable);
            }
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            drain_committed(&mut host, self.agent, &self.ordered_replies)?;
            let (_, fingerprint) = self.forwarded_install_fingerprint(&host)?;
            if fingerprint.voters.binary_search(&sender).is_err() {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            match &request.operation {
                ForwardedSharedInstallOperation::Progress
                | ForwardedSharedInstallOperation::Chunk(_) => {
                    return host
                        .transfer_forwarded_shared_install_package(self.agent, sender, request);
                }
                ForwardedSharedInstallOperation::Finish => {
                    host.load_forwarded_shared_install_package(self.agent, sender, request)?
                }
            }
        };
        let submission = self.submit_clean_management_with_owner(
            request.request.clone(),
            request.authority.clone(),
            SdkManagementArtifacts::Actor(&package),
            Some((sender, request.owner)),
        )?;
        match submission {
            CleanManagementSubmission::Applied { .. } => {
                // Cleanup cannot change terminal evidence or authorize another
                // package. Exact retry can safely re-upload after response loss.
                let mut host = self
                    .host
                    .lock()
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                host.retire_forwarded_shared_install_package(self.agent, sender, request)?;
                let crate::agent_sdk::ManagementRequest::Install(install) = &request.request else {
                    return Err(SharedAgentHostError::ScopeMismatch);
                };
                Ok(install.package.len)
            }
            CleanManagementSubmission::Denied { .. } => Err(SharedAgentHostError::Unavailable),
        }
    }

    pub(super) fn forward_shared_install(
        &self,
        owner: ForwardedSharedInstallOwner,
        request: crate::agent_sdk::ManagementRequest,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
        package: &AdmittedActorPackage,
    ) -> Result<CleanManagementSubmission, SharedAgentHostError> {
        let crate::agent_sdk::ManagementRequest::Install(install) = &request else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        if package.package_ref() != &install.package {
            return Err(SharedAgentHostError::InvalidCatalog);
        }
        let mut transfer = ForwardedSharedInstallRequest {
            owner,
            request: request.clone(),
            authority: authority.clone(),
            operation: ForwardedSharedInstallOperation::Progress,
        };
        if !transfer.is_valid(self.route) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let worker = self
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let before = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        let (route, retained) = {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            drain_committed(&mut host, self.agent, &self.ordered_replies)?;
            let (route, _) = self.forwarded_install_fingerprint(&host)?;
            let retained =
                host.retained_forwarded_shared_install(self.agent, &request, &authority)?;
            if retained.is_none() {
                host.validate_forwarded_shared_install_owner(
                    owner.system,
                    self.network.agent_node_id(),
                    owner.registration,
                    owner.member,
                    &request,
                    &authority,
                )?;
                let current = futures_executor::block_on(worker.snapshot())
                    .ok_or(SharedAgentHostError::Unavailable)?;
                CommittedProposalBarrier::from(&before).validate_applied(
                    CommittedProposalBarrier::from(&current),
                    host.capacity(self.agent)?.0,
                )?;
            }
            (route, retained)
        };
        if let Some((input, outcome, observed_slot)) = retained {
            self.require_ordered_availability(input)?;
            tracing::debug!(
                phase = "origin_retained",
                node = ?self.network.agent_node_id(),
                agent = ?self.agent,
                route = ?self.route,
                request = ?request.commitment(),
                authority = ?authority.commitment(),
                ?input,
                after_forward = false,
                "Shared Install forwarding provenance"
            );
            return Ok(CleanManagementSubmission::Applied {
                outcome,
                observed_slot,
                new_slot: false,
            });
        }
        let leader = self.management_leader(&before)?;
        let manifest = shared_raft::ArtifactBatchManifest::new(
            route,
            vec![crate::service::BlobRef {
                hash: crate::service::Hash(install.package.hash.0),
                len: install.package.len,
            }],
        )
        .map_err(|_| SharedAgentHostError::InvalidCatalog)?;
        let deadline = Instant::now() + ORDERED_REPLY_WAIT;
        let receive =
            |request: ForwardedSharedInstallRequest| -> Result<u64, SharedAgentHostError> {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .ok_or(SharedAgentHostError::Unavailable)?;
                self.network
                    .send_agent_forwarded_shared_install(leader, self.route, request)
                    .recv_timeout(remaining)
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                    .ok_or(SharedAgentHostError::Unavailable)
            };
        let mut offset = receive(transfer.clone())?;
        while offset < install.package.len {
            if !transfer.admits_progress(offset) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            let start =
                usize::try_from(offset).map_err(|_| SharedAgentHostError::InvalidCatalog)?;
            let end = start
                .checked_add(shared_raft::ARTIFACT_CHUNK_DATA_BYTES)
                .ok_or(SharedAgentHostError::InvalidCatalog)?
                .min(package.exact_bytes().len());
            let bytes = package
                .exact_bytes()
                .get(start..end)
                .ok_or(SharedAgentHostError::InvalidCatalog)?;
            let chunk =
                shared_raft::ArtifactChunk::new(manifest.clone(), 0, offset, bytes.to_vec())
                    .map_err(|_| SharedAgentHostError::InvalidCatalog)?;
            transfer.operation = ForwardedSharedInstallOperation::Chunk(chunk);
            let next = receive(transfer.clone())?;
            // A restarted peer may advertise an earlier bounded offset. End
            // this turn; exact retry resumes from a freshly queried progress.
            if next <= offset {
                return Err(SharedAgentHostError::Unavailable);
            }
            offset = next;
        }
        if offset != install.package.len {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        transfer.operation = ForwardedSharedInstallOperation::Finish;
        let _finish_hint = self
            .network
            .send_agent_forwarded_shared_install(leader, self.route, transfer);
        loop {
            let retained = {
                let mut host = self
                    .host
                    .lock()
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                drain_committed(&mut host, self.agent, &self.ordered_replies)?;
                self.forwarded_install_fingerprint(&host)?;
                host.retained_forwarded_shared_install(self.agent, &request, &authority)?
            };
            if let Some((input, outcome, observed_slot)) = retained {
                self.require_ordered_availability(input)?;
                tracing::debug!(
                    phase = "origin_retained",
                    node = ?self.network.agent_node_id(),
                    agent = ?self.agent,
                    route = ?self.route,
                    request = ?request.commitment(),
                    authority = ?authority.commitment(),
                    ?input,
                    after_forward = true,
                    "Shared Install forwarding provenance"
                );
                return Ok(CleanManagementSubmission::Applied {
                    outcome,
                    observed_slot,
                    new_slot: false,
                });
            }
            if Instant::now() >= deadline {
                return Err(SharedAgentHostError::Unavailable);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
