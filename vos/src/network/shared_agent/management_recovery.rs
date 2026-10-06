//! Original-online-owner forwarding for the fixed-three System lifecycle.
//! Peer replies never authorize local dispatch, publication or cleanup.

use super::*;
use crate::agent::shared_journal_driver::CleanInvocationReplayRequest;
use crate::agent::shared_recovery::management::SharedManagementRecoverySlot;

fn management_operation_wait_member<'a>(
    slot: Option<&'a SharedManagementRecoverySlot>,
    retained: &ManagementRecoveryOperationRequest,
) -> Result<(&'a SharedManagementRecoverySlot, usize), SharedAgentHostError> {
    let slot = slot.ok_or(SharedAgentHostError::ScopeMismatch)?;
    let index = slot
        .members()
        .iter()
        .position(|member| member.commitment().0 == retained.member.0)
        .ok_or(SharedAgentHostError::ScopeMismatch)?;
    if slot.registration().commitment().0 != retained.registration.0 {
        // A delayed signed extension can replace the owner's registration
        // while this exact member waits on peer I/O. Do not authorize the old
        // digest against its successor: retry from a fresh local manifest.
        // Missing or substituted members remain permanent scope refusals.
        return Err(SharedAgentHostError::Conflict);
    }
    Ok((slot, index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::clean_management_intent::ManagementJournalAnchor;
    use crate::agent::journal::OrderedBase;
    use crate::agent::shared_commit::ReplicaCommitSignature;
    use crate::agent::shared_recovery::{
        management_node_for_test, management_observation_for_test,
        management_recovery_fixture_for_test,
    };
    use ed25519_dalek::{Signer as _, SigningKey};

    #[test]
    fn delayed_registration_extension_retries_exact_member_without_accepting_old_scope() {
        let root = management_recovery_fixture_for_test(1, 9);
        let observed = management_observation_for_test(&root, 2, false);
        let anchor = ManagementJournalAnchor {
            genesis: root.generation().genesis(),
            admission: root.generation().admission(),
            runtime: observed.observation().input().runtime.commitment(),
            ordered: OrderedBase::post_genesis(),
        };
        let member =
            SharedManagementRecoveryMember::new(None, anchor.clone(), root.envelope().clone())
                .unwrap();
        let sign = |request: SharedManagementRecoveryRegistrationRequest| {
            let signature = ReplicaCommitSignature::new(
                root.owner(),
                SigningKey::from_bytes(&[1; 32])
                    .sign(&request.signing_message().0)
                    .to_bytes(),
            )
            .unwrap();
            SharedManagementRecoveryRegistration::new(request, signature).unwrap()
        };
        let first = sign(
            SharedManagementRecoveryRegistrationRequest::new(
                root.generation(),
                root.committee(),
                root.owner(),
                root.owner(),
                1,
                None,
                vec![member.clone()],
            )
            .unwrap(),
        );
        let mut manifest = crate::agent::shared_recovery::management_manifest_for_test();
        manifest.apply_management_registration(&first, 1, 3).unwrap();
        manifest.observe(&observed).unwrap();
        let in_flight = ManagementRecoveryOperationRequest {
            registration: Hash(first.commitment().0),
            member: Hash(member.commitment().0),
            operation: ManagementRecoveryOperation::Invoke,
        };
        let before = manifest.management_slot(root.owner()).unwrap();
        assert_eq!(
            management_operation_wait_member(Some(before), &in_flight)
                .unwrap()
                .1,
            0,
        );
        let original_evidence = before.members_evidence()[0].invoke().unwrap().clone();
        let child = management_recovery_fixture_for_test(1, 10);
        let child_member = SharedManagementRecoveryMember::new(
            Some(member.commitment()),
            anchor.clone(),
            child.envelope().clone(),
        )
        .unwrap();
        let extension = sign(
            SharedManagementRecoveryRegistrationRequest::new(
                root.generation(),
                root.committee(),
                root.owner(),
                root.owner(),
                2,
                Some(before.commitment()),
                vec![member.clone(), child_member],
            )
            .unwrap(),
        );
        // Apply the genuine signed prefix extension after the origin selected
        // its request, just as a timed-out metadata delivery can finish later.
        manifest
            .apply_management_registration(&extension, 3, 3)
            .unwrap();
        let current = manifest.management_slot(root.owner()).unwrap();
        assert_eq!(current.origin_owner(), root.owner());
        assert_eq!(
            management_operation_wait_member(Some(current), &in_flight).unwrap_err(),
            SharedAgentHostError::Conflict,
        );
        let fresh = ManagementRecoveryOperationRequest {
            registration: Hash(extension.commitment().0),
            ..in_flight.clone()
        };
        let (slot, index) = management_operation_wait_member(Some(current), &fresh).unwrap();
        assert_eq!(slot.members()[index].envelope(), root.envelope());
        assert_eq!(
            slot.members_evidence()[index].invoke(),
            Some(&original_evidence),
        );
        assert_eq!(
            original_evidence.input_id(),
            observed.observation().input_id(),
        );
        assert_eq!(
            original_evidence.outcome(),
            observed.observation().outcome(),
        );

        assert_eq!(
            management_operation_wait_member(
                manifest.management_slot(management_node_for_test(2)),
                &fresh,
            )
            .unwrap_err(),
            SharedAgentHostError::ScopeMismatch,
        );
        let mut wrong_anchor = anchor;
        wrong_anchor.runtime = crate::service::Hash([0xf1; 32]);
        let substituted =
            SharedManagementRecoveryMember::new(None, wrong_anchor, root.envelope().clone())
                .unwrap();
        for wrong_member in [Hash::ZERO, Hash(substituted.commitment().0)] {
            let wrong = ManagementRecoveryOperationRequest {
                // Changed registration cannot hide a missing or changed member.
                member: wrong_member,
                ..in_flight.clone()
            };
            assert_eq!(
                management_operation_wait_member(Some(current), &wrong).unwrap_err(),
                SharedAgentHostError::ScopeMismatch,
            );
        }
    }
}

impl SharedRouteHandler {
    pub(super) fn management_leader(
        &self,
        snapshot: &vos_raft::WorkerSnapshot<NodeId>,
    ) -> Result<NodeId, SharedAgentHostError> {
        let leader = snapshot
            .leader_hint
            .ok_or(SharedAgentHostError::Unavailable)?;
        if snapshot.role != vos_raft::Role::Follower
            || leader == self.network.agent_node_id()
            || self.route_nodes.binary_search(&leader).is_err()
        {
            return Err(SharedAgentHostError::Unavailable);
        }
        Ok(leader)
    }

    fn management_fingerprint(
        &self,
        host: &SharedAgentHost,
    ) -> Result<
        (
            crate::agent::shared_raft::AgentRouteKey,
            AttachmentFingerprint,
        ),
        SharedAgentHostError,
    > {
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

    pub(super) fn management_metadata_headroom(manifest: &SharedRecoveryManifest) -> usize {
        manifest
            .management_slots()
            .iter()
            .filter(|slot| !slot.is_released())
            .map(|slot| {
                MAX_SHARED_MANAGEMENT_RECOVERY_MEMBERS.saturating_sub(slot.members().len()) + 2
            })
            .sum()
    }

    pub(super) fn handle_management_metadata(
        &self,
        sender: NodeId,
        command: &shared_raft::AgentRaftCommand,
    ) -> Result<(), SharedAgentHostError> {
        let started = std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS")
            .is_some()
            .then(Instant::now);
        let diagnostic = started.map(|_| match command {
            shared_raft::AgentRaftCommand::RegisterManagementRecovery { registration, .. } => (
                "register",
                Some(registration.commitment()),
                registration.request().members().last().map(|member| {
                    ManagementInvocationKey::new(member.work(), member.authorization())
                }),
            ),
            shared_raft::AgentRaftCommand::ReleaseManagementRecovery { release, .. } => {
                ("release", Some(release.commitment()), None)
            }
            _ => ("unsupported", None, None),
        });
        let trace = |phase: &str| {
            if let (Some(started), Some((kind, metadata, key))) = (started, diagnostic) {
                tracing::debug!(
                    node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(),
                    origin = ?sender.0, kind, metadata = ?metadata.map(|value| value.0),
                    invocation = ?key.map(|key| key.invocation.0),
                    work = ?key.map(|key| key.work.0),
                    authorization = ?key.map(|key| key.authorization.0),
                    phase, elapsed_us = started.elapsed().as_micros(),
                    "management_metadata_leader"
                );
            }
        };
        let refused = |phase: &str, error: SharedAgentHostError| {
            trace(phase);
            if started.is_some() {
                tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(),
                    origin = ?sender.0, metadata = ?diagnostic.and_then(|(_, metadata, _)| metadata).map(|value| value.0),
                    phase, ?error, "management_metadata_leader refusal");
            }
            error
        };
        trace("proposal_start");
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| refused("proposal_lock_error", SharedAgentHostError::Unavailable))?;
        trace("proposal_acquired");
        let worker = self
            .worker
            .as_ref()
            .ok_or_else(|| refused("worker_missing", SharedAgentHostError::TransportNotAttached))?;
        trace("before_snapshot_start");
        let before = futures_executor::block_on(worker.snapshot())
            .ok_or_else(|| refused("before_snapshot_missing", SharedAgentHostError::Unavailable))?;
        trace("before_snapshot_complete");
        trace("strict_barrier_start");
        quiescent_proposal_commit(
            before.role,
            before.commit_index,
            before.last_log_index,
            false,
        )
        .map_err(|error| refused("strict_barrier_error", error))?;
        trace("strict_barrier_complete");
        trace("host_wait_start");
        let mut host = self
            .host
            .lock()
            .map_err(|_| refused("host_lock_error", SharedAgentHostError::Unavailable))?;
        trace("host_acquired");
        trace("host_drain_start");
        drain_committed(&mut host, self.agent, &self.ordered_replies)
            .map_err(|error| refused("host_drain_error", error))?;
        trace("host_drained");
        let (route, fingerprint) = self
            .management_fingerprint(&host)
            .map_err(|error| refused("fingerprint_error", error))?;
        if fingerprint.voters.binary_search(&sender).is_err() {
            return Err(refused(
                "sender_scope_error",
                SharedAgentHostError::ScopeMismatch,
            ));
        }
        trace("manifest_start");
        let manifest = host
            .recovery_manifest(self.agent)
            .map_err(|error| refused("manifest_error", error))?;
        trace("manifest_verified");
        #[cfg(test)]
        let capacity_audits_before = host.capacity_audits_for_test(self.agent)?;
        #[cfg(test)]
        let release_preflight_audits_before = if matches!(
            command,
            shared_raft::AgentRaftCommand::ReleaseManagementRecovery { .. }
        ) {
            Some(host.management_preflight_audits_for_test(self.agent)?)
        } else {
            None
        };
        let audited_capacity = match command {
            shared_raft::AgentRaftCommand::RegisterManagementRecovery {
                route: requested,
                registration,
            } if *requested == route && registration.owner().0 == sender.0 => {
                let trace_family = |status: &'static str| {
                    if let Some(started) = started {
                        let request = registration.request();
                        let registration_id = registration.commitment().0;
                        let root_member = request.members().first().map(|member| member.commitment().0);
                        for (member_index, member) in request.members().iter().enumerate() {
                            let key = ManagementInvocationKey::new(member.work(), member.authorization());
                            tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                                route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                                thread = ?std::thread::current().id(),
                                genesis = ?request.generation().genesis().as_bytes(),
                                admission = ?request.generation().admission().as_bytes(),
                                committee = ?request.committee().as_bytes(), owner = ?request.owner().0,
                                origin = ?request.origin_owner().0, registration = ?registration_id,
                                predecessor = ?request.previous().map(|value| value.0), root_member = ?root_member,
                                member_index, member = ?member.commitment().0,
                                parent = ?member.parent().map(|value| value.0),
                                invocation = ?key.invocation.0, work = ?key.work.0, authorization = ?key.authorization.0,
                                sequence = request.sequence(), phase = "family_binding", status,
                                poll = 0u64, elapsed_us = started.elapsed().as_micros(),
                                "VOS causal management");
                        }
                    }
                };
                if manifest
                    .management_slot(registration.owner())
                    .is_some_and(|slot| slot.registration() == registration)
                {
                    trace_family("retained_registration");
                    trace("retained_registration");
                    return Ok(());
                }
                if proposal.checkpoint_gate.is_some() {
                    return Err(refused(
                        "checkpoint_reservation_conflict",
                        SharedAgentHostError::Conflict,
                    ));
                }
                host.validate_management_recovery_registration_with_manifest(
                    self.agent,
                    registration,
                    &manifest,
                )
                .map_err(|error| refused("registration_validation_error", error))?;
                trace_family("signed_registration");
                trace("signed_registration_verified");
                let required = host
                    .management_retention_admission_requirement_with_manifest(
                        self.agent,
                        Some(registration.request()),
                        &manifest,
                    )
                    .map_err(|error| refused("joint_budget_error", error))?
                    .ok_or_else(|| {
                        refused(
                            "joint_budget_missing",
                            SharedAgentHostError::CapacityExhausted,
                        )
                    })?;
                trace("joint_budget_verified");
                let capacity = host
                    .capacity(self.agent)
                    .map_err(|error| refused("capacity_error", error))?;
                let (_, remaining, _) = capacity;
                trace("capacity_verified");
                let old = manifest
                    .management_slot(registration.owner())
                    .filter(|slot| !slot.is_released())
                    .map(|slot| {
                        MAX_SHARED_MANAGEMENT_RECOVERY_MEMBERS.saturating_sub(slot.members().len())
                            + 2
                    })
                    .unwrap_or(0);
                let metadata = Self::management_metadata_headroom(&manifest).saturating_sub(old)
                    + MAX_SHARED_MANAGEMENT_RECOVERY_MEMBERS
                        .saturating_sub(registration.request().members().len())
                    + 3;
                if remaining < required as u64 + metadata as u64 {
                    return Err(refused(
                        "capacity_insufficient",
                        SharedAgentHostError::CapacityExhausted,
                    ));
                }
                // The origin's preview is not authority. Recheck this new
                // exact member against the actual leader state before custody.
                trace("clock_preview_start");
                host.validate_new_management_invocation_clock_with_manifest(
                    self.agent,
                    registration.request(),
                    &manifest,
                )
                .map_err(|error| refused("clock_preview_error", error))?;
                trace("clock_preview_verified");
                capacity
            }
            shared_raft::AgentRaftCommand::ReleaseManagementRecovery {
                route: requested,
                release,
            } if *requested == route && release.request().owner().0 == sender.0 => {
                let trace_release = |status: &'static str| {
                    if let Some(started) = started {
                        let request = release.request();
                        let slot = manifest.management_slot(request.owner());
                        let root = slot.and_then(|slot| slot.members().first());
                        let key = root.map(|member| ManagementInvocationKey::new(member.work(), member.authorization()));
                        tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                            route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                            thread = ?std::thread::current().id(),
                            genesis = ?request.generation().genesis().as_bytes(),
                            admission = ?request.generation().admission().as_bytes(),
                            committee = ?request.committee().as_bytes(), owner = ?request.owner().0,
                            metadata = ?release.commitment().0, scope = ?request.scope().0,
                            registration = ?slot.map(|slot| slot.registration().commitment().0),
                            root_member = ?root.map(|member| member.commitment().0),
                            invocation = ?key.map(|key| key.invocation.0),
                            work = ?key.map(|key| key.work.0), authorization = ?key.map(|key| key.authorization.0),
                            sequence = request.sequence(), phase = "release_binding", status,
                            poll = 0u64, elapsed_us = started.elapsed().as_micros(),
                            "VOS causal management");
                    }
                };
                if manifest
                    .management_slot(release.request().owner())
                    .is_some_and(|slot| slot.release() == Some(release))
                {
                    trace_release("retained_release");
                    trace("retained_release");
                    return Ok(());
                }
                let validated = {
                    let span = started.map(|_| tracing::debug_span!(
                        "vos_causal_release_audit",
                        metadata = ?release.commitment().0,
                        stage = "signed_ledger_validation",
                    ));
                    let _span_guard = span.as_ref().map(|span| span.enter());
                    host.validate_management_recovery_release_and_capacity(self.agent, release)
                };
                let capacity = validated.map_err(|error| refused("release_validation_error", error))?;
                trace("release_capacity_from_preflight");
                trace_release("signed_release");
                capacity
            }
            _ => {
                return Err(refused(
                    "command_scope_error",
                    SharedAgentHostError::ScopeMismatch,
                ));
            }
        };
        // Registration's capacity audit or release's signed settled-prefix
        // preflight supplies this same-call tuple. These uninterrupted guards
        // exclude host publication, reservations and snapshot installation;
        // raw Raft progress still requires the final worker/prefix barriers.
        // Do not retain the tuple across preparation, guard release or a drain.
        let (applied, _, _) = audited_capacity;
        trace("current_snapshot_start");
        let current = futures_executor::block_on(worker.snapshot()).ok_or_else(|| {
            refused(
                "current_snapshot_missing",
                SharedAgentHostError::Unavailable,
            )
        })?;
        trace("current_snapshot_complete");
        trace("final_barrier_start");
        CommittedProposalBarrier::from(&before)
            .validate_applied(CommittedProposalBarrier::from(&current), applied)
            .map_err(|error| refused("final_barrier_error", error))?;
        trace("final_barrier_verified");
        #[cfg(test)]
        if let Some(preflight_before) = release_preflight_audits_before {
            assert_eq!(
                host.capacity_audits_for_test(self.agent)?,
                capacity_audits_before,
                "signed release must derive capacity from its preflight without a generic capacity audit"
            );
            assert_eq!(
                host.management_preflight_audits_for_test(self.agent)?,
                preflight_before + 1,
                "signed release admission must perform exactly one actual fresh management preflight"
            );
        } else {
            assert_eq!(
                host.capacity_audits_for_test(self.agent)?,
                capacity_audits_before + 1,
                "registration admission must perform one actual capacity audit under its uninterrupted guards"
            );
        }
        drop(manifest);
        drop(host);
        trace("commit_start");
        self.commit_management_metadata(worker, &current, &fingerprint, command)
            .map_err(|error| refused("commit_error", error))?;
        trace("commit_complete");
        Ok(())
    }

    pub(super) fn validate_management_custody(
        &self,
        host: &mut SharedAgentHost,
        owner: NodeId,
        registration: Hash,
        member: Hash,
        request: &CleanInvocationReplayRequest,
        clock: InvocationClock<'_>,
        audited_remaining: u64,
        verified_manifest: Option<SharedRecoveryManifest>,
    ) -> Result<(Option<CleanOrderedSubmission>, SharedRecoveryManifest), SharedAgentHostError> {
        let (_, fingerprint) = self.management_fingerprint(host)?;
        if fingerprint.voters.binary_search(&owner).is_err() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        // Only the same uninterrupted post-drain host/proposal guard may lend
        // capacity's manifest, after the driver's full evidence verification.
        // Fresh absence, budget and applied-availability checks remain below.
        let manifest = match verified_manifest {
            Some(manifest) => {
                // Preserve the original lookup's live lease/Agent fence after
                // the worker snapshot, including the retained-capsule path.
                // This existing selector rechecks ownership without rereading
                // or reauditing the same immutable manifest.
                host.management_custody_has_pending_with_manifest(self.agent, &manifest)?;
                manifest
            }
            None => host.recovery_manifest(self.agent)?,
        };
        let slot = manifest
            .management_slot(crate::service::NodeId(owner.0))
            .filter(|slot| slot.registration().commitment().0 == registration.0)
            .ok_or(SharedAgentHostError::Conflict)?;
        let index = slot
            .members()
            .iter()
            .position(|candidate| candidate.commitment().0 == member.0)
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        let candidate = &slot.members()[index];
        if candidate.work() != request.work()
            || candidate.authorization() != request.authorization()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let evidence = match request {
            CleanInvocationReplayRequest::Invoke {
                context: RuntimeExecutionContext::Direct,
                ..
            } if matches!(clock, InvocationClock::PersistedManagement(anchor) if anchor == candidate.anchor()) => {
                slot.members_evidence()[index].invoke()
            }
            CleanInvocationReplayRequest::Acknowledge { .. }
                if slot.members_evidence()[index].invoke().is_some() =>
            {
                slot.members_evidence()[index].acknowledgement()
            }
            _ => return Err(SharedAgentHostError::ScopeMismatch),
        };
        if let Some(evidence) = evidence {
            // The handler may have selected an absent capsule before waiting
            // for proposal exclusion. Its first operation can apply during
            // that wait. Reuse only this freshly authenticated exact member,
            // before budgeting or preparing a row that will not be appended.
            // The caller still proves applied availability after dropping
            // both guards; this observation alone grants no quorum claim.
            return Ok((
                Some(CleanOrderedSubmission {
                    input: Some(evidence.input_id()),
                    outcome: evidence.outcome().clone(),
                    new_slot: false,
                }),
                manifest,
            ));
        }
        #[cfg(test)]
        self.management_custody_budget_checks
            .fetch_add(1, Ordering::Relaxed);
        let required = if matches!(
            (request, clock),
            (CleanInvocationReplayRequest::Acknowledge { .. }, InvocationClock::Current)
                | (CleanInvocationReplayRequest::Invoke {
                    context: RuntimeExecutionContext::Direct,
                    ..
                }, InvocationClock::PersistedManagement(_))
        ) {
            host.management_custody_retention_admission_with_manifest(self.agent, &manifest)?
        } else {
            host.management_retention_admission_requirement(self.agent, None)?
        }
        .ok_or(SharedAgentHostError::CapacityExhausted)?;
        // Supplied by the caller's mandatory post-drain capacity audit and
        // fresh Raft barrier under these same uninterrupted admission guards.
        if audited_remaining
            < required as u64 + Self::management_metadata_headroom(&manifest) as u64
        {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        Ok((None, manifest))
    }

    pub(super) fn handle_management_operation(
        &self,
        sender: NodeId,
        operation: &ManagementRecoveryOperationRequest,
    ) -> Result<(), SharedAgentHostError> {
        let started = std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS")
            .is_some()
            .then(Instant::now);
        let trace = |phase: &str| {
            if let Some(started) = started {
                tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(),
                    origin = ?sender.0, registration = ?operation.registration.0,
                    member = ?operation.member.0, operation = ?operation.operation,
                    phase, elapsed_us = started.elapsed().as_micros(),
                    "management_operation_leader"
                );
            }
        };
        let refused = |phase: &str, error: SharedAgentHostError| {
            trace(phase);
            if started.is_some() {
                tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(),
                    origin = ?sender.0, registration = ?operation.registration.0,
                    member = ?operation.member.0, operation = ?operation.operation,
                    phase, ?error, "management_operation_leader refusal");
            }
            error
        };
        trace("receive");
        let (member, retained_input) = {
            trace("host_wait_start");
            let mut host = self
                .host
                .lock()
                .map_err(|_| refused("host_lock_error", SharedAgentHostError::Unavailable))?;
            trace("host_acquired");
            trace("host_drain_start");
            drain_committed(&mut host, self.agent, &self.ordered_replies)
                .map_err(|error| refused("host_drain_error", error))?;
            trace("host_drained");
            let (_, fingerprint) = self
                .management_fingerprint(&host)
                .map_err(|error| refused("fingerprint_error", error))?;
            if fingerprint.voters.binary_search(&sender).is_err() {
                return Err(refused(
                    "sender_scope_error",
                    SharedAgentHostError::ScopeMismatch,
                ));
            }
            trace("manifest_start");
            let manifest = host
                .recovery_manifest(self.agent)
                .map_err(|error| refused("manifest_error", error))?;
            trace("manifest_verified");
            let slot = manifest
                .management_slot(crate::service::NodeId(sender.0))
                .filter(|slot| slot.registration().commitment().0 == operation.registration.0)
                .ok_or_else(|| {
                    refused(
                        "registration_scope_error",
                        SharedAgentHostError::ScopeMismatch,
                    )
                })?;
            let index = slot
                .members()
                .iter()
                .position(|member| member.commitment().0 == operation.member.0)
                .ok_or_else(|| {
                    refused("member_scope_error", SharedAgentHostError::ScopeMismatch)
                })?;
            if started.is_some() {
                let key = ManagementInvocationKey::new(
                    slot.members()[index].work(),
                    slot.members()[index].authorization(),
                );
                tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(),
                    origin = ?sender.0, registration = ?operation.registration.0,
                    member = ?operation.member.0, invocation = ?key.invocation.0,
                    work = ?key.work.0, authorization = ?key.authorization.0,
                    "management_operation_leader exact member");
            }
            let evidence = match operation.operation {
                ManagementRecoveryOperation::Invoke => slot.members_evidence()[index].invoke(),
                ManagementRecoveryOperation::Acknowledge => {
                    slot.members_evidence()[index].acknowledgement()
                }
            };
            (
                slot.members()[index].clone(),
                evidence.map(|evidence| evidence.input_id()),
            )
        };
        if let Some(input) = retained_input {
            // No new row or headroom is required for an authenticated first
            // capsule. In particular an ACKed approval is not a new denial.
            if started.is_some() {
                tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(),
                    origin = ?sender.0, registration = ?operation.registration.0,
                    member = ?operation.member.0, input = ?input.as_bytes(),
                    "management_operation_leader retained input");
            }
            trace("retained_availability_start");
            self.require_ordered_availability(input)
                .map_err(|error| refused("retained_availability_error", error))?;
            trace("retained_availability_complete");
            return Ok(());
        }
        trace("submit_start");
        let work = member.work().clone();
        let authorization = member.authorization().clone();
        let (request, clock) = match operation.operation {
            ManagementRecoveryOperation::Invoke => (
                CleanInvocationReplayRequest::Invoke {
                    context: RuntimeExecutionContext::Direct,
                    work,
                    authorization,
                },
                InvocationClock::PersistedManagement(member.anchor()),
            ),
            ManagementRecoveryOperation::Acknowledge => (
                CleanInvocationReplayRequest::Acknowledge {
                    work,
                    authorization,
                },
                InvocationClock::Current,
            ),
        };
        self.submit_clean_ordered_operation_with_admission(
            request,
            matches!(operation.operation, ManagementRecoveryOperation::Invoke),
            Some(ReservedSubmission::ManagementCustody {
                owner: sender,
                registration: operation.registration,
                member: operation.member,
            }),
            clock,
        )
        .map_err(|error| refused("submit_error", error))?;
        trace("submit_complete");
        Ok(())
    }

    pub(super) fn forward_management_operation(
        &self,
        request: CleanInvocationReplayRequest,
        clock: InvocationClock<'_>,
    ) -> Result<CleanOrderedSubmission, SharedAgentHostError> {
        let started = std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS")
            .is_some()
            .then(Instant::now);
        let invocation = request.work().invocation;
        let diagnostic_key =
            started.map(|_| ManagementInvocationKey::new(request.work(), request.authorization()));
        let trace = |phase: &str| {
            if let Some(started) = started {
                tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(), invocation = ?invocation.0,
                    work = ?diagnostic_key.map(|key| key.work.0),
                    authorization = ?diagnostic_key.map(|key| key.authorization.0),
                    phase, elapsed_us = started.elapsed().as_micros(),
                    "management_operation_forward"
                );
            }
        };
        let refused = |phase: &str, error: SharedAgentHostError| {
            trace(phase);
            if started.is_some() {
                tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(), invocation = ?invocation.0, phase, ?error,
                    "management_operation_forward refusal");
            }
            error
        };
        trace("start");
        let worker = self
            .worker
            .as_ref()
            .ok_or_else(|| refused("worker_missing", SharedAgentHostError::TransportNotAttached))?;
        trace("before_snapshot_start");
        let before = futures_executor::block_on(worker.snapshot())
            .ok_or_else(|| refused("before_snapshot_missing", SharedAgentHostError::Unavailable))?;
        trace("before_snapshot_complete");
        if started.is_some() {
            tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                thread = ?std::thread::current().id(), invocation = ?invocation.0,
                role = ?before.role, term = before.current_term,
                committed = before.commit_index, last = before.last_log_index,
                "management_operation_forward before barrier"
            );
        }
        trace("strict_barrier_start");
        quiescent_proposal_commit(
            before.role,
            before.commit_index,
            before.last_log_index,
            true,
        )
        .map_err(|error| refused("strict_barrier_error", error))?;
        trace("strict_barrier_complete");
        let leader = self
            .management_leader(&before)
            .map_err(|error| refused("leader_unavailable", error))?;
        let operation = match &request {
            CleanInvocationReplayRequest::Invoke { .. } => ManagementRecoveryOperation::Invoke,
            CleanInvocationReplayRequest::Acknowledge { .. } => {
                ManagementRecoveryOperation::Acknowledge
            }
            _ => {
                return Err(refused(
                    "operation_scope_error",
                    SharedAgentHostError::ScopeMismatch,
                ));
            }
        };
        let retained = {
            trace("prepare_host_wait_start");
            let mut host = self.host.lock().map_err(|_| {
                refused("prepare_host_lock_error", SharedAgentHostError::Unavailable)
            })?;
            trace("prepare_host_acquired");
            trace("prepare_host_drain_start");
            drain_committed(&mut host, self.agent, &self.ordered_replies)
                .map_err(|error| refused("prepare_host_drain_error", error))?;
            trace("host_drained");
            self.management_fingerprint(&host)
                .map_err(|error| refused("prepare_fingerprint_error", error))?;
            trace("prepare_manifest_start");
            let manifest = host
                .recovery_manifest(self.agent)
                .map_err(|error| refused("prepare_manifest_error", error))?;
            trace("prepare_manifest_verified");
            let slot = manifest
                .management_slot(crate::service::NodeId(self.network.agent_node_id().0))
                .ok_or_else(|| {
                    refused(
                        "prepare_registration_scope_error",
                        SharedAgentHostError::ScopeMismatch,
                    )
                })?;
            let member = slot
                .members()
                .iter()
                .find(|member| {
                    member.work() == request.work()
                        && member.authorization() == request.authorization()
                })
                .ok_or_else(|| {
                    refused(
                        "prepare_member_scope_error",
                        SharedAgentHostError::ScopeMismatch,
                    )
                })?;
            if matches!(clock, InvocationClock::PersistedManagement(anchor) if anchor != member.anchor())
            {
                return Err(refused(
                    "anchor_scope_error",
                    SharedAgentHostError::ScopeMismatch,
                ));
            }
            let current = futures_executor::block_on(worker.snapshot()).ok_or_else(|| {
                refused(
                    "current_snapshot_missing",
                    SharedAgentHostError::Unavailable,
                )
            })?;
            if started.is_some() {
                tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(), invocation = ?invocation.0,
                    role = ?current.role, term = current.current_term,
                    committed = current.commit_index, last = current.last_log_index,
                    "management_operation_forward current barrier"
                );
            }
            trace("final_barrier_start");
            CommittedProposalBarrier::from(&before)
                .validate_applied(
                    CommittedProposalBarrier::from(&current),
                    host.capacity(self.agent)
                        .map_err(|error| refused("capacity_error", error))?
                        .0,
                )
                .map_err(|error| refused("final_barrier_error", error))?;
            trace("final_barrier_complete");
            ManagementRecoveryOperationRequest {
                registration: Hash(slot.registration().commitment().0),
                member: Hash(member.commitment().0),
                operation,
            }
        };
        if started.is_some() {
            tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                thread = ?std::thread::current().id(), invocation = ?invocation.0,
                work = ?diagnostic_key.map(|key| key.work.0), authorization = ?diagnostic_key.map(|key| key.authorization.0),
                leader = ?leader.0, registration = ?retained.registration.0,
                member = ?retained.member.0, operation = ?retained.operation,
                "management_operation_forward prepared");
        }
        let deadline = Instant::now() + ORDERED_REPLY_WAIT;
        // Observe first custody locally while the peer works. A missing or
        // delayed scheduling hint cannot contradict a physically verified
        // applied capsule, and no hint can authorize a missing capsule.
        let _reply_hint = self.network.send_agent_management_recovery_operation(
            leader,
            self.route,
            retained.clone(),
        );
        trace("sent");
        trace("local_custody_wait_start");
        #[cfg(test)]
        let mut hint_reported = false;
        let trace_poll = |phase: &'static str, status: &'static str, poll: u64, phase_started: Option<Instant>| {
            if let Some(phase_started) = phase_started {
                tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(), invocation = ?invocation.0,
                    work = ?diagnostic_key.map(|key| key.work.0), authorization = ?diagnostic_key.map(|key| key.authorization.0),
                    registration = ?retained.registration.0, member = ?retained.member.0,
                    operation = ?operation, phase, status, poll,
                    elapsed_us = phase_started.elapsed().as_micros(), "VOS causal management");
            }
        };
        let mut diagnostic_poll = 0u64;
        let mut diagnostic_frontier = None;
        loop {
            #[cfg(test)]
            if !hint_reported && std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                match _reply_hint.try_recv() {
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                    hint => {
                        hint_reported = true;
                        let category = match hint {
                            Ok(_) => "received",
                            Err(std::sync::mpsc::TryRecvError::Disconnected) => "disconnected",
                            Err(std::sync::mpsc::TryRecvError::Empty) => "empty",
                        };
                        tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                            route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                            thread = ?std::thread::current().id(), invocation = ?invocation.0,
                            category, "management_operation_forward reply hint");
                    }
                }
            }
            if started.is_some() {
                diagnostic_poll = diagnostic_poll.saturating_add(1);
            }
            let phase_started = started.map(|_| Instant::now());
            let host_result = self
                .host
                .lock()
                .map_err(|_| refused("wait_host_lock_error", SharedAgentHostError::Unavailable));
            trace_poll("operation_host_wait", if host_result.is_ok() { "ok" } else { "error" }, diagnostic_poll, phase_started);
            let mut host = host_result?;
            let phase_started = started.map(|_| Instant::now());
            let drain_result = drain_committed(&mut host, self.agent, &self.ordered_replies)
                .map_err(|error| refused("wait_host_drain_error", error));
            trace_poll("operation_drain", if drain_result.is_ok() { "ok" } else { "error" }, diagnostic_poll, phase_started);
            drain_result?;
            self.management_fingerprint(&host)
                .map_err(|error| refused("wait_fingerprint_error", error))?;
            let phase_started = started.map(|_| Instant::now());
            let manifest_result = host
                .recovery_manifest(self.agent)
                .map_err(|error| refused("wait_manifest_error", error));
            trace_poll("operation_manifest", if manifest_result.is_ok() { "ok" } else { "error" }, diagnostic_poll, phase_started);
            let manifest = manifest_result?;
            let (slot, index) = management_operation_wait_member(
                manifest.management_slot(crate::service::NodeId(self.network.agent_node_id().0)),
                &retained,
            )
            .map_err(|error| {
                refused(
                    if error == SharedAgentHostError::Conflict {
                        "wait_registration_changed"
                    } else {
                        "wait_member_scope_error"
                    },
                    error,
                )
            })?;
            let evidence = match operation {
                ManagementRecoveryOperation::Invoke => slot.members_evidence()[index].invoke(),
                ManagementRecoveryOperation::Acknowledge => {
                    slot.members_evidence()[index].acknowledgement()
                }
            };
            if let Some(started) = started {
                // Compare only the observed retained position. This is not
                // equality of state bytes or a proof reused by admission.
                let frontier = manifest.management_slots().iter()
                    .map(|slot| slot.last_position()).max().unwrap_or((0, 0));
                tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(), invocation = ?invocation.0,
                    work = ?diagnostic_key.map(|key| key.work.0), authorization = ?diagnostic_key.map(|key| key.authorization.0),
                    registration = ?retained.registration.0, member = ?retained.member.0,
                    operation = ?operation, phase = "operation_poll",
                    status = if evidence.is_some() { "present" } else { "absent" },
                    poll = diagnostic_poll, elapsed_us = started.elapsed().as_micros(),
                    retained_index = frontier.0, retained_term = frontier.1,
                    prior_frontier = diagnostic_frontier.is_some(),
                    retained_frontier_equal = diagnostic_frontier == Some(frontier),
                    "VOS causal management");
                diagnostic_frontier = Some(frontier);
            }
            if let Some(evidence) = evidence {
                let input = evidence.input_id();
                let outcome = evidence.outcome().clone();
                trace("local_evidence");
                if started.is_some() {
                    tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                        route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                        thread = ?std::thread::current().id(), invocation = ?invocation.0,
                        registration = ?retained.registration.0, member = ?retained.member.0,
                        input = ?input.as_bytes(), "management_operation_forward local evidence");
                }
                drop(host);
                trace("availability_start");
                self.require_ordered_availability(input)
                    .map_err(|error| refused("availability_error", error))?;
                trace("availability_complete");
                return Ok(CleanOrderedSubmission {
                    input: Some(input),
                    outcome,
                    new_slot: false,
                });
            }
            drop(host);
            if Instant::now() >= deadline {
                return Err(refused(
                    "custody_timeout",
                    SharedAgentHostError::Unavailable,
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
