//! Bounded freshness coordination for internal System observations.
//!
//! No observation is appended, registered, retained, or executed by a peer.
//! The leader reuses Raft ReadIndex; each receiving voter applies its own
//! authenticated prefix and runs the read-only guest on its own pinned state.

use super::*;

fn causal_observation_started() -> Option<Instant> {
    std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS")
        .is_some()
        .then(Instant::now)
}

fn causal_observation_status(error: &SharedAgentHostError) -> &'static str {
    match error {
        SharedAgentHostError::Unavailable => "unavailable",
        SharedAgentHostError::DirectoryInUse => "directory_in_use",
        SharedAgentHostError::InvalidScope => "invalid_scope",
        SharedAgentHostError::ScopeMismatch => "scope_mismatch",
        SharedAgentHostError::InvalidProvision => "invalid_provision",
        SharedAgentHostError::Finality(_) => "finality",
        SharedAgentHostError::InvalidCatalog => "invalid_catalog",
        SharedAgentHostError::Conflict => "conflict",
        SharedAgentHostError::CorruptResidue => "corrupt_residue",
        SharedAgentHostError::AgentNotFound => "agent_not_found",
        SharedAgentHostError::CapacityExhausted => "capacity_exhausted",
        SharedAgentHostError::TransportNotAttached => "transport_not_attached",
        SharedAgentHostError::SnapshotBoundaryRequired => "snapshot_boundary_required",
        SharedAgentHostError::SnapshotCertificateInvalid => "snapshot_certificate_invalid",
        SharedAgentHostError::SnapshotStale => "snapshot_stale",
        SharedAgentHostError::SnapshotReplay => "snapshot_replay",
        SharedAgentHostError::SnapshotEvidenceLimit => "snapshot_evidence_limit",
        SharedAgentHostError::PortableBackupUnsupported => "portable_backup_unsupported",
        SharedAgentHostError::PortableBackupInvalid => "portable_backup_invalid",
    }
}

fn report_causal_observation(
    started: Option<Instant>,
    request: Hash,
    agent: crate::service::AgentId,
    node: Option<[u8; 32]>,
    phase: &'static str,
    status: &'static str,
    count: usize,
) {
    if let Some(started) = started {
        tracing::debug!(request = ?request.0, agent = ?agent.0, node = ?node,
            phase, status, elapsed_us = started.elapsed().as_micros() as u64, count,
            thread = ?std::thread::current().id(), "VOS causal observation");
    }
}

fn fixed_observation_scope(
    fingerprint: &AttachmentFingerprint,
    local: NodeId,
) -> Result<(), SharedAgentHostError> {
    if fingerprint.members.len() != 3
        || fingerprint.voters.len() != 3
        || !valid_nodes(&fingerprint.voters)
        || fingerprint.local_role != ReplicaRole::Voter
        || fingerprint.next_committee.is_some()
        || fingerprint.next_voters.is_some()
        || fingerprint.joint_old.is_some()
        || !fingerprint
            .members
            .iter()
            .map(|(node, _)| *node)
            .eq(fingerprint.voters.iter().copied())
        || fingerprint.voters.binary_search(&local).is_err()
    {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    Ok(())
}

fn observation_configuration(
    snapshot: &vos_raft::WorkerSnapshot<NodeId>,
    fingerprint: &AttachmentFingerprint,
) -> Result<u64, SharedAgentHostError> {
    let configuration = snapshot
        .active_config_index
        .ok_or(SharedAgentHostError::Unavailable)?;
    if snapshot.members != fingerprint.voters
        || snapshot.joint_old.is_some()
        || snapshot.retirement_final_index.is_some()
        || configuration > snapshot.commit_index
    {
        return Err(SharedAgentHostError::Unavailable);
    }
    Ok(configuration)
}

fn observation_term_matches(
    snapshot: &vos_raft::WorkerSnapshot<NodeId>,
    fingerprint: &AttachmentFingerprint,
    local: NodeId,
    barrier: AuthorityReadBarrier,
) -> Result<(), SharedAgentHostError> {
    let configuration = observation_configuration(snapshot, fingerprint)?;
    let leader = match snapshot.role {
        vos_raft::Role::Leader => Some(local),
        vos_raft::Role::Follower => snapshot.leader_hint,
        _ => None,
    };
    if !barrier.is_valid()
        || snapshot.current_term != barrier.raft_term
        || configuration != barrier.configuration_index
        || leader != Some(barrier.leader)
        || fingerprint.voters.binary_search(&barrier.leader).is_err()
    {
        return Err(SharedAgentHostError::Unavailable);
    }
    Ok(())
}

fn observation_local_prefix(
    meta: &RaftMeta,
    applied: u64,
    term_at_read_index: Option<u64>,
    barrier: AuthorityReadBarrier,
) -> Result<(), SharedAgentHostError> {
    if !barrier.is_valid()
        || applied < barrier.read_index
        || meta.current_term != barrier.raft_term
        || meta.commit_index < applied
        || meta.last_applied != applied
        || term_at_read_index != Some(barrier.raft_term)
    {
        return Err(SharedAgentHostError::Unavailable);
    }
    Ok(())
}

impl SharedRouteHandler {
    /// Caller holds the exact generation's lifecycle lease. Neither the host
    /// nor proposal mutex is held across worker/quorum I/O.
    pub(super) fn authority_read_barrier(
        &self,
        request: AuthorityReadBarrierRequest,
        sender: NodeId,
        timeout: Duration,
    ) -> Result<AuthorityReadBarrier, SharedAgentHostError> {
        if request.request == Hash::ZERO || !self.management_retention || timeout.is_zero() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let local = self.network.agent_node_id();
        let fingerprint = {
            let host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let status = host
                .supervisor_attachment_status(self.agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            if status.transport != SharedAgentTransportState::Attached {
                return Err(SharedAgentHostError::TransportNotAttached);
            }
            AttachmentFingerprint::from_attachment_status(&status)?
        };
        fixed_observation_scope(&fingerprint, local)?;
        if fingerprint.protocol_route != self.route
            || fingerprint.voters.binary_search(&sender).is_err()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let worker = self
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let before = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        let configuration_index = observation_configuration(&before, &fingerprint)?;
        if before.role != vos_raft::Role::Leader {
            return Err(SharedAgentHostError::Unavailable);
        }
        // This is the freshness proof under the existing authenticated-CFT
        // contract. Local role/commit samples before and after only fence its
        // exact term/configuration; they never substitute for fresh quorum.
        let causal_read_started = causal_observation_started();
        let read_index = futures_executor::block_on(worker.read_index_with_timeout(timeout))
            .map_err(|_| SharedAgentHostError::Unavailable);
        report_causal_observation(causal_read_started, request.request, self.agent, Some(local.0),
            "leader_read_index", read_index.as_ref().map_or_else(causal_observation_status, |_| "ok"), 0);
        let read_index = read_index?;
        let after = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        let barrier = AuthorityReadBarrier {
            request: request.request,
            leader: local,
            raft_term: before.current_term,
            read_index,
            configuration_index,
        };
        observation_term_matches(&after, &fingerprint, local, barrier)?;
        if after.role != vos_raft::Role::Leader || after.commit_index < read_index {
            return Err(SharedAgentHostError::Unavailable);
        }
        let host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let status = host
            .supervisor_attachment_status(self.agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if status.transport != SharedAgentTransportState::Attached
            || AttachmentFingerprint::from_attachment_status(&status)? != fingerprint
        {
            return Err(SharedAgentHostError::Unavailable);
        }
        Ok(barrier)
    }
}

impl SharedAgentNetworkHost {
    /// Establish bounded fresh System state, apply the receiver's own prefix,
    /// then execute only a read-only local observation under the same lease.
    /// The callback cannot publish or re-enter this host/network coordinator.
    pub(crate) fn with_authority_observation<T>(
        &self,
        agent: crate::service::AgentId,
        request: Hash,
        observe: impl FnOnce(&SharedAgentHost) -> Result<T, SharedAgentHostError>,
    ) -> Result<T, SharedAgentHostError> {
        let causal_started = causal_observation_started();
        let causal_node = causal_started.map(|_| self.network.agent_node_id().0);
        let causal_event = |phase_started, phase, status, count| {
            report_causal_observation(phase_started, request, agent, causal_node, phase, status, count);
        };
        // Refusals report call elapsed time; successful phase records report
        // their own duration. Neither supplies freshness or authorization.
        let causal_refused = |phase, error: SharedAgentHostError| {
            causal_event(causal_started, phase, causal_observation_status(&error), 0);
            error
        };
        causal_event(causal_started, "start", "enter", 0);
        if request == Hash::ZERO || !self.system_agents.contains(&agent) {
            return Err(causal_refused("scope", SharedAgentHostError::ScopeMismatch));
        }
        let started = Instant::now();
        let deadline = started + ORDERED_REPLY_WAIT;
        let attached = self
            .generations
            .get(&agent)
            .ok_or_else(|| causal_refused("generation", SharedAgentHostError::TransportNotAttached))?;
        if let Some(started) = causal_started {
            let route = attached.fingerprint.protocol_route;
            tracing::debug!(request = ?request.0, agent = ?agent.0, node = ?causal_node,
                space = ?route.space.0, generation = ?route.generation.0,
                phase = "binding", status = "ok", elapsed_us = started.elapsed().as_micros() as u64,
                count = 0usize, thread = ?std::thread::current().id(), "VOS causal observation");
        }
        let causal_lifecycle_started = causal_observation_started();
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| causal_refused("lifecycle_wait", SharedAgentHostError::Unavailable))?;
        causal_event(causal_lifecycle_started, "lifecycle_wait", "ok", 0);
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(causal_refused("live", SharedAgentHostError::TransportNotAttached));
        }
        let local = self.network.agent_node_id();
        fixed_observation_scope(&attached.fingerprint, local)
            .map_err(|error| causal_refused("fixed_scope", error))?;
        let worker = attached
            .coordinator
            .worker
            .as_ref()
            .ok_or_else(|| causal_refused("worker", SharedAgentHostError::TransportNotAttached))?;
        let causal_snapshot_started = causal_observation_started();
        let initial = futures_executor::block_on(worker.snapshot())
            .ok_or_else(|| causal_refused("initial_snapshot", SharedAgentHostError::Unavailable))?;
        causal_event(causal_snapshot_started, "initial_snapshot", "ok", 0);
        observation_configuration(&initial, &attached.fingerprint)
            .map_err(|error| causal_refused("configuration", error))?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(causal_refused("remaining", SharedAgentHostError::Unavailable));
        }
        let input = AuthorityReadBarrierRequest { request };
        let causal_barrier_started = causal_observation_started();
        let barrier = if initial.role == vos_raft::Role::Leader {
            attached
                .coordinator
                .authority_read_barrier(input, local, remaining)
                .map_err(|error| causal_refused("fresh_barrier_local", error))?
        } else {
            let leader = initial
                .leader_hint
                .filter(|leader| {
                    *leader != local && attached.fingerprint.voters.binary_search(leader).is_ok()
                })
                .ok_or_else(|| causal_refused("leader_hint", SharedAgentHostError::Unavailable))?;
            self.network
                .send_agent_authority_read_barrier(
                    leader,
                    attached.fingerprint.protocol_route,
                    input,
                )
                .recv_timeout(remaining)
                .map_err(|_| causal_refused("barrier_wait", SharedAgentHostError::Unavailable))?
                .map_err(|_| causal_refused("barrier_transport", SharedAgentHostError::Unavailable))?
                .ok_or_else(|| causal_refused("barrier_missing", SharedAgentHostError::Unavailable))?
        };
        causal_event(causal_barrier_started, "fresh_barrier", "ok", 0);
        if barrier.request != request {
            return Err(causal_refused("barrier_correlation", SharedAgentHostError::ScopeMismatch));
        }
        loop {
            if Instant::now() >= deadline || attached.stale.load(Ordering::Acquire) {
                return Err(causal_refused("loop_deadline_or_stale", SharedAgentHostError::Unavailable));
            }
            // No host/proposal mutex crosses this worker mailbox operation.
            let causal_snapshot_started = causal_observation_started();
            let snapshot = futures_executor::block_on(worker.snapshot())
                .ok_or_else(|| causal_refused("worker_snapshot", SharedAgentHostError::Unavailable))?;
            causal_event(causal_snapshot_started, "worker_snapshot", "ok", 0);
            observation_term_matches(&snapshot, &attached.fingerprint, local, barrier)
                .map_err(|error| causal_refused("term_config", error))?;
            if snapshot.commit_index < barrier.read_index {
                causal_event(causal_started, "commit_wait", "pending", 0);
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            let causal_host_started = causal_observation_started();
            let mut host = self
                .host
                .lock()
                .map_err(|_| causal_refused("host_wait", SharedAgentHostError::Unavailable))?;
            causal_event(causal_host_started, "host_wait", "ok", 0);
            let status = host
                .supervisor_attachment_status(agent)
                .map_err(|error| causal_refused("attachment", error))?
                .ok_or_else(|| causal_refused("attachment", SharedAgentHostError::AgentNotFound))?;
            if status.transport != SharedAgentTransportState::Attached
                || AttachmentFingerprint::from_attachment_status(&status)
                    .map_err(|error| causal_refused("attachment", error))? != attached.fingerprint
            {
                return Err(causal_refused("attachment", SharedAgentHostError::Unavailable));
            }
            // Apply only through the needed committed frontier, not an
            // unbounded drain chasing unrelated concurrent future proposals.
            // Keep this call-local audited cursor under the uninterrupted
            // host guard. Re-audit only after actual application progress;
            // collecting volatile replies cannot advance this cursor.
            let causal_audit_started = causal_observation_started();
            let mut applied = host.capacity(agent)
                .map_err(|error| causal_refused("initial_audit", error))?.0;
            causal_event(causal_audit_started, "initial_audit", "ok", 0);
            while applied < barrier.read_index {
                if Instant::now() >= deadline {
                    return Err(causal_refused("apply_deadline", SharedAgentHostError::Unavailable));
                }
                let causal_apply_started = causal_observation_started();
                let outcome = host.apply_next(agent).map_err(|error| causal_refused("apply_step", error))?;
                let causal_apply_status = match &outcome {
                    SharedAgentApplyOutcome::Applied { .. } => "applied",
                    SharedAgentApplyOutcome::Duplicate { .. } => "duplicate",
                    SharedAgentApplyOutcome::Idle => "idle",
                };
                match outcome {
                    SharedAgentApplyOutcome::Applied { .. }
                    | SharedAgentApplyOutcome::Duplicate { .. } => {
                        causal_event(causal_apply_started, "apply_step", causal_apply_status, 1);
                        let causal_audit_started = causal_observation_started();
                        let previous_applied = applied;
                        applied = host.capacity(agent)
                            .map_err(|error| causal_refused("apply_audit", error))?.0;
                        causal_event(causal_audit_started, "apply_audit",
                            if applied > previous_applied { "advanced" } else { "unchanged" },
                            usize::from(applied > previous_applied));
                    }
                    SharedAgentApplyOutcome::Idle => {
                        causal_event(causal_apply_started, "apply_step", "idle", 0);
                        break;
                    }
                }
            }
            let causal_collect_started = causal_observation_started();
            attached
                .coordinator
                .ordered_replies
                .collect_from(&mut host, agent)
                .map_err(|error| causal_refused("reply_collect", error))?;
            causal_event(causal_collect_started, "reply_collect", "ok", 0);
            if applied < barrier.read_index {
                causal_event(causal_started, "apply_wait", "pending", 0);
                drop(host);
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            // The local committed index, exact term at R and audited apply
            // cursor establish no-op/control linkage too. Actor state may
            // last have changed before R, so do not compare an OrderedClaim
            // index with the Raft read index. Pruned R is retryable, not an
            // invitation to trust a missing term or fabricate old evidence.
            let causal_prefix_started = causal_observation_started();
            let database = host.raft_database(agent)
                .map_err(|error| causal_refused("local_prefix", error))?;
            let meta =
                RaftMeta::load(&database).map_err(|_| causal_refused("local_prefix", SharedAgentHostError::CorruptResidue))?;
            let log = RaftLog::open(database)
                .map_err(|_| causal_refused("local_prefix", SharedAgentHostError::CorruptResidue))?;
            observation_local_prefix(
                &meta,
                applied,
                log.term_at(barrier.read_index)
                    .map_err(|_| causal_refused("local_prefix", SharedAgentHostError::CorruptResidue))?,
                barrier,
            ).map_err(|error| causal_refused("local_prefix", error))?;
            causal_event(causal_prefix_started, "local_prefix", "ok", 0);
            let current = worker
                .cached_snapshot()
                .ok_or_else(|| causal_refused("pre_snapshot", SharedAgentHostError::Unavailable))?;
            observation_term_matches(&current, &attached.fingerprint, local, barrier)
                .map_err(|error| causal_refused("pre_term_config", error))?;
            if Instant::now() >= deadline {
                return Err(causal_refused("pre_deadline", SharedAgentHostError::Unavailable));
            }
            host.validate_observation_owner(agent)
                .map_err(|error| causal_refused("pre_owner", error))?;
            let refused = |phase: &'static str, error| {
                if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                    tracing::debug!(phase, elapsed_us = started.elapsed().as_micros(),
                        "Authority observation terminal guard refused");
                }
                causal_event(causal_started, phase, causal_observation_status(&error), 0);
                error
            };
            let causal_callback_started = causal_observation_started();
            causal_event(causal_callback_started, "callback", "enter", 0);
            let outcome = observe(&host).map_err(|error| refused("callback", error))?;
            causal_event(causal_callback_started, "callback", "ok", 0);
            // Guest execution is bounded separately. A changed leader or
            // configuration during it discards this observation; no durable
            // query/result has been created and no cleanup proof is needed.
            let causal_post_started = causal_observation_started();
            let current = worker
                .cached_snapshot()
                .ok_or_else(|| refused("snapshot", SharedAgentHostError::Unavailable))?;
            observation_term_matches(&current, &attached.fingerprint, local, barrier)
                .map_err(|error| refused("term_config", error))?;
            host.validate_observation_owner(agent)
                .map_err(|error| refused("owner", error))?;
            if attached.stale.load(Ordering::Acquire) {
                return Err(refused("stale", SharedAgentHostError::Unavailable));
            }
            if Instant::now() >= deadline {
                return Err(refused("deadline", SharedAgentHostError::Unavailable));
            }
            causal_event(causal_post_started, "post_guard", "ok", 0);
            causal_event(causal_started, "complete", "ok", 0);
            return Ok(outcome);
        }
    }

    /// Exercise the actual fatal-generation drain while an observation holds
    /// its lifecycle read lease. The returned action uses normal retirement;
    /// no lease, cap, or response deadline is changed by this test cut.
    #[cfg(test)]
    pub(crate) fn stage_observation_retirement_for_test(
        &self,
        agent: crate::service::AgentId,
    ) -> Result<Box<dyn FnOnce() + Send>, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        assert!(attached.lifecycle.try_write().is_err());
        attached.stale.store(true, Ordering::Release);
        let network = Arc::clone(&self.network);
        let route = attached.fingerprint.protocol_route;
        let handler = Arc::clone(&attached.handler);
        let lifecycle = Arc::clone(&attached.lifecycle);
        Ok(Box::new(move || {
            retire_route_with_lease(&network, route, &handler, &lifecycle);
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint() -> AttachmentFingerprint {
        let mut members = (1..=3)
            .map(|seed| {
                let peer = libp2p::identity::ed25519::SecretKey::try_from_bytes([seed; 32])
                    .map(libp2p::identity::ed25519::Keypair::from)
                    .map(libp2p::identity::Keypair::from)
                    .unwrap()
                    .public()
                    .to_peer_id();
                (NodeId::of_authenticated_peer(&peer.to_bytes()), peer)
            })
            .collect::<Vec<_>>();
        members.sort_unstable_by_key(|(node, _)| *node);
        AttachmentFingerprint {
            protocol_route: AgentGenerationRoute {
                space: vos_agent_sdk::SpaceId([1; 32]),
                agent: vos_agent_sdk::AgentId([2; 32]),
                generation: Hash([3; 32]),
            },
            durable_route: shared_raft::AgentRouteKey::new(
                crate::service::SpaceId([1; 32]),
                crate::service::AgentId([2; 32]),
                crate::agent::journal::AgentJournalGenesisId::new([4; 32]),
                crate::agent::genesis::AgentGenesisAdmissionId::from_bytes([5; 32]),
                crate::agent::genesis::AgentReplicaCommitteeId::from_bytes([6; 32]),
            )
            .unwrap(),
            voters: members.iter().map(|(node, _)| *node).collect(),
            members,
            next_committee: None,
            next_voters: None,
            joint_old: None,
            local_role: ReplicaRole::Voter,
        }
    }

    #[test]
    fn observations_require_exact_fixed_three_voter_scope() {
        let base = fingerprint();
        let local = base.voters[0];
        assert_eq!(fixed_observation_scope(&base, local), Ok(()));
        assert!(fixed_observation_scope(&base, NodeId::ZERO).is_err());
        for fault in 0..8 {
            let mut changed = base.clone();
            match fault {
                0 => {
                    changed.members.pop();
                }
                1 => {
                    changed.voters.pop();
                }
                2 => changed.local_role = ReplicaRole::Observer,
                3 => {
                    changed.next_committee = Some(
                        crate::agent::genesis::AgentReplicaCommitteeId::from_bytes([7; 32]),
                    )
                }
                4 => changed.next_voters = Some(base.voters.clone()),
                5 => changed.joint_old = Some(base.voters.clone()),
                6 => changed.voters.swap(0, 1),
                7 => changed.members.swap(0, 1),
                _ => unreachable!(),
            }
            assert!(
                fixed_observation_scope(&changed, local).is_err(),
                "fault {fault}"
            );
        }
    }

    #[test]
    fn observation_prefix_requires_exact_committed_term_and_audited_apply_cursor() {
        let barrier = AuthorityReadBarrier {
            request: Hash([1; 32]),
            leader: NodeId([2; 32]),
            raft_term: 3,
            read_index: 7,
            configuration_index: 0,
        };
        let meta = RaftMeta {
            current_term: 3,
            commit_index: 9,
            last_applied: 9,
            ..RaftMeta::default()
        };
        assert_eq!(observation_local_prefix(&meta, 9, Some(3), barrier), Ok(()));
        // A newer authenticated actor publication is permitted; an absent
        // pruned Raft term, unapplied cursor or changed term never is.
        for fault in 0..7 {
            let mut changed = meta.clone();
            let mut applied = 9;
            let mut term = Some(3);
            match fault {
                0 => changed.current_term = 4,
                1 => changed.commit_index = 6,
                2 => {
                    applied = 6;
                    changed.last_applied = 6;
                }
                3 => changed.last_applied = 8,
                4 => term = None,
                5 => term = Some(2),
                6 => changed.commit_index = 8,
                _ => unreachable!(),
            }
            assert!(
                observation_local_prefix(&changed, applied, term, barrier).is_err(),
                "fault {fault}"
            );
        }
    }
}
