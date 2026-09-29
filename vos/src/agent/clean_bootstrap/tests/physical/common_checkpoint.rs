//! Physical fixed-three system-image checkpoint/catch-up qualification.
//!
//! Voting uses authenticated peer requests. Checkpoint bytes are transferred
//! explicitly by this fixture: this is not generic Raft InstallSnapshot or
//! automatic network image discovery/transfer qualification.

use super::*;
use crate::agent::shared_commit::SharedAgentCommonSnapshotClaim;
use crate::agent::shared_host::{
    CommonCheckpointCrashStage, SharedAgentPortableBackupLimits, SharedAgentSnapshotState,
};
use crate::agent::shared_journal_driver::CleanInvocationReplayRequest;
use crate::network::agent_protocol::AgentGenerationRoute;

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_common_checkpoint_compacts_catches_up_reopens_and_continues() {
    check_fixed_system_pending_cluster_with_checkpoint(true, None, false, Some(Exercise::Healthy));
}

#[derive(Clone, Copy)]
pub(super) enum Exercise {
    Healthy,
    Crash(CommonCheckpointCrashStage),
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_common_checkpoint_recovers_source_and_destination_marker_crashes() {
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        None,
        false,
        Some(Exercise::Crash(CommonCheckpointCrashStage::Marker)),
    );
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_common_checkpoint_recovers_source_and_destination_journal_crashes() {
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        None,
        false,
        Some(Exercise::Crash(CommonCheckpointCrashStage::Journal)),
    );
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_common_checkpoint_recovers_source_and_destination_ledger_crashes() {
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        None,
        false,
        Some(Exercise::Crash(CommonCheckpointCrashStage::Ledger)),
    );
}

fn reopen_owner(
    fixture: &PhysicalFixture,
    directory: &TestDirectory,
    stores: &(
        BootstrapMemoryStore,
        BootstrapMemoryStore,
        IssuerMemoryStore,
    ),
    provider: Arc<MemoryProvider>,
    network: Arc<Network>,
    signer: &mut CountingSigner,
) -> MemoryBootstrapOwner {
    let mut pending = PendingCleanSystemAgentBootstrap::open_with_operation_admission(
        stores.0.clone(),
        stores.1.clone(),
        stores.2.clone(),
        signer,
        || panic!("checkpoint reopen must retain its durable bootstrap plan"),
        directory.host(),
        directory.lock(),
        fixture.plan.pins.space,
        fixture.plan.pins.node,
        fixture.trust.clone(),
        fixture.merge.clone(),
        fixture.finality.clone(),
        provider,
        network,
        None,
        None,
    )
    .unwrap();
    pending.try_complete(signer).unwrap().unwrap()
}

fn query(owner: &MemoryBootstrapOwner, index: usize, nonce: u8) -> AuthorityProjectionQuery {
    let key = SigningKey::from_bytes(&[[NODE_SEED, 0xd2, 0xd3][index]; 32]);
    let public = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32])
        .verifying_key()
        .to_bytes();
    let mut query = AuthorityProjectionQuery {
        authority: owner.authority_target(),
        credential: CredentialId::of_public_key(&public),
        nonce: Hash([nonce; 32]),
        selector: AuthorityProjectionSelector::Credential,
        recovery: None,
        authentication: AuthorityIngressAuthentication::SshNodeAttestation {
            credential_public_key: public,
            node: owner.pins.node,
            request_binding: Hash([nonce.wrapping_add(1); 32]),
            signature: [1; 64],
        },
    };
    let signature = key.sign(&query.signing_bytes()).to_bytes();
    let AuthorityIngressAuthentication::SshNodeAttestation {
        signature: actual, ..
    } = &mut query.authentication
    else {
        unreachable!()
    };
    *actual = signature;
    query
}

fn restart_network(index: usize) -> Arc<Network> {
    let keypair =
        libp2p::identity::Keypair::ed25519_from_bytes([[NODE_SEED, 0xd2, 0xd3][index]; 32])
            .unwrap();
    let peer = keypair.public().to_peer_id();
    let network = Arc::new(Network::start(NetworkConfig {
        keypair,
        local_prefix: crate::network::derive_node_prefix(&peer),
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap: vec![],
        auto_dial_mdns: false,
    }));
    assert!(wait_until(std::time::Duration::from_secs(5), || !network
        .listen_addrs()
        .is_empty()));
    network
}

pub(super) fn exercise(
    leader: usize,
    owners: &mut [Option<MemoryBootstrapOwner>],
    fixtures: &[PhysicalFixture],
    directories: &[TestDirectory],
    stores: &[(
        BootstrapMemoryStore,
        BootstrapMemoryStore,
        IssuerMemoryStore,
    )],
    providers: &[Arc<MemoryProvider>],
    networks: &mut Vec<Arc<Network>>,
    signer: &mut CountingSigner,
    exercise: Exercise,
) {
    let crash = match exercise {
        Exercise::Healthy => None,
        Exercise::Crash(stage) => Some(stage),
    };
    let agent = HostAgentId(fixtures[leader].plan.pins.agent.0);
    let lagger = (leader + 1) % 3;
    let voter = (leader + 2) % 3;
    let mut live_networks: Vec<_> = networks.drain(..).map(Some).collect();
    let lagging_host = Arc::clone(&owners[lagger].as_ref().unwrap().host);
    let lagging_position = lagging_host
        .lock()
        .unwrap()
        .journal_position(agent)
        .unwrap();
    drop(owners[lagger].take());
    stop_network(live_networks[lagger].take().unwrap());

    let source = owners[leader].as_mut().unwrap();
    assert!(wait_until(std::time::Duration::from_secs(15), || source
        ._network_host
        .bootstrap_is_local_leader(agent)
        .unwrap_or(false)));
    let older_query = query(source, leader, 0xaf);
    let older_pending = source
        .prepare_authority_projection(older_query.clone())
        .unwrap();
    let (older_work, older_auth) = older_pending.invocation().unwrap();
    let older_input = source
        .host
        .lock()
        .unwrap()
        .prepare_clean_ordered_operation(
            agent,
            CleanInvocationReplayRequest::Invoke {
                context: RuntimeExecutionContext::Direct,
                work: older_work.clone(),
                authorization: older_auth.clone(),
            },
        )
        .unwrap()
        .input();
    source.invoke_authority_projection(older_query).unwrap();
    let request = query(source, leader, 0xb1);
    let pending = source
        .prepare_authority_projection(request.clone())
        .unwrap();
    let (work, authorization) = pending.invocation().unwrap();
    let work = work.clone();
    let authorization = authorization.clone();
    // A public caller may lose its result before ACK. Keep that exact live
    // result at the checkpoint boundary; do not fabricate unresolved PAP2.
    let identity = source
        .pending_authority_projection_identity(&pending, false)
        .unwrap();
    let invoked = source
        .supervisor_invoke(identity, work.clone(), authorization.clone())
        .unwrap();
    let RuntimeOutcome::Completed(Ok(reply)) = &invoked else {
        panic!("boundary Query must complete: {invoked:?}");
    };
    let Some(crate::actors::value::Value::Bytes(response)) =
        crate::actors::value::Value::try_decode(&reply.reply)
    else {
        panic!("boundary Query must return projection bytes");
    };
    let projection =
        crate::agent::sdk::authority::AuthorityCredentialProjection::decode(&response).unwrap();
    assert_eq!(projection.query, request);
    assert_ne!(projection.principal, PrincipalId::ZERO);
    assert!(source.record.pending_projection.is_none());
    let source_state = source
        .host
        .lock()
        .unwrap()
        .clean_state_commitment(agent)
        .unwrap();
    let boundary_input = source
        .host
        .lock()
        .unwrap()
        .prepare_clean_ordered_operation(
            agent,
            CleanInvocationReplayRequest::Invoke {
                context: RuntimeExecutionContext::Direct,
                work: work.clone(),
                authorization: authorization.clone(),
            },
        )
        .unwrap()
        .input();
    assert!(source.ordered_index_for_test().unwrap() > lagging_position.ordered_index);
    assert_eq!(
        lagging_host
            .lock()
            .unwrap()
            .journal_position(agent)
            .unwrap(),
        lagging_position
    );
    assert!(wait_until(std::time::Duration::from_secs(30), || owners
        [voter]
        .as_ref()
        .unwrap()
        .host
        .lock()
        .unwrap()
        .clean_state_commitment(agent)
        .unwrap()
        == source_state));

    let source = owners[leader].as_mut().unwrap();
    let (candidate, route, old_snapshot, position) = {
        let mut host = source.host.lock().unwrap();
        let candidate = host.request_common_snapshot_compaction(agent).unwrap();
        let status = host.supervisor_attachment_status(agent).unwrap().unwrap();
        let route = AgentGenerationRoute {
            space: source.pins.space,
            agent: source.pins.agent,
            generation: Hash(status.replication_id),
        };
        (
            candidate,
            route,
            host.snapshot_state_for_test(agent).unwrap(),
            host.journal_position(agent).unwrap(),
        )
    };
    let wrong_epoch = SharedAgentCommonSnapshotClaim::new(
        candidate.claim().ordered().clone(),
        candidate.claim().active_committee().clone(),
        candidate.claim().authority_epoch() + 1,
        candidate.claim().ancestry().clone(),
    )
    .unwrap();
    let outsider = crate::agent::local_journal_driver::Ed25519NodeMergeAuthenticator::new(
        libp2p::identity::Keypair::ed25519_from_bytes([0xee; 32]).unwrap(),
    )
    .unwrap();
    assert!(
        outsider
            .sign_common_snapshot_candidate(&candidate)
            .is_none()
    );
    assert_eq!(
        live_networks[leader]
            .as_ref()
            .unwrap()
            .send_agent_common_snapshot_vote(fixtures[voter].plan.pins.node, route, wrong_epoch)
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap()
            .unwrap(),
        None
    );
    let remote = live_networks[leader]
        .as_ref()
        .unwrap()
        .send_agent_common_snapshot_vote(
            fixtures[voter].plan.pins.node,
            route,
            candidate.claim().clone(),
        )
        .recv_timeout(std::time::Duration::from_secs(3))
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(remote.signer().0, fixtures[voter].plan.pins.node.0);
    assert_eq!(
        source.host.lock().unwrap().journal_position(agent).unwrap(),
        position
    );
    assert_eq!(
        source
            .host
            .lock()
            .unwrap()
            .snapshot_state_for_test(agent)
            .unwrap(),
        old_snapshot
    );

    let checkpoint_pending = source
        .prepare_authority_projection(query(source, leader, 0xb3))
        .unwrap();
    let (checkpoint_work, checkpoint_auth) = checkpoint_pending.invocation().unwrap();
    let committee = source.pins.replicas.clone();
    assert_eq!(
        source
            ._network_host
            .certified_common_checkpoint_for_admission(
                agent,
                checkpoint_work,
                checkpoint_auth,
                &committee,
                &RefusingSnapshotSigner(HostNodeId(source.pins.node.0)),
            ),
        Err(SharedAgentHostError::SnapshotCertificateInvalid)
    );
    assert_eq!(
        source.host.lock().unwrap().journal_position(agent).unwrap(),
        position
    );
    assert_eq!(
        source
            .host
            .lock()
            .unwrap()
            .snapshot_state_for_test(agent)
            .unwrap(),
        old_snapshot
    );
    if let Some(stage) = crash {
        source
            .host
            .lock()
            .unwrap()
            .set_common_checkpoint_crash_for_test(stage);
    }
    let installed_result = source
        ._network_host
        .certified_common_checkpoint_for_admission(
            agent,
            checkpoint_work,
            checkpoint_auth,
            &committee,
            fixtures[leader].merge.as_ref(),
        );
    let certificate = if crash.is_some() {
        assert!(
            installed_result.is_err(),
            "injected local checkpoint boundary must interrupt"
        );
        assert!(source.host.lock().unwrap().show(agent).unwrap().is_none());
        drop(owners[leader].take());
        owners[leader] = Some(reopen_owner(
            &fixtures[leader],
            &directories[leader],
            &stores[leader],
            providers[leader].clone(),
            live_networks[leader].as_ref().unwrap().clone(),
            signer,
        ));
        owners[leader]
            .as_ref()
            .unwrap()
            .host
            .lock()
            .unwrap()
            .common_snapshot_certificate_for_test(agent)
            .unwrap()
            .unwrap()
    } else {
        installed_result.unwrap()
    };
    let source = owners[leader].as_mut().unwrap();
    certificate.verify(&committee, candidate.claim()).unwrap();
    assert_eq!(certificate.signatures().len(), 2);
    assert!(
        certificate
            .signatures()
            .iter()
            .all(|signature| signature.signer().0 != fixtures[lagger].plan.pins.node.0)
    );
    let limits = SharedAgentPortableBackupLimits {
        max_objects: 4096,
        max_blobs: 4096,
        max_index_nodes: 4096,
        max_bytes: 64 * 1024 * 1024,
    };
    let (bytes, installed, source_store) = {
        let mut host = source.host.lock().unwrap();
        assert_eq!(host.clean_state_commitment(agent).unwrap(), source_state);
        let installed = host.snapshot_state_for_test(agent).unwrap();
        assert_ne!(installed, old_snapshot);
        (
            host.export_common_checkpoint(agent, limits).unwrap(),
            installed,
            host.journal_store_instance_for_test(agent).unwrap(),
        )
    };
    assert!(matches!(
        installed,
        SharedAgentSnapshotState::Installed { .. }
    ));
    for index in [leader, voter] {
        let mut host = owners[index].as_ref().unwrap().host.lock().unwrap();
        let boundary = candidate.claim().ordered();
        host.verify_ordered_availability(
            agent,
            boundary.raft_index(),
            boundary.raft_term(),
            boundary.commitment(),
        )
        .unwrap();
        if index == leader {
            assert!(host.available_ordered_claim(agent, older_input).is_err());
        }
    }
    // The third replica remains detached and disconnected throughout import;
    // the live donor cannot silently fill its raw log behind this assertion.
    {
        let mut destination = lagging_host.lock().unwrap();
        let before = destination.show(agent).unwrap().unwrap();
        let mut changed = bytes.clone();
        let offset = changed.len() / 2;
        changed[offset] ^= 0x80;
        assert!(
            destination
                .restore_common_checkpoint(&changed, limits)
                .is_err()
        );
        assert_eq!(destination.show(agent).unwrap().unwrap(), before);
        assert_eq!(
            destination.journal_position(agent).unwrap(),
            lagging_position
        );
        if let Some(stage) = crash {
            destination.set_common_checkpoint_crash_for_test(stage);
        }
        let imported_result = destination.restore_common_checkpoint(&bytes, limits);
        if crash.is_some() {
            assert!(
                imported_result.is_err(),
                "injected import boundary must interrupt"
            );
            assert!(destination.show(agent).unwrap().is_none());
        } else {
            imported_result.unwrap();
            assert_eq!(
                destination.clean_state_commitment(agent).unwrap(),
                source_state
            );
            assert_eq!(destination.journal_position(agent).unwrap(), position);
            assert_ne!(
                destination.journal_store_instance_for_test(agent).unwrap(),
                source_store
            );
            assert!(
                destination
                    .retained_terminal_projection_invoke(agent, &work, &authorization)
                    .unwrap()
            );
            assert!(
                !destination
                    .retained_positive_clean_acknowledgement(agent, &work, &authorization)
                    .unwrap()
            );
            assert!(
                destination
                    .available_ordered_claim(agent, older_input)
                    .is_err()
            );
            let imported = destination.show(agent).unwrap().unwrap();
            assert_eq!(
                destination
                    .restore_common_checkpoint(&bytes, limits)
                    .unwrap(),
                imported
            );
            assert_eq!(destination.show(agent).unwrap().unwrap(), imported);
        }
    }
    drop(lagging_host);

    live_networks[lagger] = Some(restart_network(lagger));
    for index in [leader, voter] {
        live_networks[lagger]
            .as_ref()
            .unwrap()
            .connect(live_networks[index].as_ref().unwrap().listen_addrs()[0].clone());
    }
    let reopen = |index: usize, signer: &mut CountingSigner| {
        reopen_owner(
            &fixtures[index],
            &directories[index],
            &stores[index],
            providers[index].clone(),
            live_networks[index].as_ref().unwrap().clone(),
            signer,
        )
    };
    owners[lagger] = Some(reopen(lagger, signer));
    {
        let mut host = owners[lagger].as_ref().unwrap().host.lock().unwrap();
        assert_eq!(host.journal_position(agent).unwrap(), position);
        assert_eq!(host.clean_state_commitment(agent).unwrap(), source_state);
        assert_ne!(
            host.journal_store_instance_for_test(agent).unwrap(),
            source_store
        );
        assert_eq!(
            host.common_snapshot_certificate_for_test(agent).unwrap(),
            Some(certificate.clone())
        );
        assert!(host.available_ordered_claim(agent, older_input).is_err());
    }
    drop(owners[leader].take());
    owners[leader] = Some(reopen(leader, signer));
    assert!(wait_until(std::time::Duration::from_secs(30), || {
        live_networks
            .iter()
            .flatten()
            .all(|network| network.connected_peers().len() == 2)
    }));
    assert!(wait_until(std::time::Duration::from_secs(30), || owners
        .iter()
        .flatten()
        .filter(|owner| owner
            ._network_host
            .bootstrap_is_local_leader(agent)
            .unwrap_or(false))
        .count()
        == 1));
    for owner in owners.iter().flatten() {
        assert_eq!(
            owner
                .host
                .lock()
                .unwrap()
                .clean_state_commitment(agent)
                .unwrap(),
            source_state
        );
        let retained = owner
            .host
            .lock()
            .unwrap()
            .prepare_clean_ordered_operation(
                agent,
                crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                    context: RuntimeExecutionContext::Direct,
                    work: work.clone(),
                    authorization: authorization.clone(),
                },
            )
            .unwrap();
        assert_eq!(retained.retained(), Some(&invoked));
        assert_eq!(retained.input(), boundary_input);
        for changed_authorization in [false, true] {
            let mut altered_work = work.clone();
            let InvocationAuthorization::PublicPreflight(preflight) = &authorization else {
                unreachable!()
            };
            if !changed_authorization {
                altered_work.gas -= 1;
            }
            let altered_auth = InvocationAuthorization::PublicPreflight(
                crate::agent_sdk::PublicPreflight::for_work(
                    &altered_work,
                    preflight.observed_slot + u64::from(changed_authorization),
                ),
            );
            let before = owner.ordered_index_for_test().unwrap();
            let altered = owner.host.lock().unwrap().prepare_clean_ordered_operation(
                agent,
                CleanInvocationReplayRequest::Invoke {
                    context: RuntimeExecutionContext::Direct,
                    work: altered_work,
                    authorization: altered_auth,
                },
            );
            assert!(
                altered
                    .as_ref()
                    .map_or(true, |prepared| prepared.retained() != Some(&invoked))
            );
            assert_eq!(owner.ordered_index_for_test().unwrap(), before);
        }
        assert!(owner.record.pending_projection.is_none());
    }
    let successor = owners
        .iter()
        .position(|owner| {
            owner
                .as_ref()
                .unwrap()
                ._network_host
                .bootstrap_is_local_leader(agent)
                .unwrap_or(false)
        })
        .unwrap();
    let owner = owners[successor].as_mut().unwrap();
    let before_retry = owner.ordered_index_for_test().unwrap();
    let identity = owner
        .pending_authority_projection_identity(&pending, false)
        .unwrap();
    assert_eq!(
        owner
            .supervisor_invoke(identity, work.clone(), authorization.clone())
            .unwrap(),
        invoked
    );
    assert_eq!(owner.ordered_index_for_test().unwrap(), before_retry);
    let acknowledged = owner
        .supervisor_acknowledge(identity, work.clone(), authorization.clone())
        .unwrap();
    let RuntimeOutcome::Acknowledged(Ok(acknowledged)) = acknowledged else {
        panic!("recovered boundary result must positively acknowledge");
    };
    assert_eq!(acknowledged.invocation, work.invocation);
    assert_eq!(acknowledged.actor, work.actor);
    assert_eq!(acknowledged.work, work.commitment());
    assert_eq!(acknowledged.authorization, authorization.commitment());
    assert_eq!(owner.ordered_index_for_test().unwrap(), before_retry + 1);
    let fresh = query(owner, successor, 0xb5);
    let before = owner.ordered_index_for_test().unwrap();
    let fresh_response = owner.invoke_authority_projection(fresh.clone()).unwrap();
    let projection =
        crate::agent::sdk::authority::AuthorityCredentialProjection::decode(&fresh_response)
            .unwrap();
    assert_eq!(projection.query, fresh);
    assert_ne!(projection.principal, PrincipalId::ZERO);
    assert_eq!(owner.ordered_index_for_test().unwrap(), before + 2);
    let continued = owner
        .host
        .lock()
        .unwrap()
        .clean_state_commitment(agent)
        .unwrap();
    let expected_common = owner
        .host
        .lock()
        .unwrap()
        .request_common_snapshot_compaction(agent)
        .unwrap()
        .claim()
        .clone();
    for owner in owners.iter().flatten() {
        assert!(wait_until(std::time::Duration::from_secs(30), || owner
            .host
            .lock()
            .unwrap()
            .clean_state_commitment(agent)
            .unwrap()
            == continued));
        assert_eq!(
            owner
                .host
                .lock()
                .unwrap()
                .request_common_snapshot_compaction(agent)
                .unwrap()
                .claim(),
            &expected_common,
            "source, imported replica, and uncompacted voter must derive one complete claim"
        );
    }
    // Reopen an imported owner after real post-checkpoint work. Recovery must
    // preserve the common ancestry while replaying its newly retained suffix.
    drop(owners[lagger].take());
    owners[lagger] = Some(reopen(lagger, signer));
    assert_eq!(
        owners[lagger]
            .as_ref()
            .unwrap()
            .host
            .lock()
            .unwrap()
            .clean_state_commitment(agent)
            .unwrap(),
        continued
    );
    assert!(wait_until(std::time::Duration::from_secs(30), || owners
        .iter()
        .flatten()
        .any(|owner| owner
            ._network_host
            .bootstrap_is_local_leader(agent)
            .unwrap_or(false))));
    let successor = owners
        .iter()
        .position(|owner| {
            owner
                .as_ref()
                .unwrap()
                ._network_host
                .bootstrap_is_local_leader(agent)
                .unwrap_or(false)
        })
        .unwrap();
    // This qualification-only second compaction demonstrates the explicit
    // contract limit: acknowledged old projection bytes are not a durable
    // response archive. Production compaction stays disabled while remote
    // unresolved PAP2 metadata can still require that history.
    let owner = owners[successor].as_mut().unwrap();
    let checkpoint = owner
        .prepare_authority_projection(query(owner, successor, 0xb7))
        .unwrap();
    let (checkpoint_work, checkpoint_auth) = checkpoint.invocation().unwrap();
    owner
        ._network_host
        .certified_common_checkpoint_for_admission(
            agent,
            checkpoint_work,
            checkpoint_auth,
            &committee,
            fixtures[successor].merge.as_ref(),
        )
        .unwrap();
    assert_eq!(
        owner
            .host
            .lock()
            .unwrap()
            .retained_acknowledged_projection(agent, &work)
            .unwrap(),
        None
    );
    assert_eq!(owner.committed_projection_response(&work).unwrap(), None);
    *networks = live_networks.into_iter().map(Option::unwrap).collect();
}
