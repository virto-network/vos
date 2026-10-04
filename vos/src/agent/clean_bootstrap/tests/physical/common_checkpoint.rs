//! Physical fixed-three system-image checkpoint/catch-up qualification.
//!
//! Voting uses authenticated peer requests. Checkpoint bytes are transferred
//! explicitly by this fixture: this is not generic Raft InstallSnapshot or
//! automatic network image discovery/transfer qualification.

use super::*;

#[cfg(feature = "experimental-state-blocks")]
#[path = "authority_observation.rs"]
mod authority_observation;
#[cfg(feature = "experimental-state-blocks")]
#[path = "forwarded_install_origin.rs"]
mod forwarded_install_origin;
#[cfg(feature = "experimental-state-blocks")]
#[path = "genesis_publication_retry.rs"]
mod genesis_publication_retry;
#[cfg(feature = "experimental-state-blocks")]
#[path = "admin_pending_validation.rs"]
mod admin_pending_validation;
#[cfg(feature = "experimental-state-blocks")]
#[path = "local_install_recovery.rs"]
mod local_install_recovery;
#[path = "management_retention.rs"]
mod management_retention;
use crate::agent::shared_commit::SharedAgentCommonSnapshotClaim;
use crate::agent::shared_host::{
    CommonCheckpointCrashStage, SharedAgentPortableBackupLimits, SharedAgentSnapshotState,
};
use crate::agent::shared_journal_driver::CleanInvocationReplayRequest;
use crate::network::agent_protocol::AgentGenerationRoute;

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_common_checkpoint_compacts_catches_up_reopens_and_continues() {
    check_fixed_system_pending_cluster_with_checkpoint(true, Some(Exercise::Healthy));
}

#[derive(Clone, Copy)]
pub(super) enum Exercise {
    Healthy,
    Crash(CommonCheckpointCrashStage),
    #[cfg(feature = "experimental-state-blocks")]
    AuthorityObservation,
    ManagementRetention,
    ManagementRetentionFollower,
    #[cfg(feature = "experimental-state-blocks")]
    ForwardedInstallOrigin,
    #[cfg(feature = "experimental-state-blocks")]
    GenesisPublicationRetry,
    #[cfg(feature = "experimental-state-blocks")]
    AdminJournalPrewrite,
    #[cfg(feature = "experimental-state-blocks")]
    AdminRegistrationTimeout,
    #[cfg(feature = "experimental-state-blocks")]
    AdminRegistrationTimeoutCold,
    #[cfg(feature = "experimental-state-blocks")]
    LocalImageInstallRegistrationTimeout,
}

#[cfg(feature = "experimental-state-blocks")]
#[test]
#[ignore = "requires fresh Authority/System IMAGE candidates and three authenticated loopback transports"]
fn candidate_shared_publication_exact_retry_readmits_original_leased_stores() {
    assert!(std::env::var_os("AUTHORITY_CANDIDATE_ELF").is_some());
    assert!(std::env::var_os("VOS_AGENT_RUNTIME_COST_CANDIDATE").is_some());
    assert!(std::env::var_os("VOS_AGENT_PROFILE_REFINE_MACHINES").is_some());
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        Some(Exercise::GenesisPublicationRetry),
    );
}

#[cfg(feature = "experimental-state-blocks")]
#[test]
#[ignore = "requires coherent Authority/System IMAGE components and three authenticated loopback transports"]
fn candidate_admin_journal_prewrite_exact_retry_passes_production_recovery_admission() {
    assert!(std::env::var_os("AUTHORITY_CANDIDATE_ELF").is_some());
    assert!(std::env::var_os("VOS_AGENT_RUNTIME_COST_CANDIDATE").is_some());
    assert!(std::env::var_os("VOS_AGENT_PROFILE_REFINE_MACHINES").is_some());
    check_fixed_system_pending_cluster_with_checkpoint(true, Some(Exercise::AdminJournalPrewrite));
}

#[cfg(feature = "experimental-state-blocks")]
#[test]
#[ignore = "requires coherent Authority/System IMAGE components and three authenticated loopback transports"]
fn candidate_admin_registration_timeout_exact_retry_passes_production_recovery_admission() {
    assert!(std::env::var_os("AUTHORITY_CANDIDATE_ELF").is_some());
    assert!(std::env::var_os("VOS_AGENT_RUNTIME_COST_CANDIDATE").is_some());
    assert!(std::env::var_os("VOS_AGENT_PROFILE_REFINE_MACHINES").is_some());
    check_fixed_system_pending_cluster_with_checkpoint(true, Some(Exercise::AdminRegistrationTimeout));
}

#[cfg(feature = "experimental-state-blocks")]
#[test]
#[ignore = "requires coherent Authority/System IMAGE components and three authenticated loopback transports"]
fn candidate_admin_registration_timeout_cold_missing_journal_refuses_adoption() {
    assert!(std::env::var_os("AUTHORITY_CANDIDATE_ELF").is_some());
    assert!(std::env::var_os("VOS_AGENT_RUNTIME_COST_CANDIDATE").is_some());
    assert!(std::env::var_os("VOS_AGENT_PROFILE_REFINE_MACHINES").is_some());
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        Some(Exercise::AdminRegistrationTimeoutCold),
    );
}

#[cfg(feature = "experimental-state-blocks")]
#[test]
#[ignore = "requires coherent Authority/System IMAGE components and three authenticated loopback transports"]
fn candidate_local_image_install_registration_timeout_exact_retry_passes_production_recovery_admission() {
    assert!(std::env::var_os("AUTHORITY_CANDIDATE_ELF").is_some());
    assert!(std::env::var_os("VOS_AGENT_RUNTIME_COST_CANDIDATE").is_some());
    assert!(std::env::var_os("VOS_AGENT_PROFILE_REFINE_MACHINES").is_some());
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        Some(Exercise::LocalImageInstallRegistrationTimeout),
    );
}

#[cfg(feature = "experimental-state-blocks")]
#[test]
#[ignore = "requires fresh Authority/System IMAGE, external runtime, Clerk package and three authenticated loopback transports"]
fn candidate_forwarded_shared_install_refuses_shadow_and_absent_origin_at_receiver() {
    assert!(std::env::var_os("AUTHORITY_CANDIDATE_ELF").is_some());
    assert!(std::env::var_os("VOS_AGENT_RUNTIME_COST_CANDIDATE").is_some());
    assert!(std::env::var_os("VOS_AGENT_PROFILE_REFINE_MACHINES").is_some());
    assert!(std::env::var_os("CLERK_AGENT_PACKAGE").is_some());
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        Some(Exercise::ForwardedInstallOrigin),
    );
}

#[test]
#[ignore = "requires fresh Authority/System IMAGE candidates and three authenticated loopback transports"]
fn candidate_management_create_retention_survives_offline_pruning_then_installs() {
    assert!(std::env::var_os("AUTHORITY_CANDIDATE_ELF").is_some());
    assert!(std::env::var_os("VOS_AGENT_RUNTIME_COST_CANDIDATE").is_some());
    assert!(std::env::var_os("VOS_AGENT_PROFILE_REFINE_MACHINES").is_some());
    check_fixed_system_pending_cluster_with_checkpoint(true, Some(Exercise::ManagementRetention));
}

#[test]
#[ignore = "requires fresh Authority/System IMAGE candidates and three authenticated loopback transports"]
fn candidate_management_retention_recovers_and_releases_on_original_returning_follower() {
    assert!(std::env::var_os("AUTHORITY_CANDIDATE_ELF").is_some());
    assert!(std::env::var_os("VOS_AGENT_RUNTIME_COST_CANDIDATE").is_some());
    assert!(std::env::var_os("VOS_AGENT_PROFILE_REFINE_MACHINES").is_some());
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        Some(Exercise::ManagementRetentionFollower),
    );
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_common_checkpoint_recovers_source_and_destination_marker_crashes() {
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        Some(Exercise::Crash(CommonCheckpointCrashStage::Marker)),
    );
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_common_checkpoint_recovers_source_and_destination_journal_crashes() {
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        Some(Exercise::Crash(CommonCheckpointCrashStage::Journal)),
    );
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_common_checkpoint_recovers_source_and_destination_ledger_crashes() {
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        Some(Exercise::Crash(CommonCheckpointCrashStage::Ledger)),
    );
}

pub(super) fn reopen_owner(
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

/// Exercise the ordinary public Invoke/ACK Query contract, not an internal
/// Authority observation producer or compatibility recovery path.
fn public_query_work(
    owner: &MemoryBootstrapOwner,
    request: &AuthorityProjectionQuery,
) -> (
    InvocationWork,
    InvocationAuthorization,
    crate::agent::supervisor::AgentRouteIdentity,
) {
    let target = owner.authority_target();
    assert_eq!(request.authority, target);
    let mut material = owner
        .supervisor_invocation_material(owner.pins.agent, target.binding.issuer.actor)
        .unwrap();
    material.root_provenance = false;
    let identity =
        crate::agent::supervisor_adapters::physical_material_identity(&material).unwrap();
    let mut availability = vec![material.program, material.schema, material.policies];
    availability.extend(material.installation_data);
    availability.sort_unstable_by(|a, b| a.reference.cmp(&b.reference));
    let work = InvocationWork {
        space: target.space,
        agent: target.system_agent,
        runtime_deployment: target.system_runtime_deployment,
        invocation: request.expected_invocation(),
        actor: target.binding.issuer.actor,
        incarnation: material.actor.incarnation,
        deployment: target.binding.issuer.deployment,
        program: target.binding.issuer.program,
        mode: MethodMode::Query,
        origin: InvocationOrigin {
            principal: None,
            transport_node: request.attesting_node(),
            credential: None,
            actor: None,
            capability: None,
        },
        roles: InvocationRoleClaims::none(),
        message: dynamic_message(
            "credential_projection",
            "query",
            crate::actors::value::Value::Bytes(request.encode().unwrap()),
        ),
        installation_data: material.actor.entry.installation_data,
        availability,
        gas: owner.invocation_gas,
        recovery_only: false,
    };
    assert!(work.validate());
    let authorization = InvocationAuthorization::PublicPreflight(
        crate::agent_sdk::PublicPreflight::for_work(&work, material.observed_slot),
    );
    (work, authorization, identity)
}

pub(super) fn restart_network(index: usize) -> Arc<Network> {
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
    #[cfg(feature = "experimental-state-blocks")]
    if matches!(exercise, Exercise::AuthorityObservation) {
        authority_observation::exercise(
            leader,
            owners,
            fixtures,
            directories,
            stores,
            providers,
            networks,
            signer,
        );
        return;
    }
    #[cfg(feature = "experimental-state-blocks")]
    if matches!(exercise, Exercise::ForwardedInstallOrigin) {
        forwarded_install_origin::exercise(leader, owners, fixtures, directories, networks, signer);
        return;
    }
    #[cfg(feature = "experimental-state-blocks")]
    if matches!(exercise, Exercise::GenesisPublicationRetry) {
        genesis_publication_retry::exercise(leader, owners, signer);
        return;
    }
    #[cfg(feature = "experimental-state-blocks")]
    if matches!(exercise, Exercise::LocalImageInstallRegistrationTimeout) {
        local_install_recovery::exercise(leader, owners, fixtures, directories);
        return;
    }
    #[cfg(feature = "experimental-state-blocks")]
    if matches!(
        exercise,
        Exercise::AdminJournalPrewrite
            | Exercise::AdminRegistrationTimeout
            | Exercise::AdminRegistrationTimeoutCold
    ) {
        exercise_admin_missing_journal(
            leader,
            owners,
            fixtures,
            directories,
            stores,
            providers,
            networks,
            signer,
            !matches!(exercise, Exercise::AdminJournalPrewrite),
            matches!(exercise, Exercise::AdminRegistrationTimeoutCold),
        );
        return;
    }
    if matches!(
        exercise,
        Exercise::ManagementRetention | Exercise::ManagementRetentionFollower
    ) {
        management_retention::exercise(
            leader,
            owners,
            fixtures,
            directories,
            stores,
            providers,
            networks,
            signer,
            matches!(exercise, Exercise::ManagementRetentionFollower),
        );
        return;
    }
    let crash = match exercise {
        Exercise::Healthy => None,
        Exercise::Crash(stage) => Some(stage),
        #[cfg(feature = "experimental-state-blocks")]
        Exercise::AuthorityObservation => unreachable!(),
        Exercise::ManagementRetention | Exercise::ManagementRetentionFollower => unreachable!(),
        #[cfg(feature = "experimental-state-blocks")]
        Exercise::ForwardedInstallOrigin => unreachable!(),
        #[cfg(feature = "experimental-state-blocks")]
        Exercise::GenesisPublicationRetry => unreachable!(),
        #[cfg(feature = "experimental-state-blocks")]
        Exercise::AdminJournalPrewrite
        | Exercise::AdminRegistrationTimeout
        | Exercise::AdminRegistrationTimeoutCold => unreachable!(),
        #[cfg(feature = "experimental-state-blocks")]
        Exercise::LocalImageInstallRegistrationTimeout => unreachable!(),
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
    let (older_work, older_auth, older_identity) = public_query_work(source, &older_query);
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
    assert!(matches!(
        source
            .supervisor_invoke(older_identity, older_work.clone(), older_auth.clone())
            .unwrap(),
        RuntimeOutcome::Completed(Ok(_))
    ));
    assert!(matches!(
        source
            .supervisor_acknowledge(older_identity, older_work, older_auth)
            .unwrap(),
        RuntimeOutcome::Acknowledged(Ok(_))
    ));
    let request = query(source, leader, 0xb1);
    // An ordinary public actor Query may lose its result before ACK.
    // Preserve that exact retained result at the authenticated boundary.
    let (work, authorization, identity) = public_query_work(source, &request);
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

    let (checkpoint_work, checkpoint_auth, _) =
        public_query_work(source, &query(source, leader, 0xb3));
    let committee = source.pins.replicas.clone();
    assert_eq!(
        source
            ._network_host
            .certified_common_checkpoint_for_admission(
                agent,
                &checkpoint_work,
                &checkpoint_auth,
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
            &checkpoint_work,
            &checkpoint_auth,
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
    let (fresh_work, fresh_authorization, fresh_identity) = public_query_work(owner, &fresh);
    let outcome = owner
        .supervisor_invoke(
            fresh_identity,
            fresh_work.clone(),
            fresh_authorization.clone(),
        )
        .unwrap();
    let RuntimeOutcome::Completed(Ok(reply)) = outcome else {
        panic!("ordinary public Query must continue after imported checkpoint");
    };
    let Some(crate::actors::value::Value::Bytes(fresh_response)) =
        crate::actors::value::Value::try_decode(&reply.reply)
    else {
        panic!("ordinary public Query response bytes");
    };
    assert!(matches!(
        owner
            .supervisor_acknowledge(fresh_identity, fresh_work, fresh_authorization)
            .unwrap(),
        RuntimeOutcome::Acknowledged(Ok(_))
    ));
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
    // Acknowledged ordinary public Query bytes are not an indefinite response
    // archive. A later certified foundation may prune their exact replay rows.
    let owner = owners[successor].as_mut().unwrap();
    let (checkpoint_work, checkpoint_auth, _) =
        public_query_work(owner, &query(owner, successor, 0xb7));
    owner
        ._network_host
        .certified_common_checkpoint_for_admission(
            agent,
            &checkpoint_work,
            &checkpoint_auth,
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
    *networks = live_networks.into_iter().map(Option::unwrap).collect();
}


/// Live cuts retain the real original owner; the separate cold cut naturally
/// drops it and proves missing-journal refusal through normal startup/admission.
/// These component regressions do not qualify the released-bundle CLI workflow.
#[cfg(feature = "experimental-state-blocks")]
#[allow(clippy::too_many_arguments)]
fn exercise_admin_missing_journal(
    origin: usize,
    owners: &mut [Option<MemoryBootstrapOwner>],
    fixtures: &[PhysicalFixture],
    directories: &[TestDirectory],
    stores: &[(BootstrapMemoryStore, BootstrapMemoryStore, IssuerMemoryStore)],
    providers: &[Arc<MemoryProvider>],
    networks: &[Arc<Network>],
    signer: &mut CountingSigner,
    registration_timeout: bool,
    cold_reopen: bool,
) {
    use crate::actors::codec::Decode as _;
    use crate::agent::clean_bootstrap::admin_dispatch::RetainedAuthorityAdminDispatch;
    use crate::agent::local_lifecycle::{LocalLifecycleController, LocalLifecycleStoreFactory};
    use crate::agent::production_owner::{AgentProductionOwner, AgentProductionOwnerError};
    use crate::agent_sdk::authority::{
        AuthorityAdminCall, AuthorityAdminOperation, AuthorityCredentialProjection,
    };
    use crate::agent_sdk::wire::CanonicalWire as _;
    use crate::service::wire::ServiceWire as _;

    struct AdminSigner;
    impl NativeAuthorityAdminPreparationSigner for AdminSigner {
        type Error = std::io::Error;
        fn public_key(&self) -> [u8; 32] {
            SigningKey::from_bytes(&[RECEIPT_SEED; 32])
                .verifying_key()
                .to_bytes()
        }
        fn sign_admin_preparation(&mut self, bytes: &[u8]) -> Result<[u8; 64], Self::Error> {
            Ok(SigningKey::from_bytes(&[RECEIPT_SEED; 32])
                .sign(bytes)
                .to_bytes())
        }
    }
    impl NativeAuthorityAdminTerminalSigner for AdminSigner {
        type Error = std::io::Error;
        fn public_key(&self) -> [u8; 32] {
            SigningKey::from_bytes(&[RECEIPT_SEED; 32])
                .verifying_key()
                .to_bytes()
        }
        fn sign_admin_terminal(&mut self, bytes: &[u8]) -> Result<[u8; 64], Self::Error> {
            Ok(SigningKey::from_bytes(&[RECEIPT_SEED; 32])
                .sign(bytes)
                .to_bytes())
        }
    }
    struct AdminJournal {
        inner: OperationTestJournal,
        refuse_before_write: bool,
        writes: Arc<AtomicUsize>,
    }
    impl NativeAuthorityAdminJournalStore for AdminJournal {
        type Error = std::io::Error;
        fn load(&mut self, id: InvocationId) -> Result<Option<Vec<u8>>, Self::Error> {
            NativeAuthorityOperationJournalStore::load(&mut self.inner, id)
        }
        fn retain(&mut self, id: InvocationId, bytes: &[u8]) -> Result<(), Self::Error> {
            self.writes.fetch_add(1, Ordering::AcqRel);
            if core::mem::take(&mut self.refuse_before_write) {
                return Err(std::io::Error::other(
                    "injected admin journal prewrite failure",
                ));
            }
            NativeAuthorityOperationJournalStore::retain(&mut self.inner, id, bytes)
        }
    }
    struct AdminTerminals(OperationTestJournal);
    impl NativeAuthorityAdminTerminalStore for AdminTerminals {
        type Error = std::io::Error;
        fn load(
            &mut self,
            id: InvocationId,
            retired: bool,
        ) -> Result<Option<Vec<u8>>, Self::Error> {
            let key = InvocationId(
                Hash::digest(
                    b"fixed-three-admin-terminal-test",
                    &[&id.0, &[u8::from(retired)]],
                )
                .0,
            );
            NativeAuthorityOperationJournalStore::load(&mut self.0, key)
        }
        fn retain(
            &mut self,
            id: InvocationId,
            retired: bool,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            let key = InvocationId(
                Hash::digest(
                    b"fixed-three-admin-terminal-test",
                    &[&id.0, &[u8::from(retired)]],
                )
                .0,
            );
            NativeAuthorityOperationJournalStore::retain(&mut self.0, key, bytes)
        }
    }
    struct NoLifecycleStores;
    impl LocalLifecycleStoreFactory for NoLifecycleStores {
        type Intent = IssuerMemoryStore;
        type Issuer = IssuerMemoryStore;
        type Error = ();
        fn discover(&mut self, _: SpaceId, _: usize) -> Result<Vec<AgentId>, ()> {
            panic!("admin retry must not discover lifecycle stores")
        }
        fn open(&mut self, _: SpaceId, _: AgentId) -> Result<(Self::Intent, Self::Issuer), ()> {
            panic!("admin retry must not create lifecycle stores")
        }
        fn open_existing(
            &mut self,
            _: SpaceId,
            _: AgentId,
        ) -> Result<(Self::Intent, Self::Issuer), ()> {
            panic!("admin retry must not reopen lifecycle stores")
        }
    }
    fn retry_until<T>(
        deadline: std::time::Instant,
        phase: &str,
        mut operation: impl FnMut() -> Result<T, SharedAgentHostError>,
    ) -> T {
        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "{phase} exceeded the whole recovery bound"
            );
            let result = operation();
            assert!(
                std::time::Instant::now() <= deadline,
                "{phase} exceeded the whole recovery bound"
            );
            match result {
                Ok(value) => return value,
                Err(SharedAgentHostError::Unavailable | SharedAgentHostError::Conflict) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("{phase} failed: {error:?}"),
            }
        }
    }

    // This guard only restores the existing test transport cut. Every later
    // assertion or panic must leave all three authenticated peers connected.
    struct RestoreIsolationOnDrop<'a> {
        owners: &'a [Option<MemoryBootstrapOwner>],
        agent: HostAgentId,
        armed: bool,
    }
    impl RestoreIsolationOnDrop<'_> {
        fn restore_checked(&mut self) -> Result<(), SharedAgentHostError> {
            let mut failed = None;
            for owner in self.owners.iter().filter_map(Option::as_ref) {
                if let Err(error) = owner
                    ._network_host
                    .set_raft_isolated_for_test(self.agent, false)
                {
                    if failed.is_none() {
                        failed = Some(error);
                    }
                }
            }
            if let Some(error) = failed {
                return Err(error);
            }
            self.armed = false;
            Ok(())
        }
    }
    impl Drop for RestoreIsolationOnDrop<'_> {
        fn drop(&mut self) {
            if self.armed {
                for owner in self.owners.iter().filter_map(Option::as_ref) {
                    let _ = owner
                        ._network_host
                        .set_raft_isolated_for_test(self.agent, false);
                }
            }
        }
    }

    assert_eq!(owners.len(), 3);
    let agent = HostAgentId(fixtures[origin].plan.pins.agent.0);
    for owner in owners.iter().map(|owner| owner.as_ref().unwrap()) {
        assert_eq!(owner.pins.replicas.members().len(), 3);
        assert!(!owner.management_admission_held().unwrap());
    }
    assert!(
        owners[origin]
            .as_ref()
            .unwrap()
            ._network_host
            .bootstrap_is_local_leader(agent)
            .unwrap()
    );
    let current = {
        let owner = owners[origin].as_ref().unwrap();
        let request = query(owner, origin, 0xd8);
        let work = owner.prepare_authority_observation_work(&request).unwrap();
        let outcome =
            management_retention::exact_management_retry("admin initial observation", || {
                owner._network_host.with_authority_observation(
                    agent,
                    request.commitment(),
                    |host| host.observe_system_authority(agent, &work),
                )
            });
        let RuntimeOutcome::Completed(Ok(reply)) = outcome else {
            panic!("admin fixture observation did not complete");
        };
        assert_eq!(reply.status, InvocationStatus::Done);
        let Some(crate::actors::value::Value::Bytes(bytes)) =
            crate::actors::value::Value::try_decode(&reply.reply)
        else {
            panic!("admin fixture observation returned no projection bytes");
        };
        let projection = AuthorityCredentialProjection::decode(&bytes).unwrap();
        assert_eq!(projection.query, request);
        assert_eq!(projection.status, AuthorityCredentialStatus::Active);
        projection
    };
    let credential_key = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32]);
    let public = credential_key.verifying_key().to_bytes();
    let target = owners[origin].as_ref().unwrap().authority_target();
    let mut draft = AuthorityAdminCall {
        invocation: InvocationId::ZERO,
        authority: target,
        administrator: current.principal,
        credential: CredentialId::of_public_key(&public),
        request_sequence: NonZeroU64::new(current.admin_request_high_water + 1).unwrap(),
        credential_public_key: public,
        authenticated_node: owners[origin].as_ref().unwrap().pins.node,
        observed_slot: 0,
        expected_generation: current.head.administration_generation,
        operation: AuthorityAdminOperation::SetSpaceRole {
            principal: current.principal,
            role: crate::agent_sdk::RoleId([0x53; 32]),
            granted: true,
        },
        signature: [1; 64],
    };
    let sign_draft = |draft: &mut AuthorityAdminCall| {
        draft.invocation = draft.expected_invocation();
        draft.signature = credential_key.sign(&draft.signing_bytes()).to_bytes();
        draft.verify_with(&RawCredentialVerifier).unwrap();
    };
    sign_draft(&mut draft);
    let preparation = owners[origin]
        .as_ref()
        .unwrap()
        .prepare_authority_admin(&draft, &mut AdminSigner)
        .unwrap();
    let mut call = preparation.call_to_sign(&draft).unwrap();
    sign_draft(&mut call);
    assert!(preparation.matches_call(&call));
    let mut absent_draft = draft.clone();
    absent_draft.request_sequence = NonZeroU64::new(draft.request_sequence.get() + 1).unwrap();
    absent_draft.operation = AuthorityAdminOperation::SetSpaceRole {
        principal: current.principal,
        role: crate::agent_sdk::RoleId([0x56; 32]),
        granted: true,
    };
    sign_draft(&mut absent_draft);
    let absent_preparation = owners[origin]
        .as_ref()
        .unwrap()
        .prepare_authority_admin(&absent_draft, &mut AdminSigner)
        .unwrap();
    let mut absent_call = absent_preparation.call_to_sign(&absent_draft).unwrap();
    sign_draft(&mut absent_call);
    let other = (origin + 1) % 3;
    let mut other_draft = draft.clone();
    other_draft.authenticated_node = owners[other].as_ref().unwrap().pins.node;
    sign_draft(&mut other_draft);
    let other_preparation = owners[other]
        .as_ref()
        .unwrap()
        .prepare_authority_admin(&other_draft, &mut AdminSigner)
        .unwrap();
    let mut other_call = other_preparation.call_to_sign(&other_draft).unwrap();
    sign_draft(&mut other_call);
    let mut changed_call = call.clone();
    changed_call.operation = absent_draft.operation.clone();
    sign_draft(&mut changed_call);
    let mut bad_proof_bytes = preparation.encode().unwrap();
    *bad_proof_bytes.last_mut().unwrap() ^= 1;
    let bad_proof = NativeAuthorityAdminPreparation::decode(&bad_proof_bytes).unwrap();
    assert!(!bad_proof.matches_call(&call));
    for fixture in fixtures {
        fixture
            .logical_slot
            .as_ref()
            .unwrap()
            .fetch_max(call.observed_slot + 1, Ordering::AcqRel);
    }
    let journal_path = directories[origin].0.clone();
    let writes = Arc::new(AtomicUsize::new(0));
    let mut journal = AdminJournal {
        inner: OperationTestJournal(journal_path.clone()),
        refuse_before_write: !registration_timeout,
        writes: Arc::clone(&writes),
    };
    let state_before = owners[origin]
        .as_ref()
        .unwrap()
        .host
        .lock()
        .unwrap()
        .clean_state_commitment(agent)
        .unwrap();
    let recovery_started = std::time::Instant::now();
    let deadline = recovery_started + std::time::Duration::from_secs(30);
    let (delayed_registration, mut isolation_restore) = if registration_timeout {
        let database = owners[origin]
            .as_ref()
            .unwrap()
            .host
            .lock()
            .unwrap()
            .raft_database(agent)
            .unwrap();
        let meta_before = crate::raft::RaftMeta::load(&database).unwrap();
        let last_before = crate::raft::RaftLog::open(Arc::clone(&database))
            .unwrap()
            .last_index();
        assert_eq!(meta_before.commit_index, last_before);
        for owner in owners.iter().map(|owner| owner.as_ref().unwrap()) {
            owner
                ._network_host
                .set_raft_isolated_for_test(agent, true)
                .unwrap();
        }
        let cut_started = std::time::Instant::now();
        let cut = owners[origin].as_mut().unwrap().retain_authority_admin(
            &call,
            &preparation,
            &mut journal,
        );
        let cut_elapsed = cut_started.elapsed();
        let isolation_restore = RestoreIsolationOnDrop {
            owners,
            agent,
            armed: true,
        };
        // Inspect the actual isolated append before allowing replication.
        // A reply loss alone would not hold the local commit cursor.
        let observed = (|| {
            let meta = crate::raft::RaftMeta::load(&database)?;
            let raw = crate::raft::RaftLog::open(Arc::clone(&database))?;
            let last = raw.last_index();
            let entries = raw.entries(last, last)?;
            Ok::<_, crate::commit::CommitError>((meta, last, entries))
        })();
        // Reconnect a quorum containing the original longer-log owner. The
        // two shorter-log peers must not elect each other and legitimately
        // discard this uncommitted registration before the cut is exercised.
        for index in [origin, (origin + 1) % 3] {
            owners[index]
                .as_ref()
                .unwrap()
                ._network_host
                .set_raft_isolated_for_test(agent, false)
                .unwrap();
        }
        let (meta_after, last_after, entries) = observed.unwrap();
        assert!(matches!(cut, Err(SharedAgentHostError::Unavailable)));
        assert!(cut_elapsed >= std::time::Duration::from_millis(1_800));
        assert!(std::time::Instant::now() < deadline);
        assert_eq!(writes.load(Ordering::Acquire), 0);
        assert!(journal.load(call.invocation).unwrap().is_none());
        assert_eq!(meta_after.commit_index, meta_before.commit_index);
        assert_eq!(last_after, last_before + 1);
        assert_eq!(entries.len(), 1);
        let vos_raft::EntryKind::Data { payload } =
            crate::agent::shared_raft::decode_agent_raft_entry_kind(&entries[0].payload).unwrap()
        else {
            panic!("admin timeout must append the actual signed metadata command");
        };
        let crate::agent::shared_raft::AgentRaftCommand::RegisterManagementRecovery {
            registration,
            ..
        } = crate::agent::shared_raft::AgentRaftCommand::decode(&payload).unwrap()
        else {
            panic!("admin timeout must append RegisterManagementRecovery");
        };
        (Some(registration), Some(isolation_restore))
    } else {
        retry_until(deadline, "admin journal prewrite cut", || {
            let result = owners[origin].as_mut().unwrap().retain_authority_admin(
                &call,
                &preparation,
                &mut journal,
            );
            if writes.load(Ordering::Acquire) == 1 {
                assert!(matches!(result, Err(SharedAgentHostError::Unavailable)));
                Ok(())
            } else {
                result
                    .map(|_| panic!("admin prewrite cut must precede durable journal publication"))
            }
        });
        assert!(journal.load(call.invocation).unwrap().is_none());
        (None, None)
    };
    let owner = owners[origin].as_ref().unwrap();
    let retained = retry_until(deadline, "admin committed original registration", || {
        let manifest = owner._network_host.management_recovery_manifest(agent)?;
        let Some(slot) = manifest
            .management_slot(HostNodeId(owner.pins.node.0))
            .filter(|slot| {
                !slot.is_released()
                    && slot
                        .members()
                        .first()
                        .is_some_and(|member| member.work().invocation == call.invocation)
            })
        else {
            return Err(SharedAgentHostError::Unavailable);
        };
        if let Some(expected) = &delayed_registration {
            assert_eq!(slot.registration(), expected);
        }
        Ok(slot.clone())
    });
    // The exact signed registration has now committed on its original owner.
    // Restore the third peer immediately and release the borrowed cut guard
    // before any later mutable original-owner retry.
    if let Some(restore) = isolation_restore.as_mut() {
        restore.restore_checked().unwrap();
    }
    drop(isolation_restore);
    assert!(std::time::Instant::now() <= deadline);
    assert_eq!(retained.owner(), HostNodeId(owner.pins.node.0));
    assert_eq!(retained.origin_owner(), retained.owner());
    assert!(!retained.is_released());
    assert_eq!(retained.members().len(), 1);
    assert_eq!(retained.members()[0].parent(), None);
    assert!(retained.members_evidence()[0].invoke().is_none());
    assert!(retained.members_evidence()[0].acknowledgement().is_none());
    let expected_record = RetainedAuthorityAdminDispatch {
        call: call.clone(),
        envelope: retained.members()[0].envelope().clone(),
        anchor: retained.members()[0].anchor().clone(),
        preparation: preparation.clone(),
    };
    let expected_bytes = expected_record.encode().unwrap();
    assert_eq!(
        RetainedAuthorityAdminDispatch::decode(&expected_bytes).unwrap(),
        expected_record
    );
    assert_eq!(
        owner
            .host
            .lock()
            .unwrap()
            .clean_state_commitment(agent)
            .unwrap(),
        state_before
    );
    assert!(owner.management_admission_held().unwrap());
    let protected = owner._network_host.ensure_management_pending_member(
        agent,
        &expected_record.anchor,
        &expected_record.envelope,
    );
    if registration_timeout {
        assert!(matches!(protected, Err(SharedAgentHostError::Conflict)));
        assert_eq!(writes.load(Ordering::Acquire), 0);
    } else {
        protected.unwrap();
        assert_eq!(writes.load(Ordering::Acquire), 1);
    }
    let mut wrong_anchor = expected_record.anchor.clone();
    wrong_anchor.ordered.index += 1;
    assert!(
        owner
            ._network_host
            .ensure_management_pending_member(agent, &wrong_anchor, &expected_record.envelope)
            .is_err()
    );
    let mut changed_envelope = expected_record.envelope.clone();
    let RuntimeWork::Invoke { observed_slot, .. } = &mut changed_envelope else {
        unreachable!()
    };
    *observed_slot += 1;
    {
        // The absent-map cut must reject substituted physical evidence too;
        // a map-miss alone would not prove the retained signed family boundary.
        let mut hosted = owner.host.lock().unwrap();
        assert!(
            hosted
                .management_pending_admission_requirement(
                    agent,
                    &[(&wrong_anchor, &expected_record.envelope)]
                )
                .is_err()
        );
        assert!(
            hosted
                .management_pending_admission_requirement(
                    agent,
                    &[(&expected_record.anchor, &changed_envelope)]
                )
                .is_err()
        );
    }
    let missing_family = RetainedAuthorityAdminDispatch {
        call: absent_call.clone(),
        preparation: absent_preparation.clone(),
        ..expected_record.clone()
    };
    assert!(missing_family.encode().is_err());
    // Exercise the actual retain path with a different valid signed attempt.
    // Its refusal must preserve the first ambiguous attempt for exact recovery.
    assert!(matches!(
        owners[origin].as_mut().unwrap().retain_authority_admin(
            &absent_call,
            &absent_preparation,
            &mut journal,
        ),
        Err(SharedAgentHostError::Conflict)
    ));
    assert!(journal.load(call.invocation).unwrap().is_none());
    assert!(journal.load(absent_call.invocation).unwrap().is_none());
    let owner = owners[origin].as_ref().unwrap();
    assert_eq!(
        owner._network_host.management_recovery_manifest(agent).unwrap()
            .management_slot(retained.owner()),
        Some(&retained)
    );
    let protected_after_refusal = owner._network_host.ensure_management_pending_member(
        agent,
        &expected_record.anchor,
        &expected_record.envelope,
    );
    if registration_timeout {
        assert!(matches!(protected_after_refusal, Err(SharedAgentHostError::Conflict)));
        assert_eq!(writes.load(Ordering::Acquire), 0);
    } else {
        protected_after_refusal.unwrap();
        assert_eq!(writes.load(Ordering::Acquire), 1);
    }
    let retained_submission = admin_pending_validation::pending(
        owners[origin].as_mut().unwrap(),
        &retained,
        &expected_record,
        &NativeAuthorityAdminSubmission::new(absent_call.clone(), absent_preparation.clone()).unwrap(),
        &mut journal,
    );
    let owner = owners[origin].as_ref().unwrap();
    let before = native_owner_physical_state(owner);
    if cold_reopen {
        assert!(registration_timeout);
        assert_eq!(writes.load(Ordering::Acquire), 0);
        let bootstrap_bytes = || {
            (
                stores[origin].0.image(),
                stores[origin].0.commits(),
                stores[origin].1.image(),
                stores[origin].1.commits(),
                stores[origin].2.image.lock().unwrap().clone(),
            )
        };
        let durable_before = bootstrap_bytes();
        let record_before = owner.record.encode();
        // Revoke the actual transport, then relinquish every old-owner host
        // reference and lease. A new owner must not inherit its live marker.
        owners[origin]
            .as_mut()
            .unwrap()
            ._network_host
            .retire_attachment_for_test(agent)
            .unwrap();
        drop(owners[origin].take().unwrap());
        assert!(std::time::Instant::now() <= deadline);
        let assert_no_cold_adoption = || {
            assert_eq!(bootstrap_bytes(), durable_before);
            assert_eq!(writes.load(Ordering::Acquire), 0);
            let mut view = OperationTestJournal(journal_path.clone());
            for id in [call.invocation, absent_call.invocation] {
                assert!(
                    NativeAuthorityOperationJournalStore::load(&mut view, id)
                        .unwrap()
                        .is_none()
                );
            }
            for surviving in owners.iter().filter_map(Option::as_ref) {
                let manifest = retry_until(deadline, "cold admin survivor manifest", || {
                    surviving._network_host.management_recovery_manifest(agent)
                });
                assert_eq!(manifest.management_slot(retained.owner()), Some(&retained));
                assert_eq!(
                    surviving
                        .host
                        .lock()
                        .unwrap()
                        .clean_state_commitment(agent)
                        .unwrap(),
                    before.1
                );
            }
        };
        assert!(std::time::Instant::now() < deadline);
        let reopened = PendingCleanSystemAgentBootstrap::open_with_operation_admission(
            stores[origin].0.clone(),
            stores[origin].1.clone(),
            stores[origin].2.clone(),
            signer,
            || panic!("cold admin reopen must retain its durable bootstrap plan"),
            directories[origin].host(),
            directories[origin].lock(),
            fixtures[origin].plan.pins.space,
            fixtures[origin].plan.pins.node,
            fixtures[origin].trust.clone(),
            fixtures[origin].merge.clone(),
            fixtures[origin].finality.clone(),
            providers[origin].clone(),
            networks[origin].clone(),
            None,
            None,
        );
        assert!(std::time::Instant::now() <= deadline);
        let mut pending = match reopened {
            Ok(pending) => pending,
            Err(CleanSystemAgentBootstrapError::Host(SharedAgentHostError::ScopeMismatch)) => {
                assert_no_cold_adoption();
                assert!(recovery_started.elapsed() <= std::time::Duration::from_secs(30));
                eprintln!(
                    "fixed_three_admin_recovery phase=cold_startup_refusal elapsed_ms={}",
                    recovery_started.elapsed().as_millis()
                );
                return;
            }
            Err(error) => panic!("cold admin normal reopen failed before admission: {error:?}"),
        };
        let reopened = loop {
            assert!(std::time::Instant::now() < deadline);
            let result = pending.try_complete(signer);
            assert!(std::time::Instant::now() <= deadline);
            match result {
                Ok(Some(owner)) => break owner,
                Ok(None) => panic!("cold admin pending owner disappeared before completion"),
                Err(CleanSystemAgentBootstrapError::Host(SharedAgentHostError::Unavailable)) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(CleanSystemAgentBootstrapError::Host(SharedAgentHostError::ScopeMismatch)) => {
                    drop(pending);
                    assert_no_cold_adoption();
                    assert!(recovery_started.elapsed() <= std::time::Duration::from_secs(30));
                    eprintln!(
                        "fixed_three_admin_recovery phase=cold_startup_refusal elapsed_ms={}",
                        recovery_started.elapsed().as_millis()
                    );
                    return;
                }
                Err(error) => panic!("cold admin normal completion failed: {error:?}"),
            }
        };
        drop(pending);
        assert_eq!(reopened.record.encode(), record_before);
        assert!(reopened.management_admission_held().unwrap());
        assert!(matches!(
            reopened._network_host.ensure_management_pending_member(
                agent,
                &expected_record.anchor,
                &expected_record.envelope,
            ),
            Err(SharedAgentHostError::Conflict)
        ));
        let cold_before = native_owner_physical_state(&reopened);
        assert_eq!(cold_before.1, before.1);
        assert_eq!(
            reopened
                ._network_host
                .management_recovery_manifest(agent)
                .unwrap()
                .management_slot(retained.owner()),
            Some(&retained)
        );
        let cold_host = Arc::clone(&reopened.host);
        let local = crate::agent::local_sdk_host::LocalAgentHost::create(
            directories[origin].0.join("admin-cold-recovery-local-host"),
            target.space,
            fixtures[origin].plan.pins.node,
            fixtures[origin].trust.clone(),
        )
        .unwrap();
        let lifecycle = LocalLifecycleController::new(
            reopened,
            local,
            NoLifecycleStores,
            CountingSigner::new(),
        )
        .unwrap()
        .with_admins(
            NativeAuthorityAdminController::new(
                target,
                journal,
                AdminTerminals(OperationTestJournal(journal_path.clone())),
            ),
            AdminSigner,
        )
        .unwrap();
        let observation_calls = Arc::new(AtomicUsize::new(0));
        let mut production = AgentProductionOwner::start_local(
            fixtures[origin].plan.pins.node,
            crate::agent::supervisor::AgentSupervisorLimits::default(),
            Box::new(lifecycle),
            4,
            Box::new(NeverProjectionAuthenticator(Arc::clone(&observation_calls))),
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        assert!(std::time::Instant::now() <= deadline);
        assert!(production.is_running());
        assert!(!production.is_ready());
        assert!(matches!(
            production.ingress(),
            Err(AgentProductionOwnerError::ProjectionNotReady)
        ));
        assert!(matches!(
            production.prepare_admin(&draft),
            Err(SharedAgentHostError::Unavailable)
        ));
        for (refused_call, refused_preparation) in [
            (&call, &preparation),
            (&absent_call, &absent_preparation),
            (&changed_call, &preparation),
            (&call, &bad_proof),
            (&call, &absent_preparation),
            (&other_call, &other_preparation),
        ] {
            assert!(matches!(
                production.submit_admin(refused_call, refused_preparation),
                Err(SharedAgentHostError::ScopeMismatch)
            ));
            assert!(std::time::Instant::now() <= deadline);
        }
        assert_no_cold_adoption();
        {
            let mut hosted = cold_host.lock().unwrap();
            // Current-term no-op progress from a genuine election may advance
            // metadata. Exact refusal must preserve actor state and the whole
            // signed family without Invoke, ACK, or release evidence.
            assert_eq!(hosted.clean_state_commitment(agent).unwrap(), cold_before.1);
            assert_eq!(
                hosted
                    .recovery_manifest(agent)
                    .unwrap()
                    .management_slot(retained.owner()),
                Some(&retained)
            );
        }
        assert_eq!(observation_calls.load(Ordering::Acquire), 0);
        assert!(!production.is_ready());
        assert!(matches!(
            production.ingress(),
            Err(AgentProductionOwnerError::ProjectionNotReady)
        ));
        production.shutdown_and_join().unwrap();
        drop(cold_host);
        assert_no_cold_adoption();
        assert!(recovery_started.elapsed() <= std::time::Duration::from_secs(30));
        eprintln!(
            "fixed_three_admin_recovery phase=cold_exact_retry_refusal elapsed_ms={}",
            recovery_started.elapsed().as_millis()
        );
        return;
    }
    let host = Arc::clone(&owner.host);
    let controller = NativeAuthorityAdminController::new(
        target,
        journal,
        AdminTerminals(OperationTestJournal(journal_path.clone())),
    );
    let local = crate::agent::local_sdk_host::LocalAgentHost::create(
        directories[origin].0.join("admin-recovery-local-host"),
        target.space,
        fixtures[origin].plan.pins.node,
        fixtures[origin].trust.clone(),
    )
    .unwrap();
    let lifecycle = LocalLifecycleController::new(
        owners[origin].take().unwrap(),
        local,
        NoLifecycleStores,
        CountingSigner::new(),
    )
    .unwrap()
    .with_admins(controller, AdminSigner)
    .unwrap();
    let observation_calls = Arc::new(AtomicUsize::new(0));
    let mut production = AgentProductionOwner::start_local(
        fixtures[origin].plan.pins.node,
        crate::agent::supervisor::AgentSupervisorLimits::default(),
        Box::new(lifecycle),
        4,
        Box::new(NeverProjectionAuthenticator(Arc::clone(&observation_calls))),
        std::time::Duration::from_secs(5),
    )
    .unwrap();
    assert!(std::time::Instant::now() < deadline);
    assert!(production.is_running());
    assert!(!production.is_ready());
    assert!(matches!(
        production.ingress(),
        Err(AgentProductionOwnerError::ProjectionNotReady)
    ));
    assert_eq!(observation_calls.load(Ordering::Acquire), 0);
    assert!(matches!(
        production.prepare_admin(&draft),
        Err(SharedAgentHostError::Unavailable)
    ));
    for (refused_call, refused_preparation) in [
        (&absent_call, &absent_preparation),
        (&changed_call, &preparation),
        (&call, &bad_proof),
        (&call, &absent_preparation),
        (&other_call, &other_preparation),
    ] {
        assert!(matches!(
            production.submit_admin(refused_call, refused_preparation),
            Err(SharedAgentHostError::ScopeMismatch)
        ));
    }
    let mut journal_view = OperationTestJournal(journal_path);
    assert!(
        NativeAuthorityOperationJournalStore::load(&mut journal_view, call.invocation)
            .unwrap()
            .is_none()
    );
    assert!(
        NativeAuthorityOperationJournalStore::load(&mut journal_view, absent_call.invocation)
            .unwrap()
            .is_none()
    );
    {
        let mut hosted = host.lock().unwrap();
        assert_eq!(hosted.journal_position(agent).unwrap(), before.0);
        assert_eq!(hosted.clean_state_commitment(agent).unwrap(), before.1);
        assert_eq!(hosted.show(agent).unwrap().unwrap(), before.2);
        assert_eq!(
            hosted
                .recovery_manifest(agent)
                .unwrap()
                .management_slot(retained.owner()),
            Some(&retained)
        );
    }
    // The normal recovery guard must authenticate the complete existing family
    // before permitting this exact original owner's submission. The timeout cut
    // still has no volatile pending map or independent NAD2 journal.
    let completion = retry_until(deadline, "normal retained admin recovery", || {
        production.submit_admin(&call, &preparation)
    });
    assert!(completion.result().is_some());
    assert_eq!(
        NativeAuthorityAdminCompletion::verify(&call, &preparation, completion.exact_bytes())
            .unwrap(),
        completion
    );
    let bytes = NativeAuthorityOperationJournalStore::load(&mut journal_view, call.invocation)
        .unwrap()
        .unwrap();
    assert_eq!(bytes, expected_bytes);
    let final_manifest = host.lock().unwrap().recovery_manifest(agent).unwrap();
    let final_slot = final_manifest.management_slot(retained.owner()).unwrap();
    assert_eq!(final_slot.registration(), retained.registration());
    assert_eq!(final_slot.members(), retained.members());
    assert!(final_slot.is_released());
    assert_eq!(final_slot.members_evidence().len(), 1);
    assert!(final_slot.members_evidence()[0].invoke().is_some());
    assert!(final_slot.members_evidence()[0].acknowledgement().is_some());
    admin_pending_validation::released(
        &retained_submission,
        &expected_record.envelope,
        retained.owner(),
        final_slot,
    );
    let completed_position = host.lock().unwrap().journal_position(agent).unwrap();
    let completed_state = host.lock().unwrap().clean_state_commitment(agent).unwrap();
    let retry = retry_until(deadline, "normal terminal admin exact retry", || {
        production.submit_admin(&call, &preparation)
    });
    assert_eq!(retry, completion);
    assert_eq!(
        host.lock().unwrap().journal_position(agent).unwrap(),
        completed_position
    );
    assert_eq!(
        host.lock().unwrap().clean_state_commitment(agent).unwrap(),
        completed_state
    );
    assert_eq!(
        NativeAuthorityOperationJournalStore::load(&mut journal_view, call.invocation)
            .unwrap()
            .unwrap(),
        expected_bytes
    );
    assert!(
        NativeAuthorityOperationJournalStore::load(&mut journal_view, absent_call.invocation)
            .unwrap()
            .is_none()
    );
    assert_eq!(observation_calls.load(Ordering::Acquire), 0);
    assert!(recovery_started.elapsed() <= std::time::Duration::from_secs(30));
    eprintln!(
        "fixed_three_admin_recovery phase=terminal_exact_retry registration_timeout={registration_timeout} elapsed_ms={}",
        recovery_started.elapsed().as_millis()
    );
    production.shutdown_and_join().unwrap();
}
