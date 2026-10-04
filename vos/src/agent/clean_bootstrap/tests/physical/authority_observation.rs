//! Physical fixed-three observations: fresh quorum, receiver-local guest,
//! no query custody, result retirement, or read-specific durable publication.

use super::*;
use crate::actors::codec::Decode as _;
use crate::agent_sdk::authority::{
    AuthorityAdminCall, AuthorityAdminOperation, AuthorityAdminResult,
    AuthorityCredentialEnrollment, AuthorityCredentialProjection, AuthorityInventoryProjectionPage,
};
use crate::agent_sdk::wire::CanonicalWire as _;

#[test]
#[ignore = "requires fresh Authority/System observation IMAGE candidates and three authenticated loopback transports"]
fn candidate_authority_observation_uses_fresh_quorum_local_guest_without_custody_and_reopens() {
    assert!(std::env::var_os("AUTHORITY_CANDIDATE_ELF").is_some());
    assert!(std::env::var_os("VOS_AGENT_RUNTIME_COST_CANDIDATE").is_some());
    assert!(std::env::var_os("VOS_AGENT_PROFILE_REFINE_MACHINES").is_some());
    check_fixed_system_pending_cluster_with_checkpoint(true, Some(Exercise::AuthorityObservation));
}

fn observe(
    owner: &MemoryBootstrapOwner,
    request: &AuthorityProjectionQuery,
) -> Result<RuntimeOutcome, SharedAgentHostError> {
    assert!(request.recovery.is_none());
    // Volatile construction only. In particular, do not call Invoke, finish,
    // WAL publication, recovery registration, or result acknowledgement.
    let work = owner.prepare_authority_observation_work(request)?;
    let agent = HostAgentId(owner.pins.agent.0);
    owner
        ._network_host
        .with_authority_observation(agent, request.commitment(), |host| {
            host.observe_system_authority(agent, &work)
        })
}

fn credential_projection(
    outcome: &RuntimeOutcome,
) -> Option<crate::agent_sdk::authority::AuthorityCredentialProjection> {
    let RuntimeOutcome::Completed(Ok(reply)) = outcome else {
        return None;
    };
    if reply.status != crate::agent_sdk::InvocationStatus::Done {
        return None;
    }
    let Some(crate::actors::value::Value::Bytes(response)) =
        crate::actors::value::Value::try_decode(&reply.reply)
    else {
        return None;
    };
    crate::agent_sdk::authority::AuthorityCredentialProjection::decode(&response).ok()
}

fn read(
    owner: &MemoryBootstrapOwner,
    request: &AuthorityProjectionQuery,
) -> crate::agent_sdk::authority::AuthorityCredentialProjection {
    let outcome = management_retention::exact_management_retry("Authority observation", || {
        observe(owner, request)
    });
    let projection = credential_projection(&outcome)
        .expect("real installed Authority must return its authenticated credential projection");
    assert_eq!(projection.query, *request);
    assert_eq!(projection.status, AuthorityCredentialStatus::Active);
    assert_eq!(projection.kind, AuthorityCredentialKind::Ssh);
    assert!(projection.head.is_valid());
    assert_ne!(projection.principal, PrincipalId::ZERO);
    projection
}

fn durable_owner_bytes(
    owner: &MemoryBootstrapOwner,
    stores: &(
        BootstrapMemoryStore,
        BootstrapMemoryStore,
        IssuerMemoryStore,
    ),
) -> (
    Vec<u8>,
    Option<Vec<u8>>,
    usize,
    Option<Vec<u8>>,
    usize,
    Option<Vec<u8>>,
) {
    (
        owner.record.encode(),
        stores.0.image(),
        stores.0.commits(),
        stores.1.image(),
        stores.1.commits(),
        stores.2.image.lock().unwrap().clone(),
    )
}

fn apply_signed_admin(
    owner: &MemoryBootstrapOwner,
    current: &AuthorityCredentialProjection,
    operation: AuthorityAdminOperation,
) {
    use crate::actors::value::Value;
    let key = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32]);
    let public = key.verifying_key().to_bytes();
    let target = owner.authority_target();
    let mut material = owner
        .supervisor_invocation_material(owner.pins.agent, target.binding.issuer.actor)
        .unwrap();
    material.root_provenance = false;
    let identity =
        crate::agent::supervisor_adapters::physical_material_identity(&material).unwrap();
    let mut call = AuthorityAdminCall {
        invocation: InvocationId::ZERO,
        authority: target,
        administrator: current.principal,
        credential: CredentialId::of_public_key(&public),
        request_sequence: NonZeroU64::new(current.admin_request_high_water + 1).unwrap(),
        credential_public_key: public,
        authenticated_node: owner.pins.node,
        observed_slot: material.observed_slot,
        expected_generation: current.head.administration_generation,
        operation,
        signature: [1; 64],
    };
    call.invocation = call.expected_invocation();
    call.signature = key.sign(&call.signing_bytes()).to_bytes();
    call.verify_with(&RawCredentialVerifier).unwrap();
    let mut availability = vec![material.program, material.schema, material.policies];
    availability.extend(material.installation_data);
    availability.sort_unstable_by(|a, b| a.reference.cmp(&b.reference));
    let work = InvocationWork {
        space: target.space,
        agent: target.system_agent,
        runtime_deployment: target.system_runtime_deployment,
        invocation: call.invocation,
        actor: target.binding.issuer.actor,
        incarnation: material.actor.incarnation,
        deployment: target.binding.issuer.deployment,
        program: target.binding.issuer.program,
        mode: MethodMode::Linear,
        origin: InvocationOrigin {
            principal: Some(current.principal),
            credential: Some(call.credential),
            transport_node: Some(owner.pins.node),
            actor: None,
            capability: None,
        },
        roles: InvocationRoleClaims::none(),
        message: dynamic_message("administer", "call", Value::Bytes(call.encode().unwrap())),
        installation_data: material.actor.entry.installation_data,
        availability,
        gas: owner.invocation_gas,
        recovery_only: false,
    };
    let authorization = InvocationAuthorization::PublicPreflight(
        crate::agent_sdk::PublicPreflight::for_work(&work, call.observed_slot),
    );
    let result = management_retention::exact_management_retry("signed observation admin", || {
        owner.supervisor_invoke_terminal(identity, work.clone(), authorization.clone())
    });
    let RuntimeOutcome::Completed(Ok(reply)) = result else {
        panic!("signed observation admin failed: {result:?}");
    };
    assert_eq!(reply.status, crate::agent_sdk::InvocationStatus::Done);
    let Some(Value::Bytes(bytes)) = Value::try_decode(&reply.reply) else {
        panic!("signed observation admin reply is not bytes");
    };
    let result = AuthorityAdminResult::decode(&bytes).unwrap();
    result.verify_with(&RawCredentialVerifier).unwrap();
    assert_eq!(result.call, call);
    assert_eq!(result.generation, call.next_generation().unwrap());
    assert!(matches!(
        management_retention::exact_management_retry("signed observation admin ACK", || {
            owner.supervisor_acknowledge(identity, work.clone(), authorization.clone())
        }),
        RuntimeOutcome::Acknowledged(Ok(_)),
    ));
}

fn api_query(
    owner: &MemoryBootstrapOwner,
    key: &SigningKey,
    nonce: u8,
    selector: AuthorityProjectionSelector,
) -> AuthorityProjectionQuery {
    let public = key.verifying_key().to_bytes();
    let mut request = AuthorityProjectionQuery {
        authority: owner.authority_target(),
        credential: CredentialId::of_public_key(&public),
        nonce: Hash([nonce; 32]),
        selector,
        recovery: None,
        authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
            credential_public_key: public,
            signature: [1; 64],
        },
    };
    let signature = key.sign(&request.signing_bytes()).to_bytes();
    request.authentication = AuthorityIngressAuthentication::ApiCredentialSignature {
        credential_public_key: public,
        signature,
    };
    request.verify_api_with(&RawCredentialVerifier).unwrap();
    request
}

/// Receipt signing alone does not enroll a credential. Use the existing signed
/// administrator path before a recovery fixture asks for an API observation.
pub(super) fn enroll_api_projection_credential(
    owner: &MemoryBootstrapOwner,
    index: usize,
    key: &SigningKey,
) {
    let request = api_query(owner, key, 0xec, AuthorityProjectionSelector::Credential);
    let before = owner.ordered_index_for_test().unwrap();
    let rejected =
        management_retention::exact_management_retry("unregistered API observation", || {
            owner.invoke_authority_observation(request.clone())
        });
    assert!(
        rejected.is_empty(),
        "an unenrolled signer cannot observe Authority"
    );
    assert_eq!(owner.ordered_index_for_test().unwrap(), before);
    let current = read(owner, &query(owner, index, 0xed));
    apply_signed_admin(
        owner,
        &current,
        AuthorityAdminOperation::AddCredential {
            principal: current.principal,
            credential: AuthorityCredentialEnrollment::from_public_key(
                AuthorityCredentialKind::Api,
                key.verifying_key().to_bytes(),
            ),
        },
    );
    let outcome = management_retention::exact_management_retry("enrolled API observation", || {
        observe(owner, &request)
    });
    let projection = credential_projection(&outcome).unwrap();
    assert_eq!(projection.query, request);
    assert_eq!(projection.principal, current.principal);
    assert_eq!(projection.kind, AuthorityCredentialKind::Api);
    assert_eq!(projection.status, AuthorityCredentialStatus::Active);
    assert_eq!(
        owner.ordered_index_for_test().unwrap(),
        before + 2,
        "only signed enrollment Invoke/ACK"
    );
}

fn exercise_revocation(
    owners: &[Option<MemoryBootstrapOwner>],
    stores: &[(
        BootstrapMemoryStore,
        BootstrapMemoryStore,
        IssuerMemoryStore,
    )],
) {
    let agent = HostAgentId(owners[0].as_ref().unwrap().pins.agent.0);
    let leader = owners
        .iter()
        .position(|owner| {
            owner
                .as_ref()
                .unwrap()
                ._network_host
                .bootstrap_is_local_leader(agent)
                .unwrap()
        })
        .unwrap();
    let owner = owners[leader].as_ref().unwrap();
    let key = SigningKey::from_bytes(&[0xe8; 32]);
    let current = read(owner, &query(owner, leader, 0xe8));
    apply_signed_admin(
        owner,
        &current,
        AuthorityAdminOperation::AddCredential {
            principal: current.principal,
            credential: AuthorityCredentialEnrollment::from_public_key(
                AuthorityCredentialKind::Api,
                key.verifying_key().to_bytes(),
            ),
        },
    );
    // Sign both requests while the credential is active. Neither a retained
    // signed request nor its pre-revocation physical material authorizes an
    // observation against a later state in which this credential is revoked.
    let credential = api_query(owner, &key, 0xe9, AuthorityProjectionSelector::Credential);
    let inventory = api_query(
        owner,
        &key,
        0xea,
        AuthorityProjectionSelector::Inventory {
            after: None,
            limit: 1,
            known_head: None,
        },
    );
    let before = management_retention::exact_management_retry("active API observation", || {
        owner.invoke_authority_observation(credential.clone())
    });
    let before = AuthorityCredentialProjection::decode(&before).unwrap();
    assert_eq!(before.query, credential);
    assert_eq!(before.status, AuthorityCredentialStatus::Active);
    assert_eq!(before.kind, AuthorityCredentialKind::Api);
    let page = management_retention::exact_management_retry("active API inventory", || {
        owner.invoke_authority_observation(inventory.clone())
    });
    let page = AuthorityInventoryProjectionPage::decode(&page).unwrap();
    assert_eq!(page.credential.query, inventory);
    assert_eq!(page.credential.status, AuthorityCredentialStatus::Active);
    assert!(!page.entries.is_empty());
    let stale_work = owner
        .prepare_authority_observation_work(&inventory)
        .unwrap();
    let current = read(owner, &query(owner, leader, 0xeb));
    apply_signed_admin(
        owner,
        &current,
        AuthorityAdminOperation::RevokeCredential {
            principal: current.principal,
            credential: credential.credential,
        },
    );
    let follower = (0..owners.len()).find(|index| *index != leader).unwrap();
    let observe_revoked = |owner: &MemoryBootstrapOwner| {
        let bytes = management_retention::exact_management_retry("revoked API observation", || {
            owner.invoke_authority_observation(credential.clone())
        });
        let revoked = AuthorityCredentialProjection::decode(&bytes).unwrap();
        assert_eq!(revoked.query, credential);
        assert_eq!(revoked.status, AuthorityCredentialStatus::Revoked);
        assert_eq!(revoked.kind, AuthorityCredentialKind::Api);
        assert!(revoked.head.state_revision > before.head.state_revision);
        let denied = management_retention::exact_management_retry("revoked API inventory", || {
            owner.invoke_authority_observation(inventory.clone())
        });
        // Inventory intentionally reports the current revocation claims, but
        // no privileged rows, cursor or reusable unchanged-head assertion.
        let denied = AuthorityInventoryProjectionPage::decode(&denied).unwrap();
        assert_eq!(denied.credential.query, inventory);
        assert_eq!(denied.credential.status, AuthorityCredentialStatus::Revoked);
        assert_eq!(denied.credential.head, revoked.head);
        assert!(denied.entries.is_empty());
        assert!(denied.next.is_none());
        assert!(!denied.unchanged);
        let stale =
            management_retention::exact_management_retry("stale prepared API inventory", || {
                owner._network_host.with_authority_observation(
                    agent,
                    inventory.commitment(),
                    |host| host.observe_system_authority(agent, &stale_work),
                )
            });
        let RuntimeOutcome::Completed(Ok(reply)) = stale else {
            panic!("revoked prepared inventory failed outside Authority: {stale:?}");
        };
        assert_eq!(reply.status, crate::agent_sdk::InvocationStatus::Done);
        let Some(crate::actors::value::Value::Bytes(bytes)) =
            crate::actors::value::Value::try_decode(&reply.reply)
        else {
            panic!("revoked prepared inventory reply is not bytes");
        };
        assert_eq!(
            AuthorityInventoryProjectionPage::decode(&bytes).unwrap(),
            denied
        );
    };
    // A different receiving voter establishes fresh quorum and applies its
    // own signed mutation/ACK prefix before it executes the old signed reads.
    observe_revoked(owners[follower].as_ref().unwrap());
    for owner in owners.iter().flatten() {
        observe_revoked(owner);
    }
    // Enrollment and revocation legitimately published two mutations and
    // their ACKs. Baseline only after all receivers have applied them; the
    // subsequent observations must publish nothing of their own.
    let baseline: Vec<_> = owners
        .iter()
        .zip(stores)
        .map(|(owner, stores)| {
            let owner = owner.as_ref().unwrap();
            (
                native_owner_physical_state(owner),
                owner
                    ._network_host
                    .management_recovery_manifest(agent)
                    .unwrap(),
                durable_owner_bytes(owner, stores),
            )
        })
        .collect();
    for (index, owner) in owners.iter().enumerate() {
        let owner = owner.as_ref().unwrap();
        observe_revoked(owner);
        assert_eq!(native_owner_physical_state(owner), baseline[index].0);
        assert_eq!(
            owner
                ._network_host
                .management_recovery_manifest(agent)
                .unwrap(),
            baseline[index].1
        );
        assert_eq!(
            durable_owner_bytes(owner, &stores[index]),
            baseline[index].2
        );
    }
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
) {
    let agent = HostAgentId(owners[leader].as_ref().unwrap().pins.agent.0);
    let follower = (0..owners.len()).find(|index| *index != leader).unwrap();
    let request = query(owners[leader].as_ref().unwrap(), leader, 0xa0);
    let expected = read(owners[leader].as_ref().unwrap(), &request);
    assert_eq!(read(owners[follower].as_ref().unwrap(), &request), expected);
    // Warm all receivers through the committed current-term frontier before
    // taking a baseline. ReadIndex may require a leadership no-op; that is
    // control-plane progress, not an observation/result journal entry.
    for owner in owners.iter().flatten() {
        assert_eq!(read(owner, &request), expected);
        // Exercise the production callback's exact target, freshness and reply
        // decoding, not only this fixture's raw-outcome diagnostics helper.
        let bytes = management_retention::exact_management_retry("production observation", || {
            owner.invoke_authority_observation(request.clone())
        });
        let returned = crate::agent_sdk::authority::AuthorityCredentialProjection::decode(&bytes)
            .expect("production callback returns the authenticated credential bytes");
        assert_eq!(returned, expected);
    }
    // This receiver already owns the committed frontier. One fresh physical
    // suffix audit is required, but repeating it under the same host guard
    // used to consume the bounded observation window without new evidence.
    let caught_up = owners[leader].as_ref().unwrap();
    let audits_before = caught_up
        .host
        .lock()
        .unwrap()
        .capacity_audits_for_test(agent)
        .unwrap();
    let outcome = observe(caught_up, &request)
        .expect("caught-up observation succeeds within the unchanged bound");
    assert_eq!(credential_projection(&outcome), Some(expected.clone()));
    assert_eq!(
        caught_up
            .host
            .lock()
            .unwrap()
            .capacity_audits_for_test(agent)
            .unwrap(),
        audits_before + 1,
        "caught-up observation performs one fresh capacity audit, not two",
    );
    let physical: Vec<_> = owners
        .iter()
        .map(|owner| native_owner_physical_state(owner.as_ref().unwrap()))
        .collect();
    let manifests: Vec<_> = owners
        .iter()
        .map(|owner| {
            owner
                .as_ref()
                .unwrap()
                ._network_host
                .management_recovery_manifest(agent)
                .unwrap()
        })
        .collect();
    let durable: Vec<_> = owners
        .iter()
        .zip(stores)
        .map(|(owner, stores)| durable_owner_bytes(owner.as_ref().unwrap(), stores))
        .collect();
    let assert_unchanged = |owners: &[Option<MemoryBootstrapOwner>],
                            allow_control_progress: bool| {
        for (index, owner) in owners.iter().enumerate() {
            let owner = owner.as_ref().unwrap();
            let mut actual = native_owner_physical_state(owner);
            if allow_control_progress {
                assert!(actual.2.applied_slots >= physical[index].2.applied_slots);
                assert!(actual.2.remaining_slots <= physical[index].2.remaining_slots);
                actual.2.applied_slots = physical[index].2.applied_slots;
                actual.2.remaining_slots = physical[index].2.remaining_slots;
            }
            assert_eq!(actual, physical[index]);
            assert_eq!(
                owner
                    ._network_host
                    .management_recovery_manifest(agent)
                    .unwrap(),
                manifests[index],
            );
            assert_eq!(durable_owner_bytes(owner, &stores[index]), durable[index]);
        }
    };

    // More than the generic retained-result capacity, without any ACK. Both
    // leaders and followers execute their own physical System/Authority guest.
    for ordinal in 0..40u8 {
        let index = usize::from(ordinal) % owners.len();
        let owner = owners[index].as_ref().unwrap();
        let request = query(owner, index, 0x40 + ordinal);
        let projection = read(owner, &request);
        assert_eq!(projection.head, expected.head);
        assert_eq!(projection.principal, expected.principal);
    }
    assert_unchanged(owners, false);

    // Bad cryptographic attestation is shape-valid. Authority returns empty
    // bytes for refusal, so a Done outer reply is not an authenticated answer.
    let owner = owners[follower].as_ref().unwrap();
    let mut invalid = query(owner, follower, 0xc1);
    let AuthorityIngressAuthentication::SshNodeAttestation { signature, .. } =
        &mut invalid.authentication
    else {
        unreachable!()
    };
    signature[0] ^= 1;
    let refusal = management_retention::exact_management_retry("invalid observation", || {
        observe(owner, &invalid)
    });
    assert!(credential_projection(&refusal).is_none());
    assert_unchanged(owners, false);

    // Discard a successful return, then reopen the real filesystem owner.
    // Recovery requires a fresh observation, not exact old read delivery.
    let lost = query(owner, follower, 0xc2);
    drop(read(owner, &lost));
    assert_unchanged(owners, false);
    drop(owners[follower].take());
    owners[follower] = Some(reopen_owner(
        &fixtures[follower],
        &directories[follower],
        &stores[follower],
        providers[follower].clone(),
        networks[follower].clone(),
        signer,
    ));
    let owner = owners[follower].as_ref().unwrap();
    let fresh = query(owner, follower, 0xc3);
    assert_eq!(read(owner, &fresh).head, expected.head);
    assert_unchanged(owners, true);

    // A fatal generation cut after real guest execution must discard the
    // return. Normal retirement then drains the held read lease and joins;
    // a cached owner cannot issue another observation from that generation.
    let owner = owners[follower].as_ref().unwrap();
    let retiring = query(owner, follower, 0xc7);
    let work = owner.prepare_authority_observation_work(&retiring).unwrap();
    let mut retirement = None;
    let refused =
        owner
            ._network_host
            .with_authority_observation(agent, retiring.commitment(), |host| {
                let result = host.observe_system_authority(agent, &work)?;
                let drain = owner
                    ._network_host
                    .stage_observation_retirement_for_test(agent)?;
                retirement = Some(std::thread::spawn(drain));
                Ok(result)
            });
    assert_eq!(refused, Err(SharedAgentHostError::Unavailable));
    let retirement = retirement.expect("guest completed before the stale generation cut");
    assert!(wait_until(std::time::Duration::from_secs(5), || retirement
        .is_finished()));
    retirement.join().unwrap();
    assert_eq!(
        observe(owner, &retiring),
        Err(SharedAgentHostError::TransportNotAttached),
    );
    owners[follower]
        .as_mut()
        .unwrap()
        ._network_host
        .refresh()
        .unwrap();
    let owner = owners[follower].as_ref().unwrap();
    let fresh = query(owner, follower, 0xc8);
    assert_eq!(read(owner, &fresh).head, expected.head);
    assert_unchanged(owners, true);

    // Isolate only Raft, not authenticated application RPCs. A sampled old
    // Leader role cannot replace a fresh quorum barrier. The other two voters
    // must elect and serve a new local observation without read custody.
    let leader = owners
        .iter()
        .position(|owner| {
            owner
                .as_ref()
                .unwrap()
                ._network_host
                .bootstrap_is_local_leader(agent)
                .unwrap()
        })
        .expect("the reopened healthy fixed-three cluster has a current leader");
    owners[leader]
        .as_ref()
        .unwrap()
        ._network_host
        .set_raft_isolated_for_test(agent, true)
        .unwrap();
    // A cancelled receiver does not cancel already admitted remote work.
    // Existing reply/failure processing must release its bounded permit even
    // when the caller no longer exists; the transport timeout remains 2s.
    let caller = (0..owners.len()).find(|index| *index != leader).unwrap();
    let available = networks[caller].authority_observation_available_permits_for_test();
    let cancelled = networks[caller].send_agent_authority_read_barrier(
        crate::agent_sdk::NodeId(owners[leader].as_ref().unwrap().pins.node.0),
        AgentGenerationRoute {
            space: owners[leader].as_ref().unwrap().pins.space,
            agent: owners[leader].as_ref().unwrap().pins.agent,
            generation: Hash(
                owners[leader]
                    .as_ref()
                    .unwrap()
                    .host
                    .lock()
                    .unwrap()
                    .supervisor_attachment_status(agent)
                    .unwrap()
                    .unwrap()
                    .replication_id,
            ),
        },
        crate::network::agent_protocol::AuthorityReadBarrierRequest {
            request: Hash([0xc9; 32]),
        },
    );
    assert!(available > 0);
    assert_eq!(
        networks[caller].authority_observation_available_permits_for_test(),
        available - 1,
        "cancellation must exercise an admitted request, not immediate refusal",
    );
    drop(cancelled);
    let isolated = owners[leader].as_ref().unwrap();
    let unavailable = query(isolated, leader, 0xc4);
    assert_eq!(
        observe(isolated, &unavailable),
        Err(SharedAgentHostError::Unavailable)
    );
    assert_eq!(native_owner_physical_state(isolated).0, physical[leader].0);
    assert_eq!(native_owner_physical_state(isolated).1, physical[leader].1);
    assert!(wait_until(std::time::Duration::from_secs(5), || {
        networks[caller].authority_observation_available_permits_for_test() == available
    }));
    let mut successor = None;
    assert!(wait_until(std::time::Duration::from_secs(30), || {
        successor = owners.iter().enumerate().find_map(|(index, owner)| {
            (index != leader
                && owner
                    .as_ref()
                    .unwrap()
                    ._network_host
                    .bootstrap_is_local_leader(agent)
                    .unwrap())
            .then_some(index)
        });
        successor.is_some()
    }));
    let successor = successor.unwrap();
    let owner = owners[successor].as_ref().unwrap();
    let fresh = query(owner, successor, 0xc5);
    assert_eq!(read(owner, &fresh).head, expected.head);
    let other = (0..owners.len())
        .find(|index| *index != leader && *index != successor)
        .unwrap();
    assert_eq!(
        read(owners[other].as_ref().unwrap(), &fresh).head,
        expected.head
    );
    owners[leader]
        .as_ref()
        .unwrap()
        ._network_host
        .set_raft_isolated_for_test(agent, false)
        .unwrap();
    let returned = query(owners[leader].as_ref().unwrap(), leader, 0xc6);
    assert_eq!(
        read(owners[leader].as_ref().unwrap(), &returned).head,
        expected.head
    );
    // Ordered state, manifest and WAL remain identical across a leadership
    // no-op. No assertion treats a changed Raft term as a read-state mutation.
    assert_unchanged(owners, true);
    exercise_revocation(owners, stores);
}
