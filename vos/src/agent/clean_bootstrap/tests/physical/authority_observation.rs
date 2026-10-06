//! Physical fixed-three observations: fresh quorum, receiver-local guest,
//! no query custody, result retirement, or read-specific durable publication.

use super::*;
use crate::actors::codec::{Decode as _, Encode as _};
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

fn check_decoded_observation_against_checked_work(
    owner: &MemoryBootstrapOwner,
    request: &AuthorityProjectionQuery,
    expected: &AuthorityCredentialProjection,
) {
    use crate::agent_sdk as sdk;
    use crate::agent::wire::{apply_standard_runtime_input, apply_standard_runtime_work};
    use crate::service::wire::ServiceWire as _;

    let agent = HostAgentId(owner.pins.agent.0);
    let (state, observed_slot) = owner
        .host
        .lock()
        .unwrap()
        .observation_runtime_state_for_test(agent)
        .unwrap();
    // Execute owned fixture copies outside the host guard. These component
    // comparisons grant no fresh ReadIndex proof or permission to publish.
    let signed = owner.prepare_authority_observation_work(request).unwrap();
    let envelope = |invocation: sdk::InvocationWork, slot| sdk::RuntimeWork::Observe {
        context: sdk::RuntimeExecutionContext::Direct,
        state: state.clone(),
        authorization: Box::new(sdk::InvocationAuthorization::PublicPreflight(
            sdk::PublicPreflight::for_work(&invocation, slot),
        )),
        invocation: Box::new(invocation),
        observed_slot: slot,
    };
    let compare = |work: &sdk::RuntimeWork| {
        // The constructed entry remains the independent fully checked path.
        let checked = apply_standard_runtime_work(work.clone()).unwrap();
        let decoded = apply_standard_runtime_input(&work.encode().unwrap()).unwrap();
        assert_eq!(decoded.encode().unwrap(), checked.encode().unwrap());
        assert_eq!(decoded.state, state, "all four opaque components remain exact");
        decoded
    };
    let reply_bytes = |returned: &sdk::RuntimeTransition| {
        let sdk::RuntimeOutcome::Completed(Ok(reply)) = &returned.outcome else {
            panic!("observation did not return a terminal actor reply");
        };
        assert_eq!(reply.status, sdk::InvocationStatus::Done);
        let Some(crate::actors::value::Value::Bytes(bytes)) =
            crate::actors::value::Value::try_decode(&reply.reply)
        else {
            panic!("Authority reply is not a byte value");
        };
        bytes
    };
    let signed_work = envelope(signed.clone(), observed_slot);
    let returned = compare(&signed_work);
    assert_eq!(
        AuthorityCredentialProjection::decode(&reply_bytes(&returned)).unwrap(),
        *expected,
    );

    // Reuse the real installed target/artifacts and existing nonzero query ID.
    // This is the production committee message shape, not a GenesisCandidate
    // root-lineage assertion or a fabricated genesis nonce.
    let mut committee = signed.clone();
    committee.origin = sdk::InvocationOrigin::anonymous();
    committee.message = vec![crate::actors::value::TAG_DYNAMIC];
    committee.message.extend(crate::actors::value::Msg::new("genesis_signing_committee").encode());
    let returned = compare(&envelope(committee, observed_slot));
    let decoded_committee = AuthorityCommittee::decode(&reply_bytes(&returned)).unwrap();
    assert_eq!(decoded_committee.space(), HostSpaceId(owner.pins.space.0));
    assert_eq!(
        decoded_committee.authority_binding(),
        HostHash(owner.pins.authority.commitment().0),
    );

    let reject = |work: &sdk::RuntimeWork| {
        let returned = compare(work);
        assert!(matches!(returned.outcome, sdk::RuntimeOutcome::Completed(Err(_))));
    };
    let mut wrong_target = signed.clone();
    wrong_target.actor = sdk::ActorId([0xfe; 32]);
    reject(&envelope(wrong_target, observed_slot));
    let mut claimed_origin = signed.clone();
    claimed_origin.origin.principal = Some(owner.pins.descriptor.identity.owner);
    reject(&envelope(claimed_origin, observed_slot));
    let mut missing_installation = signed.clone();
    missing_installation.installation_data = None;
    reject(&envelope(missing_installation, observed_slot));
    reject(&envelope(signed.clone(), 0));

    let material = owner
        .supervisor_invocation_material(owner.pins.agent, signed.actor)
        .unwrap();
    let mut wrong_program = signed.clone();
    let program = wrong_program.availability.iter_mut()
        .find(|blob| blob.reference == material.program.reference).unwrap();
    program.bytes[0] ^= 1;
    program.reference = sdk::BlobRef::of_bytes(&program.bytes);
    wrong_program.availability.sort_unstable_by(|a, b| a.reference.cmp(&b.reference));
    assert!(wrong_program.validate(), "canonical BlobRef validity does not prove the installed ProgramId");
    reject(&envelope(wrong_program, observed_slot));
    let mut wrong_schema = signed.clone();
    let schema = wrong_schema.availability.iter_mut()
        .find(|blob| blob.reference == material.schema.reference).unwrap();
    schema.bytes[0] ^= 1;
    schema.reference = sdk::BlobRef::of_bytes(&schema.bytes);
    wrong_schema.availability.sort_unstable_by(|a, b| a.reference.cmp(&b.reference));
    assert!(wrong_schema.validate());
    reject(&envelope(wrong_schema, observed_slot));

    let mut malformed_state = signed_work.clone();
    let sdk::RuntimeWork::Observe { state: malformed, .. } = &mut malformed_state
    else { unreachable!() };
    malformed.control[0] ^= 1;
    let encoded_malformed = malformed_state.encode().unwrap();
    let checked_error = apply_standard_runtime_work(malformed_state).unwrap_err();
    assert_eq!(checked_error, crate::service::wire::DecodeError::InvalidPlatform);
    assert_eq!(apply_standard_runtime_input(&encoded_malformed).unwrap_err(), checked_error);

    // Canonical work validation is not a substitute for installed guest
    // authentication. Shape-valid bad signatures must still return refusal.
    let mut bad_query = request.clone();
    let AuthorityIngressAuthentication::SshNodeAttestation { signature, .. } =
        &mut bad_query.authentication
    else { unreachable!() };
    signature[0] ^= 1;
    let bad_signed = owner.prepare_authority_observation_work(&bad_query).unwrap();
    assert!(reply_bytes(&compare(&envelope(bad_signed, observed_slot))).is_empty());

    let encoded = signed_work.encode().unwrap();
    let largest = signed.availability.iter().max_by_key(|blob| blob.bytes.len()).unwrap();
    // Availability follows the opaque state in AWRK. Choose its final exact
    // preimage occurrence, never a matching artifact retained in the state.
    let offset = encoded.windows(largest.bytes.len())
        .rposition(|bytes| bytes == largest.bytes).unwrap();
    let mut corrupt = encoded.clone();
    corrupt[offset] ^= 1;
    assert!(apply_standard_runtime_input(&corrupt).is_err());
    assert!(apply_standard_runtime_input(&encoded[..encoded.len() - 1]).is_err());
    let mut trailing = encoded;
    trailing.push(0);
    assert!(apply_standard_runtime_input(&trailing).is_err());

    // Constructed-value callers cannot mint the decoder's borrowed proof.
    let mut corrupt_constructed = signed.clone();
    let preimage = corrupt_constructed.availability.iter_mut()
        .max_by_key(|blob| blob.bytes.len()).unwrap();
    preimage.bytes[0] ^= 1;
    let returned = apply_standard_runtime_work(envelope(corrupt_constructed, observed_slot)).unwrap();
    assert_eq!(returned.state, state);
    assert!(matches!(returned.outcome, sdk::RuntimeOutcome::Completed(Err(_))));
    for variant in 0..3 {
        let mut invalid = signed_work.clone();
        let sdk::RuntimeWork::Observe { invocation, authorization, .. } = &mut invalid
        else { unreachable!() };
        match variant {
            0 => invocation.mode = sdk::MethodMode::Linear,
            1 => invocation.recovery_only = true,
            2 => {
                let sdk::InvocationAuthorization::PublicPreflight(preflight) = authorization.as_mut()
                else { unreachable!() };
                preflight.observed_slot += 1;
            }
            _ => unreachable!(),
        }
        assert!(invalid.encode().is_err());
        let returned = apply_standard_runtime_work(invalid).unwrap();
        assert_eq!(returned.state, state);
        assert!(matches!(returned.outcome, sdk::RuntimeOutcome::Completed(Err(_))));
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
    check_decoded_observation_against_checked_work(caught_up, &request, &expected);
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
