//! Opt-in, explicitly disposable native campaign. Never use valuable old data.
use super::*;
use vos::agent::sdk::authority::{AgentAuthorityBinding, AuthorityIssuer};
use vos::agent::sdk::catalog::{CatalogActorTarget, CatalogPage, CatalogPageRequest};
use vos::agent::sdk::*;
use vos::agent::supervisor::AgentRouteKey;
use vos::agent::supervisor_adapters::{
    AgentAcknowledgementRequest, AgentAcknowledgementResponse, AgentInvocationIntent,
    AgentInvocationResponse,
};
use vos::{Decode as _, Encode as _};

fn protected_signer_roles() -> InvocationRoleClaims {
    InvocationRoleClaims {
        space: None,
        actor: Some(RoleId([0x51; 32])),
    }
}

#[test]
fn protected_signer_fixture_claims_the_required_actor_role() {
    let roles = protected_signer_roles();
    assert_eq!(roles.actor, Some(RoleId([0x51; 32])));
    assert_eq!(roles.space, None);
    assert!(roles.validate_for(InvocationOrigin {
        principal: Some(PrincipalId([0x71; 32])),
        ..InvocationOrigin::anonymous()
    }));
}

#[test]
#[ignore = "writes inputs only for an explicitly selected disposable protected actor campaign"]
fn prepare_disposable_protected_signer_inputs() {
    let root = PathBuf::from(std::env::var_os("VOSX_PROTECTED_SMOKE_ROOT").unwrap())
        .canonicalize()
        .unwrap();
    let scratch = PathBuf::from(std::env::var_os("TMPDIR").unwrap())
        .canonicalize()
        .unwrap();
    assert_eq!(root.parent(), Some(scratch.as_path()));
    assert!(
        root.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("admin-startup-smoke.")
    );
    let created: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("protected-create-resume-1.json")).unwrap(),
    )
    .unwrap();
    let ack = vos::agent::sdk::authority::ManagementApplicationAck::decode(
        &hex::decode(created["acknowledgement"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let (data, space, _, _) =
        super::super::local_create::resolve_local_space("admin-startup", None).unwrap();
    assert!(data.canonicalize().unwrap().starts_with(&root));
    assert_eq!(ack.managed.space, space);
    assert_eq!(
        created["agent"].as_str().unwrap(),
        hex::encode(ack.managed.agent.0)
    );
    let actor = ActorId::top_level(ack.managed.agent, "local-signer-smoke");
    let operator = crate::identity::load_existing().unwrap();
    let identity =
        super::super::clean_identity::CleanOperatorIdentitySigner::new(&operator).unwrap();
    // Public disposable fixture seed, never a production signing key.
    let constructor = vos::value::Args::new()
        .with("secret_seed", vec![0x71u8; 32])
        .encode();
    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(
        &vos::value::Msg::new("sign")
            .with("context", vec![0x72u8; 32])
            .with("message", b"protected-local-smoke".to_vec())
            .encode(),
    );
    let intent = AgentTargetedPreparationRequest::new(
        AgentRouteKey::new(space, ack.managed.agent, actor).unwrap(),
        AgentInvocationIntent::new(
            InvocationId([0x73; 32]),
            MethodMode::Linear,
            InvocationOrigin {
                principal: Some(identity.principal()),
                credential: Some(identity.credential()),
                ..InvocationOrigin::anonymous()
            },
            protected_signer_roles(),
            message,
            vos::agent::execution::MAX_EXECUTION_GAS,
            false,
        )
        .unwrap(),
    )
    .unwrap();
    // Re-running this input generator cannot replace a retained intent.
    for (name, bytes) in [
        ("protected-constructor.bin", constructor),
        ("protected-sign.intent", intent.encode().unwrap()),
    ] {
        let path = root.join(name);
        if path.exists() {
            assert_eq!(std::fs::read(path).unwrap(), bytes);
        } else {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .unwrap();
            file.write_all(&bytes).unwrap();
            file.sync_all().unwrap();
        }
    }
    eprintln!("protected actor={}", hex::encode(actor.0));
}

#[test]
#[ignore = "requires explicitly selected disposable native managed invocation campaign"]
fn real_daemon_managed_receipt_invocation_and_exact_retry() {
    managed_receipt_invocation_and_exact_retry(Campaign::Catalog);
}

#[test]
#[ignore = "requires completed disposable protected signer invocation; verifies retained evidence only"]
fn verify_disposable_protected_signer_result() {
    let root = PathBuf::from(std::env::var_os("VOSX_PROTECTED_SMOKE_ROOT").unwrap())
        .canonicalize()
        .unwrap();
    let scratch = PathBuf::from(std::env::var_os("TMPDIR").unwrap())
        .canonicalize()
        .unwrap();
    assert_eq!(root.parent(), Some(scratch.as_path()));
    assert!(
        root.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("admin-startup-smoke.")
    );
    let output: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("protected-invoke-1.json")).unwrap())
            .unwrap();
    assert_eq!(output["decision"], "issued");
    assert_eq!(output["delivery_retired"], true);
    assert_eq!(output["reservation_pending"], false);
    let authorization = PathBuf::from(output["request_dir"].as_str().unwrap())
        .canonicalize()
        .unwrap();
    assert!(authorization.starts_with(root.join("space/agent-client/operations")));
    let application = authorization.parent().unwrap().join("application");
    let mut store =
        super::super::clean_store::CleanInvocationFile::open_or_create(&application).unwrap();
    let request = store.load_request().unwrap().unwrap();
    let response = store.load_response().unwrap().unwrap();
    let progress = store.load_progress().unwrap().unwrap();
    assert!(
        super::super::invocation_progress::Progress::decode(&progress, &request, &response)
            .unwrap()
            .is_retired(&request, &response)
            .unwrap()
    );
    let call = super::super::local_invocation::validate_request(&request).unwrap();
    assert!(matches!(
        call.authorization(),
        InvocationAuthorization::AuthorityReceipt(_)
    ));
    let package = vos::agent::package_admission::admit_actor_package(
        &std::fs::read(root.join("protected-signer/LocalSigner.vos")).unwrap(),
    )
    .unwrap();
    assert_eq!(call.work().program, package.program());
    assert_eq!(call.work().deployment, package.deployment());
    let AgentInvocationResponse::Direct {
        outcome: RuntimeOutcome::Completed(Ok(reply)),
        ..
    } = super::super::local_invocation::verify_response(&request, &response).unwrap()
    else {
        panic!("protected invocation did not succeed");
    };
    assert_eq!(reply.status, InvocationStatus::Done);
    let vos::value::Value::Bytes(signature) = vos::value::Value::try_decode(&reply.reply).unwrap()
    else {
        panic!("expected visible signature bytes");
    };
    let mut signed = b"vos/local-signer/v1".to_vec();
    signed.extend_from_slice(&[0x72; 32]);
    signed.extend_from_slice(&(b"protected-local-smoke".len() as u64).to_le_bytes());
    signed.extend_from_slice(b"protected-local-smoke");
    ed25519_dalek::SigningKey::from_bytes(&[0x71; 32])
        .verifying_key()
        .verify_strict(
            &signed,
            &ed25519_dalek::Signature::from_slice(&signature).unwrap(),
        )
        .unwrap();
    eprintln!(
        "protected signature and retained retirement verified; restart and revoke remain separate gates"
    );
}

#[test]
#[ignore = "requires completed disposable managed invocation and explicit native campaign"]
fn real_daemon_fresh_successor_invocation_and_exact_retry() {
    managed_receipt_invocation_and_exact_retry(Campaign::Successor);
}

#[test]
#[ignore = "requires freshly installed disposable Counter and explicit native campaign"]
fn real_daemon_counter_mutation_and_exact_retry() {
    managed_receipt_invocation_and_exact_retry(Campaign::CounterMutation);
}

#[test]
#[ignore = "requires completed Counter mutation followed by an explicit daemon restart"]
fn real_daemon_counter_value_after_restart() {
    managed_receipt_invocation_and_exact_retry(Campaign::CounterRead);
}

#[derive(Clone, Copy)]
enum Campaign {
    Catalog,
    Successor,
    CounterMutation,
    CounterRead,
}

fn managed_receipt_invocation_and_exact_retry(campaign: Campaign) {
    let successor = matches!(campaign, Campaign::Successor);
    let counter = matches!(campaign, Campaign::CounterMutation | Campaign::CounterRead);
    let config_path = PathBuf::from(
        std::env::var_os("VOSX_INVOKE_SMOKE_CONFIG").expect("explicit disposable configuration"),
    );
    let (data, space, node_public, address) =
        super::super::local_create::resolve_local_space("native-denial-smoke", None).unwrap();
    assert!(data.to_string_lossy().contains("native-denial-head-reuse."));
    assert_eq!(config_path.parent(), data.parent());
    // Counter uses the already verified Create CLI result for its coordinates;
    // it does not need an unrelated Catalog installed in the same Local agent.
    let target = if counter {
        let created: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
        let acknowledgement = vos::agent::sdk::authority::ManagementApplicationAck::decode(
            &hex::decode(created["acknowledgement"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(acknowledgement.managed.space, space);
        assert_eq!(
            created["agent"].as_str().unwrap(),
            hex::encode(acknowledgement.managed.agent.0)
        );
        let package = vos::agent::package_admission::admit_actor_package(
            &std::fs::read(data.parent().unwrap().join("counter-artifact/Counter.vos")).unwrap(),
        )
        .unwrap();
        CatalogActorTarget {
            space,
            system_agent: acknowledgement.managed.agent,
            system_runtime_deployment: acknowledgement.managed.runtime_deployment,
            actor: ActorId::top_level(acknowledgement.managed.agent, "counter-smoke"),
            deployment: package.deployment(),
            program: package.program(),
            authority: acknowledgement.authority.binding,
        }
    } else {
        let config = system_catalog::SystemCatalogConfiguration::decode(
            &std::fs::read(config_path).unwrap(),
        )
        .unwrap();
        assert_eq!(config.space, space.0);
        CatalogActorTarget {
            space,
            system_agent: AgentId(config.system_agent),
            system_runtime_deployment: DeploymentId(config.system_runtime_deployment),
            actor: ActorId(config.actor),
            deployment: DeploymentId(config.deployment),
            program: ProgramId(config.program),
            authority: AgentAuthorityBinding {
                policy: Hash(config.authority.policy),
                public_key: config.authority.public_key,
                initial_epoch: config.authority.initial_epoch,
                issuer: AuthorityIssuer {
                    principal: PrincipalId(config.authority.issuer.principal),
                    actor: ActorId(config.authority.issuer.actor),
                    deployment: DeploymentId(config.authority.issuer.deployment),
                    program: ProgramId(config.authority.issuer.program),
                    producer: ProducerId(config.authority.issuer.producer),
                },
            },
        }
    };
    let query = CatalogPageRequest {
        catalog: target,
        namespace: "managed-invoke-smoke".into(),
        after: None,
        limit: 1,
    };
    let counter_package = counter.then(|| {
        let path = data.parent().unwrap().join("counter-artifact/Counter.vos");
        vos::agent::package_admission::admit_actor_package(&std::fs::read(path).unwrap()).unwrap()
    });
    let operator = crate::identity::load_existing().unwrap();
    let identity =
        super::super::clean_identity::CleanOperatorIdentitySigner::new(&operator).unwrap();
    let predecessor = if successor {
        let mut prior = CleanPreparationClientFile::open_or_create(
            data.join("agent-client/managed-invocation-smoke"),
        )
        .unwrap();
        let prior = AgentTargetedPreparationRequest::decode(
            &prior
                .load_request()
                .unwrap()
                .expect("completed predecessor intent"),
        )
        .unwrap();
        let nonce = Hash(prior.intent().invocation().0);
        let request_root = data
            .join("agent-client/operations")
            .join(format!(
                "{}-{}",
                hex::encode(identity.credential().0),
                hex::encode(nonce.0)
            ))
            .join("request");
        let mut store = CleanOperationClientFile::open_or_create(&request_root).unwrap();
        let bytes = store
            .load_request()
            .unwrap()
            .expect("predecessor authorization");
        let call = AuthorityOperationSubmission::decode(&bytes).unwrap();
        assert!(store.load_response().unwrap().is_some());
        Some((
            nonce,
            call.call().request_sequence.get(),
            request_root,
            bytes,
        ))
    } else {
        None
    };
    let root = data.join(match campaign {
        Campaign::Catalog => "agent-client/managed-invocation-smoke",
        Campaign::Successor => "agent-client/managed-invocation-successor",
        Campaign::CounterMutation => "agent-client/managed-counter-mutation",
        Campaign::CounterRead => "agent-client/managed-counter-read-after-restart",
    });
    let mut intent_store = CleanPreparationClientFile::open_or_create(&root).unwrap();
    let intent = match intent_store.load_request().unwrap() {
        Some(bytes) => AgentTargetedPreparationRequest::decode(&bytes).unwrap(),
        None => {
            if let Some((nonce, _, _, _)) = &predecessor {
                let mut reservation = CleanCredentialReservation::open_or_create(
                    &data.join("agent-client/credentials"),
                    space,
                    identity.credential(),
                )
                .unwrap();
                assert_eq!(
                    reservation.current().unwrap(),
                    Some((*nonce, CredentialReservationStatus::Completed)),
                    "fresh successor requires completed predecessor; never clear pending state"
                );
            }
            let mut nonce = [0; 32];
            getrandom::getrandom(&mut nonce).unwrap();
            let mut message = vec![vos::value::TAG_DYNAMIC];
            let call = match campaign {
                Campaign::CounterMutation => vos::value::Msg::new("increment").with("by", 7u64),
                Campaign::CounterRead => vos::value::Msg::new("value"),
                _ => vos::value::Msg::new("page").with("request", query.encode().unwrap()),
            };
            message.extend_from_slice(&call.encode());
            let actor = if counter {
                ActorId::top_level(target.system_agent, "counter-smoke")
            } else {
                target.actor
            };
            let intent = AgentTargetedPreparationRequest::new(
                AgentRouteKey::new(space, target.system_agent, actor).unwrap(),
                AgentInvocationIntent::new(
                    InvocationId(nonce),
                    if matches!(campaign, Campaign::CounterMutation) {
                        MethodMode::Linear
                    } else {
                        MethodMode::Query
                    },
                    InvocationOrigin {
                        principal: Some(identity.principal()),
                        credential: Some(identity.credential()),
                        ..InvocationOrigin::anonymous()
                    },
                    InvocationRoleClaims::none(),
                    message,
                    vos::agent::execution::MAX_EXECUTION_GAS,
                    false,
                )
                .unwrap(),
            )
            .unwrap();
            intent_store
                .publish_request(&intent.encode().unwrap())
                .unwrap();
            intent
        }
    };
    drop(intent_store);
    let start = std::time::Instant::now();
    eprintln!(
        "starting native managed receipt invocation {}",
        hex::encode(intent.intent().invocation().0)
    );
    let result = authorize_with_application(
        &data,
        address,
        &operator,
        space,
        node_public,
        Some(&intent),
        true,
    );
    eprintln!(
        "native managed attempt finished in {:.2}s: {}",
        start.elapsed().as_secs_f64(),
        if result.is_ok() {
            "completed"
        } else {
            "failed; retained state preserved"
        }
    );
    let (authorization_root, _) = result.unwrap();
    if let Some((prior_nonce, sequence, prior_root, prior_bytes)) = predecessor {
        assert_ne!(intent.intent().invocation().0, prior_nonce.0);
        let mut store = CleanOperationClientFile::open_or_create(&authorization_root).unwrap();
        let bytes = store.load_request().unwrap().unwrap();
        assert_eq!(
            AuthorityOperationSubmission::decode(&bytes)
                .unwrap()
                .call()
                .request_sequence
                .get(),
            sequence.checked_add(1).unwrap()
        );
        let mut prior = CleanOperationClientFile::open_or_create(prior_root).unwrap();
        assert_eq!(prior.load_request().unwrap().unwrap(), prior_bytes);
    }
    let application_root = authorization_root.parent().unwrap().join("application");
    let mut store =
        super::super::clean_store::CleanInvocationFile::open_or_create(&application_root).unwrap();
    let request = store.load_request().unwrap().expect("retained ASQ1");
    let response = store.load_response().unwrap().expect("retained ASR1");
    let progress = store.load_progress().unwrap().expect("retained retirement");
    assert!(
        super::super::invocation_progress::Progress::decode(&progress, &request, &response)
            .unwrap()
            .is_retired(&request, &response)
            .unwrap()
    );
    drop(store);
    let call = super::super::local_invocation::validate_request(&request).unwrap();
    assert!(matches!(
        call.authorization(),
        InvocationAuthorization::AuthorityReceipt(_)
    ));
    let AgentInvocationResponse::Direct {
        outcome: RuntimeOutcome::Completed(Ok(reply)),
        ..
    } = super::super::local_invocation::verify_response(&request, &response).unwrap()
    else {
        panic!("managed invocation did not succeed");
    };
    assert_eq!(reply.status, InvocationStatus::Done);
    if let Some(package) = counter_package {
        assert_eq!(call.work().program, package.program());
        assert_eq!(call.work().deployment, package.deployment());
        assert_eq!(
            vos::value::Value::try_decode(&reply.reply).unwrap(),
            vos::value::Value::U64(7)
        );
        // The managed path already acknowledged (and deleted) the reply.
        // Late Invoke must reject the consumed identity, not execute it again.
        // ACK retries below remain positive; a fresh post-restart Query checks
        // that the mutation happened once.
        for _ in 0..2 {
            let repeated = super::super::local_create::post_binary(
                address,
                "/__agents/invoke",
                200,
                &request,
                super::super::local_invocation::MAX_RESPONSE_BYTES,
            )
            .unwrap();
            assert!(matches!(
                super::super::local_invocation::verify_response(&request, &repeated).unwrap(),
                AgentInvocationResponse::Direct {
                    outcome: RuntimeOutcome::Completed(Err(InvocationError::DivergentInvocation)),
                    ..
                }
            ));
        }
    } else {
        let vos::value::Value::Bytes(bytes) = vos::value::Value::try_decode(&reply.reply).unwrap()
        else {
            panic!("expected Catalog bytes");
        };
        let page = CatalogPage::decode(&bytes).unwrap();
        assert_eq!(page.catalog, target);
        assert_eq!(page.namespace, query.namespace);
        assert!(page.entries.is_empty());
        assert!(page.next.is_none());
    }
    // Contact the real host even when all client work was already retained.
    let ack = AgentAcknowledgementRequest::new(
        RuntimeExecutionContext::Direct,
        None,
        call.work().clone(),
        call.authorization().clone(),
    )
    .unwrap();
    let mut previous = None;
    for _ in 0..2 {
        let bytes = super::super::local_create::post_binary(
            address,
            "/__agents/acknowledge",
            200,
            &ack.encode().unwrap(),
            super::super::local_invocation::MAX_RESPONSE_BYTES,
        )
        .unwrap();
        let response = AgentAcknowledgementResponse::decode(&bytes).unwrap();
        assert!(response.matches_request(&ack));
        assert!(matches!(
            response.outcome(),
            RuntimeOutcome::Acknowledged(Ok(_))
        ));
        if let Some(previous) = previous.replace(bytes.clone()) {
            assert_eq!(bytes, previous);
        }
    }
    assert!(
        authorize_with_application(&data, address, &operator, space, node_public, None, true)
            .is_ok()
    );
    eprintln!(
        "native receipt-bearing invocation, positive retirement and exact retry passed; this is not a non-Public policy proof"
    );
}
