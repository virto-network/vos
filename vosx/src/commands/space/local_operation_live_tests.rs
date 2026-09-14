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

#[test]
#[ignore = "requires explicitly selected disposable native managed invocation campaign"]
fn real_daemon_managed_receipt_invocation_and_exact_retry() {
    managed_receipt_invocation_and_exact_retry(Campaign::Catalog);
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
