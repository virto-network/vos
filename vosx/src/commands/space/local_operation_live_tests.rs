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

fn protected_signer_campaign_files() -> (&'static str, &'static str, u8) {
    match std::env::var("VOSX_PROTECTED_SMOKE_PHASE").as_deref() {
        Err(std::env::VarError::NotPresent) => {
            ("protected-sign.intent", "protected-invoke-1.json", 0x73)
        }
        Ok("after-restart") => (
            "protected-sign-after-restart.intent",
            "protected-invoke-after-restart.json",
            0x74,
        ),
        Ok("revoked") => (
            "protected-sign-revoked.intent",
            "protected-invoke-revoked.json",
            0x75,
        ),
        Ok("after-regrant") => (
            "protected-sign-regranted.intent",
            "protected-invoke-regranted.json",
            0x76,
        ),
        Ok("capacity-probe") => (
            "protected-sign-capacity.intent",
            "protected-invoke-capacity.json",
            0x77,
        ),
        other => panic!("unsupported protected campaign phase: {other:?}"),
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
#[ignore = "diagnoses authenticated preparation only in the explicitly selected disposable campaign"]
fn diagnose_disposable_protected_preparation() {
    use std::io::Read as _;
    use vos::agent::supervisor_adapters::AgentTargetedPreparationResponse;
    let (intent_file, _, _) = protected_signer_campaign_files();
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
    let (data, _, _, address) =
        super::super::local_create::resolve_local_space("admin-startup", None).unwrap();
    assert!(data.canonicalize().unwrap().starts_with(&root));
    assert!(address.ip().is_loopback() && address.port() != 0);
    let key = crate::identity::load_existing()
        .unwrap()
        .try_into_ed25519()
        .unwrap();
    let secret = key.secret();
    let token = vos::ingress::encode_access_token(secret.as_ref().try_into().unwrap()).unwrap();
    let bytes = std::fs::read(root.join(intent_file)).unwrap();
    let request = AgentTargetedPreparationRequest::decode(&bytes).unwrap();
    let result = ureq::AgentBuilder::new()
        .try_proxy_from_env(false)
        .redirects(0)
        .timeout_connect(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(130))
        .build()
        .post(&format!("http://{address}/__agents/prepare"))
        .set("Content-Type", "application/octet-stream")
        .set("Authorization", &format!("Bearer {token}"))
        .send_bytes(&bytes);
    match result {
        Ok(response) => {
            assert_eq!(response.status(), 200);
            let mut body = Vec::new();
            response
                .into_reader()
                .take(AgentTargetedPreparationResponse::MAX_ENCODED_BYTES as u64 + 1)
                .read_to_end(&mut body)
                .unwrap();
            let response = AgentTargetedPreparationResponse::decode(&body).unwrap();
            assert!(response.for_request(&request).is_some());
            eprintln!(
                "authenticated preparation verified against exact intent; no authorization or invocation issued"
            );
        }
        Err(ureq::Error::Status(status, response)) => {
            let mut body = String::new();
            response
                .into_reader()
                .take(256)
                .read_to_string(&mut body)
                .unwrap();
            panic!("authenticated preparation status={status}: {body}");
        }
        Err(error) => panic!("authenticated preparation transport error: {error}"),
    }
}

#[test]
#[ignore = "writes inputs only for an explicitly selected disposable protected actor campaign"]
fn prepare_disposable_protected_signer_inputs() {
    let (intent_file, _, nonce) = protected_signer_campaign_files();
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
    let package = vos::agent::package_admission::admit_actor_package(
        &std::fs::read(root.join("protected-signer/LocalSigner.vos")).unwrap(),
    )
    .unwrap();
    let policies = vos::agent::sdk::method_policy::ActorMethodPolicyArtifact::decode(
        package.method_policy_bytes(),
    )
    .unwrap();
    let method = policies.method("sign").unwrap();
    assert_eq!(method.mode, MethodMode::Local);
    assert_eq!(
        method.authorization_policy,
        vos::agent::sdk::method_policy::AuthorizationPolicySelector::ActorRole(RoleId([0x51; 32]))
    );
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
            InvocationId([nonce; 32]),
            method.mode,
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
        (intent_file, intent.encode().unwrap()),
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
#[ignore = "requires terminal disposable protected signer campaign; verifies retained evidence only"]
fn verify_disposable_protected_signer_result() {
    let (intent_file, output_file, _) = protected_signer_campaign_files();
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
        serde_json::from_slice(&std::fs::read(root.join(output_file)).unwrap()).unwrap();
    assert_eq!(output["reservation_pending"], false);
    let authorization = PathBuf::from(output["request_dir"].as_str().unwrap())
        .canonicalize()
        .unwrap();
    assert!(authorization.starts_with(root.join("space/agent-client/operations")));
    let application = authorization.parent().unwrap().join("application");
    if std::env::var("VOSX_PROTECTED_SMOKE_PHASE").as_deref() == Ok("revoked") {
        use vos::agent::supervisor_adapters::AgentTargetedPreparationResponse;
        assert_eq!(output["decision"], "denied");
        assert_eq!(output["decision_retained"], true);
        assert_eq!(output["applied"], false);
        assert!(
            !application.exists(),
            "denied work must not create an actor application"
        );
        let mut delivery = CleanOperationClientFile::open_or_create(&authorization).unwrap();
        let request = delivery.load_request().unwrap().unwrap();
        let response = delivery.load_response().unwrap().unwrap();
        assert_eq!(hex::encode(&response), output["response"].as_str().unwrap());
        let submission = AuthorityOperationSubmission::decode(&request).unwrap();
        assert!(matches!(
            submission.decode_response(&response).unwrap(),
            vos::agent::clean_bootstrap::NativeAuthorityOperationDecision::Denied { .. }
        ));
        let intent_bytes = std::fs::read(root.join(intent_file)).unwrap();
        let intent = AgentTargetedPreparationRequest::decode(&intent_bytes).unwrap();
        let mut preparation = CleanPreparationClientFile::open_or_create(
            authorization.parent().unwrap().join("preparation"),
        )
        .unwrap();
        assert_eq!(preparation.load_request().unwrap().unwrap(), intent_bytes);
        let prepared = AgentTargetedPreparationResponse::decode(
            &preparation.load_response().unwrap().unwrap(),
        )
        .unwrap();
        let prepared = prepared.for_request(&intent).unwrap();
        let AuthorityOperationIntent::InvokeActor {
            managed,
            operation_invocation,
            actor,
            actor_deployment,
            work,
            origin,
            roles,
        } = &submission.call().intent
        else {
            panic!("denial was not for actor invocation");
        };
        assert_eq!(managed.space, intent.target().space());
        assert_eq!(managed.agent, intent.target().agent());
        assert_eq!(*actor, intent.target().actor());
        assert_eq!(*operation_invocation, intent.intent().invocation());
        assert_eq!(*actor_deployment, prepared.work().deployment);
        assert_eq!(*work, prepared.work().commitment());
        assert_eq!(*origin, intent.intent().origin());
        assert_eq!(*roles, protected_signer_roles());
        let mut reservation = CleanCredentialReservation::open_or_create(
            &root.join("space/agent-client/credentials"),
            managed.space,
            submission.call().credential,
        )
        .unwrap();
        assert_eq!(
            reservation.current().unwrap(),
            Some((
                Hash(operation_invocation.0),
                CredentialReservationStatus::Denied
            ))
        );
        eprintln!(
            "signed request-bound denial retained; credential reservation denied; no actor application created"
        );
        return;
    }
    assert_eq!(output["decision"], "issued");
    assert_eq!(output["delivery_retired"], true);
    if std::env::var("VOSX_PROTECTED_SMOKE_PHASE").as_deref() == Ok("after-regrant") {
        let denied: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join("protected-invoke-revoked.json")).unwrap(),
        )
        .unwrap();
        let denied_root = PathBuf::from(denied["request_dir"].as_str().unwrap())
            .canonicalize()
            .unwrap();
        assert!(denied_root.starts_with(root.join("space/agent-client/operations")));
        assert_ne!(denied_root, authorization);
        let mut previous = CleanOperationClientFile::open_or_create(&denied_root).unwrap();
        let previous_call =
            AuthorityOperationSubmission::decode(&previous.load_request().unwrap().unwrap())
                .unwrap();
        assert!(matches!(
            previous_call
                .decode_response(&previous.load_response().unwrap().unwrap())
                .unwrap(),
            vos::agent::clean_bootstrap::NativeAuthorityOperationDecision::Denied { .. }
        ));
        let mut current = CleanOperationClientFile::open_or_create(&authorization).unwrap();
        let current_call =
            AuthorityOperationSubmission::decode(&current.load_request().unwrap().unwrap())
                .unwrap();
        assert_eq!(
            current_call.call().request_sequence,
            previous_call.call().request_sequence,
            "denial must not consume the operation credential sequence"
        );
        assert_ne!(current_call.call().intent, previous_call.call().intent);
    }
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
    let intent =
        AgentTargetedPreparationRequest::decode(&std::fs::read(root.join(intent_file)).unwrap())
            .unwrap();
    assert_eq!(call.work().space, intent.target().space());
    assert_eq!(call.work().agent, intent.target().agent());
    assert_eq!(call.work().actor, intent.target().actor());
    assert_eq!(call.work().invocation, intent.intent().invocation());
    assert_eq!(call.work().mode, MethodMode::Local);
    assert_eq!(call.work().origin, intent.intent().origin());
    assert_eq!(call.work().roles, protected_signer_roles());
    assert_eq!(call.work().message, intent.intent().message());
    assert_eq!(call.work().gas, intent.intent().gas());
    assert!(!call.work().recovery_only);
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
        "protected signature and retained retirement verified for the exact selected fixture intent"
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

#[test]
#[ignore = "requires disposable r17 Counter baseline; waits for real receipt expiry"]
fn real_daemon_counter_unseen_expiry_and_retirement() {
    managed_receipt_invocation_and_exact_retry(Campaign::CounterExpiry);
}

#[test]
#[ignore = "requires completed disposable r17 expiry followed by daemon restart"]
fn real_daemon_counter_value_after_expiry_restart() {
    managed_receipt_invocation_and_exact_retry(Campaign::CounterReadAfterExpiry);
}

#[derive(Clone, Copy)]
enum Campaign {
    Catalog,
    Successor,
    CounterMutation,
    CounterRead,
    CounterExpiry,
    CounterReadAfterExpiry,
}

fn managed_receipt_invocation_and_exact_retry(campaign: Campaign) {
    let successor = matches!(campaign, Campaign::Successor);
    let expiry = matches!(campaign, Campaign::CounterExpiry);
    let counter = matches!(
        campaign,
        Campaign::CounterMutation
            | Campaign::CounterRead
            | Campaign::CounterExpiry
            | Campaign::CounterReadAfterExpiry
    );
    let config_path = PathBuf::from(
        std::env::var_os("VOSX_INVOKE_SMOKE_CONFIG").expect("explicit disposable configuration"),
    );
    let selected_space =
        std::env::var("VOSX_INVOKE_SMOKE_SPACE").unwrap_or_else(|_| "native-denial-smoke".into());
    if matches!(
        campaign,
        Campaign::CounterExpiry | Campaign::CounterReadAfterExpiry
    ) {
        assert_eq!(
            selected_space, "r17-startup",
            "expiry requires the r17 fixture"
        );
    }
    let fixture_prefix = match selected_space.as_str() {
        "native-denial-smoke" => "native-denial-head-reuse.",
        "r17-startup" => "r17-startup-smoke.",
        "issuer-reuse-smoke" => "issuer-reuse-release.",
        "fresh-ack-smoke" => "fresh-ack-release.",
        "current-latency-smoke" => "current-latency.",
        _ => panic!("only the explicitly named disposable campaigns are supported"),
    };
    let (data, space, node_public, address) =
        super::super::local_create::resolve_local_space(&selected_space, None).unwrap();
    assert!(data.to_string_lossy().contains(fixture_prefix));
    let recovery_campaign = matches!(
        selected_space.as_str(),
        "issuer-reuse-smoke" | "fresh-ack-smoke" | "current-latency-smoke"
    );
    let campaign_root = if recovery_campaign {
        assert!(counter, "recovery fixture only supports Counter checks");
        data.ancestors().nth(3).expect("isolated XDG fixture root")
    } else {
        data.parent().unwrap()
    };
    assert_eq!(config_path.parent(), Some(campaign_root));
    let counter_name = if recovery_campaign { "counter" } else { "counter-smoke" };
    let retained_create_campaign = matches!(
        selected_space.as_str(),
        "fresh-ack-smoke" | "current-latency-smoke"
    );
    let counter_path = campaign_root.join(if retained_create_campaign {
        "counter.vos"
    } else if recovery_campaign {
        "counter-dist/counter.vos"
    } else {
        "counter-artifact/Counter.vos"
    });
    // Counter uses the already verified Create CLI result for its coordinates;
    // it does not need an unrelated Catalog installed in the same Local agent.
    let target = if counter {
        let acknowledgement = if retained_create_campaign {
            // After successor handoff the server no longer retains the older
            // Create decision. Verify the client's exact durable request/ACK;
            // do not reissue Create to manufacture test coordinates.
            use super::super::clean_store::{
                CleanLocalCreateAcknowledgementFile, CleanLocalCreateRequestFile,
            };
            let candidates: Vec<_> = std::fs::read_dir(data.join("agent-client/operations"))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.join("request/local-create.request").is_file())
                .collect();
            assert_eq!(candidates.len(), 1, "fixture must have one retained Create");
            let mut request =
                CleanLocalCreateRequestFile::open_or_create(candidates[0].join("request"))
                    .unwrap();
            let request = request.load().unwrap().expect("retained Create request");
            let mut ack = CleanLocalCreateAcknowledgementFile::open_or_create(
                candidates[0].join("acknowledgement"),
                &request,
            )
            .unwrap();
            super::super::local_create::verify_acknowledgement(
                &request,
                &ack.load().unwrap().expect("retained Create acknowledgement"),
            )
            .unwrap()
        } else {
            let created: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
            let acknowledgement = vos::agent::sdk::authority::ManagementApplicationAck::decode(
                &hex::decode(created["acknowledgement"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            assert_eq!(
                created["agent"].as_str().unwrap(),
                hex::encode(acknowledgement.managed.agent.0)
            );
            acknowledgement
        };
        assert_eq!(acknowledgement.managed.space, space);
        let package = vos::agent::package_admission::admit_actor_package(
            &std::fs::read(&counter_path).unwrap(),
        )
        .unwrap();
        CatalogActorTarget {
            space,
            system_agent: acknowledgement.managed.agent,
            system_runtime_deployment: acknowledgement.managed.runtime_deployment,
            actor: ActorId::top_level(acknowledgement.managed.agent, counter_name),
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
        vos::agent::package_admission::admit_actor_package(&std::fs::read(&counter_path).unwrap()).unwrap()
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
        Campaign::CounterExpiry => "agent-client/managed-counter-unseen-expiry",
        Campaign::CounterReadAfterExpiry => "agent-client/managed-counter-read-after-expiry",
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
                Campaign::CounterMutation | Campaign::CounterExpiry => {
                    vos::value::Msg::new("increment").with("by", 7u64)
                }
                Campaign::CounterRead | Campaign::CounterReadAfterExpiry => {
                    vos::value::Msg::new("value")
                }
                _ => vos::value::Msg::new("page").with("request", query.encode().unwrap()),
            };
            message.extend_from_slice(&call.encode());
            let actor = if counter {
                ActorId::top_level(target.system_agent, counter_name)
            } else {
                target.actor
            };
            let intent = AgentTargetedPreparationRequest::new(
                AgentRouteKey::new(space, target.system_agent, actor).unwrap(),
                AgentInvocationIntent::new(
                    InvocationId(nonce),
                    if matches!(
                        campaign,
                        Campaign::CounterMutation | Campaign::CounterExpiry
                    ) {
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
    if expiry {
        // Authorize and retain the application, but do not submit it until the
        // real signed receipt has expired. No forged clock or fixture receipt.
        let (authorization_root, _) = authorize_with_application_validity(
            &data,
            address,
            &operator,
            space,
            node_public,
            Some(&intent),
            false,
            180,
        )
        .unwrap();
        let application_root = authorization_root.parent().unwrap().join("application");
        let mut application =
            super::super::clean_store::CleanInvocationFile::open_or_create(&application_root)
                .unwrap();
        let request = application
            .load_request()
            .unwrap()
            .expect("retained unseen invocation");
        let call = super::super::local_invocation::validate_request(&request).unwrap();
        let InvocationAuthorization::AuthorityReceipt(receipt) = call.authorization() else {
            panic!("expiry campaign requires an issued receipt");
        };
        let expires_at = receipt.selector.expires_at;
        drop(application);
        let now = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        };
        assert!(
            expires_at.saturating_sub(now()) <= 180,
            "unexpected receipt window"
        );
        eprintln!("issued receipt retained without application; waiting until after {expires_at}");
        while now() <= expires_at {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
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
    let verified = super::super::local_invocation::verify_response(&request, &response).unwrap();
    let reply = match verified {
        AgentInvocationResponse::Direct {
            outcome: RuntimeOutcome::Completed(Err(InvocationError::ExpiredBeforeExecution)),
            ..
        } if expiry => None,
        AgentInvocationResponse::Direct {
            outcome: RuntimeOutcome::Completed(Ok(reply)),
            ..
        } if !expiry => {
            assert_eq!(reply.status, InvocationStatus::Done);
            Some(reply)
        }
        other => panic!("unexpected managed outcome: {other:?}"),
    };
    if let Some(package) = counter_package {
        assert_eq!(call.work().program, package.program());
        assert_eq!(call.work().deployment, package.deployment());
        if let Some(reply) = &reply {
            assert_eq!(
                vos::value::Value::try_decode(&reply.reply).unwrap(),
                vos::value::Value::U64(7)
            );
        }
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
        let reply = reply.expect("successful Catalog reply");
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
