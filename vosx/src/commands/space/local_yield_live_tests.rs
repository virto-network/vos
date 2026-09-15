//! Explicit disposable compiled-actor yield campaign. Never use valuable data.
use super::*;
use vos::agent::sdk::*;
use vos::agent::supervisor::AgentRouteKey;
use vos::agent::supervisor_adapters::{
    AgentInvocationIntent, AgentInvocationRequest, AgentInvocationResponse,
};
use vos::{Decode as _, Encode as _};

fn corrected_campaign() -> bool {
    match std::env::var("VOSX_YIELD_SMOKE_PHASE").as_deref() {
        Err(std::env::VarError::NotPresent) => false,
        Ok("fixed") => true,
        other => panic!("unsupported yield campaign phase: {other:?}"),
    }
}

fn campaign_file(root: &Path, name: &str) -> PathBuf {
    assert!(name.starts_with("yield-"));
    root.join(if corrected_campaign() {
        name.replacen("yield-", "yield-fixed-", 1)
    } else {
        name.to_owned()
    })
}

fn campaign_nonce(query: bool) -> u8 {
    match (corrected_campaign(), query) {
        (false, false) => 0x78,
        (false, true) => 0x79,
        (true, false) => 0x80,
        (true, true) => 0x81,
    }
}

fn root() -> PathBuf {
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
    root
}

fn write_exact(path: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            assert_eq!(std::fs::read(path).unwrap(), bytes);
        }
        Err(error) => panic!("fixture publication failed: {error}"),
    }
}

#[test]
#[ignore = "writes exact inputs only for the disposable compiled-yield campaign"]
fn prepare_disposable_yield_inputs() {
    let root = root();
    let (data, space, _, _) =
        super::super::local_create::resolve_local_space("admin-startup", None).unwrap();
    assert!(data.canonicalize().unwrap().starts_with(&root));
    let created: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("protected-create-resume-1.json")).unwrap(),
    )
    .unwrap();
    let ack = vos::agent::sdk::authority::ManagementApplicationAck::decode(
        &hex::decode(created["acknowledgement"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(ack.managed.space, space);
    let actor_name = if corrected_campaign() {
        "yield-probe-fixed"
    } else {
        "yield-probe"
    };
    let actor = ActorId::top_level(ack.managed.agent, actor_name);
    let package = vos::agent::package_admission::admit_actor_package(
        &std::fs::read(root.join(actor_name).join("AgentYieldProbe.vos")).unwrap(),
    )
    .unwrap();
    let policies = vos::agent::sdk::method_policy::ActorMethodPolicyArtifact::decode(
        package.method_policy_bytes(),
    )
    .unwrap();
    let method = policies.method("run").unwrap();
    assert_eq!(method.mode, MethodMode::Local);
    assert_eq!(
        method.authorization_policy,
        vos::agent::sdk::method_policy::AuthorizationPolicySelector::ActorRole(RoleId([0x51; 32]))
    );
    let operator = crate::identity::load_existing().unwrap();
    let identity =
        super::super::clean_identity::CleanOperatorIdentitySigner::new(&operator).unwrap();
    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(&vos::value::Msg::new("run").encode());
    let intent = AgentTargetedPreparationRequest::new(
        AgentRouteKey::new(space, ack.managed.agent, actor).unwrap(),
        AgentInvocationIntent::new(
            InvocationId([campaign_nonce(false); 32]),
            method.mode,
            InvocationOrigin {
                principal: Some(identity.principal()),
                credential: Some(identity.credential()),
                ..InvocationOrigin::anonymous()
            },
            InvocationRoleClaims {
                actor: Some(RoleId([0x51; 32])),
                space: None,
            },
            message,
            vos::agent::execution::MAX_EXECUTION_GAS,
            false,
        )
        .unwrap(),
    )
    .unwrap();
    write_exact(
        &campaign_file(&root, "yield-run.intent"),
        &intent.encode().unwrap(),
    );
    let query_policy = policies.method("value").unwrap();
    assert_eq!(query_policy.mode, MethodMode::LocalQuery);
    assert_eq!(
        query_policy.authorization_policy,
        vos::agent::sdk::method_policy::AuthorizationPolicySelector::Public
    );
    let mut query_message = vec![vos::value::TAG_DYNAMIC];
    query_message.extend_from_slice(&vos::value::Msg::new("value").encode());
    let query = AgentTargetedPreparationRequest::new(
        AgentRouteKey::new(space, ack.managed.agent, actor).unwrap(),
        AgentInvocationIntent::new(
            InvocationId([campaign_nonce(true); 32]),
            query_policy.mode,
            InvocationOrigin {
                principal: Some(identity.principal()),
                credential: Some(identity.credential()),
                ..InvocationOrigin::anonymous()
            },
            InvocationRoleClaims::none(),
            query_message,
            vos::agent::execution::MAX_EXECUTION_GAS,
            false,
        )
        .unwrap(),
    )
    .unwrap();
    write_exact(
        &campaign_file(&root, "yield-value.intent"),
        &query.encode().unwrap(),
    );
    write_exact(&campaign_file(&root, "yield-identity.json"), &serde_json::to_vec(&serde_json::json!({
        "agent": hex::encode(ack.managed.agent.0), "actor": hex::encode(actor.0),
        "deployment": hex::encode(package.deployment().0), "program": hex::encode(package.program().0),
    })).unwrap());
}

#[test]
#[ignore = "authorizes and delivers only the first slice in the disposable yield campaign"]
fn disposable_yield_first_slice() {
    let root = root();
    let (data, space, node_public, address) =
        super::super::local_create::resolve_local_space("admin-startup", None).unwrap();
    assert!(data.canonicalize().unwrap().starts_with(&root));
    let intent = AgentTargetedPreparationRequest::decode(
        &std::fs::read(campaign_file(&root, "yield-run.intent")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        intent.intent().invocation(),
        InvocationId([campaign_nonce(false); 32])
    );
    let operator = crate::identity::load_existing().unwrap();
    let (authorization_root, response) =
        authorize(&data, address, &operator, space, node_public, Some(&intent)).unwrap();
    assert_eq!(response[4], 0, "fixture must be authorized, not denied");
    let application = authorization_root.parent().unwrap().join("application");
    assert!(application.canonicalize().unwrap().starts_with(&data));
    let outcome = super::super::local_invocation::submit(&application, None, address).unwrap();
    let AgentInvocationResponse::Direct {
        outcome: RuntimeOutcome::Yielded(yielded),
        ..
    } = outcome
    else {
        panic!("compiled actor did not yield: {outcome:?}");
    };
    assert_eq!(yielded.reason, YieldReason::Cooperative);
    assert_eq!(yielded.ready_sequence, 1);
    let mut store =
        super::super::clean_store::CleanInvocationFile::open_or_create(&application).unwrap();
    let call = AgentInvocationRequest::decode(&store.load_request().unwrap().unwrap()).unwrap();
    assert_eq!(call.work().invocation, intent.intent().invocation());
    assert_eq!(call.work().mode, MethodMode::Local);
    assert!(matches!(
        call.authorization(),
        InvocationAuthorization::AuthorityReceipt(_)
    ));
    assert!(
        store.load_progress().unwrap().is_none(),
        "do not advance past the first yield before restart"
    );
    write_exact(
        &campaign_file(&root, "yield-first-slice.json"),
        &serde_json::to_vec(&serde_json::json!({
            "request_dir": authorization_root, "application": application,
            "ready_sequence": yielded.ready_sequence,
        }))
        .unwrap(),
    );
}

#[test]
#[ignore = "requires retained first yield and an actual disposable daemon restart"]
fn disposable_yield_resume_and_retire() {
    use vos::agent::supervisor_adapters::AgentResumeResponse;
    let root = root();
    let (data, space, node_public, address) =
        super::super::local_create::resolve_local_space("admin-startup", None).unwrap();
    assert!(data.canonicalize().unwrap().starts_with(&root));
    let saved: serde_json::Value = serde_json::from_slice(
        &std::fs::read(campaign_file(&root, "yield-first-slice.json")).unwrap(),
    )
    .unwrap();
    let application = PathBuf::from(saved["application"].as_str().unwrap())
        .canonicalize()
        .unwrap();
    assert!(application.starts_with(data.join("agent-client/operations")));
    let expected_authorization = PathBuf::from(saved["request_dir"].as_str().unwrap())
        .canonicalize()
        .unwrap();
    assert_eq!(application.parent(), expected_authorization.parent());
    let operator = crate::identity::load_existing().unwrap();
    let (authorization, _) =
        authorize_with_application(&data, address, &operator, space, node_public, None, true)
            .unwrap();
    assert_eq!(
        authorization.canonicalize().unwrap(),
        expected_authorization
    );
    let mut store =
        super::super::clean_store::CleanInvocationFile::open_or_create(&application).unwrap();
    let request = store.load_request().unwrap().unwrap();
    let response = store.load_response().unwrap().unwrap();
    let call = AgentInvocationRequest::decode(&request).unwrap();
    assert_eq!(
        call.work().invocation,
        InvocationId([campaign_nonce(false); 32])
    );
    assert!(matches!(
        call.authorization(),
        InvocationAuthorization::AuthorityReceipt(_)
    ));
    let progress = store.load_progress().unwrap().unwrap();
    assert!(
        super::super::invocation_progress::Progress::decode(&progress, &request, &response)
            .unwrap()
            .is_retired(&request, &response)
            .unwrap()
    );
    let encoded: serde_json::Value = serde_json::from_slice(&progress).unwrap();
    let exchanges = encoded["exchanges"].as_array().unwrap();
    assert_eq!(exchanges.len(), 3, "two resumes then exact retirement");
    let resumed = AgentResumeResponse::decode(
        &hex::decode(exchanges[0]["response"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let RuntimeOutcome::Yielded(second) = resumed.outcome() else {
        panic!("first resume did not yield again: {resumed:?}");
    };
    assert_eq!(second.ready_sequence, 2);
    assert_eq!(second.reason, YieldReason::Cooperative);
    let completed = AgentResumeResponse::decode(
        &hex::decode(exchanges[1]["response"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let RuntimeOutcome::Completed(Ok(reply)) = completed.outcome() else {
        panic!("second resume did not complete: {completed:?}");
    };
    assert_eq!(reply.status, InvocationStatus::Done);
    assert_eq!(
        vos::value::Value::try_decode(&reply.reply).unwrap(),
        vos::value::Value::U64(111)
    );
    drop(store);
    // Retained completion must be idempotent, including credential release.
    let (retried, _) =
        authorize_with_application(&data, address, &operator, space, node_public, None, true)
            .unwrap();
    assert_eq!(retried.canonicalize().unwrap(), expected_authorization);
    eprintln!(
        "two compiled actor yields, final value 111, exact retirement and cached retry verified"
    );
}

#[test]
#[ignore = "retires only the exact retained Panicked result from the original disposable yield fixture"]
fn disposable_yield_retire_failed_first_slice() {
    assert!(
        !corrected_campaign(),
        "this cleanup applies only to the original failure"
    );
    let root = root();
    let (data, space, node_public, address) =
        super::super::local_create::resolve_local_space("admin-startup", None).unwrap();
    assert!(data.canonicalize().unwrap().starts_with(&root));
    let intent = AgentTargetedPreparationRequest::decode(
        &std::fs::read(root.join("yield-run.intent")).unwrap(),
    )
    .unwrap();
    assert_eq!(intent.intent().invocation(), InvocationId([0x78; 32]));
    let operator = crate::identity::load_existing().unwrap();
    let (authorization, _) =
        authorize(&data, address, &operator, space, node_public, Some(&intent)).unwrap();
    let application = authorization.parent().unwrap().join("application");
    let mut store =
        super::super::clean_store::CleanInvocationFile::open_or_create(&application).unwrap();
    let request = store.load_request().unwrap().unwrap();
    let response = store.load_response().unwrap().unwrap();
    let call = AgentInvocationRequest::decode(&request).unwrap();
    assert_eq!(call.work().invocation, InvocationId([0x78; 32]));
    let original = vos::agent::package_admission::admit_actor_package(
        &std::fs::read(root.join("yield-probe/AgentYieldProbe.vos")).unwrap(),
    )
    .unwrap();
    assert_eq!(call.work().program, original.program());
    assert_eq!(call.work().deployment, original.deployment());
    let AgentInvocationResponse::Direct {
        outcome: RuntimeOutcome::Completed(Ok(reply)),
        ..
    } = super::super::local_invocation::verify_response(&request, &response).unwrap()
    else {
        panic!("only the saved terminal actor failure may be retired here");
    };
    assert_eq!(reply.status, InvocationStatus::Panicked);
    drop(store);
    let (completed, _) = authorize_with_application(
        &data,
        address,
        &operator,
        space,
        node_public,
        Some(&intent),
        true,
    )
    .unwrap_or_else(|error| {
        let mut store =
            super::super::clean_store::CleanInvocationFile::open_or_create(&application).unwrap();
        if let Some(progress) = store.load_progress().unwrap() {
            let value: serde_json::Value = serde_json::from_slice(&progress).unwrap();
            if let Some(reply) = value["exchanges"]
                .as_array()
                .unwrap()
                .last()
                .and_then(|exchange| exchange["response"].as_str())
            {
                let acknowledgement =
                    vos::agent::supervisor_adapters::AgentAcknowledgementResponse::decode(
                        &hex::decode(reply).unwrap(),
                    )
                    .unwrap();
                eprintln!(
                    "retained failure-retirement outcome: {:?}",
                    acknowledgement.outcome()
                );
            }
        }
        panic!("exact failure retirement did not complete: {error}");
    });
    assert_eq!(completed, authorization);
    let mut store =
        super::super::clean_store::CleanInvocationFile::open_or_create(&application).unwrap();
    assert_eq!(store.load_request().unwrap().unwrap(), request);
    assert_eq!(store.load_response().unwrap().unwrap(), response);
    assert!(
        super::super::invocation_progress::Progress::decode(
            &store.load_progress().unwrap().unwrap(),
            &request,
            &response
        )
        .unwrap()
        .is_retired(&request, &response)
        .unwrap()
    );
    write_exact(
        &root.join("yield-failed-retired.json"),
        &serde_json::to_vec(&serde_json::json!({
            "request_dir": authorization, "application": application,
            "status": "panicked", "retired": true,
        }))
        .unwrap(),
    );
    eprintln!(
        "original Panicked result preserved and positively retired through the normal managed client"
    );
}

#[test]
#[ignore = "requires completed yield campaign followed by a second actual daemon restart"]
fn disposable_yield_value_after_restart() {
    let root = root();
    let (data, space, node_public, address) =
        super::super::local_create::resolve_local_space("admin-startup", None).unwrap();
    assert!(data.canonicalize().unwrap().starts_with(&root));
    let intent = AgentTargetedPreparationRequest::decode(
        &std::fs::read(campaign_file(&root, "yield-value.intent")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        intent.intent().invocation(),
        InvocationId([campaign_nonce(true); 32])
    );
    let operator = crate::identity::load_existing().unwrap();
    let (authorization, _) = authorize_with_application(
        &data,
        address,
        &operator,
        space,
        node_public,
        Some(&intent),
        true,
    )
    .unwrap();
    let application = authorization.parent().unwrap().join("application");
    let mut store =
        super::super::clean_store::CleanInvocationFile::open_or_create(&application).unwrap();
    let request = store.load_request().unwrap().unwrap();
    let response = store.load_response().unwrap().unwrap();
    let AgentInvocationResponse::Direct {
        outcome: RuntimeOutcome::Completed(Ok(reply)),
        ..
    } = super::super::local_invocation::verify_response(&request, &response).unwrap()
    else {
        panic!("post-restart query did not complete");
    };
    assert_eq!(
        vos::value::Value::try_decode(&reply.reply).unwrap(),
        vos::value::Value::U64(111)
    );
    assert!(
        super::super::invocation_progress::Progress::decode(
            &store.load_progress().unwrap().unwrap(),
            &request,
            &response
        )
        .unwrap()
        .is_retired(&request, &response)
        .unwrap()
    );
    eprintln!("post-restart compiled-yield state is 111 and query is retired");
}
