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
    let config_path = PathBuf::from(
        std::env::var_os("VOSX_INVOKE_SMOKE_CONFIG").expect("explicit disposable configuration"),
    );
    let (data, space, node_public, address) =
        super::super::local_create::resolve_local_space("native-denial-smoke", None).unwrap();
    assert!(data.to_string_lossy().contains("native-denial-head-reuse."));
    assert_eq!(config_path.parent(), data.parent());
    let config =
        system_catalog::SystemCatalogConfiguration::decode(&std::fs::read(config_path).unwrap())
            .unwrap();
    assert_eq!(config.space, space.0);
    let target = CatalogActorTarget {
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
    };
    let query = CatalogPageRequest {
        catalog: target,
        namespace: "managed-invoke-smoke".into(),
        after: None,
        limit: 1,
    };
    let operator = crate::identity::load_existing().unwrap();
    let identity =
        super::super::clean_identity::CleanOperatorIdentitySigner::new(&operator).unwrap();
    let root = data.join("agent-client/managed-invocation-smoke");
    let mut intent_store = CleanPreparationClientFile::open_or_create(&root).unwrap();
    let intent = match intent_store.load_request().unwrap() {
        Some(bytes) => AgentTargetedPreparationRequest::decode(&bytes).unwrap(),
        None => {
            let mut nonce = [0; 32];
            getrandom::getrandom(&mut nonce).unwrap();
            let mut message = vec![vos::value::TAG_DYNAMIC];
            message.extend_from_slice(
                &vos::value::Msg::new("page")
                    .with("request", query.encode().unwrap())
                    .encode(),
            );
            let intent = AgentTargetedPreparationRequest::new(
                AgentRouteKey::new(space, target.system_agent, target.actor).unwrap(),
                AgentInvocationIntent::new(
                    InvocationId(nonce),
                    MethodMode::Query,
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
        panic!("Catalog query did not succeed");
    };
    assert_eq!(reply.status, InvocationStatus::Done);
    let vos::value::Value::Bytes(bytes) = vos::value::Value::try_decode(&reply.reply).unwrap()
    else {
        panic!("expected Catalog bytes");
    };
    let page = CatalogPage::decode(&bytes).unwrap();
    assert_eq!(page.catalog, target);
    assert_eq!(page.namespace, query.namespace);
    assert!(page.entries.is_empty());
    assert!(page.next.is_none());
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
        "native receipt-bearing Catalog query, positive retirement and exact retry passed; this is not a non-Public mutation proof"
    );
}
