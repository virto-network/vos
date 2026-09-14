//! Durable delivery of exact clean invocation envelopes to a local daemon.
//! This layer neither allocates an invocation ID nor issues authorization.

use vos::agent::sdk::wire::CanonicalWire as _;
use vos::agent::sdk::{
    InvocationAuthorization, InvocationOrigin, InvocationRoleClaims, RuntimeExecutionContext,
};
use vos::agent::supervisor_adapters::{AgentInvocationRequest, AgentInvocationResponse};
use vos::agent::supervisor_adapters::{
    AgentTargetedPreparationRequest, AgentTargetedPreparationResponse, PreparedAgentInvocation,
};

pub(crate) const MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_RESPONSE_BYTES: usize = AgentInvocationResponse::MAX_ENCODED_BYTES;

/// Query physical preparation for an already selected, stable client intent.
/// The caller retains that intent; this function generates no IDs or authority.
pub(crate) fn prepare(
    address: std::net::SocketAddr,
    access_token: &str,
    request: &AgentTargetedPreparationRequest,
) -> anyhow::Result<PreparedAgentInvocation> {
    let reply = prepare_response(address, access_token, request)?;
    decode_preparation(request, &reply)
}

fn decode_preparation(
    request: &AgentTargetedPreparationRequest,
    reply: &[u8],
) -> anyhow::Result<PreparedAgentInvocation> {
    let response = AgentTargetedPreparationResponse::decode(reply)
        .map_err(|error| anyhow::anyhow!("invalid ATP1: {error:?}"))?;
    response
        .for_request(request)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("physical preparation differs from the requested intent"))
}

fn validate_preparation(request: &AgentTargetedPreparationRequest) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        request.intent().origin().transport_node.is_none(),
        "HTTP cannot assert a transport node"
    );
    let bytes = request
        .encode()
        .map_err(|error| anyhow::anyhow!("invalid preparation: {error:?}"))?;
    anyhow::ensure!(
        bytes.len() <= MAX_REQUEST_BYTES,
        "preparation exceeds HTTP request limit"
    );
    Ok(bytes)
}

fn prepare_response(
    address: std::net::SocketAddr,
    access_token: &str,
    request: &AgentTargetedPreparationRequest,
) -> anyhow::Result<Vec<u8>> {
    let bytes = validate_preparation(request)?;
    let reply = super::local_create::post_binary_authenticated(
        address,
        "/__agents/prepare",
        &bytes,
        AgentTargetedPreparationResponse::MAX_ENCODED_BYTES,
        access_token,
    )?;
    decode_preparation(request, &reply)?;
    Ok(reply)
}

/// Retain the exact intent before HTTP and the first bound preparation before
/// returning. Cached work is historical, not proof of live head or approval.
#[cfg(target_os = "linux")]
pub(crate) fn prepare_retained(
    root: &std::path::Path,
    address: std::net::SocketAddr,
    access_token: &str,
    initial: Option<&AgentTargetedPreparationRequest>,
) -> anyhow::Result<PreparedAgentInvocation> {
    anyhow::ensure!(
        address.ip().is_loopback() && address.port() != 0,
        "preparation delivery requires nonzero loopback HTTP"
    );
    let mut store = super::clean_store::CleanPreparationClientFile::open_or_create(root)?;
    let bytes = match store.load_request()? {
        Some(bytes) => bytes,
        None => {
            let request =
                initial.ok_or_else(|| anyhow::anyhow!("no retained preparation intent"))?;
            let bytes = validate_preparation(request)?;
            store.publish_request(&bytes)?;
            bytes
        }
    };
    let request = AgentTargetedPreparationRequest::decode(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid retained preparation: {error:?}"))?;
    validate_preparation(&request)?;
    if let Some(reply) = store.load_response()? {
        return decode_preparation(&request, &reply);
    }
    let reply = prepare_response(address, access_token, &request)?;
    store.publish_response(&reply)?;
    decode_preparation(&request, &reply)
}

/// Combine host-prepared work with an explicitly supplied authorization.
/// Non-Public methods never receive a synthesized public preflight. The
/// runtime remains responsible for receipt signature and policy verification.
pub(crate) fn assemble(
    prepared: &PreparedAgentInvocation,
    receipt: Option<vos::agent::sdk::authority::AuthorityReceipt>,
) -> anyhow::Result<Vec<u8>> {
    let authorization = match receipt {
        Some(receipt) => InvocationAuthorization::AuthorityReceipt(receipt),
        None => InvocationAuthorization::PublicPreflight(prepared.public_preflight().ok_or_else(
            || anyhow::anyhow!("installed method requires protected Authority receipt issuance"),
        )?),
    };
    let request = AgentInvocationRequest::new(
        RuntimeExecutionContext::Direct,
        prepared.work().clone(),
        authorization,
    )
    .map_err(|error| {
        anyhow::anyhow!("authorization differs from prepared invocation: {error:?}")
    })?;
    let bytes = request
        .encode()
        .map_err(|error| anyhow::anyhow!("encode invocation: {error:?}"))?;
    validate_request(&bytes)?;
    Ok(bytes)
}

pub(crate) fn validate_request(bytes: &[u8]) -> anyhow::Result<AgentInvocationRequest> {
    anyhow::ensure!(
        bytes.len() <= MAX_REQUEST_BYTES,
        "invocation request too large"
    );
    let request = AgentInvocationRequest::decode(bytes)
        .map_err(|error| anyhow::anyhow!("invalid ASQ1: {error:?}"))?;
    anyhow::ensure!(
        request.execution() == RuntimeExecutionContext::Direct,
        "attested HTTP delivery is not available"
    );
    let work = request.work();
    anyhow::ensure!(
        work.origin.transport_node.is_none(),
        "HTTP cannot assert a transport node"
    );
    if matches!(
        request.authorization(),
        InvocationAuthorization::PublicPreflight(_)
    ) {
        anyhow::ensure!(
            work.origin == InvocationOrigin::anonymous()
                && work.roles == InvocationRoleClaims::none(),
            "unsigned public invocation must be anonymous"
        );
    }
    Ok(request)
}

pub(crate) fn verify_response(
    request: &[u8],
    bytes: &[u8],
) -> anyhow::Result<AgentInvocationResponse> {
    let request = validate_request(request)?;
    anyhow::ensure!(
        bytes.len() <= MAX_RESPONSE_BYTES,
        "invocation response too large"
    );
    let response = AgentInvocationResponse::decode(bytes)
        .map_err(|error| anyhow::anyhow!("invalid ASR1: {error:?}"))?;
    anyhow::ensure!(
        response.matches_request(&request),
        "invocation response does not match retained request"
    );
    Ok(response)
}

pub(crate) fn submit(
    root: &std::path::Path,
    input: Option<&std::path::Path>,
    address: std::net::SocketAddr,
) -> anyhow::Result<AgentInvocationResponse> {
    use std::io::Read as _;
    anyhow::ensure!(
        address.ip().is_loopback() && address.port() != 0,
        "invocation delivery requires nonzero loopback HTTP"
    );
    let mut store = super::clean_store::CleanInvocationFile::open_or_create(root)?;
    let request = match store.load_request()? {
        Some(request) => request, // No input reads or repreparation on retry.
        None => {
            let input = input.ok_or_else(|| {
                anyhow::anyhow!("no retained invocation; provide --request with canonical ASQ1")
            })?;
            let mut bytes = Vec::new();
            std::fs::File::open(input)?
                .take(MAX_REQUEST_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            store.publish_request(&bytes)?;
            bytes
        }
    };
    let result = (|| {
        if let Some(bytes) = store.load_response()? {
            return verify_response(&request, &bytes);
        }
        let bytes = super::local_create::post_binary(
            address,
            "/__agents/invoke",
            200,
            &request,
            MAX_RESPONSE_BYTES,
        )?;
        let response = verify_response(&request, &bytes)?;
        store.publish_response(&bytes)?;
        Ok(response)
    })();
    result.map_err(|error: anyhow::Error| {
        anyhow::anyhow!("{error}; exact invocation retained, execution outcome may be unknown")
    })
}

pub(crate) fn run(
    root: &std::path::Path,
    input: Option<&std::path::Path>,
    address: std::net::SocketAddr,
) -> anyhow::Result<()> {
    let response = submit(root, input, address)?;
    let bytes = response
        .encode()
        .map_err(|error| anyhow::anyhow!("encode response: {error:?}"))?;
    // Delivery is not an assertion of actor success: preserve the full outcome.
    crate::output::print_json(&serde_json::json!({
        "request": hex::encode(response.request_commitment().0),
        "response": hex::encode(bytes),
        "delivery_retained": true,
    }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::clean_store::CleanInvocationFile;
    use super::*;
    use std::os::unix::fs::DirBuilderExt as _;
    use vos::agent::sdk::*;

    #[test]
    #[ignore = "requires explicitly selected disposable native invocation campaign"]
    fn real_daemon_preparation_invocation_and_exact_retry() {
        use vos::agent::sdk::authority::{AgentAuthorityBinding, AuthorityIssuer};
        use vos::agent::sdk::catalog::{CatalogActorTarget, CatalogPage, CatalogPageRequest};
        use vos::agent::supervisor::AgentRouteKey;
        use vos::agent::supervisor_adapters::AgentInvocationIntent;
        use vos::{Decode as _, Encode as _};
        let config_path = std::path::PathBuf::from(
            std::env::var_os("VOSX_INVOKE_SMOKE_CONFIG")
                .expect("explicit disposable configuration"),
        );
        let (data, space, _, address) =
            super::super::local_create::resolve_local_space("native-denial-smoke", None).unwrap();
        assert!(data.to_string_lossy().contains("native-denial-head-reuse."));
        assert_eq!(config_path.parent(), data.parent());
        let config = system_catalog::SystemCatalogConfiguration::decode(
            &std::fs::read(config_path).unwrap(),
        )
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
            namespace: "invoke-smoke".into(),
            after: None,
            limit: u16::try_from(vos::agent::sdk::catalog::MAX_CATALOG_PAGE_ENTRIES).unwrap(),
        };
        let root = data.join("agent-client/invocation-smoke");
        let mut store = CleanInvocationFile::open_or_create(&root).unwrap();
        if store.load_request().unwrap().is_none() {
            let operator = crate::identity::load_existing()
                .unwrap()
                .try_into_ed25519()
                .unwrap();
            let secret = operator.secret();
            let token =
                vos::ingress::encode_access_token(secret.as_ref().try_into().unwrap()).unwrap();
            let mut nonce = [0; 32];
            getrandom::getrandom(&mut nonce).unwrap();
            let mut message = vec![vos::value::TAG_DYNAMIC];
            message.extend_from_slice(
                &vos::value::Msg::new("page")
                    .with("request", query.encode().unwrap())
                    .encode(),
            );
            let request = AgentTargetedPreparationRequest::new(
                AgentRouteKey::new(space, AgentId(config.system_agent), ActorId(config.actor))
                    .unwrap(),
                AgentInvocationIntent::new(
                    InvocationId(nonce),
                    MethodMode::Query,
                    InvocationOrigin::anonymous(),
                    InvocationRoleClaims::none(),
                    message,
                    vos::agent::execution::MAX_EXECUTION_GAS,
                    false,
                )
                .unwrap(),
            )
            .unwrap();
            let prepared = prepare(address, &token, &request).unwrap();
            assert_eq!(prepared.selected_method().name, "page");
            let bytes = assemble(&prepared, None).unwrap();
            store.publish_request(&bytes).unwrap();
        }
        let request = store.load_request().unwrap().unwrap();
        drop(store);
        let response = submit(&root, None, address).unwrap();
        // Force a real exact HTTP retry even when a prior campaign saved ASR1.
        let repeated = super::super::local_create::post_binary(
            address,
            "/__agents/invoke",
            200,
            &request,
            MAX_RESPONSE_BYTES,
        )
        .unwrap();
        assert_eq!(verify_response(&request, &repeated).unwrap(), response);
        let AgentInvocationResponse::Direct {
            outcome: RuntimeOutcome::Completed(Ok(reply)),
            ..
        } = response
        else {
            panic!("actor did not complete successfully");
        };
        assert_eq!(reply.status, InvocationStatus::Done);
        let vos::value::Value::Bytes(bytes) = vos::value::Value::try_decode(&reply.reply).unwrap()
        else {
            panic!("expected Catalog bytes");
        };
        let page = CatalogPage::decode(&bytes).unwrap();
        assert_eq!(page.catalog, query.catalog);
        assert_eq!(page.namespace, query.namespace);
        assert!(page.next.is_none());
        assert!(page.entries.is_empty());
        eprintln!("native Catalog query, retained delivery and exact HTTP retry passed");
    }

    #[test]
    #[ignore = "requires explicitly selected disposable native retirement campaign"]
    fn real_daemon_invocation_retirement_and_exact_retry() {
        use vos::agent::supervisor_adapters::{
            AgentAcknowledgementRequest, AgentAcknowledgementResponse,
        };
        let config_path = std::path::PathBuf::from(
            std::env::var_os("VOSX_INVOKE_SMOKE_CONFIG")
                .expect("explicit disposable configuration"),
        );
        let (data, _, _, address) =
            super::super::local_create::resolve_local_space("native-denial-smoke", None).unwrap();
        assert!(data.to_string_lossy().contains("native-denial-head-reuse."));
        assert_eq!(config_path.parent(), data.parent());
        let root = data.join("agent-client/invocation-smoke");
        let mut store = CleanInvocationFile::open_or_create(&root).unwrap();
        let request = store.load_request().unwrap().expect("retained live ASQ1");
        let response = store.load_response().unwrap().expect("retained live ASR1");
        assert!(matches!(
            verify_response(&request, &response).unwrap(),
            AgentInvocationResponse::Direct {
                outcome: RuntimeOutcome::Completed(Ok(_)),
                ..
            }
        ));
        drop(store);
        super::super::invocation_progress::continue_retained(&root, address).unwrap();

        // Always contact the physical daemon, including after restart when
        // continue_retained can return its already-durable positive reply.
        let call = validate_request(&request).unwrap();
        let acknowledgement = AgentAcknowledgementRequest::new(
            RuntimeExecutionContext::Direct,
            None,
            call.work().clone(),
            call.authorization().clone(),
        )
        .unwrap();
        let encoded = acknowledgement.encode().unwrap();
        let mut previous = None;
        for _ in 0..2 {
            let reply = super::super::local_create::post_binary(
                address,
                "/__agents/acknowledge",
                200,
                &encoded,
                MAX_RESPONSE_BYTES,
            )
            .unwrap();
            let decoded = AgentAcknowledgementResponse::decode(&reply).unwrap();
            assert!(decoded.matches_request(&acknowledgement));
            assert!(matches!(
                decoded.outcome(),
                RuntimeOutcome::Acknowledged(Ok(_))
            ));
            if let Some(previous) = previous.replace(reply.clone()) {
                assert_eq!(reply, previous);
            }
        }
        let mut store = CleanInvocationFile::open_or_create(&root).unwrap();
        assert_eq!(store.load_request().unwrap().as_ref(), Some(&request));
        assert_eq!(store.load_response().unwrap().as_ref(), Some(&response));
        let progress = store.load_progress().unwrap().expect("durable retirement");
        drop(store);
        super::super::invocation_progress::continue_retained(&root, address).unwrap();
        let mut store = CleanInvocationFile::open_or_create(&root).unwrap();
        assert_eq!(store.load_progress().unwrap(), Some(progress));
        eprintln!("native invocation retirement and two exact HTTP acknowledgement retries passed");
    }

    fn fixture(seed: u8) -> (Vec<u8>, Vec<u8>) {
        let work = InvocationWork {
            space: SpaceId([1; 32]),
            agent: AgentId([2; 32]),
            runtime_deployment: DeploymentId([3; 32]),
            invocation: InvocationId([seed; 32]),
            actor: ActorId([4; 32]),
            incarnation: Hash([5; 32]),
            deployment: DeploymentId([6; 32]),
            program: ProgramId([7; 32]),
            mode: MethodMode::Query,
            origin: InvocationOrigin::anonymous(),
            roles: InvocationRoleClaims::none(),
            message: vec![seed],
            installation_data: None,
            availability: Vec::new(),
            gas: 100,
            recovery_only: false,
        };
        let authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&work, 17));
        let request =
            AgentInvocationRequest::new(RuntimeExecutionContext::Direct, work, authorization)
                .unwrap();
        let response = AgentInvocationResponse::Direct {
            request: request.commitment(),
            outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
        };
        (request.encode().unwrap(), response.encode().unwrap())
    }

    #[test]
    fn retained_preparation_recovers_and_rejects_substitution_or_orphans() {
        use super::super::clean_store::CleanPreparationClientFile;
        let (request, reply) = preparation_fixture(31);
        let (other, other_reply) = preparation_fixture(32);
        let parent = directory();
        let root = parent.join("preparation");
        let mut store = CleanPreparationClientFile::open_or_create(&root).unwrap();
        assert!(store.publish_response(&reply).is_err());
        store.publish_request(&request.encode().unwrap()).unwrap();
        assert!(CleanPreparationClientFile::open_or_create(&root).is_err());
        assert!(store.publish_request(&other.encode().unwrap()).is_err());
        assert!(store.publish_response(&other_reply).is_err());
        let mut corrupt = reply.clone();
        corrupt.push(0);
        assert!(store.publish_response(&corrupt).is_err());
        store.publish_response(&reply).unwrap();
        drop(store);
        for name in ["preparation.request", "preparation.response"] {
            std::fs::rename(root.join(name), root.join(format!("{name}.next"))).unwrap();
        }
        // No server or token is needed to return already retained work. A
        // different fresh intent is ignored, not silently substituted.
        let prepared =
            prepare_retained(&root, "127.0.0.1:1".parse().unwrap(), "", Some(&other)).unwrap();
        assert_eq!(prepared.work().invocation, request.intent().invocation());
        let mut store = CleanPreparationClientFile::open_or_create(&root).unwrap();
        assert_eq!(store.load_response().unwrap(), Some(reply.clone()));
        assert_eq!(
            store.load_request().unwrap(),
            Some(request.encode().unwrap())
        );
        drop(store);
        let saved = std::fs::read(root.join("preparation.response")).unwrap();
        // Corrupt staged bytes must remain untouched, not be promoted/removed.
        std::fs::copy(
            root.join("preparation.response"),
            root.join("preparation.response.next"),
        )
        .unwrap();
        let staged = root.join("preparation.response.next");
        let mut bad = std::fs::read(&staged).unwrap();
        *bad.last_mut().unwrap() ^= 1;
        std::fs::write(&staged, &bad).unwrap();
        let mut store = CleanPreparationClientFile::open_or_create(&root).unwrap();
        assert!(store.load_response().is_err());
        assert_eq!(std::fs::read(&staged).unwrap(), bad);
        assert_eq!(
            std::fs::read(root.join("preparation.response")).unwrap(),
            saved
        );
        drop(store);
        std::fs::remove_file(staged).unwrap();
        // An orphan response cannot be repaired from new user input.
        std::fs::remove_file(root.join("preparation.request")).unwrap();
        let mut store = CleanPreparationClientFile::open_or_create(&root).unwrap();
        assert!(store.publish_request(&request.encode().unwrap()).is_err());
        assert!(!root.join("preparation.request").exists());
        assert_eq!(
            std::fs::read(root.join("preparation.response")).unwrap(),
            saved
        );
        drop(store);
        std::fs::remove_dir_all(parent).unwrap();
    }

    // Canonical shaped host response using admitted Catalog artifacts. This
    // tests wire binding/storage only, not native preparation or execution.
    fn preparation_fixture(seed: u8) -> (AgentTargetedPreparationRequest, Vec<u8>) {
        use vos::Encode as _;
        use vos::agent::supervisor::AgentRouteKey;
        use vos::agent::supervisor_adapters::AgentInvocationIntent;
        fn bytes(out: &mut Vec<u8>, value: &[u8]) {
            out.extend_from_slice(&(value.len() as u32).to_le_bytes());
            out.extend_from_slice(value);
        }
        fn reference(out: &mut Vec<u8>, value: &BlobRef) {
            out.extend_from_slice(value.hash.as_bytes());
            out.extend_from_slice(&value.len.to_le_bytes());
        }
        let (operator, _, descriptor, _) = super::super::local_create::tests::fixture();
        let actor = crate::bundled::root_signed_actor_package(
            crate::bundled::system_catalog_package_template(),
            "system-catalog",
            &operator,
        )
        .unwrap();
        let mut message = vec![vos::value::TAG_DYNAMIC];
        message.extend_from_slice(&vos::value::Msg::new("page").encode());
        let request = AgentTargetedPreparationRequest::new(
            AgentRouteKey::new(SpaceId([1; 32]), AgentId([2; 32]), ActorId([4; 32])).unwrap(),
            AgentInvocationIntent::new(
                InvocationId([seed; 32]),
                MethodMode::Query,
                InvocationOrigin::anonymous(),
                InvocationRoleClaims::none(),
                message.clone(),
                100,
                false,
            )
            .unwrap(),
        )
        .unwrap();
        let mut inner = b"APR1".to_vec();
        inner.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        inner.extend_from_slice(&[9; 32]); // Nonzero internal preparation commitment.
        inner.push(AgentProfile::Local as u8);
        inner.extend_from_slice(descriptor.identity.runtime_program.as_bytes());
        reference(&mut inner, &descriptor.runtime_package);
        inner.extend_from_slice(&17u64.to_le_bytes());
        for field in [
            [1; 32],
            [2; 32],
            [3; 32],
            [seed; 32],
            [4; 32],
            [5; 32],
            [6; 32],
            ProgramId::of_pvm(actor.program_bytes()).0,
        ] {
            inner.extend_from_slice(&field);
        }
        inner.push(MethodMode::Query as u8);
        inner.extend_from_slice(&[0; 7]); // Anonymous origin and no role claims.
        bytes(&mut inner, &message);
        let schema = vos::agent::sdk::schema::decode(actor.state_lane_schema_bytes()).unwrap();
        let mut blobs = vec![
            actor.program_bytes(),
            actor.state_lane_schema_bytes(),
            actor.method_policy_bytes(),
        ];
        // Presence/preimage binding only; this fixture does not execute the
        // Catalog or claim this shaped installation data is usable configuration.
        if schema.requires_installation_data() {
            inner.push(1);
            reference(&mut inner, &BlobRef::of_bytes(b"shaped installation data"));
            blobs.push(b"shaped installation data");
        } else {
            inner.push(0);
        }
        inner.extend_from_slice(&(blobs.len() as u32).to_le_bytes());
        blobs.sort_by_key(|blob| BlobRef::of_bytes(blob));
        for blob in blobs {
            reference(&mut inner, &BlobRef::of_bytes(blob));
            bytes(&mut inner, blob);
        }
        inner.extend_from_slice(&100u64.to_le_bytes());
        inner.push(0);
        bytes(&mut inner, actor.method_policy_bytes());
        bytes(&mut inner, b"page");
        let mut response = b"ATP1".to_vec();
        response.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        response.extend_from_slice(request.commitment().as_bytes());
        bytes(&mut response, &inner);
        decode_preparation(&request, &response).unwrap();
        (request, response)
    }

    #[test]
    fn preparation_http_authenticates_exact_body_and_rejects_invalid_delivery() {
        use std::io::{Read as _, Write as _};
        let (request, reply) = preparation_fixture(23);
        let (_, wrong) = preparation_fixture(24);
        let token = vos::ingress::encode_access_token(&[0x51; 32]).unwrap();
        let parent = directory();
        let root = parent.join("preparation");
        // Prove storage admission before starting a mock listener.
        drop(super::super::clean_store::CleanPreparationClientFile::open_or_create(&root).unwrap());
        assert!(prepare("192.0.2.1:8080".parse().unwrap(), &token, &request).is_err());
        assert!(prepare("127.0.0.1:1".parse().unwrap(), "invalid", &request).is_err());
        for (index, (status, content_type, response, succeeds)) in [
            (401, "application/octet-stream", reply.clone(), false),
            (504, "application/octet-stream", reply.clone(), false),
            (302, "application/octet-stream", reply.clone(), false),
            (200, "application/json", reply.clone(), false),
            (200, "application/octet-stream", b"ATP1".to_vec(), false),
            (200, "application/octet-stream", wrong, false),
            (200, "application/octet-stream", reply.clone(), true),
        ]
        .into_iter()
        .enumerate()
        {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let expected = request.encode().unwrap();
            let secret_header = format!("authorization: Bearer {token}");
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut header = Vec::new();
                loop {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    header.push(byte[0]);
                    if header.ends_with(b"\r\n\r\n") {
                        break;
                    }
                    assert!(header.len() < 8192);
                }
                let header = String::from_utf8(header).unwrap();
                assert!(header.starts_with("POST /__agents/prepare HTTP/1.1\r\n"));
                // Boolean assertion deliberately avoids printing secret headers.
                assert!(
                    header
                        .lines()
                        .any(|line| line.eq_ignore_ascii_case(&secret_header))
                );
                let mut body = vec![0; expected.len()];
                stream.read_exact(&mut body).unwrap();
                assert_eq!(body, expected);
                write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
                // Rejected headers may cause the client to close early.
                let _ = stream.write_all(&response);
            });
            let result = prepare_retained(&root, address, &token, (index == 0).then_some(&request));
            assert_eq!(result.is_ok(), succeeds, "{result:?}");
            server.join().unwrap();
            let mut retained =
                super::super::clean_store::CleanPreparationClientFile::open_or_create(&root)
                    .unwrap();
            assert_eq!(
                retained.load_request().unwrap(),
                Some(request.encode().unwrap())
            );
            assert_eq!(
                retained.load_response().unwrap(),
                succeeds.then(|| reply.clone())
            );
        }
        assert!(prepare_retained(&root, "127.0.0.1:1".parse().unwrap(), "", None).is_ok());
        std::fs::remove_dir_all(parent).unwrap();
    }

    fn directory() -> std::path::PathBuf {
        let mut nonce = [0; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let root =
            std::env::temp_dir().join(format!("vos-invocation-delivery-{}", hex::encode(nonce)));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        root
    }

    #[test]
    fn invocation_store_is_immutable_exclusive_bound_and_reopenable() {
        let root = directory();
        let path = root.join("request");
        let (request, response) = fixture(11);
        let (other, other_response) = fixture(12);
        let mut store = CleanInvocationFile::open_or_create(&path).unwrap();
        assert!(CleanInvocationFile::open_or_create(&path).is_err());
        assert!(store.publish_response(&response).is_err());
        store.publish_request(&request).unwrap();
        store.publish_request(&request).unwrap();
        assert!(store.publish_request(&other).is_err());
        assert!(store.publish_response(&other_response).is_err());
        let mut trailing = response.clone();
        trailing.push(0);
        assert!(store.publish_response(&trailing).is_err());
        store.publish_response(&response).unwrap();
        drop(store);
        let recovered = submit(
            &path,
            Some(&root.join("missing-input")),
            "127.0.0.1:1".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(recovered.encode().unwrap(), response);
        // A saved response never permits reconstruction of a deleted request.
        std::fs::remove_file(path.join("invocation.request")).unwrap();
        let mut orphan = CleanInvocationFile::open_or_create(&path).unwrap();
        assert!(orphan.publish_request(&request).is_err());
        assert!(!path.join("invocation.request").exists());
        drop(orphan);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invocation_http_retries_exact_bytes_and_retains_only_bound_binary_reply() {
        use std::io::{Read as _, Write as _};
        let root = directory();
        let path = root.join("request");
        let (request, response) = fixture(13);
        let (_, wrong) = fixture(14);
        let input = root.join("initial.asq1");
        std::fs::write(&input, &request).unwrap();
        for (status, content_type, body, succeeds) in [
            (503, "application/octet-stream", Vec::new(), false),
            (302, "application/octet-stream", response.clone(), false),
            (200, "application/json", response.clone(), false),
            (200, "application/octet-stream", wrong, false),
            (
                200,
                "application/octet-stream",
                response[..response.len() - 1].to_vec(),
                false,
            ),
            (200, "application/octet-stream", response.clone(), true),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let expected = request.clone();
            let leased = path.clone();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                let header_end = loop {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    bytes.push(byte[0]);
                    if bytes.ends_with(b"\r\n\r\n") {
                        break bytes.len();
                    }
                    assert!(bytes.len() < 8192);
                };
                assert!(bytes.starts_with(b"POST /__agents/invoke HTTP/1.1\r\n"));
                bytes.resize(header_end + expected.len(), 0);
                stream.read_exact(&mut bytes[header_end..]).unwrap();
                assert_eq!(&bytes[header_end..], expected);
                assert!(CleanInvocationFile::open_or_create(&leased).is_err());
                write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                stream.write_all(&body).unwrap();
            });
            assert_eq!(submit(&path, Some(&input), address).is_ok(), succeeds);
            server.join().unwrap();
            if input.exists() {
                std::fs::remove_file(&input).unwrap();
            }
            let mut store = CleanInvocationFile::open_or_create(&path).unwrap();
            assert_eq!(store.load_request().unwrap(), Some(request.clone()));
            assert_eq!(store.load_response().unwrap().is_some(), succeeds);
        }
        assert_eq!(
            submit(&path, None, "127.0.0.1:1".parse().unwrap())
                .unwrap()
                .encode()
                .unwrap(),
            response
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invocation_command_accepts_initial_input_and_input_free_retry() {
        use clap::Parser as _;
        for args in [
            vec![
                "vosx",
                "space",
                "submit-agent-invocation",
                "delivery",
                "--http",
                "127.0.0.1:8080",
                "--request",
                "call.asq1",
            ],
            vec![
                "vosx",
                "space",
                "submit-agent-invocation",
                "delivery",
                "--http",
                "127.0.0.1:8080",
            ],
        ] {
            let parsed = crate::Cli::try_parse_from(args).unwrap();
            assert!(matches!(
                parsed.command,
                Some(crate::Command::Space {
                    command: super::super::SpaceCommand::SubmitAgentInvocation { .. }
                })
            ));
        }
        assert!(
            crate::Cli::try_parse_from(["vosx", "space", "submit-agent-invocation", "delivery"])
                .is_err()
        );
    }
}
