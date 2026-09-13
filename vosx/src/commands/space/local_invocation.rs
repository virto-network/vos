//! Durable delivery of exact clean invocation envelopes to a local daemon.
//! This layer neither allocates an invocation ID nor issues authorization.

use vos::agent::sdk::wire::CanonicalWire as _;
use vos::agent::sdk::{
    InvocationAuthorization, InvocationOrigin, InvocationRoleClaims, RuntimeExecutionContext,
};
use vos::agent::supervisor_adapters::{AgentInvocationRequest, AgentInvocationResponse};

pub(crate) const MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_RESPONSE_BYTES: usize = AgentInvocationResponse::MAX_ENCODED_BYTES;

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
