use super::*;
use crate::commands::space::clean_store::CleanInvocationFile;
use std::os::unix::fs::DirBuilderExt as _;
use vos::agent::sdk::*;

fn fixture() -> (Vec<u8>, Vec<u8>, Vec<(String, Vec<u8>, Vec<u8>)>) {
    let work = InvocationWork {
        space: SpaceId([1; 32]),
        agent: AgentId([2; 32]),
        runtime_deployment: DeploymentId([3; 32]),
        invocation: InvocationId([4; 32]),
        actor: ActorId([5; 32]),
        incarnation: Hash([6; 32]),
        deployment: DeploymentId([7; 32]),
        program: ProgramId([8; 32]),
        mode: MethodMode::Linear,
        origin: InvocationOrigin::anonymous(),
        roles: InvocationRoleClaims::none(),
        message: vec![1],
        installation_data: None,
        availability: Vec::new(),
        gas: 100,
        recovery_only: false,
    };
    let auth = InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&work, 17));
    let call =
        AgentInvocationRequest::new(RuntimeExecutionContext::Direct, work.clone(), auth.clone())
            .unwrap();
    let mut yielded = YieldedInvocation {
        invocation: work.invocation,
        actor: work.actor,
        incarnation: work.incarnation,
        deployment: work.deployment,
        program: work.program,
        mode: work.mode,
        continuation: BlobRef::of_bytes(&[1]),
        ready_sequence: 1,
        installation_data: None,
        required: Vec::new(),
        reason: YieldReason::Cooperative,
    };
    let initial = AgentInvocationResponse::Direct {
        request: call.commitment(),
        outcome: RuntimeOutcome::Yielded(yielded.clone()),
    }
    .encode()
    .unwrap();
    let first = AgentResumeRequest::new(
        RuntimeExecutionContext::Direct,
        None,
        work.clone(),
        auth.clone(),
        yielded.clone(),
    )
    .unwrap();
    yielded.ready_sequence = 2;
    yielded.continuation = BlobRef::of_bytes(&[2]);
    let first_reply = AgentResumeResponse::Direct {
        request: first.commitment(),
        outcome: RuntimeOutcome::Yielded(yielded.clone()),
    }
    .encode()
    .unwrap();
    let second = AgentResumeRequest::new(
        RuntimeExecutionContext::Direct,
        None,
        work.clone(),
        auth.clone(),
        yielded,
    )
    .unwrap();
    let second_reply = AgentResumeResponse::Direct {
        request: second.commitment(),
        outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
    }
    .encode()
    .unwrap();
    let ack = AgentAcknowledgementRequest::new(
        RuntimeExecutionContext::Direct,
        None,
        work.clone(),
        auth.clone(),
    )
    .unwrap();
    let transition = RuntimeTransition {
        state: RuntimeState::default(),
        outcome: RuntimeOutcome::Acknowledged(Ok(InvocationAcknowledgement {
            invocation: work.invocation,
            actor: work.actor,
            incarnation: work.incarnation,
            deployment: work.deployment,
            mode: work.mode,
            work: work.commitment(),
            authorization: auth.commitment(),
        })),
    }
    .encode()
    .unwrap();
    let mut ack_reply = b"AAR3".to_vec();
    ack_reply.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    ack_reply.extend_from_slice(ack.commitment().as_bytes());
    ack_reply.extend_from_slice(&(transition.len() as u32).to_le_bytes());
    ack_reply.extend_from_slice(&transition);
    assert!(
        AgentAcknowledgementResponse::decode(&ack_reply)
            .unwrap()
            .matches_request(&ack)
    );
    (
        call.encode().unwrap(),
        initial,
        vec![
            (
                "/__agents/resume".into(),
                first.encode().unwrap(),
                first_reply,
            ),
            (
                "/__agents/resume".into(),
                second.encode().unwrap(),
                second_reply,
            ),
            (
                "/__agents/acknowledge".into(),
                ack.encode().unwrap(),
                ack_reply,
            ),
        ],
    )
}

fn directory() -> std::path::PathBuf {
    let mut nonce = [0; 8];
    getrandom::getrandom(&mut nonce).unwrap();
    let root = std::env::temp_dir().join(format!("vos-continuation-{}", hex::encode(nonce)));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .unwrap();
    root
}

#[test]
fn progress_requires_exact_predecessors_and_monotonic_publication() {
    let (request, response, exchanges) = fixture();
    let root = directory();
    let path = root.join("delivery");
    let mut store = CleanInvocationFile::open_or_create(&path).unwrap();
    store.publish_request(&request).unwrap();
    store.publish_response(&response).unwrap();
    let initial = Progress::new(&request).unwrap();
    assert!(!initial.is_retired(&request, &response).unwrap());
    let mut progress = initial.clone();
    for (_, next, reply) in &exchanges {
        let mut skipped_pending = progress.clone();
        skipped_pending.exchanges.push(Exchange {
            request: hex::encode(next),
            response: Some(hex::encode(reply)),
        });
        assert!(
            store
                .publish_progress(&skipped_pending.encode().unwrap())
                .is_err(),
            "response cannot skip durable request publication"
        );
        progress.exchanges.push(Exchange {
            request: hex::encode(next),
            response: None,
        });
        store.publish_progress(&progress.encode().unwrap()).unwrap();
        assert!(!progress.is_retired(&request, &response).unwrap());
        let pending = progress.encode().unwrap();
        assert!(store.publish_progress(&initial.encode().unwrap()).is_err());
        let mut forged = progress.clone();
        forged.exchanges.last_mut().unwrap().response = Some(hex::encode(&exchanges[0].1));
        assert!(store.publish_progress(&forged.encode().unwrap()).is_err());
        assert_eq!(store.load_progress().unwrap(), Some(pending.clone()));
        drop(store);
        store = CleanInvocationFile::open_or_create(&path).unwrap();
        assert_eq!(store.load_progress().unwrap(), Some(pending));
        progress.exchanges.last_mut().unwrap().response = Some(hex::encode(reply));
        store.publish_progress(&progress.encode().unwrap()).unwrap();
    }
    assert!(progress.is_retired(&request, &response).unwrap());
    let ack = AgentAcknowledgementRequest::decode(&exchanges.last().unwrap().1).unwrap();
    let transition = RuntimeTransition {
        state: RuntimeState::default(),
        outcome: RuntimeOutcome::Acknowledged(Err(InvocationError::NotFound)),
    }
    .encode()
    .unwrap();
    let mut failed_reply = b"AAR3".to_vec();
    failed_reply.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    failed_reply.extend_from_slice(ack.commitment().as_bytes());
    failed_reply.extend_from_slice(&(transition.len() as u32).to_le_bytes());
    failed_reply.extend_from_slice(&transition);
    let mut failed = progress.clone();
    failed.exchanges.last_mut().unwrap().response = Some(hex::encode(failed_reply));
    assert!(!failed.is_retired(&request, &response).unwrap());
    let bytes = progress.encode().unwrap();
    let mut noncanonical = bytes.clone();
    noncanonical.push(b' ');
    assert!(Progress::decode(&noncanonical, &request, &response).is_err());
    let mut overflow = initial;
    overflow.exchanges = vec![
        Exchange {
            request: String::new(),
            response: None
        };
        MAX_STEPS + 1
    ];
    assert!(overflow.encode().is_err());
    drop(store);
    assert!(continue_retained(&path, "127.0.0.1:1".parse().unwrap()).is_ok());
    std::fs::remove_file(path.join("invocation.response")).unwrap();
    let mut store = CleanInvocationFile::open_or_create(&path).unwrap();
    assert!(
        store.publish_response(&response).is_err(),
        "orphan progress must not repair its predecessor"
    );
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn historical_non_durable_response_is_preserved_without_creating_an_acknowledgement() {
    for rejection in [
        InvocationError::ResultCapacity,
        InvocationError::AuthorityExpired,
        InvocationError::InvalidAuthorization,
        InvocationError::StaleContinuation,
    ] {
        let (request, _, _) = fixture();
        let call = AgentInvocationRequest::decode(&request).unwrap();
        let response = AgentInvocationResponse::Direct {
            request: call.commitment(),
            outcome: RuntimeOutcome::Completed(Err(rejection)),
        }
        .encode()
        .unwrap();
        let root = directory();
        let path = root.join("delivery");
        let mut store = CleanInvocationFile::open_or_create(&path).unwrap();
        store.publish_request(&request).unwrap();
        store.publish_response(&response).unwrap();
        drop(store);
        let error = continue_retained(&path, "127.0.0.1:1".parse().unwrap()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(&format!("non-durable invocation rejection {rejection:?}"))
        );
        let mut reopened = CleanInvocationFile::open_or_create(&path).unwrap();
        assert_eq!(reopened.load_request().unwrap(), Some(request));
        assert_eq!(reopened.load_response().unwrap(), Some(response));
        assert!(reopened.load_progress().unwrap().is_none());
        drop(reopened);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn continuation_command_requires_the_retained_directory_and_endpoint() {
    use clap::Parser as _;
    let parsed = crate::Cli::try_parse_from([
        "vosx",
        "space",
        "continue-agent-invocation",
        "delivery",
        "--http",
        "127.0.0.1:8080",
    ])
    .unwrap();
    assert!(matches!(
        parsed.command,
        Some(crate::Command::Space {
            command: crate::commands::space::SpaceCommand::ContinueAgentInvocation { .. }
        })
    ));
    assert!(
        crate::Cli::try_parse_from(["vosx", "space", "continue-agent-invocation", "delivery"])
            .is_err()
    );
}

#[test]
fn continuation_retries_pending_bytes_then_resumes_and_retires_under_one_lease() {
    use std::io::{Read as _, Write as _};
    let (request, response, exchanges) = fixture();
    let root = directory();
    let path = root.join("delivery");
    let mut store = CleanInvocationFile::open_or_create(&path).unwrap();
    store.publish_request(&request).unwrap();
    store.publish_response(&response).unwrap();
    drop(store);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let leased = path.clone();
    let server = std::thread::spawn(move || {
        for (index, exchange) in std::iter::repeat_n(&exchanges[0], 2)
            .chain(exchanges.iter())
            .enumerate()
        {
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
            assert!(
                String::from_utf8(header)
                    .unwrap()
                    .starts_with(&format!("POST {} HTTP/1.1\r\n", exchange.0))
            );
            let mut body = vec![0; exchange.1.len()];
            stream.read_exact(&mut body).unwrap();
            assert_eq!(body, exchange.1);
            assert!(CleanInvocationFile::open_or_create(&leased).is_err());
            let saved = std::fs::read(leased.join("invocation.progress")).unwrap();
            let expected = hex::encode(&exchange.1);
            assert!(
                saved
                    .windows(expected.len())
                    .any(|window| window == expected.as_bytes())
            );
            let status = if index == 0 { 503 } else { 200 };
            let reply = if index == 1 {
                let resume = AgentResumeRequest::decode(&exchange.1).unwrap();
                AgentResumeResponse::Direct {
                    request: resume.commitment(),
                    outcome: RuntimeOutcome::Completed(Err(InvocationError::ResultCapacity)),
                }
                .encode()
                .unwrap()
            } else {
                exchange.2.clone()
            };
            write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", reply.len()).unwrap();
            stream.write_all(&reply).unwrap();
        }
    });
    assert!(continue_retained(&path, address).is_err());
    let pending = std::fs::read(path.join("invocation.progress")).unwrap();
    assert!(
        continue_retained(&path, address)
            .unwrap_err()
            .to_string()
            .contains("ResultCapacity")
    );
    assert_eq!(
        std::fs::read(path.join("invocation.progress")).unwrap(),
        pending,
        "a non-durable resume rejection must not replace its pending request with an ACK step"
    );
    continue_retained(&path, address).unwrap();
    server.join().unwrap();
    continue_retained(&path, "127.0.0.1:1".parse().unwrap()).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}
