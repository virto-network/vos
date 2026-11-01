use super::*;

#[test]
fn every_route_through_the_gateway_answers_as_the_nodes_http() {
    let served = Served::start(PerAddress::default());
    let agent = served.agent.0;
    let key = SigningKey::from_bytes(&[5; 32]);
    let client = Client::new(&Target::socket(served.socket.clone()), key.clone());
    let identity = client.identity(served.agent).unwrap();
    let call = signed_call(
        &identity,
        &key,
        client.session(served.agent),
        1,
        COUNTER,
        served.increment,
        4u64.encode(),
    )
    .encode();
    let query = signed_query(
        &identity,
        &key,
        served.now() + 60_000,
        Consistency::Applied { at: 0 },
        COUNTER,
        served.value,
        Vec::new(),
    )
    .encode();
    let stale_query = signed_query(
        &identity,
        &key,
        served.now() - 1,
        Consistency::Applied { at: 0 },
        COUNTER,
        served.value,
        Vec::new(),
    )
    .encode();
    let mut workflow = WorkflowRead {
        key: key.verifying_key().to_bytes(),
        not_after: served.now() + 60_000,
        consistency: Consistency::Applied { at: 0 },
        workflow: WorkflowId(77),
        wait_ms: 0,
        signature: [0; 64],
    };
    use ed25519_dalek::Signer;
    workflow.signature = key.sign(&workflow.message(&identity)).to_bytes();
    let workflow = workflow.encode();
    let oversize = vec![0u8; vos_wire::abi::cap::REQUEST + vos_api::ENVELOPE + 1];
    let grant = vos_wire::ingress::Grant {
        principal: vos_wire::ids::Principal::Client([9; 32]),
        role: Some(1),
    }
    .encode();
    // A first call of a session of its own for each front, adding 0: both
    // fronts' calls run, and answer the same total.
    let callers = AtomicU64::new(60);
    let first_call = || {
        let seed = callers.fetch_add(1, Ordering::SeqCst) as u8;
        let key = SigningKey::from_bytes(&[seed; 32]);
        let client = Client::new(&Target::socket(served.socket.clone()), key.clone());
        signed_call(
            &identity,
            &key,
            client.session(served.agent),
            1,
            COUNTER,
            served.increment,
            0u64.encode(),
        )
        .encode()
    };
    // A header whose command already ran: replayed at both fronts.
    let ran = served.header(Kind::Reports, [agent.encode(), true.encode()].concat());
    let reports = format!("/agents/{agent}/reports");
    let (status, _, _) = exchange(
        served.http,
        &request(
            "POST",
            &reports,
            &[format!("Authorization: {ran}")],
            &true.encode(),
        ),
    );
    assert_eq!(status, 200);
    let header_for = |node: NodeId, expires_ms: u64| {
        operated_header(&signed_operated(
            node,
            &SigningKey::from_bytes(&OPERATOR),
            Kind::Stats,
            fresh_nonce(),
            expires_ms,
            Vec::new(),
        ))
    };
    let expired = header_for(served.node.id(), served.now() - 1);
    let elsewhere = header_for(NodeId([3; 32]), served.now() + 60_000);
    let create = vos_wire::ingress::Create { replicas: vec![1] }.encode();
    // An install that runs: the counter, on an agent made for each front.
    let counter = install_of(COUNTER, &Programs::load().counter_elf).encode();
    let fresh_agent = || {
        let operator = Operator::signing(
            &Target::socket(served.socket.clone()),
            SigningKey::from_bytes(&OPERATOR),
            served.node.id(),
        );
        match operator.create_agent(Vec::new()) {
            Ok(Response::Created(agent)) => agent.0,
            other => panic!("an agent: {other:?}"),
        }
    };
    let replace = vos_wire::ingress::Replace { remove: 5, add: 6 }.encode();
    // A credentialed call in shape, its proof not one: the node refuses it
    // by its own checks (a node of no space), the gateway checking none.
    let credentialed = vos_wire::ingress::Credentialed {
        instance: vos_wire::ids::InstanceId(1),
        method: vos_wire::ids::MethodId(2),
        arguments: vec![3],
        nonce: [4; 16],
        expires_ms: served.now() + 60_000,
        format: 42,
        public: vos_wire::ingress::CredentialPublic::Owner {
            owner: [5; 32],
            binding: [6; 32],
        },
        proof: vec![7; 4096],
    }
    .encode();
    // Each request, made fresh for each front: an operator's header is
    // good once.
    type Make<'a> = Box<dyn Fn() -> Vec<u8> + 'a>;
    let corpus: Vec<(&str, Make)> = vec![
        ("node key", Box::new(|| request("GET", "/", &[], b""))),
        ("time", Box::new(|| request("GET", "/time", &[], b""))),
        (
            "an agent",
            Box::new(|| request("GET", &format!("/agents/{agent}"), &[], b"")),
        ),
        (
            "no agent",
            Box::new(|| request("GET", "/agents/99999", &[], b"")),
        ),
        ("no id", Box::new(|| request("GET", "/agents/x", &[], b""))),
        (
            "a schema",
            Box::new(|| {
                request(
                    "GET",
                    &format!("/agents/{agent}/instances/1/schema"),
                    &[],
                    b"",
                )
            }),
        ),
        (
            "no schema",
            Box::new(|| {
                request(
                    "GET",
                    &format!("/agents/{agent}/instances/9/schema"),
                    &[],
                    b"",
                )
            }),
        ),
        (
            "a schema, no id",
            Box::new(|| {
                request(
                    "GET",
                    &format!("/agents/{agent}/instances/x/schema"),
                    &[],
                    b"",
                )
            }),
        ),
        (
            "a call",
            Box::new(|| request("POST", &format!("/agents/{agent}/calls"), &[], &call)),
        ),
        (
            "a credentialed call",
            Box::new(|| {
                request(
                    "POST",
                    &format!("/agents/{agent}/credentialed"),
                    &[],
                    &credentialed,
                )
            }),
        ),
        (
            "a credentialed call that does not decode",
            Box::new(|| {
                request(
                    "POST",
                    &format!("/agents/{agent}/credentialed"),
                    &[],
                    &[0xff],
                )
            }),
        ),
        (
            "a credentialed call to no agent",
            Box::new(|| request("POST", "/agents/99999/credentialed", &[], &credentialed)),
        ),
        (
            "a malformed call",
            Box::new(|| request("POST", &format!("/agents/{agent}/calls"), &[], b"junk")),
        ),
        (
            "a call, no id",
            Box::new(|| request("POST", "/agents/x/calls", &[], &call)),
        ),
        (
            "a call past its limit",
            Box::new(|| request("POST", &format!("/agents/{agent}/calls"), &[], &oversize)),
        ),
        (
            "a query",
            Box::new(|| request("POST", &format!("/agents/{agent}/queries"), &[], &query)),
        ),
        (
            "a stale query",
            Box::new(|| {
                request(
                    "POST",
                    &format!("/agents/{agent}/queries"),
                    &[],
                    &stale_query,
                )
            }),
        ),
        (
            "a workflow",
            Box::new(|| {
                request(
                    "POST",
                    &format!("/agents/{agent}/workflows"),
                    &[],
                    &workflow,
                )
            }),
        ),
        (
            "an unknown path",
            Box::new(|| request("GET", "/nothing", &[], b"")),
        ),
        (
            "a known path, another method",
            Box::new(|| request("PUT", "/agents", &[], b"")),
        ),
        (
            "Expect",
            Box::new(|| {
                let mut bytes = format!("POST /agents/{agent}/queries HTTP/1.1\r\nHost: node\r\nConnection: close\r\nExpect: 100-continue\r\nContent-Length: {}\r\n\r\n", query.len()).into_bytes();
                bytes.extend_from_slice(&query);
                bytes
            }),
        ),
        (
            "chunked",
            Box::new(|| {
                format!("POST /agents/{agent}/calls HTTP/1.1\r\nHost: node\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n").into_bytes()
            }),
        ),
        (
            "a head too large",
            Box::new(|| {
                format!(
                    "GET / HTTP/1.1\r\nHost: node\r\nX: {}\r\n\r\n",
                    "a".repeat(17 << 10)
                )
                .into_bytes()
            }),
        ),
        (
            "stats",
            Box::new(|| {
                request(
                    "GET",
                    "/stats",
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::Stats, Vec::new())
                    )],
                    b"",
                )
            }),
        ),
        (
            "status",
            Box::new(|| {
                request(
                    "GET",
                    &format!("/agents/{agent}/status"),
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::Status, agent.encode())
                    )],
                    b"",
                )
            }),
        ),
        (
            "a grant",
            Box::new(|| {
                request(
                    "POST",
                    &format!("/agents/{agent}/roles"),
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::Grant, [agent.encode(), grant.clone()].concat())
                    )],
                    &grant,
                )
            }),
        ),
        (
            "an agent created",
            Box::new(|| {
                request(
                    "POST",
                    "/agents",
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::CreateAgent, Vec::new())
                    )],
                    b"",
                )
            }),
        ),
        (
            "an install",
            Box::new(|| {
                let agent = fresh_agent();
                request(
                    "POST",
                    &format!("/agents/{agent}/install"),
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::Install, [agent.encode(), counter.clone()].concat())
                    )],
                    &counter,
                )
            }),
        ),
        (
            "an install, malformed",
            Box::new(|| {
                request(
                    "POST",
                    &format!("/agents/{agent}/install"),
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::Install, [agent.encode(), b"elf".to_vec()].concat())
                    )],
                    b"elf",
                )
            }),
        ),
        (
            "an operator's route, no id",
            Box::new(|| {
                request(
                    "POST",
                    "/agents/x/reports",
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::Reports, Vec::new())
                    )],
                    &true.encode(),
                )
            }),
        ),
        (
            "an operator's route, no header",
            Box::new(|| request("GET", "/stats", &[], b"")),
        ),
        (
            "an operator's route, a bad header",
            Box::new(|| {
                request(
                    "GET",
                    "/stats",
                    &["Authorization: Operated !!".to_string()],
                    b"",
                )
            }),
        ),
        (
            "a first call",
            Box::new(|| {
                request(
                    "POST",
                    &format!("/agents/{agent}/calls"),
                    &[],
                    &first_call(),
                )
            }),
        ),
        (
            "a read with a body",
            Box::new(|| request("GET", &format!("/agents/{agent}"), &[], b"ignored")),
        ),
        (
            "an agent created on replicas",
            Box::new(|| {
                request(
                    "POST",
                    "/agents",
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::CreateAgent, create.clone())
                    )],
                    &create,
                )
            }),
        ),
        (
            "a representative",
            Box::new(|| {
                request(
                    "POST",
                    "/representative",
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::CreateRepresentative, Vec::new())
                    )],
                    b"",
                )
            }),
        ),
        (
            "reports",
            Box::new(|| {
                request(
                    "POST",
                    &reports,
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::Reports, [agent.encode(), false.encode()].concat())
                    )],
                    &false.encode(),
                )
            }),
        ),
        (
            "a replacement",
            Box::new(|| {
                request(
                    "POST",
                    &format!("/agents/{agent}/replicas"),
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::Replace, [agent.encode(), replace.clone()].concat())
                    )],
                    &replace,
                )
            }),
        ),
        (
            "a replayed command",
            Box::new(|| {
                request(
                    "POST",
                    &reports,
                    &[format!("Authorization: {ran}")],
                    &true.encode(),
                )
            }),
        ),
        (
            "an expired read",
            Box::new(|| request("GET", "/stats", &[format!("Authorization: {expired}")], b"")),
        ),
        (
            "a read signed for another node",
            Box::new(|| {
                request(
                    "GET",
                    "/stats",
                    &[format!("Authorization: {elsewhere}")],
                    b"",
                )
            }),
        ),
        (
            "an operator's route, signed for another agent",
            Box::new(|| {
                request(
                    "GET",
                    &format!("/agents/{agent}/status"),
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::Status, 1u32.encode())
                    )],
                    b"",
                )
            }),
        ),
    ];
    for (name, make) in &corpus {
        let (node_status, node_body, node_raw) = exchange(served.http, &make());
        let (front_status, front_body, front_raw) = exchange(served.front.address, &make());
        assert_eq!(
            masked(node_status, &node_body),
            masked(front_status, &front_body),
            "{name}"
        );
        assert_ne!(node_status, 0, "{name}");
        let _ = (node_raw, front_raw);
    }
    // The credentialed call's refusal is the node's, through the gateway.
    let path = format!("/agents/{agent}/credentialed");
    let (status, body, _) = exchange(
        served.front.address,
        &request("POST", &path, &[], &credentialed),
    );
    assert_eq!(status, 403);
    assert_eq!(
        Response::decode_exact(&body),
        Some(Response::Rejected(
            vos_wire::ingress::Rejection::Credential(vos_wire::ingress::CredentialRefusal::NoSpace)
        ))
    );
    // `Expect: 100-continue`: each says go on before the body is sent.
    let expect = |address: SocketAddr| {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let head = format!(
            "POST /agents/{agent}/queries HTTP/1.1\r\nHost: node\r\nConnection: close\r\nExpect: 100-continue\r\nContent-Length: {}\r\n\r\n",
            query.len()
        );
        stream.write_all(head.as_bytes()).unwrap();
        let mut go_on = [0u8; 25];
        stream.read_exact(&mut go_on).unwrap();
        assert_eq!(&go_on, b"HTTP/1.1 100 Continue\r\n\r\n");
        stream.write_all(&query).unwrap();
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest);
        String::from_utf8_lossy(&rest)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(expect(served.http), expect(served.front.address));
}

/// A gateway that alters a byte of a signed call's arguments gets the
/// node's `BadSignature`: it can forge nothing.
#[test]
fn a_gateway_altering_a_signed_call_is_refused() {
    let served = Served::start(PerAddress::default());
    let key = SigningKey::from_bytes(&[6; 32]);
    let client = Client::new(&Target::socket(served.socket.clone()), key.clone());
    let identity = client.identity(served.agent).unwrap();
    let mut call = signed_call(
        &identity,
        &key,
        client.session(served.agent),
        1,
        COUNTER,
        served.increment,
        7u64.encode(),
    );
    call.arguments[0] ^= 1;
    let upstream = Upstream::new(
        served.node.id().0,
        Address::Socket(served.socket.clone()),
        GATEWAY,
    );
    let body = (served.agent, call).encode();
    let (kind, answer) = served
        .front
        .runtime
        .block_on(upstream.request(Kind::Call as u16, &body))
        .unwrap();
    assert_eq!(kind, Kind::Call as u16);
    assert_eq!(
        Response::decode_exact(&answer),
        Some(Response::Rejected(Rejection::BadSignature))
    );
}
