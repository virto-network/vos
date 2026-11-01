use super::*;

/// What a route's body is pinned to: empty, the node's key, its time, an
/// agent's record, the counter's schema, or a node API answer (its applied
/// index, a created id, the stats and a replica's status masked).
enum Pin {
    Empty,
    NodeKey,
    Time,
    Info,
    Schema,
    Done,
    Stats,
    Status,
    Answer(Response),
}

fn done(reply: Vec<u8>) -> Pin {
    Pin::Answer(Response::Ran {
        outcome: Outcome::Done(reply),
        at: 0,
    })
}

/// Every route through the gateway answers its pinned status and body:
/// one corpus of each route, valid, malformed, a bad id, oversize, unknown
/// paths, `Expect`, chunked, a head past its limit, and the operator
/// routes with an `Operated` header, a bad one, none.
#[test]
fn every_route_through_the_gateway_answers_as_pinned() {
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
    // A first call of a session of its own, started at the node's time,
    // adding 0: it runs, and answers the total.
    let first_call = || {
        let key = SigningKey::from_bytes(&[60; 32]);
        let session = Session {
            key: key.verifying_key().to_bytes(),
            name: [60; 16],
            t0: served.now(),
        };
        signed_call(
            &identity,
            &key,
            session,
            1,
            COUNTER,
            served.increment,
            0u64.encode(),
        )
        .encode()
    };
    // A header whose command already ran: replayed.
    let ran = served.header(Kind::Reports, [agent.encode(), true.encode()].concat());
    let reports = format!("/agents/{agent}/reports");
    let (status, _, _) = exchange(
        served.front.address,
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
    // An install that runs: the counter, on an agent of its own.
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
    // Each request, with its status and body.
    type Make<'a> = Box<dyn Fn() -> Vec<u8> + 'a>;
    let corpus: Vec<(&str, Make, u16, Pin)> = vec![
        (
            "node key",
            Box::new(|| request("GET", "/", &[], b"")),
            200,
            Pin::NodeKey,
        ),
        (
            "time",
            Box::new(|| request("GET", "/time", &[], b"")),
            200,
            Pin::Time,
        ),
        (
            "an agent",
            Box::new(|| request("GET", &format!("/agents/{agent}"), &[], b"")),
            200,
            Pin::Info,
        ),
        (
            "no agent",
            Box::new(|| request("GET", "/agents/99999", &[], b"")),
            404,
            Pin::Empty,
        ),
        (
            "no id",
            Box::new(|| request("GET", "/agents/x", &[], b"")),
            404,
            Pin::Empty,
        ),
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
            200,
            Pin::Schema,
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
            404,
            Pin::Empty,
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
            404,
            Pin::Empty,
        ),
        (
            "a call",
            Box::new(|| request("POST", &format!("/agents/{agent}/calls"), &[], &call)),
            200,
            done(4u64.encode()),
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
            403,
            Pin::Answer(Response::Rejected(Rejection::Credential(
                vos_wire::ingress::CredentialRefusal::NoSpace,
            ))),
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
            400,
            Pin::Answer(Response::Rejected(Rejection::Malformed)),
        ),
        (
            "a credentialed call to no agent",
            Box::new(|| request("POST", "/agents/99999/credentialed", &[], &credentialed)),
            404,
            Pin::Answer(Response::NoAgent),
        ),
        (
            "a malformed call",
            Box::new(|| request("POST", &format!("/agents/{agent}/calls"), &[], b"junk")),
            400,
            Pin::Answer(Response::Rejected(Rejection::Malformed)),
        ),
        (
            "a call, no id",
            Box::new(|| request("POST", "/agents/x/calls", &[], &call)),
            404,
            Pin::Answer(Response::NoAgent),
        ),
        (
            "a call past its limit",
            Box::new(|| request("POST", &format!("/agents/{agent}/calls"), &[], &oversize)),
            413,
            Pin::Empty,
        ),
        (
            "a query",
            Box::new(|| request("POST", &format!("/agents/{agent}/queries"), &[], &query)),
            200,
            done(4u64.encode()),
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
            400,
            Pin::Answer(Response::Rejected(Rejection::StaleQuery { now: 0 })),
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
            200,
            Pin::Answer(Response::Workflow {
                status: vos_wire::ingress::WorkflowStatus::Unknown,
                at: 0,
            }),
        ),
        (
            "an unknown path",
            Box::new(|| request("GET", "/nothing", &[], b"")),
            404,
            Pin::Empty,
        ),
        (
            "a known path, another method",
            Box::new(|| request("PUT", "/agents", &[], b"")),
            404,
            Pin::Empty,
        ),
        (
            "Expect",
            Box::new(|| {
                let mut bytes = format!("POST /agents/{agent}/queries HTTP/1.1\r\nHost: node\r\nConnection: close\r\nExpect: 100-continue\r\nContent-Length: {}\r\n\r\n", query.len()).into_bytes();
                bytes.extend_from_slice(&query);
                bytes
            }),
            200,
            done(4u64.encode()),
        ),
        (
            "chunked",
            Box::new(|| {
                format!("POST /agents/{agent}/calls HTTP/1.1\r\nHost: node\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n").into_bytes()
            }),
            411,
            Pin::Empty,
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
            431,
            Pin::Empty,
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
            200,
            Pin::Stats,
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
            200,
            Pin::Status,
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
            200,
            done(Vec::new()),
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
            200,
            Pin::Answer(Response::Created(AgentId(0))),
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
            200,
            Pin::Done,
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
            400,
            Pin::Answer(Response::Rejected(Rejection::Malformed)),
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
            404,
            Pin::Answer(Response::NoAgent),
        ),
        (
            "an operator's route, no header",
            Box::new(|| request("GET", "/stats", &[], b"")),
            401,
            Pin::Answer(Response::Rejected(Rejection::Unauthorized)),
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
            401,
            Pin::Answer(Response::Rejected(Rejection::Unauthorized)),
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
            200,
            done(4u64.encode()),
        ),
        (
            "a read with a body",
            Box::new(|| request("GET", &format!("/agents/{agent}"), &[], b"ignored")),
            200,
            Pin::Info,
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
            503,
            Pin::Answer(Response::Unavailable),
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
            503,
            Pin::Answer(Response::Unavailable),
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
            200,
            done(Vec::new()),
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
            409,
            Pin::Answer(Response::Unplaced(vos_wire::ingress::Unplaced::NotAReplica)),
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
            409,
            Pin::Answer(Response::Rejected(Rejection::Operator(
                OperatorRefusal::Replayed,
            ))),
        ),
        (
            "an expired read",
            Box::new(|| request("GET", "/stats", &[format!("Authorization: {expired}")], b"")),
            403,
            Pin::Answer(Response::Rejected(Rejection::Operator(
                OperatorRefusal::Expiry { now: served.now() },
            ))),
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
            421,
            Pin::Answer(Response::Rejected(Rejection::Operator(
                OperatorRefusal::OtherNode,
            ))),
        ),
        (
            "an operator's route, signed for another agent",
            Box::new(|| {
                request(
                    "GET",
                    &format!("/agents/{agent}/status"),
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::Status, (agent + 1).encode())
                    )],
                    b"",
                )
            }),
            401,
            Pin::Answer(Response::Rejected(Rejection::BadSignature)),
        ),
    ];
    for (name, make, pinned, pin) in &corpus {
        let (status, body, _) = exchange(served.front.address, &make());
        assert_eq!(status, *pinned, "{name}");
        match pin {
            Pin::Empty => assert!(body.is_empty(), "{name}"),
            Pin::NodeKey => assert_eq!(body, served.node.id().encode(), "{name}"),
            Pin::Time => assert_eq!(u64::decode_exact(&body), Some(served.now()), "{name}"),
            Pin::Info => {
                let info = vos_wire::ingress::AgentInfo::decode_exact(&body).expect(name);
                assert_eq!(info.record.agent, served.agent, "{name}");
            }
            Pin::Schema => {
                let schema = vos_wire::schema::Schema::decode_exact(&body).expect(name);
                assert_eq!(schema.method_id("increment"), Some(served.increment));
            }
            Pin::Done => assert!(
                matches!(
                    Response::decode_exact(&body),
                    Some(Response::Ran {
                        outcome: Outcome::Done(_),
                        ..
                    })
                ),
                "{name}"
            ),
            Pin::Stats => assert!(
                matches!(Response::decode_exact(&body), Some(Response::Stats(_))),
                "{name}"
            ),
            Pin::Status => assert!(
                matches!(Response::decode_exact(&body), Some(Response::Status(_))),
                "{name}"
            ),
            Pin::Answer(answer) => {
                assert_eq!(masked(status, &body).1, answer.encode(), "{name}");
            }
        }
    }
    // `Expect: 100-continue`: the gateway says go on before the body is
    // sent.
    let mut stream = TcpStream::connect(served.front.address).unwrap();
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
    assert!(rest.starts_with(b"HTTP/1.1 200 OK\r\n"));
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
