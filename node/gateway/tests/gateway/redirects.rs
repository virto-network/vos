use super::*;

/// Nodes of one space over a hub, each serving its API's socket, their
/// ingress as `ingress` names it by number.
struct Cluster {
    programs: Programs,
    nodes: Vec<Node>,
    sockets: Vec<PathBuf>,
    _dirs: Vec<tempfile::TempDir>,
}

impl Cluster {
    fn start(count: usize, ingress: impl Fn(u8) -> String) -> Self {
        let programs = Programs::load();
        let dirs: Vec<tempfile::TempDir> =
            (0..count).map(|_| tempfile::tempdir().unwrap()).collect();
        let space = vos_checker::spaces::space(&programs.agent, &dirs, ingress);
        let hub = vos_net::memory::Hub::new(7);
        let clock = Arc::new(AtomicU64::new(vos_node::wall_clock()));
        let nodes: Vec<Node> = dirs
            .iter()
            .map(|dir| {
                let mut config = config(&programs, &clock);
                config.space = Some(space.clone());
                config.peers = Peers::Hub(hub.clone());
                let node = Node::open(dir.path(), config).unwrap();
                node.serve_socket(&dir.path().join("api.sock"), 0o600)
                    .unwrap();
                node
            })
            .collect();
        let sockets = dirs.iter().map(|dir| dir.path().join("api.sock")).collect();
        Self {
            programs,
            nodes,
            sockets,
            _dirs: dirs,
        }
    }

    /// The operator, signing for node `at` and reaching it on its socket.
    fn operator(&self, at: usize) -> Operator {
        Operator::signing(
            &Target::socket(self.sockets[at].clone()),
            SigningKey::from_bytes(&OPERATOR),
            self.nodes[at].id(),
        )
    }

    /// Node `at` as an upstream.
    fn upstream(&self, at: usize) -> ([u8; 32], Address) {
        (
            self.nodes[at].id().0,
            Address::Socket(self.sockets[at].clone()),
        )
    }

    /// The counter's `increment`, as `agent` has it installed.
    fn increment(&self, agent: AgentId) -> MethodId {
        vos_node::client::schema(&Target::socket(self.sockets[0].clone()), agent, COUNTER)
            .unwrap()
            .unwrap()
            .method_id("increment")
            .unwrap()
    }
}

/// A stand-in node on a unix socket at `path` answering every request
/// `NotLeader`, naming `leader`: what a replica answers while its group
/// changes leaders.
fn deposed(runtime: &tokio::runtime::Runtime, path: &std::path::Path, leader: NodeId) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use vos_api::{Event, Framing, Reader, Requests, frame};
    let listener = {
        let _entered = runtime.enter();
        tokio::net::UnixListener::bind(path).unwrap()
    };
    runtime.spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut reader = Reader::requests(Framing::Stream, Requests::All);
                let mut chunk = vec![0u8; 1 << 16];
                let answer = Response::NotLeader {
                    leader: Some(Contact {
                        address: "http://127.0.0.1:1".into(),
                        node: leader,
                    }),
                }
                .encode();
                while let Ok(read @ 1..) = stream.read(&mut chunk).await {
                    reader.push(&chunk[..read]);
                    while let Some(Event::Frame(request)) = reader.event() {
                        let bytes = frame(Framing::Stream, request.kind, request.id, &answer);
                        if stream.write_all(&bytes).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
}

/// A call the gateway sends to a node that no longer leads is sent on to
/// the leader its `NotLeader` names, which the gateway then learns: the
/// next call goes there at once.
#[test]
fn the_gateway_follows_not_leader_to_the_leader_it_names() {
    let served = Served::start(PerAddress::default());
    let dir = tempfile::tempdir().unwrap();
    let stand_in = dir.path().join("deposed.sock");
    // The stand-in first: the gateway's first request of the turn.
    let front = Front::start(
        vec![
            ([78; 32], Address::Socket(stand_in.clone())),
            (served.node.id().0, Address::Socket(served.socket.clone())),
        ],
        PerAddress::default(),
    );
    deposed(&front.runtime, &stand_in, served.node.id());
    let call = |seed: u8| {
        let body = Client::new(
            &Target::socket(served.socket.clone()),
            SigningKey::from_bytes(&[seed; 32]),
        )
        .call_body(served.agent, 1, COUNTER, served.increment, &1u64.encode())
        .unwrap();
        exchange(
            front.address,
            &request(
                "POST",
                &format!("/agents/{}/calls", served.agent.0),
                &[],
                &body,
            ),
        )
    };
    let (status, body, _) = call(53);
    assert_eq!(status, 200, "{:?}", Response::decode_exact(&body));
    assert!(matches!(
        Response::decode_exact(&body),
        Some(Response::Ran { .. })
    ));
    assert_eq!(front.gateway.sent(), 2, "the stand-in, then the leader");
    let (status, _, _) = call(54);
    assert_eq!(status, 200);
    assert_eq!(front.gateway.sent(), 3, "the leader as learned");
}

/// A client pinning a gateway follows a 421 through it: a gateway knowing
/// only the node that does not hold the agent passes its `Elsewhere` on,
/// the replica's ingress names a second gateway under the same key, and
/// the pin carried across the redirect holds there.
#[test]
fn a_client_pinning_the_gateway_follows_a_421_through_it() {
    let listeners: Vec<std::net::TcpListener> = (0..2)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let urls: Vec<String> = listeners
        .iter()
        .map(|listener| format!("https://{}", listener.local_addr().unwrap()))
        .collect();
    // Node 1's ingress is the first gateway, node 2's the second.
    let cluster = Cluster::start(2, |number| urls[usize::from(number) - 1].clone());
    let Ok(Response::Created(agent)) = cluster.operator(0).create_agent(Vec::new()) else {
        panic!("an agent on node 1")
    };
    installed(
        cluster
            .operator(0)
            .install(agent, &install_of(COUNTER, &cluster.programs.counter_elf))
            .unwrap(),
    );
    let at_second = Target::socket(cluster.sockets[1].clone());
    wait_until("node 2 learns the agent", || {
        matches!(vos_node::client::agent_info(&at_second, agent), Ok(Some(_)))
    });
    let increment = cluster.increment(agent);
    let tls = || {
        vos_http::tls::server_config(
            &vos_http::tls::IngressTls::NodeKey {
                names: vec!["127.0.0.1".into()],
            },
            &GATEWAY,
        )
        .unwrap()
    };
    let mut listeners = listeners.into_iter();
    let first = Front::start_on(
        listeners.next().unwrap(),
        vec![cluster.upstream(0)],
        PerAddress::default(),
        Some(tls()),
    );
    let second = Front::start_on(
        listeners.next().unwrap(),
        vec![cluster.upstream(1)],
        PerAddress::default(),
        Some(tls()),
    );
    let gateway = SigningKey::from_bytes(&GATEWAY).verifying_key().to_bytes();
    let pinned = Target::new(&urls[1], vos_node::tls::Trust::Gateway(gateway)).unwrap();
    let mut client = Client::new(&pinned, SigningKey::from_bytes(&[13; 32]));
    let answer = client
        .call(agent, COUNTER, increment, &5u64.encode())
        .unwrap();
    assert_eq!(vos_checker::calls::done(answer), 5);
    assert!(
        second.gateway.sent() >= 1,
        "asked first, it passed the 421 on"
    );
    assert!(first.gateway.sent() >= 1, "the redirect reached the first");
}

/// Two nodes of one space behind a gateway: a request to the node that
/// does not hold the agent is sent on to the one that does; a gateway
/// knowing no such node passes the redirect on; an operator's request goes
/// to the one node it is signed for, or is refused when that is none of
/// the gateway's.
#[test]
fn the_gateway_follows_redirects_and_routes_operators_by_their_node() {
    let cluster = Cluster::start(2, |number| {
        format!("http://127.0.0.1:{}", 7000 + u16::from(number))
    });
    let (nodes, sockets) = (&cluster.nodes, &cluster.sockets);
    let operator = |at: usize| cluster.operator(at);
    let Ok(Response::Created(agent)) = operator(0).create_agent(Vec::new()) else {
        panic!("an agent on node 1")
    };
    installed(
        operator(0)
            .install(agent, &install_of(COUNTER, &cluster.programs.counter_elf))
            .unwrap(),
    );
    // Node 2 learns where the agent is.
    let at_second = Target::socket(sockets[1].clone());
    wait_until("node 2 learns the agent", || {
        matches!(vos_node::client::agent_info(&at_second, agent), Ok(Some(_)))
    });
    let both = vec![cluster.upstream(1), cluster.upstream(0)];
    let front = Front::start(both, PerAddress::default());
    let url = format!("http://{}", front.address);
    let mut client = Client::new(
        &Target::loopback(&url).unwrap(),
        SigningKey::from_bytes(&[8; 32]),
    );
    let increment = cluster.increment(agent);
    for by in 1..=3u64 {
        let answer = client
            .call(agent, COUNTER, increment, &by.encode())
            .unwrap();
        assert!(matches!(answer, Response::Ran { .. }), "{answer:?}");
    }
    // A gateway knowing only node 2 passes the redirect on.
    let alone = Front::start(vec![cluster.upstream(1)], PerAddress::default());
    let call = Client::new(
        &Target::socket(sockets[0].clone()),
        SigningKey::from_bytes(&[9; 32]),
    )
    .call_body(agent, 1, COUNTER, increment, &1u64.encode())
    .unwrap();
    let (status, body, _) = exchange(
        alone.address,
        &request("POST", &format!("/agents/{}/calls", agent.0), &[], &call),
    );
    assert_eq!(status, 421);
    assert!(matches!(
        Response::decode_exact(&body),
        Some(Response::Elsewhere { .. })
    ));
    // An operator's request signed for node 2 runs on node 2; one signed
    // for a node behind no upstream is refused by the gateway.
    let through = |node: NodeId| {
        Operator::signing(
            &Target::loopback(&url).unwrap(),
            SigningKey::from_bytes(&OPERATOR),
            node,
        )
    };
    let Ok(Response::Created(created)) = through(nodes[1].id()).create_agent(Vec::new()) else {
        panic!("an agent on node 2")
    };
    assert_eq!(
        vos_wire::peer::CreationRecord::creator_of(created),
        2,
        "created by node 2"
    );
    let sent = front.gateway.sent();
    assert_eq!(
        through(NodeId([3; 32])).stats().unwrap(),
        Response::Rejected(Rejection::Operator(OperatorRefusal::OtherNode))
    );
    assert_eq!(front.gateway.sent(), sent, "no node asked");
}

/// A client pinning the gateway's own-key HTTPS calls through it: the node
/// key `GET /` answers is not compared with the gateway's, and the pin
/// holds.
#[test]
fn a_client_pinning_the_gateway_calls_through_it() {
    let served = Served::start(PerAddress::default());
    let tls = vos_http::tls::server_config(
        &vos_http::tls::IngressTls::NodeKey {
            names: vec!["127.0.0.1".into()],
        },
        &GATEWAY,
    )
    .unwrap();
    let front = Front::start_with(
        vec![(served.node.id().0, Address::Socket(served.socket.clone()))],
        PerAddress::default(),
        Some(tls),
    );
    let gateway = SigningKey::from_bytes(&GATEWAY).verifying_key().to_bytes();
    let url = format!("https://{}", front.address);
    let pinned = Target::new(&url, vos_node::tls::Trust::Gateway(gateway)).unwrap();
    assert_eq!(
        vos_node::client::node_id(&pinned).unwrap(),
        served.node.id()
    );
    // Pinned as a node instead, the gateway's key is not the node's.
    let as_node = Target::new(&url, vos_node::tls::Trust::NodeKey(gateway)).unwrap();
    assert!(vos_node::client::node_id(&as_node).is_err());
    let mut client = Client::new(&pinned, SigningKey::from_bytes(&[12; 32]));
    let mut total = 0;
    for by in 1..=3u64 {
        total += by;
        let answer = client
            .call(served.agent, COUNTER, served.increment, &by.encode())
            .unwrap();
        assert_eq!(vos_checker::calls::done(answer), total);
    }
}
