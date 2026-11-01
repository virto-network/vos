//! Signed operator requests over the node API, on both transports: each
//! refusal in its order, a command's nonce once (two copies at once, and
//! after a restart), the reads' none, the nonces' bound, and the local
//! operator key.

use std::os::unix::net::UnixStream;

use ed25519_dalek::Signer;
use vos_api::{Kind, operator_message};
use vos_node::client::signed_operated;
use vos_wire::ingress::{NodeId, OperatorRefusal};

use super::api::{connect, receive, send};
use super::quic::{GATEWAY, ask, dial, quic_served};
use super::*;

/// How a test reaches the node API.
enum Transport {
    Socket(UnixStream),
    Quic(quinn::Connection),
}

impl Transport {
    fn ask(&mut self, kind: Kind, body: &[u8]) -> Response {
        let body = match self {
            Transport::Socket(stream) => {
                send(stream, kind as u16, 1, body);
                receive(stream).expect("an answer").2
            }
            Transport::Quic(connection) => ask(connection, kind as u16, body).1,
        };
        Response::decode_exact(&body).expect("a response")
    }
}

/// A node serving its socket and QUIC, and a transport of each to it.
fn both() -> (Served, [Transport; 2]) {
    let (served, address) = quic_served(|_| {});
    let socket = Transport::Socket(connect(&served.socket));
    let quic = Transport::Quic(dial(&served, address, GATEWAY, vos_net::api::ALPN).unwrap());
    (served, [socket, quic])
}

fn refused(refusal: OperatorRefusal) -> Response {
    Response::Rejected(Rejection::Operator(refusal))
}

fn operator() -> SigningKey {
    SigningKey::from_bytes(&OPERATOR)
}

#[test]
fn each_refusal_in_its_order_on_both_transports() {
    let (served, transports) = both();
    for mut transport in transports {
        let create = |key: &SigningKey, node: NodeId, expires: u64| {
            signed_operated(
                node,
                key,
                Kind::CreateAgent,
                fresh_nonce(),
                expires,
                Vec::new(),
            )
        };
        let node = served.node.id();
        let later = served.now() + 60_000;
        // Bare: no envelope.
        assert_eq!(
            transport.ask(Kind::CreateAgent, &[]),
            Response::Rejected(Rejection::Malformed)
        );
        // Signed for another node: refused before the key or signature.
        let other = create(&SigningKey::from_bytes(&[1; 32]), NodeId([7; 32]), later);
        assert_eq!(
            transport.ask(Kind::CreateAgent, &other.encode()),
            refused(OperatorRefusal::OtherNode)
        );
        // An unlisted key.
        let stranger = create(&SigningKey::from_bytes(&[1; 32]), node, later);
        assert_eq!(
            transport.ask(Kind::CreateAgent, &stranger.encode()),
            Response::Rejected(Rejection::Unauthorized)
        );
        // Expired, and too far ahead.
        let now = served.now();
        for expires in [now - 1, now + 120_001] {
            let stale = create(&operator(), node, expires);
            assert_eq!(
                transport.ask(Kind::CreateAgent, &stale.encode()),
                refused(OperatorRefusal::Expiry { now }),
                "{expires}"
            );
        }
        // A bad signature: signed for another kind.
        let mut forged = create(&operator(), node, later);
        forged.signature = operator()
            .sign(&operator_message(
                &node,
                Kind::Grant,
                &forged.nonce,
                forged.expires_ms,
                &forged.body,
            ))
            .to_bytes();
        assert_eq!(
            transport.ask(Kind::CreateAgent, &forged.encode()),
            Response::Rejected(Rejection::BadSignature)
        );
        // An inner body that is no command.
        let malformed = signed_operated(
            node,
            &operator(),
            Kind::Replace,
            fresh_nonce(),
            later,
            vec![1, 2],
        );
        assert_eq!(
            transport.ask(Kind::Replace, &malformed.encode()),
            Response::Rejected(Rejection::Malformed)
        );
        // Good, then replayed.
        let good = create(&operator(), node, later).encode();
        assert!(matches!(
            transport.ask(Kind::CreateAgent, &good),
            Response::Created(_)
        ));
        assert_eq!(
            transport.ask(Kind::CreateAgent, &good),
            refused(OperatorRefusal::Replayed)
        );
        // A read records no nonce: replayed, it is answered.
        let stats = signed_operated(
            node,
            &operator(),
            Kind::Stats,
            fresh_nonce(),
            later,
            Vec::new(),
        )
        .encode();
        for _ in 0..2 {
            assert!(matches!(
                transport.ask(Kind::Stats, &stats),
                Response::Stats(_)
            ));
        }
    }
}

/// Two copies of one command at once on the multiplexed socket: one runs,
/// the other is a replay.
#[test]
fn two_copies_at_once_run_once() {
    let served = Served::plain();
    let mut stream = connect(&served.socket);
    let create = served.operated(Kind::CreateAgent, Vec::new());
    send(&mut stream, Kind::CreateAgent as u16, 1, &create);
    send(&mut stream, Kind::CreateAgent as u16, 2, &create);
    let mut answers: Vec<Response> = (0..2)
        .map(|_| Response::decode_exact(&receive(&mut stream).unwrap().2).unwrap())
        .collect();
    answers.sort_by_key(|answer| matches!(answer, Response::Created(_)));
    assert_eq!(answers[0], refused(OperatorRefusal::Replayed));
    assert!(matches!(answers[1], Response::Created(_)), "{answers:?}");
}

/// A command that ran is refused after the node restarts: its nonce was
/// synced before it ran.
#[test]
fn a_command_replayed_after_a_restart_is_refused() {
    let programs = vos_checker::programs::Programs::load();
    let dir = tempfile::tempdir().unwrap();
    let config = || {
        let mut config = Config::new(programs.agent.clone());
        config.executors = 2;
        config.operators = vec![operator().verifying_key().to_bytes()];
        config
    };
    let socket = dir.path().join("api.sock");
    let node = Node::open(dir.path(), config()).unwrap();
    node.serve_socket(&socket, 0o600).unwrap();
    let create = signed_operated(
        node.id(),
        &operator(),
        Kind::CreateAgent,
        fresh_nonce(),
        vos_node::wall_clock() + 60_000,
        Vec::new(),
    )
    .encode();
    let mut stream = connect(&socket);
    send(&mut stream, Kind::CreateAgent as u16, 1, &create);
    let (_, _, answer) = receive(&mut stream).unwrap();
    assert!(matches!(
        Response::decode_exact(&answer),
        Some(Response::Created(_))
    ));
    drop(stream);
    drop(node);
    let node = Node::open(dir.path(), config()).unwrap();
    node.serve_socket(&socket, 0o600).unwrap();
    let mut stream = connect(&socket);
    send(&mut stream, Kind::CreateAgent as u16, 1, &create);
    let (_, _, answer) = receive(&mut stream).unwrap();
    assert_eq!(
        Response::decode_exact(&answer),
        Some(refused(OperatorRefusal::Replayed))
    );
}

/// A replayed `Install` is refused before its package is decoded: the node
/// decodes one package, the first copy's.
#[test]
fn a_replayed_install_is_refused_before_its_package_is_decoded() {
    let served = Served::plain();
    let programs = vos_checker::programs::Programs::load();
    let decoded = || {
        served
            .node
            .stats()
            .stages
            .iter()
            .find(|stage| stage.name == "operator_body")
            .map_or(0, |stage| stage.counts.iter().sum::<u64>())
    };
    let agent = served.node.create_agent().unwrap();
    let install = vos_wire::ingress::Install {
        instance: InstanceId(9),
        elf: programs.counter_elf.clone(),
        roles: Vec::new(),
    };
    let request = served.operated(Kind::Install, (agent, install).encode());
    let mut stream = connect(&served.socket);
    let mut ask = || {
        send(&mut stream, Kind::Install as u16, 1, &request);
        Response::decode_exact(&receive(&mut stream).unwrap().2).unwrap()
    };
    let first = ask();
    assert!(!matches!(first, Response::Rejected(_)), "{first:?}");
    assert_eq!(decoded(), 1);
    assert_eq!(ask(), refused(OperatorRefusal::Replayed));
    assert_eq!(decoded(), 1, "the replay's package was not decoded");
}

/// Past the nonces kept, a command is busy; a read still runs.
#[test]
fn past_the_nonces_kept_a_command_is_busy() {
    let served = Served::start_with(Arc::new(vos_node::NoHooks), |config| {
        config.operator_nonces = 1;
    });
    let mut stream = connect(&served.socket);
    let mut ask = |kind: Kind| {
        send(
            &mut stream,
            kind as u16,
            1,
            &served.operated(kind, Vec::new()),
        );
        Response::decode_exact(&receive(&mut stream).unwrap().2).unwrap()
    };
    assert!(matches!(ask(Kind::CreateAgent), Response::Created(_)));
    assert_eq!(ask(Kind::CreateAgent), Response::Busy);
    assert!(matches!(ask(Kind::Stats), Response::Stats(_)));
}

/// The node makes its local operator key at its first start, its public
/// half beside it, and lists it unless told not to.
#[test]
fn the_local_operator_key_is_listed_unless_turned_off() {
    let served = Served::plain();
    let dir = served._dir.path();
    let secret = std::fs::read_to_string(dir.join(vos_node::OPERATOR_KEY)).unwrap();
    let public = std::fs::read_to_string(dir.join(vos_node::OPERATOR_PUB)).unwrap();
    let key = SigningKey::from_bytes(&hex32(&secret));
    assert_eq!(hex::encode(key.verifying_key().to_bytes()), public);
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(dir.join(vos_node::OPERATOR_KEY))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let mut stream = connect(&served.socket);
    let stats = signed_operated(
        served.node.id(),
        &key,
        Kind::Stats,
        fresh_nonce(),
        served.now() + 60_000,
        Vec::new(),
    );
    send(&mut stream, Kind::Stats as u16, 1, &stats.encode());
    let (_, _, answer) = receive(&mut stream).unwrap();
    assert!(matches!(
        Response::decode_exact(&answer),
        Some(Response::Stats(_))
    ));
    let off = Served::start_with(Arc::new(vos_node::NoHooks), |config| {
        config.local_operator = false;
    });
    let secret = std::fs::read_to_string(off._dir.path().join(vos_node::OPERATOR_KEY));
    assert!(secret.is_err(), "no key made");
}

fn hex32(text: &str) -> [u8; 32] {
    hex::decode(text.trim()).unwrap().try_into().unwrap()
}
