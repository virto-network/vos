//! The node API over QUIC: the client's key and protocol checked at the
//! handshake, one request a stream, frames sized from their headers,
//! operator kinds refused before signed requests, the connections at
//! once and the frame deadline.

use std::net::UdpSocket;

use vos_api::{FRAME_ERROR, FrameError, Framing, Header, Kind};

use super::*;

/// A gateway's key, which the node lists.
const GATEWAY: [u8; 32] = [21; 32];

/// A node serving its API over QUIC to [`GATEWAY`]: the node, and its
/// API's address.
fn quic_served(configure: impl FnOnce(&mut Config)) -> (Served, SocketAddr) {
    let served = Served::start_with(Arc::new(vos_node::NoHooks), configure);
    let gateway = ed25519_dalek::SigningKey::from_bytes(&GATEWAY)
        .verifying_key()
        .to_bytes();
    let address = served
        .node
        .serve_quic("127.0.0.1:0".parse().unwrap(), vec![gateway])
        .unwrap();
    (served, address)
}

fn endpoint() -> quinn::Endpoint {
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        UdpSocket::bind("127.0.0.1:0").unwrap(),
        Arc::new(quinn::SmolRuntime),
    )
    .unwrap()
}

/// A connection by the client whose seed is `secret`, speaking `alpn`.
fn dial(
    served: &Served,
    address: SocketAddr,
    secret: [u8; 32],
    alpn: &[u8],
) -> Result<quinn::Connection, String> {
    let config = vos_net::api::client_config_for(
        &secret,
        alpn,
        served.node.id().0,
        Arc::new(quinn::TransportConfig::default()),
    );
    let endpoint = endpoint();
    smol::block_on(async {
        let connecting = endpoint
            .connect_with(config, address, "node")
            .map_err(|error| error.to_string())?;
        let connection = connecting.await.map_err(|error| error.to_string())?;
        // A refused key shows once the server's verdict arrives: a
        // stream's round trip waits for it.
        vos_api::quic::request(&connection, Kind::NodeKey as u16, &[])
            .await
            .map_err(|error| error.to_string())?;
        Ok(connection)
    })
}

fn ask(connection: &quinn::Connection, kind: u16, body: &[u8]) -> (u16, Vec<u8>) {
    smol::block_on(vos_api::quic::request(connection, kind, body)).unwrap()
}

#[test]
fn an_unlisted_key_or_another_protocol_is_refused_at_the_handshake() {
    let (served, address) = quic_served(|_| {});
    assert!(dial(&served, address, [22; 32], vos_net::api::ALPN).is_err());
    assert!(dial(&served, address, GATEWAY, b"vos/1").is_err());
    let connection = dial(&served, address, GATEWAY, vos_net::api::ALPN).unwrap();
    assert_eq!(
        ask(&connection, Kind::NodeKey as u16, &[]),
        (Kind::NodeKey as u16, served.node.id().encode())
    );
    assert_eq!(
        ask(&connection, Kind::Time as u16, &[]),
        (Kind::Time as u16, served.now().encode())
    );
    let (_, info) = ask(&connection, Kind::AgentInfo as u16, &served.agent.encode());
    assert_eq!(info[0], 1, "the agent's record");
}

#[test]
fn operator_kinds_over_quic_are_refused_before_signed_requests() {
    let (served, address) = quic_served(|_| {});
    let connection = dial(&served, address, GATEWAY, vos_net::api::ALPN).unwrap();
    for kind in Kind::ALL.into_iter().filter(|kind| kind.operator()) {
        let (answered, body) = ask(&connection, kind as u16, &[]);
        assert_eq!(answered, kind as u16);
        assert_eq!(
            Response::decode_exact(&body),
            Some(Response::Rejected(Rejection::Operator(
                vos_wire::ingress::OperatorRefusal::SocketOnly
            ))),
            "{kind:?}"
        );
    }
}

#[test]
fn frames_over_quic_are_sized_from_their_headers() {
    let (served, address) = quic_served(|_| {});
    let connection = dial(&served, address, GATEWAY, vos_net::api::ALPN).unwrap();
    for kind in Kind::ALL {
        let limit = kind.limit();
        let answer = smol::block_on(async {
            let (mut send, mut receive) = connection.open_bi().await.unwrap();
            let header = Header::of(Framing::Quic, kind as u16, 0, limit as usize + 1);
            send.write_all(&header.encode(Framing::Quic)).await.unwrap();
            receive.read_to_end(1 << 10).await.unwrap()
        });
        assert_eq!(&answer[4..6], &FRAME_ERROR.to_le_bytes(), "{kind:?}");
        assert_eq!(
            FrameError::decode_exact(&answer[6..]),
            Some(FrameError::Oversize { limit })
        );
    }
    let (kind, body) = ask(&connection, 0x0300, &[]);
    assert_eq!(kind, FRAME_ERROR);
    assert_eq!(
        FrameError::decode_exact(&body),
        Some(FrameError::UnknownKind)
    );
    // A body cut short: the stream finished early is truncated.
    let answer = smol::block_on(async {
        let (mut send, mut receive) = connection.open_bi().await.unwrap();
        let header = Header::of(Framing::Quic, Kind::AgentInfo as u16, 0, 4);
        send.write_all(&header.encode(Framing::Quic)).await.unwrap();
        send.write_all(&[1]).await.unwrap();
        send.finish().unwrap();
        receive.read_to_end(1 << 10).await.unwrap()
    });
    assert_eq!(
        FrameError::decode_exact(&answer[6..]),
        Some(FrameError::Truncated)
    );
}

#[test]
fn quic_connections_and_frames_are_bounded() {
    let (served, address) = quic_served(|config| {
        config.api_connections = 1;
        config.api_frame_deadline = Duration::from_millis(300);
    });
    let first = dial(&served, address, GATEWAY, vos_net::api::ALPN).unwrap();
    assert!(
        dial(&served, address, GATEWAY, vos_net::api::ALPN).is_err(),
        "one connection at once"
    );
    // A frame part sent, never finished: past its deadline the node resets
    // the stream unanswered.
    let read = smol::block_on(async {
        let (mut send, mut receive) = first.open_bi().await.unwrap();
        send.write_all(&[2, 0, 0]).await.unwrap();
        receive.read_to_end(1 << 10).await
    });
    assert!(read.is_err(), "{read:?}");
    first.close(quinn::VarInt::from_u32(0), b"");
    wait_until("the place is given back", || {
        dial(&served, address, GATEWAY, vos_net::api::ALPN).is_ok()
    });
}
