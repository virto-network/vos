use super::*;

/// Past its burst an address is answered 429, before any node is asked.
#[test]
fn an_address_past_its_burst_is_answered_429() {
    let served = Served::start(PerAddress {
        connections: 64,
        rate: 1,
        burst: 3,
    });
    let statuses: Vec<u16> = (0..5)
        .map(|_| exchange(served.front.address, &request("GET", "/time", &[], b"")).0)
        .collect();
    assert_eq!(&statuses[..3], &[200, 200, 200]);
    assert_eq!(statuses[4], 429);
    // Decided from the head: an install-size body is never waited for.
    let header = served.header(Kind::Install, served.agent.encode());
    assert_eq!(install_head(&served, &header).0, 429);
}

/// The head of an install as large as an install may be, its body unsent:
/// the answer, if one comes before the body is asked for.
fn install_head(served: &Served, authorization: &str) -> (u16, Vec<u8>, Vec<u8>) {
    exchange(
        served.front.address,
        install_request(served, authorization).as_bytes(),
    )
}

fn install_request(served: &Served, authorization: &str) -> String {
    format!(
        "POST /agents/{}/install HTTP/1.1\r\nHost: node\r\nAuthorization: {authorization}\r\nContent-Length: {}\r\n\r\n",
        served.agent.0,
        vos_wire::abi::cap::MAX_ELF
    )
}

/// At most four install-size bodies are held at once: a fifth is answered
/// 503 from its head. An operator's route without an envelope, or with one
/// signed for a node behind no upstream, is answered from its head as the
/// whole request would be, and holds none of the four. No node is asked.
#[test]
fn install_size_bodies_are_bounded_and_refused_from_their_heads() {
    let served = Served::start(PerAddress::default());
    let before = served.node.api_frames();
    let held: Vec<TcpStream> = (0..vos_http::LARGE)
        .map(|_| {
            let mut stream = TcpStream::connect(served.front.address).unwrap();
            let header = served.header(Kind::Install, served.agent.encode());
            stream
                .write_all(install_request(&served, &header).as_bytes())
                .unwrap();
            stream
        })
        .collect();
    // The four heads are read, and their places taken, before the fifth's.
    std::thread::sleep(Duration::from_millis(500));
    let header = served.header(Kind::Install, served.agent.encode());
    let (status, body, _) = install_head(&served, &header);
    assert_eq!((status, body), (503, Vec::new()));
    let unauthorized = Response::Rejected(Rejection::Unauthorized).encode();
    assert_eq!(
        install_head(&served, "Bearer 00").0,
        401,
        "no envelope: refused before the budget"
    );
    let (status, body, _) = exchange(
        served.front.address,
        format!(
            "POST /agents/{}/install HTTP/1.1\r\nHost: node\r\nContent-Length: {}\r\n\r\n",
            served.agent.0,
            vos_wire::abi::cap::MAX_ELF
        )
        .as_bytes(),
    );
    assert_eq!((status, body), (401, unauthorized));
    let elsewhere = operated_header(&signed_operated(
        NodeId([3; 32]),
        &SigningKey::from_bytes(&OPERATOR),
        Kind::Install,
        fresh_nonce(),
        served.now() + 60_000,
        served.agent.encode(),
    ));
    let (status, body, _) = install_head(&served, &elsewhere);
    assert_eq!(
        (status, Response::decode_exact(&body)),
        (
            421,
            Some(Response::Rejected(Rejection::Operator(
                OperatorRefusal::OtherNode
            )))
        )
    );
    assert_eq!(served.node.api_frames(), before, "no node asked");
    // A place given back is taken again.
    drop(held);
    std::thread::sleep(Duration::from_millis(500));
    let mut stream = TcpStream::connect(served.front.address).unwrap();
    stream
        .write_all(install_request(&served, &header).as_bytes())
        .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut answer = [0u8; 1];
    let waited = stream.read(&mut answer);
    assert!(
        waited.is_err(),
        "the body is waited for, not refused: {waited:?}"
    );
}

/// A body past its route's limit is refused 413 by the gateway: no frame
/// reaches the node. The node's time comes through the gateway as the
/// node's clock reads.
#[test]
fn a_refusal_for_size_never_reaches_the_node() {
    let served = Served::start(PerAddress::default());
    let before = served.node.api_frames();
    let path = format!("/agents/{}/install", served.agent.0);
    let header = format!(
        "POST {path} HTTP/1.1\r\nHost: node\r\nContent-Length: {}\r\n\r\n",
        vos_wire::abi::cap::MAX_ELF + vos_api::ENVELOPE + 1
    );
    assert_eq!(exchange(served.front.address, header.as_bytes()).0, 413);
    assert_eq!(served.node.api_frames(), before);
    let (status, body, _) = exchange(served.front.address, &request("GET", "/time", &[], b""));
    assert_eq!(status, 200);
    assert_eq!(u64::decode_exact(&body), Some(served.now()));
    assert_eq!(served.node.api_frames(), before + 1);
}
