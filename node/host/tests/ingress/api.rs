//! The node API on its unix socket: frames sized from their headers, the
//! frame errors and the close after them, answers out of order, the
//! requests in flight on a connection and the connections at once, the
//! frame deadline, the node's time, and the socket's file.

use std::os::unix::net::UnixStream;
use std::path::Path;

use vos_api::{FRAME_ERROR, FrameError, Framing, Header, Kind, frame};
use vos_node::client::signed_query;

use super::*;

/// A connection to `path`, its reads given up after 30 s.
fn connect(path: &Path) -> UnixStream {
    let stream = UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
}

fn send(stream: &mut UnixStream, kind: u16, id: u64, body: &[u8]) {
    stream
        .write_all(&frame(Framing::Stream, kind, id, body))
        .unwrap();
}

/// The next answer frame's kind, id and body; `None` once the node closed
/// the connection.
fn receive(stream: &mut UnixStream) -> Option<(u16, u64, Vec<u8>)> {
    let mut header = [0u8; 14];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
            ) =>
        {
            return None;
        }
        Err(error) => panic!("{error}"),
    }
    let length = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
    let kind = u16::from_le_bytes(header[4..6].try_into().unwrap());
    let id = u64::from_le_bytes(header[6..].try_into().unwrap());
    let mut body = vec![0u8; length - 10];
    stream.read_exact(&mut body).unwrap();
    Some((kind, id, body))
}

/// The frame error answering `id`, then the connection's close.
fn refused(stream: &mut UnixStream, id: u64) -> FrameError {
    let (kind, answered, body) = receive(stream).expect("a frame error");
    assert_eq!((kind, answered), (FRAME_ERROR, id));
    assert_eq!(receive(stream), None, "the connection closes");
    FrameError::decode_exact(&body).unwrap()
}

/// A query `client` signs that waits for an applied index the agent never
/// reaches: answered `Behind` once the node's floor passes, 5 s.
fn slow_query(served: &Served, client: &Client) -> Vec<u8> {
    let identity = client.identity(served.agent).unwrap();
    let query = signed_query(
        &identity,
        &SigningKey::from_bytes(&[9; 32]),
        served.now() + 10_000,
        Consistency::Applied { at: u64::MAX },
        COUNTER,
        served.value,
        Vec::new(),
    );
    (served.agent, query).encode()
}

#[test]
fn every_kind_past_its_limit_is_refused_from_its_header() {
    let served = Served::plain();
    for kind in Kind::ALL {
        let mut stream = connect(&served.socket);
        let limit = kind.limit();
        let header = Header::of(Framing::Stream, kind as u16, 11, limit as usize + 1);
        // The header alone: the node refuses before any body byte.
        stream.write_all(&header.encode(Framing::Stream)).unwrap();
        assert_eq!(
            refused(&mut stream, 11),
            FrameError::Oversize { limit },
            "{kind:?}"
        );
    }
}

#[test]
fn unknown_kinds_and_truncated_frames_are_refused_and_closed() {
    let served = Served::plain();
    for kind in [0u16, FRAME_ERROR, vos_api::CREDENTIALED, 0x0300] {
        let mut stream = connect(&served.socket);
        send(&mut stream, kind, 3, &[]);
        assert_eq!(
            refused(&mut stream, 3),
            FrameError::UnknownKind,
            "{kind:#06x}"
        );
    }
    // A length short of the header: no id to answer.
    let mut stream = connect(&served.socket);
    stream.write_all(&9u32.to_le_bytes()).unwrap();
    stream
        .write_all(&(Kind::Time as u16).to_le_bytes())
        .unwrap();
    stream.write_all(&[0; 8]).unwrap();
    assert_eq!(refused(&mut stream, 0), FrameError::Truncated);
    // A body cut short, then the write side shut: answered under its id.
    let mut stream = connect(&served.socket);
    let bytes = frame(
        Framing::Stream,
        Kind::AgentInfo as u16,
        5,
        &served.agent.encode(),
    );
    stream.write_all(&bytes[..16]).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(refused(&mut stream, 5), FrameError::Truncated);
}

/// Every kind answers over the socket as over HTTP: the node's key, its
/// time, an agent's record, a schema, a malformed body, an operator's
/// command bare on the socket.
#[test]
fn the_socket_answers_what_http_does() {
    let served = Served::plain();
    let mut stream = connect(&served.socket);
    send(&mut stream, Kind::NodeKey as u16, 1, &[]);
    assert_eq!(
        receive(&mut stream),
        Some((Kind::NodeKey as u16, 1, served.node.id().encode()))
    );
    send(&mut stream, Kind::Time as u16, 2, &[]);
    assert_eq!(
        receive(&mut stream),
        Some((Kind::Time as u16, 2, served.now().encode()))
    );
    send(
        &mut stream,
        Kind::AgentInfo as u16,
        3,
        &served.agent.encode(),
    );
    let (_, _, info) = receive(&mut stream).unwrap();
    let info = Option::<vos_wire::ingress::AgentInfo>::decode_exact(&info).unwrap();
    assert_eq!(info.unwrap().record.agent, served.agent);
    // Three bytes are no agent: none.
    send(&mut stream, Kind::AgentInfo as u16, 4, &[1, 2, 3]);
    assert_eq!(
        receive(&mut stream),
        Some((Kind::AgentInfo as u16, 4, vec![0]))
    );
    send(
        &mut stream,
        Kind::Schema as u16,
        5,
        &(served.agent, COUNTER).encode(),
    );
    let (_, _, schema) = receive(&mut stream).unwrap();
    assert_eq!(schema[0], 1, "an installed schema");
    send(&mut stream, Kind::Call as u16, 6, &served.agent.encode());
    assert_eq!(
        receive(&mut stream),
        Some((
            Kind::Call as u16,
            6,
            Response::Rejected(Rejection::Malformed).encode()
        ))
    );
    send(&mut stream, Kind::CreateAgent as u16, 7, &[]);
    let (_, _, created) = receive(&mut stream).unwrap();
    assert!(matches!(
        Response::decode_exact(&created),
        Some(Response::Created(_))
    ));
    send(&mut stream, Kind::Stats as u16, 8, &[]);
    let (_, _, stats) = receive(&mut stream).unwrap();
    assert!(matches!(
        Response::decode_exact(&stats),
        Some(Response::Stats(_))
    ));
}

/// A slow request does not hold back one sent after it: each is answered
/// when done, by its id.
#[test]
fn answers_come_out_of_order_by_their_ids() {
    let served = Served::plain();
    let client = served.client(1);
    let mut stream = connect(&served.socket);
    send(
        &mut stream,
        Kind::Query as u16,
        1,
        &slow_query(&served, &client),
    );
    send(&mut stream, Kind::Time as u16, 2, &[]);
    let (kind, id, _) = receive(&mut stream).unwrap();
    assert_eq!((kind, id), (Kind::Time as u16, 2));
    let (kind, id, body) = receive(&mut stream).unwrap();
    assert_eq!((kind, id), (Kind::Query as u16, 1));
    assert_eq!(
        Response::decode_exact(&body),
        Some(Response::Rejected(Rejection::Behind))
    );
}

/// Past its requests in flight, a connection's next frame is read only as
/// one ends.
#[test]
fn a_connection_past_its_requests_in_flight_waits() {
    let served = Served::start_with(Arc::new(vos_node::NoHooks), |config| {
        config.api_in_flight = 2;
    });
    let client = served.client(1);
    let mut stream = connect(&served.socket);
    let asked = Instant::now();
    for id in [1, 2] {
        send(
            &mut stream,
            Kind::Query as u16,
            id,
            &slow_query(&served, &client),
        );
    }
    send(&mut stream, Kind::Time as u16, 3, &[]);
    let (kind, _, _) = receive(&mut stream).unwrap();
    assert_eq!(kind, Kind::Query as u16, "a slow one ends first");
    assert!(asked.elapsed() >= Duration::from_secs(4));
    let mut rest: Vec<u64> = (0..2).map(|_| receive(&mut stream).unwrap().1).collect();
    rest.sort_unstable();
    assert!(rest.contains(&3), "{rest:?}");
}

/// Past the connections allowed, one is closed as it is accepted; a frame
/// trickling past its deadline closes its connection.
#[test]
fn connections_and_frames_are_bounded() {
    let served = Served::start_with(Arc::new(vos_node::NoHooks), |config| {
        config.api_connections = 2;
        config.api_frame_deadline = Duration::from_millis(300);
    });
    let mut held: Vec<UnixStream> = (0..2).map(|_| connect(&served.socket)).collect();
    for stream in &mut held {
        send(stream, Kind::Time as u16, 1, &[]);
        assert!(receive(stream).is_some());
    }
    let mut third = connect(&served.socket);
    let _ = third.write_all(&frame(Framing::Stream, Kind::Time as u16, 1, &[]));
    assert_eq!(receive(&mut third), None, "closed on accept");
    drop(held);
    wait_until("a place is free", || {
        let mut stream = connect(&served.socket);
        send(&mut stream, Kind::Time as u16, 1, &[]);
        receive(&mut stream).is_some()
    });
    let mut slow = connect(&served.socket);
    slow.write_all(&frame(Framing::Stream, Kind::Time as u16, 1, &[])[..8])
        .unwrap();
    let started = Instant::now();
    assert_eq!(receive(&mut slow), None, "the deadline closes it");
    assert!(started.elapsed() < Duration::from_secs(10));
}

/// A socket file a node left is replaced by the next; a second node
/// given a socket another serves is refused.
#[test]
fn a_stale_socket_is_replaced_and_a_twin_refused() {
    let served = Served::plain();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("twin.sock");
    served.node.serve_socket(&path, 0o600).unwrap();
    let programs = vos_checker::programs::Programs::load();
    let other_dir = tempfile::tempdir().unwrap();
    let other = Node::open(other_dir.path(), Config::new(programs.agent.clone())).unwrap();
    assert!(other.serve_socket(&path, 0o600).is_err(), "a twin");
    drop(served);
    // The file stays behind, its node gone: the next node replaces it.
    assert!(path.exists());
    other.serve_socket(&path, 0o600).unwrap();
    let mut stream = connect(&path);
    send(&mut stream, Kind::NodeKey as u16, 1, &[]);
    assert_eq!(
        receive(&mut stream),
        Some((Kind::NodeKey as u16, 1, other.id().encode()))
    );
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}
