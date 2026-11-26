//! What a node holds against peers that run code of their own: a key it
//! does not configure, or a configured key used against it.

mod common;

use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::*;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer, UnixTime,
};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use vnet::quic::{Quic, Runner, Runtime};
use vnet::{Arrivals, Class, NodeKey, public_key};

fn endpoint(server: Option<quinn::ServerConfig>) -> quinn::Endpoint {
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        server,
        UdpSocket::bind(any_port()).unwrap(),
        Arc::new(quinn::SmolRuntime),
    )
    .unwrap()
}

/// A client of the peers' protocol holding `secret`, dialing `node`.
fn other_client(secret: [u8; 32], node: NodeKey) -> quinn::ClientConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.send_window(64 << 20);
    vnet::quic::client_config(&secret, ALPN, node, Arc::new(transport))
}

/// A connection to `node` holding node 2's key.
async fn dial_as_2(node: &Quic) -> (quinn::Endpoint, quinn::Connection) {
    let client = endpoint(None);
    let connection = client
        .connect_with(
            other_client(secret(2), node.key()),
            node.local_addr(),
            "other",
        )
        .unwrap()
        .await
        .unwrap();
    (client, connection)
}

fn header(class: Class, id: u64) -> [u8; 9] {
    let mut header = [0u8; 9];
    header[0] = class;
    header[1..].copy_from_slice(&id.to_be_bytes());
    header
}

/// Takes any raw key that signs its handshake.
#[derive(Debug)]
struct AnyKey(Arc<rustls::crypto::CryptoProvider>);

impl ClientCertVerifier for AnyKey {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _: &CertificateDer,
        _: &[CertificateDer],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("no TLS 1.2".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        key: &CertificateDer,
        signed: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(key.as_ref()),
            signed,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// An accepting side of the peers' protocol holding `secret`, with code of
/// its own: it may open streams toward whoever dials it.
fn other_server(secret: [u8; 32]) -> quinn::Endpoint {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let signer = provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vnet::pkcs8(
            &secret,
        ))))
        .unwrap();
    let certified = Arc::new(rustls::sign::CertifiedKey::new(
        vec![CertificateDer::from(vnet::spki(&public_key(&secret)))],
        signer,
    ));
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(Arc::new(AnyKey(provider)))
        .with_cert_resolver(Arc::new(
            rustls::server::AlwaysResolvesServerRawPublicKeys::new(certified),
        ));
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.send_window(256 << 20);
    server.transport_config(Arc::new(transport));
    endpoint(Some(server))
}

/// A node only writes on the connections it dials: the dialed side is
/// granted no stream there, so it can make the dialer buffer nothing.
#[test]
fn a_dialed_peer_is_granted_no_streams() {
    smol::block_on(async {
        let (a, _a_arrivals) = bind(1);
        let other = other_server(secret(2));
        a.set_peers(vec![peer_at(2, other.local_addr().unwrap())]);
        send(&a, key(2), CONSENSUS, 1, b"hello".to_vec()).await;
        let connection = other.accept().await.unwrap().await.unwrap();
        let opened = within(Duration::from_millis(500), connection.open_uni()).await;
        assert!(
            opened.is_none(),
            "the dialed side opened a stream toward the dialer"
        );
    });
}

/// One key, one inbound connection: a later one replaces the earlier, so
/// what a connection may hold is what a peer may hold.
#[test]
fn a_peer_holds_one_inbound_connection() {
    smol::block_on(async {
        let (a, a_arrivals, _) = node_1();
        let mut held = Vec::new();
        for _ in 0..8 {
            let (client, connection) = dial_as_2(&a).await;
            let mut stream = connection.open_uni().await.unwrap();
            stream.write_all(&header(CONSENSUS, 1)).await.unwrap();
            stream.write_all(&2u32.to_be_bytes()).await.unwrap();
            stream.write_all(b"hi").await.unwrap();
            assert_eq!(next(a_arrivals.queue(CONSENSUS)).await.frame, b"hi");
            held.push((client, connection, stream));
        }
        // The earlier seven close as the later ones are taken.
        let started = Instant::now();
        while held[..7]
            .iter()
            .any(|(_, connection, _)| connection.close_reason().is_none())
            && started.elapsed() < Duration::from_secs(10)
        {
            smol::Timer::after(Duration::from_millis(10)).await;
        }
        smol::Timer::after(Duration::from_millis(100)).await;
        let open: Vec<bool> = held
            .iter()
            .map(|(_, connection, _)| connection.close_reason().is_none())
            .collect();
        assert_eq!(
            open,
            [false, false, false, false, false, false, false, true],
            "connections one key holds open"
        );
    });
}

/// A stream that opens with a class the table does not hold is stopped,
/// and the connection's other streams are read on.
#[test]
fn a_stream_of_a_class_past_the_table_is_stopped() {
    smol::block_on(async {
        let (a, a_arrivals, _) = node_1();
        let (_client, connection) = dial_as_2(&a).await;
        let mut unknown = connection.open_uni().await.unwrap();
        unknown
            .write_all(&header(ALL.len() as Class, 1))
            .await
            .unwrap();
        unknown.write_all(&2u32.to_be_bytes()).await.unwrap();
        unknown.write_all(b"no").await.unwrap();
        let stopped = within(Duration::from_secs(5), unknown.stopped()).await;
        assert!(
            matches!(stopped, Some(Ok(Some(_)))),
            "the stream was not stopped: {stopped:?}"
        );
        let mut known = connection.open_uni().await.unwrap();
        known.write_all(&header(CONSENSUS, 1)).await.unwrap();
        known.write_all(&3u32.to_be_bytes()).await.unwrap();
        known.write_all(b"yes").await.unwrap();
        assert_eq!(next(a_arrivals.queue(CONSENSUS)).await.frame, b"yes");
        assert!(silent(&a_arrivals, Duration::from_millis(200)).await);
    });
}

/// Frames a peer began and never finished: what one peer may have the
/// node assemble at once is a few of its class's largest frames, not a
/// frame per stream it may open.
#[test]
fn unfinished_frames_from_one_peer_are_bounded() {
    smol::block_on(async {
        let (a, a_arrivals, _) = node_1();
        let (_client, connection) = dial_as_2(&a).await;
        let limit = MAX_FRAME[usize::from(CONSENSUS)];
        const STREAMS: u64 = 12;
        let taken = Arc::new(AtomicUsize::new(0));
        let mut writers = Vec::new();
        for id in 0..STREAMS {
            let mut stream = connection.open_uni().await.unwrap();
            let taken = Arc::clone(&taken);
            writers.push(smol::spawn(async move {
                stream.write_all(&header(CONSENSUS, id)).await.unwrap();
                stream
                    .write_all(&u32::try_from(limit).unwrap().to_be_bytes())
                    .await
                    .unwrap();
                // All of the frame but its last byte, which never comes.
                // The write ends once the node took all but a stream
                // window of it.
                let body = vec![0u8; limit - 1];
                if within(Duration::from_secs(5), stream.write_all(&body))
                    .await
                    .is_some_and(|wrote| wrote.is_ok())
                {
                    taken.fetch_add(body.len(), Ordering::Relaxed);
                }
                stream
            }));
        }
        let mut held = Vec::new();
        for writer in writers {
            held.push(writer.await);
        }
        let taken = taken.load(Ordering::Relaxed);
        println!(
            "the node took {} MiB of unfinished frames on {STREAMS} streams",
            taken >> 20
        );
        assert!(silent(&a_arrivals, Duration::from_millis(200)).await);
        assert!(
            taken <= 4 * limit,
            "{} MiB of unfinished frames assembled for one peer",
            taken >> 20
        );
    });
}

/// Frames waiting for a consumer that takes none: their class's queue is
/// bounded in bytes, not only in frames.
#[test]
fn an_arrival_queue_is_bounded_in_bytes() {
    smol::block_on(async {
        let nodes = Arc::new(cluster(2));
        let limit = MAX_FRAME[usize::from(REQUESTS)];
        // Sixteen of the largest frames, each on an id of its own: the
        // sender waits as the receiver pushes back.
        let sending = smol::spawn({
            let nodes = Arc::clone(&nodes);
            async move {
                for id in 0..16 {
                    send(&nodes[0].0, key(2), REQUESTS, id, vec![7; limit]).await;
                }
            }
        });
        let b_arrivals = &nodes[1].1;
        smol::Timer::after(Duration::from_millis(1000)).await;
        let waiting = b_arrivals.queue(REQUESTS).len();
        assert!(
            waiting <= 5,
            "{waiting} of the largest frames wait for the consumer"
        );
        // They are delivered all the same, as the consumer takes them.
        for _ in 0..16 {
            assert_eq!(next(b_arrivals.queue(REQUESTS)).await.frame.len(), limit);
        }
        sending.await;
    });
}

/// A full arrival queue of one class holds none of another.
#[test]
fn a_full_queue_of_one_class_does_not_hold_another() {
    smol::block_on(async {
        let nodes = cluster(2);
        let (a, _) = &nodes[0];
        let (_, b_arrivals) = &nodes[1];
        for i in 0..1500u32 {
            send(
                a,
                key(2),
                REQUESTS,
                u64::from(i % 8),
                i.to_be_bytes().to_vec(),
            )
            .await;
        }
        let started = Instant::now();
        while !b_arrivals.queue(REQUESTS).is_full() {
            assert!(started.elapsed() < Duration::from_secs(30), "never full");
            smol::Timer::after(Duration::from_millis(10)).await;
        }
        send(a, key(2), CONSENSUS, 1, b"consensus".to_vec()).await;
        send(a, key(2), LIVENESS, 1, b"alive".to_vec()).await;
        let started = Instant::now();
        assert_eq!(next(b_arrivals.queue(CONSENSUS)).await.frame, b"consensus");
        assert_eq!(next(b_arrivals.queue(LIVENESS)).await.frame, b"alive");
        assert!(started.elapsed() < Duration::from_secs(5));
    });
}

/// How long a consensus frame takes from `a` to node 2, `samples` times,
/// sorted.
async fn latencies(a: &Quic, arrivals: &Arrivals, samples: usize) -> Vec<Duration> {
    let mut taken = Vec::new();
    for i in 0..samples {
        let sent = Instant::now();
        send(a, key(2), CONSENSUS, 1, (i as u32).to_be_bytes().to_vec()).await;
        next(arrivals.queue(CONSENSUS)).await;
        taken.push(sent.elapsed());
        smol::Timer::after(Duration::from_millis(5)).await;
    }
    taken.sort();
    taken
}

/// Keys that are not configured keep dialing a node from an address no
/// peer has (127.0.0.2, on Linux's loopback): the node runs few of their
/// handshakes, and its peers' frames flow on.
#[test]
fn strangers_take_few_handshakes() {
    let nodes = cluster(2);
    let (a, _) = &nodes[0];
    let (b, b_arrivals) = &nodes[1];
    let stop = Arc::new(AtomicBool::new(false));
    // Dials that reached the node's side of a handshake, and dials it
    // refused before one.
    let (shaken, refused) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let (address, key) = (b.local_addr(), b.key());
    let strangers: Vec<_> = (0..2u8)
        .map(|thread| {
            let (stop, shaken, refused) =
                (Arc::clone(&stop), Arc::clone(&shaken), Arc::clone(&refused));
            std::thread::spawn(move || {
                let runner = Runner::start().unwrap();
                let endpoint = quinn::Endpoint::new(
                    quinn::EndpointConfig::default(),
                    None,
                    UdpSocket::bind("127.0.0.2:0").unwrap(),
                    Arc::new(Runtime(runner.spawner())),
                )
                .unwrap();
                let config = other_client([100 + thread; 32], key);
                let dials: Vec<_> = (0..64)
                    .map(|_| {
                        let (endpoint, config) = (endpoint.clone(), config.clone());
                        let (stop, shaken, refused) =
                            (Arc::clone(&stop), Arc::clone(&shaken), Arc::clone(&refused));
                        runner
                            .spawner()
                            .spawn(async move {
                                while !stop.load(Ordering::Relaxed) {
                                    let Ok(connecting) =
                                        endpoint.connect_with(config.clone(), address, "stranger")
                                    else {
                                        return;
                                    };
                                    let dialed = within(Duration::from_millis(500), connecting);
                                    match dialed.await {
                                        Some(Err(quinn::ConnectionError::ConnectionClosed(
                                            close,
                                        ))) if close.error_code
                                            == quinn::TransportErrorCode::CONNECTION_REFUSED =>
                                        {
                                            refused.fetch_add(1, Ordering::Relaxed);
                                            smol::Timer::after(Duration::from_millis(5)).await;
                                        }
                                        // Unanswered in time: not a handshake run.
                                        None => {}
                                        _ => {
                                            shaken.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }
                            })
                            .unwrap()
                    })
                    .collect();
                smol::block_on(async {
                    for dial in dials {
                        dial.await;
                    }
                });
            })
        })
        .collect();
    std::thread::sleep(Duration::from_millis(500));
    let before = shaken.load(Ordering::Relaxed);
    let started = Instant::now();
    let loud = smol::block_on(latencies(a, b_arrivals, 200));
    let elapsed = started.elapsed();
    let during = shaken.load(Ordering::Relaxed) - before;
    stop.store(true, Ordering::Relaxed);
    for stranger in strangers {
        stranger.join().unwrap();
    }
    println!(
        "{during} handshakes in {elapsed:?}, {} refused in all; a peer's frames: p50 {:?}, p99 {:?}",
        refused.load(Ordering::Relaxed),
        percentile(&loud, 50),
        percentile(&loud, 99),
    );
    // One address's places, eight, each kept a second after a failed
    // handshake.
    let bound = 8 * (elapsed.as_secs() as usize + 2);
    assert!(
        during <= bound,
        "{during} strangers' handshakes in {elapsed:?}, past {bound}"
    );
    assert!(
        percentile(&loud, 99) < Duration::from_secs(1),
        "strangers' handshakes delayed a peer's frames"
    );
}

/// A peer removed from the table loses its inbound connection at once,
/// with whatever it had begun to send.
#[test]
fn a_removed_peer_s_inbound_connection_closes() {
    smol::block_on(async {
        let (a, a_arrivals, _) = node_1();
        let (_client, connection) = dial_as_2(&a).await;
        let mut stream = connection.open_uni().await.unwrap();
        stream.write_all(&header(CONSENSUS, 1)).await.unwrap();
        stream.write_all(&(4u32 << 20).to_be_bytes()).await.unwrap();
        stream.write_all(&vec![0u8; 2 << 20]).await.unwrap();
        a.set_peers(Vec::new());
        let closed = within(Duration::from_secs(5), connection.closed()).await;
        assert!(
            closed.is_some(),
            "a removed peer's inbound connection stays open"
        );
        assert!(silent(&a_arrivals, Duration::from_millis(200)).await);
    });
}

/// A peer that takes each dial and closes it at once is dialed again only
/// after a wait.
#[test]
fn a_peer_that_closes_at_once_is_dialed_with_backoff() {
    smol::block_on(async {
        let (a, _a_arrivals) = bind(1);
        let other = other_server(secret(2));
        a.set_peers(vec![peer_at(2, other.local_addr().unwrap())]);
        let closing = smol::spawn({
            let other = other.clone();
            async move {
                let mut taken = 0u32;
                while let Some(incoming) = other.accept().await {
                    if let Ok(connection) = incoming.await {
                        taken += 1;
                        connection.close(quinn::VarInt::from_u32(0), b"");
                    }
                }
                taken
            }
        });
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(2) {
            let _ = vnet::Network::send(&a, key(2), CONSENSUS, 1, b"frame".to_vec());
            smol::Timer::after(Duration::from_micros(200)).await;
        }
        other.close(quinn::VarInt::from_u32(0), b"");
        let taken = closing.await;
        // Backing off from 50 ms, doubling up to 1 s: seven in 2 s.
        assert!(
            taken <= 10,
            "{taken} handshakes in 2 s with a peer that closes at once"
        );
    });
}
