use super::*;

/// A node that does not answer delays none of the others' requests: its
/// dial holds no lock another request waits on, reads in turn skip it
/// while it is dialed, and the request that had to go to it is answered
/// 503, at once while it is down.
#[test]
fn a_dead_node_delays_no_other_nodes_requests() {
    let served = Served::start(PerAddress::default());
    // A QUIC address where nothing answers: its dial runs to its timeout.
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let dead = SigningKey::from_bytes(&[77; 32]).verifying_key().to_bytes();
    let front = Front::start(
        vec![
            (served.node.id().0, Address::Socket(served.socket.clone())),
            (
                dead,
                Address::Quic(silent.local_addr().unwrap().to_string()),
            ),
        ],
        PerAddress::default(),
    );
    let stats = operated_header(&signed_operated(
        NodeId(dead),
        &SigningKey::from_bytes(&OPERATOR),
        Kind::Stats,
        fresh_nonce(),
        served.now() + 60_000,
        Vec::new(),
    ));
    let address = front.address;
    let to_the_dead = std::thread::spawn(move || {
        let started = std::time::Instant::now();
        let (status, _, _) = exchange(
            address,
            &request("GET", "/stats", &[format!("Authorization: {stats}")], b""),
        );
        (status, started.elapsed())
    });
    // Its dial under way for a while.
    std::thread::sleep(Duration::from_secs(1));
    let reads = |count: usize| {
        let started = std::time::Instant::now();
        let reads: Vec<_> = (0..count)
            .map(|_| {
                std::thread::spawn(move || exchange(address, &request("GET", "/time", &[], b"")).0)
            })
            .collect();
        let statuses: Vec<u16> = reads.into_iter().map(|read| read.join().unwrap()).collect();
        (statuses, started.elapsed())
    };
    let (statuses, took) = reads(8);
    let (status, waited) = to_the_dead.join().unwrap();
    assert_eq!(statuses, vec![200; 8]);
    // Held up behind the dial, begun a second before them, they would take
    // nearly all of it: at least 4 s of the 5 s or more it ran.
    assert!(
        took < waited / 2,
        "while it is dialed: {took:?}, the dial {waited:?}"
    );
    assert_eq!(status, 503);
    assert!(waited >= Duration::from_secs(5), "its dial ran: {waited:?}");
    // Down after its failed dial: its own requests are answered at once.
    let stats = operated_header(&signed_operated(
        NodeId(dead),
        &SigningKey::from_bytes(&OPERATOR),
        Kind::Stats,
        fresh_nonce(),
        served.now() + 60_000,
        Vec::new(),
    ));
    let started = std::time::Instant::now();
    let (status, _, _) = exchange(
        address,
        &request("GET", "/stats", &[format!("Authorization: {stats}")], b""),
    );
    assert_eq!(status, 503);
    // No dial again: well within a dial's 5 s, however long the first ran.
    let again = started.elapsed();
    assert!(
        again < waited.min(Duration::from_secs(5)) / 2,
        "{again:?}, its dial {waited:?}"
    );
    drop(silent);
}
