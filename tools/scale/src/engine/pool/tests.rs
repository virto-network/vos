
use super::Pool;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};
use vos_node::client::Target;
use vos_wire::Encode;
use vos_wire::ingress::Response;

/// A node stand-in on loopback: every request answered `Busy` after
/// `delay`, its connection kept.
fn stand_in(delay: Duration) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            std::thread::spawn(move || {
                let body = Response::Busy.encode();
                let mut buffer = [0u8; 4096];
                while let Ok(read) = stream.read(&mut buffer) {
                    if read == 0 {
                        return;
                    }
                    std::thread::sleep(delay);
                    let head = format!(
                        "HTTP/1.1 503 Busy\r\nContent-Length: {}\r\n\r\n",
                        body.len()
                    );
                    if stream.write_all(head.as_bytes()).is_err()
                        || stream.write_all(&body).is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    port
}

fn pool(port: u16, cap: usize) -> Pool {
    let target = Target::loopback(&format!("http://127.0.0.1:{port}")).unwrap();
    Pool::new(&target, cap).unwrap()
}

#[test]
fn requests_past_the_cap_wait_for_a_connection_and_reuse_it() {
    let pool = pool(stand_in(Duration::from_millis(50)), 2);
    let answers = smol::block_on(async {
        let posts = (0..6).map(|_| pool.post("/", b"x", Duration::from_secs(5)));
        futures_join(posts.collect()).await
    });
    assert!(answers.iter().all(|answer| *answer == Ok(Response::Busy)));
    // Two opened and kept; four waited, at most two at once in use.
    assert_eq!(pool.counts(), (2, 2));
    let stats = pool.take_stats();
    assert_eq!((stats.waits, stats.in_use_max), (4, 2));
}

#[test]
fn a_dead_node_fails_at_once_and_holds_no_place() {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let pool = pool(port, 4);
    let asked = Instant::now();
    let answer = smol::block_on(pool.post("/", b"x", Duration::from_secs(5)));
    assert!(answer.is_err(), "{answer:?}");
    assert!(asked.elapsed() < Duration::from_secs(2));
    assert_eq!(pool.counts(), (0, 0));
}

#[test]
fn a_request_past_its_deadline_is_reaped_and_its_place_freed() {
    let pool = pool(stand_in(Duration::from_secs(3)), 1);
    let answer = smol::block_on(async {
        let reaper = async {
            loop {
                smol::Timer::after(Duration::from_millis(50)).await;
                pool.reap();
            }
        };
        smol::future::or(pool.post("/", b"x", Duration::from_millis(200)), reaper).await
    });
    assert_eq!(answer, Err("timed out".into()));
    assert_eq!(pool.counts(), (0, 0));
}

/// A node's API over QUIC, as a driver's pool reaches it: one
/// connection, its requests' answers each the node's.
#[test]
fn a_pool_over_quic_reaches_the_nodes_api() {
    use vos_wire::ingress::Rejection;
    let programs = vos_checker::programs::Programs::load();
    let dir = tempfile::tempdir().unwrap();
    let driver = [17u8; 32];
    let node =
        vos_node::Node::open(dir.path(), vos_node::Config::new(programs.agent.clone())).unwrap();
    let listed = ed25519_dalek::SigningKey::from_bytes(&driver)
        .verifying_key()
        .to_bytes();
    let address = node
        .serve_quic("127.0.0.1:0".parse().unwrap(), vec![listed])
        .unwrap();
    let agent = node.create_agent().unwrap();
    let pool = Pool::quic(&format!("quic://{address}"), node.id().0, driver).unwrap();
    let answers = smol::block_on(async {
        pool.warm().await;
        let within = Duration::from_secs(10);
        let malformed = pool
            .post(&format!("/agents/{}/queries", agent.0), b"x", within)
            .await;
        let absent = pool.post("/agents/99/calls", b"x", within).await;
        (malformed, absent)
    });
    assert_eq!(answers.0, Ok(Response::Rejected(Rejection::Malformed)));
    assert_eq!(answers.1, Ok(Response::Rejected(Rejection::Malformed)));
    assert_eq!(pool.take_stats().in_use_max, 1);
    // Another key is refused at the handshake.
    let stranger = Pool::quic(&format!("quic://{address}"), node.id().0, [18; 32]).unwrap();
    let refused = smol::block_on(stranger.post(
        &format!("/agents/{}/queries", agent.0),
        b"x",
        Duration::from_secs(10),
    ));
    assert!(refused.is_err(), "{refused:?}");
}

/// Every future of `futures`, run together on this thread.
async fn futures_join<F: std::future::Future>(futures: Vec<F>) -> Vec<F::Output> {
    let ex = smol::LocalExecutor::new();
    let tasks: Vec<_> = futures.into_iter().map(|future| ex.spawn(future)).collect();
    ex.run(async {
        let mut outputs = Vec::new();
        for task in tasks {
            outputs.push(task.await);
        }
        outputs
    })
    .await
}
