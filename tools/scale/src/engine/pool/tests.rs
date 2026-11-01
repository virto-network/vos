use super::Pool;
use std::time::Duration;
use vos_api::Kind;
use vos_wire::ids::AgentId;
use vos_wire::ingress::{Rejection, Response};

/// A node's API over QUIC, as a driver's pool reaches it: one
/// connection, its requests' answers each the node's.
#[test]
fn a_pool_over_quic_reaches_the_nodes_api() {
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
    let within = Duration::from_secs(10);
    let answers = smol::block_on(async {
        pool.warm().await;
        let malformed = pool.post(Kind::Query, agent, b"x", within).await;
        let absent = pool.post(Kind::Call, AgentId(99), b"x", within).await;
        (malformed, absent)
    });
    assert_eq!(answers.0, Ok(Response::Rejected(Rejection::Malformed)));
    assert_eq!(answers.1, Ok(Response::Rejected(Rejection::Malformed)));
    assert_eq!(pool.take_stats().in_use_max, 1);
    // Another key is refused at the handshake.
    let stranger = Pool::quic(&format!("quic://{address}"), node.id().0, [18; 32]).unwrap();
    let refused = smol::block_on(stranger.post(Kind::Query, agent, b"x", within));
    assert!(refused.is_err(), "{refused:?}");
}
