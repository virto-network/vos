use super::{Routes, agents, closes_after_load, unserved};
use std::time::{Duration, Instant};
use vos_wire::ingress::Response;

/// A leader that fails is left for the next replica up; queries skip a
/// follower that failed until its backoff ends.
#[test]
fn a_dead_node_loses_its_routes_for_a_while() {
    let replicas = [0, 2, 3];
    let mut routes = Routes {
        leaders: vec![2],
        down: vec![None; 4],
    };
    let now = Instant::now();
    assert!(unserved(&Err("connection refused".into())));
    assert!(unserved(&Ok(Response::NotLeader { leader: None })));
    assert!(!unserved(&Ok(Response::Busy)));
    routes.failed(0, &replicas, 2, now);
    assert_eq!(routes.call(0), 3);
    // Queries go to the followers up, the new leader excepted.
    for user in 0..4 {
        assert_eq!(routes.query(0, &replicas, user, now), 0);
    }
    routes.failed(0, &replicas, 0, now);
    assert_eq!(routes.query(0, &replicas, 1, now), 3, "none up: the leader");
    let later = now + Duration::from_secs(3);
    assert_eq!(routes.query(0, &replicas, 1, later), [0, 2][1]);
    // The leader failing too: its place goes on, to a node up first.
    routes.failed(0, &replicas, 3, later);
    assert_eq!(routes.call(0), 0);
}

/// A read at a cut left open is an error while the load runs, and is
/// left out once its window closes after the load's last send.
#[test]
fn a_window_closing_after_the_load_is_not_an_error() {
    assert!(!closes_after_load(5_000, None), "the load still running");
    assert!(!closes_after_load(5_000, Some(5_000)));
    assert!(!closes_after_load(5_000, Some(9_000)), "closed in the run");
    assert!(closes_after_load(9_000, Some(5_000)));
}
/// The agents are read from a node's API over QUIC, as the driver key
/// the node lists.
#[test]
fn agents_are_read_over_the_api() {
    use crate::agents::Placed;
    let programs = vos_checker::programs::Programs::load();
    let dir = tempfile::tempdir().unwrap();
    let node =
        vos_node::Node::open(dir.path(), vos_node::Config::new(programs.agent.clone())).unwrap();
    let driver = [17u8; 32];
    let listed = ed25519_dalek::SigningKey::from_bytes(&driver)
        .verifying_key()
        .to_bytes();
    let address = node
        .serve_quic("127.0.0.1:0".parse().unwrap(), vec![listed])
        .unwrap();
    let placed: Vec<Placed> = (0..64)
        .map(|_| Placed {
            agent: node.create_agent().unwrap().0,
            replicas: vec![1],
            actor: "idle".into(),
            instance: 1,
            leader: None,
        })
        .collect();
    let target =
        vos_node::client::Target::quic(&format!("quic://{address}"), node.id().0, driver).unwrap();
    let refs: Vec<&Placed> = placed.iter().collect();
    let read = agents(&refs, &[target]).unwrap();
    assert_eq!(read.len(), 64);
    assert!(
        read.iter()
            .zip(&placed)
            .all(|(agent, placed)| agent.id.0 == placed.agent)
    );
}
