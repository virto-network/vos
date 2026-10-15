//! Clients' queries at a follower: a method its schema marks linearizable
//! reads after a read index, whatever consistency its client asks.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use vos_checker::calls::{Total, done, signed_query};
use vos_checker::hooks::Gate;
use vos_node::client::{Target, agent_info, post_within};
use vos_wire::ingress::{Consistency, Response};

use crate::common::{COUNTER, Cluster};

/// How long a query may take to be answered.
const QUERY_ANSWERED: Duration = Duration::from_secs(30);

/// A follower whose commits are held answers a query of `value` from the
/// state it applied, before the write its leader answered; a query of
/// `latest`, marked linearizable, only once it applied that write, though
/// its client asked for no floor.
#[test]
fn a_linearizable_method_reads_a_write_its_follower_has_not_applied() {
    let (cluster, gates) = Cluster::with_hooks::<Gate>(3);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    cluster.converged(agent);
    let (leader, follower) = cluster.leader_and_follower(agent);
    let address = cluster
        .node(follower)
        .serve("127.0.0.1:0".parse().unwrap())
        .unwrap();
    let target = Target::loopback(&format!("http://{address}")).unwrap();
    let record = agent_info(&target, agent).unwrap().unwrap().record;
    let identity = vos_node::identity(&record);
    let key = SigningKey::from_bytes(&[13; 32]);
    let path = format!("/agents/{}/queries", agent.0);
    let query = |method: &str| {
        let not_after = vos_node::wall_clock() + 60_000;
        let method = cluster.programs.method(method);
        let floorless = Consistency::Applied { at: 0 };
        signed_query(&identity, &key, not_after, floorless, COUNTER, method)
    };

    let closed = gates[usize::from(follower) - 1].close();
    assert_eq!(done(cluster.increment(leader, agent, 1, 5)), 5);
    let stale = post_within(&target, &path, &query("value"), QUERY_ANSWERED).unwrap();
    assert_eq!(stale.total(), Some(0), "{stale:?}");
    std::thread::scope(|scope| {
        let (answered, read) = std::sync::mpsc::channel();
        let (target, path, latest) = (&target, &path, query("latest"));
        scope.spawn(move || {
            let _ = answered.send(post_within(target, path, &latest, QUERY_ANSWERED));
        });
        std::thread::sleep(Duration::from_millis(300));
        let early: Option<Response> = read.try_recv().ok().map(Result::unwrap);
        drop(closed);
        assert!(
            early.is_none(),
            "read before it applied the write: {early:?}"
        );
        let latest = read.recv().unwrap().unwrap();
        assert_eq!(latest.total(), Some(5), "{latest:?}");
    });
}
