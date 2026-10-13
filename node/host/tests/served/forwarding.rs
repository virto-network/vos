//! Calls and queries over HTTP to a follower, to a node that does not
//! replicate the agent, and to a leader whose clock, refines or commits a
//! test holds: forwarded once and checked first, answered only once
//! applied where they were sent, and read where the write is.

use std::sync::atomic::Ordering;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use vos_checker::calls::{Total, signed_query};
use vos_checker::programs::{actor, method};
use vos_checker::{ANSWERED, ATTEMPT, COUNTER, Nodes, wait_until};
use vos_node::client::{Client, post_within};
use vos_node::store::{Store, View};
use vos_wire::ids::{AgentId, MethodId, Session};
use vos_wire::ingress::{Answer, Call, Consistency, Rejection, call_message};
use vos_wire::peer::NodeNumber;
use vos_wire::records::unstored;
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode, keys};

use crate::harness::{Cluster, NODES, query, session_mark};

/// The hub's seed: these tests lose no frame, so any seed will do.
const SEED: u64 = 1;

/// An agent replicated on `replicas`, running the counter: the agent and
/// its counter's increment and value methods.
fn counter_agent(cluster: &Cluster, replicas: Vec<NodeNumber>) -> (AgentId, MethodId, MethodId) {
    let counter = actor("counter");
    let agent = cluster
        .node(replicas[0])
        .unwrap()
        .create_replicated(replicas)
        .unwrap();
    wait_until("a leader", Duration::from_secs(20), || {
        cluster.leader(agent).is_some()
    });
    let leader = cluster.node(cluster.leader(agent).unwrap()).unwrap();
    let installed = smol::block_on(leader.install(agent, COUNTER, &counter, &[], vec![]));
    assert!(
        matches!(installed, Ok(vos_node::Reply::Ran(Outcome::Done(_)))),
        "{installed:?}"
    );
    (
        agent,
        method(&counter, "increment"),
        method(&counter, "value"),
    )
}

/// A signed call: `by` added in `session`, at `sequence`.
fn signed_call(
    identity: &[u8; 32],
    key: &SigningKey,
    session: Session,
    sequence: u64,
    increment: MethodId,
    by: u64,
) -> Vec<u8> {
    let arguments = by.encode();
    let message = call_message(identity, &session, sequence, COUNTER, increment, &arguments);
    Call {
        session,
        sequence,
        instance: COUNTER,
        method: increment,
        arguments,
        signature: key.sign(&message).to_bytes(),
    }
    .encode()
}

/// A signed query of the counter's value, by `key`.
fn value_query(
    identity: &[u8; 32],
    key: &SigningKey,
    value: MethodId,
    consistency: Consistency,
) -> Vec<u8> {
    let not_after = vos_node::wall_clock() + 60_000;
    signed_query(identity, key, not_after, consistency, COUNTER, value)
}

/// A follower forwards a call to the leader, and answers it once it has
/// applied it itself; the client goes on calling the follower.
#[test]
fn a_follower_forwards_a_call_and_answers_once_it_applied_it() {
    let cluster = Cluster::new(SEED);
    let (agent, increment, _) = counter_agent(&cluster, vec![1, 2, 3]);
    let leader = cluster.leader(agent).unwrap();
    let follower = leader % NODES + 1;
    let mut client = Client::new(cluster.target(follower), SigningKey::from_bytes(&[7; 32]));
    for (sequence, (by, total)) in [(5u64, 5u64), (2, 7)].into_iter().enumerate() {
        let answer = client
            .call(agent, COUNTER, increment, &by.encode())
            .unwrap();
        assert_eq!(answer.total(), Some(total), "{answer:?}");
        let session = client.session(agent);
        let node = cluster.node(follower).unwrap();
        assert!(
            session_mark(&node, agent, &session).is_some_and(|mark| mark > sequence as u64),
            "answered before the follower applied it"
        );
    }
    assert_eq!(
        vos_node::client::node_id(client.target()).unwrap().0,
        cluster.space.node(follower).unwrap().key,
        "the client still calls the follower"
    );
}

/// A follower checks a call's signature before it forwards the call: the
/// leader runs forwarded calls without checking them again.
#[test]
fn a_follower_forwards_no_call_it_cannot_verify() {
    let cluster = Cluster::new(SEED);
    let (agent, increment, value) = counter_agent(&cluster, vec![1, 2, 3]);
    let leader = cluster.leader(agent).unwrap();
    let follower = leader % NODES + 1;
    let client = Client::new(cluster.target(follower), SigningKey::from_bytes(&[9; 32]));
    let body = client
        .call_body(agent, 1, COUNTER, increment, &5u64.encode())
        .unwrap();
    let mut call = Call::decode(&body).unwrap().0;
    call.arguments = 6u64.encode();
    let path = format!("/agents/{}/calls", agent.0);
    let answer = post_within(cluster.target(follower), &path, &call.encode(), ATTEMPT);
    assert!(
        matches!(answer, Ok(Answer::Rejected(Rejection::BadSignature))),
        "{answer:?}"
    );
    std::thread::sleep(Duration::from_millis(200));
    let node = cluster.node(leader).unwrap();
    assert_eq!(
        query(&node, agent, COUNTER, value),
        Ok(Outcome::Done(0u64.encode())),
        "it never ran"
    );
}

/// A node that does not replicate the agent names its replicas, and the
/// client calls one of them from then on.
#[test]
fn a_client_follows_elsewhere_to_a_replica() {
    let cluster = Cluster::new(SEED);
    let (agent, increment, _) = counter_agent(&cluster, vec![1, 2]);
    let mut client = Client::new(cluster.target(3), SigningKey::from_bytes(&[10; 32]));
    let answer = client
        .call(agent, COUNTER, increment, &4u64.encode())
        .unwrap();
    assert_eq!(answer.total(), Some(4), "{answer:?}");
    let now = vos_node::client::node_id(client.target()).unwrap().0;
    assert!(
        [1, 2]
            .iter()
            .any(|number| cluster.space.node(*number).unwrap().key == now),
        "the client calls a replica now"
    );
}

/// A leader whose clock trails the agent's time, as one does after a
/// leader with a clock ahead, times its batches at the agent's time and
/// goes on leading: the agent's time never goes back.
#[test]
fn a_leader_whose_clock_trails_times_its_batches_at_the_agents() {
    let cluster = Cluster::new(SEED);
    let (agent, increment, _) = counter_agent(&cluster, vec![1, 2, 3]);
    let leader = cluster.leader(agent).unwrap();
    let mut client = Client::new(cluster.target(leader), SigningKey::from_bytes(&[8; 32]));
    let batch_time = || {
        let node = cluster.node(leader).unwrap();
        let bytes = node
            .store()
            .snapshot()
            .get(agent, &keys::batch_time())
            .unwrap()
            .unwrap();
        u64::decode(unstored(&bytes).unwrap()).unwrap().0
    };
    let offset = &cluster.slot(leader).offset;
    offset.store(30_000, Ordering::SeqCst);
    let answer = client
        .call(agent, COUNTER, increment, &1u64.encode())
        .unwrap();
    assert_eq!(answer.total(), Some(1), "{answer:?}");
    let ahead = batch_time();
    assert!(
        ahead >= vos_node::wall_clock() + 20_000,
        "timed by the clock ahead"
    );
    // The clock comes back: it trails the agent's time by more than the
    // bound.
    offset.store(0, Ordering::SeqCst);
    let answer = client
        .call(agent, COUNTER, increment, &2u64.encode())
        .unwrap();
    assert_eq!(answer.total(), Some(3), "{answer:?}");
    assert_eq!(cluster.leader(agent), Some(leader), "it goes on leading");
    assert!(batch_time() >= ahead, "the agent's time went back");
}

/// A resend of a new session's first call, while the first is queued,
/// joins it even once the session's time is past the skew: the first was
/// timed when its batch formed, and refusing the resend `StaleSession`
/// would have the client run it again in a new session.
#[test]
fn a_resend_of_a_queued_first_call_joins_it_past_the_skew() {
    let cluster = Cluster::new(SEED);
    let (agent, increment, value) = counter_agent(&cluster, vec![1, 2, 3]);
    let leader = cluster.leader(agent).unwrap();
    let identity = cluster.identity(leader, agent);
    let key = SigningKey::from_bytes(&[11; 32]);
    let session = Session {
        key: key.verifying_key().to_bytes(),
        name: [11; 16],
        t0: vos_node::wall_clock() - (vos_wire::defaults::SESSION_SKEW_MS - 1_500),
    };
    let body = signed_call(&identity, &key, session, 1, increment, 5);
    let path = format!("/agents/{}/calls", agent.0);
    let target = cluster.target(leader);
    let refines = &cluster.slot(leader).trip.refines;
    let reached = refines.reached();
    std::thread::scope(|scope| {
        // Inside the scope: a failure opens it before the scope waits.
        let closed = refines.close();
        let first = scope.spawn(|| post_within(target, &path, &body, ANSWERED));
        wait_until("the first is refined", Duration::from_secs(10), || {
            refines.reached() > reached
        });
        // Past the skew now.
        std::thread::sleep(Duration::from_millis(2_000));
        let second = scope.spawn(|| post_within(target, &path, &body, ANSWERED));
        std::thread::sleep(Duration::from_millis(300));
        drop(closed);
        for answer in [first.join().unwrap(), second.join().unwrap()] {
            let answer = answer.unwrap();
            assert_eq!(answer.total(), Some(5), "{answer:?}");
        }
    });
    let node = cluster.node(leader).unwrap();
    assert_eq!(
        query(&node, agent, COUNTER, value),
        Ok(Outcome::Done(5u64.encode())),
        "ran once"
    );
}

/// A follower answers a forwarded call only once it has applied it: while
/// its commits are held, the leader has run the call and the client waits.
#[test]
fn a_follower_holding_back_its_apply_holds_back_its_answer() {
    let cluster = Cluster::new(SEED);
    let (agent, increment, value) = counter_agent(&cluster, vec![1, 2, 3]);
    let leader = cluster.leader(agent).unwrap();
    let follower = leader % NODES + 1;
    let mut client = Client::new(cluster.target(follower), SigningKey::from_bytes(&[12; 32]));
    client.identity(agent).unwrap();
    let commits = &cluster.slot(follower).trip.commits;
    std::thread::scope(|scope| {
        let closed = commits.close();
        let (answered, answer) = std::sync::mpsc::channel();
        scope.spawn(move || {
            let _ = answered.send(client.call(agent, COUNTER, increment, &3u64.encode()));
        });
        let node = cluster.node(leader).unwrap();
        wait_until("the leader runs it", Duration::from_secs(10), || {
            query(&node, agent, COUNTER, value) == Ok(Outcome::Done(3u64.encode()))
        });
        std::thread::sleep(Duration::from_millis(300));
        let early = answer.try_recv();
        drop(closed);
        assert!(early.is_err(), "answered before the follower applied it");
        let answer = answer.recv().unwrap().unwrap();
        assert_eq!(answer.total(), Some(3), "{answer:?}");
    });
}

/// A follower reads a write it has not applied yet only once it has: at
/// the floor the write's answer gave, and by read index.
#[test]
fn a_follower_reads_a_write_once_it_has_applied_it() {
    let cluster = Cluster::new(SEED);
    let (agent, increment, value) = counter_agent(&cluster, vec![1, 2, 3]);
    let leader = cluster.leader(agent).unwrap();
    let follower = leader % NODES + 1;
    let identity = cluster.identity(leader, agent);
    let key = SigningKey::from_bytes(&[13; 32]);
    let path = format!("/agents/{}/queries", agent.0);
    let commits = &cluster.slot(follower).trip.commits;
    let session = Session {
        key: key.verifying_key().to_bytes(),
        name: [13; 16],
        t0: vos_node::wall_clock(),
    };
    for (sequence, consistency) in [(1, None), (2, Some(Consistency::Linearizable))] {
        std::thread::scope(|scope| {
            let closed = commits.close();
            let call = signed_call(&identity, &key, session, sequence, increment, 4);
            let calls = format!("/agents/{}/calls", agent.0);
            let answer = post_within(cluster.target(leader), &calls, &call, ANSWERED).unwrap();
            let Answer::Ran { at, .. } = answer else {
                panic!("{answer:?}")
            };
            let consistency = consistency.unwrap_or(Consistency::Applied { at });
            let query = value_query(&identity, &key, value, consistency);
            let (answered, read) = std::sync::mpsc::channel();
            let (path, target) = (&path, cluster.target(follower));
            scope.spawn(move || {
                let _ = answered.send(post_within(target, path, &query, ANSWERED));
            });
            std::thread::sleep(Duration::from_millis(300));
            let early = read.try_recv();
            drop(closed);
            assert!(
                early.is_err(),
                "read before the follower applied it: {early:?}"
            );
            let answer = read.recv().unwrap().unwrap();
            assert_eq!(
                answer.total(),
                Some(4 * sequence),
                "{consistency:?}: {answer:?}"
            );
        });
    }
}

/// A leader cut off from its followers answers no linearizable read: it
/// cannot confirm it still leads.
#[test]
fn a_leader_cut_off_answers_no_linearizable_read() {
    let cluster = Cluster::new(SEED);
    let (agent, _, value) = counter_agent(&cluster, vec![1, 2, 3]);
    let leader = cluster.leader(agent).unwrap();
    let identity = cluster.identity(leader, agent);
    let key = SigningKey::from_bytes(&[14; 32]);
    let path = format!("/agents/{}/queries", agent.0);
    cluster.hub.isolate(leader);
    let answer = post_within(
        cluster.target(leader),
        &path,
        &value_query(&identity, &key, value, Consistency::Linearizable),
        ANSWERED,
    );
    cluster.hub.heal();
    assert!(
        !matches!(answer, Ok(Answer::Ran { .. })),
        "a cut-off leader answered: {answer:?}"
    );
}

/// A replica that has not applied through a query's floor in time answers
/// `Behind`, and the client's query goes on to another replica.
#[test]
fn a_query_a_replica_is_behind_for_goes_to_another() {
    let cluster = Cluster::new(SEED);
    let (agent, increment, value) = counter_agent(&cluster, vec![1, 2, 3]);
    let leader = cluster.leader(agent).unwrap();
    let follower = leader % NODES + 1;
    let key = SigningKey::from_bytes(&[15; 32]);
    let mut client = Client::new(cluster.target(leader), key.clone());
    let identity = client.identity(agent).unwrap();
    let commits = &cluster.slot(follower).trip.commits;
    std::thread::scope(|_| {
        let _closed = commits.close();
        let answer = client
            .call(agent, COUNTER, increment, &6u64.encode())
            .unwrap();
        let Answer::Ran { at, .. } = answer else {
            panic!("{answer:?}")
        };
        let path = format!("/agents/{}/queries", agent.0);
        let query = value_query(&identity, &key, value, Consistency::Applied { at });
        let answer = post_within(cluster.target(follower), &path, &query, ANSWERED);
        assert!(
            matches!(answer, Ok(Answer::Rejected(Rejection::Behind))),
            "{answer:?}"
        );
        let reader = Client::new(cluster.target(follower), key.clone());
        reader.raise_floor(agent, at);
        let answer = reader
            .query(agent, COUNTER, value, &[], vos_node::wall_clock() + 60_000)
            .unwrap();
        assert_eq!(answer.total(), Some(6), "{answer:?}");
    });
}
