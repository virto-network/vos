//! Node processes, each a `vos node run`, joined through the test's relay
//! over QUIC:
//! - a leader the relay cuts off from the others is replaced, its calls go
//!   on, and it catches up once the cut heals;
//! - three processes as one space take calls through any of them and send
//!   messages to another agent, through the leader's SIGKILL and its
//!   restart, every call applied once;
//! - a workflow awaiting another agent completes once through its leader's
//!   SIGKILL and a partition;
//! - built with `--features faults`, the faults of `mod faults`, which a
//!   test build injects.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use vos_checker::calls::{Total, signed_query};
use vos_checker::processes::{
    Options, PROCESS_WAIT, Processes, call, converged, counter_agent, increment, served_method,
};
use vos_checker::programs::package;
use vos_checker::wait_until;
use vos_checker::workflows::{ASKED, ROUNDS, Rounds, TOLD, Tour};
use vos_node::client::Client;
use vos_wire::ids::{AgentId, InstanceId};
use vos_wire::ingress::{Consistency, Response, WorkflowStatus};
use vos_wire::records::unstored;
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode, keys};

const COUNTER: InstanceId = InstanceId(1);
/// The counter instance the other agent's messages increment.
const INBOX: InstanceId = InstanceId(2);

/// Three nodes, in the clear.
fn start() -> Processes {
    Processes::start(env!("CARGO_BIN_EXE_vos"), 3, Options::default())
}

#[test]
fn a_leader_cut_off_by_the_relay_is_replaced_and_catches_up() {
    let space = start();
    let agent = counter_agent(&space, COUNTER);
    let mut client = Client::new(space.target(1), SigningKey::from_bytes(&[31; 32]));
    let add = served_method(&mut client, agent, COUNTER, "increment");
    let mut total = 0;
    for by in 1..=5 {
        total += by;
        assert_eq!(increment(&mut client, agent, COUNTER, add, by), total);
    }
    let cut = space.leader(agent);
    space.relay.isolate(cut, 3);
    wait_until("another node leads", PROCESS_WAIT, || {
        (1..=3).filter(|number| *number != cut).any(|number| {
            space
                .status(number, agent)
                .is_some_and(|status| status.leads)
        })
    });
    for by in 6..=10 {
        total += by;
        assert_eq!(increment(&mut client, agent, COUNTER, add, by), total);
    }
    space.relay.heal();
    converged(&space, agent);
    let status = space.status(cut, agent).expect("the cut node's replica");
    assert!(!status.leads, "the cut leader stepped down");
    assert_eq!(
        space.relay.own_drops(),
        0,
        "the relay lost nothing of itself"
    );
    assert!(space.troubles().is_empty(), "{:?}", space.troubles());
}

#[test]
fn three_processes_apply_every_call_once_through_a_kill() {
    let space = start();
    let counter = package("counter");
    let create = || space.agent_with(vec![1, 2, 3], &counter, &[INBOX, COUNTER]);
    let (sender, receiver) = (create(), create());
    let mut client = Client::new(space.target(1), SigningKey::from_bytes(&[21; 32]));
    let schema = client.schema(sender, COUNTER).unwrap().unwrap();
    let (increment, forward, value) = (
        schema.method_id("increment").unwrap(),
        schema.method_id("forward").unwrap(),
        schema.method_id("value").unwrap(),
    );
    let (mut total, mut forwarded) = (0, 0);
    // One node down at a time, so a quorum stays.
    let mut down = None;
    for request in 1..=60u64 {
        match request {
            // Right after a forward was answered, its message may still
            // be unacknowledged: the sender's leader is killed, then the
            // receiver's.
            21 => down = Some(space.leader(sender)),
            41 => down = Some(space.leader(receiver)),
            31 | 51 => {
                space.restart(down.take().expect("a node down"));
            }
            _ => {}
        }
        if let Some(number) = down.filter(|number| space.is_running(*number)) {
            space.kill(number);
        }
        if request.is_multiple_of(4) {
            let by = request * 10;
            let arguments = (receiver.0, INBOX.0, by).encode();
            assert_eq!(call(&mut client, sender, COUNTER, forward, &arguments), by);
            forwarded += by;
        } else {
            total += request;
            assert_eq!(
                call(&mut client, sender, COUNTER, increment, &request.encode()),
                total
            );
        }
    }
    // Every node holds every call once, and every message once: read at
    // each node itself, which a failover to another would hide.
    let key = SigningKey::from_bytes(&[23; 32]);
    let identities = [
        (sender, client.identity(sender).unwrap()),
        (receiver, client.identity(receiver).unwrap()),
    ];
    for number in 1..=3 {
        let read = |agent: AgentId, instance: InstanceId| {
            let identity = identities
                .iter()
                .find(|(id, _)| *id == agent)
                .map(|(_, identity)| *identity)
                .unwrap();
            let query = signed_query(
                &identity,
                &key,
                vos_node::wall_clock() + 60_000,
                Consistency::Linearizable,
                instance,
                value,
            );
            let path = format!("/agents/{}/queries", agent.0);
            let (_, body) = vos_node::client::post(space.target(number), &path, &query).ok()?;
            let (answer, _) = Response::decode(&body).ok()?;
            answer.total()
        };
        wait_until("every node converges", PROCESS_WAIT, || {
            read(sender, COUNTER) == Some(total) && read(receiver, INBOX) == Some(forwarded)
        });
    }
    // Each forward's message applied once at each replica, and was sent
    // once: their pair's marks, on disk, once the nodes stopped.
    let forwards = (1..=60u64)
        .filter(|request| request.is_multiple_of(4))
        .count() as u64;
    for store in space.stop_all() {
        let mark = |agent: AgentId, key: &[u8]| {
            let bytes = store.snapshot().get(agent, key).unwrap().unwrap();
            u64::decode(unstored(&bytes).unwrap()).unwrap().0
        };
        assert_eq!(mark(receiver, &keys::pair_in(sender)), forwards);
        assert_eq!(mark(sender, &keys::pair_out(receiver)), forwards);
    }
}

/// A workflow awaiting another agent's counter, the other agent's quorum
/// cut off by a partition, loses its leader while it awaits: once the
/// partition heals, a new leader resumes it from its snapshot, and it
/// completes as a straight run, its owner reading the result by its id.
/// Every effect applied once: the counters it asked and told, its own
/// count, and its pair's messages and replies, on every replica.
#[test]
fn a_workflow_mid_await_completes_once_through_a_kill_and_a_partition() {
    let space = start();
    let rounds = Rounds::load();
    let methods = rounds.methods;
    let touring = space.agent_installing(vec![1, 2, 3], &[rounds.install(ROUNDS)]);
    // The agent it asks lives on the two nodes its leader does not.
    let leader = space.leader(touring);
    let asked_on: Vec<usize> = (1..=3).filter(|number| *number != leader).collect();
    let asked = space.agent_installing(
        asked_on.iter().map(|number| *number as u8).collect(),
        &[rounds.install(ASKED), rounds.install(TOLD)],
    );
    // One of its nodes cut off: it holds no quorum, and the tour's first
    // round awaits.
    let (cut, other) = (asked_on[0], asked_on[1]);
    space.relay.isolate(cut, 3);
    let mut client = Client::new(space.target(other), SigningKey::from_bytes(&[41; 32]));
    let tour = Tour {
        other: asked,
        amounts: vec![2, 3, 4],
        nap: 0,
        words: 64,
        passes: 4,
    };
    let started = client
        .call(touring, ROUNDS, methods.tour, &tour.arguments())
        .unwrap();
    let Response::Ran {
        outcome: Outcome::Started(workflow),
        ..
    } = started
    else {
        panic!("{started:?}")
    };
    wait_until("the tour awaits the cut off agent", PROCESS_WAIT, || {
        matches!(
            client.workflow(touring, workflow, Duration::ZERO),
            Ok(Response::Workflow {
                status: WorkflowStatus::Awaiting { agent, .. },
                ..
            }) if agent == asked
        )
    });
    // Its leader killed mid-await: the tour's agent too is left without a
    // quorum until the partition heals.
    space.kill(leader);
    std::thread::sleep(Duration::from_secs(1));
    space.relay.heal();
    space.restart(leader);
    let mut ended = None;
    wait_until("the tour ends", PROCESS_WAIT, || {
        ended = match client.workflow(touring, workflow, Duration::from_secs(5)) {
            Ok(Response::Workflow {
                status: WorkflowStatus::Ended(outcome),
                ..
            }) => Some(outcome),
            _ => None,
        };
        ended.is_some()
    });
    assert_eq!(ended, Some(Outcome::Done(tour.result(0))));

    // Read at each replica itself, which a failover to another would hide.
    let key = SigningKey::from_bytes(&[43; 32]);
    let identities = [
        (touring, client.identity(touring).unwrap()),
        (asked, client.identity(asked).unwrap()),
    ];
    let read = |number: usize, agent: AgentId, instance: InstanceId| {
        let identity = identities.iter().find(|(id, _)| *id == agent).unwrap().1;
        let query = signed_query(
            &identity,
            &key,
            vos_node::wall_clock() + 60_000,
            Consistency::Linearizable,
            instance,
            methods.tallies,
        );
        let path = format!("/agents/{}/queries", agent.0);
        let (_, body) = vos_node::client::post(space.target(number), &path, &query).ok()?;
        match Response::decode(&body).ok()?.0 {
            Response::Ran {
                outcome: Outcome::Done(tallies),
                ..
            } => <Vec<(u64, u64)>>::decode(&tallies)
                .ok()
                .map(|(tallies, _)| tallies),
            _ => None,
        }
    };
    // Each amount tallied once, here and by request and message there.
    let mut once: Vec<(u64, u64)> = tour.amounts.iter().map(|amount| (*amount, 1)).collect();
    once.sort_unstable();
    let tallied = |number, agent, instance| {
        read(number, agent, instance).map(|mut tallies| {
            tallies.sort_unstable();
            tallies
        }) == Some(once.clone())
    };
    for number in 1..=3 {
        wait_until(
            "every replica holds the tour's effects",
            PROCESS_WAIT,
            || {
                tallied(number, touring, ROUNDS)
                    && (number == leader
                        || tallied(number, asked, ASKED) && tallied(number, asked, TOLD))
            },
        );
    }
    // Each round's request and message sent once and applied once, and
    // each request answered once: the pairs' marks, on disk.
    let rounds = tour.amounts.len() as u64;
    for (number, store) in (1..=3).zip(space.stop_all()) {
        let mark = |agent: AgentId, key: &[u8]| {
            let bytes = store.snapshot().get(agent, key).unwrap().unwrap();
            u64::decode(unstored(&bytes).unwrap()).unwrap().0
        };
        assert_eq!(mark(touring, &keys::pair_out(asked)), 2 * rounds);
        assert_eq!(mark(touring, &keys::pair_in(asked)), rounds);
        if number != leader {
            assert_eq!(mark(asked, &keys::pair_in(touring)), 2 * rounds);
            assert_eq!(mark(asked, &keys::pair_out(touring)), rounds);
        }
    }
}

/// Faults a test build injects into node processes through their faults
/// files: a stalled disk hands a leader's groups over, a failing one halts
/// its node until a restart, and a gray failure, its Raft frames lost while
/// its pair heartbeat flows, deposes a leader.
#[cfg(feature = "faults")]
mod faults {
    use std::time::Instant;

    use super::*;

    /// A leader whose commits are held hands over, and the calls go on at
    /// another: a call made at the stalled leader is answered within its
    /// deadline, and sent again. Let go, its replica catches up.
    #[test]
    fn a_leader_whose_disk_stalls_hands_its_group_over() {
        let space = start();
        let agent = counter_agent(&space, COUNTER);
        let stalled = space.leader(agent);
        let mut client = Client::new(space.target(stalled), SigningKey::from_bytes(&[32; 32]));
        let add = served_method(&mut client, agent, COUNTER, "increment");
        assert_eq!(increment(&mut client, agent, COUNTER, add, 1), 1);
        space.set_faults(stalled, "hold_commits\n");
        let started = Instant::now();
        assert_eq!(increment(&mut client, agent, COUNTER, add, 2), 3);
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "a call at a stalled leader waited {:?}",
            started.elapsed()
        );
        wait_until("another node leads", PROCESS_WAIT, || {
            (1..=3).filter(|number| *number != stalled).any(|number| {
                space
                    .status(number, agent)
                    .is_some_and(|status| status.leads)
            })
        });
        space.set_faults(stalled, "");
        assert_eq!(increment(&mut client, agent, COUNTER, add, 3), 6);
        converged(&space, agent);
    }

    /// A leader whose syncs fail, its batches written but not synced, halts
    /// and says so, its status and its log; the others go on, and once
    /// restarted it catches up.
    #[test]
    fn a_leader_whose_disk_fails_halts_and_a_restart_recovers() {
        let space = start();
        let agent = counter_agent(&space, COUNTER);
        let failing = space.leader(agent);
        let other = (1..=3).find(|number| *number != failing).unwrap();
        let mut client = Client::new(space.target(other), SigningKey::from_bytes(&[34; 32]));
        let add = served_method(&mut client, agent, COUNTER, "increment");
        assert_eq!(increment(&mut client, agent, COUNTER, add, 1), 1);
        space.set_faults(failing, "fail_commits after\n");
        assert_eq!(increment(&mut client, agent, COUNTER, add, 2), 3);
        wait_until("the failing node halts", PROCESS_WAIT, || {
            space
                .status(failing, agent)
                .is_some_and(|status| status.halted)
        });
        let troubles = space.troubles();
        assert!(
            troubles
                .iter()
                .any(|line| line.starts_with(&format!("node {failing}:"))),
            "its log says it halted"
        );
        assert!(
            troubles
                .iter()
                .all(|line| line.starts_with(&format!("node {failing}:"))),
            "{troubles:?}"
        );
        space.kill(failing);
        space.restart(failing);
        assert_eq!(increment(&mut client, agent, COUNTER, add, 3), 6);
        converged(&space, agent);
    }

    /// A leader whose Raft frames are lost, its node alive and heard, steps
    /// down once its followers stop answering, and another serves.
    #[test]
    fn a_gray_failure_deposes_its_leader() {
        let space = start();
        let agent = counter_agent(&space, COUNTER);
        let mut client = Client::new(space.target(1), SigningKey::from_bytes(&[33; 32]));
        let add = served_method(&mut client, agent, COUNTER, "increment");
        assert_eq!(increment(&mut client, agent, COUNTER, add, 1), 1);
        let gray = space.leader(agent);
        space.set_faults(gray, "drop consensus 1000000\n");
        let at_fault = space.status(gray, agent).expect("the gray replica");
        assert!(at_fault.leads, "it led when its frames began to be lost");
        assert_eq!(increment(&mut client, agent, COUNTER, add, 2), 3);
        wait_until("another node leads, at a later term", PROCESS_WAIT, || {
            (1..=3).filter(|number| *number != gray).any(|number| {
                space
                    .status(number, agent)
                    .is_some_and(|status| status.leads && status.term > at_fault.term)
            })
        });
        assert!(
            !space.status(gray, agent).is_some_and(|status| status.leads),
            "the gray leader stepped down"
        );
        space.set_faults(gray, "");
        converged(&space, agent);
        assert!(space.troubles().is_empty(), "{:?}", space.troubles());
    }
}
