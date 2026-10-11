//! Faults a test build injects into node processes through their faults
//! files: a stalled disk hands a leader's groups over, a failing one halts
//! its node until a restart, and a gray failure, its Raft frames lost while
//! its pair heartbeat flows, deposes a leader.
//!
//! Built with `--features faults` only.

#![cfg(feature = "faults")]

mod support;

use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use support::{Options, Processes, converged, counter_agent, increment, method, wait_until};
use vos_node::client::Client;
use vos_wire::ids::InstanceId;

const COUNTER: InstanceId = InstanceId(1);

/// A leader whose commits are held hands over, and the calls go on at
/// another: a call made at the stalled leader is answered within its
/// deadline, and sent again. Let go, its replica catches up.
#[test]
fn a_leader_whose_disk_stalls_hands_its_group_over() {
    let space = Processes::start(3, Options::default());
    let agent = counter_agent(&space, COUNTER);
    let stalled = space.leader(agent);
    let mut client = Client::new(&space.target(stalled), SigningKey::from_bytes(&[32; 32]));
    let add = method(&mut client, agent, COUNTER, "increment");
    assert_eq!(increment(&mut client, agent, COUNTER, add, 1), 1);
    space.set_faults(stalled, "hold_commits\n");
    let started = Instant::now();
    assert_eq!(increment(&mut client, agent, COUNTER, add, 2), 3);
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "a call at a stalled leader waited {:?}",
        started.elapsed()
    );
    wait_until("another node leads", || {
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
    let mut space = Processes::start(3, Options::default());
    let agent = counter_agent(&space, COUNTER);
    let failing = space.leader(agent);
    let other = (1..=3).find(|number| *number != failing).unwrap();
    let mut client = Client::new(&space.target(other), SigningKey::from_bytes(&[34; 32]));
    let add = method(&mut client, agent, COUNTER, "increment");
    assert_eq!(increment(&mut client, agent, COUNTER, add, 1), 1);
    space.set_faults(failing, "fail_commits after\n");
    assert_eq!(increment(&mut client, agent, COUNTER, add, 2), 3);
    wait_until("the failing node halts", || {
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
    let space = Processes::start(3, Options::default());
    let agent = counter_agent(&space, COUNTER);
    let mut client = Client::new(&space.target(1), SigningKey::from_bytes(&[33; 32]));
    let add = method(&mut client, agent, COUNTER, "increment");
    assert_eq!(increment(&mut client, agent, COUNTER, add, 1), 1);
    let gray = space.leader(agent);
    space.set_faults(gray, "drop consensus 1000000\n");
    let at_fault = space.status(gray, agent).expect("the gray replica");
    assert!(at_fault.leads, "it led when its frames began to be lost");
    assert_eq!(increment(&mut client, agent, COUNTER, add, 2), 3);
    wait_until("another node leads, at a later term", || {
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
