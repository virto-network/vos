//! Leaders on nodes in one process, vouched for by the pair heartbeat:
//! quiet groups sending nothing else and waiting on no timer, electing
//! again when their leader's node stops, halts or stalls, a lossy link
//! moving no term, and a stalled leader answering within its deadline.

use std::sync::Arc;
use std::time::{Duration, Instant};

use vos_checker::calls::{Ran, done};
use vos_checker::hooks::{FailNextSync, Gate};
use vos_node::CallError;
use vos_wire::ids::AgentId;
use vos_wire::peer::NodeNumber;

use crate::common::{COUNTER, Cluster, wait_until};

/// `count` agents on nodes 1 to 3, each with a leader.
fn agents(cluster: &Cluster, count: usize) -> Vec<AgentId> {
    let agents: Vec<AgentId> = (0..count)
        .map(|_| cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap())
        .collect();
    for &agent in &agents {
        cluster.leader(agent);
    }
    agents
}

/// Each agent's term, as the highest any running replica holds.
fn terms(cluster: &Cluster, agents: &[AgentId]) -> Vec<u64> {
    agents
        .iter()
        .map(|&agent| {
            cluster
                .running()
                .map(|(_, node)| node.store().raft(agent).unwrap().hard.term)
                .max()
                .unwrap()
        })
        .collect()
}

/// A flush that fails where no group's log write meets it still halts the
/// node: its store takes no more, it falls silent, and a group it led
/// while idle elects a leader elsewhere.
#[test]
fn a_flush_failing_outside_any_log_halts_the_node() {
    let (cluster, hooks) = Cluster::with_hooks::<FailNextSync>(3);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let leader = cluster.leader(agent);
    hooks[usize::from(leader) - 1].arm();
    assert!(
        cluster.node(leader).create_agent().is_err(),
        "the record's flush failed"
    );
    wait_until("another node leads", || {
        cluster
            .running()
            .any(|(number, node)| number != leader && node.leads(agent))
    });
    assert!(
        cluster.node(leader).create_agent().is_err(),
        "its store takes no more"
    );
}

/// Groups at rest send each other nothing: the pair heartbeat vouches for
/// their leaders. A call to one goes through at once.
#[test]
fn idle_groups_send_nothing_but_the_pair_heartbeat() {
    let cluster = Cluster::new(3);
    let agents = agents(&cluster, 100);
    cluster.install(agents[0]);
    let at = |cluster: &Cluster| {
        (
            cluster.hub.sent(vos_net::Class::Consensus),
            cluster.hub.sent(vos_net::Class::Liveness),
        )
    };
    // Settled once a stretch of several election timeouts passes quietly.
    let mut quiet = false;
    for _ in 0..20 {
        let before = at(&cluster);
        std::thread::sleep(Duration::from_millis(500));
        let after = at(&cluster);
        assert!(after.1 > before.1, "pair heartbeats go on");
        if after.0 == before.0 {
            quiet = true;
            break;
        }
    }
    assert!(quiet, "the groups never went quiet");
    let terms_before = terms(&cluster, &agents);
    assert_eq!(done(cluster.increment_at_leader(agents[0], 1, 4)), 4);
    assert_eq!(terms(&cluster, &agents), terms_before);
}

/// Idle groups go quiet: every replica, leader and follower, waits on no
/// timer of its own, the pair heartbeat standing in. A call wakes its
/// group and goes through at once, no term moving, and the group goes
/// quiet again.
#[test]
fn idle_groups_wait_on_no_timer_of_their_own() {
    let cluster = Cluster::new(3);
    let agents = agents(&cluster, 30);
    cluster.install(agents[0]);
    let all_quiet = |cluster: &Cluster| {
        cluster.running().all(|(_, node)| {
            let groups = node.stats().groups;
            groups.quiet == groups.replicas
        })
    };
    wait_until("every replica is quiet", || all_quiet(&cluster));
    let terms_before = terms(&cluster, &agents);
    assert_eq!(done(cluster.increment_at_leader(agents[0], 1, 3)), 3);
    assert_eq!(terms(&cluster, &agents), terms_before);
    wait_until("every replica is quiet again", || all_quiet(&cluster));
}

/// The node leading many quiet groups stops: each group elects another
/// leader, as fast as an election timeout after its last pair heartbeat
/// allows.
#[test]
fn quiet_groups_elect_again_when_their_leaders_node_stops() {
    let mut cluster = Cluster::new(3);
    let agents = agents(&cluster, 60);
    let mut led = [0usize; 4];
    for &agent in &agents {
        led[usize::from(cluster.leader(agent))] += 1;
    }
    let gone = (1..=3).max_by_key(|&number| led[number]).unwrap() as NodeNumber;
    std::thread::sleep(Duration::from_millis(300));
    let stopped = Instant::now();
    cluster.stop(gone);
    for &agent in &agents {
        cluster.leader(agent);
    }
    let took = stopped.elapsed();
    eprintln!(
        "{} groups led by node {gone} elected again within {took:?}",
        led[usize::from(gone)]
    );
    // A few elections of one to two seconds, on a loaded host too.
    assert!(took < Duration::from_secs(10), "{took:?}");
    // Back, its new run is heard, and every group goes quiet again with
    // no term moving.
    cluster.start(gone);
    let mut quiet = false;
    for _ in 0..20 {
        let before = terms(&cluster, &agents);
        let sent = cluster.hub.sent(vos_net::Class::Consensus);
        std::thread::sleep(Duration::from_millis(500));
        if cluster.hub.sent(vos_net::Class::Consensus) == sent {
            assert_eq!(terms(&cluster, &agents), before);
            quiet = true;
            break;
        }
    }
    assert!(quiet, "the groups never went quiet again");
}

/// A follower node restarted while its groups are quiet, nothing written
/// meanwhile, hears its leaders at once: each probes it on hearing its
/// new run, rather than waiting for its own deadline to draw a heartbeat.
/// That deadline is twenty seconds or more, far from what a loaded machine
/// adds to the probes; its leaders' are a second or more.
#[test]
fn a_restarted_follower_hears_its_quiet_leaders_at_once() {
    let follower = 3;
    let elections = (20_000, 40_000);
    let mut cluster = Cluster::tuned(3, move |number, config| {
        config.election_timeout_ms = if number == follower {
            elections
        } else {
            (1_000, 2_000)
        };
    });
    let agents = agents(&cluster, 12);
    let followed: Vec<AgentId> = agents
        .iter()
        .copied()
        .filter(|&agent| cluster.leader(agent) != follower)
        .collect();
    std::thread::sleep(Duration::from_millis(500));
    cluster.stop(follower);
    std::thread::sleep(Duration::from_millis(200));
    // Timed from before the restart: its groups' deadlines start within.
    let started = Instant::now();
    cluster.start(follower);
    for &agent in &followed {
        let reply = cluster.increment(follower, agent, 1, 1);
        assert!(
            matches!(reply, Err(CallError::NotLeader(Some(_)))),
            "{reply:?}"
        );
    }
    let took = started.elapsed();
    eprintln!(
        "{} groups heard their leaders within {took:?}",
        followed.len()
    );
    assert!(took < Duration::from_millis(elections.0 / 2), "{took:?}");
}

/// A follower node restarted catches up its quiet groups.
#[test]
fn a_restarted_follower_catches_up_its_quiet_groups() {
    let mut cluster = Cluster::new(3);
    let agents = agents(&cluster, 12);
    let installed = &agents[..4];
    for &agent in installed {
        cluster.install(agent);
    }
    let leaders: Vec<NodeNumber> = installed
        .iter()
        .map(|&agent| cluster.leader(agent))
        .collect();
    // A node leading none of them, or else the one leading the fewest,
    // whose own are left out.
    let follower = (1..=3)
        .min_by_key(|number| leaders.iter().filter(|leader| *leader == number).count())
        .unwrap();
    let led: Vec<(AgentId, NodeNumber)> = installed
        .iter()
        .copied()
        .zip(leaders)
        .filter(|(_, leader)| *leader != follower)
        .collect();
    cluster.stop(follower);
    for &(agent, _) in &led {
        assert_eq!(done(cluster.increment_at_leader(agent, 1, 2)), 2);
    }
    cluster.start(follower);
    for &(agent, _) in &led {
        cluster.converged(agent);
    }
}

/// A link losing half its frames, then a link cut, moves no group's term:
/// the follower that stops hearing its leader is refused by the other,
/// which the pair heartbeat still vouches to.
#[test]
fn a_flaky_then_cut_link_moves_no_term() {
    let cluster = Cluster::new(3);
    let agents = agents(&cluster, 40);
    cluster.install(agents[0]);
    std::thread::sleep(Duration::from_millis(1_000));
    let before = terms(&cluster, &agents);
    // Lossy enough that the vouches between 1 and 2 lapse now and then.
    cluster.hub.set_link_loss(1, 2, 950_000);
    std::thread::sleep(Duration::from_secs(3));
    cluster.hub.heal();
    cluster.hub.partition(1, 2);
    std::thread::sleep(Duration::from_secs(3));
    cluster.hub.heal();
    std::thread::sleep(Duration::from_millis(1_000));
    assert_eq!(terms(&cluster, &agents), before);
    assert_eq!(done(cluster.increment_at_leader(agents[0], 1, 7)), 7);
}

/// A node whose writer stalls stops being vouched for: the quiet groups
/// it leads elect leaders elsewhere.
#[test]
fn the_groups_of_a_node_whose_writer_stalls_elect_elsewhere() {
    let commits = Arc::new(Gate::default());
    let held = Arc::clone(&commits);
    let cluster = Cluster::tuned(3, move |number, config| {
        if number == 1 {
            config.hooks = held.clone();
        }
    });
    let agents = agents(&cluster, 30);
    for &agent in &agents {
        cluster.install(agent);
    }
    // Node 1 leads some; one of them takes a call its writer holds.
    let mut led = Vec::new();
    wait_until("node 1 leads some", || {
        led = agents
            .iter()
            .copied()
            .filter(|&agent| cluster.leader(agent) == 1)
            .collect();
        !led.is_empty()
    });
    std::thread::scope(|scope| {
        // Inside the scope: a failure opens it before the scope waits.
        let closed = commits.close();
        let cluster = &cluster;
        let held = led[0];
        let call = scope.spawn(move || cluster.increment(1, held, 1, 1));
        // The group whose driver waits on the held write still believes
        // it leads, until the write returns.
        wait_until("another node leads each group node 1 led", || {
            led.iter()
                .all(|&agent| cluster.node(2).leads(agent) || cluster.node(3).leads(agent))
        });
        drop(closed);
        let _ = call.join();
    });
    for &agent in &led {
        assert_ne!(cluster.leader(agent), 1);
    }
}

/// An install at a leader whose commits stall answers that it may have
/// run, within the node's deadline, rather than wait for the commit; sent
/// again once commits go on, it installs, as an install overwrites. An
/// install a node no longer leading refuses (`NotLeader`, not run) is sent
/// to the agent's leader again, its commits open meanwhile.
#[test]
fn an_install_at_a_stalled_leader_times_out() {
    let commits = Arc::new(Gate::default());
    let held = Arc::clone(&commits);
    let cluster = Cluster::tuned(3, move |_, config| {
        config.hooks = held.clone();
        config.answered = Duration::from_millis(400);
    });
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    let until = Instant::now() + Duration::from_secs(60);
    let (installed, took, closed) = loop {
        let leader = cluster.node(cluster.leader(agent));
        let closed = commits.close();
        let started = Instant::now();
        // Bounded here too, so that waiting for the commit fails, not hangs.
        let install = leader.install(agent, COUNTER, &cluster.programs.counter_elf, vec![]);
        let installed = smol::block_on(smol::future::or(async { Some(install.await) }, async {
            smol::Timer::after(Duration::from_secs(10)).await;
            None
        }))
        .expect("the install waited for its commit, past the deadline");
        match installed {
            Err(CallError::NotLeader(_)) if Instant::now() < until => drop(closed),
            installed => break (installed, started.elapsed(), closed),
        }
    };
    assert!(
        matches!(installed, Err(CallError::TimedOut)),
        "{installed:?}"
    );
    assert!(
        took < Duration::from_secs(5),
        "answered within the deadline, not the commit: {took:?}"
    );
    drop(closed);
    // Sent again, as its operator would after `TimedOut`, until it
    // installs: with so short a deadline, the held commits' backlog can
    // outlast one try.
    wait_until("the install, sent again", || {
        let leader = cluster.node(cluster.leader(agent));
        let installed =
            smol::block_on(leader.install(agent, COUNTER, &cluster.programs.counter_elf, vec![]));
        installed.ran()
    });
    assert_eq!(done(cluster.increment_at_leader(agent, 1, 2)), 2);
}
