//! The node's costs on three node processes: three release builds of
//! `vos node run`, each pinned to a third of the laptop (`taskset`) and on
//! its own data directory, joined over QUIC; a driver on the rest of the
//! machine sends calls over HTTP, every one signed before its timed window.
//! - **agent:** one agent, the most commits per second, closed loop, over
//!   sessions; then at half load, max(10k/s, half the most), open loop.
//! - **agents:** 64 agents, the most, closed loop at 4 and 16 sessions
//!   each; open loop at 40k/s offered; and the knee, the highest offered
//!   rate whose p99 stays at 20 ms or below.
//! - **quiet:** one session, one call at a time.
//! - **query** and **linearizable:** see `query`; the heartbeat round each
//!   linearizable read takes is the difference.
//! - **idle:** see `idle`.
//! - **failover** and **failover-idle:** see `failover`, on the 64 agents
//!   or on the idle row's, with or without their rows.
//! - **soak:** see `soak`, on the 64 agents after any failover.
//!
//! Every open-loop latency is timed from when its call was scheduled to
//! go, so a slow call never hides the queue behind it; each such run gives
//! its send lag, and one whose p99 lag passes 0.5 ms is marked invalid.
//! Each run gives every process's CPU, and the CPU per commit.
//!
//! `cargo bench -p vos-cli --bench processes` (after `just build-agent
//! build-test-actors`). Its settings:
//! - `ROWS` picks rows (`agent,agents,quiet,query,linearizable,idle,
//!   failover,failover-idle,soak`; all but the last three by default);
//! - `CPUS` overrides the pinning, as `taskset -c` lists for each node and
//!   the driver, separated by `/`;
//! - `DATA` where the stores go;
//! - `VOS_BIN` another `vos` to run the nodes, to compare two builds;
//! - `LOGS` a directory to keep the nodes' logs in;
//! - `TLS=1` serves every node's ingress over TLS, each client pinning the
//!   node's key, for the rows against plain HTTP.
//!
//! `machine.sh`, beside this bench's directory, runs the rows on a machine
//! of its own, each node on cores of its own.

mod load;
mod nodes;
mod report;

use std::sync::Mutex;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use vos_checker::calls::signed_query;
use vos_checker::programs::package;
use vos_wire::Decode;
use vos_wire::ids::{AgentId, InstanceId};
use vos_wire::ingress::{Answer, Consistency};
use vos_wire::result::Outcome;

use load::{
    Bodies, Leaders, Pace, Plan, Signed, closed_calls, drive, new_sessions, open_calls, plans,
    signed, signing_plan,
};
use nodes::{Process, Space, cpus, pin_driver, pinning, transparent_huge_pages};
use report::{Measured, STALL, ms, report};

/// The nodes in the space.
const NODES: usize = 3;
const COUNTER: InstanceId = InstanceId(1);
const WARM: Duration = Duration::from_secs(2);
const MEASURE: Duration = Duration::from_secs(5);
const IDLE_SETTLE: Duration = Duration::from_secs(5);
const IDLE_MEASURE: Duration = Duration::from_secs(10);
/// The p99 the many-agent budget allows.
const KNEE_P99: Duration = Duration::from_millis(20);
/// A soak window is clean while the machine ran under this many cores
/// outside the run, and every task on it waited on IO under this share.
const CLEAN_OUTSIDE: f64 = 1.5;
const CLEAN_IO: f64 = 10.0;

fn rows() -> Vec<String> {
    std::env::var("ROWS")
        .unwrap_or_else(|_| "agent,agents,quiet,query,linearizable,idle".into())
        .split(',')
        .map(|row| row.trim().to_string())
        .collect()
}

fn main() {
    if std::env::args().any(|arg| arg == "--list") {
        return;
    }
    let rows = rows();
    let wanted = |name: &str| rows.iter().any(|row| row == name);
    let cpus = cpus();
    let pinned = pinning();
    if pinned {
        // The driver, and the threads it signs on, on its own cores.
        pin_driver(&cpus[NODES]);
        println!(
            "pinned: nodes on {:?}, the driver on {}",
            &cpus[..NODES],
            cpus[NODES]
        );
    } else {
        println!("taskset is missing: the nodes and the driver share every core");
    }
    let counter = package("counter");
    let space = Space::start(pinned, &cpus);
    // A run of `sessions` new sessions at each of `agents`: closed, or open
    // at `rate` offered over them all.
    let closed = |name: &str, agents: &[Signed], leaders: &Leaders, sessions: u64| {
        let calls = closed_calls(agents.len() as u64 * sessions);
        let plans = plans(agents, leaders, sessions, calls);
        run(name, &space, plans, Pace::Closed)
    };
    let open = |name: &str, agents: &[Signed], leaders: &Leaders, rate: f64, sessions: u64| {
        let all = agents.len() as f64 * sessions as f64;
        let interval = Duration::from_secs_f64(all / rate);
        let plans = plans(agents, leaders, sessions, open_calls(rate / all, MEASURE));
        run(name, &space, plans, Pace::Open(interval))
    };

    let one = signed(&space, space.counter_agent(&counter));
    let leaders: Leaders = [(one.agent, space.leader(one.agent))].into();
    if wanted("agent") {
        println!(
            "agent {} leads on node {}",
            one.agent.0,
            leaders[&one.agent] + 1
        );
        let mut most = 0.0f64;
        for sessions in [1u64, 4, 16, 64, 256] {
            let name = format!("agent, {sessions} sessions closed");
            most = most.max(closed(&name, &[one], &leaders, sessions).commits);
        }
        // Open loop near the most: what the agent takes without its
        // sessions all waiting on one batch; then at half load.
        let half = (most / 2.0).max(10_000.0);
        for rate in [15_000.0, 18_000.0, 21_000.0, half] {
            let name = format!("agent, open at {rate:.0}/s (256 sessions)");
            open(&name, &[one], &leaders, rate, 256);
        }
    }

    if wanted("quiet") {
        closed("quiet node, one call at a time", &[one], &leaders, 1);
    }

    if wanted("query") || wanted("linearizable") {
        let leader = leaders[&one.agent];
        let follower = (leader + 1) % NODES;
        if wanted("query") {
            query(&space, &one, follower, Consistency::Applied { at: 0 });
        }
        if wanted("linearizable") {
            query(&space, &one, follower, Consistency::Linearizable);
        }
    }

    // `failover` and `soak` take the 64 agents, with or without their
    // rows.
    let many = if wanted("agents") || wanted("failover") || wanted("soak") {
        let agents: Vec<Signed> = (0..64)
            .map(|_| signed(&space, space.counter_agent(&counter)))
            .collect();
        let leaders: Leaders = agents
            .iter()
            .map(|signed| (signed.agent, space.leader(signed.agent)))
            .collect();
        let mut led = [0usize; NODES];
        for leader in leaders.values() {
            led[*leader] += 1;
        }
        println!(
            "64 agents, leaders per node {led:?}: 16 sessions each, as many connections to each"
        );
        if wanted("agents") {
            for sessions in [4u64, 16] {
                let name = format!("64 agents × {sessions} sessions closed");
                closed(&name, &agents, &leaders, sessions);
            }
            let offered = |rate: f64| {
                let name = format!("64 agents, open at {rate:.0}/s");
                open(&name, &agents, &leaders, rate, 16)
            };
            // Upward, so no run meets the backlog of one past the knee: the
            // knee lies between the last rate that held and the first that
            // did not.
            let mut held = None;
            let mut missed = None;
            for rate in [
                5_000.0, 10_000.0, 15_000.0, 20_000.0, 25_000.0, 30_000.0, 35_000.0,
            ] {
                if offered(rate).p99 > KNEE_P99 {
                    missed = Some(rate);
                    break;
                }
                held = Some(rate);
            }
            match (held, missed) {
                (Some(held), Some(missed)) => {
                    println!(
                        "64 agents: the knee, p99 ≤ 20 ms, between {held:.0}/s and {missed:.0}/s offered"
                    )
                }
                (Some(held), None) => println!("64 agents: p99 ≤ 20 ms up to {held:.0}/s offered"),
                (None, _) => println!("64 agents: p99 above 20 ms from 5k/s offered"),
            }
            // The budget's own rate, last: past the knee, it leaves a backlog.
            offered(40_000.0);
        }
        agents
    } else {
        Vec::new()
    };

    if wanted("failover") {
        let agents: Vec<AgentId> = many.iter().map(|signed| signed.agent).collect();
        failover(&space, &agents);
    }
    if wanted("soak") {
        soak(&space, &many);
    }

    // Every increment answered as run is in its agent's counter, once.
    let mut agents = vec![one];
    agents.extend(many);
    counters_hold(&space, &agents);

    if wanted("idle") || wanted("failover-idle") {
        let idle = idle(&space);
        if wanted("failover-idle") {
            failover(&space, &idle);
        }
    }
}

/// One timed run of `plans`, reported as `name`, once the nodes are
/// quiet after the last.
fn run(name: &str, space: &Space, plans: Vec<Plan>, pace: Pace) -> Measured {
    quiet(space);
    let (mut samples, cpu) = drive(space, plans, pace, MEASURE, 1)
        .pop()
        .expect("one window");
    report(name, &mut samples, cpu, MEASURE)
}

/// Wait until the nodes use under a third of a core together, for at most
/// 20 s: the last run's backlog spent.
fn quiet(space: &Space) {
    let until = Instant::now() + Duration::from_secs(20);
    while Instant::now() < until {
        let before: f64 = space.cpu().iter().sum();
        std::thread::sleep(Duration::from_millis(300));
        let after: f64 = space.cpu().iter().sum();
        if (after - before) / 0.3 < 0.33 {
            return;
        }
    }
    println!("the nodes did not go quiet within 20 s");
}

/// Each agent's counter, read at its leader, equals the increments it
/// answered as run.
fn counters_hold(space: &Space, agents: &[Signed]) {
    let ran = space.ran.lock().unwrap().clone();
    let key = SigningKey::from_bytes(&[11; 32]);
    for signed in agents {
        let Some(expected) = ran.get(&signed.agent).copied() else {
            continue;
        };
        let body = signed_query(
            &signed.identity,
            &key,
            vos_node::wall_clock() + 60_000,
            Consistency::Linearizable,
            COUNTER,
            signed.value,
        );
        let leader = &space.processes[space.leader(signed.agent)];
        let path = format!("/agents/{}/queries", signed.agent.0);
        let answer =
            vos_node::client::post_within(&leader.target, &path, &body, Duration::from_secs(5));
        let value = match answer {
            Ok(Answer::Ran {
                outcome: Outcome::Done(bytes),
                ..
            }) => u64::decode(&bytes).unwrap().0,
            other => panic!("agent {}'s counter: {other:?}", signed.agent.0),
        };
        assert_eq!(
            value, expected,
            "agent {}'s counter against the increments it answered",
            signed.agent.0
        );
    }
    println!("every agent's counter holds every increment it answered, once");
}

/// The counter's value read on `follower` at `consistency`, open loop,
/// client to answer.
fn query(space: &Space, signed: &Signed, follower: usize, consistency: Consistency) {
    let key = SigningKey::from_bytes(&[9; 32]);
    let read = match consistency {
        Consistency::Linearizable => "linearizable",
        Consistency::Applied { .. } => "applied",
    };
    let body = signed_query(
        &signed.identity,
        &key,
        vos_node::wall_clock() + 240_000,
        consistency,
        COUNTER,
        signed.value,
    );
    // At two rates: what one more query costs the follower, beside what
    // it costs at a rate, its fixed costs included.
    let rates = [2_000.0, 6_000.0];
    let busy: Vec<f64> = rates
        .into_iter()
        .map(|rate: f64| {
            let sessions = 16usize;
            let per = open_calls(rate / sessions as f64, MEASURE);
            let plans: Vec<Plan> = (0..sessions)
                .map(|_| Plan {
                    counts: None,
                    node: follower,
                    path: format!("/agents/{}/queries", signed.agent.0),
                    bodies: Bodies::Ready(vec![body.clone(); per].into_iter()),
                })
                .collect();
            let interval = Duration::from_secs_f64(sessions as f64 / rate);
            let outcome = run(
                &format!(
                    "query ({read}) on follower node {}, open at {rate:.0}/s",
                    follower + 1
                ),
                space,
                plans,
                Pace::Open(interval),
            );
            outcome.busy[follower]
        })
        .collect();
    println!(
        "query ({read}): the follower's marginal CPU, {:.0} µs per query",
        (busy[1] - busy[0]) / (rates[1] - rates[0]) * 1e6
    );
}

/// 1,000 agents more on every node, left alone: each process's CPU,
/// threads and memory.
fn idle(space: &Space) -> Vec<AgentId> {
    let started = Instant::now();
    let created = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..125 {
                    let agent = space.create_agent();
                    created.lock().unwrap().push(agent);
                }
            });
        }
    });
    println!(
        "1,000 idle agents created in {:.1} s",
        started.elapsed().as_secs_f64()
    );
    std::thread::sleep(IDLE_SETTLE);
    let before = space.cpu();
    std::thread::sleep(IDLE_MEASURE);
    let after = space.cpu();
    for (at, process) in space.processes.iter().enumerate() {
        let (threads, rss) = process.threads_and_rss();
        println!(
            "idle node {}: {:.1}% of one core, {threads} threads, {rss} MiB resident",
            process.number,
            (after[at] - before[at]) / IDLE_MEASURE.as_secs_f64() * 100.0
        );
    }
    created.into_inner().unwrap()
}

/// The node leading the most of `agents` killed: the time until every one
/// has a leader again, and until every node left names that leader's
/// placement in its directory; then its restart: the time until it
/// listens, and its CPU while its groups catch up.
fn failover(space: &Space, agents: &[AgentId]) {
    let mut led = [0usize; NODES];
    for agent in agents {
        led[space.leader(*agent)] += 1;
    }
    let victim = (0..NODES).max_by_key(|at| led[*at]).unwrap();
    println!(
        "failover: node {} leading {} of {} agents is killed",
        victim + 1,
        led[victim],
        agents.len()
    );
    let started = Instant::now();
    space.processes[victim].kill();
    let left: Vec<&Process> = space
        .processes
        .iter()
        .enumerate()
        .filter(|(at, _)| *at != victim)
        .map(|(_, process)| process)
        .collect();
    let status = |process: &Process, agent: AgentId| match process.operator().status(agent) {
        Ok(Answer::Status(status)) => Some(status),
        _ => None,
    };
    // The term each agent's new leader leads at.
    let mut terms = Vec::with_capacity(agents.len());
    for agent in agents {
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            let term = left
                .iter()
                .find_map(|process| status(process, *agent).filter(|status| status.leads))
                .map(|status| status.term);
            if let Some(term) = term {
                terms.push(term);
                break;
            }
            assert!(Instant::now() < until, "agent {} has no leader", agent.0);
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    println!(
        "failover: every agent has a leader again {:.2} s after the kill",
        started.elapsed().as_secs_f64()
    );
    // Each node left names a placement at least as new as its leader's.
    for (agent, term) in agents.iter().zip(&terms) {
        let until = Instant::now() + Duration::from_secs(60);
        while !left.iter().all(|process| {
            status(process, *agent).is_some_and(|status| status.placement_term >= *term)
        }) {
            assert!(
                Instant::now() < until,
                "agent {}'s new placement did not reach every node",
                agent.0
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    println!(
        "failover: every node left names the new leaders' placements {:.2} s after the kill",
        started.elapsed().as_secs_f64()
    );
    // Each time above is when a sweep of the statuses saw its event: one
    // sweep's own time is their resolution.
    let swept = Instant::now();
    for agent in agents {
        for process in &left {
            status(process, *agent);
        }
    }
    println!(
        "failover: one sweep of every agent's status on the nodes left takes {:.2} s",
        swept.elapsed().as_secs_f64()
    );
    let opened = space.processes[victim].restart();
    let before = space.processes[victim].cpu();
    std::thread::sleep(IDLE_MEASURE);
    let busy = (space.processes[victim].cpu() - before) / IDLE_MEASURE.as_secs_f64();
    println!(
        "failover: node {} listens {:.2} s after its restart, then {:.0}% of one core over {} s",
        victim + 1,
        opened.as_secs_f64(),
        busy * 100.0,
        IDLE_MEASURE.as_secs()
    );
}

/// The 64-agent load open at `SOAK_RATE` (6k/s by default) for
/// `SOAK_SECONDS` (1,800), one load throughout, in windows of 50 s; the
/// windows within `SOAK_WARMUP` (150 s) of its start are reported, not
/// compared.
///
/// After the warm-up, its steady state over the clean windows (outside
/// the run under [`CLEAN_OUTSIDE`] cores, IO stalled under [`CLEAN_IO`]%),
/// to compare runs by. And the history a run leaves must not cost more:
/// the medians of the first three clean windows and of the last three
/// must agree within the bounds `judge` is given. The p99 is reported for
/// each window and judged by the budgets, not here.
fn soak(space: &Space, agents: &[Signed]) {
    let rate: f64 = std::env::var("SOAK_RATE")
        .ok()
        .and_then(|rate| rate.parse().ok())
        .unwrap_or(6_000.0);
    let seconds: u64 = std::env::var("SOAK_SECONDS")
        .ok()
        .and_then(|seconds| seconds.parse().ok())
        .unwrap_or(1_800);
    // Its first windows come before the store's steady state (nothing
    // flushed yet): reported, not compared.
    let warmup: u64 = std::env::var("SOAK_WARMUP")
        .ok()
        .and_then(|seconds| seconds.parse().ok())
        .unwrap_or(150);
    let window = Duration::from_secs(50);
    let windows = (seconds / window.as_secs()).max(1);
    let warm = warmup.div_ceil(window.as_secs()) as usize;
    let leaders: Leaders = agents
        .iter()
        .map(|signed| (signed.agent, space.leader(signed.agent)))
        .collect();
    let sessions = 4u64;
    let all = agents.len() as f64 * sessions as f64;
    let interval = Duration::from_secs_f64(all / rate);
    // One load throughout, each call signed as its session goes: the
    // nodes never rest between windows. Each plan moves to a new session
    // every `SESSION_CALLS`, so new sessions keep arriving, as clients'
    // do. (They expire after an hour, past a default soak.)
    const SESSION_CALLS: u64 = 1_000;
    let calls = open_calls(rate / all, window * windows as u32);
    let plans_count = agents.len() as u64 * sessions;
    let first = new_sessions(plans_count * (calls as u64).div_ceil(SESSION_CALLS));
    let plans: Vec<Plan> = agents
        .iter()
        .enumerate()
        .flat_map(|(at, signed)| {
            let node = leaders[&signed.agent];
            (0..sessions).map(move |session| {
                let number = first + at as u64 * sessions + session;
                signing_plan(signed, (number, plans_count, SESSION_CALLS), calls, node)
            })
        })
        .collect();
    quiet(space);
    let huge_before = transparent_huge_pages();
    let measured: Vec<Measured> =
        drive(space, plans, Pace::Open(interval), window, windows as usize)
            .into_iter()
            .enumerate()
            .map(|(at, (mut samples, cpu))| {
                report(
                    &format!("soak window {} of {windows}, open at {rate:.0}/s", at + 1),
                    &mut samples,
                    cpu,
                    window,
                )
            })
            .collect();
    // Memory under load: each node's, and what transparent huge pages cost
    // the machine meanwhile (khugepaged's CPU is not the nodes').
    let memory: Vec<String> = space
        .processes
        .iter()
        .map(|process| {
            let (_, rss) = process.threads_and_rss();
            format!(
                "node {} {rss} MiB ({} MiB in huge pages)",
                process.number,
                process.huge_pages()
            )
        })
        .collect();
    let huge: Vec<String> = transparent_huge_pages()
        .into_iter()
        .zip(huge_before)
        .filter(|((_, after), (_, before))| after != before)
        .map(|((name, after), (_, before))| format!("{name} +{}", after - before))
        .collect();
    println!(
        "soak memory: {}; huge pages over the run: {}",
        memory.join(", "),
        if huge.is_empty() {
            "none".to_string()
        } else {
            huge.join(", ")
        }
    );
    let clean: Vec<&Measured> = measured
        .iter()
        .skip(warm)
        .filter(|outcome| outcome.outside < CLEAN_OUTSIDE && outcome.io < CLEAN_IO)
        .collect();
    println!(
        "soak: {} of the {} windows after {warm} of warm-up clean (outside the run under {CLEAN_OUTSIDE} cores, IO stalled under {CLEAN_IO}%)",
        clean.len(),
        windows.saturating_sub(warm as u64)
    );
    if clean.is_empty() {
        return;
    }
    let median = |outcomes: &[&Measured], of: &dyn Fn(&Measured) -> f64| {
        let mut values: Vec<f64> = outcomes.iter().map(|outcome| of(outcome)).collect();
        values.sort_by(f64::total_cmp);
        values[values.len() / 2]
    };
    // The steady state, to compare runs by.
    let mean = |of: &dyn Fn(&Measured) -> f64| {
        clean.iter().map(|outcome| of(outcome)).sum::<f64>() / clean.len() as f64
    };
    println!(
        "soak steady: {:.1} runtime stalls and {:.1} batches of {:.0} ms or more a window, the longest batch {:.0} ms; median p95 {:.2} ms, p99 {:.2} ms; CPU per commit {:.0} µs",
        mean(&|outcome| outcome.stalls as f64),
        mean(&|outcome| outcome.long_batches as f64),
        STALL as f64 / 1000.0,
        clean
            .iter()
            .map(|outcome| outcome.longest_batch)
            .max()
            .unwrap_or(0) as f64
            / 1000.0,
        median(&clean, &|outcome| ms(outcome.p95)),
        median(&clean, &|outcome| ms(outcome.p99)),
        median(&clean, &|outcome| {
            outcome.busy.iter().sum::<f64>() / outcome.commits * 1e6
        }),
    );
    if clean.len() < 6 {
        println!("soak: too few clean windows to judge a trend");
        return;
    }
    let (early, late) = (&clean[..3], &clean[clean.len() - 3..]);
    let mut grew = Vec::new();
    let mut judge =
        |name: &str, unit: &str, of: &dyn Fn(&Measured) -> f64, allowed: f64, slack: f64| {
            let (before, after) = (median(early, of), median(late, of));
            println!("soak: {name} {before:.2}{unit} then {after:.2}{unit}");
            if after > before * allowed + slack {
                grew.push(name.to_string());
            }
        };
    judge(
        "CPU per commit",
        " µs",
        &|outcome| outcome.busy.iter().sum::<f64>() / outcome.commits * 1e6,
        1.10,
        0.0,
    );
    judge("p50", " ms", &|outcome| ms(outcome.p50), 1.10, 0.0);
    judge("p95", " ms", &|outcome| ms(outcome.p95), 1.10, 0.0);
    judge(
        "runtime stalls",
        "",
        &|outcome| outcome.stalls as f64,
        1.10,
        1.0,
    );
    judge(
        "batches over the stall",
        "",
        &|outcome| outcome.long_batches as f64,
        1.10,
        1.0,
    );
    judge(
        "the longest batch",
        " ms",
        &|outcome| outcome.longest_batch as f64 / 1000.0,
        1.25,
        0.0,
    );
    if grew.is_empty() {
        println!("soak: holds");
    } else {
        println!("soak: GROWS: {}", grew.join(", "));
    }
}
