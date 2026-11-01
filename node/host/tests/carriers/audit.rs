//! The audit's run and its carriers.

use std::sync::Arc;
use std::time::Duration;

use vos_checker::carriers::{self, Audit, Canary, Kind, Logs, Reach};
use vos_net::{Class, Network, Peer};
use vos_node::{Config, Hooks};
use vos_node_prover::Prover;
use vos_node_prover::masked::Disclosing;
use vos_venue::VenueClient;
use vos_venue::vos_statement::Statement;
use vos_wire::Encode;
use vos_wire::batch::Request;
use vos_wire::ids::AgentId;
use vos_wire::peer::NodeNumber;
use vos_wire::result::Outcome;

use crate::common::{ALICE, Cluster, wait_until};
use crate::support::past_close;
use crate::support::{Anchoring, Judging, attests, ended, holds, replica};
use crate::support::{READER, ask_in, call, clock, reader, reader_agent};

/// The replicas of the agents the run reads and represents: node 4, in the
/// space, replicates neither.
const REPLICAS: [NodeNumber; 3] = [1, 2, 3];

/// What each capture path is sent once, to show it captures: a log line
/// from a node's thread, a line on standard error from a prover's pool
/// thread, a file in a node's directory, a frame through the hub and a
/// submission through the venue's client.
const CANARY: &str = "carrier-audit-canary";

/// High in entropy, from a row's key and its write's sequence.
fn mixed(key: u64, sequence: u64) -> u64 {
    let mut mixed = (key << 8 | sequence).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    mixed ^= mixed >> 29;
    mixed.wrapping_mul(0xbf58_476d_1ce4_e5b9)
}

/// The values a run's rows hold, and the least of them searched as a
/// number.
#[derive(Clone, Copy)]
enum Values {
    /// High in entropy, so a carrier holding one is found, and past 2^40.
    Wide,
    /// Below the row floor of a run of any values (2^24), at or past the
    /// small values' ([`carriers::SMALL_FLOOR`]).
    Small,
}

impl Values {
    fn entry(self, key: u64, sequence: u64) -> u64 {
        match self {
            Values::Wide => mixed(key, sequence) | 1 << 40,
            Values::Small => {
                let span = carriers::ROW_FLOOR - carriers::SMALL_FLOOR;
                carriers::SMALL_FLOOR + mixed(key, sequence) % span
            }
        }
    }
}

/// Requests `sequences` at `agent`: 25 puts each in the reader's committed
/// map, every value one of `values`: the values written.
fn write_entries(
    cluster: &Cluster,
    agent: AgentId,
    sequences: std::ops::RangeInclusive<u64>,
    values: Values,
) -> Vec<u64> {
    let mut written = Vec::new();
    for sequence in sequences {
        let writes: Vec<(u64, Option<u64>)> = (0..25u64)
            .map(|index| {
                let key = (sequence * 37 + index * 11) % 300;
                (key, Some(values.entry(key, sequence)))
            })
            .collect();
        written.extend(writes.iter().filter_map(|(_, value)| *value));
        let request = Request {
            session: cluster.session(agent),
            sequence,
            caller: ALICE,
            instance: READER,
            method: reader("set_entries"),
            arguments: writes.encode(),
        };
        assert!(matches!(call(cluster, agent, request), Outcome::Done(_)));
    }
    written
}

#[test]
fn no_carrier_that_leaves_the_prover_role_holds_its_internals() {
    run(Values::Wide);
}

/// The run over small values: every row's value below 2^24, each a
/// needle from [`carriers::SMALL_FLOOR`] up.
#[test]
fn no_carrier_that_leaves_the_prover_role_holds_a_small_value() {
    run(Values::Small);
}

/// The environment set once in the process, before its first run starts
/// a thread.
static DEBUG_ENVIRONMENT: std::sync::Once = std::sync::Once::new();

fn run(values: Values) {
    let floor = match values {
        Values::Wide => carriers::ROW_FLOOR,
        Values::Small => carriers::SMALL_FLOOR,
    };
    // SAFETY: once, before the process's first run starts any thread that
    // reads the environment; its tests run one at a time.
    DEBUG_ENVIRONMENT.call_once(|| unsafe { carriers::debug_environment_on() });
    let stderr = carriers::Stderr::capture(std::path::Path::new(env!("CARGO_TARGET_TMPDIR")));
    let logs = Logs::install();
    let anchoring = Anchoring::new();
    let venue = Arc::new(Judging::new(Arc::clone(&anchoring.venue), false));
    let tapped = Arc::new(carriers::Tapped::new(venue.clone()));
    let prover = Arc::new(Disclosing::default());
    let canary = Arc::new(Canary::new(CANARY));
    let mut cluster = {
        let venue: Arc<dyn VenueClient> = tapped.clone();
        let prover: Arc<dyn Prover> = prover.clone();
        let hooks: Arc<dyn Hooks> = canary.clone();
        Cluster::in_space(
            4,
            Some(clock()),
            move |_: NodeNumber, config: &mut Config| {
                config.venue = Some(Arc::clone(&venue));
                config.prover = Some(Arc::clone(&prover));
                config.hooks = Arc::clone(&hooks);
            },
        )
    };
    let frames = carriers::tap_frames(&cluster.hub);

    // A read at window 0's cut, served, stated and proved.
    anchoring.register(&cluster);
    let representative = cluster.representative(&REPLICAS);
    let reader = reader_agent(&cluster, &REPLICAS);
    let written = write_entries(&cluster, reader, 1..=4, values);
    let clock = clock();
    let boundary = clock.boundary(0).unwrap();
    let (read, _, keys) = ask_in(&cluster, reader, cluster.session(reader), 5, 0);
    anchoring.set_clocks(&cluster, boundary + 1_000);
    wait_until("the representative holds the agent's root", || {
        holds(replica(&cluster, representative), representative, reader, 0)
    });
    anchoring.set_clocks(&cluster, past_close(&clock, 0));
    let answer = ended(&cluster, reader, read);
    assert!(matches!(answer, Outcome::Done(_)), "{answer:?}");
    let attest = attests(replica(&cluster, reader), reader, read)[0].clone();
    vos_checker::wait_until(
        "the venue accepts the statement",
        Duration::from_secs(900),
        || !venue.accepted.lock().unwrap().is_empty(),
    );

    let mut audit = Audit::default();
    audit.needles.debug_outputs();
    let made = prover.made();
    assert_eq!(made.len(), 1, "proved once");
    for (n, (proved, internals)) in made.iter().enumerate() {
        assert_eq!(proved, &attest);
        assert!(!internals.proofs.is_empty() && !internals.memory_roots.is_empty());
        let name = format!("statement {n}");
        audit.needles.internals(&name, internals);
        // The kernel's arguments are the read's keys, its rows after them.
        audit
            .needles
            .attest(&name, proved, keys.encode().len(), floor);
    }
    assert!(
        audit.needles.named(Kind::ServedRow, "'s value").count() >= 12,
        "every row served a needle by its value"
    );
    assert!(
        audit.needles.named(Kind::ServedRow, "'s key").count() >= 12,
        "every row served a needle by its key"
    );
    audit.needles.written("the run", written, floor);
    assert!(
        audit
            .needles
            .named(Kind::ServedRow, "the written value")
            .count()
            >= 100,
        "every value written a needle"
    );
    for drawn in [
        "entropy",
        "attempt's seed",
        "witness digest",
        "blinding value",
        "mask column's seed",
        "salt column's seed",
        "R column's seed",
    ] {
        assert!(
            audit.needles.named(Kind::WrapRandomness, drawn).count() > 0,
            "the wrap's randomness has a needle of its {drawn}"
        );
    }

    // The canaries, one through each capture path.
    let (sent, pooled) = std::sync::mpsc::channel();
    rayon::spawn(move || {
        eprintln!("{CANARY}: a pool's thread");
        sent.send(()).unwrap();
    });
    pooled.recv().unwrap();
    std::fs::write(cluster.dirs[0].path().join("canary"), CANARY).unwrap();
    let (outsider, _arrivals) = cluster.hub.join(9);
    outsider.set_peers(vec![Peer {
        number: 1,
        key: [0; 32],
        address: "127.0.0.1:9".parse().unwrap(),
    }]);
    let _ = outsider.send(1, Class::Bulk, 0, CANARY.as_bytes().to_vec());
    let canary_statement = Statement {
        output: CANARY.as_bytes().to_vec(),
        ..tapped.submitted()[0].0.clone()
    };
    let _ = tapped.submit(&canary_statement, CANARY.as_bytes());

    // What leaves the role.
    assert!(!tapped.submitted().is_empty());
    tapped.carriers(&mut audit);
    audit.carrier("the client's answers", Reach::Leaves, answer.encode());

    // What stays within it, and what reaches node 4, which replicates no
    // agent of the run.
    let reach = |number: NodeNumber| {
        if REPLICAS.contains(&number) {
            Reach::Role
        } else {
            Reach::Leaves
        }
    };
    for ((to, class), bytes) in frames.lock().unwrap().iter() {
        audit.carrier(
            format!("frames to node {to}: {class}"),
            reach(*to),
            bytes.clone(),
        );
    }
    for (number, node) in cluster.running() {
        let agents = [representative, reader];
        carriers::node_carriers(&mut audit, number, node, &agents, reach(number));
    }
    // The disks once the nodes stop, every file closed.
    let numbers: Vec<NodeNumber> = cluster.running().map(|(number, _)| number).collect();
    for number in numbers {
        cluster.stop(number);
    }
    for (at, dir) in cluster.dirs.iter().enumerate() {
        let number = at as NodeNumber + 1;
        for (path, bytes) in carriers::directory(dir.path()) {
            audit.carrier(format!("node {number}: {path}"), reach(number), bytes);
        }
    }
    // The logs last, everything the run wrote in them.
    carriers::finish_logs(&mut audit, &logs, stderr);

    eprintln!("{}", audit.summary());
    audit.assert_searchable(&Kind::PROVER);
    for carrier in [
        "the logs",
        "standard error",
        "node 1: ",
        "frames to node 1: Bulk",
        "the statement",
    ] {
        audit.assert_captured(carrier, CANARY.as_bytes());
    }
    audit.assert_clean();
}
