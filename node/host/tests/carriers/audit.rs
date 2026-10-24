//! The audit's run and its carriers.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vos_checker::carriers::{self, Audit, Kind, Logs, Reach};
use vos_net::{Class, Network, Peer};
use vos_node::{Config, Hooks, Node};
use vos_node_prover::Prover;
use vos_node_prover::masked::Disclosing;
use vos_venue::vos_statement::{Statement, StatementId};
use vos_venue::{AnchorRefusal, Anchored, ModelVenue, NotAccepted, Status, VenueClient};
use vos_wire::Encode;
use vos_wire::batch::Request;
use vos_wire::ids::AgentId;
use vos_wire::peer::NodeNumber;
use vos_wire::result::Outcome;
use vos_wire::vos_anchor::{Anchor, RootRead, SpaceId, VenueId};

use crate::common::{ALICE, Cluster, wait_until};
use crate::cuts::{READER, ask_in, call, clock, reader, reader_agent, results};
use crate::representative::{Anchoring, attests, delay, ended, holds, replica};

/// The model venue's anchors, a statement taken once by its id.
struct Venue {
    model: Arc<ModelVenue>,
    accepted: Mutex<BTreeSet<[u8; 32]>>,
}

impl VenueClient for Venue {
    fn id(&self) -> VenueId {
        self.model.id()
    }

    fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal> {
        self.model.anchor(anchor)
    }

    fn submit(&self, statement: &Statement, _: &[u8]) -> Result<StatementId, NotAccepted> {
        let id = statement.id();
        if !self.accepted.lock().unwrap().insert(id.0) {
            return Err(NotAccepted::Refused(6));
        }
        Ok(id)
    }

    fn anchored(&self, root: &RootRead) -> bool {
        self.model.anchored(root)
    }

    fn anchor_keys(&self, space: &SpaceId) -> Vec<[u8; 32]> {
        self.model.anchor_keys(space)
    }

    fn status(&self, space: &SpaceId) -> Status {
        self.model.status(space)
    }

    fn time(&self) -> Option<u64> {
        self.model.time()
    }

    fn unsettled(&self, space: &SpaceId) -> Vec<Anchor> {
        self.model.unsettled(space)
    }
}

/// The replicas of the agents the run reads and represents: node 4, in the
/// space, replicates neither.
const REPLICAS: [NodeNumber; 3] = [1, 2, 3];

/// What each capture path is sent once, to show it captures: a log line
/// from a node's thread, a line on standard error from a prover's pool
/// thread, a file in a node's directory, a frame through the hub and a
/// submission through the venue's client.
const CANARY: &str = "carrier-audit-canary";

/// Logs [`CANARY`] once, at TRACE, from the first node thread that commits.
#[derive(Default)]
struct Canary(AtomicBool);

impl Hooks for Canary {
    fn before_commit(&self) {
        if !self.0.swap(true, Ordering::SeqCst) {
            tracing::trace!(canary = CANARY, "a node's thread");
        }
    }
}

/// Every frame between the nodes, by its destination and class.
type Frames = Arc<Mutex<BTreeMap<(NodeNumber, String), Vec<u8>>>>;

/// A value of a row the run writes: high in entropy, so a carrier holding
/// it is found, and past 2^40.
fn entry(key: u64, sequence: u64) -> u64 {
    let mut mixed = (key << 8 | sequence).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    mixed ^= mixed >> 29;
    mixed.wrapping_mul(0xbf58_476d_1ce4_e5b9) | 1 << 40
}

/// Requests `sequences` at `agent`: 25 puts each in the reader's committed
/// map, every value an [`entry`].
fn write_entries(cluster: &Cluster, agent: AgentId, sequences: std::ops::RangeInclusive<u64>) {
    for sequence in sequences {
        let writes: Vec<(u64, Option<u64>)> = (0..25u64)
            .map(|index| {
                let key = (sequence * 37 + index * 11) % 300;
                (key, Some(entry(key, sequence)))
            })
            .collect();
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
}

#[test]
fn no_carrier_that_leaves_the_prover_role_holds_its_internals() {
    // Every debug output on, as an operator could set it: none prints in a
    // build without `debug-internals`.
    for name in carriers::DEBUG_ENVIRONMENT {
        // SAFETY: before the run starts any thread that reads the
        // environment.
        unsafe { std::env::set_var(name, "1") };
    }
    let stderr = carriers::Stderr::capture(std::path::Path::new(env!("CARGO_TARGET_TMPDIR")));
    let logs = Logs::install();
    let anchoring = Anchoring::new();
    let venue = Arc::new(Venue {
        model: Arc::clone(&anchoring.venue),
        accepted: Mutex::default(),
    });
    let tapped = Arc::new(carriers::Tapped::new(venue.clone()));
    let prover = Arc::new(Disclosing::default());
    let canary = Arc::new(Canary::default());
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
    let frames = Frames::default();
    let framed = Arc::clone(&frames);
    cluster.hub.tap(Arc::new(move |_, to, class, frame| {
        let mut frames = framed.lock().unwrap();
        frames
            .entry((to, format!("{class:?}")))
            .or_default()
            .extend_from_slice(frame);
    }));

    // A read at window 0's cut, served, stated and proved.
    anchoring.register(&cluster);
    let representative = cluster.representative(&REPLICAS);
    let reader = reader_agent(&cluster, &REPLICAS);
    write_entries(&cluster, reader, 1..=4);
    let clock = clock();
    let boundary = clock.boundary(0).unwrap();
    let (read, _, keys) = ask_in(&cluster, reader, cluster.session(reader), 5, 0);
    anchoring.set_clocks(&cluster, boundary + 1_000);
    wait_until("the representative holds the agent's root", || {
        holds(replica(&cluster, representative), representative, reader, 0)
    });
    anchoring.set_clocks(&cluster, boundary + delay(&clock) + 1_000);
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
        audit.needles.attest(&name, proved, keys.encode().len());
    }
    assert!(
        audit.needles.named(Kind::ServedRow, "'s value").count() >= 12,
        "every row served a needle by its value"
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
        for agent in [representative, reader] {
            audit.carrier(
                format!("node {number}: agent {}'s log", agent.0),
                reach(number),
                log_entries(node, agent),
            );
            let results: Vec<u8> = results(node, agent, 0)
                .iter()
                .flat_map(|(_, result)| result.encode())
                .collect();
            audit.carrier(
                format!("node {number}: agent {}'s work results", agent.0),
                reach(number),
                results,
            );
        }
        let jobs: Vec<u8> = node
            .store()
            .prover_jobs()
            .unwrap()
            .into_iter()
            .flat_map(|(_, id, job)| [id.to_vec(), job].concat())
            .collect();
        audit.carrier(
            format!("node {number}: the prover's table"),
            reach(number),
            jobs,
        );
        audit.carrier(
            format!("node {number}: the store's rows"),
            reach(number),
            carriers::store(node.store()),
        );
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
    std::thread::sleep(Duration::from_secs(1));
    audit.carrier("the logs, every level", Reach::Leaves, logs.bytes());
    audit.carrier("standard error", Reach::Leaves, stderr.finish());

    eprintln!("{}", audit.summary());
    audit.assert_searchable(&[
        Kind::NodeProof,
        Kind::ServedRow,
        Kind::PrivateHash,
        Kind::StepCount,
        Kind::MemoryRoot,
        Kind::Register,
        Kind::WrapRandomness,
        Kind::DebugOutput,
    ]);
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

/// Every entry `agent`'s log holds on `node`, its body as the log keeps it.
fn log_entries(node: &Node, agent: AgentId) -> Vec<u8> {
    let through = node.applied(agent).unwrap_or(0);
    (1..=through)
        .filter_map(|index| node.store().log_entry(agent, index).ok().flatten())
        .flat_map(|entry| entry.body)
        .collect()
}
