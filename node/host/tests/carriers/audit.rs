//! The audit's run and its carriers.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vos_checker::carriers::{self, Audit, Kind, Logs, Reach};
use vos_node::{Config, Node};
use vos_node_prover::Prover;
use vos_node_prover::masked::Disclosing;
use vos_venue::vos_statement::{Statement, StatementId};
use vos_venue::{AnchorRefusal, Anchored, ModelVenue, NotAccepted, Status, VenueClient};
use vos_wire::Encode;
use vos_wire::ids::AgentId;
use vos_wire::peer::NodeNumber;
use vos_wire::result::Outcome;
use vos_wire::vos_anchor::{Anchor, RootRead, SpaceId, VenueId};

use crate::common::{Cluster, wait_until};
use crate::cuts::{ask_in, clock, reader_agent, results, write};
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
}

/// Every frame between the nodes, by class.
type Frames = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

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
    let cluster = {
        let venue: Arc<dyn VenueClient> = tapped.clone();
        let prover: Arc<dyn Prover> = prover.clone();
        Cluster::in_space(
            3,
            Some(clock()),
            move |_: NodeNumber, config: &mut Config| {
                config.venue = Some(Arc::clone(&venue));
                config.prover = Some(Arc::clone(&prover));
            },
        )
    };
    let frames = Frames::default();
    let framed = Arc::clone(&frames);
    cluster.hub.tap(Arc::new(move |_, _, class, frame| {
        let mut frames = framed.lock().unwrap();
        frames
            .entry(format!("{class:?} frames"))
            .or_default()
            .extend_from_slice(frame);
    }));

    // A read at window 0's cut, served, stated and proved.
    anchoring.register(&cluster);
    let representative = cluster.representative(&[1, 2, 3]);
    let reader = reader_agent(&cluster, &[1, 2, 3]);
    write(&cluster, reader, 1..=20);
    let clock = clock();
    let boundary = clock.boundary(0).unwrap();
    let (read, ..) = ask_in(&cluster, reader, cluster.session(reader), 21, 0);
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
        audit.needles.attest(&name, proved);
    }

    // What leaves the role.
    assert!(!tapped.submitted().is_empty());
    tapped.carriers(&mut audit);
    audit.carrier("the client's answers", Reach::Leaves, answer.encode());

    // What stays within it.
    for (class, bytes) in frames.lock().unwrap().iter() {
        audit.carrier(class.clone(), Reach::Role, bytes.clone());
    }
    for (number, node) in cluster.running() {
        for agent in [representative, reader] {
            audit.carrier(
                format!("node {number}: agent {}'s log", agent.0),
                Reach::Role,
                log_entries(node, agent),
            );
            let results: Vec<u8> = results(node, agent, 0)
                .iter()
                .flat_map(|(_, result)| result.encode())
                .collect();
            audit.carrier(
                format!("node {number}: agent {}'s work results", agent.0),
                Reach::Role,
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
            Reach::Role,
            jobs,
        );
    }
    for (at, dir) in cluster.dirs.iter().enumerate() {
        for (path, bytes) in carriers::directory(dir.path()) {
            audit.carrier(format!("node {}: {path}", at + 1), Reach::Role, bytes);
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
        Kind::DebugOutput,
    ]);
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
