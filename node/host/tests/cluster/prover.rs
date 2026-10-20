//! The prover worker on three nodes: the leader of an agent whose read at
//! a window's cut is served proves its statement, has the agent record it
//! (`Input::Proven`) on every replica, and submits it once the space's
//! root is anchored; a leader stopped after recording its proof and before
//! submitting it leaves a new leader that proves it again, the proof gone
//! with the old, and the venue holds it accepted once.
//!
//! The proofs are a model prover's (the masked prover proves in minutes,
//! `just test-proof`'s), so the venue judges anchors as the model venue
//! does and takes a statement once by its id.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vos_node::Config;
use vos_node_prover::{FORMAT, Options, ProveError, Prover};
use vos_venue::vos_statement::{ProgramId, Statement, StatementId};
use vos_venue::{AnchorRefusal, Anchored, ModelVenue, NotAccepted, Status, VenueClient};
use vos_wire::ids::AgentId;
use vos_wire::keys;
use vos_wire::peer::NodeNumber;
use vos_wire::result::{Attest, Outcome};
use vos_wire::vos_anchor::{Anchor, RootRead, SpaceId, VenueId};

use crate::common::{Cluster, wait_until};
use crate::cuts::{ask_keys, clock, reader_agent, write};
use crate::representative::{Anchoring, attests, delay, ended, holds, replica};

/// The model prover's program id for every kernel.
const PROGRAM: ProgramId = ProgramId([7; 8]);

/// The model venue's anchors, and statements taken once by id, every
/// root held unanchored while `hold` is set.
struct Judging {
    model: Arc<ModelVenue>,
    accepted: Mutex<BTreeSet<[u8; 32]>>,
    submissions: AtomicUsize,
    hold: AtomicBool,
}

impl VenueClient for Judging {
    fn id(&self) -> VenueId {
        self.model.id()
    }

    fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal> {
        self.model.anchor(anchor)
    }

    fn submit(&self, statement: &Statement, _: &[u8]) -> Result<StatementId, NotAccepted> {
        self.submissions.fetch_add(1, Ordering::SeqCst);
        let id = statement.id();
        if !self.accepted.lock().unwrap().insert(id.0) {
            return Err(NotAccepted::Refused(6));
        }
        Ok(id)
    }

    fn anchored(&self, root: &RootRead) -> bool {
        !self.hold.load(Ordering::SeqCst) && self.model.anchored(root)
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

/// A prover whose proofs differ each time, as masked proofs do.
#[derive(Default)]
struct Proofs {
    made: AtomicUsize,
}

impl Prover for Proofs {
    fn program(&self, _: &[u8]) -> Result<ProgramId, ProveError> {
        Ok(PROGRAM)
    }

    fn prove(&self, _: &[u8], attest: &Attest) -> Result<Vec<u8>, ProveError> {
        let made = self.made.fetch_add(1, Ordering::SeqCst);
        Ok([b"proof".as_slice(), &attest.output, &made.to_le_bytes()].concat())
    }
}

/// Three nodes in a space anchoring at `judging`, each proving with
/// `proofs`, a proof another replica made asked for two seconds.
fn cluster(judging: &Arc<Judging>, proofs: &Arc<Proofs>) -> Cluster {
    let venue: Arc<dyn VenueClient> = judging.clone();
    let prover: Arc<dyn Prover> = proofs.clone();
    Cluster::in_space(
        3,
        Some(clock()),
        move |_: NodeNumber, config: &mut Config| {
            config.venue = Some(Arc::clone(&venue));
            config.prover = Some(Arc::clone(&prover));
            config.prover_options = Options {
                patience: Duration::from_secs(2),
                ..Options::default()
            };
        },
    )
}

/// A reader agent on the three nodes, its read at window 0's cut served
/// and stated against the anchored `S_0`: the agent and the attest.
fn stated(cluster: &Cluster, anchoring: &Anchoring) -> (AgentId, Attest) {
    let clock = clock();
    let b0 = clock.boundary(0).unwrap();
    anchoring.register(cluster);
    let representative = cluster.representative(&[1, 2, 3]);
    let agent = reader_agent(cluster, &[1, 2, 3]);
    write(cluster, agent, 1..=20);
    let (read, ..) = ask_keys(cluster, agent, 21);
    anchoring.set_clocks(cluster, b0 + 1_000);
    wait_until("the representative holds the agent's root", || {
        holds(replica(cluster, representative), representative, agent, 0)
    });
    anchoring.set_clocks(cluster, b0 + delay(&clock) + 1_000);
    assert!(matches!(ended(cluster, agent, read), Outcome::Done(_)));
    let attests = attests(replica(cluster, agent), agent, read);
    assert_eq!(attests.len(), 1);
    (agent, attests[0].clone())
}

/// The statement the worker makes of `attest`.
fn statement(attest: &Attest) -> Statement {
    Statement {
        format: FORMAT,
        program: PROGRAM,
        space: attest.roots[0].space,
        public_args: attest.public_args.clone(),
        output: attest.output.clone(),
        roots: attest.roots.clone(),
    }
}

/// Whether every running replica of `agent` holds statement `id` recorded.
fn recorded(cluster: &Cluster, agent: AgentId, id: &StatementId) -> bool {
    cluster.running().all(|(_, node)| {
        node.store()
            .snapshot()
            .get(agent, &keys::proven(&id.0))
            .unwrap()
            .is_some()
    })
}

/// The leader proves the read's statement once, every replica records it,
/// and once `S_0` is anchored it is submitted and accepted; the leader's
/// backlog then holds it accepted, nothing pending.
#[test]
fn a_reads_statement_is_proved_recorded_and_accepted() {
    let anchoring = Anchoring::new();
    let judging = Arc::new(Judging {
        model: Arc::clone(&anchoring.venue),
        accepted: Mutex::default(),
        submissions: AtomicUsize::new(0),
        hold: AtomicBool::new(false),
    });
    let proofs = Arc::new(Proofs::default());
    let cluster = cluster(&judging, &proofs);
    let (agent, attest) = stated(&cluster, &anchoring);
    let id = statement(&attest).id();
    wait_until("every replica records the statement proved", || {
        recorded(&cluster, agent, &id)
    });
    wait_until("the venue accepts the statement", || {
        judging.accepted.lock().unwrap().contains(&id.0)
    });
    assert_eq!(proofs.made.load(Ordering::SeqCst), 1, "proved once");
    assert_eq!(judging.submissions.load(Ordering::SeqCst), 1);
    let leader = cluster.node(cluster.leader(agent));
    wait_until("the leader's backlog holds it accepted", || {
        leader
            .prover_backlog()
            .is_some_and(|backlog| backlog.accepted == 1 && backlog.pending() == 0)
    });
}

/// The agent's leader proves and records the statement while `S_0` is held
/// unanchored, then stops, its proof with it. The new leader finds the
/// statement recorded, asks the others for its proof, proves it again once
/// none arrives, and submits it once the root is anchored; the venue holds
/// it accepted once, the old leader restarted as well.
#[test]
fn a_leader_change_submits_a_recorded_statement_once() {
    let anchoring = Anchoring::new();
    let judging = Arc::new(Judging {
        model: Arc::clone(&anchoring.venue),
        accepted: Mutex::default(),
        submissions: AtomicUsize::new(0),
        hold: AtomicBool::new(true),
    });
    let proofs = Arc::new(Proofs::default());
    let mut cluster = cluster(&judging, &proofs);
    let (agent, attest) = stated(&cluster, &anchoring);
    let id = statement(&attest).id();
    wait_until("every replica records the statement proved", || {
        recorded(&cluster, agent, &id)
    });
    assert_eq!(proofs.made.load(Ordering::SeqCst), 1);
    let old = cluster.leader(agent);
    cluster.stop(old);
    let new = cluster.leader(agent);
    assert_ne!(new, old);
    judging.hold.store(false, Ordering::SeqCst);
    wait_until("the venue accepts the statement", || {
        judging.accepted.lock().unwrap().contains(&id.0)
    });
    assert_eq!(proofs.made.load(Ordering::SeqCst), 2, "proved again, once");
    cluster.start(old);
    wait_until("every replica's worker is idle", || {
        cluster.running().all(|(_, node)| {
            node.prover_backlog()
                .is_none_or(|backlog| backlog.proving == 0 && backlog.queued == 0)
        })
    });
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(judging.accepted.lock().unwrap().len(), 1, "accepted once");
    assert_eq!(proofs.made.load(Ordering::SeqCst), 2);
}
