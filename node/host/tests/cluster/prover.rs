//! The prover worker on three nodes: the leader of an agent whose read at
//! a window's cut is served proves its statement, has the agent record it
//! (`Input::Proven`) on every replica, and submits it once the space's
//! root is anchored; a leader stopped after recording its proof and before
//! submitting it leaves a new leader that proves it again, the proof gone
//! with the old, and the venue holds it accepted once; a record applied
//! during a proof, its log compacting every few entries, is proved.
//!
//! The proofs are a model prover's (the masked prover proves in minutes,
//! `just test-proof`'s), so the venue judges anchors as the model venue
//! does and takes a statement once by its id.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vos_node::{Config, Node};
use vos_node_prover::{FORMAT, Job, Options, ProveError, Prover, State};
use vos_venue::vos_statement::{ProgramId, Statement, StatementId};
use vos_venue::{AnchorRefusal, Anchored, ModelVenue, NotAccepted, Status, VenueClient};
use vos_wire::batch::Request;
use vos_wire::ids::{AgentId, Session};
use vos_wire::peer::NodeNumber;
use vos_wire::result::{Attest, Outcome};
use vos_wire::vos_anchor::{Anchor, RootRead, SpaceId, VenueId};
use vos_wire::{Decode, keys};

use crate::common::{Cluster, log_start, wait_until};
use crate::cuts::{ask_in, call, clock, reader_agent, write, writes};
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

    fn unsettled(&self, space: &SpaceId) -> Vec<Anchor> {
        self.model.unsettled(space)
    }
}

/// A prover whose proofs differ each time, as masked proofs do, each
/// held while `hold` is set.
#[derive(Default)]
struct Proofs {
    made: AtomicUsize,
    hold: AtomicBool,
}

impl Prover for Proofs {
    fn program(&self, _: &[u8]) -> Result<ProgramId, ProveError> {
        Ok(PROGRAM)
    }

    fn prove(&self, _: &[u8], attest: &Attest) -> Result<Vec<u8>, ProveError> {
        while self.hold.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }
        let made = self.made.fetch_add(1, Ordering::SeqCst);
        Ok([b"proof".as_slice(), &attest.output, &made.to_le_bytes()].concat())
    }
}

/// Releases a held prover when dropped: a test that fails while it holds
/// one stops its nodes all the same.
struct Released(Arc<Proofs>);

impl Drop for Released {
    fn drop(&mut self) {
        self.0.hold.store(false, Ordering::SeqCst);
    }
}

/// Three nodes in a space anchoring at `judging`, each proving with
/// `proofs`, a proof another replica made asked for two seconds; each
/// group's log compacted every 8 entries to a tail of 2, so a record the
/// prover's scan has not read would go at once but for its mark.
fn cluster(judging: &Arc<Judging>, proofs: &Arc<Proofs>) -> Cluster {
    let venue: Arc<dyn VenueClient> = judging.clone();
    let prover: Arc<dyn Prover> = proofs.clone();
    Cluster::in_space(
        3,
        Some(clock()),
        move |_: NodeNumber, config: &mut Config| {
            config.venue = Some(Arc::clone(&venue));
            config.prover = Some(Arc::clone(&prover));
            config.compact_every = 8;
            config.compact_tail = 2;
            config.prover_options = Options {
                patience: Duration::from_secs(2),
                ..Options::default()
            };
        },
    )
}

/// The space's representative and a reader agent on the three nodes.
struct Agents {
    representative: AgentId,
    reader: AgentId,
}

/// A reader agent on the three nodes, its read at window 0's cut served
/// and stated against the anchored `S_0`: the agents and the attest.
fn stated(cluster: &Cluster, anchoring: &Anchoring) -> (Agents, Attest) {
    anchoring.register(cluster);
    let agents = Agents {
        representative: cluster.representative(&[1, 2, 3]),
        reader: reader_agent(cluster, &[1, 2, 3]),
    };
    write(cluster, agents.reader, 1..=20);
    let attest = read_at(
        cluster,
        anchoring,
        &agents,
        0,
        (cluster.session(agents.reader), 21),
    );
    (agents, attest)
}

/// `agent`'s read asked now in window `window`, a request of a session and
/// its sequence, served at its cut once the clocks pass its close and
/// stated against `S_w`.
fn read_at(
    cluster: &Cluster,
    anchoring: &Anchoring,
    agents: &Agents,
    window: u64,
    (session, sequence): (Session, u64),
) -> Attest {
    let clock = clock();
    let boundary = clock.boundary(window).unwrap();
    let (representative, agent) = (agents.representative, agents.reader);
    let (read, ..) = ask_in(cluster, agent, session, sequence, window);
    anchoring.set_clocks(cluster, boundary + 1_000);
    wait_until("the representative holds the agent's root", || {
        holds(
            replica(cluster, representative),
            representative,
            agent,
            window,
        )
    });
    anchoring.set_clocks(cluster, boundary + delay(&clock) + 1_000);
    assert!(matches!(ended(cluster, agent, read), Outcome::Done(_)));
    let attests = attests(replica(cluster, agent), agent, read);
    assert_eq!(attests.len(), 1);
    attests[0].clone()
}

/// A session opened at `agent`'s leader's time now: the clocks have moved
/// past the cluster's session's expiry.
fn later(cluster: &Cluster, agent: AgentId) -> Session {
    let t0 = cluster.clock(cluster.leader(agent));
    Session {
        key: [1; 32],
        name: t0.to_le_bytes().repeat(2).try_into().unwrap(),
        t0,
    }
}

/// Requests `sequences` of `session`, writing `agent`'s rows.
fn write_in(
    cluster: &Cluster,
    agent: AgentId,
    session: Session,
    sequences: std::ops::RangeInclusive<u64>,
) {
    for sequence in sequences {
        let request = Request {
            session,
            ..writes(cluster, agent, sequence)
        };
        assert!(matches!(call(cluster, agent, request), Outcome::Done(_)));
    }
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
            .get(agent, &keys::proven(0, &id.0))
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
    let (agents, attest) = stated(&cluster, &anchoring);
    let agent = agents.reader;
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
    let (agents, attest) = stated(&cluster, &anchoring);
    let agent = agents.reader;
    let id = statement(&attest).id();
    wait_until("every replica records the statement proved", || {
        recorded(&cluster, agent, &id)
    });
    assert_eq!(proofs.made.load(Ordering::SeqCst), 1);
    let old = cluster.leader(agent);
    cluster.stop(old);
    let new = cluster.leader(agent);
    assert_ne!(new, old);
    // The new leader's log compacted past the record: its job, read while
    // it followed, stays.
    write_in(&cluster, agent, later(&cluster, agent), 1..=40);
    let node = cluster.node(new);
    wait_until("the new leader's log compacts", || {
        log_start(node, agent) > 2
    });
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
    let backlog = cluster.node(new).prover_backlog().unwrap();
    assert_eq!(backlog.lost, 0, "no record lost to compaction");
}

/// A record applied while the leader proves another stays in the log until
/// the prover's scan reads it, however many entries follow, and is proved:
/// the log compacts no further than the scan's mark while the proof runs.
#[test]
fn a_record_applied_during_a_proof_is_proved() {
    let anchoring = Anchoring::new();
    let judging = Arc::new(Judging {
        model: Arc::clone(&anchoring.venue),
        accepted: Mutex::default(),
        submissions: AtomicUsize::new(0),
        hold: AtomicBool::new(false),
    });
    let proofs = Arc::new(Proofs::default());
    proofs.hold.store(true, Ordering::SeqCst);
    let cluster = cluster(&judging, &proofs);
    let _released = Released(Arc::clone(&proofs));
    let (agents, first) = stated(&cluster, &anchoring);
    let agent = agents.reader;
    let proving = |node: &Node| {
        node.store()
            .prover_jobs()
            .unwrap()
            .iter()
            .any(|(_, _, job)| {
                Job::decode_exact(job).is_some_and(|job| job.state == State::Proving)
            })
    };
    let mut prover = None;
    wait_until("a leader proves the first statement", || {
        prover = cluster
            .running()
            .find(|(_, node)| proving(node))
            .map(|(number, _)| number);
        prover.is_some()
    });
    let node = cluster.node(prover.unwrap());
    let session = later(&cluster, agent);
    let second = read_at(&cluster, &anchoring, &agents, 1, (session, 1));
    write_in(&cluster, agent, later(&cluster, agent), 1..=60);
    let mark = node.store().prover_mark(agent).unwrap();
    let applied = node.applied(agent).unwrap();
    assert!(
        applied > mark + 40,
        "the log runs past the mark: {mark}, {applied}"
    );
    assert!(
        log_start(node, agent) <= mark,
        "compacted to the mark at most"
    );
    proofs.hold.store(false, Ordering::SeqCst);
    for attest in [&first, &second] {
        let id = statement(attest).id();
        wait_until("the venue accepts the statement", || {
            judging.accepted.lock().unwrap().contains(&id.0)
        });
    }
    // A leader change under load may prove a statement once more; the
    // venue holds each accepted once.
    assert!(proofs.made.load(Ordering::SeqCst) >= 2);
    assert_eq!(judging.accepted.lock().unwrap().len(), 2);
    for (_, node) in cluster.running() {
        let backlog = node.prover_backlog().unwrap();
        assert_eq!(backlog.lost, 0, "no record lost to compaction");
    }
}
