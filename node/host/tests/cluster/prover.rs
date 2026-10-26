//! The prover worker on three nodes: the leader of an agent whose read at
//! a window's cut is served proves its statement, has the agent record it
//! (`Input::Proven`) on every replica, and submits it once the space's
//! root is anchored; a leader stopped after recording its proof and before
//! submitting it leaves a new leader that proves it again, the proof gone
//! with the old, and the venue holds it accepted once, however late the
//! new leader's worker read its record; a record applied
//! during a proof, its log compacted past it, is proved; and a replica that
//! installs a snapshot past a queued statement's record holds its job, and
//! proves it once it leads.
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
use vos_venue::VenueClient;
use vos_venue::vos_statement::{ProgramId, Statement, StatementId};
use vos_wire::batch::Request;
use vos_wire::ids::{AgentId, Session};
use vos_wire::peer::NodeNumber;
use vos_wire::result::{Attest, Outcome};
use vos_wire::{Decode, keys};

use crate::common::{Cluster, log_start, wait_until};
use crate::support::past_close;
use crate::support::{Anchoring, Judging, attests, ended, holds, replica};
use crate::support::{ask_in, call, clock, later, reader_agent, write, writes};

/// The model prover's program id for every kernel.
const PROGRAM: ProgramId = ProgramId([7; 8]);

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

/// [`Proofs`] on node `node`, which fails every proof while it is the
/// node `failing` names.
struct NodeProofs {
    proofs: Arc<Proofs>,
    node: NodeNumber,
    failing: Arc<AtomicUsize>,
}

impl Prover for NodeProofs {
    fn program(&self, kernel: &[u8]) -> Result<ProgramId, ProveError> {
        self.proofs.program(kernel)
    }

    fn prove(&self, kernel: &[u8], attest: &Attest) -> Result<Vec<u8>, ProveError> {
        if self.failing.load(Ordering::SeqCst) == usize::from(self.node) {
            return Err(ProveError::Failed("this node's prover fails"));
        }
        self.proofs.prove(kernel, attest)
    }
}

/// [`Proofs`] on node `node`, whose worker reads no record while
/// `waiting` names the node: no kernel's program id is computed then.
struct Waiting {
    proofs: Arc<Proofs>,
    node: NodeNumber,
    waiting: Arc<Mutex<BTreeSet<NodeNumber>>>,
}

impl Prover for Waiting {
    fn program(&self, kernel: &[u8]) -> Result<ProgramId, ProveError> {
        if self.waiting.lock().unwrap().contains(&self.node) {
            return Err(ProveError::Failed("this node's worker waits"));
        }
        self.proofs.program(kernel)
    }

    fn prove(&self, kernel: &[u8], attest: &Attest) -> Result<Vec<u8>, ProveError> {
        self.proofs.prove(kernel, attest)
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
    let prover: Arc<dyn Prover> = proofs.clone();
    cluster_with(judging, move |_| Arc::clone(&prover))
}

/// [`cluster`], node `n` proving with `prover(n)`.
fn cluster_with(
    judging: &Arc<Judging>,
    prover: impl Fn(NodeNumber) -> Arc<dyn Prover> + Send + Sync + 'static,
) -> Cluster {
    let venue: Arc<dyn VenueClient> = judging.clone();
    Cluster::in_space(
        3,
        Some(clock()),
        move |node: NodeNumber, config: &mut Config| {
            config.venue = Some(Arc::clone(&venue));
            config.prover = Some(prover(node));
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
    anchoring.set_clocks(cluster, past_close(&clock, window));
    assert!(matches!(ended(cluster, agent, read), Outcome::Done(_)));
    let attests = attests(replica(cluster, agent), agent, read);
    assert_eq!(attests.len(), 1);
    attests[0].clone()
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
    let judging = Arc::new(Judging::new(Arc::clone(&anchoring.venue), false));
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
/// it accepted once, the old leader restarted as well. Every replica keeps
/// the record with its witness.
#[test]
fn a_leader_change_submits_a_recorded_statement_once() {
    let anchoring = Anchoring::new();
    let judging = Arc::new(Judging::new(Arc::clone(&anchoring.venue), true));
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
    for (_, node) in cluster.running() {
        let record = node
            .store()
            .snapshot()
            .get(agent, &keys::attested(0, &attest.digest()))
            .unwrap()
            .and_then(|bytes| Attest::decode_exact(&bytes))
            .expect("its record kept");
        assert_eq!(record, attest, "with its witness");
    }
}

/// The followers' workers read no record until the leader's proof is
/// recorded, so they read the statement's record only after its `Proven`
/// applies. The leader then stops, its proof with it; the new leader proves
/// the statement again from the record, which every replica keeps with its
/// witness, and the venue holds it accepted once.
#[test]
fn a_record_read_after_its_proof_is_recorded_is_proved_again() {
    let anchoring = Anchoring::new();
    let judging = Arc::new(Judging::new(Arc::clone(&anchoring.venue), true));
    let proofs = Arc::new(Proofs::default());
    let waiting = Arc::new(Mutex::new(BTreeSet::new()));
    let (shared, gate) = (Arc::clone(&proofs), Arc::clone(&waiting));
    let mut cluster = cluster_with(&judging, move |node| {
        Arc::new(Waiting {
            proofs: Arc::clone(&shared),
            node,
            waiting: Arc::clone(&gate),
        })
    });
    anchoring.register(&cluster);
    let agents = Agents {
        representative: cluster.representative(&[1, 2, 3]),
        reader: reader_agent(&cluster, &[1, 2, 3]),
    };
    let agent = agents.reader;
    write(&cluster, agent, 1..=20);
    let leader = cluster.leader(agent);
    let followers: Vec<NodeNumber> = (1..=3).filter(|node| *node != leader).collect();
    waiting.lock().unwrap().extend(&followers);
    let attest = read_at(
        &cluster,
        &anchoring,
        &agents,
        0,
        (cluster.session(agent), 21),
    );
    let id = statement(&attest).id();
    wait_until("every replica records the statement proved", || {
        recorded(&cluster, agent, &id)
    });
    assert_eq!(proofs.made.load(Ordering::SeqCst), 1);
    waiting.lock().unwrap().clear();
    for &follower in &followers {
        let node = cluster.node(follower);
        wait_until("the follower's worker holds the statement proved", || {
            node.store()
                .prover_jobs()
                .unwrap()
                .iter()
                .any(|(_, held, job)| {
                    *held == id.0
                        && Job::decode_exact(job)
                            .is_some_and(|job| matches!(job.state, State::Proved { .. }))
                })
        });
    }
    cluster.stop(leader);
    assert_ne!(cluster.leader(agent), leader);
    judging.hold.store(false, Ordering::SeqCst);
    wait_until("the venue accepts the statement", || {
        judging.accepted.lock().unwrap().contains(&id.0)
    });
    assert_eq!(proofs.made.load(Ordering::SeqCst), 2, "proved again, once");
    assert_eq!(judging.accepted.lock().unwrap().len(), 1, "accepted once");
}

/// A record applied while the leader proves another is proved, however far
/// the log is compacted past it: every replica holds it in the agent's
/// state until its statement is recorded proved.
#[test]
fn a_record_applied_during_a_proof_is_proved() {
    let anchoring = Anchoring::new();
    let judging = Arc::new(Judging::new(Arc::clone(&anchoring.venue), false));
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
    wait_until("a leader proves the first statement", || {
        cluster.running().any(|(_, node)| proving(node))
    });
    let session = later(&cluster, agent);
    let second = read_at(&cluster, &anchoring, &agents, 1, (session, 1));
    let index = replica(&cluster, agent).applied(agent).unwrap();
    write_in(&cluster, agent, later(&cluster, agent), 1..=60);
    cluster.compacted_past(agent, index);
    for (_, node) in cluster.running() {
        let held = node
            .store()
            .snapshot()
            .get(agent, &keys::attested(1, &second.digest()))
            .unwrap();
        assert!(held.is_some(), "the second's record held");
    }
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
}

/// A replica that installs a snapshot past a queued statement's record
/// holds its job: the agent's leader's prover fails every proof, so the
/// statement stays queued, while a follower, down when the read was
/// served, comes back by a snapshot of the leader's compacted log. Its
/// table holds the statement queued, from the records in the snapshot.
/// Once the leader stops, the new leader proves it once, and the venue
/// holds it accepted.
#[test]
fn a_snapshot_installed_replica_proves_a_queued_statement() {
    let anchoring = Anchoring::new();
    let judging = Arc::new(Judging::new(Arc::clone(&anchoring.venue), false));
    let proofs = Arc::new(Proofs::default());
    let failing = Arc::new(AtomicUsize::new(0));
    let venue: Arc<dyn VenueClient> = judging.clone();
    let (shared, failed) = (Arc::clone(&proofs), Arc::clone(&failing));
    let mut cluster = Cluster::in_space(3, Some(clock()), move |node, config: &mut Config| {
        config.venue = Some(Arc::clone(&venue));
        config.prover = Some(Arc::new(NodeProofs {
            proofs: Arc::clone(&shared),
            node,
            failing: Arc::clone(&failed),
        }));
        config.compact_every = 8;
        config.compact_tail = 2;
        config.snapshot_chunk = 64;
    });
    anchoring.register(&cluster);
    let agents = Agents {
        representative: cluster.representative(&[1, 2, 3]),
        reader: reader_agent(&cluster, &[1, 2, 3]),
    };
    let agent = agents.reader;
    write(&cluster, agent, 1..=20);
    let (leader, follower) = cluster.leader_and_follower(agent);
    failing.store(usize::from(leader), Ordering::SeqCst);
    let stopped_at = cluster.node(follower).applied(agent).unwrap();
    cluster.stop(follower);
    let attest = read_at(
        &cluster,
        &anchoring,
        &agents,
        0,
        (cluster.session(agent), 21),
    );
    let id = statement(&attest).id();
    write_in(&cluster, agent, later(&cluster, agent), 1..=40);
    cluster.compacted_past(agent, stopped_at + 30);
    cluster.start(follower);
    let back = cluster.node(follower);
    wait_until("the follower installs a snapshot and holds the job", || {
        log_start(back, agent) > stopped_at
            && back
                .store()
                .prover_jobs()
                .unwrap()
                .iter()
                .any(|(_, held, job)| {
                    *held == id.0
                        && Job::decode_exact(job).is_some_and(|job| job.state == State::Queued)
                })
    });
    assert_eq!(proofs.made.load(Ordering::SeqCst), 0, "not proved yet");
    cluster.stop(leader);
    wait_until("the venue accepts the statement", || {
        judging.accepted.lock().unwrap().contains(&id.0)
    });
    assert_eq!(proofs.made.load(Ordering::SeqCst), 1, "proved once");
    assert_eq!(judging.accepted.lock().unwrap().len(), 1);
}
