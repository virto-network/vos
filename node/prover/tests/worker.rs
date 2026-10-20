//! The worker over a model of its node, its prover and its venue: a
//! restart mid-proof leaves one proof, a submission made twice is accepted
//! once, a leader change proves nothing twice, a dead statement is skipped,
//! and a record whose re-run is not its statement is refused.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vos_node_prover::{
    Host, Jobs, MemoryJobs, Options, ProveError, Prover, REFUSED_RERUN, State, Worker,
};
use vos_venue::vos_statement::{ProgramId, Statement, StatementId};
use vos_venue::{AnchorRefusal, Anchored, NotAccepted, Status, Unjudged, VenueClient};
use vos_wire::ids::{AgentId, ProgramHash};
use vos_wire::result::Attest;
use vos_wire::vos_anchor::{
    Anchor, MAX_ROOT_AGE_MS, RootKind, RootRead, SpaceId, VenueId, WindowClock,
};

const AGENT: AgentId = AgentId(17);
const SPACE: SpaceId = SpaceId([0x5a; 32]);
const CLOCK: WindowClock = WindowClock {
    origin_ms: 0,
    length_ms: 600_000,
};
const KERNEL: &[u8] = b"a kernel's blob";

/// An attest at window `window`'s cut, told apart by `n`.
fn attest(window: u64, n: u8) -> Attest {
    Attest {
        program: ProgramHash::of(KERNEL),
        window: Some(window),
        witness_input: vec![n; 8],
        output: vec![n],
        public_args: vec![n, n],
        roots: vec![root(window)],
    }
}

fn root(window: u64) -> RootRead {
    RootRead {
        kind: RootKind::Space,
        space: SPACE,
        window,
        root: [window as u8; 32],
    }
}

/// The agent as its replicas apply it: its log's attests by index, and
/// the proofs it recorded.
#[derive(Default)]
struct Agent {
    log: Vec<Vec<Attest>>,
    proven: BTreeMap<[u8; 32], [u8; 32]>,
}

/// A node's blobs, by hash.
type Blobs = Arc<Mutex<HashMap<[u8; 32], Vec<u8>>>>;

/// A node: the agent it replicates, whether it leads it, its blobs, and
/// its peers' blobs, which it asks for a proof it lacks.
#[derive(Clone)]
struct Node {
    agent: Arc<Mutex<Agent>>,
    leads: Arc<AtomicBool>,
    blobs: Blobs,
    peers: Arc<Mutex<Vec<Blobs>>>,
    /// The proofs it asked its peers for, which arrive at the next ask.
    asked: Arc<Mutex<BTreeSet<[u8; 32]>>>,
}

impl Node {
    fn new(agent: &Arc<Mutex<Agent>>, leads: bool) -> Self {
        Self {
            agent: Arc::clone(agent),
            leads: Arc::new(AtomicBool::new(leads)),
            blobs: Arc::default(),
            peers: Arc::default(),
            asked: Arc::default(),
        }
    }

    fn peer(&self, other: &Node) {
        self.peers.lock().unwrap().push(Arc::clone(&other.blobs));
    }

    fn blobs(&self) -> usize {
        self.blobs.lock().unwrap().len()
    }
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    ProgramHash::of(bytes).0
}

impl Host for Node {
    fn leads(&self, _: AgentId) -> bool {
        self.leads.load(Ordering::SeqCst)
    }

    fn led(&self) -> Vec<AgentId> {
        if self.leads(AGENT) {
            vec![AGENT]
        } else {
            Vec::new()
        }
    }

    fn applied(&self, _: AgentId) -> u64 {
        self.agent.lock().unwrap().log.len() as u64
    }

    fn attests(&self, _: AgentId, index: u64) -> Result<Option<Vec<Attest>>, String> {
        let agent = self.agent.lock().unwrap();
        Ok(agent.log.get(index as usize - 1).cloned())
    }

    fn program(&self, hash: &ProgramHash) -> Option<Vec<u8>> {
        (*hash == ProgramHash::of(KERNEL)).then(|| KERNEL.to_vec())
    }

    fn proven(&self, _: AgentId, id: &StatementId) -> Option<[u8; 32]> {
        self.agent.lock().unwrap().proven.get(&id.0).copied()
    }

    fn keep(&self, proof: &[u8]) -> Result<[u8; 32], String> {
        let key = hash(proof);
        self.blobs.lock().unwrap().insert(key, proof.to_vec());
        Ok(key)
    }

    fn proof(&self, _: AgentId, key: &[u8; 32]) -> Option<Vec<u8>> {
        if let Some(bytes) = self.blobs.lock().unwrap().get(key) {
            return Some(bytes.clone());
        }
        if !self.asked.lock().unwrap().insert(*key) {
            let fetched = self
                .peers
                .lock()
                .unwrap()
                .iter()
                .find_map(|peer| peer.lock().unwrap().get(key).cloned());
            if let Some(bytes) = fetched {
                self.blobs.lock().unwrap().insert(*key, bytes);
            }
        }
        None
    }

    /// The leader's next batch records it: at once here.
    fn record(&self, _: AgentId, id: StatementId, proof: [u8; 32]) {
        self.agent
            .lock()
            .unwrap()
            .proven
            .entry(id.0)
            .or_insert(proof);
    }

    fn clock(&self) -> WindowClock {
        CLOCK
    }
}

/// A prover whose proofs differ each time, as masked proofs do: it panics
/// once when told to, as a node stopping mid-proof would, and refuses the
/// records whose output is `refused`.
#[derive(Default)]
struct Proofs {
    made: AtomicUsize,
    crash: AtomicBool,
    refused: Mutex<Option<Vec<u8>>>,
}

impl Prover for Proofs {
    fn program(&self, kernel: &[u8]) -> Result<ProgramId, ProveError> {
        Ok(ProgramId([kernel.len() as u32; 8]))
    }

    fn prove(&self, _: &[u8], attest: &Attest) -> Result<Vec<u8>, ProveError> {
        if self.crash.swap(false, Ordering::SeqCst) {
            panic!("the node stops mid-proof");
        }
        if self.refused.lock().unwrap().as_ref() == Some(&attest.output) {
            return Err(ProveError::Rerun("the io-hash is not the record's".into()));
        }
        let made = self.made.fetch_add(1, Ordering::SeqCst);
        Ok([b"proof".as_slice(), &attest.output, &made.to_le_bytes()].concat())
    }
}

/// A venue: its time, the roots it holds anchored, and each statement it
/// accepted, by id; its answer to the next submission lost when told to.
#[derive(Default)]
struct Venue {
    now: AtomicU64,
    anchored: Mutex<BTreeSet<u64>>,
    accepted: Mutex<BTreeSet<[u8; 32]>>,
    submissions: AtomicUsize,
    lose: AtomicBool,
}

impl Venue {
    fn at(now: u64) -> Arc<Self> {
        let venue = Self::default();
        venue.now.store(now, Ordering::SeqCst);
        Arc::new(venue)
    }

    fn anchor(&self, window: u64) {
        self.anchored.lock().unwrap().insert(window);
    }

    fn accepted(&self) -> usize {
        self.accepted.lock().unwrap().len()
    }
}

impl VenueClient for Venue {
    fn id(&self) -> VenueId {
        VenueId([0x7e; 32])
    }

    fn anchor(&self, _: &Anchor) -> Result<Anchored, AnchorRefusal> {
        Ok(Anchored::New)
    }

    fn submit(&self, statement: &Statement, _: &[u8]) -> Result<StatementId, NotAccepted> {
        self.submissions.fetch_add(1, Ordering::SeqCst);
        let id = statement.id();
        if !self.accepted.lock().unwrap().insert(id.0) {
            return Err(NotAccepted::Refused(6));
        }
        if self.lose.swap(false, Ordering::SeqCst) {
            return Err(NotAccepted::Unjudged(Unjudged::Unknown));
        }
        Ok(id)
    }

    fn anchored(&self, root: &RootRead) -> bool {
        self.anchored.lock().unwrap().contains(&root.window)
    }

    fn anchor_keys(&self, _: &SpaceId) -> Vec<[u8; 32]> {
        Vec::new()
    }

    fn status(&self, _: &SpaceId) -> Status {
        Status::Active
    }

    fn time(&self) -> Option<u64> {
        Some(self.now.load(Ordering::SeqCst))
    }
}

/// A second into window `window + 1`, its cut's close behind it.
fn after(window: u64) -> u64 {
    CLOCK.boundary(window).unwrap() + 1_000
}

/// A worker's settings: a proof taken to last five minutes, and a proof
/// another replica made asked for an hour.
fn options() -> Options {
    Options {
        expected: Duration::from_secs(300),
        patience: Duration::from_secs(3_600),
        ..Options::default()
    }
}

fn worker(
    node: &Node,
    jobs: &MemoryJobs,
    prover: &Arc<Proofs>,
    venue: &Arc<Venue>,
) -> Worker<Node, MemoryJobs> {
    worker_with(node, jobs, prover, venue, options())
}

fn worker_with(
    node: &Node,
    jobs: &MemoryJobs,
    prover: &Arc<Proofs>,
    venue: &Arc<Venue>,
    options: Options,
) -> Worker<Node, MemoryJobs> {
    Worker::open(
        node.clone(),
        jobs.clone(),
        Arc::clone(prover) as Arc<dyn Prover>,
        Arc::clone(venue) as Arc<dyn VenueClient>,
        options,
    )
    .unwrap()
}

/// Every job's state, in the table's order.
fn states(jobs: &MemoryJobs) -> Vec<State> {
    jobs.all()
        .unwrap()
        .into_iter()
        .map(|(_, job)| job.state)
        .collect()
}

/// A node stopping while it proves leaves its job proving and no proof;
/// opened again, it proves the statement once, keeps one proof, records it
/// and has it accepted.
#[test]
fn a_restart_mid_proof_leaves_one_proof() {
    let agent = Arc::new(Mutex::new(Agent::default()));
    agent.lock().unwrap().log.push(vec![attest(3, 1)]);
    let node = Node::new(&agent, true);
    let (jobs, prover, venue) = (
        MemoryJobs::default(),
        Arc::new(Proofs::default()),
        Venue::at(after(3)),
    );
    venue.anchor(3);
    prover.crash.store(true, Ordering::SeqCst);
    let mut first = worker(&node, &jobs, &prover, &venue);
    let stopped = std::panic::catch_unwind(AssertUnwindSafe(|| first.step()));
    assert!(stopped.is_err(), "stopped mid-proof");
    drop(first);
    assert_eq!(states(&jobs), [State::Proving]);
    assert_eq!(node.blobs(), 0, "no proof kept");

    let mut second = worker(&node, &jobs, &prover, &venue);
    assert_eq!(states(&jobs), [State::Queued], "queued again on opening");
    let stepped = second.step().unwrap();
    assert!(stepped.proved);
    second.step().unwrap();
    assert_eq!(states(&jobs), [State::Accepted]);
    assert_eq!(prover.made.load(Ordering::SeqCst), 1, "proved once");
    assert_eq!(node.blobs(), 1, "one proof kept");
    assert_eq!(agent.lock().unwrap().proven.len(), 1, "one proof recorded");
    assert_eq!(venue.accepted(), 1);
    // Read once: the record makes no second job.
    second.step().unwrap();
    assert_eq!(jobs.all().unwrap().len(), 1);
}

/// A submission whose answer is lost stays submitted and goes again; the
/// venue holds it once and answers the second a repeat, counted as
/// accepted. A statement the agent has not recorded proved waits for the
/// record, and one whose roots are not anchored for the anchor.
#[test]
fn a_duplicate_submission_is_accepted_once() {
    let agent = Arc::new(Mutex::new(Agent::default()));
    agent.lock().unwrap().log.push(vec![attest(3, 1)]);
    let node = Node::new(&agent, true);
    let (jobs, prover, venue) = (
        MemoryJobs::default(),
        Arc::new(Proofs::default()),
        Venue::at(after(3)),
    );
    let mut worker = worker(&node, &jobs, &prover, &venue);
    worker.step().unwrap();
    assert!(matches!(states(&jobs)[..], [State::Proved { .. }]));
    worker.step().unwrap();
    assert_eq!(
        venue.submissions.load(Ordering::SeqCst),
        0,
        "not anchored yet"
    );
    venue.anchor(3);
    venue.lose.store(true, Ordering::SeqCst);
    worker.step().unwrap();
    assert!(
        matches!(states(&jobs)[..], [State::Submitted { .. }]),
        "its answer lost"
    );
    worker.step().unwrap();
    assert_eq!(states(&jobs), [State::Accepted]);
    assert_eq!(venue.submissions.load(Ordering::SeqCst), 2);
    assert_eq!(venue.accepted(), 1, "accepted once");
    assert_eq!(prover.made.load(Ordering::SeqCst), 1);
}

/// Leadership moves after the first leader proved and recorded a statement,
/// before its roots were anchored: the new leader proves nothing again,
/// fetches the proof from the first and submits it; the first, no longer
/// leading, submits nothing. A statement recorded after the change is
/// proved by the new leader. Without the first's proof, the new leader
/// proves the recorded statement itself once its patience ends.
#[test]
fn a_leader_change_proves_nothing_twice() {
    let agent = Arc::new(Mutex::new(Agent::default()));
    agent.lock().unwrap().log.push(vec![attest(3, 1)]);
    let (a, b) = (Node::new(&agent, true), Node::new(&agent, false));
    b.peer(&a);
    let (prover, venue) = (Arc::new(Proofs::default()), Venue::at(after(3)));
    let (a_jobs, b_jobs) = (MemoryJobs::default(), MemoryJobs::default());
    let mut on_a = worker(&a, &a_jobs, &prover, &venue);
    let mut on_b = worker(&b, &b_jobs, &prover, &venue);
    on_a.step().unwrap();
    on_b.step().unwrap();
    assert!(b_jobs.all().unwrap().is_empty(), "a follower reads nothing");
    assert_eq!(agent.lock().unwrap().proven.len(), 1);

    a.leads.store(false, Ordering::SeqCst);
    b.leads.store(true, Ordering::SeqCst);
    venue.anchor(3);
    agent.lock().unwrap().log.push(vec![attest(4, 2)]);
    venue.now.store(after(4), Ordering::SeqCst);
    venue.anchor(4);
    for _ in 0..4 {
        on_a.step().unwrap();
        on_b.step().unwrap();
    }
    assert!(
        matches!(states(&a_jobs)[..], [State::Proved { .. }]),
        "the old leader holds it"
    );
    assert_eq!(states(&b_jobs), [State::Accepted, State::Accepted]);
    assert_eq!(
        prover.made.load(Ordering::SeqCst),
        2,
        "each statement proved once"
    );
    assert_eq!(venue.accepted(), 2);
    assert_eq!(b.blobs(), 2, "the first's proof fetched, the second's made");

    // A third statement proved by a leader whose proof then is lost: the
    // next proves it again.
    agent.lock().unwrap().log.push(vec![attest(5, 3)]);
    venue.now.store(after(5), Ordering::SeqCst);
    on_b.step().unwrap();
    b.blobs.lock().unwrap().clear();
    b.leads.store(false, Ordering::SeqCst);
    let c = Node::new(&agent, true);
    let c_jobs = MemoryJobs::default();
    let impatient = Options {
        patience: Duration::ZERO,
        ..options()
    };
    let mut on_c = worker_with(&c, &c_jobs, &prover, &venue, impatient);
    venue.anchor(5);
    for _ in 0..6 {
        on_c.step().unwrap();
    }
    let accepted = states(&c_jobs)
        .into_iter()
        .filter(|state| *state == State::Accepted)
        .count();
    assert_eq!(accepted, 3, "{:?}", states(&c_jobs));
    assert_eq!(
        prover.made.load(Ordering::SeqCst),
        6,
        "the lost proofs proved again"
    );
    assert_eq!(venue.accepted(), 3);
}

/// A statement whose anchor would pass `MaxRootAge` by the venue's time
/// before its proof ends is dead, never proved; one proved whose anchor
/// then ages is dead, never submitted.
#[test]
fn a_dead_statement_is_skipped() {
    let agent = Arc::new(Mutex::new(Agent::default()));
    agent.lock().unwrap().log.push(vec![attest(3, 1)]);
    let node = Node::new(&agent, true);
    let deadline = CLOCK.boundary(3).unwrap() + MAX_ROOT_AGE_MS;
    let expected = options().expected.as_millis() as u64;
    let (jobs, prover, venue) = (
        MemoryJobs::default(),
        Arc::new(Proofs::default()),
        Venue::at(deadline - expected + 1),
    );
    venue.anchor(3);
    let mut worker = worker(&node, &jobs, &prover, &venue);
    worker.step().unwrap();
    assert_eq!(states(&jobs), [State::Dead]);
    assert_eq!(prover.made.load(Ordering::SeqCst), 0, "never proved");

    agent.lock().unwrap().log.push(vec![attest(4, 2)]);
    let deadline = CLOCK.boundary(4).unwrap() + MAX_ROOT_AGE_MS;
    venue.now.store(deadline - expected, Ordering::SeqCst);
    worker.step().unwrap();
    let proved = |state: &State| matches!(state, State::Proved { .. });
    assert!(states(&jobs).iter().any(proved));
    venue.now.store(deadline + 1, Ordering::SeqCst);
    venue.anchor(4);
    worker.step().unwrap();
    assert_eq!(states(&jobs), [State::Dead, State::Dead]);
    assert_eq!(
        venue.submissions.load(Ordering::SeqCst),
        0,
        "never submitted"
    );
    let backlog = worker.backlog().unwrap();
    assert_eq!((backlog.dead, backlog.pending()), (2, 0));
    assert_eq!(worker.prune().unwrap(), 2, "pruned once aged");
}

/// A record whose re-run is not its statement (its io-hash not the
/// record's) is refused by the prover, never kept, recorded or submitted;
/// the next record is proved.
#[test]
fn an_io_hash_mismatch_is_refused() {
    let agent = Arc::new(Mutex::new(Agent::default()));
    agent
        .lock()
        .unwrap()
        .log
        .push(vec![attest(3, 1), attest(3, 2)]);
    let node = Node::new(&agent, true);
    let (jobs, prover, venue) = (
        MemoryJobs::default(),
        Arc::new(Proofs::default()),
        Venue::at(after(3)),
    );
    venue.anchor(3);
    *prover.refused.lock().unwrap() = Some(vec![1]);
    let mut worker = worker(&node, &jobs, &prover, &venue);
    for _ in 0..3 {
        worker.step().unwrap();
    }
    let mut states = states(&jobs);
    states.sort_by_key(|state| matches!(state, State::Accepted));
    assert_eq!(states, [State::Refused(REFUSED_RERUN), State::Accepted]);
    assert_eq!(node.blobs(), 1);
    assert_eq!(agent.lock().unwrap().proven.len(), 1);
    assert_eq!(venue.accepted(), 1);
    let backlog = worker.backlog().unwrap();
    assert_eq!((backlog.refused, backlog.accepted), (1, 1));
}
