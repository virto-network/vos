//! The worker's model of its node, its prover and its venue, and the job
//! table it keeps in memory ([`MemoryJobs`]).

mod memory;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vos_node_prover::{Host, Jobs, Options, ProveError, Prover, State, Worker};
use vos_venue::vos_statement::{ProgramId, Statement, StatementId};
use vos_venue::{AnchorRefusal, Anchored, NotAccepted, Status, Unjudged, VenueClient};
use vos_wire::ids::{AgentId, ProgramHash};
use vos_wire::result::Attest;
use vos_wire::vos_anchor::{Anchor, RootKind, RootRead, SpaceId, VenueId, WindowClock};

pub(crate) use memory::MemoryJobs;

pub(crate) const AGENT: AgentId = AgentId(17);
pub(crate) const SPACE: SpaceId = SpaceId([0x5a; 32]);
pub(crate) const CLOCK: WindowClock = WindowClock {
    origin_ms: 0,
    length_ms: 600_000,
};
pub(crate) const KERNEL: &[u8] = b"a kernel's blob";

/// An attest at window `window`'s cut, told apart by `n`.
pub(crate) fn attest(window: u64, n: u8) -> Attest {
    Attest {
        program: ProgramHash::of(KERNEL),
        window: Some(window),
        witness_input: vec![n; 8],
        output: vec![n],
        public_args: vec![n, n],
        roots: vec![root(window)],
    }
}

pub(crate) fn root(window: u64) -> RootRead {
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
pub(crate) struct Agent {
    pub(crate) log: Vec<Vec<Attest>>,
    /// The log's entries through this index compacted away.
    pub(crate) compacted: u64,
    pub(crate) proven: BTreeMap<[u8; 32], [u8; 32]>,
}

/// A node's blobs, by hash.
pub(crate) type Blobs = Arc<Mutex<HashMap<[u8; 32], Vec<u8>>>>;

/// A node: the agent it replicates, whether it leads it, its blobs, and
/// its peers' blobs, which it asks for a proof it lacks.
#[derive(Clone)]
pub(crate) struct Node {
    pub(crate) agent: Arc<Mutex<Agent>>,
    pub(crate) leads: Arc<AtomicBool>,
    pub(crate) blobs: Blobs,
    pub(crate) peers: Arc<Mutex<Vec<Blobs>>>,
    /// The proofs it asked its peers for, which arrive at the next ask.
    pub(crate) asked: Arc<Mutex<BTreeSet<[u8; 32]>>>,
    /// The proofs it holds pinned.
    pub(crate) pins: Arc<Mutex<BTreeSet<[u8; 32]>>>,
}

impl Node {
    pub(crate) fn new(agent: &Arc<Mutex<Agent>>, leads: bool) -> Self {
        Self {
            agent: Arc::clone(agent),
            leads: Arc::new(AtomicBool::new(leads)),
            blobs: Arc::default(),
            peers: Arc::default(),
            asked: Arc::default(),
            pins: Arc::default(),
        }
    }

    pub(crate) fn peer(&self, other: &Node) {
        self.peers.lock().unwrap().push(Arc::clone(&other.blobs));
    }

    pub(crate) fn blobs(&self) -> usize {
        self.blobs.lock().unwrap().len()
    }
}

pub(crate) fn hash(bytes: &[u8]) -> [u8; 32] {
    ProgramHash::of(bytes).0
}

impl Host for Node {
    fn leads(&self, _: AgentId) -> bool {
        self.leads.load(Ordering::SeqCst)
    }

    fn agents(&self) -> Vec<AgentId> {
        vec![AGENT]
    }

    fn applied(&self, _: AgentId) -> u64 {
        self.agent.lock().unwrap().log.len() as u64
    }

    fn attests(&self, _: AgentId, index: u64) -> Result<Option<Vec<Attest>>, String> {
        let agent = self.agent.lock().unwrap();
        if index <= agent.compacted {
            return Ok(None);
        }
        Ok(agent.log.get(index as usize - 1).cloned())
    }

    fn program(&self, hash: &ProgramHash) -> Option<Vec<u8>> {
        (*hash == ProgramHash::of(KERNEL)).then(|| KERNEL.to_vec())
    }

    fn proven(&self, _: AgentId, _: u64, id: &StatementId) -> Option<[u8; 32]> {
        self.agent.lock().unwrap().proven.get(&id.0).copied()
    }

    fn keep(&self, proof: &[u8]) -> Result<[u8; 32], String> {
        let key = hash(proof);
        self.blobs.lock().unwrap().insert(key, proof.to_vec());
        Ok(key)
    }

    fn hold(&self, key: &[u8; 32], held: bool) {
        let mut pins = self.pins.lock().unwrap();
        match held {
            true => pins.insert(*key),
            false => pins.remove(key),
        };
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
    fn record(&self, _: AgentId, _: u64, id: StatementId, proof: [u8; 32]) {
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

/// A prover whose proofs differ each time, as masked proofs do: once when
/// told to it never returns, as a node stopped mid-proof; it panics while
/// told to; and it refuses the records whose output is `refused`.
#[derive(Default)]
pub(crate) struct Proofs {
    pub(crate) made: AtomicUsize,
    pub(crate) stop: AtomicBool,
    pub(crate) panics: AtomicBool,
    pub(crate) refused: Mutex<Option<Vec<u8>>>,
}

impl Prover for Proofs {
    fn program(&self, kernel: &[u8]) -> Result<ProgramId, ProveError> {
        Ok(ProgramId([kernel.len() as u32; 8]))
    }

    fn prove(&self, _: &[u8], attest: &Attest) -> Result<Vec<u8>, ProveError> {
        if self.stop.swap(false, Ordering::SeqCst) {
            loop {
                std::thread::park();
            }
        }
        if self.panics.load(Ordering::SeqCst) {
            panic!("the prover fails");
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
pub(crate) struct Venue {
    pub(crate) now: AtomicU64,
    pub(crate) anchored: Mutex<BTreeSet<u64>>,
    pub(crate) accepted: Mutex<BTreeSet<[u8; 32]>>,
    pub(crate) submissions: AtomicUsize,
    pub(crate) lose: AtomicBool,
    /// The codes the next submissions are refused with, in order.
    pub(crate) refuse: Mutex<Vec<u32>>,
    /// Every answer lost while set.
    pub(crate) lose_all: AtomicBool,
    /// Every answer lost while set, the statement accepted all the same.
    pub(crate) lose_landed: AtomicBool,
    /// The submissions answered unfunded still to come.
    pub(crate) unfunded: AtomicUsize,
}

impl Venue {
    pub(crate) fn at(now: u64) -> Arc<Self> {
        let venue = Self::default();
        venue.now.store(now, Ordering::SeqCst);
        Arc::new(venue)
    }

    pub(crate) fn anchor(&self, window: u64) {
        self.anchored.lock().unwrap().insert(window);
    }

    pub(crate) fn accepted(&self) -> usize {
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
        let mut refuse = self.refuse.lock().unwrap();
        if !refuse.is_empty() {
            return Err(NotAccepted::Refused(refuse.remove(0)));
        }
        drop(refuse);
        let id = statement.id();
        if !self.accepted.lock().unwrap().insert(id.0) {
            return Err(NotAccepted::Refused(6));
        }
        if self
            .unfunded
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok()
        {
            self.accepted.lock().unwrap().remove(&id.0);
            return Err(NotAccepted::Unjudged(Unjudged::Funding));
        }
        if self.lose_landed.load(Ordering::SeqCst) {
            return Err(NotAccepted::Unjudged(Unjudged::Unknown));
        }
        if self.lose_all.load(Ordering::SeqCst) {
            self.accepted.lock().unwrap().remove(&id.0);
            return Err(NotAccepted::Unjudged(Unjudged::Unknown));
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

    fn unsettled(&self, _: &SpaceId) -> Vec<Anchor> {
        Vec::new()
    }
}

/// A second into window `window + 1`, its cut's close behind it.
pub(crate) fn after(window: u64) -> u64 {
    CLOCK.boundary(window).unwrap() + 1_000
}

/// A worker's settings: a proof taken to last five minutes, and a proof
/// another replica made asked for an hour.
pub(crate) fn options() -> Options {
    Options {
        expected: Duration::from_secs(300),
        patience: Duration::from_secs(3_600),
        ..Options::default()
    }
}

pub(crate) fn worker(
    node: &Node,
    jobs: &MemoryJobs,
    prover: &Arc<Proofs>,
    venue: &Arc<Venue>,
) -> Worker<Node, MemoryJobs> {
    worker_with(node, jobs, prover, venue, options())
}

pub(crate) fn worker_with(
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
pub(crate) fn states(jobs: &MemoryJobs) -> Vec<State> {
    jobs.all()
        .unwrap()
        .into_iter()
        .map(|(_, job)| job.state)
        .collect()
}
