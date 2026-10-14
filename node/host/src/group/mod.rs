//! An agent's replica group on this node: its consensus core, driven by
//! the node's log writer and the network, and its applier, which applies
//! the committed log in order, the same way on every replica.

mod apply;
mod driver;
mod snapshot;

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use vos_raft::core::{ChangeMembershipError, Core, ProposeError, ReadIndexError};
use vos_raft::{Message, Role};
use vos_wire::ids::AgentId;
use vos_wire::peer::{CreationRecord, NodeNumber, Order, SnapshotAck, SnapshotChunk};

use crate::blobs::Held;
use crate::lock;
use crate::node::Inner;
use crate::raft::EntryReports;
use driver::Asks;

pub(crate) use apply::{DryRun, apply, programs, unpinned};
use snapshot::{Install, Shipment};
pub(crate) use snapshot::{drop_stale_epochs, empty_epoch};

/// Where a proposal's answer goes: the index it took, or why not, and
/// when the driver answered.
pub(crate) type Proposed = smol::channel::Sender<(Result<u64, ProposeError>, Instant)>;

/// What a group hears from the network and the node: bounded, and
/// dropped when full.
pub(crate) enum Input {
    /// A Raft message from a peer, already checked.
    Raft {
        from: NodeNumber,
        message: Message<NodeNumber>,
    },
    /// Blobs arrived that the group's entries, or a snapshot it installs,
    /// may wait for.
    Blobs,
    /// A snapshot chunk from the leader this replica follows, `from`.
    Chunk {
        from: NodeNumber,
        chunk: SnapshotChunk,
    },
    /// A follower's acknowledgement of a snapshot stream.
    ChunkAck { from: NodeNumber, ack: SnapshotAck },
}

/// What a group hears from its own leader loop, never dropped.
pub(crate) enum Local {
    /// A work result to replicate in `term`: its index, or why not.
    Propose {
        term: u64,
        payload: Vec<u8>,
        answer: Proposed,
        /// A large result's blob, held until its entry is written.
        held: Option<Held>,
    },
    /// This replica's leader loop stopped for good: it hands leadership
    /// over and never campaigns again, but goes on applying.
    Retire,
    /// A read index: an index to apply through before reading, once a
    /// quorum has confirmed this replica still leads.
    ReadIndex {
        answer: smol::channel::Sender<Result<u64, ReadIndexError>>,
    },
    /// Replace the group's members, `current` as the caller saw them, by
    /// `members`: answered with the index of the joint configuration,
    /// which the core finalizes once it commits; refused as in progress
    /// when the core's configuration is not `current`.
    ChangeMembership {
        current: Vec<NodeNumber>,
        members: Vec<NodeNumber>,
        answer: smol::channel::Sender<Result<u64, ChangeMembershipError>>,
    },
    /// `node` came back, by the pair heartbeat: a leader sends it a
    /// heartbeat at once ([`vos_raft::core::Core::probe`]).
    Probe(NodeNumber),
    /// Something changed that the group's next round should see, such as
    /// the writer's health.
    Wake,
    /// The snapshot stream to `to`, named by `term` and `index`, ended:
    /// `done` once its follower staged every chunk.
    StreamEnded {
        to: NodeNumber,
        term: u64,
        index: u64,
        done: bool,
    },
}

/// How many results' outcomes a group remembers, for its leader loop to
/// read after its own apply.
const OUTCOMES: usize = 256;

/// A group's state, as its driver, its applier, its leader loop and
/// ingress share it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct State {
    pub role: Role,
    pub term: u64,
    pub leader: Option<NodeNumber>,
    /// The first index of the term this replica leads, while it leads.
    pub leading_from: Option<u64>,
    pub commit: u64,
    /// The highest index this replica holds durably, blobs included.
    pub written: u64,
    pub applied: u64,
    /// The commit index the replica recovered: queries wait until it is
    /// applied.
    pub recovered: u64,
    /// When the commit index last moved: a stage's end as the driver saw
    /// it, not as a waiter woken later does.
    pub commit_at: Option<Instant>,
    /// When the applied index last moved, as the applier saw it.
    pub applied_at: Option<Instant>,
    pub stopped: bool,
    /// The replica has held a committed configuration naming it.
    pub established: bool,
}

pub(crate) struct Shared {
    pub agent: AgentId,
    pub record: CreationRecord,
    /// The agent's identity: its record's hash, which clients sign for.
    pub identity: [u8; 32],
    state: Mutex<State>,
    changed: event_listener::Event,
    /// Whether each recent work result took: accumulate advanced the
    /// agent's version with it, rather than skipping it or failing.
    outcomes: Mutex<VecDeque<(u64, bool)>>,
    /// Held by the applier while it applies an entry, and by a snapshot
    /// switch: an apply never lands on the state a switch replaced.
    pub applying: smol::lock::Mutex<()>,
    /// When the group's driver last went round, on the node's liveness
    /// clock: a leader whose driver stopped going round is not vouched
    /// for.
    pub woke: AtomicU64,
}

impl Shared {
    pub fn new(record: CreationRecord) -> Self {
        Self {
            agent: record.agent,
            identity: crate::identity(&record),
            record,
            state: Mutex::new(State {
                role: Role::Follower,
                term: 0,
                leader: None,
                leading_from: None,
                commit: 0,
                written: 0,
                applied: 0,
                recovered: 0,
                commit_at: None,
                applied_at: None,
                stopped: false,
                established: false,
            }),
            changed: event_listener::Event::new(),
            outcomes: Mutex::new(VecDeque::new()),
            applying: smol::lock::Mutex::new(()),
            woke: AtomicU64::new(0),
        }
    }

    /// Whether the work result at `index` took, if it was applied lately.
    pub fn outcome(&self, index: u64) -> Option<bool> {
        lock(&self.outcomes)
            .iter()
            .find(|(at, _)| *at == index)
            .map(|(_, took)| *took)
    }

    fn record_outcome(&self, index: u64, took: bool) {
        let mut outcomes = lock(&self.outcomes);
        if outcomes.len() == OUTCOMES {
            outcomes.pop_front();
        }
        outcomes.push_back((index, took));
    }

    pub fn state(&self) -> State {
        *lock(&self.state)
    }

    pub fn update(&self, change: impl FnOnce(&mut State)) {
        change(&mut lock(&self.state));
        self.changed.notify(usize::MAX);
    }

    /// The state once `until` holds of it.
    pub async fn wait(&self, until: impl Fn(&State) -> bool) -> State {
        loop {
            let changed = self.changed.listen();
            let state = self.state();
            if until(&state) {
                return state;
            }
            changed.await;
        }
    }

    pub fn stop(&self) {
        self.update(|state| state.stopped = true);
    }
}

/// Drive `shared`'s group until it stops, its inboxes close, or storage
/// fails.
pub(crate) async fn drive(
    inner: Arc<Inner>,
    shared: Arc<Shared>,
    inbox: smol::channel::Receiver<Input>,
    local: smol::channel::Receiver<Local>,
) {
    match Driver::start(Arc::clone(&inner), Arc::clone(&shared)).await {
        Ok(driver) => driver.run(inbox, local).await,
        Err(error) => {
            tracing::error!(
                agent = shared.agent.0,
                "the group cannot start: {error}; it stops"
            );
            shared.stop();
        }
    }
}

struct Driver {
    inner: Arc<Inner>,
    shared: Arc<Shared>,
    core: Core<NodeNumber>,
    start: Instant,
    reports: EntryReports,
    /// Each write not yet reported with its blobs, by sequence, with the
    /// log's last index after it.
    writes: VecDeque<(u64, u64)>,
    /// The log's last index as written to the store. [`State::written`]
    /// reaches it only once the entries' blobs are stored too.
    last_index: u64,
    proposals: HashMap<u64, Proposed>,
    reads: HashMap<u64, smol::channel::Sender<Result<u64, ReadIndexError>>>,
    next_token: u64,
    /// The blobs asked for and still awaited.
    asks: Asks,
    /// Which member to ask next.
    turn: usize,
    /// The held blobs of proposals not yet answered, by token.
    held_proposals: HashMap<u64, Held>,
    /// The held blobs of entries not yet written, by index: released once
    /// a write reaches it, or truncates it.
    held_entries: Vec<(u64, Held)>,
    /// The leader loop stopped for good.
    retired: bool,
    /// The core was last told to hand leadership over and not campaign.
    handing_over: bool,
    /// The snapshot streams this replica runs as leader, by follower.
    shipments: HashMap<NodeNumber, Shipment>,
    /// The snapshot this replica stages, from the leader it follows.
    install: Option<Install>,
    /// The programs a staged snapshot waits for before its switch.
    install_missing: Vec<[u8; 32]>,
    /// Snapshot chunks taken this round, staged once it is processed.
    chunks: VecDeque<(NodeNumber, SnapshotChunk)>,
    /// The highest compaction bound the core gave.
    compact_bound: u64,
    /// A compaction is due at the next chance.
    compact_due: bool,
    memberships: HashMap<u64, smol::channel::Sender<Result<u64, ChangeMembershipError>>>,
    /// The order of the placement this replica last announced as leader,
    /// since it last stepped down: set as it goes to the directory, in a
    /// task of its own, as the driver never waits on the node-wide lock a
    /// placement takes.
    announced: Option<Order>,
}
