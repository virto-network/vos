//! An agent's replica group on this node: its consensus core, driven by
//! the node's log writer and the network, and its applier, which applies
//! the committed log in order, the same way on every replica.

mod apply;
mod driver;
mod epochs;

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

use vos_raft::core::{ChangeMembershipError, ProposeError, ReadIndexError};
use vos_raft::{Message, Role};
use vos_wire::ids::AgentId;
use vos_wire::peer::{CreationRecord, NodeNumber, SnapshotAck, SnapshotChunk};

use crate::blobs::Held;
use crate::lock;

pub(crate) use apply::{DryRun, apply, pin_changes, pinned, programs};
pub(crate) use driver::drive;
pub(crate) use epochs::{drop_stale_epochs, empty_epoch};

/// Where a proposal's answer goes: the index it took, or why not, and
/// when the driver answered.
pub(crate) type Proposed = smol::channel::Sender<(Result<u64, ProposeError>, Instant)>;
/// Where a read index's answer goes.
pub(crate) type ReadIndexed = smol::channel::Sender<Result<u64, ReadIndexError>>;
/// Where a membership change's answer goes: the index of its joint
/// configuration, or why not.
pub(crate) type MembershipChanged = smol::channel::Sender<Result<u64, ChangeMembershipError>>;

/// What a group hears from the network and the node: bounded by its
/// [`Inbox`], and dropped when full.
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

/// A group's inbox, as the network and the node send to it: at most
/// `bound` inputs queued, and one past them dropped, which its sender
/// sends again. Its queue takes memory as it fills and gives it back as it
/// drains, not whole at its creation: an idle group's holds none.
pub(crate) struct Inbox {
    sender: smol::channel::Sender<Input>,
    bound: usize,
}

impl Inbox {
    /// An inbox of `bound` inputs, and the driver's end of it.
    pub(crate) fn new(bound: usize) -> (Self, smol::channel::Receiver<Input>) {
        let (sender, receiver) = smol::channel::unbounded();
        (Self { sender, bound }, receiver)
    }

    /// Queue `input`, in order: false, and dropped, when the inbox is full
    /// or closed. Senders that race past the bound queue at most one more
    /// each.
    pub(crate) fn send(&self, input: Input) -> bool {
        self.sender.len() < self.bound && self.sender.try_send(input).is_ok()
    }

    pub(crate) fn close(&self) {
        self.sender.close();
    }
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
    ReadIndex { answer: ReadIndexed },
    /// Replace the group's members, `current` as the caller saw them, by
    /// `members`: answered with the index of the joint configuration,
    /// which the core finalizes once it commits; refused as in progress
    /// when the core's configuration is not `current`.
    ChangeMembership {
        current: Vec<NodeNumber>,
        members: Vec<NodeNumber>,
        answer: MembershipChanged,
    },
    /// `node` came back, by the pair heartbeat: a leader sends it a
    /// heartbeat at once ([`vos_raft::core::Core::probe`]).
    Probe(NodeNumber),
    /// Something changed that the group's next round should see, such as
    /// the writer's health.
    Wake,
    /// Hand this replica's leadership to the member `to`, which campaigns
    /// once it has caught up ([`vos_raft::core::Core::transfer_leadership`]).
    Transfer(NodeNumber),
    /// The snapshot stream to `to`, named by `term` and `index`, ended:
    /// `done` once its follower staged every chunk.
    StreamEnded {
        to: NodeNumber,
        term: u64,
        index: u64,
        done: bool,
    },
}

impl Local {
    /// Answer that the group stopped, when it carries an answer.
    fn refuse_stopped(self) {
        match self {
            Local::Propose { answer, .. } => {
                let _ = answer.try_send((Err(ProposeError::Stopped), Instant::now()));
            }
            Local::ReadIndex { answer } => {
                let _ = answer.try_send(Err(ReadIndexError::Stopped));
            }
            Local::ChangeMembership { answer, .. } => {
                let _ = answer.try_send(Err(ChangeMembershipError::Stopped));
            }
            Local::Retire
            | Local::StreamEnded { .. }
            | Local::Probe(_)
            | Local::Wake
            | Local::Transfer(_) => {}
        }
    }
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
    /// The window cuts this replica's root builder has finished since the
    /// group started: the leader reports and closes after each.
    pub cuts_built: u64,
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
                cuts_built: 0,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn vote(term: u64) -> Input {
        Input::Raft {
            from: 1,
            message: Message::VoteAnswer {
                term,
                granted: true,
            },
        }
    }

    fn term(input: Input) -> u64 {
        match input {
            Input::Raft {
                message: Message::VoteAnswer { term, .. },
                ..
            } => term,
            _ => panic!("a vote's answer"),
        }
    }

    #[test]
    fn an_inbox_drops_past_its_bound_and_keeps_its_order() {
        let (inbox, inputs) = Inbox::new(3);
        assert!((1..=3).all(|term| inbox.send(vote(term))));
        assert!(!inbox.send(vote(4)), "full");
        assert_eq!(term(inputs.try_recv().unwrap()), 1);
        assert!(inbox.send(vote(5)), "one taken makes room for one");
        assert!(!inbox.send(vote(6)), "full again");
        let taken: Vec<u64> = std::iter::from_fn(|| inputs.try_recv().ok())
            .map(term)
            .collect();
        assert_eq!(taken, [2, 3, 5]);
        assert!(inbox.send(vote(7)), "drained");
        inbox.close();
        assert!(!inbox.send(vote(8)), "closed");
        assert_eq!(term(inputs.try_recv().unwrap()), 7, "what was queued stays");
    }
}
