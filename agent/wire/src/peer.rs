//! What one node sends another: messages for an agent's replica group,
//! snapshot chunks, blobs, liveness, the directory of agents, clients'
//! calls and read indexes, which a replica asks of its leader, and agents'
//! messages to each other, their acknowledgements and their receivers'
//! calls to send again. The node checks each against the space's
//! configuration before it reaches a group.
//!
//! The Raft types mirror the consensus core's, so the wire format is this
//! module's alone and the core may change underneath it. The network's
//! protocol name (ALPN `vos/1`) versions it.

use alloc::vec::Vec;

use scale::{Decode, Encode};

use crate::batch::Message;
use crate::ids::{AgentId, ProgramHash};
use crate::ingress::{Call, Response};

/// A node of the space: the 8-bit node part of an agent id.
pub type NodeNumber = u8;

/// A frame between nodes.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum PeerMessage {
    /// A message for `agent`'s replica group.
    #[codec(index = 0)]
    Raft { agent: AgentId, message: Raft },
    #[codec(index = 1)]
    SnapshotChunk(SnapshotChunk),
    #[codec(index = 2)]
    SnapshotAck(SnapshotAck),
    /// The blobs with these hashes, wanted by a replica of `agent`.
    #[codec(index = 3)]
    BlobRequest {
        agent: AgentId,
        hashes: Vec<[u8; 32]>,
    },
    /// A blob, which the receiver hashes before taking.
    #[codec(index = 4)]
    Blob { hash: [u8; 32], bytes: Vec<u8> },
    /// The sending node's pair heartbeat: it is alive, in its run
    /// `incarnation` (its start time, in microseconds) at heartbeat
    /// `round`, and leads each group in `leading` at its term. A long
    /// list comes in several frames of one round.
    #[codec(index = 5)]
    Liveness {
        incarnation: u64,
        round: u64,
        leading: Vec<Leading>,
    },
    /// Where an agent runs, with its creation record: from its creator at
    /// creation, then from its leader as its replicas change, or from a
    /// member asked for it.
    #[codec(index = 6)]
    Directory {
        record: CreationRecord,
        placement: Placement,
    },
    /// The receiver holds `agent`'s record and a placement at least as
    /// new as `order` durably; `runs` says whether it could run the
    /// agent's program.
    #[codec(index = 7)]
    DirectoryAck {
        agent: AgentId,
        order: Order,
        runs: bool,
    },
    /// The sender runs no group for `agent` and was sent Raft traffic for
    /// it: a node holding a placement that names the sender answers with
    /// a `Directory`.
    #[codec(index = 8)]
    DirectoryRequest { agent: AgentId },
    /// A client's call to `agent`, whose signature the sending replica
    /// checked, for the leader to run. `token` names it across re-forwards;
    /// `term` is the term the sender knows the receiver to lead at, and
    /// the receiver runs it only while it leads at that term.
    #[codec(index = 9)]
    Forward {
        agent: AgentId,
        token: u64,
        term: u64,
        call: Call,
    },
    /// The answer to a forwarded call, and the answering replica's term.
    #[codec(index = 10)]
    Forwarded {
        agent: AgentId,
        token: u64,
        term: u64,
        answer: Response,
    },
    /// A replica of `agent` asks its leader for a read index.
    #[codec(index = 11)]
    ReadIndex { agent: AgentId, token: u64 },
    /// The leader's read index, once a quorum confirmed it leads; none
    /// when it could not confirm it.
    #[codec(index = 12)]
    ReadIndexAnswer {
        agent: AgentId,
        token: u64,
        index: Option<u64>,
    },
    /// A message from agent `message.from` to agent `to`, from the
    /// sender's leader, or `relayed` by a replica of `to` to its leader.
    #[codec(index = 13)]
    Deliver {
        to: AgentId,
        message: Message,
        relayed: bool,
    },
    /// Agent `receiver` holds `sender`'s messages through `sequence`, from
    /// the receiver's leader, or `relayed` by a replica of `sender` to its
    /// leader.
    #[codec(index = 14)]
    Acknowledge {
        sender: AgentId,
        receiver: AgentId,
        sequence: u64,
        relayed: bool,
    },
    /// Agent `receiver` refused a message of `sender`'s past a gap:
    /// `sender`'s leader sends again, now, what it sent past the
    /// acknowledgement it holds. From the receiver's leader, or `relayed`
    /// by a replica of `sender` to its leader. It names no sequence, so a
    /// stale one only sends again what the receiver drops at its mark.
    #[codec(index = 15)]
    Behind {
        sender: AgentId,
        receiver: AgentId,
        relayed: bool,
    },
}

/// What makes an agent the agent it is. Its hash is the agent's identity.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct CreationRecord {
    /// Its top 8 bits are the creating node's number.
    pub agent: AgentId,
    /// The nodes replicating it, its group's first members.
    pub replicas: Vec<NodeNumber>,
    pub creator: NodeNumber,
    /// Milliseconds since the Unix epoch, by the creating node's clock.
    pub time: u64,
    /// The agent program every replica runs.
    pub program: ProgramHash,
    /// Accumulate's gas, the same on every replica, so every replica
    /// applies the same writes.
    pub accumulate_gas: u64,
}

impl CreationRecord {
    /// The number of the node whose range `agent` is in.
    pub fn creator_of(agent: AgentId) -> NodeNumber {
        (agent.0 >> 24) as NodeNumber
    }

    /// The id of node `creator`'s agent `serial`, below `1 << 24`, in its
    /// range.
    pub fn agent_id(creator: NodeNumber, serial: u32) -> AgentId {
        AgentId(u32::from(creator) << 24 | serial)
    }

    /// Which of its creator's agents `agent` is.
    pub fn serial_of(agent: AgentId) -> u32 {
        agent.0 & 0x00ff_ffff
    }
}

/// Where an agent runs: its group's configuration, as the leader that
/// announced it had it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Placement {
    /// The nodes replicating it, in order: both sets while the
    /// configuration is joint.
    pub replicas: Vec<NodeNumber>,
    /// The nodes of the configuration this one supersedes: empty at
    /// creation.
    pub before: Vec<NodeNumber>,
    /// The term of the leader that announced it, and the log index of its
    /// configuration: both 0 at creation.
    pub term: u64,
    pub index: u64,
    pub joint: bool,
    /// Whether its configuration had committed.
    pub committed: bool,
}

impl Placement {
    /// An agent's placement at its creation: its record's replicas.
    pub fn created(record: &CreationRecord) -> Self {
        Self {
            replicas: record.replicas.clone(),
            before: Vec::new(),
            term: 0,
            index: 0,
            joint: false,
            committed: true,
        }
    }

    /// Its place among an agent's placements.
    pub fn order(&self) -> Order {
        Order {
            term: self.term,
            index: self.index,
            committed: self.committed,
        }
    }

    /// Whether this placement replaces `held`: it ranks higher, and takes
    /// back no commit. A new leader may announce the configuration a
    /// committed placement names before it learns that it committed: the
    /// same configuration uncommitted, or an earlier one, never replaces
    /// a committed placement.
    pub fn supersedes(&self, held: &Placement) -> bool {
        self.order() > held.order()
            && !(held.committed
                && (self.index < held.index || (self.index == held.index && !self.committed)))
    }

    /// Whether `node` speaks for the agent: one of its replicas, or, while
    /// the configuration is uncommitted, of the one before, which may
    /// still lead.
    pub fn admits(&self, node: NodeNumber) -> bool {
        self.replicas.contains(&node) || (!self.committed && self.before.contains(&node))
    }
}

/// A placement's place among an agent's placements, compared field by
/// field: a newer leader's first, then a later configuration, then one
/// that committed. A leader that failed before its configuration reached a
/// majority is outranked by the next, whatever the index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct Order {
    /// The term of the leader that announced it.
    pub term: u64,
    /// The log index of its configuration.
    pub index: u64,
    /// Whether its configuration had committed.
    pub committed: bool,
}

/// A group a node leads, at `term`, as its pair heartbeat lists it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Leading {
    pub agent: AgentId,
    pub term: u64,
}

/// A Raft message, as the consensus core has it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Raft {
    /// Entries, or none (a heartbeat), from a leader.
    #[codec(index = 0)]
    Append {
        term: u64,
        leader: NodeNumber,
        prev_index: u64,
        prev_term: u64,
        commit: u64,
        round: u64,
        entries: Vec<Entry>,
    },
    #[codec(index = 1)]
    AppendAnswer {
        term: u64,
        round: u64,
        commit: u64,
        result: AppendResult,
    },
    #[codec(index = 2)]
    Vote {
        term: u64,
        candidate: NodeNumber,
        last_index: u64,
        last_term: u64,
    },
    #[codec(index = 3)]
    VoteAnswer { term: u64, granted: bool },
    #[codec(index = 4)]
    PreVote {
        next_term: u64,
        candidate: NodeNumber,
        last_index: u64,
        last_term: u64,
    },
    #[codec(index = 5)]
    PreVoteAnswer {
        term: u64,
        next_term: u64,
        granted: bool,
    },
    #[codec(index = 6)]
    TimeoutNow { term: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum AppendResult {
    #[codec(index = 0)]
    Matched { matched: u64 },
    #[codec(index = 1)]
    Rejected {
        rejected: u64,
        last_index: u64,
        conflict_term: u64,
        conflict_first: u64,
    },
}

/// A log entry.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Entry {
    pub index: u64,
    pub term: u64,
    pub kind: EntryKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum EntryKind {
    /// The node's entry payload: its kind, the blobs it names and its body.
    #[codec(index = 0)]
    Data { payload: Vec<u8> },
    /// A change to the group's members, joint while `joint_old` is set.
    #[codec(index = 1)]
    Configuration {
        members: Vec<NodeNumber>,
        joint_old: Option<Vec<NodeNumber>>,
    },
}

/// The members a snapshot carries, and the index that established them.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Configuration {
    pub members: Vec<NodeNumber>,
    pub joint_old: Option<Vec<NodeNumber>>,
    pub index: u64,
}

/// One chunk of the snapshot a leader streams to a replica of `agent`. A
/// stream is named by the leader's term and the snapshot's index.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct SnapshotChunk {
    pub agent: AgentId,
    /// The leader's term: a replica takes chunks only from the leader it
    /// follows, in that leader's term.
    pub term: u64,
    /// The index and term the snapshot is through: the leader's applied
    /// index when it exported its state.
    pub index: u64,
    pub snapshot_term: u64,
    /// The chunk's place in the stream, from 0.
    pub sequence: u64,
    /// What the snapshot carries besides its rows, in its first chunk.
    pub manifest: Option<Manifest>,
    /// The agent's rows, by agent-relative key.
    pub rows: Vec<(Vec<u8>, Vec<u8>)>,
    pub last: bool,
}

/// What a snapshot carries besides the agent's rows.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Manifest {
    /// The configuration in effect at the snapshot's index, when known.
    pub configuration: Option<Configuration>,
    /// The time and seed of the last work result the state applied, which
    /// times queries on it.
    pub last_result: Option<(u64, [u8; 32])>,
}

/// A replica holds the snapshot stream named by `term` and `index`
/// through the chunk before `next`, the one it wants next.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct SnapshotAck {
    pub agent: AgentId,
    pub term: u64,
    pub index: u64,
    pub next: u64,
}
