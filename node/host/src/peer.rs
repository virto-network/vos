//! What nodes send each other: the wire's messages, converted to and from
//! the consensus core's, and the checks every arrival passes before it
//! reaches a group. A check needs no I/O; what fails one is dropped and
//! counted.
//!
//! - **Any configured node may send.** A replica that has not yet seen a
//!   change of its group's members still takes the new members' messages;
//!   the core counts votes and acknowledgements only from members.
//! - **An append comes from the leader it names, a vote request from the
//!   candidate it names.** The sender is the network's authenticated peer,
//!   delivered directly: a relaying network would need the origin signed
//!   in the message.
//! - **A snapshot chunk comes from the leader the replica follows,** in
//!   that leader's term.
//! - **A blob hashes to its name.**
//! - **Each message comes on its class,** so a frame is bounded by its own
//!   class's size, and a Raft message on its agent's stream.
//! - **A creation record comes from the node that created it,** whose
//!   number its agent id carries.
//!
//! Snapshot acknowledgements, blob requests, blobs, directory
//! acknowledgements and liveness pass with only these checks: their
//! handlers authorise by sender. An acknowledgement counts only from the
//! replica a snapshot streams to, a blob only if requested, a blob request
//! only from a replica of its agent, and a directory acknowledgement only
//! for a record this node created.

use std::sync::atomic::{AtomicU64, Ordering};

use vos_net::Class;
use vos_raft::{AppendResult, EntryKind, LogEntry, Message};
use vos_wire::Decode;
use vos_wire::ids::AgentId;
use vos_wire::peer::{self, CreationRecord, NodeNumber, PeerMessage, Raft, SnapshotChunk};

/// The wire's message for the core's.
pub fn to_wire(message: &Message<NodeNumber>) -> Raft {
    match message {
        Message::Append {
            term,
            leader,
            prev_index,
            prev_term,
            commit,
            round,
            entries,
        } => Raft::Append {
            term: *term,
            leader: *leader,
            prev_index: *prev_index,
            prev_term: *prev_term,
            commit: *commit,
            round: *round,
            entries: entries.iter().map(entry_to_wire).collect(),
        },
        Message::AppendAnswer {
            term,
            round,
            commit,
            result,
        } => Raft::AppendAnswer {
            term: *term,
            round: *round,
            commit: *commit,
            result: match *result {
                AppendResult::Matched { matched } => peer::AppendResult::Matched { matched },
                AppendResult::Rejected {
                    rejected,
                    last_index,
                    conflict_term,
                    conflict_first,
                } => peer::AppendResult::Rejected {
                    rejected,
                    last_index,
                    conflict_term,
                    conflict_first,
                },
            },
        },
        Message::Vote {
            term,
            candidate,
            last_index,
            last_term,
        } => Raft::Vote {
            term: *term,
            candidate: *candidate,
            last_index: *last_index,
            last_term: *last_term,
        },
        Message::VoteAnswer { term, granted } => Raft::VoteAnswer {
            term: *term,
            granted: *granted,
        },
        Message::PreVote {
            next_term,
            candidate,
            last_index,
            last_term,
        } => Raft::PreVote {
            next_term: *next_term,
            candidate: *candidate,
            last_index: *last_index,
            last_term: *last_term,
        },
        Message::PreVoteAnswer {
            term,
            next_term,
            granted,
        } => Raft::PreVoteAnswer {
            term: *term,
            next_term: *next_term,
            granted: *granted,
        },
        Message::TimeoutNow { term } => Raft::TimeoutNow { term: *term },
    }
}

/// The core's message for the wire's.
pub fn from_wire(message: Raft) -> Message<NodeNumber> {
    match message {
        Raft::Append {
            term,
            leader,
            prev_index,
            prev_term,
            commit,
            round,
            entries,
        } => Message::Append {
            term,
            leader,
            prev_index,
            prev_term,
            commit,
            round,
            entries: entries.into_iter().map(entry_from_wire).collect(),
        },
        Raft::AppendAnswer {
            term,
            round,
            commit,
            result,
        } => Message::AppendAnswer {
            term,
            round,
            commit,
            result: match result {
                peer::AppendResult::Matched { matched } => AppendResult::Matched { matched },
                peer::AppendResult::Rejected {
                    rejected,
                    last_index,
                    conflict_term,
                    conflict_first,
                } => AppendResult::Rejected {
                    rejected,
                    last_index,
                    conflict_term,
                    conflict_first,
                },
            },
        },
        Raft::Vote {
            term,
            candidate,
            last_index,
            last_term,
        } => Message::Vote {
            term,
            candidate,
            last_index,
            last_term,
        },
        Raft::VoteAnswer { term, granted } => Message::VoteAnswer { term, granted },
        Raft::PreVote {
            next_term,
            candidate,
            last_index,
            last_term,
        } => Message::PreVote {
            next_term,
            candidate,
            last_index,
            last_term,
        },
        Raft::PreVoteAnswer {
            term,
            next_term,
            granted,
        } => Message::PreVoteAnswer {
            term,
            next_term,
            granted,
        },
        Raft::TimeoutNow { term } => Message::TimeoutNow { term },
    }
}

fn entry_to_wire(entry: &LogEntry<NodeNumber>) -> peer::Entry {
    peer::Entry {
        index: entry.index,
        term: entry.term,
        kind: match &entry.kind {
            EntryKind::Data { payload } => peer::EntryKind::Data {
                payload: payload.clone(),
            },
            EntryKind::ConfigChange { joint_old, members } => peer::EntryKind::Configuration {
                members: members.clone(),
                joint_old: joint_old.clone(),
            },
        },
    }
}

fn entry_from_wire(entry: peer::Entry) -> LogEntry<NodeNumber> {
    LogEntry {
        index: entry.index,
        term: entry.term,
        kind: match entry.kind {
            peer::EntryKind::Data { payload } => EntryKind::Data { payload },
            peer::EntryKind::Configuration { members, joint_old } => {
                EntryKind::ConfigChange { joint_old, members }
            }
        },
    }
}

/// Why an arrival was dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Refusal {
    /// It is not one whole message.
    Undecodable = 0,
    /// Its sender is not configured in the space.
    Stranger = 1,
    /// An append from a node other than the leader it names.
    NotTheLeaderNamed = 2,
    /// A vote request from a node other than the candidate it names.
    NotTheCandidateNamed = 3,
    /// A snapshot chunk from a node other than the leader the replica
    /// follows, or from another term.
    NotTheLeaderFollowed = 4,
    /// A blob whose bytes do not hash to its name.
    WrongBlob = 5,
    /// A message on a class not its own.
    WrongClass = 6,
    /// A Raft message on a stream other than its agent's.
    WrongStream = 7,
    /// A creation record from a node other than its creator, or for an
    /// agent outside the creator's range.
    NotTheCreator = 8,
    /// A Raft message for an agent with no group here, or whose inbox was
    /// full: Raft sends it again.
    Unrouted = 9,
    /// A forwarded call from a node that does not replicate its agent.
    NotAReplica = 10,
    /// An answer to a forwarded call that is no longer waited for.
    Unmatched = 11,
}

impl Refusal {
    pub const ALL: [Refusal; 12] = [
        Refusal::Undecodable,
        Refusal::Stranger,
        Refusal::NotTheLeaderNamed,
        Refusal::NotTheCandidateNamed,
        Refusal::NotTheLeaderFollowed,
        Refusal::WrongBlob,
        Refusal::WrongClass,
        Refusal::WrongStream,
        Refusal::NotTheCreator,
        Refusal::Unrouted,
        Refusal::NotAReplica,
        Refusal::Unmatched,
    ];
}

/// That `from` replicates the agent whose replicas are `replicas`, as a
/// forwarded call's sender must: replicas are trusted to have checked the
/// call's signature.
pub fn check_replica(replicas: Option<&[NodeNumber]>, from: NodeNumber) -> Result<(), Refusal> {
    match replicas {
        Some(replicas) if replicas.contains(&from) => Ok(()),
        _ => Err(Refusal::NotAReplica),
    }
}

/// The class a message travels on.
pub fn class(message: &PeerMessage) -> Class {
    match message {
        PeerMessage::Raft { .. } | PeerMessage::SnapshotAck(_) => Class::Consensus,
        PeerMessage::SnapshotChunk(_) | PeerMessage::Blob { .. } => Class::Bulk,
        PeerMessage::BlobRequest { .. }
        | PeerMessage::Directory(_)
        | PeerMessage::DirectoryAck { .. }
        | PeerMessage::Forward { .. }
        | PeerMessage::Forwarded { .. } => Class::Requests,
        PeerMessage::Liveness { .. } | PeerMessage::LivenessAnswer { .. } => Class::Liveness,
    }
}

/// The stream a message travels on: its agent's, for those of a group.
pub fn stream(message: &PeerMessage) -> u64 {
    match message {
        PeerMessage::Raft { agent, .. } | PeerMessage::BlobRequest { agent, .. } => {
            u64::from(agent.0)
        }
        PeerMessage::SnapshotChunk(chunk) => u64::from(chunk.agent.0),
        PeerMessage::SnapshotAck(ack) => u64::from(ack.agent.0),
        PeerMessage::Directory(record) => u64::from(record.agent.0),
        PeerMessage::DirectoryAck { agent }
        | PeerMessage::Forward { agent, .. }
        | PeerMessage::Forwarded { agent, .. } => u64::from(agent.0),
        PeerMessage::Blob { .. }
        | PeerMessage::Liveness { .. }
        | PeerMessage::LivenessAnswer { .. } => 0,
    }
}

/// A frame from a peer, whole.
pub fn decode(frame: &[u8]) -> Result<PeerMessage, Refusal> {
    match PeerMessage::decode(frame) {
        Ok((message, used)) if used == frame.len() => Ok(message),
        _ => Err(Refusal::Undecodable),
    }
}

/// Check what `from` sent on `class` and `stream` against `space`, the
/// nodes configured in the space. `followed` gives the leader a replica of
/// an agent follows and its term, if it follows one.
pub fn check(
    space: &[NodeNumber],
    from: NodeNumber,
    (class, stream): (Class, u64),
    message: &PeerMessage,
    followed: impl FnOnce(AgentId) -> Option<(NodeNumber, u64)>,
) -> Result<(), Refusal> {
    if !space.contains(&from) {
        return Err(Refusal::Stranger);
    }
    if class != self::class(message) {
        return Err(Refusal::WrongClass);
    }
    match message {
        PeerMessage::Raft { agent, .. } if stream != u64::from(agent.0) => {
            Err(Refusal::WrongStream)
        }
        PeerMessage::Raft { message, .. } => check_raft(from, message),
        PeerMessage::SnapshotChunk(chunk) => check_chunk(from, chunk, followed(chunk.agent)),
        PeerMessage::Blob { hash, bytes } => check_blob(hash, bytes),
        PeerMessage::Directory(record) => {
            if record.creator == from && CreationRecord::creator_of(record.agent) == from {
                Ok(())
            } else {
                Err(Refusal::NotTheCreator)
            }
        }
        PeerMessage::DirectoryAck { .. }
        | PeerMessage::SnapshotAck(_)
        | PeerMessage::BlobRequest { .. }
        | PeerMessage::Liveness { .. }
        | PeerMessage::LivenessAnswer { .. }
        | PeerMessage::Forward { .. }
        | PeerMessage::Forwarded { .. } => Ok(()),
    }
}

fn check_raft(from: NodeNumber, message: &Raft) -> Result<(), Refusal> {
    match message {
        Raft::Append { leader, .. } if *leader != from => Err(Refusal::NotTheLeaderNamed),
        Raft::Vote { candidate, .. } | Raft::PreVote { candidate, .. } if *candidate != from => {
            Err(Refusal::NotTheCandidateNamed)
        }
        _ => Ok(()),
    }
}

fn check_chunk(
    from: NodeNumber,
    chunk: &SnapshotChunk,
    followed: Option<(NodeNumber, u64)>,
) -> Result<(), Refusal> {
    if followed == Some((from, chunk.term)) {
        Ok(())
    } else {
        Err(Refusal::NotTheLeaderFollowed)
    }
}

fn check_blob(hash: &[u8; 32], bytes: &[u8]) -> Result<(), Refusal> {
    if vos_pvm::precompile::blake2b_256(bytes) == *hash {
        Ok(())
    } else {
        Err(Refusal::WrongBlob)
    }
}

/// Arrivals dropped, by why.
#[derive(Debug, Default)]
pub struct Drops([AtomicU64; Refusal::ALL.len()]);

impl Drops {
    pub fn count(&self, refusal: Refusal) {
        self.0[refusal as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub fn get(&self, refusal: Refusal) -> u64 {
        self.0[refusal as usize].load(Ordering::Relaxed)
    }
}
