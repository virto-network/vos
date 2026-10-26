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
use vos_wire::ids::AgentId;
use vos_wire::peer::{
    self, CreationRecord, NodeNumber, PeerMessage, Placement, Raft, SnapshotChunk,
};
use vos_wire::{Decode, SpaceId};

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
    /// A creation-time placement from a node other than its creator, or
    /// for an agent outside the creator's range; or a later placement from
    /// a node it does not name, nor the configuration it supersedes.
    NotTheCreator = 8,
    /// A Raft message for an agent with no group here, or whose inbox was
    /// full: Raft sends it again.
    Unrouted = 9,
    /// A forwarded call from a node that does not replicate its agent.
    NotAReplica = 10,
    /// An answer to a forwarded call that is no longer waited for.
    Unmatched = 11,
    /// An agent's message, acknowledgement or `Behind` with nowhere to go
    /// here: no leader to relay to, or a second hop. Its sender sends it
    /// again.
    Unplaced = 12,
    /// An agent's message its leader's queue here had no room for: its
    /// sender sends it again, told it is behind once the queue drained, or
    /// at its round.
    Full = 13,
    /// An agent's creation record naming another space than the node's:
    /// an agent belongs to one space, and its replicas to it.
    OtherSpace = 14,
}

impl Refusal {
    pub const ALL: [Refusal; 15] = [
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
        Refusal::Unplaced,
        Refusal::Full,
        Refusal::OtherSpace,
    ];
}

/// That `from` replicates the agent `placement` places, as a forwarded
/// call's sender must: replicas are trusted to have checked the call's
/// signature.
pub fn check_replica(placement: Option<&Placement>, from: NodeNumber) -> Result<(), Refusal> {
    match placement {
        Some(placement) if placement.admits(from) => Ok(()),
        _ => Err(Refusal::NotAReplica),
    }
}

/// The class a message travels on.
pub fn class(message: &PeerMessage) -> Class {
    match message {
        PeerMessage::Raft { .. } | PeerMessage::SnapshotAck(_) => Class::Consensus,
        PeerMessage::SnapshotChunk(_) | PeerMessage::Blob { .. } => Class::Bulk,
        PeerMessage::BlobRequest { .. }
        | PeerMessage::Directory { .. }
        | PeerMessage::DirectoryAck { .. }
        | PeerMessage::DirectoryRequest { .. }
        | PeerMessage::Forward { .. }
        | PeerMessage::Forwarded { .. }
        | PeerMessage::ReadIndex { .. }
        | PeerMessage::ReadIndexAnswer { .. }
        | PeerMessage::Deliver { .. }
        | PeerMessage::Acknowledge { .. }
        | PeerMessage::Behind { .. }
        | PeerMessage::AnchorRow { .. }
        | PeerMessage::AnchorRowAnswer { .. }
        | PeerMessage::Proved { .. } => Class::Requests,
        PeerMessage::Liveness { .. } => Class::Liveness,
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
        PeerMessage::Directory { record, .. } => u64::from(record.agent.0),
        PeerMessage::DirectoryAck { agent, .. }
        | PeerMessage::DirectoryRequest { agent }
        | PeerMessage::Forward { agent, .. }
        | PeerMessage::Forwarded { agent, .. }
        | PeerMessage::ReadIndex { agent, .. }
        | PeerMessage::ReadIndexAnswer { agent, .. }
        | PeerMessage::Deliver { to: agent, .. }
        | PeerMessage::Acknowledge { sender: agent, .. }
        | PeerMessage::Behind { sender: agent, .. }
        | PeerMessage::AnchorRow { agent, .. }
        | PeerMessage::AnchorRowAnswer { agent, .. }
        | PeerMessage::Proved { agent, .. } => u64::from(agent.0),
        PeerMessage::Blob { .. } | PeerMessage::Liveness { .. } => 0,
    }
}

/// A frame from a peer, whole.
pub fn decode(frame: &[u8]) -> Result<PeerMessage, Refusal> {
    PeerMessage::decode_exact(frame).ok_or(Refusal::Undecodable)
}

/// Check what `from` sent on `class` and `stream` against `space`, the
/// nodes configured in the space, and `ours`, its id. `followed` gives the
/// leader a replica of an agent follows and its term, if it follows one.
pub fn check(
    space: &[NodeNumber],
    ours: &SpaceId,
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
        // At creation (term 0) from its creator, or relayed whole by one
        // of its replicas, which holds the creator's; then from a node of
        // the placement, or of the configuration it supersedes: a leader
        // removing itself.
        PeerMessage::Directory { record, .. } if record.space != *ours => Err(Refusal::OtherSpace),
        PeerMessage::Directory { record, placement } => {
            let creator = CreationRecord::creator_of(record.agent);
            let from_creator = record.creator == from && creator == from;
            let relayed = record.creator == creator
                && record.replicas.contains(&from)
                && *placement == Placement::created(record);
            let from_member =
                placement.replicas.contains(&from) || placement.before.contains(&from);
            if (placement.term == 0 && (from_creator || relayed))
                || (placement.term > 0 && from_member)
            {
                Ok(())
            } else {
                Err(Refusal::NotTheCreator)
            }
        }
        PeerMessage::DirectoryAck { .. }
        | PeerMessage::DirectoryRequest { .. }
        | PeerMessage::SnapshotAck(_)
        | PeerMessage::BlobRequest { .. }
        | PeerMessage::Liveness { .. }
        | PeerMessage::Forward { .. }
        | PeerMessage::Forwarded { .. }
        | PeerMessage::ReadIndex { .. }
        | PeerMessage::ReadIndexAnswer { .. }
        | PeerMessage::Deliver { .. }
        | PeerMessage::Acknowledge { .. }
        | PeerMessage::Behind { .. }
        | PeerMessage::AnchorRow { .. }
        | PeerMessage::AnchorRowAnswer { .. }
        | PeerMessage::Proved { .. } => Ok(()),
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
