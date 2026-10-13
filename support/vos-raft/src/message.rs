//! Messages between the replicas of a group, as the protocol core emits and
//! receives them. Every message is one-way: an answer names what it answers,
//! because no request future survives to remember it.

use alloc::vec::Vec;

use crate::config::NodeId;
use crate::log_entry::LogEntry;

/// One protocol message. Exhaustive: a host's wire format mirrors every
/// message, and a new one must reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message<N: NodeId> {
    /// Entries, or none (a heartbeat), from a leader.
    Append {
        term: u64,
        leader: N,
        prev_index: u64,
        prev_term: u64,
        /// At most the receiver's acknowledged index, so a commit index never
        /// outruns what the receiver is known to hold.
        commit: u64,
        /// The heartbeat round this message belongs to; 0 before a term's
        /// first round, which confirms nothing.
        round: u64,
        entries: Vec<LogEntry<N>>,
    },
    /// A follower's answer to an append.
    AppendAnswer {
        term: u64,
        round: u64,
        /// The commit index the answered append carried.
        commit: u64,
        result: AppendResult,
    },
    Vote {
        term: u64,
        candidate: N,
        last_index: u64,
        last_term: u64,
    },
    VoteAnswer {
        term: u64,
        granted: bool,
    },
    /// Would the receiver vote for the sender at `next_term`? Changes no
    /// state on either side.
    PreVote {
        next_term: u64,
        candidate: N,
        last_index: u64,
        last_term: u64,
    },
    PreVoteAnswer {
        term: u64,
        next_term: u64,
        granted: bool,
    },
    /// Leadership transfer: the receiver starts an election at once.
    TimeoutNow {
        term: u64,
    },
}

/// The outcome of an append at a follower.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendResult {
    /// The follower holds the leader's log through `matched`, durably:
    /// min(durable, verified) when the answer left.
    Matched { matched: u64 },
    /// The follower's log does not hold `prev_index` at the leader's term.
    /// `rejected` is that `prev_index`, so a stale rejection is recognisable;
    /// the rest lets the leader skip a whole conflicting term at once.
    Rejected {
        rejected: u64,
        last_index: u64,
        /// The term of the follower's entry at `rejected`, or 0 when it
        /// holds none there: the leader then goes on from `last_index + 1`.
        conflict_term: u64,
        conflict_first: u64,
    },
}

impl<N: NodeId> Message<N> {
    /// The term the message was sent at; a pre-vote's is the sender's
    /// current term, one below the term it asks about.
    pub fn term(&self) -> u64 {
        match self {
            Message::Append { term, .. }
            | Message::AppendAnswer { term, .. }
            | Message::Vote { term, .. }
            | Message::VoteAnswer { term, .. }
            | Message::PreVoteAnswer { term, .. }
            | Message::TimeoutNow { term } => *term,
            Message::PreVote { next_term, .. } => next_term.saturating_sub(1),
        }
    }
}
