//! What clients send a node's ingress and what it answers, and the bytes a
//! client signs. A client is an ed25519 key; every signed message starts
//! with a domain tag and the agent's identity, the hash of its creation
//! record, so a signature made for one agent or one kind of message is good
//! for no other, and every replica of the agent checks the same one.

use alloc::string::String;
use alloc::vec::Vec;
use scale::{Decode, Encode};

use crate::ids::{AgentId, InstanceId, MethodId, Principal, Session};
use crate::peer::CreationRecord;
use crate::result::Outcome;

pub const CALL_DOMAIN: &[u8] = b"vos/call/1";
pub const QUERY_DOMAIN: &[u8] = b"vos/query/1";

/// A node's identity: its ed25519 public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct NodeId(pub [u8; 32]);

/// A node a client can call: its ingress address, and its key, which its
/// TLS presents.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Contact {
    pub address: String,
    pub node: NodeId,
}

/// `GET /agents/{agent}`: the agent's creation record, whose hash is its
/// identity, and its replicas, any of which serves it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct AgentInfo {
    pub record: CreationRecord,
    pub replicas: Vec<Contact>,
}

/// `POST /agents/{agent}/calls`: a command, in its session's sequence for
/// that agent. The session's key signs it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Call {
    pub session: Session,
    pub sequence: u64,
    pub instance: InstanceId,
    pub method: MethodId,
    pub arguments: Vec<u8>,
    pub signature: [u8; 64],
}

/// `POST /agents/{agent}/queries`: a query by `key`, good until
/// `not_after` by the node's clock, on state as `consistency` asks.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct QueryCall {
    pub key: [u8; 32],
    pub not_after: u64,
    pub consistency: Consistency,
    pub instance: InstanceId,
    pub method: MethodId,
    pub arguments: Vec<u8>,
    pub signature: [u8; 64],
}

/// Which applied state a query reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Consistency {
    /// The replica's, once it has applied through `at`: a client reads its
    /// own writes, and never goes back, by asking for the highest `at` it
    /// has been answered.
    #[codec(index = 0)]
    Applied { at: u64 },
    /// State that holds every call answered before the query was taken:
    /// the replica first learns from the leader how far to apply.
    #[codec(index = 1)]
    Linearizable,
}

/// The operator's `POST /agents/{agent}/install`.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Install {
    pub instance: InstanceId,
    pub program: Vec<u8>,
    pub attestables: Vec<(MethodId, Vec<u8>)>,
    pub roles: Vec<(Vec<u8>, u8)>,
}

/// The operator's `POST /agents/{agent}/replicas`: one replica replaced
/// by another node.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Replace {
    pub remove: u8,
    pub add: u8,
}

/// Why a replacement was not made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Unplaced {
    /// The node to remove does not replicate the agent.
    #[codec(index = 0)]
    NotAReplica,
    /// The node to add replicates it already.
    #[codec(index = 1)]
    AlreadyAReplica,
    /// The node to add is not in the space.
    #[codec(index = 2)]
    NotInTheSpace,
    /// Another change of the agent's replicas is under way.
    #[codec(index = 3)]
    InProgress,
    /// The node to add cannot run the agent's program, or did not say.
    #[codec(index = 4)]
    CannotRun,
}

/// The operator's `POST /agents/{agent}/roles`.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Grant {
    pub principal: Principal,
    pub role: Option<u8>,
}

/// Why ingress refused, before the agent saw anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Rejection {
    #[codec(index = 0)]
    BadSignature,
    /// A duplicate whose reply the window no longer keeps.
    #[codec(index = 1)]
    TooOld,
    /// A sequence past the next one; resend from `expected`.
    #[codec(index = 2)]
    Gap { expected: u64 },
    /// More than the reply window past the applied mark: receive replies
    /// first.
    #[codec(index = 3)]
    Ahead,
    /// A query past its `not_after`, or one too far ahead of `now`, the
    /// node's time: sign it again with a `not_after` near it.
    #[codec(index = 4)]
    StaleQuery { now: u64 },
    /// A new session whose creation time is too far from the agent's time,
    /// `now`: start one with a time near it.
    #[codec(index = 5)]
    StaleSession { now: u64 },
    /// An operator command without the node's admin token.
    #[codec(index = 6)]
    Unauthorized,
    #[codec(index = 7)]
    Malformed,
    /// The replica has not applied through the index the query asked for
    /// in time: ask another.
    #[codec(index = 8)]
    Behind,
}

/// Ingress's answer to a call, a query or an operator command.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Answer {
    /// The step ran, or the query did: its outcome, and the applied index
    /// of the state the answer reflects, which a later query may ask a
    /// replica to have reached.
    #[codec(index = 0)]
    Ran { outcome: Outcome, at: u64 },
    /// The agent refused it, with a code from [`crate::abi::refusal`].
    #[codec(index = 1)]
    Refused(u32),
    #[codec(index = 2)]
    Rejected(Rejection),
    /// Not consumed: the agent program failed on it alone. Resend the same
    /// sequence, or start a new session.
    #[codec(index = 3)]
    NotConsumed,
    #[codec(index = 4)]
    Busy,
    #[codec(index = 5)]
    NoAgent,
    /// The node stopped before answering.
    #[codec(index = 6)]
    Stopped,
    /// The operator's new agent.
    #[codec(index = 7)]
    Created(AgentId),
    /// The node failed to read or write, before anything was done: try
    /// again.
    #[codec(index = 8)]
    Unavailable,
    /// This node does not lead the agent: call its leader, when known.
    #[codec(index = 9)]
    NotLeader { leader: Option<Contact> },
    /// This node does not replicate the agent: call one of its replicas.
    #[codec(index = 10)]
    Elsewhere { replicas: Vec<Contact> },
    /// The operator's new agent, which a majority of its replicas does not
    /// hold yet: it reaches them as they return.
    #[codec(index = 11)]
    Unconfirmed(AgentId),
    /// No answer in time: the call may have run, or may yet. Send it again
    /// with the same sequence.
    #[codec(index = 12)]
    TimedOut,
    /// The agent's replicas, once a replacement committed.
    #[codec(index = 13)]
    Placed(Vec<u8>),
    /// A replacement not made, and why.
    #[codec(index = 14)]
    Unplaced(Unplaced),
    /// The operator's `GET /agents/{agent}/status`: this node's replica.
    #[codec(index = 15)]
    Status(ReplicaStatus),
    /// The operator's `GET /stats`: how long this node's stages took.
    #[codec(index = 16)]
    Stats(Stats),
}

/// How long a node's stages took since it started, each as a histogram
/// over [`bucket`]'s buckets.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Stats {
    pub stages: Vec<Stage>,
}

/// One stage's histogram: how many times it took a value in each bucket,
/// in microseconds (or, for a count, in units).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Stage {
    pub name: String,
    pub counts: Vec<u64>,
    /// The values recorded, summed: with the counts, an exact mean.
    pub total: u64,
}

/// The buckets a stage's values fall in: exact below 8, then four to each
/// power of two, so a bucket's values are within 25% of each other.
pub const BUCKETS: usize = 252;

/// The bucket `value` falls in.
pub fn bucket(value: u64) -> usize {
    if value < 8 {
        return value as usize;
    }
    let exponent = 63 - value.leading_zeros() as usize;
    let sub = ((value >> (exponent - 2)) & 3) as usize;
    8 + (exponent - 3) * 4 + sub
}

/// The highest value bucket `index` holds.
pub fn bucket_top(index: usize) -> u64 {
    if index < 8 {
        return index as u64;
    }
    let exponent = 3 + (index - 8) / 4;
    let sub = ((index - 8) % 4) as u64;
    let low = (4 + sub) << (exponent - 2);
    low + ((1u64 << (exponent - 2)) - 1)
}

/// A replica's Raft state, as its node has it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct ReplicaStatus {
    pub term: u64,
    pub leads: bool,
    /// The leader it knows, if any.
    pub leader: Option<u8>,
    pub commit: u64,
    pub applied: u64,
    /// The index its log starts after: where it was compacted to, or a
    /// snapshot installed at.
    pub log_start: u64,
    pub last_index: u64,
    /// The node halted: a flush failed, and it needs a restart.
    pub halted: bool,
    /// The sessions its applied state holds.
    pub sessions: u64,
    /// The messages its applied state holds unacknowledged.
    pub outbox: u64,
}

/// The operator's `POST /agents`: the nodes to replicate the new agent,
/// by number. None means the node alone.
#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Create {
    pub replicas: Vec<u8>,
}

fn message(domain: &[u8], identity: &[u8; 32], fields: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(identity);
    fields(&mut bytes);
    bytes
}

/// What a client signs for a call to the agent whose identity is
/// `identity`.
pub fn call_message(
    identity: &[u8; 32],
    session: &Session,
    sequence: u64,
    instance: InstanceId,
    method: MethodId,
    arguments: &[u8],
) -> Vec<u8> {
    message(CALL_DOMAIN, identity, |bytes| {
        session.encode_to(bytes);
        sequence.encode_to(bytes);
        instance.encode_to(bytes);
        method.encode_to(bytes);
        arguments.to_vec().encode_to(bytes);
    })
}

/// What a client signs for a query to the agent whose identity is
/// `identity`.
pub fn query_message(
    identity: &[u8; 32],
    key: &[u8; 32],
    not_after: u64,
    consistency: Consistency,
    instance: InstanceId,
    method: MethodId,
    arguments: &[u8],
) -> Vec<u8> {
    message(QUERY_DOMAIN, identity, |bytes| {
        bytes.extend_from_slice(key);
        not_after.encode_to(bytes);
        consistency.encode_to(bytes);
        instance.encode_to(bytes);
        method.encode_to(bytes);
        arguments.to_vec().encode_to(bytes);
    })
}
