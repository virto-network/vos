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
    /// A query past its `not_after`, or one too far ahead.
    #[codec(index = 4)]
    StaleQuery,
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
