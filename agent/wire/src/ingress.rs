//! What clients send a node's ingress and what it answers, and the bytes a
//! client signs. A client is an ed25519 key; every signed message starts
//! with a domain tag and the node's id, so a signature made for one node or
//! one kind of message is good for no other.

use alloc::vec::Vec;
use scale::{Decode, Encode};

use crate::ids::{AgentId, InstanceId, MethodId, Principal, SessionId};
use crate::result::Outcome;

pub const OPEN_DOMAIN: &[u8] = b"vos/session/1";
pub const CALL_DOMAIN: &[u8] = b"vos/call/1";
pub const QUERY_DOMAIN: &[u8] = b"vos/query/1";

/// A node's identity: its ed25519 public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct NodeId(pub [u8; 32]);

/// `POST /sessions`: open a session for `key`, at the client's `time` in
/// milliseconds since the Unix epoch.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Open {
    pub key: [u8; 32],
    pub time: u64,
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Opened {
    pub node: NodeId,
    pub session: SessionId,
}

/// `POST /agents/{agent}/calls`: a command, in its session's sequence for
/// that agent.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Call {
    pub session: SessionId,
    pub sequence: u64,
    pub instance: InstanceId,
    pub method: MethodId,
    pub arguments: Vec<u8>,
    pub signature: [u8; 64],
}

/// `POST /agents/{agent}/queries`: a query, good until `not_after` by the
/// node's clock.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct QueryCall {
    pub session: SessionId,
    pub not_after: u64,
    pub instance: InstanceId,
    pub method: MethodId,
    pub arguments: Vec<u8>,
    pub signature: [u8; 64],
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
    UnknownSession,
    #[codec(index = 1)]
    BadSignature,
    /// A duplicate whose reply the window no longer keeps.
    #[codec(index = 2)]
    TooOld,
    /// A sequence past the next one; resend from `expected`.
    #[codec(index = 3)]
    Gap { expected: u64 },
    /// More than the reply window past the applied mark: receive replies
    /// first.
    #[codec(index = 4)]
    Ahead,
    /// A query past its `not_after`, or one too far ahead.
    #[codec(index = 5)]
    StaleQuery,
    /// An open whose time is off the node's clock or not after the key's
    /// last open.
    #[codec(index = 6)]
    StaleOpen,
    /// An operator command without the node's admin token.
    #[codec(index = 7)]
    Unauthorized,
    #[codec(index = 8)]
    Malformed,
}

/// Ingress's answer to a call, a query or an operator command.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Answer {
    /// The step ran, or the query did: its outcome.
    #[codec(index = 0)]
    Ran(Outcome),
    /// The agent refused it, with a code from [`crate::abi::refusal`].
    #[codec(index = 1)]
    Refused(u32),
    #[codec(index = 2)]
    Rejected(Rejection),
    /// Not consumed: the agent program failed on it alone. Resend the same
    /// sequence, or open a new session.
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
}

fn message(domain: &[u8], node: &NodeId, fields: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&node.0);
    fields(&mut bytes);
    bytes
}

/// What a client signs to open a session.
pub fn open_message(node: &NodeId, key: &[u8; 32], time: u64) -> Vec<u8> {
    message(OPEN_DOMAIN, node, |bytes| {
        bytes.extend_from_slice(key);
        time.encode_to(bytes);
    })
}

/// What a client signs for a call to `agent`.
pub fn call_message(
    node: &NodeId,
    agent: AgentId,
    session: SessionId,
    sequence: u64,
    instance: InstanceId,
    method: MethodId,
    arguments: &[u8],
) -> Vec<u8> {
    message(CALL_DOMAIN, node, |bytes| {
        agent.encode_to(bytes);
        session.encode_to(bytes);
        sequence.encode_to(bytes);
        instance.encode_to(bytes);
        method.encode_to(bytes);
        arguments.to_vec().encode_to(bytes);
    })
}

/// What a client signs for a query to `agent`.
pub fn query_message(
    node: &NodeId,
    agent: AgentId,
    session: SessionId,
    not_after: u64,
    instance: InstanceId,
    method: MethodId,
    arguments: &[u8],
) -> Vec<u8> {
    message(QUERY_DOMAIN, node, |bytes| {
        agent.encode_to(bytes);
        session.encode_to(bytes);
        not_after.encode_to(bytes);
        instance.encode_to(bytes);
        method.encode_to(bytes);
        arguments.to_vec().encode_to(bytes);
    })
}
