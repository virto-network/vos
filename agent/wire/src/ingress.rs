//! What clients send a node's ingress and what it answers, and the bytes a
//! client signs. A client is an ed25519 key; every signed message starts
//! with a domain tag and the agent's identity, the hash of its creation
//! record, so a signature made for one agent or one kind of message is good
//! for no other, and every replica of the agent checks the same one.

use alloc::string::String;
use alloc::vec::Vec;
use scale::{Decode, Encode};

use crate::abi::Refusal;
use crate::ids::{AgentId, InstanceId, MethodId, Principal, Session, WorkflowId};
use crate::peer::{CreationRecord, NodeNumber};
use crate::result::Outcome;

const CALL_DOMAIN: &[u8] = b"vos/call/1";
const QUERY_DOMAIN: &[u8] = b"vos/query/1";
const WORKFLOW_DOMAIN: &[u8] = b"vos/workflow/1";

/// The longest a read of a workflow waits for it to end, in milliseconds.
pub const MAX_WORKFLOW_WAIT_MS: u64 = 30_000;
/// How far past its wait a read of a workflow may be good, in milliseconds
/// of the node's time: a read captured is good no longer.
pub const WORKFLOW_READ_HORIZON_MS: u64 = 60_000;

/// How far past the node's time a read of a workflow waiting `wait_ms` may
/// be good, in milliseconds.
pub fn workflow_read_horizon(wait_ms: u64) -> u64 {
    WORKFLOW_READ_HORIZON_MS + wait_ms.min(MAX_WORKFLOW_WAIT_MS)
}

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

/// `POST /agents/{agent}/workflows`: workflow `workflow`'s status, read by
/// `key`, its owner, good until `not_after` by the node's clock, at most
/// [`workflow_read_horizon`] past it, on state as `consistency` asks. A workflow not
/// ended is waited for, until it ends or `wait_ms` pass, at most
/// [`MAX_WORKFLOW_WAIT_MS`], or less as the node allows.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct WorkflowRead {
    pub key: [u8; 32],
    pub not_after: u64,
    pub consistency: Consistency,
    pub workflow: WorkflowId,
    pub wait_ms: u64,
    pub signature: [u8; 64],
}

/// Where a workflow stands, as its owner reads it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum WorkflowStatus {
    /// No workflow of that id owned by the key that read: never started,
    /// another's, or collected. An ended workflow's result is kept about an
    /// hour ([`crate::defaults::WORKFLOW_KEPT_MS`]) after its end, then
    /// reads as this.
    #[codec(index = 0)]
    Unknown,
    /// Due to run: started, or preempted between two awaits.
    #[codec(index = 1)]
    Running,
    /// Awaiting `agent`'s answer until `deadline`, by the agent's time.
    #[codec(index = 2)]
    Awaiting { agent: AgentId, deadline: u64 },
    /// Asleep until a batch at or past `until`.
    #[codec(index = 3)]
    Sleeping { until: u64 },
    /// Ended: its result, or why it failed.
    #[codec(index = 4)]
    Ended(Outcome),
    /// Awaiting its read at window `window`'s cut until `deadline`, by the
    /// agent's time.
    #[codec(index = 5)]
    Attesting { window: u64, deadline: u64 },
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

/// The operator's `POST /agents/{agent}/install`: the package, the ELF its
/// actor's crate built, as it is, from which the node derives its programs,
/// and the agent's role byte for each role name its schema uses. Answered
/// with the install's outcome, the [`crate::records::Derivation`] encoded.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Install {
    pub instance: InstanceId,
    pub elf: Vec<u8>,
    pub roles: Vec<(Vec<u8>, u8)>,
}

/// The operator's `POST /agents/{agent}/replicas`: one replica replaced
/// by another node.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Replace {
    pub remove: NodeNumber,
    pub add: NodeNumber,
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

/// The operator's `POST /agents/{agent}/roles`: a principal's role in the
/// agent, or (`None`) none. The log carries it as
/// [`crate::batch::Admin::SetRole`].
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
pub enum Response {
    /// The step ran, or the query did: its outcome, and the applied index
    /// of the state the answer reflects, which a later query may ask a
    /// replica to have reached.
    #[codec(index = 0)]
    Ran { outcome: Outcome, at: u64 },
    /// The agent refused it.
    #[codec(index = 1)]
    Refused(Refusal),
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
    Placed(Vec<NodeNumber>),
    /// A replacement not made, and why.
    #[codec(index = 14)]
    Unplaced(Unplaced),
    /// The operator's `GET /agents/{agent}/status`: this node's replica.
    #[codec(index = 15)]
    Status(ReplicaStatus),
    /// The operator's `GET /stats`: how long this node's stages took.
    #[codec(index = 16)]
    Stats(Stats),
    /// A workflow's status, and the applied index of the state it was read
    /// at.
    #[codec(index = 17)]
    Workflow { status: WorkflowStatus, at: u64 },
}

/// How long a node's stages took since it started, each as a histogram
/// over [`bucket`]'s buckets.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Stats {
    pub stages: Vec<Stage>,
    /// The node's replica groups now.
    pub groups: Groups,
}

/// A node's replica groups at one moment: how many it holds, how many it
/// leads, and their terms summed, which grows by one at each election any
/// of them holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Groups {
    pub replicas: u64,
    pub leading: u64,
    pub terms: u64,
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
    pub leader: Option<NodeNumber>,
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
    /// The term of the placement its node's directory holds for the agent:
    /// the leader's that announced it.
    pub placement_term: u64,
}

/// The operator's `POST /agents`: the nodes to replicate the new agent,
/// by number. None means the node alone.
#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Create {
    pub replicas: Vec<NodeNumber>,
}

fn message(domain: &[u8], identity: &[u8; 32], fields: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(identity);
    fields(&mut bytes);
    bytes
}

impl Call {
    /// What its session's key signs for the agent whose identity is
    /// `identity`: [`call_message`] of its fields.
    pub fn message(&self, identity: &[u8; 32]) -> Vec<u8> {
        call_message(
            identity,
            &self.session,
            self.sequence,
            self.instance,
            self.method,
            &self.arguments,
        )
    }
}

impl QueryCall {
    /// What its key signs for the agent whose identity is `identity`:
    /// [`query_message`] of its fields.
    pub fn message(&self, identity: &[u8; 32]) -> Vec<u8> {
        query_message(
            identity,
            &self.key,
            self.not_after,
            self.consistency,
            self.instance,
            self.method,
            &self.arguments,
        )
    }
}

impl WorkflowRead {
    /// What its key signs for the agent whose identity is `identity`:
    /// [`workflow_message`] of its fields.
    pub fn message(&self, identity: &[u8; 32]) -> Vec<u8> {
        workflow_message(
            identity,
            &self.key,
            self.not_after,
            self.consistency,
            self.workflow,
            self.wait_ms,
        )
    }
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
        arguments.encode_to(bytes);
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
        arguments.encode_to(bytes);
    })
}

/// What a client signs for a read of a workflow of the agent whose
/// identity is `identity`.
pub fn workflow_message(
    identity: &[u8; 32],
    key: &[u8; 32],
    not_after: u64,
    consistency: Consistency,
    workflow: WorkflowId,
    wait_ms: u64,
) -> Vec<u8> {
    message(WORKFLOW_DOMAIN, identity, |bytes| {
        bytes.extend_from_slice(key);
        not_after.encode_to(bytes);
        consistency.encode_to(bytes);
        workflow.encode_to(bytes);
        wait_ms.encode_to(bytes);
    })
}
