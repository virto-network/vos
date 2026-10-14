//! A refine's input: the batch the node assembles for one agent.

use alloc::vec::Vec;
use scale::{Decode, Encode};

use crate::abi::{Failure, Kind};
use crate::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash, Session, WorkflowId};
use crate::ingress::Grant;
use crate::keys::Due;
use crate::result::Outcome;

/// A refine's work item payload: a batch through the log, or a query on
/// applied state.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Work {
    /// Refine returns the encoded [`crate::result::WorkResult`].
    #[codec(index = 0)]
    Batch(Batch),
    /// Refine returns the encoded [`crate::result::Outcome`] and nothing
    /// else: a query never writes.
    #[codec(index = 1)]
    Query(Query),
}

/// A `&self` handler on applied state, outside the log. Its time and seed
/// are the last applied work result's.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Query {
    pub time: u64,
    pub seed: [u8; 32],
    pub caller: Principal,
    pub instance: InstanceId,
    pub method: MethodId,
    pub arguments: Vec<u8>,
}

/// One refine's batch: the state version it builds on, the leader's time
/// and seed for it, and the inputs in order.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Batch {
    /// Applied, non-skipped work results before this one.
    pub version: u64,
    /// Milliseconds since the Unix epoch by the leader's wall clock,
    /// monotonic across leaders.
    pub time: u64,
    /// From the leader's operating system. The work result carries both,
    /// so a replay reads them and never draws them again.
    pub seed: [u8; 32],
    /// The gas the node runs the refine with.
    pub budget: u64,
    pub inputs: Vec<Input>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Input {
    #[codec(index = 0)]
    Request(Request),
    #[codec(index = 1)]
    Message(Message),
    #[codec(index = 2)]
    Admin(Admin),
    /// Agent `to` has applied this agent's messages to it through
    /// `sequence`: their outbox entries can go. The node sends it.
    #[codec(index = 3)]
    Ack { to: AgentId, sequence: u64 },
    /// Rows of the due index the leader read as due at the batch's time,
    /// oldest first, at most [`crate::defaults::SWEEP_LIMIT`], each its
    /// time and entry: refine collects the sessions among them and runs
    /// each workflow's due step, and ignores a row that is not there or
    /// not due. The node puts it first in a batch.
    #[codec(index = 4)]
    Sweep { due: Vec<(u64, Due)> },
    /// A message the agent program failed on alone, twice, each time on
    /// fresh state: the leader asserts it failed. Refine consumes it in
    /// its pair's order without running it, and answers the request's
    /// await, if any. Named by its pair's sequence, without its body.
    #[codec(index = 5)]
    Failed {
        from: AgentId,
        sequence: u64,
        awaiting: Option<Await>,
    },
}

/// A client request, in its session's sequence for this agent.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Request {
    pub session: Session,
    pub sequence: u64,
    pub caller: Principal,
    pub instance: InstanceId,
    pub method: MethodId,
    pub arguments: Vec<u8>,
}

/// A message from another agent, in that pair's sequence.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Message {
    pub from: AgentId,
    pub sequence: u64,
    pub body: Body,
}

/// What a message between agents carries.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Body {
    /// A call of `instance`'s `method`. One that names an await is a
    /// request: its step replies to the sender, whatever its outcome.
    #[codec(index = 0)]
    Call {
        instance: InstanceId,
        method: MethodId,
        arguments: Vec<u8>,
        awaiting: Option<Await>,
    },
    /// A request's answer, for the await it names.
    #[codec(index = 1)]
    Reply { awaiting: Await, answer: Answer },
    /// The sender awaits the result of a workflow it started here, at
    /// `awaiting`: answered with its outcome once it ends, at once if it
    /// has.
    #[codec(index = 2)]
    Wait {
        workflow: WorkflowId,
        awaiting: Await,
    },
}

impl Body {
    /// The bytes it carries: a call's arguments, or a reply's.
    pub fn payload_len(&self) -> usize {
        match self {
            Body::Call { arguments, .. } => arguments.len(),
            Body::Reply { answer, .. } => match answer {
                Answer::Done(bytes) | Answer::Failed { detail: bytes, .. } => bytes.len(),
                Answer::Started(_) => 0,
            },
            Body::Wait { .. } => 0,
        }
    }

    /// The await a request names, which its step answers.
    pub fn awaiting(&self) -> Option<Await> {
        match self {
            Body::Call { awaiting, .. } => *awaiting,
            Body::Wait { awaiting, .. } => Some(*awaiting),
            Body::Reply { .. } => None,
        }
    }
}

/// An await of a workflow: the workflow, and its count of awaits when it
/// made this one, so a reply finds the await it answers, or none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct Await {
    pub workflow: WorkflowId,
    pub counter: u64,
}

/// What a request is answered: its step's outcome, or the workflow it
/// started.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Answer {
    /// The handler's reply.
    #[codec(index = 0)]
    Done(Vec<u8>),
    /// The step failed, with its code and detail. A request refused before
    /// its handler ran fails too: [`Failure::Unknown`] for no such
    /// instance or method, [`Failure::Forbidden`] when the requesting
    /// agent lacks the handler's role.
    #[codec(index = 1)]
    Failed { code: Failure, detail: Vec<u8> },
    /// The request started a workflow, which answers its result to an
    /// await of its own.
    #[codec(index = 2)]
    Started(WorkflowId),
}

impl From<Outcome> for Answer {
    fn from(outcome: Outcome) -> Self {
        match outcome {
            Outcome::Done(reply) => Answer::Done(reply),
            Outcome::Failed { code, detail } => Answer::Failed { code, detail },
            Outcome::Started(workflow) => Answer::Started(workflow),
        }
    }
}

/// An operator command, applied through the log like any input.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Admin {
    /// Install a package as an instance: its actor program, the programs
    /// beside it, each bound to a method of its kind, an attestable or a
    /// workflow, and the agent's role byte for each role name the schema
    /// uses.
    #[codec(index = 0)]
    Install {
        instance: InstanceId,
        program: ProgramHash,
        beside: Vec<(MethodId, Kind, ProgramHash)>,
        roles: Vec<(Vec<u8>, u8)>,
    },
    /// Grant a principal a role in this agent, or (`None`) revoke it, as
    /// the operator posted it. A role is a byte; a package's schema names
    /// its roles, and `#[msg(role)]` refers to one by name.
    #[codec(index = 1)]
    SetRole(Grant),
}
