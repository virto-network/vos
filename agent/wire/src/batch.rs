//! A refine's input: the batch the node assembles for one agent.

use alloc::vec::Vec;
use scale::{Decode, Encode};

use crate::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash, Session};

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
    /// Applied, non-skipped work results before this one (section 7.5).
    pub version: u64,
    /// Milliseconds since the Unix epoch by the leader's wall clock,
    /// monotonic across leaders.
    pub time: u64,
    /// From the leader's operating system. The work result carries both,
    /// so a replay reads them and never draws them again.
    pub seed: [u8; 32],
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
    /// Collect the sessions whose expiry rows are due at the batch's time.
    /// The node puts it first in a batch.
    #[codec(index = 4)]
    Sweep,
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
    pub instance: InstanceId,
    pub method: MethodId,
    pub arguments: Vec<u8>,
}

/// An operator command, applied through the log like any input.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Admin {
    /// Install a package as an instance: its actor program, the program
    /// bound to each attestable method, and the agent's role byte for each
    /// role name the schema uses.
    #[codec(index = 0)]
    Install {
        instance: InstanceId,
        program: ProgramHash,
        attestables: Vec<(MethodId, ProgramHash)>,
        roles: Vec<(Vec<u8>, u8)>,
    },
    /// Grant a principal a role in this agent, or (`None`) revoke it. A role
    /// is a byte; a package's schema names its roles, and `#[msg(role)]`
    /// refers to one by name.
    #[codec(index = 1)]
    SetRole {
        principal: Principal,
        role: Option<u8>,
    },
}
