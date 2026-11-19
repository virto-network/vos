//! What a node answers when a call, a replacement or its start fails.

use vos_abi::abi::Refusal;
use vos_abi::ids::AgentId;
use vos_abi::result::Outcome;
use vos_wire::ingress::{Contact, Unplaced};

/// How the node answered a request or an admin command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// The step ran: the handler's reply, or its failure.
    Ran(Outcome),
    /// Refine refused it.
    Refused(Refusal),
    /// The agent program fails on a batch holding this input alone.
    Failed,
    /// A duplicate whose reply the window no longer keeps.
    TooOld,
}

/// Why a call has no reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallError {
    /// The agent's queue is full.
    Busy,
    NoAgent,
    /// The agent's leader stopped before answering.
    Stopped,
    /// Storage or the agent program failed.
    Failed(String),
    /// This node does not lead the agent: its leader, when known.
    NotLeader(Option<Contact>),
    /// This node does not replicate the agent: its replicas.
    Elsewhere(Vec<Contact>),
    /// The agent is created, but a majority of its replicas does not hold
    /// its record yet: it reaches them as they return.
    Unconfirmed(AgentId),
    /// No answer within the node's deadline: it may have run, or may yet.
    TimedOut,
}

/// Why a replica was not replaced.
#[derive(Debug)]
pub enum ReplaceError {
    Call(CallError),
    Unplaced(Unplaced),
    /// The change goes on: the agent's placement says where it is.
    TimedOut,
}

#[derive(Debug)]
pub enum Error {
    Store(fjall::Error),
    /// The agent program does not load, or a stored program does not
    /// install.
    Program(String),
    /// The agent program is past the Gray Paper's bound on a service's
    /// code (`W_C`, [`vos_pvm::spi::MAX_SERVICE_CODE`] bytes): a JAM node
    /// refines and accumulates it as `BIG`, so no node runs it. The node
    /// counts the program alone; a JAM deployment's metadata prefix counts
    /// on top (`vos_jam_dev::service_code`).
    ServiceTooBig,
    /// The refine gas cannot fit the largest handler, or a workflow's
    /// largest step, with the agent's reserves behind a full batch's other
    /// inputs (`defaults::min_refine_gas`): some input or step could never
    /// be dispatched.
    Gas,
    /// The device formats configured are none, not ones this binary
    /// verifies, more than two, or name one twice
    /// (`Config::device_formats`).
    Formats,
    /// The data directory, the space, the network or the ingress's
    /// listener failed.
    Data(String),
    /// The process's PVM backend cannot be chosen: an override
    /// (`VOS_PVM_BACKEND`) this host cannot honour or does not know
    /// (`vos_pvm::backend::backend_choice`).
    Backend(String),
}

impl From<fjall::Error> for Error {
    fn from(error: fjall::Error) -> Self {
        Error::Store(error)
    }
}
