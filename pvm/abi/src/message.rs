//! What agents send each other: a message's body, the await a request
//! names, and the answer a reply carries. A batch delivers them in, and a
//! step's result sends them out.

use alloc::vec::Vec;
use scale::{Decode, Encode};

use crate::abi::Failure;
use crate::ids::{InstanceId, MethodId, WorkflowId};
use crate::result::Outcome;

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
    /// The space's representative closed window `window`: its root at its
    /// cut of the window, and the receiver's row's salt and path against
    /// it, which every read the receiver serves at that window's cut
    /// carries ([`crate::keys::closed`]).
    #[codec(index = 3)]
    Closed {
        window: u64,
        rep_root: [u8; 32],
        rep_salt: [u8; 16],
        space_path: Vec<u8>,
    },
    /// The sender's root at a window's cut, for the receiver, its space's
    /// representative: refine stores it natively in the representative's
    /// committed map ([`crate::served::representative_row`]), as no
    /// program's call can, the sender its message's.
    #[codec(index = 4)]
    Report(crate::served::AgentRoot),
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
            Body::Wait { .. } | Body::Report(_) => 0,
            Body::Closed { space_path, .. } => space_path.len(),
        }
    }

    /// The await a request names, which its step answers.
    pub fn awaiting(&self) -> Option<Await> {
        match self {
            Body::Call { awaiting, .. } => *awaiting,
            Body::Wait { awaiting, .. } => Some(*awaiting),
            Body::Reply { .. } | Body::Closed { .. } | Body::Report(_) => None,
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

impl Answer {
    /// A request's step that failed with `code`, and no detail.
    pub fn failed(code: Failure) -> Self {
        Answer::Failed {
            code,
            detail: Vec::new(),
        }
    }
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
