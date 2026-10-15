//! How an invocation ended, and where a workflow's step paused.

use alloc::vec::Vec;

use vos_wire::ids::AgentId;
use vos_wire::records::WorkflowState;

/// How an invocation ended, short of failing the whole step.
pub(crate) enum Ended {
    Replied(Vec<u8>),
    Failed(Vec<u8>),
    Forbidden,
    /// A workflow paused.
    Paused(Pause),
}

/// Where a workflow's step paused: awaiting another agent's answer to
/// await `counter` until a deadline, asleep until a time, or preempted
/// between two awaits, before the host call `pending` when it was not
/// served. A step preempted out of gas `idle`, having served no call and
/// written no page since it resumed, moved only if its registers or its
/// counter did.
pub(crate) enum Pause {
    Await {
        agent: AgentId,
        counter: u64,
        deadline: u64,
    },
    Sleep {
        until: u64,
    },
    Preempted {
        pending: Option<u64>,
        idle: bool,
    },
}

impl Pause {
    /// The batch time its row in the due index lies at, in a batch at
    /// `time`: a preempted workflow's is the next millisecond's, so its row
    /// moves and the next batch continues it.
    pub(crate) fn due(&self, time: u64) -> u64 {
        match self {
            Pause::Await { deadline, .. } => *deadline,
            Pause::Sleep { until } => *until,
            Pause::Preempted { .. } => time.saturating_add(1),
        }
    }

    /// The host call a preempted step left unserved.
    pub(crate) fn pending(&self) -> Option<u64> {
        match self {
            Pause::Preempted { pending, .. } => *pending,
            _ => None,
        }
    }

    /// The workflow's state while it pauses, `input` the step's.
    pub(crate) fn state(self, input: &[u8]) -> WorkflowState {
        match self {
            Pause::Await {
                agent,
                counter,
                deadline,
            } => WorkflowState::Awaiting {
                agent,
                counter,
                deadline,
            },
            Pause::Sleep { until } => WorkflowState::Sleeping { until },
            Pause::Preempted { .. } => WorkflowState::Preempted(input.to_vec()),
        }
    }
}
