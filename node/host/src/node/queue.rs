//! An agent's queue: the inputs its leader loop takes, with where their
//! replies go.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Instant;

use vos_wire::batch::{Admin, Input, Message, Request};
use vos_wire::ids::AgentId;

use super::{CallError, Inner, Reply};
use crate::lock;
use crate::store::BlobRef;

/// A reply, with the applied index of the state it reflects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Answered {
    pub(crate) reply: Reply,
    pub(crate) at: u64,
}

pub(crate) type Answer = smol::channel::Sender<Result<Answered, CallError>>;

/// A queued input, with where its reply goes.
pub(crate) enum Pending {
    Request {
        request: Request,
        answer: Answer,
    },
    /// An admin command, with the blobs its entry names.
    Admin {
        admin: Admin,
        answer: Answer,
        blobs: Vec<BlobRef>,
    },
    Message(Message),
    Ack {
        to: AgentId,
        sequence: u64,
    },
    /// The leader's sweep of expired sessions.
    Sweep,
}

impl Pending {
    pub(crate) fn input(&self) -> Input {
        match self {
            Pending::Request { request, .. } => Input::Request(request.clone()),
            Pending::Admin { admin, .. } => Input::Admin(admin.clone()),
            Pending::Message(message) => Input::Message(message.clone()),
            Pending::Ack { to, sequence } => Input::Ack {
                to: *to,
                sequence: *sequence,
            },
            Pending::Sweep => Input::Sweep,
        }
    }

    pub(crate) fn bytes(&self) -> usize {
        match self {
            Pending::Request { request, .. } => request.arguments.len(),
            Pending::Message(message) => message.arguments.len(),
            Pending::Admin { .. } | Pending::Ack { .. } | Pending::Sweep => 0,
        }
    }

    /// Counts against the queue cap: what a client queued.
    pub(crate) fn capped(&self) -> bool {
        matches!(self, Pending::Request { .. } | Pending::Admin { .. })
    }

    /// Counts against the cap on the messages other agents queue, which
    /// other nodes now fill. Acknowledgements do not: they open this
    /// agent's own windows, and the batch takes one per target.
    pub(crate) fn agents_sent(&self) -> bool {
        matches!(self, Pending::Message(_))
    }

    /// Answer that this node does not lead, when the input has a caller.
    pub(crate) fn refuse(self, hint: &CallError) {
        if let Pending::Request { answer, .. } | Pending::Admin { answer, .. } = self {
            let _ = answer.try_send(Err(hint.clone()));
        }
    }
}

#[derive(Default)]
pub(crate) struct Queue {
    /// Each with when it was queued.
    pub(crate) inputs: VecDeque<(Pending, Instant)>,
    /// Capped inputs queued.
    pub(crate) capped: usize,
    /// Messages from other agents queued.
    pub(crate) from_agents: usize,
    pub(crate) stopped: bool,
    /// The leader loop takes inputs: set when this replica's leadership
    /// starts, and cleared with the refusal of what it left. Under the
    /// queue's lock, so no input is queued where no loop will take it.
    pub(crate) leading: bool,
}

pub(crate) struct Agent {
    pub(crate) queue: Mutex<Queue>,
    wake: smol::channel::Sender<()>,
    pub(crate) woken: smol::channel::Receiver<()>,
}

impl Agent {
    pub(super) fn new() -> Self {
        let (wake, woken) = smol::channel::bounded(1);
        Self {
            queue: Mutex::new(Queue::default()),
            wake,
            woken,
        }
    }

    /// Stop the agent's leader after its batch in flight. Queued inputs are
    /// dropped: their callers see `Stopped`.
    pub(crate) fn stop(&self) {
        let dropped = {
            let mut queue = lock(&self.queue);
            queue.stopped = true;
            queue.capped = 0;
            queue.from_agents = 0;
            std::mem::take(&mut queue.inputs)
        };
        drop(dropped);
        let _ = self.wake.try_send(());
    }

    /// Answer every queued input with `error`: this node no longer leads.
    pub(crate) fn refuse(&self, error: &CallError) {
        let refused = {
            let mut queue = lock(&self.queue);
            queue.leading = false;
            queue.capped = 0;
            queue.from_agents = 0;
            std::mem::take(&mut queue.inputs)
        };
        for (pending, _) in refused {
            pending.refuse(error);
        }
    }
}

impl Inner {
    /// Queue `pending` for agent `id`, whose leader loop this node must
    /// run. Checked under the queue's lock, from any thread.
    pub(crate) fn push(&self, id: AgentId, pending: Pending) -> Result<(), CallError> {
        let run = self.run(id).ok_or_else(|| self.absent(id))?;
        let mut queue = lock(&run.agent.queue);
        if queue.stopped || run.shared.state().stopped {
            return Err(CallError::Stopped);
        }
        if !queue.leading {
            drop(queue);
            return Err(self.not_leader(&run.shared));
        }
        if pending.capped() {
            if queue.capped >= self.settings.queue_cap {
                return Err(CallError::Busy);
            }
            queue.capped += 1;
        }
        // Past the cap, the sender sends it again.
        if pending.agents_sent() {
            if queue.from_agents >= self.settings.queue_cap {
                return Err(CallError::Busy);
            }
            queue.from_agents += 1;
        }
        queue.inputs.push_back((pending, Instant::now()));
        drop(queue);
        let _ = run.agent.wake.try_send(());
        Ok(())
    }

    /// Put inputs back at the front of agent `id`'s queue, in order, as
    /// queued now.
    pub(crate) fn requeue(&self, agent: &Agent, inputs: Vec<Pending>) {
        let mut queue = lock(&agent.queue);
        if queue.stopped {
            return;
        }
        for pending in inputs.into_iter().rev() {
            if pending.capped() {
                queue.capped += 1;
            }
            if pending.agents_sent() {
                queue.from_agents += 1;
            }
            queue.inputs.push_front((pending, Instant::now()));
        }
    }
}
