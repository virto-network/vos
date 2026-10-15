//! An agent's queue: the inputs its leader loop takes, with where their
//! replies go.

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::Instant;

use vos_wire::batch::{Admin, Input, Message, Request};
use vos_wire::ids::AgentId;
use vos_wire::keys::Due;

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
    /// A message the agent program failed on alone twice, which the
    /// leader asserts failed: its batch names it without its body.
    Failed(Message),
    Ack {
        to: AgentId,
        sequence: u64,
    },
    /// The leader's sweep of the rows of the due index due at its batch's
    /// time, which it lists: expired sessions, and workflows' steps. Empty,
    /// an idle leader's mark that a sweep may be due.
    Sweep(Vec<(u64, Due)>),
}

impl Pending {
    pub(crate) fn input(&self) -> Input {
        match self {
            Pending::Request { request, .. } => Input::Request(request.clone()),
            Pending::Admin { admin, .. } => Input::Admin(admin.clone()),
            Pending::Message(message) => Input::Message(message.clone()),
            Pending::Failed(message) => Input::Failed {
                from: message.from,
                sequence: message.sequence,
                awaiting: message.body.awaiting(),
            },
            Pending::Ack { to, sequence } => Input::Ack {
                to: *to,
                sequence: *sequence,
            },
            Pending::Sweep(due) => Input::Sweep { due: due.clone() },
        }
    }

    pub(crate) fn bytes(&self) -> usize {
        match self {
            Pending::Request { request, .. } => request.arguments.len(),
            Pending::Message(message) => message.body.payload_len(),
            // Its batch carries no body.
            Pending::Failed(_)
            | Pending::Admin { .. }
            | Pending::Ack { .. }
            | Pending::Sweep(_) => 0,
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
        matches!(self, Pending::Message(_) | Pending::Failed(_))
    }

    /// Answer the input's caller, when it has one.
    pub(crate) fn answer(self, answered: Result<Answered, CallError>) {
        if let Pending::Request { answer, .. } | Pending::Admin { answer, .. } = self {
            let _ = answer.try_send(answered);
        }
    }

    /// Answer that this node does not lead, when the input has a caller.
    pub(crate) fn refuse(self, hint: &CallError) {
        self.answer(Err(hint.clone()));
    }
}

#[derive(Default)]
pub(crate) struct Queue {
    /// Each with when it was queued.
    inputs: VecDeque<(Pending, Instant)>,
    /// Capped inputs queued.
    capped: usize,
    /// Messages from other agents queued.
    from_agents: usize,
    /// The agents that refused this agent's messages past a gap since the
    /// leader loop last looked: it sends them again.
    pub(crate) behind: BTreeSet<AgentId>,
    /// The agents whose messages this queue dropped full: told they are
    /// behind once it has room for them, rather than left to their rounds'
    /// backoff.
    pub(crate) dropped: Dropped,
    pub(crate) stopped: bool,
    /// The leader loop takes inputs: set when this replica's leadership
    /// starts, and cleared with the refusal of what it left. Under the
    /// queue's lock, so no input is queued where no loop will take it.
    pub(crate) leading: bool,
}

impl Queue {
    /// Queue `pending` last, unless the queue holds `cap` of its kind
    /// already: then false, and a message's sender is told once it has
    /// room.
    fn push_back(&mut self, pending: Pending, cap: usize) -> bool {
        if pending.capped() && self.capped >= cap {
            return false;
        }
        // Past the cap, the sender sends it again.
        if pending.agents_sent() && self.from_agents >= cap {
            if let Pending::Message(message) = &pending {
                self.dropped.insert(message.from, cap);
            }
            return false;
        }
        if let Some(count) = self.count_of(&pending) {
            *count += 1;
        }
        self.inputs.push_back((pending, Instant::now()));
        true
    }

    /// Put `inputs` back at the front, in order, as queued now.
    fn push_front(&mut self, inputs: Vec<Pending>) {
        for pending in inputs.into_iter().rev() {
            if let Some(count) = self.count_of(&pending) {
                *count += 1;
            }
            self.inputs.push_front((pending, Instant::now()));
        }
    }

    /// The first input, with when it was queued, if it `fits`.
    pub(crate) fn pop_front_if(
        &mut self,
        fits: impl FnOnce(&Pending) -> bool,
    ) -> Option<(Pending, Instant)> {
        if !fits(&self.inputs.front()?.0) {
            return None;
        }
        let (pending, queued) = self.inputs.pop_front()?;
        if let Some(count) = self.count_of(&pending) {
            *count -= 1;
        }
        Some((pending, queued))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.inputs.is_empty()
    }

    /// Every input, taken; the senders to send again, and to tell, are
    /// forgotten.
    fn take_all(&mut self) -> VecDeque<(Pending, Instant)> {
        self.capped = 0;
        self.from_agents = 0;
        self.behind.clear();
        self.dropped.clear();
        std::mem::take(&mut self.inputs)
    }

    /// The count `pending` is in: of the inputs clients queued, or of the
    /// messages other agents did. Acknowledgements and sweeps count in
    /// neither.
    fn count_of(&mut self, pending: &Pending) -> Option<&mut usize> {
        if pending.capped() {
            Some(&mut self.capped)
        } else if pending.agents_sent() {
            Some(&mut self.from_agents)
        } else {
            None
        }
    }

    /// The first senders whose messages it dropped full, as many as its
    /// room under `cap` fits a `window` of each's: to be told they are
    /// behind.
    pub(crate) fn untold(&mut self, cap: usize, window: usize) -> Vec<AgentId> {
        let window = window.min(cap).max(1);
        self.dropped
            .take(cap.saturating_sub(self.from_agents) / window)
    }
}

/// Senders whose messages a queue dropped full, each once, in the order
/// first dropped.
#[derive(Default)]
pub(crate) struct Dropped {
    order: VecDeque<AgentId>,
    senders: HashSet<AgentId>,
}

impl Dropped {
    /// Note `sender`, while fewer than `most` are.
    fn insert(&mut self, sender: AgentId, most: usize) {
        if self.order.len() < most && self.senders.insert(sender) {
            self.order.push_back(sender);
        }
    }

    /// The first `count`, taken.
    fn take(&mut self, count: usize) -> Vec<AgentId> {
        let taken: Vec<AgentId> = self.order.drain(..count.min(self.order.len())).collect();
        for sender in &taken {
            self.senders.remove(sender);
        }
        taken
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    fn clear(&mut self) {
        self.order.clear();
        self.senders.clear();
    }
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
            queue.take_all()
        };
        drop(dropped);
        let _ = self.wake.try_send(());
    }

    /// Answer every queued input with `error`: this node no longer leads.
    pub(crate) fn refuse(&self, error: &CallError) {
        let refused = {
            let mut queue = lock(&self.queue);
            queue.leading = false;
            queue.take_all()
        };
        for (pending, _) in refused {
            pending.refuse(error);
        }
    }

    /// Whether the leader loop takes inputs.
    pub(crate) fn leading(&self) -> bool {
        lock(&self.queue).leading
    }

    /// Put `inputs` back at the front of the queue, in order, as queued
    /// now, unless the agent stopped.
    pub(crate) fn requeue(&self, inputs: Vec<Pending>) {
        let mut queue = lock(&self.queue);
        if !queue.stopped {
            queue.push_front(inputs);
        }
    }
}

impl Inner {
    /// Queue `pending` for agent `id`, whose leader loop this node must
    /// run. Checked under the queue's lock, from any thread.
    pub(crate) fn push(&self, id: AgentId, pending: Pending) -> Result<(), CallError> {
        let run = self.present(id)?;
        let mut queue = lock(&run.agent.queue);
        if queue.stopped || run.shared.state().stopped {
            return Err(CallError::Stopped);
        }
        if !queue.leading {
            drop(queue);
            return Err(self.not_leader(&run.shared));
        }
        if !queue.push_back(pending, self.settings.queue_cap) {
            return Err(CallError::Busy);
        }
        drop(queue);
        let _ = run.agent.wake.try_send(());
        Ok(())
    }

    /// Tell agent `sender`'s leader loop here that `receiver` found it
    /// behind: false when this node does not lead it.
    pub(crate) fn note_behind(&self, sender: AgentId, receiver: AgentId) -> bool {
        let Some(run) = self.run(sender) else {
            return false;
        };
        let mut queue = lock(&run.agent.queue);
        if queue.stopped || !queue.leading {
            return false;
        }
        queue.behind.insert(receiver);
        drop(queue);
        let _ = run.agent.wake.try_send(());
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A queue tells the senders it dropped, each once and in turn, as many
    /// as its room fits a window of each's, a steady trickle of other
    /// messages queued or not.
    #[test]
    fn dropped_senders_are_told_as_the_room_fits_their_windows() {
        let mut queue = Queue::default();
        for sender in [3, 1, 3, 2, 4, 5] {
            queue.dropped.insert(AgentId(sender), 1024);
        }
        queue.from_agents = 1024;
        assert!(queue.untold(1024, 256).is_empty(), "a full queue");
        queue.from_agents = 700;
        assert_eq!(queue.untold(1024, 256), [AgentId(3)]);
        queue.from_agents = 10;
        assert_eq!(
            queue.untold(1024, 256),
            [AgentId(1), AgentId(2), AgentId(4)]
        );
        queue.dropped.insert(AgentId(3), 1024);
        queue.from_agents = 0;
        assert_eq!(queue.untold(1024, 256), [AgentId(5), AgentId(3)]);
        assert!(queue.dropped.is_empty());

        // A cap under a window: a window's room is the whole queue.
        queue.dropped.insert(AgentId(6), 2);
        queue.from_agents = 1;
        assert!(queue.untold(2, 256).is_empty());
        queue.from_agents = 0;
        assert_eq!(queue.untold(2, 256), [AgentId(6)]);
    }
}
