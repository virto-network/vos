//! Actor registry — manages the lifecycle of child actor programs.

use pvx_abi::actor::{ActorId, Status};
use pvx_actors::Mailbox;

/// State of a registered actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorState {
    /// Actor has been registered but `init()` hasn't been called yet.
    Created,
    /// Actor is running and can receive messages.
    Running,
    /// Actor's handler returned `Pending` — needs to be polled.
    Suspended,
    /// Actor has stopped (cleanly or due to error).
    Stopped,
}

/// A registered actor entry. Holds metadata and the message queue.
///
/// The actual PVM program state lives in the PVM runtime — we only
/// track the actor's lifecycle and pending messages here.
pub struct ActorEntry<Msg, const MAILBOX_CAP: usize> {
    pub id: ActorId,
    pub state: ActorState,
    pub mailbox: Mailbox<Msg, MAILBOX_CAP>,
}

/// Registry of actor programs managed by the executor.
///
/// Fixed capacity, no allocator. `N` = max actors, `MAILBOX_CAP` = message
/// queue depth per actor.
pub struct ActorRegistry<Msg, const N: usize, const MAILBOX_CAP: usize> {
    actors: [Option<ActorEntry<Msg, MAILBOX_CAP>>; N],
    count: u32,
}

impl<Msg, const N: usize, const MAILBOX_CAP: usize> Default
    for ActorRegistry<Msg, N, MAILBOX_CAP>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<Msg, const N: usize, const MAILBOX_CAP: usize> ActorRegistry<Msg, N, MAILBOX_CAP> {
    const NONE: Option<ActorEntry<Msg, MAILBOX_CAP>> = None;

    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            actors: [Self::NONE; N],
            count: 0,
        }
    }

    /// Register a new actor. Returns its ID, or `None` if full.
    pub fn register(&mut self) -> Option<ActorId> {
        if self.count as usize >= N {
            return None;
        }
        // ID 0 is reserved for the executor itself
        self.count += 1;
        let id = ActorId(self.count);
        let idx = (id.0 - 1) as usize;
        self.actors[idx] = Some(ActorEntry {
            id,
            state: ActorState::Created,
            mailbox: Mailbox::new(),
        });
        Some(id)
    }

    /// Get an actor entry by ID.
    pub fn get(&self, id: ActorId) -> Option<&ActorEntry<Msg, MAILBOX_CAP>> {
        let idx = id.0.checked_sub(1)? as usize;
        self.actors.get(idx)?.as_ref()
    }

    /// Get a mutable actor entry by ID.
    pub fn get_mut(&mut self, id: ActorId) -> Option<&mut ActorEntry<Msg, MAILBOX_CAP>> {
        let idx = id.0.checked_sub(1)? as usize;
        self.actors.get_mut(idx)?.as_mut()
    }

    /// Update an actor's state based on a status code from the child.
    pub fn update_state(&mut self, id: ActorId, status: Status) {
        if let Some(entry) = self.get_mut(id) {
            entry.state = match status {
                Status::Ready => ActorState::Running,
                Status::Pending => ActorState::Suspended,
                Status::Done => ActorState::Stopped,
                Status::Error => ActorState::Stopped,
            };
        }
    }

    /// Send a message to an actor's mailbox. Returns `Err(msg)` if
    /// the target doesn't exist or its mailbox is full.
    pub fn send(&mut self, target: ActorId, msg: Msg) -> Result<(), Msg> {
        let entry = match self.get_mut(target) {
            Some(e) if e.state != ActorState::Stopped => e,
            _ => return Err(msg),
        };
        entry.mailbox.push(msg)
    }

    /// Iterate over actors that need work (have pending messages or
    /// are suspended). Calls `f` for each, which should return the
    /// resulting status.
    pub fn tick(&mut self, mut f: impl FnMut(ActorId, ActorState, Option<&Msg>) -> Status) {
        for slot in self.actors.iter_mut() {
            let Some(entry) = slot else { continue };
            match entry.state {
                ActorState::Stopped | ActorState::Created => continue,
                ActorState::Suspended => {
                    // Resume suspended actor (no new message)
                    let status = f(entry.id, entry.state, None);
                    entry.state = match status {
                        Status::Ready => ActorState::Running,
                        Status::Pending => ActorState::Suspended,
                        Status::Done | Status::Error => ActorState::Stopped,
                    };
                }
                ActorState::Running => {
                    // Deliver next message if available
                    if let Some(msg) = entry.mailbox.pop() {
                        let status = f(entry.id, entry.state, Some(&msg));
                        entry.state = match status {
                            Status::Ready => ActorState::Running,
                            Status::Pending => ActorState::Suspended,
                            Status::Done | Status::Error => ActorState::Stopped,
                        };
                    }
                }
            }
        }
    }

    /// Number of alive (non-stopped) actors.
    pub fn alive_count(&self) -> usize {
        self.actors
            .iter()
            .filter(|s| {
                s.as_ref()
                    .is_some_and(|e| e.state != ActorState::Stopped)
            })
            .count()
    }
}
