use crate::Actor;

/// Execution context passed to message handlers.
///
/// Provides the actor with the ability to interact with the system:
/// sending messages to other actors, stopping itself, etc.
pub struct Context<A: Actor> {
    /// Unique identifier for this actor within the executor.
    id: ActorId,
    /// Whether a stop has been requested.
    stop_requested: bool,
    _phantom: core::marker::PhantomData<A>,
}

/// Opaque actor identifier. Indexes into the executor's actor table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ActorId(pub u16);

impl<A: Actor> Context<A> {
    pub fn new(id: ActorId) -> Self {
        Self {
            id,
            stop_requested: false,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Get this actor's ID.
    pub fn id(&self) -> ActorId {
        self.id
    }

    /// Request the actor to stop after the current message.
    pub fn stop(&mut self) {
        self.stop_requested = true;
    }

    /// Check if a stop has been requested.
    pub(crate) fn stop_requested(&self) -> bool {
        self.stop_requested
    }
}
