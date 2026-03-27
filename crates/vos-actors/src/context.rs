use crate::Actor;

/// Execution context passed to message handlers.
///
/// Provides the actor with the ability to interact with the system:
/// sending messages, storing data, spawning services.
pub struct Context<A: Actor> {
    id: ServiceId,
    stop_requested: bool,
    _phantom: core::marker::PhantomData<A>,
}

/// Service identifier within the VOS runtime.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ServiceId(pub u32);

impl<A: Actor> Context<A> {
    pub fn new(id: ServiceId) -> Self {
        Self {
            id,
            stop_requested: false,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Get this actor's service ID.
    pub fn id(&self) -> ServiceId {
        self.id
    }

    /// Request the actor to stop after the current message.
    pub fn stop(&mut self) {
        self.stop_requested = true;
    }

    /// Check if a stop has been requested.
    pub fn stop_requested(&self) -> bool {
        self.stop_requested
    }
}
