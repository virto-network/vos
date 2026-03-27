use crate::Context;

/// The core actor trait. An actor is an independent unit of computation
/// that processes messages sequentially with exclusive access to its state.
pub trait Actor: Sized {
    /// Error type for lifecycle hooks and message handlers.
    type Error;

    /// Called once when the actor is spawned, before it starts processing
    /// messages. Use for initialization that needs the actor's context.
    async fn on_start(&mut self, _ctx: &mut Context<Self>) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Called when the actor is about to stop. Use for cleanup.
    async fn on_stop(&mut self) {}

    /// Called when a message handler returns an error. Return `true` to
    /// stop the actor, `false` to continue processing messages.
    fn on_error(&mut self, _error: &Self::Error) -> bool {
        true
    }
}

/// Defines how an actor handles a specific message type.
pub trait Message<M>: Actor {
    /// The response type sent back to the caller.
    type Reply;

    /// Process the message with exclusive mutable access to actor state.
    async fn handle(
        &mut self,
        msg: M,
        ctx: &mut Context<Self>,
    ) -> Result<Self::Reply, Self::Error>;
}
