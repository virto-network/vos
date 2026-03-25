use crate::Context;

/// The core actor trait. An actor is an independent unit of computation
/// that processes messages sequentially with exclusive access to its state.
///
/// In PVM, each actor maps to one program. The program is a top-level
/// future that the host polls. Message handlers are async — `.await`
/// points yield control back to the host so other programs can run.
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
    ///
    /// Default: stop on error.
    fn on_error(&mut self, _error: &Self::Error) -> bool {
        true
    }
}

/// Defines how an actor handles a specific message type.
///
/// Each message type gets its own impl, enabling compile-time dispatch.
/// The handler is async — `.await` points yield to the PVM host so
/// other programs/actors can make progress cooperatively.
///
/// # Example
///
/// ```ignore
/// struct Counter { count: i32 }
///
/// struct Increment(i32);
///
/// impl Message<Increment> for Counter {
///     type Reply = i32;
///     async fn handle(&mut self, msg: Increment, _ctx: &mut Context<Self>) -> Result<Self::Reply, Self::Error> {
///         self.count += msg.0;
///         Ok(self.count)
///     }
/// }
/// ```
pub trait Message<M>: Actor {
    /// The response type sent back to the caller.
    type Reply;

    /// Process the message with exclusive mutable access to actor state.
    /// Async — `.await` yields to the host for cooperative scheduling.
    async fn handle(
        &mut self,
        msg: M,
        ctx: &mut Context<Self>,
    ) -> Result<Self::Reply, Self::Error>;
}
