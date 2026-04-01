use super::Context;

/// The core actor trait. An actor is an independent unit of computation
/// that processes messages sequentially with exclusive access to its state.
pub trait Actor: Sized {
    /// Error type for message handlers. Must implement `Debug` so the
    /// runtime can report failures.
    type Error: core::fmt::Debug;

    /// Called once when the actor is spawned, before it starts processing
    /// messages. Use for initialization that needs the actor's context.
    async fn on_start(&mut self, _ctx: &mut Context<Self>) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Called when the actor is about to stop. Use for cleanup.
    async fn on_stop(&mut self) {}

    /// Called when a message handler returns an error. Return `true` to
    /// stop processing remaining messages in this batch, `false` to continue.
    ///
    /// Default: prints the error and stops.
    #[allow(unused_variables)]
    fn on_error(&mut self, error: &Self::Error) -> bool {
        // Use Debug format since we can't assume Display
        #[cfg(feature = "guest")]
        {
            struct ErrorWriter;
            impl core::fmt::Write for ErrorWriter {
                fn write_str(&mut self, s: &str) -> core::fmt::Result {
                    vos_abi::guest::hostcalls::debug_write(s.as_bytes());
                    Ok(())
                }
            }
            let _ = core::fmt::write(&mut ErrorWriter, format_args!("error: {:?}\n", error));
        }
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
