use super::Context;
use super::codec::{Encode, Decode};
use super::run::RunResult;

/// The core actor trait. Defines the full lifecycle of a VOS actor:
/// construction, startup, message dispatch, checkpointing, and error handling.
///
/// Serialization is handled by the `Encode + Decode` supertraits, which
/// are blanket-implemented for any type with rkyv derives. The `#[actor]`
/// macro adds these derives automatically.
///
/// ## Lifecycle hooks
///
/// - [`on_start`](Actor::on_start) — runs once on cold start, after
///   `create()`, before the message loop. Long-running actors place their
///   main loop here; `yield_now`/`sleep` work as usual.
/// - [`on_checkpoint`](Actor::on_checkpoint) — runs during the accumulate
///   phase to commit refine effects. Override to customize how state is
///   persisted (e.g. summarization on JAM, proof generation on vosx).
///
/// ## With macros
///
/// `#[actor]` generates rkyv derives + `impl Actor` with:
/// - `type Message` = the `{Name}Msg` enum (from `#[messages]`)
/// - `create` → calls `Self::new()`
/// - `dispatch` → forwards to `msg.deliver(self, ctx)`
/// - `on_start` → forwards to `start` handler if one is defined
///
/// ## Without macros
///
/// Add rkyv derives manually and implement `Actor`:
///
/// ```ignore
/// #[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
/// struct MyActor { count: i32 }
///
/// impl Actor for MyActor {
///     type Error = ();
///     type Message = MyActorMsg;
///     fn create() -> Self { MyActor { count: 0 } }
///     fn dispatch(&mut self, msg: Self::Message, ctx: &mut Context<Self>) -> RunResult<bool> {
///         vos::try_poll(async { msg.deliver(self, ctx).await })
///     }
/// }
/// ```
pub trait Actor: Sized + Encode + Decode {
    /// Error type for message handlers.
    type Error: core::fmt::Debug;

    /// The message enum dispatched to this actor.
    type Message: Decode + super::value::FromDynamic;

    /// Create a fresh actor instance with default state.
    /// Any initialization data should arrive as a regular message.
    fn create() -> Self;

    /// Called once on cold start, after `create()`, before the message
    /// dispatch loop. The default is a no-op.
    ///
    /// Use this for long-running actor loops (`yield_now` / `sleep` work
    /// normally) or one-shot initialization that needs the context.
    ///
    /// The `#[actor]` macro auto-generates this to forward to the `start`
    /// message handler if one is defined via `#[messages]`.
    async fn on_start(&mut self, _ctx: &mut Context<Self>) -> core::result::Result<(), Self::Error> {
        Ok(())
    }

    /// Dispatch a typed message to the appropriate handler.
    /// Returns `Complete(true)` to stop, `Complete(false)` to continue, `Yielded` to suspend.
    fn dispatch(&mut self, msg: Self::Message, ctx: &mut Context<Self>) -> RunResult<bool>;

    /// Called during the accumulate phase to commit refine effects.
    ///
    /// The default implementation replays all buffered effects (WRITE,
    /// TRANSFER, PROVIDE, NEW) via accumulate-phase hostcalls — this is
    /// the standard JAM-compatible path.
    ///
    /// Override to customize accumulate behavior:
    /// - **JAM**: summarize or aggregate data before on-chain storage
    /// - **vosx**: generate a ZK proof to send to external actors
    /// - **Custom**: any accumulate-phase commit logic
    #[cfg(feature = "service")]
    fn on_checkpoint(&self, payload: &crate::refine_payload::RefinePayload) {
        payload.replay_effects();
    }

    /// Called when a message handler returns an error. Return `true` to
    /// stop processing remaining messages in this batch, `false` to continue.
    #[allow(unused_variables)]
    fn on_error(&mut self, error: &Self::Error) -> bool {
        #[cfg(feature = "pvm")]
        {
            struct ErrorWriter;
            impl core::fmt::Write for ErrorWriter {
                fn write_str(&mut self, s: &str) -> core::fmt::Result {
                    crate::abi::pvm::hostcalls::debug_write(s.as_bytes());
                    Ok(())
                }
            }
            let _ = core::fmt::write(&mut ErrorWriter, format_args!("error: {:?}\n", error));
        }
        true
    }
}

/// Defines how an actor handles a specific message type.
///
/// `Output` is the raw return type of the handler:
/// - Infallible handlers: `Output = T` (e.g. `u64`)
/// - Fallible handlers: `Output = Result<T, E>`
///
/// The macro generates deliver arms that handle each case appropriately.
pub trait Message<M>: Actor {
    type Output;

    /// Process the message with exclusive mutable access to actor state.
    async fn handle(
        &mut self,
        msg: M,
        ctx: &mut Context<Self>,
    ) -> Self::Output;
}
