use crate::actor::{Actor, Message};
use crate::context::Context;

/// Type-erased message delivery. The aggregated message enum generated
/// by `#[messages]` implements this — each variant delegates to its
/// typed `Message::handle` impl.
pub trait Envelope<A: Actor> {
    /// Deliver this message to the actor, calling the appropriate async handler.
    async fn deliver(self, actor: &mut A, ctx: &mut Context<A>);
}

/// Concrete envelope for a specific message type.
pub struct TypedEnvelope<M> {
    pub msg: M,
}

impl<A, M> Envelope<A> for TypedEnvelope<M>
where
    A: Message<M>,
{
    async fn deliver(self, actor: &mut A, ctx: &mut Context<A>) {
        let _ = actor.handle(self.msg, ctx).await;
    }
}
