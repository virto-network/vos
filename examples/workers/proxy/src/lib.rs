//! Proxy worker — forwards messages to a target worker via ctx.ask().
//!
//! Demonstrates cross-worker request-reply: receives a "proxy" message,
//! asks the target worker to echo it, and returns the proxied reply.

use vos::{actor, messages, value::Msg};

#[actor]
struct ProxyWorker {
    target: u32,
}

#[messages]
impl ProxyWorker {
    fn new(target: u32) -> Self {
        ProxyWorker { target }
    }

    /// Forward a text message to the target worker's echo handler.
    /// The target ServiceId comes from the constructor (init args).
    #[msg]
    async fn proxy(&mut self, text: String, ctx: &mut Context<Self>) -> String {
        let target = vos::actors::context::ServiceId(self.target);
        let msg = Msg::new("echo").with("text", text);
        match ctx.ask(target, &msg).await {
            Ok(value) => value.as_str().unwrap_or("(no reply)").into(),
            Err(e) => format!("error: {e}"),
        }
    }
}
