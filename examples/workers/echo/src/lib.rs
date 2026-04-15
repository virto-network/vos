//! EchoWorker worker — simple native worker that echoes messages back.
//!
//! Demonstrates a worker using the same `#[actor]`/`#[messages]` DSL
//! as PVM actors but compiled as a native `.so` plugin.

use vos::{actor, messages};

#[actor]
struct EchoWorker {
    count: u32,
}

#[messages]
impl EchoWorker {
    fn new() -> Self {
        EchoWorker { count: 0 }
    }

    #[msg]
    async fn echo(&mut self, text: String, _ctx: &mut Context<Self>) -> String {
        self.count += 1;
        format!("echo #{}: {text}", self.count)
    }

    #[msg]
    async fn count(&self, _ctx: &mut Context<Self>) -> u32 {
        self.count
    }
}
