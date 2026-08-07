//! EchoExtension — simple native extension that echoes messages back.
//!
//! Demonstrates an extension using the same `#[actor]`/`#[messages]` DSL
//! as PVM actors but compiled as a native `.so` plugin.

use vos::prelude::*;

#[actor]
struct EchoExtension {
    count: u32,
}

#[messages]
impl EchoExtension {
    fn new() -> Self {
        EchoExtension { count: 0 }
    }

    #[msg]
    async fn echo(&mut self, text: String, _ctx: &mut Context<Self>) -> String {
        self.count += 1;
        log::info!("echo-extension: echoing '{text}' (#{})", self.count);
        format!("echo #{}: {text}", self.count)
    }

    #[msg]
    async fn count(&self, _ctx: &mut Context<Self>) -> u32 {
        self.count
    }
}
