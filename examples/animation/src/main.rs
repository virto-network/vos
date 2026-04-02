//! Animation actor — simple frame-counter loop.
//!
//! Demonstrates a refine-only actor that advances a frame counter
//! each iteration. Each invocation: increment frame, print, yield.

use vos::{actor, messages};

#[actor]
struct Animation {
    frame: u32,
}

#[messages]
impl Animation {
    fn new() -> Self {
        Animation { frame: 0 }
    }

    #[msg]
    async fn run(&mut self, ctx: &mut Context<Self>) {
        loop {
            self.frame += 1;
            if !ctx.replaying() {
                println!("animation: frame {}", self.frame);
            }
            ctx.yield_now().await;
        }
    }
}
