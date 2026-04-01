//! Animation actor — demonstrates cross-actor ask/tell.
//!
//! The animation actor maintains a frame counter. Each tick, it uses `ask()`
//! to query a display service for the render duration, advances the frame,
//! and sleeps for the returned duration before the next frame.
//!
//! This is a design example — the actual `ask` flow requires invoke() support
//! in the runtime. For now it demonstrates the API shape.

use vos::{actor, messages};
use vos::actors::context::ServiceId;

#[actor]
struct Animation {
    frame: u32,
    display_id: u32,
}

#[messages]
impl Animation {
    fn new(display_id: Vec<u8>) -> Self {
        let id = if display_id.is_empty() {
            2 // default display service ID
        } else {
            display_id[0] as u32
        };
        Animation {
            frame: 0,
            display_id: id,
        }
    }

    /// Advance one frame: ask the display to render, then sleep for the duration.
    #[msg]
    async fn tick(&mut self, ctx: &mut Context<Self>) {
        // Ask display service to render this frame. Returns duration to wait.
        let request = self.frame.to_le_bytes();
        let result = ctx.ask(ServiceId(self.display_id), &request);

        let duration = match result {
            Some(bytes) if bytes.len() >= 4 => {
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            }
            Some(_) => 1, // default 1 tick
            None => {
                // ask() suspended — will resume on next invocation with cached result
                return;
            }
        };

        self.frame += 1;
        println!("animation: frame {} rendered, sleeping {} tick(s)", self.frame, duration);

        if duration > 0 {
            ctx.sleep(duration);
        } else {
            ctx.yield_now();
        }
    }

    /// Query the current frame number.
    #[msg]
    async fn current_frame(&self, _ctx: &mut Context<Self>) -> u32 {
        self.frame
    }
}
