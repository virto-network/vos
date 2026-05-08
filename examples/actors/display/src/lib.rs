// Display service — virtual screen with a queryable framebuffer.
//
// Receives pixel data from animation actors via `render`, stores it
// in a framebuffer, and returns the number of ticks elapsed since the
// last frame so callers can compute time-based animations.
//
// The `read` handler returns the current framebuffer contents.

use vos::prelude::*;
const WIDTH: u32 = 16;
const HEIGHT: u32 = 8;

#[actor]
struct Display {
    /// Flat pixel buffer: one byte per cell (e.g. ASCII art or palette index).
    framebuffer: Vec<u8>,
    /// Tick counter at last render call.
    last_tick: u64,
    /// Monotonic tick counter — incremented each invocation.
    tick: u64,
}

#[messages]
impl Display {
    fn new() -> Self {
        Display {
            framebuffer: vec![b' '; (WIDTH * HEIGHT) as usize],
            last_tick: 0,
            tick: 0,
        }
    }

    /// Accept new pixel data and return ticks since last frame.
    /// The caller uses the delta to pace animations correctly.
    #[msg]
    async fn render(&mut self, pixels: Vec<u8>) -> u64 {
        self.tick += 1;
        let delta = self.tick - self.last_tick;
        self.last_tick = self.tick;

        // Copy pixels into framebuffer (clamp to buffer size)
        let len = pixels.len().min(self.framebuffer.len());
        self.framebuffer[..len].copy_from_slice(&pixels[..len]);

        log::info!("display: rendered frame ({}x{}, delta={})", WIDTH, HEIGHT, delta);
        delta
    }

    /// Return the current framebuffer contents.
    #[msg]
    async fn read(&self) -> Vec<u8> {
        self.framebuffer.clone()
    }
}

