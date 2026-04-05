//! Animation actor — drives a spinner on a virtual display.
//!
//! Each iteration:
//! 1. Compute the current spinner frame from elapsed ticks
//! 2. Render pixels into a 16x8 framebuffer
//! 3. Ask the Display service to render, receiving delta ticks back
//! 4. Accumulate elapsed time and advance the animation phase
//! 5. Yield and loop
//!
//! Demonstrates cross-actor rendering: the animation logic lives here,
//! the framebuffer/timing lives in the Display service.

use vos::{actor, messages, value::Msg};

const DISPLAY_ID: u32 = 6;
const WIDTH: usize = 16;
const HEIGHT: usize = 8;

/// Spinner characters cycling through rotation.
const SPINNER: &[u8] = b"|/-\\";

#[actor]
struct Animation {
    frame: u32,
    phase: u32,
    elapsed: u64,
}

#[messages]
impl Animation {
    fn new() -> Self {
        Animation { frame: 0, phase: 0, elapsed: 0 }
    }

    /// Run the animation loop — renders spinner frames to the display.
    #[msg]
    async fn run(&mut self, ctx: &mut Context<Self>) {
        let display = vos::actors::context::ServiceId(DISPLAY_ID);

        loop {
            self.frame += 1;

            // Build the framebuffer: a spinning indicator + status text
            let mut pixels = vec![b' '; WIDTH * HEIGHT];

            // Row 0: spinner character
            let spinner_char = SPINNER[(self.phase as usize) % SPINNER.len()];
            pixels[0] = b'[';
            pixels[1] = spinner_char;
            pixels[2] = b']';

            // Row 1: frame counter
            let label = b" frame:";
            let row1 = WIDTH;
            pixels[row1..row1 + label.len()].copy_from_slice(label);

            // Write frame number as decimal digits
            let mut num = self.frame;
            let mut digits = [0u8; 10];
            let mut n = 0;
            loop {
                digits[n] = b'0' + (num % 10) as u8;
                num /= 10;
                n += 1;
                if num == 0 { break; }
            }
            let start = row1 + label.len();
            for i in 0..n {
                if start + i < pixels.len() {
                    pixels[start + i] = digits[n - 1 - i];
                }
            }

            // Row 3: a progress bar based on elapsed ticks
            let bar_row = WIDTH * 3;
            let bar_len = ((self.elapsed % 16) + 1) as usize;
            for i in 0..bar_len.min(WIDTH) {
                pixels[bar_row + i] = b'#';
            }

            // Send pixels to display, get delta ticks back
            let delta = ctx.ask(display, &Msg::new("render")
                .with("pixels", pixels))
                .await
                .as_u64().unwrap_or(1);

            self.elapsed += delta;
            // Advance spinner phase every 2 ticks
            self.phase += (delta as u32 + 1) / 2;

            println!("animation: frame {} phase {} elapsed {}", self.frame, self.phase, self.elapsed);

            ctx.yield_now().await;
        }
    }
}
