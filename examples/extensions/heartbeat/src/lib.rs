//! Heartbeat — a service-mode extension that pings a target actor at
//! a fixed interval. Validates the Phase 3 service ABI end-to-end:
//! the host hands over a `ServiceCtx`, the extension originates
//! `ctx.ask_raw` calls without an incoming dispatch, and the loop
//! exits cleanly when shutdown is signalled.

use std::thread;
use std::time::Duration;
use vos::Encode;
use vos::extension::ServiceCtx;
use vos::log;
use vos::value::Msg;

/// Hard-coded peer the heartbeat pings. Real services would receive
/// this via init args (Phase 4 on the gateway). Heartbeat keeps it
/// simple — `ServiceId(1)` matches the auto-assigned id of the
/// first non-registry agent on a fresh `VosNode`, so the test
/// registers the echo target before the heartbeat to land at id 1.
/// Override at load time via `HEARTBEAT_TARGET=<u32>`.
fn heartbeat_target() -> u32 {
    std::env::var("HEARTBEAT_TARGET")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
}

/// Interval between pings.
const PING_EVERY: Duration = Duration::from_millis(100);

#[derive(Default)]
pub struct Heartbeat {
    pings_sent: u32,
}

impl Heartbeat {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn run(&mut self, ctx: ServiceCtx) -> i32 {
        let target = heartbeat_target();
        log::info!("heartbeat: starting; target=ServiceId({target})");

        // Encode `echo` as a TAG_DYNAMIC Msg payload — matches the
        // shape echo-extension accepts so the host's tests can use
        // it as the ping target.
        let echo_msg = Msg::new("echo").with("text", "heartbeat-ping");
        let mut payload = vec![vos::value::TAG_DYNAMIC];
        payload.extend_from_slice(&echo_msg.encode());

        loop {
            if ctx.is_shutdown() {
                break;
            }

            // Originate the ping. ask_raw blocks the calling thread
            // until the reply arrives or the host signals shutdown.
            // For heartbeat we don't care about the reply contents —
            // just confirm we got one (None = transport error / shutdown).
            match ctx.ask_raw(target, &payload) {
                Some(_reply) => {
                    self.pings_sent += 1;
                    if self.pings_sent.is_multiple_of(10) {
                        log::info!("heartbeat: {} pings sent", self.pings_sent);
                    }
                }
                None => {
                    if ctx.is_shutdown() {
                        break;
                    }
                    log::warn!("heartbeat: ask returned None — transport error?");
                    // Brief backoff so we don't spin on a broken target.
                    thread::sleep(Duration::from_millis(50));
                }
            }

            // Sleep between pings, broken into small chunks so the
            // shutdown latency stays bounded even with PING_EVERY = 1h.
            let mut left = PING_EVERY;
            while left > Duration::ZERO {
                if ctx.is_shutdown() {
                    break;
                }
                let step = left.min(Duration::from_millis(20));
                thread::sleep(step);
                left = left.saturating_sub(step);
            }
        }

        log::info!("heartbeat: shutdown signalled; sent {}", self.pings_sent);
        0
    }
}

vos::service_main!(Heartbeat);
