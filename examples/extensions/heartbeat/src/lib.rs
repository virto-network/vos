//! Heartbeat — an **actor-mode** extension that pings a target actor on a
//! Host-driven `tick()` timer.
//!
//! Validates the actor-mode periodic primitive: the host dispatches a
//! synthetic `tick` message to this actor's `tick` handler about every
//! `tick_ms` (set on the [`ExtensionConfig`](vos::node::ExtensionConfig) /
//! manifest), the handler originates exactly one `ctx.ask_dispatch` per
//! tick, and there is **no `run()` loop** — the host's generic `__stop`
//! (`vosx <agent> stop`) quiesces the agent. The host owns the cadence, the
//! actor owns one tick's work.

use vos::actors::context::ServiceId;
use vos::prelude::*;
use vos::value::Msg;

/// Hard-coded peer the heartbeat pings. Real services would receive this via
/// init args; heartbeat keeps it simple — `ServiceId(1)` matches the
/// auto-assigned id of the first non-registry agent on a fresh `VosNode`, so
/// the test registers the echo target before the heartbeat to land at id 1.
/// Override at load time via `HEARTBEAT_TARGET=<u32>`.
fn heartbeat_target() -> u32 {
    std::env::var("HEARTBEAT_TARGET")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
}

#[actor(caps = ["net.libp2p.dial"])]
pub struct Heartbeat {
    pings_sent: u32,
}

#[messages]
impl Heartbeat {
    pub fn new() -> Self {
        Self { pings_sent: 0 }
    }

    /// One heartbeat tick: ping the target actor once. The host calls this
    /// roughly every `tick_ms` (no inbound caller — the relayed authority is
    /// `Unauthenticated`). A reply (`Some`) counts as a successful ping;
    /// `None` means a transport error / the target went away (e.g. during
    /// shutdown) and is just logged — the next tick retries.
    #[msg]
    async fn tick(&mut self, ctx: &mut Context<Self>) {
        let target = heartbeat_target();
        // Encode `echo` as a TAG_DYNAMIC Msg payload — matches the shape
        // echo-extension accepts so the host's tests can use it as the ping
        // target.
        let echo_msg = Msg::new("echo").with("text", "heartbeat-ping");
        let mut payload = vec![vos::value::TAG_DYNAMIC];
        payload.extend_from_slice(&echo_msg.encode());

        match ctx.ask_dispatch(ServiceId(target), &payload).await {
            Some(_reply) => {
                self.pings_sent += 1;
                if self.pings_sent.is_multiple_of(10) {
                    log::info!("heartbeat: {} pings sent", self.pings_sent);
                }
            }
            None => {
                log::warn!("heartbeat: ask returned None — transport error / target gone?");
            }
        }
    }
}
