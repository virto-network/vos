//! HttpGateway worker — exposes other actors over HTTP.
//!
//! ## URL convention
//!
//! ```text
//! GET  /<agent-name>/<method>?key1=val1&key2=val2     → query
//! POST /<agent-name>/<method>   body: {"k1":"v1",...} → command
//! ```
//!
//! The `<agent-name>` segment resolves through the registry actor at
//! [`vos::actors::context::ServiceId::REGISTRY`]. The `<method>`
//! segment becomes the dynamic [`Msg::name`]; query params (GET) or
//! top-level JSON keys (POST/PUT/PATCH) become the [`Msg::args`]. The
//! reply [`Value`] from `ctx.ask` is rendered as JSON.
//!
//! ## HTTP stack
//!
//! - **HTTP/1.1 + HTTP/2 (cleartext)** via [`hyper`] —
//!   keep-alive, chunked transfer, h2c multiplexing.
//! - **HTTP/3** behind `feature = "http3"` via `h3` + `quinn` +
//!   `rustls`, with a self-signed cert auto-minted for `localhost`.
//!
//! Both protocols share the same `Job → ctx.ask → Response` bridge.
//!
//! ## Concurrency
//!
//! Each protocol owns a tokio runtime in its own OS thread; per-
//! connection tasks parse, look up the route, and either short-circuit
//! into the admin handler or push a `Job` onto an mpsc the actor
//! drains. Wire-side I/O scales horizontally; the actor's `ctx.ask`
//! remains serial, so dispatch throughput is bounded by upstream
//! latency.
//!
//! ## Lifecycle
//!
//! - [`HttpGateway::serve`] — bind h1+h2c on `port`; blocks until stop.
//! - [`HttpGateway::serve_h3`] — bind h3 on `port` (UDP); blocks until stop.
//! - [`HttpGateway::stop`] — flip the stop flag.
//! - [`HttpGateway::status`] — JSON snapshot.
//! - [`HttpGateway::port`] / [`HttpGateway::requests`] /
//!   [`HttpGateway::running`] — primitive accessors.
//!
//! `serve*` blocks the worker's dispatch loop while running, so other
//! actor messages can't be delivered to the gateway in the same
//! window. To preempt a running gateway from outside the host process:
//!
//! - `POST /__admin/stop` — set the stop flag (handled in the tokio
//!   task, so it works even while `serve*` is the only handler in
//!   flight).
//! - `GET /__admin/status` — JSON snapshot.
//!
//! When vos exposes worker self-pumping, `serve*` can become a
//! non-blocking bootstrap and the actor messages will work mid-flight.

use vos::prelude::*;

mod hyper_io;
mod json;
mod routing;
mod runtime;
mod state;
mod types;

#[cfg(feature = "http3")]
mod http3;

#[actor]
pub struct HttpGateway;

#[messages]
impl HttpGateway {
    fn new() -> Self {
        HttpGateway
    }

    /// Bind h1+h2c on `port` and serve until stop. Returns the loop's
    /// exit reason (`"stopped"`, an mpsc-disconnect message, or a
    /// bind/runtime error). A second call while a gateway is already
    /// running short-circuits with an "already listening" string —
    /// caller should `stop()` first.
    #[msg]
    async fn serve(&mut self, port: u32, ctx: &mut Context<Self>) -> String {
        runtime::serve_with(port as u16, "tcp", hyper_io::spawn, ctx).await
    }

    /// Bind h3 (QUIC) on UDP `port` and serve until stop. Available
    /// only when this crate is built with `--features http3`; without
    /// the feature it returns a "not enabled" string so the message
    /// surface stays stable across feature combinations.
    #[msg]
    async fn serve_h3(&mut self, port: u32, ctx: &mut Context<Self>) -> String {
        serve_h3_dispatch(port as u16, ctx).await
    }

    /// Flip the stop flag; the running `serve*` exits its loop on the
    /// next iteration. Returns whether the gateway was running at the
    /// moment of the call.
    ///
    /// **Note:** can only be processed when no `serve*` is currently
    /// in flight on this worker. Use `POST /__admin/stop` to preempt
    /// from outside the host process.
    #[msg]
    async fn stop(&self, _ctx: &mut Context<Self>) -> bool {
        let i = state::inner();
        let was_running = i.running();
        i.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        was_running
    }

    /// Bound port, or 0 when the gateway isn't running.
    #[msg]
    async fn port(&self, _ctx: &mut Context<Self>) -> u32 {
        state::inner().bound_port.load(std::sync::atomic::Ordering::Relaxed) as u32
    }

    /// Total HTTP requests served since process boot.
    #[msg]
    async fn requests(&self, _ctx: &mut Context<Self>) -> u64 {
        state::inner().requests.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// `true` when a `serve*` is in flight and hasn't been asked to stop.
    #[msg]
    async fn running(&self, _ctx: &mut Context<Self>) -> bool {
        state::inner().running()
    }

    /// Compact JSON status string: `{"port":N,"running":bool,...}`.
    /// Same shape as `GET /__admin/status`.
    #[msg]
    async fn status(&self, _ctx: &mut Context<Self>) -> String {
        state::status_json(state::inner())
    }
}

// ── serve_h3 dispatch ─────────────────────────────────────────────────
//
// `#[messages]` doesn't propagate `#[cfg]` from individual handlers to
// its dispatch glue, so the `serve_h3` body must always exist. Forward
// to a free function whose two cfg arms either run the QUIC server or
// return a "feature not enabled" string.

#[cfg(feature = "http3")]
async fn serve_h3_dispatch(port: u16, ctx: &mut vos::Context<HttpGateway>) -> String {
    http3::serve_h3_impl(port, ctx).await
}

#[cfg(not(feature = "http3"))]
async fn serve_h3_dispatch(_port: u16, _ctx: &mut vos::Context<HttpGateway>) -> String {
    "http3 feature not enabled — rebuild with --features http3".into()
}
