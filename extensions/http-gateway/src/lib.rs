//! HttpGateway extension — exposes other actors over HTTP.
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
//! reply [`Value`] from `ctx.ask_raw` is rendered as JSON.
//!
//! ## HTTP stack
//!
//! - **HTTP/1.1 + HTTP/2 (cleartext)** via [`hyper`] —
//!   keep-alive, chunked transfer, h2c multiplexing.
//! - **HTTP/3** behind `feature = "http3"` via `h3` + `quinn` +
//!   `rustls`, with a self-signed cert auto-minted for `localhost`.
//!
//! Both protocols share the same `Job → ctx.ask_raw → Response` bridge.
//!
//! ## Concurrency
//!
//! Each protocol owns a tokio runtime in its own OS thread; per-
//! connection tasks parse, look up the route, and either short-circuit
//! into the admin handler or push a `Job` onto an mpsc the gateway
//! drains in its `run` loop. Wire-side I/O scales horizontally; the
//! drain loop calling `ctx.ask_raw` is serial, so dispatch throughput
//! is bounded by upstream latency.
//!
//! ## Lifecycle (Phase 4 — service-mode extension)
//!
//! The gateway is a **service-mode extension** — the host calls
//! `vos_extension_run` once and the gateway's `run(ctx)` body owns
//! the lifecycle until shutdown.
//!
//! - `run(ctx)` — install config, bind on the configured port, drain
//!   jobs until shutdown is signalled (via `ctx.is_shutdown()` or
//!   `POST /__admin/stop`).
//! - Admin endpoints work mid-flight (tokio runtime always alive):
//!   - `POST /__admin/stop` — set the stop flag.
//!   - `GET /__admin/status` — JSON snapshot.
//!
//! Both admin routes require `X-Admin-Token` matching the configured
//! token; with no token, the entire `/__admin/*` namespace returns 404.
//!
//! ## Operator config (manifest init args)
//!
//! Six knobs are passed via the manifest as a rkyv-encoded
//! `vos::value::Args`. Each one is empty by default; an empty value
//! means "use the in-code default":
//!
//! ```toml
//! [[extension]]
//! name = "gateway"
//! path = "target/release/libhttp_gateway.so"
//! init = {
//!     bind_addr   = "0.0.0.0",
//!     auth_token  = "...",
//!     admin_token = "...",
//!     tls_cert    = "/etc/tls/cert.pem",
//!     tls_key     = "/etc/tls/key.pem",
//!     port        = 8080,
//! }
//! ```
//!
//! | Field         | Default                                       |
//! |---------------|-----------------------------------------------|
//! | `bind_addr`   | `127.0.0.1` (loopback)                        |
//! | `auth_token`  | none — open dispatch + WARN at startup        |
//! | `admin_token` | none — `/__admin/*` returns 404               |
//! | `tls_cert`    | none — h3 self-signs `localhost` (dev only)   |
//! | `tls_key`     | none — paired with `tls_cert`                 |
//! | `port`        | `8080`                                        |
//!
//! Defaults make a bare deployment loopback-only with admin disabled
//! and dispatch open. A public deployment **must** set both tokens
//! and override `bind_addr`.

mod config;
mod hyper_io;
mod json;
mod limits;
mod routing;
mod runtime;
mod state;
mod types;

#[cfg(feature = "http3")]
mod http3;

use vos::extension::ServiceCtx;
use vos::log;

/// Default bind port when `init.port` is unset or zero.
const DEFAULT_PORT: u16 = 8080;

pub struct HttpGateway {
    cfg: config::GatewayConfig,
    port: u16,
}

impl HttpGateway {
    /// Constructor invoked by `vos_extension_create`. Init args are
    /// rkyv-encoded `vos::value::Args` with the six string knobs +
    /// `port`. Empty / missing fields fall back to in-code defaults.
    pub fn new(args: &[u8]) -> Self {
        use vos::Decode;
        let parsed: vos::value::Args = if args.is_empty() {
            vos::value::Args::default()
        } else {
            vos::value::Args::decode(args)
        };
        let cfg = config::GatewayConfig {
            bind_addr: parsed.get_str("bind_addr").unwrap_or_default(),
            auth_token: parsed.get_str("auth_token").unwrap_or_default(),
            admin_token: parsed.get_str("admin_token").unwrap_or_default(),
            tls_cert: parsed.get_str("tls_cert").unwrap_or_default(),
            tls_key: parsed.get_str("tls_key").unwrap_or_default(),
        };
        let port = parsed
            .get_u32("port")
            .map(|p| p as u16)
            .unwrap_or(DEFAULT_PORT);
        Self { cfg, port }
    }

    /// Service entry point. Installs the per-process config singleton,
    /// binds on the configured port, drains jobs until shutdown.
    /// Returns 0 on clean exit; non-zero on bind failure.
    pub fn run(&mut self, ctx: ServiceCtx) -> i32 {
        config::install(self.cfg.clone());
        let port = self.port;

        log::info!("http-gateway: starting on port {port}");

        // Hyper (h1+h2c) is the always-on serving path. HTTP/3 is
        // additive and lives behind a feature flag (Phase 4 keeps
        // it gated; an h3-aware service mode can spin up both
        // protocols from inside a single `run` body in a follow-up).
        let exit = runtime::serve_with(port, "tcp", hyper_io::spawn, &ctx);
        log::info!("http-gateway: stopped ({exit})");
        0
    }
}

// Phase 6 capability declarations — log-only today, but logged at
// load time so an operator review can spot the OS access this
// extension wants. The HTTP gateway needs to bind a TCP port,
// originate outbound TCP/TLS to peers (h3 + future webhooks), own
// a tokio runtime + spawn protocol threads.
vos::service_main!(
    HttpGateway,
    caps = [
        "net.tcp.bind",
        "net.tcp.connect",
        "tokio-runtime",
        "thread.spawn",
    ]
);
