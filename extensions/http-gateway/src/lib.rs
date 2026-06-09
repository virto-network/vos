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
//! [`vos::actors::context::ServiceId::REGISTRY`]. The `<method>` segment
//! becomes the dynamic [`vos::value::Msg::name`]; query params (GET) or
//! top-level JSON keys (POST/PUT/PATCH) become the args. The reply is
//! rendered as JSON.
//!
//! ## Transport mode
//!
//! The gateway is a **transport-mode** extension. The **host** owns the
//! TCP listener + accept loop (configured via
//! `ExtensionConfig::serves(addr, tls)` from the manifest's
//! `bind_addr`/`port`/`tls_*` init args) and terminates TLS, then drives
//! one [`HttpGateway::handle_connection`] task per accepted connection on
//! its single cooperative executor. The receiver is `&self` (shared), so
//! many connections interleave while parked on I/O — all per-instance
//! state lives behind [`state::Inner`]'s atomics + `Mutex`.
//!
//! `handle_connection` reads the plaintext byte stream (`ctx.read`),
//! feeds an HTTP/1.1 parser ([`http1`], `httparse` head + our framing),
//! routes each request
//! through [`routing::dispatch`] (which `ctx.ask`s the registry + target
//! agent), serializes the reply, and writes it back (`ctx.write`),
//! keeping the connection alive until EOF or `Connection: close`.
//!
//! The host owns the TCP listener + accept loop and terminates TLS; the
//! gateway frames HTTP/1.1 off the plaintext byte stream. HTTP/2 and
//! HTTP/3 are not supported.
//!
//! ## Lifecycle (`stop` / `describe`)
//!
//! A transport extension has no inbound `#[msg]` handlers, so the gateway
//! does not answer its own `stop` / `status` invokes. Instead the host
//! provides generic per-agent primitives: `vosx gateway stop` and
//! `vosx gateway describe` are intercepted node-side as `__stop` /
//! `__describe` (see `vos::node`). Rich live status stays in-gateway as
//! the public `GET /__status` endpoint (no invoke round trip), alongside
//! the Prometheus `GET /__metrics`.
//!
//! ## Operator config (manifest init args)
//!
//! ```toml
//! [[extension]]
//! name = "gateway"
//! path = "target/release/libhttp_gateway.so"
//! init = { bind_addr = "0.0.0.0", port = 8080, auth_token = "…" }
//! ```
//!
//! | Field          | Default                                        |
//! |----------------|------------------------------------------------|
//! | `bind_addr`    | `127.0.0.1` (loopback)                         |
//! | `port`         | `8080`                                         |
//! | `auth_token`   | none — open dispatch + WARN at startup         |
//! | `tls_cert`     | none — host terminates TLS when paired with…   |
//! | `tls_key`      | none — …`tls_cert`                             |
//! | `agent_tokens` | empty — `agent:tok,agent:tok` per-agent override|
//!
//! Each field is empty-means-default. `bind_addr`/`port`/`tls_*` are read
//! host-side (in `vosx` reconcile) to configure `serves(..)`; the gateway
//! itself uses `auth_token`/`agent_tokens` (+ `port` for `/__status`).
//! A public deployment **must** set `auth_token` and override `bind_addr`.

mod config;
mod http1;
mod json;
mod limits;
mod routing;
mod state;
mod types;

use std::cell::OnceCell;

use vos::prelude::*;

/// Default bind port when `init.port` is unset or zero.
const DEFAULT_PORT: u16 = 8080;

#[actor(kind = "transport", caps = ["net.tcp.bind"])]
struct HttpGateway {
    /// Operator config, parsed from the init args. Plain rkyv-serializable
    /// fields — these are the persistable part of the actor's state.
    cfg: config::GatewayConfig,
    /// Host-bound listen port (the host owns the listener; we keep it for
    /// `/__status` + `/__metrics` reporting).
    port: u16,
    /// Live runtime state (counters + schema cache + parsed tokens), shared
    /// by every connection task via `&self` (single-threaded — `Cell` /
    /// `RefCell` interior mutability, no `Arc`/`Mutex`). **Skipped by rkyv**
    /// — `Cell`/`RefCell` aren't serializable, and a transport extension
    /// never warm-restarts, so the
    /// `Actor: Encode + Decode` bound only needs to be *satisfied*, not
    /// meaningfully exercised. Built eagerly in `new()`; `handle_connection`
    /// reaches it via `get_or_init` (the single-threaded executor makes the
    /// `OnceCell` access race-free — `Inner::new` never `.await`s, so two
    /// connection tasks can't init concurrently).
    #[rkyv(with = vos::rkyv::with::Skip)]
    inner: OnceCell<state::Inner>,
}

#[messages]
impl HttpGateway {
    /// Constructor invoked by `vos_extension_create` with the raw
    /// rkyv-encoded `vos::value::Args` init blob. Every knob is optional
    /// (empty ⇒ in-code default), so we parse the blob ourselves rather
    /// than via named constructor params (which would `expect` each to be
    /// present). A malformed `agent_tokens` lands in
    /// [`state::Inner::config_error`] and makes the gateway answer `503`
    /// to every request rather than boot with weakened auth.
    fn new(args: &[u8]) -> Self {
        use vos::Decode;
        let parsed: vos::value::Args = if args.is_empty() {
            vos::value::Args::default()
        } else {
            vos::value::Args::decode(args)
        };
        let cfg = config::GatewayConfig {
            bind_addr: parsed.get_str("bind_addr").unwrap_or_default(),
            auth_token: parsed.get_str("auth_token").unwrap_or_default(),
            tls_cert: parsed.get_str("tls_cert").unwrap_or_default(),
            tls_key: parsed.get_str("tls_key").unwrap_or_default(),
            agent_tokens: parsed.get_str("agent_tokens").unwrap_or_default(),
        };
        let port = parsed
            .get_u32("port")
            .map(|p| p as u16)
            .unwrap_or(DEFAULT_PORT);
        let inner = OnceCell::new();
        // Eager build so metrics/status are live immediately and a config
        // error is logged at boot (not deferred to the first request).
        let _ = inner.set(state::Inner::new(cfg.clone(), port));
        HttpGateway { cfg, port, inner }
    }

    /// Serve one HTTP/1.1 connection to completion (`&self`, shared — the
    /// host runs one of these per connection, concurrently). Loops
    /// parse → dispatch → write, keeping the connection alive across
    /// requests until the peer closes it or asks for `Connection: close`,
    /// then closes.
    async fn handle_connection(&self, ctx: &mut Context<Self>, conn_id: u64) {
        let inner = self
            .inner
            .get_or_init(|| state::Inner::new(self.cfg.clone(), self.port));
        serve_connection(inner, ctx, conn_id).await;
        ctx.close(conn_id).await;
    }
}

/// The per-connection serve loop. Factored out of `handle_connection` so
/// it can use crate-local helpers; takes `&Inner` (shared, immutable) +
/// the mutable connection `Context`.
async fn serve_connection(inner: &state::Inner, ctx: &mut Context<HttpGateway>, conn_id: u64) {
    let policy = routing::Policy {
        auth_token: inner.cfg.auth_token(),
        agent_tokens: (!inner.agent_tokens.is_empty()).then_some(&inner.agent_tokens),
    };

    // Buffer accumulates bytes across `ctx.read`s; leftover after one
    // request (a pipelined next request) carries into the next iteration.
    let mut buf: Vec<u8> = Vec::new();

    loop {
        // 1. Parse a request head, reading more as needed.
        let head = loop {
            match http1::parse_head(&buf) {
                http1::HeadOutcome::Complete(h) => break h,
                http1::HeadOutcome::Error(resp) => {
                    // Protocol error: answer it, then close.
                    inner.metrics.record_response(resp.status().as_u16());
                    let bytes = http1::serialize_response(&resp, false);
                    let _ = write_all(ctx, conn_id, &bytes).await;
                    return;
                }
                http1::HeadOutcome::NeedMore => match ctx.read(conn_id, limits::READ_CHUNK).await {
                    Some(data) if !data.is_empty() => buf.extend_from_slice(&data),
                    // `Some(empty)` is a clean EOF (peer closed at a request
                    // boundary, or mid-head — either way we're done); `None`
                    // is a read error. Both end the connection.
                    _ => return,
                },
            }
        };

        // 2. Read the full Content-Length body into the buffer.
        let total = head.head_len + head.content_length;
        while buf.len() < total {
            match ctx.read(conn_id, limits::READ_CHUNK).await {
                Some(data) if !data.is_empty() => buf.extend_from_slice(&data),
                // EOF / error before the declared body arrived → truncated
                // request; drop the connection.
                _ => return,
            }
        }

        // 3. Carve out the Request; retain any pipelined leftover bytes.
        //    `parse_head` already filled the head into an `http::Request<()>`;
        //    attach the body we just read.
        let keep_alive = head.keep_alive;
        let body = buf[head.head_len..total].to_vec();
        let req: types::Request = head.request.map(|()| body);
        buf.drain(..total);

        // 4. Route, record, write.
        let resp = routing::dispatch(&req, inner, ctx, policy).await;
        inner.metrics.record_response(resp.status().as_u16());
        let bytes = http1::serialize_response(&resp, keep_alive);
        if write_all(ctx, conn_id, &bytes).await.is_none() {
            return; // write error → give up on this connection
        }
        if !keep_alive {
            return;
        }
    }
}

/// Write all of `bytes` to `conn_id`, looping over partial writes.
/// `None` on a write error (or a zero-length write, which the host only
/// returns on a broken connection).
async fn write_all(ctx: &mut Context<HttpGateway>, conn_id: u64, mut bytes: &[u8]) -> Option<()> {
    while !bytes.is_empty() {
        let n = ctx.write(conn_id, bytes).await?;
        if n == 0 {
            return None;
        }
        bytes = &bytes[n..];
    }
    Some(())
}
