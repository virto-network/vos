//! HttpGateway worker — exposes other actors over hyper-backed HTTP.
//!
//! ## URL convention
//!
//! ```text
//! GET  /<agent-name>/<method>?key1=val1&key2=val2     → query (no side-effects)
//! POST /<agent-name>/<method>   body: {"k1":"v1",...} → command
//! ```
//!
//! "agent-name" is resolved via the registry actor at
//! `ServiceId::REGISTRY`. The path's `<method>` becomes the dynamic
//! `Msg::name`; query params (GET) or top-level JSON keys (POST)
//! become the `Msg::args`.
//!
//! The reply `Value` from `ctx.ask` is rendered as JSON in the body.
//!
//! ## HTTP stack
//!
//! Hyper handles HTTP/1.1 + HTTP/2 (cleartext, prior-knowledge): keep-alive,
//! chunked transfer, h2 multiplexing all come for free. HTTP/3 will arrive
//! as a `feature = "http3"` add-on (h3 + quinn + rustls); plain-TCP
//! HTTP/2 remains here.
//!
//! ## Concurrency
//!
//! Connection-side I/O runs on a tokio runtime owned by the worker.
//! Each connection gets a hyper `service_fn` that bridges into a tokio
//! `mpsc` of `Job`s; the actor handler drains that queue calling
//! `ctx.ask` per request. h2 lets a single connection multiplex many
//! requests, all of which funnel through the same mpsc — dispatch is
//! still serial through the worker's single-threaded `ctx`, but the
//! wire side scales.
//!
//! ## Lifecycle
//!
//! - `serve(port)` — bind + serve forever; returns when stop is signaled.
//! - `stop()` — set the stop flag; the running `serve` exits its loop.
//! - `status()` — JSON-friendly snapshot of port/uptime/requests/running.
//! - `port()`, `requests()`, `running()` — primitive accessors.
//!
//! `serve()` blocks the worker's dispatch loop while running, so other
//! actor messages can't be delivered to the gateway in the same window.
//! That's a vos-side limit (workers don't yet expose self-pumping). Two
//! escape hatches exist today:
//!
//! - `POST /__admin/stop` — handled directly by the tokio runtime, sets
//!   the same stop flag. This is the only path that can preempt a
//!   running `serve()` from outside the host process.
//! - `GET /__admin/status` — same idea, returns the JSON snapshot.
//!
//! Once vos lets a worker post messages back to its own inbox, `serve`
//! will become a non-blocking bootstrap and the actor messages will
//! work mid-flight too.

use std::convert::Infallible;
use std::sync::OnceLock;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use vos::actors::context::ServiceId;
use vos::actors::value::{Msg, Value};
use vos::prelude::*;

#[cfg(feature = "http3")]
mod http3;

type HyperResponse = hyper::Response<Full<Bytes>>;

// `#[messages]` emits a `type Result<T> = core::result::Result<T, ActorErr>`
// alias that shadows the std `Result`. Keep an unaliased one around for
// the HTTP/JSON helpers below (which want their own error type).
pub(crate) type IoResult<T> = core::result::Result<T, String>;

// ── Shared runtime state ───────────────────────────────────────────────
//
// Reachable both from the actor's handlers (which read/write counters
// and the stop flag) and from the tokio thread (which serves admin
// endpoints + bumps the request counter). One per process — there's
// only meant to be a single gateway instance per worker .so load.

pub(crate) struct Inner {
    /// Set to true to ask the running `start` loop to exit.
    pub(crate) stop: AtomicBool,
    /// Bound port, 0 when the gateway isn't running.
    pub(crate) bound_port: AtomicU16,
    /// Total HTTP requests fully served since process boot.
    pub(crate) requests: AtomicU64,
    /// Unix epoch seconds when `start` last entered the serve loop;
    /// 0 when never started.
    pub(crate) started_unix: AtomicU64,
}

impl Inner {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            stop: AtomicBool::new(false),
            bound_port: AtomicU16::new(0),
            requests: AtomicU64::new(0),
            started_unix: AtomicU64::new(0),
        })
    }

    fn running(&self) -> bool {
        self.bound_port.load(Ordering::Relaxed) != 0
            && !self.stop.load(Ordering::Relaxed)
    }
}

fn inner() -> &'static Arc<Inner> {
    static INNER: OnceLock<Arc<Inner>> = OnceLock::new();
    INNER.get_or_init(Inner::new)
}

#[actor]
struct HttpGateway;

#[messages]
impl HttpGateway {
    fn new() -> Self {
        HttpGateway
    }

    /// Bind `port` and serve HTTP. Blocks the worker's dispatch loop
    /// until `stop()` (or `POST /__admin/stop`) flips the stop flag,
    /// or the listener fails. Returns a short status string.
    ///
    /// Calling twice while a gateway is already running returns
    /// immediately with an "already running" message — the caller
    /// should `stop()` first.
    #[msg]
    async fn serve(&mut self, port: u32, ctx: &mut Context<Self>) -> String {
        let port = port as u16;
        let inner = inner().clone();

        if inner.bound_port.load(Ordering::Relaxed) != 0 {
            return format!(
                "already listening on 0.0.0.0:{}",
                inner.bound_port.load(Ordering::Relaxed),
            );
        }

        // Reset the stop flag — a previous run may have set it.
        inner.stop.store(false, Ordering::Relaxed);

        let (job_tx, job_rx) = mpsc::channel::<Job>();
        if let Err(e) = spawn_runtime(port, job_tx, inner.clone()) {
            log::error!("http-gateway: {e}");
            return e;
        }
        inner.bound_port.store(port, Ordering::Relaxed);
        inner.started_unix.store(unix_now(), Ordering::Relaxed);
        log::info!("http-gateway: listening on 0.0.0.0:{port}");

        let stop_msg = drain_jobs(&job_rx, &inner, ctx).await;

        inner.bound_port.store(0, Ordering::Relaxed);
        log::info!("http-gateway: {stop_msg}");
        stop_msg
    }

    /// Set the stop flag. The running `start()` will see it on the
    /// next loop iteration and return. Returns `true` if the gateway
    /// was running at the moment of the call.
    ///
    /// **Note:** this can only be processed when `start()` is *not*
    /// currently in flight on the same worker. To stop a running
    /// gateway from outside the host process, use the HTTP admin
    /// endpoint at `POST /__admin/stop`.
    #[msg]
    async fn stop(&self, _ctx: &mut Context<Self>) -> bool {
        let i = inner();
        let was_running = i.running();
        i.stop.store(true, Ordering::Relaxed);
        was_running
    }

    /// Bound port, or 0 when the gateway isn't running.
    #[msg]
    async fn port(&self, _ctx: &mut Context<Self>) -> u32 {
        inner().bound_port.load(Ordering::Relaxed) as u32
    }

    /// Total HTTP requests served since process boot.
    #[msg]
    async fn requests(&self, _ctx: &mut Context<Self>) -> u64 {
        inner().requests.load(Ordering::Relaxed)
    }

    /// `true` if a `start()` is in flight and hasn't been asked to stop.
    #[msg]
    async fn running(&self, _ctx: &mut Context<Self>) -> bool {
        inner().running()
    }

    /// Compact JSON status string: `{"port":N,"running":bool,...}`.
    /// Same shape as `GET /__admin/status`.
    #[msg]
    async fn status(&self, _ctx: &mut Context<Self>) -> String {
        status_json(inner())
    }

    /// Bind a QUIC + HTTP/3 listener on UDP `port`. Same Job → ctx.ask
    /// → Response flow as `serve`, just QUIC on the wire. Auto-mints a
    /// self-signed cert for `localhost` (dev only — operator cert
    /// loading lands in a follow-up).
    ///
    /// Like `serve`, this blocks until the stop flag flips. Available
    /// only when this crate is built with `--features http3`; without
    /// the feature it returns a "not enabled" message so the message
    /// surface is stable across feature combinations.
    #[msg]
    async fn serve_h3(&mut self, port: u32, ctx: &mut Context<Self>) -> String {
        serve_h3_impl(port as u16, ctx).await
    }
}

#[cfg(not(feature = "http3"))]
async fn serve_h3_impl(_port: u16, _ctx: &mut vos::Context<HttpGateway>) -> String {
    "http3 feature not enabled — rebuild with --features http3".into()
}

#[cfg(feature = "http3")]
async fn serve_h3_impl(port: u16, ctx: &mut vos::Context<HttpGateway>) -> String {
    let inner = inner().clone();

    if inner.bound_port.load(Ordering::Relaxed) != 0 {
        return format!(
            "already listening on 0.0.0.0:{}",
            inner.bound_port.load(Ordering::Relaxed),
        );
    }
    inner.stop.store(false, Ordering::Relaxed);

    let (job_tx, job_rx) = mpsc::channel::<Job>();
    if let Err(e) = spawn_h3_runtime(port, job_tx, inner.clone()) {
        log::error!("http-gateway: {e}");
        return e;
    }
    inner.bound_port.store(port, Ordering::Relaxed);
    inner.started_unix.store(unix_now(), Ordering::Relaxed);
    log::info!("http-gateway: listening on udp/0.0.0.0:{port} (h3)");

    let stop_msg = drain_jobs(&job_rx, &inner, ctx).await;

    inner.bound_port.store(0, Ordering::Relaxed);
    log::info!("http-gateway: {stop_msg}");
    stop_msg
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn status_json(inner: &Inner) -> String {
    let port = inner.bound_port.load(Ordering::Relaxed);
    let started = inner.started_unix.load(Ordering::Relaxed);
    let now = unix_now();
    let uptime = if started == 0 || now < started { 0 } else { now - started };
    format!(
        "{{\"port\":{port},\"running\":{running},\"requests\":{requests},\"uptime_secs\":{uptime},\"started_unix\":{started}}}",
        running = inner.running(),
        requests = inner.requests.load(Ordering::Relaxed),
    )
}

/// Shared job-drain loop used by both `serve` and `serve_h3`. Polls
/// the stop flag every 200 ms so even an idle gateway notices a
/// shutdown request promptly. Returns a short status string when the
/// loop exits.
async fn drain_jobs(
    job_rx: &mpsc::Receiver<Job>,
    inner: &Inner,
    ctx: &mut vos::Context<HttpGateway>,
) -> String {
    loop {
        if inner.stop.load(Ordering::Relaxed) {
            return "stopped".into();
        }
        match job_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(job) => {
                let response = handle(&job.request, ctx).await;
                inner.requests.fetch_add(1, Ordering::Relaxed);
                let _ = job.resp_tx.send(response);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return "job channel closed".into();
            }
        }
    }
}

// ── Job queue ───────────────────────────────────────────────────────

/// One HTTP job in flight. The connection task pushes a `Job` onto
/// the actor's mpsc; the actor handler fills `resp_tx` once `ctx.ask`
/// completes; the task awaits the oneshot and writes the response.
pub(crate) struct Job {
    pub(crate) request: Request,
    pub(crate) resp_tx: oneshot::Sender<Response>,
}

// ── HTTP plumbing ───────────────────────────────────────────────────

pub(crate) struct Request {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) query: String,
    pub(crate) body: Vec<u8>,
}

pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) content_type: &'static str,
    pub(crate) body: Vec<u8>,
}

impl Response {
    fn json(status: u16, body: Vec<u8>) -> Self {
        Self { status, content_type: "application/json", body }
    }
    pub(crate) fn text(status: u16, msg: impl Into<String>) -> Self {
        Self { status, content_type: "text/plain", body: msg.into().into_bytes() }
    }
}

/// Spawn a QUIC + h3 runtime in a dedicated OS thread. Same
/// ready-signal handshake as `spawn_runtime`.
#[cfg(feature = "http3")]
fn spawn_h3_runtime(
    port: u16,
    job_tx: mpsc::Sender<Job>,
    inner: Arc<Inner>,
) -> IoResult<()> {
    let (ready_tx, ready_rx) = mpsc::sync_channel::<IoResult<()>>(1);
    thread::Builder::new()
        .name(format!("http-gateway-h3:{port}"))
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx.send(Err(format!("runtime build: {e}")));
                    return;
                }
            };
            rt.block_on(async move {
                let addr = match format!("0.0.0.0:{port}").parse() {
                    Ok(a) => a,
                    Err(e) => {
                        let _ = ready_tx.send(Err(format!("addr parse: {e}")));
                        return;
                    }
                };
                let endpoint = match http3::build_endpoint(addr) {
                    Ok(ep) => ep,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(()));
                http3::accept_loop(endpoint, job_tx, inner).await;
            });
        })
        .map_err(|e| format!("spawn h3 thread: {e}"))?;
    ready_rx
        .recv()
        .map_err(|e| format!("ready signal: {e}"))?
}

/// Spawn the tokio runtime + accept loop in a dedicated OS thread.
/// Synchronously blocks until the listener is bound (or the bind
/// fails, in which case the error propagates back to the caller).
fn spawn_runtime(
    port: u16,
    job_tx: mpsc::Sender<Job>,
    inner: Arc<Inner>,
) -> IoResult<()> {
    let (ready_tx, ready_rx) = mpsc::sync_channel::<IoResult<()>>(1);
    thread::Builder::new()
        .name(format!("http-gateway-rt:{port}"))
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx.send(Err(format!("runtime build: {e}")));
                    return;
                }
            };
            rt.block_on(async move {
                let listener = match TcpListener::bind(("0.0.0.0", port)).await {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = ready_tx.send(Err(format!("bind 0.0.0.0:{port}: {e}")));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(()));
                accept_loop(listener, job_tx, inner).await;
            });
        })
        .map_err(|e| format!("spawn rt thread: {e}"))?;
    ready_rx
        .recv()
        .map_err(|e| format!("ready signal: {e}"))?
}

async fn accept_loop(
    listener: TcpListener,
    job_tx: mpsc::Sender<Job>,
    inner: Arc<Inner>,
) {
    // Single connection builder for both h1 and h2c. `auto::Builder`
    // sniffs the connection preface and dispatches to the right
    // protocol — h2c gives a single TCP connection multiplexed over
    // many requests, all of which funnel into our mpsc.
    let conn_builder = hyper_util::server::conn::auto::Builder::new(
        hyper_util::rt::TokioExecutor::new(),
    );

    loop {
        // Stop flipping → finish in-flight tasks but stop accepting.
        if inner.stop.load(Ordering::Relaxed) {
            return;
        }
        let accept = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        let (stream, peer) = match accept {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => {
                log::warn!("http-gateway: accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
            Err(_) => continue, // timeout — re-check stop and loop
        };
        let job_tx = job_tx.clone();
        let inner = inner.clone();
        let conn_builder = conn_builder.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: hyper::Request<Incoming>| {
                let job_tx = job_tx.clone();
                let inner = inner.clone();
                async move { Ok::<_, Infallible>(serve_request(req, job_tx, inner).await) }
            });
            if let Err(e) = conn_builder.serve_connection(io, svc).await {
                log::debug!("http-gateway: conn {peer}: {e}");
            }
        });
    }
}

/// Hyper service function. Translates hyper's `Request<Incoming>` into
/// our internal `Request`, runs the admin shortcut or queues a `Job`
/// for the actor handler, then turns the resulting `Response` back
/// into a hyper response.
async fn serve_request(
    req: hyper::Request<Incoming>,
    job_tx: mpsc::Sender<Job>,
    inner: Arc<Inner>,
) -> HyperResponse {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();

    // Read the body. Bounded by hyper's default per-frame limits;
    // a future iteration could enforce a hard cap here.
    let body = match req.into_body().collect().await {
        Ok(c) => c.to_bytes().to_vec(),
        Err(e) => {
            return into_hyper(Response::text(400, format!("read body: {e}")));
        }
    };

    let our_req = Request { method, path, query, body };

    // Admin endpoints don't need an actor round-trip — handle them in
    // the tokio task so they work even while `serve()` is the only
    // message the worker is currently processing.
    if let Some(response) = handle_admin(&our_req, &inner) {
        return into_hyper(response);
    }

    let (resp_tx, resp_rx) = oneshot::channel::<Response>();
    if job_tx.send(Job { request: our_req, resp_tx }).is_err() {
        // Actor handler dropped the receiver — gateway is shutting down.
        return into_hyper(Response::text(503, "gateway stopped"));
    }

    let response = match resp_rx.await {
        Ok(r) => r,
        Err(_) => {
            // Actor never sent a response (panicked / dropped sender).
            Response::text(500, "no response from actor")
        }
    };
    into_hyper(response)
}

fn into_hyper(r: Response) -> HyperResponse {
    // Builder errors are unreachable here: status codes are limited to
    // the small set we hand-write, and content-type values are static.
    hyper::Response::builder()
        .status(r.status)
        .header("content-type", r.content_type)
        .body(Full::new(Bytes::from(r.body)))
        .expect("hyper response builder")
}

/// Direct admin endpoints. Returns `Some(response)` to short-circuit
/// the normal actor-dispatch path. Routes:
///
/// - `GET  /__admin/status` — JSON snapshot
/// - `POST /__admin/stop`   — set the stop flag, reply 204
pub(crate) fn handle_admin(req: &Request, inner: &Inner) -> Option<Response> {
    if !req.path.starts_with("/__admin/") {
        return None;
    }
    Some(match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/__admin/status") => Response::json(200, status_json(inner).into_bytes()),
        ("POST", "/__admin/stop") => {
            inner.stop.store(true, Ordering::Relaxed);
            Response { status: 204, content_type: "text/plain", body: Vec::new() }
        }
        _ => Response::text(404, format!("unknown admin route {} {}", req.method, req.path)),
    })
}

// ── Routing ─────────────────────────────────────────────────────────

async fn handle(req: &Request, ctx: &mut vos::Context<HttpGateway>) -> Response {
    // Path is "/<agent>/<method>" — split off any leading slash.
    let trimmed = req.path.trim_start_matches('/');
    let (agent, method) = match trimmed.split_once('/') {
        Some((a, m)) if !a.is_empty() && !m.is_empty() => (a.to_string(), m.to_string()),
        _ => return Response::text(400, "expected /<agent>/<method>"),
    };

    // Resolve agent name via the well-known registry actor.
    let resolve_msg = Msg::new("resolve").with("name", agent.clone());
    let resolved = match ctx.ask(ServiceId::REGISTRY, &resolve_msg).await {
        Ok(v) => v.as_u32().unwrap_or(0),
        Err(e) => return Response::text(502, format!("registry: {e}")),
    };
    if resolved == 0 {
        return Response::text(404, format!("unknown agent '{agent}'"));
    }
    let target = ServiceId(resolved);

    // Build the message from method + args.
    let mut msg = Msg::new(method);
    match req.method.as_str() {
        "GET" => {
            for (k, v) in parse_query(&req.query) {
                msg = msg.with(k, v);
            }
        }
        "POST" | "PUT" | "PATCH" => {
            if !req.body.is_empty() {
                match parse_flat_json(&req.body) {
                    Ok(pairs) => {
                        for (k, v) in pairs {
                            msg = msg.with(k, v);
                        }
                    }
                    Err(e) => return Response::text(400, format!("invalid JSON: {e}")),
                }
            }
        }
        other => return Response::text(405, format!("method {other} not allowed")),
    }

    // Dispatch to the resolved agent.
    match ctx.ask(target, &msg).await {
        Ok(value) => Response::json(200, value_to_json(&value).into_bytes()),
        Err(e) => Response::text(502, format!("upstream error: {e}")),
    }
}

/// Parse `a=1&b=hello+world` into `[(a, "1"), (b, "hello world")]`.
/// All values are returned as `String` — no type inference. Good
/// enough for the scaffold; structured args belong on POST.
fn parse_query(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return Vec::new();
    }
    query
        .split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            if k.is_empty() {
                return None;
            }
            Some((url_decode(k), url_decode(v)))
        })
        .collect()
}

/// Tiny percent-decoder. Handles `+` → space and `%XX` hex escapes;
/// invalid escapes fall through unchanged. Sufficient for query
/// strings; not a full RFC 3986 implementation.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hi = hex(bytes[i + 1]);
                let lo = hex(bytes[i + 2]);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi << 4) | lo);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(&e.into_bytes()).into_owned())
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ── JSON ⇄ Value ────────────────────────────────────────────────────
//
// Parsing covers a top-level JSON object whose values are scalars,
// strings, or null. Arrays land as `ListStr` when every element is a
// string and `ListU32` when every element is a non-negative integer
// fitting in u32 — that matches what `vos::Value` can carry.
// Anything richer (nested objects, mixed-type arrays, floats) is
// rejected with a 400; the URL contract is "method name + flat
// argument map", and a richer arg form belongs in a future iteration.
//
// Serialization renders the whole `Value` enum. `Bytes` becomes a
// base16 string — we're not optimizing for blob transfer over JSON.

fn parse_flat_json(body: &[u8]) -> IoResult<Vec<(String, Value)>> {
    let json: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("{e}"))?;
    let serde_json::Value::Object(map) = json else {
        return Err("expected a top-level JSON object".into());
    };
    map.into_iter()
        .map(|(k, v)| Ok((k, json_to_value(v)?)))
        .collect()
}

fn json_to_value(j: serde_json::Value) -> IoResult<Value> {
    use serde_json::Value as J;
    Ok(match j {
        J::Null => Value::Unit,
        J::Bool(b) => Value::Bool(b),
        J::Number(n) => json_number_to_value(n)?,
        J::String(s) => Value::Str(s),
        J::Array(xs) => json_array_to_value(xs)?,
        J::Object(_) => return Err("nested objects are not supported".into()),
    })
}

fn json_number_to_value(n: serde_json::Number) -> IoResult<Value> {
    if let Some(u) = n.as_u64() {
        return Ok(if u <= u32::MAX as u64 {
            Value::U32(u as u32)
        } else {
            Value::U64(u)
        });
    }
    if let Some(i) = n.as_i64() {
        return Ok(Value::I64(i));
    }
    // Floats land as strings — `vos::Value` has no float variant.
    Err(format!("non-integer number {n} unsupported"))
}

fn json_array_to_value(xs: Vec<serde_json::Value>) -> IoResult<Value> {
    if xs.is_empty() {
        return Ok(Value::ListStr(Vec::new()));
    }
    if xs.iter().all(|v| v.is_string()) {
        let strings = xs
            .into_iter()
            .map(|v| v.as_str().expect("checked").to_string())
            .collect();
        return Ok(Value::ListStr(strings));
    }
    if xs.iter().all(|v| v.as_u64().is_some_and(|u| u <= u32::MAX as u64)) {
        let nums = xs
            .into_iter()
            .map(|v| v.as_u64().expect("checked") as u32)
            .collect();
        return Ok(Value::ListU32(nums));
    }
    Err("array elements must all be strings or all be non-negative u32-fitting integers".into())
}

fn value_to_json(v: &Value) -> String {
    serde_json::to_string(&value_to_json_value(v)).unwrap_or_else(|_| "null".into())
}

fn value_to_json_value(v: &Value) -> serde_json::Value {
    use serde_json::Value as J;
    match v {
        Value::Unit => J::Null,
        Value::Bool(b) => J::Bool(*b),
        Value::U8(v) => (*v).into(),
        Value::U16(v) => (*v).into(),
        Value::U32(v) => (*v).into(),
        Value::U64(v) => (*v).into(),
        Value::I32(v) => (*v).into(),
        Value::I64(v) => (*v).into(),
        Value::Str(s) => J::String(s.clone()),
        // Bytes → hex string. Same posture as before — JSON isn't a
        // good blob transport, so we surface them as inspectable text.
        Value::Bytes(b) => {
            let mut s = String::with_capacity(b.len() * 2);
            for byte in b {
                use std::fmt::Write as _;
                let _ = write!(s, "{byte:02x}");
            }
            J::String(s)
        }
        Value::ListU32(xs) => J::Array(xs.iter().map(|x| (*x).into()).collect()),
        Value::ListStr(xs) => J::Array(xs.iter().map(|s| J::String(s.clone())).collect()),
    }
}
