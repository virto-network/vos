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

type HyperResponse = hyper::Response<Full<Bytes>>;

// `#[messages]` emits a `type Result<T> = core::result::Result<T, ActorErr>`
// alias that shadows the std `Result`. Keep an unaliased one around for
// the HTTP/JSON helpers below (which want their own error type).
type IoResult<T> = core::result::Result<T, String>;

// ── Shared runtime state ───────────────────────────────────────────────
//
// Reachable both from the actor's handlers (which read/write counters
// and the stop flag) and from the tokio thread (which serves admin
// endpoints + bumps the request counter). One per process — there's
// only meant to be a single gateway instance per worker .so load.

struct Inner {
    /// Set to true to ask the running `start` loop to exit.
    stop: AtomicBool,
    /// Bound port, 0 when the gateway isn't running.
    bound_port: AtomicU16,
    /// Total HTTP requests fully served since process boot.
    requests: AtomicU64,
    /// Unix epoch seconds when `start` last entered the serve loop;
    /// 0 when never started.
    started_unix: AtomicU64,
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

        // Drain loop. Polls the stop flag every recv-timeout tick so
        // even a quiet gateway notices a shutdown request.
        let stop_msg = loop {
            if inner.stop.load(Ordering::Relaxed) {
                break "stopped".to_string();
            }
            match job_rx.recv_timeout(Duration::from_millis(200)) {
                Ok(job) => {
                    let response = handle(&job.request, ctx).await;
                    inner.requests.fetch_add(1, Ordering::Relaxed);
                    // Connection task may have given up (client hangup);
                    // drop the response silently rather than failing.
                    let _ = job.resp_tx.send(response);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break "job channel closed".to_string();
                }
            }
        };

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

// ── Job queue ───────────────────────────────────────────────────────

/// One HTTP job in flight. The connection task pushes a `Job` onto
/// the actor's mpsc; the actor handler fills `resp_tx` once `ctx.ask`
/// completes; the task awaits the oneshot and writes the response.
struct Job {
    request: Request,
    resp_tx: oneshot::Sender<Response>,
}

// ── HTTP plumbing ───────────────────────────────────────────────────

struct Request {
    method: String,
    path: String,
    query: String,
    body: Vec<u8>,
}

struct Response {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

impl Response {
    fn json(status: u16, body: Vec<u8>) -> Self {
        Self { status, content_type: "application/json", body }
    }
    fn text(status: u16, msg: impl Into<String>) -> Self {
        Self { status, content_type: "text/plain", body: msg.into().into_bytes() }
    }
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
fn handle_admin(req: &Request, inner: &Inner) -> Option<Response> {
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
                let body_str = match std::str::from_utf8(&req.body) {
                    Ok(s) => s,
                    Err(_) => return Response::text(400, "body is not valid utf-8"),
                };
                match parse_flat_json(body_str) {
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

// ── Tiny JSON ───────────────────────────────────────────────────────
//
// Both directions are deliberately minimal:
//
// - `parse_flat_json` only accepts a top-level object whose values
//   are strings/numbers/bools/null. That matches the URL convention
//   (one method-name + a flat arg map) and keeps the worker free of
//   a real JSON dep for now.
// - `value_to_json` renders the whole `Value` enum, including list
//   variants, so callers see structured replies instead of opaque
//   debug formatting.

fn parse_flat_json(input: &str) -> IoResult<Vec<(String, Value)>> {
    let mut p = JsonParser::new(input);
    p.skip_ws();
    p.expect(b'{')?;
    p.skip_ws();
    let mut out = Vec::new();
    if p.peek() == Some(b'}') {
        p.bump();
        return Ok(out);
    }
    loop {
        p.skip_ws();
        let key = p.parse_string()?;
        p.skip_ws();
        p.expect(b':')?;
        p.skip_ws();
        let value = p.parse_value()?;
        out.push((key, value));
        p.skip_ws();
        match p.peek() {
            Some(b',') => { p.bump(); }
            Some(b'}') => { p.bump(); return Ok(out); }
            _ => return Err("expected ',' or '}'".into()),
        }
    }
}

struct JsonParser<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn new(s: &'a str) -> Self { Self { src: s.as_bytes(), pos: 0 } }
    fn peek(&self) -> Option<u8> { self.src.get(self.pos).copied() }
    fn bump(&mut self) -> Option<u8> { let b = self.peek()?; self.pos += 1; Some(b) }
    fn expect(&mut self, b: u8) -> IoResult<()> {
        match self.bump() {
            Some(c) if c == b => Ok(()),
            Some(c) => Err(format!("expected {:?}, got {:?}", b as char, c as char)),
            None => Err(format!("expected {:?}, got EOF", b as char)),
        }
    }
    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' { self.pos += 1; } else { break; }
        }
    }
    fn parse_string(&mut self) -> IoResult<String> {
        self.expect(b'"')?;
        let mut out = Vec::new();
        loop {
            match self.bump() {
                None => return Err("unterminated string".into()),
                Some(b'"') => break,
                Some(b'\\') => match self.bump() {
                    Some(b'"') => out.push(b'"'),
                    Some(b'\\') => out.push(b'\\'),
                    Some(b'/') => out.push(b'/'),
                    Some(b'n') => out.push(b'\n'),
                    Some(b't') => out.push(b'\t'),
                    Some(b'r') => out.push(b'\r'),
                    Some(c) => out.push(c),
                    None => return Err("unterminated escape".into()),
                }
                Some(b) => out.push(b),
            }
        }
        String::from_utf8(out).map_err(|_| "invalid utf-8 in string".into())
    }
    fn parse_value(&mut self) -> IoResult<Value> {
        match self.peek() {
            Some(b'"') => self.parse_string().map(Value::Str),
            Some(b't') => { self.consume(b"true")?; Ok(Value::Bool(true)) }
            Some(b'f') => { self.consume(b"false")?; Ok(Value::Bool(false)) }
            Some(b'n') => { self.consume(b"null")?; Ok(Value::Unit) }
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            Some(c) => Err(format!("unexpected token {:?}", c as char)),
            None => Err("unexpected EOF".into()),
        }
    }
    fn consume(&mut self, lit: &[u8]) -> IoResult<()> {
        for &b in lit {
            self.expect(b)?;
        }
        Ok(())
    }
    fn parse_number(&mut self) -> IoResult<Value> {
        let start = self.pos;
        if self.peek() == Some(b'-') { self.pos += 1; }
        while matches!(self.peek(), Some(b'0'..=b'9')) { self.pos += 1; }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            while matches!(self.peek(), Some(b'0'..=b'9')) { self.pos += 1; }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) { self.pos += 1; }
            while matches!(self.peek(), Some(b'0'..=b'9')) { self.pos += 1; }
        }
        let slice = &self.src[start..self.pos];
        let s = std::str::from_utf8(slice).map_err(|_| "non-utf8 number".to_string())?;
        if is_float {
            // The Value enum has no float variant — store as string for now.
            // Receivers that want floats should parse from string until we
            // extend Value.
            Ok(Value::Str(s.to_string()))
        } else if let Ok(v) = s.parse::<i64>() {
            if v >= 0 && v <= u32::MAX as i64 { Ok(Value::U32(v as u32)) }
            else { Ok(Value::I64(v)) }
        } else {
            Err(format!("invalid number {s}"))
        }
    }
}

fn value_to_json(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut String, value: &Value) {
    use std::fmt::Write as _;
    match value {
        Value::Unit => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::U8(v) => { let _ = write!(out, "{v}"); }
        Value::U16(v) => { let _ = write!(out, "{v}"); }
        Value::U32(v) => { let _ = write!(out, "{v}"); }
        Value::U64(v) => { let _ = write!(out, "{v}"); }
        Value::I32(v) => { let _ = write!(out, "{v}"); }
        Value::I64(v) => { let _ = write!(out, "{v}"); }
        Value::Str(s) => write_json_string(out, s),
        Value::Bytes(b) => {
            // Rendered as a base16 string for now — the gateway is
            // about API surfaces, not raw blob transfer.
            out.push('"');
            for byte in b {
                let _ = write!(out, "{byte:02x}");
            }
            out.push('"');
        }
        Value::ListU32(xs) => {
            out.push('[');
            for (i, v) in xs.iter().enumerate() {
                if i > 0 { out.push(','); }
                let _ = write!(out, "{v}");
            }
            out.push(']');
        }
        Value::ListStr(xs) => {
            out.push('[');
            for (i, s) in xs.iter().enumerate() {
                if i > 0 { out.push(','); }
                write_json_string(out, s);
            }
            out.push(']');
        }
    }
}

fn write_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
