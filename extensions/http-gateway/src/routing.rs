//! Request routing.
//!
//! Three layers, from outside in:
//!
//! 1. [`dispatch_request`] — wire-side entry. Runs the admin shortcut,
//!    enforces `Authorization: Bearer <token>` if configured, then
//!    pushes a `Job` for the actor to handle. Both the hyper and h3
//!    paths land here after extracting an internal [`Request`] from
//!    the wire format. Auth happens here so failed requests never
//!    consume a job-queue slot.
//! 2. [`handle_admin`] — direct `/__admin/*` routes, never round-trip
//!    through the actor.
//! 3. [`handle`] — actor-side. Pulls the `Job`, resolves the agent
//!    name through the registry, dispatches via `ctx.ask`, and packs
//!    the reply.
//!
//! [`drain_jobs`] is the loop on the actor side that pumps `handle`.

use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Duration;

use tokio::sync::oneshot;
use vos::actors::context::ServiceId;
use vos::actors::value::Msg;
use vos::extension::ServiceCtx;
use vos::log;
use vos::{Decode, Encode};

use crate::config::{ct_eq, header_value};
use crate::json::{parse_flat_json, value_to_json};
use crate::state::{Inner, status_json};
use crate::types::{Job, Request, Response};

/// Per-request auth policy threaded through the wire path. The
/// connection-side glue reads these from [`crate::config`] once and
/// passes them through; tests construct policies directly to exercise
/// each combination without touching the global singleton.
#[derive(Clone, Copy, Default)]
pub(crate) struct Policy<'a> {
    pub admin_token: Option<&'a str>,
    pub auth_token: Option<&'a str>,
}

/// Wire-side dispatch. Runs in the connection task; turns one
/// internal [`Request`] into a [`Response`] using the admin shortcut,
/// the auth gate, and the actor's job queue in that order.
pub(crate) async fn dispatch_request(
    req: Request,
    job_tx: &mpsc::SyncSender<Job>,
    inner: &Inner,
    policy: Policy<'_>,
) -> Response {
    if let Some(response) = handle_admin(&req, inner, policy.admin_token) {
        return response;
    }
    if let Some(response) = check_auth(&req, policy.auth_token) {
        return response;
    }
    let (resp_tx, resp_rx) = oneshot::channel::<Response>();
    match job_tx.try_send(Job {
        request: req,
        resp_tx,
    }) {
        Ok(()) => {}
        Err(mpsc::TrySendError::Full(_)) => {
            return Response::text(503, "gateway saturated; retry");
        }
        Err(mpsc::TrySendError::Disconnected(_)) => {
            return Response::text(503, "gateway stopped");
        }
    }
    resp_rx
        .await
        .unwrap_or_else(|_| Response::text(500, "no response from actor"))
}

/// Bearer-token gate. `None` if the request is allowed (either auth
/// is disabled or the header matches), `Some(401)` if it should be
/// rejected.
fn check_auth(req: &Request, expected: Option<&str>) -> Option<Response> {
    let expected = expected?;
    let provided = header_value(&req.headers, "authorization").and_then(|v| {
        v.strip_prefix("Bearer ")
            .or_else(|| v.strip_prefix("bearer "))
    });
    if provided.is_some_and(|t| ct_eq(t.trim(), expected)) {
        None
    } else {
        Some(Response::text(401, "unauthorized"))
    }
}

/// Drain loop on the gateway's `run` thread. Pulls Jobs from the
/// connection-side mpsc, dispatches via `ctx.ask_raw`, sends the
/// reply back. Synchronous because `ServiceCtx::ask_raw` blocks the
/// calling thread by design — no async bridge needed at this layer.
///
/// Exits when `inner.stop` is flipped (admin endpoint or
/// `ctx.is_shutdown()` polled by the caller) or when the protocol
/// thread closes the job channel.
pub(crate) fn drain_jobs(job_rx: &mpsc::Receiver<Job>, inner: &Inner, ctx: &ServiceCtx) -> String {
    loop {
        if inner.stop.load(Ordering::Relaxed) || ctx.is_shutdown() {
            return "stopped".into();
        }
        match job_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(job) => {
                let response = handle(&job.request, inner, ctx);
                inner.requests.fetch_add(1, Ordering::Relaxed);
                let _ = job.resp_tx.send(response);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return "job channel closed".into(),
        }
    }
}

fn handle(req: &Request, inner: &Inner, ctx: &ServiceCtx) -> Response {
    let Some((agent, method)) = split_path(&req.path) else {
        return Response::text(400, "expected /<agent>/<method>");
    };

    let target = match resolve(ctx, &agent) {
        Some(id) => id,
        None => return Response::text(404, format!("unknown agent '{agent}'")),
    };

    // Look up (and lazily cache) the actor's schema. With it,
    // `build_msg` can coerce query/JSON values to the handler's
    // declared types; without it the request still flies, but
    // numeric query args stay as strings and json U32/U64
    // classification stays leaky.
    let meta = ensure_meta_cached(ctx, inner, target, &agent);
    let method_meta = meta
        .as_ref()
        .and_then(|m| m.messages.iter().find(|msg| msg.name == method).cloned());

    let msg = match build_msg(method, method_meta.as_ref(), req) {
        Ok(m) => m,
        Err(r) => return r,
    };

    // Encode as TAG_DYNAMIC + rkyv'd Msg — same wire format the
    // existing actor-mode dispatch path produces.
    let encoded = msg.encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(vos::value::TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);

    match ctx.ask_raw(target.0, &payload) {
        Some(reply_bytes) if reply_bytes.is_empty() => {
            // Empty reply = handler returned () successfully OR the
            // worker dispatch errored (no such handler, type
            // mismatch, panic). Indistinguishable on the wire
            // today; render as JSON null. The host always sends a
            // reply for ask-style traffic so the gateway doesn't
            // hang for the 5-min ask timeout when a dispatch
            // errors — see vos/src/node.rs's worker reply loop.
            Response::json(200, value_to_json(&vos::value::Value::Unit))
        }
        Some(reply_bytes) => {
            // try_decode runs rkyv's checked access — handles
            // arbitrary alignment + validates the buffer. decode
            // would unsafely access_unchecked, panicking on
            // misaligned slices that came back through the invoke
            // envelope unwrap.
            match <vos::value::Value as vos::Decode>::try_decode(&reply_bytes) {
                Some(value) => Response::json(200, value_to_json(&value)),
                None => Response::text(502, "upstream returned malformed reply"),
            }
        }
        None => Response::text(502, "upstream error or shutdown"),
    }
}

/// Direct admin endpoints — bypass `ctx.ask` so they work even while
/// `serve()` is the only message in flight on the worker.
///
/// Auth: with `admin_token = None` the gateway returns 404 for the
/// entire `/__admin/*` namespace so its existence isn't even
/// disclosed. With `Some(expected)`, the request must carry a
/// matching `X-Admin-Token` header (constant-time compared).
///
/// - `GET  /__admin/status` → JSON snapshot
/// - `POST /__admin/stop`   → set the stop flag, reply 204
pub(crate) fn handle_admin(
    req: &Request,
    inner: &Inner,
    admin_token: Option<&str>,
) -> Option<Response> {
    if !req.path.starts_with("/__admin/") {
        return None;
    }
    let Some(expected) = admin_token else {
        return Some(Response::text(404, "not found"));
    };
    let provided = header_value(&req.headers, "x-admin-token");
    if !provided.is_some_and(|t| ct_eq(t, expected)) {
        return Some(Response::text(401, "unauthorized"));
    }
    Some(match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/__admin/status") => Response::json(200, status_json(inner).into_bytes()),
        ("POST", "/__admin/stop") => {
            inner.stop.store(true, Ordering::Relaxed);
            Response::empty(204)
        }
        _ => Response::text(
            404,
            format!("unknown admin route {} {}", req.method, req.path),
        ),
    })
}

fn split_path(path: &str) -> Option<(String, String)> {
    let trimmed = path.trim_start_matches('/');
    let (agent, method) = trimmed.split_once('/')?;
    (!agent.is_empty() && !method.is_empty()).then(|| (agent.to_string(), method.to_string()))
}

/// Look up an agent's `ServiceId` via the space registry actor.
/// Returns `None` for unknown names OR for any error from the
/// registry — collapsing the variants on purpose because both render
/// the same to the HTTP caller.
///
/// `caller_prefix` is required by the bundled space-registry's
/// `resolve(name, caller_prefix)` handler so it can derive the
/// agent's ServiceId in the gateway's node namespace. We extract
/// the prefix from the gateway's own ServiceId (high 16 bits via
/// `ctx.me()`).
fn resolve(ctx: &ServiceCtx, name: &str) -> Option<ServiceId> {
    let caller_prefix = (ctx.me() >> 16) as u64;
    let msg = Msg::new("resolve")
        .with("name", name.to_string())
        .with("caller_prefix", caller_prefix);
    let encoded = msg.encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(vos::value::TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    let bytes = ctx.ask_raw(ServiceId::REGISTRY.0, &payload)?;
    if bytes.is_empty() {
        return None;
    }
    let value: vos::value::Value = vos::value::Value::decode(&bytes);
    let id = value.as_u32().unwrap_or(0);
    (id != 0).then_some(ServiceId(id))
}

fn build_msg(
    method: String,
    method_meta: Option<&vos::metadata::ParsedMessage>,
    req: &Request,
) -> core::result::Result<Msg, Response> {
    use vos::value::Value;
    let mut msg = Msg::new(method);
    let coerce = |key: &str, v: Value| -> Value {
        let Some(meta) = method_meta else {
            return v;
        };
        match meta.fields.iter().find(|f| f.name == key) {
            Some(field) => coerce_to_type(v, &field.ty),
            None => v,
        }
    };
    match req.method.as_str() {
        "GET" => {
            // Query args arrive as `Value::Str` (no JSON typing
            // in a query string). With schema knowledge we can
            // parse them into the declared type — `?n=5` becomes
            // `Value::U64(5)` when the handler signature is u64.
            for (k, v) in parse_query(&req.query) {
                let typed = coerce(&k, Value::Str(v));
                msg = msg.with(k, typed);
            }
        }
        "POST" | "PUT" | "PATCH" => {
            if !req.body.is_empty() {
                let pairs = parse_flat_json(&req.body).map_err(|e| {
                    // Detail (line/column, offending token) goes to logs;
                    // clients see a generic 400 so server internals don't
                    // leak via crafted-input probing.
                    log::debug!("http-gateway: invalid JSON body: {e}");
                    Response::text(400, "invalid JSON body")
                })?;
                for (k, v) in pairs {
                    let typed = coerce(&k, v);
                    msg = msg.with(k, typed);
                }
            }
        }
        other => return Err(Response::text(405, format!("method {other} not allowed"))),
    }
    Ok(msg)
}

/// Coerce a `Value` into the variant matching a Rust type string
/// from `ParsedMeta::messages[i].fields[j].ty`. Used by the gateway
/// to bridge the JSON / query-string world (`Value::Str(_)` and
/// untyped numeric `Value::U32/U64`) to the actor's declared
/// signature. On a failed parse the original value passes through
/// — the actor will then reject the wrong type and the gateway
/// renders an empty reply. Bool/string/bytes pass through
/// unchanged.
fn coerce_to_type(v: vos::value::Value, ty: &str) -> vos::value::Value {
    use vos::value::Value;
    // Pull a string out for parse-based coercion (the GET path).
    let as_str = if let Value::Str(ref s) = v {
        Some(s.as_str())
    } else {
        None
    };
    match ty {
        "u8" => as_str
            .and_then(|s| s.parse::<u8>().ok())
            .map(Value::U8)
            .or_else(|| v.as_u8().map(Value::U8))
            .unwrap_or(v),
        "u16" => as_str
            .and_then(|s| s.parse::<u16>().ok())
            .map(Value::U16)
            .or_else(|| v.as_u16().map(Value::U16))
            .unwrap_or(v),
        "u32" => as_str
            .and_then(|s| s.parse::<u32>().ok())
            .map(Value::U32)
            .or_else(|| v.as_u32().map(Value::U32))
            .unwrap_or(v),
        "u64" => as_str
            .and_then(|s| s.parse::<u64>().ok())
            .map(Value::U64)
            .or_else(|| v.as_u64().map(Value::U64))
            .unwrap_or(v),
        "i32" => as_str
            .and_then(|s| s.parse::<i32>().ok())
            .map(Value::I32)
            .or_else(|| v.as_i32().map(Value::I32))
            .unwrap_or(v),
        "i64" => as_str
            .and_then(|s| s.parse::<i64>().ok())
            .map(Value::I64)
            .or_else(|| v.as_i64().map(Value::I64))
            .unwrap_or(v),
        "bool" => as_str
            .and_then(|s| s.parse::<bool>().ok())
            .map(Value::Bool)
            .unwrap_or(v),
        // String and complex types (Vec, bytes) pass through.
        // The actor's macro-generated `from_msg` runs the typed
        // accessor and rejects the message if the shape doesn't
        // match — no silent corruption.
        _ => v,
    }
}

/// Fetch the actor's schema from the registry on a cache miss; return
/// the cached entry on a hit. The cache distinguishes "not yet asked"
/// (absent) from "asked, no schema available" (`Some(None)`), so a
/// permanent miss costs at most one round trip per gateway lifetime.
fn ensure_meta_cached(
    ctx: &ServiceCtx,
    inner: &Inner,
    target: ServiceId,
    name: &str,
) -> Option<vos::metadata::ParsedMeta> {
    // Fast path: cache hit.
    {
        let cache = inner.meta_cache.lock().unwrap();
        if let Some(entry) = cache.get(&target.0) {
            return entry.clone();
        }
    }
    // Cache miss — ask the registry. We forward the name; the
    // registry does the agent → program_hash → meta join. Empty
    // reply means "no meta registered" → store `None` so we
    // don't retry on every request.
    let parsed = fetch_meta_from_registry(ctx, name);
    let mut cache = inner.meta_cache.lock().unwrap();
    cache.insert(target.0, parsed.clone());
    parsed
}

fn fetch_meta_from_registry(ctx: &ServiceCtx, name: &str) -> Option<vos::metadata::ParsedMeta> {
    let msg = Msg::new("meta_for_instance").with("name", name.to_string());
    let encoded = msg.encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(vos::value::TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    let bytes = ctx.ask_raw(ServiceId::REGISTRY.0, &payload)?;
    if bytes.is_empty() {
        return None;
    }
    // The reply is a `Value::Bytes(...)` carrying the raw
    // `.vos_meta` section. Empty bytes means the registry didn't
    // find a meta entry (old binary, hash mismatch). `decode`
    // returns None on a malformed/empty section too.
    let value: vos::value::Value = vos::value::Value::decode(&bytes);
    let raw = value.as_bytes()?;
    if raw.is_empty() {
        return None;
    }
    vos::metadata::decode(raw)
}

/// Parse `a=1&b=hello+world` into key-value pairs, with proper percent
/// + plus decoding handled by `serde_urlencoded`.
fn parse_query(query: &str) -> Vec<(String, String)> {
    serde_urlencoded::from_str(query).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_path_happy() {
        assert_eq!(
            split_path("/agent/method"),
            Some(("agent".into(), "method".into()))
        );
    }

    #[test]
    fn split_path_no_leading_slash() {
        assert_eq!(
            split_path("agent/method"),
            Some(("agent".into(), "method".into()))
        );
    }

    #[test]
    fn split_path_extra_segments_kept_in_method() {
        // `<method>` carries the rest of the path verbatim — no
        // escaping or slash-handling beyond the first split.
        assert_eq!(
            split_path("/agent/method/extra"),
            Some(("agent".into(), "method/extra".into()))
        );
    }

    #[test]
    fn split_path_rejects_empty_segments() {
        assert!(split_path("/").is_none());
        assert!(split_path("/agent").is_none());
        assert!(split_path("/agent/").is_none());
        assert!(split_path("//method").is_none());
    }

    #[test]
    fn parse_query_empty() {
        assert!(parse_query("").is_empty());
    }

    #[test]
    fn parse_query_simple_pairs() {
        assert_eq!(
            parse_query("a=1&b=hi"),
            vec![("a".into(), "1".into()), ("b".into(), "hi".into())],
        );
    }

    #[test]
    fn parse_query_handles_percent_and_plus() {
        // serde_urlencoded -> form_urlencoded percent + `+` decoding.
        assert_eq!(
            parse_query("name=hello+world&q=%26"),
            vec![
                ("name".into(), "hello world".into()),
                ("q".into(), "&".into()),
            ],
        );
    }

    // ── Wire-level dispatch tests ─────────────────────────────────
    //
    // Drive `dispatch_request` directly with hand-built `Request`s
    // and assert on the returned `Response`. Bypasses the hyper /
    // h3 wire-format extraction (covered by hyper's own tests) and
    // the actor's `ctx.ask` (covered by vos), focusing on the
    // policy/admin/auth/queue logic this crate owns.

    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64};

    fn fresh_inner() -> Inner {
        Inner {
            stop: AtomicBool::new(false),
            bound_port: AtomicU16::new(8080),
            requests: AtomicU64::new(0),
            started_unix: AtomicU64::new(1_700_000_000),
            in_flight: AtomicU16::new(0),
            cfg: crate::config::GatewayConfig::default(),
            meta_cache: Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn req(method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_vec(),
        }
    }

    fn channel() -> (mpsc::SyncSender<Job>, mpsc::Receiver<Job>) {
        mpsc::sync_channel::<Job>(4)
    }

    #[tokio::test]
    async fn admin_disabled_returns_404() {
        let inner = fresh_inner();
        let (tx, _rx) = channel();
        let resp = dispatch_request(
            req("GET", "/__admin/status", &[], &[]),
            &tx,
            &inner,
            Policy::default(),
        )
        .await;
        assert_eq!(resp.status, 404);
    }

    #[tokio::test]
    async fn admin_no_token_returns_401() {
        let inner = fresh_inner();
        let (tx, _rx) = channel();
        let resp = dispatch_request(
            req("GET", "/__admin/status", &[], &[]),
            &tx,
            &inner,
            Policy {
                admin_token: Some("expected"),
                auth_token: None,
            },
        )
        .await;
        assert_eq!(resp.status, 401);
    }

    #[tokio::test]
    async fn admin_wrong_token_returns_401() {
        let inner = fresh_inner();
        let (tx, _rx) = channel();
        let resp = dispatch_request(
            req("GET", "/__admin/status", &[("x-admin-token", "wrong")], &[]),
            &tx,
            &inner,
            Policy {
                admin_token: Some("expected"),
                auth_token: None,
            },
        )
        .await;
        assert_eq!(resp.status, 401);
    }

    #[tokio::test]
    async fn admin_correct_token_status_returns_json() {
        let inner = fresh_inner();
        let (tx, _rx) = channel();
        let resp = dispatch_request(
            req(
                "GET",
                "/__admin/status",
                &[("x-admin-token", "secret")],
                &[],
            ),
            &tx,
            &inner,
            Policy {
                admin_token: Some("secret"),
                auth_token: None,
            },
        )
        .await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type, "application/json");
        // Status JSON should contain the bound port we set in `fresh_inner`.
        let body = std::str::from_utf8(&resp.body).expect("utf-8 body");
        assert!(body.contains("\"port\":8080"), "body: {body}");
    }

    #[tokio::test]
    async fn admin_stop_sets_flag_and_returns_204() {
        let inner = fresh_inner();
        let (tx, _rx) = channel();
        let resp = dispatch_request(
            req("POST", "/__admin/stop", &[("x-admin-token", "secret")], &[]),
            &tx,
            &inner,
            Policy {
                admin_token: Some("secret"),
                auth_token: None,
            },
        )
        .await;
        assert_eq!(resp.status, 204);
        assert!(resp.body.is_empty());
        assert!(inner.stop.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn auth_required_missing_returns_401() {
        let inner = fresh_inner();
        let (tx, _rx) = channel();
        let resp = dispatch_request(
            req("GET", "/agent/method", &[], &[]),
            &tx,
            &inner,
            Policy {
                admin_token: None,
                auth_token: Some("secret"),
            },
        )
        .await;
        assert_eq!(resp.status, 401);
    }

    #[tokio::test]
    async fn auth_required_wrong_bearer_returns_401() {
        let inner = fresh_inner();
        let (tx, _rx) = channel();
        let resp = dispatch_request(
            req(
                "GET",
                "/agent/method",
                &[("authorization", "Bearer wrong")],
                &[],
            ),
            &tx,
            &inner,
            Policy {
                admin_token: None,
                auth_token: Some("secret"),
            },
        )
        .await;
        assert_eq!(resp.status, 401);
    }

    #[tokio::test]
    async fn auth_required_correct_bearer_pushes_job() {
        let inner = fresh_inner();
        let (tx, rx) = channel();
        // Fake actor: pull one Job and reply with a canned 200.
        let actor = tokio::task::spawn_blocking(move || {
            let job = rx.recv().expect("job");
            let _ = job.resp_tx.send(Response::text(200, "from actor"));
        });
        let resp = dispatch_request(
            req(
                "GET",
                "/agent/method",
                &[("authorization", "Bearer secret")],
                &[],
            ),
            &tx,
            &inner,
            Policy {
                admin_token: None,
                auth_token: Some("secret"),
            },
        )
        .await;
        actor.await.expect("actor task");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"from actor");
    }

    #[tokio::test]
    async fn auth_bearer_lowercase_scheme_accepted() {
        let inner = fresh_inner();
        let (tx, rx) = channel();
        let actor = tokio::task::spawn_blocking(move || {
            let job = rx.recv().expect("job");
            let _ = job.resp_tx.send(Response::text(200, "ok"));
        });
        let resp = dispatch_request(
            req(
                "GET",
                "/agent/method",
                &[("authorization", "bearer secret")],
                &[],
            ),
            &tx,
            &inner,
            Policy {
                admin_token: None,
                auth_token: Some("secret"),
            },
        )
        .await;
        actor.await.expect("actor task");
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn closed_channel_returns_503() {
        let inner = fresh_inner();
        let (tx, rx) = channel();
        drop(rx); // simulate the actor side having stopped
        let resp = dispatch_request(
            req("GET", "/agent/method", &[], &[]),
            &tx,
            &inner,
            Policy::default(),
        )
        .await;
        assert_eq!(resp.status, 503);
        // Body distinguishes Full vs Disconnected so operators can
        // tell saturation from shutdown apart in logs.
        assert!(resp.body.starts_with(b"gateway stopped"));
    }

    #[tokio::test]
    async fn saturated_channel_returns_503_retry() {
        let inner = fresh_inner();
        // Capacity-1 channel: pre-fill it, then dispatch — the
        // second try_send must hit `Full`.
        let (tx, _rx) = mpsc::sync_channel::<Job>(1);
        let (resp_tx, _resp_rx) = oneshot::channel::<Response>();
        tx.try_send(Job {
            request: req("GET", "/x/y", &[], &[]),
            resp_tx,
        })
        .expect("first send fits");
        let resp = dispatch_request(
            req("GET", "/agent/method", &[], &[]),
            &tx,
            &inner,
            Policy::default(),
        )
        .await;
        assert_eq!(resp.status, 503);
        assert!(resp.body.starts_with(b"gateway saturated"));
    }

    #[tokio::test]
    async fn admin_path_with_unknown_method_returns_404() {
        let inner = fresh_inner();
        let (tx, _rx) = channel();
        let resp = dispatch_request(
            req(
                "DELETE",
                "/__admin/whatever",
                &[("x-admin-token", "secret")],
                &[],
            ),
            &tx,
            &inner,
            Policy {
                admin_token: Some("secret"),
                auth_token: None,
            },
        )
        .await;
        assert_eq!(resp.status, 404);
    }
}
