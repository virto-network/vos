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
///
/// `agent_tokens` overrides the global `auth_token` per-agent —
/// requests to `/<agent>/*` where the agent is in the map require
/// the matching token, *instead of* the global one. Agents not in
/// the map fall through to the global gate. Admin/schema/metrics
/// paths are unaffected.
#[derive(Clone, Copy, Default)]
pub(crate) struct Policy<'a> {
    pub admin_token: Option<&'a str>,
    pub auth_token: Option<&'a str>,
    pub agent_tokens: Option<&'a std::collections::HashMap<String, String>>,
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
    let response = dispatch_inner(req, job_tx, inner, policy).await;
    // Record every response — admin shortcuts, auth failures,
    // job-queue rejections, and actor-dispatched results all
    // count toward `vos_gateway_responses_total{status_class}`.
    // `vos_gateway_requests_total` is the narrower
    // dispatched-to-actor counter, bumped inside `drain_jobs`.
    inner.metrics.record_response(response.status);
    response
}

async fn dispatch_inner(
    req: Request,
    job_tx: &mpsc::SyncSender<Job>,
    inner: &Inner,
    policy: Policy<'_>,
) -> Response {
    if let Some(response) = handle_admin(&req, inner, policy.admin_token) {
        return response;
    }
    if let Some(response) = handle_metrics(&req, inner) {
        return response;
    }
    // Per-agent auth overrides the global gate. If the URL is
    // `/<agent>/*` and `agent_tokens` has an entry for that
    // name, the per-agent token replaces the global one for this
    // request. Falls back to the global token otherwise.
    let effective_auth = effective_auth_for(&req, &policy);
    if let Some(response) = check_auth(&req, effective_auth) {
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

/// `GET /__metrics` — Prometheus exposition format. Public, no
/// admin gate (matches Prometheus convention: scrapers don't auth).
/// Connection-side because the render only touches atomics on
/// `Inner` — no `ServiceCtx` round trip required.
fn handle_metrics(req: &Request, inner: &Inner) -> Option<Response> {
    if req.path != "/__metrics" {
        return None;
    }
    if req.method != "GET" {
        return Some(Response::text(405, "/__metrics is GET-only"));
    }
    let body = crate::state::render_prometheus(inner).into_bytes();
    // Prometheus exposition convention. Some scrapers tolerate
    // bare `text/plain` too, but the versioned content-type is
    // the canonical form.
    Some(Response::with_content_type(
        200,
        "text/plain; version=0.0.4",
        body,
    ))
}

/// Pick the auth token to enforce for this request. Inspects
/// `req.path` for the leading `/<agent>/`; if the agent name has
/// an entry in `agent_tokens`, returns that token (per-agent
/// override). Otherwise falls back to the global `auth_token`.
///
/// Paths that don't start with `/<agent>/` (the admin / schema /
/// metrics namespaces, plus the empty path) return `None` here so
/// `check_auth` immediately allows them — those endpoints have
/// their own gating (admin token) or are intentionally public.
fn effective_auth_for<'a>(req: &Request, policy: &Policy<'a>) -> Option<&'a str> {
    // Only `/<agent>/<method>` URLs receive auth checks. The
    // dispatch handler will 400 on missing method later anyway.
    let trimmed = req.path.trim_start_matches('/');
    let agent_name = trimmed.split_once('/').map(|(a, _)| a).unwrap_or(trimmed);
    if agent_name.is_empty() || agent_name.starts_with('_') {
        // `_admin`, `_schema`, `_metrics`, openapi: skip the
        // dispatch-side auth entirely.
        return None;
    }
    if let Some(tokens) = policy.agent_tokens
        && let Some(t) = tokens.get(agent_name)
    {
        return Some(t.as_str());
    }
    policy.auth_token
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
    // `/__schema*` and `/openapi.json` paths short-circuit the
    // agent/method dispatcher. They still consume a job slot
    // (actor-side) because the lookups need `ServiceCtx` to talk
    // to the registry — handle_admin can't be used (it's
    // connection-side, no ctx).
    if let Some(resp) = handle_schema(req, inner, ctx) {
        return resp;
    }
    if let Some(resp) = handle_openapi(req, inner, ctx) {
        return resp;
    }

    let Some((agent, method)) = split_path(&req.path) else {
        return Response::text(400, "expected /<agent>/<method>");
    };

    let target = match resolve(ctx, &agent) {
        Some(id) => id,
        None => return Response::text(404, format!("unknown agent '{agent}'")),
    };

    // Look up (and lazily cache) the actor's schema. With it,
    // `build_msg` can coerce query/JSON values to the handler's
    // declared types AND reject unknown methods / type mismatches
    // up front. Without meta the gateway falls back to today's
    // permissive pass-through: pass whatever the wire produced
    // and let the actor's `from_msg` decide.
    let meta = ensure_meta_cached(ctx, inner, target, &agent);
    let method_meta = meta
        .as_ref()
        .and_then(|m| m.messages.iter().find(|msg| msg.name == method).cloned());

    // Typed-error gate: when the actor's schema is known and the
    // requested method isn't in it, return 404 immediately. The
    // legacy "200 null" path stays for actors that haven't
    // registered meta (older binaries, hash drift).
    if meta.is_some() && method_meta.is_none() {
        return Response::text(404, format!("unknown method '{method}' on agent '{agent}'"));
    }

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

/// Self-documenting schema endpoints. Public — schema is no more
/// sensitive than what the registry already serves over libp2p to
/// any peer node. Returns `None` for unrelated paths so the
/// caller falls through to the agent/method dispatcher.
///
/// - `GET /__schema`           → JSON `["name", ...]` of installed agents
/// - `GET /__schema/<agent>`   → JSON `ActorMeta` of that agent
///
/// Non-GET methods 405; unknown agents 404; agents without
/// registered meta (older binaries, hash mismatch) 404 with
/// "no schema for".
fn handle_schema(req: &Request, inner: &Inner, ctx: &ServiceCtx) -> Option<Response> {
    if !req.path.starts_with("/__schema") {
        return None;
    }
    if req.method != "GET" {
        return Some(Response::text(405, "schema endpoints are GET-only"));
    }
    if req.path == "/__schema" || req.path == "/__schema/" {
        return Some(list_schemas(ctx));
    }
    let name = req
        .path
        .trim_start_matches("/__schema/")
        .trim_end_matches('/');
    if name.is_empty() || name.contains('/') {
        return Some(Response::text(400, "expected /__schema/<agent>"));
    }
    Some(schema_for_agent(name, inner, ctx))
}

fn list_schemas(ctx: &ServiceCtx) -> Response {
    let msg = Msg::new("agent_names");
    let encoded = msg.encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(vos::value::TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    let bytes = match ctx.ask_raw(ServiceId::REGISTRY.0, &payload) {
        Some(b) if !b.is_empty() => b,
        _ => return Response::text(502, "registry unreachable"),
    };
    let value: vos::value::Value = vos::value::Value::decode(&bytes);
    let names = value.as_list_str().map(|s| s.to_vec()).unwrap_or_default();
    Response::json(
        200,
        serde_json::to_vec(&names).unwrap_or_else(|_| b"[]".to_vec()),
    )
}

fn schema_for_agent(name: &str, inner: &Inner, ctx: &ServiceCtx) -> Response {
    let Some(target) = resolve(ctx, name) else {
        return Response::text(404, format!("unknown agent '{name}'"));
    };
    match ensure_meta_cached(ctx, inner, target, name) {
        Some(meta) => Response::json(200, meta_to_json(&meta).into_bytes()),
        None => Response::text(404, format!("no schema for agent '{name}'")),
    }
}

/// Render a `ParsedMeta` as JSON. Mirrors the field names of the
/// in-tree `ActorMeta`/`MessageMeta`/`FieldMeta` structs so a
/// client that's parsed a vos meta binary in a previous life sees
/// the same names — `actor_name`, `messages[i].name`,
/// `messages[i].is_query`, `messages[i].fields[j].name/type`,
/// `constructor[i].name/type`, `kind`, `caps`.
fn meta_to_json(meta: &vos::metadata::ParsedMeta) -> String {
    let messages: Vec<_> = meta
        .messages
        .iter()
        .map(|m| {
            let fields: Vec<_> = m
                .fields
                .iter()
                .map(|f| serde_json::json!({ "name": f.name, "type": f.ty }))
                .collect();
            serde_json::json!({
                "name": m.name,
                "is_query": m.is_query,
                "fields": fields,
            })
        })
        .collect();
    let constructor: Vec<_> = meta
        .constructor
        .iter()
        .map(|f| serde_json::json!({ "name": f.name, "type": f.ty }))
        .collect();
    serde_json::json!({
        "actor_name": meta.actor_name,
        "messages": messages,
        "constructor": constructor,
        "kind": meta.kind,
        "caps": meta.caps,
    })
    .to_string()
}

/// OpenAPI 3.0 document at `GET /openapi.json`. Walks every agent
/// the registry knows about, fetches each one's schema (using the
/// same `ensure_meta_cached` warm path as the dispatcher), and
/// renders one `paths./<agent>/<method>` entry per `#[msg]`. Public,
/// no admin token — same threat model as `/__schema/*`.
///
/// Type mapping for arg shapes mirrors what `coerce_to_type`
/// accepts on the way in (so the documented surface and the
/// reality match):
///   `u8/u16/u32/u64`  → `integer` (`uint8`/`uint16`/`uint32`/`uint64`)
///   `i32/i64`         → `integer` (`int32`/`int64`)
///   `bool`            → `boolean`
///   `String`          → `string`
///   `Vec<u8>`         → `string` (`byte`)
///   `Vec<u32>`        → `array` of integers
///   `Vec<String>`     → `array` of strings
///   any other         → `string` (fallback — generic UI still works)
fn handle_openapi(req: &Request, inner: &Inner, ctx: &ServiceCtx) -> Option<Response> {
    if req.path != "/openapi.json" {
        return None;
    }
    if req.method != "GET" {
        return Some(Response::text(405, "/openapi.json is GET-only"));
    }
    Some(render_openapi(inner, ctx))
}

fn render_openapi(inner: &Inner, ctx: &ServiceCtx) -> Response {
    // 1. Get every installed agent's name.
    let names = {
        let msg = Msg::new("agent_names");
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(vos::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        let Some(bytes) = ctx.ask_raw(ServiceId::REGISTRY.0, &payload) else {
            return Response::text(502, "registry unreachable");
        };
        if bytes.is_empty() {
            Vec::new()
        } else {
            let value: vos::value::Value = vos::value::Value::decode(&bytes);
            value.as_list_str().map(|s| s.to_vec()).unwrap_or_default()
        }
    };

    // 2. For each agent, fetch its schema (cache-warm) and
    //    render the per-method routes.
    let mut paths_obj = serde_json::Map::new();
    for name in &names {
        let Some(target) = resolve(ctx, name) else {
            continue;
        };
        let Some(meta) = ensure_meta_cached(ctx, inner, target, name) else {
            continue;
        };
        for msg in &meta.messages {
            let path_key = format!("/{}/{}", name, msg.name);
            paths_obj.insert(path_key, openapi_operation_for(&meta.actor_name, msg));
        }
    }

    let doc = serde_json::json!({
        "openapi": "3.0.3",
        "info": {
            "title": "VOS gateway",
            "version": "1.0",
            "description": "Auto-generated from installed-agent schemas (see GET /__schema)."
        },
        "paths": paths_obj,
    });

    Response::json(
        200,
        serde_json::to_vec(&doc).unwrap_or_else(|_| b"{}".to_vec()),
    )
}

/// Render one `#[msg]` as an OpenAPI `pathItem` entry. Picks
/// GET for `is_query` handlers (read-only `&self`) with args
/// going into the query string, POST for everything else with
/// args going into a JSON body. Both shapes match what the
/// gateway actually dispatches via `build_msg`.
fn openapi_operation_for(
    actor_name: &str,
    msg: &vos::metadata::ParsedMessage,
) -> serde_json::Value {
    let http_method = if msg.is_query { "get" } else { "post" };
    let summary = format!("{actor_name}::{}", msg.name);
    let operation_id = format!("{actor_name}_{}", msg.name);

    if msg.is_query {
        let parameters: Vec<_> = msg
            .fields
            .iter()
            .map(|f| {
                serde_json::json!({
                    "name": f.name,
                    "in": "query",
                    "required": true,
                    "schema": vos_ty_to_openapi(&f.ty),
                })
            })
            .collect();
        serde_json::json!({
            http_method: {
                "summary": summary,
                "operationId": operation_id,
                "parameters": parameters,
                "responses": { "200": { "description": "JSON-encoded return value" } }
            }
        })
    } else {
        let mut properties = serde_json::Map::new();
        let mut required = Vec::new();
        for f in &msg.fields {
            properties.insert(f.name.clone(), vos_ty_to_openapi(&f.ty));
            required.push(f.name.clone());
        }
        serde_json::json!({
            http_method: {
                "summary": summary,
                "operationId": operation_id,
                "requestBody": {
                    "required": !msg.fields.is_empty(),
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": properties,
                                "required": required,
                            }
                        }
                    }
                },
                "responses": { "200": { "description": "JSON-encoded return value" } }
            }
        })
    }
}

/// Map a vos type-string to an OpenAPI 3 schema. Mirrors the
/// types `coerce_to_type` recognises; unknown types fall
/// through to `{ "type": "string" }` so the operation is
/// still inspectable, just less precisely typed than ideal.
fn vos_ty_to_openapi(ty: &str) -> serde_json::Value {
    match ty {
        "u8" => serde_json::json!({ "type": "integer", "format": "uint8" }),
        "u16" => serde_json::json!({ "type": "integer", "format": "uint16" }),
        "u32" => serde_json::json!({ "type": "integer", "format": "uint32" }),
        "u64" => serde_json::json!({ "type": "integer", "format": "uint64" }),
        "i32" => serde_json::json!({ "type": "integer", "format": "int32" }),
        "i64" => serde_json::json!({ "type": "integer", "format": "int64" }),
        "bool" => serde_json::json!({ "type": "boolean" }),
        "String" => serde_json::json!({ "type": "string" }),
        "Vec<u8>" => serde_json::json!({ "type": "string", "format": "byte" }),
        "Vec<u32>" => serde_json::json!({
            "type": "array",
            "items": { "type": "integer", "format": "uint32" }
        }),
        "Vec<String>" => serde_json::json!({
            "type": "array",
            "items": { "type": "string" }
        }),
        _ => serde_json::json!({ "type": "string" }),
    }
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
    let mut seen_keys: Vec<String> = Vec::new();
    // Pulls the typed result from `coerce_to_type` when the
    // schema is known and a field declaration matches; signals
    // a failed parse via `Err(Response)` so build_msg can 400
    // instead of silently passing through a wrong-typed value.
    // When schema is unknown OR the field isn't in the
    // declared list (typo, gateway-injected key), the original
    // value passes through — preserves today's permissive
    // pre-schema behaviour for that codepath.
    let coerce = |key: &str, v: Value| -> Result<Value, Response> {
        let Some(meta) = method_meta else {
            return Ok(v);
        };
        let Some(field) = meta.fields.iter().find(|f| f.name == key) else {
            return Ok(v);
        };
        match coerce_to_type(v, &field.ty) {
            Some(coerced) => Ok(coerced),
            None => Err(Response::text(
                400,
                format!("arg '{}' expects type '{}'", key, field.ty),
            )),
        }
    };
    match req.method.as_str() {
        "GET" => {
            // Query args arrive as `Value::Str` (no JSON typing
            // in a query string). With schema knowledge we can
            // parse them into the declared type — `?n=5` becomes
            // `Value::U64(5)` when the handler signature is u64.
            for (k, v) in parse_query(&req.query) {
                let typed = coerce(&k, Value::Str(v))?;
                seen_keys.push(k.clone());
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
                    let typed = coerce(&k, v)?;
                    seen_keys.push(k.clone());
                    msg = msg.with(k, typed);
                }
            }
        }
        other => return Err(Response::text(405, format!("method {other} not allowed"))),
    }
    // Schema-aware missing-arg check. Every field the handler
    // declares must show up in the parsed args — otherwise the
    // actor's `from_msg` would silently return None and the
    // request would round-trip to a 502. Surface as 400 with
    // the missing field name so clients can fix their request.
    // Skipped when no schema is registered (legacy permissive
    // path): without meta the gateway has no way to know what
    // "required" means.
    if let Some(meta) = method_meta {
        for field in &meta.fields {
            if !seen_keys.iter().any(|k| k.as_str() == field.name) {
                return Err(Response::text(
                    400,
                    format!("missing required arg '{}'", field.name),
                ));
            }
        }
    }
    Ok(msg)
}

/// Coerce a `Value` into the variant matching a Rust type string
/// from `ParsedMeta::messages[i].fields[j].ty`. Returns `Some(v)`
/// on a successful coercion to the target type, `None` when the
/// value can't fit. The caller surfaces `None` as a 400 type-
/// mismatch when schema is known. Bool/string/bytes pass through
/// when the input variant already matches — there's no narrowing
/// to do for those.
fn coerce_to_type(v: vos::value::Value, ty: &str) -> Option<vos::value::Value> {
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
            .or_else(|| v.as_u8().map(Value::U8)),
        "u16" => as_str
            .and_then(|s| s.parse::<u16>().ok())
            .map(Value::U16)
            .or_else(|| v.as_u16().map(Value::U16)),
        "u32" => as_str
            .and_then(|s| s.parse::<u32>().ok())
            .map(Value::U32)
            .or_else(|| v.as_u32().map(Value::U32)),
        "u64" => as_str
            .and_then(|s| s.parse::<u64>().ok())
            .map(Value::U64)
            .or_else(|| v.as_u64().map(Value::U64)),
        "i32" => as_str
            .and_then(|s| s.parse::<i32>().ok())
            .map(Value::I32)
            .or_else(|| v.as_i32().map(Value::I32)),
        "i64" => as_str
            .and_then(|s| s.parse::<i64>().ok())
            .map(Value::I64)
            .or_else(|| v.as_i64().map(Value::I64)),
        "bool" => as_str
            .and_then(|s| s.parse::<bool>().ok())
            .map(Value::Bool)
            .or_else(|| v.as_bool().map(Value::Bool)),
        "String" => match v {
            Value::Str(_) => Some(v),
            _ => None,
        },
        // Complex types we don't coerce — pass the original
        // through unchanged so the actor's `from_msg` accessor
        // gets a chance to evaluate the shape. Returning
        // `Some(v)` here keeps the 400-on-failure check
        // restricted to scalars the gateway is confident about.
        _ => Some(v),
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
    // Fast path: cache hit + entry is still fresh. TTL covers the
    // `vosx space upgrade` case where the registry now has a
    // different schema but the gateway has no event-driven signal
    // to invalidate. Bounded staleness rather than per-request
    // revalidation.
    {
        let cache = inner.meta_cache.lock().unwrap();
        if let Some(entry) = cache.get(&target.0)
            && entry.fetched_at.elapsed() < crate::state::META_CACHE_TTL
        {
            return entry.meta.clone();
        }
    }
    // Cache miss / stale — ask the registry. We forward the name;
    // the registry does the agent → program_hash → meta join.
    // Empty reply means "no meta registered" → store `None` so we
    // don't retry on every request inside this TTL window.
    let parsed = fetch_meta_from_registry(ctx, name);
    let mut cache = inner.meta_cache.lock().unwrap();
    cache.insert(
        target.0,
        crate::state::MetaEntry {
            meta: parsed.clone(),
            fetched_at: std::time::Instant::now(),
        },
    );
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

    #[test]
    fn meta_cache_entry_past_ttl_is_considered_stale() {
        // Hand-seed a cache entry with `fetched_at` set just past
        // the TTL boundary, then confirm the staleness check the
        // dispatcher uses on the fast path returns false. Catches
        // accidental `<=` / `>=` flips or a TTL constant typo.
        use crate::state::{META_CACHE_TTL, MetaEntry};
        use std::time::Instant;

        let inner = fresh_inner();
        let target_id = 7u32;
        let fresh = Instant::now();
        let stale = fresh
            .checked_sub(META_CACHE_TTL + std::time::Duration::from_millis(1))
            .expect("subtract TTL");

        // Fresh entry: well within TTL.
        {
            let mut cache = inner.meta_cache.lock().unwrap();
            cache.insert(
                target_id,
                MetaEntry {
                    meta: None,
                    fetched_at: fresh,
                },
            );
        }
        let cache = inner.meta_cache.lock().unwrap();
        let entry = cache.get(&target_id).expect("entry");
        assert!(
            entry.fetched_at.elapsed() < META_CACHE_TTL,
            "freshly-inserted entry must read as in-TTL",
        );
        drop(cache);

        // Stale entry: past TTL by 1ms.
        {
            let mut cache = inner.meta_cache.lock().unwrap();
            cache.insert(
                target_id,
                MetaEntry {
                    meta: None,
                    fetched_at: stale,
                },
            );
        }
        let cache = inner.meta_cache.lock().unwrap();
        let entry = cache.get(&target_id).expect("entry");
        assert!(
            entry.fetched_at.elapsed() >= META_CACHE_TTL,
            "entry set 1ms past TTL must read as expired",
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
            metrics: crate::state::Metrics::default(),
            agent_tokens: std::collections::HashMap::new(),
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
                agent_tokens: None,
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
                agent_tokens: None,
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
                agent_tokens: None,
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
                agent_tokens: None,
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
                agent_tokens: None,
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
                agent_tokens: None,
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
                agent_tokens: None,
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
                agent_tokens: None,
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
                agent_tokens: None,
            },
        )
        .await;
        assert_eq!(resp.status, 404);
    }

    // ── Per-agent Bearer auth ─────────────────────────────────────
    //
    // Validates the `agent_tokens` override against the global
    // `auth_token` and the public namespaces.

    fn agent_tokens_for(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[tokio::test]
    async fn per_agent_token_requires_match_for_that_agent() {
        let inner = fresh_inner();
        let (tx, rx) = channel();
        let actor = tokio::task::spawn_blocking(move || {
            // Drain whatever job arrives — test only cares about
            // the auth path, not what the actor returns.
            if let Ok(job) = rx.recv() {
                let _ = job.resp_tx.send(Response::text(200, "ok"));
            }
        });
        let tokens = agent_tokens_for(&[("secret-agent", "agent-only-token")]);
        let resp = dispatch_request(
            req(
                "GET",
                "/secret-agent/whoami",
                &[("authorization", "Bearer agent-only-token")],
                &[],
            ),
            &tx,
            &inner,
            Policy {
                admin_token: None,
                auth_token: None,
                agent_tokens: Some(&tokens),
            },
        )
        .await;
        actor.await.expect("actor task");
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn per_agent_token_rejects_wrong_bearer() {
        let inner = fresh_inner();
        let (tx, _rx) = channel();
        let tokens = agent_tokens_for(&[("secret-agent", "agent-only-token")]);
        let resp = dispatch_request(
            req(
                "GET",
                "/secret-agent/whoami",
                &[("authorization", "Bearer wrong")],
                &[],
            ),
            &tx,
            &inner,
            Policy {
                admin_token: None,
                auth_token: None,
                agent_tokens: Some(&tokens),
            },
        )
        .await;
        assert_eq!(resp.status, 401);
    }

    #[tokio::test]
    async fn per_agent_token_overrides_global_for_that_agent() {
        // Global gate is `global-token`; the per-agent override
        // for `special` is `agent-token`. Hitting `/special/...`
        // with the global token must 401 — the agent token is the
        // only one that opens this agent.
        let inner = fresh_inner();
        let (tx, _rx) = channel();
        let tokens = agent_tokens_for(&[("special", "agent-token")]);
        let resp = dispatch_request(
            req(
                "GET",
                "/special/foo",
                &[("authorization", "Bearer global-token")],
                &[],
            ),
            &tx,
            &inner,
            Policy {
                admin_token: None,
                auth_token: Some("global-token"),
                agent_tokens: Some(&tokens),
            },
        )
        .await;
        assert_eq!(resp.status, 401);
    }

    #[tokio::test]
    async fn per_agent_falls_back_to_global_for_other_agents() {
        // Only `special` is in the per-agent map. `regular` hits
        // the global gate; the global token works.
        let inner = fresh_inner();
        let (tx, rx) = channel();
        let actor = tokio::task::spawn_blocking(move || {
            if let Ok(job) = rx.recv() {
                let _ = job.resp_tx.send(Response::text(200, "ok"));
            }
        });
        let tokens = agent_tokens_for(&[("special", "agent-token")]);
        let resp = dispatch_request(
            req(
                "GET",
                "/regular/foo",
                &[("authorization", "Bearer global-token")],
                &[],
            ),
            &tx,
            &inner,
            Policy {
                admin_token: None,
                auth_token: Some("global-token"),
                agent_tokens: Some(&tokens),
            },
        )
        .await;
        actor.await.expect("actor task");
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn metrics_endpoint_ignores_per_agent_tokens() {
        // `/__metrics`, `/__schema`, `/openapi.json` are public —
        // a per-agent gate shouldn't accidentally cover them.
        let inner = fresh_inner();
        let (tx, _rx) = channel();
        let tokens = agent_tokens_for(&[("anything", "agent-token")]);
        let resp = dispatch_request(
            req("GET", "/__metrics", &[], &[]),
            &tx,
            &inner,
            Policy {
                admin_token: None,
                auth_token: Some("global-token"),
                agent_tokens: Some(&tokens),
            },
        )
        .await;
        assert_eq!(resp.status, 200);
    }
}
