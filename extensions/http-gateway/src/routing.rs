//! Request routing (transport mode).
//!
//! A connection task ([`crate::HttpGateway::handle_connection`]) parses
//! one HTTP/1.1 request off the byte stream and calls [`dispatch`], which
//! runs the built-in intercepts + the bearer-auth gate and then hands
//! `/<agent>/<method>` traffic to [`handle`]. Both layers run **in the
//! same connection task**; the actor `Context<HttpGateway>` reaches the registry and
//! target agents (via the async [`Context::ask_dispatch`]), and many
//! connection tasks interleave on the host's one cooperative executor.
//!
//! ## Built-in routes (precedence + auth)
//!
//! | # | path                        | method | ask?     | auth          |
//! |---|-----------------------------|--------|----------|---------------|
//! | 1 | `/__metrics`                | GET    | no       | public        |
//! | 2 | `/__status`                 | GET    | no       | public        |
//! | 3 | `/__schema`, `/__schema/<a>`| GET    | registry | public        |
//! | 4 | `/openapi.json`             | GET    | registry | public        |
//! | 5 | `/<agent>/<method>`         | any    | agent    | varies†       |
//!
//! † `/<agent>/<method>` uses the global `auth_token` unless the
//! manifest declared a per-agent override in `agent_tokens`.
//! Schema / metrics / status are unaffected by either token.
//!
//! `/__metrics` + `/__status` read only `Inner` atomics, so they're
//! answered ahead of the auth gate (and never `ask`). `/__schema*` /
//! `/openapi.json` are public-by-name ([`PUBLIC_NAMESPACES`]) but DO
//! `ask` the registry, so they ride the same async path as dispatch.
//!
//! Adding a built-in: append a row here AND insert the `handle_*`
//! call in either [`dispatch`] (ask-free, pre-auth) or [`handle`]
//! (registry/agent asks) in the matching precedence slot.
//!
//! ## Lifecycle: `stop` / `describe`
//!
//! In transport mode the **host** owns lifecycle: `vosx gateway stop` and
//! `vosx gateway describe` are intercepted node-side as the generic
//! `__stop` / `__describe` primitives (see `vos::node`), uniform across
//! every agent kind. Rich live status stays in the gateway as the
//! in-process `GET /__status` endpoint (no invoke round trip).

use http::Method;
use vos::Context;
use vos::Encode;
use vos::actors::context::ServiceId;
use vos::actors::value::Msg;
use vos::log;

use crate::HttpGateway;
use crate::config::ct_eq;
use crate::json::{parse_flat_json, value_to_json};
use crate::state::Inner;
use crate::types::{Request, Response, json, text, with_content_type};

/// Per-request auth policy threaded through the wire path. The
/// connection-side glue reads these from [`crate::config`] once and
/// passes them through; tests construct policies directly to exercise
/// each combination without touching the global singleton.
///
/// `agent_tokens` overrides the global `auth_token` per-agent —
/// requests to `/<agent>/*` where the agent is in the map require
/// the matching token, *instead of* the global one. Agents not in
/// the map fall through to the global gate. Schema and metrics
/// paths are unaffected.
#[derive(Clone, Copy, Default)]
pub(crate) struct Policy<'a> {
    pub auth_token: Option<&'a str>,
    pub agent_tokens: Option<&'a std::collections::HashMap<String, String>>,
}

/// Per-request entry point, called from a connection task with the
/// parsed [`Request`] + the actor [`Context`]. Runs the ask-free public
/// intercepts (`/__metrics`, `/__status`), the bearer-auth gate, then
/// hands everything else to [`handle`] (registry + agent asks). The
/// caller records the response status into `Inner::metrics`.
pub(crate) async fn dispatch(
    req: &Request,
    inner: &Inner,
    ctx: &mut Context<HttpGateway>,
    policy: Policy<'_>,
) -> Response {
    // A config error (today: malformed `agent_tokens`) means we'd be
    // serving with weakened auth — refuse every request instead. In
    // transport mode `new()` can't decline to boot (the host owns the
    // listener), so the refusal lives here.
    if let Some(reason) = &inner.config_error {
        log::error!("http-gateway: refusing request — config error: {reason}");
        return text(503, "gateway misconfigured");
    }
    // Ask-free public endpoints answer ahead of the auth gate.
    if let Some(response) = handle_metrics(req, inner) {
        return response;
    }
    if let Some(response) = handle_status(req, inner) {
        return response;
    }
    // Per-agent auth overrides the global gate. If the URL is
    // `/<agent>/*` and `agent_tokens` has an entry for that name, the
    // per-agent token replaces the global one. Falls back to the
    // global token otherwise.
    let effective_auth = effective_auth_for(req, &policy);
    if let Some(response) = check_auth(req, effective_auth) {
        return response;
    }
    // Past the gates: this counts as a dispatched request and bumps
    // `vos_gateway_requests_total` once (schema / openapi / agent dispatch
    // alike; `/__metrics` + `/__status` short-circuit above and don't count).
    inner.requests.set(inner.requests.get() + 1);
    handle(req, inner, ctx).await
}

/// `GET /__status` — compact JSON liveness snapshot (port, running,
/// request count, uptime). Reads only `Inner` atomics, so
/// it needs no registry round trip and works regardless of upstream
/// reachability. Public (no token), like `/__metrics`.
fn handle_status(req: &Request, inner: &Inner) -> Option<Response> {
    if req.uri().path() != "/__status" {
        return None;
    }
    if req.method() != Method::GET {
        return Some(text(405, "/__status is GET-only"));
    }
    Some(json(200, crate::state::status_json(inner).into_bytes()))
}

/// `GET /__metrics` — Prometheus exposition format. Public, no
/// admin gate (matches Prometheus convention: scrapers don't auth).
/// Connection-side because the render only touches atomics on
/// `Inner` — no round trip required.
fn handle_metrics(req: &Request, inner: &Inner) -> Option<Response> {
    if req.uri().path() != "/__metrics" {
        return None;
    }
    if req.method() != Method::GET {
        return Some(text(405, "/__metrics is GET-only"));
    }
    let body = crate::state::render_prometheus(inner).into_bytes();
    // Prometheus exposition convention. Some scrapers tolerate
    // bare `text/plain` too, but the versioned content-type is
    // the canonical form.
    Some(with_content_type(200, "text/plain; version=0.0.4", body))
}

/// Public-namespace paths that skip the dispatch auth gate
/// regardless of token config. Schema / metrics / openapi are
/// intentionally readable by anyone reachable on the bound port
/// — they describe what the gateway is, not anything sensitive.
/// Centralized here so the `effective_auth_for` predicate doesn't
/// rely on a fragile `agent_name.starts_with('_')` heuristic that
/// silently auth-gated `/openapi.json` (which has no underscore).
const PUBLIC_NAMESPACES: &[&str] = &["__schema", "__metrics", "openapi.json"];

/// Pick the auth token to enforce for this request. Inspects
/// the URI path for the leading `/<agent>/`; if the agent name has
/// an entry in `agent_tokens`, returns that token (per-agent
/// override). Otherwise falls back to the global `auth_token`.
///
/// Paths that map to a public namespace ([`PUBLIC_NAMESPACES`])
/// or to the empty path return `None` here so `check_auth`
/// allows them through — those endpoints are intentionally
/// readable without a token.
fn effective_auth_for<'a>(req: &Request, policy: &Policy<'a>) -> Option<&'a str> {
    // Only `/<agent>/<method>` URLs receive auth checks. The
    // dispatch handler will 400 on missing method later anyway.
    let trimmed = req.uri().path().trim_start_matches('/');
    let agent_name = trimmed.split_once('/').map(|(a, _)| a).unwrap_or(trimmed);
    if agent_name.is_empty() || PUBLIC_NAMESPACES.contains(&agent_name) {
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
    let provided = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        });
    if provided.is_some_and(|t| ct_eq(t.trim(), expected)) {
        None
    } else {
        Some(text(401, "unauthorized"))
    }
}

/// Resolve `/<agent>/<method>` (and the `/__schema*` / `/openapi.json`
/// registry-backed endpoints) by asking the registry + target agent
/// through the async [`Context::ask_dispatch`]. Many connection tasks
/// run this concurrently on the host's one cooperative executor —
/// `&self` shared, all mutable runtime state behind `Inner`'s atomics /
/// `Mutex`.
async fn handle(req: &Request, inner: &Inner, ctx: &mut Context<HttpGateway>) -> Response {
    // `/__schema*` and `/openapi.json` short-circuit the agent/method
    // dispatcher. They `ask` the registry for schema, so they live here
    // (not in `dispatch`'s ask-free pre-auth shortcut).
    if let Some(resp) = handle_schema(req, inner, ctx).await {
        return resp;
    }
    if let Some(resp) = handle_openapi(req, inner, ctx).await {
        return resp;
    }

    let Some((agent, method)) = split_path(req.uri().path()) else {
        return text(400, "expected /<agent>/<method>");
    };

    // Reserve the gateway's own namespaces. The exact built-in paths
    // (`/__metrics`, `/__status`, `/__schema*`, `/openapi.json`) were handled
    // above; a *sub-path* like `/__metrics/foo` falls through to here and would
    // otherwise dispatch to an agent literally named `__metrics` — which
    // `effective_auth_for` classifies as a public namespace, so it would reach
    // that agent with NO token. Refuse dispatch to any `__`-prefixed name (or a
    // public namespace) so a reserved-named agent can't be reached — let alone
    // unauthenticated — through the gateway.
    if agent.starts_with("__") || PUBLIC_NAMESPACES.contains(&agent.as_str()) {
        return text(404, format!("'{agent}' is a reserved gateway namespace"));
    }

    let target = match resolve(ctx, &agent).await {
        Some(id) => id,
        None => return text(404, format!("unknown agent '{agent}'")),
    };

    // Look up (and lazily cache) the actor's schema. With it,
    // `build_msg` can coerce query/JSON values to the handler's
    // declared types AND reject unknown methods / type mismatches
    // up front. Without meta the gateway falls back to today's
    // permissive pass-through: pass whatever the wire produced
    // and let the actor's `from_msg` decide.
    let meta = ensure_meta_cached(ctx, inner, target, &agent).await;
    let method_meta = meta
        .as_ref()
        .and_then(|m| m.messages.iter().find(|msg| msg.name == method).cloned());

    // Typed-error gate: when the actor's schema is known and the
    // requested method isn't in it, return 404 immediately. The
    // permissive "200 null" fallback stays for actors that haven't
    // registered meta (older binaries, hash drift).
    if meta.is_some() && method_meta.is_none() {
        return text(404, format!("unknown method '{method}' on agent '{agent}'"));
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

    // `ask_dispatch` is status-framed (unlike the collapsing `ask_raw`):
    // `Some(empty)` is a real `()` return → `200 null`; `None` is a
    // dispatch failure (panic / non-DONE status / no route / timeout) →
    // `502`. This is what preserves the panic→502 distinction in
    // transport mode.
    let ret_ty = method_meta.as_ref().map(|m| m.returns.as_str());
    match ctx.ask_dispatch(target, &payload).await {
        Some(reply_bytes) if reply_bytes.is_empty() => {
            // Handler returned `()` successfully → JSON null.
            json(200, value_to_json(&vos::value::Value::Unit))
        }
        Some(reply_bytes) => {
            // try_decode runs rkyv's checked access — handles
            // arbitrary alignment + validates the buffer. decode
            // would unsafely access_unchecked, panicking on
            // misaligned slices that came back through the invoke
            // envelope unwrap.
            match <vos::value::Value as vos::Decode>::try_decode(&reply_bytes) {
                Some(value) => label_return(json(200, value_to_json(&value)), ret_ty),
                None => text(502, "upstream returned malformed reply"),
            }
        }
        None => text(502, "upstream error or shutdown"),
    }
}

/// Attach the schema's declared return type as an `x-vos-return-type`
/// response header. A `Value::Bytes` reply renders as an opaque hex
/// string in the JSON body (JSON has no blob type); the header tells a
/// client whether those bytes are a `[u8;32]` root, a `Vec<u8>` proof,
/// or a custom struct. No-op for unit / unknown return types.
fn label_return(mut resp: Response, ret_ty: Option<&str>) -> Response {
    if let Some(ty) = ret_ty
        && !ty.is_empty()
        && ty != "()"
        && let Ok(value) = http::HeaderValue::from_str(ty)
    {
        resp.headers_mut().insert("x-vos-return-type", value);
    }
    resp
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
async fn handle_schema(
    req: &Request,
    inner: &Inner,
    ctx: &mut Context<HttpGateway>,
) -> Option<Response> {
    let path = req.uri().path();
    if !path.starts_with("/__schema") {
        return None;
    }
    if req.method() != Method::GET {
        return Some(text(405, "schema endpoints are GET-only"));
    }
    if path == "/__schema" || path == "/__schema/" {
        return Some(list_schemas(ctx).await);
    }
    let name = path.trim_start_matches("/__schema/").trim_end_matches('/');
    if name.is_empty() || name.contains('/') {
        return Some(text(400, "expected /__schema/<agent>"));
    }
    Some(schema_for_agent(name, inner, ctx).await)
}

async fn list_schemas(ctx: &mut Context<HttpGateway>) -> Response {
    let msg = Msg::new("agent_names");
    let encoded = msg.encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(vos::value::TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    let bytes = match ctx.ask_dispatch(ServiceId::REGISTRY, &payload).await {
        Some(b) if !b.is_empty() => b,
        _ => return text(502, "registry unreachable"),
    };
    // try_decode (checked rkyv access) — a malformed/misaligned registry reply
    // degrades to an empty list rather than panicking the connection task.
    let names = match <vos::value::Value as vos::Decode>::try_decode(&bytes) {
        Some(value) => value.as_list_str().map(|s| s.to_vec()).unwrap_or_default(),
        None => Vec::new(),
    };
    json(
        200,
        serde_json::to_vec(&names).unwrap_or_else(|_| b"[]".to_vec()),
    )
}

async fn schema_for_agent(name: &str, inner: &Inner, ctx: &mut Context<HttpGateway>) -> Response {
    let Some(target) = resolve(ctx, name).await else {
        return text(404, format!("unknown agent '{name}'"));
    };
    match ensure_meta_cached(ctx, inner, target, name).await {
        Some(meta) => json(200, meta_to_json(&meta).into_bytes()),
        None => text(404, format!("no schema for agent '{name}'")),
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
async fn handle_openapi(
    req: &Request,
    inner: &Inner,
    ctx: &mut Context<HttpGateway>,
) -> Option<Response> {
    if req.uri().path() != "/openapi.json" {
        return None;
    }
    if req.method() != Method::GET {
        return Some(text(405, "/openapi.json is GET-only"));
    }
    Some(render_openapi(inner, ctx).await)
}

async fn render_openapi(inner: &Inner, ctx: &mut Context<HttpGateway>) -> Response {
    // 1. Get every installed agent's name.
    let names = {
        let msg = Msg::new("agent_names");
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(vos::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        let Some(bytes) = ctx.ask_dispatch(ServiceId::REGISTRY, &payload).await else {
            return text(502, "registry unreachable");
        };
        if bytes.is_empty() {
            Vec::new()
        } else {
            match <vos::value::Value as vos::Decode>::try_decode(&bytes) {
                Some(value) => value.as_list_str().map(|s| s.to_vec()).unwrap_or_default(),
                None => Vec::new(),
            }
        }
    };

    // 2. For each agent, fetch its schema (cache-warm) and
    //    render the per-method routes.
    let mut paths_obj = serde_json::Map::new();
    for name in &names {
        let Some(target) = resolve(ctx, name).await else {
            continue;
        };
        let Some(meta) = ensure_meta_cached(ctx, inner, target, name).await else {
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

    json(
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
    // Label the response with the declared return type when the schema
    // carries one; a `Value::Bytes` reply (custom struct / [u8;N] /
    // Vec<u8>) renders as a hex string, and this is where the type name
    // that disambiguates it is documented (mirrors the live
    // `x-vos-return-type` header).
    let response_desc = match msg.returns.as_str() {
        "" | "()" => "JSON-encoded return value".to_string(),
        ty => format!("JSON-encoded return value (type: {ty})"),
    };

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
                "responses": { "200": { "description": response_desc } }
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
                "responses": { "200": { "description": response_desc } }
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
/// `ctx.id()`).
async fn resolve(ctx: &mut Context<HttpGateway>, name: &str) -> Option<ServiceId> {
    let caller_prefix = (ctx.id().0 >> 16) as u64;
    let msg = Msg::new("resolve")
        .with("name", name.to_string())
        .with("caller_prefix", caller_prefix);
    let encoded = msg.encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(vos::value::TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    let bytes = ctx.ask_dispatch(ServiceId::REGISTRY, &payload).await?;
    if bytes.is_empty() {
        return None;
    }
    let value = <vos::value::Value as vos::Decode>::try_decode(&bytes)?;
    let id = value.as_u32().unwrap_or(0);
    (id != 0).then_some(ServiceId(id))
}

// The Err variant is the terminal 400 response, built once on the
// cold rejection path — not worth boxing every call site for.
#[allow(clippy::result_large_err)]
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
            None => Err(text(
                400,
                format!("arg '{}' expects type '{}'", key, field.ty),
            )),
        }
    };
    match req.method().as_str() {
        "GET" => {
            // Query args arrive as `Value::Str` (no JSON typing
            // in a query string). With schema knowledge we can
            // parse them into the declared type — `?n=5` becomes
            // `Value::U64(5)` when the handler signature is u64.
            for (k, v) in parse_query(req.uri().query().unwrap_or("")) {
                let typed = coerce(&k, Value::Str(v))?;
                seen_keys.push(k.clone());
                msg = msg.with(k, typed);
            }
        }
        "POST" | "PUT" | "PATCH" => {
            if !req.body().is_empty() {
                let pairs = parse_flat_json(req.body()).map_err(|e| {
                    // Detail (line/column, offending token) goes to logs;
                    // clients see a generic 400 so server internals don't
                    // leak via crafted-input probing.
                    log::debug!("http-gateway: invalid JSON body: {e}");
                    text(400, "invalid JSON body")
                })?;
                for (k, v) in pairs {
                    let typed = coerce(&k, v)?;
                    seen_keys.push(k.clone());
                    msg = msg.with(k, typed);
                }
            }
        }
        other => return Err(text(405, format!("method {other} not allowed"))),
    }
    // Schema-aware missing-arg check. Every field the handler
    // declares must show up in the parsed args — otherwise the
    // actor's `from_msg` would silently return None and the
    // request would round-trip to a 502. Surface as 400 with
    // the missing field name so clients can fix their request.
    // Skipped when no schema is registered (the pre-schema
    // permissive fallback): without meta the gateway has no way to know what
    // "required" means.
    if let Some(meta) = method_meta {
        for field in &meta.fields {
            if !seen_keys.iter().any(|k| k.as_str() == field.name) {
                return Err(text(400, format!("missing required arg '{}'", field.name)));
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
    // The schema renders field types pretty-printed with spaces
    // (e.g. `Vec < u8 >`); strip whitespace so the arms below can use
    // the canonical spelling.
    let ty: String = ty.chars().filter(|c| !c.is_whitespace()).collect();
    match ty.as_str() {
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
        // `Vec<u8>` handler args need `Value::Bytes`, which the JSON
        // layer never produces directly. Accept either a hex string
        // (symmetric with how `Bytes` replies render — copy a hex
        // value out of a reply and pass it straight back) or a JSON
        // array of byte-valued numbers; pass an existing `Bytes`
        // through. Without this, every `Vec<u8>`-arg handler (clerk's
        // bootstrap / create_account / apply_transfer / account(id) /
        // …) silently fails the actor's `from_dynamic` and round-trips
        // to a misleading "200 null".
        "Vec<u8>" => {
            if let Some(s) = as_str {
                crate::json::hex_decode(s).map(Value::Bytes)
            } else if let Value::ListU32(ref nums) = v {
                nums.iter()
                    .map(|&n| u8::try_from(n).ok())
                    .collect::<Option<Vec<u8>>>()
                    .map(Value::Bytes)
            } else {
                v.as_bytes().map(|b| Value::Bytes(b.to_vec()))
            }
        }
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
async fn ensure_meta_cached(
    ctx: &mut Context<HttpGateway>,
    inner: &Inner,
    target: ServiceId,
    name: &str,
) -> Option<vos::metadata::ParsedMeta> {
    // Fast path: cache hit + entry is still fresh. TTL covers the
    // `vosx space upgrade` case where the registry now has a
    // different schema but the gateway has no event-driven signal
    // to invalidate. Bounded staleness rather than per-request
    // revalidation. The `RefCell` borrow is dropped before the registry
    // `ask` below (never held across an `.await` — the single-threaded
    // executor would panic on a concurrent borrow).
    {
        let cache = inner.meta_cache.borrow();
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
    let parsed = fetch_meta_from_registry(ctx, name).await;
    let mut cache = inner.meta_cache.borrow_mut();
    cache.insert(
        target.0,
        crate::state::MetaEntry {
            meta: parsed.clone(),
            fetched_at: std::time::Instant::now(),
        },
    );
    parsed
}

async fn fetch_meta_from_registry(
    ctx: &mut Context<HttpGateway>,
    name: &str,
) -> Option<vos::metadata::ParsedMeta> {
    let msg = Msg::new("meta_for_instance").with("name", name.to_string());
    let encoded = msg.encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(vos::value::TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    let bytes = ctx.ask_dispatch(ServiceId::REGISTRY, &payload).await?;
    if bytes.is_empty() {
        return None;
    }
    // The reply is a `Value::Bytes(...)` carrying the raw
    // `.vos_meta` section. Empty bytes means the registry didn't
    // find a meta entry (old binary, hash mismatch). `decode`
    // returns None on a malformed/empty section too.
    let value = <vos::value::Value as vos::Decode>::try_decode(&bytes)?;
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
            let mut cache = inner.meta_cache.borrow_mut();
            cache.insert(
                target_id,
                MetaEntry {
                    meta: None,
                    fetched_at: fresh,
                },
            );
        }
        {
            let cache = inner.meta_cache.borrow();
            let entry = cache.get(&target_id).expect("entry");
            assert!(
                entry.fetched_at.elapsed() < META_CACHE_TTL,
                "freshly-inserted entry must read as in-TTL",
            );
        }

        // Stale entry: past TTL by 1ms.
        {
            let mut cache = inner.meta_cache.borrow_mut();
            cache.insert(
                target_id,
                MetaEntry {
                    meta: None,
                    fetched_at: stale,
                },
            );
        }
        let cache = inner.meta_cache.borrow();
        let entry = cache.get(&target_id).expect("entry");
        assert!(
            entry.fetched_at.elapsed() >= META_CACHE_TTL,
            "entry set 1ms past TTL must read as expired",
        );
    }

    // ── Auth-gate tests ───────────────────────────────────────────
    //
    // The connection-side gate is two pure functions: `effective_auth_for`
    // (which token, if any, applies to this URL) + `check_auth` (does the
    // request carry it). These are tested directly as pure functions.
    // End-to-end dispatch (registry resolve → `ctx.ask` →
    // reply) is covered by `dispatch_e2e` + `gateway_pvm_e2e` against a
    // real VosNode; the parser is covered by `crate::http1`'s unit tests.

    use std::cell::{Cell, RefCell};

    fn fresh_inner() -> Inner {
        Inner {
            bound_port: 8080,
            started_unix: 1_700_000_000,
            requests: Cell::new(0),
            cfg: crate::config::GatewayConfig::default(),
            meta_cache: RefCell::new(std::collections::HashMap::new()),
            metrics: crate::state::Metrics::default(),
            agent_tokens: std::collections::HashMap::new(),
            config_error: None,
        }
    }

    fn req(method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Request {
        let mut builder = http::Request::builder().method(method).uri(path);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        builder.body(body.to_vec()).expect("valid test request")
    }

    /// `None` if the request passes the gate, `Some(status)` if it's
    /// rejected — the exact composition `dispatch` runs.
    fn gate(r: &Request, policy: Policy<'_>) -> Option<u16> {
        check_auth(r, effective_auth_for(r, &policy)).map(|resp| resp.status().as_u16())
    }

    fn agent_tokens_for(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn auth_required_missing_returns_401() {
        let r = req("GET", "/agent/method", &[], &[]);
        assert_eq!(
            gate(
                &r,
                Policy {
                    auth_token: Some("secret"),
                    agent_tokens: None,
                },
            ),
            Some(401),
        );
    }

    #[test]
    fn auth_required_wrong_bearer_returns_401() {
        let r = req(
            "GET",
            "/agent/method",
            &[("authorization", "Bearer wrong")],
            &[],
        );
        assert_eq!(
            gate(
                &r,
                Policy {
                    auth_token: Some("secret"),
                    agent_tokens: None,
                },
            ),
            Some(401),
        );
    }

    #[test]
    fn auth_correct_bearer_passes_gate() {
        let r = req(
            "GET",
            "/agent/method",
            &[("authorization", "Bearer secret")],
            &[],
        );
        assert_eq!(
            gate(
                &r,
                Policy {
                    auth_token: Some("secret"),
                    agent_tokens: None,
                },
            ),
            None,
        );
    }

    #[test]
    fn auth_bearer_lowercase_scheme_accepted() {
        let r = req(
            "GET",
            "/agent/method",
            &[("authorization", "bearer secret")],
            &[],
        );
        assert_eq!(
            gate(
                &r,
                Policy {
                    auth_token: Some("secret"),
                    agent_tokens: None,
                },
            ),
            None,
        );
    }

    #[test]
    fn no_token_configured_passes_gate() {
        // Open dispatch (no `auth_token`): every request passes.
        let r = req("GET", "/agent/method", &[], &[]);
        assert_eq!(gate(&r, Policy::default()), None);
    }

    // ── Per-agent Bearer auth ─────────────────────────────────────
    //
    // Validates the `agent_tokens` override against the global
    // `auth_token` and the public namespaces.

    #[test]
    fn per_agent_token_requires_match_for_that_agent() {
        let tokens = agent_tokens_for(&[("secret-agent", "agent-only-token")]);
        let r = req(
            "GET",
            "/secret-agent/whoami",
            &[("authorization", "Bearer agent-only-token")],
            &[],
        );
        assert_eq!(
            gate(
                &r,
                Policy {
                    auth_token: None,
                    agent_tokens: Some(&tokens),
                },
            ),
            None,
        );
    }

    #[test]
    fn per_agent_token_rejects_wrong_bearer() {
        let tokens = agent_tokens_for(&[("secret-agent", "agent-only-token")]);
        let r = req(
            "GET",
            "/secret-agent/whoami",
            &[("authorization", "Bearer wrong")],
            &[],
        );
        assert_eq!(
            gate(
                &r,
                Policy {
                    auth_token: None,
                    agent_tokens: Some(&tokens),
                },
            ),
            Some(401),
        );
    }

    #[test]
    fn per_agent_token_overrides_global_for_that_agent() {
        // Global gate is `global-token`; the per-agent override for
        // `special` is `agent-token`. Hitting `/special/...` with the
        // global token must 401 — the agent token is the only one that
        // opens this agent.
        let tokens = agent_tokens_for(&[("special", "agent-token")]);
        let r = req(
            "GET",
            "/special/foo",
            &[("authorization", "Bearer global-token")],
            &[],
        );
        assert_eq!(
            gate(
                &r,
                Policy {
                    auth_token: Some("global-token"),
                    agent_tokens: Some(&tokens),
                },
            ),
            Some(401),
        );
    }

    #[test]
    fn per_agent_falls_back_to_global_for_other_agents() {
        // Only `special` is in the per-agent map. `regular` hits the
        // global gate; the global token works.
        let tokens = agent_tokens_for(&[("special", "agent-token")]);
        let r = req(
            "GET",
            "/regular/foo",
            &[("authorization", "Bearer global-token")],
            &[],
        );
        assert_eq!(
            gate(
                &r,
                Policy {
                    auth_token: Some("global-token"),
                    agent_tokens: Some(&tokens),
                },
            ),
            None,
        );
    }

    #[test]
    fn public_endpoints_ignore_tokens() {
        // `/__metrics`, `/__status`, `/__schema`, `/openapi.json` are
        // public — neither the global nor a per-agent gate covers them.
        let tokens = agent_tokens_for(&[("anything", "agent-token")]);
        let policy = Policy {
            auth_token: Some("global-token"),
            agent_tokens: Some(&tokens),
        };
        for path in ["/__metrics", "/__schema", "/__schema/math", "/openapi.json"] {
            let r = req("GET", path, &[], &[]);
            assert_eq!(gate(&r, policy), None, "{path} should bypass auth");
        }
    }
}
