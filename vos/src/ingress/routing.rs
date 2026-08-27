//! Built-in HTTP request routing.
//!
//! The host parses HTTP/1.1, authenticates a bearer credential against the
//! canonical space authority, and converts `/<actor>/<method>` into the same
//! schema-bound actor invocation used by typed VOS clients. Socket and HTTP
//! state never enter actor execution.
//!
//! ## Built-in routes (precedence + auth)
//!
//! | # | path                        | method | ask?     | auth          |
//! |---|-----------------------------|--------|----------|---------------|
//! | 1 | `/__status`                  | GET    | none     | anonymous     |
//! | 2 | `/__metrics`                 | GET    | none     | Admin         |
//! | 3 | `/__schema`, `/__schema/<a>` | GET    | registry | Member        |
//! | 4 | `/openapi.json`              | GET    | registry | Member        |
//! | 5 | `/<actor>/<method>`           | any    | actor    | Member + policy |
//!
//! Credential revocation and role changes take effect on the next request.

use crate::Encode;
use crate::actors::value::Msg;
use crate::log;
use crate::service::ActorId;
use http::Method;
use std::sync::atomic::Ordering;

use super::HttpIngressContext;
use super::json::{hex_encode, parse_flat_json, value_to_json, value_to_json_value};
use super::state::Inner;
use super::types::{Request, Response, json, text, with_content_type};

/// Per-request entry point. Only the minimal health endpoint is anonymous.
/// Every other route requires a live authority decision; schemas require
/// Member and metrics require Admin.
pub(crate) fn dispatch(req: &Request, inner: &Inner, ctx: &mut HttpIngressContext) -> Response {
    if let Some(response) = handle_status(req, inner) {
        return response;
    }
    if !ctx.is_authenticated() {
        return text(401, "a live VOS access token is required");
    }
    if req.uri().path() == "/__metrics" {
        if !ctx.has_capability(crate::capability::SPACE_METRICS_READ) {
            return text(403, "admin access is required");
        }
        return handle_metrics(req, inner).expect("metrics path matched");
    }
    if !ctx.has_capability(crate::capability::SPACE_DISCOVER) {
        return text(403, "member access is required");
    }
    inner.requests.fetch_add(1, Ordering::Relaxed);
    handle(req, inner, ctx)
}

/// `GET /__status` — compact JSON liveness snapshot (port, running,
/// request count, uptime). Reads only `Inner` atomics, so
/// it needs no registry round trip and works regardless of upstream
/// reachability. Public (no token).
fn handle_status(req: &Request, inner: &Inner) -> Option<Response> {
    if req.uri().path() != "/__status" {
        return None;
    }
    if req.method() != Method::GET {
        return Some(text(405, "/__status is GET-only"));
    }
    Some(json(200, super::state::status_json(inner).into_bytes()))
}

/// `GET /__metrics` — Prometheus exposition format. The caller enforces the
/// Admin gate before entering this ask-free renderer.
fn handle_metrics(req: &Request, inner: &Inner) -> Option<Response> {
    if req.uri().path() != "/__metrics" {
        return None;
    }
    if req.method() != Method::GET {
        return Some(text(405, "/__metrics is GET-only"));
    }
    let body = super::state::render_prometheus(inner).into_bytes();
    // Prometheus exposition convention. Some scrapers also tolerate bare
    // `text/plain`, but this is the canonical content type.
    Some(with_content_type(200, "text/plain; version=0.0.4", body))
}

/// Reserved namespaces which can never be actor names.
const PUBLIC_NAMESPACES: &[&str] = &["__schema", "__metrics", "openapi.json"];

/// Resolve `/<agent>/<method>` (and the `/__schema*` / `/openapi.json`
/// registry-backed endpoints) through the host ingress handle.
fn handle(req: &Request, inner: &Inner, ctx: &mut HttpIngressContext) -> Response {
    // `/__schema*` and `/openapi.json` short-circuit the agent/method
    // dispatcher. They `ask` the registry for schema, so they live here
    // (not in `dispatch`'s ask-free pre-auth shortcut).
    if let Some(resp) = handle_schema(req, inner, ctx) {
        return resp;
    }
    if let Some(resp) = handle_openapi(req, inner, ctx) {
        return resp;
    }

    let Some((agent, method)) = split_path(req.uri().path()) else {
        return text(400, "expected /<agent>/<method>");
    };

    // Reserve the ingress namespaces. The exact built-in paths
    // (`/__metrics`, `/__status`, `/__schema*`, `/openapi.json`) were handled
    // above; a *sub-path* like `/__metrics/foo` falls through to here and would
    // otherwise dispatch to an agent literally named `__metrics` — which
    // `effective_auth_for` classifies as a public namespace, so it would reach
    // that agent with NO token. Refuse dispatch to any `__`-prefixed name (or a
    // public namespace) so a reserved-named agent can't be reached — let alone
    // unauthenticated — through HTTP ingress.
    if agent.starts_with("__") || PUBLIC_NAMESPACES.contains(&agent.as_str()) {
        return text(404, format!("'{agent}' is a reserved ingress namespace"));
    }

    let target = match resolve(ctx, &agent) {
        Some(id) => id,
        None => return text(404, format!("unknown agent '{agent}'")),
    };

    // Look up the actor's schema. Dynamic HTTP dispatch is schema-bound so
    // method and argument validation cannot drift from the actor contract.
    let Some(meta) = ensure_meta_cached(ctx, inner, target, &agent) else {
        return text(502, format!("schema unavailable for agent '{agent}'"));
    };
    let Some(method_meta) = meta.messages.iter().find(|msg| msg.name == method).cloned() else {
        return text(404, format!("unknown method '{method}' on agent '{agent}'"));
    };

    let msg = match build_msg(method, &method_meta, req) {
        Ok(m) => m,
        Err(r) => return r,
    };

    // Encode as TAG_DYNAMIC + rkyv'd Msg — same wire format the
    // existing extension dispatch path produces.
    let encoded = msg.encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(crate::value::TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);

    let ret_ty = Some(method_meta.returns.as_str());
    let idempotency_key = match mutation_idempotency_key(req, method_meta.is_query) {
        Ok(key) => key,
        Err(response) => return response,
    };
    match ctx.invoke_actor(
        target,
        &payload,
        method_meta.attested,
        idempotency_key.as_deref(),
    ) {
        Ok(reply_bytes) if method_meta.attested => attested_response(&reply_bytes, ret_ty),
        Ok(reply_bytes) if reply_bytes.is_empty() => {
            // Handler returned `()` successfully → JSON null.
            json(200, value_to_json(&crate::value::Value::Unit))
        }
        Ok(reply_bytes) => {
            // try_decode runs rkyv's checked access — handles
            // arbitrary alignment + validates the buffer. decode
            // would unsafely access_unchecked, panicking on
            // misaligned slices that came back through the invoke
            // envelope unwrap.
            match <crate::value::Value as crate::Decode>::try_decode(&reply_bytes) {
                Some(value) => label_return(json(200, value_to_json(&value)), ret_ty),
                None => text(502, "upstream returned malformed reply"),
            }
        }
        Err(crate::ClientError::Forbidden) => text(403, "actor policy denied the request"),
        Err(crate::ClientError::NotFound) => text(404, "actor is no longer available"),
        Err(crate::ClientError::Call(crate::CallError::Timeout)) => {
            text(504, "actor invocation timed out")
        }
        Err(crate::ClientError::Unreachable) => text(503, "actor is unavailable"),
        Err(error) => {
            log::warn!("HTTP ingress actor invocation failed: {error:?}");
            text(502, "actor invocation failed")
        }
    }
}

fn attested_response(wire: &[u8], ret_ty: Option<&str>) -> Response {
    use crate::service::ServiceWire;

    let Ok(result) = crate::service::RootTreeAttestedResult::decode(wire) else {
        return text(502, "upstream returned a malformed attestation");
    };
    let Some(value) = <crate::value::Value as crate::Decode>::try_decode(&result.reply) else {
        return text(502, "attested reply is malformed");
    };
    let body = serde_json::json!({
        "reply": value_to_json_value(&value),
        "attestation_wire": hex_encode(wire),
    });
    label_return(
        json(
            200,
            serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
        ),
        ret_ty,
    )
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

/// Self-documenting schema endpoints. The caller applies the Member gate
/// before entering this function. Returns `None` for unrelated paths so the
/// caller falls through to the agent/method dispatcher.
///
/// - `GET /__schema`           → JSON `["name", ...]` of installed agents
/// - `GET /__schema/<agent>`   → JSON `ActorMeta` of that agent
///
/// Non-GET methods return 405. Unknown agents and agents without registered
/// metadata return 404.
fn handle_schema(req: &Request, inner: &Inner, ctx: &mut HttpIngressContext) -> Option<Response> {
    let path = req.uri().path();
    if !path.starts_with("/__schema") {
        return None;
    }
    if req.method() != Method::GET {
        return Some(text(405, "schema endpoints are GET-only"));
    }
    if path == "/__schema" || path == "/__schema/" {
        return Some(list_schemas(ctx));
    }
    let name = path.trim_start_matches("/__schema/").trim_end_matches('/');
    if name.is_empty() || name.contains('/') {
        return Some(text(400, "expected /__schema/<agent>"));
    }
    Some(schema_for_agent(name, inner, ctx))
}

/// Drain the registry's paginated `agent_names` into one list, in
/// `instance_name` order. `None` means the registry was unreachable (a
/// dropped dispatch); a malformed/misaligned page degrades to the names
/// gathered so far rather than panicking the connection task.
fn drain_agent_names(ctx: &mut HttpIngressContext) -> Option<Vec<String>> {
    let mut names: Vec<String> = Vec::new();
    loop {
        let after = names.last().cloned().unwrap_or_default();
        let msg = Msg::new("agent_names")
            .with("after_name", after)
            .with("budget", 0u32);
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(crate::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        let bytes = ctx.ask_registry(&payload)?;
        // Reply is `Value::Bytes(rkyv(AgentNamePage))`; anything else (empty,
        // Unit, non-decodable) ends the drain with what we have.
        let page = match <crate::value::Value as crate::Decode>::try_decode(&bytes) {
            Some(crate::value::Value::Bytes(inner)) if !inner.is_empty() => {
                match <crate::registry::AgentNamePage as crate::Decode>::try_decode(&inner) {
                    Some(page) => page,
                    None => break,
                }
            }
            _ => break,
        };
        let more = page.more;
        names.extend(page.names);
        if !more {
            break;
        }
    }
    Some(names)
}

fn list_schemas(ctx: &mut HttpIngressContext) -> Response {
    let Some(names) = drain_agent_names(ctx) else {
        return text(502, "registry unreachable");
    };
    json(
        200,
        serde_json::to_vec(&names).unwrap_or_else(|_| b"[]".to_vec()),
    )
}

fn schema_for_agent(name: &str, inner: &Inner, ctx: &mut HttpIngressContext) -> Response {
    let Some(target) = resolve(ctx, name) else {
        return text(404, format!("unknown agent '{name}'"));
    };
    match ensure_meta_cached(ctx, inner, target, name) {
        Some(meta) => json(200, meta_to_json(&meta).into_bytes()),
        None => text(404, format!("no schema for agent '{name}'")),
    }
}

/// Render a `ParsedMeta` as JSON. Mirrors the field names of the
/// in-tree `ActorMeta`/`MessageMeta`/`FieldMeta` structs so a
/// The field names mirror the in-tree schema: `actor_name`, `messages[i].name`,
/// `messages[i].is_query`, `messages[i].fields[j].name/type`,
/// `constructor[i].name/type`.
fn meta_to_json(meta: &crate::metadata::ParsedMeta) -> String {
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
                "returns": m.returns,
                "doc": m.doc,
                "timeout_ms": m.timeout_ms,
                "mode": m.mode,
                "attested": m.attested,
                "space_role": m.space_role,
                "actor_role": m.actor_role,
                "capability": m.capability,
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
        "doc": meta.doc,
        "crdt": meta.crdt,
        "provable": meta.provable,
        "messages": messages,
        "constructor": constructor,
    })
    .to_string()
}

/// OpenAPI 3.0 document at `GET /openapi.json`. Walks every agent
/// the registry knows about, fetches each one's schema (using the
/// same `ensure_meta_cached` warm path as the dispatcher), and
/// renders one `paths./<agent>/<method>` entry per `#[msg]`. The caller applies
/// the Member gate before entering this function.
///
/// Type mapping for arg shapes mirrors what `coerce_to_type`
/// accepts on the way in (so the documented surface and the
/// reality match):
///   `u8/u16/u32/u64`  → `integer` (`uint8`/`uint16`/`uint32`/`uint64`)
///   `i32/i64`         → `integer` (`int32`/`int64`)
///   `bool`            → `boolean`
///   `String`          → `string`
///   `Vec<u8>` `[u8;N]` → `string` (`byte`)
///   `Vec<u32>`        → `array` of integers
///   `Vec<String>`     → `array` of strings
///   any other         → `string` (fallback — generic UI still works)
fn handle_openapi(req: &Request, inner: &Inner, ctx: &mut HttpIngressContext) -> Option<Response> {
    if req.uri().path() != "/openapi.json" {
        return None;
    }
    if req.method() != Method::GET {
        return Some(text(405, "/openapi.json is GET-only"));
    }
    Some(render_openapi(inner, ctx))
}

fn render_openapi(inner: &Inner, ctx: &mut HttpIngressContext) -> Response {
    // 1. Get every installed agent's name.
    let Some(names) = drain_agent_names(ctx) else {
        return text(502, "registry unreachable");
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
            "title": "VOS HTTP ingress",
            "version": "unreleased",
            "description": "Auto-generated from installed-agent schemas (see GET /__schema)."
        },
        "components": {
            "securitySchemes": {
                "vosAccess": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "vos-access"
                }
            }
        },
        "security": [{ "vosAccess": [] }],
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
/// ingress actually dispatches via `build_msg`.
fn openapi_operation_for(
    actor_name: &str,
    msg: &crate::metadata::ParsedMessage,
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
                    "style": "form",
                    "explode": false,
                    "schema": vos_ty_to_openapi(&f.ty),
                })
            })
            .collect();
        serde_json::json!({
            http_method: {
                "summary": summary,
                "description": msg.doc,
                "operationId": operation_id,
                "x-vos-attested": msg.attested,
                "x-vos-space-role": msg.space_role,
                "x-vos-capability": msg.capability,
                "x-vos-actor-role": msg.actor_role,
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
                "description": msg.doc,
                "operationId": operation_id,
                "x-vos-attested": msg.attested,
                "x-vos-space-role": msg.space_role,
                "x-vos-capability": msg.capability,
                "x-vos-actor-role": msg.actor_role,
                "parameters": [{
                    "name": "Idempotency-Key",
                    "in": "header",
                    "required": true,
                    "schema": { "type": "string", "minLength": 1, "maxLength": 128 }
                }],
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
    // Types are recorded whitespace-free by the macro; normalize so
    // older pretty-printed `Vec < u8 >` blobs document correctly too
    // (they previously fell through to a plain `string`).
    let ty: String = ty.chars().filter(|c| !c.is_whitespace()).collect();
    // `[u8; N]` — a fixed-length byte array, rendered as a hex string.
    if ty.starts_with("[u8;") && ty.ends_with(']') {
        return serde_json::json!({ "type": "string", "format": "hex" });
    }
    match ty.as_str() {
        "u8" => serde_json::json!({ "type": "integer", "format": "uint8" }),
        "u16" => serde_json::json!({ "type": "integer", "format": "uint16" }),
        "u32" => serde_json::json!({ "type": "integer", "format": "uint32" }),
        "u64" => serde_json::json!({ "type": "integer", "format": "uint64" }),
        "i32" => serde_json::json!({ "type": "integer", "format": "int32" }),
        "i64" => serde_json::json!({ "type": "integer", "format": "int64" }),
        "bool" => serde_json::json!({ "type": "boolean" }),
        "String" => serde_json::json!({ "type": "string" }),
        "Vec<u8>" => serde_json::json!({ "type": "string", "format": "hex" }),
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

#[allow(clippy::result_large_err)]
fn mutation_idempotency_key(req: &Request, is_query: bool) -> Result<Option<String>, Response> {
    if is_query {
        return Ok(None);
    }
    let Some(value) = req.headers().get("idempotency-key") else {
        return Err(text(
            428,
            "mutating requests require an Idempotency-Key header",
        ));
    };
    let Ok(value) = value.to_str() else {
        return Err(text(400, "Idempotency-Key must be visible ASCII"));
    };
    if value.is_empty() || value.len() > 128 {
        return Err(text(
            400,
            "Idempotency-Key must contain 1 to 128 characters",
        ));
    }
    Ok(Some(value.to_owned()))
}

/// Resolve only roots attached to this node. HTTP listeners are host-local;
/// they do not turn registry aliases into implicit cross-node routes.
fn resolve(ctx: &mut HttpIngressContext, name: &str) -> Option<ActorId> {
    ctx.resolve_actor(name)
}

// The Err variant is the terminal 400 response, built once on the
// cold rejection path — not worth boxing every call site for.
#[allow(clippy::result_large_err)]
fn build_msg(
    method: String,
    method_meta: &crate::metadata::ParsedMessage,
    req: &Request,
) -> core::result::Result<Msg, Response> {
    use crate::value::Value;
    if method_meta.is_query && req.method() != Method::GET {
        return Err(text(405, "query methods require GET"));
    }
    if !method_meta.is_query
        && !matches!(req.method(), &Method::POST | &Method::PUT | &Method::PATCH)
    {
        return Err(text(405, "mutating methods require POST, PUT, or PATCH"));
    }
    let mut msg = Msg::new(method);
    let mut seen_keys: Vec<String> = Vec::new();
    // Pulls the typed result from `coerce_to_type` when a field declaration
    // matches; signals
    // a failed parse via `Err(Response)` so build_msg can 400
    // instead of silently passing through a wrong-typed value.
    let coerce = |key: &str, v: Value| -> Result<Value, Response> {
        let Some(field) = method_meta.fields.iter().find(|f| f.name == key) else {
            return Err(text(400, format!("unknown argument '{key}'")));
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
                    log::debug!("HTTP ingress rejected invalid JSON: {e}");
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
    for field in &method_meta.fields {
        if !seen_keys.iter().any(|k| k.as_str() == field.name) {
            return Err(text(400, format!("missing required arg '{}'", field.name)));
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
fn coerce_to_type(v: crate::value::Value, ty: &str) -> Option<crate::value::Value> {
    use crate::value::Value;
    // Pull a string out for parse-based coercion (the GET path).
    let as_str = if let Value::Str(ref s) = v {
        Some(s.as_str())
    } else {
        None
    };
    // Normalize the Rust type spelling emitted by token formatting.
    let ty: String = ty.chars().filter(|c| !c.is_whitespace()).collect();
    // `Vec<u8>` and `[u8; N]` handler args both need `Value::Bytes`,
    // which the JSON layer never produces directly. Accept either a hex
    // string (symmetric with how `Bytes` replies render — copy a hex
    // value out of a reply and pass it straight back) or a JSON array of
    // byte-valued numbers; pass an existing `Bytes` through. Without
    // this, every bytes-arg handler (clerk's bootstrap / create_account
    // / apply_transfer / account(id) / …) silently fails the actor's
    // `from_dynamic` and round-trips to a misleading "200 null". The
    // actor's `from_msg` validates the `[u8; N]` length.
    if ty == "Vec<u8>" || (ty.starts_with("[u8;") && ty.ends_with(']')) {
        return if let Some(s) = as_str {
            super::json::hex_decode(s).map(Value::Bytes)
        } else if let Value::ListU32(ref nums) = v {
            nums.iter()
                .map(|&n| u8::try_from(n).ok())
                .collect::<Option<Vec<u8>>>()
                .map(Value::Bytes)
        } else {
            v.as_bytes().map(|b| Value::Bytes(b.to_vec()))
        };
    }
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
        "Vec<u32>" => {
            if let Some(value) = as_str {
                parse_query_u32_list(value).map(Value::ListU32)
            } else if matches!(v, Value::ListU32(_)) {
                Some(v)
            } else {
                None
            }
        }
        "Vec<String>" => {
            if let Some(value) = as_str {
                parse_query_string_list(value).map(Value::ListStr)
            } else if matches!(v, Value::ListStr(_)) {
                Some(v)
            } else {
                None
            }
        }
        // Complex types we don't coerce — pass the original
        // through unchanged so the actor's `from_msg` accessor
        // gets a chance to evaluate the shape. Returning
        // `Some(v)` here keeps the 400-on-failure check
        // restricted to scalars the ingress is confident about.
        _ => Some(v),
    }
}

fn parse_query_u32_list(value: &str) -> Option<Vec<u32>> {
    serde_json::from_str(value).ok().or_else(|| {
        if value.is_empty() {
            return Some(Vec::new());
        }
        value.split(',').map(|item| item.parse().ok()).collect()
    })
}

fn parse_query_string_list(value: &str) -> Option<Vec<String>> {
    serde_json::from_str(value).ok().or_else(|| {
        Some(
            value
                .split(',')
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .collect(),
        )
    })
}

/// Fetch the actor's schema from the registry on a cache miss and return the
/// cached entry on a hit. A missing schema is cached for the TTL.
fn ensure_meta_cached(
    ctx: &mut HttpIngressContext,
    inner: &Inner,
    target: ActorId,
    name: &str,
) -> Option<crate::metadata::ParsedMeta> {
    // Fast path: cache hit + entry is still fresh. TTL covers the
    // `vosx space upgrade` case where the registry now has a
    // different schema but the ingress has no event-driven signal
    // to invalidate. Bounded staleness rather than per-request
    // revalidation. The `RefCell` borrow is dropped before the registry
    // `ask` below (never held across an `.await` — the single-threaded
    // executor would panic on a concurrent borrow).
    {
        let cache = inner.meta_cache.lock().unwrap();
        if let Some(entry) = cache.get(&target)
            && entry.fetched_at.elapsed() < super::state::META_CACHE_TTL
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
        target,
        super::state::MetaEntry {
            meta: parsed.clone(),
            fetched_at: std::time::Instant::now(),
        },
    );
    parsed
}

fn fetch_meta_from_registry(
    ctx: &mut HttpIngressContext,
    name: &str,
) -> Option<crate::metadata::ParsedMeta> {
    let msg = Msg::new("meta_for_instance").with("name", name.to_string());
    let encoded = msg.encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(crate::value::TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    let bytes = ctx.ask_registry(&payload)?;
    if bytes.is_empty() {
        return None;
    }
    // The reply is a `Value::Bytes(...)` carrying the raw
    // `.vos_meta` section. Empty bytes mean no entry exists. `decode`
    // returns None for malformed data too.
    let value = <crate::value::Value as crate::Decode>::try_decode(&bytes)?;
    let raw = value.as_bytes()?;
    if raw.is_empty() {
        return None;
    }
    crate::metadata::decode(raw)
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
    fn coerce_vec_u8_from_hex_string() {
        use crate::value::Value;
        let got = coerce_to_type(Value::Str("0xdead".into()), "Vec<u8>");
        assert_eq!(got, Some(Value::Bytes(vec![0xde, 0xad])));
    }

    #[test]
    fn coerce_byte_array_from_hex_string() {
        use crate::value::Value;
        // Length is not checked here — the actor's from_msg validates it.
        let got = coerce_to_type(Value::Str("01020304".into()), "[u8;4]");
        assert_eq!(got, Some(Value::Bytes(vec![1, 2, 3, 4])));
    }

    #[test]
    fn coerce_bytes_from_spaced_type() {
        use crate::value::Value;
        // Older binaries pretty-print the type; whitespace is stripped.
        let got = coerce_to_type(Value::Str("ab".into()), "Vec < u8 >");
        assert_eq!(got, Some(Value::Bytes(vec![0xab])));
    }

    #[test]
    fn openapi_byte_array_documents_the_actual_hex_encoding() {
        let s = vos_ty_to_openapi("[u8;32]");
        assert_eq!(s["type"], "string");
        assert_eq!(s["format"], "hex");
    }

    #[test]
    fn openapi_vec_u8_spaced_still_documents_hex() {
        // The whitespace bug previously documented this as a plain string.
        let s = vos_ty_to_openapi("Vec < u8 >");
        assert_eq!(s["type"], "string");
        assert_eq!(s["format"], "hex");
    }

    #[test]
    fn query_array_coercion_matches_openapi_form_encoding() {
        use crate::value::Value;
        assert_eq!(
            coerce_to_type(Value::Str("1,2,3".into()), "Vec<u32>"),
            Some(Value::ListU32(vec![1, 2, 3])),
        );
        assert_eq!(
            coerce_to_type(Value::Str("one,two".into()), "Vec<String>"),
            Some(Value::ListStr(vec!["one".into(), "two".into()])),
        );
    }

    #[test]
    fn actor_http_verbs_follow_the_schema_query_flag() {
        let mut method = parsed_method(true);
        let post = http::Request::builder()
            .method(Method::POST)
            .uri("/counter/value")
            .body(Vec::new())
            .unwrap();
        assert_eq!(
            build_msg("value".into(), &method, &post)
                .expect_err("queries are GET-only")
                .status(),
            405
        );

        method.is_query = false;
        let get = http::Request::builder()
            .method(Method::GET)
            .uri("/counter/increment")
            .body(Vec::new())
            .unwrap();
        assert_eq!(
            build_msg("increment".into(), &method, &get)
                .expect_err("mutations reject GET")
                .status(),
            405
        );
    }

    #[test]
    fn mutations_require_a_bounded_idempotency_key() {
        let query = http::Request::builder()
            .method(Method::GET)
            .uri("/counter/value")
            .body(Vec::new())
            .unwrap();
        assert_eq!(mutation_idempotency_key(&query, true).unwrap(), None);

        let missing = http::Request::builder()
            .method(Method::POST)
            .uri("/counter/increment")
            .body(Vec::new())
            .unwrap();
        assert_eq!(
            mutation_idempotency_key(&missing, false)
                .expect_err("mutation must be recoverable")
                .status(),
            428,
        );

        let keyed = http::Request::builder()
            .method(Method::POST)
            .uri("/counter/increment")
            .header("Idempotency-Key", "transfer-42")
            .body(Vec::new())
            .unwrap();
        assert_eq!(
            mutation_idempotency_key(&keyed, false).unwrap(),
            Some("transfer-42".into()),
        );
    }

    #[test]
    fn meta_cache_entry_past_ttl_is_considered_stale() {
        // Hand-seed a cache entry with `fetched_at` set just past
        // the TTL boundary, then confirm the staleness check the
        // dispatcher uses on the fast path returns false. Catches
        // accidental `<=` / `>=` flips or a TTL constant typo.
        use crate::ingress::state::{META_CACHE_TTL, MetaEntry};
        use std::time::Instant;

        let inner = fresh_inner();
        let target_id = crate::service::ActorId([7; 32]);
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
        {
            let cache = inner.meta_cache.lock().unwrap();
            let entry = cache.get(&target_id).expect("entry");
            assert!(
                entry.fetched_at.elapsed() < META_CACHE_TTL,
                "freshly-inserted entry must read as in-TTL",
            );
        }

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

    fn fresh_inner() -> Inner {
        Inner::new(8080)
    }

    fn parsed_method(is_query: bool) -> crate::metadata::ParsedMessage {
        crate::metadata::ParsedMessage {
            name: "method".into(),
            is_query,
            fields: Vec::new(),
            exposed_to_cli: false,
            returns: "()".into(),
            doc: String::new(),
            timeout_ms: 0,
            mode: 0,
            attested: false,
            space_role: None,
            actor_role: None,
        }
    }
}
