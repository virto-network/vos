//! Request routing.
//!
//! `handle` resolves the URL's `<agent>` segment through the registry
//! actor, builds a dynamic `Msg` from query params (GET) or JSON body
//! (POST/PUT/PATCH), dispatches via `ctx.ask`, and returns the reply
//! as a JSON `Response`.
//!
//! `handle_admin` short-circuits the `/__admin/*` routes — they're
//! served entirely by the tokio side, so they preempt a busy `serve()`.
//!
//! `drain_jobs` is the actor-side serve loop: pull a `Job` off the
//! mpsc, run `handle`, return the response on the oneshot, repeat
//! until the stop flag flips.

use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Duration;

use vos::actors::context::ServiceId;
use vos::actors::value::{Msg, Value};
use vos::log;

use crate::HttpGateway;
use crate::config::{admin_token, auth_token, ct_eq, header_value};
use crate::json::{parse_flat_json, value_to_json};
use crate::state::{Inner, status_json};
use crate::types::{Job, Request, Response};

pub(crate) async fn drain_jobs(
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
            Err(mpsc::RecvTimeoutError::Disconnected) => return "job channel closed".into(),
        }
    }
}

async fn handle(req: &Request, ctx: &mut vos::Context<HttpGateway>) -> Response {
    if let Some(expected) = auth_token() {
        let provided = header_value(&req.headers, "authorization")
            .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")));
        if !provided.is_some_and(|t| ct_eq(t.trim(), expected)) {
            return Response::text(401, "unauthorized");
        }
    }

    let Some((agent, method)) = split_path(&req.path) else {
        return Response::text(400, "expected /<agent>/<method>");
    };

    let target = match resolve(ctx, &agent).await {
        Ok(Some(id)) => id,
        Ok(None) => return Response::text(404, format!("unknown agent '{agent}'")),
        Err(e) => return Response::text(502, format!("registry: {e}")),
    };

    let msg = match build_msg(method, req) {
        Ok(m) => m,
        Err(r) => return r,
    };

    match ctx.ask(target, &msg).await {
        Ok(value) => Response::json(200, value_to_json(&value)),
        Err(e) => Response::text(502, format!("upstream error: {e}")),
    }
}

/// Direct admin endpoints — bypass `ctx.ask` so they work even while
/// `serve()` is the only message in flight on the worker.
///
/// Auth: when `HTTP_GATEWAY_ADMIN_TOKEN` is unset, the gateway returns
/// 404 for the entire `/__admin/*` namespace so its existence isn't
/// even disclosed. When set, the request must carry a matching
/// `X-Admin-Token` header (constant-time compared).
///
/// - `GET  /__admin/status` → JSON snapshot
/// - `POST /__admin/stop`   → set the stop flag, reply 204
pub(crate) fn handle_admin(req: &Request, inner: &Inner) -> Option<Response> {
    if !req.path.starts_with("/__admin/") {
        return None;
    }
    let Some(expected) = admin_token() else {
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
        _ => Response::text(404, format!("unknown admin route {} {}", req.method, req.path)),
    })
}

fn split_path(path: &str) -> Option<(String, String)> {
    let trimmed = path.trim_start_matches('/');
    let (agent, method) = trimmed.split_once('/')?;
    (!agent.is_empty() && !method.is_empty()).then(|| (agent.to_string(), method.to_string()))
}

async fn resolve(
    ctx: &mut vos::Context<HttpGateway>,
    name: &str,
) -> core::result::Result<Option<ServiceId>, vos::actors::value::InvokeError> {
    let msg = Msg::new("resolve").with("name", name.to_string());
    let id = ctx.ask(ServiceId::REGISTRY, &msg).await?.as_u32().unwrap_or(0);
    Ok((id != 0).then(|| ServiceId(id)))
}

fn build_msg(method: String, req: &Request) -> core::result::Result<Msg, Response> {
    let mut msg = Msg::new(method);
    match req.method.as_str() {
        "GET" => {
            for (k, v) in parse_query(&req.query) {
                msg = msg.with(k, v);
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
                    msg = msg.with(k, Value::from(v));
                }
            }
        }
        other => return Err(Response::text(405, format!("method {other} not allowed"))),
    }
    Ok(msg)
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
}
