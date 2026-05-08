//! Hyper-side wire plumbing for HTTP/1.1 + HTTP/2 (cleartext).
//!
//! Each accepted TCP connection runs a hyper `service_fn` that
//! translates a `hyper::Request<Incoming>` into our internal
//! `Request`, runs the admin shortcut or pushes a `Job`, awaits the
//! oneshot, and returns a hyper response. h2c lets a single TCP
//! connection multiplex many requests, all funneled through the same
//! mpsc — dispatch is still serial through the worker's `ctx`.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, oneshot};
use vos::log;

use crate::config;
use crate::limits::{
    HEADER_READ_TIMEOUT, MAX_BODY_BYTES, MAX_CONCURRENT_CONNS, MAX_REQUEST_HEADERS,
};
use crate::runtime::{self, InFlightGuard, drain_in_flight};
use crate::routing::handle_admin;
use crate::state::Inner;
use crate::types::{IoResult, Job, Request, Response};

type HyperResponse = hyper::Response<Full<Bytes>>;

/// Bootstrap: spawn an OS thread holding a current-thread tokio
/// runtime that owns the TCP listener and per-connection tasks.
/// Synchronously blocks until the listener is bound.
pub(crate) fn spawn(
    port: u16,
    job_tx: mpsc::SyncSender<Job>,
    inner: Arc<Inner>,
) -> IoResult<thread::JoinHandle<()>> {
    let bind = config::bind_ip();
    runtime::spawn_on_thread(format!("http-gateway-rt:{port}"), move |ready_tx| async move {
        let listener = match TcpListener::bind((bind, port)).await {
            Ok(l) => l,
            Err(e) => {
                let _ = ready_tx.send(Err(format!("bind {bind}:{port}: {e}")));
                return;
            }
        };
        let _ = ready_tx.send(Ok(()));
        accept_loop(listener, job_tx, inner).await;
    })
}

async fn accept_loop(
    listener: TcpListener,
    job_tx: mpsc::SyncSender<Job>,
    inner: Arc<Inner>,
) {
    // One builder shared across connections; sniffs the protocol
    // preface and dispatches to h1 or h2c.
    let mut conn_builder =
        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    // Slow-loris mitigation: cap the time spent reading the request
    // line + headers. Hyper closes the connection if this elapses
    // without progress.
    conn_builder.http1().header_read_timeout(HEADER_READ_TIMEOUT);
    // Per-protocol connection cap. Connections beyond this are
    // dropped; clients see an immediate close rather than queuing
    // FDs in the kernel.
    let conn_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNS));

    while !inner.stop.load(Ordering::Relaxed) {
        let accept = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        let (stream, peer) = match accept {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => {
                log::warn!("http-gateway: accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
            Err(_) => continue, // timeout — re-check stop
        };
        let permit = match conn_sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                log::warn!("http-gateway: conn limit ({MAX_CONCURRENT_CONNS}) hit; dropping {peer}");
                drop(stream);
                continue;
            }
        };
        inner.in_flight.fetch_add(1, Ordering::Relaxed);
        let job_tx = job_tx.clone();
        let inner_for_task = inner.clone();
        let conn_builder = conn_builder.clone();
        tokio::spawn(async move {
            let _permit = permit; // released when this task ends
            let _guard = InFlightGuard::new(inner_for_task.clone());
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: hyper::Request<Incoming>| {
                let job_tx = job_tx.clone();
                let inner = inner_for_task.clone();
                async move { Ok::<_, Infallible>(serve_request(req, job_tx, inner).await) }
            });
            if let Err(e) = conn_builder.serve_connection(io, svc).await {
                log::debug!("http-gateway: conn {peer}: {e}");
            }
        });
    }

    // Stop signaled — wait for live connections to drain.
    drain_in_flight(&inner).await;
}

async fn serve_request(
    req: hyper::Request<Incoming>,
    job_tx: mpsc::SyncSender<Job>,
    inner: Arc<Inner>,
) -> HyperResponse {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .take(MAX_REQUEST_HEADERS)
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_ascii_lowercase(), v.to_string()))
        })
        .collect();

    // `Limited` aborts the body stream once `MAX_BODY_BYTES` is
    // exceeded, so an attacker can't OOM us with a huge payload.
    let body = match Limited::new(req.into_body(), MAX_BODY_BYTES).collect().await {
        Ok(c) => c.to_bytes().to_vec(),
        Err(_) => {
            return into_hyper(Response::text(
                413,
                format!("body exceeds {MAX_BODY_BYTES} bytes"),
            ));
        }
    };

    let our_req = Request { method, path, query, headers, body };

    if let Some(response) = handle_admin(&our_req, &inner) {
        return into_hyper(response);
    }

    let (resp_tx, resp_rx) = oneshot::channel::<Response>();
    match job_tx.try_send(Job { request: our_req, resp_tx }) {
        Ok(()) => {}
        Err(mpsc::TrySendError::Full(_)) => {
            return into_hyper(Response::text(503, "gateway saturated; retry"));
        }
        Err(mpsc::TrySendError::Disconnected(_)) => {
            return into_hyper(Response::text(503, "gateway stopped"));
        }
    }

    let response = resp_rx
        .await
        .unwrap_or_else(|_| Response::text(500, "no response from actor"));
    into_hyper(response)
}

fn into_hyper(r: Response) -> HyperResponse {
    // Today all callers go through `Response::{text,json,empty}` with
    // status codes from a small set, so the builder never errors —
    // but if a future caller hands us a malformed status / header,
    // fall through to a static 500 instead of panicking the worker.
    match hyper::Response::builder()
        .status(r.status)
        .header("content-type", r.content_type)
        .body(Full::new(Bytes::from(r.body)))
    {
        Ok(resp) => resp,
        Err(e) => {
            log::error!("http-gateway: response build error: {e}");
            fallback_500()
        }
    }
}

fn fallback_500() -> HyperResponse {
    // Construction is purely literal — status 500, fixed content-type,
    // empty body — so the inner builder genuinely cannot fail.
    hyper::Response::builder()
        .status(500)
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from_static(b"internal error")))
        .expect("static 500 response")
}
