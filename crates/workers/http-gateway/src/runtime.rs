//! Shared bootstrap for the per-protocol tokio runtimes.
//!
//! Both the hyper (h1+h2c) and h3 modules park their work on a
//! dedicated OS thread holding a current-thread tokio runtime. This
//! module owns the thread + runtime + ready-signal handshake so the
//! protocol modules just supply the async work to drive.
//!
//! Also home to `serve_with`: the actor-side bootstrap dance shared by
//! `serve` and `serve_h3` (claim port, reset stop flag, spawn the
//! protocol thread, drain jobs until stop).

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use vos::log;

use crate::HttpGateway;
use crate::config;
use crate::limits::{DRAIN_TIMEOUT, JOB_QUEUE_CAP};
use crate::routing::drain_jobs;
use crate::state::{Inner, inner, now_unix};
use crate::types::{IoResult, Job};

/// RAII guard that decrements `Inner::in_flight` on drop. Bump the
/// counter just before `tokio::spawn` and place this guard inside the
/// spawned future so the count tracks live tasks across both happy-
/// path completion and runtime cancellation.
pub(crate) struct InFlightGuard(Arc<Inner>);

impl InFlightGuard {
    pub(crate) fn new(inner: Arc<Inner>) -> Self {
        Self(inner)
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Async poll loop used by each protocol's accept_loop after the stop
/// flag flips. Sleeps in 50ms increments until `in_flight` drops to
/// zero or the timeout elapses.
pub(crate) async fn drain_in_flight(inner: &Inner) {
    let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;
    while inner.in_flight.load(Ordering::Relaxed) > 0 {
        if tokio::time::Instant::now() >= deadline {
            let n = inner.in_flight.load(Ordering::Relaxed);
            log::warn!("http-gateway: drain timeout, {n} task(s) still in flight");
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Spawn a named OS thread, build a current-thread tokio runtime on
/// it, and run `work(ready_tx)` to completion. Synchronously blocks
/// the caller until `work` reports readiness via `ready_tx`, then
/// returns the thread's join handle so callers can wait for it to
/// fully exit on shutdown (otherwise a fast restart races against
/// the listener still holding the port).
pub(crate) fn spawn_on_thread<F, Fut>(
    name: String,
    work: F,
) -> IoResult<thread::JoinHandle<()>>
where
    F: FnOnce(mpsc::SyncSender<IoResult<()>>) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    let (ready_tx, ready_rx) = mpsc::sync_channel::<IoResult<()>>(1);
    let ready_tx_for_work = ready_tx.clone();
    let handle = thread::Builder::new()
        .name(name)
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
            rt.block_on(work(ready_tx_for_work));
        })
        .map_err(|e| format!("spawn thread: {e}"))?;
    ready_rx.recv().map_err(|e| format!("ready signal: {e}"))??;
    Ok(handle)
}

/// Actor-side bootstrap: claim the port slot, kick off the protocol
/// thread, then drain jobs through `ctx.ask` until stop. Used by both
/// `serve` (hyper) and `serve_h3`. Returns the loop's exit reason.
pub(crate) async fn serve_with<F>(
    port: u16,
    proto: &str,
    spawn_protocol: F,
    ctx: &mut vos::Context<HttpGateway>,
) -> String
where
    F: FnOnce(u16, mpsc::SyncSender<Job>, Arc<Inner>) -> IoResult<thread::JoinHandle<()>>,
{
    let inner = inner().clone();

    let already = inner.bound_port.load(Ordering::Relaxed);
    if already != 0 {
        return format!("already listening on port {already}");
    }
    inner.stop.store(false, Ordering::Relaxed);
    inner.in_flight.store(0, Ordering::Relaxed);

    let (job_tx, job_rx) = mpsc::sync_channel::<Job>(JOB_QUEUE_CAP);
    let handle = match spawn_protocol(port, job_tx, inner.clone()) {
        Ok(h) => h,
        Err(e) => {
            log::error!("http-gateway: {e}");
            return e;
        }
    };
    inner.bound_port.store(port, Ordering::Relaxed);
    inner.started_unix.store(now_unix(), Ordering::Relaxed);
    let bind = config::bind_ip();
    log::info!("http-gateway: listening on {bind}:{port} ({proto})");
    if config::auth_token().is_none() {
        log::warn!(
            "http-gateway: HTTP_GATEWAY_AUTH_TOKEN not set — dispatch is open to anyone reachable on {bind}:{port}"
        );
    }
    if config::admin_token().is_none() {
        log::info!(
            "http-gateway: HTTP_GATEWAY_ADMIN_TOKEN not set — /__admin/* disabled"
        );
    }

    let stop_msg = drain_jobs(&job_rx, &inner, ctx).await;

    // Wait for the protocol thread to fully exit. The accept loop on
    // that thread polls `in_flight` after stop is signaled, so this
    // join reflects "listener closed + connections drained (or
    // drain-timeout reached)". Bounded by `DRAIN_TIMEOUT` from the
    // accept-loop side.
    wait_for_thread(handle);

    inner.bound_port.store(0, Ordering::Relaxed);
    log::info!("http-gateway: {stop_msg}");
    stop_msg
}

/// Block the caller until the protocol thread exits, with a hard cap.
/// The accept loop already self-limits via `DRAIN_TIMEOUT`, so this
/// wait is bounded; the extra ceiling here is belt-and-suspenders for
/// a wedged thread (which would also be a bug worth surfacing).
fn wait_for_thread(handle: thread::JoinHandle<()>) {
    let deadline = Instant::now() + DRAIN_TIMEOUT + Duration::from_secs(1);
    loop {
        if handle.is_finished() {
            if let Err(panic) = handle.join() {
                log::error!("http-gateway: protocol thread panicked: {panic:?}");
            }
            return;
        }
        if Instant::now() >= deadline {
            log::warn!(
                "http-gateway: protocol thread didn't exit within drain timeout; releasing port slot anyway (next bind may race)"
            );
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}
