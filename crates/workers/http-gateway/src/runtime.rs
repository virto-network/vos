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

use vos::log;

use crate::HttpGateway;
use crate::routing::drain_jobs;
use crate::state::{Inner, inner, now_unix};
use crate::types::{IoResult, Job};

/// Spawn a named OS thread, build a current-thread tokio runtime on
/// it, and run `work(ready_tx)` to completion. Synchronously blocks
/// the caller until `work` reports readiness via `ready_tx`.
///
/// `work` is responsible for binding its listener and signaling
/// success or failure on `ready_tx` before entering its accept loop.
pub(crate) fn spawn_on_thread<F, Fut>(
    name: String,
    work: F,
) -> IoResult<()>
where
    F: FnOnce(mpsc::SyncSender<IoResult<()>>) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    let (ready_tx, ready_rx) = mpsc::sync_channel::<IoResult<()>>(1);
    let ready_tx_for_work = ready_tx.clone();
    thread::Builder::new()
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
    ready_rx.recv().map_err(|e| format!("ready signal: {e}"))?
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
    F: FnOnce(u16, mpsc::Sender<Job>, Arc<Inner>) -> IoResult<()>,
{
    let inner = inner().clone();

    let already = inner.bound_port.load(Ordering::Relaxed);
    if already != 0 {
        return format!("already listening on 0.0.0.0:{already}");
    }
    inner.stop.store(false, Ordering::Relaxed);

    let (job_tx, job_rx) = mpsc::channel::<Job>();
    if let Err(e) = spawn_protocol(port, job_tx, inner.clone()) {
        log::error!("http-gateway: {e}");
        return e;
    }
    inner.bound_port.store(port, Ordering::Relaxed);
    inner.started_unix.store(now_unix(), Ordering::Relaxed);
    log::info!("http-gateway: listening on 0.0.0.0:{port} ({proto})");

    let stop_msg = drain_jobs(&job_rx, &inner, ctx).await;

    inner.bound_port.store(0, Ordering::Relaxed);
    log::info!("http-gateway: {stop_msg}");
    stop_msg
}
