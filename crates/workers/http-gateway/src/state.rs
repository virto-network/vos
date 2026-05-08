//! Shared runtime state — atomics reachable from both the actor
//! handlers and the tokio thread.
//!
//! One per process: there's only meant to be a single gateway
//! instance per worker `.so` load. The `OnceLock` makes the singleton
//! lazy and thread-safe; both sides use `Ordering::Relaxed` because
//! the values they exchange (a stop flag, a port, a few counters)
//! never establish happens-before relationships with other data.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) struct Inner {
    /// Set to true to ask the running serve loop to exit.
    pub(crate) stop: AtomicBool,
    /// Bound port, 0 when the gateway isn't running.
    pub(crate) bound_port: AtomicU16,
    /// Total HTTP requests fully served since process boot.
    pub(crate) requests: AtomicU64,
    /// Unix epoch seconds when the gateway last entered the serve
    /// loop; 0 when never started.
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

    /// `true` once a `serve*` is in flight and hasn't been asked to
    /// stop. Used both by the `running()` actor message and to gate
    /// the "already running" early-return on a second `serve` call.
    pub(crate) fn running(&self) -> bool {
        self.bound_port.load(Ordering::Relaxed) != 0
            && !self.stop.load(Ordering::Relaxed)
    }
}

pub(crate) fn inner() -> &'static Arc<Inner> {
    static INNER: OnceLock<Arc<Inner>> = OnceLock::new();
    INNER.get_or_init(Inner::new)
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Compact JSON snapshot — same shape served by `GET /__admin/status`
/// and the `status()` actor message.
pub(crate) fn status_json(inner: &Inner) -> String {
    let started = inner.started_unix.load(Ordering::Relaxed);
    let uptime = if started == 0 { 0 } else { now_unix().saturating_sub(started) };
    serde_json::json!({
        "port": inner.bound_port.load(Ordering::Relaxed),
        "running": inner.running(),
        "requests": inner.requests.load(Ordering::Relaxed),
        "uptime_secs": uptime,
        "started_unix": started,
    })
    .to_string()
}
