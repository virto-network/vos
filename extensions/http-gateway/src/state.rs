//! Shared runtime state — atomics + config reachable from both the
//! gateway's `run` thread and the tokio connection tasks.
//!
//! Per-instance: each gateway extension that boots makes its own
//! `Arc<Inner>` and threads it everywhere. Process-globals were a
//! footgun for tests (every test in a single binary shared the same
//! singleton, even when each one wanted its own port + admin
//! token). All atomics use `Ordering::Relaxed` because the values
//! they exchange (a stop flag, a port, a few counters) never
//! establish happens-before relationships with other data.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::GatewayConfig;

pub(crate) struct Inner {
    /// Set to true to ask the running serve loop to exit.
    pub(crate) stop: AtomicBool,
    /// Bound port, 0 when the gateway isn't running.
    pub(crate) bound_port: AtomicU16,
    /// Total HTTP requests fully served since gateway boot.
    pub(crate) requests: AtomicU64,
    /// Unix epoch seconds when the gateway last entered the serve
    /// loop; 0 when never started.
    pub(crate) started_unix: AtomicU64,
    /// Per-connection tasks currently running. Bumped in the accept
    /// loop before spawn; an `InFlightGuard` decrements on task drop.
    /// `accept_loop` polls this on shutdown so connections drain
    /// before the runtime exits.
    pub(crate) in_flight: AtomicU16,
    /// Operator-supplied config: bind address, tokens, TLS paths.
    /// Set once at construction; read by both the run thread and
    /// the per-connection tasks (immutable, no atomics needed).
    pub(crate) cfg: GatewayConfig,
}

impl Inner {
    pub(crate) fn new(cfg: GatewayConfig) -> Arc<Self> {
        Arc::new(Self {
            stop: AtomicBool::new(false),
            bound_port: AtomicU16::new(0),
            requests: AtomicU64::new(0),
            started_unix: AtomicU64::new(0),
            in_flight: AtomicU16::new(0),
            cfg,
        })
    }

    /// `true` once a `serve*` is in flight and hasn't been asked to
    /// stop. Used both by the `running()` actor message and to gate
    /// the "already running" early-return on a second `serve` call.
    pub(crate) fn running(&self) -> bool {
        self.bound_port.load(Ordering::Relaxed) != 0 && !self.stop.load(Ordering::Relaxed)
    }
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
    let uptime = if started == 0 {
        0
    } else {
        now_unix().saturating_sub(started)
    };
    serde_json::json!({
        "port": inner.bound_port.load(Ordering::Relaxed),
        "running": inner.running(),
        "requests": inner.requests.load(Ordering::Relaxed),
        "uptime_secs": uptime,
        "started_unix": started,
    })
    .to_string()
}
