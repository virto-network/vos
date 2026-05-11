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

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use vos::metadata::ParsedMeta;

use crate::config::GatewayConfig;

/// Per-agent type schema cache. Keyed by raw ServiceId. Populated
/// lazily on the first dispatch to an agent (registry round-trip)
/// and never invalidated for the gateway's lifetime — a future
/// `space upgrade` would need an explicit clear, but the
/// re-registration on the registry side will at least give us
/// fresh schema bytes on the next process restart.
///
/// Values: `Some(meta)` once we successfully fetched + decoded
/// the schema; `None` once we asked and got back "no meta" (so
/// we don't retry on every subsequent request to the same
/// agent). Distinguishes "not yet asked" (absent key) from
/// "asked, found nothing" (key present with None).
pub(crate) type MetaCache = Mutex<HashMap<u32, Option<ParsedMeta>>>;

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
    /// Per-agent schema cache. See [`MetaCache`] for semantics.
    pub(crate) meta_cache: MetaCache,
    /// Aggregate counters surfaced via `/__metrics`. Connection
    /// tasks update them on response shape; the metrics endpoint
    /// reads them lock-free. See [`Metrics`].
    pub(crate) metrics: Metrics,
    /// Parsed per-agent Bearer tokens map, derived from
    /// `cfg.agent_tokens`. Populated once at construction so the
    /// hot path doesn't re-parse on every request.
    pub(crate) agent_tokens: HashMap<String, String>,
}

/// Atomic counters powering the `/__metrics` Prometheus
/// endpoint. Designed to be additive — new gauges/counters just
/// land here and get emitted by `render_prometheus`. Per-actor
/// labels (`vos_gateway_actor_requests_total{actor="…"}`) are a
/// natural extension; they'd live in a separate `Mutex<HashMap>`
/// rather than fixed atomics because the set of actors is
/// dynamic. Today everything here is fixed-cardinality so the
/// scrape cost is bounded.
#[derive(Default)]
pub(crate) struct Metrics {
    pub(crate) responses_2xx: AtomicU64,
    pub(crate) responses_3xx: AtomicU64,
    pub(crate) responses_4xx: AtomicU64,
    pub(crate) responses_5xx: AtomicU64,
}

impl Metrics {
    /// Record one served HTTP response. Buckets by status class
    /// — keeps the scraper-cost bounded vs per-code labels and
    /// matches what most ops dashboards want at the gateway layer
    /// (per-route detail belongs on per-actor metrics, which
    /// land alongside the schema cache when needed).
    pub(crate) fn record_response(&self, status: u16) {
        let bucket = match status / 100 {
            2 => &self.responses_2xx,
            3 => &self.responses_3xx,
            4 => &self.responses_4xx,
            _ => &self.responses_5xx,
        };
        bucket.fetch_add(1, Ordering::Relaxed);
    }
}

impl Inner {
    pub(crate) fn new(cfg: GatewayConfig) -> Arc<Self> {
        let agent_tokens = cfg.parse_agent_tokens();
        Arc::new(Self {
            stop: AtomicBool::new(false),
            bound_port: AtomicU16::new(0),
            requests: AtomicU64::new(0),
            started_unix: AtomicU64::new(0),
            in_flight: AtomicU16::new(0),
            cfg,
            meta_cache: Mutex::new(HashMap::new()),
            metrics: Metrics::default(),
            agent_tokens,
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

/// Prometheus exposition format for `GET /__metrics`. Plain text,
/// one metric per stanza (HELP + TYPE + samples). Counters are
/// `_total`-suffixed per the convention; gauges aren't.
///
/// Add new metrics by appending a stanza here and bumping the
/// underlying atomic in the relevant code path. The
/// `vos_gateway_*` namespace stays — future per-actor labelled
/// series should use `vos_gateway_actor_*` so a scraper can group
/// them and the Prometheus regex matchers stay shallow.
pub(crate) fn render_prometheus(inner: &Inner) -> String {
    let started = inner.started_unix.load(Ordering::Relaxed);
    let uptime = if started == 0 {
        0
    } else {
        now_unix().saturating_sub(started)
    };
    let up = if inner.running() { 1 } else { 0 };
    let port = inner.bound_port.load(Ordering::Relaxed);
    let in_flight = inner.in_flight.load(Ordering::Relaxed);
    let dispatched = inner.requests.load(Ordering::Relaxed);
    let r2xx = inner.metrics.responses_2xx.load(Ordering::Relaxed);
    let r3xx = inner.metrics.responses_3xx.load(Ordering::Relaxed);
    let r4xx = inner.metrics.responses_4xx.load(Ordering::Relaxed);
    let r5xx = inner.metrics.responses_5xx.load(Ordering::Relaxed);

    let mut out = String::with_capacity(1024);

    out.push_str("# HELP vos_gateway_up Gateway running flag (1=running, 0=stopped).\n");
    out.push_str("# TYPE vos_gateway_up gauge\n");
    out.push_str(&format!("vos_gateway_up {up}\n"));

    out.push_str("# HELP vos_gateway_port TCP port the gateway is bound to (0 if not running).\n");
    out.push_str("# TYPE vos_gateway_port gauge\n");
    out.push_str(&format!("vos_gateway_port {port}\n"));

    out.push_str(
        "# HELP vos_gateway_uptime_seconds Seconds since the gateway last entered serve.\n",
    );
    out.push_str("# TYPE vos_gateway_uptime_seconds gauge\n");
    out.push_str(&format!("vos_gateway_uptime_seconds {uptime}\n"));

    out.push_str("# HELP vos_gateway_in_flight Current in-flight connection count.\n");
    out.push_str("# TYPE vos_gateway_in_flight gauge\n");
    out.push_str(&format!("vos_gateway_in_flight {in_flight}\n"));

    out.push_str(
        "# HELP vos_gateway_requests_total Total HTTP requests dispatched to an actor since boot.\n",
    );
    out.push_str("# TYPE vos_gateway_requests_total counter\n");
    out.push_str(&format!("vos_gateway_requests_total {dispatched}\n"));

    out.push_str(
        "# HELP vos_gateway_responses_total Total HTTP responses by status class since boot.\n",
    );
    out.push_str("# TYPE vos_gateway_responses_total counter\n");
    out.push_str(&format!(
        "vos_gateway_responses_total{{status_class=\"2xx\"}} {r2xx}\n"
    ));
    out.push_str(&format!(
        "vos_gateway_responses_total{{status_class=\"3xx\"}} {r3xx}\n"
    ));
    out.push_str(&format!(
        "vos_gateway_responses_total{{status_class=\"4xx\"}} {r4xx}\n"
    ));
    out.push_str(&format!(
        "vos_gateway_responses_total{{status_class=\"5xx\"}} {r5xx}\n"
    ));

    out
}
