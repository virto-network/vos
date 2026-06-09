//! Per-instance runtime state — config + counters + schema cache.
//!
//! In transport mode the host drives the gateway on a
//! **single cooperative executor thread**: many connection tasks share
//! `&self`, but they only ever interleave at `.await` points and never
//! run on different threads. So the synchronization is
//! single-threaded interior mutability — `Cell` / `RefCell`, **no
//! `Arc` / `Mutex` / atomics**. A `RefCell` borrow MUST NOT be held across an
//! `.await` (it would panic on a concurrent borrow rather than corrupt) —
//! every borrow here is taken and dropped between yields.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use vos::metadata::ParsedMeta;

use crate::config::GatewayConfig;

/// How long a schema cache entry stays trusted before the next
/// hit triggers a fresh registry fetch. `vosx space upgrade`
/// re-registers meta on the registry side, so a stale entry
/// will refresh within this window without operator action.
/// 60 seconds keeps the hot path effectively free in steady
/// state (a typical actor takes thousands of requests in that
/// window) while bounding post-upgrade staleness.
pub(crate) const META_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// One entry in the per-agent schema cache. `meta` is `Some` when
/// the schema is known, `None` when the registry confirmed "no
/// schema for this name" — the distinction matters so a name
/// without a schema doesn't pay a round trip every request.
///
/// `fetched_at` is checked against [`META_CACHE_TTL`] on each
/// lookup; expired entries fall back to a fresh registry fetch.
#[derive(Clone)]
pub(crate) struct MetaEntry {
    pub(crate) meta: Option<ParsedMeta>,
    pub(crate) fetched_at: Instant,
}

/// Per-agent type schema cache. Keyed by raw ServiceId. Populated
/// lazily on the first dispatch to an agent (registry round-trip)
/// and refreshed when an entry is older than [`META_CACHE_TTL`].
///
/// The cache distinguishes three states for a given ServiceId:
/// - absent key: "not yet asked"
/// - present, `meta = Some(_)`: schema known
/// - present, `meta = None`: registry asked, no schema available
///   (old binary, hash mismatch). Caching `None` avoids
///   re-asking on every request for the same name.
///
/// `RefCell` (not `Mutex`): single-threaded executor. The borrow is
/// always dropped before the registry `ask` — never held across an await.
pub(crate) type MetaCache = RefCell<HashMap<u32, MetaEntry>>;

pub(crate) struct Inner {
    /// Host-bound listen port (the host owns the listener in transport
    /// mode). Set once at construction from the configured port; the
    /// gateway reports it via `/__status` + `/__metrics` but never binds
    /// or unbinds itself. The authoritative stopped/running signal is
    /// host-side (`vosx <agent> describe` → the node's `agent_shutdown`
    /// flag), not this field. Immutable after construction.
    pub(crate) bound_port: u16,
    /// Unix epoch seconds when the gateway instance was constructed.
    /// Immutable after construction.
    pub(crate) started_unix: u64,
    /// Total HTTP requests dispatched past the auth gate since boot.
    pub(crate) requests: Cell<u64>,
    /// Operator-supplied config: bind address, tokens, TLS paths.
    /// Set once at construction; read by every connection task.
    pub(crate) cfg: GatewayConfig,
    /// Per-agent schema cache. See [`MetaCache`] for semantics.
    pub(crate) meta_cache: MetaCache,
    /// Aggregate counters surfaced via `/__metrics`. See [`Metrics`].
    pub(crate) metrics: Metrics,
    /// Parsed per-agent Bearer tokens map, derived from
    /// `cfg.agent_tokens`. Populated once at construction so the
    /// hot path doesn't re-parse on every request.
    pub(crate) agent_tokens: HashMap<String, String>,
    /// `Some(reason)` when the config failed validation (today: a
    /// malformed `agent_tokens` string). In transport mode `new()`
    /// can't refuse to boot — the host owns the listener — so a
    /// misconfigured gateway constructs but **refuses every request
    /// with `503`** rather than serving with weakened auth. `None`
    /// when the config is sound. Immutable after construction.
    pub(crate) config_error: Option<String>,
}

/// Counters powering the `/__metrics` Prometheus endpoint. Designed to
/// be additive — new gauges/counters just land here and get emitted by
/// `render_prometheus`. `Cell` (not atomics): single-threaded executor.
#[derive(Default)]
pub(crate) struct Metrics {
    pub(crate) responses_2xx: Cell<u64>,
    pub(crate) responses_3xx: Cell<u64>,
    pub(crate) responses_4xx: Cell<u64>,
    pub(crate) responses_5xx: Cell<u64>,
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
        bucket.set(bucket.get() + 1);
    }
}

impl Inner {
    /// Build the per-instance runtime state for a transport-mode gateway
    ///. Always succeeds so the `#[messages]` `new()`
    /// constructor (which can't return an error) gets a live `Inner`
    /// eagerly — under `&self` + N concurrent connection tasks the state
    /// must exist at construction, since there is no later mutable
    /// entry point to populate it.
    ///
    /// `port` is the host-bound listen port (the host owns the listener;
    /// the gateway only reports it via `/__status` + `/__metrics`).
    /// `started_unix` is stamped now. A malformed `agent_tokens` is
    /// **not** silently dropped: it lands in `config_error`, the parsed
    /// map is left empty, and `handle_connection` answers `503` to every
    /// request — refusing to serve rather than boot with weakened auth.
    pub(crate) fn new(cfg: GatewayConfig, port: u16) -> Self {
        let (agent_tokens, config_error) = match cfg.parse_agent_tokens() {
            Ok(m) => (m, None),
            Err(e) => (HashMap::new(), Some(e)),
        };
        Self {
            bound_port: port,
            started_unix: now_unix(),
            requests: Cell::new(0),
            cfg,
            meta_cache: RefCell::new(HashMap::new()),
            metrics: Metrics::default(),
            agent_tokens,
            config_error,
        }
    }

    /// `true` when the gateway is serving real traffic — it has a bound
    /// port and a sound config. A config error (malformed `agent_tokens`)
    /// makes it refuse every request (`503`), so it reports `running =
    /// false` even though it's reachable. NOTE: this is the gateway's own
    /// view; the **host-side** `vosx <agent> describe` (the node's
    /// `agent_shutdown` flag) is the authoritative stopped signal — after a
    /// `stop` the host closes the listener, so a stopped gateway isn't
    /// reachable to report anything anyway.
    pub(crate) fn running(&self) -> bool {
        self.bound_port != 0 && self.config_error.is_none()
    }
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Compact JSON liveness snapshot served at `GET /__status`.
pub(crate) fn status_json(inner: &Inner) -> String {
    let started = inner.started_unix;
    let uptime = if started == 0 {
        0
    } else {
        now_unix().saturating_sub(started)
    };
    serde_json::json!({
        "port": inner.bound_port,
        "running": inner.running(),
        "requests": inner.requests.get(),
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
/// underlying counter in the relevant code path. The `vos_gateway_*`
/// namespace stays — future per-actor labelled series should use
/// `vos_gateway_actor_*` so a scraper can group them and the Prometheus
/// regex matchers stay shallow.
pub(crate) fn render_prometheus(inner: &Inner) -> String {
    let started = inner.started_unix;
    let uptime = if started == 0 {
        0
    } else {
        now_unix().saturating_sub(started)
    };
    let up = if inner.running() { 1 } else { 0 };
    let port = inner.bound_port;
    let dispatched = inner.requests.get();
    let r2xx = inner.metrics.responses_2xx.get();
    let r3xx = inner.metrics.responses_3xx.get();
    let r4xx = inner.metrics.responses_4xx.get();
    let r5xx = inner.metrics.responses_5xx.get();

    let mut out = String::with_capacity(1024);

    out.push_str(
        "# HELP vos_gateway_up Gateway serving flag (1=reachable+config-ok, 0=config error). \
         Authoritative stopped state is host-side: `vosx <agent> describe`.\n",
    );
    out.push_str("# TYPE vos_gateway_up gauge\n");
    out.push_str(&format!("vos_gateway_up {up}\n"));

    out.push_str("# HELP vos_gateway_port TCP port the gateway is bound to.\n");
    out.push_str("# TYPE vos_gateway_port gauge\n");
    out.push_str(&format!("vos_gateway_port {port}\n"));

    out.push_str(
        "# HELP vos_gateway_uptime_seconds Seconds since the gateway instance was constructed.\n",
    );
    out.push_str("# TYPE vos_gateway_uptime_seconds gauge\n");
    out.push_str(&format!("vos_gateway_uptime_seconds {uptime}\n"));

    // (No vos_gateway_in_flight: the host owns the accept loop and
    // tracks live connections, so the gateway can't observe that count.)

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
