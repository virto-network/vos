//! Thread-safe runtime state shared by all built-in HTTP connections.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::metadata::ParsedMeta;
use crate::service::ActorId;

pub(crate) const META_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Clone)]
pub(crate) struct MetaEntry {
    pub(crate) meta: Option<ParsedMeta>,
    pub(crate) fetched_at: Instant,
}

pub(crate) type MetaCache = Mutex<HashMap<ActorId, MetaEntry>>;

pub(crate) struct Inner {
    pub(crate) bound_port: u16,
    pub(crate) started_unix: u64,
    pub(crate) requests: AtomicU64,
    pub(crate) meta_cache: MetaCache,
    pub(crate) metrics: Metrics,
}

#[derive(Default)]
pub(crate) struct Metrics {
    pub(crate) responses_2xx: AtomicU64,
    pub(crate) responses_3xx: AtomicU64,
    pub(crate) responses_4xx: AtomicU64,
    pub(crate) responses_5xx: AtomicU64,
}

impl Metrics {
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
    pub(crate) fn new(port: u16) -> Self {
        Self {
            bound_port: port,
            started_unix: now_unix(),
            requests: AtomicU64::new(0),
            meta_cache: Mutex::new(HashMap::new()),
            metrics: Metrics::default(),
        }
    }
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub(crate) fn status_json(inner: &Inner) -> String {
    let uptime = now_unix().saturating_sub(inner.started_unix);
    serde_json::json!({
        "status": "ok",
        "port": inner.bound_port,
        "uptime_secs": uptime,
    })
    .to_string()
}

pub(crate) fn render_prometheus(inner: &Inner) -> String {
    let uptime = now_unix().saturating_sub(inner.started_unix);
    let dispatched = inner.requests.load(Ordering::Relaxed);
    let r2xx = inner.metrics.responses_2xx.load(Ordering::Relaxed);
    let r3xx = inner.metrics.responses_3xx.load(Ordering::Relaxed);
    let r4xx = inner.metrics.responses_4xx.load(Ordering::Relaxed);
    let r5xx = inner.metrics.responses_5xx.load(Ordering::Relaxed);
    format!(
        "# TYPE vos_ingress_up gauge\nvos_ingress_up 1\n\
         # TYPE vos_ingress_uptime_seconds gauge\nvos_ingress_uptime_seconds {uptime}\n\
         # TYPE vos_ingress_requests_total counter\nvos_ingress_requests_total {dispatched}\n\
         # TYPE vos_ingress_responses_total counter\n\
         vos_ingress_responses_total{{status_class=\"2xx\"}} {r2xx}\n\
         vos_ingress_responses_total{{status_class=\"3xx\"}} {r3xx}\n\
         vos_ingress_responses_total{{status_class=\"4xx\"}} {r4xx}\n\
         vos_ingress_responses_total{{status_class=\"5xx\"}} {r5xx}\n"
    )
}
