//! What a driver counts: each kind's sends, answers, latencies and
//! refusals by name, an interval at a time and over the whole load; and
//! the driver's own CPU.

use std::collections::BTreeMap;

use vos_wire::Decode;
use vos_wire::abi::AttestError;
use vos_wire::ingress::{Response, WorkflowStatus};
use vos_wire::result::Outcome;

use crate::drive::Plan;
use crate::histogram::Histogram;
use crate::load::Kind;

/// A refusal's name: its variant, and for `Rejected`, `Refused` and a
/// failed outcome, the inner one.
pub fn refusal(answer: &Result<Response, String>) -> String {
    let response = match answer {
        Ok(response) => response,
        Err(error) => return format!("client: {error}"),
    };
    let name = match response {
        Response::Ran {
            outcome: Outcome::Failed { code, detail },
            ..
        }
        | Response::Workflow {
            status: WorkflowStatus::Ended(Outcome::Failed { code, detail }),
            ..
        } => {
            return match AttestError::decode(detail) {
                Ok((error, _)) if *code == vos_wire::abi::Failure::Handler => {
                    format!("Failed({code:?}: {error:?})")
                }
                _ => format!("Failed({code:?})"),
            };
        }
        Response::Rejected(rejection) => return format!("Rejected({})", variant(rejection)),
        Response::Refused(refused) => return format!("Refused({})", variant(refused)),
        Response::Workflow { status, .. } => return format!("Workflow({})", variant(status)),
        Response::Ran { .. } => "Ran",
        Response::NotConsumed => "NotConsumed",
        Response::Busy => "Busy",
        Response::NoAgent => "NoAgent",
        Response::Stopped => "Stopped",
        Response::Created(_) => "Created",
        Response::Unavailable => "Unavailable",
        Response::NotLeader { .. } => "NotLeader",
        Response::Elsewhere { .. } => "Elsewhere",
        Response::Unconfirmed(_) => "Unconfirmed",
        Response::TimedOut => "TimedOut",
        Response::Placed(_) => "Placed",
        Response::Unplaced(_) => "Unplaced",
        Response::Status(_) => "Status",
        Response::Stats(_) => "Stats",
    };
    name.to_string()
}

/// A small enum's variant, by the first word its `Debug` writes.
fn variant(value: &impl std::fmt::Debug) -> String {
    let text = format!("{value:?}");
    text.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .find(|word| !word.is_empty())
        .unwrap_or("?")
        .to_string()
}

/// One kind's counts over an interval, or the whole load.
#[derive(Clone, Default)]
pub struct KindStats {
    pub sent: u64,
    pub ok: u64,
    pub latency: Histogram,
    pub errors: BTreeMap<String, u64>,
    /// How long the refused took to be answered.
    pub refused: Histogram,
    /// Sends more than [`crate::drive::LATE_US`] behind their schedule,
    /// and the latest.
    pub late_sends: u64,
    pub late_us: u64,
    /// Calls that waited behind their user's last, unanswered one.
    pub queued: u64,
    /// Transfers to another shard.
    pub cross: u64,
    /// Signatures the sending thread made: calls signed again for their
    /// turn, and the reads of workflows and cuts.
    pub signed: u64,
    /// Reads at a cut still open when the driver gave up on them, their
    /// window closing after the load's last send: the run ended before
    /// the window could close, so they are neither answered nor errors.
    pub not_closed: u64,
}

impl KindStats {
    pub fn absorb(&mut self, other: &KindStats) {
        self.sent += other.sent;
        self.ok += other.ok;
        self.latency.add(&other.latency);
        self.refused.add(&other.refused);
        for (kind, count) in &other.errors {
            *self.errors.entry(kind.clone()).or_default() += count;
        }
        self.late_sends += other.late_sends;
        self.late_us = self.late_us.max(other.late_us);
        self.queued += other.queued;
        self.cross += other.cross;
        self.signed += other.signed;
        self.not_closed += other.not_closed;
    }

    pub fn line(&self, t_ms: u64, seconds: f64, kind: &str, total: bool) -> serde_json::Value {
        let errors: u64 = self.errors.values().sum();
        let seconds = seconds.max(1e-9);
        serde_json::json!({
            "t_ms": t_ms,
            "total": total,
            "kind": kind,
            "sent": self.sent,
            "offered": self.sent as f64 / seconds,
            "ok": self.ok,
            "errors": errors,
            "by_error": self.errors,
            "rate": self.ok as f64 / seconds,
            "p50_us": self.latency.quantile(0.5),
            "p99_us": self.latency.quantile(0.99),
            "p999_us": self.latency.quantile(0.999),
            "refused_p50_us": self.refused.quantile(0.5),
            "refused_p99_us": self.refused.quantile(0.99),
            "late_us": self.late_us,
            "late_sends": self.late_sends,
            "queued": self.queued,
            "cross": self.cross,
            "signed_sending": self.signed,
            "not_closed": self.not_closed,
        })
    }
}

/// The kinds a record reports: the mix's, the identity writes, the
/// agents' reads at a cut, and the reads that wait for a cut's close.
pub const REPORTED: [&str; 8] = [
    "transfer",
    "query",
    "workflow",
    "cut",
    "cut_read",
    "identity",
    "reader",
    "reader_read",
];

#[derive(Default)]
pub struct Stats {
    pub kinds: BTreeMap<&'static str, KindStats>,
}

impl Stats {
    pub fn kind(&mut self, name: &'static str) -> &mut KindStats {
        self.kinds.entry(name).or_default()
    }

    /// The mix's kinds together.
    pub fn mix(&self) -> KindStats {
        let mut all = KindStats::default();
        for kind in Kind::MIX {
            if let Some(stats) = self.kinds.get(kind.name()) {
                all.absorb(stats);
            }
        }
        all
    }
}

/// This process's threads' CPU time so far, in seconds, by name.
pub fn thread_seconds() -> BTreeMap<String, f64> {
    // SAFETY: `sysconf` reads a constant.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as f64;
    let mut threads = BTreeMap::new();
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        return threads;
    };
    for task in tasks.flatten() {
        let Ok(stat) = std::fs::read_to_string(task.path().join("stat")) else {
            continue;
        };
        // `pid (comm) state ...`: utime and stime the 14th and 15th fields.
        let (Some(open), Some(close)) = (stat.find('('), stat.rfind(')')) else {
            continue;
        };
        let name = stat[open + 1..close].to_string();
        let fields: Vec<&str> = stat[close + 2..].split(' ').collect();
        let used: f64 = fields
            .get(11..13)
            .map(|times| {
                times
                    .iter()
                    .filter_map(|time| time.parse::<f64>().ok())
                    .sum()
            })
            .unwrap_or(0.0);
        *threads.entry(name).or_default() += used / ticks;
    }
    threads
}

/// This process's CPU time so far, user and system, in seconds.
pub fn cpu_seconds() -> f64 {
    // SAFETY: `getrusage` writes the struct it is given.
    let usage = unsafe {
        let mut usage = std::mem::zeroed::<libc::rusage>();
        libc::getrusage(libc::RUSAGE_SELF, &mut usage);
        usage
    };
    let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1e6;
    seconds(usage.ru_utime) + seconds(usage.ru_stime)
}

/// The mix as sent against its target: each kind's share, and the
/// transfers' cross-shard share.
pub fn mix_line(plan: &Plan, whole: &BTreeMap<&str, KindStats>) -> serde_json::Value {
    let sent = |name: &str| whole.get(name).map_or(0, |stats| stats.sent);
    let total: u64 = Kind::MIX.iter().map(|kind| sent(kind.name())).sum();
    let mut kinds = serde_json::Map::new();
    let mut worst: f64 = 0.0;
    for kind in Kind::MIX {
        let target = plan.model.shares.of(kind);
        let share = sent(kind.name()) as f64 / total.max(1) as f64;
        worst = worst.max((share - target).abs());
        kinds.insert(
            kind.name().into(),
            serde_json::json!({ "target": target, "sent": share }),
        );
    }
    let transfers = sent("transfer");
    let cross = whole.get("transfer").map_or(0, |stats| stats.cross);
    let cross_share = cross as f64 / transfers.max(1) as f64;
    worst = worst.max((cross_share - plan.model.cross).abs());
    serde_json::json!({
        "kinds": kinds,
        "cross": { "target": plan.model.cross, "sent": cross_share },
        "worst_error": worst,
    })
}

#[cfg(test)]
mod tests {
    use super::{KindStats, refusal};
    use vos_wire::Encode;
    use vos_wire::abi::{AttestError, Failure, Refusal};
    use vos_wire::ingress::{Rejection, Response, WorkflowStatus};
    use vos_wire::result::Outcome;

    #[test]
    fn a_refusal_is_named_by_its_variant_and_the_inner_one() {
        let named = |answer: Response| refusal(&Ok(answer));
        assert_eq!(named(Response::Busy), "Busy");
        assert_eq!(named(Response::NotLeader { leader: None }), "NotLeader");
        assert_eq!(
            named(Response::Rejected(Rejection::Gap { expected: 3 })),
            "Rejected(Gap)"
        );
        assert_eq!(
            named(Response::Refused(Refusal::SessionsFull)),
            "Refused(SessionsFull)"
        );
        let closed = Outcome::Failed {
            code: Failure::Handler,
            detail: AttestError::NotClosed.encode(),
        };
        assert_eq!(
            named(Response::Workflow {
                status: WorkflowStatus::Ended(closed),
                at: 1
            }),
            "Failed(Handler: NotClosed)"
        );
        assert_eq!(
            named(Response::Workflow {
                status: WorkflowStatus::Running,
                at: 1
            }),
            "Workflow(Running)"
        );
        assert_eq!(refusal(&Err("timed out".into())), "client: timed out");
    }

    /// A read left open by the run's end is counted apart from the errors,
    /// in an interval's line and in the totals.
    #[test]
    fn reads_not_closed_in_the_run_are_not_errors() {
        let interval = KindStats {
            sent: 3,
            ok: 1,
            not_closed: 2,
            ..KindStats::default()
        };
        let mut whole = KindStats::default();
        whole.absorb(&interval);
        whole.absorb(&interval);
        let line = whole.line(0, 1.0, "cut_read", true);
        assert_eq!(line["not_closed"], 4);
        assert_eq!(line["errors"], 0);
        assert_eq!(line["ok"], 2);
    }
}
