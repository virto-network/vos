//! `report`: a run's summary, from its hosts' samples, its nodes' polls
//! and its drivers' records, over a window of the run (the drivers' span
//! by default; at the knee, the step the knee was found at). Each host's
//! binding resource is the most used of its CPU (its node's, against the
//! cores it may use), its busiest thread against one core, iowait, its
//! data disk's busy time and its link against its speed. The slowest node
//! host is the one whose node's commits' p99 is the highest. `--compare`
//! sets two runs side by side, as a run again without the slowest host
//! (four node hosts at least) needs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::check::Facts;
use crate::histogram::quantile;
use crate::runs::Run;
use crate::sample::Sample;

/// Where the mix's defaults come from, stated in every report.
pub const MIX_DEFAULTS: &str = "the mix's defaults (transfers 80%, queries 15%, workflows 4.5%, reads at a cut 0.5%) are the harness's own, pending the owner's";

/// What the runs do not model, stated in every report.
pub const NOT_MODELED: &str = "not modeled: the per-call identity read, credentialed calls (measured at 7.11), cross-space traffic, proving";

/// T2's assumption, stated in every report with the run's `K`.
pub const T2: &str = "T2's \"room for 8 million users\" assumes K scales with users: an agent holds at most 65,536 sessions, so 8 million users need K >= 128 ledger agents; the agent is the unit of scaling";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HostSummary {
    pub name: String,
    pub role: String,
    pub seconds: f64,
    /// The node's CPU in cores, and as a share of the cores it may use.
    pub process_cores: f64,
    pub process_cpu_pct: f64,
    /// The host's CPU busy and iowait, as shares of all its cores.
    pub host_busy_pct: f64,
    pub iowait_pct: f64,
    pub disk_util_pct: Option<f64>,
    pub disk_write_mb_s: Option<f64>,
    /// The mean time a disk request waited and ran.
    pub disk_ms_per_io: Option<f64>,
    pub link_mbps: Option<f64>,
    pub link_rx_mb_s: Option<f64>,
    pub link_tx_mb_s: Option<f64>,
    pub link_util_pct: Option<f64>,
    pub rss_mib: f64,
    pub rss_max_mib: f64,
    pub wakes_per_s: f64,
    /// Its threads' preemptions a second: the host's other work taking
    /// their cores.
    #[serde(default)]
    pub preempted_per_s: f64,
    /// The busiest threads, those of one name together: name and share
    /// of one core.
    pub threads: Vec<(String, f64)>,
    /// The busiest single thread, as a share of one core: a thread at
    /// 100% binds however idle the host's other cores are.
    pub busiest_thread: Option<(String, f64)>,
    /// The cores' mean clock against their top, over the window.
    pub clock_pct: Option<f64>,
    pub binding: String,
    pub binding_pct: f64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NodeSummary {
    pub node: u64,
    /// The host it ran on.
    pub host: String,
    /// The groups it led at the window's end, and the elections its
    /// groups held within it (their terms' sum's growth).
    pub leading: u64,
    pub elections: u64,
    /// Stage quantiles over the window, in microseconds: `commit`, `late`,
    /// `batch`, `queued`, and the waits for an executor (`refine_queue`,
    /// `dry_run_queue`, `root_build_queue`) with the root builds' runs.
    pub stages: BTreeMap<String, (u64, u64, u64)>,
    pub halted: bool,
    pub poll_errors: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DriverSummary {
    pub name: String,
    pub ok: u64,
    pub errors: u64,
    pub by_error: BTreeMap<String, u64>,
    pub rate: f64,
    pub p50_us: u64,
    pub p99_us: u64,
    pub p999_us: u64,
    /// The latest a send went behind its schedule, and the share of sends
    /// later than the driver's bound: a driver behind is what bound.
    pub late_us: u64,
    pub late_share: f64,
    /// Calls a second it sent, of the mix; the CPU it used, in cores.
    pub offered: f64,
    pub cores: f64,
    /// Each kind apart: the mix's, the reads waiting for a cut's close
    /// (`cut_read`, timed from the close) and the identity writes.
    pub kinds: BTreeMap<String, KindSummary>,
    /// The mix as sent against its target: the worst share's distance.
    pub mix_error: f64,
    pub mix: serde_json::Value,
    /// Requests that waited for a connection, the most in use at once on
    /// one node, and the cap a node.
    pub conn_waits: u64,
    pub in_use_max: u64,
    pub connections: u64,
    /// Each shard's distinct users and the sessions opened at it.
    pub shard_users: Vec<u64>,
    pub shard_sessions: Vec<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct KindSummary {
    pub sent: u64,
    pub ok: u64,
    pub errors: u64,
    pub by_error: BTreeMap<String, u64>,
    pub rate: f64,
    pub p50_us: u64,
    pub p99_us: u64,
    pub p999_us: u64,
}

/// The kinds a report lists, in its order.
const KINDS: [&str; 8] = [
    "transfer",
    "query",
    "workflow",
    "cut",
    "cut_read",
    "identity",
    "reader",
    "reader_read",
];

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Summary {
    pub run: String,
    pub versions: serde_json::Value,
    pub agents: usize,
    pub window_ms: (u64, u64),
    pub hosts: Vec<HostSummary>,
    pub nodes: Vec<NodeSummary>,
    pub drivers: Vec<DriverSummary>,
    pub rate: f64,
    pub leader_changes: u64,
    pub slowest: Option<String>,
    pub warnings: Vec<String>,
    pub not_modeled: String,
    pub t2: String,
    /// The load model the drivers ran: `U`, `a`, `r`, the mix, `x`.
    pub model: serde_json::Value,
}

fn jsonl<T: for<'de> Deserialize<'de>>(path: &Path) -> Vec<T> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn delta(first: u64, last: u64) -> f64 {
    last.saturating_sub(first) as f64
}

/// A host's summary over its samples `first` to `last`.
pub fn host_summary(facts: &Facts, samples: &[&Sample]) -> HostSummary {
    let mut summary = HostSummary {
        name: facts.name.clone(),
        role: facts.role.clone(),
        ..HostSummary::default()
    };
    let (Some(first), Some(last)) = (samples.first(), samples.last()) else {
        summary.binding = "no samples".into();
        return summary;
    };
    let seconds = (last.t_ms.saturating_sub(first.t_ms) as f64 / 1e3).max(1e-9);
    summary.seconds = seconds;
    let tck = facts.number("clk_tck").unwrap_or(100) as f64;
    let cpu = |sample: &Sample, kind: &str| sample.cpu.get(kind).copied().unwrap_or(0);
    let total: f64 = first
        .cpu
        .keys()
        .map(|kind| delta(cpu(first, kind), cpu(last, kind)))
        .sum::<f64>()
        .max(1.0);
    let idle = delta(cpu(first, "idle"), cpu(last, "idle"));
    let iowait = delta(cpu(first, "iowait"), cpu(last, "iowait"));
    summary.host_busy_pct = 100.0 * (total - idle - iowait) / total;
    summary.iowait_pct = 100.0 * iowait / total;
    let mut candidates = vec![
        ("CPU (host)".to_string(), summary.host_busy_pct),
        ("iowait".to_string(), summary.iowait_pct),
    ];
    // The process over the samples that saw it: a driver starts after its
    // sampler, and a restarted node is followed from its restart.
    let end = samples
        .iter()
        .rev()
        .find_map(|sample| Some((sample.t_ms, sample.process.as_ref()?)));
    let begin = end.and_then(|(_, end)| {
        samples.iter().find_map(|sample| {
            let process = sample
                .process
                .as_ref()
                .filter(|process| process.pid == end.pid)?;
            Some((sample.t_ms, process))
        })
    });
    if let (Some((since, begin)), Some((until, end))) = (begin, end)
        && until > since
    {
        let seconds = (until - since) as f64 / 1e3;
        let before: BTreeMap<u32, &crate::sample::Thread> = begin
            .threads
            .iter()
            .map(|thread| (thread.tid, thread))
            .collect();
        let mut threads: Vec<(String, f64)> = Vec::new();
        let mut busiest: Option<(String, f64)> = None;
        let mut wakes = 0.0;
        let mut preempted = 0.0;
        for thread in &end.threads {
            preempted += match before.get(&thread.tid) {
                Some(old) => delta(old.involuntary, thread.involuntary),
                None => thread.involuntary as f64,
            };
            let (ticks, voluntary) = match before.get(&thread.tid) {
                Some(old) => (
                    delta(old.utime + old.stime, thread.utime + thread.stime),
                    delta(old.voluntary, thread.voluntary),
                ),
                None => (
                    (thread.utime + thread.stime) as f64,
                    thread.voluntary as f64,
                ),
            };
            let pct = 100.0 * ticks / tck / seconds;
            if busiest.as_ref().is_none_or(|(_, most)| pct > *most) {
                busiest = Some((format!("{} ({})", thread.comm, thread.tid), pct));
            }
            threads.push((thread.comm.clone(), pct));
            wakes += voluntary;
        }
        // The process's own totals hold its ended threads too.
        summary.process_cores =
            delta(begin.utime + begin.stime, end.utime + end.stime) / tck / seconds;
        summary.process_cpu_pct = 100.0 * summary.process_cores / facts.cores_used().max(1) as f64;
        summary.wakes_per_s = wakes / seconds;
        summary.preempted_per_s = preempted / seconds;
        let mut named: BTreeMap<String, f64> = BTreeMap::new();
        for (name, pct) in threads {
            *named.entry(name).or_default() += pct;
        }
        let mut threads: Vec<(String, f64)> = named.into_iter().collect();
        threads.sort_by(|a, b| b.1.total_cmp(&a.1));
        threads.truncate(5);
        summary.threads = threads;
        summary.rss_mib = end.rss_kb as f64 / 1024.0;
        candidates[0] = ("CPU".to_string(), summary.process_cpu_pct);
        if let Some((name, pct)) = &busiest {
            candidates.push((format!("thread {name}"), *pct));
        }
        summary.busiest_thread = busiest;
    }
    let clocks: Vec<f64> = samples
        .iter()
        .filter_map(|sample| {
            Some(
                100.0 * sample.freq_khz? as f64
                    / sample.freq_max_khz.filter(|top| *top > 0)? as f64,
            )
        })
        .collect();
    summary.clock_pct =
        (!clocks.is_empty()).then(|| clocks.iter().sum::<f64>() / clocks.len() as f64);
    summary.rss_max_mib = samples
        .iter()
        .filter_map(|sample| sample.process.as_ref())
        .map(|process| process.rss_kb as f64 / 1024.0)
        .fold(0.0, f64::max);
    if let (Some(begin), Some(end)) = (&first.disk, &last.disk) {
        let util = 100.0 * delta(begin.io_ms, end.io_ms) / (seconds * 1e3);
        summary.disk_util_pct = Some(util);
        summary.disk_write_mb_s =
            Some(delta(begin.write_sectors, end.write_sectors) * 512.0 / 1e6 / seconds);
        let ios = delta(begin.reads + begin.writes, end.reads + end.writes);
        summary.disk_ms_per_io =
            (ios > 0.0).then(|| delta(begin.weighted_ms, end.weighted_ms) / ios);
        candidates.push(("disk".to_string(), util));
    }
    if let (Some(rx0), Some(rx1), Some(tx0), Some(tx1)) =
        (first.rx_bytes, last.rx_bytes, first.tx_bytes, last.tx_bytes)
    {
        let (rx, tx) = (
            delta(rx0, rx1) / 1e6 / seconds,
            delta(tx0, tx1) / 1e6 / seconds,
        );
        summary.link_rx_mb_s = Some(rx);
        summary.link_tx_mb_s = Some(tx);
        let speed = facts
            .number("link_mbps")
            .filter(|speed| *speed > 0 && *speed < 1 << 31 && facts.get("iface") != Some("lo"));
        if let Some(speed) = speed {
            summary.link_mbps = Some(speed as f64);
            let util = 100.0 * rx.max(tx) * 8.0 / speed as f64;
            summary.link_util_pct = Some(util);
            candidates.push(("NIC".to_string(), util));
        }
    }
    let (binding, pct) = candidates
        .into_iter()
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .expect("CPU at least");
    summary.binding = binding;
    summary.binding_pct = pct;
    summary
}

/// The stages' quantiles between two polls' cumulative histograms.
fn stage_quantiles(
    first: &serde_json::Value,
    last: &serde_json::Value,
    stage: &str,
) -> Option<(u64, u64, u64)> {
    let counts = |poll: &serde_json::Value| -> Vec<u64> {
        let mut counts = vec![0u64; vos_wire::ingress::BUCKETS];
        if let Some(buckets) = poll["stats"][stage]["buckets"].as_object() {
            for (index, count) in buckets {
                if let (Ok(index), Some(count)) = (index.parse::<usize>(), count.as_u64())
                    && index < counts.len()
                {
                    counts[index] = count;
                }
            }
        }
        counts
    };
    let (before, after) = (counts(first), counts(last));
    let window: Vec<u64> = after
        .iter()
        .zip(&before)
        .map(|(after, before)| after.saturating_sub(*before))
        .collect();
    (window.iter().sum::<u64>() > 0).then(|| {
        (
            quantile(&window, 0.5),
            quantile(&window, 0.99),
            quantile(&window, 0.999),
        )
    })
}

/// Summarise `run` over `window` (milliseconds since the epoch), the
/// drivers' span when `None`; written to the run's `summary.json` and
/// `report.txt`.
/// A share of late sends above which the driver, not the nodes, may have
/// bound the run.
const LATE_SHARE: f64 = 0.01;

/// The sampling interval the run's inventory names.
fn every_s(run: &Run) -> u64 {
    std::fs::read_to_string(run.file("inventory.toml"))
        .ok()
        .and_then(|text| text.parse::<toml::Table>().ok())
        .and_then(|table| table.get("harness")?.get("every_s")?.as_integer())
        .map_or(10, |every| every.max(1) as u64)
}

pub fn report(
    run: &Run,
    window: Option<(u64, u64)>,
    ramp_s: Option<u64>,
) -> Result<Summary, String> {
    let facts: Vec<Facts> = serde_json::from_str(
        &std::fs::read_to_string(run.file("hosts.json"))
            .map_err(|error| format!("{}: {error}", run.file("hosts.json").display()))?,
    )
    .map_err(|error| error.to_string())?;
    let deployed: serde_json::Value = std::fs::read_to_string(run.file("deployed.json"))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default();
    let agents: serde_json::Value = std::fs::read_to_string(run.file("agents.json"))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default();
    let host_dir = |name: &str| run.dir.join("hosts").join(name);
    let records: Vec<(String, Vec<serde_json::Value>)> = facts
        .iter()
        .filter(|host| host.role == "driver")
        .map(|host| {
            let path = host_dir(&host.name).join(format!("{}.drive.jsonl", run.id));
            (host.name.clone(), jsonl(&path))
        })
        .collect();
    let intervals: Vec<&serde_json::Value> = records
        .iter()
        .flat_map(|(_, lines)| lines)
        .filter(|line| line["total"] == false)
        .collect();
    // By default the drivers' load, from the first send to the last, past
    // its ramp: the drain after it, waiting for the last answers, is left
    // out. A record without the load's span gives its intervals' span: an
    // interval's line is written at its end, so the span starts an interval
    // before the first. The ramp is an interval unless said otherwise,
    // dropped if it would leave no window.
    let every_ms = every_s(run) * 1_000;
    let ramp_ms = ramp_s.map_or(every_ms, |ramp| ramp * 1_000);
    let loads: Vec<(u64, u64)> = records
        .iter()
        .filter_map(|(_, lines)| {
            let total = lines
                .iter()
                .rfind(|line| line["total"] == true && line["kind"] == "all")?;
            Some((
                total["load_from_ms"].as_u64()?,
                total["load_to_ms"].as_u64()?,
            ))
        })
        .collect();
    let loaded = match (
        loads.iter().map(|load| load.0).min(),
        loads.iter().map(|load| load.1).max(),
    ) {
        (Some(from), Some(to)) => {
            let ramped = from + ramp_ms;
            Some((if ramped < to { ramped } else { from }, to))
        }
        _ => None,
    };
    let window = window.or(loaded).unwrap_or_else(|| {
        let times: Vec<u64> = intervals
            .iter()
            .filter_map(|line| line["t_ms"].as_u64())
            .collect();
        match (times.iter().min(), times.iter().max()) {
            (Some(first), Some(last)) => {
                let start = first.saturating_sub(every_ms);
                let ramped = start + ramp_ms;
                (if ramped < *last { ramped } else { start }, *last)
            }
            _ => (0, u64::MAX),
        }
    });
    let mut summary = Summary {
        run: run.id.clone(),
        versions: deployed["versions"].clone(),
        agents: agents["agents"].as_array().map_or(0, Vec::len),
        window_ms: window,
        not_modeled: NOT_MODELED.into(),
        t2: T2.into(),
        model: facts
            .iter()
            .find(|host| host.role == "driver")
            .and_then(|host| {
                let text =
                    std::fs::read_to_string(run.file(&format!("drive-{}.json", host.name))).ok()?;
                serde_json::from_str::<serde_json::Value>(&text).ok()
            })
            .map(|plan| plan["model"].clone())
            .unwrap_or_default(),
        ..Summary::default()
    };
    for host in &facts {
        let samples: Vec<Sample> =
            jsonl(&host_dir(&host.name).join(format!("{}.samples.jsonl", run.id)));
        // The window's edges: the last sample at or before its start, the
        // first at or after its end.
        let start = samples
            .iter()
            .rposition(|sample| sample.t_ms <= window.0)
            .unwrap_or(0);
        let end = samples
            .iter()
            .position(|sample| sample.t_ms >= window.1)
            .unwrap_or(samples.len().saturating_sub(1));
        let within: Vec<&Sample> = samples
            .get(start..=end.max(start))
            .map(|samples| samples.iter().collect())
            .unwrap_or_default();
        summary.hosts.push(host_summary(host, &within));
        for warning in &host.warnings {
            summary.warnings.push(format!("{}: {warning}", host.name));
        }
    }
    let hosts_of: BTreeMap<u64, String> = deployed["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|node| Some((node["number"].as_u64()?, node["name"].as_str()?.to_string())))
        .collect();
    let polls: Vec<serde_json::Value> = jsonl(&run.file("nodes.jsonl"));
    let numbers: BTreeSet<u64> = polls
        .iter()
        .filter_map(|poll| poll["node"].as_u64())
        .collect();
    let mut terms: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
    for number in numbers {
        let mine: Vec<&serde_json::Value> = polls
            .iter()
            .filter(|poll| poll["node"].as_u64() == Some(number))
            .collect();
        let inside = |poll: &&&serde_json::Value| {
            poll["t_ms"]
                .as_u64()
                .is_some_and(|t| t >= window.0 && t <= window.1)
        };
        let first = mine
            .iter()
            .rev()
            .find(|poll| poll["t_ms"].as_u64().is_some_and(|t| t <= window.0))
            .or(mine.first());
        let last = mine.iter().rfind(&inside).or(mine.last());
        let mut node = NodeSummary {
            node: number,
            host: hosts_of.get(&number).cloned().unwrap_or_default(),
            ..NodeSummary::default()
        };
        if let (Some(first), Some(last)) = (first, last) {
            node.leading = last["groups"]["leading"].as_u64().unwrap_or(0);
            if let (Some(before), Some(after)) = (
                first["groups"]["terms"].as_u64(),
                last["groups"]["terms"].as_u64(),
            ) {
                node.elections = after.saturating_sub(before);
            }
            for stage in [
                "commit",
                "late",
                "batch",
                "queued",
                "refine_queue",
                "dry_run_queue",
                "root_build_queue",
                "root_build",
            ] {
                if let Some(quantiles) = stage_quantiles(first, last, stage) {
                    node.stages.insert(stage.into(), quantiles);
                }
            }
        }
        for poll in mine.iter().filter(inside) {
            if poll["stats"]["error"].is_string() {
                node.poll_errors += 1;
            }
            for status in poll["statuses"].as_array().into_iter().flatten() {
                node.halted |= status["halted"] == true;
                if let (Some(agent), Some(term)) =
                    (status["agent"].as_u64(), status["term"].as_u64())
                {
                    let seen = terms.entry(agent).or_insert((term, term));
                    seen.0 = seen.0.min(term);
                    seen.1 = seen.1.max(term);
                }
            }
        }
        summary.nodes.push(node);
    }
    summary.leader_changes = terms.values().map(|(low, high)| high - low).sum();
    for (name, lines) in &records {
        let mut driver = DriverSummary {
            name: name.clone(),
            ..DriverSummary::default()
        };
        let totals: Vec<&serde_json::Value> =
            lines.iter().filter(|line| line["total"] == true).collect();
        for line in &totals {
            let kind = line["kind"].as_str().unwrap_or("all");
            if kind == "all" {
                continue;
            }
            driver.kinds.insert(
                kind.to_string(),
                KindSummary {
                    sent: line["sent"].as_u64().unwrap_or(0),
                    ok: line["ok"].as_u64().unwrap_or(0),
                    errors: line["errors"].as_u64().unwrap_or(0),
                    by_error: serde_json::from_value(line["by_error"].clone()).unwrap_or_default(),
                    rate: line["rate"].as_f64().unwrap_or(0.0),
                    p50_us: line["p50_us"].as_u64().unwrap_or(0),
                    p99_us: line["p99_us"].as_u64().unwrap_or(0),
                    p999_us: line["p999_us"].as_u64().unwrap_or(0),
                },
            );
        }
        if let Some(total) = totals.last() {
            driver.offered = total["offered"].as_f64().unwrap_or(0.0);
            driver.mix = total["mix"].clone();
            driver.mix_error = total["mix"]["worst_error"].as_f64().unwrap_or(0.0);
            driver.cores = total["load_cores"].as_f64().unwrap_or(0.0);
            driver.conn_waits = total["conn_waits"].as_u64().unwrap_or(0);
            driver.in_use_max = total["in_use_max"].as_u64().unwrap_or(0);
            driver.connections = total["connections"].as_u64().unwrap_or(0);
            driver.shard_users =
                serde_json::from_value(total["shard_users"].clone()).unwrap_or_default();
            driver.shard_sessions =
                serde_json::from_value(total["shard_sessions"].clone()).unwrap_or_default();
            driver.ok = total["ok"].as_u64().unwrap_or(0);
            driver.errors = total["errors"].as_u64().unwrap_or(0);
            driver.rate = total["rate"].as_f64().unwrap_or(0.0);
            driver.p50_us = total["p50_us"].as_u64().unwrap_or(0);
            driver.p99_us = total["p99_us"].as_u64().unwrap_or(0);
            driver.p999_us = total["p999_us"].as_u64().unwrap_or(0);
            driver.by_error = serde_json::from_value(total["by_error"].clone()).unwrap_or_default();
            driver.late_us = total["late_us"].as_u64().unwrap_or(0);
            let sent = total["sent"].as_u64().unwrap_or(0);
            if driver.conn_waits as f64 > LATE_SHARE * sent as f64 {
                summary.warnings.push(format!(
                    "driver {name}: {} of its {sent} requests waited for a connection, {} at once in use at most of {} a node: the pool bound; raise [harness] driver_connections with [node] ingress_connections",
                    driver.conn_waits, driver.in_use_max, driver.connections
                ));
            }
            driver.late_share =
                total["late_sends"].as_u64().unwrap_or(0) as f64 / sent.max(1) as f64;
            if driver.late_share > LATE_SHARE {
                summary.warnings.push(format!(
                    "driver {name}: {:.1}% of its sends went more than {} ms behind their schedule (at worst {} ms): the driver may be what bound, not the nodes",
                    100.0 * driver.late_share,
                    crate::drive::LATE_US / 1_000,
                    driver.late_us / 1_000
                ));
            }
        }
        summary.rate += driver.rate;
        summary.drivers.push(driver);
    }
    summary.slowest = slowest(&summary);
    let node_hosts = facts.iter().filter(|host| host.role == "node").count();
    if node_hosts < 4 {
        summary.warnings.push(format!(
            "{node_hosts} node hosts: a run without the slowest needs four at least, three replicas an agent"
        ));
    }
    for host in &summary.hosts {
        if host.role == "node" && host.clock_pct.is_some_and(|clock| clock < 70.0) {
            summary.warnings.push(format!(
                "{}: its cores ran at {:.0}% of their top clock: throttled or saving power",
                host.name,
                host.clock_pct.unwrap_or(0.0)
            ));
        }
    }
    std::fs::write(
        run.file("summary.json"),
        serde_json::to_string_pretty(&summary).expect("json"),
    )
    .map_err(|error| error.to_string())?;
    std::fs::write(run.file("report.txt"), text(&summary)).map_err(|error| error.to_string())?;
    Ok(summary)
}

/// The slowest node host: the node whose commits' p99 is the highest, its
/// host's disk time per I/O breaking ties; a group commits at its median
/// replica's fsync, so this host gates the groups it follows.
fn slowest(summary: &Summary) -> Option<String> {
    let disk = |host: &str| {
        summary
            .hosts
            .iter()
            .find(|summary| summary.name == host)
            .and_then(|summary| summary.disk_ms_per_io)
            .unwrap_or(0.0)
    };
    summary
        .nodes
        .iter()
        .filter(|node| !node.host.is_empty())
        .max_by(|a, b| {
            let commit = |node: &NodeSummary| node.stages.get("commit").map_or(0, |stage| stage.1);
            commit(a)
                .cmp(&commit(b))
                .then(disk(&a.host).total_cmp(&disk(&b.host)))
        })
        .map(|node| node.host.clone())
}

fn optional(value: Option<f64>) -> String {
    value.map_or("-".into(), |value| format!("{value:.1}"))
}

/// The summary as text.
pub fn text(summary: &Summary) -> String {
    let mut text = format!(
        "run {}\nversions {}\nagents (K) {}\nwindow {}..{} ms\n\n",
        summary.run, summary.versions, summary.agents, summary.window_ms.0, summary.window_ms.1
    );
    text += &format!(
        "{:<14} {:<6} {:>6} {:>6} {:>6} {:>6} {:>7} {:>7} {:>7} {:>7} {:>8} {:>8}  {}\n",
        "host",
        "role",
        "cores",
        "cpu%",
        "clock%",
        "iow%",
        "disk%",
        "ms/io",
        "nic%",
        "rssMiB",
        "wakes/s",
        "MB/s tx",
        "binding"
    );
    for host in &summary.hosts {
        text += &format!(
            "{:<14} {:<6} {:>6.2} {:>6.1} {:>6} {:>6.1} {:>7} {:>7} {:>7} {:>7.0} {:>8.0} {:>8}  {} {:.1}%\n",
            host.name,
            host.role,
            host.process_cores,
            host.process_cpu_pct,
            optional(host.clock_pct),
            host.iowait_pct,
            optional(host.disk_util_pct),
            optional(host.disk_ms_per_io),
            optional(host.link_util_pct),
            host.rss_mib,
            host.wakes_per_s,
            optional(host.link_tx_mb_s),
            host.binding,
            host.binding_pct,
        );
    }
    text += "\npreemptions a second (the host's other work taking a thread's core)\n";
    for host in &summary.hosts {
        text += &format!("  {}: {:.0}\n", host.name, host.preempted_per_s);
    }
    text += "\nbusiest threads (% of a core)\n";
    for host in summary.hosts.iter().filter(|host| !host.threads.is_empty()) {
        let threads: Vec<String> = host
            .threads
            .iter()
            .map(|(name, pct)| format!("{name} {pct:.1}"))
            .collect();
        text += &format!("  {}: {}\n", host.name, threads.join(", "));
    }
    text += "\nnode stages (p50 / p99 / p99.9, us)\n";
    for node in &summary.nodes {
        let stages: Vec<String> = node
            .stages
            .iter()
            .map(|(name, (p50, p99, p999))| format!("{name} {p50}/{p99}/{p999}"))
            .collect();
        text += &format!(
            "  node {} ({}): leads {}, {} elections; {}{}{}\n",
            node.node,
            node.host,
            node.leading,
            node.elections,
            stages.join(", "),
            if node.halted { ", HALTED" } else { "" },
            if node.poll_errors > 0 {
                format!(", {} polls failed", node.poll_errors)
            } else {
                String::new()
            },
        );
    }
    text += &format!("\nleader changes {}\n\ndrivers\n", summary.leader_changes);
    for driver in &summary.drivers {
        text += &format!(
            "  {}: {:.1} calls/s, {} ok, {} errors {:?}, p50 {} us, p99 {} us, p99.9 {} us; late at worst {} us, {:.2}% of sends past {} us\n",
            driver.name,
            driver.rate,
            driver.ok,
            driver.errors,
            driver.by_error,
            driver.p50_us,
            driver.p99_us,
            driver.p999_us,
            driver.late_us,
            100.0 * driver.late_share,
            crate::drive::LATE_US
        );
    }
    text += &format!("  all: {:.1} calls/s\n", summary.rate);
    for driver in &summary.drivers {
        text += &format!(
            "  {}: offered {:.1} calls/s on {:.2} cores; the mix within {:.2} points of its target\n",
            driver.name,
            driver.offered,
            driver.cores,
            100.0 * driver.mix_error
        );
        for kind in KINDS {
            if let Some(stats) = driver.kinds.get(kind) {
                text += &format!(
                    "    {kind:<9} {:>9} sent {:>9} ok {:>7} errors {:?}, {:.1}/s, p50 {} us, p99 {} us, p99.9 {} us\n",
                    stats.sent,
                    stats.ok,
                    stats.errors,
                    stats.by_error,
                    stats.rate,
                    stats.p50_us,
                    stats.p99_us,
                    stats.p999_us
                );
            }
        }
    }
    let model = &summary.model;
    if !model.is_null() {
        text += &format!(
            "  the model: U = {}, a = {}, r = {}, U·a·r = {:.0} calls/s; mix {}; x = {}; Zipf({})\n",
            model["users"],
            model["active"],
            model["per_user"],
            model["users"].as_f64().unwrap_or(0.0)
                * model["active"].as_f64().unwrap_or(0.0)
                * model["per_user"].as_f64().unwrap_or(0.0),
            model["shares"],
            model["cross"],
            model["zipf"]
        );
        text += &format!("  {MIX_DEFAULTS}\n");
    }
    for driver in &summary.drivers {
        if driver.shard_sessions.is_empty() {
            continue;
        }
        let most = |counts: &[u64]| counts.iter().max().copied().unwrap_or(0);
        text += &format!(
            "  {}: {} users and {} sessions over {} shards, {} users and {} sessions at the busiest; {} requests waited for a connection, {} in use at most of {} a node\n",
            driver.name,
            driver.shard_users.iter().sum::<u64>(),
            driver.shard_sessions.iter().sum::<u64>(),
            driver.shard_sessions.len(),
            most(&driver.shard_users),
            most(&driver.shard_sessions),
            driver.conn_waits,
            driver.in_use_max,
            driver.connections
        );
    }
    text += "\n";
    if let Some(slowest) = &summary.slowest {
        text += &format!(
            "slowest node host: {slowest} (its node's commits' p99 the highest): with four node hosts or more, rerun with --exclude {slowest} and compare\n"
        );
    }
    for warning in &summary.warnings {
        text += &format!("warning: {warning}\n");
    }
    text += &format!(
        "{}\n{} (this run: K = {})\n",
        summary.not_modeled, summary.t2, summary.agents
    );
    text
}

/// Two runs side by side: the drivers' rate and p99, and each host's
/// binding resource; a host in one run alone is named.
pub fn compare(this: &Summary, other: &Summary) -> String {
    let p99 = |summary: &Summary| {
        summary
            .drivers
            .iter()
            .map(|driver| driver.p99_us)
            .max()
            .unwrap_or(0)
    };
    let mut text = format!(
        "{:<24} {:>30} {:>30}\n{:<24} {:>30} {:>30}\n{:<24} {:>30.1} {:>30.1}\n{:<24} {:>30} {:>30}\n",
        "",
        "this",
        "other",
        "run",
        this.run,
        other.run,
        "calls/s",
        this.rate,
        other.rate,
        "p99 us (worst driver)",
        p99(this),
        p99(other)
    );
    let names: BTreeSet<&String> = this
        .hosts
        .iter()
        .chain(&other.hosts)
        .map(|host| &host.name)
        .collect();
    for name in names {
        let find = |summary: &Summary| {
            summary
                .hosts
                .iter()
                .find(|host| &host.name == name)
                .map_or("absent".to_string(), |host| {
                    format!("{} {:.1}%", host.binding, host.binding_pct)
                })
        };
        text += &format!("{name:<24} {:>30} {:>30}\n", find(this), find(other));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::{Summary, compare, host_summary, text};
    use crate::check::Facts;
    use crate::sample::{Disk, Process, Sample, Thread};

    fn facts() -> Facts {
        let mut facts = Facts {
            name: "a".into(),
            role: "node".into(),
            cores: Some("0-3".into()),
            ..Facts::default()
        };
        for (key, value) in [("clk_tck", "100"), ("iface", "eth0"), ("link_mbps", "1000")] {
            facts.probe.insert(key.into(), value.into());
        }
        facts
    }

    fn sample(t_ms: u64, busy: u64, ticks: u64, io_ms: u64, tx: u64) -> Sample {
        Sample {
            t_ms,
            cpu: [("user", busy), ("idle", 10_000 - busy), ("iowait", 0)]
                .into_iter()
                .map(|(kind, value)| (kind.to_string(), value))
                .collect(),
            process: Some(Process {
                pid: 7,
                utime: ticks,
                rss_kb: 1 << 20,
                threads: vec![Thread {
                    tid: 8,
                    comm: "vos runtime".into(),
                    utime: ticks,
                    ..Thread::default()
                }],
                ..Process::default()
            }),
            disk: Some(Disk {
                io_ms,
                ..Disk::default()
            }),
            rx_bytes: Some(0),
            tx_bytes: Some(tx),
            freq_khz: Some(2_000_000),
            freq_max_khz: Some(4_000_000),
        }
    }

    #[test]
    fn a_saturated_thread_binds_on_an_idle_host() {
        // Over 10 s one thread used 950 ticks: 95% of a core, a quarter of
        // the four the node may use, the disk idle.
        let first = sample(0, 0, 0, 0, 0);
        let last = sample(10_000, 950, 950, 0, 0);
        let summary = host_summary(&facts(), &[&first, &last]);
        assert!(
            (summary.process_cpu_pct - 23.75).abs() < 1e-6,
            "{}",
            summary.process_cpu_pct
        );
        assert_eq!(summary.binding, "thread vos runtime (8)");
        assert!((summary.binding_pct - 95.0).abs() < 1e-6);
        assert_eq!(summary.clock_pct, Some(50.0));
    }

    #[test]
    fn the_binding_resource_is_the_most_used() {
        // Over 10 s: the node's thread used 200 ticks (2 s of a core: 5% of
        // four), the disk was busy 9 s (90%), the link sent 100 MB (8% of
        // 1 GbE).
        let first = sample(0, 0, 0, 0, 0);
        let last = sample(10_000, 1_000, 200, 9_000, 100_000_000);
        let summary = host_summary(&facts(), &[&first, &last]);
        assert!(
            (summary.process_cpu_pct - 5.0).abs() < 1e-6,
            "{}",
            summary.process_cpu_pct
        );
        assert!(
            (summary.link_util_pct.unwrap() - 8.0).abs() < 1e-6,
            "{:?}",
            summary.link_util_pct
        );
        assert_eq!(summary.binding, "disk");
        assert!((summary.binding_pct - 90.0).abs() < 1e-6);
        assert_eq!(summary.threads[0].0, "vos runtime");
        assert_eq!(summary.rss_mib, 1024.0);
    }

    /// The window is the drivers' load past its ramp: the drain's lines,
    /// written while the last answers come, are left out; a pool that made
    /// requests wait is warned of.
    #[test]
    fn the_window_is_the_load_not_the_drain() {
        let dir = tempfile::tempdir().unwrap();
        let run = crate::runs::Run {
            id: "r".into(),
            dir: dir.path().to_path_buf(),
        };
        let driver = Facts {
            name: "d".into(),
            role: "driver".into(),
            ..Facts::default()
        };
        std::fs::write(
            run.file("hosts.json"),
            serde_json::to_string(&vec![driver]).unwrap(),
        )
        .unwrap();
        let mut lines = String::new();
        for t in (110_000..=400_000).step_by(10_000) {
            lines += &format!("{{\"t_ms\":{t},\"total\":false,\"kind\":\"all\",\"sent\":1}}\n");
        }
        lines += "{\"t_ms\":400000,\"total\":true,\"kind\":\"all\",\"sent\":1000,\"conn_waits\":50,\"load_from_ms\":100000,\"load_to_ms\":160000}\n";
        let hosts = run.dir.join("hosts").join("d");
        std::fs::create_dir_all(&hosts).unwrap();
        std::fs::write(hosts.join("r.drive.jsonl"), lines).unwrap();
        let summary = super::report(&run, None, Some(10)).unwrap();
        assert_eq!(summary.window_ms, (110_000, 160_000));
        assert!(
            summary
                .warnings
                .iter()
                .any(|warning| warning.contains("the pool bound")),
            "{:?}",
            summary.warnings
        );
    }

    #[test]
    fn every_report_states_what_it_does_not_model_and_t2s_assumption() {
        let summary = Summary {
            not_modeled: super::NOT_MODELED.into(),
            t2: super::T2.into(),
            agents: 64,
            ..Summary::default()
        };
        let text = text(&summary);
        assert!(text.contains("not modeled"));
        assert!(text.contains("K >= 128"));
        assert!(text.contains("K = 64"));
        assert!(compare(&summary, &summary).contains("calls/s"));
    }
}
