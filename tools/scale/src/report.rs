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
use crate::engine::stats::REPORTED;
use crate::histogram::quantile;
use crate::runs::Run;
use crate::sample::Sample;

mod host;
mod text;

pub use host::host_summary;
use text::slowest;
pub use text::{compare, text};

/// Where the mix's defaults come from, stated in every report.
pub const MIX_DEFAULTS: &str = "the mix's defaults (transfers 80%, queries 15%, workflows 4.5%, reads at a cut 0.5%) are the harness's own, pending the owner's";

/// What the runs do not model, stated in every report.
pub const NOT_MODELED: &str = "not modeled: the per-call identity read, credentialed calls (measured apart), cross-space traffic, proving";

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
    /// Reads at a cut whose window closed after the load ended, left open
    /// by the run's end: apart from the errors.
    #[serde(default)]
    pub not_closed: u64,
    pub rate: f64,
    pub p50_us: u64,
    pub p99_us: u64,
    pub p999_us: u64,
}

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
    /// The gateway's cost, when the run measured it.
    #[serde(default)]
    pub gateway: Option<crate::gateway::Cost>,
}

fn jsonl<T: for<'de> Deserialize<'de>>(path: &Path) -> Vec<T> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
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

/// Summarise `run` over `window` (milliseconds since the epoch), the
/// drivers' span when `None`; written to the run's `summary.json` and
/// `report.txt`.
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
    let window = window.unwrap_or_else(|| load_window(run, &records, ramp_s));
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
        summary
            .nodes
            .push(node_summary(number, &polls, window, &hosts_of, &mut terms));
    }
    summary.leader_changes = terms.values().map(|(low, high)| high - low).sum();
    for (name, lines) in &records {
        let driver = driver_summary(name, lines, &mut summary.warnings);
        summary.rate += driver.rate;
        summary.drivers.push(driver);
    }
    summary.slowest = slowest(&summary);
    summary.gateway = std::fs::read_to_string(run.file("gateway.json"))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok());
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

/// The window a run is summarised over by default: the drivers' load, from
/// its records.
fn load_window(
    run: &Run,
    records: &[(String, Vec<serde_json::Value>)],
    ramp_s: Option<u64>,
) -> (u64, u64) {
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
    loaded.unwrap_or_else(|| {
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
    })
}

/// Node `number`'s summary over `window` from the polls; the agents' terms
/// it saw widen `terms`.
fn node_summary(
    number: u64,
    polls: &[serde_json::Value],
    window: (u64, u64),
    hosts_of: &BTreeMap<u64, String>,
    terms: &mut BTreeMap<u64, (u64, u64)>,
) -> NodeSummary {
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
            if let (Some(agent), Some(term)) = (status["agent"].as_u64(), status["term"].as_u64()) {
                let seen = terms.entry(agent).or_insert((term, term));
                seen.0 = seen.0.min(term);
                seen.1 = seen.1.max(term);
            }
        }
    }
    node
}

/// Driver `name`'s summary from its record's totals; what may have bound
/// the run instead of the nodes is added to `warnings`.
fn driver_summary(
    name: &str,
    lines: &[serde_json::Value],
    warnings: &mut Vec<String>,
) -> DriverSummary {
    let mut driver = DriverSummary {
        name: name.to_string(),
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
                not_closed: line["not_closed"].as_u64().unwrap_or(0),
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
            warnings.push(format!(
                "driver {name}: {} of its {sent} requests waited for a connection, {} at once in use at most of {} a node: the pool bound; raise [harness] driver_connections with [node] ingress_connections",
                driver.conn_waits, driver.in_use_max, driver.connections
            ));
        }
        driver.late_share = total["late_sends"].as_u64().unwrap_or(0) as f64 / sent.max(1) as f64;
        if driver.late_share > LATE_SHARE {
            warnings.push(format!(
                "driver {name}: {:.1}% of its sends went more than {} ms behind their schedule (at worst {} ms): the driver may be what bound, not the nodes",
                100.0 * driver.late_share,
                crate::drive::LATE_US / 1_000,
                driver.late_us / 1_000
            ));
        }
    }
    driver
}

#[cfg(test)]
mod tests;
