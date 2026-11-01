//! A summary as text, alone and against another.

use super::*;

/// The slowest node host: the node whose commits' p99 is the highest, its
/// host's disk time per I/O breaking ties; a group commits at its median
/// replica's fsync, so this host gates the groups it follows.
pub(super) fn slowest(summary: &Summary) -> Option<String> {
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
        for kind in REPORTED {
            if let Some(stats) = driver.kinds.get(kind) {
                text += &format!(
                    "    {kind:<9} {:>9} sent {:>9} ok {:>7} errors {:?}, {:.1}/s, p50 {} us, p99 {} us, p99.9 {} us{}\n",
                    stats.sent,
                    stats.ok,
                    stats.errors,
                    stats.by_error,
                    stats.rate,
                    stats.p50_us,
                    stats.p99_us,
                    stats.p999_us,
                    match stats.not_closed {
                        0 => String::new(),
                        open => format!("; {open} not closed in the run"),
                    }
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
    if let Some(gateway) = &summary.gateway {
        text += &format!("  {}\n", gateway.line());
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
