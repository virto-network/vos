//! A run's personal agents in its report: each node's memory before their
//! creation, after it and at the load's end, per personal replica it
//! holds; the drivers' wakes by kind; the fill, the replacement and the
//! spare's install.

use std::fmt::Write;
use std::path::Path;

use super::{Fill, Personals};
use crate::runs::Run;
use crate::sample::Sample;

fn lines(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

/// The files in `dir` whose names end with `suffix`.
fn files(dir: &Path, suffix: &str) -> Vec<std::path::PathBuf> {
    let mut found: Vec<_> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.to_string_lossy().ends_with(suffix))
        .collect();
    found.sort();
    found
}

fn rss_mib(sample: &Sample) -> Option<f64> {
    Some(sample.process.as_ref()?.rss_kb as f64 / 1024.0)
}

/// The run's personal agents, as text; none when the run made none.
pub fn summary(run: &Run) -> Option<String> {
    let text = std::fs::read_to_string(run.file("personal.json")).ok()?;
    let personals: Personals = serde_json::from_str(&text).ok()?;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "\npersonal agents: {} and the full one, the home agent {}; {} admitting their device through the onion; created and claimed in {:.0} s",
        personals.agents.len(),
        personals.home.as_ref().map_or(0, |home| home.agent),
        personals.admitted,
        personals
            .created_to_ms
            .saturating_sub(personals.created_from_ms) as f64
            / 1e3
    );
    // The load's end: the last personal record line, else the last sample.
    let records: Vec<(String, Vec<serde_json::Value>)> = std::fs::read_dir(run.dir.join("hosts"))
        .into_iter()
        .flatten()
        .flatten()
        .flat_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            files(&entry.path(), ".personal.jsonl")
                .into_iter()
                .map(move |path| (name.clone(), lines(&path)))
        })
        .collect();
    let load_end = records
        .iter()
        .filter_map(|(_, lines)| lines.last()?["t_ms"].as_u64())
        .max();
    let _ = writeln!(
        out,
        "  each node's RSS: before the creation, after it, and at the load's end (or the fill's start); per personal replica it holds, the shard load's growth included: set it against the run without personal agents"
    );
    let hosts_dir = run.dir.join("hosts");
    let nodes = &personals.nodes;
    let fill = std::fs::read_to_string(run.file("fill.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<Fill>(&text).ok());
    // The load's end, or the fill's start when the run filled an agent:
    // its 64 MiB are no personal replica's idle cost.
    let load_end = match &fill {
        Some(fill) => Some(load_end.map_or(fill.from_ms, |end| end.min(fill.from_ms))),
        None => load_end,
    };
    for (at, name) in nodes.iter().enumerate() {
        let number = at as u8 + 1;
        let replicas = personals
            .all()
            .filter(|member| member.replicas.contains(&number))
            .count();
        let samples: Vec<Sample> = files(&hosts_dir.join(name), ".samples.jsonl")
            .iter()
            .flat_map(|path| lines(path))
            .filter_map(|line| serde_json::from_value(line).ok())
            .collect();
        let before = samples
            .iter()
            .rev()
            .find(|sample| sample.t_ms <= personals.created_from_ms)
            .and_then(rss_mib);
        let after = samples
            .iter()
            .find(|sample| sample.t_ms >= personals.created_to_ms)
            .and_then(rss_mib);
        let end = samples
            .iter()
            .rev()
            .find(|sample| load_end.is_none_or(|end| sample.t_ms <= end))
            .and_then(rss_mib);
        let per = |mib: Option<f64>| match (before, mib) {
            (Some(before), Some(mib)) if replicas > 0 => {
                format!("{:+.1} KiB", (mib - before) * 1024.0 / replicas as f64)
            }
            _ => "?".into(),
        };
        let show = |mib: Option<f64>| mib.map_or("?".into(), |mib| format!("{mib:.0} MiB"));
        let _ = writeln!(
            out,
            "    {name}: {replicas} replicas; {} before, {} after ({} a replica), {} at the load's end ({} a replica)",
            show(before),
            show(after),
            per(after),
            show(end),
            per(end)
        );
    }
    for (host, lines) in &records {
        let totals: Vec<&serde_json::Value> =
            lines.iter().filter(|line| line["total"] == true).collect();
        for line in totals {
            if line["kind"] == "all" {
                let _ = writeln!(
                    out,
                    "  {host}: {} agents, {} wakes, {} sessions opened, {} pushes of the largest envelope; late at worst {} us, {} unfinished",
                    line["agents"],
                    line["wakes"],
                    line["sessions"],
                    line["full_pushes"],
                    line["late_max_us"],
                    line["unfinished"]
                );
            } else {
                let _ = writeln!(
                    out,
                    "    {:<6} {:>8} sent {:>8} ok {:>6} errors {}, p50 {} us, p99 {} us, p99.9 {} us (fine: {} / {} / {} us), {:.1} MiB",
                    line["kind"].as_str().unwrap_or("?"),
                    line["sent"],
                    line["ok"],
                    line["errors"],
                    line["by_error"],
                    line["p50_us"],
                    line["p99_us"],
                    line["p999_us"],
                    line["fine"]["p50_us"],
                    line["fine"]["p99_us"],
                    line["fine"]["p999_us"],
                    line["bytes"].as_f64().unwrap_or(0.0) / (1 << 20) as f64
                );
            }
        }
    }
    if let Some(sessions) = std::fs::read_to_string(run.file("personal-sessions.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<Vec<serde_json::Value>>(&text).ok())
        .filter(|sampled| !sampled.is_empty())
    {
        let held: Vec<u64> = sessions
            .iter()
            .filter_map(|one| one["sessions"].as_u64())
            .collect();
        let _ = writeln!(
            out,
            "  sessions held at the load's end by {} sampled agents' leaders: {} at most, {:.1} on average",
            held.len(),
            held.iter().max().unwrap_or(&0),
            held.iter().sum::<u64>() as f64 / held.len().max(1) as f64
        );
    }
    if let Some(fill) = fill {
        let _ = writeln!(
            out,
            "  the fill: agent {}, {} envelopes, {:.1} MiB in {:.1} s (push p50 {} us, p99 {} us), stopped by {:?}",
            fill.agent,
            fill.pushes,
            fill.bytes as f64 / (1 << 20) as f64,
            fill.fill_ms as f64 / 1e3,
            fill.push_p50_us,
            fill.push_p99_us,
            fill.stopped_by
        );
        let _ = writeln!(
            out,
            "    its leader node {:?}, commit {}, log from {} (compacted after {:?} ms); replica {} replaced by node {}: {} in {} ms",
            fill.leader,
            fill.leader_commit,
            fill.leader_log_start,
            fill.compacted_ms,
            fill.remove,
            fill.add,
            fill.replace_answer,
            fill.replace_ms
        );
        let _ = writeln!(
            out,
            "    the spare's replica applied the leader's commit {:?} ms from the replacement's start (its log from, applied: {:?}); it served {:?} (envelopes, bytes){}",
            fill.installed_ms,
            fill.installed,
            fill.served,
            fill.error
                .as_ref()
                .map_or(String::new(), |error| format!("; error: {error}"))
        );
        let _ = writeln!(
            out,
            "    the gate (filled to the quota, the spare's snapshot past the leader's commit {} before the fill, installed within {} ms): {}",
            fill.commit_before,
            super::fill::INSTALL_LIMIT_MS,
            if fill.passed { "met" } else { "MISSED" }
        );
    }
    Some(out)
}
