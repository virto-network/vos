//! A host's summary from its samples.

use super::*;

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
