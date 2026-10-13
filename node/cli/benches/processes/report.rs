//! What a run measured, printed: its rate, its percentiles, the CPU it
//! took, and the nodes' stages over its window.

use std::time::Duration;

use crate::load::Samples;
use crate::nodes::Cpu;

/// The most an open-loop run's p99 send lag may be.
const LAG: Duration = Duration::from_micros(500);

/// A stage this long or longer is a stall: about 50 ms, at a bucket's
/// edge, so a bucket counts whole.
pub const STALL: u64 = 49_152;

/// What a run gave: commits (or calls) per second, its percentiles, each
/// node's busy cores, how clean the machine was, and its stalls.
pub struct Measured {
    pub commits: f64,
    pub p50: Duration,
    pub p95: Duration,
    pub p99: Duration,
    pub busy: Vec<f64>,
    /// The machine's CPU outside the run, in cores, and the share of the
    /// window every task on it waited on IO.
    pub outside: f64,
    pub io: f64,
    /// The runtime probe's wakes over [`STALL`] late, every node's.
    pub stalls: u64,
    /// Batches longer than [`STALL`], every node's, and the longest, in
    /// µs (a bucket's top).
    pub long_batches: u64,
    pub longest_batch: u64,
}

pub fn percentile(sorted: &[Duration], at: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    sorted[((sorted.len() - 1) as f64 * at).round() as usize]
}

pub fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// The p50, p99 and largest of a stage's counts, as bucket tops.
fn stage_percentiles(counts: &[u64]) -> Option<(u64, u64, u64)> {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return None;
    }
    let at = |share: f64| {
        let want = ((total as f64) * share).ceil() as u64;
        let mut seen = 0;
        for (index, count) in counts.iter().enumerate() {
            seen += count;
            if seen >= want {
                return vos_wire::ingress::bucket_top(index);
            }
        }
        u64::MAX
    };
    Some((at(0.50), at(0.99), at(1.0)))
}

/// How many of a stage's `counts` lie in buckets from `micros` up.
fn over(counts: &[u64], micros: u64) -> u64 {
    counts
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(index, _)| vos_wire::ingress::bucket_top(index - 1) + 1 >= micros)
        .map(|(_, count)| count)
        .sum()
}

/// Print what one run gives: commits per second, latency and lag
/// percentiles, each node's CPU over the window, per commit too, by
/// thread, and its stages.
pub fn report(
    name: &str,
    samples: &mut Samples,
    (before, after): (Cpu, Cpu),
    measure: Duration,
) -> Measured {
    samples.latencies.sort();
    samples.lags.sort();
    let seconds = measure.as_secs_f64();
    let commits = samples.latencies.len() as f64 / seconds;
    let p50 = percentile(&samples.latencies, 0.50);
    let p95 = percentile(&samples.latencies, 0.95);
    let p99 = percentile(&samples.latencies, 0.99);
    let busy: Vec<f64> = after
        .nodes
        .iter()
        .zip(&before.nodes)
        .map(|(after, before)| (after - before) / seconds)
        .collect();
    // Past the knee the calls scheduled in the window are answered after
    // it, their CPU spent past it: no CPU per commit then.
    let past_knee = past_knee(samples);
    let per_commit: Vec<f64> = busy
        .iter()
        .map(|busy| {
            if commits > 0.0 && past_knee.is_none() {
                busy / commits * 1e6
            } else {
                0.0
            }
        })
        .collect();
    // Each node's executors: the busiest's share of a core, and their mean.
    let executors: Vec<String> = after
        .executors
        .iter()
        .zip(&before.executors)
        .map(|(after, before)| {
            let shares: Vec<f64> = after
                .iter()
                .zip(before)
                .map(|(after, before)| (after - before) / seconds * 100.0)
                .collect();
            let most = shares.iter().copied().fold(0.0, f64::max);
            let mean = shares.iter().sum::<f64>() / shares.len().max(1) as f64;
            format!("{most:.0}%/{mean:.0}%")
        })
        .collect();
    let driver = (after.driver - before.driver) / seconds;
    // What else the machine ran meanwhile, and how long every task on it
    // waited on IO at once: a run is only as clean as these.
    let outside = (after.machine - before.machine) / seconds - busy.iter().sum::<f64>() - driver;
    let io = (after.io_stalled - before.io_stalled) / seconds * 100.0;
    // Each node's runtime thread, writer and network, as shares of a core.
    let others: Vec<String> = after
        .others
        .iter()
        .zip(&before.others)
        .map(|(after, before)| {
            let share = |at: usize| (after[at] - before[at]) / seconds * 100.0;
            format!(
                "{:.0}/{:.0}/{:.0}/{:.0}%",
                share(0),
                share(1),
                share(2),
                share(3)
            )
        })
        .collect();
    let failure = samples
        .first_failure
        .as_ref()
        .map_or_else(String::new, |failure| format!(" (first: {failure})"));
    // What else there is to say of the run, where there is.
    let notes: String = [
        send_lag(&samples.lags),
        (samples.behind > 0).then(|| {
            format!(
                "{} calls waited on their session's previous one",
                samples.behind
            )
        }),
        past_knee.map(|late| {
            format!(
                "past the knee: {:.0}% of its calls answered after the window",
                late * 100.0
            )
        }),
        (samples.exhausted > 0).then(|| {
            format!(
                "{} sessions ran out of calls UNDERCOUNTED",
                samples.exhausted
            )
        }),
    ]
    .into_iter()
    .flatten()
    .map(|note| format!("; {note}"))
    .collect();
    let stages = stages(&before, &after);
    println!(
        "{name}: {commits:.0}/s, p50 {:.2} ms, p99 {:.2} ms, {} failed{failure}; nodes busy {:?} cores (executors most/mean {executors:?}; runtime/writer/net/fjall {others:?}), {:?} µs CPU per commit; driver {driver:.2} cores; outside the run {outside:.2} cores, IO stalled {io:.1}%{notes}",
        ms(p50),
        ms(p99),
        samples.failed,
        busy.iter()
            .map(|busy| (busy * 100.0).round() / 100.0)
            .collect::<Vec<_>>(),
        per_commit.iter().map(|cpu| cpu.round()).collect::<Vec<_>>(),
    );
    if !stages.lines.is_empty() {
        println!("  stages p50/p99/max, mean µs: {}", stages.lines.join(", "));
        println!(
            "  stalls: {} runtime wakes and {} batches of {:.0} ms or more; the longest batch {:.0} ms; p95 {:.2} ms",
            stages.stalls,
            stages.long_batches,
            STALL as f64 / 1000.0,
            stages.longest_batch as f64 / 1000.0,
            ms(p95)
        );
    }
    Measured {
        commits,
        p50,
        p95,
        p99,
        busy,
        outside,
        io,
        stalls: stages.stalls,
        long_batches: stages.long_batches,
        longest_batch: stages.longest_batch,
    }
}

/// An open loop's send lag, marked invalid past [`LAG`]; none for a
/// closed loop.
fn send_lag(sorted: &[Duration]) -> Option<String> {
    if sorted.is_empty() {
        return None;
    }
    let p99 = percentile(sorted, 0.99);
    Some(format!(
        "send lag p50 {:.3} ms, p99 {:.3} ms{}",
        ms(percentile(sorted, 0.50)),
        ms(p99),
        if p99 > LAG { " INVALID" } else { "" }
    ))
}

/// The share of a run's calls answered after its window, if the run is
/// past the knee. Its sign is a backlog that grows: more than 1% of the
/// window's calls answered after it, and the last quarter's median
/// latency at least twice the first's. A stall at the window's end makes
/// calls late without moving that median; calls that waited on their
/// session's previous one are no sign alone either, as one long batch
/// holds them too.
fn past_knee(samples: &mut Samples) -> Option<f64> {
    let late = samples.answered_after as f64 / samples.latencies.len().max(1) as f64;
    let median = |latencies: &mut Vec<Duration>| {
        latencies.sort_unstable();
        percentile(latencies, 0.5)
    };
    let growing = median(&mut samples.last_quarter) >= median(&mut samples.first_quarter) * 2;
    (late > 0.01 && growing).then_some(late)
}

/// The nodes' stages over a window, every node's counts together.
struct Stages {
    /// Each stage's `p50/p99/max mean (count)`, in µs (in units for
    /// counts).
    lines: Vec<String>,
    stalls: u64,
    long_batches: u64,
    longest_batch: u64,
}

fn stages(before: &Cpu, after: &Cpu) -> Stages {
    // Each stage's counts over the window.
    let deltas: Vec<(&str, Vec<u64>)> = after
        .stages
        .iter()
        .filter_map(|(name, counts)| {
            let earlier = before.stages.iter().find(|(earlier, _)| earlier == name)?;
            let delta = counts
                .iter()
                .zip(&earlier.1)
                .map(|(after, before)| after.saturating_sub(*before))
                .collect();
            Some((name.as_str(), delta))
        })
        .collect();
    let stage = |name: &str| {
        deltas
            .iter()
            .find(|(stage, _)| *stage == name)
            .map(|(_, delta)| delta.as_slice())
            .unwrap_or_default()
    };
    // A stage's exact mean over the window: its values' sum over its
    // count. The stages' means add up where their bucket tops do not.
    let mean = |name: &str, delta: &[u64]| {
        let count: u64 = delta.iter().sum();
        let total = |cpu: &Cpu| {
            cpu.totals
                .iter()
                .find(|(stage, _)| stage == name)
                .map_or(0, |(_, total)| *total)
        };
        // A node restarted in the window counts from zero again: its part
        // of the counts is lost, and so is its part of the sum.
        (count > 0).then(|| total(after).saturating_sub(total(before)) as f64 / count as f64)
    };
    let lines = deltas
        .iter()
        .filter_map(|(name, delta)| {
            let (p50, p99, max) = stage_percentiles(delta)?;
            let mean = mean(name, delta)?;
            let count: u64 = delta.iter().sum();
            Some(format!("{name} {p50}/{p99}/{max} mean {mean:.0} ({count})"))
        })
        .collect();
    Stages {
        lines,
        stalls: over(stage("late"), STALL),
        long_batches: over(stage("batch"), STALL),
        longest_batch: stage_percentiles(stage("batch")).map_or(0, |(_, _, max)| max),
    }
}
