//! `sample`, run on each host beside its node: every few seconds a JSON
//! line of the host's CPU (iowait apart), the node's threads (CPU ticks
//! and voluntary switches, its idle wakes), its memory and I/O, the data
//! disk's counters and the link's bytes. Counters are cumulative; the
//! report takes their differences. The node's process is found by its
//! unit's main PID, read again each sample, so a restart is followed.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Thread {
    pub tid: u32,
    pub comm: String,
    /// User and system time, in clock ticks.
    pub utime: u64,
    pub stime: u64,
    /// Times it slept by choice: its wakes.
    pub voluntary: u64,
    /// Times it was taken off a core it wanted: the host's other work
    /// preempting it.
    #[serde(default)]
    pub involuntary: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Process {
    pub pid: u32,
    /// The process's user and system time, in clock ticks: its threads'
    /// that ended too.
    pub utime: u64,
    pub stime: u64,
    pub rss_kb: u64,
    pub hwm_kb: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub threads: Vec<Thread>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Disk {
    pub reads: u64,
    pub read_sectors: u64,
    pub writes: u64,
    pub write_sectors: u64,
    /// Milliseconds it was busy, and its requests' total time in queue.
    pub io_ms: u64,
    pub weighted_ms: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Sample {
    pub t_ms: u64,
    /// The host's CPU time by kind, in clock ticks, over all its cores:
    /// `user`, `nice`, `system`, `idle`, `iowait`, `irq`, `softirq`,
    /// `steal`.
    pub cpu: BTreeMap<String, u64>,
    pub process: Option<Process>,
    pub disk: Option<Disk>,
    /// The cores' mean clock, and their top: below it under load, the
    /// host is throttled or saving power.
    pub freq_khz: Option<u64>,
    pub freq_max_khz: Option<u64>,
    /// The link's received and sent bytes.
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
}

const CPU_KINDS: [&str; 8] = [
    "user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal",
];

fn read(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn host_cpu() -> BTreeMap<String, u64> {
    let stat = read("/proc/stat").unwrap_or_default();
    let line = stat
        .lines()
        .find(|line| line.starts_with("cpu "))
        .unwrap_or("");
    CPU_KINDS
        .iter()
        .zip(line.split_whitespace().skip(1))
        .map(|(kind, value)| (kind.to_string(), value.parse().unwrap_or(0)))
        .collect()
}

/// A `Key:   value kB` field of a status file.
fn status_field(status: &str, key: &str) -> u64 {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix(':'))
        .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
        .unwrap_or(0)
}

/// A thread's `stat`: its name, and its user and system ticks.
fn thread_stat(stat: &str) -> Option<(String, u64, u64)> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let comm = stat[open + 1..close].to_string();
    // After the name: state is field 3; utime and stime fields 14 and 15.
    let rest: Vec<&str> = stat[close + 2..].split_whitespace().collect();
    Some((
        comm,
        rest.get(11)?.parse().ok()?,
        rest.get(12)?.parse().ok()?,
    ))
}

fn process(pid: u32) -> Option<Process> {
    let root = format!("/proc/{pid}");
    let status = read(format!("{root}/status"))?;
    let (_, utime, stime) = thread_stat(&read(format!("{root}/stat"))?)?;
    let io = read(format!("{root}/io")).unwrap_or_default();
    let mut threads = Vec::new();
    for task in std::fs::read_dir(format!("{root}/task")).ok()?.flatten() {
        let Some(tid) = task.file_name().to_str().and_then(|tid| tid.parse().ok()) else {
            continue;
        };
        let Some((comm, utime, stime)) = read(task.path().join("stat"))
            .as_deref()
            .and_then(thread_stat)
        else {
            continue;
        };
        let voluntary = status_field(
            &read(task.path().join("status")).unwrap_or_default(),
            "voluntary_ctxt_switches",
        );
        let involuntary = status_field(
            &read(task.path().join("status")).unwrap_or_default(),
            "nonvoluntary_ctxt_switches",
        );
        threads.push(Thread {
            tid,
            comm,
            utime,
            stime,
            voluntary,
            involuntary,
        });
    }
    Some(Process {
        pid,
        utime,
        stime,
        rss_kb: status_field(&status, "VmRSS"),
        hwm_kb: status_field(&status, "VmHWM"),
        read_bytes: status_field(&io, "read_bytes"),
        write_bytes: status_field(&io, "write_bytes"),
        threads,
    })
}

fn disk(name: &str) -> Option<Disk> {
    let stats = read("/proc/diskstats")?;
    let fields: Vec<u64> = stats
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .find(|fields| fields.get(2) == Some(&name))?
        .iter()
        .skip(3)
        .map(|field| field.parse().unwrap_or(0))
        .collect();
    Some(Disk {
        reads: *fields.first()?,
        read_sectors: *fields.get(2)?,
        writes: *fields.get(4)?,
        write_sectors: *fields.get(6)?,
        io_ms: *fields.get(9)?,
        weighted_ms: *fields.get(10)?,
    })
}

fn link(iface: &str) -> Option<(u64, u64)> {
    let dev = read("/proc/net/dev")?;
    let line = dev
        .lines()
        .find_map(|line| line.trim_start().strip_prefix(iface)?.strip_prefix(':'))?;
    let fields: Vec<u64> = line
        .split_whitespace()
        .map(|field| field.parse().unwrap_or(0))
        .collect();
    Some((*fields.first()?, *fields.get(8)?))
}

/// The cores' mean current clock and the first core's top, in kHz.
fn frequency() -> (Option<u64>, Option<u64>) {
    let mut total = 0;
    let mut cores = 0;
    for core in std::fs::read_dir("/sys/devices/system/cpu")
        .into_iter()
        .flatten()
        .flatten()
    {
        if let Some(khz) = read(core.path().join("cpufreq/scaling_cur_freq"))
            .and_then(|text| text.trim().parse::<u64>().ok())
        {
            total += khz;
            cores += 1;
        }
    }
    let top = read("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq")
        .and_then(|text| text.trim().parse().ok());
    ((cores > 0).then(|| total / cores), top)
}

/// The main PID of the user unit `unit`, if it runs.
fn main_pid(unit: &str) -> Option<u32> {
    let output = Command::new("systemctl")
        .args(["--user", "show", "--property=MainPID", "--value", unit])
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .ok()
        .filter(|pid| *pid != 0)
}

/// One sample now.
pub fn sample(unit: Option<&str>, iface: Option<&str>, disk_name: Option<&str>) -> Sample {
    let (rx_bytes, tx_bytes) = iface.and_then(link).unzip();
    let (freq_khz, freq_max_khz) = frequency();
    Sample {
        freq_khz,
        freq_max_khz,
        t_ms: crate::now_ms(),
        cpu: host_cpu(),
        process: unit.and_then(main_pid).and_then(process),
        disk: disk_name.and_then(disk),
        rx_bytes,
        tx_bytes,
    }
}

/// Sample every `every` into `out`, appended to, until stopped.
pub fn run(
    unit: Option<&str>,
    iface: Option<&str>,
    disk_name: Option<&str>,
    every: Duration,
    out: &Path,
) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(out)
        .map_err(|error| format!("{}: {error}", out.display()))?;
    loop {
        let line = serde_json::to_string(&sample(unit, iface, disk_name)).expect("json");
        writeln!(file, "{line}").map_err(|error| error.to_string())?;
        std::thread::sleep(every);
    }
}

#[cfg(test)]
mod tests {
    use super::{status_field, thread_stat};

    #[test]
    fn a_threads_stat_and_status_read() {
        let stat = "4242 (vos exec (1)) S 1 2 3 4 5 6 7 8 9 10 1234 567 0 0 20 0 1 0";
        assert_eq!(thread_stat(stat), Some(("vos exec (1)".into(), 1234, 567)));
        let status = "Name:\tvos\nVmRSS:\t  20480 kB\nvoluntary_ctxt_switches:\t99\nnonvoluntary_ctxt_switches:\t7\n";
        assert_eq!(status_field(status, "VmRSS"), 20480);
        assert_eq!(status_field(status, "voluntary_ctxt_switches"), 99);
        assert_eq!(status_field(status, "nonvoluntary_ctxt_switches"), 7);
        assert_eq!(status_field(status, "VmHWM"), 0);
    }

    #[test]
    fn this_host_samples() {
        let sample = super::sample(None, Some("lo"), None);
        assert!(sample.cpu["idle"] > 0);
        assert!(sample.rx_bytes.is_some());
        let me = super::process(std::process::id()).expect("this process");
        assert!(me.rss_kb > 0 && !me.threads.is_empty());
    }
}
