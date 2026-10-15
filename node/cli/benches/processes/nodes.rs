//! The node processes, each pinned to its share of the machine, and
//! what `/proc` says of them and of the machine as a whole.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use vos_checker::processes::{self, Running, first_run, read_log};
use vos_checker::spaces::{free_tcp_port, free_udp_port};
use vos_node::client::{Operator, Target};
use vos_node::tls::Trust;
use vos_wire::ids::AgentId;
use vos_wire::ingress::{Install, Response};

use crate::{COUNTER, NODES};

/// The pinning on the reference laptop: each node two P-cores (four
/// threads) and two E-cores; the driver the rest.
const CPUS: [&str; NODES + 1] = [
    "0,5,1,2,12,13",
    "3,4,6,7,14,15",
    "8,9,10,11,16,17",
    "18,19,20,21",
];

/// Each node's cores and then the driver's, as `taskset -c` lists them.
pub fn cpus() -> Vec<String> {
    match std::env::var("CPUS") {
        Ok(cpus) => cpus.split('/').map(str::to_string).collect(),
        Err(_) => CPUS.iter().map(|cpus| cpus.to_string()).collect(),
    }
}

/// Whether `taskset` is there to pin the nodes and the driver with.
pub fn pinning() -> bool {
    Command::new("taskset")
        .arg("-V")
        .output()
        .is_ok_and(|output| output.status.success())
}

/// Pin the driver, and the threads it starts from then on, to `cpus`.
pub fn pin_driver(cpus: &str) {
    taskset(cpus, std::process::id());
}

/// Pin the calling thread to `cpus`, by its thread id.
pub fn pin_thread(cpus: &str) {
    let tid = std::fs::read_link("/proc/thread-self")
        .ok()
        .and_then(|link| link.file_name()?.to_str()?.parse::<u32>().ok());
    if let Some(tid) = tid {
        taskset(cpus, tid);
    }
}

fn taskset(cpus: &str, id: u32) {
    let _ = Command::new("taskset")
        .args(["-p", "-c", cpus, &id.to_string()])
        .stdout(Stdio::null())
        .status();
}

/// The CPU a `/proc` stat line says its process or thread used, in
/// seconds: utime and stime, the 14th and 15th fields.
fn stat_cpu(stat: &str) -> f64 {
    let fields: Vec<&str> = stat
        .rsplit_once(") ")
        .map(|(_, rest)| rest.split_whitespace().collect())
        .unwrap_or_default();
    let ticks: u64 = fields
        .get(11..13)
        .map(|times| {
            times
                .iter()
                .filter_map(|time| time.parse::<u64>().ok())
                .sum()
        })
        .unwrap_or(0);
    ticks as f64 / 100.0
}

/// The CPU so far of each thread of process `pid` whose name starts with
/// `named`, in seconds, in the order of their names.
fn threads_cpu(pid: u32, named: &str) -> Vec<f64> {
    let mut threads: Vec<(String, f64)> = std::fs::read_dir(format!("/proc/{pid}/task"))
        .map(|tasks| {
            tasks
                .filter_map(Result::ok)
                .filter_map(|task| {
                    let name = std::fs::read_to_string(task.path().join("comm")).ok()?;
                    let name = name.trim().to_string();
                    name.starts_with(named).then(|| {
                        let stat =
                            std::fs::read_to_string(task.path().join("stat")).unwrap_or_default();
                        (name, stat_cpu(&stat))
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    threads.sort_by(|a, b| a.0.cmp(&b.0));
    threads.into_iter().map(|(_, cpu)| cpu).collect()
}

/// The driver's own CPU so far, in seconds.
fn driver_cpu() -> f64 {
    stat_cpu(&std::fs::read_to_string("/proc/self/stat").unwrap_or_default())
}

/// The machine's transparent huge page counters (`/proc/vmstat`'s
/// `thp_*`), by name.
pub fn transparent_huge_pages() -> Vec<(String, u64)> {
    std::fs::read_to_string("/proc/vmstat")
        .unwrap_or_default()
        .lines()
        .filter(|line| line.starts_with("thp_"))
        .filter_map(|line| {
            let (name, value) = line.split_once(' ')?;
            Some((name.to_string(), value.trim().parse().ok()?))
        })
        .collect()
}

/// The whole machine's busy CPU so far, every process's, in seconds
/// (`/proc/stat`, all but idle and waiting on IO).
fn machine_cpu() -> f64 {
    let stat = std::fs::read_to_string("/proc/stat").unwrap_or_default();
    let ticks: Vec<u64> = stat
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("cpu "))
        .map(|times| {
            times
                .split_whitespace()
                .filter_map(|time| time.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    // user nice system idle iowait irq softirq steal (guests are in user).
    let busy: u64 = ticks
        .iter()
        .take(8)
        .enumerate()
        .filter(|(at, _)| *at != 3 && *at != 4)
        .map(|(_, ticks)| ticks)
        .sum();
    busy as f64 / 100.0
}

/// How long every task on the machine waited on IO at once, so far, in
/// seconds (`/proc/pressure/io`, its `full` line).
fn io_stalled() -> f64 {
    let pressure = std::fs::read_to_string("/proc/pressure/io").unwrap_or_default();
    pressure
        .lines()
        .find_map(|line| line.strip_prefix("full "))
        .and_then(|fields| {
            fields
                .split_whitespace()
                .find_map(|field| field.strip_prefix("total="))
        })
        .and_then(|total| total.parse::<u64>().ok())
        .map_or(0.0, |micros| micros as f64 / 1e6)
}

/// A node process, killed when dropped.
pub struct Process {
    running: Mutex<Running>,
    pub number: u8,
    pub url: String,
    pub target: Target,
    /// Its data directory, where it writes its operator's token at each
    /// start.
    data: PathBuf,
    /// How it is started again: its arguments, its pinning, its log.
    args: Vec<String>,
    cpus: Option<String>,
    log: PathBuf,
}

impl Drop for Process {
    fn drop(&mut self) {
        self.running.get_mut().unwrap().kill();
        // `LOGS` keeps each node's log past the run.
        if let Ok(logs) = std::env::var("LOGS") {
            let _ = std::fs::create_dir_all(&logs);
            let _ = std::fs::copy(
                &self.log,
                Path::new(&logs).join(format!("node-{}.log", self.number)),
            );
        }
    }
}

impl Process {
    fn pid(&self) -> u32 {
        self.running.lock().unwrap().pid()
    }

    pub fn operator(&self) -> Operator {
        let token =
            std::fs::read_to_string(self.data.join(vos_node::ADMIN_TOKEN)).unwrap_or_default();
        Operator::new(&self.target, &token)
    }

    /// Kill it (SIGKILL).
    pub fn kill(&self) {
        self.running.lock().unwrap().kill();
    }

    /// Start it again: how long until it listens.
    pub fn restart(&self) -> Duration {
        let started = Instant::now();
        let args: Vec<&str> = self.args.iter().map(String::as_str).collect();
        let (running, _) = launch(&args, self.cpus.as_deref(), &self.log);
        *self.running.lock().unwrap() = running;
        started.elapsed()
    }

    /// Its CPU so far, in seconds.
    pub fn cpu(&self) -> f64 {
        stat_cpu(&std::fs::read_to_string(format!("/proc/{}/stat", self.pid())).unwrap_or_default())
    }

    /// Each of its executor threads' CPU so far, in seconds.
    fn executors_cpu(&self) -> Vec<f64> {
        threads_cpu(self.pid(), "vos-executor")
    }

    /// Its runtime thread's, its writer's, its network's and fjall's
    /// workers' (flushes and compactions) CPU so far, in seconds.
    fn others_cpu(&self) -> [f64; 4] {
        let pid = self.pid();
        let sum = |named: &str| threads_cpu(pid, named).iter().sum();
        [
            sum("vos-node"),
            sum("vos-storage"),
            sum("vos-net"),
            sum("fjall"),
        ]
    }

    /// Its anonymous memory backed by huge pages, in MiB.
    pub fn huge_pages(&self) -> u64 {
        std::fs::read_to_string(format!("/proc/{}/smaps_rollup", self.pid()))
            .unwrap_or_default()
            .lines()
            .find_map(|line| line.strip_prefix("AnonHugePages:"))
            .and_then(|value| value.split_whitespace().next()?.parse::<u64>().ok())
            .unwrap_or(0)
            / 1024
    }

    /// Its threads and its resident memory in MiB.
    pub fn threads_and_rss(&self) -> (u64, u64) {
        let status =
            std::fs::read_to_string(format!("/proc/{}/status", self.pid())).unwrap_or_default();
        let field = |name: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .and_then(|value| value.split_whitespace().next()?.parse::<u64>().ok())
                .unwrap_or(0)
        };
        (field("Threads:"), field("VmRSS:") / 1024)
    }
}

/// The `vos` that runs the nodes: `VOS_BIN`, or this build's.
fn vos() -> PathBuf {
    std::env::var("VOS_BIN")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_vos").into())
        .into()
}

/// Run `vos node run` with `args`, pinned to `cpus` if any, its log
/// appended to `log`: the process, once it printed its address, and its
/// key.
fn launch(args: &[&str], cpus: Option<&str>, log: &Path) -> (Running, String) {
    let started = processes::run(&vos(), args, log, None, cpus)
        .unwrap_or_else(|| panic!("{}", read_log(log)));
    (started.running, started.key)
}

/// The nodes, each pinned to its share of the machine.
pub struct Space {
    pub processes: Vec<Process>,
    /// The increments each agent answered as run, every run's.
    pub ran: Mutex<HashMap<AgentId, u64>>,
    _dir: tempfile::TempDir,
}

impl Space {
    pub fn start(pinned: bool, cpus: &[String]) -> Self {
        // Under `target/` by default (on the reference laptop `/tmp` is
        // tmpfs); `DATA` puts the stores elsewhere, `/tmp` to take the
        // disk out of a run.
        let base = std::env::var("DATA").unwrap_or_else(|_| env!("CARGO_TARGET_TMPDIR").into());
        let dir = tempfile::Builder::new()
            .prefix("processes-")
            .tempdir_in(base)
            .unwrap();
        let keys: Vec<String> = (1..=NODES)
            .map(|number| {
                first_run(
                    &vos(),
                    &dir.path().join(format!("node-{number}")),
                    &dir.path().join(format!("first-{number}.log")),
                )
            })
            .collect();
        let ingress: Vec<u16> = (0..NODES).map(|_| free_tcp_port()).collect();
        let peers: Vec<u16> = (0..NODES).map(|_| free_udp_port()).collect();
        let tls = std::env::var("TLS").is_ok_and(|tls| tls == "1");
        let scheme = if tls { "https" } else { "http" };
        let space: String = (0..NODES)
            .map(|at| {
                format!(
                    "{} {} 127.0.0.1:{} {scheme}://127.0.0.1:{}\n",
                    at + 1,
                    keys[at],
                    peers[at],
                    ingress[at]
                )
            })
            .collect();
        let space_file = dir.path().join("space");
        std::fs::write(&space_file, space).unwrap();
        let processes = (1..=NODES as u8)
            .map(|number| {
                let at = usize::from(number) - 1;
                let data = dir.path().join(format!("node-{number}"));
                let listen = format!("127.0.0.1:{}", ingress[at]);
                let log = dir.path().join(format!("node-{number}.log"));
                let mut args: Vec<String> = [
                    "--data",
                    data.to_str().unwrap(),
                    "--listen",
                    &listen,
                    "--space",
                    space_file.to_str().unwrap(),
                ]
                .iter()
                .map(|arg| arg.to_string())
                .collect();
                if tls {
                    args.push("--tls".into());
                }
                let pinning = pinned.then(|| cpus[at].clone());
                let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
                let (running, key) = launch(&borrowed, pinning.as_deref(), &log);
                assert_eq!(key, keys[at]);
                let url = format!("{scheme}://{listen}");
                let trust = if tls {
                    let mut pinned = [0u8; 32];
                    hex::decode_to_slice(&key, &mut pinned).unwrap();
                    Trust::NodeKey(pinned)
                } else {
                    Trust::Loopback
                };
                Process {
                    running: Mutex::new(running),
                    number,
                    target: Target::new(&url, trust).unwrap(),
                    url,
                    data,
                    args,
                    cpus: pinning,
                    log,
                }
            })
            .collect();
        Self {
            processes,
            ran: Mutex::new(HashMap::new()),
            _dir: dir,
        }
    }

    pub fn by_url(&self, url: &str) -> Option<usize> {
        self.processes.iter().position(|process| process.url == url)
    }

    /// An operator's command, at whichever node takes it.
    fn operate(
        &self,
        command: impl Fn(&Operator) -> Response,
        taken: impl Fn(&Response) -> bool,
    ) -> Response {
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            for process in &self.processes {
                let answer = command(&process.operator());
                if taken(&answer) {
                    return answer;
                }
            }
            assert!(Instant::now() < until, "no node took an operator's command");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// An agent on every node.
    pub fn create_agent(&self) -> AgentId {
        let every: Vec<u8> = (1..=NODES as u8).collect();
        let Response::Created(agent) = self.operate(
            |operator| {
                operator
                    .create_agent(every.clone())
                    .unwrap_or(Response::Unavailable)
            },
            |answer| matches!(answer, Response::Created(_)),
        ) else {
            unreachable!()
        };
        agent
    }

    /// An agent on every node, with the counter's package installed.
    pub fn counter_agent(&self, counter: &[u8]) -> AgentId {
        let agent = self.create_agent();
        let install = Install {
            instance: COUNTER,
            elf: counter.to_vec(),
            roles: Vec::new(),
        };
        self.operate(
            |operator| {
                operator
                    .install(agent, &install)
                    .unwrap_or(Response::Unavailable)
            },
            |answer| matches!(answer, Response::Ran { .. }),
        );
        agent
    }

    /// The node leading `agent`, by index.
    pub fn leader(&self, agent: AgentId) -> usize {
        let until = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(at) = self.processes.iter().position(|process| {
                matches!(process.operator().status(agent), Ok(Response::Status(status)) if status.leads)
            }) {
                return at;
            }
            assert!(Instant::now() < until, "agent {} has no leader", agent.0);
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn cpu(&self) -> Vec<f64> {
        self.processes.iter().map(Process::cpu).collect()
    }

    fn executors_cpu(&self) -> Vec<Vec<f64>> {
        self.processes.iter().map(Process::executors_cpu).collect()
    }
}

/// CPU at a run's window's edges: each node's, each node's executors',
/// runtime thread's, writer's, network's and fjall workers', and the
/// driver's.
#[derive(Clone, Default)]
pub struct Cpu {
    pub nodes: Vec<f64>,
    pub executors: Vec<Vec<f64>>,
    pub others: Vec<[f64; 4]>,
    pub driver: f64,
    /// The machine's, every process's.
    pub machine: f64,
    pub io_stalled: f64,
    /// Each stage's counts, summed over the nodes, from their stats route.
    pub stages: Vec<(String, Vec<u64>)>,
    /// Each stage's values' sum, over the nodes.
    pub totals: Vec<(String, u64)>,
}

impl Cpu {
    pub fn now(space: &Space) -> Self {
        let mut stages: Vec<(String, Vec<u64>)> = Vec::new();
        let mut totals: Vec<(String, u64)> = Vec::new();
        for process in &space.processes {
            if let Ok(Response::Stats(stats)) = process.operator().stats() {
                for stage in stats.stages {
                    match totals.iter_mut().find(|(name, _)| *name == stage.name) {
                        Some((_, total)) => *total = total.wrapping_add(stage.total),
                        None => totals.push((stage.name.clone(), stage.total)),
                    }
                    match stages.iter_mut().find(|(name, _)| *name == stage.name) {
                        Some((_, counts)) => {
                            for (sum, count) in counts.iter_mut().zip(&stage.counts) {
                                *sum += count;
                            }
                        }
                        None => stages.push((stage.name, stage.counts)),
                    }
                }
            }
        }
        Self {
            nodes: space.cpu(),
            executors: space.executors_cpu(),
            others: space.processes.iter().map(Process::others_cpu).collect(),
            driver: driver_cpu(),
            machine: machine_cpu(),
            io_stalled: io_stalled(),
            stages,
            totals,
        }
    }
}
