//! Section 14's budgets on three node processes (slice 3, step 3.10):
//! three release builds of `vos node run`, each pinned to a third of the
//! laptop (`taskset`) and on its own data directory, joined over QUIC; a
//! driver on the rest of the machine sends calls over HTTP, every one
//! signed before its timed window.
//! - **agent:** one agent, the most commits per second, closed loop, over
//!   sessions; then at half load, max(10k/s, half the most), open loop.
//! - **agents:** 64 agents, the most, closed loop at 4 and 16 sessions
//!   each; open loop at 40k/s offered; and the knee, the highest offered
//!   rate whose p99 stays at 20 ms or below.
//! - **quiet:** one session, one call at a time.
//! - **query:** the counter's value on a follower, open loop, as applied
//!   there.
//! - **linearizable:** the same at `Linearizable`: the heartbeat round
//!   each read takes is the difference.
//! - **idle:** 1,000 agents per node left alone: each process's CPU,
//!   threads and memory.
//! - **failover** (on the 64 agents, with or without their rows): the
//!   node leading the most of them killed, the time until each has a
//!   leader again and every node's directory names it, and its restart.
//! - **failover-idle:** the same on the idle row's 1,000 agents a node
//!   (with or without that row).
//! - **soak** (on the 64 agents, after any failover): their load open for
//!   `SOAK_SECONDS` (1,800) at `SOAK_RATE` (6k/s), one load throughout:
//!   CPU per commit, p50, p95 and the stalls compared early and late.
//!
//! Every open-loop latency is timed from when its call was scheduled to
//! go, so a slow call never hides the queue behind it; each such run gives
//! its send lag, and one whose p99 lag passes 0.5 ms is marked invalid.
//! Each run gives every process's CPU, and the CPU per commit.
//!
//! `cargo bench -p vos-cli --bench processes` (after `just build-agent
//! build-test-actors`). Its settings:
//! - `ROWS` picks rows (`agent,agents,quiet,query,linearizable,idle,
//!   failover,failover-idle,soak`; all but the last three by default);
//! - `CPUS` overrides the pinning, as `taskset -c` lists for each node and
//!   the driver, separated by `/`;
//! - `DATA` where the stores go;
//! - `VOS_BIN` another `vos` to run the nodes, for a lever's A/B runs;
//! - `LOGS` a directory to keep the nodes' logs in;
//! - `TLS=1` serves every node's ingress over TLS, each client pinning the
//!   node's key, for the rows against plain HTTP.
//!
//! `machine.sh`, beside this file, runs the rows on a machine of its own,
//! each node on cores of its own.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use smol::io::{AsyncReadExt, AsyncWriteExt};
use vos_node::client::{Operator, Target};
use vos_node::tls::Trust;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Session};
use vos_wire::ingress::{
    Answer, Call, Consistency, Install, QueryCall, call_message, query_message,
};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};

const COUNTER: InstanceId = InstanceId(1);
const WARM: Duration = Duration::from_secs(2);
const MEASURE: Duration = Duration::from_secs(5);
const IDLE_SETTLE: Duration = Duration::from_secs(5);
const IDLE_MEASURE: Duration = Duration::from_secs(10);
/// The most an open-loop run's p99 send lag may be.
const LAG: Duration = Duration::from_micros(500);
/// The p99 the many-agent budget allows.
const KNEE_P99: Duration = Duration::from_millis(20);
/// A soak window is clean while the machine ran under this many cores
/// outside the run, and every task on it waited on IO under this share.
const CLEAN_OUTSIDE: f64 = 1.5;
const CLEAN_IO: f64 = 10.0;
/// The pinning on the reference laptop: each node two P-cores (four
/// threads) and two E-cores; the driver the rest.
const CPUS: [&str; 4] = [
    "0,5,1,2,12,13",
    "3,4,6,7,14,15",
    "8,9,10,11,16,17",
    "18,19,20,21",
];

fn guest(path: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../agent")
        .join(path);
    assert!(
        path.exists(),
        "{}: run `just build-agent build-test-actors`",
        path.display()
    );
    path
}

fn rows() -> Vec<String> {
    std::env::var("ROWS")
        .unwrap_or_else(|_| "agent,agents,quiet,query,linearizable,idle".into())
        .split(',')
        .map(|row| row.trim().to_string())
        .collect()
}

fn cpus() -> Vec<String> {
    match std::env::var("CPUS") {
        Ok(cpus) => cpus.split('/').map(str::to_string).collect(),
        Err(_) => CPUS.iter().map(|cpus| cpus.to_string()).collect(),
    }
}

fn pinning() -> bool {
    Command::new("taskset")
        .arg("-V")
        .output()
        .is_ok_and(|output| output.status.success())
}

/// Pin the calling thread to `cpus`, by its thread id.
fn pin_thread(cpus: &str) {
    let tid = std::fs::read_link("/proc/thread-self")
        .ok()
        .and_then(|link| link.file_name()?.to_str()?.parse::<u32>().ok());
    if let Some(tid) = tid {
        let _ = Command::new("taskset")
            .args(["-p", "-c", cpus, &tid.to_string()])
            .stdout(Stdio::null())
            .status();
    }
}

fn free_port(udp: bool) -> u16 {
    if udp {
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    } else {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
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
fn transparent_huge_pages() -> Vec<(String, u64)> {
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
struct Process {
    child: Mutex<Child>,
    number: u8,
    url: String,
    target: Target,
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
        let child = self.child.get_mut().unwrap();
        let _ = child.kill();
        let _ = child.wait();
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
        self.child.lock().unwrap().id()
    }

    fn operator(&self) -> Operator {
        let token =
            std::fs::read_to_string(self.data.join(vos_node::ADMIN_TOKEN)).unwrap_or_default();
        Operator::new(&self.target, &token)
    }

    /// Kill it (SIGKILL).
    fn kill(&self) {
        let mut child = self.child.lock().unwrap();
        let _ = child.kill();
        let _ = child.wait();
    }

    /// Start it again: how long until it listens.
    fn restart(&self) -> Duration {
        let started = Instant::now();
        let args: Vec<&str> = self.args.iter().map(String::as_str).collect();
        let (child, _) = launch(&args, self.cpus.as_deref(), &self.log);
        *self.child.lock().unwrap() = child;
        started.elapsed()
    }

    /// Its CPU so far, in seconds.
    fn cpu(&self) -> f64 {
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
    fn huge_pages(&self) -> u64 {
        std::fs::read_to_string(format!("/proc/{}/smaps_rollup", self.pid()))
            .unwrap_or_default()
            .lines()
            .find_map(|line| line.strip_prefix("AnonHugePages:"))
            .and_then(|value| value.split_whitespace().next()?.parse::<u64>().ok())
            .unwrap_or(0)
            / 1024
    }

    /// Its threads and its resident memory in MiB.
    fn threads_and_rss(&self) -> (u64, u64) {
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

/// Run `vos node run` with `args`, pinned to `cpus` if any: the process,
/// once it printed its address, and its key.
fn launch(args: &[&str], cpus: Option<&str>, log: &Path) -> (Child, String) {
    // Appended to, so a restart keeps what came before.
    let errors = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .unwrap();
    let vos = std::env::var("VOS_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_vos").into());
    let vos = vos.as_str();
    let agent = guest("default/target/riscv64em-vos/release/vos-agent.elf");
    let mut command = match cpus {
        Some(cpus) => {
            let mut command = Command::new("taskset");
            command.args(["-c", cpus, vos]);
            command
        }
        None => Command::new(vos),
    };
    command
        .args(["node", "run"])
        .args(args)
        .arg("--agent")
        .arg(agent)
        .stdout(Stdio::piped())
        .stderr(errors);
    let mut child = command.spawn().expect("vos runs");
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let listening = lines.next().and_then(Result::ok).unwrap_or_default();
    assert!(
        listening.starts_with("listening on "),
        "{}",
        std::fs::read_to_string(log).unwrap_or_default()
    );
    let key = lines
        .next()
        .and_then(Result::ok)
        .and_then(|line| line.strip_prefix("node ").map(str::to_string))
        .expect("the node's key");
    std::thread::spawn(move || for _ in lines {});
    (child, key)
}

/// Three nodes, each pinned to its share of the machine.
struct Space {
    processes: Vec<Process>,
    /// The increments each agent answered as run, every run's.
    ran: Mutex<HashMap<AgentId, u64>>,
    _dir: tempfile::TempDir,
}

impl Space {
    fn start(pinned: bool, cpus: &[String]) -> Self {
        // Under `target/` by default (on the reference laptop `/tmp` is
        // tmpfs); `DATA` puts the stores elsewhere, `/tmp` to take the
        // disk out of a run.
        let base = std::env::var("DATA").unwrap_or_else(|_| env!("CARGO_TARGET_TMPDIR").into());
        let dir = tempfile::Builder::new()
            .prefix("processes-")
            .tempdir_in(base)
            .unwrap();
        let keys: Vec<String> = (1..=3)
            .map(|number| {
                let data = dir.path().join(format!("node-{number}"));
                let log = dir.path().join(format!("first-{number}.log"));
                let (mut child, key) = launch(
                    &["--data", data.to_str().unwrap(), "--listen", "127.0.0.1:0"],
                    None,
                    &log,
                );
                let _ = child.kill();
                let _ = child.wait();
                key
            })
            .collect();
        let ingress: Vec<u16> = (0..3).map(|_| free_port(false)).collect();
        let peers: Vec<u16> = (0..3).map(|_| free_port(true)).collect();
        let tls = std::env::var("TLS").is_ok_and(|tls| tls == "1");
        let scheme = if tls { "https" } else { "http" };
        let space: String = (0..3)
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
        let processes = (1..=3u8)
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
                let (child, key) = launch(&borrowed, pinning.as_deref(), &log);
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
                    child: Mutex::new(child),
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

    fn by_url(&self, url: &str) -> Option<usize> {
        self.processes.iter().position(|process| process.url == url)
    }

    /// An operator's command, at whichever node takes it.
    fn operate(
        &self,
        command: impl Fn(&Operator) -> Answer,
        taken: impl Fn(&Answer) -> bool,
    ) -> Answer {
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

    /// An agent on the three nodes, with the counter installed.
    fn counter_agent(&self, counter: &[u8]) -> AgentId {
        let Answer::Created(agent) = self.operate(
            |operator| {
                operator
                    .create_agent(vec![1, 2, 3])
                    .unwrap_or(Answer::Unavailable)
            },
            |answer| matches!(answer, Answer::Created(_)),
        ) else {
            unreachable!()
        };
        let install = Install {
            instance: COUNTER,
            program: counter.to_vec(),
            attestables: Vec::new(),
            roles: Vec::new(),
        };
        self.operate(
            |operator| {
                operator
                    .install(agent, &install)
                    .unwrap_or(Answer::Unavailable)
            },
            |answer| matches!(answer, Answer::Ran { .. }),
        );
        agent
    }

    /// The node leading `agent`, by index.
    fn leader(&self, agent: AgentId) -> usize {
        let until = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(at) = self.processes.iter().position(|process| {
                matches!(process.operator().status(agent), Ok(Answer::Status(status)) if status.leads)
            }) {
                return at;
            }
            assert!(Instant::now() < until, "agent {} has no leader", agent.0);
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn cpu(&self) -> Vec<f64> {
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
struct Cpu {
    nodes: Vec<f64>,
    executors: Vec<Vec<f64>>,
    others: Vec<[f64; 4]>,
    driver: f64,
    /// The machine's, every process's.
    machine: f64,
    io_stalled: f64,
    /// Each stage's counts, summed over the nodes, from their stats route.
    stages: Vec<(String, Vec<u64>)>,
    /// Each stage's values' sum, over the nodes.
    totals: Vec<(String, u64)>,
}

impl Cpu {
    fn now(space: &Space) -> Self {
        let mut stages: Vec<(String, Vec<u64>)> = Vec::new();
        let mut totals: Vec<(String, u64)> = Vec::new();
        for process in &space.processes {
            if let Ok(Answer::Stats(stats)) = process.operator().stats() {
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

/// What the driver needs of an agent to sign its calls.
#[derive(Clone, Copy)]
struct Signed {
    agent: AgentId,
    identity: [u8; 32],
    increment: MethodId,
    value: MethodId,
}

fn signed(space: &Space, agent: AgentId) -> Signed {
    // At whichever node has applied its install.
    let until = Instant::now() + Duration::from_secs(30);
    let (info, schema) = loop {
        let served = space.processes.iter().find_map(|process| {
            let info = vos_node::client::agent_info(&process.target, agent).ok()??;
            let schema = vos_node::client::schema(&process.target, agent, COUNTER).ok()??;
            Some((info, schema))
        });
        if let Some(served) = served {
            break served;
        }
        assert!(
            Instant::now() < until,
            "agent {}'s schema is not served",
            agent.0
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let method = |name: &str| {
        schema
            .methods
            .iter()
            .find(|method| method.name == name.as_bytes())
            .unwrap()
            .id
    };
    Signed {
        agent,
        identity: vos_node::identity(&info.record),
        increment: method("increment"),
        value: method("value"),
    }
}

/// One session's calls: the node it starts at, and each call's path and
/// body in order.
struct Plan {
    /// The agent whose counter its calls increment, if they do.
    counts: Option<AgentId>,
    node: usize,
    path: String,
    bodies: Bodies,
}

/// A plan's call bodies: signed before the run, or one at a time as it
/// goes, after each answer, for runs too long to sign ahead.
enum Bodies {
    Ready(std::vec::IntoIter<Vec<u8>>),
    Signing(Box<Signing>),
}

/// Calls signed as a plan goes, in a new session every `every` calls, as
/// clients come and go: session `number`, then `number + stride`, and so
/// on.
struct Signing {
    signed: Signed,
    number: u64,
    stride: u64,
    every: u64,
    key: SessionKey,
    /// The plan's next call, from 1, and its last.
    next: u64,
    last: u64,
}

impl Bodies {
    fn next(&mut self) -> Option<Vec<u8>> {
        match self {
            Bodies::Ready(bodies) => bodies.next(),
            Bodies::Signing(signing) => {
                if signing.next > signing.last {
                    return None;
                }
                let sequence = (signing.next - 1) % signing.every + 1;
                if sequence == 1 && signing.next > 1 {
                    signing.number += signing.stride;
                    signing.key = SessionKey::new(&signing.signed, signing.number);
                }
                signing.next += 1;
                Some(signing.key.sign(sequence))
            }
        }
    }
}

/// What signs a session's increments.
struct SessionKey {
    key: SigningKey,
    session: Session,
    identity: [u8; 32],
    increment: MethodId,
}

impl SessionKey {
    /// Session `number` at `signed`'s agent.
    fn new(signed: &Signed, number: u64) -> Self {
        let mut seed = [7u8; 32];
        seed[..8].copy_from_slice(&number.to_le_bytes());
        seed[8..12].copy_from_slice(&signed.agent.0.to_le_bytes());
        let key = SigningKey::from_bytes(&seed);
        let mut name = [0u8; 16];
        name[..8].copy_from_slice(&number.to_le_bytes());
        let session = Session {
            key: key.verifying_key().to_bytes(),
            name,
            t0: vos_node::wall_clock(),
        };
        Self {
            key,
            session,
            identity: signed.identity,
            increment: signed.increment,
        }
    }

    /// The increment at `sequence`, signed.
    fn sign(&self, sequence: u64) -> Vec<u8> {
        let arguments = 1u64.encode();
        let message = call_message(
            &self.identity,
            &self.session,
            sequence,
            COUNTER,
            self.increment,
            &arguments,
        );
        Call {
            session: self.session,
            sequence,
            instance: COUNTER,
            method: self.increment,
            arguments,
            signature: self.key.sign(&message).to_bytes(),
        }
        .encode()
    }
}

/// `calls` increments in a new session `number` at `signed`'s agent,
/// signed now.
fn session_plan(signed: &Signed, number: u64, calls: usize, node: usize) -> Plan {
    let signer = SessionKey::new(signed, number);
    let bodies: Vec<Vec<u8>> = (1..=calls as u64)
        .map(|sequence| signer.sign(sequence))
        .collect();
    Plan {
        counts: Some(signed.agent),
        node,
        path: format!("/agents/{}/calls", signed.agent.0),
        bodies: Bodies::Ready(bodies.into_iter()),
    }
}

/// `calls` increments at `signed`'s agent, each signed as it goes, in
/// session `number` and then a new one every `every` calls, `stride`
/// apart.
fn signing_plan(
    signed: &Signed,
    (number, stride, every): (u64, u64, u64),
    calls: usize,
    node: usize,
) -> Plan {
    Plan {
        counts: Some(signed.agent),
        node,
        path: format!("/agents/{}/calls", signed.agent.0),
        bodies: Bodies::Signing(Box::new(Signing {
            signed: *signed,
            number,
            stride,
            every,
            key: SessionKey::new(signed, number),
            next: 1,
            last: calls as u64,
        })),
    }
}

/// Plans signed on the driver's threads at once.
fn sign_plans(jobs: Vec<(Signed, u64, usize, usize)>) -> Vec<Plan> {
    let threads = 4;
    let chunk = jobs.len().div_ceil(threads).max(1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = jobs
            .chunks(chunk)
            .map(|jobs| {
                scope.spawn(move || {
                    jobs.iter()
                        .map(|(signed, number, calls, node)| {
                            session_plan(signed, *number, *calls, *node)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap())
            .collect()
    })
}

trait Stream: smol::io::AsyncRead + smol::io::AsyncWrite + Unpin + Send {}
impl<T: smol::io::AsyncRead + smol::io::AsyncWrite + Unpin + Send> Stream for T {}

/// HTTP/1.1 on a connection kept open.
struct Http {
    stream: Box<dyn Stream>,
    authority: String,
    buffer: Vec<u8>,
}

impl Http {
    async fn connect(target: &Target) -> std::io::Result<Self> {
        let tcp = smol::net::TcpStream::connect(target.authority()).await?;
        tcp.set_nodelay(true)?;
        let stream: Box<dyn Stream> = match target.tls() {
            Some((config, name)) => Box::new(
                futures_rustls::TlsConnector::from(config)
                    .connect(name, tcp)
                    .await?,
            ),
            None => Box::new(tcp),
        };
        Ok(Self {
            stream,
            authority: target.authority().to_string(),
            buffer: Vec::with_capacity(4096),
        })
    }

    async fn post(&mut self, path: &str, body: &[u8]) -> std::io::Result<Answer> {
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n",
            self.authority,
            body.len()
        );
        let mut request = Vec::with_capacity(head.len() + body.len());
        request.extend_from_slice(head.as_bytes());
        request.extend_from_slice(body);
        self.stream.write_all(&request).await?;
        self.stream.flush().await?;
        let invalid = |why: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, why);
        let mut chunk = [0u8; 8192];
        loop {
            let mut headers = [httparse::EMPTY_HEADER; 16];
            let mut response = httparse::Response::new(&mut headers);
            if let httparse::Status::Complete(head) = response
                .parse(&self.buffer)
                .map_err(|_| invalid("not HTTP"))?
            {
                let length = response
                    .headers
                    .iter()
                    .find(|header| header.name.eq_ignore_ascii_case("content-length"))
                    .and_then(|header| {
                        std::str::from_utf8(header.value)
                            .ok()?
                            .trim()
                            .parse::<usize>()
                            .ok()
                    })
                    .ok_or_else(|| invalid("no length"))?;
                while self.buffer.len() < head + length {
                    let read = self.stream.read(&mut chunk).await?;
                    if read == 0 {
                        return Err(invalid("closed"));
                    }
                    self.buffer.extend_from_slice(&chunk[..read]);
                }
                let answer = Answer::decode(&self.buffer[head..head + length])
                    .map(|(answer, _)| answer)
                    .map_err(|_| invalid("no answer"));
                self.buffer.drain(..head + length);
                return answer;
            }
            let read = self.stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(invalid("closed"));
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }
}

/// What a run measured: each call's latency, and in an open loop its send
/// lag, for the calls scheduled in the timed window.
#[derive(Default)]
struct Samples {
    latencies: Vec<Duration>,
    lags: Vec<Duration>,
    failed: u64,
    /// The first answer that was not a call run to completion.
    first_failure: Option<String>,
    /// Calls in an open loop that waited for their session's previous call
    /// to be answered: the nodes, not the driver, held them.
    behind: u64,
    /// Calls answered after their window ended: a backlog past the knee,
    /// once more than the few in flight at its end.
    answered_after: u64,
    /// The latencies of the calls scheduled in the window's first quarter,
    /// and in its last: past the knee the backlog, and with it the
    /// latency, grows across the window.
    first_quarter: Vec<Duration>,
    last_quarter: Vec<Duration>,
    /// Sessions whose signed calls ran out before the window ended.
    exhausted: u64,
}

fn percentile(sorted: &[Duration], at: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    sorted[((sorted.len() - 1) as f64 * at).round() as usize]
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// When calls go: back to back, or each at its scheduled time.
#[derive(Clone, Copy)]
enum Pace {
    Closed,
    /// One call every so long per session, the sessions staggered.
    Open(Duration),
}

/// Send one call until it is answered, following the leader: its answer,
/// or none once the run ends.
async fn call(
    space: &Space,
    http: &mut Option<Http>,
    node: &mut usize,
    path: &str,
    body: &[u8],
    until: Instant,
) -> Option<Answer> {
    loop {
        if Instant::now() >= until + Duration::from_secs(10) {
            return None;
        }
        if http.is_none() {
            *http = Http::connect(&space.processes[*node].target).await.ok();
        }
        let Some(connection) = http.as_mut() else {
            smol::Timer::after(Duration::from_millis(10)).await;
            continue;
        };
        match connection.post(path, body).await {
            Ok(answer @ Answer::Ran { .. }) => return Some(answer),
            Ok(Answer::NotLeader {
                leader: Some(leader),
            }) => {
                if let Some(at) = space.by_url(&leader.address) {
                    *node = at;
                }
                *http = None;
            }
            Ok(
                Answer::Busy | Answer::Unavailable | Answer::TimedOut | Answer::NotLeader { .. },
            ) => {
                smol::Timer::after(Duration::from_millis(2)).await;
            }
            Ok(other) => return Some(other),
            Err(_) => {
                *http = None;
                smol::Timer::after(Duration::from_millis(10)).await;
            }
        }
    }
}

/// Run `plans` paced as `pace`, measuring the calls scheduled in the
/// window after the warm-up, on the driver's executor: two threads, each
/// on one of the driver's first two cores. With the samples, each node's
/// CPU at the window's start and end.
fn drive(space: &Space, plans: Vec<Plan>, pace: Pace, measure: Duration) -> (Samples, (Cpu, Cpu)) {
    drive_windows(space, plans, pace, measure, 1)
        .pop()
        .expect("one window")
}

/// As [`drive`], over `windows` windows of `measure` back to back, one
/// load throughout: each window's samples, and the CPU at its edges.
fn drive_windows(
    space: &Space,
    plans: Vec<Plan>,
    pace: Pace,
    measure: Duration,
    windows: usize,
) -> Vec<(Samples, (Cpu, Cpu))> {
    let samples: Mutex<Vec<Samples>> =
        Mutex::new((0..windows).map(|_| Samples::default()).collect());
    let edges_cpu = Mutex::new(Vec::new());
    let stop = AtomicBool::new(false);
    let executor = smol::Executor::new();
    let start = Instant::now() + Duration::from_millis(200);
    let first = start + WARM;
    let end = first + measure * windows as u32;
    // The window a call scheduled `from` counts in, if any.
    let window_of = move |from: Instant| {
        (from >= first && from < end).then(|| {
            (((from - first).as_secs_f64() / measure.as_secs_f64()) as usize).min(windows - 1)
        })
    };
    let count = plans.len() as u32;
    let cores: Vec<String> = cpus()
        .get(3)
        .map(|cpus| cpus.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    std::thread::scope(|scope| {
        let edges_cpu = &edges_cpu;
        scope.spawn(move || {
            for edge in 0..=windows {
                let at = first + measure * edge as u32;
                std::thread::sleep(at.saturating_duration_since(Instant::now()));
                let cpu = Cpu::now(space);
                edges_cpu.lock().unwrap().push(cpu);
            }
        });
        for thread in 0..2 {
            let (executor, stop, core) = (&executor, &stop, cores.get(thread).cloned());
            scope.spawn(move || {
                if let Some(core) = core {
                    pin_thread(&core);
                }
                smol::block_on(executor.run(async {
                    while !stop.load(Ordering::Relaxed) {
                        smol::Timer::after(Duration::from_millis(20)).await;
                    }
                }));
            });
        }
        let tasks: Vec<_> = plans
            .into_iter()
            .enumerate()
            .map(|(at, plan)| {
                let samples = &samples;
                executor.spawn(async move {
                    let mut node = plan.node;
                    let mut http = None;
                    let mut mine: Vec<Samples> = (0..windows).map(|_| Samples::default()).collect();
                    let mut scheduled = start
                        + match pace {
                            Pace::Closed => Duration::ZERO,
                            Pace::Open(interval) => interval * at as u32 / count,
                        };
                    smol::Timer::at(scheduled).await;
                    let mut bodies = plan.bodies;
                    // When the session's previous call was answered: no
                    // call goes before it.
                    let mut previous = scheduled;
                    // Its increments run, in or out of the windows.
                    let mut ran = 0u64;
                    while scheduled < end {
                        // Signed, when it is signed as it goes, in the
                        // session's time between calls.
                        let Some(body) = bodies.next() else {
                            let window = if scheduled < first {
                                0
                            } else {
                                window_of(scheduled).unwrap_or(windows - 1)
                            };
                            mine[window].exhausted += 1;
                            break;
                        };
                        if let Pace::Open(_) = pace {
                            smol::Timer::at(scheduled).await;
                        }
                        let sent = Instant::now();
                        let from = match pace {
                            Pace::Closed => sent,
                            Pace::Open(_) => scheduled,
                        };
                        let answer =
                            call(space, &mut http, &mut node, &plan.path, &body, end).await;
                        let answered = Instant::now();
                        if matches!(
                            answer,
                            Some(Answer::Ran {
                                outcome: Outcome::Done(_),
                                ..
                            })
                        ) {
                            ran += 1;
                        }
                        if let Some(window) = window_of(from) {
                            let opened = first + measure * window as u32;
                            if answered >= opened + measure {
                                mine[window].answered_after += 1;
                            }
                            let into = from - opened;
                            if into < measure / 4 {
                                mine[window].first_quarter.push(answered - from);
                            } else if into >= measure * 3 / 4 {
                                mine[window].last_quarter.push(answered - from);
                            }
                            let mine = &mut mine[window];
                            match answer {
                                Some(Answer::Ran {
                                    outcome: Outcome::Done(_),
                                    ..
                                }) => {
                                    mine.latencies.push(answered - from);
                                    if let Pace::Open(_) = pace {
                                        // The driver's own lateness: past
                                        // the schedule and the previous
                                        // answer both.
                                        mine.lags.push(
                                            sent.saturating_duration_since(scheduled.max(previous)),
                                        );
                                        if previous > scheduled {
                                            mine.behind += 1;
                                        }
                                    }
                                }
                                other => {
                                    mine.failed += 1;
                                    mine.first_failure.get_or_insert(format!("{other:?}"));
                                }
                            }
                        }
                        previous = answered;
                        scheduled = match pace {
                            Pace::Closed => answered,
                            Pace::Open(interval) => scheduled + interval,
                        };
                    }
                    if let Some(agent) = plan.counts {
                        *space.ran.lock().unwrap().entry(agent).or_default() += ran;
                    }
                    let mut samples = samples.lock().unwrap();
                    for (samples, mine) in samples.iter_mut().zip(mine) {
                        samples.latencies.extend(mine.latencies);
                        samples.lags.extend(mine.lags);
                        samples.failed += mine.failed;
                        samples.exhausted += mine.exhausted;
                        samples.behind += mine.behind;
                        samples.answered_after += mine.answered_after;
                        samples.first_quarter.extend(mine.first_quarter);
                        samples.last_quarter.extend(mine.last_quarter);
                        if samples.first_failure.is_none() {
                            samples.first_failure = mine.first_failure;
                        }
                    }
                })
            })
            .collect();
        for task in tasks {
            smol::block_on(task);
        }
        stop.store(true, Ordering::Relaxed);
    });
    drop(executor);
    let edges = edges_cpu.into_inner().unwrap();
    let mut edges = edges.into_iter();
    let mut before = edges.next().unwrap_or_default();
    samples
        .into_inner()
        .unwrap()
        .into_iter()
        .map(|samples| {
            let after = edges.next().unwrap_or_default();
            let cpu = (std::mem::replace(&mut before, after.clone()), after);
            (samples, cpu)
        })
        .collect()
}

/// What a run gave: commits (or calls) per second, its percentiles, each
/// node's busy cores, how clean the machine was, and its stalls.
struct Measured {
    commits: f64,
    p50: Duration,
    p95: Duration,
    p99: Duration,
    busy: Vec<f64>,
    /// The machine's CPU outside the run, in cores, and the share of the
    /// window every task on it waited on IO.
    outside: f64,
    io: f64,
    /// The runtime probe's wakes over [`STALL`] late, every node's.
    stalls: u64,
    /// Batches longer than [`STALL`], every node's, and the longest, in
    /// µs (a bucket's top).
    long_batches: u64,
    longest_batch: u64,
}

/// A stage this long or longer is a stall: about 50 ms, at a bucket's
/// edge, so a bucket counts whole.
const STALL: u64 = 49_152;

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
fn report(name: &str, samples: &mut Samples, cpu: (Cpu, Cpu), measure: Duration) -> Measured {
    samples.latencies.sort();
    samples.lags.sort();
    let seconds = measure.as_secs_f64();
    let commits = samples.latencies.len() as f64 / seconds;
    let p50 = percentile(&samples.latencies, 0.50);
    let p95 = percentile(&samples.latencies, 0.95);
    let p99 = percentile(&samples.latencies, 0.99);
    let (before, after) = cpu;
    let busy: Vec<f64> = after
        .nodes
        .iter()
        .zip(&before.nodes)
        .map(|(after, before)| (after - before) / seconds)
        .collect();
    // Past the knee the calls scheduled in the window are answered after
    // it, their CPU spent past it: no CPU per commit then. Its sign is a
    // backlog that grows: more than 1% of the window's calls answered after
    // it, and the last quarter's median latency at least twice the
    // first's. A stall at the window's end makes calls late without
    // moving that median; calls that waited on their session's previous
    // one are no sign alone either, as one long batch holds them too.
    let late = samples.answered_after as f64 / samples.latencies.len().max(1) as f64;
    let median = |latencies: &mut Vec<Duration>| {
        latencies.sort_unstable();
        percentile(latencies, 0.5)
    };
    let growing = median(&mut samples.last_quarter) >= median(&mut samples.first_quarter) * 2;
    let past_knee = late > 0.01 && growing;
    let per_commit: Vec<f64> = busy
        .iter()
        .map(|busy| {
            if commits > 0.0 && !past_knee {
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
    let lag = if samples.lags.is_empty() {
        String::new()
    } else {
        let lag99 = percentile(&samples.lags, 0.99);
        format!(
            "; send lag p50 {:.3} ms, p99 {:.3} ms{}",
            ms(percentile(&samples.lags, 0.50)),
            ms(lag99),
            if lag99 > LAG { " INVALID" } else { "" }
        )
    };
    let failure = match &samples.first_failure {
        Some(failure) => format!(" (first: {failure})"),
        None => String::new(),
    };
    let behind = if samples.behind > 0 {
        format!(
            "; {} calls waited on their session's previous one",
            samples.behind
        )
    } else {
        String::new()
    };
    let behind = if past_knee {
        format!(
            "{behind}; past the knee: {:.0}% of its calls answered after the window",
            late * 100.0
        )
    } else {
        behind
    };
    let exhausted = if samples.exhausted > 0 {
        format!(
            "; {} sessions ran out of calls UNDERCOUNTED",
            samples.exhausted
        )
    } else {
        String::new()
    };
    // Each stage's counts over the window, every node's together.
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
        (count > 0).then(|| total(&after).saturating_sub(total(&before)) as f64 / count as f64)
    };
    let stalls = over(stage("late"), STALL);
    let long_batches = over(stage("batch"), STALL);
    let longest_batch = stage_percentiles(stage("batch")).map_or(0, |(_, _, max)| max);
    // p50/p99/max and the mean, in µs (in units for counts).
    let stages: Vec<String> = deltas
        .iter()
        .filter_map(|(name, delta)| {
            let (p50, p99, max) = stage_percentiles(delta)?;
            let mean = mean(name, delta)?;
            let count: u64 = delta.iter().sum();
            Some(format!("{name} {p50}/{p99}/{max} mean {mean:.0} ({count})"))
        })
        .collect();
    println!(
        "{name}: {commits:.0}/s, p50 {:.2} ms, p99 {:.2} ms, {} failed{failure}; nodes busy {:?} cores (executors most/mean {executors:?}; runtime/writer/net/fjall {others:?}), {:?} µs CPU per commit; driver {driver:.2} cores; outside the run {outside:.2} cores, IO stalled {io:.1}%{lag}{behind}{exhausted}",
        ms(p50),
        ms(p99),
        samples.failed,
        busy.iter()
            .map(|busy| (busy * 100.0).round() / 100.0)
            .collect::<Vec<_>>(),
        per_commit.iter().map(|cpu| cpu.round()).collect::<Vec<_>>(),
    );
    if !stages.is_empty() {
        println!("  stages p50/p99/max, mean µs: {}", stages.join(", "));
        println!(
            "  stalls: {stalls} runtime wakes and {long_batches} batches of {:.0} ms or more; the longest batch {:.0} ms; p95 {:.2} ms",
            STALL as f64 / 1000.0,
            longest_batch as f64 / 1000.0,
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
        stalls,
        long_batches,
        longest_batch,
    }
}

/// Sessions spread over `agents`, each starting at its agent's leader,
/// with `calls` signed calls each.
fn plans(
    agents: &[Signed],
    leaders: &HashMap<AgentId, usize>,
    sessions: u64,
    calls: usize,
    first: u64,
) -> Vec<Plan> {
    let spread = spread();
    let jobs = agents
        .iter()
        .flat_map(|signed| {
            (0..sessions).map(move |session| {
                let leader = leaders[&signed.agent];
                // Spread, each session goes to one of the space's three
                // nodes in turn, which checks its calls' signatures and
                // forwards them to the leader, as clients spread over the
                // replicas would.
                let node = if spread {
                    (leader + session as usize) % 3
                } else {
                    leader
                };
                (*signed, first + session, calls, node)
            })
        })
        .collect();
    sign_plans(jobs)
}

/// Whether sessions are spread over the three nodes (`SPREAD=1`), rather
/// than sent to their agent's leader.
fn spread() -> bool {
    std::env::var("SPREAD").is_ok_and(|value| value == "1")
}

/// One timed run of `plans`, reported as `name`, once the nodes are
/// quiet after the last.
fn run(name: &str, space: &Space, plans: Vec<Plan>, pace: Pace) -> Measured {
    run_for(name, space, plans, pace, MEASURE)
}

/// One run timed over `measure`.
fn run_for(name: &str, space: &Space, plans: Vec<Plan>, pace: Pace, measure: Duration) -> Measured {
    quiet(space);
    let (mut samples, cpu) = drive(space, plans, pace, measure);
    report(name, &mut samples, cpu, measure)
}

/// Wait until the nodes use under a third of a core together, for at most
/// 20 s: the last run's backlog spent.
fn quiet(space: &Space) {
    let until = Instant::now() + Duration::from_secs(20);
    while Instant::now() < until {
        let before: f64 = space.cpu().iter().sum();
        std::thread::sleep(Duration::from_millis(300));
        let after: f64 = space.cpu().iter().sum();
        if (after - before) / 0.3 < 0.33 {
            return;
        }
    }
    println!("the nodes did not go quiet within 20 s");
}

/// Signed calls for each session of a closed-loop run: enough for a
/// session's share of the most the nodes could take, within a bound on
/// them all, so memory stays bounded.
fn closed_calls(sessions: u64) -> usize {
    (400_000 / sessions as usize).min(4_000) + 64
}

/// Calls per session a run needs at `rate` per session, with room.
fn calls_for(per_session: f64) -> usize {
    calls_over(per_session, MEASURE)
}

/// Calls per session a run of `measure` needs at `per_session`, with room.
fn calls_over(per_session: f64, measure: Duration) -> usize {
    ((per_session * (WARM + measure).as_secs_f64()) * 1.2) as usize + 16
}

fn main() {
    if std::env::args().any(|arg| arg == "--list") {
        return;
    }
    let rows = rows();
    let cpus = cpus();
    let pinned = pinning();
    if pinned {
        // The driver, and the threads it signs on, on its own cores.
        let _ = Command::new("taskset")
            .args(["-p", "-c", &cpus[3], &std::process::id().to_string()])
            .stdout(Stdio::null())
            .status();
        println!(
            "pinned: nodes on {:?}, the driver on {}",
            &cpus[..3],
            cpus[3]
        );
    } else {
        println!("taskset is missing: the nodes and the driver share every core");
    }
    let counter = vos_pvm_compiler::link_elf_spi(
        &std::fs::read(guest(
            "test-actors/target/riscv64em-vos/release/counter.elf",
        ))
        .unwrap(),
    )
    .unwrap();
    let space = Space::start(pinned, &cpus);
    let mut session = 0u64;
    let mut next = |count: u64| {
        let first = session;
        session += count;
        first
    };

    let one = signed(&space, space.counter_agent(&counter));
    let leaders: HashMap<AgentId, usize> = [(one.agent, space.leader(one.agent))].into();
    if rows.iter().any(|row| row == "agent") {
        println!(
            "agent {} leads on node {}",
            one.agent.0,
            leaders[&one.agent] + 1
        );
        let mut most = 0.0f64;
        for sessions in [1u64, 4, 16, 64, 256] {
            let plans = plans(
                &[one],
                &leaders,
                sessions,
                closed_calls(sessions),
                next(sessions),
            );
            let Measured { commits, .. } = run(
                &format!("agent, {sessions} sessions closed"),
                &space,
                plans,
                Pace::Closed,
            );
            most = most.max(commits);
        }
        // Open loop near the most: what the agent takes without its
        // sessions all waiting on one batch.
        for rate in [15_000.0, 18_000.0, 21_000.0] {
            let sessions = 256u64;
            let interval = Duration::from_secs_f64(sessions as f64 / rate);
            let plans = plans(
                &[one],
                &leaders,
                sessions,
                calls_for(rate / sessions as f64),
                next(sessions),
            );
            run(
                &format!("agent, open at {rate:.0}/s (256 sessions)"),
                &space,
                plans,
                Pace::Open(interval),
            );
        }
        let half = (most / 2.0).max(10_000.0);
        let sessions = 256u64;
        let interval = Duration::from_secs_f64(sessions as f64 / half);
        let plans = plans(
            &[one],
            &leaders,
            sessions,
            calls_for(half / sessions as f64),
            next(sessions),
        );
        run(
            &format!("agent, open at {half:.0}/s (256 sessions)"),
            &space,
            plans,
            Pace::Open(interval),
        );
    }

    if rows.iter().any(|row| row == "quiet") {
        let plans = plans(&[one], &leaders, 1, closed_calls(1), next(1));
        run(
            "quiet node, one call at a time",
            &space,
            plans,
            Pace::Closed,
        );
    }

    let wanted = |name: &str| rows.iter().any(|row| row == name);
    if wanted("query") || wanted("linearizable") {
        let leader = leaders[&one.agent];
        let follower = (leader + 1) % 3;
        if wanted("query") {
            query(&space, &one, follower, Consistency::Applied { at: 0 });
        }
        if wanted("linearizable") {
            query(&space, &one, follower, Consistency::Linearizable);
        }
    }

    // `failover` and `soak` take the 64 agents, with or without their
    // rows.
    let many = if wanted("agents") || wanted("failover") || wanted("soak") {
        let agents: Vec<Signed> = (0..64)
            .map(|_| signed(&space, space.counter_agent(&counter)))
            .collect();
        let leaders: HashMap<AgentId, usize> = agents
            .iter()
            .map(|signed| (signed.agent, space.leader(signed.agent)))
            .collect();
        let mut led = [0usize; 3];
        for leader in leaders.values() {
            led[*leader] += 1;
        }
        println!(
            "64 agents, leaders per node {led:?}: 16 sessions each, as many connections to each"
        );
        if wanted("agents") {
            for sessions in [4u64, 16] {
                let plans = plans(
                    &agents,
                    &leaders,
                    sessions,
                    closed_calls(64 * sessions),
                    next(64 * sessions),
                );
                run(
                    &format!("64 agents × {sessions} sessions closed"),
                    &space,
                    plans,
                    Pace::Closed,
                );
            }
            let open = |rate: f64, next: &mut dyn FnMut(u64) -> u64| {
                let sessions = 16u64;
                let all = 64.0 * sessions as f64;
                let interval = Duration::from_secs_f64(all / rate);
                let plans = plans(
                    &agents,
                    &leaders,
                    sessions,
                    calls_for(rate / all),
                    next(64 * sessions),
                );
                run(
                    &format!("64 agents, open at {rate:.0}/s"),
                    &space,
                    plans,
                    Pace::Open(interval),
                )
            };
            // Upward, so no run meets the backlog of one past the knee: the
            // knee lies between the last rate that held and the first that
            // did not.
            let mut held = None;
            let mut missed = None;
            for rate in [
                5_000.0, 10_000.0, 15_000.0, 20_000.0, 25_000.0, 30_000.0, 35_000.0,
            ] {
                let Measured { p99, .. } = open(rate, &mut next);
                if p99 > KNEE_P99 {
                    missed = Some(rate);
                    break;
                }
                held = Some(rate);
            }
            match (held, missed) {
                (Some(held), Some(missed)) => {
                    println!(
                        "64 agents: the knee, p99 ≤ 20 ms, between {held:.0}/s and {missed:.0}/s offered"
                    )
                }
                (Some(held), None) => println!("64 agents: p99 ≤ 20 ms up to {held:.0}/s offered"),
                (None, _) => println!("64 agents: p99 above 20 ms from 5k/s offered"),
            }
            // The budget's own rate, last: past the knee, it leaves a backlog.
            open(40_000.0, &mut next);
        }
        agents
    } else {
        Vec::new()
    };

    if wanted("failover") {
        let agents: Vec<AgentId> = many.iter().map(|signed| signed.agent).collect();
        failover(&space, &agents);
    }
    if wanted("soak") {
        soak(&space, &many, &mut next);
    }

    // Every increment answered as run is in its agent's counter, once.
    let mut agents = vec![one];
    agents.extend(many);
    counters_hold(&space, &agents);

    if wanted("idle") || wanted("failover-idle") {
        let idle = idle(&space);
        if wanted("failover-idle") {
            failover(&space, &idle);
        }
    }
}

/// Each agent's counter, read at its leader, equals the increments it
/// answered as run.
fn counters_hold(space: &Space, agents: &[Signed]) {
    let ran = space.ran.lock().unwrap().clone();
    let key = SigningKey::from_bytes(&[11; 32]);
    let public = key.verifying_key().to_bytes();
    for signed in agents {
        let Some(expected) = ran.get(&signed.agent).copied() else {
            continue;
        };
        let not_after = vos_node::wall_clock() + 60_000;
        let consistency = Consistency::Linearizable;
        let message = query_message(
            &signed.identity,
            &public,
            not_after,
            consistency,
            COUNTER,
            signed.value,
            &[],
        );
        let body = QueryCall {
            key: public,
            not_after,
            consistency,
            instance: COUNTER,
            method: signed.value,
            arguments: Vec::new(),
            signature: key.sign(&message).to_bytes(),
        }
        .encode();
        let leader = &space.processes[space.leader(signed.agent)];
        let path = format!("/agents/{}/queries", signed.agent.0);
        let answer =
            vos_node::client::post_within(&leader.target, &path, &body, Duration::from_secs(5));
        let value = match answer {
            Ok(Answer::Ran {
                outcome: Outcome::Done(bytes),
                ..
            }) => u64::decode(&bytes).unwrap().0,
            other => panic!("agent {}'s counter: {other:?}", signed.agent.0),
        };
        assert_eq!(
            value, expected,
            "agent {}'s counter against the increments it answered",
            signed.agent.0
        );
    }
    println!("every agent's counter holds every increment it answered, once");
}

/// The counter's value read on `follower` at `consistency`, open loop,
/// client to answer.
fn query(space: &Space, signed: &Signed, follower: usize, consistency: Consistency) {
    let key = SigningKey::from_bytes(&[9; 32]);
    let public = key.verifying_key().to_bytes();
    let not_after = vos_node::wall_clock() + 240_000;
    let read = match consistency {
        Consistency::Linearizable => "linearizable",
        Consistency::Applied { .. } => "applied",
    };
    let message = query_message(
        &signed.identity,
        &public,
        not_after,
        consistency,
        COUNTER,
        signed.value,
        &[],
    );
    let body = QueryCall {
        key: public,
        not_after,
        consistency,
        instance: COUNTER,
        method: signed.value,
        arguments: Vec::new(),
        signature: key.sign(&message).to_bytes(),
    }
    .encode();
    // At two rates: what one more query costs the follower, beside what
    // it costs at a rate, its fixed costs included.
    let busy: Vec<f64> = [2_000.0, 6_000.0]
        .into_iter()
        .map(|rate: f64| {
            let sessions = 16usize;
            let per = calls_for(rate / sessions as f64);
            let plans: Vec<Plan> = (0..sessions)
                .map(|_| Plan {
                    counts: None,
                    node: follower,
                    path: format!("/agents/{}/queries", signed.agent.0),
                    bodies: Bodies::Ready(vec![body.clone(); per].into_iter()),
                })
                .collect();
            let interval = Duration::from_secs_f64(sessions as f64 / rate);
            let outcome = run(
                &format!(
                    "query ({read}) on follower node {}, open at {rate:.0}/s",
                    follower + 1
                ),
                space,
                plans,
                Pace::Open(interval),
            );
            outcome.busy[follower]
        })
        .collect();
    println!(
        "query ({read}): the follower's marginal CPU, {:.0} µs per query",
        (busy[1] - busy[0]) / 4_000.0 * 1e6
    );
}

/// 1,000 agents more on every node, left alone: each process's CPU,
/// threads and memory.
fn idle(space: &Space) -> Vec<AgentId> {
    let started = Instant::now();
    let created = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..125 {
                    let answer = space.operate(
                        |operator| {
                            operator
                                .create_agent(vec![1, 2, 3])
                                .unwrap_or(Answer::Unavailable)
                        },
                        |answer| matches!(answer, Answer::Created(_)),
                    );
                    if let Answer::Created(agent) = answer {
                        created.lock().unwrap().push(agent);
                    }
                }
            });
        }
    });
    println!(
        "1,000 idle agents created in {:.1} s",
        started.elapsed().as_secs_f64()
    );
    std::thread::sleep(IDLE_SETTLE);
    let before = space.cpu();
    std::thread::sleep(IDLE_MEASURE);
    let after = space.cpu();
    for (at, process) in space.processes.iter().enumerate() {
        let (threads, rss) = process.threads_and_rss();
        println!(
            "idle node {}: {:.1}% of one core, {threads} threads, {rss} MiB resident",
            process.number,
            (after[at] - before[at]) / IDLE_MEASURE.as_secs_f64() * 100.0
        );
    }
    created.into_inner().unwrap()
}

/// The node leading the most of `agents` killed: the time until every one
/// has a leader again, and until every node left names that leader's
/// placement in its directory; then its restart: the time until it
/// listens, and its CPU while its groups catch up.
fn failover(space: &Space, agents: &[AgentId]) {
    let mut led = [0usize; 3];
    for agent in agents {
        led[space.leader(*agent)] += 1;
    }
    let victim = (0..3).max_by_key(|at| led[*at]).unwrap();
    println!(
        "failover: node {} leading {} of {} agents is killed",
        victim + 1,
        led[victim],
        agents.len()
    );
    let started = Instant::now();
    space.processes[victim].kill();
    let left: Vec<&Process> = space
        .processes
        .iter()
        .enumerate()
        .filter(|(at, _)| *at != victim)
        .map(|(_, process)| process)
        .collect();
    let status = |process: &Process, agent: AgentId| match process.operator().status(agent) {
        Ok(Answer::Status(status)) => Some(status),
        _ => None,
    };
    // The term each agent's new leader leads at.
    let mut terms = Vec::with_capacity(agents.len());
    for agent in agents {
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            let term = left
                .iter()
                .find_map(|process| status(process, *agent).filter(|status| status.leads))
                .map(|status| status.term);
            if let Some(term) = term {
                terms.push(term);
                break;
            }
            assert!(Instant::now() < until, "agent {} has no leader", agent.0);
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    println!(
        "failover: every agent has a leader again {:.2} s after the kill",
        started.elapsed().as_secs_f64()
    );
    // Each node left names a placement at least as new as its leader's.
    for (agent, term) in agents.iter().zip(&terms) {
        let until = Instant::now() + Duration::from_secs(60);
        while !left.iter().all(|process| {
            status(process, *agent).is_some_and(|status| status.placement_term >= *term)
        }) {
            assert!(
                Instant::now() < until,
                "agent {}'s new placement did not reach every node",
                agent.0
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    println!(
        "failover: every node left names the new leaders' placements {:.2} s after the kill",
        started.elapsed().as_secs_f64()
    );
    // Each time above is when a sweep of the statuses saw its event: one
    // sweep's own time is their resolution.
    let swept = Instant::now();
    for agent in agents {
        for process in &left {
            status(process, *agent);
        }
    }
    println!(
        "failover: one sweep of every agent's status on the nodes left takes {:.2} s",
        swept.elapsed().as_secs_f64()
    );
    let opened = space.processes[victim].restart();
    let before = space.processes[victim].cpu();
    std::thread::sleep(IDLE_MEASURE);
    let busy = (space.processes[victim].cpu() - before) / IDLE_MEASURE.as_secs_f64();
    println!(
        "failover: node {} listens {:.2} s after its restart, then {:.0}% of one core over {} s",
        victim + 1,
        opened.as_secs_f64(),
        busy * 100.0,
        IDLE_MEASURE.as_secs()
    );
}

/// The 64-agent load open at `SOAK_RATE` (6k/s by default) for
/// `SOAK_SECONDS` (1,800), one load throughout, in windows of 50 s; the
/// windows within `SOAK_WARMUP` (150 s) of its start are reported, not
/// compared. Each session moves to a new one every 1,000 calls.
///
/// After the warm-up, its steady state over the clean windows (outside
/// the run under [`CLEAN_OUTSIDE`] cores, IO stalled under [`CLEAN_IO`]%):
/// the stalls and longest batch, p95, p99 and CPU per commit, to compare
/// runs by. And the history a run leaves must not cost more: the median
/// of the first three clean windows and of the last three must agree for
/// - CPU per commit, and p50 and p95, within 10%;
/// - the stalls, within 10% and one more;
/// - the longest batch, within one bucket (a quarter).
///
/// The p99 is reported for each window and judged by the budgets, stalls
/// and all, not here.
fn soak(space: &Space, agents: &[Signed], next: &mut dyn FnMut(u64) -> u64) {
    let rate: f64 = std::env::var("SOAK_RATE")
        .ok()
        .and_then(|rate| rate.parse().ok())
        .unwrap_or(6_000.0);
    let seconds: u64 = std::env::var("SOAK_SECONDS")
        .ok()
        .and_then(|seconds| seconds.parse().ok())
        .unwrap_or(1_800);
    // Its first windows come before the store's steady state (nothing
    // flushed yet): reported, not compared.
    let warmup: u64 = std::env::var("SOAK_WARMUP")
        .ok()
        .and_then(|seconds| seconds.parse().ok())
        .unwrap_or(150);
    let window = Duration::from_secs(50);
    let windows = (seconds / window.as_secs()).max(1);
    let warm = warmup.div_ceil(window.as_secs()) as usize;
    let leaders: HashMap<AgentId, usize> = agents
        .iter()
        .map(|signed| (signed.agent, space.leader(signed.agent)))
        .collect();
    let sessions = 4u64;
    let all = agents.len() as f64 * sessions as f64;
    let interval = Duration::from_secs_f64(all / rate);
    // One load throughout, each call signed as its session goes: the
    // nodes never rest between windows. Each plan moves to a new session
    // every `SESSION_CALLS`, so new sessions keep arriving, as clients'
    // do. (They expire after an hour, past a default soak.)
    const SESSION_CALLS: u64 = 1_000;
    let calls = calls_over(rate / all, window * windows as u32);
    let plans_count = agents.len() as u64 * sessions;
    let first = next(plans_count * (calls as u64).div_ceil(SESSION_CALLS));
    let plans: Vec<Plan> = agents
        .iter()
        .enumerate()
        .flat_map(|(at, signed)| {
            let node = leaders[&signed.agent];
            (0..sessions).map(move |session| {
                let number = first + at as u64 * sessions + session;
                signing_plan(signed, (number, plans_count, SESSION_CALLS), calls, node)
            })
        })
        .collect();
    quiet(space);
    let huge_before = transparent_huge_pages();
    let measured: Vec<Measured> =
        drive_windows(space, plans, Pace::Open(interval), window, windows as usize)
            .into_iter()
            .enumerate()
            .map(|(at, (mut samples, cpu))| {
                report(
                    &format!("soak window {} of {windows}, open at {rate:.0}/s", at + 1),
                    &mut samples,
                    cpu,
                    window,
                )
            })
            .collect();
    // Memory under load: each node's, and what transparent huge pages cost
    // the machine meanwhile (khugepaged's CPU is not the nodes').
    let memory: Vec<String> = space
        .processes
        .iter()
        .map(|process| {
            let (_, rss) = process.threads_and_rss();
            format!(
                "node {} {rss} MiB ({} MiB in huge pages)",
                process.number,
                process.huge_pages()
            )
        })
        .collect();
    let huge: Vec<String> = transparent_huge_pages()
        .into_iter()
        .zip(huge_before)
        .filter(|((_, after), (_, before))| after != before)
        .map(|((name, after), (_, before))| format!("{name} +{}", after - before))
        .collect();
    println!(
        "soak memory: {}; huge pages over the run: {}",
        memory.join(", "),
        if huge.is_empty() {
            "none".to_string()
        } else {
            huge.join(", ")
        }
    );
    let clean: Vec<&Measured> = measured
        .iter()
        .skip(warm)
        .filter(|outcome| outcome.outside < CLEAN_OUTSIDE && outcome.io < CLEAN_IO)
        .collect();
    println!(
        "soak: {} of the {} windows after {warm} of warm-up clean (outside the run under {CLEAN_OUTSIDE} cores, IO stalled under {CLEAN_IO}%)",
        clean.len(),
        windows.saturating_sub(warm as u64)
    );
    if clean.is_empty() {
        return;
    }
    let median = |outcomes: &[&Measured], of: &dyn Fn(&Measured) -> f64| {
        let mut values: Vec<f64> = outcomes.iter().map(|outcome| of(outcome)).collect();
        values.sort_by(f64::total_cmp);
        values[values.len() / 2]
    };
    // The steady state, to compare runs by.
    let mean = |of: &dyn Fn(&Measured) -> f64| {
        clean.iter().map(|outcome| of(outcome)).sum::<f64>() / clean.len() as f64
    };
    println!(
        "soak steady: {:.1} runtime stalls and {:.1} batches of {:.0} ms or more a window, the longest batch {:.0} ms; median p95 {:.2} ms, p99 {:.2} ms; CPU per commit {:.0} µs",
        mean(&|outcome| outcome.stalls as f64),
        mean(&|outcome| outcome.long_batches as f64),
        STALL as f64 / 1000.0,
        clean
            .iter()
            .map(|outcome| outcome.longest_batch)
            .max()
            .unwrap_or(0) as f64
            / 1000.0,
        median(&clean, &|outcome| ms(outcome.p95)),
        median(&clean, &|outcome| ms(outcome.p99)),
        median(&clean, &|outcome| {
            outcome.busy.iter().sum::<f64>() / outcome.commits * 1e6
        }),
    );
    if clean.len() < 6 {
        println!("soak: too few clean windows to judge a trend");
        return;
    }
    let (early, late) = (&clean[..3], &clean[clean.len() - 3..]);
    let mut grew = Vec::new();
    let mut judge =
        |name: &str, unit: &str, of: &dyn Fn(&Measured) -> f64, allowed: f64, slack: f64| {
            let (before, after) = (median(early, of), median(late, of));
            println!("soak: {name} {before:.2}{unit} then {after:.2}{unit}");
            if after > before * allowed + slack {
                grew.push(name.to_string());
            }
        };
    judge(
        "CPU per commit",
        " µs",
        &|outcome| outcome.busy.iter().sum::<f64>() / outcome.commits * 1e6,
        1.10,
        0.0,
    );
    judge("p50", " ms", &|outcome| ms(outcome.p50), 1.10, 0.0);
    judge("p95", " ms", &|outcome| ms(outcome.p95), 1.10, 0.0);
    judge(
        "runtime stalls",
        "",
        &|outcome| outcome.stalls as f64,
        1.10,
        1.0,
    );
    judge(
        "batches over the stall",
        "",
        &|outcome| outcome.long_batches as f64,
        1.10,
        1.0,
    );
    judge(
        "the longest batch",
        " ms",
        &|outcome| outcome.longest_batch as f64 / 1000.0,
        1.25,
        0.0,
    );
    if grew.is_empty() {
        println!("soak: holds");
    } else {
        println!("soak: GROWS: {}", grew.join(", "));
    }
}
