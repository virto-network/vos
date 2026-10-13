//! Node processes for the process tests: each a `vos node run` with its
//! own data directory, ports, log and faults file, joined through a relay
//! the test controls, served in the clear or over TLS.

#![allow(dead_code)]

pub mod relay;

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use vos_checker::{Log, Methods, Nodes};
use vos_node::client::{Operator, Target};
use vos_node::tls::Trust;
use vos_wire::ids::{AgentId, InstanceId};
use vos_wire::ingress::{Answer, Install, ReplicaStatus};
use vos_wire::peer::NodeNumber;

use relay::Relay;

pub fn guest(path: &str) -> PathBuf {
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

pub fn agent_elf() -> PathBuf {
    guest("default/target/riscv64em-vos/release/vos-agent.elf")
}

/// The counter actor, linked.
pub fn counter_program() -> Vec<u8> {
    let counter = std::fs::read(guest(
        "test-actors/target/riscv64em-vos/release/counter.elf",
    ))
    .unwrap();
    vos_pvm_compiler::link_elf_spi(&counter).expect("links")
}

/// A running node, killed when dropped, however the test ends.
pub struct Running(Child);

impl Running {
    fn pid(&self) -> u32 {
        self.0.id()
    }

    /// How it exited, if it did before the harness killed it.
    fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.0.try_wait().ok().flatten()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start `vos node run` with `args` and `faults` as its faults file: the
/// node, once it printed its address and key, or `None` if it exited
/// first. Its stderr goes to `log`; its stdout is read to the end, so the
/// node never writes to a closed pipe.
pub fn run(args: &[&str], log: &Path, faults: Option<&Path>) -> Option<(Running, String)> {
    let errors = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_vos"));
    command
        .args(["node", "run"])
        .args(args)
        .arg("--agent")
        .arg(agent_elf())
        .stdout(Stdio::piped())
        .stderr(errors);
    if let Some(faults) = faults {
        command.env("VOS_FAULTS", faults);
    }
    let mut child = command.spawn().expect("vos runs");
    let stdout = child.stdout.take().unwrap();
    let running = Running(child);
    let (lines, read) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { return };
            let _ = lines.send(line);
        }
    });
    let deadline = Duration::from_secs(60);
    let Ok(listening) = read.recv_timeout(deadline) else {
        // Where a node that never says it listens is: each thread's name,
        // state and kernel wait, which /proc shows without tracing it.
        let threads = std::fs::read_dir(format!("/proc/{}/task", running.pid()))
            .map(|tasks| {
                tasks
                    .filter_map(Result::ok)
                    .map(|task| {
                        let read = |name: &str| {
                            std::fs::read_to_string(task.path().join(name))
                                .unwrap_or_default()
                                .trim()
                                .to_string()
                        };
                        let state = read("stat")
                            .rsplit_once(") ")
                            .map(|(_, rest)| rest.chars().next().unwrap_or('?'))
                            .unwrap_or('?');
                        format!("{} {state} {}", read("comm"), read("wchan"))
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        let _ = std::fs::write(log.with_extension("stuck"), threads);
        return None;
    };
    listening.strip_prefix("listening on ")?;
    let key = read
        .recv_timeout(deadline)
        .ok()?
        .strip_prefix("node ")?
        .to_string();
    Some((running, key))
}

/// A free local port, TCP or UDP, below the range the system gives out
/// for outgoing connections: a node restarted takes its ports again, and
/// a connection made meanwhile must not have taken one.
pub fn free_port(udp: bool) -> u16 {
    static STATE: AtomicU64 = AtomicU64::new(0);
    let lowest_ephemeral = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|range| range.split_whitespace().next()?.parse::<u16>().ok())
        .unwrap_or(32_768);
    // Never a privileged port.
    let (low, high) = ((lowest_ephemeral / 2).max(1024), lowest_ephemeral);
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |since| since.as_nanos() as u64)
        ^ u64::from(std::process::id()) << 32;
    for _ in 0..if high > low { 1000 } else { 0 } {
        // A xorshift step, shared by the tests of this process.
        let mut x = STATE.load(Ordering::Relaxed);
        if x == 0 {
            x = seed | 1;
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        STATE.store(x, Ordering::Relaxed);
        let port = low + (x % u64::from(high - low)) as u16;
        let free = if udp {
            UdpSocket::bind(("127.0.0.1", port)).is_ok()
        } else {
            TcpListener::bind(("127.0.0.1", port)).is_ok()
        };
        if free {
            return port;
        }
    }
    // No room below that range: any port the system gives.
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

pub fn read_log(log: &Path) -> String {
    std::fs::read_to_string(log).unwrap_or_default()
}

pub fn wait_until(what: &str, done: impl FnMut() -> bool) {
    vos_checker::wait_until(what, Duration::from_secs(60), done);
}

/// How the nodes run.
#[derive(Clone, Default)]
pub struct Options {
    /// TLS on the ingress, clients pinning the nodes' keys.
    pub tls: bool,
    /// Lines of each faults file a node reads once, at start: the groups'
    /// timing and compaction, QUIC's idle timeout.
    pub settings: String,
}

/// One node's process, and the faults the test gives it.
#[derive(Default)]
struct Slot {
    running: Mutex<Option<Running>>,
    /// How often it started.
    starts: AtomicU64,
    /// Paused (SIGSTOP): it takes no faults until it goes on.
    paused: AtomicBool,
    /// Its own faults, as lines of its faults file.
    faults: Mutex<String>,
    /// How far its clock runs ahead of every node's, or behind.
    jump: AtomicI64,
    /// The generation its faults file holds.
    written: AtomicU64,
}

/// Nodes 1..=count of one space, each its own process, their peers
/// joined through a relay.
pub struct Processes {
    pub dir: tempfile::TempDir,
    pub count: usize,
    keys: Vec<String>,
    ingress: Vec<u16>,
    bound: Vec<SocketAddr>,
    pub relay: Relay,
    slots: Vec<Slot>,
    targets: Vec<Target>,
    options: Options,
    /// The last generation of faults written, for a node to acknowledge.
    generation: AtomicU64,
    /// How far every node's clock runs ahead of the wall clock...
    clocks: AtomicI64,
    /// ... and the agents' time as clients take it: the same, but while
    /// the nodes' clocks move, when it moves last.
    offset: AtomicI64,
    /// Whether the nodes' clocks are moving, some there and some not.
    moving: AtomicBool,
    /// Clients pause at their next request while it is set.
    pub clients_paused: AtomicBool,
    log: Log,
    /// Nodes that exited before the harness killed them.
    exits: Mutex<Vec<String>>,
}

/// How long a status or an operator's command may take at one node.
const OPERATOR: Duration = Duration::from_secs(5);

impl Processes {
    pub fn data(&self, number: usize) -> PathBuf {
        self.dir.path().join(format!("node-{number}"))
    }

    pub fn log_path(&self, number: usize) -> PathBuf {
        self.dir.path().join(format!("node-{number}.log"))
    }

    /// Node `number`'s faults file, which it reads every 50 ms.
    pub fn faults_file(&self, number: usize) -> PathBuf {
        self.dir.path().join(format!("node-{number}.faults"))
    }

    pub fn url(&self, number: usize) -> String {
        let scheme = if self.options.tls { "https" } else { "http" };
        format!("{scheme}://127.0.0.1:{}", self.ingress[number - 1])
    }

    pub fn key(&self, number: usize) -> [u8; 32] {
        let mut key = [0; 32];
        hex::decode_to_slice(&self.keys[number - 1], &mut key).unwrap();
        key
    }

    /// Where node `number`'s ingress is reached.
    pub fn target(&self, number: usize) -> &Target {
        &self.targets[number - 1]
    }

    pub fn operator(&self, number: usize) -> Operator {
        let token = std::fs::read_to_string(self.data(number).join(vos_node::ADMIN_TOKEN)).unwrap();
        Operator::within(self.target(number), &token, OPERATOR)
    }

    pub fn is_running(&self, number: usize) -> bool {
        self.slot(number).running.lock().unwrap().is_some()
    }

    fn slot(&self, number: usize) -> &Slot {
        &self.slots[number - 1]
    }

    /// Start `count` nodes, choosing their ports again if one cannot take
    /// them.
    pub fn start(count: usize, options: Options) -> Self {
        let mut dir = tempfile::tempdir().unwrap();
        // `KEEP_NODES` keeps the nodes' data and logs, to look at after.
        if std::env::var_os("KEEP_NODES").is_some() {
            dir.disable_cleanup(true);
            eprintln!("the nodes' data and logs stay in {}", dir.path().display());
        }
        // A first run alone makes each node's key.
        let keys: Vec<String> = (1..=count)
            .map(|number| {
                let data = dir.path().join(format!("node-{number}"));
                let log = dir.path().join(format!("node-{number}.log"));
                let (_, key) = run(
                    &["--data", data.to_str().unwrap(), "--listen", "127.0.0.1:0"],
                    &log,
                    None,
                )
                .unwrap_or_else(|| panic!("a node alone starts: {}", read_log(&log)));
                key
            })
            .collect();
        for _attempt in 0..5 {
            let ingress: Vec<u16> = (0..count).map(|_| free_port(false)).collect();
            let bound: Vec<SocketAddr> = (0..count)
                .map(|_| format!("127.0.0.1:{}", free_port(true)).parse().unwrap())
                .collect();
            let relay = Relay::start(&bound).expect("the relay starts");
            let scheme = if options.tls { "https" } else { "http" };
            let text: String = (0..count)
                .map(|at| {
                    format!(
                        "{} {} {} {scheme}://127.0.0.1:{}\n",
                        at + 1,
                        keys[at],
                        relay.listed(at + 1),
                        ingress[at]
                    )
                })
                .collect();
            std::fs::write(dir.path().join("space"), text).unwrap();
            let targets = (0..count)
                .map(|at| {
                    let url = format!("{scheme}://127.0.0.1:{}", ingress[at]);
                    let trust = if options.tls {
                        let mut key = [0; 32];
                        hex::decode_to_slice(&keys[at], &mut key).unwrap();
                        Trust::NodeKey(key)
                    } else {
                        Trust::Loopback
                    };
                    Target::new(&url, trust).unwrap()
                })
                .collect();
            let processes = Processes {
                dir,
                count,
                keys: keys.clone(),
                ingress,
                bound,
                relay,
                slots: (0..count).map(|_| Slot::default()).collect(),
                targets,
                options: options.clone(),
                generation: AtomicU64::new(0),
                clocks: AtomicI64::new(0),
                offset: AtomicI64::new(0),
                moving: AtomicBool::new(false),
                clients_paused: AtomicBool::new(false),
                log: Log::default(),
                exits: Mutex::new(Vec::new()),
            };
            let started = (1..=count).all(|number| match processes.launch(number) {
                Some(running) => {
                    *processes.slot(number).running.lock().unwrap() = Some(running);
                    processes.slot(number).starts.fetch_add(1, Ordering::SeqCst);
                    true
                }
                None => false,
            });
            if started {
                return processes;
            }
            for number in 1..=count {
                processes.slot(number).running.lock().unwrap().take();
            }
            dir = processes.dir;
        }
        panic!("the nodes could not take their ports");
    }

    fn launch(&self, number: usize) -> Option<Running> {
        let data = self.data(number);
        let listen = format!("127.0.0.1:{}", self.ingress[number - 1]);
        let space = self.dir.path().join("space");
        let bind = self.bound[number - 1].to_string();
        let faults = self.faults_file(number);
        if !faults.exists() {
            self.write_faults(number);
        }
        let mut args = vec![
            "--data",
            data.to_str().unwrap(),
            "--listen",
            &listen,
            "--space",
            space.to_str().unwrap(),
            "--peer-bind",
            &bind,
        ];
        if self.options.tls {
            args.extend(["--tls", "--tls-name", "127.0.0.1"]);
        }
        let (running, key) = run(&args, &self.log_path(number), Some(&faults))?;
        assert_eq!(key, self.keys[number - 1]);
        Some(running)
    }

    /// Kill node `number` with SIGKILL, clearing its own faults: a fault
    /// left in place would meet its restart. Every node's clock offset
    /// stays.
    pub fn kill(&self, number: usize) {
        self.end(number);
        let slot = self.slot(number);
        slot.paused.store(false, Ordering::SeqCst);
        slot.faults.lock().unwrap().clear();
        slot.jump.store(0, Ordering::SeqCst);
        self.write_faults(number);
    }

    /// End node `number`'s process, noting whether it had exited by
    /// itself.
    fn end(&self, number: usize) {
        let mut running = self.slot(number).running.lock().unwrap();
        if let Some(status) = running.as_mut().and_then(Running::exited) {
            self.exits
                .lock()
                .unwrap()
                .push(format!("node {number} exited by itself: {status}"));
        }
        drop(running.take());
    }

    /// Pause node `number` (SIGSTOP), or let it go on (SIGCONT), once it
    /// takes the faults written while it was paused.
    pub fn pause(&self, number: usize, paused: bool) {
        let running = self.slot(number).running.lock().unwrap();
        let Some(pid) = running.as_ref().map(Running::pid) else {
            return;
        };
        drop(running);
        let signal = if paused { "-STOP" } else { "-CONT" };
        let _ = Command::new("kill")
            .args([signal, &pid.to_string()])
            .status();
        self.slot(number).paused.store(paused, Ordering::SeqCst);
        if !paused {
            self.taken(number, self.slot(number).written.load(Ordering::SeqCst));
        }
    }

    /// Start node `number` again, once its faults are in force.
    pub fn restart(&self, number: usize) {
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            let started = Instant::now();
            if let Some(running) = self.launch(number) {
                *self.slot(number).running.lock().unwrap() = Some(running);
                self.slot(number).starts.fetch_add(1, Ordering::SeqCst);
                self.log.event(format!(
                    "node {number} restarted in {:?}",
                    started.elapsed()
                ));
                return;
            }
            assert!(
                Instant::now() < until,
                "node {number} did not restart: {}\nits threads:\n{}\nthe last events:\n{}",
                read_log(&self.log_path(number)),
                read_log(&self.log_path(number).with_extension("stuck")),
                self.log.events(),
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Node `number`'s own faults, as lines of its faults file: in force
    /// once this returns, if the node runs and is not paused, as it says;
    /// else once it starts or goes on.
    pub fn set_faults(&self, number: usize, lines: &str) {
        *self.slot(number).faults.lock().unwrap() = lines.to_string();
        self.write_faults(number);
    }

    /// Run node `number`'s clock `jump` milliseconds ahead of every
    /// node's, or behind.
    pub fn jump_clock(&self, number: usize, jump: i64) {
        self.slot(number).jump.store(jump, Ordering::SeqCst);
        self.write_faults(number);
    }

    /// Move every node's clock on by `by` milliseconds, one node after
    /// another; then clients take the agents' time to have moved too.
    pub fn jump_every_clock(&self, by: i64) {
        self.moving.store(true, Ordering::SeqCst);
        self.clocks.fetch_add(by, Ordering::SeqCst);
        for number in 1..=self.count {
            self.write_faults(number);
        }
        self.offset.fetch_add(by, Ordering::SeqCst);
        self.moving.store(false, Ordering::SeqCst);
    }

    /// Write node `number`'s faults file whole, headed by a new
    /// generation, and wait for the node to take it if it runs and is not
    /// paused.
    fn write_faults(&self, number: usize) {
        let slot = self.slot(number);
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let clock = self.clocks.load(Ordering::SeqCst) + slot.jump.load(Ordering::SeqCst);
        let text = format!(
            "generation {generation}\n{}clock {clock}\n{}",
            self.options.settings,
            slot.faults.lock().unwrap()
        );
        let file = self.faults_file(number);
        let staged = file.with_extension("staged");
        std::fs::write(&staged, text).unwrap();
        std::fs::rename(&staged, &file).unwrap();
        slot.written.store(generation, Ordering::SeqCst);
        if self.is_running(number) && !slot.paused.load(Ordering::SeqCst) {
            self.taken(number, generation);
        }
    }

    /// Wait until node `number` says the faults of `generation`, or later
    /// ones, are in force.
    fn taken(&self, number: usize, generation: u64) {
        let taken = self.faults_file(number).with_extension("taken");
        wait_until("the node takes its faults", || {
            let mut running = self.slot(number).running.lock().unwrap();
            if let Some(status) = running.as_mut().and_then(Running::exited) {
                panic!(
                    "node {number} exited by itself: {status}\n{}",
                    read_log(&self.log_path(number))
                );
            }
            drop(running);
            std::fs::read_to_string(&taken)
                .ok()
                .and_then(|text| text.trim().parse::<u64>().ok())
                .is_some_and(|taken| taken >= generation)
        });
    }

    /// Node `number`'s replica of `agent`, if it runs, is not paused, and
    /// holds one.
    pub fn status(&self, number: usize, agent: AgentId) -> Option<ReplicaStatus> {
        if !self.is_running(number) || self.slot(number).paused.load(Ordering::SeqCst) {
            return None;
        }
        match self.operator(number).status(agent) {
            Ok(Answer::Status(status)) => Some(status),
            _ => None,
        }
    }

    /// The running node leading `agent` at the highest term, once one
    /// does: a deposed leader may not know yet.
    pub fn leader(&self, agent: AgentId) -> usize {
        let mut leader = None;
        wait_until("a leader is known", || {
            leader = self.leading(agent);
            leader.is_some()
        });
        leader.unwrap()
    }

    /// The running node leading `agent` at the highest term, if one does.
    pub fn leading(&self, agent: AgentId) -> Option<usize> {
        (1..=self.count)
            .filter_map(|number| {
                self.status(number, agent)
                    .filter(|status| status.leads)
                    .map(|status| (status.term, number))
            })
            .max()
            .map(|(_, number)| number)
    }

    /// Lines of the nodes' logs that tell of a panic or a halt, and the
    /// nodes that exited by themselves.
    pub fn troubles(&self) -> Vec<String> {
        let mut troubles: Vec<String> = (1..=self.count)
            .flat_map(|number| {
                self.trouble_lines(number)
                    .into_iter()
                    .map(move |(_, line)| format!("node {number}: {line}"))
            })
            .collect();
        troubles.extend(self.exits.lock().unwrap().iter().cloned());
        troubles
    }

    /// Lines of node `number`'s log that tell of a panic or a halt, each
    /// with where it starts in the log.
    pub fn trouble_lines(&self, number: usize) -> Vec<(u64, String)> {
        let log = std::fs::read(self.log_path(number)).unwrap_or_default();
        let mut at = 0u64;
        let mut lines = Vec::new();
        for line in log.split_inclusive(|byte| *byte == b'\n') {
            let text = String::from_utf8_lossy(line);
            if text.contains("panicked") || text.contains("needs a restart") {
                lines.push((at, text.trim_end().to_string()));
            }
            at += line.len() as u64;
        }
        lines
    }

    /// How long node `number`'s log is.
    pub fn log_len(&self, number: usize) -> u64 {
        std::fs::metadata(self.log_path(number)).map_or(0, |log| log.len())
    }

    /// The nodes that exited before the harness killed them.
    pub fn exits(&self) -> Vec<String> {
        self.exits.lock().unwrap().clone()
    }

    /// An operator's command, at whichever running node takes it: its
    /// answer, once one is `accepted`.
    pub fn operate(
        &self,
        command: impl Fn(&Operator) -> Answer,
        accepted: impl Fn(&Answer) -> bool,
    ) -> Answer {
        let mut answer = None;
        wait_until("an operator's command is taken", || {
            answer = (1..=self.count)
                .filter(|number| self.is_running(*number))
                .map(|number| command(&self.operator(number)))
                .find(&accepted);
            answer.is_some()
        });
        answer.unwrap()
    }

    /// An agent created on `replicas`, with `program` installed as each
    /// of `instances`, in order.
    pub fn agent_with(
        &self,
        replicas: Vec<NodeNumber>,
        program: &[u8],
        instances: &[InstanceId],
    ) -> AgentId {
        let Answer::Created(agent) = self.operate(
            |operator| {
                operator
                    .create_agent(replicas.clone())
                    .unwrap_or(Answer::Unavailable)
            },
            |answer| matches!(answer, Answer::Created(_)),
        ) else {
            unreachable!()
        };
        for instance in instances {
            let install = Install {
                instance: *instance,
                program: program.to_vec(),
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
        }
        agent
    }

    /// Agent `agent`'s identity, the hash of its creation record.
    pub fn identity(&self, agent: AgentId) -> [u8; 32] {
        let mut identity = None;
        wait_until("the agent's record is served", || {
            identity = (1..=self.count)
                .filter(|number| self.is_running(*number))
                .find_map(|number| {
                    vos_node::client::agent_info(self.target(number), agent)
                        .ok()
                        .flatten()
                })
                .map(|info| vos_node::identity(&info.record));
            identity.is_some()
        });
        identity.unwrap()
    }

    /// Stop every node at once (SIGSTOP), so none goes on while another
    /// is killed, then kill them (SIGKILL) and open each one's store.
    pub fn stop_all(&self) -> Vec<vos_node::store::Fjall> {
        for number in 1..=self.count {
            let running = self.slot(number).running.lock().unwrap();
            if let Some(pid) = running.as_ref().map(Running::pid) {
                let _ = Command::new("kill")
                    .args(["-STOP", &pid.to_string()])
                    .status();
            }
        }
        for number in 1..=self.count {
            self.end(number);
        }
        (1..=self.count)
            .map(|number| {
                vos_node::store::Fjall::open(self.data(number).join(vos_node::STORE))
                    .unwrap_or_else(|error| panic!("node {number}'s store: {error}"))
            })
            .collect()
    }
}

impl Nodes for Processes {
    fn count(&self) -> NodeNumber {
        self.count as NodeNumber
    }

    fn target(&self, number: NodeNumber) -> &Target {
        Processes::target(self, usize::from(number))
    }

    fn number_at(&self, address: &str) -> Option<NodeNumber> {
        (1..=self.count)
            .find(|number| self.url(*number) == address)
            .map(|number| number as NodeNumber)
    }

    fn offset(&self) -> i64 {
        self.offset.load(Ordering::SeqCst)
    }

    fn starts(&self, number: NodeNumber) -> u64 {
        self.slot(usize::from(number)).starts.load(Ordering::SeqCst)
    }

    /// Unknown cheaply: a status read per answer would cost as much as the
    /// call.
    fn leader(&self, _: AgentId) -> Option<NodeNumber> {
        None
    }

    fn paused(&self) -> bool {
        self.clients_paused.load(Ordering::SeqCst)
    }

    fn clocks_moving(&self) -> bool {
        self.moving.load(Ordering::SeqCst)
    }

    fn log(&self) -> &Log {
        &self.log
    }

    fn report(&self, agent: AgentId) -> String {
        let statuses: Vec<String> = (1..=self.count)
            .map(|number| match self.status(number, agent) {
                Some(status) => format!("node {number}: {status:?}"),
                None => format!("node {number}: no status"),
            })
            .collect();
        format!(
            "agent {}\n{}\n{}\n{}",
            agent.0,
            statuses.join("\n"),
            self.log.events(),
            self.troubles().join("\n")
        )
    }
}

/// The counter's methods, by its schema at `agent`'s `instance`.
pub fn methods(processes: &Processes, agent: AgentId, instance: InstanceId) -> Methods {
    let mut schema = None;
    wait_until("the schema is served", || {
        schema = (1..=processes.count)
            .filter(|number| processes.is_running(*number))
            .find_map(|number| {
                vos_node::client::schema(processes.target(number), agent, instance)
                    .ok()
                    .flatten()
            });
        schema.is_some()
    });
    let schema = schema.unwrap();
    let method = |name: &str| {
        schema
            .methods
            .iter()
            .find(|method| method.name == name.as_bytes())
            .unwrap_or_else(|| panic!("no method {name}"))
            .id
    };
    Methods {
        increment: method("increment"),
        value: method("value"),
        forward: method("forward"),
    }
}

/// An agent created on nodes 1 to 3, with the test counter installed as
/// `instance`, through whichever node takes the operator's commands.
pub fn counter_agent(processes: &Processes, instance: InstanceId) -> AgentId {
    processes.agent_with(vec![1, 2, 3], &counter_program(), &[instance])
}

/// The value a call answered with, if it ran to completion.
pub fn done(answer: &Answer) -> Option<u64> {
    match answer {
        Answer::Ran {
            outcome: vos_wire::result::Outcome::Done(bytes),
            ..
        } => Some(vos_wire::Decode::decode(bytes).unwrap().0),
        _ => None,
    }
}

/// The method `name` of `agent`'s `instance`, read once its schema is
/// served.
pub fn method(
    client: &mut vos_node::client::Client,
    agent: AgentId,
    instance: InstanceId,
    name: &str,
) -> vos_wire::ids::MethodId {
    let mut schema = None;
    wait_until("the schema is served", || {
        schema = client.schema(agent, instance).ok().flatten();
        schema.is_some()
    });
    schema
        .unwrap()
        .methods
        .iter()
        .find(|method| method.name == name.as_bytes())
        .unwrap_or_else(|| panic!("no method {name}"))
        .id
}

/// Call `method` of `agent`'s `instance` with `by` through `client`,
/// sending again with the same sequence until it is answered: the value
/// it answers with.
pub fn increment(
    client: &mut vos_node::client::Client,
    agent: AgentId,
    instance: InstanceId,
    method: vos_wire::ids::MethodId,
    by: u64,
) -> u64 {
    let arguments = vos_wire::Encode::encode(&by);
    let mut answered = None;
    wait_until("a call is answered", || {
        answered = client
            .call(agent, instance, method, &arguments)
            .ok()
            .as_ref()
            .and_then(done);
        answered.is_some()
    });
    answered.unwrap()
}

/// Wait until the three replicas of `agent` applied through the commit
/// of its leader at the highest term: their statuses, read at each node.
pub fn converged(processes: &Processes, agent: AgentId) {
    wait_until("every replica applies through the commit", || {
        let statuses: Vec<ReplicaStatus> = (1..=processes.count)
            .filter_map(|number| processes.status(number, agent))
            .collect();
        let Some(commit) = statuses
            .iter()
            .filter(|status| status.leads)
            .max_by_key(|status| status.term)
            .map(|status| status.commit)
        else {
            return false;
        };
        statuses.len() == 3 && statuses.iter().all(|status| status.applied >= commit)
    });
}
