//! Node processes for the process tests: each a `vos node run` with its
//! own data directory, ports, log and faults file, joined through a relay
//! the test controls, served in the clear or over TLS.

#![allow(dead_code)]

pub mod relay;

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use vos_node::client::{Operator, Target};
use vos_node::tls::Trust;
use vos_wire::ids::AgentId;
use vos_wire::ingress::{Answer, ReplicaStatus};

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

/// A running node, killed when dropped, however the test ends.
pub struct Running(Child);

impl Running {
    fn pid(&self) -> u32 {
        self.0.id()
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
    let deadline = Duration::from_secs(20);
    let listening = read.recv_timeout(deadline).ok()?;
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

pub fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(60);
    while !done() {
        assert!(Instant::now() < until, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// How the nodes run.
#[derive(Clone, Copy, Default)]
pub struct Options {
    /// TLS on the ingress, clients pinning the nodes' keys.
    pub tls: bool,
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
    running: Vec<Option<Running>>,
    /// Nodes paused (SIGSTOP), which take no faults until they go on.
    paused: Vec<AtomicBool>,
    /// The last generation of faults written, for a node to acknowledge.
    generation: AtomicU64,
    /// The generation each node's faults file holds.
    written: Vec<AtomicU64>,
    options: Options,
}

impl Processes {
    pub fn data(&self, number: usize) -> PathBuf {
        self.dir.path().join(format!("node-{number}"))
    }

    pub fn log(&self, number: usize) -> PathBuf {
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

    pub fn target(&self, number: usize) -> Target {
        let trust = if self.options.tls {
            Trust::NodeKey(self.key(number))
        } else {
            Trust::Loopback
        };
        Target::new(&self.url(number), trust).unwrap()
    }

    pub fn operator(&self, number: usize) -> Operator {
        let token = std::fs::read_to_string(self.data(number).join(vos_node::ADMIN_TOKEN)).unwrap();
        Operator::new(&self.target(number), &token)
    }

    pub fn is_running(&self, number: usize) -> bool {
        self.running[number - 1].is_some()
    }

    /// Start `count` nodes, choosing their ports again if one cannot take
    /// them.
    pub fn start(count: usize, options: Options) -> Self {
        let mut dir = tempfile::tempdir().unwrap();
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
            let mut processes = Processes {
                dir,
                count,
                keys: keys.clone(),
                ingress,
                bound,
                relay,
                running: Vec::new(),
                paused: (0..count).map(|_| AtomicBool::new(false)).collect(),
                generation: AtomicU64::new(0),
                written: (0..count).map(|_| AtomicU64::new(0)).collect(),
                options,
            };
            let started: Vec<Option<Running>> =
                (1..=count).map(|number| processes.launch(number)).collect();
            if started.iter().all(Option::is_some) {
                processes.running = started;
                return processes;
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
            std::fs::write(&faults, "").unwrap();
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
        let (running, key) = run(&args, &self.log(number), Some(&faults))?;
        assert_eq!(key, self.keys[number - 1]);
        Some(running)
    }

    /// Kill node `number` with SIGKILL, emptying its faults file: a
    /// fault left in place would meet its restart.
    pub fn kill(&mut self, number: usize) {
        drop(self.running[number - 1].take());
        self.paused[number - 1].store(false, Ordering::SeqCst);
        self.set_faults(number, "");
    }

    /// Pause node `number` (SIGSTOP), or let it go on (SIGCONT), once it
    /// takes the faults written while it was paused.
    pub fn pause(&self, number: usize, paused: bool) {
        if let Some(running) = &self.running[number - 1] {
            let signal = if paused { "-STOP" } else { "-CONT" };
            let _ = Command::new("kill")
                .args([signal, &running.pid().to_string()])
                .status();
            self.paused[number - 1].store(paused, Ordering::SeqCst);
            if !paused {
                self.taken(number, self.written[number - 1].load(Ordering::SeqCst));
            }
        }
    }

    /// Wait until node `number` says the faults of `generation` are in
    /// force.
    fn taken(&self, number: usize, generation: u64) {
        if generation == 0 {
            return;
        }
        let taken = self.faults_file(number).with_extension("taken");
        wait_until("the node takes its faults", || {
            std::fs::read_to_string(&taken)
                .ok()
                .and_then(|text| text.trim().parse::<u64>().ok())
                == Some(generation)
        });
    }

    pub fn restart(&mut self, number: usize) {
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(running) = self.launch(number) {
                self.running[number - 1] = Some(running);
                return;
            }
            assert!(
                Instant::now() < until,
                "node {number} did not restart: {}",
                read_log(&self.log(number))
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Node `number`'s faults, as lines of its faults file: in force once
    /// this returns, if the node runs and is not paused, as it says; else
    /// once it starts or goes on.
    pub fn set_faults(&self, number: usize, lines: &str) {
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let file = self.faults_file(number);
        let staged = file.with_extension("staged");
        std::fs::write(&staged, format!("generation {generation}\n{lines}")).unwrap();
        std::fs::rename(&staged, &file).unwrap();
        self.written[number - 1].store(generation, Ordering::SeqCst);
        if self.is_running(number) && !self.paused[number - 1].load(Ordering::SeqCst) {
            self.taken(number, generation);
        }
    }

    /// Node `number`'s replica of `agent`, if it runs and holds one.
    pub fn status(&self, number: usize, agent: AgentId) -> Option<ReplicaStatus> {
        if !self.is_running(number) {
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
            leader = (1..=self.count)
                .filter_map(|number| {
                    self.status(number, agent)
                        .filter(|status| status.leads)
                        .map(|status| (status.term, number))
                })
                .max()
                .map(|(_, number)| number);
            leader.is_some()
        });
        leader.unwrap()
    }

    /// Lines of the nodes' logs that tell of a panic or a halt.
    pub fn troubles(&self) -> Vec<String> {
        (1..=self.count)
            .flat_map(|number| {
                read_log(&self.log(number))
                    .lines()
                    .filter(|line| line.contains("panicked") || line.contains("needs a restart"))
                    .map(|line| format!("node {number}: {line}"))
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

/// An agent created on nodes 1 to 3, with the test counter installed as
/// `instance`, through whichever node takes the operator's commands.
pub fn counter_agent(processes: &Processes, instance: vos_wire::ids::InstanceId) -> AgentId {
    let counter = std::fs::read(guest(
        "test-actors/target/riscv64em-vos/release/counter.elf",
    ))
    .unwrap();
    let counter = vos_pvm_compiler::link_elf_spi(&counter).expect("links");
    let operate = |command: &dyn Fn(&Operator) -> Answer| -> Answer {
        let mut answer = None;
        wait_until("an operator's command is taken", || {
            answer = (1..=processes.count)
                .filter(|number| processes.is_running(*number))
                .map(|number| command(&processes.operator(number)))
                .find(|answer| matches!(answer, Answer::Ran { .. } | Answer::Created(_)));
            answer.is_some()
        });
        answer.unwrap()
    };
    let Answer::Created(agent) = operate(&|operator| operator.create_agent(vec![1, 2, 3]).unwrap())
    else {
        unreachable!()
    };
    let install = vos_wire::ingress::Install {
        instance,
        program: counter,
        attestables: Vec::new(),
        roles: Vec::new(),
    };
    operate(&|operator| operator.install(agent, &install).unwrap());
    agent
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
    instance: vos_wire::ids::InstanceId,
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
    instance: vos_wire::ids::InstanceId,
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
