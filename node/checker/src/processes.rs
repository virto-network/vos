//! Node processes, each a `vos node run` of the `vos` binary a test
//! names, with its own data directory, ports, log and faults file, joined
//! through a relay the test controls, served in the clear or over TLS.

mod faults;
pub mod relay;
mod space;

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vos_node::client::{Operator, Target};
use vos_node::tls::Trust;
use vos_wire::ids::AgentId;
use vos_wire::ingress::{ReplicaStatus, Response};
use vos_wire::peer::NodeNumber;

use crate::programs::agent_elf;
use crate::spaces::{free_tcp_port, free_udp_port};
use crate::{Log, Nodes, wait_until};
use relay::Relay;

/// How long the harness waits for what it waits on: a node to listen or
/// to take its faults, a leader, an operator's command, a call's answer.
pub const PROCESS_WAIT: Duration = Duration::from_secs(60);

/// A running node, killed when dropped, however the test ends.
pub struct Running(Child);

impl Running {
    pub fn pid(&self) -> u32 {
        self.0.id()
    }

    /// Kill it (SIGKILL), and wait for it to end.
    pub fn kill(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }

    /// How it exited, if it did before the harness killed it.
    fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.0.try_wait().ok().flatten()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.kill();
    }
}

/// A node that started: the address it listens on, and its key in hex.
pub struct Started {
    pub running: Running,
    pub address: String,
    pub key: String,
}

/// Start `vos node run` of the binary `vos` with `args`, the default
/// agent, `faults` as its faults file, and pinned to `cpus` (as `taskset
/// -c` lists them) if given: the node, once it printed its address and
/// key, or `None` if it exited first. Its stderr goes to `log`, appended
/// to; its stdout is read to the end, so the node never writes to a
/// closed pipe.
pub fn run(
    vos: &Path,
    args: &[&str],
    log: &Path,
    faults: Option<&Path>,
    cpus: Option<&str>,
) -> Option<Started> {
    let errors = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .unwrap();
    let mut command = match cpus {
        Some(cpus) => {
            let mut command = Command::new("taskset");
            command.args(["-c", cpus]).arg(vos);
            command
        }
        None => Command::new(vos),
    };
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
    let Ok(listening) = read.recv_timeout(PROCESS_WAIT) else {
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
    let address = listening.strip_prefix("listening on ")?.to_string();
    let key = read
        .recv_timeout(PROCESS_WAIT)
        .ok()?
        .strip_prefix("node ")?
        .to_string();
    Some(Started {
        running,
        address,
        key,
    })
}

/// The key, in hex, a first run of `vos` alone makes at `data`, logging
/// to `log`.
pub fn first_run(vos: &Path, data: &Path, log: &Path) -> String {
    let args = ["--data", data.to_str().unwrap(), "--listen", "127.0.0.1:0"];
    run(vos, &args, log, None, None)
        .unwrap_or_else(|| panic!("a node alone starts: {}", read_log(log)))
        .key
}

/// What a node logged to `log`, if anything.
pub fn read_log(log: &Path) -> String {
    std::fs::read_to_string(log).unwrap_or_default()
}

/// A space file's text: a line for each of `nodes`, numbered from 1, of
/// its key in hex, its peer address and its ingress URL.
pub fn space_file<'a>(nodes: impl IntoIterator<Item = (&'a str, SocketAddr, &'a str)>) -> String {
    nodes
        .into_iter()
        .zip(1..)
        .map(|((key, peer, url), number)| format!("{number} {key} {peer} {url}\n"))
        .collect()
}

/// Where the node at `url` is reached: pinned to its key, `key` in hex,
/// over `tls`; else on a loopback address in the clear.
pub fn target(url: &str, key: &str, tls: bool) -> Target {
    let trust = if tls {
        let mut pinned = [0; 32];
        hex::decode_to_slice(key, &mut pinned).unwrap();
        Trust::NodeKey(pinned)
    } else {
        Trust::Loopback
    };
    Target::new(url, trust).unwrap()
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
    /// Its operator, with the token of the run it was made for: kept, so
    /// that what polls the node goes on one connection.
    operator: Mutex<Option<(String, Arc<Operator>)>>,
}

/// Nodes 1..=count of one space, each its own process, their peers
/// joined through a relay.
pub struct Processes {
    /// The `vos` binary the nodes run.
    vos: PathBuf,
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
    /// How far every node's clock runs ahead of the wall clock.
    clocks: AtomicI64,
    /// How far the agents' time runs ahead of the wall clock, as clients
    /// take it: as `clocks`, but moved last while the nodes' clocks move.
    offset: AtomicI64,
    /// Whether the nodes' clocks are moving: some moved on, some not yet.
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
    pub(crate) fn data(&self, number: usize) -> PathBuf {
        self.dir.path().join(format!("node-{number}"))
    }

    pub(crate) fn log_path(&self, number: usize) -> PathBuf {
        self.dir.path().join(format!("node-{number}.log"))
    }

    /// Node `number`'s faults file, which it reads every 50 ms.
    pub(crate) fn faults_file(&self, number: usize) -> PathBuf {
        self.dir.path().join(format!("node-{number}.faults"))
    }

    pub(crate) fn url(&self, number: usize) -> String {
        let scheme = if self.options.tls { "https" } else { "http" };
        format!("{scheme}://127.0.0.1:{}", self.ingress[number - 1])
    }

    /// Where node `number`'s ingress is reached.
    pub fn target(&self, number: usize) -> &Target {
        &self.targets[number - 1]
    }

    /// Node `number`'s operator, by the token its run wrote: the same
    /// one, and its kept connections, until the node starts again.
    pub(crate) fn operator(&self, number: usize) -> Arc<Operator> {
        let token = std::fs::read_to_string(self.data(number).join(vos_node::ADMIN_TOKEN)).unwrap();
        let mut kept = self.slot(number).operator.lock().unwrap();
        match &*kept {
            Some((made_for, operator)) if *made_for == token => Arc::clone(operator),
            _ => {
                let operator = Arc::new(Operator::within(self.target(number), &token, OPERATOR));
                *kept = Some((token, Arc::clone(&operator)));
                operator
            }
        }
    }

    pub fn is_running(&self, number: usize) -> bool {
        self.slot(number).running.lock().unwrap().is_some()
    }

    fn slot(&self, number: usize) -> &Slot {
        &self.slots[number - 1]
    }

    /// Start `count` nodes of the binary `vos`, choosing their ports
    /// again if one cannot take them.
    pub fn start(vos: impl AsRef<Path>, count: usize, options: Options) -> Self {
        let vos = vos.as_ref();
        let mut dir = tempfile::tempdir().unwrap();
        // `KEEP_NODES` keeps the nodes' data and logs, to look at after.
        if std::env::var_os("KEEP_NODES").is_some() {
            dir.disable_cleanup(true);
            eprintln!("the nodes' data and logs stay in {}", dir.path().display());
        }
        // A first run alone makes each node's key.
        let keys: Vec<String> = (1..=count)
            .map(|number| {
                first_run(
                    vos,
                    &dir.path().join(format!("node-{number}")),
                    &dir.path().join(format!("node-{number}.log")),
                )
            })
            .collect();
        for _attempt in 0..5 {
            let ingress: Vec<u16> = (0..count).map(|_| free_tcp_port()).collect();
            let bound: Vec<SocketAddr> = (0..count)
                .map(|_| format!("127.0.0.1:{}", free_udp_port()).parse().unwrap())
                .collect();
            let relay = Relay::start(&bound).expect("the relay starts");
            let scheme = if options.tls { "https" } else { "http" };
            let urls: Vec<String> = ingress
                .iter()
                .map(|port| format!("{scheme}://127.0.0.1:{port}"))
                .collect();
            let nodes = (0..count).map(|at| (&*keys[at], relay.listed(at + 1), &*urls[at]));
            std::fs::write(dir.path().join("space"), space_file(nodes)).unwrap();
            let targets = (0..count)
                .map(|at| target(&urls[at], &keys[at], options.tls))
                .collect();
            let processes = Processes {
                vos: vos.to_path_buf(),
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
        let started = run(
            &self.vos,
            &args,
            &self.log_path(number),
            Some(&faults),
            None,
        )?;
        assert_eq!(started.key, self.keys[number - 1]);
        Some(started.running)
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

    /// Node `number`'s replica of `agent`, if it runs, is not paused, and
    /// holds one.
    pub fn status(&self, number: usize, agent: AgentId) -> Option<ReplicaStatus> {
        if !self.is_running(number) || self.slot(number).paused.load(Ordering::SeqCst) {
            return None;
        }
        match self.operator(number).status(agent) {
            Ok(Response::Status(status)) => Some(status),
            _ => None,
        }
    }

    /// The running node leading `agent` at the highest term, once one
    /// does: a deposed leader may not know yet.
    pub fn leader(&self, agent: AgentId) -> usize {
        let mut leader = None;
        wait_until("a leader is known", PROCESS_WAIT, || {
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

    pub fn log_len(&self, number: usize) -> u64 {
        std::fs::metadata(self.log_path(number)).map_or(0, |log| log.len())
    }

    pub fn exits(&self) -> Vec<String> {
        self.exits.lock().unwrap().clone()
    }

    /// Stop every node at once (SIGSTOP), so none goes on while another
    /// is killed, then kill them (SIGKILL) and open each one's store.
    pub fn stop_all(&self) -> Vec<vos_node::store::Fjall> {
        for number in 1..=self.count {
            self.signal(number, "-STOP");
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
