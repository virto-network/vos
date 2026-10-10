//! Three `vos node run` processes as one space, over QUIC: an agent on all
//! three takes calls through any of them and sends messages to another,
//! through the leader's SIGKILL and its restart, every call applied once.

use std::io::{BufRead, BufReader};
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use vos_node::client::{Client, Operator, Target};
use vos_node::store::View;
use vos_wire::Encode;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal};
use vos_wire::ingress::{Answer, Consistency, Install, QueryCall, query_message};
use vos_wire::keys;
use vos_wire::result::Outcome;
use vos_wire::schema::Schema;

const COUNTER: InstanceId = InstanceId(1);
/// The counter instance the other agent's messages increment.
const INBOX: InstanceId = InstanceId(2);

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

fn agent_elf() -> PathBuf {
    guest("default/target/riscv64em-vos/release/vos-agent.elf")
}

/// A running node, killed when dropped, however the test ends.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start `vos node run` with `args`: the node, once it printed its
/// address and key, or `None` if it exited first.
/// Its stderr goes to `log`, for a failure to show; its stdout is read to
/// the end, so the node never writes to a closed pipe.
fn run(args: &[&str], log: &Path) -> Option<(Running, String)> {
    let errors = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_vos"))
        .args(["node", "run"])
        .args(args)
        .arg("--agent")
        .arg(agent_elf())
        .stdout(Stdio::piped())
        .stderr(errors)
        .spawn()
        .expect("vos runs");
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

/// A free local port, TCP or UDP.
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

/// Three nodes of one space, each its own process.
struct Space {
    dir: tempfile::TempDir,
    keys: Vec<String>,
    ingress: Vec<u16>,
    running: Vec<Option<Running>>,
}

impl Space {
    fn data(&self, number: usize) -> PathBuf {
        self.dir.path().join(format!("node-{number}"))
    }

    fn log(&self, number: usize) -> PathBuf {
        self.dir.path().join(format!("node-{number}.log"))
    }

    fn url(&self, number: usize) -> String {
        format!("http://127.0.0.1:{}", self.ingress[number - 1])
    }

    fn target(&self, number: usize) -> Target {
        Target::loopback(&self.url(number)).unwrap()
    }

    fn operator(&self, number: usize) -> Operator {
        let token = std::fs::read_to_string(self.data(number).join(vos_node::ADMIN_TOKEN)).unwrap();
        Operator::new(&self.target(number), &token)
    }

    /// Start three nodes, choosing their ports again if one cannot take
    /// them.
    fn start() -> Self {
        let mut dir = tempfile::tempdir().unwrap();
        // A first run alone makes each node's key.
        let keys: Vec<String> = (1..=3)
            .map(|number| {
                let data = dir.path().join(format!("node-{number}"));
                let log = dir.path().join(format!("node-{number}.log"));
                let (_, key) = run(
                    &["--data", data.to_str().unwrap(), "--listen", "127.0.0.1:0"],
                    &log,
                )
                .unwrap_or_else(|| panic!("a node alone starts: {}", read_log(&log)));
                key
            })
            .collect();
        for _attempt in 0..5 {
            let ingress: Vec<u16> = (0..3).map(|_| free_port(false)).collect();
            let peers: Vec<u16> = (0..3).map(|_| free_port(true)).collect();
            let text: String = (0..3)
                .map(|at| {
                    format!(
                        "{} {} 127.0.0.1:{} http://127.0.0.1:{}\n",
                        at + 1,
                        keys[at],
                        peers[at],
                        ingress[at]
                    )
                })
                .collect();
            std::fs::write(dir.path().join("space"), text).unwrap();
            let mut space = Space {
                dir,
                keys: keys.clone(),
                ingress,
                running: Vec::new(),
            };
            let started: Vec<Option<Running>> =
                (1..=3).map(|number| space.launch(number)).collect();
            if started.iter().all(Option::is_some) {
                space.running = started;
                return space;
            }
            dir = space.dir;
        }
        panic!("the nodes could not take their ports");
    }

    fn launch(&self, number: usize) -> Option<Running> {
        let data = self.data(number);
        let listen = format!("127.0.0.1:{}", self.ingress[number - 1]);
        let space = self.dir.path().join("space");
        let (running, key) = run(
            &[
                "--data",
                data.to_str().unwrap(),
                "--listen",
                &listen,
                "--space",
                space.to_str().unwrap(),
            ],
            &self.log(number),
        )?;
        assert_eq!(key, self.keys[number - 1]);
        Some(running)
    }

    /// The node leading `agent`: only the leader takes an operator's
    /// command, here a revoke of a role no one holds.
    fn leader(&self, agent: AgentId) -> usize {
        let mut leader = None;
        wait_until("a leader is known", || {
            let answer = self
                .operator(1)
                .grant(agent, Principal::Client([0; 32]), None)
                .unwrap();
            leader = match answer {
                Answer::Ran { .. } => Some(1),
                Answer::NotLeader {
                    leader: Some(contact),
                } => (1..=3).find(|number| contact.address == self.url(*number)),
                _ => None,
            };
            leader.is_some()
        });
        leader.unwrap()
    }

    /// Kill node `number` with SIGKILL.
    fn kill(&mut self, number: usize) {
        drop(self.running[number - 1].take());
    }

    fn restart(&mut self, number: usize) {
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
}

fn read_log(log: &Path) -> String {
    std::fs::read_to_string(log).unwrap_or_default()
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(60);
    while !done() {
        assert!(Instant::now() < until, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn method(schema: &Schema, name: &str) -> MethodId {
    schema
        .methods
        .iter()
        .find(|method| method.name == name.as_bytes())
        .unwrap_or_else(|| panic!("no method {name}"))
        .id
}

fn done(answer: &Answer) -> Option<u64> {
    match answer {
        Answer::Ran {
            outcome: Outcome::Done(bytes),
            ..
        } => Some(vos_wire::Decode::decode(bytes).unwrap().0),
        _ => None,
    }
}

/// An operator's command, at whichever node takes it.
fn at_any(space: &Space, command: impl Fn(&Operator) -> Answer) -> Answer {
    let mut answer = None;
    wait_until("an operator's command is taken", || {
        for number in 1..=3 {
            if space.running[number - 1].is_none() {
                continue;
            }
            if let done @ (Answer::Ran { .. } | Answer::Created(_)) =
                command(&space.operator(number))
            {
                answer = Some(done);
                return true;
            }
        }
        false
    });
    answer.unwrap()
}

#[test]
fn three_processes_apply_every_call_once_through_a_kill() {
    let mut space = Space::start();
    let counter = std::fs::read(guest(
        "test-actors/target/riscv64em-vos/release/counter.elf",
    ))
    .unwrap();
    let counter = vos_pvm_compiler::link_elf_spi(&counter).expect("links");
    let create = |space: &Space| {
        let Answer::Created(agent) = at_any(space, |operator| {
            operator.create_agent(vec![1, 2, 3]).unwrap()
        }) else {
            unreachable!()
        };
        for instance in [INBOX, COUNTER] {
            let install = Install {
                instance,
                program: counter.clone(),
                attestables: Vec::new(),
                roles: Vec::new(),
            };
            at_any(space, |operator| operator.install(agent, &install).unwrap());
        }
        agent
    };
    let (sender, receiver) = (create(&space), create(&space));
    let mut client = Client::new(&space.target(1), SigningKey::from_bytes(&[21; 32]));
    let schema = client.schema(sender, COUNTER).unwrap().unwrap();
    let (increment, forward, value) = (
        method(&schema, "increment"),
        method(&schema, "forward"),
        method(&schema, "value"),
    );
    // Each call goes again, with its sequence, until it is answered.
    let call = |client: &mut Client, method: MethodId, arguments: Vec<u8>| -> u64 {
        let mut answered = None;
        wait_until("a call is answered", || {
            answered = client
                .call(sender, COUNTER, method, &arguments)
                .ok()
                .as_ref()
                .and_then(done);
            answered.is_some()
        });
        answered.unwrap()
    };
    let (mut total, mut forwarded) = (0, 0);
    // One node down at a time, so a quorum stays.
    let mut down = None;
    for request in 1..=60u64 {
        match request {
            // Right after a forward was answered, its message may still
            // be unacknowledged: the sender's leader is killed, then the
            // receiver's.
            21 => down = Some(space.leader(sender)),
            41 => down = Some(space.leader(receiver)),
            31 | 51 => {
                space.restart(down.take().expect("a node down"));
            }
            _ => {}
        }
        if let Some(number) = down.filter(|number| space.running[number - 1].is_some()) {
            space.kill(number);
        }
        if request.is_multiple_of(4) {
            let by = request * 10;
            assert_eq!(
                call(&mut client, forward, (receiver.0, INBOX.0, by).encode()),
                by
            );
            forwarded += by;
        } else {
            total += request;
            assert_eq!(call(&mut client, increment, request.encode()), total);
        }
    }
    // Every node holds every call once, and every message once: read at
    // each node itself, which a failover to another would hide.
    let key = SigningKey::from_bytes(&[23; 32]);
    let identities = [
        (sender, client.identity(sender).unwrap()),
        (receiver, client.identity(receiver).unwrap()),
    ];
    for number in 1..=3 {
        let read = |agent: AgentId, instance: InstanceId| {
            let identity = identities
                .iter()
                .find(|(id, _)| *id == agent)
                .map(|(_, identity)| *identity)
                .unwrap();
            let not_after = vos_node::wall_clock() + 60_000;
            let public = key.verifying_key().to_bytes();
            let consistency = Consistency::Linearizable;
            let message = query_message(
                &identity,
                &public,
                not_after,
                consistency,
                instance,
                value,
                &[],
            );
            let query = QueryCall {
                key: public,
                not_after,
                consistency,
                instance,
                method: value,
                arguments: Vec::new(),
                signature: ed25519_dalek::Signer::sign(&key, &message).to_bytes(),
            };
            let path = format!("/agents/{}/queries", agent.0);
            let (_, body) =
                vos_node::client::post(&space.target(number), &path, &query.encode()).ok()?;
            let (answer, _) = <Answer as vos_wire::Decode>::decode(&body).ok()?;
            done(&answer)
        };
        wait_until("every node converges", || {
            read(sender, COUNTER) == Some(total) && read(receiver, INBOX) == Some(forwarded)
        });
    }
    // Each forward's message applied once at each replica, and was sent
    // once: their pair's marks, on disk, once the nodes stopped.
    let forwards = (1..=60u64)
        .filter(|request| request.is_multiple_of(4))
        .count() as u64;
    for number in 1..=3 {
        space.kill(number);
    }
    for number in 1..=3 {
        let store = vos_node::store::Fjall::open(space.data(number).join("store")).unwrap();
        let mark = |agent: AgentId, key: &[u8]| {
            let bytes = vos_node::store::Store::snapshot(&store)
                .get(agent, key)
                .unwrap()
                .unwrap();
            let value = vos_wire::records::unstored(&bytes).unwrap();
            <u64 as vos_wire::Decode>::decode(value).unwrap().0
        };
        assert_eq!(mark(receiver, &keys::pair_in(sender)), forwards);
        assert_eq!(mark(sender, &keys::pair_out(receiver)), forwards);
    }
}
