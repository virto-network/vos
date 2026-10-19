//! The `vos` command end to end: a node, an operator and a client, as
//! separate processes.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use vos_checker::processes::{Running, Started, read_log, run};
use vos_checker::programs::{actor_elf, agent, agent_elf};
use vos_checker::wait_until;

const VOS: &str = env!("CARGO_BIN_EXE_vos");

/// `vos` with `args`, and the arguments as it was given them.
fn vos_run(args: impl IntoIterator<Item: AsRef<OsStr>>) -> (Output, Vec<String>) {
    let args: Vec<String> = args
        .into_iter()
        .map(|arg| arg.as_ref().to_string_lossy().into_owned())
        .collect();
    let output = Command::new(VOS).args(&args).output().expect("vos runs");
    (output, args)
}

/// `vos` that should succeed: what it printed.
fn vos(args: impl IntoIterator<Item: AsRef<OsStr>>) -> String {
    let (output, args) = vos_run(args);
    assert!(
        output.status.success(),
        "vos {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

/// `vos` that should fail: its error.
fn vos_fails(args: impl IntoIterator<Item: AsRef<OsStr>>) -> String {
    let (output, args) = vos_run(args);
    assert!(!output.status.success(), "vos {args:?} succeeded");
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// `vos install` of `elf` as `agent`'s `instance`, at the node at `url`
/// whose data directory is `data`.
fn install(url: &str, data: &str, agent: &str, instance: &str, elf: &Path) -> Vec<String> {
    let elf = elf.to_str().unwrap();
    [
        "install",
        "--node",
        url,
        "--data",
        data,
        "--agent",
        agent,
        "--instance",
        instance,
        "--elf",
        elf,
    ]
    .map(str::to_string)
    .to_vec()
}

/// A client of `agent` at `url`, by the key whose seed is at `key`.
struct Client<'a> {
    url: &'a str,
    key: &'a str,
    agent: &'a str,
}

impl Client<'_> {
    /// `vos command` of `instance`'s `method`, with `args` in hex.
    fn invoke(&self, command: &str, instance: &str, method: &str, args: &str) -> Vec<String> {
        [
            command,
            "--node",
            self.url,
            "--key",
            self.key,
            "--agent",
            self.agent,
            "--instance",
            instance,
            "--method",
            method,
            "--args",
            args,
        ]
        .map(str::to_string)
        .to_vec()
    }
}

/// A node `vos node run` started, killed when dropped; a failing test
/// prints its log.
struct Node {
    running: Running,
    address: String,
    key: String,
    log: PathBuf,
}

impl Drop for Node {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.running.kill();
            eprintln!("the node's log:\n{}", read_log(&self.log));
        }
    }
}

/// `vos node run` with `args`, its log in `dir`: once it listens.
fn node_run(dir: &Path, args: &[&str]) -> Node {
    let log = dir.join("node.log");
    let Started {
        running,
        address,
        key,
    } = run(Path::new(VOS), args, &log, None, None)
        .unwrap_or_else(|| panic!("the node starts: {}", read_log(&log)));
    Node {
        running,
        address,
        key,
        log,
    }
}

/// A node of its own in `dir`, its data directory `dir/node`: the node,
/// its data directory and its URL.
fn single_node(dir: &Path) -> (Node, String, String) {
    let data = dir.join("node").to_str().unwrap().to_string();
    let node = node_run(dir, &["--data", &data, "--listen", "127.0.0.1:0"]);
    let url = format!("http://{}", node.address);
    (node, data, url)
}

/// A new client key at `dir/name`: its path.
fn new_key(dir: &Path, name: &str) -> String {
    let path = dir.join(name).to_str().unwrap().to_string();
    vos(["key", "new", "--out", &path]);
    path
}

/// `vos space up` founds a space once: its genesis, of the nodes the space
/// file lists, beside it, the id printed its hash; a second founding, a
/// window a venue would not register, or a founding node that holds an
/// agent already, is refused.
#[test]
fn a_space_is_founded_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("space");
    let file = path.to_str().unwrap();
    let data = dir.path().join("node");
    let data = data.to_str().unwrap();
    std::fs::write(
        &path,
        format!(
            "1 {} 127.0.0.1:7800 http://127.0.0.1:7700\n2 {} 127.0.0.1:7801 http://127.0.0.1:7701\n",
            "11".repeat(32),
            "22".repeat(32)
        ),
    )
    .unwrap();
    let up = |more: &[&str]| -> Vec<String> {
        ["space", "up", "--space", file, "--data", data]
            .iter()
            .chain(more)
            .map(|arg| arg.to_string())
            .collect()
    };
    let refused = vos_fails(up(&["--window-ms", "60000"]));
    assert!(refused.contains("120000"), "{refused}");
    assert!(!dir.path().join("space.genesis").exists());

    let id = vos(up(&["--window-ms", "120000", "--origin-ms", "5000"]));
    let space = vos_node::Space::read(&path).unwrap();
    let genesis = space.genesis().expect("the genesis beside the space file");
    assert_eq!(id, hex::encode(space.id().0));
    assert_eq!(genesis.nodes, [(1, [0x11; 32]), (2, [0x22; 32])]);
    assert_eq!(
        space.clock(),
        vos_wire::WindowClock {
            origin_ms: 5_000,
            length_ms: 120_000
        }
    );
    let refused = vos_fails(up(&[]));
    assert!(refused.contains("never changes"), "{refused}");
    assert_eq!(vos_node::Space::read(&path).unwrap().id(), space.id());
}

/// A node that holds an agent founds no space: its agent recorded no space
/// at its first install, for good.
#[test]
fn a_node_holding_agents_founds_no_space() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, data, url) = single_node(dir.path());
    vos(["agent", "create", "--node", &url, "--data", &data]);
    node.running.kill();
    let path = dir.path().join("space");
    std::fs::write(
        &path,
        format!("1 {} 127.0.0.1:7800 http://127.0.0.1:7700\n", node.key),
    )
    .unwrap();
    let refused = vos_fails([
        "space",
        "up",
        "--space",
        path.to_str().unwrap(),
        "--data",
        &data,
    ]);
    assert!(refused.contains("before creating any agent"), "{refused}");
    assert!(!dir.path().join("space.genesis").exists());
}

/// `vos node anchor-key rotate` makes a key in a stopped node's store and
/// prints it: each rotation another, kept in order, apart from the node
/// key. A directory with no node's store is refused.
#[test]
fn an_anchor_key_is_rotated_on_a_stopped_node() {
    let dir = tempfile::tempdir().unwrap();
    let refused = vos_fails([
        "node",
        "anchor-key",
        "rotate",
        "--data",
        dir.path().to_str().unwrap(),
    ]);
    assert!(refused.contains("run the node once first"), "{refused}");
    let (mut node, data, _) = single_node(dir.path());
    node.running.kill();
    let rotate = || vos(["node", "anchor-key", "rotate", "--data", &data]);
    let (first, second) = (rotate(), rotate());
    assert_ne!(first, second);
    let store = vos_node::store::Fjall::open(Path::new(&data).join(vos_node::STORE)).unwrap();
    let made: Vec<String> = store
        .anchor_secrets()
        .unwrap()
        .iter()
        .map(|(_, seed)| {
            let key = ed25519_dalek::SigningKey::from_bytes(&seed.unwrap()).verifying_key();
            key.to_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        })
        .collect();
    assert_eq!(made, [first, second]);
    assert_ne!(node.key, made[0], "apart from the node key");
}

#[test]
fn a_client_calls_an_agent_the_operator_installed() {
    let dir = tempfile::tempdir().unwrap();
    let (node, data, url) = single_node(dir.path());
    assert_eq!(vos(["node", "info", "--node", &url]), node.key);

    let key = dir.path().join("client.key").to_str().unwrap().to_string();
    let public = vos(["key", "new", "--out", &key]);
    assert_eq!(public.len(), 64);
    let agent = vos(["agent", "create", "--node", &url, "--data", &data]);
    let installed = vos(install(&url, &data, &agent, "1", &actor_elf("counter")));
    assert!(installed.starts_with("done"), "{installed}");
    let client = Client {
        url: &url,
        key: &key,
        agent: &agent,
    };
    let invoke =
        |command: &str, method: &str, args: &str| vos(client.invoke(command, "1", method, args));
    assert_eq!(
        invoke("call", "increment", "0500000000000000"),
        "done 0500000000000000"
    );
    let kept = std::fs::read_to_string(dir.path().join("client.key.session")).unwrap();
    assert_eq!(
        invoke("call", "increment", "0200000000000000"),
        "done 0700000000000000"
    );
    assert_eq!(invoke("query", "value", ""), "done 0700000000000000");
    let mut linearizable = client.invoke("query", "1", "value", "");
    linearizable.push("--linearizable".into());
    assert_eq!(vos(linearizable), "done 0700000000000000");
    // One session for the agent, kept next to the key, whose sequence
    // went on; and the agent's identity, fetched once.
    let session = |text: &str| -> Vec<String> {
        let line = text
            .lines()
            .find(|line| line.starts_with(&format!("session {agent} ")))
            .expect("the agent's session");
        line.split_whitespace().map(str::to_string).collect()
    };
    let after = std::fs::read_to_string(dir.path().join("client.key.session")).unwrap();
    let (before, after_session) = (session(&kept), session(&after));
    assert_eq!(before[..4], after_session[..4], "the same session");
    assert_eq!((&*before[4], &*after_session[4]), ("2", "3"));
    assert!(after.contains(&format!("identity {agent} ")), "{after}");
    // The floor the answers gave, so the next command reads its writes.
    assert!(after.contains(&format!("at {agent} ")), "{after}");
}

/// An operator installs a package, the ELF its actor's crate built: the
/// node derives its programs, the actor's and a kernel per attestable
/// method, and the install prints their hashes, as the derivation here
/// gives them. An ELF that is no package is refused before anything is
/// sent, and the agent refuses an install whose roles leave one unmapped.
#[test]
fn an_operator_installs_a_package() {
    let dir = tempfile::tempdir().unwrap();
    let (_node, data, url) = single_node(dir.path());
    let key = new_key(dir.path(), "client.key");
    let agent = vos(["agent", "create", "--node", &url, "--data", &data]);
    let ledger = actor_elf("ledger");
    let instance_2 = |elf: &Path| install(&url, &data, &agent, "2", elf);

    let refused = vos_fails(instance_2(&agent_elf()));
    assert!(refused.contains("vos_schema"), "{refused}");
    let unmapped = vos(instance_2(&ledger));
    assert!(unmapped.starts_with("failed 6"), "unknown: {unmapped}");
    let installed = vos([
        instance_2(&ledger),
        vec!["--role".into(), "minter=1".into()],
    ]
    .concat());
    // The node's derivation is the one a JAM builder makes of the same ELF.
    let elf = std::fs::read(&ledger).unwrap();
    let jam = vos_jam::programs::derive(&elf).unwrap().derivation;
    assert_eq!(
        installed,
        format!(
            "done\nprogram {}\nkernel checksum {}\nelf {}\ntranspiler {}",
            hex::encode(jam.program.0),
            hex::encode(jam.kernels[0].program.0),
            hex::encode(jam.elf),
            vos_pvm_compiler::TRANSPILER_VERSION,
        )
    );
    // The attestable runs as the kernel derived from the ledger's ELF: the
    // checksum of no values is its offset basis.
    let client = Client {
        url: &url,
        key: &key,
        agent: &agent,
    };
    let audited = vos(client.invoke("call", "2", "audit", "00000000"));
    assert_eq!(audited, "done 25232284e49cf2cb");
}

/// Arguments that do not parse end `vos` before it reaches any node, with
/// code 2: a call's arguments that are not hex, an install's role that is
/// not `NAME=BYTE` or whose byte is none, and a grant's role byte that is
/// none.
#[test]
fn malformed_arguments_exit_with_code_2() {
    let url = "http://127.0.0.1:1";
    let client = Client {
        url,
        key: "client.key",
        agent: "1",
    };
    let installing = |role: &str| {
        [
            install(url, "data", "1", "2", Path::new("actor.elf")),
            vec!["--role".into(), role.into()],
        ]
        .concat()
    };
    let granting = [
        "role",
        "--node",
        url,
        "--data",
        "data",
        "--agent",
        "1",
        "--principal",
        "00",
        "--role",
        "minter",
    ]
    .map(str::to_string)
    .to_vec();
    for args in [
        client.invoke("call", "2", "increment", "zz"),
        installing("minter"),
        installing("minter=x"),
        granting,
    ] {
        let (output, args) = vos_run(args);
        let error = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "vos {args:?}: {error}");
        assert!(error.contains("invalid value"), "vos {args:?}: {error}");
    }
}

/// A call that starts a workflow prints its id; the key that started it
/// reads its result by the id, waiting for it to end, and another key
/// reads nothing.
#[test]
fn a_client_reads_the_workflow_it_started() {
    let dir = tempfile::tempdir().unwrap();
    let (_node, data, url) = single_node(dir.path());
    let agent = vos(["agent", "create", "--node", &url, "--data", &data]);
    let ledger = install(&url, &data, &agent, "2", &actor_elf("ledger"));
    let installed = vos([ledger, vec!["--role".into(), "minter=1".into()]].concat());
    assert!(installed.starts_with("done"), "{installed}");
    let (owner, stranger) = (
        new_key(dir.path(), "owner.key"),
        new_key(dir.path(), "stranger.key"),
    );
    // The amounts 1 and 2.
    let amounts = "0200000001000000000000000200000000000000";
    let client = Client {
        url: &url,
        key: &owner,
        agent: &agent,
    };
    let started = vos(client.invoke("call", "2", "tally", amounts));
    let id = started
        .strip_prefix("started ")
        .unwrap_or_else(|| panic!("{started}"));
    let read = |key: &str| {
        [
            "workflow", "--node", &url, "--key", key, "--agent", &agent, "--id", id, "--wait", "10",
        ]
        .map(str::to_string)
    };
    assert_eq!(vos(read(&owner)), "done 0300000000000000");
    let unknown = vos_fails(read(&stranger));
    assert!(
        unknown.contains(&format!("holds no workflow {id} this key started")),
        "{unknown}"
    );
}

#[test]
fn an_operator_reaches_a_tls_node_by_its_key() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    let data = data.to_str().unwrap();
    let agent = agent_elf();

    // Without TLS, a node listens on a loopback address only.
    let refused = vos_fails([
        "node",
        "run",
        "--data",
        data,
        "--listen",
        "0.0.0.0:0",
        "--agent",
        agent.to_str().unwrap(),
    ]);
    assert!(refused.contains("loopback"), "{refused}");

    let node = node_run(
        dir.path(),
        &["--tls", "--data", data, "--listen", "127.0.0.1:0"],
    );
    let (address, key) = (&node.address, node.key.clone());
    let url = format!("https://{address}");

    assert_eq!(
        vos(["node", "info", "--node", &url, "--node-key", &key]),
        key
    );
    let created = vos([
        "agent",
        "create",
        "--node",
        &url,
        "--node-key",
        &key,
        "--data",
        data,
    ]);
    assert!(created.parse::<u32>().is_ok(), "{created}");
    // On the node's host, operator commands pin the key the node keeps in
    // its data directory.
    let created = vos(["agent", "create", "--node", &url, "--data", data]);
    assert!(created.parse::<u32>().is_ok(), "{created}");
    // Another key, no key, or plain HTTP: refused.
    let other = "11".repeat(32);
    vos_fails(["node", "info", "--node", &url, "--node-key", &other]);
    vos_fails(["node", "info", "--node", &url]);
    vos_fails(["node", "info", "--node", &format!("http://{address}")]);
}

/// Stops the leader loop once, after the commit it is armed for and before
/// its answers, and says so: that call ran, and the node stopping then
/// loses its answer.
#[derive(Default)]
struct LoseAnswer {
    armed: std::sync::atomic::AtomicBool,
    tripped: std::sync::atomic::AtomicBool,
}

impl vos_node::Hooks for LoseAnswer {
    fn after_commit(&self, _: vos_wire::ids::AgentId, _: u64) -> bool {
        use std::sync::atomic::Ordering;
        if self.armed.swap(false, Ordering::SeqCst) {
            self.tripped.store(true, Ordering::SeqCst);
            return false;
        }
        true
    }
}

/// A call left unanswered stays pending however long it waits. Called
/// again once the agent has collected its session, nothing can say whether
/// it ran: `vos` says so, forgets it, and never runs it again.
#[test]
fn a_pending_call_whose_session_was_collected_is_lost() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use vos_wire::{defaults, expiry, keys};

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    let bucket = defaults::SESSION_BUCKET_MS;
    let start = (vos_node::wall_clock() / bucket + 1) * bucket;
    let clock = Arc::new(AtomicU64::new(start));
    let lose = Arc::new(LoseAnswer::default());
    let open = || {
        let mut config = vos_node::Config::new(agent());
        config.hooks = lose.clone();
        config.clock = {
            let clock = Arc::clone(&clock);
            Arc::new(move || clock.load(Ordering::SeqCst))
        };
        let node = vos_node::Node::open(&data, config).unwrap();
        let address = node.serve("127.0.0.1:0".parse().unwrap()).unwrap();
        (node, format!("http://{address}"))
    };
    let (node, url) = open();
    let data = data.to_str().unwrap();
    let key = new_key(dir.path(), "client.key");
    let agent = vos(["agent", "create", "--node", &url, "--data", data]);
    let installed = vos(install(&url, data, &agent, "1", &actor_elf("counter")));
    assert!(installed.starts_with("done"), "{installed}");
    let client = |url: &str, command: &str, method: &str, args: &str| {
        let client = Client {
            url,
            key: &key,
            agent: &agent,
        };
        client.invoke(command, "1", method, args)
    };
    assert_eq!(
        vos(client(&url, "call", "increment", "0100000000000000")),
        "done 0100000000000000"
    );
    lose.armed.store(true, Ordering::SeqCst);
    let unanswered = std::thread::scope(|scope| {
        let call = scope.spawn(|| vos_fails(client(&url, "call", "increment", "0200000000000000")));
        wait_until("the call commits", Duration::from_secs(20), || {
            lose.tripped.load(Ordering::SeqCst)
        });
        node.shutdown();
        call.join().unwrap()
    });
    assert!(unanswered.contains("may have run"), "{unanswered}");
    let session_file = dir.path().join("client.key.session");
    assert!(
        std::fs::read_to_string(&session_file)
            .unwrap()
            .contains(&format!("pending {agent} ")),
        "kept pending"
    );
    // A line it does not know: the file is refused, and kept as it is.
    let kept = std::fs::read_to_string(&session_file).unwrap();
    std::fs::write(&session_file, format!("{kept}something else\n")).unwrap();
    let refused = vos_fails(client(&url, "call", "increment", "0200000000000000"));
    assert!(refused.contains("cannot read"), "{refused}");
    assert!(
        std::fs::read_to_string(&session_file)
            .unwrap()
            .contains("something else")
    );
    std::fs::write(&session_file, &kept).unwrap();

    // Back after its session's row came due: the idle leader collects it.
    clock.store(expiry::due(expiry::bucket(start)), Ordering::SeqCst);
    let (node, url) = open();
    let id = vos_wire::ids::AgentId(agent.parse().unwrap());
    wait_until("the session is collected", Duration::from_secs(20), || {
        vos_checker::applied::<u64>(node.store(), id, &keys::live_sessions()) == Some(0)
    });
    let lost = vos_fails(client(&url, "call", "increment", "0200000000000000"));
    assert!(lost.contains("lost"), "{lost}");
    assert!(
        !std::fs::read_to_string(&session_file)
            .unwrap()
            .contains("pending"),
        "forgotten"
    );
    assert_eq!(
        vos(client(&url, "query", "value", "")),
        "done 0300000000000000",
        "the lost call ran once"
    );
    node.shutdown();
}
