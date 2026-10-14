//! The `vos` command end to end: a node, an operator and a client, as
//! separate processes.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use vos_checker::processes::{Running, Started, read_log, run};
use vos_checker::programs::{actor_elf, agent, agent_elf};
use vos_checker::wait_until;

const VOS: &str = env!("CARGO_BIN_EXE_vos");

fn vos(args: &[&str]) -> String {
    let output = Command::new(VOS).args(args).output().expect("vos runs");
    assert!(
        output.status.success(),
        "vos {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
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

#[test]
fn a_client_calls_an_agent_the_operator_installed() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    let data = data.to_str().unwrap();
    let node = node_run(dir.path(), &["--data", data, "--listen", "127.0.0.1:0"]);
    let url = format!("http://{}", node.address);
    assert_eq!(vos(&["node", "info", "--node", &url]), node.key);

    let key = dir.path().join("client.key");
    let public = vos(&["key", "new", "--out", key.to_str().unwrap()]);
    assert_eq!(public.len(), 64);
    let agent = vos(&["agent", "create", "--node", &url, "--data", data]);
    let counter = actor_elf("counter");
    let installed = vos(&[
        "install",
        "--node",
        &url,
        "--data",
        data,
        "--agent",
        &agent,
        "--instance",
        "1",
        "--elf",
        counter.to_str().unwrap(),
    ]);
    assert!(installed.starts_with("done"), "{installed}");
    let client = |command: &str, method: &str, args: &str| {
        vos(&[
            command,
            "--node",
            &url,
            "--key",
            key.to_str().unwrap(),
            "--agent",
            &agent,
            "--instance",
            "1",
            "--method",
            method,
            "--args",
            args,
        ])
    };
    assert_eq!(
        client("call", "increment", "0500000000000000"),
        "done 0500000000000000"
    );
    let kept = std::fs::read_to_string(dir.path().join("client.key.session")).unwrap();
    assert_eq!(
        client("call", "increment", "0200000000000000"),
        "done 0700000000000000"
    );
    assert_eq!(client("query", "value", ""), "done 0700000000000000");
    let linearizable = vos(&[
        "query",
        "--linearizable",
        "--node",
        &url,
        "--key",
        key.to_str().unwrap(),
        "--agent",
        &agent,
        "--instance",
        "1",
        "--method",
        "value",
    ]);
    assert_eq!(linearizable, "done 0700000000000000");
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
    let data = dir.path().join("node");
    let data = data.to_str().unwrap();
    let node = node_run(dir.path(), &["--data", data, "--listen", "127.0.0.1:0"]);
    let url = format!("http://{}", node.address);
    let key = dir.path().join("client.key");
    vos(&["key", "new", "--out", key.to_str().unwrap()]);
    let agent = vos(&["agent", "create", "--node", &url, "--data", data]);
    let ledger = actor_elf("ledger").to_str().unwrap().to_string();
    let install = |elf: &str, roles: &[&str]| -> Vec<String> {
        let mut args: Vec<String> = [
            "install",
            "--node",
            &url,
            "--data",
            data,
            "--agent",
            &agent,
            "--instance",
            "2",
            "--elf",
            elf,
        ]
        .map(str::to_string)
        .to_vec();
        args.extend(roles.iter().map(|arg| arg.to_string()));
        args
    };

    let agent_elf = agent_elf();
    let refused = vos_fails(&strs(&install(agent_elf.to_str().unwrap(), &[])));
    assert!(refused.contains("vos_schema"), "{refused}");
    let unmapped = vos(&strs(&install(&ledger, &[])));
    assert!(unmapped.starts_with("failed 6"), "unknown: {unmapped}");
    let installed = vos(&strs(&install(&ledger, &["--role", "minter=1"])));
    // The node's derivation is the one a JAM builder makes of the same ELF.
    let elf = std::fs::read(&ledger).unwrap();
    let jam = vos_jam::programs::derive(&elf).unwrap().derivation;
    assert_eq!(
        installed,
        format!(
            "done\nprogram {}\nkernel checksum {}\nelf {}\ntranspiler {}",
            hex::encode(jam.program.0),
            hex::encode(jam.kernels[0].1.0),
            hex::encode(jam.elf),
            vos_pvm_compiler::TRANSPILER_VERSION,
        )
    );
    // The attestable runs as the kernel derived from the ledger's ELF: the
    // checksum of no values is its offset basis.
    let audited = vos(&[
        "call",
        "--node",
        &url,
        "--key",
        key.to_str().unwrap(),
        "--agent",
        &agent,
        "--instance",
        "2",
        "--method",
        "audit",
        "--args",
        "00000000",
    ]);
    assert_eq!(audited, "done 25232284e49cf2cb");
}

/// A call that starts a workflow prints its id; the key that started it
/// reads its result by the id, waiting for it to end, and another key
/// reads nothing.
#[test]
fn a_client_reads_the_workflow_it_started() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    let data = data.to_str().unwrap();
    let node = node_run(dir.path(), &["--data", data, "--listen", "127.0.0.1:0"]);
    let url = format!("http://{}", node.address);
    let agent = vos(&["agent", "create", "--node", &url, "--data", data]);
    let elf = |name: &str| actor_elf(name).to_str().unwrap().to_string();
    let installed = vos(&[
        "install",
        "--node",
        &url,
        "--data",
        data,
        "--agent",
        &agent,
        "--instance",
        "2",
        "--elf",
        &elf("ledger"),
        "--role",
        "minter=1",
    ]);
    assert!(installed.starts_with("done"), "{installed}");
    let key = |name: &str| {
        let path = dir.path().join(name);
        vos(&["key", "new", "--out", path.to_str().unwrap()]);
        path.to_str().unwrap().to_string()
    };
    let (owner, stranger) = (key("owner.key"), key("stranger.key"));
    // The amounts 1 and 2.
    let amounts = "0200000001000000000000000200000000000000";
    let started = vos(&[
        "call",
        "--node",
        &url,
        "--key",
        &owner,
        "--agent",
        &agent,
        "--instance",
        "2",
        "--method",
        "tally",
        "--args",
        amounts,
    ]);
    let id = started
        .strip_prefix("started ")
        .unwrap_or_else(|| panic!("{started}"));
    let read = |key: &str| {
        [
            "workflow", "--node", &url, "--key", key, "--agent", &agent, "--id", id, "--wait", "10",
        ]
        .map(str::to_string)
    };
    assert_eq!(vos(&strs(&read(&owner))), "done 0300000000000000");
    let unknown = vos_fails(&strs(&read(&stranger)));
    assert!(
        unknown.contains(&format!("holds no workflow {id} this key started")),
        "{unknown}"
    );
}

fn strs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

/// `vos` that should fail: its error.
fn vos_fails(args: &[&str]) -> String {
    let output = Command::new(VOS).args(args).output().expect("vos runs");
    assert!(!output.status.success(), "vos {args:?} succeeded");
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn an_operator_reaches_a_tls_node_by_its_key() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    let data = data.to_str().unwrap();
    let agent = agent_elf();

    // Without TLS, a node listens on a loopback address only.
    let refused = vos_fails(&[
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
        vos(&["node", "info", "--node", &url, "--node-key", &key]),
        key
    );
    let created = vos(&[
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
    let created = vos(&["agent", "create", "--node", &url, "--data", data]);
    assert!(created.parse::<u32>().is_ok(), "{created}");
    // Another key, no key, or plain HTTP: refused.
    let other = "11".repeat(32);
    vos_fails(&["node", "info", "--node", &url, "--node-key", &other]);
    vos_fails(&["node", "info", "--node", &url]);
    vos_fails(&["node", "info", "--node", &format!("http://{address}")]);
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
    use vos_wire::{Decode, defaults, expiry, keys};

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
    let key = dir.path().join("client.key");
    vos(&["key", "new", "--out", key.to_str().unwrap()]);
    let agent = vos(&["agent", "create", "--node", &url, "--data", data]);
    let counter = actor_elf("counter");
    let installed = vos(&[
        "install",
        "--node",
        &url,
        "--data",
        data,
        "--agent",
        &agent,
        "--instance",
        "1",
        "--elf",
        counter.to_str().unwrap(),
    ]);
    assert!(installed.starts_with("done"), "{installed}");
    let client = |url: &str, command: &str, method: &str, args: &str| {
        [
            command,
            "--node",
            url,
            "--key",
            key.to_str().unwrap(),
            "--agent",
            &agent,
            "--instance",
            "1",
            "--method",
            method,
            "--args",
            args,
        ]
        .map(str::to_string)
    };
    let run = |args: [String; 13]| vos(&args.iter().map(String::as_str).collect::<Vec<_>>());
    let fails =
        |args: [String; 13]| vos_fails(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(
        run(client(&url, "call", "increment", "0100000000000000")),
        "done 0100000000000000"
    );
    lose.armed.store(true, Ordering::SeqCst);
    let unanswered = std::thread::scope(|scope| {
        let call = scope.spawn(|| fails(client(&url, "call", "increment", "0200000000000000")));
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
    let refused = fails(client(&url, "call", "increment", "0200000000000000"));
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
        let live = node
            .store()
            .snapshot()
            .get(id, &keys::live_sessions())
            .unwrap()
            .and_then(|bytes| u64::decode(vos_wire::records::unstored(&bytes)?).ok())
            .map(|(live, _)| live);
        live == Some(0)
    });
    let lost = fails(client(&url, "call", "increment", "0200000000000000"));
    assert!(lost.contains("lost"), "{lost}");
    assert!(
        !std::fs::read_to_string(&session_file)
            .unwrap()
            .contains("pending"),
        "forgotten"
    );
    assert_eq!(
        run(client(&url, "query", "value", "")),
        "done 0300000000000000",
        "the lost call ran once"
    );
    node.shutdown();
}
