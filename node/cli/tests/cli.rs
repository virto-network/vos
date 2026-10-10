//! The `vos` command end to end: a node, an operator and a client, as
//! separate processes.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

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

fn vos(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_vos"))
        .args(args)
        .output()
        .expect("vos runs");
    assert!(
        output.status.success(),
        "vos {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

/// Kills the node when the test ends, however it ends.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_client_calls_an_agent_the_operator_installed() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    let data = data.to_str().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_vos"))
        .args([
            "node",
            "run",
            "--data",
            data,
            "--listen",
            "127.0.0.1:0",
            "--agent",
        ])
        .arg(guest("default/target/riscv64em-vos/release/vos-agent.elf"))
        .stdout(Stdio::piped())
        .spawn()
        .expect("the node starts");
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let _node = Running(child);
    let listening = lines.next().unwrap().unwrap();
    let address = listening
        .strip_prefix("listening on ")
        .expect("its address");
    let url = format!("http://{address}");
    let started = lines.next().unwrap().unwrap();
    let node_key = started.strip_prefix("node ").expect("its key");
    assert_eq!(vos(&["node", "info", "--node", &url]), node_key);

    let key = dir.path().join("client.key");
    let public = vos(&["key", "new", "--out", key.to_str().unwrap()]);
    assert_eq!(public.len(), 64);
    let agent = vos(&["agent", "create", "--node", &url, "--data", data]);
    let counter = guest("test-actors/target/riscv64em-vos/release/counter.elf");
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
        "--program",
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

/// `vos` that should fail: its error.
fn vos_fails(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_vos"))
        .args(args)
        .output()
        .expect("vos runs");
    assert!(!output.status.success(), "vos {args:?} succeeded");
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn an_operator_reaches_a_tls_node_by_its_key() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    let data = data.to_str().unwrap();
    let agent = guest("default/target/riscv64em-vos/release/vos-agent.elf");

    // Without TLS, a node listens on a loopback address only.
    let refused = Command::new(env!("CARGO_BIN_EXE_vos"))
        .args([
            "node",
            "run",
            "--data",
            data,
            "--listen",
            "0.0.0.0:0",
            "--agent",
        ])
        .arg(&agent)
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("loopback"));

    let mut child = Command::new(env!("CARGO_BIN_EXE_vos"))
        .args([
            "node",
            "run",
            "--tls",
            "--data",
            data,
            "--listen",
            "127.0.0.1:0",
            "--agent",
        ])
        .arg(&agent)
        .stdout(Stdio::piped())
        .spawn()
        .expect("the node starts");
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let _node = Running(child);
    let listening = lines.next().unwrap().unwrap();
    let address = listening
        .strip_prefix("listening on ")
        .expect("its address");
    let started = lines.next().unwrap().unwrap();
    let key = started.strip_prefix("node ").expect("its key").to_string();
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
    use vos_node::store::{Store, View};
    use vos_wire::{Decode, defaults, expiry, keys};

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    let bucket = defaults::SESSION_BUCKET_MS;
    let start = (vos_node::wall_clock() / bucket + 1) * bucket;
    let clock = Arc::new(AtomicU64::new(start));
    let lose = Arc::new(LoseAnswer::default());
    let open = || {
        let elf =
            std::fs::read(guest("default/target/riscv64em-vos/release/vos-agent.elf")).unwrap();
        let agent = vos_pvm_compiler::link_elf_spi(&elf).expect("links");
        let mut config = vos_node::Config::new(agent);
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
    let counter = guest("test-actors/target/riscv64em-vos/release/counter.elf");
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
        "--program",
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
        let until = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !lose.tripped.load(Ordering::SeqCst) {
            assert!(std::time::Instant::now() < until, "never committed");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
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
    // As an earlier version kept it, with the time it was left: still read.
    let kept = std::fs::read_to_string(&session_file).unwrap();
    let old: String = kept
        .lines()
        .map(|line| match line.starts_with("pending ") {
            true => format!("{line} 1\n"),
            false => format!("{line}\n"),
        })
        .collect();
    // A line no version wrote: the file is refused, and kept as it is.
    std::fs::write(&session_file, format!("{old}something else\n")).unwrap();
    let refused = fails(client(&url, "call", "increment", "0200000000000000"));
    assert!(refused.contains("cannot read"), "{refused}");
    assert!(
        std::fs::read_to_string(&session_file)
            .unwrap()
            .contains("something else")
    );
    std::fs::write(&session_file, &old).unwrap();

    // Back after its session's row came due: the idle leader collects it.
    clock.store(expiry::due(expiry::bucket(start)), Ordering::SeqCst);
    let (node, url) = open();
    let id = vos_wire::ids::AgentId(agent.parse().unwrap());
    let until = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let live = node
            .store()
            .snapshot()
            .get(id, &keys::live_sessions())
            .unwrap()
            .and_then(|bytes| u64::decode(vos_wire::records::unstored(&bytes)?).ok())
            .map(|(live, _)| live);
        if live == Some(0) {
            break;
        }
        assert!(std::time::Instant::now() < until, "never collected");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
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
