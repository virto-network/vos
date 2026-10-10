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
