//! End-to-end: real `vosx` daemon + dev extension + dev-project
//! actor + space-registry. Drives the full source→PVM→catalog
//! pipeline through the same wire path an agent would use:
//!
//!   `vosx space new` →
//!   `vosx space up --manifest <with dev extension>` →
//!   `vosx dev new myproject` →
//!   test-client: put_blob(counter source) + commit on `main` →
//!   `vosx dev compile myproject` →
//!   `vosx dev publish myproject counter 0.1.0` →
//!   `vosx space install counter:0.1.0` →
//!   test-client: counter.inc (twice) → expect 1, 2
//!
//! The test verifies the compile pipeline actually produces a
//! working PVM blob (not just "the wire moves bytes"), so the
//! final `inc` assertion is the real value here. Everything
//! before that is plumbing the dev extension was already verified
//! against in earlier phases.
//!
//! Build prerequisites
//!
//!   cargo build -p vosx -p dev-extension
//!
//! Both must be present before this test runs — the harness
//! panics with a hint if either is missing rather than trying to
//! rebuild from inside the test runner.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use libp2p::Multiaddr;
use vos::Decode;
use vos::Encode;
use vos::abi::service::ServiceId;
use vos::network::{Network, NetworkConfig};
use vos::node::VosNode;
use vos::value::{Msg, TAG_DYNAMIC, Value};

// ── Paths ────────────────────────────────────────────────────────────

fn workspace() -> PathBuf {
    // CARGO_MANIFEST_DIR is `extensions/dev/`. Two `parent()`s to
    // climb out of `extensions/` to the workspace root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("extensions/")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn vosx_bin() -> PathBuf {
    workspace().join("target").join("debug").join("vosx")
}

fn dev_extension_so() -> PathBuf {
    workspace()
        .join("target")
        .join("debug")
        .join("libdev_extension.so")
}

fn ensure_built() {
    for (path, hint) in [
        (vosx_bin(), "cargo build -p vosx"),
        (dev_extension_so(), "cargo build -p dev-extension"),
    ] {
        if !path.exists() {
            panic!("test artifact missing: {}\nRun: {hint}", path.display());
        }
    }
}

// ── Tiny temp-dir helper (no `tempfile` dep) ─────────────────────────

struct TempDir(PathBuf);
impl TempDir {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        p.push(format!(
            "vos-dev-e2e-{}-{}-{}",
            std::process::id(),
            label,
            nanos
        ));
        fs::create_dir_all(&p).expect("create tempdir");
        TempDir(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("TempDir kept for debugging: {}", self.0.display());
            return;
        }
        let _ = fs::remove_dir_all(&self.0);
    }
}

// ── Endpoint file mirror (we can't import vosx::endpoint here) ───────

#[derive(serde::Deserialize)]
struct Endpoint {
    peer_id: String,
    multiaddrs: Vec<String>,
    prefix: u16,
    #[allow(dead_code)]
    pid: u32,
}

fn read_endpoint(data_dir: &Path) -> Endpoint {
    let p = data_dir.join(".endpoint");
    let raw = fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!("read endpoint {}: {e}", p.display());
    });
    toml::from_str(&raw).unwrap_or_else(|e| panic!("parse endpoint: {e}"))
}

// ── Daemon harness ───────────────────────────────────────────────────

struct Daemon {
    child: Option<Child>,
    data_home: TempDir,
    config_home: TempDir,
    manifest: PathBuf,
    space_name: String,
    space_data_dir: PathBuf,
}

impl Daemon {
    fn data_dir(&self) -> &Path {
        &self.space_data_dir
    }

    /// Stop + restart the daemon process against the same
    /// space + manifest. Used after registry-modifying operations
    /// (`dev new`, `space install`) so the reconciler's startup
    /// scan picks up the new agents — the current daemon doesn't
    /// have a watch loop for runtime registry updates.
    fn restart(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // Endpoint persists across the kill; wipe so the connect
        // loop doesn't latch onto the dead daemon's PID/port.
        let _ = fs::remove_file(self.space_data_dir.join(".endpoint"));
        let log_path = self.data_home.path().join("daemon.stderr");
        let log_file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .expect("reopen daemon log");
        let child = Command::new(vosx_bin())
            .args(["space", "up", &self.space_name, "--manifest"])
            .arg(&self.manifest)
            .env("XDG_DATA_HOME", self.data_home.path())
            .env("XDG_CONFIG_HOME", self.config_home.path())
            .env("RUST_LOG", "info")
            .env("VOSX_DISABLE_MDNS", "1")
            .stdout(Stdio::null())
            .stderr(log_file)
            .spawn()
            .expect("spawn vosx space up (restart)");
        self.child = Some(child);

        let endpoint_path = self.space_data_dir.join(".endpoint");
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if endpoint_path.exists() {
                return;
            }
            thread::sleep(Duration::from_millis(150));
        }
        panic!(
            "daemon didn't write endpoint within 30s on restart\n--- data ---\n{}",
            self.space_data_dir.display(),
        );
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn boot_daemon() -> Daemon {
    let data_home = TempDir::new("data");
    let config_home = TempDir::new("config");
    let space_name = "dev-e2e";

    // 1. `vosx space new`. Bundled space-registry blob kicks in
    //    automatically — no --registry needed.
    let new = Command::new(vosx_bin())
        .args(["space", "new", "--name", space_name])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("spawn vosx space new");
    assert!(
        new.status.success(),
        "vosx space new failed: stderr={}",
        String::from_utf8_lossy(&new.stderr)
    );

    // 2. Synthesise a manifest that loads the dev extension.
    let manifest = write_manifest(config_home.path());

    // 3. `vosx space up <name> --manifest <path>`. Stderr to file
    //    so a failed boot is inspectable without straddling a pipe.
    let log_path = data_home.path().join("daemon.stderr");
    let log_file = fs::File::create(&log_path).expect("create daemon stderr log");
    let child = Command::new(vosx_bin())
        .args(["space", "up", space_name, "--manifest"])
        .arg(&manifest)
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("RUST_LOG", "info")
        .env("VOSX_DISABLE_MDNS", "1")
        .stdout(Stdio::null())
        .stderr(log_file)
        .spawn()
        .expect("spawn vosx space up");

    // 4. Wait for the endpoint file. `space up` writes it after
    //    libp2p binds, so its presence means the daemon's ready
    //    for client invokes.
    let space_data_dir = resolve_space_data_dir(config_home.path(), space_name);
    let endpoint_path = space_data_dir.join(".endpoint");
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if endpoint_path.exists() {
            return Daemon {
                child: Some(child),
                data_home,
                config_home,
                manifest,
                space_name: space_name.to_string(),
                space_data_dir,
            };
        }
        thread::sleep(Duration::from_millis(150));
    }

    let stderr_tail = fs::read_to_string(&log_path).unwrap_or_default();
    panic!(
        "daemon didn't write endpoint within 30s\n--- stderr ---\n{stderr_tail}\n--- data ---\n{}",
        space_data_dir.display(),
    );
}

fn resolve_space_data_dir(config_home: &Path, space_name: &str) -> PathBuf {
    // Match vosx's resolve: scan `<XDG_CONFIG_HOME>/vosx/spaces.toml`
    // for the entry with matching name and return its data_dir.
    // Hard-codes the index format for the test's narrow needs.
    let index_path = config_home.join("vosx").join("spaces.toml");
    let raw = fs::read_to_string(&index_path)
        .unwrap_or_else(|e| panic!("read spaces.toml {}: {e}", index_path.display()));
    let parsed: toml::Value = toml::from_str(&raw).expect("parse spaces.toml");
    let entries = parsed
        .get("space")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("spaces.toml missing [[space]] entries: {raw}"));
    for entry in entries {
        let n = entry
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if n == space_name {
            let d = entry
                .get("data_dir")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            return PathBuf::from(d);
        }
    }
    panic!("space '{space_name}' not in spaces.toml");
}

fn write_manifest(dir: &Path) -> PathBuf {
    let manifest_path = dir.join("dev-e2e-manifest.toml");
    // `intra_caps = ["space-registry:admin"]` is required post
    // caller-propagation: the dev extension's `publish` handler relays
    // the operator's caller to `space-registry.publish` (Admin-gated).
    // Without a declared cap the relay arrives Unauthenticated and the
    // registry refuses it — see dev_publish_admin_succeeds_member_refused.
    let body = format!(
        r#"
space = "dev-e2e"
version = "0.1.0"

[[extension]]
name = "dev"
path = "{dev_so}"
intra_caps = ["space-registry:admin"]
"#,
        dev_so = dev_extension_so().display(),
    );
    fs::write(&manifest_path, body).expect("write manifest");
    manifest_path
}

// ── Test client (libp2p dial of the daemon) ──────────────────────────

struct TestClient {
    node: VosNode,
    daemon_prefix: u16,
}

impl TestClient {
    fn connect(data_dir: &Path) -> Self {
        let ep = read_endpoint(data_dir);
        let bootstrap_str = format!(
            "{}/p2p/{}",
            ep.multiaddrs.first().expect("at least one multiaddr"),
            ep.peer_id,
        );
        let bootstrap = Multiaddr::from_str(&bootstrap_str)
            .unwrap_or_else(|e| panic!("parse daemon multiaddr '{bootstrap_str}': {e}"));

        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = libp2p::PeerId::from(keypair.public());
        let local_prefix = vos::network::derive_node_prefix(&peer_id);

        let net = Network::start(NetworkConfig {
            keypair,
            local_prefix,
            listen: vec![],
            bootstrap: vec![bootstrap],
            auto_dial_mdns: false,
        });
        let mut node = VosNode::with_prefix(local_prefix);
        node.attach_network(net);

        let net_arc = node.network().expect("network was just attached");
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if net_arc.peer_for_prefix(ep.prefix).is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(
            net_arc.peer_for_prefix(ep.prefix).is_some(),
            "couldn't reach daemon at prefix {:#06x} within 10s",
            ep.prefix,
        );

        TestClient {
            node,
            daemon_prefix: ep.prefix,
        }
    }

    /// Per-node service id derived the same way `vosx space *`
    /// and the registry do — mirrors `instance_service_id`.
    fn resolve_instance(&self, name: &str) -> ServiceId {
        let raw: [u8; 2] =
            vos::crypto::blake2b_hash(b"vos-instance-svc-id/v1", &[&[0u8], name.as_bytes()]);
        let local = (u16::from_le_bytes(raw) & 0x7FFF).max(0x100);
        ServiceId(((self.daemon_prefix as u32) << 16) | (local as u32))
    }

    fn invoke(&self, target: ServiceId, msg: &Msg) -> Value {
        let mut payload = Vec::with_capacity(1 + 64);
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&msg.encode());
        let reply = self
            .node
            .invoke_with_timeout(target, payload, Duration::from_secs(120))
            .expect("daemon didn't reply within 120s");
        if reply.is_empty() {
            return Value::Unit;
        }
        <Value as Decode>::decode(&reply)
    }
}

impl Drop for TestClient {
    fn drop(&mut self) {
        // VosNode's network thread is the only thing keeping the
        // process alive after the test body returns. Take it down
        // proactively so the test process doesn't hang on exit.
        self.node.shutdown();
        let _ = std::mem::replace(&mut self.node, VosNode::with_prefix(0)).collect();
    }
}

// ── Counter actor source ─────────────────────────────────────────────

/// Minimal stateful counter actor — `inc` mutates + returns the
/// new count, `get` is a read-only query. Same shape as the
/// existing examples/actors/counter but with explicit `inc`/`get`
/// handlers so the assertions are observable from outside.
const COUNTER_SOURCE: &str = r#"
use vos::prelude::*;

#[actor]
pub struct Counter {
    count: u32,
}

#[messages]
impl Counter {
    fn new() -> Self {
        Self { count: 0 }
    }

    #[msg]
    async fn inc(&mut self) -> u32 {
        self.count += 1;
        self.count
    }

    #[msg]
    async fn get(&self) -> u32 {
        self.count
    }
}
"#;

// ── CLI wrappers (subprocess) ───────────────────────────────────────

fn vosx_cmd(daemon: &Daemon) -> Command {
    let mut c = Command::new(vosx_bin());
    c.env("XDG_DATA_HOME", daemon.data_home.path())
        .env("XDG_CONFIG_HOME", daemon.config_home.path())
        .env("VOSX_DISABLE_MDNS", "1")
        // The dev extension's `compile` runs cargo + rustc under
        // the hood — typical cold compile of a one-file counter
        // takes 5-20s. The CLI's default invoke timeout (10s) is
        // tuned for catalog reads, not compile; bump it well past
        // a slow cold-cache rebuild so the test isn't flaky.
        .env("VOSX_INVOKE_TIMEOUT_MS", "180000");
    c
}

/// Run a CLI command and capture (exit_code, stdout, stderr)
/// regardless of success. Used by tests that assert on failure
/// modes (the regular `run_cli` panics on non-zero exit).
fn run_cli_capture(daemon: &Daemon, args: &[&str], context: &str) -> (i32, String, String) {
    let mut cmd = vosx_cmd(daemon);
    cmd.args(args);
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("spawn vosx for {context}: {e}"));
    let code = out.status.code().unwrap_or(-1);
    (
        code,
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn run_cli(daemon: &Daemon, args: &[&str], context: &str) -> String {
    let mut cmd = vosx_cmd(daemon);
    cmd.args(args);
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("spawn vosx for {context}: {e}"));
    if !out.status.success() {
        panic!(
            "{context} failed (status={:?})\nargs: {args:?}\nstdout: {}\nstderr: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Run a CLI command as a *different* operator identity (its own
/// XDG_CONFIG_HOME) against the same daemon. Used to prove the dev
/// extension relays the *real* caller's role rather than its own
/// intra-system trust. Returns (exit_code, stdout, stderr).
fn run_cli_capture_as(
    daemon: &Daemon,
    config_home: &Path,
    args: &[&str],
    context: &str,
) -> (i32, String, String) {
    let out = Command::new(vosx_bin())
        .args(args)
        .env("XDG_DATA_HOME", daemon.data_home.path())
        .env("XDG_CONFIG_HOME", config_home)
        .env("VOSX_DISABLE_MDNS", "1")
        .env("VOSX_INVOKE_TIMEOUT_MS", "180000")
        .output()
        .unwrap_or_else(|e| panic!("spawn vosx for {context}: {e}"));
    let code = out.status.code().unwrap_or(-1);
    (
        code,
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// Provision a fresh, non-admin operator identity that can still reach
/// the same daemon: a new config home with the admin's `spaces.toml`
/// copied in so it resolves the space's endpoint. Its libp2p identity
/// stays independent (a fresh keypair, no role granted → Guest), which
/// is exactly the "outsider" shape `auth_smoke` uses.
fn member_config(daemon: &Daemon) -> TempDir {
    let cfg = TempDir::new("config-member");
    let admin_spaces = daemon.config_home.path().join("vosx").join("spaces.toml");
    let member_vosx = cfg.path().join("vosx");
    fs::create_dir_all(&member_vosx).expect("create member vosx dir");
    fs::copy(&admin_spaces, member_vosx.join("spaces.toml")).expect("copy spaces.toml to member");
    cfg
}

// ── The test ────────────────────────────────────────────────────────

#[test]
fn dev_compile_publish_install_invoke() {
    ensure_built();
    let mut daemon = boot_daemon();

    // 1. Provision the dev-project instance via the CLI. The
    //    registry now knows about `myproject`, but the daemon's
    //    `spawn_installed_agents` only runs at startup — restart
    //    so the new agent's thread comes up.
    run_cli(
        &daemon,
        &["dev", "new", "--space", &daemon.space_name, "myproject"],
        "vosx dev new",
    );
    daemon.restart();

    let client = TestClient::connect(daemon.data_dir());

    // 2. Resolve the project's ServiceId so we can talk to it.
    let project_id = client.resolve_instance("myproject");

    // 3. Put the counter source into the project's blob store.
    let put_reply = client.invoke(
        project_id,
        &Msg::new("put_blob").with("bytes", COUNTER_SOURCE.as_bytes().to_vec()),
    );
    let blob_hash = match put_reply {
        Value::Bytes(b) => {
            assert_eq!(b.len(), 32, "put_blob hash should be 32 bytes");
            b
        }
        other => panic!("put_blob returned {other:?}"),
    };

    // 4. Commit the blob on `main` at `src/lib.rs`. parent is
    //    empty (root commit, branch doesn't exist yet).
    let commit_reply = client.invoke(
        project_id,
        &Msg::new("commit")
            .with("parent", Vec::<u8>::new())
            .with("paths", vec!["src/lib.rs".to_string()])
            .with("blob_hashes", blob_hash.clone())
            .with("branch", "main".to_string())
            .with("intent_tag", dev_project::INTENT_EDIT)
            .with("intent_data", Vec::<u8>::new())
            .with("author", Vec::<u8>::new())
            .with("ts_ms", 0u64)
            .with("change_id", Vec::<u8>::new()),
    );
    let source_commit_hash = decode_hash_result_assert_ok(commit_reply, "commit src");
    assert_eq!(source_commit_hash.len(), 32, "commit hash size");

    // 5. Drive the dev extension's compile via the CLI. Default
    //    branch is `main`, which we just populated.
    run_cli(
        &daemon,
        &["dev", "compile", "--space", &daemon.space_name, "myproject"],
        "vosx dev compile",
    );

    // 6. Confirm a build commit appeared on the `builds` branch.
    let log_reply = client.invoke(
        project_id,
        &Msg::new("log")
            .with("branch", "builds".to_string())
            .with("limit", 4u32),
    );
    let log_bytes = match log_reply {
        Value::Bytes(b) => b,
        other => panic!("log returned {other:?}"),
    };
    assert_eq!(
        log_bytes.len(),
        32,
        "builds branch should have exactly one entry, got {} bytes",
        log_bytes.len()
    );

    // 7. Publish under (counter, 0.1.0).
    run_cli(
        &daemon,
        &[
            "dev",
            "publish",
            "--space",
            &daemon.space_name,
            "myproject",
            "counter",
            "0.1.0",
        ],
        "vosx dev publish",
    );

    // 8. Install the published program as an instance named
    //    `counter`. `space install` takes positional <SPACE>
    //    <PROGRAM_REF>, unlike the `dev *` family which uses
    //    `--space`.
    run_cli(
        &daemon,
        &["space", "install", &daemon.space_name, "counter:0.1.0"],
        "vosx space install",
    );

    // Drop the client + restart the daemon: same reason as after
    // `dev new` — `space install` only writes the registry row,
    // the agent thread comes up at the next `spawn_installed_agents`
    // pass, which is currently bound to daemon startup.
    drop(client);
    daemon.restart();
    let client = TestClient::connect(daemon.data_dir());

    // 9. Invoke `inc` twice; assert the count advances 1 → 2.
    let counter_id = client.resolve_instance("counter");
    let first = client.invoke(counter_id, &Msg::new("inc"));
    let second = client.invoke(counter_id, &Msg::new("inc"));

    let first_n = extract_u32(first);
    let second_n = extract_u32(second);
    assert_eq!(first_n, 1, "first inc should yield 1");
    assert_eq!(second_n, 2, "second inc should yield 2");
}

/// Caller-propagation + cap intersection, end-to-end (the C2 fix).
///
/// `vosx dev publish` invokes the dev extension's `publish` handler,
/// which relays the operator's caller to `space-registry.publish`
/// (Admin-gated). Before the fix the relay carried `Caller::Actor(dev)`
/// — trusted intra-system — so *any* operator could publish through the
/// extension. Now:
///   - a non-admin (Guest) operator's publish is REFUSED at the registry
///     step (the extension can't amplify the caller past its Guest role),
///   - the admin operator's publish SUCCEEDS — same daemon, same project,
///     same build, same `(name, version)`, same command; only the
///     identity differs.
///
/// That contrast is the security property: the refusal is role-driven,
/// not a setup or transport artifact. (The compile step hits the ungated
/// dev-project actor, so it's identity-agnostic — only the publish relay
/// is gated.)
#[test]
fn dev_publish_admin_succeeds_member_refused() {
    ensure_built();
    let mut daemon = boot_daemon();

    // Admin provisions + compiles a project.
    run_cli(
        &daemon,
        &["dev", "new", "--space", &daemon.space_name, "authproj"],
        "vosx dev new authproj",
    );
    daemon.restart();
    let client = TestClient::connect(daemon.data_dir());
    let project_id = client.resolve_instance("authproj");
    let src_hash = put_source(&client, project_id, "put_blob", COUNTER_SOURCE.as_bytes());
    commit_source(&client, project_id, &src_hash);
    drop(client);

    run_cli(
        &daemon,
        &["dev", "compile", "--space", &daemon.space_name, "authproj"],
        "vosx dev compile authproj",
    );

    // A non-admin operator (fresh identity, no grant → Guest) attempts
    // the same publish. The dev extension relays the member's Guest
    // authority — not its own trust — so the Admin-gated registry.publish
    // refuses it, and the CLI exits non-zero. Nothing is recorded (the
    // refusal precedes the publishes-branch commit), so the admin's
    // publish of the same (name, version) below is fresh.
    let member = member_config(&daemon);
    let (code, _out, err) = run_cli_capture_as(
        &daemon,
        member.path(),
        &[
            "dev",
            "publish",
            "--space",
            &daemon.space_name,
            "authproj",
            "counter",
            "0.1.0",
        ],
        "member dev publish",
    );
    assert_ne!(
        code, 0,
        "a non-admin operator's `dev publish` must be refused at the registry relay\nstderr: {err}",
    );
    // Pin the failure to the publish step (registry relay refusal), not
    // an incidental connect/resolve error — otherwise the assertion
    // above could pass without exercising the security property. The
    // member reaches the dev extension (resolve + builds-head are
    // ungated) and only the relayed registry.publish is refused.
    assert!(
        err.contains("publish failed"),
        "member's failure must be the publish-step refusal, not a transport/setup error\nstderr: {err}",
    );

    // The admin operator (the space creator → Admin) publishes the SAME
    // build under the SAME (name, version) and SUCCEEDS. Same everything
    // but the identity → the member's refusal above was role-driven.
    run_cli(
        &daemon,
        &[
            "dev",
            "publish",
            "--space",
            &daemon.space_name,
            "authproj",
            "counter",
            "0.1.0",
        ],
        "admin dev publish",
    );
}

fn decode_hash_result_assert_ok(value: Value, label: &str) -> Vec<u8> {
    let inner = match value {
        Value::Bytes(b) => b,
        other => panic!("{label}: expected Value::Bytes, got {other:?}"),
    };
    let result = <dev_project::HashResult as Decode>::try_decode(&inner)
        .unwrap_or_else(|| panic!("{label}: HashResult decode failed"));
    assert_eq!(
        result.status,
        dev_project::STATUS_OK,
        "{label}: expected STATUS_OK, got {}",
        result.status
    );
    result.hash
}

/// Verifies the property: storing source as `BlobKind::RustAst`
/// and compiling produces the same artifact ELF (same hash) as
/// storing the same source as `BlobKind::Raw` and compiling. The
/// dev extension's materialise step renders RustAst back to
/// canonical text via `dev_ast::ast_to_text` before writing to
/// disk, so the cargo invocation sees byte-identical source in
/// both flows.
///
/// This test was `#[ignore]`d 2026-05-12 (Phase 5 transpiler
/// regression note) because `put_blob_ast` returned Unit on
/// cold start. The companion regression test
/// `dev_project_main_branch_survives_daemon_restart` exercises
/// the same dispatch path and confirms the bug is gone — the
/// fix landed in some intervening commit (likely one of the
/// per-identity / side-branch / picky-review passes). Un-ignored
/// 2026-05-13 as part of the Sprint 1 correctness sweep.
#[test]
fn compile_via_ast_matches_raw_artifact() {
    ensure_built();
    let mut daemon = boot_daemon();

    // Provision two independent projects.
    run_cli(
        &daemon,
        &["dev", "new", "--space", &daemon.space_name, "proj-raw"],
        "vosx dev new proj-raw",
    );
    run_cli(
        &daemon,
        &["dev", "new", "--space", &daemon.space_name, "proj-ast"],
        "vosx dev new proj-ast",
    );
    daemon.restart();

    let client = TestClient::connect(daemon.data_dir());
    let raw_id = client.resolve_instance("proj-raw");
    let ast_id = client.resolve_instance("proj-ast");

    // Use a canonical-form source so the byte-identity property
    // is unambiguous — prettyplease would strip a stray comment
    // or normalise tabs even though the resulting ELF is the
    // same, which would obscure the comparison we're after.
    let canonical = dev_ast::ast_to_text(
        &dev_ast::text_to_ast(COUNTER_SOURCE).expect("parse canonical counter"),
    )
    .expect("canonical counter back to text");

    // proj-raw: put the canonical text as a Raw blob.
    let raw_hash = put_source(&client, raw_id, "put_blob", canonical.as_bytes());
    commit_source(&client, raw_id, &raw_hash);

    // proj-ast: put the canonical text as a RustAst blob via
    // `put_blob_ast`. The actor stores it as `BlobKind::RustAst`
    // under a separate domain tag.
    let ast_blob = dev_ast::text_to_ast(&canonical).expect("re-ast canonical");
    let ast_hash = put_source(&client, ast_id, "put_blob_ast", &ast_blob);
    commit_source(&client, ast_id, &ast_hash);

    // Compile both.
    run_cli(
        &daemon,
        &["dev", "compile", "--space", &daemon.space_name, "proj-raw"],
        "vosx dev compile proj-raw",
    );
    run_cli(
        &daemon,
        &["dev", "compile", "--space", &daemon.space_name, "proj-ast"],
        "vosx dev compile proj-ast",
    );

    let raw_artifact = artifact_hash_for(&client, raw_id);
    let ast_artifact = artifact_hash_for(&client, ast_id);
    assert_eq!(
        raw_artifact, ast_artifact,
        "AST and Raw paths should produce identical artifact ELFs"
    );
}

fn put_source(client: &TestClient, project_id: ServiceId, method: &str, bytes: &[u8]) -> Vec<u8> {
    let reply = client.invoke(project_id, &Msg::new(method).with("bytes", bytes.to_vec()));
    match reply {
        Value::Bytes(b) => {
            assert_eq!(b.len(), 32, "{method} should return a 32-byte hash");
            b
        }
        other => panic!("{method} returned {other:?}"),
    }
}

fn commit_source(client: &TestClient, project_id: ServiceId, blob_hash: &[u8]) {
    let reply = client.invoke(
        project_id,
        &Msg::new("commit")
            .with("parent", Vec::<u8>::new())
            .with("paths", vec!["src/lib.rs".to_string()])
            .with("blob_hashes", blob_hash.to_vec())
            .with("branch", "main".to_string())
            .with("intent_tag", dev_project::INTENT_EDIT)
            .with("intent_data", Vec::<u8>::new())
            .with("author", Vec::<u8>::new())
            .with("ts_ms", 0u64)
            .with("change_id", Vec::<u8>::new()),
    );
    let _ = decode_hash_result_assert_ok(reply, "commit source");
}

/// Walk the `builds` branch to its head, fetch that commit, decode
/// the `BuildIntent.artifact` field. Returns the empty-domain
/// blake2b hash compile.rs wrote into the host blob cache.
fn artifact_hash_for(client: &TestClient, project_id: ServiceId) -> [u8; 32] {
    let head_reply = client.invoke(
        project_id,
        &Msg::new("head").with("branch", "builds".to_string()),
    );
    let head_bytes = match head_reply {
        Value::Bytes(b) => b,
        other => panic!("head returned {other:?}"),
    };
    assert_eq!(head_bytes.len(), 32, "builds head should be a 32-byte hash");

    let commit_reply = client.invoke(project_id, &Msg::new("get_commit").with("hash", head_bytes));
    let commit_outer = match commit_reply {
        Value::Bytes(b) => b,
        other => panic!("get_commit returned {other:?}"),
    };
    assert!(!commit_outer.is_empty(), "get_commit should return Some");
    let commit =
        <dev_project::CommitNode as Decode>::try_decode(&commit_outer).expect("decode CommitNode");
    let intent = <dev_project::BuildIntent as Decode>::try_decode(&commit.intent_data)
        .expect("decode BuildIntent");
    assert_eq!(intent.ok, 1, "build should have succeeded");
    intent.artifact
}

fn extract_u32(v: Value) -> u32 {
    // Typed-handler return: u32 → `reply.into()` → `Value::U32`.
    // Account for the `Value::Bytes(rkyv-u32)` shape too in case
    // codegen changes upstream — read whichever it is.
    match v {
        Value::U32(n) => n,
        Value::U64(n) => n as u32,
        Value::Bytes(b) => <u32 as Decode>::try_decode(&b).unwrap_or_else(|| {
            panic!(
                "extract_u32: bytes ({} bytes) not a rkyv-encoded u32",
                b.len()
            )
        }),
        other => panic!("extract_u32: unexpected value {other:?}"),
    }
}

// ── Phase 5.5: cross-project deps ──────────────────────────────────

/// Minimal lib source for a dep project — a single pub function
/// so the cargo workspace has something to link against. `no_std`
/// + `no_main` are injected by the synthesised `.cargo/config.toml`
/// rustflags, same as the root project.
const LIB_SOURCE: &str = r#"
#![no_std]
pub fn forty_two() -> u32 { 42 }
"#;

/// Set the project's `.vos-project.rkyv` metadata to the given
/// deps + crate_type. Stores the rkyv-encoded `ProjectMetadata`
/// as a blob and commits it alongside the source on the project's
/// `main` branch. Returns the new commit hash.
fn put_metadata(
    client: &TestClient,
    project_id: ServiceId,
    parent: &[u8],
    src_path: &str,
    src_hash: &[u8],
    name: &str,
    crate_type: &str,
    deps: Vec<dev_project::DepEntry>,
    ts_ms: u64,
) -> Vec<u8> {
    let meta = dev_project::ProjectMetadata {
        name: name.to_string(),
        vos_version: String::new(),
        crate_type: crate_type.to_string(),
        deps,
        caps: Vec::new(),
    };
    let meta_bytes = <dev_project::ProjectMetadata as Encode>::encode(&meta);
    let meta_hash = put_source(client, project_id, "put_blob", &meta_bytes);

    // Commit lists src + metadata, sorted by path (the actor
    // rejects duplicate paths but accepts arbitrary order).
    let mut paths = vec![src_path.to_string(), ".vos-project.rkyv".to_string()];
    paths.sort();
    let mut blob_hashes = Vec::with_capacity(64);
    for p in &paths {
        let h = if p == ".vos-project.rkyv" {
            &meta_hash[..]
        } else {
            src_hash
        };
        blob_hashes.extend_from_slice(h);
    }

    let reply = client.invoke(
        project_id,
        &Msg::new("commit")
            .with("parent", parent.to_vec())
            .with("paths", paths)
            .with("blob_hashes", blob_hashes)
            .with("branch", "main".to_string())
            .with("intent_tag", dev_project::INTENT_EDIT)
            .with("intent_data", Vec::<u8>::new())
            .with("author", Vec::<u8>::new())
            .with("ts_ms", ts_ms)
            .with("change_id", Vec::<u8>::new()),
    );
    decode_hash_result_assert_ok(reply, "commit src+metadata")
}

/// Walk the `builds` branch to its head and return the decoded
/// `BuildIntent`. The test asserts on `intent.ok` to distinguish
/// successful from failed builds.
fn build_intent_for(client: &TestClient, project_id: ServiceId) -> dev_project::BuildIntent {
    let head_reply = client.invoke(
        project_id,
        &Msg::new("head").with("branch", "builds".to_string()),
    );
    let head_bytes = match head_reply {
        Value::Bytes(b) => b,
        other => panic!("builds head returned {other:?}"),
    };
    assert_eq!(
        head_bytes.len(),
        32,
        "expected builds branch head, got {} bytes",
        head_bytes.len()
    );
    let commit_reply = client.invoke(project_id, &Msg::new("get_commit").with("hash", head_bytes));
    let commit_outer = match commit_reply {
        Value::Bytes(b) => b,
        other => panic!("get_commit returned {other:?}"),
    };
    assert!(!commit_outer.is_empty(), "build commit should exist");
    let commit =
        <dev_project::CommitNode as Decode>::try_decode(&commit_outer).expect("decode CommitNode");
    <dev_project::BuildIntent as Decode>::try_decode(&commit.intent_data)
        .expect("decode BuildIntent")
}

/// A depends on B (lib). Compile A — should resolve B + materialise
/// it under `vendor/proj-b/` + emit a workspace Cargo.toml + cargo
/// compile the whole thing.
#[test]
fn cross_project_deps_compile_resolves_lib() {
    ensure_built();
    let mut daemon = boot_daemon();

    run_cli(
        &daemon,
        &["dev", "new", "--space", &daemon.space_name, "proj-b"],
        "vosx dev new proj-b",
    );
    run_cli(
        &daemon,
        &["dev", "new", "--space", &daemon.space_name, "proj-a"],
        "vosx dev new proj-a",
    );
    daemon.restart();
    let client = TestClient::connect(daemon.data_dir());

    let proj_b_id = client.resolve_instance("proj-b");
    let proj_a_id = client.resolve_instance("proj-a");

    // proj-b: a tiny pub fn lib, no deps.
    let b_src_hash = put_source(&client, proj_b_id, "put_blob", LIB_SOURCE.as_bytes());
    let b_commit = put_metadata(
        &client,
        proj_b_id,
        &[],
        "src/lib.rs",
        &b_src_hash,
        "proj-b",
        "rlib",
        Vec::new(),
        1,
    );

    // proj-a: counter actor, depends on proj-b at the commit
    // we just made. Note proj-a's source doesn't actually `use
    // proj_b` — the dep is in the cargo workspace, which is what
    // 5.2's resolver synthesis exercises.
    let a_src_hash = put_source(&client, proj_a_id, "put_blob", COUNTER_SOURCE.as_bytes());
    let _a_commit = put_metadata(
        &client,
        proj_a_id,
        &[],
        "src/lib.rs",
        &a_src_hash,
        "proj-a",
        "",
        vec![dev_project::DepEntry {
            name: "proj_b".to_string(),
            dep: dev_project::DepRef::Space {
                space_id: [0u8; 32],
                project_name: "proj-b".to_string(),
                commit: bytes_to_arr32(&b_commit),
            },
        }],
        2,
    );

    // Compile A. The dev extension reads proj-a's metadata,
    // resolves proj-b, materialises it under `vendor/proj-b/`,
    // and runs cargo against the workspace.
    run_cli(
        &daemon,
        &["dev", "compile", "--space", &daemon.space_name, "proj-a"],
        "vosx dev compile proj-a",
    );

    let intent = build_intent_for(&client, proj_a_id);
    assert_eq!(
        intent.ok, 1,
        "proj-a compile with proj-b dep should succeed; build commit intent_data: {intent:?}"
    );
}

/// proj-a's metadata lists itself as a dep — resolver bails with
/// COMPILE_STATUS_CYCLE before cargo runs.
#[test]
fn cross_project_deps_self_cycle_errors_loudly() {
    ensure_built();
    let mut daemon = boot_daemon();

    run_cli(
        &daemon,
        &["dev", "new", "--space", &daemon.space_name, "proj-cycle"],
        "vosx dev new proj-cycle",
    );
    daemon.restart();
    let client = TestClient::connect(daemon.data_dir());

    let proj_id = client.resolve_instance("proj-cycle");
    let src_hash = put_source(&client, proj_id, "put_blob", COUNTER_SOURCE.as_bytes());

    // Bogus commit hash for the self-dep — even if it pointed at
    // a real commit, the cycle check fires first because
    // project_name matches the root.
    put_metadata(
        &client,
        proj_id,
        &[],
        "src/lib.rs",
        &src_hash,
        "proj-cycle",
        "",
        vec![dev_project::DepEntry {
            name: "self".to_string(),
            dep: dev_project::DepRef::Space {
                space_id: [0u8; 32],
                project_name: "proj-cycle".to_string(),
                commit: [0xAAu8; 32],
            },
        }],
        1,
    );

    // Capture exit + streams: the CLI now surfaces any
    // intent.ok=0 outcome (cycle, cargo failure, etc.) as a
    // non-zero exit. Cycle detection runs before cargo, so the
    // build never gets that far — `compile_and_record` writes a
    // build commit with ok=0 and the CLI bails.
    let (code, stdout, stderr) = run_cli_capture(
        &daemon,
        &[
            "dev",
            "compile",
            "--space",
            &daemon.space_name,
            "proj-cycle",
        ],
        "vosx dev compile proj-cycle",
    );
    assert_ne!(
        code, 0,
        "self-cycle compile should exit non-zero\nstdout: {stdout}\nstderr: {stderr}"
    );

    let intent = build_intent_for(&client, proj_id);
    assert_eq!(
        intent.ok, 0,
        "self-cycle should record a failed build, got intent: {intent:?}"
    );
}

fn bytes_to_arr32(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..b.len().min(32)].copy_from_slice(&b[..b.len().min(32)]);
    out
}

/// Source with a syntax error — cargo build should fail. Used to
/// drive the intent.ok=0 path so the CLI's "failed cargo" surface
/// is regression-covered.
const BROKEN_SOURCE: &str = r#"
use vos::prelude::*;

#[actor]
pub struct Counter {
    count: u32,
}

#[messages]
impl Counter {
    fn new() -> Self {
        Self { count: 0 }
    }

    #[msg]
    async fn inc(&mut self) -> u32 {
        // Intentional syntax error: dangling token after expression.
        self.count = self.count + ;
        self.count
    }
}
"#;

/// Compiling a project whose source fails to build should exit
/// the CLI non-zero with a useful "cargo build failed" message.
/// Regression test for the intent.ok=0 path the CLI used to
/// silently treat as success (printed "compiled <name>" even
/// though the BuildIntent recorded the cargo failure).
#[test]
fn dev_compile_surfaces_cargo_failure() {
    ensure_built();
    let mut daemon = boot_daemon();

    run_cli(
        &daemon,
        &["dev", "new", "--space", &daemon.space_name, "proj-broken"],
        "vosx dev new proj-broken",
    );
    daemon.restart();
    let client = TestClient::connect(daemon.data_dir());

    let project_id = client.resolve_instance("proj-broken");
    let src_hash = put_source(&client, project_id, "put_blob", BROKEN_SOURCE.as_bytes());
    commit_source(&client, project_id, &src_hash);

    let (code, stdout, stderr) = run_cli_capture(
        &daemon,
        &[
            "dev",
            "compile",
            "--space",
            &daemon.space_name,
            "proj-broken",
        ],
        "vosx dev compile proj-broken",
    );

    assert_ne!(
        code, 0,
        "vosx dev compile should exit non-zero on cargo failure\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("compiled "),
        "stdout shouldn't claim 'compiled' on cargo failure\nstdout: {stdout}"
    );
    assert!(
        stderr.to_lowercase().contains("compile failed")
            || stderr.to_lowercase().contains("build failed"),
        "stderr should mention the failure\nstderr: {stderr}"
    );

    // Confirm the daemon-side record landed too — failure should
    // still show up as a BuildIntent with ok=0 on the builds branch.
    let intent = build_intent_for(&client, project_id);
    assert_eq!(
        intent.ok, 0,
        "broken source should record a failed build, got intent: {intent:?}"
    );
}

// ── vosx dev show + vosx dev merge ──────────────────────────────────

/// `vosx dev show --project P` (no path) lists the tree at head.
/// `vosx dev show --project P PATH` dumps that file's bytes.
/// Both paths should work against a project with a single
/// committed file.
#[test]
fn dev_show_tree_and_file() {
    ensure_built();
    let mut daemon = boot_daemon();

    run_cli(
        &daemon,
        &["dev", "new", "--space", &daemon.space_name, "showproj"],
        "vosx dev new showproj",
    );
    daemon.restart();
    let client = TestClient::connect(daemon.data_dir());
    let project_id = client.resolve_instance("showproj");

    // Seed src/lib.rs with the counter source on main.
    let src_hash = put_source(&client, project_id, "put_blob", COUNTER_SOURCE.as_bytes());
    commit_source(&client, project_id, &src_hash);

    // Tree listing — should mention the path + size > 0.
    let tree_text = run_cli(
        &daemon,
        &[
            "dev",
            "show",
            "--space",
            &daemon.space_name,
            "--project",
            "showproj",
        ],
        "vosx dev show (tree)",
    );
    assert!(
        tree_text.contains("src/lib.rs"),
        "tree listing should mention src/lib.rs, got:\n{tree_text}"
    );
    assert!(
        !tree_text.contains("? "),
        "tree size column shouldn't fall back to '?', got:\n{tree_text}"
    );

    // File content — should match what we committed.
    let file_text = run_cli(
        &daemon,
        &[
            "dev",
            "show",
            "--space",
            &daemon.space_name,
            "--project",
            "showproj",
            "src/lib.rs",
        ],
        "vosx dev show (file)",
    );
    assert!(
        file_text.contains("pub struct Counter"),
        "file dump should contain the counter source, got:\n{file_text}"
    );
}

/// `vosx dev show --project P does/not/exist` errors with a
/// specific message naming the missing path (not a generic
/// transport failure).
#[test]
fn dev_show_missing_path_errors() {
    ensure_built();
    let mut daemon = boot_daemon();

    run_cli(
        &daemon,
        &["dev", "new", "--space", &daemon.space_name, "showproj2"],
        "vosx dev new showproj2",
    );
    daemon.restart();
    let client = TestClient::connect(daemon.data_dir());
    let project_id = client.resolve_instance("showproj2");
    let src_hash = put_source(&client, project_id, "put_blob", COUNTER_SOURCE.as_bytes());
    commit_source(&client, project_id, &src_hash);

    let (code, _stdout, stderr) = run_cli_capture(
        &daemon,
        &[
            "dev",
            "show",
            "--space",
            &daemon.space_name,
            "--project",
            "showproj2",
            "does/not/exist.rs",
        ],
        "vosx dev show missing path",
    );
    assert_ne!(code, 0, "show on missing path should exit non-zero");
    assert!(
        stderr.contains("does/not/exist.rs") && stderr.contains("not in commit"),
        "error should name the missing path + reason, got:\n{stderr}"
    );
}

/// `vosx dev merge` fast-forwards `main` to a descendant branch's
/// head. Sets up a side branch by committing on top of main's
/// current head and exercises the FF path explicitly.
#[test]
fn dev_merge_ff_advances_main() {
    ensure_built();
    let mut daemon = boot_daemon();

    run_cli(
        &daemon,
        &["dev", "new", "--space", &daemon.space_name, "mergeproj"],
        "vosx dev new mergeproj",
    );
    daemon.restart();
    let client = TestClient::connect(daemon.data_dir());
    let project_id = client.resolve_instance("mergeproj");

    // Seed main with a base commit.
    let base_hash = put_source(&client, project_id, "put_blob", COUNTER_SOURCE.as_bytes());
    commit_source(&client, project_id, &base_hash);
    let main_before = current_head(&client, project_id, "main");

    // Commit a follow-up on a side branch (`feature`) off main.
    let updated = format!("{COUNTER_SOURCE}\n// trivial change\n");
    let side_blob = put_source(&client, project_id, "put_blob", updated.as_bytes());
    let side_commit_reply = client.invoke(
        project_id,
        &Msg::new("commit")
            .with("parent", main_before.clone())
            .with("paths", vec!["src/lib.rs".to_string()])
            .with("blob_hashes", side_blob)
            .with("branch", "feature".to_string())
            .with("intent_tag", dev_project::INTENT_EDIT)
            .with("intent_data", Vec::<u8>::new())
            .with("author", Vec::<u8>::new())
            .with("ts_ms", 1u64)
            .with("change_id", Vec::<u8>::new()),
    );
    let side_head = decode_hash_result_assert_ok(side_commit_reply, "commit feature");

    // `vosx dev merge --from feature --into main` should FF.
    let out = run_cli(
        &daemon,
        &[
            "dev",
            "merge",
            "--space",
            &daemon.space_name,
            "--project",
            "mergeproj",
            "--from",
            "feature",
            "--into",
            "main",
        ],
        "vosx dev merge feature → main",
    );
    assert!(
        out.contains("fast-forwarded"),
        "merge should report fast-forward, got:\n{out}"
    );

    // main now points at the feature head.
    let main_after = current_head(&client, project_id, "main");
    assert_eq!(
        main_after, side_head,
        "main should equal feature's head after FF merge",
    );
}

/// `vosx dev merge --into <missing>` returns a clear,
/// specific error instead of the actor's opaque
/// `STATUS_NOT_FOUND`.
#[test]
fn dev_merge_missing_into_errors_clearly() {
    ensure_built();
    let mut daemon = boot_daemon();

    run_cli(
        &daemon,
        &["dev", "new", "--space", &daemon.space_name, "mergeproj2"],
        "vosx dev new mergeproj2",
    );
    daemon.restart();
    let client = TestClient::connect(daemon.data_dir());
    let project_id = client.resolve_instance("mergeproj2");

    // Seed a side branch but NOT main, so --into main is missing.
    let blob = put_source(&client, project_id, "put_blob", COUNTER_SOURCE.as_bytes());
    let reply = client.invoke(
        project_id,
        &Msg::new("commit")
            .with("parent", Vec::<u8>::new())
            .with("paths", vec!["src/lib.rs".to_string()])
            .with("blob_hashes", blob)
            .with("branch", "feature".to_string())
            .with("intent_tag", dev_project::INTENT_EDIT)
            .with("intent_data", Vec::<u8>::new())
            .with("author", Vec::<u8>::new())
            .with("ts_ms", 1u64)
            .with("change_id", Vec::<u8>::new()),
    );
    let _ = decode_hash_result_assert_ok(reply, "commit feature");

    let (code, _stdout, stderr) = run_cli_capture(
        &daemon,
        &[
            "dev",
            "merge",
            "--space",
            &daemon.space_name,
            "--project",
            "mergeproj2",
            "--from",
            "feature",
            "--into",
            "main",
        ],
        "vosx dev merge into missing main",
    );
    assert_ne!(code, 0, "merge into missing branch should fail");
    assert!(
        stderr.contains("'main'") && stderr.contains("doesn't exist"),
        "error should specifically call out the missing target branch, got:\n{stderr}",
    );
}

fn current_head(client: &TestClient, project_id: ServiceId, branch: &str) -> Vec<u8> {
    let head = client.invoke(
        project_id,
        &Msg::new("head").with("branch", branch.to_string()),
    );
    match head {
        Value::Bytes(b) => b,
        other => panic!("head({branch}) returned {other:?}"),
    }
}

/// Regression for Sprint 1 / B5: a CRDT-replicated dev-project's
/// `main` commits must survive a daemon restart. The 2026-05-12
/// per-identity e2e session observed `main` reverting to empty
/// after `space up` restarted — symptoms identical to the
/// long-ignored `compile_via_ast_matches_raw_artifact` test in
/// this file (handlers return `Value::Unit` on cold start). The
/// regression test asserts the property directly: after a commit
/// + restart, `head(main)` returns the same 32-byte hash.
#[test]
fn dev_project_main_branch_survives_daemon_restart() {
    ensure_built();
    let mut daemon = boot_daemon();

    run_cli(
        &daemon,
        &["dev", "new", "--space", &daemon.space_name, "restartproj"],
        "vosx dev new restartproj",
    );
    daemon.restart();

    let client = TestClient::connect(daemon.data_dir());
    let project_id = client.resolve_instance("restartproj");

    // Put a blob and commit on `main`.
    let blob_hash = put_source(&client, project_id, "put_blob", COUNTER_SOURCE.as_bytes());
    let commit_reply = client.invoke(
        project_id,
        &Msg::new("commit")
            .with("parent", Vec::<u8>::new())
            .with("paths", vec!["src/lib.rs".to_string()])
            .with("blob_hashes", blob_hash.clone())
            .with("branch", "main".to_string())
            .with("intent_tag", dev_project::INTENT_EDIT)
            .with("intent_data", Vec::<u8>::new())
            .with("author", Vec::<u8>::new())
            .with("ts_ms", 0u64)
            .with("change_id", Vec::<u8>::new()),
    );
    let commit_hash = decode_hash_result_assert_ok(commit_reply, "commit main");
    assert_eq!(commit_hash.len(), 32, "commit hash size");

    let head_before = current_head(&client, project_id, "main");
    assert_eq!(
        head_before, commit_hash,
        "head(main) immediately after commit should equal the commit hash"
    );

    // Restart the daemon — the dev-project actor's state has to
    // be restored from the CRDT replicated storage. Drop the
    // client first so its libp2p outbound queues don't survive
    // the daemon's PID change.
    drop(client);
    daemon.restart();
    let client = TestClient::connect(daemon.data_dir());

    let head_after = current_head(&client, project_id, "main");
    assert_eq!(
        head_after,
        commit_hash,
        "head(main) after daemon restart should still equal the commit hash; \
         got {} bytes (commit was {} bytes)",
        head_after.len(),
        commit_hash.len(),
    );

    // get_blob should still resolve the source bytes too — covers
    // the case where the branch ref persists but the blob table
    // restoration lags. Without this, `dev compile` after restart
    // would silently produce empty output.
    let blob_reply = client.invoke(
        project_id,
        &Msg::new("get_blob").with("hash", blob_hash.clone()),
    );
    let restored_blob_bytes = match blob_reply {
        Value::Bytes(b) => b,
        other => panic!("get_blob after restart returned {other:?}"),
    };
    let restored_blob = <dev_project::BlobObject as Decode>::try_decode(&restored_blob_bytes)
        .expect("decode BlobObject after restart");
    assert_eq!(
        restored_blob.bytes.as_slice(),
        COUNTER_SOURCE.as_bytes(),
        "blob bytes must round-trip across a daemon restart"
    );

    // Same coverage for the AST handler — the long-ignored
    // `compile_via_ast_matches_raw_artifact` test in this file
    // reports `put_blob_ast` returning Unit on cold start. Put
    // an AST blob *after* the restart so we test both the
    // post-restore write path and the immediate read-back.
    let ast_blob = dev_ast::text_to_ast(COUNTER_SOURCE).expect("text→ast canonical");
    let ast_reply = client.invoke(
        project_id,
        &Msg::new("put_blob_ast").with("bytes", ast_blob.clone()),
    );
    let ast_hash = match ast_reply {
        Value::Bytes(b) => {
            assert_eq!(b.len(), 32, "put_blob_ast hash should be 32 bytes");
            b
        }
        Value::Unit => panic!(
            "put_blob_ast returned Value::Unit on a warm-restart daemon — \
             reproduces the bug from compile_via_ast_matches_raw_artifact"
        ),
        other => panic!("put_blob_ast returned {other:?}"),
    };
    let ast_get_reply = client.invoke(project_id, &Msg::new("get_blob").with("hash", ast_hash));
    let ast_get_bytes = match ast_get_reply {
        Value::Bytes(b) => b,
        other => panic!("get_blob(AST) returned {other:?}"),
    };
    let ast_get = <dev_project::BlobObject as Decode>::try_decode(&ast_get_bytes)
        .expect("decode BlobObject (AST)");
    assert_eq!(
        ast_get.kind,
        dev_project::BlobKind::RustAst,
        "AST blob must be tagged BlobKind::RustAst"
    );
    assert_eq!(ast_get.bytes, ast_blob, "AST blob bytes must round-trip");
}

/// Approach-C cap surfacing: the daemon records each service
/// extension's effective `intra_caps` in its endpoint descriptor at
/// boot, and `space caps` / `space describe` render them. The dev
/// manifest declares `intra_caps = ["space-registry:admin"]`, so both
/// surfaces must show that for the `dev` extension — no boot-log
/// scraping required.
#[test]
fn dev_relay_caps_surfaced_via_caps_and_describe() {
    ensure_built();
    let daemon = boot_daemon();

    // `space caps <space>` lists every extension's relay caps.
    let all = run_cli(
        &daemon,
        &["space", "caps", &daemon.space_name],
        "vosx space caps",
    );
    assert!(
        all.contains("dev") && all.contains("space-registry:admin"),
        "space caps should list dev's relay cap, got:\n{all}"
    );

    // Filtered to the one instance.
    let one = run_cli(
        &daemon,
        &["space", "caps", &daemon.space_name, "dev"],
        "vosx space caps dev",
    );
    assert!(
        one.contains("space-registry:admin"),
        "space caps dev should show the declared cap, got:\n{one}"
    );

    // A non-extension name is rejected with guidance.
    let (code, _out, err) = run_cli_capture(
        &daemon,
        &["space", "caps", &daemon.space_name, "space-registry"],
        "vosx space caps space-registry",
    );
    assert_ne!(code, 0, "caps for a non-extension should fail");
    assert!(
        err.contains("not a service extension"),
        "expected a helpful error, got:\n{err}"
    );

    // `space describe <space> dev` adds a `relay caps:` line distinct
    // from the host-ABI `caps:` line.
    let desc = run_cli(
        &daemon,
        &["space", "describe", &daemon.space_name, "dev"],
        "vosx space describe dev",
    );
    assert!(
        desc.contains("relay caps:") && desc.contains("space-registry:admin"),
        "describe should show a relay caps line, got:\n{desc}"
    );
}
