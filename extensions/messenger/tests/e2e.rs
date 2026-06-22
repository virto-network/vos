//! End-to-end: two real `vosx` daemons in one space exchange
//! E2E-encrypted messages through the replicated channel actors.
//!
//!   host A: `space new` → `space up` (msg-general-{log,ctl} +
//!           messenger) → register alice → create channel →
//!           send a pre-invite message
//!   host B: `space join` (dials A) → `space up` → register bob →
//!           mint a KeyPackage
//!   host A: grant B's operator the member tier → invite bob with
//!           the KeyPackage
//!   host B: tick picks the Welcome off the commit chain → joins →
//!           both sides exchange messages
//!
//! The assertions that matter:
//!   1. plaintext round-trips both directions across two processes
//!      and a libp2p hop;
//!   2. the replicated `msg-general-log` holds ONLY ciphertext —
//!      no plaintext substring appears in any stored envelope on
//!      either node;
//!   3. bob never sees the message sent before his join epoch
//!      (MLS forward secrecy through the log's epoch gate), even
//!      though his node replicates its ciphertext.
//!
//! Build prerequisites (the harness panics with hints otherwise):
//!
//!   cargo build -p vosx -p messenger-extension
//!   just build-msg-actors

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use libp2p::Multiaddr;
use vos::abi::service::ServiceId;
use vos::network::{Network, NetworkConfig};
use vos::node::VosNode;
use vos::value::{Msg, TAG_DYNAMIC, Value};
use vos::{Decode, Encode};

// ── Paths ────────────────────────────────────────────────────────────

fn workspace() -> PathBuf {
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

fn messenger_so() -> PathBuf {
    workspace()
        .join("target")
        .join("debug")
        .join("libmessenger_extension.so")
}

fn msg_log_elf() -> PathBuf {
    workspace().join("actors/msg-log/target/riscv64em-javm/release/msg_log.elf")
}

fn msg_ctl_elf() -> PathBuf {
    workspace().join("actors/msg-ctl/target/riscv64em-javm/release/msg_ctl.elf")
}

fn msg_directory_elf() -> PathBuf {
    workspace().join("actors/msg-directory/target/riscv64em-javm/release/msg_directory.elf")
}

fn ensure_built() {
    for (path, hint) in [
        (vosx_bin(), "cargo build -p vosx"),
        (messenger_so(), "cargo build -p messenger-extension"),
        (msg_log_elf(), "just build-msg-actors"),
        (msg_ctl_elf(), "just build-msg-actors"),
        (msg_directory_elf(), "just build-msg-actors"),
    ] {
        if !path.exists() {
            panic!("test artifact missing: {}\nRun: {hint}", path.display());
        }
    }
}

// ── Tiny temp-dir helper ─────────────────────────────────────────────

struct TempDir(PathBuf);
impl TempDir {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        p.push(format!(
            "vos-msg-e2e-{}-{}-{}",
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

// ── Endpoint file mirror ─────────────────────────────────────────────

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

const SPACE_NAME: &str = "msg-e2e";

struct Daemon {
    child: Option<Child>,
    data_home: TempDir,
    config_home: TempDir,
    cache_home: TempDir,
    space_data_dir: PathBuf,
    log_path: PathBuf,
}

impl Daemon {
    fn data_dir(&self) -> &Path {
        &self.space_data_dir
    }
    fn log_tail(&self) -> String {
        fs::read_to_string(&self.log_path).unwrap_or_default()
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

fn write_manifest(dir: &Path) -> PathBuf {
    let manifest_path = dir.join("msg-e2e-manifest.toml");
    let body = format!(
        r#"
space = "{SPACE_NAME}"
version = "0.1.0"

[[agent]]
name = "msg-general-log"
path = "{log_elf}"
consistency = "crdt"

[[agent]]
name = "msg-general-ctl"
path = "{ctl_elf}"
consistency = "crdt"

[[agent]]
name = "msg-directory"
path = "{dir_elf}"
consistency = "crdt"

[[extension]]
name = "messenger"
path = "{so}"
tick_ms = 300
intra_caps = ["msg-general-log:member", "msg-general-ctl:member", "msg-directory:member"]
"#,
        log_elf = msg_log_elf().display(),
        ctl_elf = msg_ctl_elf().display(),
        dir_elf = msg_directory_elf().display(),
        so = messenger_so().display(),
    );
    fs::write(&manifest_path, body).expect("write manifest");
    manifest_path
}

fn spawn_up(
    data_home: &TempDir,
    config_home: &TempDir,
    cache_home: &TempDir,
    manifest: &Path,
    connect: Option<&str>,
    log_path: &Path,
) -> Child {
    let log_file = fs::File::create(log_path).expect("create daemon log");
    let mut cmd = Command::new(vosx_bin());
    cmd.args(["space", "up", SPACE_NAME, "--manifest"])
        .arg(manifest);
    if let Some(bootnode) = connect {
        cmd.args(["--connect", bootnode]);
    }
    cmd.env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("XDG_CACHE_HOME", cache_home.path())
        .env("RUST_LOG", "info")
        .env("VOSX_DISABLE_MDNS", "1")
        .stdout(Stdio::null())
        .stderr(log_file)
        .spawn()
        .expect("spawn vosx space up")
}

fn wait_endpoint(space_data_dir: &Path, log_path: &Path) {
    let endpoint_path = space_data_dir.join(".endpoint");
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if endpoint_path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(150));
    }
    panic!(
        "daemon didn't write endpoint within 30s\n--- log ---\n{}",
        fs::read_to_string(log_path).unwrap_or_default(),
    );
}

fn resolve_space_data_dir(config_home: &Path) -> PathBuf {
    let index_path = config_home.join("vosx").join("spaces.toml");
    let raw = fs::read_to_string(&index_path)
        .unwrap_or_else(|e| panic!("read spaces.toml {}: {e}", index_path.display()));
    let parsed: toml::Value = toml::from_str(&raw).expect("parse spaces.toml");
    for entry in parsed
        .get("space")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("spaces.toml missing [[space]] entries: {raw}"))
    {
        if entry.get("name").and_then(|v| v.as_str()) == Some(SPACE_NAME) {
            let d = entry
                .get("data_dir")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            return PathBuf::from(d);
        }
    }
    panic!("space '{SPACE_NAME}' not in spaces.toml");
}

fn space_id(config_home: &Path) -> String {
    let raw = fs::read_to_string(config_home.join("vosx").join("spaces.toml"))
        .expect("read spaces.toml for id");
    raw.lines()
        .find_map(|l| l.trim().strip_prefix("id = "))
        .map(|v| v.trim().trim_matches('"').to_string())
        .expect("spaces.toml should carry the space id")
}

/// Boot host A: create the space and bring the daemon up.
fn boot_creator() -> Daemon {
    let data_home = TempDir::new("a-data");
    let config_home = TempDir::new("a-config");
    let cache_home = TempDir::new("a-cache");

    let new = Command::new(vosx_bin())
        .args(["space", "new", "--name", SPACE_NAME])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("XDG_CACHE_HOME", cache_home.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("spawn vosx space new");
    assert!(
        new.status.success(),
        "vosx space new failed: stderr={}",
        String::from_utf8_lossy(&new.stderr)
    );

    let manifest = write_manifest(config_home.path());
    let log_path = data_home.path().join("daemon.stderr");
    let child = spawn_up(
        &data_home,
        &config_home,
        &cache_home,
        &manifest,
        None,
        &log_path,
    );
    let space_data_dir = resolve_space_data_dir(config_home.path());
    wait_endpoint(&space_data_dir, &log_path);
    Daemon {
        child: Some(child),
        data_home,
        config_home,
        cache_home,
        space_data_dir,
        log_path,
    }
}

/// Boot host B: join A's space over libp2p and bring a second
/// daemon up against it.
fn boot_joiner(bootnode: &str, id: &str) -> Daemon {
    let data_home = TempDir::new("b-data");
    let config_home = TempDir::new("b-config");
    let cache_home = TempDir::new("b-cache");

    let join = Command::new(vosx_bin())
        .args([
            "space",
            "join",
            &format!("{id}@{bootnode}"),
            "--name",
            SPACE_NAME,
        ])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("XDG_CACHE_HOME", cache_home.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("spawn vosx space join");
    assert!(
        join.status.success(),
        "vosx space join failed: stdout={} stderr={}",
        String::from_utf8_lossy(&join.stdout),
        String::from_utf8_lossy(&join.stderr)
    );

    let manifest = write_manifest(config_home.path());
    let log_path = data_home.path().join("daemon.stderr");
    let child = spawn_up(
        &data_home,
        &config_home,
        &cache_home,
        &manifest,
        Some(bootnode),
        &log_path,
    );
    let space_data_dir = resolve_space_data_dir(config_home.path());
    wait_endpoint(&space_data_dir, &log_path);
    Daemon {
        child: Some(child),
        data_home,
        config_home,
        cache_home,
        space_data_dir,
        log_path,
    }
}

// ── CLI wrappers ─────────────────────────────────────────────────────

fn cli(daemon: &Daemon, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(vosx_bin())
        .args(args)
        .env("XDG_DATA_HOME", daemon.data_home.path())
        .env("XDG_CONFIG_HOME", daemon.config_home.path())
        .env("XDG_CACHE_HOME", daemon.cache_home.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .unwrap_or_else(|e| panic!("spawn vosx {args:?}: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn run_cli(daemon: &Daemon, args: &[&str], what: &str) -> String {
    let (ok, stdout, stderr) = cli(daemon, args);
    assert!(
        ok,
        "{what} failed\nargs: {args:?}\nstdout: {stdout}\nstderr: {stderr}\n--- daemon log ---\n{}",
        daemon.log_tail()
    );
    stdout
}

fn messenger(daemon: &Daemon, verb_and_args: &[&str], what: &str) -> String {
    let mut args = vec!["messenger"];
    args.extend_from_slice(&verb_and_args[..1]);
    args.extend_from_slice(&["--space", SPACE_NAME]);
    args.extend_from_slice(&verb_and_args[1..]);
    run_cli(daemon, &args, what)
}

/// Poll a CLI read until `pred` accepts its stdout.
fn wait_for(daemon: &Daemon, verb_and_args: &[&str], what: &str, pred: impl Fn(&str) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut last = String::new();
    while Instant::now() < deadline {
        last = messenger(daemon, verb_and_args, what);
        if pred(&last) {
            return;
        }
        thread::sleep(Duration::from_millis(400));
    }
    panic!(
        "{what}: condition not met within 45s\nlast output:\n{last}\n--- daemon log ---\n{}",
        daemon.log_tail()
    );
}

// ── Raw-log client (libp2p dial, reads ciphertext envelopes) ─────────

struct RawClient {
    node: VosNode,
    daemon_prefix: u16,
}

impl RawClient {
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
        RawClient {
            node,
            daemon_prefix: ep.prefix,
        }
    }

    /// Page the whole raw envelope log off the daemon's
    /// msg-general-log replica.
    fn raw_envelopes(&self) -> Vec<msg_log::EnvelopeRow> {
        let raw: [u8; 2] = vos::crypto::blake2b_hash(
            b"vos-instance-svc-id/v1",
            &[&[0u8], "msg-general-log".as_bytes()],
        );
        let local = (u16::from_le_bytes(raw) & 0x7FFF).max(0x100);
        let target = ServiceId(((self.daemon_prefix as u32) << 16) | (local as u32));

        let mut out: Vec<msg_log::EnvelopeRow> = Vec::new();
        loop {
            let (after_lamport, after_id) = match out.last() {
                Some(e) => (e.lamport, e.id.to_vec()),
                None => (0, Vec::new()),
            };
            let msg = Msg::new("history")
                .with("after_lamport", after_lamport)
                .with("after_id", after_id)
                .with("limit", 64u64);
            let mut payload = Vec::with_capacity(1 + 64);
            payload.push(TAG_DYNAMIC);
            payload.extend_from_slice(&msg.encode());
            let reply = self
                .node
                .invoke_with_timeout(target, payload, Duration::from_secs(30))
                .expect("daemon didn't reply to raw history");
            let value = <Value as Decode>::decode(&reply);
            let inner = match value {
                Value::Bytes(b) => b,
                Value::Unit => Vec::new(),
                other => panic!("unexpected raw history reply: {other:?}"),
            };
            if inner.is_empty() {
                break;
            }
            let page = <Vec<msg_log::EnvelopeRow> as Decode>::try_decode(&inner)
                .expect("decode raw history page");
            if page.is_empty() {
                break;
            }
            out.extend(page);
        }
        out
    }
}

impl Drop for RawClient {
    fn drop(&mut self) {
        self.node.shutdown();
        let _ = std::mem::replace(&mut self.node, VosNode::with_prefix(0)).collect();
    }
}

// ── The test ─────────────────────────────────────────────────────────

const PRE_JOIN_TEXT: &str = "pre-bob secret: only alice's epoch can read this";
const A_TO_B_TEXT: &str = "hello bob, this never crossed the wire in the clear";
const B_TO_A_TEXT: &str = "hi alice, ciphertext-only replication confirmed";
const POST_REMOVAL_TEXT: &str = "after-eviction secret: bob's keys stop here";
const POST_REJOIN_TEXT: &str = "welcome back bob, fresh epoch fresh keys";

#[test]
fn two_nodes_exchange_e2ee_messages() {
    ensure_built();

    // ── Host A up, channel created, one pre-invite message. ────
    let a = boot_creator();
    let ep_a = read_endpoint(a.data_dir());
    let bootnode = format!(
        "{}/p2p/{}",
        ep_a.multiaddrs.first().expect("A listens"),
        ep_a.peer_id
    );
    let id = space_id(a.config_home.path());

    let out = messenger(&a, &["register", "nickname=alice"], "alice register");
    assert!(out.contains("registered"), "register reply: {out}");
    messenger(&a, &["create", "channel=general"], "alice create channel");
    messenger(
        &a,
        &["send", "channel=general", &format!("text={PRE_JOIN_TEXT}")],
        "alice pre-join send",
    );

    // ── Host B joins the space. ─────────────────────────────────
    let b = boot_joiner(&bootnode, &id);

    // B's operator starts as Guest; A (admin) grants the member
    // tier so B's relayed posts clear the actors' role gates. The
    // grant replicates to B's registry replica via CRDT sync.
    let whoami = run_cli(&b, &["whoami"], "bob whoami");
    let peer_b = whoami
        .lines()
        .find_map(|l| l.strip_prefix("peer_id = "))
        .map(str::trim)
        .expect("whoami output should contain peer_id");
    run_cli(
        &a,
        &["space", "role", SPACE_NAME, "grant", peer_b, "read"],
        "grant bob member tier",
    );

    // The grant must reach B's registry replica before bob's
    // register tries to publish KeyPackages under it.
    {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let (ok, stdout, _) = cli(&b, &["space", "role", SPACE_NAME, "list"]);
            if ok && stdout.contains(peer_b) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "bob's grant never replicated to B's registry:\n{stdout}"
            );
            thread::sleep(Duration::from_millis(400));
        }
    }

    // ── Bob registers (auto-stocks the directory), watches the
    //    channel. ──────────────────────────────────────────────
    let out = messenger(&b, &["register", "nickname=bob"], "bob register");
    assert!(
        out.contains("key packages published"),
        "register should stock the directory: {out}"
    );
    messenger(&b, &["join", "channel=general"], "bob join");

    // ── Alice invites bob BY NAME (directory claim); bob's tick
    //    completes the join. ─────────────────────────────────────
    let out = messenger(&b, &["status"], "bob status pre-invite");
    assert!(out.contains("waiting for welcome"), "status: {out}");
    // Bob's directory rows replicate to A's replica via CRDT sync;
    // alice's claim races that, so poll the invite itself.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let out = messenger(
            &a,
            &["invite", "channel=general", "member=bob"],
            "alice invite",
        );
        if out.contains("invited") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "alice's invite-by-name never succeeded: {out}"
        );
        assert!(
            out.contains("no key packages left"),
            "unexpected invite failure: {out}"
        );
        thread::sleep(Duration::from_millis(400));
    }
    wait_for(&b, &["status"], "bob status until joined", |s| {
        s.contains("joined")
    });

    // ── Plaintext round-trips both directions. ──────────────────
    messenger(
        &a,
        &["send", "channel=general", &format!("text={A_TO_B_TEXT}")],
        "alice send",
    );
    wait_for(
        &b,
        &["history", "channel=general", "limit=20"],
        "bob history",
        |s| s.contains(A_TO_B_TEXT),
    );
    messenger(
        &b,
        &["send", "channel=general", &format!("text={B_TO_A_TEXT}")],
        "bob send",
    );
    wait_for(
        &a,
        &["history", "channel=general", "limit=20"],
        "alice history",
        |s| s.contains(B_TO_A_TEXT) && s.contains(A_TO_B_TEXT) && s.contains(PRE_JOIN_TEXT),
    );

    // ── Privacy gate 1: bob never sees the pre-join message —
    //    his replica holds its ciphertext, his MLS state has no
    //    keys for that epoch.
    let bob_history = messenger(
        &b,
        &["history", "channel=general", "limit=50"],
        "bob full history",
    );
    assert!(
        !bob_history.contains("pre-bob"),
        "bob must not decrypt pre-join history:\n{bob_history}"
    );

    // ── Privacy gate 2: the replicated log is ciphertext-only on
    //    BOTH nodes. Every plaintext we exchanged must be absent
    //    from every stored envelope body.
    let plaintexts: [&[u8]; 5] = [
        PRE_JOIN_TEXT.as_bytes(),
        A_TO_B_TEXT.as_bytes(),
        B_TO_A_TEXT.as_bytes(),
        b"alice",
        b"bob",
    ];
    for (who, daemon) in [("A", &a), ("B", &b)] {
        let envelopes = RawClient::connect(daemon.data_dir()).raw_envelopes();
        assert!(
            envelopes.len() >= 3,
            "node {who} should replicate all 3 envelopes, got {}",
            envelopes.len()
        );
        for env in &envelopes {
            for needle in plaintexts {
                assert!(
                    !env.body.windows(needle.len()).any(|w| w == needle),
                    "node {who}: envelope lamport={} leaks plaintext {:?}",
                    env.lamport,
                    String::from_utf8_lossy(needle)
                );
            }
        }
    }

    // ── Removal: post-compromise security end to end. ───────────
    let out = messenger(
        &a,
        &["remove", "channel=general", "nickname=bob"],
        "alice removes bob",
    );
    assert!(out.contains("removed 'bob'"), "remove reply: {out}");
    wait_for(&b, &["status"], "bob status until removed", |s| {
        s.contains("removed — awaiting re-invite")
    });

    messenger(
        &a,
        &[
            "send",
            "channel=general",
            &format!("text={POST_REMOVAL_TEXT}"),
        ],
        "alice post-removal send",
    );
    wait_for(
        &a,
        &["history", "channel=general", "limit=50"],
        "alice sees own post-removal message",
        |s| s.contains(POST_REMOVAL_TEXT),
    );
    // Wait until bob's replica demonstrably HOLDS the post-removal
    // ciphertext (replication delivered it), then assert his
    // plaintext store never gains it — eviction revoked the keys,
    // not the bytes.
    {
        let bob_raw = RawClient::connect(b.data_dir());
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if bob_raw.raw_envelopes().len() >= 4 {
                break;
            }
            thread::sleep(Duration::from_millis(400));
        }
        assert!(
            bob_raw.raw_envelopes().len() >= 4,
            "bob's replica should hold the post-removal ciphertext"
        );
    }
    thread::sleep(Duration::from_secs(2));
    let bob_history = messenger(
        &b,
        &["history", "channel=general", "limit=50"],
        "bob post-removal history",
    );
    assert!(
        !bob_history.contains(POST_REMOVAL_TEXT),
        "an evicted member must not decrypt post-removal traffic:\n{bob_history}"
    );
    assert!(
        bob_history.contains(A_TO_B_TEXT),
        "pre-removal history stays readable locally:\n{bob_history}"
    );

    // ── Re-invite: a fresh out-of-band KeyPackage restores
    //    membership (the hex path stays supported alongside the
    //    directory). ──────────────────────────────────────────────
    let kp_out = messenger(&b, &["key_package"], "bob fresh key_package");
    let kp_hex = kp_out
        .split(|c: char| !c.is_ascii_hexdigit())
        .max_by_key(|run| run.len())
        .filter(|run| run.len() > 64)
        .unwrap_or_else(|| panic!("fresh key_package should print hex; got:\n{kp_out}"))
        .to_string();
    let out = messenger(
        &a,
        &["invite", "channel=general", &format!("member={kp_hex}")],
        "alice re-invites bob",
    );
    assert!(out.contains("invited"), "re-invite reply: {out}");
    wait_for(&b, &["status"], "bob status until re-joined", |s| {
        s.contains("joined")
    });
    messenger(
        &a,
        &[
            "send",
            "channel=general",
            &format!("text={POST_REJOIN_TEXT}"),
        ],
        "alice post-rejoin send",
    );
    wait_for(
        &b,
        &["history", "channel=general", "limit=50"],
        "bob sees post-rejoin message",
        |s| s.contains(POST_REJOIN_TEXT) && !s.contains(POST_REMOVAL_TEXT),
    );
}
