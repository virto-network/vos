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
//!   cargo build -p vosx; cd actors/messenger && cargo +nightly actor
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
        .expect("actors/")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn vosx_bin() -> PathBuf {
    workspace().join("target").join("debug").join("vosx")
}

fn messenger_elf() -> PathBuf {
    workspace().join("actors/messenger/target/riscv64em-javm/release/messenger.elf")
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
        (messenger_elf(), "cd actors/messenger && cargo +nightly actor"),
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
consistency = "raft"

[[agent]]
name = "msg-directory"
path = "{dir_elf}"
consistency = "raft"

[[agent]]
name = "messenger"
path = "{elf}"
consistency = "local"
device_secret = true
tick_ms = 300
intra_caps = ["msg-*:member", "space-registry:admin"]
"#,
        log_elf = msg_log_elf().display(),
        ctl_elf = msg_ctl_elf().display(),
        dir_elf = msg_directory_elf().display(),
        elf = messenger_elf().display(),
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
    /// This client's own libp2p PeerId (string form) — the identity the
    /// daemon sees as `Caller::Peer`. Exposed so a test can grant it a space
    /// role to access private `msg-*` logs.
    peer_id: String,
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
            peer_id: peer_id.to_string(),
        }
    }

    /// This client's libp2p PeerId (string), for granting it a space role.
    fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// Page the whole raw envelope log off one of the daemon's
    /// msg-<chan>-log replicas.
    fn raw_envelopes(&self, log_instance: &str) -> Vec<msg_log::EnvelopeRow> {
        let raw: [u8; 2] = vos::crypto::blake2b_hash(
            b"vos-instance-svc-id/v1",
            &[&[0u8], log_instance.as_bytes()],
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
            // An empty reply means the daemon refused the read (non-members
            // are denied access) — no rows to page.
            if reply.is_empty() {
                break;
            }
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

/// Connect a raw client to `daemon` and grant its peer the space READ tier
/// (via `admin`), waiting until `daemon`'s registry replica sees the grant —
/// so read access allows its raw `msg-*` ciphertext reads. The reader is
/// a space member but NOT a channel (MLS-group) member, so it can page the
/// replicated log yet only ever sees ciphertext.
fn connect_reader(daemon: &Daemon, admin: &Daemon) -> RawClient {
    let rc = RawClient::connect(daemon.data_dir());
    run_cli(
        admin,
        &["space", "role", SPACE_NAME, "grant", rc.peer_id(), "read"],
        "grant raw reader the space read tier",
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let (ok, stdout, _) = cli(daemon, &["space", "role", SPACE_NAME, "list"]);
        if ok && stdout.contains(rc.peer_id()) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "raw reader grant never replicated:\n{stdout}"
        );
        thread::sleep(Duration::from_millis(400));
    }
    rc
}

// ── The test ─────────────────────────────────────────────────────────

const PRE_JOIN_TEXT: &str = "pre-bob secret: only alice's epoch can read this";
const A_TO_B_TEXT: &str = "hello bob, this never crossed the wire in the clear";
const B_TO_A_TEXT: &str = "hi alice, ciphertext-only replication confirmed";
const POST_REMOVAL_TEXT: &str = "after-eviction secret: bob's keys stop here";
const POST_REJOIN_TEXT: &str = "welcome back bob, fresh epoch fresh keys";
const DEV_WARMUP_TEXT: &str = "dev epoch-0 warm-up: pre-bob, forever alice-only";
const DEV_A_TEXT: &str = "dev channel says hi over runtime-spawned agents";
const DEV_B_TEXT: &str = "roger from bob on the runtime channel";

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

    // ── Raft enrollment: msg-general-ctl + msg-directory run as a
    //    raft group whose voters come from the registry's members
    //    table. A is the genesis voter; enroll B's DAEMON node so
    //    its reconciler joins the groups and spawns followers.
    //    Forwarded raft writes (a follower's commit re-sent to the
    //    leader) carry the forwarding NODE's peer — distinct from
    //    the operators' client peers — so both daemons' node peers
    //    also get the member tier. ─────────────────────────────────
    let ep_b = read_endpoint(b.data_dir());
    run_cli(
        &a,
        &["space", "members", SPACE_NAME, "add-node", &ep_b.peer_id],
        "enroll B's daemon as a raft voter",
    );
    run_cli(
        &a,
        &["space", "role", SPACE_NAME, "grant", &ep_b.peer_id, "read"],
        "grant B's daemon the member tier",
    );
    run_cli(
        &a,
        &["space", "role", SPACE_NAME, "grant", &ep_a.peer_id, "read"],
        "grant A's daemon the member tier",
    );
    // B's reconciler must join the groups and spawn its follower
    // replicas before bob's register can publish KeyPackages (his
    // local directory replica is the publish target).
    {
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            let log = b.log_tail();
            if log.contains("agent 'msg-directory' spawned at runtime")
                && log.contains("agent 'msg-general-ctl' spawned at runtime")
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "B never spawned its raft follower replicas\n--- B log ---\n{log}"
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
    // Bob's KeyPackages reach A's directory replica via the raft
    // log; alice's claim races that — and the ctl group may still
    // be mid-join (B's admission as a voter) — so poll the invite
    // itself and let the deadline be the real assert.
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

    // ── Privacy gate 2: the replicated `msg-*` log is membership-gated AND
    //    ciphertext-only. (a) Private read handlers require membership; a
    //    NON-member can't read the log at all. (b) A
    //    space member who is NOT in the channel CAN read the replicated log
    //    on both nodes, but every envelope body is ciphertext (it never held
    //    the MLS keys). ────────────────────────────────────────────────────
    let plaintexts: [&[u8]; 5] = [
        PRE_JOIN_TEXT.as_bytes(),
        A_TO_B_TEXT.as_bytes(),
        B_TO_A_TEXT.as_bytes(),
        b"alice",
        b"bob",
    ];

    // (a) An ungranted outsider is denied access (empty → no rows).
    let outsider = RawClient::connect(a.data_dir());
    assert!(
        outsider.raw_envelopes("msg-general-log").is_empty(),
        "M1: an ungranted peer must not read the private msg- log"
    );

    // (b) Grant a snooper the space READ tier and confirm it reads only
    //     ciphertext from BOTH nodes. The snooper is a space member but not a
    //     channel (MLS-group) member — the realistic metadata-snooping threat.
    for (who, daemon) in [("A", &a), ("B", &b)] {
        let snoop = connect_reader(daemon, &a);
        let envelopes = snoop.raw_envelopes("msg-general-log");
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
    //
    // What this e2e proves: a removed member's messenger replicates
    // the ciphertext but stops surfacing the channel's new plaintext.
    // It does NOT by itself prove the *cryptographic* inability to
    // decrypt — once removed, bob's messenger marks the channel
    // un-joined and skips its log drain, so it never attempts the
    // decryption. The hard PCS property (the evicted member's keys
    // cannot decrypt post-removal traffic even if it tries) is pinned
    // by the offline `removed_member_cannot_decrypt_post_removal_traffic`
    // unit test, which drives `decrypt_app` directly and asserts Err.
    {
        let bob_raw = connect_reader(&b, &a);
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if bob_raw.raw_envelopes("msg-general-log").len() >= 4 {
                break;
            }
            thread::sleep(Duration::from_millis(400));
        }
        assert!(
            bob_raw.raw_envelopes("msg-general-log").len() >= 4,
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
        "an evicted member must not surface post-removal traffic:\n{bob_history}"
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

    // ── Dynamic second channel: no manifest entry, no restart.
    //    `create` clones the general pair's program rows into
    //    fresh msg-dev-{log,ctl} registry rows; A's idle
    //    spawn-reconcile brings them up locally, B's spawns them
    //    from the CRDT-synced rows; the invite/join/exchange flow
    //    then runs unchanged on the new channel. ─────────────────
    messenger(&a, &["create", "channel=dev"], "alice creates dev channel");
    // The first send races the spawn-reconcile window — poll until
    // the channel's freshly spawned log agent answers. This epoch-0
    // message predates bob's join, so it must stay alice-only.
    wait_for(
        &a,
        &["send", "channel=dev", &format!("text={DEV_WARMUP_TEXT}")],
        "alice dev warm-up send",
        |s| s.contains("sent"),
    );
    // msg-dev-ctl is a fresh raft group with voters {A, B}: the
    // smallest voter prefix bootstraps it (after confirming the
    // group absent on the other), the other node joins through its
    // leader. Wait for the replica on BOTH daemons before driving
    // the join/invite flow over it.
    {
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            let spawned = |log: &str| log.contains("agent 'msg-dev-ctl' spawned at runtime");
            if spawned(&a.log_tail()) && spawned(&b.log_tail()) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "msg-dev-ctl never spawned on both daemons\n--- A log ---\n{}\n--- B log ---\n{}",
                a.log_tail(),
                b.log_tail(),
            );
            thread::sleep(Duration::from_millis(400));
        }
    }
    messenger(&b, &["join", "channel=dev"], "bob joins dev");
    {
        // Same KeyPackage-replication race as the general-channel
        // invite, plus bob's msg-dev-ctl spawn window.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let out = messenger(
                &a,
                &["invite", "channel=dev", "member=bob"],
                "alice dev invite",
            );
            if out.contains("invited") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "alice's dev invite never succeeded: {out}"
            );
            thread::sleep(Duration::from_millis(400));
        }
    }
    wait_for(&b, &["status"], "bob status until dev joined", |s| {
        s.contains("channel dev: joined")
    });
    messenger(
        &a,
        &["send", "channel=dev", &format!("text={DEV_A_TEXT}")],
        "alice dev send",
    );
    wait_for(
        &b,
        &["history", "channel=dev", "limit=20"],
        "bob dev history",
        |s| s.contains(DEV_A_TEXT),
    );
    messenger(
        &b,
        &["send", "channel=dev", &format!("text={DEV_B_TEXT}")],
        "bob dev send",
    );
    wait_for(
        &a,
        &["history", "channel=dev", "limit=20"],
        "alice dev history",
        |s| s.contains(DEV_B_TEXT) && s.contains(DEV_A_TEXT),
    );
    // Pre-join history stays sealed on the runtime channel too:
    // bob's replica holds the warm-up ciphertext, his MLS state
    // has no epoch-0 keys.
    let bob_dev_history = messenger(
        &b,
        &["history", "channel=dev", "limit=50"],
        "bob full dev history",
    );
    assert!(
        !bob_dev_history.contains("warm-up"),
        "bob must not decrypt the dev channel's pre-join history:\n{bob_dev_history}"
    );

    // The runtime-spawned log replicates ciphertext-only on both
    // nodes — same privacy gate as the manifest channel.
    for (who, daemon) in [("A", &a), ("B", &b)] {
        let envelopes = connect_reader(daemon, &a).raw_envelopes("msg-dev-log");
        assert!(
            envelopes.len() >= 3,
            "node {who} should replicate the dev channel's envelopes, got {}",
            envelopes.len()
        );
        for env in &envelopes {
            for needle in [
                DEV_WARMUP_TEXT.as_bytes(),
                DEV_A_TEXT.as_bytes(),
                DEV_B_TEXT.as_bytes(),
            ] {
                assert!(
                    !env.body.windows(needle.len()).any(|w| w == needle),
                    "node {who}: dev envelope lamport={} leaks plaintext {:?}",
                    env.lamport,
                    String::from_utf8_lossy(needle),
                );
            }
        }
    }
}
