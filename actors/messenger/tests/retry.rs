//! Deterministic commit-race retry: the production
//! `commit_chain_op` catch-up path, driven end to end.
//!
//! One daemon hosts FOUR messenger instances sharing one channel
//! stack (msg-general-{log,ctl} + msg-directory, ctl + directory on
//! solo-voter raft). No `tick_ms` anywhere — every drain goes
//! through the explicit `sync` verb, so each instance's epoch view
//! is under test control:
//!
//!   alice creates the channel and invites bob (directory claim,
//!   chain epoch 0); bob syncs and joins. Alice then invites carol
//!   (chain epoch 1) — and bob, still at epoch 1 because he never
//!   synced, invites dave. His commit submits at the stale epoch,
//!   msg-ctl answers STATUS_EPOCH_TAKEN, and `commit_chain_op`
//!   drains the chain (processing carol's add) and resubmits at the
//!   real head — landing dave at chain epoch 2 with no fork.
//!
//! Asserts: bob's invite reports the post-retry epoch; the chain
//! holds exactly the three winning commits; both members converge
//! on the post-race message flow. Also exercises solo-voter raft
//! bootstrap (the groups elect a leader of one at boot).
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
            "vos-msg-retry-{}-{}-{}",
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

// ── Daemon harness ───────────────────────────────────────────────────

const SPACE_NAME: &str = "msg-retry";

/// The four messenger instances. Carol and dave only ever mint
/// out-of-band KeyPackages (a valid KP needs a real MLS identity);
/// they never join.
const ALICE: &str = "msgr-alice";
const BOB: &str = "msgr-bob";
const CAROL: &str = "msgr-carol";
const DAVE: &str = "msgr-dave";

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

/// Four device-local messenger agents (same ELF, distinct names); NO
/// `tick_ms`, so the only drains are explicit `sync` calls.
fn write_manifest(dir: &Path) -> PathBuf {
    let manifest_path = dir.join("msg-retry-manifest.toml");
    let mut body = format!(
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
"#,
        log_elf = msg_log_elf().display(),
        ctl_elf = msg_ctl_elf().display(),
        dir_elf = msg_directory_elf().display(),
    );
    // Four device-local messenger agents (distinct names → distinct seeds +
    // identities) sharing the one channel stack. No `tick_ms`: every drain is
    // the explicit `sync` verb so each instance's epoch view is under test
    // control.
    for name in [ALICE, BOB, CAROL, DAVE] {
        body.push_str(&format!(
            r#"
[[agent]]
name = "{name}"
path = "{elf}"
consistency = "local"
device_secret = true
intra_caps = ["msg-*:member", "space-registry:admin"]
"#,
            elf = messenger_elf().display(),
        ));
    }
    fs::write(&manifest_path, body).expect("write manifest");
    manifest_path
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

fn boot_daemon() -> Daemon {
    let data_home = TempDir::new("data");
    let config_home = TempDir::new("config");
    let cache_home = TempDir::new("cache");

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
    let log_file = fs::File::create(&log_path).expect("create daemon log");
    let child = Command::new(vosx_bin())
        .args(["space", "up", SPACE_NAME, "--manifest"])
        .arg(&manifest)
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("XDG_CACHE_HOME", cache_home.path())
        .env("RUST_LOG", "info")
        .env("VOSX_DISABLE_MDNS", "1")
        .stdout(Stdio::null())
        .stderr(log_file)
        .spawn()
        .expect("spawn vosx space up");

    let space_data_dir = resolve_space_data_dir(config_home.path());
    let endpoint_path = space_data_dir.join(".endpoint");
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline && !endpoint_path.exists() {
        thread::sleep(Duration::from_millis(150));
    }
    assert!(
        endpoint_path.exists(),
        "daemon didn't write endpoint within 30s\n--- log ---\n{}",
        fs::read_to_string(&log_path).unwrap_or_default(),
    );

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

fn run_cli(daemon: &Daemon, args: &[&str], what: &str) -> String {
    let out = Command::new(vosx_bin())
        .args(args)
        .env("XDG_DATA_HOME", daemon.data_home.path())
        .env("XDG_CONFIG_HOME", daemon.config_home.path())
        .env("XDG_CACHE_HOME", daemon.cache_home.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .unwrap_or_else(|e| panic!("spawn vosx {args:?}: {e}"));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "{what} failed\nargs: {args:?}\nstdout: {stdout}\nstderr: {}\n--- daemon log ---\n{}",
        String::from_utf8_lossy(&out.stderr),
        daemon.log_tail()
    );
    stdout
}

/// Invoke one messenger instance's verb:
/// `vosx <instance> <verb> --space <space> <args…>`.
fn msgr(daemon: &Daemon, instance: &str, verb_and_args: &[&str], what: &str) -> String {
    let mut args = vec![instance];
    args.extend_from_slice(&verb_and_args[..1]);
    args.extend_from_slice(&["--space", SPACE_NAME]);
    args.extend_from_slice(&verb_and_args[1..]);
    run_cli(daemon, &args, what)
}

/// Poll one instance's verb until `pred` accepts its stdout.
fn wait_for(
    daemon: &Daemon,
    instance: &str,
    verb_and_args: &[&str],
    what: &str,
    pred: impl Fn(&str) -> bool,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut last = String::new();
    while Instant::now() < deadline {
        last = msgr(daemon, instance, verb_and_args, what);
        if pred(&last) {
            return last;
        }
        thread::sleep(Duration::from_millis(400));
    }
    panic!(
        "{what}: condition not met within 45s\nlast output:\n{last}\n--- daemon log ---\n{}",
        daemon.log_tail()
    );
}

/// Extract the hex KeyPackage from a `key_package` reply.
fn kp_hex(out: &str) -> String {
    out.split(|c: char| !c.is_ascii_hexdigit())
        .max_by_key(|run| run.len())
        .filter(|run| run.len() > 64)
        .unwrap_or_else(|| panic!("key_package should print hex; got:\n{out}"))
        .to_string()
}

// ── Raw chain reader (libp2p dial, pages msg-ctl.commits) ────────────

#[derive(serde::Deserialize)]
struct Endpoint {
    peer_id: String,
    multiaddrs: Vec<String>,
    prefix: u16,
    #[allow(dead_code)]
    pid: u32,
}

fn read_chain(daemon: &Daemon) -> Vec<msg_ctl::CommitRow> {
    let data_dir = daemon.data_dir();
    let raw = fs::read_to_string(data_dir.join(".endpoint")).expect("read endpoint");
    let ep: Endpoint = toml::from_str(&raw).expect("parse endpoint");
    let bootstrap_str = format!(
        "{}/p2p/{}",
        ep.multiaddrs.first().expect("at least one multiaddr"),
        ep.peer_id,
    );
    let bootstrap = Multiaddr::from_str(&bootstrap_str).expect("parse daemon multiaddr");
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = libp2p::PeerId::from(keypair.public());

    // `commits` is a private `msg-*` read: the dispatch layer refuses it
    // for a non-member peer (the membership gate). Grant this raw
    // chain-reader the read tier first, the way a real operator would.
    run_cli(
        daemon,
        &[
            "space",
            "role",
            SPACE_NAME,
            "grant",
            &peer_id.to_string(),
            "read",
        ],
        "grant raw chain-reader the read tier",
    );

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
    while Instant::now() < deadline && net_arc.peer_for_prefix(ep.prefix).is_none() {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        net_arc.peer_for_prefix(ep.prefix).is_some(),
        "couldn't reach daemon at prefix {:#06x} within 10s",
        ep.prefix,
    );

    let raw_id: [u8; 2] = vos::crypto::blake2b_hash(
        b"vos-instance-svc-id/v1",
        &[&[0u8], "msg-general-ctl".as_bytes()],
    );
    let local = (u16::from_le_bytes(raw_id) & 0x7FFF).max(0x100);
    let target = ServiceId(((ep.prefix as u32) << 16) | (local as u32));

    let msg = Msg::new("commits")
        .with("from_epoch", 0u64)
        .with("limit", 16u64);
    let mut payload = Vec::with_capacity(1 + 64);
    payload.push(TAG_DYNAMIC);
    payload.extend_from_slice(&msg.encode());
    let reply = node
        .invoke_with_timeout(target, payload, Duration::from_secs(30))
        .expect("daemon didn't reply to raw commits");
    let value = <Value as Decode>::decode(&reply);
    let inner = match value {
        Value::Bytes(b) => b,
        Value::Unit => Vec::new(),
        other => panic!("unexpected raw commits reply: {other:?}"),
    };
    let rows = if inner.is_empty() {
        Vec::new()
    } else {
        <Vec<msg_ctl::CommitRow> as Decode>::try_decode(&inner).expect("decode commits page")
    };
    node.shutdown();
    let _ = node.collect();
    rows
}

// ── The test ─────────────────────────────────────────────────────────

const POST_RACE_TEXT: &str = "post-race: the chain converged on one history";

#[test]
fn stale_committer_retries_through_production_catch_up() {
    ensure_built();
    let d = boot_daemon();

    // All four identities; the chain participants watch nothing yet.
    for (instance, nick) in [
        (ALICE, "alice"),
        (BOB, "bob"),
        (CAROL, "carol"),
        (DAVE, "dave"),
    ] {
        let out = msgr(
            &d,
            instance,
            &["register", &format!("nickname={nick}")],
            "register",
        );
        assert!(out.contains("registered"), "{instance} register: {out}");
    }

    msgr(&d, ALICE, &["create", "channel=general"], "alice create");

    // Alice invites bob by name — the chain's first commit (epoch 0).
    // The directory claim and the first commit race the raft groups'
    // solo elections + the channel agents' spawn window, so poll.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let out = msgr(
            &d,
            ALICE,
            &["invite", "channel=general", "member=bob"],
            "alice invites bob",
        );
        if out.contains("invited") {
            assert!(
                out.contains("epoch 1"),
                "first invite should land at chain epoch 0 → group epoch 1: {out}"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "alice's invite never succeeded: {out}"
        );
        thread::sleep(Duration::from_millis(400));
    }

    // Bob joins: watch the channel, then explicit syncs pick the
    // Welcome off the chain. No background tick exists to race.
    msgr(&d, BOB, &["join", "channel=general"], "bob join");
    {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            msgr(&d, BOB, &["sync"], "bob sync to join");
            let status = msgr(&d, BOB, &["status"], "bob status");
            if status.contains("joined") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "bob never joined after syncs: {status}"
            );
            thread::sleep(Duration::from_millis(300));
        }
    }

    // Alice advances the chain WITHOUT bob noticing: carol's
    // out-of-band KeyPackage becomes the epoch-1 commit.
    let carol_kp = kp_hex(&msgr(&d, CAROL, &["key_package"], "carol key_package"));
    let out = msgr(
        &d,
        ALICE,
        &["invite", "channel=general", &format!("member={carol_kp}")],
        "alice invites carol",
    );
    assert!(
        out.contains("invited") && out.contains("epoch 2"),
        "carol's invite should land at chain epoch 1 → group epoch 2: {out}"
    );

    // Bob — stale at group epoch 1 — invites dave. His commit
    // submits at the taken epoch; msg-ctl refuses with
    // STATUS_EPOCH_TAKEN; commit_chain_op's catch-up branch drains
    // the chain (applying carol's add) and resubmits at the real
    // head. THE assertion of this test: the production retry path,
    // not a hand-rolled simulation, converges the race.
    let dave_kp = kp_hex(&msgr(&d, DAVE, &["key_package"], "dave key_package"));
    let out = msgr(
        &d,
        BOB,
        &["invite", "channel=general", &format!("member={dave_kp}")],
        "bob invites dave from a stale epoch",
    );
    assert!(
        out.contains("invited") && out.contains("epoch 3"),
        "bob's stale invite must retry through the catch-up and land \
         at chain epoch 2 → group epoch 3: {out}"
    );

    // The chain holds exactly the three winning commits, in order,
    // each carrying a welcome (all three were Adds).
    let chain = read_chain(&d);
    assert_eq!(
        chain.len(),
        3,
        "chain should hold exactly 3 commits (bob, carol, dave): {chain:#?}"
    );
    for (i, row) in chain.iter().enumerate() {
        assert_eq!(row.epoch, i as u64, "chain epochs must be contiguous");
        assert!(!row.welcome.is_empty(), "every Add carries a welcome");
    }

    // Both sides converge on the post-race history.
    msgr(&d, ALICE, &["sync"], "alice syncs the race aftermath");
    msgr(
        &d,
        ALICE,
        &["send", "channel=general", &format!("text={POST_RACE_TEXT}")],
        "alice sends post-race",
    );
    msgr(&d, BOB, &["sync"], "bob syncs the message");
    let history = msgr(
        &d,
        BOB,
        &["history", "channel=general", "limit=20"],
        "bob history",
    );
    assert!(
        history.contains(POST_RACE_TEXT),
        "bob must decrypt alice's post-race message:\n{history}"
    );
}
