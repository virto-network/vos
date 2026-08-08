//! Onboarding end-to-end: `space up <token>` join + redeem + sync.
//!
//! The point of the whole onboarding plan: getting a second node into a
//! space is one command with one argument. This test drives the real
//! two-daemon path with the bundled registry (no riscv actor build
//! needed):
//!
//!   host A: `space new` → `space up` → `space invite --role member`
//!   host B: `space up <token>`  (join-if-needed + auto-redeem)
//!
//! and asserts the two properties that make the wave work:
//!
//! 1. B's redeem loop reaches A and A records the redemption — A's
//!    `space members` grows an `# invites` section (an InviteRow is
//!    written only by the `redeem_invite` handler, so its mere presence
//!    proves the delegated-grant chain verified on A).
//! 2. B syncs A's registry — which now serves at the MEMBER floor
//!    (decision 9). B started with an empty registry, so the genesis
//!    ADMIN grant showing up in B's `space role list` can only have
//!    arrived by a Member-gated `FetchHeads` that A served *because* the
//!    redemption granted B's node key. This is the bootstrap the flip
//!    depends on: redeem-first (ungated invoke) → grant → sync.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};
use std::{fs, thread};

fn vosx_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vosx"))
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        p.push(format!(
            "vosx-onb-{}-{}-{}",
            std::process::id(),
            label,
            nanos
        ));
        fs::create_dir_all(&p).expect("create tmpdir");
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

/// A running daemon; SIGKILLed on drop so a failed assertion doesn't
/// leak the process.
struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn find_endpoint(root: &Path) -> Option<PathBuf> {
    for entry in fs::read_dir(root).ok()?.flatten() {
        let p = entry.path();
        if p.is_dir()
            && let Some(found) = find_endpoint(&p)
        {
            return Some(found);
        } else if p.file_name().and_then(|f| f.to_str()) == Some(".endpoint") {
            return Some(p);
        }
    }
    None
}

/// Run a one-shot `vosx` client command against a config/data home.
fn vosx(data_home: &Path, config_home: &Path, args: &[&str]) -> Output {
    Command::new(vosx_bin())
        .args(args)
        .env("XDG_DATA_HOME", data_home)
        .env("XDG_CONFIG_HOME", config_home)
        .env("VOSX_DISABLE_MDNS", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run vosx")
}

/// Spawn a long-running `space up <arg>` daemon, logging to a file.
fn spawn_up(data_home: &Path, config_home: &Path, arg: &str, log_path: &Path) -> Child {
    spawn_up_with_service(data_home, config_home, arg, log_path, None)
}

fn spawn_up_with_service(
    data_home: &Path,
    config_home: &Path,
    arg: &str,
    log_path: &Path,
    service_pvm: Option<&Path>,
) -> Child {
    let log_file = fs::File::create(log_path).expect("create log");
    let mut command = Command::new(vosx_bin());
    command.args(["space", "up", arg]);
    if let Some(path) = service_pvm {
        command.arg("--service-pvm").arg(path);
    }
    command
        .env("XDG_DATA_HOME", data_home)
        .env("XDG_CONFIG_HOME", config_home)
        .env("RUST_LOG", "info")
        .env("VOSX_DISABLE_MDNS", "1")
        .env("NO_COLOR", "1")
        .stdout(Stdio::null())
        .stderr(log_file)
        .spawn()
        .expect("spawn vosx space up")
}

fn counter_package_fixture(output_dir: &Path) -> PathBuf {
    let actor_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../examples/actors/target/riscv64em-javm/release/v2_counter.elf");
    assert!(
        actor_elf.is_file(),
        "build the public counter first: `just build-examples` ({})",
        actor_elf.display(),
    );
    let build_data = output_dir.join("build-data");
    let build_config = output_dir.join("build-config");
    let actor = actor_elf.to_string_lossy().into_owned();
    let out = output_dir.to_string_lossy().into_owned();
    vosx_ok(
        &build_data,
        &build_config,
        &[
            "build",
            &actor,
            "--name",
            "onboarding-counter",
            "--version",
            "0.1.0",
            "--out-dir",
            &out,
        ],
    );
    let package = output_dir.join("onboarding-counter.vos");
    assert!(package.is_file(), "vosx build must emit the signed package");
    package
}

fn wait_for_endpoint(data_home: &Path, log_path: &Path, who: &str) -> PathBuf {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(p) = find_endpoint(data_home) {
            return p;
        }
        if Instant::now() >= deadline {
            panic!(
                "daemon {who} didn't write an endpoint within 15s — log:\n{}",
                fs::read_to_string(log_path).unwrap_or_default(),
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Poll `f` until it returns true or the deadline elapses; panic with
/// `msg` (and the daemon logs) on timeout.
fn poll_until(secs: u64, mut f: impl FnMut() -> bool, on_fail: impl FnOnce() -> String) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if f() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("{}", on_fail());
        }
        thread::sleep(Duration::from_millis(250));
    }
}

#[test]
fn onboarding_via_token_redeems_syncs_spawns_and_reattaches() {
    let space = "onb";
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let service_pvm = workspace.join("services/vos-service/vos-service.pvm");
    assert!(
        service_pvm.is_file(),
        "build the canonical service first: `just build-vos-service`",
    );
    let artifacts = TempDir::new("onb-artifacts");
    let counter_package = counter_package_fixture(artifacts.path());
    let data_b = TempDir::new("b-data");
    let cfg_b = TempDir::new("b-config");

    // ── host A: create + boot + install a MEMBER-floor v2 actor ────
    let (data_a, cfg_a, _daemon_a, log_a) = boot_admin_with_service(space, Some(&service_pvm));
    vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &[
            "space",
            "publish",
            space,
            "onboarding-counter:0.1.0",
            counter_package.to_str().expect("package path is UTF-8"),
        ],
    );
    vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &[
            "space",
            "install",
            space,
            "onboarding-counter:0.1.0",
            "--name",
            "counter",
            "--consistency",
            "local",
            "--sync",
            "member",
        ],
    );

    // ── host A: mint a member invite (default bootnodes = A's addrs) ─
    let stdout = vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &["space", "invite", space, "--role", "member"],
    );
    let token = stdout
        .lines()
        .next()
        .expect("invite prints the token first")
        .trim()
        .to_string();
    assert!(
        token.starts_with("vos1"),
        "expected a vos1… token, got: {token}"
    );

    // ── host B: literally `space up <token>` — join + redeem + sync ─
    let log_b = data_b.path().join("daemon-b.stderr");
    let daemon_b = Daemon(spawn_up_with_service(
        data_b.path(),
        cfg_b.path(),
        &token,
        &log_b,
        Some(&service_pvm),
    ));
    let endpoint_b = wait_for_endpoint(data_b.path(), &log_b, "B");
    let pending_invite = endpoint_b
        .parent()
        .expect("B endpoint has a space directory")
        .join(".pending-invite.token");

    // (1) Redemption reaches A: an `# invites` section appears in A's
    //     members only once the `redeem_invite` handler records the row.
    poll_until(
        40,
        || {
            let o = vosx(data_a.path(), cfg_a.path(), &["space", "members", space]);
            o.status.success() && String::from_utf8_lossy(&o.stdout).contains("# invites")
        },
        || {
            format!(
                "A never recorded the redemption (no `# invites` in `space members`) — \
                 the redeem loop didn't reach A. B log:\n{}\nA log:\n{}",
                fs::read_to_string(&log_b).unwrap_or_default(),
                fs::read_to_string(&log_a).unwrap_or_default(),
            )
        },
    );

    // (2) B synced A's MEMBER-gated registry: B started empty, so the
    //     genesis ADMIN grant in B's role list arrived only via a
    //     Member-gated FetchHeads A served because the redemption
    //     granted B's node key. This is the flip working.
    poll_until(
        40,
        || {
            let o = vosx(
                data_b.path(),
                cfg_b.path(),
                &["space", "role", space, "list"],
            );
            o.status.success() && String::from_utf8_lossy(&o.stdout).contains("admin")
        },
        || {
            format!(
                "B never synced A's Member-gated registry (no admin grant in B's `space role \
                 list`) — either the redeem didn't grant B's node key, or the Member floor \
                 refused B's sync. B log:\n{}",
                fs::read_to_string(&log_b).unwrap_or_default(),
            )
        },
    );

    poll_until(
        40,
        || !pending_invite.exists(),
        || {
            format!(
                "B's registry grant landed, but canonical authority redemption did not. B log:\n{}",
                fs::read_to_string(&log_b).unwrap_or_default(),
            )
        },
    );

    // (3) B starts the signed Member-floor v2 root and serves a real call.
    // Registry sync alone cannot make this pass: B must fetch the exact
    // package, validate its service pin, open the guest-owned image, and
    // register the root route.
    poll_until(
        40,
        || {
            vosx(
                data_b.path(),
                cfg_b.path(),
                &["space", "call", space, "counter", "value"],
            )
            .status
            .success()
        },
        || {
            format!(
                "a call to the signed v2 counter on B never succeeded. B log:\n{}",
                fs::read_to_string(&log_b).unwrap_or_default(),
            )
        },
    );

    // (5) Bare-restart re-attach: kill B and restart with `space up
    //     <name>` — no token, no manifest. The redemption already
    //     cleared the pending invite secret, so B re-boots from the index + synced
    //     registry + local.toml alone and re-spawns crdt-counter. This is
    //     the standing restart-bug fix under the onboarding flow.
    drop(daemon_b); // SIGKILL B's first daemon
    let restart_at = std::time::SystemTime::now();
    let log_b2 = data_b.path().join("daemon-b2.stderr");
    let _daemon_b2 = Daemon(spawn_up_with_service(
        data_b.path(),
        cfg_b.path(),
        space,
        &log_b2,
        Some(&service_pvm),
    ));
    // Wait for a FRESH endpoint (newer than the kill), past the stale one.
    poll_until(
        20,
        || {
            find_endpoint(data_b.path())
                .and_then(|p| fs::metadata(&p).ok())
                .and_then(|m| m.modified().ok())
                .is_some_and(|mt| mt >= restart_at)
        },
        || {
            format!(
                "B didn't re-attach after a bare restart; log:\n{}",
                fs::read_to_string(&log_b2).unwrap_or_default()
            )
        },
    );
    // Reopen is proven by the actor being reachable again; merely retaining
    // its image on disk would not prove route registration or guest startup.
    poll_until(
        30,
        || {
            vosx(
                data_b.path(),
                cfg_b.path(),
                &["space", "call", space, "counter", "value"],
            )
            .status
            .success()
        },
        || {
            format!(
                "B didn't reopen counter after a bare `space up {space}` restart; log:\n{}",
                fs::read_to_string(&log_b2).unwrap_or_default()
            )
        },
    );
}

#[test]
fn signed_v2_package_runs_and_reopens_through_the_space_daemon() {
    let space = "v2-root";
    let data = TempDir::new("v2-root-data");
    let config = TempDir::new("v2-root-config");
    let dist = TempDir::new("v2-root-dist");
    let upgrade_dist = TempDir::new("v2-root-upgrade-dist");
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let actor_elf = workspace.join("examples/actors/target/riscv64em-javm/release/v2_counter.elf");
    let service_pvm = workspace.join("services/vos-service/vos-service.pvm");
    assert!(
        actor_elf.is_file(),
        "build the v2 daemon actor first: `cd examples/actors && cargo +nightly actor -p v2-counter`",
    );
    assert!(
        service_pvm.is_file(),
        "build the canonical service first: `just build-vos-service`",
    );

    let actor = actor_elf.to_string_lossy().into_owned();
    let out = dist.path().to_string_lossy().into_owned();
    vosx_ok(
        data.path(),
        config.path(),
        &[
            "build",
            &actor,
            "--name",
            "counter",
            "--version",
            "0.1.0",
            "--out-dir",
            &out,
        ],
    );
    let package = dist.path().join("counter.vos");
    assert!(package.is_file(), "vosx build must emit the signed package");
    let upgrade_out = upgrade_dist.path().to_string_lossy().into_owned();
    vosx_ok(
        data.path(),
        config.path(),
        &[
            "build",
            &actor,
            "--name",
            "counter",
            "--version",
            "0.2.0",
            "--out-dir",
            &upgrade_out,
        ],
    );
    let upgrade_package = upgrade_dist.path().join("counter.vos");
    assert!(
        upgrade_package.is_file(),
        "vosx build must emit the upgrade package",
    );

    vosx_ok(data.path(), config.path(), &["space", "new", space]);
    let first_log = data.path().join("v2-root-first.stderr");
    let first = Daemon(spawn_up_with_service(
        data.path(),
        config.path(),
        space,
        &first_log,
        Some(&service_pvm),
    ));
    wait_for_endpoint(data.path(), &first_log, "v2-root-first");

    let package_source = package.to_string_lossy().into_owned();
    vosx_ok(
        data.path(),
        config.path(),
        &["space", "publish", space, "counter:0.1.0", &package_source],
    );
    vosx_ok(
        data.path(),
        config.path(),
        &[
            "space",
            "install",
            space,
            "counter:0.1.0",
            "--consistency",
            "local",
        ],
    );

    poll_until(
        30,
        || {
            let output = vosx(
                data.path(),
                config.path(),
                &["space", "call", space, "counter", "value"],
            );
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "U64(0)"
        },
        || {
            format!(
                "the daemon never attached the installed v2 root service; log:\n{}",
                fs::read_to_string(&first_log).unwrap_or_default(),
            )
        },
    );
    let incremented = vosx_ok(
        data.path(),
        config.path(),
        &["space", "call", space, "counter", "increment", "by=3"],
    );
    assert_eq!(incremented.trim(), "U64(3)");

    let endpoint_path = find_endpoint(data.path()).unwrap();
    let service_data_dir = endpoint_path.parent().unwrap().to_path_buf();
    let endpoint_body = fs::read_to_string(&endpoint_path).unwrap();
    let endpoint: toml::Value = toml::from_str(&endpoint_body).unwrap();
    let prefix = endpoint["prefix"].as_integer().unwrap() as u16;
    let raw_route = format!(
        "0x{:08x}",
        vos::registry::instance_service_id("counter", prefix),
    );
    let raw_value = vosx_ok(
        data.path(),
        config.path(),
        &["space", "call", space, &raw_route, "value"],
    );
    assert_eq!(raw_value.trim(), "U64(3)");

    let described = vosx_ok(
        data.path(),
        config.path(),
        &["space", "call", space, "counter", "describe"],
    );
    assert!(
        described.contains("counter"),
        "reserved host describe must bypass package method lookup: {described}",
    );

    let upgrade_source = upgrade_package.to_string_lossy().into_owned();
    vosx_ok(
        data.path(),
        config.path(),
        &["space", "publish", space, "counter:0.2.0", &upgrade_source],
    );
    let refused_upgrade = vosx(
        data.path(),
        config.path(),
        &["space", "upgrade", space, "counter", "counter:0.2.0"],
    );
    assert!(!refused_upgrade.status.success());
    assert!(
        String::from_utf8_lossy(&refused_upgrade.stderr).contains("guest-owned UpgradeActor"),
        "v2 catalog upgrade must fail before mutating the registry: {}",
        String::from_utf8_lossy(&refused_upgrade.stderr),
    );

    drop(first);
    let restart_at = std::time::SystemTime::now();
    let second_log = data.path().join("v2-root-second.stderr");
    let second = Daemon(spawn_up_with_service(
        data.path(),
        config.path(),
        space,
        &second_log,
        Some(&service_pvm),
    ));
    poll_until(
        20,
        || {
            find_endpoint(data.path())
                .and_then(|path| fs::metadata(path).ok())
                .and_then(|metadata| metadata.modified().ok())
                .is_some_and(|modified| modified >= restart_at)
        },
        || {
            format!(
                "the daemon did not reopen the v2 root service; log:\n{}",
                fs::read_to_string(&second_log).unwrap_or_default(),
            )
        },
    );
    poll_until(
        30,
        || {
            let output = vosx(
                data.path(),
                config.path(),
                &["space", "call", space, "counter", "value"],
            );
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "U64(3)"
        },
        || {
            format!(
                "the reopened v2 service did not retain its committed state; log:\n{}",
                fs::read_to_string(&second_log).unwrap_or_default(),
            )
        },
    );

    let old_image = fs::read_dir(service_data_dir.join("v2-services"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "image")
        })
        .expect("the first installation must own a durable v2 image");

    vosx_ok(
        data.path(),
        config.path(),
        &["space", "call", space, "counter", "stop"],
    );
    vosx_ok(
        data.path(),
        config.path(),
        &["space", "uninstall", space, "counter"],
    );
    let fresh_replication_id = "22".repeat(32);
    vosx_ok(
        data.path(),
        config.path(),
        &[
            "space",
            "install",
            space,
            "counter:0.1.0",
            "--consistency",
            "local",
            "--replication-id",
            &fresh_replication_id,
        ],
    );

    drop(second);
    let reinstall_at = std::time::SystemTime::now();
    let third_log = data.path().join("v2-root-third.stderr");
    let _third = Daemon(spawn_up_with_service(
        data.path(),
        config.path(),
        space,
        &third_log,
        Some(&service_pvm),
    ));
    poll_until(
        20,
        || {
            find_endpoint(data.path())
                .and_then(|path| fs::metadata(path).ok())
                .and_then(|metadata| metadata.modified().ok())
                .is_some_and(|modified| modified >= reinstall_at)
        },
        || {
            format!(
                "the daemon did not open the reinstalled v2 root; log:\n{}",
                fs::read_to_string(&third_log).unwrap_or_default(),
            )
        },
    );
    poll_until(
        30,
        || {
            let output = vosx(
                data.path(),
                config.path(),
                &["space", "call", space, "counter", "value"],
            );
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "U64(0)"
        },
        || {
            format!(
                "the fresh installation inherited old state or failed to start; log:\n{}",
                fs::read_to_string(&third_log).unwrap_or_default(),
            )
        },
    );
    assert!(!old_image.exists(), "deleted installation remained active");
    assert!(
        service_data_dir
            .join("trash")
            .join("v2-services")
            .join(old_image.file_name().unwrap())
            .is_file(),
        "deleted installation image was not moved to recoverable trash",
    );
}

/// Run a `vosx` command and assert it succeeded, returning stdout.
fn vosx_ok(data_home: &Path, config_home: &Path, args: &[&str]) -> String {
    let o = vosx(data_home, config_home, args);
    assert!(
        o.status.success(),
        "`vosx {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&o.stderr),
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// Boot host A (new + up) and install the CRDT counter fixture as a
/// member-floor app agent. Returns (data_a, cfg_a, daemon_a, log_a).
fn boot_admin(space: &str) -> (TempDir, TempDir, Daemon, PathBuf) {
    boot_admin_with_service(space, None)
}

fn boot_admin_with_service(
    space: &str,
    service_pvm: Option<&Path>,
) -> (TempDir, TempDir, Daemon, PathBuf) {
    let data_a = TempDir::new("a-data");
    let cfg_a = TempDir::new("a-config");
    vosx_ok(data_a.path(), cfg_a.path(), &["space", "new", space]);
    let log_a = data_a.path().join("daemon-a.stderr");
    let daemon_a = Daemon(spawn_up_with_service(
        data_a.path(),
        cfg_a.path(),
        space,
        &log_a,
        service_pvm,
    ));
    wait_for_endpoint(data_a.path(), &log_a, "A");
    let counter_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/fixtures/v2/actors/crdt-counter/target/riscv64em-javm/release/crdt_counter_v2.elf");
    assert!(
        counter_elf.is_file(),
        "build the onboarding CRDT fixture first: `just build-v2-registry-fixtures`",
    );
    let counter_source = counter_elf.to_string_lossy().into_owned();
    vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &[
            "space",
            "publish",
            space,
            "crdt-counter:0.1.0",
            &counter_source,
        ],
    );
    vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &[
            "space",
            "install",
            space,
            "crdt-counter:0.1.0",
            "--consistency",
            "crdt",
        ],
    );
    (data_a, cfg_a, daemon_a, log_a)
}

/// A tampered `vos1…` token fails the checksum at parse time, so `space
/// up` errors immediately (no daemon, no partial join).
#[test]
fn tampered_token_fails_parse() {
    let data = TempDir::new("tamper-data");
    let cfg = TempDir::new("tamper-config");
    // A syntactically-`vos1` string with a corrupt body.
    let o = vosx(
        data.path(),
        cfg.path(),
        &["space", "up", "vos1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"],
    );
    assert!(!o.status.success(), "a tampered token must be rejected");
    let err = String::from_utf8_lossy(&o.stderr).to_lowercase();
    assert!(
        err.contains("token") || err.contains("checksum") || err.contains("base58"),
        "error should name the bad token; got: {err}",
    );
}

/// An expired invite is not redeemed (honored on the joiner path), so
/// the joiner stays a non-member — and the Member-gated registry then
/// refuses its sync, so it never learns the catalog. One test, both
/// properties: `--expires` is real AND the Member floor excludes
/// non-members.
#[test]
fn expired_token_not_redeemed_and_non_member_cannot_sync() {
    let space = "exp";
    let (data_a, cfg_a, _da, _la) = boot_admin(space);

    // Mint with a 1-second lifetime, then let it lapse before B boots.
    let stdout = vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &[
            "space",
            "invite",
            space,
            "--role",
            "member",
            "--expires",
            "1",
        ],
    );
    let token = stdout.lines().next().unwrap().trim().to_string();
    thread::sleep(Duration::from_secs(2));

    let data_b = TempDir::new("exp-b-data");
    let cfg_b = TempDir::new("exp-b-config");
    let log_b = data_b.path().join("daemon-b.stderr");
    let _db = Daemon(spawn_up(data_b.path(), cfg_b.path(), &token, &log_b));
    wait_for_endpoint(data_b.path(), &log_b, "B");

    // The daemon recognizes the token as expired and refuses to redeem.
    poll_until(
        20,
        || {
            fs::read_to_string(&log_b)
                .unwrap_or_default()
                .contains("expired")
        },
        || {
            format!(
                "B never logged the token as expired; log:\n{}",
                fs::read_to_string(&log_b).unwrap_or_default()
            )
        },
    );

    // And because it never became a member, the Member-gated registry is
    // never served to it: give sync a generous window, then assert its
    // role list still lacks A's admin grant (it started empty).
    thread::sleep(Duration::from_secs(6));
    let roles = vosx_ok(
        data_b.path(),
        cfg_b.path(),
        &["space", "role", space, "list"],
    );
    assert!(
        !roles.contains("admin"),
        "a non-member must NOT sync the Member-gated registry; got role list:\n{roles}",
    );
}

/// Partition honesty (decision 6): the same token redeemed at two
/// distinct nodes yields two grants, and `space members` flags the
/// double-redemption rather than pretending to have prevented it.
#[test]
fn double_redemption_is_flagged() {
    let space = "dbl";
    let service_pvm =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../services/vos-service/vos-service.pvm");
    assert!(
        service_pvm.is_file(),
        "build the canonical service first: `just build-vos-service`",
    );
    let (data_a, cfg_a, _da, _la) = boot_admin_with_service(space, Some(&service_pvm));
    let stdout = vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &["space", "invite", space, "--role", "member"],
    );
    let token = stdout.lines().next().unwrap().trim().to_string();

    // Two joiners redeem the SAME token (both dial A; they never connect
    // to each other — VOSX_DISABLE_MDNS and no cross --connect).
    let data_b = TempDir::new("dbl-b-data");
    let cfg_b = TempDir::new("dbl-b-config");
    let log_b = data_b.path().join("b.stderr");
    let _db = Daemon(spawn_up_with_service(
        data_b.path(),
        cfg_b.path(),
        &token,
        &log_b,
        Some(&service_pvm),
    ));
    let endpoint_b = wait_for_endpoint(data_b.path(), &log_b, "B");
    let pending_b = endpoint_b
        .parent()
        .expect("B endpoint has a space directory")
        .join(".pending-invite.token");

    let data_c = TempDir::new("dbl-c-data");
    let cfg_c = TempDir::new("dbl-c-config");
    let log_c = data_c.path().join("c.stderr");
    let _dc = Daemon(spawn_up_with_service(
        data_c.path(),
        cfg_c.path(),
        &token,
        &log_c,
        Some(&service_pvm),
    ));
    let endpoint_c = wait_for_endpoint(data_c.path(), &log_c, "C");
    let pending_c = endpoint_c
        .parent()
        .expect("C endpoint has a space directory")
        .join(".pending-invite.token");

    // A records BOTH redemptions on the one InviteRow → members flags it.
    poll_until(
        40,
        || {
            let m = vosx_ok(data_a.path(), cfg_a.path(), &["space", "members", space]);
            m.contains("double-redeemed")
        },
        || {
            format!(
                "A never flagged the double-redemption. members:\n{}\nB log:\n{}\nC log:\n{}",
                vosx_ok(data_a.path(), cfg_a.path(), &["space", "members", space]),
                fs::read_to_string(&log_b).unwrap_or_default(),
                fs::read_to_string(&log_c).unwrap_or_default(),
            )
        },
    );

    // Registry acceptance is only the first half of v2 onboarding. The
    // daemon removes the bearer secret only after the canonical authority PVM
    // accepts the same evidence through physical guest Accumulate.
    poll_until(
        30,
        || !pending_b.exists() && !pending_c.exists(),
        || {
            format!(
                "one or both joiners never committed invite redemption to space-authority \
                 (pending B={}, C={}). B log:\n{}\nC log:\n{}",
                pending_b.exists(),
                pending_c.exists(),
                fs::read_to_string(&log_b).unwrap_or_default(),
                fs::read_to_string(&log_c).unwrap_or_default(),
            )
        },
    );
}
