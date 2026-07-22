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
        p.push(format!("vosx-onb-{}-{}-{}", std::process::id(), label, nanos));
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
    if let Some(service_pvm) = service_pvm {
        command.arg("--service-pvm").arg(service_pvm);
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

/// Transpile the exact generic service guest built by `just build-pvm`.
/// Direct `cargo test` runs may not have that target artifact, matching the
/// existing physical-service integration tests: print the prerequisite and
/// let the caller skip instead of silently substituting a synthetic PVM.
fn service_pvm_fixture(output_dir: &Path) -> Option<PathBuf> {
    let elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../services/vos-service/target/riscv64em-javm/release/vos_service.elf");
    if !elf.is_file() {
        eprintln!(
            "skipping: build the generic service with \
             `cd services/vos-service && cargo +nightly actor` ({})",
            elf.display(),
        );
        return None;
    }
    let pvm = output_dir.join("vos-service.pvm");
    let output = Command::new(vosx_bin())
        .arg("service-pvm")
        .arg(&elf)
        .arg("--out")
        .arg(&pvm)
        .env("NO_COLOR", "1")
        .output()
        .expect("transpile canonical service PVM");
    assert!(
        output.status.success(),
        "`vosx service-pvm` failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    Some(pvm)
}

fn counter_package_fixture(output_dir: &Path, service_pvm: &Path) -> Option<PathBuf> {
    let actor_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../examples/actors/target/riscv64em-javm/release/v2_counter.elf");
    if !actor_elf.is_file() {
        eprintln!(
            "skipping: build the public counter with \
             `cd examples/actors && cargo +nightly actor -p v2-counter` ({})",
            actor_elf.display(),
        );
        return None;
    }
    let output = Command::new(vosx_bin())
        .arg("build")
        .arg(&actor_elf)
        .arg("--name")
        .arg("onboarding-counter")
        .arg("--version")
        .arg("acceptance")
        .arg("--service-pvm")
        .arg(service_pvm)
        .arg("--out-dir")
        .arg(output_dir)
        .env("XDG_DATA_HOME", output_dir.join("build-data"))
        .env("XDG_CONFIG_HOME", output_dir.join("build-config"))
        .env("NO_COLOR", "1")
        .output()
        .expect("build signed onboarding package");
    assert!(
        output.status.success(),
        "`vosx build` failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    Some(output_dir.join("onboarding-counter.vos"))
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
    let artifacts = TempDir::new("onb-artifacts");
    let Some(service_pvm) = service_pvm_fixture(artifacts.path()) else {
        return;
    };
    let Some(counter_package) = counter_package_fixture(artifacts.path(), &service_pvm) else {
        return;
    };
    let data_b = TempDir::new("b-data");
    let cfg_b = TempDir::new("b-config");

    // ── host A: create + boot + install a MEMBER-floor v2 actor ────
    // The package is signed and pins the same generic service bytes supplied
    // to every daemon. Nothing is bundled or retranspiled by the registry.
    let (data_a, cfg_a, _daemon_a, log_a) = boot_admin_with_service(space, Some(&service_pvm));
    vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &[
            "space",
            "publish",
            space,
            "onboarding-counter:acceptance",
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
            "onboarding-counter:acceptance",
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
    assert!(token.starts_with("vos1"), "expected a vos1… token, got: {token}");

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
            let o = vosx(data_b.path(), cfg_b.path(), &["space", "role", space, "list"]);
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

    // (3) B SPAWNS the Member-floor actor: node_is_member must recognize
    //     B's redeemed node-key grant, fetch the exact package blob, and
    //     create its guest-owned image. A non-voter correctly routes authority
    //     calls to the Raft leader without hosting an authority image locally.
    let services_dir = endpoint_b
        .parent()
        .expect("B endpoint has a space directory")
        .join("v2-services");
    poll_until(
        40,
        || spawned_v2_application(&services_dir),
        || {
            format!(
                "B synced counter's row but never SPAWNED it — node_is_member likely still \
                 ignores the redeemed node-key grant, so node_meets_floor narrowed the Member \
                 actor out, or the exact package blob was unavailable. B log:\n{}",
                fs::read_to_string(&log_b).unwrap_or_default(),
            )
        },
    );

    // (4) The spawned agent is live + reachable on B — a real call
    //     (`value`, a no-arg read) returns rather than erroring.
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
                "a call to the spawned counter on B never succeeded. B log:\n{}",
                fs::read_to_string(&log_b).unwrap_or_default(),
            )
        },
    );

    // (5) Bare-restart re-attach: kill B and restart with `space up
    //     <name>` — no token, no manifest. The redemption already
    //     cleared the pending invite secret, so B re-boots from the index + synced
    //     registry + local.toml alone and re-spawns dev-project. This is
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
    // Reopen is proven by the actor being reachable again (the service image
    // persists on disk regardless, so its presence proves nothing); a
    // successful call means B re-registered counter from the cached
    // registry row + signed package with no token/manifest in play.
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
                "B didn't re-spawn counter after a bare `space up {space}` restart; log:\n{}",
                fs::read_to_string(&log_b2).unwrap_or_default()
            )
        },
    );
}

/// A local v2 image proves the synchronized application row became a running
/// root-tree service. Joiners are not authority Raft voters by default.
fn spawned_v2_application(services_dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(services_dir) else {
        return false;
    };
    entries
        .flatten()
        .any(|entry| entry.path().extension().is_some_and(|ext| ext == "image"))
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

/// Boot an admin host for invite and membership tests. Application package
/// installation is deliberately separate: v2 has no raw bundled actors.
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
        &["space", "invite", space, "--role", "member", "--expires", "1"],
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
        || fs::read_to_string(&log_b).unwrap_or_default().contains("expired"),
        || format!("B never logged the token as expired; log:\n{}", fs::read_to_string(&log_b).unwrap_or_default()),
    );

    // And because it never became a member, the Member-gated registry is
    // never served to it: give sync a generous window, then assert its
    // role list still lacks A's admin grant (it started empty).
    thread::sleep(Duration::from_secs(6));
    let roles = vosx_ok(data_b.path(), cfg_b.path(), &["space", "role", space, "list"]);
    assert!(
        !roles.contains("admin"),
        "a non-member must NOT sync the Member-gated registry; got role list:\n{roles}",
    );
}

/// A minted token is an offline bearer and therefore has no registry row yet.
/// Revoking by the exact token must pre-create the grow-only revocation row;
/// a later join attempt cannot redeem or cross the Member sync floor.
#[test]
fn unredeemed_token_can_be_revoked_before_join() {
    let space = "rev";
    let (data_a, cfg_a, _da, log_a) = boot_admin(space);
    let stdout = vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &["space", "invite", space, "--role", "member"],
    );
    let token = stdout.lines().next().unwrap().trim().to_string();

    let revoked = vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &["space", "invite", space, "revoke", &token],
    );
    assert!(
        revoked.contains("revoked invite"),
        "the exact offline token should be accepted as a revoke selector: {revoked}",
    );
    let prefix = revoked
        .split_whitespace()
        .nth(2)
        .expect("revoke output contains the token prefix")
        .trim_end_matches('…');
    let repeated = vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &["space", "invite", space, "revoke", prefix],
    );
    assert!(
        repeated.contains("revoked invite"),
        "recorded-prefix revocation remains idempotent: {repeated}",
    );
    let invites = vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &["space", "invite", space, "list"],
    );
    assert!(
        invites.contains("revoked"),
        "revocation must be durable before any redemption:\n{invites}",
    );

    let data_b = TempDir::new("rev-b-data");
    let cfg_b = TempDir::new("rev-b-config");
    let log_b = data_b.path().join("daemon-b.stderr");
    let _db = Daemon(spawn_up(data_b.path(), cfg_b.path(), &token, &log_b));
    wait_for_endpoint(data_b.path(), &log_b, "B");

    // Give the redeem loop and registry anti-entropy multiple passes. The
    // grow-only revoked row must win regardless of arrival order, leaving B
    // without A's genesis Admin row.
    thread::sleep(Duration::from_secs(8));
    let roles = vosx_ok(
        data_b.path(),
        cfg_b.path(),
        &["space", "role", space, "list"],
    );
    assert!(
        !roles.contains("admin"),
        "a revoked invite must not grant Member sync access; got role list:\n{roles}\n\
         B log:\n{}\nA log:\n{}",
        fs::read_to_string(&log_b).unwrap_or_default(),
        fs::read_to_string(&log_a).unwrap_or_default(),
    );
}

/// Partition honesty (decision 6): the same token redeemed at two
/// distinct nodes yields two grants, and `space members` flags the
/// double-redemption rather than pretending to have prevented it.
#[test]
fn double_redemption_is_flagged() {
    let space = "dbl";
    let service_dir = TempDir::new("dbl-service");
    let Some(service_pvm) = service_pvm_fixture(service_dir.path()) else {
        return;
    };
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

    // Legacy registry acceptance is only the first half of v2 onboarding.
    // The daemon removes this bearer secret only after the canonical
    // space-authority PVM accepts the same evidence through physical
    // Accumulate and publishes `Bool(true)`. Require both divergent holders
    // to finish that guest-owned commit, not merely appear in the legacy
    // InviteRow checked above.
    poll_until(
        20,
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
