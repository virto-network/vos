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
    let log_file = fs::File::create(log_path).expect("create log");
    Command::new(vosx_bin())
        .args(["space", "up", arg])
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
    let data_b = TempDir::new("b-data");
    let cfg_b = TempDir::new("b-config");

    // ── host A: create + boot + install a MEMBER-floor app agent ───
    // (bundled dev-project) so B has something to spawn once it is a
    // member. Its sync floor defaults to `member`, so a node judged
    // non-member would narrow it out — exercising node_is_member's
    // node-key grant path.
    let (data_a, cfg_a, _daemon_a, log_a) = boot_admin(space);

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
    let daemon_b = Daemon(spawn_up(data_b.path(), cfg_b.path(), &token, &log_b));
    wait_for_endpoint(data_b.path(), &log_b, "B");

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

    // (3) B SPAWNS the Member-floor agent: node_is_member must recognize
    //     B's redeemed node-key grant, else node_meets_floor narrows
    //     dev-project out and B logs "not spawned … sync floor is above".
    //     A spawned agent opens its own per-node redb, so a redb in B's
    //     agents dir other than the registry's (00000000.redb) is the
    //     spawn signal — sync alone (the row) would not create it.
    let agents_dir = find_endpoint(data_b.path())
        .and_then(|ep| ep.parent().map(|p| p.join("agents")))
        .expect("B has a space data dir");
    poll_until(
        40,
        || spawned_app_agent(&agents_dir),
        || {
            format!(
                "B synced dev-project's row but never SPAWNED it — node_is_member likely still \
                 ignores the redeemed node-key grant, so node_meets_floor narrowed the Member \
                 agent out. B log:\n{}",
                fs::read_to_string(&log_b).unwrap_or_default(),
            )
        },
    );

    // (4) The spawned agent is live + reachable on B — a real call
    //     (list_branches, a no-arg read) returns rather than erroring.
    poll_until(
        30,
        || {
            vosx(data_b.path(), cfg_b.path(), &["space", "call", space, "dev-project", "list_branches"])
                .status
                .success()
        },
        || {
            format!(
                "a call to the spawned dev-project on B never succeeded. B log:\n{}",
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
    let _daemon_b2 = Daemon(spawn_up(data_b.path(), cfg_b.path(), space, &log_b2));
    // Wait for a FRESH endpoint (newer than the kill), past the stale one.
    poll_until(
        20,
        || {
            find_endpoint(data_b.path())
                .and_then(|p| fs::metadata(&p).ok())
                .and_then(|m| m.modified().ok())
                .is_some_and(|mt| mt >= restart_at)
        },
        || format!("B didn't re-attach after a bare restart; log:\n{}", fs::read_to_string(&log_b2).unwrap_or_default()),
    );
    // Re-spawn is proven by the agent being reachable again (the redb
    // file persists on disk regardless, so its presence proves nothing);
    // a successful call means B re-registered dev-project from the cached
    // registry row + blob with no token/manifest in play.
    poll_until(
        30,
        || {
            vosx(data_b.path(), cfg_b.path(), &["space", "call", space, "dev-project", "list_branches"])
                .status
                .success()
        },
        || format!("B didn't re-spawn dev-project after a bare `space up {space}` restart; log:\n{}", fs::read_to_string(&log_b2).unwrap_or_default()),
    );
}

/// True once B's agents dir holds a per-agent redb other than the
/// registry's `00000000.redb` — i.e. an app agent actually spawned.
fn spawned_app_agent(agents_dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(agents_dir) else {
        return false;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".redb") && name != "00000000.redb" {
            return true;
        }
    }
    false
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

/// Boot host A (new + up) and install the bundled dev-project as a
/// member-floor app agent. Returns (data_a, cfg_a, daemon_a, log_a).
fn boot_admin(space: &str) -> (TempDir, TempDir, Daemon, PathBuf) {
    let data_a = TempDir::new("a-data");
    let cfg_a = TempDir::new("a-config");
    vosx_ok(data_a.path(), cfg_a.path(), &["space", "new", space]);
    let log_a = data_a.path().join("daemon-a.stderr");
    let daemon_a = Daemon(spawn_up(data_a.path(), cfg_a.path(), space, &log_a));
    wait_for_endpoint(data_a.path(), &log_a, "A");
    vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &["space", "publish", space, "--bundled", "dev-project"],
    );
    vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &["space", "install", space, "dev-project:0.1.0"],
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

/// Partition honesty (decision 6): the same token redeemed at two
/// distinct nodes yields two grants, and `space members` flags the
/// double-redemption rather than pretending to have prevented it.
#[test]
fn double_redemption_is_flagged() {
    let space = "dbl";
    let (data_a, cfg_a, _da, _la) = boot_admin(space);
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
    let _db = Daemon(spawn_up(data_b.path(), cfg_b.path(), &token, &log_b));
    wait_for_endpoint(data_b.path(), &log_b, "B");

    let data_c = TempDir::new("dbl-c-data");
    let cfg_c = TempDir::new("dbl-c-config");
    let log_c = data_c.path().join("c.stderr");
    let _dc = Daemon(spawn_up(data_c.path(), cfg_c.path(), &token, &log_c));
    wait_for_endpoint(data_c.path(), &log_c, "C");

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
}
