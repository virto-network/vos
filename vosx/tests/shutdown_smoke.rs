//! `vosx space up` exits cleanly on SIGTERM.
//!
//! Regression for Sprint 1 / C8 — without a signal handler the
//! daemon ignored SIGTERM and the supervisor had to escalate to
//! SIGKILL, losing in-flight commits + leaking the endpoint file.
//! The handler installed in `vosx::shutdown::install` flips the
//! same `AtomicBool` that `node.run_forever` polls every 50 ms,
//! so the daemon returns from `space up` cleanly.
//!
//! Smoke test:
//!
//! 1. `vosx space new` + `vosx space up` in a tmp XDG home.
//! 2. Wait for the endpoint file (≤ 10 s).
//! 3. Send SIGTERM.
//! 4. Assert the daemon exits within 5 s with status 0 and that
//!    it removed its own endpoint file.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use std::{fs, thread};

fn vosx_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vosx"))
}

/// Recursively look for `.endpoint` under the XDG_DATA_HOME root.
/// The exact path includes the space id (assigned at `space new`)
/// which the test harness doesn't track explicitly.
fn find_endpoint(root: &Path) -> Option<PathBuf> {
    for entry in fs::read_dir(root).ok()?.flatten() {
        let p = entry.path();
        if p.is_dir() {
            if let Some(found) = find_endpoint(&p) {
                return Some(found);
            }
        } else if p.file_name().and_then(|f| f.to_str()) == Some(".endpoint") {
            return Some(p);
        }
    }
    None
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
            "vosx-shutdown-{}-{}-{}",
            std::process::id(),
            label,
            nanos,
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

#[cfg(unix)]
#[test]
fn space_up_exits_cleanly_on_sigterm() {
    let data_home = TempDir::new("data");
    let config_home = TempDir::new("config");
    let space_name = "shutdown-smoke";

    let new = Command::new(vosx_bin())
        .args(["space", "new", space_name])
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

    let log_path = data_home.path().join("daemon.stderr");
    let log_file = fs::File::create(&log_path).expect("create log");
    let mut child: Child = Command::new(vosx_bin())
        .args(["space", "up", space_name])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("RUST_LOG", "info")
        .env("VOSX_DISABLE_MDNS", "1")
        .stdout(Stdio::null())
        .stderr(log_file)
        .spawn()
        .expect("spawn vosx space up");

    // vosx writes the endpoint under
    // `$XDG_DATA_HOME/vosx/<space-id-hex>/.endpoint`. The id is
    // assigned at `space new` time; we don't know it up front,
    // so walk the tree for `.endpoint`.
    let endpoint_deadline = Instant::now() + Duration::from_secs(10);
    let endpoint = loop {
        if let Some(p) = find_endpoint(data_home.path()) {
            break p;
        }
        if Instant::now() >= endpoint_deadline {
            panic!(
                "daemon didn't write endpoint within 10s — log:\n{}",
                fs::read_to_string(&log_path).unwrap_or_default(),
            );
        }
        thread::sleep(Duration::from_millis(100));
    };

    // SIGTERM — the production "docker stop" / k8s preStop signal.
    let pid = child.id() as libc::pid_t;
    // SAFETY: libc::kill takes only scalar args; child is a live
    // process we just spawned.
    let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(
        rc,
        0,
        "kill(SIGTERM, {pid}): {}",
        std::io::Error::last_os_error()
    );

    // Daemon should exit within 5s. The 50ms poll inside
    // run_forever means the actual latency is much smaller, but
    // give the agent threads room to flush their inboxes.
    let exit_deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() < exit_deadline => {
                thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "daemon didn't exit within 5s of SIGTERM — \
                     graceful shutdown handler is broken.\nLog tail:\n{}",
                    fs::read_to_string(&log_path).unwrap_or_default(),
                );
            }
            Err(e) => panic!("try_wait error: {e}"),
        }
    };

    assert!(
        status.success(),
        "daemon exited non-zero on SIGTERM: status={status:?}; log:\n{}",
        fs::read_to_string(&log_path).unwrap_or_default(),
    );

    // The daemon's own cleanup removes the endpoint file. If it
    // doesn't, the next `vosx space up` will see a stale endpoint
    // and confuse client commands.
    assert!(
        !endpoint.exists(),
        "endpoint file leaked across SIGTERM exit (was at {})",
        endpoint.display(),
    );
}

#[cfg(unix)]
fn spawn_daemon(data_home: &Path, config_home: &Path, space_name: &str, log_path: &Path) -> Child {
    let log_file = fs::File::create(log_path).expect("create log");
    Command::new(vosx_bin())
        .args(["space", "up", space_name])
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

#[cfg(unix)]
fn wait_for_endpoint(data_home: &Path, log_path: &Path) -> PathBuf {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(p) = find_endpoint(data_home) {
            return p;
        }
        if Instant::now() >= deadline {
            panic!(
                "daemon didn't write endpoint within 10s — log:\n{}",
                fs::read_to_string(log_path).unwrap_or_default(),
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Sprint 5: SIGKILL bypasses the graceful shutdown handler and
/// any in-process cleanup the daemon would otherwise run. The
/// auth_grants the operator wrote BEFORE the kill must still be
/// in redb when the daemon restarts — that's the durability
/// contract redb gives us per committed transaction. If a
/// regression batches grant writes into an in-memory buffer
/// flushed only at shutdown, this test catches it; today's
/// `shutdown_smoke` only verifies the SIGTERM path.
#[cfg(unix)]
#[test]
fn space_survives_kill9_restart_with_state_intact() {
    let data_home = TempDir::new("kill9-data");
    let config_home = TempDir::new("kill9-config");
    let space_name = "kill9-smoke";

    // 1. Create + boot daemon A.
    let new = Command::new(vosx_bin())
        .args(["space", "new", space_name])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("spawn vosx space new");
    assert!(
        new.status.success(),
        "vosx space new failed: stderr={}",
        String::from_utf8_lossy(&new.stderr),
    );

    let log_a = data_home.path().join("daemon-a.stderr");
    let mut child_a = spawn_daemon(data_home.path(), config_home.path(), space_name, &log_a);
    let endpoint = wait_for_endpoint(data_home.path(), &log_a);

    // 2. Mutate state: grant a synthetic peer the `developer`
    //    role. The registry doesn't verify peer existence on
    //    grant — only that the caller (us, the bootstrap admin)
    //    has admin. This is the same trick auth_smoke.rs uses.
    let synthetic = "12D3KooWAfBVdmphtMFPVq3GVRkubsbjY7d4kkpEFG1cd6CSC95N";
    let grant = Command::new(vosx_bin())
        .args(["space", "role", space_name, "grant", synthetic, "developer"])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("spawn role grant");
    assert!(
        grant.status.success(),
        "bootstrap admin grant should succeed; stderr={}",
        String::from_utf8_lossy(&grant.stderr),
    );

    // 3. Sanity: the grant is visible to the running daemon.
    let list_pre = Command::new(vosx_bin())
        .args(["space", "role", space_name, "list"])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("spawn role list (pre)");
    assert!(list_pre.status.success());
    let pre_stdout = String::from_utf8_lossy(&list_pre.stdout);
    assert!(
        pre_stdout.contains(synthetic) && pre_stdout.contains("developer"),
        "grant must be visible BEFORE the kill; got:\n{pre_stdout}",
    );

    // 4. SIGKILL — bypasses the graceful handler entirely. No
    //    endpoint cleanup, no journal flush opportunity beyond
    //    what redb has already persisted on commit.
    let pid = child_a.id() as libc::pid_t;
    let kill_time = std::time::SystemTime::now();
    let rc = unsafe { libc::kill(pid, libc::SIGKILL) };
    assert_eq!(
        rc,
        0,
        "kill(SIGKILL, {pid}): {}",
        std::io::Error::last_os_error(),
    );
    let _ = child_a.wait();
    // Endpoint file is stale; auto-cleanup at next `space up`
    // is part of the contract.
    assert!(
        endpoint.exists(),
        "endpoint file should still exist after SIGKILL (no cleanup ran)",
    );

    // 5. Restart. `space up` should detect the stale endpoint,
    //    clean it up, and re-open the redb. The auth_grants row
    //    must replay from disk. Poll for an endpoint *newer*
    //    than the kill time so we don't race on the stale one
    //    daemon A left behind.
    let log_b = data_home.path().join("daemon-b.stderr");
    let mut child_b = spawn_daemon(data_home.path(), config_home.path(), space_name, &log_b);
    let restart_deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(p) = find_endpoint(data_home.path())
            && let Ok(meta) = fs::metadata(&p)
            && let Ok(mtime) = meta.modified()
            && mtime > kill_time
        {
            break;
        }
        if Instant::now() >= restart_deadline {
            let _ = child_b.kill();
            let _ = child_b.wait();
            panic!(
                "daemon B didn't write a fresh endpoint within 15s — log:\n{}",
                fs::read_to_string(&log_b).unwrap_or_default(),
            );
        }
        thread::sleep(Duration::from_millis(100));
    }

    // 6. State integrity: the grant from step 2 MUST still be
    //    there. This is the redb-durability + auth_grants-replay
    //    invariant; a regression that buffers grants in RAM until
    //    shutdown would fail here.
    let list_post = Command::new(vosx_bin())
        .args(["space", "role", space_name, "list"])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("spawn role list (post)");
    assert!(
        list_post.status.success(),
        "role list after kill-9 + restart failed: stderr={}",
        String::from_utf8_lossy(&list_post.stderr),
    );
    let post_stdout = String::from_utf8_lossy(&list_post.stdout);
    assert!(
        post_stdout.contains(synthetic),
        "auth_grants entry for synthetic peer MUST survive SIGKILL + restart; \
         stdout after restart:\n{post_stdout}",
    );
    assert!(
        post_stdout.contains("developer"),
        "role label MUST survive (not just the peer row); got:\n{post_stdout}",
    );
    // Bootstrap admin must also still be there.
    assert!(
        post_stdout.contains("admin"),
        "bootstrap admin row should also survive; got:\n{post_stdout}",
    );

    // Cleanup.
    let _ = child_b.kill();
    let _ = child_b.wait();
}
