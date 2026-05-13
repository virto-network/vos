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
