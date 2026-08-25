//! The space daemon exits cleanly on SIGTERM.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use std::{fs, thread};

fn vosx_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vosx"))
}

fn find_endpoint(root: &Path) -> Option<PathBuf> {
    for entry in fs::read_dir(root).ok()?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find_endpoint(&path) {
                return Some(found);
            }
        } else if path.file_name().and_then(|name| name.to_str()) == Some(".endpoint") {
            return Some(path);
        }
    }
    None
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "vosx-shutdown-{}-{label}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&path).expect("create temporary directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if !thread::panicking() {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

#[test]
fn space_up_exits_cleanly_on_sigterm() {
    let data_home = TempDir::new("data");
    let config_home = TempDir::new("config");
    let space_name = "shutdown-smoke";

    let created = Command::new(vosx_bin())
        .args(["space", "new", space_name])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("create space");
    assert!(
        created.status.success(),
        "space creation failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );

    let log_path = data_home.path().join("daemon.stderr");
    let log_file = fs::File::create(&log_path).expect("create daemon log");
    let mut child: Child = Command::new(vosx_bin())
        .args(["space", "up", space_name])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .stdout(Stdio::null())
        .stderr(log_file)
        .spawn()
        .expect("start space daemon");

    let endpoint_deadline = Instant::now() + Duration::from_secs(10);
    let endpoint = loop {
        if let Some(path) = find_endpoint(data_home.path()) {
            break path;
        }
        if Instant::now() >= endpoint_deadline {
            panic!(
                "daemon did not publish an endpoint: {}",
                fs::read_to_string(&log_path).unwrap_or_default()
            );
        }
        thread::sleep(Duration::from_millis(100));
    };

    // SAFETY: `child` is the live process created immediately above.
    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    let exit_deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        match child.try_wait().expect("poll daemon") {
            Some(status) => break status,
            None if Instant::now() < exit_deadline => thread::sleep(Duration::from_millis(50)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("daemon did not stop after SIGTERM");
            }
        }
    };
    assert!(status.success(), "daemon exited with {status}");
    assert!(!endpoint.exists(), "daemon left its endpoint behind");
}
