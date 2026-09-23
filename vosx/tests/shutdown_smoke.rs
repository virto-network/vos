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

// Reap the exact test child on every panic path, including startup timeout.
// Child::drop alone does not stop a still-running daemon.
struct DaemonChild(Child);

impl Drop for DaemonChild {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(Some(_))) {
            return;
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl TempDir {
    fn new(label: &str) -> Self {
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target"));
        let base = target.join("test-tmp");
        fs::create_dir_all(&base).expect("create test scratch directory");
        let path = base.join(format!(
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
    run_shutdown_smoke("shutdown-smoke", false);
}

#[cfg(all(target_os = "linux", feature = "experimental-state-blocks"))]
#[test]
fn external_space_create_and_exact_retry_after_restart() {
    run_shutdown_smoke("external-shutdown-smoke", true);
}

fn run_shutdown_smoke(space_name: &str, external: bool) {
    let data_home = TempDir::new(&format!("{space_name}-data"));
    let config_home = TempDir::new(&format!("{space_name}-config"));
    let cache_home = TempDir::new(&format!("{space_name}-cache"));

    let created = Command::new(vosx_bin())
        .args(["space", "new", space_name, "--format", "json"])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("XDG_CACHE_HOME", cache_home.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("create space");
    assert!(
        created.status.success(),
        "space creation failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );
    let created_space: serde_json::Value =
        serde_json::from_slice(&created.stdout).expect("space creation JSON");
    let space_root = PathBuf::from(created_space["data_dir"].as_str().expect("space data dir"));
    #[cfg(feature = "experimental-state-blocks")]
    let candidate_present =
        !include_bytes!(env!("VOSX_CANDIDATE_SYSTEM_AUTHORITY_PACKAGE")).is_empty();
    #[cfg(not(feature = "experimental-state-blocks"))]
    let candidate_present = false;
    let http_port = if external && candidate_present {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("reserve an isolated HTTP test port");
        listener.local_addr().unwrap().port()
    } else {
        0
    };
    // Exercise both ingress services without competing with the developer's
    // default ports or with another test process.
    let storage = if external {
        "local_agent_storage = \"external-state\"\n"
    } else {
        ""
    };
    fs::write(
        space_root.join("local.toml"),
        format!(
            "{storage}listen = [\"/ip4/127.0.0.1/tcp/0\"]\n\
         [[ingress.http]]\nname = \"http\"\nlisten = \"127.0.0.1:{http_port}\"\n\
         [[ingress.ssh]]\nname = \"ssh\"\nlisten = \"127.0.0.1:0\"\n"
        ),
    )
    .expect("write isolated ingress config");

    #[cfg(feature = "experimental-state-blocks")]
    if external && !candidate_present {
        let refused = Command::new(vosx_bin())
            .args(["space", "up", space_name])
            .env("XDG_DATA_HOME", data_home.path())
            .env("XDG_CONFIG_HOME", config_home.path())
            .env("XDG_CACHE_HOME", cache_home.path())
            .env("VOSX_DISABLE_MDNS", "1")
            .output()
            .expect("attempt startup without checked candidates");
        assert!(!refused.status.success());
        assert!(
            String::from_utf8_lossy(&refused.stderr)
                .contains("both checked experimental artifacts"),
            "unexpected refusal: {}",
            String::from_utf8_lossy(&refused.stderr),
        );
        assert!(!space_root.join("local-agent-external").exists());
        assert!(!space_root.join("local-agent-external-lifecycle").exists());
        return;
    }

    let mut first_create: Option<serde_json::Value> = None;
    for boot in 0..if external { 2 } else { 1 } {
        let log_path = data_home.path().join(format!("daemon-{boot}.stderr"));
        let log_file = fs::File::create(&log_path).expect("create daemon log");
        let daemon_started = Instant::now();
        let mut child = DaemonChild(
            Command::new(vosx_bin())
                .args(["space", "up", space_name])
                .env("XDG_DATA_HOME", data_home.path())
                .env("XDG_CONFIG_HOME", config_home.path())
                .env("XDG_CACHE_HOME", cache_home.path())
                .env("VOSX_DISABLE_MDNS", "1")
                .stdout(Stdio::null())
                .stderr(log_file)
                .spawn()
                .expect("start space daemon"),
        );

        // This is a shutdown/storage-mode smoke, not the startup-latency gate.
        // Both modes run full system-Agent bootstrap before publishing an endpoint.
        let endpoint_deadline = daemon_started + Duration::from_secs(60);
        let endpoint = loop {
            if let Some(path) = find_endpoint(data_home.path()) {
                break path;
            }
            if let Some(status) = child.0.try_wait().expect("poll startup") {
                panic!(
                    "daemon exited before publishing an endpoint ({status}): {}",
                    fs::read_to_string(&log_path).unwrap_or_default()
                );
            }
            if Instant::now() >= endpoint_deadline {
                panic!(
                    "daemon did not publish an endpoint: {}",
                    fs::read_to_string(&log_path).unwrap_or_default()
                );
            }
            thread::sleep(Duration::from_millis(100));
        };
        eprintln!(
            "{space_name} boot {boot} endpoint ready after {} ms",
            daemon_started.elapsed().as_millis()
        );
        if external {
            assert!(space_root.join("local-agent-external").is_dir());
            assert!(space_root.join("local-agent-external-lifecycle").is_dir());
            assert!(!space_root.join("local-agent-host").exists());
            assert!(!space_root.join("local-agent-lifecycle").exists());
            let mut create = Command::new(vosx_bin());
            create.args([
                "space",
                "create-local-agent",
                space_name,
                "--http",
                &format!("127.0.0.1:{http_port}"),
                "--format",
                "json",
            ]);
            if boot == 1 {
                create.arg("--resume");
            }
            let create_started = Instant::now();
            let created = create
                .env("XDG_DATA_HOME", data_home.path())
                .env("XDG_CONFIG_HOME", config_home.path())
                .env("XDG_CACHE_HOME", cache_home.path())
                .env("VOSX_DISABLE_MDNS", "1")
                .env("RUST_LOG", "vosx::commands::space::local_create=debug")
                .output()
                .expect("submit exact external Local Create");
            eprintln!(
                "{space_name} boot {boot} Local Create/retained retry completed after {} ms",
                create_started.elapsed().as_millis(),
            );
            assert!(
                created.status.success(),
                "external Create boot {boot} failed: {}",
                String::from_utf8_lossy(&created.stderr),
            );
            eprintln!("{}", String::from_utf8_lossy(&created.stderr));
            let acknowledgement: serde_json::Value =
                serde_json::from_slice(&created.stdout).expect("external Create JSON");
            assert!(acknowledgement["agent"].is_string());
            if let Some(first) = &first_create {
                assert_eq!(
                    &acknowledgement, first,
                    "restart changed the exact Create ACK"
                );
            } else {
                first_create = Some(acknowledgement);
            }
        }

        // SAFETY: `child` is the live process created immediately above.
        assert_eq!(
            unsafe { libc::kill(child.0.id() as libc::pid_t, libc::SIGTERM) },
            0
        );
        let exit_deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            match child.0.try_wait().expect("poll daemon") {
                Some(status) => break status,
                None if Instant::now() < exit_deadline => thread::sleep(Duration::from_millis(50)),
                None => {
                    let _ = child.0.kill();
                    let _ = child.0.wait();
                    panic!("daemon did not stop after SIGTERM");
                }
            }
        };
        assert!(status.success(), "daemon exited with {status}");
        assert!(!endpoint.exists(), "daemon left its endpoint behind");
    }
}
