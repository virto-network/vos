//! The space daemon exits cleanly on SIGTERM.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
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

#[cfg(all(target_os = "linux", feature = "experimental-state-blocks"))]
fn read_http_head(stream: &mut std::net::TcpStream) -> Vec<u8> {
    use std::io::Read as _;
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 16 * 1024, "HTTP header exceeds test bound");
        let mut byte = [0];
        stream.read_exact(&mut byte).expect("read HTTP header");
        head.push(byte[0]);
    }
    head
}

#[cfg(all(target_os = "linux", feature = "experimental-state-blocks"))]
fn http_content_length(head: &[u8]) -> u64 {
    let head = std::str::from_utf8(head).expect("ASCII HTTP headers");
    head.split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("Content-Length"))
        .map(|(_, value)| value.trim().parse().expect("decimal Content-Length"))
        .expect("bounded HTTP response declares Content-Length")
}

#[cfg(all(target_os = "linux", feature = "experimental-state-blocks"))]
fn relay_then_lose_create_reply(listener: std::net::TcpListener, daemon: std::net::SocketAddr) {
    use std::io::{Read as _, Write as _};
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(90);
    for _ in 0..4 {
        let (mut client, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "Create client never reached proxy"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept Create proxy: {error}"),
            }
        };
        client
            .set_read_timeout(Some(Duration::from_secs(85)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(85)))
            .unwrap();
        let mut upstream = std::net::TcpStream::connect(daemon).expect("connect daemon HTTP");
        upstream
            .set_read_timeout(Some(Duration::from_secs(85)))
            .unwrap();
        upstream
            .set_write_timeout(Some(Duration::from_secs(85)))
            .unwrap();
        let request_head = read_http_head(&mut client);
        let create = request_head.starts_with(b"POST /__agents/local HTTP/1.1\r\n");
        upstream.write_all(&request_head).unwrap();
        let request_len = http_content_length(&request_head);
        assert_eq!(
            std::io::copy(
                &mut std::io::Read::by_ref(&mut client).take(request_len),
                &mut upstream,
            )
            .unwrap(),
            request_len,
            "proxy must forward the complete retained request",
        );
        upstream.flush().unwrap();
        let response_head = read_http_head(&mut upstream);
        if create {
            assert!(
                response_head.starts_with(b"HTTP/1.1 201 "),
                "daemon must commit Create before the reply is lost: {}",
                String::from_utf8_lossy(&response_head),
            );
            // Deliberately give the client no response bytes after the daemon
            // has produced its successful HTTP status.
            return;
        }
        let response_len = http_content_length(&response_head);
        client.write_all(&response_head).unwrap();
        assert_eq!(
            std::io::copy(
                &mut std::io::Read::by_ref(&mut upstream).take(response_len),
                &mut client,
            )
            .unwrap(),
            response_len,
        );
        client.flush().unwrap();
    }
    panic!("Create proxy never observed the Local Create request");
}

fn create_local_cli(
    space_name: &str,
    address: std::net::SocketAddr,
    resume: bool,
    data_home: &Path,
    config_home: &Path,
    cache_home: &Path,
) -> Output {
    let mut create = Command::new(vosx_bin());
    create.args([
        "space",
        "create-local-agent",
        space_name,
        "--http",
        &address.to_string(),
        "--format",
        "json",
    ]);
    if resume {
        create.arg("--resume");
    }
    create
        .env("XDG_DATA_HOME", data_home)
        .env("XDG_CONFIG_HOME", config_home)
        .env("XDG_CACHE_HOME", cache_home)
        .env("VOSX_DISABLE_MDNS", "1")
        .env("RUST_LOG", "vosx::commands::space::local_create=debug")
        .output()
        .expect("submit exact external Local Create")
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
    run_shutdown_smoke("shutdown-smoke", false, false);
}

#[cfg(all(target_os = "linux", feature = "experimental-state-blocks"))]
#[test]
fn external_space_create_and_exact_retry_after_restart() {
    run_shutdown_smoke("external-shutdown-smoke", true, false);
}

#[cfg(all(target_os = "linux", feature = "experimental-state-blocks"))]
#[test]
fn external_create_lost_reply_recovers_before_and_after_restart() {
    run_shutdown_smoke("external-lost-reply", true, true);
}

fn run_shutdown_smoke(space_name: &str, external: bool, lose_first_reply: bool) {
    #[cfg(not(all(target_os = "linux", feature = "experimental-state-blocks")))]
    let _ = lose_first_reply;
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
                .env(
                    "RUST_LOG",
                    "vos::agent::clean_bootstrap=debug,vos::agent::production_owner=debug",
                )
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
        // Startup retains the Shared admission factory lazily. Neither system
        // bootstrap nor Local mode selection may create ordinary Shared roots.
        for name in [
            "shared-agent-lifecycle",
            "shared-agent-committee",
            "shared-agent-genesis",
        ] {
            assert!(
                !space_root.join(name).exists(),
                "startup eagerly created {name}"
            );
        }
        if external {
            assert!(space_root.join("local-agent-external").is_dir());
            assert!(space_root.join("local-agent-external-lifecycle").is_dir());
            assert!(!space_root.join("local-agent-host").exists());
            assert!(!space_root.join("local-agent-lifecycle").exists());
            let daemon_http = format!("127.0.0.1:{http_port}").parse().unwrap();
            let create_started = Instant::now();
            #[cfg(all(target_os = "linux", feature = "experimental-state-blocks"))]
            let created = if lose_first_reply && boot == 0 {
                let listener = std::net::TcpListener::bind("127.0.0.1:0")
                    .expect("bind isolated lost-response proxy");
                let proxy_http = listener.local_addr().unwrap();
                let proxy =
                    thread::spawn(move || relay_then_lose_create_reply(listener, daemon_http));
                let lost = create_local_cli(
                    space_name,
                    proxy_http,
                    false,
                    data_home.path(),
                    config_home.path(),
                    cache_home.path(),
                );
                proxy.join().expect("proxy forwarded a committed Create");
                assert!(
                    !lost.status.success(),
                    "proxy unexpectedly delivered Create ACK"
                );
                assert!(
                    String::from_utf8_lossy(&lost.stderr).contains("request retained"),
                    "lost reply did not retain exact Create: {}",
                    String::from_utf8_lossy(&lost.stderr),
                );
                create_local_cli(
                    space_name,
                    daemon_http,
                    true,
                    data_home.path(),
                    config_home.path(),
                    cache_home.path(),
                )
            } else {
                create_local_cli(
                    space_name,
                    daemon_http,
                    boot == 1,
                    data_home.path(),
                    config_home.path(),
                    cache_home.path(),
                )
            };
            #[cfg(not(all(target_os = "linux", feature = "experimental-state-blocks")))]
            let created = create_local_cli(
                space_name,
                daemon_http,
                boot == 1,
                data_home.path(),
                config_home.path(),
                cache_home.path(),
            );
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
            for line in fs::read_to_string(&log_path).unwrap_or_default().lines() {
                if line.contains("external Local Create")
                    || line.contains("Local Create publication complete")
                    || line.contains("Local Create exact publication reused")
                    || line.contains("Authority inventory query")
                    || line.contains("Authority inventory pending recovery")
                    || line.contains("Authority inventory loaded")
                    || line.contains("Authority route reconciliation complete")
                    || line.contains("Authority projection phase complete")
                    || line.contains("Authority projection execution phase complete")
                {
                    eprintln!("{line}");
                }
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
