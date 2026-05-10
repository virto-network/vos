//! Shared test scaffolding for the http-gateway integration tests.
//!
//! Three responsibilities:
//!   1. Path resolution for the gateway + fixture .so files,
//!      with a clean "skip with build hint" if anything's missing.
//!   2. `TestNode` — owns a running VosNode in a side thread,
//!      tears down on drop.
//!   3. `Http` — minimal HTTP/1.1 client (status + body + headers
//!      out, raw bytes in). Connection-per-call; no keep-alive.
//!
//! Each test file does `mod common;` to pull this in.

#![allow(dead_code)] // each test uses a different subset

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use vos::abi::service::ServiceId;
use vos::node::{ExtensionConfig, VosNode};
use vos::value::Args;

// ── Path resolution ──────────────────────────────────────────────

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn debug_or_release() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

pub fn gateway_so_path() -> PathBuf {
    workspace_root()
        .join("target")
        .join(debug_or_release())
        .join("libhttp_gateway.so")
}

pub fn fixture_so_path(fixture: &str, lib_name: &str) -> PathBuf {
    workspace_root()
        .join("extensions/http-gateway/test_fixtures")
        .join(fixture)
        .join("target/debug")
        .join(lib_name)
}

/// All standard fixture paths. None means "build me first".
pub struct FixturePaths {
    pub gateway: PathBuf,
    pub mock_registry: PathBuf,
    pub counter: PathBuf,
    pub kitchen: PathBuf,
}

impl FixturePaths {
    pub fn discover() -> Self {
        Self {
            gateway: gateway_so_path(),
            mock_registry: fixture_so_path("mock-registry", "libmock_registry_extension.so"),
            counter: fixture_so_path("counter", "libcounter_extension.so"),
            kitchen: fixture_so_path("kitchen-sink", "libkitchen_sink_extension.so"),
        }
    }

    /// `true` if every fixture is built. `print_skip_hint` covers
    /// the diagnostic when this returns false.
    pub fn all_present(&self) -> bool {
        self.gateway.exists()
            && self.mock_registry.exists()
            && self.counter.exists()
            && self.kitchen.exists()
    }

    pub fn print_skip_hint(&self) {
        eprintln!("skipping: build the gateway and all test fixtures first.\n");
        if !self.gateway.exists() {
            eprintln!("  cargo build -p http-gateway");
        }
        if !self.mock_registry.exists() {
            eprintln!(
                "  cargo build --manifest-path {}/Cargo.toml",
                self.mock_registry
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .display(),
            );
        }
        if !self.counter.exists() {
            eprintln!(
                "  cargo build --manifest-path {}/Cargo.toml",
                self.counter.parent().unwrap().parent().unwrap().display(),
            );
        }
        if !self.kitchen.exists() {
            eprintln!(
                "  cargo build --manifest-path {}/Cargo.toml",
                self.kitchen.parent().unwrap().parent().unwrap().display(),
            );
        }
    }
}

// ── Port allocation ──────────────────────────────────────────────

/// Tests share a process; static counter avoids port collisions when
/// multiple tests run in parallel. Picks from the high-end
/// unprivileged range; collisions with random other processes are
/// astronomically unlikely.
static NEXT_PORT: AtomicU16 = AtomicU16::new(28080);

pub fn next_port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::Relaxed)
}

// ── TestNode ─────────────────────────────────────────────────────

/// Running VosNode + gateway combo. Drop signals shutdown and
/// joins. Tests construct one per case — each gets its own port,
/// its own node, its own log spam.
pub struct TestNode {
    pub port: u16,
    pub admin_token: &'static str,
    shutdown: Arc<AtomicBool>,
    node_thread: Option<thread::JoinHandle<VosNode>>,
}

impl TestNode {
    /// Stand up the standard layout for dispatch tests:
    ///   - mock-registry at ServiceId::REGISTRY
    ///   - counter       at ServiceId(1)  (mock-registry maps "counter"→1)
    ///   - kitchen-sink  at ServiceId(2)  (mock-registry maps "kitchen"→2)
    ///   - gateway       at next available id
    ///
    /// Returns once the gateway has bound the port (or after a 3s
    /// timeout, in which case calls to `http.*` will fail loudly).
    pub fn start(paths: &FixturePaths) -> Self {
        Self::start_with_admin_token(paths, "dispatch-test-token")
    }

    pub fn start_with_admin_token(paths: &FixturePaths, admin_token: &'static str) -> Self {
        let port = next_port();
        let mut node = VosNode::new();
        let shutdown = node.shutdown_handle();

        node.register_extension_at_id(
            ExtensionConfig::new(&paths.mock_registry),
            ServiceId::REGISTRY,
        );
        let counter_id = node.register_extension(ExtensionConfig::new(&paths.counter));
        assert_eq!(
            counter_id.0, 1,
            "counter should land at id 1 to match mock-registry"
        );
        let kitchen_id = node.register_extension(ExtensionConfig::new(&paths.kitchen));
        assert_eq!(
            kitchen_id.0, 2,
            "kitchen should land at id 2 to match mock-registry"
        );

        let args = Args::new()
            .with("bind_addr", "127.0.0.1")
            .with("admin_token", admin_token)
            .with("port", port as u32);
        node.register_extension(ExtensionConfig::with_args(&paths.gateway, &args));

        let node_thread = thread::spawn(move || {
            node.run_forever();
            node
        });

        let bound = wait_until_listening(port, Duration::from_secs(3));
        assert!(bound, "gateway never bound to 127.0.0.1:{port}");

        Self {
            port,
            admin_token,
            shutdown,
            node_thread: Some(node_thread),
        }
    }

    pub fn http(&self) -> Http {
        Http { port: self.port }
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.node_thread.take() {
            // 5s gives the gateway's drain timeout (3s default) +
            // a little buffer. If join times out, leak the thread —
            // panicking from Drop is worse than a stale OS thread.
            let deadline = Instant::now() + Duration::from_secs(8);
            while Instant::now() < deadline {
                if handle.is_finished() {
                    let node = handle.join().expect("node thread join");
                    let results = node.collect();
                    for r in &results {
                        if r.panics > 0 {
                            // Don't panic from Drop — print and let
                            // the test continue. If a panic is
                            // expected (boom test), the test asserts
                            // separately on the result; otherwise this
                            // hint surfaces.
                            eprintln!(
                                "TestNode drop: extension {} panics={} error={:?}",
                                r.id, r.panics, r.error
                            );
                        }
                    }
                    return;
                }
                thread::sleep(Duration::from_millis(20));
            }
            eprintln!("TestNode drop: node thread didn't exit in 8s; leaking");
        }
    }
}

fn wait_until_listening(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

// ── HTTP client ──────────────────────────────────────────────────

pub struct Http {
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
    pub raw_headers: String,
}

impl HttpResponse {
    pub fn assert_status(&self, expected: u16) -> &Self {
        assert_eq!(
            self.status, expected,
            "expected {} got {}; body={:?}",
            expected, self.status, self.body
        );
        self
    }

    /// Parse the body as JSON. Panics with diagnostic if the body
    /// isn't valid JSON.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| {
            panic!(
                "expected JSON body, parse error {e}; raw body={:?}",
                self.body
            )
        })
    }
}

impl Http {
    pub fn get(&self, path: &str) -> HttpResponse {
        self.request("GET", path, &[], &[])
    }

    pub fn get_with_header(&self, path: &str, header: (&str, &str)) -> HttpResponse {
        self.request("GET", path, &[header], &[])
    }

    pub fn post_json(&self, path: &str, body: &str) -> HttpResponse {
        self.request(
            "POST",
            path,
            &[("Content-Type", "application/json")],
            body.as_bytes(),
        )
    }

    pub fn put_json(&self, path: &str, body: &str) -> HttpResponse {
        self.request(
            "PUT",
            path,
            &[("Content-Type", "application/json")],
            body.as_bytes(),
        )
    }

    pub fn patch_json(&self, path: &str, body: &str) -> HttpResponse {
        self.request(
            "PATCH",
            path,
            &[("Content-Type", "application/json")],
            body.as_bytes(),
        )
    }

    pub fn delete(&self, path: &str) -> HttpResponse {
        self.request("DELETE", path, &[], &[])
    }

    pub fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> HttpResponse {
        use std::io::{Read, Write};
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", self.port))
            .unwrap_or_else(|e| panic!("connect to 127.0.0.1:{}: {e}", self.port));
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n",
            self.port
        );
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        if !body.is_empty() {
            req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        req.push_str("\r\n");

        stream.write_all(req.as_bytes()).expect("write headers");
        if !body.is_empty() {
            stream.write_all(body).expect("write body");
        }

        let mut raw = String::new();
        let _ = stream.read_to_string(&mut raw);

        let status = raw
            .split("\r\n")
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let (raw_headers, body) = match raw.split_once("\r\n\r\n") {
            Some((h, b)) => (h.to_string(), b.to_string()),
            None => (raw.clone(), String::new()),
        };
        HttpResponse {
            status,
            body,
            raw_headers,
        }
    }
}

// Suppress "module imported but unused" when individual tests only
// touch a subset of the harness.
pub fn _force_link() {
    let _ = (next_port(), Duration::ZERO, mpsc::channel::<()>());
}
