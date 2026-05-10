//! Phase 4 e2e: load http-gateway as a kind=Service extension,
//! confirm its `run` body actually binds the port and serves HTTP
//! while waiting for shutdown.
//!
//! Doesn't exercise the full URL-→actor dispatch path (that needs a
//! registry, which arrives via CLI dispatch in Phase 5). Hits the
//! admin endpoint instead — same protocol/runtime path, no registry
//! dependency.

use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use vos::extension::ExtensionPlugin;
use vos::node::{ExtensionConfig, VosNode};
use vos::value::Args;

fn gateway_so_path() -> std::path::PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    // From extensions/http-gateway/, two `..` lands at workspace root.
    let workspace_root = std::path::PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    workspace_root
        .join("target")
        .join(profile)
        .join("libhttp_gateway.so")
}

#[test]
fn gateway_runs_as_service_extension_and_serves_admin() {
    let so = gateway_so_path();
    if !so.exists() {
        eprintln!(
            "skipping: build http-gateway first (cargo build -p http-gateway)\nlooked for: {}",
            so.display()
        );
        return;
    }

    // Pick a port unlikely to collide with anything else on a dev box.
    // 18080 is well outside common conflicts and inside the 1024+
    // unprivileged range.
    let port: u32 = 18080;
    let admin_token = "phase4-test-token";

    let args = Args::new()
        .with("bind_addr", "127.0.0.1")
        .with("admin_token", admin_token)
        .with("port", port);
    let cfg = ExtensionConfig::with_args(&so, &args);

    // Phase 6 — sanity-check the .so's declared caps before we
    // register it. Loading via ExtensionPlugin separately (it's
    // dropped right after) doesn't disturb the host-side load
    // that follows.
    {
        let plugin = unsafe { ExtensionPlugin::load(&so) }.expect("load gateway plugin");
        let meta = plugin.meta().expect("gateway should have meta");
        assert!(
            meta.caps.iter().any(|c| c == "net.tcp.bind"),
            "gateway should declare net.tcp.bind; saw {:?}",
            meta.caps
        );
        assert!(
            meta.caps.iter().any(|c| c == "tokio-runtime"),
            "gateway should declare tokio-runtime; saw {:?}",
            meta.caps
        );
    }

    let mut node = VosNode::new();
    let shutdown_handle = node.shutdown_handle();
    let _ext_id = node.register_extension(cfg);

    // Run the node on a worker thread so we can poke it with HTTP
    // from the test thread.
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let node_thread = thread::spawn(move || {
        node.run_forever();
        let _ = done_tx.send(());
        node
    });

    // Wait for the gateway to bind. Polling because the gateway boots
    // its tokio runtime + accept loop on its own thread; there's no
    // explicit ready signal exposed back to the host.
    let bound = wait_until_listening(port, Duration::from_secs(2));
    assert!(
        bound,
        "gateway never bound to 127.0.0.1:{port} (probably crashed)"
    );

    // Hit /__admin/status with the matching token. Validates the
    // full wire path: TCP accept → hyper parse → admin route →
    // status JSON → reply on the wire. ctx.ask_raw isn't on this
    // code path, but the rest of the stack is.
    let resp = http_get(
        port,
        "/__admin/status",
        Some(("X-Admin-Token", admin_token)),
    );
    assert!(
        resp.status_ok(),
        "expected 200 from /__admin/status, got {}",
        resp.status
    );
    assert!(
        resp.body.starts_with('{'),
        "expected JSON, got {:?}",
        resp.body
    );

    // Confirm wrong token gives 401 (auth gate is on the wire path).
    let bad = http_get(port, "/__admin/status", Some(("X-Admin-Token", "nope")));
    assert_eq!(bad.status, 401, "wrong admin token should yield 401");

    // Confirm shutdown signalling propagates: flip the flag, gateway's
    // ServiceCtx::is_shutdown returns true, drain_jobs exits, run
    // returns 0, service_thread cleans up.
    shutdown_handle.store(true, Ordering::Relaxed);
    let recv = done_rx.recv_timeout(Duration::from_secs(5));
    assert!(recv.is_ok(), "node didn't shut down within 5s after signal");

    let node = node_thread.join().expect("node thread join");
    let results = node.collect();
    for r in &results {
        assert_eq!(r.panics, 0, "extension {} panicked: {:?}", r.id, r.error);
    }
}

fn wait_until_listening(port: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port as u16)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

struct HttpResponse {
    status: u16,
    body: String,
}

impl HttpResponse {
    fn status_ok(&self) -> bool {
        self.status == 200
    }
}

/// Minimal HTTP/1.1 client. Doesn't parse headers in the response —
/// just splits status line and body. Enough for an admin-route
/// validation; tests that need richer behaviour can pull in `ureq`.
fn http_get(port: u32, path: &str, header: Option<(&str, &str)>) -> HttpResponse {
    use std::io::{Read, Write};
    let mut stream =
        std::net::TcpStream::connect(("127.0.0.1", port as u16)).expect("connect to gateway");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n");
    if let Some((k, v)) = header {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).expect("write request");

    let mut raw = String::new();
    let _ = stream.read_to_string(&mut raw);
    let mut lines = raw.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    // Body is everything after the first blank line.
    let body = match raw.split_once("\r\n\r\n") {
        Some((_, b)) => b.to_string(),
        None => String::new(),
    };
    HttpResponse { status, body }
}
