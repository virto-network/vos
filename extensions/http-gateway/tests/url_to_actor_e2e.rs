//! End-to-end: HTTP request → registry resolve → actor dispatch
//! → JSON reply on the wire.
//!
//! Stands up:
//!   - mock-registry  at ServiceId::REGISTRY (= 0)
//!   - counter        at ServiceId(1) — matches what mock-registry's
//!                    `resolve("counter")` returns
//!   - http-gateway   at the next available id
//!
//! Then issues `GET /counter/inc` three times and asserts the JSON
//! reply each time matches the new count. Final `GET /counter/get`
//! confirms the count survived. Validates the full Phase 4 wire
//! path with a real registry round-trip — not just the admin
//! shortcut the prior service_mode test exercised.
//!
//! Both fixture .so files live under
//! `extensions/http-gateway/test_fixtures/{mock-registry,counter}/`
//! as out-of-workspace crates with their own [workspace] tables —
//! they only build when this test (or a manual `cargo build
//! --manifest-path …`) asks for them. The test skips with a clear
//! message if either .so is missing.

use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use vos::abi::service::ServiceId;
use vos::extension::ExtensionPlugin;
use vos::node::{ExtensionConfig, VosNode};
use vos::value::Args;

fn workspace_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn gateway_so_path() -> std::path::PathBuf {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    workspace_root()
        .join("target")
        .join(profile)
        .join("libhttp_gateway.so")
}

fn fixture_so_path(fixture: &str, lib_name: &str) -> std::path::PathBuf {
    // Fixtures have their own per-crate target dirs because they
    // live in [workspace]-isolated sub-Cargos. Always look in
    // debug/ — fixtures don't ship release builds.
    workspace_root()
        .join("extensions/http-gateway/test_fixtures")
        .join(fixture)
        .join("target/debug")
        .join(lib_name)
}

#[test]
fn http_get_routes_to_actor_via_registry() {
    let gateway = gateway_so_path();
    let mock_registry = fixture_so_path("mock-registry", "libmock_registry_extension.so");
    let counter = fixture_so_path("counter", "libcounter_extension.so");
    if !gateway.exists() || !mock_registry.exists() || !counter.exists() {
        eprintln!(
            "skipping: build all three first.\n\
             cargo build -p http-gateway\n\
             cargo build --manifest-path {}/Cargo.toml\n\
             cargo build --manifest-path {}/Cargo.toml",
            mock_registry.parent().unwrap().parent().unwrap().display(),
            counter.parent().unwrap().parent().unwrap().display(),
        );
        return;
    }

    let port: u32 = 18081; // distinct from the service_mode test
    let admin_token = "e2e-test-token";

    // Quick sanity: gateway .so must really declare the caps Phase
    // 6 added; if this fails the .so is stale.
    {
        let plugin = unsafe { ExtensionPlugin::load(&gateway) }.expect("load gateway");
        let meta = plugin.meta().expect("gateway meta");
        assert!(
            meta.caps.iter().any(|c| c == "net.tcp.bind"),
            "gateway should declare net.tcp.bind; saw {:?}",
            meta.caps
        );
    }

    let mut node = VosNode::new();
    let shutdown = node.shutdown_handle();

    // 1. Mock registry at the well-known REGISTRY id. The gateway
    //    asks ServiceId(0).resolve("counter") → 1.
    let _reg_id =
        node.register_extension_at_id(ExtensionConfig::new(&mock_registry), ServiceId::REGISTRY);

    // 2. Counter — auto-allocated id, which on a fresh VosNode
    //    starts at 1 (next_local::AtomicU16 init = 1). Confirm
    //    that's what we got so the registry's hardcoded "counter
    //    → 1" mapping holds.
    let counter_id = node.register_extension(ExtensionConfig::new(&counter));
    assert_eq!(
        counter_id.0, 1,
        "counter should land at id 1 to match the mock registry's resolve mapping"
    );

    // 3. Gateway — service-mode, port + admin_token via init args.
    let gw_args = Args::new()
        .with("bind_addr", "127.0.0.1")
        .with("admin_token", admin_token)
        .with("port", port);
    let _gw_id = node.register_extension(ExtensionConfig::with_args(&gateway, &gw_args));

    let (done_tx, done_rx) = mpsc::channel::<()>();
    let node_thread = thread::spawn(move || {
        node.run_forever();
        let _ = done_tx.send(());
        node
    });

    let bound = wait_until_listening(port, Duration::from_secs(3));
    assert!(
        bound,
        "gateway never bound to 127.0.0.1:{port} (probably crashed)"
    );

    // ── Real HTTP round-trips ───────────────────────────────────
    //
    // GET /counter/inc → registry.resolve("counter") → counter.inc()
    // → JSON {"u32": <count>} (the gateway's value_to_json wraps
    // primitive numerics under a type tag).
    for expected_count in 1..=3u32 {
        let resp = http_get(port, "/counter/inc", None);
        assert_eq!(
            resp.status, 200,
            "GET /counter/inc #{expected_count}: expected 200, got {} body={:?}",
            resp.status, resp.body
        );
        // Body should be JSON — at minimum it should parse and
        // contain the number we expect somewhere. Don't pin the
        // exact JSON shape — value_to_json may evolve and we want
        // to keep this test robust to that.
        assert!(
            resp.body.contains(&expected_count.to_string()),
            "reply body should contain {expected_count}; got {:?}",
            resp.body
        );
    }

    // GET /counter/get → counter.get() → 3.
    let final_resp = http_get(port, "/counter/get", None);
    assert_eq!(
        final_resp.status, 200,
        "GET /counter/get: expected 200, got {} body={:?}",
        final_resp.status, final_resp.body
    );
    assert!(
        final_resp.body.contains('3'),
        "final get should report 3; body={:?}",
        final_resp.body
    );

    // 4. Unknown agent → registry returns 0 → gateway returns 404.
    let unknown = http_get(port, "/nope/whatever", None);
    assert_eq!(
        unknown.status, 404,
        "unknown agent should yield 404; got {} body={:?}",
        unknown.status, unknown.body
    );

    // 5. Clean shutdown.
    shutdown.store(true, Ordering::Relaxed);
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
    let status = raw
        .split("\r\n")
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = match raw.split_once("\r\n\r\n") {
        Some((_, b)) => b.to_string(),
        None => String::new(),
    };
    HttpResponse { status, body }
}
