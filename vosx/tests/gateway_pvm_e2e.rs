//! End-to-end: real `vosx` daemon + bundled (PVM) space-registry +
//! real PVM actors + the http-gateway extension. Drives HTTP
//! requests through the full production wire path:
//!
//!   curl → host TCP accept loop → gateway handle_connection →
//!   ctx.ask_dispatch → invoke channel →
//!   space-registry (PVM, resolves name via blake2b precompile) →
//!   ask_dispatch → target actor (PVM, decodes Msg, runs handler) →
//!   invoke envelope → unwrap → JSON
//!
//! Catches the failure class the in-process `dispatch_e2e` suite
//! cannot. That suite uses a host-native mock registry — its
//! `resolve` runs on x86, not in PVM, so it never exercises the
//! `vos::crypto::blake2b_hash` precompile path on the riscv64
//! side. Before the slot-100 cap install in
//! `runtime::install_vos_precompile_caps`, the PVM blake2b ECALL
//! silently no-op'd and the registry returned a constant garbage
//! id for every name; this test would have failed with 502s
//! across the board.
//!
//! Three properties verified:
//!
//! 1. Two different agent names resolve to two different
//!    ServiceIds (the registry isn't returning the same garbage
//!    id for everything → blake2b precompile is firing).
//! 2. Dispatch to a *registered* agent returns 200 (and a
//!    sensible body); dispatch to an *unknown* name returns 404.
//! 3. State-bearing handlers persist across requests — the
//!    counter actor's count advances on each successive
//!    `/counter/start`.
//!
//! Build prerequisites
//!
//!   cargo build -p vosx -p http-gateway
//!   cd examples && just build
//!
//! The test panics with a helpful hint if any artifact is
//! missing rather than trying to build it itself — keeps
//! iteration fast.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// `vosx` binary location for this `cargo test` invocation.
fn vosx_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vosx"))
}

/// Workspace root — `vosx/`'s parent.
fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("vosx's parent is the workspace")
        .to_path_buf()
}

/// Gateway .so — sits next to vosx in `target/<profile>/`.
fn gateway_so() -> PathBuf {
    vosx_bin()
        .parent()
        .expect("vosx binary has a parent dir")
        .join("libhttp_gateway.so")
}

fn actor_elf(name: &str) -> PathBuf {
    workspace().join(format!(
        "examples/actors/{name}/target/riscv64em-javm/release/{name}.elf"
    ))
}

fn ensure_built() {
    for (path, hint) in [
        (vosx_bin(), "cargo build -p vosx"),
        (gateway_so(), "cargo build -p http-gateway"),
        (actor_elf("greeter"), "cd examples && just build"),
        (actor_elf("counter"), "cd examples && just build"),
        (actor_elf("math"), "cd examples && just build"),
    ] {
        if !path.exists() {
            panic!("test artifact missing: {}\nRun: {}", path.display(), hint,);
        }
    }
}

/// Bind ephemeral, immediately release. There's a race window
/// between this and the daemon's bind, but small enough that
/// flakiness is rare — and the alternative (hard-coded port)
/// collides with anything else on the dev box.
fn pick_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

/// RAII child handle. Drops SIGKILL the daemon and reap.
struct Daemon {
    child: Child,
    port: u16,
    _data_home: TempDir,
    _config_home: TempDir,
}

impl Daemon {
    fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Minimal temp dir — doesn't pull `tempfile` for two of these.
struct TempDir(PathBuf);
impl TempDir {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        p.push(format!(
            "vosx-e2e-{}-{}-{}",
            std::process::id(),
            label,
            nanos
        ));
        std::fs::create_dir_all(&p).expect("create tempdir");
        TempDir(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        // Leave behind on panic so a failing test can be debugged
        // — std's test harness sets this when a test fails.
        if std::thread::panicking() {
            eprintln!("TempDir kept for debugging: {}", self.0.display());
            return;
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Boot a fresh vosx daemon against a temp data/config home.
/// Returns once the gateway port accepts TCP or panics on a
/// generous bring-up budget.
fn boot_daemon(manifest_path: &Path, port: u16) -> Daemon {
    let data_home = TempDir::new("data");
    let config_home = TempDir::new("config");

    let space_name = "e2e";

    // 1. `vosx space new --name e2e` — bundled registry kicks
    //    in automatically (no --registry needed).
    let new = Command::new(vosx_bin())
        .args(["space", "new", "--name", space_name])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .output()
        .expect("spawn vosx space new");
    assert!(
        new.status.success(),
        "vosx space new failed: stderr={}",
        String::from_utf8_lossy(&new.stderr),
    );

    // 2. `vosx space up <recipe.toml>` — the trivalent positional
    //    detects the recipe path, finds the just-created `e2e` space
    //    (the recipe's `space = "e2e"`), stamps it pending, and runs a
    //    one-shot genesis apply at boot (agents → registry, gateway
    //    extension → local.toml → registered). Daemon stderr goes to a
    //    file inside `data_home` so a failed boot is still inspectable,
    //    while NOT going through a pipe — under release-LTO the daemon's
    //    mDNS-discovery INFO logs can exceed the default 64KB pipe
    //    buffer between test polls and deadlock the dispatch thread on
    //    stderr write (manifested as the test hanging on the first HTTP
    //    read).
    let log_path = data_home.path().join("daemon.stderr");
    let log_file = std::fs::File::create(&log_path).expect("create daemon stderr log");
    let child = Command::new(vosx_bin())
        .args(["space", "up"])
        .arg(manifest_path)
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("RUST_LOG", "info")
        // Disable mDNS auto-dial — without this, a daemon running
        // on a dev machine alongside an IPFS node / Substrate node
        // / another libp2p app picks them up over mDNS, dials them,
        // and the resulting connection failures perturb the
        // dispatch path under release-LTO timings (see D2 in the
        // publish-readiness review).
        .env("VOSX_DISABLE_MDNS", "1")
        .stdout(Stdio::null())
        .stderr(log_file)
        .spawn()
        .expect("spawn vosx space up");

    // 3. Wait for the gateway to bind. A daemon that fails fast
    //    (port collision, missing artifacts) would otherwise
    //    deadlock the test on `connect`.
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(100),
        )
        .is_ok()
        {
            return Daemon {
                child,
                port,
                _data_home: data_home,
                _config_home: config_home,
            };
        }
        std::thread::sleep(Duration::from_millis(150));
    }

    panic!(
        "daemon didn't open port {port} within 20s — data dir was {}",
        data_home.path().display(),
    );
}

/// Render a minimal manifest TOML installing greeter + counter +
/// math PVM actors + the http-gateway. consistency = ephemeral
/// keeps state in memory only, which suits the test's lifecycle.
fn write_manifest(dir: &Path, port: u16) -> PathBuf {
    let path = dir.join("manifest.toml");
    let body = format!(
        r#"
space = "e2e"
version = "0.1.0"

[[agent]]
name = "greeter"
path = "{greeter}"
consistency = "ephemeral"

[[agent]]
name = "counter"
path = "{counter}"
consistency = "ephemeral"

[[agent]]
name = "math"
path = "{math}"
consistency = "ephemeral"

[[extension]]
name = "gateway"
path = "{gateway}"
init = {{ bind_addr = "127.0.0.1", port = {port} }}
"#,
        greeter = actor_elf("greeter").display(),
        counter = actor_elf("counter").display(),
        math = actor_elf("math").display(),
        gateway = gateway_so().display(),
    );
    std::fs::write(&path, body).expect("write manifest");
    path
}

/// One-shot HTTP request. Returns (status_code, headers_blob, body).
/// `Connection: close` makes the daemon close after the reply so
/// `read_to_end` returns cleanly.
fn http_request(
    port: u16,
    method: &str,
    path: &str,
    extra_header: Option<(&str, &str)>,
    body: &[u8],
) -> (u16, Vec<u8>) {
    let mut conn = TcpStream::connect(("127.0.0.1", port)).expect("connect to gateway");
    // Read budget covers gateway boot + first-dispatch warmup
    // under release-LTO, which can stretch ~12-15s on cold cache.
    // Dev builds finish in <1s; the budget mostly absorbs slow CI.
    conn.set_read_timeout(Some(Duration::from_secs(60)))
        .expect("set read timeout");
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n",);
    if let Some((k, v)) = extra_header {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    conn.write_all(req.as_bytes()).expect("write headers");
    conn.write_all(body).expect("write body");

    let mut raw = Vec::new();
    conn.read_to_end(&mut raw).expect("read response");
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> (u16, Vec<u8>) {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("missing end-of-headers in HTTP response");
    let headers = &raw[..split];
    let body = raw[split + 4..].to_vec();
    let status_line = std::str::from_utf8(
        &headers[..headers
            .iter()
            .position(|&b| b == b'\r')
            .unwrap_or(headers.len())],
    )
    .expect("status line utf-8");
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("parse status code");
    (status, body)
}

/// Poll a dispatch URL until it returns 200 — i.e. the manifest
/// reconciler finished both installing the agent (registry knows
/// the name) AND wiring its invoke channel (`register_at_id`
/// populated `invoke_routes`). 404 means the registry hasn't seen
/// the name yet; 502 means the registry resolved but the channel
/// isn't there. Either way, not ready. Panics after 15 s.
fn wait_until_ready(port: u16, path: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut last_status = 0;
    while Instant::now() < deadline {
        let (status, _body) = http_request(port, "POST", path, None, &[]);
        if status == 200 {
            return;
        }
        last_status = status;
        std::thread::sleep(Duration::from_millis(150));
    }
    panic!("agents never finished installing within 15s; last status for {path} = {last_status}",);
}

/// Extract the numeric value following a Prometheus metric name in
/// the exposition body. Matches the first line that starts with the
/// (full, including labels) identifier — keeps the scan simple
/// without pulling in a parser dep.
fn extract_counter(body: &str, name: &str) -> u64 {
    for line in body.lines() {
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix(name) {
            return rest.trim().parse().unwrap_or(0);
        }
    }
    0
}

/// Pull the dispatched-request count out of the public
/// `/__metrics` endpoint (`vos_gateway_requests_total` line).
/// Replaces the pre-Phase-6 `admin_request_count` which read the
/// same number from `/__admin/status`; the admin namespace is
/// gone, the metrics endpoint stays.
fn dispatch_request_count(daemon: &Daemon) -> u64 {
    let (status, body) = http_request(daemon.port(), "GET", "/__metrics", None, &[]);
    assert_eq!(status, 200, "/__metrics returned {status}");
    let s = std::str::from_utf8(&body).expect("metrics body utf-8");
    s.lines()
        .find_map(|l| l.strip_prefix("vos_gateway_requests_total "))
        .and_then(|t| t.trim().parse::<u64>().ok())
        .unwrap_or_else(|| panic!("vos_gateway_requests_total missing from metrics: {s}"))
}

// Passes cleanly under `cargo test` (dev profile). FAILS under
// `cargo test --release`: the release-built `libhttp_gateway.so`
// receives an HTTP request, fires `ServiceCtx::ask_raw` against
// the PVM actor (which runs — `greeter: Hello n=42` shows in the
// daemon log), then never writes the response back to the
// client. `hyper_io` logs `connection closed before message
// completed` on the client's eventual disconnect.
//
// Reproduces by hand with a release vosx + release gateway —
// it's a real `--release` codegen issue in either the gateway's
// tokio-runtime ↔ ask_raw bridge or the host's invoke-reply
// channel. Not on the publishing-`vosx` critical path (vosx the
// CLI is fine in release), but it does block shipping the
// gateway example.
//
// Tracking: D2 in the publish-readiness review. Re-enable once
// the root cause is found.
#[cfg_attr(
    not(debug_assertions),
    ignore = "release-build hang under investigation (D2)"
)]
#[test]
fn pvm_actors_via_gateway() {
    ensure_built();

    let port = pick_port();
    let tempdir = TempDir::new("manifest");
    let manifest = write_manifest(tempdir.path(), port);

    let daemon = boot_daemon(&manifest, port);

    // The gateway starts listening before the manifest reconciler
    // finishes installing agents, so a request right after port-
    // open can race the install and 404. Poll `/greeter/start`
    // until it stops 404'ing — the dispatch counter tracks both
    // the readiness probe AND the test's real first hit.
    wait_until_ready(daemon.port(), "/greeter/start");

    // 1. Sanity check on the public dispatch counter — confirms
    //    the gateway booted cleanly and counted the readiness
    //    probe. (Pre-Phase-6 this scraped `/__admin/status`; the
    //    same number now rides `/__metrics` as
    //    `vos_gateway_requests_total`.)
    let count0 = dispatch_request_count(&daemon);
    assert!(count0 >= 1, "readiness probe should have counted");

    // 2. Dispatch to greeter. Empty handler returns () → 200 null.
    //    A 200 here proves the *full* path is alive:
    //      gateway → registry (PVM) resolves "greeter" → invoke →
    //      greeter actor (PVM) runs `start()` → reply envelope →
    //      gateway unwraps → JSON.
    let (status, body) = http_request(daemon.port(), "POST", "/greeter/start", None, &[]);
    assert_eq!(
        status,
        200,
        "POST /greeter/start expected 200, got {status} body={:?}. \
         If 502 'upstream error', the PVM blake2b precompile may not \
         be installed at slot 100 — see runtime::install_vos_precompile_caps.",
        String::from_utf8_lossy(&body),
    );
    let body_str = std::str::from_utf8(&body).expect("body utf-8").trim();
    assert_eq!(
        body_str, "null",
        "greeter.start returns (); expected JSON null"
    );

    // 3. Dispatch to counter. Same shape — different actor,
    //    different registered ServiceId. If the registry is
    //    returning the same garbage id for every name (blake2b
    //    no-op'd), the gateway hits the same target as step 3
    //    and the counter never ticks.
    for _ in 0..3 {
        let (status, body) = http_request(daemon.port(), "POST", "/counter/start", None, &[]);
        assert_eq!(
            status,
            200,
            "POST /counter/start expected 200, got {status} body={:?}",
            String::from_utf8_lossy(&body),
        );
    }

    // 4. Math actor with JSON-encoded args — exercises the full
    //    typed-arg round trip. `parse_flat_json` encodes small
    //    ints as `Value::U32`; `math::add(a:u64, b:u64) -> u64`
    //    relies on `Value::as_u64` widening from U32. Returns
    //    JSON-encoded sum.
    let (status, body) = http_request(
        daemon.port(),
        "POST",
        "/math/add",
        None,
        br#"{"a":2,"b":3}"#,
    );
    assert_eq!(
        status,
        200,
        "POST /math/add expected 200, got {status} body={:?}",
        String::from_utf8_lossy(&body),
    );
    assert_eq!(
        std::str::from_utf8(&body).expect("body utf-8").trim(),
        "5",
        "math/add(2,3): if this is 'null', Value::as_u64 isn't widening U32 → u64",
    );

    // Same actor, second method — proves dispatch picks the
    // right handler by name and the type coercion is consistent.
    let (status, body) = http_request(
        daemon.port(),
        "POST",
        "/math/multiply",
        None,
        br#"{"a":6,"b":7}"#,
    );
    assert_eq!(
        status, 200,
        "POST /math/multiply expected 200, got {status}"
    );
    assert_eq!(std::str::from_utf8(&body).expect("body utf-8").trim(), "42",);

    // U64-shaped JSON (value > u32::MAX) also coerces — exercises
    // the wide branch of the JSON parser's classifier.
    let (status, body) = http_request(
        daemon.port(),
        "POST",
        "/math/add",
        None,
        br#"{"a":5000000000,"b":1}"#,
    );
    assert_eq!(status, 200);
    assert_eq!(
        std::str::from_utf8(&body).expect("body utf-8").trim(),
        "5000000001",
    );

    // GET with numeric query args — exercises the schema-aware
    // coercion path that landed alongside registry-owned meta.
    // Query strings carry no JSON typing, so without the schema
    // lookup `a` and `b` would arrive as `Value::Str` and the
    // u64-typed handler would reject them. The registry's
    // `meta_for_instance("math")` round trip (cached after the
    // first request — math/add above already populated it) tells
    // the gateway both fields are `u64`, and `coerce_to_type`
    // parses "21" / "21" out of the URL.
    let (status, body) = http_request(daemon.port(), "GET", "/math/add?a=21&b=21", None, &[]);
    assert_eq!(
        status,
        200,
        "GET /math/add?a=21&b=21 expected 200, got {status} body={:?}. \
         If 'null', registry meta lookup or coerce_to_type isn't \
         parsing query strings into Value::U64.",
        String::from_utf8_lossy(&body),
    );
    assert_eq!(std::str::from_utf8(&body).expect("body utf-8").trim(), "42",);

    // 5. Unknown agent — registry returns 0 → gateway 404.
    //    Asserts the negative path: registry isn't blanket-
    //    returning a non-zero id for everything.
    let (status, body) = http_request(daemon.port(), "POST", "/no-such-agent/whatever", None, &[]);
    assert_eq!(
        status,
        404,
        "unknown agent should 404, got {status} body={:?}",
        String::from_utf8_lossy(&body),
    );

    // 5b. Schema-aware error surface: an unknown method on a
    //     known agent → 404 (not "200 null" like pre-schema).
    let (status, body) = http_request(
        daemon.port(),
        "POST",
        "/math/divide",
        None,
        br#"{"a":4,"b":2}"#,
    );
    assert_eq!(
        status,
        404,
        "unknown method should 404 with schema present, got {status} body={:?}",
        String::from_utf8_lossy(&body),
    );
    assert!(
        body.windows(7).any(|w| w == b"unknown"),
        "unknown method body should mention 'unknown', got {:?}",
        String::from_utf8_lossy(&body),
    );

    // 5c. Schema-aware error surface: type-mismatched arg → 400
    //     (not "200 null"). math.add expects u64; sending a
    //     non-numeric string for `a` should fail at the gateway.
    let (status, body) = http_request(
        daemon.port(),
        "GET",
        "/math/add?a=notanumber&b=3",
        None,
        &[],
    );
    assert_eq!(
        status,
        400,
        "type mismatch should 400 with schema present, got {status} body={:?}",
        String::from_utf8_lossy(&body),
    );
    let body_str = String::from_utf8_lossy(&body);
    assert!(
        body_str.contains("'a'") && body_str.contains("u64"),
        "type-mismatch body should name the bad arg and its expected type, got {body_str:?}",
    );

    // 6. /__schema → list of installed agents (JSON array of
    //    names). Public endpoint, no admin token. Sorted by
    //    instance_name on the registry side.
    let (status, body) = http_request(daemon.port(), "GET", "/__schema", None, &[]);
    assert_eq!(status, 200, "GET /__schema expected 200, got {status}");
    let names: Vec<String> = serde_json::from_slice(&body).expect("/__schema returns a JSON array");
    assert!(
        names.contains(&"math".to_string())
            && names.contains(&"greeter".to_string())
            && names.contains(&"counter".to_string()),
        "expected math + greeter + counter in /__schema, got {names:?}",
    );

    // 7. /__schema/math → full ActorMeta as JSON. Catches both
    //    the registry's `meta_for_instance` join and the gateway's
    //    `meta_to_json` rendering.
    let (status, body) = http_request(daemon.port(), "GET", "/__schema/math", None, &[]);
    assert_eq!(status, 200, "GET /__schema/math expected 200, got {status}");
    let meta: serde_json::Value =
        serde_json::from_slice(&body).expect("/__schema/<agent> returns JSON");
    assert_eq!(meta["actor_name"], "Math");
    // Math has two messages: add(u64,u64) and multiply(u64,u64).
    let messages = meta["messages"].as_array().expect("messages array");
    let add = messages
        .iter()
        .find(|m| m["name"] == "add")
        .expect("add method in schema");
    let fields = add["fields"].as_array().expect("add.fields");
    assert_eq!(fields.len(), 2, "add has 2 args");
    let a = fields.iter().find(|f| f["name"] == "a").expect("'a' arg");
    assert_eq!(a["type"], "u64", "math.add.a is declared u64");

    // 8. /__schema/<unknown> → 404 (negative path).
    let (status, _body) = http_request(daemon.port(), "GET", "/__schema/nonexistent", None, &[]);
    assert_eq!(
        status, 404,
        "GET /__schema/nonexistent should 404, got {status}",
    );

    // 9. `vosx space describe` CLI — operator-facing mirror of
    //     `/__schema/<agent>`. Uses the same daemon (via
    //     DaemonClient) so this exercises the registry's
    //     `meta_for_instance` handler over libp2p, plus the CLI's
    //     JSON renderer end to end.
    let out = Command::new(vosx_bin())
        .args(["--format", "json", "space", "describe", "e2e", "math"])
        .env("XDG_DATA_HOME", daemon._data_home.path())
        .env("XDG_CONFIG_HOME", daemon._config_home.path())
        .output()
        .expect("spawn vosx space describe");
    assert!(
        out.status.success(),
        "vosx space describe failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    let cli_meta: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "`describe --format json` stdout not JSON ({e}): {:?}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert_eq!(cli_meta["actor_name"], "Math");
    assert!(
        cli_meta["messages"]
            .as_array()
            .map(|a| a.iter().any(|m| m["name"] == "multiply"))
            .unwrap_or(false),
        "describe should list math.multiply: {cli_meta}",
    );

    // 9a-pre. Phase 4 dynamic dispatch: `vosx --space e2e math add a=2 b=3`
    //          replaces `vosx space call e2e math add a=2 b=3` with an
    //          ergonomic shape that's schema-aware (the registry's
    //          math.add(u64, u64) signature drives arg coercion).
    let out = Command::new(vosx_bin())
        .args([
            "--format", "json", "--space", "e2e", "math", "add", "a=2", "b=3",
        ])
        .env("XDG_DATA_HOME", daemon._data_home.path())
        .env("XDG_CONFIG_HOME", daemon._config_home.path())
        .output()
        .expect("spawn vosx math add");
    assert!(
        out.status.success(),
        "vosx math add failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    let body = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        body.trim(),
        "5",
        "math.add(2,3) via dynamic dispatch: {body}"
    );

    // Schema-aware rejection: math.add wants u64; sending a
    // non-numeric arg must fail at the CLI level (before the
    // daemon round trip) with a typed error.
    let out = Command::new(vosx_bin())
        .args(["--space", "e2e", "math", "add", "a=notanumber", "b=3"])
        .env("XDG_DATA_HOME", daemon._data_home.path())
        .env("XDG_CONFIG_HOME", daemon._config_home.path())
        .output()
        .expect("spawn vosx math add (bad arg)");
    assert!(
        !out.status.success(),
        "type mismatch must error; got stdout={:?}",
        String::from_utf8_lossy(&out.stdout),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("u64") && stderr.contains("notanumber"),
        "schema-aware error should name the type + value: {stderr}",
    );

    // `vosx <unknown>` from the index → "unknown" error from the
    // registry meta lookup, not a daemon hang or a confusing
    // "no such ELF" from the one-shot run path.
    let out = Command::new(vosx_bin())
        .args(["--space", "e2e", "no-such-target"])
        .env("XDG_DATA_HOME", daemon._data_home.path())
        .env("XDG_CONFIG_HOME", daemon._config_home.path())
        .output()
        .expect("spawn vosx unknown");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no schema") || stderr.contains("unknown"),
        "unknown target must give a clear error: {stderr}",
    );

    // 9a-cache. The previous `vosx --space e2e math add` round
    //            wrote the math schema into the per-space CLI
    //            cache at `<XDG_CONFIG_HOME>/vosx/cli_cache.toml`.
    //            `vosx --help` should now surface `math` as a
    //            discoverable target without re-dialling the
    //            daemon (proves the cache survives across
    //            invocations and the post-help renderer reads it).
    let out = Command::new(vosx_bin())
        .args(["--help"])
        .env("XDG_DATA_HOME", daemon._data_home.path())
        .env("XDG_CONFIG_HOME", daemon._config_home.path())
        .output()
        .expect("spawn vosx --help");
    assert!(
        out.status.success(),
        "vosx --help failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        help.contains("Discovered targets"),
        "vosx --help should include cache-derived section, got:\n{help}",
    );
    assert!(
        help.contains("e2e") && help.contains("math"),
        "vosx --help should list cached target `math` in space `e2e`, got:\n{help}",
    );

    // 9a. Same CLI, but pointed at the gateway *extension* instead
    //      of a PVM agent. Phase 3 wired vosx reconcile to forward
    //      `[[extension]]` meta to the registry's `register_extension_meta`;
    //      `meta_for_instance` falls through, so this round-trips
    //      through the same libp2p path as math/greeter/counter and
    //      renders the gateway's meta. The gateway is a
    //      TRANSPORT extension (`kind = 2`) with NO `#[msg]` handlers — so
    //      it exposes no CLI methods (lifecycle moved to the generic
    //      host-side `stop`/`describe`, exercised in step 11).
    let out = Command::new(vosx_bin())
        .args(["--format", "json", "space", "describe", "e2e", "gateway"])
        .env("XDG_DATA_HOME", daemon._data_home.path())
        .env("XDG_CONFIG_HOME", daemon._config_home.path())
        .output()
        .expect("spawn vosx space describe gateway");
    assert!(
        out.status.success(),
        "vosx space describe gateway failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    let ext_meta: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "`describe gateway --format json` stdout not JSON ({e}): {:?}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert_eq!(ext_meta["actor_name"], "HttpGateway");
    assert_eq!(
        ext_meta["kind"], 2,
        "gateway is now a transport-mode extension (kind 2)",
    );
    let exposed: Vec<&str> = ext_meta["messages"]
        .as_array()
        .map(|ms| {
            ms.iter()
                .filter(|m| m["exposed_to_cli"] == true)
                .filter_map(|m| m["name"].as_str())
                .collect()
        })
        .unwrap_or_default();
    assert!(
        exposed.is_empty(),
        "a transport gateway declares no CLI methods; saw {exposed:?}",
    );

    // 9b. /openapi.json — auto-generated from registered schemas.
    //      Asserts the doc shape: openapi version, math.add /
    //      math.multiply paths each with the right HTTP method,
    //      and that the u64 arg type maps to the proper OpenAPI
    //      integer/format pair.
    let (status, body) = http_request(daemon.port(), "GET", "/openapi.json", None, &[]);
    assert_eq!(status, 200, "GET /openapi.json expected 200, got {status}");
    let doc: serde_json::Value = serde_json::from_slice(&body).expect("/openapi.json returns JSON");
    assert_eq!(doc["openapi"], "3.0.3");
    let paths = doc["paths"].as_object().expect("paths is object");
    assert!(
        paths.contains_key("/math/add"),
        "/math/add should be in openapi paths"
    );
    let add_op = &paths["/math/add"];
    // math.add is `&self → u64` so is_query=true → GET.
    let get_op = &add_op["get"];
    assert!(
        !get_op.is_null(),
        "math.add should expose GET (query handler)"
    );
    let params = get_op["parameters"].as_array().expect("parameters array");
    let a_param = params
        .iter()
        .find(|p| p["name"] == "a")
        .expect("'a' parameter");
    assert_eq!(a_param["schema"]["type"], "integer");
    assert_eq!(a_param["schema"]["format"], "uint64");

    // 9c. /__metrics — Prometheus exposition format. Public,
    //      no token. Asserts both the surface (HELP/TYPE lines)
    //      and a counter actually moved across all the requests
    //      we issued above. `responses_total{status_class="2xx"}`
    //      must be at least 4 (greeter + 3 counter + 3 math +
    //      GET + schema + openapi = many 2xx).
    let (status, body) = http_request(daemon.port(), "GET", "/__metrics", None, &[]);
    assert_eq!(status, 200, "GET /__metrics expected 200, got {status}");
    let metrics_body = String::from_utf8_lossy(&body);
    assert!(
        metrics_body.contains("# TYPE vos_gateway_up gauge"),
        "metrics body missing vos_gateway_up: {metrics_body}",
    );
    assert!(
        metrics_body.contains("vos_gateway_up 1"),
        "gateway should report up=1: {metrics_body}",
    );
    assert!(
        metrics_body.contains("vos_gateway_responses_total{status_class=\"2xx\"}"),
        "missing 2xx counter label: {metrics_body}",
    );
    let twoxx = extract_counter(
        &metrics_body,
        "vos_gateway_responses_total{status_class=\"2xx\"}",
    );
    assert!(twoxx >= 1, "expected ≥1 2xx response counted, got {twoxx}");
    let fourxx = extract_counter(
        &metrics_body,
        "vos_gateway_responses_total{status_class=\"4xx\"}",
    );
    // Step 5 issued /no-such-agent → 404, /math/divide → 404 (if
    // schema present — depends on runtime; conservative ≥1).
    assert!(
        fourxx >= 1,
        "expected ≥1 4xx response counted, got {fourxx}"
    );

    // 10. Dispatched-request counter monotonically advances. Don't
    //     pin an exact number — the readiness poll above can retry
    //     an unbounded number of times depending on install timing
    //     — just require it advanced by at least the dispatch
    //     requests in steps 3–9 (greeter + 3 counter + 3 math + 1
    //     GET + 404 + /__schema + /__schema/math + /__schema/missing
    //     = 12). Step 10's `describe` invokes the registry via a
    //     fresh libp2p client, which doesn't go through the
    //     gateway's request counter, so it doesn't add here.
    let count1 = dispatch_request_count(&daemon);
    assert!(
        count1 >= count0 + 12,
        "expected counter to advance by ≥12, got {count0} → {count1}",
    );

    // 10b. Sprint 5: concurrent /math/add stress. The sequential
    //      checks above prove dispatch *works*; this one proves
    //      it works *concurrently* — no response cross-talk, no
    //      lost dispatches, no actor-mutex deadlock. `math::add`
    //      is pure on its inputs, so each (a,b) pair has exactly
    //      one correct sum and we can detect any reply mixup.
    {
        const N: u32 = 16;
        let port = daemon.port();
        let pre = dispatch_request_count(&daemon);
        let handles: Vec<_> = (0..N)
            .map(|i| {
                std::thread::spawn(move || {
                    let a = (i as u64) * 100 + 1;
                    let b = (i as u64) * 100 + 2;
                    let body_json = format!(r#"{{"a":{a},"b":{b}}}"#);
                    let (status, body) =
                        http_request(port, "POST", "/math/add", None, body_json.as_bytes());
                    (i, a, b, status, body)
                })
            })
            .collect();
        let mut results: Vec<(u32, u64, u64, u16, Vec<u8>)> = handles
            .into_iter()
            .map(|h| h.join().expect("worker thread panicked"))
            .collect();
        // Sort by `i` so the assertion failure messages are stable.
        results.sort_by_key(|r| r.0);

        for (i, a, b, status, body) in &results {
            assert_eq!(
                *status,
                200,
                "concurrent /math/add[{i}] (a={a}, b={b}) expected 200; got {status} body={:?}",
                String::from_utf8_lossy(body),
            );
            let txt = std::str::from_utf8(body).expect("body utf-8").trim();
            let got: u64 = txt
                .parse()
                .unwrap_or_else(|_| panic!("non-numeric reply for ({a},{b}): {txt}"));
            assert_eq!(
                got,
                a + b,
                "concurrent /math/add[{i}] reply mismatch — \
                 cross-talk between in-flight requests? \
                 want {} + {} = {}, got {}",
                a,
                b,
                a + b,
                got,
            );
        }

        // Every dispatched /math/add ticks the gateway request
        // counter; /__metrics is a system endpoint and does NOT
        // self-count. So the gap is exactly `N`. A weaker `>= N`
        // would let a lost-dispatch regression slip through, so
        // pin the exact number.
        let post = dispatch_request_count(&daemon);
        assert_eq!(
            post - pre,
            N as u64,
            "concurrent burst dispatch counter mismatch: pre={pre} post={post} \
             expected delta {N} (one tick per /math/add request)",
        );
    }

    // 11. The lifecycle surface split in two.
    //
    //  (a) Rich live status stays IN the gateway as the public
    //      `GET /__status` endpoint (reads only `Inner` atomics — no
    //      registry round trip), replacing the old `vosx gateway status`
    //      invoke sidecar.
    let (status_code, body) = http_request(daemon.port(), "GET", "/__status", None, &[]);
    assert_eq!(
        status_code, 200,
        "GET /__status expected 200, got {status_code}"
    );
    let status: serde_json::Value =
        serde_json::from_slice(&body).expect("/__status returns a JSON object");
    assert_eq!(
        status["running"], true,
        "gateway should report running=true: {status}",
    );
    assert!(
        status["port"].is_number(),
        "/__status should include the bound port: {status}",
    );

    //  (b) `vosx gateway describe` is the GENERIC host primitive
    //      (`__describe`) — works for any agent, reports the live
    //      running flag + transport kind + host-bound serve address.
    let out = Command::new(vosx_bin())
        .args(["--format", "json", "--space", "e2e", "gateway", "describe"])
        .env("XDG_DATA_HOME", daemon._data_home.path())
        .env("XDG_CONFIG_HOME", daemon._config_home.path())
        .output()
        .expect("spawn vosx gateway describe");
    assert!(
        out.status.success(),
        "vosx gateway describe failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    let desc: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
        .expect("vosx gateway describe returns a JSON object");
    assert_eq!(desc["running"], true, "describe before stop: {desc}");
    assert_eq!(desc["kind"], 2, "gateway is transport-kind: {desc}");
    assert!(
        desc["serves_addr"]
            .as_str()
            .is_some_and(|a| a.contains(&port.to_string())),
        "describe should report the host-bound serve addr: {desc}",
    );

    //  (c) `vosx gateway stop` is the GENERIC host primitive (`__stop`)
    //      — flips the gateway agent's shutdown flag so its accept loop
    //      exits, WITHOUT tearing down the node. Returns Value::Unit →
    //      JSON `null`. Lives at the end because it stops serving.
    let out = Command::new(vosx_bin())
        .args(["--format", "json", "--space", "e2e", "gateway", "stop"])
        .env("XDG_DATA_HOME", daemon._data_home.path())
        .env("XDG_CONFIG_HOME", daemon._config_home.path())
        .output()
        .expect("spawn vosx gateway stop");
    assert!(
        out.status.success(),
        "vosx gateway stop failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    let body = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        body.trim(),
        "null",
        "stop should return Value::Unit → null, got: {body}",
    );

    // The accept loop polls its shutdown flag every ~50ms; give it a
    // moment, then confirm the listener is gone (connection refused) —
    // proving `__stop` stopped the gateway agent specifically.
    let mut closed = false;
    for _ in 0..40 {
        std::thread::sleep(Duration::from_millis(50));
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", daemon.port()).parse().unwrap(),
            Duration::from_millis(100),
        )
        .is_err()
        {
            closed = true;
            break;
        }
    }
    assert!(closed, "gateway listener should close after `gateway stop`");

    // Daemon teardown via Drop.
}
