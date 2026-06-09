//! End-to-end dispatch tests for http-gateway.
//!
//! Stands the gateway up alongside a mock-registry + counter +
//! kitchen-sink fixture, then drives real HTTP requests at it and
//! asserts what the actors received and what the wire reply
//! contained. Validates the full chain:
//!
//!   wire bytes → host accept loop → handle_connection (HTTP/1.1
//!     parser) → routing::dispatch (auth gate) → resolve(name)
//!     → ctx.ask_dispatch → actor handler → reply Value → JSON → wire
//!
//! Each test case spins up its own `TestNode` (own port, own VosNode
//! instance) so failures are isolated. Cases are short by design —
//! the harness in `tests/common/mod.rs` carries the boilerplate.
//!
//! Skips with a clear "build these first" hint if any fixture .so
//! is missing. CI builds them via the per-fixture cargo manifest
//! paths in the harness's `print_skip_hint`.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use common::{FixturePaths, TestNode};
use serde_json::json;

/// Read one HTTP/1.1 response off a (possibly keep-alive) connection,
/// framed by `Content-Length`. Returns `(status, body)`.
fn read_http_response<R: BufRead>(reader: &mut R) -> (u16, Vec<u8>) {
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .expect("read status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("bad status line: {status_line:?}"));
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("read header line");
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break; // end of headers
        }
        if let Some(v) = trimmed
            .strip_prefix("Content-Length:")
            .or_else(|| trimmed.strip_prefix("content-length:"))
        {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).expect("read body");
    (status, body)
}

/// Send a sequence of GET requests over ONE keep-alive connection (all
/// but the last marked `Connection: keep-alive`), reading each response
/// before sending the next. Proves connection reuse + `Content-Length`
/// framing across requests.
fn keepalive_gets(port: u16, paths: &[String]) -> Vec<(u16, String)> {
    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    let mut out = Vec::with_capacity(paths.len());
    for (i, path) in paths.iter().enumerate() {
        let conn = if i + 1 == paths.len() {
            "close"
        } else {
            "keep-alive"
        };
        let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: {conn}\r\n\r\n");
        writer.write_all(req.as_bytes()).expect("write request");
        let (status, body) = read_http_response(&mut reader);
        out.push((status, String::from_utf8_lossy(&body).into_owned()));
    }
    out
}

// ── Fixture sanity ──────────────────────────────────────────────
//
// Pre-Phase-6 admin-namespace tests are gone; `vosx gateway *`
// covers the lifecycle surface in `gateway_pvm_e2e`. Boot-time
// sanity is implicitly covered by every test below — a failed
// `TestNode::start` aborts the run.

#[test]
fn gateway_caps_are_declared_on_the_so() {
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let plugin =
        unsafe { vos::extension::ExtensionPlugin::load(&paths.gateway) }.expect("load gateway");
    let meta = plugin.meta().expect("meta");
    // The gateway is now a transport extension — the HOST
    // owns the listener, so the gateway declares only `net.tcp.bind`
    // (the OS access it asks the host to perform on its behalf); the old
    // `tokio-runtime` / `thread.spawn` caps are gone with the hyper stack.
    assert!(
        meta.caps.iter().any(|c| c == "net.tcp.bind"),
        "gateway should declare net.tcp.bind; saw {:?}",
        meta.caps
    );
}

#[test]
fn gateway_is_a_transport_extension_with_no_msg_handlers() {
    // The gateway is a `#[actor(kind="transport")]` + `handle_connection`
    // extension. A transport extension has NO `#[msg]` handlers (the macro
    // rejects them), so its meta lists zero CLI-exposed methods — lifecycle is
    // the generic host-side `vosx gateway stop|describe` (`__stop` /
    // `__describe`), not gateway-declared invokes.
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let plugin =
        unsafe { vos::extension::ExtensionPlugin::load(&paths.gateway) }.expect("load gateway");
    let meta = plugin.meta().expect("meta");
    assert_eq!(
        meta.kind, 2,
        "gateway should be ExtensionKind::Transport (2); saw kind {}",
        meta.kind,
    );
    assert!(
        meta.messages.iter().all(|m| !m.exposed_to_cli),
        "a transport gateway exposes no CLI methods; saw {:?}",
        meta.messages
            .iter()
            .filter(|m| m.exposed_to_cli)
            .map(|m| &m.name)
            .collect::<Vec<_>>(),
    );
}

// ── Routing: registry resolution ─────────────────────────────────

#[test]
fn unknown_agent_returns_404() {
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    let resp = http.get("/no-such-agent/anything");
    resp.assert_status(404);
}

#[test]
fn malformed_url_returns_400() {
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    // /<agent>/<method> with no method.
    http.get("/counter/").assert_status(400);
    // Just /agent (no slash + method).
    http.get("/counter").assert_status(400);
    // Empty path.
    http.get("/").assert_status(400);
}

// ── GET path: query args → Str-typed handler ─────────────────────

#[test]
fn get_with_query_arg_round_trips_to_string_handler() {
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    let resp = http.get("/kitchen/echo?text=hello");
    resp.assert_status(200);
    assert_eq!(resp.json(), json!("hello"));

    // The actor recorded what it saw — confirm via the getter.
    let last = http.get("/kitchen/last_text");
    assert_eq!(last.json(), json!("hello"));
}

#[test]
fn get_handles_url_encoding() {
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    // Percent-encoded space.
    let resp = http.get("/kitchen/echo?text=hello%20world");
    resp.assert_status(200);
    assert_eq!(resp.json(), json!("hello world"));

    // Plus-as-space (form-encoding convention).
    let resp = http.get("/kitchen/echo?text=hello+world");
    resp.assert_status(200);
    assert_eq!(resp.json(), json!("hello world"));

    // Reserved char (`&`) percent-encoded.
    let resp = http.get("/kitchen/echo?text=a%26b");
    resp.assert_status(200);
    assert_eq!(resp.json(), json!("a&b"));
}

#[test]
fn get_with_typed_arg_coerces_via_schema() {
    // Schema-aware coercion: GET query args are `Value::Str(_)`,
    // but the mock-registry serves kitchen-sink's schema so the
    // gateway knows `add(a: u32, b: u32)` and parses "2"/"3" into
    // `Value::U32(2)`/`Value::U32(3)`. Previously rendered as
    // `200 null` because the macro's `from_msg` rejected the
    // Str→u32 shape; now closes that gap when meta is registered.
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    let resp = http.get("/kitchen/add?a=2&b=3");
    resp.assert_status(200);
    assert_eq!(resp.json(), json!(5));
}

#[test]
fn get_with_string_arg_returning_list() {
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    let resp = http.get("/kitchen/split?s=a,b,c");
    resp.assert_status(200);
    assert_eq!(resp.json(), json!(["a", "b", "c"]));
}

// ── POST path: JSON body → typed handler ─────────────────────────

#[test]
fn post_with_json_body_dispatches_typed_args() {
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    let resp = http.post_json("/kitchen/add", r#"{"a":2,"b":3}"#);
    resp.assert_status(200);
    assert_eq!(resp.json(), json!(5));

    // Mutating dispatch landed — the getter sees the recorded sum.
    let last = http.get("/kitchen/last_sum");
    assert_eq!(last.json(), json!(5));
}

#[test]
fn post_bool_round_trip() {
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    let resp = http.post_json("/kitchen/flip", r#"{"b":true}"#);
    resp.assert_status(200);
    assert_eq!(resp.json(), json!(false));

    let resp = http.post_json("/kitchen/flip", r#"{"b":false}"#);
    resp.assert_status(200);
    assert_eq!(resp.json(), json!(true));
}

#[test]
fn post_list_args() {
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    let resp = http.post_json("/kitchen/sum_list", r#"{"xs":[1,2,3,4]}"#);
    resp.assert_status(200);
    assert_eq!(resp.json(), json!(10));

    let resp = http.post_json("/kitchen/concat", r#"{"parts":["a","b","c"]}"#);
    resp.assert_status(200);
    assert_eq!(resp.json(), json!("a,b,c"));
}

#[test]
fn post_returning_lists() {
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    let resp = http.post_json("/kitchen/range", r#"{"n":5}"#);
    resp.assert_status(200);
    assert_eq!(resp.json(), json!([0, 1, 2, 3, 4]));
}

#[test]
fn put_and_patch_use_same_codec_as_post() {
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    let r1 = http.put_json("/kitchen/add", r#"{"a":10,"b":20}"#);
    r1.assert_status(200);
    assert_eq!(r1.json(), json!(30));

    let r2 = http.patch_json("/kitchen/add", r#"{"a":100,"b":1}"#);
    r2.assert_status(200);
    assert_eq!(r2.json(), json!(101));
}

#[test]
fn delete_method_is_rejected() {
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    let resp = http.delete("/kitchen/echo");
    resp.assert_status(405);
}

// ── Reply types ──────────────────────────────────────────────────

#[test]
fn unit_reply_renders_as_json_null() {
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    let resp = http.get("/kitchen/ping");
    resp.assert_status(200);
    assert_eq!(resp.json(), json!(null));
}

#[test]
fn numeric_reply_is_a_bare_json_number() {
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    let resp = http.get("/counter/inc");
    resp.assert_status(200);
    // Body must parse as a number, not a string or object.
    match resp.json() {
        serde_json::Value::Number(n) => {
            assert_eq!(n.as_u64(), Some(1));
        }
        other => panic!("expected JSON number, got {other:?}"),
    }
}

// ── Error paths ──────────────────────────────────────────────────

#[test]
fn upstream_panic_yields_502() {
    // Handler panic surfaces as 502 distinct from the legitimate
    // `()` return that renders as 200 null. Previously both
    // collapsed to 200 null because the host couldn't tell them
    // apart on the wire; the invoke envelope now carries
    // STATUS_PANICKED for caught panics (set by `extension_thread`
    // when `dispatch_and_poll` returns `DispatchOutcome::Err`),
    // and `unwrap_invoke_envelope` returns None for any
    // non-success status, which `ServiceCtx::ask_raw` passes
    // through to the gateway's None → 502 path.
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    let resp = http.get("/kitchen/boom");
    resp.assert_status(502);
}

#[test]
fn unknown_method_on_known_agent_404s_with_schema() {
    // Schema-aware error surface: resolve("kitchen") succeeds, but
    // kitchen-sink's schema doesn't list `nonsense`. The gateway
    // pre-checks `ParsedMessage` and 404s without dispatching.
    // Pre-schema this used to render as `200 null` (handler
    // missing was indistinguishable from `()`-returning).
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    let resp = http.get("/kitchen/nonsense");
    resp.assert_status(404);
    assert!(
        resp.body.contains("unknown method"),
        "expected 'unknown method' in body, got {:?}",
        resp.body
    );
}

#[test]
fn malformed_json_body_yields_400() {
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    let resp = http.post_json("/kitchen/add", "{not json");
    resp.assert_status(400);

    // Top-level array (not object) also rejected — contract is
    // "flat object of args".
    let resp = http.post_json("/kitchen/add", "[1,2]");
    resp.assert_status(400);
}

#[test]
fn missing_required_arg_yields_400() {
    // Schema-aware required-arg check: `add(a, b)` declares both
    // fields, sending only `{"a":2}` is a malformed request rather
    // than a server-side failure. Gateway 400s with the missing
    // field name in the body — clients can fix their request
    // without round-tripping the actor.
    //
    // Pre-schema this collapsed to "200 null" (actor's from_msg
    // returns None silently); post-schema-coercion-only it was
    // 502 (POLL_ERR_NO_FUTURE → STATUS_PANICKED → unwrap None);
    // now we cut it short at the gateway with a useful body.
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    let resp = http.post_json("/kitchen/add", r#"{"a":2}"#); // missing b
    resp.assert_status(400);
    assert!(
        resp.body.contains("missing required arg") && resp.body.contains("'b'"),
        "expected missing-arg body, got {:?}",
        resp.body,
    );
}

// ── State + lifecycle ────────────────────────────────────────────

#[test]
fn mutating_state_persists_across_calls() {
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    for expected in 1..=3u32 {
        let resp = http.get("/counter/inc");
        resp.assert_status(200);
        assert_eq!(resp.json(), json!(expected));
    }
    let final_resp = http.get("/counter/get");
    assert_eq!(final_resp.json(), json!(3));
}

#[test]
fn metrics_reflect_request_count() {
    // Replaces the pre-Phase-6 `admin_status_reflects_request_count`
    // that scraped `GET /__admin/status`. The same dispatched-
    // request counter now rides `GET /__metrics` as
    // `vos_gateway_requests_total` — public, scrape-friendly,
    // and survives the admin-namespace removal.
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    for _ in 0..5 {
        http.get("/counter/inc").assert_status(200);
    }
    let resp = http.get("/__metrics");
    let body = resp.text();
    let count = body
        .lines()
        .find_map(|l| l.strip_prefix("vos_gateway_requests_total "))
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or_else(|| panic!("vos_gateway_requests_total missing from metrics: {body}"));
    assert!(
        count >= 5,
        "expected ≥5 requests counted, got {count}; metrics body:\n{body}",
    );
}

// ── Concurrency ──────────────────────────────────────────────────

// ── keep-alive + concurrency + large-body ─────────
//
// The other guards all use `Connection: close` (one request per
// connection), so they never exercise the keep-alive loop in
// `handle_connection` or multi-read body framing. These do.

#[test]
fn keepalive_serves_multiple_requests_on_one_connection() {
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);

    // Three independent (pure) adds over ONE keep-alive connection.
    let reqs: Vec<String> = vec![
        "/kitchen/add?a=1&b=2".into(),
        "/kitchen/add?a=10&b=20".into(),
        "/kitchen/add?a=100&b=200".into(),
    ];
    let resps = keepalive_gets(node.port, &reqs);
    assert_eq!(resps.len(), 3);
    assert_eq!(resps[0], (200, "3".to_string()), "first keep-alive request");
    assert_eq!(
        resps[1],
        (200, "30".to_string()),
        "second keep-alive request"
    );
    assert_eq!(
        resps[2],
        (200, "300".to_string()),
        "third keep-alive request"
    );
}

#[test]
fn concurrent_keepalive_connections_interleave() {
    // M concurrent connections, each issuing K keep-alive requests with
    // its own (a, b) pairs. Each (a, b) has exactly one correct sum, so a
    // reply mixup (cross-talk between in-flight connection tasks on the
    // host's single executor) is detectable — the
    // tcp_echo interleave guard at the HTTP layer.
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let port = node.port;

    const M: usize = 8;
    const K: usize = 6;
    let mut handles = Vec::with_capacity(M);
    for m in 0..M {
        handles.push(std::thread::spawn(move || {
            let reqs: Vec<String> = (0..K)
                .map(|k| {
                    let a = m * 1000 + k;
                    format!("/kitchen/add?a={a}&b=7")
                })
                .collect();
            let resps = keepalive_gets(port, &reqs);
            for (k, (status, body)) in resps.iter().enumerate() {
                let a = m * 1000 + k;
                assert_eq!(*status, 200, "conn {m} req {k}: status");
                assert_eq!(
                    body,
                    &(a + 7).to_string(),
                    "conn {m} req {k}: reply cross-talk? want {}+7",
                    a,
                );
            }
        }));
    }
    for h in handles {
        h.join().expect("keep-alive worker thread");
    }
}

#[test]
fn large_body_post_is_framed_across_reads() {
    // A POST body well over the 16 KiB `READ_CHUNK` exercises the parser's
    // multi-read body accumulation + exact `Content-Length` framing. The
    // kitchen `sum_list` handler returns the sum, so the result is a
    // function of the (large) body — a framing bug (short/over read) would
    // corrupt the JSON and fail to parse or sum wrong.
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    const N: usize = 9000; // "[1,1,…]" ≈ 18 KiB > READ_CHUNK
    let xs: Vec<u32> = vec![1; N];
    let body = serde_json::json!({ "xs": xs }).to_string();
    assert!(body.len() > 16 * 1024, "body must exceed READ_CHUNK");

    let resp = http.post_json("/kitchen/sum_list", &body);
    resp.assert_status(200);
    assert_eq!(resp.json(), json!(N as u64), "sum of {N} ones");
}

#[test]
fn gateway_with_no_init_args_boots_on_defaults() {
    // Regression: a transport gateway created with
    // EMPTY init args — a manifest `[[extension]]` with no `init = {}`, a
    // documented way to request the defaults — must boot, NOT panic across
    // the `extern "C"` create boundary and abort the whole daemon. We
    // register the gateway with no args + `.serves(addr)` and assert the host
    // binds the port (i.e. `new(&[])` ran and applied defaults).
    use std::sync::atomic::Ordering;
    use vos::node::{ExtensionConfig, VosNode};

    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let port = common::next_port();
    let addr = format!("127.0.0.1:{port}");

    let mut node = VosNode::new();
    let shutdown = node.shutdown_handle();
    // No init args at all — the host still binds via `.serves`, and the
    // gateway's `new(&[])` applies in-code defaults.
    node.register_extension(ExtensionConfig::new(&paths.gateway).serves(addr, false));
    let handle = std::thread::spawn(move || {
        node.run_forever();
        node
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut bound = false;
    while std::time::Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            bound = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    shutdown.store(true, Ordering::Relaxed);
    let _ = handle.join();
    assert!(
        bound,
        "gateway with empty init args should bind {port} on defaults, not abort the daemon",
    );
}

#[test]
fn parallel_requests_serialize_through_dispatch_correctly() {
    // 20 parallel HTTP clients each call `/counter/inc` once. The
    // gateway's drain_jobs serializes ctx.ask_raw calls, so the
    // counter should reach exactly 20 even though the connections
    // are concurrent on the wire.
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let port = node.port;

    const N: usize = 20;
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        handles.push(std::thread::spawn(move || {
            let http = common::Http { port };
            let resp = http.get("/counter/inc");
            assert_eq!(resp.status, 200, "body={:?}", resp.body);
        }));
    }
    for h in handles {
        h.join().expect("worker join");
    }

    // After 20 increments, get returns 20.
    let final_resp = node.http().get("/counter/get");
    final_resp.assert_status(200);
    assert_eq!(final_resp.json(), json!(N as u64));
}

// ── Review hardening: pipelining + over-the-wire framing rejections ──
//
// `keepalive_gets` is request→response→request, so it never leaves a
// trailing request in the read buffer. These drive the subtler paths the
// parse_head unit tests don't reach end-to-end.

#[test]
fn pipelined_requests_on_one_connection() {
    // Two requests written in a SINGLE `write_all` (before reading any
    // response) — true HTTP/1.1 pipelining. This exercises serve_connection's
    // drain-and-retain of the *trailing* request already sitting in the read
    // buffer (the part keepalive_gets can't reach). Responses must come back
    // in order, correctly framed.
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let stream = TcpStream::connect(("127.0.0.1", node.port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);

    // Both heads in one write; first keep-alive, second closes.
    let pipelined = "GET /kitchen/add?a=1&b=2 HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n\
                     GET /kitchen/add?a=10&b=20 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    writer
        .write_all(pipelined.as_bytes())
        .expect("write pipelined");

    let (s1, b1) = read_http_response(&mut reader);
    let (s2, b2) = read_http_response(&mut reader);
    assert_eq!(
        (s1, String::from_utf8_lossy(&b1).into_owned()),
        (200, "3".to_string()),
        "first pipelined response"
    );
    assert_eq!(
        (s2, String::from_utf8_lossy(&b2).into_owned()),
        (200, "30".to_string()),
        "second pipelined response (drained from the buffer)"
    );
}

/// Send one raw request head over a fresh connection and return the status.
fn raw_request_status(port: u16, raw: &str) -> u16 {
    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    writer.write_all(raw.as_bytes()).expect("write raw request");
    read_http_response(&mut reader).0
}

#[test]
fn oversize_content_length_yields_413_over_the_wire() {
    // `parse_head` rejects Content-Length > MAX_BODY_BYTES with 413; confirm it
    // travels the full accept → handle_connection → serve loop as a framed
    // response (not a hang waiting for a body the client never sends).
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let status = raw_request_status(
        node.port,
        "POST /kitchen/add HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(status, 413, "oversize Content-Length should be 413");
}

#[test]
fn duplicate_content_length_yields_400_over_the_wire() {
    // Conflicting Content-Length must be rejected (smuggling defense), end to
    // end — not framed by the first value.
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let status = raw_request_status(
        node.port,
        "POST /kitchen/add HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\
         Content-Length: 5\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status, 400, "duplicate Content-Length should be 400");
}

#[test]
fn reserved_namespace_subpath_is_not_dispatched() {
    // Review fix: `/__metrics/<x>` must NOT dispatch to an agent named
    // `__metrics` (which `effective_auth_for` classifies as public → no token).
    // The reserved-namespace guard 404s it.
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let resp = node.http().get("/__metrics/inc");
    assert_eq!(
        resp.status, 404,
        "a reserved-namespace sub-path must 404, not dispatch unauthenticated; body={:?}",
        resp.body
    );
}
