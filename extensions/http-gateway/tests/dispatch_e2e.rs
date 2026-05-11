//! End-to-end dispatch tests for http-gateway.
//!
//! Stands the gateway up alongside a mock-registry + counter +
//! kitchen-sink fixture, then drives real HTTP requests at it and
//! asserts what the actors received and what the wire reply
//! contained. Validates the full chain:
//!
//!   wire bytes → hyper → dispatch_request → admin/auth gates
//!     → Job queue → drain_jobs → resolve(name) → ctx.ask_raw
//!     → actor handler → reply Value → JSON → wire bytes
//!
//! Each test case spins up its own `TestNode` (own port, own VosNode
//! instance) so failures are isolated. Cases are short by design —
//! the harness in `tests/common/mod.rs` carries the boilerplate.
//!
//! Skips with a clear "build these first" hint if any fixture .so
//! is missing. CI builds them via the per-fixture cargo manifest
//! paths in the harness's `print_skip_hint`.

mod common;

use common::{FixturePaths, TestNode};
use serde_json::json;

// ── Fixture sanity ──────────────────────────────────────────────

#[test]
fn gateway_boots_and_serves_admin_endpoint() {
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    let resp = http.get_with_header("/__admin/status", ("X-Admin-Token", node.admin_token));
    resp.assert_status(200);
    let v = resp.json();
    assert!(
        v.get("port").is_some(),
        "status should include port: {:?}",
        v
    );

    let bad = http.get_with_header("/__admin/status", ("X-Admin-Token", "wrong"));
    bad.assert_status(401);

    let no_token = http.get("/__admin/status");
    no_token.assert_status(401);
}

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
fn admin_status_reflects_request_count() {
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
    let status = http
        .get_with_header("/__admin/status", ("X-Admin-Token", node.admin_token))
        .json();
    let requests = status
        .get("requests")
        .and_then(|v| v.as_u64())
        .expect("status.requests");
    assert!(
        requests >= 5,
        "expected >=5 requests counted, got {requests}; status={status}"
    );
}

#[test]
fn admin_stop_signals_gateway_to_exit() {
    let paths = FixturePaths::discover();
    if !paths.all_present() {
        paths.print_skip_hint();
        return;
    }
    let node = TestNode::start(&paths);
    let http = node.http();

    // POST /__admin/stop — expect 204 No Content.
    let resp = http.request(
        "POST",
        "/__admin/stop",
        &[("X-Admin-Token", node.admin_token)],
        &[],
    );
    resp.assert_status(204);

    // After stop, give the gateway a beat to drain. Subsequent
    // connect attempts will eventually fail (port unbinds). We
    // don't strictly assert that — the TestNode drop confirms
    // clean shutdown semantics. Just confirm no panic before drop.
}

// ── Concurrency ──────────────────────────────────────────────────

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
