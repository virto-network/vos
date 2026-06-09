# Writing a VOS extension

Extensions are native `.so` plugins the host loads alongside its PVM
agents. Two kinds: **Actor** (request-driven — handlers run to completion
per dispatch, plus an optional periodic `tick`) and **Transport** (the host
owns a listener + accept loop and hands the extension one connection at a
time via `handle_connection`). There is no service-mode (a self-spun
`run(ServiceCtx)` loop) — the host owns concurrency.

This is the cookbook. The book chapter at
[`docs/extensions.md`](../docs/extensions.md) is the reader-facing
intro.

## When to pick which kind

- **Actor** if the extension's job is "something calls in, the handler
  runs, replies, done" — or it needs to originate work on a timer (a
  heartbeat, a cache sweep) via `tick`. No listening sockets, no
  self-managed threads. Examples: `examples/extensions/echo`,
  `examples/extensions/fetcher`, `examples/extensions/heartbeat`,
  `extensions/dev`, `extensions/ai`.

- **Transport** if the extension serves a network protocol over a socket
  the host binds for it. You write `handle_connection(&self, ctx, conn_id)`;
  the host binds the listener, runs the accept loop, terminates TLS, and
  spawns one concurrent connection task per accept — all sharing `&self`.
  Example: `extensions/http-gateway`.

If you find yourself wanting `serve()` / `listen()` / `accept_loop` as a
blocking handler, you want a Transport extension — the host runs that loop
for you.

## Cargo.toml — either kind

```toml
[lib]
crate-type = ["rlib", "cdylib"]

[features]
default = ["bin", "extension"]
bin = []
extension = []

[lints.rust.unexpected_cfgs]
level = "allow"
check-cfg = ['cfg(feature, values("pvm", "service", "extension", "wasm"))']

[dependencies]
vos = { path = "../../vos", default-features = false, features = ["extension"] }
```

The `bin` feature gates the `vos_extension_*` extern fn exports — keep it on
for the produced `.so`, off when another crate pulls this one in as an
`rlib` for its `Ref` types. Actor and Transport use the same manifest; only
the source differs.

## src/lib.rs — Actor kind

```rust
use vos::prelude::*;

#[actor]
pub struct Echo {
    count: u32,
}

#[messages]
impl Echo {
    fn new() -> Self { Echo { count: 0 } }

    #[msg]
    async fn echo(&mut self, text: String, _ctx: &mut Context<Self>) -> String {
        self.count += 1;
        format!("echo #{}: {text}", self.count)
    }

    #[msg]
    async fn count(&self, _ctx: &mut Context<Self>) -> u32 {
        self.count
    }
}
```

Same story as PVM actors. `#[messages]` emits the dispatch enum + the
`vos_extension_*` C ABI symbols on the cdylib build. Dispatch is N=1: the
host drives one handler to completion before the next on this agent's
thread, so `&mut self` handlers never race.

## src/lib.rs — periodic work with `tick`

An actor that needs to *originate* work on a schedule (rather than only
react to inbound messages) declares a `tick` handler. The host calls it
about every `tick_ms` (set per-extension in the manifest) — the actor-mode
replacement for a self-spun `run()` poll loop. No `run()`, no dedicated
thread: the host owns the cadence, the actor owns one tick's work, and the
generic `<agent> stop` quiesces it.

```rust
use vos::actors::context::ServiceId;
use vos::prelude::*;
use vos::value::Msg;

#[actor(caps = ["net.libp2p.dial"])]
pub struct Heartbeat {
    pings_sent: u32,
}

#[messages]
impl Heartbeat {
    pub fn new() -> Self { Self { pings_sent: 0 } }

    /// Called by the host roughly every `tick_ms`. One tick = one ping.
    /// No inbound caller, so an outbound `ctx.ask_dispatch` relays as
    /// `Unauthenticated` (bounded by the extension's declared `intra_caps`).
    #[msg]
    async fn tick(&mut self, ctx: &mut Context<Self>) {
        let echo = Msg::new("echo").with("text", "heartbeat-ping");
        let mut payload = vec![vos::value::TAG_DYNAMIC];
        payload.extend_from_slice(&echo.encode());
        if ctx.ask_dispatch(ServiceId(1), &payload).await.is_some() {
            self.pings_sent += 1;
        }
    }
}
```

Enable ticking in the space manifest:

```toml
[[extension]]
name = "heartbeat"
path = "…/libheartbeat_extension.so"
tick_ms = 100        # call `tick` ~every 100ms; omit / 0 = no ticking
```

Cadence is best-effort: a long-running invoke legitimately delays the next
tick (the host never preempts a handler). Ticking is sequential w.r.t. the
actor's other `#[msg]` handlers — `tick` takes `&mut self`, so it never
races them.

## src/lib.rs — Transport kind

A transport extension serves connections; the host owns the listener.
Declare `kind = "transport"`, take `&self` on `handle_connection` (many
connection tasks run concurrently, sharing the actor), and keep live state
behind a `#[rkyv(with = vos::rkyv::with::Skip)] OnceCell<…>` with interior
mutability (`Cell`/`RefCell` — it's single-threaded, one cooperative
executor). A transport extension has **no `#[msg]` handlers** in v1.

```rust
use vos::prelude::*;

#[actor(kind = "transport", caps = ["net.tcp.bind"])]
pub struct EchoServer {
    cfg: MyConfig,                                   // rkyv-persisted
    #[rkyv(with = vos::rkyv::with::Skip)]
    inner: std::cell::OnceCell<State>,               // live, single-threaded
}

#[messages]
impl EchoServer {
    fn new(args: &[u8]) -> Self { /* parse init args */ }

    /// One accepted connection. The host bound the listener (from the
    /// manifest's `bind_addr`/`port`), accepted + (optionally) terminated
    /// TLS, and spawned this task. Read/write plaintext via `ctx`.
    async fn handle_connection(&self, ctx: &mut Context<Self>, conn_id: u64) {
        while let Some(bytes) = ctx.read(conn_id, 4096).await {
            if bytes.is_empty() || ctx.write(conn_id, &bytes).await.is_none() {
                break;
            }
        }
        ctx.close(conn_id).await;
    }
}
```

The host binds the socket from the manifest (`bind_addr` + `port`, optional
`tls_cert`/`tls_key`) and caps concurrent connection tasks (`serves_max`,
default 1024) — see `extensions/http-gateway` for the full HTTP example.

## Capabilities

Declare what OS access the extension needs. Log-only today (the cap-gated
host vtable went away with service-mode); an operator review can still spot
a sketchy install, and a future enforcement layer will consult them.

```rust
#[actor(caps = ["fs.read:/etc/...", "net.tcp.connect"])]
pub struct ConfigLoader { /* ... */ }

#[actor(kind = "transport", caps = ["net.tcp.bind"])]
pub struct MyServer { /* ... */ }
```

Conventional tokens (loose; not enforced):
- `net.tcp.bind`, `net.tcp.connect`, `net.udp.bind`, `net.udp.connect`
- `net.libp2p.dial`
- `fs.read:/path/...`, `fs.write:/path/...`
- `process.spawn`, `thread.spawn`

Add new ones freely — the meta blob carries any `&'static str`.
Convention will harden once an enforcement layer wants them.

## Context API surface

Handlers reach the host through `&mut Context<Self>`. The relevant calls:

```rust
// Ask another local actor / extension on the host invoke path — reaches PVM
// agents + extensions, status-framed (a handler panic is distinguishable
// from an empty `()` reply). Relays the real caller bounded by the
// extension's declared `intra_caps`. None on transport failure / timeout.
pub async fn ask_dispatch(&mut self, target: ServiceId, payload: &[u8]) -> Option<Vec<u8>>;

// Byte-stream effects for a transport connection task (conn_id from
// handle_connection): plaintext read / write / close over the host-owned,
// TLS-terminated socket.
pub async fn read(&mut self, conn_id: u64, max: u32) -> Option<Vec<u8>>;
pub async fn write(&mut self, conn_id: u64, data: &[u8]) -> Option<usize>;
pub async fn close(&mut self, conn_id: u64);

// This agent's ServiceId.
pub fn id(&self) -> ServiceId;
```

## Manifest entry

Either kind installs the same way (transport adds `bind_addr`/`port`,
periodic actors add `tick_ms`):

```toml
[[extension]]
name = "gateway"
path = "../target/debug/libhttp_gateway.so"
init = {
    bind_addr = "127.0.0.1",
    port      = 18080,
}
```

Boot the daemon:
```bash
vosx space up <space> --manifest <path/to/space.toml>
```

The reconciler logs the load + caps, registers the extension on the
live `VosNode`, and the extension starts.

## Testing

Two layers:

1. **Unit / wire-level** — test the logic of your extension as
   plain Rust (no `.so` load). See
   `extensions/http-gateway/src/routing.rs` tests for the pattern:
   build an internal `Request` directly, call the dispatch
   function, assert on the `Response`.

2. **End-to-end** — load the .so via `vos::extension::ExtensionPlugin`
   or register it on a `VosNode` and drive it. See
   `extensions/http-gateway/tests/dispatch_e2e.rs` (transport boot + HTTP
   round-trip) and `extensions/dev/tests/e2e.rs` (actor-mode CLI dispatch).
   Add a `[dev-dependencies]` block to your `Cargo.toml`:

   ```toml
   [dev-dependencies]
   vos = { path = "../../vos", default-features = false,
           features = ["extension", "std", "network", "storage", "http"] }
   ```

   The `std` feature unlocks `vos::node::VosNode` and friends; the
   library build keeps `default-features = false` so the cdylib
   stays lean.

## Limitations (V1)

- Init args are whatever `vos::value::Args::decode` parses — the same wire
  format for actor- and transport-mode constructors.
- Caps are declared but not host-enforced yet (log-only).
- `ask_dispatch` reply correlation is per-call async on the invoke path;
  actor-mode dispatch itself is N=1 (one handler at a time).
- A transport extension has no `#[msg]` handlers in v1 — it serves
  connections only.

These all lift in follow-on phases as concrete needs surface.
