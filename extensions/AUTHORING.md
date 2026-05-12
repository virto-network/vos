# Writing a VOS extension

Extensions are native `.so` plugins the host loads alongside its PVM
agents. Two flavours: **Actor** (request-driven, today's worker
shape) and **Service** (long-running, owns its own thread + runtime).

This is the cookbook. The book chapter at
[`docs/extensions.md`](../docs/extensions.md) is the reader-facing
intro.

## When to pick which kind

- **Actor** if the extension's job is "PVM agent calls in, helper
  runs, replies, done". No long-lived state, no listening sockets,
  no internal runtime. Examples: `examples/extensions/echo`,
  `examples/extensions/fetcher`, `examples/extensions/proxy`.

- **Service** if the extension owns something the host shouldn't
  manage on its behalf — a TCP listener, a tokio/quinn runtime, a
  background task that needs to wake itself up. Examples:
  `extensions/http-gateway`, `examples/extensions/heartbeat`.

If you find yourself writing `serve()` or `listen()` or
`accept_loop` as an Actor handler that blocks indefinitely, you
want a Service.

## Cargo.toml — Actor kind

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

The `bin` feature gates the `vos_extension_*` extern fn exports —
keep it on for the produced `.so`, off when another crate pulls
this one in as an `rlib` for its `Ref` types.

## Cargo.toml — Service kind

Identical to Actor — same features, same crate-type. The only
difference is what the source emits.

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

Same story as PVM actors. `#[messages]` emits the dispatch enum +
the `vos_extension_*` C ABI symbols on the cdylib build.

## src/lib.rs — Service kind

```rust
use vos::extension::ServiceCtx;
use vos::log;

pub struct Heartbeat {
    pings_sent: u32,
}

impl Heartbeat {
    /// Constructor — `args` is the rkyv-encoded `vos::value::Args`
    /// from the manifest's `init = { ... }` block.  Decode whatever
    /// you need, ignore the rest.
    pub fn new(_args: &[u8]) -> Self {
        Self { pings_sent: 0 }
    }

    /// The single entry point.  The host calls this once on a
    /// dedicated thread and waits for it to return.  Return `0` for
    /// clean exit, non-zero for an error code the host logs.
    pub fn run(&mut self, ctx: ServiceCtx) -> i32 {
        while !ctx.is_shutdown() {
            // Originate a call into another actor.  Blocks until
            // reply or shutdown.
            let _ = ctx.ask_raw(/* target */ 1, /* payload */ &[]);
            self.pings_sent += 1;
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        log::info!("heartbeat: stopped after {} pings", self.pings_sent);
        0
    }
}

vos::service_main!(Heartbeat, caps = ["thread.spawn"]);
```

## Capabilities

Declare what OS access the extension needs.  Log-only today; an
operator review can spot a sketchy install.

For Actor kind:
```rust
#[actor(caps = ["fs.read:/etc/...", "net.tcp.connect"])]
pub struct ConfigLoader { /* ... */ }
```

For Service kind:
```rust
vos::service_main!(MyService, caps = ["net.tcp.bind", "tokio-runtime"]);
```

Conventional tokens (loose; not enforced):
- `net.tcp.bind`, `net.tcp.connect`, `net.udp.bind`, `net.udp.connect`
- `fs.read:/path/...`, `fs.write:/path/...`
- `tokio-runtime`, `thread.spawn`

Add new ones freely — the meta blob carries any `&'static str`.
Convention will harden once an enforcement layer wants them.

## ServiceCtx API surface

`ServiceCtx` is `Copy + Send + Sync` — clone freely into spawned
tasks. All methods take `&self`; the host serialises concurrent
callers through its mpsc channels.

```rust
// Originate a call.  Blocks until reply or shutdown.  None on
// transport error or shutdown.
pub fn ask_raw(&self, target: u32, payload: &[u8]) -> Option<Vec<u8>>;

// Same with explicit timeout (ms).  0 = block forever.
pub fn ask_raw_with_timeout(&self, target: u32, payload: &[u8], timeout_ms: u64) -> Option<Vec<u8>>;

// Receive a non-reply envelope (control message addressed to this
// extension).  Blocks up to `timeout_ms`; None on timeout or
// shutdown.  0 = block forever.
pub fn recv_envelope(&self, timeout_ms: u64) -> Option<(u32, Vec<u8>)>;

// Non-blocking shutdown check.  Poll between blocking ops; exit
// `run` cleanly when it returns true.
pub fn is_shutdown(&self) -> bool;
```

## Manifest entry

Either kind installs the same way:

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
   plain Rust (no `.so` load).  See
   `extensions/http-gateway/src/routing.rs` tests for the pattern:
   build an internal `Request` directly, call the dispatch
   function, assert on the `Response`.

2. **End-to-end** — load the .so via `vos::extension::ExtensionPlugin`
   (Actor) or register it on a `VosNode` (either kind).  See
   `extensions/http-gateway/tests/service_mode.rs` for a full
   service-mode boot + HTTP round-trip + clean shutdown e2e.
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

- No init args for `service_main!` callers beyond what
  `vos::value::Args::decode` parses — same wire format as actor-mode
  init args.
- No persistent state for service extensions — fresh on each boot.
- One in-flight `ask_raw` per logical caller chain — the host's reply
  correlator is FIFO-by-sender, not request_id keyed.  Concurrent
  callers serialize.
- No CLI subcommand surface yet — extensions are configured via
  manifest `init` and controlled via their own surfaces (the gateway
  has admin HTTP).

These all lift in follow-on phases as concrete needs surface.
