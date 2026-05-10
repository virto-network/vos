# Extensions

An **extension** is a native shared library (`.so` / `.dylib`) that
the VOS host loads alongside its PVM agents. Extensions are the I/O
surface of a space: anything that needs OS access — network sockets,
filesystem, system clock, hardware, threads, async runtimes — lives
inside one. PVM agents stay in the deterministic universe and reach
the outside world through extensions via `ctx.ask`.

## Two kinds

Each extension declares its kind in the `.vos_meta` blob the host
reads at load time:

| Kind | Lifecycle | Use cases |
|---|---|---|
| **Actor** (default) | Request-driven. Each incoming message starts a handler that runs to completion. | `echo`, `fetcher`, `proxy` — small native helpers PVM agents call into for one-shot I/O. |
| **Service** | Long-running. The host calls `run(ctx)` once; the extension owns its thread + any internal runtime (tokio, etc.) and exits when shutdown is signalled. | `http-gateway` — anything that binds a port, owns an event loop, or has internal state that doesn't fit per-message dispatch. |

A PVM agent can't tell the difference: in both cases, an extension is
an entry in the address book that responds to `ctx.ask(target, msg)`.

## Authoring an Actor-mode extension

Same DSL as a PVM actor — `#[actor]` + `#[messages]`, with
`features = ["extension"]` enabling the native cdylib glue.

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
}
```

`Cargo.toml`:

```toml
[lib]
crate-type = ["rlib", "cdylib"]

[features]
default = ["bin", "extension"]
bin = []
extension = []

[dependencies]
vos = { path = "...", default-features = false, features = ["extension"] }
```

Build with `cargo build`; the resulting `target/debug/libecho.so` is
the file an operator points the manifest at.

## Authoring a Service-mode extension

No `#[actor]` / `#[messages]` — service extensions are plain Rust
structs with two methods: `fn new(args: &[u8])` and
`fn run(&mut self, ctx: ServiceCtx) -> i32`. The
`vos::service_main!` macro emits the C ABI glue.

```rust
use vos::extension::ServiceCtx;
use vos::log;

pub struct Heartbeat {
    pings_sent: u32,
}

impl Heartbeat {
    pub fn new(_args: &[u8]) -> Self {
        Self { pings_sent: 0 }
    }

    pub fn run(&mut self, ctx: ServiceCtx) -> i32 {
        while !ctx.is_shutdown() {
            // originate calls into other actors with ctx.ask_raw
            let _reply = ctx.ask_raw(/* target id */ 1, /* payload */ &[]);
            self.pings_sent += 1;
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        log::info!("heartbeat: stopped after {} pings", self.pings_sent);
        0
    }
}

vos::service_main!(Heartbeat, caps = ["thread.spawn"]);
```

`ServiceCtx` is `Copy + Send + Sync` — clone it freely into spawned
tasks. All methods are `&self`; the host serialises concurrent
callers internally through its mpsc channels.

### Init args

The service constructor takes a `&[u8]` slice — the rkyv-encoded
`vos::value::Args` from the manifest's `init = { ... }` block. The
constructor decodes it however it wants:

```rust
pub fn new(args: &[u8]) -> Self {
    use vos::Decode;
    let parsed: vos::value::Args = if args.is_empty() {
        vos::value::Args::default()
    } else {
        vos::value::Args::decode(args)
    };
    let port = parsed.get_u32("port").unwrap_or(8080);
    // ...
}
```

## Installing an extension

Add an `[[extension]]` block to the space manifest:

```toml
[[extension]]
name = "gateway"
path = "../target/debug/libhttp_gateway.so"
init = {
    bind_addr   = "127.0.0.1",
    port        = 18080,
    admin_token = "dev-only-token",
}
```

Then bring the daemon up with the manifest:

```bash
vosx space up <space> --manifest <path/to/space.toml>
```

The manifest reconciler logs the load, registers the extension on
the live `VosNode`, and the extension's `run()` (Service-kind) or
dispatch loop (Actor-kind) starts immediately.

## Capabilities

Extensions break the PVM sandbox by design. Each extension declares
what OS-side superpowers it wants in its meta blob — log-only today,
visible to anyone reviewing the manifest:

```rust
vos::service_main!(MyGateway, caps = [
    "net.tcp.bind",
    "net.tcp.connect",
    "tokio-runtime",
    "thread.spawn",
]);
```

Or, for actor-mode extensions:

```rust
#[actor(caps = ["fs.read:/etc/...", "net.tcp.connect"])]
pub struct ConfigLoader { /* ... */ }
```

The host logs `extension: declared capabilities caps=[...]` at load
time. There's no enforcement in V1 — declarations are an audit
surface, not a sandbox.

Conventional tokens (loose, not enforced):

| Token | Means |
|---|---|
| `net.tcp.bind` | binds a TCP listener |
| `net.tcp.connect` | originates outbound TCP connections |
| `net.udp.bind` / `net.udp.connect` | UDP analogues |
| `fs.read:/path/...` | reads from a specific filesystem path |
| `fs.write:/path/...` | writes to a specific filesystem path |
| `tokio-runtime` | builds a tokio runtime internally |
| `thread.spawn` | spawns OS threads |

## Source map

- [`vos/src/extension.rs`](https://github.com/virto-network/vos/tree/master/vos/src/extension.rs) —
  the C ABI primitives (`ExtensionPlugin`, `ServiceCtx`, host
  vtable + callbacks)
- [`vos-macros/src/lib.rs`](https://github.com/virto-network/vos/tree/master/vos-macros/src/lib.rs) —
  `#[actor(kind = …, caps = […])]` parsing
- [`vos/src/lib.rs`](https://github.com/virto-network/vos/tree/master/vos/src/lib.rs) —
  `service_main!` decl-macro
- [`extensions/http-gateway/`](https://github.com/virto-network/vos/tree/master/extensions/http-gateway) —
  the canonical Service-mode extension
- [`examples/extensions/heartbeat/`](https://github.com/virto-network/vos/tree/master/examples/extensions/heartbeat) —
  minimal Service-mode extension validating the Phase 3 ABI
- [`examples/extensions/{echo,fetcher,proxy}/`](https://github.com/virto-network/vos/tree/master/examples/extensions) —
  Actor-mode extension examples
- [`docs/design/extensions.md`](https://github.com/virto-network/vos/tree/master/docs/design/extensions.md) —
  the original design plan, kept for context

## Open work

- Per-extension shutdown signal (today: shared `node.shutdown` for
  every extension on the node).
- Multi-in-flight `ServiceCtx::ask` correlation by request_id —
  current FIFO model serializes concurrent callers through a single
  in-flight slot. Fine for the gateway; matters when an extension
  needs hundreds of concurrent upstream calls.
- `vosx extension list` / `vosx extension info` operator commands
  to surface installed extensions + their declared caps without
  parsing the manifest by hand.
- Capability enforcement (seccomp, namespaces). The declaration
  surface is in place; the enforcement layer is its own project.
