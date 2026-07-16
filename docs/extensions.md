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
| **Actor** (default) | Request-driven. Each incoming message starts a handler that runs to completion. An optional `async fn tick` handler, driven by a manifest `tick_ms`, lets it originate periodic work. | `echo`, `fetcher`, `proxy`, `dev`, `ai`, `heartbeat` — native helpers PVM agents call into, plus timer-driven background work. |
| **Transport** | Serves a network protocol. The host binds the listener, runs the accept loop, terminates TLS, and spawns one concurrent `handle_connection(&self, …)` task per connection — all sharing `&self` on one cooperative executor. | `http-gateway` — anything that binds a port and frames its own protocol off a byte stream. |

> The original **Service** kind (a self-spun `run(ServiceCtx)` poll loop)
> was removed in the *unify* refactor: the host now owns concurrency, so
> periodic work is a `tick` handler and listening servers are Transport
> extensions.

A PVM agent can't tell the difference between an Actor and a Transport
target: in both cases, an extension is an entry in the address book that
responds to `ctx.ask(target, msg)` (Transport extensions just don't expose
`#[msg]` handlers — they serve connections).

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

## Periodic work: the `tick` handler

To originate work on a schedule (a heartbeat, a cache sweep) rather than
only react to inbound messages, an actor declares an `async fn tick`. The
host calls it about every `tick_ms` (set per-extension in the manifest) —
no `run()` loop, no dedicated thread; the host owns the cadence and the
generic `<agent> stop` quiesces it.

```rust
use vos::actors::context::ServiceId;
use vos::prelude::*;
use vos::value::Msg;

#[actor(caps = ["net.libp2p.dial"])]
pub struct Heartbeat { pings_sent: u32 }

#[messages]
impl Heartbeat {
    pub fn new() -> Self { Self { pings_sent: 0 } }

    /// Called by the host roughly every `tick_ms`. One tick = one ping.
    #[msg]
    async fn tick(&mut self, ctx: &mut Context<Self>) {
        let echo = Msg::new("echo").with("text", "ping");
        let mut payload = vec![vos::value::TAG_DYNAMIC];
        payload.extend_from_slice(&echo.encode());
        if ctx.ask_dispatch(ServiceId(1), &payload).await.is_some() {
            self.pings_sent += 1;
        }
    }
}
```

```toml
[[extension]]
name = "heartbeat"
path = "…/libheartbeat_extension.so"
tick_ms = 100   # call `tick` ~every 100ms; omit / 0 = no ticking
```

Cadence is best-effort (a long invoke delays the next tick — the host
never preempts a handler), and `tick` is sequential w.r.t. the actor's
other `#[msg]` handlers.

## Authoring a Transport extension

A Transport extension serves connections; the host owns the listener.
Declare `kind = "transport"`, take `&self` on `handle_connection` (many
connection tasks run concurrently, sharing the actor), and keep live state
behind a `#[rkyv(with = vos::rkyv::with::Skip)] OnceCell<…>` with
single-threaded interior mutability (`Cell` / `RefCell`). It has **no
`#[msg]` handlers** in v1.

```rust
use vos::prelude::*;

#[actor(kind = "transport", caps = ["net.tcp.bind"])]
pub struct EchoServer { /* rkyv state; live state behind Skip'd OnceCell */ }

#[messages]
impl EchoServer {
    fn new(args: &[u8]) -> Self { /* parse init args */ }

    /// One accepted connection. The host bound the listener (manifest
    /// `bind_addr`/`port`), accepted + (optionally) terminated TLS, and
    /// spawned this task. Read/write plaintext via `ctx`.
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

See `extensions/http-gateway` for the full HTTP example (manifest
`bind_addr`/`port`/`tls_cert`/`tls_key`, plus a `serves_max` connection
cap).

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
    bind_addr = "127.0.0.1",
    port      = 18080,
}
```

Then create the space with the recipe and bring the daemon up:

```bash
vosx space new <space> --recipe <path/to/space.toml>
vosx space up <space>
```

The recipe's node-local `[[extension]]` entries are written to the
space's `local.toml` at genesis apply, and every boot registers them
on the live `VosNode` — the host logs the load and the extension starts
immediately, its message dispatch loop (Actor) or the host's accept
loop (Transport). `vosx space up <path/to/space.toml>` is the one-shot
equivalent (create-if-missing, genesis-apply, boot).

## Capabilities

Extensions break the PVM sandbox by design. Each extension declares
what OS-side superpowers it wants in its meta blob — log-only today,
visible to anyone reviewing the manifest:

```rust
#[actor(caps = ["fs.read:/etc/...", "net.tcp.connect"])]
pub struct ConfigLoader { /* ... */ }

#[actor(kind = "transport", caps = ["net.tcp.bind"])]
pub struct MyServer { /* ... */ }
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
| `net.libp2p.dial` | originates intra-space (libp2p) calls |
| `fs.read:/path/...` | reads from a specific filesystem path |
| `fs.write:/path/...` | writes to a specific filesystem path |
| `process.spawn` / `thread.spawn` | spawns subprocesses / OS threads |

## Source map

- [`vos/src/extension.rs`](https://github.com/virto-network/vos/tree/master/vos/src/extension.rs) —
  the C ABI primitives (`ExtensionPlugin` + the per-task executor ABI)
- [`vos/src/node.rs`](https://github.com/virto-network/vos/tree/master/vos/src/node.rs) —
  the host-side driver: the cooperative executor, the byte-stream
  reactor, and the transport accept loop
- [`vos-macros/src/lib.rs`](https://github.com/virto-network/vos/tree/master/vos-macros/src/lib.rs) —
  `#[actor(kind = …, caps = […])]` + `#[messages]` parsing
- [`extensions/http-gateway/`](https://github.com/virto-network/vos/tree/master/extensions/http-gateway) —
  the canonical Transport extension
- [`examples/extensions/{echo,heartbeat,fetcher,proxy}/`](https://github.com/virto-network/vos/tree/master/examples/extensions) —
  Actor-mode examples (`heartbeat` shows the `tick` handler);
  [`tcp-echo`](https://github.com/virto-network/vos/tree/master/examples/extensions/tcp-echo) is a minimal Transport example
- [`extensions/AUTHORING.md`](https://github.com/virto-network/vos/tree/master/extensions/AUTHORING.md) —
  the full cookbook

## Open work

- Caps are declared but not host-enforced (log-only); a future
  enforcement layer for the actor/transport host ABI will consult them.
- `&self` concurrent inbound `#[msg]` handlers (Actor-mode is N=1 today;
  Transport already runs `handle_connection(&self)` concurrently).
- `vosx extension list` / `vosx extension info` operator commands
  to surface installed extensions + their declared caps without
  parsing the manifest by hand.
- Capability enforcement (seccomp, namespaces). The declaration
  surface is in place; the enforcement layer is its own project.
