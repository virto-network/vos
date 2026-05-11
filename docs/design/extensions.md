# Extensions: rename + rearchitecture

> Design note. Not part of the book TOC. Status: **proposed**, 2026-05-10.

## Why

Today's `workers/` directory contains two qualitatively different
things under one name:

- **Native actors that PVM agents call into for I/O.** Echo, fetcher,
  proxy. They're message-driven: handler runs, yields effects (host
  fetch, ask another actor), produces a reply, returns. Pure request /
  response. The runtime mechanism behind them — the C ABI in
  `vos/src/worker.rs` — is essentially "actor that runs natively
  instead of in the PVM".

- **Long-running services that *expose* actors to the outside world.**
  `workers/http-gateway/` listens on TCP, parses HTTP, looks up an
  actor in the registry, originates `ctx.ask` calls into it, returns
  the JSON reply on the wire. It's not an actor that gets called — it's
  a daemon that calls *out* and is wedged into the worker ABI today
  because that's the only host-plugin mechanism available.

The mismatch shows up in the gateway's source: `serve()` blocks the
worker dispatch loop forever, the tokio runtime is smuggled into a
side thread, and reply correlation is ad-hoc. The lib.rs comment is
explicit: *"When vos exposes worker self-pumping, serve* can become a
non-blocking bootstrap and the actor messages will work mid-flight."*

The plan below introduces that "self-pumping" mode as a first-class
extension shape, renames `workers` → `extensions` to capture both
flavors under one role-level concept, and adds a CLI dispatch path so
extensions can extend `vosx` natively (`vosx gateway start --port 8080`,
not `vosx space call gateway serve port=8080`).

## Vocabulary

The current code conflates **role** ("a thing that extends what `vosx`
can natively do") with **mechanism** ("a `.so` plugin loaded with
libloading and driven by a dispatch / poll cycle").

After the rename:

| Concept | Today | Tomorrow |
|---|---|---|
| Role (user-facing) | "worker" | **extension** |
| Mechanism (host-internal dispatch primitive) | `WorkerPlugin`, `WorkerInstance` | `ExtensionPlugin`, `ExtensionInstance` |
| Trait declaring an actor needs OS access | `WorkerActor` | `Extension` |
| Trait giving I/O methods on `Context` | `WorkerCtx` | `ExtensionCtx` |
| Host-side config | `WorkerConfig` | `ExtensionConfig` |
| Host-side register call | `register_worker` | `register_extension` |
| C ABI symbol prefix | `vos_worker_*` | `vos_extension_*` |
| Cargo feature on `vos` | `worker` | `extension` |
| Module path | `vos::worker` | `vos::extension` |
| Filesystem dir | `workers/`, `examples/workers/` | `extensions/`, `examples/extensions/` |
| Manifest section | `[[worker]]` (aspirational) | `[[extension]]` |

Pre-1.0 + no out-of-tree plugins → we rename the C ABI symbols cleanly
without keeping aliases.

## Two extension shapes

A `kind` field in the extension's metadata blob (`ExtensionMeta`)
distinguishes:

### `kind = Actor` — request-driven (today's behavior)

Lifecycle:

```
create(args)  → instance
dispatch(msg) → poll → poll → ... → ready(reply)
                   ↑       ↓
                   └─ host fulfills EFFECT_ASK / EFFECT_FETCH ─┘
drop(instance)
```

C ABI: `vos_extension_{create,dispatch,poll,pending_effect,provide_result,drop,free,load,state,meta}` — exactly the current worker ABI, renamed.

Use cases: `echo`, `fetcher`, `proxy`. Anything that reacts to incoming
messages and doesn't need to own a thread.

### `kind = Service` — long-running (new)

Lifecycle:

```
create(args)         → instance
run(ctx_handle)      → blocks until shutdown; returns status
                       ↓
                       ctx_handle.send(target, payload) -> request_id
                       ctx_handle.recv_reply(request_id) -> bytes  (await reply)
                       ctx_handle.recv_envelope() -> Envelope        (control msgs in)
                       ctx_handle.shutdown_signaled() -> bool
stop(instance)       → flips a shutdown flag; run() returns
drop(instance)
```

The host calls `run` once on a dedicated OS thread; the extension owns
its concurrency (typically a tokio runtime). Control messages addressed
to the extension's `ServiceId` arrive on `ctx_handle.recv_envelope()`
and the extension dispatches them to handler functions however it likes
— a service in Rust can use the same `#[messages]` macro to generate
a control-message dispatcher just like an actor-mode extension.

Use cases: `http-gateway`, future Kunekt encryption / sync gateways,
metric exporters, anything with a port to bind or a runtime to own.

### Why one ABI, not two

A two-symbol-set ABI (`vos_extension_actor_*` vs `vos_extension_service_*`)
would be cleaner on paper but doubles the loader code and forces every
extension to pick a single mode at compile time. Today's design lets
the metadata declare it, the loader picks the right code path, and the
two modes share the lifecycle primitives that don't differ
(`create`, `drop`, `state`, `meta`).

## Bidirectional ctx (the actually hard part)

Service-mode extensions need to originate `ctx.ask` calls *outside* a
dispatch handler. Today's worker ABI has no concept of this — `ctx`
exists only inside `dispatch_and_poll`.

### What service `ctx` needs to do

1. **Originate request → reply.** Given a target `ServiceId` and a
   payload, send to the host's outbox, get a future that resolves with
   the reply.
2. **Receive control messages.** Read incoming envelopes (control RPC
   from `vosx <ext> *` clients, messages from peer actors).
3. **Survive concurrency.** Multiple in-flight `ask` calls from
   different tokio tasks; replies must correlate to the right awaiter.
4. **Surface shutdown.** A way for tokio tasks to wake up and exit
   cleanly when `stop()` is called.

### Design

The host gives the extension a small set of C ABI callbacks:

```c
// Originate a message; returns a per-request opaque correlation id.
uint64_t vos_host_send(ctx_handle, target_id, payload, len);

// Block until the reply for `request_id` arrives. Returns reply
// bytes (caller frees with vos_host_free_reply).
ReplyBuf vos_host_recv_reply(ctx_handle, uint64_t request_id, uint64_t timeout_ms);

// Block until any incoming envelope arrives that isn't a tracked reply.
EnvelopeBuf vos_host_recv_envelope(ctx_handle, uint64_t timeout_ms);

bool vos_host_shutdown_signaled(ctx_handle);
```

The Rust-side wrapper in `vos::extension` packages this into:

```rust
pub struct ServiceCtx { handle: *mut HostCtx, /* ... */ }

impl ServiceCtx {
    pub async fn ask(&self, target: ServiceId, msg: &Msg) -> Reply { ... }
    pub async fn recv_envelope(&self) -> Option<Envelope> { ... }
    pub fn is_shutdown(&self) -> bool { ... }
}
```

Internally `ServiceCtx` runs a small reply demultiplexer: one OS thread
(or tokio blocking task) calls `vos_host_recv_envelope` in a loop;
incoming envelopes either match a pending request_id (oneshot fires)
or get pushed to the user-facing envelope channel.

Reply correlation re-uses the existing `request_id` field that
`actors/run.rs` already threads through `Ask` / `dispatch_and_poll` —
the host just needs to expose it on the wire and on the demultiplexer
side.

### Routing model: ask vs tell, invoke vs outbox

Two host-side channels carry traffic into and out of an extension:

- **Outbox / inbox (envelope path).** Fire-and-forget. The host's
  outbox dispatcher routes envelopes by `to`; replies arrive on the
  inbox addressed `from = target`. Authors interact with it through
  `ctx.recv_envelope()` (and a future `ctx.tell(target, payload)`
  for sending). Used for: control RPC from `vosx <ext> *`, async
  notifications, gossip from peer actors.
- **Invoke channel (sync RPC path).** Each agent and actor-mode
  extension registers a dedicated `Receiver<InvokeRequest>` in
  `node::invoke_routes`. The wire envelope is
  `[status][state_len:u32][state][reply]` so YIELDED/DONE
  bookkeeping for the PVM continuation model rides alongside the
  user payload. Authors interact with it through `ctx.ask_raw`.
  PVM agents reply *only* through this channel — they have no
  envelope outbox.

`ServiceCtx::ask_raw` routes through invoke as of commit 05178e1.
That's the only ask primitive exposed today. A future `ctx.tell`
will route through outbox; the two stay distinct because their
semantics differ (sync request/reply with continuation state vs
async fire-and-forget envelope), not because the wire format is
duplicated.

The legacy `vh_send` / `vh_recv_reply` vtable callbacks stay live
for the existing one-in-flight extension-to-extension tests and
the eventual `tell` surface, but they aren't on the ask hot path
anymore. The dispatch_e2e suite proves the envelope-mode path
still works; the gateway → PVM path proves the invoke path works
end-to-end (see `vosx/tests/gateway_pvm_e2e.rs`).

### Persistence

Service-mode persistence is opt-in (default off). The lifecycle hook
`save_state(&self) -> Vec<u8>` is called on graceful shutdown only;
restored via `load_state(bytes)` on next boot. Per-message persistence
doesn't make sense for things like a gateway whose state is a request
counter that mutates 10× per second. Authors who need point-in-time
snapshots can call a host-provided `ctx.persist_now()` from inside
`run`.

## CLI dispatch (`vosx <ext> <cmd>`)

Today, `vosx space *` is hand-coded against the bundled space-registry.
Generalizing it: each extension declares CLI subcommands in its
metadata blob; vosx walks installed extensions on `--help` / parse
and dynamically extends clap.

### Schema (in `ExtensionMeta`)

```toml
[extension.cli]
verb = "gateway"  # the top-level subcommand vosx exposes
[[extension.cli.command]]
name = "start"
invoke = "serve"  # the message handler on the extension
description = "Bind on the configured port and start serving."
[[extension.cli.command.arg]]
name = "port"
typ = "u16"
required = false
default = "8080"
[[extension.cli.command]]
name = "stop"
invoke = "stop"
[[extension.cli.command]]
name = "status"
invoke = "status"
```

`vosx gateway start --port 8080` resolves to:

1. Look up the extension by `verb = "gateway"` in
   `~/.config/vosx/extensions.toml` (cached at install time).
2. Pick the current space (or `--space <name>`).
3. `DaemonClient::invoke_dyn(<gateway-ext-id>, "serve", {port: 8080u16})`.
4. Print the reply (JSON / `Format::*` per global flag).

### Caching the schema

Loading every extension's metadata blob on every CLI invocation is
expensive (libloading + meta parse). At `space install --extension foo`
time we extract the CLI schema once and write it to
`~/.config/vosx/extensions.toml`:

```toml
[[extension]]
verb = "gateway"
extension_id = "<service-id-hex>"
space = "<space-name>"   # which space owns this extension instance
schema = "<inlined CLI schema TOML>"
```

vosx reads this on every invocation to extend its clap CommandFactory.
A `vosx extension refresh` command rebuilds the cache from currently
installed extensions across all known spaces.

### Per-node vs per-space scope

V1: extensions are per-space (installed via `vosx space install`).
The CLI dispatches through the space's daemon. `vosx gateway start`
without `--space` picks the first space that has a `gateway` extension
installed.

Future: per-node extensions (one HTTP listener fanning out across
spaces) get a separate code path that loads + runs the extension
inside the vosx process directly, no daemon. Out of scope for V1.

## Capability declarations

Extensions break the PVM sandbox — they get full OS access. Make this
visible in the metadata so a manifest review can spot a sketchy install:

```toml
[extension]
caps = [
  "net.tcp.bind",
  "net.tcp.connect",
  "fs.read:/etc/tls/",
  "fs.read:/etc/tls/",
  "thread.spawn",
  "tokio-runtime",
]
```

V1: declaration only. Logged at load time. No enforcement. Future:
Linux-side seccomp / namespaces could enforce, but that's a different
project.

## Migration phases

Order chosen so each phase leaves the workspace in a building, testing
state with no dangling abstractions.

### Phase 1 — Mechanical rename

Pure mechanical; no semantic change.

- Filesystem: `workers/` → `extensions/`, `examples/workers/` → `examples/extensions/`.
- Cargo workspace member paths in root `Cargo.toml`.
- Path refs in every extension's `Cargo.toml` (`workers/http-gateway/Cargo.toml`, three `examples/workers/*/Cargo.toml`, `examples/wasm/fetcher` reuses fetcher source via path).
- `vos/src/worker.rs` → `vos/src/extension.rs`. `pub mod worker;` → `pub mod extension;` in `lib.rs`. All re-exports updated.
- Type renames in `vos/src/extension.rs`, `vos/src/node.rs`, `vos/src/actors/context.rs`:
  - `WorkerPlugin` → `ExtensionPlugin`
  - `WorkerInstance` → `ExtensionInstance`
  - `WorkerActor` → `Extension`
  - `WorkerCtx` → `ExtensionCtx`
  - `WorkerConfig` → `ExtensionConfig`
  - `register_worker` → `register_extension`
  - `worker_thread` → `extension_thread`
  - `WorkerPollResult` → `ExtensionPollResult`
- C ABI symbol rename: `vos_worker_*` → `vos_extension_*`. Generated by `vos-macros::actor`/`messages`; flip the symbol prefix in one place.
- Cargo feature rename: `worker = []` → `extension = []` in `vos/Cargo.toml`. Update every `features = ["worker"]` to `features = ["extension"]` across the workspace.
- `lints.rust.unexpected_cfgs` `check-cfg` arrays still listing `"worker"` get the new value.
- `[[worker]]` manifest section → `[[extension]]` (today only commented in `examples/space.toml`).
- `vosx` build script copy of the bundled extension blob: paths.
- README + book references: "worker" → "extension" in user-facing prose. Internal references to "the worker dispatch ABI" can stay as-is (it IS the dispatch primitive).
- Tests: `worker_*` test names → `extension_*`.

Validation: `cargo check --workspace`, `cargo test --workspace`,
`cargo build` of every excluded `examples/extensions/*` and the
`workers/http-gateway` (now `extensions/http-gateway`) stays green.

Estimated diff: ~50 files, almost entirely renames and string substitutions.

### Phase 2 — `kind` field in ExtensionMeta

No new behavior; lays groundwork.

- Add `kind: ExtensionKind { Actor, Service }` to the metadata
  emitted by `#[actor]` / `#[messages]`.
- Default to `Actor` for every existing extension.
- `vos-macros` accepts `#[actor(kind = "service")]` to flip it. Inert
  for now — host loader still treats every extension as actor-kind in
  Phase 2.

Validation: meta blob round-trips; extensions still load and run.

### Phase 3 — Service ABI implementation

The actually-new mechanism.

- New C ABI symbols in `vos-macros` (gated on `kind = "service"`):
  - `vos_extension_run(state, ctx_handle) -> i32`
  - `vos_extension_stop(state)`
- Host-side `ServiceCtx` and `HostCtx` types in `vos/src/extension.rs`.
- Host callbacks: `vos_host_send`, `vos_host_recv_reply`,
  `vos_host_recv_envelope`, `vos_host_shutdown_signaled`,
  `vos_host_free_reply`, `vos_host_free_envelope`.
- `node::register_extension` branches on `meta.kind`:
  - `Actor` → existing `extension_thread` (today's `worker_thread`).
  - `Service` → new `service_thread`: builds `HostCtx`, calls
    `extension.run(ctx_handle)`, drives the reply demultiplexer.
- Reply correlation: extend `dispatch_and_poll`'s in-flight tracking
  to support multiple concurrent requests keyed by `request_id`. The
  existing `wait_for_reply` becomes one user of the underlying
  correlator.
- A test extension `examples/extensions/heartbeat/` that pings a
  counter every 100ms in `kind = "service"` mode. Validates the
  full ABI.

Validation: heartbeat test extension runs, originates 10 asks to a
counter actor, sees correct replies, exits cleanly on shutdown.

### Phase 4 — http-gateway as a service-kind extension

The validation target. Removes the smuggled tokio runtime; replaces
the side-thread channel with proper `ServiceCtx` calls.

- `extensions/http-gateway/Cargo.toml` declares `kind = "service"`.
- `serve(port)` no longer blocks the dispatch loop — it's the body of
  `run(ctx_handle)`. Admin routes (`/__admin/stop`, `/__admin/status`)
  flip a flag the run loop checks; control messages (e.g.
  `gateway.status`) come in via `ctx.recv_envelope()`.
- The hyper accept loop spawns a task per connection; per-task asks
  go through `ServiceCtx::ask`.
- HTTP/3 stays gated behind `feature = "http3"`.
- Integration test: spin up a counter actor + http-gateway in a space,
  GET `/counter/inc`, verify the counter incremented.

Validation: existing http-gateway tests pass; new e2e test (counter
over HTTP) passes.

### Phase 5 — CLI dispatch from extension metadata

The `vosx <ext> <cmd>` surface.

- Extend `ExtensionMeta` with the `cli` schema described above.
- `space install` (when adopting an extension) extracts the CLI schema
  and writes it to `~/.config/vosx/extensions.toml`.
- `vosx::main` runs `Cli::command()`, then walks
  `extensions.toml` and inserts a dynamic `Subcommand` per declared
  `verb`. Reparse with the augmented command tree.
- Each dispatched subcommand → `DaemonClient::invoke_dyn(ext_id, invoke, args)`.
- New top-level `vosx extension list` / `vosx extension refresh`
  for cache management.

Validation: `vosx gateway start --port 8080` on an installed
http-gateway extension binds, serves, and replies. `vosx gateway status`
works. `vosx gateway stop` works.

### Phase 6 — Capabilities

Declaration-only.

- `caps = [...]` field in `ExtensionMeta`.
- Logged at load time with `tracing::info!`.
- `vosx space info` / `vosx extension list` print caps.
- No enforcement.

### Phase 7 — Docs

- New book chapter `docs/extensions.md` (Part I — Platform).
- An `extensions/AUTHORING.md` explaining the two kinds, the ABI, the
  CLI schema, and the capability declaration.
- Update `examples/space.toml` to use `[[extension]]` (was
  commented-out `[[worker]]`).
- Update `README.md`'s "Writing an actor" section with a sibling
  "Writing an extension" subsection.

## Open questions / tradeoffs deferred to execution

1. **Macro vs runtime declaration of `kind`.** Today `#[actor]` is
   compile-time. We could either (a) parse `kind = "service"` as an
   attribute arg and emit different ABI symbols, or (b) emit both ABI
   surfaces and let the metadata pick at runtime. (a) is smaller
   binaries; (b) makes the `kind` switchable without a recompile.
   Going with (a) — the kind is a fundamental design choice for the
   extension, not a deployment knob.

2. **Reply timeouts.** `recv_reply(request_id, timeout_ms)` —
   default? configurable per-call? Per-extension? Start with
   per-call, default 5 minutes, configurable via `ServiceCtx::ask`
   builder.

3. **Restart on panic.** Today's worker_thread panics → the agent
   shows up in `node.collect()` with `panics: 1`. Service extensions
   could optionally restart-on-panic. Defer; require explicit
   author opt-in.

4. **Rate limit / backpressure on origination.** A buggy service
   could fire 10k asks per second at a slow actor. The reply
   correlator should bound in-flight requests per extension. Pick a
   default in Phase 3.

5. **Authentication / authority for CLI dispatch.** `vosx gateway
   stop` from another machine with daemon access can stop the
   gateway. Same trust model as `vosx space call` today (LAN /
   localhost). Capabilities and per-command auth tokens are a
   separate piece.

6. **WASM extensions?** WASM actors today are sandboxed (no OS
   access). They aren't extensions in the role sense — they don't
   extend `vosx`'s native capabilities. WASM stays a third execution
   shape (PVM / native / WASM), not an extension kind.

## Out of scope

- Per-node extensions (deployed once, span all spaces). All
  extensions are per-space in V1; per-node deferred.
- Hot reload of running extensions.
- Extension marketplace / blob distribution beyond the existing
  blob_store / cache_get model.
- Capability enforcement (only declaration).
