# VOS

A peer-to-peer operating system for collaborative, replicated applications.

VOS runs deterministic actors on a JAM-aligned PVM (RISC-V) and replicates
them across nodes using either CRDTs (eventual) or Raft (strict). Spaces
group actors into per-collaboration roots that converge automatically when
peers come online, with no central server and no coordination protocol on
the user's critical path.

## What's in this repo

| Path | What |
|---|---|
| [`vos/`](vos/) | Core runtime: PVM host, scheduler, persistence, networking |
| [`vos/vos-macros/`](vos/vos-macros/) | `#[actor]` / `#[messages]` / `#[msg]` proc-macros |
| [`support/vos-raft/`](support/vos-raft/) | Async Raft implementation used by the `raft` consistency mode |
| [`support/merkle-crdt/`](support/merkle-crdt/) | Merkle-DAG CRDT used by the `crdt` consistency mode |
| [`support/vos-shell/`](support/vos-shell/) | Sandboxed nushell-backed console engine |
| [`vosx/`](vosx/) | Operator-facing CLI (`vosx run …`, `vosx space …`) — see its [README](vosx/README.md) |
| [`actors/`](actors/) | Built-in PVM actors bundled into `vosx` (e.g. `space-registry`) |
| [`extensions/`](extensions/) | Native extension plugins loaded by the runtime (e.g. `http-gateway`) |
| [`zkpvm/`](zkpvm/) | ZK proving for PVM bytecode via Stwo |
| [`examples/`](examples/) | Four v2 actor examples plus extension and WASM API samples |
| [`tests/acceptance/clerk/`](tests/acceptance/clerk/) | Complex replicated-payment acceptance application |
| [`docs/`](docs/) | The VOS Book (architecture, protocols, applications) |

The clean-break service, continuation, wire, package and CRDT contracts—and
their current implementation status—are documented in
[`docs/runtime-v2.md`](docs/runtime-v2.md).

## Quick start

```bash
# Build the protocol-pinned generic service once.
cd services/vos-service && cargo +nightly actor && cd ../..
cargo run -p vosx -- service-pvm \
  services/vos-service/target/riscv64em-javm/release/vos_service.elf \
  --out dist/vos-service.pvm

# Build one canonical application PVM and its signed .vos package.
cargo run -p vosx -- build examples/actors/counter \
  --service-pvm dist/vos-service.pvm

# Cross-root names are signed package dependencies, not ambient routes.
cargo run -p vosx -- build examples/actors/age-gate \
  --service-pvm dist/vos-service.pvm \
  --external-actor private-age

# The local conformance runner installs and executes the same service PVM.
cargo run -p vosx -- run dist/Counter.vos \
  --service-pvm dist/vos-service.pvm \
  --method value
```

## Consistency modes

Each installed root actor tree picks one `consistency` mode. Its owned children
share the same JAM service, scheduler, state transaction, and replication mode:

| Mode | Replication | Read-from-any-replica | Writes block on |
|---|---|---|---|
| `ephemeral` | none, in-memory | n/a | nothing |
| `local` | redb on local disk | n/a | local fsync |
| `crdt` | merkle-CRDT, eventual | yes | local commit |
| `raft` | Raft consensus, strict | leader only (today) | quorum ack |

CRDT is available only to `#[actor(crdt)]` programs whose fields use explicit
convergent types such as `Counter`, `Value`, `Map`, `Set`, `List`, and `Text`.
Raft fits strictly sequenced state where divergence corrupts (ledgers,
unique-name registries). Modes mix freely between root services.

Raft requires a cluster membership list (every replica's `node_prefix`). The
daemon driver and package flow are documented in
[`docs/runtime-v2.md`](docs/runtime-v2.md).

```bash
just test                              # rebuild artifacts + full integration suite
```

## Multi-node

The admin node installs agents once; a joiner never boots its own
manifest — it redeems an invite token and syncs the catalog from the
registry.

```bash
# host A — create with a genesis recipe, boot, then invite a member
vosx space new a --recipe ./my-space.toml
vosx space up a --listen /ip4/0.0.0.0/tcp/4811 &   # first boot genesis-applies the recipe
vosx space info a            # prints the node's bootnode hint:
                             #   /ip4/.../tcp/4811/p2p/<peer-id>
vosx space invite a --role member --bootnode <bootnode-hint>
                             # prints a vos1… token on its first stdout line

# host B — redeem the token: join-if-needed + boot + auto-redeem
vosx space up "<paste-the-vos1-token>" &
                             # or  vosx space up -  to read the token from stdin
```

The TOML recipe is a devhelper, not the runtime source of truth —
the registry is. A recipe is consumed once at genesis (the space's
first boot) to seed the registry; thereafter the registry is
authoritative and joiners sync agents from it. `space export`
re-derives a recipe from the live registry; `space apply`
reconciles a recipe against a running space.

## Writing an actor

```rust
use vos::prelude::*;

#[actor]
pub struct Counter { count: u64 }

#[messages]
impl Counter {
    fn new() -> Self { Counter { count: 0 } }

    #[msg]
    async fn inc(&mut self) { self.count += 1; }

    #[msg]
    async fn get(&self) -> u64 { self.count }
}
```

`#[actor]` emits the canonical actor PVM entrypoint. The generic VOS service,
not application code, owns Refine and Accumulate. `#[messages]` generates the
per-handler message types, the `CounterRef` reference marker, and a bound handle
whose methods need no extra context argument:

```rust
use counter::CounterRef;

let mut counter = ctx.actor::<CounterRef>("counter").await?;
counter.inc().await?;
let n = counter.get().await?;
```

`vosx new counter` creates the target configuration that injects `no_std` and
`no_main` plus the required `core,alloc,compiler_builtins` build-std flags.
Use `vosx new shared-board --crdt` for an explicit CRDT template.
Declare every cross-root dependency with repeatable `vosx build
--external-actor <installed-name>` flags. These names are covered by the
package signature and resolve to exact signed deployments when the space
starts; upgrading a dependency therefore requires rebuilding the consumer.

## Writing an extension

An **extension** is a native `.so` plugin that runs alongside PVM
agents and gives them OS access — sockets, filesystem, threads,
async runtimes. PVM agents reach the outside world by `ctx.ask`-ing
extensions. Two kinds:

- **Actor** — request-driven, same `#[actor]` / `#[messages]` DSL
  as PVM agents, just compiled as a cdylib. Add an `async fn tick`
  handler (driven by a manifest `tick_ms`) to originate periodic work.
- **Transport** — serves a network protocol on a socket the host
  binds for it. You write `handle_connection(&self, ctx, conn_id)`;
  the host owns the listener + accept loop and spawns one concurrent
  connection task per accept, all sharing `&self`.

```rust
use vos::prelude::*;

#[actor(kind = "transport", caps = ["net.tcp.bind"])]
pub struct MyServer { /* state */ }

#[messages]
impl MyServer {
    fn new(args: &[u8]) -> Self { /* parse init args */ }

    // The host binds the listener (from the manifest's bind_addr/port),
    // accepts + terminates TLS, and drives one task per connection.
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

Install via the manifest:

```toml
[[extension]]
name = "gateway"
path = "../target/debug/libmy_gateway.so"
init = { bind_addr = "127.0.0.1", port = 8080 }
```

See [`extensions/AUTHORING.md`](extensions/AUTHORING.md) for the
full cookbook and [`docs/extensions.md`](docs/extensions.md) for the
book chapter. The canonical transport example is
[`extensions/http-gateway/`](extensions/http-gateway/).

## Applications

VOS is a substrate. Concrete applications are built on top of it as
groups of actors and services.

### Kunekt — private-by-default collaboration

**Kunekt** is the headline application that the design of VOS was originally
shaped around: a protocol for private, decentralized real-time collaboration.
It combines the VOS runtime with three protocol layers:

1. **Sync** — Merkle-CRDT documents propagated via the standard `crdt`
   consistency mode.
2. **Encryption** — group ratchet keys (MLS-style) so peers and storage
   backends only ever see opaque blobs.
3. **Persistence** — encrypted DAG nodes can ride on any content-addressed
   backend (relay, DHT, DA layer) since storage doesn't need to be trusted.

Kunekt itself is exposed as a built-in actor/service group inside VOS, with
its own slice of the documentation covering the protocol layers, threat
model, and integrations (Nostr, anonymous credentials, zk-promises). See
[`docs/kunekt.md`](docs/kunekt.md).

## Development

Install the in-repo git hooks once after cloning:

```bash
just install-hooks
```

This points `core.hooksPath` at `.githooks/`. Pre-commit gates on
`cargo fmt --check`, `cargo clippy -D warnings`, and `vosx`'s unit
tests; pre-push runs the full workspace test suite and `just build-pvm`
(which also re-asserts the multi-target Cargo warning stays silenced).
Run everything by hand with `just check-all`.
