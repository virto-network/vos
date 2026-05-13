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
| [`vos-macros/`](vos-macros/) | `#[actor]` / `#[messages]` / `#[msg]` proc-macros |
| [`vos-raft/`](vos-raft/) | Async Raft implementation used by the `raft` consistency mode |
| [`merkle-crdt/`](merkle-crdt/) | Merkle-DAG CRDT used by the `crdt` consistency mode |
| [`vosx/`](vosx/) | Operator-facing CLI (`vosx run …`, `vosx space …`) |
| [`actors/`](actors/) | Built-in PVM actors bundled into `vosx` (e.g. `space-registry`) |
| [`extensions/`](extensions/) | Native extension plugins loaded by the runtime (e.g. `http-gateway`) |
| [`zkpvm/`](zkpvm/) | ZK proving for PVM bytecode via Stwo |
| [`examples/`](examples/) | Sample actors, agents, extensions, wasm guests, space manifests |
| [`containers/`](containers/) | Dockerfile + docker-compose for production deployments |
| [`book/`](book/) | The VOS Book (architecture, protocols, applications). Source in [`docs/`](docs/) |

## Quick start

```bash
# Create a space. Generates per-space identity, runs the bundled
# space-registry briefly to commit a genesis CrdtEvent, derives
# space_id from the resulting DAG root.
vosx space new --name demo

# Run the daemon. Owns the redb, listens on libp2p (auto-port
# loopback by default; pass --listen for a routable addr).
# `--manifest` reconciles a TOML into the registry on startup
# (publishes blobs, installs agents, fires their `on_start`).
vosx space up demo --manifest examples/space-crdt-a.toml &

# Talk to it. `space call` is the floor primitive — any agent,
# any handler. `space publish/install/agents/etc.` are typed
# sugar on top.
vosx space call demo counter inc
vosx space agents demo
vosx space info demo                    # metadata + daemon liveness + RTT
vosx space export demo > snapshot.toml  # round-trip back to TOML
```

Two-process CRDT convergence demo (one shell):

```bash
just demo-crdt-procs   # creates + dials two daemons, both reach count=2
just demo-crdt-sync    # in-process variant, no separate processes
```

## Running in production

For container-based deployments use [`containers/`](containers/) —
multi-stage Dockerfile, docker-compose exemplar, healthcheck,
graceful SIGTERM, capability enforcement, and persistent
identity all wired up:

```bash
docker compose -f containers/ai-daemon.yml up -d
```

The [Operations Runbook](docs/operations.md) covers identity
setup, auth-role grants, capability policy, troubleshooting,
and the rest of the day-2 operator surface.

## Consistency modes

Each `[[agent]]` in a manifest picks a `consistency` mode:

| Mode | Replication | Read-from-any-replica | Writes block on |
|---|---|---|---|
| `ephemeral` | none, in-memory | n/a | nothing |
| `local` | redb on local disk | n/a | local fsync |
| `crdt` | merkle-CRDT, eventual | yes | local commit |
| `raft` | Raft consensus, strict | leader only (today) | quorum ack |

CRDT fits commutative state (counters, sets, LWW maps,
append-only logs) where reads-from-anywhere matter. Raft fits
strictly sequenced state where divergence corrupts (ledgers,
unique-name registries). Modes mix freely per-agent.

Raft requires a cluster membership list (every replica's
`node_prefix`). See `examples/space-raft.toml`.

```bash
cargo test --all -- --test-threads=1   # full integration suite
```

## Multi-node

```bash
# host A
vosx space new --name a
vosx space up a --manifest space-crdt-a.toml --listen /ip4/0.0.0.0/tcp/4811 &
vosx space info a            # prints the bootnode hint:
                             #   <space_id>@/ip4/.../tcp/4811/p2p/<peer-id>

# host B (paste the bootnode hint)
vosx space join "<bootnode-hint>" --name b
vosx space up b --manifest space-crdt-b.toml --connect /ip4/.../tcp/4811/p2p/<peer-id> &
```

The TOML manifest is a devhelper, not the runtime source of
truth — the registry is. `space export` re-derives a manifest
from the live registry; `space up --manifest` is idempotent
reconciliation.

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

`#[actor]` emits the PVM `_start` / `accumulate` entry points.
`#[messages]` generates the per-handler message types and a
typed `CounterRef` for host-side calls:

```rust
use vos::node::{AgentConfig, VosNode};
use counter::CounterRef;

let mut node = VosNode::new();
let id = node.register(AgentConfig::new(blob));
let counter = CounterRef::at(id);
vos::block_on(counter.inc(&mut &node))?;
let n = vos::block_on(counter.get(&mut &node))?;
```

Compile with the `riscv64em-javm` target — see
`examples/actors/counter/.cargo/config.toml`.

## Writing an extension

An **extension** is a native `.so` plugin that runs alongside PVM
agents and gives them OS access — sockets, filesystem, threads,
async runtimes. PVM agents reach the outside world by `ctx.ask`-ing
extensions. Two kinds:

- **Actor** — request-driven, same `#[actor]` / `#[messages]` DSL
  as PVM agents, just compiled as a cdylib.
- **Service** — long-running, owns its own thread + runtime. Use
  `vos::service_main!(MyService, caps = [...])` and provide a
  `run(&mut self, ctx: ServiceCtx) -> i32`.

```rust
use vos::extension::ServiceCtx;

pub struct MyGateway { /* ... */ }
impl MyGateway {
    pub fn new(_args: &[u8]) -> Self { /* ... */ }
    pub fn run(&mut self, ctx: ServiceCtx) -> i32 {
        while !ctx.is_shutdown() {
            // do work, originate ctx.ask_raw(...) calls
        }
        0
    }
}
vos::service_main!(MyGateway, caps = ["net.tcp.bind", "tokio-runtime"]);
```

Install via the manifest:

```toml
[[extension]]
name = "gateway"
path = "../target/debug/libmy_gateway.so"
init = { port = 8080 }
```

See [`extensions/AUTHORING.md`](extensions/AUTHORING.md) for the
full cookbook and [`docs/extensions.md`](docs/extensions.md) for the
book chapter. The canonical service-mode example is
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
its own slice of the book covering the protocol layers, threat model, and
integrations (Nostr, anonymous credentials, zk-promises). See
[`book/`](book/) → "Applications → Kunekt".

## Development

Install the in-repo git hooks once after cloning:

```bash
just install-hooks
```

This points `core.hooksPath` at `.githooks/`. Pre-commit gates on
`cargo fmt --check`, `cargo clippy -D warnings`, and `vosx`'s unit
tests; pre-push runs the full workspace test suite and `just build-pvm`
(which also re-asserts the multi-target Cargo warning stays silenced).
Run everything by hand with `just verify`.
