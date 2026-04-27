# VOS examples

This directory contains a runnable collection of example actors and agents you
can use to explore VOS, the actor runtime at the core of Kunekt.

```
examples/
├── space.toml     # space manifest: agents (with optional child actors) + workers
├── justfile       # build and run recipes
├── agents/        # orchestrators (services that drive actors)
│   ├── scheduler/   — invokes children each round, re-runs on yield
│   ├── router/      — stateless message forwarder
│   └── nushell/     — stub for a nu-style scripting agent
└── actors/        # guest actors hosted by an agent
    ├── greeter/     — one-shot "hello" actor
    ├── counter/     — counts ticks in persistent state
    ├── fizzbuzz/    — cooperative loop with yield
    ├── hasher/      — uses preimage hostcalls
    ├── math/        — stateless compute service (add, multiply)
    ├── display/     — virtual framebuffer + tick accumulator
    ├── animation/   — draws a spinner via the display actor
    └── pipeline/    — multi-step computation across math
```

## What is VOS?

VOS is a small actor framework built on the JAR JAVM. An **actor** is a Rust
struct whose methods are message handlers. To you as an author, an actor looks
like a long-running program: you can write `loop { ... }`, `await` other
actors, sleep, and hold local variables across those awaits.

Under the hood, each service runs inside a PVM (a minimal RISC-V virtual
machine). Every tick follows the JAM **refine→accumulate** split:

- **Refine** (PC=0, pure): reads state, dispatches messages, buffers side
  effects, and halts with a `RefinePayload` containing the new actor state
  and queued effects. Cannot mutate storage.
- **Accumulate** (commit): replays the buffered effects — storage writes,
  transfers to other services, preimage provides — making them permanent.

When a handler calls `ctx.yield_now()`, the framework sets `continue_next`
in the refine output. The accumulate stage persists the serialized actor
state to storage and issues a self-directed transfer so the service is
re-ticked. On the next tick, refine reads the persisted state and the actor
picks up where it left off. This continuation protocol is JAM-compatible:
it relies only on standard `READ`, `WRITE`, and `TRANSFER` hostcalls, so
services work on any conformant host without special runtime support.

VOS adds a transparent optimization on top: when a service yields, the
runtime also captures the PVM's flat memory image. On the next tick the
kernel is warm-started with that image, so the actor's heap and statics
survive without a serialize/deserialize round-trip.

**Agents** are services that orchestrate actors. The `scheduler` agent keeps a
list of children, sends each of them a `start` message on startup, and
re-invokes any that yielded so cooperative loops can make progress.

### Execution flow

```
vosx start space.toml
  └─ load manifest, transpile ELFs to PVM blobs
  └─ register workers, then each [[agent]]'s child actors,
     then the agent itself, on the multi-threaded VosNode
  └─ kick-start every registered service
     │
     ▼
  scheduler (refine, PC=0)
     ├─ fetch "start" message
     ├─ for each child: invoke(child, Msg::new("start"))
     │     │
     │     ▼
     │  actor (refine, PC=0)
     │     ├─ read persisted state (or create fresh)
     │     ├─ fetch + dispatch messages
     │     │    (may ctx.ask() → synchronous INVOKE hostcall)
     │     │    (may ctx.yield_now() → sets continue_next flag)
     │     └─ halt with RefinePayload(state, effects, reply)
     │
     ├─ accumulate: replay effects (writes, transfers)
     ├─ if continue_next: persist state + self-transfer
     └─ repeat until no yielded children remain
```

Handlers get an `&mut Context` that offers:

- `ctx.tell(target, &Msg::new("foo"))` — fire-and-forget transfer
- `ctx.ask(target, &Msg::new("foo").with("a", 1)).await` — synchronous query via `INVOKE` hostcall, returns `Result<Value, InvokeError>`
- `ctx.yield_now().await` — checkpoint state and let other actors run
- `ctx.sleep(n).await` — sleep for N ticks
- `ctx.store(key, value)` — queue a storage write (applied in accumulate)

`ask()` is synchronous: the host suspends the caller's PVM at the `INVOKE`
ecall, runs the child to completion, and resumes the caller with the reply
already in hand. No snapshots, no replay — just a nested PVM invocation.

## Running

```sh
# build everything and start the example space
just run

# list actors and their messages without running
just list

# just build, don't run
just build

# run a single actor without a manifest
cargo run -p vos --bin vosx -- run actors/greeter/target/riscv64em-javm/release/greeter.elf
```

The `space.toml` manifest is the structural unit: one `vosx start` =
one space. See `space.toml` itself for the full schema (agents,
nested actors, workers, `provides` roles, optional `[node]` block).

You'll need [`just`](https://github.com/casey/just) and a recent nightly Rust
toolchain. The example crates compile to RISC-V via a custom `riscv64em-javm`
target (configured per-crate in `.cargo/config.toml`).

## Where to look next

- **`actors/greeter`** — the smallest possible actor
- **`actors/counter`** — persistent state across invocations
- **`actors/pipeline`** — chained `ctx.ask()` calls to another actor
- **`agents/scheduler`** — how an agent drives children via `lifecycle::invoke`
- **`../crates/vos/src/actors/run.rs`** — service entry points (`run_refine_service`, `run_accumulate_service`)
- **`../crates/vos/src/runtime.rs`** — host-side runtime, journal, continuation wiring
