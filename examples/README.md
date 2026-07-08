# VOS examples

Runnable actors, agents, and TOML manifests for exploring VOS.

```
examples/
├── space.toml          # full manifest (scheduler + nested actors + extensions)
├── space-crdt-{a,b}.toml  # two-process CRDT convergence demo
├── space-raft.toml     # Raft cluster template
├── justfile            # build recipes (cargo actor, cargo wasm, cargo extension)
├── agents/             # services that orchestrate actors (scheduler/, …)
└── actors/             # leaf actors (greeter/, counter/, crdt-counter/, …)
```

## What is VOS?

A small actor framework that compiles Rust to a JAM-aligned PVM
(RISC-V) target and runs it inside a deterministic host. Each
actor is a Rust struct whose `#[msg]`-tagged methods are message
handlers. Replicas of the same actor under the same
`replication_id` converge automatically via merkle-CRDT (or Raft).

Each tick follows the JAM **refine→accumulate** split:

- **Refine** (PC=0, pure): dispatches messages, buffers writes
  + transfers, halts with a `RefinePayload`. Cannot mutate
  storage directly.
- **Accumulate**: replays the buffered effects. Storage writes
  and cross-actor transfers become permanent here.

`ctx.yield_now().await` checkpoints across ticks — accumulate
persists state and self-transfers, refine resumes on the next
tick. JAM-pure (only standard `READ`/`WRITE`/`TRANSFER`
hostcalls). VOS adds a flat-memory warm-restart on top so
heap + statics survive without serialize/deserialize.

## Running

`vosx space *` is the operator surface. The TOML manifests in
this dir are reconciled into a space's registry on startup —
they're devhelpers, not the runtime source of truth.

```bash
# Build all the example actors (riscv64em-javm target)
just build

# Single-actor smoke test, no manifest, no networking
cargo run -p vosx -- run actors/greeter/target/riscv64em-javm/release/greeter.elf

# Run the full example space (scheduler + greeter + counter + fizzbuzz)
vosx space new --name demo
vosx space up demo --manifest examples/space.toml &

# Then: list state, query agents, exercise handlers
vosx space agents demo
vosx space call demo counter inc
vosx space export demo

# Two-process CRDT convergence
just -f ../justfile demo-crdt-procs
```

## `Context` API

Handlers get `&mut Context`:

- `ctx.tell(target, &Msg::new("foo"))` — fire-and-forget transfer
- `ctx.ask(target, &Msg::new("foo").with("a", 1)).await` —
  synchronous query, returns `Result<Value, InvokeError>`. Host
  suspends the caller's PVM at the `INVOKE` ecall, runs the
  child to completion, resumes the caller with the reply.
- `ctx.yield_now().await` — checkpoint state, let other actors
  run; refine resumes on next tick.
- `ctx.sleep(n).await` — alias for `yield_now` (the tick count is not honored).
- `ctx.store(key, value)` — queue a storage write (applied
  in accumulate).

## Where to look

- `actors/greeter` — smallest possible actor
- `actors/counter` — persistent state across invocations
- `actors/crdt-counter` — minimal CRDT-replicated state
- `actors/pipeline` — chained `ctx.ask()` calls
- `agents/scheduler` — agent driving children via `lifecycle::invoke`
- `../vos/src/actors/run.rs` — refine/accumulate entry points
- `../vos/src/runtime.rs` — host journal + continuation wiring

You'll need [`just`](https://github.com/casey/just) and the nightly
Rust toolchain (per-crate `riscv64em-javm` target spec via
`.cargo/config.toml`).
