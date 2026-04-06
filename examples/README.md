# VOS examples

This directory contains a runnable collection of example actors and agents you
can use to explore VOS, the actor runtime at the core of Kunekt.

```
examples/
├── Agent.toml     # manifest: one agent + a list of actors
├── justfile       # build and run recipes
├── agents/        # orchestrators (services that drive actors)
│   ├── scheduler/   — invokes children each round, re-runs on yield
│   ├── router/      — stateless message forwarder
│   └── nushell/     — stub for a nu-style scripting agent
└── actors/        # guest actors driven by an agent
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

VOS is a small actor framework built on the JAR JAVM. An **actor** is a Rust struct
whose methods are message handlers. To you as an author, an actor looks like
a long-running program: you can write `loop { ... }`, `await` other actors,
sleep, and hold local variables across those awaits. Under the hood, nothing
is actually long-lived — each time a message arrives, a fresh PVM (a minimal
RISC-V virtual machine) is spun up, the actor's state is deserialized from
storage, the handler runs, new state is written back, and the PVM halts.
Yields and `ask()` calls checkpoint the handler so the next invocation can
pick up where it left off. The result: code that reads like a normal async
service, but every invocation is deterministic and cheap to replay.

**Agents** are services that orchestrate actors. The `scheduler` agent keeps a
list of children, sends each of them a `run` message on startup, and
re-invokes any that yielded so cooperative loops can make progress.

### Execution flow

```
vosx Agent.toml
  └─ load manifest, transpile ELFs to PVM blobs
  └─ register scheduler service + actor blobs
  └─ kick-start the scheduler
     │
     ▼
  scheduler (accumulate phase, PC=5)
     ├─ fetch "start" message
     ├─ for each child: invoke(child, Msg::new("run"))
     │     │
     │     ▼
     │  actor (refine phase, PC=0)
     │     ├─ fetch state + message
     │     ├─ run handler
     │     │    (may ctx.ask() another actor → suspends, replays on reply)
     │     │    (may ctx.yield_now() → halts with Yielded status)
     │     └─ write back [status][state][reply]
     │
     ├─ queue any yielded children for the next round
     └─ self-schedule a "tick" until queue is empty
```

Handlers get an `&mut Context` that offers:

- `ctx.tell(target, &Msg::new("foo"))` — fire-and-forget
- `ctx.ask(target, &Msg::new("foo").with("a", 1)).await` — query, returns `Result<Value, InvokeError>`
- `ctx.yield_now().await` — checkpoint state and let other actors run
- `ctx.sleep(n).await` — sleep for N ticks

Under the hood, `ask()` uses an ask-replay pattern: the handler yields, the
framework resolves the invoke, restores the pre-ask snapshot, and replays the
handler with the cached reply. Actor code just looks like plain async Rust.

## Running

```sh
# build everything and run the scheduler with all example actors
just run

# list actors and their messages without running
just list

# just build, don't run
just build
```

You'll need [`just`](https://github.com/casey/just) and a recent nightly Rust
toolchain. The example crates compile to RISC-V via a custom `riscv64em-javm`
target (configured per-crate in `.cargo/config.toml`).

## Where to look next

- **`actors/greeter`** — the smallest possible actor
- **`actors/counter`** — persistent state across invocations
- **`actors/pipeline`** — chained `ctx.ask()` calls to another actor
- **`agents/scheduler`** — how an agent drives children via `lifecycle::invoke`
- **`../crates/vos/src/actors/`** — the framework itself, starting with `run.rs`
