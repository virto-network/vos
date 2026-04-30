# vos-raft

Transport- and storage-agnostic Raft consensus core. `no_std + alloc`
compatible, native async, runtime-agnostic. Designed to live next
to whatever transport (libp2p, tarpc, raw TCP, an embedded radio)
and whatever persistence layer (redb, sled, an MCU flash log, an
in-memory hash map for tests) the host runs.

## Differences vs `openraft`

| Property                     | `openraft`            | `vos-raft`              |
|------------------------------|-----------------------|-------------------------|
| Async runtime                | tokio (locked in)     | runtime-agnostic        |
| `no_std + alloc` compatible  | no                    | yes                     |
| Spawns helper threads/tasks  | yes (per-RPC)         | no — single future      |
| Pluggable clock              | no (uses `tokio::time`) | yes (`Clock` trait)   |
| Pluggable RNG                | no                    | yes (`Rng` trait)       |
| Storage trait shape          | many small methods    | atomic `WriteBatch`     |
| Required deps (no_std)       | n/a                   | zero non-stdlib         |

The single-future design means the worker can run on:
- `tokio` (`Runtime::block_on(run_worker(...).await)`),
- `async-std`, `smol`, or any other host executor,
- Embassy on a microcontroller (Cortex-M, RISC-V),
- A deterministic simulator that pumps a virtual clock.

## API surface

```rust
use vos_raft::{
    Clock, Config, Rng, Storage, Transport,
    StdClock, StdRng,        // std-feature defaults
    MemStorage,              // in-memory test backend
};

// Async traits — implementations live in the host crate.
pub trait Storage<N: NodeId>: Send + 'static { /* async fn ... */ }
pub trait Transport<N: NodeId>: Send + Sync + 'static { /* async fn ... */ }
pub trait Clock: Send + Sync + 'static { /* async fn sleep_until ... */ }
pub trait Rng: Send + 'static { fn next_u64(&mut self) -> u64; }
```

## std vs no_std

- `default = ["std"]` enables the `Worker::spawn` helper that runs
  the worker on a dedicated std thread, plus `StdClock` / `StdRng`.
- `default-features = false` strips out the worker driver — only
  the data types (`Config`, `LogEntry`, `Meta`, `Role`, RPC structs)
  and the `Storage` / `Transport` / `Clock` / `Rng` trait
  definitions remain. Embedded hosts implement these against
  Embassy primitives and call `run_worker(...).await` themselves.

## Atomicity contract

Storage writes batch through `WriteBatch<N>`. The implementation
applies the populated fields in a single atomic unit:

1. `truncate_after`  (drop divergent tail)
2. `compact_to`      (drop head, advance snap pointer)
3. `appends`         (write the leader's authoritative tail)
4. `state`           (replace materialized state row)
5. `meta`            (replace durable scalars)

A crash mid-batch leaves either the pre-batch or the post-batch
state on disk, never a partial mix. Concrete backends compose
this into a redb transaction, a flash erase-program cycle, or
whatever their native unit of atomicity is.
