# vos-raft

Transport- and storage-agnostic Raft consensus core. `no_std + alloc`
compatible, async by default, runtime-agnostic. Designed to live
next to whatever transport (libp2p, tarpc, raw TCP, an embedded
radio) and whatever persistence layer (redb, sled, an MCU flash
log, an in-memory hash map for tests) the host runs.

## Positioning vs `openraft`

`openraft` is a mature, battle-tested Raft library — it has live
snapshot streaming, learners, joint consensus, observability, and
years of production use. It is also tightly bound to `tokio` and
requires `std`.

`vos-raft` is positioned differently: a smaller, runtime-agnostic
core for hosts that need consensus on a non-tokio executor — Embassy
on a microcontroller, a deterministic simulator, an `async-std` or
`smol` host. It is **not feature-equivalent** to `openraft` (no
joint consensus, no learners, no chunked snapshot streaming yet).

| Property                          | `openraft`              | `vos-raft`                          |
|-----------------------------------|-------------------------|-------------------------------------|
| Async runtime                     | `tokio` (required)      | runtime-agnostic                    |
| `no_std + alloc` compatible       | no                      | yes                                 |
| Worker driver                     | `tokio::spawn`'d task   | single future, host drives it       |
| Pluggable clock                   | no (uses `tokio::time`) | yes (`Clock` trait)                 |
| Pluggable RNG                     | no                      | yes (`Rng` trait)                   |
| Pluggable apply-notification sink | various                 | yes (`ApplySink` trait)             |
| Storage trait shape               | many small methods      | atomic `WriteBatch`                 |
| Required deps (no_std mode)       | n/a                     | core + alloc only                   |
| Joint consensus                   | yes                     | no (planned)                        |
| Chunked snapshot streaming        | yes                     | no (one-shot only)                  |
| Production maturity               | high                    | first carve-out                     |

The core worker — `run_worker(...).await` — is one async future with
no internal task spawning. The host's executor (tokio, embassy,
async-std, a deterministic simulator) drives it however it likes.

## Honest disclosure: thread spawning in std defaults

The std-feature defaults trade some thread spawns for simplicity:

- `Worker::spawn` spawns a dedicated thread that runs
  `futures_executor::block_on(run_worker(...))`. Convenience
  shim — embedded hosts skip this and call `run_worker` on
  their own executor directly.
- `StdClock::sleep_until` spawns a per-`Delay` helper thread
  that calls `std::thread::sleep` and wakes the parent task.
  This avoids `futures-timer`'s shared-timer-wheel contention
  under heavy `cargo test` parallelism but is wasteful at
  scale. **Production tokio-native deployments should enable
  the `tokio` feature and use `TokioClock` instead** — it
  registers sleeps with the host's tokio timer driver and
  doesn't spawn anything per `Delay`.
- vos's `VosTransport` (in the `vos` crate, not here) spawns a
  helper thread per outbound RPC to bridge libp2p's sync reply
  channel to an async future.

The core itself does not spawn anything; thread spawns are
introduced by the std-feature convenience layer.

### Picking a `Clock` impl

| Host                    | Recommended `Clock`               | Why                                           |
|-------------------------|-----------------------------------|-----------------------------------------------|
| tokio                   | `TokioClock` (`tokio` feature)    | Native `tokio::time::sleep_until`, no spawns |
| Embassy / no_std        | Your own (e.g. `embassy_time::Timer` wrapper) | No std deps                                  |
| async-std / smol / quick smoke | `StdClock` (default)       | No external runtime dep, thread-per-Delay    |
| Deterministic simulator | Your own (virtual clock)          | Ticks under test control                     |

## API surface

```rust
use vos_raft::{
    ApplySink, Clock, Config, Rng, Storage, Transport,
    StdClock, StdRng,        // std-feature defaults
    MemStorage,              // in-memory test backend
};

// Async traits — implementations live in the host crate.
pub trait Storage<N: NodeId>: Send + 'static { /* async fn ... */ }
pub trait Transport<N: NodeId>: Send + Sync + 'static { /* async fn ... */ }
pub trait Clock: Send + Sync + 'static { /* async fn sleep_until ... */ }
pub trait Rng: Send + 'static { fn next_u64(&mut self) -> u64; }
pub trait ApplySink: Send + 'static { fn notify(&self, commit_index: u64); }
```

`Config<N>`, `WorkerSnapshot<N>`, and `ProposeError<E>` are
`#[non_exhaustive]` — construct `Config` via `Config::new(me,
members, replication_id)` and match `ProposeError` with a
wildcard arm so future variants don't break callers.

## std vs no_std

- `default = ["std"]` enables the `Worker::spawn` thread-spawning
  convenience, `StdClock` / `StdRng`, and the
  `ApplySink for std::sync::mpsc::Sender<u64>` impl.
- `default-features = false` keeps only the data types (`Config`,
  `LogEntry`, `Meta`, `Role`, RPC structs), the `Storage` /
  `Transport` / `Clock` / `Rng` / `ApplySink` trait definitions,
  and `MemStorage`. Embedded hosts implement these against
  Embassy primitives and drive `run_worker(...).await` on their
  own executor.

Verified `cargo build --no-default-features --target …`:
- `thumbv7em-none-eabihf` (Cortex-M4F, e.g. an STM32)
- `riscv32imc-unknown-none-elf`

## Atomicity contract

Storage writes batch through `WriteBatch<N>`. The implementation
applies the populated fields in a single atomic unit, in this
order:

1. `truncate_after`  (drop divergent tail)
2. `compact_to`      (drop head, advance snap pointer)
3. `appends`         (write the leader's authoritative tail)
4. `state`           (replace materialized state row)
5. `meta`            (replace durable scalars)

A crash mid-batch leaves either the pre-batch or the post-batch
state on disk, never a partial mix. Concrete backends compose
this into a redb transaction, a flash erase-program cycle, or
whatever their native unit of atomicity is.
