# Changelog

All notable changes to `vos-raft`. The crate is pre-1.0; the API
surface is intentionally small but reserves room to grow via
`#[non_exhaustive]` on every public struct/enum.

## [Unreleased]

### Added
- **`TokioClock`** behind the new `tokio` feature — uses
  `tokio::time::sleep_until` instead of `StdClock`'s thread-per-`Delay`
  approach. Recommended for tokio-native hosts. Spawn via
  [`Worker::spawn_with_tokio_runtime`] (which builds a tokio
  current-thread runtime with `enable_time()` on the worker
  thread); plain `spawn_with` panics on the first `TokioClock`
  poll because `futures-executor` has no timer driver.
- **Async-by-default `Storage<N>` and `Transport<N>` traits**.
  Methods return `impl Future + Send`. Synchronous backends
  (`MemStorage`, the redb adapter in `vos`) just return ready
  futures; async backends (`embassy-storage`, an SPI flash
  driver) `.await` natively.
- **`Clock` and `Rng` traits**. Worker is runtime-agnostic — the
  host plugs in `tokio::time` / `embassy_time::Timer` / a
  deterministic simulator. Std-feature ships `StdClock`
  (per-`Delay` thread-spawning timer) + `StdRng` (xorshift64*).
- **`ApplySink` trait** with `()` and `std::sync::mpsc::Sender<u64>`
  blanket impls. Replaces the earlier `Option<std::sync::mpsc::Sender<u64>>`
  parameter so embedded hosts can plug their own commit-notification
  channel.
- **Single-future async worker** driven by `futures::select!` over
  inbox + election timer + in-flight outbound RPCs
  (`FuturesUnordered`). No threads spawned by the core. Std-feature
  `Worker::spawn` is a thread-spawning convenience for hosts that
  want one.
- **`run_worker(...)` async function** for embedded hosts that
  drive the future directly on their own executor.
- **Atomic `WriteBatch<N>`** storage contract: `truncate_after`,
  `compact_to`, `appends`, `state`, `meta` apply in one
  implementation-defined unit (a redb txn, a flash erase-program
  cycle, etc.). Crash-safe.
- **`#[non_exhaustive]` on `Config`, `WorkerSnapshot`, `ProposeError`,
  `RaftMsg`** so future field/variant additions don't break SemVer.
- **`Config::compact_hysteresis`** field replaces the old
  `pub const COMPACT_HYSTERESIS = 16` so each replica can tune it.
- **`Config::new(me, members, replication_id)`** constructor with
  sensible defaults (election 150–300ms, heartbeat 50ms,
  compact_hysteresis 16).
- **`Inbox<N>` opaque newtype** hides `futures-channel` from the
  public API so a future channel-impl swap stays SemVer-safe.
- **`WorkerSnapshot::snap_last_index`** — newly surfaced for
  proptest-style invariant audits.

### Verified
- Builds cleanly on `thumbv7em-none-eabihf` (Cortex-M4F) and
  `riscv32imc-unknown-none-elf` with `--no-default-features`.
  Zero non-stdlib deps in that mode (the `std` feature pulls
  in `futures-channel`, `futures-util`, `futures-executor`).
- Test coverage:
  - 16 worker unit tests (handler-level state transitions)
  - 2 proptest properties × 256 cases each (term / commit /
    snap-pointer monotonicity, log-matching, at-most-one-vote-per-term)
  - 2 no_std build smoke tests (skip cleanly when targets aren't
    installed)
  - 7 integration tests against a `MockTransport` with per-edge
    partition control (3-node election, replication, partition
    quorum, one-way-partition, leader/candidate step-down on
    higher-term replies)
  - 1 runnable doctest

### Known limitations (deferred for future commits)
- **No joint consensus** — membership changes are not yet
  supported. Use a static `Config::members` list at construction.
- **Single-shot `InstallSnapshot`** — large snapshots are not
  chunked. Callers that ship multi-MB state should layer their
  own chunking on top.
- **No learner role** — every `Config::members` entry is a full
  voter.
- **Storage error is "drop and forget"**: when
  `Storage::commit_batch` returns `Err`, the worker's
  in-memory `state.meta` is already mutated (term bump, vote,
  etc.) but the on-disk row stays at the pre-call value. The
  worker doesn't retry the specific failed write — the next
  inbound RPC that touches the same fields recomputes and
  commits. Single-shot transient errors are tolerated; a
  persistently-failing storage backend will diverge in-memory
  from disk indefinitely. Future work: queue failed writes for
  retry, or drain the in-memory mutation on Err.
- *(removed)* `Meta::last_applied` is no longer part of the
  worker's meta — the host tracks its own apply progress.
  See `Meta`'s docs.
- **`StdClock::sleep_until` spawns a thread per `Delay`** to avoid
  `futures-timer`'s shared-timer contention under heavy
  parallelism. Tokio-native hosts should enable the `tokio`
  feature and use `TokioClock` (`tokio::time::sleep_until`,
  no thread spawns).

### Comparison vs `openraft`

`openraft` is a mature, production-grade Raft library tied to
`tokio` + `std`. `vos-raft` is positioned for hosts that need
consensus on a non-tokio executor — Embassy on a microcontroller,
async-std, smol, a deterministic simulator. It is **not**
feature-equivalent: `openraft` has joint consensus, learners,
chunked snapshot streaming, and years of production hardening.
Pick `openraft` for tokio-native production; pick `vos-raft` for
embedded / runtime-agnostic / vos-specific use cases.
