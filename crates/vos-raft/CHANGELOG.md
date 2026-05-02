# Changelog

All notable changes to `vos-raft`. The crate is pre-1.0; the API
surface is intentionally small but reserves room to grow via
`#[non_exhaustive]` on every public struct/enum.

## [Unreleased]

### Added
- **Joint-consensus membership change** (Ongaro thesis §4.3) —
  new `WorkerHandle::change_membership(new_members)` API moves
  the cluster to a new voter set without downtime. The leader
  appends a joint `EntryKind::ConfigChange { joint_old:
  Some(old), members: new }` entry; the joint configuration
  takes effect immediately for quorum decisions (heartbeat
  targets, vote counting, commit-index advancement) and quorum
  now requires majorities from BOTH the old AND new sets.
  Once the joint entry commits the leader auto-appends the
  final non-joint entry (`joint_old: None, members: new`);
  once that commits the cluster is on the new membership.
  New `ChangeMembershipError` enum (`NotLeader`, `InProgress`,
  `Storage`). Concurrent change requests during a joint phase
  return `InProgress` — Raft permits at most one membership
  change in flight at a time. `LogEntry` is now parameterized
  over `N: NodeId` so config-change entries can carry typed
  `Vec<N>` member sets; pure-data callers use the new
  `LogEntry::data(idx, term, payload)` constructor and
  `entry.payload()` accessor.
  **Wire compatibility**: vos's libp2p frame layer doesn't yet
  ferry the `ConfigChange` variant — vos's transport adapters
  panic with a clear message if a `ConfigChange` entry ever
  reaches them. Vos workers don't emit them today.
- **Chunked `InstallSnapshot`** — snapshots that exceed the
  transport's frame budget are now streamed across multiple
  RPCs. `InstallSnapshotReq` gained `offset: u64`, `done: bool`,
  and renamed `snapshot: Vec<u8>` → `data: Vec<u8>` (the chunk
  bytes for *this RPC only*). `InstallSnapshotResp` gained
  `bytes_received: u64` so the leader can resume after a
  dropped chunk. The follower assembles chunks under a
  `(last_included_index, last_included_term)` identity and
  commits the snapshot atomically when `done = true` lands;
  duplicate chunks (same offset) and gap chunks
  (offset > current length) are handled idempotently. New
  `Config::install_snapshot_chunk_bytes` (default `32 * 1024`,
  i.e. 32 KiB) caps each chunk; `usize::MAX` disables chunking.
  **Breaking** schema change for transports — vos's adapter
  pins the chunk size to `usize::MAX` until libp2p's frame
  layer learns to ferry chunked offsets.
- **Linearizable reads via `read_index`** (Ongaro thesis §6.4) —
  new `WorkerHandle::read_index() -> Result<u64, ReadIndexError>`
  returns the leader's `commit_index` only after a fresh
  heartbeat round confirms quorum-leadership at the current
  term. Callers wait for their apply progress to reach the
  returned index, then read state-machine state without going
  through the log. `ReadIndexError` distinguishes `NotLeader`
  (address the leader instead) from `LeaderStepped` (we were
  leader at request time but stepped down before a quorum could
  confirm — retry against the new leader). Solo-cluster
  shortcut resolves immediately. Linearizability is closed
  by appending a no-op `Data` entry on leader promotion
  (Ongaro §6.4) so `read_index` can't return a `commit_index`
  that points only at prior-term state.
- **Pre-vote** (Ongaro thesis §9.6) — prevents term inflation
  from a flapping partition. New `Role::PreCandidate`, new
  `PreVoteReq`/`PreVoteResp` RPC types, new
  `Transport::send_prevote` method (with a default impl that
  refuses, so existing transports degrade gracefully). New
  `Config::pre_vote` flag (default `true`); set to `false`
  if your transport doesn't yet route `PreVoteReq` over the
  wire — the worker skips the pre-vote phase and falls back
  to plain Raft. Vos's `RaftCommit` defaults to `false`
  pending libp2p frame support.
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
  - 18 worker unit tests (handler-level state transitions)
  - 2 proptest properties × 256 cases each (term / commit /
    snap-pointer monotonicity, log-matching, at-most-one-vote-per-term)
  - 2 no_std build smoke tests (skip cleanly when targets aren't
    installed)
  - 15 integration tests against a `MockTransport` with per-edge
    partition control (3-node election, replication, partition
    quorum, one-way-partition, leader/candidate step-down on
    higher-term replies, pre-vote term-stability,
    `read_index` quorum confirmation + leader-stepped-on-partition,
    chunked-`InstallSnapshot` assembly + duplicate-idempotence
    + gap-rejection, joint-consensus growth from 3 to 4 nodes
    with `InProgress` rejection of concurrent changes)
  - 5 fault-injection tests (storage `Err` paths)
  - 1 runnable doctest

### Known limitations (deferred for future commits)
- **No learner role** — every `Config::members` entry is a full
  voter.
- **Membership recovery via snapshot is not surfaced** — when
  the leader compacts past a `ConfigChange` entry, only the
  log-tail scan recovers the active config on restart. Hosts
  that need cross-snapshot membership persistence must encode
  the active config into their snapshot bytes; the priming API
  for that path isn't exposed yet.
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
