# vos-raft

Raft consensus as a protocol core without I/O, plus a driver that runs
one replica of it.

- **`core::Core`** (`no_std + alloc`): one replica of one group as a
  state machine. The host feeds it events and carries out the actions it
  returns. It reads no clock, spawns nothing and does no I/O, so one host
  can drive thousands of groups on whatever executor it has.
- **`Worker` / `WorkerHandle`** (`std`): a driver for one replica over a
  `Storage`, a `Transport`, a `Clock` and an `ApplySink`. It also streams
  snapshots, which the core leaves to its host.
- **`sim`** (`std`): a deterministic simulator — groups of cores over a
  simulated network and stores with drops, duplicates, delays, partitions
  and crashes that lose unsynced writes — checked for Raft's safety
  properties. Every run is seeded and replays exactly.

Features: pre-vote, check-quorum, leadership transfer, linearizable reads
(`read_index`), joint-consensus membership changes, chunked snapshot
streaming, and log compaction.

## The core's contract

Events in: `tick(now)`, `receive(from, message)`, `propose`, `read_index`,
`change_membership`, `transfer_leadership`, and the host's reports —
`durable(seq)`, `loaded(load, entries)`, `snapshot_installed`,
`snapshot_failed`, `durably_applied`, `compacted`, `writer_health`,
`peer_alive`.

Actions out (`take_actions()`), carried out in order:

- `Write`: an ordered, atomic write (truncate, append, then the meta and
  configuration rows). The host reports each one with `durable(seq)` once
  it is on disk; `sync` asks for an fsync before the report.
- `Send`: a one-way message to a peer.
- `LoadEntries`: entries the core no longer caches; answered with
  `loaded`.
- `Committed`: entries through this index may be applied.
- `SendSnapshot`: stream a snapshot to a peer that needs one.
- `CompactBound`: the log may be compacted through this index.
- `Answer`: the outcome of a proposal, read or membership change.
- `Changed`: the term, role or known leader changed.

Writes follow etcd's asynchronous-storage-writes rules. A replica
acknowledges only what is durable and agrees with the leader's log. It
applies nothing beyond what it has verified. It answers at a new term,
or grants a vote, only once that term or vote is durable. A leader
counts its own log toward a commit only once it is durable.

## The driver

`Worker::spawn` runs a replica on its own thread
(`Worker::spawn_with_tokio_runtime` for `TokioClock`); `run_worker` runs
it as one future on the host's executor. Each round hands the core
everything already in the inbox, so a burst of proposals or appends
becomes one write. A store that returns `Err` stops the worker: it
cannot know what reached the disk. Its handles then report it stopped.

`Transport::send(from, to, envelope)` is one-way and must not block;
deliver what arrives with `WorkerHandle::deliver(from, envelope)`.

## Storage atomicity

`Storage::commit_batch` applies a `WriteBatch` atomically, in this
order: `truncate_after`, `compact_to`, `appends`, `state`, `meta`,
`active_config`. A crash leaves the pre-batch or the post-batch state,
never a mix. `MemStorage` is the in-memory backend for tests.

## std and no_std

`default = ["std"]` adds the driver, `StdClock` / `StdRng`, the simulator
and `ApplySink for std::sync::mpsc::Sender<u64>`. `tokio` adds
`TokioClock`. With `default-features = false`, the core, the messages,
the data types and the traits compile on `core + alloc`.
