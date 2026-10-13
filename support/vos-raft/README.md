# vos-raft

Raft consensus as a protocol core without I/O, on `core + alloc`
(`no_std`).

- **`core::Core`**: one replica of one group as a state machine. The host
  feeds it events and carries out the actions it returns. It reads no
  clock, spawns nothing and does no I/O, so one host can drive thousands
  of groups on whatever executor it has.
- **`sim`**: a deterministic simulator — groups of cores over a simulated
  network and stores with drops, duplicates, delays, partitions and
  crashes that lose unsynced writes — checked for Raft's safety
  properties. Every run is seeded and replays exactly.

Features: pre-vote, check-quorum, leadership transfer, linearizable reads
(`read_index`), joint-consensus membership changes, and log compaction.
The host streams snapshots; the core says when and to whom.

## The core's contract

Events in: `tick(now)` (`next_deadline()` says when), `receive(from,
message)`, `propose`, `read_index`, `change_membership`,
`transfer_leadership`, and the host's reports: `durable(seq)`,
`entries_durable(seq)`, `loaded(load, entries)`, `snapshot_installed`,
`snapshot_failed`, `durably_applied`, `compacted`, `writer_health`,
`peer_alive`. `snapshot_switch` gives the rows a snapshot install
writes.

Actions out (`take_actions()`), carried out in order:

- `Write`: an ordered, atomic write (truncate, append, then the meta and
  configuration rows). The host reports it with `durable(seq)` once it is
  on disk (its term and vote), and with `entries_durable(seq)` once its
  entries can be counted: a follower acknowledges, and a leader counts its
  own log, only then. `sync` asks for an fsync before the reports.
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

`just check-no-std` builds the crate for an embedded target.
