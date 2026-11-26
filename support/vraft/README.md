# vraft

Raft consensus as a protocol core without I/O, on `core + alloc`
(`no_std`).

- **`core::Core`**: one replica of one group as a state machine. The host
  feeds it events and carries out the actions it returns. It reads no
  clock, spawns nothing and does no I/O, so one host can drive thousands
  of groups on whatever executor it has.
- **`sim`**: a deterministic simulator — groups of cores over a simulated
  network and stores with drops, duplicates, delays, partitions, crashes
  that lose unsynced writes, and restarts whose host cuts the log at an
  entry it never reported durable — checked as it runs: one leadership
  per term (by two nodes, or one node in two runs), one entry per
  committed index (configuration entries compared whole), no commit past
  a replica's log, no compaction past its commit, no read below what was
  committed when it was asked, and no configuration naming an entry its
  replica's log does not hold. Every run is seeded and replays exactly.
- **`pair`**: the pair heartbeat between two nodes, telling each other
  which groups they lead, so idle groups send nothing. A `PeerTable` holds
  at most a bounded number of groups per peer (`LISTED` by default); a
  frame past it is refused.

Features: pre-vote, check-quorum, leadership transfer, linearizable reads
(`read_index`), joint-consensus membership changes, and log compaction.
The host streams snapshots; the core says when and to whom.

## The core's contract

Events in: `tick(now)` (`next_deadline()` says when), `receive(from,
message)`, `propose`, `read_index`, `change_membership`,
`transfer_leadership`, and the host's reports: `durable(seq)`,
`entries_durable(seq)`, `loaded(load, entries)`, `snapshot_installed`,
`snapshot_failed`, `durably_applied`, `compacted`, `writer_health`, and
from the pair heartbeats `vouch` and `probe`.

Actions out (`take_actions()`). Writes are made in order; a batch's
sends may go before its writes, since whatever must wait for a write is
held back by the core until that write is reported:

- `Write`: an ordered, atomic write (truncate, append, then the hard
  state and configuration rows). Its `meta` is the term, vote and commit
  index only: the snapshot pointer is the host's, moved by a compaction
  and a snapshot switch alone. The host reports it with `durable(seq)`
  once it is on disk (its term and vote), and with `entries_durable(seq)`
  once its entries can be counted: a follower acknowledges, and a leader
  counts its own log, only then. `sync` asks for an fsync before the
  reports.
- `Send`: a one-way message to a peer.
- `LoadEntries`: entries the core no longer caches. Every load is
  answered with `loaded`, empty if the store has nothing: the core asks
  for the same range again only once it is answered.
- `Committed`: entries through this index may be applied.
- `SendSnapshot`: stream a snapshot to a peer that needs one.
- `CompactBound`: the log may be compacted through this index; the host
  reports a compaction with `compacted`, which refuses (`false`) any
  point past the bound.
- `Answer`: the outcome of a proposal, read or membership change.
- `Changed`: the term, role or known leader changed.

Writes follow etcd's asynchronous-storage-writes rules. A replica
acknowledges only what is durable and agrees with the leader's log. It
applies nothing beyond what it has verified. It answers at a new term,
or grants a vote, only once that term or vote is durable. A candidate
asks for votes, counts grants and leads only once its term and its own
vote are durable: one that crashes before then asked no one at that
term, so it never leads one term twice. A leader counts its own log
toward a commit only once it is durable.

A snapshot install is two calls around the host's one atomic batch:
`snapshot_switch` gives the rows to write, or `None` when the switch is
not the replica's to make (it does not follow a leader, a write of its
is not yet reported durable, the snapshot is no later than its own, or
it disagrees with the replica's log at a committed index); once the
batch is durable the host hands the switch back to `snapshot_installed`,
feeding the core nothing in between.

## Who a replica listens to

The host authenticates each message's sender, and passes a group only
the messages of nodes that may speak for it. The core cannot make that
check itself: a replica that lags a membership change does not know the
members it added, and one of them may be the leader, or the candidate
whose election the group needs. The host admits the members it knows
the group to have, from a source of its own, and those of the
configuration it supersedes while that is uncommitted.

The core then:

- takes an append from a node outside the configuration it knows: a
  newly added replica starts from the members the group was created
  with, and a lagging one has not seen the entry that added its leader;
- takes a vote request or a pre-vote from such a node only while it
  hears no leader (it leads, or heard its leader within the election
  timeout's lower end): a removed replica that never learned of its
  removal cannot depose a live leader, and a replica whose vote a member
  it does not know needs still gives it when no leader is left;
- ignores answers from outside its configuration, and the terms they
  name: it counts votes and acknowledgements from members only, and
  nothing it asked a non-member needs one;
- refuses, from anyone, what no correct peer sends: a term with no
  successor (`u64::MAX`), or more than 2^32 past its own (a replica that
  reaches the last term no longer campaigns), a second leader of a term
  it leads, led or follows, and an append whose first entry differing
  from its log is at or below its commit index. A refused message
  changes nothing and gets no answer, as if it were lost;
  `Status::refused` counts them, with the answers and vote requests
  dropped above. A member's claim past the leader's log counts as the
  leader's last index.

## Limits

- **A voter that lies.** Raft tolerates crashes, not lies. A voter of a
  group can name itself leader at a higher term and have followers take
  its entries and commit index, acknowledge what it does not hold,
  grant two candidates, burn terms (at most 2^32 a message, so wedging
  a group at the last term takes billions of them), install a
  configuration of its choice on followers, and as leader send a
  snapshot. The checks above bound what a node outside the group can do,
  not what a member can.
- **The host's filter is the defence against outsiders.** A node outside
  the configuration whose appends the host passes can still write
  entries past a follower's commit and have it commit them on its word.
- **Vote requests from members are not sticky.** With pre-votes on, a
  member campaigns only after a quorum stopped hearing the leader; a
  member that skips the pre-vote (a leadership transfer's target, or
  `pre_vote = false`) deposes a live leader by design.
- **A configuration the replica never learned.** A replica whose store
  kept no configuration at its log's start, and receives a snapshot
  without one, falls back to the members the group was created with.
- **Liveness under lag.** A replica that lags a membership change and
  hears a leader ignores a vote request from a member it does not know;
  that candidate needs it only when no leader is heard, and then it is
  answered.

## How it is tested

`tests/core/` drives one core write by write (elections, replication,
durability, membership, who it listens to, idle groups, and several
replicas crashing between a write and its sync);
`tests/proptest_invariants.rs` feeds one replica random messages,
terms and indexes up to `u64::MAX` included, against Raft's invariants;
`tests/simulated.rs` runs the simulator's chaos seeds, with and without
membership changes, entries waiting for blobs, pre-votes off and
leadership handovers, pair heartbeats in place of idle heartbeats, and
restarts that cut the log.

`just check-no-std` builds the crate for an embedded target.
