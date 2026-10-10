# Slice 3: Replication

Plan v2 for build step 3 of `core-model.md` (section 16): large entries
(item 18), then the node log writer (item 15), many active agents per node
(item 16) and the vos-raft driver (item 19). It builds on slice 2's node
(`slice-2-one-node.md`) and on S3's findings (`spikes.md`, "S3 — Logs").
v1 was reviewed by the second-opinion reviewer; v2 folds in its findings.
Tags as in the core model. Items marked [owner] are the owner's to decide;
the list is at the end.

## Goal

An agent replicated on three nodes runs end to end:

1. A client calls a method through any of the agent's replicas.
2. A follower forwards the request to the leader, which batches, refines
   and proposes the work result to the agent's Raft group.
3. Every replica appends the entry durably; once a quorum holds it, the
   entry commits and every replica accumulates it.
4. The client's reply comes from the applied state of the replica it
   called; a retry after a failover returns the stored reply.
5. Messages between agents on different nodes are delivered and
   acknowledged exactly once, across leader changes and restarts.

The slice delivers:

1. **The vos-raft driver** S3 requires (item 19), on a protocol core that
   no longer does I/O itself.
2. **The node log writer** (item 15): one per node, group commit across
   agents, capped flushes, durable appends and non-durable applies under
   section 9.5's invariants, Raft snapshot export and ingestion.
3. **Large entries** (item 18), measured first; their path is settled
   before the writer is built.
4. **A transport between nodes**, with per-node-pair combined heartbeats.
5. **Replicated agents in the node:** groups, forwarding, followers'
   queries, read-index queries, leader changes per section 7.5.
6. **Many active agents per node** (item 16) within budget.
7. **Fault tests** of exactly-once delivery and replies across crashes,
   partitions and leader changes.

Out of scope:

- the catalog: placement and rebalancing (the operator sets each agent's
  replica set; membership changes are only used to replace a replica);
- refine on any replica, and pipelined refines over an overlay of pending
  results (section 7.2), unless the budget needs them (step 3.10);
- workflows, snapshot pages and witnesses (step 4); their blobs reuse
  this slice's large-entry path;
- the Merge lane (step 6), JAM (step 4).

## What S3 and slice 2 leave

From S3 (`spikes.md`, "Decision"):

- group commit of queued proposals;
- replicate on propose, one append in flight per peer;
- no fsync for commit-index-only writes;
- one log writer per node with group commit across agents, never on
  executor threads;
- liveness independent of log I/O: combined heartbeats per node pair,
  slow heartbeats or quiescence when idle;
- one shared executor;
- every append carries its heartbeat round;
- the cause of the slow 64 KiB entries.

From the code (the inventory behind this plan):

- **vos-raft's worker awaits every storage write inline.** A follower
  answers a heartbeat only after writing its meta; the leader counts
  itself at its last index, so a write must be durable before the worker
  moves on. The worker runs one group per future with a thread-per-sleep
  clock.
- **The eager prototype predates the read-barrier rounds** (d785694b); it
  must be reapplied, not merged.
- **Messages have no wire encoding,** and backtracking costs one round
  trip per entry (no conflict hint). Snapshots are one `Vec<u8>`, re-read
  per chunk and buffered whole by the follower.
- **The node's log has no entry kind**, and its applied index doubles as
  the agent's version: Raft's no-op and configuration entries break both.
- **Agent ids and session ids are per-node counters,** so two nodes would
  collide inside one replicated agent.
- **No transport exists** between nodes.

## Design

### vos-raft: a protocol core without I/O [owner: decision 1]

The worker becomes a state machine the node drives:

- **Input:** an event (a message from a peer, a proposal, a timer tick, a
  read-index request, a membership change, or "durable up to index n").
- **Output:** a list of actions: persist a batch (with its durability),
  send a message to a peer, notify a commit index, answer a proposal or
  a read.

The protocol logic is kept: elections with pre-vote, joint consensus,
read index with rounds, compaction, snapshots. What changes:

- **Durable index.** The core tracks the index its own log is durable at,
  reported back by the writer. The leader counts itself at that index,
  not at its last index: counting a non-durable entry would commit it
  with one durable copy too few. A follower acknowledges entries only
  once they are durable.
- **Liveness without I/O, at an unchanged term.** A heartbeat, or an
  append whose entries are not yet durable, is answered at once with the
  term and the round, so elections and read barriers never wait for a
  disk. Two exceptions wait for their write, as Raft requires: an answer
  that adopts a higher term, and every vote. A follower that answered at
  a new term and lost the term in a crash could otherwise accept a
  stale leader's appends over entries it had acknowledged.
- **Two answers per append.** The early answer is a heartbeat answer:
  term, round, and the follower's durable index for information. Only
  the durable acknowledgement moves `match_index`, and only upward within
  a term; `next_index` moves only on durable acknowledgements and
  rejections. A late durable acknowledgement after a newer early answer
  therefore cannot move either backwards.
- **Replicate on propose:** new entries go to each peer at once, one
  append in flight per peer, capped in bytes (see "Defaults") but always
  carrying at least one entry, so a 4 MiB result still ships. Proposals
  queued together are one batch.
- **Rounds.** Every append carries the current round; only a heartbeat
  sweep or a read-index request opens a new one. A send before the first
  round of a term carries 0, which confirms nothing. A round confirms
  leadership, not durability, which is why the early answer serves it. A
  leader serves no read index until its term's no-op is committed.
- **Durability per write:** entries, term and vote are durable;
  commit-index-only writes are not. On recovery, the commit index is the
  larger of the stored one and the applied index, since only committed
  entries are applied.
- **Fast backtracking:** a rejection carries the follower's last index
  and the first index of the conflicting term.
- **Streamed snapshots:** the leader reads a snapshot chunk by chunk from
  a source the node supplies; the follower hands chunks to the node to
  ingest, and installs on the last.
- **Clock:** time comes in with ticks; the core reads no clock.

The existing suites (70 tests, the proptest invariants, the read-barrier
test) move onto the core, with a deterministic simulated network and
storage that can drop, delay, reorder and crash.

### The node log writer and storage (items 15, 18)

The storage thread from slice 2 becomes the node log writer:

- **Per change, a durability:** Raft appends, terms and votes are
  synced; commit-index moves and applies are buffered.
- **Group commit across agents,** as now, but a flush is capped in bytes
  (see "Defaults"), so one large entry does not hold back every agent.
- **Separate append and apply.** An entry is appended (durable) when it
  arrives; it is applied (accumulate's writes, buffered) once committed.
  The seven invariants of section 9.5 hold, each with a test.
- **The log row carries a kind:** a work result, a no-op, a
  configuration, or a node command (install's programs, below).
- **Applied index and version part.** The applied index counts log
  entries; the agent's version counts applied work results that were not
  skipped (section 7.5). Both are stored; the node no longer assumes they
  are equal.
- **Raft meta rows:** term, vote, commit index, snapshot index and term,
  active configuration.
- **Truncation and compaction:** truncate after an index (a new leader's
  conflicting suffix); compact the log to at most the durable applied
  index (invariant 4). The writer records, per synced flush, the highest
  applied index that flush made durable, and compacts only below it,
  never below the in-memory applied index.
- **Snapshots:** an agent's snapshot is its key prefix in `state` and
  `system`, read from one store snapshot and streamed in chunks.
- **Installing a snapshot is one switch.** Chunks go to a staging copy of
  the agent's prefix (an epoch byte in the prefix). One synced batch then
  moves the agent's epoch pointer and records the applied index, the
  version and the snapshot's index and term; the old epoch is
  range-deleted afterwards. Queries read through the pointer, so they
  never see a half-installed state. A crash before the switch leaves the
  old state and index; after it, the new ones. Invariant 6 becomes: a
  snapshot and the index that depends on it are one durable batch.
- **Recovery:** after a crash a replica re-applies the log from its
  recovered applied index. Applies are buffered, so a crash may lose a
  local apply of a committed entry, including session marks, reply
  windows and outbox rows; re-applying regenerates them, with the same
  outbox sequence numbers, which receivers deduplicate (section 9.5).

**Large entries take a blob path** [decided by step 3.1; see
`slice-3-progress.md`]. A work result may be 4 MiB
(`cap::WORK_RESULT`), and an install carries its programs. Through a
shared writer, one agent's 4 MiB entries pushed every other agent's small
appends to a p99 of 263 ms, and no flush cap helped. A separate blob
writer brought it to 15 ms. So:

- entries of 64 KiB or more are content-addressed blobs, written by the
  node's blob writer (its own thread, files and syncs, with group commit);
- the log entry carries the blob's hash and length;
- a replica appends the reference only once its copy of the blob is
  durable (invariant 7);
- the leader sends the blob ahead of the append that names it;
- smaller entries stay inline in the log partition;
- S3's slow 64 KiB entries were redb's cost per commit, not the driver's.

Why not one log file for everything: it would give up invariant 2 (state
and log share one journal). Blobs keep every reference in the journal,
and invariant 7 bridges the blob file. What the blob path requires:

- **A blob counts as durable only once verified** against its hash; the
  length in the reference bounds the receive.
- **An entry is durable when its reference and every blob it names are.**
  The writer reports "durable up to n" only then, so the leader's
  self-count, a follower's `match_index` and the read barrier need nothing
  more. An append that arrives before its blob is appended but not yet
  durable, not refused.
- **So a replica that holds an entry holds its blobs,** which makes a
  leader change safe: any replica with the entry can serve its blobs.
- **Fetching:** a replica missing a named blob fetches it from the leader
  or any replica holding the entry. A leader keeps blobs as long as it
  keeps their entries for lagging followers.
- **Hashing runs on executors** (BLAKE2b-256 over 4 MiB is 2–4 ms): the
  leader hashes at refine's end, a follower on receipt, never on a
  writer thread.
- **Accumulate resolves a reference to its bytes** before it runs: a
  read on the apply path, off the journal.
- **Collection:** a blob is referenced by log entries, by installed
  programs across every agent (one blob, many pins) and by the blobs a
  leader sent ahead of appends still in flight. An unreferenced blob is
  garbage only after a horizon, since its append may be in flight. Blobs
  sent ahead by a leader that died, and blobs of a truncated suffix,
  become such orphans.
- **New files are durable** only with a directory sync, or segments are
  preallocated; step 3.3 chooses.

**Programs** always take the blob path: an install body may hold 64 MiB
(slice 2's cap). The node's program store becomes pinned blobs, so every
replica can lead. A work result's blob lives until log compaction passes
its entry; blob files are collected by liveness (step 3.3).

### Transport [owner: decision 2]

Proposed: TCP between nodes with the Noise protocol (`XX` handshake, the
`snow` crate), authenticated by each node's static key, and SCALE-encoded
frames. One connection per node pair carries:

- blobs, ahead of the appends that name them, and fetches of missing
  blobs, with flow control per pair so a 64 MiB program never delays a
  heartbeat; the core's byte caps count inline bytes only;
- Raft messages of every group the two nodes share, with one combined
  heartbeat per pair per interval (it lists the groups and their rounds);
- forwarded client requests and their answers;
- agent-to-agent messages and acknowledgements;
- snapshot chunks, with flow control so they never delay heartbeats.

Tests use an in-process transport with the same frames, able to drop,
delay, duplicate and partition: the same simulated network the vos-raft
core is tested on (step 3.2), so there is one fault simulator. Peers are
listed in the node's configuration until the catalog: a stable node
number, its id, address and key.

### Replicated agents in the node

- **Groups.** Each agent with more than one replica has a Raft group; a
  single-replica agent keeps slice 2's path (a group of one, through the
  same code, if that costs nothing measurable).
- **Creation** [owner: decision 3]. The operator creates an agent on one
  node with its replica set; that node tells the others, and each starts
  the group with the same initial configuration.
- **The leader** batches and refines as in slice 2, proposes the work
  result, and dispatches replies and messages only after its own
  accumulate applied it (section 7.5).
- **Followers** apply committed entries in order and answer their own
  clients from applied state.
- **Leader changes** (section 7.5):
  - a new leader commits a no-op and applies everything before it before
    refining; it takes its batch version from the agent's `version` key
    once applied through its no-op, and its batch times never go below
    the last committed one;
  - no-ops, acknowledgements and configuration entries advance the
    applied index but not the version, so the two part; `Node::open`'s
    check that they are equal goes;
  - accumulate skips a result whose version is no longer current, and its
    inputs are retried;
  - a skipped result or a term change aborts the leader's pipeline and
    flushes its cached machines.
- **Forwarding.** A follower forwards a client request to the leader it
  knows, and never runs lane logic (window, gap, in flight) itself: its
  applied marks may lag. The leader runs the lane and answers once its
  replica applied the request; the follower then waits for its own apply
  to reach that entry and answers from its own applied state.
  - A forward is idempotent by (session, sequence). On `NotLeader` or a
    timeout the follower forwards again to the new leader, whose lane
    serves the reply from the window if the entry committed, or runs the
    request; a duplicate of a request pending in the leader's pipeline
    joins it (section 7.5).
- **What a client signs.** Slice 2 binds every signed message to the
  node's id, against replay at another node. With replicas, a client
  talks to any of them, so the binding becomes an identity they share:
  the agent's creation record, by its hash, carried in its configuration
  entry. A follower forwards a request of a session it has not yet
  applied, unverified; the leader verifies.
- **Queries** run on any replica against applied state; a client may ask
  for a version at or after one it has seen. `#[msg(linearizable)]`
  first takes the read index.
- **Messages between agents.** The outbox is replicated state. The
  sender's leader sends each message and acknowledgement to the
  receiver's leader; a replica that is not the leader answers
  `NotLeader { hint }` and the sender retries there. A new leader on
  either side resends what is unacknowledged. Messages are idempotent by
  per-pair sequence number and acknowledgements are monotone, so every
  retry is safe, as in slice 2.

### Ids and sessions across nodes [owner: decision 3]

Agent ids and session ids are per-node counters today. Proposed until the
catalog:

- **Agent ids** are chosen by the creating node from its own range: its
  configured node number in the high bits. `AgentId` stays 32 bits: 8
  bits of node number, 24 of counter.
- **Sessions move into the agent,** the only choice that keeps
  exactly-once across failover. Every replica then authenticates a
  session's requests and retries, so a client that fails over keeps its
  session, its sequence numbers and its replies. Lane logic runs only on
  the leader (above). Sessions join the agent's snapshot, O(active
  sessions), and slice 2's node-level session registry goes. Two shapes:
  - **(a) Opened in the log.** The client's signed open, naming the
    agent, is an input; accumulate assigns the session id (a counter in
    the agent's state) and records the key; the id is the open's reply.
    One log entry and one round trip per open.
  - **(b) Named by the client.** A session is (client key, a name the
    client picks). The first signed request of a new session creates it
    in accumulate, which enforces the per-key cap. No open, no extra
    entry: the simpler design, raised as the alternative in slice 2.

The alternative to both is node-level sessions with ids namespaced by
node: no log entry per opening, but a client that fails over opens a new
session and loses exactly-once for requests in flight. Not recommended.

### Many active agents per node (item 16)

- one node writer for every agent (above);
- one executor runs every group's core and every leader loop; refines and
  accumulates stay on executor threads;
- heartbeats combined per node pair; the pair heartbeat is the liveness
  signal. A group quiesces after a few idle intervals only while its
  leader's node answers the pair heartbeat; a missed pair heartbeat
  wakes every group led from that node, and a proposal wakes its group.
  Quiescing on a group's own heartbeats would elect a new leader at
  every quiescence;
- admission per agent as in slice 2.

## Steps

### 3.1 Large entries (item 18) [done]

Measured durable appends through the node writer on fjall by entry size,
alone and beside other agents' small entries; found the cause of S3's
64 KiB case; settled the blob path above (`slice-3-progress.md`).

### 3.2 vos-raft core

Restructure the worker into the core above; port every existing test and
invariant; add the simulated network and storage, with crashes that lose
whatever was not durable. Then add, each with tests: the durable index,
answers without I/O at an unchanged term (and the term and vote writes
that answers wait for), the two answers per append, replicate on propose
with the byte cap, rounds on every append, durability per write, fast
backtracking, streamed snapshots. The `std` worker goes; the node drives
the core.

### 3.3 Node storage for Raft

The blob store and its writer, log kinds, meta rows, truncation,
compaction below the durably applied index, the applied index apart from the version, per-change durability,
capped flushes, snapshot export, staged ingestion and the atomic switch,
recovery. A crash test like slice 2's, per invariant of section 9.5.

### 3.4 Transport

The frames (SCALE), the in-process transport on step 3.2's simulated
network, then TCP with Noise and combined heartbeats per node pair.

### 3.5 Replicated agents

Groups, creation with a replica set, the leader proposing, followers
applying, leader changes per section 7.5, forwarding and re-forwarding,
what clients sign, followers' queries, read-index queries, programs
reaching every replica, agent messages between nodes. Three nodes in one
process first, then three processes.

**The exactly-once checker lands here,** run under randomized faults in
the in-process cluster: a history of increments, replies and read-index
queries; no acknowledged request lost or applied twice, no reply before
its result is applied on the answering replica, no message lost or
applied twice, every read-index query linearizable. Steps 3.6–3.8 extend
it.

### 3.6 Sessions across replicas

Per decision 3.

### 3.7 Snapshots and catching up

Log compaction on every replica, snapshots streamed to a lagging or new
replica, and replacing a replica through a membership change.

A snapshot carries applied state, so work results' blobs need not travel
with it; pinned blobs (programs) do. Its manifest lists the pinned
hashes, the receiver fetches those it lacks, and the switch batch is
written only once every one is durable (as invariant 6).

### 3.8 Many active agents (item 16)

Writer batching across agents, scheduling under load, quiescence. Tests
with 64 active agents and 1,000 idle groups.

### 3.9 Faults across processes

The checker's faults on three processes: kills, restarts, partitions
between processes, slow disks.

### 3.10 Acceptance

Against section 14, on three nodes (three processes on the reference
laptop, each on its own data directory; the shared disk is a caveat):

| Budget | Threshold |
|---|---|
| Replicated agent, simple mutations | ≥ 20k per second per agent; p99 commit ≤ 10 ms at half load |
| Many active agents per node | 64 active agents: ≥ 40k commits per second in total, p99 ≤ 20 ms |
| Idle groups | 1,000 per node: no thread per group, idle CPU ≤ 5% of one core |
| Query on a follower | ≤ 100 µs (percentile per the open slice 2 decision) |
| Table reads under continuous writes | the steady-state cost section 9.5 leaves to this slice |
| Exactly-once and apply-then-send across faults | the checker passes |

If the replicated budget needs pipelined refines, they come here, with
their own review.

## Gates

| Gate | Threshold |
|---|---|
| Slices 1 and 2 | `just ci-full` stays green |
| Raft safety | election safety, log matching, leader completeness and state-machine safety hold under the simulated faults; read-index queries are linearizable across leader changes |
| Section 9.5 | a crash test per invariant |
| Exactly-once | the fault checker passes |
| Budgets | as in 3.10 |

## Risks

- **Restructuring vos-raft** touches every path of a 4,500-line worker.
  Porting the existing tests first, and the simulated faults, are the
  guard; the protocol logic moves, it is not rewritten.
- **The blob path is in this slice** (step 3.1), not step 4: a second
  writer per node, blobs in the transport with flow control, and
  collection by liveness.
- **Moving sessions into the agent** adds a log entry per opening and
  changes slice 2's ingress.
- **One laptop** measures three replicas on one disk and one CPU, as S3
  did; a second machine, or two, would make the replicated numbers mean
  more.

## Decisions for the owner

1. **vos-raft's core without I/O,** driven by the node, instead of
   patching the async worker as S3's prototype did. Recommended: the
   durable index and answers without I/O need it, and one driver for
   thousands of groups is simpler around a state machine.
2. **The transport:** TCP with Noise and node keys, peers in the node's
   configuration. Alternatives: libp2p (master's stack, larger, its own
   runtime), QUIC (`quinn`, tokio-based where the node uses smol).
3. **Sessions and what clients sign, until the catalog.** Sessions move
   into the agent, so failover keeps exactly-once: (a) opened in the
   log, or (b) named by the client (simplest; recommended). Either way
   clients sign for the agent's identity instead of a node's, which
   changes slice 2's client protocol. Agent ids come from per-node ranges.
4. **Scope:** pipelined refines only if the budget needs them, and the
   catalog's placement left out.

**Defaults** (engineering, recorded rather than asked): heartbeat 500 ms,
election timeout 1.5–3 s, quiescence after 4 idle intervals, blob
threshold 64 KiB, append cap 1 MiB, flush cap 8 MiB, compaction when the
log passes 4,096 entries or 64 MiB beyond the applied index. Step 3.10
may move them.
