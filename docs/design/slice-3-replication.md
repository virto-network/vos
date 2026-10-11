# Slice 3: Replication

Plan v3 for build step 3 of `core-model.md` (section 16): large entries
(item 18), then the node log writer (item 15), many active agents per node
(item 16) and the vos-raft driver (item 19). It builds on slice 2's node
(`slice-2-one-node.md`) and on S3's findings (`spikes.md`, "S3 — Logs").
v1 and v2 were reviewed, v3 folds in the second review, and the owner's
decisions are at the end. Tags as in the core model.

## Goal

An agent replicated on three nodes runs end to end:

1. A client calls a method through any of the agent's replicas.
2. The replica forwards the request to the leader, which batches, refines
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
   agents, durable appends and non-durable applies under section 9.5's
   invariants, Raft snapshot export and ingestion; and the blob path for
   large entries (item 18, step 3.1).
3. **A network layer** between nodes, consensus-agnostic, on QUIC.
4. **Replicated agents in the node:** groups, forwarding, followers'
   queries, read-index queries, leader changes per section 7.5,
   client-named sessions in the agent.
5. **Many active agents per node** (item 16) within budget.
6. **An exactly-once checker** under randomized faults.

Out of scope:

- the catalog: placement and rebalancing (the operator sets each agent's
  replica set; membership changes are only used to replace a replica);
- refine on any replica, and pipelined refines over an overlay of pending
  results (section 7.2), unless the budget needs them (step 3.10);
- workflows, snapshot pages and witnesses (step 4); their blobs reuse
  this slice's blob path;
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
- every append carries its heartbeat round.

From the code:

- **vos-raft's worker awaits every storage write inline.** A follower
  answers a heartbeat only after writing its meta; the leader counts
  itself at its last index, so a write must be durable before the worker
  moves on. The worker runs one group per future with a thread-per-sleep
  clock.
- **The eager prototype predates the read-barrier rounds** (d785694b), so
  it is reapplied, not merged; and it skips heartbeats to peers with an
  append in flight, which is not reapplied.
- **Messages have no wire encoding** and are request and response: the
  RPC futures carry the round, `leader_commit` and the snapshot cursor.
  Backtracking costs one round trip per entry. Snapshots are one
  `Vec<u8>`, re-read per chunk and buffered whole by the follower.
- **vos-raft trusts what a message claims:** it ignores who sent it and
  takes `req.leader` at its word.
- **The node's log has no entry kind**, and its applied index doubles as
  the agent's version: Raft's no-op and configuration entries break both.
- **Agent ids and session ids are per-node counters,** so two nodes would
  collide inside one replicated agent.
- **No network exists** between nodes, and client ingress is plain HTTP.

## Design

### vos-raft: a protocol core without I/O [owner decision 1]

The core follows etcd's asynchronous storage writes (go.etcd.io/raft v3.6,
as CockroachDB uses it), not its classic Ready/Advance contract. In the
classic contract a Ready's messages leave only after its entries and hard
state are persisted, and the next Ready waits for Advance, so a
follower's heartbeat answer waits behind an fsync: what lost leaders in
S3.

**Events in:**

- `Received { from, message }`: `from` is the authenticated sender (see
  "Authorization");
- `Propose`, `ReadIndex` (local, or asked by a follower),
  `ChangeMembership`, `TransferLeadership`;
- `Tick(now)`: time arrives only with ticks;
- `Durable { write }`: the writer made the group's writes through `write`
  durable; a group's writes complete in order, with several in flight;
- `Loaded { request, entries }`: answers a `LoadEntries` action. The
  log can change while a load is in flight (a leader steps down, is
  truncated, leads again), so each request carries the term it was made
  in; the core drops older results and checks every loaded entry against
  its term runs;
- `SnapshotInstalled { index, term, configuration }`: the node's durable
  switch to a received snapshot (below);
- `DurablyApplied { index }` and `Compacted { through }`;
- `WriterHealth { stalled }`;
- `PeerAlive { node, incarnation }`: the multi-group driver's pair
  heartbeat answered. Check-quorum and the pre-vote leader check count it
  as having heard from that node while a group is quiesced.

**Actions out:**

- `Write { seq, truncate_after, entries, hard_state, durable, release }`:
  one ordered write. `release` holds the messages that may leave only once
  this write is durable.
- `Send { to, message }`: a message that may leave now.
- `LoadEntries { from, to }`: a miss in the core's bounded tail cache.
  The core keeps every entry's term in memory as compact runs.
- `Committed { index }`: what this replica may apply (below).
- `SendSnapshot { to }`: the node's streamer sends one; the core only
  says a peer needs it;
- `CompactBound { through }`: how far the node may compact; only the core
  knows what retiring configurations pin.
- `Answer { token, result }`, and `Changed { term, role, leader }`.

**Which messages wait for their write:**

- "Unchanged term" means equal to the *durable* term, not the term in
  memory.
- Wait: vote grants; any answer at a term above the durable term (it
  adopts that term); durable acknowledgements of appends. A candidate
  counts its own vote only once its term and vote are durable.
- Go at once: pre-votes and their answers; rejections and heartbeat
  answers at the durable term; a leader's appends, before its own write
  is durable.
- A follower that answered at a new term and lost the term in a crash
  could otherwise accept a stale leader's appends over entries it had
  acknowledged.

**Durability, and what a replica may claim and apply:**

- **Durability is (index, term).** The core maps each write's sequence
  to the last entry it wrote and its term. A report is ignored if the
  term at that index has changed since: a truncation replaced the entry
  (etcd's `stableTo`). Truncating after index t sets durable to at most t.
  The leader counts itself by the same rule. Otherwise a late report of
  an old leader's write could vouch for a new leader's entry at the same
  index, and two different entries could commit there. Checking the
  entry's term is enough, since a stale report can only match an older
  term's entry, which Raft never commits by counting. Test: truncate,
  re-append the same (index, term) through a later leader, deliver the
  stale report late, and no commit counts it.
- **`verified`** is the highest index this replica has matched against
  the current term's leader; it resets at every term change.
  - A durable acknowledgement claims min(durable, verified), computed
    when it is sent: on a `Durable` event, or at once only if the claim is
    already durable. A duplicated append whose entries are present but not
    yet durable is not acknowledged early. A term change resets
    `verified` to the commit index.
  - A follower applies up to min(leader's commit, verified).
  - A leader sends each peer a commit index of at most that peer's
    `match_index`, as etcd does for heartbeats.
  - Otherwise a commit update that overtakes an append makes a follower
    apply a stale entry it holds at that index.
- **Two answers per append.** The early answer is a heartbeat answer:
  term, round, and the durable index as information only. Only durable
  acknowledgements move `match_index`, only upward within a term;
  `next_index` moves only on durable acknowledgements and rejections.
- **Responses describe themselves:** an answer names the append it
  answers (its last index and term), the round, and the commit index it
  carried, since a one-way network has no RPC future to remember them.
- **Recovery:** the commit index is the larger of the stored one and the
  applied index, since only committed entries are applied.

**Replication:**

- **Replicate on propose:** new entries go to each peer at once, one
  append in flight per peer, capped in inline bytes but always carrying
  at least one entry. Proposals queued together are one write.
- **The in-flight slot** is released by the durable acknowledgement or
  rejection of the append it holds, by a resend timeout, or by a term
  change.
- **Heartbeats go to every peer every interval,** whether or not an append
  is in flight.
- **Rounds:** every append carries the current round; only a heartbeat
  sweep or a read-index request opens a new one. A read-index request
  sends its round at once, not at the next combined interval, or
  linearizable reads would wait up to a heartbeat. A send before a term's
  first round carries 0, which confirms nothing. A round confirms
  leadership, not durability, so the early answer serves it. A leader
  serves no read index until its term's no-op is committed.
- **Fast backtracking:** a rejection carries the follower's last index
  and the first index of the conflicting term.

**Liveness:**

- **Check-quorum:** a leader that has not heard from a quorum within an
  election timeout steps down.
- **Leadership transfer:** a leader hands its group to an up-to-date peer.
- **A stalled writer:** a leader whose writer reports a stall beyond a
  bound transfers leadership, or stops heartbeating so a peer takes over.
  Liveness without disk I/O must not keep a leader whose disk has
  stopped, since such a leader cannot apply, refine or reply.

**Compaction and snapshots:**

- The node decides when to compact (by size); the core bounds how far
  with `CompactBound`: at most the durably applied index, and not past
  what retiring configurations pin. The node reports `Compacted`.
- Snapshots leave the core: it emits `SendSnapshot`, the node streams
  the agent's state, and the receiver reports `SnapshotInstalled` once
  its switch is durable (see the storage section below).
- **A peer receiving a snapshot** gets no appends until it acknowledges an
  index at or above the snapshot's; a failure event or a timeout sends it
  back to probing. The in-flight slot rule covers appends only.
- **`SnapshotInstalled { index, term }`** sets `verified`, the durable
  index and the commit index to at least that index (a snapshot is
  committed state, matching every later leader's log). The log suffix
  stays only if its entry at that index has that term, otherwise it is
  dropped in the same switch batch. The leader is acknowledged with the
  index. A node refuses a snapshot at or below its applied index.

**Tests:**

- The existing suites (70 tests, the proptest invariants, the
  read-barrier test) run on the core, through a thin driver that keeps
  today's `Worker` interface for them.
- A deterministic simulator, payload-agnostic, so that step 3.4 reuses it
  as the network layer's in-process implementation:
  - it drops, delays, duplicates, reorders and partitions;
  - a crash keeps any prefix of each writer's unsynced writes, with the
    journal and the blob store independent.

### The node log writer and storage (items 15, 18)

The storage thread from slice 2 becomes the node log writer:

- **Per change, a durability:** Raft appends, terms and votes are
  synced; commit-index moves and applies are buffered.
- **Group commit across agents,** with a flush cap as a guard.
- **Separate append and apply.** An entry is appended (durable) when it
  arrives, and applied (accumulate's writes, buffered) once committed.
  The seven invariants of section 9.5 hold, each with a test.
- **The log row carries a kind:** a work result, a no-op, a
  configuration, or a blob reference.
- **Applied index and version part.** The applied index counts log
  entries; the agent's version counts applied work results that were not
  skipped (section 7.5). Both are stored.
- **Raft meta rows:** term, vote, commit index, snapshot index and term,
  active configuration.
- **Truncation and compaction:** truncate after an index (a new leader's
  conflicting suffix). Compaction stays at or below the durably applied
  index (invariant 4). The writer records, per synced flush, the highest
  applied index that flush made durable, and that is the bound, never the
  applied index in memory.
- **Snapshots:** an agent's snapshot is its key prefix in `state` and
  `system`, read from one store snapshot and streamed in chunks.
- **Installing a snapshot is one switch.**
  - Chunks go to a staging copy of the agent's prefix (an epoch byte in
    the prefix).
  - One synced batch then moves the agent's epoch pointer and records the
    applied index, the version, and the snapshot's index and term.
  - The old epoch is range-deleted afterwards.
  - Queries read through the pointer, so they never see a half-installed
    state. A crash before the switch leaves the old state and index;
    after it, the new ones.
  - Invariant 6 becomes: a snapshot and the index that depends on it are
    one durable batch.
- **Recovery:** after a crash a replica re-applies the log from its
  recovered applied index. Applies are buffered, so a crash may lose a
  local apply of a committed entry, including session marks, reply
  windows and outbox rows. Re-applying regenerates them, with the same
  outbox sequence numbers, which receivers deduplicate (section 9.5).

**Large entries take a blob path** [decided by step 3.1; see
`slice-3-progress.md`]:

- **Why:** through a shared writer, one agent's 4 MiB entries pushed every
  other agent's small appends to a p99 of 263 ms, and no flush cap
  helped. A separate blob writer brought it to 15 ms.
- **What:**
  - entries of 64 KiB or more are content-addressed blobs, written by the
    node's blob writer (its own thread, files and syncs, with group
    commit);
  - the log entry carries the blob's hash and length;
  - smaller entries stay inline;
  - S3's slow 64 KiB entries were redb's cost per commit, not the
    driver's.
- **Why not one log file for everything:** it would give up invariant 2
  (state and log share one journal). Blobs keep every reference in the
  journal, and invariant 7 bridges the blob file.

What the blob path requires:

- **A blob counts as durable only once verified** against its hash; the
  length in the reference bounds the receive.
- **An entry is durable when its reference and every blob it names are,**
  on every replica, the leader included. That is invariant 7 as this
  slice applies it; section 9.5's wording ("durable before the entry is
  proposed") is updated to match. The writer reports an entry durable only
  then, so the leader's self-count, `match_index` and the read barrier need
  nothing more. An append that arrives before its blob is appended but
  not yet durable, not refused.
- **So a replica that holds an entry holds its blobs,** which makes a
  leader change safe: any replica with the entry can serve its blobs.
- **Fetching:** a replica missing a named blob fetches it from the leader
  or any replica holding the entry. A leader keeps blobs as long as it
  keeps their entries for lagging followers.
- **Hashing runs on executors** (BLAKE2b-256 over 4 MiB is 2–4 ms): the
  leader hashes at refine's end and a follower on receipt, never a writer
  thread.
- **Accumulate resolves a reference to its bytes** before it runs: a
  read on the apply path, off the journal.
- **Collection:**
  - A blob is referenced by log entries, by installed programs across
    every agent (one blob, many pins), and by blobs a leader sent ahead of
    appends still in flight.
  - An unreferenced blob is garbage only after a horizon, since its append
    may be in flight. Blobs sent ahead by a leader that died, and blobs of
    a truncated suffix, become such orphans.
- **New files are durable** only with a directory sync, or segments are
  preallocated; step 3.3 chooses.
- **Programs** always take the blob path (an install body may hold
  64 MiB). The node's program store becomes pinned blobs, so every replica
  can lead.

### The network [owner decision 2: QUIC, behind an abstraction]

Nodes talk through a **network layer that knows nothing of Raft**, so
that a consensus for public spaces, or libp2p, can come later. It offers:

- **authenticated channels between node identities:** a node is its
  ed25519 key, not its address. The receiver of every message learns the
  authenticated sender, for authorization above;
- **classes of traffic:** liveness, consensus, requests and messages,
  bulk (blobs, snapshot chunks). Each class has its own priority and flow
  control;
- **streams by group or by message, not one per class,** so one agent's
  1 MiB append does not delay everyone's small ones. Order holds only
  within a stream; a message is delivered at most once;
- **SCALE-encoded messages,** whose meaning belongs to the layer above.

What it is not:

- **Combined heartbeats and quiescence are not in it.** They belong to
  the node's multi-group driver, which sends them as ordinary messages on
  the liveness class.
- **Pair liveness comes from the driver's own messages,** not transport
  keepalives, so a wedged executor looks dead.

**Authorization**, in the node's group driver:

- every Raft message must come from a configured node of the space. A
  replica's own configuration may lag: after C is replaced by D, a
  replica behind the joint entry would otherwise drop every append from D
  and never catch up;
- an append must come from the leader it names, and a vote request from
  the candidate it names;
- votes and acknowledgements count only from the group's members, as
  vos-raft does today;
- anything else is dropped and counted.

The first implementation is **QUIC** (`quinn` on its smol runtime):

- TLS 1.3 bound to the node's key;
- no 0-RTT; ALPN for protocol versions;
- a large connection-level receive window, so unread bulk cannot starve
  other streams; stream priorities by class;
- slice 2's random node id becomes the node's key.

An in-process implementation, step 3.2's simulator, serves the tests.

**Peers and the directory**, until the catalog:

- each node's configuration lists every peer: a node number (stable,
  never reused), its key and address;
- **the directory:** which nodes host each agent. Creation and membership
  changes are broadcast to every configured node, versioned by the
  agent's configuration index, so a sender finds a receiver agent's
  replicas;
- removed replicas leave tombstones, so stale messages cannot bring them
  back.

**What a consensus for public spaces would need.** Byzantine faults
inside a space are a non-goal for v1 (core model section 2). For later:

- **the network layer would gain:**
  - multicast or gossip;
  - a message's origin apart from the channel peer, with transferable
    signatures made by the consensus layer;
  - a dynamic set of peers with discovery;
  - quotas per peer.
- **The execution model changes too,** not just the network's users:
  - today the leader refines;
  - accumulate applies writes without re-executing them;
  - one replica's reply is trusted.

  A Byzantine-fault-tolerant space needs re-execution or proofs, and
  quorums of replies. "Without changing what runs above" holds only for
  the network layer's own users.

### Replicated agents in the node

- **Groups.** Each agent with more than one replica has a Raft group; a
  single-replica agent keeps slice 2's path (a group of one, through the
  same code, if that costs nothing measurable).
- **Creation** [owner decision 3]:
  - the operator creates an agent on one node with its replica set;
  - that node tells the others (the directory), and each replica starts
    the group with the same initial configuration;
  - agent ids come from per-node ranges: 8 bits of node number (a space
    of at most 256 nodes until the catalog), 24 of counter.
- **The leader** batches and refines as in slice 2, proposes the work
  result, and dispatches replies and messages only after its own
  accumulate applied it (section 7.5).
- **Followers** apply committed entries in order (up to min(commit,
  verified), above) and answer their own clients from applied state.
- **Leader changes** (section 7.5):
  - a new leader commits a no-op and applies everything before it before
    refining. It takes its batch version from the agent's `version` key
    once applied through its no-op, and its batch times never go below
    the last committed one;
  - no-ops, acknowledgements and configuration entries advance the
    applied index but not the version, so the two part; `Node::open`'s
    check that they are equal goes;
  - accumulate skips a result whose version is no longer current, and its
    inputs are retried;
  - a skipped result or a term change aborts the leader's pipeline and
    flushes its cached machines.
- **What a client signs:** the agent's identity (the hash of its creation
  record, carried in its configuration entry), not a node's, so any
  replica accepts it.
- **Forwarding.** The replica a client calls forwards the request to the
  leader. It never runs lane logic (window, gap, in flight) itself,
  because its applied marks may lag.
  - It **verifies the signature first,** on an executor: every request
    names its key, so any replica can, and garbage never reaches the
    leader. At about 50 µs a signature, this keeps one core's worth of
    checks per 20k requests a second off the leader's thread.
  - The leader runs the lane and answers once its replica applied the
    request. The forwarding replica then waits for its own apply to reach
    that entry and answers from its own applied state.
  - A forward is idempotent by (session, sequence). On `NotLeader` or a
    timeout the replica forwards again to the new leader. That leader's
    lane serves the reply from the window if the entry committed, or runs
    the request; a duplicate of a request pending in its pipeline joins
    it (section 7.5).
- **Queries** run on any replica against applied state; a client may ask
  for a version at or after one it has seen. `#[msg(linearizable)]` first
  takes the read index.
- **Messages between agents:**
  - The outbox is replicated state. The sender's leader finds the
    receiver's replicas in the directory and sends each message and
    acknowledgement to the receiver's leader.
  - A replica that is not the leader answers `NotLeader { hint }`, and
    the sender retries there.
  - A new leader on either side resends what is unacknowledged.
  - Messages are idempotent by per-pair sequence number and
    acknowledgements are monotone, so every retry is safe, as in slice 2.

### Sessions [owner decision 3: named by the client, in the agent]

Sessions move into the agent's replicated state, the only choice that
keeps exactly-once across failover. Every replica can then authenticate a
session's requests and retries, so a client that fails over keeps its
session, its sequence numbers and its replies. Slice 2's node-level session
registry goes, and section 8.4's "the server assigns session ids" is
replaced.

- **A session is named by the client:** its key, a random 128-bit name,
  and a creation time t0, all in every signed request. No open, no extra
  log entry. **The triple is the session's identity:** a client that
  reuses a name with a new t0 starts a new session. Looked up by (key,
  name) alone, its first request would get the old session's stored reply
  and never run.
- **Created once:** accumulate creates a session only if t0 is within the
  skew of the batch's time.
- **Collected safely:** accumulate collects a session only when it has
  expired after inactivity *and* the batch time is past t0 plus the skew.
  A request naming an absent session whose t0 is stale is refused with
  "session expired" and never runs.
  - Without the t0 rule this design replays. A client's request commits,
    its reply is lost, the client stays away past expiry, the session is
    collected, and the resend creates the session again and runs the
    request twice. Anyone who captured the signed request could do the
    same.
- **Caps refuse, never evict:** a per-key cap and a per-agent cap on live
  sessions refuse new sessions. Evicting the oldest, as slice 2's per-key
  cap does, would collect a session that is still alive and reopen the
  replay.
- **Collection** runs in accumulate by work-result time, through an expiry
  index in the agent's state. A sweep input lets idle agents collect too.
  Admission limits the rate of new sessions, but not how many are alive:
  20k a second for a one-hour expiry would be 72M sessions in replicated
  state and snapshots, hence the cap.
- **Inside the agent,** a session is a compact number assigned at
  creation from a counter that is never reused, indexed by the triple, so
  marks and reply keys do not repeat its 48–56 bytes.
- **Refine refuses a stale t0 too,** as slice 2 does for sequence gaps,
  and the refusal carries the agent's time, so a client with a skewed
  clock can choose an acceptable t0.

**Batch time must never go backwards,** or the t0 rule replays: a replay
succeeds if time goes back by about the expiry. Today a new leader takes
the last batch time from the entry at its applied index, and falls back
to 0 when that entry is not a work result. In this slice that entry is
usually its own no-op, or compacted away. So:

- the agent's replicated state keeps a batch-time high-water mark,
  carried by snapshots;
- refine never goes below it, and accumulate refuses a result that does;
- nodes are kept within seconds of each other (NTP), an assumption the
  plan states;
- a leader whose clock trails the stored time by more than a bound hands
  over leadership. A fast clock otherwise pushes batch time ahead for
  every later leader, and a slow one freezes it. Once the gap passes the
  skew, every new session is refused until real time catches up.
- **Lane logic** runs only on the leader (above).

### What a client reveals, and how to reveal less

The owner wants clients as private as possible, and those who want
privacy able to run their own node.

**What every replica of the agent retains**, in its log, applied state and
snapshots, for as long as they are kept:

- each session's key, name, t0 and sequence numbers;
- each reply, failures' details included;
- each step's writes;
- the instances each step ran and the gas each used, a side channel on
  the code's path;
- outgoing messages to other agents, with their arguments;
- attestable runs' private arguments and outputs;
- each batch's time and seed.

**What replicas see in transit** without retaining it in the log:

- each request's method and arguments, at the replica the client called
  and at the leader (and any replica may become the leader);
- a query's arguments and result, at the replica that serves it, linked to
  the session by its key;
- which replica forwarded a request, and when it arrived (the leader).

**What links a client's sessions** even with a fresh key for each:

- its network address, and a reused connection;
- timing, and the content of its requests;
- the node that forwarded them.

**Other leaks:**

- **Agent ids** reveal the node that created the agent, and in what order.
  They appear in URLs and in messages' `from`.
- **A new or replacement replica** receives the retained history of every
  session, through a snapshot or the log. So "choose replicas" covers
  future replicas too.
- **Collection is logical, not physical:** LSM tombstones, journals, blob
  files and orphan blobs keep data on disk until compaction and
  collection catch up.
- **Messages to other agents** carry request-derived data to their
  operators, with timing that correlates.
- **The schema endpoint is public.**

**What this slice does:**

- **TLS on client ingress** (rustls, or HTTP/3 on the same QUIC stack),
  with the server's key pinned to the replica's node key from the agent's
  configuration.
  - Today ingress is plain HTTP: anyone on the path reads keys, sessions,
    methods, arguments and replies. They can also capture signed requests,
    which fetch stored replies from the window, and forge answers, which
    are unsigned.
  - Required before any client reaches a replica over a real network.
- **Fresh keys:** sessions need no long-term identity. Only an actor whose
  roles name a principal needs one.
- **Session caps and collection,** as above, as data minimisation:
  replies do not outlive their window, logically.
- **Logs and metrics** never carry keys, session names or arguments.
- **Choosing replicas:** an agent that holds private data is replicated on
  nodes its owners trust, now and later.

**A client's own node** [proposed, small; or deferred to step 5]:

- It connects **as a client, without a node identity:**
  - it forwards signed requests, and the receiving replica verifies each
    one;
  - answers are relayed back to it;
  - admission and limits on pending requests apply per forwarder;
  - it gets no Raft, agent-message, blob or snapshot traffic.
- **What it is not:** a node in the group. As an authenticated node, its
  key and address would link every session it forwards, worse than a
  client with fresh keys. And vos-raft trusts the sender (authorization
  above).
- **In this slice it adds little.** Its purpose comes with local
  execution (below).

**Later, each with its home:**

- **Content:** the request runs on the client's own node and submits only
  its writes and a zero-knowledge proof. This needs proven `#[attestable]`
  methods (step 5), zero knowledge (items 9–11) and read sets validated at
  accumulate (open question 8). Fetching the witnesses still reveals what
  is read, unless they are fetched privately or in bulk.
- **Writes** are visible to replicas, which execute on plaintext. The
  compressed root format (step 4) hides values only in published roots.
  Hiding writes from replicas needs encryption held by clients (notes and
  nullifiers), and encrypted private agents are a v1 non-goal (core model
  section 2).
- **Network address:** a relay in front of client ingress (an Oblivious
  HTTP relay, or Tor), not the node-to-node layer.
- **Roles without identity:** anonymous credentials, proving membership
  of a role in zero knowledge.
- **Rate limits without identity:** for example rate-limiting
  nullifiers, so fresh keys cannot flood an agent.
- **Sizes and timing:** padding.

### Many active agents per node (item 16)

- one node writer for every agent;
- one executor runs every group's core and every leader loop; refines and
  accumulates stay on executor threads;
- **the multi-group driver** sends one combined heartbeat per node pair
  and interval. It carries the sending node's incarnation, and its answers
  are the pair's liveness signal.
- **Quiescence:** a group quiesces after a few idle intervals only while
  its leader's node answers the pair heartbeat.
  - A missed pair heartbeat, or a new incarnation of the leader's node,
    wakes every group led from that node. So does a proposal, for its
    group.
  - A pre-vote from the presumed leader itself clears the presumption.
  - One flaky link must not start elections in every quiesced group: the
    pair heartbeat must miss for a full election timeout first.
- admission per agent as in slice 2.

## Steps

### 3.1 Large entries (item 18) [done]

Measured durable appends through the node writer on fjall by entry size,
alone and beside other agents' small entries; found the cause of S3's
64 KiB case; settled the blob path above (`slice-3-progress.md`).

### 3.2 vos-raft core [done]

- Restructure the worker into the core above.
- Run the existing tests on it through the thin driver.
- Build the simulator.
- Then add, each with tests:
  - durability as (index, term), with truncation;
  - `verified`, and the commit index capped per peer;
  - which messages wait for their write;
  - the two answers per append, self-describing;
  - replicate on propose with the byte cap and the in-flight slot;
  - heartbeats regardless of appends;
  - rounds on every append;
  - fast backtracking;
  - check-quorum, leadership transfer and the stalled writer;
  - snapshots and compaction moved out to the node.

### 3.3 Node storage for Raft [done]

The blob store and its writer, log kinds, meta rows, truncation,
compaction below the durably applied index, the applied index apart from
the version, per-change durability, snapshot export, staged ingestion and
the atomic switch, recovery. A crash test like slice 2's, per invariant of
section 9.5.

### 3.4 The network [done]

The network layer and its messages (SCALE), with authorization in the
group driver. The in-process implementation is step 3.2's simulator;
then QUIC. Then TLS on client ingress.

### 3.5 Replicated agents [done]

Split in four, with 3.6's sessions moved ahead of forwarding: the
replicated group (3.5a), sessions in the agent (3.5b), any replica
serving (3.5c), and messages across nodes and processes (3.5d). See the
progress log.

- Groups and the directory.
- Creation with a replica set.
- The leader proposing and followers applying.
- Leader changes per section 7.5.
- Forwarding with verification, and re-forwarding.
- What clients sign.
- Followers' queries and read-index queries.
- Programs reaching every replica.
- Agent messages between nodes.

Three nodes in one process first, then three processes.

**The exactly-once checker lands here,** run under randomized faults in
the in-process cluster:

- its history holds increments, replies and read-index queries;
- no acknowledged request is lost or applied twice;
- no reply leaves before its result is applied on the answering replica;
- no message is lost or applied twice;
- every read-index query is linearizable.

Steps 3.6–3.8 extend it.

### 3.6 Sessions [done]

Client-named sessions in the agent, with t0, caps that refuse, and
collection with the expiry index and the sweep. The checker gains expiry
and replay: a resend after collection and a captured request both fail.

### 3.7 Snapshots and catching up [done]

Log compaction on every replica, snapshots streamed to a lagging or new
replica, and replacing a replica through a membership change.

A snapshot carries applied state, so work results' blobs need not travel
with it, but pinned blobs (programs) do:

- its manifest lists the pinned hashes;
- the receiver fetches those it lacks;
- the switch batch is written only once every one is durable (as
  invariant 6).

### 3.8 Many active agents (item 16)

Writer batching across agents, scheduling under load, combined
heartbeats and quiescence. Tests with 64 active agents and 1,000 idle
groups, including a flaky link.

### 3.9 Faults across processes

The checker's faults on three processes: kills, restarts, partitions
between processes, slow and stalled disks.

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
| Raft safety | election safety, log matching, leader completeness and state-machine safety under the simulated faults; read-index queries linearizable across leader changes |
| Section 9.5 | a crash test per invariant |
| Exactly-once | the checker passes, replay and expiry included |
| Budgets | as in 3.10 |

## Risks

- **Restructuring vos-raft** touches every path of a 4,500-line worker.
  The guard is to run the existing tests on the core first, and then the
  simulated faults. The protocol logic moves; it is not rewritten.
- **The blob path is in this slice** (step 3.1), not step 4: a second
  writer per node, blobs on the network with flow control, and
  collection by liveness.
- **Sessions in the agent** change slice 2's ingress and client protocol.
- **One laptop** measures three replicas on one disk and one CPU, as S3
  did; a second machine, or two, would make the replicated numbers mean
  more.

## Decisions [decided by the owner]

1. **vos-raft becomes a core without I/O,** driven by the node.
2. **QUIC, behind a network layer that knows nothing of Raft,** so a
   consensus for public spaces, or libp2p, can come later. What that
   consensus would also need is under "The network".
3. **Sessions are named by the client and live in the agent,** so
   failover keeps exactly-once:
   - clients sign for the agent's identity, which changes slice 2's
     client protocol;
   - agent ids come from per-node ranges;
   - privacy goes as far as this slice can take it ("What a client
     reveals");
   - a client's own node is proposed, small.
4. **Scope as planned:** pipelined refines only if the budget needs them,
   and the catalog's placement left out.

**Defaults** (engineering, recorded rather than asked):

| Setting | Value |
|---|---|
| Heartbeat | 500 ms |
| Election timeout | 1.5–3 s |
| Quiescence | after 4 idle intervals |
| Blob threshold | 64 KiB |
| Append cap | 1 MiB inline |
| Flush cap | 8 MiB |
| Compaction | past 4,096 entries or 64 MiB beyond the applied index |
| Session skew | 5 minutes |
| Live sessions | 1M per agent |

Step 3.10 may move them.
