# Slice 3 progress

The record of building slice 3 (`slice-3-replication.md`), step by step.

## Step 3.1: large entries (item 18)

**Harnesses:**

- `node/host/src/bin/log-bench.rs` writes through writers shaped like the
  node log writer: one thread per node drains every queued append into
  one fjall batch and one sync, up to a cap in bytes.
  - Three nodes on one disk stand in for a leader and two followers; an
    entry commits once two of the three made it durable.
  - Entries are incompressible, as encoded work results mostly are.
  - `sizes` runs closed-loop proposers by entry size; `mixed` runs 15
    agents of 1 KiB entries beside one agent of large entries.
  - `BLOBS=<bytes>` prototypes the blob path: entries at least that large
    go to a blob file per node, with their own writer and sync, and the
    log takes a 40-byte reference once the blob is durable.
- S3's harness gains `one <mem|redb> <bytes> <proposers>`, to rerun single
  cases.

**The disk:** a WD SN740 2 TB, 86% full. A direct 1 GiB sequential write
runs at 2.4–2.5 GB/s; one append and `fdatasync` takes 0.5–1.4 ms by size.
Large-write figures move with the drive's state, by up to 4× between
runs. The figures below come from isolated runs: each case alone, with a
pause before it, alternating configurations, two rounds.

**S3's slow 64 KiB entries were redb's cost, not the driver's:**

- The eager driver in memory commits 64 KiB entries at 38.9k per second.
- On redb, repeated runs give 430–520 per second (27–32 MiB/s). A single
  redb commit of 64 KiB costs 1.0 ms against 0.49 ms for a raw append and
  sync; at 256 KiB, 4.3 ms against 1.4 ms.
- A first run on a fresh drive reached 3.1k per second, which is how S3's
  figure could vary.

**fjall through the node writer**, three nodes, entries kept in the log
partition:

| Entry | Proposers | Commits/s | MiB/s committed | p50 | p99 |
|---|---|---|---|---|---|
| 1 KiB | 64 | 57–64k | 56–62 | 0.8 ms | 1.7–5.2 ms |
| 16 KiB | 16 | 10.4–11.2k | 162–175 | 1.2 ms | 5.6–7.7 ms |
| 64 KiB | 16 | 2.3–4.2k | 145–261 | 2.0 ms | 48–55 ms |
| 256 KiB | 16 | 200–850 | 50–212 | 7–67 ms | 0.15–1.1 s |
| 1 MiB | 8 | 184–349 | 185–349 | 14–16 ms | 80–610 ms |
| 4 MiB | 4 | 8–54 | 33–214 | 35–380 ms | 0.8–1.7 s |

- Small and medium entries are well within the replicated budget.
- From 64 KiB up, the tails grow to tens of milliseconds and then
  seconds: the memtable fills fast, and flushes and stalls follow.
- fjall's key-value separation does not help: the journal still carries
  every value before it reaches the value log. A constant-filled payload
  had made it look 4–40× faster, because lz4 compressed the payload away.
  With incompressible entries the two configurations are within noise,
  and separation is sometimes slower.

**One agent's large entries stall every agent's small ones.** 15 agents
appending 1 KiB entries, beside one agent of large entries, through the
shared writer:

| Beside | Path | Small commits/s | Small p50 | Small p99 | Large commits/s |
|---|---|---|---|---|---|
| nothing | log | 13.4k | 1.1 ms | 1.9 ms | — |
| 256 KiB entries | log | 8.7k | 1.2 ms | 9.6 ms | 581 |
| 256 KiB entries | log, flush cap 1 MiB | 8.4k | 1.2 ms | 19.0 ms | 563 |
| 256 KiB entries | blobs | 12.3k | 1.1 ms | 2.9 ms | 564 |
| 4 MiB entries | log | 548 | 10.4 ms | 263 ms | 33 |
| 4 MiB entries | log, flush cap 8 MiB | 497 | 9.9 ms | 293 ms | 30 |
| 4 MiB entries | log, flush cap 1 MiB | 692 | 9.5 ms | 235 ms | 44 |
| 4 MiB entries | blobs | 6.1k | 1.4 ms | 14.8 ms | 146 |

- A flush cap does not help: the large write itself, and the LSM work
  behind it, block the queue.
- A separate blob writer does. The small entries' p99 drops from 263 ms
  to 15 ms beside 4 MiB entries, and to 2.9 ms beside 256 KiB ones. The
  large agent also commits 4.4× faster at 4 MiB.
- What remains beside 4 MiB entries is the shared disk: three nodes
  write about 1.75 GB/s between them.

**Why not the alternatives:**

- **A priority queue in one writer** cannot help, and the flush-cap rows
  are that experiment. A 1 MiB cap already puts a 4 MiB entry in a batch
  of its own, which is all a priority queue would do, and the small p99
  stays at 235–293 ms. The cost is the large journal write and the LSM
  work behind it inside one commit, which blocks the journal for every
  agent whatever the order.
- **A raw segment log for everything** would write large entries as well
  as the blob file does, since it is the same write. But it gives up
  section 9.5's invariant 2: state and log share one journal, so a
  buffered apply is never durable without the log write it depends on.
  With the log in its own file, a later fjall sync could make an apply
  durable while the local log entry is not, and recovery would need a
  path to fetch the missing entries. Blobs keep every reference in the
  one journal, and invariant 7 bridges the blob file.

**The threshold, from below:** entries just under 64 KiB, inline, do not
move the small entries' latency (two rounds, isolated):

| Beside | Small commits/s | Small p99 | Large commits/s |
|---|---|---|---|
| nothing | 13.3–13.4k | 1.9–2.1 ms | — |
| 32 KiB entries | 13.4–13.5k | 1.9–2.2 ms | 886–897 |
| 48 KiB entries | 12.9–13.4k | 2.0–2.5 ms | 852–889 |

64 KiB entries alone already show a p99 of about 50 ms, so 64 KiB is the
threshold.

**Decided** (settles the plan's inline-or-blob question):

- **Entries of 64 KiB or more take the blob path.**
  - The payload is a content-addressed blob (BLAKE2b-256), written by the
    node's blob writer: its own thread, its own files and syncs, with
    group commit.
  - The log entry carries the blob's hash and length.
  - A replica appends the reference only after its own copy of the blob
    is durable (section 9.5's invariant 7).
  - The leader sends the blob ahead of the append that names it, and a
    follower acknowledges the entry only once both are durable.
- **Smaller entries stay inline** in fjall's log partition, without
  key-value separation.
- **Programs always take the blob path:** an install body may hold
  64 MiB. The node's program store becomes pinned blobs.
- **The flush cap stays as a guard** (8 MiB), not as the remedy.
- **Blob lifetime:**
  - a work result's blob lives until log compaction passes its entry;
  - a program's lives while installed;
  - snapshot pages and witnesses (step 4) reuse the path.

  Blob files are collected by liveness; step 3.3 designs it.

**What this changes in the plan:**

- step 3.3 includes the blob store;
- the transport (3.4) carries blobs, with flow control so they never
  delay heartbeats;
- the replicated budget is for simple mutations: on this laptop, large
  entries' throughput across three nodes on one disk is about
  150–350 MiB/s committed.

**Review:** Fable signed off on the decision and the measurements. Its
additions are in: why not the alternatives, the threshold from below,
the file-creation caveat, and in the plan what the blob path requires
(verification, durability folded into the durable index, fetching,
hashing on executors, accumulate's read, collection, snapshot
manifests).

**Caveats:**

- One laptop, with three nodes on one consumer NVMe that is 86% full.
- The prototype appends to one file created beforehand, so it never pays
  a directory sync. A store that creates files (one per blob, or
  segments) must sync the directory for a new file to be durable, or
  preallocate segments; step 3.3 chooses.

**Raw runs**, for step 3.10 to compare on the same drive, one line per
run:

```
# log-bench-isolated.txt (tree: entries kept in the log tree; 4096: key-value separation at 4 KiB)
round 1 tree:     1 KiB × 64 on 3 node(s):   57026 commits/s (  55.7 MiB/s), p50   0.86 ms, p99   5.23 ms
round 1 4096:     1 KiB × 64 on 3 node(s):   63690 commits/s (  62.2 MiB/s), p50   0.83 ms, p99   1.92 ms
round 1 tree:    16 KiB × 16 on 3 node(s):   11225 commits/s ( 175.4 MiB/s), p50   1.20 ms, p99   5.61 ms
round 1 4096:    16 KiB × 16 on 3 node(s):   11226 commits/s ( 175.4 MiB/s), p50   1.20 ms, p99   5.60 ms
round 1 tree:    64 KiB × 16 on 3 node(s):    3347 commits/s ( 209.2 MiB/s), p50   2.03 ms, p99  55.12 ms
round 1 4096:    64 KiB × 16 on 3 node(s):    2326 commits/s ( 145.4 MiB/s), p50   2.15 ms, p99  54.82 ms
round 1 tree:   256 KiB × 16 on 3 node(s):     848 commits/s ( 211.9 MiB/s), p50   7.60 ms, p99 279.85 ms
round 1 4096:   256 KiB × 16 on 3 node(s):     783 commits/s ( 195.8 MiB/s), p50   7.20 ms, p99 150.24 ms
round 1 tree:  1024 KiB ×  8 on 3 node(s):     186 commits/s ( 185.5 MiB/s), p50  14.85 ms, p99 610.69 ms
round 1 4096:  1024 KiB ×  8 on 3 node(s):     195 commits/s ( 195.2 MiB/s), p50  16.24 ms, p99 308.49 ms
round 1 tree:  4096 KiB ×  4 on 3 node(s):      54 commits/s ( 214.0 MiB/s), p50  35.26 ms, p99 786.40 ms
round 1 4096:  4096 KiB ×  4 on 3 node(s):      47 commits/s ( 187.0 MiB/s), p50  36.67 ms, p99 1194.61 ms
round 2 tree:     1 KiB × 64 on 3 node(s):   62170 commits/s (  60.7 MiB/s), p50   0.86 ms, p99   2.44 ms
round 2 4096:     1 KiB × 64 on 3 node(s):   63541 commits/s (  62.1 MiB/s), p50   0.83 ms, p99   1.70 ms
round 2 tree:    16 KiB × 16 on 3 node(s):   10398 commits/s ( 162.5 MiB/s), p50   1.20 ms, p99   7.66 ms
round 2 4096:    16 KiB × 16 on 3 node(s):   10939 commits/s ( 170.9 MiB/s), p50   1.20 ms, p99   6.28 ms
round 2 tree:    64 KiB × 16 on 3 node(s):    4172 commits/s ( 260.8 MiB/s), p50   2.00 ms, p99  48.03 ms
round 2 4096:    64 KiB × 16 on 3 node(s):    2579 commits/s ( 161.2 MiB/s), p50   2.09 ms, p99  50.37 ms
round 2 tree:   256 KiB × 16 on 3 node(s):     664 commits/s ( 166.0 MiB/s), p50   7.60 ms, p99 225.05 ms
round 2 4096:   256 KiB × 16 on 3 node(s):     199 commits/s (  49.8 MiB/s), p50  67.48 ms, p99 1118.53 ms
round 2 tree:  1024 KiB ×  8 on 3 node(s):     349 commits/s ( 349.2 MiB/s), p50  14.35 ms, p99  80.27 ms
round 2 4096:  1024 KiB ×  8 on 3 node(s):     184 commits/s ( 184.5 MiB/s), p50  16.15 ms, p99 549.20 ms
round 2 tree:  4096 KiB ×  4 on 3 node(s):      41 commits/s ( 164.0 MiB/s), p50  37.92 ms, p99 1253.06 ms
round 2 4096:  4096 KiB ×  4 on 3 node(s):       8 commits/s (  33.0 MiB/s), p50 380.35 ms, p99 1659.79 ms
# log-bench-mixed.txt
mixed 0: 15 agents of 1 KiB beside one of 0 KiB, no cap: small 13360 commits/s, p50 1.10 ms, p99 1.90 ms; large 0 commits/s
mixed 262144: 15 agents of 1 KiB beside one of 256 KiB, no cap: small 8713 commits/s, p50 1.20 ms, p99 9.56 ms; large 581 commits/s
mixed 262144 1048576: 15 agents of 1 KiB beside one of 256 KiB, cap 1024 KiB: small 8433 commits/s, p50 1.21 ms, p99 18.97 ms; large 563 commits/s
mixed 4194304: 15 agents of 1 KiB beside one of 4096 KiB, no cap: small 548 commits/s, p50 10.37 ms, p99 263.03 ms; large 33 commits/s
mixed 4194304 8388608: 15 agents of 1 KiB beside one of 4096 KiB, cap 8192 KiB: small 497 commits/s, p50 9.88 ms, p99 292.87 ms; large 30 commits/s
mixed 4194304 1048576: 15 agents of 1 KiB beside one of 4096 KiB, cap 1024 KiB: small 692 commits/s, p50 9.49 ms, p99 235.29 ms; large 44 commits/s
# log-bench-blobs.txt (blob path at 64 KiB)
blobs, mixed 262144: 15 agents of 1 KiB beside one of 256 KiB, no cap: small 12337 commits/s, p50 1.14 ms, p99 2.89 ms; large 564 commits/s
blobs, mixed 4194304: 15 agents of 1 KiB beside one of 4096 KiB, no cap: small 6072 commits/s, p50 1.43 ms, p99 14.78 ms; large 146 commits/s
blobs:    64 KiB × 16 on 3 node(s):    2712 commits/s ( 169.5 MiB/s), p50   2.80 ms, p99  39.14 ms
blobs:   256 KiB × 16 on 3 node(s):     933 commits/s ( 233.3 MiB/s), p50   6.81 ms, p99 108.05 ms
blobs:  1024 KiB ×  8 on 3 node(s):     194 commits/s ( 193.5 MiB/s), p50  25.56 ms, p99 175.48 ms
blobs:  4096 KiB ×  4 on 3 node(s):      57 commits/s ( 227.0 MiB/s), p50  17.67 ms, p99 409.41 ms
# log-bench-threshold.txt
round 1: 15 agents of 1 KiB beside one of 0 KiB, no cap: small 13274 commits/s, p50 1.12 ms, p99 2.07 ms; large 0 commits/s
round 1: 15 agents of 1 KiB beside one of 32 KiB, no cap: small 13372 commits/s, p50 1.10 ms, p99 2.17 ms; large 886 commits/s
round 1: 15 agents of 1 KiB beside one of 48 KiB, no cap: small 12903 commits/s, p50 1.11 ms, p99 2.45 ms; large 852 commits/s
round 2: 15 agents of 1 KiB beside one of 0 KiB, no cap: small 13403 commits/s, p50 1.10 ms, p99 1.91 ms; large 0 commits/s
round 2: 15 agents of 1 KiB beside one of 32 KiB, no cap: small 13489 commits/s, p50 1.09 ms, p99 1.93 ms; large 897 commits/s
round 2: 15 agents of 1 KiB beside one of 48 KiB, no cap: small 13350 commits/s, p50 1.09 ms, p99 1.96 ms; large 889 commits/s
```

## Step 3.2: the vos-raft core

**What changed:** vos-raft is now a protocol core without I/O, a driver
around it, and a simulator.

- `core::Core` (`no_std + alloc`) is one replica as a state machine.
  - Events in: ticks, messages, proposals, reads, membership changes,
    transfers, and the host's reports (`durable`, `loaded`,
    `snapshot_installed`, `snapshot_failed`, `durably_applied`,
    `compacted`, `writer_health`, `peer_alive`).
  - Actions out: ordered writes, one-way sends, loads, commit
    notifications, snapshot sends, the compaction bound, answers, and
    role changes.
  - It keeps the log's terms as runs and a suffix of entries in a byte-
    bounded cache (`log_view`); older entries come back through
    `LoadEntries`.
- `message::Message` replaces the request/response RPC structs: appends
  and their answers, votes, pre-votes and `TimeoutNow`. Every message is
  one-way, and each answer says what it answers (round, commit, matched
  or rejected, with a hint).
- `Transport` is now `send(from, to, envelope)`, one-way and non-
  blocking; a host hands what arrives to `WorkerHandle::deliver`.
  Snapshot chunks and their acknowledgements travel as their own
  envelopes, and the driver streams them, one chunk in flight.
- The worker became the driver. It carries out the core's actions
  against `Storage`, `Transport` and `ApplySink`.
  - **Each round hands the core everything already in the inbox**, so a
    burst of proposals or appends becomes one write.
  - **`snapshot()` is a barrier:** it is answered after the round's
    writes are durable and its answers sent.
  - **A store that returns `Err` stops the worker.** It cannot know what
    reached the disk. Its role reads follower from then on, and requests
    report `Stopped`, which replaces the never-returned `Storage(())`
    variants. Before, a stopped worker answered `NotLeader`.
- `sim` (std) runs groups of cores over a simulated network and stores.
  It checks for two leaders in a term, two entries at one committed
  index, a commit past a replica's log, and a read index below what was
  committed anywhere when the read was asked.
  - The network drops, duplicates, delays and partitions messages, and
    carries snapshots like any other message.
  - Stores sync after a random delay, and a crash keeps a random prefix
    of the unsynced writes and compactions. A snapshot switch is durable
    at once, after every write before it, as the driver's is.
  - The chaos runs crash nodes every few hundred milliseconds, partition
    and heal, and propose and read throughout. The cache holds 64 bytes
    and the log compacts every four entries, so lagging replicas load
    from the store or install snapshots. One variant has four nodes, with
    the membership moving between three-node subsets.
  - Over 200 seeds, the fixed-membership run installs 3,771 snapshots,
    makes 56,230 compactions durable, answers 54,710 loads and checks
    16,024 reads. The churn run starts 2,438 membership changes and
    installs 5,442 snapshots. The test fails if these fall well below.

**The plan's items, and what pins each one:**

| Item | Tests |
|---|---|
| Durability as (index, term), with truncation | `a_late_report_of_a_replaced_write_vouches_for_nothing` |
| `verified`, and the commit index capped per peer | `a_commit_index_never_applies_an_unverified_entry`, `a_leader_sends_each_peer_a_commit_it_has_acknowledged` |
| Which messages wait for their write | `a_vote_leaves_only_once_it_is_durable`, `an_answer_at_a_new_term_waits_for_the_term`, `a_candidate_counts_its_own_vote_only_once_durable` |
| Two answers per append, self-describing | `a_late_report_…` (the durable prefix at once, the rest once durable) |
| Replicate on propose, in-flight slot, byte cap | `a_proposal_goes_out_at_once_unless_an_append_is_in_flight`, `an_append_carries_at_most_its_byte_cap` |
| Heartbeats regardless of appends | `heartbeats_go_to_peers_with_an_append_in_flight` |
| Rounds on every append | `read_index_ignores_answers_to_heartbeats_sent_before_it` |
| Fast backtracking | `a_rejection_moves_the_probe_past_the_conflicting_term` |
| Check-quorum | `check_quorum_deposes_a_leader_that_hears_from_no_one` |
| Leadership transfer | `a_transfer_hands_over_once_the_target_holds_everything` |
| The stalled writer | `a_stalled_writer_hands_leadership_over`, `a_stalled_leader_keeps_handing_over_until_a_peer_catches_up`, `a_stalled_leader_steps_down_and_stays_quiet` |
| Pre-votes cannot depose a live leader | `a_leader_refuses_pre_votes`, `isolated_follower_does_not_inflate_term_under_pre_vote` |
| Snapshots and compaction moved out | the chunked-snapshot tests in `state_machine.rs`, `compaction_never_crosses_durable_application_cursor`, `compaction_survives_a_restart` |
| Loads from the store | `a_follower_behind_the_cache_catches_up_from_the_store` |
| A snapshot switch is one atomic write | `a_crash_after_a_snapshot_switch_keeps_its_membership` |
| Safety under faults | `safety_holds_under_faults` and `safety_holds_under_faults_and_membership_changes`: 200 seeds each of 2,000 steps (see below) |

**Mutation checks.** Each safety rule was broken by hand, and the tests
must fail:

| Mutation | Caught by |
|---|---|
| A leader counts its own log before it is durable | core test; chaos (seed 13) |
| A follower applies past its verified index | core test |
| A vote leaves before it is durable | core test; churn chaos (seed 96) |
| A heartbeat's commit is not capped at the peer's match | core test; churn chaos (seed 50) |
| A late write report vouches for a replaced entry | core test |
| An answer at a new term leaves before the term is durable | core test |
| No in-flight slot | core test |
| No byte cap | core test |
| Backtracking one index at a time | core test |
| No check-quorum | core test |
| Proposals taken during a transfer | core test |
| `TimeoutNow` before the target holds everything | core test |
| A stalled leader gives up handing over | core test |
| A stalled leader never steps down | core test |
| A stalled replica campaigns | core test |
| A leader grants pre-votes | core test |
| `TimeoutNow` taken from anyone | core test |
| The switch's membership record taken from the old view | persistence tests |
| Loads that can never join the cache, reissued (the spin) | core test |
| The switch batch without its meta and membership record | persistence test |
| No replication on an append's answer | two core tests |

Chaos misses four of these: the early answer at a new term, the late
write report, applying an unverified entry, and the switch without its
rows. Each needs a narrow interleaving (for the last, a crash right
after a switch, during a membership change), and the direct tests pin
them.

**Found and fixed while building it:**

- **A stalled writer could never hand leadership over.** `TimeoutNow`
  also waited for the leader's own log to be durable, which a stalled
  writer never makes it. What makes the handover safe is that the
  target holds every entry. Found by writing the test.
- **A stalled leader gave up handing over.** A transfer that outlived its
  deadline was dropped, and the leader took proposals again with its
  writer still stalled. While the writer stays stalled, it now starts a
  new handover to its most up-to-date peer and refuses proposals.
- **The first driver paid one fsync per proposal.** It took the core's
  actions after each inbox message. The S3 harness, ported to the new
  transport, showed it: 4.1k commits per second at 64 proposers on redb,
  against 23k for the old worker. Draining the inbox each round fixed it.

**Review** (Opus, no-go until B1 and B2 were fixed; all items below are
fixed, with tests):

- **B1. A lagging follower made the leader spin.** A load for entries
  the cache had evicted asked for everything up to the end of the log,
  which could never join the cache's front, so the core dropped the
  result and asked again, forever. A load now covers only the gap below
  the cache, capped in bytes, and its result goes straight to the peer
  waiting for it. An empty result is not reissued; the peer's next
  answer retries.
- **B2. A snapshot switch was not atomic with its membership record.**
  The switch wrote the state and the compaction, and the commit index
  and membership record came in a later write. After a crash between the
  two, a replica could restart with the snapshot's state and a membership
  the group had left, and count a quorum of the wrong members. The core
  now computes the switch's rows (`snapshot_switch`), and the driver
  writes them in the switch's batch, after every earlier write.
- **S1. A leader granted pre-votes**, so a follower that stopped hearing
  it over a lossy link could depose it. A leader now refuses.
- **S2. The simulator never exercised snapshots, compaction, loads or
  reads.** It now does, and it checks reads; see above.
- **S3. A stalled leader had no fallback.** After three handovers that
  fail, it steps down, and a replica whose writer is stalled does not
  campaign.
- **S4. Followers ignored the cache bound.** They now evict too.
- **S5.** The answer to an installed snapshot waits for its term to be
  durable, as every other answer does.
- **Nits fixed:**
  - a leader that steps down stops naming itself as the leader;
  - membership changes are refused during a handover, and finalizing a
    joint configuration waits for the handover to end or be given up;
  - `TimeoutNow` counts only from the known leader;
  - the retirement test pins the index again.
- **Found while fixing them:** a write's meta row carries the core's
  snapshot pointer as of when the write was made. A compaction made
  between the write's creation and its execution would then be undone
  in the store's meta. Hosts now keep their own pointer, which only
  compaction and a switch move: the driver, and the simulator's store.
  The persistence harness asserts that the pointer never moves back.

**Re-review** (Opus): go. Also fixed before the commit:

- **The switch's meta now records the term and vote in memory**, not
  the durable ones. A host whose writer queues the switch behind writes
  not yet reported (step 3.3's) would otherwise rewind a vote a queued
  write already made, and a crash could then let the replica vote twice
  in one term. The in-memory values are at least as new as anything
  queued, and persisting them early is safe.
- **A load that starts past its first index sends nothing.** A store
  that compacted between the request and the read returns entries from
  later on; sent as they were, the peer would reject them and its slot
  would wait out the resend timeout.
- **A stalled replica ignores `TimeoutNow`**, as it does its own timer.

Tests: `a_snapshot_switch_records_the_newest_term_and_vote`,
`a_load_that_starts_late_sends_nothing`, and a stalled case in
`timeout_now_counts_only_from_the_leader`; each fails without its fix.

**Left to later steps, from the review:**

- `Write::sync` does not reach `Storage` yet (step 3.3's store takes it).
- A snapshot should be labelled with its state's applied index (3.3).
- Votes have no leader lease (only pre-votes); with pre-vote on, that is
  enough. Revisit if pre-vote can ever be off in production.
- The core accepts appends from any sender that names itself leader;
  step 3.4's group driver checks membership, and its tests cover
  non-member senders.
- **The pair heartbeat must vouch only for the groups a node leads**
  (step 3.8). Otherwise a leader that stepped down, for example because
  its writer stalled, keeps its followers refusing each other's
  pre-votes, and the group stays leaderless. `peer_alive`'s
  documentation states the contract.
- For step 3.3, keep the snapshot pointer in its own row, so no write
  touches it.
- For step 3.7: a replica whose suffix a snapshot drops keeps its
  current membership view, even when that view came from an entry in the
  dropped suffix (recorded without provenance). It lasts until the
  leader's next appends.

**Throughput against the old worker** (S3's `one` harness: three nodes,
1 KiB entries, in one process, same build profile; `old` is the eager
worker the spike carries):

| Store | Proposers | Old commits/s | New commits/s | Old p99 | New p99 |
|---|---|---|---|---|---|
| redb | 1 | 1,359 | 2,164 | 1.46 ms | 1.00 ms |
| redb | 64 | 22,953 | 33,691 | 7.80 ms | 3.44 ms |
| redb | 256 | 23,461 | 57,524 | 37.75 ms | 8.13 ms |
| memory | 1 | 115,068 | 124,833 | 0.02 ms | 0.02 ms |
| memory | 64 | 487,812 | 365,324 | 0.22 ms | 0.32 ms |

The one regression is in memory with 64 proposers. A profile puts most
of that run in tokio's scheduler and channel wake-ups: answers are now
messages of their own, where the old worker awaited replies inline.
Raft's own code is a small share. Nothing durable is affected; step 3.4's
transport sets the real per-message cost.

After the review's fixes: redb with 64 proposers runs at 33.3k–34.2k
commits per second (p99 3.2–3.4 ms, four runs; one earlier run dipped to
23.9k, which repeated runs put down to the drive). With 256 proposers it
runs at 58.5k. Memory with 64 proposers runs at 433k.

**What the old tests had to change:** they ran against the request/
response worker, and some pinned what the contract now replaces.

- `audit_findings.rs` is now `persistence.rs`, without the audit
  narrative.
- **A snapshot chunk moves no term.** A chunk is taken only from the
  leader of the replica's current term. A higher-term chunk is refused
  until the leader's heartbeat; that heartbeat makes the term durable
  before it is answered.
- **A failed write stops the worker** (`fault_injection.rs`, rewritten).
  Before, errors were swallowed, mapped to `Storage(())`, or left a
  candidate retrying.
- **A leader takes its role before its no-op is durable.** It answers no
  read until its term's first entry commits.
- **Recovery clamps the commit index to the log.** Two fixtures claimed a
  commit over an empty log; they now hold the entries.
- `proptest_invariants.rs` now also checks one durable vote per term,
  and draws from the two peers and few terms, so snapshot chunks come
  from the leader of the current term often enough to install.
- The S3 spike's transport is ported (the eager variant keeps the old
  one).

**Left for later steps:**

- `Storage` keeps its shape: step 3.3 replaces it with the node's log
  kinds, blob store and switch.
- The driver keeps one thread per worker by default. Step 3.8 drives
  many groups per node.

**Checks:**

- `just ci` is green.
- vos-raft has 102 tests in 10 binaries, unit tests and the doctest
  included. The suite ran 10 times in a row without a failure before the
  last two deterministic core tests.
- clippy and rustdoc are clean, with and without features.

## Step 3.3: node storage for Raft

### Design

Step 3.3 gives the node's store what a replicated agent needs. The node
itself stays on slice 2's single-replica path until step 3.5, which runs
it through Raft; this step builds and tests the storage, the writer and
an adapter between them and vos-raft's core, and keeps the single-node
path working on the new layout.

It lands in three parts, each with its own review and commit:

1. **Layout, Raft rows and the writer** (3.3a).
2. **The blob store** (3.3b).
3. **Snapshots: export, staging and the switch** (3.3c).

#### 3.3a Layout, Raft rows and the writer

**Keys.** One keyspace, as in slice 2, with an epoch byte after the
agent id, fixed at 0 until 3.3c installs snapshots, so the layout, slice
2's tests and its bench change once:

| Partition | Key | Value |
|---|---|---|
| `state` | agent (4) ∥ epoch (1) ∥ agent key | row |
| `system` | agent (4) ∥ epoch (1) ∥ agent system key (`0x00` …) | row |
| `system` | agent (4) ∥ `0xff` ∥ kind | the node's rows for the agent |
| `log` | agent (4) ∥ index (8) | term (8) ∥ kind (1) ∥ blobs ∥ body |

Epochs are `0..=0xfe`; `0xff` is the node's own rows, so no agent row
reaches them.

- **Every log row names the blobs it depends on:** a count, then each
  blob's hash and length, readable without decoding the work result. A
  work result too large to inline is a row with an empty body naming its
  blob; an install names its program. The writer (invariant 7) and the
  collector (3.3b) read these, and nothing else.
- **Log entry kinds** (`#[repr(u8)]`): a no-op, a work result, and a
  configuration. The Raft payload of a data entry is the kind byte, the
  blob list and the body; an empty payload is the no-op, as vos-raft
  writes it.

**The node's rows for an agent** (`agent ∥ 0xff ∥ kind`):

- **applied:** the last log index applied, in the same batch as the
  apply (invariant 1), as in slice 2;
- **hard state:** term, vote and commit index;
- **log start:** the index and term the log was compacted to, or a
  snapshot installed at. It has its own row, so no other write touches
  it (vos-raft's `Write::meta` carries a snapshot pointer the host must
  not take);
- **membership:** the active configuration record;
- the registry row (the agent's program) stays a node-wide record.

The agent's version stays in its own state (`keys::version()`); the
applied index counts log entries and the version counts applied work
results, so the two part. `Node::open`'s check that they are equal goes
with step 3.5, when no-ops reach the log.

**The node log writer** (slice 2's storage thread):

- **Per-change durability.** A change says whether it must be synced:
  appends, truncation, a term or vote, membership and the snapshot switch
  are; a commit-index move, applies, compaction and staged rows are not.
  A group of commits syncs if any change in it must. vos-raft's
  `Write::sync` maps onto it.
- **Reports.** Each commit is answered once its batch is written, or once
  synced if it asked to be. vos-raft's `durable(seq)` follows that
  answer.
- **The durably applied index**, per agent: every synced flush makes all
  earlier batches durable, so the writer records, per synced flush, the
  highest applied index of every agent up to it. That, never the applied
  index in memory, is what the agent reports to its core as durably
  applied, and so bounds compaction (invariant 4).
- **Group commit across agents,** with the 8 MiB flush cap as a guard.
- **Stalls.** The writer knows the age of its oldest pending commit; past
  a bound (configurable, 1 s by default) it reports itself stalled, and
  recovered once it drains. The node passes that to every core it runs
  (`writer_health`), which hands leadership over (step 3.2).
- **Truncation** removes the log's rows after an index, row by row (fjall
  has no range tombstones). Usually short, but a deposed leader that kept
  appending can leave tens of thousands of rows.
- **Compaction** removes the log's rows through an index, row by row,
  and writes the log-start row. It is buffered: losing it is harmless.
  The writer refuses one beyond the agent's durably applied index.

**Recovery.** `Store::raft(agent)` reads the hard state, log start,
membership, applied index and the log after the log start: everything
vos-raft's `Recovered` needs. The node then re-applies from the applied
index up to the commit index (step 3.5 drives it).

**The adapter** (`node/host/src/raft.rs`) maps the core's actions onto
the writer for one agent: a `Write` to changes (entries to appends,
`truncate_after`, the hard state without the snapshot pointer, the
membership record), `LoadEntries` to a log range read within its
`max_bytes`, `CompactBound` to a compaction, and the store's rows to
`Recovered`. Node numbers are `u8`
(the plan's 8-bit node part of an agent id).

**Tests:**

- unit tests of the rows, truncation and compaction;
- **three cores over three real stores**, in one process with a
  deterministic network, through the adapter and writer: proposals,
  leader changes, restarts that reopen each store, compaction; committed
  entries agree and survive;
- **crash tests**, in slice 2's harness (a child killed at random, then
  torn journal tails):
  - invariants 1 and 2: the store recovers an applied index and state
    that are one prefix, and the log holds every entry through it;
  - invariant 4: the log start never passes the applied index, and the
    log is contiguous after it;
  - a hard state reported synced survives.

#### 3.3b The blob store

**How blob files become durable** (the plan left it to this step). Four
layouts through `log-bench` (`BLOB_LAYOUT`), one node, interleaved over
three rounds after the drive idled; commits per second, 16 proposers (4
at 4 MiB):

| Blob | Append to one file | A file per blob | A file per group | A second fjall |
|---|---|---|---|---|
| 64 KiB | 3,136–8,570 | 1,016–1,165 | 2,752–8,567 | 1,680–5,036 |
| 256 KiB | 823–3,491 | 1,144–1,271 | 673–1,028 | 326–524 (p99 0.4–0.6 s) |
| 4 MiB | 56–155 | 70–182 | 45–58 | 28–59 (p99 0.6 s) |

- **A second fjall database** (its own journal and writer, key-value
  separation) writes every blob twice and stalls on flushes: its p99 is
  0.4–0.6 s from 256 KiB up. Out.
- **A file per blob** (write, sync, rename, then one directory sync per
  group) is the simplest to collect, but costs about 1 ms of syncs per
  blob whatever its size: the node tops out near 1k blobs a second, a
  third to an eighth of appending at 64 KiB.
- **Appending, or a file per group,** share one sync per group, and lead
  at 64 KiB. The drive moved results by up to 4× between rounds (it is
  86% full, after a day of benchmarks), so only the 64 KiB gap is clear.
- The ranking is structural rather than numeric: a file per blob pays
  metadata syncs per blob, a second fjall writes each blob twice and
  stalls on flushes, and appending pays one sync per group. Step 3.10
  re-measures on an emptier drive.

**Decided: append-only segments.**

- Blobs are appended to the current segment file (`blobs/<n>`), a group
  at a time, with one `fdatasync` per group, then each is reported
  durable. A segment is closed at 256 MiB; a new one is created with a
  directory sync, once per segment.
- A record is a header (magic, length, hash) and the bytes.
- **The index** (hash → segment, offset, length) is a `blobs` partition
  of the node's keyspace, written without a sync after the segment's. On
  open, the writer reads each segment past its last indexed record,
  rehashes those records, indexes the whole ones, and truncates at the
  first torn one. The journal recovers a prefix and the writer indexes
  in order, so only a segment's tail can be unindexed.
- **Collection** by segment: a segment whose blobs are all dead is
  deleted; one less than half live is compacted by copying its live
  blobs to the current segment, syncing their new index rows, then
  deleting it. Blobs mostly die in the order they were written (log
  compaction), so most segments go whole.

- **Content-addressed:** BLAKE2b-256, as program hashes are. A blob is
  durable only once verified against its hash; the reference's length
  bounds a receive.
- **Its own writer thread,** with group commit, off the log writer and
  off executors; hashing runs on executors before a blob is handed over.
- **Invariant 7 in the log writer**, with a change to vos-raft's core:
  - **The core learns entry durability apart from the rest.**
    `durable(seq)` is cumulative, so if it waited for a blob, nothing
    after it could be reported either: not a term, a vote or a
    truncation. A follower holding an entry whose blob never came (its
    leader died) could then never count its own vote, and a group of
    three could lose its election with one node down. So `durable(seq)`
    credits the hard state and truncations only, and the host reports
    entries with `entries_durable(index, term)`: the highest index
    through which every entry, and every blob each names, is durable.
    The core takes it only if it still holds that entry at that term,
    as it already checks.
  - The writer writes an append at once, and reports its entries once
    their blobs are durable too, in order per agent. A truncation drops
    the wait on the entries it removes.
  - A host without blobs (the driver, the simulator) reports both
    together.
- **Recovery cuts the log at the first entry missing a blob.** Every
  agent shares the one journal, so an append whose blob never synced can
  still survive a crash, made durable by another agent's synced flush.
  On open, each agent's log is cut at the first entry naming a blob that
  is not present and verified. Such an entry was never reported, so no
  replica counted it.
- **Programs become pinned blobs:** the `programs` partition goes; a pin
  row per (program, agent) keeps a program's blob.
- **Liveness:** a blob lives while a log row names it, a pin holds it,
  or it was put within a horizon (its append may still be in flight:
  blobs sent ahead by a leader that died, and blobs of a truncated
  suffix, become such orphans).
  - A put of a blob already stored refreshes its age, so a second agent
    installing the same program, or a re-sent blob, is never collected
    under it.
  - Collection reads only durable liveness: compaction and unpinning are
    buffered, and a crash could bring a reference back. It runs against
    what the last synced flush made durable, and re-checks references
    after a fence before it deletes.
  - Dead blobs' index rows are removed, synced, before their segment
    goes, so a later put never mistakes a deleted blob for present.
- **Crash test for invariant 7:** after a kill, every append reported
  durable has its blob and the blob verifies, and no surviving log entry
  is missing a blob.
- Fetching a missing blob from a peer is the network's (3.4, 3.7).

#### 3.3c Snapshots

- **Epochs.** The agent's current epoch becomes a node row (3.3a fixed
  it at 0).
- **Reads go through the pointer:** a store snapshot reads each agent's
  epoch row once, from the same snapshot, and caches it. A reader never
  mixes epochs and never sees a half-installed state.
- **Export:** from one store snapshot, an agent's rows in both
  partitions under its current epoch, in key order, in chunks of about
  1 MiB. The export is labelled with its own applied index and the term
  there, and the membership record, not the core's compaction point:
  the core takes a snapshot above its own (step 3.2's review). The
  membership record goes with it only if its index is at or below the
  export's applied index; otherwise the export carries none, as the core
  does.
- **Staging:** an install writes the chunks under a new epoch, buffered,
  through the writer and so the journal (fjall's bulk ingestion would
  bypass the journal, and the synced switch would no longer cover the
  staged rows). A new staging epoch first removes any rows an aborted
  install left in it, and is never one still being removed.
- **Applies carry their epoch.** An accumulate already running when a
  switch is queued could otherwise write after it, into a dead epoch, and
  move the applied index back below the snapshot. The writer refuses an
  apply at or below the agent's applied index, or for an epoch that is
  no longer current.
- **The switch:** one synced batch moves the epoch pointer and writes
  the applied index, the log start (the snapshot's index and term), the
  hard state and membership from vos-raft's `SnapshotSwitch`, removes the
  log through the snapshot, and the suffix if `truncate_after` says so.
  The staged rows share the journal, so the synced switch makes them
  durable too: invariant 6 becomes "a snapshot and the index that depends
  on it are one durable batch".
- **The old epoch** is removed row by row afterwards, in the background,
  in bounded chunks so it never stalls the writer. A crash before that
  leaves rows no pointer names; startup removes them.
- **Crash test for invariant 6:** a child installs snapshots of known
  content in a loop; after a kill the agent's rows are exactly one
  installed snapshot, at the applied index recorded with it.
- Pinned blobs in a snapshot's manifest, and streaming between nodes,
  are step 3.7's.

#### What the single-node path changes

The node keeps committing an append and an apply together, synced, now
through the new layout: log kinds in its entries (3.3a), programs as
pinned blobs (3.3b), epochs in its keys (3.3c). Its tests and the
slice 2 acceptance bench must not move.

**Review** (Opus): go for 3.3a; 3.3b only with invariant 7's two gaps
designed (both above: entry durability reported apart from the rest, and
recovery cutting at a missing blob); 3.3c with its apply guard. Folded
in: rows name their blobs, the writer reports stalls, the epoch byte
from 3.3a, the collection races, the export's membership rule, staging
through the journal, bounded removal. For step 3.7: dropping an agent's
replica (log, epochs, node rows, pins) with its tombstone.

### 3.3a: Raft rows and the writer

**Built:**

- **The layout** (`store.rs`):
  - agent rows sit under an epoch byte, fixed at 0;
  - the node's rows for an agent are `agent ∥ 0xff ∥ row`, named by an
    enum;
  - log rows carry their kind and the blobs they name;
  - a replica's hard state, log start and membership each have a row.
  - `Store` gains `raft(agent)` (everything recovery needs) and
    `log_range(…, max_bytes)`.
  - `Batch` gains `truncate`, `compact`, `hard_state` and `membership`.
  - A truncation also removes entries the same batch appended earlier: a
    group can hold one write's appends and the next leader's truncation.
- **Opening a store syncs what it recovered.** fjall syncs a recovered
  journal only when it cuts a torn tail, so rows a crashed process left
  in the page cache could be lost to a later power cut, after the node
  relied on them. `Fjall::open` syncs every journal and its directory
  first. Found when the writer refused a compaction after a restart: the
  core counted the recovered applied index as durable, the writer did not.
- **The writer** (`storage.rs`, now public):
  - changes carry their durability, and a group syncs if any change in
    it must;
  - the durably applied index is per agent, per synced flush, and is
    seeded by `recovered(agent, applied)` at startup;
  - a compaction past it is refused;
  - an 8 MiB flush cap guards a group's size;
  - `stalled()` reports a commit that waited past 1 s.
- **The adapter** (`raft.rs`) maps the core's writes to changes (leaving
  the meta's snapshot pointer out), loads to ranges, `CompactBound` to a
  compaction, and rows to `Recovered`; node numbers are `u8`.
- **The single-node path** commits an append and an apply where it
  committed one combined change; nothing else moves. vos-raft's
  `EntryKind` is no longer `#[non_exhaustive]`, so the adapter matches it
  whole.

**Tests:**

- unit tests: Raft rows across a reopen; a truncation over stored and
  batched entries, another agent untouched; byte-capped ranges; entries
  round-tripping through the adapter, an unreadable payload included; the
  durably applied index moving only with a synced flush; compaction
  refused past it; a stall reported and cleared.
- **Three vos-raft cores over three real stores and writers:**
  - one run restarts a replica every round (the leader every third),
    each recovering from its store, with compaction off: a replica down
    while the others compact would need a snapshot (3.3c);
  - another compacts with every replica up.
  - Every replica applies the same entries through the same index, and
    its state agrees.
- **`raft_crash`:** a child drives the writer as a replica does (synced
  appends with their hard state, buffered applies and commit moves, new
  terms, compactions within the durably applied index). Twelve rounds of
  random kills, the last six tearing the journal's tail. After each:
  - invariant 1: one prefix of applies;
  - invariant 2: the log holds every entry from its start through the
    applied index and on, without a gap;
  - invariant 4: the log starts at or below the applied index;
  - the term and every append reported synced survive, but for a tear's
    reach.
- Slice 2's suites pass unchanged in substance; its crash test passes on
  the new layout. The acceptance bench: 29.3 µs per request under load
  (22.6 µs execution), 0.94 ms per commit, a query at median 53 µs, as
  in step 2.9.

**Review** (Opus): go, with these fixed before the commit:

- a truncation whose read fails fails its batch, rather than leaving a
  suffix the core believes removed;
- applies count toward the durably applied index only once their batch
  committed;
- a data payload never becomes a membership change on a round trip;
- the journals are synced before the store opens, not racing fjall's
  workers;
- every replica restarts from its compacted log, in a test of its own;
- the crash tests tear back from where a journal's data ends (fjall
  preallocates journals, so a tear from the file's end could hit only
  zeros), and fail if no torn round reached data.

For later steps: refuse a compaction at or below the log start once a
switch can move it (3.3c); recover each agent's terms and the log's tail
only, not its whole live log, when a node runs many agents (3.8).

### 3.3b, part 1: entries reported apart (vos-raft)

**Built:**

- **`durable(seq)` credits terms, votes and truncations only.** Entries
  count once the host reports them with `entries_durable(seq)`: the
  entries of every write through `seq` are durable, with every blob each
  names.
  - The core remembers which write appended each index (runs of first
    index and write, cut on truncation). A report credits only entries
    those writes appended that the log still holds. A report from before
    a truncation never vouches for an entry written again after it, even
    one with the same index and term.
  - The driver, the simulator and the node's adapter report both
    together after each write.
- **`discard_unreported()`:** a replica drops the entries it never
  reported, above max(durable index, commit index), as a crash drops
  unsynced writes. When to give up on a blob is the host's (steps 3.4 and
  3.7); the recovery cut (below) does the same at startup.
  - **Why:** separate reports let a follower holding an entry without
    its blob vote and campaign. But if the blob is lost with the leader
    that sent it, that follower wins (its log is the longest) and can
    never commit, since its own score stops below the entry.
  - **Safe** because it never acknowledged those entries. Entries at or
    below the commit index stay: a quorum holds them, blobs included.
  - **A candidate, pre-candidate or leader steps down first.** A
    candidate's requests advertised the longer log, so a grant made
    against it must no longer count. A leader may have counted followers
    for its own entries, and it cannot know which inherited entries are
    committed.
- **The configuration in effect at the log's start.** Found by the
  chaos run below (two leaders in one term, seed 78):
  - A follower whose log was compacted past its configuration entries
    took a truncation that removed a newer one. It fell back to the
    static members of its first configuration, while its peers counted
    majorities of the real set.
  - The core now keeps the configuration in effect at its log's start.
    `CompactBound` carries it, the host keeps it with the log's start (a
    snapshot switch sets it too), and `Recovered` returns it. A
    truncation, or a recovery with no configuration entry left in the
    log, falls back to it.
  - A snapshot sent to a peer carries that configuration: the one at the
    snapshot's index, not the newest view.
  - vos-raft's `Storage` gains an optional row for it, which `MemStorage`
    and the worker driver keep. A host that kept none leaves it unknown:
    a persisted view at or below the log's start stands in, else nothing.
    A snapshot then carries no configuration, rather than a guess, and a
    truncation falls back to the static members, as before.
  - `config_at(index)` is public. A host exporting a snapshot at its own
    applied index ships the configuration there (3.3c).

**Tests:**

- core tests:
  - an entry waiting for a lost blob never stalls an election;
  - a discard keeps committed entries;
  - a leader steps down before it discards;
  - a candidate that discards ignores grants for its longer log;
  - a report from before a discard vouches for nothing written after;
  - a truncation falls back to the log start's configuration;
  - an unknown log start's configuration is never sent;
  - `MemStorage` keeps it across a compaction.
- **Chaos with lagging entry reports:** entries are reported 1–60 ms
  after their writes, and replicas discard unreported entries at random,
  over 200 seeds with membership churn. The other variants, fixed and
  churning membership, pass as before.
- **Mutations**, each caught by its core test:
  - no step-down for a candidate;
  - reports by (index, term) instead of by write;
  - a leader that never discards;
  - the static fallback.
  The chaos run caught a leader discarding without stepping down (seed
  1). Since the fixes, it catches none of these: the interleavings are
  narrow.
- vos-raft has 111 tests. The node's adapter, its three-replica runs and
  `raft_crash` carry the log start's configuration.

**Review** (Opus): the first version was a no-go. A candidate that
discarded could be elected on its advertised longer log, and a stale
report could vouch for an entry written again in the same term. Both are
fixed above, as is the leader's step-down it recommended.

The second review was a go, with the reference driver keeping the log
start's configuration and nothing ever shipping a guess, both done.
Notes for later steps:
- 3.3b's host reports `entries_durable(seq)` only once every write
  through `seq` is synced and has its blobs. A late report is always
  safe; an early one is not.
- "Lost" in the discard policy means unfetchable, not merely slow: a
  discard too early costs a leadership change.
- 3.3c's switch writes `SnapshotSwitch.log_start_config` into the
  log-start row, in the same batch.

### 3.3b, part 2: the blob store

**Built** (`blobs.rs`):

- **Segments:** append-only files, a group of puts at a time with one
  data sync, closed at 256 MiB. A new segment is created with a
  directory sync. A record is a magic, the length, the hash, then the
  bytes.
- **The index** is the `blobs` partition of the node's keyspace:
  location rows (hash → segment, offset, length, put time in
  milliseconds), segment rows (the end of the indexed records, and
  where the last starts), and pins. Location rows are written after the
  segment's sync, without one of their own.
- **On open,** each segment is synced, then read past its indexed end:
  whole records are rehashed and indexed, and the file is cut at the
  first one that is not.
  - The last indexed record is rehashed too. If it is torn, or the file
    is shorter than the indexed end (a disk that lost what it said it
    wrote), the segment is walked from its start and the index rows past
    the damage go.
  - Found by `blob_crash`, whose tears reach indexed records as the
    journal tests' tears reach synced batches.
- **`put`** takes a reference its caller hashed, off the writer. A put of
  a stored blob only refreshes its time. `get`, `contains`, and `wait`,
  which resolves once a blob is stored.
- **Collection** (`collect`):
  - It reads references from a store snapshot that a synced barrier then
    makes durable, so a crash cannot bring a reference back.
  - Unreferenced, unpinned blobs older than the horizon are candidates.
    A second snapshot and barrier act as a fence before they are
    removed, synced.
  - Segments left empty are deleted; sparse ones (under half live) have
    their live blobs moved, the index synced, then are deleted.
- **The writer** gains `Barrier`, `Pin` and `Unpin` changes. A synced
  commit of nothing still syncs: fjall skips an empty batch, sync and
  all.
- **Programs are pinned blobs.** The `programs` partition is gone. An
  install puts its programs, then pins them. The node loads pinned
  programs into the machine pool at start, and refine's
  `historical_lookup` reads the blob store.
- **Invariant 7** (`raft.rs`):
  - `cut_missing_blobs` cuts an agent's log at its first entry naming a
    blob not stored, on open.
  - `EntryReports` queues a replica's writes in order. A write's entries
    are reported (`entries_durable(seq)`) once its blobs, and every
    earlier write's, are stored. A truncation drops the waits of the
    entries it removes.

**Tests:**

- unit tests:
  - round trips across segments and a reopen;
  - a lost index row recovered from the tail, and a torn record cut;
  - an indexed record torn anyway;
  - a waiter woken;
  - collection keeping named, pinned and young blobs, deleting segments
    and moving live blobs, across a reopen;
  - a re-put refreshing a blob's age;
  - entry reports waiting in write order;
  - a truncation dropping waits;
  - the recovery cut.
- **`blob_crash`:** a child appends entries each naming a blob, storing
  some blobs first and some after the append, and reports an entry only
  once both are durable. Twelve rounds of random kills, the last six
  tearing the journal's tail or the blob segment's. After each, with the
  blob store recovered and the log cut on open:
  - every surviving entry's blob is stored and holds its bytes;
  - every reported entry survives, but for a tear's reach;
  - the log has no gap.
  Cuts occur both for a torn blob and for an append that never got its
  blob.
- Slice 2's suites pass; installs now store programs as blobs. The
  acceptance bench: 31.1 µs per request under load (24.0 µs execution),
  0.99 ms per commit, a query at median 50 µs, within run-to-run noise
  of step 2.9.

**Review** (Opus): go, with the writer stopping on any error before the
commit. Also done before it:

- **Collection's removal is ordered with puts.**
  - The collector's decision was not ordered with a dedup put. A blob an
    entry came to rely on after the collector's last snapshot could
    still lose its index row.
  - Removal now runs on the blob writer, in order with puts and touches,
    rechecking each candidate's age there.
  - Hosts `touch` every blob they come to rely on, which refreshes its
    age and says it is stored. `EntryReports::written` answers from a
    touch.
  - One collection runs at a time. `get` re-reads a blob that a
    collection moved meanwhile, and open segment handles are bounded.
- **The blob writer stops on any error.** A partial record or a failed
  sync would otherwise misplace every later record. Later puts answer
  that the writer stopped.
- **`EntryReports`:** `missing()` lists every awaited blob, so a driver
  fetches them together, and `switched(index, keeps_suffix)` releases
  the waits a snapshot switch covered or dropped.
- **Collection under kills.** `blob_crash`'s child now applies each
  entry, compacts its log below what is durably applied, leaves orphan
  blobs, and collects with no horizon over 16 KiB segments, so dead
  blobs go and segments are deleted or moved. The test found:
  - **A segment row without its file.** A journal tear took back the
    synced removal of a deleted segment's rows, but not the unlink. On
    open, rows of segments whose files are gone are dropped, with the
    locations in them. A collection deleting a file already gone
    carries on.
  - **A blob tear can take an older entry's blob,** which collection
    moved to the newest segment's tail. The log is then cut at that
    entry; the test allows that cut, and only that one.
  It passed 100 runs in a row.
- vos-node has 28 unit tests, with touch against removal and the new
  `EntryReports` hooks.

### 3.3c: snapshots

**Built:**

- **Epochs** (`store.rs`):
  - an agent's rows sit under `agent ∥ epoch ∥ key`, and an epoch row
    names the current one;
  - a store snapshot reads each agent's epoch once and caches it, so a
    reader never mixes epochs and never sees a half-installed snapshot;
  - `View::epoch` exposes it;
  - epochs cycle through `0..=0xfe` (`next_epoch`).
- **Export:** `Store::export(agent)` reads one store snapshot. It is
  labelled with the agent's own applied index and the term there (from
  its log, or its log start), and is read in chunks of rows, system keys
  first. The membership to send with it is the core's `config_at` the
  applied index.
- **Staging:** `Change::Stage` writes rows under an epoch beside the
  current one, through the writer and so the journal, without a sync.
  `Change::DropEpoch` removes up to a limit of an old epoch's rows.
  `Store::stale_epochs` lists epochs holding rows other than the current
  one, for the startup sweep.
- **The switch:** `Change::Switch` is one synced batch. It moves the
  epoch pointer, records the applied index, the log start (with the
  membership in effect there), the hard state and the membership, and
  compacts the log through the snapshot (cutting it after, if told). The
  staged rows share the journal, so the switch makes them durable too:
  invariant 6. `raft::switch_change` maps vos-raft's `SnapshotSwitch`
  onto it.
- **The writer's guards**, from what it knows of each agent's epoch,
  applied index and log start (read once, then kept in step with what it
  commits). It refuses:
  - an apply not in the current epoch, or not past the applied index (an
    accumulate that raced a switch);
  - staging into, or dropping, the current epoch;
  - a switch that does not move to a new epoch past the applied index;
  - a compaction at or below the log start (a switch moves it).
- **The node** applies under its agent's epoch.
- **The recovery cut, revisited:** an entry at or below the applied
  index whose blob is gone (a tear of synced data) is committed and
  applied, so the log is compacted through the applied index rather than
  cut below it. Found by `blob_crash`, whose next apply the new guard
  refused.

**Tests:**

- unit tests:
  - a staged export switching in at once, with a snapshot taken before
    the switch still reading the old epoch whole;
  - the old epoch kept until dropped;
  - the writer's refusals.
- **Three vos-raft cores over three real stores:** the restart test now
  runs with compaction on. A replica stopped while the others compact
  catches up by a snapshot: exported by its leader at its applied index,
  staged under the next epoch, switched in, the old epoch dropped.
- **`snapshot_crash`:** a child installs snapshots of known content in a
  loop: it clears the next epoch, stages in chunks, switches, applies a
  few entries, then drops the old epoch, and sweeps stale epochs on
  start. Twelve rounds of kills (mid-staging, mid-apply, mid-drop), the
  last six tearing the journal. The rows are always exactly one snapshot
  with the applies after it, at the applied index, and every install
  reported survives, but for a tear's reach.
- Every suite passes: four crash tests, the node's, slice 2's. The
  acceptance bench: 28.7–30.3 µs per request, query median 50–57 µs,
  as before.

**Review** (Opus): go. Also done before the commit:

- **The recovery cut goes through the writer.** `recovery_cut` returns
  its changes for the node log writer, once told the agent's recovered
  applied index, so the writer's knowledge of the log start never goes
  stale.
- **Its compaction keeps the membership** in effect at the applied index:
  the latest configuration entry at or below it, else the old log
  start's.
- **A failed read of the epoch row** is a scan's first and only item,
  never another epoch's rows.
- **An install's first chunk is refused** while its epoch still holds
  rows (`Stage { first }`). `snapshot_crash` moves each snapshot's key
  window, so a leaked row, left staged or not dropped, would show.
- Applies come one index at a time; a truncation below the applied index
  is refused; an export whose applied entry is missing from its log is an
  error, not term 0.

**Left to later steps:**

- **The node's driver (3.5):** recovery runs each agent's `recovery_cut`
  and its stale-epoch sweep before the agent's first commit; applies
  under the current epoch after a switch; `EntryReports::switched`.
- **Streaming between nodes, and the manifest of pinned blobs (3.7).**

## Step 3.4: the network

### Design

A network layer that knows nothing of Raft (owner decision 2), its
messages, and TLS on client ingress. Three parts, each reviewed and
committed on its own:

1. **3.4a, the layer (`node/net`, crate `vos-net`):** the interface, an
   in-process implementation for tests, and QUIC.
2. **3.4b, the node's messages and their authorization:** SCALE
   encodings of what nodes send each other, and the group driver's
   checks, as pure functions with tests. Step 3.5 wires them in.
3. **3.4c, TLS on client ingress.**

#### 3.4a The layer

**Identity.** A node is its ed25519 key.
- **A fresh secret seed**, generated once and kept in its own node
  record, is never served. Slice 2's node id is public (ingress serves
  it, clients sign over it), so it cannot be the seed.
- **The node's public identity is its public key:** `GET /` and
  `vos node info` serve it, and clients sign over it where they signed
  over the old id.
- A node's configuration lists its peers: a number (stable, never
  reused, the 8 bits of agent ids), a key and an address.
- Another signature by the node key is domain-separated from TLS's.

**The interface:**

```rust
pub enum Class { Liveness, Consensus, Requests, Bulk }

pub struct Incoming { pub from: NodeNumber, pub stream: u64, pub frame: Vec<u8> }

pub trait Network: Send + Sync + 'static {
    /// Queue `frame` for `to` on stream `stream` of `class`. Never blocks:
    /// it refuses with a reason (full, unknown peer, closed), and the
    /// caller decides (Raft drops; a forward or a bulk transfer retries).
    fn send(&self, to: NodeNumber, class: Class, stream: u64, frame: Vec<u8>) -> Result<(), Refused>;
    /// Resolves once `to` can take more of `class` (bulk senders wait on
    /// it rather than spin).
    fn ready(&self, to: NodeNumber, class: Class) -> impl Future<Output = ()>;
    /// Send to every peer; a gossip implementation may do better.
    fn send_to_all(&self, class: Class, stream: u64, frame: Vec<u8>) { /* loops */ }
    /// Replace the peer table without a restart.
    fn set_peers(&self, peers: Vec<Peer>);
}
```

- **Arrivals queue per class,** each frame with its authenticated
  sender, and the consumer always drains Liveness and Consensus first. A
  single queue would undo the head-of-line protection: bulk ahead of
  heartbeats.
- **`from` is the authenticated channel peer.** A relaying transport
  would later need an origin signed at the message layer; 3.4b's checks
  assume direct delivery.
- **Order holds within one (peer, class, stream), on one connection.** A
  redial can reorder across the old and the new connection. A frame is
  delivered at most once.
- **Streams:**
  - Liveness and Consensus streams are long-lived, one per group
    (stream = agent id), so one agent's large append never delays
    another's;
  - Requests too, one per agent, so a session's pipelined forwards keep
    their order (out of order, the leader's lane would refuse them as
    gaps);
  - Bulk opens a stream per frame, so a 4 MiB blob never sits ahead of
    anything.

**QUIC** (`quinn`, `runtime-smol`, `rustls-ring`; no tokio):

- **TLS 1.3 bound to node keys, both ways** (a spike confirmed it with
  quinn 0.11, rustls 0.23 and rcgen 0.13):
  - each node presents a self-signed certificate (`rcgen`) for its
    ed25519 key;
  - **the dialing side pins the peer it dialed:** a client
    configuration per dial whose verifier holds that peer's key. A wrong
    address, or a path through another node, fails rather than reaching
    the wrong peer;
  - **the accepting side** accepts any configured peer's key, and takes
    the peer's number from it;
  - the handshake signature is checked against the certificate's own
    key, and client authentication is mandatory;
  - TLS 1.3 and Ed25519 only; certificate validity times are ignored,
    since keys are pinned;
  - ALPN `vos/1`; no 0-RTT.
- **Connections:**
  - each node dials every peer it sends to and sends only on its own
    connection, so sends never wait for the other side to dial;
  - the accepting side never sends on an accepted connection;
  - that is two connections per pair, fine at 256 nodes or fewer;
  - it redials with backoff, and frames wait in a bounded queue per peer
    meanwhile.
- **Restarts:** the endpoint's stateless-reset key derives from the
  node's secret. A restarted peer then resets the connections it no
  longer knows at once, instead of leaving them silent until the idle
  timeout. A peer dialing in anew also closes this node's outgoing
  connection to it, which then redials.
- **Streams:** unidirectional. A stream opens with its class and id; a
  frame is a length (u32) and its bytes.
- **Priorities** (`SendStream::set_priority`): Liveness above Consensus,
  above Requests, above Bulk.
- **Flow control:**
  - the connection window stays unlimited (quinn's default), so a few
    unread bulk streams cannot fill it and stall everything;
  - memory is bounded by per-stream windows and a cap on concurrent bulk
    streams;
  - `max_concurrent_uni_streams` is raised above slice 3's groups times
    classes.
- **Frames are bounded on receipt, per class,** and read incrementally:
  - consensus at the 1 MiB append cap;
  - bulk at the largest blob plus its header;
  - requests at the request cap plus their envelope.
  A length prefix never sizes an allocation by itself.
- No transport keepalives as liveness: the node's own liveness messages
  carry that (plan). An idle timeout of 30 s closes dead connections, and
  the next send redials.

**In-process:** a hub connecting endpoints through channels, with
partitions, drops and delays to set. Step 3.5's tests run replicated
agents on it.

**Tests:**

- three nodes on localhost exchange frames on every class;
- order within a stream;
- a peer with an unknown key, or a key that is not the one configured
  for its number, fails the handshake;
- redial after a peer restarts;
- **head of line:** small consensus frames' latency, alone and beside
  4 MiB bulk frames to the same peer. The bulk must not move the small
  frames' p99 by more than a few milliseconds. This measures what the
  stream design is for.
- the dialing side refuses a peer with the wrong key at the right
  address;
- a restarted peer is reachable again at once;
- an oversized frame is refused, not allocated.

#### 3.4b Messages and authorization

**The node's messages,** SCALE-encoded in a `vos-wire` module:

- a Raft message for an agent's group: vos-raft's `Message<u8>`, with
  its entries in the store's payload form;
- snapshot chunks and their acknowledgements;
- blob requests and blobs (by hash; the receiver verifies);
- directory updates (step 3.5 defines their content);
- liveness.

Requests and inter-agent messages come with step 3.5.

**Authorization**, as pure functions the group driver (3.5) calls on
each arrival, with tests:

- a Raft message comes from a node configured in the space;
- an append comes from the leader it names, and a vote request from the
  candidate it names;
- votes and acknowledgements count only from members, which vos-raft
  checks already;
- the tests include stale membership: a replica that has not yet seen a
  replacement still accepts the new member's messages, since the check
  is "configured in the space", while its votes and acknowledgements
  count only once it is a member;
- a snapshot chunk comes from the leader the replica follows;
- anything else is dropped and counted.

#### 3.4c TLS on client ingress

- The HTTP ingress (slice 2: `http.rs`, smol) serves TLS 1.3
  (`futures-rustls`). Its certificate is either configured (PEM files)
  or self-signed for the node's key.
- The `vos` CLI (`ureq` with rustls) pins one of: the node's key (from
  `vos node info`, kept with the profile), or a CA. From step 3.5 it
  pins the keys of all the agent's replicas, so failing over to another
  replica passes the check.
- Plain HTTP stays only on loopback, for tests and local use. A
  non-loopback ingress requires TLS, and `0.0.0.0` and `::` are not
  loopback.

#### What 3.4 does not do

- The multi-group driver: combined heartbeats, quiescence, pair
  liveness (step 3.8).
- The directory's content and broadcast, and requests and forwarding
  (step 3.5).
- Snapshot streaming end to end (step 3.7).

**Review** (Opus): no-go until the node's key stops being its public id.
Done above: a secret seed of its own, and the public key as identity.
Also folded in:
- the dialing side pins the peer it dialed;
- stateless resets keyed by the node's secret;
- incoming queues per class;
- an unlimited connection window, with per-stream bounds and stream
  caps;
- frames bounded per class;
- requests on a stream per agent;
- the interface additions (refusal reasons, readiness, send to all, a
  peer table update);
- the stale-membership authorization tests;
- the CLI pinning every replica's key.

Then go for 3.4a.

### 3.4a: the layer

**Built:**

- **The node's identity** (`node/host`):
  - a fresh secret seed, made on first open, in its own node record
    (`0x0a`), never served;
  - the old public id's row (`0x02`) is retired, never read as a
    secret, and deleted when the secret is made;
  - the data directory is the owner's alone (0700): made so, or others'
    access taken away on open. fjall gives its files no mode of their
    own, and the secret is in them;
  - the node id is the seed's ed25519 public key: `GET /` serves it,
    clients sign over it, and `vos node info` prints it (`vos node`
    became `vos node run`).
- **The interface** (`node/net`, crate `vos-net`):
  - `Network`: `send` (refusing as full, unknown peer, too large or
    closed), `ready`, `peers`, `set_peers` and `send_to_all`. `ready`
    returns `impl Future`, so the trait is used through generics, not as
    a trait object;
  - `Arrivals`, a queue per class: 1024 frames each, but 16 for bulk;
  - `Limits`: the largest frame per class (liveness 64 KiB, consensus
    2 MiB, requests 1 MiB, bulk 64 MiB and a header), never above a
    `u32` length;
  - per peer and class, waiting frames have a budget of four of the
    largest frames' worth, or one bulk frame's. A queue under its budget
    takes one frame more, and each frame costs 64 bytes beyond its own,
    so empty frames are bounded too.
- **QUIC** (`quinn` 0.11 on smol, rustls 0.23 with ring):
  - **Raw public keys (RFC 7250), not certificates.** Each side presents
    its ed25519 key as a bare SubjectPublicKeyInfo, and the key checked
    is exactly that document, the one the handshake's signature is
    checked against. There is no X.509 to parse, and no rcgen. Picking a
    key out of a certificate by its bytes could take a key other than
    the one the signature was checked against.
  - The dialing side pins the peer it dialed: a client configuration per
    peer. The accepting side takes any configured key and reads the
    peer's number from it.
  - TLS 1.3, Ed25519, ALPN `vos/1`, no 0-RTT.
  - **No session resumption,** either side: a resumed handshake skips
    the key check, so a peer removed since could still connect.
  - **Restarts:**
    - The stateless-reset key is derived from the secret.
    - Connection ids are 16 bytes: 8 random, and an 8-byte HMAC mark over
      them keyed by the secret. quinn resets only the connections of ids
      it can tell it made, and drops packets for any other id. With a
      random mark, a restarted node dropped the old connection's packets,
      and its peer waited out the idle timeout: 30 s before, 31 ms after.
    - Every id is new. With a fixed key and quinn's hashed ids (3 random
      bytes), ids would recur, and a reset token anyone can learn from a
      handshake would serve again later, for spoofed resets.
  - **Incarnations:** the name a node dials with carries a random
    incarnation. A peer dialing in as a new one closes this node's
    connection to the old one, which then redials.
  - **Dials:**
    - a dial times out after 2 s;
    - backoff runs from 50 ms to 1 s, also after the peer took the
      handshake and then refused this node (a TLS alert, or no longer
      configured);
    - the initial round-trip estimate is 100 ms, a cluster's rather than
      the internet's, so a lost first packet is soon sent again;
    - a link whose task ended is started again by `set_peers`.
  - **Streams and flow control:**
    - a writer task per long-lived stream, and a task per bulk frame,
      four at once, each held until the peer has it all;
    - **a stream quiet for 10 s is finished,** so the streams held open
      are those of groups busy lately, within the 8192 a peer grants. A
      new stream for the same id opens once the old one is finished and
      acknowledged;
    - the receiving side delivers a stream's frames only once the last
      stream for its id has delivered all of its own (acknowledged is not
      yet read). So order holds per id across streams, on one
      connection;
    - an unlimited connection receive window, a 1 MiB stream window and
      a 16 MiB send window, so the bulk streams' share (4 MiB) never
      fills it.
  - **Receipt:** each frame's length is checked against its class's
    bound before reading, and an oversized frame stops its stream. A
    frame grows as its bytes arrive, from at most the stream window, and
    four bulk frames are read at once per connection. Every frame is
    checked against the current peer table, and a removed peer's
    connection is closed.
- **The in-process hub** (`memory::Hub`): endpoints joined through
  channels, with directed cuts, partitions, isolation, seeded random
  loss and delay.
  - Order holds per pair of nodes: once a link is delayed it stays on
    its delivery task. Unlike QUIC, order holds across streams and
    classes too.
  - A node takes frames only from the peers it lists, as over QUIC.
  - A node that joins again under its number replaces its old endpoint,
    as a restart does. A delayed frame goes to whichever run is up when
    it is due.
  - A node whose arrivals were dropped loses frames, with no wait.

**Tests** (`node/net/tests`):

- **`quic`, on localhost:**
  - three nodes exchange frames on every class, with sender and stream;
  - order within a stream (2000 frames each on a consensus and a
    requests stream);
  - an unknown key is refused, and so is a configured number presented
    with another key; the dialing side refuses another key at the right
    address;
  - a removed peer is cut off;
  - a queue to an unreachable peer fills per class, and `ready` waits;
  - an oversized frame is refused by the sender's limits, and by the
    receiver's when the sender's are larger, while other streams carry
    on;
  - after a clean shutdown and start, a peer is reached in about 300 ms
    (the first packet is lost in the gap);
  - **stream caps:** with eight streams granted, a ninth opens once the
    first eight go quiet;
  - **order across streams:** three bursts on one id, each on a new
    stream after the last went quiet, read by a slow consumer, arrive in
    order. Without the receiving side's turns, they did not.
- **`restart`, a SIGKILLed peer in a child process:**
  - one that never sends after its restart is reached in about 31 ms,
    through the stateless reset;
  - one that greets node 1 on start gets node 1's very next frame. With
    the incarnation rule switched off, that frame was lost.
- **`head_of_line`, in a process of its own:** small consensus frames
  on 16 streams, one per millisecond, alone and beside 4 MiB bulk frames
  sent back to back. The p99 moves from 0.4–1.2 ms to 2.4–4.2 ms (debug
  build, both nodes in one process on smol's single global executor
  thread). The test bounds the rise at 5 ms. The p50 beside bulk is
  1.0 ms: quinn's pacing granularity.
- **Unit tests:** a raw key is exactly an ed25519 one; connection ids
  are new and marked, known to a restarted run and to no other node;
  ring's public key is ed25519-dalek's; the reset key is not the secret.
- **`memory`, the hub:** delivery, refusals with their reasons and
  `ready`, partitions, cuts and healing, a loss rate, delayed frames in
  order, a restart, a delayed link reaching the restarted run, peers
  listed, a consumer gone.
- **The node:** its id is the public key of the stored seed, not the
  seed, and the same on every open; its data directory is 0700, made so
  or tightened; `vos node info` prints the key the node printed on
  start.
- `just test-agent` now runs `vos-net` too.

**Review** (Opus): go, with seven should-fixes, all done above:

1. connection ids that never recur, so reset tokens cannot be harvested
   (with quinn's hashed ids under a fixed key, they could);
2. the data directory made the owner's alone;
3. a test of the incarnation rule that fails without it;
4. the hub's delayed links reaching a restarted run;
5. the head-of-line test in a process of its own;
6. quiet streams finished, within the peer's stream grant, with order
   kept per id across streams;
7. the bulk arrival queue bounded at 16 frames.

Also done: refused dials back off; dead links are respawned; limits are
clamped to a `u32`; each frame costs 64 bytes in its budget; the retired
id row is deleted; the child processes are killed from a drop guard.

**Left to step 3.5, which wires the layer in:**

- **`Full` is invisible to vos-raft:** a refused frame is dropped, and
  the core waits for its in-flight slot to clear. With many groups
  sending 1 MiB appends to one follower, the budget could stall a group
  for a heartbeat interval. Feed refusals back to the core, or size the
  budget by active groups.
- **One executor thread:** smol's global executor runs one thread unless
  `SMOL_THREADS` says otherwise, and quinn's drivers spawn there. Give
  the network an executor of its own, with a few threads. The receiving
  side's turns rely on readers being polled in accept order, which one
  thread gives. With several, a successor stream's reader could take the
  turn first (a writer stuck waiting for stream credit, retired, then
  finished just before its successor opened). So either carry a sequence
  number per (class, id) in the stream header and serve turns in order,
  or keep each connection's readers on one thread.
- **A spurious close:** a node whose send to a restarted peer is reset
  may redial and reach the new run before that run's own dial-in is
  processed. The incarnation rule then closes the fresh connection: one
  handshake, and the frames in flight, once per restart. The accepting
  side could send its name on a stream of its own instead.
- **For 3.8's scale test:** quinn sends at most one stateless reset per
  20 ms, so a restarted node in a 255-node space resets about 50 old
  connections a second; the dial-ins of its own pair heartbeats cover
  the rest.
- **The hub keeps order across streams,** which QUIC does not; a reorder
  setting would make it a harsher test bed.

**Review of the fixes** (Opus): go. Done after it:
- the quiet-stream sweep runs on its deadline in every turn of the write
  loop, so a queue that never empties cannot starve it;
- the hub's delayed delivery looks for the run up at each try, and
  waits for room without blocking on a replaced run's full queue (test:
  a full, unread old run, then a restart).
- The note on turns and executor threads, above.
- Taken into 3.4c, which changes the same code: a data directory that
  exists but holds no store is refused, with the `chmod` to run, rather
  than having its mode changed.

### 3.4b: messages and authorization

**Built:**

- **The node's messages** (`vos_wire::peer`), SCALE-coded:
  - `PeerMessage`: a Raft message for an agent's group, a snapshot chunk
    and its acknowledgement, a blob request, a blob, and liveness with
    its answer (each carrying the sender's incarnation and a round, for
    3.8's pair heartbeat).
  - The Raft types mirror the consensus core's (`Raft`, `AppendResult`,
    `Entry`, `EntryKind`), so the wire format is the module's own and
    the core may change underneath it. A data entry's payload is the
    node's entry payload (kind, blobs, body); a configuration entry is
    carried as members, not bytes.
  - vos-raft's `Message` is no longer `#[non_exhaustive]`: the
    conversions match it whole, so a new message cannot reach the wire
    unconverted.
  - Snapshot chunks carry the leader's term, the snapshot's index, term
    and configuration, a sequence number, rows and a last flag. Step 3.7
    adds the pinned blobs' manifest and the streaming around it.
  - Requests and messages between agents, and the directory, come with
    step 3.5.
- **The checks** (`vos_node::peer`), pure functions:
  - `decode` takes a frame only if it is one whole message;
  - `check(space, from, message, followed)`:
    - the sender is configured in the space;
    - an append comes from the leader it names, a vote or pre-vote
      request from the candidate it names;
    - a snapshot chunk comes from the leader the replica follows, in
      that leader's term (`followed` asks the group);
    - a blob hashes to its name;
    - the match is exhaustive, so a new message kind needs a decision;
  - `Refusal` names why, and `Drops` counts drops by why;
  - `to_wire` and `from_wire` convert the core's messages.

**Tests** (`node/host/tests/peer.rs`):

- every Raft message survives the wire, with arbitrary fields and
  entries of both kinds (proptest); so does every other message;
- a frame with a byte too many or too few, or none, is refused;
- strangers, misnamed leaders and candidates, chunks from anyone but
  the leader followed in its term, and blobs that do not hash to their
  name are refused; drops are counted by why;
- **stale membership,** with a real core: a replica whose members, as
  it knows them, are 1, 2 and 3 takes node 4's pre-vote, vote and
  acknowledgement, since node 4 is configured in the space, but counts
  none of them. A member's then elects it and commits. It follows node 4
  when node 4 leads a later term. Node 5, not configured, is refused
  before the core.
- **Mutations:** removing the core's member check on vote answers leaves
  the test passing, because the election's tally counts members only, a
  second layer. Making the tally count every voter as well fails it.

**Review** (Opus): go, with two should-fixes, both done:

1. **The codec reserves at most four times a frame's own size up
   front.** A count was checked only against the bytes left, and
   reserved `count × size_of::<T>()`: a 64 MiB frame of snapshot rows
   could ask for about 3 GiB before failing to decode. This was a slice 2
   bug, reached from the operator's install too. A bound of one times
   the input made the agent's 1,000-method schema reallocate as it grew,
   and its install's gas went from 6.3M to 6.7M, past its reserve.
   Honest items are rarely smaller encoded than a quarter of their size
   in memory, so four times keeps it at 6.3M.
2. **The stale-membership test's second half:** once the leader adds
   node 4, the joint configuration needs majorities of both sets. A
   member's acknowledgement then commits nothing, and node 4's commits.

Also done:
- `peer::class` and `peer::stream` say where each message travels.
  `check` refuses a message on another class, so a Raft frame on bulk
  cannot escape its 2 MiB bound, and a Raft message on a stream other
  than its agent's.
- The module says which messages their handlers authorise by sender:
  an acknowledgement only from the replica the snapshot streams to, a
  blob only if requested, a blob request only from a replica of its
  agent. Blob requests now name their agent.
- The ALPN, `vos/1`, versions the format.

**Left to step 3.5:**
- hash blobs off the consumer's hot path (up to 64 MiB each);
- test that a removed node which missed its removal keeps campaigning
  without moving the members' terms. Pre-votes, the log-freshness
  check, check-quorum and TimeoutNow only from the known leader cover
  it. An etcd-style lease (ignore a higher-term vote request soon after
  hearing a leader) is optional hardening, and would need a transfer
  flag on vote requests.

### 3.4c: TLS on client ingress

**Built:**

- **The ingress serves TLS 1.3** (`futures-rustls` on smol, rustls with
  ring), with one of two certificates (`vos_node::tls::IngressTls`):
  - **for the node's own key:** made at start (`rcgen`), self-signed,
    naming the hosts given (`localhost` by default). Clients pin the key;
    names and dates do not matter to them;
  - **from PEM files** (a chain and its key): clients trust its CA.
  A client has 10 s to finish its handshake. The HTTP server is the same
  over plain and TLS streams.
- **Plain HTTP serves loopback addresses only.** `Node::serve` refuses
  `0.0.0.0`, `::` or any other address without TLS.
- **The data directory, again:** an empty directory, or a node's own,
  that others can reach is made its owner's alone, as before. Any other
  existing directory others can reach is refused, with the `chmod` to
  run, and not changed: it may be `/tmp`, or a home.
- **The client** (`vos_node::client`) no longer uses ureq, which cannot
  take a verifier of its own. It is a small blocking HTTP/1.1 client
  over `std::net` and rustls. Requests may go at once, each on a
  connection of its own, and up to four idle connections are kept for up
  to 20 s (within the node's 30 s). A test pipelines requests from three
  threads through one client:
  - `Target::new(url, trust)` pairs an address with a `Trust`:
    - `Loopback`: plain HTTP, to `localhost` or a loopback address only;
    - `NodeKey(key)`: TLS 1.3 whose certificate holds this ed25519 key.
      The key webpki reads from the certificate is the one the
      handshake's signature is checked against. Names and dates are not
      checked;
    - `Ca(certificates)`: TLS whose certificate chains to one of these
      CAs, for the host's name.
  - An address and its trust must agree: `https://` needs a key or a CA,
    `http://` is for loopback alone.
  - The handshake completes when connecting, so a wrong key fails before
    any request.
  - **A pinned node must name itself by its key:** `GET /` answering
    another id fails as `NotTheNode`, even through a certificate that
    holds the pinned key.
- **The CLI:**
  - `vos node run --tls [--tls-name NAME]...`, or `--tls-cert FILE
    --tls-key FILE`;
  - every command that reaches a node takes `--node URL` with
    `--node-key HEX` (or `VOS_NODE_KEY`) or `--ca FILE` (or `VOS_CA`).
    The key is the one `vos node run` prints and `vos node info` checks.

**Tests:**

- `node/host/tests/ingress_tls.rs`:
  - plain HTTP is refused on `0.0.0.0` and `::`, and served on 127.0.0.1;
  - addresses and trust must agree (eleven cases);
  - **a pinned key:** the node id, an operator's command and a session
    over TLS; another key is refused in the handshake; plain HTTP does
    not reach a TLS ingress;
  - **a CA:** a node serving a certificate a test CA signed for
    `localhost` is trusted through that CA. It is refused through
    another CA, or by the node's key, which this certificate does not
    hold. A client pinning the certificate's own key passes TLS, but the
    node names itself otherwise: `NotTheNode`.
- The node test covers the data directory's four cases.
- `node/cli/tests/cli.rs`: `vos node run` refuses `0.0.0.0` without
  TLS; with `--tls`, `vos node info` and `vos agent create` over
  `https://` with the printed key work; another key, no key, or plain
  HTTP are refused.
- The ingress tests, sessions and the operator's, run through the new
  client.

**Left to later steps:**

- **Step 3.5:** the CLI pins every replica's key, so failing over to
  another replica passes the check.
- **Browsers:** some do not take Ed25519 certificates. A node that
  serves them uses PEM files with another kind of key.

**Review** (Opus): go, with three should-fixes, all done:

1. **Plain targets never resolve a name.** `localhost` maps to 127.0.0.1
   and ::1, and an address must be a loopback one. A resolver asked for
   `localhost` (when `/etc/hosts` lacks it, glibc asks DNS) could have
   sent the operator's token off the host in the clear.
2. **The server pins TLS 1.3,** rather than relying on no dependency
   turning on rustls's `tls12` feature.
3. **The handshake runs within the 10 s connect timeout,** then the
   timeouts rise to the 300 s an answer may take.

Also done:
- **A stale kept connection:** a request that the node takes twice as
  once fails on a kept connection before any answer arrives (the node
  likely restarted). It is then sent once more on a new connection, and
  the other kept connections are dropped. That covers reads, and signed
  calls and queries, which the node deduplicates. A session open and an
  operator's command are never sent twice. Test: a node restarted in
  the same process under a client's kept connection; it fails without
  the retry.
- **Shutting down ended the ingress but not its connections.** They were
  detached tasks, and a kept connection held the node's store open
  after `Node::shutdown`, so the node could not open again in the same
  process. Step 3.5's in-process clusters restart nodes. The ingress now
  owns its connections, and on shutdown cancels each before the runtime
  stops.
- answers above 16 MiB are refused;
- the node keeps its public key in its data directory (`node.key`), and
  operator commands, which run on the node's host, pin it when given
  neither a key nor a CA;
- `--node-key` wins over `--ca` (or their variables), rather than
  conflicting;
- a host name rustls cannot take (an underscore, say) still works with
  a pinned key, which needs no name.

**For step 3.5:** `Trust::NodeKey` becomes a set (the replicas' keys,
from the directory, read from a node already pinned), and a client's
kept sessions are keyed by agent rather than by node.

## Step 3.5: replicated agents

### Design

**Sequencing: sessions move into this step,** ahead of forwarding. The
plan puts forwarding here and client-named sessions in 3.6. But slice
2's sessions are a node's own: ids the node assigned, keys in a
node-level registry. Another replica cannot check a session's
signatures, nor keep its sequence across a failover, and the
exactly-once checker would fail its first failover. Four parts, each
reviewed and committed on its own:

1. **3.5a, the replicated group:**
   - the space's configuration and the network in the node;
   - creation with a replica set, and the directory;
   - the group driver;
   - the leader proposing, and every replica applying;
   - leader changes;
   - programs and blobs reaching every replica.

   Clients call the leader. Elsewhere, calls answer `NotLeader` with the
   leader's address, and queries run on any replica.
2. **3.5b, sessions in the agent** (3.6's design):
   - client-named sessions;
   - signatures over the agent's identity;
   - failover by `NotLeader` redirect;
   - the exactly-once checker's first form, under leader kills: no
     acknowledged request lost or applied twice, no reply before its
     apply.
3. **3.5c, any replica serves:**
   - forwarding with verification, and re-forwarding;
   - followers' queries with version floors, and read-index queries;
   - the client pinning every replica's key;
   - the checker gains linearizable reads;
   - before this step, commits reach followers eagerly (section 7.5). A
     leader with nothing new to send sends nothing today
     (`core.rs:1879`), so followers learn of a commit only from the
     next heartbeat.
4. **3.5d, messages between agents across nodes;** then three
   processes.

What 3.6 keeps: expiry, collection and caps, under the checker (expiry
and replay).

#### 3.5a The replicated group

**The space.**
- A node runs in a space given by a file. For each node it lists:
  - its number;
  - its key;
  - its peer address;
  - its ingress address.
- `vos node run --space FILE`: the node finds its own entry by its key.
  `NotLeader` names the leader's ingress address, which a client can
  reach (a node number is not reachable).
- Without a space file, the node is a space of one: every agent is a
  group of one, through the same code.

**The network in the node:**
- **vos-net gets an executor of its own,** driven by one thread, and a
  small `quinn::Runtime` that spawns there. Today quinn's smol runtime
  and vos-net's tasks use smol's global executor, so `SMOL_THREADS`
  could give it several threads and break the receiving side's turns.
- **A dispatcher** drains the arrival queues, Liveness and Consensus
  first. For each frame it:
  - decodes it and runs `peer::check`, hashing a blob off the runtime
    thread;
  - routes it to its group's bounded inbox without waiting;
  - drops and counts a frame whose agent is unknown, or whose inbox is
    full.

**Agent ids** carry their creating node: the top 8 bits are its number,
and the low 24 the next after the highest id in its own range (the
registry also holds other nodes' agents).

**Creation and the directory:**
- **The creation record** names:
  - the agent's id and its replica set;
  - the creating node and the time;
  - the hash of the agent program;
  - accumulate's gas limit.

  Its hash is the agent's identity, which 3.5b's clients sign for.
- **Making it durable:** the creating node writes the record durably in
  a registry row, then sends it as `Directory` to every node of the
  space.
  - A node that receives it writes its row durably before acknowledging
    (`DirectoryAck`). Applying it again is idempotent.
  - The creating node resends what is unacknowledged, on a timer and
    after every restart.
- **Authorization:**
  - an id's top byte must be the number of its sender, the creating
    node;
  - a different record for a known id is refused and logged, never
    written over.
- **The operator's answer waits for a majority of the replica set to
  hold the row.** Before that the group cannot elect a leader, and the
  creating node's disk is its only copy.
- **What each node does with a row:**
  - a replica starts the agent's group, with the replica set as its
    initial members;
  - every other node keeps the row to route by.
  - A call or query for an agent the node does not replicate answers
    with the replica set and their ingress addresses (`Elsewhere`), not
    `NoAgent`.
- From 3.7 on, when groups change members, the group's own
  configuration is the authority, and the directory is a routing hint.

**Every replica applies the same things in the same way.**
- **The program:** a replica runs a group only if its own agent program
  has the hash in the creation record. One that does not refuses to
  start the group, and says so.
- **Accumulate's gas** is the creation record's, not node
  configuration. A replica configured lower would run out where the
  others halt, and diverge in silence. Refine's gas stays a node's own:
  only the leader refines, and its result is replicated.
- **A deterministic failure** (a trap, or running out of gas) applies as
  no writes, on every replica alike, and the applied index moves on.
- **An infrastructure fault** (an executor panic, a read error) retries
  the apply, and never skips it.

**The group driver** (`group.rs`), a task per agent on the node's
runtime, owns the agent's vos-raft core:
- **Starting** follows the step 3.3c contract:
  - `writer.recovered(applied)`, then `recovery_cut`;
  - drop stale epochs;
  - `Core::new` from `store.raft`.
- **Inputs:**
  - timers (`tick` at the core's deadline);
  - its inbox of Raft messages;
  - proposals from the agent's leader loop;
  - blobs arriving.
- **Its actions:**
  - `Write`:
    - the writer commits `raft::changes`;
    - the core then hears `durable` and, through `EntryReports`,
      `entries_durable`;
    - an entry naming a blob the node lacks waits for it (below);
  - `Send`: frame it with `peer::to_wire`, then send it on Consensus on
    the agent's stream; a refusal drops it, and Raft resends;
  - `LoadEntries`: `raft::load`, run off the runtime thread, then
    `loaded`;
  - `Committed`: raise the applier's commit bound (below);
  - `CompactBound`: ignored until 3.7;
  - `SendSnapshot`: `snapshot_failed` until 3.7;
  - `Answer`: to the proposer waiting on its token;
  - `Changed`: to the leader loop.

**The applier,** a task per agent:
- **It applies through min(commit, written).** `written` is the highest
  index whose write the local writer committed and whose blobs it holds.
  A leader's commit can pass its own durable index, since followers'
  acknowledgements suffice (`member_score(me)` is the durable index in
  the majority floor), and a new leader may hold old entries without
  their blobs.
- **One entry at a time:**
  - read the entry from the store;
  - for a work result, run accumulate on the applied state, with the
    record's gas, and commit `Change::Apply` with its writes;
  - for a no-op or a configuration, the same `Apply` with no writes.
  Each apply is visible before the next accumulate takes its snapshot.
- **`Apply` is not synced:** the state rebuilds from the synced log. One
  fsync per batch, as in slice 2.
- **The applied index is published,** for the leader loop and queries
  to wait on. After a restart, an agent's calls and queries wait until
  the applier has reached the commit index it recovered.
- **The last work result's time and seed** go in a node row, in each
  apply's batch. Refine takes its time floor from it, and queries their
  time and seed. Reading the entry at the applied index, as slice 2
  does, gives time 0 after a no-op or a configuration entry.

**The leader loop**, while the group's core leads:
- **Starting,** on `Changed { Leader }`:
  1. learn the term's first index: the no-op, the first entry of the
     term in the core's first `Write`;
  2. wait until it is applied;
  3. read the agent's `version`, and the time floor;
  4. deliver what the outbox holds, as slice 2's recovery does;
  5. then batch.
- **A batch:**
  1. take inputs;
  2. refine against the applied state;
  3. **dry-run accumulate** on the same state, to isolate a failure off
     the log: a trap or running out of gas fails the batch as slice 2's
     `Fault::Agent` does (requeue it shorter, then fail the one input);
  4. propose the result; its entry names its blobs;
  5. wait until its index is applied here, and check the entry there is
     its own (same term);
  6. answer from the applied result, and deliver the outbox.

  The leader's apply of its own entry reuses the dry run's writes when
  nothing was applied in between: the same entry on the same state.
- **No refine runs ahead of the apply before it.** There is no
  pipelining in this slice, unless 3.10's budgets need it (p99 at half
  load likely will).
- **Stopping,** on losing leadership or a `Propose` error:
  - inputs taken and inputs still queued answer `NotLeader`, with the
    leader's address when known;
  - the loop never waits for the in-flight entry's apply.
- **Machine caches are flushed on every role change.** Followers' queries
  fill them too, from older applied states.
- **Hooks:**
  - `fail_refine` stays on the leader's refine;
  - `after_commit(agent, index)` fires after the leader's own apply of
    its entry, before it answers. False stops the loop, as now;
  - `before_commit` and `fail_commit` stay on the writer, for Raft
    writes and applies alike. A failed Raft write halts the node, as in
    slice 2.

**Blobs and programs:**
- **An install's entry names its programs' blobs,** as a large result's
  names its own. The leader knows them from the batch's install inputs.
- **A follower lacking a blob** asks the leader for it (`BlobRequest`),
  and falls back to the other members. A new leader asks the followers
  for blobs its old entries name. A `Blob` is taken if it hashes to its
  name, and a `BlobRequest` is served only to replicas of its agent.
- **An entry is reported durable once its blobs are** (`EntryReports`,
  3.3b). A missing blob holds back that entry's acknowledgement, never
  a vote.
- **Pins follow the agent's installed instances:**
  - an apply that writes an instance's `Installed` row pins the
    programs it names, in the same batch;
  - one that replaces or removes it unpins the programs no instance
    names any more;
  - so every replica pins the same programs.
- **The leader no longer pins at install time.** A blob's age keeps it
  until the entry names it, and an install that never commits ages out.
- The machine pool prepares a program on its first use, from the blob
  store, so followers' queries find it.
- **A follower's ingress refuses an install** before storing its blobs.

**Clients in 3.5a:**
- **Calls, installs and grants go to the leader.** A follower answers
  `NotLeader` with the leader's ingress address, and the client retries
  there.
- **Queries run on any replica** against its applied state. Reporting
  the applied index they read (section 7.6) comes with 3.5c's version
  floors, which compare against it.
- **Sessions stay slice 2's node-level ones** until 3.5b. A client fails
  over by opening a new session at the new leader, so exactly-once
  across failover is not claimed until 3.5b. A resend in the same
  session to a node that leads again is not applied twice: the lane
  reads the applied mark, and a new leader applies through its no-op
  before it refines.
- **Messages to an agent led on another node** stay in the outbox until
  3.5d.

**With compaction off** (until 3.7):
- the log is kept whole, and so are the blobs it names;
- a restart reads the whole log;
- the core sends no snapshot while the log starts at 0.
- **One trap:** `recovery_cut`'s lost-blob path compacts through the
  applied index. A follower lagging behind that then needs a snapshot,
  and the leader retries `SendSnapshot` and `snapshot_failed` at each
  heartbeat until 3.7.

**Tests** (in process, on the hub, each node with its own clock; then
QUIC in one process):
- **Creation on three nodes:**
  - the operator's answer comes after a majority holds the row;
  - the directory reaches every node, also after the creating node
    restarts;
  - a record for a known id from the wrong node is refused.
- **Calls and installs at the leader:** every replica applies them, and
  the three states are equal row for row, pins included.
- A replica with another agent program, or a record with another
  program hash, refuses the group.
- **An input whose accumulate traps:** it is isolated by the dry run,
  and nothing reaches the log.
- **A follower answers `NotLeader`** with the leader's address. A
  non-replica answers `Elsewhere` with the replicas.
- **The leader killed:** another is elected, applies through its no-op,
  and serves calls, with batch time never going back. The old leader
  rejoins and catches up from the log.
- **A follower partitioned during an install:** it catches up, fetches
  the program blob (from a follower, when the leader lacks it), pins it,
  and serves queries with it.
- **A node restarted in process** recovers its groups from its store.
- Slice 2's tests pass on a space of one.
- **The acceptance bench** on a space of one, against slice 2's 29–31 µs
  per request. Single-replica agents keep slice 2's path only if the
  group of one costs measurably.

**Not in 3.5a:**
- compaction and snapshots (3.7);
- combined heartbeats and quiescence (3.8);
- membership changes after creation.

**Review** (Opus): go, once one blocking item was in the design. It now
is: every replica applies the same things in the same way. The
creation record names the program and accumulate's gas, and failures
have a rule. The should-fixes are folded in above:
- the applier's bound and its one-at-a-time applies;
- blobs fetched from any member;
- the time floor in a node row;
- the directory's durability, authorization and majority answer;
- ingress addresses in the space;
- the leader loop's start, stop and hooks;
- vos-net's own one-thread executor.

The step split into four, and the nits, are folded in too.

### 3.5a: the replicated group

**Built:**

- **The space** (`space.rs`): a file of nodes (number, key, peer
  address, ingress address), `vos node run --space FILE`. A node finds
  its number by its key; without a file it is node 0, alone.
- **vos-net's own executor:** a thread of its own drives every network
  task, quinn's included, through a `quinn::Runtime` that spawns there.
  Tasks reach it by a weak spawner, so none keeps it alive in a cycle.
- **The network in the node:** QUIC, or a hub for tests. A dispatcher
  takes liveness and consensus first, checks each frame (hashing blobs
  off the node's thread), and routes Raft messages to each group's
  bounded inbox without waiting.
- **Creation and the directory** (`dispatch.rs`):
  - agent ids carry the creating node's number in their top 8 bits;
  - the creation record (id, replicas, creator, time, program hash,
    accumulate gas) is the registry row, and its hash the agent's
    identity;
  - the creator announces it to every node, and resends every second and
    after every restart until each acknowledges holding it durably;
  - a record comes only from its creator (`Refusal::NotTheCreator`), and
    one that differs from the record held for its agent is refused;
  - the operator's answer waits, up to 30 s, for a majority of the
    replicas;
  - a replica whose agent program has another hash refuses the group.
- **The group driver** (`group.rs`), following the 3.3c recovery
  contract:
  - writes go through the node writer, with `EntryReports` holding back
    an entry's durability until its blobs are stored;
  - `CompactBound` is ignored and `SendSnapshot` answered
    `snapshot_failed` until 3.7;
  - it publishes the group's role, term, leader, the first index of a
    term it leads, commit and written indices.
- **The applier,** a task per agent:
  - it applies through min(commit, written), one entry at a time, each
    `Apply` unsynced;
  - accumulate runs with the creation record's gas, and a deterministic
    failure applies as no writes;
  - an infrastructure fault retries, with backoff;
  - the last work result's time and seed go in a node row (`LastResult`)
    in the same commit;
  - pins follow the `Installed` rows the apply writes.
- **The leader loop** (`leader.rs`, slice 2's leader moved out of
  `node.rs`):
  - it starts once this replica applied its term's no-op;
  - each batch refines, dry-runs accumulate (whose failure isolates
    inputs off the log), proposes, and answers after its own apply of
    its own entry. The apply reuses the dry run's writes for that entry
    on that state;
  - losing leadership answers `NotLeader`, and a stopped group answers
    `Stopped`;
  - `after_commit` false stops the leader loop only; the replica goes on
    applying;
  - recovery's redelivery first lets each local target's group settle.
- **Clients:**
  - a call to a replica that knows no leader yet waits for one, up to
    four election timeouts;
  - a call is still queued at once when the leader is known, so calls
    made together share a batch;
  - a follower answers `NotLeader` with the leader's ingress address
    (HTTP 421), and a node that does not replicate the agent answers
    `Elsewhere` with the replicas';
  - `vos agent create --replicas 1,2,3`.
- **Slice 2's single-node behaviour is unchanged on a space of one,**
  through the same code. Its tests' log indices now count each term's
  no-op.

**Tests:**

- `node/host/tests/cluster.rs` (each node with its own clock, on a hub
  unless said; elections 40–80 ms):
  - created on three nodes: every replica runs the group; installs and
    calls at the leader apply alike, row for row and pin for pin; every
    replica answers queries;
  - a follower answers `NotLeader` with the leader's address, and a
    fourth node `Elsewhere` with the replicas;
  - the leader stops: another serves the same session on, batch time
    never goes back, and the old one rejoins and catches up;
  - a partitioned follower catches up, fetches the program blob it
    missed, pins it, and runs it;
  - a restarted follower recovers its group;
  - a record reaches a node that was down, once its creator restarts, or
    by the creator's resends while it runs;
  - a replica with another agent program refuses the group;
  - an input whose accumulate fails is isolated by the dry run, and no
    entry carries it;
  - three nodes over QUIC on localhost replicate, fail over and catch
    up.
- **Mutations:**
  - without pins following the applies, the pin comparison fails;
  - without the resend timer, the late node never learns of the agent;
  - without blob fetching, a follower cannot acknowledge the install,
    and the install never commits.
- Every slice 2 node, ingress and crash test passes on a space of one.
- **The acceptance bench, on a space of one:**
  - 28.0 µs per request under load, 35.7k per second (slice 2: 27.5–30.9
    µs), and 29.1–30.5 µs after the review's fixes;
  - a request alone takes 2.8–2.9 ms (slice 2: about 3 ms);
  - query median 50–52 µs.

  So single-replica agents take the group path.

**Not done in 3.5a, deliberately:**

- **Queries do not yet report the applied index they read:** it needs a
  wire change, which comes with 3.5c's version floors.
- **Machine caches:** `OuterMachines` reset every machine they restore,
  so a role change has nothing to flush.
- **Two paths are built but not tested end to end:**
  - fetching a blob from a follower when the leader lacks it (the
    request rotates through the members);
  - an apply whose accumulate fails on a committed entry (the dry run
    keeps such entries off the log, and no test can commit one yet).
- **Results of 64 KiB or more** still go inline in the entry; blobs carry
  only programs so far.

**Review** (Opus): no-go on two blocking holes, both fixed:

1. **A proposal from an earlier leadership could land in a later term,
   and a batch be answered `Ran` though accumulate skipped it.** A
   leader refining a long batch loses leadership and wins it back. Its
   old proposal lands in the new term, and the new loop's batch, refined
   at the same version, then applies as no writes but is answered.
   - Proposals now carry their term, on a channel of their own (never
     dropped), and the driver refuses one whose term or role no longer
     holds.
   - The applier records whether each work result took (accumulate
     advanced the version with it). The leader answers only one that
     took, and requeues the inputs of one that did not.
   - Each batch reads its version from the state it refines on.
   - Test: a hook fails the apply of the first entry carrying a marked
     input, on every replica alike. The leader requeues, and the input
     applies once. Without the outcome check, the call is answered and
     the state stays 0.
2. **A work result over 2 MiB could never replicate.** Refine allows 4
   MiB, but a consensus frame was bounded at 2 MiB, so the append was
   refused forever while heartbeats kept the leader. The bound is now 5
   MiB, with a compile-time assert tying it to the work-result cap.

Should-fixes, all done:
- **S1:** a truncation lowers `written` and the queued writes' last
  indices, so an entry replaced at the same index never counts as
  holding the old one's blobs.
- **S2:** a leader loop that stops for good (a hook, a broken invariant)
  retires its replica: the driver reports its writer stalled from then
  on, so the core hands leadership over and never campaigns, while the
  replica goes on applying and answering queries.
- **S3:** the queue holds a `leading` flag, set when this replica's
  leadership starts and cleared with the refusal of what it left. A push
  checks it under the queue's lock, from any thread, so no input lands
  where no loop will take it.
  - Queueing every call through a task on the node's thread did the same,
    but cost a quarter of the throughput: 39 µs per request against 29.
  - Calls are queued at once again, and calls made together share a
    batch.
  - Installs and grants run on the node's thread.
- **S4:** a driver that exits answers every proposal still queued, and
  the leader races its wait for an answer with the group stopping, so a
  storage failure cannot hang shutdown.
- **S5:** the leader's proposals no longer share the bounded inbox with
  peers' messages.
- **S6:** the dispatcher routes Raft messages inline; blobs (hashed off
  the thread) and creation records (committed) are handled in tasks of
  their own. Raft messages with no group, or a full inbox, are counted
  (`Refusal::Unrouted`).
- **S7:** a round's messages go out before its writes are waited on (the
  core holds back what must wait), so a leader's appends and its own
  fsync overlap. The writer's health reaches the core
  (`writer_health`).
- **S8:** a creation that a majority does not confirm within 30 s
  answers `Unconfirmed` with the agent's id (HTTP 202), not a failure.
- **S9:** the defaults are the plan's: 500 ms heartbeats and elections
  between 1.5 and 3 s. **A lone member now elects itself at its first
  tick** (a vos-raft change, with a test): no other member could lead,
  and a space of one would otherwise wait out a timeout.

Also done:
- `recovered` is clamped to what the log holds;
- the id that would be the node's own records' is never made;
- blobs are served one at a time, each once the peer's bulk queue has
  room (for 5 s at most);
- a test of fetching a blob from another member while the leader
  withholds it (`Hooks::serve_blob`);
- the cluster tests take hooks per node.

**Notes for later steps:**
- **3.7:**
  - only the creator resends a creation record, so a node that missed it
    never learns of the agent if the creator is lost for good. Groups'
    own configurations become the authority with membership changes;
  - `LastResult` is a node row, not agent state, so snapshots must carry
    it.
- **3.8:** a restart re-announces every record the node created, to
  every node.
- **The directory, still:** a replica that refuses the agent's program
  acknowledges its record (it holds it durably), so it counts toward the
  creation's majority, and it is listed among the replicas in
  `Elsewhere`.

**Re-review** (Opus): go. Also folded in:
- a leader loop whose start fails on a read retries with backoff while
  its replica leads, rather than leave a leader with no loop;
- a batch whose result applies as no writes twice running is shortened
  as a failing batch is, so a persistent apply failure cannot append
  entries without end;
- a retired replica refuses callers with `NotLeader` and the next
  leader's address, not `Stopped`;
- creation records are checked and stored one at a time, so two records
  for one id are never both written;
- the dry run is keyed by the applied index of the snapshot the batch
  is refined on.

### 3.5b: sessions in the agent

#### Design

The plan's "Sessions" section, made concrete, without 3.6's expiry,
collection and caps.

**What a session is:**
- **Named by the client:** `Session { key, name, t0 }`, its ed25519
  key, a random 128-bit name, and its creation time in milliseconds
  since the Unix epoch. The triple is the session's identity: the same
  key and name with another t0 is another session.
- **No open:** every request carries its triple, and its key signs it.
  `POST /sessions`, `Open` and `Opened` go, and so do the node-level
  session registry (`Change::Session`/`ForgetSession`, the
  `Session`/`NextSession`/`KeyOpened` rows, retired) and the per-key
  cap that evicted.
- **What a client signs:** `domain ∥ agent identity ∥ fields`, where the
  identity is the hash of the agent's creation record, not a node's id.
  Any replica, and any later leader, checks the same signature.
  - `call_message(identity, session, sequence, instance, method,
    arguments)`;
  - `query_message(identity, key, not_after, instance, method,
    arguments)`: queries carry a key, not a session. A captured query
    can be replayed until its `not_after` (5 min at most), at any
    replica: it is a read, as its caller.
  - `GET /agents/{id}` answers the agent's creation record, from which a
    client computes the identity, and from 3.5c learns the replicas.

**In the agent's state** (new keys under `SYSTEM`):
- **`session_index(session)`:** keyed by the raw triple (key ∥ name ∥ t0,
  big-endian), the session's compact `SessionId`. Accumulate assigns it
  when it creates the session, from a counter that is never reused
  (`next_session`), so marks and reply keys stay short. A key's
  sessions sit together, so 3.6's per-key cap is a prefix scan.
- **`session(id)`:** `SessionMark { session, sequence, time }`, now with
  its triple, so 3.6's collection can remove the index.
- **`reply(id, sequence)`:** the reply window, as in slice 2.
- **`live_sessions`:** a count of sessions, for 3.6's per-agent cap.
- **`batch_time`:** the high-water mark of work-result time.
- **A step's reference to its session** is `Known(id)` or `New(triple)`,
  so only a new session puts its 56 bytes in the log.

**Refine** (the default agent, per request):
- **A session the state holds:** the expiry and sequence checks of
  slice 2, as before.
- **A new session:**
  - its first request has sequence 1;
  - its t0 is within the skew (`SESSION_SKEW_MS`, 60 s) of the batch's
    time, else it is refused `STALE_SESSION` and never runs;
  - several requests of one new session in one batch run in order.
- **Refine does not check batch time against the mark.** The leader's
  floor is the mark, and accumulate refuses below it. A dry run that
  applies as no writes is the leader's invariant failure, not a poisoned
  input to bisect.

**Accumulate** is the authority, per result and per request:
- **A result whose time is below `batch_time`** applies as no writes;
  otherwise `batch_time` moves to the result's time.
- **A ran request of a session the state does not hold** creates it if
  its t0 is within the skew of the result's time: the next id, the
  index, the live count, then the mark and the reply. Outside the skew,
  **the whole step is skipped**: no writes, messages, mark or reply. A
  resend of sequence 1 then runs once, or never.

**The leader:**
- **Its time floor** is `batch_time`, read with the version from the
  snapshot a batch refines on. Its batch time is max(clock, floor).
- **A leader whose clock trails the floor** by more than `CLOCK_BOUND`
  (10 s) logs it loudly and keeps leading, its time held at the floor.
  - With `StaleSession` reporting the effective time (below), a held
    time only delays expiry.
  - A transfer here would flap: every replica trails after a fast clock
    led. One to a peer known not to trail waits for 3.8's liveness,
    which can carry clocks.
- **It is the authority for duplicates.** A request refined `SEQUENCE`
  at or below its session's applied mark is answered with the reply in
  the window, or `TooOld`, the same rule as for messages.
  - This is the main failover path. A new leader takes calls before its
    predecessor's last entries apply, so the ingress, reading a stale
    mark, queues a resend whose original committed. Refine, after the
    catch-up, refuses it as a duplicate.
  - So `SEQUENCE` reaches a client only for a gap.

**The ingress, on the leader only** (a follower answers `NotLeader`
before any of this):
- **The signature,** checked against the request's own key.
- **The lane logic of slice 2,** keyed by (agent, triple), reading the
  agent's applied state through `session_index`:
  - at or below the mark, the reply from the window, or `TooOld`;
  - in flight, a wait for its answer;
  - the next, queued;
  - otherwise `Gap` or `Ahead`.
- **A request of a session the state does not hold** whose t0 is outside
  the skew of the leader's effective batch time, max(clock,
  `batch_time`), is rejected `StaleSession { now }`, with that time. A
  client picks a t0 that refine accepts. Refine's refusal stays the
  authority.

**Redirects:** `NotLeader` and `Elsewhere` carry each node's key as well
as its ingress address, from the space. A client that pinned one node
follows a redirect it vouched for: it already trusts that node's
unsigned replies, so this adds no trust.

**The client:**
- **One session per agent:** a fresh name and t0 = the time it last
  learned from the node (its clock at first), and a new session only on
  a definitive refusal (`EXPIRED`, `STALE_SESSION`, `StaleSession`).
  Never on an ambiguous failure: it resends the same sequence instead.
- **Kept with the key file:** `session <agent> <name> <t0> <next>` per
  agent, and the agent's identity once fetched.
- **`NotLeader`:** it follows the redirect, pinning the key the
  redirecting node gave, with the same session and sequence, at most a
  few times.

**The exactly-once checker, first form** (`tests/exactly_once.rs`):
- **The cluster:** three nodes in one process on a hub, each serving its
  ingress on a port chosen before the space is written, so redirects
  name reachable addresses.
- **Clients:**
  - over HTTP, sending increments of distinct amounts, each to the node
    they believe leads;
  - on `NotLeader` they follow the hint; on `Stopped`, an error or a
    timeout they try the next node, the same sequence each time, until
    it is answered;
  - one mode sends one request at a time per session; another pipelines
    several, so lanes, in-flight joins and gaps meet failover.
- **Faults,** seeded and at random:
  - the leader stopped and started again;
  - a stop between the leader's own apply and its answer (a hook stops
    its loop there, and the node is then stopped): the window path;
  - a node partitioned and healed;
  - the hub's loss and delay;
  - a jump in one node's clock.
- **Checks:**
  - every answer equals the running total of its session's amounts, so
    no request applied twice or was skipped;
  - an unexpected answer fails the run: `Refused(SEQUENCE)`, `Gap`,
    `Ahead` or `TooOld` where a client resent in order;
  - after an answer, the answering replica's applied state holds it: no
    reply before its apply;
  - at the end, every replica's counter is the sum of all amounts.
- Read-index queries join in 3.5c.

**Not in 3.5b:**
- expiry by collection, the expiry index, the sweep input, and the caps
  (3.6). Sessions are never collected until then, so state grows with
  every session a client makes;
- forwarding, pinning the replica set, and verifying signatures on
  executors (3.5c).

**Review** (Opus): no-go until the leader was the authority for
duplicates, which it now is (above). Also folded in:
- a step whose session accumulate does not create applies nothing;
- `StaleSession` reports the effective batch time, not the raw clock;
- no transfer for a trailing clock;
- redirects carry keys;
- the checker's stronger checks and faults, and a pipelined mode;
- a batch below the mark is an invariant failure, not bisected;
- `Known`/`New` session references;
- the live-session count for 3.6.

#### Built

- **The wire** (`vos-wire`):
  - `Session { key, name, t0 }`, and `SessionRef::{Known(id), New(session)}`
    in a step's `InputRef`, the new session boxed so every step does not
    carry its size;
  - a `Request` carries its session whole;
  - `SessionMark` stays `{ sequence, time }`: the session's whole is
    written once, under `session_of(id)`, when accumulate creates it (for
    3.6's collection). With the whole in the mark, accumulate had to read
    the mark of every request to rewrite it;
  - new system keys: `session_index`, `session_of`, `next_session`,
    `live_sessions`, `batch_time`, and `SESSION_SKEW_MS` (60 s);
  - the codec encodes a `Box<T>` as its `T`;
  - `Open`, `Opened`, `UnknownSession` and `StaleOpen` are gone;
    `Rejection::StaleSession { now }` and `refusal::STALE_SESSION` are
    new;
  - `call_message` and `query_message` sign over the agent's identity; a
    query carries a key;
  - `NotLeader` and `Elsewhere` carry `Contact { address, node }`;
  - `STEP_RESULT`'s envelope is 128 bytes, for a new session's 57.
- **The default agent:**
  - refine finds a session by its triple (`session_index`, then its
    mark), names it `Known` or `New`, and refuses a new one outside the
    skew `STALE_SESSION`, before the sequence check;
  - accumulate skips a result timed before `batch_time`, or holding a
    new session outside the skew, whole (version and all: the leader's
    dry run then fails as an invariant). It creates a step's new session
    before its writes (id, index, whole, live count). A `Known` step
    reads nothing: the version check stands for refine's reads, as it
    does for pair marks;
  - refine's batch map orders sessions by name as a number, then time,
    then key, with no copies: the derived order compared the 32-byte key
    first, and a tuple order copied both sessions per comparison;
  - small records (ids, marks) are read and decoded on the stack
    (`state_read_into`), and the index key is built without an
    allocation.
- **The node:**
  - the session registry, `POST /sessions`, its rows and the per-key cap
    are gone;
  - `GET /agents/{id}` answers the creation record, and
    `vos_node::identity(record)` is its hash;
  - ingress first asks `Inner::leading`: a replica that does not lead
    answers where the leader is, before the signature or the lanes. The
    lanes are keyed by (agent, session) and read the agent's state
    through `session_index`;
  - a session the agent does not hold, with a t0 outside the skew of
    max(clock, `batch_time`), is rejected `StaleSession { now }`;
  - the leader reads `batch_time` with the version per batch and times
    the batch at max(clock, it), logging once when its clock trails by
    more than 10 s;
  - a request refined `SEQUENCE` at or below its applied mark is
    answered from the window, or `Reply::TooOld`.
- **The client** (`client.rs`):
  - one session per agent, named and timed by the client (`Kept`), and
    the agent's identity fetched once;
  - `call` follows `NotLeader` and `Elsewhere` (up to 4 times), trusting
    the next node as it trusts nodes: by the same CAs, or pinned by the
    key the redirecting node gave;
  - it starts a new session on `EXPIRED`, `STALE_SESSION` or
    `StaleSession` (up to 2 times), taking the node's time as an offset
    to its clock.
- **The CLI** keeps `session <agent> <name> <t0> <next>` and
  `identity <agent> <hex>` beside the key, replacing the file whole. A
  call left unanswered (an error, `Stopped`, `NotLeader`, `Unavailable`)
  is kept as `pending <agent> <digest>`: the same call again goes with
  its sequence, and another call first starts a new session, so it never
  takes the earlier one's answer.

**Found by the checker, and fixed:** right after a failover, a new
leader's ingress read a mark that trailed what the old leader had
answered, so a client's next request was answered `Gap`. Ingress now
waits until the leader has applied its term's no-op (everything its
predecessors committed) before it reads a mark, for 10 s at most
(`Unavailable` after). With that, the leader's
own duplicate answer is a second line: the checker reaches it only when
ingress lets a duplicate through.

**Tests:**
- **Agent** (`tests/agent.rs`): sessions named by their triple and
  created by accumulate (`Known`/`New` references, ids never reused,
  the session's whole under its id, the live count, `STALE_SESSION`
  both sides of the skew, a new session starting at 1, another t0
  another session); accumulate skipping a stale new session, and a
  result timed before the agent's time. The pricing test measures `send` over eight steps:
  over one, the heap's growth weighed on 16 sends and the measure moved
  with the request's size.
- **Ingress:** a changed session name or key fails the signature; a body
  signed for one agent fails at another; `StaleSession { now }` both
  sides of the skew; an expired session renewed by the client at the
  node's time.
- **Node:** the leader answers a duplicate past ingress from the window,
  `TooOld` past it, and refuses a gap.
- **The exactly-once checker** (`tests/exactly_once.rs`): three nodes on
  a hub serving HTTP at the addresses their space names, three clients
  each at its own agent (so every answer is the running total of its
  amounts), each starting a new session every 32–60 requests (about 100
  a run), one request at a time or four in flight on their own
  connections. Sixteen faults per run, seeded: stops; a stop between
  the leader's apply and its answer (`after_commit`); a node isolated;
  loss and delay; a clock 15 s ahead or behind. Checks: every answer the
  running total, no unexpected answer (`Gap` only for a pipelined
  request that passed its predecessor), the answering replica's mark at
  or past the sequence, every replica's counter the sum at the end. A
  run answers about 2,500 requests one at a time and 4,500 pipelined in
  about 8 s each. Before the fix above, four seeds of twelve failed with
  `Gap`; since, 24 seeds have passed.
- **Also over HTTP:** a client sent to a follower calls the leader from
  then on; a leader whose clock trails by 30 s times its batches at the
  agent's time and goes on leading.
- **Mutations, each caught:**
  - answering on commit, before the leader's apply: "answered sequence
    3 at mark 2";
  - no catch-up wait at ingress: `Gap`;
  - ingress letting duplicates through: the leader's duplicate answer
    keeps the checker passing; without it too, `Refused(SEQUENCE)`. The
    node test catches the leader's answer missing alone;
  - no time floor at the leader: the trailing leader's call is
    `Stopped`.

**Cost** (acceptance bench on a space of one, against the 3.5a commit on
the same machine and session; 256 sessions, about 190 a batch, so nearly
every request is its session's first in its batch):
- first build: 39.0–39.9 µs per request against 28.1–32.1. Refine gas
  per request was 132.9k against 95.1k, and accumulate's 26.3k against
  23.7k;
- the batch map's order, small reads on the stack, the stack-built key,
  the mark without the session and the boxed new session bring refine to
  99.1k (+4%) and accumulate to 24.1k (+2%);
- **what remains: 32.6–34.5 µs against 30.8–31.2,** all in refine's wall
  time (20.2–20.6 µs per request against 17.8–18.3; the dry run and the
  decode are even). It is the second read a request's session costs
  (triple to id, then the mark): cheap in gas, but a store lookup and a
  host call each. Ingress pays the same second read per call.
- **The way to remove it:** keep the mark in the index row, so one read by
  triple gives id and mark, and have each step carry its session whole
  (and its id), so accumulate writes that row without reading. That costs
  56 bytes more per request in the log, which `Known`/`New` was made to
  avoid. Left for review.

**Review** (Opus): go, with no blocking issue. Folded in before the
commit:
- a redirect keeps the client's trust: a client that trusts CAs no longer
  pins the key it is given, which fails against a node serving a
  certificate from files;
- the CLI counts `Unavailable` as unanswered (the leader's duplicate
  answer fails that way when it cannot read), and writes its file whole;
- the checker's clients rotate sessions, so a session's first request
  meets failovers;
- accumulate skips a whole result holding a stale new session, not the
  step alone: later steps were refined as if it ran;
- the catch-up wait is bounded.

Accepted: the mark without the session, the boxed `New`, the pricing
test over eight steps, and the cost (about 8% on a space of one, inside
the replicated budget; revisit with 3.10's pipelining).

**Left for later:**
- `query` does not follow `Elsewhere` (3.5c's queries);
- the checker could mix two clients on one agent (`Known` and `New` in
  one batch), and run over TLS with pinned clients;
- a clock far enough off for `StaleSession` under failures: the jumps
  stay within the skew.


### 3.5c: any replica serves

#### Design

A client calls and queries any replica of an agent, and fails over to
another without a redirect. Two commits, each reviewed:
- **3.5c1, calls:**
  - commits reach followers at once;
  - answers carry the applied index they reflect;
  - forwarding, and signature checks on executors;
  - the client using every replica;
  - the checker calling through any replica.
- **3.5c2, queries:**
  - floors and read-index queries;
  - the checker's reads.

**Commits reach followers at once** (vos-raft). Today a leader with
nothing new for a peer sends nothing (`replicate`'s `next > last`), so a
follower learns a commit at the next heartbeat, up to 500 ms later, and
a forwarded call would wait that long.
- **A leader tracks the commit index each peer was last sent.** The
  commit append is built as a heartbeat is:
  - `prev_index = next − 1`;
  - `commit = min(commit, match_index)`, the per-peer cap the plan sets,
    so a commit can never make a follower apply an entry it does not
    hold as the leader's;
  - it carries the current round, never a new one. Its acknowledgement
    confirms only reads registered before it was sent, so that is
    sound.
- **When it goes:** at once, when that capped commit passes the last
  commit sent to the peer, unless an append with entries in the same
  round already carries it.
- **It takes no in-flight slot.**
- One message per commit per peer. 3.8's combined heartbeats revisit it
  for many groups.
- Test: a follower applies an entry before any heartbeat is due.

**Answers carry `at`,** the applied index of the state they reflect:
- `Answer::Ran { outcome, at }`;
- for a call, the index of the entry it applied in, or for a reply from
  the window, the applied index the window was read at;
- for a query, the applied index it ran on.

A client keeps the highest `at` it has seen for each agent, as the floor
for its next query (3.5c2). Internally the leader's answer carries the
index beside the `Reply`.

**Forwarding:**
- **A replica that does not lead takes the call:**
  1. it checks the signature on an executor;
  2. it sends `Forward { agent, token, call }` to the leader it follows
     (class Requests, on the agent's stream). `token` is random, chosen
     once per call and kept across every re-forward;
  3. the leader runs the call as its ingress does (the lanes move out of
     the HTTP ingress into a module both use), and answers
     `Forwarded { agent, token, answer }` when it would answer its own
     client;
  4. on a `Ran`, the forwarder waits until its own applied index reaches
     `at`, then answers its client. So no reply leaves before the
     request is applied on the replica that answers. Any other answer
     goes back at once.
- **The leader trusts the forwarder's signature check.** A `Forward`
  comes only from a replica of the agent, and replicas are trusted as
  Raft members are: under crash faults, one that lied could do worse
  through its votes. The leader's own ingress checks its own clients.
  `Forward` carries the signed call whole, so the leader re-verifies it
  once a space can hold members it does not trust, and for step 5's
  "client's own node", which is no member.
- **The dispatcher hands each `Forward` to a task:** its lane waits for
  the call's answer, and the dispatcher never waits (3.5a's S6).
- **Installs and grants are not forwarded.** An install carries up to
  64 MiB of programs, and operator commands still answer `NotLeader`.
- **Re-forwarding,** with the same call and token, until a deadline
  (30 s):
  - on `NotLeader` or `Unavailable` from the leader;
  - on `Stopped`, once the replica follows another leader, or after a
    pause: a retired leader answers `Stopped` while it hands over, and
    sending it the call again at once would spin;
  - when no answer comes within 2 s;
  - when the replica follows a new leader;
  - with no leader known, after the group settles.

  A `Forwarded` is matched by its token, from any node: a late `Ran`
  from an earlier leader still completes the call.
- **A forwarder that becomes the leader** runs its pending calls through
  its own lanes: the network refuses a send to its own number.

  The leader's lane makes each one safe: it joins a duplicate in
  flight, answers one already applied from the window, and refine's
  duplicate answer covers the rest.
- **When the deadline passes, `Answer::TimedOut`:** the call may have
  run, or may yet. The client sends it again with the same sequence, as
  after any unanswered call; the CLI keeps it as pending.
  - The wait for the replica's own apply counts against the same
    deadline.
  - At the deadline the answer is `TimedOut`, never the leader's
    outcome: no reply leaves before its apply on the replica that
    answers. A resend at another replica is answered from its window at
    once.
- **Admission:** the leader holds at most 1,024 forwarded calls in flight
  per forwarding node, and answers `Busy` past that. A forwarder's own
  are bounded by its connections.
- **Checks** (`peer::check`):
  - `Forward` and `ReadIndex` only from a replica of the agent;
  - `Forwarded` and `ReadIndexAnswer` are matched by token, and one that
    matches nothing is dropped and counted.
- **A node that does not replicate the agent** still answers `Elsewhere`.
  Forwarding through a node with no replica, as the plan's "client's own
  node" would, comes with step 5.

**Signature checks on executors:** ingress checks each call and query on
an executor, at the forwarder and at the leader alike. This keeps about
50 µs per request off the node's async thread.

**The client:**
- **`GET /agents/{id}` answers `AgentInfo { record, replicas }`,** the
  replicas as `Contact`s. The client computes the identity from the
  record, as before, and keeps the replicas.
- **Trust:** each replica is trusted as `follow` trusts a node: by the
  same CAs, or pinned by the key the answering node gave.
- **It calls the replica it was given.**
  - On an error, `Stopped`, `Unavailable` or `TimedOut`, it calls the
    next replica with the same sequence.
  - On `Busy`, which comes from the leader's admission, it backs off:
    any replica forwards to the same leader.
  - It still follows `Elsewhere` and `NotLeader`.
- `vos call` and `vos query` take any replica's address.

**Queries (3.5c2):**
- **`QueryCall` gains `read`,** in the signed bytes:
  - `Read::Applied { at }` waits until the replica has applied through
    `at`, for 5 s at most, else `Rejected(Behind)`, and the client tries
    another replica;
  - `Read::Linearizable` takes a read index first.
- **The read index:**
  - a leader asks its core (`read_index`, through the driver's local
    channel), which confirms leadership with a round and answers an
    index at or past its term's no-op;
  - a follower asks its leader (`ReadIndex { agent, token }`, answered
    `ReadIndexAnswer { agent, token, index }`), and asks again on
    `NotLeader`, on a timeout, or once it follows a new leader, as
    forwarding does;
  - each read opens a round. Batching the reads registered before a round
    goes out is for heavy linearizable load, later;
  - then it waits until it has applied that index, and runs the query.
- **The client's default** is `Applied { at }` at the highest `at` it
  has seen for the agent: it reads its own writes, and reads never go
  back, at any replica. `Linearizable` is asked for
  (`vos query --linearizable`).
- **The CLI keeps each agent's floor** (`at <agent> <index>`) beside its
  sessions, so it reads its own writes across `vos` commands.
- **`#[msg(linearizable)]` is not in this step.** It is a promise to the
  agent's developer that a method never reads stale state, whatever the
  client asks. It goes with the SDK's next macro work (step 5 at the
  latest). Here the client chooses its consistency per query.

**The checker:**
- **3.5c1:**
  - clients call a random replica and move to another on failure, so
    forwarding and re-forwarding meet the faults. The answering
    replica's mark check stands, now mostly at followers;
  - a new fault cuts the leader off from its followers while clients
    call the followers;
  - a test checks that a forwarder refuses a badly signed call before
    forwarding it.
- **3.5c2:** each client reads its counter alongside its calls, at
  random replicas:
  - a linearizable read must be `total(k)` for some `k` between the
    requests acknowledged before it started and those sent before it
    ended (the totals are distinct and increasing);
  - a read floored at the last acknowledged call's `at` must be at least
    that call's total;
  - a client's successive floored reads never go back, since answers'
    `at` feed its floor.

**Not in 3.5c:**
- `#[msg(linearizable)]` (above);
- leases;
- forwarding through nodes with no replica;
- messages across nodes (3.5d).

**Review** (Opus): go, with no blocking issue. Folded in above:
- the commit append's shape;
- one token per call, matched from any node;
- a forwarder that becomes the leader;
- re-forwarding on `Stopped`;
- installs and grants not forwarded;
- `Forward` handled in tasks;
- the CLI's floors;
- `ReadIndex`'s checks;
- the checker's new fault and floored reads.

Answered:
- trusting the forwarder is sound while members are trusted, and the
  call travels whole for later re-verification;
- `#[msg(linearizable)]` waits for the SDK;
- `TimedOut` is the answer at the deadline, never the leader's outcome.


#### 3.5c1 Built

- **vos-raft:**
  - a leader whose commit advances replicates to every peer at once;
  - a peer with nothing due gets an append with no entries, carrying the
    commit capped by its match index, in the current round, and holding
    no slot;
  - each peer's last commit sent is tracked, so the append goes once.
- **The wire:**
  - `Answer::Ran { outcome, at }` and `Answer::TimedOut`;
  - `AgentInfo { record, replicas }`;
  - `PeerMessage::Forward { agent, token, call }` and `Forwarded`, on
    Requests, on the agent's stream.
- **`calls.rs`** holds what ingress did for calls, and forwarding:
  - the lanes, moved out of the HTTP ingress;
  - each call's signature checked on an executor, then the call run in
    its lane if this replica leads, else forwarded;
  - the forwarding loop, as designed:
    - one token per call;
    - again on `NotLeader`, `Elsewhere`, `Stopped` or `Unavailable`
      after a pause or a change of leader, after 2 s without an answer,
      and on a change of leader;
    - its own lane once it leads;
    - on `Ran`, an answer only after its own apply through `at`;
    - `TimedOut` at 30 s;
  - the leader's side: the sender checked as a replica (`NotAReplica`),
    at most 1,024 calls per forwarder (`Busy` past that), each run in a
    task and answered by token. An answer no one waits for is counted
    (`Unmatched`).
- **Answers carry `at`:** the leader's answer channel carries the index
  of its entry (`Answered`), the window's reply the applied index it was
  read at, and a query the index it ran on. `Node`'s own API still
  answers `Reply`.
- **The client:**
  - it learns the replicas with the identity (`GET /agents/{id}` now
    answers `AgentInfo`);
  - after an error, `Stopped`, `Unavailable` or `TimedOut`, it goes to
    the next replica, at most 6 times, trusting it as `follow` does;
  - on `Busy` it waits, from 50 ms doubling to 1 s.
- **The CLI** keeps a `TimedOut` call as pending.

**Found by the checker, and fixed:**
1. **A deposed leader that had not heard so answered `Gap` from stale
   marks.** A leader cut off from its followers still runs its lanes.
   Its marks trail what its successor applied, so a client's next request
   was answered `Gap`. The checker's calls through every replica, and its
   new fault cutting the leader off, found it in every run. It could
   happen before, rarely, for a client that came back to a deposed
   leader.
   - Now a lane's refusal for a low mark or a missing session (`Gap`,
     `Ahead`, `StaleSession`) is answered only after a read index
     confirms this replica leads, and its apply reaches that index; the
     lane is then read again.
   - Answers from state that is there (the window, `TooOld`) need no
     confirmation.
   - The read index goes through the group driver (`Local::ReadIndex`),
     so 3.5c2's queries use the same path.
2. **A node shutting down answered forwarded calls `Elsewhere`:** its
   groups are gone while its dispatcher still runs.
   - A replica with no group now answers `Stopped`, as does a node that
     refused the group.
   - A forwarder treats `Elsewhere` from another replica as it treats
     `NotLeader`.

Also: a lane with nothing in flight is dropped when its call is answered
at once. One answered `Gap` used to stay in the map.

**Tests:**
- vos-raft: followers learn a commit at once, once, and never above what
  they hold.
- Peer: forwarding messages survive the wire, travel on Requests on
  their agent's stream, and come only from replicas.
- **Over HTTP:**
  - a follower forwards a call and answers it once it applied it, and the
    client goes on calling the follower;
  - a follower forwards no call it cannot verify (the leader would run
    it): the counter stays 0;
  - a client follows `Elsewhere` from a node that does not replicate the
    agent.
- **The checker:**
  - requests take turns at every replica, so about 60% are answered by
    followers;
  - a new fault cuts the leader off from its followers.
  - Twenty seeds pass since the fixes above, the default seeds besides.
- **Mutations caught by the checker:**
  - no read index before a lane's refusal: `Gap`;
  - the forwarder answering before its own apply: "answered before it
    held the session".
  - The focused test misses the second: with commits sent at once, a
    quiet follower applies before the answer reaches it.
- **The acceptance bench** is unmoved: 32.4–33.0 µs per request, query
  median 51–52 µs.

**Review** (Opus): no-go on one blocking item, now fixed.
- **B1. A resend of a new session's first call, while the first was still
  queued, could be refused `StaleSession`,** once the session's time had
  passed the skew. The client then ran the call again in a new session.
  The first had been timed when its batch formed, and ran.
  - Now a leader checks a new session's time only for a session it
    holds nothing of. A resend joins the call in flight first.
  - Test: the leader's refine is held, the same first call is sent twice
    2 s apart across the skew, and both are answered as one run.
    Without the fix, the second is refused `StaleSession`.
- **Beyond B1:** the client no longer starts a new session on
  `StaleSession` after any attempt whose fate it does not know (an
  error, `Stopped`, `Unavailable`, `TimedOut`, `NotLeader` with no
  leader). It answers `TimedOut` instead. A replica that lost its
  client's connection may still be forwarding the first call, and
  leaders whose clocks differ could take it then.

Should-fixes, all done:
- **S1, `Busy`:**
  - a leader drops a re-forward of a call that still runs: one task and
    one answer per call;
  - a forwarder passes `Busy` back only from its first send. Later, an
    earlier send may still run, so it waits and sends again;
  - the client answers a final `Busy` as `TimedOut` after an attempt
    whose fate it does not know.
- **S2:** a lane's `NotConsumed` is confirmed by a read index, then the
  lane is read again: a deposed leader's stale dry run cannot deny a call
  its successor ran.
- **S3:** the client fails over on `NotLeader` with no leader named.
- **S4:**
  - the client matches a replica by its normalized `host:port`, the
    scheme's port included;
  - it learns the replicas on its first call, while the node it was
    given is up.

Nits, done:
- the forwarder waits for its own leader loop as `settled` does;
- the read index's wait for the apply is bounded;
- a forwarded call's admission is given back by a drop guard;
- a failover's error no longer hides the call's;
- `Forwarded` comes only from a replica.

**The follower-apply test is deterministic now:** the follower's commits
are held while the leader runs the call, and the client must still be
waiting. Without the forwarder's wait for its own apply, it fails.

Since: sixteen more seeds pass, and `just ci` is green.

**Re-review** (Opus): go. Also folded in:
- **A forwarder that sent a call more than once** answers `StaleSession`
  and `NotConsumed` as `TimedOut`. Another of its sends may still run the
  call, so a refusal of one says nothing of the call. It does not send
  again after `NotConsumed`, which would run a failing program again and
  again.
- **The client answers `NotConsumed` as `TimedOut`** after an attempt
  whose fate it does not know, as it does `Busy` and `StaleSession`.
- **The CLI keeps when a pending call was left unanswered**
  (`pending <agent> <digest> <time>`). The same call sent again within
  60 s tells the client it repeats one whose fate is unknown
  (`Client::repeats_unknown`), so copies still in transit are covered
  across processes.
- **The forwarder re-sends after `Busy`** at the 2 s pace of a quiet
  leader, not every 100 ms.
- **A kept identity stands:** a node whose record of the agent hashes to
  another identity is refused (`ClientError::OtherAgent`).
- **The tests' gates are closed inside their scopes,** so a failing test
  opens them before the scope waits on its threads.

Left for later:
- `Forward` could carry the forwarder's view of the leader's term,
  dropped at any other. vos-net holds frames while it redials, with no
  expiry, so a held frame can reach a later leader. The lane makes that
  safe, and the term would bound every copy's life by its forwarder's
  30 s.
- the O(tasks) `retain` in the node's `spawn`;
- seq 0 taking a read index.


#### 3.5c2 Built

- **The wire:**
  - `QueryCall` carries `consistency`, in the signed bytes:
    `Consistency::Applied { at }` or `Consistency::Linearizable`;
  - `Rejection::Behind`;
  - `PeerMessage::ReadIndex { agent, token }` and
    `ReadIndexAnswer { agent, token, index }`, on Requests, on the
    agent's stream.
  - The enum is `Consistency`, not the design's `Read`, which clashes
    with `std::io::Read` wherever both are used.
- **`queries.rs`:**
  - a query waits until its replica has applied through the index it
    asks for, for 5 s at most, else `Behind`, then runs on applied state
    and answers the index it read;
  - a linearizable query first takes a read index:
    - its own core's, through the driver, when the replica leads;
    - else its leader's (`ReadIndex`), asked again after 2 s, on a
      change of leader, or after a pause when the leader could not
      confirm;
    - for 10 s at most;
  - the leader answers `ReadIndex` in a task, once its core has
    confirmed it leads, without waiting for its own apply;
  - `ReadIndex` and its answer come only from replicas of the agent.
- **`Inner::read_index`** is split into `confirm` (the core's read index)
  and `applied_through` (the bounded wait for the apply). The lanes use
  both; a remote read index uses `confirm` alone.
- **The client:**
  - keeps each agent's floor: the highest `at` any answer reflected;
  - `query` reads at that floor, and `query_with` takes any consistency.
- **The CLI:**
  - keeps each agent's floor (`at <agent> <index>`);
  - `vos query --linearizable`.

**Tests:**
- **Over HTTP, at a follower whose commits are held,** a read at the
  floor of a write's answer, and a linearizable read, each wait until
  the follower has applied the write, then see it. Without the floor's
  wait, or without the read index, the read comes back early.
- **A leader cut off from its followers** answers no linearizable read.
  Without the read index it answers from its stale state.
- **Peer:** the read-index messages survive the wire and travel on
  Requests on their agent's stream.
- **CLI:** `--linearizable`, and the kept floor.
- **The checker reads:** each client reads its counter alongside its
  calls, at every replica in turn, about 360 linearizable reads and 360
  at its floor per run:
  - a read must equal the total of a prefix of the client's requests,
    up to those sent before it ended;
  - a linearizable read must hold every request answered before it
    started;
  - a read at the floor of the last answered prefix holds that prefix,
    and never goes back.
  - Sixteen seeds pass.
- **Mutations caught by the checker:**
  - a linearizable read with no read index: "saw 128 requests, 157 were
    answered before it";
  - a floor not waited for: "went back".

**Review** (Opus): go, with no blocking issue. Its findings:
- a follower's read index from a leader deposed before the follower
  applies through it is still linearizable;
- the checker's bounds hold in pipelined mode;
- nothing a deposed leader does can make a query wrong.

Folded in:
- **A query that a replica cannot answer now goes to the others in
  turn** (`Behind`, `TimedOut`, `Unavailable`, `Stopped`, `NotLeader`,
  `Elsewhere`, a transport error): it changes nothing, so it is always
  safe to send again. Test: a follower whose commits are held answers a
  floored read `Behind`, and the client's query reads the write at
  another replica.
- **A read index is asked of the replica's own core whenever its core
  leads,** not only once its leader loop takes calls. While a handover is
  under way it asks the next leader within its deadline.
- **A leader that answers no index** is asked again at the 2 s pace, not
  every 100 ms: it may only be busy.
- **The query's wait for what its replica recovered** counts against the
  floor's 5 s.
- **A read index's answer is bound to the agent it was asked for.**
- **The checker:** a linearizable read is never below what an earlier
  read by the same client showed.
- **One `within`,** shared.

### 3.5d: messages across nodes

#### Design

An agent's message reaches an agent led on another node, and its
acknowledgement comes back, exactly once through failures. Then the
nodes run as three processes. Two commits:
- **3.5d1:** delivery across nodes, in process.
- **3.5d2:** three processes.

**Today** the leader pushes an outbox entry, and the receiver's leader
its acknowledgement, into the other agent's queue only when that agent
is led on the same node. Otherwise the entry waits in the outbox.

**The wire:**
- `PeerMessage::Deliver { to, message, relayed }`: a `batch::Message`
  (`from`, `sequence`, instance, method, arguments) for agent `to`, on
  Requests, on `to`'s stream;
- `PeerMessage::Acknowledge { sender, receiver, sequence, relayed }`:
  agent `receiver` holds `sender`'s messages through `sequence`, on
  `sender`'s stream. The names say which way it goes: in the sender's
  queue it becomes `Pending::Ack { to: receiver }`.

**Routing a message or acknowledgement to an agent:**
- **this node leads it:** into its queue, as today;
- **this node replicates it** without leading: to the leader its group
  follows;
- **otherwise:** to one of its replicas from the directory, a different
  one each time it goes again.

A replica that does not lead relays what it receives to its leader,
once (`relayed`), never to itself. A node whose group names it leader
before its leader loop takes inputs drops it. Anything else it cannot
place is dropped: the sender sends again.

**Checks,** by hop:
- **a direct hop** comes from a node replicating the origin:
  `message.from` for a `Deliver`, `receiver` for an `Acknowledge`;
- **a relayed hop** comes from a node replicating the destination: `to`
  for a `Deliver`, `sender` for an `Acknowledge`.

Replicas are trusted as Raft members are:
- a direct hop could be forged only by a node that could also forge the
  origin's log;
- a relayed hop, only by one trusted with the destination's inputs.

**The sender's leader keeps a window per target** (go-back-N):
- **The window:** it sends what its outbox holds above the target's
  acknowledgement, in order, at most 256 entries and 1 MiB beyond the
  highest acknowledgement it has taken. That bound holds for every send:
  after each batch, when its leadership starts, and on a round.
  - A burst never floods the 4 MiB Requests queue, which other agents'
    `Forward` and `ReadIndex` frames share.
- **An acknowledgement taken from the queue** (not only once applied)
  opens the window, and the window goes on: acknowledgements drive
  delivery, so a backlog drains.
- **A round:** while the outbox holds entries above the target's
  acknowledgement and none has come for 1 s, it goes back to the
  acknowledgement and sends one window again.
  - A round that brings nothing doubles the target's wait, up to 16 s,
    and progress resets it. A target refusing its messages for good
    (`UNREADABLE`) is not tried every second.
  - The leader loop wakes for rounds only while some target has entries
    above its acknowledgement.
- **It never relies on whether the network took a frame:** a refused one
  is sent again by the round.
- **An `Acknowledge` reaching its replica** goes into its queue as
  `Pending::Ack`, as a local one does. The batch clears the outbox; the
  acknowledgement is monotone and bounded by `ACK_LIMIT`, as today.

**The receiver's leader:**
- a message at or below its pair mark is a duplicate, acknowledged
  with the mark, as today;
- **a gap is now dropped before the batch:** it keeps only the next
  expected sequence per sender, in queue order. Compaction is off, and
  a refusal-only batch would cost a log entry;
- the next runs, and is acknowledged once applied;
- **messages and acknowledgements count against the queue's cap,**
  which other nodes now fill. Past it they are dropped, and the sender
  sends them again.

Its acknowledgements are routed as above. A deposed leader that has not
heard so acknowledges only marks it read from committed state. Messages
it took never commit, and are delivered again.

**Exactly once,** as in slice 2: messages are idempotent by their pair's
sequence, acknowledgements are monotone, and every retry is safe.

**The checker** (3.5d1):
- every agent gets the counter at a second instance, its inbox,
  installed before the first `forward`;
- every fifth request a client sends is `forward`, which sends its
  amount to the next client's agent's inbox;
- increments' running totals and the reads count increments only. A
  forward repeats a total, so reads compare totals: a read is at least
  the answered prefix's total;
- `forward` answers its amount;
- **at the end:**
  - every replica's inbox holds exactly the amounts forwarded to its
    agent;
  - the receiver's pair mark, and the sender's acknowledgement and last
    sequence sent for that pair, all equal the number of forwards;
  - every outbox is empty.
- **mid-run,** reads of an inbox are prefix sums of the amounts
  forwarded to it: each pair is FIFO.
- **Deliveries that crossed nodes are counted,** and a run must have
  some. Agents are led on different nodes as elections fall, and faults
  hit both ends.

**Tests (3.5d1):**
- a message to an agent led on another node arrives once and is
  acknowledged, and the sender's outbox empties;
- **four nodes, the sender on {1, 2, 3} and the target on {2, 3, 4}:**
  routing through the directory, relaying, and the checks by hop;
- a backlog larger than a window drains, driven by acknowledgements;
- **a receiver's leader stops** with messages queued: the sender
  delivers them to the next one;
- **a sender's leader stops** with its outbox unacknowledged: the next
  sender leader delivers them;
- a `Deliver` from a node that does not replicate the sender is
  dropped.

**3.5d2, three processes:**
- **a test spawns three `vos node run --space` processes,** QUIC between
  them, and creates an agent on all three with the operator's command;
- **it drives calls and queries** with the client library, and messages
  between two agents through `forward`;
- **it kills the agents' leader with SIGKILL while forwards are in
  flight, and starts it again,** and calls go on through the other two;
- **at the end,** every replica's counters, inboxes and outboxes agree,
  holding every answered call once and every forwarded amount once;
- the children are killed when the test ends, failed or not, and their
  ports are chosen with retries.

The checker stays in process, where faults are cheap and seeded. The
process test is its smoke test at the real boundary: real binaries,
QUIC, crash restarts.

**Not in 3.5d:**
- `Forward` carrying the term (3.5c1's note);
- message batching across agents, which belongs to 3.8's work on many
  agents.

**Review** (Opus): go, once five should-fixes were in the design. They
now are:
1. `Deliver` names its target;
2. checks by hop, so relays from the destination's replicas pass, and
   `Acknowledge` relays too;
3. the per-target window, driven by acknowledgements, with rounds and
   backoff, so an outbox always drains;
4. the checker compares totals, which forwards repeat;
5. deliveries across nodes are counted, plus the four-node test for the
   directory route and relays.

Answers:
- **(a)** relaying once is sound and enough. A negative answer is never
  acted on, so hidden copies and drops are harmless, and `relayed` stops
  loops.
- **(b)** the leader loop owns the rounds. They are bounded by bytes as
  well as entries, back off, and run only while something trails.
- **(c)** a stale or deposed receiver leader acknowledges only committed
  marks, which the sender treats as monotone and bounds by what it sent;
  it cannot clear an outbox wrongly.
- **(d)** the checker's end state catches a double delivery and a loss;
  pair marks and mid-run inbox prefixes make it stronger.

Folded nits:
- messages and acknowledgements under the queue's cap;
- gaps dropped before the batch;
- the `Acknowledge` field names;
- the process test's details.


#### 3.5d1 Built

- **The wire:** `PeerMessage::Deliver { to, message, relayed }` and
  `Acknowledge { sender, receiver, sequence, relayed }`, on Requests,
  on the destination's stream.
- **`messages.rs`:**
  - routing to an agent: into its queue here, to its leader, or to one
    of its replicas from the directory;
  - receiving, checked by hop: a direct hop from a replica of the
    origin, a relayed one from a replica of the destination;
  - a replica that does not lead relays once, never to itself.
- **One replica per window:**
  - a window goes through one replica of the target, the same for every
    entry, so a sender's messages keep their order on one stream. Each
    round goes through the next replica;
  - an acknowledgement goes through a different one each time: it is
    monotone, and any order will do.
  - Found by the backlog test: picking a replica per message split a
    window between a direct path and a relayed one. The two arrived out
    of order, and the gaps dropped most of every round.
- **The sender's leader keeps a `Window` per target,** in place of the
  delivered map:
  - 256 entries and 1 MiB past the acknowledgement;
  - acknowledgements taken from the queue open it, and the targets whose
    acknowledgements a batch held are filled after it;
  - **rounds:** after 1 s with the outbox above the acknowledgement, a
    window goes back to the acknowledgement and is sent again. The wait
    doubles on each round with no progress, up to 16 s, and progress
    resets it;
  - the loop wakes for a round when one is due, yields to the node's
    other tasks, and checks rounds between batches too.
- **The receiver:**
  - drops gaps before the batch (only each sender's next, in turn,
    reaches it);
  - routes its acknowledgements;
  - queues messages and acknowledgements under a cap of their own.
- **`Node::messages_sent_across`** counts the messages a node sent
  toward other nodes.

**Tests:**
- **Cluster:**
  - a message to an agent on nodes the sender's node does not replicate
    goes through the directory and a relay, applies once, and the
    sender's outbox empties;
  - four nodes with overlapping replica sets;
  - the receiver's leader stopping with messages in flight;
  - the sender's leader stopping with its outbox unacknowledged, the
    target down meanwhile;
  - a backlog of 300 (beyond a window) draining once the target's nodes
    return;
  - a forged `Deliver`, direct or relayed, from a node replicating
    neither end, is dropped.
- **Node:** a gap is dropped before any batch, unacknowledged, until it
  fills. This replaces the test that refine refuses it.
- **Peer:** the new messages survive the wire, on Requests and their
  destination's stream.
- **The checker:**
  - every fifth request forwards to the next client's agent's inbox;
  - inbox reads mid-run are prefix sums of what was forwarded, never
    going back;
  - at the end, every replica's inbox, pair mark, acknowledgement and
    last sequence sent match the forwards, and every outbox is empty;
  - about 70 to 270 messages per run cross nodes, counted across
    restarts.
  - Twelve seeds pass.
- **Mutations:**
  - with no rounds, the receiver-stop and backlog tests fail;
  - with rounds that send nothing, the checker never converges.
  - A mutation that left rounds due without rewinding them spun the
    leader loop and starved the node's thread. The loop now yields after
    a round.

**Review** (Opus): go, with no blocking issue. Its findings:
- no window wedges or sends past its outbox;
- nothing spins;
- gap filtering loses nothing and acknowledges nothing wrongly;
- the checks by hop and the relay conditions are right.

Folded in:
- **The checker's inbox reads raise the client's floor** with the index
  they read at. Reads never go back only at the client's floor, and a
  lagging replica could otherwise fail the check falsely.
- **An acknowledgement taken from the queue no longer moves a window:**
  one whose batch was lost could have opened a window the outbox
  disagrees with. The targets a batch's acknowledgements touch are filled
  after it, from the applied acknowledgement.
- **Acknowledgements:**
  - one no higher than the applied acknowledgement is dropped before the
    batch, and the rest are coalesced, one per target, so re-acks cost
    no log entries;
  - they no longer count against the cap on messages, which could
    otherwise starve the agent's own windows.
- **A target whose delivery fails at a leadership's start** still gets a
  window, whose round tries again.
- **A node's windows start at a replica of its own:** directory-routed
  senders spread over the replicas instead of all trying the first.
- **Drops are counted:** a message or acknowledgement with nowhere to go
  (`Refusal::Unplaced`).
- **`Node::messages_relayed`,** and a test that a follower relays: node
  1's first window goes through node 3, made a follower first. Without
  relaying, it fails.

Left for later:
- acknowledging the mark when a gap is dropped, so the sender goes back
  at once (fast retransmit);
- fan-in past the receiver's cap (more than four full windows into one
  agent), for 3.8.

#### 3.5d2 Built

**`node/cli/tests/three_processes.rs`:**
- **The space:**
  - three nodes, each first run alone to make its key;
  - then a space file of their keys and fresh ports;
  - three `vos node run --space` processes, QUIC between them, plain
    HTTP on loopback for the clients.
  - When a node cannot take its ports, the attempt starts over with new
    ones, five times at most.
- **The test:**
  - the operator creates two agents on all three nodes and installs the
    counter twice in each, at whichever node takes the command;
  - a client calls the first agent through the client library, starting
    at node 1. Every fourth request forwards an amount to the second
    agent's inbox; the rest increment, and each is answered with the
    running total;
  - **two kills,** each with SIGKILL, never overlapping, so a quorum
    stays:
    - the first agent's leader at request 21, right after a forward was
      answered and its message may still be unacknowledged, starting
      again at 31;
    - the second agent's leader at 41, starting again at 51.
    - A leader is found as the node that takes an operator's no-op, a
      revoke of a role no one holds. The client goes on through the
      others.
  - **At the end:**
    - a linearizable read at every node, posted to that node alone (a
      failover would hide one that never caught up), holds the total of
      the increments and the sum of the forwards;
    - then the nodes stop, and every replica's pair marks on disk hold
      each forward once: the receiver's `pair_in` and the sender's
      `pair_out`.
- **The children:**
  - they are killed when the test ends, however it ends;
  - their stdout is read to the end, against a deadline at start;
  - their stderr goes to a log that a failed start prints.
- Seven runs passed in 21–26 s each, with no process left behind.

The checker stays the place for faults and mutations. This test is its
smoke test at the real boundary: the binary, QUIC, and a crash restart.

**Review** (Opus): go, once the end check read every node itself and the
kills caught messages in flight. Both are folded in above, with the
pair marks on disk, the bounded start, the drained stdout and the logs.

Left:
- the children are not tied to the test process with `PR_SET_PDEATHSIG`,
  so a test killed by CI can leave them running;
- a port from the ephemeral range could be taken by a client's
  connection before a restart.

**3.5 is done.** Carried forward, so nothing is lost:
- **3.6:**
  - session collection, the expiry index, the sweep and the caps (state
    grows with every session until then);
  - the checker: `StaleSession` under failures, with a clock beyond the
    skew (it panics on it today, and 3.5c1's B1 lived there);
  - the checker: two clients on one agent (`Known` and `New` in one
    batch), and replay after collection;
  - optionally, a TLS run with pinned clients.
- **3.7:**
  - compaction and snapshots, which must carry the `LastResult` row;
  - creation records resent only by their creator;
  - membership changes;
  - a replica refusing the agent's program still acknowledges its
    record, counts toward the creation's majority, and is listed in
    `Elsewhere`.
- **3.8:**
  - combined heartbeats and quiescence;
  - a restart re-announcing every record to every node;
  - message batching across agents, and fan-in past a receiver's cap;
  - one heartbeat round per linearizable read;
  - the O(tasks) `retain` in the node's `spawn`.
- **3.9:**
  - `Forward` carrying the term (vos-net holds frames across redials);
  - the process test growing into the fault suite;
  - optionally, fast retransmit on a dropped gap.
- **Step 5:** `#[msg(linearizable)]`.
- **Unscheduled:** seq 0 taking a read index.



## Step 3.6: sessions

### Design

3.5b put sessions in the agent: named by the client, created by
accumulate within the skew of batch time, and never collected. This
step collects them, caps them, keeps a client from running a call
twice once its session is gone, and makes the checker meet expiry,
replay and a clock beyond the skew.

**The expiry index** (new system keys):
- **`expiry(bucket, id)`:** one row per live session, its value empty
  (stored, as every value is). A bucket is a time divided by
  `SESSION_BUCKET_MS` (5 minutes), big-endian, so a scan meets the
  oldest first.
- **Written once, at creation,** at the creation time's bucket. A
  request does not move it: the hot path writes nothing more than
  today, and a `Known` step still reads nothing in accumulate.
- **Invariant:** a session's row lies at or before its mark's bucket.
  The sweep moves a row that lags when it reaches it (below), so a
  session active for hours moves once per expiry period, not once per
  request.
- **`key_sessions(key)`:** how many sessions a key holds at this agent,
  for its cap, deleted at zero so a key with no session leaves nothing.
  `live_sessions` (3.5b) counts them all.
- Stores written before this step hold sessions with neither; they are
  development stores, and are discarded.

**Collecting** (the plan's rule): a session goes once it has expired
after inactivity, and batch time is past its t0 plus the skew.
- **A bucket is due** when every session whose mark lies in it has
  expired: batch time at least the bucket's end plus
  `SESSION_EXPIRY_MS`. Rows there whose sessions were active since are
  moved instead.
- **The t0 rule follows from expiry:** a session was created within the
  skew of its t0 and time never goes back, so its mark is at least t0
  minus the skew. Once it has expired, batch time is past t0 plus the
  skew whenever the expiry is at least twice the skew, which a constant
  assertion holds. Accumulate checks both anyway: it reads t0 to delete
  the index.
- **After collection,** a resend of any of its requests names an absent
  session with a stale t0: ingress rejects it `StaleSession`, refine
  refuses it `STALE_SESSION`, and accumulate would skip it. It never
  runs, and neither does a captured request. Before collection, an
  expired session's next request is refused `EXPIRED`, and one at or
  below its mark is answered from the window, as today.

**The sweep:**
- **`Input::Sweep`:** no payload. The leader puts one **first** in a
  batch whose time makes its first expiry row due, so a batch cut short
  by gas or size never drops it. It reads that row with the version and
  `batch_time`, from the snapshot the batch refines on.
- **An idle leader** reads it when its queue empties and runs the sweep
  alone once the row is due by its effective time (max(clock,
  `batch_time`)). It checks again at least every 5 s while a row
  exists, as a clock stepped forward does not move a monotonic timer.
  A leader opens only after it has applied what it took over, so it
  reads state its predecessors left.
- **Refine** scans the expiry rows in order and lists those due, up to
  `SWEEP_LIMIT` (32), as `Step::Swept { due: Vec<(bucket, SessionId)> }`.
  It reads no marks: accumulate decides. It never traps on the sweep: a
  row whose key is not an expiry key, or whose value was not stored, is
  passed over, and an unreadable page lists nothing.
- **Accumulate, per listed row, leaves it out of the due range:**
  - no mark: the row alone, deleted;
  - expired, and past t0 plus the skew: **collected**. The index row,
    the whole (`session_of`), the mark, the replies it holds
    (`max(1, mark − W + 1)..=mark`, every one present, so no absent key
    is deleted), and the expiry row go; the live and key counts drop. A
    mark without its whole loses what can go without the triple (mark,
    replies, row, live count);
  - otherwise the row moves to the bucket of the later of its mark's
    time and t0 plus the skew, which is not due; nothing is written when
    it is there already (refine listed it early).
- **Progress:** an honest sweep deletes or moves every row it lists.
  When the leader's first due row is the same after a sweep, it adds no
  sweep for a minute and logs it once.
- **Order within a batch:** collection and moves change later batches
  only. A request in the sweep's batch for a collected session is
  refused `EXPIRED` (same time), a new session cannot take a collected
  one's triple (its t0 is stale), and a moved row stays at or before
  its mark when a later step moves the mark.
- **Cost:** one row scan per batch at the leader, one at idle; a sweep
  of 32 sessions with full windows is about 2,200 deletes in one apply.
  Measured in the bench; `SWEEP_LIMIT` and the bucket are constants,
  revisited in 3.10. A backlog (a mass expiry) puts a sweep on every
  batch until it drains; 3.10 limits their rate if latency shows it.
- Logs and counters carry counts only: no key, session name or id.

**The caps refuse, never evict** (`defaults`):
- `MAX_SESSIONS` (65,536) per agent, `MAX_KEY_SESSIONS` (64) per key at
  an agent: room for a client that loses its session file on every
  restart, or a server with many workers under one identity.
- **Refine** refuses a new session's first request at a cap,
  `SESSIONS_FULL` or `KEY_SESSIONS_FULL` (new refusals), after the skew
  and sequence checks. It counts the sessions this batch creates, in all
  and per key, reading each count once a batch.
- **Accumulate** counts the result's distinct new triples (a new
  session's several requests each name it `New`), in all and per key,
  against the counts before it applies anything, and skips the whole
  result past a cap, as for a stale session: refine refuses, so it was
  not refined on this state.
- **The node:** a refused request consumed nothing, so its lane resets
  and the client may send it again. Ingress answers 503 for the agent's
  cap and 429 for the key's.
- **The client** returns the refusal: a new session would be refused
  too. After an inconclusive attempt it answers `TimedOut`, as for
  `Busy`: the earlier attempt may still create the session.
- **What the caps do not stop:** fresh keys are free, so anyone can fill
  the agent's cap and refuse new sessions for an expiry period. That is
  liveness, not safety, and admission bounds the rate. Rate limits
  without identity are later (the plan's privacy section).

**A call whose fate is unknown, once its session may be gone.** Before
collection, a resend of a call that ran is answered from the window.
Collection removes the window, so a client must not take a refusal of
the session then as proof that the call never ran:
- **`EXPIRED`** stays safe to start a new session on: a call that ran is
  at or below the mark, and answered from the window first. Refine
  checks a duplicate (at or below the mark) before expiry and refuses
  it `SEQUENCE`, so the leader answers it from the window even when it
  reaches refine.
- **`StaleSession { now }` for a call whose fate is unknown** (an
  earlier attempt failed, or the caller says it repeats one):
  - in a session it has had an answer in, the session was created and
    is gone: **`ClientError::Lost`**, final. The call may have run, and
    nothing can say;
  - in a session never answered:
    - `now` at most t0 plus twice the skew: `TimedOut`, as today. Copies
      may still be on their way, and a leader may still create it, or
      will once time reaches a t0 that is ahead;
    - `now` past that but within the expiry less the skew of t0: it was
      never created (collection needs batch time past t0 minus the skew
      plus the expiry), and no leader can create it now, as every clock
      is within half the skew of true time (the plan's NTP assumption).
      A new session, and the call goes again;
    - later: `Lost`.
  - `Refused(STALE_SESSION)` carries no time: `TimedOut`, and the next
    attempt meets the lane's `StaleSession`.
- **The CLI** keeps a pending call unknown however old it is: sent
  again, it is always a repeat of an unknown one. On `Lost` it clears
  the pending call and says it may have run. The library documents
  `repeats_unknown` for callers that retry across processes.
- **Queries' clocks:** `StaleQuery` carries the node's time, and the
  client signs a query again once, with its `not_after` moved by the
  difference, as it does for a session's t0.

**The checker:**
- **One clock offset for the whole cluster,** added to every node's
  clock, every session's t0 and every query's `not_after`, so a jump is
  one store. Each node's own ±15 s jump stays on top.
- **Two clients on one agent:** each agent gains a second client, with
  its own key and sessions, incrementing a third instance. Batches then
  mix `Known` and `New` sessions of two keys. It only increments, so
  the forward ring stays one sender per pair.
- **A clock beyond the skew, under load:** the offset moves 120 s ahead
  once, for good: past the skew plus both directions of a node's jump,
  with 30 s to spare, which the checker asserts from the offsets.
  - **`StaleSession` is definitive** for a session timed with an earlier
    offset, on an attempt sent after the jump: every leader's time is
    then past its t0 plus the skew, so no copy can create it. The
    session is timed again (a new name, t0 from the offset) from its
    first request, and the window's later requests follow it.
  - An attempt sent before the jump is sent again unchanged.
  - Any other `StaleSession`, `STALE_SESSION` or `EXPIRED` fails the run.
- **Expiry and replay, once a run:**
  - clients pause at a request boundary until every request is
    answered;
  - each captures a request that ran and one signed but never sent;
  - the offset moves past the expiry plus a bucket; a leader is stopped
    while the sweeps run, and started again;
  - once every replica holds no session row (index, whole, mark, reply,
    expiry, counts), each captured request is posted to every node:
    `StaleSession` or `TimedOut`, never `Ran`; then every counter at
    every replica is still its total;
  - clients resume, each in a new session.
- The end checks stand: every total, and each forward once.

**Tests:**
- **Agent:**
  - creation writes the expiry row and the key count;
  - a sweep before due collects nothing; at due, an idle session goes
    whole and one active since moves;
  - `EXPIRED` before collection, `STALE_SESSION` after, and a new
    session's id is never reused;
  - each cap at its edge, counted within a batch; a collection frees
    room;
  - accumulate skipping a hand-built result past a cap, and moving or
    deleting hand-listed rows (not due, no mark, no whole);
  - refine passing over a malformed row;
  - more due rows than `SWEEP_LIMIT` take two sweeps;
  - **a property test** of the session life cycle against a model: keys
    from a small pool, t0 near or far, sequences with gaps and
    duplicates, time moving a little or past expiry, and sweeps. After
    every batch every session row and count equals the model's.
- **Node:**
  - a busy leader's batch carries the sweep once due, and an idle one
    sweeps alone after its clock steps forward; every replica's session
    rows are equal;
  - **a lost answer, over HTTP with test clocks:** a call runs and its
    answer is lost. Past expiry but before its bucket is due, the resend
    is answered from the window. Past collection, the client's retry
    ends `Lost`, and the call ran once. A first call in a session never
    created, retried after twice the skew, runs in a new session once.
- **Mutations,** each to be caught: creation without the skew check (in
  the agent: the resend after collection runs); collection without
  moving rows (an active session collected); a count not decremented;
  no idle sweep; the CLI's old in-transit window (the lost answer runs
  twice).

**Not in 3.6:**
- caps or expiry set per agent: constants until an operator needs them;
- a TLS run of the checker with pinned clients (3.9's fault suite);
- rate limits without identity (later).

**Review** (Opus): no-go until a client could no longer run a call twice
once its session was collected: the CLI then renewed after its
in-transit window, and the call ran again. Folded in above: the client's
rules for a call whose fate is unknown, and `Lost`. Also folded: the
sweep first in its batch; every listed row leaving the due range, with
a pause when a sweep makes no progress and no trap on a bad row; the
idle check every 5 s; one cluster offset and a 120 s jump with its
margin asserted; `StaleQuery` with the node's time; distinct triples;
discarded old stores; counts only in logs; the stored empty row; and
the checker's totals after the replays. Re-review: go, with the renewal
bound one-sided (a t0 ahead of the agent's time waits) and refine's
duplicate check before expiry, both folded above.

#### Built

- **The wire** (`vos-wire`):
  - `expiry(bucket, id)`, `expiry_prefix`, `expiry_entry` and
    `key_sessions(key)` under `SYSTEM`; `vos_wire::expiry::{bucket, due}`;
  - `defaults`: `SESSION_BUCKET_MS` (5 min), `SWEEP_LIMIT` (32),
    `MAX_SESSIONS` (65,536), `MAX_KEY_SESSIONS` (64), and the assertion
    that the expiry is at least twice the skew;
  - `Input::Sweep`, `Step::Swept { due }`, `refusal::SESSIONS_FULL` and
    `KEY_SESSIONS_FULL`, `Rejection::StaleQuery { now }`.
- **The default agent:**
  - refine checks a duplicate before expiry, then the skew, the
    sequence and the caps (`Counts`: the applied counts read once a
    batch, plus the batch's creations);
  - refine's sweep lists due rows by key alone, page by page, passing
    over keys that are not expiry keys; values are not read, so it never
    traps;
  - accumulate counts a result's distinct new triples against the caps
    before it applies anything, creates a session with its expiry row and
    key count, and per listed row deletes it (no mark), collects the
    session (expired, past t0 plus the skew) or moves the row to the
    bucket of the later of its mark and t0 plus the skew.
- **The node:**
  - `Pending::Sweep`; the leader reads the first expiry row with the
    batch's state and puts a sweep first in a batch it is due for;
  - idle, it sweeps alone once due by its effective time, and looks
    again at most every 5 s while a row exists;
  - a sweep that applied, or failed alone, leaving the first due row in
    place pauses sweeps for a minute, said once in the log (counts
    only); a read error when idle means looking again in 5 s;
  - a duplicate refined `SEQUENCE` whose session the batch's sweep
    collected is answered from the state the batch refined on;
  - ingress answers 503 for `SESSIONS_FULL`, 429 for
    `KEY_SESSIONS_FULL`, and a stale query with the node's time.
- **The client:**
  - `ClientError::Lost`, and `Fate::{InTransit, NeverRan, Lost}` for a
    call whose fate is unknown that meets `StaleSession`;
  - `EXPIRED` renews and clears the doubt; `Refused(STALE_SESSION)` and a
    cap refusal answer `TimedOut` when in doubt;
  - a query's `not_after` is by the client's clock, moved by the offset
    it learned, and signed again once on `StaleQuery { now }`.
- **The CLI:** a pending call is kept by its digest alone, always sent
  again as a repeat of an unknown one; `Lost` clears it and says the call
  may have run; refusals of the caps are named. A kept file with a line
  it cannot read is refused, not dropped, as it may hold a pending call;
  the earlier pending line, with its time, still reads. A new call says
  when it leaves an unanswered one unknown.

**Found while testing, and fixed:** an idle leader whose sweeps paused
looked again every millisecond for the minute of the pause; it now waits
out the pause. And an idle sweep yields to the node's other tasks first:
were the leader's two reads of the first row to disagree (a clock
stepped back between them), it would otherwise spin without yielding.
Both showed as hangs under mutations.

**Tests:**
- **Agent** (`tests/agent.rs`):
  - collection and moves: a session's whole state goes once its row is
    due, a session active since moves, `EXPIRED` and a duplicate's
    `SEQUENCE` before collection, `STALE_SESSION` after, ids never
    reused, and the moved row collected in its turn;
  - the caps at their edges within one batch, the agent's from a seeded
    count, and collection making room again, at most `SWEEP_LIMIT` a
    sweep;
  - accumulate on hand-built results: past a cap nothing applies, one
    session named twice counts once, a row listed early stays, a row
    without its session goes, a session without its whole loses the
    rest;
  - refine passing over a key that is not an expiry key;
  - **the life cycle against a model** (64 cases): after every batch,
    every session row and count equals the model's.
  - The test node prepares the agent once a run: the suite went from
    53 s to 11 s with these tests in it.
- **Node** (`tests/ingress.rs`): a lost answer answered from the window
  past expiry, then `Lost` past collection, the call run once; a first
  call in a session never created: `TimedOut` within twice the skew, run
  once in a new session after; `Lost` past the expiry less the skew; a
  busy leader's batch collecting an expired session; queries signed
  again at a node's time ten minutes ahead.
- **CLI** (`tests/cli.rs`): a node in the test process with the test's
  clock; a call whose answer is lost as the node stops stays pending;
  back past its session's collection, `vos` says it is lost, forgets it,
  and the counter shows it ran once.
- **The checker** (`tests/exactly_once.rs`):
  - one clock offset for the cluster; six clients, a second at each
    agent on its own counter; each client times its next session ahead;
  - every clock 120 s ahead under load: every run times sessions again
    (asserted), and some attempts sent before the jump go again;
  - every session expiring, with a leader stopped while the sweeps run:
    every replica holds no session row, captured requests run nowhere,
    and every counter is unchanged;
  - the second clients start a session every 4 or 8 requests, each
    with a fresh key: under one key they met its cap of 64 within a run,
    as they should;
  - a failing check ends the clients and readers rather than leaving
    them paused; ingress ports lie below the ephemeral range, so no
    client's connection takes one while its node is down;
  - 24 seeds (101–112, 201–212) pass in both modes, about 20–25 s each.
- **Mutations, each caught:**
  - agent: rows never moved; the key count never decremented; creation
    without the skew check (the resend after collection runs); expiry
    checked before a duplicate (the property test, and the collection
    test);
  - node: no idle sweep; no sweep in a busy batch (the ingress and CLI
    tests);
  - client: a lost call sent again in a new session (it runs twice);
  - CLI: a pending call not marked unknown (it runs twice);
  - checker: no skew check anywhere (a captured request runs, caught at
    once); a stale session refused while its first call is queued (the
    B1 bug of 3.5c1: a client's total off in 2 of 4 seeds, and always
    by its focused test).

**Cost** (acceptance bench on a space of one, alternating with the 3.5d2
tree on the same disk; each bench session now has its own key, as one
key's 256 sessions would pass its cap):
- under load: 31.4–36.2 µs per request against 32.7–35.0, execution
  24.7–26.9 against 25.7–27.3 µs, commits about 1 ms both;
- one request alone: a 2.9 ms median both; queries 50–60 µs both.
- The agent program grew from 274 to 324 KiB.
- A first comparison showed commits twice as slow: the earlier tree was
  under `/tmp`, a tmpfs, where a sync costs nothing.

**Review** (Opus): go, with no path found that runs a call twice.
Folded in before the commit:
- the CLI refused to drop a kept file it cannot read: dropping it wiped
  the pending call with the session, and the call could then run twice;
- the sweep pause starts once a sweep applied, or failed alone, not when
  one is added: an agent fault elsewhere in its batch, or a skipped
  result, delayed collection by a minute;
- an idle leader's read error looks again in 5 s instead of waiting for
  an input;
- a duplicate in the batch that collects its session is answered from
  the window it was refined on;
- a missing key count is not deleted;
- a new call says when it leaves an unanswered one unknown.

**Left for later:**
- the checker catches the B1 mutation in about half its seeds; its
  focused test always does;
- caps and expiry per agent, a TLS run of the checker (3.9), and rate
  limits without identity, as the design says.

**3.6 is done.** What 3.7–3.10 carry stands in the list at the end of
3.5.


## Step 3.7: snapshots and catching up

### Design

The pieces exist: vos-raft asks for compaction (`CompactBound`) and for
a snapshot (`SendSnapshot`), and switches to one it is given
(`snapshot_switch`, `snapshot_installed`); the store exports an agent's
state at its own applied index, stages rows under another epoch and
switches in one synced batch (3.3c); a test harness in `raft.rs` ships
snapshots through them. The node ignores both actions today: logs grow
without bound, and a replica that falls behind the log's start, or a new
one, cannot catch up. Split in two:

- **3.7a:** compaction on every replica, and snapshots streamed to a
  replica that needs one;
- **3.7b:** replacing a replica, through a membership change, with the
  directory following it.

#### 3.7a Compaction and snapshots

**Compaction, on every replica:**
- On `CompactBound { through }` the group compacts to a point P: `through`
  less a tail of 256 entries, so a follower a little behind still gets
  entries, not a snapshot, and never past the lowest index of a snapshot
  it is streaming (its follower needs the entries after it). The
  writer's `Compact` change records the configuration in effect at P
  (`core.config_at(P)`, not the action's, which is for `through`), then
  `core.compacted(P)`. The core emits a bound only after
  `compact_hysteresis` entries (1,024 here, a constant), and never past
  the durably applied index or a retiring configuration.
- Blobs only compacted entries named are collected, as 3.3b provides.

**A snapshot, from the leader:**
- On `SendSnapshot { to }` the leader exports its state at its own
  applied index A (term T there), with the configuration in effect at A
  (`core.config_at(A)`). That is committed state, at or past the
  snapshot index the core asked for, and the follower acknowledges A.
- **The manifest,** in the first chunk:
  - (A, T) and the configuration;
  - the programs the state's installed instances name (pinned blobs);
  - the last result's time and seed (`LastResult`, a node row the
    export reads from the same store snapshot): queries on the replica
    are timed by it.
- **A stream is named by (leader term, A).** Its `SnapshotChunk`s carry
  both, about 1 MiB of rows each, on the bulk class; each is acknowledged
  by `SnapshotAck` (with the same name) once staged. Four go
  unacknowledged at most; an acknowledgement names the next sequence the
  follower wants, and the leader goes on from there (the bulk class may
  reorder frames). The leader takes an acknowledgement only from the
  stream's follower, for its name.
- **One stream per follower, kept by the host:** a `SendSnapshot` while
  that stream makes progress is ignored (the core's own deadline, 60 s,
  is shorter than a large stream, and it asks again on every replicate).
  No acknowledgement for 10 s, or a lost leadership, ends the stream and
  calls `core.snapshot_failed`; the core asks again in time.
- The export holds its store snapshot for the stream's length.

**The follower:**
- takes chunks only from the leader it follows, in its term (3.4b's
  check), into the agent's next epoch;
- **the first chunk of a newer stream** (sequence 0, a name greater
  than the current stream's, by term then index) starts it: the earlier
  stream's staged rows are dropped first (`DropEpoch` until empty), as
  the writer refuses a first `Stage` into an epoch that holds rows. A
  late first chunk of an older stream is ignored. A stream past its idle
  limit (30 s) is dropped the same way;
- only chunks of the current stream are staged, in order; one out of
  order is not, and the acknowledgement says which one is next;
- **after the last chunk:**
  - it fetches the manifest's programs it lacks, from the leader then
    the other replicas (`BlobRequest`), and waits until each is durable;
  - it writes the switch, synced, in one batch: the core's
    `snapshot_switch` rows, the epoch pointer, the applied index A, the
    `LastResult`, and the pins (a `Pin` for every program the new state
    names, an `Unpin` for one the old named and the new does not);
  - then `core.snapshot_installed`, the applier's index moves to A, and
    the old epoch is dropped in the background;
- **refuses** a snapshot at or below its applied index (the writer does
  too).

**What moves with the switch:**
- the group's shared state (`applied`, `recovered`), so waits on an
  applied index (read floors, a forwarder's own-apply wait) see A;
- the applier resumes at A + 1; the writer refuses an apply staged for
  the old epoch;
- nothing else holds applied state: lanes and the leader's marks are a
  leader's, and a follower installs.

**Tests:**
- a cluster with a small hysteresis: every replica's log stays short;
- a follower stopped while the log is compacted past it catches up by a
  snapshot when started, and holds the same state, pins and
  `LastResult`; its queries answer the same;
- a follower that lacks an actor's program fetches it before the switch;
- a stream cut by a leader change, then sent again by the next leader;
- a stream longer than the core's snapshot deadline, not restarted;
- a snapshot under sustained load with a small hysteresis: compaction
  waits for it, and it installs;
- a snapshot taken during a joint configuration, which it carries;
- a replica caught up by snapshot that then leads, and answers a resend
  from its window: sessions, expiry rows and windows came with it;
- crash points: after some chunks (old state, staged rows dropped on
  recovery), after the switch (new state), during the old epoch's drop;
- the checker runs with compaction on, so restarted nodes catch up by
  snapshot under its faults.

#### 3.7b Replacing a replica

**The directory follows the group's membership.** A creation record
never changes (its hash is the agent's identity clients sign for), so
replicas move to a **placement** beside it: `{ agent, replicas, before,
term, index, committed }`. `index` is the log index of the configuration
it reflects (0 at creation, from the record), `before` the configuration
it supersedes, `term` the term of the leader that announced it, and
`committed` whether that configuration had committed.
- **Placements are ordered by (term, index, committed).** A new leader's
  announcement supersedes anything from an older term: a joint
  configuration announced by a leader that failed before it reached a
  majority is replaced by the next leader's, even at a lower index, and
  late messages from a deposed leader are ignored. Ordering by index
  alone let such a phantom outrank the real configuration for good.
- Every node keeps, per agent, the record and the greatest placement it
  has heard of, durably. The replicas everything reads today (routing,
  a replica's checks, `Elsewhere`, `agent_info`) come from it.
- During a joint configuration, the placement lists both sets: either
  may send, and messages may go to either.
- **Routing uses the greatest placement,** committed or not: a joint one
  is a superset, and a message to a would-be replica fails over or is
  sent again. **Checks of who may send** accept, while the greatest
  placement is uncommitted, the nodes of `before` too: under an
  uncommitted final placement the replica it leaves out may still lead.

**Who says so:** the agent's leader, whenever a configuration entry is
appended or committed, sends `Placement` to every node in the space
until each acknowledges it. A new leader announces its latest
configuration, and announces it again, committed, once its commit index
passes that entry: retirement waits for a committed final placement.
3.8's batching should cover the burst of placements a wave of elections
sends. The record travels with it, so a node that missed the
creation learns the agent too, and records are no longer sent only by
their creator. A placement is taken from a node named in it or in the
configuration it supersedes (a leader removing itself), or from the
record's creator at index 0.

**The operator's command:** `vos agent replace --agent A --remove X
--add Y` (`POST /agents/{id}/replicas`, with the operator's token) at the
agent's leader (a redirect otherwise):
- checks: X a member, Y not, Y in the space, no change in progress, and
  **Y can run the agent:** the leader first sends Y the current
  placement, and Y's acknowledgement says whether it could run the
  agent's program (its own is the record's), since it runs no group yet;
  otherwise the replacement is refused before anything is proposed;
- `core.change_membership` with X replaced by Y: the joint
  configuration is appended, and the core finalizes it once it commits;
- answered once the final configuration commits, or `TimedOut` after a
  bound (the change goes on; the placement says where it is).

**The new replica:**
- learns a placement naming it and starts the agent's group, as a
  member of the configuration *before* the change (`before`), so its
  core is no voter and never campaigns (vos-raft's pre-vote, election
  and `TimeoutNow` paths all check membership);
- **until it has held a committed placement naming it,** a later
  placement that no longer names it (a phantom superseded) stops the
  group and retires the agent. Its data is uncommitted, or held by a
  majority of the old configuration: had the joint entry committed, the
  superseding leader could not have been elected without it. If the old
  leader returns and the joint configuration becomes real again, its
  placement starts the replica again, from its tombstone's term and vote;
- the leader replicates to it: by entries while they last, else a
  snapshot (3.7a), which brings the configuration naming it;
- refuses to start if it runs another agent program (as today), and its
  acknowledgement says so.

**The removed replica:**
- **a member that held a committed placement naming it** retires only
  once it hears of a **committed, final** placement without it, and is
  not leading: under an uncommitted final, a candidate whose log lacks
  the final entry is still elected under the joint rules, and may need
  this replica's vote. It then stops its group and **retires** the
  agent. A removed
  leader steps down as the final configuration commits, announces the
  committed final placement as it does, and retires. Retiring is a writer change: the log, commit index,
  membership and state rows go (the state in chunks, like an old epoch);
  the record, the placement as a tombstone, and the term and vote stay,
  so a replica added again never votes twice in a term;
- a restart leaves a retired agent stopped, and no placement brings it
  back unless it supersedes the one held: one ranking lower does not,
  nor one taking back a commit (a later leader announcing the committed
  configuration before it learns that it committed); Raft messages for it are dropped as unrouted. A
  removed replica that restarts with its old log, before its tombstone,
  cannot disrupt the group: it is no member of the final configuration,
  and pre-vote stays on.

**Availability while the new replica catches up:** the new configuration
counts it, so losing one of the others before it catches up stops
commits until it does. Adding it first as a learner removes that gap;
it is left for later.

**A replica that refuses the agent's program** (a carried item) still
holds the record, but no longer counts as running it: `DirectoryAck`
says whether it runs the agent, and creation waits for a majority that
does.

**Tests:**
- in a space of four, an agent on 1, 2, 3 under load; 3 replaced by 4:
  4 catches up by snapshot, the final placement is {1, 2, 4} on every
  node, 3 holds no state for the agent and does not start it again
  after a restart, clients and messages follow the placement;
- the leader failing during the joint configuration: the next leader
  finalizes it and sends the placement;
- **a phantom:** the leader failing before the joint entry reaches a
  majority; the next leader's placement supersedes it, the would-be
  replica stops, and a retry with another node succeeds;
- the leader replacing itself;
- a placement lost to a node, then resent; an older one ignored;
- a removed replica restarting with its old log: no disruption, and it
  does not start the agent again;
- a new replica that refuses the program: the replacement is refused
  before anything is proposed.
- The checker: optionally a replacement fault, with a fourth node.

**Not in 3.7:**
- adding or removing replicas other than one for one, and placement
  policy (the catalog);
- snapshots by pages or witnesses (step 4);
- combined heartbeats (3.8).

**Review** (Opus): go for 3.7a, no-go for 3.7b until placements were
ordered by the announcing leader's term as well as the index: by index
alone, a joint configuration announced by a leader that failed before
it reached a majority outranked the real one for good, and a retry
landing at a lower index was ignored while its new replica counted in
the configuration. Folded in above: placements by (term, index,
committed), retiring only on a committed final placement and not while
leading, a placement from the configuration it supersedes, Y checked
before the change, the term and vote kept in the tombstone; compaction
held back by a stream in flight and recording the configuration at its
own point; streams named by (term, A), one per follower kept by the
host; and the tests.

**Re-review** (Opus): go for 3.7b. Made explicit above: sender checks
accept `before` while the greatest placement is uncommitted; a new
leader announces again once its configuration commits; the phantom and
committed-final retirement rules apply to different replicas; the
pre-check asks whether Y could run the program.

### 3.7a: compaction and snapshots

#### Built

- **The wire:** a snapshot stream is named by the leader's term and the
  snapshot's index; its first chunk carries a `Manifest` (the
  configuration in effect there and the last result's time and seed);
  `SnapshotAck` names the next chunk the follower wants.
- **The store's export** reads `LastResult` from the same store snapshot
  as the rows.
- **The node** (`Config`): `compact_every` (1,024 entries), `compact_tail`
  (256) and `snapshot_chunk` (1 MiB), which tests lower.
- **The group driver:**
  - reports the writer's durably applied index to its core every round:
    the core's compaction bound never moved before, as nothing told it;
  - compacts to the bound less the tail, never past a snapshot it
    streams, recording the configuration in effect at that point;
  - **streams** a snapshot (a task per follower, at most one): exported at
    its applied index, chunks read on an executor, four ahead of the
    follower's acknowledgement; an acknowledgement that does not move
    sends the chunk it names again, at most once in 2 s (reordered
    duplicates would otherwise multiply), and 2 s with none sends the
    window again; given up after 10 s of silence or with the leadership;
    a stream ends with a chunk of no rows;
  - a stream whose chunks are all staged is **held** until the follower's
    match reaches its index (`Core::match_index`, new) or 60 s pass: it
    keeps compaction from passing the snapshot, and the core asking
    again is not heard, so no newer stream displaces one being switched
    to;
  - **stages** the chunks of the newest stream it hears, in order, under
    an epoch past the current one that holds no rows (one an earlier
    stream left is dropped in the background, in chunks of 4,096 rows,
    never in one batch on the shared writer), acknowledging each; noting
    the programs the staged instances name (from the rows, not the
    leader's word); a snapshot staged whole is switched to, or dropped
    once idle for 30 s, before any newer stream; anything staged is
    dropped once it leads;
  - **switches** once every chunk is staged and those programs are here
    (asked for like an entry's blobs): the core's rows, the epoch, the
    applied index, `LastResult` and the pins (`Pin`/`Unpin` against the
    state before) in one synced commit, under the applier's lock; then
    the core, the entry reports, the shared state, and the old epoch
    dropped in the background.
- **The applier** holds that lock while it applies, and looks again at
  the applied index once it has it: a switch never meets an apply, which
  the writer would refuse, halting the node.
- `Node::snapshots_installed` counts switches, for tests.

**Tests** (`tests/cluster.rs`, nodes compacting every 8 entries, keeping
2, with chunks of 64 bytes):
- every replica compacts its log as it applies;
- a follower down while the log is compacted past it catches up by a
  snapshot under load: the same rows, last result and pins, the program
  it missed, queries that answer the same, no epoch left behind;
- such a replica, once it leads, answers a call from its window;
- a snapshot cut short by its follower stopping, then by its leader
  stopping, is sent again and installs;
- a snapshot waits for the programs it names: while every node withholds
  blobs, the follower stages but does not switch.
- **The checker** compacts every 64 entries (keeping 16, chunks of 4 KiB):
  14–18 snapshots install per run under its faults, and a run asserts at
  least one.
- **Mutations, each caught:** no snapshot sent; no last result in the
  switch; no pins; the durably applied index not reported (nothing
  compacts); a switch that does not wait for its programs (only by the
  test that withholds them: otherwise they arrive a moment later).
- 24 checker seeds (101–103, 301–312 and others) pass in both modes.

**Cost:** the acceptance bench is where 3.6 left it (33.1–33.6 µs per
request, commits about 1 ms, a lone request 2.9 ms); it never reaches a
compaction, at 1,024 entries.

**Not tested:** a stream outlasting the core's own snapshot deadline
(60 s); a snapshot holding a joint configuration, which 3.7b's tests
bring.

**Review** (Opus): go. Folded in before the commit: a stuck
acknowledgement sends one chunk again, not the window; a stream held
until its follower switches; staged rows dropped in the background, a
new stream staging into an empty epoch instead.

### 3.7b: replacing a replica

#### Built

- **The wire:**
  - `Placement { replicas, before, term, index, joint, committed }`,
    ordered by `order()` (term, index, committed), with `admits(node)`
    (a replica, or one of `before` while uncommitted), `created(record)`
    and `supersedes(held)`: it ranks higher and takes back no commit (the
    same index uncommitted, or an earlier one, never replaces a committed
    placement);
  - `PeerMessage::Directory { record, placement }` replaces the record
    alone; `DirectoryAck` carries the order it was sent (the node holds
    that placement or one superseding it) and whether the node could run
    the agent's program;
  - the operator's `Replace { remove, add }` (`POST
    /agents/{id}/replicas`), answered `Placed(replicas)`, `Unplaced(why)`
    (not a replica, already one, not in the space, a change in progress,
    cannot run) or `TimedOut`.
- **The store and writer:** a placement row per agent (node-wide, read at
  start); `Change::Placement`; `Change::Retire { agent, epoch, hard }`,
  which drops the log (from its start), applied index, log start,
  membership and last result, moves the state to an epoch holding no rows
  and keeps the term and vote. The writer refuses a retirement into the
  current epoch or one holding rows (a snapshot staged there would
  become a replica's state if it were added again), and resets the
  agent's state and its durably applied index with it: a stale one would
  let a replica added again compact past what it applied.
- **The node:**
  - the directory holds `Known { record, placement }`; routing, the
    checks of who may send, `Elsewhere`, `agent_info` and blob requests
    read the placement;
  - `reconsider` starts a group where the placement names the node (as a
    member of `before` without itself, after creation: never a voter
    until its configuration arrives), and retires it where it no longer
    does: at once while not established, else on a committed final
    placement while not leading;
  - `retire_agent` stops the group, then writes the retirement, into an
    epoch no snapshot staged in, and the unpins of the programs its state
    named, and drops every stale epoch in the background; a node starting
    with a replica its placement no longer names (a crash cut its
    retirement short) finishes the retirement instead of starting the
    group. Until the retirement is written no group starts for the agent
    (one would read rows the retirement then removes under it), and the
    node then reconsiders it, for a placement naming it again meanwhile;
  - a placement row that cannot be read leaves its agent unrun until a
    placement comes, rather than taken for its creation's, which could
    retire a replica added later;
  - `place` keeps a placement the node's leadership gives when it
    supersedes the one held, acts on it, and announces it to every node
    until each acknowledges it (the record with it); `on_directory` keeps
    one it hears that supersedes the one held, durably, and acknowledges;
    a creator re-announces at start only the placement of the creation
    (term 0);
  - creation counts toward its majority only the replicas that could run
    the program;
  - `replace`: at the leader, after the checks and `could_run` (the
    current placement sent to the new node until it says), a
    `ChangeMembership` through the group, from the replicas the directory
    holds, which the driver refuses as in progress unless they are the
    core's own configuration (just after an election the directory may
    trail it); answered once a committed final
    placement past the joint index is held, or after 30 s (2 s once the
    node no longer leads: a leader removing itself steps down as the final
    configuration commits, and says so as it does).
- **The group driver:** the members a core starts with come from the
  placement; at start and each round it notes when the replica holds a
  committed configuration naming it (`established`), and, leading,
  announces a placement whenever its order changes: on election, on a
  configuration appended, and once it commits. A leader the committed
  final configuration removes announces that placement as it steps down,
  rather than leave it to the next election; a replica that stops leading
  asks the node to reconsider, so a removed leader retires. A placement
  not kept is announced again the next round.
- **Removed voters are released:** vos-raft's leader waits for each
  voter a change removed to acknowledge the committed final
  configuration, then appends a confirmation; until that commits it
  takes no further change and compacts nothing past the configuration
  before the final one. Here the removed replica learns of its removal
  from the directory: the leader announces it to every node until each
  holds it (one that is down once it returns; if the announcer stops
  first, the next leader announces on its election), and it retires at
  once, so its group
  never acknowledges: the leader would wait for good, and the log grow
  without bound. Each round the leading driver releases them
  (`Core::release_retiring_voters`, new: it counts every removed voter
  as acknowledged once the final configuration has committed).
- **The CLI:** `vos agent replace --agent A --remove X --add Y`.

**Found by the checker, and fixed:** a node shutting down started a
group again, and then waited for it for good. Its runs were taken out of
the node first; a stopping driver's last change of role then asked the
node to reconsider the agent, which, named and running nothing, started
a new group, whose tasks no runtime polled any more. A node shutting
down now reconsiders nothing, a stopped driver does not ask, and a group
starts under the runs' lock only while the node is not closing, which
the shutdown sets under the same lock: one that checked just before
could still slip in. And a node's shutdown ran once more when the node
was dropped, after its runtime had stopped, waiting to cancel tasks a
stopping driver had spawned meanwhile (an old epoch's removal): no
runtime would ever run them. A shutdown now runs once, and a node
closing spawns nothing (what it would do happens at the next start).
Each race showed about once in thirty to a hundred runs, the checker's
clients piling sessions on one key meanwhile until its cap refused
them.

**Tests** (`tests/cluster.rs`, four nodes):
- a replica replaced under load: the new one catches up, every node holds
  the final placement, the old one keeps no state or log and stays
  stopped after a restart;
- the leader replacing itself: it retires, and a new leader goes on;
  with elections as slow as a deployment's (2.5–3 s), it is answered
  before the next one;
- **a phantom:** the leader cut off from its followers announces a joint
  configuration that reaches only the node it adds, which starts the
  group; the next leader's placement outranks it and that node retires;
  the same replacement at the next leader succeeds;
- the leader cut off as it appends the final configuration: the others
  finish the change;
- a replica down while replaced comes back with its old log: no election,
  and it retires once it hears;
- a node that cannot run the program is refused before anything changes;
- a retirement cut short: a stopped replica given the final placement
  that drops it, then started cut off from every node, retires on its
  own;
- the writer refuses a retirement into the current epoch or one holding
  rows (`storage.rs`);
- after a replacement the group compacts again and takes the next
  change: the leader replaces itself, then its successor replaces
  another replica (five nodes, compacting);
- a replica down for good, replaced: the group compacts and takes the
  next change without it;
- a retired leader keeps its committed placement when a later leader's
  arrives for the same configuration, uncommitted and naming it among
  the nodes before: it does not start the group again;
- placements' order, `supersedes`, the checks of who may send, and of
  who may announce (`tests/peer.rs`);
- a voter removed while down holds the leader's next change until the
  host releases it, which lets it through (`vos-raft`,
  `tests/simulated.rs`).
- **Mutations:** ordering by index alone (four tests fail); no new
  announcement once a configuration commits (four); no check that the
  new node can run the program (one); no announcement by a removed
  leader stepping down (the slow elections' test); no retirement
  finished at start (the one cut short); a retirement into an epoch
  holding rows (the writer's test). Not caught: dropping the phantom
  rule (here the next leader's placement is committed and final, so the
  other rule retires the phantom's replica too); retiring while leading
  (a removed leader's core steps down as the final configuration
  commits, so it never holds that placement while it leads); and a
  restarted replica not established until its first round (only a
  placement dropping it, heard in that moment, shows it). All three
  stay, as guards.
- **Mutations of the second review's fixes:** no release of removed
  voters (both new compaction tests fail); placements replaced by order
  alone (the retired leader's test, and the self-replacement in it then
  times out, its committed placement taken back; the `supersedes`
  test). Not caught, and kept as guards: a group starting while its
  retirement is unwritten (a narrow race), and a change from members
  the directory holds that the core no longer does (just after an
  election).

**Not in 3.7b:** a replacement fault in the checker (3.9's fault suite);
learners (the gap while the new replica catches up).

**Review** (Opus): go, with four things folded in before the commit. A
retirement moved the state to the next epoch, which could be one a
snapshot had staged rows in: a replica added again would have taken
them for its state. It now goes to an empty epoch, and the writer
refuses any other. A crash between the placement that drops a replica
and its retirement left the replica's rows for good; a node now
finishes such a retirement when it starts. A leader removing itself
left the final placement to the next leader, whose election can take
longer than the 2 s its answer waits once it steps down (1.5–3 s by
default); it now announces the placement as it steps down. And a
restarted replica counted as not established until its group's first
round, so a placement heard meanwhile could retire it; it now counts as
established from the configuration it recovers.

**Second review** (Sonnet, on the folds; the Opus reviewer had reached
its weekly limit): go, with one blocking finding, confirmed by a test
before the fix. vos-raft's leader waited for every removed voter to
acknowledge its removal, and the removed replica, retired as soon as
the directory told it, never did: after any replacement whose removed
replica retired first (always, once the leader removed itself) the
group compacted nothing more and refused every further change. The
directory delivers that finality, so the leader now releases removed
voters once the final configuration commits; that also keeps a replica
down for good from holding the group. Folded in with it: a committed
placement is never replaced by a later leader's announcement of the
same configuration uncommitted (it restarted the retired leader's group
on a wiped store); no group starts while a retirement is unwritten; an
unreadable placement row leaves its agent unrun instead of retiring it;
a replacement's members are checked against the core's own
configuration; a creator re-announces only the creation's placement; a
placement not kept is announced again; comments and this log brought in
line with the code.

**3.7 is done.** Carried forward, beside what 3.5's list gives 3.8 and
3.9:
- **3.8:** every election announces a placement to every node, and
  every node acknowledges it: with many agents, one leader change per
  agent is one round to the whole space. A replacement announces up to
  four (joint, final, and the confirmation uncommitted then committed),
  each a synced commit on every node.
- **3.9:** a replacement among the checker's faults; a snapshot stream
  outlasting the core's own deadline (60 s).
- **Unscheduled:** learners, so a new replica catches up before it
  counts toward a majority.


## Step 3.8: many active agents

### Design

**Where it stands.** A new bench (`benches/agents.rs`) runs three nodes
in one process over QUIC on localhost, each on its own data directory,
with the default timeouts (elections 1.5–3 s, heartbeats every 500 ms).
On the reference laptop (22 hardware threads):

| Run | Result |
|---|---|
| 64 agents × 4 sessions, closed loop at each leader | 10–13k commits/s, p50 20–24 ms, p99 30–45 ms, 12 cores busy |
| 64 agents × 16 sessions | 29k commits/s, p50 37 ms, p99 61 ms, 12.5 cores |
| 1,064 groups per node, idle | 56% of one core for the three nodes; 90 threads |

- **Active:** the process is CPU-bound, and the PVM takes most of it.
  - The latencies are closed-loop at saturation: sessions divided by
    throughput, not service time.
  - 60% of samples are on the executors: 22 per node, so 66 threads on
    22 hardware threads. 28% is JIT code; the rest is machine setup and
    teardown (page permissions, dirty pages, resets), overstated perhaps
    by 66 threads sharing one process's memory map.
  - Store point reads take 11%.
  - A batch runs refine and a dry-run accumulate on the leader, and
    accumulate on every replica (section 2). With few sessions per agent,
    batches hold a few inputs, so the fixed cost per batch dominates.
  - The budget itself is 3.10's ("pipelined refines, if needed, come
    there"); 3.8 measures the curve, so 3.10 knows early whether it
    needs them.
- **Idle:** 62% of samples are in the network thread (QUIC frames, one
  heartbeat per group per follower every 500 ms). 36% is in group
  drivers: timers and wakeups, two per group per heartbeat.
- **Writer batching across agents** is in place since 3.3a: the writer
  takes every commit queued into one batch and one sync. The bench
  reports commits per sync.

Split in two:
- **3.8a:** pair heartbeats, and group timers they vouch for;
- **3.8b:** the active path measured, scheduling under load, and the
  carried items.

#### 3.8a Pair heartbeats, and group timers they vouch for

An idle group sends nothing; its timers stay, re-armed from what the
node-wide heartbeat says. A group never parks without a timer: whatever
fails (the pair heartbeat, a node's table, a stopped or stalled group),
it falls back to Raft's own timing, not to a group stuck asleep.

**The pair heartbeat.**
- Every node sends every other node of its space one
  `Liveness { incarnation, round, leading }` per heartbeat interval, on
  a thread of its own (`vos-liveness`), which also takes the liveness
  frames arriving: a busy node thread delays neither.
  - The incarnation is the node's start time in µs, or one past the
    last run's when the clock stands behind it: it is kept in the store
    and written at each start, so a clock stepped back cannot make a
    new run look older than the last.
  - `round` counts within an incarnation.
  - `leading` lists `(agent, term)` for each group the sender leads at
    that term, sent only to peers its placement admits (every node when
    it holds none): 12 bytes a group.
  - A group is left out when its driver is stopped, or has not gone
    round in two election timeouts (an idle leader goes round at least
    once per check-quorum window): a wedged driver stops being vouched
    for.
- A node whose writer is stalled lists no group.
- A node that halted sends no heartbeat.
- A long list goes in several frames of one round, 4,096 groups each,
  within the liveness frame's 64 KiB.
- `LivenessAnswer` goes: the other side's own heartbeat is the answer.
- The node keeps a **peer table** (`vos_raft::pair::PeerTable`, which
  the simulator uses too): for each peer, when it was last heard, the
  `(incarnation, round)` last taken, and for each group it listed, the
  term and when it last listed it.
  - A heartbeat below the last `(incarnation, round)` taken is ignored
    (equal is another frame of the same round), so a late frame changes
    nothing. A new run's first heartbeat forgets what the last listed.
  - A group a peer stops listing ages out of the window a vouch
    accepts. No frame of a round needs the others.
  - The table holds facts only. It raises no events and wakes no group;
    drivers read it when they need it.

**vos-raft:**
- `Config::idle_heartbeats` (true by default; the node turns it off).
  When off, a leader's heartbeat round skips a follower that is caught
  up: it acknowledged the last index and an append carrying the commit
  index (answers echo the commit they answer), nothing is in flight to
  it, and no read waits on a round. It also skips a member whose node
  the host has not heard lately (below). With none left to send to and
  no read waiting, the leader arms no heartbeat deadline, only
  check-quorum's.
  - A proposal still goes out at once.
  - A commit still reaches followers at once (`send_commit`); one lost
    is sent again, as its follower is not caught up until it answers.
  - Whenever a follower stops being caught up (entries or a commit it
    has not acknowledged, an append or a snapshot that failed), the
    leader arms its heartbeat deadline again: each round retries what
    the follower lacks.
  - A read starts its own round as today.
- **A leader that gets a pre-vote from a member** refuses it as today,
  and also sends that member a heartbeat at once: a follower whose timer
  lapsed hears its leader.
- `Core::heard_leader_at(at)`, at a follower: its leader was vouched
  for at `at`. When `at` is later than the last time it heard the
  leader, it takes `at` as that time, and re-arms its election deadline
  to `at` plus a random span in [low, high). Stickiness then holds as
  if a heartbeat had come at `at`.
- `Core::vouch(now, listed, heard)` is what a host calls with its
  table: at a follower, `heard_leader_at` with the time its leader last
  listed the group at the follower's term, if within the election
  timeout's lower bound; at a leader, `peer_alive` for each member heard
  within check-quorum's window, and every other member marked silent.
- A solo group arms no timer at all: no check-quorum, no heartbeats. A
  solo leader that adds members starts check-quorum's window then.

**The driver:**
- **Before any tick a deadline is due for,** whatever woke the driver,
  and before delivering a pre-vote, the driver calls `Core::vouch` with
  the table. A follower vouched for moves its deadline and starts no
  pre-vote, or refuses one by stickiness; one not vouched for runs Raft
  as today. A leader counts the members heard, so one cut off from a
  majority still steps down within the same bound as today.
- The lookups take a read lock on the table and a map lookup per group,
  only when a deadline is due or a pre-vote arrives.

**What an idle group costs.**
- A follower wakes once per election timeout (about every 2 s).
- A leader wakes once per check-quorum interval (3 s).
- No group sends frames.
- For 1,000 groups per node that is about 450 wakes per second, near
  20 µs each in today's profile: about 1% of a core. Add the pair
  heartbeats: two frames per interval per node, with lists.

**Failure cases.**
- **A leader's node dies:** its followers' deadlines, re-armed from the
  last vouch, lapse 1.5 to 3 s after its last pair heartbeat, as after
  its last heartbeat today. They pre-vote, and the others, also
  unvouched, grant.
- **A flaky link:**
  - A lapse needs three heartbeats in a row lost, so a link losing half
    its frames lets one group in eight pre-vote at each lapse.
  - The other follower is vouched for and refuses, refreshing first
    from the table. The leader answers with a heartbeat. No term moves.
- **A cut link:** the cut follower pre-votes once per election timeout
  in each group. The other follower refuses, and the leader hears
  nothing; no term moves. When the link heals, the next heartbeat
  vouches again.
- **A leader's group stopped, halted, stalled or wedged** drops out of
  the list. Its followers' next lapse goes unvouched, and they elect.
- **Both followers unvouched while the leader lives** (its pair
  heartbeats lost or late): one's pre-vote can win the other's grant
  before the leader's answering heartbeat lands, and an election
  follows that was not needed. Safety holds; the pair heartbeat's own
  thread makes it rare. The simulator's chaos includes blackouts of a
  node's pair heartbeat.
- **A member's node is down:** the leader marks it silent and sends it
  nothing; heard again, it is not caught up, so heartbeats start and
  catch it up.

**Tests.**
- **vos-raft core:**
  - with idle heartbeats off, an idle leader sends nothing once its
    follower acknowledged the commit;
  - a lost commit notice is sent again;
  - a lagging follower still gets heartbeats; a silent member gets
    none until heard again;
  - a proposal and a read go out at once;
  - `heard_leader_at` moves the deadline and holds stickiness;
  - a member's pre-vote draws a heartbeat;
  - a solo group arms no timer.
- **Simulator:**
  - the chaos runs with idle heartbeats off and the pair heartbeat
    model through the faulty network, the hosts' tables lost in their
    crashes, and blackouts of a node's pair heartbeat;
  - crashes long enough for deadlines to lapse unvouched;
  - safety as today; after healing the group commits, then its members
    send each other nothing for a second, every member holding the
    leader's commit.
- **Cluster** (in process, over the hub):
  - 1,000 idle groups go quiet: after a settling time, no Raft frames
    cross the hub, only pair heartbeats;
  - a call to a quiet group goes through at once;
  - the node leading many groups stops: every group elects within a
    bound set from measurement;
  - a follower node restarts and catches up;
  - a link losing half its frames for 10 s, then a link cut for 10 s:
    no term moves, every group serves after;
  - a node whose writer stalls stops being listed, and its groups elect
    elsewhere.
- **The exactly-once checker** with idle heartbeats off: its stops,
  cuts and lost frames meet the vouching.
- **Bench:** idle CPU for 1,000 groups per node within 5% of one core
  per node, with idle single-replica agents beside them.

#### 3.8a Built

- **vos-raft:**
  - `Config::idle_heartbeats`. When off, a follower is caught up once
    it has:
    - acknowledged the last index;
    - acknowledged an append carrying the commit (`acked_commit`, from
      the commit an answer echoes);
    - nothing in flight;
    - or a silent node.

    An idle leader skips caught-up followers, and parks its heartbeat
    deadline once it skips them all. `take_actions` re-arms the deadline
    as soon as a follower stops being caught up.
  - A member's pre-vote at a leader draws a heartbeat, and so does
    `probe(node)`, for a member that came back. A probe also drops the
    member's acknowledged commit, so it gets a heartbeat each round
    until it answers.
  - A transfer's target is never caught up, so a lost TimeoutNow goes
    again with its next answer.
  - `heard_leader_at`; `vouch(now, listed, heard)`, which marks the
    members not heard as silent, unless the ones heard (the leader
    with them) make no quorum: then the host may be the one gone deaf,
    and the leader goes on sending.
  - A solo group arms no timer. A solo leader that adds members starts
    its check-quorum window then.
  - `pair::PeerTable`.
  - The simulator:
    - the pair heartbeat model (`pair_heartbeats`), with tables lost in a
      crash;
    - `pair_blackout`;
    - Raft sends counted per pair of nodes.
- **The wire:** `Liveness { incarnation, round, leading }`, with
  `Leading { agent, term }`; `LivenessAnswer` is gone.
- **The node:**
  - `liveness.rs`, on the `vos-liveness` thread. It sends the pair
    heartbeat and takes the liveness frames; dispatch takes them no
    more.
  - What the heartbeat lists:
    - every group the node leads, sent to the peers its placement
      admits;
    - not a group whose driver is stopped;
    - not a group whose driver has not gone round in two election
      timeouts (`Shared::woke`, stamped each round);
    - nothing while the writer is stalled;
    - nothing at all, not even a heartbeat, once the node halted
      (`Inner::halted`).
  - The incarnation is kept in the store (`NodeRow::Incarnation`):
    the clock's µs, or one past the last run's.
  - A peer heard as a new run, or again after a silence of an election
    timeout, is probed (`Local::Probe`) by every group the node leads
    with it. A replica that restarted while its groups were quiet thus
    hears its leaders at once, not at its first deadline.
  - When the writer's stall starts or ends, the thread wakes every group
    the node leads (`Local::Wake`), so it hands over at once.
  - The thread starts again after a panic, logging it, unless stopped
    meanwhile. Its rounds go on across restarts (peers ignore a round
    below the last they took from a run). The table's lock tolerates
    poisoning: a failed pair heartbeat never stops the node's groups.
    The first heartbeat goes at once.
  - The driver turns idle heartbeats off. It vouches before any tick a
    deadline is due for and before a pre-vote, and arms no timer when
    nothing is due.
- **vos-net's hub** counts frames by class and loses frames per link
  (`sent`, `set_link_loss`), for the tests.

**Found while building, and fixed:** a replica added while its group
was idle never caught up.
- The leader's heartbeat deadline was parked.
- The snapshot stream to the new replica failed once, and nothing
  retried it: the next heartbeat round used to.
- The 3.7b test that replaces a replica while it is down caught it in
  two runs of three.
- The fix is the re-arm above. The review's lost-commit case is its
  twin.

**Found by the paired chaos's check for a steady configuration, and
fixed in vos-raft** (from before 3.8, unseen while no run checked that
the group settles):
- A replica that installed a snapshot holding a joint configuration
  kept it, but not the entry that started it. Leading later, it never
  finalized it, and its group stayed joint for good, taking no further
  change. It now keeps that entry pending.
- A leader whose pending entry was compacted away finalizes from the
  configuration in effect:
  - the joint one, when the pending entry is the one in effect;
  - otherwise the final one, pending past it: it goes steady without
    appending the final again, which a recovery would read as a
    retirement's confirmation.
- Recovery took the persisted configuration record over a newer one at
  the log's start, when a crash had lost the record's update. It now
  takes the later of the two, and a joint one stays pending.
- Each has a core test of its own: a replica given a joint snapshot
  finalizes it when it leads; recovery takes the later configuration; a
  recovered joint configuration is finalized by its leader.

**Results** (bench, three nodes in one process):
- 1,004 groups per node, idle, take 4.7% of one core for the three
  nodes, against 56% before: about 1.6% per node, within 5%.
- With the tests' timeouts (elections 40–80 ms), 21 quiet groups whose
  leader's node stopped had new leaders within 68 ms.

**Tests:**
- **vos-raft:** core tests. They cover:
  - an idle leader quiet once its follower acknowledged the commit;
  - a lost commit notice sent again;
  - a lagging follower still heartbeated;
  - a silent member left alone until heard;
  - a read's round;
  - a member's pre-vote drawing a heartbeat;
  - a vouched leader holding stickiness;
  - a solo group with no timer.

  The paired chaos runs come on top: 100 seeds each with and without
  membership churn; long crashes; blackouts. They check safety, quiet
  among the members after healing, and every member holding the
  leader's commit.
- **Cluster:**
  - 100 idle groups go quiet (no Raft frames for half a second, pair
    heartbeats going on), and a call then goes through with no term
    moving;
  - 60 quiet groups elect again when their leaders' node stops;
  - a restarted follower catches up its quiet groups;
  - a link losing half its frames for 3 s, then cut for 3 s, moves no
    term in 40 groups;
  - a node whose writer stalls loses all its groups to other leaders,
    the one waiting on the held write included.
- **The node's own:**
  - a new run's incarnation outranks the last when the clock stands
    behind it;
  - a long list goes in frames of one round.
- **More, from the review:**
  - vos-raft: a probe, a lost TimeoutNow to an idle target, a leader
    hearing no quorum going on sending;
  - the peer table: late frames, a new run, listings forgotten;
  - the chaos runs:
    - after healing, before any proposal could carry them, every
      member matches the leader's last index and commit;
    - the configuration settles;
    - no election while idle (blackouts ended at the heal);
  - a follower node restarted with nothing written meanwhile hears its
    leaders within 32 ms (elections of 1–2 s here);
  - the stopped leader's node, back, is heard as a new run, and every
    group goes quiet again;
  - the quiet tests run elections of 300–600 ms, so a loaded machine
    does not let the pair heartbeat lapse;
  - the flaky link loses 95% of its frames, so vouches do lapse.
- **Mutations, each caught:**
  - no vouch before a due tick: the quiet test and the flaky link's;
  - idle heartbeats left on: the quiet test;
  - no re-arm when a follower falls behind: the silent member's core
    test, and the 3.7b replacement test, again;
  - caught up on a commit sent rather than acknowledged: the lost
    notice's test;
  - silent members heartbeated: their core test;
  - the vouching mutations of the core (follower, leader), and the
    pre-vote heartbeat.
- **Mutations of the review's fixes, caught:**
  - no probe (the restarted follower's test);
  - the transfer target counted as caught up;
  - no rule for a deaf host;
  - each membership fix, by its core test. A compacted joint entry not
    finalized fails the chaos run's steady configuration too. The
    steady route for a compacted final has no test of its own; it is
    reached only when a transfer holds back a final configuration's
    commit until compaction passes it.
- **Not caught alone, and kept as guards:**
  - listing groups while the writer is stalled, and listing a group
    whose driver has not gone round: each covers the other in the
    stalled writer's test, and without both it fails;
  - the wake on a stall flip: with the tests' timeouts an idle leader
    goes round within 80 ms anyway.

**Review** (Sonnet, the Opus reviewer having reached its weekly limit):
- **The design:** the first version quiesced groups outright. It was
  sent back: a leader re-woken by its followers' answers, and groups
  left leaderless by edge-triggered events. It was replaced by
  vouched timers, which fall back to Raft's own timing.
- **The design check** found:
  - idle skipping that trusted a commit sent, not acknowledged;
  - a wall-clock incarnation that a clock stepped back would sink;
  - an unlisted wedged driver;
  - the pair heartbeat sharing the node's thread;
  - the simulator's tables surviving crashes.
- **The diff review:** go, with four fixes folded in before the
  commit:
  - probing a member that came back;
  - heartbeats to a transfer's target;
  - waking leaders on a stall flip;
  - supervising the thread.

  With them came:
  - the rule for a deaf host;
  - a pinned check-quorum;
  - the test gaps above.

#### 3.8b The active path, scheduling under load, and carried items

**Measured with the bench:**
- **A session sweep** (1 to 64 per agent) for commits per second
  against p50 and p99, to find the knee 3.10's "40k/s at p99 ≤ 20 ms"
  needs.
- **A linger and batch-size sweep** (`linger`, `max_inputs`): the
  cheapest throughput lever.
- **Executors per node** set to the machine's share when nodes share
  it, as 3.10's three processes will.
- **Commits per sync.**
- **Fairness:** one hot agent (64 sessions) beside 63 with one each.
  The cold agents' p99 must stay within a bound of their p99 alone. If
  it does not, executors and leader loops take work round-robin across
  agents, not FIFO.
- **A node stopping while it leads 1,000 groups:** the time until every
  group serves again. Every election writes a synced placement under
  the node-wide `recording` lock, so about 333 serialized syncs per
  node. If the time shows it, the lock is striped by agent and the
  writer batches the syncs.
- **A restart with 1,000 agents:** time to serve and CPU, including
  every creator re-announcing its records.

**Fixed:** the O(tasks) `retain` in the node's `spawn`: finished tasks
are dropped by count, not by a scan per spawn.

**Carried to 3.10 with their numbers, or settled:**
- Message batching across agents, and fan-in past a receiver's cap:
  measured with agents messaging across nodes.
- One heartbeat round per linearizable read. A read must join the next
  round to start, never one already in flight: that round's answers do
  not prove leadership at the read's arrival.
- Recovery loading the whole live log is bounded by compaction (3.7a).
- The pair heartbeat vouches only for groups its node leads, by its
  `leading` list.

**Not in 3.8:** pipelined refines and the active-agent budget itself
(3.10); a bench in three processes (3.10's acceptance runs three
`vos node run`).

#### 3.8b Built

**The bench** (`benches/agents.rs`):
- knobs: `EXECUTORS` per node, `LINGER_MS`, `MAX_INPUTS`;
- `HOT`: one agent with many sessions beside the rest, its calls
  reported apart;
- `FAILOVER=1`: the node leading the most groups stops, then starts
  again;
- hooks count the writer's flushes and the committed batches.

**Measured** (three nodes in one process, 22 hardware threads, 64
agents):

| Run | Result |
|---|---|
| 4 sessions each, 22 executors per node (the default: every core) | 12.1k commits/s, p50 21 ms, p99 40 ms |
| 4 sessions each, 7 executors per node (the machine's share) | 15.0k commits/s, p50 18 ms, p99 25 ms |
| 16 sessions each, 7 executors | 33.8k commits/s, p50 30 ms, p99 54 ms; 10.5 inputs per batch, 2.6 batches per flush |
| the same, linger 0 ms / 5 ms (2 ms by default) | 34.4k, p99 91 ms / 32.1k, p99 64 ms |
| the same, at most 32 inputs a batch | 33.6k, p99 57 ms |
| 1 session each, 7 executors | 7.3k commits/s, p50 8.7 ms, p99 12.0 ms |
| the same, the first agent with 64 sessions | the others: p50 9.3 ms, p99 13.1 ms (+9% on their p99 alone); the hot one: 3.6k commits/s, p99 29 ms |
| 1,064 groups per node, idle | 5.0% of one core for the three nodes |
| the node leading 365 of 1,064 groups stops | every group has a leader again 2.56 s later (elections 1.5–3 s): a leader, not yet one that serves, which waits for its no-op to apply |
| it starts again, with 1,064 agents | opens in 0.77 s; 12.6% of one core while its groups catch up |

What the numbers say:
- **CPU sits near 12 cores in every active run.** The machine is
  saturated, and throughput follows the cost of a batch, not of a
  commit. A batch runs the agent program five times: refine and a dry
  run of accumulate at the leader, then accumulate on each replica.
  Each run has a fixed cost of a few hundred µs (machine setup, store
  reads, the JIT's code) beside its inputs'. More inputs per batch
  raise throughput, and the closed loop's wait with it.
- **Executors on a machine the nodes share** should be its share: three
  times the machine's threads cost a fifth of the throughput and half
  again the p99. The default stays every core, for one node per
  machine; 3.10's three processes set it.
- **Linger and batch size** are fine as they are: no linger trades the
  p99 for nothing, and batches never reach the cap.
- **Fairness holds:** a hot agent costs the others 9% on their p99, and
  executors and leader loops stay FIFO.
- **A mass election finds its leaders on time:** 365 groups within the
  election timeout. That does not measure the synced placement each
  election writes under the node-wide `recording` lock: a leader's role
  is known before its placement is written, and placements are written
  off the driver. The lock's cost is the directory's convergence, about
  365 serialized syncs per surviving node here, and more for a node
  catching up after a restart. It stays open, for 3.10 to measure.
- **A restart with 1,064 agents** opens in under a second.

**Fixed:** the node's `spawn` scanned every task it held on each spawn.
Finished tasks are now dropped only once the list has doubled since
the last pruning (unit test: 10,000 short tasks keep the list under
65, running ones are kept).

**Found in CI, and fixed:** the crash test (3.3a) failed a round whose
writer was killed before it reported any append synced: it expected
the first term even then. Nothing reported now owes no term.

**Carried to 3.10, with these numbers:**
- **The active-agent budget** (64 agents, 40k commits/s at p99
  ≤ 20 ms): today 15k at p99 25 ms with four sessions, or 34k at
  p99 54 ms with sixteen.
  - The lever is the fixed cost of an agent program run, and the
    number of runs per batch, not pipelining: the CPU is already full.
  - Candidates: a machine kept warm per agent, the dry run's
    accumulate reused at the leader's own apply, fewer store reads per
    batch.
- Message batching across agents, and fan-in past a receiver's cap.
- One heartbeat round per linearizable read (a read joins the next
  round to start).
- A bench in three processes.

**Opus's review of 3.7b and 3.8a,** which a Sonnet agent had reviewed
while Opus was out of quota: GO-with-fixes for both. One finding was
blocking, a safety bug. It and the rest are folded in this commit:
- **A replica added again voted with an empty log** (blocking).
  - What went wrong:
    - A retirement wipes the log, keeping the term and vote.
    - Release no longer waits for removed voters to learn of their
      removal, and vos-raft never checked a voter's own membership.
    - So a replica removed while down could come back with its old
      configuration and win an election through the vote of a replica
      retired and added again, empty.
    - That leader serves stale state, acknowledges writes the group
      never holds, and halts the node whose log it tries to cut back.
  - The fix: the retirement keeps the last log position the replica
    held (`NodeRow::VoteFloor`), and vos-raft votes, and pre-votes, only
    for candidates whose log reaches its own or that floor
    (`Recovered::vote_floor`). Raft's rule, that a vote honours every
    entry the voter acknowledged, holds across the wipe.
  - The simulator now models retirement:
    - a dropped replica's log and state wiped, its term, vote and floor
      kept;
    - no group until a configuration names it again, then one starting
      empty;
    - leaders releasing removed voters;
    - 400 seeds each in the paired chaos runs.

    Without the floor, seed 1305 commits two entries at one index;
    with it, 800 seeds pass through 2,928 retirements. Core test: a
    wiped replica refuses a vote and a pre-vote to a candidate behind
    its floor, and grants one that reaches it.
- **A replica a committed final placement leaves out retires, even
  while it believes it leads:** it is stale, and an idle stale leader
  hears from no one.
  - The test cuts, on the hub's new per-class cuts, a leader's Raft
    frames both ways and its pair heartbeat to its followers, while it
    still hears theirs.
  - Its followers elect another, which replaces it. The stale one,
    still leading in its own view, retires once the cut heals and the
    committed final placement reaches it.
- **A group starts from the members of its creation record,** the log's
  first configuration, not from the placement's `before`. A creation
  member restarted between a joint placement and its entry could start
  as a non-member, and never campaign.
- **A node resends a placement only while it holds the one it
  announced:** a removed leader no longer resends forever a later
  leader's placement, which the receiver refuses from it.
- **Check-quorum and gray failures:**
  - A member counts through its node's pair heartbeat only while it
    holds every entry, or it has sent any Raft message at this term
    within three times the longer of an election timeout and an
    append's resend (9 s by default).
  - A leader whose frames go unanswered, the node alive but its Raft
    frames lost, steps down. A slow follower, still answering, keeps
    counting.
  - Rules tied to the election timeout alone (holding every entry; the
    matched index moving within two windows) made leaders step down in
    two to four of eight runs of the cluster suite: under its load, a
    follower's answers wait on its fsync and a program's blob for
    longer than the tests' 80 ms windows. The resend timeout is the
    core's own measure of an answer that is late.
  - Core test: a leader whose append goes unanswered steps down, though
    the node is heard.
  - So a gray failure (Raft frames lost, the node alive) leaves the
    groups its node leads without a working leader for about 9–12 s by
    default: the patience, then a check-quorum window. 3.9's deadlines
    for an answer allow for it.
- **A placement is written off the driver** (`Local::Placed`): a driver
  waiting on the node-wide `recording` lock in a mass election would
  stop stamping `woke`, drop out of the list, and draw another
  election.
- **A failed log load is cleared** (`loaded` with nothing), so its peer
  gets entries again.
- **The pair heartbeat restarts after 100 ms,** not a second: every
  group it leads is unvouched meanwhile.
- **Mutations:** each caught:
  - the floor dropped from the simulator's retirement (seed 1305);
  - the floor ignored in votes (its core test);
  - pair liveness counting every member (the gray failure's test).

  - a leader kept on a committed final placement (the stale leader's
    test).

  Not caught, and kept as guards:
  - a group seeded from `before`;
  - a placement resent whatever order the node holds;
  - a failed load left in place.
- **The pair heartbeat's restart** waits 100 ms, doubling while it keeps
  failing, to 1 s.
- **Carried:**
  - the confirmation entry, pure cost once the host releases removed
    voters (3.10);
  - a gray failure's deposition at node level: the core's test only.

**3.8 is done.** What it leaves for 3.9 and 3.10 is in the lists
above and in 3.7's.



## Step 3.9: faults across processes

### Design

The checker (`tests/exactly_once.rs`) runs its faults on nodes in one
process: cheap, seeded, and blind to everything below the node API.
3.9 runs faults on real `vos node run` processes over QUIC:
- kills and restarts, and pauses (SIGSTOP);
- partitions, lossy links and gray failures between processes;
- slow, stalled and failing disks;
- clock jumps;
- replicas replaced.

Through all of them every client is answered exactly once, and the
replicas agree. 3.5d2's three-process test grows into it. Split in
three:
- **3.9a:** the harness, the relay, and faults in the binary;
- **3.9b:** the fault suite, in the clear and over TLS, on the checker's
  model;
- **3.9c:** `Forward` carrying the term, and a snapshot stream outlasting
  the core's deadline.

#### 3.9a The harness, the relay, and faults in the binary

**Binding apart from the address listed.** `vos node run --peer-bind
<addr>` binds the QUIC endpoint there; the space still lists the
address peers dial. This is useful on its own, for a node behind
port forwarding or in a container. Here it puts a relay in between.

**The relay** (in the test process, on a thread of its own).
- **The forwarding:** for each node, a UDP socket at the address the
  space lists forwards datagrams to the node's bound address, and the
  node's replies back to their sender.
  - One socket per sender stands for it toward the node, as a NAT does.
    It is kept for the whole run, so the node never sees a sender's
    address move.
  - A sender is known by its source address: each node sends from the
    one socket it binds.
- **Two kinds of fault, as vos-net runs one connection per direction of
  dialing:**
  - a *connection* cut: all datagrams of the connection node A dialed
    to node B, both ways, are lost. B's messages to A go on, over B's
    own connection. That is one-way message loss.
  - a *link* fault: the datagrams from A to B, of both connections, are
    lost in part, delayed, or all lost. This cuts the acknowledgements
    of the other direction's connection too, so a full link cut is a
    partition both ways.
- **Practicalities:**
  - receive buffers of 64 KiB, as QUIC may probe large datagrams on
    loopback;
  - a large `SO_RCVBUF`;
  - errors from a killed node's port ignored;
  - the relay's own drops counted, so a run can tell them from the
    faults it injects.

**QUIC's idle timeout** (30 s) is lowered for the suite by a startup
setting, so cuts of a few seconds outlast it. Some cuts outlast it
anyway: idle timeouts, redials and frames held across them are the
point of the real network.

**vos-net holds no liveness frame across a redial:** one held through a
cut would arrive after the heal and vouch, as fresh, for what its
sender led before.

**Faults in the binary,** behind a cargo feature (`faults`, on
vos-node and vos-cli). Production builds carry none of it.
- With the feature, `VOS_FAULTS=<file>` names a control file. A thread
  of its own reads it every 50 ms, never the writer's. Each line is a
  fault:
  - `delay_commits <ms>`: each writer flush waits that long first;
  - `hold_commits`: no flush until the line goes;
  - `fail_commits before` and `fail_commits after`: flushes fail, as
    on a full or failing disk, which halts the node.
    - `before`: before the batch is written.
    - `after`: once it is written but before its sync: the data may
      survive the kill in the page cache, which Raft must tolerate (a
      write reported failed that persisted is harmless).
  - `clock <ms>`: the node's clock runs that far ahead, or behind;
  - `drop <class> <per million> [to <node>]`: frames of one class lost
    above QUIC. That is a gray failure (consensus lost while the pair
    heartbeat flows) or the reverse.
  - `quic_idle <ms>`: QUIC's idle timeout, read at start.
- **The clock fault covers the node's clock** (`Config::clock`): batch
  times, sessions, queries' staleness.
  - Blob ages move to the monotonic clock within a run. A wall-clock
    jump forward must not age a blob stored ahead of its entry past
    collection's horizon.
  - The incarnation stays on the wall clock, kept monotonic by the
    store.
  - rustls and quinn read their own clocks; their certificates do not
    expire within a run.
- **A build with the feature says so:** a warning at startup, and in
  `vos --version`. CI builds the release binary and checks that its
  `--version` does not.
- `just test-agent` runs the fault suite with the feature.
- **A node's faults file is emptied when the harness kills the node,**
  unless the scenario keeps a fault through the restart on purpose: a
  `hold_commits` left in place is a stalled disk at boot.
- A power loss, unsynced writes lost, is not a fault here: SIGKILL keeps
  the page cache. 3.3's crash tests cover it.

**An operator status route** (`GET /agents/{id}/status`, with the
operator's token) reports a replica's term, role, commit, applied index,
log start and last index. The end checks read every running replica
with it: a running node's store is locked to others.

**The harness** (`node/cli/tests/support/`), shared by the process
tests:
- starting a node with its own data directory, ports and log, and
  restarting it;
- SIGKILL, SIGSTOP and SIGCONT;
- the relay's faults, and a node's faults file;
- clients pinned to the space's nodes, over HTTP or TLS;
- at the end, stopping every node and opening each store.

#### 3.9b The fault suite

`node/cli/tests/faults.rs`, on the checker's model.

**A dev-only crate, `node/checker`** (`publish = false`), holds the
model both suites share:
- **The core:** the history and its checks, pure (events in, violations
  out): running totals, linearizable and floored reads, messages,
  captured replay.
- **A client driver** over `vos_node::client` (HTTP or TLS), its targets
  chosen by the suite.
- **Fault controls behind a trait:** the node clock, its jumps past the
  skew, and session collection, which each suite drives its own way
  (in process through `Config::clock`; across processes through the
  faults file).
- **Store inspection stays in the in-process suite**: the check that a
  node holds a request applied before it answers it.
- **A caution:** the crate depends on vos-node for the client, and
  vos-node's integration tests depend on it. Cargo allows the cycle, and
  integration tests link the same library, so types unify. vos-node's
  own unit tests (`#[cfg(test)]` in `src/`) must never use it: that
  build is a second instance of vos-node.

**The suite:**
- **The space:** five node processes.
  - Six agents are each on three of them, the other nodes spares for
    replacements.
  - A few hundred idle agents besides, so restarts and elections come
    with placement bursts and directory catch-up.
  - The suite's settings: compaction every few dozen entries, so
    restarts catch up by snapshot, and elections of 300–600 ms, so a
    seed sees many.
- **The clients,** as the checker's:
  - two per agent, in sessions renewed every few dozen requests, each
    request resent until answered;
  - every answer the client's running total;
  - linearizable reads, and reads at a floor;
  - messages between agents;
  - requests captured and replayed after their session is collected;
  - `Lost` answered by reading the total. A replacement's `TimedOut` or
    `InProgress`, and a skewed node's refusals, are expected answers,
    not failures.
- **The faults,** from a seed:
  - SIGKILL of a node, often a leader, and its restart a little later;
  - SIGSTOP for 1–5 s, then SIGCONT;
  - a connection cut, a link cut, or a node cut off from the rest, for
    2–10 s, and now and then past QUIC's idle timeout;
  - a link losing 30–90% of its datagrams, or delaying them by
    20–200 ms;
  - a gray failure: one class of frames lost on a link, the others
    flowing;
  - a slow disk (commits delayed 20–200 ms), a stalled one (commits
    held 2–5 s, past the writer's stall bound), or a failing one
    (commits fail, the node halts, and is restarted);
  - a node's clock jumping 15 s either way; once a run, every node's
    clock past the session skew;
  - **replacements, some aimed at the vote floor:** the shape that
    produces a stale replica and an empty one that could vote for it.
    1. Group {1,2,3}, spares 4 and 5; node 1 is killed.
    2. 1 is replaced by 4: node 1 is now stale.
    3. 2 is replaced by 5: node 2 retires, keeping its floor.
    4. 5 is replaced by 2: node 2 is added again, empty, with its
       floor.
    5. Node 1 restarts, close to node 2's new start, with no election
       in between.

    With the floor, node 1 is refused; without it, node 2 could grant
    it. A down node cannot be added (the node added must say it can
    run the program), which is why this takes two spares. Besides it:
    the current leader replaced, and random replacements.
  - **at most one node down or cut off at a time,** so a majority of
    every group stays, except a **quorum-loss window** once a run: two
    of a group's replicas down or cut together. Safety only, then heal
    and require progress.
- **Answers' deadlines are suspended** in the windows where waiting is
  expected:
  - delays, whose round trips can exceed the low election timeout and
    bring elections one after another;
  - the quorum-loss window;
  - gray failures, whose leader steps down only after its patience
    (about 3 s at the suite's timeouts).

  Safety is checked throughout.
- **At the end:**
  - everything heals, and every client's last request is answered;
  - every replica applies through the leader's commit, read through the
    status route;
  - the nodes stop, and each store is opened:
    - every agent's replicas hold the same entries above the highest
      log start, through the lowest commit;
    - the same rows where their applied indexes are equal;
  - no node's log holds a panic, or a halt without a failing disk
    injected.
- **TLS:** each seed runs in the clear or over TLS, clients pinning the
  nodes' keys, by its parity.
- **Runs:** the seed is printed, and `FAULTS_SEED` runs one again. `just
  ci` runs one seed, a couple of minutes. A loop runs many before a
  step's commit, as the checker's does.

#### 3.9c The carried items

- **`Forward` carries the forwarder's view of the leader's term.**
  - A node not leading at that term, whether it leads at another term
    or leads nothing, answers `NotLeader`, with its hint and its own
    term, as a node that leads nothing does today. A silent drop would
    cost every call through a forwarder its 2 s re-forward after each
    election.
  - The forwarder re-forwards at once only when the answer's term is
    higher than its own view, carrying that term. A lower term comes
    from a stale leader: the forwarder waits for its own core to name
    one. Otherwise the two would ping-pong.
  - vos-net holds frames across a redial, with no expiry. A held
    `Forward` could reach a later leader: the session's lane makes that
    safe, and the term bounds every copy's life by its forwarder's.
  - A test: a `Forward` at an old term is answered `NotLeader`, and the
    call is answered once.
- **A snapshot stream outlasting the core's own deadline**
  (`snapshot_timeout_ms`): the stream and the core must agree on giving
  up. The core starts a new stream only once the host's has ended, and
  the follower stages only the newest.
  - A cluster test with the deadline lowered, and the stream slowed by
    a hook.
- **Not in 3.9:** fast retransmit on a dropped gap (the suite shows
  whether it is needed); learners stay unscheduled.

#### 3.9a Built

**`vos node run --peer-bind <addr>`** binds the QUIC endpoint there
(`Config::peer_bind`); the space still lists the address peers dial.

**The relay** (`node/cli/tests/support/relay.rs`), threads in the test
process:
- a socket at each node's listed address, and one per (dialer, peer)
  that stands for the dialer toward the peer, kept for the run;
- connection cuts, link cuts, a node cut off from the rest, and links
  thinning or delaying datagrams (delayed ones wait on a thread of their
  own, in the order they fall due);
- 4 MiB socket buffers and 64 KiB datagrams;
- its own failures to pass a datagram on, counted (`own_drops`): a test
  checks there are none.

**vos-net:**
- `Config::idle`, QUIC's idle timeout, which the node sets from
  `Config::quic_idle`.
- A liveness frame queued before its connection was made is dropped, not
  sent. Test: frames queued while the peer is unreachable reach it once
  it binds, the liveness frame among them excepted, and a fresh one
  arrives.
- **That covers redials only.** A liveness frame handed to a connection
  that outlives a cut (any cut shorter than QUIC's idle timeout) is
  retransmitted by QUIC after the heal. Its receiver stamps it on
  arrival, as fresh.
  - **The bound:** a listing stamped late vouches for its leader at its
    term until a full election timeout after the late frames arrive.
    After a long cut, QUIC's probe backoff can deliver them seconds
    after the heal.
  - **When it matters:** only if the sender stopped leading during the
    cut while the receiver's group is still at that term. A group at a
    later term asks about its own term, so the stale listing does not
    match.
  - **The cost:** one election delayed by up to an election timeout.
    Never a safety matter.
  - **A precise fix,** if 3.9b shows the need: each frame carries its
    sender's monotonic time, mapped through a windowed minimum offset
    (windowed, as two machines' clocks drift).

**Faults in the binary** (`node/host/src/faults.rs`, the `faults`
feature of vos-node and vos-cli), as designed, with these choices:
- **A generation handshake:** the harness replaces a faults file whole
  (written beside it, then renamed), headed by `generation <n>`.
  - Once the faults are in force, the node writes `n` to the file
    beside it (`.taken`), and `set_faults` waits for it.
  - It does not wait for a node that is down or paused: that node takes
    its faults when it starts, which `restart` waits for (the node
    acknowledges before it prints its address), or when it goes on,
    which `pause(n, false)` waits for.
  - The faults are stored with release ordering, so they are in force
    before the acknowledgement.
- **Frame losses sit in a network of their own** (`Lossy`), wrapping
  the node's. The groups' drivers send Raft frames through the network
  directly, so a loss at `Inner::send` would miss them.
- **`fail_commits after`** writes the batch unsynced
  (`Durability::Buffered`), then fails it, through a new hook,
  `Hooks::fail_sync`.
- **The clock fault moves `Config::clock` only:** batch times,
  sessions, and ingress's freshness checks.
  - Blobs' put times are immune by construction: they are the wall
    clock at the process's start, moved on by the monotonic clock.
  - The incarnation reads the system clock, which the fault does not
    move.
- **`vos --version` says so,** "(faults: a test build)", and the node
  warns at start.
- **`just check-no-faults`, in `ci`:** a plain build of `vos`, after
  the fault suite built it with the feature, must not say so; and no
  workspace member turns the feature on for vos-node (`cargo tree`).
  - It checks a debug build, not the release one the design named.
    Features resolve the same in both, and a release build would cost
    CI minutes for nothing.
- Clippy also runs on vos-cli with the feature.

**An operator status route:** `GET /agents/{id}/status`, with the
operator's token, answers `Answer::Status(ReplicaStatus)`:
- the term, and whether this replica leads;
- the leader it knows;
- the commit and applied indexes;
- its log's start and last index;
- whether the node halted.

A store it cannot read answers `Unavailable`.

The client calls it with `Operator::status`.

**A deadline on a call's answer at its leader** (`calls.rs`, `ANSWERED`
= 30 s), found by the stalled-disk test.
- **The problem:** a call waited for its answer as long as its commit
  took. A leader whose disk stalled held every caller up to the
  client's own timeout (300 s), though another node had taken over.
- **Now** the caller is answered `TimedOut` after 30 s, and sends it
  again. The resend reaches the new leader through a forward, or waits
  on the same call.
- The call is pushed when its lane queues it, so the order of a
  session's calls stays the lane's. Then it runs to its end in a task of
  its own, which settles the lane however long it takes. Only the
  caller's wait is cut short.

**A failed flush stops the writer for good** (`storage.rs`), found by
the review.
- **The problem:** a flush that failed may still have reached the disk,
  as `fail_commits after` does and a real failed fsync can. The writer
  answered `Err` and went on taking commits, checking them against its
  view of each agent's rows, which the failed flush may have changed.
  - A snapshot switch written but failed was abandoned, and its epoch
    dropped in the background, though the store pointed at it.
  - A compaction written but failed could be retried at a lower point,
    moving the log start back over a gap.
- **Now** the writer refuses every commit after a failed flush, and
  says so (`StorageThread::failed`).
  - The node halts when it sees this, whichever path met the failure.
    The pair heartbeat looks each round, and the records' resend loop
    each second, which a space of one runs too. The node falls silent,
    and its groups elect elsewhere.
  - A halted node stores and acknowledges no placement or blob from
    its peers: their resends are dropped quietly, not logged one by
    one.
  - A snapshot switch that fails so halts at once, rather than
    abandoning its epoch.
- **Tests:**
  - the writer refuses everything after a failed sync, and only the
    failed flush's write is in the store;
  - a cluster test: a flush failing outside any log write, at an idle
    leader, halts its node, and the group elects another leader;
  - an ingress test: the status route reports a replica, refuses a
    stranger, answers `NoAgent` for an agent the node does not run,
    and reports a halt in a space of one;
  - each mutation is caught.

**The node's log:** `vos node run` writes tracing to stderr, at `info`
or the level `VOS_LOG` names. Halts were dropped silently before.

**The harness** (`node/cli/tests/support/`): `Processes` starts nodes
through the relay, each with its own data directory, ports, log and
faults file, in the clear or over TLS. It can:
- kill a node, emptying its faults file;
- pause and resume a node, and restart it;
- read a replica's status, and find the leader at the highest term;
- list the log lines that tell of a panic or a halt ("needs a
  restart").

A node's ports are drawn below the range the system gives out for
outgoing connections, so a restart finds them free. The relay's own
losses include the datagrams the system dropped at its sockets
(`/proc/net/udp`).

Opening each store at the end comes with 3.9b's end checks.

**Tests:**
- `three_processes.rs` (3.5d2's) runs through the relay (24 s).
- `processes.rs`: the relay cuts a leader off; another node is elected
  and the calls go on; once healed, the old leader catches up. The relay
  loses nothing of itself (22 s).
- `faults.rs`, with the feature (48 s for the three):
  - a leader whose disk stalls hands its group over. A call made at it
    is answered within a minute (300 s without the deadline), and the
    replica catches up once its disk is let go;
  - a leader whose syncs fail halts, and says so in its status and its
    log; the others go on, and once restarted it catches up;
  - a gray failure (Raft frames lost, the pair heartbeat flowing)
    deposes its leader: it led when the fault took hold, and another
    node leads at a later term.
- A unit test of the control file's parser.

**Opus's review of 3.9a:** GO-with-fixes, all folded above.
- **A failed flush that reached the disk** (should-fix, a safety
  matter): the writer went on over its stale view. It now stops for
  good, and the node halts.
- **Halts were invisible:** `vos` installed no log subscriber, and the
  harness looked for a word no message holds. Now the node logs to
  stderr, and the status reports `halted`.
- **`set_faults` slept 150 ms** and hoped. It now waits for the node's
  acknowledgement. The gray-failure test checks that the gray node led
  when the fault took hold, and that leadership moved to a later term.
- **Liveness frames within a surviving connection** can still arrive
  late: the bound is stated above.
- **Nits:**
  - a queued call is pushed before its task is spawned, so a session's
    order never depends on task scheduling;
  - the relay counts the kernel's drops at its sockets;
  - `leader()` takes the highest term;
  - nodes' ports are drawn outside the ephemeral range;
  - `check-no-faults` also checks the workspace's features;
  - the status route answers `Unavailable` on a store error;
  - the clock fault's scope is stated.

**Opus's check of the folds:** GO. Its six nits are folded too:
- `free_port` never draws a privileged port, and falls back to any port
  when no range is left below the system's;
- the liveness bound is restated;
- a halted node no longer logs each placement it is resent;
- a space of one halts within a second;
- resuming a paused node waits for its faults;
- the faults' ordering is release and acquire.

**Carried:**
- Install and role commands still wait as long as their commit takes at
  a stalled leader, with no deadline of their own. The operator's
  client times out at 300 s.
- One task and one channel per queued call, on the leader's hot path:
  for 3.10's budget.

#### 3.9b Built

**`node/checker` (vos-checker, `publish = false`):** the model both
exactly-once suites share, behind a trait, `Nodes`, through which a suite
says what its clients see of its nodes:
- how many there are, where each one's ingress is reached, and which
  one an answer's address names;
- the clock offset every node shares, and how often each one started;
- the leader, where the suite knows it cheaply;
- whether clients pause;
- a log of what was seen;
- a hook checking what a node answered against its store, where the
  suite can see it (in process only).

It holds:
- `Client`: the client model (running totals, forwards to the next
  agent's inbox, sessions timed ahead and timed again past a clock jump)
  and its driver.
  - One request at a time or pipelined.
  - It follows `NotLeader` and, with five nodes, `Elsewhere`: a node
    replicating nothing names the replicas, a different one each try.
- Its reader: linearizable and floored reads, checked against what was
  answered, and its inbox read against what the previous client
  forwarded.
- `capture` and `replay`: requests signed in a live session, sent again
  once every node has collected it; none may run.
- `Random`, `Mode`, `Log`, and the instances' and deadlines' constants.

**`exactly_once.rs` runs on it**, its `Cluster` implementing `Nodes`.
What only one process can do stays there:
- the check that a node holds a request applied before it answers it;
- waiting for every replica to collect every session, read in the
  stores;
- the end checks on the stores while the nodes run.

**Around it:**
- `vos_node::client::post_within`: one request on a connection of its
  own, answered within a deadline, in the clear or over TLS.
- `ReplicaStatus.sessions`: the live sessions a replica's applied state
  holds. The process suite waits for every replica to collect every
  session by it: a session is removed, and the count lowered, in one
  accumulate.
- `vos_node::STORE`: where a stopped node's store is opened.
- **Settings a test build reads once at start, in the faults file:**
  `election_ms <low> <high>`, `heartbeat_ms <ms>`,
  `compact <every> <tail>`.

**The harness** serves clients and faults at once (`&self`
throughout).
- **Each faults file is written whole each time:**
  - a generation;
  - the suite's settings;
  - a `clock` line: the offset every node shares, plus the node's own
    jump;
  - the node's own faults.
- **A kill clears the node's own faults and jump,** and keeps the
  shared offset.
- **New helpers:**
  - `agent_with`: an agent created on chosen nodes, with programs
    installed;
  - `identity`, `operate`, `jump_clock`, `jump_every_clock`;
  - `stop_all`: SIGKILL every node, then open each store.
- **A node that never says it listens:** the harness records each of
  its threads' name, state and kernel wait from `/proc`, and the
  failure shows them with the run's last events.

**The suite** (`node/cli/tests/fault_suite.rs`, with the feature): as
designed.
- **The space:**
  - five nodes;
  - six agents, each on three of them in turn;
  - 200 idle agents;
  - elections of 300–600 ms, compaction every 32 entries, QUIC's idle
    timeout at 5 s.
- **The clients:** twelve, two per agent, with a reader at each
  forwarding one.
- **The faults:** 24, one at a time.
  - Drawn from the design's list: a leader killed, a node paused, a
    connection cut, a link cut, a leader cut off, a lossy or slow link,
    a gray leader and the reverse (a node's pair heartbeat lost, its
    Raft frames flowing), a slow disk, a stalled one, a failing one
    (before or after its write), a node's clock jump, a random
    replacement, and the leader replaced.
  - At set points:
    - every clock past the skew;
    - the replacements aimed at the vote floor;
    - every session expiring, with requests captured and replayed;
    - the quorum-loss window.
- **The end checks:** as designed.
  - After them, each sender's pair marks and outbox, and each
    receiver's, are read in the stores.

It is its own test binary, beside `faults.rs`. In the same binary,
cargo would run it beside the three-process tests, and their load would
change its timing.

**Found by the suite, and fixed:**
- **A debug build's node took 8.6 s to start**, and more than 20 s
  under the suite's load. The linker in `vos-pvm-compiler` ran
  unoptimized.
  - It is optimized in the dev and test profiles, as `vos-pvm` is: a
    start takes 0.27 s.
- **A shared clock jump across processes is not atomic:** the five
  faults files are written one after another. Clients took the new
  offset first, so a session they timed met nodes still at the old one,
  120 s apart.
  - The harness moves the nodes first and the clients last.
  - In between it says the clocks are moving (`Nodes::clocks_moving`),
    and the checker sends a stale-session refusal again then.
  - The in-process suite moves one atomic and never says so.
- **A forwarding client used one key for every session.** A long run
  reached the agent's cap of 64 live sessions on one key, and was
  refused `KEY_SESSIONS_FULL`.
  - Such a client now takes a fresh key every 32 sessions.
  - Retiming a session refused this way would not be safe: unlike a
    stale one, a copy of it could be created later, once the cap
    frees.

**Where it departs from the design:**
- **Answers' deadlines are not suspended.** Every window where waiting
  is expected is shorter than a client's 60 s to an answer:
  - a delay of at most 5 s;
  - a quorum lost for at most 8 s;
  - a gray leader, whose patience is 3 s at the suite's settings.
- **The quorum-loss window kills two of a group's replicas,** rather
  than cutting them off: restarts, catch-up and elections follow at
  once.
- **A run's coverage is printed, not required.** The in-process suite
  requires a session timed again past the clocks' jump; every seed here
  showed 14 to 16.
- **The process suite's clients do not know the leader cheaply:** a
  status read per answer would cost as much as the call. They count
  "answered", not "by the leader" or "by a follower".
- **The stores are opened after SIGKILL,** so the end checks read what
  recovery makes of each.

**Runs:** the default seed and seeds 11–32 pass, each seed its own
schedule (`2·seed + 1`). After the review's folds, the default seed and
seeds 33–40 pass, the floor-aimed set point reaching its state in each.
- Both transports and both client modes.
- 120 to 300 s a seed.
- 14,000 to 83,000 requests answered a run.
- Failing disks halting and recovering, gray leaders and their reverse.
- The relay losing nothing of itself.

`just ci` runs the default seed. The in-process checker passes its
48-run loop on the shared crate.

**Opus's review of 3.9b:** GO-with-fixes, all on the test side, all
folded:
- **The floor-aimed replacements never reached the state they named.**
  b, added again, heard its leader at once, and refused a's pre-votes
  under its lease; c refused them by its log. Deleting the floor left
  the set point passing.
  - **Now:**
    - c, d and e send b no Raft frames while b is added again: b runs
      the group empty, hearing no leader. e is cut too, as it may lead
      then and would fill b by a snapshot;
    - no node tells a of the placement that removed it, so a, restarted,
      campaigns in its old configuration;
    - a must never lead, and only b's floor stands in its way: until
      a's term has caught up with b's, through the refusals that raise
      it, and two election timeouts after;
    - b must stay empty all along.
  - **Mutation:** with the floor disabled in vos-raft, three seeds out
    of three fail there, a stale node leading on an empty node's vote.
    The checker saw it too: requests answered from the stale state with
    a wrong total.
- **The pair marks and outbox were asserted once, after SIGKILL, with
  nothing waiting for the last acknowledgements:** a flake.
  - `ReplicaStatus.outbox` counts the messages a replica's applied state
    holds unacknowledged.
  - The end waits until, at every replica of every agent, the leader's
    log is committed through its end and applied everywhere, and every
    outbox is empty. Then it waits again after the reads, and stops.
- **`stores_agree` could compare nothing:** a store without the agent
  reads as defaults. Now:
  - every replica must have applied, on disk, at least what it settled
    at, and all must have applied as far;
  - every entry in the compared range must be there;
  - every replica must hold rows.
- **A node that died on its own went unseen:** the harness now notes
  any exit it did not make, and the suite fails on one.
- **Halts were allowed at a failing-disk node at any time:** now only
  between the fault and its restart, as offsets in the node's log. The
  fault also waits for a halt it saw, not just for a missing status.
- **Settled in one pass:** the end settles every agent in one pass
  just before stopping every node. An election in between would leave a
  leader an entry ahead of its followers; the window is now one status
  pass.
- **Nits:**
  - a node that exits while the harness waits for its faults fails the
    wait at once, naming the exit;
  - trouble lines are read from the log's bytes;
  - a zero heartbeat or compaction interval is unreadable;
  - the checker reads whether the clocks move before the offset, so the
    two loads cannot straddle the harness's;
  - the harness's statuses and commands are answered within 5 s
    (`Operator::within`);
  - a live-sessions count that does not decode answers `Unavailable`;
  - `post_within`'s deadline is stated per read and write;
  - a settings line a node cannot read, or a heartbeat not shorter than
    the elections, stops the node at start;
  - `stop_all` pauses every node before killing any.

#### 3.9c Built

**`Forward` carries the forwarder's view of the leader's term,** and
`Forwarded` its answerer's term (both on the wire, in `PeerMessage`).
- **The receiver** runs the call only while it leads at that term.
  Otherwise, whether it leads at another term or leads nothing, it
  answers `NotLeader`, naming who it knows leads (itself, if it leads at
  another term), with its own term.
- **The forwarder** acts on the answer's term:
  - higher than its own view: it sends the call there at once, carrying
    that term, and keeps the named leader until its own core reaches
    that term;
  - lower or equal: it waits, as before, for its own core to name a
    leader. Two nodes never send the call back and forth.
- **Test** (cluster): the test stands in for a follower on the hub, and
  forwards a call to the leader at a term it does not lead at.
  - It is answered `NotLeader`, naming the leader at its term, and does
    not run.
  - Sent again at the leader's term, it runs once.
  - Mutation: without the receiver's term check, the call runs at the
    wrong term, and the test fails.
- **Not tested on its own:** the forwarder's going at once. Without it a
  forwarder waits for its own core, which is correct but slower. The
  checker and fault suites cover its correctness.

**A snapshot stream outlasting the leader's deadline goes on,** as it
already did. A stream that takes longer than the deadline would never
finish if it were started over.
- **When the core's deadline passes,** it asks for another stream. The
  host starts none while one to that follower runs, and the follower
  stages only the newest stream it is sent.
- **The two agree on giving up:**
  - a stream that falls silent tells the core, as before;
  - a stream all staged but never switched to, released after its hold,
    now tells the core too, which sends again at once rather than at
    its own deadline.
- **New:**
  - `Config::snapshot_timeout_ms`, the core's deadline, 60 s by
    default;
  - `Hooks::delay_chunk`, which slows a stream;
  - `Node::snapshots_streamed`, a count of the streams a node started.
- **Test** (cluster): with the deadline at 300 ms and each 64-byte chunk
  delayed 40 ms, a stream outlasting the deadline catches a follower up.
  - The follower switches once, and the leader started no other stream.
  - Mutation: a host that starts a stream again whenever the core asks
    started 44, and the test fails.

**Opus's review of 3.9c:** GO. Its nits are folded:
- **A hint naming the forwarder itself** is never taken as a named
  leader. A spin it would cause is unreachable today, but only by the
  order of the core's events.
- **A forward to a node with no group for the agent** is answered
  `NotLeader` with no leader, so its forwarder goes again soon rather
  than after its 2 s.
- **The test also sends at an earlier term**, the design's case of a
  copy held across a redial. It reads past other requests to the
  stand-in, within a deadline.
- **Doc comments** put back on `Node::leads` and on the window test.

**Carried, a design note:** `Forward` and `Forwarded` gained a field
under the same codec indexes. Between nodes of two versions, forwards
would not decode. That is fine before a release, and needs a wire
version if rolling upgrades are ever promised.

**3.9 is done.** What it leaves for 3.10 is in the lists above and in
3.8's.



## Step 3.10: acceptance

### Design

3.10 measures section 14's budgets as the plan's table states them:
- three `vos node run` processes, each on its own data directory (the
  shared disk a caveat), talking QUIC;
- clients over HTTP.

It then works on the ones that miss until they pass, or until the levers
are spent and the owner decides. Split in three:
- **3.10a:** the bench, and the table measured as the code stands, with
  the costs attributed;
- **3.10b:** the levers, one at a time, each kept only if it moves the
  cost it targets by the method below;
- **3.10c:** section 14 and the slice's defaults updated, every carried
  item closed or carried on to a named slice, and the gates checked.

**Where it starts** (the in-process bench of 3.8b; three nodes in one
process; 64 agents × 16 sessions; 7 executors per node):
- 31k commits/s at p99 57 ms;
- 12.7 cores busy, about 410 µs of CPU per commit across the three
  nodes.

A first profile of that run (perf, 999 Hz, no call graphs):

| Where | Share |
|---|---|
| the agent program's guest code (JIT) | 31–34% |
| libc: memory copies and fills, malloc and free | 20–22% |
| fjall point reads (memtable search, snapshot versions) | about 15% |
| the rest: the PVM runtime, QUIC, the executors, Raft | about 30% |

Without callers it names no lever by itself. 3.10a attributes it first.

#### 3.10a The bench, and the table as it stands

**The machine, pinned.** Section 14's budgets are per node, on three
LAN machines; here one laptop holds the three nodes and the clients.
- **Each node process is pinned** (`taskset`) to its own cores, the same
  mix for each:
  - two P-cores, four threads;
  - two E-cores.

  On the reference laptop: node 1 on CPUs 0, 5, 1, 2, 12, 13; node 2 on
  3, 4, 6, 7, 14, 15; node 3 on 8–11, 16, 17.
  - Not quite the same mix: the two 4.8 GHz P-cores (1/2, 3/4) went to
    nodes 1 and 2, and node 3's run at 4.5 GHz.
  - It matters at light load, so each light-load run notes which node
    leads its agent.
- **The driver** has the rest: its timing threads on the E-cores 18 and
  19, the rest of it on 18–21.
- **The executor count** follows the affinity mask
  (`available_parallelism` honours it), so a node uses what it is
  given, as on a machine of its own.
- **The pass criterion:** a budget passes when one pinned node, a third
  of the laptop, carries its share.
  - CPU per commit is reported by role, leader and follower, so the
    numbers translate to a machine per node.
  - The shared disk stays a caveat.

**The bench** (`node/cli/benches/processes.rs`; not run by `just ci`):
- **The nodes:** three release builds of `vos node run`, each with its
  own data directory under `target/`, the peer endpoints bound directly.
- **The driver** is async (smol), with few threads:
  - a task per session, over a connection it keeps;
  - every call's body signed before the timed window, as sessions and
    sequences are known in advance;
  - for long runs (the soak), signed ahead into a bounded queue instead,
    that CPU counted as the driver's;
  - each session's t0 set just before its first call, so no session is
    timed further from it than the skew;
  - its own CPU is reported.
- **Its send lag is reported:** each open-loop run gives the p50 and p99
  of a call's actual send time minus its scheduled one. A run whose p99
  lag passes 0.5 ms is invalid. A late driver would otherwise count as
  the nodes' latency.
- **Calls go to the agent's leader,** following redirects, through
  ingress: signature check and lanes included.

**Load, and how it is timed:**
- **Open loop for every latency.** Calls are sent at an offered rate,
  each timed from when it was scheduled to go, not from when it went: a
  slow call does not delay the next and hide the queue. Each session's
  interval is far above the latency it measures, so each has at most one
  call in flight (e.g. 256 sessions at 10k/s).
- **Closed loop only for the most commits per second.**

**What it reports,** each from runs after a warm-up, on a store
pre-populated by running the load itself (never by writing rows past
Raft) until it is in the steady state the run would leave:
- **One replicated agent:**
  - the most commits per second, closed loop, swept over sessions;
  - at half load, max(10k/s, half that most), open loop, a call's p50
    and p99, client to answer;
  - beside it, the node's own batch-to-commit, from a new operator
    stats route: histograms of the writer's and the leader loop's
    times, read as deltas over the window, so they give percentiles.
- **64 active agents:**
  - the most commits per second, closed loop;
  - open loop at 40k/s offered, p50 and p99;
  - the knee: the highest offered rate whose p99 stays ≤ 20 ms.
- **A quiet node:** one session, one call at a time, p50 and p99 over
  HTTP (the "request latency on a quiet node ≤ 5 ms at p99" row).
- **Idle groups:** 1,000 idle agents per node. For each process over
  10 s, from `/proc`: its CPU as a share of one core, its threads and its
  RSS.
- **A query on a follower:** the counter's value at applied consistency,
  open loop, client to answer, p50 and p99. Slice 2's node-path measure
  is repeated in process (`benches/acceptance.rs`).
  - Which percentile the budget means is the owner's open decision from
    slice 2. Both are reported; if p99, the query's tail joins the
    levers.
- **Table reads under continuous writes:** in process, a 10M-row table.
  - Point reads are timed while writes run at the 64-agent run's rate,
    in rows per second, with that run's mix of rows (log entries,
    applied state, sessions).
  - In the steady state compaction keeps, not right after a load.
- **Mass failover:** the node leading the most groups is killed.
  - The time until every group has a leader again, and until every
    node's directory agrees: the `recording` lock and the directory's
    convergence, which 3.8b left to 3.10.
  - Then its restart: the time to open and catch up.
- **A soak:** the 64-agent load at half its knee for 10 minutes or more.
  No hot path may grow with history: CPU per commit and p99 over the last
  minute must stay within 10% of the first minute's, after the warm-up.
  A bigger difference is either explained or a failure.
- **Memory:** each process's RSS in every active run.
- **TLS:** the 64-agent run once with TLS on ingress, its production
  default off loopback.
- **Exactly once:** the checker and the fault suite pass (3.9).
- **Slice 2's rows** the levers touch (invocation, fixed cost per refine,
  pooled acquire) are re-measured with `benches/acceptance.rs`.

**Attribution, before any lever is chosen:**
- **Call graphs:** a build with frame pointers
  (`-C force-frame-pointers=yes`), or perf's DWARF unwinding.
- **The JIT's code named:** the PVM JIT writes a perf map
  (`/tmp/perf-<pid>.map`) behind an environment variable, opt-in.
  - It is created new (never following a link), with mode 0600, as it
    tells where code lies.
- **An off-CPU profile** (scheduler waits: locks, fsync, channels).
- **The same load on fewer pinned cores,** to tell a saturated CPU from
  a queue or a lock. The lever is CPU per commit only if that holds.

Nothing is optimized in 3.10a. Its results go into a table like section
14's, with the earlier numbers beside them.

#### 3.10b The levers

**The method, for each lever:**
- **The metrics:** instructions and CPU per commit (`perf stat`), at a
  fixed offered load below saturation; and the lever's own target,
  measured directly (reads per run, reset µs, allocations per input).
- **At least five runs per variant,** interleaved A/B, on the pinned
  cores, with fresh data and a warm-up; the performance governor where
  the machine allows it.
- **Kept only if its median moves past the other's spread** (or a rank
  test says so). Else it is reverted, and the result recorded.
- **After each kept lever,** the safety gates again: the checker loop,
  several fault-suite seeds, the simulator's chaos runs and the crash
  tests.
- **The budgets** are judged on throughput and p99 only at the end.

**The candidates,** ordered by 3.10a's attribution. As the first profile
suggests them:
1. **Store reads, scoped to a batch.** They keep fjall's snapshot
   consistency:
   - one snapshot shared by refine and the dry run;
   - a memo of the rows read, valid for that snapshot only;
   - the apply reading its entry from the core's cache, and its epoch
     from memory, rather than a snapshot per apply.
2. **Machine setup and reset**, if the attribution puts the memory
   copies and fills there.
   - Resetting only dirty pages, or keeping an agent's machine warm.
   - Replicas must run alike: a page left dirty would make a leader's
     dry run and a follower's apply differ.
   - So it comes with a differential test (a warm, reset machine against
     a fresh one, over random inputs), the fault suite's store
     comparison, and a memory bound at 1,000 agents.
3. **Allocation** on the per-input path.
4. **The agent program's own work** per input: the session bookkeeping
   the default agent does in refine and accumulate.
   - Measured per input; changed only where it is waste, never its
     semantics.
   - The JIT's share is the largest, so this may come first.
5. **A row cache per agent across batches,** last, and only with every
   guard below. The leader's apply reuses its dry run's writes, so a
   stale read there would make replicas diverge, not just waste a
   batch.
   - Every reader (refine, dry run, query) sees exactly one applied
     index.
   - It is updated only after a committed apply's store commit
     succeeds: never by a refine or a dry run (a deposed leader's dry
     run never commits).
   - It is keyed by epoch, and dropped with a snapshot switch, a
     retirement, a halt and a restart, at once.
   - Its memory is bounded.
   - A shadow mode compares every read with the store's, under the
     checker and the fault suite.
6. **Pipelined refines,** only if the single-agent budget misses once
   CPU per commit has come down, as the plan says, with their own design
   and review.

**Carried items, taken where they are levers:**
- message batching across agents;
- one heartbeat round per linearizable read;
- the leader's one task and one channel per queued call.

#### 3.10c Closing the slice

- **Section 14's rows** updated with 3.10's numbers, each with the setup
  it was measured on.
- **The defaults:** the plan's table disagrees with the code in places,
  and each is settled, with its reason:

  | Default | Plan | Code |
  |---|---|---|
  | Session skew | 5 min | 60 s |
  | Live sessions | 1M | 65,536 |
  | Compaction | 4,096 entries or 64 MiB | 1,024, keeping 256 |
  | Quiescence | after 4 idle intervals | the pair heartbeat (3.8) |

  The rest (heartbeat, elections, thresholds, caps) are confirmed or
  moved.
- **Each carried item closed, or carried to a named slice:**
  - the directory's convergence and the `recording` lock, from 3.10a's
    failover run;
  - the confirmation entry's overhead;
  - install and role commands without a deadline at a stalled leader;
  - liveness frames late within a surviving connection;
  - the wire version;
  - fast retransmit on a dropped gap (3.9);
  - fan-in past a receiver's cap (3.8b).
- **The gates** (the plan's "Gates") checked one by one, ending with
  `just ci-full`.

After 3.10, the slice's end review, by Fable 5.1.

#### 3.10a1 Built: the bench, and the table's first rows

**`node/cli/benches/processes.rs`** (`cargo bench -p vos-cli --bench
processes`; `ROWS` picks rows, `CPUS` overrides the pinning), as
designed.
- **The setup:** three release node processes pinned as above, each
  running five executors.
- **The driver:**
  - two executor threads on CPUs 18 and 19, signing on 18–21;
  - a task per session over a connection it keeps (`smol`, with
    `futures-rustls` for TLS);
  - every call signed before its run.
  - `Target::authority` and `Target::tls` are now public, so the driver
    opens its own connections.
- **How a run is measured:**
  - each node's CPU is sampled at the timed window's edges;
  - the nodes are left to go quiet before each run;
  - an open-loop call's latency is timed from its schedule.
- **What a run reports, beside the latency:**
  - each node's CPU, and its executors' (the busiest's share of a core,
    and their mean), from `/proc/<pid>/task`;
  - the driver's own CPU;
  - the driver's own lag: the time past both the schedule and the
    session's previous answer. Above 0.5 ms at p99, the run is invalid;
  - the calls that waited on their session's previous one, as a sign
    the run is past the knee. It then gives no CPU per commit, as the
    calls answered in the window are not those scheduled in it;
  - sessions that ran out of signed calls (an undercount);
  - the first failed answer.
- **The knee is searched upward,** from 5k/s, so no run meets the backlog
  of one past it. It is reported as a bracket, and 40k/s runs last.
- **At the end, every agent's counter, read at its leader, must equal
  the increments it answered,** over every run: a silent failure cannot
  pass as a commit.
- **`DATA`** puts the stores elsewhere: `/tmp` (tmpfs) takes the disk
  out of a run.

**Found, and fixed: every answer over HTTP waited about 40 ms.**
- **Why:** the ingress set no `TCP_NODELAY` on the connections it
  accepted, and wrote each response's head and body apart. Nagle's
  algorithm held the body until the head was acknowledged, and the
  client delayed that acknowledgement.
- **The effect:** a quiet node answered at 46 ms. Slice 2 never measured
  over HTTP, so nothing showed it.
- **Now** accepted connections set `TCP_NODELAY`, and a response goes in
  one write. A quiet node answers at 3.5 ms.
- **The client library** (`vos_node::client`) also sends a request's head
  and body in one write: it already set `TCP_NODELAY`, so there was no
  stall, but two segments woke the node twice.

**The first rows.** Each node is pinned to two P-cores and two E-cores,
six logical CPUs, and runs five executors. `/proc` counts each logical
CPU's busy time, so a node saturated on all six would read about 6
cores busy. Hyperthreading lowers what each gets done, not what it
reports.

Numbers from the run after the review's fixes (the rows before them gave
the same picture, with CPU over a wider window):

| Row | Result | Budget |
|---|---|---|
| One agent, most, closed (256 sessions) | 15.2–16.3k/s, p99 20–25 ms. The leader 2.3 cores busy, its executors 36% each | ≥ 20k/s: misses |
| One agent, half load, open (10k/s) | p50 5.9 ms; p99 8.4, 18.6 and 9.9 ms in three runs | p99 ≤ 10 ms: varies across runs |
| 64 agents, most, closed | 17.9k/s at 4 sessions each (p99 23 ms), 27.2k/s at 16 (p99 54 ms). The nodes 4.0–4.6 of 6 CPUs busy, their executors only 50–63% each; 170–226 µs of CPU per commit per node | ≥ 40k/s: misses |
| 64 agents, open | p99 5.9 ms at 5k/s, 5.1 ms at 10k/s, 15 ms at 15k/s (that run invalid: the driver's lag p99 0.76 ms), 696 ms at 20k/s: the knee between 10k and 20k/s offered until a valid 15k/s run | p99 ≤ 20 ms at 40k/s: misses |
| Quiet node, one call at a time | p50 3.5 ms, p99 3.8–4.1 ms | p99 ≤ 5 ms: passes |
| Query on a follower, open, 2k/s | p50 0.36–0.40 ms, p99 0.60–0.72 ms over HTTP; about 350 µs of the follower's executor time per query at this rate, fixed costs (executors spinning before they park) included: the marginal cost needs two rates | ≤ 100 µs for the node's path (re-measured in 3.10a2) |
| Idle, about 1,065 groups per node | 1.1–1.4% of one core, 16 threads, 620–690 MiB resident | ≤ 5%, no thread per group: passes |
| The counters | each agent's counter holds every increment it answered, once | |

**With the stores on tmpfs** (`DATA=/tmp`), 64 agents gave 20.9k/s at 4
sessions each (+17%) and 29.3k/s at 16 (+7%), the executors still 58–66%
busy. The disk costs something, and is not the ceiling.

The same run's open loop at 5k/s gave a p99 of 78 ms (p50 1.9 ms),
against 5.9 ms on disk. That stays an unexplained outlier, not noise: an
election, a compaction stall, or the driver's reactor on a slow core
would each explain it, and a p99 like that is what the budget
measures.

**Per-thread, at 16 sessions each, closed:**
- the runtime thread (`vos-node`) about 70%;
- the five executors 55–70% each;
- the writer about 45%;
- QUIC (`vos-net`) about 30%.

None is saturated, and together they are about 4.75 of 6 CPUs.

**An earlier "low-load tail"** (p99 35 ms at 10k/s) came from the backlog
of the overloaded runs the knee search used to start from. Searching
upward, it is gone: p99 5.1 ms at 10k/s.

**What the rows say so far** (to be confirmed by 3.10a2's thread times
and stage times):
- **Neither budget is missed for want of total CPU.** The nodes leave a
  quarter of their CPUs idle, and the executors a third. But single
  threads are not ruled out:
  - the node's one async runtime thread (`vos-node`, about 70%), which
    runs every group's driver, leader loop and apply loop, and every
    ingress connection, with each lane's store reads and each apply's
    snapshot;
  - the driver, whose lag was already marginal at 15k/s on two E-cores.
- **64 agents: the cap is something they share, not each agent's
  cycle.**
  - 27.2k/s over 64 agents is about 425/s each. With 16 closed sessions
    each, Little's law gives about 38 ms in flight per call.
  - A cycle's own stages take a few milliseconds: the 2 ms linger, the
    refine of 16 inputs (about 0.35 ms) and the dry run, the append,
    sync and replication (2–3 ms). So most of the 38 ms is waiting.
  - The suspects: the `vos-node` thread first, the driver, the writer,
    executor bursts.
- **One agent:** its leader's `vos-node` thread parses and routes every
  call, runs each lane's check with its reads, and writes every answer:
  some 30–50 µs a call, at 15k/s near all of one thread. It is the
  likelier cap than the cycle.
- **The linger is not a lever.** It is taken only after the leader loop
  found its queue empty and waited, so in a closed loop it gathers the
  next burst, as meant. 3.8b measured none at all: +2% throughput,
  against a p99 of 91 ms rather than 54.
- **The disk** costs 7–17% of the 64-agent throughput on this laptop.

**The order the levers will be taken in, once attributed:**
1. **If the `vos-node` thread or the driver is the cap:**
   - the node's runtime spread over several threads (its tasks are
     already `Send`);
   - the lanes' and the applies' store reads off that thread.
2. **Cheaper refines per input.**
3. **Pipelined refines** for the single agent, with their own design and
   review.
4. **CPU per commit.**

**Left for 3.10a2, the attribution first:**
- each node's `vos-node`, `vos-storage` and `vos-net` CPU, and the
  driver's threads apart, in every run;
- the closed-loop maxima with the driver on P-cores, which shows whether
  the driver capped them;
- the stats route's stage times, with the waits between stages: input to
  batch, batch to refine, refine, propose to commit, commit to apply,
  apply to answer;
- the node's runtime on two or three threads, as an experiment: if
  throughput rises, the one runtime thread was the cap;
- a query's marginal cost, from two rates;
- a valid run at 15k/s.

**Then:**
- the operator stats route with its histograms;
- mass failover, the soak, TLS, and table reads under writes;
- slice 2's rows re-measured;
- the attribution: call graphs, the JIT's perf map, off-CPU, and fewer
  cores;
- repeated runs for the variance.

#### 3.10a2 Built: attribution

**Each thread's CPU in every run.** For each node: its runtime threads
(`vos-node`), its writer (`vos-storage`) and its network (`vos-net`),
beside its executors, from `/proc/<pid>/task`. For 64 agents × 16
sessions, closed:
- the runtime about 70–77%;
- the writer about 45%;
- the network about 30%;
- the executors 60–63% each.

None is saturated.

**The node's runtime on several threads, an experiment.**
- **The setting:** `Config::runtime_threads`, 1 by default. Its flag,
  `vos node run --runtime-threads`, is hidden: more than one thread has
  run under no fault suite.
- **The result:** with three threads, each node's throughput fell (one
  agent 14.0k/s rather than 15.0k/s; 64 agents 14.7k and 26.1k rather
  than 18.0k and 27.8k). The runtime threads used about 100% between
  them, rather than 70%.
- **It proves less than it seems.** The nodes' six pinned CPUs were
  already about 4.7 busy, and two more threads oversubscribe them. The
  drop measures CPU contention as much as anything the runtime does. The
  default stays 1, and the stage times below, not this run, place the
  runtime.

**Stage times, from a new operator stats route** (`GET /stats`,
`Answer::Stats`).
- **What it serves:** log-linear histograms (four buckets to each power
  of two, `vos_wire::ingress::bucket`), recorded with relaxed atomics.
- **Each stage is stamped where it ends:**
  - an executor's work ends inside the executor;
  - a proposal ends when the driver answers it;
  - a commit when the driver takes `Committed`;
  - an apply when the applier records it.

  The leader loop's wait to be polled again after each is a stage of its
  own (`resume`).
- **The stages:**
  - **the leader's batch:** its inputs; its refine and dry run, each
    with its wait for an executor; its proposal; its commit; its apply;
    the whole batch;
  - **the writer:** each commit's wait in its queue (`commit_queue`), its
    synced and its buffered flushes apart, and the commits each took;
  - **ingress:** each signature check (`verify`);
  - **the queue:** each input's wait in its agent's queue until a batch
    takes it (`queued`);
  - **the runtime:** how late a probe sleeping 10 ms at a time wakes
    (`late`).
- **Lost batches** record only their early stages, so the stages'
  counts differ.
- **The bench** reads the stats at each window's edges, and gives each
  stage's p50, p99 and largest over the window, with its count.

| Run | refine | dry run | propose | commit | apply | resume | queue | synced flush | verify |
|---|---|---|---|---|---|---|---|---|---|
| one agent, 256 sessions closed (about 190 inputs a batch) | 5.1 ms | 1.8 ms | 23 µs | 1.3 ms | 0.8 ms | 13 µs | 6 µs | 0.8 ms | |
| 64 agents, 10k/s open (about 19 inputs) | 0.8 ms | 0.3 ms | 13 µs | 1.0 ms | 0.1 ms | 7 µs | 4 µs | 0.8 ms | |
| 64 agents × 4, closed (4 inputs) | 0.5 ms | 0.2 ms | 0.2 ms | 4.1 ms | 3.1 ms | 0.2 ms | 0.8 ms | 1.3 ms | 127 µs |
| 64 agents × 16, closed (13 inputs) | 1.3 ms | 0.4 ms | 0.9 ms | 10.2 ms | 5.1 ms | 0.9 ms | 0.9 ms | 1.3 ms | 159 µs |

(p50s; their p99s are 2–5 times as long under load.)

**One agent: its capacity is about 14k/s.**
- Open loop at 15k, 18k and 21k/s offered, it falls behind at each.
- A batch's refine takes about 27 µs an input, run in series in one
  program run: 5 ms for 190 inputs. The dry run takes about a third as
  long, and the commit and apply about 2 ms.
- The levers are a cheaper refine per input, and the next batch's refine
  overlapping the last one's commit (pipelined refines).

**64 agents: the commit waits on serialized rounds.**
- Under the 16-session load, a commit takes 10 ms and an apply 5 ms.
  Meanwhile a commit waits about 0.9 ms in the writer's queue, and a
  synced flush takes about 1.3 ms.
  - The leader loop's own wait to be polled again is apart (`resume`,
    about 1 ms).
  - The driver and the applier are tasks on the same runtime thread,
    though, so `commit` and `apply` include their waits to be polled.
  - A probe now measures that wait directly (`late`): a task on the
    runtime sleeps 10 ms at a time and records how late it wakes.
- So a commit spans several rounds of about 2 ms each.
- The structural cause is in the driver: a round awaits its durable write
  inline (`act()`'s `Action::Write(write) => return self.write(write).await`),
  and takes no input, acknowledgement or proposal until the writer
  answers. An append, a follower's acknowledgement and the commit each
  wait a round.
- The core already supports writes answered later (as etcd does). The
  design of that lever starts there.

**Profiles (perf, no frame pointers, by symbol).**

*A follower answering queries at 6k/s:*
- ed25519 verification: about 50% of the node's CPU (curve25519 field
  operations; `calls::verify`).
- Parsing and validating a program's code blob (`spi::validate_code_blob`,
  `parse_compact_code_blob`): about 16%.
- The query's marginal cost, from two rates (2k/s and 6k/s), is about
  420–470 µs of the follower's CPU, against 50 µs for the node's query
  path in process (`benches/acceptance.rs`: median 50.6 µs, p99 151 µs).
  - So most of a query over HTTP is its signature check and its
    program's parse.

*One node under 64 agents × 4, closed:*

| Where | Share |
|---|---|
| ed25519 verification (curve25519 field operations, `calls::verify`) | about 36% |
| the agents' guest code (JIT) | 21% |
| libc (copies, fills, malloc and free) | 13% |
| fjall point reads (memtable search, skiplist) | about 8% |

**What a signature check costs** (`benches/verify.rs`, ed25519-dalek
alone, pinned):

| Check | A P-core | An E-core |
|---|---|---|
| key decompressed each time, strict (the node's check) | 34 µs | 77 µs |
| key decompressed once, strict | 36 µs | 66 µs |
| key decompressed once, not strict | 27 µs | 54 µs |

- **In a loaded node, a check takes 127–159 µs at p50** (the `verify`
  stage), exactly one per call. With the node's hyperthread siblings and
  E-cores busy, a check runs 2–4 times as long.
- At 27.6k calls/s that is about 1.5 cores per node, the profile's 36%.
- **The levers:**
  - Caching decompressed keys buys little: nothing on a P-core, 14% on
    an E-core.
  - A non-strict check, or batch verification, buys more. Each changes
    what signatures are accepted, so each needs a design for strict
    semantics.

**Why programs are parsed again.**
- **Where the pool's programs come from:** a node puts a program in its
  machine pool in two places only:
  - when it takes the program's install as the agent's leader;
  - at start, for every program pinned then.
- **What a node without it does:** a follower applies the install, and
  pins the program, but leaves it out of its pool.
  - The agent's `instantiate` then answers `WHO`, and the guest builds
    the machine itself, as on a JAM host: `historical_lookup`, then
    `machine` (which parses and validates the whole blob), `pages` and
    `poke`.
  - **The gas differs.**
    - The failed `instantiate` still charges `machine`'s base.
    - Then the guest pays for `historical_lookup` twice (a 256-byte
      head, then the rest: about the blob's length in all), for its own
      copying, and for the loader's calls, which cost what the pool's
      price does.
    - Inner machines are made only in refine, whose output the log
      carries, so replicas never diverge.
    - But a refine's outcome near its gas limit depends on whether its
      leader's pool held the program, and a query's on the node it
      reaches.
- **Where it costs:** until the node restarts, every query on a node
  that never took the program's install, and every refine there once
  it leads.
- **The lever:** the pool loads a stored program on a miss, at the
  same price, so `instantiate` answers alike on every node holding it.

**Slice 2's rows, in process** (`benches/acceptance.rs`, one node):
- 34.7 µs per request under load, of which 26.5 µs is execution;
- one request alone, 2.9 ms;
- a query, median 50.6 µs, p99 151 µs.

They are unchanged.

**Found in CI, and fixed: a property test's check was wrong** (vos-raft,
`tests/proptest_invariants.rs`). It is pre-existing.
- **The old check:** an entry's term could change at an index only if
  the worker's term had advanced since its last observation.
- **What failed:** a random case, a term-0 append, then a term-11 one
  rejected (raising the term), then a term-11 append replacing the entry.
  That is ordinary Raft: a later leader replaces an uncommitted entry,
  its term already known.
- **The check now:** an entry is replaced only when the worker holds a
  later term than the entry's.
- **Not added: committed entries never change.** The test's random
  messages come from senders no real leader would be (a "leader" at
  term 0 commits an entry that one at term 1 then contradicts), and the
  core trusts its leaders.
- **Carried to 3.10c:** whether the core refuses to truncate below its
  commit, as etcd's does (it panics), against a bug elsewhere.
- proptest's regression file keeps the first case.

**Failover and the soak: the baseline** (after the 64-agent rows, on
the same nodes).
- **Failover:** node 3, leading 24 of the 64 agents, is killed. Every
  agent has a leader again 2.63 s later. Restarted, node 3 listens after
  4.29 s, then takes 4% of one core over 10 s.
- **The soak:** 64 agents × 4 sessions, open at 6k/s, twelve windows of
  50 s, after the failover. No call failed, and every agent's counter
  holds every increment it answered, once.

  | Window | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 |
  |---|---|---|---|---|---|---|---|---|---|---|---|---|
  | p99 (ms) | 10.3 | 31.1 | 24.7 | 28.6 | 71.6 | 35.5 | 19.7 | 27.9 | 53.9 | 407.9 | 38.2 | 48.5 |
  | node 1 busy (cores) | 1.93 | 2.15 | 2.12 | 2.09 | 2.14 | 2.08 | 2.07 | 2.10 | 2.11 | 2.12 | 2.24 | 2.31 |

  - p50 stays at 5.3–5.6 ms throughout. Window 2 overlapped a build of
    mine on the same cores.
- **It fails the criterion as it stood** (±10% between the first window
  and the last):
  - CPU per commit rose from 756 µs to 889 µs (+17%), most of it in the
    last two windows;
  - the p99 rose from 10.3 ms to 48.5 ms.
- **The p99 is decided by rare stalls,** not by a rising cost.
  - In every window, a few thousand calls waited on their session's
    previous one: some calls took longer than a session's 43 ms between
    calls.
  - The same stalls appear at 10k/s before the failover (p99 103–117 ms,
    500–700 calls waiting). They put that run's knee between 5k and
    10k/s, where earlier runs had it between 10k and 20k.

- **Its CPU per commit is not the open rows'.** Four sessions an agent
  hold a batch to 4 inputs, where the open rows' batches take 7 to 19.
  So each commit carries more of a batch's fixed cost.
- **Its rise is not explained yet.** Node 1's busy cores went from 1.93
  to 2.31 at the same rate. Three later soaks of 5 minutes rose by 2–7%.
  The bench now splits each window's CPU by thread with fjall's workers
  (flushes and compactions) apart, and the next soak runs 30 minutes, to
  see whether it levels off.
- **The criterion, changed** (the soak's purpose is no growth with
  history, and the p99 is decided by rare stalls):
  - over the clean windows only: the machine ran under 1.5 cores outside
    the run, and every task on it waited on IO under 10% of the window;
    the windows dropped are reported;
  - the median of the first three windows against the last three, for
    CPU per commit, p50 and p95, within 10%;
  - the stalls as a trend of their own: the runtime probe's wakes about
    50 ms late or more and the batches as long (within 10% and one
    more), and the longest batch (within one bucket);
  - one load throughout, each call signed as its session goes, with the
    CPU and the stats read at each window's edges: the nodes never rest
    between windows, so flushes and compactions stay in the windows;
  - 30 minutes by default;
  - the p99 is still each window's, and the budgets judge it, stalls and
    all.
- **Its first continuous run** (5 minutes, disk, no failover before):
  - all six windows clean; fjall's workers now show 1–3% of a core,
    where windows with gaps between them showed none;
  - window 1 had no stall (nothing flushed yet), then about six runtime
    stalls a window;
  - p95 6.4 ms in window 1, 17–18 ms after; p50 flat at 5.3–5.6 ms; CPU
    per commit 787 µs, then 831;
  - the verdict: it grows, on the batches of 49 ms or more (26, then 112)
    and the longest batch (131 ms, then 328).
  - Part of that rise is the store reaching its steady state, not
    growth with history: the first windows come before any flush.
- **Carried to the next soak's use** (3.10b0's A/B):
  - the early median starts after a warm-up, once every keyspace has
    flushed;
  - sessions keep arriving: each plan moves to a new session every so
    many calls, as real clients do, so the session rows, the expiry
    index and its sweeps grow as they would;
  - a session that runs out before the first window counts in the
    first, not the last.

**The stalls, found: fjall frees a flushed memtable under its version
lock.**
- **What the stages show:** each stage's largest value (the bench now
  prints p50/p99/max). In a soak window whose p99 is 4.5 ms, the largest
  `queued`, `commit`, `apply`, `resume` and `refine` are still 114–196
  ms. Stalls of 100–260 ms come a few times a minute, on every run.
- **Not the disk:** the same soak on tmpfs (`DATA=/tmp`) has no IO
  stalls (`/proc/pressure/io` reads 0%), and the same stalls, though its
  synced flushes take at most 2 ms in some of those windows.
- **Not the machine:** what else ran stayed at 0.2–1.3 cores (`/proc/stat`
  less the run), the nodes were far from busy, and memory pressure was
  nil.
- **Where:** node 1 sampled at 499 Hz with its stacks for 120 s of the
  soak (`perf record --call-graph dwarf`, no samples lost).
  - Four times, its runtime thread, its writer and its executors all go
    without a sample for 110–160 ms at the same instant, while fjall's
    workers run.
  - In each gap, one fjall worker is flushing a memtable to a table
    (`fjall::flush::worker::run`), and another is dropping sealed
    memtables (`drop_in_place<Vec<Arc<Memtable>>>`, freeing every
    skiplist node).
- **Why it blocks everyone:** lsm-tree 3.1.10's `register_tables` takes
  the tree's `compaction_state` lock, then its `version_history` write
  lock. Under both:
  - **The version's upgrade:** `persist_version` syncs the version file
    and its directory, then `rewrite_atomic` replaces `CURRENT` (a
    synced temporary file, a rename, a sync, a directory sync). Five
    syncs a version, under the lock.
  - **`maintenance`** pops the versions older than the watermark. The
    one holding a flushed memtable's last reference frees that whole
    skiplist there: a 64 MiB memtable, fjall's default, is about a
    million nodes.
  - **Every reader and writer waits:** `get`, ranges and `append_entry`
    take the same lock to read. The log keyspace takes every Raft
    append, so a stall there stops the writer, and with it every agent
    on the node.
  - **Compactions do the same:** the compaction worker upgrades versions
    and runs `maintenance` under the write lock too.
  - **No node thread can be the one to free it:** a version below the
    watermark has no live snapshot, and while a snapshot lives, the
    history holds its version.
- **How often:** each keyspace's memtable fills and flushes every few
  tens of seconds under load, so a node stalls a few times a minute.
  Every agent on the node shares the keyspaces, so every agent stalls.

**The levers, in the order 3.10b takes them** (by the attribution above;
each by 3.10b's method):
0. **No memtable freed under fjall's version lock.** It decides the p99
   and the knee, so it comes first, with its own design and review.
   - **The fix:** `maintenance` returns the versions it popped, and
     every caller (flush, compactions) drops them after its locks.
     - A patch to lsm-tree, through `[patch.crates-io]`, offered
       upstream.
     - It is one more thing to remove before master, as vos-raft's
       copy is.
     - Before patching, the stacks confirm the chain: the drop under
       `maintenance`, under `register_tables`.
   - **Measured beside it, in the same A/B:**
     - smaller memtables: shorter stalls, but more flushes, so more
       version upgrades with their syncs and more level-0 tables. fjall
       keeps each keyspace's size from its creation, so a change takes
       new keyspaces; the log keyspace is the hot one;
     - an allocator whose frees from another thread are cheap. It would
       shorten the free, and libc's allocation is 13% of a loaded node.
       But it changes the whole process, and the free still happens
       under the lock.
   - **What stays:** the five syncs under the lock at every flush and
     every compaction. Measured apart, disk against tmpfs, after the
     fix.
   - **Its measure:** the soak's stalls and largest stage times, against
     the baselines above, and a soak of 30 minutes first.
1. **`instantiate` loads a stored program the pool lacks,** at the same
   price. Queries on a node that never took the install, and refines
   there once it leads, run pooled, and every node charges the same gas.
   With its own design and review.
2. **A cache of decompressed verifying keys,** bounded. Small by the
   microbenchmark; kept only if it moves the node's numbers.
3. **Store reads scoped to a batch** (3.10b's first candidate).
4. **The driver's durable writes, answered later,** so a round goes on
   while the writer syncs. With its own design and review.
5. **Cheaper signature checks:** batch or non-strict verification,
   keeping the strict check's semantics. With its own design and review.
6. **A cheaper refine per input, then pipelined refines,** once the
   single agent's open-loop capacity is measured again. Pipelined
   refines have their own design and review.

**Moved:** TLS and table reads under writes are measured in 3.10c, with
the final numbers. Failover and the soak run twice: a baseline now, and
again at the end.

#### 3.10b The levers: designs

Each lever below was reviewed before it was built (Opus 5.5).

#### 3.10b0 Design: no memtable freed under fjall's version lock

**The defect** (3.10a2's attribution): lsm-tree 3.1.10 frees a flushed
memtable while it holds the tree's `version_history` write lock. Every
reader and writer of that keyspace waits, 110–160 ms for a 64 MiB
memtable on the reference laptop, a few times a minute under load. The
log keyspace takes every Raft append, so its stall stops every agent on
the node.

**The fix, in lsm-tree:** `SuperVersions::maintenance` returns the
versions it pops instead of dropping them. Each caller drops them after
its guards:
- the flush's `Tree::register_tables` (after `version_lock` and
  `compaction_state`);
- the compaction worker's three version upgrades: returned up to the
  worker's top, past `compaction_state` too. No reader or writer takes
  that lock, but a flush's registration does, so a free under it would
  still hold a flush back by the free's time, toward fjall's write
  backpressure;
- the two ingestions, which call it with a watermark of 0 and pop
  nothing, take the new signature only.

The popped versions are then freed on fjall's own worker thread, as
now, with no lock held. A table a popped version held, marked deleted,
is unlinked there too.

**What does not change:** which versions are popped, when, and what a
reader sees. A version below the watermark has no live snapshot, and a
live snapshot keeps its version in the history, so no node thread ever
drops one; the patch only moves the drop past the guards.

**How it is carried:**
- `support/lsm-tree`, lsm-tree 3.1.10's published source with the patch,
  and `[patch.crates-io] lsm-tree = { path = "support/lsm-tree" }` in the
  workspace.
- Its tests and fjall's run in `just ci`.
- A removal item for the cleanup before master, as for vos-raft's copy:
  replaced by an upstream release with the fix.
- An upstream issue and pull request, drafted here for the owner to
  file. The draft also notes that the version's syncs could be prepared
  before the lock is taken.

**First, the chain confirmed:** node 1 sampled again with deeper stacks
(`--call-graph dwarf,65528`) on fjall's workers, until a sample in a
stall shows `drop_in_place<SuperVersion>` under `maintenance` under
`register_tables` (or the compaction worker).

**Tests:**
- in the patched lsm-tree:
  - `maintenance` returns the versions it pops, and the history no
    longer holds them;
  - a flush releasing a memtable large enough that freeing it takes
    50 ms or more, with no snapshot left open (so the popped version
    holds its last reference), and `get`s timed on another thread
    throughout: the longest waits under half the free, which the same
    test times, so the margin is checked and CI's load does not make it
    flaky;
- in the node: none new; the soak measures it.

**Measured** by 3.10b's method, staged, as the effect is large (stalls
of 100–160 ms a few times a minute against none):
- **A against B,** three interleaved 6-minute soaks each, one load
  throughout, on the reference pinning and disk (`ROWS=soak`, the 64
  agents without their rows). Each gives the stalls per window (runtime
  wakes and batches of about 50 ms or more), the longest batch, p95, p99
  and CPU per commit. **B is kept if its stalls and longest batch move
  past A's spread.**
- **Smaller memtables** only if the owner declines the patch: once the
  free leaves the lock they only multiply flushes, and the syncs with
  them.
- **mimalloc** later, as a CPU lever by 3.10b's method (instructions and
  CPU per commit), not as a stall fix.

**What stays after it:** the five syncs under the lock at every flush
and compaction, measured apart: B on disk against B on tmpfs.

#### 3.10b1 Design: `instantiate` loads a program its agent pins

**The gap** (3.10a2's attribution): a node adds a program to its machine
pool only when it takes the install as the agent's leader, and at start
for every pinned program. Elsewhere `instantiate` answers `WHO`, and the
agent builds the machine from the blob on every run: `historical_lookup`
twice, `machine` (a whole parse and validation), `pages`, `poke`.
- **CPU:** on a follower answering queries, that parse is about 16% of
  the node's CPU.
- **Gas:** the fallback costs more: `instantiate`'s base, then two
  lookups (a head, then the rest: about the blob's length in all), the
  guest's copying, then the loader's calls, which cost the price.
  - Replicas never diverge, since inner machines are made only in
    refine, whose output the log carries.
  - But a refine's outcome near its gas limit depends on whether its
    leader's pool held the program, and a query's on the node it
    reaches.

**The rule: the pool is a cache that `instantiate` fills.**
- **A source, per run:** `RefineContext::with_programs`, a function from
  a code hash to the program's bytes. The node's gives the blob only if
  the running agent pins it (its pin row, `pin_key(hash, agent)`), so
  the pool stays what pins make it, as at a restart; any other stored
  blob, however valid, is no program of this agent's.
- **Its answers:** `Ok(Some(bytes))`, `Ok(None)` (not this agent's, or
  not stored), or `Err` (the store could not be read).
- **On a miss,** `instantiate` asks the source:
  - **bytes:** checked against the hash asked for (a corrupt store
    installs nothing), installed, and then as for a hit: the same base,
    the same `price()`;
  - **none, or bytes that are not a valid program:** `WHO`, as today;
  - **an error:** the run faults, as other store reads do. Answering
    `WHO` instead would send the guest down the fallback, with its gas.
- **So the gas is the same on every node:** every replica holds the
  blobs its agent pins, so for an agent's own programs `instantiate`
  answers alike everywhere, by construction.
- **Loading on an executor:** `instantiate` already runs there, inside
  refine. Two misses at once may both parse; the first install wins and
  the other's copy is dropped.
- **The first run after a miss** pays the parse and, on the recompiler,
  the build of the prepared code: once per program per node.

**Whose programs:** the pin check applies on a miss, not on a hit. Any
program in the node's pool can be instantiated by its hash, whichever
agent pinned it.
- That holds because `instantiate`'s only caller is the node's own
  agent program, which names only its agent's installed programs.
  Actors cannot reach it.
- So the check on a miss is a defense. A guest naming another agent's
  program would get an answer that depends on the node; that case
  belongs with the isolation question carried below.
- Hits are not checked: the leader's install pools its programs before
  their pins exist.

**Eviction:** after a committed change set with an unpin (an apply whose
writes touch the installed rows, a snapshot switch, a retirement), each
program unpinned that no agent here still pins leaves the pool, as a
restart would leave it. A race with a new pin costs at most a reload on
the next miss, at the same gas, so no lock is needed.

**What does not change:**
- The leader's install still adds its programs before the entry
  commits. One that never commits stays pooled until restart or its
  eviction: memory only, since the guest instantiates installed
  programs.
- Machines lent when a program leaves the pool are dropped on return
  (`MachinePool::release`).
- A context without a source (JAM, and every test that sets none)
  answers `WHO` on a miss, as now.

**Carried, for the owner, out of this step:** `historical_lookup`
answers any hash in the node's blob store, whatever the agent. An agent
that knows a hash can read another agent's blobs, programs or a large
entry's. It is an isolation question.

**Tests:**
- vos-pvm:
  - a refine instantiating a program its pool lacks but its source holds
    uses exactly the gas of one whose pool holds it, and the program is
    pooled after;
  - a source answering none answers `WHO`, as does one giving an invalid
    program or bytes of another hash;
  - a source erring faults the run.
- node:
  - a follower that never took an agent's install holds its program in
    the pool after its first query;
  - a leader elected later holds it after its first refine;
  - a program pinned only by another agent is not loaded;
  - the pool drops a program once the last agent pinning it retires,
    keeps one another agent still pins, and reloads an evicted one on
    its next use.

**Mutations:** without the miss path, the first vos-pvm test and the
follower test fail; without the pin check, the other-agent test; without
eviction, the retirement test.

**Measured** by 3.10b's method, five interleaved runs a variant:
- the query row's marginal cost on the follower (2k and 6k/s), against
  about 420–470 µs now;
- the single agent's closed-loop throughput with its leader moved to a
  node that never took the install.

#### 3.10b0 Built: memtables freed off the version lock

**The design changed once it was measured.**
- **The first shape** (`maintenance` returning what it popped, for
  lsm-tree's callers to drop after their locks) changed nothing: one
  soak each on tmpfs, 4.8 runtime stalls a window against 5.0.
- **Why:** fjall calls `maintenance` itself. `Keyspace::inner_rotate_memtable`,
  on a fjall worker after every memtable rotation, runs
  `keyspace.tree.get_version_history_lock().maintenance(..)` on every
  keyspace. The guard is a temporary of that statement, so whatever it
  returned was dropped under the lock. That rotation is where the gc
  watermark moves up, so it is where most flushed memtables lose their
  last reference.
- **Ruled out on the way:**
  - glibc's heap trimming (`GLIBC_TUNABLES=glibc.malloc.trim_threshold`
    at 16 GiB): 4.8 runtime stalls a window;
  - mimalloc alone: 4.7, since the free stays under the lock.

**The shape now** (`support/lsm-tree/src/version/super_version.rs`, the
only source that differs from lsm-tree 3.1.10):
- a version `maintenance` pops has its memtables sent to a thread of
  their own (`lsm-release`, started on first use), which frees them. No
  caller changes, fjall's included;
- its tables are dropped where it is popped, as before. A deleted table
  removes its file when dropped, and removed later, on that thread, the
  file could already be a reopened tree's: the cluster tests and the
  checker reopen nodes in one process, and recovery restarts table ids
  at the highest live one plus one;
- with no thread, the memtables are freed where they are popped, as
  before.

**Carried as a patch:**
- `support/lsm-tree`, outside the workspace (its own empty `[workspace]`;
  excluded in the root manifest), taken through `[patch.crates-io]`;
- its tests run in `just test`;
- `VENDORED.md` says what differs and when the copy goes;
- `UPSTREAM.md` holds the issue, and two fixes for upstream to choose
  from (callers dropping what `maintenance` returns, fjall's included;
  or the release thread), for the owner to file.

**The test** (`tests/released_versions.rs`):
- A memtable is grown until freeing it alone takes 50 ms or more here;
  on a machine too fast for 12 M items, the test says so and passes.
- A tree flushed with a watermark of 0 keeps the versions holding that
  memtable. A small flush with every version below the watermark then
  pops them, while a thread times `get`s until the memtable is gone, and
  through the free's length after.
- Unpatched, a read waits 102 ms through a 103 ms free, and the test
  fails. Patched, it passes, in debug and release, with the crate's 236
  unit and 23 doc tests.

**Measured** (`ROWS=soak SOAK_SECONDS=450 SOAK_WARMUP=150`, the 64 agents
at 6k/s, continuous; `soak steady` over the windows after the warm-up):

| Run | Runtime stalls a window | Batches ≥ 49 ms a window | Longest batch | p95 | p99 | CPU per commit |
|---|---|---|---|---|---|---|
| tmpfs, A (published) | 5.0, 5.0, 4.8 | 134, 165, 131 | 328, 262, 328 ms | 3.33–3.35 ms | 39, 50, 34 ms | 682, 683, 676 µs |
| tmpfs, B (patched) | 0.0, 0.0, 0.0 | 87, 103, 91 | 164, 164, 197 ms | 3.29–3.41 ms | 4.1, 4.2, 3.8 ms | 710, 714, 676 µs |
| disk, A | 5.3 | 263 | 655 ms | 23.6 ms | 250 ms | 815 µs |
| disk, B | 0.7 | 263 | 524 ms | 22.7 ms | 101 ms | 807 µs |

- **On tmpfs it holds in every pair:** no runtime stall, and p99 from
  34–50 ms to 3.8–4.2 ms. Kept.
- **CPU per commit** is within A's spread, though twice higher: freeing
  nodes allocated in the writer's arena takes that arena's lock, so the
  free contends a little with the writer.
- **mimalloc** (screening, one soak each): with the patch, p99 3.6 ms and
  CPU per commit 661 µs; alone, 656 µs. A CPU lever, taken later by
  3.10b's method.
- **The pairs above** ran a build that sent whole versions to the
  thread, tables too. The final shape, memtables only, measured on its
  own (one soak each):
  - tmpfs: no runtime stall, 96 batches of 49 ms or more a window, the
    longest 164 ms; p95 3.35 ms, p99 3.98 ms; CPU per commit 689 µs;
  - disk: no runtime stall, 184 batches a window, the longest 229 ms;
    p95 17.0 ms, p99 41 ms; CPU per commit 850 µs.
  - So deleted tables unlinking under the lock again, as published,
    costs nothing seen: on disk it does no worse than the whole-version
    build (p99 101 ms, longest batch 524 ms).
  - Every agent's counter held every increment it answered, once.

**What remains:**
- **On tmpfs:** about 90 batches a window of 49 ms or more (under 0.1%
  of batches). The writer's synced flushes reach 57 ms there, where a
  sync costs nothing, with propose, commit and apply stretched behind
  them, and the runtime on time (`late` at most 6 ms). That is fjall's
  write path: its throttles (writes sleep 100 ms at a time while four
  sealed memtables wait; they spin once level 0 holds 20 runs), or its
  journal's work.
- **On disk, ext4's journal.** Each thread's kernel wait point
  (`/proc/<pid>/task/<tid>/wchan`, sampled each millisecond) shows the
  writer waiting on the journal's commit (`jbd2_log_wait_commit`) most of
  the time, and during a flush up to 180 ms in `do_get_write_access`,
  behind the commit carrying the flushed table's data (ordered mode).
  Tables are written whole and synced once at the end, by flushes and
  compactions alike. The next step: progressive writeback (RocksDB's
  `bytes_per_sync`), smaller memtables, or both, by their own design.

**The 30-minute soak, before the patch** (disk, continuous, the 64
agents at 6k/s, 36 windows, all clean):
- CPU levels off: each node busy 1.6–1.9 cores from the second window to
  the last, CPU per commit 827 µs early and 854 µs late.
- p50 rises over the run: 5.3 ms, then 6.0, 6.6, 6.9 and 7.3 ms by the
  last windows, at a fixed rate and with CPU per commit flat.
- The stalls run throughout: 6.3 runtime stalls and 270 batches of 49 ms
  or more a window, the longest batch 786 ms, p99 131 ms at the median.
  Its verdict, "grows", is mostly the stall.

**Open, in order:**
1. **The disk's stalls** (ext4's journal behind table writes): the next
   lever, with its own design.
2. **The p50 creep:** 5.3 ms to 7.3 ms over 30 minutes at a fixed 6k/s,
   CPU per commit flat. Growth with history, apart from the stalls; the
   soak after the next lever shows whether it remains, then it is found.
3. **fjall's write path on tmpfs:** the writer's synced flushes up to
   57 ms with nothing to sync.

**Carried, for the owner:** `historical_lookup` answers any hash in the
node's blob store, whatever the agent: an isolation question (from
3.10b1's review).

#### 3.10b1 Built: `instantiate` loads a program its agent pins

**vos-pvm** (`refine_host.rs`):
- `ProgramSource`: where `instantiate` finds a program its pool lacks,
  set per run with `RefineContext::with_programs`.
- On a miss, `instantiate` asks it. Bytes of the very program asked for
  (their code hash checked) and a valid program are installed in the pool,
  then lent as a hit is, at the same base and the same `price()`.
  Anything else answers `WHO`, as a missing program does.

**The node:**
- **Its source** (`pvm.rs`, `AgentPrograms`): the blob, only if the
  running agent pins it (`Blobs::pinned_by`). A store it cannot read
  panics the run, as refine's other reads do, and the executor turns that
  into a fault.
- **Eviction:** after a committed change set that unpins (an apply that
  touches the installed rows, a snapshot switch, a retirement), each
  program no agent here still pins (`Blobs::pinned_by_any`) leaves the
  pool (`Inner::evict`). No lock: a pin made meanwhile costs a reload.
- `Node::pooled`, whether the pool holds a program.

**Tests:**
- vos-pvm: a program loaded from the source costs exactly the gas an
  installed one does, and is pooled after. A source with nothing, with an
  invalid program, or with another program's bytes answers `WHO` and
  pools nothing.
- node, unit: an agent loads a program it pins, not one only another
  agent pins.
- cluster:
  - replicas that never took the install hold the program in the pool
    once they run it: a leader elected later at its first call, a
    follower at its first query;
  - the pool keeps a program another agent still pins, drops it once the
    last pinning agent retires from the node, and holds it again once it
    is pinned and run there again.
- **Mutations**, each caught:
  - without the miss path, both cluster tests and the vos-pvm test fail;
  - without the pin check, the unit test;
  - without eviction, the retirement test;
  - with eviction ignoring other pins, the retirement test too.

**Measured** (the query row: one agent, 16 sessions querying a follower
that never took its install, at 2k and 6k/s; five runs a build,
interleaved, lever 0's build against this one):

| Build | The follower's CPU per query (from the two rates) | At 6k/s: p50 | p99 | The follower's busy cores |
|---|---|---|---|---|
| before | 407, 411, 434, 413, 407 µs | 0.41–0.42 ms | 0.59–0.67 ms | 2.31–2.43 |
| loading on a miss | 90, 104, 95, 101, 105 µs | 0.13–0.15 ms | 0.22–0.24 ms | 0.77–0.85 |

- **A query costs the follower a quarter of what it did.** That is far
  more than the parse (16% in the profile): the whole fallback went too,
  the two lookups copying the blob into the guest, the machine laid out
  by host calls, the prepared code looked up by the blob's bytes.
- **Not measured:** the single agent's throughput with a leader elected
  after the install. The bench has no such row, and the cluster test
  shows that leader pooling the program at its first call.
- Slice 2's in-process query (50 µs) was always pooled: the gap left over
  HTTP is the signature check and the transport.
- **Found while gating it, already in the code before:** under heavy load
  (three copies of the exactly-once tests at once), those tests fail on
  the commit before this step as often as on this one:
  - an executor thread panics joining itself: the last owner of the
    executors dropped on one of their own threads;
  - "no node caught up by a snapshot": a coverage check the load can
    defeat, as fewer requests leave every log short of compaction;
  - once, in a loaded `just ci`, a restarted node answered `NoAgent` for
    agents it replicates, not reproduced since.
  The next step fixes the first two and looks for the third.

#### The exactly-once tests under load: two fixes

Found while gating 3.10b1, and already in the code before it: three
copies of the exactly-once tests at once, with the seed `just ci` uses,
failed on the commit before 3.10b1 in four copies out of nine.
- **An executor thread joined itself.** The executors' last owner (the
  node's state) went with a job one of them ran, and their `Drop` joined
  every executor thread, that one included: `EDEADLK`, which std turns
  into a panic. `Executors::drop` now leaves the current thread to end on
  its own. A unit test hands the last owner to a job; with the old join
  it panics exactly so.
- **"No node caught up by a snapshot".** The check holds only if some
  fault happened to keep a node down while the log compacted past it;
  under load the clients go slower and it may not. A fault at three
  quarters of the schedule now stops a follower and keeps it down until
  its leader's log starts past the follower's last entry (at most a
  minute), so its restart is by a snapshot under any load.
- **A cluster test read a replica before it caught up.** The backlog
  test stops both of an agent's replicas right after its install, starts
  them again, and polls one for the count. A replica not yet holding the
  install again answers its query with an unknown instance, which the
  test's reader took for a failure. The poll now counts that as nothing
  yet, until its deadline. (Its `just ci` failed so once.)
- **Since:** nine loaded copies, none failing either way. One failed to
  bind an address another cluster's port picker took, in another copy
  or a parallel test in the same binary.
- **Not reproduced:** the `NoAgent` a restarted node answered once in a
  loaded `just ci`, in 24 loaded copies across these runs. The directory
  is rebuilt from synced records at open, so it should not happen; it
  stays on the open list until it recurs or is explained.


#### 3.10b2 Design: table writes reach the disk as they go

**The stall left** (3.10b0's measurements, on ext4 after levers 0 and 1):
on disk, about 184–263 batches a window take 49 ms or more, the longest
229–524 ms, p99 41–101 ms, where tmpfs has 4 ms. Each thread's kernel
wait point:
- the writer waits on ext4's journal commit (`jbd2_log_wait_commit`)
  for most of its time: nearly every sync it makes commits, since it
  changes the journal file's mtime and writes into the sparse journal;
- during a table's flush, up to 180 ms in `do_get_write_access`: the
  BH_Shadow wait, for a metadata block (most likely the inode-table block
  holding the journal file's inode) that the committing transaction is
  writing to ext4's journal;
- meanwhile a fjall worker waits on page writeback, then on a commit.

**Why, on this mount** (`dioread_nolock`, `delalloc`, `data=ordered`):
- With `dioread_nolock`, delalloc blocks are allocated as unwritten
  extents and converted when their I/O completes, so no transaction
  carries a table's data (the kernel's code says so; jbd2's averages
  since mount agree: 0 ms flushing ordered data, about 1.2 ms and 3
  blocks a commit).
- So the 180 ms is most likely one small journal write waiting in the
  drive's queue,
  behind a table's tens of megabytes. A table is written whole into the
  page cache, and its final `sync_all` (`table/writer/mod.rs`, `finish`)
  submits all of it at once, or the next commit's cache flush drains it.
- So the lever works through the drive, not through jbd2: spread a
  table's writes, and the queue a commit waits behind stays short.

**The change, in the vendored lsm-tree's table writer:**
- After each data block, once a megabyte or more has reached the kernel
  since the last time, it writes that range back:
  `sync_file_range(fd, from, to - from, flags)`, `to` rounded down to
  4 KiB, never a zero length (which means to the end of the file).
- **Two variants, measured from the start:**
  - **write:** `SYNC_FILE_RANGE_WRITE`, as RocksDB's `bytes_per_sync`:
    starts the range's writeback and returns. It bounds nothing if the
    writer outruns the drive;
  - **bounded:** `SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE`
    over `[0, to)`, as RocksDB's `strict_bytes_per_sync`: it first waits
    for everything before to be written, so at most a megabyte or two
    of a table is ever queued. One wait a megabyte, on a fjall worker.
- **Every error fails the table write.** With a wait, the kernel reports
  a writeback error there and advances the file's error cursor, so the
  final `sync_all` would not report it again: logging it and going on
  could install a table whose blocks were lost. Without a wait the error
  would still reach the final sync, but both variants fail the same way.
- The final `sync_all` stays, so what is durable when does not change.
- The descriptor: `file_writer.get_mut().inner_mut().get_ref()`; the
  bytes in the kernel: the writer's offset less the `BufWriter`'s
  buffered bytes (no seek, which would flush it).
- Linux only (`libc`, a Linux-only dependency); elsewhere, nothing.
- Every table the node writes goes through this writer, on a fjall
  worker: flushes, and compactions (64 MiB tables, the larger source of
  bursts). A snapshot's rows are staged in ordinary batches, so they
  reach tables by flushes too.
- A failed table write fails the fjall worker, which poisons the
  database, and the node halts: as a failing final sync does today, so
  only where the error is seen is new.

**What does not change:** a table's bytes, when it is durable, and the
order of anything.

**The A/B's builds:** fjall builds lsm-tree's settings itself, so a
variant cannot be chosen from the node. Each arm is a build with its
variant as a constant. After the A/B the winner stays and the loser is
deleted, with its tests. **The rule, set now:** bounded is kept unless
write does better on the tail in every pair, as bounded's limit does not
depend on the drive's state.

**Considered, and not taken:** smaller memtables. They shrink only
flushes' tables: compactions still write 64 MiB tables, and more level-0
runs mean more compaction.

**Tests** (the writer's unit tests, in `src/`, where a test-only counter
and hook are visible):
- A table of several megabytes reads back whole, through a reopen.
- What was written back, checked on a live writer before `finish`: the
  synced-to offset is 4 KiB-aligned and only grows; it never passes the
  file's size as the filesystem reports it (`metadata().len()`, the bytes
  written so far, an independent oracle); and it reaches at least the
  size less the threshold and the buffer (64 KiB).
- The error path, through an injected range sync that fails: the table
  write fails.
- The stall itself is measured, not unit-tested.

**Measured:** on disk, kept quiet (no builds or tests on it during the
soaks), three interleaved 7.5-minute soaks each of lever 1's build,
**write** and **bounded**:
- judged on the tail: batches of 49 ms or more, the longest batch, p99,
  the runtime stalls a window, and the writer's longest
  `do_get_write_access` run; p50 reported too (flat, or a little up);
- the writer's long waits split by wait point, jbd2's against futexes:
  the lever also shortens a compaction's finish under the version lock,
  and without the split a gain there would be credited to the drive;
- the jbd2 wait share is not the test: every sync commits today either
  way;
- the mechanism checked: `/sys/block/nvme0n1/inflight` sampled each
  millisecond beside the wait points. The long waits should line up with
  a queued write backlog without the lever, and not with it.
- All three nodes share one drive and one ext4 journal, and replicas
  flush nearly together: the absolute counts are a shared-disk worst
  case.

**Found on the way, not in this step:**
- **A compaction finishes its last table under the version write lock**
  (`compaction/worker.rs`: `finish`'s `sync_all`, the directory sync and
  the table's recovery, under `version_history.write()`), so reads and
  rotations on that tree wait for it. This lever shortens that hold; the
  hold itself is its own lever (finish before taking the locks), and
  could go upstream.
- **fjall's journal syncs** (the larger lever for the writer's routine
  latency, after this one): preallocating the journal with written
  extents (`FALLOC_FL_WRITE_ZEROES`) and syncing data only would take
  most commits off the writer's path. It touches fjall. Even then,
  `write()` journals the mtime change about once a millisecond, and the
  same BH_Shadow wait can still occur unless the filesystem is mounted
  `lazytime` (this root filesystem is `rw,noatime`): a deployment note.

**Upstream:** `bytes_per_sync` and `strict_bytes_per_sync` settings, in
`UPSTREAM.md`.

#### 3.10b2 Built and measured: not kept

**Built as designed:**
- each megabyte written back after a data block, in the two variants;
- every error failing the table write;
- unit tests on the synced-to offset against the file's real size, and
  on an injected failure;
- a read-back test through a reopen.

Three mutations (never writing back, swallowing the error, ignoring the
buffered bytes) each failed a test.

**Measured** on disk, quiet, three interleaved 7.5-minute soaks of each
build (`soak steady`, after 150 s of warm-up):

| Build | Batches ≥ 49 ms a window | Longest batch | p95 | p99 |
|---|---|---|---|---|
| 3.10b1's | 100, 274, 264 | 328, 459, 524 ms | 19.6, 28.8, 24.6 ms | 31, 220, 68 ms |
| write | 245, 115, 183 | 655, 786, 786 ms | 23.3, 26.8, 25.2 ms | 144, 378, 316 ms |
| bounded | 182, 266, 268 | 262, 393, 197 ms | 23.4, 30.9, 52.4 ms | 50, 178, 356 ms |

- **write is worse:** its longest batch passes every run of the build
  before it.
- **bounded does not move past the spread:** the counts of long batches
  and the p99 overlap entirely. Its longest batch is the lowest of the
  three in every round (262, 393 and 197 ms), but the p99 and the counts
  do not follow: suggestive, not shown.
- **By the rule set before measuring,** neither is kept. The code is
  reverted; this design and these numbers are the record, and nothing
  goes to `UPSTREAM.md`.
- **Not run:** the design's mechanism measures (the writer's longest
  `do_get_write_access` run, the drive's requests in flight beside it,
  p50). With neither variant kept they could not change the outcome.

**Why the measurement could not decide:**
- The runs vary more than any effect. The same build gives p99 31 ms in
  one run and 220 ms in another.
- Every build drifts worse through the session (p95 from about 20 ms to
  30–50 ms, CPU per commit from about 1,000 to 1,270 µs).
  - The drive's own state fits the latency: DRAM-less, 89% full, mounted
    without discard, so each soak's deleted store is never trimmed.
  - It does not explain the CPU, as a slow drive adds waiting, not work.
    That could be fjall's write throttle (it spins once level 0 holds 20
    runs, as compactions fall behind a slower drive), heat, or memory
    pressure.
  - Repeated tmpfs soaks over one session would tell the machine's drift
    from the drive's.
- A soak is slow to count rare events: a fresh store flushes nothing for
  its first minutes, and a 64 MiB memtable flushes a few times a minute.

**For any later disk lever** (fjall's journal first), the measurement
comes first:
- more events a minute, and a shorter warm-up, from a bench setting of
  smaller memtables, with any result confirmed at the default sizes;
- the writer's own synced-flush times (the `flush_synced` stage) as the
  primary measure, closer to the cause than whole batches;
- and a drive in a known state (`fstrim` before each round).

#### The exactly-once tests under load: the review's follow-ups

- **A node's teardown no longer outlives it.** `stop` now closes the
  executors after the runtime threads, waiting for the jobs already
  taken. Before, jobs left over (a signature check, a log load, a
  snapshot export) could still hold the node's state, with its store and
  the store directory's lock, after `Node::drop` returned. An in-process
  restart could then find the store locked. That late teardown was what
  joined an executor thread from itself.
- **A signature check holds only the stats it records,** not the node's
  state (`Inner::stats` is shared).
- **The blob writer holds only the waiters it notifies,** so it never
  holds the blob store's last reference. Before, it held it while
  notifying, and dropping it there would have joined the writer from
  itself, the same bug.
- **The follower-down fault is never skipped silently.** It waits up to
  10 s for a leader and a follower, and logs a skip, or a minute run out,
  as such.
- **The backlog test counts only an unknown instance as "not yet".**
  Anything else fails it at once, as before.
- **Shutdown now waits for the executors' jobs in flight.** A refine runs
  to its end, bounded by its gas; a test hook that holds one must let it
  go before its node stops.
- **Tests:** closing waits for the jobs taken, and takes none after it;
  and a node stopped while a job holds its state opens again on the same
  directory at once. Without the close in `stop`, that open fails with
  the store locked.

#### 3.10b3: mimalloc as the node's allocator

**Why:** libc's allocation was 13% of a loaded node's CPU in 3.10a2's
profile, and in 3.10b0's screening mimalloc lowered CPU per commit by
4–7%.

**The verifying-key cache** (lever 2 in the order) is skipped on
3.10a2's microbenchmark: a cached key saves nothing measurable on a
P-core.

**The change:**
- `vos-cli`'s default feature `mimalloc` makes it the `vos` binary's
  global allocator. A build without the feature keeps the system's, which
  heap tools (heaptrack, valgrind, sanitizers) see.
- With it, the binary turns transparent huge pages off for its process
  at start (`PR_SET_THP_DISABLE`), as mimalloc's own `allow_thp=0` does.
- vos-node's unit and integration tests run on mimalloc too, as the
  binary does.
- The crate builds mimalloc 3.3.2.

**Measured** on tmpfs: the 64 agents at 6k/s, continuous; 5-minute
soaks with 100 s of warm-up, four steady windows each; interleaved. CPU
per commit and memory are from the bench; instructions and cycles from
`perf stat` (user space only: the kernel's counts are not open to an
unprivileged user here) over the steady windows.

(The cycles and instructions here are `perf stat`'s scaled sums, about twice the counts executed: see "Perf's counts on this CPU were scaled", below.)

| Build | Runs | CPU per commit | Cycles per commit | Instructions per commit | p99 | Resident per node |
|---|---|---|---|---|---|---|
| system allocator | 8 | 821–874 µs | 2,471k–2,520k | 2,289k–2,300k | 4.9–6.7 ms | 452–456 MiB |
| mimalloc | 5 | 759–790 µs | 2,369k–2,391k | 2,267k–2,272k | 4.1–4.6 ms | 530–544 MiB |
| system allocator, no huge pages | 3 | 844–857 µs | 2,538k–2,551k | 2,292k–2,293k | 5.4–7.2 ms | 449–453 MiB |
| mimalloc, no huge pages | 6 | 763–787 µs | 2,414k–2,431k | 2,268k–2,273k | 4.3–4.7 ms | 483–491 MiB |

- **mimalloc does about 8% less CPU per commit,** with or without huge
  pages: about 5% fewer cycles a commit (4% without huge pages) for 1%
  fewer instructions, so it saves stalls more than work, and kernel time
  besides. Its p99 is lower too. The ranges do not overlap.
- **With huge pages, it kept about a fifth more memory resident,** past
  the limit set before measuring (10%). It also split many more huge pages
  (about 800 deferred splits a run against 7).
- **Without huge pages** its memory is 8% above the system allocator's
  (one pair 9.3%), within the limit.
- **Huge pages off is not free:** about 2% more cycles a commit for
  either allocator (2,471k–2,520k against 2,538k–2,551k for the system
  allocator; 2,369k–2,391k against 2,414k–2,431k for mimalloc). The ranges
  do not overlap, though CPU per commit's wider spread hides it. Likely
  TLB misses on the heap and the binary's text.
- **What ships, against what was:** mimalloc without huge pages, against
  the system allocator with them: about 3% fewer cycles and 8% less CPU a
  commit, and 8% more memory (at five minutes). **Kept, without huge
  pages,** subject to the 30-minute soaks below.
- **The tests** run on mimalloc with huge pages off too
  (`MIMALLOC_ALLOW_THP=0` in the `justfile`); ci also lints the build
  without the feature, the one heap tools use.
- **The final build** (mimalloc, huge pages turned off by the binary
  itself), three runs interleaved with the system allocator's three:
  CPU per commit 772, 784 and 776 µs against 827, 828 and 791; p99
  4.3–4.5 ms against 4.8–5.4 ms; 483–494 MiB a node against 452–456 MiB
  (+8%). The binary's nodes report `THP_enabled: 0`.
- **Thirty minutes each** (tmpfs, the same load, after 150 s of
  warm-up): both soaks hold. Steady CPU per commit was 777 µs with
  mimalloc and 835 µs with the system allocator; p99 5.0 and 5.8 ms. At
  the end, mimalloc's nodes held 897–904 MiB and the system allocator's
  924–931 MiB. Both grow with the run's data: the extra 8% after five
  minutes does not last, and after thirty mimalloc holds about 3% less.

#### After levers 0, 1 and 3: where the node stands

**The rows again** (tmpfs, the pinned laptop, this build):

| Row | Before the levers (3.10a) | Now |
|---|---|---|
| one agent, capacity | about 14k/s | about 14k/s (closed 13.7k at 256 sessions; open falls behind at 15k) |
| 64 agents × 16 sessions, closed | 27k/s (disk) | 23.5k/s, every node about 5.1 of its 6 cores busy |
| 64 agents, the knee (p99 ≤ 20 ms) | 5k–20k/s, by the run's stalls | between 15k and 20k/s (p99 14 ms at 15k) |

- **The single agent** is still held by its serial refine: its leader's
  executors run at about 46%, one batch at a time.
- **The 64 agents are now held by CPU:** at saturation every node is
  near its six cores, at about 216 µs of CPU a commit each. The runtime
  thread runs at about 70%, and its probe's lateness reaches 6 ms at p99
  near the knee.

**Where a loaded node's CPU goes** (one node at 15k/s, `perf record`, by
symbol, both core types together):

| Where | Share |
|---|---|
| fjall: memtable lookups (`Memtable::get`, the skiplist search), versions, writes | about 19% |
| signature checks (curve25519's field arithmetic, `calls::verify`) | about 18% |
| libc | about 7% |
| the PVM runtime (its memory permissions and dirty pages, the run loop) | about 7% |
| the async runtime | about 7% |
| the allocator (mimalloc) | about 5% |
| the node's own code | about 4% |
| the network (QUIC, TLS) | about 3% |

**Next, each with its own design:** store reads scoped to a batch (the
memtable lookups), then cheaper signature checks that keep the strict
check's semantics.

**Where the reads and the signature checks go** (a build with frame
pointers and line tables, one node at 15k/s, 152,810 samples):
- **Memtable lookups** (8.5% of samples) by caller:
  - the writer's own inserts searching the skiplist: 3.5% (write cost);
  - accumulate's `write` reading each key's old value to report its old
    length (the JAM call returns it): 2.5%;
  - refine's state reads: 0.7%;
  - accumulate's own reads: 0.7%;
  - the rest (log entries, sessions, the node's checks): about 1%.

  So a memo of rows read, per snapshot, saves the repeats: accumulate
  reading a key and then writing it, and the dry run reading what refine
  read. That is a few percent of the node.
- **Signature checks** (17% of samples):
  - the check's equation (the double-base scalar multiplication): 11.2%;
  - decompressing the caller's key (`VerifyingKey::from_bytes`), at every
    call: 3.4%;
  - other curve work 2%, hashing 0.3%.
- **The microbenchmark was wrong about the key:** in it, a cached key
  saved nothing on a P-core. In the node, decompression is a fifth of
  each check. So the verifying-key cache, skipped in 3.10b3, is back in
  the order, and next: about 3% of a node's CPU, bounded by sessions.

#### 3.10b4 Design: decompressed verifying keys, kept

**Why:** in a loaded node, `calls::verify` decompresses the caller's key
at every check (`VerifyingKey::from_bytes`): 1.7% of the node's samples,
about a tenth of each signature check. (The profile's 3.4% for
decompression counted R's too, which `verify_strict` decompresses
itself; the split is below.) A call is checked once, at the node that
takes it from the client; a leader does not check a forwarded call
again.

**The change:**
- `calls::verify` takes the decompressed key from one cache the node's
  executors share (`quick_cache::sync::Cache`, 0.6.24, already in the
  tree through lsm-tree).
  - Not one per executor: every executor takes jobs from one queue, so
    each would come to hold the same keys, and a session of k calls would
    miss about min(k, executors) times.
  - A hit takes a read lock on one of the cache's shards, tens of
    nanoseconds against the microseconds it saves.
- A miss decompresses as now, and keeps the key.
- A key that fails to decompress is not kept, and fails as now.
- **The bound:** an agent's live sessions, `MAX_SESSIONS` (65,536 keys,
  about 200 bytes each, so about 13 MB at most).
  - The cache is the process's, so every agent on the node shares it.
    A node with many busy agents can outgrow it, and a check whose key
    was pushed out decompresses it again, at today's cost.
  - Random keys can push out real ones, but the cache's admission
    shields keys used again, and its hasher is randomized. The worst
    case is today's cost.

**What does not change:** which signatures pass.
- `from_bytes` only decompresses: a pure function of the 32 bytes, with
  no weak-key check.
- Every strict check runs inside `verify_strict`, at each call: R
  decompressed, R's and the key's small-order checks, and the equation
  over the key's own stored bytes. So a kept key is bit-identical to a
  fresh one.
- The cache is keyed by the encoding, not the point: two encodings of one
  point are kept apart, each with its bytes.

**Tests:**
- a signature passes, and a wrong one fails, before and after its key is
  kept;
- a check uses the key kept for its bytes: kept under other bytes,
  another key's signature passes for them, which only the cache can do
  (the test calls the check, `verify_in`, which `verify` runs on the
  node's cache);
- bytes that are no key fail every time and are not kept;
- the cache stays within its bound (a small instance).

**Measured** on tmpfs, five interleaved 5-minute soaks of each build
(the 64 agents at 6k/s, four steady windows each):
- **primary:** user instructions per commit from `perf stat`, whose
  spread was 0.2% where CPU per commit's was 3–4%;
- CPU per commit, p50 and p99 reported;
- kept if instructions per commit move past the other build's spread;
- the mechanism: one node re-profiled with the frame-pointer build,
  where `from_bytes` should fall to about nothing.

**Also folded:** `benches/verify.rs` corrected, below.

#### 3.10b4 Built: decompressed verifying keys, kept

**The change** (`calls.rs`):
- `verify` takes the key from `KEYS`, a `quick_cache::sync::Cache` of
  `MAX_SESSIONS` keys every executor shares. A miss decompresses and
  keeps the key, and bytes that are no key are not kept.
- The four tests above, the bound on an instance of 8.

**The microbenchmark, corrected** (`benches/verify.rs`):
- **What was wrong:** two single runs, one after the other, the kept
  key's always second. Turbo, heat or a busy sibling between them
  easily outweighed the 3–10 µs a kept key saves.
- **Now:** the variants alternate in blocks of 2,000 checks, 25 blocks
  each, and each reports its median block. It also times a key's
  decompression alone.

| Core | Strict check, key decompressed each time | Key kept | Decompression alone |
|---|---|---|---|
| P-core (CPU 1, its sibling idle) | 36.3 µs | 32.9 µs | 3.2 µs |
| E-core (CPU 12) | 77.0 µs | 66.7 µs | 10.2 µs |

- So a kept key saves 9–13% of a check, about the decompression's cost.
  3.10b3's "nothing measurable on a P-core" is withdrawn.

**Measured:** five interleaved 5-minute soaks of each build, tmpfs, the
64 agents at 6k/s:

(The cycles and instructions here are `perf stat`'s scaled sums, about twice the counts executed: see "Perf's counts on this CPU were scaled", below.)

| | Without (3.10b3) | With the kept keys |
|---|---|---|
| user instructions per commit (three nodes) | 2,241–2,267k, median 2,262k | 2,194–2,206k, median 2,197k |
| user cycles per commit | 2,414–2,457k, median 2,427k | 2,370–2,411k, median 2,394k |
| CPU per commit | 775–904 µs, median 842 | 780–883 µs, median 811 |
| p99, the median run | 5.35 ms | 5.26 ms |
| resident memory a node | 489–495 MiB | 483–500 MiB |

- **Kept:** instructions per commit fell 2.8%, and the two builds' ranges
  do not meet. Cycles fell 1.4%, also without overlap. p99 and memory
  did not move.
- **An upper bound:** the bench's sessions last 1,000 calls, so about
  99.5% of checks hit. Shorter sessions gain less.
- **The mechanism,** in one node at 15k/s with the frame-pointer build
  (154,368 samples), against 3.10a2's profile:
  - the key's decompression fell from 1.73% of the node's samples to
    0.05%, and signature checks from 17.0% to 15.7%;
  - the cache's own lookups drew no samples.
  - **A correction:** the 3.4% "Where the reads and the signature checks
    go" gave the key was both decompressions: the key's (1.73%) and R's
    (1.72%), which `verify_strict` decompresses at every check.
  - The kept key saves more instructions (2.8%) than cycles (1.4%): the
    work it saves ran at about 2 instructions a cycle (between the
    medians, 65k instructions and 33k cycles a commit), against the
    node's 0.92. The 33k is within either build's own range of cycles,
    so the 2 is rough.
- **Batches of 49 ms or more** varied from 0 to 68 a window on tmpfs.
  The high runs were two of each build, and came together in time (run
  2, then runs 7–9): they follow the machine, not the build.
  - Every window of runs 7–9 passed the bench's clean filter (outside
    the run 0.4–0.9 cores, IO stalled 0–0.2%), so other load is not
    their lead. Their cause is open; 3.10b5 reports them per run.
  - The calls that waited on their session's previous one rise with
    them: about 2,300 a run in runs 7–9, about 600 in runs 4–6. At 6k/s
    that is what marks nearly every window "past the knee", by the
    bench's rule. Those waits come from the long batches, not from
    load, so the label is wrong at this rate. The steady CPU per commit
    does not use it.

#### Found in 3.10b4's gates: a replica that missed its record, and no one left to send it

**What failed:** `just ci` failed once in the cluster suite:
`three_nodes_over_quic_replicate_and_fail_over` timed out waiting for a
leader after the first one stopped. The whole suite run 12 times failed
it 3 times; the test alone, or three copies at once, passed 80 of 80. It
is older than the levers.

**What the replicas said** (the harness now prints it when no leader
comes; below):
- node 2: term 1, following node 1, the placement of term 1 committed;
- node 3: no group, and no placement: it never learned of the agent.

**Why** (logs of a failing run, the test in one process and the rest of
the suite beside it for the load):
- node 1 creates the agent on nodes 1, 2 and 3, and is answered once a
  majority, nodes 1 and 2, holds the record. Its first send to node 3
  waited behind a QUIC dial begun before node 3 listened, retried on
  the dial's backoff.
- The test then stopped node 1, the leader too, within the second
  before the creator's resend.
- Nodes 2 and 3 are a majority of the three, but node 3 runs no group,
  so node 2 cannot be elected.
- Node 2 holds the record and the placement, but only an announcer
  sends them: the creator at term 0, a leader after.
- **A second failure, from the same lateness:** `converged` skipped the
  running nodes without the agent. Once node 3 learned of it (from node
  2's leadership, 140 ms after the creation), it could start its group
  between `converged`'s two checks, and its empty rows "differed".

**The gap is known:** 3.5 handed it to 3.7 ("only the creator resends a
creation record, so a node that missed it never learns of the agent if
the creator is lost for good"). 3.7 added the leader's announcements,
which share it: when the announcer stops before a member acknowledges,
no one else sends.
- A majority of live replicas can then be unable to elect, which a
  Raft group promises they can.
- The test only met it because a slow dial and a quick stop came
  together. A replica down at the creation, and a creator lost before
  it returns, meet it every time.

**Fixed in the harness now** (with 3.10b4):
- `converged` waits for every running node the newest placement names
  to run the agent and apply as far as the others, and compares their
  rows. A replica still learning of the agent is waited for, not
  skipped.
- `leader`, on its deadline, reports each running node's replica status
  and placement, and both helpers report their caller's line.
- With it, the failover test establishes its premise, three replicating
  nodes, before it stops the leader. The whole suite then passed 20 runs
  of 20.
- So that test no longer meets the gap. The next step's tests must.
  - Joint configurations: `Placement::replicas` holds both sets while
    joint, so `converged` waits for every member. Once the new one
    commits, the nodes left in `before` are no longer compared. The old
    helper compared a removed replica still running its group, which
    stops applying once removed.
- **The gap itself** is the next step's, with its own design and review.


#### Design: a node asks for the record its group's peers need

**Two ways, weighed** (with the review):
- **Push:** every member sends the placement it keeps to the other members
  until each acknowledges. It needs the creator's and the members' sends
  for one agent merged by order. It also needs a send of every held
  placement at each start, as resends live only in memory: about 2,000
  frames for 1,000 groups of three.
- **Pull, taken:** a node that gets Raft traffic for an agent it runs no
  group for asks the sender for the record and placement. That is exactly
  when the record matters, as the group needs this node's vote or log. It
  covers a lost announcer and restarts alike, with no start-time sends
  and no resend bookkeeping.

**The change:**
- **A new peer message,** `DirectoryRequest { agent }` (requests class, the
  agent's stream).
- **Asking** (`dispatch.rs`, `arrive`): a Raft message for an agent with no
  group here asks its sender, when the directory has no placement for the
  agent or the one held does not admit this node, so a newer one may.
  - Keyed on there being no group, not on the message going unrouted:
    a running group's full inbox also leaves a message unrouted, and
    must not ask for a record it holds.
  - At most once a second per agent and sender. The times asked are
    kept in a map; once it holds more than 1,024, those older than a
    second go.
  - A group refused for another agent program (its placement admits the
    node) does not ask.
- **Answering:** a node holding the agent's record and a placement that
  admits the asker (a creation's placement is its record's replicas,
  committed), and names the node itself, in it or in the configuration
  before, as the asker's check requires, sends
  it an ordinary `Directory`. Anyone else ignores the request. The asker
  acknowledges it as any record. The answer goes to the asker only, and
  takes no resend: the asker asks again.
- **The check,** tightened as the review asked, for a term-0 placement
  relayed by a member: accepted from the creator as now, or from a node
  the record names as a replica when the placement is exactly
  `Placement::created(record)` and the record's creator is the one its
  id names. A relayed creation is then the creator's, whoever relays it.
  A record that differs from the one held is still refused, and a
  placement is kept only if it `supersedes`.

**What does not change:** the creator's and leaders' announcements to
every node, the acknowledgements, which placement is kept.

**Still open, recorded:** a node outside the placement that missed both
the creator's and the first leader's announcements learns of the agent
only at the next leadership change. Until then, calls sent to it for the
agent fail. That is routing, not the group's availability.

**Tests:**
- `a_record_reaches_a_node_that_was_down_from_a_replica`: node 3 down at
  the creation; the creator stopped; node 3 started. Node 2's vote
  requests make node 3 ask; it learns, and nodes 2 and 3 elect and serve.
  It replaces `a_record_reaches_a_node_that_was_down_once_its_creator_restarts`,
  whose "only the creator sends it" no longer holds.
- **`peer::check`:**
  - a term-0 placement relayed by a replica is accepted when it is the
    creation's;
  - one that differs from `Placement::created`, or relayed by a node
    neither its creator nor a replica, is refused.
  - Which placement the integration test relays depends on timing:
    term 0 if no election placed another before the creator stops, else
    term 1. The unit tests cover the relayed creation either way.
- **The rules, as pure functions with unit tests** (no sleeps):
  - `should_ask(held, has_group, me, last_asked, now)`: no ask with a
    group, nor when the placement held admits the node; an ask with no
    placement, or one that does not admit it; at most once a second,
    `now` given; the map trimmed;
  - `should_answer(placement, asker)`: members are answered, others not.
- **The integration test** keeps the wiring: without the ask it fails.
  Its end keeps the replaced test's second half (the creator restarts,
  node 3 converges), so the creator's re-announcement still runs.
- **Why Raft alone triggers enough** (the review): with the leader gone,
  a holder campaigns and its pre-votes reach the node every round;
  while a leader lives, its appends, or its announcement's resends,
  reach it; snapshot chunks come only after appends.
- The cluster suite 20 times.

#### Built: a node asks for the record its group's peers need

**The change,** as designed:
- the wire: `PeerMessage::DirectoryRequest { agent }`, index 15;
- `peer::check`: a term-0 placement relayed by a replica is accepted when
  it is exactly the creation's, under a record whose creator is the one
  its id names; the new message's class and stream;
- `dispatch.rs`:
  - `arrive` asks when a Raft message finds no group, by `should_ask`;
  - `on_request` answers by `should_answer`;
  - the asks kept are `Inner::asked`, bounded by `trim_asks`.
  - Every Raft message that finds no room asks through `should_ask`, a
    full inbox too, so the rule tested is the rule applied: a node with
    a group never asks.

**Tests:**
- `should_ask`, `should_answer` and `trim_asks`, as unit tests with the
  time given;
- `peer::check`:
  - a creation relayed by a replica is accepted;
  - refused from a node neither its creator nor a replica, when it
    differs from the creation's, and when its record claims a creator
    its id does not name;
  - the new message survives the wire.
- `a_record_reaches_a_node_that_was_down_from_a_replica`:
  - **Without the ask it fails:** no leader in 20 s. Node 2 then still
    held the creation's placement, term 0, as no election had placed
    another before the creator stopped, so the test meets the relayed
    creation too.
  - With the ask, nodes 2 and 3 elect and serve, and the creator, back,
    catches up.
- The cluster suite, 20 runs: all pass.

#### Where a node's CPU goes, by phase

The frame-pointer profile of 3.10a2's last run (one node at 15k/s,
152,810 samples) split by thread and by phase. The leader's refine and
dry run are the two jobs `leader::execute` hands the executors.
Accumulate in an apply runs only on followers, as the leader applies
its dry run's writes.

| Thread | Share | Of it |
|---|---|---|
| executors | 62.8% | mainly: the agent's guest code 22.1% (compiled, without frames, so not split by phase); signature checks 17.0%; followers' accumulate 9.9%; refine 7.4%; the dry run 5.0% |
| the runtime thread | 15.8% | store reads 5.1%, HTTP 2.6%, Raft 1.1%, the async runtime's own about 5% |
| the writer | 9.6% | |
| the network thread | 9.4% | |
| fjall's workers | 1.6% | flushes and compactions |

- **The agent's work** is about 44% of the node: its guest code, and the
  host side of refine, the dry run and followers' accumulate.
  - The host side is mostly store reads: about 11% of the node. 6.4% of
    that is accumulate's `write` looking up each key's previous length.
- **Each node leads a third of the agents:** per commit, it refines and
  dry-runs for a third, and runs accumulate again for the other two
  thirds.

**What would move it a lot changes a contract, so it is the owner's:**
- **Followers apply the leader's writes** instead of running accumulate
  again: about 15–18% of a node (their accumulate's host side, and its
  share of the guest code).
  - Followers already take refine's output from the leader; they would
    take accumulate's too.
  - The log's entries would carry the writes, so more bytes on the
    network and the disk.
- **A write host call that returns no previous length,** used by the
  default agent: the lookup goes on every replica, about 6% of a node.
  An addition to the agents' ABI.
- **Signature checks in batches:** ed25519's batch verification costs
  up to about half as much per signature in large batches, on the
  11.2% the equation costs.
  - Its semantics are not `verify_strict`'s. With a torsion component
    in R, a batch can pass a signature the strict check refuses: its
    random weights clear the component at least one time in eight, so a
    signer who resubmits gets one through in a few tries.
  - Keeping the strict semantics would take a torsion check per
    signature, which costs about what batching saves. So it is a
    choice of semantics.

#### 3.10b5 Design: memtables that fit the cache

**Why:** a loaded node spends about 14% of its samples in point reads
(the frame-pointer profile of 3.10a2's run, one node at 15k/s, 152,810
samples), most of it searching the active memtable.

| Where in a point read | Share of the node |
|---|---|
| following the skiplist's pointers (`decompose_tag` alone 4.0%) and comparing keys | 5.9% |
| libc, most of it the key comparisons' `memcmp` | 3.1% |
| pinning crossbeam's epoch | 1.5% |
| the tables: filters, indexes, blocks | 1.1% |
| clones, drops and the bound key's allocation | about 1.9% |
| the rest (the version's lock, sealed memtables) | about 0.5% |

The writer's inserts search the same skiplists (3.5%, outside these
rows).

- **What size can move** is the traversal and the comparisons, about 9%
  of the node. The epoch pin, the reference counts and the copies are
  paid per search, whatever the size.
- **Why the traversal is dear:** fjall's default memtable is 64 MiB,
  about a million skiplist nodes. A search visits about 2·log2(n) of
  them, about 40. The samples gather on the load of each node's next
  pointer, as they do when that load misses the cache:
  - each node has up to 64 MiB of active memtable in each keyspace,
    against a 24 MiB last-level cache the three nodes and the driver
    share;
  - the counter's key holds one version per call: the state keyspace's
    memtable is mostly runs of versions of a few keys, and comparing
    within a run compares equal keys whole.
- **By count alone,** a 4 MiB memtable (about 64k nodes) visits about 20%
  fewer nodes. Any gain past that is the cache's, and the measurement
  counts the misses to tell which.

**Who reads:**
- Accumulate's `write` looks up each key's previous length (the host
  call returns it): 6.4% of the node.
  - 4.3% of it is in followers' applies. The leader applies its dry
    run's writes without running accumulate again (`Inner::dry_run`).
  - 2.1% is in the leader's dry run.
- Refine's reads: 2.7%. The runtime thread's (sessions, the log): 5.1%.
- **A memo of the rows a batch read does not help.**
  - Per request, the agent's accumulate writes four keys (the state key
    refine computed, the session's mark, the new reply, the reply
    leaving the window) and reads none of them first.
  - Refine read the first two at the same snapshot, but only on the
    leader. A memo would save part of the dry run's lookups, about 1%
    of the node.
- **The previous length is only a return value:** the accumulate host
  puts it in φ7 and uses it for nothing else, and the default agent
  discards it. Two other levers follow from that, for later:
  - a read of the length alone, without copying the value: small;
  - a write host call that returns nothing, used by the default agent:
    no lookup on any replica. An addition to the agents' ABI, so the
    owner's decision.

**The change:** the `state` and `system` keyspaces get a smaller
`max_memtable_size` (`KeyspaceCreateOptions::max_memtable_size`, in
`store::Tuning::rows` and for `system`). One setting, the size measured
below.
- **`log` keeps 64 MiB.**
  - Its keys are unique and appended, with no runs of versions, and its
    reads are near the tail, which stays in cache.
  - Its entries are large, so its skiplist is shallower anyway.
  - An entry and its delete, soon after the apply, meet in a large
    memtable, where the flush writes only the tombstone.
  - It takes the most bytes, so it would add the most flushes.
- **New stores only:** fjall keeps a keyspace's options from its
  creation, and a reopened keyspace takes them from its metadata. An
  existing store keeps 64 MiB. Nothing is released yet, so the defaults
  apply to every store from here on, and the doc says so.

**What it costs:**
- **More flushes,** each smaller: the bytes flushed are the same, less
  what a larger memtable would have dropped as shadowed versions.
  - A reply lives about 4 s at this load (64 calls of a session at about
    15 a second) before its delete. A memtable that seals sooner than
    that writes both the reply and its tombstone to tables, where a
    larger one may hold both and drop the reply at the flush. So more
    compaction.
- **More level-0 tables** for misses to probe (their filters).
- **More stalls per flush on disk:**
  - every flush takes the version write lock for its syncs (3.10b0);
  - every flush syncs the journal under the journal writer's lock,
    which the node's writer appends through (fjall's flush worker
    rotates the journal or `persist(SyncAll)`s it).
  - On tmpfs these are cheap. On ext4 each adds its sync to the
    writer's stalls, about sixteen times as often at 4 MiB as at 64. So
    the disk is measured before a size is kept.
- **fjall's own write stalls:**
  - writes sleep in 100 ms steps while a keyspace has 4 sealed
    memtables;
  - they spin from 20 level-0 runs and halt at 30.
  - A faster flush rate brings both nearer. The 100 ms sleeps show in
    the batches of 49 ms or more, which each run reports.
- The memtables' memory: less.

**Measured** by 3.10b's method, on tmpfs:
- **The nodes on P-cores only** (`CPUS=0,5,1,2/3,4,6,7/8,9,10,11/12-21`),
  each on two P-cores. The driver gets the E-cores. With the reference
  pinning, the scheduler moves a node's threads between core types, and
  an E-core takes more cycles for the same work, so summed cycles shift
  with placement. At 6k/s a node needs about two cores.
- **Primary: user cycles per commit** from `perf stat`. Not
  instructions: a cache miss costs cycles, not instructions.
- **Beside it, per commit:** user instructions, and
  `mem_load_retired.l2_miss` and `l3_miss` (user). A change in cycles
  then has its cause counted, and a null result its reason.
- **Also reported:** CPU per commit, p50 and p99, the batches of 49 ms or
  more and the longest batch, and fjall's workers' CPU (flushes and
  compactions) from their threads' times.
- **Screening:** one 5-minute soak each at 64, 16 and 4 MiB, to choose
  the size. Then five interleaved soaks of that size against 64 MiB.
- **Kept if:**
  - cycles per commit fall past the other build's spread;
  - p99 and the batches of 49 ms or more do not get worse;
  - on disk, three interleaved soaks each show stalls a window (batches
    of 49 ms or more, the longest batch) that are no worse. The journal
    syncs a flush adds are the expected cause if they are.

#### 3.10b5 Measured: not kept

**Screened** on tmpfs, one 5-minute soak of each size (the 64 agents at
6k/s, four steady windows), the nodes on P-cores only:

| Memtable (`state`, `system`) | Cycles a commit | Instructions | L2 misses | L3 misses | fjall's workers | p99 |
|---|---|---|---|---|---|---|
| 64 MiB | 1,235k | 1,130k | 1,804 | 463 | 9.2 µs | 7.6 ms |
| 16 MiB | 1,220k | 1,128k | 1,708 | 402 | 8.6 µs | 5.7 ms |
| 4 MiB | 1,218k | 1,146k | 1,595 | 314 | 12.0 µs | 4.9 ms |

- **The search got cheaper; the flushing took back about half.** At
  4 MiB, against 64 (one soak each, so roughly):
  - cycles fell 17k a commit (1.4%), and 1.2% at 16 MiB;
  - fjall's workers did 2.8 µs more a commit, about 12–13k cycles,
    which matches the 16k more instructions;
  - so outside the workers, cycles fell about 30k a commit, about 2.4%;
  - and L3 misses fell 149 a commit (463 to 314), at about 200 cycles
    each. So the search got cheaper mostly through misses.
- **On disk it can only cost more:** each flush also syncs fjall's journal
  under the lock the writer appends through, and 4 MiB flushes sixteen
  times as often.
- **Not taken to an A/B.** The screened gain is within a build's spread
  as measured so far (1.5–1.7% in 3.10b4's soaks, with the nodes on both
  core types; the spread on P-cores alone is not yet measured), and the
  disk can only add cost. The change is set aside: `max_memtable_size`
  stays fjall's default. p99 is reported, not judged.

#### Perf's counts on this CPU were scaled: a correction

**Found** in 3.10b5's screening: with the nodes on P-cores only,
instructions per commit came out at about half of 3.10b4's, at the same
load.
- On the hybrid CPU, `perf stat` opens each event on both core types'
  counters. Each counts only while a thread runs on its kind of core.
- perf then divides each count by the share of the time it was running,
  extrapolating it to the whole time, as it does for multiplexed
  counters. These soaks ran 37% on E-cores and 62% on P-cores.
- So the sums in 3.10b3's and 3.10b4's tables were about twice the
  instructions and cycles executed: 1.95 times, in one run checked.
- **The true counts** are each line's value times its running share. With
  the nodes on one kind of core, as from 3.10b5 on, nothing is scaled.
- **Per commit** divides by 6,000 a second over perf's 180 s, which holds
  as the open loop kept its 6k/s through every steady window of these
  runs.
- Raw cycles of the two core types are still not equal work, so the
  measurements from here on keep the nodes on P-cores.

**Recomputed, the conclusions hold:**

| Run | Instructions a commit | Cycles a commit |
|---|---|---|
| 3.10b3: system allocator | 1,171–1,178k | 1,244–1,269k |
| 3.10b3: mimalloc | 1,158–1,164k | 1,189–1,203k |
| 3.10b3: system allocator, no huge pages | 1,175–1,176k | 1,277–1,284k |
| 3.10b3: mimalloc, no huge pages | 1,159–1,161k | 1,213–1,221k |
| 3.10b4: without the kept keys | 1,147–1,159k, median 1,158k | 1,216–1,237k, median 1,219.5k |
| 3.10b4: with them | 1,120–1,127k, median 1,122k | 1,194–1,213k, median 1,204.5k |

- **mimalloc:** about 5% fewer cycles, with huge pages or without, for
  1.3% fewer instructions; turning huge pages off costs about 2% more
  cycles for either allocator. The ranges still do not meet.
- **The kept keys:** 3.1% fewer instructions and 1.2% fewer cycles a
  commit. Both builds' ranges still do not meet, the cycles' by a small
  margin (1,213k against 1,216k). The work saved ran at roughly 2 or
  more instructions a cycle (36k instructions, 15k cycles, the cycles'
  difference smaller than either build's own range), against the node's
  0.93.
- The tables in 3.10b3 and 3.10b4 above keep their scaled numbers, as
  measured. These are the ones to read.

#### 3.10b6 Design: pipelined refines

**Why:** the single-agent budget is 20k/s, with p99 ≤ 10 ms at half load.
Its capacity is about 14k/s, because the leader runs one batch at a
time:
- refine, then the dry run, on an executor;
- then propose, commit and apply;
- then the replies, and only then the next batch.

At capacity a batch is about 190 inputs (3.10a2):
- refine takes 5.1 ms (about 27 µs an input, in one program run);
- the dry run 1.8 ms;
- the commit 1.3 ms;
- the apply 0.8 ms.

The leader's executors are busy about 46% of the time.

- **What pipelining can buy:** the next batch's refine and dry run run
  while the last batch commits and applies. Measured since ("One agent's
  batch cycle, accounted"), that hides about 1.0 ms of an 8.0–8.6 ms
  cycle: about +13–15%.
- **The rest of the gap** is refine's own cost per input. That is guest
  code, measured on its own.
- **It does not help the 64 agents:** their nodes are out of CPU, and a
  speculation thrown away costs some.

**Fixed already** (core model §7.2 and §7.5; plan §3, "Leader changes"):
- the base is the applied state plus an overlay of the leader's pending
  work results;
- a work result's version counts the leader's pending results;
- accumulate skips a result whose version is not current;
- a skipped result or a term change aborts the pipeline;
- replies, acknowledgements and outbox sends happen only after the
  local apply;
- a retry of a pending input joins it.

**The change** (`leader.rs`, `pvm.rs`, `node.rs`):
- **Depth two.** One batch, N, may be in flight from its dry run until its
  local apply while the next, N+1, is refined, dry-run and proposed. N+1
  waits for N's apply before its own replies. Deeper adds little:
  refine dominates the cycle.
- **The rule for everything that leaves the node:** nothing leaves on the
  strength of the view, only of applied state. Replies, acknowledgements,
  deliveries and outbox sends stay where they are, after the local
  apply of the batch they belong to.
- **The view.** N+1 is refined on a `Pending` view: the snapshot N was
  refined on, under N's dry-run writes (key to value, or deleted). It
  implements the store's `View` trait (its applied index is N's index),
  so every read of the leader's works on it unchanged.
  - **Refine** reads through it: `StateReader::read`, and `rows`, which
    merges the writes into the snapshot's scan in key order. The merge
    mirrors the guest's own (`refine.rs`, which merges a batch's writes
    over paged applied rows), and `FjallSnapshot::scan`'s cursor rule:
    a cursor below the prefix starts at the prefix, one past it yields
    nothing. The guest scans page by page from the last key it got, so
    the merge must be exact from any cursor.
  - **The dry run's** accumulate takes the view as its base. Accumulate
    only reads and writes keys, so its `Overlay` needs only `read` of
    the view.
  - **The leader's own reads** for N+1 read it too: the version, the batch
    time floor, the first expiry row (the sweep decision), and the
    sessions a duplicate's reply is found in (`dispatch`'s `before`).
  - **Two marks per sender.** A message is filtered, and a gap found, by
    the view's pair mark; but the early acknowledgement of a duplicate
    rises only to the applied mark, which is what has applied.
    - Otherwise a resend of a message N consumed would be acknowledged
      before N applied. If N were then lost, the sender would clear its
      outbox through it, and the message would apply nowhere.
    - N's own steps are acknowledged at N's dispatch, after its apply,
      as now.
  - **Acknowledgements as inputs** (`Pending::Ack`) are filtered by the
    applied `acked` row, not the view's, so a lost N never makes one
    vanish.
  - **The caches** (`marks`, and the sweep's `swept` and `stuck`) are
    valid within one pipeline run: they advance when N+1 starts, and on
    any outcome but `Done` they are cleared and read again from applied
    state.
- **Version and time:** N+1's version is N's plus one, and its time is no
  earlier than N's.
- **The log:** N+1 is proposed after N, so it follows N in the log.
  - Only this leader proposes results. Within one term only a
    configuration entry can come between two of them (a term's no-op
    comes first), and it writes no agent state (`apply_one` gives it no
    writes). Snapshots install only on a follower, and pins change only
    at an install's apply, which ends the pipeline. So the view stays
    the state N+1 applies on.
  - Proposals keep their order through the group's local channel, and
    N+1's term is checked as N's is.
- **The dry runs kept:** today one per agent, taken when its entry is
  the next index. They become a short queue, and an entry's kept writes
  are used only when all of these hold:
  - it is the entry the dry run was made for: its payload, at the index
    after the state the dry run read;
  - **the entry before it took:** `apply_one` drops the agent's queue
    whenever an entry applies as no writes, or not with its kept
    writes. Otherwise, after N applied as no writes at the leader, N+1's
    kept writes, built on N's, would apply there while every follower
    skipped N+1: the leader would diverge for good. This sits in the
    applier, as the leader loop learns N's outcome only after the
    applier has used the kept writes.
  - Stale entries are popped from the front, and the queue is dropped
    when leadership ends and when the agent stops.
  - Otherwise accumulate runs at apply, which is always correct.
- **N's uncovered tail goes back first.** When N's result covers fewer
  inputs than its batch (its gas or size cut it short), the inputs
  without a step are requeued at the front right after N's dry run,
  before N+1 takes any. Today that happens at dispatch, which would put
  them behind N+1's: a session's next request, already queued, would
  then be refined before the one left over, and refused as a gap.
- **Linger only with nothing in flight:** while N commits and applies, its
  time is N+1's batching window.
- **What ends the pipeline,** so the next batch waits for the last
  batch's apply:
  - a batch holding an `Admin` input: an install pins programs at
    apply, and N+1's refine would not find them;
  - a batch whose result applied as no writes (`Ran::Skipped`);
  - leadership ending;
  - the agent stopping.

**When N does not end well:**
- **N is lost** (leadership ended before it applied here):
  - N+1 cannot commit before N, so it is lost too;
  - if N+1 was not yet proposed, it is not;
  - both batches' callers are refused with the leader's hint, as a lost
    batch's are today;
  - entries a new leader commits apply on every replica in log order,
    on the state N+1 was refined on.
- **N applies as no writes** (skipped by the version check):
  - N's writes never happened, and N+1's version is past the stored
    one, so accumulate skips N+1 too;
  - both are requeued, N's inputs first: the queue takes them at its
    front in order, so N+1's go back first, then N's;
  - the "skipped twice in a row" rule counts N's skip, not N+1's,
    which is its consequence: N+1's skip runs neither `fail` nor the
    shortening, which would answer a caller `Failed` for an input
    never at fault. N+1 skipped with N done counts as a first skip.
- **N's refine or dry run fails:** N+1 has not started, as it starts from
  N's dry-run writes.
- **N+1's refine or dry run fails:** as a failed batch today (requeued
  shorter, or retried); N is unaffected.
  - A retry's backoff (up to 5 s) waits until N is finished, so N's
    callers are not held behind it.
  - An input of N+1 answered `Failed` carries the last index applied
    here, not N's.
- **N's proposal refused:** N+1 is lost before it is proposed. N+1's dry
  run's predecessor index is N's, known from N's proposal answer.
- **A new leadership** starts with no view, marks, kept dry runs or
  caches from the last, even on the same node.
- **A storage fault:** the node halts, as today.

**What does not change:** the log's format, accumulate, followers,
the version rule, apply-then-send, and exactly-once. Queries read
applied state only, never a view.

**First, the cycle measured** (before building): the stage times at
capacity sum to less than a batch's cycle, so `/stats` gains the rest
of it: `prepare` (inputs taken to refine), `dispatch` (replies,
deliveries) and `between` (a batch's end to the next one's taking its
inputs). Pipelining hides commit and apply, and whatever runtime work
overlaps N+1's refine (N's dispatch, its HTTP answers): from about +15%
if the rest is serial, to about +50% if the executor alone bounds it.

**Measured** on tmpfs, nodes on P-cores only, the counts unscaled:
- **One agent,** judged on the open rows:
  - open at 15k, 18k and 21k/s: whether it keeps up;
  - p99 at half of the new capacity;
  - closed: at 256 sessions the pipeline is under-fed (N+1 gets what
    arrived during N's refine), so closed is reported at 512 and 1,024
    sessions too, or as latency.
- **64 agents at 6k/s:** CPU and cycles per commit, with depth two
  against without: the pipeline's fixed cost, as two in flight are rare
  there. The knee does not move down.
- **Aborted speculation's cost:** the failover run, 24 leaders lost at
  once.
- `batch` is defined once batches overlap: from a batch's refine to its
  apply, as now, so two batches' times overlap.
- The exactly-once checker loop and the fault suite.

**Tests** (the review's, with the design's):
- **No acknowledgement leaves on the view:** a message consumed in N, its
  duplicate in N+1 while N's commit is held by a hook; no
  `Acknowledge` before N applies. Then N lost (its leader killed before
  the commit): the message applies once (`pair_in`, `acked`, an empty
  outbox, as the checker checks).
- **N applied as no writes with N+1 in flight:** the replicas' whole agent
  state compared, not only the counter.
- **N cut short by gas,** the session's next request already queued: the
  client sees only running totals.
- **Leadership lost between N's and N+1's proposals, the same node elected
  again:** the new leadership inherits nothing.
- **A stop after a commit** (`after_commit`) with two in flight.
- **A configuration change between N and N+1:** N+1 applies with the same
  writes on every replica.
- **The view:**
  - reads, deletes, and scans merged in key order with an `after` cursor;
  - unit tests, with a proptest against a model map.
- **A batch refined on the view sees the last batch's writes:** two
  batches in flight on one counter, with the commit held by a hook, add
  up.
- **N skipped:** a hook makes N apply as no writes. N+1 skips too, both
  are retried, each caller is answered once, and the counter adds up.
- **Leadership lost with N and N+1 in flight:** both refused; the checker
  sees each request applied once.
- **An `Admin` input ends the pipeline:** an install, then a call to the
  installed instance, in the batch after it.
- **The kept dry runs:** used for the next entry; not used when a
  configuration entry came between (accumulate runs, with the same
  writes).

**The baseline** (HEAD 6528733c, tmpfs, the nodes on P-cores only; two
runs, the agent led from node 1 and from node 2):
- closed at 256 sessions: 15.1k and 14.7k/s;
- open at 15k/s: kept up (p99 21 and 35 ms); at 18k and 21k/s: fell
  behind;
- at half load, 10k/s: p99 14.8 and 12.1 ms, against the budget's 10;
- at saturation, about 100 inputs a batch:
  - refine 5–6 ms, the dry run about 1.5 ms, the commit about 0.3 ms,
    the apply about 0.5 ms;
  - the whole batch cycle about 10 ms;
  - the leader's executors 61–66% busy.

**Reviewed by Fable** (design v1, then folded here):
- **two soundness holes,** both closed above:
  - an early acknowledgement on the view's pair mark could lose a
    message for good if N was lost;
  - the kept dry run of N+1 could apply at the leader after N applied
    as no writes, and diverge it from every follower for good;
- the caches cleared on any outcome but `Done`;
- N's uncovered tail requeued before N+1 takes inputs;
- the skip, backoff and `at` details;
- linger only with nothing in flight;
- the measurement asked for first, which found the gain at about 15%
  (the next section).

Not built yet: refine's own cost is measured first.

#### One agent's batch cycle, accounted

**Why:** Fable's review of 3.10b6 found the stage p50s at capacity summed
to less than a batch's cycle, so pipelining's gain could not be
predicted.
- **`/stats` gains three stages:**
  - `prepare`: inputs taken to refine;
  - `dispatch`: the replies, deliveries and acknowledgements;
  - `between`: a batch's end to the next one's taking its inputs. That
    includes any idle wait for inputs, so it means something only at
    capacity.
- **Each histogram also keeps the sum of what it recorded,** so the bench
  prints each stage's exact mean beside its percentiles. Bucket tops are
  up to a quarter apart, and do not add up; means do.
- **Two counts per batch:** `refine_gas` (refine's gas, per input) and
  `step_gas` (its steps' gas, per input).

**Measured** (one agent, tmpfs, the nodes on P-cores only; exact means,
in µs):

| Stage | Closed, 256 sessions (14.85k/s) | Open, 15k/s |
|---|---|---|
| inputs a batch | 128 | 121 |
| refine's wait for an executor | 6 | 9 |
| refine | 5,150 | 5,265 |
| dry run's wait for an executor | 1,021 | 113 |
| dry run | 1,386 | 1,566 |
| propose, commit, apply | 26 + 358 + 489 | 28 + 322 + 580 |
| `batch`, refine to apply | 8,537 | 7,952 |
| `prepare`, `dispatch`, `between` | 23, 50, 8 | 23, 51, 6 |

- **It adds up:** the stages inside `batch`, with its four resumes (about
  20 µs each), are 8.52 ms of its 8.54. The whole cycle is 8.62 ms, and
  128 inputs every 8.62 ms is 14.85k/s, the rate measured. Open: 121
  inputs every 8.03 ms is 15.06k/s, at 15k offered.
- **Refine is 60–66% of the cycle,** about 40–44 µs an input on a P-core.
  The dry run is another 16–20%, about 11–13 µs an input.
- **The dry run waits behind signature checks** when closed, 1.0 ms a
  batch, as the executors take both from one queue. Open, 0.1 ms.
- **What pipelining can hide** is propose, commit and apply, and the loop's
  own steps: about 1.0 ms a cycle. So **about +13–15%** (8.62 / 7.59
  closed, 8.03 / 6.96 open), not the +25–30% first estimated.
- **So refine's own cost decides the single-agent budget.** Halving it
  would gain about 40–50%. It is measured next, before pipelining is
  built: if a cheaper refine reaches 20k/s, the pipeline's complexity is
  not needed.

**Gas cannot tell where the time goes:**
- refine uses about 100k gas an input, 95k of it in its steps;
- but a step's gas is mostly prices, charges rather than work: the
  counter's `get` (20,000) and `put` (64,000) and a few 2,000-gas
  operations;
- and the rest is not instructions either. The recompiler charges each
  basic block on entry the Gray Paper's modeled cycles on an ideal
  core, often well under one an instruction. About 5k gas is left in
  the handler, and about 5k in the agent around it.
- The profile, below, puts about two thirds of refine's time in
  compiled guest code. So either that code runs several times slower
  than the model, or its samples include the work around it (the JIT's
  entry and exit code, memory setup). The perf map, next, will tell.
- `refine_gas` and `step_gas` record each batch's average per input, so
  their means do not weight batches by size: negligible at capacity,
  where batches are much alike.

**Where refine's 40 µs an input go** (the leader under the one agent at
saturation, the frame-pointer build, 84,468 samples):
- **Signature checks take 42.7% of the leader's CPU,** about a core at 15k
  calls a second, as the bench sends every session's calls to the leader.
  Refine's host side is 6.6% (store reads 2.1%), and the guest code of
  refine and the dry run 16.9%, about two thirds of it refine's.
- So refine is about two thirds guest code (the default agent and the
  counter actor, the JIT's own entry and exit code with them) and one
  third host side (the runtime's `invoke`, machine setup, and about
  4 µs of store reads).
- **Are the checks slowing refine?** The leader's executors share two
  P-cores, so the serial refine can run beside a check on its
  hyperthread sibling. A bench setting, `SPREAD=1`, sends the sessions to
  the three nodes in turn, each checking its calls and forwarding them,
  as the plan's clients would:
  - the leader's load fell from 2.4 to 2.0 cores, and the dry run's wait
    for an executor from about 0.6 ms a batch to nearly nothing;
  - but refine took 41.5 µs an input against 40 (bucket means, that
    run), and the capacity stayed about 15.9k/s.
  - So refine's cost is its own.
  - Why the 0.6 ms saved a batch did not raise the capacity is not
    measured: the forwarding hop, and batches of another size, are
    candidates.
- **Next:** where refine's guest time goes, by program and by function,
  with the PVM's code mapped back to the programs' symbols. Then
  pipelining, as reviewed, for its 13–15%.

**Found in the gates, and fixed:** lsm-tree's own unit test `fifo_ttl`
failed once in `just test`. Its tests set a process-wide clock, and on a
parallel thread `fifo_ttl_then_limit_additional_drops_blob_unit` set it
to 10,000,000 s. That expired both of `fifo_ttl`'s tables. The vendored
crate's test clock is now per thread (`VENDORED.md`, and a note for
upstream in `UPSTREAM.md`). Its unit suite then passed 30 runs of 30.

#### Built: guest code named in perf

As designed, with the review's changes:
- **`vos_pvm::perf_map`:**
  - the binary turns it on at start from `VOS_PVM_PERF_MAP`;
  - it empties `/tmp/perf-<pid>.map` then, as a process that had the
    pid before may have left one;
  - each `recompiler::compile_code` appends its lines, one write each,
    under a lock.
- **Its programs' names:**
  - a program whose functions were registered (`register`, by its
    code's hash) is named a line a function: entry and exits apart, a
    function from its entry's native offset to the next one's;
  - any other program, a line for the whole.
- **`vos_pvm_compiler::link_elf_spi_with_symbols`:** the linker reads the
  ELF's function symbols and carries their PVM offsets through the pass
  that inserts block starts (`ensure_branch_targets_with_pc_map`). It
  names them as source spells them (`rustc-demangle`).
- **The CLI** registers its agent's functions when the map is on.
- **The codegen** reports its panic stub's offset: a pc the dispatch table
  does not map holds it.

**Tests:**
- the line's format;
- a program's name;
- the regions: an unmapped entry starts at the next mapped pc, one that
  falls onto another's entry leaves that function its name, and a dead
  one is dropped;
- a compile names the region its code occupies (its own test binary, as
  it turns the map on for its process);
- on the real agent:
  - every function's entry is a basic-block start, and maps exactly in
    the dispatch table;
  - the compiled agent is named in contiguous regions, entry to exits,
    exactly its code's span, `run_batch` among them.

**Where the guest time goes** (the one agent's leader at saturation, the
map on, 88k samples): guest code is 19% of the leader's samples, about
30 µs an input of refine and dry run together. Of it:

| Region | Share of guest time |
|---|---|
| `vos_agent::refine::run_batch` (the input loop, much of it inlined) | 14% |
| the counter actor (its whole program) | 11% |
| `Invocation::invoke` | 8% |
| `compiler_builtins::mem::memcpy` (the guest's own) | 8% |
| `vos_accumulate` (the dry run's entry, inlined) | 6% |
| `refine::command` | 6% |
| `vos_refine` (refine's entry, inlined) | 5% |
| `ResultWriter::push`, `keys::key`, `BTreeMap::insert` | 3% each |
| allocation and growth (`RawVec`, realloc) | about 5% |
| drops (`Step`, `BTreeMap` iterators, `Vec<Attest>`) | about 4% |
| the rest, under 1% each | the remainder |

- **No one hotspot:** the agent's own code is nine tenths of it, spread
  over the shape of general Rust: building owned keys and values,
  copying them (`memcpy` alone 8%), growing vectors, inserting into
  `BTreeMap`s, encoding steps, and dropping it all.
- So the agent's per-input cost falls only by reworking how it handles
  an input's data (borrowed keys, fewer owned copies, preallocated
  buffers), not by one fix. That is its own design.
- The JIT's entry and exits, named apart, are under 1%: switching
  machines is not where the time goes.

#### Refine on this laptop: why the cluster's is twice the in-process node's

**Found:** the in-process bench (`benches/acceptance.rs`, one node, the same
agent and counter, now printing the node's stage means) refines at
16.7–19.5 µs an input across runs, and dry-runs at about 5 µs. The
cluster's leader refines at about 40 µs an input, and dry-runs at about
11.
- **The in-process node is a quieter one,** not only a differently pinned
  one. It is called directly (`Node::call`), so it has no ingress and no
  signature checks, no network thread and no replication; its cores do
  little but refine and dry-run. Its rate bounds refine from below, and
  does not predict a node on a machine of its own.

**What changes refine there** (the in-process bench, one run each, so
effects under about 8%, the baseline's own range, are not resolved):

| Condition | Refine an input | Dry run an input |
|---|---|---|
| two threads on two P-cores, their siblings idle | 16.7 µs | 4.7 µs |
| the same, the siblings running a busy loop | 23.1 µs | 7.3 µs |
| two hyperthread pairs, the other eight P-core threads busy | 23.6 µs | 6.7 µs |
| huge pages off for the process | about +4%, within the noise | |

- Sharing a core with a busy thread costs refine about 40%. The busy loop
  is a scalar loop, not the leader's actual co-runners (AVX2 curve
  arithmetic, a memory-bound runtime thread, QUIC's encryption), so what
  those cost is not measured here.
- The third row changes two things at once: both siblings of two cores,
  and the clock (it fell from about 4.5 GHz to 3.4–3.7 with every other
  P-core busy). Separating them would keep the node on one thread a
  core, and load only the other cores.

**The cluster with the leader's four threads on four separate P-cores**
(`CPUS=0,1,3,6/8,10,12,13/14,15,16,17/18,19,20,21`, their siblings idle;
node 1 led; one run):
- refine 32 µs an input, against about 40 on the reference pinning;
- closed at 64 sessions 17.3k/s, against 12.7–14.6k; at 256, 16.9k/s;
- open at 15k/s: kept up, p99 14 ms. At 18k/s it fell behind, the driver
  keeping up (its send lag's p99 0.014 ms);
- **at half load (10k/s): p99 7.0 ms, within the budget's 10, in this one
  run.**
- **The rest of the gap,** 32 µs against 17, is not separated. The
  candidates are:
  - the lower clock with every P-core of the laptop busy;
  - the last-level cache the three nodes and the driver share;
  - the leader's own other work sharing its four CPUs: about a core of
    signature checks, its runtime thread and its network thread.
    (Moving two thirds of the checks off the leader, `SPREAD=1`, left
    refine unchanged, which argues against the checks alone, not
    against the rest.)

**What it means for the budgets:**
- **The half-load p99** passed once the leader's cores were its own, in
  one run. 3.10c repeats it.
- **The capacity budget (20k/s):** pipelining's estimate (13–15%, itself an
  upper estimate: it assumes the 1 ms hidden completely) on 16.9–17.3k/s
  gives 19.1–19.9k/s: at the edge, not past it.
- **Unmeasured, a hypothesis:** whether a node with a machine of its own
  refines nearer 17 µs an input than 32. Only another machine can tell.
- 3.10c reports the single agent's rows on both pinnings, with this as
  the reason.
