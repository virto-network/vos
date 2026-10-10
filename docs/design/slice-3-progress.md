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
