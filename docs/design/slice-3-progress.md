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

