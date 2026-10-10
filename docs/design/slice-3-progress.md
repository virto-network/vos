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
