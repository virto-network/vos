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
