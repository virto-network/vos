# Run 3 spikes: results

Measurements that settle the open performance and compatibility questions of
`core-model.md`. Each entry records the setup, the result and the decision.
Spike code lives in `spikes/` and is not part of the build.

Environment: Intel Core Ultra 7 155H, 62 GB RAM, Linux 7.1; release builds.

## S1 — Workflow snapshots

**Setup.** `spikes/s1-snapshots`. A Rust guest with three workflows and a
bump-arena allocator (8 MiB arena in `.bss`), linked with the saga's 0.8.0
compiler and run on the saga's `vos-pvm` runtime:

- **transfer:** parse a request, await a remote risk check, call the ledger
  synchronously, reply;
- **saga:** five steps, each awaiting a remote reply, accumulating results in
  a `BTreeMap`;
- **compute:** fill a 2 MiB vector, then sort it in 16 chunks with a
  checkpoint after each.

The harness runs each workflow straight through on the interpreter and the
JIT, then again restoring a fresh machine from a snapshot at every
suspension. At each suspension it measures:

- pages that differ from the program image;
- pages changed since the previous snapshot;
- capture by scanning all writable pages versus copying and hashing only the
  changed ones;
- restore cost on both backends;
- the prefix a replay journal would re-execute.

**Result.**

| Workflow | Changed pages per suspension | Shipped (raw / LZ4) | Capture: scan / tracked | Restore: interpreter / JIT | Replay would redo |
|---|---|---|---|---|---|
| transfer (1 await) | 3 | 12 KiB / 0.6 KiB | 670 µs / 16 µs | 2.3 ms / 0.11 ms | 48 µs (interp) |
| saga (5 awaits) | 3 each | 12 KiB / 0.4–0.7 KiB | 660–830 µs / 17 µs | 2.3 ms / 0.11 ms | 21→143 µs, growing per step |
| compute (16 checkpoints) | 514 first, then 34 | 2 MiB first, then 136 KiB (random data does not compress) | ~1.1 ms / 0.17 ms (2.4 ms for the first) | 2.6 ms / 0.7–0.9 ms | 1.2·k ms on the JIT at checkpoint k; quadratic in total |

- Restored runs produce output identical to the straight runs for all three
  workflows. The interpreter and the JIT agree.
- Straight runs: transfer 87 µs interpreted; compute 236 ms interpreted
  versus 21 ms on the JIT.

**Findings.**

- Typical suspensions are tiny: a few pages, under 1 KiB compressed.
  Snapshots cost about as much as replaying a short handler, avoid any
  journal, and are the only workable option for long computations.
- Native dirty-page tracking is required. Scanning every writable page costs
  about 1 ms with an 8 MiB arena; tracking costs microseconds.
- Machines must come from prepared copy-on-write images. The 2.3 ms
  interpreter restore is almost entirely cloning the sparse memory's fixed
  tables. JIT instantiation costs about 0.1 ms.
- A fresh JIT machine pays about 0.5 ms on its first resume. A likely cause
  is the native permission sync, which walks the whole 4 GiB page table once
  per revision. This must go before the actor-invocation budget (≤ 50 µs)
  can hold; spike S2 measures it.
- In the interpreter, GP 0.8.0 gas pipeline simulation
  (`gas_sim::ConformanceState`) takes about a fifth of execution time.
- Ship snapshot pages LZ4-compressed: 20–30× on workflow pages.

**Decision.** The gate (typical suspension ≤ 50 KB and ≤ 1 ms) passes with
dirty tracking and pooled images. Snapshots stay the only continuation
mechanism. Required runtime work:

- native dirty-page tracking on both backends;
- copy-on-write image pool;
- removing the full-span permission sync;
- LZ4 for shipped pages.

## SJ — JAM compatibility (part a)

**Setup.** PolkaJam `nightly-2026-10-08` (`polkajam 0.1.29`, Gray Paper
0.8.0) as a local 7-validator testnet (`polkajam-testnet`), driven with
`jamt`. A minimal service (`spikes/sj-jam/guest`) written in Rust for the
`riscv64em-vos` target: refine returns `vos:` plus its work-item payload;
accumulate stores its first input under the key `last`. Linked with the
saga's `vos-pvm-compiler::link_elf_spi` (Gray Paper 0.8.0 standard program
with the IC 0 / IC 5 entry prologue) and prefixed with conventional metadata
(`spikes/sj-jam/tool`). Total blob: 1,958 bytes.

**Result.**

- `jamt create-service` accepted the blob unchanged; PolkaJam parsed the
  metadata ("vos-sj-echo v0.1.0").
- Refine ran on the guarantors and returned `vos:hello-jam`. Accumulate ran
  on all seven validators, and the stored operand ends with the Ok-tagged
  refine output (`00 0d 766f733a68656c6c6f2d6a616d`).
- Host calls `fetch` (2), `write` (5) and `log` (100), the refine argument
  encoding `E(c, i, s, ↕payload, H(p))` and the halt convention (output
  window in a0/a1, return to the host-installed address) all behaved as
  specified.
- The first submission refined to `BAD` because the code preimage was not
  yet available at that package's lookup anchor; a later submission
  succeeded. Deployment tooling must wait for code availability.

**Findings.**

- Guests issue host calls as `li t0, <id>; csrw 0x801, zero; ecall`, which
  the compiler lowers to `ecalli <id>`.
- The linker script must set the read-write base explicitly before `.data`;
  otherwise a program without initialized data places `.bss` in the
  read-only zone and linking fails.
- PolkaVM's JIT sandbox needs `vm.unprivileged_userfaultfd=1`. The testnet
  ran with `POLKAVM_BACKEND=interpreter` instead of changing the kernel
  setting.

**Decision.** Gray Paper 0.8.0 is the single PVM version for VOS: runtime,
compiler, prover and agents. The saga's 0.8.0 PVM layer is the base. Master's
JAR capability-kernel profile and its gas model are dropped.

**Remaining (part b, moved to the first JAM milestone).** A workflow
suspended in one work package and resumed in a later one needs the agent
program to load standard programs into inner machines itself (the `machine`
call takes bare code; data, stack and arguments are set up with `pages` and
`poke`) and to carry snapshot pages through export and import segments. This
is the agent framework's loader, built as part of the first slice rather
than as a throwaway spike.

## S3 — Logs

**Setup.** `spikes/s3-raft`. Three-node Raft groups in one process: in-process
channels instead of a network, all three replicas on the same disk (WD SN740,
a consumer NVMe without power-loss protection). The disk benchmarks ran
under `target/`, not `/tmp`: `/tmp` is tmpfs there, where fsync costs
nothing. Three implementations:

- **vos-raft as is:** `support/vos-raft`, `run_worker` futures on one tokio
  runtime;
- **vos-raft prototype driver:** `spikes/s3-raft/vos-raft-eager`, a copy
  with a 165-line patch to `worker.rs`:
  - queued proposals are appended in one storage batch (group commit);
  - new entries go to followers immediately, with one append in flight per
    peer, instead of waiting for the heartbeat;
  - the store skips the fsync for batches that only move `commit_index`,
    which is volatile in Raft.

  vos-raft's own suites pass on the copy: 70 tests, including fault
  injection and the proptest invariants. The `no_std` build check does not
  apply to a copy.
- **openraft 0.9.25 as a reference:** `src/bin/openraft_ref.rs`, with the
  same redb layout and a background flusher that batches appends, which
  is how openraft's `LogFlushed` callback is meant to be used.

Logs are stored in redb, with one transaction per batch and an in-memory
mirror of the log tail. Proposers run closed-loop. Latency is measured on
the leader, from propose to commit. Each step is 4 s for throughput and
10 s for idle CPU.

**Result: one agent, 1 KiB entries, redb, 50 ms heartbeat.**

| Proposers | vos-raft as is | Prototype driver | openraft |
|---|---|---|---|
| 1 | 20/s, p99 52 ms | 1,374/s, p99 1.4 ms | 1,112/s, p99 1.8 ms |
| 16 | 314/s, p99 58 ms | 9,318/s, p99 4.3 ms | 2,508/s, p99 12 ms |
| 64 | 1,232/s, p99 58 ms | 24,982/s, p99 7.9 ms | 2,544/s, p99 55 ms |
| 256 | 3,956/s, p99 111 ms | 44,496/s, p99 16 ms | 2,752/s, p99 135 ms |

- In memory with 64 proposers: 1,280/s as is (bound by the heartbeat),
  494k/s with the prototype, 255k/s with openraft.
- As is, with a 5 ms heartbeat and 64 proposers: 4,095/s, p99 26 ms. The
  per-proposal fsync is now the bound.
- Prototype driver with larger entries: 16 KiB with 64 proposers gives
  9,467/s (148 MiB/s), p99 17 ms. 64 KiB with 16 proposers gives only
  613/s, p99 60 ms; this is not explained yet.

**Result: disk, one sync.**

| Write per sync | Raw append + fdatasync | redb commit |
|---|---|---|
| 1 × 1 KiB | 442 µs | 362 µs |
| 64 × 1 KiB | 526 µs (122k entries/s) | 960 µs (67k entries/s) |
| 1 × 16 KiB | 470 µs | 536 µs |
| 1 × 64 KiB | 489 µs | 630 µs |
| 1 × 256 KiB | 578 µs | 1,023 µs |

**Result: many active agents (prototype driver, 1 KiB entries, one
proposer loop each, total commits/s).** Ranges cover repeated runs; the
spread between runs was up to 4×.

| Agents × proposers | One redb file per replica | One redb per node, commit in the task | One log writer per node |
|---|---|---|---|
| 1 × 64 | 18.8–22.4k, p99 8–19 ms | 23.3k, p99 7.5 ms | 17.1–26.0k, p99 7.5–19 ms |
| 16 × 16 | 23.9–24.6k, p99 23–32 ms | 11.6k, p99 60 ms | 19.8–42.8k, p99 16–56 ms |
| 64 × 4 | 4.4–5.9k, p99 0.15–0.34 s | leaders lost | 6.3–26.1k, p99 31–191 ms |
| 256 × 1 | 1.1k, p99 2.6 s; 83 leaders lost | leaders lost | 6.0–8.8k, p99 86–156 ms |
| 1,000 × 1 | 230, p99 6.5 s; 393 leaders lost | — | 8.3–10.8k, p99 0.2–0.86 s; leaders lost in 2 of 3 runs |

The node log writer is a thread per node. It drains every queued write
from every group into one redb transaction, with one fsync, using a single
log table keyed by (agent, index). A table per agent made each transaction
slower as the number of agents grew.

**Result: idle groups.** All three replicas of every group run in one
process, so per-node figures are a third of these.

| Driver | Groups | Heartbeat | Threads | RSS | Idle CPU (one core) | RPC/s |
|---|---|---|---|---|---|---|
| Thread per group (`Worker`) | 100 | 50 ms | 2,062 | — | 94% | 4.0k |
| Thread per group (`Worker`) | 300 | 50 ms | 6,168 | — | 263% | 12k |
| Thread per group (`Worker`) | 1,000 | 50 ms | did not settle in 5 min | | | |
| Shared runtime (4 threads) | 1,000 | 50 ms | 5 | 24 MiB | 32–36% | 39k |
| Shared runtime (4 threads) | 1,000 | 200 ms | 5 | 24 MiB | 9.7% | 9.9k |
| Shared runtime (4 threads) | 1,000 | 500 ms | 5 | 23 MiB | 4.7% | 4.0k |
| Shared runtime (4 threads) | 1,000 | 1 s | 5 | 23 MiB | 2.8% | 2.0k |
| Shared runtime (4 threads) | 3,000 | 1 s | 5 | 62 MiB | 6.9% | 6.0k |
| openraft | 1,000 | 50 ms | 5 | 298 MiB | 48% | 26k |
| openraft | 1,000 | 500 ms | 5 | 155 MiB | 5.3% | 2.7k |

**Findings.**

- vos-raft's driver, not its protocol, misses the budget:
  - a commit waits for the next heartbeat, so latency equals the heartbeat
    interval;
  - the leader fsyncs once per proposal, and again each time the commit
    index advances.
- With the three driver changes, one agent meets the replicated budget on
  this hardware: about 25k/s at p99 7.9 ms, at roughly 55% of the 44k/s
  peak.
- openraft is not faster here: 2.5k/s on the same store, and half the
  prototype's in-memory rate. Keeping vos-raft is confirmed.
- fsync costs 0.35–0.5 ms on this disk, so batching dominates every other
  cost. redb matches a raw append for single small writes and costs up to
  2× more for large or batched ones.
- Many active agents need one log writer per node with group commit across
  agents:
  - separate stores pay one fsync per agent per round. With fsyncs on
    executor threads starving heartbeats, they lost leaders from 256
    active agents up (p99 0.15–0.34 s already at 64);
  - one shared redb with commits in the task serializes the writers and
    lost leaders from 64 active agents up.
- At 1,000 active agents the node writer still loses leaders. A follower
  answers a heartbeat only after its store write completes, so liveness
  waits on the disk. Heartbeats must not wait for log I/O.
- Idle cost is linear in heartbeat messages: about 8 µs per RPC
  in-process (openraft about 18 µs).
  - With replicate-on-propose, the heartbeat no longer sets commit
    latency, only failure detection.
  - At a 500 ms heartbeat, 1,000 groups cost about 1.6% of a core per
    node, with 5 threads and about 8 KiB per replica.
  - A real transport adds serialization and syscalls per message, so
    heartbeats are combined per node pair, and idle groups quiesce or
    heartbeat slowly.
- A thread per group is unusable: about 20 threads and 0.9% of a core per
  idle group.

**Caveats.** One machine; three replicas share one consumer NVMe and one
CPU. In-process channels stand in for a LAN, which adds about 0.1–0.3 ms
per round. Load is closed-loop, so "half load" is approximated by the
proposer count that reaches about half of peak throughput.

**Decision.**

- **Replicated budget:** passes with the prototype driver; fails as is.
- **Idle-group budget:** passes on a shared runtime at a 500 ms heartbeat;
  fails with a thread per group.
- vos-raft's protocol core is kept and its driver is rewritten. Required
  work:
  - group commit of queued proposals;
  - replicate on propose, with one append in flight per peer;
  - no fsync for commit-index-only writes;
  - one log writer per node with group commit across agents, and storage
    I/O never on executor threads;
  - a liveness path independent of log I/O: combined heartbeats per node
    pair, and slow heartbeats or quiescence for idle groups;
  - one shared executor; the thread-per-group `Worker` is dropped;
  - every outbound AppendEntries carries the heartbeat round it was sent
    in, including replicate-on-propose sends: a read barrier counts only
    answers to rounds sent after it was queued (a round of 0 never
    counts).

**Proposed for section 9.5.** All Raft logs on a node go to one node-level
log: a redb table keyed by (agent, index) first, then a raw append-only
segment log if large entries make redb's up-to-2× write cost matter.
Large entries include witnesses and snapshot pages.

**Open.** Find the cause of the slow 64 KiB entries before witnesses ride
the log.

## Note — Byte loops under the 0.8.0 gas model (slice 2)

The block-gas model charges a load 25 cycles and a branch whose outcome is
not obvious 20. compiler_builtins' `memcmp` compares a byte per iteration,
about 50 gas a byte: the default agent spent 72 gas per byte of a 1 KiB key
on a `get`. Comparing a word at a time where both sides share an alignment
cut that `get` from 91,000 to 29,000 gas. Every guest gets that `memcmp`
and `bcmp` from `vos_sdk::program_runtime!`, which is where to replace any
other builtin a guest leans on (`memcpy`, `memset`) once a measurement
shows it hot.

## S2 — Nesting

**Setup.** `spikes/s2-nesting`. Two guests built with the saga's 0.8.0
compiler, run on the saga's `vos-pvm` runtime:

- **actor** (788 bytes): a ledger handler with no allocator. A transfer
  makes two `GET`s and two `PUT`s and returns a 24-byte reply; a query
  makes one `GET`. A machine that halts can be invoked again from its
  entry.
- **agent** (3.5 KB): a refine loop. It takes inputs from the node, builds
  the actor as a JAM inner machine and serves the actor's calls:
  - the machine is built with `machine` plus `pages` and `poke`, the
    loader SJ calls for;
  - reads go through an overlay of the agent's own writes to the node's
    `STATE_GET`;
  - writes are buffered and emitted in the work result;
  - an accumulate entry applies the result through `STATE_PUT`.

Paths compared, on the interpreter and the JIT:

- **nested:** the agent hosts the actor (the decided design);
- **native:** the node drives the same inner machines itself and serves the
  actor's calls (the candidate node-side fast path);
- each with a machine built per request (**fresh**) or reused across a
  batch (**warm**). **warm + reset** also restores the actor's writable
  memory (84 KiB) to the image after every request, as a pool would.

Both paths produce identical writes, replies and accumulated state on
both backends. Workload: 1,000 transfers or queries over 10,000 accounts.
State reads come from an in-memory map; storage cost is S4's subject.
Fixed and per-request costs are derived from batches of 1 and 1,000
requests; each figure is the median of 7 runs.

**Result: primitives.**

| | Interpreter | JIT |
|---|---|---|
| Node host call from the agent | 0.11 µs | 0.12 µs |
| Actor call round trip, nested (exit to the agent and invoke again) | 0.17 µs | 0.15 µs |
| Actor call round trip, native | 0.04 µs | 0.05 µs |
| Prepare a program, uncached (decode; compile on the JIT) | 227 µs for 3.5 KB | 502 µs for 3.5 KB |

**Result: machine setup.**

| | Interpreter | JIT |
|---|---|---|
| Agent machine per refine | 129 µs, up to 800 µs while other machines are live | 52 µs, plus 340–400 µs on its first resume |
| Actor `machine` (program preparation cached) | 1.0 µs | 1.6 µs |
| Actor memory and layout (`pages`, `poke`) | 126 µs | 47 µs |
| Actor first call | 0.8 µs | 336 µs |
| Actor second call | 0.4 µs | 0.3 µs |

**Result: per request** (fixed cost per batch / marginal cost per
request).

| Path | Interpreter | JIT |
|---|---|---|
| Transfer, nested, warm | 1,574 µs / 4.6 µs | 817 µs / 2.9 µs |
| Transfer, native, warm | 132 µs / 1.0 µs | 396 µs / 0.5 µs |
| Transfer, native, warm + reset | 135 µs / 2.5 µs | 409 µs / 1.9 µs |
| Transfer, nested, fresh | — / 136 µs | — / 421 µs |
| Transfer, native, fresh | — / 130 µs | — / 413 µs |
| Query, nested, warm | 1,598 µs / 2.3 µs | 821 µs / 1.5 µs |
| Query, native, warm | 131 µs / 0.4 µs | 391 µs / 0.2 µs |
| Accumulate, per transfer (two writes) | 0.44 µs | 0.68 µs |

**Result: where the fixed cost goes.** A one-transfer refine, timed from the
node at the agent's host calls (steady state):

| Phase | Interpreter | JIT |
|---|---|---|
| Load the agent machine | 796 µs | 219 µs |
| Agent's first resume | — | 407 µs |
| Build the actor and run it to its first `GET` | 1,071 µs | 654 µs |
| The transfer itself | 4.7 µs | 6.5 µs |
| Drop the machines | 215 µs | 65 µs |

perf attributes these costs to address-space-sized structures:

- **JIT:** `NativeMemory::sync_permissions` takes 70–82% of the samples. It
  walks the permission table of the whole 4 GiB space.
- **Interpreter:** libc fills and frees fresh pages. Every sparse memory
  allocates a million-entry page table (4 MiB) plus permission arrays, and
  an inner machine sets a second million-entry permission table.

**Findings.**

- **Warm machines meet the invocation budget about 10× over.** A nested
  transfer costs 2.9–4.6 µs, and its accumulate 0.4–0.7 µs. A query costs
  1.5–2.3 µs.
- **Nesting adds about 2.4–3.6 µs per transfer** over the native fast path.
  That is about 20 agent host calls at 0.11–0.12 µs each (exit, peek, read,
  poke, invoke), plus the agent's own code. The native path is 5–9×
  faster, but the absolute gain is small against the budget. Fewer, larger
  peeks would recover part of it.
- **A machine per invocation misses the budget by 3–8×** (130–420 µs).
  Almost none of that is execution; it is setup sized to the 4 GiB address
  space. The same setup makes up the 0.8–1.6 ms fixed cost of every
  refine, which is 25–50% of a 1–5 ms batch window.
- **Isolation between requests is affordable.** Resetting a reused
  machine's whole writable image costs about 1.4 µs for this actor.
  Dirty-page tracking (S1) makes the reset proportional to touched pages.
- **The JIT barely helps short handlers:** about 1.6× per request, since the
  cost is host calls, and its first resume costs 340–400 µs. It pays off
  on computation (S1's compute workload: 11×).
- **Preparation is too slow to repeat:** 64–140 µs per KB of program, so a
  500 KB actor takes tens of milliseconds. The runtime caches only one
  inner program per thread.

**Decision.**

- **Invocation budget:** passes with warm machines; fails with a machine per
  invocation.
- **No node-side fast path in v1.** The nested path is well within budget;
  revisit only if profiles show the agent layer.
- Required runtime work:
  - memory structures proportional to mapped pages: a two-level or hashed
    page table and permissions in the interpreter, and a JIT permission
    sync limited to changed ranges (also required by S1);
  - a machine pool on the node, keyed by program hash, for actors and for
    agent programs. A machine is reused across requests and refines, and
    its writable memory is reset to the image (dirty pages) between uses.
    It is exposed to agents as `instantiate(code_hash)`; on JAM the
    loader path (`machine`, `pages`, `poke`) remains;
  - prepared programs (decoded and compiled) cached by hash, not one per
    thread.
- **Proposed gate for that work:** acquiring and resetting a pooled machine
  ≤ 5 µs for a small actor, and building a new machine ≤ 50 µs.

**Caveats.**

- The actor is tiny. Real actors have more code and data pages: after the
  fixes, setup scales with touched pages and execution with code.
- The query budget (≤ 100 µs on a follower) also includes storage reads,
  measured in S4.

## S4 — Tables

**Setup.** `spikes/s4-tables`. Three parts, on the real disk with a warm
page cache (62 GB of RAM; every dataset fits):

- **Tables:** point reads, updates, inserts and 1,000-row scans on tables of
  u64 keys and 64-byte values, at 1M and 10M rows. Writes are committed
  without fsync, as section 9.5 proposes, unless noted. Engines:
  - redb (1 GiB default cache);
  - fjall 3.1, a pure-Rust LSM tree, with a 1 GiB block cache and the bulk
    load compacted before reading.
- **Committed roots:** an in-memory binary radix tree that stores only
  branching nodes, as the row-backed `CommittedMap` does, hashed two ways:
  - fixed-depth, the current math: every key bit is a level, so children
    are lifted through empty-sibling spines, and both children are lifted
    whenever a parent is rehashed;
  - compressed: a leaf hash commits its full key, and a branch hash commits
    its split level and both children.

  Both formats run on the same tree. Fixed-depth sibling hashes are
  placeholders, which leaves the hashing work per update exact.
- **Hashing:** BLAKE2b-256 of a 76-byte node input (a 12-byte domain and two
  children), natively and inside the PVM (`blake2b_simd`, portable code).

**Result: tables** (µs per row).

| | redb 1M | redb 10M | fjall 1M | fjall 10M |
|---|---|---|---|---|
| Bulk load | 2.2 | 11.3 | 0.9 | 1.7 |
| Size after load | 515 MiB | 24.6 GiB | 143 MiB | 928 MiB |
| Read, hit | 0.52 | 1.57 | 2.78 | 5.56 (5.24 after the update runs) |
| Read, miss | 0.51 | 1.23 | 1.56 | 2.26 |
| Update, one-row transaction | 61.5 | 70.1 | 1.51 | 1.77 |
| Update, 1,000-row transaction | 9.3 | 17.7 | 1.26 | 1.54 |
| Update, 1,000 rows with fsync | 28.6¹ | 254¹ | 1.88 | 2.07 |
| Insert new key, 1,000-row transaction | 9.2 | 17.1 | 1.28 | 1.47 |
| Scan | 0.13 | 0.15 | 0.36 | 0.25 |

¹ Inflated: the first durable commit flushes the pages of every earlier
non-durable one. With a durable commit every 10th transaction (1M rows),
updates cost 10.2 µs, or 11.7 µs with fsync, and the file stays at
515 MiB.

redb cannot reuse pages freed by non-durable commits until a durable
commit. The 10M-row load (0.7 GB of data, all non-durable) therefore grew
to 24.6 GiB.

**Result: durable log appends** (S3's node log writer; 1 KiB entries keyed
by (agent, index)).

| Entries per commit | redb | fjall |
|---|---|---|
| 1 | 380 µs | 261 µs |
| 64 | 1,104 µs (58k entries/s) | 609 µs (105k entries/s) |
| 1,024 | 6,067 µs (169k entries/s) | 2,839 µs (361k entries/s) |

**Result: committed roots** (hashes per update, then µs per update
including the tree walk; batches from 1 to 10,000 updates).

| Keys | Key bits | Fixed-depth | Compressed |
|---|---|---|---|
| 1M | 64 | 122 → 107; 25.7 → 21.9 µs | 21 → 7.9; 6.3 → 4.3 µs |
| 1M | 128 | 283 → 268; 48.5 → 37.6 µs | 21 → 8.1; 5.7 → 3.4 µs |
| 10M | 64 | 112 → 99; 18.8 → 18.0 µs | 24 → 11; 7.2 → 6.4 µs |
| 10M | 128 | 280 → 266; 42.9 → 42.0 µs | 25 → 11; 8.3 → 6.6 µs |

- Branch-node rows rewritten per update are the same in both formats: 20–24
  for single updates, 7–10 in batches of 10,000.
- A full compressed root from scratch takes 0.5 s at 1M keys and 5 s at
  10M (20M hashes).

**Result: hashing.** Native BLAKE2b: 0.17 µs. In the PVM: 29.7 µs on the
interpreter (175×) and 4.7 µs on the JIT (28×).

**Findings.**

- **redb misses the write budget at both sizes:** 9–18 µs per row in batches,
  and 60–70 µs for a single-row commit. A copy-on-write B-tree rewrites a
  leaf page per random row. Reclaiming space needs durable commits, which
  conflicts with not fsyncing applied state (S3).
- **fjall meets the write budget** (1.3–2.1 µs) at both sizes. Its reads
  miss it slightly at 10M rows (5.2–5.6 µs, warm cache) and pass at 1M
  (2.8 µs). Misses stay
  cheap (1.6–2.3 µs). Its durable log appends are 1.5–2.1× faster than
  redb's, close to S3's raw append.
- **The current root math dominates committed writes:** 100–280 hashes per
  update (18–49 µs) whatever the batch size, because spines through empty
  levels are rehashed. The compressed format needs 8–25 hashes per update
  (3.4–8.3 µs). Node-row rewrites are the same in both formats. At
  about 1.5 µs per LSM row, they favor large sorted batches at attest
  boundaries.
- **Hashing must be a host call.** In-PVM BLAKE2b is 28–175× slower than
  native.

**Caveats.**

- Reads hit a warm page cache. Cold random reads from this NVMe would add
  about 0.1 ms for either engine.
- fjall's compaction runs on background threads; that CPU is not counted.
- Steady-state LSM read cost under continuous writes depends on compaction
  tuning.

**Decision.**

- **Table budget:** reads pass on both engines; writes pass only on the LSM.
- **Proposed for section 9.5:** one LSM engine per node (fjall first) for
  state tables, Merge state, the page store, system tables and the node
  log. redb is dropped.
  - Agents share a few LSM trees (one per data class) under agent key
    prefixes, rather than a tree per agent, to bound memtables and
    background work.
  - A Raft snapshot exports an agent's prefix as a range and installs by
    range delete and ingestion.
- **Proposed for section 9.3:** adopt the compressed root format. This
  breaks root compatibility with cipher-clerk and the current
  `vos::zk::state` math, which would have to move together; that is the
  owner's call.
- Roots and node rows are updated only at attest or settlement boundaries,
  in sorted batches.
- The native hash host call is required for tree math inside the PVM.

## S6 — Merge apply

**Setup.** `spikes/s6-merge`, using `support/merkle-crdt` with an in-memory
store and BLAKE2b CIDs. The workload is a last-writer-wins map over 100,000
keys. A replica holds a history of H operations: a chain with a concurrent
branch merged every 64 operations. A peer adds 1 or 100 operations on top,
and the replica syncs them.

Two replicas are compared:

- **current:** the library's `MerkleCrdt`. Each sync re-validates the whole
  reachable DAG (`ancestry_is_valid`, which re-hashes every node), then
  rebuilds state from every node (`materialize`). Each local operation
  clones the whole state first.
- **incremental:** a 40-line prototype on the library's own
  `fetch_missing`. It applies only the fetched nodes, which arrive
  topologically sorted with their CIDs checked, onto the current state.
  The new roots follow from the fetched set: local roots that a fetched
  node points to are dropped, and the remote root is added. After the
  runs, its state equals a full rebuild.

**Result** (median time per synced operation).

| History | Current: sync 1 | Current: sync 100 (per op) | Current: local op | Incremental: sync 1 | Incremental: sync 100 (per op) |
|---|---|---|---|---|---|
| 1k | 2.3 ms | 25 µs | 17 µs | 1.06 µs | 1.17 µs |
| 10k | 25 ms | 196 µs | 26 µs | 1.03 µs | 1.02 µs |
| 100k | 441 ms | 3.7 ms | 339 µs | 1.44 µs | 1.33 µs |
| 1M | 8.7 s | 72 ms | 478 µs | 1.87 µs | 1.77 µs |

**Findings.**

- **The current library fails the merge budget by more than three orders of
  magnitude.** Sync cost grows linearly with history: 3,700× from 1k to 1M.
  The local operation grows with state size, because of the clone.
- **Incremental apply meets the gate:** 1.5–1.8× from 1k to 1M, the residue
  being the in-memory store's ordered map. The rewrite is small: the
  library's fetch and topological sort are reused as they are.

**Caveats.**

- With the node's LSM store, each fetched node adds a store lookup and
  write, about 1.5–3 µs (S4).
- Author signature checks (accept-all here) add their own cost per node.
  They still scale with the fetched nodes, not with history.
- Sequence CRDTs such as lists have their own per-operation costs. The v2
  `List` that rebuilds its order on every call is already marked for
  replacement (section 9.4).
- The epoch authorization rule is not measured.

**Decision.**

- **Merge budget:** passes with incremental apply; fails with the current
  library.
- The apply path is rewritten as section 9.4 specifies:
  - validate and apply only the fetched nodes;
  - derive the heads from the fetch frontier;
  - apply local operations in place, with no state clone.

  Full validation and rebuild remain only for recovery and audits.

## S5 — Attestable

**Setup.** `spikes/s5-attestable`, on the saga's Gray Paper 0.8.0 prover
(`trace_refine`, `prove_refine`, `verify_refine_bundle_replayed`, production
PCS configuration). The proved program is S4's guest, which runs BLAKE2b
inside the PVM. Hashing is the work an attestable root update does without
a hash precompile.

Each proof runs in its own process under a 24 GiB memory cap. Sizes stop at
2^16 steps, which peaked at 15 GiB, and larger windows are extrapolated
rather than risked.

**Finding before measuring** (corrected after review). The guest calls the
existing BLAKE2b and Ristretto precompiles as host calls: `csrw 0x801;
ecall` lowers to `ecalli 100`–`114`. Three things keep them from a
conformant attestable program today:

- **Id clash:** BLAKE2b's id 100 is JAM's `log` call (JIP-1).
- **Not on the refine path:** only the legacy tracer intercepts them
  (`TracingPvm::run_with_precompiles`). The Gray Paper refine prover
  (`trace_refine`) treats any host call other than 9–14 as an error.
- **JAR leftovers:** the proof allow-list still accepts JAR lifecycle stubs
  (ids 1, 2, 4, 5, 6, 26, which "return 0"); JAM assigns those ids other
  meanings.

The measurements below therefore hash inside the PVM.

An earlier version of this entry said the precompiles used the JAR `ecall`
opcode; they do not.

**Result: steps.** One BLAKE2b of a 76-byte node input costs 4,790 PVM
steps in the guest (portable `blake2b_simd`). The program's fixed cost is
117 steps.

**Result: proving** (one slice each).

| Steps | Prove | Throughput | Peak RSS | Proof | Verify (replay + STARK) |
|---|---|---|---|---|---|
| 4,933 | 2.25 s | 2.2k steps/s | 4.6 GiB | 556 KiB | 1.1 s |
| 14,509 | 2.96 s | 4.9k steps/s | 6.1 GiB | 565 KiB | 1.4 s |
| 33,661 | 4.90 s | 6.9k steps/s | 9.2 GiB | 571 KiB | 2.9 s |
| 67,177 | 7.38 s | 9.1k steps/s | 15.0 GiB | 582 KiB | 4.0 s |

Roughly 2 s plus 80 µs per step to prove, and 4.6 GiB plus about 170 KiB
per step of memory. `prove_refine` proves each machine slice as one STARK,
so one slice tops out near 2^17 steps on a 64 GB machine. The prover
already supports chained segments (`prove_chain`), but the refine path
does not use them.

**Derived: a transfer kernel.** A transfer touches two leaves. Proving it
means checking each leaf's path against the root before and recomputing it
for the root after, with hash counts from S4 at 10M keys:

| Root format | Hashes per transfer | Steps, hashing in the PVM | Proving per transfer | 1,000-transfer window |
|---|---|---|---|---|
| Compressed, batched window | about 45 | about 0.2M | about 25 s | about 6 prover-hours |
| Compressed, alone | about 100 | about 0.5M | about 55 s | — |
| Fixed-depth, 128-bit keys | about 1,080 | about 5.2M | about 10 min | about 160 prover-hours |

- With a hash precompile, a transfer becomes about 45–100 compressions
  plus a few thousand steps of kernel logic. The cost then depends on the
  chip's rows per compression, which is not measured here.
- Signature checks inside the kernel would add to all of these.
- Witness size: about 1.6 KB per transfer with independent paths at 10M
  keys (two leaves and about 23 siblings each). A 1,000-transfer window
  shares upper levels, which brings it to about 0.9 KB per transfer.

**Findings.**

- **Hashing dominates attestable cost.** Without a precompile, every hash
  costs about 0.4 s of proving. The current fixed-depth root math makes a
  single transfer cost minutes.
- **The precompiles have to move to the Gray Paper refine path:**
  - an id outside JAM's assignments;
  - native service in the refine host;
  - chip records in the refine collector.

  The BLAKE2b and Ristretto chips themselves are reused.
- **Memory, not time, limits a proof.** About 170 KiB per step; slices
  beyond about 2^16–2^17 steps must be chained.
- **Per-item proofs do not scale; window proofs do.** Sharing upper tree
  levels halves the hashing per transfer, and a window pays the fixed
  proof cost once.

**Decision.**

- **Proposed size guideline:**
  - an attestable call proves in chained segments of at most 2^16 steps
    (about 7 s and 15 GiB each on the reference machine);
  - a whole settlement window targets about 1M steps (about 2 minutes of
    proving);
  - a window covers many items, never one proof per item.

  The 1M-step target assumes the hash precompile: without one, a single
  transfer already costs 0.2–0.5M steps. It is checked once the
  precompile exists.
- Required work:
  - precompiles on the Gray Paper refine path, with VOS-owned `ecalli`
    ids, backed by the existing BLAKE2b and Ristretto chips;
  - chained segments in the refine prover;
  - the compressed root format (S4) for every committed map that
    attestable code reads.

**Caveats.**

- One measured program (hashing); the kernel figures are derived from S4's
  hash counts, not from a proved transfer kernel.
- Measured on the saga's prover. Its memory profile may differ from the
  prover line on master.

## S5b — Precompiles on the JAM refine path

**Question** (owner, after S5). Can the zkVM keep its precompiles while
guests use only JAM refine host calls?

**Prototype.** Branch `exp/gp-precompiles` (`6659ddea`, from the saga
commit), with the spike in `spikes/s5-precompile`. 11 files changed,
+359/−40:

- **Id:** BLAKE2b compression is `ecalli 0x400`. VOS precompiles take
  `0x400..=0x4ff`, outside every id JAM assigns (the Gray Paper calls and
  JIP-1 `log` at 100). The CPU chip keeps its internal dispatch code, so
  the AIR is unchanged.
- **Runtime:** the refine host serves the call in place, for the outer
  machine and for inner machines, on the interpreter and the JIT. Execution
  continues in the same slice, and each call is reported as a `Precompile`
  observation (`pvm/runtime/src/precompile.rs`).
- **Prover:** the refine collector acknowledges the `ecalli` row, as the
  legacy tracer did, and attaches the BLAKE2b chip call and its memory
  operations to the slice.
- **Guest:** calls the precompile. If φ[7] comes back as `WHAT`, it
  compresses in software. That is what a JAM node answers for an id it
  does not assign; the precompile itself leaves every register unchanged.

**Result: agreement and steps** (the same 76-byte node hash chain as S4).

| Hashes | Outputs | Steps on VOS (precompile) | Steps on a JAM-like host (fallback) |
|---|---|---|---|
| 1 | VOS = JAM fallback = S4 software | 176 | 4,869 |
| 100 | all agree | 6,710 | 476,010 |
| 1,000 | all agree | 66,110 | 4,759,110 |

The precompile costs about 66 steps per hash; the fallback costs about
4,760.

**Result: proving** (one slice, 24 GiB cap).

| Hashes | Steps | Prove | Peak RSS | Proof | Verify |
|---|---|---|---|---|---|
| 1 | 176 | 2.02 s | 4.0 GiB | 855 KiB | 0.9 s |
| 10 | 770 | 2.08 s | 4.2 GiB | 855 KiB | 1.0 s |
| 100 | 6,710 | 3.94 s | 8.4 GiB | 870 KiB | 1.9 s |
| 200 | 13,310 | 6.49 s | 13.5 GiB | 882 KiB | 3.0 s |
| 400 | 26,510 | 15.65 s | 23.8 GiB | 889 KiB | 7.2 s |

A compression costs about 25–45 ms of proving and about 50 MiB of prover
memory. Hashing inside the PVM costs about 0.4 s and 800 MiB per hash, so
the precompile is about 10× faster and 16× smaller. One 24 GiB slice holds
about 400 compressions.

**Result: soundness checks.**

| Tampering | Outcome |
|---|---|
| Change a recorded compression input | Proving succeeds, but the STARK alone rejects it ("claimed logup sum is not zero"); replay verification rejects it too |
| Change the output bytes in the memory ledger | Proving fails (constraints not satisfied) |
| Drop a chip record | Proving fails (constraints not satisfied) |

**Result: tests.**

- Runtime: 276 pass.
- Prover library: 120 pass; one legacy test was re-encoded for the two-byte
  id.
- `prove_vos_actor`: 30 pass. The 5 failures also fail on the unmodified
  saga commit; they load JAR-format actor blobs.

**Derived: a transfer kernel.**

- About 45–100 compressions per transfer: about 2–4 s of proving, and about
  0.5–1.2 prover-hours for a 1,000-transfer window.
- The chip's memory per call becomes the limit, so segments must be cut by
  chip rows as well as by steps.

**Findings.**

- **Precompiles work over JAM host calls.** The same program runs on a
  VOS node (precompile) and on a JAM node (software fallback) with
  identical outputs. Only gas differs.
- **The change is small and leaves the AIR alone:** a new id, in-place
  service in the refine host, and chip records in the refine collector.
- **The BLAKE2b chip's memory, about 50 MiB per compression, is the next
  prover cost to cut.**

**Remaining work:**

- Move Ristretto and the scalar precompiles (110–114) into the VOS range
  the same way, and give the guest shims the `WHAT` fallback.
- Remove the JAR leftovers:
  - lifecycle stubs in the proof allow-list (ids 1, 2, 4, 5, 6, 26) and
    the VOS capability calls (117–119);
  - the capability-manifest encoding and the `ecall` opcode paths in the
    compiler and the AIR;
  - `run_with_vos_stubs`;
  - the JAR blob tests.
- Price precompiles in VOS gas. Today a call costs only its instruction's
  block gas, while the JAM fallback pays the full software cost.
- Cut segments by chip rows as well as by steps.
- ~~Investigate the linker warning "unresolved return_fixup", printed while
  linking this guest.~~ Fixed in slice 1, step 1.1: such a return now
  targets a trap, where it used to name the entry point.

## Note — Settlement verifier under Gray Paper 0.8.0 (slice 1)

The Poseidon2-M31 settlement verifier (`pvm/proof/settlement-verifier`),
linked as a standard program and run on the interpreter, accepts the
honest fixture:

- 10,683,638 instructions;
- 28,951,968 gas under the 0.8.0 block-gas model, about 2.7 gas per
  instruction.

It ran 10,677,000 instructions and 28,882,195 gas while the translator
still folded a constant into the branch that compares with it; it no
longer does, since the constant can be read after the branch.

A first measurement read 102,671,695 gas because the refine harness still
charged JAR's 1,500 gas per mapped page at initialization (49,193 pages for
the verifier's 192 MiB heap). Gray Paper 0.8.0 has no such charge; slice 1
removed it.

The earlier figure of about 10.7M cycles was measured under JAR. One segment
fits a refine's gas budget comfortably; a settlement window of many segments
needs aggregation (core model section 11.4).

## Note — S1, S2 and S5b on the slice 1 base

Slice 1's step 1.7 reran the in-tree S1 (`snapshots`), S2 (`nesting`) and
S5b (`precompile`) harnesses against the finished PVM base: Gray Paper
0.8.0 only, page-proportional memory, dirty-page tracking and the machine
pool. Same laptop, other work running (load average 3–5).

**S1, snapshots.** Captures use dirty-page tracking; a full scan of the
writable pages stays as the before-picture and as a check.

| Suspension | Scan | Capture, interpreter | Capture, JIT | Restore, fresh JIT | Restore, pooled (interpreter / JIT) |
|---|---|---|---|---|---|
| Transfer and saga, 3 pages | 350–630 µs | 0.2–0.6 µs | 6–19 µs | 28–34 µs | 0.3 / 0.2–0.3 µs |
| Compute, 34 changed pages | 0.8–1.7 ms | 0.9–2.8 µs | 10–37 µs | 440–500 µs | 150–190 / about 400 µs |

Copying and hashing the pages to ship them costs 10–15 µs for three pages
and about 120 µs for 34. A pooled restore, as timed here, acquires a
machine and writes the snapshot's pages, which for the compute workload is
all 514 dirty pages. On the JIT that is mostly faulting those pages back
in, since the last reset discarded them. It excludes the machine's reset
when it returns to the pool (2.4–3.5 µs) and loading registers, gas and
the counter, which a real restore also does. The JIT captures ran under
load; on a quiet machine step 1.5 measured 8–12 µs. The decision to use
snapshots with no replay journal rests on the original S1 figures above,
which still stand.

**S2, invocation** (per request, transfer):

| Path | Interpreter | JIT |
|---|---|---|
| Nested in the agent, fresh actor (`machine`, `pages`, `poke`) | 12.0 µs | 59.1 µs |
| Nested in the agent, pooled actor (`instantiate`) | 7.1 µs | 12.7 µs |
| Nested in the agent, actor kept warm | 4.0 µs | 3.0 µs |
| Driven by the node, fresh actor | 7.9 µs | 54.8 µs |
| Driven by the node, pooled actor | 3.5 µs | 9.3 µs |
| Driven by the node, actor kept warm | 0.9 µs | 0.6 µs |

The agent's pooled path falls back to building the actor itself when the
host answers `WHAT`, as JAM does; both give the same work result. An agent
machine per refine costs 6.0 µs (interpreter) and 17.8 µs (JIT), against
0.8–1.6 ms in S2.

**S5b, precompile proving** (one slice, 24 GiB cap):

| Hashes | Steps | Prove | Peak RSS | Proof | Verify |
|---|---|---|---|---|---|
| 1 | 470 | 2.11 s | 4.0 GiB | 856 KiB | 1.1 s |
| 10 | 3,395 | 2.53 s | 4.4 GiB | 856 KiB | 1.2 s |
| 100 | 32,645 | 5.64 s | 10.5 GiB | 866 KiB | 2.9 s |

The guest now hashes through the shim crate's streaming `blake2b_hash`,
which handles the parameter block, padding and parts, so it takes about
325 steps per hash where the spike's hand-written loop took 66. The
proving time added is consistent with those extra steps at about 80 µs
each, so the compressions themselves appear to cost the same.

The consequence: core model section 11.3's target of about 1M steps per
window assumed 66 steps per compression. At 325, a 1,000-transfer window
(45k–100k compressions) would take 15–33M steps. Attestable kernels must
therefore hash tree nodes with the compress-level call (one block for a
76-byte node), never the streaming API.
