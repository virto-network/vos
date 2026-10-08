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
  - separate stores pay one fsync per agent per round;
  - fsyncs run on executor threads and starve heartbeats, so leaders are
    lost from 64 active agents up;
  - one shared redb with commits in the task serializes the writers.
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
  - one shared executor; the thread-per-group `Worker` is dropped.

**Proposed for section 9.5.** All Raft logs on a node go to one node-level
log: a redb table keyed by (agent, index) first, then a raw append-only
segment log if large entries make redb's up-to-2× write cost matter.
Large entries include witnesses and snapshot pages.

**Open.** Find the cause of the slow 64 KiB entries before witnesses ride
the log.
