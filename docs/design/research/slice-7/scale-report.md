# The scale test: runs 1–6

Slice 7's M3.9 asks for the scale runs reported against "The scale test"
targets T1–T6 (`slice-7-mobile.md`, S26, narrowed by S35 and S36). The
runs were made in five rounds, each recorded in `slice-7-progress.md`:
7.6 (run 1), 7.6b (the per-replica levers, run 1 again), 7.6c (runs 2–6),
7.6d (the election storm, levers 1 and 2, runs 3–6 again) and 7.6e (the
soak's step, the cold restart's memory, runs 4–6 again), then run 3 once
more on the final build over the node API (7.23). This report
gathers them; every number is from those entries or from the runs' own
reports under `~/vos-scale/runs/` on the coordinating desktop. Tags:
[measured] from a run; [derived] arithmetic on measured numbers, shown.

## Verdicts

| target | verdict | best final numbers | runs |
|---|---|---|---|
| T1 users: 10^6 users, 5,000 calls/s, `x` = 98%, client p99 ≤ 50 ms, no session refused | **missed** (p99) | final build over the node API (7.23, two runs): 3,999.5 transfers/s answered at offer; transfers p50 / p99 / p99.9 197 ms / 1.31 s / 2.1 s, none timed out, no session refused. Over node HTTP: 328 ms / 2.6 s / 4.2 s (7.6d). At the final node over the soak's two hours: 328 ms / 3.1 s / 6.3 s, its first half hour's p99 (median 10-minute interval) 786 ms (7.6e) | `20261101T182528Z-r3f-api-1`, `20261101T185808Z-r3f-api-2`; `20261030T235838Z-r3d-if1`; `20261031T160903Z-r6e-soak` |
| T2 headroom: knee ≥ 40,000 calls/s on ≥ 4 node hosts | **not measurable** (S35: one node host) | one host's knee about 8,000–9,000 calls/s at 10^5 users (`x` = 98%), about 10,000 at `x` = 30%, about 5,000 at 10^6 users; not re-measured after 7.6d–e's levers | run 2's steps (7.6c), `20261027T184355Z-r3-u1m-6400` |
| T3 agents: 10^4 a space, idle ≤ 5% of a core and ≤ 64 MiB per 1,000 replicas | **met**, the 10^5 stretch's idle cost met; beyond the target, 10^5 agents also held the baseline load | 45.6 MiB and 0.16% of a core per 1,000 replicas (1k → 10k, 7.6b); 46 MiB per 1,000 at 10^4 under load (7.6c). 10^5: 43 MiB per 1,000 idle; under the baseline load 0 elections, transfers p50 / p99 / p99.9 197 ms / 1.05–1.31 s / 2.1 s, RSS flat at 6.1 GiB a node (7.6d) | `20261027T072743Z-r1b-idle-10k`, `20261027T192015Z-r4-idle-10k`, `20261031T014621Z-r4d-idle-100k`, `20261031T080020Z-r4e-idle-100k` |
| T4 windows: every read served by `B_w + D + 10 s`, none `NotClosed` without a fault | **met where measured** (p99.9 at most 6.3 s from the close, none `NotClosed`; the maximum is not recorded); the representative's work per reader not separated | readers' reads 15,520 of 15,520 at 10^5 agents (p99 / p99.9 4.2 / 5.2 s from the close); reads at a cut 0 errors in every run that kept up (181,856 over the final soak, p99.9 6.3 s from the close); C9's fail rate 0 of 139,467 at the LAN's 1–10 ms skew (7.6c) | `20261031T014621Z-r4d-idle-100k`, `20261031T160903Z-r6e-soak` |
| T5-partial: a node's unit killed under load; led again ≤ 5 s, throughput ≥ 80% within 30 s, rejoined ≤ 60 s | **partly met**: re-election and rejoin met, throughput missed in all three rounds | 7.6d: led again p50 2.5 s, at most 3.6 s; answering 7.6 s after its restart; throughput under 80% for 34 of the first 60 s. 7.6e (final): at most 5.3 s (0.3 s over, at the polls' 1 s grain), answering in 2.2 s, under 80% for 36 s | `20261031T051738Z-r5d-fault-c2`, `20261031T181145Z-r5e-fault-c2` |
| T6 soak: 2 h at T1, RSS within 10% after minute 30, p99 within 20% of the first half hour | **missed** (p99); RSS met on 10-minute means | final node: no collapse, 0 timed out, answered at offer for 2 h; RSS's 10-minute means +7.6–8.9% from minutes 20–30 to 110–120 (raw samples swing about ±200 MiB with the memtables); p99 0.8 s in the first half hour, 2.1 s in the last ten minutes | `20261031T160903Z-r6e-soak` |

## The hardware and the setup

- **Nodes** (S35): three on `compumax` (AMD Threadripper 2990WX), each its
  own systemd unit with its own data directory, cores 0-3, 4-7 and 8-11
  (4 cores a node), all three on one Samsung 970 PRO NVMe and one 1 GbE
  wired link. Memory caps 8 GiB a node; 12 GiB for runs at 10^5 agents.
- **The driver:** run 1 on the desktop (Intel Core Ultra 7 155H) over
  Wi-Fi (S45; run 1's round trips p50 1.0 ms, p99 2.4 ms); from run 2 on,
  `sigma` (i5-1340P, wired, cores 0-7, `performance`; round trips p50
  0.4 ms, p99 0.4–0.6 ms), the desktop only coordinating (S56). Its
  lateness (the reports' "late at worst"): at most 3.1 ms in run 2 (0.00%
  of sends past 10 ms); 21–29 ms in `r3d-if1`, `r6d-soak`, `r6e-soak` and
  `r5e-fault-c2` (at most 0.71% past 10 ms, `r6d`); 968 ms once in
  `r5d-fault-c2` (0.33% past 10 ms), during its timeout flood. At most
  0.41 cores.
- **compumax's governor:** `performance` (S53) for runs 1 and 1b, for runs
  2–4 at 10^4 (7.6c, 2026-10-27), and for every run of 7.6d and 7.6e;
  `ondemand` for 7.6c's run 4 at 10^5 and runs 5–6 (2026-10-30), warned by
  each `check`; under load the nodes' cores ran at 76% of their top clock
  under both. Every target's final number above is from a `performance`
  run.
- **Clocks:** compumax 16–34 ms ahead of the desktop in run 1, 1–10 ms in
  every later `check`, all hosts synced.
- **Every run from 2 on:** `L` = 2 min, `--representative`, `--identity`
  (a row a user), the harness's default mix (transfers 80%, queries 15%,
  workflows 4.5%, reads at a cut 0.5%), `K` = 64 shard agents, a full
  deploy, the window the load past a 10 s ramp (the 30-minute and longer
  runs reported again with `--ramp-s 60`).
- **The nodes' revisions,** as each run's report names them
  (`versions.revision`): 7.6c's `bins-7.6c` (vos-core `920103b3`);
  `r3d-if1` `eb76f560`; `r4d-idle-100k` and `r5d-fault-c2` `b9a5c89a`;
  `r6d-soak` `e3a74620`; `r4e`, `r4f` and `r4j` `d9824539`; `r6e-soak`
  and `r5e-fault-c2` `24f11862` (`bins-7.6e3`). The `revision` is the
  deployed one: for the 7.6e restarts the binaries were swapped in place,
  so `r4i` ran `274d76e3` and `r4j` `24f11862` under a report naming
  `d9824539` (progress, 7.6e).

## The runs, by target

### T1 and T2: users and the knee

**Run 2, the baseline** (7.6c; `U` = 10^5, 8-minute steps):
- At `x` = 98% the nodes kept up through 8,000 calls a second (p99 1–7 s,
  no trend); at 10,000 they answered about 7,200 transfers a second
  against 8,000 offered and the backlog grew. **One host's knee is about
  8,000–9,000 a second**; at `x` = 30% about 10,000.
- No step had a p99 within 50 ms: transfers 98 / 229 / 328 ms (p50 / p99
  / p99.9) at 1,000 a second, 164 / 786 / 1,311 ms at 5,000 over 30
  minutes. 0 errors, elections and leader changes in every step.
- Where a transfer's time went at 5,000 a second (node 1, means): queued
  63 ms (one batch in flight a group), batch 103 ms (commit 45, commit to
  apply 37, refine 2.1, dry run 0.9, executor queues 1.8 and 3.7, propose
  1.1), 19 inputs a batch; the writer's fsync 21 ms mean, p99 82 ms, on
  the disk the three nodes share.

**Run 3, users** (`U` = 10^6, `x` = 98%, 30 minutes):

| round | node | transfers answered/s | p50 / p99 / p99.9 | timed out | run |
|---|---|---|---|---|---|
| 7.6c | `920103b3` | 3,989 | 393 ms / 10.5 s / 25.2 s | 223 | `20261027T180915Z-r3-u1m-5000` |
| 7.6c, 6,400/s | `920103b3` | 3,652 | 41.9 s / 537 s / 671 s | 1,479,494 | `20261027T184355Z-r3-u1m-6400` |
| 7.6d, one batch in flight | `eb76f560` | 3,999.5 | 328 ms / 2.6 s / 4.2 s | 0 | `20261030T235838Z-r3d-if1` |

- At 6,400 a second (80% of the 10^5 knee) run 3 collapsed: **at 10^6
  users the knee is about 5,000 a second.** From 10^5 to 10^6 users at the
  same rate, the disk writes rose 51 → 78 MB/s and the fsync mean 21 → 35
  ms (p99 82 → 262 ms), the batches doubled in size and length, and CPU
  barely moved: the shared disk binds at T1's shape.
- No session was refused in any run.

**T1: missed.** The best p99 at T1's shape is 2.6 s (7.6d), 52 times the
target [derived: 2.6 s ÷ 50 ms]; even at 10^5 users and 1,000 a second it was 229 ms. **T2: not
measurable** on one node host (S35); the knee was not re-measured after
7.6d and 7.6e's levers.

### T3: idle agents

**Run 1, the per-replica cost** (`--shards 8 --idle I --users 1000 --rate
10`; every agent has a replica on each node, so `I` idle agents are `I`
replicas a node):

| round | replicas a node | RSS at the window's start | node CPU | runtime-thread wakes/s | run |
|---|---|---|---|---|---|
| 7.6 | 1,008 / 5,008 / 10,008 | 307 / 1,182 / 2,272 MiB | 7.4 / 9.8 / 12.6% | 957 / 2,648 / 4,579 | `…211953Z-r1-idle-1k`, `…220041Z-r1-idle-5k`, `…225257Z-r1-idle-10k` |
| 7.6b | 1,009 / 10,009 | 132 / 542 MiB | 6.7 / 8.1% | 527 / 817 | `20261027T064256Z-r1b-idle-1k`, `20261027T072743Z-r1b-idle-10k` |

Per 1,000 idle replicas (the slope from 1k to 10k): **218 MiB and 0.58%
of a core before, 45.6 MiB and 0.16% after** (T3: 64 MiB, 5%); runtime
wakes 0.40 → 0.032 a replica a second; the intercept about 86 MiB.
Every replica quiet at both sizes; 0 elections.

**Run 4, agents under the baseline load** (`U` = 10^5, 5,000/s, readers 1%):

| round | `I` | idle RSS a node | under load | transfers p50 / p99 / p99.9 | elections | run |
|---|---|---|---|---|---|---|
| 7.6c | 10^4 | | 2,294 MiB | 164 ms / 918 ms / 1.3 s | 0 | `20261027T192015Z-r4-idle-10k` |
| 7.6c (`ondemand`) | 10^5 | 4,330–4,440 MiB | to the 12 GiB cap in 10.5 min, two nodes OOM-killed | 16.8 s / 58.7 s at 5 min | 1.45 million (node 2) | `20261030T113939Z-r4-idle-100k-c` |
| 7.6d | 10^5 | 4,297–4,314 MiB | 4.4 → 6.0 GiB in 15 min, then flat at 6.1 | 197 ms / 1.05 s / 2.1 s | 0 | `20261031T014621Z-r4d-idle-100k` |
| 7.6d, again (`r4e`, report revision `d9824539`) | 10^5 | | | 197 ms / 1.31 s / 2.1 s | 0 | `20261031T080020Z-r4e-idle-100k` |

At 10^5 the pair heartbeat's thread (`vos-liveness`) fell from 12.5–12.9%
to 3.8–4.0% of a core idle. **T3 met at 10^4; the 10^5 stretch's idle
cost met (43 MiB per 1,000).** Beyond T3, which bounds idle cost, the
nodes also held the baseline load at 10^5 agents from 7.6d on.

**The cold restart at 10^5** (run 4's agents started again on their data,
the baseline load at once):

| round | answering after `up` | groups led | RSS | transfers p50 / p99 / p99.9 | run |
|---|---|---|---|---|---|
| 7.6c | 3.5 min | 6,468 of 100,066 after 20 min | | refused `NotLeader`, then timed out | `20261030T111501Z-r4-idle-100k-b` |
| 7.6d | 2.75 min | 52,000 at 8 min, about 100/s | 1 GiB a minute, node 3 OOM-killed at 12.8 min | timeouts, then OOM | `20261031T113827Z-r4f-idle-100k-b` |
| 7.6e (final) | within 21 s with `check` (`r4i`) | all 100,066, every one quiet, at the first poll (2 min) | flat, 6.2–6.3 GiB at most | 524 ms / 8.4 s / 16.8 s, 0 errors | `20261031T153134Z-r4j-idle-100k-b` |

Converged within memory, but the leaders came out unbalanced (node 2 led
45,621 of 100,066, node 3 24,484, node 1 29,961 at 76% of its 4 cores),
and its p99 is 8.4 s against 1.3 s in a run that did not restart.

### T4: reads at a cut

The latency is the harness's `read_at_cut` measure (`cut_read` and
`reader_read` rows): from the window's close, `B_w + D`, so the bound
leaves 10 s past it. Only run 4 ran T4's readers (1% of agents reading a
window); the other rows are the mix's reads at a cut (0.5% of calls). The
reports record p50, p99, p99.9 and `not_closed`, not the maximum.

| run | reads | served | from the close, p99 / p99.9 | |
|---|---|---|---|---|
| run 2's 30-minute steps (7.6c) | 46,652 and 46,368 | all | p99 2.1 s | `…170345Z-r2-x98-5000-steady`, `…173625Z-r2-x30-5000-steady` |
| run 4, 10^4 (7.6c) | 46,399; readers 1,560 | all | 2.6 s; readers' p99 1.8 s | `20261027T192015Z-r4-idle-10k` |
| run 4, 10^5 (7.6d) | readers 15,520 | all | readers' 4.2 / 5.2 s (the first read 0.52 s p99 from its send) | `20261031T014621Z-r4d-idle-100k` |
| run 3, 10^6 users (7.6d) | 47,006 | all, 0 errors | 6.3 / 6.3 s | `20261030T235838Z-r3d-if1` |
| run 6, 2 h (7.6e) | 181,856 | all, 0 errors | 5.2 / 6.3 s | `20261031T160903Z-r6e-soak` |

- None ended `NotClosed` in the runs that kept up. Where the calls timed
  out, the reads failed with them (7.6c's run 3: 1 of 47,005 timed out;
  its run 6: 19,941 of 117,007; 7.6e's fault run: 2,066 of 43,894, of
  which 2,044 timed out, 17 `Behind`, 5 `StaleQuery`).
- **C9's fail rate** at the LAN's 1–10 ms skew: 0 of 139,467 reads in the
  7.6c runs that kept up.
- **C10's proportionality** (the representative's work a window
  proportional to readers) was not separated in any run.
- T4 is **met where measured**: p99.9 at most 6.3 s from the close
  against the bound's 10 s, none `NotClosed`.

### T5-partial: a node's unit killed

Run 3's shape (10^6 users, 5,000 a second), c2's unit SIGKILLed at 600 s
and started again at 900 s, polls every second:

| | 7.6c (`ondemand`) | 7.6d | 7.6e (final) | bound |
|---|---|---|---|---|
| agents c2 led at the kill | 21 | 23 | 26 | |
| each led again elsewhere | p50 2.9 s, at most 4.9 s | p50 2.5 s, at most 3.6 s | p50 3.1 s, at most 5.3 s | 5 s |
| throughput under 80% after the kill | 33 of the first 60 s | 34 | 36 | 30 s |
| answering after its restart | 7.1 s | 7.6 s | 2.2 s | 60 s |
| its replicas caught up | 163 s, from 1,900 entries behind | | | |
| calls timed out over the run, by the progress record | 839,000 (all kinds) | 873,473 (transfers) | 485,858 (transfers, the driver's own timeout) | |
| run | `20261030T143927Z-r5-fault-c2` | `20261031T051738Z-r5d-fault-c2` | `20261031T181145Z-r5e-fault-c2` | |

- **The throughput gap** is the calls in flight to c2: they time out at
  the driver's 30 s bound and hold their users' next calls (18,268 timed
  out in the 30 s from 30 s after the kill, 7.6e).
- **The restart costs more than the kill.** For 40 s after it, queries
  routed to the catching-up follower were refused `Behind` (up to 10,000
  a second, 7.6c); the catch-up tips the nodes, at their knee at T1's
  shape, past it: transfers p99 2.1 s before the kill, 134–268 s from the
  restart on (7.6e). No round settled again.

### T6: the soak

Run 3's shape for two hours:

| round | answered/s over the run | timed out | p99 by 10 minutes | RSS a node | run |
|---|---|---|---|---|---|
| 7.6c (`ondemand`) | collapsed at minute 30 (1,387–1,651/s by the end) | 9.5 million | 1.0–1.8 s to minute 30; 67 s at 30–40, up to 36 min by the end | 1,960–2,270 MiB, +10–13% after minute 30 | `20261030T151526Z-r6-soak` |
| 7.6d | 2,790 | 7.74 million | 1.0–2.1 s to minute 30; 84 s at 30–40, 31 min by the end | 1,938–2,215 MiB, +11.8% at most | `20261031T055339Z-r6d-soak` |
| 7.6e (final) | at offer (4,999.5 calls/s offered) for 2 h | 0 | 786 ms (0–30) → 1,049 (30–40) → 1,180 (50–60) → 1,311 (80–90) → 2,097 ms (110–120) | 1,996–2,197 MiB at the 10-minute marks | `20261031T160903Z-r6e-soak` |

- 7.6e: of 36.3 million calls, 120 refused, all after minute 60
  (`Expired` 24, `StaleSession` 96: sessions the agents expired at their
  hour that the driver still held; not investigated). 551,862 users'
  accounts written by the end, 551,982 sessions (7.6d: 8.77 million, a
  session per timed-out call's user).
- **RSS, by its measure** [derived from the runs' samples against the
  report's window]: the 10-minute marks stay within 5.8% of minute 30's
  (c3 2,076 → 2,197 MiB at 90; the progress record's "within 5.0%"
  did not name its measure); the 10-minute means rise 7.6–8.9% from minutes 20–30
  to 110–120 (c1 1,983 → 2,160, c2 1,988 → 2,139, c3 1,977 → 2,141 MiB);
  raw samples swing about ±200 MiB with the memtables' cycle, peaking at
  2,310–2,344 MiB, 21–23% over the minute-30 sample. Within 10% holds on
  marks and means, not on raw peaks.
- **T6: RSS met (on 10-minute marks and means); p99 missed.** It doubled from the first half hour to the
  last ten minutes, against within 20%. It follows the commit: commit p50
  56 → 92 ms, the writer's fsync mean 28 → 40 ms as the state grows, on the
  one shared disk.

## Run 3 on the final build (over the node API)

Step 7.23's rerun of run 3 on the final build, and S50's T1 re-measured
over the node API (the node's HTTP was deleted in C10). It uses vos-core
`88fc26e18`, built under `~/vos-scale/bins-s7run3`. The shape is the one
recorded for `r3d-if1`: `--shards 64 --users 1000000 --rate 5000 --secs 1860
--identity --representative`, `x` = 98%, one batch in flight (the node's
default), a full deploy, and the same hosts and cores. Two repetitions,
on 2026-11-01.

- **Governors:** compumax `performance` on all 32 cores (`check` read the
  nodes' cores as such). sigma came back from a restart (an unrelated hang)
  with `powersave` (intel_pstate, `balance_performance`), which `check`
  warned of, and it was not changed. The driver used 0.25 cores and was
  late by at most 23 ms (0.00% of sends past 10 ms), as in `r3d-if1`.
- **The inventory:** `ingress = 7701–7703` became `api = 8701–8703`. The
  file named no `transport`, `driver_connections` or
  `ingress_connections`.

Transfers [measured]:

| run | node | transport | answered/s | p50 / p99 / p99.9 | timed out | refused | node CPU (of 4) | RSS MiB |
|---|---|---|---|---|---|---|---|---|
| `20261030T235838Z-r3d-if1` | `eb76f560` | node HTTPS, 512 connections a node | 3,999.5 | 328 ms / 2.6 s / 4.2 s | 0 | 0 | 2.48–2.70 | 2,068–2,097 |
| `20261101T182528Z-r3f-api-1` | `88fc26e18` | node API, QUIC, one connection a node | 3,999.5 | 197 ms / 1.31 s / 2.1 s | 0 | 0 | 2.63–2.79 | 1,960–1,998 |
| `20261101T185808Z-r3f-api-2` | `88fc26e18` | the same | 3,999.5 | 197 ms / 1.31 s / 2.1 s | 0 | 0 | 2.66–2.78 | 1,916–1,974 |

- **Every kind:** each run answered all 9,299,728 calls, with 0 errors, 0
  sessions refused and 0 leader changes. Queries p99 0.66–0.79 s (was
  1.8 s), workflows 1.8–2.1 s (was 4.2 s), reads at a cut p99 from the
  close 3.7–4.2 s (was 6.3 s).
- **The histograms' grain:** the harness's buckets are a quarter-octave
  wide, so 1.31 s and 2.6 s are bucket bounds. The halving is eight
  buckets.
- **The 10-second intervals:** the transfers' p99 in each 10-second
  interval over the run had a median of 786 ms in both runs (was 1.31 s),
  a 90th percentile of 1.3–1.6 s (was 2.6 s) and a maximum of 2.6 s (was
  6.3 s).
- **The nodes' stages, p50:**

  | stage | `r3d-if1` | final build |
  |---|---|---|
  | batch | 131 ms | 98 ms |
  | commit | 49–57 ms | 41 ms |
  | queued | 82 ms | 57–65 ms |
  | disk time per I/O | 16.8 ms | 12.8–13.2 ms |
  | NVMe `%util` | 66% | 70% |

**What differs from `r3d-if1`, and what it explains:**
- **The node's code:** `eb76f560` to `88fc26e18`, 150 commits.
  - On this path: 7.6d's last two (`d26eecd3`, the starts' reads on the
    executors; `d9824539`, `between` from a batch's landing).
  - 7.6e's scan that ends at its prefix (`63b2f033`), the placements
    stored by one task, and the campaigns handed on.
  - C10's deletion of the node's HTTP.
  - The rest (the credential and device-proof checks, the cuts, the
    code-quality steps) adds no work to an uncredentialed call.
- **Most of the gain came with 7.6e's node, not with the transport.**
  `r6e-soak` (`24f11862`, still over node HTTPS) had a median 10-second
  p99 of 786 ms over its first 31 minutes, the same as here. Its 90th
  percentile was 1.8 s and its maximum 3.7 s, against 1.3–1.6 s and 2.6 s
  here. Over the same span the API adds no tail that HTTP did not have;
  it trims the worst intervals somewhat. A run of `24f11862` on the same
  day would separate the two, but it was not made.
- **The node's CPU moved off the runtime thread:**
  - `vos-node` dropped from 42–46% of a core to 23–26%. The HTTP server,
    its parsing and its 512 connections a node ran there.
  - The executors rose from 42–47% to 52–56% each, and the total node
    CPU from 2.5–2.7 to 2.6–2.8 cores.
  - `vos-net` stayed at 18–20%.
  - The busiest threads, from the samples over the report's window
    (`~/vos-scale/s7run3/threads.py`).
- **The driver's stream bound:**
  - The driver keeps one QUIC connection a node, and a node takes 1,024
    requests at once on it (`api_in_flight`). At most 4,756–4,768 were in
    flight on one connection.
  - The rest waited for a stream, and their wait counts in the latency,
    since each call is timed from its scheduled send. The report warns
    "the stream bound".
  - `r3d-if1` had 7,182 requests in use at most across its 512
    connections a node.
  - So the final build's tail may include a client-side wait. A run with
    `[node] api_in_flight` raised (4,096 or 8,192) would separate it.
- **The binary:**
  - The final `vos` is 25.6 MB against 11.1 MB (`bins-7.6e3`). Neither is
    stripped and neither has debug sections (`readelf -S`: `.symtab`
    only). The growth is code: `.text` is 21.0 MB against 7.7 MB.
  - Most of it is `vos_pvm_proof` (7.7 MB), `stwo_constraint_framework`
    (1.6 MB), `stwo` and `rayon` (1.8 MB). This is the device-proof
    verifier, which `vos-node` links through `vos-pvm-recair` since
    `6ac865b68` (credentialed calls, format 43, then 45).
  - It is not the `prover` feature: `vos-cli`'s only default feature is
    `mimalloc`.
  - Only a credentialed call with a device proof runs it, and this load
    sends none ("not modeled: credentialed calls"), so the comparison is
    like for like on the path measured.
- **Unchanged:** the hosts, the cores, the 8 GiB caps, the one shared
  NVMe, the mix, `K` = 64, and the space freshly deployed.

**T1 over the node API: still missed.** The transfers' p99 is 1.31 s
against 50 ms, 26 times the target [derived: 1,310.72 ms ÷ 50 ms = 26.2].
At `r3d-if1` it was 52 times. The rate was met (3,999.5 transfers a second
of 5,000 calls offered, every call answered) and no session was refused.
The bind is unchanged: the commit's fsync on the one disk the three nodes
share (NVMe 70% busy, commit p99 262–328 ms), with the 4-core cpusets at
66–70%.

## The cost

Per node at T1's shape (10^6 users, 5,000 calls a second, `x` = 98%; every
agent replicated on all three nodes):
- **CPU:** 2.5–2.9 of a node's 4 cores [measured, `r3d-if1`, `r6e-soak`],
  so about 0.5–0.6 ms of a node's CPU per call and 7.5–8.7 cores for the
  three nodes [derived: 2.5–2.9 × 3; 2.5–2.9 ÷ 5,000 s⁻¹]. The busiest threads: the
  three executors 42–56% each, the runtime thread 42–46% (`r3d-if1`; below
  the five busiest in `r6e-soak`), `vos-storage` 32–34%, fjall's worker
  about 35% (`r6e-soak`).
- **Memory:** a node settles near 2.0–2.3 GiB: the store's block cache at
  its 1 GiB cap from minute 15, the write buffers cycling near 130 MiB,
  the Raft entry caches 74–283 MiB [measured, 7.6c]. With 551,862 users'
  rows written by the soak's end the RSS was 2,065–2,167 MiB a node; the
  bytes a user's rows take were not separated.
- **Disk:** at 10^6 users the store wrote about 16 KB a call across the
  three nodes, 78 MB/s on the shared NVMe (7.6c, run 3).

Per idle agent (three replicas, one a node):
- **Memory:** 43–46 MiB per 1,000 replicas past an intercept of about
  86 MiB a node, so about 130–140 KiB of RSS across the three nodes per
  idle agent [derived: 43–46 MiB per 1,000 is 44–47 KiB a replica; × 3 = 132–141 KiB].
- **CPU:** 0.16% of a core per 1,000 replicas idle (7.6b), at most 0.29%
  with the driver reading the agents' records (10^5, 7.6c); no measurable
  CPU under load at 10^4.
- **Wakes:** 0.032 runtime-thread wakes a replica a second, the quiet
  groups' safety round, one every 30 s.

## What binds

- **At T1's shape, the one disk** the three nodes share: the fsync each
  commit waits on (mean 35–40 ms, p99 262 ms at 10^6 users) and the
  store's write traffic as the state grows. The report's `disk%` column is
  the NVMe's `%util`, which counts any I/O in flight; read it as the fsync
  latency.
- **Past the knee, the 4-core cpuset:** 3.0 of 4 cores at 10,000 a second,
  the executors at 60–63% each, signature verification about 0.45 of a
  core at 5,000 a second (0.09 ms a call).
- **One batch in flight a group:** queued ≈ one batch's length (63 ms of a
  transfer's time at 5,000 a second, 10^5 users).
- **The commit-to-apply gap:** 37 ms mean at 5,000 a second, 65 ms at
  10^6 users, after the commit and on the latency path.
- **Before 7.6d–e:** the idle groups' timers and the inbox's reserved
  memory (run 1), the pair heartbeat's refused frames and the QUIC stream
  cap (the 10^5 storm and the cold restart), the outbox scan over deleted
  rows (the soak's collapse at minute 30), and the placements' per-frame
  tasks (the cold restart's memory). All fixed; below.

## The levers, measured

| lever | commit(s) | before → after |
|---|---|---|
| the group inbox allocated as it fills | `722d6932` | with the quiet groups below (run 1b carried both, not separated): 218 → 45.6 MiB per 1,000 idle replicas; the inbox is the memory lever by its size (184 KiB a group reserved before) |
| quiet groups wait on no timer of their own | `8e0a4fe9`, `a899ef7b` | runtime wakes 0.40 → 0.032 a replica a second; 0.58 → 0.16% of a core per 1,000 |
| the harness refuses reads at a cut without the representative | `a13f5400` | run 1's reads all failed (no window closed); 99 of 99 served after |
| lanes: an agent's frames on one of `peer_lanes` streams | `2c2d91fa` | the cold restart's stream starvation (6,468 leaders after 20 min) gone; regression test |
| the pair heartbeat sends what changed | `1b2b0075` | with the lanes, the vote floor and the campaigns' bound (7.6d's node, `b9a5c89a`, not separated), at 10^5 under load: elections 1.45 million → 0, quiet replicas 83,000–91,000 → 100,001–100,066 of 100,066; `vos-liveness` 12.5–12.9% → 3.8–4.0% idle |
| a bound on campaigns at once | `f4421239`, `e3a74620`, `d26eecd3` | with the starts' reads on the executors, the cold restart answered in 2.75 min (was 3.5), but still OOM (fixed in 7.6e) |
| the vote floor's campaign rule (a safety bug the churn simulator found) | `f00737b0` | two entries committed at one index (seed 1760) fixed; 3,000 more churn seeds pass |
| lever 1, batches in flight | `f20eab31`, `17eaea9d`, `b9a5c89a` | **worse**: p99 2.6 s at 1 → 6.3 s (2, once committed), 201 s (2), 403 s (4); built, safe, off by default (`Config::in_flight` 1) |
| lever 2, the due index's floor | `eb1925fb` | `prepare` 6.4 → 0.3–0.9 ms through the soak; not the collapse's cause |
| a scan ends at its prefix | `63b2f033` | the soak's collapse at minute 30 gone: timed out 7.74 million → 0; `resume` mean 6–15 → 1.0–2.8 ms past minute 30; a probe's 1,000 scans 469 s → under 0.5 s |
| placements stored many to a write by one task | `214fd78b`, `24f11862` | the cold restart's RSS from 1 GiB a minute to OOM → flat at 6.2–6.3 GiB |
| a campaign given back goes to the next group waiting | `274d76e3` | every group led at the first poll after a cold restart (was 30–120 elected a second) |

## What remains

- **Leaders unbalanced after a cold restart** (45,621 / 29,961 / 24,484 of
  100,066): p99 8.4 s against 1.3 s. No rebalance exists.
- **T6's p99 drift** with the state on the shared disk (commit p50 56 → 92
  ms, fsync mean 28 → 40 ms over two hours); not a node defect found here,
  to be re-measured on separate disks.
- **T5's bounds:** throughput back to 80% within 30 s missed in every
  round (33–36 s), driven by the driver's 30 s call timeout and the
  restart's catch-up at the knee; re-election at most 5.3 s in the final
  round, over its 5 s by less than the polls' 1 s grain; the host kill (as
  opposed to a unit's) needs a second node machine (S36).
- **The 120 `Expired` / `StaleSession` refusals** past the soak's hour:
  sessions the agents expired that the driver still held; not
  investigated.
- **T1's 50 ms:** the best p99 at T1's shape 1.31 s (the final build,
  over the node API; 2.6 s over node HTTP at 7.6d); no measured step at
  any rate has reached 50 ms (229 ms at 1,000 a second, 10^5 users).
- **T2, and run 2 without its slowest host:** need four node hosts (S35).
  The one host's knee was not re-measured after 7.6d–e.
- **T4's C10 proportionality** not separated.
- **Carried to the next slice** (S59): of 7.6c's levers, the
  commit-to-apply gap (4), the fsync on a shared disk and its write
  amplification (5), and batched signature checks on the executors (6);
  lever 1 (batches in flight) stays built and off, paying only with
  cheaper batches or appends pipelined to followers; lever 3 (quiet
  groups' liveness) was taken in 7.6d–e, its leader rebalance left. Lever
  7, whether a client resumes its session after a timeout instead of
  opening another, is the client's design.

## Where the data is

`~/vos-scale/runs/` on the desktop (each run's `report.txt`,
`summary.json`, `nodes.jsonl`, `faults.json`); the inventories
`inventory.toml`, `inventory.r4-12g.toml` and `inventory.r5.toml`; the
scripts in `~/vos-scale/s76c/`, `s76d/` and `s76e/`; the binaries in
`bins-7.6c`, `bins-7.6d`, `bins-7.6e3`, `bins-7.6e-prof` and `bins-s7run3` (the final build); the final build's scripts in `~/vos-scale/s7run3/`; the profiles
in `compumax:~/vos-scale/prof/`.

## Review

Fable, read-only, against the progress record and the runs' files:
accept after fixes, no High. Folded: the nodes' revisions per run as the
reports name them (M1); the driver's lateness per run, not run 2's alone
(M2); T6's RSS measure stated, the 10-minute means and the raw peaks
given (M3); T4's metric defined as the harness's from-the-close latency,
p99.9 added, the maximum unrecorded and the readers' runs told apart
from the mix's reads (M4); levers measured together marked so (L5); the
derived arithmetic shown (L6); the fault runs' timeouts on a named
basis (L7); the fault run's read failures split by kind (L8); run 1's
round trips cited to the run, not S52 (L9); the soaks' p99 wording and
T3's under-load result labelled beyond the target (L10).
