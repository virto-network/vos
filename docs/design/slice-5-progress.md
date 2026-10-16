# Slice 5: progress

The log of build step 5, against `slice-5-proving.md`. Every number is
tagged measured, model or projected.

## Step 5.2: the reference Poseidon2 and a SIMD hasher

**Gate: failed as first written** (`proving.md` §3.2), on the 8 threads
of an Intel Core Ultra 7 155H (AVX2, no AVX-512):
- a window-kernel segment proves on Poseidon2 in **1.75–1.85×** Blake2s's
  time, against 1.5× [measured];
- a leaf's commitment of 25M permutations takes **0.63 s**, against 0.5 s
  [measured, and projected from the permutation rate].

What dominates is the permutation itself: about 112M a segment, 95% in
leaves, take 58% of the Poseidon2 prove's cycles, and the packed
permutation runs at Plonky3's own speed on this machine.

### The decision: Poseidon2-M31 stays the segment channel

**The owner's, on 2026-10-16.** The gate becomes a segment's total cost,
its proving plus its leaf, against the Blake2s route's projection. Per
segment at the 32k cut:
- **Poseidon2:** about 5.6 s to prove [measured] plus a leaf of about
  1.5–3 s [projected]: about 7.1–8.6 s.
- **Blake2s:** about 3.1 s to prove [measured] plus a leaf with
  in-circuit Blake2s of about 4.5–6 s [projected]: about 7.6–9.1 s.
- **The Blake2s route would also** add a Blake2s gate to the recursion
  AIR and re-derive its padded shape and fixed point.
- **The fallback is dropped:** no Blake2s gate in the recursion AIR, and
  segments prove on Poseidon2-M31.

### The permutation

- **The reference arrangement** (`pvm/proof/src/poseidon2/mod.rs:318-355`,
  `permute_with` and `full_round`): the external matrix once, 4 full
  rounds, 14 partial rounds, 4 full rounds. A full round adds its
  constants, applies `x^5` to every word, then the external matrix; a
  partial round adds its constant to word 0, applies `x^5` to it, then
  the internal matrix. Before, each linear layer preceded its S-box layer
  and there was no first external matrix (Stwo's example order).
- **Plonky3's parameters at `f983316`:**
  - the external matrix `circ(2·M4, M4, M4, M4)` with Plonky3's
    `M4 = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]` (`apply_m4` and
    `apply_external_round_matrix`, `:250-296`); vos had HorizenLabs'
    `[[5,7,1,3],…]`;
  - the internal matrix `1 + diag(-2, 2^0, 2^1, …, 2^8, 2^10, 2^12, 2^13,
    2^14, 2^15, 2^16)` (`INTERNAL_DIAG_SHIFTS`, `INTERNAL_DIAGONAL`,
    `apply_internal_round_matrix`, `:229-310`); vos had
    `diag(2^1, …, 2^16)`;
  - the Grain round constants: unchanged, they were already Plonky3's
    `MERSENNE31_POSEIDON2_RC_16_EXTERNAL_INITIAL`, `_EXTERNAL_FINAL` and
    `_INTERNAL`, and `poseidon2_round_constants` still re-derives them.
- **The vectors, bit for bit** (`poseidon2::tests`):
  - `test_default_mersenne31_poseidon2_width_16`: input 0..15 under the
    reference constants;
  - `test_poseidon2_width_16_random`: Sage's vector under the constants
    `Xoroshiro128Plus` seed 1 draws (the generator and Plonky3's rejection
    sampling written out in the test), through `permute_with`;
  - the two matrices checked on unit vectors.
- **Modes unchanged:** the sponge (rate 8, capacity 8), the leaf and node
  layouts and the channel.
- **The settlement verifier** carries the same permutation. Its unused
  degree-2 permutation AIR fragment (`eval_permutation`) is deleted
  rather than rewritten untested; the recursion AIR's `p2` replaces it.
  On the PVM it accepts the regenerated fixture in **11,427,015
  instructions** [measured].

### The SIMD hasher

**Adapted, not depended on.** Plonky3 at `f983316` does not build on the
workspace's pinned nightly-2025-07-14 (`p3-util` uses `maybe_uninit_slice`,
stabilized later), and the pinned Stwo does not build on the nightlies
Plonky3 needs (`array_chunks` was removed), so the two cannot share a
toolchain. A dependency would also bring about fifteen crates into the
prover (`p3-field`, `-dft`, `-matrix`, `-mds`, `-poseidon1`, `-poseidon2`,
`-symmetric`, `-util`, `-maybe-rayon`, `rand` 0.10, `num-bigint` 0.5,
`itertools` 0.15, `paste`, `spin`, `tracing`) for the few functions used.

- **What was adapted** (`pvm/proof/src/poseidon2/packed/`, prover only):
  per instruction set, modular add and subtract, the fused round
  constant and `x^5` (`exp5`), and the rotations that multiply by the
  internal diagonal; the arrangement is written once over them. Headers
  name each source file at `f983316` and the change made;
  `LICENSE-PLONKY3-MIT` keeps the notice. The verifier stays on the
  scalar code, with no new dependency.
- **Sixteen lanes a call**, as one 512-bit, two 256-bit or four 128-bit
  registers a word, so independent lanes interleave. The instruction set
  is chosen at compile time by `target_feature`, as Stwo's `SimdBackend`
  chooses its own: AVX-512F, else AVX2, else NEON, else the scalar
  permutation lane by lane.
- **On `SimdBackend`** (`poseidon2/simd_backend.rs`): leaves (the lifted
  algorithm, sixteen sponges a block, finalized before the last lift),
  nodes and the grind. Roots and nonces equal `CpuBackend`'s; the grind
  returns the smallest nonce, as `CpuBackend`'s does.
- **A generic permutation over Stwo's `PackedM31`** was tried first:
  440 ns a permutation against Plonky3's 200 ns, both under a load
  average of about 24 [measured], so it was dropped.
- **Tests:** sixteen lanes equal the scalar permutation on 1,024 random
  states with `0`, `P` and `P - 1` among the words; leaves equal
  `CpuBackend`'s over lifted groups straddling a block and the sixteen-leaf
  boundary; nodes; the grind's nonce; a committed tree decommits,
  verifies, and refuses a changed value.
- **Where they ran:** AVX2 on this machine; the scalar fallback in a
  build without `target-cpu=native`; NEON under `qemu-aarch64`
  (`cargo test --target aarch64-unknown-linux-gnu`). The 11 Poseidon2
  tests pass on each. AVX-512F is compiled and linted
  (`-C target-feature=+avx512f`) but **not run**: this machine has no
  AVX-512. Its `exp5` reads sign bits with `vpcmpd` (F) where Plonky3 uses
  `vpmovd2m` (DQ).

### The gate's numbers

**Permutations** (`cargo bench --bench poseidon2`, load average 0.25)
[measured]:

| | 1 thread | 8 threads |
|---|---|---|
| scalar | 1.47 M/s | 7.05 M/s |
| packed (AVX2) | 10.78 M/s | 39.45 M/s |
| Plonky3's own packed, same machine (its own toolchain) | 11.7 M/s | 40.5 M/s |

- The 8 threads span the 155H's 6 P-cores (hyper-threaded) and its
  E-cores; 6, 12 and 16 threads reach 49, 44 and 51 M/s.
- **A leaf's commitment, 25M permutations:** 0.634 s projected from the
  rate, and **0.629 s** measured committing 176 columns of 2^20 rows
  (25.2M permutations) on `SimdBackend`. The same columns under Blake2s:
  0.118 s.

**A window-kernel segment** (spike 3's kernel, `n1000000-j2`, 32,768
steps and 8 pages, MOBILE, the full shape, since the `d165a7b6` seam is
not on `vos-core`), 5 segments, `RAYON_NUM_THREADS=8`, under
`systemd-run` at 16 GiB, load average 4.4–7.7 before the runs
[measured]:

| Channel | Prove, 5 segments | Per segment | Against Blake2s |
|---|---|---|---|
| Blake2s (format 24) | 14.94, 16.03, 16.19 s | 2.1–3.8 s | 1 |
| Poseidon2, this step | 27.01, 28.03, 29.91 s | 4.4–7.4 s | 1.75–1.85× |
| Poseidon2, before (spike 3's binary) | 102.98 s | 15.9–24.0 s | 6.4–6.9× |

- **What dominates** [measured]: per segment about 107M leaf
  permutations and 5.5M node permutations (77M and 1.6M for the
  868-step tail); the grind takes 16–36 ms. Under `perf`,
  `permute_x16` is 57.6% of the Poseidon2 prove's user cycles; Blake2s's
  compression is 20.0% of its prove's.
- The proofs verify standalone, 0.08 s a segment on Poseidon2 against
  0.026 s on Blake2s; proof sizes are unchanged (2.56–2.61 MB in
  bincode).

### Regenerated fixtures

- `pvm/proof/settlement-verifier/fixtures/bool_proof.postcard`, by
  `settle_fixture`.
- No other fixture or pinned constant depends on the permutation: the
  format 25 tests compute their commitments at run time, and the round
  constants did not change.

### Gates

- `just check`: green.
- `just test-proof`'s suites, under `systemd-run` at 16 GiB with
  `nice -n 10` and one test thread: green, the settlement verifier's PVM
  run included.
- Clippy with `-D warnings` for AVX-512F, the scalar fallback and
  aarch64 as well as the host.

## Step 5.7: the items carried from slice 4

### Per-target limits (the owner's decision)

**Built:**
- **An install names its target,** VOS or JAM (`cap::Target`), in
  `Admin::Install` and the `Installed` record; a workflow keeps its
  instance's in its record (format 5). The agent and the model hold an
  instance to its target's `cap::Limits` on every host, so a builder's
  simulation, the JAM refine and a VOS node replaying the batch agree.
  A step runs within the limits of the instance it enters, its nested
  calls too.
- **JAM's limits** (`cap::JAM`), each within VOS's (asserted):

  | | VOS | JAM |
  |---|---|---|
  | A step's writes | 256 KiB, rows by gas (about 3,125) | 16 KiB in at most 128 rows |
  | Messages, each's arguments | 16, 64 KiB | 8, 2 KiB |
  | Attests, each's arguments and output | 16, 64 KiB | 8, 2 KiB |
  | Pages a workflow's program may write | 4,096 | 256 |
  | Pages a step writes, pages held | 8 MiB, 576 | 256 KiB, 64 |
  | Checked at install: pages, program, kernels | — , 64 MiB, 1,024 | 256 (the whole heap), 512 KiB, 32 |
  | A kernel's BLAKE2b compressions | the caller's gas | 4,096: its method's gas limit over 600 |

- **Derived from slice 4's budgets** (model, `vos_jam::gas::effects`): at
  VOS's caps a step's effects take up to about 1.40e9 gas of a package's
  own work, past PolkaJam's 1e9; at JAM's, 39.4M, 35.6 times fewer.
  `WORST_JAM_STEP`, a step restoring, storing and dropping every page a
  JAM workflow holds and ending it, with its effects at their limits, is
  839M of the 950M usable, asserted at compile time. The worst VOS
  ending with its effects is about 2.31e9.
- **`#[attestable(gas = N)]`** declares a kernel's limit. On JAM a
  kernel runs within it, so its compressions, each served in software
  (`PRECOMPILE_SERVING`), are bounded at install.
- **One page price everywhere,** unchanged: the limits cap a step and
  never price it.
- **The JAM testnet** installs its actors for JAM, the shop built with
  the default heap (`lean`).

**Tests:**
- at the edge of each JAM effect limit and one past it (messages, rows,
  bytes): `Cap` for JAM alone, on a VOS node and on the JAM-only host,
  as the model;
- an install past JAM's page limit (the shop's 4 MiB heap) and one whose
  attestable's default gas limit pays for 16,666 compressions are
  refused, `Cap`, with no record written; the default-heap shop installs;
- a JAM workflow past its step's pages, and past its held pages, fails
  `Cap`; the same for VOS pauses;
- derived kernels run for both targets on both hosts, as the model;
- a compile-fail case: `#[attestable]` takes no role;
- `the_jam_limits_fit_a_package` prints and checks the figures above.

### DA: a waiting workflow's pages

**Chosen: the deterministic failure.** The core model (§12) and slice
4's F2 left re-export or failure open. Failing is a rule the agent
keeps, the same on every host and checkable on chain, where re-export
is a duty of the builder's, and a workflow whose builder was away past
retention would wait for good.

**Built:**
- JAM keeps a workflow's pages a day (`Limits::pages_kept`), well
  within JAM's imports DA. A workflow's record keeps the batch time
  from which every page it holds has been stored (`Workflow::stored`):
  its start's, then that of a step after which it holds no page an
  earlier step stored. A conservative bound, by one time per record,
  never a page's own.
- A step due at or past `stored` plus the keep, while the workflow
  holds pages, ends it `Failure::Expired` (12) without restoring or
  importing them, its pages dropped and its owner told.
- The builder no longer leaves such a workflow out of a sweep; one whose
  pages DA lacks earlier still waits, as one installed for VOS does.

**Tests:** a JAM workflow resumed just within the keep and one just past
it, on both hosts, as the model; the builder over the emulated chain,
DA emptied: the workflow left out within the keep, then ended
`Expired` past it in a package that imports nothing.

### A heap per kind of invocation

**Built:**
- The SDK's arena is a section of its own, `.vos_heap`, which the
  guest's linker script places last in the read-write data, its state
  apart. The allocator bumps fresh memory from the arena's start.
- **The derivation** (transpiler version 2) holds the arena's first 512
  KiB (`INVOCATION_HEAP`) in the actor's program and in each kernel, all
  a handler or a kernel maps, and records the pages past them,
  `Derivation::heap`. A handler past 512 KiB faults and traps.
- **A workflow's machine** maps those pages itself past its program's
  read-write data, zeroed, and arms them with its writable pages: its
  record's `writable` counts them, so `ARM_PAGE` pays for them.
- **A kernel's layout** is its program's alone, the same whatever heap
  its actor declares. The pinned fixture is now the kernels actor built
  with a 4 MiB heap (`roomy`): 896 pages left out.
- On JAM a handler of the 4 MiB shop now maps 512 KiB, not 4 MiB (model:
  about 15,000 gas of loading a call, not about 124,000).

**Tests:**
- a kernel's layout and its handlers' program equal across the kernels
  actor built with the default heap and with 4 MiB;
- the actor's program is `link_elf_spi`'s but for the heap pages it
  leaves out, which are exactly the arena's past 512 KiB;
- a workflow computing over 1 MiB on the derived shop runs to its end
  beside a handler, on both hosts, as the model maps the same pages;
- the derivation the same in every process; the pins.

### Measurements

Measured with the processes bench (`ROWS=resume` and `ROWS=catch-up`),
on the reference laptop's pinning, on the slice's base (b7c4fd69): the
paths measured run on VOS and are unchanged since. Quiet runs only,
load 1.7–5.2; runs under other agents' builds (load 8–24) gave medians
of 2–21 ms and were discarded. The leader runs in the bench's process,
so it can deliver replies itself as the one-node bench does; its
followers are `vos node run` processes over QUIC.

| A workflow's resume, a reply in to its step applied | Median | p99 |
|---|---|---|
| Three nodes, synced commits on NVMe (4 runs) | 1.77–1.92 ms | 2.48–2.77 ms |
| Node 1 alone, the same runs | 1.25–1.30 ms | 1.96–3.43 ms |
| Three nodes, stores on tmpfs (2 runs) | 0.92–0.97 ms | 1.77–1.81 ms |
| Node 1 alone, tmpfs | 0.69–0.72 ms | 1.13–1.29 ms |

- 603 resumes a row. Replication adds about 0.45 ms to the commit on
  disk (920–980 µs against 500–550 µs): the QUIC round trip and the
  follower's synced flush beside the leader's own. The step's refine,
  restoring the workflow, takes 0.5–0.65 ms; queueing, proposing and
  applying about 0.15 ms.

| A follower's catch-up (4 runs) | Within the kept tail | Beyond it |
|---|---|---|
| Missed while down | 40 fills, 9.6 MB of results in 5 entries | 224–232 fills, 54–56 MB in 28–29 entries |
| Names its leader | 0.24–0.27 s | 0.49–0.59 s |
| Has applied the leader's commit | 0.95–0.96 s, from the log | 2.24–2.55 s, from a snapshot |

- **The settings** (`vos_node::Config`): compaction once 1,024 entries
  or 64 MiB, a large result counted by its blob, are applied durably; a
  kept tail of at most 256 entries and 16 MiB; snapshot chunks of 1
  MiB; a result of 64 KiB or more stored as a blob.
- The kept tail held 9–10 results of about 1.9 MB (measured), so 4.4c's
  "4 to 8" was for results of 2–4 MB.
- The snapshot carried 401–409 rows, 0.25 MB: the agent's state, not
  the log missed. About 1.7–2.0 s of the catch-up passes between naming
  the leader and installing it, which fits a stream begun while the
  follower was down, resent every 2 s (`CHUNK_RESEND`) (model, from the
  code).

### Ristretto ids 110–114

Already so: `derive` refuses a kernel reaching any host call but a
precompile, and these are none. A test now pins it for each of the five
ids, beside BLAKE2b's precompile, which derives.

### PolkaJam

- **The re-probe** (`nightly-2026-10-13`, still the installed version:
  polkajam and jamt 0.1.29, Gray Paper 0.8.0, the same sha256): on the
  interpreter every record PolkaJam produces is unchanged, gas included
  (fault tracking, counters, segments by `wp:` and `sr:`, the 14
  starved and re-entry records, `solicit` and `historical_lookup`); the
  availability race and late `wp:` imports dropping recur. Our JAM-only
  host now agrees on 34 of the 36 fault records; `fetch` kind 0 still
  differs. Results in `spikes/sj-jam-b/results/2026-10-16-*`; `probe.sh`
  takes the backend from `POLKAVM_BACKEND`.
- **The recompiler run still waits.** `vm.unprivileged_userfaultfd` is
  1 now, but PolkaVM's sandbox reads every CPU's L3 cache entry, and
  this machine's two low-power cores have none: every node fails at
  start, and neither core pinning off nor CPU affinity helps. It needs a
  PolkaJam build that tolerates them, or another machine. Kernel
  settings were not touched.
- **The testnet on the interpreter, with this step's code** (`just
  jam-testnet`): the agent and its actors installed for JAM, the
  workflow across three later packages (70 pages exported, 104
  imported), every package landed at its first attempt, each work result
  read back from DA equal to the simulation's and the VOS node's, the
  testnet logging no error. Refines 0.26M–41.9M gas each (measured, on
  our JAM-only host).

### Also

- **A cluster test's flake, fixed:** under load the compaction test's
  leader moved while it sent its fifty increments; each is now sent
  again at its sequence to whichever node leads.

**Gates:** `just check` on each commit, 990 tests at the last; the node suites at the end: cluster and processes in it, the faults process tests and the five-process fault suite.
