# Slice 5: proving, the foundation and the recursion

Plan, draft 7.
- **The architecture** is `proving.md` (draft 4), and the recursion AIR's
  design is `recursion-air.md`. The research behind both is in
  `research/slice-5/`.
- **This slice builds `proving.md`'s M0 and M1:** the foundation, then
  our own recursion AIR, proved end to end in tests.
  - Slice 6 masks the final proof and puts statements on chain (Kreivo,
    JAM, `&self` reads).
  - Slice 7 is mobile.
  - The Clerk across spaces (`slice-6-clerk.md`, to be renumbered)
    follows slice 6.
- **Draft 7 replaces draft 6** with the owner's decisions of 2026-10-16
  (`proving.md` §12).

## Goals

1. A derived kernel proves on the Poseidon2-M31 segment channel, over its
   own shape, with its arguments delivered as witness.
2. Our recursion AIR verifies those segment proofs in leaves, folds them
   to one root, and wraps the root in a final proof on the Blake2b-256
   channel.
3. That final proof verifies natively, in a Wasm runtime and on the
   JAM-only host. The final proof costs at most 150M gas unmasked, against
   about 85M modelled.
4. The window statement and the solvency predicate pass end to end, with
   golden fixtures every venue judges alike.

No proof leaves a test in this slice: masking is slice 6.

## What exists at the start

- **vos-core** at `b5d42dc2` plus the hang fix, with three verifier fixes
  from the spikes:
  - the verifier path builds without std (now gated on wasm32);
  - the Poseidon2 leaf hasher absorbs in place;
  - the query-count preflight replays Stwo's transcript exactly.
- **Spike branches** (local, not pushed), whose code steps may take:
  - `spike/s5-guest-verify`: the guest verifier, the component-mask seam
    `d165a7b6`, the lean verify seam `a465c10b`, and the final-gas proxy;
  - `spike/s5-kernel-proof`: the derived window kernel and the chain
    tracer's sparse-memory fix;
  - `spike/s5-recair`: the gate-count crate, and `6acdc7df`
    (`drive_chip_oods` reaches BITWISE_AND_BYTE);
  - `spike/s5-mobile`: the device statements and the memory-ledger
    measurement seam.
- **The Stwo fork** (~/src/virto/stwo, branch `no-std-pvf-gating`): the
  pinned `e1286720` plus no_std gating, and spike 2's masking prototype on
  `zk-masking-spike`.

## How every step runs

- **A brief per step,** written when the step starts from this plan and
  the two design docs. An implementing agent works from it alone.
- **Reviews:**
  - an Opus review of every step's diff;
  - Fable as well for soundness-critical steps (marked **F** below): the
    fork's channel and FRI changes, Poseidon2, the security accounting,
    the witness-input binding, the gate VM, the compiler, the in-AIR
    verifier, the leaf binding, the fold, and the wrap.
- **Gates:**
  - `just check` per step;
  - `ci-full`, `test-proof` and the checker loop at each milestone's end.
- **Rules:**
  - commit on `vos-core` and never rewrite what is on origin;
  - push after reviewed milestones;
  - comments are timeless;
  - no `#[ignore]`, and no Co-Authored-By;
  - heavy runs under `systemd-run --user --scope -q -p MemoryMax=… -p MemorySwapMax=0`;
  - kill processes only by PID;
  - fix pre-existing failures that are hit;
  - the Stwo fork is pushed only with the owner's word.
- **Every measured number** in a step's log is tagged measured, model or
  projected, and lands in `slice-5-progress.md`.

## M0: the foundation

### 5.1 The Stwo fork as vos-core's base (F)

- **Pin vos-core to the owner's fork** (olanod/stwo) at a revision that
  carries:
  - `no-std-pvf-gating` (dashmap optional, Poseidon252 gated);
  - **upstream's completeness fix `74951f79`, backported.** Today a valid
    proof is refused when the preprocessed tree sits below the lifting
    height.
- **Tests:**
  - the completeness case, which fails on `e1286720` and passes on the
    fork;
  - the verifier crate built for `thumbv7em-none-eabihf` (true no_std)
    as well as wasm32.
- **Gate:** every suite green, and proof bytes unchanged on the existing
  fixtures, except where the completeness fix changes them (it should
  not).
- **Estimate:** 2–4 days.

### 5.2 The reference Poseidon2 and a SIMD hasher (F)

- **The permutation:**
  - It becomes the reference Poseidon2 arrangement, with Plonky3's
    width-16 M31 parameters: round counts, round constants, the internal
    diagonal, and the external matrix.
  - Plonky3's test vectors pass bit for bit.
  - The sponge and Merkle modes stay as `proving.md` and
    `recursion-air.md` §1.3 define them.
- **The prover's hasher and channel:**
  - Packed SIMD for AVX2, AVX-512 and NEON, from Plonky3's `mersenne-31`
    packed Poseidon2 (MIT or Apache-2.0), adapted or depended on.
  - It has a scalar fallback for the no_std verifier.
- **Tests:**
  - the vectors;
  - scalar equals SIMD on random inputs;
  - Merkle roots and proofs on the Poseidon2 channel round-trip.
- **Gate (`proving.md` §3.2):**
  - a window-kernel segment proves on Poseidon2 within 1.5× of Blake2s
    (today 23 s against 5 s);
  - permutations a second support a leaf commitment (about 25M) in at
    most 0.5 s on 8 threads.
  - **If it fails,** the step stops and records the numbers. The plan
    then adds a Blake2s gate to the recursion AIR, and segments stay on
    Blake2s-M31.
- **Estimate:** 2–3 weeks.

### 5.3 The format registry, run-time selection and the security accounting (F)

- **The registry** (`proving.md` A.4): new format numbers for
  - segment proofs on Poseidon2-M31;
  - leaf and fold;
  - the final wrap;
  - two reserved numbers: device proofs and credential proofs.
- **Run-time selection:** a proof's format selects its channel and
  parameters at run time; the cargo feature that fixes them today
  (`pvm/proof/src/proof.rs:180-187`) goes. One verifier build accepts
  every registered format.
- **Inner parameters:** blowup 4, 39 queries, PoW 26.
- **Interaction PoW of 24 bits,** mixed before any logup challenge is
  drawn (A.1 item 4), in the prover, the native verifier and the
  preflight.
- **One tool for both bit counts.** It computes conjectured and proven
  (Johnson, with the DEEP, ALI and logup terms) bits per format and
  shape. The format tests pin its output, and the verifier refuses a
  proof below either floor.
- **Fold step > 1 stays refused** until 5.14 admits it for the wrap.
- **Tests:**
  - every format round-trips;
  - a proof under one format is refused under another;
  - interaction PoW is checked;
  - the bit counts are pinned per format.
- **Estimate:** 1–2 weeks.

### 5.4 A shape per kernel

- **The shape:**
  - a kernel's component set comes from its code (the component-mask
    seam, `d165a7b6`), with pinned log sizes per segment class;
  - the verifier accepts exactly that set and those sizes for the
    kernel;
  - the shape is recorded in the install's `Derivation`.
- **The program id:** its v2 fields (`proving.md` §3.6) are assembled
  here. The leaf-circuit hashes are added in 5.12, when they exist.
- **Tests:**
  - the window kernel and the solvency predicate prove and verify over
    their shapes;
  - a full-set proof of the same kernel is refused;
  - a missing chip is refused.
- **Gate:** the window kernel's verify gas falls by at least 30% on the
  JAM-only host (the audit measured 38%).
- **Estimate:** about 1 week.

### 5.5 The witness-input precompile and the io-hash (F)

- **A new precompile id** in the VOS range delivers a kernel's arguments
  and witness rows:
  - the tracer serves it with free witness;
  - the agent serves it live, from the `Attest` record;
  - `derive`'s prologue reads arguments through it, instead of from the
    initial image.
- **Its AIR binding:**
  - the dispatch id is committed in PROGRAM_MEMORY;
  - writes go only to the range its registers name, with a size cap;
  - it has no other effect;
  - `derive` admits the id.
- **The initial image:** the first segment's initial memory root is the
  image root of code, data and zeroed regions, computed at install and
  stored in the `Derivation`.
- **The io-hash** is `compute_io_hash(public_args, output, roots)`:
  BLAKE2b-256 through `0x400`, in the canonical encoding (`proving.md`
  §3.6).
- **Tests:**
  - live ≡ traced: the agent's live run and the prover's re-run produce
    the same output and io-hash;
  - writes outside the named range are refused;
  - an oversize input is refused;
  - the initial root equals the install's.
- **Estimate:** 1–2 weeks.

### 5.6 The phone run (with the owner's team)

- **The authentication statement on a real Android flagship:**
  - two shapes: as built, and the no-boundary proxy;
  - one segment, 4 threads, MOBILE settings;
  - built as a static `aarch64-unknown-linux-musl` binary run over
    `adb`.
- **I prepare the binary and a one-page runbook;** the owner's team runs
  it. Recorded: the time and memory per shape against the x86 4-P-core
  figures.
- **Gate:** the phone factor is measured, replacing the projected 1.0–2.6.
  An iPhone run, through a test app, is optional.
- **Estimate:** 2 days of preparation.

### 5.7 Carried from slice 4

- **Per-target JAM limits** (the owner's decision):
  - a JAM profile about 31× smaller than VOS's;
  - enforced at run time and named in the install record;
  - statics checked at install;
  - one page price everywhere.
- **DA:** re-export a waiting workflow's pages, or fail it
  deterministically.
- **A heap per kind of invocation** (a bump allocator). It lands before
  5.5's live≡traced test, or kernels are excluded from it.
- **Measurements:**
  - a workflow's resume latency on three processes;
  - a follower's catch-up beyond the kept tail.
- **PolkaJam:** a re-probe on upgrade, and the recompiler run once the
  owner sets `vm.unprivileged_userfaultfd`.
- **Ristretto ids 110–114:** carried. Derive refuses a kernel that
  reaches them.
- **Estimate:** 2–3 weeks, beside 5.1–5.6.

### M0 acceptance

- **Gates:** `ci-full`, `test-proof` (format-25 tests included) and the
  checker loop.
- **Recorded:**
  - segment proving time and memory on Poseidon2 against Blake2s;
  - the phone factor;
  - the window kernel's verify gas over its shape.
- **Reviews:** an Opus milestone review, then a push.

## M1: the recursion, unmasked, in tests

Steps 5.8–5.15 are `recursion-air.md` §10's, in its order.

### 5.8 The gate VM (F)

- **A new crate, `vos-recair`.** It holds:
  - a `Context` that builds circuits;
  - the three components (`p2`, `qm31`, `h8`, `recursion-air.md` §1) and
    their trace generation;
  - the `Gate` relation with signed multiplicities;
  - constants, padding, and preprocessing;
  - the circuit hash.
- It **proves and verifies natively** on the Poseidon2 channel.
- **The `vos-final-verifier` skeleton** builds on stable no_std for
  wasm32 and riscv64em-javm.
- **Tests:**
  - random circuits prove and verify;
  - each value is yielded exactly once;
  - a tamper per component and per mode is refused;
  - `p2` equals the reference permutation of 5.2.
- **Gate:**
  - a 10k-gate circuit proves and verifies;
  - the degree ≤ 3 audit passes;
  - a three-component multi-fraction logup proves at three log sizes (a
    failure the archive never root-caused).
- **Estimate:** 3–4 weeks.

### 5.9 The gate compiler (F)

- **What it does:** the recording evaluator plus a hash-consed DAG turn
  each chip's `add_constraints` into gates (`recursion-air.md` §3). It
  handles per-relation challenges, next-row masks, paired and unpaired
  logup, and intermediates. It also runs static checks on the wiring's
  signed multiplicities.
- **Tests:** §3's four equivalence tests (constraint ≡ gate on random
  points), on all 32 chips.
- **Gate:** 32 of 32 chips are equivalent, with counts within 1% of the
  spike's log.
- **Estimate:** 1–2 weeks.

### 5.10 The in-AIR verifier's pieces (F)

- **The pieces:**
  - the Poseidon2-M31 channel;
  - lifted Merkle paths;
  - FRI at fold step 1 and 3;
  - DEEP through `h8`;
  - OODS through compiled gates;
  - the logup sums, including the boundary chips' public terms
    (`boundary_binding.rs:116-168`).
- **The transcript** follows `proving.md` A.1.
- **Tests:**
  - each piece against the native code, on recorded data;
  - transcript equality with the native channel's recorder.
- **Gate:** every piece accepts real data and refuses each tamper.
- **Estimate:** 3–4 weeks.

### 5.11 COMPARE's leaf: the first feasibility gate

- **What:** a COMPARE proof verified in a circuit, and that circuit's
  proof verified natively.
- **Tests:** a tampered OODS sample, queried value, sibling, FRI value
  and nonce are each refused.
- **Gate:** rows within 15% of 8,488 / 10,869 / 273, and at most 1 s.
- **Estimate:** 1–2 weeks.

### 5.12 The kernel leaves (F)

- **The leaves for the window kernel and the solvency predicate,** each
  carrying:
  - the entry and exit state digests;
  - the entry and halt flags;
  - the io-hash;
  - the A.3 output digest.
- **The program id is finalized** with its leaf-circuit hashes, in the
  `Derivation`.
- **Derive computes every kernel's leaf rows** from its shape, and
  refuses a kernel over the padded shape.
- **Tests:**
  - spike 3's real segment on the Poseidon2 channel;
  - native and in-circuit transcripts equal;
  - each flag's conditions, negated, are refused.
- **Gate:**
  - rows within the padded shape (2^16 / 2^17 / 2^16);
  - at most 24 GiB;
  - time at most 1× the segment's proving, against a target of
    0.13–0.5×.
- **Estimate:** 2–3 weeks.

### 5.13 The fold and the fixed point (F)

- **The fold node** (`proving.md` §3.4, A.3):
  - it re-hashes each child's preimage;
  - it checks the circuit set, with the fold's own hash self-carried;
  - it checks the program id, adjacency, continuity, and the ends.
- **Tests:**
  - a fold of two leaves;
  - a fold of two folds within the constant shape;
  - a tree over four segments;
  - refusals: a wrong program, a gap, broken continuity, a prefix, a
    mid-run start, a wrong child circuit.
- **Gate:** a fold verifies two folds within the shape, at the memory and
  time of a leaf.
- **Estimate:** 2–3 weeks.

### 5.14 The final wrap (F)

- **In our Stwo fork:**
  - a Blake2b-256 Merkle hasher and Fiat–Shamir channel;
  - FRI fold step 3 admitted after a review and tamper tests.
- **The wrap circuit:**
  - a 1-to-1 node over the root;
  - blowup 64, 18 queries, PoW 26, fold step 3, a 2^6 last layer;
  - 134 conjectured and 80 proven bits;
  - the wrap pins the fold circuit's hash.
- **`vos-final-verifier`, complete,** for x86, wasm32 and riscv64em-javm.
- **Tests:**
  - tampers on fold step 3 and on the Blake2b channel;
  - verification in the Wasm harness (from spike 4a) and on the JAM-only
    host.
- **Gate:**
  - at most 150M gas unmasked on the JAM-only host (target about 85M,
    64M through `0x400`);
  - at most 2^17 rows;
  - at most 24 GiB.
- **Estimate:** 3–4 weeks.

### 5.15 End to end

- **`vos-statement`:** the types, the canonical encoding, the statement
  id, and the venue's recomputation of the io-hash (`proving.md` §3.6).
- **The golden fixtures** of A.6.
- **The window statement and the solvency predicate,** each:
  - segments, leaves, folds and the wrap;
  - verified natively, in Wasm and on the JAM-only host.
- **Gate:** every venue judges every fixture alike.
- **Estimate:** about 2 weeks.

### 5.16 Acceptance

- **Gates:** `ci-full`, `test-proof` and the checker loop.
- **Rows measured:**
  - segment proving time and memory per kernel, on Poseidon2;
  - leaf, fold and wrap time and memory;
  - the final proof's size;
  - verify gas on the JAM-only host and through `0x400`;
  - Wasm instructions;
  - recursion as a share of segment proving, per statement.
- **Reviews:**
  - the end review (Fable);
  - the code-quality review (Opus);
  - a cleanup step.

## Estimates

| | weeks |
|---|---|
| M0 (5.1–5.7) | 5–7 |
| M1 (5.8–5.15) | 17–24 |
| reviews and acceptance | 2–3 |
| **slice 5** | **24–34** |

## Decisions

**Taken by the owner** (`proving.md` §12): all eight, including the three
that shape this slice:
- our own recursion AIR on StarkWare's design;
- Blake2b-256 for the final proof;
- arguments through a witness-input precompile.

**Decided on the evidence, and the owner's to override:**
- the reference Poseidon2 with Plonky3's parameters;
- the segment channel set by 5.2's gate;
- the inner parameters and interaction PoW;
- the padded shape as a format constant;
- 5.6's phone run on Android first.

## Risks

`proving.md` §10 and `recursion-air.md` §11 hold the full list, each with
its gate. This slice's sharpest:
- **5.2's hasher gate.** If Poseidon2 commits stay slow, the recursion
  AIR gains a Blake2s gate, and segments stay on Blake2s-M31.
- **The gate compiler and the in-AIR verifier.** They are new
  soundness-critical code: differential tests, Fable reviews, and the
  external audit before value.
- **The model's rows:** 5.11 and 5.12 count real rows early.
