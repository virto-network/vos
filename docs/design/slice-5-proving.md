# Slice 5: proving, the foundation and the recursion

Plan, draft 8.
- **The architecture** is `proving.md` (draft 5), and the recursion AIR's
  design is `recursion-air.md` (draft 2). The research behind both is in
  `research/slice-5/`.
- **This slice builds `proving.md`'s M0 and M1:** the foundation, then
  our own recursion AIR, proved end to end in tests.
  - Slice 6 masks the final proof and puts statements on chain (Kreivo,
    JAM, `&self` reads).
  - Slice 7 is mobile.
  - The Clerk across spaces (`slice-6-clerk.md`, to be renumbered)
    follows slice 6.
- **Draft 8 replaces draft 7.** It folds in Fable's review of draft 7
  (`research/slice-5/plan7-review.md`, R1–R11) and the owner's word on
  pushing the Stwo fork (2026-10-16).
- **M0 is done** (`slice-5-progress.md`, "M0 acceptance"). Where its outcome
  changed M1's premises, M1's opening and its steps say so.
- **M0's milestone review is folded in.** Its stale docs are fixed, and
  its preparation items open M1 as 5.8.0.

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
- **Test tiers:**
  - every structural recursion test in `just check` uses a small test
    kernel (log ≤ 12);
  - the window kernel runs only in `test-proof`, under `systemd-run`
    at `proving.md` A.7's memory caps. A.7 also gives each heavy
    test's expected wall time.
- **Fixtures** come from a generator (5.8.0), regenerated at each format
  bump and stored under `pvm/proof/fixtures` (about 1.2 MB for A.6).
- **Rules:**
  - commit on `vos-core` and never rewrite what is on origin;
  - push after reviewed milestones;
  - **the Stwo fork** (the owner's word, 2026-10-16): reviewed branches
    may be pushed to olanod/stwo, each push after a Fable review of the
    fork change; published history is never force-pushed;
  - **Rust:** no nightly features in the source; stable for x86 and
    wasm32; the JAM build on the pinned nightly with build-std;
  - comments are timeless;
  - no `#[ignore]`, and no Co-Authored-By;
  - heavy runs under `systemd-run --user --scope -q -p MemoryMax=… -p MemorySwapMax=0`;
  - kill processes only by PID;
  - fix pre-existing failures that are hit.
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
- **Closing gate:** Fable's review of the fork change, then its push to
  olanod/stwo, so CI can build vos-core's pin.
- **Estimate:** 2–4 days.

### 5.2 The reference Poseidon2 and a SIMD hasher (F)

- **The permutation:**
  - It becomes the reference Poseidon2 arrangement, with Plonky3's
    width-16 M31 parameters, pinned at revision `f983316`
    (`f98331687e47106a64ab82a77e2e1d0d66c9161b`,
    `mersenne-31/src/poseidon2.rs`). Older revisions drew the M31
    constants from an RNG.
    - Round counts R_F = 8, R_P = 14, and the Grain round constants
      `MERSENNE31_POSEIDON2_RC_16_EXTERNAL_INITIAL`,
      `MERSENNE31_POSEIDON2_RC_16_EXTERNAL_FINAL` and
      `MERSENNE31_POSEIDON2_RC_16_INTERNAL`;
    - the internal diagonal, `POSEIDON2_INTERNAL_MATRIX_DIAG_16_SHIFTS`;
    - the external matrix.
  - **Test vectors,** bit for bit:
    - `test_default_mersenne31_poseidon2_width_16`: input 0..15 under
      the constants above;
    - `test_poseidon2_width_16_random`: Sage's vector, with constants
      from `Xoroshiro128Plus` seed 1, which checks the arrangement apart
      from the constants.
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
- **Gate (`proving.md` §3.2):** a segment's total cost, its proving
  plus its leaf, against the Blake2s route's projection. Per segment at
  the 32k cut, on 8 threads:
  - Poseidon2: about 5.6 s to prove [measured] plus a leaf of about
    1.5–3 s [projected];
  - Blake2s: about 3.1 s to prove [measured] plus a leaf with in-circuit
    Blake2s of about 4.5–6 s [projected].
  - **Measured:** the proving alone at 1.75–1.85× Blake2s, and a leaf's
    commitment (25M permutations) in 0.63 s; the first bounds were 1.5×
    and 0.5 s.
  - **Decided by the owner:** Poseidon2-M31 stays the segment channel.
    The Blake2s route also re-derives the recursion AIR's shape and fixed
    point.
- **Closing gate,** if the fork changes: Fable's review of the change,
  then its push to olanod/stwo.
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
- **Lossless encodings** (`proving.md` A.3):
  - the boundary states enter the transcript as the boundary chips'
    bytes, one M31 a byte, absorbed as one run, so the transcript binds
    the public logup tuples before any challenge;
  - every other u64 that enters a hash or a transcript is four 16-bit
    limbs, little-endian, a u32 two, a 32-byte hash 16. The Poseidon2
    channel's `mix_u64` and PoW nonces move to four limbs; today's
    `reduce(lo32), reduce(hi32)` retires with the old formats.
- **Inner parameters** (formats 31, 32): blowup 4, 44 queries, PoW 20,
  FRI fold step 1, log last-layer degree bound 0: 108 conjectured and
  62.8 proven bits for segments [model], a grind of about 30 ms.
  Superseded at 5.10a by 35/36/37 (segments at 40 queries and PoW 24).
- **Interaction PoW of 8 bits,** mixed before any logup challenge is
  drawn (A.1 item 4), in the prover, the native verifier and the
  preflight; its slot in the transcript stays for every format with
  logup.
- **Device and credential formats** (34, 30): blowup 2, 86 queries, PoW
  20, interaction PoW 8: 62 proven bits, 2 over the floor. Superseded at
  5.10a by 35/36/37 (the device format is 37).
- **The wrap** (28): blowup 64, 20 queries, PoW 26, interaction PoW 8,
  fold step 3, last layer 2^6, needing affine DEEP batching for its 80
  proven bits; as built it counts 74 (`proving.md` §3.5). 5.14 decides
  between affine batching, a batching-phase PoW and blowup 8.
- **One tool for both bit counts.** It computes conjectured and proven
  (Johnson, with the DEEP, ALI and logup terms) bits per format and
  shape. The format tests pin its output, and the verifier refuses a
  proof below either floor.
- **Fold step > 1 stays refused** until 5.14 admits it for the wrap, with
  the wrap's DEEP batching.
- **Tests:**
  - every format round-trips;
  - a proof under one format is refused under another;
  - two boundary states that differ only by p in a 32-bit word draw
    different challenges;
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
- **Gate, as built:** the exact set and sizes accepted, every other
  refused. The verify-gas gate (at least 30%, from the audit's 38%) counted
  the Ristretto chips, which M0 removed (5.7): on the hardened AIR a kernel's code
  leaves out two small tables, and the shape saves 0.2–0.4% of verify gas
  [measured]. **The shape is the kernel's identity and its leaf's
  constants:** it pins every log size, which the program id binds and the
  leaf circuit takes as constants.
- **Estimate:** about 1 week.

### 5.5 The witness-input precompile, the run's ends and the io-hash (F)

- **Precompile `0x401`, `WITNESS_INPUT`,** delivers a kernel's arguments
  and witness rows.
  It is the first free id of VOS's `0x400..=0x47f`
  (`agent/wire/src/abi/surface.rs`): `0x400` is BLAKE2b, and `0x480` on
  are refine extensions.
  - **Registers:** φ7 the destination, φ8 the capacity. It writes
    `min(capacity, remaining)` bytes and returns the count in φ7; 0
    means the end of input. Reads are deterministic.
  - The agent serves it live and records the stream; the tracer replays
    the stream as free witness.
  - `derive`'s prologue reads arguments through it, instead of from the
    initial image.
- **The record:** `Attest` (`agent/wire/src/result.rs:351`, today
  `{ program, arguments, output }`) gains `witness_input: Vec<u8>`, the
  exact byte stream the kernel read, in call order.
  - Its total is capped at 4 MiB, as a work result is
    (`agent/wire/src/abi/cap.rs`); a large result travels as a blob
    (4.4a).
  - A `window` field for anchors, and the final proof's hash, come in
    slice 6.
- **The precompile's AIR binding:**
  - the dispatch id is committed in PROGRAM_MEMORY;
  - writes go only to `[φ7, φ7 + count)`, with the count at most φ8;
  - it has no other effect;
  - `derive` admits the id.
- **The run's ends** (`proving.md` §3.3):
  - the first segment's initial memory root is the image root of code,
    data and zeroed regions, computed at install; the `Derivation`
    (`agent/wire/src/records.rs:18`) gains it;
  - the loader's register image no longer depends on the arguments: φ8,
    their size, is 0;
  - a halting step's `next_pc` becomes `PVM_HALT_ADDR` (2^32 − 2^16),
    where today CpuChip keeps it at `pc`, so `pc_out == PVM_HALT_ADDR`
    marks a halt.
- **The io-hash** is `compute_io_hash(public_args, output, roots)`:
  today's `compute_io_hash(public, return)` gains the roots. It is
  BLAKE2b-256 through `0x400`, in the canonical encoding (`proving.md`
  §3.6).
- **Tests:**
  - live ≡ traced: the agent's live run and the prover's re-run produce
    the same output and io-hash;
  - the tracer's and the agent's cursors agree at every call;
  - a short read returns its count, and a read at the end returns 0;
  - writes outside the named range are refused;
  - an oversize input is refused;
  - the initial root equals the install's;
  - a halting run's last segment has `pc_out == PVM_HALT_ADDR`;
  - a non-halting segment's `pc_out` is not the halt address, including
    one cut just before its halting step.
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
- **Ristretto ids 110–114:** removed, chips and ids (the owner's
  decision): they were unsound, and slice 7's generic bignum chip
  replaces them. Derive refuses a kernel that reaches them.
- **Estimate:** 2–3 weeks, beside 5.1–5.6.

### M0 acceptance

- **Gates:** `ci-full`, `test-proof` (formats 31 and 33) and the checker
  loop.
- **Recorded:**
  - segment proving time and memory on Poseidon2 against Blake2s;
  - the phone factor;
  - the window kernel's verify gas over its shape.
- **Reviews:** an Opus milestone review, then a push.

## M1: the recursion, unmasked, in tests

5.8.0 prepares the line. Steps 5.8–5.15 are then `recursion-air.md` §10's,
in its order; 5.9 runs beside 5.8.

**What M0 changed under M1:**
- **Formats:** segments are 31 (Poseidon2-M31), leaves and folds 32, the
  wrap 28; 33 is the legacy Blake2s segment format, 34 and 30 the device
  and credential formats. 24–27 and 29 are retired. Superseded at 5.10a by
  35/36/37: 31, 33 and 34 are retired.
- **The segment AIR** is 25 chips, **8,039 columns** in full (185
  preprocessed, 4,882 main, 2,964 interaction, 8 composition) and 5,177
  constraints. A derived kernel's shape is 23 of them, 8,024 columns
  [measured]. `count.log` counted the pre-hardening window shape, 7,519
  columns and 4,223 constraints.
- **The shape** is identity and the leaf's constants, not a gas lever
  (5.4).
- **Inner proofs take 44 queries** (5.3's reviews), where `count.log`
  counted 39. A leaf's rows grow with width times queries, so the kernel
  leaf's `p2` comes to about 64.8k of 2^16 (below). The ~9,300-column
  headroom (`recursion-air.md` §5) was counted at 39 queries; at 44 it is
  about 8,100 columns [model]. The full 8,039 still fits, with about 1% of
  `p2`'s rows to spare. 5.8.0 holds the rule that recounts it and picks a
  lever.
- **`count.log` predates the hardening:** 4,223 constraints and 7,519
  columns, against 5,177 and 8,039 now. 5.9 re-baselines it before any
  gate compares against it.

### 5.8.0 Preparation

M0's milestone review left these before the recursion builds on them.

- **The window kernel on the line.** Today it lives only on
  `spike/s5-shape`, built on cipher-clerk through a software Ristretto
  shim. 5.11, 5.12 and 5.15 need it in `test-proof`.
  - **The route:** a test actor, `window`, under `agent/test-actors`, on
    cipher-clerk v0.3.0 with `settlement` and without `pvm-precompile`.
    That feature is what names the shim, so none is needed. The kernel is
    written on the line; the spike's kernel is a reference only, and its
    shim, harness and patched workspace stay on the spike.
  - **The curve code:** cipher-clerk depends on curve25519-dalek
    unconditionally, so dalek compiles in, but the settlement window
    reaches none of it [read, not built]. Derive refuses only a kernel
    that reaches ids 110–114.
  - **The cost:** without the precompile feature, `PseudoAccount::of`
    hashes with the `blake2` crate in software, so the kernel's steps and
    classes move from the spike's 404,091 steps. The step measures them
    again.
  - **The fallback:** if the actor does not build for the guest target,
    or derive refuses it, the kernel is a window-like kernel in the
    `kernels` actor: a vos-tree multiproof over the BLAKE2b compress
    precompile and a netting of its rows, without cipher-clerk. The step's
    log says which route it took.
- **The A.6 fixture generator** (`pvm/proof/fixtures`). M0 promised it
  and did not build it, a deviation (`slice-5-progress.md`). It is built
  here: a generator for each admitted format, and a test that refuses a
  stale fixture. The segment fixtures land now; 5.15 adds A.6's statement
  fixtures once the wrap exists.
- **One no_std Poseidon2 crate,** with no Stwo dependency: the
  permutation, its parameters, and the sponge and Merkle modes.
  - Its users: the prover, the settlement verifier, and later
    `recair-air` and `vos-final-verifier`.
  - Today there are two copies (`pvm/proof/src/poseidon2/mod.rs`,
    `pvm/proof/settlement-verifier/src/lib.rs`), held together by a test
    (`tests/poseidon2_round_constants.rs`).
- **One transcript prefix.**
  - `verify/recursion.rs:195-290` copies `verify.rs:308-410`, and mixes
    the boundary states only `if side_note.closing_chip_active`.
  - One function serves both, and A.1's in-AIR transcript follows it.
  - `tests/recursion_seams.rs:45`'s `..._format_26_...` is renamed for
    format 31 (superseded at 5.10a by 35/36/37).
- **One page tree.** `page_merkle.rs:74-140` re-implements
  `vos_pvm_program::image`'s tree; it reuses it, and the stale comment at
  `:75` (formats 12 to 21) goes.
- **`chips/cpu/mod.rs`'s `add_constraints` split by instruction class.**
  It is 3,560 lines, and 5.9 pins gate mismatches chip by chip. The same
  constraints in the same order, so proofs stay byte-identical.
- **The inner parameters, recounted: the decision rule.**
  - **When:** at 5.10's start, on 5.9's re-baselined count, the kernel
    leaf is recounted over the hardened 8,024-column shape at the inner
    parameters.
  - **The rule:** if `p2`'s headroom is under 10% of 2^16, a new segment
    format is registered with fewer queries and more PoW. The milestone
    review's count [model]:
    - PoW 24 with 40 queries: 62.86 proven and 104 conjectured bits,
      about 6k fewer `p2` rows;
    - PoW 22 with 42 queries: about 3k fewer.
  - **The trade:** PoW 24 grinds about 0.4 s more a segment.
  - **Only the segment format moves.** Leaves and folds (32) keep 44
    queries, since a fold uses under half the shape. A new format takes a
    new number; 31 is never re-registered with other parameters.
  - **FRI fold step 3 stays the wrap's only.** In-AIR fold step 3 is not
    built (5.10).
- **Later, at the slice's code-quality pass** (5.16), recorded here:
  - the `*_gate.rs` and `*_negative.rs` tests grouped under
    `tests/gates/`;
  - `phase2_alu.rs` renamed;
  - `divrem.rs` (1,059 lines) split;
  - `proof.rs:90-245`'s changelog moved to `docs/status.md`.
- **Tests:** `just check` green; the shared Poseidon2, prefix and page
  tree, and the CPU split, leave proof bytes and the fixtures unchanged;
  the window kernel proves and verifies over its shape in `test-proof`.
- **Reviews:** Opus on each item; Fable on a new segment format, if the
  rule registers one.
- **Estimate:** 1–2 weeks.

### 5.8 The gate VM (F)

- **Two new crates:**
  - `vos-recair` (`pvm/proof/recair`), the prover. It holds:
    - a `Context` that builds circuits, with static checks on the
      wiring: each address yielded exactly once, and each relation's
      total multiplicity below p (`recursion-air.md` §1.1);
    - the components' trace generation, padding rows included: a `p2`
      padding row holds the permutation of its zero input, since the
      round constraints still apply;
    - the `Gate` relation with signed multiplicities;
    - constants, padding, and preprocessing;
    - the circuit hash.
  - `vos-recair-air` (`pvm/proof/recair-air`): the bodies of `p2`,
    `qm31` and `h8` (`recursion-air.md` §1), no_std, with no prover
    dependency.
- It **proves and verifies natively** on the Poseidon2 channel.
- **It needs 5.1's completeness fix:** the recursion AIR's preprocessed
  tree (2^17) sits below its lifting height (2^20).
- **The `vos-final-verifier` skeleton** (`pvm/proof/final-verifier`)
  builds no_std: on stable for x86 and wasm32, on the pinned nightly with
  build-std for riscv64em-javm.
- **Tests,** on small circuits in `just check`:
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
  logup, and intermediates.
- **Beside 5.8:** it needs the gate set's definition, not the VM.
- **Tests:** §3's four equivalence tests (constraint ≡ gate on random
  points), on all 25 chips.
- **The baseline first.** `count.log` predates the hardening (4,223
  constraints and 7,519 columns, against 5,177 and 8,039 now). At 5.9's
  start, the gate-count crate from `spike/s5-recair` re-runs on the
  hardened AIR, and its log is the baseline for 5.9 and 5.11.
- **Gate:** 25 of 25 chips are equivalent, with counts within 1% of the
  re-baselined log.
- **Estimate:** 1–2 weeks.

### 5.10 The in-AIR verifier's pieces (F)

- **The pieces:**
  - the Poseidon2-M31 channel, on 5.3's lossless encodings;
  - lifted Merkle paths, with a witness builder, `expand_decommitment`,
    that expands Stwo's deduplicated `hash_witness` into per-query
    paths and FRI siblings (`recursion-air.md` §4.3);
  - FRI at fold step 1;
  - DEEP through `h8`;
  - OODS through compiled gates;
  - the logup sums, including the boundary chips' public terms
    (`boundary_binding.rs:147-205`).
- **At its start,** 5.8.0's rule recounts the inner parameters, and the
  pieces take the segment format it leaves.
- **In-AIR FRI fold step 3 is not built:** no inner proof uses it, and
  the wrap's is verified natively. Fewer queries with more PoW comes
  first (5.8.0).
- **The transcript** follows `proving.md` A.1.
- **Tests:**
  - each piece against the native code, on recorded data;
  - transcript equality with the native channel's recorder.
- **Gate:** every piece accepts real data and refuses each tamper.
- **Estimate:** 3–4 weeks.

### 5.11 COMPARE's leaf and the kernel leaf's rows: the first feasibility gate

- **What:**
  - a COMPARE proof verified in a circuit, and that circuit's proof
    verified natively;
  - the window kernel's leaf topology built and counted
    (`Context<NoValue>`, no proof). COMPARE's leaf is mostly width-free
    per-query work, so it does not exercise the kernel leaf's dominant
    terms.
- **Tests:**
  - a tampered OODS sample, queried value, sibling, FRI value and nonce
    are each refused;
  - a regression test pins the topology's rows per term of the
    re-baselined log (`count-35.log`), not only its totals.
- **Gate** (format 35: 40 queries, PoW 24, the window kernel's 8,009
  columns; `research/slice-5/count-35.log`):
  - COMPARE's rows within 15% of **8,644 / 10,352 / 280** [model, the
    verifier's rows at 40 queries; 8,702 / 11,152 / 280 with a leaf's own
    work, which a chip-isolated proof has none of; 8,488 / 10,869 / 273
    was the 39-query count], and at most 1 s;
  - the kernel leaf's topology within 2^16 / 2^17 / 2^16: **59,242 /
    102,049 / 46,080** [model] before the leaf's own work (59,300 /
    102,849 / 46,080 with it), `p2` 9.5% under 2^16. At 44 queries over
    the 8,024-column shape it was about 64.8k / 111k / 51k [model], `p2`
    within about 1% of 2^16, which 5.8.0's rule moved to format 35 at
    5.10a.
- **Gate passed** [measured, 5.11]:
  - **COMPARE's leaf** (COMPARE at 2^12 rows with the byte-range table's
    one preprocessed column, 68 columns, chip-isolated, format 35):
    **7,732 / 10,279 / 240** rows, 0.89 / 0.99 / 0.86 of the model
    (lifting 2^14, not the model's 2^15); padded to 2^13 / 2^14 / 2^8;
    proved in **0.21–0.24 s** at load 8–10, verified in 0.013–0.015 s; every tamper refused by its
    check.
  - **The kernel leaf's topology: 57,655 / 101,638 / 46,000** rows, `p2`
    12.0% under 2^16, `qm31` 29,434 under 2^17, `h8` 19,536 under 2^16;
    each of `count-35.log`'s terms pinned, with its delta from the model.
- **Estimate:** 1–2 weeks.

### 5.12 The kernel leaves (F)

- **The leaves for the window kernel and the solvency predicate,** each
  carrying (`proving.md` §3.3, A.3):
  - the boundary states, mixed as bytes;
  - the entry and exit state digests, over 148 bytes in A.3's order;
  - the entry flag, against leaf-circuit constants: the entry pc,
    ts = 1, the loader's register image and the image root. The image
    is taken from the loader's code, which decides which register holds
    the halt address, not from a description of it;
  - the halt flag, `pc_out == PVM_HALT_ADDR`;
  - the io-hash, whose 32 φ9..12 bytes the leaf range-checks
    (`proving.md` A.3);
  - the A.3 output digest, with the program id and W as witnesses.
- **The program id is finalized** with its leaf-circuit hashes, in the
  `Derivation`.
- **Derive computes every kernel's leaf rows** from its shape, and
  refuses a kernel over the padded shape.
- **Tests,** in `test-proof`:
  - spike 3's real segment on the Poseidon2 channel;
  - native and in-circuit transcripts equal;
  - each flag's conditions, negated, are refused;
  - a tampered boundary byte is refused.
- **Gate:**
  - rows within the padded shape (2^16 / 2^17 / 2^16);
  - at most 4 GiB;
  - time at most 1× the segment's proving (expected 1.2–2.6 s), against
    a target of 0.13–0.5×.
- **Gate passed** [measured, 5.12; `vos-recair`'s `leaf`]:
  - **the window kernel's leaves,** its real first, second and last
    segments (classes 0, 1 and 0) verified in their classes' leaves as
    natively, transcript for transcript: the class-1 leaf **57,700 /
    102,227 / 46,000** rows finalized, proved in **1.5 s, 0.22×** its
    segment's 6.8 s, at **0.92 GiB** of heap against the segment's 4.8
    GiB; the class-0 leaves 56,698 / 102,145 / 45,960, 1.4–2.1 s,
    0.39–0.57× their segments' 3.7 s. The
    first states the entry, the last the halt and the run's io-hash, and
    the first's exit digest is the second's entry digest;
  - **`areas`,** a predicate-like kernel (a row read and a comparison), its
    run one class-0 segment: both flags, its io-hash, 1.4–1.5 s;
  - each flag's conditions negated, refused (an entry pc, ts, register or
    image root; a segment from mid-run; one not ending at the halt); a
    tampered boundary byte refused, and an io-hash byte of 256 by its range
    check;
  - **the program id finalized** with its classes' leaf-circuit hashes
    (the slot's version 1), in the prover role: 1.5 s for the window
    kernel's three classes, at 351 MiB; an install derives without the
    prover's stack;
  - **derive counts every class's leaf rows** from the shape
    (`vos_pvm_compiler::leaf`), the built circuit's exactly, and refuses a
    kernel whose leaf would not fit.
- **Estimate:** 2–3 weeks.

### 5.13 The fold and the fixed point (F)

- **The fold node** (`proving.md` §3.4, A.3):
  - it re-hashes each child's preimage;
  - **the circuit set:** each child's recomputed circuit hash is one of
    the program's leaf-circuit hashes or the fold word W, **and** the
    child carries W; the fold copies W to its output;
  - **the program:** the id is recomputed from its preimage, both
    children carry it, and a leaf child's hash is among that preimage's
    leaf-circuit hashes;
  - it checks adjacency, continuity, and the ends.
- **Tests:**
  - a fold of two leaves;
  - a fold of two folds within the constant shape;
  - a tree over four segments;
  - refusals: a wrong program, a gap, broken continuity, a prefix, a
    mid-run start, a wrong child circuit, a child carrying a foreign
    word, a leaf carrying a wrong program id.
- **Gate:** a fold verifies two folds within the shape, at the memory and
  time of a leaf (≤ 4 GiB, expected 1.2–2.6 s).
- **Estimate:** 2–3 weeks.

### 5.14 The final wrap (F)

- **In our Stwo fork:**
  - a Blake2b-256 Merkle hasher and Fiat–Shamir channel;
  - FRI fold step 3 admitted after a review and tamper tests;
  - the way to the wrap's 80 proven bits, decided here (`proving.md`
    §3.5): affine DEEP batching for format 28 only (recommended, about
    1.06× verify), a 6-bit batching-phase PoW (1.11×), or blowup 8 with
    41 queries (1.97×);
  - `MerkleVerifierLifted::verify`'s `assert_eq!` on the values at
    duplicate query positions, a panic on prover data, becomes an error.
- **The wrap circuit:**
  - a 1-to-1 node over the root;
  - blowup 64, 20 queries, PoW 26, interaction PoW 8, fold step 3, a
    2^6 last layer, with affine DEEP batching;
  - 146 conjectured and 80 proven bits [model];
  - it checks the root's W against the fold circuit's hash, its
    constant;
  - its public words, the program id and the io-hash, sit at reserved
    addresses 0–23 (`proving.md` A.3).
- **`vos-final-verifier`, complete** (`pvm/proof/final-verifier`), for
  x86, wasm32 and riscv64em-javm.
- **Tests:**
  - tampers on fold step 3 and on the Blake2b channel;
  - verification in the Wasm harness (from spike 4a) and on the JAM-only
    host.
- **Gate:**
  - at most 150M gas unmasked on the JAM-only host (target about 85M,
    64M through `0x400`);
  - at most 2^17 rows;
  - at most 8 GiB unmasked (expected 4.4–9.5 s).
- **Closing gate:** Fable's review of the fork change, then its push to
  olanod/stwo.
- **Estimate:** 3–4 weeks.

### 5.15 End to end

- **`vos-statement`** (`pvm/proof/statement`, with no vos dependency,
  so Kreivo can depend on it): the types, the canonical encoding, the
  statement id, and the venue's recomputation of the io-hash
  (`proving.md` §3.6).
- **The golden fixtures** of A.6, from the fixture generator.
- **The window statement and the solvency predicate,** each:
  - segments, leaves, folds and the wrap, in `test-proof` (about 3–5
    minutes a window);
  - verified natively, in Wasm and on the JAM-only host.
- **Gate:** every venue judges every fixture alike.
- **Estimate:** about 2 weeks.

### 5.16 Acceptance

- **Gates:** `ci-full`, `test-proof` and the checker loop.
- **Rows measured:**
  - segment proving time and memory per kernel, on Poseidon2;
  - leaf, fold and wrap time and memory, against `proving.md` A.7;
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
| M0 (5.1–5.7) | 6–9 |
| M1's preparation (5.8.0) | 1–2 |
| M1 (5.8–5.15) | 17–24 |
| reviews and acceptance | 2–3 |
| **slice 5** | **26–38** |

- **M0 runs on two tracks.** Its critical path is 5.1 → 5.2 → 5.4, and
  5.5 → 5.12 across the milestones. 5.7 (2–3 weeks) runs beside it.
- **M1 is 18–26 in all:** 5.8.0's 1–2, then 17–24 for 5.8–5.15. Those
  sit below spike 4b §8's 20–28 to a working tree for our own AIR: the
  design and its counts are now measured, and production hardening (the
  audit, masking) is slice 6.

## Decisions

**Taken by the owner** (`proving.md` §12): all eight, including the three
that shape this slice:
- our own recursion AIR on StarkWare's design;
- Blake2b-256 for the final proof;
- arguments through a witness-input precompile.

Also the owner's, on 2026-10-16: the fork's pushes (Rules), and
Poseidon2-M31 as the segment channel, on 5.2's total cost a segment.

**Decided on the evidence, and the owner's to override:**
- the reference Poseidon2 with Plonky3's parameters;
- lossless encodings in the new formats: the boundary states as bytes,
  other words as 16-bit limbs;
- the inner parameters and interaction PoW;
- the padded shape as a format constant;
- 5.6's phone run on Android first.

## Risks

`proving.md` §10 and `recursion-air.md` §11 hold the full list, each with
its gate. This slice's sharpest:
- **The leaf's Poseidon2 hashing.** A leaf's commitment takes 0.63 s
  [measured]; 5.12 measures the whole leaf against its 1.5–3 s
  projection.
- **The gate compiler and the in-AIR verifier.** They are new
  soundness-critical code: differential tests, Fable reviews, and the
  external audit before value.
- **The model's rows:** 5.11 counts the kernel leaf's topology term by
  term, weeks before 5.12 proves it. At 44 queries over the hardened
  shape, its `p2` sat within about 1% of 2^16 [model]; 5.8.0's rule moved
  the segment format to 35 (40 queries, PoW 24), and the built topology's
  `p2` is 12.0% under 2^16 [measured, 5.11].
