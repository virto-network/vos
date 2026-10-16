# Slice 5, spike 4a: what a final recursion proof costs to verify on JAM, on Kreivo and natively

Date 2026-10-16. Repository `/home/daniel/src/virto/vos`, worktree
`.worktrees/s5-spike1`, branch `spike/s5-guest-verify`. Two local commits on
top of the audit's `a6f6adbc`; nothing pushed, no existing commit rewritten.
The `vos-core` worktree, the Stwo fork, Kreivo, polkadot-sdk and
`proving-src` were only read.

Paths:
- `VC` = the `vos-core` worktree (read only);
- `SB` = the spike branch's tree; `S4` = `SB/spikes/s5-final-gas`;
- `ST` = the Stwo fork at `4f417dd` (vos-core's pinned `e1286720` plus two
  build-config commits), as cargo checked it out:
  `~/.cargo/git/checkouts/stwo-5d589575e54d9465/4f417dd`;
- `UP` = `/home/daniel/.claude/jobs/8e1fc21e/tmp/s5/proving-src`
  (`starkware-libs/proving` at `916aefb5`);
- `PS` = `/home/daniel/src/gh/polkadot-sdk` (master `eb11ef2b85`; no
  stable2603 checkout exists locally, see Caveats); `KR` =
  `/home/daniel/src/virto/kreivo` (`feat/update-stable2603`);
- `PR` = `/home/daniel/.claude/jobs/8e1fc21e/tmp/s5/spike4a-proofs` (every
  proof used here, with its preprocessed root).

Tags:
- **[measured]**: gas on vos-core's JAM-only host (deterministic to the
  unit), bytes, RSS, retired x86 instructions of the Wasm run
  (deterministic to ±30 in 23M);
- **[measured, noisy]**: wall times; another spike loaded the machine
  throughout (load 10–15 on 22 threads), so every time is a minimum over
  repeated runs and still varies ±25%;
- **[model]**: a least-squares fit to measured points, with its error;
- **[projected]**: an estimate from measured parts, not run;
- **[read]**: read in source, cited.

## 0. The verdict: go

**A final proof of a realistic recursion layer fits JAM, with room**, once
its FRI folds three steps at a time (the format pins one today):

| final layer (unmasked unless said) | JAM gas | bytes | rule |
|---|---|---|---|
| **dedicated final layer: 320 cols, log 16, blowup 64, 13 queries, fold 3, last layer 2^6** | **54.4M** [measured] | **79.8 KB** | 36% of 150M |
| same, 400 columns | 60.3M [measured] | 86.6 KB | 40% |
| same, log 17 | 55.7M [measured] | 82.9 KB | 37% |
| same, masked, spike 2's (c) factor ×1.37–1.40 | ≈75–76M [projected] | ≈108–112 KB | 38% of 200M |
| same, masked, structural proxy (log 18, blowup 32, 16 queries) | 65.9M [projected; proxy measured] | 102 KB | 33% of 200M |
| root fold at the leaf's shape: 320 cols, log 20, blowup 8, 26 queries, fold 3 | 99.5M [measured] | 160 KB | 66% of 150M |
| same, masked (×1.40) | ≈139M [projected] | ≈224 KB | 70% of 200M |
| **today's FRI (fold step 1), log 20, blowup 4, 38 queries** | **198.9M** [measured] | 306 KB | **133% of 150M: fails** |
| StarkWare's circuit setting (blowup 4, 35 q, 26 PoW, fold 4) at its log 21 | 131.6M [measured] | 211 KB | 88% |
| StarkWare's prover default (blowup 2, 70 q, 26 PoW, fold 1) at log 21 | 328.5M [measured] | 515 KB | fails |

- **Against a 1e9 package:** 18 unmasked or 13 masked final proofs of the
  recommended layer per package, by gas [measured / projected].
- **The audit's projection held:** 60–150M and 100–300 KB were projected
  (`audit.md` §5.2); the measured range is 54–131M and 80–211 KB for the
  realistic settings, 199M only with today's fold step 1 at blowup 4.
- **On Kreivo** (Wasm under wasmtime 35.0.0 with sc-executor-wasmtime's
  settings), the recommended proof is **23.0M retired instructions**
  [measured]: 1.7 ms on this machine at its least loaded [measured, noisy],
  ≈2.9 ms on a reference-class core [projected], so **ref_time ≈ 2.9e9 ps**
  unmasked, ≈4.0e9 masked [projected]. That is 0.2–0.3% of a block's
  normal-class weight. **Proof bytes bind first:** 80 KB unmasked (1.5% of
  the 5 MiB PoV, 49 per block in the normal class's 3.75 MiB of length),
  ≈112 KB masked (2.1%, 35 per block) [measured / projected].
- **What must change:** the format's `fold_step == 1` pin
  (`VC/pvm/proof/src/proof.rs:421-425`) must admit 3 for the final layer.
  The pinned Stwo implements and tests multi-step folding
  (`ST/crates/stwo/src/core/fri.rs:131`, `:1191`), contrary to the pin's
  comment; it still needs the fork's review before the format admits it.
- **What the final layer's size decides:** blowup 64 is affordable only for
  a small final layer. The prover's memory is 5.1–5.4 bytes per committed cell
  of the extended domain [measured]: log 16 at blowup 64 takes 6.4 GiB,
  log 17 12.8 GiB, log 20 at blowup 8 12.8 GiB, log 20 at blowup 64 would
  take ≈100 GiB [projected]. So **make the final layer a dedicated wrap of
  the root fold, at log ≤ 17**, rather than raising the root fold's blowup.

**Recommended final-layer settings** (§9): a dedicated wrap at log ≤ 17,
≈320–400 columns, log blowup 6 with 13 queries and 20 PoW bits (98
conjectured bits; or 12 queries and 24 bits: −4% gas, −5% bytes), FRI fold
step 3 and last layer 2^6, Blake2b-256 Merkle trees (§5), a lean verifier
(no preflight; §4), and masking (c) on top.

## 1. What was built

`S4` (commit `4229b35f`), each crate its own workspace:
- **`air`**: the proxy AIR, `no_std` (`S4/air/src/lib.rs`).
  - One component in StarkWare's circuit-AIR proportions, 45:114:152:8 of
    319 committed columns (`UP/crates/circuit_verifier/src/circuit_components.rs:47-59`
    and the audit §5.1); `Shape::proportional` scales it (`:68`): 320 =
    45 + 115 + 152 + 8, 400 = 56 + 144 + 192 + 8, 500 = 71 + 181 + 240 + 8.
  - Preprocessed columns hold fixed values; main column `k ≥ 2` is
    constrained `m[k] = m[k-1]² + m[k-2]² + pre[k mod p]`; the interaction
    columns are logup batches of two fractions each
    (`finalize_logup_in_pairs`, degree 3, as every circuit-AIR component;
    `:120-149`), each fraction looking up two main and one preprocessed
    value, with a non-zero claimed sum. The composition splits in two:
    8 columns.
  - The verifier (`:188-219`) sizes the trees from the shape, draws the
    lookup elements and builds the component once: no preflight, no second
    build.
  - `prover.rs`: SIMD trace generation and `prove` (`:96`).
  - `hash.rs`: Merkle hashers with a pluggable compression (Blake2s
    bit-identical to stwo's, Blake2b-256) and a whole-message host hasher
    (§5).
- **`prove`**: proves one configuration in one process, records time and
  peak RSS (`VmHWM`), verifies natively, writes `(Statement, StarkProof)`
  postcard and the preprocessed root.
- **`guest`**: the verifier as a JAM refine program, spike 1's scaffold
  (allocator, stack, host calls) with a 68-byte payload (root, the proof's
  preimage hash, its length) and the proof as a preimage
  (`S4/guest/src/main.rs:474`); Merkle hash by feature (`:50-62`).
- **`harness`**: runs it on `RefineContext::try_run_jam` (the
  interpreter, PolkaJam's host prices), counts instructions on a bare
  machine (its gas equals the JAM run's in every case), profiles by
  function, serves VOS's BLAKE2b precompile and a priced Blake2s one on
  request (`S4/harness/src/main.rs:276`, `:317`), tampers, and verifies
  natively (single-threaded).
- **`wasm`** and **`wasm-run`**: the same verifier as a runtime-style Wasm
  blob and its executor (§6).

## 2. JAM: columns × log size × blowup

Blake2s channel, 20 PoW bits, fold step 1, last layer 2^0, every
configuration at ≥96 conjectured bits as vos-core's STANDARD (20 + 19·4).
Cells: gas / proof bytes / prover peak RSS [measured;
`S4/runs/guest-main.log`, `prove-main.log`]. Every proof accepted; gas on
the JAM host equals the bare machine's to the unit.

| log | log blowup : queries | 320 cols | 400 cols | 500 cols |
|---|---|---|---|---|
| 16 | 1 : 76 | 234.3M / 354 KB / 0.2 GiB | 247.0M / 378 KB / 0.3 GiB | 272.6M / 423 KB / 0.3 GiB |
| 16 | 2 : 38 | 147.3M / 217 KB / 0.4 GiB | 156.6M / 232 KB / 0.5 GiB | 170.8M / 254 KB / 0.6 GiB |
| 16 | 4 : 19 | 100.2M / 145 KB / 1.7 GiB | 107.9M / 155 KB / 2.0 GiB | 116.2M / 166 KB / 2.4 GiB |
| 16 | 5 : 16 | 91.6M / 135 KB / 3.4 GiB | 96.8M / 141 KB / 4.0 GiB | 105.6M / 151 KB / 4.8 GiB |
| 16 | 6 : 13 | 83.6M / 123 KB / 6.8 GiB | 90.3M / 131 KB / 8.0 GiB | 96.9M / 137 KB / 9.6 GiB |
| 18 | 1 : 76 | 273.3M / 419 KB / 0.9 GiB | 290.7M / 452 KB / 1.1 GiB | 308.6M / 483 KB / 1.3 GiB |
| 18 | 2 : 38 | 164.4M / 247 KB / 1.7 GiB | 180.3M / 272 KB / 2.0 GiB | 194.5M / 294 KB / 2.4 GiB |
| 18 | 4 : 19 | 113.4M / 168 KB / 6.8 GiB | 121.2M / 179 KB / 8.1 GiB | 128.0M / 186 KB / 9.6 GiB |
| 18 | 5 : 16 | 102.6M / 155 KB / 13.6 GiB | — | — |
| 20 | 1 : 76 | 326.0M / 508 KB / 3.4 GiB | 345.3M / 544 KB / 4.2 GiB | 366.3M / 581 KB / 5.2 GiB |
| 20 | 2 : 38 | 198.9M / 306 KB / 6.8 GiB | 205.5M / 316 KB / 8.1 GiB | 223.2M / 344 KB / 9.6 GiB |

- **Not proved, by memory** (16 GiB cap): log 18 at blowup 32–64 beyond 320
  columns, log 20 above blowup 4. RSS is 5.1–5.4 bytes per cell of the
  extended domain (columns × 2^(log + log blowup)) at every point.
- **Columns cost little:** ≈74k gas a column at blowup 64 and fold step 3
  (c320 → c400: +5.9M) [measured]; 320 → 500 at log 16 adds 13–38M.
- **Log size costs little too:** +1.3M (+2.4%) per doubling at blowup 64
  and fold step 3 (log 16 → 17) [measured]. Most of the gas is
  width-free: FRI and Merkle paths.
- **Blowup pays:** at log 16, blowup 2 → 64 cuts 234M to 84M, because
  queries fall from 76 to 13.
- **StarkWare's settings** [measured; `UP/crates/privacy_circuit_verify/src/consts.rs:44-64`,
  `UP/crates/prover/src/prover.rs:385-396`]:

  | setting | log 16 | log 18 | log 20 | log 21 |
  |---|---|---|---|---|
  | blowup 4, 35 q, 26 PoW, fold 1 (c320) | 134.7M / 197 KB | 157.7M / 235 KB | 185.5M / 284 KB | — |
  | **blowup 4, 35 q, 26 PoW, fold 4 (their circuit config)** | 102.2M / 160 KB | — | 126.1M / 202 KB | **131.6M / 211 KB / 12.8 GiB** |
  | blowup 2, 70 q, 26 PoW, fold 1 (their prover's default) | 215.0M / 323 KB | 254.5M / 389 KB | 297.8M / 462 KB | 328.5M / 515 KB |

  At their own size (log 21, fold 4) the proxy's proof is 211 KB against
  their recursive proof's 263,812 B (`consts.rs:8`) [read]: the proxy is
  a fair stand-in, a little narrower in sampled values.
- **Instructions:** 14.3M PVM instructions for the recommended proof, 3.7–3.8
  gas each across the sweep (every count in `S4/runs/guest-*.log`)
  [measured].
- **Natively** (single-threaded verify, best of 20): 0.8–1.0 ms for the
  recommended layer (320–400 columns, Blake2s or Blake2b), 1.3 ms at log 20
  blowup 8, 3.2 ms at log 20 blowup 4 fold 1 [measured, noisy]. Proving
  on 8 threads: 10–16 s and 6.4 GiB for the recommended layer, 25 s and
  12.8 GiB at log 20 blowup 8 [measured, noisy / measured].
- **Guest memory:** peak live heap ≤ 1.1 MiB, ≤ 542 pages written
  (2.1 MiB), 12 KiB of stack, across every proof [measured]. The verifier
  program is 344–370 KB by variant (spike 1's segment verifier: 2.46 MB).
- **Rejects** (`S4/runs/guest-tamper.log`, the recommended proof): a byte
  flipped at 25/50/75% is refused for 35.5M, 35.5M and 44.6M gas
  (65–82% of a full verify); a wrong preprocessed root for 9.0M (the
  decode, then the check) [measured].

**The 2-to-1 fold's log size.** The audit counts ≈26M trace cells to verify
one kernel-shape segment (a Poseidon2 component at 2^16 rows and a QM31-ops
component at 2^19 per inner proof; `audit.md` §5.2). A leaf fold verifies
two: ≈52M cells, the QM31 component at **2^20**, an average height of
≈2^17 over ≈350 columns [projected]. StarkWare's leaf circuit sits at
2^21 (`consts.rs:45`) [read]. A fold of two fold proofs (≈350 columns
each) needs far less, ≈2^16–2^17, but a tree padded to one shape (as
StarkWare's) keeps the leaf's 2^20 everywhere, the root included. A
dedicated final wrap of the root verifies one narrow proof: ≈2^16–2^17
[projected].

## 3. The FRI fold step and the last layer

The pinned Stwo implements a fold step above 1 (circle fold plus line
folds by `fold_step`, packed leaves; `ST/crates/stwo/src/core/fri.rs:31-36,
119-175`), with tests (`:1191`, `valid_proof_with_jumps_passes_verification`).
The prover and verifier at the pinned rev accept it; vos-core's format
refuses it (`VC/pvm/proof/src/proof.rs:421-425`). Measured, gas M / KB
[`S4/runs/guest-fold.log`]:

| proof | f1 ll0 | f1 ll3 | f1 ll6 | f2 ll0 | f2 ll6 | **f3 ll0** | **f3 ll6** | f4 ll0 | f4 ll6 |
|---|---|---|---|---|---|---|---|---|---|
| c320 log 16 blowup 16 q19 | 100.2 / 145 | 97.7 / 145 | 90.3 / 135 | 73.7 / 114 | 69.0 / 107 | 68.1 / 102 | 67.8 / 102 | 71.9 / 107 | 66.6 / 99 |
| c320 log 16 blowup 64 q13 | 83.6 / 123 | 77.0 / 114 | 70.4 / 104 | 60.4 / 91 | 56.9 / 86 | 57.0 / 83 | **54.4 / 80** | 58.6 / 85 | 54.1 / 79 |
| c320 log 18 blowup 16 q19 | 113.4 / 168 | 110.1 / 166 | 102.6 / 156 | 81.0 / 127 | 75.9 / 120 | 74.0 / 113 | 74.1 / 115 | 77.8 / 117 | 74.6 / 113 |
| c320 log 20 blowup 4 q38 | 198.9 / 306 | 196.6 / 304 | 193.1 / 304 | 137.1 / 231 | 137.0 / 231 | 130.4 / 215 | 129.6 / 214 | 135.0 / 218 | 131.7 / 212 |

- **Fold step 3 saves 32–35% of the gas and 30–35% of the bytes** at every
  shape; 4 saves no more (each query opens 16 values a layer instead of 8).
- **A larger last layer** saves 3–16% at fold step 1, 0–5% at fold step 3.
- FRI is the bulk of the width-free part: at fold step 1 the model (§7)
  puts 65–72% of the gas in Merkle path hashes, two thirds of them FRI's;
  at the recommended fold step 3 and last layer 2^6, 49% (FRI 19%, the four
  trace trees 30%), with 35% per column once and 17% per column per query
  [model].

## 4. A lean verifier

**The proxy's verifier is already lean:** it sizes the trees from the
shape and builds its one component once (`S4/air/src/lib.rs:188-219`);
stwo's own `InfoEvaluator` pass inside `FrameworkComponent::new` is ≈0.3M
instructions (2%) [measured, profile].

**vos-core's segment verifier without its preflight** (`verify_standalone_lean`,
`SB/pvm/proof/verifier/src/lib.rs:430`, commit `a465c10b`): no component
set built with dummy lookup elements, no constraint-counting
`preflight_component_dimensions`, no transcript replay in
`expected_fiat_shamir_query_count` (`:524`, `:710`). Spike 1's guest, audit
proofs, JAM host [measured; `S4/runs/lean-segment.log`]:

| proof | as is | lean | saved |
|---|---|---|---|
| p2 kernel shape, real seg, MOBILE | 3.474B | 2.992B | −0.48B (−13.9%) |
| p2 kernel shape, real seg, STANDARD | 2.391B | 1.909B | −0.48B (−20.2%) |
| p2 full shape, 2-step, MOBILE | 5.475B | 4.647B | −0.83B (−15.1%) |
| b2s kernel shape, real seg, MOBILE | 1.520B | 1.282B | −0.24B (−15.6%) |
| b2s kernel shape, real seg, STANDARD | 1.167B | 0.929B | −0.24B (−20.4%) |
| b2s full shape, 2-step, MOBILE | 2.324B | 1.919B | −0.41B (−17.4%) |

- **The preflight costs 14–21%, not the audit's ≈8%.** It is a constant per
  shape (0.24B on Blake2s, 0.48B on Poseidon2 for the kernel shape). The
  doubling on Poseidon2 is consistent with the transcript replay, which
  hashes every sampled value again (the two parts were not separated). The
  as-is figures equal the audit's to the unit.
- **Decoding is the next lever:** postcard decoding is 8.8M of the
  recommended proof's 54.4M (16%) and ≈100–110 gas a proof byte everywhere
  [measured; `S4/runs/profile-c320-l16-b6-f3-ll6.log`]. A fixed-layout,
  zero-copy proof format would save most of it [projected].

## 5. Hashes: software, precompiles and the host's own

The recommended proof hashes 2,081 Blake2s blocks; `compress` is 43% of the
verify's instructions, QM31 products 10%, `fri_answers` 7%, `memcpy` 6%
[measured, profile]. Six guests verify the same proofs (§1;
`S4/runs/guest-variants.log`, `guest-b2b-rc.log`); JAM host, gas M:

| proof | stwo Blake2s | own Blake2s | own Blake2s, `0x401` at 600 | Blake2b-256 (RustCrypto) | own Blake2b | Blake2b, **VOS `0x400`** |
|---|---|---|---|---|---|---|
| c320 log 16 b64 f3 ll6 | **54.4** | 72.7 | **40.4** (1,958 calls) | 57.3 | 79.8 | **43.1** (1,884 calls) |
| c320 log 16 b16 f1 | 100.2 | 143.0 | 63.5 | 101.3 | 150.8 | 66.7 |
| c320 log 18 b16 f3 | 74.0 | 101.3 | 54.5 | 81.0 | 115.8 | 60.0 |
| c320 log 20 b4 f3 | 130.4 | 184.3 | 92.3 | 135.0 | 198.4 | 97.7 |
| c400 log 16 b16 f1 | 107.9 | 152.5 | 71.1 | 111.7 | 164.7 | 75.5 |

- **A Blake2s precompile would save 26–37%** (`0x401`, priced at 600 gas
  like VOS's BLAKE2b compression, `VC/pvm/runtime/src/precompile.rs:21-29`;
  no such VOS precompile exists, the harness serves it). Measured against
  stwo's software Blake2s; this spike's own compression is 34% slower than
  RustCrypto's in software, so the precompile figures carry its overheads.
  **JAM has no precompile:** there the precompile guests answer `WHAT` and
  pay 1,000 gas per unserved call on top of software
  (`VC/pvm/runtime/src/refine_host/jam.rs:20`; 74.8M against that guest's
  software 72.7M).
- **Blake2b-256 trees** cost +1 to +10% in software on JAM (RustCrypto's;
  +5% on the recommended proof: node hashes are 64 bytes, a half-empty
  128-byte block), and **−19 to −33% through VOS's real BLAKE2b
  precompile** (`0x400`, 600 gas; −21% on the recommended proof)
  [measured].
- **Kreivo's host offers Blake2b-256, not Blake2s.** `sp_io::hashing`
  serves keccak_256/512, sha2_256, blake2_128/256 (Blake2b) and twox
  (`PS/substrate/primitives/io/src/lib.rs:1443-1484`) [read]; there is no
  Blake2s, no Blake3, no compression call; the arkworks curve calls are not
  in a parachain's host functions [read]. Measured in Wasm (§6), the same
  trees hashed through `ext_hashing_blake2_256_version_1` cost **24–36%
  fewer instructions** than stwo's Blake2s in the blob (23.0M → 17.4M on the
  recommended proof); this spike's own Blake2b in the blob saves nothing
  (+1 to +11%).
- **So the final layer's Merkle trees should hash with Blake2b-256:** at
  par on JAM, a precompile on VOS, a host function on Kreivo. Its
  Fiat-Shamir channel can stay Blake2s (a few kilobytes a proof) or move
  with it. The final layer is never verified in-circuit, so its hash costs
  the recursion nothing. This departs from the plan's "Blake2s channel" for
  the final proof (`VC/docs/design/slice-5-proving.md:240`): the owner's to
  decide.

## 6. The Wasm runtime (Kreivo)

**The blob** (`S4/wasm`): the same `air` verifier, `wasm32-unknown-unknown`,
`-C target-cpu=mvp`, `-Z build-std=core,alloc` (substrate-wasm-builder's
fallback when `wasm32v1-none` is absent,
`PS/substrate/utils/wasm-builder/src/wasm_project.rs:860-878`), memory
imported, every allocation through sp-io's host allocator ABI with
`RuntimeAllocator`'s alignment scheme (`S4/wasm/src/lib.rs:86`;
`PS/substrate/primitives/io/src/global_alloc_wasm.rs:48-84`). 208 KB
uncompressed [measured].

**The executor** (`S4/wasm-run/src/main.rs:86-131`): wasmtime **35.0.0**
(Kreivo's lockfile, `KR/Cargo.lock:11225-11226`), configured as
`sc-executor-wasmtime`'s `common_config`
(`PS/substrate/client/executor/wasmtime/src/runtime.rs:218-314`): Cranelift
`SpeedAndSize`, every post-MVP feature off, `RecreateInstanceCopyOnWrite`,
`sc_allocator::FreeingBumpHeapAllocator` behind
`ext_allocator_{malloc,free}_version_1`; and the two semantics:
- **client** (block import and benchmarking,
  `PS/substrate/client/executor/src/wasm_runtime.rs:311-321`): no stack
  metering, NaNs not canonicalized, 1 MiB native stack, `Static` memory;
- **PVF** (validation, `PS/polkadot/node/core/pvf/common/src/executor_interface.rs:53-97`):
  stack-depth metering injected by `wasm-instrument` at 65,536, NaN
  canonicalization, 256 MiB native stack, `Dynamic { 2080 pages }`.

The run is pinned to one P-core; retired user-mode instructions of the
thread over the call (host functions and allocator included) are counted
with `perf_event` [measured; `S4/runs/wasm-count.log`, `wasm-rounds.log`,
`wasm-extra.log`]:

| proof | PVF instructions | client instructions | min wall PVF / client (ms) | host allocations |
|---|---|---|---|---|
| **c320 log 16 b64 f3 ll6** | **23.0M** | 22.8M | 1.74 / 1.67 | 5,559 |
| c400 log 16 b64 f3 ll6 | 25.5M | 25.2M | 1.93 / 1.80 | 6,640 |
| c320 log 17 b64 f3 ll6 | 23.5M | 23.3M | 1.86 / 1.70 | 5,604 |
| c320 log 18 b32 f3 ll6 (masked proxy) | 27.4M | 27.2M | 2.15 / 1.98 | 5,728 |
| c320 log 20 b8 f3 | 40.6M | 40.2M | 3.07 / 2.93 | 6,671 |
| c320 log 20 b4 f3 | 52.1M | 51.7M | 5.28 / 4.62 | 7,114 |
| c320 log 20 b4 f1 (today) | 81.4M | 80.8M | 5.37 / 9.20 | 9,223 |
| c320 log 21, StarkWare circuit setting | 53.4M | 53.0M | 4.07 / 3.79 | 7,177 |
| c320 log 21, StarkWare prover default | 132.2M | 131.4M | 9.13 / 9.15 | 11,277 |

- **Stack metering costs 1%** (PVF against client) [measured].
- **JAM gas ≈ 2.43 × Wasm instructions** (2.34–2.55 over 98 proofs)
  [measured]: the two venues rank configurations the same way.
- **Time:** at its least loaded this P-core retired one instruction per
  0.06–0.08 ns (p10 0.063 ns over 98 proofs) [measured, noisy]. A
  reference-class core (Kreivo's weights were generated on a Xeon Platinum
  8370C at 2.8 GHz, `KR/runtime/kreivo/src/weights/pallet_contracts.rs:5-8`)
  is assumed at 0.125 ns (≈2.5 IPC at 3.2 GHz) [projected]. The weight must
  come from frame benchmarks on the reference machine; these are its
  expected order.
- Instantiation 10–30 µs; 34 pages (2.1 MiB) of linear memory under the
  PVF's dynamic heap [measured].

**Kreivo's limits** [read]: `MAXIMUM_BLOCK_WEIGHT` 2 s ref_time and a
5 MiB PoV (`KR/runtime/kreivo/src/config/system.rs:27,31`); normal class
75% (`:48`), so ≈1.4 s for one extrinsic; `BlockLength`
`max_with_normal_ratio(5 MiB, 75%)` = 3,932,160 bytes for normal
extrinsics (`:41`); the relay's `MAX_POV_SIZE` is 10 MiB
(`PS/polkadot/primitives/src/v9/mod.rs:463`); the PVF's backing timeout is
2 s (`PS/polkadot/primitives/src/v9/executor_params.rs:56`). 1 ref_time unit
is 1 ps (`PS/substrate/primitives/weights/src/lib.rs:43-49`).

**Per proof on Kreivo** (ref_time at 0.125 ns an instruction [projected];
bytes [measured], masked ×1.40 [projected]):

| final proof | ref_time | per block by weight | bytes | PoV share | per block by length |
|---|---|---|---|---|---|
| **recommended, unmasked** | 2.9e9 | 486 | 79.8 KB | 1.5% | **49** |
| **recommended, masked** | 4.0e9 | 347 | ≈112 KB | 2.1% | **35** |
| 400 columns, masked | 4.5e9 | 313 | ≈121 KB | 2.3% | 32 |
| log 20 b8 f3, masked | 7.1e9 | 197 | ≈224 KB | 4.3% | 17 |
| today's FRI, log 20, masked | 14.2e9 | 98 | ≈428 KB | 8.2% | 9 |

**Length binds, not weight:** a proof's bytes run out the normal class's
3.75 MiB ten times before its weight runs out 1.4 s. One proof is far under
the extrinsic length limit (the normal class's 3.75 MiB). Modesto's segment
verifier, by comparison, spends 0.48 MB and ≈11 ms a proof
(`/home/daniel/src/virto/modesto/docs/verifier-spike.md:51-59`) [read].

## 7. The cost model

**The brief's form** (fold step 1, last layer 2^0; 44 points)
[model; `S4/runs/fit.txt`]:

    gas ≈ −1.0M + 138k · columns + 179k · (queries × log size)

within 13.3% (rms 6.1%); `q × (log + log blowup)` fits no better.

**A mechanistic form** (98 points, every fold step and last layer):

    gas ≈ −4.2M + 59.3k · C + 2,171 · q·C + 17,183 · P + 9,376 · F

- `C` committed columns; `q` queries;
- `P` Merkle path hashes: `q·[4·(L+B−log2 q) + Σ over FRI layers (h_i − log2 q − (f−1))]`,
  the four trace trees and each FRI layer of height `h_i`;
- `F` FRI values folded: `q · layers · 2^f`.

It fits within **5.8% (rms 2.0%)**. The eight proofs made after the first
fit (log 17–21, blowup up to 128, PoW 24) landed within 0.2–3.6% of its
predictions [measured against model]. Read off it:
- 17.2k gas a path hash (one Blake2s compression ≈12.4k, plus the walk);
- 2.2k gas a column a query (4 bytes of leaf hash, the DEEP quotient's
  multiply-adds, ≈5 decoded bytes);
- 59k gas a column once (OODS evaluation, the quotients' line
  coefficients, sampled values decoded and mixed).
- **Wasm instructions** fit the same form within 8.0% (rms 2.5%):
  −1.63M + 29.0k·C + 678·q·C + 7,132·P + 3,801·F.
- **Projected with it:** log 20 at blowup 64, fold 3, last 2^6: 64.6M
  (320 cols); 400 columns at log 20, blowup 8, fold 3: 112.1M.

## 8. Masked

Spike 2's variant (c) at blowup 8 / 26 queries against unmasked STANDARD
(16 / 19) measured verify ×1.39 / ×1.37 and bytes ×1.35 / ×1.40 at 2^16 /
2^18 rows (`spike2-masking.md:734,742`) [read], on a 100-column toy.
Applied to this AIR [projected]:

| final proof | unmasked | masked ×1.37–1.40 | vs 200M | bytes masked |
|---|---|---|---|---|
| recommended (c320 log 16 b64 f3 ll6) | 54.4M | 74.5–76.1M | 38% | 108–112 KB |
| c400 log 16 b64 f3 ll6 | 60.3M | 82.6–84.4M | 42% | 117–121 KB |
| c320 log 20 b8 f3 | 99.5M | 136–139M | 70% | 216–224 KB |
| c320 log 20 b4 f3 | 130.4M | 179–183M | 91% | 290–301 KB |
| c320 log 20 b4, fold 1 (today) | 198.9M | 272–278M | **fails** | 413–428 KB |

**A structural proxy on this AIR:** (c) at blowup B lifts every tree one
level higher, commits the composition at 4N and runs FRI at rate 2^-(B-1)
with queries for 96 bits there (`spike2-masking.md:640-669`); its verifier
walks the trees and FRI of an unmasked proof at log L+2 and blowup B/2.
For the recommended layer that is c320 log 18 b32 16 q f3 ll6: **65.9M,
102 KB** [projected; proxy measured], ×1.21 the unmasked, before salts and the FRI mask
(a few columns). The toy's ×1.40 is the safer figure. For the log-20
root at blowup 8 the same proxy (log 22, blowup 4, 38 queries) is 149M by
the model [projected]. Prover memory under
(c) is ×1.56–1.57 (spike 2): ≈10 GiB for the recommended layer at log 16,
≈20 GiB at log 17 or at log 20 blowup 8 [projected], within the 24 GiB cap.

## 9. Recommended settings for the final layer

1. **A dedicated final wrap**: verify the root fold (Poseidon2 inner
   channel) in a final circuit whose own trace stays at log ≤ 17; do not
   raise the blowup of a root fold padded to the leaf's log 20.
2. **Log blowup 6 (64×), 13 queries, 20 PoW bits** (98 bits): 54.4–60.3M
   gas unmasked at 320–400 columns [measured]. Blowup 128 (11 queries)
   saves 7% more for twice the prover memory (50.4M, 12.8 GiB at log 16)
   [measured]; 12 queries with 24 PoW bits save 4% (52.2M) for 16× the
   grinding [measured].
3. **FRI fold step 3, last layer 2^6** (−35% gas, −35% bytes against fold
   1, last 2^0) [measured]. The format admits it for the final layer only,
   after the fork's review of the multi-step FRI path.
4. **Blake2b-256 Merkle trees** (§5): on the recommended proof +5% on JAM,
   −21% on VOS through `0x400`, −25% on Kreivo through `blake2_256`
   [measured].
5. **A lean verifier**: no preflight (−14 to −21% on the segment verifier,
   §4), components built once, and a fixed-layout proof decode (16% of the
   recommended verify) [measured / projected].
6. **Masked (c)** on top: ≈66–76M gas, ≈102–112 KB, ≈4e9 ref_time on
   Kreivo [projected].
7. **If the final layer must be the root at log 20:** blowup 8, 26 queries,
   fold step 3: 99.5M unmasked, ≈139M masked, 160–224 KB, 12.8 GiB to
   prove unmasked, ≈20 GiB masked [measured / projected]. It meets the
   rules, with half the margin.

## 10. Reproduce

Commits on `spike/s5-guest-verify` (local, not pushed):
- `a465c10b` `pvm/proof/verifier`: `verify_standalone_lean` (a measuring
  seam; `verify_standalone`'s path is unchanged: the as-is gas equals the
  audit's), and spike 1's guest `lean` feature;
- `4229b35f` the spike: `S4/{air,prove,guest,harness,wasm,wasm-run}`, the
  scripts and every log in `S4/runs`.

```sh
cd spikes/s5-final-gas
(cd prove && cargo build --release)            # nightly-2025-07-14
(cd guest && cargo build --release --target riscv64em-vos-atomic.json [--features b2b-pre --target-dir target-b2b-pre])
(cd harness && cargo build --release)
(cd wasm && cargo build --release [--features b2b-host --target-dir target-b2b-host])
(cd wasm-run && cargo build --release)
scripts/prove-sweep.sh <out> scripts/main-sweep.list       # also fold-, b2b-, extra-sweep.list
scripts/guest.sh [--profile] [--tamper] [--precompile=600] [--b2b] <out>/*.proof
scripts/wasm.sh <pvf|client> <runs> <b2s|b2b|b2b-host> <out>/*.proof
scripts/lean.sh                                             # the segment verifier, lean or not
python3 scripts/fit.py runs/guest-all2.results; python3 scripts/derived.py
```

Each heavy step ran under `systemd-run --user --scope -p MemoryMax=16G
-p MemorySwapMax=0 nice -n 10`, provers with 8 threads.

## Caveats

- **A proxy, not the recursion AIR:** one wide component with the circuit
  AIR's column proportions and logup degree. The real final layer has
  several components at several heights and its own constraint count; the
  verify cost is set by columns, queries and depths (the model fits that
  within 6%), so a real one of the same width should land near, but the
  OODS term (59k gas a column) depends on the constraints.
- **Gas** is vos-core's JAM-only host (Gray Paper 0.8.0 instruction gas,
  PolkaJam's host prices), not PolkaJam's own refine gas.
- **Wall times are noisy** (another job throughout); instruction counts are
  not. The reference-machine time per instruction (0.125 ns) is an
  assumption; the weight must come from benchmarks on reference hardware.
- **polkadot-sdk stable2603 sources are not local:** the executor settings
  were read at master `eb11ef2b85` (identical to stable2512 in the cited
  files); stable2603 also pins wasmtime 35.0.0 (Kreivo's lockfile).
  `sc-allocator` 39.0.0 from crates.io served the host allocator; its
  freeing-bump algorithm is the one in the tree. No `wasm-opt` pass.
- **Masking** is projected: spike 2's toy ratios, and a structural proxy
  that leaves out salts and the FRI mask.
- **Fold step > 1** is implemented and tested at the pinned Stwo but not
  reviewed for vos-core; spike 2's lifted-Merkle ordering defect
  (`74951f79` upstream) is a separate path, not exercised here (every tree
  is at the lifting height).
- **Prover times** (1–48 s) are on a loaded machine with 8 threads; peak
  RSS is reliable.
- **The Blake2s precompile** is hypothetical (VOS serves BLAKE2b only); its
  600-gas price copies the BLAKE2b one.
