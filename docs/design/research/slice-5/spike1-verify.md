# Slice 5, spike 1: one real segment proof verified as a PVM guest on the JAM-only host

Date 2026-10-15. Repository `/home/daniel/src/virto/vos`, worktree
`.worktrees/s5-spike1`, branch `spike/s5-guest-verify` from `vos-core` at
`3713cb42`; local commits only, nothing pushed. The `vos-core` worktree was
not touched. The owner's Stwo fork was used read-only, at branch
`no-std-pvf-gating` (`4f417dd`), through a `file://` git dependency; no
branch was made there (no change was needed).

Paths:
- `VC` = the `vos-core` tree at `3713cb42`;
- `SB` = the spike branch's tree;
- `S1` = `SB/spikes/s5-guest-verify`;
- `PR` = `/home/daniel/.claude/jobs/8e1fc21e/tmp/s5/proofs` (spike 3's proofs).

Machine caveat: another spike ran throughout. Gas and instruction counts
are deterministic (each JAM run's gas equals the observed rerun's to the
unit); wall times and native verify times are noisy (77–139 ms for the same
segment natively).

## The verdict

**It does not fit JAM.** One real Poseidon2-M31 segment (MOBILE settings)
costs **10.61–10.72 billion gas** to verify on the JAM-only host, as built:
**106–107 times** the rule's 100M unmasked bound, and 10.7 times the
whole refine gas of a PolkaJam work package (1e9). The four-segment run
costs 42.7 billion gas. Its proof, 1.94–2.02 MB (postcard), sits on the
rule's 2 MB line; gas, not size, is what fails.

**By how much, after every lever measured here:**
- a small fix to the Poseidon2 leaf hasher (on the spike branch) halves
  it: **5.56–5.68 billion gas**, 56 times the bound;
- the best combination measured, the Blake2s channel with STANDARD
  settings, is about **1.9 billion gas** a segment, 19 times the bound
  and still past a whole 1e9 package, before masking doubles it;
- a floor of about **0.79 billion gas** is spent before the verifier
  touches a single commitment (decode, structure preflight, building the
  32 components), measured by a proof with a wrong commitment.

**Realistic levers do not close two orders of magnitude.** Fewer queries
(STANDARD) saves 21–31%; a larger blowup saves less and the prover cannot
afford it; smaller segments save nothing (verify cost is flat in segment
size: a 2-step program costs 96% of a 131,072-step segment). Only an
aggregation or wrap layer, whose own verifier is narrow, can reach ~100M.
Under the plan's rule (5.0, spike 1: "Otherwise peers verify"), **peers
verify**; JAM can verify only a wrapped proof, in a later slice.

## Answers in brief

1. **Built:** the full-AIR verifier (`vos-pvm-proof-verifier`,
   `verify_standalone`) as a no_std PVM guest for vos-core's guest target
   and guest toolchain (`nightly-2026-03-20`), taking the program
   commitment and public inputs from the work item's payload and the
   postcard proof as a preimage, returning a verdict, the final memory
   root and the io-hash (`S1/guest/src/main.rs`). Two deviations, both
   forced: a target with `max-atomic-width: 64` and single-core atomic
   libcalls (stwo's verify graph pulls `tracing-core` and `foldhash`), and
   a no_std fix at 8 sites in `vos-pvm-proof` (its verifier path no
   longer built without std).
2. **Ran** on vos-core's JAM-only host (`RefineContext::try_run_jam`,
   `Host::Jam`, the interpreter, PolkaJam's host-call prices), gas limit
   1e11, on all four `p2-n1000000-j8-b131072-64` segments and both
   `p2-n1000000-j1` segments, and both `b2s-n1000000-j1` segments.
3. **Recorded per segment:** gas, instructions, heap (peak live 10.7 MiB,
   16.7 MiB high-water, 4,087–4,141 pages written in all), stack (56 KiB),
   proof size, native verify time (§3).
4. **Verdicts:** every real segment ACCEPTS; one byte flipped at three
   places REJECTS ("Root mismatch."), as does a wrong commitment; a wrong
   initial root is refused before verifying (§4).
5. **Decision rule:** does not fit, by 106–107× as built, by 56× with the
   leaf fix, by about 19× in the best measured combination (§6).
6. **For a JAM verifier agent** (§7): a 132-byte payload, a ~2 MB proof per
   segment, a ~2.46 MB program, a 24 MiB heap; the preimage path costs
   ~0.55M gas, negligible; the gas is the problem.

## 1. The guest

**Crate:** `S1/guest`, its own workspace (`S1/guest/Cargo.toml`), binary
`verify`.
- **Dependencies:** `vos-pvm-proof-verifier` by path, feature `p2` →
  `poseidon2-channel` (default; `--no-default-features` builds the Blake2s
  verifier), `postcard` (no_std, alloc).
- **Stwo:** `[patch."https://github.com/starkware-libs/stwo"]` to the
  fork's `4f417ddaf8a4…` (`no-std-pvf-gating`: the pinned `e1286720` plus
  `dashmap` prover-gated and the Poseidon252 PCS behind a default-on
  feature). With default features off, stwo is verify-only and no_std. No
  fork change was needed.
- **Toolchain and target:** `nightly-2026-03-20` (`S1/guest/rust-toolchain.toml`,
  a copy of `VC/pvm/guest/rust-toolchain.toml`), `build-std` and the
  linker script `VC/pvm/guest/pvm.ld` (`S1/guest/.cargo/config.toml`).
  - **The target is `VC/pvm/guest/riscv64em-vos.json` with one change,**
    `"max-atomic-width": 0` → `64` (`S1/guest/riscv64em-vos-atomic.json:13`;
    the original at `VC/pvm/guest/riscv64em-vos.json:13`). With width 0,
    `tracing-core` 0.1.36 and `foldhash` fail to compile (no
    `AtomicUsize`, no `alloc::sync`). With 64 and no `+a`, LLVM emits
    `__atomic_*` libcalls; the guest supplies single-core shims for
    load, store, exchange and compare-exchange at 1, 2, 4 and 8 bytes
    (`S1/guest/src/main.rs:491-556`). This is the settlement verifier's
    choice too (`VC/pvm/proof/settlement-verifier/riscv64em-vos.json:13`;
    `VC/pvm/proof/settlement-verifier/src/lib.rs:659-750`). The program is
    still RV64EM: no atomic instruction is emitted.
  - **Alternative:** gate `tracing` and `foldhash` out of the fork's
    verify graph, and keep vos-core's target unchanged.
- **A no_std fix in `vos-pvm-proof`:** its verifier path no longer built
  without std: `std::slice::from_ref` at
  `VC/pvm/proof/src/chips/ristretto/mod.rs:514, 524, 543, 552` (an
  evaluate path the verifier compiles). Replaced by `core::slice::from_ref`
  in that file (8 sites) on the spike branch. Nothing in `just ci` builds
  the verifier without std, so it rotted unseen.

**Input** (`S1/guest/src/main.rs:1-16, 410-468`), as a JAM work item gives it:
- **Work item 0's payload** (`fetch`, kind 13; served at
  `VC/pvm/runtime/src/refine_host/jam.rs:60, 139-155`), 132 bytes:
  - the program commitment, 32 bytes (the preprocessed root: 8 LE M31
    limbs on Poseidon2, 32 bytes on Blake2s);
  - the expected initial memory root (32);
  - the expected final memory root (32; zero = unchecked);
  - the proof's preimage hash (32; BLAKE2b-256 in the harness);
  - the proof's length (`u32`).
- **The proof:** a postcard `vos_pvm_proof::Proof`, read by
  `historical_lookup` (`:427-436`; served at `jam.rs:170-186`) into a
  `Vec` of its length, decoded (`:439-443`) and the bytes dropped.
- **Checks:** the proof's initial memory root equals the expected one
  (`:447-449`), the final one if given (`:450-452`), then
  `verify_standalone(proof, commitment)` (`:456`; `VC/pvm/proof/verifier/src/lib.rs:350`),
  which enforces the format version, the conjectured-security floor
  (MOBILE and STANDARD pass), the log-size cap, the commitment
  (`lib.rs:567-573`), boundary binding and stwo's verify (`lib.rs:695`).

**Output** (φ7 address, φ8 length; `S1/guest/src/main.rs:322-388, 391-408`):
the verdict (1 accept, 0 reject, 2–6 the refusals before verifying), gas
left at each phase (from the `gas` call, 48 gas each on JAM), the heap's
figures, the final memory root, the io-hash (φ9..12 of the final
registers), and the verification error's text on a reject. A panic traps
with φ7 = `0xDEAD` and the message's address and length (`:470-489`).

**Memory** (`S1/guest/src/main.rs:31-205`):
- **Heap:** a 192 MiB arena in `.bss` (`:38`; a standard program's zero
  pages are an `E₂` field, at most 2^16 pages, so 256 MiB is refused at
  link: "SPI: a field exceeds its wire width", `VC/pvm/compiler/src/linker.rs:190`,
  `VC/pvm/compiler/src/linker/layout.rs:92`). The allocator frees:
  power-of-two classes to 64 KiB, best-fit page runs above, in-place
  growth at the top (`:56-205`). It counts live bytes, their peak, the
  bump high-water mark (the pages it reached), and every allocation.
- **Stack:** the guest's own 1 MiB in `.bss`, set in `_start`
  (`:31-60`), because the standard program's stack is the read-only
  data's page offset, 64 KiB (`VC/pvm/compiler/src/linker/layout.rs:143-148`).
  It needed 56 KiB, so the default stack would do, barely.
- **Pages written** are counted by the host after the run
  (`Memory::take_dirty_pages`, `S1/harness/src/main.rs:168-190`), split
  into arena, stack and other.

**The linked program:** 2,455,473 bytes before the leaf fix, 2,455,320
after (Poseidon2); 2,476,785 (Blake2s); 876 and 884 functions. ELF 4.16 MB
(not committed; copies in `/home/daniel/.claude/jobs/8e1fc21e/tmp/s5/spike1-elf/`).

## 2. The run on the JAM-only host

**Harness:** `S1/harness/src/main.rs`, its own workspace.
- **Link:** `vos_pvm_compiler::link_elf_spi_with_symbols`, checked equal to
  `link_elf_spi` (`:343-349`).
- **The JAM run** (`run_jam`, `:144-196`): `RefineContext::load(program,
  &[], 1e11)` then `try_run_jam(JamRefine { service: 7, items: [payload],
  item: 0, preimages: Some(proof by its BLAKE2b-256) })`
  (`VC/pvm/runtime/src/refine_host/jam.rs:109-118`), so `Host::Jam`
  (`VC/pvm/runtime/src/refine_host.rs:99-106`): the reference interpreter
  (`RefineContext::load` → `PvmBackend::ForceInterpreter`,
  `VC/pvm/runtime/src/refine.rs:229-236`), no precompile, PolkaJam's
  prices for `gas` (48), `fetch` and `historical_lookup` (1,125 + 264 per
  KiB) (`jam.rs:11-42`). Instruction gas is vos-pvm's Gray Paper 0.8.0
  model; PolkaJam itself reports no refine gas
  (`VC/node/jam/src/builder/fit.rs:95-96`), so this is vos-core's figure,
  not PolkaJam's.
- **Instructions** (`run_counted`, `:242-291`): the same program on a bare
  `Machine` (sparse memory), observed, serving the same three calls at
  the same prices (`serve`, `:217-238`). **Its gas equals the JAM run's in
  every case**, to the unit.
- **Profile:** instructions by function from the linked symbols, and the
  entries into each function (jumps to its first instruction).
- **Native:** postcard decode and `verify_standalone`, best of three
  (`native`, `:294-308`).
- **Tampering** (`:444-484`): one byte XOR `0x01` at 25%, 50% and 75% of
  the proof, moved forward until it still decodes with the same roots
  (so the STARK, not the decoder or the root check, must reject); a
  wrong commitment; a wrong initial root.

## 3. Per segment

### 3.1 Poseidon2-M31, MOBILE (blowup 4, 38 queries, 20 PoW bits), as built

`S1/runs/mobile.log`. Gas limit 1e11; every run halts.

| Segment | Steps | Postcard B | Bincode B | **Gas** | Instructions | Gas/instr | Native verify |
|---|---|---|---|---|---|---|---|
| b131072-64 seg0 | 131,072 | 1,998,593 | 2,624,366 | **10,685,639,214** | 2,346,990,924 | 4.553 | 84.8 ms |
| b131072-64 seg1 | 131,072 | 2,019,085 | 2,645,790 | **10,723,507,870** | 2,360,462,247 | 4.543 | 86.8 ms |
| b131072-64 seg2 | 131,072 | 1,992,681 | 2,622,686 | **10,682,072,390** | 2,345,826,937 | 4.554 | 94.0 ms |
| b131072-64 seg3 | 13,126 | 1,938,095 | 2,583,854 | **10,609,907,786** | 2,320,432,978 | 4.572 | 84.7 ms |
| j1 seg0 | 32,768 | 1,971,491 | 2,603,182 | **10,647,562,828** | 2,333,539,972 | 4.563 | 92.9 ms |
| j1 seg1 | 31,342 | 1,966,459 | 2,599,182 | **10,639,334,527** | 2,330,609,859 | 4.565 | 99.6 ms |

- **By phase** (gas, from the guest's `gas` calls), b131072 seg1:
  - fetch and preimage lookup: 556,582;
  - postcard decode: 253,641,428 (2.4%);
  - `verify_standalone`: 10,469,309,608.
- **The four-segment run:** 42,701,127,260 gas.
- **Heap, every segment alike:**
  - 2.86–2.92 MiB live after decode (the decoded proof);
  - **peak live 10.65–10.69 MiB**;
  - high-water 16.41–16.68 MiB (the allocator's rounding);
  - about 379,000 allocations, 53.4–53.8 MiB allocated in all;
  - **pages written: 4,087–4,141 (15.96–16.18 MiB)**: 4,069–4,126 in the
    arena, 14 on the stack (56 KiB), 1–4 elsewhere.
- **It does not stream.** The whole proof is decoded (2.9 MiB) and stwo's
  `verify` consumes a whole `StarkProof`. It does not need to stream:
  memory is bounded at ~11 MiB live. **A 24 MiB heap suffices**, and the
  64 KiB standard stack.
- **Wall time** on the interpreter: 7.8–10.7 s a segment (JAM run).

### 3.2 With the leaf-hash fix (Poseidon2, MOBILE)

`S1/runs/leaffix-all.log` (the committed guest). Same proofs, same
verdicts.

| Segment | **Gas** | Instructions | Gas/instr | vs as built |
|---|---|---|---|---|
| b131072-64 seg0 | **5,640,680,641** | 1,842,069,074 | 3.062 | 0.528 |
| b131072-64 seg1 | **5,678,547,530** | 1,855,540,734 | 3.060 | 0.530 |
| b131072-64 seg2 | **5,637,113,973** | 1,840,905,057 | 3.062 | 0.528 |
| b131072-64 seg3 | **5,564,953,163** | 1,815,510,374 | 3.065 | 0.524 |
| j1 seg0 | **5,602,606,074** | 1,828,617,775 | 3.064 | 0.526 |
| j1 seg1 | **5,594,378,397** | 1,825,687,542 | 3.064 | 0.526 |

Heap and pages unchanged (peak live 10.65–10.69 MiB; 4,087–4,141 pages).
Native verify 77.7–88.1 ms.

### 3.3 Blake2s channel (format 24), MOBILE, for comparison

`S1/runs/b2s.log`; guest built `--no-default-features`.

| Segment | Postcard B | **Gas** | Instructions | Gas/instr | Native verify |
|---|---|---|---|---|---|
| b2s j1 seg0 | 1,934,310 | **2,407,628,144** | 576,621,668 | 4.175 | 24.0 ms |
| b2s j1 seg1 | 1,930,413 | **2,407,672,441** | 576,689,866 | 4.175 | 24.3 ms |

Decode 254.8M gas; peak live 10.66 MiB; 4,108–4,109 pages written.

## 4. Verdicts

All runs on the JAM host; native verdicts agree in every case.

| Proof | Guest verdict | Gas spent | Error |
|---|---|---|---|
| every real segment (12 runs above) | ACCEPT | as tabled | — |
| p2 b131072 seg0, byte 499,648 ^1 (as built) | REJECT | 9,980,200,140 | Root mismatch. |
| same, byte 999,296 ^1 | REJECT | 9,980,200,140 | Root mismatch. |
| same, byte 1,498,944 ^1 | REJECT | 9,980,200,205 | Root mismatch. |
| p2 b131072 seg1, bytes 504,771 / 1,009,542 / 1,514,313 ^1 (leaf fix) | REJECT | 4,941,972,639 / 4,941,972,639 / 4,941,972,704 | Root mismatch. |
| b2s j1 seg0, bytes 483,577 / 967,155 / 1,450,732 ^1 | REJECT | 1,914,950,106 / 1,914,950,106 / 1,914,872,291 | Root mismatch. |
| wrong commitment (one bit), p2 / p2 fixed / b2s | REJECT | 791,977,797 / 794,220,397 / 791,019,833 | preprocessed commitment mismatch |
| wrong initial root (one bit) | INITIAL_ROOT (5), not verified | 258,839,430 / 260,825,128 / 261,989,517 | — |

(`S1/runs/mobile.log`, `leaffix.log`, `b2s.log`.)
- **A tampered proof costs nearly a full verify** (93% as built, 87% with
  the fix, 80% on Blake2s): the trace trees' leaves are all hashed before
  a root is compared. Whoever submits a proof must pay for its rejection.
- **The wrong commitment marks a floor:** about 0.79 billion gas is spent
  before the first commitment is compared (`VC/pvm/proof/verifier/src/lib.rs:415-573`):
  ~0.25B decode, ~0.54B structure preflight and building the 32
  components' shapes. That alone is 7.9 times the bound.

## 5. Where the gas goes

**Profile, p2 b131072 seg1, as built** (`S1/runs/profile-baseline-seg1.log`):

| Instructions | Share | Entries | Function |
|---|---|---|---|
| 1,038,118,223 | 44.0% | 91,877 | `vos_pvm_proof::poseidon2::permute` |
| 504,946,321 | 21.4% | 68,696 | `compiler_builtins::mem::memmove` |
| 418,224,104 | 17.7% | 735,016 | `poseidon2::apply_external_round_matrix` |
| 113,840,388 | 4.8% | 1 | `stwo::core::pcs::quotients::fri_answers` |
| 70,184,898 | 3.0% | 263,853 | `QM31 * QM31` |
| 32,543,447 | 1.4% | 24 | `MerkleVerifierLifted::verify` |
| 26,251,061 | 1.1% | 494,108 | `memset` |
| ~45M | ~1.9% | — | building the components (`InfoEvaluator`, `ArithmeticCounter`, `Rc` drops) |

- **Poseidon2 is 61.7%:** 91,877 permutations at **15,851 instructions
  each** (`VC/pvm/proof/src/poseidon2/mod.rs:236-306`: generic
  `apply_m4`/external matrix and a reduction per field operation; with 16
  registers on RV64E the 16-word state likely lives in memory). An efficient
  M31 permutation on this ISA should be several times cheaper; not
  attempted here.
- **The memmove is a bug-grade inefficiency:** `P2MerkleHasher::update_leaf`
  appends a leaf's whole row to its buffer and then `drain(0..RATE)`s
  each 8-element block from the front (`VC/pvm/proof/src/poseidon2/mod.rs:381-390`),
  moving the rest of a ~16k-column row every time: quadratic in the row.
  The prover uses the same hasher, so it pays it too.
  - **Fixed on the spike branch** (`SB/pvm/proof/src/poseidon2/mod.rs:381-406`):
    absorb whole blocks in place, keep the remainder. Behaviour is
    identical: the guest built with it accepts all six real proofs made
    before it, so every leaf hash matches the committed roots.
  - **Effect:** instructions −21.4% and **gas −47%** (gas per instruction
    falls from 4.55 to 3.06; memory traffic is priced high).
- **After the fix** (`S1/runs/leaffix.log`): `permute` 55.9%, the external
  matrix 22.5%, `fri_answers` 6.1%, QM31 multiplication 3.8%.
- **Blake2s instead** (`S1/runs/b2s.log`, j1 seg0): 55,742 compressions
  at **2,978 instructions each** (28.8%), `fri_answers` 19.7%, QM31
  multiplication 12.2%, Merkle 6.4%. Hashing on the PVM is 5.3 times
  cheaper per call and moves 64-byte blocks rather than 32.
- **What scales with what:**
  - **Queries × columns:** the leaf hashes (each opened row hashes every
    committed column, ~15.8k) and `fri_answers`.
  - **Fixed per proof:** decode, the preflight, building the components,
    the OODS evaluation (the 263,853 QM31 products are the same with 19
    queries as with 38) and mixing the sampled values into the channel.
  - **Not the trace length:** a 2-step program forced to the full
    component set (`S1/prove`) costs 5,474,950,709 gas to verify on
    MOBILE (fixed guest), **96–97% of a 131,072-step segment's**. The
    AIR's width sets the cost.

## 6. The decision rule

**The rule** (`VC/docs/design/slice-5-proving.md:88-97`): a segment fits
if it costs at most ~100M gas and ~2 MB unmasked, so that masked (~2×) it
stays within ~200M and ~4 MB, and four fit a 1e9 package
(`POLKAJAM_REFINE_GAS`, `VC/node/jam/src/builder/fit.rs:105-106`) within
its 13.79 MB input (`max_input`, `fit.rs:88-89`).

| Variant | Gas a segment, unmasked | Masked (×2) | vs 100M | One segment vs a 1e9 package | Proof, unmasked |
|---|---|---|---|---|---|
| **p2 MOBILE, as built** (measured) | **10.61–10.72B** | ~21.4B | **106–107×** | 10.7× | 1.94–2.02 MB |
| p2 MOBILE, leaf fix (measured) | 5.56–5.68B | ~11.4B | 56–57× | 5.7× | same |
| p2 STANDARD, leaf fix (measured ratio 0.693 × 5.68B) | ~3.9B | ~7.9B | ~39× | 3.9× | ~1.2 MB (×0.593) |
| b2s MOBILE (measured) | 2.41B | ~4.8B | 24× | 2.4× | 1.93 MB |
| **b2s STANDARD** (measured ratio 0.786 × 2.41B) | **~1.9B** | ~3.8B | **~19×** | 1.9× | ~1.1 MB |
| any config: the floor before the first commitment check (measured) | 0.79B | — | 7.9× | 0.8× | — |

**Plainly: one segment does not fit; four do not fit; not even one
segment fits a whole PolkaJam work package, in any configuration
measured.** The proof size is not the problem (the four segments,
7.95 MB, fit the 13.79 MB input and the builder's 12 MiB cap); the gas is,
by one to two orders of magnitude.

### The levers, measured

The config levers were measured on a 2-step program forced to the full
component set (`S1/prove/src/main.rs`; `prove_canonical_with_config`,
`SB/pvm/proof/src/prove.rs:657`), proved under each config, and verified
on the same guest (`S1/runs/config-sweep.log`, `config-sweep-b2s.log`,
`prove-sweep.log`, `prove-sweep-b2s.log`). Ratios carry to real segments
because the cost is set by the component set, not the trace (§5).

| Config (log blowup : queries : PoW) | Conj. bits | p2 gas | vs MOBILE | Postcard B | Prover peak RSS (2-step!) |
|---|---|---|---|---|---|
| 2 : 38 : 20 (MOBILE) | 96 | 5,474,950,709 | 1.000 | 1,261,572 | 3.42 GB |
| 3 : 26 : 20 | 98 | 4,422,030,087 | 0.808 | 941,754 | 5.90 GB |
| 4 : 19 : 20 (STANDARD) | 96 | 3,796,527,258 | **0.693** | 747,686 | 11.14 GB |
| 4 : 18 : 26 | 98 | 3,694,949,435 | 0.675 | 713,169 | 11.14 GB; +105 s of grinding |
| 5 : 16 : 20 | 100 | — | — | — | **killed at the 16 GiB cap** |
| 6 : 13 : 20 | 98 | — | — | — | **killed at the 16 GiB cap** |
| b2s 2 : 38 : 20 | 96 | 2,324,771,163 | 1.000 | 1,229,224 | 2.80 GB |
| b2s 4 : 19 : 20 | 96 | 1,828,303,168 | **0.786** | 718,276 | 8.77 GB |

- **Fewer queries (STANDARD):** −31% gas on Poseidon2, −21% on Blake2s,
  not −50%: the fixed part (§5) does not shrink, and permutations fell
  only 37% (88,668 → 55,893). Proof −41%. **The prover pays:** 3.3 times
  the memory on this tiny program; spike 3's 131,072-step segments took
  18 GiB on MOBILE, so STANDARD there would pass the 24 GiB slice cap.
  STANDARD is only realistic on the 32,768-step cut (5.4 GiB on MOBILE,
  about 18 GiB by the same factor: an estimate).
- **A larger blowup:** blowup 32 and 64 could not be proved under 16 GiB
  even for a 2-step program (every component's LDE grows); blowup 8 saves
  19%. More PoW (26 bits) saves another 2.7% for 105 s of grinding.
- **Smaller segments:** no gain. Per-segment cost is flat in segment size
  (10.61B at 13,126 steps, 10.64B at 32,768, 10.72B at 131,072; 5.47B for
  2 steps against 5.68B), so smaller segments only multiply it. Larger
  segments are cheaper per step, and they are limited by the prover's
  memory, not the verifier.
- **Implementation:** the leaf fix (−47%, done); a faster Poseidon2
  permutation (it is 78% of the fixed guest's instructions; a 3× faster
  one would cut ~half again: an estimate, not measured); precomputed
  component shapes for a pinned shape class instead of building the 32
  components twice (part of the 0.54B preflight). Together with STANDARD
  these might bring Poseidon2 near ~2B: still ~20×.
- **The channel:** Blake2s verifies 2.3 times cheaper than the fixed
  Poseidon2 (j1 seg0 on MOBILE: 2.41B against 5.60B), against the plan's choice of
  Poseidon2-M31 as the one published channel (`VC/docs/design/slice-5-proving.md:264`),
  made for recursion. JAM's PVM has no hash host function, so on JAM the
  published channel's hash is paid in software either way.
- **An aggregation or wrap layer:** the only lever of the right size. A
  narrow final proof is cheap to verify: the settlement verifier's
  one-column AIR verifies in 28,951,968 gas (`VC/docs/design/spikes.md:826-833`).
  But native recursion over this 15.8k-column AIR was measured as not
  viable (`VC/pvm/proof/docs/design/recursion-decision.md:22-29`), and a
  pairing-based SNARK wrap has no pairing host function on JAM, so its
  verifier would also run in software: **unmeasured, and the next number
  to get** before JAM can be the venue.

## 7. What the verifier as a guest needs to become a JAM verifier agent

- **Input per segment:**
  - a 132-byte payload (commitment, two roots, the proof's hash and
    length; it could carry the shape class and public io-hash instead);
  - the proof, **1.94–2.02 MB** postcard as built (≈1.2 MB on STANDARD,
    ≈4 MB masked if masking doubles it): far past what a payload should
    carry, so a preimage.
- **The preimage path** (measured): `historical_lookup` of the whole proof
  into a heap buffer, 1,125 + 264 gas per KiB (`jam.rs:27-31`): the
  fetch, the lookup and two `gas` calls together cost **535,702–556,582
  gas**, under 0.01% of the verify. But a preimage must exist on chain
  before the package's lookup anchor: the service solicits it in an
  accumulate and someone provides it in a block, so **each segment is a
  ~2 MB preimage on chain and at least one block of latency.**
- **The other path:** a work item's extrinsic data, inside the package's
  13.79 MB `max_input` (the builder caps packages at 12 MiB,
  `VC/node/jam/src/builder/fit.rs:88-89`). The JAM-only host serves no
  extrinsic `fetch` kind today (only 0, 5, 6 and 13,
  `VC/pvm/runtime/src/refine_host/jam.rs:51-61`), so this path is
  unmeasured here; `fetch` is priced lower than the lookup (10 + 40 gas
  per KiB, `jam.rs:21-25`, fitted at 4 KiB only).
- **The program:** ~2.46 MB of standard program (the verifier's code).
  Check it against PolkaJam's service-code limit (Gray Paper `W_C`,
  4,000,000 bytes from memory; vos-core records no such parameter).
- **Memory:** a 24 MiB heap (peak live 10.7 MiB; 16.7 MiB high-water
  with a rounding allocator); the 64 KiB standard stack (56 KiB used); the
  192 MiB arena of this spike was only a measuring margin.
- **The build:** vos-core's guest toolchain, with atomics as libcalls
  (§1) or the fork changed to drop `tracing` and `foldhash` from the
  verify graph; the no_std fix in `vos-pvm-proof` (§1) kept, and a CI
  build of the verifier for the guest target so it does not rot again.
- **Pinned ids:** the accepted commitments (one per kernel and shape
  class) as constants in the agent, checked against the payload's
  (5.5's "pinned as constants"); the guest's output (verdict, final
  root, io-hash) is the statement JAM would record.
- **Gas:** what the venue cannot provide. Even with every lever above, a
  segment needs ~1.9–2B gas unmasked; PolkaJam gives a package 1e9.
- **Rejects cost:** a tampered proof burns 80–93% of a full verify before
  it is refused (§4); a verifier agent must charge the submitter.

## 8. The spike branch

Commits on `spike/s5-guest-verify` (local, not pushed):
- **`fc6ab580` `pvm/proof`: the verifier path builds without std again** —
  `SB/pvm/proof/src/chips/ristretto/mod.rs` (8 sites).
- **`2000c349` `pvm/proof`: absorb a Poseidon2 leaf's blocks in place** —
  `SB/pvm/proof/src/poseidon2/mod.rs:381-406`. Worth taking to vos-core
  on its own: it halves the verifier's gas and removes a quadratic copy
  from the prover's Poseidon2 commit as well (not measured on the
  prover).
- **`b90af489` `pvm/proof`: `prove_canonical_with_config`** —
  `SB/pvm/proof/src/prove.rs:648-680`, `SB/pvm/proof/src/lib.rs:575`:
  `prove_canonical` under a given PCS config (a measuring seam).
- **`6b5b45cd` the spike:** `S1/guest` (the verifier program), `S1/harness` (the
  JAM-host runs), `S1/prove` (proofs of the forced shape under other
  configs), `S1/runs/*.log` (every number above).

**Reproduce** (each under `systemd-run --user --scope -q -p MemoryMax=16G
-p MemorySwapMax=0 nice -n 10`):

```sh
cd spikes/s5-guest-verify/guest   && cargo build --release --target riscv64em-vos-atomic.json
cd spikes/s5-guest-verify/harness && cargo build --release
harness/target/release/s5-guest-verify-harness guest/target/riscv64em-vos-atomic/release/verify.elf \
  [--tamper] [--profile] <seg.postcard>:<commitment.bincode>...
# Blake2s: both with --no-default-features --target-dir target-b2s
prove/target/release/s5-guest-verify-prove <out> <name> <log sizes> <log blowup>:<queries>:<pow>...
```

The as-built numbers (§3.1) are from the guest built at `fc6ab580` (before
the leaf fix) with the spike directory.

## Caveats

- **Gas model:** vos-pvm's Gray Paper 0.8.0 instruction gas with
  PolkaJam's host-call prices. PolkaJam's own refine gas for this program
  was not measured (it reports none to the builder). The 2.7 gas per
  instruction of the toy settlement verifier rose to 3.1–4.6 here:
  memory-heavy code is priced higher.
- **The interpreter only;** the recompiler charges the same gas, faster.
- **Masking is assumed to double** cost and size, as the rule says; not
  measured (spike 2).
- **The config ratios** come from a 2-step program at natural sizes (its
  largest component 2^16), not from re-proving the kernel; the 2-step
  MOBILE proof verifies within 2–4% of a real segment, so they carry, but
  STANDARD on a real 131,072-step segment was not proved (it would not fit
  the prover's memory).
- **Not optimized:** the Poseidon2 permutation, `fri_answers` and the
  preflight were left as they are; the projections in §6 for them are
  estimates.
