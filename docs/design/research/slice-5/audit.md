# Slice 5 audit: the prover's width and the cost of verifying it

Date 2026-10-15. Repository `/home/daniel/src/virto/vos`. Work on spike 1's
worktree `.worktrees/s5-spike1`, branch `spike/s5-guest-verify`; local
commits only, nothing pushed. The `vos-core` worktree was not touched; the
Stwo fork was only read.

Paths:
- `VC` = the `vos-core` tree at `3713cb42`; `P` = `VC/pvm/proof`;
- `SB` = the spike branch's tree (spike 1's commits, spike 3's two commits
  cherry-picked as `f9f1c904` and `a3c49f4c`, and this audit's two commits);
- `AR` = `SB/spikes/s5-audit/runs` (every log behind a number below);
- `UP` = `/home/daniel/.claude/jobs/8e1fc21e/tmp/s5/proving-src`
  (`starkware-libs/proving` at `916aefb5`).

Tags:
- **[measured]**: gas on vos-core's JAM-only host (spike 1's guest verifier,
  the interpreter, deterministic to the unit), bytes, columns, RSS;
- **[model]**: a least-squares fit to the measured points, with its error;
- **[projected]**: an estimate from measured parts, not run;
- **[read]**: read in the source, cited;
- **[from memory]**: production systems I did not check in source here.

All gas figures are with spike 1's leaf-hash fix (`2000c349`) unless they say
"as built". Machine caveat: another job ran throughout; times are noisy, gas
and bytes are not.

## 0. The answers

1. **Width.** The AIR is **13,037 committed columns** (456 preprocessed,
   7,909 main, 4,664 interaction, 8 composition), not the ~15,775 the
   recursion record quotes (`P/docs/design/recursion-decision.md:25`); that
   figure predates the C2 diet, which took 512 limbs a row out of each
   BLAKE2b chip (`P/docs/plans/roadmap.md:179-184`). The widths are the same
   at both cuts; only log sizes change. Three groups make it:
   - **Ristretto, 8 chips: 42% of the columns** (5,503), 14% of the bytes
     (its 16-row columns are zero padding, which postcard encodes in one
     byte), **39% of the verify gas**;
   - **BLAKE2B: 23% / 31% / 21%**, half of it per-compression I/O replicated
     on every one of a compression's 96 rows;
   - **the page-Merkle boundary** (BLAKE2B_BOUNDARY, MEMORY_PAGE,
     MEMORY_MERKLE, MEMORY_ROOT_BOUNDARY): **22% / 30% / 20%**, and 47% of
     the prover's committed cells at the (32,768, 8) cut;
   - CPU is 6%, everything else under 7% together.
   - **Verify gas is linear in columns**, within 1% over four shapes and
     three configs on both channels: p2 MOBILE ≈ 0.42B + 388k gas per
     column; b2s MOBILE ≈ 0.20B + 164k. Every column costs the verifier the
     same whether it holds data or zeros.
2. **A shape per kernel is sound and measured.** The window kernel uses 22
   of the 32 chips (no Ristretto, POPCOUNT or BITCOUNT; the same mask from its
   code as from its trace): **7,519 columns, −42%**. Every relation still
   balances (the production `prove` path already drops up to 11 gated chips
   per proof, and the verifier accepts any mask holding the binding chips).
   A real 32,768-step segment proved under it verifies for **3.47B gas (p2)
   / 1.52B (b2s), −38% and −37%**; proof 1.69 / 1.65 MB (−14%); prover RSS
   −10%. The kernel id must pin the mask and log sizes.
3. **The levers stacked**, one real window-kernel segment, JAM-only host:

   | | p2 gas | b2s gas | proof |
   |---|---|---|---|
   | as built (full shape, MOBILE) | 10.65B [measured, spike 1] | 2.41B | 1.97 MB |
   | + leaf fix | 5.60B [measured, spike 1] | 2.41B | 1.97 MB |
   | + shape per kernel | **3.47B** [measured] | **1.52B** | 1.69 / 1.65 MB |
   | + blowup 8, 26 queries | **2.80B** [measured] | **1.30B** | 1.24 / 1.21 MB |
   | or + STANDARD (16, 19) | **2.39B** [measured] | **1.17B** | 0.97 / 0.94 MB |
   | masked, variant (c) at 8/26 | ≈3.3B [projected] | ≈1.6B | ≈1.3 MB |

   **Best measured: 1.17B, 11.7× the 100M target and above a whole 1e9
   package.** Masked, ≈1.6B. Every lever stacked that this audit can
   project (narrow BLAKE2b chips, global memory, a leaner verifier) leaves
   ≈0.45–0.9B unmasked: **no flat path reaches 100M**, because the
   width-independent part alone (FRI and Merkle paths) is 0.14–0.42B.
4. **The memory boundary.** Global memory (a logup memory argument across
   segments) would delete 2,856 columns of the kernel's 7,519 (−38%; ≈−0.38B
   b2s / −0.78B p2 at STANDARD [model]), 35% of the proof bytes, and about
   half the prover's committed cells at the (32,768, 8) cut (36% at
   (131,072, 64)). It is a protocol change, not an AIR tweak: a cross-segment
   challenge (or an elliptic-curve multiset hash, as SP1 now uses), a
   chain-level sum, and a new anchoring of the initial image. About 6–10
   engineer-weeks plus review. (SP1 does this; RISC Zero, from memory, pages
   per segment through a Poseidon2 Merkle tree, as VOS does with BLAKE2b.)
5. **Recursion.** StarkWare verifies a Cairo AIR of 8,331 columns (as wide as
   ours) at 70 queries inside a 319-column circuit AIR and folds proofs 2 to 1;
   its root proof is 264–546 KB [read]. For us, verifying one kernel-shape
   segment in a dedicated Poseidon2-M31 recursion AIR is ≈54k permutations
   and ≈0.4M QM31 operations [measured counts], about 26M trace cells, ≈13%
   of the segment's own proving. Its final proof (≈300–400 columns, Blake2s
   outer channel, high blowup) would verify on JAM for **≈60–150M gas**
   [projected], **once per aggregate**, at ≈100–300 KB. The earlier native
   recursion pushed the verifier through the general PVM AIR: ≈16k PVM steps
   (each a 781-column CPU row plus ledger rows) per Poseidon2 permutation
   where a dedicated AIR spends one ≈160-column row.
6. **Verdict.** The prover's foundation is appropriate (Stwo, M31, logup,
   canonical segments, a Poseidon2-M31 channel for recursion), and its width
   is ordinary for a VM. What is wrong is (a) the venue assumption, flat
   verification of base segments, which no production zkVM does, and (b)
   four wastes: the full 32-chip shape on every segment, BLAKE2b chips that
   carry per-compression I/O on all 96 rows, whole-page BLAKE2b hashing at
   every segment boundary, and an unoptimised verifier. **First:** take the
   leaf fix and the shape per kernel (≈1 week, measured −38%). **Then the
   only route to JAM is a recursion layer** (≈2–3 engineer-months on
   StarkWare's circuit stack, ≈4–6 on our own Poseidon2 AIR); until it
   exists, peers verify.

## 1. Width by chip

### 1.1 The table

Real segment proofs from spike 3 (`p2-n1000000-j8` seg 6, the (32,768, 8)
cut; `p2-n1000000-j8-b131072-64` seg 1, the (131,072, 64) cut), measured by
`s5-kernel-proof width` (`SB/spikes/s5-kernel-proof/harness/src/width.rs`;
`AR/width-full-p2.txt`). Columns per component come from driving each chip's
constraints through Stwo's `InfoEvaluator` (`drive_chip_oods`,
`P/src/framework_access.rs:100`) and its preprocessed count
(`MachineComponent::preprocessed_trace_sizes`); the proof's own bytes are
each component's queried and sampled values, re-encoded with postcard.

"% verify gas" is the fitted model of §1.3: the component's columns × the
per-column cost, over the measured total (p2 MOBILE: 388.3k gas per column,
5.475B in all; b2s: 163.6k, 2.325B). The two channels agree to 0.2 points.

| # | chip | log 32k / 131k | pre | main | inter | total | % cols | % proof B | % verify gas | constraints |
|---|---|---|---|---|---|---|---|---|---|---|
| 0 | CPU | 15 / 17 | 0 | 601 | 180 | 781 | 6.0 | 6.6 | 5.5 | 708 |
| 1 | **BLAKE2B** | 14 / 16 | 42 | 1991 | 948 | **2981** | **22.9** | **30.6** | **21.1** | 1419 |
| 2 | **BLAKE2B_BOUNDARY** | 16 / 17 | 43 | 951 | 436 | **1430** | **11.0** | **14.8** | **10.1** | 1022 |
| 3 | MEMORY | 18 / 20 | 0 | 50 | 4 | 54 | 0.4 | 0.4 | 0.4 | 54 |
| 4 | **MEMORY_PAGE** | 9 / 10 | 13 | 544 | 520 | **1077** | **8.3** | **11.4** | **7.6** | 430 |
| 5 | MEMORY_MERKLE | 6 / 6 | 0 | 268 | 12 | 280 | 2.1 | 2.9 | 2.0 | 80 |
| 6 | MEMORY_ROOT_BOUNDARY | 4 / 4 | 0 | 65 | 4 | 69 | 0.5 | 0.7 | 0.5 | 1 |
| 7 | REGISTER_MEMORY | 17 / 19 | 0 | 85 | 8 | 93 | 0.7 | 0.6 | 0.7 | 62 |
| 8 | REGISTER_MEMORY_BOUNDARY | 4 / 4 | 0 | 10 | 4 | 14 | 0.1 | 0.1 | 0.1 | 1 |
| 9 | REGISTER_MEMORY_CLOSING | 4 / 4 | 0 | 18 | 4 | 22 | 0.2 | 0.2 | 0.2 | 1 |
| 10 | PROGRAM_BOUNDARY | 4 / 4 | 0 | 25 | 4 | 29 | 0.2 | 0.2 | 0.2 | 1 |
| 11 | PROGRAM_MEMORY | 16 / 16 | 32 | 1 | 4 | 37 | 0.3 | 0.3 | 0.3 | 1 |
| 12 | JUMP_TABLE | 8 / 8 | 8 | 1 | 4 | 13 | 0.1 | 0.1 | 0.1 | 1 |
| 13 | RANGE_MULTIPLICITY_256 | 8 / 8 | 1 | 2 | 4 | 7 | 0.1 | 0.1 | 0.0 | 1 |
| 14 | BITWISE_LOOKUP | 8 / 8 | 3 | 4 | 4 | 11 | 0.1 | 0.1 | 0.1 | 1 |
| 15 | POWER_OF_TWO | 6 / 6 | 9 | 10 | 4 | 23 | 0.2 | 0.2 | 0.2 | 1 |
| 16 | POPCOUNT | 8 / 8 | 2 | 1 | 4 | 7 | 0.1 | 0.0 | 0.0 | 1 |
| 17 | BITCOUNT | 8 / 8 | 3 | 1 | 4 | 8 | 0.1 | 0.0 | 0.1 | 1 |
| 18 | BYTE_TO_BITS | 8 / 8 | 9 | 1 | 4 | 14 | 0.1 | 0.2 | 0.1 | 1 |
| 19 | MUL | 12 / 14 | 0 | 162 | 4 | 166 | 1.3 | 1.1 | 1.2 | 159 |
| 20 | BITWISE | 12 / 14 | 0 | 63 | 36 | 99 | 0.8 | 1.0 | 0.7 | 66 |
| 21 | COMPARE | 12 / 14 | 0 | 34 | 20 | 54 | 0.4 | 0.6 | 0.4 | 24 |
| 22 | DIVREM | 10 / 12 | 0 | 213 | 36 | 249 | 1.9 | 1.7 | 1.8 | 188 |
| 23 | **RISTRETTO** | 4 / 4 | 35 | 855 | 1476 | **2366** | **18.1** | 5.3 | **16.8** | 909 |
| 24 | RISTRETTO_ECALL | 4 / 4 | 6 | 46 | 8 | 60 | 0.5 | 0.2 | 0.4 | 56 |
| 25 | RISTRETTO_COMB_TABLE | 10 / 10 | 130 | 1 | 4 | 135 | 1.0 | 1.4 | 1.0 | 1 |
| 26 | RISTRETTO_FIXED_BASE_CONSUMER | 4 / 4 | 37 | 859 | 320 | 1216 | 9.3 | 3.0 | 8.6 | 623 |
| 27 | RISTRETTO_COMB_ANCHOR | 4 / 4 | 32 | 132 | 260 | 424 | 3.3 | 0.9 | 3.0 | 66 |
| 28 | RISTRETTO_COMB_SCALAR_BOUNDARY | 4 / 4 | 5 | 26 | 8 | 39 | 0.3 | 0.1 | 0.3 | 25 |
| 29 | RISTRETTO_COMB_COMPRESS | 4 / 4 | 39 | 865 | 324 | 1228 | 9.4 | 3.0 | 8.7 | 721 |
| 30 | RISTRETTO_COMB_COMPRESS_OUTPUT | 4 / 4 | 4 | 23 | 8 | 35 | 0.3 | 0.1 | 0.2 | 24 |
| 31 | BITWISE_AND_BYTE | 16 / 16 | 3 | 1 | 4 | 8 | 0.1 | 0.1 | 0.1 | 1 |
| | **total** | | 456 | 7909 | 4664 | **13,029 + 8** | 100 | 88 (rest shared) | 92.5 (7.5 width-free) | 6,650 |

- Both cuts have the same widths; the per-chip shares of bytes differ by at
  most 0.2 points (`AR/width-full-p2.txt`).
- The 14,094 column-samples are what the DEEP quotient touches per query
  (two-offset columns count twice); the OODS evaluation is 43,491 QM31
  products over 6,650 constraints.

### 1.2 Where a proof's 2 MB go

p2 seg 6, 1,969,745 B postcard [measured, `AR/width-full-p2.txt`]:
- queried values 1,544,514 B (**78%**): 13,037 values per query × 38
  queries, 4–5 B each;
- sampled (OODS) values 191,989 B (10%);
- FRI 151,155 B (8%); Merkle decommitments 81,172 B (4%).

So the size is columns × queries, and nothing else matters much. Bincode is
larger (2.6 MB: 4 B per value). The kernel-shape proof drops columns that
were mostly zero, so its bytes fall less than its columns (−14% against
−42%).

### 1.3 Verify gas is linear in columns [measured, model]

Spike 1's 2-step program forced to a canonical shape (its `j1shape` profile)
was proved under four masks and three configs on both channels
(`SB/spikes/s5-guest-verify/prove`, now taking a mask) and verified on the
guest (`AR/guest-*-2step*.log`):

| shape | columns | p2 2:38 | p2 3:26 | p2 4:19 | b2s 2:38 | b2s 3:26 | b2s 4:19 |
|---|---|---|---|---|---|---|---|
| full (`ffffffff`) | 13,037 | 5.475B | 4.422B | 3.797B | 2.325B | 2.013B | 1.828B |
| window kernel (`807cffff`) | 7,519 | 3.356B | 2.709B | 2.319B | 1.441B | 1.239B | 1.127B |
| kernel without BLAKE2B (`807cfffd`) | 4,538 | 2.166B | 1.750B | 1.508B | 0.935B | 0.804B | 0.724B |
| minimal (`8004effd`, 16 chips) | 3,957 | 1.958B | 1.559B | 1.353B | 0.841B | 0.723B | 0.649B |

(Config = log blowup : queries; 20 PoW bits throughout. The full-shape
figures equal spike 1's to the unit.)

Fit `gas = a + b · columns` per config, maximum error 1.0%:

| channel, config | a (width-free) | b (per column) |
|---|---|---|
| p2 2:38 (MOBILE) | 0.418B | 388.3k |
| p2 3:26 | 0.322B | 315.0k |
| p2 4:19 (STANDARD) | 0.289B | 269.3k |
| b2s 2:38 | 0.197B | 163.6k |
| b2s 3:26 | 0.162B | 142.2k |
| b2s 4:19 | 0.138B | 129.9k |

- Per column, across configs: **p2 ≈ 151k + 6.25k × queries; b2s ≈ 96k +
  1.77k × queries**. The p2 per-query term is about one Poseidon2
  permutation per 8 opened values (48.5k gas each, `RATE = 8`,
  `P/src/poseidon2/mod.rs:44`).
- **What the per-column cost is** (profiles, `AR/profile-*-kernel-mob.log`):
  - p2: Poseidon2 is **78%** of the instructions (54,274 permutations at
    15,850 instructions each: the leaf hashes of 7,519 values × 38 queries,
    the sampled values mixed into the channel, paths and FRI);
    `fri_answers` and QM31 products 10%;
  - b2s: Blake2s 29% (34,258 compressions at 2,978), `fri_answers` and QM31
    products 33%, Merkle 6%, `memset`/`memcpy`/allocation 11%, and ≈8% in
    `InfoEvaluator`/`ArithmeticCounter`: the preflight evaluates every
    component's constraints with an arithmetic counter, work a verifier with
    pinned shapes does not need.
- **The width-free part** (FRI layers, Merkle paths, fixed setup) is 7.5% of
  a full-shape verify and 12% of a kernel-shape one; at STANDARD on b2s it
  is still **0.138B, above the 100M target by itself.**
- **Real segments cost 3–5% more** than the 2-step proof of the same shape
  (kernel shape: p2 3.474 vs 3.356; b2s 1.520 vs 1.441), as spike 1 found.

### 1.4 Why the wide chips are wide [read]

- **Byte limbs everywhere.** PVM values are 64-bit; M31 holds 31 bits; the
  AIR stores a value as 8 byte limbs and checks XOR/AND through byte
  lookups. CPU's 601 main columns are 191 one-bit flags plus ~50 eight-byte
  values (`P/src/chips/cpu/columns.rs`); memory is byte-granular (one
  `MemoryAccess` lookup per byte).
- **BLAKE2B (2,981): every row carries the whole compression.** One G
  function per row, 96 rows per compression, but each row also holds:
  - the 16-word message, `H`, `T` (208 columns, `blake2b/columns.rs:83-137`)
    and the state `V0..V15` plus its 16 `VNextSum` helpers (256, `:180-424`);
  - the output and its two AND witnesses (192, `:233-242`), live on the last
    row only;
  - **1,024 byte-address columns** for the 256 byte-level memory lookups of
    `h`, `m` and the output (`:257-285`), live on the first row only
    (`blake2b/mod.rs:1746-1750`), and those 256 lookups' interaction
    columns (≈512 of its 948).

  About **half its width serves one row in 96.** The roadmap saw the same in
  the interaction tree ("FULL-HEIGHT columns carrying fractions gated to
  1-in-96 rows", `P/docs/plans/roadmap.md:175`).
- **BLAKE2B_BOUNDARY (1,430)** is the same G-row layout without the memory
  binding (`blake2b/boundary.rs:222`); its row count is what costs the
  prover: 2^16–2^17 rows forced, **46.7% of all committed cells** at the
  (32,768, 8) cut and 31% at (131,072, 64) [measured from widths × log
  sizes].
- **MEMORY_PAGE (1,077):** one row per 128-byte block of a listed page, with
  the block's bytes before and after (256 columns), four 64-byte hash states
  (256), and 256 `MemoryAccess` lookups (128 boundary writes, 128 closing
  reads), which are its 520 interaction columns (`memory_page.rs:1-19,
  65-86`).
- **MEMORY_MERKLE (280):** two children before/after (128 bytes) and two
  64-byte states per merge row.
- **REGISTER_MEMORY (93):** narrow but tall (4 rows per step; 2^17 at 32k
  steps): 28 sortedness bits, timestamp and value limbs. 0.7% of the
  verifier, 6% of the prover's cells.
- **RISTRETTO (2,366) and the comb chips:** GF(2^255−19) arithmetic in 32
  byte limbs per element, with 64-limb product and carry vectors and 642
  `Range256` lookups per row (`chips/ristretto/mod.rs`); 16-row chips that
  are pure padding in a kernel.

## 2. A shape per kernel

### 2.1 What the window kernel uses [measured]

`s5-kernel-proof mask` (`SB/pvm/proof/src/lib.rs`, `program_component_mask`
and `trace_component_mask`):
- **trace mask `0x807cffff`, 22 chips; program mask the same.** Absent:
  POPCOUNT, BITCOUNT and the eight Ristretto chips.
- The program mask reads every instruction's opcode class from the code
  (any `ecalli` counts as BLAKE2b, the only call `derive` admits); it is
  witness-independent and so the one to pin.
- 7,519 columns (163 + 5,100 + 2,248 + 8): BLAKE2B 39.7%, the boundary
  group 38.0%, CPU 10.4%, the four ALU chips 7.5%, the rest 4.4%
  (`AR/shapes.txt`).
- A kernel that does not hash (a solvency predicate) would also drop
  BLAKE2B: 4,538 columns. The floor, the 16 always-active chips, is 3,957.

### 2.2 Is dropping them sound? Yes.

- **The production path already does it.** `prove` keeps only the chips a
  trace uses (`P/src/lib.rs:357-499`); the design rule is stated at `:347`:
  "Skipping a chip is safe iff all of its lookup producers and consumers
  have multiplicity 0 across the trace." Only `prove_canonical` forces all 32
  (`P/src/prove.rs:648-669`, mask at `:657`), so that one commitment covers
  any segment.
- **The verifier already accepts any mask** that holds the three
  boundary-binding chips and MEMORY_ROOT_BOUNDARY
  (`P/verifier/src/lib.rs:445-486`; `P/src/boundary_binding.rs:98-108`),
  draws lookup elements for the mask (`verifier/src/lib.rs:618`) and requires
  the claimed sums to total zero (`:619-625`).
- **Every relation balances on the remaining set:**
  - POPCOUNT and BITCOUNT are tables; CPU's requests to them carry
    multiplicities from opcode flags bound to `PROGRAM_MEMORY`. With no such
    opcode, the requests are zero.
  - The Ristretto chips' own relations (register file, comb, coordinate and
    scalar boundaries, compress output, fixed timestamps) touch only
    Ristretto chips and vanish with them. Their `MemoryAccess` and `Range256`
    entries vanish too.
  - CPU's `RistrettoCall` requests (5 per row) are gated by served calls
    110–114, which `derive` refuses in a kernel
    (`VC/pvm/compiler/src/derive.rs:630-641`).
- **A cheating prover gains nothing.** A row that needs a dropped chip
  emits a request no one answers, so the sum is non-zero and the verifier
  rejects. This rests on CPU's request multiplicities being constrained
  rather than free, the same property the production path relies on today.
- **Measured:** every kernel-shape proof in this audit (two channels, three
  configs, both cuts, and the 2-step shapes) proves and verifies natively
  and on the guest; tampered ones are refused (`AR/guest-real-*.log`).

**What a deployment must add:**
- **Pin the mask and the log sizes in the kernel id,** and refuse any other
  before verifying.
  - The preprocessed root binds the mask only through chips with
    preprocessed columns. This mask does change the root
    (`p2-j8-k-mob` against `p2-n1000000-j8`), but masks that differ in MUL,
    BITWISE, COMPARE, DIVREM or MEMORY would not.
  - It is not a soundness hole (any mask that verifies is a valid
    execution), but it is an identity and gas-DoS one: a full-mask proof of
    the same kernel costs 1.6× the gas.
- **Take the mask from the code,** not the run, so a path not taken
  (an error branch's DIVREM) is still covered.
- **CPU keeps its columns for every relation** (popcount, bitcount and
  Ristretto requests among its 180 interaction columns). A CPU specialised
  per kernel is a further, smaller lever.

### 2.3 Measured on real segments

The kernel harness (`SB/spikes/s5-kernel-proof/harness`, now with
`S5_MASK`, `S5_CONFIG`, `S5_SEGMENTS`) proved segment 6 of the 8-journal
window (32,768 steps, 84 kernel compressions, 378 boundary compressions) and
segment 1 of the (131,072, 64) cut (343 and 567), on both channels; the
guest verified them (`AR/real.log`, `AR/guest-real-*.log`):

| segment | config | p2 gas | b2s gas | p2 / b2s postcard | prover RSS p2 / b2s | prove p2 / b2s |
|---|---|---|---|---|---|---|
| 32k seg 6, full shape | MOBILE | 5.60B (spike 1, j1 seg 0) | 2.41B | 1.97 / 1.93 MB | 6.6 / 5.5 GiB | — |
| **32k seg 6, kernel shape** | MOBILE | **3.474B** | **1.520B** | 1.69 / 1.65 MB | 6.0 / 4.8 GiB | 23 / 5 s |
| 32k seg 6, kernel shape | 3:26 | **2.801B** | **1.298B** | 1.24 / 1.21 MB | 10.5 / 8.4 GiB | 39 / 7 s |
| 32k seg 6, kernel shape | STANDARD | **2.391B** | **1.167B** | 0.97 / 0.94 MB | 19.7 / 15.3 GiB | 72 / 12 s |
| 131k seg 1, kernel shape | MOBILE | **3.549B** | **1.545B** | 1.74 / 1.69 MB | 18.1 / 15.0 GiB | 69 / 16 s |

- **−38% gas (p2), −37% (b2s)** against the full shape; the model predicted
  −39%.
- **The floor before the first commitment check** fell from 0.79B to 0.51B
  (wrong-commitment runs, both channels); a tampered proof still burns 85%
  (p2) or 78% (b2s) of a full verify.
- Guest heap: peak live 6.2 MiB (was 10.7), 2,555 pages written.
- **Per window:** the 8-journal window is 16 segments at the 32k cut
  (≈55.6B p2 / 24.3B b2s at MOBILE) but 4 at the 131k cut (≈14.2B /
  6.2B): per-segment cost is flat in segment size, so larger segments are
  cheaper per step, bounded by prover memory (18 GiB at 131k on p2).

## 3. The levers stacked, one window-kernel segment, JAM-only host

Against the 100M target (≈200M masked) and a 1e9 package:

| step | p2 gas | b2s gas | proof (p2 / b2s) | vs 100M (best) | vs 1e9 | basis |
|---|---|---|---|---|---|---|
| as built: full shape, MOBILE, no leaf fix | 10.65B | 2.41B | 1.97 / 1.93 MB | 24× | 2.4× | measured, spike 1 |
| + leaf-hash fix | 5.60B | 2.41B | same | 24× | 2.4× | measured, spike 1 |
| + shape per kernel | 3.47B | 1.52B | 1.69 / 1.65 MB | 15× | 1.5× | measured |
| + blowup 8, 26 queries (masking (c)'s published setting, unmasked) | 2.80B | 1.30B | 1.24 / 1.21 MB | 13× | 1.3× | measured |
| or + STANDARD (16, 19) | 2.39B | **1.17B** | 0.97 / 0.94 MB | **11.7×** | **1.17×** | measured |
| masked, (c) at 8/26 (×1.37–1.40 over unmasked STANDARD, spike 2) | ≈3.3B | ≈1.6B | ≈1.3 MB | 8× the masked 200M | 1.6× | projected |

**The channel:** Blake2s verifies 2.0–2.3× cheaper than Poseidon2 at every
step. Per hashed field element on the PVM a Poseidon2 permutation (8
elements, ≈48.5k gas) costs 7.8× a Blake2s compression (16 elements, ≈12.4k
gas). The plan chose Poseidon2-M31 as the one published channel for
recursion (`VC/docs/design/slice-5-proving.md:264`); for a flat JAM verify it
is the wrong one.

**What the prover pays for the settings** (32k segment, kernel shape,
measured): RSS 6.0 → 10.5 → 19.7 GiB on p2 (MOBILE, 3:26, STANDARD) and
4.8 → 8.4 → 15.3 GiB on b2s. STANDARD fits the 24 GiB cap at the 32k cut
only. **Masking (c) at blowup 8 is ≈×1.56 the unmasked STANDARD memory**
(spike 2's ratio, measured against blowup 16 / 19 queries), so ≈31 GiB (p2)
and ≈24 GiB (b2s) for this segment [projected]: over the cap. 5.3 must
measure it; smaller segments or the narrow BLAKE2b chips (§3, below) would
bring it back.

**Further levers, projected with the per-column model** (STANDARD, real =
2-step × 1.035):

| lever | columns after | b2s | p2 | basis |
|---|---|---|---|---|
| kernel shape (measured) | 7,519 | 1.17B | 2.39B | measured |
| narrow BLAKE2b chips (per-compression I/O on its own row, word-level memory: BLAKE2B ≈2,981 → ≈1,050, BOUNDARY ≈1,430 → ≈1,150) | ≈5,300 | ≈0.87B | ≈1.78B | projected |
| + global memory (the narrowed boundary group, ≈2,580 columns, out; ≈60 in) | ≈2,800 | ≈0.53B | ≈1.07B | projected |
| + a 3× faster Poseidon2 permutation (78% of p2's instructions) | — | — | ≈0.51B | projected |
| + verifier without the per-proof `InfoEvaluator` pass and double component build (≈8%) | — | ≈0.49B | ≈0.47B | projected |
| masked (c), ×1.4 | — | ≈0.69B | ≈0.66B | projected |

Even stacked, ≈0.45–0.5B unmasked and ≈0.65–0.7B masked: **5–7× the
target, at most one segment per package.** The width-free part (0.14B at STANDARD b2s, mostly FRI with fold
step 1, which the format pins: `P/src/proof.rs:423`) alone exceeds 100M; a
larger fold step and last layer would cut it, but not to the width the target
needs. Flat verification of a VM segment is not a JAM venue.

## 4. The memory boundary

### 4.1 What it costs today

Per segment, every listed 4 KiB page is hashed twice in-AIR (entering and
exit image: 2 × 32 BLAKE2b compressions) plus its Merkle path share
(`P/src/chips/memory_page.rs:1-19`), and MEMORY gets 8,192 ledger rows per
listed page (4,096 `ts=0` writes and 4,096 closing reads), whatever bytes the
segment touched. Spike 3: 6,585 boundary compressions against the kernel's
685 at the 32k cut; 2,683 at the 131k cut.

| | (32,768, 8) | (131,072, 64) |
|---|---|---|
| BLAKE2B_BOUNDARY cells (rows forced × 1,430) | 93.7M of 200.7M (46.7%) | 187.4M of 602.1M (31.1%) |
| MEMORY rows that are page-boundary entries | 65,536 of 2^18 (25%) | 524,288 of 2^20 (50%) |
| boundary group columns (verifier) | 2,856 of 7,519 (38.0%) | same |
| boundary group proof bytes (kernel shape) | 40.3% of its own bytes, 35% of the proof | same |

### 4.2 The alternative: one memory argument across segments

How production systems do it [from memory]:
- **SP1** keeps per-shard memory consistent with local init/finalize
  events, and links shards through a global interaction: first a logup whose
  challenge is drawn after all shards' main traces are committed (two-phase
  proving), since v4 an elliptic-curve multiset hash over a septic extension,
  so shards prove independently and recursion sums the digests. The global
  init/finalize chips list each touched address once, sorted.
- **RISC Zero** pages per segment: page-in and page-out against a Merkle
  root of the memory image (Poseidon2 in v1, 1 KiB pages), which is VOS's
  design with a field-native hash and smaller pages. The brief's "as SP1 and
  RISC Zero do" holds for SP1 only.

**For VOS:**
- **The AIR:** delete BLAKE2B_BOUNDARY, MEMORY_PAGE, MEMORY_MERKLE and
  MEMORY_ROOT_BOUNDARY. Add a narrow MEMORY_GLOBAL chip: one row per touched
  byte (or word), with address, value, timestamp, and two or three lookups
  (local init/final into `MemoryAccess`, one into the global relation);
  ≈30–60 columns. MEMORY injects init/final entries for touched bytes only,
  not 8,192 per page.
- **The protocol:**
  - a cross-segment challenge (commit every segment's main trace, then draw
    it, which ends today's independent per-segment proving and streaming),
    or an elliptic-curve multiset hash over an M31 extension (new,
    soundness-critical arithmetic);
  - a chain-level check that the global sums and the public part of the
    initial image total zero;
  - the initial image: public data pages from the kernel id, private
    arguments as one commitment hashed once per chain;
  - the final image: only the output region, or the io-hash.
  - The `memory_root` link of `verify_chain_standalone`
    (`P/verifier/src/lib.rs:737-823`) and spike 2's salted-root plan are
    replaced by blinded global sums.

**What it saves [model, projected]:**
- **Verifier:** 7,519 → ≈4,720 columns; ≈−0.38B (b2s) / −0.78B (p2) at
  STANDARD; ≈−35% proof bytes.
- **Prover:** ≈49% of committed cells at the 32k cut (≈36% at 131k); the
  2,683–6,585 boundary compressions disappear. Prover memory and time fall
  about in proportion, so larger segments fit the same RAM.

**Effort:** ≈6–10 engineer-weeks plus a soundness review, re-pinning, and new
gates in place of `memory_merkle_gate`. It touches the chain format and the
masking design at once.

**A cheaper middle:** keep per-segment paging but hash pages with Poseidon2
in-AIR. One permutation is one ≈160-column row (Stwo's example: 16 × 9 + 14 =
158, `crates/examples/src/poseidon/mod.rs:38`), ≈150 per 4 KiB page, against
32 BLAKE2b compressions × 96 rows × 1,430 columns. That is ≈−1,100 verifier
columns and most of the boundary's prover cells, with chain linking by roots
unchanged. ≈3–5 weeks [projected].

## 5. The recursion route

### 5.1 What production systems do

- **StarkWare** (`starkware-libs/proving`) [read, through a delegated
  source read]:
  - **The circuit AIR:** 11 components, 319 columns (45 preprocessed, 114
    main, 152 interaction, 8 composition;
    `UP/crates/circuit_verifier/src/circuit_components.rs:47-59`). Its gates
    are QM31 ops, eq, triple_xor, m31_to_u32 and a Blake2s `G` per row, wired
    through a Gate relation whose addresses are preprocessed.
  - **The in-circuit verifier hashes Blake2s:** 80 G rows per compression,
    `UP/crates/circuits/src/blake.rs:308-328`.
  - **The inner Cairo AIR is about as wide as ours:** 79 components, 8,331
    columns (leaf set). Verifying it at 70 queries takes ≈53k compressions
    (2^23 G rows), the leaf hashes ≈70% of that.
  - **The tree:** proofs fold 2 to 1 (`circuit_multiverifier`,
    `stwo_run_and_prove_recursive_tree`), every node padded to one shape.
  - **The root proof:** 263,812 B in the privacy setting (blowup 4, 35
    queries; `UP/crates/privacy_circuit_verify/src/consts.rs:5-8`), ≈546 KB in
    production (blowup 2, 70 queries).
  - **The final verifier** is a Cairo verifier on Starknet; there is no
    SNARK wrap.
- **SP1** [from memory]:
  - RISC-V shards on BabyBear and Poseidon2;
  - a dedicated recursion VM (Poseidon2, extension-field ALU and FRI chips),
    not RISC-V;
  - compress (a reduction tree), shrink (one proof, different FRI shape),
    wrap into BN254 Poseidon2, then Groth16 (≈260 B) or PLONK.
- **RISC Zero** [from memory]:
  - segment receipts lifted, joined 2 to 1 and resolved by a recursion
    circuit (a small VM with Poseidon2 and field ops) into a ≈200 KB
    succinct receipt;
  - identity_p254 then Groth16, a 256-byte seal.
- **Plonky3:** the primitives, uni-stark and a Poseidon2 AIR
  (`plonky3-src/poseidon2-air`); recursion lives outside this repository
  (SP1 and OpenVM build their own).
- **The common lesson:** every one has a wide base AIR, and **none verifies
  base proofs on chain**. They recurse into a narrow, dedicated verifier
  AIR, then verify one small proof.

### 5.2 A dedicated recursion AIR for our segments [measured counts, projected sizes]

**The work of verifying one kernel-shape segment proof**, read off the
guest's profile (p2, MOBILE; `AR/profile-p2-kernel-mob.log`): 54,274
Poseidon2 permutations, 165,852 QM31 products plus `fri_answers`' ≈323k
multiply-adds (8,493 column-samples × 38 queries), and a 28k-product OODS
evaluation over 4,223 constraints. At blowup 8 and 26 queries, ≈37k
permutations.

**Its shape**, with a Poseidon2-M31 inner channel, which the plan already
chose for this:
- a Poseidon2 component at one permutation per row (≈160–300 columns,
  2^16 rows per inner proof);
- a QM31-ops component (≈20–30 columns with interaction, 2^19 rows; cf.
  StarkWare's qm31_ops, 12 + 8 + 8);
- Merkle-path and FRI-fold control, a wiring relation, and the inner AIR's
  OODS constraints as gates;
- ≈300–400 columns in all, about StarkWare's 319;
- ≈26M trace cells per verified inner proof, **≈13% of a 32k-segment's own
  200M cells** (≈4% at the 131k cut). A 2-to-1 tree adds ≈15–30% to total
  proving.
- **With a Blake2s inner channel** (StarkWare's choice), the same verify is
  ≈17k compressions × 80 G rows ≈ 141M cells, as much as proving the segment
  again. The Poseidon2-M31 channel is right for the inner proofs; only its
  software cost on the PVM is wrong.

**The final proof and its JAM verify [projected]:**
- the last layer switches to the Blake2s channel (as SP1 and RISC Zero
  switch hash at their last step), at a high blowup (log 5–6, 13–16 queries
  with 20–26 PoW bits) and a fold step above 1;
- with ≈400 columns, our model's per-column cost is ≈130k gas ≈ 50M, plus
  FRI and paths ≈30–60M, plus decode and OODS ≈10–20M;
- so **≈60–150M gas, once for N segments**, and ≈100–300 KB. The low end
  needs a lean verifier and fold step > 1; the high end is today's verifier
  code at fold step 1.
- A pairing-based wrap would not help on JAM: no pairing host call, so the
  pairing runs in software (unmeasured; likely ≥0.2B).

**Build effort:**
- **R1: StarkWare's circuit stack.**
  - Move to the `proving` monorepo (toolchain `nightly-2026-01-15`, API
    churn; spike 2 §1).
  - Write a Statement and a `CircuitEval` per chip for our 22–32 chips:
    generate the gates by driving each chip's `add_constraints` through a
    gate-recording `EvalAtRow`, which the existing `drive_chip_oods` seam
    allows (`P/src/framework_access.rs:90-100`).
  - Add a Poseidon2-M31 gate, or accept in-circuit Blake2s at ≈5× the
    recursion cost.
  - Port the guest verifier to the circuit AIR (spike 1's pattern).
  - **≈2–3 engineer-months** to a working tree.
- **R2: our own Poseidon2-M31 recursion AIR,** on the archived PCS plumbing
  (`voucher-recursion-archive`): **≈4–6 engineer-months**, more risk, no
  upstream dependency.

### 5.3 Why the earlier native recursion was the wrong tool

`P/docs/design/recursion-decision.md:22-29` measured a join at 600–750M
instructions with a 69 GiB wall, because it ran the verifier through the
general PVM AIR (in-AIR self-verify, or the verifier as a guest).
- **The arithmetic went through a RISC-V-like CPU.** This audit's guest
  spends 15,850 PVM steps per Poseidon2 permutation and 1.1–1.8B steps per
  segment verify (p2).
  - Each step is a 781-column CPU row plus ledger and register rows: a
    permutation costs ≈10^7 committed cells against one ≈160-column row in
    a Poseidon2 chip, about 5 orders of magnitude.
  - At ≤131,072 steps per segment, one verify is ≥8,000 segments, so
    K-splitting a join diverges, as recorded.
- **"Width wall regardless" does not follow.** In a dedicated AIR, the
  inner width costs a constant factor (columns × queries ÷ 8 permutations,
  plus one QM31 op per column-sample per query). StarkWare verifies an
  8,331-column AIR at 70 queries routinely.

## 6. The verdict

**Is the prover design appropriate?** For a prover, mostly yes:
- Stwo's circle STARK over M31, logup, canonical segment shapes and a
  Poseidon2-M31 channel are mainstream.
- 13k columns full, 7.5k for this kernel, is about Cairo's 8.3k for a
  64-bit VM in byte limbs.
- The ≈2 MB is columns × queries (78% queried values), as for any FRI proof
  of that width.

What is not appropriate:
1. **The venue assumption.** Base segment proofs verified directly by a PVM
   program. No production zkVM does this, and the measurements say why: the
   best flat setting measured is 1.17B a segment, and every projected lever
   stacked leaves ≈0.45–0.5B (≈0.65–0.7B masked).
2. **The full 32-chip shape on every segment:** 42% of the columns are
   Ristretto padding for a kernel that cannot call Ristretto.
3. **BLAKE2b chips that replicate per-compression I/O on all 96 rows:**
   about half their width.
4. **Whole-page BLAKE2b hashing at every segment boundary:** half the
   prover's cells at the production cut, 38% of the kernel shape's columns.
5. **An unoptimised verifier:**
   - a Poseidon2 permutation at 15,850 instructions;
   - the quadratic leaf copy (fixed on the spike branch);
   - the constraint-counting preflight;
   - components built twice.

**What to change first, in order:**

| step | cost | effort | basis |
|---|---|---|---|
| 1. Take the leaf fix (`2000c349`) and the shape per kernel (mask from code, pinned with log sizes in the kernel id; `d165a7b6` is the seam) | −47% then −38% verify gas; −14% bytes; −10% prover RSS | ≈1 week | measured |
| 2. Decide that JAM verifies only a recursion proof; peers verify segments until then | — | decision | spike 1 + this audit |
| 3. Narrow the two BLAKE2b chips (per-compression I/O on its own row, word-level memory) | ≈−2,200 columns; less prover memory; cheaper recursion | ≈3–5 weeks | projected |
| 4. A recursion layer: Poseidon2-M31 inner, Blake2s outer final, high-blowup last layer | ≈60–150M gas once per aggregate, ≈100–300 KB | ≈2–3 months (R1) / 4–6 (R2) | projected |
| 5. The memory boundary: Poseidon2 page hashing (cheap middle) or global memory (biggest prover win, a protocol change) | ≈−1,100 / ≈−2,800 columns; up to ≈−49% prover cells | ≈3–5 / 6–10 weeks | projected |

**The realistic path to verifying on JAM:**
- **Shape per kernel plus settings, flat:** measured 1.17–1.52B (b2s) or
  2.39–3.47B (p2) per segment unmasked, ≈1.6B masked. With every projected
  lever, ≈0.45–0.7B. That is months of work and never 100M: at most one
  segment per package, before any other work in it.
- **A recursion layer:** ≈60–150M gas for a whole window or more,
  independent of its segment count, plus ≈15–30% prover overhead with a
  Poseidon2 inner channel. That is ≈2–6 engineer-months. **This is the
  path.** Items 1 and 3 make it cheaper, because the recursion's cost per
  inner proof is the inner proof's columns × queries.

## 7. What was built, and how to reproduce it

**Commits on `spike/s5-guest-verify`** (local, not pushed):
- `f9f1c904`, `a3c49f4c`: spike 3's kernel spike and tracer fix,
  cherry-picked (the tracer's sparse-memory BLAKE2b serving is needed to
  trace the kernel here).
- `d165a7b6` `pvm/proof`:
  - `prove_canonical_masked`: a canonical shape over a component mask
    (`SB/pvm/proof/src/prove.rs`);
  - `program_component_mask` (`SB/pvm/proof/src/lib.rs`) and
    `trace_component_mask`;
  - `drive_chip_oods` now reaches BITWISE_AND_BYTE (it panicked on index
    31).
- `a6f6adbc` the spike:
  - the kernel harness's `width`, `shape`, `mask` commands and
    `S5_MASK`/`S5_CONFIG`/`S5_SEGMENTS` (`SB/spikes/s5-kernel-proof/harness/src/{width,main}.rs`);
  - masks in spike 1's prover (`SB/spikes/s5-guest-verify/prove/src/main.rs`);
  - the scripts and every log (`SB/spikes/s5-audit/`).

**Proof files:** `/home/daniel/.claude/jobs/8e1fc21e/tmp/s5/audit-proofs/`
(`p2/`, `b2s/` the 2-step shapes; `real/` the kernel-shape segments, each
with its commitment).

**Reproduce** (each under `systemd-run --user --scope -q -p MemoryMax=20G
-p MemorySwapMax=0 nice -n 10`):
```sh
# widths of any proof, or of a profile under a mask
spikes/s5-kernel-proof/harness/target-p2/release/s5-kernel-proof width <seg.postcard>...
spikes/s5-kernel-proof/harness/target/release/s5-kernel-proof shape <32 log sizes> <mask hex>
# a real segment under the kernel's mask and a config
S5_MASK=program S5_CONFIG=4:19:20 S5_SEGMENTS=6 \
  spikes/s5-kernel-proof/harness/target-p2/release/s5-kernel-proof prove <elf> <args> 32768 8 <out>
# the 2-step shapes
spikes/s5-guest-verify/prove/target/release/s5-guest-verify-prove <out> j1shape <32 log sizes> 2:38:20:807cffff ...
# the guest verify
spikes/s5-audit/scripts/guest.sh <p2|b2s> <proof.postcard>...
```
(The kernel's ELF and arguments are spike 3's, in `.worktrees/s5-spike3/spikes/s5-kernel-proof/{actor/target,data}`.)

## Caveats

- **The gas model** is spike 1's: vos-pvm's Gray Paper 0.8.0 instruction
  gas with PolkaJam's host-call prices. It is not PolkaJam's own refine
  gas.
- **STANDARD on a full-shape real segment** was not proved (prover
  memory). Its figure in spike 1 is a ratio; the kernel-shape STANDARD
  figures here are measured.
- **Masking** is spike 2's ratio on a 100-column toy AIR, applied to ours.
  The real factor needs 5.3.
- **The per-chip verifier shares** are the column-linear model, checked
  within 1% across four shapes. A zero-padded column costs the verifier the
  same as a full one; a column's bytes do not.
- **Projected levers** (narrow BLAKE2b, global memory, a faster
  permutation, the recursion AIR's width and final verify) are estimates
  from these measurements; none was built.
- **SP1 and RISC Zero details** are from memory; the StarkWare figures were
  read in source through a delegated read, with its file:line citations.
