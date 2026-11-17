# Proving: layers, formats and verifiers

How VOS proves a kernel's run and where the proofs are checked: the
segment proofs, the recursion that folds them, the masked final wrap, the
statement every venue judges, the venues, the roots they anchor, and the
proofs a phone makes. The recursion AIR's own design is
`recursion-air.md`.
- **Status:** [decided] marks a settled design choice; [built] what the
  code holds; [proposed] what is designed and open to review.
- **Evidence:** every number carries its tag: [measured, hardware, date],
  [model] (a count from the design's own cost model or the security tool),
  [derived], [est] or [projected]. "x86 dev machine" is the development
  desktop (Intel Core Ultra 7 155H); the phone is a Fairphone 6
  (Snapdragon 7s Gen 3: four Cortex-A720-class and four A520 cores). A
  [measured] number with no hardware or date ran on the x86 dev machine,
  on or before 2026-11-01.
- **Open work** is listed in `open.md`.

## 1. Requirements [decided]

- **STARKs only.** No trusted setup, and post-quantum readiness. No SNARK
  wrap at any layer.
- **One proof per statement.** A statement's segment proofs fold through
  a recursion layer into one final proof. That proof is verified by:
  - a peer;
  - a pallet on the Kreivo parachain, first;
  - a JAM statements service, a dedicated service whose refine verifies
    and whose accumulate records.
- **One shape for every final proof.** A general-purpose verifier checks
  any statement from any space. Public data travels as opaque bytes,
  which a handler for that program decodes after verification.
- **Privacy:**
  - node proofs stay inside the space's prover role until masked;
  - only masked final proofs leave it;
  - a device's proof leaves the device, so it is masked itself.
- **Fast mobile proving.** Recent flagship phones (about 2023 or later,
  under 3 GB of app memory) prove these in under a second:
  - authentication;
  - private payment authorization;
  - signatures, post-quantum first (§8).
- **Node proofs** may be slower, but stay reasonably fast up to the
  fold.

## 2. What the research found

- **Verifying a raw segment on JAM is not viable.**
  - A segment's AIR is wide: 26 chips and about 8,000 columns (§3.2).
    The page-Merkle boundary and BLAKE2b's chips are a large share of
    any shape that holds them.
  - Verify gas is linear in columns. The best measured segment verify
    is 1.17B gas, and every projected lever stacked still leaves
    0.45–0.7B.
- **A small final proof is cheap to verify.**
  - A proxy (320 columns, log 16, blowup 64, 13 queries, fold step 3, a
    2^6 last layer) measured 54.4M gas and 80 KB unmasked; about 66–76M
    and 102–112 KB masked [projected].
  - In a Wasm runtime it takes 23M instructions, about 1.7 ms. On Kreivo
    a proof is about 0.3% of a block's weight, and its bytes bind first.
- **Recursion works on StarkWare's design** [measured on their stack]:
  - one of our chips' constraints compiled to circuit gates automatically
    and verified in-circuit;
  - a 2-to-1 fold node took 10.5–18.7 s and 5.3–9.0 GiB.
  - Their stack's costs come from its Blake2s gates: folds at 1.4–2.1× a
    segment's proving, and a floor of 2^20 rows on every circuit (its XOR
    table).
  - Our own narrow recursion AIR (`recursion-air.md`) has 458 columns,
    built from counts measured on our chips. It verifies the window
    kernel's segment in 33.2M cells, **0.16× the segment's own proving**
    (0.054× at the 131k cut) [model]. Its fold converges at once.
  - A recursion AIR built wide, laying a child's columns out as columns,
    diverges: an earlier attempt grew 2.3× per level [measured].
- **Phones:**
  - the general zkVM's fixed floor is the page boundary: 91% of an empty
    kernel's cells [measured, x86];
  - a dedicated Poseidon2 circuit proved the authentication statements
    in tens of milliseconds on x86 [measured]; one proving path, the
    device profile, is kept instead (`light-node.md` §4.1);
  - signatures in software take minutes. With chips they are about
    8–10M cells [model].
  - The phone proves byte-identically to x86: the general zkVM's auth
    statement under the device profile in 645 ms, masked [measured,
    Fairphone 6, 2026-11-01] (§8).
- **The critique:**
  - Stwo is the right base;
  - our 96 bits are conjectured, and the proven figure is lower (§4
    counts both);
  - the PVM is wider than RV32 for a zkVM, and JAM alignment is the real
    gain;
  - P-256 and ed25519 inside a proof are not post-quantum.

## 3. The layers

```
segment proof ─ leaf ─┐
segment proof ─ leaf ─┼─ fold ─ … ─ fold (root) ─ final wrap (masked) ─▶ peers, Kreivo, JAM
segment proof ─ leaf ─┘
```

**Device proofs do not enter the fold in v1** [decided].
- A device proof is verified natively at the space's ingress. Its result
  is recorded as a fact in the space's state.
- A chain-bound statement is proved by the space's nodes over that state.
- Folding device proofs later needs the recursion AIR to verify masked
  proofs (salted leaves, the composition committed whole, the FRI mask,
  blinded sums), with its own gate.

### 3.1 The recursion AIR [decided: ours, on StarkWare's design]

**A narrow, gate-based recursion AIR on our pinned Stwo,** following
StarkWare's circuit architecture (Apache-2.0; pieces are adapted with
attribution). Its full design is `recursion-air.md`.
- **Three components, wired by one `Gate` relation** `(address, 4
  limbs)`, whose addresses and signed multiplicities are preprocessed:
  - `p2`: a Poseidon2-M31 permutation a row, with sponge and Merkle
    modes, 354 columns;
  - `qm31`: a linear-form QM31 gate with fused multiply-add, 41 columns;
  - `h8`: an accumulator over eight DEEP samples, 55 columns.
- **458 columns in all,** every constraint at degree ≤ 3 with paired
  logup [measured]. There are no lookup tables, so there is no row floor.
- **A circuit is its preprocessed wiring.** The circuit hash is the root
  of its preprocessed tree.
- **The in-AIR verifier**, built from those gates:
  - the Poseidon2-M31 channel;
  - Merkle paths;
  - FRI;
  - the OODS check through generated gates;
  - the logup sums.
- **It verifies our AIR's conventions natively:** a challenge pair per
  relation, next-row masks, and unpaired logup. Our base AIR changes
  nothing to be verified.
- **The gate compiler** turns each chip's `add_constraints` into gates
  through the recording evaluator. No constraint is written by hand.
  Equivalence tests check that constraint and gate agree on random
  points, chip by chip.
- **The fixed point:** a fold verifies two proofs of its own shape inside
  that same shape. Ours converges at once [model]:
  - a fold uses 47% / 32% / 5% of the padded shape (2^16 / 2^17 / 2^16
    rows), which the window kernel's leaf sets;
  - a child's columns become rows, never columns, so the verifier's width
    stays the gate set's 458. A wide AIR, laying a child's columns out
    as columns, diverges.
  - Measured on real proofs, it holds (§3.4).
- **Reused:** gate bodies from the `voucher-recursion-archive` tag (the
  Poseidon2 constraints, QM31 idioms, the FRI fold, Merkle and the
  channel), not its architecture.

### 3.2 Base proofs: node segments

- **Kernels on the chain path,** re-run from the `Attest` record.
- **A shape per kernel:** the component set from its code, and pinned
  log sizes per segment class.
- **The segment channel:** Poseidon2-M31, so the recursion verifies
  cheaply [decided].
- **The permutation is the reference Poseidon2 arrangement,** with
  Plonky3's width-16 M31 parameters (pinned at `f983316`), checked
  against their test vectors.
- **A SIMD hasher on the prover:** sixteen permutations a call, adapted
  from Plonky3's packed M31 Poseidon2 (AVX2, AVX-512 and NEON; MIT or
  Apache-2.0). The verifier keeps the scalar permutation.
  - 39.5M permutations a second on 8 threads (AVX2), against 7.05M
    scalar [measured].
- **Why Poseidon2-M31:** on a segment's total cost, its proving plus its
  leaf, against the Blake2s route's projection. Per segment at the 32k
  cut:
  - Poseidon2: about 5.6 s to prove [measured] plus a leaf of about
    1.5–3 s [projected];
  - Blake2s: about 3.1 s to prove [measured] plus a leaf with in-circuit
    Blake2s of about 4.5–6 s [projected]; the recursion AIR's shape and
    fixed point would also be re-derived.
  - The proving alone runs at 1.75–1.85× Blake2s, and a leaf's
    commitment (25M permutations) at 0.63 s [measured]. Poseidon2-M31
    wins on the total, which is what a statement pays.
- **The initial image is public** [decided]:
  - the kernel's arguments and witness rows enter through a
    **witness-input precompile**, not through the initial memory;
  - the agent serves the call live and records the bytes in the
    `Attest` (A.5); the tracer replays them, as free witness;
  - the first segment's initial memory root is the image root of code,
    data and zeroed regions. It is computable at install and is a field
    of the program id;
  - no root over private memory reaches a public input, so there is no
    salt page.
- **The precompile, `0x401`** (free in VOS's `0x400..=0x47f`):
  - **its registers:** φ7 the destination, φ8 the capacity. It writes
    `min(capacity, remaining)` bytes and returns the count in φ7; 0
    means the end of input. Reads are deterministic;
  - **its AIR binding:** the dispatch id is committed in PROGRAM_MEMORY,
    like `0x400`'s; it writes only `[φ7, φ7 + count)`, with the count at
    most φ8, and has no other effect;
  - the caller's arguments are capped by `Limits::attest` (64 KiB on VOS,
    2 KiB on JAM); a statement's served witness travels inline in the
    `Resume` input that answers the read, under `Limits::served` (128 KiB
    on VOS, 32 KiB on JAM) and the kernel's declared gas; 4 MiB stays the
    ceiling of the kernel's whole input;
  - `derive` admits the id, and a live≡traced test gates it.
- **Page permissions are preprocessed.** The program's layout is four
  regions of pages: two readable (the read-only data, the argument
  window) and two writable (the read-write data with its heap, the
  stack). Their bounds are MEMORY_PAGE's preprocessed columns
  (`pvm/proof/src/chips/memory_page.rs`), so the preprocessed root, and
  through it the program id, pins them: they are part of the program's
  identity. A write to a readable page, or a touch of an unmapped one,
  cannot be proved.
- **No gas in the AIR** [decided]. The AIR proves no gas accounting, and
  an out-of-gas exit is never proven: a proof states the run's steps, and
  gas stays the meter of the host that runs the kernel. The CPU's `Gas`
  column, which trace generation filled and no constraint read, is
  dropped rather than constrained, with the other columns and next-row
  masks no constraint reads: each cost every leaf its samples.
- **One chip set, two shapes** [decided]: the node's segments (format
  41) and the device profile (format 47, §8) share one chip set and one
  CPU, so a lever on the chips serves both; the node's shape takes a chip
  only while every kernel leaf still fits the fold's fixed padded shape
  (§3.4). The node's shape keeps the page-Merkle boundary, the device's
  replaces it (§8). What the set holds [built]:
  - **the Poseidon2 call, `0x402`** (dispatch 102, §8's `C`): `IsP2Ecall`
    a CPU column, the call's row handing `(ts, φ7, φ8)` to the Poseidon2
    chip (one permutation a row, its 64 input bytes read and 32 output
    bytes written through the memory ledger, each input word
    range-checked below p, so a call the live PVM traps has no proof), an
    optional chip at index 2 of the segment's 26 (`SEGMENT_CHIPS`). Node
    kernels may make the call; `derive` admits it in every kernel;
  - **the Poseidon2 chip's shape classes** [decided]: a kernel
    holding the chip takes (12, 8), (15, 8) and (12, 17), its third class
    at 17 pages, since at 24 its leaf passes 2^17 `qm31` rows beside
    BLAKE2b's chips; a kernel without the chip keeps 24 pages. One step
    touching more pages than its largest class (a witness-input read past
    about 64 KiB in one call) has no proof: the cutter cuts only between
    steps, `derive`'s and the kernel ABI's docs state the cap, and the
    prover refuses such a run (`SegmentError::Shape`);
  - **two cuts** [decided]: the seven `MemByteActiveMonoH` columns,
    which a constraint pinned to zero, dropped (the memory chip's
    monotonicity stated directly, degree 2); logical right shifts
    multiplied through MUL by `2^((width − n) mod width)`, taking the
    product's high word (its low word for a zero shift), so a kernel
    whose only division-like opcodes are logical shifts holds no DIVREM.
    The window kernel's cells fall 5.75% (8,001 → 7,600 columns), the
    auth device kernel's 7.3% [measured, x86 dev machine, 2026-10-31];
  - **the throughput:** the window statement proves end to end in 33.3 s
    on format 41 (3 segments 17.0 s, 3 leaves 5.7 s, 2 folds 3.5 s, the
    masked wrap 7.1 s) [measured, x86 dev machine, 2026-10-31].
- **Unmasked.** Segments never leave the prover role.

### 3.3 Leaf circuits

- **One leaf circuit per (kernel, segment class),** generated by the
  gate compiler.
- **The segment's preprocessed root is a constant of the leaf circuit.**
  The leaf circuit's hash therefore pins the kernel's code and shape.
- **A leaf verifies one segment proof** and outputs a digest whose
  preimage is in A.3. The preimage holds:
  - the program id, a witness the fold binds (§3.4);
  - the position range `(p, p)`;
  - the entry and exit state digests;
  - an entry flag;
  - a halt flag;
  - the io-hash, when halted;
  - the fold-circuit word W (§3.4).
- **A state digest** is the Poseidon2-M31 hash of, in order, the 13
  registers, pc, ts and the memory root, as bytes (A.3).
- **The entry flag holds** when the entry state equals leaf-circuit
  constants:
  - pc is the kernel's entry;
  - ts is 1, the first step's (0 is reserved for the initial memory);
  - the registers are the loader's image (φ0 the halt address, φ1 the
    stack top, φ7 the argument base), with φ8, the argument size, at 0,
    since arguments arrive through the precompile;
  - the memory root is the image root.
- **A flag is a bit the prover states,** and the leaf checks it implies its
  conditions (`flag·(w − k) = 0` a wire). A flag left at zero states
  nothing: the fold takes the entry flag from the left and the halt flag
  from the right, and the wrap refuses a root without both, so leaving one
  at zero only costs the prover its statement.
- **Every segment's initial ts is not zero,** as the native verifier
  refuses a segment starting at ts 0 (memory-boundary anchoring): one of
  the ts's two wires has an inverse.
- **The halt flag holds** when `pc_out` equals a leaf-circuit constant,
  `PVM_HALT_ADDR` (2^32 − 2^16, `pvm/runtime/src/lib.rs:88`): the return
  address the loader puts in φ0.
  - Today a halting step keeps `next_pc = pc` (CpuChip's halt
    selectors), so the new segment format sets it to that address. No
    code offset reaches it, so only a halt ends a segment there.
  - The io-hash is φ9..12's 32 bytes, as 16 limbs of 16 bits.
- **A leaf's size is the kernel's width times the queries, not the
  segment's length** [model]. Four times longer segments add 4% of rows,
  so longer segments make recursion cheaper per step.
  - **The shape per kernel is load-bearing.** At the segments' 40
    queries, a kernel-like shape fits the padded shape up to about 9,033
    columns (about 8,100 at 44 queries) [model]. The full chip set, about
    8,000 columns, fits inside it [model].
  - At derive time, each kernel's leaf rows are computed from its shape
    (`vos_pvm_compiler::leaf`: the chips' AIR as tables and the in-AIR
    verifier's structure, its DEEP plan among it, the built circuit's rows
    exactly, with an allowance for its constants). A kernel over the limit
    is refused, or waits for a format with a larger shape.
  - **Width is not the only term:** the chips at the largest log size are
    at the lifting height, where a two-sample column's periodicity sample
    falls on its second sample's point, so their samples leave DEEP's
    `h8` blocks for `qm31` rows of one sample. The window kernel's chips
    all at one size take 155.5k `qm31` rows, past 2^17 [measured]; its
    derived classes, with MEMORY alone the largest, take 102k.

### 3.4 Fold nodes

- **2 to 1.** A fold takes each child's output preimage as witness,
  hashes it in-circuit, and checks the result against the child's
  committed digest. Then it checks:
  - **the circuit:** every node's preimage carries one word W, the fold
    circuit's hash, because a circuit cannot hold its own hash as a
    constant. A leaf copies W from its witness. For each child, the
    fold requires that the child's recomputed circuit hash is one of
    the program id's leaf-circuit hashes or W, **and** that the child
    carries W. It copies W to its output;
  - **the program:** the program id's preimage is a fold witness, and
    the id is recomputed in-circuit; the leaf-circuit hashes above are
    that preimage's. Both children carry that id. A leaf's program id
    is a witness, so this is what binds it;
  - **adjacency:** `left.last + 1 == right.first`;
  - **continuity:** `left.exit_digest == right.entry_digest`;
  - **the ends:** the entry flag comes from the left, and the halt flag
    and io-hash from the right, each from its side alone. A fold states
    a run without an entry or a halt and refuses nothing for it: the
    flag stays zero, and the wrap refuses the root.
- **The wrap** checks the root's W against the true fold-circuit hash,
  its constant. Every fold below then carries that hash, so every fold
  child is a leaf of the program or a true fold. The wrap refuses a
  root without `first = 0`, the entry flag and the halt flag, so a
  prefix of a run, or a run started mid-way, cannot fold into a
  statement.
- **One padded shape for leaves and folds,** a format constant
  (`LEAF_FOLD_LOG_SIZES`): 2^16 / 2^17 / 2^16 rows. Every child a fold
  verifies has it, so one circuit verifies a leaf or a fold, and only the
  preprocessed root, a witness, tells them apart.
  - **The kernel leaf fits.** At 40 queries over the window kernel's
    shape, its leaf is 55,451 / 99,412 / 43,960 rows under format 41 (its
    logical right shifts multiply, so its shape holds no DIVREM)
    [measured], 15% of `p2` spare; every test actor's kernel's classes fit
    within 57,825 / 129,629 / 46,040 [model, the derivation's bound]. A
    kernel holding the Poseidon2 chip beside BLAKE2b's takes the chip's
    classes (§3.2; at 24 pages its leaf would pass 2^17 `qm31` rows, about
    135k): built, 59,105 / 99,904 / 47,920 at (15, 8) and 59,145 / 105,859
    / 47,240 at (12, 17) [measured], and every test actor's kernel, the
    chip added, within 63,637 / 111,167 / 51,520 [model]. Over the
    window kernel's 8,009-column shape before the two cuts, at 40 queries,
    its `p2` was 57,700 rows [measured]; at 44 queries it would have been
    about 64.8k, 1% spare [model], which is why segments take 40 queries
    with PoW 24 (§4).
  - **The levers,** if a count passes 2^16 (a wider kernel, or the next
    fix that widens the AIR): fewer queries with more PoW (a new segment
    format), FRI fold step 3 in inner proofs, or `p2` at 2^17 (+70%
    cells). The fold's shape is kept [decided]: changing it moves the
    fold-circuit hash and every venue's pinned wrap (§6). A per-program
    CPU (§9) narrows every leaf; a 4-way split of the CPU by opcode family
    would pass 2^16 `p2` rows on a kernel holding the Poseidon2 chip
    (66,254) [model].
  - A fold uses under half of the shape, so a child could grow by about
    3,200 columns before the fold outgrows it.
  - A kernel that does not fit is refused (§3.3).
- **Built** [measured, x86 dev machine, 2026-10-18; `vos-pvm-recair`'s
  `fold`]:
  - a child's verification is 16,065 / 21,394 / 2,024 rows (its lifting
    height 2^19, 17 FRI layers, 486 sampled values at 3 points), and the
    fold's own work 37 `p2` and 74 `qm31` rows: **32,167 / 42,896 /
    4,048** finalized, 49.1% / 32.7% / 6.2% of the padded shape, the
    model's 47% / 32% / 5%;
  - it proves in **1.5 s at 942 MiB** of heap, a leaf's time and memory,
    over the window kernel's leaves and over two folds;
  - the fixed point holds at once: a fold of two children of the padded
    shape fits the padded shape, and its rows do not depend on whether
    the children are leaves or folds.
- **Depth:** the root proof's shape does not depend on the tree's depth.
  Only proving time reveals the segment count, and statements are
  published at the window cadence.

### 3.5 The final wrap

- **One wrap per statement,** a 1-to-1 node over the root. Its tallest
  component is 2^15 rows [model].
- **Parameters** (format 39, masked under variant (c), A.4): blowup 32,
  24 queries, PoW 26, interaction PoW 8, fold step 3, a 2^6 last layer,
  and **affine DEEP batching** (an independent coefficient a sampled
  value). That is 146 conjectured and 82 proven bits (82.70; 80 needs 23
  queries) [model].
- **Why affine batching:** Stwo batches the sampled values by powers of one
  coefficient, and that term's error is the values' count times a
  proximity-gap error that grows with the blowup. Batched by powers, the
  masked wrap caps at 76.98 proven bits at blowup 32 and 74.48 at blowup
  64 however many queries are taken; only blowup 8, with 41 queries,
  reaches 80 [model].

  **Chosen: affine batching,** built in our fork for the configurations
  that ask for it (`PcsConfig::deep_batching`, its `DIVERGENCE-012`) and
  off by default, so no other format's proofs change. A proof does not
  carry its batching: a verifier takes it from the format. The security
  tool counts its batching term as `ε_lin(k)` (BCIKS20 Theorem 1.6), and
  its first FRI round as the fork folds it, by `2^fold_step` with the
  circle fold in it (`DIVERGENCE-011`).
- **The final channel** [decided]: Blake2b-256 Merkle trees and a
  Blake2b Fiat–Shamir transcript. This is new code in our Stwo fork.
  VOS's `0x400` serves a Blake2b compression and Kreivo's host
  `blake2_256` the whole-message hash; JAM serves no hash (Gray Paper
  0.8.0 has no hash host call), so a JAM verifier hashes in software. On
  Kreivo the host hash would shorten ref_time, but proof_size binds a
  block and length sets the fee.
- **Built, format 39** [measured, x86 dev machine, 2026-10-19 and
  2026-10-24], its proof decoded from a fixed layout
  (`vos_pvm_final_verifier::masked`), never postcard:
  - **the window kernel's wrap:** 148,868 bytes, proved in 7.44 s under
    load at a 3,627 MiB heap peak;
  - **on the JAM-only host** (`final-verify.elf`, Blake2b-256 in
    software, the guests' allocator a bump over its arena): the `valid`
    fixture's proof, 146,564 bytes in the fixtures of that measurement
    (A.6 gives the committed one's length), in 79.3M gas, the decode
    1.50M of it and the verify 77.8M; the JAM statements service's
    refine of one statement 79.4M;
  - **in Wasm** under the PVF's semantics: 44.9M instructions (the window
    kernel's proof), 46.4M of the 50M budget at the worst shape.
- **Levers:** the Blake2b hook is deferred, a lever for when ref_time
  binds: no venue verifies as a PVM guest on a VOS host, and Kreivo's
  binding limit is proof_size.
- **Fold step above 1:** the pinned Stwo implements it; our fork's review
  and tamper tests admitted it for the wrap's formats.
- **Its public inputs** are the program id (8 M31) and the io-hash (its
  32 bytes as 16 limbs of 16 bits): 24 words, at the wrap's reserved
  addresses 0–23 (A.3).

### 3.6 The statement, one format for every kernel

```rust
pub struct Statement {
    pub format: FormatVersion,       // the final format; the venue checks it is accepted
    pub program: ProgramId,          // a public input of the proof
    pub space: SpaceId,              // checked by the venue against every RootRead
    pub public_args: Vec<u8>,        // in order: the kernel's own leading fields, the reader
                                     // (AgentId, InstanceId) (`&self`), each #[public] argument
    pub output: Vec<u8>,             // opaque; the handler for `program` decodes it
    pub roots: Vec<RootRead>,        // { kind, space, window, root }
}
```

- **The io-hash** is `BLAKE2b-256(public_args ‖ output ‖ roots)`, in the
  canonical encoding: the domain `vos/io/v1`, then each field's SCALE
  encoding (a compact length and the bytes; a compact count and each
  `RootRead` as its kind byte, its space, its window as eight LE bytes and
  its root). The kernel computes it through the `0x400` precompile and
  writes it to φ9..12 at halt (`vos_pvm_precompiles::compute_io_hash`).
- **The venue recomputes the io-hash** from the statement's fields and
  compares it with the proof's public input. It never trusts a submitted
  hash.
- **The statement id** is
  `BLAKE2b-256("vos/statement/v1" ‖ program ‖ space ‖ io_hash)`.
  The venue computes it, and golden vectors pin it across Rust, Wasm and
  the PVM.
- **The id does not hash the format.** A venue accepts two final formats
  during a transition, and the program id does not move with the final
  format (it covers the segment format only): one run wrapped under each
  is one statement, which the venue's repeat check refuses the second
  time. An id that hashed the format would give the run an id per format,
  and a settlement would apply once under each. The format stays a
  checked field, as `space` is.
- **Who binds what:**
  - the proof binds `program` and `io_hash`, and through it
    `public_args`, `output` and `roots`;
  - the venue authenticates `format` (accepted), the roots (equal to
    anchored space roots, §7) and `space` (equal to every
    `RootRead.space`, at least one of them, never the zero id);
  - **only the kernel's code binds a `RootRead` to what the kernel
    verified against.** No layer checks that a stated root is the one
    the kernel's multiproof was checked against: the kernel writes its
    roots into the io-hash, and the program id pins that code. So
    admitting a program id is admitting an audit of that kernel: that it
    states the roots it verified, carries a nonce where its statements
    can repeat, and keeps its low-entropy fields salted, as SECURITY.md's
    "program intent" says of the base layer.
- **A venue judges rooted statements alone; a statement claiming a space
  must read a root of it.** Only a root binds the space: the proof states
  none, and the id hashes it. Were a statement's space free of its roots,
  one accepted proof would make a new id under each space and pass the
  repeat check again: a settlement applied twice. The venue refuses a
  statement of no root, or of the zero id (`SpaceId::NONE`), and one whose
  roots are not all its space's, as `Refusal::Space` (`0x4`).
- **A kernel that does not state its roots** carries what it read in its
  output, which no venue checks: its handler must. A `&self` kernel states
  its root: the window kernel reads its rows at one cut and states `S_w`,
  its public arguments the reader, the pair and the carried commitment
  `c_prev`, its output `(net, seq, c_new)` naming no anchor.
- **Repeats:** a venue refuses a statement id it has seen. A kernel whose
  legitimate statements can repeat carries a nonce in `public_args`.
  A venue keys on the statement id, never on the proof's bytes or their
  hash: many proofs state one statement.
- **The venue's check** (`vos_statement::judge`), in order: the format
  (one the venue accepts and the build links: 39); the statement's
  program against the venue's
  pins; the space, at least one root and every root the statement's; every
  root anchored (`vos_anchor::venue::anchored`: the space active at the
  venue, the root held at its window, not past `MaxRootAge`); the
  io-hash recomputed from the fields and the id from it; a repeat; then the
  final proof (at most 256 KiB, the format's own decode and nothing after
  it) against the pinned program id and the recomputed io-hash. **The
  program id is the venue's argument, never the caller's:** a venue that
  verified against the statement's or the proof's id would accept any
  kernel's proof. Each refusal has a class every venue reports alike
  (`Refusal::code`, the final verifier's `Error::code` under it).
- **`Seen` and time** (`vos_statement::seen_expiry`): a statement's entry
  may be dropped once its newest root is past `MaxRootAge`
  (`B_w + MaxRootAge`), since a replay then fails `0x5`.
- **Low-entropy fields:** anything in `output` or `public_args` derived
  from private data is a nullifier or a salted commitment, never a plain
  hash of a guessable value.
- **The program id** is a Poseidon2-M31 hash, so the fold can recompute
  it. It covers:
  - `TRANSPILER_VERSION`;
  - `ProgramHash`;
  - the shape (component set and classes);
  - the segment channel;
  - the preprocessed root;
  - the image root;
  - the leaf-circuit hashes.

  It hashes in two levels, so that one fold circuit recomputes every
  kernel's id: the kernel's digest over everything but the leaf circuits,
  a run whose length is the kernel's, then the id over a preimage of fixed
  length, 44 words: that digest, the leaf-circuit slot's version and
  count, and four hashes (the most classes a shape has), zeros past the
  count. A fold takes those 44 words as its witness.

  The prover role computes it from the install's record of the kernel (its
  hash, image root and shape, the shape's policy version among it,
  `vos_abi::records::Shape::POLICY`; the
  `Derivation`'s transpiler version), with each class's preprocessed root
  and leaf circuit: an install derives without the prover's stack. Venues
  store and compare it; they never compute it.
- **Who computes the id a venue pins:** it needs the recursion stack (a
  class's preprocessed root is a commitment to its trace at its sizes, and
  a leaf circuit's hash commits its padded wiring), so the prover role, or
  a build tool with that stack, computes it from the kernel and its install
  record. A venue takes the pinned id as governance input, set by whoever
  admits the kernel, and trusts it as such: anyone with the stack can
  recompute it and check the pin.
- **Formats are chosen at run time,** so a verifier accepts two during a
  transition: a proof's format number selects its channel and parameters
  from the registry (A.4). The statement id leaves the format out, so the
  transition is not a replay (above).
- **The crates,** under `pvm/proof/`:
  - `recair` (`vos-pvm-recair`): the recursion prover and its `Context`;
  - `recair-air` (`vos-pvm-recair-air`): the components' constraint bodies,
    no_std, with no prover dependency;
  - `final-verifier` (`vos-pvm-final-verifier`): no_std, for x86, wasm32
    and riscv64em-vos (the PVM target);
  - `anchor` (`vos-anchor`): `SpaceId` and the genesis it hashes, the
    window clock, root kinds, anchors, and the digests a venue checks
    signatures over (the space root, the anchor, the registration, a JAM
    venue's id), no_std, with BLAKE2b its one dependency, and the golden
    vectors every venue computes alike;
  - `statement` (`vos-statement`): the types, the encoding, the io-hash
    and the id, and the venue's check over `vos-pvm-final-verifier`, with no
    other vos dependency than `vos-anchor`, which it re-exports, so Kreivo
    can depend on it; its `model` is a venue as plain data, which the
    fixtures are judged against, and its JAM refine program
    (`final-verify.elf`) the harness's on the JAM-only host, which judges
    the fixtures and accepts nothing without a proof. It is not deployed
    as a venue; the JAM venue is the statements service;
  - `statement/service` (`vos-statement-service`): the JAM statements
    service (§6), its refine and accumulate over `vos-statement`, built
    as a JAM program (`statement-service.elf`);
  - the device profile (§8): `vos-pvm-device` (the device program
    from a kernel or its release, its verifier and pre-check, `H_io` of a
    claim, and its `masked` module, the masked device segment);
    `vos-pvm-proof`'s `device` (the shape) and `masked` (the masked
    segment chips);
  - `device` (`vos-light`, `node/light`): the device library (§8), `std`,
    which the `vos.credential` facility (`node/light/android`, a `cdylib`
    s4's Android client loads) links;
  - the golden fixtures, under `fixtures` (A.6).

  Every venue uses `final-verifier`, `anchor` and `statement`. The source
  uses no nightly feature: it builds on stable for x86 and wasm32, and the
  JAM build runs on the pinned nightly with build-std.

## 4. Security levels [proposed]

**Soundness only has to hold until a proof is verified; hiding has to
last for decades.**

- **The basis:**
  - **"Conjectured" bits** are PoW + queries × log₂ blowup: the ethSTARK
    up-to-capacity conjecture. It was refuted as stated in 2025
    (Diamond–Gruen; Crites–Stewart). The salvaged fixed-rate form costs
    3–15% more queries, and the parameters below carry at least 5% of
    that margin.
  - **"Proven" bits** are the Johnson-bound count, including the DEEP,
    ALI and logup error terms. One tool computes both counts for a
    shape; the format tests pin its output, and the verifier checks
    both.
  - Grover halves the search against a quantum prover. That is a
    heuristic, not a theorem.
- **What 60 proven bits buy:** about 2^60 hash evaluations. Inner proofs
  sit at that floor, and the final proof at 80.

| proof | target | example | conjectured / proven |
|---|---|---|---|
| segment proofs (format 41) | ≥ 100 / ≥ 60 | blowup 4 (log 2), 40 queries, PoW 24, plus interaction PoW 8; FRI fold step 1, log last-layer degree bound 0 | 104 / 62 (62.81) |
| leaf and fold proofs (32) | ≥ 100 / ≥ 60 | blowup 4, 44 queries, PoW 20, plus interaction PoW 8; fold step 1, last layer 2^0 | 108 / 63 |
| device proofs (47; verified at ingress, never folded) | ≥ 100 / ≥ 60, with 2 bits of margin, counted on the masked shape | blowup 4, 47 queries, PoW 16, interaction PoW 8; variant (c), `h = 256` (§8, "The device parameters") | 110 / 62 (62.82, each) |
| the final wrap, masked (39) | ≥ 100 / ≥ 80 | blowup 32 (log 5), 24 queries, PoW 26, plus interaction PoW 8; fold step 3, last layer 2^6; affine DEEP batching (§3.5); variant (c) | 146 / 82 (82.70) |

- **The counts** are the security tool's (`pvm/proof/src/security.rs`) at
  each format's reference shape [model], pinned by the format tests.
- **The numbers:** 41 and 47 name the segment AIR's current form, the
  chip set the node's segments and the device shape share (§3.2), 47 with
  the device's per-program CPU cut and word ledger (§8); the default
  prover produces 41. A number names one AIR and one set of
  parameters; the registry refuses every other (A.4).
- **The inner grind:** a segment's PoW 24 costs 0.43 s on average on 8
  threads (median 0.26 s, 95th percentile 1.44 s), against 0.028 s at 20
  [measured, x86 dev machine, 128 grinds each, SIMD]; interaction PoW 8
  is negligible.
  Leaves and folds keep PoW 20, and their 44 queries make a fold about 13%
  dearer than 39 would [model]. The inner proven count is set by the query
  term.
- **Why segments take 40 queries:** a kernel leaf's `p2` rows grow with the
  segment's width times its queries. At 44 over the window kernel's 8,009
  columns the leaf needs 64,717 of `p2`'s 65,536 rows; at 40, 59,300, 9.5%
  to spare [model, `recursion-air.md`, Appendix: the verifier cost
  model]. PoW 24 keeps the proven count, 62.86
  against 62.74 at 44 queries and PoW 20, where the batching term binds.
  Counted on format 41's own reference (every chip at 2^20 rows, the
  Poseidon2 chip among them; 11,091 sampled values, 5,750 constraints): 40
  queries and PoW 24 count 62.81 proven bits, so they stand.
- **Devices:** §8, "The device parameters".

- **Inner soundness carries through:** forging a fold's input forges the
  final proof. **The system's proven bound is therefore the weakest inner
  format's, 62.81 bits (format 41), not the wrap's 82.6;** its conjectured
  bound is 104. Under Grover's heuristic that is about 31 proven and 52
  conjectured bits against a quantum prover, so post-quantum readiness
  rests on the conjectured count. All counts are the security tool's own
  [model], pinned by tests and not yet reviewed outside.
- **Salts:** 8 M31 (248 bits).
- **Interaction PoW** applies to every proof with logup, folds included.
- **An external audit,** before value rides on a proof, of:
  - the in-AIR verifier;
  - the fold node;
  - the gate compiler (constraint ≡ gate);
  - the claimed-sum handling;
  - the masking, and the public-sum re-cut;
  - the masked wrap's transcript and R1–R4 (§5), and the lifted protocol
    under (c);
  - the base segment AIR's parts without forgery gates: PROGRAM_MEMORY's
    decode binding, JUMP_TABLE, the lookup tables, MEMORY_PAGE and
    MEMORY_MERKLE, the witness-input chip, the boundary-binding argument;
  - the fork's divergences (below);
  - the security tool's counts (`security.rs`);
  - the leaf's binding, the wrap, `vos-pvm-final-verifier` and
    `vos-statement`, and `derive` with the program id's derivation;
  - the mobile proofs: the masked chips
    (the blinding joined to each chip's last batch, the public sums); the
    device shape (its four chips in place of the page boundary, the
    first-touch and permission rules), the Poseidon2 chip on both shapes,
    `H_io`'s binding argument and the `h = 256` argument (§5); the
    logical right shift through MUL.

  Its engagement is open (`open.md`). No value rides on a proof before
  it.
- **The Stwo fork, as pinned** [built]: olanod/stwo at `e14925a8`, a chain
  of branches, each a divergence from upstream with its own tests:
  - `vos/wrap` (`ab294189`): the Blake2b-256 channel (§3.5), FRI fold
    step above 1 with the first round folding by `2^fold_step`
    (DIVERGENCE-011), affine DEEP batching opt-in per format
    (DIVERGENCE-012), and the completeness backport;
  - `vos/verify-panics` (`c3ec9813`): the DEEP quotient's degenerate
    lines refused as `InvalidStructure`, not asserted (DIVERGENCE-013),
    for the verifier's panic-freedom (§6);
  - `vos/grind-chunks` (`4cd1f83f`): the prover's parallel PoW grind in
    chunks of 2^14 nonces, the smallest nonce kept, so its nonce is
    the same at every thread count;
  - `vos/simd-m31-reduce` (`9e9b4ff6`): the SIMD backend's reduction of a
    Blake2s-M31 digest word below p made canonical over the whole `u32`
    range, as the verifier reduces it; without it, about one honest
    masked Blake2s-M31 proof in 30,000 fails its Merkle check [measured];
  - `vos/neon-compress16` (`e14925a8`): Blake2s's 16-lane compression
    run as four NEON groups of four on aarch64, its words unchanged:
    ×1.27 a compression on the phone's prime core, ×1.76 on a little
    core, about 3–4% of a device proof [measured].

  `pvm/proof/SECURITY.md` keeps the open items' detail (011–013).

## 5. Masking [built: formats 39 and 47]

- **Where:** the final wrap (39) and device proofs (47): the masking is generic over the component set and the
  channel. The device's chips mask (`vos_pvm_proof::masked`): each chip's
  blinding fraction joins its last batch of fractions, so masking adds no
  column and no degree to any chip; the claimed sum the public values fix
  (DeviceIoChip's) stays unblinded; the fixed tables pad by
  repeating their entries with no multiplicity; every chip pads to four
  times its `h`. The device shape proves them masked against its program
  (`vos_pvm_device::masked`): the program's chips mixed after the
  header, its log sizes pinned, the io-hash the one public sum. Node
  segment, leaf and fold proofs stay unmasked, in the prover role, as the
  witness rows do.
- **Its cost on the segment chips** [measured, the auth statement on
  x86, quiet]: ×2.14–2.19 in time and ×2.1–2.2 in peak memory on the
  floor and lean shapes (×2.45 and ×2.11 on the built shape) against the
  same shape unmasked; the proof ×1.12–1.30 [measured, under load]: every column at `2N`,
  the composition at `4N` and every tree lifted one level more. 36 cubic
  gates (the CPU's 34, the memory ledger's 2) keep the composition at
  `4N`; rewriting them would save about 20–30% of the masked time [est],
  an AIR change not made.
- **Device proofs (rate 1/4)** serve authorizations a
  space re-checks at its ingress, never settlement.
- **How:** variant (c) (each column randomized off its domain, below),
  under eight requirements, R1–R8, as the code names them
  (`vos_pvm_recair::masked`):
  1. the rank check; the prover retries on R1's failure, a public event
     that leaks nothing;
  2. claimed sums blinded: one blinding QM31 a component on one row,
     through a `BlindRelation` drawn after `Gate`; the wrap's public sum
     is the 24 words and `u`, so its boundary re-cut is trivial;
  3. the FRI mask's rank: under affine batching each of R's columns gets
     its own QM31 coefficient, so a 4-column R is singular about 2^-31 an
     attempt; R takes 8 columns, whose coefficients span M31^4 except
     with probability about 2^-155, with no prover check (the rank test
     runs on a small circuit only);
  4. hedged randomness: each attempt's stream seeded with
     `BLAKE2b-256("vos/mask/seed/v1" ‖ 32 OS bytes ‖ witness digest ‖
     attempt)`, the witness digest binding the statement and the main
     columns (`MaskRng`; a seeded stream only on the tests' dev edge,
     `seeded-masks`, which no production build enables);
  5. a degree audit (the recursion AIR's gates stay at degree ≤ 3 with
     paired logup, so (c) applies);
  6. parameters pinned in the format;
  7. every carrier audited (A.5);
  8. the cost measured (§3.5).
- **How large `h` must be** [decided]:
  - **What a column reveals.** A masked column is `f' = f + v_H·r`, `r`
    uniform over the `h` coefficients of the size-`h` circle FFT basis,
    one `r` a column, drawn independently. Every published value that
    depends on `r` is `f'` at a point off `H` (where `v_H ≠ 0`), so an
    M31-affine function `f(p) + L_p(r)`:
    - each out-of-domain sample, a QM31 value: **4** M31 functionals, for
      each of the column's `|O|` offsets;
    - each decommitted query: **1**, `f'` at the query lifted to the
      column's domain;
    - the composition's opening at each query: **`|O|`**, `f'` at the
      query lifted to the composition's level and shifted by each offset.
      The composition sits one level above the masked columns, so these
      reads are other points than the decommitted one. Only the
      composition's value, a function of every column's reads, is
      published, so counting each column's own is an over-count.
    - Nothing else: the DEEP quotients at the queries are computed from
      these; the claimed sums are blinded by R2; an unopened leaf's hash
      is hidden by its salt; the preprocessed columns are public.
    - **The composition's sample at `π(z)`:** its 4 coordinate columns
      `C_k` are each sampled at `w = π(z)`, 16 M31 values against the one
      QM31 value `C(w)`. They are determined all the same: the `C_k(w)`
      follow from `C(σⁱw)`, `i = 0..3`, `σ` QM31's Frobenius over M31
      (its Galois conjugates), and each `C(σⁱw)` is computable from the
      columns' samples conjugated, since `f'`, `π` and the offsets' shifts
      are over M31 and the composition's only QM31 inputs (its
      coefficient `α`, the relation challenges, the blinded sums) are
      public.
    - **Conditional on R3:** FRI's siblings, inner layers and last layer
      are hidden by `R`, uniform in the FRI code, whose rank is asserted
      by construction, with no check (`masked/mod.rs`'s R3): 8 columns of
      `2^{m+2}` coefficients each, at least 8·2^12 = 32,768 M31
      coefficients for the smallest device shape, against about 10³
      functionals FRI reveals at 47 queries. The `h` argument here
      covers the columns' randomizers alone, and holds with R3.
  - **The count**, per column of offsets `O`, at `q` queries:
    `4|O| + q(|O| + 1)` rows, fewer when points coincide (two queries
    lifted to one point of a small component's domain, a read on a
    decommitted point), never more. R1 builds exactly these rows from
    the transcript (`rank::revealed_functionals`).
  - **The condition.** If a column's rows are linearly independent over
    M31, the map `r ↦ (L_p(r))_p` is onto, so for uniform `r` the
    revealed values are uniform and independent of `f`; the columns'
    `r` are independent, so the joint view is too. With R2, R3 and the
    salts, the simulator samples the transcript from the public values
    alone. Independence needs `rows ≤ h`, so **`h` must be at least the
    largest column's count**, and R1 checks independence itself on every
    transcript; `h ≤ N/4` keeps (c)'s composition bound.
  - **The margin is not the argument.** `h` at twice the count (Plonky3's
    hiding PCS takes `2(q + 4·points)` for a scheme with no check of its
    own) makes a rank deficiency rarer; here R1 is checked exactly and a
    deficient transcript is drawn again with fresh masks. Whether R1
    passes is a function of the format, the shape, `z` and the query
    positions: Fiat–Shamir outputs on salted, masked commitments, which
    in the random-oracle model are uniform and independent of the
    witness. Conditioning on it, and the count of attempts, reveal
    nothing. The margin buys only fewer retries, which cost time
    (`MAX_ATTEMPTS`, 8, then the prover fails without a proof).
  - **The device shape at 47 queries** (the device parameters; the auth
    kernel's program at `h = 256`; each chip's widest offsets read off the
    built device set's mask points): every chip reads its previous row,
    the logup running sum's `[-1, 0]` at least, and none a third row, so
    the widest `|O|` is 2 in every chip and each of its masked columns,
    main, interaction and blinding, reveals at most `4·2 + 47·3 = 149`
    rows:

    Measured on the auth program at the device parameters over the byte
    ledger and the full CPU (format 46, since retired), before the two cuts
    (§3.2), which drop DIVREM from it, the count unchanged; the word
    ledger and the CPU cut change the log sizes, not `|O|`:

    | chips | log size at `h = 256` (at 512) | `|O|` | rows at most | `h` | spare | `h / rows` |
    |---|---|---|---|---|---|---|
    | MEMORY | 14 (14) | 2 | 8 + 47 + 94 = 149 | 256 | 107 | 1.72 |
    | PROGRAM_MEMORY, the data table | 13 (13) | 2 | 149 | 256 | 107 | 1.72 |
    | REGISTER_MEMORY | 12 (12) | 2 | 149 | 256 | 107 | 1.72 |
    | CPU, WITNESS_INPUT, the device memory | 11 (11) | 2 | 149 | 256 | 107 | 1.72 |
    | Poseidon2, the device boundary, DeviceIoChip, JUMP_TABLE, RANGE_MULTIPLICITY_256, BITWISE_LOOKUP, POWER_OF_TWO, BYTE_TO_BITS, MUL, BITWISE, COMPARE, DIVREM | **10** (11) | 2 | 149 | 256 | 107 | 1.72 |

    The count does not depend on the log size: a small chip's points
    coincide more often, so its transcript's count is at most 149. At
    the floor, 2^10 rows, `h = N/4` exactly. **`h = 256` meets the
    condition for every chip, with 107 rows spare (×1.72)**; R1 measured
    149 on the auth kernel's transcripts at `h = 256` and accepted each at
    its first attempt [measured]; a leakage gate at `h = 256` (128 proofs,
    121,099 hypotheses) refused none [measured]. A column of one offset would reveal
    `4 + 2·47 = 98`. The rule's other limits: `h = 512` at 47
    queries kept ×2 (298); `h = 256` keeps ×2 up to 40 queries, and
    holds the condition up to 82 (`8 + 3q ≤ 256`).
  - **What would break it:** more offsets (`|O| = 3`: 200 rows, still
    under 256; `|O| = 4`: 251; `|O| = 5`: 302, over) or more queries. R1
    refuses a transcript whose rows pass `h` (`n_rows ≤ h` before the
    rank), so a shape that broke it would fail to prove (after
    `MAX_ATTEMPTS` refused transcripts), never prove leaky; the device
    install refuses such a format before any proof (`device_floors`).
    `mask_rows` sizes each chip's `h` from its own offsets only below the
    format's cap: at format 47 every device chip reaches the cap, 256.
- **The composition mode:** a test pins that (c) lifts no constraint past
  the blowup. If it did, the prover would re-LDE every column.
- **On the wrap:** no re-LDE [measured]; the prover ×2.6–2.9 in time
  (the lifting rises to 22, and Blake2b Merkle hashing of the doubled
  leaf layer dominates), ×1.41 in memory; verify ×1.20, bytes ×1.31
  [measured, x86 dev machine, at blowup 64].
- **Leaks:**
  - proving time (mitigated by publishing at the window cadence);
  - the public fields the kernel declares.

## 6. Verifiers [proposed]

- **Peers:** native, on the same crate.
- **Kreivo, a general-purpose pallet** [decided], `pallet-spaces`
  (`spaces-pallet.md`, its handoff design):
  - **Registries:**
    - spaces: a space registered from its genesis, with a **sovereign
      account** that holds the registration deposit and pays its
      authorities' fees and deposits; an **authorities map** of the
      nodes' own sr25519 accounts, each paired with its ed25519 anchor
      key, set by the controller (an `AccountId`); a space anchors from
      the venue's next window at its registration, and an equivocation
      ends it for good, its record kept as a tombstone;
    - anchors keyed by `(space, kind, window)`; `MaxRootAge` (24 h) is
      the only age;
    - formats and programs: governance, with a delay.
  - **Fees:** `submit` takes a refundable deposit, released on acceptance
    or a repeat, forfeited on any other refusal; normal length and weight
    fees, paid by the sovereign account through `ChargeSpaceFee` within a
    spend budget per window. A proof's length counts as proof_size, so
    about 20 statements fit a block on one core.
  - **The Kreivo client** (`vos_kreivo::KreivoVenue`, in `tools/kreivo`,
    which no node links): the representative and the worker would anchor
    and submit through it, a
    `VenueClient`, the space's sovereign account paying. It reaches the
    chain by message through a `Transport`; VOS tests it against a
    reference mock of the designed pallet and the conformance vectors
    (`tools/kreivo/conformance`), which the teammate's pallet must pass.
    The chain transport (on sube, signing with the node's sr25519
    authority key) is a port of the substrate extension VOS's master held
    at `d2378274c` (`extensions/substrate`, removed from master with the
    change that lands `pvm/` alone) onto the node's extension host: VOS's work once that host exists. The pallet is
    the teammate's. Until both exist, no node reaches Kreivo
    (`spaces-pallet.md` §9.1; `open.md`).
  - The weights and benchmarks are the teammate's.
  - **`submit(statement, proof)`, checked in this order:**
    1. the size cap;
    2. a strict decode;
    3. the format is accepted and the program is registered;
    4. the roots are anchored and `space` matches;
    5. the io-hash, recomputed;
    6. the statement id is unseen;
    7. the STARK;
    8. dispatch to the handler compiled into the runtime for that
       program.

    Steps 1–7 but the statement's own decode are `vos_statement::judge`,
    the program's pinned id passed in from the registry.
    The pallet caps the extrinsic's length itself (step 1): `judge`
    applies its 256 KiB cap at the proof's decode, after the cheap checks.
    The statement's words are an input to the verifier, never an output.
  - **Panic-free by construction:** a FRAME runtime cannot catch a panic
    (no unwinding on wasm32 without std; a panic aborts the block's
    import), so no guard can wrap the decode and the verifier. The final
    verifier and the statement code must not panic on any input: the
    shape and sample checks (`check_shape`, `samples_fit`) refuse
    before Stwo reaches its indexing and `unwrap`s, and the statement's
    decode bounds every count by the bytes left. The final verifier,
    `vos-statement` and `vos-anchor` deny `unwrap`, `expect`, indexing,
    `panic` and unchecked arithmetic outside their tests; every such site
    on the fork's verify path at the pin is listed with its guard
    (`SECURITY.md`, § Panic-freedom); the fuzz targets (`pvm/proof/fuzz`)
    run in CI.
  - **Every re-pin is a governance event at every venue:** a segment
    format bump (any base-AIR hardening) changes every program id, and a
    change to `recair`'s compiler or gate set changes every leaf-circuit
    hash, `H_fold` and the pinned wrap root. That is the price of the next
    soundness fix.
  - **The anchor table is keyed by root kind too:** `Venue::anchored`
    compares the whole `RootRead`, kind among it.
  - **Fail-closed:** a runtime without the verifier rejects every proof,
    and a failed submit pays its full weight.
  - **Built-in handlers:** `Record`; a `Credential` handler once a
    cross-space credential exists (the in-space credential is verified at
    its own space's ingress, §8, and reaches no venue); the Clerk's
    settlement handler with the Clerk. Every
    value-moving handler is two-sided or spends the submitting space's
    own escrow. No handler runs a STARK in `validate`.
  - **Its home:** `pallet-spaces`, in Kreivo, built by the Kreivo teammate
    from `spaces-pallet.md`, to replace pallet-communities later; the
    verifier stack vendored into Kreivo with a sync check against a VOS
    tag (VOS's kit, `pvm/proof/kit`); frame-contrib and crates.io later.
- **The JAM statements service** (`vos-statement-service`): a dedicated
  service; refine verifies anchors' signatures and statements (79.4M gas
  a statement [measured]; a report's accumulate has 10M); accumulate
  holds the spaces,
  anchors and repeats, and records, checking an anchor's signer against
  the space's registered keys, through the venue rules
  (`vos_anchor::venue`) as Kreivo's pallet does; accepted program ids are constants
  changed by redeploy; a statement rides in its `Submit` item's payload
  and its proof as the item's extrinsic, since JAM-NP's CE 133 bounds the
  package at 204,802 bytes. An actor in the default agent cannot host
  it: `MAX_HANDLER_GAS` 100M, a 512 KiB program cap, 2 KiB messages, no
  preimage access.
- **The JAM client is development tooling** [decided]: VOS ships the
  statements service and the agent-as-JAM-service build (`vos-jam`); it
  deploys on JAM with JAM's own tooling. The PolkaJam JSON-RPC and `jamt`
  driver, the service's client and `JamVenue` live in `tools/jam-dev`
  (`vos-jam-dev`), which serves the end-to-end tests and the testnets;
  neither `vos` nor `vos-node` depends on it, nor on anything under
  `tools/` (`just check-no-tools`).
  A node reaches JAM later through an extension running a light node.
- **Venues in the node:** a space anchors and submits at one venue, through
  a `VenueClient` (`vos-venue`: the trait, `ModelVenue`, the `AnchorQueue`
  that sends anchors until the venue answers, and `KreivoVenue`). The
  representative's leader signs and anchors each window some agent
  reported; the prover worker (`vos-node-prover`), on the leader of the
  agent whose record it is, proves each statement at an anchored cut,
  records the proof's hash in the agent (`Input::Proven`) and submits it
  once its roots are anchored, a repeat counted as accepted. Its records
  are the agent's state: every replica's apply keeps each attest at a cut
  (`keys::attested`) with its witness until its window's roots age, so a
  replica that installs a snapshot and then leads holds every statement
  still to prove, and proves again one whose proof went with the old leader
  (an accepted one too: no replica learns of an acceptance; the witnesses
  kept are up to `MaxRootAge` of the agent's reads). The prover is built
  into the node and stays there [decided]: proving is essential to VOS, not
  an add-on; the extension host that will carry the venues' transports
  comes later (`open.md`). The worker proves statements at an anchored cut
  alone (an attest with a window), the only statements a venue judges.

## 7. Roots and anchors [proposed]

The anchoring protocol keeps as few states as it can: its state machine
had grown hard to reason about, so equivocation is terminal, a node has
one key, a space never migrates, a read is never re-cut, nothing is
handed back, and an agent reports only for windows a read waits on; each
removes a state, at the cost named where it is stated (§11).

- **The kernel verifies its rows up to the space root.** Its witness
  carries the full path: row → map root → agent root → space root. So
  `RootRead.root` is the anchored space root, which the venue compares.
  The path costs 14 compressions (one more for `S_w`) and 590 B at 1,024
  agents, a row 19.07 compressions and 842 B [measured].
- **A chain-bound statement reads at the space's last anchored window
  cut.** A statement that stays inside the space keeps "as of the latest
  complete root W ≤ V".
- **Windows** [decided] are Unix time from the space's genesis,
  `w = ⌊(t − origin)/length⌋`, the clock frozen in the genesis; the length
  per space in [2, 60] minutes, default 10.
- **Time between parties is the venue's** [decided]: every expiry,
  timeout or exposure deadline between parties uses the venue's chain
  time, never a window number or the space's clock; the space's clock
  schedules only its own cuts, and a venue anchors only windows closed by
  its own clock (`w < now_w`).
- **Latency:** authorization across spaces is instant (the counterparty
  credits within its exposure cap); trustless settlement takes about
  `L/2 + D + t_prove + inclusion`, about 10 minutes on average at L = 10;
  parallel proving is the lever below that.
- **Each space root commits to `(space_id, window)`,** and each
  `RootRead` carries both.
- **`SpaceId`** [decided] is the genesis hash,
  `BLAKE2b-256("vos/space/id" ‖ SCALE(genesis))`; the window clock is
  frozen in the genesis.
- **The space root** [decided] is built by the space's representative
  agent: `S_w = BLAKE2b-256("vos/space/v1" ‖ space ‖ w ‖ A_rep)`, `A_rep`
  the representative's agent root at its own cut of w, over its rows
  `(agent, kind, w) → the agent's root at cut(w)`. An agent cuts, and
  reports its root, only at a window a read of it waits on, or at every
  window when it reports every one (an issuer,
  `Admin::ReportEveryWindow`), so `S_w` covers the agents that reported
  w; a window no agent reported is not anchored.
- **Anchors** [decided] are signed by one registered node key, a node's key
  set once when the controller lists it, with no rotation: a compromised
  key means replacing the node. The representative's close of each window
  writes `S_w` in a row, the same bytes on every replica; its leader signs
  only those rows, never a root of a batch under proposal, in window order,
  and offers each again until the venue holds it or never takes it. The
  venue's client answers one of five outcomes (taken, not yet, never,
  unlisted, stopped); unlisted, the leader hands its leadership to a
  replica whose key the venue lists, at most once a window. Nothing is
  handed back.
- **The venue rules** [decided] are written once, in `vos_anchor::venue`,
  and every venue calls them: the registration, the anchor rule,
  `anchored` and a root's freshness (`spaces-pallet.md` §6.1–§6.3).
- **Equivocation** [decided]: a second root at a fresh window held is
  evidence and ends the space for good: its status `Ended`, its
  roots refused from then on (`0x5`), no resume; the record is a
  tombstone the venue never prunes, so its registration replayed is
  refused; the registration deposit is released and the controller can
  still move the sovereign's funds. The space founds again under a new
  genesis. An honest node raises it: the representative's leader, finding
  the venue holding another root at a window whose row it holds, sends
  its anchor as the evidence once its divergence guard passes: a quorum
  of the replicas holds the same row, any dissenting replica alerted
  by name with its root; without a quorum nothing is sent. A second root at a
  window past `MaxRootAge` is refused as aged, never evidence
  (`spaces-pallet.md` §6.1, vector G5).
- **Known limits:** any single founding key registers the
  space at a venue it has not reached, under a controller of its choosing,
  and so squats it there (`spaces-pallet.md` §6.2); and nothing ties a
  space to one venue but its own discipline: a founder may register the
  same genesis at two venues. Anchoring the same roots at both, a
  statement is accepted, and handled, at both; anchoring different roots,
  the space forks unseen, since equivocation is caught per venue (an
  anchor gives no integrity).
- **Retention:** none past a cut. A request made in window w reads at
  `cut(w)` and is served there once the representative closes w, or
  fails `NotClosed` at `B_{w+2}`; the caller asks again; no re-cut
  is made.
- **Spans** [decided]: a statement over a span of windows takes a carried
  commitment to its last settled state as a `#[public]` argument, not an
  old root; no tree history is kept.
- **An anchor gives ordering and non-equivocation, not integrity:** a
  space can anchor any root of its own making, so every value-moving
  handler is two-sided or spends the submitting space's own escrow.
- **One venue, no migration** [decided]: a space anchors at one
  venue for good, from the venue's next window at its registration; a
  space that changes venue founds again under a new genesis. With every
  statement rooted, a statement is accepted only where its space's roots
  are anchored, which is where the space registered (the known limit
  above).
- **Root kinds:**
  - Committed rows sit first in the keyspace, under `0x03`, so an
    agent's root is the same on both hosts: VOS's tree per agent equals
    JAM's node at `0x03` [decided]. `RootKind { Space = 0 }`; 1 is
    reserved for a Poseidon2 kind, which the cross-space credential will
    take (§8). The in-space credential's tree needs none: it lives in its
    actor's rows, and only its space's ingress reads it.

## 8. Mobile [built: the device profile and the stock kernels]

Device-held secrets with hash credentials come first; standard
signatures need chips and come after (part 3). Every device statement is
a device kernel proved under the device profile (format 47): the stock
`auth` and `owner` kernels, and any actor's own (`light-node.md` §4). The
phone's budgets for a statement under the device profile: at most 1.0 s,
1 GiB of peak resident memory and a 1.5 MiB proof, verified on the phone
and accepted at a space's ingress, its verify at ingress at most 40 ms on
one x86 core. All are met (below).

**1. The credential values and the stock kernels** [built]. The stock
kernels prove facts about a device secret `s`, and a space's ingress
verifies them. This section pins what they hash, the tree they read and
the secret's derivation; the actor keeping the tree, the request,
ingress's checks and the origins are `identity-and-authority.md` §5–§7.

**The hash is one function,** Poseidon2-M31's compression `C(l, r)`: the
first 8 words of the width-16 permutation (4 + 4 full rounds, 14 partial,
`vos-pvm-poseidon2`'s constants) of `l ‖ r`, each half 8 words, with no
feed-forward. The `0x402` host call computes exactly `C`, so the
actor's tree, the node and the phone agree word for word.
- **A digest** is 8 M31 words. Its bytes are the words as little-endian
  `u32`s, 32 bytes; a decode refuses a word ≥ p.
- **A tag** `T(name)` is the 8-word block `[t, 0, 0, 0, 0, 0, 0, 0]`, where
  `t` is `u32_le(BLAKE2b-256("vos/p2/" ‖ name)[0..4]) & 0x7fff_ffff`,
  reduced mod p. The names are `member`, `owner`, `leaf`, `nf`, `scope`
  and `binding`; a test pins the six `t` distinct and nonzero.
- **The words of 32 bytes** `W(d)`: word `i` is
  `u32_le(d[4i..4i+4]) & 0x7fff_ffff`, reduced mod p (`2^31 − 1` becomes
  0). Eight words, 248 bits.

**What is stored, logged and proven** (each `C` is one permutation):

| value | definition | where it lives |
|---|---|---|
| `member(s)` | `C(T(member), s)` | the credential actor's tree, under a leaf |
| `owner(s)` | `C(T(owner), s)` | a ledger row's owner |
| `leaf(m)` | `C(T(leaf), m)` | the tree, at the member's slot |
| a node | `C(left, right)` | the tree |
| `scope` | `C(T(scope), W(BLAKE2b-256("vos/cred/scope/v1" ‖ space ‖ agent ‖ instance ‖ name)))` | computed by ingress from the method's guard |
| `nullifier` | `C(C(T(nf), s), scope)` | auth's claim field; the logged pseudonym |
| `binding` | `C(T(binding), W(b))`, `b` the call's binding digest | every claim's last field |

`s` is 8 words (below). In the scope's preimage `space` is the `SpaceId`'s
32 bytes, `agent` the `AgentId` and `instance` the `InstanceId` as 4
little-endian bytes each, `name` the guard's scope name (1–64 bytes) in
SCALE (a `u32` little-endian length, then the bytes, as the codec
writes them). `b` is
`identity-and-authority.md` §5's binding digest.
- **No epoch in `member`:** a revocation removes
  the leaf, and a new secret source is a new `s` and a new leaf.
- **The nullifier** is `scope` keyed by `C(T(nf), s)`, a value only the
  holder of `s` computes: two scopes' nullifiers are unlinkable, and
  neither links to `member` or `owner`. In one scope it is stable: a
  pseudonym, not a one-time token (`identity-and-authority.md` §5).
- **The leaf does not hash its slot:** the position is the path's. A
  32-bit slot would not fit one M31 word, and its bits recomposed mod p
  would alias.

**The tree** (`identity-and-authority.md` §6): a positional sparse Merkle
tree of depth 32 over `C`. Slot `i` (a `u32`) holds `leaf(member)`, or the
empty leaf `E_0`, eight zero words; node `i` at level `l` is
`C(child 2i, child 2i + 1)` of level `l − 1`, level 0 the leaves; the empty
subtree at level `l` is `E_l = C(E_{l−1}, E_{l−1})`, a constant. A path is
the 32 siblings from level 0 up; bit `l` of the slot, least significant
first, is 1 when the level-`l` node is a right child. No leaf equals
`E_0` but with a preimage of `C`, so an empty slot proves nothing. An
enrollment costs 33 calls of `C`, the leaf and 32 levels; a revocation 32.

**The stock kernels** (the credential actor's `auth` and `owner`, written
with the SDK, `vos_sdk::p2`; `light-node.md` §4.2): each claim is SCALE
words of 32 bytes, the call's `binding` last, which the kernel carries
without reading; the claims carry no kind byte, the guard naming the
kernel.
- **Auth:** the claim `AuthClaim { map_root, scope, nullifier, binding }`
  (128 bytes). Its arguments, read in place: the path's 32 siblings from
  the leaf's level up and its slot (eight little-endian bytes), the
  secret's 32 bytes, then the claim. It computes `m = C(T(member), s)` and
  `C(T(leaf), m)`, walks the path with one select a level on the slot's
  bit (branch-free, so the trace's shape never depends on the witness),
  asserts the top equals `map_root`, and asserts
  `C(C(T(nf), s), scope) = nullifier`.
- **Owner:** the claim `OwnerClaim { owner, binding }` (64 bytes); its
  arguments the secret, then the claim. Asserts `C(T(owner), s) = owner`.
  No path, no balance and no range check: the payer is public
  [decided]: pay proves knowing `s` behind an account's owner digest,
  bound to the call. The ledger debits the account the digest holds at
  apply, so a former owner's proof pays from nothing once the account is
  rekeyed.
  Revocation does not stop payment; the ledger's `rekey(account, owner)`
  and `freeze(account)`, under an operator role, do [decided].
- **The claim binds the proof:** ingress computes `H_io` of the claim
  (no output, no roots) and verifies the proof against it, so a proof
  verifies under its own claim alone. Neither `scope` nor `binding` is
  computed from its BLAKE2b preimage in the kernel: ingress computes both
  from the guard and the request. `scope` is the second input of the
  nullifier's outer compression, so the kernel hashes it; `binding` is
  read by no instruction, bound through the io-hash.
- **The program id** of each is its device program's (below, *The device
  program*), from the credential actor's release; the binding names it,
  so a proof under one kernel authorizes nothing under another.
- **Their cost** is the device profile's (below) and `light-node.md`
  §4.4's: on the phone a sign-in in about 0.6 s, a proof of about 0.88 MB.

**The device secret, from a secret source** [decided]:
- **The source** is an HMAC-SHA-256 under a key the device never
  exports, evaluated once a use after the user's consent: by default an
  Android Keystore HMAC key (user authentication at every use, by a
  biometric or the PIN through `BiometricPrompt`; StrongBox-backed when
  present; Android 11 or later); optionally a security key's
  `hmac-secret` by CTAP2 directly through YubiKit, always with user
  verification (its PIN) and a touch: CTAP2 keeps a credential's
  `hmac-secret` key apart with and without user verification, so a use
  without the PIN would derive another `s`. One credential serves every
  handle (the salt varies), made under one pinned `rpId` constant,
  `"vos.device"`, a CTAP2 string and not a WebAuthn relying party. No
  passkeys, Credential Manager or Play services; a source that spans
  devices is later work. The device keeps the source's reference (the
  Keystore alias, or the security key's credential id).
- **The input:** `input = SHA-256("vos/device/input/v1" ‖ handle)`
  [decided], the message the source's HMAC takes (a security key's
  salt as it is: no WebAuthn client prefixes it). `handle` is the space's
  stable 32-byte handle (`identity-and-authority.md` §6), not its
  `SpaceId`, so a member's secret survives a re-founding (an equivocation
  ends a space for good, §7).
- **The derivation:** `o` the source's 32-byte output;
  `w = BLAKE2b-512("vos/device/secret/v1" ‖ handle ‖ o)`;
  `s_i = u64_le(w[8i..8i+8]) mod p` for `i < 8` (a bias below 2^-33 a
  word). It is derived again at each use, from a fresh evaluation, and
  never stored.
- **One source, many spaces:** spaces with different handles get
  unrelated secrets. Two that share a handle share `s`, so their `member`
  and `owner` digests are equal; their scopes carry the `SpaceId`, so
  their nullifiers are not. The client shows the handle and pins it at
  the first enrollment.
- **What `s` is exposed to** is `identity-and-authority.md` §7's threat
  model.

**The device library** (`vos-light`, `std`, aarch64 and x86_64; linked
as a Rust crate by s4's Android client, a Rust `cdylib`, so VOS has no JNI
shim of its own; built for `aarch64-linux-android` with `cargo-ndk`
against the client's NDK; mimalloc, no other C dependency). Neither the
client nor a gateway encodes a proven call's bytes: the library builds
every request and decodes every answer it needs.

```rust
pub struct Digest(pub [u32; 8]);                  // each word below p
pub struct DeviceSecret(/* [M31; 8]; zeroized on drop, no Clone, no Debug */);

pub fn source_input(handle: &[u8; 32]) -> [u8; 32];
pub fn derive_secret(source_output: &[u8; 32], handle: &[u8; 32]) -> DeviceSecret;
pub fn member(secret: &DeviceSecret) -> Digest;
pub fn owner(secret: &DeviceSecret) -> Digest;

/// The call a proof authorizes; `new` draws the nonce from the OS.
pub struct Call {
    pub space: [u8; 32], pub agent: u32, pub instance: u32, pub method: u32,
    pub arguments: Vec<u8>, pub nonce: [u8; 16], pub expires_ms: u64,
}
pub struct AuthWitness { pub root: Digest, pub slot: u32, pub siblings: [Digest; 32] }
/// A proven call's proof: the device format, the kernel's claim, the bytes.
pub struct Proven { pub format: u32, pub claim: Vec<u8>, pub proof: Vec<u8> }

pub struct ProverConfig { pub threads: Threads, pub max_memory: u64 }
pub enum Threads { Auto, Count(usize), Cores(Vec<usize>) }
pub struct Prover { /* the thread pool, the masks' source */ }
impl Prover {
    pub fn new(config: ProverConfig) -> Result<Self, DeviceError>;
    /// The stock auth kernel; `name` is the guard's scope name, the scope,
    /// the nullifier and the binding computed here.
    pub fn prove_auth(&self, s: &DeviceSecret, witness: &AuthWitness, name: &[u8],
                      call: &Call, program: &DeviceProgram) -> Result<Proven, DeviceError>;
    /// The stock owner kernel.
    pub fn prove_owner(&self, s: &DeviceSecret, call: &Call, program: &DeviceProgram)
                       -> Result<Proven, DeviceError>;
    /// A device kernel's run on `arguments`, under the device format.
    pub fn prove_kernel(&self, program: &DeviceProgram, arguments: &[u8])
                        -> Result<DeviceProof, DeviceError>;
}
/// Ingress's checks that need no clock or state; `name` an auth guard's.
pub fn verify(proof: &Proven, call: &Call, program: &DeviceProgram, name: Option<&[u8]>)
              -> Result<(), DeviceError>;
pub fn claim_io(claim: &[u8]) -> Option<[u8; 32]>;

/// A device kernel's program, from its release artifact, as every node
/// computes it: `vos_pvm_device::Program`, re-exported.
pub use vos_pvm_device::Program as DeviceProgram;
impl Program {
    pub fn from_release(release: &Release) -> Result<Self, vos_pvm_device::Error>;  // no run
    pub fn id(&self) -> &DeviceProgramId;
}

// The wire (identity-and-authority.md §5–§6): node-API requests, each its
// kind and SCALE body (the transport adds the length and any request id).
// `agent` addresses the request; `identity` is the agent's 32-byte
// identity, which a query's key signs over.
pub fn time_request() -> Vec<u8>;                                    // Time
pub fn time_answer(body: &[u8]) -> Result<u64, DeviceError>;
/// A `QueryCall` of `feed(from)`, signed by a fresh key: it names no member.
pub fn feed_query(agent: u32, identity: &[u8; 32], instance: u32,
                  from: u64, not_after: u64) -> Result<Vec<u8>, DeviceError>;
pub fn feed_answer(body: &[u8]) -> Result<Feed, DeviceError>;
/// The request, addressed to `call.agent`.
pub fn credentialed(call: &Call, proof: &Proven) -> Vec<u8>;

/// The whole tree, kept from the feed on a jittered timer, each page
/// checked against the root its last change names; the member's path computed here.
pub struct TreeKeeper { /* the tree's nodes, the feed's place, the root, the timer */ }
impl TreeKeeper {
    pub fn new(member: Digest) -> Self;
    pub fn request(&self, agent: u32, identity: &[u8; 32], instance: u32,
                   not_after: u64) -> Result<Vec<u8>, DeviceError>;
    pub fn due(&self, now_ms: u64) -> bool;
    pub fn ingest(&mut self, answer: &[u8], now_ms: u64) -> Result<Synced, DeviceError>;
    pub fn witness(&self) -> Option<AuthWitness>;
    pub fn unknown(&mut self, now_ms: u64);
    pub fn encode(&self) -> Vec<u8>;
    pub fn restore(member: Digest, kept: &[u8]) -> Result<Self, DeviceError>;
}
```
- **`prove_auth` checks its witness first:** the leaf of `member(s)` under
  `root` by the path, else `DeviceError::Witness` before any proving;
  every stock proof is checked to state its claim's io-hash before it is
  returned.
- **`DeviceError`** names what failed and carries no value.
- **`Threads::Auto`** [built]: the cores the thread may
  run on, grouped by the rate the system states for each (its capacity,
  else its highest clock), each class's rate measured on one of its cores;
  the work goes to the fastest classes whose count times the slowest kept
  rate is greatest, one thread pinned to each of their cores (every core
  unpinned when every class is kept). On the Fairphone 6 it keeps the
  four big cores, pinned: the same four unpinned are ×1.20 slower, the
  split over all eight ×1.3 [measured, Fairphone 6, 2026-10-31]. The pool's stacks are 16 MiB
  (`STACK_BYTES`): a nested join overflowed rayon's default 2 MiB.
- **`feed_query` signs with a key drawn for that query alone,** so a
  read links to no client key; a proof uses the path `TreeKeeper`
  computes, and no read precedes it.
- **No logging of witnesses,** and no `seeded-masks` feature in a
  production build (`just check-no-seeded-masks`). The client's bridge zero-fills its `byte[]` of `o` once
  the library has copied it; the library zeroizes its copies of `o` and
  `s`, and a kernel's arguments once its run is proved.
- **Built** (`node/light`, its `SECURITY.md`): as sketched; the masks
  always the operating system's, a `seeded-masks` test seam
  (`Prover::seeded`) for the phone bench's byte comparison alone;
  `Call::new` and `feed_query` answering `Result` (the operating
  system's randomness may fail); `TreeKeeper::unknown` for a
  `RootUnknown` or `RootStale` answer, with
  `wire::credentialed_answer` (the node's `Response` decoded exactly, a
  refusal as `vos_wire`'s `CredentialRefusal`, `Expiry`'s `now` kept);
  the request is `vos_wire`'s `Credentialed` under `Kind::Credentialed`,
  the scope, the claims and the binding `vos_wire`'s
  (`credentials::scope`, `AuthClaim`, `OwnerClaim`, `Bound::digest`), so
  the library and ingress share one computation. The keeper's timer is
  30 s with a uniform jitter of half a period either way, halved on each
  `RootUnknown` (to 1 s) and doubled back on a read that finds the tree
  unchanged. `Prover::new` refuses an allowance below `PEAK_BYTES`, 1 GiB,
  the device budget, above the stock auth kernel's peak of 0.70 GiB on
  the phone.

**No Poseidon2 root kind for the in-space credential** [decided]: the
credential tree lives in the actor's own rows,
hashed through `0x402`, and no venue checks a Poseidon2 root. `RootKind`
1 stays reserved for the cross-space credential, which will prove its
root's place under `S_w` by a BLAKE2b path outside the proof, its issuer
reporting every window (§7).
- **The zkPVM has a Poseidon2 chip** [built] (§3.2): one permutation a
  row, the S-boxes as the recursion AIR's `p2` (284 columns, degree 3);
  with its 96 byte accesses through the memory ledger and its range
  checks, about 1,060 columns a row once its single-denominator fractions
  are paired. At its floor of 2^10 rows a device kernel's 43 calls cost
  the chip's floor, not its calls.
- **The host serves Poseidon2 natively** [built], at 3,000 gas a
  call: one compression takes 1,925 cycles natively against BLAKE2b's
  about 410 (×4.7) [measured, x86 dev machine (Intel Core Ultra 7 155H),
  2026-11-12], about 2,800 at BLAKE2b's gas a cycle, and 3,000 is the
  round price above it with headroom [decided]. A JAM-deployed agent pays it in software, about 37,600 gas a
  permutation [measured, 2026-10-26], as it does BLAKE2b.

**2. The device profile** [built: `vos_pvm_proof::device`,
`vos_pvm_device`]. The general zkVM runs on
phones, for any device kernel. It proves one segment with no page-Merkle
boundary, over the shared chip set (§3.2), its CPU cut to the columns the
program's code sets (`CpuColumns::of_code`), and chips of its own: the
word ledger (`src/chips/word_memory/`: WordMemoryChip in the memory chip's
place, a row an 8-byte word an access touches; DeviceWordMemoryChip, a
word's first touch with its region's permission and its closing read;
DataWordTableChip, the program's data a word a row), DeviceBoundaryChip
(the registers' entry as the program's constants and their halt blinded)
and DeviceIoChip (φ9..12 to the io-hash), binding the run like this:
- **code:** program memory, preprocessed;
- **first touches** (`ts = 0` ledger entries), by address region:
  - the data region: a preprocessed data table;
  - stack and heap: zero;
  - anywhere else: refused (the live PVM traps there);
- **arguments:** the witness-input precompile;
- **read-only pages:** a preprocessed permission table per region refuses
  writes;
- **output:** the io-hash only: the entry (timestamp 1, pc 0, the
  layout's registers) and the halt's pc are the program's constants, every
  other register at the halt hidden, φ9..12 bound to the public io-hash by
  one public claimed sum (DeviceIoChip's); a device kernel's io-hash is
  `H_io` below, over Poseidon2, not BLAKE2b;
- **masking:** a floor of rows per masked component, set by the queries:
  the randomizer covers the rows a column reveals, `4|O| + q(|O| + 1)`
  for `|O|` offsets a column (§5, how large `h` must be), rounded to a
  power of two `h`, and a component has at least `4h` rows. The device
  format takes the rows themselves, 149 at blowup 4 with 47 queries, so `h =
  256` and a floor of 2^10 rows [decided]; `device_floors` refuses at
  install a format whose `h` is below a chip's revealed rows. A component
  with no next-row read (`|O| = 1`) would need less, so `h` is set per
  component (at most the format's); every segment chip reads its running
  sum's previous row, so each takes the full `h` [built]. Taking `h` at
  the rows rather than twice them cost nothing in bits and took ×0.82 the
  time and ×0.87 the peak on the phone [measured, Fairphone 6,
  2026-10-31].

**The device io-hash `H_io`** [built]. A device
kernel's io-hash is over `C`, not `compute_io_hash`'s BLAKE2b-256: with
BLAKE2b's, BLAKE2b (3,136 columns) and its AND table stayed in every
device shape, the Poseidon2 statement's too, 48% of its columns, and the
Merkle hashing and the proof's bytes go with the columns [measured,
2026-10-30]. A
kernel that hashes only through `0x402` reaches neither: on the phone
its proof took ×0.40 the time, ×0.39 the peak and ×0.54 the bytes of the
same statement under BLAKE2b's io-hash [measured, Fairphone 6,
2026-10-31].
- **The bytes:** `E`, exactly what `compute_io_hash` hashes after its
  domain: `compact(|a|) ‖ a ‖ compact(|o|) ‖ o ‖ compact(|R|)`, then each
  root read's kind byte, space, window (8 bytes little-endian) and root;
  `a` the public arguments, `o` the output, `R` the roots. A device kernel
  reads no root, so its `E` ends with the count 0, and `E` is what it
  returns at its halt (read back by `KernelReturn::from_device_return`;
  not `KernelReturn`'s own codec, whose lengths are four bytes).
- **The bound:** `ℓ = |E| < 2^24`. `compute_device_io_hash` returns
  `Option<[u8; 32]>`: `None` for a longer `E`, never a wrapped or
  truncated hash; ingress refuses such a request, and the kernel's end
  traps. That trap comes after the method ran, with no diagnostic of its
  own (a trap like any other). The bound never binds a real return: a
  kernel's `E` lies in its heap (512 KiB) and a work result holds 4 MiB.
  2^24 rather than `p` (any `ℓ < p` is a distinct field element, all the
  binding needs) keeps the length block's word below 2^24 like every data
  word.
- **The words:** `E` zero-padded to `n = ⌈ℓ / 24⌉` blocks of 24 bytes;
  block `i`'s word `j` is `b₀ + 2^8·b₁ + 2^16·b₂` of its three bytes,
  below 2^24, so no word reaches p and the call never traps on one.
- **The chain:** `h₀ = T(io)`, `t_io = 0x7038_de5c` the tag word of the
  name `io` (`vos_pvm_precompiles::DEVICE_IO_TAG`, `Tag::Io`);
  `h_i = C(h_{i−1}, block_i)` for each block; then the length block,
  `H_io = C(h_n, [ℓ, 0, 0, 0, 0, 0, 0, 0])`. Its 8 words are 32
  little-endian bytes in φ9..12 as before (each word below p, so the bytes
  are canonical).
- **One implementation:** `DeviceIoHasher`, a streaming hasher (the
  chain's state, a 24-byte buffer and the length so far) over a lane of 16
  words that `C` compresses in place. The kernel's end absorbs its `E`
  where it wrote it; the testkit checks a device return with
  `compute_device_io_hash`; ingress computes it from the request's claim
  (`vos_pvm_device::claim_io`). In a kernel the lane's call is `0x402` issued
  directly (`Poseidon2Call`, which traps where no host serves it, as the
  lean kernel's own calls do), never `poseidon2_compress_into`, which
  would link the software permutation.
- **Domain separation:** `t_io` is a seventh tag, pinned distinct from the
  six (`Tag::ALL` holds seven), and `H_io`'s first call takes `T(io)` on
  the left. No pinned computation over `C` starts there: the credential
  values' first calls take another tag, and a tree node's left input is a
  leaf or a node. A witness-supplied input may hold a `T` value, which is
  harmless: the argument below asks no input to be fresh.
- **Why it binds:** Merkle–Damgård with the length in its last block
  (strengthening). Two encodings with one `H_io`: if their lengths differ,
  the last calls' right inputs differ and the last call is a collision of
  `C`; if equal, they have as many blocks, the padding at that length is
  injective, so the encodings' blocks differ somewhere and walking the two
  chains back from the meeting output finds a collision of `C` at the
  first call where the inputs differ. That collision is of a restricted
  form: each right input is a packed block (every word below 2^24) or a
  length block `[ℓ, 0, …, 0]`, and each left input is `T(io)` or an output
  of an earlier call. An unrestricted collision of `C` is easy (`C` is a
  truncated permutation with no feed-forward: inverting the permutation on
  `y ‖ z₁` and on `y ‖ z₂` gives two inputs of one output, as it gives
  preimages when both halves are free), so the argument rests on the
  restriction: in the ideal-permutation model an inverse query lands on a
  packed or length right half with probability about 2^-56 and on a
  reachable left half negligibly, and forward queries meet only by a
  birthday bound on the 248-bit output, about 2^124 (BLAKE2b-256's 128),
  far above the proofs' 62 proven bits.
- **Extension:** `H_io` extends from itself alone: given `H_io` of `E`,
  anyone computes `H_io` of a longer chain through it. That is harmless
  here, where every check recomputes `H_io` from parts it holds whole and
  nothing secret is prefixed; `H_io` must never serve as a keyed
  commitment.
- **What a device kernel is:** `#[attestable(device)]`, which sets `DEVICE
  = 1 << 33` in its method word beside `READS_SERVED`, its schema kind
  `Device`; it takes no `&self` (a device reads no root and no node serves
  it rows) and is not `venue_bound` (no venue judges its statement); its
  end is `vos_sdk::device::DeviceReturn`, which writes `E` once, in place,
  and `H_io` (a device kernel always returns its parts, however few). A
  `proven = k` guard must name one of the actor's, or a stock kernel,
  else the macro refuses, and the schema's validation checks it again. The derivation admits
  `0x402` in any kernel and refuses `0x400` in a marked one, naming the
  chain of functions that reaches it; it refuses a mark its schema kind
  contradicts and a `Device` method of no entry, and names the device
  kernels (`Derived::devices`). A device kernel's record keeps the node's
  segment shape, never proved and not held to the recursion's leaves; the
  device proves it under the device profile, whose chips its code gives
  (`device_chips_of_code`), against the program computed from the kernel
  (below, *The device program*). Node kernels keep BLAKE2b's io-hash and
  may make the `0x402` call too (§3.2); a device kernel never calls
  BLAKE2b's.
- **No node attests one:** the runtime and the testkit refuse `Attest` of
  a `Device` method before its kernel runs, and `AttestAt` takes `Reading`
  methods alone; the macro gives a device method no `AttestableMethod`,
  so a workflow's attest of one does not compile. The prove-later path
  never meets `H_io`.
- **What the verifier and ingress check** [built]: the verifier
  is the device segment's (the io-hash's 32 bytes are the public values,
  DeviceIoChip's sum recomputed from them); ingress picks the io-hash by
  the proof's format, 47's being `H_io` (not by the guard), computes it
  from the request's claim (`a` the claim's bytes, `o` empty, no roots:
  for the stock auth claim `ℓ = 132`, six blocks and the length's) and
  verifies the proof under its format against it. A
  proof whose kernel ended with BLAKE2b states another io-hash and fails.
- **Where it lives:** the device kernel's end (`DeviceReturn`); a device
  return's check (`KernelReturn::device_io_hash`, the testkit's
  `device_parts` and `run_device_kernel`); the schema's kind `Device`
  (index 6); the seventh tag. Node kernels' io-hash
  (`compute_io_hash`, `vos_pvm_statement::Statement::io_hash`), `Attest`
  and `KernelReturn`'s codec are BLAKE2b's and untouched by it; the device
  format's reference keeps BLAKE2b's chips, since a device program may
  still hold them.
- **Its cost:** seven calls for auth (the Poseidon2 chip's rows 36 to 43,
  under its floor) and the packing's steps. The lever pays only if no
  BLAKE2b call site (`ecalli 0x400`) is reachable from a device kernel's
  entry: `device_chips_of_code` adds BLAKE2b and the AND table for any
  reachable call, and the derivation keeps everything a relocation
  reaches. So nothing a device kernel reaches may call `compute_io_hash`,
  the SDK's node ends (`attested`, `attested_output`) or
  the credential tree's BLAKE2b helpers (`vos_abi::credentials::tag_word`,
  `vos_wire::credentials`' `scope` and `Bound::digest`); a kernel takes
  the tags as `Tag::word()`'s constants.
  The derivation refuses one that does, and a gate holds the auth kernel's
  device chips to neither BLAKE2b's nor the AND table's
  (`device_kernel::a_device_kernels_shape_holds_no_blake2b`).

**The lean kernel** [built; the `device` test actor's `auth`]: the auth
statement in 1,722 steps, under 2^11, which a gate holds, so the CPU sits
at 2^11 rows [measured, 2026-10-31]. Its arguments are read where the witness input
left them (a pointer decoded in place, no copy; the siblings first, so
page-aligned); its path is walked in one lane `[sibling, node, sibling]`,
each level's `0x402` call reading the half the slot's bit picks by its
address, never a branch, and writing the parent over the node; its end
writes the parts once into a buffer with room for their lengths and
hashes `E` where it lies, one four-byte load a packed word
(`padded_device_io_words`); it moves its words whole at any alignment
(the PVM serves unaligned loads and stores; the guest target's own go
byte by byte). A kernel of the same statement that copies its arguments
and converts them byte by byte takes 18,733 steps [measured,
2026-10-30].

**Format 47, device proofs** [built]: the device parameters, masking
and floors (below) over the per-program CPU (the columns the program's
code sets, `CpuColumns::of_code`) and the word ledger (WordMemoryChip, a
row an 8-byte word), counted on its own masked reference (the word set
with the full CPU at 2^17 rows: 7,470 DEEP values, 4,309 constraints):
110 conjectured and 62.82 proven bits; a per-program CPU's cut drops
columns and constraints, which only raises the count (a gate counts the
cut set too). The word ledger's last row is padding
(`IsLast · (1 − IsPadding) = 0`, degree 2, `open.md`). Its kernels are
built for a guest target with `unaligned-scalar-mem`, every unaligned
word access one load or store. The device format: ingress admits it for
every proven call (`DEVICE_FORMATS`). On the stock kernels at release,
against format 46 (the same parameters over the full CPU and the byte
ledger, since retired): auth 1,312 steps (1,546 before the target
feature), 10.24M → 7.23M cells (−29.4%), MEMORY at 2^14 → 2^11 rows, the
CPU 577 → 393 main columns (`vos-phone`'s `cpu_columns`), proofs 880,297 → 784,094 bytes, peak 390 → 209
MiB; owner 259 steps (385), 6.29M → 5.32M cells (−15.4%), 859,617 →
748,356 bytes, peak 225 → 141 MiB; every proof verified; the times, at
load average 20–23 from other work, too noisy to read [measured, x86 dev
machine (Intel Core Ultra 7 155H), four threads, 2026-11-11]. PG1′ and
PG2′ on 47 are the phone sessions' (plan 8.10).

**Format 46** [retired and deleted]: the device parameters over the full
CPU and a ledger a row a byte, which let a byte have two boundary rows
(§10's risk table, A.4); its number is never reused.

**A device proof's bytes and verify** [built]: masked (c), the
Blake2s-M31 channel, blowup 4, 47 queries, PoW 16, interaction PoW 8,
affine DEEP batching, `h = 256`, every chip's floor 2^10 rows; every
device chip at most 2^17 rows (`DEVICE_MAX_LOG_SIZE`, which install, the
prover and the verifier enforce). A proof is at most 1.5 MiB and its
bytes the masked proof's postcard encoding alone, canonical, with no
io-hash. Verified on one x86 thread in 11.7 ms on a quiet machine (the
budget: at most 40 ms on one x86 core) [measured on format 46, x86 dev
machine, 2026-11-01]. Before the decode, a pre-check reads the
proof's leading fields and checks its interaction PoW over the program,
the first two roots and the io-hash: a wrong interaction PoW, a main
root changed or the proof under another claim's io-hash is refused in
0.017 ms at the median, 0.021 ms at the 95th percentile, and a wrong PoW
after the decode and the composition, 11–27 ms by the machine's load
[measured, x86 dev machine (Intel Core Ultra 7 155H), one thread, load
average 7–21, 2026-11-06; `node/SECURITY.md`]. The interaction PoW is 8
bits, so junk ground for 2^8 nonces passes the pre-check: refusing all
well-formed junk in under 1 ms takes a heavier interaction PoW, a format
change (`open.md`).

**The device parameters** [decided]. Counted on the masked device
reference (every chip a device program may hold at 2^17 rows), the least
queries clearing 62 proven bits (the floor of 60 with 2 bits of margin)
and 100 conjectured [model]:

| blowup | PoW | queries | rows a column reveals (`8 + 3q`) | outcome |
|---|---|---|---|---|
| 2 | 20 | 85–87 | 263–269 | proof past 1.5 MiB, no faster |
| 4 | 20 | 43 | 137 | the grind's long tail |
| **4** | **16** | **47** | **149** | **chosen** |
| 8 | 20 | 29 | 95 | slower, more memory |

- **Blowup 2 is out on bytes:** on the lean device kernel its proof is
  1.66 MB, past 1.5 MiB, and it proves no faster than blowup 4 (0.47–0.49
  s against 0.45–0.46 s on four x86 cores) [measured, x86 dev machine,
  2026-10-31]. A small AIR's padded floor costs the same cells at any
  blowup (`4h × 2 × blowup` a column, `h` falling as the queries do),
  while the proof shrinks with the queries.
- **Blowup 8 is out on time and memory:** 0.58–0.59 s and 856–868 MiB
  against blowup 4's 0.45–0.46 s and 573–583 MiB on the same kernel, for
  a 0.65 MB proof [measured, x86 dev machine, 2026-10-31].
- **PoW 16 over PoW 20** at blowup 4: 4 more queries and about 8% more
  bytes for the grind's short tail on the phone: PoW 20's 95th percentile
  50.2–50.6 ms, above the 50 ms rule, PoW 16's 6.8–9.1 ms [measured,
  Fairphone 6, 2026-11-01].
- **`h = 256`:** at 47 queries a column of two offsets reveals at most
  149 rows (§5, how large `h` must be), so `h = 256` and a floor of 2^10
  rows a component.
- **Counted on the masked shape:** a masked device format's bits are
  counted on its masked reference, where (c)'s lifted composition costs
  bits against the unmasked count.

**The device program** [built, `vos_pvm_device`; decided]:
what a device proof is verified against, computed from the kernel alone,
never taken from a request. Its chips are those the kernel's code reaches
(`device_chips_of_code`); its log sizes are those a reference run needs,
each at least the masking's floor and at most `DEVICE_MAX_LOG_SIZE`; its
preprocessed root commits its code, data table, regions, permissions and
entry registers. Its reference run is on what the kernel's reference
program returns (`#[attestable(device, reference = path, headroom = k)]`,
the derivation's `references`), each size raised by its headroom
(`Program::from_kernel`, the reference a `ReferenceProgram`, distinct
from the `ReferenceArguments` a test sizes a program on,
`Program::sized_for`); the stock kernels' reference is auth's public
reference statement (`vos_sdk::p2::reference`, and `auth_reference` in
the hand-lean test kernel's layout: a fixed, public secret's member at
slot 0 of the empty tree, a fixed scope and binding), so every node computes one
program from the installed kernel's release, and a release build the
same from the same package (`light-node.md` §4.4, which a device embeds
and commits without a run, `Program::from_release`); a branch-free kernel's
every witness runs to those sizes. The program id, which a binding names, is
BLAKE2b-256 of `"vos/device/program/v1"`, the format's number and
parameters (log blowup, queries, PoW, fold step, log last layer,
interaction PoW, `log h`), the chips, the count of log sizes and each,
and the root (every integer four little-endian bytes); the transcript
mixes each of them too. The leader computes every device kernel's at the
install, which fails for a kernel whose reference or whose run on it does
not end within the format's shape; a replica that did not install it (or
restarted), once a device proof naming the kernel passes the checks
before the binding, or a window read names it, one computation however
many requests wait, then keeps its verifier. A guard admits its kernel's
release and, until its date, the previous one (`light-node.md` §4.4,
compatibility windows); the binding names which. A run is traced with at most 2^18 gas
(`device::GAS`): the CPU's most steps, and as much again for its
Poseidon2 calls (about 109 a run, fewer as its steps grow; a kernel past
them fails its install out of gas). The stock auth kernel's arguments
are the path's 32 siblings from the leaf's level up and its slot (eight
little-endian bytes), the secret's 32 bytes and the claim, in that order,
which `vos-light`'s `prove_auth` writes; a kernel that reads them
otherwise does not run the reference and is refused at the install.

**What a device proof authorizes** [decided]: the call its claim's
binding names, under the guard the method carries. A device kernel is an
`#[attestable(device)]` method whose `public_args` are its claim, SCALE
words, the binding last, and whose output is empty. Ingress takes the
claim from the request, recomputes the io-hash, verifies the proof under
its format against the device program the node computes from the
installed kernel the guard names (above), runs a stock kernel's checks
(`identity-and-authority.md` §5), and logs the claim, which an actor
kernel's handler judges at apply. The trace is witness-independent: the
prover pads every chip to the program id's log sizes and fails on a run
past them, and the stock auth kernel walks its path with selects.

**The device profile on the phone:** the auth statement under the
device profile, masked, format 46, automatic threads, nine rounds: 645 ms
(the median of three groups' medians; the largest 688 ms), peak resident
427 MiB, proofs 866,827–881,935 bytes, every proof verified on the phone;
each round the node's ingress ran the guarded method as the member's
pseudonym, answering in 54–71 ms, one pseudonym every round [measured,
Fairphone 6, 2026-11-01]. Within the 1.0 s, 1 GiB and 1.5 MiB budgets
(the memory's target, 768 MiB, too).

**The stock kernels at release, PG1′ and PG2′:** `vos-phone run` on the
`auth` and `owner` kernels' release artifacts, format 46, automatic
threads (4), three rounds of five: `auth` 615.6 ms (the rounds' medians
613.7–629.8 ms, the 95th percentile 664–681 ms), peak resident ≤ 505 MiB,
proofs 875,530–881,437 bytes; `owner` 351.8 ms (351.4–362.4 ms, the 95th
percentile 382–415 ms), ≤ 337 MiB, 851,494–856,567 bytes. Every proof
verified on the phone and again on x86; the seeded build's proofs equal
the x86 run's byte for byte. Three sign-ins proved on the phone
(646–665 ms, ~400 MiB) were run by the node's ingress as the member's
pseudonym, answering in 61–68 ms [measured, Fairphone 6, 2026-11-08].
PG1′ (≤ 0.5 s, ≤ 512 MiB) and PG2′ (≤ 1.0 s, ≤ 1 GiB, ≤ 1.5 MiB) passed
there at format 46, since retired; the gates stand at 47,
the device format, whose phone runs are the phone sessions' (above).
A second device, the Pixel 1 (LineageOS, Android 15, four threads), one
round of five on the same artifacts: `auth` 1,532 ms (the 95th percentile
1,589 ms), ≤ 441 MiB, 880,128 bytes; `owner` 817 ms (837 ms), ≤ 311 MiB;
verified on the phone and on x86, the seeded build's proofs equal to
x86's [measured, Pixel 1, 2026-11-09]. The gates are the Fairphone 6's;
this is the floor of an older phone.

**What brought it there,** each lever measured on the phone (the auth
statement over the credential actor's Poseidon2 tree, masked, blowup 4,
47 queries, PoW 16, automatic threads, the median) [measured, Fairphone
6, 2026-10-27 to 2026-10-31]:

| shape | steps | time | peak | proof |
|---|---|---|---|---|
| the first device kernel, BLAKE2b's io-hash, `h = 512`, an even split over eight cores | 18,733 | 5.79–5.98 s | 3.6 GiB | 1.89 MB |
| arguments in place and the path in one lane; the preprocessed tree committed once at install; the Poseidon2 chip's fractions paired; `Threads::Auto` | 5,665 | 2.43 s | 1.8 GiB | 1.82 MB |
| `H_io` over Poseidon2 (BLAKE2b and the AND table out of the shape) | 2,860 | 0.97 s | 0.70 GiB | 0.98 MB |
| the end hashing in place, words moved whole: the lean kernel | 1,722 | 0.74 s | 636 MiB | 0.99 MB |
| `h = 256` | 1,722 | 0.60 s | 543 MiB | 0.98 MB |
| the fork's NEON compression | 1,722 | 0.58 s | 513 MiB | 0.98 MB |

- **Not taken:** blowup 2 (its proof past 1.5 MiB, no faster); a
  `cortex-a720` build (the phone's cores refuse it); little cores pinned
  beside the big ones (slower); the grind and the query count (under 1% of
  a proof at PoW 16). mimalloc never purging tightens the tail, within
  noise at the median.
- **Where a proof goes** [measured, x86 dev machine, 2026-10-31]: the main tree 29%, the
  composition 23%, the interaction tree 19%, DEEP and FRI 17%, the trace
  5%, R1 4%; Blake2s-M31's compression a third, the FFTs about 8%.
- **The ARM factor** on this shape: the phone at automatic threads about
  2.4× x86 on four performance cores, 2.8× x86 on four performance and
  four efficient ones [measured, Fairphone 6 and x86 dev machine,
  2026-10-31].

**The cell model** [model]: on the phone 1.0 s is about 20M committed
cells and 1 GiB of peak 26–40M, so time binds first, at about a device
kernel of 2^11–2^12 steps of node-like code. The CPU split by opcode
family pays little at the device's size: a 4-way split widens the CPU
(785 → 1,284 columns, a 109-column core repeated) and saves 5.4% of the
auth kernel's cells, 1–8% of a node segment's, so it is not built. What
pays (`open.md`):
- **a per-program CPU,** its columns following the program's code (every
  traced kernel uses 48–55 of the 139 opcodes): 785 → 535–549 columns at
  every length, −8.8% of the auth kernel's cells, −14–17% of heavier
  kernels', and a narrower node leaf, in both formats;
  **as built (2026-11-09), in the device format** (format 47): the full CPU
  AIR with the columns the program's code cannot set fixed to zero and
  the constraints and fractions that vanish under that cut dropped, so
  every cut trace is a trace of the full AIR. The column set is a
  function of the code alone (opcode flags and `ecalli` ids), hashed
  into the program id and the transcript header. Its fill sets each
  column on its instructions' rows alone, so an honest run's cut columns
  are already zero; the full CPU's fill, and so every shipped proof, is
  unchanged. On the stock kernels
  the CPU is 781 → 539 columns (auth) and 538 (owner), the kernel's
  cells −9.5% (auth, 10.43M → 9.44M) and −7.8% (owner, 6.39M → 5.89M);
  proving at four threads 231 → 211 ms (auth) and 135 → 128 ms (owner),
  peak −5%, proofs −6.5% [measured, x86 dev machine (Intel Core Ultra 7
  155H, loaded by other work, automatic threads too noisy to read),
  2026-11-09]. On the Pixel 1 at automatic threads, one round of five,
  each cell's proofs verified there and on x86: auth 1,463 → 1,406 ms
  (−3.9%), 439 → 418 MiB, 879,737 → 820,480 bytes; owner 844 → 825 ms
  (−2.3%), 286 → 292 MiB, 858,350 → 798,408 bytes [measured, Pixel 1,
  2026-11-09]: on that phone the time falls less than the cells. Format
  47 takes it beside word-level memory [built];
- **word-level memory:** −17% of the auth kernel's cells, its memory
  ledger byte-level at 2^14 rows for 1,722 steps; −26% beside the
  per-program CPU [model]; **as built (2026-11-09), in the device
  format** (format 47): WordMemoryChip, a row an 8-byte word at one
  `(timestamp, is_write)`, its eight lanes consuming the producers'
  byte tuples unchanged (the CPU, the precompiles and the witness input
  at any width and alignment; an access across a word's end is two
  rows); a word's group starts and ends with a word tuple only
  DeviceWordMemoryChip produces, from 29 address bits, so a group is
  one aligned word and its lanes its bytes; every inner row takes a lane
  (its timestamp a producer's) and padding lies past the real rows
  alone; the data table a word a row; the ledger's tag in the program id
  and the transcript header. Eight bytes, not four, from the stock
  kernels' access mix: of auth's 1,546 steps' 9,262 byte accesses, the
  CPU's 3,942 are 75% aligned 8-byte loads and stores (riscv64's
  spills), the Poseidon2 calls' 4,128 on 8-aligned buffers; the ledger
  takes 12,754 rows a byte, 3,245 a 4-byte word, 1,713 an 8-byte one
  (2^14, 2^12, 2^11). The first touch of a touched word's every byte is
  the layout's, touched or not. On the stock kernels the cells are
  10.43M → 8.42M (auth, −19.3%) and 6.39M → 5.92M (owner, −7.3%), MEMORY
  62 columns at 2^14 → 101 at 2^11 (auth); beside the per-program CPU
  7.43M (−28.8%) and 5.43M (−15.1%); peak 403 → 241 → 221 MiB (auth) and
  237 → 166 → 155 MiB (owner); proofs 0.876 → 0.847 → 0.783 MB (auth),
  0.856 → 0.828 → 0.763 MB (owner); the times, at load average 16–25
  from other work, too noisy to read [measured, x86 dev machine (Intel
  Core Ultra 7 155H), four threads, 2026-11-09]. On the Pixel 1 at
  automatic threads, one round of five, every proof verified there and
  on x86: auth 1,438 → 959 → 922 ms (−33%, −36%), 417 → 315 → 273 MiB;
  owner 828 → 634 → 599 ms (−23%, −28%), 292 → 214 → 195 MiB [measured,
  Pixel 1, 2026-11-10]: the time falls further than the cells, the
  ledger's trace eight times shorter.
The two cheap cuts the model found are in formats 41 and 47 (§3.2).

**3. Signature chips** come last, for flows that must prove a standard
signature [decided, after the hash credentials]:
- SHA-256 and SHA-512, in the narrow layout;
- one generic modular bignum chip (q·m form, 8-bit limbs), with the
  moduli (p25519, p256, n256) preprocessed;
- P-256 and Edwards drivers on top.

Each signature statement is then about 8–10M cells [model]. They are not
post-quantum. None is built (`open.md`).

**The phone** is a Fairphone 6, the one device the budgets are measured
on, reached over adb. On the node's segment shape, with its page
boundary, the auth statement took 6.2–6.5 s unmasked and 2.2–3.0 s
without the boundary [measured, Fairphone 6, 2026-10-25], which is why
the device profile drops it. The enroll, sign-in and pay flows run end to
end on the phone through a gateway (s4's Android client), the secret from
the Keystore behind the biometric prompt (`identity-and-authority.md` §7)
[measured, Fairphone 6, 2026-11-01]. The phone bench is `tools/phone`
(`vos-phone`): a timing build and a `seeded-masks` build whose proofs are
compared with x86's byte for byte.

## 9. Node proving levers, named with their numbers

| lever | effect | effort | status |
|---|---|---|---|
| a shape per kernel | −38% verify, −14% bytes, −10% RSS [measured] | about 1 week | built |
| the reference Poseidon2 and a SIMD hasher | segments on Poseidon2 at 1.75–1.85× Blake2s, against 6.4–6.9× before; a leaf's commitment 0.63 s [measured] | 2–3 weeks | built |
| the seven zero columns dropped; logical right shifts through MUL | the window kernel −5.75% of its cells; its statement 33.3 s end to end [measured] | | built (formats 41 and 47) |
| a per-program CPU (its columns the program's opcodes') | 785 → 535–549 CPU columns; −8.8% to −17% of a kernel's cells; a narrower leaf [model]; the stock kernels 781 → 538–539 columns, −7.8% / −9.5% of their cells [measured] | 3–5 weeks | built for the device profile: format 47; node segments later |
| word-level memory | MEMORY 4–8× fewer rows; −17% of the auth kernel's cells [model]; 8-byte words: auth's ledger 2^14 → 2^11 rows, the stock kernels −19.3% / −7.3% of their cells, −28.8% / −15.1% beside the per-program CPU [measured] | 4–6 weeks | built for the device profile: format 47 |
| the CPU split by opcode family | 4-way: −5.4% of the auth kernel's cells, 1–8% of a segment's, under 1% at a class's fixed shape, wider by 499 columns, past a leaf with the Poseidon2 chip [model] | 6–10 weeks | not built; a 2-way split on the per-program CPU only where padding pays |
| narrow BLAKE2b chips | −2,200 columns; −30–45% of BLAKE2b's cells [model] | 3–5 weeks | later (device kernels hold no BLAKE2b, §8; folds gain) |
| a lighter page boundary (Poseidon2 page hashing), or one memory argument across segments | about −1,100 / −2,800 columns; up to −49% of prover cells | 3–5 / 6–10 weeks | later |
| the 36 cubic gates rewritten | the masked composition at `2N`: about −20–30% of a masked proof's time [est] | an AIR change | later |

A fold costs the inner proof's columns times its queries, so every lever
that narrows the inner proof makes folds cheaper too.

## 10. Risks, and what retires or holds each

| risk | retired or held by |
|---|---|
| the ARM factor is wrong | **retired:** the phone at 2.4–2.8× x86 on the device shape (§8) [measured, 2026-10-31] |
| the Poseidon2 segment channel is too slow to prove | **retired:** a segment's proving plus its leaf beats the Blake2s route's projection (§3.2) [measured, projected] |
| our permutation is not the reference Poseidon2 | the reference arrangement and Plonky3's parameters, checked on their vectors |
| the recursion AIR does not converge | **retired:** a fold verifies two folds within the constant shape (§3.4) [measured] |
| signed multiplicities in the wiring are new soundness surface | the `Context`'s static checks; the audit of the wiring argument (`recursion-air.md` §1.1) |
| the gate compiler is wrong | equivalence tests (constraint ≡ gate) on every chip; tamper tests |
| a kernel's leaf is too big for the padded shape | `derive` computes each kernel's leaf rows and refuses one over the limit (§3.3); the levers of §3.4 |
| the final wrap misses its gas or size | **retired:** the masked wrap verified on the JAM-only host in 79.3M gas and in Wasm in 44.9M instructions (§3.5) [measured] |
| the multi-step FRI path, or the Blake2b channel, is unsound | a review plus tamper tests before a format admits them |
| the wrap misses its 80 proven bits | **retired:** affine DEEP batching, 82.6 proven bits (§3.5) [model] |
| masking the wrap costs more than (c)'s factor | **retired:** format 39 at a 3.6 GiB heap and 79.3M gas [measured], within the bound of 24 GiB and 200M gas; leakage and soundness tests |
| the cut and held build fail under failover | the cut and the held build across a leader change |
| the prover worker falls behind the window cadence | the worker measured against the cadence |
| the teammate's pallet diverges from the design | the pallet against the conformance vectors |
| a deadline between parties is read from a space's clock | a test that every deadline is the venue's time |
| a forgery in the recursion AIR | the recursion AIR's forgery gates |
| a prover's internals leave the role | the carrier audit (A.5) on the model venue and on chain |
| an honest proof is refused | **retired:** the fork's SIMD reduction of a Blake2s-M31 digest word made canonical; 180,000 masked Blake2s-M31 proofs at 43 queries and PoW 20 and 20,000 at 47 queries and PoW 16, none refused [measured, 2026-10-27] |
| the device profile misses 1 s on the phone | **retired:** 645 ms, 427 MiB, 0.87–0.88 MB, accepted at ingress (§8) [measured, Fairphone 6, 2026-11-01] |
| masking the segment chips leaks or breaks the nodes' proofs | soundness and leakage gates on the device shape (two witnesses at equal public values); the unmasked proofs byte for byte unchanged |
| `h = 256` reveals more than its randomizer covers | the revealed-rows argument (§5); R1 on every transcript; `device_floors` at install; a leakage gate at `h = 256` |
| format 41's wider AIR overflows a kernel leaf | the leaves counted as built, within 2^16 / 2^17 / 2^16; the Poseidon2 chip's 17-page class (§3.2) |
| a device proof's shape leaks its witness | the trace padded to the program's log sizes, which a public reference run sets (§8); branch-free kernels; a test of two path shapes under one program |
| the signature chips' cost or soundness | a gate ladder per chip; a phone run (`open.md`) |
| a ledger's padding splits an address into two groups | segments: **held**, a byte's and a register's boundary produced once, padding inside each ledger harmless; device 47: **held**, its word ledger keeping padding past the real rows and its last row padding; device 46 (retired and deleted): **not held**, its byte ledger let a byte have two boundary rows (`open.md`) [reviewed, 2026-11-10; built] |

## 11. Design choices

Each is stated, with its reason, in the section it governs:
- **The recursion** is our own narrow gate-based AIR on our pinned Stwo,
  on StarkWare's design, with Poseidon2 throughout: narrow, so its fold
  converges at once (§3.1).
- **Device proofs are not folded:** a space's ingress verifies them and
  records the fact; chain statements are node-proved over that state
  (§3).
- **Hash credentials before signature chips,** on one proving path, the
  device profile: device-held secrets prove in under a second; signatures
  in software take minutes (§8).
- **The segment channel is Poseidon2-M31,** on a segment's total cost
  (§3.2); **the final channel is Blake2b-256,** which every venue hashes
  natively or cheaply (§3.5).
- **Arguments enter through a witness-input precompile,** so the initial
  image is public and no root over private memory reaches a public input
  (§3.2).
- **One chip set for the node's segments and the device,** as far as the
  node's kernel leaves fit the fold's fixed shape (§3.2).
- **Reads at the last anchored cut, to the space root; windows of venue
  time** (§7).
- **Anchoring cut to the fewest states,** since its state machine had
  grown hard to reason about (§7). Equivocation is terminal: no
  suspension or resume; the space re-founds, its Clerk pairs reset. One
  node key, no rotation: a compromised key means replacing the node. No
  migration ranges or `venue_bound`: a space that changes venue re-founds,
  so Clerk counterparties share a venue for good. No re-cuts: a read not
  closed in time fails `NotClosed` and the caller asks again. No
  hand-back or re-sign: the close writes `S_w` in a replicated row and
  the leader signs from it alone. Reports only for windows a read waits
  on, not `S_w` over every agent's root: a window no agent reported is not
  anchored, and an issuer opts in to every window.
- **Runtime format selection, with lossless encodings** (§3.6, A.3);
  **interaction PoW** on every proof with logup and **248-bit salts**
  (§4); **one padded fold shape** as a format constant (§3.4).
- **The Kreivo venue is a general-purpose pallet,** `pallet-spaces`,
  built by the Kreivo teammate from `spaces-pallet.md`; VOS keeps the
  design, the verifier kit, the node's client and the conformance vectors
  (§6).
- **The prover stays in the node;** chain transports, the JAM client
  among them, are development tooling until the extension host exists
  (§6).
- **An external audit before value rides on a proof** (§4).

## Appendix A. For the implementer

The specs the recursion, the venues and their tests are built to.

**A.1 The transcript.** The in-AIR verifier replays the native
verifier's (`verify_standalone_on` in `pvm/proof/verifier/src/lib.rs`,
through `vos_pvm_proof::proof::replay_prefix`, then Stwo's `verify`), in
this order:
1. the domain, format and PCS configuration, then each chip's log size.
   These are constants of a leaf circuit;
2. the preprocessed root (also a constant), then the main trace root;
3. the boundary states: the 13 registers in, the 13 out, pc and ts in,
   pc and ts out, and the memory roots in and out, as one run of bytes;
4. the interaction PoW nonce, which comes before any logup
   challenge is drawn;
5. the relation challenges: each active chip in `BASE_COMPONENTS` order
   draws its relations, each relation once, at first use; then the
   claimed sums and the interaction root;
6. the composition coefficient and root, the OODS point, all sampled
   values in one mix, the DEEP coefficient, each FRI layer's root and
   coefficient, the last layer, the PoW nonce, and the queries.

The boundary states are mixed as bytes, every other value in 16-bit
limbs (A.3). The boundary chips' claimed sums
are recomputed from the boundary states
(`check_boundary_claimed_sums` in `pvm/proof/src/boundary_binding.rs`) as
public logup terms. A
transcript-equality test checks that the native and in-AIR channels draw
alike.

**A.2 What the in-AIR verifier must handle,** from our chips:
- **a challenge pair per relation,** drawn as A.1 item 5 says;
- **chips reading the next row:** CPU, BLAKE2B, BLAKE2B_BOUNDARY, MEMORY,
  MEMORY_PAGE, REGISTER_MEMORY;
- **chips finalizing one fraction a column:** bitcount, bitwise_and_byte,
  bitwise_lookup, byte_to_bits, jump_table, memory_root_boundary, memory,
  popcount, power_of_two, program_memory, range_multiplicity,
  register_memory_boundary, register_memory_closing.

**A.3 Encodings and the node output.**
- **Lossless encodings,** in every format (A.4).
  - **The boundary states** enter the transcript and the state digest
    in the boundary chips' own byte-limb form (`boundary_binding.rs`),
    one M31 a byte: a register or ts is 8 little-endian bytes, pc 4, a
    memory root its 32. The transcript absorbs the 296 bytes in A.1's
    order as one run. It then binds the exact tuples the public logup
    terms use before any challenge is drawn, so the binding argument of
    `boundary_binding.rs` carries over.
  - **Range checks, kept local.** The leaf range-checks exactly the 32
    bytes it combines: φ9..12, whose bytes become the io-hash's 16-bit
    limbs by linear gates, the only lossy combination of boundary bytes.
    Every other use is exact on M31 values: the transcript, the
    148-word state digest, digest equality between neighbours, and the
    entry and halt flags compared with constant bytes. A value ≥ 256
    there cannot alias another state. That keeps the argument local to
    the leaf, rather than resting on which chips range-check which
    registers across the whole chain.
  - **Every other u64** that enters a hash or a transcript is four
    16-bit limbs, little-endian; a u32 is two; a 32-byte hash is 16.
    The Poseidon2 channel's `mix_u64` (log sizes) and the PoW nonces
    take the four limbs, never a 32-bit half reduced mod p, which would
    fold a word ≥ p onto a smaller one.
  - The io-hash's 16 limbs come from φ9..12's bound bytes by linear
    gates, `b0 + 256·b1`.
- **A state digest** hashes 148 words, in order: the 13 registers (8
  bytes each), pc (4), ts (8), the memory root (32). Memory continuity
  is the memory root's, which the boundary chips bind.
- **A node outputs** one 8-word Poseidon2-M31 digest, the leaf sponge over
  its preimage's 52 words, in this order, each field on whole wires of
  four:
  - the program id (8);
  - `first`, `last`, the entry flag and the halt flag (1 each);
  - the entry and exit digests (8 each);
  - the io-hash (16 limbs, φ9..12's);
  - the fold-circuit word W (8).

  A parent takes the preimage as witness and re-hashes it to the
  child's digest. A leaf copies its program id and W from its witness;
  the fold binds both (§3.4).
- **Positions:** a leaf's `(p, p)` is a free witness. Continuity through
  the ts-bearing digests is what orders segments, and `first = 0` is
  checked only for the wrap's refusal.
- **The wrap's public words:** the program id (8 M31) and the io-hash
  (16 limbs), 24 words at the wrap's reserved addresses 0–23, one word
  a wire. Its zero, one and `u` follow them.

**A.4 The format registry,** `pvm/proof/src/format.rs`. Parameters
as log blowup, queries, PoW, fold step, log last layer, interaction PoW;
counts as conjectured / proven at the reference shape [model]:

| number | proofs | channel | parameters | floors | counts | status |
|---|---|---|---|---|---|---|
| 41 | segments | Poseidon2-M31 | 2, 40, 24, 1, 0, 8 | 100 / 60 | 104 / 62 | admitted |
| 32 | leaf and fold (one padded shape) | Poseidon2-M31 | 2, 44, 20, 1, 0, 8 | 100 / 60 | 108 / 63 | internal: proved and verified inside the prover alone, refused where a proof names it (`Status::Internal`) |
| 39 | the final wrap, masked (variant (c)) | Blake2b-256 | 5, 24, 26, 3, 6, 8, affine DEEP batching | 100 / 80 | 146 / 82 | admitted: the final format |
| 47 | device proofs, masked (variant (c)), `h = 256`, the per-program CPU and the word ledger | Blake2s-M31 | 2, 47, 16, 1, 0, 8, affine DEEP batching | 100 / 60 | 110 / 62 (62.82), on its masked shape | admitted: the device format |

- **A number names one AIR and one set of parameters,** and is never
  reused: every number not in the table is refused. 38 is held by no
  format; the tests use it as "a number no format holds". 28, 44 and 46
  are retired and never reused: 46's memory ledger of a row a byte does
  not keep a byte one group, so its memory argument is unsound.
- **Each entry** holds its channel, its parameters, the DEEP batching its
  proven floor assumes and both bit counts.
- **Every entry uses A.3's encodings** and exactly its parameters.
- **41 takes fewer queries and more PoW than 32** (40 and 24 bits against
  44 and 20): a kernel leaf's rows grow with the segment's width times its
  queries, and a fold verifies under half the recursion AIR's shape. On the
  segment shape 41's count is its query term's, 62.81; 32's parameters give
  62.74, their batching term binding.
- **41 and 47 name the segment AIR,** hardened, without the columns and
  next-row masks no constraint reads (§3.2), its chip set shared by the
  node's segments and the device shape; 32 and 39 prove the
  recursion AIR, 32's leaves verifying the segment AIR. A reserved entry is refused until its AIR and channel
  exist. 32's exist: `vos-pvm-recair` proves and verifies its proofs
  natively, and the registry
  refuses it, as no verifier outside the recursion reads a leaf or a fold.
  39 is admitted: `vos-pvm-recair` proves the wrap masked and
  `vos-pvm-final-verifier` verifies it by its fixed layout; a segment
  verifier takes only a segment format.

**A.5 What may leave the prover role:**
- the `Statement`;
- the final proof.

`Attest` (`pvm/abi/src/result.rs`) is `{ program, window,
witness_input, output, public_args, roots }`:
- **`window`:** the window whose cut it read at, for a read at a cut;
  none for a plain attest;
- **`witness_input`:** the exact byte stream the kernel read, in call
  order: its arguments, then, at a cut, the served rows' encoding, which
  arrived inline in the `Resume` input; at most a work result's cap. A
  prover's re-run is served the same bytes;
- **`public_args`** and **`roots`:** the statement's, as §3.6 orders them.

The final proof's hash reaches the agent as an `Input::Proven { window,
id, proof }`, through its leader; the proof itself is a blob, held until
its job finishes.

**The carrier audit** (`vos_checker::carriers`, `just test-carriers` on
the model venue and `just e2e-chain` on both venues) searches every byte
a run produced for what never leaves the role, each needle in its bytes,
its hex, its `Debug` list and, for a number, its digits and byte orders:
- **the needles:** every segment, leaf and fold proof's roots, encoding and
  output digests; each segment's steps and the gas its re-run left; each
  boundary's memory roots and registers φ0..φ8; the served rows, their keys
  and salts, every value the run wrote, the cut's roots and paths, the
  private arguments and their plain and domain-prefixed hashes (a run over
  high-entropy values and a run over small ones); the masked wrap's
  randomness (each attempt's entropy and seed, the witness digest, the
  blinding values, the seeds of the mask, salt and `R` columns), shown by
  the prover's watch seam (`vos-pvm-recair`'s `watch`, a dev edge only);
  each debug output's text;
- **the carriers, by reach:** what leaves the role (a venue's calls, every
  JAM package, extrinsic and work report as sent, the statements
  service's storage read over RPC, the logs at every level, standard
  error, a client's answers, frames to and the disk of a node that does
  not replicate the agent) is searched for every needle in every form; a
  chain's own record (its log and database) for every needle in its full
  forms, a number's being matched there by the chain's counters by
  chance; what stays within the agent's replicas (their logs, blobs,
  stores, disks once stopped, frames) for proofs, memory roots, register
  files and the wrap's randomness, which no carrier may hold;
- **the proven calls** (`node/host/tests/carriers/credentials.rs`):
  a member's calls proved by the device library under the stock kernels
  and an actor's own, sent over the node API's socket and a gateway over
  QUIC, refused at ingress in each way a device meets;
  needles the member's device secret (its source's output, `w`, `s` and
  each word, the nullifier's key, their hashes, a device kernel's
  arguments), a proof's masks as drawn, and its place in the
  tree (its digest, its leaf, its slot, its occupied siblings), the place
  searched in every carrier that leaves but the feed's connection; and the
  phone bench's lines and proofs. A run over small values (rows from
  2^20) searches a number below 2^24 by its digits and hex alone. The
  facility (`node/light/android`) is audited through its C ABI and every
  freed heap block (its `tests/leaks.rs`);
  its known gaps are `identity-and-authority.md` §7's;
- **the guards:** each capture path shown to capture by a canary; each
  needle found when planted in each of its forms; the audit's seams and
  the debug outputs reach no production build (`just
  check-no-debug-internals`, `check-no-seeded-masks`); a panic while a
  proof is made prints its place and not its message; a failed proof's
  error names what failed, no value.

**A.6 The golden fixtures:**
- a valid statement and proof;
- a tampered proof;
- a wrong program;
- a stale or unanchored root;
- a prefix of a run;
- a run started mid-way;
- a repeated statement id;
- an unaccepted format;
- a wrong io-hash;
- the same run under another accepted final format.

Every venue judges them alike. A generator
(`pvm/proof/tests/kernel/fixtures.rs`) makes them, regenerated at each
format bump, and stores them under `pvm/proof/fixtures`. It proves a small
kernel stating a fixed statement `S` (two roots of its space, a nonce, an
output; its `public_args` a venue's id and a nonce, which the io-hash
binds and no venue reads apart) in three segments, folds them and wraps
the root under format 39, masked from the seeded test seam
(`MaskRng::Seeded`, so the bytes are its own every run; `wrap.proof` is
142,468 bytes, a size that moves a few percent with the seed); and it
wraps two roots that are not a whole run, as a cheating prover would,
the wrap's checks failing (`wrap-prefix.proof`, `wrap-midway.proof`). The
generator makes the same bytes in every build of the prover: a kernel's
program id does not depend on the features a build turns on (the drawn
relations are kept in the order drawn, never in `TypeId` order).

The venue accepts {39}, registers `S`'s space from window 40 and judges
at window 42's boundary. 20 cases (`statements.cases`), each a venue's
state, a statement, a proof or a patch of one, and its verdict; each but
the accepted one a replay of an accepted statement with one thing
changed. Every verdict is the same natively, in Wasm (PVF and client;
`just judge-wasm`) and on the JAM-only host (`final-verify.elf`):

| case | verdict | JAM-only host [measured] |
|---|---|---|
| valid | accepted | 79.4M gas |
| tampered | `0x112` | 47.6M |
| wrong program; wrong io-hash; the nonce; the roots' order; a root dropped | `0x108` | 11.0M |
| prefix; mid-way | `0x109` | 11.1M |
| unaccepted format (38) | `0x2` | 0.1M |
| another program than the pin | `0x3` | 0.1M |
| another space; the space; rootless; rooted, of no space | `0x4` | 0.1M |
| unanchored root; a root's window; a root; replayed past MaxRootAge | `0x5` | 0.1M |
| repeated | `0x6` | 0.1M |

- **The id is the same at every venue,** and a refused proof's class is
  the first check it fails.
- **The id leaves the format out,** so a run wrapped under each of two
  final formats a venue accepts during a transition has one id under
  either (`vos-statement`'s `every_field_is_bound`), and a venue's repeat
  check refuses it the second time. Past `MaxRootAge` a replay is unanchored (its
  `Seen` entry and anchors dropped).
- **Why `0x108` and `0x109`:** the words are mixed before the interaction
  PoW (8 bits), so a proof of other words fails there (`0x108`) with
  probability 255/256, or otherwise at the logup sums (`0x109`); a wrap
  proved over a refused root does not balance its logup sums.
- **Cheap refusals:** a judgement refused before its proof costs no proof
  lookup on the JAM-only host, and a proof longer than 256 KiB is refused
  before its lookup.
- **The guests' size:** the venue's guest's program is 391,784 bytes,
  within JAM's 4,000,000-byte bound on a
  service's code, its only size bound.

**A.7 Budgets per node.** Heavy tests run
under `systemd-run` with these caps as `MemoryMax`.

| node | rows | memory | time |
|---|---|---|---|
| segment (the window kernel's) | its class | ≤ 24 GiB | ≤ 8 s |
| leaf | ≤ the padded shape | ≤ 4 GiB | 1.2–2.6 s [projected]; ≤ 1× the segment's proving (target 0.13–0.5×) |
| fold | the padded shape | ≤ 4 GiB; 942 MiB of heap [measured] | 1.2–2.6 s [projected]; ≤ the leaf's; 1.5 s [measured] |
| wrap (39) | ≤ 2^17; 2^14 / 2^15 / 2^11 [measured] | ≤ 8 GiB; a 3,627 MiB heap [measured] | ≤ 15 s; 7.44–8.40 s under load [measured] |

A window of 16 segments proves end to end in about 3–5 minutes
[projected].
