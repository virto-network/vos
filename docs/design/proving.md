# Proving: layers, formats and verifiers

Design, draft 5. It is the architecture behind slices 5, 6 and 7
(`slice-5-proving.md`). The recursion AIR's own design is
`recursion-air.md`.
- **Status:** [decided] marks the owner's decisions; [proposed] marks
  everything else, which is open to review.
- **Evidence:** the research is in `research/slice-5/`. Every number below
  carries its tag there: [measured], [model] or [projected].
- **History:**
  - draft 2 folded in Fable's review (`research/slice-5/proving-review.md`,
    R1–R13);
  - draft 3 took the owner's decisions (§12) and Fable's check of draft 2
    (D1–D4);
  - draft 4 takes `recursion-air.md`'s measurements and corrections;
  - draft 5 folds in Fable's review of the planning set
    (`research/slice-5/plan7-review.md`, R1–R11): the fold's carry of
    the circuit hash, lossless encodings, the witness-input record, the
    crates' homes, the budgets per node and the estimates.

## 1. What the owner requires [decided]

- **STARKs only.** No trusted setup, and post-quantum readiness. No SNARK
  wrap at any layer.
- **One proof per statement.** A statement's segment proofs fold through
  a recursion layer into one final proof. That proof is verified by:
  - a peer;
  - a pallet on the Kreivo parachain, first;
  - a JAM statements service, a dedicated service whose refine verifies
    and whose accumulate records (slice 6).
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
  - The base AIR was 13,037 columns: Ristretto 42% of them, BLAKE2b
    23% and the page-Merkle boundary 22%, the CPU 6%. The Ristretto
    chips have since been removed (unsound; slice 7's generic bignum chip
    replaces them), and the AIR audit's hardening widened what was left:
    the full shape is now 25 chips and 8,039 columns [measured].
  - Verify gas is linear in columns. The best measured segment verify
    is 1.17B gas, and every projected lever stacked still leaves
    0.45–0.7B.
- **A small final proof is cheap to verify.**
  - A proxy (320 columns, log 16, blowup 64, 13 queries, fold step 3, a
    2^6 last layer) measured 54.4M gas and 80 KB unmasked; about 66–76M
    and 102–112 KB masked [projected].
  - In a Wasm runtime it takes 23M instructions, about 1.7 ms here. On
    Kreivo a proof is about 0.3% of a block's weight, and its bytes bind
    first.
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
  - Our own earlier attempt diverged 2.3× per level because it was built
    wide, not narrow.
- **Phones** [measured on x86, projected to phones]:
  - the general zkVM's fixed floor is the page boundary: 91% of an empty
    kernel's cells;
  - with four levers, authentication and payment authorization project
    to 0.36–0.9 s masked on Apple-class phones and 0.65–1.6 s on Tensor;
  - a dedicated Poseidon2 credential AIR proves the same statements in
    tens of milliseconds [model];
  - signatures in software take minutes. With chips they are about
    8–10M cells.
  - An ARM build proves byte-identically to x86. No phone has run it yet.
- **The critique** (Fable):
  - Stwo is the right base;
  - our 96 bits are conjectured, and the proven figure is 58;
  - the PVM is wider than RV32 for a zkVM, and JAM alignment is the real
    gain;
  - P-256 and ed25519 inside a proof are not post-quantum.
- **Bugs found on the way, fixed on vos-core:**
  - the query-count preflight replayed the transcript out of order;
  - the verifier path had stopped building without std;
  - a quadratic copy in the Poseidon2 leaf hasher.

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
    stays the gate set's 458. The archive diverged because it laid a
    child's columns out as columns.
  - M1 gates the convergence on real proofs.
- **Reused:** gate bodies from the `voucher-recursion-archive` tag (the
  Poseidon2 constraints, QM31 idioms, the FRI fold, Merkle and the
  channel), not its architecture.

### 3.2 Base proofs: node segments

- **Kernels on the chain path,** re-run from the `Attest` record.
- **A shape per kernel:** the component set from its code, and pinned
  log sizes per segment class.
- **The segment channel:** Poseidon2-M31, so the recursion verifies
  cheaply [decided, owner].
- **The permutation is the reference Poseidon2 arrangement,** with
  Plonky3's width-16 M31 parameters (pinned at `f983316`), checked
  against their test vectors.
- **A SIMD hasher on the prover:** sixteen permutations a call, adapted
  from Plonky3's packed M31 Poseidon2 (AVX2, AVX-512 and NEON; MIT or
  Apache-2.0). The verifier keeps the scalar permutation.
  - 39.5M permutations a second on 8 threads (AVX2), against 7.05M
    scalar [measured].
- **Gate:** a segment's total cost, its proving plus its leaf, against
  the Blake2s route's projection. Per segment at the 32k cut:
  - Poseidon2: about 5.6 s to prove [measured] plus a leaf of about
    1.5–3 s [projected];
  - Blake2s: about 3.1 s to prove [measured] plus a leaf with in-circuit
    Blake2s of about 4.5–6 s [projected]; the recursion AIR's shape and
    fixed point would also be re-derived.
  - The proving alone runs at 1.75–1.85× Blake2s, and a leaf's
    commitment (25M permutations) at 0.63 s [measured]. The first gate's
    bounds (1.5×, 0.5 s) priced the prove alone; the owner kept
    Poseidon2-M31 on the total.
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
    2 KiB on JAM); a statement's served witness travels as a blob by
    hash, under `Limits::served` (proposed; set by 6.0a) and the
    kernel's declared gas (slice 6);
    4 MiB stays the ceiling of the kernel's whole input;
  - `derive` admits the new id, and a live≡traced test gates it in M0.
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
  masks no constraint reads (formats 35 to 37): each cost every leaf its
  samples.
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
  - **The shape per kernel is load-bearing.** At format 35's 40 queries,
    a kernel-like shape fits the padded shape up to about 9,033 columns
    (about 8,100 at 44 queries) [model]. The full 32-chip set (13,037)
    would have doubled every node; without the Ristretto chips and
    hardened, the full set is 8,039 columns, inside it [model].
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
  - **The kernel leaf fits, with about 1,000 columns to spare.** At
    format 35's 40 queries over the window kernel's 8,009 columns, its
    `p2` is 57,700 rows of 2^16 finalized, 12% spare, and its `qm31`
    102,227 of 2^17 [measured, slice 5's 5.11–5.12]. At 44 queries over
    the 8,024-column shape it would have been about 64.8k, 1% spare
    [model], which is why segments take 40 queries with PoW 24 (§4).
  - **The levers,** if a count passes 2^16 (a wider kernel, or the next
    fix that widens the AIR): fewer queries with more PoW (a new segment
    format, as 35 was), FRI fold step 3 in inner proofs, or `p2` at 2^17
    (+70% cells).
  - A fold uses under half of the shape, so a child could grow by about
    3,200 columns before the fold outgrows it.
  - A kernel that does not fit is refused (§3.3).
- **Built** [measured, slice 5's 5.13; `vos-pvm-recair`'s `fold`]:
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
- **Parameters** (format 28): blowup 64, 20 queries, PoW 26, interaction
  PoW 8, fold step 3, a 2^6 last layer, and **affine DEEP batching** (an
  independent coefficient a sampled value). That is 146 conjectured and 82
  proven bits (82.6; 80 needs 19 queries) [model].
- **Why affine batching:** Stwo batches the sampled values by powers of one
  coefficient, and that term's error is the values' count times a
  proximity-gap error that grows with the blowup. At blowup 64 it caps the
  proven count at 74.7 bits however many queries are taken, 18 or 20
  [model]. The ways to 80, decided at 5.14 [model]:
  - **affine DEEP batching** at blowup 64 and 19–20 queries, about 1.06×
    the verifier's cost, a change to our fork for the wrap's format only
    (recommended);
  - **a 6-bit PoW in the batching phase** at blowup 64 and 20 queries, about
    1.11×;
  - **blowup 8 with 41 queries,** about 1.97×.

  **Decided at 5.14: affine batching,** built in our fork for the
  configurations that ask for it (`PcsConfig::deep_batching`, its
  `DIVERGENCE-012`) and off by default, so no other format's proofs
  change. A proof does not carry its batching: a verifier takes it from
  the format. The security tool counts its batching term as `ε_lin(k)`
  (BCIKS20 Theorem 1.6), and its first FRI round as the fork folds it, by
  `2^fold_step` with the circle fold in it (`DIVERGENCE-011`).
- **Masked** as format 39 (variant (c), A.4): blowup 32, 24 queries, PoW
  26, interaction PoW 8, fold step 3, a 2^6 last layer, affine DEEP
  batching; 146 / 82 (82.70) [model]. Format 28 stays a test format.
- **The final channel** [decided]: Blake2b-256 Merkle trees and a
  Blake2b Fiat–Shamir transcript. This is new code in our Stwo fork.
  VOS's `0x400` serves a Blake2b compression and Kreivo's host
  `blake2_256` the whole-message hash; JAM serves no hash (Gray Paper
  0.8.0 has no hash host call), so a JAM verifier hashes in software. On
  Kreivo the host hash would shorten ref_time, but proof_size binds a
  block and length sets the fee.
- **Cost:**
  - about 85M JAM gas unmasked with Blake2b in software, and 64M through
    VOS's `0x400` precompile [model];
  - masked (spike 6a, shape A, postcard): 115.8–118.7M JAM gas (decode
    19.9M, verify 95.8M), 45.2M Wasm instructions, 160–163 KB, 3.45 GiB
    of heap and 11.6–15 s to prove [measured]; about 98M with format
    39's fixed-layout decode [est];
  - about 122 KB unmasked [model].
- **Built** (slice 5's 5.14) [measured], unmasked:
  - **96.4M JAM gas** on the JAM-only host, Blake2b-256 in software: the
    proof's postcard decode 16.0M of it, the verify 80.3M; a 469 KB PVM
    program, a 339 KiB heap peak;
  - **38.2M retired Wasm instructions** under the PVF's semantics (37.7M
    the client's), 2.1 ms, a 292 KB blob;
  - **122–125 KB** (the window kernel's 123,686 bytes);
  - **5.45 s and a 2.5 GiB heap** to prove the window kernel's wrap.
- **Levers:** format 39 is to decode a fixed layout (6.4); the Blake2b
  hook is deferred, a lever for when ref_time binds: nothing in slice 6
  verifies as a PVM guest on a VOS host, and Kreivo's binding limit is
  proof_size.
- **Fold step above 1:** the pinned Stwo implements it; our fork's review
  and tamper tests admitted it for format 28 (slice 5's 5.14).
- **Its public inputs** are the program id (8 M31) and the io-hash (its
  32 bytes as 16 limbs of 16 bits): 24 words, at the wrap's reserved
  addresses 0–23 (A.3).

### 3.6 The statement, one format for every kernel

```rust
pub struct Statement {
    pub format: FormatVersion,       // the final format; the venue checks it is accepted
    pub program: ProgramId,          // a public input of the proof
    pub space: SpaceId,              // checked by the venue against every RootRead
    pub public_args: Vec<u8>,        // the kernel's #[public] arguments, canonical encoding
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
    `RootRead.space`, or the zero id for a rootless statement);
  - **only the kernel's code binds a `RootRead` to what the kernel
    verified against.** No layer checks that a stated root is the one
    the kernel's multiproof was checked against: the kernel writes its
    roots into the io-hash, and the program id pins that code. So
    admitting a program id is admitting an audit of that kernel: that it
    states the roots it verified, carries a nonce where its statements
    can repeat, and keeps its low-entropy fields salted, as SECURITY.md's
    "program intent" says of the base layer.
- **A rootless statement belongs to no space; a statement claiming a space
  must read a root of it.** Only a root binds the space: the proof states
  none, and the id hashes it. Were a rootless statement's space free, one
  accepted proof would make a new id under each space and pass the repeat
  check again: a settlement applied twice. The venue refuses a rootless
  statement whose space is not the zero id (`SpaceId::NONE`), as
  `Refusal::Space` (`0x4`).
- **A kernel that does not state its roots** carries what it read in its
  output, which no venue checks: its handler must. The window kernel is
  one, until the SDK puts a kernel's public arguments and roots in its
  io-hash (slice 6): its statement is rootless, `public_args` empty, and
  its space and anchors (`anchor_i`, `anchor_j`) are in its output, which
  the Clerk's handler checks against its anchored roots.
- **Repeats:** a venue refuses a statement id it has seen. A kernel whose
  legitimate statements can repeat carries a nonce in `public_args`.
  A venue keys on the statement id, never on the proof's bytes or their
  hash: postcard's varints need not be minimal, so one proof has many
  encodings, and many proofs state one statement.
- **The venue's check, built** (slice 5's 5.15, `vos_statement::judge`),
  in order: the format (accepted, and 28, the one the final verifier
  reads); the statement's program against the venue's pin; the space,
  every root's the statement's and a rootless statement's none; every root
  anchored; the io-hash
  recomputed from the fields and the id from it; a repeat; then the final
  proof (at most 256 KiB, one postcard encoding and nothing after it)
  against the pinned program id and the recomputed io-hash. **The program
  id is the venue's argument, never the caller's:** a venue that verified
  against the statement's or the proof's id would accept any kernel's
  proof. Each refusal has a class every venue reports alike
  (`Refusal::code`, the final verifier's `Error::code` under it).
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
  hash, image root and shape, the shape's policy version among it; the
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
    and riscv64em-javm;
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
    (`final-verify.elf`) is the venue on the JAM-only host;
  - the golden fixtures, under `fixtures` (A.6).

  Every venue uses the last four. The source uses no nightly feature:
  it builds on stable for x86 and wasm32, and the JAM build runs on the
  pinned nightly with build-std.

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
| segment proofs (format 35) | ≥ 100 / ≥ 60 | blowup 4 (log 2), 40 queries, PoW 24, plus interaction PoW 8; FRI fold step 1, log last-layer degree bound 0 | 104 / 62 (62.86) |
| leaf and fold proofs (32) | ≥ 100 / ≥ 60 | blowup 4, 44 queries, PoW 20, plus interaction PoW 8; fold step 1, last layer 2^0 | 108 / 63 |
| device and credential proofs (37, 30; verified at ingress, never folded) | ≥ 100 / ≥ 60, with 2 bits of margin | blowup 2 (log 1), 86 queries, PoW 20, plus interaction PoW 8 | 106 / 62 |
| the final wrap, unmasked (28; tests only) | ≥ 100 / ≥ 80 | blowup 64 (log 6), 20 queries, PoW 26, plus interaction PoW 8; fold step 3, last layer 2^6; affine DEEP batching (§3.5) | 146 / 82 (82.60) |
| the final wrap, masked (39) | ≥ 100 / ≥ 80 | blowup 32 (log 5), 24 queries, PoW 26, plus interaction PoW 8; fold step 3, last layer 2^6; affine DEEP batching; variant (c) | 146 / 82 (82.70) |

- **The counts** are the security tool's (`pvm/proof/src/security.rs`) at
  each format's reference shape [model], pinned by the format tests.
- **The numbers:** 35 to 37 name the segment AIR (36 is the legacy
  Blake2s segment format the default prover produces). 24 to 27, 29, 31,
  33 and 34, which named its earlier forms, are retired: refused, and
  never registered again.
- **The inner grind:** a segment's PoW 24 costs 0.43 s on average on 8
  threads (median 0.26 s, 95th percentile 1.44 s), against 0.028 s at 20
  [measured, 128 grinds each, SIMD]; interaction PoW 8 is negligible.
  Leaves and folds keep PoW 20, and their 44 queries make a fold about 13%
  dearer than 39 would [model]. The inner proven count is set by the query
  term.
- **Why segments take 40 queries:** a kernel leaf's `p2` rows grow with the
  segment's width times its queries. At 44 over the window kernel's 8,009
  columns the leaf needs 64,717 of `p2`'s 65,536 rows; at 40, 59,300, 9.5%
  to spare [model, `count-35.log`]. PoW 24 keeps the proven count, 62.86
  against 62.74 at 44 queries and PoW 20, where the batching term binds.
- **Devices:** 86 is the least query count whose proven count clears 60 by
  2 bits; 84 gave 61.2.

- **Inner soundness carries through:** forging a fold's input forges the
  final proof. **The system's proven bound is therefore the weakest inner
  format's, 62.86 bits (format 35), not the wrap's 82.6;** its conjectured
  bound is 104. Under Grover's heuristic that is about 31 proven and 52
  conjectured bits against a quantum prover, so post-quantum readiness
  rests on the conjectured count. All counts are the security tool's own
  [model], pinned by tests and not yet reviewed outside.
- **Format 36,** the legacy Blake2s segment format the default prover and
  the refine bundles still produce, is at 96 / 57: below the 60-bit proven
  floor. It is admitted for the legacy path alone and never wrapped into a
  published statement; its retirement, or the refine path's move to 35,
  is carried out of slice 5 (`slice-5-progress.md`, "Carried out of
  slice 5").
- **Salts:** 8 M31 (248 bits).
- **Interaction PoW** applies to every proof with logup, folds included.
- **An external audit,** before value rides on a proof, of:
  - the in-AIR verifier;
  - the fold node;
  - the gate compiler (constraint ≡ gate);
  - the claimed-sum handling;
  - the masking, and the public-sum re-cut;
  - the masked wrap's transcript and R1–R4, and the lifted protocol under
    (c) (`research/slice-6/spike6b-masked-bits.md` §4);
  - the base segment AIR, the parts slice 5's hardening left without
    forgery gates first: PROGRAM_MEMORY's decode binding, JUMP_TABLE, the
    lookup tables, MEMORY_PAGE and MEMORY_MERKLE, the witness-input chip,
    the boundary-binding argument;
  - the fork's divergences (the Blake2b channel, fold step 3, affine DEEP
    batching, the completeness backport);
  - the security tool's counts (`security.rs`);
  - the leaf's binding, the wrap, `vos-pvm-final-verifier` and
    `vos-statement`, and `derive` with the program id's derivation.

  Its owner and timing are the owner's to set, and open
  (`slice-5-progress.md`, "Carried out of slice 5").

## 5. Masking [proposed]

- **Where:** the final wrap (slice 6). Device proofs (slice 7) reuse it:
  the masking is generic over the component set and the channel. Segment,
  leaf and fold proofs stay in the prover role, as the witness rows do.
- **Device proofs at rate 1/2** serve authorizations a space re-checks at
  its ingress, never settlement.
- **How:** spike 2's variant (c), already prototyped on our pinned Stwo
  fork, with Fable's R1–R8:
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
  4. hedged randomness, H(OS ‖ witness);
  5. a degree audit (the recursion AIR's gates stay at degree ≤ 3 with
     paired logup, so (c) applies);
  6. parameters pinned in the format;
  7. every carrier audited (A.5);
  8. the cost measured.
- **The composition mode:** a test pins that (c) lifts no constraint past
  the blowup. If it did, the prover would re-LDE every column.
- **On the wrap** (spike 6a): no re-LDE [measured]; the prover ×2.6–2.9
  in time (the lifting rises to 22, and Blake2b Merkle hashing of the
  doubled leaf layer dominates), ×1.41 in memory; verify ×1.20, bytes
  ×1.31 [measured]. Shape A's preprocessed root is format 28's.
- **Leaks:**
  - proving time (mitigated by publishing at the window cadence);
  - the public fields the kernel declares.

## 6. Verifiers [proposed]

- **Peers:** native, on the same crate.
- **Kreivo, a general-purpose pallet** [decided], `pallet-spaces`
  (`spaces-pallet.md`, its handoff design; `research/slice-5/kreivo-pallet.md`
  for the first survey):
  - **Registries:**
    - spaces: a space registered from its genesis, with a **sovereign
      account** that holds the registration deposit and pays its
      authorities' fees and deposits; an **authorities map** of the
      nodes' own sr25519 accounts, each paired with its ed25519 anchor
      key, set by the controller (an `AccountId`); a registration signs
      its first window; the venue-bound flag; the migration range;
    - anchors keyed by `(space, kind, window)`; `MaxRootAge` (24 h) is
      the only age;
    - formats and programs: governance, with a delay.
  - **Fees:** `submit` takes a refundable deposit, released on acceptance
    or a repeat, forfeited on any other refusal; normal length and weight
    fees, paid by the sovereign account through `ChargeSpaceFee` within a
    spend budget per window. A proof's length counts as proof_size, so
    about 20 statements fit a block on one core.
  - **The repeat rule:** a rootless statement's `Seen` entry never
    expires, since it has no anchor whose age refuses a replay.
  - **The node's Kreivo client:** the representative and the worker
    anchor and submit through a `VenueClient` signing with the node's own
    sr25519 key, which holds no balance.
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

    Steps 1–7 but the statement's own decode are `vos_statement::judge`
    (slice 5's 5.15), the program's pinned id passed in from the registry.
    The pallet caps the extrinsic's length itself (step 1): `judge`
    applies its 256 KiB cap at the proof's decode, after the cheap checks.
    The statement's words are an input to the verifier, never an output.
  - **Panic-free by construction:** a FRAME runtime cannot catch a panic
    (no unwinding on wasm32 without std; a panic aborts the block's
    import), so no guard can wrap the decode and the verifier. The final
    verifier and the statement code must not panic on any input: the
    shape and sample checks (`check_shape`, `check_samples`) refuse
    before Stwo reaches its indexing and `unwrap`s, and the statement's
    decode bounds every count by the bytes left. Fuzzing
    (`pvm/proof/fuzz`) is the evidence so far; a CI fuzz job and an audit
    of every index and `unwrap` on the verify path at the pin are carried
    to slice 6.
  - **Every re-pin is a governance event at every venue:** a segment
    format bump (any base-AIR hardening) changes every program id, and a
    change to `recair`'s compiler or gate set changes every leaf-circuit
    hash, `H_fold` and the pinned wrap root. That is the price of the next
    soundness fix.
  - **The anchor table is keyed by root kind too:** `Venue::anchored`
    compares the whole `RootRead`, kind among it.
  - **Fail-closed:** a runtime without the verifier rejects every proof,
    and a failed submit pays its full weight.
  - **Built-in handlers:** `Record`; a `Credential` handler with slice 7's
    credential AIR; the Clerk's settlement handler with the Clerk. Every
    value-moving handler is two-sided or spends the submitting space's
    own escrow. No handler runs a STARK in `validate`.
  - **Its home:** `pallet-spaces`, in Kreivo, built by the Kreivo teammate
    from `spaces-pallet.md`, to replace pallet-communities later; the
    verifier stack vendored into Kreivo with a sync check against a VOS
    tag (VOS's kit, slice 6's 6.16); frame-contrib and crates.io later.
- **The JAM statements service** (slice 6): a dedicated service; refine
  verifies anchors' signatures and statements (about 100M gas a
  statement; a report's accumulate has 10M); accumulate holds the spaces,
  anchors and repeats, and records, checking an anchor's signer against
  the space's registered keys and keeping a rootless statement's `Seen`
  entry forever, as Kreivo does; accepted program ids are constants
  changed by redeploy; a proof rides in its work item's payload (or as a
  preimage; 6.0b decides). An actor in the
  default agent cannot host it: `MAX_HANDLER_GAS` 100M, a 512 KiB program
  cap (538,683 B with both formats linked), 2 KiB messages, no preimage
  access.

## 7. Roots and anchors [proposed]

- **The kernel verifies its rows up to the space root.** Its witness
  carries the full path: row → map root → agent root → space root. So
  `RootRead.root` is the anchored space root, which the venue compares.
  That costs a few dozen more compressions per statement.
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
  `(agent, kind, w) → the agent's root at cut(w)` (`slice-6-on-chain.md`,
  pin D).
- **Anchors** [decided] are signed by one registered node key; the
  controller rotates the keys.
- **Retention:** none past a cut. A request made in window w reads at
  `cut(w)` and is served at the next cut.
- **Spans** [decided]: a statement over a span of windows takes a carried
  commitment to its last settled state as a `#[public]` argument, not an
  old root; no tree history is kept.
- **An anchor gives ordering and non-equivocation, not integrity:** a
  space can anchor any root of its own making, so every value-moving
  handler is two-sided or spends the submitting space's own escrow.
- **Venue migration:** a space anchors on one venue at a time. The signed
  migration point is recorded on both venues, and each refuses windows
  outside its range.
- **Root kinds:**
  - Committed rows sit first in the keyspace, under `0x03`, so an
    agent's root is the same on both hosts: VOS's tree per agent equals
    JAM's node at `0x03` [decided]. `RootKind { Space = 0 }`; 1 is
    reserved for the Poseidon2 kind (§8).
  - A map may take the **Poseidon2 root kind** (§8). Its root is then a
    Poseidon2-M31 tree's root.

## 8. Mobile [decided: credential AIR first, then the device profile; PRF first, then chips]

**1. The credential AIR** comes first. It is a small, dedicated
Poseidon2-M31 AIR, built from the recursion AIR's Poseidon2 component.
- **Authentication:**
  - membership of a credential leaf in a Poseidon2 tree;
  - a nullifier scoped to the context;
  - a binding to the challenge.
- **Payment authorization:**
  - a balance row read from a Poseidon2 tree;
  - a range check that balance ≥ amount;
  - a binding to the payment.
- **Proved on the phone in Blake2s-M31, masked** (variant (c), the
  device parameters of §4). It is verified at the space's ingress.
- **Projected at tens of milliseconds** [model].

**Passkeys, post-quantum** [decided, first]:
- The passkey's PRF extension (shipped on iOS, Android and Chrome)
  derives a device secret.
- The credential leaf is `Poseidon2(secret ‖ …)`.
- The passkey stays the user experience and the key wrap. No curve
  arithmetic enters the proof.

**The Poseidon2 root kind,** needed by the credential AIR:
- **vos-tree gains a Poseidon2-M31 root kind** per map. Credential sets
  and the balances phones read take it.
- **The zkPVM gains a Poseidon2 precompile chip** (one permutation a row,
  about 300 columns at degree ≤ 3, like the recursion AIR's `p2`). Node
  kernels can then read those maps, and it is cheaper than BLAKE2b
  in-AIR.
- **The host serves Poseidon2 natively.** A JAM-deployed agent pays it in
  software, about 15,800 instructions a permutation, as it does
  BLAKE2b.

**2. The device profile** comes next. The general zkVM runs on phones,
for any attestable kernel. It proves one segment with no page-Merkle
boundary, binding the run like this:
- **code:** program memory, preprocessed;
- **first touches** (`ts = 0` ledger entries), by address region:
  - the data region: a preprocessed data table;
  - stack and heap: zero;
  - anywhere else: refused (the live PVM traps there);
- **arguments:** the witness-input precompile;
- **read-only pages:** a preprocessed permission table per region refuses
  writes;
- **output:** the io-hash only;
- **masking:** a floor of 2^11 rows per component.

Its levers:
1. no boundary, −58% [measured proxy];
2. lean kernels and narrow BLAKE2b chips, about −54% of the rest;
3. blowup 2, −20%;
4. threads weighted by core class.

It projects to 0.36–0.9 s on Apple-class phones [projected].

**3. Signature chips** come last, for flows that must prove a standard
signature [decided, after PRF]:
- SHA-256 and SHA-512, in the narrow layout;
- one generic modular bignum chip (q·m form, 8-bit limbs), with the
  moduli (p25519, p256, n256) preprocessed;
- P-256 and Edwards drivers on top.

Each signature statement is then about 8–10M cells [model]. They are not
post-quantum.

**A real phone, early:** a one-day run of the auth statement, as built
and without the boundary, on a real flagship, to replace the projected
ARM factor with a measurement. Planned in slice 5's foundation (5.6) and
not done there: it waits on the owner's team, carried to slice 7.

## 9. Node proving levers, named with their numbers

| lever | effect | effort | when |
|---|---|---|---|
| a shape per kernel | −38% verify, −14% bytes, −10% RSS [measured] | about 1 week | slice 5 |
| the reference Poseidon2 and a SIMD hasher | segments on Poseidon2 at 1.75–1.85× Blake2s, against 6.4–6.9× before; a leaf's commitment 0.63 s [measured] | 2–3 weeks | slice 5 |
| narrow BLAKE2b chips | −2,200 columns; −30–45% of BLAKE2b's cells [model] | 3–5 weeks | slice 7 (mobile needs it; folds gain) |
| a lighter page boundary (Poseidon2 page hashing), or one memory argument across segments | about −1,100 / −2,800 columns; up to −49% of prover cells | 3–5 / 6–10 weeks | later |
| word-level memory | MEMORY 4–8× fewer rows | 4–6 weeks | later |
| CPU components per opcode family | −50–70% of the CPU's cells | 6–10 weeks | later |

A fold costs the inner proof's columns times its queries, so every lever
that narrows the inner proof makes folds cheaper too.

## 10. Risks, and the gate that retires each

| risk | gate | when |
|---|---|---|
| the ARM factor is wrong | the auth statement, as built and without the boundary, on a real flagship | planned in slice 5's M0, not run; pending the owner's team (slice 7) |
| the Poseidon2 segment channel is too slow to prove | retired: a segment's proving plus its leaf beats the Blake2s route's projection (§3.2) [measured, projected]; Poseidon2-M31 kept by the owner | slice 5, M0 |
| our permutation is not the reference Poseidon2 | the reference arrangement and Plonky3's parameters adopted, checked on their vectors | slice 5, M0 |
| the recursion AIR does not converge | sized in `recursion-air.md` (it converges at once [model]); then measured: a fold verifies two folds within the constant shape | slice 5, M1 |
| signed multiplicities in the wiring are new soundness surface | the `Context`'s static checks; the audit of the wiring argument (`recursion-air.md` §1.1) | slice 5, M1 |
| the gate compiler is wrong | equivalence tests (constraint ≡ gate) on every chip; tamper tests | slice 5, M1 |
| the window kernel's leaf is too big (`p2` about 64.8k of 2^16 at 44 queries [model]) | recounted on the hardened shape (5.8.0, 5.10), its topology counted (5.11), then its leaf proved within A.7; otherwise fewer queries with more PoW (PoW 24 and 40 queries, about −6k `p2` rows), FRI fold step 3 in inner proofs, `p2` at 2^17 (+70% cells), or narrower chips | slice 5, M1 |
| the final wrap misses its gas or size | the real wrap verified on the JAM-only host (≤ 150M unmasked) and in the Wasm harness | slice 5, M1 |
| the multi-step FRI path, or the new Blake2b channel, is unsound | a review plus tamper tests before the format admits them | slice 5, M1 |
| the wrap misses its 80 proven bits | 74.7 at blowup 64 with powers-of-one DEEP batching [model]; **retired at 5.14:** affine batching in the fork for format 28, 82.6 proven bits [model] | slice 5, M1 |
| masking the wrap costs more than (c)'s factor | one masked wrap: ≤ 24 GiB, ≤ 200M gas; leakage and soundness tests. Measured (spike 6a): 3.45 GiB of heap, 115.8–118.7M gas; the gate is 6.3–6.6 | slice 6 |
| the cut and held build fail under failover | the cut and the held build across a leader change (6.12) | slice 6 |
| the prover worker falls behind the window cadence | the worker measured against the cadence (6.18) | slice 6 |
| the teammate's pallet diverges from the design | the pallet against the conformance vectors (6.17) | slice 6, then the teammate's |
| a deadline between parties is read from a space's clock | a test that every deadline is the venue's time | slice 6 |
| a forgery in the recursion AIR | the recursion AIR's forgery gates (6.8) | slice 6 |
| the credential AIR misses sub-second | masked auth and payment proofs on a real flagship | slice 7 |
| the signature chips' cost or soundness | a gate ladder per chip; a phone run | slice 7 |

## 11. Slices and milestones [decided: three slices]

| slice | milestone | content | estimate |
|---|---|---|---|
| **5** | **M0 Foundation** | our Stwo fork pinned, with the completeness fix and no_std gating; a shape per kernel; formats chosen at run time, with lossless encodings; the inner parameters, interaction PoW and both bit counts; the witness-input precompile, the halt pc and the io-hash with roots; the reference Poseidon2, a SIMD hasher and the channel gate; the phone run (not run: pending the owner's team) | 6–9 weeks |
| **5** | **M1 The recursion, unmasked, in tests** | a preparation step (slice 5's 5.8.0: the window kernel on the line, the fixture generator, shared code, the inner parameters recounted); then `recursion-air.md` §10's eight steps: the gate VM; the gate compiler; the in-AIR verifier's pieces; COMPARE's leaf; the window kernel's and the solvency predicate's leaves; the fold and the fixed point; the final wrap with the Blake2b channel and `vos-pvm-final-verifier`; end to end with `vos-statement` and the golden fixtures | 18–26 weeks, plus reviews |
| **6** | **M2 Masking** | R1–R8 on the final wrap, generic over components and channel for slice 7; format 39; 248-bit salts; leakage and soundness gates; the items carried from slice 5 | 8.5–13 weeks |
| **6** | **M3 Statements on chain** | the public-input model; `&self` witnessed reads to the space root at anchored cuts; the prover worker; the Kreivo spaces pallet's design, the verifier kit and the node's client (the pallet is the Kreivo teammate's); the JAM statements service | 18.5–29 weeks |
| **7** | **M4 Credential AIR** | the Poseidon2 root kind; the zkPVM Poseidon2 chip; the credential AIR with PRF passkeys; a phone gate | 6–10 weeks |
| **7** | **M5 Device profile** | the device shape; lean kernels; narrow BLAKE2b | 6–10 weeks |
| **7** | **M6 Signature chips** | SHA-256, SHA-512, the bignum chip, the P-256 and Edwards drivers | 8–14 weeks |

- M0 runs on two tracks. Its critical path is 5.1 → 5.2 → 5.4, and
  5.5 → 5.12 (`slice-5-proving.md`); 5.7 runs beside it.
- M1's 18–26 weeks are 1–2 for its preparation and 17–24 for §10's
  steps, which sit below spike 4b §8's 20–28 to a working tree for our
  own AIR: the design and its counts are now measured; masking is slice
  6; the external audit's timing is the owner's (`slice-5-progress.md`).
- Slice 6's spikes, acceptance and the slice-5 rest add 5–7 weeks to M2
  and M3: slice 6 is 32–49 engineer-weeks (`slice-6-on-chain.md`,
  "Estimates").
- The Clerk across spaces follows slice 6.
- The total is about 76–118 engineer-weeks.

## 12. Decisions

**Taken by the owner:**
1. **The recursion:** our own narrow gate-based AIR on our pinned Stwo,
   on StarkWare's design, with Poseidon2 from day one.
2. **Device proofs** are not folded in v1. They are verified at a space's
   ingress, and chain statements are node-proved.
3. **Signatures:** both, PRF first. Passkey-derived secrets with hash
   credentials come first, and P-256 and ed25519 chips after.
4. **Mobile:** both, credential AIR first. It brings a Poseidon2 root kind
   and a zkPVM Poseidon2 chip; the device profile follows.
5. **The final channel:** Blake2b-256.
6. **Arguments** go through a witness-input precompile.
7. **The Kreivo pallet** comes after the recursion, with P0 and P1
   together in slice 6.
8. **Slicing:** three slices, as in §11.
9. **The segment channel:** Poseidon2-M31, on a segment's total cost
   (§3.2).
10. **The window length** (2026-10-19): windows of Unix time from the
    space's genesis, the length per space in [2, 60] minutes, default 10;
    every deadline between parties is the venue's time (§7).
11. **The pallet's home** (2026-10-19): `pallet-spaces` in Kreivo, built
    by the Kreivo teammate from `spaces-pallet.md`, to replace
    pallet-communities later; slice 6 delivers its design, the verifier
    kit vendored with a sync check, and the node's client (§6). This
    replaces 7's "in slice 6".

**Decided on the evidence, and the owner's to override:**
- reads at the last anchored cut, to the space root;
- runtime format selection, with lossless encodings;
- interaction PoW;
- 248-bit salts;
- one padded fold shape as a format constant;
- an external audit before value rides on a proof.

## Appendix A. For the implementer

These specs are pinned by the first step of the milestone named in each.

**A.1 The transcript (M1).** The in-AIR verifier replays the native
verifier's (`verify_standalone_on` in `pvm/proof/verifier/src/lib.rs`,
through `vos_pvm_proof::proof::replay_prefix`, then Stwo's `verify`), in
this order:
1. the domain, format and PCS configuration, then each chip's log size.
   These are constants of a leaf circuit;
2. the preprocessed root (also a constant), then the main trace root;
3. the boundary states: the 13 registers in, the 13 out, pc and ts in,
   pc and ts out, and the memory roots in and out, as one run of bytes;
4. the interaction PoW nonce (new in M0), which comes before any logup
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

**A.2 What the in-AIR verifier must handle (M1),** from our chips:
- **a challenge pair per relation,** drawn as A.1 item 5 says;
- **chips reading the next row:** CPU, BLAKE2B, BLAKE2B_BOUNDARY, MEMORY,
  MEMORY_PAGE, REGISTER_MEMORY;
- **chips finalizing one fraction a column:** bitcount, bitwise_and_byte,
  bitwise_lookup, byte_to_bits, jump_table, memory_root_boundary, memory,
  popcount, power_of_two, program_memory, range_multiplicity,
  register_memory_boundary, register_memory_closing.

**A.3 Encodings and the node output (M0 for the encodings, M1 for the
output).**
- **Lossless encodings,** in every new format (A.4).
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
    take the four limbs; the old `reduce(lo32), reduce(hi32)`, which
    folded a word ≥ p onto a smaller one, retired with the formats that
    used it. Stwo's Blake2s channel hashes the eight bytes, so it is lossless
    already.
  - The io-hash's 16 limbs come from φ9..12's bound bytes by linear
    gates, `b0 + 256·b1`.
- **A state digest** hashes 148 words, in order: the 13 registers (8
  bytes each), pc (4), ts (8), the memory root (32). A segment state's
  `memory_commitment`, the prover's blake3 of the flat memory, is left out
  on purpose: no committed column binds it and no transcript mixes it, so
  a digest over it would bind nothing. Memory continuity is the memory
  root's, which the boundary chips bind.
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

**A.4 The format registry (M0),** `pvm/proof/src/format.rs`. Parameters
as log blowup, queries, PoW, fold step, log last layer, interaction PoW;
counts as conjectured / proven at the reference shape [model]:

| number | proofs | channel | parameters | floors | counts | status |
|---|---|---|---|---|---|---|
| 35 | segments | Poseidon2-M31 | 2, 40, 24, 1, 0, 8 | 100 / 60 | 104 / 62 | admitted |
| 32 | leaf and fold (one padded shape) | Poseidon2-M31 | 2, 44, 20, 1, 0, 8 | 100 / 60 | 108 / 63 | reserved |
| 36 | segments, legacy encodings | Blake2s | the proof's own, at least 96 conjectured bits (MOBILE: 2, 38, 20, 1, 0, none) | 96 / — | 96 / 57 | admitted |
| 37 | device proofs, masked | Blake2s-M31 | 1, 86, 20, 1, 0, 8 | 100 / 60 | 106 / 62 | reserved |
| 28 | the final wrap, unmasked (tests only) | Blake2b-256 | 6, 20, 26, 3, 6, 8, affine DEEP batching | 100 / 80 | 146 / 82 | admitted |
| 39 | the final wrap, masked (variant (c)) | Blake2b-256 | 5, 24, 26, 3, 6, 8, affine DEEP batching | 100 / 80 | 146 / 82 | reserved; admitted at slice 6's 6.4 |
| 30 | credential proofs, masked | Blake2s-M31 | 1, 86, 20, 1, 0, 8 | 100 / 60 | 106 / 62 | reserved |

- **Each entry** holds its channel, its encodings, its parameters, the DEEP
  batching its proven floor assumes and both bit counts.
- **32, 35 and 37 use A.3's encodings** and exactly their parameters, as
  do 28 and 30.
- **35 takes fewer queries and more PoW than 32** (40 and 24 bits against
  44 and 20): a kernel leaf's rows grow with the segment's width times its
  queries, and a fold verifies under half the recursion AIR's shape. On the
  segment shape 35's count is its query term's, 62.86; 32's parameters give
  62.74, their batching term binding.
- **36 is the legacy segment format** the default prover produces, kept
  while the refine bundles and chain proofs use it: no interaction PoW,
  the boundary states mixed a word at a time, and the proof's own
  parameters under the 96-bit conjectured floor.
- **35 to 37 name the segment AIR,** hardened and without the columns and
  next-row masks no constraint reads (§3.2); 28, 30 and 32 prove the
  recursion AIR, 32's leaves verifying the segment AIR. A reserved entry is
  refused until its AIR and channel exist. 32's exist from slice 5's 5.8:
  `vos-pvm-recair` proves and verifies its proofs natively, and the registry
  refuses it, as no verifier outside the recursion reads a leaf or a fold.
  28 is admitted from slice 5's 5.14: `vos-pvm-recair` proves the wrap and
  `vos-pvm-final-verifier` verifies it; a segment verifier takes only a
  segment format.
- **Masking takes a new number, 39:** a bump of 28 would break "a number
  names one AIR and one set of parameters". 40, spike 6a's blowup-64
  shape, is retired unregistered; 38 stays unassigned, the fixtures' "a
  number no format holds".
- **24 to 27, 29, 31, 33, 34 and 40 are retired.** 24 to 27 and 29 named
  the segment AIR before its hardening, and 31, 33 and 34 the hardened AIR
  with its unread columns (31 at 44 queries); 40 was never registered,
  but spike 6a's measured masked wrap at blowup 64 was made under it. They
  are refused and never registered again: a number names one AIR and one
  set of parameters.

**A.5 What may leave the prover role (slice 6):**
- the `Statement`;
- the final proof.

`Attest` (`agent/wire/src/result.rs`) is `{ program, witness_input,
output }`.
- **`witness_input`** replaced `arguments` in M0: the exact byte stream
  the kernel read, in call order, at most 4 MiB. Keeping both would have
  held the same bytes twice. A large result travels as a blob (slice 4's
  4.4a).
- Slice 6 adds the window, then the final proof's hash.

Segment, leaf and fold proofs appear in no log entry, blob or message
that leaves the role. The carrier audit checks every one of those
carriers.

**A.6 The golden fixtures (M1, extended in slice 6):**
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

Every venue judges them alike. A generator makes them, regenerated at
each format bump, and stores them under `pvm/proof/fixtures` (about
380 KB, plus the segment fixtures). M0 promised it and did not build
it; slice 5's 5.8.0 does.

**Built** (slice 5's 5.15, its review folded in 5.15b) [measured]: the
generator (`pvm/proof/tests/kernel/fixtures.rs`) proves a small kernel stating a fixed
statement `S` (two roots of its space, a nonce, an output) in three
segments, folds them and wraps the root (`wrap.proof`, 124,025 bytes), and
wraps two roots that are not a whole run as a cheating prover would, the
wrap's checks failing (`wrap-prefix.proof`, `wrap-midway.proof`). The cases
(`statements.cases`, 6.4 KB), each a venue's state, a statement, a proof or
a patch of one, and its verdict:

| case | verdict | native | Wasm (PVF, client) | JAM-only host |
|---|---|---|---|---|
| valid | accepted | accepted | accepted, 38.4M / 37.9M instructions | accepted, 96.4M gas |
| tampered (a byte flipped) | `0x112` Stwo, Merkle | `0x112` | `0x112` | `0x112`, 67.1M |
| wrong program (the venue pins another, the wrap is this kernel's) | `0x108` interaction PoW | `0x108` | `0x108` | `0x108`, 17.5M |
| unanchored root (an older window's) | `0x5` | `0x5` | `0x5` | `0x5`, < 0.1M |
| prefix (no halt) | `0x109` logup | `0x109` | `0x109` | `0x109`, 17.5M |
| mid-way (no entry, labelled from 0) | `0x109` logup | `0x109` | `0x109` | `0x109`, 17.4M |
| repeated | `0x6` | `0x6` | `0x6` | `0x6`, 0.1M |
| unaccepted format (30) | `0x2` | `0x2` | `0x2` | `0x2`, < 0.1M |
| wrong io-hash (the output changed) | `0x108` interaction PoW | `0x108` | `0x108` | `0x108`, 17.5M |
| another program than the pin | `0x3` | `0x3` | `0x3` | `0x3`, < 0.1M |
| another space | `0x4` | `0x4` | `0x4` | `0x4`, 0.1M |
| rootless, another space (`S` without its roots, its space still claimed) | `0x4` | `0x4` | `0x4` | `0x4`, < 0.1M |
| the same run, another accepted format (the venue accepts 28 and 38, and accepted `S` under 38) | `0x6` | `0x6` | `0x6` | `0x6`, 0.1M |

The accepted statement's id is the same at every venue. A refused proof's
class is the first check it fails. The last case is a transition's: the
id leaves the format out, so the run the venue accepted under a successor
format is the same statement under 28. No format holds 38 and this
verifier reads 28 alone, so the case records the successor's acceptance
as the id the venue keeps, all its repeat check reads; slice 6's masked
format adds the case the other way round. The words are mixed before the
interaction PoW (8 bits), so a proof of other words fails there (`0x108`)
with probability 255/256, or otherwise at the logup sums (`0x109`); a wrap
proved over a refused root does not balance its logup sums. A judgement
refused before its proof costs no proof lookup on the JAM-only host, and a
proof longer than 256 KiB is refused before its lookup. The generator makes
the same bytes in every build of the prover: a kernel's program id does not
depend on the features a build turns on (the drawn relations are kept in
the order drawn, never in `TypeId` order). `just judge-wasm` (in
`test-proof`) judges the fixtures in Wasm.

**A.7 Budgets per node (M1: measured, then pinned).** Heavy tests run
under `systemd-run` with these caps as `MemoryMax`.

| node | rows | memory | time |
|---|---|---|---|
| segment (the window kernel's) | its class | ≤ 24 GiB | ≤ 8 s, once the SIMD hasher lands |
| leaf | ≤ the padded shape | ≤ 4 GiB | 1.2–2.6 s [projected]; ≤ 1× the segment's proving (target 0.13–0.5×) |
| fold | the padded shape | ≤ 4 GiB; 942 MiB of heap [measured] | 1.2–2.6 s [projected]; ≤ the leaf's; 1.5 s [measured] |
| wrap | ≤ 2^17; 2^14 / 2^15 / 2^11 [measured] | ≤ 8 GiB unmasked; a 2.5 GiB heap [measured]. 39: ≤ 8 GiB; 3.45 GiB of heap [measured] | 4.4–9.5 s [projected]; 5.45 s [measured]. 39: ≤ 15 s; 11.6 s [measured] |

A window of 16 segments proves end to end in about 3–5 minutes
[projected].
